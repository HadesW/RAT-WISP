// Sample native plugin (plan P5): exercises the ABI v1 host contract —
// wisp_plugin_abi / init(host) / start, logging through the host callback.
// It is loaded with wisp_map, so it never appears in the process module list.
use std::ffi::{c_char, CString};
use std::sync::atomic::{AtomicUsize, Ordering};

#[repr(C)]
pub struct WispHostApiV1 {
    pub abi: u32,
    pub log: Option<extern "C" fn(u32, *const c_char)>,
}

static LOG_FN: AtomicUsize = AtomicUsize::new(0);

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
    plugin_log(1, "hello-native: init ok");
    0
}

#[no_mangle]
pub extern "C" fn wisp_plugin_start() -> i32 {
    plugin_log(2, "hello-native: started");
    0
}