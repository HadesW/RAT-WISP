// mapspike: dev harness for the manual mapper — maps a DLL from disk, runs its
// entry, optionally calls a no-arg export and prints the result. Used to
// isolate mapper/TLS behaviour from the full staged chain.
#[cfg(windows)]
fn main() {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32)
            -> *mut c_void;
    }

    let mut args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: mapspike <dll> [export] [--occupy]");
        std::process::exit(2);
    }
    let occupy = args.iter().any(|a| a == "--occupy");
    args.retain(|a| a != "--occupy");
    if occupy {
        // Occupy the linker-preferred base so map_image must relocate.
        let hint = unsafe {
            VirtualAlloc(0x1_8000_0000 as *mut c_void, 0x100_0000, 0x1000 | 0x2000, 0x04)
        };
        if hint.is_null() {
            eprintln!("occupy: VirtualAlloc at 0x180000000 failed");
            std::process::exit(2);
        }
        eprintln!("occupied {hint:p}..+0x1000000");
    }
    let bytes = std::fs::read(&args[1]).expect("read dll");
    let img = match wisp_map::map_image(&bytes) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("map: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "mapped at {:#x} (preferred {:#x}, {} tls callbacks)",
        img.base as usize,
        img.image_base as usize,
        img.tls_callbacks.len()
    );
    eprintln!("entry -> {}", wisp_map::call_entry(&img));
    if let Some(name) = args.get(2) {
        match wisp_map::resolve_export(&img, name) {
            Ok(p) => {
                let f: extern "system" fn() -> u32 = unsafe { std::mem::transmute(p) };
                eprintln!("{name}() = {}", f());
            }
            Err(e) => {
                eprintln!("resolve: {e}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("mapspike: windows only");
}