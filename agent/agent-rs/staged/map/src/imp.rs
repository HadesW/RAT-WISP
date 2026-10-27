// Windows manual-mapper implementation. The image is allocated at its
// preferred base when possible (relocations applied otherwise), imports are
// resolved with LoadLibraryA/GetProcAddress, x64 exception tables are
// registered with RtlAddFunctionTable and PE TLS callbacks are collected so
// the caller can replay them for threads it creates itself.
use std::ffi::c_void;
use std::mem;
use std::ptr;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
    fn VirtualProtect(addr: *mut c_void, size: usize, new_protect: u32, old: *mut u32) -> i32;
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn RtlAddFunctionTable(table: *mut c_void, count: u32, base: usize) -> u8;
}

pub struct MappedImage {
    pub base: *mut u8,
    pub size: usize,
    pub image_base: u64,
    pub entry_rva: u32,
    pub headers_len: usize,
    pub tls_callbacks: Vec<usize>,
    export_dir: (u32, u32),
}

#[derive(Clone, Copy)]
struct Section {
    va: u32,
    vsize: u32,
    raw_off: u32,
    raw_len: u32,
    chars: u32,
}

struct PeInfo {
    image_base: u64,
    size_of_image: u32,
    size_of_headers: u32,
    entry_rva: u32,
    dirs: [(u32, u32); 16],
    sections: Vec<Section>,
}

fn read_u16(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("pe: u16 @{at:#x} out of bounds"))
}

fn read_u32(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("pe: u32 @{at:#x} out of bounds"))
}

fn read_u64(b: &[u8], at: usize) -> Result<u64, String> {
    b.get(at..at + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("pe: u64 @{at:#x} out of bounds"))
}

fn parse_pe(b: &[u8]) -> Result<PeInfo, String> {
    let lfanew = read_u32(b, 0x3c)? as usize;
    if b.get(lfanew..lfanew + 4) != Some(b"PE\0\0") {
        return Err("pe: bad signature".into());
    }
    let nsec = read_u16(b, lfanew + 6)? as usize;
    let sizeopt = read_u16(b, lfanew + 20)? as usize;
    let opt = lfanew + 24;
    let magic = read_u16(b, opt)?;
    if magic != 0x20b {
        return Err(format!("pe: expected PE32+ image, magic {magic:#x}"));
    }
    let image_base = read_u64(b, opt + 24)?;
    let size_of_image = read_u32(b, opt + 56)?;
    let size_of_headers = read_u32(b, opt + 60)?;
    let entry_rva = read_u32(b, opt + 16)?;
    let num_dirs = read_u32(b, opt + 108)?.min(16) as usize;
    let mut dirs = [(0u32, 0u32); 16];
    for (i, d) in dirs.iter_mut().enumerate().take(num_dirs) {
        let at = opt + 112 + i * 8;
        *d = (read_u32(b, at)?, read_u32(b, at + 4)?);
    }
    let secs_at = opt + sizeopt;
    let mut sections = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let s = secs_at + i * 40;
        sections.push(Section {
            vsize: read_u32(b, s + 8)?,
            va: read_u32(b, s + 12)?,
            raw_len: read_u32(b, s + 16)?,
            raw_off: read_u32(b, s + 20)?,
            chars: read_u32(b, s + 36)?,
        });
    }
    Ok(PeInfo { image_base, size_of_image, size_of_headers, entry_rva, dirs, sections })
}

unsafe fn read_cstr(p: *const u8) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for i in 0..4096 {
        let c = *p.add(i);
        if c == 0 {
            out.push(0);
            return Ok(out);
        }
        out.push(c);
    }
    Err("pe: string not terminated".into())
}

// Maps a raw PE image into private memory. The image is not registered with
// the OS loader; call `call_entry` to run CRT initialisation.
pub fn map_image(bytes: &[u8]) -> Result<MappedImage, String> {
    let pe = parse_pe(bytes)?;
    let size = pe.size_of_image as usize;
    if size == 0 {
        return Err("pe: zero SizeOfImage".into());
    }
    let raw = unsafe {
        let preferred =
            VirtualAlloc(pe.image_base as *mut c_void, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if preferred.is_null() {
            VirtualAlloc(ptr::null_mut(), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        } else {
            preferred
        }
    };
    if raw.is_null() {
        return Err("map: VirtualAlloc failed".into());
    }
    let base = raw as *mut u8;
    let r = map_into(&pe, bytes, base);
    if let Err(e) = r {
        unsafe {
            VirtualFree(raw, 0, MEM_RELEASE);
        }
        return Err(e);
    }
    let mut tls_callbacks = Vec::new();
    if let Some(cbs) = tls_callback_vas(&pe, base) {
        tls_callbacks = cbs;
    }
    Ok(MappedImage {
        base,
        size,
        image_base: pe.image_base,
        entry_rva: pe.entry_rva,
        headers_len: pe.size_of_headers as usize,
        tls_callbacks,
        export_dir: pe.dirs[DIR_EXPORT],
    })
}

fn map_into(pe: &PeInfo, bytes: &[u8], base: *mut u8) -> Result<(), String> {
    let headers = (pe.size_of_headers as usize).min(bytes.len()).min(pe.size_of_image as usize);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), base, headers);
    }
    for s in &pe.sections {
        if s.raw_len == 0 {
            continue;
        }
        let virt = if s.vsize == 0 { s.raw_len } else { s.vsize };
        let n = (s.raw_len.min(virt)) as usize;
        let src = s.raw_off as usize;
        let dst = s.va as usize;
        if src + n > bytes.len() || dst + n > pe.size_of_image as usize {
            return Err("map: section out of bounds".into());
        }
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr().add(src), base.add(dst), n);
        }
    }
    let delta = (base as i64) - (pe.image_base as i64);
    if delta != 0 {
        apply_relocations(pe, base, delta)?;
    }
    resolve_imports(pe, base)?;
    let exc = pe.dirs[DIR_EXCEPTION];
    if exc.1 > 0 {
        unsafe {
            RtlAddFunctionTable(
                base.add(exc.0 as usize) as *mut c_void,
                exc.1 / 12,
                base as usize,
            );
        }
    }
    for s in &pe.sections {
        if s.vsize == 0 {
            continue;
        }
        let prot = if s.chars & IMAGE_SCN_MEM_WRITE != 0 {
            if s.chars & IMAGE_SCN_MEM_EXECUTE != 0 {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_READWRITE
            }
        } else if s.chars & IMAGE_SCN_MEM_EXECUTE != 0 {
            PAGE_EXECUTE_READ
        } else {
            PAGE_READONLY
        };
        let mut old = 0u32;
        unsafe {
            VirtualProtect(base.add(s.va as usize) as *mut c_void, s.vsize as usize, prot, &mut old);
        }
    }
    Ok(())
}

fn apply_relocations(pe: &PeInfo, base: *mut u8, delta: i64) -> Result<(), String> {
    let dir = pe.dirs[DIR_BASERELOC];
    if dir.1 == 0 {
        return Err("map: base occupied and image has no relocations".into());
    }
    let mut at = dir.0 as usize;
    let end = at + dir.1 as usize;
    while at + 8 <= end {
        let page = unsafe { ptr::read_unaligned(base.add(at) as *const u32) } as usize;
        let block = unsafe { ptr::read_unaligned(base.add(at + 4) as *const u32) } as usize;
        if block < 8 {
            break;
        }
        let entries = (block - 8) / 2;
        for i in 0..entries {
            let e = unsafe { ptr::read_unaligned(base.add(at + 8 + i * 2) as *const u16) };
            let kind = e >> 12;
            let off = (e & 0x0fff) as usize;
            let slot = base.wrapping_add(page + off);
            match kind {
                0 => {}
                10 => unsafe {
                    // IMAGE_REL_BASED_DIR64
                    let v = ptr::read_unaligned(slot as *const u64);
                    ptr::write_unaligned(slot as *mut u64, v.wrapping_add(delta as u64));
                },
                3 => unsafe {
                    // IMAGE_REL_BASED_HIGHLOW (32-bit images; accepted for completeness)
                    let v = ptr::read_unaligned(slot as *const u32);
                    ptr::write_unaligned(
                        slot as *mut u32,
                        (v as i64).wrapping_add(delta) as u32,
                    );
                },
                other => return Err(format!("map: unsupported relocation type {other}")),
            }
        }
        at += block;
    }
    Ok(())
}

fn resolve_imports(pe: &PeInfo, base: *mut u8) -> Result<(), String> {
    let dir = pe.dirs[DIR_IMPORT];
    if dir.1 == 0 {
        return Ok(());
    }
    let mut de = unsafe { base.add(dir.0 as usize) };
    loop {
        let oft = unsafe { ptr::read_unaligned(de as *const u32) } as usize;
        let name_rva = unsafe { ptr::read_unaligned(de.add(12) as *const u32) } as usize;
        let first = unsafe { ptr::read_unaligned(de.add(16) as *const u32) } as usize;
        if oft == 0 && name_rva == 0 && first == 0 {
            return Ok(());
        }
        if name_rva == 0 {
            return Err("map: import descriptor without name".into());
        }
        let dll = unsafe { read_cstr(base.add(name_rva))? };
        let module = unsafe { LoadLibraryA(dll.as_ptr()) };
        if module.is_null() {
            return Err(format!(
                "map: LoadLibraryA({}) failed",
                String::from_utf8_lossy(&dll[..dll.len().saturating_sub(1)])
            ));
        }
        let mut names = unsafe { base.add(if oft != 0 { oft } else { first }) } as *const u64;
        let mut iat = unsafe { base.add(first) } as *mut u64;
        loop {
            let thunk = unsafe { ptr::read_unaligned(names) };
            if thunk == 0 {
                break;
            }
            let proc = if thunk & (1u64 << 63) != 0 {
                unsafe { GetProcAddress(module, (thunk & 0xffff) as *const u8) }
            } else {
                let nr = unsafe { base.add(thunk as usize) };
                unsafe { GetProcAddress(module, nr.add(2)) }
            };
            if proc.is_null() {
                return Err(format!(
                    "map: unresolved import in {}",
                    String::from_utf8_lossy(&dll[..dll.len().saturating_sub(1)])
                ));
            }
            unsafe {
                ptr::write_unaligned(iat, proc as u64);
                names = names.add(1);
                iat = iat.add(1);
            }
        }
        de = unsafe { de.add(20) };
    }
}

// tls_callback_vas reads IMAGE_TLS_DIRECTORY.AddressOfCallBacks from the mapped
// image. By the time this runs every VA in the image is final — the image was
// either mapped at its preferred base or the relocation pass rebased it — so
// the pointers must NOT be adjusted again. `fix` only guards the odd toolchain
// that emits no base relocation for the TLS directory fields.
fn tls_callback_vas(pe: &PeInfo, base: *mut u8) -> Option<Vec<usize>> {
    let dir = pe.dirs[DIR_TLS];
    if dir.1 < 40 {
        return None;
    }
    let at = dir.0 as usize;
    let linked = unsafe { ptr::read_unaligned(base.add(at + 24) as *const u64) };
    if linked == 0 {
        return None;
    }
    let lo = base as u64;
    let hi = lo + pe.size_of_image as u64;
    let delta = (base as i64) - (pe.image_base as i64);
    let fix = |va: u64| -> Option<usize> {
        let v = if (lo..hi).contains(&va) { va } else { (va as i64).wrapping_add(delta) as u64 };
        (lo..hi).contains(&v).then_some(v as usize)
    };
    let list = fix(linked)? as *const u64;
    let mut out = Vec::new();
    for i in 0..64 {
        let cb = unsafe { ptr::read_unaligned(list.add(i)) };
        if cb == 0 {
            return Some(out);
        }
        out.push(fix(cb)?);
    }
    Some(out)
}

// Calls the image entry point (DllMainCRTStartup for cdylibs), which performs
// static-CRT initialisation; without it the static runtime in a manual-mapped
// image is not usable.
pub fn call_entry(img: &MappedImage) -> i32 {
    if img.entry_rva == 0 {
        return 0;
    }
    let f: extern "system" fn(*mut c_void, u32, *mut c_void) -> i32 =
        unsafe { mem::transmute(img.base.add(img.entry_rva as usize)) };
    f(img.base as *mut c_void, 1 /* DLL_PROCESS_ATTACH */, ptr::null_mut())
}

// Replays the image's PE TLS callbacks. The OS never does that for
// manual-mapped images, so the host must call this with DLL_PROCESS_ATTACH (1)
// on the "loading" thread and DLL_THREAD_ATTACH (2) on every thread it starts
// that will run image code.
pub fn tls_notify(img: &MappedImage, reason: u32) {
    for cb in &img.tls_callbacks {
        let f: extern "system" fn(*mut c_void, u32, *mut c_void) =
            unsafe { mem::transmute(*cb) };
        f(img.base as *mut c_void, reason, ptr::null_mut());
    }
}

pub fn resolve_export(img: &MappedImage, name: &str) -> Result<*mut c_void, String> {
    let (dir_rva, dir_size) = img.export_dir;
    let dir_rva = dir_rva as usize;
    if dir_rva == 0 {
        return Err("export: image has no export directory".into());
    }
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    let d = unsafe { img.base.add(dir_rva) };
    let n_names = unsafe { ptr::read_unaligned(d.add(24) as *const u32) } as usize;
    let funcs = unsafe { ptr::read_unaligned(d.add(28) as *const u32) } as usize;
    let names = unsafe { ptr::read_unaligned(d.add(32) as *const u32) } as usize;
    let ords = unsafe { ptr::read_unaligned(d.add(36) as *const u32) } as usize;
    for i in 0..n_names {
        let nr = unsafe { ptr::read_unaligned(img.base.add(names + i * 4) as *const u32) } as usize;
        let cand = unsafe { read_cstr(img.base.add(nr))? };
        if cand == name {
            let ord =
                unsafe { ptr::read_unaligned(img.base.add(ords + i * 2) as *const u16) } as usize;
            let rva =
                unsafe { ptr::read_unaligned(img.base.add(funcs + ord * 4) as *const u32) } as usize;
            if rva >= dir_rva && rva < dir_rva + dir_size as usize {
                return Err("export: forwarded exports are not supported".into());
            }
            return Ok(unsafe { img.base.add(rva) } as *mut c_void);
        }
    }
    Err(format!("export: {:?} not found", String::from_utf8_lossy(&name[..name.len() - 1])))
}

// Zeroes the PE headers once imports/TLS/entry data have been consumed, so the
// mapped image leaves no parseable fingerprint in memory.
pub fn wipe_headers(img: &MappedImage) {
    unsafe {
        ptr::write_bytes(img.base, 0, img.headers_len.min(img.size));
    }
}

pub fn free_image(img: &MappedImage) {
    unsafe {
        VirtualFree(img.base as *mut c_void, 0, MEM_RELEASE);
    }
}