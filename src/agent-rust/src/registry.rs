// Plugin registry + AgentCtx — the pluggable command dispatch core.
//
// Modeled on Go agent/commands/dispatcher.go. The Dispatcher owns the command
// registry; AgentCtx is the per-agent mutable state passed to handlers. This
// separation avoids aliasing issues (a handler mutates ctx while the registry
// stays a distinct, immutable lookup table).

use crate::protocol::types::Task;
use std::collections::HashMap;

/// Result returned to the server for a completed task.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TaskResult {
    #[serde(rename = "task_id")]
    pub task_id: String,
    pub output: String,
    pub status: String,
}

impl TaskResult {
    pub fn ok(task_id: &str, output: String) -> Self {
        TaskResult { task_id: task_id.to_string(), output, status: "completed".into() }
    }
    pub fn fail(task_id: &str, output: String) -> Self {
        TaskResult { task_id: task_id.to_string(), output, status: "failed".into() }
    }
}

/// A task handler. Returns None if the task was consumed as an async job.
pub type CommandFn = Box<dyn Fn(&mut AgentCtx, &Task) -> Option<TaskResult> + Send + Sync>;

/// Mutable per-agent context shared by all command handlers.
pub struct AgentCtx {
    pub cwd: std::path::PathBuf,
    pub config: crate::agent::AgentConfig,
    /// Pending results queued for the next checkin.
    pub pending: Vec<TaskResult>,
    /// Force-exit flag (standalone agents: true; DLL: false).
    pub force_exit: bool,
    /// Whether the agent is still running.
    pub running: bool,
}

impl AgentCtx {
    pub fn new(config: crate::agent::AgentConfig) -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
        AgentCtx {
            cwd,
            config,
            pending: Vec::new(),
            force_exit: true,
            running: true,
        }
    }

    /// Queue a result for the next checkin.
    pub fn queue_result(&mut self, r: TaskResult) {
        self.pending.push(r);
    }
}

/// Plugin registry: command_id → handler.
pub struct Registry {
    map: HashMap<u32, CommandFn>,
}

impl Registry {
    pub fn new() -> Self {
        Registry { map: HashMap::new() }
    }

    /// Register a command handler. Errors if the ID is already taken.
    pub fn register<F>(&mut self, id: u32, f: F) -> Result<(), String>
    where
        F: Fn(&mut AgentCtx, &Task) -> Option<TaskResult> + Send + Sync + 'static,
    {
        if self.map.contains_key(&id) {
            return Err(format!("command {id} already registered"));
        }
        self.map.insert(id, Box::new(f));
        Ok(())
    }

    pub fn unregister(&mut self, id: u32) {
        self.map.remove(&id);
    }

    pub fn has(&self, id: u32) -> bool {
        self.map.contains_key(&id)
    }

    /// Dispatch a task to its handler. Returns the handler's result.
    pub fn get(&self, id: u32) -> Option<&CommandFn> {
        self.map.get(&id)
    }
}

/// A Dispatcher bundles a Registry plus helper state; it dispatches tasks to
/// handlers while the AgentCtx is passed through mutably.
pub struct Dispatcher {
    registry: Registry,
}

impl Dispatcher {
    pub fn new() -> Self {
        Dispatcher { registry: Registry::new() }
    }

    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.registry
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Dispatch a task. Returns Some(result) to submit, or None (async consumed).
    pub fn dispatch(&self, ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
        match self.registry.get(task.command_id as u32) {
            Some(f) => f(ctx, task),
            None => Some(TaskResult::fail(
                &task.id,
                format!("unknown command id {}", task.command_id),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::Task;

    fn task(id: u32) -> Task {
        Task { id: "t".into(), command_id: id as i64, args: "{}".into(), status: "pending".into(), result: String::new() }
    }

    #[test]
    fn unknown_command_reports_fail() {
        let mut d = Dispatcher::new();
        crate::plugins::register_all(d.registry_mut()).unwrap();
        let cfg = crate::agent::AgentConfig {
            server_host: "h".into(), server_port: 1, rsa_pub_pem: "p".into(),
            psk: "p".into(), sleep_ms: 1, jitter: 0, transport: "http".into(), scheme: "http".into(),
            traffic_profile: None,
        };
        let mut ctx = AgentCtx::new(cfg);
        // command 999 unregistered
        let r = d.dispatch(&mut ctx, &task(999));
        assert!(r.is_some());
        assert_eq!(r.unwrap().status, "failed");
    }

    #[cfg(feature = "screenshot")]
    #[test]
    fn screenshot_registered_when_feature_on() {
        let mut d = Dispatcher::new();
        crate::plugins::register_all(d.registry_mut()).unwrap();
        assert!(d.registry().has(crate::protocol::constants::CMD_SCREENSHOT));
    }
}
