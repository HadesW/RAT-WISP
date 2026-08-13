// Task / Result / register payload structures — MUST match the Go side
// (agent/commands/dispatcher.go Task, internal/server/listener.go TaskResult,
// agent/main.go regData).

use serde::{Deserialize, Serialize};

/// Task sent from server (Go db.TaskRow json tags: id, command_id, args, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    #[serde(rename = "command_id")]
    pub command_id: i64,
    pub args: String,
    pub status: String,
    pub result: String,
}

/// Result posted back to the server (Go TaskResult: task_id, output, status).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    #[serde(rename = "task_id")]
    pub task_id: String,
    pub output: String,
    pub status: String,
}

/// Agent registration payload (Go main.go regData keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterData {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub domain: String,
    #[serde(rename = "internal_ip")]
    pub internal_ip: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
    #[serde(rename = "process_name")]
    pub process_name: String,
    #[serde(rename = "is_elevated")]
    pub is_elevated: bool,
    pub sleep: u64,
    pub jitter: u64,
    pub psk: String,
}
