// RCP (Remote Control Protocol) client — long-lived channel for screen
// streaming + input, independent of the polling sleep. Matches Go
// agent/transport/rcp.go + internal/server/rcp_listener.go.
//
// Handshake:
//   agent → server: TypeRCPHello [8B raw agentID][RSA-OAEP(challenge16)]
//   server → agent: TypeRCPAck   [AES-session(challenge16)]
// Stream:
//   agent → server: TypeRCPFrame [AES-session(seq8BE+w4BE+h4BE+jpeg)]
//   server → agent: TypeRCPInput [AES-session(json)]
//   server → agent: TypeRCPPing  (keepalive, empty payload)
//   agent → server: TypeRCPError [AES-session(msg)] / TypeRCPClose

use crate::protocol::crypto::SessionKeys;
use crate::protocol::{
    read_packet, write_packet, Packet, TYPE_RCP_ACK, TYPE_RCP_CLOSE, TYPE_RCP_ERROR, TYPE_RCP_FRAME,
    TYPE_RCP_HELLO, TYPE_RCP_INPUT, TYPE_RCP_PING,
};
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::kcp::KcpIo;

/// Frame header: seq(8 BE) + width(4 BE) + height(4 BE).
pub const RCP_FRAME_SIZE: usize = 16;

/// Produces one JPEG frame: (jpeg bytes, width, height).
pub type CaptureFn = Arc<dyn Fn(u8) -> Result<(Vec<u8>, u32, u32), String> + Send + Sync>;
/// Receives a decoded JSON input message from the server.
pub type InputFn = Arc<dyn Fn(String) + Send + Sync>;

/// Backing connection handle shared by the frame/read loops.
enum RcpHandle {
    Tcp(Arc<Mutex<Option<TcpStream>>>),
    Kcp(Arc<Mutex<Option<KcpIo>>>),
}

pub struct RcpClient {
    pub host: String,
    pub port: u16,
    /// Hex-encoded 16-char agent id (raw 8 bytes on the wire).
    pub agent_id: String,
    pub rsa_pub_pem: String,
    pub keys: SessionKeys,
    pub capture: Option<CaptureFn>,
    pub on_input: Option<InputFn>,
    pub quality: u8,
    pub interval: Duration,
    pub proto: String, // "tcp" or "kcp"

    conn: Arc<Mutex<RcpHandle>>,
    running: Arc<AtomicBool>,
}

impl RcpClient {
    pub fn new(
        host: &str,
        port: u16,
        agent_id: &str,
        rsa_pub_pem: &str,
        keys: SessionKeys,
    ) -> Self {
        RcpClient {
            host: host.to_string(),
            port,
            agent_id: agent_id.to_string(),
            rsa_pub_pem: rsa_pub_pem.to_string(),
            keys,
            capture: None,
            on_input: None,
            quality: 45,
            interval: Duration::from_millis(50),
            proto: "tcp".to_string(),
            conn: Arc::new(Mutex::new(RcpHandle::Tcp(Arc::new(Mutex::new(None))))),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn connected(&self) -> bool {
        if !self.running.load(Ordering::SeqCst) {
            return false;
        }
        match &*self.conn.lock().unwrap() {
            RcpHandle::Tcp(c) => c.lock().unwrap().is_some(),
            RcpHandle::Kcp(c) => c.lock().unwrap().is_some(),
        }
    }

    /// Dial the RCP listener, authenticate, and start the frame/read loops.
    /// Returns after the handshake completes (channel is live in the background).
    pub fn connect(&self) -> Result<(), String> {
        self.close();
        match self.proto.as_str() {
            "kcp" => self.connect_kcp(),
            _ => self.connect_tcp(),
        }
    }

    fn connect_tcp(&self) -> Result<(), String> {
        let addr = format!("{}:{}", self.host, self.port);
        let conn = TcpStream::connect(&addr).map_err(|e| format!("rcp dial: {e}"))?;
        conn.set_read_timeout(Some(Duration::from_secs(45)))
            .map_err(|e| format!("set timeout: {e}"))?;
        conn.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("set timeout: {e}"))?;

        self.handshake(&conn)?;

        let t_conn = Arc::new(Mutex::new(Some(conn)));
        *self.conn.lock().unwrap() = RcpHandle::Tcp(t_conn.clone());
        self.running.store(true, Ordering::SeqCst);

        let capture = self.capture.clone();
        let on_input = self.on_input.clone();
        let quality = self.quality;
        let interval = self.interval;

        // Frame loop: capture at a fixed rate, independent of the polling sleep.
        let f_conn = t_conn.clone();
        let f_run = self.running.clone();
        let f_keys = self.keys.clone();
        std::thread::spawn(move || {
            frame_loop(&f_conn, &f_keys, capture.as_ref(), quality, interval, f_run.clone());
        });

        // Read loop: consume server input / ping / close.
        let r_run = self.running.clone();
        let r_keys = self.keys.clone();
        std::thread::spawn(move || {
            read_loop_tcp(t_conn, r_run, r_keys, on_input);
        });
        Ok(())
    }

    fn connect_kcp(&self) -> Result<(), String> {
        let mut io = super::kcp::new_kcp_io(&self.host, self.port, Duration::from_secs(10))
            .map_err(|e| format!("rcp kcp dial: {e}"))?;

        self.handshake_kcp(&mut io)?;

        let k_conn = Arc::new(Mutex::new(Some(io)));
        *self.conn.lock().unwrap() = RcpHandle::Kcp(k_conn.clone());
        self.running.store(true, Ordering::SeqCst);

        let capture = self.capture.clone();
        let on_input = self.on_input.clone();
        let quality = self.quality;
        let interval = self.interval;

        let f_conn = k_conn.clone();
        let f_run = self.running.clone();
        let f_keys = self.keys.clone();
        std::thread::spawn(move || {
            frame_loop_kcp(&f_conn, &f_keys, capture.as_ref(), quality, interval, f_run.clone());
        });
        let p_run = self.running.clone();
        let p_keys = self.keys.clone();
        std::thread::spawn(move || {
            pump_loop_kcp(k_conn, p_run, p_keys, on_input);
        });
        Ok(())
    }

    fn handshake(&self, conn: &TcpStream) -> Result<(), String> {
        let mut challenge = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut challenge);

        let raw_id: Vec<u8> = (0..self.agent_id.len() / 2)
            .map(|i| u8::from_str_radix(&self.agent_id[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();

        let enc_challenge = crate::protocol::crypto::rsa_encrypt_oaep(&self.rsa_pub_pem, &challenge)
            .map_err(|e| format!("encrypt challenge: {e}"))?;
        let mut payload = Vec::with_capacity(raw_id.len() + enc_challenge.len());
        payload.extend_from_slice(&raw_id);
        payload.extend_from_slice(&enc_challenge);

        let hello = Packet::new(TYPE_RCP_HELLO, payload);
        let mut c = conn.try_clone().map_err(|e| e.to_string())?;
        write_packet(&mut c, &hello).map_err(|e| format!("write hello: {e}"))?;
        c.flush().map_err(|e| e.to_string())?;

        c.set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let ack = read_packet(&mut c).map_err(|e| format!("read ack: {e}"))?;
        if ack.ptype != TYPE_RCP_ACK {
            return Err(format!("rcp handshake rejected (type {:#04x})", ack.ptype));
        }
        let dec = self.keys.decrypt(&ack.payload).map_err(|e| e.to_string())?;
        if dec != challenge {
            return Err("rcp handshake challenge mismatch".into());
        }
        Ok(())
    }

    fn handshake_kcp(&self, io: &mut KcpIo) -> Result<(), String> {
        let mut challenge = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut challenge);

        let raw_id: Vec<u8> = (0..self.agent_id.len() / 2)
            .map(|i| u8::from_str_radix(&self.agent_id[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();

        let enc_challenge = crate::protocol::crypto::rsa_encrypt_oaep(&self.rsa_pub_pem, &challenge)
            .map_err(|e| format!("encrypt challenge: {e}"))?;
        let mut payload = Vec::with_capacity(raw_id.len() + enc_challenge.len());
        payload.extend_from_slice(&raw_id);
        payload.extend_from_slice(&enc_challenge);

        io.write_packet_flush(&Packet::new(TYPE_RCP_HELLO, payload))?;
        let ack = io.read_packet_timeout(Duration::from_secs(10))?;
        if ack.ptype != TYPE_RCP_ACK {
            return Err(format!("rcp handshake rejected (type {:#04x})", ack.ptype));
        }
        let dec = self.keys.decrypt(&ack.payload).map_err(|e| e.to_string())?;
        if dec != challenge {
            return Err("rcp handshake challenge mismatch".into());
        }
        Ok(())
    }

    /// Close the channel and stop the loops.
    pub fn close(&self) {
        self.running.store(false, Ordering::SeqCst);
        match &*self.conn.lock().unwrap() {
            RcpHandle::Tcp(c) => {
                let mut guard = c.lock().unwrap();
                if let Some(mut s) = guard.take() {
                    let _ = write_packet(&mut s, &Packet::new(TYPE_RCP_CLOSE, Vec::new()));
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            }
            RcpHandle::Kcp(c) => {
                let mut guard = c.lock().unwrap();
                if let Some(mut io) = guard.take() {
                    let _ = io.write_packet_flush(&Packet::new(TYPE_RCP_CLOSE, Vec::new()));
                }
            }
        }
    }
}

/// TCP frame loop: capture → encrypt → write one RCP frame packet.
fn frame_loop(
    conn: &Arc<Mutex<Option<TcpStream>>>,
    keys: &SessionKeys,
    capture: Option<&CaptureFn>,
    quality: u8,
    interval: Duration,
    running: Arc<AtomicBool>,
) {
    let mut seq: u64 = 0;
    let mut err_count: u32 = 0;
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(interval);
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let frame = match capture {
            Some(f) => f(quality),
            None => Err("screen capture is not configured".into()),
        };
        let (jpeg, w, h) = match frame {
            Ok(v) => {
                err_count = 0;
                v
            }
            Err(e) => {
                err_count += 1;
                if err_count == 1 {
                    let _ = send_rcp_tcp(conn, keys, TYPE_RCP_ERROR, e.as_bytes());
                }
                if err_count >= 30 {
                    running.store(false, Ordering::SeqCst);
                    if let Some(c) = conn.lock().unwrap().take() {
                        let _ = c.shutdown(std::net::Shutdown::Both);
                    }
                }
                continue;
            }
        };
        seq += 1;
        let enc = keys.encrypt(&encode_frame(seq, w, h, &jpeg));
        let pkt = Packet::new(TYPE_RCP_FRAME, enc);
        let mut guard = conn.lock().unwrap();
        if let Some(c) = guard.as_mut() {
            c.set_write_timeout(Some(Duration::from_secs(2))).ok();
            if write_packet(c, &pkt).is_err() {
                running.store(false, Ordering::SeqCst);
            }
            c.flush().ok();
        }
    }
}

/// KCP frame loop: same, but writes over the shared KcpIo under the lock.
fn frame_loop_kcp(
    conn: &Arc<Mutex<Option<KcpIo>>>,
    keys: &SessionKeys,
    capture: Option<&CaptureFn>,
    quality: u8,
    interval: Duration,
    running: Arc<AtomicBool>,
) {
    let mut seq: u64 = 0;
    let mut err_count: u32 = 0;
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(interval);
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let frame = match capture {
            Some(f) => f(quality),
            None => Err("screen capture is not configured".into()),
        };
        let (jpeg, w, h) = match frame {
            Ok(v) => {
                err_count = 0;
                v
            }
            Err(e) => {
                err_count += 1;
                if err_count == 1 {
                    let _ = send_rcp_kcp(conn, keys, TYPE_RCP_ERROR, e.as_bytes());
                }
                if err_count >= 30 {
                    running.store(false, Ordering::SeqCst);
                    conn.lock().unwrap().take();
                }
                continue;
            }
        };
        seq += 1;
        let enc = keys.encrypt(&encode_frame(seq, w, h, &jpeg));
        let pkt = Packet::new(TYPE_RCP_FRAME, enc);
        let mut guard = conn.lock().unwrap();
        if let Some(io) = guard.as_mut() {
            if io.write_packet_flush(&pkt).is_err() {
                running.store(false, Ordering::SeqCst);
            }
        }
    }
}

fn encode_frame(seq: u64, w: u32, h: u32, jpeg: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(RCP_FRAME_SIZE + jpeg.len());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&w.to_be_bytes());
    p.extend_from_slice(&h.to_be_bytes());
    p.extend_from_slice(jpeg);
    p
}

/// TCP read loop: block on packets, dispatch input/ping/close.
fn read_loop_tcp(
    conn: Arc<Mutex<Option<TcpStream>>>,
    running: Arc<AtomicBool>,
    keys: SessionKeys,
    on_input: Option<InputFn>,
) {
    while running.load(Ordering::SeqCst) {
        let Some(c) = conn.lock().unwrap().as_ref().map(|c| c.try_clone().unwrap())
        else {
            break;
        };
        let mut tmp = c;
        tmp.set_read_timeout(Some(Duration::from_secs(45))).ok();
        let pkt = match read_packet(&mut tmp) {
            Ok(p) => p,
            Err(_) => {
                running.store(false, Ordering::SeqCst);
                break;
            }
        };
        if !dispatch_packet(&pkt, &keys, &on_input) {
            break;
        }
    }
    if let Some(c) = conn.lock().unwrap().take() {
        let _ = c.shutdown(std::net::Shutdown::Both);
    }
}

/// KCP pump loop: drive UDP→KCP, reassemble packet stream, dispatch messages.
/// Uses a lightweight incremental parser (KCP is a byte stream, so a packet may
/// span chunks).
fn pump_loop_kcp(
    conn: Arc<Mutex<Option<KcpIo>>>,
    running: Arc<AtomicBool>,
    keys: SessionKeys,
    on_input: Option<InputFn>,
) {
    use crate::protocol::{HEADER_SIZE, MAGIC, MAX_PACKET_SIZE};
    let mut buf: Vec<u8> = Vec::new();
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(5));
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let mut guard = conn.lock().unwrap();
        let Some(io) = guard.as_mut() else { break };
        if io.pump_public().is_err() {
            running.store(false, Ordering::SeqCst);
            break;
        }
        while let Some(chunk) = io.recv_available() {
            buf.extend_from_slice(&chunk);
        }
        drop(guard);

        // Parse complete packets out of the accumulated stream.
        loop {
            if buf.len() < HEADER_SIZE {
                break;
            }
            if buf[0..4] != MAGIC {
                running.store(false, Ordering::SeqCst);
                break;
            }
            let size = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
            if size > MAX_PACKET_SIZE {
                running.store(false, Ordering::SeqCst);
                break;
            }
            let total = HEADER_SIZE + size;
            if buf.len() < total {
                break;
            }
            let pkt = Packet {
                ptype: buf[HEADER_SIZE - 1],
                payload: buf[HEADER_SIZE..total].to_vec(),
            };
            buf.drain(..total);
            if !dispatch_packet(&pkt, &keys, &on_input) {
                running.store(false, Ordering::SeqCst);
                return;
            }
        }
    }
    conn.lock().unwrap().take();
}

fn dispatch_packet(pkt: &Packet, keys: &SessionKeys, on_input: &Option<InputFn>) -> bool {
    match pkt.ptype {
        TYPE_RCP_INPUT => {
            if let Ok(dec) = keys.decrypt(&pkt.payload) {
                if let Some(f) = on_input {
                    f(String::from_utf8_lossy(&dec).into_owned());
                }
            }
            true
        }
        TYPE_RCP_PING => true,
        TYPE_RCP_CLOSE => false,
        _ => true,
    }
}

/// Send one packet encrypted with the session keys (TCP; error/close path).
fn send_rcp_tcp(
    conn: &Arc<Mutex<Option<TcpStream>>>,
    keys: &SessionKeys,
    ptype: u8,
    plaintext: &[u8],
) -> Result<(), String> {
    let enc = keys.encrypt(plaintext);
    let mut guard = conn.lock().unwrap();
    if let Some(c) = guard.as_mut() {
        c.set_write_timeout(Some(Duration::from_secs(2))).ok();
        write_packet(c, &Packet::new(ptype, enc)).map_err(|e| e.to_string())?;
        c.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Send one packet encrypted with the session keys (KCP; error/close path).
fn send_rcp_kcp(
    conn: &Arc<Mutex<Option<KcpIo>>>,
    keys: &SessionKeys,
    ptype: u8,
    plaintext: &[u8],
) -> Result<(), String> {
    let enc = keys.encrypt(plaintext);
    let mut guard = conn.lock().unwrap();
    if let Some(io) = guard.as_mut() {
        io.write_packet_flush(&Packet::new(ptype, enc))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::RCP_FRAME_SIZE;

    fn encode_frame(seq: u64, w: u32, h: u32, jpeg: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(RCP_FRAME_SIZE + jpeg.len());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&w.to_be_bytes());
        p.extend_from_slice(&h.to_be_bytes());
        p.extend_from_slice(jpeg);
        p
    }

    #[test]
    fn frame_layout_matches_go() {
        // Matches Go EncodeRCPFrame/DecodeRCPFrame: seq(8 BE)+w(4)+h(4)+jpeg.
        let jpeg = vec![0xFF, 0xD8, 1, 2, 3, 0xFF, 0xD9];
        let p = encode_frame(7, 1920, 1080, &jpeg);
        assert_eq!(p.len(), RCP_FRAME_SIZE + jpeg.len());
        assert_eq!(u64::from_be_bytes(p[0..8].try_into().unwrap()), 7);
        assert_eq!(u32::from_be_bytes(p[8..12].try_into().unwrap()), 1920);
        assert_eq!(u32::from_be_bytes(p[12..16].try_into().unwrap()), 1080);
        assert_eq!(&p[16..], &jpeg[..]);
    }
}
