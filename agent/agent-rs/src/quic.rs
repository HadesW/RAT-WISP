// Type1 over QUIC (plan P6, feature "quic"): quinn + rustls, one dial per
// envelope round-trip with the shared magic framing — same shape as the TCP
// path, so the register/heartbeat/result loop is transport-agnostic. The
// server certificate is skipped (self-signed, plan §3); trust comes from the
// RSA pubkey bootstrap exactly like plaintext TCP. Feature-gated per plan
// decision #7: payload templates enable it, default builds stay lean.
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rsa::RsaPublicKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::Deserialize;
use tokio::runtime::Runtime;

use crate::crypto::parse_public_key;
use crate::envelope::{Envelope, MSG_PUBKEY};
use crate::transport::{MAGIC, MAX_PACKET, TYPE_ENVELOPE};

const ALPN: &[u8] = b"wisp";
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Quic {
    servers: Vec<String>, // quic://host:port
    rt: Runtime,
    cfg: ClientConfig,
}

impl Quic {
    pub fn new(servers: Vec<String>) -> Result<Self, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("quic: runtime: {e}"))?;
        let cfg = client_config()?;
        Ok(Self { servers, rt, cfg })
    }

    pub fn exchange(&self, env: &Envelope) -> Result<Envelope, String> {
        let payload = env.marshal();
        let mut last = String::from("transport: no quic servers");
        for s in &self.servers {
            let target = match resolve(s) {
                Ok(t) => t,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            match self
                .rt
                .block_on(round_trip(&self.cfg, target, TYPE_ENVELOPE, &payload))
            {
                Ok(raw) => {
                    return serde_json::from_slice(&raw).map_err(|e| format!("envelope: {e}"))
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    pub fn pubkey(&self) -> Result<RsaPublicKey, String> {
        // Plain pubkey envelope: the QUIC listener only carries TypeEnvelope
        // (no TypeRequestKey bootstrap frames), same as the Go agent.
        let env = Envelope::plain(MSG_PUBKEY, "", serde_json::Value::Null);
        let resp = self.exchange(&env)?;
        #[derive(Deserialize)]
        struct PubkeyInfo {
            #[serde(default)]
            pem: String,
        }
        let info: PubkeyInfo = serde_json::from_value(resp.d.unwrap_or_default())
            .map_err(|e| format!("pubkey response: {e}"))?;
        parse_public_key(&info.pem)
    }
}

struct Target {
    addr: SocketAddr,
    server_name: String,
}

fn resolve(server: &str) -> Result<Target, String> {
    let raw = server.strip_prefix("quic://").unwrap_or(server);
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| format!("transport: bad quic server {server:?} (want quic://host:port)"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("transport: bad quic port in {server:?}"))?;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("resolve {host}: no addresses"))?;
    Ok(Target {
        addr,
        server_name: host.trim_matches(|c| c == '[').to_string(),
    })
}

// round_trip dials fresh, opens one bidi stream, sends one framed packet and
// reads the framed reply — then closes the connection (beacon cadence makes
// connection reuse not worth the state; QUIC handshake is 1-RTT).
async fn round_trip(
    cfg: &ClientConfig,
    target: Target,
    typ: u8,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let bind: SocketAddr = if target.addr.is_ipv6() {
            "[::]:0".parse().expect("static")
        } else {
            "0.0.0.0:0".parse().expect("static")
        };
        let mut endpoint =
            Endpoint::client(bind).map_err(|e| format!("quic: endpoint: {e}"))?;
        endpoint.set_default_client_config(cfg.clone());
        let conn = tokio::time::timeout(DIAL_TIMEOUT, async {
            endpoint
                .connect(target.addr, &target.server_name)
                .map_err(|e| format!("quic: connect {}: {e}", target.addr))?
                .await
                .map_err(|e| format!("quic: handshake {}: {e}", target.addr))
        })
        .await
        .map_err(|_| format!("quic: connect timeout to {}", target.addr))??;

        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.push(typ);
        frame.extend_from_slice(payload);

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("quic: open stream: {e}"))?;
        send.write_all(&frame)
            .await
            .map_err(|e| format!("quic: write: {e}"))?;
        // Half-close tells the server the request is complete; it answers on
        // the same stream and closes its side.
        let _ = send.finish();

        let mut hdr = [0u8; 9];
        recv.read_exact(&mut hdr)
            .await
            .map_err(|e| format!("quic: read header: {e}"))?;
        if hdr[0..4] != MAGIC {
            return Err(format!("quic: invalid magic: {:x?}", &hdr[0..4]));
        }
        let size = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        if size > MAX_PACKET {
            return Err(format!("quic: packet too large: {size}"));
        }
        let mut out = vec![0u8; size];
        recv.read_exact(&mut out)
            .await
            .map_err(|e| format!("quic: read payload: {e}"))?;
        if hdr[8] != TYPE_ENVELOPE {
            return Err(format!("quic: unexpected packet type {:#x}", hdr[8]));
        }
        conn.close(0u32.into(), b"");
        Ok(out)
    })
    .await
    .map_err(|_| "quic: exchange timeout".to_string())?
}

fn client_config() -> Result<ClientConfig, String> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|e| format!("quic: tls config: {e}"))?;
    Ok(ClientConfig::new(Arc::new(crypto)))
}

// SkipServerVerification accepts any certificate: the transport only provides
// confidentiality, server authenticity comes from the RSA pubkey bootstrap
// (same trust model as plaintext TCP with InsecureSkipVerify-style agents).
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::MSG_PUBKEY;
    use quinn::crypto::rustls::QuicServerConfig;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use std::sync::mpsc;

    // server_config builds a quinn server with an rcgen self-signed cert and
    // the same ALPN the agent offers.
    fn server_config() -> quinn::ServerConfig {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key.into())
            .unwrap();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = QuicServerConfig::try_from(tls).unwrap();
        quinn::ServerConfig::with_crypto(Arc::new(crypto))
    }

    // serve_once accepts one connection + one stream, answers every framed
    // envelope with `reply`, then idles until the client closes.
    fn serve_once(reply: Envelope) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let (addr_tx, addr_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let endpoint = quinn::Endpoint::server(
                    server_config(),
                    "127.0.0.1:0".parse().expect("static"),
                )
                .expect("server endpoint");
                addr_tx.send(endpoint.local_addr().expect("local addr")).unwrap();
                let conn = endpoint.accept().await.expect("incoming").await.expect("conn");
                let (mut send, mut recv) = conn.accept_bi().await.expect("stream");
                let mut hdr = [0u8; 9];
                recv.read_exact(&mut hdr).await.expect("req header");
                assert_eq!(hdr[0..4], MAGIC);
                let size = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
                let mut payload = vec![0u8; size];
                recv.read_exact(&mut payload).await.expect("req payload");
                let raw = reply.marshal();
                let mut frame = Vec::with_capacity(9 + raw.len());
                frame.extend_from_slice(&MAGIC);
                frame.extend_from_slice(&(raw.len() as u32).to_le_bytes());
                frame.push(TYPE_ENVELOPE);
                frame.extend_from_slice(&raw);
                send.write_all(&frame).await.expect("resp write");
                send.finish().expect("resp finish");
                conn.closed().await;
            });
        });
        let addr = addr_rx.recv_timeout(Duration::from_secs(5)).expect("server addr");
        (addr, handle)
    }

    #[test]
    fn exchange_roundtrip() {
        let reply = Envelope::plain("checkin", "", serde_json::json!({"ok": true}));
        let (addr, server) = serve_once(reply);
        let q = Quic::new(vec![format!("quic://{addr}")]).unwrap();
        let out = q
            .exchange(&Envelope::plain("checkin", "", serde_json::Value::Null))
            .unwrap();
        assert_eq!(out.t, "checkin");
        assert_eq!(out.d.unwrap()["ok"], true);
        server.join().unwrap();
    }

    #[test]
    fn pubkey_bootstrap() {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = rsa::RsaPublicKey::from(&key)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let reply = Envelope::plain(
            MSG_PUBKEY,
            "",
            serde_json::json!({ "pem": pem }),
        );
        let (addr, server) = serve_once(reply);
        let q = Quic::new(vec![format!("quic://{addr}")]).unwrap();
        let got = q.pubkey().unwrap();
        assert_eq!(got.n().bits(), 2048);
        server.join().unwrap();
    }

    #[test]
    fn bad_scheme_is_rejected() {
        assert!(resolve("quic://no-port").is_err());
        assert!(resolve("quic://127.0.0.1:notaport").is_err());
    }

    #[test]
    fn unreachable_server_errors() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed unroutable, and the
        // dial timeout keeps this fast.
        let q = Quic::new(vec!["quic://192.0.2.1:4433".to_string()]).unwrap();
        let err = q
            .exchange(&Envelope::plain("checkin", "", serde_json::Value::Null))
            .unwrap_err();
        assert!(err.contains("quic"), "{err}");
    }
}
