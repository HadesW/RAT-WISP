// TLS helpers for the agent's HTTPS transport. The C2 server uses a self-signed
// cert generated at first startup; the Go agent connects with
// InsecureSkipVerify. We mirror that with a rustls verifier that accepts any
// server certificate (the C2 channel already provides end-to-end secrecy via
// the session keys on top of TLS, so transport-layer trust is not required).

use ureq::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use ureq::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use ureq::rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::sync::Arc;

#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build a rustls client config that trusts any server certificate (self-signed
/// C2 servers), with TLS 1.2+ like the Go server (MinVersion TLS12).
pub fn insecure_tls_config() -> Arc<ureq::rustls::ClientConfig> {
    use ureq::rustls::ClientConfig;
    let builder = ClientConfig::builder();
    // Default provider verifies chain; we replace the verifier below.
    let cfg = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Build an agent that accepts self-signed certs (mirrors Go InsecureSkipVerify).
pub fn insecure_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .tls_config(insecure_tls_config())
        .timeout_connect(std::time::Duration::from_secs(15))
        .timeout_read(std::time::Duration::from_secs(60))
        .timeout_write(std::time::Duration::from_secs(15))
        .build()
}
