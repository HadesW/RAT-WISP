pub mod http;
pub mod kcp;
pub mod quic;
pub mod rcp;
pub mod tcp;
pub mod tls;

use std::io;

/// Shared transport error (both HTTP and TCP transports).
#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Status(u16, String),
    Reauth,
    Other(String),
}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        TransportError::Io(e)
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "io: {e}"),
            TransportError::Status(c, m) => write!(f, "status {c}: {m}"),
            TransportError::Reauth => write!(f, "reauth required"),
            TransportError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Abstract agent transport: register + checkin (HTTP or TCP).
pub trait AgentTransport {
    fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError>;
    fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError>;
    fn reset_seq(&mut self);
    /// Negotiated AES/HMAC session keys (for the RCP channel).
    fn session_keys(&self) -> Option<crate::protocol::crypto::SessionKeys>;
    /// The RSA public key in use (fetched from the server if none was built in).
    fn rsa_pub_pem(&self) -> String;
}

impl AgentTransport for http::HttpTransport {
    fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        self.register(reg_json)
    }
    fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        self.checkin(results)
    }
    fn reset_seq(&mut self) {
        self.reset_seq()
    }
    fn session_keys(&self) -> Option<crate::protocol::crypto::SessionKeys> {
        self.session_keys.clone()
    }
    fn rsa_pub_pem(&self) -> String {
        self.rsa_pub_pem.clone()
    }
}

impl AgentTransport for tcp::TcpTransport {
    fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        self.register(reg_json)
    }
    fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        self.checkin(results)
    }
    fn reset_seq(&mut self) {
        self.reset_seq()
    }
    fn session_keys(&self) -> Option<crate::protocol::crypto::SessionKeys> {
        self.session_keys.clone()
    }
    fn rsa_pub_pem(&self) -> String {
        self.rsa_pub_pem.clone()
    }
}

impl AgentTransport for quic::QuicTransport {
    fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        self.register(reg_json)
    }
    fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        self.checkin(results)
    }
    fn reset_seq(&mut self) {
        self.reset_seq()
    }
    fn session_keys(&self) -> Option<crate::protocol::crypto::SessionKeys> {
        self.session_keys.clone()
    }
    fn rsa_pub_pem(&self) -> String {
        self.rsa_pub_pem.clone()
    }
}

impl AgentTransport for kcp::KcpTransport {
    fn register(&mut self, reg_json: &[u8]) -> Result<(), TransportError> {
        self.register(reg_json)
    }
    fn checkin(&mut self, results: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        self.checkin(results)
    }
    fn reset_seq(&mut self) {
        self.reset_seq()
    }
    fn session_keys(&self) -> Option<crate::protocol::crypto::SessionKeys> {
        self.session_keys.clone()
    }
    fn rsa_pub_pem(&self) -> String {
        self.rsa_pub_pem.clone()
    }
}
