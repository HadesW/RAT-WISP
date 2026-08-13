// Codec trait — the pluggable wire-format / crypto layer.
//
// DEFAULT implementation = Go-compatible AES-256-CTR + HMAC-SHA256 (crypto.rs).
// The trait is the extension point for future Malleable-profile transforms or
// script-defined codecs (Lua/WASM): an agent can be built with a different
// Codec that still uses the same packet/HTTP framing, only the payload
// transform changes. This mirrors the plan's "数据包加解密可插拔" design.

/// Transform a plaintext payload into wire bytes (e.g. encrypt + MAC).
pub trait Codec: Send + Sync {
    /// Encode plaintext → transport bytes.
    fn encode(&self, plaintext: &[u8]) -> Vec<u8>;
    /// Decode transport bytes → plaintext, verifying integrity.
    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Clone into a boxed trait object.
    fn boxed(&self) -> Box<dyn Codec>;
}

/// Default codec: AES-256-CTR + HMAC-SHA256, exactly matching Go
/// shared/protocol/crypto.go. IV(16)+CT(N)+HMAC(32).
pub struct DefaultCodec {
    pub aes_key: [u8; 32],
    pub hmac_key: [u8; 32],
}

impl DefaultCodec {
    pub fn new(aes_key: [u8; 32], hmac_key: [u8; 32]) -> Self {
        DefaultCodec { aes_key, hmac_key }
    }
}

impl Codec for DefaultCodec {
    fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        use crate::protocol::crypto::SessionKeys;
        SessionKeys { aes_key: self.aes_key, hmac_key: self.hmac_key }.encrypt(plaintext)
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use crate::protocol::crypto::SessionKeys;
        SessionKeys { aes_key: self.aes_key, hmac_key: self.hmac_key }.decrypt(data)
    }

    fn boxed(&self) -> Box<dyn Codec> {
        Box::new(DefaultCodec::new(self.aes_key, self.hmac_key))
    }
}
