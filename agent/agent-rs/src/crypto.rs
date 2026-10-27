// Session-layer crypto shared with the Go teamserver (plan §3):
// RSA-OAEP(SHA-256) key exchange, then IV || AES-256-CTR(ct) || HMAC-SHA256.
use aes::Aes256;
use ctr::{
    cipher::{KeyIvInit, StreamCipher},
    Ctr128BE,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct SessionKey {
    pub enc: [u8; 32],
    pub mac: [u8; 32],
    pub id: [u8; 16],
}

impl SessionKey {
    pub fn random() -> Self {
        let mut b = [0u8; 80];
        rand::thread_rng().fill_bytes(&mut b);
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        let mut id = [0u8; 16];
        enc.copy_from_slice(&b[0..32]);
        mac.copy_from_slice(&b[32..64]);
        id.copy_from_slice(&b[64..80]);
        Self { enc, mac, id }
    }

    pub fn blob(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(80);
        b.extend_from_slice(&self.enc);
        b.extend_from_slice(&self.mac);
        b.extend_from_slice(&self.id);
        b
    }

    pub fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let mut ct = plain.to_vec();
        let mut c = Ctr128BE::<Aes256>::new((&self.enc).into(), (&iv).into());
        c.apply_keystream(&mut ct);
        let mut m = HmacSha256::new_from_slice(&self.mac).expect("hmac key");
        m.update(&iv);
        m.update(&ct);
        let tag = m.finalize().into_bytes();
        let mut out = Vec::with_capacity(16 + ct.len() + 32);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        out
    }

    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 48 {
            return None;
        }
        let (iv, rest) = sealed.split_at(16);
        let (ct, tag) = rest.split_at(rest.len() - 32);
        let mut m = HmacSha256::new_from_slice(&self.mac).ok()?;
        m.update(iv);
        m.update(ct);
        m.verify_slice(tag).ok()?;
        let mut pt = ct.to_vec();
        let mut c = Ctr128BE::<Aes256>::new((&self.enc).into(), iv.into());
        c.apply_keystream(&mut pt);
        Some(pt)
    }
}

pub fn psk_proof(psk: &str, agent: &str, key_id: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(psk.as_bytes()).expect("psk");
    m.update(agent.as_bytes());
    m.update(&[0x7c]);
    m.update(hex::encode(key_id).as_bytes());
    m.finalize().into_bytes().to_vec()
}

pub fn parse_public_key(pem: &str) -> Result<RsaPublicKey, String> {
    RsaPublicKey::from_public_key_pem(pem).map_err(|e| format!("parse public key: {e}"))
}

pub fn wrap_session_key(pub_key: &RsaPublicKey, sk: &SessionKey) -> Result<Vec<u8>, String> {
    let mut rng = rand::thread_rng();
    pub_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &sk.blob())
        .map_err(|e| format!("oaep encrypt: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip() {
        let sk = SessionKey::random();
        let msg = b"hello wisp";
        let sealed = sk.seal(msg);
        assert_eq!(sealed.len(), 16 + msg.len() + 32);
        assert_eq!(sk.open(&sealed).unwrap(), msg);
    }

    #[test]
    fn tamper_is_rejected() {
        let sk = SessionKey::random();
        let mut sealed = sk.seal(b"payload");
        let n = sealed.len();
        sealed[n - 1] ^= 1;
        assert!(sk.open(&sealed).is_none());
    }

    #[test]
    fn psk_proof_is_stable() {
        let id = [0xabu8; 16];
        assert_eq!(
            hex::encode(psk_proof("psk", "agent01", &id)),
            hex::encode(psk_proof("psk", "agent01", &id))
        );
        assert_ne!(
            hex::encode(psk_proof("psk", "agent01", &id)),
            hex::encode(psk_proof("psk", "agent01", &[0u8; 16]))
        );
    }
}
