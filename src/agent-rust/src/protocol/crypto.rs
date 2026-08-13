// Session encryption — MUST interop with Go shared/protocol/crypto.go.
//
// Encrypt output format: IV(16) + Ciphertext(N) + HMAC(32)
//   - AES-256-CTR with random 16-byte IV
//   - HMAC-SHA256 keyed with a separate 32-byte HMAC key, computed over
//     IV+Ciphertext (NOT the plaintext, matching Go).
//
// RSA: OAEP with SHA-256, matching Go rsa.EncryptOAEP(sha256.New(), ...).

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::{Digest, Sha256};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

pub const AES_KEY_LEN: usize = 32;
pub const HMAC_KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const HMAC_LEN: usize = 32;

#[derive(Clone)]
pub struct SessionKeys {
    pub aes_key: [u8; AES_KEY_LEN],
    pub hmac_key: [u8; HMAC_KEY_LEN],
}

impl SessionKeys {
    pub fn generate() -> Self {
        let mut aes_key = [0u8; AES_KEY_LEN];
        let mut hmac_key = [0u8; HMAC_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut aes_key);
        rand::rngs::OsRng.fill_bytes(&mut hmac_key);
        SessionKeys { aes_key, hmac_key }
    }

    /// Encrypt plaintext → IV(16) + ciphertext(N) + HMAC(32).
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; IV_LEN];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        let mut cipher = Aes256Ctr::new(&self.aes_key.into(), &iv.into());
        let mut ct = plaintext.to_vec();
        cipher.apply_keystream(&mut ct);

        let mut out = Vec::with_capacity(IV_LEN + ct.len() + HMAC_LEN);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key).unwrap();
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());

        out
    }

    /// Decrypt IV(16) + ciphertext(N) + HMAC(32), verifying HMAC first.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < IV_LEN + HMAC_LEN {
            return Err("ciphertext too short".into());
        }
        let mac_start = data.len() - HMAC_LEN;
        let received_mac = &data[mac_start..];
        let iv_and_ct = &data[..mac_start];

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key).unwrap();
        mac.update(iv_and_ct);
        let expected = mac.finalize().into_bytes();
        if received_mac != expected.as_slice() {
            return Err("HMAC verification failed".into());
        }

        let iv: [u8; IV_LEN] = iv_and_ct[..IV_LEN].try_into().unwrap();
        let ct = &iv_and_ct[IV_LEN..];
        let mut cipher = Aes256Ctr::new(&self.aes_key.into(), &iv.into());
        let mut pt = ct.to_vec();
        cipher.apply_keystream(&mut pt);
        Ok(pt)
    }
}

/// RSA OAEP-SHA256 encrypt with a PEM PKIX public key (matches Go).
pub fn rsa_encrypt_oaep(pub_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let pub_key = RsaPublicKey::from_public_key_pem(pub_pem)
        .map_err(|e| format!("parse public key: {e}"))?;
    let oaep = Oaep::new::<Sha256>();
    pub_key
        .encrypt(&mut rand::rngs::OsRng, oaep, plaintext)
        .map_err(|e| format!("rsa encrypt: {e}"))
}

/// SHA-256 helper (used for message digests where needed).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let keys = SessionKeys::generate();
        let pt = b"hello world, this is a test payload";
        let enc = keys.encrypt(pt);
        assert_eq!(enc.len(), IV_LEN + pt.len() + HMAC_LEN);
        let dec = keys.decrypt(&enc).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn tamper_detected() {
        let keys = SessionKeys::generate();
        let pt = b"integrity test";
        let mut enc = keys.encrypt(pt);
        enc[IV_LEN] ^= 0xff; // flip a ciphertext byte
        assert!(keys.decrypt(&enc).is_err());
    }
}
