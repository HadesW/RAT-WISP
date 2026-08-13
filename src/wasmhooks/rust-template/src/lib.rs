//! WISP Rust/WASM hook module template.
//!
//! ABI implemented by every hook module (see services/wasmhook/wasmhook.go):
//!
//! ```text
//! wisp_alloc(size: i32) -> i32        allocate linear memory
//! wisp_handle(ptr: i32, len: i32) -> i32   input JSON -> output JSON ptr
//! wisp_handle_len() -> i32            length of the output JSON
//! ```
//!
//! The host writes the input JSON at `ptr`, calls `wisp_handle`, then reads
//! `wisp_handle_len()` bytes at the returned pointer.
//!
//! JSON shape (in and out):
//! ```json
//! { "event": "listener:checkin", "phase": "pre",
//!   "abort": false,
//!   "input": { "ip": "...", "path": "...", ... },
//!   "output": { "response_headers": { ... } } }
//! ```
//!
//! Mutate `input` / `output` / `abort` in the output JSON to shape the C2.

use std::alloc::{alloc, dealloc, Layout};
use std::mem;

use serde::{Deserialize, Serialize};

/// Mirror of the host's hook context.
#[derive(Serialize, Deserialize, Clone)]
struct HookContext {
    event: String,
    phase: String,
    #[serde(default)]
    abort: bool,
    #[serde(default)]
    input: serde_json::Value,
    #[serde(default)]
    output: serde_json::Value,
}

// ---- bump allocator over the module's linear memory -------------------------

static mut HEAP: [u8; 256 * 1024] = [0u8; 256 * 1024];
static mut HEAP_OFF: usize = 0;

/// `wisp_alloc` — bump-allocate `size` bytes, return the linear-memory offset.
#[no_mangle]
pub extern "C" fn wisp_alloc(size: i32) -> i32 {
    unsafe {
        let n = size as usize;
        if HEAP_OFF + n > HEAP.len() {
            return 0;
        }
        let p = HEAP_OFF;
        HEAP_OFF += n;
        p as i32
    }
}

static mut OUT_PTR: i32 = 0;
static mut OUT_LEN: i32 = 0;

/// `wisp_handle` — transform the input JSON and write the output JSON back
/// into module memory, returning its pointer.
#[no_mangle]
pub extern "C" fn wisp_handle(ptr: i32, len: i32) -> i32 {
    unsafe {
        let input = core::slice::from_raw_parts(HEAP.as_ptr().add(ptr as usize), len as usize);
        let out = match handle(serde_json::from_slice::<HookContext>(input)) {
            Ok(res) => res,
            Err(e) => {
                // On parse failure return a no-op context so the C2 stays up.
                let noop = HookContext {
                    event: String::new(),
                    phase: String::new(),
                    abort: false,
                    input: serde_json::Value::Null,
                    output: serde_json::Value::Null,
                };
                let _ = e;
                noop
            }
        };
        let bytes = serde_json::to_vec(&out).unwrap_or_default();
        OUT_LEN = bytes.len() as i32;
        let p = wisp_alloc(OUT_LEN) as usize;
        HEAP[p..p + bytes.len()].copy_from_slice(&bytes);
        OUT_PTR = p as i32;
        OUT_PTR
    }
}

/// `wisp_handle_len` — length of the output JSON written by the last handle.
#[no_mangle]
pub extern "C" fn wisp_handle_len() -> i32 {
    unsafe { OUT_LEN }
}

/// User logic. Implement your traffic shaping / command rewrite here.
fn handle(mut ctx: HookContext) -> Result<HookContext, String> {
    // Example: add an "X-Wasm" response header on checkins.
    if ctx.event == "listener:checkin" {
        if let Some(output) = ctx.output.as_object_mut() {
            let headers = output
                .entry("response_headers")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(h) = headers.as_object_mut() {
                h.insert("X-Wasm".into(), serde_json::json!("rust-module"));
            }
        }
    }

    // Example: abort any checkin from a blocklisted IP.
    if let Some(ip) = ctx.input.get("ip").and_then(|v| v.as_str()) {
        if ip == "10.0.0.66" {
            ctx.abort = true;
        }
    }

    Ok(ctx)
}
