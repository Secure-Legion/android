pub mod crypto;
pub mod crdt;
#[cfg(not(target_os = "windows"))]
pub mod audio;
#[cfg(not(target_os = "windows"))]
pub mod network;
#[cfg(not(target_os = "windows"))]
pub mod nlx402;
pub mod util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_version() -> &'static str {
    VERSION
}
