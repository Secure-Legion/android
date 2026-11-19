pub mod crypto;
pub mod crdt;
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub mod audio;
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub mod network;
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub mod nlx402;
pub mod util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_version() -> &'static str {
    VERSION
}
