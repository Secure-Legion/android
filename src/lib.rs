pub mod crypto;
pub mod crdt;
pub mod audio;
pub mod network;
pub mod nlx402;
pub mod util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_version() -> &'static str {
    VERSION
}
