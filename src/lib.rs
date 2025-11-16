pub mod crypto;
pub mod protocol;
pub mod network;
pub mod blockchain;
pub mod ffi;

// Re-export main types
pub use crypto::{
    encrypt_message, decrypt_message,
    sign_data, verify_signature, generate_keypair,
    derive_shared_secret, hash_password, hash_handle,
};

pub use protocol::{Message, ContactCard, SecurityMode, MessageType};
pub use network::{PingToken, PongToken, PingPongManager, TorManager};
pub use blockchain::{register_username, lookup_username, EncryptedContactCard};

// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get library version
pub fn get_version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }
}
