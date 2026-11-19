pub mod crypto;
pub mod protocol;
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub mod network;
#[cfg(feature = "platform-ffi")]
pub mod ffi;

// Re-export public crate modules
pub use securelegion_crypto;
pub use securelegion_crypto::crdt;
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub use securelegion_crypto::audio;
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub use securelegion_crypto::nlx402;
pub use securelegion_crypto::util;

// Re-export main types
pub use crypto::{
    encrypt_message, decrypt_message,
    sign_data, verify_signature, generate_keypair,
    derive_shared_secret, hash_password, hash_handle,
};

pub use protocol::{Message, ContactCard, SecurityMode, MessageType};
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub use network::{PingToken, PongToken, PingPongManager, TorManager};
#[cfg(all(not(target_os = "windows"), feature = "mobile-network"))]
pub use nlx402::{PaymentQuote, create_quote, verify_payment, verify_payment_simple, extract_quote_hash_from_memo, VerificationResult};

// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get library version
pub fn get_version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_version() {
        assert!(!super::VERSION.is_empty());
    }
}
