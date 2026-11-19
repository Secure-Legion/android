pub mod encryption;
pub mod ack_state;
pub mod pin;

// Re-export public crypto from securelegion-crypto
pub use securelegion_crypto::crypto::signing;
pub use securelegion_crypto::crypto::key_exchange;
pub use securelegion_crypto::crypto::hashing;
pub use securelegion_crypto::crypto::pqc;
pub use securelegion_crypto::crypto::replay_cache;
#[cfg(feature = "range-proofs")]
pub use securelegion_crypto::crypto::zkproofs;

// Re-export the same public API the old mod.rs had
pub use securelegion_crypto::crypto::signing::{sign_data, verify_signature, generate_keypair};
pub use securelegion_crypto::crypto::key_exchange::{derive_shared_secret, generate_ephemeral_key};
pub use securelegion_crypto::crypto::hashing::{hash_password, hash_handle};
pub use securelegion_crypto::crypto::pqc::{
    generate_hybrid_keypair_from_seed,
    hybrid_encapsulate,
    hybrid_decapsulate,
    HybridKEMKeypair,
    HybridCiphertext,
};
#[cfg(feature = "range-proofs")]
pub use securelegion_crypto::crypto::zkproofs::{generate_range_proof, verify_range_proof};

pub use encryption::{
    encrypt_message,
    decrypt_message,
    derive_root_key,
    evolve_chain_key,
    derive_message_key,
    encrypt_message_with_evolution,
    decrypt_message_with_evolution,
    derive_receive_key_at_sequence,
};

pub use pin::{decrypt_pin_payload, encrypt_pin_payload};
