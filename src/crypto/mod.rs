pub mod encryption;
pub mod signing;
pub mod key_exchange;
pub mod hashing;
pub mod pqc;
pub mod replay_cache;
pub mod ack_state;

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
pub use signing::{sign_data, verify_signature, generate_keypair};
pub use key_exchange::{derive_shared_secret, generate_ephemeral_key};
pub use hashing::{hash_password, hash_handle};
pub use pqc::{
    generate_hybrid_keypair_from_seed,
    hybrid_encapsulate,
    hybrid_decapsulate,
    HybridKEMKeypair,
    HybridCiphertext,
};
