/// Post-Quantum Cryptography Module
/// Implements hybrid X25519 + ML-KEM-1024 key encapsulation
///
/// Security: Protected against both classical and quantum attacks
/// Standards: NIST FIPS 203 (ML-KEM) + RFC 7748 (X25519)

pub mod hybrid_kem;
pub mod types;

// Re-export main types and functions
pub use hybrid_kem::{
    generate_hybrid_keypair_from_seed, hybrid_decapsulate, hybrid_encapsulate, HybridKEMError,
};
pub use types::{
    HybridCiphertext, HybridKEMKeypair, HYBRID_SHARED_SECRET_BYTES, KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES, KYBER_SECRET_KEY_BYTES, KYBER_SHARED_SECRET_BYTES,
    X25519_PUBLIC_KEY_BYTES, X25519_SECRET_KEY_BYTES,
};
