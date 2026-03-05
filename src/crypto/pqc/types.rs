/// Post-Quantum Cryptography Type Definitions
/// Hybrid X25519 + ML-KEM-1024 implementation

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

/// Kyber-1024 parameter constants (NIST FIPS 203)
pub const KYBER_PUBLIC_KEY_BYTES: usize = 1568;
pub const KYBER_SECRET_KEY_BYTES: usize = 3168;
pub const KYBER_CIPHERTEXT_BYTES: usize = 1568;
pub const KYBER_SHARED_SECRET_BYTES: usize = 32;

/// X25519 parameter constants
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const X25519_SECRET_KEY_BYTES: usize = 32;

/// Combined hybrid secret size (64 bytes)
pub const HYBRID_SHARED_SECRET_BYTES: usize = 64;

/// Hybrid KEM keypair (X25519 + Kyber-1024)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct HybridKEMKeypair {
    pub x25519_public: [u8; X25519_PUBLIC_KEY_BYTES],
    pub x25519_secret: [u8; X25519_SECRET_KEY_BYTES],
    pub kyber_public: [u8; KYBER_PUBLIC_KEY_BYTES],
    pub kyber_secret: [u8; KYBER_SECRET_KEY_BYTES],
}

/// Hybrid KEM ciphertext (X25519 ephemeral + Kyber ciphertext)
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub x25519_ephemeral: [u8; X25519_PUBLIC_KEY_BYTES],
    #[serde(with = "BigArray")]
    pub kyber_ciphertext: [u8; KYBER_CIPHERTEXT_BYTES],
}

impl HybridKEMKeypair {
    /// Get total serialized size of keypair
    pub fn serialized_size() -> usize {
        X25519_PUBLIC_KEY_BYTES
            + X25519_SECRET_KEY_BYTES
            + KYBER_PUBLIC_KEY_BYTES
            + KYBER_SECRET_KEY_BYTES
    }

    /// Serialize keypair to bytes
    /// Format: [x25519_pub][x25519_sec][kyber_pub][kyber_sec]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(Self::serialized_size());
        result.extend_from_slice(&self.x25519_public);
        result.extend_from_slice(&self.x25519_secret);
        result.extend_from_slice(&self.kyber_public);
        result.extend_from_slice(&self.kyber_secret);
        result
    }

    /// Deserialize keypair from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != Self::serialized_size() {
            return Err("Invalid keypair size");
        }

        let mut x25519_public = [0u8; X25519_PUBLIC_KEY_BYTES];
        let mut x25519_secret = [0u8; X25519_SECRET_KEY_BYTES];
        let mut kyber_public = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut kyber_secret = [0u8; KYBER_SECRET_KEY_BYTES];

        let mut offset = 0;
        x25519_public.copy_from_slice(&bytes[offset..offset + X25519_PUBLIC_KEY_BYTES]);
        offset += X25519_PUBLIC_KEY_BYTES;

        x25519_secret.copy_from_slice(&bytes[offset..offset + X25519_SECRET_KEY_BYTES]);
        offset += X25519_SECRET_KEY_BYTES;

        kyber_public.copy_from_slice(&bytes[offset..offset + KYBER_PUBLIC_KEY_BYTES]);
        offset += KYBER_PUBLIC_KEY_BYTES;

        kyber_secret.copy_from_slice(&bytes[offset..offset + KYBER_SECRET_KEY_BYTES]);

        Ok(Self {
            x25519_public,
            x25519_secret,
            kyber_public,
            kyber_secret,
        })
    }
}

impl HybridCiphertext {
    /// Get total size of ciphertext
    pub fn size() -> usize {
        X25519_PUBLIC_KEY_BYTES + KYBER_CIPHERTEXT_BYTES
    }

    /// Serialize ciphertext to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(Self::size());
        result.extend_from_slice(&self.x25519_ephemeral);
        result.extend_from_slice(&self.kyber_ciphertext);
        result
    }

    /// Deserialize ciphertext from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != Self::size() {
            return Err("Invalid ciphertext size");
        }

        let mut x25519_ephemeral = [0u8; X25519_PUBLIC_KEY_BYTES];
        let mut kyber_ciphertext = [0u8; KYBER_CIPHERTEXT_BYTES];

        x25519_ephemeral.copy_from_slice(&bytes[0..X25519_PUBLIC_KEY_BYTES]);
        kyber_ciphertext.copy_from_slice(&bytes[X25519_PUBLIC_KEY_BYTES..]);

        Ok(Self {
            x25519_ephemeral,
            kyber_ciphertext,
        })
    }
}
