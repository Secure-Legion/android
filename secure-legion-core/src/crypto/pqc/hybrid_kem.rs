/// Hybrid Post-Quantum Key Encapsulation Mechanism
/// Combines X25519 (classical ECDH) with ML-KEM-1024 (post-quantum KEM)
///
/// Security: Protected if EITHER X25519 OR ML-KEM-1024 remains unbroken
/// Standard: NIST FIPS 203 (ML-KEM) + RFC 7748 (X25519)

use super::types::*;
use hkdf::Hkdf;
use pqc_kyber::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum HybridKEMError {
    #[error("Invalid seed length (expected 32 bytes)")]
    InvalidSeedLength,
    #[error("Kyber key generation failed")]
    KyberKeyGenFailed,
    #[error("Kyber encapsulation failed")]
    KyberEncapsFailed,
    #[error("Kyber decapsulation failed")]
    KyberDecapsFailed,
    #[error("HKDF expansion failed")]
    HKDFExpansionFailed,
    #[error("Invalid keypair size")]
    InvalidKeypairSize,
}

pub type Result<T> = std::result::Result<T, HybridKEMError>;

/// Generate hybrid KEM keypair from seed (deterministic)
///
/// # Arguments
/// * `seed` - 32-byte seed for key derivation
///
/// # Returns
/// Hybrid keypair containing X25519 and Kyber-1024 keys
///
/// # Security
/// Uses domain separation to derive independent X25519 and Kyber seeds
pub fn generate_hybrid_keypair_from_seed(seed: &[u8; 32]) -> Result<HybridKEMKeypair> {
    // 1. Use seed directly for X25519 (matches existing KeyManager behavior)
    let x25519_secret = StaticSecret::from(*seed);
    let x25519_public = PublicKey::from(&x25519_secret);

    // 2. Derive Kyber seed using domain separation
    let kyber_seed = derive_kyber_seed(seed);

    // 3. Generate Kyber-1024 keypair from deterministic RNG
    let mut rng = ChaCha20Rng::from_seed(kyber_seed);
    let kyber_keys =
        keypair(&mut rng).map_err(|_| HybridKEMError::KyberKeyGenFailed)?;

    Ok(HybridKEMKeypair {
        x25519_public: x25519_public.to_bytes(),
        x25519_secret: x25519_secret.to_bytes(),
        kyber_public: kyber_keys.public,
        kyber_secret: kyber_keys.secret,
    })
}

/// Derive Kyber seed from X25519 seed using domain separation
///
/// Uses SHA-256(seed || "kyber1024") to ensure Kyber and X25519 keys are independent
fn derive_kyber_seed(x25519_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(x25519_seed);
    hasher.update(b"kyber1024"); // Domain separation constant
    let hash = hasher.finalize();
    hash.into()
}

/// Hybrid encapsulation - generate shared secret for recipient
///
/// # Arguments
/// * `their_x25519_public` - Recipient's X25519 public key (32 bytes)
/// * `their_kyber_public` - Recipient's Kyber public key (1568 bytes)
///
/// # Returns
/// Tuple of (combined_secret, ciphertext) where:
/// - combined_secret: 64-byte hybrid shared secret
/// - ciphertext: Encapsulated data to send to recipient
///
/// # Security
/// Combines X25519 and Kyber secrets using HKDF-SHA256
/// Secret is secure if EITHER algorithm remains unbroken
pub fn hybrid_encapsulate(
    their_x25519_public: &[u8; X25519_PUBLIC_KEY_BYTES],
    their_kyber_public: &[u8; KYBER_PUBLIC_KEY_BYTES],
) -> Result<([u8; HYBRID_SHARED_SECRET_BYTES], HybridCiphertext)> {
    // 1. X25519 key exchange (generate ephemeral key)
    let our_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let our_ephemeral_public = PublicKey::from(&our_ephemeral_secret);

    let mut their_x25519_pk_array = [0u8; X25519_PUBLIC_KEY_BYTES];
    their_x25519_pk_array.copy_from_slice(their_x25519_public);
    let their_x25519_pk = PublicKey::from(their_x25519_pk_array);

    let x25519_shared_secret = our_ephemeral_secret.diffie_hellman(&their_x25519_pk);

    // 2. Kyber-1024 encapsulation
    let (kyber_ciphertext, kyber_shared_secret) =
        encapsulate(their_kyber_public, &mut OsRng)
            .map_err(|_| HybridKEMError::KyberEncapsFailed)?;

    // 3. Combine both shared secrets using HKDF
    let combined_secret =
        combine_secrets(x25519_shared_secret.as_bytes(), &kyber_shared_secret)?;

    // 4. Build ciphertext
    let ciphertext = HybridCiphertext {
        x25519_ephemeral: our_ephemeral_public.to_bytes(),
        kyber_ciphertext,
    };

    Ok((combined_secret, ciphertext))
}

/// Hybrid decapsulation - recover shared secret from ciphertext
///
/// # Arguments
/// * `our_x25519_secret` - Our X25519 secret key (32 bytes)
/// * `our_kyber_secret` - Our Kyber secret key (3168 bytes)
/// * `ciphertext` - Hybrid ciphertext received from sender
///
/// # Returns
/// 64-byte combined shared secret (identical to encapsulation result)
///
/// # Security
/// Both X25519 and Kyber secrets must be kept confidential
pub fn hybrid_decapsulate(
    our_x25519_secret: &[u8; X25519_SECRET_KEY_BYTES],
    our_kyber_secret: &[u8; KYBER_SECRET_KEY_BYTES],
    ciphertext: &HybridCiphertext,
) -> Result<[u8; HYBRID_SHARED_SECRET_BYTES]> {
    // 1. X25519 key exchange (use their ephemeral public key)
    let our_static_secret = StaticSecret::from(*our_x25519_secret);
    let their_ephemeral_public = PublicKey::from(ciphertext.x25519_ephemeral);
    let x25519_shared_secret = our_static_secret.diffie_hellman(&their_ephemeral_public);

    // 2. Kyber-1024 decapsulation
    let kyber_shared_secret = decapsulate(&ciphertext.kyber_ciphertext, our_kyber_secret)
        .map_err(|_| HybridKEMError::KyberDecapsFailed)?;

    // 3. Combine both shared secrets (must match encapsulation)
    let combined_secret =
        combine_secrets(x25519_shared_secret.as_bytes(), &kyber_shared_secret)?;

    Ok(combined_secret)
}

/// Combine X25519 and Kyber shared secrets using HKDF-SHA256
///
/// # Security Properties
/// - Uses HKDF-Expand with domain-separated info string
/// - Produces 64-byte output for enhanced security margin
/// - Compromising one algorithm doesn't reveal the combined secret
///
/// Formula: HKDF-Expand(x25519_secret || kyber_secret, "SecureLegion-Hybrid-KEM-v2")
fn combine_secrets(
    x25519_secret: &[u8],
    kyber_secret: &[u8],
) -> Result<[u8; HYBRID_SHARED_SECRET_BYTES]> {
    // Concatenate both secrets as HKDF input key material
    let mut ikm = Vec::with_capacity(x25519_secret.len() + kyber_secret.len());
    ikm.extend_from_slice(x25519_secret);
    ikm.extend_from_slice(kyber_secret);

    // Use HKDF to combine secrets
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = [0u8; HYBRID_SHARED_SECRET_BYTES];

    hkdf.expand(b"SecureLegion-Hybrid-KEM-v2", &mut output)
        .map_err(|_| HybridKEMError::HKDFExpansionFailed)?;

    // Zeroize intermediate key material
    ikm.zeroize();

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_from_seed() {
        let seed = [42u8; 32];
        let keypair1 = generate_hybrid_keypair_from_seed(&seed).unwrap();
        let keypair2 = generate_hybrid_keypair_from_seed(&seed).unwrap();

        // Same seed produces same keys (deterministic)
        assert_eq!(keypair1.x25519_public, keypair2.x25519_public);
        assert_eq!(keypair1.x25519_secret, keypair2.x25519_secret);
        assert_eq!(keypair1.kyber_public, keypair2.kyber_public);
        assert_eq!(keypair1.kyber_secret, keypair2.kyber_secret);
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let seed = [42u8; 32];
        let keypair = generate_hybrid_keypair_from_seed(&seed).unwrap();

        let (secret1, ciphertext) = hybrid_encapsulate(
            &keypair.x25519_public,
            &keypair.kyber_public,
        )
        .unwrap();

        let secret2 = hybrid_decapsulate(
            &keypair.x25519_secret,
            &keypair.kyber_secret,
            &ciphertext,
        )
        .unwrap();

        // Both parties derive same secret
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let keypair1 = generate_hybrid_keypair_from_seed(&seed1).unwrap();
        let keypair2 = generate_hybrid_keypair_from_seed(&seed2).unwrap();

        // Different seeds produce different keys
        assert_ne!(keypair1.x25519_public, keypair2.x25519_public);
        assert_ne!(keypair1.kyber_public, keypair2.kyber_public);
    }

    #[test]
    fn test_wrong_secret_key_fails() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let keypair1 = generate_hybrid_keypair_from_seed(&seed1).unwrap();
        let keypair2 = generate_hybrid_keypair_from_seed(&seed2).unwrap();

        let (secret1, ciphertext) = hybrid_encapsulate(
            &keypair1.x25519_public,
            &keypair1.kyber_public,
        )
        .unwrap();

        // Try to decapsulate with wrong key
        let secret2 = hybrid_decapsulate(
            &keypair2.x25519_secret,
            &keypair2.kyber_secret,
            &ciphertext,
        )
        .unwrap();

        // Secrets should NOT match (different keys)
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let seed = [42u8; 32];
        let keypair = generate_hybrid_keypair_from_seed(&seed).unwrap();

        // Serialize and deserialize
        let bytes = keypair.to_bytes();
        let restored = HybridKEMKeypair::from_bytes(&bytes).unwrap();

        assert_eq!(keypair.x25519_public, restored.x25519_public);
        assert_eq!(keypair.x25519_secret, restored.x25519_secret);
        assert_eq!(keypair.kyber_public, restored.kyber_public);
        assert_eq!(keypair.kyber_secret, restored.kyber_secret);
    }

    #[test]
    fn test_combined_secret_size() {
        let seed = [42u8; 32];
        let keypair = generate_hybrid_keypair_from_seed(&seed).unwrap();

        let (combined_secret, _) = hybrid_encapsulate(
            &keypair.x25519_public,
            &keypair.kyber_public,
        )
        .unwrap();

        // Combined secret should be 64 bytes
        assert_eq!(combined_secret.len(), HYBRID_SHARED_SECRET_BYTES);
    }
}
