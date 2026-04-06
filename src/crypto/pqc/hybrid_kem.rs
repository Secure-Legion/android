/// Hybrid Post-Quantum Key Encapsulation Mechanism
/// Combines X25519 (classical ECDH) with ML-KEM-1024 (post-quantum KEM)
///
/// Security: Protected if EITHER X25519 OR ML-KEM-1024 remains unbroken
/// Standard: NIST FIPS 203 (ML-KEM) + RFC 7748 (X25519)

use super::types::*;
use hkdf::Hkdf;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use ml_kem::kem::{Decapsulate, Encapsulate};
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
    #[error("ML-KEM key generation failed")]
    MlKemKeyGenFailed,
    #[error("ML-KEM encapsulation failed")]
    MlKemEncapsFailed,
    #[error("ML-KEM decapsulation failed")]
    MlKemDecapsFailed,
    #[error("HKDF expansion failed")]
    HKDFExpansionFailed,
    #[error("Invalid keypair size")]
    InvalidKeypairSize,
}

pub type Result<T> = std::result::Result<T, HybridKEMError>;

/// Generate hybrid KEM keypair from seed (deterministic)
pub fn generate_hybrid_keypair_from_seed(seed: &[u8; 32]) -> Result<HybridKEMKeypair> {
    // 1. Use seed directly for X25519 (matches existing KeyManager behavior)
    let x25519_secret = StaticSecret::from(*seed);
    let x25519_public = PublicKey::from(&x25519_secret);

    // 2. Derive ML-KEM seed using domain separation
    let mlkem_seed = derive_mlkem_seed(seed);

    // 3. Generate ML-KEM-1024 keypair from deterministic RNG
    let mut rng = ChaCha20Rng::from_seed(mlkem_seed);
    let (dk, ek) = MlKem1024::generate(&mut rng);

    // Extract raw bytes
    let ek_encoded = ek.as_bytes();
    let dk_encoded = dk.as_bytes();

    let mut kyber_public = [0u8; KYBER_PUBLIC_KEY_BYTES];
    let mut kyber_secret = [0u8; KYBER_SECRET_KEY_BYTES];
    kyber_public.copy_from_slice(ek_encoded.as_slice());
    kyber_secret.copy_from_slice(dk_encoded.as_slice());

    Ok(HybridKEMKeypair {
        x25519_public: x25519_public.to_bytes(),
        x25519_secret: x25519_secret.to_bytes(),
        kyber_public,
        kyber_secret,
    })
}

/// Derive ML-KEM seed from X25519 seed using domain separation
fn derive_mlkem_seed(x25519_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(x25519_seed);
    hasher.update(b"mlkem1024");
    let hash = hasher.finalize();
    hash.into()
}

/// Hybrid encapsulation - generate shared secret for recipient
pub fn hybrid_encapsulate(
    their_x25519_public: &[u8; X25519_PUBLIC_KEY_BYTES],
    their_kyber_public: &[u8; KYBER_PUBLIC_KEY_BYTES],
) -> Result<([u8; HYBRID_SHARED_SECRET_BYTES], HybridCiphertext)> {
    // 1. X25519 key exchange (generate ephemeral key)
    let our_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let our_ephemeral_public = PublicKey::from(&our_ephemeral_secret);

    let their_x25519_pk = PublicKey::from(*their_x25519_public);
    let x25519_shared_secret = our_ephemeral_secret.diffie_hellman(&their_x25519_pk);

    // 2. ML-KEM-1024 encapsulation
    let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(
        their_kyber_public.into()
    );
    let (ct, mlkem_ss) = ek.encapsulate(&mut OsRng).unwrap();

    let mut kyber_ciphertext = [0u8; KYBER_CIPHERTEXT_BYTES];
    kyber_ciphertext.copy_from_slice(ct.as_slice());

    // 3. Combine both shared secrets using HKDF
    let combined_secret =
        combine_secrets(x25519_shared_secret.as_bytes(), mlkem_ss.as_slice())?;

    let ciphertext = HybridCiphertext {
        x25519_ephemeral: our_ephemeral_public.to_bytes(),
        kyber_ciphertext,
    };

    Ok((combined_secret, ciphertext))
}

/// Hybrid decapsulation - recover shared secret from ciphertext
pub fn hybrid_decapsulate(
    our_x25519_secret: &[u8; X25519_SECRET_KEY_BYTES],
    our_kyber_secret: &[u8; KYBER_SECRET_KEY_BYTES],
    ciphertext: &HybridCiphertext,
) -> Result<[u8; HYBRID_SHARED_SECRET_BYTES]> {
    // 1. X25519 key exchange
    let our_static_secret = StaticSecret::from(*our_x25519_secret);
    let their_ephemeral_public = PublicKey::from(ciphertext.x25519_ephemeral);
    let x25519_shared_secret = our_static_secret.diffie_hellman(&their_ephemeral_public);

    // 2. ML-KEM-1024 decapsulation (timing-safe, unlike pqc_kyber)
    let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(
        our_kyber_secret.into()
    );
    let ct = (&ciphertext.kyber_ciphertext).into();
    let mlkem_ss = dk.decapsulate(ct)
        .map_err(|_| HybridKEMError::MlKemDecapsFailed)?;

    // 3. Combine both shared secrets
    let combined_secret =
        combine_secrets(x25519_shared_secret.as_bytes(), mlkem_ss.as_slice())?;

    Ok(combined_secret)
}

/// Combine X25519 and ML-KEM shared secrets using HKDF-SHA256
fn combine_secrets(
    x25519_secret: &[u8],
    mlkem_secret: &[u8],
) -> Result<[u8; HYBRID_SHARED_SECRET_BYTES]> {
    let mut ikm = Vec::with_capacity(x25519_secret.len() + mlkem_secret.len());
    ikm.extend_from_slice(x25519_secret);
    ikm.extend_from_slice(mlkem_secret);

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = [0u8; HYBRID_SHARED_SECRET_BYTES];

    hkdf.expand(b"SecureLegion-Hybrid-KEM-v2", &mut output)
        .map_err(|_| HybridKEMError::HKDFExpansionFailed)?;

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

        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let keypair1 = generate_hybrid_keypair_from_seed(&seed1).unwrap();
        let keypair2 = generate_hybrid_keypair_from_seed(&seed2).unwrap();

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

        let secret2 = hybrid_decapsulate(
            &keypair2.x25519_secret,
            &keypair2.kyber_secret,
            &ciphertext,
        )
        .unwrap();

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let seed = [42u8; 32];
        let keypair = generate_hybrid_keypair_from_seed(&seed).unwrap();

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

        assert_eq!(combined_secret.len(), HYBRID_SHARED_SECRET_BYTES);
    }
}
