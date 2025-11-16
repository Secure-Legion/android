use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Signing failed")]
    SigningFailed,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid signature")]
    InvalidSignature,
}

pub type Result<T> = std::result::Result<T, SigningError>;

/// Generate an Ed25519 keypair
///
/// # Returns
/// (public_key, private_key) - Both as 32-byte arrays
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);

    let secret_key = signing_key.to_bytes();
    let public_key = signing_key.verifying_key().to_bytes();

    (public_key, secret_key)
}

/// Sign data with Ed25519 private key
///
/// # Arguments
/// * `data` - Data to sign
/// * `private_key` - 32-byte Ed25519 private key
///
/// # Returns
/// 64-byte signature
pub fn sign_data(data: &[u8], private_key: &[u8]) -> Result<[u8; 64]> {
    if private_key.len() != 32 {
        return Err(SigningError::InvalidKeyLength);
    }

    // Create signing key from bytes
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(private_key);
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Sign
    let signature = signing_key.sign(data);

    Ok(signature.to_bytes())
}

/// Verify Ed25519 signature
///
/// # Arguments
/// * `data` - Original data
/// * `signature` - 64-byte signature
/// * `public_key` - 32-byte Ed25519 public key
///
/// # Returns
/// True if signature is valid
pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if public_key.len() != 32 {
        return Err(SigningError::InvalidKeyLength);
    }

    if signature.len() != 64 {
        return Err(SigningError::InvalidSignature);
    }

    // Parse public key
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(public_key);
    let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|_| SigningError::InvalidKeyLength)?;

    // Parse signature
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);

    // Verify
    match verifying_key.verify(data, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Derive public key from private key
///
/// # Arguments
/// * `private_key` - 32-byte Ed25519 private key
///
/// # Returns
/// 32-byte public key
pub fn derive_public_key(private_key: &[u8]) -> Result<[u8; 32]> {
    if private_key.len() != 32 {
        return Err(SigningError::InvalidKeyLength);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(private_key);
    let signing_key = SigningKey::from_bytes(&key_bytes);

    Ok(signing_key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (public, private) = generate_keypair();
        assert_eq!(public.len(), 32);
        assert_eq!(private.len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let (public, private) = generate_keypair();
        let data = b"Test message for signing";

        let signature = sign_data(data, &private).unwrap();
        assert_eq!(signature.len(), 64);

        let valid = verify_signature(data, &signature, &public).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_invalid_signature() {
        let (public, _) = generate_keypair();
        let data = b"Test message";
        let fake_signature = [0u8; 64];

        let valid = verify_signature(data, &fake_signature, &public).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_derive_public_key() {
        let (expected_public, private) = generate_keypair();
        let derived_public = derive_public_key(&private).unwrap();

        assert_eq!(expected_public, derived_public);
    }
}
