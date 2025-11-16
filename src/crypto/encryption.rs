use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
}

pub type Result<T> = std::result::Result<T, EncryptionError>;

/// Encrypt a message using XChaCha20-Poly1305
///
/// # Arguments
/// * `plaintext` - The message to encrypt
/// * `key` - 32-byte encryption key
///
/// # Returns
/// Encrypted message with prepended nonce (24 bytes + ciphertext)
pub fn encrypt_message(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength);
    }

    // Create cipher
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(24 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a message using XChaCha20-Poly1305
///
/// # Arguments
/// * `encrypted_data` - Encrypted message with prepended nonce (24 bytes + ciphertext)
/// * `key` - 32-byte encryption key
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt_message(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength);
    }

    // Validate minimum length (nonce + tag)
    if encrypted_data.len() < 24 + 16 {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    // Create cipher
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Generate a random 32-byte key
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key();
        let plaintext = b"Hello, Secure Legion!";

        let encrypted = encrypt_message(plaintext, &key).unwrap();
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_message(&encrypted, &key).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"Secret message";

        let encrypted = encrypt_message(plaintext, &key1).unwrap();
        let result = decrypt_message(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let plaintext = b"Test";
        let short_key = [0u8; 16];

        let result = encrypt_message(plaintext, &short_key);
        assert!(result.is_err());
    }
}
