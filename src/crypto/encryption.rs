use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

/// Result of encryption with atomic key evolution
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub evolved_chain_key: [u8; 32],
}

/// Result of decryption with atomic key evolution
#[derive(Debug, Clone)]
pub struct DecryptionResult {
    pub plaintext: Vec<u8>,
    pub evolved_chain_key: [u8; 32],
}

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

/// Derive root key from X25519 shared secret using HKDF-SHA256
///
/// # Arguments
/// * `shared_secret` - 32-byte X25519 shared secret OR 64-byte hybrid X25519+Kyber combined secret
/// * `info` - Context information (e.g., "SecureLegion-RootKey-v1")
///
/// # Returns
/// 32-byte root key for initializing key chains
pub fn derive_root_key(shared_secret: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    if shared_secret.len() != 32 && shared_secret.len() != 64 {
        return Err(EncryptionError::InvalidKeyLength);
    }

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut root_key = [0u8; 32];
    hkdf.expand(info, &mut root_key)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok(root_key)
}

/// Evolve chain key forward using HMAC-SHA256 (one-way function)
///
/// This provides forward secrecy - old chain keys cannot be recovered from new ones.
///
/// # Arguments
/// * `chain_key` - Current 32-byte chain key
///
/// # Returns
/// Next chain key (32 bytes)
pub fn evolve_chain_key(chain_key: &mut [u8; 32]) -> Result<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    // HMAC(chain_key, 0x01) for chain key evolution
    mac.update(&[0x01]);
    let result = mac.finalize();
    let new_chain_key: [u8; 32] = result.into_bytes().into();

    // Zero out the old chain key for forward secrecy
    chain_key.zeroize();

    Ok(new_chain_key)
}

/// Derive ephemeral message key from chain key
///
/// # Arguments
/// * `chain_key` - Current 32-byte chain key
///
/// # Returns
/// 32-byte message key for encrypting/decrypting this message
pub fn derive_message_key(chain_key: &[u8; 32]) -> Result<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    // HMAC(chain_key, 0x02) for message key derivation
    mac.update(&[0x02]);
    let result = mac.finalize();
    let message_key: [u8; 32] = result.into_bytes().into();

    Ok(message_key)
}

/// Derive outgoing direction chain key from root key
///
/// Both parties use this for ONE direction of communication.
/// The direction is determined by lexicographic comparison of .onion addresses.
///
/// # Arguments
/// * `root_key` - 32-byte root key derived from X25519 shared secret
///
/// # Returns
/// 32-byte chain key for outgoing direction
pub fn derive_outgoing_chain_key(root_key: &[u8; 32]) -> Result<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(root_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    // HMAC(root_key, 0x03) for outgoing direction chain key
    mac.update(&[0x03]);
    let result = mac.finalize();
    let chain_key: [u8; 32] = result.into_bytes().into();

    Ok(chain_key)
}

/// Derive incoming direction chain key from root key
///
/// Both parties use this for the OTHER direction of communication.
/// The direction is determined by lexicographic comparison of .onion addresses.
///
/// # Arguments
/// * `root_key` - 32-byte root key derived from X25519 shared secret
///
/// # Returns
/// 32-byte chain key for incoming direction
pub fn derive_incoming_chain_key(root_key: &[u8; 32]) -> Result<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(root_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    // HMAC(root_key, 0x04) for incoming direction chain key
    mac.update(&[0x04]);
    let result = mac.finalize();
    let chain_key: [u8; 32] = result.into_bytes().into();

    Ok(chain_key)
}

/// Encrypt message with key evolution (for messaging)
///
/// ATOMIC OPERATION: Encrypts and evolves key in one indivisible operation
/// This ensures encryption and key state update never get out of sync
///
/// # Arguments
/// * `plaintext` - Message to encrypt
/// * `chain_key` - Current chain key (will be evolved)
/// * `sequence` - Message sequence number
///
/// # Returns
/// EncryptionResult containing both encrypted message and evolved chain key
/// Wire format: [version: 1][sequence: 8][nonce: 24][ciphertext][tag: 16]
pub fn encrypt_message_with_evolution(
    plaintext: &[u8],
    chain_key: &mut [u8; 32],
    sequence: u64,
) -> Result<EncryptionResult> {
    // Derive message key from current chain key
    let message_key = derive_message_key(chain_key)?;

    // Evolve chain key forward (provides forward secrecy)
    let new_chain_key = evolve_chain_key(chain_key)?;
    *chain_key = new_chain_key;

    // Encrypt with derived message key
    let cipher = XChaCha20Poly1305::new_from_slice(&message_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    // Build wire format: [version][sequence][nonce][ciphertext]
    let mut encrypted_message = Vec::with_capacity(1 + 8 + 24 + ciphertext.len());
    encrypted_message.push(0x01); // Version 1
    encrypted_message.extend_from_slice(&sequence.to_be_bytes());
    encrypted_message.extend_from_slice(&nonce_bytes);
    encrypted_message.extend_from_slice(&ciphertext);

    // Return both encrypted message AND evolved key atomically
    Ok(EncryptionResult {
        ciphertext: encrypted_message,
        evolved_chain_key: new_chain_key,
    })
}

/// Decrypt message with key evolution (for messaging)
///
/// ATOMIC OPERATION: Decrypts and evolves key in one indivisible operation
/// This ensures decryption and key state update never get out of sync
///
/// # Arguments
/// * `encrypted_data` - Encrypted message with header
/// * `chain_key` - Current chain key (will be evolved)
/// * `expected_sequence` - Expected sequence number
///
/// # Returns
/// DecryptionResult containing both decrypted plaintext and evolved chain key
pub fn decrypt_message_with_evolution(
    encrypted_data: &[u8],
    chain_key: &mut [u8; 32],
    expected_sequence: u64,
) -> Result<DecryptionResult> {
    // Validate minimum length: version(1) + sequence(8) + nonce(24) + tag(16)
    if encrypted_data.len() < 1 + 8 + 24 + 16 {
        return Err(EncryptionError::DecryptionFailed);
    }

    // Parse wire format
    let version = encrypted_data[0];
    if version != 0x01 {
        return Err(EncryptionError::DecryptionFailed);
    }

    let sequence = u64::from_be_bytes(
        encrypted_data[1..9].try_into()
            .map_err(|_| EncryptionError::DecryptionFailed)?
    );

    // Verify sequence number (prevents replay attacks)
    if sequence != expected_sequence {
        return Err(EncryptionError::DecryptionFailed);
    }

    let nonce_bytes = &encrypted_data[9..33];
    let ciphertext = &encrypted_data[33..];

    // Derive message key from current chain key
    let message_key = derive_message_key(chain_key)?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&message_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // Evolve chain key forward (must match sender's evolution)
    let new_chain_key = evolve_chain_key(chain_key)?;
    *chain_key = new_chain_key;

    // Return both plaintext AND evolved key atomically
    Ok(DecryptionResult {
        plaintext,
        evolved_chain_key: new_chain_key,
    })
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
