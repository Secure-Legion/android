/// Solana Name Service integration for SecureLegion
/// Handles username registration and PIN-protected contact discovery

use crate::protocol::ContactCard;
use crate::crypto::encryption::{encrypt_message, decrypt_message};
use serde::{Deserialize, Serialize};
use std::error::Error;
use argon2::{
    password_hash::{PasswordHasher, SaltString, PasswordHash, PasswordVerifier},
    Argon2, Algorithm, Version, Params,
};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

/// Encrypted contact card stored on Solana blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedContactCard {
    /// Username (e.g., "john")
    pub username: String,

    /// Encrypted ContactCard data
    pub encrypted_data: Vec<u8>,

    /// Salt for PIN key derivation
    pub salt: Vec<u8>,

    /// Hash of PIN for verification (to detect wrong PIN early)
    pub pin_verification_hash: Vec<u8>,

    /// Nonce used for encryption
    pub nonce: Vec<u8>,

    /// Timestamp of creation
    pub timestamp: i64,
}

impl EncryptedContactCard {
    /// Create a new encrypted contact card with PIN protection
    pub fn new(username: String, contact_card: &ContactCard, pin: &str) -> Result<Self, Box<dyn Error>> {
        // Generate random salt for key derivation
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes().to_vec();

        // Derive encryption key from PIN using Argon2
        let key = derive_key_from_pin(pin, &salt_bytes)?;

        // Create verification hash (so we can detect wrong PIN quickly)
        let pin_verification_hash = create_pin_verification_hash(pin, &salt_bytes);

        // Serialize ContactCard
        let contact_data = contact_card.serialize()?;

        // Generate random nonce
        let nonce = generate_nonce();

        // Encrypt ContactCard data with ChaCha20-Poly1305
        let encrypted_data = encrypt_with_key(&contact_data, &key, &nonce)?;

        Ok(EncryptedContactCard {
            username,
            encrypted_data,
            salt: salt_bytes,
            pin_verification_hash,
            nonce,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Decrypt contact card with PIN
    pub fn decrypt(&self, pin: &str) -> Result<ContactCard, Box<dyn Error>> {
        // First verify PIN hash (fast check before expensive decryption)
        if !verify_pin_hash(pin, &self.salt, &self.pin_verification_hash) {
            return Err("Invalid PIN".into());
        }

        // Derive key from PIN
        let key = derive_key_from_pin(pin, &self.salt)?;

        // Decrypt data
        let decrypted_data = decrypt_with_key(&self.encrypted_data, &key, &self.nonce)?;

        // Deserialize ContactCard
        let contact_card = ContactCard::deserialize(&decrypted_data)?;

        Ok(contact_card)
    }

    /// Serialize to JSON for blockchain storage
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Derive 256-bit encryption key from PIN using Argon2
fn derive_key_from_pin(pin: &str, salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Use Argon2id with moderate parameters (balanced security/performance for mobile)
    let params = Params::new(
        15 * 1024,  // 15 MB memory
        2,          // 2 iterations
        1,          // 1 thread (mobile-friendly)
        Some(32),   // 32-byte output (256 bits)
    ).map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Hash PIN with salt
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| format!("Salt encoding error: {}", e))?;

    let password_hash = argon2.hash_password(pin.as_bytes(), &salt_string)
        .map_err(|e| format!("Password hashing error: {}", e))?;

    // Extract hash bytes (32 bytes for ChaCha20 key)
    let hash_bytes = password_hash.hash
        .ok_or("No hash generated")?
        .as_bytes()
        .to_vec();

    Ok(hash_bytes)
}

/// Create verification hash for quick PIN validation
fn create_pin_verification_hash(pin: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"PIN_VERIFICATION:");
    hasher.update(pin.as_bytes());
    hasher.update(salt);
    hasher.finalize().to_vec()
}

/// Verify PIN hash (fast check)
fn verify_pin_hash(pin: &str, salt: &[u8], expected_hash: &[u8]) -> bool {
    let computed_hash = create_pin_verification_hash(pin, salt);
    computed_hash == expected_hash
}

/// Generate random 24-byte nonce for XChaCha20-Poly1305
fn generate_nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut nonce = vec![0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt data with key using ChaCha20-Poly1305
fn encrypt_with_key(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };

    // Create cipher
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| format!("Cipher creation error: {}", e))?;

    // Create nonce
    let nonce_array = XNonce::from_slice(nonce);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce_array, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    Ok(ciphertext)
}

/// Decrypt data with key using ChaCha20-Poly1305
fn decrypt_with_key(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };

    // Create cipher
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| format!("Cipher creation error: {}", e))?;

    // Create nonce
    let nonce_array = XNonce::from_slice(nonce);

    // Decrypt
    let plaintext = cipher.decrypt(nonce_array, ciphertext)
        .map_err(|e| "Decryption failed: Invalid PIN or corrupted data")?;

    Ok(plaintext)
}

/// Register username on Solana Name Service
/// Creates subdomain: username.securelegion.sol
pub fn register_username(
    username: &str,
    pin: &str,
    contact_card: &ContactCard,
) -> Result<String, Box<dyn Error>> {
    // Validate username
    validate_username(username)?;

    // Create encrypted contact card
    let encrypted = EncryptedContactCard::new(username.to_string(), contact_card, pin)?;

    // TODO: Actual Solana blockchain interaction
    // For now, return the encrypted JSON that would be stored on-chain
    let json_data = encrypted.to_json()?;

    // Full SNS domain
    let full_domain = format!("{}.securelegion.sol", username);

    log::info!("Would register SNS domain: {}", full_domain);
    log::info!("Encrypted data size: {} bytes", encrypted.encrypted_data.len());

    Ok(full_domain)
}

/// Lookup username on Solana Name Service and decrypt with PIN
pub fn lookup_username(
    username: &str,
    pin: &str,
) -> Result<ContactCard, Box<dyn Error>> {
    // TODO: Actual Solana blockchain lookup
    // For now, this is a placeholder that would:
    // 1. Query Solana for username.securelegion.sol
    // 2. Get EncryptedContactCard from account data
    // 3. Decrypt with PIN

    Err("SNS lookup not yet implemented - requires Solana RPC connection".into())
}

/// Validate username format
fn validate_username(username: &str) -> Result<(), Box<dyn Error>> {
    // Must be 3-20 characters
    if username.len() < 3 || username.len() > 20 {
        return Err("Username must be 3-20 characters".into());
    }

    // Must be alphanumeric + underscore/hyphen only
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err("Username can only contain letters, numbers, underscore, and hyphen".into());
    }

    // Must start with letter or number
    if let Some(first_char) = username.chars().next() {
        if !first_char.is_alphanumeric() {
            return Err("Username must start with a letter or number".into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_encryption_decryption() {
        let contact = ContactCard::new(
            vec![1, 2, 3, 4],
            "SolanaAddress123".to_string(),
            "user1".to_string(),
            Some("test123.onion".to_string()),
        );

        let pin = "MySecretPIN123";

        // Encrypt
        let encrypted = EncryptedContactCard::new("user1".to_string(), &contact, pin).unwrap();

        // Decrypt with correct PIN
        let decrypted = encrypted.decrypt(pin).unwrap();
        assert_eq!(decrypted.handle, "user1");
        assert_eq!(decrypted.onion_address, Some("test123.onion".to_string()));

        // Decrypt with wrong PIN should fail
        let wrong_result = encrypted.decrypt("WrongPIN");
        assert!(wrong_result.is_err());
    }

    #[test]
    fn test_username_validation() {
        assert!(validate_username("user1").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user-name").is_ok());

        assert!(validate_username("ab").is_err()); // Too short
        assert!(validate_username("a".repeat(21).as_str()).is_err()); // Too long
        assert!(validate_username("user@name").is_err()); // Invalid char
        assert!(validate_username("_username").is_err()); // Doesn't start with alphanumeric
    }
}
