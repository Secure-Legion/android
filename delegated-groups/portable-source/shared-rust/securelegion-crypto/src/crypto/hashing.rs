use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashingError {
    #[error("Hashing failed")]
    HashingFailed,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid salt")]
    InvalidSalt,
}

pub type Result<T> = std::result::Result<T, HashingError>;

/// Hash a password using Argon2id
///
/// # Arguments
/// * `password` - Password to hash
///
/// # Returns
/// Password hash string (PHC format)
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| HashingError::HashingFailed)?
        .to_string();

    Ok(password_hash)
}

/// Hash a password with a specific salt
///
/// # Arguments
/// * `password` - Password to hash
/// * `salt` - Salt bytes (16 bytes recommended)
///
/// # Returns
/// 32-byte hash
pub fn hash_password_with_salt(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    if salt.len() < 16 {
        return Err(HashingError::InvalidSalt);
    }

    let argon2 = Argon2::default();

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|_| HashingError::HashingFailed)?;

    Ok(output)
}

/// Verify a password against a hash
///
/// # Arguments
/// * `password` - Password to verify
/// * `hash` - Password hash string (PHC format)
///
/// # Returns
/// True if password matches
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|_| HashingError::VerificationFailed)?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Hash a handle (username) for privacy-preserving lookup
///
/// # Arguments
/// * `handle` - User handle/username
/// * `salt` - Global salt (should be consistent across app)
///
/// # Returns
/// 32-byte hash
pub fn hash_handle(handle: &str, salt: &[u8]) -> Result<[u8; 32]> {
    hash_password_with_salt(handle, salt)
}

/// Generate a random salt
///
/// # Returns
/// 16-byte salt
pub fn generate_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        let password = "my_secure_password";
        let hash = hash_password(password).unwrap();

        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_verify_password() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        let valid = verify_password(password, &hash).unwrap();
        assert!(valid);

        let invalid = verify_password("wrong_password", &hash).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_hash_password_with_salt() {
        let password = "test";
        let salt = generate_salt();

        let hash1 = hash_password_with_salt(password, &salt).unwrap();
        let hash2 = hash_password_with_salt(password, &salt).unwrap();

        // Same password and salt should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_handle() {
        let handle = "testuser";
        let salt = b"global_salt_12345";

        let hash1 = hash_handle(handle, salt).unwrap();
        let hash2 = hash_handle(handle, salt).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_eq!(salt1.len(), 16);
        assert_ne!(salt1, salt2);
    }
}
