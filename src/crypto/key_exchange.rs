use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(Error, Debug)]
pub enum KeyExchangeError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

pub type Result<T> = std::result::Result<T, KeyExchangeError>;

/// Generate an ephemeral X25519 keypair
///
/// # Returns
/// (public_key, secret_key) - Both as 32-byte arrays
pub fn generate_ephemeral_key() -> ([u8; 32], EphemeralSecret) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    (public.to_bytes(), secret)
}

/// Generate a static X25519 keypair
///
/// # Returns
/// (public_key, secret_key) - Both as 32-byte arrays
pub fn generate_static_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    (public.to_bytes(), secret.to_bytes())
}

/// Derive shared secret using X25519
///
/// # Arguments
/// * `our_private_key` - Our 32-byte X25519 private key
/// * `their_public_key` - Their 32-byte X25519 public key
///
/// # Returns
/// 32-byte shared secret
pub fn derive_shared_secret(
    our_private_key: &[u8],
    their_public_key: &[u8],
) -> Result<[u8; 32]> {
    if our_private_key.len() != 32 {
        return Err(KeyExchangeError::InvalidKeyLength);
    }

    if their_public_key.len() != 32 {
        return Err(KeyExchangeError::InvalidKeyLength);
    }

    // Create our secret key
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(our_private_key);
    let secret = StaticSecret::from(secret_bytes);

    // Create their public key
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(their_public_key);
    let public = PublicKey::from(public_bytes);

    // Perform Diffie-Hellman
    let shared_secret = secret.diffie_hellman(&public);

    Ok(shared_secret.to_bytes())
}

/// Derive shared secret using ephemeral private key
///
/// # Arguments
/// * `ephemeral_secret` - Ephemeral secret
/// * `their_public_key` - Their 32-byte X25519 public key
///
/// # Returns
/// 32-byte shared secret
pub fn derive_shared_secret_ephemeral(
    ephemeral_secret: EphemeralSecret,
    their_public_key: &[u8],
) -> Result<[u8; 32]> {
    if their_public_key.len() != 32 {
        return Err(KeyExchangeError::InvalidKeyLength);
    }

    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(their_public_key);
    let public = PublicKey::from(public_bytes);

    let shared_secret = ephemeral_secret.diffie_hellman(&public);

    Ok(shared_secret.to_bytes())
}

/// Derive public key from private key
///
/// # Arguments
/// * `private_key` - 32-byte X25519 private key
///
/// # Returns
/// 32-byte public key
pub fn derive_public_key(private_key: &[u8]) -> Result<[u8; 32]> {
    if private_key.len() != 32 {
        return Err(KeyExchangeError::InvalidKeyLength);
    }

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(private_key);
    let secret = StaticSecret::from(secret_bytes);

    let public = PublicKey::from(&secret);

    Ok(public.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_static_keypair() {
        let (public, private) = generate_static_keypair();
        assert_eq!(public.len(), 32);
        assert_eq!(private.len(), 32);
    }

    #[test]
    fn test_derive_shared_secret() {
        // User1 generates keypair
        let (user1_public, user1_private) = generate_static_keypair();

        // User2 generates keypair
        let (user2_public, user2_private) = generate_static_keypair();

        // Both derive same shared secret
        let user1_shared = derive_shared_secret(&user1_private, &user2_public).unwrap();
        let user2_shared = derive_shared_secret(&user2_private, &user1_public).unwrap();

        assert_eq!(user1_shared, user2_shared);
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        // User1 generates ephemeral key
        let (user1_public, user1_secret) = generate_ephemeral_key();

        // User2 generates static keypair
        let (user2_public, user2_private) = generate_static_keypair();

        // User1 derives shared secret
        let user1_shared = derive_shared_secret_ephemeral(user1_secret, &user2_public).unwrap();

        // User2 derives shared secret
        let user2_shared = derive_shared_secret(&user2_private, &user1_public).unwrap();

        assert_eq!(user1_shared, user2_shared);
    }

    #[test]
    fn test_derive_public_key() {
        let (expected_public, private) = generate_static_keypair();
        let derived_public = derive_public_key(&private).unwrap();

        assert_eq!(expected_public, derived_public);
    }
}
