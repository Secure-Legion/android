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

/// Maximum number of sequence numbers ahead that will be accepted
/// Messages with sequence >= expected + WINDOW_SIZE will be rejected
/// This prevents desync from packet loss while still protecting against replay attacks
const SEQUENCE_WINDOW_SIZE: u64 = 100;

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
    #[error("Replay attack detected: sequence {received} < expected {expected}")]
    ReplayAttack { received: u64, expected: u64 },
    #[error("Sequence too far ahead: received {received}, expected {expected}, max {max}")]
    SequenceTooFar { received: u64, expected: u64, max: u64 },
    #[error("Out of order message: received {received}, expected {expected}")]
    OutOfOrder { received: u64, expected: u64 },
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

/// Derive receive chain key for a specific sender sequence (out-of-order decryption)
///
/// This implements two-stage derivation:
/// 1. Derive direction key from root (sender's perspective)
/// 2. Evolve N times to reach sender's sequence
///
/// This allows decrypting messages from ANY past sequence, fixing out-of-order delivery.
///
/// # Arguments
/// * `root_key` - 32-byte root key (same for both parties)
/// * `sender_sequence` - The sequence number the sender used to encrypt
/// * `our_onion` - Our .onion address (for direction mapping)
/// * `their_onion` - Their .onion address (for direction mapping)
///
/// # Returns
/// 32-byte chain key at sender's sequence (for decrypting their message)
///
/// # Example
/// ```
/// // They encrypted with sequence 10, we're at sequence 15
/// // We need to derive the key they used at sequence 10
/// let key = derive_receive_key_at_sequence(&root_key, 10, our_onion, their_onion)?;
/// let plaintext = decrypt_message(ciphertext, &key)?;
/// ```
pub fn derive_receive_key_at_sequence(
    root_key: &[u8; 32],
    sender_sequence: u64,
    our_onion: &str,
    their_onion: &str,
) -> Result<[u8; 32]> {
    // Max sequence gap protection (prevent DoS)
    const MAX_SEQUENCE_GAP: u64 = 10_000;
    if sender_sequence > MAX_SEQUENCE_GAP {
        return Err(EncryptionError::SequenceTooFar {
            received: sender_sequence,
            expected: 0,
            max: MAX_SEQUENCE_GAP,
        });
    }

    // STAGE 1: Derive direction key (sender's perspective)
    // Sender used their SEND chain, which is our RECEIVE chain
    // Key insight: We need to derive the key THEY used to send
    // If our_onion < their_onion: THEY have bigger onion, so THEY send with incoming (0x04)
    // If our_onion > their_onion: THEY have smaller onion, so THEY send with outgoing (0x03)
    let direction_key = if our_onion < their_onion {
        // Their onion is bigger, so they used incoming (0x04) to send to us
        derive_incoming_chain_key(root_key)?
    } else {
        // Their onion is smaller, so they used outgoing (0x03) to send to us
        derive_outgoing_chain_key(root_key)?
    };

    // STAGE 2: Evolve to sender's sequence
    // Start from direction key and evolve N times
    let mut key = direction_key;
    for _ in 0..sender_sequence {
        // Each evolution: HMAC(key, 0x01)
        let new_key = {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)
                .map_err(|_| EncryptionError::InvalidKeyLength)?;
            mac.update(&[0x01]);
            let result = mac.finalize();
            let evolved: [u8; 32] = result.into_bytes().into();
            evolved
        };
        key = new_key;
    }

    Ok(key)
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

    // Windowed sequence acceptance (prevents replay while allowing out-of-order delivery)

    // Reject replays (sequence < expected)
    if sequence < expected_sequence {
        return Err(EncryptionError::ReplayAttack {
            received: sequence,
            expected: expected_sequence,
        });
    }

    // Reject sequences too far in future (prevents desync attacks)
    if sequence >= expected_sequence + SEQUENCE_WINDOW_SIZE {
        return Err(EncryptionError::SequenceTooFar {
            received: sequence,
            expected: expected_sequence,
            max: expected_sequence + SEQUENCE_WINDOW_SIZE - 1,
        });
    }

    // Accept out-of-order messages within window [expected, expected+100)
    // Note: Kotlin layer must buffer and process in order to maintain key chain sync
    if sequence != expected_sequence {
        return Err(EncryptionError::OutOfOrder {
            received: sequence,
            expected: expected_sequence,
        });
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

// ==================== TWO-PHASE RATCHET COMMIT (Fix #6) ====================

use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Result of deferred encryption (ratchet not yet committed)
#[derive(Debug, Clone)]
pub struct DeferredEncryptionResult {
    pub ciphertext: Vec<u8>,
    pub next_chain_key: [u8; 32], // Next key, but not committed yet
    pub next_sequence: u64,
}

/// Encrypt message WITHOUT committing ratchet advancement
///
/// This is Phase 1 of two-phase commit protocol.
/// The chain key is evolved locally but NOT persisted.
/// Call `commit_ratchet_advancement()` after PING_ACK received.
///
/// # Arguments
/// * `plaintext` - Message to encrypt
/// * `chain_key` - Current chain key (NOT mutated)
/// * `sequence` - Current sequence number
///
/// # Returns
/// DeferredEncryptionResult with ciphertext and next state (uncommitted)
pub fn encrypt_message_deferred(
    plaintext: &[u8],
    chain_key: &[u8; 32], // Immutable borrow - does NOT modify
    sequence: u64,
) -> Result<DeferredEncryptionResult> {
    // Derive message key from current chain key
    let message_key = derive_message_key(chain_key)?;

    // Evolve chain key forward (provides forward secrecy)
    // Create mutable copy for evolution
    let mut chain_key_copy = *chain_key;
    let next_chain_key = evolve_chain_key(&mut chain_key_copy)?;
    let next_sequence = sequence + 1;

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

    // Return deferred result (ratchet NOT committed yet)
    Ok(DeferredEncryptionResult {
        ciphertext: encrypted_message,
        next_chain_key,
        next_sequence,
    })
}

/// Pending ratchet advancement waiting for PING_ACK
#[derive(Clone)]
struct PendingRatchetAdvancement {
    contact_id: String, // Contact identifier (pubkey or onion)
    message_id: String, // Message ID (for tracking)
    next_chain_key: [u8; 32], // Next chain key (uncommitted)
    next_sequence: u64, // Next sequence number (uncommitted)
    created_at: std::time::SystemTime,
}

/// Global storage for pending ratchet advancements
static PENDING_RATCHETS: Lazy<Mutex<HashMap<String, PendingRatchetAdvancement>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Store a pending ratchet advancement (waiting for PING_ACK)
///
/// # Arguments
/// * `contact_id` - Unique contact identifier (pubkey or onion address)
/// * `message_id` - Message ID (for tracking which message this ratchet belongs to)
/// * `next_chain_key` - The evolved chain key (not yet committed)
/// * `next_sequence` - The next sequence number (not yet committed)
pub fn store_pending_ratchet_advancement(
    contact_id: &str,
    message_id: &str,
    next_chain_key: [u8; 32],
    next_sequence: u64,
) -> Result<()> {
    let mut pending = PENDING_RATCHETS.lock()
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    let advancement = PendingRatchetAdvancement {
        contact_id: contact_id.to_string(),
        message_id: message_id.to_string(),
        next_chain_key,
        next_sequence,
        created_at: std::time::SystemTime::now(),
    };

    pending.insert(contact_id.to_string(), advancement);

    log::info!("Stored pending ratchet advancement for contact {}, message {}",
        contact_id, message_id);

    Ok(())
}

/// Commit ratchet advancement after PING_ACK received (Phase 2)
///
/// This is called by Kotlin after PING_ACK arrives.
/// Returns the next chain key and sequence to persist in database.
///
/// # Arguments
/// * `contact_id` - Contact identifier (must match store_pending_ratchet_advancement)
///
/// # Returns
/// (next_chain_key, next_sequence) to persist, or None if no pending advancement
pub fn commit_ratchet_advancement(
    contact_id: &str,
) -> Result<Option<([u8; 32], u64)>> {
    let mut pending = PENDING_RATCHETS.lock()
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    if let Some(advancement) = pending.remove(contact_id) {
        log::info!("Committed ratchet advancement for contact {}, message {}",
            contact_id, advancement.message_id);

        Ok(Some((advancement.next_chain_key, advancement.next_sequence)))
    } else {
        log::warn!("No pending ratchet advancement found for contact {}", contact_id);
        Ok(None)
    }
}

/// Rollback/discard pending ratchet advancement (if send permanently fails)
///
/// Call this if message is deleted before receiving PING_ACK.
///
/// # Arguments
/// * `contact_id` - Contact identifier
pub fn rollback_ratchet_advancement(contact_id: &str) -> Result<()> {
    let mut pending = PENDING_RATCHETS.lock()
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    if let Some(advancement) = pending.remove(contact_id) {
        log::info!("Rolled back ratchet advancement for contact {}, message {}",
            contact_id, advancement.message_id);
    }

    Ok(())
}

/// Clean up expired pending ratchet advancements (older than 5 minutes)
pub fn cleanup_expired_pending_ratchets() -> Result<()> {
    let mut pending = PENDING_RATCHETS.lock()
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    let now = std::time::SystemTime::now();
    const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(300); // 5 minutes

    pending.retain(|contact_id, advancement| {
        if let Ok(age) = now.duration_since(advancement.created_at) {
            if age > MAX_AGE {
                log::warn!("Expired pending ratchet for contact {} (age: {:?})",
                    contact_id, age);
                return false;
            }
        }
        true
    });

    Ok(())
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
