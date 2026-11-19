//! Portable PIN envelope encryption used by contact invitations.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use crypto_secretbox::XSalsa20Poly1305;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

fn pin_kdf(pin: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(64 * 1024, 2, 1, Some(KEY_LEN))
        .map_err(|error| format!("invalid PIN KDF parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; KEY_LEN];
    argon2
        .hash_password_into(pin, salt, &mut output)
        .map_err(|error| format!("PIN key derivation failed: {error}"))?;
    Ok(output)
}

pub fn encrypt_pin_payload(plaintext: &[u8], pin: &[u8]) -> Result<Vec<u8>, String> {
    if pin.len() != 10 || !pin.iter().all(u8::is_ascii_digit) {
        return Err("friend invitation PIN must contain exactly 10 digits".to_string());
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = pin_kdf(pin, &salt)?;
    let cipher = XSalsa20Poly1305::new_from_slice(&key)
        .map_err(|_| "invalid PIN encryption key".to_string())?;
    let encrypted = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| "PIN encryption failed".to_string());
    key.zeroize();
    let encrypted = encrypted?;

    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + encrypted.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

pub fn decrypt_pin_payload(payload: &[u8], pin: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err("PIN ciphertext too short".to_string());
    }

    let salt = &payload[..SALT_LEN];
    let nonce = &payload[SALT_LEN..SALT_LEN + NONCE_LEN];
    let body = &payload[SALT_LEN + NONCE_LEN..];

    let mut key = pin_kdf(pin, salt)?;
    let salsa = XSalsa20Poly1305::new_from_slice(&key)
        .map_err(|_| "invalid PIN decryption key".to_string())?;
    let primary = salsa.decrypt(XNonce::from_slice(nonce), body);
    key.zeroize();
    if let Ok(plaintext) = primary {
        return Ok(plaintext);
    }

    let mut legacy_key = securelegion_crypto::crypto::hashing::hash_password_with_salt(
        std::str::from_utf8(pin).map_err(|_| "PIN is not UTF-8".to_string())?,
        salt,
    )
    .map_err(|error| format!("legacy PIN key derivation failed: {error}"))?;
    let chacha = XChaCha20Poly1305::new_from_slice(&legacy_key)
        .map_err(|_| "invalid legacy PIN key".to_string())?;
    let legacy = chacha
        .decrypt(XNonce::from_slice(nonce), body)
        .map_err(|_| "PIN authentication failed".to_string());
    legacy_key.zeroize();
    legacy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_pin_payload_round_trip() {
        let plaintext = br#"{"type":"friend_request","version":2}"#;
        let encrypted = encrypt_pin_payload(plaintext, b"0123456789").unwrap();
        assert_eq!(
            decrypt_pin_payload(&encrypted, b"0123456789").unwrap(),
            plaintext
        );
        assert!(decrypt_pin_payload(&encrypted, b"9999999999").is_err());
    }

    #[test]
    fn renamed_secretbox_decrypts_legacy_mobile_compatible_vector() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let fixture: serde_json::Value=serde_json::from_str(include_str!(
            "../../tests/fixtures/legacy-pin-secretbox.json")).unwrap();
        let encrypted=STANDARD.decode(fixture["ciphertext_base64"].as_str().unwrap()).unwrap();
        let expected=STANDARD.decode(fixture["plaintext_base64"].as_str().unwrap()).unwrap();
        assert_eq!(decrypt_pin_payload(&encrypted,fixture["pin"].as_str().unwrap().as_bytes()).unwrap(),expected);
    }

    #[test]
    fn encryption_rejects_non_protocol_pin() {
        assert!(encrypt_pin_payload(b"payload", b"1234").is_err());
        assert!(encrypt_pin_payload(b"payload", b"abcdefghij").is_err());
    }
}
