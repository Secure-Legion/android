/// FFI KeyStore Integration
///
/// Provides secure access to Android KeyStore from Rust via JNI callbacks.
/// This ensures private keys never leave the hardware-backed secure storage.

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JByteArray};
use jni::sys::jbyteArray;

/// KeyStore access errors
#[derive(Debug)]
pub enum KeyStoreError {
    KeyNotFound,
    SigningFailed,
    EncryptionFailed,
    DecryptionFailed,
    JniError(String),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound => write!(f, "Key not found in KeyStore"),
            Self::SigningFailed => write!(f, "Signing operation failed"),
            Self::EncryptionFailed => write!(f, "Encryption operation failed"),
            Self::DecryptionFailed => write!(f, "Decryption operation failed"),
            Self::JniError(msg) => write!(f, "JNI error: {}", msg),
        }
    }
}

impl std::error::Error for KeyStoreError {}

/// Get Ed25519 signing key from Android KeyStore
///
/// This calls back to KeyManager.getSigningKeyBytes() via JNI
/// The key is never stored in Rust - only used for signing operations
pub fn get_signing_private_key(env: &mut JNIEnv, key_manager: &JObject) -> Result<Vec<u8>, KeyStoreError> {
    // Call KeyManager.getSigningKeyBytes()
    let result = env
        .call_method(
            key_manager,
            "getSigningKeyBytes",
            "()[B",
            &[],
        )
        .map_err(|e| KeyStoreError::JniError(format!("Failed to call getSigningKeyBytes: {}", e)))?;

    // Convert result to byte array
    let byte_array = result.l()
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get byte array: {}", e)))?;

    // Convert Java byte array to Rust Vec<u8>
    let jbyte_array = JByteArray::from(byte_array);
    let len = env.get_array_length(&jbyte_array)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get array length: {}", e)))?;

    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&jbyte_array, 0, &mut buf)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to copy bytes: {}", e)))?;

    let buf: Vec<u8> = buf.into_iter().map(|b| b as u8).collect();

    if buf.len() != 32 {
        return Err(KeyStoreError::KeyNotFound);
    }

    Ok(buf)
}

/// Get Ed25519 public key from Android KeyStore
pub fn get_signing_public_key(env: &mut JNIEnv, key_manager: &JObject) -> Result<Vec<u8>, KeyStoreError> {
    let result = env
        .call_method(
            key_manager,
            "getSigningPublicKey",
            "()[B",
            &[],
        )
        .map_err(|e| KeyStoreError::JniError(format!("Failed to call getSigningPublicKey: {}", e)))?;

    let byte_array = result.l()
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get byte array: {}", e)))?;

    let jbyte_array = JByteArray::from(byte_array);
    let len = env.get_array_length(&jbyte_array)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get array length: {}", e)))?;

    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&jbyte_array, 0, &mut buf)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to copy bytes: {}", e)))?;

    let buf: Vec<u8> = buf.into_iter().map(|b| b as u8).collect();

    if buf.len() != 32 {
        return Err(KeyStoreError::KeyNotFound);
    }

    Ok(buf)
}

/// Get X25519 encryption private key from Android KeyStore
pub fn get_encryption_private_key(env: &mut JNIEnv, key_manager: &JObject) -> Result<Vec<u8>, KeyStoreError> {
    let result = env
        .call_method(
            key_manager,
            "getEncryptionKeyBytes",
            "()[B",
            &[],
        )
        .map_err(|e| KeyStoreError::JniError(format!("Failed to call getEncryptionKeyBytes: {}", e)))?;

    let byte_array = result.l()
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get byte array: {}", e)))?;

    let jbyte_array = JByteArray::from(byte_array);
    let len = env.get_array_length(&jbyte_array)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get array length: {}", e)))?;

    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&jbyte_array, 0, &mut buf)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to copy bytes: {}", e)))?;

    let buf: Vec<u8> = buf.into_iter().map(|b| b as u8).collect();

    if buf.len() != 32 {
        return Err(KeyStoreError::KeyNotFound);
    }

    Ok(buf)
}

/// Get X25519 encryption public key from Android KeyStore
pub fn get_encryption_public_key(env: &mut JNIEnv, key_manager: &JObject) -> Result<Vec<u8>, KeyStoreError> {
    let result = env
        .call_method(
            key_manager,
            "getEncryptionPublicKey",
            "()[B",
            &[],
        )
        .map_err(|e| KeyStoreError::JniError(format!("Failed to call getEncryptionPublicKey: {}", e)))?;

    let byte_array = result.l()
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get byte array: {}", e)))?;

    let jbyte_array = JByteArray::from(byte_array);
    let len = env.get_array_length(&jbyte_array)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get array length: {}", e)))?;

    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&jbyte_array, 0, &mut buf)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to copy bytes: {}", e)))?;

    let buf: Vec<u8> = buf.into_iter().map(|b| b as u8).collect();

    if buf.len() != 32 {
        return Err(KeyStoreError::KeyNotFound);
    }

    Ok(buf)
}

/// Get hidden service Ed25519 private key from Android KeyStore
pub fn get_hidden_service_private_key(env: &mut JNIEnv, key_manager: &JObject) -> Result<Vec<u8>, KeyStoreError> {
    let result = env
        .call_method(
            key_manager,
            "getHiddenServiceKeyBytes",
            "()[B",
            &[],
        )
        .map_err(|e| KeyStoreError::JniError(format!("Failed to call getHiddenServiceKeyBytes: {}", e)))?;

    let byte_array = result.l()
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get byte array: {}", e)))?;

    let jbyte_array = JByteArray::from(byte_array);
    let len = env.get_array_length(&jbyte_array)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get array length: {}", e)))?;

    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&jbyte_array, 0, &mut buf)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to copy bytes: {}", e)))?;

    let buf: Vec<u8> = buf.into_iter().map(|b| b as u8).collect();

    if buf.len() != 32 {
        return Err(KeyStoreError::KeyNotFound);
    }

    Ok(buf)
}

/// Sign data using Ed25519 key from Android KeyStore
///
/// Delegates the actual signing operation to Android KeyStore for maximum security
pub fn sign_with_keystore(
    env: &mut JNIEnv,
    key_manager: &JObject,
    data: &[u8],
) -> Result<Vec<u8>, KeyStoreError> {
    // Convert data to Java byte array
    let data_array = env.byte_array_from_slice(data)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to create byte array: {}", e)))?;

    // Call KeyManager.signData(data)
    let result = env
        .call_method(
            key_manager,
            "signData",
            "([B)[B",
            &[(&data_array).into()],
        )
        .map_err(|e| KeyStoreError::SigningFailed)?;

    let signature_array = result.l()
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get signature: {}", e)))?;

    let jbyte_array = JByteArray::from(signature_array);
    let len = env.get_array_length(&jbyte_array)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get signature length: {}", e)))?;

    let mut buf = vec![0i8; len as usize];
    env.get_byte_array_region(&jbyte_array, 0, &mut buf)
        .map_err(|e| KeyStoreError::JniError(format!("Failed to copy signature: {}", e)))?;

    let signature: Vec<u8> = buf.into_iter().map(|b| b as u8).collect();

    if signature.len() != 64 {
        return Err(KeyStoreError::SigningFailed);
    }

    Ok(signature)
}

/// Get KeyManager instance from context
///
/// Retrieves the singleton KeyManager instance for callback operations
pub fn get_key_manager<'a>(env: &mut JNIEnv<'a>, context: &JObject) -> Result<JObject<'a>, KeyStoreError> {
    // Get KeyManager.getInstance(context)
    let key_manager_class = env
        .find_class("com/securelegion/crypto/KeyManager")
        .map_err(|e| KeyStoreError::JniError(format!("Failed to find KeyManager class: {}", e)))?;

    let key_manager = env
        .call_static_method(
            key_manager_class,
            "getInstance",
            "(Landroid/content/Context;)Lcom/securelegion/crypto/KeyManager;",
            &[context.into()],
        )
        .map_err(|e| KeyStoreError::JniError(format!("Failed to get KeyManager instance: {}", e)))?;

    Ok(key_manager.l()
        .map_err(|e| KeyStoreError::JniError(format!("Failed to cast KeyManager: {}", e)))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_error_display() {
        let err = KeyStoreError::KeyNotFound;
        assert_eq!(err.to_string(), "Key not found in KeyStore");
    }
}
