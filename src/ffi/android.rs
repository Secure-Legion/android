use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, jobjectArray};
use jni::JNIEnv;
use std::panic;
use std::sync::{Arc, Mutex};
use once_cell::sync::{OnceCell, Lazy};
use std::collections::HashMap;

use crate::crypto::{
    decrypt_message, encrypt_message, generate_keypair, hash_handle, hash_password, sign_data,
    verify_signature,
};
use crate::network::TorManager;
use crate::protocol::ContactCard;
use crate::blockchain::{register_username, lookup_username};
use tokio::sync::{mpsc, oneshot};

// ==================== HELPER FUNCTIONS ====================

/// Convert Java byte array to Rust Vec<u8>
fn jbytearray_to_vec(env: &mut JNIEnv, array: JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(array)
        .map_err(|e| format!("Failed to convert byte array: {}", e))
}

/// Convert Rust Vec<u8> to Java byte array
fn vec_to_jbytearray<'a>(env: &mut JNIEnv<'a>, data: &[u8]) -> Result<JByteArray<'a>, String> {
    env.byte_array_from_slice(data)
        .map_err(|e| format!("Failed to create byte array: {}", e))
}

/// Convert Java String to Rust String
fn jstring_to_string(env: &mut JNIEnv, string: JString) -> Result<String, String> {
    env.get_string(&string)
        .map(|s| s.into())
        .map_err(|e| format!("Failed to convert string: {}", e))
}

/// Convert Rust String to Java String
fn string_to_jstring<'a>(env: &mut JNIEnv<'a>, string: &str) -> Result<JString<'a>, String> {
    env.new_string(string)
        .map_err(|e| format!("Failed to create string: {}", e))
}

/// Safely execute a function and catch panics
macro_rules! catch_panic {
    ($env:expr, $code:expr, $default:expr) => {
        match panic::catch_unwind(panic::AssertUnwindSafe(|| $code)) {
            Ok(result) => result,
            Err(_) => {
                let _ = $env.throw_new("java/lang/RuntimeException", "Rust panic occurred");
                $default
            }
        }
    };
}

// ==================== GLOBAL TOR MANAGER ====================

/// Global TorManager instance
static GLOBAL_TOR_MANAGER: OnceCell<Arc<Mutex<TorManager>>> = OnceCell::new();
static GLOBAL_PING_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>> = OnceCell::new();

/// Global storage for Pong response channels
/// Maps ping_id -> oneshot sender for sending Pong bytes back to connection handler
static GLOBAL_PONG_SENDERS: OnceCell<Arc<Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>>> = OnceCell::new();

fn get_pong_senders() -> Arc<Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>> {
    GLOBAL_PONG_SENDERS
        .get_or_init(|| Arc::new(Mutex::new(std::collections::HashMap::new())))
        .clone()
}

/// Get or initialize the global TorManager
fn get_tor_manager() -> Arc<Mutex<TorManager>> {
    GLOBAL_TOR_MANAGER
        .get_or_init(|| {
            let tor_manager = TorManager::new().expect("Failed to create TorManager");
            Arc::new(Mutex::new(tor_manager))
        })
        .clone()
}

// ==================== CRYPTOGRAPHY ====================

/// Encrypt a message using XChaCha20-Poly1305 with X25519 ECDH
/// NOTE: This is a temporary MVP implementation that uses the recipient's
/// public key as the encryption key. In production, this should:
/// 1. Accept sender's X25519 private key as parameter
/// 2. Derive shared secret via ECDH: deriveSharedSecret(senderPrivate, recipientPublic)
/// 3. Use that shared secret for encryption
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_encryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    plaintext: JString,
    recipient_public_key: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        // Convert Java types to Rust types
        let plaintext_str = match jstring_to_string(&mut env, plaintext) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let pub_key = match jbytearray_to_vec(&mut env, recipient_public_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // MVP: Use recipient public key as encryption key (32 bytes)
        // TODO: Change signature to accept sender's X25519 private key and derive shared secret
        let key = if pub_key.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pub_key[0..32]);
            arr
        } else {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid public key length");
            return std::ptr::null_mut();
        };

        // Encrypt
        match encrypt_message(plaintext_str.as_bytes(), &key) {
            Ok(encrypted) => match vec_to_jbytearray(&mut env, &encrypted) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    let _ = env.throw_new("java/lang/RuntimeException", e);
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Decrypt a message using XChaCha20-Poly1305 with X25519 ECDH
/// NOTE: This is a temporary MVP implementation that uses the sender's
/// public key as the decryption key. In production, this should:
/// 1. Derive shared secret via ECDH: deriveSharedSecret(ourPrivate, senderPublic)
/// 2. Use that shared secret for decryption
/// For MVP: Both sides must use the same key (sender's X25519 pubkey)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    ciphertext: JByteArray,
    sender_public_key: JByteArray,
    private_key: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // Convert Java types
        let ciphertext_vec = match jbytearray_to_vec(&mut env, ciphertext) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let sender_pub = match jbytearray_to_vec(&mut env, sender_public_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let _priv_key = match jbytearray_to_vec(&mut env, private_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // MVP: Use sender public key as decryption key (matches encryption)
        // TODO: Derive shared secret: deriveSharedSecret(ourPrivate, senderPublic)
        let key = if sender_pub.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sender_pub[0..32]);
            arr
        } else {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid public key length");
            return std::ptr::null_mut();
        };

        // Decrypt
        match decrypt_message(&ciphertext_vec, &key) {
            Ok(plaintext) => {
                let plaintext_str = String::from_utf8_lossy(&plaintext);
                match string_to_jstring(&mut env, &plaintext_str) {
                    Ok(s) => s.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Sign data with Ed25519
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_signData(
    mut env: JNIEnv,
    _class: JClass,
    data: JByteArray,
    private_key: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let data_vec = match jbytearray_to_vec(&mut env, data) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let priv_key = match jbytearray_to_vec(&mut env, private_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        match sign_data(&data_vec, &priv_key) {
            Ok(signature) => match vec_to_jbytearray(&mut env, &signature) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    let _ = env.throw_new("java/lang/RuntimeException", e);
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Verify Ed25519 signature
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_verifySignature(
    mut env: JNIEnv,
    _class: JClass,
    data: JByteArray,
    signature: JByteArray,
    public_key: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        let data_vec = match jbytearray_to_vec(&mut env, data) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        let sig_vec = match jbytearray_to_vec(&mut env, signature) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        let pub_key = match jbytearray_to_vec(&mut env, public_key) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        match verify_signature(&data_vec, &sig_vec, &pub_key) {
            Ok(valid) => if valid { 1 } else { 0 },
            Err(_) => 0,
        }
    }, 0)
}

/// Generate keypair
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_generateKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    catch_panic!(env, {
        let (public_key, private_key) = generate_keypair();

        // Create Object[] array
        let array = match env.new_object_array(2, "java/lang/Object", JByteArray::default()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                return std::ptr::null_mut();
            }
        };

        // Convert keys to byte arrays
        let pub_arr = match vec_to_jbytearray(&mut env, &public_key) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let priv_arr = match vec_to_jbytearray(&mut env, &private_key) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        // Set array elements
        let _ = env.set_object_array_element(&array, 0, pub_arr);
        let _ = env.set_object_array_element(&array, 1, priv_arr);

        array.into_raw()
    }, std::ptr::null_mut())
}

/// Hash password with Argon2id
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_hashPassword(
    mut env: JNIEnv,
    _class: JClass,
    password: JString,
    salt: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let password_str = match jstring_to_string(&mut env, password) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let salt_vec = match jbytearray_to_vec(&mut env, salt) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        match crate::crypto::hashing::hash_password_with_salt(&password_str, &salt_vec) {
            Ok(hash) => match vec_to_jbytearray(&mut env, &hash) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    let _ = env.throw_new("java/lang/RuntimeException", e);
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== NETWORK (Tor Integration) ====================

/// Initialize Tor client and bootstrap connection to Tor network
/// Returns status message
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_initializeTor(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();

        // Run async initialization in blocking context
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        let result = runtime.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.initialize().await
        });

        match result {
            Ok(status) => match string_to_jstring(&mut env, &status) {
                Ok(s) => s.into_raw(),
                Err(_) => {
                    let _ = env.throw_new("java/lang/RuntimeException", "Failed to create status string");
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                let error_msg = format!("Tor initialization failed: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", error_msg);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Create a deterministic hidden service from seed-derived key
/// Returns the .onion address for receiving connections
///
/// # Arguments
/// * `service_port` - The virtual port on the .onion address (e.g., 80, 9150)
/// * `local_port` - The local port to forward connections to (e.g., 9150)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_createHiddenService(
    mut env: JNIEnv,
    _class: JClass,
    service_port: jint,
    local_port: jint,
) -> jstring {
    catch_panic!(env, {
        // Get KeyManager to retrieve seed-derived hidden service key
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get hidden service private key (deterministic from seed)
        let hs_private_key = match crate::ffi::keystore::get_hidden_service_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get hidden service key: {}", e));
                return std::ptr::null_mut();
            }
        };

        let tor_manager = get_tor_manager();

        // Run async hidden service creation with seed-derived key
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        let result = runtime.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.create_hidden_service(service_port as u16, local_port as u16, &hs_private_key).await
        });

        match result {
            Ok(onion_address) => match string_to_jstring(&mut env, &onion_address) {
                Ok(s) => s.into_raw(),
                Err(_) => {
                    let _ = env.throw_new("java/lang/RuntimeException", "Failed to create onion address string");
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                let error_msg = format!("Hidden service creation failed: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", error_msg);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Get the current hidden service .onion address (if created)
/// Returns the .onion address or null if not created yet
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getHiddenServiceAddress(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();
        let manager = tor_manager.lock().unwrap();

        match manager.get_hidden_service_address() {
            Some(address) => match string_to_jstring(&mut env, address) {
                Ok(s) => s.into_raw(),
                Err(_) => std::ptr::null_mut(),
            },
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Start the hidden service listener on the specified port
/// This enables receiving incoming Ping tokens
/// Returns true if listener started successfully
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startHiddenServiceListener(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
) -> jboolean {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();

        // Run async listener start in blocking context
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        let result = runtime.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        });

        match result {
            Ok(receiver) => {
                // Store the receiver globally
                let _ = GLOBAL_PING_RECEIVER.set(Arc::new(Mutex::new(receiver)));
                1 as jboolean
            }
            Err(e) => {
                let error_msg = format!("Failed to start listener: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", error_msg);
                0 as jboolean
            }
        }
    }, 0 as jboolean)
}

/// Stop the hidden service listener
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_stopHiddenServiceListener(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();
        let mut manager = tor_manager.lock().unwrap();
        manager.stop_listener();
    }, ())
}

/// Poll for an incoming Ping token (non-blocking)
/// Returns encoded data: [connection_id (8 bytes)][encrypted_ping_bytes]
/// or null if no ping available
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingPing(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        if let Some(receiver) = GLOBAL_PING_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok((connection_id, ping_bytes)) => {
                    // Encode: [connection_id as 8 bytes little-endian][ping_bytes]
                    let mut encoded = Vec::new();
                    encoded.extend_from_slice(&connection_id.to_le_bytes());
                    encoded.extend_from_slice(&ping_bytes);

                    match vec_to_jbytearray(&mut env, &encoded) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No ping available
                    std::ptr::null_mut()
                }
            }
        } else {
            // Listener not started
            std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Send encrypted Pong response back to a pending connection
///
/// # Arguments
/// * `connection_id` - The connection ID from pollIncomingPing
/// * `encrypted_pong_bytes` - The encrypted Pong token bytes (from createPongToken)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendPongBytes(
    mut env: JNIEnv,
    _class: JClass,
    connection_id: jlong,
    encrypted_pong_bytes: JByteArray,
) {
    catch_panic!(env, {
        // Convert encrypted pong bytes
        let pong_bytes = match jbytearray_to_vec(&mut env, encrypted_pong_bytes) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return;
            }
        };

        log::info!("Sending encrypted Pong response ({} bytes) for connection {}", pong_bytes.len(), connection_id);

        // Send Pong response back through the stored connection
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        let result = runtime.block_on(async {
            crate::network::TorManager::send_pong_response(connection_id as u64, &pong_bytes).await
        });

        match result {
            Ok(_) => {
                log::info!("Encrypted Pong sent successfully for connection {}", connection_id);
            }
            Err(e) => {
                let error_msg = format!("Failed to send Pong: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", error_msg);
            }
        }
    }, ())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendPing(
    mut env: JNIEnv,
    _class: JClass,
    recipient_ed25519_pubkey: JByteArray,
    recipient_x25519_pubkey: JByteArray,
    recipient_onion: JString,
) -> jstring {
    catch_panic!(env, {
        // Convert inputs
        let recipient_ed25519_bytes = match jbytearray_to_vec(&mut env, recipient_ed25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let recipient_x25519_bytes = match jbytearray_to_vec(&mut env, recipient_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let recipient_onion_str = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Get KeyManager for our keys
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our signing private key (Ed25519)
        let our_signing_private = match crate::ffi::keystore::get_signing_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get signing key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Create Ed25519 signing keypair
        let sender_keypair = match ed25519_dalek::SigningKey::from_bytes(&our_signing_private.as_slice().try_into().unwrap()) {
            signing_key => ed25519_dalek::SigningKey::from(signing_key)
        };

        let recipient_ed25519_verifying = match ed25519_dalek::VerifyingKey::from_bytes(&recipient_ed25519_bytes.as_slice().try_into().unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid recipient Ed25519 pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Create PingToken (signed)
        let ping_token = match crate::network::PingToken::new(&sender_keypair, &recipient_ed25519_verifying) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create Ping: {}", e));
                return std::ptr::null_mut();
            }
        };

        let ping_id = hex::encode(&ping_token.nonce);

        // Serialize PingToken
        let ping_bytes = match ping_token.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to serialize Ping: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 encryption private key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret using X25519 ECDH
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Encrypt PingToken with shared secret
        let encrypted_ping = match crate::crypto::encryption::encrypt_message(&ping_bytes, &shared_secret) {
            Ok(enc) => enc,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Encryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 public key to prepend to message
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get our X25519 pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Wire format: [Our X25519 Public Key - 32 bytes][Encrypted Ping Token]
        let mut wire_message = Vec::new();
        wire_message.extend_from_slice(&our_x25519_public);
        wire_message.extend_from_slice(&encrypted_ping);

        // Send encrypted Ping via Tor
        let tor_manager = get_tor_manager();
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        const PING_PONG_PORT: u16 = 9150;

        let result = runtime.block_on(async {
            let manager = tor_manager.lock().unwrap();
            let mut conn = manager.connect(&recipient_onion_str, PING_PONG_PORT).await?;
            manager.send(&mut conn, &wire_message).await?;

            // Wait for encrypted Pong response
            let response = manager.receive(&mut conn, 4096).await?;

            Ok::<Vec<u8>, Box<dyn std::error::Error>>(response)
        });

        match result {
            Ok(encrypted_pong_response) => {
                log::info!("Encrypted Ping sent successfully: {}", ping_id);

                // Store encrypted Pong for later decryption by waitForPong
                // Extract sender's X25519 pubkey (first 32 bytes) and encrypted data
                if encrypted_pong_response.len() > 32 {
                    // Store in global session for waitForPong to decrypt
                    // For now, just log success
                    log::info!("Received encrypted Pong response ({} bytes)", encrypted_pong_response.len());
                }

                match string_to_jstring(&mut env, &ping_id) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to send Ping: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_waitForPong(
    mut env: JNIEnv,
    _class: JClass,
    ping_id: JString,
    timeout_seconds: jint,
) -> jboolean {
    catch_panic!(env, {
        // Convert ping_id to Rust string
        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let timeout_ms = (timeout_seconds as u64) * 1000;
        let poll_interval_ms = 100; // Check every 100ms
        let start_time = std::time::Instant::now();

        // Poll for Pong with timeout
        loop {
            // Check if Pong has been received
            if let Some(_pong_session) = crate::network::pingpong::get_pong_session(&ping_id_str) {
                // Pong found! Clean up and return success
                crate::network::pingpong::remove_pong_session(&ping_id_str);
                return 1; // true
            }

            // Check timeout
            if start_time.elapsed().as_millis() as u64 >= timeout_ms {
                // Timeout - no Pong received
                return 0; // false
            }

            // Sleep before next poll
            std::thread::sleep(std::time::Duration::from_millis(poll_interval_ms));
        }
    }, 0)
}

/// Global storage for decrypted Ping tokens: ping_id -> PingToken
static STORED_PINGS: Lazy<Arc<Mutex<HashMap<String, crate::network::PingToken>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Decrypt an incoming encrypted Ping token
///
/// Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Ping Token]
/// Returns: Ping ID (String) that can be passed to respondToPing
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptIncomingPing(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_ping_wire: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // Convert wire bytes
        let wire_bytes = match jbytearray_to_vec(&mut env, encrypted_ping_wire) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Wire format: [Sender X25519 Pubkey - 32 bytes][Encrypted Token]
        if wire_bytes.len() < 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Wire message too short");
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (first 32 bytes)
        let sender_x25519_pubkey = &wire_bytes[0..32];

        // Extract encrypted Ping token (rest of bytes)
        let encrypted_ping = &wire_bytes[32..];

        log::info!("Decrypting incoming Ping: {} bytes encrypted data", encrypted_ping.len());

        // Get KeyManager to access our X25519 private key
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 private key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get X25519 private key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret using X25519 ECDH
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            sender_x25519_pubkey,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        log::info!("Derived shared secret for Ping decryption");

        // Decrypt the Ping token
        let decrypted_ping = match crate::crypto::encryption::decrypt_message(encrypted_ping, &shared_secret) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                let _ = env.throw_new("java/lang/SecurityException", format!("Ping decryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        log::info!("Ping decrypted successfully: {} bytes", decrypted_ping.len());

        // Parse PingToken
        let ping_token = match crate::network::PingToken::from_bytes(&decrypted_ping) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to parse PingToken: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Verify signature
        match ping_token.verify() {
            Ok(true) => {},
            Ok(false) => {
                let _ = env.throw_new("java/lang/SecurityException", "Invalid Ping signature");
                return std::ptr::null_mut();
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Signature verification failed: {}", e));
                return std::ptr::null_mut();
            }
        }

        // Generate unique ping_id from nonce
        let ping_id = hex::encode(&ping_token.nonce);

        // Store the PingToken
        {
            let mut stored = STORED_PINGS.lock().unwrap();
            stored.insert(ping_id.clone(), ping_token);
        }

        log::info!("Stored Ping with ID: {}", ping_id);

        // Return ping_id as String
        match env.new_string(&ping_id) {
            Ok(jstr) => jstr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create string: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_respondToPing(
    mut env: JNIEnv,
    _class: JClass,
    ping_id: JString,
    authenticated: jboolean,
) -> jbyteArray {
    catch_panic!(env, {
        // If not authenticated, return null (no Pong)
        if authenticated == 0 {
            log::info!("Ping denied by user - not sending Pong");
            return std::ptr::null_mut();
        }

        // Convert ping_id to String
        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Look up stored PingToken
        let ping_token = {
            let mut stored = STORED_PINGS.lock().unwrap();
            match stored.remove(&ping_id_str) {
                Some(token) => token,
                None => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Ping ID not found: {}", ping_id_str));
                    return std::ptr::null_mut();
                }
            }
        };

        log::info!("Retrieved Ping {} from storage", ping_id_str);

        // Get sender's X25519 public key from PingToken
        // Note: We need to extract this from the sender's Ed25519 public key
        // For now, we'll derive shared secret using the same approach as in sendPing

        // Get KeyManager for our keys
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our signing private key
        let our_signing_private = match crate::ffi::keystore::get_signing_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get signing key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Create Ed25519 keypair
        let recipient_keypair = match ed25519_dalek::SigningKey::from_bytes(&our_signing_private.as_slice().try_into().unwrap()) {
            signing_key => ed25519_dalek::SigningKey::from(signing_key)
        };

        // Create PongToken
        let pong_token = match crate::network::PongToken::new(&ping_token, &recipient_keypair, true) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create Pong: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Serialize PongToken
        let pong_bytes = match pong_token.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to serialize Pong: {}", e));
                return std::ptr::null_mut();
            }
        };

        log::info!("Pong created successfully for Ping {}", hex::encode(&ping_token.nonce));

        // Get our X25519 private key for encryption
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get X25519 private key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get sender's X25519 public key
        // TODO: For now, use the sender's Ed25519 public key bytes directly as X25519
        // In production, sender should include their X25519 pubkey in Ping
        let sender_x25519_pubkey = &ping_token.sender_pubkey;

        // Derive shared secret
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            sender_x25519_pubkey,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Encrypt Pong token
        let encrypted_pong = match crate::crypto::encryption::encrypt_message(&pong_bytes, &shared_secret) {
            Ok(ciphertext) => ciphertext,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Pong encryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 public key to prepend
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get our X25519 pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Wire format: [Our X25519 Public Key - 32 bytes][Encrypted Pong Token]
        let mut wire_message = Vec::new();
        wire_message.extend_from_slice(&our_x25519_public);
        wire_message.extend_from_slice(&encrypted_pong);

        log::info!("Encrypted Pong: {} bytes wire message", wire_message.len());

        // Return encrypted Pong wire message
        match vec_to_jbytearray(&mut env, &wire_message) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendDirectMessage(
    _env: JNIEnv,
    _class: JClass,
    _recipient_onion: JString,
    _encrypted_message: JByteArray,
) -> jboolean {
    // TODO: Implement direct message sending
    1
}

// ==================== PING-PONG PROTOCOL (Socket.IO) ====================

/// Create encrypted Ping token for socket.io wake notification
/// Uses KeyStore keys via JNI callbacks + X25519 ECDH for encryption
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_createPingToken(
    mut env: JNIEnv,
    _class: JClass,
    recipient_pubkey: JByteArray,
    recipient_x25519_pubkey: JByteArray,
    ping_id: JString,
) -> jbyteArray {
    catch_panic!(env, {
        // 1. Convert Java inputs
        let recipient_ed25519_bytes = match jbytearray_to_vec(&mut env, recipient_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let recipient_x25519_bytes = match jbytearray_to_vec(&mut env, recipient_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // 2. Get KeyManager instance
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 3. Get our signing keys from KeyStore
        let our_signing_private = match crate::ffi::keystore::get_signing_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get signing key: {}", e));
                return std::ptr::null_mut();
            }
        };

        let our_signing_public = match crate::ffi::keystore::get_signing_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get public key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 4. Create Ed25519 keypair for signing
        let sender_keypair = match ed25519_dalek::SigningKey::from_bytes(&our_signing_private.as_slice().try_into().unwrap()) {
            signing_key => {
                ed25519_dalek::SigningKey::from(signing_key)
            }
        };

        let recipient_ed25519_pubkey = match ed25519_dalek::VerifyingKey::from_bytes(&recipient_ed25519_bytes.as_slice().try_into().unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid recipient pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 5. Create PingToken
        let ping_token = match crate::network::PingToken::new(&sender_keypair, &recipient_ed25519_pubkey) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create Ping: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 6. Serialize PingToken
        let ping_bytes = match ping_token.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to serialize Ping: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 7. Get our X25519 encryption key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 8. Derive shared secret using X25519 ECDH
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 9. Encrypt PingToken with shared secret
        let encrypted_ping = match crate::crypto::encryption::encrypt_message(&ping_bytes, &shared_secret) {
            Ok(enc) => enc,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Encryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 10. Return encrypted bytes
        match vec_to_jbytearray(&mut env, &encrypted_ping) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Decrypt and parse incoming Ping token
/// Stores in global session storage for later Pong creation
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_nativeDecryptPingToken(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_ping: JByteArray,
    sender_x25519_pubkey: JByteArray,
) -> jobjectArray {
    catch_panic!(env, {
        // 1. Convert inputs
        let encrypted_bytes = match jbytearray_to_vec(&mut env, encrypted_ping) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let sender_x25519_bytes = match jbytearray_to_vec(&mut env, sender_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // 2. Get KeyManager
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 3. Get our X25519 private key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 4. Derive shared secret
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &sender_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 5. Decrypt
        let ping_bytes = match crate::crypto::encryption::decrypt_message(&encrypted_bytes, &shared_secret) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Decryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 6. Deserialize PingToken
        let ping_token = match crate::network::PingToken::from_bytes(&ping_bytes) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to parse Ping: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 7. Verify signature
        match ping_token.verify() {
            Ok(true) => {}, // Valid
            Ok(false) => {
                let _ = env.throw_new("java/lang/SecurityException", "Invalid Ping signature");
                return std::ptr::null_mut();
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Signature verification failed: {}", e));
                return std::ptr::null_mut();
            }
        }

        // 8. Store in global session storage
        let ping_id = hex::encode(&ping_token.nonce);
        crate::network::store_ping_session(&ping_id, ping_token.clone());

        // 9. Extract fields for return
        let sender_pubkey_bytes = ping_token.sender_pubkey.to_vec();
        let timestamp_str = ping_token.timestamp.to_string();

        // 10. Create return array [sender_pubkey, ping_id_bytes, timestamp_bytes]
        let byte_array_class = env.find_class("[B").unwrap();
        let array = match env.new_object_array(3, byte_array_class, JObject::null()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                return std::ptr::null_mut();
            }
        };

        let sender_arr = match vec_to_jbytearray(&mut env, &sender_pubkey_bytes) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let ping_id_arr = match vec_to_jbytearray(&mut env, ping_id.as_bytes()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let timestamp_arr = match vec_to_jbytearray(&mut env, timestamp_str.as_bytes()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let _ = env.set_object_array_element(&array, 0, sender_arr);
        let _ = env.set_object_array_element(&array, 1, ping_id_arr);
        let _ = env.set_object_array_element(&array, 2, timestamp_arr);

        array.into_raw()
    }, std::ptr::null_mut())
}

/// Create encrypted Pong response token
/// Retrieves stored Ping from global session storage
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_createPongToken(
    mut env: JNIEnv,
    _class: JClass,
    sender_x25519_pubkey: JByteArray,
    ping_id: JString,
) -> jbyteArray {
    catch_panic!(env, {
        // 1. Convert inputs
        let sender_x25519_bytes = match jbytearray_to_vec(&mut env, sender_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // 2. Retrieve stored Ping from global session storage
        let stored_session = match crate::network::get_ping_session(&ping_id_str) {
            Some(session) => session,
            None => {
                let _ = env.throw_new("java/lang/IllegalStateException", "Ping session not found");
                return std::ptr::null_mut();
            }
        };

        let ping_token = stored_session.ping_token;

        // 3. Get KeyManager
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 4. Get our signing keys
        let our_signing_private = match crate::ffi::keystore::get_signing_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get signing key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 5. Create Ed25519 keypair for signing
        let recipient_keypair = match ed25519_dalek::SigningKey::from_bytes(&our_signing_private.as_slice().try_into().unwrap()) {
            signing_key => {
                ed25519_dalek::SigningKey::from(signing_key)
            }
        };

        // 6. Create PongToken
        let pong_token = match crate::network::PongToken::new(&ping_token, &recipient_keypair, true) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create Pong: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 7. Serialize PongToken
        let pong_bytes = match pong_token.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to serialize Pong: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 8. Get our X25519 encryption key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 9. Derive shared secret using X25519 ECDH (with sender's X25519 public key)
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &sender_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 10. Encrypt PongToken with shared secret
        let encrypted_pong = match crate::crypto::encryption::encrypt_message(&pong_bytes, &shared_secret) {
            Ok(enc) => enc,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Encryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 11. Clean up: remove Ping session after Pong is created
        crate::network::remove_ping_session(&ping_id_str);

        // 12. Return encrypted bytes
        match vec_to_jbytearray(&mut env, &encrypted_pong) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Decrypt and parse incoming Pong token for verification
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_nativeDecryptPongToken(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_pong: JByteArray,
    recipient_x25519_pubkey: JByteArray,
    recipient_ed25519_pubkey: JByteArray,
) -> jobjectArray {
    catch_panic!(env, {
        // 1. Convert inputs
        let encrypted_bytes = match jbytearray_to_vec(&mut env, encrypted_pong) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let recipient_x25519_bytes = match jbytearray_to_vec(&mut env, recipient_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let recipient_ed25519_bytes = match jbytearray_to_vec(&mut env, recipient_ed25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // 2. Get KeyManager
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get context: {}", e));
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 3. Get our X25519 private key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 4. Derive shared secret
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 5. Decrypt
        let pong_bytes = match crate::crypto::encryption::decrypt_message(&encrypted_bytes, &shared_secret) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Decryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 6. Deserialize PongToken
        let pong_token = match crate::network::PongToken::from_bytes(&pong_bytes) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to parse Pong: {}", e));
                return std::ptr::null_mut();
            }
        };

        // 7. Verify signature with recipient's Ed25519 public key
        let recipient_ed25519_pubkey = match ed25519_dalek::VerifyingKey::from_bytes(&recipient_ed25519_bytes.as_slice().try_into().unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid recipient pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        match pong_token.verify(&recipient_ed25519_pubkey) {
            Ok(true) => {}, // Valid
            Ok(false) => {
                let _ = env.throw_new("java/lang/SecurityException", "Invalid Pong signature");
                return std::ptr::null_mut();
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Signature verification failed: {}", e));
                return std::ptr::null_mut();
            }
        }

        // 8. Extract fields for return
        let ping_id = hex::encode(&pong_token.ping_nonce);
        let timestamp_str = pong_token.timestamp.to_string();
        let authenticated = if pong_token.authenticated { "true" } else { "false" };

        // 9. Create return array [recipient_pubkey, ping_id_bytes, timestamp_bytes]
        let byte_array_class = env.find_class("[B").unwrap();
        let array = match env.new_object_array(3, byte_array_class, JObject::null()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                return std::ptr::null_mut();
            }
        };

        let recipient_arr = match vec_to_jbytearray(&mut env, &recipient_ed25519_bytes) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let ping_id_arr = match vec_to_jbytearray(&mut env, ping_id.as_bytes()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let timestamp_arr = match vec_to_jbytearray(&mut env, timestamp_str.as_bytes()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let _ = env.set_object_array_element(&array, 0, recipient_arr);
        let _ = env.set_object_array_element(&array, 1, ping_id_arr);
        let _ = env.set_object_array_element(&array, 2, timestamp_arr);

        // 10. Store Pong in global session for waitForPong polling
        crate::network::pingpong::store_pong_session(&ping_id, pong_token);

        array.into_raw()
    }, std::ptr::null_mut())
}

// ==================== RELAY NETWORK (Stubs) ====================

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_uploadToRelay(
    mut env: JNIEnv,
    _class: JClass,
    _encrypted_message: JByteArray,
    _recipient_public_key: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // TODO: Implement relay upload
        match string_to_jstring(&mut env, "message_id_123") {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_checkRelay(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    catch_panic!(env, {
        // TODO: Implement relay checking
        // Return empty array for now
        match env.new_object_array(0, "java/lang/String", JString::default()) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_downloadFromRelay(
    mut env: JNIEnv,
    _class: JClass,
    _message_id: JString,
) -> jbyteArray {
    catch_panic!(env, {
        // TODO: Implement relay download
        match vec_to_jbytearray(&mut env, &[]) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_deleteFromRelay(
    _env: JNIEnv,
    _class: JClass,
    _message_id: JString,
) -> jboolean {
    // TODO: Implement relay deletion
    1
}

// ==================== BLOCKCHAIN (Stubs) ====================

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_initializeSolanaWallet(
    mut env: JNIEnv,
    _class: JClass,
    _private_key: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // TODO: Implement Solana wallet
        match string_to_jstring(&mut env, "SoL1234567890abcdefghijklmnopqrstuv") {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getSolanaBalance(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    // TODO: Implement balance checking
    0
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendSolanaTransaction(
    mut env: JNIEnv,
    _class: JClass,
    _to_address: JString,
    _amount_lamports: jlong,
) -> jstring {
    catch_panic!(env, {
        // TODO: Implement SOL transaction
        match string_to_jstring(&mut env, "tx_signature_123") {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Register username on Solana Name Service with PIN protection
/// Args:
///   username - Username to register (e.g., "john")
///   pin - PIN for encrypting contact card
///   contactCardJson - ContactCard serialized as JSON
/// Returns: Full SNS domain (e.g., "john.securelegion.sol")
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_registerUsername(
    mut env: JNIEnv,
    _class: JClass,
    username: JString,
    pin: JString,
    contact_card_json: JString,
) -> jstring {
    catch_panic!(env, {
        // Convert Java strings to Rust
        let username_str = match jstring_to_string(&mut env, username) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let pin_str = match jstring_to_string(&mut env, pin) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let card_json = match jstring_to_string(&mut env, contact_card_json) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Deserialize ContactCard
        let contact_card = match ContactCard::from_json(&card_json) {
            Ok(card) => card,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException",
                    format!("Failed to parse ContactCard JSON: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Register username
        match register_username(&username_str, &pin_str, &contact_card) {
            Ok(domain) => {
                match string_to_jstring(&mut env, &domain) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException",
                    format!("Username registration failed: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Lookup username on Solana Name Service and decrypt with PIN
/// Args:
///   username - Username to lookup (e.g., "john")
///   pin - PIN to decrypt contact card
/// Returns: ContactCard as JSON string
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_lookupUsername(
    mut env: JNIEnv,
    _class: JClass,
    username: JString,
    pin: JString,
) -> jstring {
    catch_panic!(env, {
        // Convert Java strings to Rust
        let username_str = match jstring_to_string(&mut env, username) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let pin_str = match jstring_to_string(&mut env, pin) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Lookup and decrypt
        match lookup_username(&username_str, &pin_str) {
            Ok(contact_card) => {
                // Serialize to JSON
                match contact_card.to_json() {
                    Ok(json) => {
                        match string_to_jstring(&mut env, &json) {
                            Ok(s) => s.into_raw(),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException",
                            format!("Failed to serialize ContactCard: {}", e));
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException",
                    format!("Username lookup failed: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== IPFS (Stubs) ====================

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_uploadToIPFS(
    mut env: JNIEnv,
    _class: JClass,
    _data: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // TODO: Implement IPFS upload
        match string_to_jstring(&mut env, "QmIPFS123abc") {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_downloadFromIPFS(
    mut env: JNIEnv,
    _class: JClass,
    _cid: JString,
) -> jbyteArray {
    catch_panic!(env, {
        // TODO: Implement IPFS download
        match vec_to_jbytearray(&mut env, &[]) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

// ==================== X25519 KEY OPERATIONS ====================

/// Generate X25519 keypair for encryption
/// Returns: byte[2][32] - [publicKey, privateKey]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_generateX25519Keypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    catch_panic!(env, {
        let (public_key, private_key) = crate::crypto::key_exchange::generate_static_keypair();

        // Create Object[] array
        let array = match env.new_object_array(2, "java/lang/Object", JByteArray::default()) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                return std::ptr::null_mut();
            }
        };

        // Convert keys to byte arrays
        let pub_arr = match vec_to_jbytearray(&mut env, &public_key) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let priv_arr = match vec_to_jbytearray(&mut env, &private_key) {
            Ok(arr) => arr,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        // Set array elements
        let _ = env.set_object_array_element(&array, 0, pub_arr);
        let _ = env.set_object_array_element(&array, 1, priv_arr);

        array.into_raw()
    }, std::ptr::null_mut())
}

/// Derive X25519 public key from private key
/// Args: privateKey - 32-byte X25519 private key
/// Returns: 32-byte public key
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_deriveX25519PublicKey(
    mut env: JNIEnv,
    _class: JClass,
    private_key: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        // Convert JNI byte array to Rust
        let private_key_bytes = match jbytearray_to_vec(&mut env, private_key) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        // Derive public key
        match crate::crypto::key_exchange::derive_public_key(&private_key_bytes) {
            Ok(public_key) => {
                match vec_to_jbytearray(&mut env, &public_key) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Derive shared secret using X25519 ECDH
/// Args:
///   ourPrivateKey - Our 32-byte X25519 private key
///   theirPublicKey - Their 32-byte X25519 public key
/// Returns: 32-byte shared secret
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_deriveSharedSecret(
    mut env: JNIEnv,
    _class: JClass,
    our_private_key: JByteArray,
    their_public_key: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        // Convert JNI byte arrays to Rust
        let our_private = match jbytearray_to_vec(&mut env, our_private_key) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        let their_public = match jbytearray_to_vec(&mut env, their_public_key) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret
        match crate::crypto::key_exchange::derive_shared_secret(&our_private, &their_public) {
            Ok(shared_secret) => {
                match vec_to_jbytearray(&mut env, &shared_secret) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== UTILITY ====================

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        match string_to_jstring(&mut env, crate::VERSION) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}
