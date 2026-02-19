use jni::objects::{JByteArray, JClass, JObject, JString, GlobalRef};
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jlong, jstring, jobjectArray, JNI_TRUE, JNI_FALSE};
use jni::JNIEnv;
use std::panic;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicI32, Ordering};
use once_cell::sync::{OnceCell, Lazy};
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::crypto::{
    decrypt_message, encrypt_message, generate_keypair, sign_data,
    verify_signature, derive_root_key, evolve_chain_key, derive_message_key,
    encrypt_message_with_evolution, decrypt_message_with_evolution,
    derive_receive_key_at_sequence,
};
use crate::network::{TorManager, PENDING_CONNECTIONS};
use crate::audio::voice_streaming::{VoiceStreamingListener, VoicePacket};
use tokio::sync::mpsc;
use tokio::io::AsyncReadExt;

// ==================== PORT CONSTANTS (Single Source of Truth) ====================
// These must match Kotlin side constants!
const MAIN_LISTENER_PORT: u16 = 8080; // Main multiplexed listener (all message types: ping, pong, message, ack)
const PING_PONG_HANDSHAKE_PORT: u16 = 9150; // Ping/Pong handshake port (used in sendPongToNewConnection)
// NOTE: Voice streaming uses separate ports defined in VoiceStreamingListener

// ==================== STRESS TEST & DEBUG METRICS ====================
// Thread-safe counters for diagnosing SOCKS timeout and MESSAGE_TX initialization race
// Public so they can be accessed from network::tor for receiver-side instrumentation

/// Categorized error counters for sendMessageBlob failures
pub static BLOB_FAIL_SOCKS_TIMEOUT: AtomicU64 = AtomicU64::new(0);
pub static BLOB_FAIL_CONNECT_ERR: AtomicU64 = AtomicU64::new(0);
pub static BLOB_FAIL_TOR_NOT_READY: AtomicU64 = AtomicU64::new(0);
pub static BLOB_FAIL_WRITE_ERR: AtomicU64 = AtomicU64::new(0);
pub static BLOB_FAIL_UNKNOWN: AtomicU64 = AtomicU64::new(0);

/// Receiver-side metrics
pub static RX_MESSAGE_ACCEPT_COUNT: AtomicU64 = AtomicU64::new(0); // Messages successfully accepted by receiver
pub static RX_MESSAGE_TX_DROP_COUNT: AtomicU64 = AtomicU64::new(0); // Messages dropped due to channel not initialized

/// Listener lifecycle metrics
pub static LISTENER_BIND_COUNT: AtomicU64 = AtomicU64::new(0); // Total listener bind attempts
pub static LISTENER_REPLACED_COUNT: AtomicU64 = AtomicU64::new(0); // Listener replaced mid-run (thrashing indicator)
pub static LAST_LISTENER_PORT: AtomicI32 = AtomicI32::new(0); // Last bound port (for detecting port changes)

/// Pong session tracking (session leak detector)
pub static PONG_SESSION_COUNT: AtomicU64 = AtomicU64::new(0); // Current active Pong sessions

// ==================== LIBRARY INITIALIZATION ====================

/// Initialize Android logging when library loads
/// This is called automatically by the JVM when the native library is loaded
#[no_mangle]
pub extern "C" fn JNI_OnLoad(_vm: *mut jni::sys::JavaVM, _reserved: *mut std::ffi::c_void) -> jni::sys::jint {
    // Initialize Android logger with INFO level
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("SecureLegion-Rust")
    );

    log::info!("SecureLegion native library loaded");

    // Return JNI version
    jni::sys::JNI_VERSION_1_6
}

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

/// Validate message type byte is a known type
fn is_valid_message_type(msg_type: u8) -> bool {
    matches!(msg_type,
        crate::network::tor::MSG_TYPE_PING |
        crate::network::tor::MSG_TYPE_PONG |
        crate::network::tor::MSG_TYPE_TEXT |
        crate::network::tor::MSG_TYPE_VOICE |
        crate::network::tor::MSG_TYPE_TAP |
        crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION |
        crate::network::tor::MSG_TYPE_FRIEND_REQUEST |
        crate::network::tor::MSG_TYPE_FRIEND_REQUEST_ACCEPTED |
        crate::network::tor::MSG_TYPE_IMAGE |
        crate::network::tor::MSG_TYPE_PAYMENT_REQUEST |
        crate::network::tor::MSG_TYPE_PAYMENT_SENT |
        crate::network::tor::MSG_TYPE_PAYMENT_ACCEPTED |
        crate::network::tor::MSG_TYPE_CALL_SIGNALING |
        crate::network::tor::MSG_TYPE_PROFILE_UPDATE |
        crate::network::tor::MSG_TYPE_CRDT_OPS |
        crate::network::tor::MSG_TYPE_SYNC_REQUEST |
        crate::network::tor::MSG_TYPE_SYNC_CHUNK
    )
}

/// Normalize stored wire bytes by detecting and prepending missing type byte
///
/// Legacy packets from older builds may be missing the type byte prefix.
/// This function migrates them to the new format: [type][pubkey32][ciphertext...]
///
/// # Arguments
/// * `expected_type` - The message type this wire blob should have (based on context)
/// * `wire_bytes` - The stored wire bytes (may or may not have type byte)
///
/// # Returns
/// Normalized wire bytes with type byte at offset 0
fn normalize_wire_bytes(expected_type: u8, wire_bytes: &[u8]) -> Vec<u8> {
    if wire_bytes.is_empty() {
        log::warn!("normalize_wire_bytes: empty wire bytes");
        return wire_bytes.to_vec();
    }

    let first_byte = wire_bytes[0];
    let is_typed = is_valid_message_type(first_byte);

    if is_typed {
        // Already has type byte, verify it matches expected
        if first_byte != expected_type {
            log::warn!(
                "normalize_wire_bytes: type mismatch! expected=0x{:02x}, found=0x{:02x} (len={})",
                expected_type, first_byte, wire_bytes.len()
            );
        }
        wire_bytes.to_vec() // Already typed, return as-is
    } else {
        // Legacy format without type byte - prepend expected type
        log::info!(
            " LEGACY_WIRE_MIGRATED: prepending type=0x{:02x} to {}-byte legacy wire blob",
            expected_type, wire_bytes.len()
        );
        let mut result = Vec::with_capacity(1 + wire_bytes.len());
        result.push(expected_type);
        result.extend_from_slice(wire_bytes);
        result
    }
}

// ==================== GLOBAL TOR MANAGER ====================

/// Global TorManager instance
/// Using tokio::sync::Mutex instead of std::sync::Mutex to prevent deadlocks when holding locks across .await
static GLOBAL_TOR_MANAGER: OnceCell<Arc<Mutex<TorManager>>> = OnceCell::new();
static GLOBAL_PING_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>> = OnceCell::new();
static GLOBAL_TAP_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>> = OnceCell::new();
static GLOBAL_PONG_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>> = OnceCell::new();
static GLOBAL_ACK_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>> = OnceCell::new();
static GLOBAL_MESSAGE_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>> = OnceCell::new();
static GLOBAL_VOICE_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>> = OnceCell::new();
static GLOBAL_FRIEND_REQUEST_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>> = OnceCell::new();

/// Global Voice Streaming Listener (v2.0)
static GLOBAL_VOICE_LISTENER: OnceCell<Arc<tokio::sync::Mutex<VoiceStreamingListener>>> = OnceCell::new();

/// Global Voice Packet Callback (v2.0)
/// Stores a global reference to the Kotlin callback object
static GLOBAL_VOICE_CALLBACK: OnceCell<Mutex<Option<GlobalRef>>> = OnceCell::new();

/// Global Voice Signaling Callback (v2.0)
/// Stores a global reference to the Kotlin callback object for signaling messages (CALL_OFFER, CALL_ANSWER, etc)
static GLOBAL_VOICE_SIGNALING_CALLBACK: OnceCell<Mutex<Option<GlobalRef>>> = OnceCell::new();

/// Global Tor Event Callback
/// Stores a global reference to the Kotlin callback object for ControlPort events (CIRC, HS_DESC, etc)
static GLOBAL_TOR_EVENT_CALLBACK: OnceCell<Mutex<Option<GlobalRef>>> = OnceCell::new();

/// Global JavaVM for Tor event callbacks
/// Stored once at registration time, used to attach threads for event forwarding
static GLOBAL_TOR_EVENT_JVM: OnceCell<jni::JavaVM> = OnceCell::new();

/// Global Tokio runtime for async operations
/// This runtime persists for the lifetime of the process, allowing spawned tasks to continue running
static GLOBAL_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Runtime::new().expect("Failed to create global Tokio runtime")
});

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

/// Get or initialize the global Voice Streaming Listener
fn get_voice_listener() -> Arc<tokio::sync::Mutex<VoiceStreamingListener>> {
    GLOBAL_VOICE_LISTENER
        .get_or_init(|| {
            let voice_listener = VoiceStreamingListener::new();
            Arc::new(tokio::sync::Mutex::new(voice_listener))
        })
        .clone()
}

// ==================== BLOCKING POLL HELPERS ====================

/// Blocking recv on a (u64, Vec<u8>) channel with timeout.
/// Parks the calling thread until data arrives or timeout elapses.
/// Returns None on timeout, channel closure, or if receiver not initialized.
/// SAFETY: Must be called from a non-tokio thread (JVM Dispatchers.IO is safe).
fn blocking_recv_pair(
    receiver: &OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>>,
    timeout_secs: u64,
) -> Option<(u64, Vec<u8>)> {
    let rx_arc = receiver.get()?;
    let mut rx = rx_arc.lock().unwrap();

    GLOBAL_RUNTIME.block_on(async {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            rx.recv()
        ).await {
            Ok(data) => data,
            Err(_) => None, // Timeout
        }
    })
}

/// Blocking recv on a Vec<u8> channel with timeout.
fn blocking_recv_vec(
    receiver: &OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>>,
    timeout_secs: u64,
) -> Option<Vec<u8>> {
    let rx_arc = receiver.get()?;
    let mut rx = rx_arc.lock().unwrap();

    GLOBAL_RUNTIME.block_on(async {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            rx.recv()
        ).await {
            Ok(data) => data,
            Err(_) => None,
        }
    })
}

// ==================== CRYPTOGRAPHY ====================

/// Encrypt a message using XChaCha20-Poly1305 with X25519 ECDH
/// Uses proper X25519 ECDH key exchange to derive shared secret
/// Wire format: [Our X25519 Public Key - 32 bytes][Encrypted Message]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_encryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    plaintext: JString,
    recipient_x25519_public_key: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        // Convert Java types to Rust types
        let mut plaintext_str = match jstring_to_string(&mut env, plaintext) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let recipient_x25519_bytes = match jbytearray_to_vec(&mut env, recipient_x25519_public_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if recipient_x25519_bytes.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid X25519 public key length (expected 32 bytes)");
            return std::ptr::null_mut();
        }

        // Get application context
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

        // Get KeyManager instance
        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 encryption private key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption private key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 public key (needed for wire format)
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption public key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret using X25519 ECDH
        let mut shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Encrypt with shared secret
        let encrypted = match encrypt_message(plaintext_str.as_bytes(), &shared_secret) {
            Ok(enc) => enc,
            Err(e) => {
                shared_secret.zeroize();
                let _ = env.throw_new("java/lang/RuntimeException", format!("Encryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Wire format: [Our X25519 Public Key - 32 bytes][Encrypted Message]
        let mut wire_message = Vec::new();
        wire_message.extend_from_slice(&our_x25519_public);
        wire_message.extend_from_slice(&encrypted);

        let result = match vec_to_jbytearray(&mut env, &wire_message) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        };

        // SECURITY: Zeroize sensitive data before dropping
        unsafe {
            plaintext_str.as_bytes_mut().zeroize();
        }
        shared_secret.zeroize();

        result
    }, std::ptr::null_mut())
}

/// Decrypt a message using XChaCha20-Poly1305 with X25519 ECDH
/// Uses proper X25519 ECDH key exchange to derive shared secret
/// Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Message]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    wire_message: JByteArray,
    _sender_public_key: JByteArray,
    _private_key: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // Convert wire message (sender X25519 pubkey + encrypted data)
        let wire_bytes = match jbytearray_to_vec(&mut env, wire_message) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Message]
        if wire_bytes.len() < 32 + 24 + 16 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid wire message length (too short)");
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (first 32 bytes)
        let mut sender_x25519_public = [0u8; 32];
        sender_x25519_public.copy_from_slice(&wire_bytes[0..32]);

        // Extract encrypted message (remaining bytes)
        let encrypted_data = &wire_bytes[32..];

        // Get application context
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

        // Get KeyManager instance
        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 encryption private key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption private key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret using X25519 ECDH
        let mut shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &sender_x25519_public,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Decrypt with shared secret
        let result = match decrypt_message(encrypted_data, &shared_secret) {
            Ok(mut plaintext) => {
                let plaintext_str = String::from_utf8_lossy(&plaintext);
                let result = match string_to_jstring(&mut env, &plaintext_str) {
                    Ok(s) => s.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                };
                // SECURITY: Zeroize plaintext after converting to string
                plaintext.zeroize();
                result
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Decryption failed: {}", e));
                std::ptr::null_mut()
            }
        };

        // SECURITY: Zeroize sensitive data before dropping
        shared_secret.zeroize();

        result
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
/// (Tor daemon managed by OnionProxyManager, this just connects to control port)
/// Returns status message
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_initializeTor(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {

        let tor_manager = get_tor_manager();

        // Event listener should already be started via startBootstrapListener()
        // Run async initialization using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.initialize().await
        });

        match result {
            Ok(status) => {
                log::info!("Tor initialized successfully");

                match string_to_jstring(&mut env, &status) {
                    Ok(s) => s.into_raw(),
                    Err(_) => {
                        let _ = env.throw_new("java/lang/RuntimeException", "Failed to create status string");
                        std::ptr::null_mut()
                    }
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

/// Initialize VOICE Tor control connection (port 9052)
/// This must be called AFTER voice Tor daemon is started by TorManager.kt
/// Voice Tor runs with Single Onion Service configuration (HiddenServiceNonAnonymousMode 1)
/// cookie_path: The full filesystem path to the voice Tor control_auth_cookie file
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_initializeVoiceTorControl(
    mut env: JNIEnv,
    _class: JClass,
    cookie_path: JString,
) -> jstring {
    catch_panic!(env, {
        let cookie_path_str: String = match env.get_string(&cookie_path) {
            Ok(s) => s.into(),
            Err(_) => {
                let _ = env.throw_new("java/lang/RuntimeException", "Failed to read cookie path string");
                return std::ptr::null_mut();
            }
        };

        let tor_manager = get_tor_manager();

        // Connect to voice Tor control port (9052)
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.initialize_voice_control(&cookie_path_str).await
        });

        match result {
            Ok(status) => {
                log::info!("Voice Tor control initialized successfully");

                match string_to_jstring(&mut env, &status) {
                    Ok(s) => s.into_raw(),
                    Err(_) => {
                        let _ = env.throw_new("java/lang/RuntimeException", "Failed to create status string");
                        std::ptr::null_mut()
                    }
                }
            },
            Err(e) => {
                let error_msg = format!("Voice Tor control initialization failed: {}", e);
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
            Ok(val) => match val.l() {
                Ok(ctx) => ctx,
                Err(_) => {
                    let _ = env.throw_new("java/lang/RuntimeException", "currentApplication returned null or invalid object");
                    return std::ptr::null_mut();
                }
            },
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

        // Run async hidden service creation with seed-derived key using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
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

/// Pre-compute a v3 .onion address from a BIP39 seed + domain separator, without Tor.
///
/// Uses the exact same derivation path as `create_hidden_service`:
///   1. SHA-256(seed || domain_sep) → 32-byte Ed25519 seed
///   2. Ed25519 seed → public key
///   3. Public key → .onion address (per rend-spec-v3 section 6)
///
/// # Arguments
/// * `seed` - 64-byte BIP39 seed
/// * `domain_sep` - Domain separation string: "tor_hs", "friend_req", or "tor_voice"
///
/// # Returns
/// The v3 .onion address (56 chars + ".onion")
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_computeOnionAddressFromSeed(
    mut env: JNIEnv,
    _class: JClass,
    seed: JByteArray,
    domain_sep: JString,
) -> jstring {
    use sha2::{Digest as Sha2Digest, Sha256};
    use crate::network::compute_onion_address_from_ed25519_seed;

    catch_panic!(env, {
        // Get seed bytes
        let mut seed_bytes = match env.convert_byte_array(&seed) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read seed: {}", e));
                return std::ptr::null_mut();
            }
        };

        if seed_bytes.len() != 64 {
            let _ = env.throw_new("java/lang/IllegalArgumentException",
                format!("Seed must be 64 bytes, got {}", seed_bytes.len()));
            seed_bytes.zeroize();
            return std::ptr::null_mut();
        }

        // Get domain separator string
        let domain_str: String = match env.get_string(&domain_sep) {
            Ok(s) => s.into(),
            Err(e) => {
                seed_bytes.zeroize();
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read domain separator: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Validate domain separator — only the three known values are accepted
        match domain_str.as_str() {
            "tor_hs" | "friend_req" | "tor_voice" => {}
            _ => {
                seed_bytes.zeroize();
                let _ = env.throw_new("java/lang/IllegalArgumentException",
                    format!("Invalid domain separator '{}'. Must be 'tor_hs', 'friend_req', or 'tor_voice'", domain_str));
                return std::ptr::null_mut();
            }
        }

        // Step 1: Domain separation — SHA-256(seed || domain_string) → 32-byte Ed25519 seed
        // This matches KeyManager.deriveHiddenServiceKeyPair() / deriveFriendRequestKeyPair() / deriveVoiceServiceKeyPair()
        let mut sha256 = Sha256::new();
        sha256.update(&seed_bytes);
        sha256.update(domain_str.as_bytes());
        let mut ed25519_seed: [u8; 32] = sha256.finalize().into();

        // Step 2+3: Derive pubkey and compute .onion address using the shared helper
        // This is the exact same function used by create_hidden_service, guaranteeing identical results
        let full_address = compute_onion_address_from_ed25519_seed(&ed25519_seed);

        // Zeroize sensitive material
        ed25519_seed.zeroize();
        seed_bytes.zeroize();

        match string_to_jstring(&mut env, &full_address) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                let _ = env.throw_new("java/lang/RuntimeException", "Failed to create onion address string");
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Clear all ephemeral hidden services
/// This removes orphaned services from previous failed account creation attempts
/// Returns the number of services deleted
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_clearAllEphemeralServices(
    mut env: JNIEnv,
    _class: JClass,
) -> jint {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();

        // Run async clear operation using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let manager = tor_manager.lock().unwrap();
            manager.clear_all_ephemeral_services().await
        });

        match result {
            Ok(count) => {
                log::info!("Cleared {} ephemeral service(s)", count);
                count as jint
            },
            Err(e) => {
                let error_msg = format!("Failed to clear ephemeral services: {}", e);
                log::error!("{}", error_msg);
                let _ = env.throw_new("java/lang/RuntimeException", error_msg);
                -1
            }
        }
    }, -1)
}

/// Create voice hidden service for voice calling (v2.0)
/// Uses seed-derived voice service Ed25519 key from KeyManager
/// Returns the .onion address (port 9152)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_createVoiceHiddenService(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        // Get KeyManager to retrieve seed-derived voice service key
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

        // Get voice service private key (deterministic from seed with domain separation)
        let voice_private_key = match crate::ffi::keystore::get_voice_service_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get voice service key: {}", e));
                return std::ptr::null_mut();
            }
        };

        let tor_manager = get_tor_manager();

        // Run async voice hidden service creation using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.create_voice_hidden_service(&voice_private_key).await
        });

        match result {
            Ok(onion_address) => match string_to_jstring(&mut env, &onion_address) {
                Ok(s) => s.into_raw(),
                Err(_) => {
                    let _ = env.throw_new("java/lang/RuntimeException", "Failed to create voice onion address string");
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                let error_msg = format!("Voice hidden service creation failed: {}", e);
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
            Some(address) => match string_to_jstring(&mut env, &address) {
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

        // Run async listener start using the global runtime (persists for process lifetime)
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        });

        match result {
            Ok((ping_receiver, pong_receiver)) => {
                // Store both PING and PONG receivers globally (local channels, no globals in tor.rs)
                if let Err(_) = GLOBAL_PING_RECEIVER.set(Arc::new(Mutex::new(ping_receiver))) {
                    log::warn!("PING_RECEIVER already initialized (listener restart?)");
                }
                if let Err(_) = GLOBAL_PONG_RECEIVER.set(Arc::new(Mutex::new(pong_receiver))) {
                    log::warn!("PONG_RECEIVER already initialized (listener restart?)");
                }

                // Initialize MESSAGE channel for TEXT/VOICE/IMAGE/PAYMENT routing
                let (message_tx, message_rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();
                if let Err(_) = GLOBAL_MESSAGE_RECEIVER.set(Arc::new(Mutex::new(message_rx))) {
                    log::warn!("MESSAGE_RECEIVER already initialized (listener restart?)");
                }
                let tx_arc = Arc::new(std::sync::Mutex::new(message_tx));
                if let Err(_) = crate::network::tor::MESSAGE_TX.set(tx_arc) {
                    log::warn!("MESSAGE_TX channel already initialized");
                }
                log::info!("MESSAGE channel initialized for direct routing");

                // Initialize VOICE channel for CALL_SIGNALING routing
                let (voice_tx, voice_rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();
                if let Err(_) = GLOBAL_VOICE_RECEIVER.set(Arc::new(Mutex::new(voice_rx))) {
                    log::warn!("VOICE_RECEIVER already initialized (listener restart?)");
                }
                let voice_tx_arc = Arc::new(std::sync::Mutex::new(voice_tx));
                if let Err(_) = crate::network::tor::VOICE_TX.set(voice_tx_arc) {
                    log::warn!("VOICE channel already initialized");
                }
                log::info!("VOICE channel initialized for call signaling (separate from MESSAGE)");

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

        // stop_listener is now async, need to await it
        GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.stop_listener().await;
        });
    }, ())
}

/// Start SOCKS5 proxy server on 127.0.0.1:9050
/// Routes all HTTP traffic through Tor for privacy
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startSocksProxy(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();
        let mut manager = tor_manager.lock().unwrap();

        // Use the global persistent Tokio runtime
        match GLOBAL_RUNTIME.block_on(manager.start_socks_proxy()) {
            Ok(_) => {
                log::info!("SOCKS proxy started successfully on persistent runtime");
                1 as jboolean
            }
            Err(e) => {
                log::error!("Failed to start SOCKS proxy: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException",
                    format!("Failed to start SOCKS proxy: {}", e));
                0 as jboolean
            }
        }
    }, 0 as jboolean)
}

/// Stop SOCKS5 proxy server
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_stopSocksProxy(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();
        let mut manager = tor_manager.lock().unwrap();
        manager.stop_socks_proxy();
        log::info!("SOCKS proxy stopped");
    }, ())
}

/// Check if SOCKS5 proxy is running
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_isSocksProxyRunning(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();
        let manager = tor_manager.lock().unwrap();
        if manager.is_socks_proxy_running() {
            1 as jboolean
        } else {
            0 as jboolean
        }
    }, 0 as jboolean)
}

/// Test SOCKS5 proxy connectivity
/// Actually attempts a connection to verify SOCKS is functional
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_testSocksConnectivity(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();
        let manager = tor_manager.lock().unwrap();

        // Use the global persistent Tokio runtime
        match GLOBAL_RUNTIME.block_on(manager.test_socks_connectivity()) {
            true => {
                log::info!("SOCKS connectivity test passed");
                1 as jboolean
            }
            false => {
                log::warn!("SOCKS connectivity test failed");
                0 as jboolean
            }
        }
    }, 0 as jboolean)
}

/// Stop all listeners (hidden service listener, tap listener, etc.)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_stopListeners(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        log::info!("Stopping all listeners...");

        let tor_manager = get_tor_manager();

        // Stop the hidden service listener (now async)
        GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.stop_listener().await;
        });

        // Note: TAP listener and PING listener are managed through global channels
        // They will naturally stop when no longer polled

        log::info!("All listeners stopped");
    }, ())
}

/// Send NEWNYM signal to Tor via ControlPort
/// Rotates Tor guards and circuits (rate-limited by Tor itself)
/// Returns true on success, false if failed or rate-limited
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendNewnym(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();

        let result = GLOBAL_RUNTIME.block_on(async {
            let manager = tor_manager.lock().unwrap();
            manager.send_newnym().await
        });

        if result {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }, JNI_FALSE)
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
                    // CONSUMER INVARIANT: Verify type byte matches expected poller
                    if ping_bytes.is_empty() {
                        log::error!("FRAMING_VIOLATION: pollIncomingPing got empty buffer, conn_id={}", connection_id);
                        return std::ptr::null_mut();
                    }

                    const MSG_TYPE_PING: u8 = 0x01;
                    if ping_bytes[0] != MSG_TYPE_PING {
                        let head_hex: String = ping_bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                        log::error!("FRAMING_VIOLATION: pollIncomingPing got type=0x{:02x} expected=0x{:02x} conn_id={} len={} head={}",
                            ping_bytes[0], MSG_TYPE_PING, connection_id, ping_bytes.len(), head_hex);
                        return std::ptr::null_mut();
                    }

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

/// Poll for incoming MESSAGE (TEXT/VOICE/IMAGE/PAYMENT) from the listener
/// Returns encoded data: [connection_id (8 bytes)][encrypted message blob]
/// Returns null if no message is available
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingMessage(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        if let Some(receiver) = GLOBAL_MESSAGE_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok((connection_id, message_bytes)) => {
                    // Encode: [connection_id as 8 bytes little-endian][message_bytes]
                    let mut encoded = Vec::new();
                    encoded.extend_from_slice(&connection_id.to_le_bytes());
                    encoded.extend_from_slice(&message_bytes);

                    match vec_to_jbytearray(&mut env, &encoded) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No message available
                    std::ptr::null_mut()
                }
            }
        } else {
            // Listener not started
            std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Poll for incoming VOICE call signaling (CALL_SIGNALING) from the listener
/// Returns encoded data: [connection_id (8 bytes)][encrypted call signaling blob]
/// Returns null if no message is available
/// Completely separate from MESSAGE channel to allow simultaneous text messaging during voice calls
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollVoiceMessage(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        if let Some(receiver) = GLOBAL_VOICE_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok((connection_id, message_bytes)) => {
                    // Encode: [connection_id as 8 bytes little-endian][message_bytes]
                    let mut encoded = Vec::new();
                    encoded.extend_from_slice(&connection_id.to_le_bytes());
                    encoded.extend_from_slice(&message_bytes);

                    match vec_to_jbytearray(&mut env, &encoded) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No voice message available
                    std::ptr::null_mut()
                }
            }
        } else {
            // VOICE listener not started
            std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Check if a connection is still alive and responsive
///
/// # Arguments
/// * `connection_id` - The connection ID to check
///
/// # Returns
/// True if connection exists in PENDING_CONNECTIONS (indicates it's still alive)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_isConnectionAlive(
    mut env: JNIEnv,
    _class: JClass,
    connection_id: jlong,
) -> jboolean {
    catch_panic!(env, {
        // Check if connection exists in PENDING_CONNECTIONS
        let pending = PENDING_CONNECTIONS.lock().unwrap();
        let exists = pending.contains_key(&(connection_id as u64));

        if exists {
            log::debug!("Connection {} is alive (found in PENDING_CONNECTIONS)", connection_id);
            1 // true
        } else {
            log::debug!("Connection {} is dead (not found in PENDING_CONNECTIONS)", connection_id);
            0 // false
        }
    }, 0)
}

/// Send encrypted Pong response back to a pending connection and receive the message
///
/// # Arguments
/// * `connection_id` - The connection ID from pollIncomingPing
/// * `encrypted_pong_bytes` - The encrypted Pong token bytes (from createPongToken)
///
/// # Returns
/// The encrypted message bytes sent by the sender after receiving the Pong
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendPongBytes(
    mut env: JNIEnv,
    _class: JClass,
    connection_id: jlong,
    encrypted_pong_bytes: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        // Convert encrypted pong bytes
        let pong_bytes = match jbytearray_to_vec(&mut env, encrypted_pong_bytes) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        log::info!("Sending encrypted Pong response ({} bytes) for connection {}", pong_bytes.len(), connection_id);

        // Send Pong response back through the stored connection and wait for message
        // Use global runtime instead of creating a new one
        let result = GLOBAL_RUNTIME.block_on(async {
            crate::network::TorManager::send_pong_response(connection_id as u64, &pong_bytes).await
        });

        match result {
            Ok(message_bytes) => {
                log::info!("Encrypted Pong sent and message received successfully ({} bytes) for connection {}", message_bytes.len(), connection_id);

                // Convert message bytes to jbyteArray
                match env.byte_array_from_slice(&message_bytes) {
                    Ok(jarray) => jarray.into_raw(),
                    Err(e) => {
                        let error_msg = format!("Failed to convert message bytes: {}", e);
                        let _ = env.throw_new("java/lang/RuntimeException", error_msg);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let error_msg = format!("Failed to send Pong or receive message: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", error_msg);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Send encrypted Pong over a NEW connection to sender's .onion address
/// Used when original connection has closed (e.g., user downloads message hours later)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendPongToNewConnection(
    mut env: JNIEnv,
    _class: JClass,
    sender_onion: JString,
    encrypted_pong_bytes: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        // Convert parameters
        let onion_address = match jstring_to_string(&mut env, sender_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert onion address: {}", e);
                return 0;
            }
        };

        let pong_bytes = match jbytearray_to_vec(&mut env, encrypted_pong_bytes) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert Pong bytes: {}", e);
                return 0;
            }
        };

        log::info!("Sending Pong over NEW connection to {} ({} bytes)", onion_address, pong_bytes.len());

        // Get Tor manager
        let tor_manager = get_tor_manager();

        // Open new connection and send Pong using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            // Connect to sender's .onion address on handshake port (lock only during connect)
            let mut conn = {
                let tor = tor_manager.lock().unwrap();
                tor.connect(&onion_address, PING_PONG_HANDSHAKE_PORT).await?
            }; // Lock released

            // Send Pong bytes (lock only during send)
            {
                let tor = tor_manager.lock().unwrap();
                tor.send(&mut conn, &pong_bytes).await?;
            } // Lock released

            log::info!("Pong sent successfully over new connection to {}", onion_address);
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        match result {
            Ok(_) => 1, // success
            Err(e) => {
                log::error!("Failed to send Pong over new connection: {}", e);
                0 // failure
            }
        }
    }, 0)
}

/// Send encrypted Pong to sender's Pong listener (port 9152)
/// Used for delayed downloads - sends pong to sender's listening port
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendPongToListener(
    mut env: JNIEnv,
    _class: JClass,
    sender_onion: JString,
    encrypted_pong_bytes: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        // Convert parameters
        let onion_address = match jstring_to_string(&mut env, sender_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert onion address: {}", e);
                return 0;
            }
        };

        let pong_bytes = match jbytearray_to_vec(&mut env, encrypted_pong_bytes) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert Pong bytes: {}", e);
                return 0;
            }
        };

        log::info!("Sending Pong to listener at {}:{} ({} bytes)", onion_address, PING_PONG_HANDSHAKE_PORT, pong_bytes.len());

        // Get Tor manager
        let tor_manager = get_tor_manager();

        // Open connection to sender's messaging port (9150 handshake) and send Pong using global runtime
        // NOTE: CRITICAL FIX - Use PING_PONG_HANDSHAKE_PORT (9150), NOT MAIN_LISTENER_PORT (8080)
        // The recipient's hidden service exposes 9150 for messaging, NOT 8080
        // 8080 is only the local port this instance listens on
        let result = GLOBAL_RUNTIME.block_on(async {
            // Build wire message with type byte
            let mut wire_message = Vec::new();
            wire_message.push(crate::network::tor::MSG_TYPE_PONG); // Add type byte
            wire_message.extend_from_slice(&pong_bytes);

            // Connect to sender's messaging handshake port (9150) - NOT 8080
            let mut conn = {
                let tor = tor_manager.lock().unwrap();
                tor.connect(&onion_address, PING_PONG_HANDSHAKE_PORT).await?
            }; // Lock released

            // Send wire message (lock only during send)
            {
                let tor = tor_manager.lock().unwrap();
                tor.send(&mut conn, &wire_message).await?;
            } // Lock released

            log::info!("Pong sent successfully to listener at {}:{}", onion_address, PING_PONG_HANDSHAKE_PORT);
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        match result {
            Ok(_) => 1, // success
            Err(e) => {
                log::error!("Failed to send Pong to listener: {}", e);
                0 // failure
            }
        }
    }, 0)
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendPing(
    mut env: JNIEnv,
    _class: JClass,
    recipient_ed25519_pubkey: JByteArray,
    recipient_x25519_pubkey: JByteArray,
    recipient_onion: JString,
    encrypted_message: JByteArray,
    message_type_byte: jbyte,
    ping_id: JString, // Ping ID (hex-encoded nonce) - generated in Kotlin, never changes
    ping_timestamp: jlong, // Timestamp when ping was created - also from Kotlin
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

        let message_bytes = match jbytearray_to_vec(&mut env, encrypted_message) {
            Ok(v) => v,
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
            Ok(val) => match val.l() {
                Ok(ctx) => ctx,
                Err(_) => {
                    let _ = env.throw_new("java/lang/RuntimeException", "currentApplication returned null or invalid object");
                    return std::ptr::null_mut();
                }
            },
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

        // Validate Ed25519 private key length (must be 32 bytes)
        if our_signing_private.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException",
                                  format!("Invalid Ed25519 private key length: expected 32 bytes, got {}", our_signing_private.len()));
            return std::ptr::null_mut();
        }

        // Create Ed25519 signing keypair with validated key
        let sk_bytes: [u8; 32] = our_signing_private.as_slice().try_into().unwrap(); // Safe now
        let sender_keypair = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);

        // Validate recipient Ed25519 public key length (must be 32 bytes)
        if recipient_ed25519_bytes.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException",
                                  format!("Invalid recipient Ed25519 public key length: expected 32 bytes, got {}", recipient_ed25519_bytes.len()));
            return std::ptr::null_mut();
        }

        let recipient_ed25519_verifying = match ed25519_dalek::VerifyingKey::from_bytes(&recipient_ed25519_bytes.as_slice().try_into().unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid recipient Ed25519 pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Get our X25519 public key (needed for PingToken)
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get our X25519 pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Convert X25519 keys to fixed-size arrays
        let sender_x25519_pubkey: [u8; 32] = match our_x25519_public.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid sender X25519 pubkey size");
                return std::ptr::null_mut();
            }
        };

        let recipient_x25519_pubkey: [u8; 32] = match recipient_x25519_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid recipient X25519 pubkey size");
                return std::ptr::null_mut();
            }
        };

        // Parse ping_id from Kotlin (hex-encoded nonce, generated once, never changes)
        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Decode hex ping_id to nonce bytes
        let nonce_bytes = match hex::decode(&ping_id_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid ping_id hex: {}", e));
                return std::ptr::null_mut();
            }
        };

        if nonce_bytes.len() != 24 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid ping_id length: expected 24 bytes, got {}", nonce_bytes.len()));
            return std::ptr::null_mut();
        }

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        // Convert timestamp from milliseconds (Java/Kotlin) to seconds (Unix timestamp)
        let timestamp_secs = (ping_timestamp / 1000) as i64;

        log::info!("Creating PingToken with provided ID: {} (timestamp: {})", &ping_id_str[..8.min(ping_id_str.len())], timestamp_secs);

        // Create PingToken with provided nonce and timestamp (ensures retries use identical bytes)
        let ping_token = match crate::network::PingToken::with_nonce(
            &sender_keypair,
            &recipient_ed25519_verifying,
            &sender_x25519_pubkey,
            &recipient_x25519_pubkey,
            nonce,
            timestamp_secs,
        ) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create Ping with nonce: {}", e));
                return std::ptr::null_mut();
            }
        };

        let ping_id = ping_id_str; // Use the provided ping_id (not regenerated)

        // Store recipient's Ed25519 pubkey for PONG/ACK signature verification
        {
            let mut signers = OUTGOING_PING_SIGNERS.lock().unwrap();
            signers.insert(ping_id.clone(), ping_token.recipient_pubkey);
        }

        // Persist to Room DB so PONG verification survives process restart
        store_pending_ping_db(&mut env, &ping_id, &ping_token.recipient_pubkey);

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

        // Wire format: [Type Byte 0x01][Our X25519 Public Key - 32 bytes][Encrypted Ping Token]
        let mut wire_message = Vec::new();
        wire_message.push(crate::network::tor::MSG_TYPE_PING); // Add type byte
        wire_message.extend_from_slice(&sender_x25519_pubkey);
        wire_message.extend_from_slice(&encrypted_ping);

        // Send encrypted Ping via Tor
        // HYBRID MODE: Try instant Pong (30s timeout), fall back to delayed mode
        let tor_manager = get_tor_manager();
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        const PING_PONG_PORT: u16 = 9150;
        const INSTANT_PONG_TIMEOUT_SECS: u64 = 30;

        let result: Result<(), Box<dyn std::error::Error>> = runtime.block_on(async {
            // Connect and send Ping (lock only during operations)
            let mut conn = {
                let manager = tor_manager.lock().unwrap();
                manager.connect(&recipient_onion_str, PING_PONG_PORT).await?
            }; // Lock released

            {
                let manager = tor_manager.lock().unwrap();
                manager.send(&mut conn, &wire_message).await?;
            } // Lock released

            log::info!("Ping sent successfully ({}), waiting for instant Pong ({}s timeout)...", ping_id, INSTANT_PONG_TIMEOUT_SECS);

            // Try to receive instant Pong response (recipient online and accepts immediately)
            // No lock needed - we own the connection
            let pong_result = tokio::time::timeout(
                std::time::Duration::from_secs(INSTANT_PONG_TIMEOUT_SECS),
                async {
                    // Read length prefix
                    let mut len_buf = [0u8; 4];
                    conn.stream.read_exact(&mut len_buf).await?;
                    let total_len = u32::from_be_bytes(len_buf) as usize;

                    if total_len > 10_000 {
                        return Err("Pong response too large".into());
                    }

                    // Read type byte
                    let mut type_byte = [0u8; 1];
                    conn.stream.read_exact(&mut type_byte).await?;

                    if type_byte[0] != crate::network::tor::MSG_TYPE_PONG {
                        if type_byte[0] == crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION {
                            log::warn!("Received PING_ACK (0x06) on PING connection - ignoring (should go to port 9153)");
                            log::warn!("→ This is a bug - PING_ACK was sent to wrong port. Treating as 'no instant pong'.");
                            return Err("PING_ACK received on wrong connection".into());
                        }
                        log::warn!("Expected PONG (0x02) but got type 0x{:02x}", type_byte[0]);
                        return Err(format!("Wrong message type: expected PONG, got 0x{:02x}", type_byte[0]).into());
                    }

                    // Read the pong data
                    let data_len = total_len.saturating_sub(1);
                    let mut pong_data = vec![0u8; data_len];
                    conn.stream.read_exact(&mut pong_data).await?;

                    log::info!("Received instant Pong response ({} bytes)", data_len);

                    Ok::<Vec<u8>, Box<dyn std::error::Error>>(pong_data)
                }
            ).await;

            match pong_result {
                Ok(Ok(pong_data)) => {
                    // Verify instant Pong signature before sending message payload
                    // Wire layout (after length+type stripping): [responder_x25519:32][encrypted_pong]
                    // recipient_ed25519_verifying = the contact we dialed (i.e. the PONG signer)
                    if pong_data.len() >= 32 {
                        let pong_encrypted = &pong_data[32..];
                        match crate::crypto::encryption::decrypt_message(pong_encrypted, &shared_secret) {
                            Ok(pong_plaintext) => {
                                match bincode::deserialize::<crate::protocol::message::PongToken>(&pong_plaintext) {
                                    Ok(pong_token) => {
                                        let pingpong_pong = crate::network::pingpong::PongToken {
                                            protocol_version: pong_token.protocol_version,
                                            ping_nonce: pong_token.ping_nonce,
                                            pong_nonce: pong_token.pong_nonce,
                                            timestamp: pong_token.timestamp,
                                            authenticated: pong_token.authenticated,
                                            signature: pong_token.signature,
                                        };
                                        match pingpong_pong.verify(&recipient_ed25519_verifying) {
                                            Ok(true) => {
                                                log::info!("PONG_SIG_OK: Instant Pong signature verified for ping_id={}", ping_id);
                                                // Store verified pong and clean up signer entry
                                                crate::network::pingpong::store_pong_session(&ping_id, pingpong_pong);
                                                OUTGOING_PING_SIGNERS.lock().unwrap().remove(&ping_id);
                                                delete_pending_ping_db(&mut env, &ping_id);
                                            },
                                            Ok(false) => {
                                                log::error!("PONG_SIG_INVALID: Instant Pong signature verification FAILED for ping_id={}", ping_id);
                                                return Err("Invalid instant Pong signature — rejecting".into());
                                            },
                                            Err(e) => {
                                                log::error!("PONG_SIG_ERROR: Instant Pong sig check error: {}", e);
                                                return Err(format!("Pong signature error: {}", e).into());
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        log::error!("PONG_DESER_FAIL: Failed to deserialize instant Pong: {} — rejecting", e);
                                        return Err(format!("Invalid instant Pong format: {}", e).into());
                                    },
                                }
                            },
                            Err(e) => {
                                log::error!("PONG_DECRYPT_FAIL: Failed to decrypt instant Pong: {} — rejecting", e);
                                return Err(format!("Cannot decrypt instant Pong: {}", e).into());
                            },
                        }
                    } else {
                        log::error!("PONG_TOO_SHORT: Instant Pong data too short ({} bytes, need >=32) — rejecting", pong_data.len());
                        return Err("Instant Pong data too short".into());
                    }

                    log::info!("INSTANT MODE: Pong verified, sending message payload...");
                    log::info!("Message size: {} bytes encrypted", message_bytes.len());

                    // Build message wire format: [Type Byte][Sender X25519 Public Key - 32 bytes][Encrypted Message]
                    // Receiver's handleInstantMessageBlob expects [type][x25519_32][payload]

                    // Validate message type before sending
                    let msg_type = message_type_byte as u8;
                    if !is_valid_message_type(msg_type) {
                        log::error!("Invalid message type: {}", msg_type);
                        return Err(format!("Invalid message type: {}", msg_type).into());
                    }

                    // Strict boundary validation: encrypted payload minimum wire format
                    if message_bytes.len() < 49 {
                        log::error!("Encrypted payload too short: {} bytes (minimum 49)", message_bytes.len());
                        return Err(format!("Encrypted payload too short: {}", message_bytes.len()).into());
                    }

                    let mut message_wire = Vec::with_capacity(1 + 32 + message_bytes.len());
                    message_wire.push(msg_type);
                    message_wire.extend_from_slice(&sender_x25519_pubkey); // Our X25519 public key
                    message_wire.extend_from_slice(&message_bytes); // Encrypted message payload

                    log::info!("Sending message wire: {} bytes total (1 type + 32 x25519 + {} encrypted)",
                        message_wire.len(), message_bytes.len());

                    // Send message on same connection (lock only during send)
                    {
                        let manager = tor_manager.lock().unwrap();
                        manager.send(&mut conn, &message_wire).await?;
                    } // Lock released

                    log::info!("Message sent successfully ({} bytes) in INSTANT MODE", message_bytes.len());
                    Ok(())
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to receive instant Pong: {}", e);
                    log::info!("→ DELAYED MODE: Pong will arrive later via port 8080 main listener");
                    Ok(())
                }
                Err(_) => {
                    log::info!("→ DELAYED MODE: Instant Pong timeout ({}s) - recipient may be offline or busy", INSTANT_PONG_TIMEOUT_SECS);
                    log::info!("Pong will arrive later via port 8080 main listener when recipient comes online");
                    Ok(())
                }
            }
        });

        match result {
            Ok(_) => {
                log::info!("Ping sent to {}: {}", recipient_onion_str, ping_id);

                // Encode wire_message as Base64 for storage and retry
                let wire_bytes_base64 = base64::encode(&wire_message);

                // Return JSON with ping_id and wire_bytes for tracking and retry
                let json_response = format!(
                    r#"{{"pingId":"{}","wireBytes":"{}"}}"#,
                    ping_id,
                    wire_bytes_base64
                );

                match string_to_jstring(&mut env, &json_response) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(e) => {
                log::error!("Failed to send Ping: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to send Ping: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_resendPingWithWireBytes(
    mut env: JNIEnv,
    _class: JClass,
    wire_bytes_base64: JString,
    recipient_onion: JString,
) -> jboolean {
    catch_panic!(env, {
        // Convert inputs
        let wire_bytes_b64_str = match jstring_to_string(&mut env, wire_bytes_base64) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert wire bytes Base64 string: {}", e);
                return 0;
            }
        };

        let recipient_onion_str = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert onion address: {}", e);
                return 0;
            }
        };

        // Decode Base64 wire bytes
        let mut wire_message = match base64::decode(&wire_bytes_b64_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Failed to decode Base64 wire bytes: {}", e);
                return 0;
            }
        };

        // CRITICAL FIX: Normalize stored wire bytes to prevent legacy format (missing type byte)
        // Legacy builds may have stored [pubkey32][ciphertext] without type byte prefix
        // This migrates them to [0x01=PING][pubkey32][ciphertext] format
        let original_len = wire_message.len();
        wire_message = normalize_wire_bytes(crate::network::tor::MSG_TYPE_PING, &wire_message);
        if wire_message.len() != original_len {
            log::info!("LEGACY_WIRE_MIGRATED: prepended PING type byte ({} → {} bytes)", original_len, wire_message.len());
        }

        log::info!("Resending Ping with stored wire bytes ({} bytes) to {}", wire_message.len(), recipient_onion_str);

        // Send encrypted Ping via Tor
        // HYBRID MODE: Try instant Pong (30s timeout), fall back to delayed mode
        let tor_manager = get_tor_manager();
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        const PING_PONG_PORT: u16 = 9150;
        const INSTANT_PONG_TIMEOUT_SECS: u64 = 30;

        let result: Result<(), Box<dyn std::error::Error>> = runtime.block_on(async {
            // Connect and send Ping (lock only during operations)
            let mut conn = {
                let manager = tor_manager.lock().unwrap();
                manager.connect(&recipient_onion_str, PING_PONG_PORT).await?
            }; // Lock released

            {
                let manager = tor_manager.lock().unwrap();
                manager.send(&mut conn, &wire_message).await?;
            } // Lock released

            log::info!("Ping resent successfully, waiting for instant Pong ({}s timeout)...", INSTANT_PONG_TIMEOUT_SECS);

            // Try to receive instant Pong response (recipient online and accepts immediately)
            // Note: This retry doesn't include the message payload - that's already been sent before
            // We're just resending the Ping to get acknowledgment
            let pong_result = tokio::time::timeout(
                std::time::Duration::from_secs(INSTANT_PONG_TIMEOUT_SECS),
                async {
                    // Read length prefix
                    let mut len_buf = [0u8; 4];
                    conn.stream.read_exact(&mut len_buf).await?;
                    let total_len = u32::from_be_bytes(len_buf) as usize;

                    if total_len > 10_000 {
                        return Err("Pong response too large".into());
                    }

                    // Read type byte
                    let mut type_byte = [0u8; 1];
                    conn.stream.read_exact(&mut type_byte).await?;

                    if type_byte[0] != crate::network::tor::MSG_TYPE_PONG {
                        if type_byte[0] == crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION {
                            log::warn!("Received PING_ACK (0x06) on PING connection during retry - ignoring (should go to port 9153)");
                            log::warn!("→ This is a bug - PING_ACK was sent to wrong port. Treating as 'no instant pong'.");
                            return Err("PING_ACK received on wrong connection".into());
                        }
                        log::warn!("Expected PONG (0x02) but got type 0x{:02x}", type_byte[0]);
                        return Err(format!("Wrong message type: expected PONG, got 0x{:02x}", type_byte[0]).into());
                    }

                    // Read the pong data
                    let data_len = total_len.saturating_sub(1);
                    let mut pong_data = vec![0u8; data_len];
                    conn.stream.read_exact(&mut pong_data).await?;

                    log::info!("Received instant Pong response ({} bytes) for retry", data_len);

                    Ok::<Vec<u8>, Box<dyn std::error::Error>>(pong_data)
                }
            ).await;

            match pong_result {
                Ok(Ok(_pong_data)) => {
                    log::info!("INSTANT MODE: Pong received for resent Ping");
                    Ok(())
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to receive instant Pong for retry: {}", e);
                    log::info!("→ DELAYED MODE: Pong will arrive later via port 8080 main listener");
                    Ok(())
                }
                Err(_) => {
                    log::info!("→ DELAYED MODE: Instant Pong timeout ({}s) for retry - recipient may be offline or busy", INSTANT_PONG_TIMEOUT_SECS);
                    log::info!("Pong will arrive later via port 8080 main listener when recipient comes online");
                    Ok(())
                }
            }
        });

        match result {
            Ok(_) => {
                log::info!("Ping resent successfully to {}", recipient_onion_str);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to resend Ping: {}", e);
                0 // failure
            }
        }
    }, 0)
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendTap(
    mut env: JNIEnv,
    _class: JClass,
    recipient_ed25519_pubkey: JByteArray,
    recipient_x25519_pubkey: JByteArray,
    recipient_onion: JString,
) -> jboolean {
    catch_panic!(env, {
        // Convert inputs
        let recipient_x25519_bytes = match jbytearray_to_vec(&mut env, recipient_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert recipient X25519 pubkey: {}", e);
                return 0;
            }
        };

        let recipient_onion_str = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert onion address: {}", e);
                return 0;
            }
        };

        log::info!("Sending tap to {}", recipient_onion_str);

        // Get KeyManager for our keys
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                log::error!("Failed to get context: {}", e);
                return 0;
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                log::error!("Failed to get KeyManager: {}", e);
                return 0;
            }
        };

        // Get our X25519 keys
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get our X25519 pubkey: {}", e);
                return 0;
            }
        };

        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get encryption key: {}", e);
                return 0;
            }
        };

        // Derive shared secret using X25519 ECDH
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                log::error!("ECDH failed: {}", e);
                return 0;
            }
        };

        // Create simple tap payload (just timestamp)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let tap_payload = format!("TAP:{}", timestamp);

        // Encrypt tap with shared secret
        let encrypted_tap = match crate::crypto::encryption::encrypt_message(tap_payload.as_bytes(), &shared_secret) {
            Ok(enc) => enc,
            Err(e) => {
                log::error!("Tap encryption failed: {}", e);
                return 0;
            }
        };

        // Wire format: [Type Byte 0x05][Our X25519 Public Key - 32 bytes][Encrypted Tap]
        let sender_x25519_pubkey: [u8; 32] = match our_x25519_public.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                log::error!("Invalid sender X25519 pubkey size");
                return 0;
            }
        };

        let mut wire_message = Vec::new();
        wire_message.push(crate::network::tor::MSG_TYPE_TAP); // Add type byte
        wire_message.extend_from_slice(&sender_x25519_pubkey);
        wire_message.extend_from_slice(&encrypted_tap);

        // Send tap via Tor (fire-and-forget, no response expected)
        let tor_manager = get_tor_manager();
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        const TAP_PORT: u16 = 9151; // Different port from Ping-Pong (9150)

        let result = runtime.block_on(async {
            let manager = tor_manager.lock().unwrap();
            let mut conn = manager.connect(&recipient_onion_str, TAP_PORT).await?;
            manager.send(&mut conn, &wire_message).await?;

            log::info!("Tap sent successfully to {}", recipient_onion_str);
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        match result {
            Ok(_) => {
                log::info!("Tap sent successfully to {}", recipient_onion_str);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to send tap to {}: {}", recipient_onion_str, e);
                0 // failure
            }
        }
    }, 0)
}

/// Send friend request (fire-and-forget notification)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendFriendRequest(
    mut env: JNIEnv,
    _class: JClass,
    recipient_onion: JString,
    encrypted_friend_request: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        // Convert onion address
        let recipient_onion_str = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert onion address: {}", e);
                return 0;
            }
        };

        // Convert encrypted friend request bytes
        let friend_request_bytes = match jbytearray_to_vec(&mut env, encrypted_friend_request) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert friend request bytes: {}", e);
                return 0;
            }
        };

        log::info!("Sending friend request to {} ({} bytes)", recipient_onion_str, friend_request_bytes.len());

        // Build wire message with type byte 0x07 (FRIEND_REQUEST)
        // Wire format: [0x07][Sender X25519 - 32 bytes][Encrypted Friend Request]
        let mut wire_message = Vec::new();
        wire_message.push(crate::network::tor::MSG_TYPE_FRIEND_REQUEST); // 0x07
        wire_message.extend_from_slice(&friend_request_bytes);

        log::info!("Wire message: {} bytes (type={:02X})", wire_message.len(), wire_message[0]);

        // Send friend request via Tor (fire-and-forget, no response expected)
        let tor_manager = get_tor_manager();
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        const FRIEND_REQUEST_PORT: u16 = 9151; // Friend request .onion port (wire protocol)
        const FALLBACK_PORT: u16 = 8080; // Fallback to main listener if 9151 fails
        const MAX_RETRIES: u32 = 24; // 24 retries x 5s = 2 min for slow bridges (Snowflake)
        const RETRY_DELAY_SECS: u64 = 5;

        for attempt in 1..=MAX_RETRIES {
            // Try port 9151 first
            let result = runtime.block_on(async {
                let manager = tor_manager.lock().unwrap();
                let mut conn = manager.connect(&recipient_onion_str, FRIEND_REQUEST_PORT).await?;
                manager.send(&mut conn, &wire_message).await?;
                Ok::<(), Box<dyn std::error::Error>>(())
            });

            match result {
                Ok(_) => {
                    log::info!("Friend request sent successfully to {} on port {} (attempt {})", recipient_onion_str, FRIEND_REQUEST_PORT, attempt);
                    return 1;
                }
                Err(e) => {
                    log::warn!("Port {} attempt {}/{} failed: {}. Trying fallback port {}...", FRIEND_REQUEST_PORT, attempt, MAX_RETRIES, e, FALLBACK_PORT);

                    // Fallback to port 8080
                    let fallback_result = runtime.block_on(async {
                        let manager = tor_manager.lock().unwrap();
                        let mut conn = manager.connect(&recipient_onion_str, FALLBACK_PORT).await?;
                        manager.send(&mut conn, &wire_message).await?;
                        Ok::<(), Box<dyn std::error::Error>>(())
                    });

                    match fallback_result {
                        Ok(_) => {
                            log::info!("Friend request sent via fallback port {} (attempt {})", FALLBACK_PORT, attempt);
                            return 1;
                        }
                        Err(fallback_err) => {
                            if attempt < MAX_RETRIES {
                                log::warn!("Friend request attempt {}/{} failed (both ports): {}. Retrying in {}s...",
                                    attempt, MAX_RETRIES, fallback_err, RETRY_DELAY_SECS);
                                std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS));
                            } else {
                                log::error!("Failed to send friend request to {} after {} attempts: {}",
                                    recipient_onion_str, MAX_RETRIES, fallback_err);
                            }
                        }
                    }
                }
            }
        }

        0 // all retries exhausted
    }, 0)
}

/// Send friend request accepted message to a recipient
/// Args:
/// recipient_onion - Recipient's .onion address
/// encrypted_acceptance - Encrypted friend request acceptance message
/// Returns: true if sent successfully, false otherwise
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendFriendRequestAccepted(
    mut env: JNIEnv,
    _class: JClass,
    recipient_onion: JString,
    encrypted_acceptance: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        // Convert onion address
        let recipient_onion_str = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert onion address: {}", e);
                return 0;
            }
        };

        // Convert encrypted acceptance bytes
        let acceptance_bytes = match jbytearray_to_vec(&mut env, encrypted_acceptance) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert acceptance bytes: {}", e);
                return 0;
            }
        };

        log::info!("Sending friend request accepted to {} ({} bytes)", recipient_onion_str, acceptance_bytes.len());

        // Build wire message with type byte 0x08 (FRIEND_REQUEST_ACCEPTED)
        // Wire format: [0x08][Encrypted Acceptance]
        let mut wire_message = Vec::new();
        wire_message.push(crate::network::tor::MSG_TYPE_FRIEND_REQUEST_ACCEPTED); // 0x08
        wire_message.extend_from_slice(&acceptance_bytes);

        log::info!("Wire message: {} bytes (type={:02X})", wire_message.len(), wire_message[0]);

        // Send acceptance via Tor (fire-and-forget, no response expected)
        let tor_manager = get_tor_manager();
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        const FRIEND_REQUEST_PORT: u16 = 9151; // Friend request .onion port (wire protocol)
        const FALLBACK_PORT: u16 = 8080; // Fallback to main listener if 9151 fails
        const MAX_RETRIES: u32 = 24; // 24 retries x 5s = 2 min for slow bridges (Snowflake)
        const RETRY_DELAY_SECS: u64 = 5;

        for attempt in 1..=MAX_RETRIES {
            // Try port 9151 first
            let result = runtime.block_on(async {
                let manager = tor_manager.lock().unwrap();
                let mut conn = manager.connect(&recipient_onion_str, FRIEND_REQUEST_PORT).await?;
                manager.send(&mut conn, &wire_message).await?;
                Ok::<(), Box<dyn std::error::Error>>(())
            });

            match result {
                Ok(_) => {
                    log::info!("Friend request acceptance sent to {} on port {} (attempt {})", recipient_onion_str, FRIEND_REQUEST_PORT, attempt);
                    return 1;
                }
                Err(e) => {
                    log::warn!("Port {} attempt {}/{} failed: {}. Trying fallback port {}...", FRIEND_REQUEST_PORT, attempt, MAX_RETRIES, e, FALLBACK_PORT);

                    // Fallback to port 8080
                    let fallback_result = runtime.block_on(async {
                        let manager = tor_manager.lock().unwrap();
                        let mut conn = manager.connect(&recipient_onion_str, FALLBACK_PORT).await?;
                        manager.send(&mut conn, &wire_message).await?;
                        Ok::<(), Box<dyn std::error::Error>>(())
                    });

                    match fallback_result {
                        Ok(_) => {
                            log::info!("Friend request acceptance sent via fallback port {} (attempt {})", FALLBACK_PORT, attempt);
                            return 1;
                        }
                        Err(fallback_err) => {
                            if attempt < MAX_RETRIES {
                                log::warn!("Acceptance attempt {}/{} failed (both ports): {}. Retrying in {}s...",
                                    attempt, MAX_RETRIES, fallback_err, RETRY_DELAY_SECS);
                                std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS));
                            } else {
                                log::error!("Failed to send friend request acceptance to {} after {} attempts: {}",
                                    recipient_onion_str, MAX_RETRIES, fallback_err);
                            }
                        }
                    }
                }
            }
        }

        0 // all retries exhausted
    }, 0)
}

/// Reset TorManager singleton state
/// WARNING: Must stop all listeners first before calling this
/// Used when wiping account data to prevent stale control port connections
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_resetTorManager(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        log::warn!("Resetting TorManager singleton...");

        // Create new TorManager instance
        match TorManager::new() {
            Ok(new_manager) => {
                // Replace global instance
                let tor_manager = get_tor_manager();
                let mut manager = tor_manager.lock().unwrap();
                *manager = new_manager;
                log::info!("TorManager reset complete - fresh state initialized");
            }
            Err(e) => {
                log::error!("Failed to reset TorManager: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", format!("TorManager reset failed: {}", e));
            }
        }
    }, ())
}

/// Send ACK on an existing connection (fire-and-forget)
/// Args:
/// connection_id - Connection ID from pollIncomingPing
/// item_id - Item ID (ping_id or message_id)
/// ack_type - "PING_ACK" or "MESSAGE_ACK"
/// encrypted_ack - Encrypted ACK bytes
/// Returns: true if sent successfully, false otherwise
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendAckOnConnection(
    mut env: JNIEnv,
    _class: JClass,
    connection_id: jlong,
    item_id: JString,
    ack_type: JString,
    encrypted_ack: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        // Convert parameters
        let item_id_str = match jstring_to_string(&mut env, item_id) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert item_id: {}", e);
                return 0;
            }
        };

        let ack_type_str = match jstring_to_string(&mut env, ack_type) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert ack_type: {}", e);
                return 0;
            }
        };

        let ack_bytes = match jbytearray_to_vec(&mut env, encrypted_ack) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert ACK bytes: {}", e);
                return 0;
            }
        };

        log::info!("Sending {} on connection {}: {} bytes (item_id={})", ack_type_str, connection_id, ack_bytes.len(), item_id_str);

        // Map ACK type string to message type byte
        let msg_type = match ack_type_str.as_str() {
            "PING_ACK" => crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION,
            "MESSAGE_ACK" => crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION,
            "PONG_ACK" => crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION,
            "TAP_ACK" => crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION,
            _ => {
                log::error!("Unknown ACK type: {}", ack_type_str);
                return 0;
            }
        };

        // Send ACK on connection
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        let result = runtime.block_on(async {
            crate::network::TorManager::send_ack_on_connection(connection_id as u64, msg_type, &ack_bytes).await
        });

        match result {
            Ok(_) => {
                log::info!("{} sent successfully on connection {} (item_id={})", ack_type_str, connection_id, item_id_str);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to send {} on connection {}: {}", ack_type_str, connection_id, e);
                0 // failure
            }
        }
    }, 0)
}

/// Start tap listener on port 9151
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startTapListener(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
) -> jboolean {
    catch_panic!(env, {
        log::info!("Starting multiplexed listener on port {} (TAP + FRIEND_REQUEST)", port);

        let tor_manager = get_tor_manager();

        // Run async listener start using the global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        });

        match result {
            Ok((mut ping_receiver, _pong_receiver)) => {
                // Create channel for tap messages
                let (tap_tx, tap_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                // Create channel for friend request messages
                let (fr_tx, fr_rx) = mpsc::unbounded_channel::<Vec<u8>>();

                // Store receivers globally
                let _ = GLOBAL_TAP_RECEIVER.set(Arc::new(Mutex::new(tap_rx)));
                let _ = GLOBAL_FRIEND_REQUEST_RECEIVER.set(Arc::new(Mutex::new(fr_rx)));

                // Store friend request sender in global FRIEND_REQUEST_TX for routing in tor.rs
                let fr_tx_arc = Arc::new(std::sync::Mutex::new(fr_tx.clone()));
                let _ = crate::network::tor::FRIEND_REQUEST_TX.set(fr_tx_arc);
                log::info!("Friend request channel initialized successfully (shared port {})", port);

                // Spawn task to receive from TorManager PING channel and route by message type
                GLOBAL_RUNTIME.spawn(async move {
                    while let Some((_connection_id, tap_bytes)) = ping_receiver.recv().await {
                        log::info!("Received message via multiplexed listener: {} bytes", tap_bytes.len());

                        // Send to tap channel (friend requests already routed by tor.rs)
                        if let Err(e) = tap_tx.send(tap_bytes) {
                            log::error!("Failed to send to TAP channel: {}", e);
                            // Don't break - keep listener alive even if one message fails
                            continue;
                        }
                    }
                    log::warn!("Multiplexed listener receiver closed");
                });

                log::info!("Multiplexed listener started on port {} - routing TAP and FRIEND_REQUEST by message type", port);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to start multiplexed listener: {}", e);
                0 // failure
            }
        }
    }, 0)
}

/// Stop the TAP listener
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_stopTapListener(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();

        // stop_listener is now async
        GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.stop_listener().await;
        });

        log::info!("TAP listener stopped");
    }, ())
}

/// Poll for an incoming tap (non-blocking)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingTap(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        if let Some(receiver) = GLOBAL_TAP_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok(tap_bytes) => {
                    log::info!("Polled tap: {} bytes", tap_bytes.len());
                    match vec_to_jbytearray(&mut env, &tap_bytes) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No tap available
                    std::ptr::null_mut()
                }
            }
        } else {
            // Listener not started
            std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Start friend request listener (separate from TAP to avoid interference)
/// Initializes the global friend request channel
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startFriendRequestListener(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    catch_panic!(env, {
        log::info!("Initializing friend request listener channel");

        // Create channel for friend requests
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Store receiver globally for polling
        let _ = GLOBAL_FRIEND_REQUEST_RECEIVER.set(Arc::new(Mutex::new(rx)));

        // Store sender in global FRIEND_REQUEST_TX for routing in tor.rs
        let tx_arc = Arc::new(std::sync::Mutex::new(tx));
        if let Err(_) = crate::network::tor::FRIEND_REQUEST_TX.set(tx_arc) {
            log::error!("Friend request channel already initialized");
            return 0;
        }

        log::info!("Friend request listener channel initialized successfully");
        1 // success
    }, 0)
}

/// Decrypt incoming tap and return sender's Ed25519 public key
/// Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Tap]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptIncomingTap(
    mut env: JNIEnv,
    _class: JClass,
    tap_wire: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let wire_bytes = match jbytearray_to_vec(&mut env, tap_wire) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert tap wire bytes: {}", e);
                return std::ptr::null_mut();
            }
        };

        // Network-received packets always have type byte at offset 0
        // Wire format: [type_byte][sender_x25519_pubkey (32 bytes)][encrypted_payload]
        const MIN_LEN: usize = 33; // 1 (type) + 32 (pubkey)

        if wire_bytes.len() < MIN_LEN {
            log::error!("Tap wire too short: {} bytes (min {})", wire_bytes.len(), MIN_LEN);
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (after type byte at offset 1)
        let sender_x25519_pubkey: [u8; 32] = wire_bytes[1..33].try_into().unwrap();
        let encrypted_tap = &wire_bytes[33..];

        log::info!("Decrypting tap from sender X25519: {}", hex::encode(&sender_x25519_pubkey));

        // Get our X25519 private key from KeyManager
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                log::error!("Failed to get context: {}", e);
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                log::error!("Failed to get KeyManager: {}", e);
                return std::ptr::null_mut();
            }
        };

        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get encryption private key: {}", e);
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &sender_x25519_pubkey.to_vec(),
        ) {
            Ok(secret) => secret,
            Err(e) => {
                log::error!("ECDH failed: {}", e);
                return std::ptr::null_mut();
            }
        };

        // Decrypt tap
        let decrypted = match crate::crypto::encryption::decrypt_message(encrypted_tap, &shared_secret) {
            Ok(plain) => plain,
            Err(e) => {
                log::error!("Tap decryption failed: {}", e);
                return std::ptr::null_mut();
            }
        };

        log::info!("Tap decrypted: {}", String::from_utf8_lossy(&decrypted));

        // Return sender's X25519 public key (used to look up contact in database)
        match vec_to_jbytearray(&mut env, &sender_x25519_pubkey.to_vec()) {
            Ok(array) => array.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Start pong listener on port 9152
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startPongListener(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
) -> jboolean {
    catch_panic!(env, {
        log::info!("Starting pong listener on port {}", port);

        let tor_manager = get_tor_manager();

        // Run async listener start using the global runtime
        // Note: PONG_TX and PONG_RX are now initialized inside start_listener()
        // No forwarding task needed - pollIncomingPong() reads directly from PONG_RX
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        });

        match result {
            Ok((_ping_receiver, _pong_receiver)) => {
                log::info!("Pong listener started on port {} (returns both receivers but not stored here)", port);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to start pong listener: {}", e);
                0 // failure
            }
        }
    }, 0)
}

/// Poll for an incoming pong (non-blocking)
/// Reads from GLOBAL_PONG_RECEIVER (local channel stored in FFI, not global in tor.rs)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingPong(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        // Read from GLOBAL_PONG_RECEIVER (same pattern as GLOBAL_PING_RECEIVER)
        if let Some(receiver) = GLOBAL_PONG_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok((conn_id, pong_bytes)) => {
                    // CONSUMER INVARIANT: Verify type byte matches expected poller
                    if pong_bytes.is_empty() {
                        log::error!("FRAMING_VIOLATION: pollIncomingPong got empty buffer, conn_id={}", conn_id);
                        return std::ptr::null_mut();
                    }

                    const MSG_TYPE_PONG: u8 = 0x02;
                    if pong_bytes[0] != MSG_TYPE_PONG {
                        let head_hex: String = pong_bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                        log::error!("FRAMING_VIOLATION: pollIncomingPong got type=0x{:02x} expected=0x{:02x} conn_id={} len={} head={}",
                            pong_bytes[0], MSG_TYPE_PONG, conn_id, pong_bytes.len(), head_hex);
                        return std::ptr::null_mut();
                    }

                    log::info!("POLL: got pong len={} conn={} head={:02x}{:02x}{:02x}{:02x}",
                        pong_bytes.len(), conn_id,
                        pong_bytes.get(0).unwrap_or(&0),
                        pong_bytes.get(1).unwrap_or(&0),
                        pong_bytes.get(2).unwrap_or(&0),
                        pong_bytes.get(3).unwrap_or(&0));

                    match vec_to_jbytearray(&mut env, &pong_bytes) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No pong available (expected - non-blocking poll)
                    std::ptr::null_mut()
                }
            }
        } else {
            // GLOBAL_PONG_RECEIVER not initialized - listener not started yet
            std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Decrypt incoming pong from listener and store in GLOBAL_PONG_SESSIONS
/// Wire format: [Recipient X25519 Public Key - 32 bytes][Encrypted Pong]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptAndStorePongFromListener(
    mut env: JNIEnv,
    _class: JClass,
    pong_wire: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        let wire_bytes = match jbytearray_to_vec(&mut env, pong_wire) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert pong wire bytes: {}", e);
                return 0;
            }
        };

        // Network-received packets always have type byte at offset 0
        // Wire format: [type_byte][sender_x25519_pubkey (32 bytes)][encrypted_payload]
        const MIN_LEN: usize = 33; // 1 (type) + 32 (pubkey)

        if wire_bytes.len() < MIN_LEN {
            log::error!("Pong wire too short: {} bytes (min {})", wire_bytes.len(), MIN_LEN);
            return 0;
        }

        // Extract recipient's X25519 public key (after type byte at offset 1)
        let recipient_x25519_pubkey: [u8; 32] = wire_bytes[1..33].try_into().unwrap();
        let encrypted_pong = &wire_bytes[33..];

        log::info!("Decrypting pong from recipient X25519: {}", hex::encode(&recipient_x25519_pubkey));

        // Get our X25519 private key from KeyManager
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                log::error!("Failed to get context: {}", e);
                return 0;
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                log::error!("Failed to get KeyManager: {}", e);
                return 0;
            }
        };

        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get encryption private key: {}", e);
                return 0;
            }
        };

        // Derive shared secret
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_pubkey.to_vec(),
        ) {
            Ok(secret) => secret,
            Err(e) => {
                log::error!("ECDH failed: {}", e);
                return 0;
            }
        };

        // Decrypt the Pong token
        let decrypted_pong = match crate::crypto::encryption::decrypt_message(encrypted_pong, &shared_secret) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                log::error!("Pong decryption failed: {}", e);
                return 0;
            }
        };

        // Deserialize Pong token
        let pong_token: crate::protocol::message::PongToken = match bincode::deserialize(&decrypted_pong) {
            Ok(token) => token,
            Err(e) => {
                log::error!("Failed to deserialize Pong token: {}", e);
                return 0;
            }
        };

        // Validate protocol version before further processing
        if pong_token.protocol_version != crate::network::tor::P2P_PROTOCOL_VERSION {
            log::error!("PROTOCOL_MISMATCH: Listener Pong protocol_version={} ours={} — dropping",
                pong_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION);
            return 0;
        }

        // Use ping_nonce as ping_id (hex-encoded)
        let ping_id = hex::encode(&pong_token.ping_nonce);
        log::info!("Received Pong for ping_id: {}", ping_id);

        // Convert message::PongToken to pingpong::PongToken
        let pingpong_token = crate::network::pingpong::PongToken {
            protocol_version: pong_token.protocol_version,
            ping_nonce: pong_token.ping_nonce,
            pong_nonce: pong_token.pong_nonce,
            timestamp: pong_token.timestamp,
            authenticated: pong_token.authenticated,
            signature: pong_token.signature,
        };

        // Verify PONG signature using stored outgoing ping signer
        let expected_signer = {
            let signers = OUTGOING_PING_SIGNERS.lock().unwrap();
            signers.get(&ping_id).cloned()
        };
        // DB fallback: if in-memory miss (e.g. process restarted), try Room persistence
        let expected_signer = expected_signer.or_else(|| {
            log::info!("In-memory signer miss for ping_id={}, trying DB fallback...", ping_id);
            let db_result = lookup_signer_db(&mut env, &ping_id);
            if db_result.is_some() {
                log::info!("DB_SIGNER_HIT: Found signer in Room DB for ping_id={}", ping_id);
            } else {
                log::warn!("DB_SIGNER_MISS: No signer in Room DB either for ping_id={}", ping_id);
            }
            db_result
        });
        match expected_signer {
            Some(signer_bytes) => {
                match ed25519_dalek::VerifyingKey::from_bytes(&signer_bytes) {
                    Ok(verifying_key) => {
                        match pingpong_token.verify(&verifying_key) {
                            Ok(true) => {
                                log::info!("PONG_SIG_OK: Listener Pong signature verified for ping_id={}", ping_id);
                                OUTGOING_PING_SIGNERS.lock().unwrap().remove(&ping_id);
                                delete_pending_ping_db(&mut env, &ping_id);
                            },
                            Ok(false) => {
                                log::error!("PONG_SIG_INVALID: Listener Pong signature verification FAILED for ping_id={} — dropping", ping_id);
                                return 0;
                            },
                            Err(e) => {
                                log::error!("PONG_SIG_ERROR: Listener Pong sig check error for ping_id={}: {} — dropping", ping_id, e);
                                return 0;
                            }
                        }
                    },
                    Err(e) => {
                        log::error!("PONG_SIG_ERROR: Invalid stored signer pubkey for ping_id={}: {} — dropping", ping_id, e);
                        return 0;
                    }
                }
            },
            None => {
                log::error!("PONG_SIG_REJECT: No stored signer for ping_id={} (memory + DB miss) — cannot verify, dropping", ping_id);
                return 0;
            }
        }

        // Store verified PONG in GLOBAL_PONG_SESSIONS
        crate::network::pingpong::store_pong_session(&ping_id, pingpong_token);
        PONG_SESSION_COUNT.fetch_add(1, Ordering::Relaxed);
        log::info!("Stored verified Pong in GLOBAL_PONG_SESSIONS (count={})", PONG_SESSION_COUNT.load(Ordering::Relaxed));

        1 // success
    }, 0)
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

/// Check if a Pong has been received (non-blocking poll)
/// Returns true if Pong exists in global storage
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollForPong(
    mut env: JNIEnv,
    _class: JClass,
    ping_id: JString,
) -> jboolean {
    catch_panic!(env, {
        // Convert ping_id to Rust string
        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        log::debug!("pollForPong checking for ping_id: {}", ping_id_str);

        // Check if Pong exists (non-blocking check)
        if crate::network::pingpong::get_pong_session(&ping_id_str).is_some() {
            log::info!("Found Pong for ping_id: {}", ping_id_str);
            1 // true - Pong is waiting
        } else {
            log::debug!("No Pong found for ping_id: {}", ping_id_str);
            0 // false - no Pong yet
        }
    }, 0)
}

/// Send encrypted message blob to recipient via Tor
/// Used after Pong is received - sends the actual message payload
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendMessageBlob(
    mut env: JNIEnv,
    _class: JClass,
    recipient_onion: JString,
    encrypted_message: JByteArray,
    message_type_byte: jbyte,
) -> jboolean {
    catch_panic!(env, {
        // Convert parameters
        let onion_address = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert onion address: {}", e);
                return 0;
            }
        };

        let message_bytes = match jbytearray_to_vec(&mut env, encrypted_message) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert message bytes: {}", e);
                return 0;
            }
        };

        log::info!("Sending message blob to {} ({} bytes encrypted message)", onion_address, message_bytes.len());

        // Get KeyManager to access our X25519 public key
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                log::error!("Failed to get context: {}", e);
                return 0;
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                log::error!("Failed to get KeyManager: {}", e);
                return 0;
            }
        };

        // Get our X25519 public key
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get our X25519 public key: {}", e);
                return 0;
            }
        };

        // Strict boundary validation: X25519 pubkey must be exactly 32 bytes
        if our_x25519_public.len() != 32 {
            log::error!("Invalid X25519 public key length: expected 32 bytes, got {}", our_x25519_public.len());
            return 0;
        }

        // Validate message type before sending
        let msg_type = message_type_byte as u8;
        if !is_valid_message_type(msg_type) {
            log::error!("Invalid message type: 0x{:02x}", msg_type);
            return 0;
        }

        // Payload size validation (CRDT types are NOT evolution-encrypted, skip 49-byte minimum)
        let is_crdt_type = matches!(msg_type,
            crate::network::tor::MSG_TYPE_CRDT_OPS |
            crate::network::tor::MSG_TYPE_SYNC_REQUEST |
            crate::network::tor::MSG_TYPE_SYNC_CHUNK
        );
        if !is_crdt_type && message_bytes.len() < 49 {
            log::error!("Encrypted payload too short: {} bytes (minimum 49)", message_bytes.len());
            return 0;
        }

        // Create wire message: [Type Byte][Sender X25519 Public Key - 32 bytes][Encrypted Message]
        let mut wire_message = Vec::with_capacity(1 + 32 + message_bytes.len());
        wire_message.push(msg_type);
        wire_message.extend_from_slice(&our_x25519_public);
        wire_message.extend_from_slice(&message_bytes);

        log::info!("Wire message: {} bytes (1-byte type + 32-byte X25519 pubkey + {} bytes encrypted)",
            wire_message.len(), message_bytes.len());

        // Get Tor manager
        let tor_manager = get_tor_manager();

        // Send message blob via Tor using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            // Use port 9151 for friend requests (0x07, 0x08), port 9150 for regular messages
            const FRIEND_REQUEST_PORT: u16 = 9151;
            const MESSAGE_PORT: u16 = 9150;

            let port = match msg_type {
                0x07 | 0x08 => FRIEND_REQUEST_PORT, // FRIEND_REQUEST or FRIEND_RESPONSE
                _ => MESSAGE_PORT // Regular messages
            };

            // Add 15-second timeout for Tor connection and send
            // This prevents blocking indefinitely when Tor circuits are slow
            let timeout_duration = std::time::Duration::from_secs(15);

            tokio::time::timeout(timeout_duration, async {
                // Connect to recipient
                let tor = tor_manager.lock().unwrap();
                let mut conn = tor.connect(&onion_address, port).await?;

                // Send wire message (with X25519 pubkey prefix)
                tor.send(&mut conn, &wire_message).await?;

                log::info!("Message blob sent successfully to {}", onion_address);
                Ok::<(), Box<dyn std::error::Error>>(())
            }).await.map_err(|_| {
                log::warn!("Send message blob timed out after 15 seconds to {}", onion_address);
                Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "Operation timed out")) as Box<dyn std::error::Error>
            })?
        });

        match result {
            Ok(_) => 1, // success
            Err(e) => {
                // Categorize error type for stress test diagnostics
                let error_msg = e.to_string().to_lowercase();

                if error_msg.contains("timed out") || error_msg.contains("timeout") {
                    BLOB_FAIL_SOCKS_TIMEOUT.fetch_add(1, Ordering::Relaxed);
                    log::error!("BLOB_SEND_FAIL kind=SOCKS_TIMEOUT to {}: {}", onion_address, e);
                } else if error_msg.contains("connection refused") || error_msg.contains("connect") {
                    BLOB_FAIL_CONNECT_ERR.fetch_add(1, Ordering::Relaxed);
                    log::error!("BLOB_SEND_FAIL kind=CONNECT_ERR to {}: {}", onion_address, e);
                } else if error_msg.contains("tor") || error_msg.contains("bootstrap") || error_msg.contains("circuit") {
                    BLOB_FAIL_TOR_NOT_READY.fetch_add(1, Ordering::Relaxed);
                    log::error!("BLOB_SEND_FAIL kind=TOR_NOT_READY to {}: {}", onion_address, e);
                } else if error_msg.contains("write") || error_msg.contains("send") || error_msg.contains("broken pipe") {
                    BLOB_FAIL_WRITE_ERR.fetch_add(1, Ordering::Relaxed);
                    log::error!("BLOB_SEND_FAIL kind=WRITE_ERR to {}: {}", onion_address, e);
                } else {
                    BLOB_FAIL_UNKNOWN.fetch_add(1, Ordering::Relaxed);
                    log::error!("BLOB_SEND_FAIL kind=UNKNOWN_ERR to {}: {}", onion_address, e);
                }

                0 // failure
            }
        }
    }, 0)
}

/// Send call signaling message via HTTP POST to voice .onion
/// This bypasses VOICE channel routing and sends directly to voice streaming listener
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendHttpToVoiceOnion(
    mut env: JNIEnv,
    _class: JClass,
    voice_onion: JString,
    sender_x25519_pubkey: JByteArray,
    encrypted_message: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        // Convert parameters
        let onion_address = match jstring_to_string(&mut env, voice_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert voice onion address: {}", e);
                return 0;
            }
        };

        let sender_pubkey = match jbytearray_to_vec(&mut env, sender_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert sender pubkey: {}", e);
                return 0;
            }
        };

        let message_bytes = match jbytearray_to_vec(&mut env, encrypted_message) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert encrypted message: {}", e);
                return 0;
            }
        };

        log::info!("Sending call signaling via HTTP POST to voice onion {} ({} bytes encrypted)", onion_address, message_bytes.len());

        // Create wire message: [Type Byte 0x0D][Sender X25519 Public Key - 32 bytes][Encrypted Message]
        const MSG_TYPE_CALL_SIGNALING: u8 = 0x0D;
        let mut wire_message = Vec::with_capacity(1 + 32 + message_bytes.len());
        wire_message.push(MSG_TYPE_CALL_SIGNALING);
        wire_message.extend_from_slice(&sender_pubkey);
        wire_message.extend_from_slice(&message_bytes);

        log::info!("Wire message: {} bytes total", wire_message.len());

        // Send HTTP POST via SOCKS5 to voice listener on port 9152
        let result = GLOBAL_RUNTIME.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Connect to voice .onion via SOCKS5 (port 9152)
            // For signaling, use generic isolation params (not part of multi-circuit)
            let mut stream = match crate::audio::voice_streaming::connect_via_socks5(&onion_address, 9152, 0, "signaling", 0).await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to connect to voice onion via SOCKS5: {}", e);
                    return Err(e);
                }
            };

            // Craft HTTP POST request
            let http_request = format!(
                "POST / HTTP/1.1\r\nHost: {}.onion\r\nContent-Length: {}\r\n\r\n",
                onion_address.trim_end_matches(".onion"),
                wire_message.len()
            );

            // Send HTTP headers
            stream.write_all(http_request.as_bytes()).await?;
            // Send body (wire message)
            stream.write_all(&wire_message).await?;
            stream.flush().await?;

            log::info!("HTTP POST request sent, waiting for response...");

            // Read HTTP response (just check for 200 OK)
            let mut response_buf = vec![0u8; 1024];
            let n = stream.read(&mut response_buf).await?;
            let response_str = String::from_utf8_lossy(&response_buf[..n]);

            if response_str.contains("200 OK") {
                log::info!("HTTP 200 OK received from voice listener");
                Ok(())
            } else {
                log::error!("Unexpected HTTP response: {}", response_str.lines().next().unwrap_or(""));
                Err("HTTP request failed".into())
            }
        });

        match result {
            Ok(_) => 1, // success
            Err(e) => {
                log::error!("Failed to send HTTP POST to voice onion: {}", e);
                0 // failure
            }
        }
    }, 0)
}

/// Global storage for decrypted Ping tokens: ping_id -> PingToken
static STORED_PINGS: Lazy<Arc<Mutex<HashMap<String, crate::network::PingToken>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Global storage for outgoing Ping signer verification: ping_id -> recipient Ed25519 pubkey
/// Used to verify PONG and ACK signatures from the listener path
static OUTGOING_PING_SIGNERS: Lazy<Arc<Mutex<HashMap<String, [u8; 32]>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Store a pending ping signer in the Kotlin Room database (JNI callback).
/// Called after inserting into OUTGOING_PING_SIGNERS in-memory map.
/// Persists across process restart so PONG verification doesn't fail.
fn store_pending_ping_db(env: &mut JNIEnv, ping_id: &str, signer_pubkey: &[u8; 32]) {
    let class = match env.find_class("com/securelegion/database/PendingPingStore") {
        Ok(c) => c,
        Err(_) => {
            log::warn!("store_pending_ping_db: PendingPingStore class not found (DAO not initialized?)");
            return;
        }
    };
    let j_ping_id = match env.new_string(ping_id) {
        Ok(s) => s,
        Err(e) => { log::warn!("store_pending_ping_db: new_string failed: {}", e); return; }
    };
    let j_signer = match env.byte_array_from_slice(signer_pubkey) {
        Ok(a) => a,
        Err(e) => { log::warn!("store_pending_ping_db: byte_array failed: {}", e); return; }
    };
    // PendingPingStore.store(pingId: String, signerPubKey: ByteArray, nowElapsed: Long, ttlMs: Long)
    // We pass 0 for nowElapsed — Kotlin side uses SystemClock.elapsedRealtime() via the store() method
    // Actually, PendingPingStore.store() expects caller to pass nowElapsed, so we call Android API from Rust
    // Simpler: call with current time from Java side — let's use System.currentTimeMillis as rough proxy
    // TTL is 72 hours — Tor peers routinely offline for hours/days, 4h was too aggressive
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let ttl_ms: i64 = 72 * 60 * 60 * 1000; // 72 hours

    if let Err(e) = env.call_static_method(
        &class,
        "store",
        "(Ljava/lang/String;[BJJ)V",
        &[
            (&j_ping_id).into(),
            (&j_signer).into(),
            jni::objects::JValue::Long(now_ms),
            jni::objects::JValue::Long(ttl_ms),
        ],
    ) {
        log::warn!("store_pending_ping_db: JNI call failed: {}", e);
        let _ = env.exception_clear();
    }
}

/// Lookup a pending ping signer from the Kotlin Room database (JNI callback).
/// Called when OUTGOING_PING_SIGNERS in-memory miss — DB fallback for process restart survival.
/// Returns Some([u8; 32]) if found, None if not found or error.
fn lookup_signer_db(env: &mut JNIEnv, ping_id: &str) -> Option<[u8; 32]> {
    let class = match env.find_class("com/securelegion/database/PendingPingStore") {
        Ok(c) => c,
        Err(_) => {
            log::debug!("lookup_signer_db: PendingPingStore class not found");
            return None;
        }
    };
    let j_ping_id = match env.new_string(ping_id) {
        Ok(s) => s,
        Err(e) => { log::warn!("lookup_signer_db: new_string failed: {}", e); return None; }
    };
    // PendingPingStore.lookupSigner(pingId: String): ByteArray?
    let result = match env.call_static_method(
        &class,
        "lookupSigner",
        "(Ljava/lang/String;)[B",
        &[(&j_ping_id).into()],
    ) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("lookup_signer_db: JNI call failed: {}", e);
            let _ = env.exception_clear();
            return None;
        }
    };
    // Result is JObject (byte array or null)
    let obj = match result.l() {
        Ok(o) => o,
        Err(_) => return None,
    };
    if obj.is_null() {
        return None;
    }
    // Convert JByteArray to [u8; 32]
    let j_bytes: jni::objects::JByteArray = obj.into();
    match jbytearray_to_vec(env, j_bytes) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        Ok(bytes) => {
            log::warn!("lookup_signer_db: unexpected signer length {} (expected 32)", bytes.len());
            None
        }
        Err(e) => {
            log::warn!("lookup_signer_db: byte conversion failed: {}", e);
            None
        }
    }
}

/// Delete a pending ping from the Kotlin Room database after successful verification.
fn delete_pending_ping_db(env: &mut JNIEnv, ping_id: &str) {
    let class = match env.find_class("com/securelegion/database/PendingPingStore") {
        Ok(c) => c,
        Err(_) => return,
    };
    let j_ping_id = match env.new_string(ping_id) {
        Ok(s) => s,
        Err(_) => return,
    };
    if let Err(e) = env.call_static_method(
        &class,
        "delete",
        "(Ljava/lang/String;)V",
        &[(&j_ping_id).into()],
    ) {
        log::warn!("delete_pending_ping_db: JNI call failed: {}", e);
        let _ = env.exception_clear();
    }
}

/// Detect if wire message has type-byte prefix (backward compatible)
///
/// Known types: 0x01 (Ping), 0x02 (Pong), 0x03 (Text), 0x04 (Voice), 0x05 (Tap), etc.
/// Returns (offset, has_type_byte):
/// - (1, true) if wire_bytes[0] is a known message type
/// - (0, false) if wire_bytes[0] is NOT a type byte (legacy format)
fn detect_wire_format(wire_bytes: &[u8]) -> (usize, bool) {
    if wire_bytes.is_empty() {
        return (0, false);
    }

    let first_byte = wire_bytes[0];
    let is_known_type = matches!(
        first_byte,
        0x01..=0x0D // MSG_TYPE_PING through MSG_TYPE_CALL_SIGNALING
    );

    if is_known_type {
        (1, true) // Skip type byte, this is new format
    } else {
        (0, false) // No type byte, this is legacy format
    }
}

/// Decrypt an incoming encrypted Ping token
///
/// Wire format: [Optional Type Byte 0x01][Sender X25519 Public Key - 32 bytes][Encrypted Ping Token]
/// Backward compatible: detects if type byte is present automatically
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

        // DIAGNOSTIC: Log raw wire bytes BEFORE decryption
        log::info!("BEFORE decryptIncomingPing ");
        log::info!("len: {} bytes", wire_bytes.len());
        if !wire_bytes.is_empty() {
            log::info!("type_byte: 0x{:02x}", wire_bytes[0]);
            log::info!("first 8 bytes: {}",
                wire_bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            if wire_bytes.len() > 1 {
                log::info!("second byte: 0x{:02x}", wire_bytes[1]);
            }
            if wire_bytes[0] == 0x01 && wire_bytes.len() >= 5 {
                log::info!("PING pubkey_first4: {}",
                    wire_bytes[1..5].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            }
        }
        log::info!("");

        // Network-received packets always have type byte at offset 0
        // Wire format: [type_byte][sender_x25519_pubkey (32 bytes)][encrypted_payload]
        const OFFSET: usize = 1; // Skip type byte
        const MIN_LEN: usize = 33; // 1 (type) + 32 (pubkey)

        if wire_bytes.len() < MIN_LEN {
            log::error!("FRAMING_PROTOCOL_VIOLATION: Ping wire too short");
            log::error!("actual_len={}, min_required={}", wire_bytes.len(), MIN_LEN);
            let _ = env.throw_new("java/lang/IllegalArgumentException", "FRAMING_PROTOCOL_VIOLATION: Wire message too short");
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (after type byte at offset 1)
        let sender_x25519_pubkey = &wire_bytes[OFFSET..OFFSET + 32];

        // Extract encrypted Ping token (after type + pubkey at offset 33)
        let encrypted_ping = &wire_bytes[OFFSET + 32..];

        log::info!("Decrypting incoming Ping: offset={}, encrypted_len={} bytes",
                   OFFSET, encrypted_ping.len());

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
                log::error!("PAYLOAD_PARSE_FAILURE: Decrypted OK but PingToken parse failed");
                log::error!("Reason: {}", e);
                log::error!("Decrypted {} bytes - wrong payload type for PING", decrypted_ping.len());
                let _ = env.throw_new("java/lang/RuntimeException", format!("PAYLOAD_PARSE_FAILURE: Failed to parse PingToken: {}", e));
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

        // Validate protocol version
        if ping_token.protocol_version != crate::network::tor::P2P_PROTOCOL_VERSION {
            log::error!("PROTOCOL_MISMATCH: Ping protocol_version={} ours={} — rejecting",
                ping_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION);
            let _ = env.throw_new("java/lang/SecurityException",
                format!("Protocol version mismatch: peer={} ours={}", ping_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION));
            return std::ptr::null_mut();
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

/// Get the sender's Ed25519 public key from a stored Ping token
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getPingSenderPublicKey(
    mut env: JNIEnv,
    _class: JClass,
    ping_id: JString,
) -> jbyteArray {
    catch_panic!(env, {
        // Convert ping_id to String
        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Look up stored PingToken (read-only, don't remove)
        let sender_pubkey = {
            let stored = STORED_PINGS.lock().unwrap();
            match stored.get(&ping_id_str) {
                Some(token) => token.sender_pubkey.clone(),
                None => {
                    log::warn!("Ping ID not found in storage: {}", ping_id_str);
                    return std::ptr::null_mut();
                }
            }
        };

        log::info!("Retrieved sender public key for Ping {}", ping_id_str);

        // Convert sender_pubkey to Java byte array
        match env.byte_array_from_slice(&sender_pubkey) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create byte array: {}", e));
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

        // Get sender's X25519 public key from PingToken (now properly included)
        let sender_x25519_pubkey = &ping_token.sender_x25519_pubkey;

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

/// Decrypt an incoming encrypted Pong token
///
/// Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Pong Token]
/// Returns: Ping ID (String) that the Pong is responding to
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptIncomingPong(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_pong_wire: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // Convert wire bytes
        let wire_bytes = match jbytearray_to_vec(&mut env, encrypted_pong_wire) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Network-received packets always have type byte at offset 0
        // Wire format: [type_byte][sender_x25519_pubkey (32 bytes)][encrypted_payload]
        const OFFSET: usize = 1; // Skip type byte
        const MIN_LEN: usize = 33; // 1 (type) + 32 (pubkey)

        if wire_bytes.len() < MIN_LEN {
            log::warn!("Pong wire too short: actual_len={}, min_required={}", wire_bytes.len(), MIN_LEN);
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Wire message too short - missing X25519 pubkey");
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (after type byte at offset 1)
        let sender_x25519_bytes: [u8; 32] = wire_bytes[OFFSET..OFFSET + 32].try_into().unwrap();
        let encrypted_pong = &wire_bytes[OFFSET + 32..];

        log::info!("Attempting to decrypt incoming Pong: offset={}, encrypted_len={} bytes",
                   OFFSET, encrypted_pong.len());

        // Get KeyManager for our X25519 private key
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
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption key: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &sender_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                log::error!("ECDH failed for Pong decryption: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Decrypt Pong
        let pong_bytes = match crate::crypto::encryption::decrypt_message(encrypted_pong, &shared_secret) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Pong decryption failed: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", format!("Decryption failed: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Deserialize PongToken
        let pong_token = match crate::network::PongToken::from_bytes(&pong_bytes) {
            Ok(token) => token,
            Err(e) => {
                log::error!("Failed to parse Pong token: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to parse Pong: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Validate protocol version
        if pong_token.protocol_version != crate::network::tor::P2P_PROTOCOL_VERSION {
            log::error!("PROTOCOL_MISMATCH: Pong protocol_version={} ours={} — rejecting",
                pong_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION);
            let _ = env.throw_new("java/lang/SecurityException",
                format!("Protocol version mismatch: peer={} ours={}", pong_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION));
            return std::ptr::null_mut();
        }

        // Extract Ping ID from Pong (the ping_nonce field)
        let ping_id = hex::encode(&pong_token.ping_nonce);

        log::info!("Decrypted incoming Pong for Ping ID: {} (authenticated={})", ping_id, pong_token.authenticated);

        // Store Pong in global session storage for pollForPong()
        crate::network::pingpong::store_pong_session(&ping_id, pong_token);
        PONG_SESSION_COUNT.fetch_add(1, Ordering::Relaxed);

        // Return Ping ID
        match string_to_jstring(&mut env, &ping_id) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Send encrypted message via Tor after Ping-Pong wake protocol
///
/// Flow:
/// 1. Send Ping to recipient's .onion address
/// 2. Wait for Pong response (user authentication)
/// 3. If authenticated, send encrypted message
/// 4. Return success/failure
///
/// # Arguments
/// * `recipient_ed25519_pubkey` - Recipient's Ed25519 public key (for Ping signature)
/// * `recipient_x25519_pubkey` - Recipient's X25519 public key (for encryption)
/// * `recipient_onion` - Recipient's .onion address
/// * `encrypted_message` - Pre-encrypted message bytes
///
/// # Returns
/// * `true` if message sent successfully, `false` otherwise
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendDirectMessage(
    mut env: JNIEnv,
    _class: JClass,
    recipient_ed25519_pubkey: JByteArray,
    recipient_x25519_pubkey: JByteArray,
    recipient_onion: JString,
    encrypted_message: JByteArray,
    message_type_byte: jbyte,
) -> jboolean {
    catch_panic!(env, {
        // Convert inputs
        let recipient_ed25519_bytes = match jbytearray_to_vec(&mut env, recipient_ed25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        let recipient_x25519_bytes = match jbytearray_to_vec(&mut env, recipient_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        let recipient_onion_str = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        let message_bytes = match jbytearray_to_vec(&mut env, encrypted_message) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        log::info!("Sending message to {} ({} bytes)", recipient_onion_str, message_bytes.len());

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
                return 0;
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get KeyManager: {}", e));
                return 0;
            }
        };

        // Get our signing private key (Ed25519)
        let our_signing_private = match crate::ffi::keystore::get_signing_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get signing key: {}", e));
                return 0;
            }
        };

        // Create Ed25519 signing keypair
        let sender_keypair = ed25519_dalek::SigningKey::from_bytes(&our_signing_private.as_slice().try_into().unwrap());

        let recipient_ed25519_verifying = match ed25519_dalek::VerifyingKey::from_bytes(&recipient_ed25519_bytes.as_slice().try_into().unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid recipient Ed25519 pubkey: {}", e));
                return 0;
            }
        };

        // Get our X25519 public key (needed for PingToken)
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get our X25519 pubkey: {}", e));
                return 0;
            }
        };

        // Convert X25519 keys to fixed-size arrays
        let sender_x25519_pubkey: [u8; 32] = match our_x25519_public.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid sender X25519 pubkey size");
                return 0;
            }
        };

        let recipient_x25519_pubkey: [u8; 32] = match recipient_x25519_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid recipient X25519 pubkey size");
                return 0;
            }
        };

        // Step 1: Create and send Ping token (with both Ed25519 and X25519 keys)
        let ping_token = match crate::network::PingToken::new(
            &sender_keypair,
            &recipient_ed25519_verifying,
            &sender_x25519_pubkey,
            &recipient_x25519_pubkey,
        ) {
            Ok(token) => token,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create Ping: {}", e));
                return 0;
            }
        };

        let ping_bytes = match ping_token.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to serialize Ping: {}", e));
                return 0;
            }
        };

        // Get our X25519 encryption private key
        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get encryption key: {}", e));
                return 0;
            }
        };

        // Derive shared secret for Ping encryption
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("ECDH failed: {}", e));
                return 0;
            }
        };

        // Encrypt Ping
        let encrypted_ping = match crate::crypto::encryption::encrypt_message(&ping_bytes, &shared_secret) {
            Ok(enc) => enc,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Ping encryption failed: {}", e));
                return 0;
            }
        };

        // Get our X25519 public key to prepend
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get our X25519 pubkey: {}", e));
                return 0;
            }
        };

        // Wire format for Ping: [Type Byte 0x01][Our X25519 Public Key - 32 bytes][Encrypted Ping Token]
        let mut ping_wire_message = Vec::new();
        ping_wire_message.push(crate::network::tor::MSG_TYPE_PING); // Add type byte
        ping_wire_message.extend_from_slice(&our_x25519_public);
        ping_wire_message.extend_from_slice(&encrypted_ping);

        // Step 2: Send Ping via Tor and wait for Pong
        let tor_manager = get_tor_manager();

        // Validate message type before sending
        let msg_type = message_type_byte as u8;
        if !is_valid_message_type(msg_type) {
            log::error!("Invalid message type: {}", msg_type);
            return 0;
        }

        const MESSAGE_PORT: u16 = 9150;

        let result = GLOBAL_RUNTIME.block_on(async {
            // Connect to recipient's .onion address (lock only during connect)
            let mut conn = {
                let manager = tor_manager.lock().unwrap();
                manager.connect(&recipient_onion_str, MESSAGE_PORT).await?
            }; // Lock released here - allows concurrent operations

            // Send Ping (lock only during send)
            {
                let manager = tor_manager.lock().unwrap();
                manager.send(&mut conn, &ping_wire_message).await?;
            } // Lock released here
            log::info!("Ping sent, waiting for Pong response...");

            // Wait for encrypted Pong response (with timeout)
            // No lock needed - TorConnection owns the socket
            let pong_response = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                conn.receive()
            ).await.map_err(|_| "Pong timeout")??;

            // Verify Pong (decrypt and check authentication)
            if pong_response.len() < 2 {
                return Err("Invalid Pong response".into());
            }

            // Extract type byte
            let type_byte = pong_response[0];
            if type_byte != crate::network::tor::MSG_TYPE_PONG {
                if type_byte == crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION {
                    log::warn!("Received PING_ACK (0x06) when expecting PONG - ignoring (should go to port 9153)");
                    log::warn!("→ This is a bug - PING_ACK was sent to wrong port. Continuing without instant pong.");
                    return Err("PING_ACK received instead of PONG".into());
                }
                log::warn!("Expected PONG (0x02) but got type 0x{:02x}", type_byte);
                return Err(format!("Wrong message type: expected PONG, got 0x{:02x}", type_byte).into());
            }

            // Encrypted Pong starts after type byte
            let encrypted_pong = &pong_response[1..];

            // Decrypt Pong
            let decrypted_pong = crate::crypto::encryption::decrypt_message(encrypted_pong, &shared_secret)?;

            // Parse Pong token
            let pong_token = crate::network::PongToken::from_bytes(&decrypted_pong)?;

            // Verify Pong signature and check authentication
            pong_token.verify(&recipient_ed25519_verifying)?;

            if !pong_token.authenticated {
                log::warn!("Recipient declined message (not authenticated)");
                return Err("Recipient declined message".into());
            }

            log::info!("Pong received and authenticated! Sending message...");

            // Step 3: Send encrypted message (lock only during send)
            // Wire format for message: [Type Byte][Sender X25519 Public Key][Encrypted Message]
            // (Length prefix is added automatically by manager.send())
            let mut message_wire = Vec::new();
            message_wire.push(msg_type); // Type byte from parameter
            message_wire.extend_from_slice(&our_x25519_public); // Sender X25519 pubkey
            message_wire.extend_from_slice(&message_bytes); // Encrypted message

            {
                let manager = tor_manager.lock().unwrap();
                manager.send(&mut conn, &message_wire).await?;
            } // Lock released here

            log::info!("Message sent successfully ({} bytes)", message_bytes.len());

            Ok::<(), Box<dyn std::error::Error>>(())
        });

        match result {
            Ok(_) => {
                log::info!("Message delivery complete");
                1 // true
            }
            Err(e) => {
                log::error!("Message delivery failed: {}", e);
                let _ = env.throw_new("java/lang/RuntimeException", format!("Message send failed: {}", e));
                0 // false
            }
        }
    }, 0)
}

/// Receive incoming message after Pong is sent
/// Reads the encrypted message from the pending connection
///
/// # Arguments
/// * `connection_id` - The connection ID from the Ping-Pong handshake
///
/// # Returns
/// * Encrypted message bytes, or null if no message or error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_receiveIncomingMessage(
    mut env: JNIEnv,
    _class: JClass,
    connection_id: jlong,
) -> jbyteArray {
    catch_panic!(env, {
        let conn_id = connection_id as u64;
        log::info!("Receiving incoming message on connection {}", conn_id);

        // Get the connection from the pending connections map
        let pending_conn = {
            let mut map = PENDING_CONNECTIONS.lock().unwrap();
            map.remove(&conn_id)
        };

        if pending_conn.is_none() {
            log::error!("Connection {} not found in pending connections", conn_id);
            return std::ptr::null_mut();
        }

        let mut pending = pending_conn.unwrap();

        // Read message from the connection
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        let result = runtime.block_on(async {
            use tokio::io::AsyncReadExt;

            // Read message length (4 bytes, big-endian)
            let mut length_bytes = [0u8; 4];
            pending.socket.read_exact(&mut length_bytes).await?;
            let message_length = u32::from_be_bytes(length_bytes) as usize;

            log::info!("Incoming message length: {} bytes", message_length);

            // Validate length (max 10MB for safety)
            if message_length > 10_000_000 {
                return Err("Message too large".into());
            }

            // Read the encrypted message
            let mut message_bytes = vec![0u8; message_length];
            pending.socket.read_exact(&mut message_bytes).await?;

            log::info!("Successfully read encrypted message ({} bytes)", message_bytes.len());

            Ok::<Vec<u8>, Box<dyn std::error::Error>>(message_bytes)
        });

        match result {
            Ok(message_bytes) => {
                // Convert to Java byte array
                match env.byte_array_from_slice(&message_bytes) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        log::error!("Failed to create Java byte array: {}", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to receive message: {}", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Start the Tor bootstrap event listener
/// This should be called early, before Tor initialization, so it can capture progress from the start
/// socketPath: path to ControlSocket file (GP tor-android 0.4.9.5 Unix domain socket)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startBootstrapListener(
    mut env: JNIEnv,
    _class: JClass,
    socket_path: JObject,
) {
    catch_panic!(env, {
        let path: Option<String> = if socket_path.is_null() {
            None
        } else {
            let js = JString::from(socket_path);
            env.get_string(&js).ok().map(|s| s.into())
        };
        log::info!("Starting bootstrap event listener (ControlSocket: {})...",
            if path.is_some() { "set" } else { "not set" });
        crate::network::tor::start_bootstrap_event_listener_with_socket(path);
    }, ())
}

/// Check if the bootstrap event listener thread is currently running
/// Returns JNI_TRUE (1) if running, JNI_FALSE (0) if dead/stopped
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_isEventListenerRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    crate::network::tor::is_event_listener_running() as jboolean
}

/// Stop the bootstrap event listener (signal it to exit)
/// Call this before restarting Tor so a fresh listener can be spawned
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_stopBootstrapListener(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        log::info!("Stopping bootstrap event listener...");
        crate::network::tor::stop_bootstrap_event_listener();
    }, ())
}

/// Get Tor bootstrap status (0-100%)
/// Returns the current bootstrap percentage from the global atomic (updated by event listener)
/// This is much faster than querying the control port and provides real-time updates
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getBootstrapStatus(
    mut env: JNIEnv,
    _class: JClass,
) -> jint {
    catch_panic!(env, {
        // Read from the global atomic (updated in real-time by event listener)
        let percentage = crate::network::tor::get_bootstrap_status_fast();
        log::debug!("Tor bootstrap status: {}%", percentage);
        percentage as jint
    }, -1 as jint)
}

/// Get circuit established status (0 = no circuits, 1 = circuits established)
/// Fast atomic read, updated every 5 seconds by ControlPort polling
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getCircuitEstablished(
    mut env: JNIEnv,
    _class: JClass,
) -> jint {
    catch_panic!(env, {
        // Read from the global atomic (polled every 5s from ControlPort)
        let status = crate::network::tor::get_circuit_established_fast();
        log::debug!("Circuit established status: {}", status);
        status as jint
    }, 0 as jint)
}

/// Get event listener heartbeat (epoch millis of last successful operation).
/// Returns 0 if the listener has never run or the control port connection is dead.
/// Kotlin uses this to detect a frozen/stale listener — if heartbeat is >30s old
/// and tor state is RUNNING, the listener is dead and health should be treated as unhealthy.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getLastListenerHeartbeat(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    catch_panic!(env, {
        crate::network::tor::get_last_listener_heartbeat() as jlong
    }, 0 as jlong)
}

/// Get HS descriptor upload count - how many HSDirs have confirmed our descriptor
/// Updated in real-time by event listener when it sees HS_DESC UPLOADED events
/// v3 onions upload to ~6-8 HSDirs; count >= 1 means partially reachable, >= 3 is good
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getHsDescUploadCount(
    mut env: JNIEnv,
    _class: JClass,
) -> jint {
    catch_panic!(env, {
        let count = crate::network::tor::get_hs_desc_upload_count();
        count as jint
    }, 0 as jint)
}

/// Reset HS descriptor upload counter (call before creating a new hidden service)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_resetHsDescUploadCount(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        crate::network::tor::reset_hs_desc_upload_count();
        log::info!("HS_DESC upload counter reset from JNI");
    }, ())
}

/// Register Tor event callback handler
/// Receives ControlPort events (CIRC, HS_DESC, STATUS_GENERAL, etc)
/// Callback signature: onTorEvent(eventType: String, circId: String, reason: String, address: String, severity: String, message: String, progress: Int)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_setTorEventCallback(
    mut env: JNIEnv,
    _class: JClass,
    callback: JObject,
) {
    catch_panic!(env, {
        // Create global reference to callback object
        let global_callback = env.new_global_ref(callback)
            .expect("Failed to create global reference to Tor event callback");

        // Store callback in global
        let callback_storage = GLOBAL_TOR_EVENT_CALLBACK.get_or_init(|| Mutex::new(None));
        *callback_storage.lock().unwrap() = Some(global_callback);

        // Store JavaVM globally for 'static lifetime (get_or_init ensures it's only set once)
        let jvm = env.get_java_vm().expect("Failed to get JavaVM");
        GLOBAL_TOR_EVENT_JVM.get_or_init(|| jvm);

        log::info!("Tor event callback registered");

        // Register the callback with the tor module
        crate::network::tor::register_tor_event_callback(move |event| {
            // Forward event to Kotlin via JNI callback
            if let Err(e) = invoke_tor_event_callback(event) {
                log::error!("Failed to invoke Tor event callback: {}", e);
            }
        });
    }, ())
}

/// Helper function to invoke Kotlin callback with Tor event data
/// Must be called from Rust thread (not JNI thread)
fn invoke_tor_event_callback(event: crate::network::tor::TorEventType) -> Result<(), Box<dyn std::error::Error>> {
    use crate::network::tor::TorEventType;

    // 1) Get JavaVM from global storage ('static lifetime, no mutex needed)
    let jvm = match GLOBAL_TOR_EVENT_JVM.get() {
        Some(vm) => vm,
        None => {
            // JVM not initialized yet
            return Ok(());
        }
    };

    // 2) Attach to current thread (attach guard must live for entire function)
    let mut env = jvm.attach_current_thread()?;

    // 3) Clone GlobalRef out of callback storage (avoid holding lock during call_method)
    let callback: jni::objects::GlobalRef = {
        let callback_storage = GLOBAL_TOR_EVENT_CALLBACK.get_or_init(|| Mutex::new(None));
        let guard = callback_storage.lock().unwrap();
        match guard.as_ref() {
            Some(cb) => cb.clone(),
            None => return Ok(()),
        }
    }; // Lock dropped here

    let callback_obj = callback.as_obj();

    // Prepare event data based on type
    let (event_type, circ_id, reason, address, severity, message, progress) = match event {
        TorEventType::Bootstrap { progress } => {
            ("BOOTSTRAP".to_string(), "".to_string(), "".to_string(), "".to_string(), "".to_string(), "".to_string(), progress as i32)
        }
        TorEventType::CircuitBuilt { circ_id } => {
            ("CIRC_BUILT".to_string(), circ_id, "".to_string(), "".to_string(), "".to_string(), "".to_string(), 0)
        }
        TorEventType::CircuitFailed { circ_id, reason } => {
            ("CIRC_FAILED".to_string(), circ_id, reason, "".to_string(), "".to_string(), "".to_string(), 0)
        }
        TorEventType::CircuitClosed { circ_id, reason } => {
            ("CIRC_CLOSED".to_string(), circ_id, reason, "".to_string(), "".to_string(), "".to_string(), 0)
        }
        TorEventType::HsDescUploaded { address } => {
            ("HS_DESC_UPLOADED".to_string(), "".to_string(), "".to_string(), address, "".to_string(), "".to_string(), 0)
        }
        TorEventType::HsDescUploadFailed { address, reason } => {
            ("HS_DESC_FAILED".to_string(), "".to_string(), reason, address, "".to_string(), "".to_string(), 0)
        }
        TorEventType::StatusGeneral { severity, message } => {
            ("STATUS_GENERAL".to_string(), "".to_string(), "".to_string(), "".to_string(), severity, message, 0)
        }
    };

    // Convert to JString
    let j_event_type = env.new_string(event_type)?;
    let j_circ_id = env.new_string(circ_id)?;
    let j_reason = env.new_string(reason)?;
    let j_address = env.new_string(address)?;
    let j_severity = env.new_string(severity)?;
    let j_message = env.new_string(message)?;

    // Call Kotlin callback: onTorEvent(eventType, circId, reason, address, severity, message, progress)
    env.call_method(
        callback_obj,
        "onTorEvent",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V",
        &[
            (&j_event_type).into(),
            (&j_circ_id).into(),
            (&j_reason).into(),
            (&j_address).into(),
            (&j_severity).into(),
            (&j_message).into(),
            progress.into(),
        ],
    )?;

    Ok(())
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

        // Get our X25519 public key (needed for PingToken)
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get our X25519 pubkey: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Convert X25519 keys to fixed-size arrays
        let sender_x25519_pubkey: [u8; 32] = match our_x25519_public.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid sender X25519 pubkey size");
                return std::ptr::null_mut();
            }
        };

        let recipient_x25519_pubkey: [u8; 32] = match recipient_x25519_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid recipient X25519 pubkey size");
                return std::ptr::null_mut();
            }
        };

        // 5. Create PingToken (with both Ed25519 and X25519 keys)
        let ping_token = match crate::network::PingToken::new(
            &sender_keypair,
            &recipient_ed25519_pubkey,
            &sender_x25519_pubkey,
            &recipient_x25519_pubkey,
        ) {
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

        // 7b. Validate protocol version
        if ping_token.protocol_version != crate::network::tor::P2P_PROTOCOL_VERSION {
            log::error!("PROTOCOL_MISMATCH: Ping protocol_version={} ours={} — rejecting",
                ping_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION);
            let _ = env.throw_new("java/lang/SecurityException",
                format!("Protocol version mismatch: peer={} ours={}", ping_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION));
            return std::ptr::null_mut();
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

        // 7b. Validate protocol version
        if pong_token.protocol_version != crate::network::tor::P2P_PROTOCOL_VERSION {
            log::error!("PROTOCOL_MISMATCH: Pong protocol_version={} ours={} — rejecting",
                pong_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION);
            let _ = env.throw_new("java/lang/SecurityException",
                format!("Protocol version mismatch: peer={} ours={}", pong_token.protocol_version, crate::network::tor::P2P_PROTOCOL_VERSION));
            return std::ptr::null_mut();
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
        PONG_SESSION_COUNT.fetch_add(1, Ordering::Relaxed);

        array.into_raw()
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
/// ourPrivateKey - Our 32-byte X25519 private key
/// theirPublicKey - Their 32-byte X25519 public key
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

/// Derive root key from X25519 shared secret using HKDF-SHA256
/// @param sharedSecret 32-byte X25519 shared secret
/// @param info Context string (e.g., "SecureLegion-RootKey-v1")
/// @return 32-byte root key
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_deriveRootKey(
    mut env: JNIEnv,
    _class: JClass,
    shared_secret: JByteArray,
    info: JString,
) -> jbyteArray {
    catch_panic!(env, {
        let shared_secret_vec = match jbytearray_to_vec(&mut env, shared_secret) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if shared_secret_vec.len() != 32 && shared_secret_vec.len() != 64 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Shared secret must be 32 or 64 bytes");
            return std::ptr::null_mut();
        }

        let info_str = match jstring_to_string(&mut env, info) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        match derive_root_key(&shared_secret_vec, info_str.as_bytes()) {
            Ok(root_key) => match vec_to_jbytearray(&mut env, &root_key) {
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

/// Evolve chain key forward using HMAC-SHA256 (one-way function)
/// Provides forward secrecy - old chain keys cannot be recovered from new ones
/// @param chainKey Current 32-byte chain key (will be zeroized)
/// @return Next chain key (32 bytes)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_evolveChainKey(
    mut env: JNIEnv,
    _class: JClass,
    chain_key: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let chain_key_vec = match jbytearray_to_vec(&mut env, chain_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if chain_key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Chain key must be 32 bytes");
            return std::ptr::null_mut();
        }

        let mut chain_key_array: [u8; 32] = chain_key_vec.try_into().unwrap();

        match evolve_chain_key(&mut chain_key_array) {
            Ok(new_chain_key) => match vec_to_jbytearray(&mut env, &new_chain_key) {
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

/// Derive receive chain key for a specific sender sequence (out-of-order decryption)
/// @param rootKey 32-byte root key (same for both parties)
/// @param senderSequence The sequence number the sender used to encrypt
/// @param ourOnion Our .onion address (for direction mapping)
/// @param theirOnion Their .onion address (for direction mapping)
/// @return 32-byte chain key at sender's sequence (for decrypting their message)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_deriveReceiveKeyAtSequence(
    mut env: JNIEnv,
    _class: JClass,
    root_key: JByteArray,
    sender_sequence: jlong,
    our_onion: JString,
    their_onion: JString,
) -> jbyteArray {
    catch_panic!(env, {
        // Parse root key
        let root_key_vec = match jbytearray_to_vec(&mut env, root_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if root_key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Root key must be 32 bytes");
            return std::ptr::null_mut();
        }

        let root_key_array: [u8; 32] = root_key_vec.try_into().unwrap();

        // Parse onion addresses
        let our_onion_str = match jstring_to_string(&mut env, our_onion) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let their_onion_str = match jstring_to_string(&mut env, their_onion) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Derive key at sequence
        match derive_receive_key_at_sequence(
            &root_key_array,
            sender_sequence as u64,
            &our_onion_str,
            &their_onion_str,
        ) {
            Ok(key) => match vec_to_jbytearray(&mut env, &key[..]) {
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

/// Derive ephemeral message key from chain key
/// @param chainKey Current 32-byte chain key
/// @return 32-byte message key for encrypting/decrypting this message
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_deriveMessageKey(
    mut env: JNIEnv,
    _class: JClass,
    chain_key: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let chain_key_vec = match jbytearray_to_vec(&mut env, chain_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if chain_key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Chain key must be 32 bytes");
            return std::ptr::null_mut();
        }

        let chain_key_array: [u8; 32] = chain_key_vec.try_into().unwrap();

        match derive_message_key(&chain_key_array) {
            Ok(message_key) => match vec_to_jbytearray(&mut env, &message_key) {
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

// ==================== HYBRID POST-QUANTUM CRYPTOGRAPHY ====================

/// Generate hybrid KEM keypair from seed (X25519 + Kyber-1024)
/// @param seed 32-byte seed for deterministic key generation
/// @return Serialized keypair: [x25519_pub:32][x25519_sec:32][kyber_pub:1568][kyber_sec:3168]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_generateHybridKEMKeypairFromSeed(
    mut env: JNIEnv,
    _class: JClass,
    seed: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let seed_vec = match jbytearray_to_vec(&mut env, seed) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if seed_vec.len() != 32 {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Seed must be 32 bytes"
            );
            return std::ptr::null_mut();
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed_vec);

        match crate::crypto::generate_hybrid_keypair_from_seed(&seed_array) {
            Ok(keypair) => {
                let serialized = keypair.to_bytes();
                match vec_to_jbytearray(&mut env, &serialized) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    format!("Failed to generate hybrid keypair: {}", e)
                );
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Hybrid encapsulation (X25519 + Kyber-1024)
/// @param theirX25519Public Their X25519 public key (32 bytes)
/// @param theirKyberPublic Their Kyber public key (1568 bytes)
/// @return [combined_secret:64][x25519_ephemeral:32][kyber_ciphertext:1568]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_hybridEncapsulate(
    mut env: JNIEnv,
    _class: JClass,
    their_x25519_public: JByteArray,
    their_kyber_public: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let x25519_pub = match jbytearray_to_vec(&mut env, their_x25519_public) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let kyber_pub = match jbytearray_to_vec(&mut env, their_kyber_public) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if x25519_pub.len() != 32 {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "X25519 public key must be 32 bytes"
            );
            return std::ptr::null_mut();
        }

        if kyber_pub.len() != 1568 {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Kyber public key must be 1568 bytes"
            );
            return std::ptr::null_mut();
        }

        let mut x25519_array = [0u8; 32];
        x25519_array.copy_from_slice(&x25519_pub);

        let mut kyber_array = [0u8; 1568];
        kyber_array.copy_from_slice(&kyber_pub);

        match crate::crypto::hybrid_encapsulate(&x25519_array, &kyber_array) {
            Ok((combined_secret, ciphertext)) => {
                // Serialize: [combined_secret:64][ciphertext]
                let mut result = Vec::with_capacity(64 + ciphertext.to_bytes().len());
                result.extend_from_slice(&combined_secret);
                result.extend_from_slice(&ciphertext.to_bytes());

                match vec_to_jbytearray(&mut env, &result) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    format!("Encapsulation failed: {}", e)
                );
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Hybrid decapsulation (X25519 + Kyber-1024)
/// @param ourX25519Secret Our X25519 secret key (32 bytes)
/// @param ourKyberSecret Our Kyber secret key (3168 bytes)
/// @param ciphertext Combined ciphertext (1600 bytes: 32 + 1568)
/// @return Combined secret (64 bytes)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_hybridDecapsulate(
    mut env: JNIEnv,
    _class: JClass,
    our_x25519_secret: JByteArray,
    our_kyber_secret: JByteArray,
    ciphertext: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        let x25519_sec = match jbytearray_to_vec(&mut env, our_x25519_secret) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let kyber_sec = match jbytearray_to_vec(&mut env, our_kyber_secret) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let ct = match jbytearray_to_vec(&mut env, ciphertext) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if x25519_sec.len() != 32 {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "X25519 secret must be 32 bytes"
            );
            return std::ptr::null_mut();
        }

        if kyber_sec.len() != 3168 {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Kyber secret must be 3168 bytes"
            );
            return std::ptr::null_mut();
        }

        if ct.len() != 1600 {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Ciphertext must be 1600 bytes (32 + 1568)"
            );
            return std::ptr::null_mut();
        }

        let mut x25519_array = [0u8; 32];
        x25519_array.copy_from_slice(&x25519_sec);

        let mut kyber_array = [0u8; 3168];
        kyber_array.copy_from_slice(&kyber_sec);

        let hybrid_ct = match crate::crypto::HybridCiphertext::from_bytes(&ct) {
            Ok(ct) => ct,
            Err(e) => {
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    format!("Invalid ciphertext: {}", e)
                );
                return std::ptr::null_mut();
            }
        };

        match crate::crypto::hybrid_decapsulate(&x25519_array, &kyber_array, &hybrid_ct) {
            Ok(combined_secret) => {
                match vec_to_jbytearray(&mut env, &combined_secret) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    format!("Decapsulation failed: {}", e)
                );
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== END HYBRID POST-QUANTUM CRYPTOGRAPHY ====================

/// Encrypt message with key evolution (for messaging)
/// ATOMIC OPERATION: Returns both encrypted message and evolved key
///
/// Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
/// Return format: [evolved_key:32][ciphertext]
///
/// @param plaintext Message to encrypt
/// @param chainKey Current chain key (will be evolved)
/// @param sequence Message sequence number
/// @return [evolved_chain_key:32][encrypted_message] - split first 32 bytes on Kotlin side
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_encryptMessageWithEvolutionJNI(
    mut env: JNIEnv,
    _class: JClass,
    plaintext: JString,
    chain_key: JByteArray,
    sequence: jlong,
) -> jbyteArray {
    catch_panic!(env, {
        let plaintext_str = match jstring_to_string(&mut env, plaintext) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let chain_key_vec = match jbytearray_to_vec(&mut env, chain_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if chain_key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Chain key must be 32 bytes");
            return std::ptr::null_mut();
        }

        let mut chain_key_array: [u8; 32] = chain_key_vec.try_into().unwrap();

        match encrypt_message_with_evolution(plaintext_str.as_bytes(), &mut chain_key_array, sequence as u64) {
            Ok(result) => {
                // Build result: [evolved_key:32][ciphertext]
                let mut output = Vec::with_capacity(32 + result.ciphertext.len());
                output.extend_from_slice(&result.evolved_chain_key);
                output.extend_from_slice(&result.ciphertext);

                match vec_to_jbytearray(&mut env, &output) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("{}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Decrypt message with key evolution (for messaging)
/// ATOMIC OPERATION: Returns both decrypted message and evolved key
///
/// Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
/// Return format: [evolved_key:32][plaintext_utf8]
///
/// @param encryptedData Encrypted message with wire format header
/// @param chainKey Current chain key (will be evolved)
/// @param expectedSequence Expected sequence number (for replay protection)
/// @return [evolved_chain_key:32][plaintext_utf8] - split first 32 bytes on Kotlin side, or null if decryption fails
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptMessageWithEvolutionJNI(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_data: JByteArray,
    chain_key: JByteArray,
    expected_sequence: jlong,
) -> jbyteArray {
    catch_panic!(env, {
        let encrypted_vec = match jbytearray_to_vec(&mut env, encrypted_data) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let chain_key_vec = match jbytearray_to_vec(&mut env, chain_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if chain_key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Chain key must be 32 bytes");
            return std::ptr::null_mut();
        }

        let mut chain_key_array: [u8; 32] = chain_key_vec.try_into().unwrap();

        match decrypt_message_with_evolution(&encrypted_vec, &mut chain_key_array, expected_sequence as u64) {
            Ok(result) => {
                // Convert plaintext bytes to UTF-8 string first
                match String::from_utf8(result.plaintext.clone()) {
                    Ok(plaintext_str) => {
                        // Build result: [evolved_key:32][plaintext_utf8]
                        let plaintext_bytes = plaintext_str.as_bytes();
                        let mut output = Vec::with_capacity(32 + plaintext_bytes.len());
                        output.extend_from_slice(&result.evolved_chain_key);
                        output.extend_from_slice(plaintext_bytes);

                        match vec_to_jbytearray(&mut env, &output) {
                            Ok(arr) => arr.into_raw(),
                            Err(e) => {
                                let _ = env.throw_new("java/lang/RuntimeException", e);
                                std::ptr::null_mut()
                            }
                        }
                    },
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", format!("Invalid UTF-8: {}", e));
                        std::ptr::null_mut()
                    }
                }
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Decryption failed: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Decrypt message using a pre-derived message key (for skipped messages)
/// Wire format: [version:1][sequence:8][nonce:24][ciphertext+tag]
/// This is used for decrypting messages that arrived out-of-order after their key was pre-derived
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptWithMessageKey(
    mut env: JNIEnv,
    _class: JClass,
    ciphertext: JByteArray,
    message_key: JByteArray,
) -> jstring {
    catch_panic!(env, {
        let ciphertext_vec = match jbytearray_to_vec(&mut env, ciphertext) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let message_key_vec = match jbytearray_to_vec(&mut env, message_key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if message_key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Message key must be 32 bytes");
            return std::ptr::null_mut();
        }

        // Wire format: [version:1][sequence:8][nonce:24][ciphertext+tag]
        if ciphertext_vec.len() < 33 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Ciphertext too short");
            return std::ptr::null_mut();
        }

        // Extract nonce (bytes 9-32, after version and sequence)
        let nonce: [u8; 24] = match ciphertext_vec[9..33].try_into() {
            Ok(n) => n,
            Err(_) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid nonce length");
                return std::ptr::null_mut();
            }
        };

        // Ciphertext + tag is everything after nonce
        let encrypted_payload = &ciphertext_vec[33..];

        // Decrypt using XChaCha20-Poly1305
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            XChaCha20Poly1305, XNonce,
        };

        let cipher = XChaCha20Poly1305::new_from_slice(&message_key_vec)
            .map_err(|e| format!("Failed to create cipher: {}", e))
            .unwrap();

        let nonce_obj = XNonce::from_slice(&nonce);

        match cipher.decrypt(nonce_obj, encrypted_payload) {
            Ok(plaintext_bytes) => {
                match String::from_utf8(plaintext_bytes) {
                    Ok(plaintext_str) => {
                        match env.new_string(&plaintext_str) {
                            Ok(jstr) => jstr.into_raw(),
                            Err(e) => {
                                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create Java string: {}", e));
                                std::ptr::null_mut()
                            }
                        }
                    },
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", format!("Invalid UTF-8: {}", e));
                        std::ptr::null_mut()
                    }
                }
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Decryption failed: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== PROTOCOL SECURITY FIXES (FIX #6, #7, #9) ====================

use crate::crypto::encryption::{encrypt_message_deferred, store_pending_ratchet_advancement, commit_ratchet_advancement, rollback_ratchet_advancement};
use crate::crypto::replay_cache::check_ping_replay;
use crate::crypto::ack_state::{validate_and_record_ack, reset_ack_state};

/// FIX #6: Encrypt message with deferred ratchet commitment (Phase 1)
/// Returns JSON: {"ciphertext": "base64", "nextChainKey": "base64", "nextSequence": 123}
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_encryptMessageDeferred(
    mut env: JNIEnv,
    _class: JClass,
    plaintext: JString,
    chain_key_bytes: JByteArray,
    sequence: jlong,
) -> jstring {
    catch_panic!(env, {
        let plaintext_str = match jstring_to_string(&mut env, plaintext) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let chain_key_vec = match jbytearray_to_vec(&mut env, chain_key_bytes) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if chain_key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Chain key must be 32 bytes");
            return std::ptr::null_mut();
        }

        let mut chain_key_array = [0u8; 32];
        chain_key_array.copy_from_slice(&chain_key_vec);

        match encrypt_message_deferred(plaintext_str.as_bytes(), &chain_key_array, sequence as u64) {
            Ok(result) => {
                let json = serde_json::json!({
                    "ciphertext": base64::encode(&result.ciphertext),
                    "nextChainKey": base64::encode(&result.next_chain_key),
                    "nextSequence": result.next_sequence
                });

                match env.new_string(json.to_string()) {
                    Ok(s) => s.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create JSON: {}", e));
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Encryption failed: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// FIX #6: Store pending ratchet advancement (after encryption but before PING_ACK)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_storePendingRatchetAdvancement(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    message_id: JString,
    next_chain_key: JByteArray,
    next_sequence: jlong,
) -> jboolean {
    catch_panic!(env, {
        let contact_id_str = match jstring_to_string(&mut env, contact_id) {
            Ok(s) => s,
            Err(_) => return 0
        };

        let message_id_str = match jstring_to_string(&mut env, message_id) {
            Ok(s) => s,
            Err(_) => return 0
        };

        let chain_key_vec = match jbytearray_to_vec(&mut env, next_chain_key) {
            Ok(v) => v,
            Err(_) => return 0
        };

        if chain_key_vec.len() != 32 {
            return 0;
        }

        let mut chain_key_array = [0u8; 32];
        chain_key_array.copy_from_slice(&chain_key_vec);

        match store_pending_ratchet_advancement(&contact_id_str, &message_id_str, chain_key_array, next_sequence as u64) {
            Ok(_) => 1,
            Err(_) => 0
        }
    }, 0)
}

/// FIX #6: Commit ratchet advancement after PING_ACK received (Phase 2)
/// Returns JSON: {"nextChainKey": "base64", "nextSequence": 123} or null if no pending
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_commitRatchetAdvancement(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
) -> jstring {
    catch_panic!(env, {
        let contact_id_str = match jstring_to_string(&mut env, contact_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        match commit_ratchet_advancement(&contact_id_str) {
            Ok(Some((next_key, next_seq))) => {
                let json = serde_json::json!({
                    "nextChainKey": base64::encode(&next_key),
                    "nextSequence": next_seq
                });

                match env.new_string(json.to_string()) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut()
                }
            }
            Ok(None) => {
                std::ptr::null_mut()
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Commit failed: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// FIX #6: Rollback pending ratchet advancement (if send permanently fails)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_rollbackRatchetAdvancement(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
) -> jboolean {
    catch_panic!(env, {
        let contact_id_str = match jstring_to_string(&mut env, contact_id) {
            Ok(s) => s,
            Err(_) => return 0
        };

        match rollback_ratchet_advancement(&contact_id_str) {
            Ok(_) => 1,
            Err(_) => 0
        }
    }, 0)
}

/// FIX #9: Check if PING is a replay attack
/// Returns true if PING should be processed (not a replay)
/// Returns false if PING is a duplicate (should be dropped)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_checkPingReplay(
    mut env: JNIEnv,
    _class: JClass,
    sender_pubkey: JByteArray,
    ping_bytes: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        let pubkey_vec = match jbytearray_to_vec(&mut env, sender_pubkey) {
            Ok(v) => v,
            Err(_) => return 0
        };

        let ping_vec = match jbytearray_to_vec(&mut env, ping_bytes) {
            Ok(v) => v,
            Err(_) => return 0
        };

        if pubkey_vec.len() != 32 {
            return 0;
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_vec);

        let ping_hash = blake3::hash(&ping_vec);
        let ping_hash_array: [u8; 32] = *ping_hash.as_bytes();

        if check_ping_replay(pubkey, ping_hash_array) {
            1 // Not a replay - process it
        } else {
            0 // Replay detected - drop it
        }
    }, 0)
}

/// FIX #7: Validate ACK ordering according to protocol rules
/// @param contactId Contact identifier
/// @param ackType 0=PING_ACK, 1=PONG_ACK, 2=MESSAGE_ACK
/// @return true if ACK is valid, false if it violates ordering
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_validateAckOrdering(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    ack_type: jint,
) -> jboolean {
    catch_panic!(env, {
        let contact_id_str = match jstring_to_string(&mut env, contact_id) {
            Ok(s) => s,
            Err(_) => return 0
        };

        let ack_type_u8 = match ack_type {
            0 | 1 | 2 => ack_type as u8,
            _ => return 0
        };

        if validate_and_record_ack(&contact_id_str, ack_type_u8) {
            1 // Valid
        } else {
            0 // Invalid
        }
    }, 0)
}

/// FIX #7: Reset ACK state for a contact (after completing message exchange)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_resetAckState(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
) {
    catch_panic!(env, {
        let contact_id_str = match jstring_to_string(&mut env, contact_id) {
            Ok(s) => s,
            Err(_) => return
        };

        reset_ack_state(&contact_id_str);
    }, ())
}

// ==================== END PROTOCOL SECURITY FIXES ====================

// ==================== DELIVERY ACK (CONFIRMATION) ====================

/// Send a delivery ACK (confirmation) to recipient
/// ack_type: "PING_ACK" or "MESSAGE_ACK"
/// item_id: ping_id or message_id being acknowledged
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendDeliveryAck(
    mut env: JNIEnv,
    _class: JClass,
    item_id: JString,
    ack_type: JString,
    recipient_ed25519_pubkey: JByteArray,
    recipient_x25519_pubkey: JByteArray,
    recipient_onion: JString,
) -> jboolean {
    catch_panic!(env, {
        // Convert inputs
        let item_id_str = match jstring_to_string(&mut env, item_id) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert item_id: {}", e);
                return 0;
            }
        };

        let ack_type_str = match jstring_to_string(&mut env, ack_type) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert ack_type: {}", e);
                return 0;
            }
        };

        let recipient_ed25519_bytes = match jbytearray_to_vec(&mut env, recipient_ed25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert recipient Ed25519 pubkey: {}", e);
                return 0;
            }
        };

        let recipient_x25519_bytes = match jbytearray_to_vec(&mut env, recipient_x25519_pubkey) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert recipient X25519 pubkey: {}", e);
                return 0;
            }
        };

        let recipient_onion_str = match jstring_to_string(&mut env, recipient_onion) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert recipient onion: {}", e);
                return 0;
            }
        };

        log::info!("");
        log::info!("SENDING DELIVERY ACK");
        log::info!("Item ID: {}", item_id_str);
        log::info!("ACK Type: {}", ack_type_str);
        log::info!("Recipient: {}", recipient_onion_str);
        log::info!("");

        // Get KeyManager for our keys
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                log::error!("Failed to get context: {}", e);
                return 0;
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                log::error!("Failed to get KeyManager: {}", e);
                return 0;
            }
        };

        // Get our signing private key (Ed25519)
        let our_signing_private = match crate::ffi::keystore::get_signing_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get signing key: {}", e);
                return 0;
            }
        };

        // Create Ed25519 signing keypair
        let sender_keypair = ed25519_dalek::SigningKey::from_bytes(&our_signing_private.as_slice().try_into().unwrap());

        // Create DeliveryAck token (signed)
        let ack_token = match crate::network::pingpong::DeliveryAck::new(
            &item_id_str,
            &ack_type_str,
            &sender_keypair,
        ) {
            Ok(token) => token,
            Err(e) => {
                log::error!("Failed to create ACK: {}", e);
                return 0;
            }
        };

        // Serialize ACK token
        let ack_bytes = match ack_token.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Failed to serialize ACK: {}", e);
                return 0;
            }
        };

        // Get our X25519 encryption keys
        let our_x25519_public = match crate::ffi::keystore::get_encryption_public_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get our X25519 pubkey: {}", e);
                return 0;
            }
        };

        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get encryption key: {}", e);
                return 0;
            }
        };

        // Derive shared secret using X25519 ECDH
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &recipient_x25519_bytes,
        ) {
            Ok(secret) => secret,
            Err(e) => {
                log::error!("ECDH failed: {}", e);
                return 0;
            }
        };

        // Encrypt ACK with shared secret
        let encrypted_ack = match crate::crypto::encryption::encrypt_message(&ack_bytes, &shared_secret) {
            Ok(enc) => enc,
            Err(e) => {
                log::error!("Encryption failed: {}", e);
                return 0;
            }
        };

        // Wire format: [Type Byte 0x06][Our X25519 Public Key - 32 bytes][Encrypted ACK]
        let mut wire_message = Vec::new();
        wire_message.push(crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION);

        let sender_x25519_pubkey: [u8; 32] = match our_x25519_public.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                log::error!("Invalid sender X25519 pubkey size");
                return 0;
            }
        };
        wire_message.extend_from_slice(&sender_x25519_pubkey);
        wire_message.extend_from_slice(&encrypted_ack);

        // Send encrypted ACK via Tor to recipient's port 9153 (ACK listener)
        let tor_manager = get_tor_manager();
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        const ACK_PORT: u16 = 9153;

        let result: Result<(), Box<dyn std::error::Error>> = runtime.block_on(async {
            let manager = tor_manager.lock().unwrap();
            let mut conn = manager.connect(&recipient_onion_str, ACK_PORT).await?;
            manager.send(&mut conn, &wire_message).await?;
            Ok(())
        });

        match result {
            Ok(_) => {
                log::info!("ACK sent successfully: {} for {}", ack_type_str, item_id_str);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to send ACK: {}", e);
                0 // failure
            }
        }
    }, 0)
}

/// Start ACK listener on port 9153
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startAckListener(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
) -> jboolean {
    catch_panic!(env, {
        log::info!("Starting ACK listener on port {}...", port);

        let tor_manager = get_tor_manager();

        // Run async listener start using the global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        });

        match result {
            Ok((mut ping_receiver, _pong_receiver)) => {
                // Create shared channel for ACK messages
                // This channel is accessible from both port 9153 (normal path) and port 8080 (error recovery)
                let (tx, rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();

                // Store receiver globally for polling
                let _ = GLOBAL_ACK_RECEIVER.set(Arc::new(Mutex::new(rx)));

                // Store sender globally so port 8080 can route misrouted ACKs
                let _ = crate::network::tor::ACK_TX.set(Arc::new(std::sync::Mutex::new(tx.clone())));

                // Spawn task to receive from TorManager PING channel and forward to shared ACK channel
                // Note: ACKs should be routed via ACK_TX in tor.rs, not via PING channel
                GLOBAL_RUNTIME.spawn(async move {
                    while let Some((connection_id, ack_bytes)) = ping_receiver.recv().await {
                        log::info!("Received ACK via port 9153 listener: {} bytes", ack_bytes.len());

                        // Forward to shared ACK channel
                        if let Err(e) = tx.send((connection_id, ack_bytes)) {
                            log::error!("Failed to send ACK to shared channel: {}", e);
                            break;
                        }
                    }
                    log::warn!("ACK listener receiver closed");
                });

                log::info!("ACK listener started successfully on port {} with shared channel", port);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to start ACK listener: {}", e);
                0 // failure
            }
        }
    }, 0)
}

/// Poll for an incoming ACK (non-blocking)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingAck(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        if let Some(receiver) = GLOBAL_ACK_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok((_conn_id, ack_bytes)) => {
                    log::info!("Polled ACK: {} bytes", ack_bytes.len());
                    match vec_to_jbytearray(&mut env, &ack_bytes) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No ACK available
                    std::ptr::null_mut()
                }
            }
        } else {
            // Listener not started
            std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Decrypt incoming ACK from listener and store in GLOBAL_ACK_SESSIONS
/// Wire format: [Type byte][Sender X25519 Public Key - 32 bytes][Encrypted ACK]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_decryptAndStoreAckFromListener(
    mut env: JNIEnv,
    _class: JClass,
    ack_wire: JByteArray,
) -> jstring {
    catch_panic!(env, {
        let wire_bytes = match jbytearray_to_vec(&mut env, ack_wire) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to convert ACK wire bytes: {}", e);
                return std::ptr::null_mut();
            }
        };

        // Network-received packets always have type byte at offset 0
        // Wire format: [type_byte][sender_x25519_pubkey (32 bytes)][encrypted_payload]
        const OFFSET: usize = 1; // Skip type byte
        const MIN_LEN: usize = 33; // 1 (type) + 32 (pubkey)

        if wire_bytes.len() < MIN_LEN {
            log::error!("ACK wire too short: actual_len={}, min_required={}", wire_bytes.len(), MIN_LEN);
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (after type byte at offset 1)
        let sender_x25519_pubkey: [u8; 32] = wire_bytes[OFFSET..OFFSET + 32].try_into().unwrap();
        let encrypted_ack = &wire_bytes[OFFSET + 32..];

        log::info!("Decrypting ACK: offset={}, sender_x25519={}, encrypted_len={}",
                   OFFSET, hex::encode(&sender_x25519_pubkey), encrypted_ack.len());

        // Get our X25519 private key from KeyManager
        let context = match env.call_static_method(
            "android/app/ActivityThread",
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) {
            Ok(ctx) => ctx.l().unwrap(),
            Err(e) => {
                log::error!("Failed to get context: {}", e);
                return std::ptr::null_mut();
            }
        };

        let key_manager = match crate::ffi::keystore::get_key_manager(&mut env, &context) {
            Ok(km) => km,
            Err(e) => {
                log::error!("Failed to get KeyManager: {}", e);
                return std::ptr::null_mut();
            }
        };

        let our_x25519_private = match crate::ffi::keystore::get_encryption_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to get encryption private key: {}", e);
                return std::ptr::null_mut();
            }
        };

        // Derive shared secret
        let shared_secret = match crate::crypto::key_exchange::derive_shared_secret(
            &our_x25519_private,
            &sender_x25519_pubkey.to_vec(),
        ) {
            Ok(secret) => secret,
            Err(e) => {
                log::error!("ECDH failed: {}", e);
                return std::ptr::null_mut();
            }
        };

        // Decrypt ACK
        let ack_bytes = match crate::crypto::encryption::decrypt_message(encrypted_ack, &shared_secret) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                log::error!("Decryption failed: {}", e);
                return std::ptr::null_mut();
            }
        };

        // Deserialize ACK
        let ack_token = match crate::network::pingpong::DeliveryAck::from_bytes(&ack_bytes) {
            Ok(token) => token,
            Err(e) => {
                log::error!("Failed to deserialize ACK: {}", e);
                return std::ptr::null_mut();
            }
        };

        let item_id = ack_token.item_id.clone();
        let ack_type = ack_token.ack_type.clone();

        log::info!("RECEIVED DELIVERY ACK: item_id={}, ack_type={}", item_id, ack_type);

        // === Two-tier ACK signature verification ===
        // Tier 1 (fast path): OUTGOING_PING_SIGNERS lookup (same session, pre-PONG-removal)
        // Tier 2 (fallback): Use sender_ed25519_signing_pubkey embedded in the ACK itself
        //   (cross-restart or post-PONG-removal — Kotlin MUST cross-check against contact DB)
        let stored_signer = {
            let signers = OUTGOING_PING_SIGNERS.lock().unwrap();
            signers.get(&item_id).cloned()
        };

        let (signer_bytes, used_fallback) = match stored_signer {
            Some(stored) => {
                log::info!("ACK_VERIFY: Using stored signer (fast path) for {} item_id={}", ack_type, item_id);
                (stored, false)
            },
            None => {
                log::info!("ACK_VERIFY: No stored signer for {} item_id={}, using embedded sender_ed25519_signing_pubkey (fallback path)", ack_type, item_id);
                (ack_token.sender_ed25519_signing_pubkey, true)
            }
        };

        // Verify Ed25519 signature with whichever key we resolved
        match ed25519_dalek::VerifyingKey::from_bytes(&signer_bytes) {
            Ok(verifying_key) => {
                match ack_token.verify(&verifying_key) {
                    Ok(true) => {
                        log::info!("ACK_SIG_OK: {} signature verified for item_id={} (fallback={})", ack_type, item_id, used_fallback);
                    },
                    Ok(false) => {
                        log::error!("ACK_SIG_INVALID: {} signature verification FAILED for item_id={} — dropping", ack_type, item_id);
                        return std::ptr::null_mut();
                    },
                    Err(e) => {
                        log::error!("ACK_SIG_ERROR: {} sig check error for item_id={}: {} — dropping", ack_type, item_id, e);
                        return std::ptr::null_mut();
                    }
                }
            },
            Err(e) => {
                log::error!("ACK_SIG_ERROR: Invalid signer pubkey for item_id={}: {} — dropping", item_id, e);
                return std::ptr::null_mut();
            }
        }

        // Only commit to GLOBAL_ACK_SESSIONS on the trusted fast path.
        // Fallback-verified ACKs must NOT be committed until Kotlin cross-checks
        // the sender's identity against the contact DB.
        let sender_ed25519_hex = hex::encode(&ack_token.sender_ed25519_signing_pubkey);
        if !used_fallback {
            crate::network::pingpong::store_ack_session(&item_id, ack_token);
            log::info!("Stored trusted ACK in GLOBAL_ACK_SESSIONS");
        } else {
            log::info!("Fallback ACK NOT stored — awaiting Kotlin identity cross-check");
        }

        // Return JSON with item_id, ack_type, and fallback verification metadata
        // If fallback was used, Kotlin MUST cross-check sender identity against contact DB
        // before processing the ACK (calling handleIncomingAck)
        let ack_json = if used_fallback {
            format!(
                r#"{{"item_id":"{}","ack_type":"{}","fallback":true,"sender_ed25519":"{}"}}"#,
                item_id, ack_type, sender_ed25519_hex
            )
        } else {
            format!(r#"{{"item_id":"{}","ack_type":"{}","fallback":false}}"#, item_id, ack_type)
        };
        match string_to_jstring(&mut env, &ack_json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
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

// ==================== SESSION CLEANUP ====================

/// Remove Ping session after Pong is sent
/// Call this immediately after successfully sending Pong to prevent memory leak
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_removePingSession(
    mut env: JNIEnv,
    _class: JClass,
    ping_id: JString,
) {
    catch_panic!(env, {
        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert ping_id: {}", e);
                return;
            }
        };

        log::debug!("Removing Ping session: {}", ping_id_str);
        crate::network::remove_ping_session(&ping_id_str);
    }, ())
}

/// Remove Pong session after message blob is sent
/// Call this immediately after successfully sending message to prevent memory leak
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_removePongSession(
    mut env: JNIEnv,
    _class: JClass,
    ping_id: JString,
) {
    catch_panic!(env, {
        let ping_id_str = match jstring_to_string(&mut env, ping_id) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert ping_id: {}", e);
                return;
            }
        };

        log::debug!("Removing Pong session: {}", ping_id_str);
        crate::network::remove_pong_session(&ping_id_str);

        // Decrement session count (track session leaks)
        let old_count = PONG_SESSION_COUNT.fetch_sub(1, Ordering::Relaxed);
        if old_count == 0 {
            log::warn!("Pong session counter underflow detected (already at 0)");
        }
    }, ())
}

/// Remove ACK session after processing
/// Call this immediately after processing ACK to prevent memory leak
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_removeAckSession(
    mut env: JNIEnv,
    _class: JClass,
    item_id: JString,
) {
    catch_panic!(env, {
        let item_id_str = match jstring_to_string(&mut env, item_id) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert item_id: {}", e);
                return;
            }
        };

        log::debug!("Removing ACK session: {}", item_id_str);
        crate::network::remove_ack_session(&item_id_str);
    }, ())
}

/// Clean up expired Ping/Pong/ACK sessions (older than 5 minutes)
/// Call this periodically as a safety net for orphaned entries from crashes
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_cleanupExpiredSessions(
    _env: JNIEnv,
    _class: JClass,
) {
    log::debug!("Cleaning up expired sessions...");
    crate::network::cleanup_expired_pings();
    crate::network::cleanup_expired_pongs();
    crate::network::cleanup_expired_acks();
}

// ==================== NLx402 PAYMENT PROTOCOL ====================

/// Create a payment quote for NLx402 protocol
/// Returns JSON string containing the quote
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_createPaymentQuote(
    mut env: JNIEnv,
    _class: JClass,
    recipient: JString,
    amount: jlong,
    token: JString,
    description: JString,
    sender_handle: JString,
    recipient_handle: JString,
    expiry_secs: jlong,
) -> jstring {
    catch_panic!(env, {
        let recipient_str = match jstring_to_string(&mut env, recipient) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let token_str = match jstring_to_string(&mut env, token) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        // Handle optional parameters (empty string = None)
        let description_opt = match jstring_to_string(&mut env, description) {
            Ok(s) if !s.is_empty() => Some(s),
            _ => None,
        };

        let sender_handle_opt = match jstring_to_string(&mut env, sender_handle) {
            Ok(s) if !s.is_empty() => Some(s),
            _ => None,
        };

        let recipient_handle_opt = match jstring_to_string(&mut env, recipient_handle) {
            Ok(s) if !s.is_empty() => Some(s),
            _ => None,
        };

        // Create the quote with custom expiry
        let quote = match crate::nlx402::create_quote_with_expiry(
            &recipient_str,
            amount as u64,
            &token_str,
            description_opt.as_deref(),
            sender_handle_opt.as_deref(),
            recipient_handle_opt.as_deref(),
            expiry_secs as u64,
        ) {
            Ok(q) => q,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create quote: {}", e));
                return std::ptr::null_mut();
            }
        };

        // Serialize to JSON
        let json = match quote.to_json() {
            Ok(j) => j,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to serialize quote: {}", e));
                return std::ptr::null_mut();
            }
        };

        log::info!("Created payment quote: {} for {} {}", quote.quote_id, amount, token_str);

        match string_to_jstring(&mut env, &json) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Get the memo string for a payment quote (for embedding in transaction)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getQuoteMemo(
    mut env: JNIEnv,
    _class: JClass,
    quote_json: JString,
) -> jstring {
    catch_panic!(env, {
        let json_str = match jstring_to_string(&mut env, quote_json) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let quote = match crate::nlx402::PaymentQuote::from_json(&json_str) {
            Ok(q) => q,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to parse quote: {}", e));
                return std::ptr::null_mut();
            }
        };

        let memo = quote.to_memo();

        match string_to_jstring(&mut env, &memo) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Verify a payment against a quote
/// Returns true if payment is valid (excluding replay check - that's done in Kotlin)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_verifyPayment(
    mut env: JNIEnv,
    _class: JClass,
    quote_json: JString,
    tx_memo: JString,
    tx_amount: jlong,
    tx_recipient: JString,
    tx_token: JString,
) -> jboolean {
    catch_panic!(env, {
        let json_str = match jstring_to_string(&mut env, quote_json) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to get quote_json: {}", e);
                return 0;
            }
        };

        let memo_str = match jstring_to_string(&mut env, tx_memo) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to get tx_memo: {}", e);
                return 0;
            }
        };

        let recipient_str = match jstring_to_string(&mut env, tx_recipient) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to get tx_recipient: {}", e);
                return 0;
            }
        };

        let token_str = match jstring_to_string(&mut env, tx_token) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to get tx_token: {}", e);
                return 0;
            }
        };

        let quote = match crate::nlx402::PaymentQuote::from_json(&json_str) {
            Ok(q) => q,
            Err(e) => {
                log::error!("Failed to parse quote: {}", e);
                return 0;
            }
        };

        // Use simple verification (replay check is done in Kotlin with local DB)
        match crate::nlx402::verify_payment_simple(
            &quote,
            &memo_str,
            tx_amount as u64,
            &recipient_str,
            &token_str,
        ) {
            Ok(_) => {
                log::info!("Payment verified successfully for quote {}", quote.quote_id);
                1
            }
            Err(e) => {
                log::warn!("Payment verification failed: {}", e);
                0
            }
        }
    }, 0)
}

/// Check if a quote has expired
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_isQuoteExpired(
    mut env: JNIEnv,
    _class: JClass,
    quote_json: JString,
) -> jboolean {
    catch_panic!(env, {
        let json_str = match jstring_to_string(&mut env, quote_json) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to get quote_json: {}", e);
                return 1; // Treat as expired if we can't parse
            }
        };

        let quote = match crate::nlx402::PaymentQuote::from_json(&json_str) {
            Ok(q) => q,
            Err(e) => {
                log::error!("Failed to parse quote: {}", e);
                return 1; // Treat as expired if we can't parse
            }
        };

        if quote.is_expired() { 1 } else { 0 }
    }, 1)
}

/// Extract quote hash from a transaction memo
/// Returns empty string if memo is not valid NLx402 format
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_extractQuoteHashFromMemo(
    mut env: JNIEnv,
    _class: JClass,
    memo: JString,
) -> jstring {
    catch_panic!(env, {
        let memo_str = match jstring_to_string(&mut env, memo) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let hash = match crate::nlx402::extract_quote_hash_from_memo(&memo_str) {
            Ok(h) => h,
            Err(_) => String::new(), // Return empty string for invalid memos
        };

        match string_to_jstring(&mut env, &hash) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Get the NLx402 protocol version
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getNLx402Version(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        match string_to_jstring(&mut env, crate::nlx402::PROTOCOL_VERSION) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== v2.0: Friend Request System (Two .onion + IPFS) ====================

/// Create a friend request hidden service (.onion address)
/// Returns the .onion address as a string
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_createFriendRequestHiddenService(
    mut env: JNIEnv,
    _class: JClass,
    service_port: jint,
    local_port: jint,
    directory: JString,
) -> jstring {
    catch_panic!(env, {
        let dir_str = match jstring_to_string(&mut env, directory) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        log::info!("Creating friend request hidden service on port {} -> {}, dir: {}",
            service_port, local_port, dir_str);

        // Get KeyManager to retrieve friend request key
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

        // Get friend request private key (derived from seed with domain separation)
        let fr_private_key = match crate::ffi::keystore::get_friend_request_private_key(&mut env, &key_manager) {
            Ok(k) => k,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get friend request key: {}", e));
                return std::ptr::null_mut();
            }
        };

        let tor_manager = get_tor_manager();

        // Run async hidden service creation with friend request key
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.create_hidden_service(service_port as u16, local_port as u16, &fr_private_key).await
        });

        match result {
            Ok(onion_address) => {
                log::info!("Friend request hidden service created successfully: {}", onion_address);

                match string_to_jstring(&mut env, &onion_address) {
                    Ok(s) => s.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            },
            Err(e) => {
                let error_msg = format!("Failed to create friend request hidden service: {}", e);
                log::error!("{}", error_msg);
                let _ = env.throw_new("java/lang/RuntimeException", error_msg);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Start the contact exchange endpoint on the specified port
/// Returns true if endpoint started successfully
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startFriendRequestServer(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
) -> jboolean {
    catch_panic!(env, {
        log::info!("Starting contact exchange endpoint on port {}", port);

        // Start contact exchange endpoint in background tokio runtime
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let endpoint = crate::network::friend_request_server::get_endpoint().await;
                if let Err(e) = endpoint.start(port as u16).await {
                    log::error!("Failed to start contact exchange endpoint: {}", e);
                } else {
                    log::info!("Contact exchange endpoint started successfully on port {}", port);
                }
            });
        });

        1 // true
    }, 0)
}

/// Stop the contact exchange endpoint
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_stopFriendRequestServer(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        log::info!("Stopping contact exchange endpoint");

        // Stop endpoint in background task
        std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let endpoint = crate::network::friend_request_server::get_endpoint().await;
                endpoint.stop().await;
                log::info!("Contact exchange endpoint stopped");
            });
        });

    }, ())
}

/// Store encrypted contact card to be served at GET /contact-card
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_serveContactCard(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_card: JByteArray,
    card_length: jint,
    cid: JString,
) {
    catch_panic!(env, {
        let card_bytes = match jbytearray_to_vec(&mut env, encrypted_card) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return;
            }
        };

        let cid_str = match jstring_to_string(&mut env, cid) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return;
            }
        };

        log::info!("Storing encrypted contact card (CID: {}, length: {})", cid_str, card_length);

        // Store card in endpoint state
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let endpoint = crate::network::friend_request_server::get_endpoint().await;
                endpoint.set_contact_card(card_bytes, cid_str).await;
                log::info!("Contact card stored in contact exchange endpoint");
            });
        });

    }, ())
}

/// Serve contact list on the contact exchange endpoint (v5 architecture)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_serveContactList(
    mut env: JNIEnv,
    _class: JClass,
    cid: JString,
    encrypted_list: JByteArray,
    list_length: jint,
) {
    catch_panic!(env, {
        let cid_str = match jstring_to_string(&mut env, cid) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return;
            }
        };

        let list_bytes = match jbytearray_to_vec(&mut env, encrypted_list) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return;
            }
        };

        log::info!("Storing encrypted contact list (CID: {}, length: {})", cid_str, list_length);

        // Store contact list in endpoint state
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let endpoint = crate::network::friend_request_server::get_endpoint().await;
                endpoint.set_contact_list(cid_str, list_bytes).await;
                log::info!("Contact list stored in contact exchange endpoint");
            });
        });

    }, ())
}

/// Poll for incoming friend requests (non-blocking)
/// Returns raw encrypted bytes (0x07 or 0x08 wire protocol messages)
/// Kotlin will handle decryption based on message type
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollFriendRequest(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        if let Some(receiver) = GLOBAL_FRIEND_REQUEST_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok(friend_request_bytes) => {
                    log::info!("Polled friend request: {} bytes", friend_request_bytes.len());
                    match vec_to_jbytearray(&mut env, &friend_request_bytes) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No friend request available
                    std::ptr::null_mut()
                }
            }
        } else {
            // Listener not started
            std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Poll for friend request responses (non-blocking)
/// Returns JSON string with response data, or null if no responses
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollFriendResponse(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        log::debug!("Polling for friend request responses");

        // Poll for response in blocking fashion
        let result = std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let endpoint = crate::network::friend_request_server::get_endpoint().await;
                endpoint.poll_response().await
            })
        }).join();

        match result {
            Ok(Some(response)) => {
                // Convert to JSON
                let json = format!(
                    r#"{{"approved":{},"encryptedCard":"{}","timestamp":{}}}"#,
                    response.approved,
                    base64::encode(&response.encrypted_card),
                    response.timestamp
                );

                match string_to_jstring(&mut env, &json) {
                    Ok(s) => s.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            _ => std::ptr::null_mut()
        }
    }, std::ptr::null_mut())
}

/// Make HTTP GET request via Tor SOCKS5 proxy
/// Returns response body or null on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_httpGetViaTor(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
) -> jstring {
    catch_panic!(env, {
        let url_str = match jstring_to_string(&mut env, url) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        log::info!("HTTP GET via Tor: {}", url_str);

        // Create SOCKS5 client and make request
        let client = crate::network::Socks5Client::tor_default();

        match client.http_get(&url_str) {
            Ok(response) => {
                // Extract body from response
                if let Some(body) = crate::network::socks5_client::extract_http_body(&response) {
                    match string_to_jstring(&mut env, &body) {
                        Ok(s) => {
                            log::info!("HTTP GET successful ({} bytes)", body.len());
                            s.into_raw()
                        }
                        Err(e) => {
                            let _ = env.throw_new("java/lang/RuntimeException", e);
                            std::ptr::null_mut()
                        }
                    }
                } else {
                    // Return full response if can't extract body
                    match string_to_jstring(&mut env, &response) {
                        Ok(s) => s.into_raw(),
                        Err(e) => {
                            let _ = env.throw_new("java/lang/RuntimeException", e);
                            std::ptr::null_mut()
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("HTTP GET via Tor failed: {}", e);
                let error_msg = format!("HTTP GET failed: {}", e);
                let _ = env.throw_new("java/io/IOException", &error_msg);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Make HTTP POST request via Tor SOCKS5 proxy
/// Returns response body or null on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_httpPostViaTor(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
    body: JString,
) -> jstring {
    catch_panic!(env, {
        let url_str = match jstring_to_string(&mut env, url) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let body_str = match jstring_to_string(&mut env, body) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        log::info!("HTTP POST via Tor: {} (body length: {})", url_str, body_str.len());

        // Create SOCKS5 client and make request
        let client = crate::network::Socks5Client::tor_default();

        // Use application/json as default content type
        match client.http_post(&url_str, &body_str, "application/json") {
            Ok(response) => {
                // Extract body from response
                if let Some(body) = crate::network::socks5_client::extract_http_body(&response) {
                    match string_to_jstring(&mut env, &body) {
                        Ok(s) => {
                            log::info!("HTTP POST successful ({} bytes)", body.len());
                            s.into_raw()
                        }
                        Err(e) => {
                            let _ = env.throw_new("java/lang/RuntimeException", e);
                            std::ptr::null_mut()
                        }
                    }
                } else {
                    // Return full response if can't extract body
                    match string_to_jstring(&mut env, &response) {
                        Ok(s) => s.into_raw(),
                        Err(e) => {
                            let _ = env.throw_new("java/lang/RuntimeException", e);
                            std::ptr::null_mut()
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("HTTP POST via Tor failed: {}", e);
                let error_msg = format!("HTTP POST failed: {}", e);
                let _ = env.throw_new("java/io/IOException", &error_msg);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== Push Recovery (v5 Contact List Mesh) ====================

/// Enable recovery mode on the contact exchange endpoint.
/// Called by Kotlin after seed restore when contacts weren't found locally.
/// Rust will accept POST /recovery/push/{cid} and write the blob to disk.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_setRecoveryMode(
    mut env: JNIEnv,
    _class: JClass,
    enabled: jboolean,
    expected_cid: JString,
    data_dir: JString,
) {
    catch_panic!(env, {
        let enabled = enabled != 0;

        let cid_str = if enabled {
            match jstring_to_string(&mut env, expected_cid) {
                Ok(s) if !s.is_empty() => Some(s),
                _ => None,
            }
        } else {
            None
        };

        let dir_str = if enabled {
            match jstring_to_string(&mut env, data_dir) {
                Ok(s) if !s.is_empty() => Some(s),
                _ => None,
            }
        } else {
            None
        };

        log::info!("setRecoveryMode: enabled={}, has_cid={}, has_dir={}",
            enabled, cid_str.is_some(), dir_str.is_some());

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let endpoint = crate::network::friend_request_server::get_endpoint().await;
                endpoint.set_recovery_mode(enabled, cid_str, dir_str).await;
            });
        });

    }, ())
}

/// Clear recovery mode after contacts have been successfully imported.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_clearRecoveryMode(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        log::info!("clearRecoveryMode called");

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let endpoint = crate::network::friend_request_server::get_endpoint().await;
                endpoint.clear_recovery_mode().await;
            });
        });

    }, ())
}

/// Poll whether a recovery blob has been written to disk by a friend's push.
/// Returns true if Kotlin should call recoverFromIPFS() to try importing contacts.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollRecoveryReady(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    catch_panic!(env, {
        // Use a short-lived runtime to check the async state
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(_) => return 0,
        };

        let ready = rt.block_on(async {
            let endpoint = crate::network::friend_request_server::get_endpoint().await;
            endpoint.is_recovery_ready().await
        });

        if ready { 1 } else { 0 }
    }, 0)
}

/// POST raw binary data to a URL via Tor SOCKS5 proxy.
/// Used by the friend side to push the encrypted contact list blob.
/// Returns response body as String, or null on error.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_httpPostBinaryViaTor(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
    data: JByteArray,
) -> jstring {
    catch_panic!(env, {
        let url_str = match jstring_to_string(&mut env, url) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        let data_bytes = match jbytearray_to_vec(&mut env, data) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", e);
                return std::ptr::null_mut();
            }
        };

        log::info!("HTTP POST binary via Tor: {} ({} bytes)", url_str, data_bytes.len());

        let client = crate::network::Socks5Client::tor_default();

        match client.http_post_binary(&url_str, &data_bytes, "application/octet-stream") {
            Ok(response) => {
                if let Some(body) = crate::network::socks5_client::extract_http_body(&response) {
                    match string_to_jstring(&mut env, &body) {
                        Ok(s) => {
                            log::info!("HTTP POST binary successful ({} bytes response)", body.len());
                            s.into_raw()
                        }
                        Err(e) => {
                            let _ = env.throw_new("java/lang/RuntimeException", e);
                            std::ptr::null_mut()
                        }
                    }
                } else {
                    match string_to_jstring(&mut env, &response) {
                        Ok(s) => s.into_raw(),
                        Err(e) => {
                            let _ = env.throw_new("java/lang/RuntimeException", e);
                            std::ptr::null_mut()
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("HTTP POST binary via Tor failed: {}", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== END Push Recovery ====================

// ==================== END v2.0: Friend Request System ====================

// ==================== v2.0: Voice Streaming ====================

/// Register voice packet callback handler (v2.0)
/// Must be called before startVoiceStreamingServer
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_setVoicePacketCallback(
    mut env: JNIEnv,
    _class: JClass,
    callback: JObject,
) {
    catch_panic!(env, {
        // Create global reference to callback object
        let global_callback = env.new_global_ref(callback)
            .expect("Failed to create global reference to voice callback");

        // Store in global
        let callback_storage = GLOBAL_VOICE_CALLBACK.get_or_init(|| Mutex::new(None));
        *callback_storage.lock().unwrap() = Some(global_callback);

        log::info!("Voice packet callback registered");
    }, ())
}

/// Register voice signaling callback handler (v2.0)
/// Handles incoming signaling messages (CALL_OFFER, CALL_ANSWER, etc) over voice onion HTTP
/// Must be called before startVoiceStreamingServer
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_setVoiceSignalingCallback(
    mut env: JNIEnv,
    _class: JClass,
    callback: JObject,
) {
    catch_panic!(env, {
        // Create global reference to callback object
        let global_callback = env.new_global_ref(callback)
            .expect("Failed to create global reference to voice signaling callback");

        // Store in global
        let callback_storage = GLOBAL_VOICE_SIGNALING_CALLBACK.get_or_init(|| Mutex::new(None));
        *callback_storage.lock().unwrap() = Some(global_callback);

        log::info!("Voice signaling callback registered");
    }, ())
}

/// Start voice streaming listener on port 9152 (v2.0)
/// Must be called before accepting or creating voice sessions
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startVoiceStreamingServer(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        let voice_listener = get_voice_listener();

        // Get JavaVM for callback invocations (get twice since JavaVM doesn't implement Clone)
        let jvm_audio = env.get_java_vm().expect("Failed to get JavaVM");
        let jvm_signaling = env.get_java_vm().expect("Failed to get JavaVM");

        // Start listener in background task
        GLOBAL_RUNTIME.spawn(async move {
            // Set audio callback (must be done before starting listener)
            {
                let mut listener = voice_listener.lock().await;
                listener.set_audio_callback(move |call_id: String, packet: crate::audio::voice_streaming::VoicePacket| {
                // Get JNI environment (attach thread if needed)
                let mut env = match jvm_audio.attach_current_thread() {
                    Ok(env) => env,
                    Err(e) => {
                        log::error!("Failed to attach thread for voice callback: {}", e);
                        return;
                    }
                };

                // Get callback object
                let callback_storage = GLOBAL_VOICE_CALLBACK.get().unwrap();
                let callback_lock = callback_storage.lock().unwrap();

                if let Some(ref callback_ref) = *callback_lock {
                    let callback_obj = callback_ref.as_obj();

                    // Convert call_id to JString
                    let call_id_jstring: JString = match env.new_string(&call_id) {
                        Ok(s) => s,
                        Err(e) => {
                            log::error!("Failed to create call_id JString: {}", e);
                            return;
                        }
                    };

                    // Convert audio_data to JByteArray
                    let audio_data_array: JByteArray = match env.byte_array_from_slice(&packet.audio_data) {
                        Ok(arr) => arr,
                        Err(e) => {
                            log::error!("Failed to create audio data byte array: {}", e);
                            return;
                        }
                    };

                    // Call onVoicePacket(callId: String, sequence: Int, timestamp: Long, circuitIndex: Byte, ptype: Byte, audioData: ByteArray)
                    let result = env.call_method(
                        callback_obj,
                        "onVoicePacket",
                        "(Ljava/lang/String;IJBB[B)V",
                        &[
                            (&call_id_jstring).into(),
                            (packet.sequence as i32).into(),
                            (packet.timestamp as i64).into(),
                            (packet.circuit_index as i8).into(),
                            (packet.ptype as i8).into(),
                            (&audio_data_array).into(),
                        ],
                    );

                    if let Err(e) = result {
                        log::error!("Failed to invoke voice packet callback: {}", e);
                    }
                } else {
                    log::warn!("Voice packet received but no callback registered");
                }
                });

                // Set signaling callback for HTTP POST messages (CALL_OFFER, CALL_ANSWER, etc)
                listener.set_signaling_callback(move |sender_pubkey: Vec<u8>, wire_message: Vec<u8>| {
                    // Get JNI environment (attach thread if needed)
                    let mut env = match jvm_signaling.attach_current_thread() {
                        Ok(env) => env,
                        Err(e) => {
                            log::error!("Failed to attach thread for signaling callback: {}", e);
                            return;
                        }
                    };

                    // Get callback object
                    let callback_storage = GLOBAL_VOICE_SIGNALING_CALLBACK.get().unwrap();
                    let callback_lock = callback_storage.lock().unwrap();

                    if let Some(ref callback_ref) = *callback_lock {
                        let callback_obj = callback_ref.as_obj();

                        // Convert sender_pubkey to JByteArray
                        let sender_pubkey_array: JByteArray = match env.byte_array_from_slice(&sender_pubkey) {
                            Ok(arr) => arr,
                            Err(e) => {
                                log::error!("Failed to create sender pubkey byte array: {}", e);
                                return;
                            }
                        };

                        // Convert wire_message to JByteArray
                        let wire_message_array: JByteArray = match env.byte_array_from_slice(&wire_message) {
                            Ok(arr) => arr,
                            Err(e) => {
                                log::error!("Failed to create wire message byte array: {}", e);
                                return;
                            }
                        };

                        // Call onSignalingMessage(senderPubkey: ByteArray, wireMessage: ByteArray)
                        let result = env.call_method(
                            callback_obj,
                            "onSignalingMessage",
                            "([B[B)V",
                            &[
                                (&sender_pubkey_array).into(),
                                (&wire_message_array).into(),
                            ],
                        );

                        if let Err(e) = result {
                            log::error!("Failed to invoke voice signaling callback: {}", e);
                        } else {
                            log::info!("Voice signaling callback invoked successfully");
                        }
                    } else {
                        log::warn!("Voice signaling message received but no callback registered");
                    }
                });
            } // Drop MutexGuard here

            // Start listener
            if let Err(e) = voice_listener.lock().await.start().await {
                log::error!("Failed to start voice streaming listener: {}", e);
                return;
            }

            log::info!("Voice streaming listener started on port 9152");

            // Note: start() now spawns its own accept task internally,
            // so we don't need to do anything else here
        });
    }, ())
}

/// Create outgoing voice session to peer's voice .onion (v2.0)
/// Connects to peer's voice hidden service on port 9152 with multiple circuits
/// @param num_circuits Number of parallel Tor circuits to create (typically 3)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_createVoiceSession(
    mut env: JNIEnv,
    _class: JClass,
    call_id: JString,
    peer_voice_onion: JString,
    num_circuits: jint,
) -> jboolean {
    catch_panic!(env, {
        let call_id_str = match jstring_to_string(&mut env, call_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        let peer_onion_str = match jstring_to_string(&mut env, peer_voice_onion) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        let num_circuits_usize = num_circuits as usize;
        log::info!("Creating voice session with {} circuits for call: {} to {}",
                   num_circuits_usize, call_id_str, peer_onion_str);

        let voice_listener = get_voice_listener();

        // Create session using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut listener = voice_listener.lock().await;
            listener.create_session(call_id_str.clone(), &peer_onion_str, num_circuits_usize).await
        });

        match result {
            Ok(_) => {
                log::info!("Voice session with {} circuits created for call: {}", num_circuits_usize, call_id_str);
                1
            }
            Err(e) => {
                log::error!("Failed to create voice session: {}", e);
                let error_msg = format!("Voice session creation failed: {}", e);
                let _ = env.throw_new("java/io/IOException", &error_msg);
                0
            }
        }
    }, 0)
}

/// Send audio packet to peer in active voice session on specific circuit (v2.0)
/// Audio data should be Opus-encoded
/// @param circuit_index Which circuit to use (0 to num_circuits-1)
/// @param ptype Packet type (0x01=AUDIO, 0x02=CONTROL)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_sendAudioPacket(
    mut env: JNIEnv,
    _class: JClass,
    call_id: JString,
    sequence: jint,
    timestamp: jlong,
    audio_data: JByteArray,
    circuit_index: jint,
    ptype: jint,
) -> jboolean {
    catch_panic!(env, {
        let call_id_str = match jstring_to_string(&mut env, call_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        let audio_bytes = match jbytearray_to_vec(&mut env, audio_data) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return 0;
            }
        };

        let packet = VoicePacket {
            sequence: sequence as u32,
            timestamp: timestamp as u64,
            audio_data: audio_bytes,
            circuit_index: circuit_index as u8,
            ptype: ptype as u8,
            redundant_audio_data: Vec::new(), // Phase 3: Will be populated by sender task
            redundant_sequence: 0, // Phase 3: Will be populated by sender task
        };

        let voice_listener = get_voice_listener();
        let listener = voice_listener.blocking_lock();

        match listener.send_audio(&call_id_str, circuit_index as usize, packet) {
            Ok(_) => 1,
            Err(e) => {
                log::warn!("Failed to send audio packet for call {} on circuit {}: {}", call_id_str, circuit_index, e);
                0
            }
        }
    }, 0)
}

/// End voice session and close connection (v2.0)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_endVoiceSession(
    mut env: JNIEnv,
    _class: JClass,
    call_id: JString,
) {
    catch_panic!(env, {
        let call_id_str = match jstring_to_string(&mut env, call_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return;
            }
        };

        log::info!("Ending voice session for call: {}", call_id_str);

        let voice_listener = get_voice_listener();
        let listener = voice_listener.blocking_lock();
        listener.end_session(&call_id_str);
    }, ())
}

/// Get number of active voice sessions (v2.0)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getActiveVoiceSessions(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let voice_listener = get_voice_listener();
    let listener = voice_listener.blocking_lock();
    listener.active_sessions() as jint
}

/// Rebuild a specific voice circuit (close and reconnect with fresh Tor path)
/// Tor daemon will automatically pick a different relay path via SOCKS5 isolation
/// @param call_id Active call session ID
/// @param circuit_index Circuit to rebuild (0-2)
/// @param rebuild_epoch Incremented counter (forces fresh SOCKS5 isolation)
/// @return true if rebuild succeeded, false if failed
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_rebuildVoiceCircuit(
    mut env: JNIEnv,
    _class: JClass,
    call_id: JString,
    circuit_index: jint,
    rebuild_epoch: jint,
) -> jboolean {
    catch_panic!(env, {
        let call_id_str = match jstring_to_string(&mut env, call_id) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to convert call_id: {}", e);
                return 0;
            }
        };

        log::warn!("Rebuilding voice circuit {} for call {} (rebuild_epoch={})", circuit_index, call_id_str, rebuild_epoch);

        // Rebuild circuit via async runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let voice_listener = get_voice_listener();
            let mut listener = voice_listener.lock().await;

            listener.rebuild_circuit(&call_id_str, circuit_index as usize, rebuild_epoch as u32).await
        });

        match result {
            Ok(_) => {
                log::info!("Circuit {} rebuild SUCCESS for call {}", circuit_index, call_id_str);
                1 // success
            }
            Err(e) => {
                log::error!("Circuit {} rebuild FAILED for call {}: {}", circuit_index, call_id_str, e);
                0 // failure
            }
        }
    }, 0)
}

// ==================== STRESS TEST & DEBUG METRICS FFI ====================

/// Get all debug counters as JSON string
/// Returns: {"blobFailSocksTimeout": 5, "blobFailConnectErr": 2, ...}
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getDebugCountersJson(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        let json = format!(
            r#"{{"blobFailSocksTimeout":{},"blobFailConnectErr":{},"blobFailTorNotReady":{},"blobFailWriteErr":{},"blobFailUnknown":{},"rxMessageAcceptCount":{},"rxMessageTxDropCount":{},"listenerBindCount":{},"listenerReplacedCount":{},"lastListenerPort":{},"pongSessionCount":{}}}"#,
            BLOB_FAIL_SOCKS_TIMEOUT.load(Ordering::Relaxed),
            BLOB_FAIL_CONNECT_ERR.load(Ordering::Relaxed),
            BLOB_FAIL_TOR_NOT_READY.load(Ordering::Relaxed),
            BLOB_FAIL_WRITE_ERR.load(Ordering::Relaxed),
            BLOB_FAIL_UNKNOWN.load(Ordering::Relaxed),
            RX_MESSAGE_ACCEPT_COUNT.load(Ordering::Relaxed),
            RX_MESSAGE_TX_DROP_COUNT.load(Ordering::Relaxed),
            LISTENER_BIND_COUNT.load(Ordering::Relaxed),
            LISTENER_REPLACED_COUNT.load(Ordering::Relaxed),
            LAST_LISTENER_PORT.load(Ordering::Relaxed),
            PONG_SESSION_COUNT.load(Ordering::Relaxed),
        );

        match string_to_jstring(&mut env, &json) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                log::error!("Failed to create JSON string: {}", e);
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Reset all debug counters (dev-only, for fast iteration)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_resetDebugCounters(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        BLOB_FAIL_SOCKS_TIMEOUT.store(0, Ordering::Relaxed);
        BLOB_FAIL_CONNECT_ERR.store(0, Ordering::Relaxed);
        BLOB_FAIL_TOR_NOT_READY.store(0, Ordering::Relaxed);
        BLOB_FAIL_WRITE_ERR.store(0, Ordering::Relaxed);
        BLOB_FAIL_UNKNOWN.store(0, Ordering::Relaxed);
        RX_MESSAGE_ACCEPT_COUNT.store(0, Ordering::Relaxed);
        RX_MESSAGE_TX_DROP_COUNT.store(0, Ordering::Relaxed);
        LISTENER_BIND_COUNT.store(0, Ordering::Relaxed);
        LISTENER_REPLACED_COUNT.store(0, Ordering::Relaxed);
        // Note: Don't reset LAST_LISTENER_PORT or PONG_SESSION_COUNT (current state, not counters)

        log::info!("Debug counters reset");
    }, ())
}

/// Get current Pong session count (session leak detector)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getPongSessionCount(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    catch_panic!(env, {
        PONG_SESSION_COUNT.load(Ordering::Relaxed) as jlong
    }, 0)
}

/// Get listener replaced count (thrashing indicator)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getListenerReplacedCount(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    catch_panic!(env, {
        LISTENER_REPLACED_COUNT.load(Ordering::Relaxed) as jlong
    }, 0)
}

/// Get MESSAGE_TX drop count (initialization race indicator)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getMessageTxDropCount(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    catch_panic!(env, {
        RX_MESSAGE_TX_DROP_COUNT.load(Ordering::Relaxed) as jlong
    }, 0)
}

// ==================== END v2.0: Voice Streaming ====================

// ==================== ZK Range Proofs ====================

/// Helper to cast &[u8] to &[i8] for JNI byte arrays
fn bytemuck_cast_slice(bytes: &[u8]) -> &[i8] {
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const i8, bytes.len()) }
}

/// Generate a Bulletproof range proof for private transfers
/// Returns: [4-byte proof_len (big-endian)][proof_bytes][32-byte commitment][32-byte blinding_factor]
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_generateRangeProof(
    mut env: JNIEnv,
    _class: JClass,
    amount: jlong,
    bit_length: jint,
) -> jbyteArray {
    catch_panic!(env, {
        use crate::crypto::zkproofs::generate_range_proof;

        let amount_u64 = amount as u64;
        let bit_len = bit_length as usize;

        match generate_range_proof(amount_u64, bit_len) {
            Ok((proof_bytes, commitment, blinding)) => {
                // Pack: [4-byte proof_len BE][proof_bytes][32-byte commitment][32-byte blinding]
                let proof_len = proof_bytes.len() as u32;
                let total_len = 4 + proof_bytes.len() + 32 + 32;
                let mut result = Vec::with_capacity(total_len);
                result.extend_from_slice(&proof_len.to_be_bytes());
                result.extend_from_slice(&proof_bytes);
                result.extend_from_slice(&commitment);
                result.extend_from_slice(&blinding);

                let output = env.new_byte_array(result.len() as i32)
                    .expect("Failed to create byte array");
                env.set_byte_array_region(&output, 0, bytemuck_cast_slice(&result))
                    .expect("Failed to set byte array");
                output.into_raw()
            }
            Err(e) => {
                log::error!("generateRangeProof failed: {}", e);
                env.throw_new("java/lang/RuntimeException", &e)
                    .expect("Failed to throw exception");
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

/// Verify a Bulletproof range proof
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_verifyRangeProof(
    mut env: JNIEnv,
    _class: JClass,
    proof_bytes: JByteArray,
    commitment_bytes: JByteArray,
    bit_length: jint,
) -> jboolean {
    catch_panic!(env, {
        use crate::crypto::zkproofs::verify_range_proof;

        let proof = env.convert_byte_array(&proof_bytes)
            .expect("Failed to read proof bytes");
        let commitment_vec = env.convert_byte_array(&commitment_bytes)
            .expect("Failed to read commitment bytes");

        if commitment_vec.len() != 32 {
            log::error!("verifyRangeProof: commitment must be 32 bytes, got {}", commitment_vec.len());
            return JNI_FALSE;
        }

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&commitment_vec);

        match verify_range_proof(&proof, &commitment, bit_length as usize) {
            Ok(true) => JNI_TRUE,
            Ok(false) => JNI_FALSE,
            Err(e) => {
                log::warn!("verifyRangeProof failed: {}", e);
                JNI_FALSE
            }
        }
    }, JNI_FALSE)
}

// ==================== END ZK Range Proofs ====================

// ==================== XChaCha20-Poly1305 Symmetric Encryption ====================
// Used by CRDT group messages: encrypt/decrypt with shared group secret.

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_xchacha20Encrypt(
    mut env: JNIEnv,
    _class: JClass,
    plaintext: JByteArray,
    key: JByteArray,
    nonce: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};

        let plaintext_vec = match jbytearray_to_vec(&mut env, plaintext) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };
        let key_vec = match jbytearray_to_vec(&mut env, key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };
        let nonce_vec = match jbytearray_to_vec(&mut env, nonce) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException",
                format!("Key must be 32 bytes, got {}", key_vec.len()));
            return std::ptr::null_mut();
        }
        if nonce_vec.len() != 24 {
            let _ = env.throw_new("java/lang/IllegalArgumentException",
                format!("Nonce must be 24 bytes, got {}", nonce_vec.len()));
            return std::ptr::null_mut();
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&key_vec)
            .expect("Invalid key length");
        let nonce_obj = XNonce::from_slice(&nonce_vec);

        match cipher.encrypt(nonce_obj, plaintext_vec.as_ref()) {
            Ok(ciphertext) => {
                match vec_to_jbytearray(&mut env, &ciphertext) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException",
                    format!("XChaCha20 encryption failed: {}", e));
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_xchacha20Decrypt(
    mut env: JNIEnv,
    _class: JClass,
    ciphertext: JByteArray,
    key: JByteArray,
    nonce: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};

        let ciphertext_vec = match jbytearray_to_vec(&mut env, ciphertext) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };
        let key_vec = match jbytearray_to_vec(&mut env, key) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };
        let nonce_vec = match jbytearray_to_vec(&mut env, nonce) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", e);
                return std::ptr::null_mut();
            }
        };

        if key_vec.len() != 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException",
                format!("Key must be 32 bytes, got {}", key_vec.len()));
            return std::ptr::null_mut();
        }
        if nonce_vec.len() != 24 {
            let _ = env.throw_new("java/lang/IllegalArgumentException",
                format!("Nonce must be 24 bytes, got {}", nonce_vec.len()));
            return std::ptr::null_mut();
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&key_vec)
            .expect("Invalid key length");
        let nonce_obj = XNonce::from_slice(&nonce_vec);

        match cipher.decrypt(nonce_obj, ciphertext_vec.as_ref()) {
            Ok(plaintext) => {
                match vec_to_jbytearray(&mut env, &plaintext) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        let _ = env.throw_new("java/lang/RuntimeException", e);
                        std::ptr::null_mut()
                    }
                }
            }
            Err(_) => {
                // Authentication failure — return null (not an exception)
                std::ptr::null_mut()
            }
        }
    }, std::ptr::null_mut())
}

// ==================== END XChaCha20-Poly1305 ====================

// ==================== BLOCKING POLL JNI FUNCTIONS ====================
// These block the JNI thread for up to 5 seconds waiting for data.
// Used by Kotlin poller coroutines on Dispatchers.IO for zero-latency message receipt.

/// Blocking poll for incoming Ping (blocks up to 5s)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingPingBlocking(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        match blocking_recv_pair(&GLOBAL_PING_RECEIVER, 5) {
            Some((connection_id, ping_bytes)) => {
                if ping_bytes.is_empty() {
                    log::error!("FRAMING_VIOLATION: pollIncomingPingBlocking got empty buffer, conn_id={}", connection_id);
                    return std::ptr::null_mut();
                }
                const MSG_TYPE_PING: u8 = 0x01;
                if ping_bytes[0] != MSG_TYPE_PING {
                    let head_hex: String = ping_bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                    log::error!("FRAMING_VIOLATION: pollIncomingPingBlocking got type=0x{:02x} expected=0x{:02x} conn_id={} len={} head={}",
                        ping_bytes[0], MSG_TYPE_PING, connection_id, ping_bytes.len(), head_hex);
                    return std::ptr::null_mut();
                }
                let mut encoded = Vec::new();
                encoded.extend_from_slice(&connection_id.to_le_bytes());
                encoded.extend_from_slice(&ping_bytes);
                match vec_to_jbytearray(&mut env, &encoded) {
                    Ok(array) => array.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Blocking poll for incoming MESSAGE (blocks up to 5s)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingMessageBlocking(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        match blocking_recv_pair(&GLOBAL_MESSAGE_RECEIVER, 5) {
            Some((connection_id, message_bytes)) => {
                let mut encoded = Vec::new();
                encoded.extend_from_slice(&connection_id.to_le_bytes());
                encoded.extend_from_slice(&message_bytes);
                match vec_to_jbytearray(&mut env, &encoded) {
                    Ok(array) => array.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Blocking poll for incoming VOICE signaling (blocks up to 5s)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollVoiceMessageBlocking(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        match blocking_recv_pair(&GLOBAL_VOICE_RECEIVER, 5) {
            Some((connection_id, message_bytes)) => {
                let mut encoded = Vec::new();
                encoded.extend_from_slice(&connection_id.to_le_bytes());
                encoded.extend_from_slice(&message_bytes);
                match vec_to_jbytearray(&mut env, &encoded) {
                    Ok(array) => array.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Blocking poll for incoming Tap (blocks up to 5s)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingTapBlocking(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        match blocking_recv_vec(&GLOBAL_TAP_RECEIVER, 5) {
            Some(tap_bytes) => {
                log::info!("Polled tap (blocking): {} bytes", tap_bytes.len());
                match vec_to_jbytearray(&mut env, &tap_bytes) {
                    Ok(array) => array.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Blocking poll for incoming Pong (blocks up to 5s)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingPongBlocking(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        match blocking_recv_pair(&GLOBAL_PONG_RECEIVER, 5) {
            Some((conn_id, pong_bytes)) => {
                if pong_bytes.is_empty() {
                    log::error!("FRAMING_VIOLATION: pollIncomingPongBlocking got empty buffer, conn_id={}", conn_id);
                    return std::ptr::null_mut();
                }
                const MSG_TYPE_PONG: u8 = 0x02;
                if pong_bytes[0] != MSG_TYPE_PONG {
                    let head_hex: String = pong_bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                    log::error!("FRAMING_VIOLATION: pollIncomingPongBlocking got type=0x{:02x} expected=0x{:02x} conn_id={} len={} head={}",
                        pong_bytes[0], MSG_TYPE_PONG, conn_id, pong_bytes.len(), head_hex);
                    return std::ptr::null_mut();
                }
                log::info!("POLL_BLOCKING: got pong len={} conn={}", pong_bytes.len(), conn_id);
                match vec_to_jbytearray(&mut env, &pong_bytes) {
                    Ok(array) => array.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Blocking poll for incoming ACK (blocks up to 5s)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingAckBlocking(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        match blocking_recv_pair(&GLOBAL_ACK_RECEIVER, 5) {
            Some((_conn_id, ack_bytes)) => {
                log::info!("Polled ACK (blocking): {} bytes", ack_bytes.len());
                match vec_to_jbytearray(&mut env, &ack_bytes) {
                    Ok(array) => array.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

/// Blocking poll for incoming friend requests (blocks up to 5s)
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollFriendRequestBlocking(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        match blocking_recv_vec(&GLOBAL_FRIEND_REQUEST_RECEIVER, 5) {
            Some(friend_request_bytes) => {
                log::info!("Polled friend request (blocking): {} bytes", friend_request_bytes.len());
                match vec_to_jbytearray(&mut env, &friend_request_bytes) {
                    Ok(array) => array.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}
