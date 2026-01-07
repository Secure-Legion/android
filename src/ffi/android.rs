use jni::objects::{JByteArray, JClass, JObject, JString, GlobalRef};
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jlong, jstring, jobjectArray};
use jni::JNIEnv;
use std::panic;
use std::sync::{Arc, Mutex};
use once_cell::sync::{OnceCell, Lazy};
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::crypto::{
    decrypt_message, encrypt_message, generate_keypair, hash_handle, hash_password, sign_data,
    verify_signature, derive_root_key, evolve_chain_key, derive_message_key,
    encrypt_message_with_evolution, decrypt_message_with_evolution,
};
use crate::network::{TorManager, PENDING_CONNECTIONS};
use crate::protocol::ContactCard;
use crate::blockchain::{register_username, lookup_username};
use crate::audio::voice_streaming::{VoiceStreamingListener, VoicePacket};
use tokio::sync::{mpsc, oneshot};
use tokio::io::AsyncReadExt;

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

// ==================== GLOBAL TOR MANAGER ====================

/// Global TorManager instance
static GLOBAL_TOR_MANAGER: OnceCell<Arc<Mutex<TorManager>>> = OnceCell::new();
static GLOBAL_PING_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<(u64, Vec<u8>)>>>> = OnceCell::new();
static GLOBAL_TAP_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>> = OnceCell::new();
static GLOBAL_PONG_RECEIVER: OnceCell<Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>> = OnceCell::new();
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
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_initializeVoiceTorControl(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        let tor_manager = get_tor_manager();

        // Connect to voice Tor control port (9052)
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.initialize_voice_control().await
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
            Ok(receiver) => {
                // Store the PING receiver globally
                let _ = GLOBAL_PING_RECEIVER.set(Arc::new(Mutex::new(receiver)));

                // Initialize MESSAGE channel for TEXT/VOICE/IMAGE/PAYMENT routing
                let (message_tx, message_rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();
                let _ = GLOBAL_MESSAGE_RECEIVER.set(Arc::new(Mutex::new(message_rx)));
                let tx_arc = Arc::new(std::sync::Mutex::new(message_tx));
                if let Err(_) = crate::network::tor::MESSAGE_TX.set(tx_arc) {
                    log::warn!("MESSAGE channel already initialized");
                }
                log::info!("MESSAGE channel initialized for direct routing");

                // Initialize VOICE channel for CALL_SIGNALING routing
                let (voice_tx, voice_rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();
                let _ = GLOBAL_VOICE_RECEIVER.set(Arc::new(Mutex::new(voice_rx)));
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
        let mut manager = tor_manager.lock().unwrap();
        manager.stop_listener();
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
        let mut manager = tor_manager.lock().unwrap();

        // Stop the hidden service listener
        manager.stop_listener();

        // Note: TAP listener and PING listener are managed through global channels
        // They will naturally stop when no longer polled

        log::info!("All listeners stopped");
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
            1  // true
        } else {
            log::debug!("Connection {} is dead (not found in PENDING_CONNECTIONS)", connection_id);
            0  // false
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
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        let result = runtime.block_on(async {
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

        // Open new connection and send Pong
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        let result = runtime.block_on(async {
            const PONG_PORT: u16 = 9150;

            // Connect to sender's .onion address (lock only during connect)
            let mut conn = {
                let tor = tor_manager.lock().unwrap();
                tor.connect(&onion_address, PONG_PORT).await?
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

        log::info!("Sending Pong to listener at {}:8080 ({} bytes)", onion_address, pong_bytes.len());

        // Get Tor manager
        let tor_manager = get_tor_manager();

        // Open connection to sender's Pong listener and send Pong
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        let result = runtime.block_on(async {
            const PONG_LISTENER_PORT: u16 = 8080;  // Main listener port (handles all message types)

            // Build wire message with type byte
            let mut wire_message = Vec::new();
            wire_message.push(crate::network::tor::MSG_TYPE_PONG); // Add type byte
            wire_message.extend_from_slice(&pong_bytes);

            // Connect to sender's Pong listener (lock only during connect)
            let mut conn = {
                let tor = tor_manager.lock().unwrap();
                tor.connect(&onion_address, PONG_LISTENER_PORT).await?
            }; // Lock released

            // Send wire message (lock only during send)
            {
                let tor = tor_manager.lock().unwrap();
                tor.send(&mut conn, &wire_message).await?;
            } // Lock released

            log::info!("Pong sent successfully to listener at {}:8080", onion_address);
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
    ping_id: JString,  // Ping ID (hex-encoded nonce) - generated in Kotlin, never changes
    ping_timestamp: jlong,  // Timestamp when ping was created - also from Kotlin
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

        let ping_id = ping_id_str;  // Use the provided ping_id (not regenerated)

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
                            log::warn!("⚠️  Received PING_ACK (0x06) on PING connection - ignoring (should go to port 9153)");
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

                    log::info!("✓ Received instant Pong response ({} bytes)", data_len);

                    Ok::<Vec<u8>, Box<dyn std::error::Error>>(pong_data)
                }
            ).await;

            match pong_result {
                Ok(Ok(_pong_data)) => {
                    log::info!("✓ INSTANT MODE: Pong received, sending message payload...");
                    log::info!("Message size: {} bytes encrypted", message_bytes.len());

                    // Build message wire format: [Type Byte][Encrypted Message]
                    // NOTE: message_bytes from encryptMessage() already contains [X25519 32 bytes][Encrypted data]
                    let mut message_wire = Vec::new();
                    message_wire.push(message_type_byte as u8); // Type byte from parameter
                    message_wire.extend_from_slice(&message_bytes);          // Encrypted message (already has X25519 key)

                    log::info!("Sending message wire: {} bytes total (1 type + {} encrypted)",
                        message_wire.len(), message_bytes.len());

                    // Send message on same connection (lock only during send)
                    {
                        let manager = tor_manager.lock().unwrap();
                        manager.send(&mut conn, &message_wire).await?;
                    } // Lock released

                    log::info!("✓ Message sent successfully ({} bytes) in INSTANT MODE", message_bytes.len());
                    Ok(())
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to receive instant Pong: {}", e);
                    log::info!("→ DELAYED MODE: Pong will arrive later via port 8080 main listener");
                    Ok(())
                }
                Err(_) => {
                    log::info!("→ DELAYED MODE: Instant Pong timeout ({}s) - recipient may be offline or busy", INSTANT_PONG_TIMEOUT_SECS);
                    log::info!("   Pong will arrive later via port 8080 main listener when recipient comes online");
                    Ok(())
                }
            }
        });

        match result {
            Ok(_) => {
                log::info!("✓ Ping sent to {}: {}", recipient_onion_str, ping_id);

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
        let wire_message = match base64::decode(&wire_bytes_b64_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Failed to decode Base64 wire bytes: {}", e);
                return 0;
            }
        };

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
                            log::warn!("⚠️  Received PING_ACK (0x06) on PING connection during retry - ignoring (should go to port 9153)");
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

                    log::info!("✓ Received instant Pong response ({} bytes) for retry", data_len);

                    Ok::<Vec<u8>, Box<dyn std::error::Error>>(pong_data)
                }
            ).await;

            match pong_result {
                Ok(Ok(_pong_data)) => {
                    log::info!("✓ INSTANT MODE: Pong received for resent Ping");
                    Ok(())
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to receive instant Pong for retry: {}", e);
                    log::info!("→ DELAYED MODE: Pong will arrive later via port 8080 main listener");
                    Ok(())
                }
                Err(_) => {
                    log::info!("→ DELAYED MODE: Instant Pong timeout ({}s) for retry - recipient may be offline or busy", INSTANT_PONG_TIMEOUT_SECS);
                    log::info!("   Pong will arrive later via port 8080 main listener when recipient comes online");
                    Ok(())
                }
            }
        });

        match result {
            Ok(_) => {
                log::info!("✓ Ping resent successfully to {}", recipient_onion_str);
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

        let result = runtime.block_on(async {
            let manager = tor_manager.lock().unwrap();
            let mut conn = manager.connect(&recipient_onion_str, FRIEND_REQUEST_PORT).await?;
            manager.send(&mut conn, &wire_message).await?;

            log::info!("Friend request sent successfully to {}", recipient_onion_str);
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        match result {
            Ok(_) => {
                log::info!("Friend request sent successfully to {}", recipient_onion_str);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to send friend request to {}: {}", recipient_onion_str, e);
                0 // failure
            }
        }
    }, 0)
}

/// Send friend request accepted message to a recipient
/// Args:
///   recipient_onion - Recipient's .onion address
///   encrypted_acceptance - Encrypted friend request acceptance message
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

        let result = runtime.block_on(async {
            let manager = tor_manager.lock().unwrap();
            let mut conn = manager.connect(&recipient_onion_str, FRIEND_REQUEST_PORT).await?;
            manager.send(&mut conn, &wire_message).await?;

            log::info!("Friend request acceptance sent successfully to {}", recipient_onion_str);
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        match result {
            Ok(_) => {
                log::info!("Friend request acceptance sent successfully to {}", recipient_onion_str);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to send friend request acceptance to {}: {}", recipient_onion_str, e);
                0 // failure
            }
        }
    }, 0)
}

/// Send ACK on an existing connection (fire-and-forget)
/// Args:
///   connection_id - Connection ID from pollIncomingPing
///   item_id - Item ID (ping_id or message_id)
///   ack_type - "PING_ACK" or "MESSAGE_ACK"
///   encrypted_ack - Encrypted ACK bytes
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
        log::info!("Starting tap listener on port {}", port);

        let tor_manager = get_tor_manager();

        // Run async listener start using the global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        });

        match result {
            Ok(mut receiver) => {
                // Create channel for tap messages (converting from (u64, Vec<u8>) to just Vec<u8>)
                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

                // Store receiver globally
                let _ = GLOBAL_TAP_RECEIVER.set(Arc::new(Mutex::new(rx)));

                // Spawn task to receive from TorManager and forward to tap channel
                GLOBAL_RUNTIME.spawn(async move {
                    while let Some((_connection_id, tap_bytes)) = receiver.recv().await {
                        log::info!("Received tap via listener: {} bytes", tap_bytes.len());

                        // Send to tap channel
                        if let Err(e) = tx.send(tap_bytes) {
                            log::error!("Failed to send tap to channel: {}", e);
                            break;
                        }
                    }
                    log::warn!("Tap listener receiver closed");
                });

                log::info!("Tap listener started on port {}", port);
                1 // success
            }
            Err(e) => {
                log::error!("Failed to start tap listener: {}", e);
                0 // failure
            }
        }
    }, 0)
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

        if wire_bytes.len() < 32 {
            log::error!("Tap wire too short: {} bytes", wire_bytes.len());
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (first 32 bytes)
        let sender_x25519_pubkey: [u8; 32] = wire_bytes[0..32].try_into().unwrap();
        let encrypted_tap = &wire_bytes[32..];

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
        let result = GLOBAL_RUNTIME.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        });

        match result {
            Ok(mut receiver) => {
                // Create channel for pong messages (converting from (u64, Vec<u8>) to just Vec<u8>)
                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

                // Store receiver globally
                let _ = GLOBAL_PONG_RECEIVER.set(Arc::new(Mutex::new(rx)));

                // Spawn task to receive from TorManager and forward to pong channel
                GLOBAL_RUNTIME.spawn(async move {
                    while let Some((_connection_id, pong_bytes)) = receiver.recv().await {
                        log::info!("Received pong via listener: {} bytes", pong_bytes.len());

                        // Send to pong channel
                        if let Err(e) = tx.send(pong_bytes) {
                            log::error!("Failed to send pong to channel: {}", e);
                            break;
                        }
                    }
                    log::warn!("Pong listener receiver closed");
                });

                log::info!("Pong listener started on port {}", port);
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
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_pollIncomingPong(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_panic!(env, {
        if let Some(receiver) = GLOBAL_PONG_RECEIVER.get() {
            let mut rx = receiver.lock().unwrap();

            // Try to receive without blocking
            match rx.try_recv() {
                Ok(pong_bytes) => {
                    log::info!("Polled pong: {} bytes", pong_bytes.len());
                    match vec_to_jbytearray(&mut env, &pong_bytes) {
                        Ok(array) => array.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => {
                    // No pong available
                    std::ptr::null_mut()
                }
            }
        } else {
            // Listener not started
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

        if wire_bytes.len() < 32 {
            log::error!("Pong wire too short: {} bytes", wire_bytes.len());
            return 0;
        }

        // Extract recipient's X25519 public key (first 32 bytes)
        let recipient_x25519_pubkey: [u8; 32] = wire_bytes[0..32].try_into().unwrap();
        let encrypted_pong = &wire_bytes[32..];

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

        // Use ping_nonce as ping_id (hex-encoded)
        let ping_id = hex::encode(&pong_token.ping_nonce);
        log::info!("Received Pong for ping_id: {}", ping_id);

        // Convert message::PongToken to pingpong::PongToken
        let pingpong_token = crate::network::pingpong::PongToken {
            ping_nonce: pong_token.ping_nonce,
            pong_nonce: pong_token.pong_nonce,
            timestamp: pong_token.timestamp,
            authenticated: pong_token.authenticated,
            signature: pong_token.signature,
        };

        // Store in GLOBAL_PONG_SESSIONS
        crate::network::pingpong::store_pong_session(&ping_id, pingpong_token);
        log::info!("Stored Pong in GLOBAL_PONG_SESSIONS");

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
            log::info!("✓ Found Pong for ping_id: {}", ping_id_str);
            1 // true - Pong is waiting
        } else {
            log::debug!("✗ No Pong found for ping_id: {}", ping_id_str);
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

        // Create wire message: [Type Byte][Sender X25519 Public Key - 32 bytes][Encrypted Message]
        let mut wire_message = Vec::with_capacity(1 + 32 + message_bytes.len());
        wire_message.push(message_type_byte as u8); // Type byte from parameter
        wire_message.extend_from_slice(&our_x25519_public);
        wire_message.extend_from_slice(&message_bytes);

        log::info!("Wire message: {} bytes (1-byte type + 32-byte X25519 pubkey + {} bytes encrypted)",
            wire_message.len(), message_bytes.len());

        // Get Tor manager
        let tor_manager = get_tor_manager();

        // Send message blob via Tor
        // Use async runtime to send
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        let result = runtime.block_on(async {
            // Use port 9151 for friend requests (0x07, 0x08), port 9150 for regular messages
            const FRIEND_REQUEST_PORT: u16 = 9151;
            const MESSAGE_PORT: u16 = 9150;

            let port = match message_type_byte as u8 {
                0x07 | 0x08 => FRIEND_REQUEST_PORT, // FRIEND_REQUEST or FRIEND_RESPONSE
                _ => MESSAGE_PORT                    // Regular messages
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
                log::error!("Failed to send message blob: {}", e);
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
                log::info!("✓ HTTP 200 OK received from voice listener");
                Ok(())
            } else {
                log::error!("✗ Unexpected HTTP response: {}", response_str.lines().next().unwrap_or(""));
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

        if wire_bytes.len() < 32 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Wire message too short - missing X25519 pubkey");
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (first 32 bytes)
        let sender_x25519_bytes: [u8; 32] = wire_bytes[0..32].try_into().unwrap();
        let encrypted_pong = &wire_bytes[32..];

        log::info!("Attempting to decrypt incoming Pong ({} bytes encrypted data)", encrypted_pong.len());

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

        // Extract Ping ID from Pong (the ping_nonce field)
        let ping_id = hex::encode(&pong_token.ping_nonce);

        log::info!("✓ Decrypted incoming Pong for Ping ID: {} (authenticated={})", ping_id, pong_token.authenticated);

        // Store Pong in global session storage for pollForPong()
        crate::network::pingpong::store_pong_session(&ping_id, pong_token);

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
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        // Capture message type byte for async block
        let msg_type = message_type_byte as u8;

        const MESSAGE_PORT: u16 = 9150;

        let result = runtime.block_on(async {
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
                    log::warn!("⚠️  Received PING_ACK (0x06) when expecting PONG - ignoring (should go to port 9153)");
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
            message_wire.extend_from_slice(&our_x25519_public);    // Sender X25519 pubkey
            message_wire.extend_from_slice(&message_bytes);         // Encrypted message

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
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_startBootstrapListener(
    mut env: JNIEnv,
    _class: JClass,
) {
    catch_panic!(env, {
        log::info!("Starting bootstrap event listener from explicit call...");
        crate::network::tor::start_bootstrap_event_listener();
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

        log::info!("╔════════════════════════════════════════");
        log::info!("║ 📤 SENDING DELIVERY ACK");
        log::info!("║ Item ID: {}", item_id_str);
        log::info!("║ ACK Type: {}", ack_type_str);
        log::info!("║ Recipient: {}", recipient_onion_str);
        log::info!("╚════════════════════════════════════════");

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
                log::info!("✓ ACK sent successfully: {} for {}", ack_type_str, item_id_str);
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
            Ok(mut receiver) => {
                // Create shared channel for ACK messages
                // This channel is accessible from both port 9153 (normal path) and port 8080 (error recovery)
                let (tx, rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();

                // Store receiver globally for polling
                let _ = GLOBAL_ACK_RECEIVER.set(Arc::new(Mutex::new(rx)));

                // Store sender globally so port 8080 can route misrouted ACKs
                let _ = crate::network::tor::ACK_TX.set(Arc::new(std::sync::Mutex::new(tx.clone())));

                // Spawn task to receive from TorManager listener and forward to shared ACK channel
                GLOBAL_RUNTIME.spawn(async move {
                    while let Some((connection_id, ack_bytes)) = receiver.recv().await {
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
/// Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted ACK]
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

        if wire_bytes.len() < 32 {
            log::error!("ACK wire too short: {} bytes", wire_bytes.len());
            return std::ptr::null_mut();
        }

        // Extract sender's X25519 public key (first 32 bytes)
        let sender_x25519_pubkey: [u8; 32] = wire_bytes[0..32].try_into().unwrap();
        let encrypted_ack = &wire_bytes[32..];

        log::info!("Decrypting ACK from sender X25519: {}", hex::encode(&sender_x25519_pubkey));

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

        log::info!("╔════════════════════════════════════════");
        log::info!("║ 📥 RECEIVED DELIVERY ACK");
        log::info!("║ Item ID: {}", ack_token.item_id);
        log::info!("║ ACK Type: {}", ack_token.ack_type);
        log::info!("╚════════════════════════════════════════");

        let item_id = ack_token.item_id.clone();
        let ack_type = ack_token.ack_type.clone();

        // Store in GLOBAL_ACK_SESSIONS
        crate::network::pingpong::store_ack_session(&item_id, ack_token);
        log::info!("Stored ACK in GLOBAL_ACK_SESSIONS");

        // Return JSON with item_id and ack_type
        let ack_json = format!(r#"{{"item_id":"{}","ack_type":"{}"}}"#, item_id, ack_type);
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
            redundant_audio_data: Vec::new(),  // Phase 3: Will be populated by sender task
            redundant_sequence: 0,              // Phase 3: Will be populated by sender task
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
                log::info!("✓ Circuit {} rebuild SUCCESS for call {}", circuit_index, call_id_str);
                1 // success
            }
            Err(e) => {
                log::error!("✗ Circuit {} rebuild FAILED for call {}: {}", circuit_index, call_id_str, e);
                0 // failure
            }
        }
    }, 0)
}

// ==================== END v2.0: Voice Streaming ====================
