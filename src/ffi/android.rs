use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jlong, jstring, jobjectArray};
use jni::JNIEnv;
use std::panic;
use std::sync::{Arc, Mutex};
use once_cell::sync::{OnceCell, Lazy};
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::crypto::{
    decrypt_message, encrypt_message, generate_keypair, hash_handle, hash_password, sign_data,
    verify_signature,
};
use crate::network::{TorManager, PENDING_CONNECTIONS};
use crate::protocol::ContactCard;
use crate::blockchain::{register_username, lookup_username};
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
        // Start the bootstrap event listener (separate control port connection)
        // This will continuously update BOOTSTRAP_STATUS in real-time
        log::info!("Starting bootstrap event listener...");
        crate::network::tor::start_bootstrap_event_listener();

        let tor_manager = get_tor_manager();

        // Run async initialization using global runtime
        let result = GLOBAL_RUNTIME.block_on(async {
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

        log::info!("Sending Pong to listener at {}:9152 ({} bytes)", onion_address, pong_bytes.len());

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
            const PONG_LISTENER_PORT: u16 = 9152;

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

            log::info!("Pong sent successfully to listener at {}:9152", onion_address);
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

        // Create PingToken (signed) with both Ed25519 and X25519 keys
        let ping_token = match crate::network::PingToken::new(
            &sender_keypair,
            &recipient_ed25519_verifying,
            &sender_x25519_pubkey,
            &recipient_x25519_pubkey,
        ) {
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
                    log::info!("→ DELAYED MODE: Pong will arrive later via port 9152 listener");
                    Ok(())
                }
                Err(_) => {
                    log::info!("→ DELAYED MODE: Instant Pong timeout ({}s) - recipient may be offline or busy", INSTANT_PONG_TIMEOUT_SECS);
                    log::info!("   Pong will arrive later via port 9152 listener when recipient comes online");
                    Ok(())
                }
            }
        });

        match result {
            Ok(_) => {
                log::info!("✓ Ping sent to {}: {}", recipient_onion_str, ping_id);

                // Return the ping_id immediately so the sender can poll for Pong later
                match string_to_jstring(&mut env, &ping_id) {
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

        const FRIEND_REQUEST_PORT: u16 = 9150; // Use same port as hidden service

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

        // Check if Pong exists (non-blocking check)
        if crate::network::pingpong::get_pong_session(&ping_id_str).is_some() {
            1 // true - Pong is waiting
        } else {
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
            const MESSAGE_PORT: u16 = 9150;

            // Connect to recipient
            let tor = tor_manager.lock().unwrap();
            let mut conn = tor.connect(&onion_address, MESSAGE_PORT).await?;

            // Send wire message (with X25519 pubkey prefix)
            tor.send(&mut conn, &wire_message).await?;

            log::info!("Message blob sent successfully to {}", onion_address);
            Ok::<(), Box<dyn std::error::Error>>(())
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
        let runtime = GLOBAL_RUNTIME.handle();

        match runtime.block_on(async {
            let mut manager = tor_manager.lock().unwrap();
            manager.start_listener(Some(port as u16)).await
        }) {
            Ok(rx) => {
                // Store receiver in global static
                let _ = GLOBAL_ACK_RECEIVER.set(Arc::new(Mutex::new(rx)));
                log::info!("ACK listener started successfully on port {}", port);
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

        // Store in GLOBAL_ACK_SESSIONS
        crate::network::pingpong::store_ack_session(&item_id, ack_token);
        log::info!("Stored ACK in GLOBAL_ACK_SESSIONS");

        // Return item_id to caller
        match string_to_jstring(&mut env, &item_id) {
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
