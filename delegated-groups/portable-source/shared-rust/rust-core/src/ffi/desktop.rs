//! C FFI exports for the Flutter desktop app (Windows/macOS/Linux).
//! These are plain C functions callable via Dart's dart:ffi.
//! Separate from android.rs (JNI) and ios.rs to avoid touching mobile code.

use std::slice;
use std::ptr;

// ==================== HELPER FUNCTIONS ====================

/// Write bytes into a caller-provided buffer. Returns bytes written, or -1 if buffer too small.
unsafe fn write_to_buffer(data: &[u8], out: *mut u8, out_len: *mut u32) -> i32 {
    if out.is_null() || out_len.is_null() {
        return -1;
    }
    let capacity = *out_len as usize;
    if data.len() > capacity {
        *out_len = data.len() as u32;
        return -1;
    }
    ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    *out_len = data.len() as u32;
    0
}

/// Read bytes from a raw pointer + length into a Vec.
unsafe fn read_from_ptr(ptr: *const u8, len: u32) -> Option<Vec<u8>> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len as usize).to_vec())
}

// ==================== VERSION ====================

/// Return the library version as a null-terminated C string.
/// Caller must NOT free the returned pointer (static lifetime).
#[no_mangle]
pub extern "C" fn sl_desktop_version() -> *const std::os::raw::c_char {
    static VERSION: &[u8] = b"1.0.0\0";
    VERSION.as_ptr() as *const std::os::raw::c_char
}

// ==================== KEY GENERATION ====================

/// Generate an Ed25519 keypair. Writes 32-byte pubkey and 32-byte privkey.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_generate_keypair(
    pubkey_out: *mut u8,
    privkey_out: *mut u8,
) -> i32 {
    if pubkey_out.is_null() || privkey_out.is_null() {
        return -1;
    }
    let (pubkey, privkey) = crate::crypto::generate_keypair();
    ptr::copy_nonoverlapping(pubkey.as_ptr(), pubkey_out, 32);
    ptr::copy_nonoverlapping(privkey.as_ptr(), privkey_out, 32);
    0
}

/// Generate an X25519 keypair from random. Writes 32-byte pubkey and 32-byte privkey.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_generate_x25519_keypair(
    pubkey_out: *mut u8,
    privkey_out: *mut u8,
) -> i32 {
    if pubkey_out.is_null() || privkey_out.is_null() {
        return -1;
    }
    use x25519_dalek::{StaticSecret, PublicKey};
    use rand::rngs::OsRng;

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    ptr::copy_nonoverlapping(public.as_bytes().as_ptr(), pubkey_out, 32);
    ptr::copy_nonoverlapping(secret.as_bytes().as_ptr(), privkey_out, 32);
    0
}

// ==================== SIGNING ====================

/// Sign data with an Ed25519 private key (32-byte seed).
/// Writes 64-byte signature to sig_out.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_sign(
    message: *const u8,
    message_len: u32,
    private_key: *const u8,
    private_key_len: u32,
    sig_out: *mut u8,
) -> i32 {
    let msg = match read_from_ptr(message, message_len) {
        Some(v) => v,
        None => return -1,
    };
    let key = match read_from_ptr(private_key, private_key_len) {
        Some(v) if v.len() == 32 => v,
        _ => return -1,
    };
    if sig_out.is_null() {
        return -1;
    }

    let sk_bytes: [u8; 32] = key.as_slice().try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&msg);
    ptr::copy_nonoverlapping(signature.to_bytes().as_ptr(), sig_out, 64);
    0
}

/// Verify an Ed25519 signature.
/// Returns 1 (true) if valid, 0 (false) if invalid.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_verify(
    message: *const u8,
    message_len: u32,
    public_key: *const u8,
    public_key_len: u32,
    signature: *const u8,
    signature_len: u32,
) -> i32 {
    let msg = match read_from_ptr(message, message_len) {
        Some(v) => v,
        None => return 0,
    };
    let pk = match read_from_ptr(public_key, public_key_len) {
        Some(v) if v.len() == 32 => v,
        _ => return 0,
    };
    let sig = match read_from_ptr(signature, signature_len) {
        Some(v) if v.len() == 64 => v,
        _ => return 0,
    };

    let pk_bytes: [u8; 32] = pk.as_slice().try_into().unwrap();
    let sig_bytes: [u8; 64] = sig.as_slice().try_into().unwrap();

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
        Ok(vk) => vk,
        Err(_) => return 0,
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    if verifying_key.verify(&msg, &signature).is_ok() { 1 } else { 0 }
}

// ==================== ENCRYPTION ====================

/// Encrypt plaintext with a 32-byte key (XChaCha20-Poly1305).
/// Output buffer must be at least plaintext_len + 40 bytes.
/// Returns 0 on success, -1 on failure. out_len is set to actual output size.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_encrypt(
    plaintext: *const u8,
    plaintext_len: u32,
    key: *const u8,
    key_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    let pt = match read_from_ptr(plaintext, plaintext_len) {
        Some(v) => v,
        None => return -1,
    };
    let k = match read_from_ptr(key, key_len) {
        Some(v) if v.len() == 32 => v,
        _ => return -1,
    };

    match crate::crypto::encrypt_message(&pt, &k) {
        Ok(ciphertext) => write_to_buffer(&ciphertext, out, out_len),
        Err(_) => -1,
    }
}

/// Decrypt ciphertext with a 32-byte key (XChaCha20-Poly1305).
/// Output buffer must be at least ciphertext_len bytes.
/// Returns 0 on success, -1 on failure. out_len is set to actual plaintext size.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_decrypt(
    ciphertext: *const u8,
    ciphertext_len: u32,
    key: *const u8,
    key_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    let ct = match read_from_ptr(ciphertext, ciphertext_len) {
        Some(v) => v,
        None => return -1,
    };
    let k = match read_from_ptr(key, key_len) {
        Some(v) if v.len() == 32 => v,
        _ => return -1,
    };

    match crate::crypto::decrypt_message(&ct, &k) {
        Ok(plaintext) => write_to_buffer(&plaintext, out, out_len),
        Err(_) => -1,
    }
}

// ==================== KEY DERIVATION ====================

/// Derive a 32-byte root key from shared secret using HKDF-SHA256.
/// info is a null-terminated C string.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_derive_root_key(
    shared_secret: *const u8,
    shared_secret_len: u32,
    info: *const std::os::raw::c_char,
    out: *mut u8,
) -> i32 {
    let secret = match read_from_ptr(shared_secret, shared_secret_len) {
        Some(v) => v,
        None => return -1,
    };
    if info.is_null() || out.is_null() {
        return -1;
    }
    let info_str = match std::ffi::CStr::from_ptr(info).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match crate::crypto::derive_root_key(&secret, info_str.as_bytes()) {
        Ok(key) => {
            ptr::copy_nonoverlapping(key.as_ptr(), out, 32);
            0
        }
        Err(_) => -1,
    }
}

/// Evolve chain key forward. Writes new 32-byte chain key to out.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_evolve_chain_key(
    chain_key: *const u8,
    out: *mut u8,
) -> i32 {
    if chain_key.is_null() || out.is_null() {
        return -1;
    }
    let key_slice = slice::from_raw_parts(chain_key, 32);
    let mut key_array: [u8; 32] = key_slice.try_into().unwrap();

    match crate::crypto::evolve_chain_key(&mut key_array) {
        Ok(evolved) => {
            ptr::copy_nonoverlapping(evolved.as_ptr(), out, 32);
            0
        }
        Err(_) => -1,
    }
}

/// Derive per-message key from chain key. Writes 32-byte message key to out.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_derive_message_key(
    chain_key: *const u8,
    out: *mut u8,
) -> i32 {
    if chain_key.is_null() || out.is_null() {
        return -1;
    }
    let key_slice = slice::from_raw_parts(chain_key, 32);
    let mut key_array: [u8; 32] = key_slice.try_into().unwrap();

    match crate::crypto::derive_message_key(&mut key_array) {
        Ok(msg_key) => {
            ptr::copy_nonoverlapping(msg_key.as_ptr(), out, 32);
            0
        }
        Err(_) => -1,
    }
}

// ==================== ENCRYPT/DECRYPT WITH EVOLUTION ====================

/// Encrypt with atomic key evolution.
/// Output: [evolved_chain_key:32][ciphertext]
/// Returns 0 on success, -1 on failure. out_len set to total output size.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_encrypt_with_evolution(
    plaintext: *const u8,
    plaintext_len: u32,
    chain_key: *const u8,
    sequence: u64,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    let pt = match read_from_ptr(plaintext, plaintext_len) {
        Some(v) => v,
        None => return -1,
    };
    if chain_key.is_null() {
        return -1;
    }
    let key_slice = slice::from_raw_parts(chain_key, 32);
    let mut key_array: [u8; 32] = key_slice.try_into().unwrap();

    match crate::crypto::encrypt_message_with_evolution(&pt, &mut key_array, sequence) {
        Ok(result) => {
            let mut output = Vec::with_capacity(32 + result.ciphertext.len());
            output.extend_from_slice(&result.evolved_chain_key);
            output.extend_from_slice(&result.ciphertext);
            write_to_buffer(&output, out, out_len)
        }
        Err(_) => -1,
    }
}

/// Decrypt with atomic key evolution.
/// Output: [evolved_chain_key:32][plaintext_raw_bytes]
/// Returns 0 on success, -1 on failure. out_len set to total output size.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_decrypt_with_evolution(
    encrypted: *const u8,
    encrypted_len: u32,
    chain_key: *const u8,
    expected_sequence: u64,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    let ct = match read_from_ptr(encrypted, encrypted_len) {
        Some(v) => v,
        None => return -1,
    };
    if chain_key.is_null() {
        return -1;
    }
    let key_slice = slice::from_raw_parts(chain_key, 32);
    let mut key_array: [u8; 32] = key_slice.try_into().unwrap();

    match crate::crypto::decrypt_message_with_evolution(&ct, &mut key_array, expected_sequence) {
        Ok(result) => {
            let mut output = Vec::with_capacity(32 + result.plaintext.len());
            output.extend_from_slice(&result.evolved_chain_key);
            output.extend_from_slice(&result.plaintext);
            write_to_buffer(&output, out, out_len)
        }
        Err(_) => -1,
    }
}

// ==================== HYBRID KEM ====================

/// Generate hybrid X25519 + ML-KEM-1024 keypair from 32-byte seed.
/// Writes: x25519_pub(32) + x25519_sec(32) + kyber_pub(1568) + kyber_sec(3168)
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_generate_hybrid_kem_keypair(
    seed: *const u8,
    x25519_pub_out: *mut u8,
    x25519_sec_out: *mut u8,
    kyber_pub_out: *mut u8,
    kyber_sec_out: *mut u8,
) -> i32 {
    if seed.is_null() || x25519_pub_out.is_null() || x25519_sec_out.is_null()
        || kyber_pub_out.is_null() || kyber_sec_out.is_null()
    {
        return -1;
    }
    let seed_slice = slice::from_raw_parts(seed, 32);
    let seed_array: [u8; 32] = seed_slice.try_into().unwrap();

    match crate::crypto::pqc::hybrid_kem::generate_hybrid_keypair_from_seed(&seed_array) {
        Ok(keypair) => {
            ptr::copy_nonoverlapping(keypair.x25519_public.as_ptr(), x25519_pub_out, 32);
            ptr::copy_nonoverlapping(keypair.x25519_secret.as_ptr(), x25519_sec_out, 32);
            ptr::copy_nonoverlapping(keypair.kyber_public.as_ptr(), kyber_pub_out, 1568);
            ptr::copy_nonoverlapping(keypair.kyber_secret.as_ptr(), kyber_sec_out, 3168);
            0
        }
        Err(_) => -1,
    }
}

// ==================== ONION ADDRESS ====================
// TODO: Add sl_desktop_compute_onion_address once network modules are gated
// for cross-platform compilation. The function lives in network::tor which
// depends on Arti/Tokio (not available on Windows yet).
