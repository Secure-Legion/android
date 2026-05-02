use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use once_cell::sync::Lazy;
use rand::RngCore;
use xsalsa20poly1305::XSalsa20Poly1305;

use crate::crdt::apply::GroupState;
use crate::crdt::ids::{DeviceID, GroupID, OpID};
use crate::crdt::limits::{HARD_CAP_OPS_PER_GROUP, MAX_OP_PAYLOAD_BYTES};
use crate::crdt::messages::MessageEntry;
use crate::crdt::ops::{
    generate_msg_id, AdminRights, GroupCreatePayload, GroupDeletePayload, MemberAcceptPayload,
    MemberInvitePayload, MemberRemovePayload, MemberUnbanPayload, MetadataKey, MetadataSetPayload,
    MsgAddPayload, MsgDeletePayload, MsgEditPayload, OpEnvelope, OpType, ReactionSetPayload,
    RemoveReason, Role, RoleSetPayload,
};
use crate::crypto::encryption::{
    decrypt_message, decrypt_message_with_evolution, derive_message_key,
    derive_receive_key_at_sequence, derive_root_key, encrypt_message,
    encrypt_message_with_evolution, evolve_chain_key,
};
use crate::crypto::hashing::{generate_salt, hash_password_with_salt};
use crate::crypto::key_exchange::{derive_shared_secret, generate_static_keypair};
use crate::crypto::pqc::{
    generate_hybrid_keypair_from_seed, hybrid_decapsulate, hybrid_encapsulate, HybridCiphertext,
};
use crate::crypto::signing::{generate_keypair, sign_data, verify_signature};
use crate::network::compute_onion_address_from_ed25519_seed;
use crate::network::friend_request_server::get_endpoint;
use crate::network::pingpong::{DeliveryAck, PingToken, PongToken};
use crate::network::tor::MSG_TYPE_DELIVERY_CONFIRMATION;

const MAX_SERIALIZED_OP_BYTES: usize = MAX_OP_PAYLOAD_BYTES + 1024;
const MAX_OPS_PER_APPLY_BATCH: usize = 2_000;

static GROUPS: OnceLock<Mutex<HashMap<GroupID, GroupState>>> = OnceLock::new();
static MY_LAMPORT: OnceLock<Mutex<HashMap<GroupID, u64>>> = OnceLock::new();
static VERSION_CSTR: Lazy<CString> =
    Lazy::new(|| CString::new(crate::VERSION).unwrap_or_else(|_| CString::new("unknown").unwrap()));
static RUNTIME: Lazy<tokio::runtime::Runtime> =
    Lazy::new(|| tokio::runtime::Runtime::new().expect("failed to create tokio runtime"));
static FR_SERVER_STARTED: AtomicBool = AtomicBool::new(false);
static ARTI_STREAMS: Lazy<Mutex<HashMap<u64, crate::network::arti::ArtiStream>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static ARTI_LAST_ERROR: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
static NEXT_ARTI_STREAM_ID: AtomicU64 = AtomicU64::new(1);
const IOS_ARTI_DIRECT_CONNECT_TIMEOUT_MS: u64 = 90_000;
const IOS_ARTI_DIRECT_WRITE_TIMEOUT_MS: u64 = 8_000;
const IOS_ARTI_DIRECT_ACK_TIMEOUT_MS: u64 = 15_000;

fn get_groups() -> &'static Mutex<HashMap<GroupID, GroupState>> {
    GROUPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_lamport_map() -> &'static Mutex<HashMap<GroupID, u64>> {
    MY_LAMPORT.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe fn cstr_to_string(ptr: *const c_char) -> Result<String, &'static str> {
    if ptr.is_null() {
        return Err("null string pointer");
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| "invalid utf8 string")
}

unsafe fn bytes_from_ptr<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], &'static str> {
    if ptr.is_null() {
        return Err("null bytes pointer");
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

unsafe fn bytes_from_ptr_opt<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

unsafe fn copy_fixed<const N: usize>(ptr: *const u8) -> Result<[u8; N], &'static str> {
    let s = bytes_from_ptr(ptr, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(s);
    Ok(out)
}

unsafe fn write_bytes_with_len(out_ptr: *mut u8, out_len_ptr: *mut u32, data: &[u8]) -> i32 {
    if out_ptr.is_null() || out_len_ptr.is_null() {
        return -1;
    }
    let cap = *out_len_ptr as usize;
    if data.len() > cap {
        *out_len_ptr = data.len() as u32;
        return -1;
    }
    ptr::copy_nonoverlapping(data.as_ptr(), out_ptr, data.len());
    *out_len_ptr = data.len() as u32;
    0
}

fn set_arti_last_error(message: impl Into<String>) {
    let mut guard = ARTI_LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    *guard = message.into();
}

fn clear_arti_last_error() {
    let mut guard = ARTI_LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    guard.clear();
}

unsafe fn write_cstr_to_buf(out_ptr: *mut c_char, data: &str, max_without_nul: usize) -> i32 {
    if out_ptr.is_null() || data.len() > max_without_nul || data.as_bytes().contains(&0) {
        return -1;
    }
    ptr::copy_nonoverlapping(data.as_ptr(), out_ptr as *mut u8, data.len());
    *(out_ptr.add(data.len())) = 0;
    0
}

fn decode_length_prefixed_ops(
    data: &[u8],
    max_ops: usize,
    max_op_size: usize,
) -> Result<Vec<OpEnvelope>, String> {
    let mut ops = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= data.len() {
        if ops.len() >= max_ops {
            return Err(format!("op count exceeds {}", max_ops));
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[offset..offset + 4]);
        let len = u32::from_be_bytes(len_bytes) as usize;
        offset += 4;
        if len > max_op_size {
            return Err(format!("op size {} exceeds {}", len, max_op_size));
        }
        if offset + len > data.len() {
            return Err("truncated op bytes".to_string());
        }
        let op = OpEnvelope::from_bytes(&data[offset..offset + len])
            .map_err(|e| format!("decode op failed: {}", e))?;
        ops.push(op);
        offset += len;
    }
    Ok(ops)
}

fn parse_op_type(s: &str) -> Result<OpType, String> {
    match s {
        "GroupCreate" => Ok(OpType::GroupCreate),
        "MemberInvite" => Ok(OpType::MemberInvite),
        "MemberAccept" => Ok(OpType::MemberAccept),
        "MemberRemove" => Ok(OpType::MemberRemove),
        "RoleSet" => Ok(OpType::RoleSet),
        "MsgAdd" => Ok(OpType::MsgAdd),
        "MsgEdit" => Ok(OpType::MsgEdit),
        "MsgDelete" => Ok(OpType::MsgDelete),
        "ReactionSet" => Ok(OpType::ReactionSet),
        "MetadataSet" => Ok(OpType::MetadataSet),
        other => Err(format!("unknown op type: {}", other)),
    }
}

fn parse_role(s: &str) -> Result<Role, String> {
    match s {
        "Owner" => Ok(Role::Owner),
        "Admin" => Ok(Role::Admin),
        "Member" => Ok(Role::Member),
        "ReadOnly" => Ok(Role::ReadOnly),
        other => Err(format!("unknown role: {}", other)),
    }
}

fn parse_remove_reason(s: &str) -> Result<RemoveReason, String> {
    match s {
        "Kick" => Ok(RemoveReason::Kick),
        "Leave" => Ok(RemoveReason::Leave),
        other => Err(format!("unknown remove reason: {}", other)),
    }
}

fn parse_metadata_key(s: &str) -> Result<MetadataKey, String> {
    match s {
        "Name" => Ok(MetadataKey::Name),
        "Avatar" => Ok(MetadataKey::Avatar),
        "Topic" => Ok(MetadataKey::Topic),
        "AllowMemberSendMessages" => Ok(MetadataKey::AllowMemberSendMessages),
        "AllowMemberInvites" => Ok(MetadataKey::AllowMemberInvites),
        "AllowMemberPin" => Ok(MetadataKey::AllowMemberPin),
        "AllowMemberChangeInfo" => Ok(MetadataKey::AllowMemberChangeInfo),
        other => Err(format!("unknown metadata key: {}", other)),
    }
}

fn hex_to_32(hex_str: &str, field_name: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad {} hex: {}", field_name, e))?;
    if bytes.len() != 32 {
        return Err(format!("{} must be 32 bytes", field_name));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn b64_to_24(s: &str, field_name: &str) -> Result<[u8; 24], String> {
    let bytes = B64
        .decode(s)
        .map_err(|e| format!("bad {} b64: {}", field_name, e))?;
    if bytes.len() != 24 {
        return Err(format!("{} must be 24 bytes", field_name));
    }
    let mut out = [0u8; 24];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn next_lamport(group_id: &GroupID, state: &GroupState) -> u64 {
    let mut lmap = get_lamport_map().lock().unwrap_or_else(|e| e.into_inner());
    let group_max = state.max_lamport.values().max().copied().unwrap_or(0);
    let my_current = *lmap.get(group_id).unwrap_or(&0);
    let next = std::cmp::max(group_max, my_current) + 1;
    lmap.insert(*group_id, next);
    next
}

fn message_to_json(msg: &MessageEntry) -> serde_json::Value {
    let reactions: Vec<serde_json::Value> = msg
        .reactions
        .iter()
        .filter(|(_, present)| **present)
        .map(|((reactor, emoji), _)| {
            serde_json::json!({
                "reactor": reactor.to_hex(),
                "emoji": emoji,
            })
        })
        .collect();

    serde_json::json!({
        "msg_id": hex::encode(msg.msg_id),
        "author": msg.author.to_hex(),
        "ciphertext_b64": B64.encode(&msg.ciphertext),
        "nonce_b64": B64.encode(&msg.nonce),
        "timestamp_ms": msg.timestamp_ms,
        "deleted": msg.deleted,
        "reactions": reactions,
    })
}

/// Derive a 32-byte key from PIN + salt using Argon2id with Android-compatible params.
/// Matches libsodium crypto_pwhash(OPSLIMIT_INTERACTIVE=2, MEMLIMIT_INTERACTIVE=64MB).
fn pin_kdf(pin: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 2, 1, Some(32)).map_err(|e| format!("argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut output)
        .map_err(|e| format!("pin kdf failed: {}", e))?;
    Ok(output)
}

/// PIN encrypt using XSalsa20-Poly1305 (matches Android libsodium crypto_secretbox_easy).
/// Output: [salt:16][nonce:24][ciphertext+mac]
fn pin_encrypt_internal(plaintext: &[u8], pin: &str) -> Result<Vec<u8>, String> {
    let salt = generate_salt();
    let key = pin_kdf(pin, &salt)?;
    let cipher = XSalsa20Poly1305::new_from_slice(&key).map_err(|_| "invalid key".to_string())?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| "pin encrypt failed".to_string())?;

    let mut out = Vec::with_capacity(16 + 24 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// PIN decrypt — tries Android-compatible XSalsa20-Poly1305 first,
/// falls back to legacy XChaCha20-Poly1305 (old iOS builds).
fn pin_decrypt_internal(ciphertext: &[u8], pin: &str) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 16 + 24 + 16 {
        return Err("pin ciphertext too short".to_string());
    }
    let salt = &ciphertext[..16];
    let nonce = &ciphertext[16..40];
    let body = &ciphertext[40..];

    // Primary: XSalsa20-Poly1305 + Argon2id(m=65536) — matches Android libsodium
    let key = pin_kdf(pin, salt)?;
    let salsa = XSalsa20Poly1305::new_from_slice(&key).map_err(|_| "invalid key".to_string())?;
    if let Ok(pt) = salsa.decrypt(XNonce::from_slice(nonce), body) {
        return Ok(pt);
    }

    // Fallback: XChaCha20-Poly1305 + Argon2id(default m=19456) — old iOS format
    let old_key =
        hash_password_with_salt(pin, salt).map_err(|e| format!("pin kdf failed: {}", e))?;
    let chacha =
        XChaCha20Poly1305::new_from_slice(&old_key).map_err(|_| "invalid key".to_string())?;
    chacha
        .decrypt(XNonce::from_slice(nonce), body)
        .map_err(|_| "pin decrypt failed".to_string())
}

#[no_mangle]
pub extern "C" fn securelegion_version() -> *const c_char {
    VERSION_CSTR.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_generate_keypair(
    pubkey_out: *mut u8,
    privkey_out: *mut u8,
) -> i32 {
    if pubkey_out.is_null() || privkey_out.is_null() {
        return -1;
    }
    let (pubk, privk) = generate_keypair();
    ptr::copy_nonoverlapping(pubk.as_ptr(), pubkey_out, 32);
    ptr::copy_nonoverlapping(privk.as_ptr(), privkey_out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_encrypt(
    plaintext: *const u8,
    plaintext_len: u32,
    key: *const u8,
    key_len: u32,
    ciphertext_out: *mut u8,
    ciphertext_len_out: *mut u32,
) -> i32 {
    if key_len != 32 {
        return -1;
    }
    let pt = match bytes_from_ptr(plaintext, plaintext_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let key_b = match bytes_from_ptr(key, key_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match encrypt_message(pt, key_b) {
        Ok(ct) => write_bytes_with_len(ciphertext_out, ciphertext_len_out, &ct),
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_decrypt(
    ciphertext: *const u8,
    ciphertext_len: u32,
    key: *const u8,
    key_len: u32,
    plaintext_out: *mut u8,
    plaintext_len_out: *mut u32,
) -> i32 {
    if key_len != 32 {
        return -1;
    }
    let ct = match bytes_from_ptr(ciphertext, ciphertext_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let key_b = match bytes_from_ptr(key, key_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match decrypt_message(ct, key_b) {
        Ok(pt) => write_bytes_with_len(plaintext_out, plaintext_len_out, &pt),
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_pin_encrypt(
    plaintext: *const u8,
    plaintext_len: u32,
    pin: *const c_char,
    ciphertext_out: *mut u8,
    ciphertext_len_out: *mut u32,
) -> i32 {
    let pt = match bytes_from_ptr(plaintext, plaintext_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let pin_s = match cstr_to_string(pin) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match pin_encrypt_internal(pt, &pin_s) {
        Ok(out) => write_bytes_with_len(ciphertext_out, ciphertext_len_out, &out),
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_pin_decrypt(
    ciphertext: *const u8,
    ciphertext_len: u32,
    pin: *const c_char,
    plaintext_out: *mut u8,
    plaintext_len_out: *mut u32,
) -> i32 {
    let ct = match bytes_from_ptr(ciphertext, ciphertext_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let pin_s = match cstr_to_string(pin) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match pin_decrypt_internal(ct, &pin_s) {
        Ok(out) => write_bytes_with_len(plaintext_out, plaintext_len_out, &out),
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_sign(
    message: *const u8,
    message_len: u32,
    privkey: *const u8,
    privkey_len: u32,
    signature_out: *mut u8,
) -> i32 {
    if privkey_len != 32 || signature_out.is_null() {
        return -1;
    }
    let msg = match bytes_from_ptr(message, message_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let key = match bytes_from_ptr(privkey, privkey_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match sign_data(msg, key) {
        Ok(sig) => {
            ptr::copy_nonoverlapping(sig.as_ptr(), signature_out, 64);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_verify(
    message: *const u8,
    message_len: u32,
    pubkey: *const u8,
    pubkey_len: u32,
    signature: *const u8,
    signature_len: u32,
) -> bool {
    if pubkey_len != 32 || signature_len != 64 {
        return false;
    }
    let msg = match bytes_from_ptr(message, message_len as usize) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let pk = match bytes_from_ptr(pubkey, pubkey_len as usize) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match bytes_from_ptr(signature, signature_len as usize) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verify_signature(msg, sig, pk).unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_generate_x25519_keypair(
    pubkey_out: *mut u8,
    privkey_out: *mut u8,
) -> i32 {
    if pubkey_out.is_null() || privkey_out.is_null() {
        return -1;
    }
    let (pubk, privk) = generate_static_keypair();
    ptr::copy_nonoverlapping(pubk.as_ptr(), pubkey_out, 32);
    ptr::copy_nonoverlapping(privk.as_ptr(), privkey_out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_derive_shared_secret(
    our_private_key: *const u8,
    their_public_key: *const u8,
    shared_secret_out: *mut u8,
) -> i32 {
    if shared_secret_out.is_null() {
        return -1;
    }
    let our = match bytes_from_ptr(our_private_key, 32) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let their = match bytes_from_ptr(their_public_key, 32) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match derive_shared_secret(our, their) {
        Ok(secret) => {
            ptr::copy_nonoverlapping(secret.as_ptr(), shared_secret_out, 32);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_derive_root_key(
    shared_secret: *const u8,
    shared_secret_len: u32,
    info: *const c_char,
    root_key_out: *mut u8,
) -> i32 {
    if root_key_out.is_null() {
        return -1;
    }
    let sec = match bytes_from_ptr(shared_secret, shared_secret_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let info_s = match cstr_to_string(info) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match derive_root_key(sec, info_s.as_bytes()) {
        Ok(root) => {
            ptr::copy_nonoverlapping(root.as_ptr(), root_key_out, 32);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_evolve_chain_key(
    chain_key: *const u8,
    evolved_key_out: *mut u8,
) -> i32 {
    if evolved_key_out.is_null() {
        return -1;
    }
    let mut key = match copy_fixed::<32>(chain_key) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match evolve_chain_key(&mut key) {
        Ok(next) => {
            ptr::copy_nonoverlapping(next.as_ptr(), evolved_key_out, 32);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_derive_message_key(
    chain_key: *const u8,
    message_key_out: *mut u8,
) -> i32 {
    if message_key_out.is_null() {
        return -1;
    }
    let key = match copy_fixed::<32>(chain_key) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match derive_message_key(&key) {
        Ok(msg_key) => {
            ptr::copy_nonoverlapping(msg_key.as_ptr(), message_key_out, 32);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_encrypt_with_evolution(
    plaintext: *const u8,
    plaintext_len: u32,
    chain_key: *const u8,
    sequence: u64,
    ciphertext_out: *mut u8,
    ciphertext_len_out: *mut u32,
    evolved_key_out: *mut u8,
) -> i32 {
    if evolved_key_out.is_null() {
        return -1;
    }
    let pt = match bytes_from_ptr(plaintext, plaintext_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let mut key = match copy_fixed::<32>(chain_key) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match encrypt_message_with_evolution(pt, &mut key, sequence) {
        Ok(result) => {
            ptr::copy_nonoverlapping(result.evolved_chain_key.as_ptr(), evolved_key_out, 32);
            write_bytes_with_len(ciphertext_out, ciphertext_len_out, &result.ciphertext)
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_decrypt_with_evolution(
    encrypted: *const u8,
    encrypted_len: u32,
    chain_key: *const u8,
    expected_sequence: u64,
    plaintext_out: *mut u8,
    plaintext_len_out: *mut u32,
    evolved_key_out: *mut u8,
) -> i32 {
    if evolved_key_out.is_null() {
        return -1;
    }
    let enc = match bytes_from_ptr(encrypted, encrypted_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let mut key = match copy_fixed::<32>(chain_key) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match decrypt_message_with_evolution(enc, &mut key, expected_sequence) {
        Ok(result) => {
            ptr::copy_nonoverlapping(result.evolved_chain_key.as_ptr(), evolved_key_out, 32);
            write_bytes_with_len(plaintext_out, plaintext_len_out, &result.plaintext)
        }
        Err(e) => match e {
            crate::crypto::encryption::EncryptionError::ReplayAttack { .. } => -10,
            crate::crypto::encryption::EncryptionError::OutOfOrder { .. } => -11,
            crate::crypto::encryption::EncryptionError::SequenceTooFar { .. } => -12,
            crate::crypto::encryption::EncryptionError::DecryptionFailed => -13,
            crate::crypto::encryption::EncryptionError::InvalidKeyLength => -14,
            _ => -1,
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_derive_receive_key_at_sequence(
    root_key: *const u8,
    sender_sequence: u64,
    our_onion: *const c_char,
    their_onion: *const c_char,
    chain_key_out: *mut u8,
) -> i32 {
    if chain_key_out.is_null() {
        return -1;
    }
    let key = match copy_fixed::<32>(root_key) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let our = match cstr_to_string(our_onion) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let their = match cstr_to_string(their_onion) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match derive_receive_key_at_sequence(&key, sender_sequence, &our, &their) {
        Ok(out) => {
            ptr::copy_nonoverlapping(out.as_ptr(), chain_key_out, 32);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_create_ping_token(
    sender_seed: *const u8,
    recipient_pubkey: *const u8,
    sender_x25519: *const u8,
    recipient_x25519: *const u8,
    token_out: *mut u8,
    token_len_out: *mut u32,
) -> i32 {
    let seed = match copy_fixed::<32>(sender_seed) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let recip_ed = match copy_fixed::<32>(recipient_pubkey) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let sx = match copy_fixed::<32>(sender_x25519) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let rx = match copy_fixed::<32>(recipient_x25519) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let sender_key = SigningKey::from_bytes(&seed);
    let recip_vk = match VerifyingKey::from_bytes(&recip_ed) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match PingToken::new(&sender_key, &recip_vk, &sx, &rx).and_then(|p| p.to_bytes()) {
        Ok(bytes) => write_bytes_with_len(token_out, token_len_out, &bytes),
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_create_pong_token(
    ping_token: *const u8,
    ping_token_len: u32,
    recipient_seed: *const u8,
    authenticated: bool,
    token_out: *mut u8,
    token_len_out: *mut u32,
) -> i32 {
    let ping_bytes = match bytes_from_ptr(ping_token, ping_token_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let seed = match copy_fixed::<32>(recipient_seed) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let recip_key = SigningKey::from_bytes(&seed);
    let ping = match PingToken::from_bytes(ping_bytes) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match PongToken::new(&ping, &recip_key, authenticated, false).and_then(|p| p.to_bytes()) {
        Ok(bytes) => write_bytes_with_len(token_out, token_len_out, &bytes),
        Err(_) => -1,
    }
}

/// Extract the hex-encoded pingId (nonce) from a decrypted PingToken.
/// Returns the number of bytes written to `ping_id_out` (48 for a valid token), or -1 on error.
/// The caller must provide a buffer of at least 48 bytes.
#[no_mangle]
pub unsafe extern "C" fn securelegion_extract_ping_id(
    ping_token: *const u8,
    ping_token_len: u32,
    ping_id_out: *mut u8,
    ping_id_len_out: *mut u32,
) -> i32 {
    let ping_bytes = match bytes_from_ptr(ping_token, ping_token_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let token = match PingToken::from_bytes(ping_bytes) {
        Ok(t) => t,
        Err(_) => return -1,
    };
    let hex_id = hex::encode(&token.nonce);
    write_bytes_with_len(ping_id_out, ping_id_len_out, hex_id.as_bytes())
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_generate_hybrid_kem_keypair(
    seed: *const u8,
    x25519_pub_out: *mut u8,
    x25519_sec_out: *mut u8,
    kyber_pub_out: *mut u8,
    kyber_sec_out: *mut u8,
) -> i32 {
    if x25519_pub_out.is_null()
        || x25519_sec_out.is_null()
        || kyber_pub_out.is_null()
        || kyber_sec_out.is_null()
    {
        return -1;
    }
    let seed_arr = match copy_fixed::<32>(seed) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match generate_hybrid_keypair_from_seed(&seed_arr) {
        Ok(kp) => {
            ptr::copy_nonoverlapping(kp.x25519_public.as_ptr(), x25519_pub_out, 32);
            ptr::copy_nonoverlapping(kp.x25519_secret.as_ptr(), x25519_sec_out, 32);
            ptr::copy_nonoverlapping(kp.kyber_public.as_ptr(), kyber_pub_out, 1568);
            ptr::copy_nonoverlapping(kp.kyber_secret.as_ptr(), kyber_sec_out, 3168);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_hybrid_encapsulate(
    their_x25519_pub: *const u8,
    their_kyber_pub: *const u8,
    shared_secret_out: *mut u8,
    ciphertext_out: *mut u8,
) -> i32 {
    if shared_secret_out.is_null() || ciphertext_out.is_null() {
        return -1;
    }
    let x = match copy_fixed::<32>(their_x25519_pub) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let k = match copy_fixed::<1568>(their_kyber_pub) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match hybrid_encapsulate(&x, &k) {
        Ok((secret, ct)) => {
            let ct_bytes = ct.to_bytes();
            ptr::copy_nonoverlapping(secret.as_ptr(), shared_secret_out, 64);
            ptr::copy_nonoverlapping(ct_bytes.as_ptr(), ciphertext_out, 1600);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_hybrid_decapsulate(
    ciphertext: *const u8,
    our_x25519_sec: *const u8,
    our_kyber_sec: *const u8,
    shared_secret_out: *mut u8,
) -> i32 {
    if shared_secret_out.is_null() {
        return -1;
    }
    let ct_bytes = match copy_fixed::<1600>(ciphertext) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let x_sec = match copy_fixed::<32>(our_x25519_sec) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let k_sec = match copy_fixed::<3168>(our_kyber_sec) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let ct = match HybridCiphertext::from_bytes(&ct_bytes) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match hybrid_decapsulate(&x_sec, &k_sec, &ct) {
        Ok(secret) => {
            ptr::copy_nonoverlapping(secret.as_ptr(), shared_secret_out, 64);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_tor_start_fr_server(port: u32) -> i32 {
    let port_u16 = if port == 0 { 8081 } else { port as u16 };
    if FR_SERVER_STARTED.load(Ordering::SeqCst) {
        return 0;
    }
    let res = RUNTIME.block_on(async {
        let ep = get_endpoint().await;
        ep.start(port_u16).await
    });
    match res {
        Ok(_) => {
            FR_SERVER_STARTED.store(true, Ordering::SeqCst);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_tor_stop_fr_server() {
    if !FR_SERVER_STARTED.load(Ordering::SeqCst) {
        return;
    }
    RUNTIME.block_on(async {
        let ep = get_endpoint().await;
        ep.stop().await;
    });
    FR_SERVER_STARTED.store(false, Ordering::SeqCst);
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_tor_serve_contact_card(
    encrypted_card: *const u8,
    card_len: u32,
    cid: *const c_char,
) -> i32 {
    let card = match bytes_from_ptr(encrypted_card, card_len as usize) {
        Ok(v) => v.to_vec(),
        Err(_) => return -1,
    };
    let cid_s = match cstr_to_string(cid) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    RUNTIME.block_on(async {
        let ep = get_endpoint().await;
        ep.set_contact_card(card, cid_s).await;
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_compute_onion_address(
    ed25519_seed: *const u8,
    seed_len: u32,
    address_out: *mut c_char,
    address_buf_len: u32,
) -> i32 {
    if seed_len != 32 || address_out.is_null() || address_buf_len == 0 {
        return -1;
    }
    let seed = match copy_fixed::<32>(ed25519_seed) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let onion = compute_onion_address_from_ed25519_seed(&seed);
    let need = onion.len() + 1;
    if need > address_buf_len as usize || onion.as_bytes().contains(&0) {
        return -1;
    }
    ptr::copy_nonoverlapping(onion.as_ptr(), address_out as *mut u8, onion.len());
    *(address_out.add(onion.len())) = 0;
    onion.len() as i32
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_create_ack_wire_bytes(
    item_id: *const c_char,
    ack_type: *const c_char,
    ed25519_seed: *const u8,
    our_x25519_priv: *const u8,
    our_x25519_pub: *const u8,
    recipient_x25519_pub: *const u8,
    wire_out: *mut u8,
    wire_len_out: *mut u32,
) -> i32 {
    let item_id_s = match cstr_to_string(item_id) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let ack_type_s = match cstr_to_string(ack_type) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let seed = match copy_fixed::<32>(ed25519_seed) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let our_priv = match copy_fixed::<32>(our_x25519_priv) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let our_pub = match copy_fixed::<32>(our_x25519_pub) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let recip_pub = match copy_fixed::<32>(recipient_x25519_pub) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let signing = SigningKey::from_bytes(&seed);
    let ack = match DeliveryAck::new(&item_id_s, &ack_type_s, &signing) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let ack_bytes = match ack.to_bytes() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let shared = match derive_shared_secret(&our_priv, &recip_pub) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let encrypted = match encrypt_message(&ack_bytes, &shared) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let mut wire = Vec::with_capacity(1 + 32 + encrypted.len());
    wire.push(MSG_TYPE_DELIVERY_CONFIRMATION);
    wire.extend_from_slice(&our_pub);
    wire.extend_from_slice(&encrypted);
    write_bytes_with_len(wire_out, wire_len_out, &wire)
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_decrypt_and_verify_ack(
    wire_bytes: *const u8,
    wire_len: u32,
    our_x25519_priv: *const u8,
    item_id_out: *mut c_char,
    ack_type_out: *mut c_char,
) -> i32 {
    let wire = match bytes_from_ptr(wire_bytes, wire_len as usize) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let our_priv = match copy_fixed::<32>(our_x25519_priv) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let offset = if !wire.is_empty() && wire[0] == MSG_TYPE_DELIVERY_CONFIRMATION {
        1usize
    } else {
        0usize
    };
    if wire.len() < offset + 32 + 16 {
        return -1;
    }
    let mut sender_pub = [0u8; 32];
    sender_pub.copy_from_slice(&wire[offset..offset + 32]);
    let encrypted = &wire[offset + 32..];

    let shared = match derive_shared_secret(&our_priv, &sender_pub) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let ack_bytes = match decrypt_message(encrypted, &shared) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let ack = match DeliveryAck::from_bytes(&ack_bytes) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let signer = match VerifyingKey::from_bytes(&ack.sender_ed25519_signing_pubkey) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    if !ack.verify(&signer).unwrap_or(false) {
        return -1;
    }

    if write_cstr_to_buf(item_id_out, &ack.item_id, 255) != 0 {
        return -1;
    }
    if write_cstr_to_buf(ack_type_out, &ack.ack_type, 63) != 0 {
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_load_group(
    group_id_hex: *const c_char,
    serialized_ops: *const u8,
    serialized_ops_len: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid_s = match cstr_to_string(group_id_hex) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let gid = match GroupID::from_hex(&gid_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let data = bytes_from_ptr_opt(serialized_ops, serialized_ops_len as usize);
        let ops =
            match decode_length_prefixed_ops(data, HARD_CAP_OPS_PER_GROUP, MAX_SERIALIZED_OP_BYTES)
            {
                Ok(v) => v,
                Err(_) => return -1,
            };
        let state = match GroupState::rebuild_from_ops(gid, &ops) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        get_groups()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(gid, state);
        0
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_unload_group(group_id_hex: *const c_char) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid_s = match cstr_to_string(group_id_hex) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let gid = match GroupID::from_hex(&gid_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        get_groups()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&gid);
        get_lamport_map()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&gid);
        0
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_apply_ops(
    group_id_hex: *const c_char,
    serialized_ops: *const u8,
    serialized_ops_len: u32,
    result_json_out: *mut u8,
    result_json_len: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid_s = match cstr_to_string(group_id_hex) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let gid = match GroupID::from_hex(&gid_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let data = match bytes_from_ptr(serialized_ops, serialized_ops_len as usize) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let ops = match decode_length_prefixed_ops(
            data,
            MAX_OPS_PER_APPLY_BATCH,
            MAX_SERIALIZED_OP_BYTES,
        ) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let mut groups = get_groups().lock().unwrap_or_else(|e| e.into_inner());
        let state = match groups.get_mut(&gid) {
            Some(v) => v,
            None => return -1,
        };
        let mut applied = 0u64;
        let mut rejected = 0u64;
        for op in &ops {
            match state.apply_op(op) {
                Ok(true) => applied += 1,
                Ok(false) => {}
                Err(_) => rejected += 1,
            }
        }
        let json = serde_json::json!({
            "applied": applied,
            "rejected": rejected,
            "limit_status": format!("{:?}", state.limit_status()),
        })
        .to_string();
        write_bytes_with_len(result_json_out, result_json_len, json.as_bytes())
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_create_op(
    group_id_hex: *const c_char,
    op_type_str: *const c_char,
    params_json: *const c_char,
    author_pubkey: *const u8,
    author_privkey: *const u8,
    result_out: *mut u8,
    result_len: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid_s = match cstr_to_string(group_id_hex) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let gid = match GroupID::from_hex(&gid_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let otype_s = match cstr_to_string(op_type_str) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let otype = match parse_op_type(&otype_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let params_s = match cstr_to_string(params_json) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let params: serde_json::Value = match serde_json::from_str(&params_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let pub_key = match copy_fixed::<32>(author_pubkey) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let priv_key = match copy_fixed::<32>(author_privkey) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let author_device = DeviceID::from_pubkey(&pub_key);

        let mut groups = get_groups().lock().unwrap_or_else(|e| e.into_inner());
        if otype == OpType::GroupCreate && !groups.contains_key(&gid) {
            groups.insert(gid, GroupState::new(gid));
        }
        let state = match groups.get_mut(&gid) {
            Some(v) => v,
            None => return -1,
        };

        let lamport = if otype == OpType::GroupCreate {
            1
        } else {
            next_lamport(&gid, state)
        };
        let op_nonce: u64 = rand::random();

        let envelope = match otype {
            OpType::GroupCreate => {
                let group_name = params["group_name"].as_str().unwrap_or("").to_string();
                let secret = B64
                    .decode(params["encrypted_group_secret_b64"].as_str().unwrap_or(""))
                    .unwrap_or_default();
                let payload = GroupCreatePayload {
                    group_name,
                    encrypted_group_secret: secret,
                };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MemberInvite => {
                let invited_pubkey = match hex_to_32(
                    params["invited_pubkey_hex"].as_str().unwrap_or(""),
                    "invited_pubkey",
                ) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let role = match parse_role(params["role"].as_str().unwrap_or("Member")) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let secret = B64
                    .decode(params["encrypted_group_secret_b64"].as_str().unwrap_or(""))
                    .unwrap_or_default();
                let invited_device_id = DeviceID::from_pubkey(&invited_pubkey);
                let payload = MemberInvitePayload {
                    invited_device_id,
                    invited_pubkey,
                    role,
                    encrypted_group_secret: secret,
                };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MemberAccept => {
                let invite_op_id =
                    match OpID::from_hex(params["invite_op_id_hex"].as_str().unwrap_or("")) {
                        Ok(v) => v,
                        Err(_) => return -1,
                    };
                let payload = MemberAcceptPayload { invite_op_id };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MemberRemove => {
                let target_pk = match hex_to_32(
                    params["target_pubkey_hex"].as_str().unwrap_or(""),
                    "target_pubkey",
                ) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let reason = match parse_remove_reason(params["reason"].as_str().unwrap_or("Kick"))
                {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let target_device_id = DeviceID::from_pubkey(&target_pk);
                let ban = params["ban"].as_bool().unwrap_or(false);
                let payload = MemberRemovePayload {
                    target_device_id,
                    reason,
                    ban,
                };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::RoleSet => {
                let target_pk = match hex_to_32(
                    params["target_pubkey_hex"].as_str().unwrap_or(""),
                    "target_pubkey",
                ) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let new_role = match parse_role(params["new_role"].as_str().unwrap_or("Member")) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let target_device_id = DeviceID::from_pubkey(&target_pk);
                let admin_rights = params.get("admin_rights").and_then(|ar| {
                    if ar.is_null() || !ar.is_object() {
                        return None;
                    }
                    Some(AdminRights {
                        can_invite: ar["can_invite"].as_bool().unwrap_or(false),
                        can_remove: ar["can_remove"].as_bool().unwrap_or(false),
                        can_change_info: ar["can_change_info"].as_bool().unwrap_or(false),
                        can_delete_messages: ar["can_delete_messages"].as_bool().unwrap_or(false),
                        can_pin_messages: ar["can_pin_messages"].as_bool().unwrap_or(false),
                        can_add_admins: ar["can_add_admins"].as_bool().unwrap_or(false),
                    })
                });
                let custom_title = params["custom_title"].as_str().map(|s| s.to_string());
                let payload = RoleSetPayload {
                    target_device_id,
                    new_role,
                    admin_rights,
                    custom_title,
                };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MsgAdd => {
                let msg_id = generate_msg_id(&author_device, lamport, op_nonce);
                let ciphertext = B64
                    .decode(params["ciphertext_b64"].as_str().unwrap_or(""))
                    .unwrap_or_default();
                let nonce = match b64_to_24(params["nonce_b64"].as_str().unwrap_or(""), "nonce") {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let payload = MsgAddPayload {
                    msg_id,
                    ciphertext,
                    nonce,
                };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MsgEdit => {
                let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id")
                {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let new_ciphertext = B64
                    .decode(params["new_ciphertext_b64"].as_str().unwrap_or(""))
                    .unwrap_or_default();
                let nonce = match b64_to_24(params["nonce_b64"].as_str().unwrap_or(""), "nonce") {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let payload = MsgEditPayload {
                    msg_id,
                    new_ciphertext,
                    nonce,
                };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MsgDelete => {
                let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id")
                {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let payload = MsgDeletePayload { msg_id };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::ReactionSet => {
                let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id")
                {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let emoji = params["emoji"].as_str().unwrap_or("").to_string();
                let present = params["present"].as_bool().unwrap_or(true);
                let payload = ReactionSetPayload {
                    msg_id,
                    emoji,
                    present,
                };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MetadataSet => {
                let key = match parse_metadata_key(params["key"].as_str().unwrap_or("")) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let value = B64
                    .decode(params["value_b64"].as_str().unwrap_or(""))
                    .unwrap_or_default();
                let payload = MetadataSetPayload { key, value };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::MemberUnban => {
                let target_pk = match hex_to_32(
                    params["target_pubkey_hex"].as_str().unwrap_or(""),
                    "target_pubkey",
                ) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                let target_device_id = DeviceID::from_pubkey(&target_pk);
                let payload = MemberUnbanPayload { target_device_id };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
            OpType::GroupDelete => {
                let reason = params["reason"].as_str().map(|s| s.to_string());
                let payload = GroupDeletePayload { reason };
                OpEnvelope::create_signed(
                    gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key,
                )
            }
        };

        let envelope = match envelope {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if state.apply_op(&envelope).is_err() {
            return -1;
        }
        {
            let mut lmap = get_lamport_map().lock().unwrap_or_else(|e| e.into_inner());
            lmap.entry(gid)
                .and_modify(|l| *l = (*l).max(lamport))
                .or_insert(lamport);
        }
        let op_bytes = match envelope.to_bytes() {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let mut json = serde_json::json!({
            "op_bytes_b64": B64.encode(&op_bytes),
            "op_id": envelope.op_id.to_hex(),
            "op_type": otype_s,
            "lamport": lamport,
        });
        if otype == OpType::MsgAdd {
            let msg_id = generate_msg_id(&author_device, lamport, op_nonce);
            json["msg_id_hex"] = serde_json::Value::String(hex::encode(msg_id));
        }
        write_bytes_with_len(result_out, result_len, json.to_string().as_bytes())
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_query(
    group_id_hex: *const c_char,
    query_type: *const c_char,
    params_json: *const c_char,
    result_out: *mut u8,
    result_len: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid_s = match cstr_to_string(group_id_hex) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let gid = match GroupID::from_hex(&gid_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let qt = match cstr_to_string(query_type) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let params_s = cstr_to_string(params_json).unwrap_or_else(|_| "{}".to_string());

        let groups = get_groups().lock().unwrap_or_else(|e| e.into_inner());
        let state = match groups.get(&gid) {
            Some(v) => v,
            None => return -1,
        };

        let json = match qt.as_str() {
            "members" => {
                let members: Vec<serde_json::Value> = state
                    .membership
                    .members()
                    .iter()
                    .map(|(did, entry)| {
                        serde_json::json!({
                            "device_id": did.to_hex(),
                            "pubkey_hex": hex::encode(entry.pubkey),
                            "role": format!("{:?}", entry.role),
                            "accepted": entry.accepted,
                            "removed": entry.removed,
                            "banned": entry.banned,
                            "rekey_required": entry.rekey_required,
                            "invited_by_op_id": entry.invited_by.to_hex(),
                            "encrypted_group_secret_b64": B64.encode(&entry.encrypted_group_secret),
                            "admin_rights": entry.admin_rights.map(|ar| serde_json::json!({
                                "can_invite": ar.can_invite,
                                "can_remove": ar.can_remove,
                                "can_change_info": ar.can_change_info,
                                "can_delete_messages": ar.can_delete_messages,
                                "can_pin_messages": ar.can_pin_messages,
                                "can_add_admins": ar.can_add_admins,
                            })),
                            "custom_title": entry.custom_title,
                        })
                    })
                    .collect();
                serde_json::Value::Array(members)
            }
            "messages" => {
                let msgs: Vec<serde_json::Value> = state.renderable_messages().iter().map(|m| message_to_json(m)).collect();
                serde_json::Value::Array(msgs)
            }
            "messages_after" => {
                let params: serde_json::Value = serde_json::from_str(&params_s).unwrap_or_default();
                let after_lamport = params["after_lamport"].as_u64().unwrap_or(0);
                let limit = params["limit"].as_u64().unwrap_or(50) as usize;
                let mut msgs: Vec<&MessageEntry> = state
                    .renderable_messages()
                    .into_iter()
                    .filter(|m| m.create_op.lamport > after_lamport)
                    .collect();
                msgs.sort_by(|a, b| a.create_op.cmp(&b.create_op));
                msgs.truncate(limit);
                serde_json::Value::Array(msgs.iter().map(|m| message_to_json(m)).collect())
            }
            "metadata" => {
                let mut obj = serde_json::Map::new();
                if let Some(name) = state.metadata.name() {
                    obj.insert("name".into(), serde_json::Value::String(name.to_string()));
                }
                if let Some(topic) = state.metadata.topic() {
                    obj.insert("topic".into(), serde_json::Value::String(topic.to_string()));
                }
                if let Some(avatar) = state.metadata.get(&MetadataKey::Avatar) {
                    obj.insert("avatar_b64".into(), serde_json::Value::String(B64.encode(&avatar.value)));
                }
                for (key, name) in [
                    (MetadataKey::AllowMemberSendMessages, "allow_member_send_messages"),
                    (MetadataKey::AllowMemberInvites, "allow_member_invites"),
                    (MetadataKey::AllowMemberPin, "allow_member_pin"),
                    (MetadataKey::AllowMemberChangeInfo, "allow_member_change_info"),
                ] {
                    if let Some(v) = state.metadata.get_bool(key) {
                        obj.insert(name.into(), serde_json::Value::Bool(v));
                    }
                }
                serde_json::Value::Object(obj)
            }
            "heads" => {
                let heads: Vec<String> = state.heads.iter().map(|h| h.to_hex()).collect();
                let per_author: serde_json::Map<String, serde_json::Value> = state
                    .max_lamport
                    .iter()
                    .map(|(did, l)| (did.to_hex(), serde_json::Value::Number((*l).into())))
                    .collect();
                serde_json::json!({ "heads": heads, "per_author_lamport": per_author })
            }
            "state_hash" => serde_json::json!({ "hash": hex::encode(state.state_hash()) }),
            "group_status" => serde_json::json!({
                "deleted": state.group_deleted,
                "delete_reason": state.delete_reason,
            }),
            "limit_status" => serde_json::json!({ "status": format!("{:?}", state.limit_status()), "op_count": state.op_count }),
            _ => return -1,
        };

        write_bytes_with_len(result_out, result_len, json.to_string().as_bytes())
    })).unwrap_or(-1)
}

/// Compute DeviceID from Ed25519 public key — BLAKE3(pubkey)[0..16] → 32 hex chars.
/// Swift uses this to match the author field returned by CRDT queries.
#[no_mangle]
pub unsafe extern "C" fn securelegion_device_id_from_pubkey(
    pubkey: *const u8, // 32-byte Ed25519 public key
    out_buf: *mut u8,  // buffer for hex string output
    out_len: *mut u32, // set to actual length written
) -> i32 {
    if pubkey.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let pk: [u8; 32] = {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(pubkey, buf.as_mut_ptr(), 32);
        buf
    };
    let did = DeviceID::from_pubkey(&pk);
    let hex_str = did.to_hex();
    let hex_bytes = hex_str.as_bytes();
    if hex_bytes.len() > 64 {
        return -1;
    }
    std::ptr::copy_nonoverlapping(hex_bytes.as_ptr(), out_buf, hex_bytes.len());
    *out_len = hex_bytes.len() as u32;
    0
}

// ----- Group wire-protocol helpers for iOS -----

/// Validate that `data` consists of well-formed length-prefixed op frames:
/// [4-byte BE len][op bytes]{repeat}. Returns 1 for valid (including empty),
/// 0 for malformed.
#[no_mangle]
pub unsafe extern "C" fn securelegion_validate_packed_ops(
    data: *const u8,
    data_len: u32,
) -> i32 {
    if data.is_null() && data_len > 0 {
        return 0;
    }
    if data_len == 0 {
        return 1;
    }
    let bytes = std::slice::from_raw_parts(data, data_len as usize);
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&bytes[offset..offset + 4]);
        let len = u32::from_be_bytes(len_buf) as usize;
        offset += 4;
        if len == 0 || len > MAX_SERIALIZED_OP_BYTES {
            return 0;
        }
        if offset + len > bytes.len() {
            return 0;
        }
        offset += len;
    }
    if offset == bytes.len() { 1 } else { 0 }
}

/// Encrypt a group message: XChaCha20-Poly1305 with random nonce.
/// Returns JSON {"ciphertext_b64":"...","nonce_b64":"..."} in result_out.
#[no_mangle]
pub unsafe extern "C" fn securelegion_encrypt_group_message(
    plaintext: *const u8,
    plaintext_len: u32,
    group_secret: *const u8,
    result_json_out: *mut u8,
    result_json_len: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let pt = match bytes_from_ptr(plaintext, plaintext_len as usize) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let key = match copy_fixed::<32>(group_secret) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let cipher = match XChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = match cipher.encrypt(nonce, pt) {
            Ok(ct) => ct,
            Err(_) => return -1,
        };
        let json = serde_json::json!({
            "ciphertext_b64": B64.encode(&ciphertext),
            "nonce_b64": B64.encode(&nonce_bytes),
        });
        write_bytes_with_len(result_json_out, result_json_len, json.to_string().as_bytes())
    }))
    .unwrap_or(-1)
}

/// Decrypt a group message given base64-encoded ciphertext and nonce.
/// Returns plaintext bytes in plaintext_out.
#[no_mangle]
pub unsafe extern "C" fn securelegion_decrypt_group_message(
    ciphertext_b64: *const c_char,
    nonce_b64: *const c_char,
    group_secret: *const u8,
    plaintext_out: *mut u8,
    plaintext_len_out: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let ct_str = match cstr_to_string(ciphertext_b64) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let nonce_str = match cstr_to_string(nonce_b64) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let ct = match B64.decode(&ct_str) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let nonce_bytes = match B64.decode(&nonce_str) {
            Ok(v) if v.len() == 24 => {
                let mut arr = [0u8; 24];
                arr.copy_from_slice(&v);
                arr
            }
            _ => return -1,
        };
        let key = match copy_fixed::<32>(group_secret) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let cipher = match XChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = match cipher.decrypt(nonce, ct.as_ref()) {
            Ok(pt) => pt,
            Err(_) => return -1,
        };
        write_bytes_with_len(plaintext_out, plaintext_len_out, &plaintext)
    }))
    .unwrap_or(-1)
}

/// Check if a loaded group needs key rotation. Returns 1 if rekey needed,
/// 0 if not, -1 if group not loaded.
#[no_mangle]
pub unsafe extern "C" fn securelegion_needs_rekey(
    group_id_hex: *const c_char,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid_s = match cstr_to_string(group_id_hex) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let gid = match GroupID::from_hex(&gid_s) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let groups = get_groups().lock().unwrap_or_else(|e| e.into_inner());
        let state = match groups.get(&gid) {
            Some(s) => s,
            None => return -1,
        };
        if state.membership.needs_rekey() { 1 } else { 0 }
    }))
    .unwrap_or(-1)
}

/// Strip wire framing from an inbound group ops body. Handles all 4 format
/// combinations: +/-24-byte ping_id prefix, +/-64-byte transport sig suffix.
/// Returns [groupId:32][packedOps...] in body_out as one contiguous buffer.
/// Returns 0 on success, -1 if no valid format found.
#[no_mangle]
pub unsafe extern "C" fn securelegion_parse_group_ops_body(
    data: *const u8,
    data_len: u32,
    body_out: *mut u8,
    body_len_out: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let raw = match bytes_from_ptr(data, data_len as usize) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        for (strip_sig, strip_ping) in [(true, false), (true, true), (false, true), (false, false)] {
            let mut body = raw;
            if strip_ping && body.len() >= 24 {
                body = &body[24..];
            }
            if strip_sig && body.len() >= 64 {
                body = &body[..body.len() - 64];
            }
            if body.len() < 32 {
                continue;
            }
            let potential_ops = &body[32..];
            let valid = if potential_ops.is_empty() {
                false
            } else {
                securelegion_validate_packed_ops(potential_ops.as_ptr(), potential_ops.len() as u32) == 1
            };
            if valid {
                return write_bytes_with_len(body_out, body_len_out, body);
            }
        }
        -1
    }))
    .unwrap_or(-1)
}

/// Build a complete group ops wire frame:
/// [type=0x30][x25519_pub:32][groupId:32][packedOps][transportSig:64]
/// `packed_ops` is already length-prefixed: [4BE len][op bytes]...
#[no_mangle]
pub unsafe extern "C" fn securelegion_pack_group_ops_frame(
    group_id: *const u8,            // 32 bytes raw
    packed_ops: *const u8,
    packed_ops_len: u32,
    sender_x25519_pub: *const u8,   // 32 bytes
    sender_ed25519_seed: *const u8, // 32 bytes (signs body)
    frame_out: *mut u8,
    frame_len_out: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid = match bytes_from_ptr(group_id, 32) { Ok(v) => v, Err(_) => return -1 };
        let ops = bytes_from_ptr_opt(packed_ops, packed_ops_len as usize);
        let x25519 = match bytes_from_ptr(sender_x25519_pub, 32) { Ok(v) => v, Err(_) => return -1 };
        let seed = match copy_fixed::<32>(sender_ed25519_seed) { Ok(v) => v, Err(_) => return -1 };

        let mut body = Vec::with_capacity(32 + ops.len());
        body.extend_from_slice(gid);
        body.extend_from_slice(ops);

        let sig = match sign_data(&body, &seed) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let mut frame = Vec::with_capacity(1 + 32 + body.len() + 64);
        frame.push(0x30u8);
        frame.extend_from_slice(x25519);
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&sig);

        write_bytes_with_len(frame_out, frame_len_out, &frame)
    }))
    .unwrap_or(-1)
}

/// Parse a routing update payload and return JSON array of peer entries.
/// Input: raw body after type+x25519 strip: [groupId:32][senderEd:32][innerSig:64][count:u16BE][entries...]
/// Returns JSON: {"group_id_hex":"...","sender_ed_hex":"...","verified":bool,"peers":[{...}]}
#[no_mangle]
pub unsafe extern "C" fn securelegion_parse_routing_update(
    data: *const u8,
    data_len: u32,
    result_json_out: *mut u8,
    result_json_len: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let raw = match bytes_from_ptr(data, data_len as usize) { Ok(v) => v, Err(_) => return -1 };
        if raw.len() < 32 + 32 + 64 + 2 { return -1; }

        let group_id_hex = hex::encode(&raw[..32]);
        let sender_ed = &raw[32..64];
        let sender_ed_hex = hex::encode(sender_ed);
        let inner_sig = &raw[64..128];
        let inner = &raw[128..];

        // Verify inner signature
        let verified = verify_signature(inner, inner_sig, sender_ed).unwrap_or(false);

        if inner.len() < 2 { return -1; }
        let count = u16::from_be_bytes([inner[0], inner[1]]) as usize;
        let mut offset = 2usize;
        let mut peers = Vec::new();

        for _ in 0..count {
            if offset + 32 + 32 + 2 > inner.len() { break; }
            let ed_hex = hex::encode(&inner[offset..offset + 32]);
            offset += 32;
            let x25519_hex = hex::encode(&inner[offset..offset + 32]);
            offset += 32;

            if offset + 2 > inner.len() { break; }
            let onion_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
            offset += 2;
            if offset + onion_len > inner.len() { break; }
            let onion = String::from_utf8_lossy(&inner[offset..offset + onion_len]).to_string();
            offset += onion_len;

            if offset + 2 > inner.len() { break; }
            let name_len = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
            offset += 2;
            if offset + name_len > inner.len() { break; }
            let name = String::from_utf8_lossy(&inner[offset..offset + name_len]).to_string();
            offset += name_len;

            peers.push(serde_json::json!({
                "ed25519_hex": ed_hex,
                "x25519_hex": x25519_hex,
                "onion": onion,
                "display_name": name,
            }));
        }

        let result = serde_json::json!({
            "group_id_hex": group_id_hex,
            "sender_ed_hex": sender_ed_hex,
            "verified": verified,
            "peers": peers,
        });
        write_bytes_with_len(result_json_out, result_json_len, result.to_string().as_bytes())
    }))
    .unwrap_or(-1)
}

/// Build a routing update wire frame:
/// [type=0x35][x25519:32][groupId:32][senderEd:32][innerSig:64][count:u16BE][entries...][transportSig:64]
/// `entries_json` is a JSON array of {"ed25519_hex","x25519_hex","onion","display_name"}.
#[no_mangle]
pub unsafe extern "C" fn securelegion_build_routing_update(
    group_id: *const u8,            // 32 bytes raw
    entries_json: *const c_char,    // JSON array
    sender_x25519_pub: *const u8,   // 32 bytes
    sender_ed25519_pub: *const u8,  // 32 bytes
    sender_ed25519_seed: *const u8, // 32 bytes
    frame_out: *mut u8,
    frame_len_out: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid = match bytes_from_ptr(group_id, 32) { Ok(v) => v, Err(_) => return -1 };
        let x25519 = match bytes_from_ptr(sender_x25519_pub, 32) { Ok(v) => v, Err(_) => return -1 };
        let ed_pub = match bytes_from_ptr(sender_ed25519_pub, 32) { Ok(v) => v, Err(_) => return -1 };
        let seed = match copy_fixed::<32>(sender_ed25519_seed) { Ok(v) => v, Err(_) => return -1 };
        let json_str = match cstr_to_string(entries_json) { Ok(v) => v, Err(_) => return -1 };

        let entries: Vec<serde_json::Value> = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(_) => return -1,
        };

        // Serialize entries first, then write actual count
        let mut entry_data = Vec::new();
        let mut serialized_count: u16 = 0;

        for entry in &entries {
            let ed_hex = entry["ed25519_hex"].as_str().unwrap_or("");
            let x_hex = entry["x25519_hex"].as_str().unwrap_or("");
            let onion = entry["onion"].as_str().unwrap_or("");
            let name = entry["display_name"].as_str().unwrap_or("");

            let ed_bytes = match hex::decode(ed_hex) { Ok(v) if v.len() == 32 => v, _ => continue };
            let x_bytes = match hex::decode(x_hex) { Ok(v) if v.len() == 32 => v, _ => continue };

            let onion_bytes = onion.trim().to_lowercase().as_bytes().to_vec();
            let name_bytes = name.as_bytes().to_vec();

            entry_data.extend_from_slice(&ed_bytes);
            entry_data.extend_from_slice(&x_bytes);
            entry_data.extend_from_slice(&(onion_bytes.len() as u16).to_be_bytes());
            entry_data.extend_from_slice(&onion_bytes);
            entry_data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            entry_data.extend_from_slice(&name_bytes);
            serialized_count += 1;
        }

        // Build inner: [count:u16BE][entries...] -- count matches actual serialized entries
        let mut inner = Vec::new();
        inner.extend_from_slice(&serialized_count.to_be_bytes());
        inner.extend_from_slice(&entry_data);

        let inner_sig = match sign_data(&inner, &seed) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let mut body = Vec::new();
        body.extend_from_slice(gid);
        body.extend_from_slice(ed_pub);
        body.extend_from_slice(&inner_sig);
        body.extend_from_slice(&inner);

        let transport_sig = match sign_data(&body, &seed) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        // Full frame: [0x35][x25519:32][body][transportSig:64]
        let mut frame = Vec::new();
        frame.push(0x35u8);
        frame.extend_from_slice(x25519);
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&transport_sig);

        write_bytes_with_len(frame_out, frame_len_out, &frame)
    }))
    .unwrap_or(-1)
}

/// Build a routing request wire frame:
/// [type=0x36][x25519:32][groupId:32][senderEd:32][innerSig:64][requestedEd:32][transportSig:64]
#[no_mangle]
pub unsafe extern "C" fn securelegion_build_routing_request(
    group_id: *const u8,              // 32 bytes
    requested_ed25519: *const u8,     // 32 bytes (all-zero = request full directory)
    sender_x25519_pub: *const u8,     // 32 bytes
    sender_ed25519_pub: *const u8,    // 32 bytes
    sender_ed25519_seed: *const u8,   // 32 bytes
    frame_out: *mut u8,
    frame_len_out: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid = match bytes_from_ptr(group_id, 32) { Ok(v) => v, Err(_) => return -1 };
        let requested = match bytes_from_ptr(requested_ed25519, 32) { Ok(v) => v, Err(_) => return -1 };
        let x25519 = match bytes_from_ptr(sender_x25519_pub, 32) { Ok(v) => v, Err(_) => return -1 };
        let ed_pub = match bytes_from_ptr(sender_ed25519_pub, 32) { Ok(v) => v, Err(_) => return -1 };
        let seed = match copy_fixed::<32>(sender_ed25519_seed) { Ok(v) => v, Err(_) => return -1 };

        let inner_sig = match sign_data(requested, &seed) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let mut body = Vec::new();
        body.extend_from_slice(gid);
        body.extend_from_slice(ed_pub);
        body.extend_from_slice(&inner_sig);
        body.extend_from_slice(requested);

        let transport_sig = match sign_data(&body, &seed) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let mut frame = Vec::new();
        frame.push(0x36u8);
        frame.extend_from_slice(x25519);
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&transport_sig);

        write_bytes_with_len(frame_out, frame_len_out, &frame)
    }))
    .unwrap_or(-1)
}

/// Build a sync request wire frame:
/// [type=0x32][x25519:32][groupId:32][senderEd:32][sig(groupId):64][transportSig:64]
#[no_mangle]
pub unsafe extern "C" fn securelegion_pack_sync_request(
    group_id: *const u8,              // 32 bytes
    sender_x25519_pub: *const u8,     // 32 bytes
    sender_ed25519_pub: *const u8,    // 32 bytes
    sender_ed25519_seed: *const u8,   // 32 bytes
    frame_out: *mut u8,
    frame_len_out: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let gid = match bytes_from_ptr(group_id, 32) { Ok(v) => v, Err(_) => return -1 };
        let x25519 = match bytes_from_ptr(sender_x25519_pub, 32) { Ok(v) => v, Err(_) => return -1 };
        let ed_pub = match bytes_from_ptr(sender_ed25519_pub, 32) { Ok(v) => v, Err(_) => return -1 };
        let seed = match copy_fixed::<32>(sender_ed25519_seed) { Ok(v) => v, Err(_) => return -1 };

        let sig = match sign_data(gid, &seed) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let mut body = Vec::new();
        body.extend_from_slice(gid);
        body.extend_from_slice(ed_pub);
        body.extend_from_slice(&sig);

        let transport_sig = match sign_data(&body, &seed) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let mut frame = Vec::new();
        frame.push(0x32u8);
        frame.extend_from_slice(x25519);
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&transport_sig);

        write_bytes_with_len(frame_out, frame_len_out, &frame)
    }))
    .unwrap_or(-1)
}

/// Parse a sync request body (after type+x25519 strip).
/// Handles both iOS format [groupId:32][senderEd:32][sig:64] and
/// Android format [groupId:32][senderX25519:32] (shorter, no sig).
/// Returns JSON: {"group_id_hex":"...","sender_ed_hex":"...","verified":bool}
#[no_mangle]
pub unsafe extern "C" fn securelegion_parse_sync_request(
    data: *const u8,
    data_len: u32,
    result_json_out: *mut u8,
    result_json_len: *mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let raw = match bytes_from_ptr(data, data_len as usize) { Ok(v) => v, Err(_) => return -1 };

        let (group_id_hex, sender_hex, verified);

        if raw.len() >= 128 {
            // iOS format: [groupId:32][senderEd:32][sig:64]
            group_id_hex = hex::encode(&raw[..32]);
            let sender_ed = &raw[32..64];
            sender_hex = hex::encode(sender_ed);
            let sig = &raw[64..128];
            verified = verify_signature(&raw[..32], sig, sender_ed).unwrap_or(false);
        } else if raw.len() >= 64 {
            // Android format: [groupId:32][senderX25519:32] (no sig, verify by contact lookup)
            group_id_hex = hex::encode(&raw[..32]);
            sender_hex = hex::encode(&raw[32..64]);
            verified = false; // caller must verify via contact lookup
        } else {
            return -1;
        }

        let result = serde_json::json!({
            "group_id_hex": group_id_hex,
            "sender_hex": sender_hex,
            "verified": verified,
        });
        write_bytes_with_len(result_json_out, result_json_len, result.to_string().as_bytes())
    }))
    .unwrap_or(-1)
}

// ───── Arti (in-process Tor) FFI for iOS main app ─────

/// Initialize Arti and bootstrap to the Tor network.
/// Blocks the calling thread during bootstrap (~5-30s) — Swift must call from a background thread.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn securelegion_arti_init(data_dir: *const c_char) -> i32 {
    if data_dir.is_null() {
        return -1;
    }
    let data_dir_str = match unsafe { CStr::from_ptr(data_dir) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    match RUNTIME.block_on(crate::network::arti::initialize_arti(&data_dir_str)) {
        Ok(()) => 0,
        Err(e) => {
            let msg = format!("securelegion_arti_init failed: {}", e);
            log::error!("{}", msg);
            set_arti_last_error(msg);
            -1
        }
    }
}

/// Returns the current Arti bootstrap progress (0-100). Non-blocking, safe to poll.
#[no_mangle]
pub extern "C" fn securelegion_arti_bootstrap_status() -> u32 {
    crate::network::tor::BOOTSTRAP_STATUS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Returns true if Arti is initialized and bootstrap >= 100.
#[no_mangle]
pub extern "C" fn securelegion_arti_is_ready() -> bool {
    crate::network::arti::is_arti_ready()
}

/// Get messaging HS publisher status for the in-process Arti client.
#[no_mangle]
pub extern "C" fn securelegion_arti_get_hs_publisher_status(
    out_buf: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let status = crate::network::arti::get_hs_publisher_status();
    unsafe { write_bytes_with_len(out_buf, out_len, status.as_bytes()) }
}

/// Get listener heartbeat timestamp (epoch millis).
#[no_mangle]
pub extern "C" fn securelegion_arti_get_last_listener_heartbeat() -> u64 {
    crate::network::tor::get_last_listener_heartbeat()
}

/// Get HS loop heartbeat timestamp (epoch millis).
#[no_mangle]
pub extern "C" fn securelegion_arti_get_last_hs_loop_heartbeat() -> u64 {
    crate::network::tor::get_last_hs_loop_heartbeat()
}

/// Get HS accept heartbeat timestamp (epoch millis).
#[no_mangle]
pub extern "C" fn securelegion_arti_get_last_hs_accept_heartbeat() -> u64 {
    crate::network::tor::get_last_hs_accept_heartbeat()
}

/// Get last proof timestamp (epoch millis).
#[no_mangle]
pub extern "C" fn securelegion_arti_get_last_tor_proof_ms() -> u64 {
    crate::network::tor::get_last_tor_proof_ms()
}

/// Return the most recent app-side Arti FFI failure string.
#[no_mangle]
pub extern "C" fn securelegion_arti_last_error(out_buf: *mut u8, out_len: *mut u32) -> i32 {
    if out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let guard = ARTI_LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { write_bytes_with_len(out_buf, out_len, guard.as_bytes()) }
}

/// Return targeted Arti bootstrap/cache diagnostics for support exports.
/// Writes a multi-line UTF-8 string to out_buf. Returns 0 on success.
#[no_mangle]
pub extern "C" fn securelegion_arti_bootstrap_diagnostic(out_buf: *mut u8, out_len: *mut u32) -> i32 {
    if out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let diag = crate::network::arti::arti_bootstrap_diagnostic();
    unsafe { write_bytes_with_len(out_buf, out_len, diag.as_bytes()) }
}

/// Purge app-side Arti cache for diagnostics. Caller must shutdown Arti first.
/// Returns a compact summary string in out_buf.
#[no_mangle]
pub extern "C" fn securelegion_arti_purge_cache(
    data_dir: *const c_char,
    out_buf: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if data_dir.is_null() || out_buf.is_null() || out_len.is_null() {
        set_arti_last_error("arti_purge_cache: invalid null argument");
        return -1;
    }
    let data_dir_str = match unsafe { CStr::from_ptr(data_dir) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_arti_last_error("arti_purge_cache: data dir is not valid UTF-8");
            return -1;
        }
    };

    match crate::network::arti::purge_arti_cache_for_data_dir(&data_dir_str) {
        Ok(summary) => unsafe { write_bytes_with_len(out_buf, out_len, summary.as_bytes()) },
        Err(e) => {
            let msg = format!("arti_purge_cache: {}", e);
            log::error!("{}", msg);
            set_arti_last_error(msg.clone());
            unsafe {
                let _ = write_bytes_with_len(out_buf, out_len, msg.as_bytes());
            }
            -1
        }
    }
}

/// Reset Arti guard state: wipe guard/circuit files from state dir, forcing fresh guard selection.
/// Caller must shutdown Arti first. Returns summary string in out_buf.
#[no_mangle]
pub extern "C" fn securelegion_arti_reset_guard_state(
    data_dir: *const c_char,
    out_buf: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if data_dir.is_null() || out_buf.is_null() || out_len.is_null() {
        set_arti_last_error("arti_reset_guard_state: invalid null argument");
        return -1;
    }
    let data_dir_str = match unsafe { CStr::from_ptr(data_dir) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_arti_last_error("arti_reset_guard_state: data dir is not valid UTF-8");
            return -1;
        }
    };

    match crate::network::arti::reset_arti_guard_state(&data_dir_str) {
        Ok(summary) => unsafe { write_bytes_with_len(out_buf, out_len, summary.as_bytes()) },
        Err(e) => {
            let msg = format!("arti_reset_guard_state: {}", e);
            set_arti_last_error(msg.clone());
            unsafe {
                let _ = write_bytes_with_len(out_buf, out_len, msg.as_bytes());
            }
            -1
        }
    }
}

/// High-level atomic send: connect -> write_message -> optionally read ACK -> close.
/// Returns: 0=success, -1=not ready, -2=connect failed, -3=write failed.
/// ACK read failure is not a send failure: the recipient may already have stored
/// the message and can still return ACK over the outbound retry path.
#[no_mangle]
pub unsafe extern "C" fn securelegion_arti_send_to_onion(
    onion_address: *const c_char,
    port: u16,
    payload: *const u8,
    payload_len: u32,
    read_ack: bool,
    ack_out: *mut u8,
    ack_len: *mut u32,
) -> i32 {
    clear_arti_last_error();
    if onion_address.is_null() || payload.is_null() {
        set_arti_last_error("arti_send_to_onion: invalid null argument");
        return -1;
    }
    let onion_str = match CStr::from_ptr(onion_address).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_arti_last_error("arti_send_to_onion: onion address is not valid UTF-8");
            return -1;
        }
    };
    let payload_slice = std::slice::from_raw_parts(payload, payload_len as usize);
    let payload_vec = payload_slice.to_vec();

    if !crate::network::arti::is_arti_ready() {
        set_arti_last_error("arti_send_to_onion: Arti is not ready");
        return -1;
    }

    RUNTIME.block_on(async {
        // Connect
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_millis(IOS_ARTI_DIRECT_CONNECT_TIMEOUT_MS),
            crate::network::arti::arti_connect_to_onion(&onion_str, port),
        ).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let msg = format!("arti_send_to_onion: connect failed: {}", e);
                log::error!("{}", msg);
                set_arti_last_error(msg);
                return -2;
            },
            Err(_) => {
                let msg = format!(
                    "arti_send_to_onion: connect timed out after {}ms",
                    IOS_ARTI_DIRECT_CONNECT_TIMEOUT_MS
                );
                log::error!("{}", msg);
                set_arti_last_error(msg);
                return -2;
            },
        };

        // Write message (length-prefixed)
        match tokio::time::timeout(
            std::time::Duration::from_millis(IOS_ARTI_DIRECT_WRITE_TIMEOUT_MS),
            stream.write_message(&payload_vec),
        ).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let msg = format!("arti_send_to_onion: write failed: {}", e);
                log::error!("{}", msg);
                set_arti_last_error(msg);
                return -3;
            },
            Err(_) => {
                let msg = format!(
                    "arti_send_to_onion: write timed out after {}ms",
                    IOS_ARTI_DIRECT_WRITE_TIMEOUT_MS
                );
                log::error!("{}", msg);
                set_arti_last_error(msg);
                return -3;
            },
        }

        // Optionally read ACK response
        if read_ack && !ack_out.is_null() && !ack_len.is_null() {
            match tokio::time::timeout(
                std::time::Duration::from_millis(IOS_ARTI_DIRECT_ACK_TIMEOUT_MS),
                stream.read_message(),
            ).await {
                Ok(Ok(ack_data)) => {
                    let max_len = *ack_len as usize;
                    let copy_len = ack_data.len().min(max_len);
                    std::ptr::copy_nonoverlapping(ack_data.as_ptr(), ack_out, copy_len);
                    *ack_len = copy_len as u32;
                },
                Ok(Err(e)) => {
                    log::warn!("arti_send_to_onion: ACK read failed after write succeeded: {}", e);
                    *ack_len = 0;
                },
                Err(_) => {
                    log::warn!("arti_send_to_onion: ACK read timed out after {}ms; treating write as success", IOS_ARTI_DIRECT_ACK_TIMEOUT_MS);
                    *ack_len = 0;
                },
            }
        } else if !ack_len.is_null() {
            *ack_len = 0;
        }

        0
    })
}

/// Atomic tracked exchange on one Arti connection:
/// connect -> write PING -> read PONG -> write MESSAGE -> read ACK -> close.
/// Returns:
///   0 success
///  -1 invalid args / arti not ready
///  -2 connect failed
///  -3 ping write failed
///  -4 pong read failed / timeout
///  -5 message write failed
///  -6 ack read failed / timeout
#[no_mangle]
pub unsafe extern "C" fn securelegion_arti_tracked_exchange(
    onion_address: *const c_char,
    port: u16,
    ping_payload: *const u8,
    ping_payload_len: u32,
    message_payload: *const u8,
    message_payload_len: u32,
    pong_out: *mut u8,
    pong_len: *mut u32,
    ack_out: *mut u8,
    ack_len: *mut u32,
) -> i32 {
    if onion_address.is_null()
        || ping_payload.is_null()
        || message_payload.is_null()
        || pong_out.is_null()
        || pong_len.is_null()
        || ack_out.is_null()
        || ack_len.is_null()
    {
        return -1;
    }
    if !crate::network::arti::is_arti_ready() {
        return -1;
    }

    let onion_str = match CStr::from_ptr(onion_address).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let ping_vec = std::slice::from_raw_parts(ping_payload, ping_payload_len as usize).to_vec();
    let message_vec =
        std::slice::from_raw_parts(message_payload, message_payload_len as usize).to_vec();

    RUNTIME.block_on(async {
        let mut stream = match crate::network::arti::arti_connect_to_onion(&onion_str, port).await {
            Ok(s) => s,
            Err(e) => {
                log::error!("arti_tracked_exchange: connect failed: {}", e);
                return -2;
            }
        };

        if let Err(e) = stream.write_message(&ping_vec).await {
            log::error!("arti_tracked_exchange: ping write failed: {}", e);
            return -3;
        }

        let pong_data = match tokio::time::timeout(
            std::time::Duration::from_millis(60_000),
            stream.read_message(),
        )
        .await
        {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => {
                log::warn!(
                    "arti_tracked_exchange: pong read failed after ping write: {}",
                    e
                );
                return -4;
            }
            Err(_) => {
                log::warn!("arti_tracked_exchange: pong read timed out after 60000ms");
                return -4;
            }
        };

        let pong_rc = write_bytes_with_len(pong_out, pong_len, &pong_data);
        if pong_rc != 0 {
            return pong_rc;
        }

        if let Err(e) = stream.write_message(&message_vec).await {
            log::error!("arti_tracked_exchange: message write failed: {}", e);
            return -5;
        }

        let ack_data = match tokio::time::timeout(
            std::time::Duration::from_millis(30_000),
            stream.read_message(),
        )
        .await
        {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => {
                log::warn!(
                    "arti_tracked_exchange: ack read failed after message write: {}",
                    e
                );
                return -6;
            }
            Err(_) => {
                log::warn!("arti_tracked_exchange: ack read timed out after 30000ms");
                return -6;
            }
        };

        write_bytes_with_len(ack_out, ack_len, &ack_data)
    })
}

/// Shut down Arti and release all resources.
#[no_mangle]
pub extern "C" fn securelegion_arti_shutdown() {
    crate::network::arti::shutdown_arti();
}

/// Request fresh outbound Arti circuits without tearing down the client.
#[no_mangle]
pub extern "C" fn securelegion_arti_send_newnym() -> bool {
    if !crate::network::arti::is_arti_ready() {
        return false;
    }
    crate::network::arti::send_newnym();
    true
}

/// Lightweight outbound connect/close probe used before repeated-failure sends.
/// Returns 0 on success, -1 on invalid args / arti not ready, -2 on connect failure or timeout.
#[no_mangle]
pub unsafe extern "C" fn securelegion_arti_preflight_connect(
    onion_address: *const c_char,
    port: u16,
    timeout_ms: u32,
    latency_ms_out: *mut u32,
) -> i32 {
    clear_arti_last_error();
    if onion_address.is_null() {
        set_arti_last_error("arti_preflight_connect: invalid null onion address");
        return -1;
    }
    let onion_str = match CStr::from_ptr(onion_address).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_arti_last_error("arti_preflight_connect: onion address is not valid UTF-8");
            return -1;
        }
    };

    if !crate::network::arti::is_arti_ready() {
        set_arti_last_error("arti_preflight_connect: Arti is not ready");
        return -1;
    }

    let started = std::time::Instant::now();
    let result = RUNTIME.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms.max(1) as u64),
            crate::network::arti::arti_connect_to_onion(&onion_str, port),
        )
        .await
    });

    match result {
        Ok(Ok(_stream)) => {
            if !latency_ms_out.is_null() {
                *latency_ms_out = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
            }
            0
        }
        Ok(Err(e)) => {
            let msg = format!("arti_preflight_connect: connect failed: {}", e);
            log::warn!("{}", msg);
            set_arti_last_error(msg);
            if !latency_ms_out.is_null() {
                *latency_ms_out = 0;
            }
            -2
        }
        Err(_) => {
            let msg = format!("arti_preflight_connect: timed out after {}ms", timeout_ms.max(1));
            log::warn!("{}", msg);
            set_arti_last_error(msg);
            if !latency_ms_out.is_null() {
                *latency_ms_out = 0;
            }
            -2
        }
    }
}

/// Open a reusable outbound Arti stream to a peer onion.
/// Returns a non-zero stream handle on success, 0 on failure.
#[no_mangle]
pub unsafe extern "C" fn securelegion_arti_open_stream(
    onion_address: *const c_char,
    port: u16,
) -> u64 {
    if onion_address.is_null() {
        return 0;
    }
    let onion_str = match CStr::from_ptr(onion_address).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };

    if !crate::network::arti::is_arti_ready() {
        return 0;
    }

    let stream = match RUNTIME
        .block_on(async { crate::network::arti::arti_connect_to_onion(&onion_str, port).await })
    {
        Ok(stream) => stream,
        Err(e) => {
            log::error!("arti_open_stream: connect failed: {}", e);
            return 0;
        }
    };

    let handle = NEXT_ARTI_STREAM_ID.fetch_add(1, Ordering::SeqCst);
    let mut map = ARTI_STREAMS.lock().unwrap_or_else(|e| e.into_inner());
    map.insert(handle, stream);
    handle
}

/// Write one length-prefixed wire payload to an open Arti stream.
/// Returns 0 on success, -1 on invalid handle/args, -2 on write failure.
#[no_mangle]
pub unsafe extern "C" fn securelegion_arti_write_stream(
    stream_handle: u64,
    payload: *const u8,
    payload_len: u32,
) -> i32 {
    if stream_handle == 0 || payload.is_null() {
        return -1;
    }
    let payload_vec = std::slice::from_raw_parts(payload, payload_len as usize).to_vec();
    let mut stream = {
        let mut map = ARTI_STREAMS.lock().unwrap_or_else(|e| e.into_inner());
        match map.remove(&stream_handle) {
            Some(stream) => stream,
            None => return -1,
        }
    };

    let result = RUNTIME.block_on(async { stream.write_message(&payload_vec).await });
    match result {
        Ok(()) => {
            let mut map = ARTI_STREAMS.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(stream_handle, stream);
            0
        }
        Err(e) => {
            log::error!(
                "arti_write_stream: write failed handle={}: {}",
                stream_handle,
                e
            );
            -2
        }
    }
}

/// Read one length-prefixed wire payload from an open Arti stream.
/// Returns 0 on success, -1 on invalid handle/args, -2 on read failure, -3 on timeout.
#[no_mangle]
pub unsafe extern "C" fn securelegion_arti_read_stream(
    stream_handle: u64,
    timeout_ms: u32,
    payload_out: *mut u8,
    payload_len_out: *mut u32,
) -> i32 {
    if stream_handle == 0 || payload_out.is_null() || payload_len_out.is_null() {
        return -1;
    }
    let mut stream = {
        let mut map = ARTI_STREAMS.lock().unwrap_or_else(|e| e.into_inner());
        match map.remove(&stream_handle) {
            Some(stream) => stream,
            None => return -1,
        }
    };

    let read_result = RUNTIME.block_on(async {
        if timeout_ms == 0 {
            stream
                .read_message()
                .await
                .map_err(|e| e.to_string())
                .map(Some)
        } else {
            match tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms as u64),
                stream.read_message(),
            )
            .await
            {
                Ok(Ok(data)) => Ok(Some(data)),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Ok(None),
            }
        }
    });

    match read_result {
        Ok(Some(data)) => {
            let rc = write_bytes_with_len(payload_out, payload_len_out, &data);
            let mut map = ARTI_STREAMS.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(stream_handle, stream);
            rc
        }
        Ok(None) => {
            let mut map = ARTI_STREAMS.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(stream_handle, stream);
            -3
        }
        Err(e) => {
            log::error!(
                "arti_read_stream: read failed handle={}: {}",
                stream_handle,
                e
            );
            -2
        }
    }
}

/// Close and drop an open Arti stream handle.
#[no_mangle]
pub extern "C" fn securelegion_arti_close_stream(stream_handle: u64) {
    if stream_handle == 0 {
        return;
    }
    let mut map = ARTI_STREAMS.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(&stream_handle);
}
