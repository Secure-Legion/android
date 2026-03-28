use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use argon2::{Algorithm, Argon2, Params, Version};
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
    generate_msg_id, GroupCreatePayload, MemberAcceptPayload, MemberInvitePayload, MemberRemovePayload,
    MetadataKey, MetadataSetPayload, MsgAddPayload, MsgDeletePayload, MsgEditPayload, OpEnvelope, OpType,
    ReactionSetPayload, RemoveReason, Role, RoleSetPayload,
};
use crate::crypto::encryption::{
    decrypt_message, decrypt_message_with_evolution, derive_message_key, derive_receive_key_at_sequence,
    derive_root_key, encrypt_message, encrypt_message_with_evolution, evolve_chain_key,
};
use crate::crypto::hashing::{generate_salt, hash_password_with_salt};
use crate::crypto::key_exchange::{derive_shared_secret, generate_static_keypair};
use crate::crypto::pqc::{generate_hybrid_keypair_from_seed, hybrid_decapsulate, hybrid_encapsulate, HybridCiphertext};
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

unsafe fn write_cstr_to_buf(out_ptr: *mut c_char, data: &str, max_without_nul: usize) -> i32 {
    if out_ptr.is_null() || data.len() > max_without_nul || data.as_bytes().contains(&0) {
        return -1;
    }
    ptr::copy_nonoverlapping(data.as_ptr(), out_ptr as *mut u8, data.len());
    *(out_ptr.add(data.len())) = 0;
    0
}

fn decode_length_prefixed_ops(data: &[u8], max_ops: usize, max_op_size: usize) -> Result<Vec<OpEnvelope>, String> {
    let mut ops = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= data.len() {
        if ops.len() >= max_ops {
            return Err(format!("op count exceeds {}", max_ops));
        }
        let len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
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
    let bytes = B64.decode(s).map_err(|e| format!("bad {} b64: {}", field_name, e))?;
    if bytes.len() != 24 {
        return Err(format!("{} must be 24 bytes", field_name));
    }
    let mut out = [0u8; 24];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn next_lamport(group_id: &GroupID, state: &GroupState) -> u64 {
    let mut lmap = get_lamport_map().lock().unwrap();
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
    let params = Params::new(65536, 2, 1, Some(32))
        .map_err(|e| format!("argon2 params: {}", e))?;
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
    let old_key = hash_password_with_salt(pin, salt).map_err(|e| format!("pin kdf failed: {}", e))?;
    let chacha = XChaCha20Poly1305::new_from_slice(&old_key).map_err(|_| "invalid key".to_string())?;
    chacha
        .decrypt(XNonce::from_slice(nonce), body)
        .map_err(|_| "pin decrypt failed".to_string())
}

#[no_mangle]
pub extern "C" fn securelegion_version() -> *const c_char {
    VERSION_CSTR.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_generate_keypair(pubkey_out: *mut u8, privkey_out: *mut u8) -> i32 {
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
pub unsafe extern "C" fn securelegion_generate_x25519_keypair(pubkey_out: *mut u8, privkey_out: *mut u8) -> i32 {
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
pub unsafe extern "C" fn securelegion_evolve_chain_key(chain_key: *const u8, evolved_key_out: *mut u8) -> i32 {
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
pub unsafe extern "C" fn securelegion_derive_message_key(chain_key: *const u8, message_key_out: *mut u8) -> i32 {
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
        Err(_) => -1,
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

#[no_mangle]
pub unsafe extern "C" fn securelegion_generate_hybrid_kem_keypair(
    seed: *const u8,
    x25519_pub_out: *mut u8,
    x25519_sec_out: *mut u8,
    kyber_pub_out: *mut u8,
    kyber_sec_out: *mut u8,
) -> i32 {
    if x25519_pub_out.is_null() || x25519_sec_out.is_null() || kyber_pub_out.is_null() || kyber_sec_out.is_null() {
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
    let gid_s = match cstr_to_string(group_id_hex) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let gid = match GroupID::from_hex(&gid_s) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let data = bytes_from_ptr_opt(serialized_ops, serialized_ops_len as usize);
    let ops = match decode_length_prefixed_ops(data, HARD_CAP_OPS_PER_GROUP, MAX_SERIALIZED_OP_BYTES) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let state = match GroupState::rebuild_from_ops(gid, &ops) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    get_groups().lock().unwrap().insert(gid, state);
    0
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_unload_group(group_id_hex: *const c_char) -> i32 {
    let gid_s = match cstr_to_string(group_id_hex) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let gid = match GroupID::from_hex(&gid_s) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    get_groups().lock().unwrap().remove(&gid);
    get_lamport_map().lock().unwrap().remove(&gid);
    0
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_apply_ops(
    group_id_hex: *const c_char,
    serialized_ops: *const u8,
    serialized_ops_len: u32,
    result_json_out: *mut u8,
    result_json_len: *mut u32,
) -> i32 {
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
    let ops = match decode_length_prefixed_ops(data, MAX_OPS_PER_APPLY_BATCH, MAX_SERIALIZED_OP_BYTES) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let mut groups = get_groups().lock().unwrap();
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

    let mut groups = get_groups().lock().unwrap();
    if otype == OpType::GroupCreate && !groups.contains_key(&gid) {
        groups.insert(gid, GroupState::new(gid));
    }
    let state = match groups.get_mut(&gid) {
        Some(v) => v,
        None => return -1,
    };

    let lamport = if otype == OpType::GroupCreate { 1 } else { next_lamport(&gid, state) };
    let op_nonce: u64 = rand::random();

    let envelope = match otype {
        OpType::GroupCreate => {
            let group_name = params["group_name"].as_str().unwrap_or("").to_string();
            let secret = B64.decode(params["encrypted_group_secret_b64"].as_str().unwrap_or("")).unwrap_or_default();
            let payload = GroupCreatePayload { group_name, encrypted_group_secret: secret };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::MemberInvite => {
            let invited_pubkey = match hex_to_32(params["invited_pubkey_hex"].as_str().unwrap_or(""), "invited_pubkey") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let role = match parse_role(params["role"].as_str().unwrap_or("Member")) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let secret = B64.decode(params["encrypted_group_secret_b64"].as_str().unwrap_or("")).unwrap_or_default();
            let invited_device_id = DeviceID::from_pubkey(&invited_pubkey);
            let payload = MemberInvitePayload { invited_device_id, invited_pubkey, role, encrypted_group_secret: secret };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::MemberAccept => {
            let invite_op_id = match OpID::from_hex(params["invite_op_id_hex"].as_str().unwrap_or("")) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let payload = MemberAcceptPayload { invite_op_id };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::MemberRemove => {
            let target_pk = match hex_to_32(params["target_pubkey_hex"].as_str().unwrap_or(""), "target_pubkey") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let reason = match parse_remove_reason(params["reason"].as_str().unwrap_or("Kick")) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let target_device_id = DeviceID::from_pubkey(&target_pk);
            let payload = MemberRemovePayload { target_device_id, reason };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::RoleSet => {
            let target_pk = match hex_to_32(params["target_pubkey_hex"].as_str().unwrap_or(""), "target_pubkey") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let new_role = match parse_role(params["new_role"].as_str().unwrap_or("Member")) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let target_device_id = DeviceID::from_pubkey(&target_pk);
            let payload = RoleSetPayload { target_device_id, new_role };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::MsgAdd => {
            let msg_id = generate_msg_id(&author_device, lamport, op_nonce);
            let ciphertext = B64.decode(params["ciphertext_b64"].as_str().unwrap_or("")).unwrap_or_default();
            let nonce = match b64_to_24(params["nonce_b64"].as_str().unwrap_or(""), "nonce") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let payload = MsgAddPayload { msg_id, ciphertext, nonce };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::MsgEdit => {
            let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let new_ciphertext = B64.decode(params["new_ciphertext_b64"].as_str().unwrap_or("")).unwrap_or_default();
            let nonce = match b64_to_24(params["nonce_b64"].as_str().unwrap_or(""), "nonce") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let payload = MsgEditPayload { msg_id, new_ciphertext, nonce };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::MsgDelete => {
            let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let payload = MsgDeletePayload { msg_id };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::ReactionSet => {
            let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id") {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let emoji = params["emoji"].as_str().unwrap_or("").to_string();
            let present = params["present"].as_bool().unwrap_or(true);
            let payload = ReactionSetPayload { msg_id, emoji, present };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
        }
        OpType::MetadataSet => {
            let key = match parse_metadata_key(params["key"].as_str().unwrap_or("")) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            let value = B64.decode(params["value_b64"].as_str().unwrap_or("")).unwrap_or_default();
            let payload = MetadataSetPayload { key, value };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, &priv_key)
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
        let mut lmap = get_lamport_map().lock().unwrap();
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
}

#[no_mangle]
pub unsafe extern "C" fn securelegion_crdt_query(
    group_id_hex: *const c_char,
    query_type: *const c_char,
    params_json: *const c_char,
    result_out: *mut u8,
    result_len: *mut u32,
) -> i32 {
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

    let groups = get_groups().lock().unwrap();
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
                        "rekey_required": entry.rekey_required,
                        "invited_by_op_id": entry.invited_by.to_hex(),
                        "encrypted_group_secret_b64": B64.encode(&entry.encrypted_group_secret),
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
        "limit_status" => serde_json::json!({ "status": format!("{:?}", state.limit_status()), "op_count": state.op_count }),
        _ => return -1,
    };

    write_bytes_with_len(result_out, result_len, json.to_string().as_bytes())
}
