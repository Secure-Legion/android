/// CRDT group JNI bridge — 5 core + 4 sync (stub) entry points.
///
/// In-memory group state lives behind `GROUPS` (Mutex<HashMap>).
/// Kotlin persists ops in Room/SQLCipher; Rust owns the derived state.
///
/// **Core API:**
/// - `crdtLoadGroup` — rebuild from serialized ops (startup)
/// - `crdtUnloadGroup` — free memory (off-screen / low-memory)
/// - `crdtApplyOps` — apply batch of received ops → JSON result
/// - `crdtCreateOp` — create + sign + apply → JSON with op bytes + metadata
/// - `crdtQuery` — query derived state → JSON
///
/// **Sync stubs (Phase 6):**
/// - `crdtGenerateSyncHello`, `crdtProcessSyncHello`,
///   `crdtPrepareSyncChunks`, `crdtApplySyncChunk`

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jstring, JNI_TRUE, JNI_FALSE};
use jni::JNIEnv;
use std::collections::HashMap;
use std::panic;
use std::sync::Mutex;
use std::sync::OnceLock;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::crdt::ids::{DeviceID, GroupID, OpID};
use crate::crdt::ops::{
    OpEnvelope, OpType, Role, RemoveReason, MetadataKey,
    GroupCreatePayload, MemberInvitePayload, MemberAcceptPayload,
    MemberRemovePayload, RoleSetPayload, MsgAddPayload, MsgEditPayload,
    MsgDeletePayload, ReactionSetPayload, MetadataSetPayload,
    generate_msg_id,
};
use crate::crdt::limits::{MAX_OP_PAYLOAD_BYTES, HARD_CAP_OPS_PER_GROUP};
use crate::crdt::apply::GroupState;
use crate::crdt::messages::MessageEntry;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Max serialized op size: payload limit + generous envelope overhead.
const MAX_SERIALIZED_OP_BYTES: usize = MAX_OP_PAYLOAD_BYTES + 1024; // ~65 KB

/// Max ops per crdtApplyOps call (sync receive / incremental apply).
const MAX_OPS_PER_APPLY_BATCH: usize = 2_000;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// In-memory group states, keyed by GroupID.
static GROUPS: OnceLock<Mutex<HashMap<GroupID, GroupState>>> = OnceLock::new();

/// Per-group lamport counter for the local device.
static MY_LAMPORT: OnceLock<Mutex<HashMap<GroupID, u64>>> = OnceLock::new();

fn get_groups() -> &'static Mutex<HashMap<GroupID, GroupState>> {
    GROUPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_lamport_map() -> &'static Mutex<HashMap<GroupID, u64>> {
    MY_LAMPORT.get_or_init(|| Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// JNI helpers (local copies — trivial conversions)
// ---------------------------------------------------------------------------

fn jbytearray_to_vec(env: &mut JNIEnv, array: JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(array)
        .map_err(|e| format!("Failed to convert byte array: {}", e))
}

fn vec_to_jbytearray<'a>(env: &mut JNIEnv<'a>, data: &[u8]) -> Result<JByteArray<'a>, String> {
    env.byte_array_from_slice(data)
        .map_err(|e| format!("Failed to create byte array: {}", e))
}

fn jstring_to_string(env: &mut JNIEnv, string: JString) -> Result<String, String> {
    env.get_string(&string)
        .map(|s| s.into())
        .map_err(|e| format!("Failed to convert string: {}", e))
}

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

// ---------------------------------------------------------------------------
// Parse helpers
// ---------------------------------------------------------------------------

fn parse_group_id(env: &mut JNIEnv, hex: JString) -> Result<GroupID, String> {
    let s = jstring_to_string(env, hex)?;
    GroupID::from_hex(&s).map_err(|e| format!("Invalid group ID: {}", e))
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
        other => Err(format!("Unknown op type: {}", other)),
    }
}

fn parse_role(s: &str) -> Result<Role, String> {
    match s {
        "Owner" => Ok(Role::Owner),
        "Admin" => Ok(Role::Admin),
        "Member" => Ok(Role::Member),
        "ReadOnly" => Ok(Role::ReadOnly),
        other => Err(format!("Unknown role: {}", other)),
    }
}

fn parse_remove_reason(s: &str) -> Result<RemoveReason, String> {
    match s {
        "Kick" => Ok(RemoveReason::Kick),
        "Leave" => Ok(RemoveReason::Leave),
        other => Err(format!("Unknown remove reason: {}", other)),
    }
}

fn parse_metadata_key(s: &str) -> Result<MetadataKey, String> {
    match s {
        "Name" => Ok(MetadataKey::Name),
        "Avatar" => Ok(MetadataKey::Avatar),
        "Topic" => Ok(MetadataKey::Topic),
        other => Err(format!("Unknown metadata key: {}", other)),
    }
}

/// Decode hex string to a fixed 32-byte array (pubkey, msg_id, etc.).
fn hex_to_32(hex_str: &str, field_name: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("Bad {} hex: {}", field_name, e))?;
    if bytes.len() != 32 {
        return Err(format!("{} must be 32 bytes (64 hex chars), got {}", field_name, bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Decode base64 string to a fixed 24-byte array (XChaCha20 nonce).
fn b64_to_24(b64_str: &str, field_name: &str) -> Result<[u8; 24], String> {
    let bytes = B64.decode(b64_str)
        .map_err(|e| format!("Bad {} base64: {}", field_name, e))?;
    if bytes.len() != 24 {
        return Err(format!("{} must be 24 bytes, got {}", field_name, bytes.len()));
    }
    let mut arr = [0u8; 24];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Decode length-prefixed concatenated ops: [4-byte BE len][bytes]...
///
/// Enforces per-op size cap and total op count cap to prevent DoS.
fn decode_length_prefixed_ops(
    data: &[u8],
    max_ops: usize,
    max_op_size: usize,
) -> Result<Vec<OpEnvelope>, String> {
    let mut ops = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        if ops.len() >= max_ops {
            return Err(format!("Op count exceeds limit of {}", max_ops));
        }

        let len = u32::from_be_bytes(
            data[offset..offset + 4].try_into().unwrap(),
        ) as usize;
        offset += 4;

        if len > max_op_size {
            return Err(format!(
                "Op at offset {} is {} bytes, exceeds max of {}",
                offset, len, max_op_size
            ));
        }

        if offset + len > data.len() {
            return Err(format!(
                "Truncated op at offset {} (need {} bytes, have {})",
                offset, len, data.len() - offset
            ));
        }

        let op = OpEnvelope::from_bytes(&data[offset..offset + len])
            .map_err(|e| format!("Op decode at offset {}: {}", offset, e))?;
        ops.push(op);
        offset += len;
    }

    Ok(ops)
}

/// Compute the next lamport for this device in a group.
///
/// Ensures causal ordering: always greater than any seen lamport.
fn next_lamport(group_id: &GroupID, state: &GroupState) -> u64 {
    let mut lmap = get_lamport_map().lock().unwrap();
    let group_max = state.max_lamport.values().max().copied().unwrap_or(0);
    let my_current = *lmap.get(group_id).unwrap_or(&0);
    let next = std::cmp::max(group_max, my_current) + 1;
    lmap.insert(*group_id, next);
    next
}

/// Throw IllegalArgumentException and return null.
macro_rules! throw_arg {
    ($env:expr, $msg:expr) => {{
        let _ = $env.throw_new("java/lang/IllegalArgumentException", &*$msg.to_string());
        return std::ptr::null_mut();
    }};
}

/// Throw IllegalStateException and return null.
macro_rules! throw_state {
    ($env:expr, $msg:expr) => {{
        let _ = $env.throw_new("java/lang/IllegalStateException", &*$msg.to_string());
        return std::ptr::null_mut();
    }};
}

/// Throw RuntimeException and return null.
macro_rules! throw_rt {
    ($env:expr, $msg:expr) => {{
        let _ = $env.throw_new("java/lang/RuntimeException", &*$msg.to_string());
        return std::ptr::null_mut();
    }};
}

// ===========================================================================
// 1. crdtLoadGroup
// ===========================================================================

/// Rebuild group state from serialized ops (call on app startup).
///
/// `serialized_ops_bytes` is length-prefixed: [4-byte BE len][op bytes]...
/// Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtLoadGroup(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    serialized_ops_bytes: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        let gid = match parse_group_id(&mut env, group_id_hex) {
            Ok(g) => g,
            Err(e) => { log::error!("crdtLoadGroup: {}", e); return JNI_FALSE; }
        };

        let data = match jbytearray_to_vec(&mut env, serialized_ops_bytes) {
            Ok(d) => d,
            Err(e) => { log::error!("crdtLoadGroup: {}", e); return JNI_FALSE; }
        };

        // Load allows up to hard cap ops (full group rebuild).
        let ops = match decode_length_prefixed_ops(&data, HARD_CAP_OPS_PER_GROUP, MAX_SERIALIZED_OP_BYTES) {
            Ok(o) => o,
            Err(e) => { log::error!("crdtLoadGroup decode: {}", e); return JNI_FALSE; }
        };

        let op_count = ops.len();
        let state = match GroupState::rebuild_from_ops(gid, &ops) {
            Ok(s) => s,
            Err(e) => { log::error!("crdtLoadGroup rebuild: {}", e); return JNI_FALSE; }
        };

        let mut groups = get_groups().lock().unwrap();
        groups.insert(gid, state);

        log::info!("crdtLoadGroup: loaded {} ops for {}", op_count, gid);
        JNI_TRUE
    }, JNI_FALSE)
}

// ===========================================================================
// 2. crdtUnloadGroup
// ===========================================================================

/// Free group state from memory (call when off-screen or on low memory).
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtUnloadGroup(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
) {
    catch_panic!(env, {
        let gid = match parse_group_id(&mut env, group_id_hex) {
            Ok(g) => g,
            Err(e) => { log::error!("crdtUnloadGroup: {}", e); return; }
        };

        {
            let mut groups = get_groups().lock().unwrap();
            groups.remove(&gid);
        }
        {
            let mut lmap = get_lamport_map().lock().unwrap();
            lmap.remove(&gid);
        }

        log::info!("crdtUnloadGroup: {}", gid);
    }, ())
}

// ===========================================================================
// 3. crdtApplyOps
// ===========================================================================

/// Apply one or more ops to a group. Ops must already be signed.
///
/// Returns JSON: `{"applied": N, "rejected": N, "limit_status": "Ok|..."}`
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtApplyOps(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    serialized_ops_bytes: JByteArray,
) -> jstring {
    catch_panic!(env, {
        let gid = match parse_group_id(&mut env, group_id_hex) {
            Ok(g) => g,
            Err(e) => throw_arg!(env, e),
        };

        let data = match jbytearray_to_vec(&mut env, serialized_ops_bytes) {
            Ok(d) => d,
            Err(e) => throw_arg!(env, e),
        };

        // Batch apply capped at MAX_OPS_PER_APPLY_BATCH.
        let ops = match decode_length_prefixed_ops(&data, MAX_OPS_PER_APPLY_BATCH, MAX_SERIALIZED_OP_BYTES) {
            Ok(o) => o,
            Err(e) => throw_arg!(env, e),
        };

        let mut groups = get_groups().lock().unwrap();
        let state = match groups.get_mut(&gid) {
            Some(s) => s,
            None => throw_state!(env, "Group not loaded — call crdtLoadGroup first"),
        };

        let mut applied = 0u64;
        let mut rejected = 0u64;

        for op in &ops {
            match state.apply_op(op) {
                Ok(true) => applied += 1,
                Ok(false) => {} // duplicate — silently skip
                Err(e) => {
                    log::warn!("crdtApplyOps: rejected op {:?}: {}", op.op_id, e);
                    rejected += 1;
                }
            }
        }

        let json = serde_json::json!({
            "applied": applied,
            "rejected": rejected,
            "limit_status": format!("{:?}", state.limit_status()),
        });

        match env.new_string(json.to_string()) {
            Ok(s) => s.into_raw(),
            Err(e) => throw_rt!(env, format!("JSON creation failed: {}", e)),
        }
    }, std::ptr::null_mut())
}

// ===========================================================================
// 4. crdtCreateOp
// ===========================================================================

/// Create a signed op, apply it locally, and return JSON with the serialized
/// bytes and metadata.
///
/// Returns JSON:
/// ```json
/// {
///   "op_bytes_b64": "...",
///   "op_id": "author_hex:lamport_hex:nonce_hex",
///   "op_type": "MsgAdd",
///   "lamport": 5,
///   "msg_id_hex": "..."   // only for MsgAdd
/// }
/// ```
///
/// **Deviation from plan:** returns `String` (JSON) instead of `ByteArray`
/// so Kotlin gets the op_id and lamport without extra parsing.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtCreateOp(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    op_type_str: JString,
    params_json: JString,
    author_pubkey: JByteArray,
    author_privkey: JByteArray,
) -> jstring {
    catch_panic!(env, {
        // --- Parse inputs ---
        let gid = match parse_group_id(&mut env, group_id_hex) {
            Ok(g) => g,
            Err(e) => throw_arg!(env, e),
        };
        let otype_str = match jstring_to_string(&mut env, op_type_str) {
            Ok(s) => s,
            Err(e) => throw_arg!(env, e),
        };
        let params_str = match jstring_to_string(&mut env, params_json) {
            Ok(s) => s,
            Err(e) => throw_arg!(env, e),
        };
        let pub_key = match jbytearray_to_vec(&mut env, author_pubkey) {
            Ok(v) if v.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&v); a }
            Ok(v) => throw_arg!(env, format!("Pubkey must be 32 bytes, got {}", v.len())),
            Err(e) => throw_arg!(env, e),
        };
        let priv_key = match jbytearray_to_vec(&mut env, author_privkey) {
            Ok(v) if v.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&v); a }
            Ok(v) => throw_arg!(env, format!("Privkey must be 32 bytes, got {}", v.len())),
            Err(e) => throw_arg!(env, e),
        };

        let otype = match parse_op_type(&otype_str) {
            Ok(o) => o,
            Err(e) => throw_arg!(env, e),
        };
        let params: serde_json::Value = match serde_json::from_str(&params_str) {
            Ok(v) => v,
            Err(e) => throw_arg!(env, format!("Invalid JSON: {}", e)),
        };

        // --- Get/create group state ---
        let mut groups = get_groups().lock().unwrap();
        if otype == OpType::GroupCreate && !groups.contains_key(&gid) {
            groups.insert(gid, GroupState::new(gid));
        }
        let state = match groups.get_mut(&gid) {
            Some(s) => s,
            None => throw_state!(env, "Group not loaded — call crdtLoadGroup first"),
        };

        // --- Lamport + nonce ---
        let lamport = if otype == OpType::GroupCreate { 1 } else { next_lamport(&gid, state) };
        let op_nonce: u64 = rand::random();
        let author_device = DeviceID::from_pubkey(&pub_key);

        // --- Build payload and create signed op ---
        let envelope = match build_op_envelope(
            &mut env, gid, otype, &params, lamport, op_nonce,
            pub_key, &priv_key, &author_device,
        ) {
            Some(op) => op,
            None => return std::ptr::null_mut(), // exception already thrown
        };

        // --- Apply to local state ---
        let op_id_hex = envelope.op_id.to_hex();
        if let Err(e) = state.apply_op(&envelope) {
            throw_rt!(env, format!("Op apply failed: {}", e));
        }

        // --- Update my lamport tracker ---
        {
            let mut lmap = get_lamport_map().lock().unwrap();
            lmap.entry(gid)
                .and_modify(|l| *l = (*l).max(lamport))
                .or_insert(lamport);
        }

        // --- Serialize and return JSON ---
        let op_bytes = match envelope.to_bytes() {
            Ok(b) => b,
            Err(e) => throw_rt!(env, format!("Op serialization failed: {}", e)),
        };

        let mut json = serde_json::json!({
            "op_bytes_b64": B64.encode(&op_bytes),
            "op_id": op_id_hex,
            "op_type": otype_str,
            "lamport": lamport,
        });

        // Include auto-generated msg_id for MsgAdd
        if otype == OpType::MsgAdd {
            let msg_id = generate_msg_id(&author_device, lamport, op_nonce);
            json["msg_id_hex"] = serde_json::Value::String(hex::encode(msg_id));
        }

        match env.new_string(json.to_string()) {
            Ok(s) => s.into_raw(),
            Err(e) => throw_rt!(env, format!("JSON creation failed: {}", e)),
        }
    }, std::ptr::null_mut())
}

/// Build an OpEnvelope for the given op type and params. Returns None if an
/// exception was thrown (caller should return null).
fn build_op_envelope(
    env: &mut JNIEnv,
    gid: GroupID,
    otype: OpType,
    params: &serde_json::Value,
    lamport: u64,
    op_nonce: u64,
    pub_key: [u8; 32],
    priv_key: &[u8; 32],
    author_device: &DeviceID,
) -> Option<OpEnvelope> {
    let result = match otype {
        OpType::GroupCreate => {
            let group_name = params["group_name"].as_str().unwrap_or("").to_string();
            let secret = B64.decode(params["encrypted_group_secret_b64"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let payload = GroupCreatePayload { group_name, encrypted_group_secret: secret };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MemberInvite => {
            let pk_hex = params["invited_pubkey_hex"].as_str().unwrap_or("");
            let invited_pubkey = match hex_to_32(pk_hex, "invited_pubkey") {
                Ok(a) => a,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let role = match parse_role(params["role"].as_str().unwrap_or("Member")) {
                Ok(r) => r,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let secret = B64.decode(params["encrypted_group_secret_b64"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let invited_device_id = DeviceID::from_pubkey(&invited_pubkey);
            let payload = MemberInvitePayload {
                invited_device_id, invited_pubkey, role, encrypted_group_secret: secret,
            };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MemberAccept => {
            let id_hex = params["invite_op_id_hex"].as_str().unwrap_or("");
            let invite_op_id = match OpID::from_hex(id_hex) {
                Ok(id) => id,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let payload = MemberAcceptPayload { invite_op_id };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MemberRemove => {
            let pk_hex = params["target_pubkey_hex"].as_str().unwrap_or("");
            let target_pk = match hex_to_32(pk_hex, "target_pubkey") {
                Ok(a) => a,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let reason = match parse_remove_reason(params["reason"].as_str().unwrap_or("Kick")) {
                Ok(r) => r,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let target_device_id = DeviceID::from_pubkey(&target_pk);
            let payload = MemberRemovePayload { target_device_id, reason };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::RoleSet => {
            let pk_hex = params["target_pubkey_hex"].as_str().unwrap_or("");
            let target_pk = match hex_to_32(pk_hex, "target_pubkey") {
                Ok(a) => a,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let new_role = match parse_role(params["new_role"].as_str().unwrap_or("Member")) {
                Ok(r) => r,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let target_device_id = DeviceID::from_pubkey(&target_pk);
            let payload = RoleSetPayload { target_device_id, new_role };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MsgAdd => {
            let msg_id = generate_msg_id(author_device, lamport, op_nonce);
            let ciphertext = B64.decode(params["ciphertext_b64"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let enc_nonce = match b64_to_24(params["nonce_b64"].as_str().unwrap_or(""), "nonce") {
                Ok(n) => n,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let payload = MsgAddPayload { msg_id, ciphertext, nonce: enc_nonce };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MsgEdit => {
            let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id") {
                Ok(a) => a,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let new_ciphertext = B64.decode(params["new_ciphertext_b64"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let enc_nonce = match b64_to_24(params["nonce_b64"].as_str().unwrap_or(""), "nonce") {
                Ok(n) => n,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let payload = MsgEditPayload { msg_id, new_ciphertext, nonce: enc_nonce };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MsgDelete => {
            let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id") {
                Ok(a) => a,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let payload = MsgDeletePayload { msg_id };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::ReactionSet => {
            let msg_id = match hex_to_32(params["msg_id_hex"].as_str().unwrap_or(""), "msg_id") {
                Ok(a) => a,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let emoji = params["emoji"].as_str().unwrap_or("").to_string();
            let present = params["present"].as_bool().unwrap_or(true);
            let payload = ReactionSetPayload { msg_id, emoji, present };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MetadataSet => {
            let key = match parse_metadata_key(params["key"].as_str().unwrap_or("")) {
                Ok(k) => k,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let value = B64.decode(params["value_b64"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let payload = MetadataSetPayload { key, value };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
    };

    match result {
        Ok(op) => Some(op),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException",
                format!("Op creation failed: {}", e));
            None
        }
    }
}

// ===========================================================================
// 5. crdtQuery
// ===========================================================================

/// Query derived state for a loaded group. Returns JSON.
///
/// Supported `query_type` values:
/// - `"members"` — all members with role/status
/// - `"messages"` — renderable messages (membership-gated, not deleted)
/// - `"messages_after"` — cursor-based: `paramsJson={"after_lamport":N,"limit":50}`
/// - `"metadata"` — group name, topic, avatar
/// - `"heads"` — DAG heads + per-author lamport
/// - `"state_hash"` — BLAKE3 convergence hash
/// - `"limit_status"` — op count + limit status
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtQuery(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    query_type: JString,
    params_json: JString,
) -> jstring {
    catch_panic!(env, {
        let gid = match parse_group_id(&mut env, group_id_hex) {
            Ok(g) => g,
            Err(e) => throw_arg!(env, e),
        };
        let qt = match jstring_to_string(&mut env, query_type) {
            Ok(s) => s,
            Err(e) => throw_arg!(env, e),
        };
        let params_str = match jstring_to_string(&mut env, params_json) {
            Ok(s) => s,
            Err(e) => throw_arg!(env, e),
        };

        let groups = get_groups().lock().unwrap();
        let state = match groups.get(&gid) {
            Some(s) => s,
            None => throw_state!(env, "Group not loaded"),
        };

        let json = match qt.as_str() {
            "members" => query_members(state),
            "messages" => query_messages(state),
            "messages_after" => query_messages_after(state, &params_str),
            "metadata" => query_metadata(state),
            "heads" => query_heads(state),
            "state_hash" => query_state_hash(state),
            "limit_status" => query_limit_status(state),
            other => throw_arg!(env, format!("Unknown query type: {}", other)),
        };

        match env.new_string(json.to_string()) {
            Ok(s) => s.into_raw(),
            Err(e) => throw_rt!(env, format!("JSON creation failed: {}", e)),
        }
    }, std::ptr::null_mut())
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

fn query_members(state: &GroupState) -> serde_json::Value {
    let members: Vec<serde_json::Value> = state.membership.members().iter()
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

fn query_messages(state: &GroupState) -> serde_json::Value {
    let msgs: Vec<serde_json::Value> = state.renderable_messages().iter()
        .map(|msg| message_to_json(msg))
        .collect();
    serde_json::Value::Array(msgs)
}

fn query_messages_after(state: &GroupState, params_str: &str) -> serde_json::Value {
    let params: serde_json::Value = serde_json::from_str(params_str).unwrap_or_default();
    let after_lamport = params["after_lamport"].as_u64().unwrap_or(0);
    let limit = params["limit"].as_u64().unwrap_or(50) as usize;

    let mut msgs: Vec<&MessageEntry> = state.renderable_messages()
        .into_iter()
        .filter(|m| m.create_op.lamport > after_lamport)
        .collect();
    msgs.sort_by(|a, b| a.create_op.cmp(&b.create_op));
    msgs.truncate(limit);

    let result: Vec<serde_json::Value> = msgs.iter().map(|m| message_to_json(m)).collect();
    serde_json::Value::Array(result)
}

fn query_metadata(state: &GroupState) -> serde_json::Value {
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

fn query_heads(state: &GroupState) -> serde_json::Value {
    let heads: Vec<String> = state.heads.iter().map(|h| h.to_hex()).collect();
    let per_author: serde_json::Map<String, serde_json::Value> = state.max_lamport.iter()
        .map(|(did, l)| (did.to_hex(), serde_json::Value::Number((*l).into())))
        .collect();
    serde_json::json!({
        "heads": heads,
        "per_author_lamport": per_author,
    })
}

fn query_state_hash(state: &GroupState) -> serde_json::Value {
    serde_json::json!({
        "hash": hex::encode(state.state_hash()),
    })
}

fn query_limit_status(state: &GroupState) -> serde_json::Value {
    serde_json::json!({
        "status": format!("{:?}", state.limit_status()),
        "op_count": state.op_count,
    })
}

fn message_to_json(msg: &MessageEntry) -> serde_json::Value {
    let reactions: Vec<serde_json::Value> = msg.reactions.iter()
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

// ===========================================================================
// 6-9. Sync stubs (Phase 6 implementation)
// ===========================================================================

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtGenerateSyncHello(
    mut env: JNIEnv,
    _class: JClass,
    _peer_device_id_hex: JString,
) -> jbyteArray {
    catch_panic!(env, {
        log::warn!("crdtGenerateSyncHello: stub — not implemented until Phase 6");
        match vec_to_jbytearray(&mut env, &[]) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtProcessSyncHello(
    mut env: JNIEnv,
    _class: JClass,
    _peer_device_id_hex: JString,
    _hello_bytes: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        log::warn!("crdtProcessSyncHello: stub — not implemented until Phase 6");
        match vec_to_jbytearray(&mut env, &[]) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtPrepareSyncChunks(
    mut env: JNIEnv,
    _class: JClass,
    _request_bytes: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        log::warn!("crdtPrepareSyncChunks: stub — not implemented until Phase 6");
        match vec_to_jbytearray(&mut env, &[]) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtApplySyncChunk(
    mut env: JNIEnv,
    _class: JClass,
    _chunk_bytes: JByteArray,
) -> jbyteArray {
    catch_panic!(env, {
        log::warn!("crdtApplySyncChunk: stub — not implemented until Phase 6");
        match vec_to_jbytearray(&mut env, &[]) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}
