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
use jni::sys::{jboolean, jstring, JNI_TRUE, JNI_FALSE};
use jni::JNIEnv;
use std::cell::Cell;
use std::collections::HashMap;
use std::panic;
use std::sync::Mutex;
use std::sync::OnceLock;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::crdt::ids::{DeviceID, GroupID, OpID};
use crate::crdt::ops::{
    AdminRights, OpEnvelope, OpType, Role, RemoveReason, MetadataKey,
    GroupCreatePayload, MemberInvitePayload, MemberAcceptPayload,
    MemberRemovePayload, MemberUnbanPayload, RoleSetPayload, GroupDeletePayload, MsgAddPayload, MsgEditPayload,
    MsgDeletePayload, ReactionSetPayload, MetadataSetPayload,
    generate_msg_id,
};
use crate::crdt::limits::{MAX_OP_PAYLOAD_BYTES, HARD_CAP_OPS_PER_GROUP, MAX_OPS_PER_SYNC_ROUND};
use crate::crdt::apply::GroupState;
use crate::crdt::messages::MessageEntry;
use crate::crdt::sync::manager::{SyncManager, SyncBackend, StartError};
use crate::crdt::sync::session::SyncAction;

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

/// Phase 6 sync manager. `None` until `crdtSyncInit` is called.
///
/// **Reentrancy contract**: Kotlin code invoked via the `SyncBackend` callback
/// (`syncBackendComputeDelta`) MUST NOT call any `crdtSync*` JNI function. Doing
/// so will deadlock on this mutex. The callback is for op-log queries only.
static SYNC_MGR: OnceLock<Mutex<Option<SyncManager>>> = OnceLock::new();

fn get_groups() -> &'static Mutex<HashMap<GroupID, GroupState>> {
    GROUPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_lamport_map() -> &'static Mutex<HashMap<GroupID, u64>> {
    MY_LAMPORT.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_sync_mgr() -> &'static Mutex<Option<SyncManager>> {
    SYNC_MGR.get_or_init(|| Mutex::new(None))
}

thread_local! {
    /// Per-thread reentrancy flag. Set on entry to any `crdtSync*` function;
    /// cleared on exit. If a Kotlin callback invoked via the SyncBackend tries
    /// to re-enter, we detect it here BEFORE the SYNC_MGR mutex deadlocks.
    static SYNC_REENTRANCY_GUARD: Cell<bool> = const { Cell::new(false) };
}

/// RAII guard that enforces single-entry into the sync JNI surface per thread.
/// `enter()` returns `Err(())` if the current thread is already inside a
/// `crdtSync*` call (i.e. Kotlin re-entered via syncBackendComputeDelta).
struct SyncReentrancyGuard;

impl SyncReentrancyGuard {
    fn enter() -> Result<Self, ()> {
        SYNC_REENTRANCY_GUARD.with(|g| {
            if g.get() {
                log::error!(
                    "SYNC: REENTRANCY DETECTED — Kotlin re-entered crdtSync* from \
                     inside syncBackendComputeDelta. The callback MUST NOT call any \
                     crdtSync* function. Aborting to prevent SYNC_MGR mutex deadlock."
                );
                Err(())
            } else {
                g.set(true);
                Ok(SyncReentrancyGuard)
            }
        })
    }
}

impl Drop for SyncReentrancyGuard {
    fn drop(&mut self) {
        SYNC_REENTRANCY_GUARD.with(|g| g.set(false));
    }
}

// ---------------------------------------------------------------------------
// JNI helpers (local copies — trivial conversions)
// ---------------------------------------------------------------------------

fn jbytearray_to_vec(env: &mut JNIEnv, array: JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(array)
        .map_err(|e| format!("Failed to convert byte array: {}", e))
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
        "MemberUnban" => Ok(OpType::MemberUnban),
        "RoleSet" => Ok(OpType::RoleSet),
        "MsgAdd" => Ok(OpType::MsgAdd),
        "MsgEdit" => Ok(OpType::MsgEdit),
        "MsgDelete" => Ok(OpType::MsgDelete),
        "ReactionSet" => Ok(OpType::ReactionSet),
        "MetadataSet" => Ok(OpType::MetadataSet),
        "GroupDelete" => Ok(OpType::GroupDelete),
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
        "AllowMemberSendMessages" => Ok(MetadataKey::AllowMemberSendMessages),
        "AllowMemberInvites" => Ok(MetadataKey::AllowMemberInvites),
        "AllowMemberPin" => Ok(MetadataKey::AllowMemberPin),
        "AllowMemberChangeInfo" => Ok(MetadataKey::AllowMemberChangeInfo),
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
/// `self_pubkey_hex` is the caller's Ed25519 identity (64 hex chars). Used to
/// distinguish MsgAdd ops authored by this user from those authored by others,
/// so the UI can suppress notifications for self-echo. Pass an empty string to
/// count all MsgAdd as "from others" (disables self filtering).
///
/// Returns JSON: `{"applied": N, "rejected": N, "applied_messages": N,
/// "applied_messages_from_others": N, "limit_status": "Ok|..."}`
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtApplyOps(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    serialized_ops_bytes: JByteArray,
    self_pubkey_hex: JString,
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

        // Optional self pubkey: empty string disables self filtering.
        let self_pk: Option<[u8; 32]> = match jstring_to_string(&mut env, self_pubkey_hex) {
            Ok(s) if s.is_empty() => None,
            Ok(s) => match hex::decode(&s) {
                Ok(v) if v.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&v);
                    Some(a)
                }
                _ => throw_arg!(env, "self_pubkey_hex must be 64 hex chars or empty"),
            },
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
        let mut applied_messages = 0u64;
        let mut applied_messages_from_others = 0u64;

        for op in &ops {
            match state.apply_op(op) {
                Ok(true) => {
                    applied += 1;
                    if op.op_type == OpType::MsgAdd {
                        applied_messages += 1;
                        let from_self = self_pk.map(|pk| pk == op.author_pubkey).unwrap_or(false);
                        if !from_self {
                            applied_messages_from_others += 1;
                        }
                    }
                }
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
            "applied_messages": applied_messages,
            "applied_messages_from_others": applied_messages_from_others,
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
            let ban = params["ban"].as_bool().unwrap_or(false);
            let payload = MemberRemovePayload { target_device_id, reason, ban };
            OpEnvelope::create_signed(gid, otype, &payload, lamport, op_nonce, pub_key, priv_key)
        }
        OpType::MemberUnban => {
            let pk_hex = params["target_pubkey_hex"].as_str().unwrap_or("");
            let target_pk = match hex_to_32(pk_hex, "target_pubkey") {
                Ok(a) => a,
                Err(e) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", &*e);
                    return None;
                }
            };
            let target_device_id = DeviceID::from_pubkey(&target_pk);
            let payload = MemberUnbanPayload { target_device_id };
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

            // Parse admin_rights (optional; only meaningful when new_role == Admin)
            let admin_rights = params.get("admin_rights").and_then(|ar| {
                if ar.is_null() || !ar.is_object() { return None; }
                Some(AdminRights {
                    can_invite: ar["can_invite"].as_bool().unwrap_or(false),
                    can_remove: ar["can_remove"].as_bool().unwrap_or(false),
                    can_change_info: ar["can_change_info"].as_bool().unwrap_or(false),
                    can_delete_messages: ar["can_delete_messages"].as_bool().unwrap_or(false),
                    can_pin_messages: ar["can_pin_messages"].as_bool().unwrap_or(false),
                    can_add_admins: ar["can_add_admins"].as_bool().unwrap_or(false),
                })
            });

            // Parse custom_title (optional; Rust apply layer rejects > 32 bytes)
            let custom_title = params["custom_title"].as_str().map(|s| s.to_string());

            let payload = RoleSetPayload {
                target_device_id,
                new_role,
                admin_rights,
                custom_title,
            };
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
        OpType::GroupDelete => {
            let reason = params["reason"].as_str().map(|s| s.to_string());
            let payload = GroupDeletePayload { reason };
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
            "group_status" => serde_json::json!({
                "deleted": state.group_deleted,
                "delete_reason": state.delete_reason,
            }),
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
                "promoted_by_device_id": entry.promoted_by.map(|d| d.to_hex()),
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
    // Member-tier permission toggles (Phase 3). Emit only if set; Kotlin
    // falls back to documented defaults when keys are absent.
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
// 6. Sync — Phase 6 manager-backed implementation
// ===========================================================================
//
// Six functions:
//   crdtSyncInit            — set local DeviceID, allocate manager
//   crdtSyncBuildHello      — start outbound (Initiator) session
//   crdtSyncProcessFrame    — single inbound entrypoint
//   crdtSyncTick            — periodic timeout sweep
//   crdtSyncListSessions    — observability snapshot
//   crdtSyncAbortGroup      — abort all sessions for a group
//
// All sync functions return JSON action arrays that Kotlin executes:
//   [{"type":"SendFrame","wireType":51,"bytesB64":"..."},
//    {"type":"PersistOps","opsBytesB64":"..."},   // length-prefixed packed ops
//    {"type":"CloseSession","reason":"Normal"}]
//
// `crdtSyncProcessFrame` will, on inbound HELLO, call back into Kotlin via
// `RustBridge.syncBackendComputeDelta(groupIdHex, headsJson, bloomB64, bloomK)`.
// Kotlin returns a length-prefixed packed-ops byte[] of the delta. Reentrancy
// is forbidden — see SYNC_MGR doc.

/// JSON serialization of a heads map: `{"<deviceHex>": <lamport>, ...}`.
fn heads_to_json(heads: &HashMap<DeviceID, u64>) -> String {
    let map: serde_json::Map<String, serde_json::Value> = heads
        .iter()
        .map(|(d, l)| (d.to_hex(), serde_json::Value::from(*l)))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// Inverse of `heads_to_json`. Tolerant: ignores entries with bad hex/numbers.
fn heads_from_json(s: &str) -> HashMap<DeviceID, u64> {
    let mut out = HashMap::new();
    let v: serde_json::Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) => return out,
    };
    if let Some(obj) = v.as_object() {
        for (k, v) in obj {
            if let (Ok(d), Some(l)) = (DeviceID::from_hex(k), v.as_u64()) {
                out.insert(d, l);
            }
        }
    }
    out
}

/// Length-prefix-pack a list of OpEnvelopes for transport across the JNI
/// boundary. Same encoding as `decode_length_prefixed_ops` in this file.
fn pack_ops_length_prefixed(ops: &[OpEnvelope]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        if let Ok(b) = op.to_bytes() {
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(&b);
        }
    }
    out
}

/// Convert a `Vec<SyncAction>` to the JSON wire format Kotlin parses.
fn actions_to_json(actions: &[SyncAction]) -> String {
    use serde_json::json;
    let arr: Vec<serde_json::Value> = actions
        .iter()
        .map(|a| match a {
            SyncAction::SendFrame { wire_type, bytes } => json!({
                "type": "SendFrame",
                "wireType": *wire_type as u32,
                "bytesB64": B64.encode(bytes),
            }),
            SyncAction::PersistOps(ops) => json!({
                "type": "PersistOps",
                "opsBytesB64": B64.encode(pack_ops_length_prefixed(ops)),
            }),
            SyncAction::CloseSession { reason } => json!({
                "type": "CloseSession",
                "reason": format!("{:?}", reason),
            }),
        })
        .collect();
    serde_json::Value::Array(arr).to_string()
}

/// Bridge `SyncBackend::compute_delta` to a synchronous Kotlin static call.
///
/// **Reentrancy**: the Kotlin callback MUST NOT invoke any `crdtSync*`
/// function (would deadlock SYNC_MGR). It is permitted to read the DAO
/// and return a packed-ops byte[].
struct JniBackend<'a, 'env> {
    env: &'a mut JNIEnv<'env>,
}

impl<'a, 'env> SyncBackend for JniBackend<'a, 'env> {
    fn compute_delta(
        &mut self,
        group_id: &GroupID,
        peer_heads: &HashMap<DeviceID, u64>,
        peer_bloom: &[u8],
        peer_bloom_k: u8,
    ) -> Vec<OpEnvelope> {
        let group_hex = group_id.to_hex();
        let heads_json = heads_to_json(peer_heads);
        let bloom_b64 = B64.encode(peer_bloom);

        let group_jstr = match self.env.new_string(&group_hex) {
            Ok(s) => s,
            Err(e) => {
                log::error!("JniBackend: new_string(group) failed: {:?}", e);
                return vec![];
            }
        };
        let heads_jstr = match self.env.new_string(&heads_json) {
            Ok(s) => s,
            Err(e) => {
                log::error!("JniBackend: new_string(heads) failed: {:?}", e);
                return vec![];
            }
        };
        let bloom_jstr = match self.env.new_string(&bloom_b64) {
            Ok(s) => s,
            Err(e) => {
                log::error!("JniBackend: new_string(bloom) failed: {:?}", e);
                return vec![];
            }
        };
        let bridge_class = match self.env.find_class("com/securelegion/crypto/RustBridge") {
            Ok(c) => c,
            Err(e) => {
                log::error!("JniBackend: find_class(RustBridge) failed: {:?}", e);
                return vec![];
            }
        };

        use jni::objects::{JObject, JValue};
        let group_obj = JObject::from(group_jstr);
        let heads_obj = JObject::from(heads_jstr);
        let bloom_obj = JObject::from(bloom_jstr);
        let result = self.env.call_static_method(
            &bridge_class,
            "syncBackendComputeDelta",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)[B",
            &[
                JValue::Object(&group_obj),
                JValue::Object(&heads_obj),
                JValue::Object(&bloom_obj),
                JValue::Int(peer_bloom_k as i32),
            ],
        );

        let arr_obj = match result {
            Ok(v) => match v.l() {
                Ok(o) => o,
                Err(e) => {
                    log::error!("JniBackend: result.l() failed: {:?}", e);
                    return vec![];
                }
            },
            Err(e) => {
                log::error!("JniBackend: call_static_method(syncBackendComputeDelta) failed: {:?}", e);
                if self.env.exception_check().unwrap_or(false) {
                    let _ = self.env.exception_clear();
                }
                return vec![];
            }
        };

        if arr_obj.is_null() {
            return vec![];
        }
        let arr = JByteArray::from(arr_obj);
        let bytes = match self.env.convert_byte_array(&arr) {
            Ok(b) => b,
            Err(e) => {
                log::error!("JniBackend: convert_byte_array failed: {:?}", e);
                return vec![];
            }
        };

        match decode_length_prefixed_ops(&bytes, MAX_OPS_PER_SYNC_ROUND, MAX_SERIALIZED_OP_BYTES) {
            Ok(ops) => ops,
            Err(e) => {
                log::error!("JniBackend: delta decode failed: {}", e);
                vec![]
            }
        }
    }
}

// -------------------- 6.0 crdtDeriveDeviceId --------------------

/// Derive a CRDT DeviceID from an Ed25519 public key.
/// Returns the 32-char hex of `BLAKE3(pubkey)[..16]`. Empty string on error.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtDeriveDeviceId(
    mut env: JNIEnv,
    _class: JClass,
    pubkey_bytes: JByteArray,
) -> jstring {
    catch_panic!(env, {
        let bytes = match jbytearray_to_vec(&mut env, pubkey_bytes) {
            Ok(b) => b,
            Err(_) => return std::ptr::null_mut(),
        };
        if bytes.len() != 32 {
            return std::ptr::null_mut();
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        let device = DeviceID::from_pubkey(&pk);
        match env.new_string(device.to_hex()) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

// -------------------- 6.1 crdtSyncInit --------------------

/// Initialize the global SyncManager. Caller passes the local Ed25519
/// public key (32 bytes); Rust derives DeviceID via BLAKE3.
///
/// Idempotent: safe to call multiple times; later calls replace the manager
/// (aborting any in-flight sessions).
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtSyncInit(
    mut env: JNIEnv,
    _class: JClass,
    local_pubkey_bytes: JByteArray,
) -> jboolean {
    catch_panic!(env, {
        let _guard = match SyncReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => return JNI_FALSE,
        };
        let bytes = match jbytearray_to_vec(&mut env, local_pubkey_bytes) {
            Ok(b) => b,
            Err(e) => { log::error!("crdtSyncInit: {}", e); return JNI_FALSE; }
        };
        if bytes.len() != 32 {
            log::error!("crdtSyncInit: pubkey must be 32 bytes, got {}", bytes.len());
            return JNI_FALSE;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        let device = DeviceID::from_pubkey(&pk);
        let mut guard = get_sync_mgr().lock().unwrap();
        if let Some(old) = guard.as_mut() {
            let _ = old.abort_all();
        }
        *guard = Some(SyncManager::new(device));
        log::info!("crdtSyncInit: SyncManager initialized for device={}", device.to_hex());
        JNI_TRUE
    }, JNI_FALSE)
}

// -------------------- 6.2 crdtSyncBuildHello --------------------

/// Start an outbound (Initiator) sync session.
///
/// Returns a JSON action array. On error (peer == self, cap reached, etc.)
/// returns `[{"type":"Error","kind":"<StartError>"}]`.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtSyncBuildHello(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    peer_device_id_hex: JString,
    heads_json: JString,
    bloom_b64: JString,
    bloom_k: jni::sys::jint,
    bloom_n: jni::sys::jint,
    session_id: jni::sys::jlong,
    now_ms: jni::sys::jlong,
) -> jstring {
    catch_panic!(env, {
        let _guard = match SyncReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => throw_state!(env, "crdtSyncBuildHello: reentrant call"),
        };
        let gid = match parse_group_id(&mut env, group_id_hex) {
            Ok(g) => g,
            Err(e) => throw_arg!(env, format!("crdtSyncBuildHello: {}", e)),
        };
        let peer_hex = match jstring_to_string(&mut env, peer_device_id_hex) {
            Ok(s) => s,
            Err(e) => throw_arg!(env, format!("crdtSyncBuildHello: {}", e)),
        };
        let peer = match DeviceID::from_hex(&peer_hex) {
            Ok(d) => d,
            Err(e) => throw_arg!(env, format!("crdtSyncBuildHello peer: {}", e)),
        };
        let heads_str = jstring_to_string(&mut env, heads_json).unwrap_or_default();
        let heads = heads_from_json(&heads_str);
        let bloom_str = jstring_to_string(&mut env, bloom_b64).unwrap_or_default();
        let bloom = B64.decode(&bloom_str).unwrap_or_default();

        let mut guard = get_sync_mgr().lock().unwrap();
        let mgr = match guard.as_mut() {
            Some(m) => m,
            None => throw_state!(env, "SyncManager not initialized — call crdtSyncInit first"),
        };

        let actions_or_err = mgr.start_initiator(
            gid, peer, heads, bloom,
            bloom_k as u8,
            bloom_n.max(0) as u32,
            session_id as u64,
            now_ms as u64,
        );

        let json = match actions_or_err {
            Ok(actions) => actions_to_json(&actions),
            Err(e) => {
                let kind = match e {
                    StartError::GlobalCapReached => "GlobalCapReached",
                    StartError::SessionAlreadyExists => "SessionAlreadyExists",
                    StartError::PeerRateLimited => "PeerRateLimited",
                    StartError::EncodeError(_) => "EncodeError",
                    StartError::SelfPeer => "SelfPeer",
                };
                format!("[{{\"type\":\"Error\",\"kind\":\"{}\"}}]", kind)
            }
        };
        drop(guard);

        match env.new_string(&json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

// -------------------- 6.3 crdtSyncProcessFrame --------------------

/// Process an inbound transport frame.
///
/// `wire_type` is the Tor byte (0x31..0x34). `body_bytes` is the decoded
/// transport body (no transport envelope, no signature — the manager parses
/// the bincode SyncFrame directly).
///
/// Returns a JSON action array.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtSyncProcessFrame(
    mut env: JNIEnv,
    _class: JClass,
    peer_device_id_hex: JString,
    wire_type: jni::sys::jint,
    body_bytes: JByteArray,
    now_ms: jni::sys::jlong,
) -> jstring {
    catch_panic!(env, {
        let _guard = match SyncReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => throw_state!(env, "crdtSyncProcessFrame: reentrant call"),
        };
        let peer_hex = match jstring_to_string(&mut env, peer_device_id_hex) {
            Ok(s) => s,
            Err(e) => throw_arg!(env, format!("crdtSyncProcessFrame: {}", e)),
        };
        let peer = match DeviceID::from_hex(&peer_hex) {
            Ok(d) => d,
            Err(e) => throw_arg!(env, format!("crdtSyncProcessFrame peer: {}", e)),
        };
        let body = match jbytearray_to_vec(&mut env, body_bytes) {
            Ok(b) => b,
            Err(e) => throw_arg!(env, format!("crdtSyncProcessFrame body: {}", e)),
        };

        let actions = {
            let mut backend = JniBackend { env: &mut env };
            let mut guard = get_sync_mgr().lock().unwrap();
            let mgr = match guard.as_mut() {
                Some(m) => m,
                None => {
                    drop(guard);
                    throw_state!(env, "SyncManager not initialized — call crdtSyncInit first")
                }
            };
            mgr.process_frame(
                &mut backend,
                peer,
                wire_type as u8,
                &body,
                now_ms as u64,
            )
        };

        let json = actions_to_json(&actions);
        match env.new_string(&json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

// -------------------- 6.4 crdtSyncTick --------------------

/// Periodic tick (caller drives, e.g. once per second from a background loop).
/// Fires timeout transitions for stale sessions and returns CloseSession
/// actions for any harvested.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtSyncTick(
    mut env: JNIEnv,
    _class: JClass,
    now_ms: jni::sys::jlong,
) -> jstring {
    catch_panic!(env, {
        let _guard = match SyncReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => throw_state!(env, "crdtSyncTick: reentrant call"),
        };
        let actions = {
            let mut guard = get_sync_mgr().lock().unwrap();
            match guard.as_mut() {
                Some(m) => m.tick(now_ms as u64),
                None => vec![],
            }
        };
        let json = actions_to_json(&actions);
        match env.new_string(&json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

// -------------------- 6.5 crdtSyncListSessions --------------------

/// Observability snapshot. Returns a JSON array of `SessionInfo`.
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtSyncListSessions(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_panic!(env, {
        let _guard = match SyncReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => throw_state!(env, "crdtSyncListSessions: reentrant call"),
        };
        let snapshot = {
            let guard = get_sync_mgr().lock().unwrap();
            match guard.as_ref() {
                Some(m) => m.list_sessions(),
                None => vec![],
            }
        };
        let json = serde_json::to_string(&snapshot).unwrap_or_else(|_| "[]".into());
        match env.new_string(&json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}

// -------------------- 6.6 crdtSyncAbortGroup --------------------

/// Abort all sessions for a group (e.g. on group deletion).
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_crdtSyncAbortGroup(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
) -> jstring {
    catch_panic!(env, {
        let _guard = match SyncReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => throw_state!(env, "crdtSyncAbortGroup: reentrant call"),
        };
        let gid = match parse_group_id(&mut env, group_id_hex) {
            Ok(g) => g,
            Err(e) => throw_arg!(env, format!("crdtSyncAbortGroup: {}", e)),
        };
        let actions = {
            let mut guard = get_sync_mgr().lock().unwrap();
            match guard.as_mut() {
                Some(m) => m.abort_group(&gid),
                None => vec![],
            }
        };
        let json = actions_to_json(&actions);
        match env.new_string(&json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }, std::ptr::null_mut())
}
