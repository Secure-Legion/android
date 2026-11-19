//! Stateless, bounded platform API. All committed-log and roster arguments are
//! host-owned database state, never fields copied from a received packet.
//! JSON may contain encrypted content and membership key material: do not log
//! requests or responses. Signing seeds and the current group key are separate.
use crate::{
    history::{HistoryReceipt, MAX_HISTORY_BYTES},
    state::{AccountGroupState, Authority, GroupOperation},
    *,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, RngCore};
use secure_device_protocol::{CAP_SYNC, MAX_ROSTER_LEN};
use securelegion::crdt::{
    apply::ApplyError, limits::HARD_CAP_OPS_PER_GROUP, messages::MessageEntry, ops::*,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

pub const MAX_API_LEN: usize = 72 * 1024 * 1024;
pub const MAX_RESULT_LEN: usize = 40 * 1024 * 1024;
const MAX_LIVE_OPS: usize = 1000;
const MAX_ROSTERS: usize = 128;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("malformed group request")]
    Malformed,
    #[error("group request exceeds limit")]
    Limit,
    #[error("group authority or membership is unavailable")]
    Authority,
    #[error("invalid group operation or signature")]
    InvalidOperation,
    #[error("group dependency is unavailable")]
    Dependency,
    #[error("group operation identity conflict")]
    Conflict,
    #[error("group key rotation is required")]
    RekeyRequired,
}
type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Inspect {
        encoded: String,
    },
    ReadState {
        state: StateInput,
    },
    MissingHistoryAuthority {
        state: StateInput,
        limit: usize,
    },
    PreviewLive {
        state: StateInput,
        incoming: String,
    },
    PreviewHistory {
        state: StateInput,
        incoming: String,
        receipt: String,
        #[serde(default)]
        incoming_key: Option<String>,
    },
    PreviewInvite {
        state: StateInput,
        incoming: String,
        source_account: String,
        receipt: String,
        #[serde(default)]
        incoming_key: Option<String>,
    },
    PreviewReinvite {
        state: StateInput,
        incoming: String,
        source_account: String,
        receipt: String,
        incoming_key: Option<String>,
    },
    ReadMessages {
        state: StateInput,
        after: Option<String>,
        limit: usize,
        #[serde(default)]
        include_local_dispositions: bool,
        #[serde(default)]
        recent: bool,
    },
    SelectDelivery {
        state: StateInput,
        certificate: String,
        origin_op_id: String,
        acknowledged: Vec<String>,
        limit: usize,
        #[serde(default)]
        terminal_recipient: Option<String>,
    },
    CompactDeliveryAcknowledgements {
        state: StateInput,
        certificate: String,
        acknowledged: Vec<String>,
    },
    PrepareInvitation {
        state: StateInput,
        certificate: String,
        origin_op_id: String,
        recipient_account: String,
    },
    CreateOperation {
        state: StateInput,
        certificate: String,
        mutation: Mutation,
    },
    AttestHistory {
        state: StateInput,
        certificate: String,
    },
    AttestInvitation {
        state: StateInput,
        certificate: String,
    },
    Ratify {
        encoded: String,
        approved_hash: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateInput {
    group_id: String,
    account_public: String,
    existing_local: String,
    rosters: Vec<RosterInput>,
    ratifications: Vec<String>,
    now_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterInput {
    account_public: String,
    encoded: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Mutation {
    GroupRekey,
    GroupCreate {
        name: String,
    },
    MemberInvite {
        account_public: String,
        role: Role,
    },
    MemberAccept {
        invite_op_id: String,
    },
    MemberRemove {
        account_public: String,
        reason: RemoveReason,
        ban: bool,
    },
    MemberUnban {
        account_public: String,
    },
    RoleSet {
        account_public: String,
        role: Role,
        admin_rights: Option<Rights>,
        custom_title: Option<String>,
    },
    MsgAdd {
        ciphertext: String,
        nonce: String,
    },
    MsgEdit {
        msg_id: String,
        ciphertext: String,
        nonce: String,
    },
    MsgDelete {
        msg_id: String,
    },
    ReactionSet {
        msg_id: String,
        emoji: String,
        present: bool,
    },
    MetadataSet {
        key: MetadataKey,
        value: String,
    },
    GroupDelete {
        reason: Option<String>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rights {
    can_invite: bool,
    can_remove: bool,
    can_change_info: bool,
    can_delete_messages: bool,
    can_pin_messages: bool,
    can_add_admins: bool,
}
impl From<Rights> for AdminRights {
    fn from(r: Rights) -> Self {
        Self {
            can_invite: r.can_invite,
            can_remove: r.can_remove,
            can_change_info: r.can_change_info,
            can_delete_messages: r.can_delete_messages,
            can_pin_messages: r.can_pin_messages,
            can_add_admins: r.can_add_admins,
        }
    }
}

fn decode(value: &str, max: usize) -> ApiResult<Vec<u8>> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(ApiError::Limit);
    }
    let bytes = B64.decode(value).map_err(|_| ApiError::Malformed)?;
    if bytes.len() > max || B64.encode(&bytes) != value {
        return Err(ApiError::Malformed);
    }
    Ok(bytes)
}
fn fixed<const N: usize>(value: &str) -> ApiResult<[u8; N]> {
    decode(value, N)?
        .try_into()
        .map_err(|_| ApiError::Malformed)
}
fn hex_fixed<const N: usize>(value: &str) -> ApiResult<[u8; N]> {
    if value.len() != 2 * N {
        return Err(ApiError::Malformed);
    }
    let bytes = hex::decode(value).map_err(|_| ApiError::Malformed)?;
    if hex::encode(&bytes) != value {
        return Err(ApiError::Malformed);
    }
    bytes.try_into().map_err(|_| ApiError::Malformed)
}
fn op_id(value: &str) -> ApiResult<OpID> {
    let id = OpID::from_hex(value).map_err(|_| ApiError::Malformed)?;
    if id.to_hex() != value {
        return Err(ApiError::Malformed);
    }
    Ok(id)
}
fn state_error(error: state::StateError) -> ApiError {
    use state::StateError::*;
    match error {
        Conflict => ApiError::Conflict,
        MissingAuthority => ApiError::Authority,
        RekeyRequired => ApiError::RekeyRequired,
        ClockGap | MissingDependency => ApiError::Dependency,
        ResourceLimit => ApiError::Limit,
        Core(ApplyError::Unauthorized(_)) => ApiError::Authority,
        Core(ApplyError::Membership(_) | ApplyError::Message(_)) => ApiError::Dependency,
        _ => ApiError::InvalidOperation,
    }
}

/// Length-prefixed mixed legacy/SLGO01 records. No alternate parser may strip
/// a device wrapper and mistake its zero inner signature for a legacy record.
pub fn unpack(data: &[u8]) -> ApiResult<Vec<GroupOperation>> {
    if data.len() > MAX_HISTORY_BYTES {
        return Err(ApiError::Limit);
    }
    let mut ops = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let prefix = data.get(offset..offset + 4).ok_or(ApiError::Malformed)?;
        let len = u32::from_be_bytes(prefix.try_into().unwrap()) as usize;
        offset += 4;
        if len == 0 || len > MAX_OPERATION_BYTES || ops.len() >= HARD_CAP_OPS_PER_GROUP {
            return Err(ApiError::Limit);
        }
        let record = data.get(offset..offset + len).ok_or(ApiError::Malformed)?;
        ops.push(GroupOperation::decode(record).map_err(state_error)?);
        offset += len;
    }
    Ok(ops)
}
pub fn pack(ops: &[GroupOperation]) -> ApiResult<Vec<u8>> {
    let mut out = Vec::new();
    for op in ops {
        if out.len() + 4 + op.encoded().len() > MAX_HISTORY_BYTES {
            return Err(ApiError::Limit);
        }
        out.extend_from_slice(&(op.encoded().len() as u32).to_be_bytes());
        out.extend_from_slice(op.encoded());
    }
    Ok(out)
}

struct Context {
    group: GroupID,
    account: [u8; 32],
    old_bytes: Vec<u8>,
    old: Vec<GroupOperation>,
    rosters: Vec<DeviceRoster>,
    proofs: Vec<RootRatification>,
    now: u64,
}
impl Context {
    fn parse(input: StateInput, incoming: &[GroupOperation]) -> ApiResult<Self> {
        if input.now_ms == 0 || input.now_ms > MAX_SAFE || input.rosters.len() > MAX_ROSTERS {
            return Err(ApiError::Limit);
        }
        let group = GroupID::from_bytes(hex_fixed(&input.group_id)?);
        let account = fixed(&input.account_public)?;
        let old_bytes = decode(&input.existing_local, MAX_HISTORY_BYTES)?;
        let old = unpack(&old_bytes)?;
        let all: Vec<_> = old.iter().chain(incoming).collect();
        if all.iter().any(|op| op.operation().group_id != group) {
            return Err(ApiError::InvalidOperation);
        }
        if input.ratifications.len() > all.len() {
            return Err(ApiError::Limit);
        }
        let mut rosters = Vec::<DeviceRoster>::new();
        for input in input.rosters {
            let encoded = decode(&input.encoded, MAX_ROSTER_LEN)?;
            let root = fixed(&input.account_public)?;
            rosters.push(DeviceRoster::verify(&encoded, &root).map_err(|_| ApiError::Authority)?);
        }
        // Validate every equal-epoch observation too; never choose a convenient
        // lower epoch or silently resolve a fork. Pins still belong to the host.
        for roster in &rosters {
            let latest = rosters
                .iter()
                .filter(|r| r.account_ed() == roster.account_ed())
                .max_by_key(|r| r.epoch())
                .unwrap();
            latest
                .check_update(Some(roster), input.now_ms)
                .map_err(|_| ApiError::Authority)?;
        }
        let by_hash: HashMap<_, _> = all
            .iter()
            .filter(|op| op.certificate().is_some())
            .map(|op| (op.hash(), op))
            .collect();
        let mut seen = HashSet::new();
        let mut proofs = Vec::new();
        for proof in input.ratifications {
            let encoded = fixed::<134>(&proof)?;
            let hash: [u8; 32] = encoded[6..38].try_into().unwrap();
            if !seen.insert(hash) {
                return Err(ApiError::Malformed);
            }
            let operation = by_hash.get(&hash).ok_or(ApiError::InvalidOperation)?;
            proofs.push(
                RootRatification::verify_exact(
                    &encoded,
                    operation.hash(),
                    &operation.operation().author_pubkey,
                )
                .map_err(|_| ApiError::InvalidOperation)?,
            );
        }
        Ok(Self {
            group,
            account,
            old_bytes,
            old,
            rosters,
            proofs,
            now: input.now_ms,
        })
    }
    fn authority(&self) -> Authority<'_> {
        Authority {
            rosters: &self.rosters,
            ratifications: &self.proofs,
            now_ms: self.now,
        }
    }
    fn roster(&self, account: &[u8; 32]) -> ApiResult<&DeviceRoster> {
        self.rosters
            .iter()
            .filter(|r| r.account_ed() == account)
            .max_by_key(|r| r.epoch())
            .ok_or(ApiError::Authority)
    }
    fn load(&self) -> ApiResult<AccountGroupState> {
        AccountGroupState::rebuild(self.group, &self.old, &[], &self.authority())
            .map_err(state_error)
    }
    fn local_certificate(&self, encoded: &str, caps: u32) -> ApiResult<DeviceCertificate> {
        let cert = DeviceCertificate::verify(&fixed::<CERTIFICATE_LEN>(encoded)?, &self.account)
            .map_err(|_| ApiError::Authority)?;
        let current = self
            .roster(&self.account)?
            .active_device(&cert.claims().device_id_bytes(), caps, self.now)
            .map_err(|_| ApiError::Authority)?;
        // Signing must use the current certificate, rather than perpetuating an
        // old lease. Receiving separately allows the same device's renewed cert.
        if current.certificate().encoded() != cert.encoded() {
            return Err(ApiError::Authority);
        }
        Ok(cert)
    }
}

fn descriptor(op: &GroupOperation) -> Value {
    let inner = op.operation();
    let message_target = op.core_operation().and_then(|inner| match inner.op_type {
        OpType::MsgAdd => inner
            .decode_payload::<MsgAddPayload>()
            .ok()
            .map(|p| p.msg_id),
        OpType::MsgEdit => inner
            .decode_payload::<MsgEditPayload>()
            .ok()
            .map(|p| p.msg_id),
        OpType::MsgDelete => inner
            .decode_payload::<MsgDeletePayload>()
            .ok()
            .map(|p| p.msg_id),
        OpType::ReactionSet => inner
            .decode_payload::<ReactionSetPayload>()
            .ok()
            .map(|p| p.msg_id),
        _ => None,
    });
    let invitation_dependency = op
        .core_operation()
        .filter(|op| op.op_type == OpType::MemberAccept)
        .and_then(|op| op.decode_payload::<MemberAcceptPayload>().ok())
        .map(|p| p.invite_op_id.to_hex());
    json!({"op_id":inner.op_id.to_hex(), "op_type":op.type_name(),
        "group_id":inner.group_id.to_hex(), "account_public":B64.encode(inner.author_pubkey),
        "author_device_id":DeviceID::from_pubkey(&inner.author_pubkey).to_hex(),
        "installation_id":inner.op_id.author.to_hex(), "lamport":inner.lamport,
        "timestamp_ms":inner.timestamp_ms, "hash":hex::encode(op.hash()),
        "parent_heads":inner.parent_heads.iter().map(OpID::to_hex).collect::<Vec<_>>(),
        "message_target":message_target.map(hex::encode),
        "invitation_dependency":invitation_dependency,
        "epoch_predecessor":op.epoch().map(|epoch|hex::encode(epoch.header().previous_epoch)),
        "epoch_removal_dependencies":op.epoch().map(|epoch|epoch.header().removal_frontier.iter().map(OpID::to_hex).collect::<Vec<_>>()),
        "certificate":op.certificate().map(|cert| B64.encode(cert.encoded()))})
}
fn message_json(state: &AccountGroupState, m: &MessageEntry) -> Value {
    // A failed internal binding never guesses another epoch's key.
    let binding = state.message_cipher(m).ok();
    json!({"msg_id":hex::encode(m.msg_id),"author":m.author.to_hex(),
        "ciphertext_b64":binding.as_ref().map(|(_,cipher)|B64.encode(cipher)),"nonce_b64":B64.encode(m.nonce),
        "cipher_epoch":binding.map(|(id,_)|hex::encode(id)),
        "timestamp_ms":m.timestamp_ms,"deleted":m.deleted,"create_op_id":m.create_op.to_hex(),
        "reactions":m.reactions.iter().filter(|(_,p)| **p).map(|((r,e),_)|json!({"reactor":r.to_hex(),"emoji":e})).collect::<Vec<_>>()})
}
fn verify_key(state: &AccountGroupState, account: &[u8; 32], key: &[u8; 32]) -> ApiResult<()> {
    let id = DeviceID::from_pubkey(account);
    if !state.core().membership.members().contains_key(&id) && state.archived_invite(&id).is_none()
    {
        return Err(ApiError::Authority);
    }
    let stored = state.current_key().ok_or(ApiError::Authority)?;
    if !group_key_eq(stored, key) {
        return Err(ApiError::InvalidOperation);
    }
    Ok(())
}
fn check_pending_invitation(
    state: &AccountGroupState,
    account: &[u8; 32],
    source: &[u8; 32],
) -> ApiResult<()> {
    let account_id = DeviceID::from_pubkey(account);
    let source_id = DeviceID::from_pubkey(source);
    let member = state
        .core()
        .membership
        .members()
        .get(&account_id)
        .ok_or(ApiError::Authority)?;
    let sender = state
        .core()
        .membership
        .get_active_member(&source_id)
        .ok_or(ApiError::Authority)?;
    if state.core().group_deleted
        || member.removed
        || member.accepted
        || state.is_banned(&account_id)
        || !sender.accepted
        || state.is_banned(&source_id)
        || !state.core().membership.can_author_op(
            &source_id,
            &OpType::MemberInvite,
            &state.core().metadata,
        )
    {
        return Err(ApiError::Authority);
    }
    Ok(())
}

/// An active installation may have missed another device's valid leave/kick.
/// Validate a bounded closing closure with CURRENT roles before permitting the
/// existing removed->pending invitation path. Historical reconstruction alone
/// must never manufacture this transition or bypass current authority.
fn prove_prior_departure(
    ctx: &Context,
    current: &AccountGroupState,
    incoming: &[GroupOperation],
) -> ApiResult<OpID> {
    let account = DeviceID::from_pubkey(&ctx.account);
    let old_invite = current
        .core()
        .membership
        .members()
        .get(&account)
        .ok_or(ApiError::Authority)?
        .invited_by;
    let mut candidates: Vec<_> = incoming
        .iter()
        .filter(|op| {
            op.operation().lamport > old_invite.lamport
                && op.core_operation().is_some_and(|inner| {
                    inner.op_type == OpType::MemberRemove
                        && inner
                            .decode_payload::<MemberRemovePayload>()
                            .is_ok_and(|payload| payload.target_device_id == account)
                })
        })
        .collect();
    candidates.sort_by_key(|op| (op.operation().lamport, op.operation().op_id));
    if candidates.len() > 64 {
        return Err(ApiError::Limit);
    }
    let mut union = ctx.old.clone();
    union.extend_from_slice(incoming);
    for closing in candidates {
        let mut shadow = current.clone();
        let mut known: HashSet<_> = ctx.old.iter().map(GroupOperation::hash).collect();
        loop {
            let selected =
                crate::delivery::select(&union, closing.operation().op_id, &known, MAX_LIVE_OPS)
                    .map_err(|_| ApiError::Conflict)?;
            let batch: Vec<_> = selected.operations.iter().map(|op| (*op).clone()).collect();
            if shadow.apply_batch(&batch, &ctx.authority()).is_err() {
                break;
            }
            known.extend(batch.iter().map(GroupOperation::hash));
            if selected.complete {
                if !shadow.core().group_deleted
                    && shadow
                        .core()
                        .membership
                        .members()
                        .get(&account)
                        .is_some_and(|member| member.removed && member.invited_by == old_invite)
                {
                    return Ok(old_invite);
                }
                break;
            }
            if batch.is_empty() {
                return Err(ApiError::Dependency);
            }
        }
    }
    Err(ApiError::Authority)
}

fn encode_result(value: &Value) -> ApiResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| ApiError::Malformed)?;
    if bytes.len() > MAX_RESULT_LEN {
        return Err(ApiError::Limit);
    }
    Ok(bytes)
}

fn summary(
    ctx: &Context,
    state: &AccountGroupState,
    incoming: &[GroupOperation],
    key: &[u8; 32],
) -> ApiResult<Value> {
    verify_key(state, &ctx.account, key)?;
    render_summary(ctx, state, incoming, false)
}
fn render_summary(
    ctx: &Context,
    state: &AccountGroupState,
    incoming: &[GroupOperation],
    with_keys: bool,
) -> ApiResult<Value> {
    let core = state.core();
    let id = DeviceID::from_pubkey(&ctx.account);
    let ours = core.membership.members().get(&id);
    let archive = state.archived_invite(&id);
    let invite_id = ours
        .map(|m| m.invited_by)
        .or_else(|| archive.map(|(id, _)| *id))
        .ok_or(ApiError::Authority)?;
    let founding_name = ctx
        .old
        .iter()
        .chain(incoming)
        .filter_map(GroupOperation::core_operation)
        .find(|o| o.op_type == OpType::GroupCreate)
        .and_then(|o| o.decode_payload::<GroupCreatePayload>().ok())
        .map(|p| p.group_name)
        .unwrap_or_else(|| "Group".into());
    let members: Vec<_> = core.membership.members().values().map(|m|json!({
        "device_id":m.device_id.to_hex(),"pubkey_hex":hex::encode(m.pubkey),"role":format!("{:?}",m.role),
        "accepted":m.accepted,"removed":m.removed,"banned":state.is_banned(&m.device_id),"rekey_required":state.needs_rekey() && m.accepted && !m.removed && !state.is_banned(&m.device_id),
        "invited_by_op_id":m.invited_by.to_hex(),"admin_rights":m.admin_rights,"custom_title":m.custom_title})).collect();
    let mut result = json!({"name":core.metadata.name().unwrap_or(&founding_name),
        "our_role":ours.filter(|m|!m.removed && !m.banned).map(|m|format!("{:?}",m.role)).unwrap_or_else(||"Removed".into()),
        "pending_invite":ours.is_some_and(|m|!m.accepted && !m.removed && !m.banned),"invite_op_id":invite_id.to_hex(),
        "archived":ours.is_none(),
        "deleted":core.group_deleted,"needs_rekey":state.needs_rekey(),
        "state_hash":hex::encode(state.state_hash()),"op_count":core.op_count,"members":members,
        "current_epoch":state.current_epoch().map(hex::encode),
        "heads":core.heads.iter().map(OpID::to_hex).collect::<Vec<_>>(),
        "metadata":core.metadata.registers().iter().map(|(k,v)|json!({"key":k,"value":B64.encode(&v.value),"op_id":v.writer_op.to_hex()})).collect::<Vec<_>>(),
        "incoming_ops":incoming.iter().map(descriptor).collect::<Vec<_>>(),
        "superseded":state.superseded().iter().map(|(id,hash)|json!({"op_id":id.to_hex(),"hash":hex::encode(hash)})).collect::<Vec<_>>(),
        "historical_principals":state.historical_principals().map(hex::encode).collect::<Vec<_>>(),
        // Accepted historical messages remain visible after their author leaves.
        // Superseded concurrent effects never entered this validated message map.
        "last_message":core.messages.messages().values().max_by_key(|m|m.create_op).map(|message|message_json(state,message)) });
    if with_keys {
        result["group_secret"] = json!(B64.encode(state.current_key().ok_or(ApiError::Authority)?));
        result["keyring"]=json!(state.key_versions().map(|(id,key,eligible)|json!({"epoch":hex::encode(id),"key":B64.encode(key),"eligible":eligible})).collect::<Vec<_>>());
    }
    Ok(result)
}

fn membership_dependencies(
    history: &[GroupOperation],
    state: &AccountGroupState,
    account: DeviceID,
    required: &mut HashSet<OpID>,
) {
    if let Some(member) = state.core().membership.members().get(&account) {
        required.insert(member.invited_by);
        if let Some(removed) = member.remove_op {
            required.insert(removed);
        }
        if let Some(ban) = state.ban_operation(&account) {
            required.insert(ban);
        }
        if let Some(accept) = history
            .iter()
            .filter_map(GroupOperation::core_operation)
            .filter(|op| {
                op.author_pubkey == member.pubkey
                    && op.op_type == OpType::MemberAccept
                    && !state.superseded().contains_key(&op.op_id)
                    && op
                        .decode_payload::<MemberAcceptPayload>()
                        .is_ok_and(|p| p.invite_op_id == member.invited_by)
            })
            .max_by_key(|op| op.op_id)
        {
            required.insert(accept.op_id);
        }
        if let Some(grant) = history
            .iter()
            .filter_map(GroupOperation::core_operation)
            .filter(|op| {
                op.op_type == OpType::RoleSet
                    && op.op_id > member.invited_by
                    && !state.superseded().contains_key(&op.op_id)
                    && op
                        .decode_payload::<RoleSetPayload>()
                        .is_ok_and(|p| p.target_device_id == account)
            })
            .max_by_key(|op| op.op_id)
        {
            required.insert(grant.op_id);
        }
    }
}

fn create(
    ctx: &Context,
    state: &AccountGroupState,
    cert: DeviceCertificate,
    mutation: Mutation,
    seed: &[u8; 32],
    key: &[u8; 32],
) -> ApiResult<GroupOperation> {
    let lamport = state
        .core()
        .max_lamport
        .values()
        .copied()
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .filter(|n| *n <= MAX_SAFE)
        .ok_or(ApiError::Limit)?;
    let nonce = OsRng.next_u64();
    let account = DeviceID::from_pubkey(&ctx.account);
    let lifecycle = state
        .core()
        .membership
        .members()
        .get(&account)
        .map(|member| member.invited_by.lamport)
        .unwrap_or(0);
    // Preserve old committed history locally, but do not make a new lifecycle
    // depend on superseded offline actions or a previous lifecycle's messages.
    // Exact current invitation/acceptance/key authority is added below.
    let current_history = |op: &GroupOperation| {
        op.operation().lamport >= lifecycle
            && !state.superseded().contains_key(&op.operation().op_id)
    };
    let current_ids: HashSet<_> = ctx
        .old
        .iter()
        .filter(|op| current_history(op))
        .map(|op| op.operation().op_id)
        .collect();
    let mut heads: Vec<_> = state
        .core()
        .heads
        .iter()
        .copied()
        .filter(|id| current_ids.contains(id))
        .collect();
    // A bounded subset still references already committed earlier operations.
    // The complete max lamport above is independent of this bounded DAG window.
    if heads.len() > MAX_PARENT_HEADS {
        heads = heads.split_off(heads.len() - MAX_PARENT_HEADS);
    }
    // Keep exact authority/key dependencies even when a new leaf did not author
    // the account's acceptance or promotion. Missing proofs can then be repaired.
    let mut required = HashSet::new();
    let author = DeviceID::from_pubkey(&cert.claims().device_ed);
    if let Some(prior) = ctx
        .old
        .iter()
        .filter(|op| current_history(op))
        .map(GroupOperation::operation)
        .filter(|op| op.op_id.author == author)
        .max_by_key(|op| (op.lamport, op.op_id))
    {
        required.insert(prior.op_id);
    }
    membership_dependencies(&ctx.old, state, account, &mut required);
    let membership_target = match &mutation {
        Mutation::MemberInvite { account_public, .. }
        | Mutation::MemberRemove { account_public, .. }
        | Mutation::MemberUnban { account_public }
        | Mutation::RoleSet { account_public, .. } => {
            Some(DeviceID::from_pubkey(&fixed::<32>(account_public)?))
        }
        _ => None,
    };
    if let Some(target) = membership_target {
        membership_dependencies(&ctx.old, state, target, &mut required);
    }
    for (property, value) in state.core().metadata.registers() {
        if matches!(
            property,
            MetadataKey::AllowMemberSendMessages
                | MetadataKey::AllowMemberInvites
                | MetadataKey::AllowMemberChangeInfo
        ) {
            required.insert(value.writer_op);
        }
    }
    if let Some(epoch) = state.current_epoch_operation() {
        required.insert(epoch);
    }
    let message_target = match &mutation {
        Mutation::MsgEdit { msg_id, .. }
        | Mutation::MsgDelete { msg_id }
        | Mutation::ReactionSet { msg_id, .. } => Some(hex_fixed::<32>(msg_id)?),
        _ => None,
    };
    if let Some(id) = message_target {
        let message = state
            .core()
            .messages
            .messages()
            .get(&id)
            .ok_or(ApiError::Dependency)?;
        required.insert(message.create_op);
        if let Some(edit) = message.last_edit_op {
            required.insert(edit);
        }
    }
    if let Mutation::MemberInvite { account_public, .. } = &mutation {
        let target = DeviceID::from_pubkey(&fixed(account_public)?);
        if let Some(removed) = state
            .core()
            .membership
            .members()
            .get(&target)
            .and_then(|m| m.remove_op)
        {
            required.insert(removed);
        }
    }
    if required.len() > MAX_PARENT_HEADS {
        return Err(ApiError::Limit);
    }
    heads.retain(|id| !required.contains(id));
    heads = heads
        .into_iter()
        .rev()
        .take(MAX_PARENT_HEADS - required.len())
        .collect();
    heads.extend(required);
    heads.sort();
    macro_rules! make {
        ($kind:ident, $payload:expr) => {{
            let payload = $payload;
            DelegatedOperation::create(
                cert,
                seed,
                ctx.group,
                OpType::$kind,
                &payload,
                heads,
                lamport,
                nonce,
                ctx.now,
            )
            .map(GroupOperation::from_device)
            .map_err(|_| ApiError::InvalidOperation)
        }};
    }
    match mutation {
        Mutation::GroupRekey => {
            if state.core().group_deleted || !state.can_rotate(&ctx.account) {
                return Err(ApiError::Authority);
            }
            let previous_epoch = state.current_epoch().ok_or(ApiError::Dependency)?;
            let op_id = OpID::new(
                DeviceID::from_pubkey(&cert.claims().device_ed),
                lamport,
                nonce,
            );
            let mut fresh = zeroize::Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(fresh.as_mut());
            epoch::EpochOperation::create(
                cert,
                seed,
                epoch::EpochHeader {
                    group_id: ctx.group,
                    op_id,
                    timestamp_ms: ctx.now,
                    parent_heads: heads,
                    removal_frontier: state.removal_frontier(),
                    previous_epoch,
                    membership_digest: state.membership_digest(),
                },
                *fresh,
            )
            .map(GroupOperation::from_epoch)
            .map_err(|_| ApiError::InvalidOperation)
        }
        Mutation::GroupCreate { name } => {
            if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                return Err(ApiError::Malformed);
            }
            make!(
                GroupCreate,
                GroupCreatePayload {
                    group_name: name,
                    encrypted_group_secret: key.to_vec()
                }
            )
        }
        Mutation::MemberInvite {
            account_public,
            role,
        } => {
            let root = fixed(&account_public)?;
            if !matches!(role, Role::Member | Role::ReadOnly) {
                return Err(ApiError::Authority);
            }
            if state.core().membership.active_member_count() >= 20 {
                return Err(ApiError::Limit);
            }
            make!(
                MemberInvite,
                MemberInvitePayload {
                    invited_device_id: DeviceID::from_pubkey(&root),
                    invited_pubkey: root,
                    role,
                    encrypted_group_secret: key.to_vec()
                }
            )
        }
        Mutation::MemberAccept { invite_op_id } => make!(
            MemberAccept,
            MemberAcceptPayload {
                invite_op_id: op_id(&invite_op_id)?
            }
        ),
        Mutation::MemberRemove {
            account_public,
            reason,
            ban,
        } => {
            if matches!(reason, RemoveReason::Leave) && ban {
                return Err(ApiError::Malformed);
            }
            make!(
                MemberRemove,
                MemberRemovePayload {
                    target_device_id: DeviceID::from_pubkey(&fixed(&account_public)?),
                    reason,
                    ban
                }
            )
        }
        Mutation::MemberUnban { account_public } => make!(
            MemberUnban,
            MemberUnbanPayload {
                target_device_id: DeviceID::from_pubkey(&fixed(&account_public)?)
            }
        ),
        Mutation::RoleSet {
            account_public,
            role,
            admin_rights,
            custom_title,
        } => {
            if custom_title
                .as_ref()
                .is_some_and(|s| s.len() > 32 || s.chars().any(char::is_control))
                || (role != Role::Admin && admin_rights.is_some())
            {
                return Err(ApiError::Malformed);
            }
            make!(
                RoleSet,
                RoleSetPayload {
                    target_device_id: DeviceID::from_pubkey(&fixed(&account_public)?),
                    new_role: role,
                    admin_rights: admin_rights.map(Into::into),
                    custom_title
                }
            )
        }
        Mutation::MsgAdd {
            ciphertext,
            nonce: iv,
        } => {
            if state.needs_rekey() {
                return Err(ApiError::RekeyRequired);
            }
            let ciphertext = decode(&ciphertext, 30 * 1024 + 16)?;
            if ciphertext.len() < 16 {
                return Err(ApiError::Malformed);
            }
            make!(
                MsgAdd,
                MsgAddPayload {
                    msg_id: generate_msg_id(
                        &DeviceID::from_pubkey(&cert.claims().device_ed),
                        lamport,
                        nonce
                    ),
                    ciphertext: crate::message_cipher::wrap(
                        state.current_epoch().ok_or(ApiError::Dependency)?,
                        &ciphertext
                    ),
                    nonce: fixed(&iv)?
                }
            )
        }
        Mutation::MsgEdit {
            msg_id,
            ciphertext,
            nonce: iv,
        } => {
            if state.needs_rekey() {
                return Err(ApiError::RekeyRequired);
            }
            let ciphertext = decode(&ciphertext, 30 * 1024 + 16)?;
            if ciphertext.len() < 16 {
                return Err(ApiError::Malformed);
            }
            make!(
                MsgEdit,
                MsgEditPayload {
                    msg_id: hex_fixed(&msg_id)?,
                    new_ciphertext: crate::message_cipher::wrap(
                        state.current_epoch().ok_or(ApiError::Dependency)?,
                        &ciphertext
                    ),
                    nonce: fixed(&iv)?
                }
            )
        }
        Mutation::MsgDelete { msg_id } => make!(
            MsgDelete,
            MsgDeletePayload {
                msg_id: hex_fixed(&msg_id)?
            }
        ),
        Mutation::ReactionSet {
            msg_id,
            emoji,
            present,
        } => {
            if emoji.is_empty() || emoji.len() > 64 || emoji.chars().any(char::is_control) {
                return Err(ApiError::Malformed);
            }
            make!(
                ReactionSet,
                ReactionSetPayload {
                    msg_id: hex_fixed(&msg_id)?,
                    emoji,
                    present
                }
            )
        }
        Mutation::MetadataSet { key: field, value } => {
            let value = decode(&value, 32 * 1024)?;
            match field {
                MetadataKey::Name | MetadataKey::Topic => {
                    let text = std::str::from_utf8(&value).map_err(|_| ApiError::Malformed)?;
                    if value.len() > 1024 || text.chars().any(char::is_control) {
                        return Err(ApiError::Malformed);
                    }
                }
                MetadataKey::Avatar => {}
                _ => {
                    if value.as_slice() != [0] && value.as_slice() != [1] {
                        return Err(ApiError::Malformed);
                    }
                }
            }
            make!(MetadataSet, MetadataSetPayload { key: field, value })
        }
        Mutation::GroupDelete { reason } => {
            if reason
                .as_ref()
                .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
            {
                return Err(ApiError::Malformed);
            }
            make!(GroupDelete, GroupDeletePayload { reason })
        }
    }
}

/// Signing seed means leaf key for create/attest and root key for ratify. The
/// host must require primary role + fresh authority and an exact committed hash
/// before ratifying. Supplying any secret to a read-only request is rejected.
pub fn execute(
    request: &[u8],
    signing_seed: Option<&[u8; 32]>,
    group_key: Option<&[u8; 32]>,
) -> ApiResult<Vec<u8>> {
    if request.is_empty() || request.len() > MAX_API_LEN {
        return Err(ApiError::Limit);
    }
    let request: Request = serde_json::from_slice(request).map_err(|_| ApiError::Malformed)?;
    let signing = matches!(
        request,
        Request::CreateOperation { .. }
            | Request::AttestHistory { .. }
            | Request::AttestInvitation { .. }
            | Request::PrepareInvitation { .. }
            | Request::Ratify { .. }
    );
    let needs_key = !matches!(request, Request::Inspect { .. } | Request::Ratify { .. });
    if signing != signing_seed.is_some() || needs_key != group_key.is_some() {
        return Err(ApiError::Malformed);
    }
    let reinvitation = matches!(&request, Request::PreviewReinvite { .. });
    let value = match request {
        Request::ReadState { state } => {
            let ctx = Context::parse(state, &[])?;
            summary(&ctx, &ctx.load()?, &[], group_key.unwrap())?
        }
        Request::MissingHistoryAuthority { state, limit } => {
            if limit == 0 || limit > 128 {
                return Err(ApiError::Limit);
            }
            let ctx = Context::parse(state, &[])?;
            let current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            let authority = ctx.authority();
            let permanent = authority.ratified(ctx.old.iter());
            let mut missing: Vec<_> = ctx
                .old
                .iter()
                .filter(|op| {
                    op.certificate().is_some_and(|cert| {
                        !permanent.contains(&op.hash())
                            && authority.authorize_certificate(cert).is_err()
                    })
                })
                .map(|op| (op.operation().author_pubkey, op.hash()))
                .collect();
            missing.sort();
            let has_more = missing.len() > limit;
            missing.truncate(limit);
            json!({"missing":missing.iter().map(|(root,hash)|json!({
                "account_public":B64.encode(root),"hash":hex::encode(hash)})).collect::<Vec<_>>(),
                "has_more":has_more,"state_hash":hex::encode(current.state_hash()),
                "op_count":current.core().op_count})
        }
        Request::Inspect { encoded } => descriptor(
            &GroupOperation::decode(&decode(&encoded, MAX_OPERATION_BYTES)?)
                .map_err(state_error)?,
        ),
        Request::Ratify {
            encoded,
            approved_hash,
        } => {
            let op = GroupOperation::decode(&decode(&encoded, MAX_OPERATION_BYTES)?)
                .map_err(state_error)?;
            if op.hash() != hex_fixed(&approved_hash)? {
                return Err(ApiError::Conflict);
            }
            if op.certificate().is_none() {
                return Err(ApiError::Malformed);
            }
            let proof = RootRatification::issue_exact(
                op.hash(),
                &op.operation().author_pubkey,
                signing_seed.unwrap(),
            )
            .map_err(|_| ApiError::Authority)?;
            json!({"hash":approved_hash,"ratification":B64.encode(proof.encoded())})
        }
        Request::PreviewLive { state, incoming } => {
            let incoming = unpack(&decode(&incoming, MAX_HISTORY_BYTES)?)?;
            if incoming.is_empty() || incoming.len() > MAX_LIVE_OPS {
                return Err(ApiError::Limit);
            }
            let ctx = Context::parse(state, &incoming)?;
            if ctx.old.is_empty() {
                return Err(ApiError::Dependency);
            }
            let mut current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            let recipient_removed = current
                .core()
                .membership
                .members()
                .get(&DeviceID::from_pubkey(&ctx.account))
                .is_none_or(|m| m.removed || m.banned);
            // Preserve packet order and use CURRENT roles. Never sort an unseen
            // foreign operation back into a more convenient historical role.
            let applied = current
                .apply_batch(&incoming, &ctx.authority())
                .map_err(state_error)?;
            if recipient_removed && applied != 0 {
                return Err(ApiError::Authority);
            }
            // Also require a deterministic restart/replay of the accepted union.
            // Passing current-role authorization must not create a log that
            // changes permissions or cannot be rebuilt after a restart.
            let mut accepted = ctx.old.clone();
            accepted.extend(incoming.iter().cloned());
            let rebuilt = AccountGroupState::rebuild(ctx.group, &accepted, &[], &ctx.authority())
                .map_err(state_error)?;
            render_summary(&ctx, &rebuilt, &incoming, true)?
        }
        Request::PreviewHistory {
            state,
            incoming,
            receipt,
            incoming_key,
        } => {
            let bytes = decode(&incoming, MAX_HISTORY_BYTES)?;
            let incoming = unpack(&bytes)?;
            let ctx = Context::parse(state, &incoming)?;
            let receipt = HistoryReceipt::verify(
                &decode(&receipt, history::RECEIPT_LEN)?,
                &ctx.account,
                ctx.group,
                &bytes,
            )
            .map_err(|_| ApiError::Authority)?;
            receipt
                .authorize_current(ctx.roster(&ctx.account)?, CAP_GROUPS | CAP_SYNC, ctx.now)
                .map_err(|_| ApiError::Authority)?;
            if !ctx.old.is_empty() {
                verify_key(&ctx.load()?, &ctx.account, group_key.unwrap())?;
            }
            // Legacy same-key callers may attest an exact partial delta. A
            // changing source key requires its complete receipt-bound branch.
            if incoming_key.is_some() || ctx.old.is_empty() {
                let proposed = incoming_key
                    .as_ref()
                    .map(|encoded| fixed::<32>(encoded))
                    .transpose()?
                    .unwrap_or(*group_key.unwrap());
                let source =
                    AccountGroupState::rebuild(ctx.group, &incoming, &[], &ctx.authority())
                        .map_err(state_error)?;
                verify_key(&source, &ctx.account, &proposed)?;
            }
            // Only an authenticated CURRENT OWN-ACCOUNT sync+groups device can
            // attest that this exact history was already validated/committed.
            let mut trusted = ctx.old.clone();
            trusted.extend(incoming.iter().cloned());
            let rebuilt = AccountGroupState::rebuild(ctx.group, &trusted, &[], &ctx.authority())
                .map_err(state_error)?;
            if incoming_key.is_none() && !ctx.old.is_empty() {
                verify_key(&rebuilt, &ctx.account, group_key.unwrap())?;
            }
            render_summary(&ctx, &rebuilt, &incoming, true)?
        }
        Request::PreviewInvite {
            state,
            incoming,
            source_account,
            receipt,
            incoming_key,
        }
        | Request::PreviewReinvite {
            state,
            incoming,
            source_account,
            receipt,
            incoming_key,
        } => {
            let bytes = decode(&incoming, MAX_HISTORY_BYTES)?;
            let incoming = unpack(&bytes)?;
            let ctx = Context::parse(state, &incoming)?;
            let source = fixed(&source_account)?;
            if source == ctx.account {
                return Err(ApiError::Authority);
            }
            let receipt = HistoryReceipt::verify(
                &decode(&receipt, history::RECEIPT_LEN)?,
                &source,
                ctx.group,
                &bytes,
            )
            .map_err(|_| ApiError::Authority)?;
            receipt
                .authorize_current(ctx.roster(&source)?, CAP_GROUPS, ctx.now)
                .map_err(|_| ApiError::Authority)?;
            if !ctx.old.is_empty() {
                // Receipt caches are bounded. Re-ACK exact already-committed
                // invitation history without replaying membership or imposing
                // the smaller live-batch limit. Unseen history must use an
                // explicit reinvitation lifecycle, never overwrite local state.
                let known: HashSet<_> = ctx.old.iter().map(GroupOperation::hash).collect();
                if incoming.is_empty() {
                    return Err(ApiError::Conflict);
                }
                let current = ctx.load()?;
                verify_key(&current, &ctx.account, group_key.unwrap())?;
                let unseen = incoming.iter().any(|op| !known.contains(&op.hash()));
                if unseen {
                    if !reinvitation || current.core().group_deleted {
                        return Err(ApiError::Conflict);
                    }
                    let account_id = DeviceID::from_pubkey(&ctx.account);
                    let old_invite = match current.core().membership.members().get(&account_id) {
                        Some(member) if member.removed => member.invited_by,
                        None => current
                            .archived_invite(&account_id)
                            .map(|(id, _)| *id)
                            .ok_or(ApiError::Authority)?,
                        Some(_) => prove_prior_departure(&ctx, &current, &incoming)?,
                    };
                    let source_view = AccountGroupState::reconstruct_invitation(
                        ctx.group,
                        &incoming,
                        &ctx.old,
                        &ctx.authority(),
                    )
                    .map_err(state_error)?;
                    let proposed = incoming_key
                        .as_ref()
                        .map(|encoded| fixed::<32>(encoded))
                        .transpose()?
                        .unwrap_or(*group_key.unwrap());
                    verify_key(&source_view, &ctx.account, &proposed)?;
                    check_pending_invitation(&source_view, &ctx.account, &source)?;
                    let next_invite = source_view
                        .core()
                        .membership
                        .members()
                        .get(&account_id)
                        .unwrap()
                        .invited_by;
                    if next_invite == old_invite
                        || known.contains(
                            &incoming
                                .iter()
                                .find(|op| op.operation().op_id == next_invite)
                                .ok_or(ApiError::Dependency)?
                                .hash(),
                        )
                    {
                        return Err(ApiError::Conflict);
                    }
                    let mut trusted = ctx.old.clone();
                    trusted.extend(incoming.iter().cloned());
                    let merged =
                        AccountGroupState::rebuild(ctx.group, &trusted, &[], &ctx.authority())
                            .map_err(state_error)?;
                    check_pending_invitation(&merged, &ctx.account, &source)?;
                    if merged
                        .core()
                        .membership
                        .members()
                        .get(&account_id)
                        .unwrap()
                        .invited_by
                        != next_invite
                    {
                        return Err(ApiError::Conflict);
                    }
                    let result = render_summary(&ctx, &merged, &incoming, true)?;
                    return encode_result(&result);
                }
                let proposed = incoming_key
                    .as_ref()
                    .map(|encoded| fixed::<32>(encoded))
                    .transpose()?
                    .unwrap_or(*group_key.unwrap());
                let original =
                    AccountGroupState::rebuild(ctx.group, &incoming, &[], &ctx.authority())
                        .map_err(state_error)?;
                verify_key(&original, &ctx.account, &proposed)?;
                return serde_json::to_vec(&render_summary(&ctx, &current, &incoming, true)?)
                    .map_err(|_| ApiError::Malformed)
                    .and_then(|bytes| {
                        if bytes.len() <= MAX_RESULT_LEN {
                            Ok(bytes)
                        } else {
                            Err(ApiError::Limit)
                        }
                    });
            }
            // Foreign receipts authenticate delivery only. Every unseen foreign
            // operation still requires current authority or exact root proof.
            let rebuilt = AccountGroupState::reconstruct_invitation(
                ctx.group,
                &incoming,
                &[],
                &ctx.authority(),
            )
            .map_err(state_error)?;
            check_pending_invitation(&rebuilt, &ctx.account, &source)?;
            let proposed = incoming_key
                .as_ref()
                .map(|encoded| fixed::<32>(encoded))
                .transpose()?
                .unwrap_or(*group_key.unwrap());
            verify_key(&rebuilt, &ctx.account, &proposed)?;
            render_summary(&ctx, &rebuilt, &incoming, true)?
        }
        Request::ReadMessages {
            state,
            after,
            limit,
            include_local_dispositions,
            recent,
        } => {
            if limit == 0 || limit > 256 {
                return Err(ApiError::Limit);
            }
            let ctx = Context::parse(state, &[])?;
            let current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            if recent && after.is_some() {
                return Err(ApiError::Malformed);
            }
            let after = after.map(|id| op_id(&id)).transpose()?;
            let mut messages: Vec<_> = current
                .core()
                .messages
                .messages()
                .values()
                .map(|m| (m.create_op, message_json(&current, m)))
                .collect();
            if include_local_dispositions {
                // Display only this account's authenticated local history.
                // These rows remain outside the active CRDT and delivery path.
                let deleted: HashSet<_> = ctx
                    .old
                    .iter()
                    .filter_map(|op| {
                        let inner = op.core_operation()?;
                        (inner.op_type == OpType::MsgDelete)
                            .then(|| {
                                inner
                                    .decode_payload::<MsgDeletePayload>()
                                    .ok()
                                    .map(|p| p.msg_id)
                            })
                            .flatten()
                    })
                    .collect();
                for encoded in &ctx.old {
                    let Some(op) = encoded.core_operation() else {
                        continue;
                    };
                    if op.author_pubkey != ctx.account
                        || op.op_type != OpType::MsgAdd
                        || !current.superseded().contains_key(&op.op_id)
                    {
                        continue;
                    }
                    let payload = op
                        .decode_payload::<MsgAddPayload>()
                        .map_err(|_| ApiError::Malformed)?;
                    if current
                        .core()
                        .messages
                        .messages()
                        .contains_key(&payload.msg_id)
                    {
                        continue;
                    }
                    let cipher = current
                        .genesis_epoch()
                        .and_then(|genesis| {
                            crate::message_cipher::split(
                                &payload.ciphertext,
                                genesis,
                                encoded.certificate().is_none(),
                            )
                            .ok()
                        })
                        .filter(|(epoch, _, _)| current.epoch_key(epoch).is_some());
                    messages.push((op.op_id,json!({"msg_id":hex::encode(payload.msg_id),
                        "author":DeviceID::from_pubkey(&op.author_pubkey).to_hex(),
                        "ciphertext_b64":cipher.as_ref().map(|(_,cipher,_)|B64.encode(cipher)),
                        "cipher_epoch":cipher.map(|(epoch,_,_)|hex::encode(epoch)),
                        "nonce_b64":B64.encode(payload.nonce),"timestamp_ms":op.timestamp_ms,
                        "create_op_id":op.op_id.to_hex(),"deleted":deleted.contains(&payload.msg_id),
                        "reactions":[],"local_disposition":"not_delivered"})));
                }
            }
            messages.sort_by_key(|m| m.0);
            if recent {
                let has_more = messages.len() > limit;
                let start = messages.len().saturating_sub(limit);
                let page = &messages[start..];
                return encode_result(&json!({"messages":page.iter().map(|m|&m.1).collect::<Vec<_>>(),
                    "has_more":has_more,"next":page.first().map(|m|m.0.to_hex())}));
            }
            let mut page = messages
                .into_iter()
                .filter(|m| after.is_none_or(|id| m.0 > id))
                .take(limit + 1)
                .collect::<Vec<_>>();
            let has_more = page.len() > limit;
            page.truncate(limit);
            json!({"messages":page.iter().map(|m|&m.1).collect::<Vec<_>>(),"has_more":has_more,
                "next":page.last().map(|m|m.0.to_hex())})
        }
        Request::PrepareInvitation {
            state,
            certificate,
            origin_op_id,
            recipient_account,
        } => {
            let ctx = Context::parse(state, &[])?;
            let certificate = ctx.local_certificate(&certificate, CAP_GROUPS)?;
            let current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            let recipient = fixed::<32>(&recipient_account)?;
            let recipient_id = DeviceID::from_pubkey(&recipient);
            let source_id = DeviceID::from_pubkey(&ctx.account);
            let origin = op_id(&origin_op_id)?;
            let owned = ctx
                .old
                .iter()
                .find(|op| op.operation().op_id == origin)
                .ok_or(ApiError::Dependency)?;
            if recipient == ctx.account
                || owned.operation().author_pubkey != ctx.account
                || origin.author != DeviceID::from_pubkey(&certificate.claims().device_ed)
            {
                return Err(ApiError::Authority);
            }
            let invite = owned
                .core_operation()
                .filter(|op| op.op_type == OpType::MemberInvite)
                .ok_or(ApiError::Malformed)?
                .decode_payload::<MemberInvitePayload>()
                .map_err(|_| ApiError::Malformed)?;
            if invite.invited_pubkey != recipient
                || invite.invited_device_id != recipient_id
                || current.core().group_deleted
            {
                return Err(ApiError::Authority);
            }
            let member = current
                .core()
                .membership
                .members()
                .get(&recipient_id)
                .ok_or(ApiError::Authority)?;
            let ours = current
                .core()
                .membership
                .get_active_member(&source_id)
                .ok_or(ApiError::Authority)?;
            if member.invited_by != origin
                || member.removed
                || current.is_banned(&recipient_id)
                || !current.core().membership.can_author_op(
                    &source_id,
                    &OpType::MemberInvite,
                    &current.core().metadata,
                )
            {
                return Err(ApiError::Authority);
            }
            // An accepted account's other devices may still need the original
            // pending invitation. Stop before the first acceptance; never send
            // an accepted-account snapshot as a fabricated new invitation.
            let acceptance = ctx
                .old
                .iter()
                .filter_map(GroupOperation::core_operation)
                .filter(|op| op.author_pubkey == recipient && op.op_type == OpType::MemberAccept)
                .filter(|op| !current.superseded().contains_key(&op.op_id))
                .filter(|op| {
                    op.decode_payload::<MemberAcceptPayload>()
                        .is_ok_and(|p| p.invite_op_id == origin)
                })
                .map(|op| op.lamport)
                .min();
            if member.accepted && acceptance.is_none() {
                return Err(ApiError::Conflict);
            }
            let mut snapshot: Vec<_> = ctx
                .old
                .iter()
                .filter(|op| acceptance.is_none_or(|clock| op.operation().lamport < clock))
                .cloned()
                .collect();
            snapshot.sort_by_key(|op| (op.operation().lamport, op.operation().op_id));
            let view = AccountGroupState::rebuild(ctx.group, &snapshot, &[], &ctx.authority())
                .map_err(state_error)?;
            check_pending_invitation(&view, &recipient, &ctx.account)?;
            if view
                .core()
                .membership
                .members()
                .get(&recipient_id)
                .unwrap()
                .invited_by
                != origin
                || view
                    .core()
                    .membership
                    .get_active_member(&source_id)
                    .is_none_or(|m| m.invited_by != ours.invited_by)
            {
                return Err(ApiError::Authority);
            }
            let prior: Vec<_> = snapshot
                .iter()
                .filter(|op| op.operation().lamport < origin.lamport)
                .cloned()
                .collect();
            let before = AccountGroupState::rebuild(ctx.group, &prior, &[], &ctx.authority())
                .map_err(state_error)?;
            let reinvitation = before
                .core()
                .membership
                .members()
                .get(&recipient_id)
                .is_some_and(|m| m.removed)
                || before.archived_invite(&recipient_id).is_some();
            let packed = pack(&snapshot)?;
            let receipt =
                HistoryReceipt::issue(certificate, signing_seed.unwrap(), ctx.group, &packed)
                    .map_err(|_| ApiError::Authority)?;
            let key = view.current_key().ok_or(ApiError::Authority)?;
            let hashes: HashSet<_> = snapshot.iter().map(GroupOperation::hash).collect();
            let coverage = crate::delivery::compact_acknowledgements(&ctx.old, &hashes)
                .map_err(|_| ApiError::Conflict)?;
            if coverage.len() > 4096 {
                return Err(ApiError::Limit);
            }
            let mut coverage: Vec<_> = coverage.into_iter().map(hex::encode).collect();
            coverage.sort();
            let ratified: HashSet<[u8; 32]> = ctx
                .proofs
                .iter()
                .map(|p| p.encoded()[6..38].try_into().unwrap())
                .collect();
            let mut accounts: Vec<_> = snapshot
                .iter()
                .filter(|op| op.certificate().is_some() && !ratified.contains(&op.hash()))
                .map(|op| B64.encode(op.operation().author_pubkey))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            if accounts.len() > 128 {
                return Err(ApiError::Limit);
            }
            accounts.sort();
            json!({"packed_ops":B64.encode(packed),"group_secret":B64.encode(key),"receipt":B64.encode(receipt.encoded()),
                "reinvitation":reinvitation,"operation_hashes":snapshot.iter().map(|op|hex::encode(op.hash())).collect::<Vec<_>>(),
                "acknowledged_on_commit":coverage,"roster_accounts":accounts,
                "origin":descriptor(owned)})
        }
        Request::CompactDeliveryAcknowledgements {
            state,
            certificate,
            acknowledged,
        } => {
            let ctx = Context::parse(state, &[])?;
            ctx.local_certificate(&certificate, CAP_GROUPS)?;
            let current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            if acknowledged.len() > ctx.old.len() || acknowledged.len() > 8192 {
                return Err(ApiError::Limit);
            }
            let known: HashSet<_> = acknowledged
                .iter()
                .map(|hash| hex_fixed::<32>(hash))
                .collect::<ApiResult<_>>()?;
            if known.len() != acknowledged.len() {
                return Err(ApiError::Malformed);
            }
            let compact =
                crate::delivery::compact_acknowledgements(&ctx.old, &known).map_err(|error| {
                    match error {
                        crate::delivery::SelectionError::Dependency => ApiError::Dependency,
                        crate::delivery::SelectionError::Conflict => ApiError::Conflict,
                        crate::delivery::SelectionError::Limit => ApiError::Limit,
                    }
                })?;
            if compact.len() > 4096 {
                return Err(ApiError::Limit);
            }
            let mut compact: Vec<_> = compact.into_iter().map(hex::encode).collect();
            compact.sort();
            json!({"acknowledged":compact})
        }
        Request::SelectDelivery {
            state,
            certificate,
            origin_op_id,
            acknowledged,
            limit,
            terminal_recipient,
        } => {
            let ctx = Context::parse(state, &[])?;
            let certificate = ctx.local_certificate(&certificate, CAP_GROUPS)?;
            let current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            let origin = op_id(&origin_op_id)?;
            let owned = ctx
                .old
                .iter()
                .find(|op| op.operation().op_id == origin)
                .ok_or(ApiError::Dependency)?;
            if owned.operation().author_pubkey != ctx.account
                || origin.author != DeviceID::from_pubkey(&certificate.claims().device_ed)
            {
                return Err(ApiError::Authority);
            }
            if let Some(recipient) = terminal_recipient {
                let recipient = fixed::<32>(&recipient)?;
                let terminal = owned.core_operation().ok_or(ApiError::Malformed)?;
                if !matches!(terminal.op_type, OpType::MemberRemove | OpType::GroupDelete) {
                    return Err(ApiError::Malformed);
                }
                if recipient == ctx.account || current.superseded().contains_key(&origin) {
                    return Err(ApiError::Authority);
                }
                // A terminal notice can outlive the sender's own membership.
                // Its recipient was entitled to this exact pre-terminal state;
                // structural selection still cannot include later epochs/data.
                let before: Vec<_> = ctx
                    .old
                    .iter()
                    .filter(|op| op.operation().lamport < origin.lamport)
                    .cloned()
                    .collect();
                let before = AccountGroupState::rebuild(ctx.group, &before, &[], &ctx.authority())
                    .map_err(state_error)?;
                let id = DeviceID::from_pubkey(&recipient);
                if before.core().group_deleted
                    || before.is_banned(&id)
                    || before
                        .core()
                        .membership
                        .members()
                        .get(&id)
                        .is_none_or(|m| m.removed)
                {
                    return Err(ApiError::Authority);
                }
            }
            if acknowledged.len() > ctx.old.len() {
                return Err(ApiError::Limit);
            }
            let known: HashSet<_> = acknowledged
                .iter()
                .map(|hash| hex_fixed::<32>(hash))
                .collect::<ApiResult<_>>()?;
            if known.len() != acknowledged.len() {
                return Err(ApiError::Malformed);
            }
            let selection =
                crate::delivery::select(&ctx.old, origin, &known, limit).map_err(|error| {
                    match error {
                        crate::delivery::SelectionError::Dependency => ApiError::Dependency,
                        crate::delivery::SelectionError::Conflict => ApiError::Conflict,
                        crate::delivery::SelectionError::Limit => ApiError::Limit,
                    }
                })?;
            let operations: Vec<_> = selection
                .operations
                .iter()
                .map(|op| (*op).clone())
                .collect();
            json!({"packed_ops":B64.encode(pack(&operations)?),"complete":selection.complete,
                "operation_hashes":selection.operations.iter().map(|op|hex::encode(op.hash())).collect::<Vec<_>>(),
                "origin":descriptor(owned)})
        }
        Request::CreateOperation {
            state,
            certificate,
            mutation,
        } => {
            let ctx = Context::parse(state, &[])?;
            let certificate = ctx.local_certificate(&certificate, CAP_GROUPS)?;
            let mut current = ctx.load()?;
            if !ctx.old.is_empty() {
                verify_key(&current, &ctx.account, group_key.unwrap())?;
            }
            let ours = current
                .core()
                .membership
                .members()
                .get(&DeviceID::from_pubkey(&ctx.account));
            let unchanged = !current.core().group_deleted
                && match &mutation {
                    Mutation::MemberAccept { invite_op_id } => {
                        let invite = op_id(invite_op_id)?;
                        ours.is_some_and(|m| (m.accepted || m.removed) && m.invited_by == invite)
                    }
                    Mutation::MemberRemove {
                        account_public,
                        reason: RemoveReason::Leave,
                        ban: false,
                    } => {
                        fixed::<32>(account_public)? == ctx.account
                            && ours.is_some_and(|m| m.removed)
                    }
                    _ => false,
                };
            if unchanged {
                if ed25519_dalek::SigningKey::from_bytes(signing_seed.unwrap())
                    .verifying_key()
                    .to_bytes()
                    != certificate.claims().device_ed
                {
                    return Err(ApiError::Authority);
                }
                json!({"unchanged":true,"summary":summary(&ctx,&current,&[],group_key.unwrap())?})
            } else {
                let op = create(
                    &ctx,
                    &current,
                    certificate,
                    mutation,
                    signing_seed.unwrap(),
                    group_key.unwrap(),
                )?;
                current
                    .apply_batch(std::slice::from_ref(&op), &ctx.authority())
                    .map_err(state_error)?;
                let result = render_summary(&ctx, &current, std::slice::from_ref(&op), true)?;
                json!({"encoded":B64.encode(op.encoded()),"descriptor":descriptor(&op),"summary":result})
            }
        }
        Request::AttestHistory { state, certificate } => {
            let ctx = Context::parse(state, &[])?;
            let certificate = ctx.local_certificate(&certificate, CAP_GROUPS | CAP_SYNC)?;
            let current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            let receipt = HistoryReceipt::issue(
                certificate,
                signing_seed.unwrap(),
                ctx.group,
                &ctx.old_bytes,
            )
            .map_err(|_| ApiError::Authority)?;
            json!({"receipt":B64.encode(receipt.encoded())})
        }
        Request::AttestInvitation { state, certificate } => {
            let ctx = Context::parse(state, &[])?;
            let certificate = ctx.local_certificate(&certificate, CAP_GROUPS)?;
            let current = ctx.load()?;
            verify_key(&current, &ctx.account, group_key.unwrap())?;
            if current.core().group_deleted
                || current
                    .core()
                    .membership
                    .get_active_member(&DeviceID::from_pubkey(&ctx.account))
                    .is_none()
            {
                return Err(ApiError::Authority);
            }
            if !current.core().membership.can_author_op(
                &DeviceID::from_pubkey(&ctx.account),
                &OpType::MemberInvite,
                &current.core().metadata,
            ) {
                return Err(ApiError::Authority);
            }
            let receipt = HistoryReceipt::issue(
                certificate,
                signing_seed.unwrap(),
                ctx.group,
                &ctx.old_bytes,
            )
            .map_err(|_| ApiError::Authority)?;
            json!({"receipt":B64.encode(receipt.encoded())})
        }
    };
    encode_result(&value)
}
