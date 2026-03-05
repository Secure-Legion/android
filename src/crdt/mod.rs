/// CRDT group system — operation-based conflict-free replicated data types.
///
/// Groups are represented as append-only operation logs. Every action (create,
/// invite, message, edit, delete, react, metadata change) is a signed, immutable
/// operation. Devices converge by exchanging missing ops and replaying them in
/// deterministic order.
///
/// # Module structure
/// - `ids` — DeviceID, GroupID, OpID identity types
/// - `ops` — OpEnvelope, OpType, payload types, signing/verification
/// - `limits` — Guardrail constants and op limit checking
/// - `membership` — OR-Set membership CRDT with role-based authorization
/// - `messages` — Message add/edit/delete/react with LWW edits and permanent tombstones
/// - `metadata` — LWW registers for group name, avatar, topic
/// - `apply` — Unified apply engine (GroupState, rebuild, state_hash)

pub mod ids;
pub mod ops;
pub mod limits;
pub mod membership;
pub mod messages;
pub mod metadata;
pub mod apply;

// Re-export core types for convenience
pub use ids::{DeviceID, GroupID, OpID};
pub use ops::{
    OpEnvelope, OpType, OpError,
    Role, RemoveReason, MetadataKey,
    GroupCreatePayload, MemberInvitePayload, MemberAcceptPayload,
    MemberRemovePayload, RoleSetPayload,
    MsgAddPayload, MsgEditPayload, MsgDeletePayload,
    ReactionSetPayload, MetadataSetPayload,
    cbor_encode, cbor_decode, generate_msg_id,
};
pub use limits::{OpLimitStatus, check_op_limits};
pub use membership::{MembershipState, MemberEntry, MembershipError};
pub use messages::{MessageState, MessageEntry, MessageError};
pub use metadata::{MetadataState, LWWRegister, MetadataError};
pub use apply::{GroupState, ApplyError};
