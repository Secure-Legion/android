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

pub mod ids;
pub mod ops;
pub mod limits;

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
