/// CRDT operation envelope and payload types.
///
/// Every group action is an immutable, signed operation. Ops are the atomic
/// unit of the CRDT — stored, replicated, and replayed deterministically.
///
/// - Outer envelope: bincode-serialized (deterministic, compact)
/// - Inner payload: CBOR-serialized via ciborium (serde-native, compact binary)
/// - Signing: Ed25519 over BLAKE3(signable_bytes)

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::crdt::ids::{DeviceID, GroupID, OpID};
use crate::crdt::limits::MAX_OP_PAYLOAD_BYTES;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum OpError {
    #[error("Payload exceeds max size ({size} > {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("CBOR encoding failed: {0}")]
    CborEncode(String),

    #[error("CBOR decoding failed: {0}")]
    CborDecode(String),

    #[error("Bincode serialization failed: {0}")]
    BincodeError(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Author DeviceID does not match pubkey")]
    AuthorMismatch,

    #[error("Invalid key length")]
    InvalidKeyLength,
}

// ---------------------------------------------------------------------------
// OpType enum
// ---------------------------------------------------------------------------

/// The type of CRDT operation.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpType {
    // Membership
    GroupCreate,
    MemberInvite,
    MemberAccept,
    MemberRemove,
    RoleSet,

    // Messages
    MsgAdd,
    MsgEdit,
    MsgDelete,
    ReactionSet,

    // Metadata (LWW registers)
    MetadataSet,
}

impl OpType {
    /// Returns true for membership-related ops (always allowed, even at hard cap).
    pub fn is_membership_op(&self) -> bool {
        matches!(
            self,
            OpType::GroupCreate
                | OpType::MemberInvite
                | OpType::MemberAccept
                | OpType::MemberRemove
                | OpType::RoleSet
        )
    }

    /// String name for JSON/JNI interop.
    pub fn as_str(&self) -> &'static str {
        match self {
            OpType::GroupCreate => "GroupCreate",
            OpType::MemberInvite => "MemberInvite",
            OpType::MemberAccept => "MemberAccept",
            OpType::MemberRemove => "MemberRemove",
            OpType::RoleSet => "RoleSet",
            OpType::MsgAdd => "MsgAdd",
            OpType::MsgEdit => "MsgEdit",
            OpType::MsgDelete => "MsgDelete",
            OpType::ReactionSet => "ReactionSet",
            OpType::MetadataSet => "MetadataSet",
        }
    }
}

// ---------------------------------------------------------------------------
// Role, RemoveReason, MetadataKey
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Role {
    Owner = 0,
    Admin = 1,
    Member = 2,
    ReadOnly = 3,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RemoveReason {
    Kick,
    Leave,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MetadataKey {
    Name = 0,
    Avatar = 1,
    Topic = 2,
}

// ---------------------------------------------------------------------------
// Payload types (CBOR-encoded inside OpEnvelope.payload)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GroupCreatePayload {
    pub group_name: String,
    /// GroupSecret encrypted to creator's own X25519 key.
    pub encrypted_group_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemberInvitePayload {
    pub invited_device_id: DeviceID,
    pub invited_pubkey: [u8; 32],
    pub role: Role,
    /// GroupSecret encrypted to invitee's X25519 key.
    pub encrypted_group_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemberAcceptPayload {
    /// References the MemberInvite op this accepts.
    pub invite_op_id: OpID,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemberRemovePayload {
    pub target_device_id: DeviceID,
    pub reason: RemoveReason,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RoleSetPayload {
    pub target_device_id: DeviceID,
    pub new_role: Role,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MsgAddPayload {
    /// BLAKE3(author_device_id || lamport || nonce) — unique message identifier.
    pub msg_id: [u8; 32],
    /// Message content encrypted with GroupSecret (XChaCha20-Poly1305).
    pub ciphertext: Vec<u8>,
    /// XChaCha20 nonce used for encryption.
    pub nonce: [u8; 24],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MsgEditPayload {
    pub msg_id: [u8; 32],
    pub new_ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MsgDeletePayload {
    pub msg_id: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReactionSetPayload {
    pub msg_id: [u8; 32],
    /// Unicode emoji string.
    pub emoji: String,
    /// true = add reaction, false = remove reaction.
    pub present: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetadataSetPayload {
    pub key: MetadataKey,
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
// OpEnvelope
// ---------------------------------------------------------------------------

/// Immutable, signed CRDT operation envelope.
///
/// This is the fundamental unit of replication. Every group action (create,
/// invite, message, edit, delete, react, metadata change) is wrapped in an
/// OpEnvelope, signed by the author, and stored in the append-only op log.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OpEnvelope {
    pub group_id: GroupID,
    pub op_id: OpID,
    /// Causal context — heads at creation time (empty until Phase 7).
    pub parent_heads: Vec<OpID>,
    /// Author's lamport clock value (same as op_id.lamport, for fast access).
    pub lamport: u64,
    /// Wall clock timestamp in milliseconds — UX only, not used for ordering.
    pub timestamp_ms: u64,
    pub op_type: OpType,
    /// CBOR-encoded payload bytes.
    pub payload: Vec<u8>,
    /// Ed25519 public key of the author.
    pub author_pubkey: [u8; 32],
    /// Ed25519 signature over BLAKE3(signable_bytes).
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl OpEnvelope {
    /// Create and sign a new operation.
    ///
    /// # Arguments
    /// * `group_id` — target group
    /// * `op_type` — operation kind
    /// * `payload` — will be CBOR-encoded
    /// * `lamport` — author's current lamport value (must be pre-incremented by caller)
    /// * `nonce` — random u64 for OpID uniqueness
    /// * `author_pubkey` — author's Ed25519 public key (32 bytes)
    /// * `author_privkey` — author's Ed25519 private key (32 bytes)
    pub fn create_signed<P: Serialize>(
        group_id: GroupID,
        op_type: OpType,
        payload: &P,
        lamport: u64,
        nonce: u64,
        author_pubkey: [u8; 32],
        author_privkey: &[u8; 32],
    ) -> Result<Self, OpError> {
        // CBOR-encode the payload
        let payload_bytes = cbor_encode(payload)?;

        // Enforce payload size limit
        if payload_bytes.len() > MAX_OP_PAYLOAD_BYTES {
            return Err(OpError::PayloadTooLarge {
                size: payload_bytes.len(),
                max: MAX_OP_PAYLOAD_BYTES,
            });
        }

        let device_id = DeviceID::from_pubkey(&author_pubkey);
        let op_id = OpID::new(device_id, lamport, nonce);

        let mut envelope = OpEnvelope {
            group_id,
            op_id,
            parent_heads: vec![],
            lamport,
            timestamp_ms: now_ms(),
            op_type,
            payload: payload_bytes,
            author_pubkey,
            signature: [0u8; 64],
        };

        // Sign: BLAKE3(signable_bytes) → Ed25519 sign
        let signable = envelope.signable_bytes()?;
        let hash = blake3::hash(&signable);
        envelope.signature = crate::crypto::signing::sign_data(hash.as_bytes(), author_privkey)
            .map_err(|e| OpError::SigningFailed(e.to_string()))?;

        Ok(envelope)
    }

    /// Verify the signature on this operation.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid signature,
    /// or `Err` if the envelope can't be serialized for verification.
    pub fn verify(&self) -> Result<bool, OpError> {
        // Check author_pubkey matches op_id.author
        let expected_device = DeviceID::from_pubkey(&self.author_pubkey);
        if expected_device != self.op_id.author {
            return Err(OpError::AuthorMismatch);
        }

        let signable = self.signable_bytes()?;
        let hash = blake3::hash(&signable);
        crate::crypto::signing::verify_signature(
            hash.as_bytes(),
            &self.signature,
            &self.author_pubkey,
        )
        .map_err(|e| OpError::SigningFailed(e.to_string()))
    }

    /// Produce the canonical bytes to sign/verify.
    ///
    /// Includes all fields except `signature`. Uses bincode for deterministic
    /// serialization (field order is fixed by struct definition).
    fn signable_bytes(&self) -> Result<Vec<u8>, OpError> {
        // Serialize a tuple of all fields except signature for determinism
        let signable = (
            &self.group_id,
            &self.op_id,
            &self.parent_heads,
            self.lamport,
            self.timestamp_ms,
            &self.op_type,
            &self.payload,
            &self.author_pubkey,
        );
        bincode::serialize(&signable)
            .map_err(|e| OpError::BincodeError(e.to_string()))
    }

    /// Serialize the full envelope to bytes (for storage / wire transfer).
    pub fn to_bytes(&self) -> Result<Vec<u8>, OpError> {
        bincode::serialize(self)
            .map_err(|e| OpError::BincodeError(e.to_string()))
    }

    /// Deserialize an envelope from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OpError> {
        bincode::deserialize(bytes)
            .map_err(|e| OpError::BincodeError(e.to_string()))
    }

    /// Decode the CBOR payload into a typed struct.
    pub fn decode_payload<P: serde::de::DeserializeOwned>(&self) -> Result<P, OpError> {
        cbor_decode(&self.payload)
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

/// CBOR-encode a value to bytes.
pub fn cbor_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, OpError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| OpError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// CBOR-decode a value from bytes.
pub fn cbor_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, OpError> {
    ciborium::from_reader(bytes)
        .map_err(|e| OpError::CborDecode(e.to_string()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current time in milliseconds since Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Generate a unique message ID: BLAKE3(author_device_id || lamport || nonce).
pub fn generate_msg_id(author: &DeviceID, lamport: u64, nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(author.as_bytes());
    hasher.update(&lamport.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a fresh keypair for testing.
    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        crate::crypto::signing::generate_keypair()
    }

    /// Helper: create a test GroupID.
    fn test_group_id(pubkey: &[u8; 32]) -> GroupID {
        let creator = DeviceID::from_pubkey(pubkey);
        GroupID::new(&creator, &[0xAA; 32])
    }

    #[test]
    fn test_op_type_is_membership() {
        assert!(OpType::GroupCreate.is_membership_op());
        assert!(OpType::MemberInvite.is_membership_op());
        assert!(OpType::MemberAccept.is_membership_op());
        assert!(OpType::MemberRemove.is_membership_op());
        assert!(OpType::RoleSet.is_membership_op());
        assert!(!OpType::MsgAdd.is_membership_op());
        assert!(!OpType::MsgEdit.is_membership_op());
        assert!(!OpType::MsgDelete.is_membership_op());
        assert!(!OpType::ReactionSet.is_membership_op());
        assert!(!OpType::MetadataSet.is_membership_op());
    }

    #[test]
    fn test_create_signed_and_verify() {
        let (pubkey, privkey) = test_keypair();
        let group_id = test_group_id(&pubkey);

        let payload = GroupCreatePayload {
            group_name: "Test Group".to_string(),
            encrypted_group_secret: vec![1, 2, 3, 4],
        };

        let op = OpEnvelope::create_signed(
            group_id,
            OpType::GroupCreate,
            &payload,
            1, // lamport
            42, // nonce
            pubkey,
            &privkey,
        )
        .unwrap();

        // Verify signature
        assert!(op.verify().unwrap());

        // Check fields
        assert_eq!(op.group_id, group_id);
        assert_eq!(op.op_type, OpType::GroupCreate);
        assert_eq!(op.lamport, 1);
        assert_eq!(op.op_id.lamport, 1);
        assert_eq!(op.op_id.nonce, 42);
        assert_eq!(op.author_pubkey, pubkey);
        assert_eq!(op.op_id.author, DeviceID::from_pubkey(&pubkey));
    }

    #[test]
    fn test_verify_detects_tampered_payload() {
        let (pubkey, privkey) = test_keypair();
        let group_id = test_group_id(&pubkey);

        let payload = MsgAddPayload {
            msg_id: [0xBB; 32],
            ciphertext: vec![10, 20, 30],
            nonce: [0xCC; 24],
        };

        let mut op = OpEnvelope::create_signed(
            group_id,
            OpType::MsgAdd,
            &payload,
            5,
            99,
            pubkey,
            &privkey,
        )
        .unwrap();

        // Tamper with payload
        op.payload.push(0xFF);

        // Verification should fail
        assert!(!op.verify().unwrap());
    }

    #[test]
    fn test_verify_detects_wrong_pubkey() {
        let (pubkey, privkey) = test_keypair();
        let (other_pubkey, _) = test_keypair();
        let group_id = test_group_id(&pubkey);

        let payload = GroupCreatePayload {
            group_name: "X".to_string(),
            encrypted_group_secret: vec![],
        };

        let mut op = OpEnvelope::create_signed(
            group_id,
            OpType::GroupCreate,
            &payload,
            1,
            0,
            pubkey,
            &privkey,
        )
        .unwrap();

        // Replace pubkey with a different one
        op.author_pubkey = other_pubkey;

        // Should fail: author mismatch (DeviceID != from_pubkey(other))
        assert!(op.verify().is_err());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let (pubkey, privkey) = test_keypair();
        let group_id = test_group_id(&pubkey);

        let payload = MsgDeletePayload {
            msg_id: [0x11; 32],
        };

        let op = OpEnvelope::create_signed(
            group_id,
            OpType::MsgDelete,
            &payload,
            10,
            555,
            pubkey,
            &privkey,
        )
        .unwrap();

        // Serialize → deserialize
        let bytes = op.to_bytes().unwrap();
        let restored = OpEnvelope::from_bytes(&bytes).unwrap();

        // Verify the restored op
        assert!(restored.verify().unwrap());
        assert_eq!(restored.group_id, op.group_id);
        assert_eq!(restored.op_id, op.op_id);
        assert_eq!(restored.op_type, op.op_type);
        assert_eq!(restored.lamport, op.lamport);
        assert_eq!(restored.payload, op.payload);
        assert_eq!(restored.signature, op.signature);
    }

    #[test]
    fn test_payload_too_large_rejected() {
        let (pubkey, privkey) = test_keypair();
        let group_id = test_group_id(&pubkey);

        // Create a payload that exceeds MAX_OP_PAYLOAD_BYTES (64 KB)
        let oversized = MsgAddPayload {
            msg_id: [0; 32],
            ciphertext: vec![0u8; MAX_OP_PAYLOAD_BYTES + 1],
            nonce: [0; 24],
        };

        let result = OpEnvelope::create_signed(
            group_id,
            OpType::MsgAdd,
            &oversized,
            1,
            0,
            pubkey,
            &privkey,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            OpError::PayloadTooLarge { size, max } => {
                assert!(size > max);
                assert_eq!(max, MAX_OP_PAYLOAD_BYTES);
            }
            other => panic!("Expected PayloadTooLarge, got: {:?}", other),
        }
    }

    #[test]
    fn test_cbor_payload_roundtrip() {
        let payload = ReactionSetPayload {
            msg_id: [0xDD; 32],
            emoji: "\u{1F602}".to_string(), // 
            present: true,
        };

        let encoded = cbor_encode(&payload).unwrap();
        let decoded: ReactionSetPayload = cbor_decode(&encoded).unwrap();

        assert_eq!(decoded.msg_id, payload.msg_id);
        assert_eq!(decoded.emoji, payload.emoji);
        assert_eq!(decoded.present, payload.present);
    }

    #[test]
    fn test_decode_payload_from_envelope() {
        let (pubkey, privkey) = test_keypair();
        let group_id = test_group_id(&pubkey);

        let original = MetadataSetPayload {
            key: MetadataKey::Name,
            value: b"New Group Name".to_vec(),
        };

        let op = OpEnvelope::create_signed(
            group_id,
            OpType::MetadataSet,
            &original,
            3,
            77,
            pubkey,
            &privkey,
        )
        .unwrap();

        let decoded: MetadataSetPayload = op.decode_payload().unwrap();
        assert_eq!(decoded.key, MetadataKey::Name);
        assert_eq!(decoded.value, b"New Group Name");
    }

    #[test]
    fn test_generate_msg_id_deterministic() {
        let author = DeviceID::from_pubkey(&[10u8; 32]);
        let id1 = generate_msg_id(&author, 5, 100);
        let id2 = generate_msg_id(&author, 5, 100);
        assert_eq!(id1, id2);

        // Different inputs → different msg_id
        let id3 = generate_msg_id(&author, 5, 101);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_all_payload_types_cbor_roundtrip() {
        // GroupCreate
        let p = GroupCreatePayload {
            group_name: "Test".to_string(),
            encrypted_group_secret: vec![1, 2, 3],
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: GroupCreatePayload = cbor_decode(&bytes).unwrap();

        // MemberInvite
        let p = MemberInvitePayload {
            invited_device_id: DeviceID::from_bytes([1; 16]),
            invited_pubkey: [2; 32],
            role: Role::Member,
            encrypted_group_secret: vec![4, 5, 6],
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: MemberInvitePayload = cbor_decode(&bytes).unwrap();

        // MemberAccept
        let p = MemberAcceptPayload {
            invite_op_id: OpID::new(DeviceID::from_bytes([3; 16]), 1, 0),
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: MemberAcceptPayload = cbor_decode(&bytes).unwrap();

        // MemberRemove
        let p = MemberRemovePayload {
            target_device_id: DeviceID::from_bytes([4; 16]),
            reason: RemoveReason::Kick,
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: MemberRemovePayload = cbor_decode(&bytes).unwrap();

        // RoleSet
        let p = RoleSetPayload {
            target_device_id: DeviceID::from_bytes([5; 16]),
            new_role: Role::Admin,
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: RoleSetPayload = cbor_decode(&bytes).unwrap();

        // MsgAdd
        let p = MsgAddPayload {
            msg_id: [6; 32],
            ciphertext: vec![7, 8, 9],
            nonce: [10; 24],
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: MsgAddPayload = cbor_decode(&bytes).unwrap();

        // MsgEdit
        let p = MsgEditPayload {
            msg_id: [11; 32],
            new_ciphertext: vec![12, 13],
            nonce: [14; 24],
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: MsgEditPayload = cbor_decode(&bytes).unwrap();

        // MsgDelete
        let p = MsgDeletePayload { msg_id: [15; 32] };
        let bytes = cbor_encode(&p).unwrap();
        let _: MsgDeletePayload = cbor_decode(&bytes).unwrap();

        // ReactionSet
        let p = ReactionSetPayload {
            msg_id: [16; 32],
            emoji: "".to_string(),
            present: false,
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: ReactionSetPayload = cbor_decode(&bytes).unwrap();

        // MetadataSet
        let p = MetadataSetPayload {
            key: MetadataKey::Topic,
            value: b"general chat".to_vec(),
        };
        let bytes = cbor_encode(&p).unwrap();
        let _: MetadataSetPayload = cbor_decode(&bytes).unwrap();
    }

    #[test]
    fn test_op_type_as_str() {
        assert_eq!(OpType::GroupCreate.as_str(), "GroupCreate");
        assert_eq!(OpType::MsgAdd.as_str(), "MsgAdd");
        assert_eq!(OpType::MetadataSet.as_str(), "MetadataSet");
    }
}
