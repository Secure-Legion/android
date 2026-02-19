/// Metadata CRDT — LWW (Last-Writer-Wins) registers for group properties.
///
/// Tracks group name, avatar, and topic as independent LWW registers.
/// Each register stores the latest value, the lamport of the writer, and the
/// OpID for deterministic tie-breaking.

use std::collections::BTreeMap;
use thiserror::Error;

use crate::crdt::ids::OpID;
use crate::crdt::ops::{MetadataKey, MetadataSetPayload, OpEnvelope};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("Payload decode error: {0}")]
    PayloadDecode(String),
}

// ---------------------------------------------------------------------------
// LWWRegister
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct LWWRegister {
    pub value: Vec<u8>,
    pub lamport: u64,
    pub writer_op: OpID,
}

// ---------------------------------------------------------------------------
// MetadataState
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MetadataState {
    registers: BTreeMap<MetadataKey, LWWRegister>,
}

impl MetadataState {
    pub fn new() -> Self {
        MetadataState {
            registers: BTreeMap::new(),
        }
    }

    /// Read-only access to the registers.
    pub fn registers(&self) -> &BTreeMap<MetadataKey, LWWRegister> {
        &self.registers
    }

    /// Get the current value for a metadata key, if set.
    pub fn get(&self, key: &MetadataKey) -> Option<&LWWRegister> {
        self.registers.get(key)
    }

    /// Get the group name as a UTF-8 string, if set.
    pub fn name(&self) -> Option<&str> {
        self.registers
            .get(&MetadataKey::Name)
            .and_then(|r| std::str::from_utf8(&r.value).ok())
    }

    /// Get the group topic as a UTF-8 string, if set.
    pub fn topic(&self) -> Option<&str> {
        self.registers
            .get(&MetadataKey::Topic)
            .and_then(|r| std::str::from_utf8(&r.value).ok())
    }

    // -----------------------------------------------------------------------
    // Apply
    // -----------------------------------------------------------------------

    /// Apply a MetadataSet op. LWW: only update if this op supersedes the current writer.
    pub fn apply_metadata_set(&mut self, op: &OpEnvelope) -> Result<(), MetadataError> {
        let payload: MetadataSetPayload = op
            .decode_payload()
            .map_err(|e| MetadataError::PayloadDecode(e.to_string()))?;

        let should_update = match self.registers.get(&payload.key) {
            None => true,
            Some(reg) => {
                op.lamport > reg.lamport
                    || (op.lamport == reg.lamport && op.op_id > reg.writer_op)
            }
        };

        if should_update {
            self.registers.insert(
                payload.key,
                LWWRegister {
                    value: payload.value,
                    lamport: op.lamport,
                    writer_op: op.op_id,
                },
            );
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::ids::{DeviceID, GroupID};
    use crate::crdt::ops::{MetadataKey, MetadataSetPayload, OpEnvelope, OpType};

    fn keypair() -> ([u8; 32], [u8; 32]) {
        crate::crypto::signing::generate_keypair()
    }

    fn test_group_id(pubkey: &[u8; 32]) -> GroupID {
        let creator = DeviceID::from_pubkey(pubkey);
        GroupID::new(&creator, &[0xCC; 32])
    }

    fn make_metadata_set(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        key: MetadataKey,
        value: Vec<u8>,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MetadataSetPayload { key, value };
        OpEnvelope::create_signed(
            gid,
            OpType::MetadataSet,
            &payload,
            lamport,
            nonce,
            author_pub,
            author_priv,
        )
        .unwrap()
    }

    #[test]
    fn test_set_and_get_name() {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);
        let mut meta = MetadataState::new();

        assert!(meta.name().is_none());

        let op = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Name,
            b"My Group".to_vec(),
            1,
            100,
        );
        meta.apply_metadata_set(&op).unwrap();

        assert_eq!(meta.name(), Some("My Group"));
    }

    #[test]
    fn test_set_and_get_topic() {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);
        let mut meta = MetadataState::new();

        let op = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Topic,
            b"General chat".to_vec(),
            1,
            100,
        );
        meta.apply_metadata_set(&op).unwrap();

        assert_eq!(meta.topic(), Some("General chat"));
    }

    #[test]
    fn test_lww_higher_lamport_wins() {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);
        let mut meta = MetadataState::new();

        // Set name at lamport=2
        let op1 = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Name,
            b"First".to_vec(),
            2,
            200,
        );
        meta.apply_metadata_set(&op1).unwrap();

        // Set name at lamport=5 — should win
        let op2 = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Name,
            b"Second".to_vec(),
            5,
            500,
        );
        meta.apply_metadata_set(&op2).unwrap();

        assert_eq!(meta.name(), Some("Second"));

        // Stale op at lamport=3 — should be ignored
        let op3 = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Name,
            b"Stale".to_vec(),
            3,
            300,
        );
        meta.apply_metadata_set(&op3).unwrap();

        assert_eq!(meta.name(), Some("Second")); // unchanged
    }

    #[test]
    fn test_lww_tiebreak_converges() {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);

        // Two ops at same lamport, different nonces
        let op_a = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Name,
            b"Alpha".to_vec(),
            4,
            100,
        );
        let op_b = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Name,
            b"Beta".to_vec(),
            4,
            999,
        );

        // Apply in order A then B
        let mut meta_ab = MetadataState::new();
        meta_ab.apply_metadata_set(&op_a).unwrap();
        meta_ab.apply_metadata_set(&op_b).unwrap();

        // Apply in order B then A
        let mut meta_ba = MetadataState::new();
        meta_ba.apply_metadata_set(&op_b).unwrap();
        meta_ba.apply_metadata_set(&op_a).unwrap();

        // Must converge to the same value
        assert_eq!(meta_ab.name(), meta_ba.name());
    }

    #[test]
    fn test_independent_keys_dont_interfere() {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);
        let mut meta = MetadataState::new();

        let name_op = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Name,
            b"Group Name".to_vec(),
            1,
            100,
        );
        let topic_op = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Topic,
            b"Off-topic".to_vec(),
            2,
            200,
        );

        meta.apply_metadata_set(&name_op).unwrap();
        meta.apply_metadata_set(&topic_op).unwrap();

        assert_eq!(meta.name(), Some("Group Name"));
        assert_eq!(meta.topic(), Some("Off-topic"));
        assert_eq!(meta.registers().len(), 2);
    }

    #[test]
    fn test_avatar_binary_data() {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);
        let mut meta = MetadataState::new();

        let avatar_bytes = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG header bytes
        let op = make_metadata_set(
            gid,
            pub_k,
            &priv_k,
            MetadataKey::Avatar,
            avatar_bytes.clone(),
            1,
            100,
        );
        meta.apply_metadata_set(&op).unwrap();

        let reg = meta.get(&MetadataKey::Avatar).unwrap();
        assert_eq!(reg.value, avatar_bytes);
    }
}
