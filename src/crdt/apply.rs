/// Unified apply engine — the single entry point for applying CRDT operations.
///
/// `GroupState` holds the full in-memory state for one group: membership,
/// messages, metadata, DAG heads, and bookkeeping. Every op flows through
/// `apply_op`, which validates, dispatches, and tracks it.
///
/// **Determinism guarantee:** `rebuild_from_ops(same ops in ANY order)` produces
/// the same `state_hash`, because ops are sorted by `(lamport, op_id)` before
/// replay and all sub-CRDTs use commutative merge semantics.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use thiserror::Error;

use crate::crdt::ids::{DeviceID, GroupID, OpID};
use crate::crdt::limits::{check_op_limits, OpLimitStatus};
use crate::crdt::membership::{MembershipError, MembershipState};
use crate::crdt::messages::{MessageEntry, MessageError, MessageState};
use crate::crdt::metadata::{MetadataError, MetadataState};
use crate::crdt::ops::{OpEnvelope, OpError, OpType};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum ApplyError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Op targets wrong group")]
    WrongGroup,

    #[error("Hard op limit reached — only membership ops allowed")]
    OpLimitReached,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Membership error: {0}")]
    Membership(#[from] MembershipError),

    #[error("Message error: {0}")]
    Message(#[from] MessageError),

    #[error("Metadata error: {0}")]
    Metadata(#[from] MetadataError),

    #[error("Op error: {0}")]
    Op(#[from] OpError),
}

// ---------------------------------------------------------------------------
// GroupState
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct GroupState {
    pub group_id: GroupID,
    pub membership: MembershipState,
    pub messages: MessageState,
    pub metadata: MetadataState,
    /// Current DAG heads (all ops until parent_heads is populated in Phase 7).
    pub heads: BTreeSet<OpID>,
    /// Per-author maximum lamport (for sync gap detection).
    pub max_lamport: BTreeMap<DeviceID, u64>,
    /// Set of applied OpIDs (for idempotency).
    applied_ops: HashSet<OpID>,
    /// Total applied op count (for limit checking).
    pub op_count: usize,
}

impl GroupState {
    /// Create a new empty group state.
    pub fn new(group_id: GroupID) -> Self {
        GroupState {
            group_id,
            membership: MembershipState::new(),
            messages: MessageState::new(),
            metadata: MetadataState::new(),
            heads: BTreeSet::new(),
            max_lamport: BTreeMap::new(),
            applied_ops: HashSet::new(),
            op_count: 0,
        }
    }

    /// Apply a single op. Returns `Ok(true)` if applied, `Ok(false)` if duplicate.
    pub fn apply_op(&mut self, op: &OpEnvelope) -> Result<bool, ApplyError> {
        // 1. Verify signature
        match op.verify() {
            Ok(true) => {}
            Ok(false) => return Err(ApplyError::InvalidSignature),
            Err(_) => return Err(ApplyError::InvalidSignature),
        }

        // 2. Check group_id
        if op.group_id != self.group_id {
            return Err(ApplyError::WrongGroup);
        }

        // 3. Idempotency check
        if self.applied_ops.contains(&op.op_id) {
            return Ok(false);
        }

        // 4. Op limit check (hard cap — membership ops always bypass)
        if !op.op_type.is_membership_op() {
            if let OpLimitStatus::HardCapReached = check_op_limits(self.op_count) {
                return Err(ApplyError::OpLimitReached);
            }
        }

        // 5. Authorization check
        //    GroupCreate is the founding op — no members exist yet.
        //    Its own apply function validates lamport=1 and no prior creation.
        let author_device = DeviceID::from_pubkey(&op.author_pubkey);
        if op.op_type != OpType::GroupCreate {
            if !self.membership.can_author_op(&author_device, &op.op_type) {
                return Err(ApplyError::Unauthorized(format!(
                    "{:?} cannot author {:?}",
                    author_device, op.op_type
                )));
            }
        }

        // 6. Dispatch to sub-CRDT
        match op.op_type {
            OpType::GroupCreate => self.membership.apply_group_create(op)?,
            OpType::MemberInvite => self.membership.apply_member_invite(op)?,
            OpType::MemberAccept => self.membership.apply_member_accept(op)?,
            OpType::MemberRemove => self.membership.apply_member_remove(op)?,
            OpType::RoleSet => self.membership.apply_role_set(op)?,
            OpType::MsgAdd => self.messages.apply_msg_add(op)?,
            OpType::MsgEdit => self.messages.apply_msg_edit(op)?,
            OpType::MsgDelete => self.messages.apply_msg_delete(op, &self.membership)?,
            OpType::ReactionSet => self.messages.apply_reaction_set(op)?,
            OpType::MetadataSet => self.metadata.apply_metadata_set(op)?,
        }

        // 7. Bookkeeping
        self.applied_ops.insert(op.op_id);
        self.update_heads(op);
        self.op_count += 1;
        self.max_lamport
            .entry(author_device)
            .and_modify(|l| *l = (*l).max(op.lamport))
            .or_insert(op.lamport);

        Ok(true)
    }

    /// Rebuild state from a complete op set (startup / verification).
    ///
    /// Sorts ops by `(lamport, op_id)` for deterministic replay. Any input
    /// order produces the same final state.
    pub fn rebuild_from_ops(group_id: GroupID, ops: &[OpEnvelope]) -> Result<Self, ApplyError> {
        let mut state = GroupState::new(group_id);
        let mut sorted = ops.to_vec();
        sorted.sort_by(|a, b| a.lamport.cmp(&b.lamport).then_with(|| a.op_id.cmp(&b.op_id)));
        for op in &sorted {
            state.apply_op(op)?;
        }
        Ok(state)
    }

    /// Deterministic state hash for convergence verification.
    ///
    /// Hashes membership, messages, and metadata in canonical BTreeMap iteration
    /// order. Two peers with the same applied ops will always produce the same
    /// hash. Enum discriminants use stable `#[repr(u8)]` values.
    pub fn state_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // --- Membership ---
        hasher.update(b"M");
        for (device_id, entry) in self.membership.members() {
            hasher.update(device_id.as_bytes());
            hasher.update(&[entry.role as u8]);
            hasher.update(&[entry.accepted as u8]);
            hasher.update(&[entry.removed as u8]);
            hasher.update(&[entry.rekey_required as u8]);
        }

        // --- Messages ---
        hasher.update(b"G");
        for (msg_id, entry) in self.messages.messages() {
            hasher.update(msg_id);
            hasher.update(entry.author.as_bytes());
            hasher.update(&[entry.deleted as u8]);
            hasher.update(&entry.last_edit_lamport.to_le_bytes());
            hasher.update(&(entry.ciphertext.len() as u64).to_le_bytes());
            hasher.update(&entry.ciphertext);
            hasher.update(&entry.nonce);
            // Reactions (BTreeMap — deterministic iteration order)
            for ((reactor, emoji), present) in &entry.reactions {
                hasher.update(reactor.as_bytes());
                hasher.update(&(emoji.len() as u64).to_le_bytes());
                hasher.update(emoji.as_bytes());
                hasher.update(&[*present as u8]);
            }
        }

        // --- Metadata ---
        hasher.update(b"D");
        for (key, reg) in self.metadata.registers() {
            hasher.update(&[*key as u8]);
            hasher.update(&(reg.value.len() as u64).to_le_bytes());
            hasher.update(&reg.value);
            hasher.update(&reg.lamport.to_le_bytes());
        }

        *hasher.finalize().as_bytes()
    }

    /// Get renderable messages — membership-gated.
    ///
    /// Returns only messages whose author is currently an active member and
    /// that are not tombstoned.
    pub fn renderable_messages(&self) -> Vec<&MessageEntry> {
        self.messages
            .messages()
            .values()
            .filter(|msg| !msg.deleted)
            .filter(|msg| self.membership.is_author_active_for_render(&msg.author))
            .collect()
    }

    /// Current op limit status for UI.
    pub fn limit_status(&self) -> OpLimitStatus {
        check_op_limits(self.op_count)
    }

    /// Whether an OpID has already been applied.
    pub fn has_applied(&self, op_id: &OpID) -> bool {
        self.applied_ops.contains(op_id)
    }

    /// Update DAG heads after applying an op.
    ///
    /// Removes any heads referenced as parents by this op, then adds this op
    /// as a new head. With empty `parent_heads` (v1), every applied op is a
    /// head — pruning happens in Phase 7.
    fn update_heads(&mut self, op: &OpEnvelope) {
        for parent in &op.parent_heads {
            self.heads.remove(parent);
        }
        self.heads.insert(op.op_id);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::ops::{
        GroupCreatePayload, MemberAcceptPayload, MemberInvitePayload, MemberRemovePayload,
        MetadataKey, MetadataSetPayload, MsgAddPayload, MsgDeletePayload, ReactionSetPayload,
        RemoveReason, Role,
    };

    fn keypair() -> ([u8; 32], [u8; 32]) {
        crate::crypto::signing::generate_keypair()
    }

    fn test_group_id(pubkey: &[u8; 32]) -> GroupID {
        let creator = DeviceID::from_pubkey(pubkey);
        GroupID::new(&creator, &[0xDD; 32])
    }

    // --- Op builder helpers ------------------------------------------------

    fn op_group_create(gid: GroupID, pub_k: [u8; 32], priv_k: &[u8; 32]) -> OpEnvelope {
        let payload = GroupCreatePayload {
            group_name: "Test Group".into(),
            encrypted_group_secret: vec![1, 2, 3],
        };
        OpEnvelope::create_signed(gid, OpType::GroupCreate, &payload, 1, 100, pub_k, priv_k)
            .unwrap()
    }

    fn op_invite(
        gid: GroupID,
        inviter_pub: [u8; 32],
        inviter_priv: &[u8; 32],
        invitee_pub: [u8; 32],
        role: Role,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&invitee_pub),
            invited_pubkey: invitee_pub,
            role,
            encrypted_group_secret: vec![10, 20],
        };
        OpEnvelope::create_signed(
            gid,
            OpType::MemberInvite,
            &payload,
            lamport,
            nonce,
            inviter_pub,
            inviter_priv,
        )
        .unwrap()
    }

    fn op_accept(
        gid: GroupID,
        pub_k: [u8; 32],
        priv_k: &[u8; 32],
        invite_op_id: OpID,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MemberAcceptPayload { invite_op_id };
        OpEnvelope::create_signed(
            gid,
            OpType::MemberAccept,
            &payload,
            lamport,
            nonce,
            pub_k,
            priv_k,
        )
        .unwrap()
    }

    fn op_msg_add(
        gid: GroupID,
        pub_k: [u8; 32],
        priv_k: &[u8; 32],
        msg_id: [u8; 32],
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MsgAddPayload {
            msg_id,
            ciphertext: vec![0xAA, 0xBB],
            nonce: [0x11; 24],
        };
        OpEnvelope::create_signed(
            gid,
            OpType::MsgAdd,
            &payload,
            lamport,
            nonce,
            pub_k,
            priv_k,
        )
        .unwrap()
    }

    fn op_remove(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        target_pub: [u8; 32],
        reason: RemoveReason,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&target_pub),
            reason,
        };
        OpEnvelope::create_signed(
            gid,
            OpType::MemberRemove,
            &payload,
            lamport,
            nonce,
            author_pub,
            author_priv,
        )
        .unwrap()
    }

    fn op_metadata(
        gid: GroupID,
        pub_k: [u8; 32],
        priv_k: &[u8; 32],
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
            pub_k,
            priv_k,
        )
        .unwrap()
    }

    fn op_reaction(
        gid: GroupID,
        pub_k: [u8; 32],
        priv_k: &[u8; 32],
        msg_id: [u8; 32],
        emoji: &str,
        present: bool,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = ReactionSetPayload {
            msg_id,
            emoji: emoji.to_string(),
            present,
        };
        OpEnvelope::create_signed(
            gid,
            OpType::ReactionSet,
            &payload,
            lamport,
            nonce,
            pub_k,
            priv_k,
        )
        .unwrap()
    }

    /// Standard group: owner + alice (Member). Returns keys and the 3 setup ops.
    fn setup_group() -> (GroupID, [u8; 32], [u8; 32], [u8; 32], [u8; 32], Vec<OpEnvelope>) {
        let (owner_pub, owner_priv) = keypair();
        let (alice_pub, alice_priv) = keypair();
        let gid = test_group_id(&owner_pub);

        let create = op_group_create(gid, owner_pub, &owner_priv);
        let invite = op_invite(gid, owner_pub, &owner_priv, alice_pub, Role::Member, 2, 200);
        let accept = op_accept(gid, alice_pub, &alice_priv, invite.op_id, 3, 300);

        (gid, owner_pub, owner_priv, alice_pub, alice_priv, vec![create, invite, accept])
    }

    // -------------------------------------------------------------------
    // Basic apply_op flow
    // -------------------------------------------------------------------

    #[test]
    fn test_apply_group_create() {
        let (owner_pub, owner_priv) = keypair();
        let gid = test_group_id(&owner_pub);
        let mut state = GroupState::new(gid);

        let create = op_group_create(gid, owner_pub, &owner_priv);
        assert!(state.apply_op(&create).unwrap());
        assert_eq!(state.op_count, 1);
        assert_eq!(state.membership.active_member_count(), 1);
        assert!(state.membership.is_created());
    }

    #[test]
    fn test_apply_idempotent() {
        let (owner_pub, owner_priv) = keypair();
        let gid = test_group_id(&owner_pub);
        let mut state = GroupState::new(gid);

        let create = op_group_create(gid, owner_pub, &owner_priv);
        assert!(state.apply_op(&create).unwrap());
        assert!(!state.apply_op(&create).unwrap()); // duplicate
        assert_eq!(state.op_count, 1);
    }

    #[test]
    fn test_apply_wrong_group_rejected() {
        let (owner_pub, owner_priv) = keypair();
        let gid = test_group_id(&owner_pub);
        let other_gid = GroupID::from_bytes([0xFF; 32]);
        let mut state = GroupState::new(other_gid);

        let create = op_group_create(gid, owner_pub, &owner_priv);
        let err = state.apply_op(&create).unwrap_err();
        assert!(matches!(err, ApplyError::WrongGroup));
    }

    #[test]
    fn test_apply_full_lifecycle() {
        let (gid, _owner_pub, _owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops {
            state.apply_op(op).unwrap();
        }

        assert_eq!(state.op_count, 3);
        assert_eq!(state.membership.active_member_count(), 2);

        let msg = op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400);
        state.apply_op(&msg).unwrap();
        assert_eq!(state.messages.message_count(), 1);
        assert_eq!(state.op_count, 4);
    }

    #[test]
    fn test_apply_unauthorized_rejected() {
        let (gid, _owner_pub, _owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops {
            state.apply_op(op).unwrap();
        }

        // Alice (Member) tries to invite — should fail
        let (bob_pub, _) = keypair();
        let invite = op_invite(gid, alice_pub, &alice_priv, bob_pub, Role::Member, 4, 400);
        let err = state.apply_op(&invite).unwrap_err();
        assert!(matches!(err, ApplyError::Unauthorized(_)));
    }

    // -------------------------------------------------------------------
    // rebuild_from_ops — determinism
    // -------------------------------------------------------------------

    #[test]
    fn test_rebuild_deterministic_basic() {
        let (gid, owner_pub, owner_priv, alice_pub, alice_priv, mut ops) = setup_group();

        ops.push(op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400));
        ops.push(op_msg_add(gid, owner_pub, &owner_priv, [0x02; 32], 5, 500));
        ops.push(op_metadata(
            gid, owner_pub, &owner_priv, MetadataKey::Name, b"Test".to_vec(), 6, 600,
        ));
        ops.push(op_reaction(
            gid, alice_pub, &alice_priv, [0x01; 32], "\u{1F44D}", true, 7, 700,
        ));

        let hash_fwd = GroupState::rebuild_from_ops(gid, &ops).unwrap().state_hash();

        let mut rev = ops.clone();
        rev.reverse();
        let hash_rev = GroupState::rebuild_from_ops(gid, &rev).unwrap().state_hash();

        assert_eq!(hash_fwd, hash_rev);

        let mut interleaved: Vec<_> = ops.iter().step_by(2).cloned().collect();
        interleaved.extend(ops.iter().skip(1).step_by(2).cloned());
        let hash_int = GroupState::rebuild_from_ops(gid, &interleaved).unwrap().state_hash();

        assert_eq!(hash_fwd, hash_int);
    }

    #[test]
    fn test_rebuild_many_ops_multiple_permutations() {
        let (owner_pub, owner_priv) = keypair();
        let gid = test_group_id(&owner_pub);

        let create = op_group_create(gid, owner_pub, &owner_priv);
        let members: Vec<([u8; 32], [u8; 32])> = (0..3).map(|_| keypair()).collect();
        let mut ops = vec![create];

        let mut lamport = 2u64;
        let mut nonce = 200u64;

        // Invite + accept 3 members
        for (m_pub, m_priv) in &members {
            let inv = op_invite(gid, owner_pub, &owner_priv, *m_pub, Role::Member, lamport, nonce);
            let inv_id = inv.op_id;
            ops.push(inv);
            lamport += 1;
            nonce += 100;

            ops.push(op_accept(gid, *m_pub, m_priv, inv_id, lamport, nonce));
            lamport += 1;
            nonce += 100;
        }

        // Each member sends 5 messages
        for (m_pub, m_priv) in &members {
            for i in 0u8..5 {
                let mut mid = [0u8; 32];
                mid[0] = m_pub[0];
                mid[1] = i;
                ops.push(op_msg_add(gid, *m_pub, m_priv, mid, lamport, nonce));
                lamport += 1;
                nonce += 100;
            }
        }

        // Metadata
        ops.push(op_metadata(
            gid, owner_pub, &owner_priv, MetadataKey::Name, b"Big Group".to_vec(), lamport, nonce,
        ));
        lamport += 1;
        nonce += 100;
        ops.push(op_metadata(
            gid, owner_pub, &owner_priv, MetadataKey::Topic, b"General".to_vec(), lamport, nonce,
        ));

        assert_eq!(ops.len(), 24);

        let hash_orig = GroupState::rebuild_from_ops(gid, &ops).unwrap().state_hash();

        // 5 different permutations
        let perms: Vec<Vec<OpEnvelope>> = vec![
            { let mut v = ops.clone(); v.reverse(); v },
            { let mut v = ops.clone(); v.rotate_left(7); v },
            { let mut v = ops.clone(); v.rotate_left(13); v },
            {
                let mut v = ops.clone();
                for i in (0..v.len() - 1).step_by(2) { v.swap(i, i + 1); }
                v
            },
            {
                let mut v = ops.clone();
                let mid = v.len() / 2;
                v[..mid].reverse();
                v
            },
        ];

        for (i, perm) in perms.iter().enumerate() {
            let s = GroupState::rebuild_from_ops(gid, perm).unwrap();
            assert_eq!(s.state_hash(), hash_orig, "perm {} diverged", i);
            assert_eq!(s.op_count, 24);
            assert_eq!(s.membership.active_member_count(), 4);
        }
    }

    // -------------------------------------------------------------------
    // renderable_messages — membership-gated
    // -------------------------------------------------------------------

    #[test]
    fn test_renderable_hides_kicked_member() {
        let (gid, owner_pub, owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops { state.apply_op(op).unwrap(); }

        let msg = op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400);
        state.apply_op(&msg).unwrap();
        assert_eq!(state.renderable_messages().len(), 1);

        let kick = op_remove(gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 5, 500);
        state.apply_op(&kick).unwrap();

        // Message stored but not renderable
        assert_eq!(state.renderable_messages().len(), 0);
        assert_eq!(state.messages.message_count(), 1);
    }

    #[test]
    fn test_renderable_restored_after_reinvite() {
        let (gid, owner_pub, owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops { state.apply_op(op).unwrap(); }

        let msg = op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400);
        state.apply_op(&msg).unwrap();

        let kick = op_remove(gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 5, 500);
        state.apply_op(&kick).unwrap();
        assert_eq!(state.renderable_messages().len(), 0);

        let reinv = op_invite(gid, owner_pub, &owner_priv, alice_pub, Role::Member, 6, 600);
        state.apply_op(&reinv).unwrap();
        let reacc = op_accept(gid, alice_pub, &alice_priv, reinv.op_id, 7, 700);
        state.apply_op(&reacc).unwrap();

        assert_eq!(state.renderable_messages().len(), 1);
    }

    #[test]
    fn test_renderable_excludes_deleted() {
        let (gid, _owner_pub, _owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops { state.apply_op(op).unwrap(); }

        state.apply_op(&op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400)).unwrap();
        state.apply_op(&op_msg_add(gid, alice_pub, &alice_priv, [0x02; 32], 5, 500)).unwrap();
        assert_eq!(state.renderable_messages().len(), 2);

        let del_payload = MsgDeletePayload { msg_id: [0x01; 32] };
        let del = OpEnvelope::create_signed(
            gid, OpType::MsgDelete, &del_payload, 6, 600, alice_pub, &alice_priv,
        ).unwrap();
        state.apply_op(&del).unwrap();
        assert_eq!(state.renderable_messages().len(), 1);
    }

    // -------------------------------------------------------------------
    // state_hash
    // -------------------------------------------------------------------

    #[test]
    fn test_state_hash_changes_on_new_op() {
        let (gid, _owner_pub, _owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops { state.apply_op(op).unwrap(); }
        let h1 = state.state_hash();

        state.apply_op(&op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400)).unwrap();
        assert_ne!(h1, state.state_hash());
    }

    #[test]
    fn test_state_hash_stable_after_idempotent() {
        let (gid, _owner_pub, _owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops { state.apply_op(op).unwrap(); }

        let msg = op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400);
        state.apply_op(&msg).unwrap();
        let h1 = state.state_hash();
        state.apply_op(&msg).unwrap(); // idempotent
        assert_eq!(h1, state.state_hash());
    }

    // -------------------------------------------------------------------
    // Bookkeeping
    // -------------------------------------------------------------------

    #[test]
    fn test_limit_status_ok() {
        let (gid, _, _, _, _, ops) = setup_group();
        let state = GroupState::rebuild_from_ops(gid, &ops).unwrap();
        assert_eq!(state.limit_status(), OpLimitStatus::Ok);
    }

    #[test]
    fn test_heads_accumulate_in_v1() {
        let (gid, _owner_pub, _owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops { state.apply_op(op).unwrap(); }
        assert_eq!(state.heads.len(), 3);

        state.apply_op(&op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 4, 400)).unwrap();
        assert_eq!(state.heads.len(), 4);
    }

    #[test]
    fn test_max_lamport_tracked() {
        let (gid, owner_pub, _owner_priv, alice_pub, alice_priv, ops) = setup_group();
        let mut state = GroupState::new(gid);
        for op in &ops { state.apply_op(op).unwrap(); }

        let owner_dev = DeviceID::from_pubkey(&owner_pub);
        let alice_dev = DeviceID::from_pubkey(&alice_pub);
        assert_eq!(state.max_lamport[&owner_dev], 2);
        assert_eq!(state.max_lamport[&alice_dev], 3);

        state.apply_op(&op_msg_add(gid, alice_pub, &alice_priv, [0x01; 32], 10, 1000)).unwrap();
        assert_eq!(state.max_lamport[&alice_dev], 10);
    }
}
