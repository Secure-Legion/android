//! Account-role state adapter over the pinned group CRDT. Installation IDs
//! distinguish operations; membership and all permission checks remain account
//! scoped. Existing local history is a host-owned durable trust boundary.
use crate::epoch::{EpochOperation, MAGIC as EPOCH_MAGIC};
use crate::key_state::{GroupKeys, KeyStateError};
use crate::{DelegatedOperation, GroupError, RootRatification, MAGIC, MAX_OPERATION_BYTES};
use secure_device_protocol::DeviceCertificate;
use secure_device_protocol::DeviceRoster;
use securelegion::crdt::{
    apply::{ApplyError, GroupState},
    ids::{DeviceID, GroupID, OpID},
    limits::{check_op_limits, OpLimitStatus},
    ops::{GroupDeletePayload, OpEnvelope, OpType},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum StateError {
    #[error(transparent)]
    Envelope(#[from] GroupError),
    #[error("invalid legacy group signature or encoding")]
    Legacy,
    #[error("conflicting group operation identity")]
    Conflict,
    #[error("unseen device operation lacks current authority or exact root ratification")]
    MissingAuthority,
    #[error("group key rotation is required")]
    RekeyRequired,
    #[error("group clock is ahead of available history")]
    ClockGap,
    #[error("group causal dependency is missing")]
    MissingDependency,
    #[error("group protocol resource limit reached")]
    ResourceLimit,
    #[error(transparent)]
    Core(#[from] ApplyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use secure_device_protocol::{
        onion_from_public_key, DeviceCertificate, DeviceClaims, RosterEntry, ALL_CAPABILITIES,
        ML_KEM_PUBLIC_LEN,
    };
    use securelegion::crdt::ops::{
        GroupCreatePayload, GroupDeletePayload, MsgAddPayload, MsgEditPayload, Role, RoleSetPayload,
    };
    use serde::Serialize;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn public(n: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()
    }
    fn entry(root: u8, leaf: u8) -> RosterEntry {
        let ed = public(leaf);
        let x = PublicKey::from(&StaticSecret::from([leaf + 30; 32])).to_bytes();
        let kem = [leaf; ML_KEM_PUBLIC_LEN];
        let onion = onion_from_public_key(&ed).unwrap();
        let cert = DeviceCertificate::issue(
            DeviceClaims {
                account_ed: public(root),
                device_ed: ed,
                device_x: x,
                ml_kem_public_hash: Sha256::digest(kem).into(),
                onion: onion
                    .strip_suffix(".onion")
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                issued_at_ms: 1000,
                expires_at_ms: 1_000_000,
                capabilities: ALL_CAPABILITIES,
            },
            &[root; 32],
        )
        .unwrap();
        RosterEntry::new(cert, kem, format!("Synthetic {leaf}")).unwrap()
    }
    fn roster(root: u8) -> DeviceRoster {
        let a = entry(root, 10 + root);
        let b = entry(root, 20 + root);
        DeviceRoster::issue(
            &[root; 32],
            1,
            1000,
            a.certificate().claims().device_id_bytes(),
            vec![a, b],
        )
        .unwrap()
    }
    fn group() -> GroupID {
        GroupID::new(&DeviceID::from_pubkey(&public(1)), &[5; 32])
    }
    fn create() -> GroupCreatePayload {
        GroupCreatePayload {
            group_name: "Synthetic".into(),
            encrypted_group_secret: vec![9; 32],
        }
    }
    fn message(id: u8) -> MsgAddPayload {
        MsgAddPayload {
            msg_id: [id; 32],
            ciphertext: vec![id],
            nonce: [id; 24],
        }
    }
    fn legacy<P: Serialize>(
        root: u8,
        kind: OpType,
        payload: &P,
        lamport: u64,
        nonce: u64,
    ) -> GroupOperation {
        let op = OpEnvelope::create_signed(
            group(),
            kind,
            payload,
            lamport,
            nonce,
            public(root),
            &[root; 32],
        )
        .unwrap();
        GroupOperation::decode(&op.to_bytes().unwrap()).unwrap()
    }
    fn device<P: Serialize>(
        root: u8,
        leaf: u8,
        kind: OpType,
        payload: &P,
        lamport: u64,
        nonce: u64,
    ) -> GroupOperation {
        GroupOperation::from_device(
            DelegatedOperation::create(
                entry(root, leaf).certificate().clone(),
                &[leaf; 32],
                group(),
                kind,
                payload,
                vec![],
                lamport,
                nonce,
                2000,
            )
            .unwrap(),
        )
    }

    #[test]
    fn legacy_only_history_keeps_the_pinned_core_state_hash() {
        let ops = vec![
            legacy(1, OpType::GroupCreate, &create(), 1, 1),
            legacy(1, OpType::MsgAdd, &message(7), 2, 2),
        ];
        let inner: Vec<_> = ops
            .iter()
            .map(|op| op.core_operation().unwrap().clone())
            .collect();
        let native = GroupState::rebuild_from_ops(group(), &inner).unwrap();
        let state = AccountGroupState::rebuild(
            group(),
            &[],
            &ops,
            &Authority {
                rosters: &[],
                ratifications: &[],
                now_ms: 2000,
            },
        )
        .unwrap();
        assert_eq!(native.state_hash(), state.core().state_hash());
        assert_eq!(native.heads, state.core().heads);
        assert_eq!(native.max_lamport, state.core().max_lamport);
    }

    #[test]
    fn devices_share_one_account_membership_and_can_edit_the_accounts_own_message() {
        let rosters = [roster(1)];
        let authority = Authority {
            rosters: &rosters,
            ratifications: &[],
            now_ms: 2000,
        };
        let create = device(1, 11, OpType::GroupCreate, &create(), 1, 1);
        let msg = device(1, 21, OpType::MsgAdd, &message(7), 2, 2);
        let edit = device(
            1,
            11,
            OpType::MsgEdit,
            &MsgEditPayload {
                msg_id: [7; 32],
                new_ciphertext: vec![8],
                nonce: [8; 24],
            },
            3,
            3,
        );
        let mut state = AccountGroupState::new(group());
        assert_eq!(
            state
                .apply_batch(&[create.clone(), msg.clone(), edit.clone()], &authority)
                .unwrap(),
            3
        );
        assert_eq!(state.core().membership.members().len(), 1);
        assert!(state
            .core()
            .membership
            .members()
            .contains_key(&DeviceID::from_pubkey(&public(1))));
        assert_eq!(
            state.core().messages.messages()[&[7; 32]].author,
            DeviceID::from_pubkey(&public(1))
        );
        assert_eq!(
            state.core().messages.messages()[&[7; 32]].ciphertext,
            vec![8]
        );
        assert!(state
            .core()
            .max_lamport
            .contains_key(&DeviceID::from_pubkey(&public(11))));
        assert!(state
            .core()
            .max_lamport
            .contains_key(&DeviceID::from_pubkey(&public(21))));
        assert_eq!(state.apply_batch(&[edit], &authority).unwrap(), 0);
    }

    #[test]
    fn permanent_account_ratification_cannot_invent_a_group_role_and_batches_are_atomic() {
        let rosters = [roster(1)];
        let authority = Authority {
            rosters: &rosters,
            ratifications: &[],
            now_ms: 2000,
        };
        let mut state = AccountGroupState::new(group());
        state
            .apply_batch(
                &[legacy(1, OpType::GroupCreate, &create(), 1, 1)],
                &authority,
            )
            .unwrap();
        let before = state.core().state_hash();
        let heads = state.core().heads.clone();
        let valid = device(1, 11, OpType::MsgAdd, &message(7), 2, 2);
        let intruder = device(2, 12, OpType::MsgAdd, &message(8), 3, 3);
        let Kind::Device(ref operation) = intruder.kind else {
            unreachable!()
        };
        let proof = RootRatification::issue(operation, &[2; 32]).unwrap();
        let proofs = [proof];
        let authority = Authority {
            rosters: &rosters,
            ratifications: &proofs,
            now_ms: 2000,
        };
        assert!(matches!(
            state.apply_batch(&[valid.clone(), intruder], &authority),
            Err(StateError::Core(ApplyError::Unauthorized(_)))
        ));
        assert_eq!(before, state.core().state_hash());
        assert_eq!(heads, state.core().heads);
        assert_eq!(state.core().op_count, 1);
        assert!(!state.has_applied(&valid.operation().op_id));
        let demote = device(
            1,
            11,
            OpType::RoleSet,
            &RoleSetPayload {
                target_device_id: DeviceID::from_pubkey(&public(1)),
                new_role: Role::Member,
                admin_rights: None,
                custom_title: None,
            },
            2,
            9,
        );
        assert!(state.apply_batch(&[demote], &authority).is_err());
        assert_eq!(state.core().op_count, 1);
    }

    #[test]
    fn known_history_survives_revocation_but_new_backdated_ops_need_exact_root_approval() {
        let rosters = [roster(1)];
        let old_authority = Authority {
            rosters: &rosters,
            ratifications: &[],
            now_ms: 2000,
        };
        let create = legacy(1, OpType::GroupCreate, &create(), 1, 1);
        let first = device(1, 21, OpType::MsgAdd, &message(7), 2, 2);
        let later = device(1, 21, OpType::MsgAdd, &message(8), 3, 3);
        let mut old = AccountGroupState::new(group());
        old.apply_batch(&[create.clone(), first.clone()], &old_authority)
            .unwrap();
        let primary = entry(1, 11);
        let revoked = DeviceRoster::issue(
            &[1; 32],
            2,
            2000,
            primary.certificate().claims().device_id_bytes(),
            vec![primary],
        )
        .unwrap();
        let revoked = [revoked];
        let authority = Authority {
            rosters: &revoked,
            ratifications: &[],
            now_ms: 3000,
        };
        let restored =
            AccountGroupState::rebuild(group(), &[create.clone(), first.clone()], &[], &authority)
                .unwrap();
        assert_eq!(old.core().state_hash(), restored.core().state_hash());
        assert!(matches!(
            AccountGroupState::rebuild(
                group(),
                &[create.clone(), first.clone()],
                &[later.clone()],
                &authority
            ),
            Err(StateError::MissingAuthority)
        ));
        let Kind::Device(ref operation) = later.kind else {
            unreachable!()
        };
        let proofs = [RootRatification::issue(operation, &[1; 32]).unwrap()];
        let authority = Authority {
            rosters: &revoked,
            ratifications: &proofs,
            now_ms: 3000,
        };
        let accepted =
            AccountGroupState::rebuild(group(), &[create, first], &[later], &authority).unwrap();
        assert_eq!(accepted.core().messages.messages().len(), 2);
    }

    #[test]
    fn conflicting_signed_variants_fail_and_group_deletion_remains_final() {
        let rosters = [roster(1)];
        let authority = Authority {
            rosters: &rosters,
            ratifications: &[],
            now_ms: 2000,
        };
        let create = legacy(1, OpType::GroupCreate, &create(), 1, 1);
        let first = device(1, 21, OpType::MsgAdd, &message(7), 2, 2);
        let fork = device(1, 21, OpType::MsgAdd, &message(8), 2, 2);
        assert!(matches!(
            AccountGroupState::rebuild(group(), &[create.clone(), first], &[fork], &authority),
            Err(StateError::Conflict)
        ));
        let deleted = device(
            1,
            11,
            OpType::GroupDelete,
            &GroupDeletePayload { reason: None },
            2,
            3,
        );
        let mut state = AccountGroupState::new(group());
        state
            .apply_batch(&[create, deleted.clone()], &authority)
            .unwrap();
        assert!(state.core().group_deleted);
        assert_eq!(state.apply_batch(&[deleted], &authority).unwrap(), 0);
        let msg = device(1, 11, OpType::MsgAdd, &message(9), 3, 4);
        assert!(matches!(
            state.apply_batch(&[msg], &authority),
            Err(StateError::Core(ApplyError::GroupDeleted))
        ));
    }
}
impl From<securelegion::crdt::membership::MembershipError> for StateError {
    fn from(value: securelegion::crdt::membership::MembershipError) -> Self {
        Self::Core(value.into())
    }
}
impl From<securelegion::crdt::messages::MessageError> for StateError {
    fn from(value: securelegion::crdt::messages::MessageError) -> Self {
        Self::Core(value.into())
    }
}
impl From<securelegion::crdt::metadata::MetadataError> for StateError {
    fn from(value: securelegion::crdt::metadata::MetadataError) -> Self {
        Self::Core(value.into())
    }
}

#[derive(Clone)]
enum Kind {
    Legacy(OpEnvelope),
    Device(DelegatedOperation),
    Epoch(EpochOperation),
}
#[derive(Clone)]
pub struct GroupOperation {
    encoded: Zeroizing<Vec<u8>>,
    kind: Kind,
}
/// Common signed routing/causal fields. Extensions do not masquerade as a core
/// OpType or require a fabricated core envelope merely to expose these fields.
#[derive(Clone, Copy, Debug)]
pub struct OperationHeader<'a> {
    pub group_id: GroupID,
    pub op_id: OpID,
    pub parent_heads: &'a [OpID],
    pub lamport: u64,
    pub timestamp_ms: u64,
    pub author_pubkey: [u8; 32],
}
impl GroupOperation {
    pub fn decode(encoded: &[u8]) -> Result<Self, StateError> {
        if encoded.len() > MAX_OPERATION_BYTES {
            return Err(StateError::Legacy);
        }
        let kind = if encoded.starts_with(EPOCH_MAGIC) {
            if encoded.len() < 44 {
                return Err(StateError::Legacy);
            }
            let root = encoded[12..44].try_into().map_err(|_| StateError::Legacy)?;
            Kind::Epoch(EpochOperation::verify(encoded, &root)?)
        } else if encoded.starts_with(MAGIC) {
            if encoded.len() < 44 {
                return Err(StateError::Legacy);
            }
            let root: [u8; 32] = encoded[12..44].try_into().map_err(|_| StateError::Legacy)?;
            Kind::Device(DelegatedOperation::verify(encoded, &root)?)
        } else {
            let op = OpEnvelope::from_bytes(encoded).map_err(|_| StateError::Legacy)?;
            if op.to_bytes().map_err(|_| StateError::Legacy)?.as_slice() != encoded
                || !op.verify().map_err(|_| StateError::Legacy)?
                || op.lamport == 0
                || op.lamport > crate::MAX_SAFE
                || op.op_id.lamport != op.lamport
                || op.timestamp_ms > crate::MAX_TIMESTAMP
                || op.payload.len() > securelegion::crdt::limits::MAX_OP_PAYLOAD_BYTES
            {
                return Err(StateError::Legacy);
            }
            Kind::Legacy(op)
        };
        Ok(Self {
            encoded: Zeroizing::new(encoded.to_vec()),
            kind,
        })
    }
    pub fn from_device(operation: DelegatedOperation) -> Self {
        Self {
            encoded: Zeroizing::new(operation.encoded().to_vec()),
            kind: Kind::Device(operation),
        }
    }
    pub fn core_operation(&self) -> Option<&OpEnvelope> {
        Some(match &self.kind {
            Kind::Legacy(op) => op,
            Kind::Device(op) => op.operation(),
            Kind::Epoch(_) => return None,
        })
    }
    pub fn operation(&self) -> OperationHeader<'_> {
        fn core_header(op: &OpEnvelope) -> OperationHeader<'_> {
            OperationHeader {
                group_id: op.group_id,
                op_id: op.op_id,
                parent_heads: &op.parent_heads,
                lamport: op.lamport,
                timestamp_ms: op.timestamp_ms,
                author_pubkey: op.author_pubkey,
            }
        }
        match &self.kind {
            Kind::Epoch(epoch) => {
                let h = epoch.header();
                OperationHeader {
                    group_id: h.group_id,
                    op_id: h.op_id,
                    parent_heads: &h.parent_heads,
                    lamport: h.op_id.lamport,
                    timestamp_ms: h.timestamp_ms,
                    author_pubkey: epoch.certificate().claims().account_ed,
                }
            }
            Kind::Legacy(op) => core_header(op),
            Kind::Device(op) => core_header(op.operation()),
        }
    }
    pub fn type_name(&self) -> &'static str {
        match &self.kind {
            Kind::Legacy(op) => op.op_type.as_str(),
            Kind::Device(op) => op.operation().op_type.as_str(),
            Kind::Epoch(_) => "GroupKeyEpoch",
        }
    }
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.encoded).into()
    }
    pub fn delegated(&self) -> Option<&DelegatedOperation> {
        match &self.kind {
            Kind::Device(op) => Some(op),
            Kind::Legacy(_) => None,
            Kind::Epoch(_) => None,
        }
    }
    pub fn from_epoch(epoch: EpochOperation) -> Self {
        Self {
            encoded: Zeroizing::new(epoch.encoded().to_vec()),
            kind: Kind::Epoch(epoch),
        }
    }
    pub fn certificate(&self) -> Option<&DeviceCertificate> {
        match &self.kind {
            Kind::Legacy(_) => None,
            Kind::Device(op) => Some(op.certificate()),
            Kind::Epoch(op) => Some(op.certificate()),
        }
    }
    pub fn epoch(&self) -> Option<&EpochOperation> {
        match &self.kind {
            Kind::Epoch(epoch) => Some(epoch),
            _ => None,
        }
    }
}

/// Callers must source these rosters from their highest durably pinned epochs,
/// never directly from an incoming operation. Ratification is exact root-signed
/// authority and does not bypass the pinned membership/role state machine.
pub struct Authority<'a> {
    pub rosters: &'a [DeviceRoster],
    pub ratifications: &'a [RootRatification],
    pub now_ms: u64,
}
impl Authority<'_> {
    pub(crate) fn ratified<'a>(
        &self,
        operations: impl Iterator<Item = &'a GroupOperation>,
    ) -> HashSet<[u8; 32]> {
        let by_hash: HashMap<_, _> = operations
            .filter(|op| op.certificate().is_some())
            .map(|op| (op.hash(), op))
            .collect();
        self.ratifications
            .iter()
            .filter_map(|proof| {
                let hash: [u8; 32] = proof.encoded()[6..38].try_into().unwrap();
                let op = by_hash.get(&hash)?;
                RootRatification::verify_exact(
                    proof.encoded(),
                    op.hash(),
                    &op.operation().author_pubkey,
                )
                .ok()
                .map(|_| hash)
            })
            .collect()
    }
    fn authorize(&self, op: &DelegatedOperation) -> Result<(), StateError> {
        self.authorize_certificate(op.certificate())
    }
    pub(crate) fn authorize_certificate(
        &self,
        certificate: &DeviceCertificate,
    ) -> Result<(), StateError> {
        let root = &certificate.claims().account_ed;
        let roster = self
            .rosters
            .iter()
            .filter(|r| r.account_ed() == root)
            .max_by_key(|r| r.epoch())
            .ok_or(StateError::MissingAuthority)?;
        // Do not silently choose one of two forked equal-epoch observations.
        for other in self.rosters.iter().filter(|r| r.account_ed() == root) {
            roster
                .check_update(Some(other), self.now_ms)
                .map_err(GroupError::from)?;
        }
        crate::authorize_group_certificate(certificate, roster, None, self.now_ms)
            .map_err(|_| StateError::MissingAuthority)
    }
}

#[derive(Clone)]
pub struct AccountGroupState {
    core: GroupState,
    hashes: HashMap<OpID, [u8; 32]>,
    superseded: BTreeMap<OpID, [u8; 32]>,
    archived_invites: BTreeMap<DeviceID, (OpID, Vec<u8>)>,
    removal_requires_rotation: bool,
    keys: GroupKeys,
    exposure_events: BTreeMap<OpID, DeviceID>,
    message_epochs: HashMap<[u8; 32], ([u8; 32], bool)>,
    // The pinned core rejects a ban when a concurrent leave already removed
    // its target. Retain that later authorized ban without fabricating a
    // membership transition or changing the shared core.
    removed_bans: BTreeMap<DeviceID, OpID>,
    discarded_messages: HashSet<[u8; 32]>,
    historical_roots: BTreeMap<DeviceID, [u8; 32]>,
    membership_actions: BTreeMap<(DeviceID, OpID, u8), OpID>,
}
impl AccountGroupState {
    pub fn new(group: GroupID) -> Self {
        Self {
            core: GroupState::new(group),
            hashes: HashMap::new(),
            superseded: BTreeMap::new(),
            archived_invites: BTreeMap::new(),
            removal_requires_rotation: false,
            keys: GroupKeys::default(),
            exposure_events: BTreeMap::new(),
            message_epochs: HashMap::new(),
            removed_bans: BTreeMap::new(),
            discarded_messages: HashSet::new(),
            historical_roots: BTreeMap::new(),
            membership_actions: BTreeMap::new(),
        }
    }
    pub fn core(&self) -> &GroupState {
        &self.core
    }
    pub fn state_hash(&self) -> [u8; 32] {
        let core = self.keys.state_hash(self.core.state_hash());
        if self.removed_bans.is_empty() {
            return core;
        }
        let mut hash = Sha256::new();
        hash.update(b"secure-legion-group-removed-bans-v1\0");
        hash.update(core);
        hash.update((self.removed_bans.len() as u32).to_be_bytes());
        for (account, event) in &self.removed_bans {
            hash.update(account.as_bytes());
            hash.update(event.author.as_bytes());
            hash.update(event.lamport.to_be_bytes());
            hash.update(event.nonce.to_be_bytes());
        }
        hash.finalize().into()
    }
    pub fn is_banned(&self, account: &DeviceID) -> bool {
        self.removed_bans.contains_key(account)
            || self
                .core
                .membership
                .members()
                .get(account)
                .is_some_and(|m| m.banned)
    }
    pub(crate) fn ban_operation(&self, account: &DeviceID) -> Option<OpID> {
        self.removed_bans.get(account).copied().or_else(|| {
            self.core
                .membership
                .members()
                .get(account)
                .filter(|m| m.banned)
                .and_then(|m| m.remove_op)
        })
    }
    pub fn current_key(&self) -> Option<&[u8; 32]> {
        self.keys.current().map(|version| &*version.key)
    }
    pub fn current_epoch(&self) -> Option<[u8; 32]> {
        self.keys.current().map(|version| version.id)
    }
    pub fn current_epoch_operation(&self) -> Option<OpID> {
        self.keys.current().map(|version| version.op_id)
    }
    pub fn genesis_epoch(&self) -> Option<[u8; 32]> {
        self.keys.genesis()
    }
    pub fn epoch_key(&self, id: &[u8; 32]) -> Option<&[u8; 32]> {
        self.keys.get(id).map(|version| &*version.key)
    }
    pub fn epoch_ready(&self, id: &[u8; 32]) -> bool {
        self.keys.ready(id)
    }
    pub fn key_versions(&self) -> impl Iterator<Item = (&[u8; 32], &[u8; 32], bool)> {
        self.keys.versions().map(|v| (&v.id, &*v.key, v.eligible))
    }
    pub fn removal_frontier(&self) -> Vec<OpID> {
        self.keys.frontier()
    }
    pub fn message_cipher<'a>(
        &self,
        message: &'a securelegion::crdt::messages::MessageEntry,
    ) -> Result<([u8; 32], &'a [u8]), StateError> {
        let (id, framed) = *self
            .message_epochs
            .get(&message.msg_id)
            .ok_or(StateError::MissingDependency)?;
        let raw = if framed {
            message.ciphertext.get(38..).ok_or(StateError::Legacy)?
        } else {
            message.ciphertext.as_slice()
        };
        Ok((id, raw))
    }
    fn message_binding(
        &self,
        op: &OpEnvelope,
        legacy: bool,
    ) -> Result<Option<([u8; 32], [u8; 32], bool)>, StateError> {
        use securelegion::crdt::ops::{MsgAddPayload, MsgEditPayload};
        let (message, cipher) = match op.op_type {
            OpType::MsgAdd => {
                let p: MsgAddPayload = op.decode_payload().map_err(ApplyError::from)?;
                (p.msg_id, p.ciphertext)
            }
            OpType::MsgEdit => {
                let p: MsgEditPayload = op.decode_payload().map_err(ApplyError::from)?;
                (p.msg_id, p.new_ciphertext)
            }
            _ => return Ok(None),
        };
        let genesis = self.keys.genesis().ok_or(StateError::MissingDependency)?;
        let (id, _, framed) = crate::message_cipher::split(&cipher, genesis, legacy)
            .map_err(|_| StateError::Legacy)?;
        Ok(Some((message, id, framed)))
    }
    pub fn membership_digest(&self) -> [u8; 32] {
        let mut roots: Vec<_> = self
            .core
            .membership
            .members()
            .values()
            .filter(|m| !m.removed && !m.banned)
            .map(|m| m.pubkey)
            .collect();
        roots.sort();
        let mut digest = Sha256::new();
        digest.update(b"secure-legion-group-membership-view-v1\0");
        digest.update(self.core.group_id.as_bytes());
        digest.update((roots.len() as u32).to_be_bytes());
        for root in roots {
            digest.update(root);
        }
        digest.finalize().into()
    }
    pub fn can_rotate(&self, account: &[u8; 32]) -> bool {
        use securelegion::crdt::ops::Role;
        self.core
            .membership
            .get_active_member(&DeviceID::from_pubkey(account))
            .is_some_and(|m| {
                !m.banned
                    && (m.role == Role::Owner
                        || (m.role == Role::Admin
                            && m.admin_rights.is_some_and(|rights| rights.can_remove)))
            })
    }
    fn key_error(error: KeyStateError) -> StateError {
        match error {
            KeyStateError::Dependency => StateError::MissingDependency,
            KeyStateError::Invalid => StateError::Conflict,
        }
    }
    fn exposure(&mut self, op: &OpEnvelope, required: bool) -> Result<(), StateError> {
        use securelegion::crdt::ops::{MemberInvitePayload, MemberRemovePayload};
        let target = match op.op_type {
            OpType::MemberRemove => {
                op.decode_payload::<MemberRemovePayload>()
                    .map_err(ApplyError::from)?
                    .target_device_id
            }
            OpType::MemberInvite => {
                op.decode_payload::<MemberInvitePayload>()
                    .map_err(ApplyError::from)?
                    .invited_device_id
            }
            _ => return Ok(()),
        };
        self.exposure_events.insert(op.op_id, target);
        if required {
            self.keys
                .expose(target, op.op_id)
                .map_err(Self::key_error)?;
        }
        Ok(())
    }
    fn apply_epoch(
        &mut self,
        encoded: &GroupOperation,
        epoch: &EpochOperation,
        authority: &Authority<'_>,
        known: &HashSet<[u8; 32]>,
        replay_known: &HashSet<[u8; 32]>,
    ) -> Result<bool, StateError> {
        if !known.contains(&encoded.hash()) {
            authority.authorize_certificate(epoch.certificate())?;
        }
        let header = epoch.header();
        if header
            .parent_heads
            .iter()
            .chain(&header.removal_frontier)
            .any(|id| !self.hashes.contains_key(id))
        {
            return Err(StateError::MissingDependency);
        }
        let eligible =
            !self.core.group_deleted && self.can_rotate(&encoded.operation().author_pubkey);
        if !eligible && !replay_known.contains(&encoded.hash()) {
            return Err(StateError::MissingAuthority);
        }
        let mut coverage = BTreeMap::new();
        for id in &header.removal_frontier {
            let target = *self.exposure_events.get(id).ok_or(StateError::Legacy)?;
            if coverage.insert(target, *id).is_some() {
                return Err(StateError::Legacy);
            }
        }
        self.keys
            .install(epoch, coverage, eligible)
            .map_err(Self::key_error)?;
        if !eligible {
            return self.suppress(encoded);
        }
        self.track(encoded.operation());
        self.hashes.insert(header.op_id, encoded.hash());
        Ok(true)
    }
    pub fn has_applied(&self, id: &OpID) -> bool {
        self.hashes.contains_key(id)
    }
    pub fn superseded(&self) -> &BTreeMap<OpID, [u8; 32]> {
        &self.superseded
    }
    pub fn historical_principals(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.historical_roots
            .iter()
            .filter(|(id, _)| !self.core.membership.members().contains_key(id))
            .map(|(_, root)| root)
    }
    pub fn archived_invite(&self, account: &DeviceID) -> Option<&(OpID, Vec<u8>)> {
        self.archived_invites.get(account)
    }
    fn track(&mut self, op: OperationHeader<'_>) {
        for parent in op.parent_heads {
            self.core.heads.remove(parent);
        }
        self.core.heads.insert(op.op_id);
        self.core.op_count += 1;
        self.core
            .max_lamport
            .entry(op.op_id.author)
            .and_modify(|n| *n = (*n).max(op.lamport))
            .or_insert(op.lamport);
    }
    fn suppress(&mut self, encoded: &GroupOperation) -> Result<bool, StateError> {
        let header = encoded.operation();
        self.historical_roots.insert(
            DeviceID::from_pubkey(&header.author_pubkey),
            header.author_pubkey,
        );
        if let Some(op) = encoded
            .core_operation()
            .filter(|op| op.op_type == OpType::MsgAdd)
        {
            let p: securelegion::crdt::ops::MsgAddPayload =
                op.decode_payload().map_err(ApplyError::from)?;
            self.discarded_messages.insert(p.msg_id);
        }
        // Preserve private archive access if a previously accepted invitation
        // is invalidated by its inviter's concurrent departure. This does not
        // insert a member, confer a role, or authorize a new invitation.
        if let Some(op) = encoded
            .core_operation()
            .filter(|op| op.op_type == OpType::MemberInvite)
        {
            if let Ok(p) = op.decode_payload::<securelegion::crdt::ops::MemberInvitePayload>() {
                self.historical_roots
                    .insert(p.invited_device_id, p.invited_pubkey);
                let required = self
                    .core
                    .membership
                    .members()
                    .get(&p.invited_device_id)
                    .is_none_or(|m| m.removed || m.banned);
                if required {
                    self.exposure(op, true)?;
                }
                self.archived_invites
                    .insert(p.invited_device_id, (op.op_id, p.encrypted_group_secret));
            }
        }
        if let Some(op) = encoded
            .core_operation()
            .filter(|op| op.op_type == OpType::MemberRemove)
        {
            self.exposure(op, false)?;
        }
        self.track(header);
        self.hashes.insert(header.op_id, encoded.hash());
        self.superseded.insert(header.op_id, encoded.hash());
        Ok(true)
    }
    fn logical_duplicate(&self, op: &OpEnvelope) -> Result<bool, StateError> {
        use securelegion::crdt::ops::*;
        let account = DeviceID::from_pubkey(&op.author_pubkey);
        Ok(match op.op_type {
            OpType::MemberAccept => {
                let p: MemberAcceptPayload = op.decode_payload().map_err(ApplyError::from)?;
                self.core
                    .membership
                    .members()
                    .get(&account)
                    .is_some_and(|m| (m.accepted || m.removed) && m.invited_by == p.invite_op_id)
            }
            OpType::MemberRemove => {
                let p: MemberRemovePayload = op.decode_payload().map_err(ApplyError::from)?;
                matches!(p.reason, RemoveReason::Leave)
                    && p.target_device_id == account
                    && !p.ban
                    && self
                        .core
                        .membership
                        .members()
                        .get(&account)
                        .is_some_and(|m| m.removed)
            }
            _ => false,
        })
    }
    fn membership_action(
        &self,
        op: &OpEnvelope,
    ) -> Result<Option<(DeviceID, OpID, u8)>, StateError> {
        use securelegion::crdt::ops::*;
        let account = DeviceID::from_pubkey(&op.author_pubkey);
        Ok(match op.op_type {
            OpType::MemberAccept => {
                let p: MemberAcceptPayload = op.decode_payload().map_err(ApplyError::from)?;
                Some((op.op_id.author, p.invite_op_id, 1))
            }
            OpType::MemberRemove => {
                let p: MemberRemovePayload = op.decode_payload().map_err(ApplyError::from)?;
                if matches!(p.reason, RemoveReason::Leave)
                    && !p.ban
                    && p.target_device_id == account
                {
                    self.core
                        .membership
                        .members()
                        .get(&account)
                        .map(|m| (op.op_id.author, m.invited_by, 2))
                } else {
                    None
                }
            }
            _ => None,
        })
    }
    fn replay_conflict(&self, op: &OpEnvelope) -> Result<bool, StateError> {
        use securelegion::crdt::ops::*;
        let account = DeviceID::from_pubkey(&op.author_pubkey);
        let members = self.core.membership.members();
        Ok(match op.op_type {
            OpType::MemberAccept => {
                let p: MemberAcceptPayload = op.decode_payload().map_err(ApplyError::from)?;
                members.get(&account).is_none_or(|m| {
                    m.removed || m.banned || m.accepted || m.invited_by != p.invite_op_id
                })
            }
            OpType::MemberInvite => {
                let p: MemberInvitePayload = op.decode_payload().map_err(ApplyError::from)?;
                members.get(&p.invited_device_id).is_some_and(|m| {
                    self.is_banned(&p.invited_device_id) || (m.accepted && !m.removed)
                })
            }
            OpType::MemberRemove => {
                let p: MemberRemovePayload = op.decode_payload().map_err(ApplyError::from)?;
                members.get(&p.target_device_id).is_none_or(|m| {
                    (m.removed && !self.can_ban_removed(op, &p))
                        || (matches!(p.reason, RemoveReason::Kick)
                            && members.get(&account).is_none_or(|author| {
                                !author.accepted || author.removed || author.role > m.role
                            }))
                })
            }
            OpType::RoleSet => {
                let p: RoleSetPayload = op.decode_payload().map_err(ApplyError::from)?;
                members
                    .get(&p.target_device_id)
                    .is_none_or(|m| !m.accepted || m.removed || m.banned)
            }
            OpType::MemberUnban => {
                let p: MemberUnbanPayload = op.decode_payload().map_err(ApplyError::from)?;
                !self.is_banned(&p.target_device_id)
            }
            OpType::MsgEdit => {
                let p: MsgEditPayload = op.decode_payload().map_err(ApplyError::from)?;
                !self.core.messages.messages().contains_key(&p.msg_id)
                    && self.discarded_messages.contains(&p.msg_id)
            }
            OpType::MsgDelete => {
                let p: MsgDeletePayload = op.decode_payload().map_err(ApplyError::from)?;
                !self.core.messages.messages().contains_key(&p.msg_id)
                    && self.discarded_messages.contains(&p.msg_id)
            }
            OpType::ReactionSet => {
                let p: ReactionSetPayload = op.decode_payload().map_err(ApplyError::from)?;
                !self.core.messages.messages().contains_key(&p.msg_id)
                    && self.discarded_messages.contains(&p.msg_id)
            }
            _ => false,
        })
    }
    fn can_ban_removed(
        &self,
        op: &OpEnvelope,
        payload: &securelegion::crdt::ops::MemberRemovePayload,
    ) -> bool {
        use securelegion::crdt::ops::RemoveReason;
        let members = self.core.membership.members();
        matches!(payload.reason, RemoveReason::Kick)
            && payload.ban
            && members
                .get(&payload.target_device_id)
                .is_some_and(|target| {
                    target.removed
                        && self
                            .core
                            .membership
                            .get_active_member(&DeviceID::from_pubkey(&op.author_pubkey))
                            .is_some_and(|author| author.role <= target.role)
                })
    }
    pub fn needs_rekey(&self) -> bool {
        if self
            .keys
            .versions()
            .any(|version| Some(version.id) != self.keys.genesis() && version.eligible)
        {
            self.keys.needs_rekey()
        } else {
            self.removal_requires_rotation
                || self.core.membership.needs_rekey()
                || self.keys.needs_rekey()
        }
    }
    fn privilege_guard(&self, op: &OpEnvelope) -> Result<(), StateError> {
        use securelegion::crdt::ops::{
            MemberInvitePayload, MemberRemovePayload, MetadataKey, MetadataSetPayload,
            RemoveReason, Role, RoleSetPayload,
        };
        let owner = self
            .core
            .membership
            .get_active_member(&DeviceID::from_pubkey(&op.author_pubkey))
            .is_some_and(|m| m.role == Role::Owner);
        match op.op_type {
            OpType::MemberInvite => {
                let p: MemberInvitePayload = op.decode_payload().map_err(ApplyError::from)?;
                if p.invited_device_id != DeviceID::from_pubkey(&p.invited_pubkey) {
                    return Err(StateError::Legacy);
                }
                if matches!(p.role, Role::Owner | Role::Admin) && !owner {
                    return Err(ApplyError::Unauthorized(
                        "only owner may invite privileged roles".into(),
                    )
                    .into());
                }
            }
            OpType::RoleSet => {
                let p: RoleSetPayload = op.decode_payload().map_err(ApplyError::from)?;
                if p.new_role != Role::Owner
                    && self
                        .core
                        .membership
                        .members()
                        .get(&p.target_device_id)
                        .is_some_and(|m| m.role == Role::Owner)
                {
                    return Err(ApplyError::Unauthorized("owner role is immutable".into()).into());
                }
                if p.new_role == Role::Owner && !owner {
                    return Err(
                        ApplyError::Unauthorized("only owner may grant ownership".into()).into(),
                    );
                }
            }
            OpType::MemberRemove => {
                let p: MemberRemovePayload = op.decode_payload().map_err(ApplyError::from)?;
                if matches!(p.reason, RemoveReason::Leave)
                    && p.target_device_id != DeviceID::from_pubkey(&op.author_pubkey)
                {
                    return Err(
                        ApplyError::Unauthorized("leave author must be target".into()).into(),
                    );
                }
                if self
                    .core
                    .membership
                    .members()
                    .get(&p.target_device_id)
                    .is_some_and(|m| m.role == Role::Owner)
                {
                    return Err(ApplyError::Unauthorized("owner cannot be removed".into()).into());
                }
            }
            OpType::MetadataSet => {
                let p: MetadataSetPayload = op.decode_payload().map_err(ApplyError::from)?;
                if !matches!(
                    p.key,
                    MetadataKey::Name | MetadataKey::Avatar | MetadataKey::Topic
                ) && !owner
                {
                    return Err(ApplyError::Unauthorized(
                        "only owner may change group permissions".into(),
                    )
                    .into());
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn invite_at_capacity(&self, op: &OpEnvelope) -> Result<bool, StateError> {
        if op.op_type != OpType::MemberInvite {
            return Ok(false);
        }
        let p: securelegion::crdt::ops::MemberInvitePayload =
            op.decode_payload().map_err(ApplyError::from)?;
        let members = self.core.membership.members();
        Ok(members
            .get(&p.invited_device_id)
            .is_none_or(|m| m.removed || m.banned)
            && members.values().filter(|m| !m.removed && !m.banned).count() >= 20)
    }

    /// Atomic live batch. A rejection never publishes partial permissions,
    /// messages, heads or duplicate bookkeeping.
    pub fn apply_batch(
        &mut self,
        operations: &[GroupOperation],
        authority: &Authority<'_>,
    ) -> Result<usize, StateError> {
        let mut candidate = self.clone();
        let mut applied = 0;
        let ratified = authority.ratified(operations.iter());
        let no_replay = HashSet::new();
        for op in operations {
            applied += usize::from(candidate.apply_one(op, authority, &ratified, &no_replay)?);
        }
        *self = candidate;
        Ok(applied)
    }

    /// `existing_local` must come from previously validated, committed local
    /// storage. It must never be filled from untrusted packet/snapshot fields.
    /// Exact old hashes preserve history without accepting newly backdated ops.
    pub fn rebuild(
        group: GroupID,
        existing_local: &[GroupOperation],
        incoming: &[GroupOperation],
        authority: &Authority<'_>,
    ) -> Result<Self, StateError> {
        let replay_known: HashSet<_> = existing_local.iter().map(GroupOperation::hash).collect();
        let mut known = replay_known.clone();
        // Verify exact proofs once per batch; rescanning/verifying a complete
        // history's proof list for every operation creates quadratic work.
        known.extend(authority.ratified(existing_local.iter().chain(incoming.iter())));
        let mut unique = BTreeMap::<OpID, &GroupOperation>::new();
        for op in existing_local.iter().chain(incoming) {
            if op.operation().group_id != group {
                return Err(ApplyError::WrongGroup.into());
            }
            if let Some(prior) = unique.insert(op.operation().op_id, op) {
                if prior.hash() != op.hash() {
                    return Err(StateError::Conflict);
                }
            }
        }
        let mut all: Vec<_> = unique.into_values().collect();
        all.sort_by_key(|op| (op.operation().lamport, op.operation().op_id));
        let mut state = Self::new(group);
        for op in all {
            state.apply_one(op, authority, &known, &replay_known)?;
        }
        Ok(state)
    }

    /// A receipt-bound foreign invitation may retain deterministically
    /// invalidated historical records as no-effects. Authenticate EVERY leaf
    /// against the current roster or its exact Root proof before enabling that
    /// replay. This never authorizes unseen live effects or admits the recipient;
    /// the caller must still check actual pending membership/current inviter.
    pub(crate) fn reconstruct_invitation(
        group: GroupID,
        operations: &[GroupOperation],
        previous_local: &[GroupOperation],
        authority: &Authority<'_>,
    ) -> Result<Self, StateError> {
        let mut ratified = authority.ratified(operations.iter());
        ratified.extend(previous_local.iter().map(GroupOperation::hash));
        for op in operations {
            if let Some(certificate) = op.certificate() {
                if !ratified.contains(&op.hash()) {
                    authority.authorize_certificate(certificate)?;
                }
            }
        }
        Self::rebuild(group, operations, &[], authority)
    }

    fn apply_one(
        &mut self,
        encoded: &GroupOperation,
        authority: &Authority<'_>,
        known: &HashSet<[u8; 32]>,
        replay_known: &HashSet<[u8; 32]>,
    ) -> Result<bool, StateError> {
        let header = encoded.operation();
        let hash = encoded.hash();
        if header.group_id != self.core.group_id {
            return Err(ApplyError::WrongGroup.into());
        }
        if let Some(old) = self.hashes.get(&header.op_id) {
            return if old == &hash {
                Ok(false)
            } else {
                Err(StateError::Conflict)
            };
        }
        // Complete histories produced by this protocol advance from committed
        // state. A signed giant counter must not permanently exhaust the clock.
        // A legitimate far-ahead peer first supplies its missing history.
        let maximum = self.core.max_lamport.values().copied().max().unwrap_or(0);
        if header.lamport > maximum.saturating_add(4096) {
            return Err(StateError::ClockGap);
        }
        if let Kind::Epoch(epoch) = &encoded.kind {
            return self.apply_epoch(encoded, epoch, authority, known, replay_known);
        }
        let op = encoded
            .core_operation()
            .ok_or(StateError::MissingDependency)?;
        // Already committed histories can contain concurrent writes accepted
        // before another device learned of a leave, demotion or deletion. Keep
        // their exact signed records/clock identities, but do not reapply an
        // effect invalidated by the deterministic control history. A new wire
        // op or a Root ratification alone never receives this replay privilege.
        // Static identity/Owner protections and conflicting creation stay hard.
        self.privilege_guard(op)?;
        if let Kind::Device(delegated) = &encoded.kind {
            if !known.contains(&hash) {
                authority.authorize(delegated)?;
            }
            if op
                .parent_heads
                .iter()
                .any(|id| !self.hashes.contains_key(id))
            {
                return Err(StateError::MissingDependency);
            }
            if op.op_type == OpType::MemberAccept {
                let p: securelegion::crdt::ops::MemberAcceptPayload =
                    op.decode_payload().map_err(ApplyError::from)?;
                if !self.hashes.contains_key(&p.invite_op_id) {
                    return Err(StateError::MissingDependency);
                }
            }
        }
        let binding = self.message_binding(op, matches!(encoded.kind, Kind::Legacy(_)))?;
        if let Some(action) = self.membership_action(op)? {
            if self
                .membership_actions
                .get(&action)
                .is_some_and(|prior| *prior != op.op_id)
                && !replay_known.contains(&hash)
            {
                return Err(StateError::ResourceLimit);
            }
            self.membership_actions.entry(action).or_insert(op.op_id);
        }
        if self.invite_at_capacity(op)? {
            if replay_known.contains(&hash) {
                return self.suppress(encoded);
            }
            return Err(StateError::ResourceLimit);
        }
        if !self.core.group_deleted && self.logical_duplicate(op)? {
            return self.suppress(encoded);
        }
        let account = DeviceID::from_pubkey(&op.author_pubkey);
        let self_leave = if op.op_type == OpType::MemberRemove {
            let p: securelegion::crdt::ops::MemberRemovePayload =
                op.decode_payload().map_err(ApplyError::from)?;
            matches!(p.reason, securelegion::crdt::ops::RemoveReason::Leave)
                && p.target_device_id == account
                && self
                    .core
                    .membership
                    .members()
                    .get(&account)
                    .is_some_and(|m| !m.removed && !m.banned)
        } else {
            false
        };
        if replay_known.contains(&hash)
            && op.op_type != OpType::GroupCreate
            && (self.core.group_deleted
                || (!self_leave
                    && !self.core.membership.can_author_op(
                        &account,
                        &op.op_type,
                        &self.core.metadata,
                    ))
                || (matches!(op.op_type, OpType::MsgAdd | OpType::MsgEdit) && self.needs_rekey())
                || self.replay_conflict(op)?)
        {
            return self.suppress(encoded);
        }
        // A late, authorized ban still applies if a concurrent leave removed
        // the target first. Unbanning this overlay does not restore membership.
        let ban_removed = if op.op_type == OpType::MemberRemove {
            let p = op.decode_payload().map_err(ApplyError::from)?;
            self.can_ban_removed(op, &p).then_some(p.target_device_id)
        } else {
            None
        };
        let unban_removed = if op.op_type == OpType::MemberUnban {
            let p: securelegion::crdt::ops::MemberUnbanPayload =
                op.decode_payload().map_err(ApplyError::from)?;
            self.removed_bans
                .contains_key(&p.target_device_id)
                .then_some(p.target_device_id)
        } else {
            None
        };
        if ban_removed.is_some() || unban_removed.is_some() {
            if self.core.group_deleted
                || !self
                    .core
                    .membership
                    .can_author_op(&account, &op.op_type, &self.core.metadata)
            {
                return Err(StateError::MissingAuthority);
            }
            if let Some(target) = ban_removed {
                self.removed_bans.insert(target, op.op_id);
                self.exposure(op, false)?;
            }
            if let Some(target) = unban_removed {
                if self
                    .core
                    .membership
                    .members()
                    .get(&target)
                    .is_some_and(|m| m.banned)
                {
                    self.core.membership.apply_member_unban(op)?;
                }
                self.removed_bans.remove(&target);
            }
            self.track(header);
            self.hashes.insert(op.op_id, hash);
            return Ok(true);
        }
        if op.op_type == OpType::MemberInvite {
            let p: securelegion::crdt::ops::MemberInvitePayload =
                op.decode_payload().map_err(ApplyError::from)?;
            if self.is_banned(&p.invited_device_id) {
                return Err(StateError::MissingAuthority);
            }
        }
        match &encoded.kind {
            Kind::Legacy(op) => {
                // Root-signed records must not evade identity/privilege checks
                // during mixed-format import or after a legacy-history reload.
                self.privilege_guard(op)?;
                if let Some((_, id, _)) = binding {
                    if !self.keys.ready(&id) {
                        if replay_known.contains(&hash) {
                            return self.suppress(encoded);
                        }
                        return Err(StateError::RekeyRequired);
                    }
                }
                if !known.contains(&hash)
                    && matches!(op.op_type, OpType::MsgAdd | OpType::MsgEdit)
                    && self.needs_rekey()
                {
                    return Err(StateError::RekeyRequired);
                }
                self.core.apply_op(op)?;
            }
            Kind::Device(delegated) => {
                if !known.contains(&hash) {
                    authority.authorize(delegated)?;
                }
                if self.core.group_deleted {
                    return Err(ApplyError::GroupDeleted.into());
                }
                if !op.op_type.is_membership_op()
                    && check_op_limits(self.core.op_count) == OpLimitStatus::HardCapReached
                {
                    return Err(ApplyError::OpLimitReached.into());
                }
                // The core's generic gate treats all MemberRemove operations
                // as administrative. A current or pending non-owner may leave
                // itself; the pinned membership dispatcher still prevents
                // owner removal and validates the exact leave author/target.
                if op.op_type != OpType::GroupCreate
                    && !self_leave
                    && !self.core.membership.can_author_op(
                        &account,
                        &op.op_type,
                        &self.core.metadata,
                    )
                {
                    return Err(
                        ApplyError::Unauthorized("account cannot author operation".into()).into(),
                    );
                }
                if let Some((_, id, _)) = binding {
                    if self.keys.get(&id).is_none() {
                        return Err(StateError::MissingDependency);
                    }
                    if !self.keys.ready(&id) {
                        if replay_known.contains(&hash) {
                            return self.suppress(encoded);
                        }
                        return Err(StateError::RekeyRequired);
                    }
                }
                let target = match op.op_type {
                    OpType::ReactionSet => Some(
                        op.decode_payload::<securelegion::crdt::ops::ReactionSetPayload>()
                            .map_err(ApplyError::from)?
                            .msg_id,
                    ),
                    OpType::MsgDelete => Some(
                        op.decode_payload::<securelegion::crdt::ops::MsgDeletePayload>()
                            .map_err(ApplyError::from)?
                            .msg_id,
                    ),
                    OpType::MsgEdit => Some(
                        op.decode_payload::<securelegion::crdt::ops::MsgEditPayload>()
                            .map_err(ApplyError::from)?
                            .msg_id,
                    ),
                    _ => None,
                };
                if target.is_some_and(|id| !self.core.messages.messages().contains_key(&id)) {
                    return Err(StateError::MissingDependency);
                }
                // New device frames must not promote an administrator to
                // Owner or let an info editor grant membership permissions.
                // Ordinary member invites are promoted separately by RoleSet.
                self.privilege_guard(op)?;
                if matches!(op.op_type, OpType::MsgAdd | OpType::MsgEdit) && self.needs_rekey() {
                    return Err(StateError::RekeyRequired);
                }
                // Same dispatch and role state as the pinned apply.rs. No
                // alternate Dart/Swift implementation or synthetic member.
                match op.op_type {
                    OpType::GroupCreate => self.core.membership.apply_group_create(op)?,
                    OpType::MemberInvite => self.core.membership.apply_member_invite(op)?,
                    OpType::MemberAccept => self.core.membership.apply_member_accept(op)?,
                    OpType::MemberRemove => self.core.membership.apply_member_remove(op)?,
                    OpType::MemberUnban => self.core.membership.apply_member_unban(op)?,
                    OpType::RoleSet => self.core.membership.apply_role_set(op)?,
                    OpType::MsgAdd => self.core.messages.apply_msg_add(op)?,
                    OpType::MsgEdit => self.core.messages.apply_msg_edit(op)?,
                    OpType::MsgDelete => self
                        .core
                        .messages
                        .apply_msg_delete(op, &self.core.membership)?,
                    OpType::ReactionSet => self.core.messages.apply_reaction_set(op)?,
                    OpType::MetadataSet => self.core.metadata.apply_metadata_set(op)?,
                    OpType::GroupDelete => {
                        let payload: GroupDeletePayload =
                            op.decode_payload().map_err(ApplyError::from)?;
                        self.core.group_deleted = true;
                        self.core.delete_reason = payload.reason;
                    }
                }
                self.track(header);
            }
            Kind::Epoch(_) => return Err(StateError::Legacy),
        }
        if op.op_type == OpType::GroupCreate {
            let p: securelegion::crdt::ops::GroupCreatePayload =
                op.decode_payload().map_err(ApplyError::from)?;
            let key = p
                .encrypted_group_secret
                .as_slice()
                .try_into()
                .map_err(|_| StateError::Legacy)?;
            self.keys
                .set_genesis(hash, op.op_id, key)
                .map_err(Self::key_error)?;
        }
        // Leaving members also retain the old key. Preserve this requirement
        // across replay/re-invites until an explicit key-epoch protocol exists.
        if op.op_type == OpType::MemberRemove {
            self.removal_requires_rotation = true;
            self.exposure(op, true)?;
        }
        if let Some((message, id, framed)) = binding {
            if self
                .core
                .messages
                .messages()
                .get(&message)
                .is_some_and(|m| {
                    (op.op_type == OpType::MsgAdd && m.create_op == op.op_id)
                        || (op.op_type == OpType::MsgEdit && m.last_edit_op == Some(op.op_id))
                })
            {
                self.message_epochs.insert(message, (id, framed));
            }
        }
        self.hashes.insert(op.op_id, hash);
        Ok(true)
    }
}
