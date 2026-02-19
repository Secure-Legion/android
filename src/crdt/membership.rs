/// Membership CRDT — Observed-Remove Set with role-based authorization.
///
/// Tracks group membership as a set of `MemberEntry` records keyed by DeviceID.
/// - OR-Set semantics: re-invite after removal only succeeds if the invite op
///   supersedes the remove (higher lamport/OpID). Stale invites cannot resurrect
///   kicked members.
/// - Role changes use LWW (Last-Writer-Wins) by lamport, tie-break by OpID.
/// - `rekey_required` flag set on all active members after a Kick (rotation deferred to v2).

use std::collections::BTreeMap;
use thiserror::Error;

use crate::crdt::ids::{DeviceID, OpID};
use crate::crdt::ops::{
    GroupCreatePayload, MemberAcceptPayload, MemberInvitePayload, MemberRemovePayload,
    OpEnvelope, OpType, RemoveReason, Role, RoleSetPayload,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum MembershipError {
    #[error("Group already created")]
    GroupAlreadyCreated,

    #[error("GroupCreate must have lamport=1")]
    InvalidCreateLamport,

    #[error("Target is already an active member")]
    AlreadyActiveMember,

    #[error("No pending invite found for this device")]
    NoPendingInvite,

    #[error("Accept does not match invite op")]
    AcceptInviteMismatch,

    #[error("Member already accepted")]
    AlreadyAccepted,

    #[error("Target not found in membership")]
    TargetNotFound,

    #[error("Target already removed")]
    AlreadyRemoved,

    #[error("Kicker is not an active member")]
    KickerNotActive,

    #[error("Insufficient role to kick target")]
    InsufficientRoleForKick,

    #[error("Leave requires author to be the target")]
    LeaveAuthorMismatch,

    #[error("Target is not an active member")]
    TargetNotActive,

    #[error("Payload decode error: {0}")]
    PayloadDecode(String),
}

// ---------------------------------------------------------------------------
// MemberEntry
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MemberEntry {
    pub device_id: DeviceID,
    pub pubkey: [u8; 32],
    pub role: Role,
    /// The MemberInvite (or GroupCreate) op that added this member.
    pub invited_by: OpID,
    /// True after MemberAccept received (creator is auto-accepted).
    pub accepted: bool,
    /// True after MemberRemove applied.
    pub removed: bool,
    /// The MemberRemove op, if any.
    pub remove_op: Option<OpID>,
    /// True after a Kick — flags stale GroupSecret for remaining members.
    pub rekey_required: bool,
    /// GroupSecret from the MemberInvite (or GroupCreate) payload.
    /// Kotlin extracts this to store in the Group entity when processing an invite.
    pub encrypted_group_secret: Vec<u8>,
    /// Lamport of the op that last set the role (for LWW).
    role_lamport: u64,
    /// OpID of the op that last set the role (for LWW tie-break).
    role_op: OpID,
}

// ---------------------------------------------------------------------------
// MembershipState
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MembershipState {
    members: BTreeMap<DeviceID, MemberEntry>,
    created: bool,
}

impl MembershipState {
    pub fn new() -> Self {
        MembershipState {
            members: BTreeMap::new(),
            created: false,
        }
    }

    /// Whether GroupCreate has been applied.
    pub fn is_created(&self) -> bool {
        self.created
    }

    /// Read-only access to the membership map.
    pub fn members(&self) -> &BTreeMap<DeviceID, MemberEntry> {
        &self.members
    }

    /// Count of active (accepted + not removed) members.
    pub fn active_member_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.accepted && !m.removed)
            .count()
    }

    // -----------------------------------------------------------------------
    // Apply functions — called from the unified apply engine (Phase 3)
    // -----------------------------------------------------------------------

    /// Apply a GroupCreate op. Sets the creator as Owner, auto-accepted.
    pub fn apply_group_create(&mut self, op: &OpEnvelope) -> Result<(), MembershipError> {
        if self.created {
            return Err(MembershipError::GroupAlreadyCreated);
        }
        if op.lamport != 1 {
            return Err(MembershipError::InvalidCreateLamport);
        }

        let payload: GroupCreatePayload = op
            .decode_payload()
            .map_err(|e| MembershipError::PayloadDecode(e.to_string()))?;

        let device_id = DeviceID::from_pubkey(&op.author_pubkey);

        let entry = MemberEntry {
            device_id,
            pubkey: op.author_pubkey,
            role: Role::Owner,
            invited_by: op.op_id,
            accepted: true,
            removed: false,
            remove_op: None,
            rekey_required: false,
            encrypted_group_secret: payload.encrypted_group_secret,
            role_lamport: op.lamport,
            role_op: op.op_id,
        };

        self.members.insert(device_id, entry);
        self.created = true;
        Ok(())
    }

    /// Apply a MemberInvite op. Adds a new entry (or re-adds after removal).
    ///
    /// If the target was previously removed, the invite must have a higher
    /// lamport/OpID than the remove op — prevents stale invites from
    /// resurrecting kicked members.
    pub fn apply_member_invite(&mut self, op: &OpEnvelope) -> Result<(), MembershipError> {
        let payload: MemberInvitePayload = op
            .decode_payload()
            .map_err(|e| MembershipError::PayloadDecode(e.to_string()))?;

        // Target must not already be an active member
        if self.get_active_member(&payload.invited_device_id).is_some() {
            return Err(MembershipError::AlreadyActiveMember);
        }

        // If previously removed, only re-invite if this op supersedes the remove
        if let Some(existing) = self.members.get(&payload.invited_device_id) {
            if existing.removed {
                if let Some(remove_op) = existing.remove_op {
                    // Stale invite (older or concurrent-but-lower OpID) cannot undo a remove
                    if op.op_id <= remove_op {
                        return Ok(()); // silently drop stale invite
                    }
                }
            }
        }

        // Insert or overwrite — new invite supersedes old state
        let entry = MemberEntry {
            device_id: payload.invited_device_id,
            pubkey: payload.invited_pubkey,
            role: payload.role,
            invited_by: op.op_id,
            accepted: false,
            removed: false,
            remove_op: None,
            rekey_required: false,
            encrypted_group_secret: payload.encrypted_group_secret,
            role_lamport: op.lamport,
            role_op: op.op_id,
        };

        self.members.insert(payload.invited_device_id, entry);
        Ok(())
    }

    /// Apply a MemberAccept op. Sets accepted=true for the accepting device.
    pub fn apply_member_accept(&mut self, op: &OpEnvelope) -> Result<(), MembershipError> {
        let payload: MemberAcceptPayload = op
            .decode_payload()
            .map_err(|e| MembershipError::PayloadDecode(e.to_string()))?;

        let author_device = DeviceID::from_pubkey(&op.author_pubkey);

        let entry = self
            .members
            .get_mut(&author_device)
            .ok_or(MembershipError::NoPendingInvite)?;

        // Verify accept references the correct invite
        if entry.invited_by != payload.invite_op_id {
            return Err(MembershipError::AcceptInviteMismatch);
        }

        if entry.accepted {
            return Err(MembershipError::AlreadyAccepted);
        }

        if entry.removed {
            return Err(MembershipError::AlreadyRemoved);
        }

        entry.accepted = true;
        Ok(())
    }

    /// Apply a MemberRemove op.
    /// - Kick: kicker must be active with ≥ authority than target; sets rekey_required
    ///   on all remaining active members.
    /// - Leave: author must be the target (self-remove).
    pub fn apply_member_remove(&mut self, op: &OpEnvelope) -> Result<(), MembershipError> {
        let payload: MemberRemovePayload = op
            .decode_payload()
            .map_err(|e| MembershipError::PayloadDecode(e.to_string()))?;

        let author_device = DeviceID::from_pubkey(&op.author_pubkey);

        // Target must exist and not already be removed
        let target = self
            .members
            .get(&payload.target_device_id)
            .ok_or(MembershipError::TargetNotFound)?;

        if target.removed {
            return Err(MembershipError::AlreadyRemoved);
        }

        match payload.reason {
            RemoveReason::Kick => {
                // Kicker must be an active member
                let kicker = self
                    .get_active_member(&author_device)
                    .ok_or(MembershipError::KickerNotActive)?;
                let kicker_role = kicker.role;
                let target_role = target.role;

                // Kicker must have ≥ authority (lower Ord value = higher authority)
                if kicker_role > target_role {
                    return Err(MembershipError::InsufficientRoleForKick);
                }

                let target_device = payload.target_device_id;

                // Mark target as removed
                let target_mut = self.members.get_mut(&target_device).unwrap();
                target_mut.removed = true;
                target_mut.remove_op = Some(op.op_id);

                // Set rekey_required on ALL remaining active members
                let active_devices: Vec<DeviceID> = self
                    .members
                    .iter()
                    .filter(|(did, m)| m.accepted && !m.removed && **did != target_device)
                    .map(|(did, _)| *did)
                    .collect();

                for did in active_devices {
                    if let Some(m) = self.members.get_mut(&did) {
                        m.rekey_required = true;
                    }
                }
            }
            RemoveReason::Leave => {
                if author_device != payload.target_device_id {
                    return Err(MembershipError::LeaveAuthorMismatch);
                }

                let target_mut = self
                    .members
                    .get_mut(&payload.target_device_id)
                    .unwrap();
                target_mut.removed = true;
                target_mut.remove_op = Some(op.op_id);
            }
        }

        Ok(())
    }

    /// Apply a RoleSet op. LWW: higher lamport wins, tie-break by OpID.
    pub fn apply_role_set(&mut self, op: &OpEnvelope) -> Result<(), MembershipError> {
        let payload: RoleSetPayload = op
            .decode_payload()
            .map_err(|e| MembershipError::PayloadDecode(e.to_string()))?;

        // Target must be active
        {
            let target = self
                .members
                .get(&payload.target_device_id)
                .ok_or(MembershipError::TargetNotFound)?;

            if !target.accepted || target.removed {
                return Err(MembershipError::TargetNotActive);
            }

            // LWW: ignore if this op is dominated by the current role setter
            let dominated = op.lamport < target.role_lamport
                || (op.lamport == target.role_lamport && op.op_id < target.role_op);
            if dominated {
                return Ok(()); // silently ignore stale role set
            }
        }

        // Apply the update
        let target = self
            .members
            .get_mut(&payload.target_device_id)
            .unwrap();
        target.role = payload.new_role;
        target.role_lamport = op.lamport;
        target.role_op = op.op_id;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Query functions
    // -----------------------------------------------------------------------

    /// Check if a device is authorized to create the given op type.
    ///
    /// General gate — specific apply functions may do additional checks
    /// (e.g., kick role comparison, accept invite matching).
    pub fn can_author_op(&self, device_id: &DeviceID, op_type: &OpType) -> bool {
        match self.get_active_member(device_id) {
            None => {
                // Non-active devices can only author MemberAccept
                matches!(op_type, OpType::MemberAccept)
            }
            Some(member) => match op_type {
                OpType::MsgAdd
                | OpType::MsgEdit
                | OpType::MsgDelete
                | OpType::ReactionSet => member.role != Role::ReadOnly,

                OpType::MemberInvite | OpType::MemberRemove => {
                    member.role == Role::Owner || member.role == Role::Admin
                }

                OpType::RoleSet | OpType::MetadataSet => {
                    member.role == Role::Owner || member.role == Role::Admin
                }

                OpType::GroupCreate => false, // only valid as the very first op
                OpType::MemberAccept => true,
            },
        }
    }

    /// Get an active member (accepted AND not removed).
    pub fn get_active_member(&self, device_id: &DeviceID) -> Option<&MemberEntry> {
        self.members
            .get(device_id)
            .filter(|m| m.accepted && !m.removed)
    }

    /// Check if a device is currently active — used for membership-gated message rendering.
    pub fn is_author_active_for_render(&self, device_id: &DeviceID) -> bool {
        self.get_active_member(device_id).is_some()
    }

    /// Check if any active member has rekey_required set (kicked member had the GroupSecret).
    pub fn needs_rekey(&self) -> bool {
        self.members
            .values()
            .any(|m| m.rekey_required && !m.removed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::ids::GroupID;
    use crate::crdt::ops::{OpEnvelope, OpType};

    /// Generate a fresh Ed25519 keypair.
    fn keypair() -> ([u8; 32], [u8; 32]) {
        crate::crypto::signing::generate_keypair()
    }

    /// Create a test GroupID from a pubkey.
    fn test_group_id(pubkey: &[u8; 32]) -> GroupID {
        let creator = DeviceID::from_pubkey(pubkey);
        GroupID::new(&creator, &[0xAA; 32])
    }

    /// Build a GroupCreate op.
    fn make_group_create() -> (OpEnvelope, GroupID, [u8; 32], [u8; 32]) {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);
        let payload = GroupCreatePayload {
            group_name: "Test Group".into(),
            encrypted_group_secret: vec![1, 2, 3],
        };
        let op = OpEnvelope::create_signed(
            gid, OpType::GroupCreate, &payload, 1, 100, pub_k, &priv_k,
        )
        .unwrap();
        (op, gid, pub_k, priv_k)
    }

    /// Build a MemberInvite op.
    fn make_invite(
        gid: GroupID,
        inviter_pub: [u8; 32],
        inviter_priv: &[u8; 32],
        invitee_pub: [u8; 32],
        lamport: u64,
        nonce: u64,
        role: Role,
    ) -> OpEnvelope {
        let invitee_device = DeviceID::from_pubkey(&invitee_pub);
        let payload = MemberInvitePayload {
            invited_device_id: invitee_device,
            invited_pubkey: invitee_pub,
            role,
            encrypted_group_secret: vec![10, 20, 30],
        };
        OpEnvelope::create_signed(
            gid, OpType::MemberInvite, &payload, lamport, nonce, inviter_pub, inviter_priv,
        )
        .unwrap()
    }

    /// Build a MemberAccept op.
    fn make_accept(
        gid: GroupID,
        accepter_pub: [u8; 32],
        accepter_priv: &[u8; 32],
        invite_op_id: OpID,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MemberAcceptPayload { invite_op_id };
        OpEnvelope::create_signed(
            gid, OpType::MemberAccept, &payload, lamport, nonce, accepter_pub, accepter_priv,
        )
        .unwrap()
    }

    /// Build a MemberRemove op.
    fn make_remove(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        target_pub: [u8; 32],
        reason: RemoveReason,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let target_device = DeviceID::from_pubkey(&target_pub);
        let payload = MemberRemovePayload {
            target_device_id: target_device,
            reason,
        };
        OpEnvelope::create_signed(
            gid, OpType::MemberRemove, &payload, lamport, nonce, author_pub, author_priv,
        )
        .unwrap()
    }

    /// Build a RoleSet op.
    fn make_role_set(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        target_pub: [u8; 32],
        new_role: Role,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let target_device = DeviceID::from_pubkey(&target_pub);
        let payload = RoleSetPayload {
            target_device_id: target_device,
            new_role,
        };
        OpEnvelope::create_signed(
            gid, OpType::RoleSet, &payload, lamport, nonce, author_pub, author_priv,
        )
        .unwrap()
    }

    // -------------------------------------------------------------------
    // Basic lifecycle: create → invite → accept → verify active
    // -------------------------------------------------------------------

    #[test]
    fn test_create_group() {
        let mut state = MembershipState::new();
        let (create_op, _, pub_k, _) = make_group_create();

        state.apply_group_create(&create_op).unwrap();

        assert!(state.is_created());
        assert_eq!(state.active_member_count(), 1);

        let creator_device = DeviceID::from_pubkey(&pub_k);
        let member = state.get_active_member(&creator_device).unwrap();
        assert_eq!(member.role, Role::Owner);
        assert!(member.accepted);
        assert!(!member.removed);
    }

    #[test]
    fn test_create_group_duplicate_rejected() {
        let mut state = MembershipState::new();
        let (create_op, _, _, _) = make_group_create();

        state.apply_group_create(&create_op).unwrap();
        let err = state.apply_group_create(&create_op).unwrap_err();
        assert!(matches!(err, MembershipError::GroupAlreadyCreated));
    }

    #[test]
    fn test_create_group_wrong_lamport_rejected() {
        let (pub_k, priv_k) = keypair();
        let gid = test_group_id(&pub_k);
        let payload = GroupCreatePayload {
            group_name: "Bad".into(),
            encrypted_group_secret: vec![],
        };
        let op = OpEnvelope::create_signed(
            gid, OpType::GroupCreate, &payload, 5, 0, pub_k, &priv_k,
        )
        .unwrap();

        let mut state = MembershipState::new();
        let err = state.apply_group_create(&op).unwrap_err();
        assert!(matches!(err, MembershipError::InvalidCreateLamport));
    }

    #[test]
    fn test_full_lifecycle_create_invite_accept() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        // Invite Alice
        let (alice_pub, alice_priv) = keypair();
        let invite_op = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite_op).unwrap();

        let alice_device = DeviceID::from_pubkey(&alice_pub);

        // Alice is NOT active yet (not accepted)
        assert!(state.get_active_member(&alice_device).is_none());
        assert_eq!(state.active_member_count(), 1);

        // Alice accepts
        let accept_op = make_accept(gid, alice_pub, &alice_priv, invite_op.op_id, 3, 300);
        state.apply_member_accept(&accept_op).unwrap();

        // Now Alice is active
        let alice = state.get_active_member(&alice_device).unwrap();
        assert_eq!(alice.role, Role::Member);
        assert!(alice.accepted);
        assert!(!alice.removed);
        assert_eq!(state.active_member_count(), 2);
    }

    // -------------------------------------------------------------------
    // Kick + rekey_required
    // -------------------------------------------------------------------

    #[test]
    fn test_kick_sets_removed_and_rekey_required() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        // Invite and accept Alice + Bob
        let (alice_pub, alice_priv) = keypair();
        let invite_a = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite_a).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite_a.op_id, 3, 300,
            ))
            .unwrap();

        let (bob_pub, bob_priv) = keypair();
        let invite_b = make_invite(
            gid, owner_pub, &owner_priv, bob_pub, 4, 400, Role::Member,
        );
        state.apply_member_invite(&invite_b).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, bob_pub, &bob_priv, invite_b.op_id, 5, 500,
            ))
            .unwrap();

        assert_eq!(state.active_member_count(), 3);
        assert!(!state.needs_rekey());

        // Owner kicks Alice
        let kick = make_remove(
            gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 6, 600,
        );
        state.apply_member_remove(&kick).unwrap();

        let alice_device = DeviceID::from_pubkey(&alice_pub);
        assert!(state.get_active_member(&alice_device).is_none());
        assert!(state.members().get(&alice_device).unwrap().removed);
        assert_eq!(state.active_member_count(), 2);

        // rekey_required set on remaining active members
        assert!(state.needs_rekey());
        let owner_device = DeviceID::from_pubkey(&owner_pub);
        assert!(state.members().get(&owner_device).unwrap().rekey_required);
        let bob_device = DeviceID::from_pubkey(&bob_pub);
        assert!(state.members().get(&bob_device).unwrap().rekey_required);
    }

    #[test]
    fn test_leave_no_rekey() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite.op_id, 3, 300,
            ))
            .unwrap();

        // Alice leaves voluntarily
        let leave = make_remove(
            gid, alice_pub, &alice_priv, alice_pub, RemoveReason::Leave, 4, 400,
        );
        state.apply_member_remove(&leave).unwrap();

        let alice_device = DeviceID::from_pubkey(&alice_pub);
        assert!(state.get_active_member(&alice_device).is_none());
        assert_eq!(state.active_member_count(), 1);
        assert!(!state.needs_rekey()); // leave does NOT set rekey
    }

    // -------------------------------------------------------------------
    // OR-Set: re-invite after removal (lamport-gated)
    // -------------------------------------------------------------------

    #[test]
    fn test_reinvite_after_kick_with_higher_lamport() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        // Invite → accept → kick Alice
        let (alice_pub, alice_priv) = keypair();
        let invite1 = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite1).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite1.op_id, 3, 300,
            ))
            .unwrap();
        let kick = make_remove(
            gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 4, 400,
        );
        state.apply_member_remove(&kick).unwrap();

        let alice_device = DeviceID::from_pubkey(&alice_pub);
        assert!(state.get_active_member(&alice_device).is_none());

        // Re-invite with HIGHER lamport (5 > 4) — succeeds
        let invite2 = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 5, 500, Role::Admin,
        );
        state.apply_member_invite(&invite2).unwrap();

        let entry = state.members().get(&alice_device).unwrap();
        assert!(!entry.removed);
        assert!(!entry.accepted);
        assert_eq!(entry.role, Role::Admin);

        // Accept the re-invite
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite2.op_id, 6, 600,
            ))
            .unwrap();
        let alice = state.get_active_member(&alice_device).unwrap();
        assert_eq!(alice.role, Role::Admin);
        assert!(alice.accepted);
    }

    #[test]
    fn test_stale_invite_after_kick_silently_dropped() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        // Invite → accept → kick Alice at lamport=4
        let (alice_pub, alice_priv) = keypair();
        let invite1 = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite1).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite1.op_id, 3, 300,
            ))
            .unwrap();
        let kick = make_remove(
            gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 4, 400,
        );
        state.apply_member_remove(&kick).unwrap();

        // Stale invite with LOWER lamport (2 < 4) — silently dropped
        let stale_invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 201, Role::Member,
        );
        state.apply_member_invite(&stale_invite).unwrap(); // no error, just ignored

        // Alice is still removed
        let alice_device = DeviceID::from_pubkey(&alice_pub);
        assert!(state.members().get(&alice_device).unwrap().removed);
        assert!(state.get_active_member(&alice_device).is_none());
    }

    // -------------------------------------------------------------------
    // Authorization: role hierarchy + escalation prevention
    // -------------------------------------------------------------------

    #[test]
    fn test_member_cannot_invite() {
        let mut state = MembershipState::new();
        let (create_op, _, owner_pub, _) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, _) = keypair();
        let alice_device = DeviceID::from_pubkey(&alice_pub);
        let owner_device = DeviceID::from_pubkey(&owner_pub);
        let owner_op_id = state.members().get(&owner_device).unwrap().invited_by;

        // Insert Alice as active Member for auth testing
        state.members.insert(
            alice_device,
            MemberEntry {
                device_id: alice_device,
                pubkey: alice_pub,
                role: Role::Member,
                invited_by: owner_op_id,
                accepted: true,
                removed: false,
                remove_op: None,
                rekey_required: false,
                encrypted_group_secret: vec![],
                role_lamport: 2,
                role_op: owner_op_id,
            },
        );

        assert!(state.can_author_op(&alice_device, &OpType::MsgAdd));
        assert!(state.can_author_op(&alice_device, &OpType::ReactionSet));
        assert!(!state.can_author_op(&alice_device, &OpType::MemberInvite));
        assert!(!state.can_author_op(&alice_device, &OpType::MemberRemove));
        assert!(!state.can_author_op(&alice_device, &OpType::RoleSet));
        assert!(!state.can_author_op(&alice_device, &OpType::MetadataSet));
    }

    #[test]
    fn test_readonly_cannot_send_messages() {
        let mut state = MembershipState::new();
        let (create_op, _, owner_pub, _) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (ro_pub, _) = keypair();
        let ro_device = DeviceID::from_pubkey(&ro_pub);
        let owner_device = DeviceID::from_pubkey(&owner_pub);
        let owner_op_id = state.members().get(&owner_device).unwrap().invited_by;

        state.members.insert(
            ro_device,
            MemberEntry {
                device_id: ro_device,
                pubkey: ro_pub,
                role: Role::ReadOnly,
                invited_by: owner_op_id,
                accepted: true,
                removed: false,
                remove_op: None,
                rekey_required: false,
                encrypted_group_secret: vec![],
                role_lamport: 2,
                role_op: owner_op_id,
            },
        );

        assert!(!state.can_author_op(&ro_device, &OpType::MsgAdd));
        assert!(!state.can_author_op(&ro_device, &OpType::MsgEdit));
        assert!(!state.can_author_op(&ro_device, &OpType::MsgDelete));
        assert!(!state.can_author_op(&ro_device, &OpType::ReactionSet));
    }

    #[test]
    fn test_admin_can_invite_and_kick() {
        let mut state = MembershipState::new();
        let (create_op, _, owner_pub, _) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (admin_pub, _) = keypair();
        let admin_device = DeviceID::from_pubkey(&admin_pub);
        let owner_device = DeviceID::from_pubkey(&owner_pub);
        let owner_op_id = state.members().get(&owner_device).unwrap().invited_by;

        state.members.insert(
            admin_device,
            MemberEntry {
                device_id: admin_device,
                pubkey: admin_pub,
                role: Role::Admin,
                invited_by: owner_op_id,
                accepted: true,
                removed: false,
                remove_op: None,
                rekey_required: false,
                encrypted_group_secret: vec![],
                role_lamport: 2,
                role_op: owner_op_id,
            },
        );

        assert!(state.can_author_op(&admin_device, &OpType::MemberInvite));
        assert!(state.can_author_op(&admin_device, &OpType::MemberRemove));
        assert!(state.can_author_op(&admin_device, &OpType::MetadataSet));
        assert!(state.can_author_op(&admin_device, &OpType::MsgAdd));
    }

    #[test]
    fn test_non_member_can_only_accept() {
        let state = MembershipState::new();
        let (stranger_pub, _) = keypair();
        let stranger_device = DeviceID::from_pubkey(&stranger_pub);

        assert!(state.can_author_op(&stranger_device, &OpType::MemberAccept));
        assert!(!state.can_author_op(&stranger_device, &OpType::MsgAdd));
        assert!(!state.can_author_op(&stranger_device, &OpType::MemberInvite));
        assert!(!state.can_author_op(&stranger_device, &OpType::GroupCreate));
    }

    // -------------------------------------------------------------------
    // Kick authorization: role hierarchy
    // -------------------------------------------------------------------

    #[test]
    fn test_admin_cannot_kick_owner() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (admin_pub, admin_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, admin_pub, 2, 200, Role::Admin,
        );
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, admin_pub, &admin_priv, invite.op_id, 3, 300,
            ))
            .unwrap();

        // Admin tries to kick Owner — should fail
        let kick = make_remove(
            gid, admin_pub, &admin_priv, owner_pub, RemoveReason::Kick, 4, 400,
        );
        let err = state.apply_member_remove(&kick).unwrap_err();
        assert!(matches!(err, MembershipError::InsufficientRoleForKick));
    }

    #[test]
    fn test_admin_can_kick_member() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        // Add admin and member through proper ops
        let (admin_pub, admin_priv) = keypair();
        let invite_admin = make_invite(
            gid, owner_pub, &owner_priv, admin_pub, 2, 200, Role::Admin,
        );
        state.apply_member_invite(&invite_admin).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, admin_pub, &admin_priv, invite_admin.op_id, 3, 300,
            ))
            .unwrap();

        let (member_pub, member_priv) = keypair();
        let invite_member = make_invite(
            gid, owner_pub, &owner_priv, member_pub, 4, 400, Role::Member,
        );
        state.apply_member_invite(&invite_member).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, member_pub, &member_priv, invite_member.op_id, 5, 500,
            ))
            .unwrap();

        assert_eq!(state.active_member_count(), 3);

        // Admin kicks member — should succeed
        let kick = make_remove(
            gid, admin_pub, &admin_priv, member_pub, RemoveReason::Kick, 6, 600,
        );
        state.apply_member_remove(&kick).unwrap();

        let member_device = DeviceID::from_pubkey(&member_pub);
        assert!(state.get_active_member(&member_device).is_none());
        assert_eq!(state.active_member_count(), 2);
    }

    #[test]
    fn test_inactive_kicker_rejected() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        // Invite Alice (accepted) and Bob (not accepted)
        let (alice_pub, alice_priv) = keypair();
        let invite_alice = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Admin,
        );
        state.apply_member_invite(&invite_alice).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite_alice.op_id, 3, 300,
            ))
            .unwrap();

        let (bob_pub, bob_priv) = keypair();
        let invite_bob = make_invite(
            gid, owner_pub, &owner_priv, bob_pub, 4, 400, Role::Admin,
        );
        state.apply_member_invite(&invite_bob).unwrap();
        // Bob does NOT accept — he's pending, not active

        // Bob (pending, not active) tries to kick Alice — should fail
        let kick = make_remove(
            gid, bob_pub, &bob_priv, alice_pub, RemoveReason::Kick, 5, 500,
        );
        let err = state.apply_member_remove(&kick).unwrap_err();
        assert!(matches!(err, MembershipError::KickerNotActive));
    }

    // -------------------------------------------------------------------
    // RoleSet LWW
    // -------------------------------------------------------------------

    #[test]
    fn test_role_set_lww_higher_lamport_wins() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite.op_id, 3, 300,
            ))
            .unwrap();

        let alice_device = DeviceID::from_pubkey(&alice_pub);
        assert_eq!(
            state.get_active_member(&alice_device).unwrap().role,
            Role::Member
        );

        // Promote to Admin at lamport=4
        let role_op = make_role_set(
            gid, owner_pub, &owner_priv, alice_pub, Role::Admin, 4, 400,
        );
        state.apply_role_set(&role_op).unwrap();
        assert_eq!(
            state.get_active_member(&alice_device).unwrap().role,
            Role::Admin
        );

        // Stale op at lamport=3 — silently ignored
        let stale = make_role_set(
            gid, owner_pub, &owner_priv, alice_pub, Role::ReadOnly, 3, 350,
        );
        state.apply_role_set(&stale).unwrap();
        assert_eq!(
            state.get_active_member(&alice_device).unwrap().role,
            Role::Admin
        );
    }

    #[test]
    fn test_role_set_lww_tiebreak_by_opid() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite.op_id, 3, 300,
            ))
            .unwrap();

        // Two role sets at same lamport, different nonces
        let role_a = make_role_set(
            gid, owner_pub, &owner_priv, alice_pub, Role::Admin, 4, 100,
        );
        let role_b = make_role_set(
            gid, owner_pub, &owner_priv, alice_pub, Role::ReadOnly, 4, 999,
        );

        // Apply in both orders — should converge
        let mut state_ab = state.clone();
        state_ab.apply_role_set(&role_a).unwrap();
        state_ab.apply_role_set(&role_b).unwrap();

        let mut state_ba = state.clone();
        state_ba.apply_role_set(&role_b).unwrap();
        state_ba.apply_role_set(&role_a).unwrap();

        let alice_device = DeviceID::from_pubkey(&alice_pub);
        let role_ab = state_ab.get_active_member(&alice_device).unwrap().role;
        let role_ba = state_ba.get_active_member(&alice_device).unwrap().role;
        assert_eq!(role_ab, role_ba);
    }

    // -------------------------------------------------------------------
    // Error cases
    // -------------------------------------------------------------------

    #[test]
    fn test_invite_already_active_rejected() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite.op_id, 3, 300,
            ))
            .unwrap();

        // Double-invite while active — should fail
        let invite2 = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 4, 400, Role::Admin,
        );
        let err = state.apply_member_invite(&invite2).unwrap_err();
        assert!(matches!(err, MembershipError::AlreadyActiveMember));
    }

    #[test]
    fn test_accept_wrong_invite_rejected() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();

        let bogus_op_id = OpID::new(DeviceID::from_bytes([0xFF; 16]), 99, 99);
        let bad_accept = make_accept(gid, alice_pub, &alice_priv, bogus_op_id, 3, 300);
        let err = state.apply_member_accept(&bad_accept).unwrap_err();
        assert!(matches!(err, MembershipError::AcceptInviteMismatch));
    }

    #[test]
    fn test_double_accept_rejected() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();

        let accept = make_accept(gid, alice_pub, &alice_priv, invite.op_id, 3, 300);
        state.apply_member_accept(&accept).unwrap();

        let accept2 = make_accept(gid, alice_pub, &alice_priv, invite.op_id, 4, 400);
        let err = state.apply_member_accept(&accept2).unwrap_err();
        assert!(matches!(err, MembershipError::AlreadyAccepted));
    }

    #[test]
    fn test_double_remove_rejected() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite.op_id, 3, 300,
            ))
            .unwrap();

        let kick = make_remove(
            gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 4, 400,
        );
        state.apply_member_remove(&kick).unwrap();

        let kick2 = make_remove(
            gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 5, 500,
        );
        let err = state.apply_member_remove(&kick2).unwrap_err();
        assert!(matches!(err, MembershipError::AlreadyRemoved));
    }

    #[test]
    fn test_leave_wrong_author_rejected() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite.op_id, 3, 300,
            ))
            .unwrap();

        // Owner tries to "leave" Alice — author != target
        let bad_leave = make_remove(
            gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Leave, 4, 400,
        );
        let err = state.apply_member_remove(&bad_leave).unwrap_err();
        assert!(matches!(err, MembershipError::LeaveAuthorMismatch));
    }

    #[test]
    fn test_role_set_on_inactive_rejected() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, _) = keypair();
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        // Alice never accepts

        let role_op = make_role_set(
            gid, owner_pub, &owner_priv, alice_pub, Role::Admin, 3, 300,
        );
        let err = state.apply_role_set(&role_op).unwrap_err();
        assert!(matches!(err, MembershipError::TargetNotActive));
    }

    // -------------------------------------------------------------------
    // Rendering gate
    // -------------------------------------------------------------------

    #[test]
    fn test_is_author_active_for_render() {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let alice_device = DeviceID::from_pubkey(&alice_pub);

        // Before invite
        assert!(!state.is_author_active_for_render(&alice_device));

        // Invited but not accepted
        let invite = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member,
        );
        state.apply_member_invite(&invite).unwrap();
        assert!(!state.is_author_active_for_render(&alice_device));

        // Accepted
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite.op_id, 3, 300,
            ))
            .unwrap();
        assert!(state.is_author_active_for_render(&alice_device));

        // Kicked
        let kick = make_remove(
            gid, owner_pub, &owner_priv, alice_pub, RemoveReason::Kick, 4, 400,
        );
        state.apply_member_remove(&kick).unwrap();
        assert!(!state.is_author_active_for_render(&alice_device));

        // Re-invited + accepted → active again
        let invite2 = make_invite(
            gid, owner_pub, &owner_priv, alice_pub, 5, 500, Role::Member,
        );
        state.apply_member_invite(&invite2).unwrap();
        state
            .apply_member_accept(&make_accept(
                gid, alice_pub, &alice_priv, invite2.op_id, 6, 600,
            ))
            .unwrap();
        assert!(state.is_author_active_for_render(&alice_device));
    }
}
