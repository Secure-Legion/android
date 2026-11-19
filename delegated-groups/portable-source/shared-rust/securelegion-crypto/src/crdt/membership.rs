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
use crate::crdt::metadata::MetadataState;
use crate::crdt::ops::{
    AdminRights, GroupCreatePayload, MemberAcceptPayload, MemberInvitePayload,
    MemberRemovePayload, MemberUnbanPayload, MetadataKey, OpEnvelope, OpType, RemoveReason,
    Role, RoleSetPayload,
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

    #[error("Owner cannot be removed")]
    OwnerCannotBeRemoved,

    #[error("Owner role is immutable")]
    OwnerRoleImmutable,

    #[error("custom_title exceeds 32 bytes")]
    CustomTitleTooLong,

    #[error("Admin cannot grant rights they don't hold")]
    CannotGrantUnheldRights,

    #[error("User is banned from this group")]
    UserBanned,

    #[error("Target is not banned")]
    NotBanned,
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
    /// Per-admin rights bitfield. `Some` iff role == Admin. Owner has all
    /// rights implicitly (stored as None); Member consults group metadata.
    pub admin_rights: Option<AdminRights>,
    /// Optional free-text title (max 32 bytes) shown next to the admin's name.
    pub custom_title: Option<String>,
    /// DeviceID of the admin/owner who promoted this member (attribution).
    pub promoted_by: Option<DeviceID>,
    /// True if the member was removed with ban=true — prevents re-invite.
    pub banned: bool,
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
            admin_rights: None,
            custom_title: None,
            promoted_by: None,
            banned: false,
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
            // Banned users cannot be re-invited until unbanned.
            if existing.banned {
                return Err(MembershipError::UserBanned);
            }
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
            admin_rights: if payload.role == Role::Admin { Some(AdminRights::all_true()) } else { None },
            custom_title: None,
            promoted_by: None,
            banned: false,
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

        // Owner is immutable — cannot be removed by anyone.
        if target.role == Role::Owner {
            return Err(MembershipError::OwnerCannotBeRemoved);
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

                // Mark target as removed (and banned if the op requested it)
                let target_mut = self.members.get_mut(&target_device).unwrap();
                target_mut.removed = true;
                target_mut.remove_op = Some(op.op_id);
                if payload.ban {
                    target_mut.banned = true;
                }

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

    /// Apply a MemberUnban op. Clears the banned flag; membership is
    /// otherwise unchanged (target remains `removed = true`). Authorization
    /// is handled by `can_author_op` (requires `can_remove` admin right).
    pub fn apply_member_unban(&mut self, op: &OpEnvelope) -> Result<(), MembershipError> {
        let payload: MemberUnbanPayload = op
            .decode_payload()
            .map_err(|e| MembershipError::PayloadDecode(e.to_string()))?;

        let target = self
            .members
            .get_mut(&payload.target_device_id)
            .ok_or(MembershipError::TargetNotFound)?;
        if !target.banned {
            return Err(MembershipError::NotBanned);
        }
        target.banned = false;
        Ok(())
    }

    /// Apply a RoleSet op. LWW: higher lamport wins, tie-break by OpID.
    pub fn apply_role_set(&mut self, op: &OpEnvelope) -> Result<(), MembershipError> {
        let payload: RoleSetPayload = op
            .decode_payload()
            .map_err(|e| MembershipError::PayloadDecode(e.to_string()))?;

        // Validate custom_title length (max 32 bytes).
        if let Some(title) = &payload.custom_title {
            if title.as_bytes().len() > 32 {
                return Err(MembershipError::CustomTitleTooLong);
            }
        }

        let author_device = DeviceID::from_pubkey(&op.author_pubkey);

        // Target must be active
        {
            let target = self
                .members
                .get(&payload.target_device_id)
                .ok_or(MembershipError::TargetNotFound)?;

            if !target.accepted || target.removed {
                return Err(MembershipError::TargetNotActive);
            }

            // Owner role is immutable — no one (not even Owner) can change it.
            if target.role == Role::Owner && payload.new_role != Role::Owner {
                return Err(MembershipError::OwnerRoleImmutable);
            }

            // LWW: ignore if this op is dominated by the current role setter
            let dominated = op.lamport < target.role_lamport
                || (op.lamport == target.role_lamport && op.op_id < target.role_op);
            if dominated {
                return Ok(()); // silently ignore stale role set
            }
        }

        // Privilege-escalation guard: an Admin author can only grant rights
        // they themselves hold. Owners bypass this check.
        if payload.new_role == Role::Admin {
            if let Some(author) = self.get_active_member(&author_device) {
                if author.role == Role::Admin {
                    let author_rights = author.admin_rights.unwrap_or(AdminRights::all_false());
                    let granted = payload.admin_rights.unwrap_or(AdminRights::all_false());
                    let escalates = (granted.can_invite && !author_rights.can_invite)
                        || (granted.can_remove && !author_rights.can_remove)
                        || (granted.can_change_info && !author_rights.can_change_info)
                        || (granted.can_delete_messages && !author_rights.can_delete_messages)
                        || (granted.can_pin_messages && !author_rights.can_pin_messages)
                        || (granted.can_add_admins && !author_rights.can_add_admins);
                    if escalates {
                        return Err(MembershipError::CannotGrantUnheldRights);
                    }
                }
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
        target.promoted_by = Some(author_device);

        // Rights + title only stored on Admin role; other roles clear them.
        if payload.new_role == Role::Admin {
            target.admin_rights = payload.admin_rights.or(Some(AdminRights::all_false()));
            target.custom_title = payload.custom_title;
        } else {
            target.admin_rights = None;
            target.custom_title = None;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Query functions
    // -----------------------------------------------------------------------

    /// Check if a device is authorized to create the given op type.
    ///
    /// General gate — specific apply functions may do additional checks
    /// (e.g., kick role comparison, accept invite matching).
    pub fn can_author_op(
        &self,
        device_id: &DeviceID,
        op_type: &OpType,
        metadata: &MetadataState,
    ) -> bool {
        let Some(member) = self.get_active_member(device_id) else {
            // Non-active devices can only author MemberAccept
            return matches!(op_type, OpType::MemberAccept);
        };

        // Owner has all rights (except GroupCreate, which is only the first op).
        if member.role == Role::Owner {
            return !matches!(op_type, OpType::GroupCreate);
        }

        // Admin: check per-admin bitfield for privileged ops. Regular
        // message/reaction ops are allowed to all non-ReadOnly members below.
        if member.role == Role::Admin {
            let rights = member.admin_rights.unwrap_or(AdminRights::all_false());
            match op_type {
                OpType::MemberInvite => return rights.can_invite,
                OpType::MemberRemove | OpType::MemberUnban => return rights.can_remove,
                OpType::RoleSet => return rights.can_add_admins,
                // Admins with can_change_info can always edit group info/permissions,
                // overriding the member-tier metadata toggle.
                OpType::MetadataSet => return rights.can_change_info,
                // MsgDelete by admins uses can_delete_messages; authors can
                // always delete their own via apply_msg_delete's separate check.
                OpType::MsgDelete => return rights.can_delete_messages,
                // Admins can always send messages/reactions — member-tier
                // broadcast-mode toggle only gates plain Members.
                OpType::MsgAdd | OpType::MsgEdit | OpType::ReactionSet => return true,
                // GroupCreate is first-op-only; GroupDelete is Owner-only.
                OpType::GroupCreate | OpType::GroupDelete => return false,
                OpType::MemberAccept => return true,
            }
        }

        // Member / ReadOnly: consult group metadata for tier-level toggles.
        // ReadOnly always blocked from write ops; Member defaults match plan.
        if member.role == Role::ReadOnly {
            return matches!(op_type, OpType::MemberAccept);
        }

        match op_type {
            // Default send ON so empty metadata still permits messaging.
            OpType::MsgAdd | OpType::MsgEdit | OpType::MsgDelete | OpType::ReactionSet =>
                metadata.get_bool(MetadataKey::AllowMemberSendMessages).unwrap_or(true),
            // Default OFF — admins must grant these explicitly.
            OpType::MemberInvite =>
                metadata.get_bool(MetadataKey::AllowMemberInvites).unwrap_or(false),
            OpType::MetadataSet =>
                metadata.get_bool(MetadataKey::AllowMemberChangeInfo).unwrap_or(false),
            OpType::MemberRemove | OpType::MemberUnban | OpType::RoleSet
                | OpType::GroupCreate | OpType::GroupDelete => false,
            OpType::MemberAccept => true,
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
            ban: false,
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
            admin_rights: if new_role == Role::Admin { Some(AdminRights::all_true()) } else { None },
            custom_title: None,
        };
        OpEnvelope::create_signed(
            gid, OpType::RoleSet, &payload, lamport, nonce, author_pub, author_priv,
        )
        .unwrap()
    }

    fn make_role_set_full(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        target_pub: [u8; 32],
        new_role: Role,
        admin_rights: Option<AdminRights>,
        custom_title: Option<String>,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let target_device = DeviceID::from_pubkey(&target_pub);
        let payload = RoleSetPayload { target_device_id: target_device, new_role, admin_rights, custom_title };
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
                admin_rights: None,
                custom_title: None,
                promoted_by: None,
                banned: false,
                role_lamport: 2,
                role_op: owner_op_id,
            },
        );

        assert!(state.can_author_op(&alice_device, &OpType::MsgAdd, &MetadataState::new()));
        assert!(state.can_author_op(&alice_device, &OpType::ReactionSet, &MetadataState::new()));
        assert!(!state.can_author_op(&alice_device, &OpType::MemberInvite, &MetadataState::new()));
        assert!(!state.can_author_op(&alice_device, &OpType::MemberRemove, &MetadataState::new()));
        assert!(!state.can_author_op(&alice_device, &OpType::RoleSet, &MetadataState::new()));
        assert!(!state.can_author_op(&alice_device, &OpType::MetadataSet, &MetadataState::new()));
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
                admin_rights: None,
                custom_title: None,
                promoted_by: None,
                banned: false,
                role_lamport: 2,
                role_op: owner_op_id,
            },
        );

        assert!(!state.can_author_op(&ro_device, &OpType::MsgAdd, &MetadataState::new()));
        assert!(!state.can_author_op(&ro_device, &OpType::MsgEdit, &MetadataState::new()));
        assert!(!state.can_author_op(&ro_device, &OpType::MsgDelete, &MetadataState::new()));
        assert!(!state.can_author_op(&ro_device, &OpType::ReactionSet, &MetadataState::new()));
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
                admin_rights: Some(AdminRights::all_true()),
                custom_title: None,
                promoted_by: None,
                banned: false,
                role_lamport: 2,
                role_op: owner_op_id,
            },
        );

        assert!(state.can_author_op(&admin_device, &OpType::MemberInvite, &MetadataState::new()));
        assert!(state.can_author_op(&admin_device, &OpType::MemberRemove, &MetadataState::new()));
        assert!(state.can_author_op(&admin_device, &OpType::MetadataSet, &MetadataState::new()));
        assert!(state.can_author_op(&admin_device, &OpType::MsgAdd, &MetadataState::new()));
    }

    #[test]
    fn test_non_member_can_only_accept() {
        let state = MembershipState::new();
        let (stranger_pub, _) = keypair();
        let stranger_device = DeviceID::from_pubkey(&stranger_pub);

        assert!(state.can_author_op(&stranger_device, &OpType::MemberAccept, &MetadataState::new()));
        assert!(!state.can_author_op(&stranger_device, &OpType::MsgAdd, &MetadataState::new()));
        assert!(!state.can_author_op(&stranger_device, &OpType::MemberInvite, &MetadataState::new()));
        assert!(!state.can_author_op(&stranger_device, &OpType::GroupCreate, &MetadataState::new()));
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

        // Admin tries to kick Owner — should fail (Owner is immutable)
        let kick = make_remove(
            gid, admin_pub, &admin_priv, owner_pub, RemoveReason::Kick, 4, 400,
        );
        let err = state.apply_member_remove(&kick).unwrap_err();
        assert!(matches!(err, MembershipError::OwnerCannotBeRemoved));
    }

    #[test]
    fn test_owner_cannot_leave_via_remove() {
        // Owner tries to Leave (remove themselves) — should still fail.
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let leave = make_remove(
            gid, owner_pub, &owner_priv, owner_pub, RemoveReason::Leave, 2, 200,
        );
        let err = state.apply_member_remove(&leave).unwrap_err();
        assert!(matches!(err, MembershipError::OwnerCannotBeRemoved));
    }

    #[test]
    fn test_owner_role_cannot_be_demoted() {
        // Even the Owner themselves trying to demote to Admin must fail.
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let role_op = make_role_set(
            gid, owner_pub, &owner_priv, owner_pub, Role::Admin, 2, 200,
        );
        let err = state.apply_role_set(&role_op).unwrap_err();
        assert!(matches!(err, MembershipError::OwnerRoleImmutable));
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

    // -------------------------------------------------------------------
    // Phase 2: admin rights bitfield + promote attribution
    // -------------------------------------------------------------------

    /// Helper: set up owner + accepted member. Returns (state, gid, owner_pub, owner_priv, member_pub, member_priv).
    fn setup_owner_and_member() -> (MembershipState, GroupID, [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (member_pub, member_priv) = keypair();
        let invite = make_invite(gid, owner_pub, &owner_priv, member_pub, 2, 200, Role::Member);
        state.apply_member_invite(&invite).unwrap();
        state
            .apply_member_accept(&make_accept(gid, member_pub, &member_priv, invite.op_id, 3, 300))
            .unwrap();
        (state, gid, owner_pub, owner_priv, member_pub, member_priv)
    }

    #[test]
    fn test_role_set_records_rights_title_and_promoted_by() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);
        let owner_device = DeviceID::from_pubkey(&owner_pub);

        let rights = AdminRights {
            can_invite: true, can_remove: false, can_change_info: true,
            can_delete_messages: false, can_pin_messages: true, can_add_admins: false,
        };
        let role_op = make_role_set_full(
            gid, owner_pub, &owner_priv, member_pub, Role::Admin,
            Some(rights), Some("Moderator".to_string()), 4, 400,
        );
        state.apply_role_set(&role_op).unwrap();

        let entry = state.members.get(&member_device).unwrap();
        assert_eq!(entry.role, Role::Admin);
        assert_eq!(entry.admin_rights, Some(rights));
        assert_eq!(entry.custom_title, Some("Moderator".to_string()));
        assert_eq!(entry.promoted_by, Some(owner_device));
    }

    #[test]
    fn test_role_set_demote_clears_rights_and_title() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        // Promote first
        let promote = make_role_set_full(
            gid, owner_pub, &owner_priv, member_pub, Role::Admin,
            Some(AdminRights::all_true()), Some("Boss".to_string()), 4, 400,
        );
        state.apply_role_set(&promote).unwrap();

        // Now demote back to Member
        let demote = make_role_set_full(
            gid, owner_pub, &owner_priv, member_pub, Role::Member, None, None, 5, 500,
        );
        state.apply_role_set(&demote).unwrap();

        let entry = state.members.get(&member_device).unwrap();
        assert_eq!(entry.role, Role::Member);
        assert_eq!(entry.admin_rights, None);
        assert_eq!(entry.custom_title, None);
    }

    #[test]
    fn test_role_set_custom_title_too_long_rejected() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();

        // 33-byte title (over 32-byte cap)
        let long_title = "x".repeat(33);
        let role_op = make_role_set_full(
            gid, owner_pub, &owner_priv, member_pub, Role::Admin,
            Some(AdminRights::all_true()), Some(long_title), 4, 400,
        );
        let err = state.apply_role_set(&role_op).unwrap_err();
        assert!(matches!(err, MembershipError::CustomTitleTooLong));
    }

    #[test]
    fn test_can_author_op_admin_with_invite_right() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        let rights = AdminRights { can_invite: true, ..AdminRights::all_false() };
        let promote = make_role_set_full(
            gid, owner_pub, &owner_priv, member_pub, Role::Admin, Some(rights), None, 4, 400,
        );
        state.apply_role_set(&promote).unwrap();

        assert!(state.can_author_op(&member_device, &OpType::MemberInvite, &MetadataState::new()));
        assert!(!state.can_author_op(&member_device, &OpType::MemberRemove, &MetadataState::new()));
        assert!(!state.can_author_op(&member_device, &OpType::RoleSet, &MetadataState::new()));
        assert!(!state.can_author_op(&member_device, &OpType::MetadataSet, &MetadataState::new()));
        assert!(!state.can_author_op(&member_device, &OpType::MsgDelete, &MetadataState::new()));
        // Regular msg ops always allowed for Admins
        assert!(state.can_author_op(&member_device, &OpType::MsgAdd, &MetadataState::new()));
        assert!(state.can_author_op(&member_device, &OpType::ReactionSet, &MetadataState::new()));
    }

    #[test]
    fn test_can_author_op_admin_without_invite_right() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        let promote = make_role_set_full(
            gid, owner_pub, &owner_priv, member_pub, Role::Admin,
            Some(AdminRights::all_false()), None, 4, 400,
        );
        state.apply_role_set(&promote).unwrap();

        assert!(!state.can_author_op(&member_device, &OpType::MemberInvite, &MetadataState::new()));
    }

    #[test]
    fn test_owner_can_author_all_non_groupcreate_ops() {
        let (state, _, owner_pub, _, _, _) = setup_owner_and_member();
        let owner_device = DeviceID::from_pubkey(&owner_pub);

        for op in &[OpType::MemberInvite, OpType::MemberRemove, OpType::RoleSet,
                    OpType::MetadataSet, OpType::MsgAdd, OpType::MsgEdit,
                    OpType::MsgDelete, OpType::ReactionSet, OpType::MemberAccept] {
            assert!(state.can_author_op(&owner_device, op, &MetadataState::new()), "Owner should author {:?}", op);
        }
        assert!(!state.can_author_op(&owner_device, &OpType::GroupCreate, &MetadataState::new()));
    }

    #[test]
    fn test_admin_cannot_grant_rights_they_lack() {
        // Set up: Owner promotes Alice to Admin with only can_add_admins=true.
        // Alice then tries to promote Bob with can_remove=true → should fail.
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let alice_invite = make_invite(gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member);
        state.apply_member_invite(&alice_invite).unwrap();
        state
            .apply_member_accept(&make_accept(gid, alice_pub, &alice_priv, alice_invite.op_id, 3, 300))
            .unwrap();

        let alice_limited = AdminRights { can_add_admins: true, ..AdminRights::all_false() };
        let alice_promote = make_role_set_full(
            gid, owner_pub, &owner_priv, alice_pub, Role::Admin, Some(alice_limited), None, 4, 400,
        );
        state.apply_role_set(&alice_promote).unwrap();

        // Add Bob as plain Member
        let (bob_pub, bob_priv) = keypair();
        let bob_invite = make_invite(gid, owner_pub, &owner_priv, bob_pub, 5, 500, Role::Member);
        state.apply_member_invite(&bob_invite).unwrap();
        state
            .apply_member_accept(&make_accept(gid, bob_pub, &bob_priv, bob_invite.op_id, 6, 600))
            .unwrap();

        // Alice (admin, can_add_admins only) tries to grant Bob can_remove → fail
        let bob_promote = make_role_set_full(
            gid, alice_pub, &alice_priv, bob_pub, Role::Admin,
            Some(AdminRights { can_remove: true, ..AdminRights::all_false() }),
            None, 7, 700,
        );
        let err = state.apply_role_set(&bob_promote).unwrap_err();
        assert!(matches!(err, MembershipError::CannotGrantUnheldRights));
    }

    // -------------------------------------------------------------------
    // Phase 4: banned users list
    // -------------------------------------------------------------------

    fn make_remove_ban(
        gid: GroupID, author_pub: [u8; 32], author_priv: &[u8; 32],
        target_pub: [u8; 32], lamport: u64, nonce: u64,
    ) -> OpEnvelope {
        let payload = MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&target_pub),
            reason: RemoveReason::Kick,
            ban: true,
        };
        OpEnvelope::create_signed(
            gid, OpType::MemberRemove, &payload, lamport, nonce, author_pub, author_priv,
        ).unwrap()
    }

    fn make_unban(
        gid: GroupID, author_pub: [u8; 32], author_priv: &[u8; 32],
        target_pub: [u8; 32], lamport: u64, nonce: u64,
    ) -> OpEnvelope {
        let payload = MemberUnbanPayload {
            target_device_id: DeviceID::from_pubkey(&target_pub),
        };
        OpEnvelope::create_signed(
            gid, OpType::MemberUnban, &payload, lamport, nonce, author_pub, author_priv,
        ).unwrap()
    }

    #[test]
    fn test_banned_user_cannot_be_reinvited() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        // Owner kicks + bans
        let ban = make_remove_ban(gid, owner_pub, &owner_priv, member_pub, 4, 400);
        state.apply_member_remove(&ban).unwrap();
        assert!(state.members.get(&member_device).unwrap().banned);

        // Re-invite should fail
        let reinvite = make_invite(gid, owner_pub, &owner_priv, member_pub, 5, 500, Role::Member);
        let err = state.apply_member_invite(&reinvite).unwrap_err();
        assert!(matches!(err, MembershipError::UserBanned));
    }

    #[test]
    fn test_unban_then_reinvite_works() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, member_priv) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        // Ban, then unban
        let ban = make_remove_ban(gid, owner_pub, &owner_priv, member_pub, 4, 400);
        state.apply_member_remove(&ban).unwrap();
        let unban = make_unban(gid, owner_pub, &owner_priv, member_pub, 5, 500);
        state.apply_member_unban(&unban).unwrap();
        assert!(!state.members.get(&member_device).unwrap().banned);
        // Still removed (unban doesn't restore membership)
        assert!(state.members.get(&member_device).unwrap().removed);

        // Re-invite now succeeds (and must supersede the remove op)
        let reinvite = make_invite(gid, owner_pub, &owner_priv, member_pub, 6, 600, Role::Member);
        state.apply_member_invite(&reinvite).unwrap();
        // Accept to re-activate
        state
            .apply_member_accept(&make_accept(gid, member_pub, &member_priv, reinvite.op_id, 7, 700))
            .unwrap();
        assert!(state.get_active_member(&member_device).is_some());
    }

    #[test]
    fn test_unban_on_non_banned_rejected() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let unban = make_unban(gid, owner_pub, &owner_priv, member_pub, 4, 400);
        let err = state.apply_member_unban(&unban).unwrap_err();
        assert!(matches!(err, MembershipError::NotBanned));
    }

    #[test]
    fn test_kick_without_ban_does_not_set_banned() {
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);
        // Standard kick (ban=false by default in make_remove helper)
        let kick = make_remove(gid, owner_pub, &owner_priv, member_pub, RemoveReason::Kick, 4, 400);
        state.apply_member_remove(&kick).unwrap();
        let entry = state.members.get(&member_device).unwrap();
        assert!(entry.removed);
        assert!(!entry.banned);
    }

    // -------------------------------------------------------------------
    // Phase 3: member-tier group permissions via MetadataState
    // -------------------------------------------------------------------

    fn md_with_bool(key: MetadataKey, value: bool) -> MetadataState {
        use crate::crdt::ops::MetadataSetPayload;
        // Build a MetadataState by applying a synthetic MetadataSet op.
        let (pub_k, priv_k) = keypair();
        let (create_op, gid, _, _) = make_group_create();
        let mut md = MetadataState::new();
        let payload = MetadataSetPayload { key, value: vec![if value { 1u8 } else { 0u8 }] };
        let op = OpEnvelope::create_signed(
            gid, OpType::MetadataSet, &payload, 2, 200, pub_k, &priv_k,
        ).unwrap();
        md.apply_metadata_set(&op).unwrap();
        let _ = create_op; // silence unused
        md
    }

    #[test]
    fn test_member_can_invite_when_group_allows_it() {
        let (state, _, _, _, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        // Default (no metadata): member cannot invite
        let empty = MetadataState::new();
        assert!(!state.can_author_op(&member_device, &OpType::MemberInvite, &empty));

        // Owner flips allow_member_invites=true
        let md = md_with_bool(MetadataKey::AllowMemberInvites, true);
        assert!(state.can_author_op(&member_device, &OpType::MemberInvite, &md));
    }

    #[test]
    fn test_member_cannot_send_when_broadcast_mode_on() {
        let (state, _, _, _, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        // Default: member CAN send (AllowMemberSendMessages defaults to true)
        let empty = MetadataState::new();
        assert!(state.can_author_op(&member_device, &OpType::MsgAdd, &empty));

        // Owner flips to false → admins-only broadcast mode
        let md = md_with_bool(MetadataKey::AllowMemberSendMessages, false);
        assert!(!state.can_author_op(&member_device, &OpType::MsgAdd, &md));
        assert!(!state.can_author_op(&member_device, &OpType::MsgEdit, &md));
        assert!(!state.can_author_op(&member_device, &OpType::ReactionSet, &md));
    }

    #[test]
    fn test_admin_bypasses_member_broadcast_mode() {
        // Admins (with can_change_info or msg ops) are never affected by member-tier
        // metadata toggles. Broadcast mode only silences plain Members.
        let (mut state, gid, owner_pub, owner_priv, member_pub, _) = setup_owner_and_member();
        let member_device = DeviceID::from_pubkey(&member_pub);

        // Promote member to Admin with all rights
        let promote = make_role_set_full(
            gid, owner_pub, &owner_priv, member_pub, Role::Admin,
            Some(AdminRights::all_true()), None, 4, 400,
        );
        state.apply_role_set(&promote).unwrap();

        // Even with broadcast mode on, admin can post
        let md = md_with_bool(MetadataKey::AllowMemberSendMessages, false);
        assert!(state.can_author_op(&member_device, &OpType::MsgAdd, &md));
    }

    #[test]
    fn test_owner_bypasses_all_member_toggles() {
        let (state, _, owner_pub, _, _, _) = setup_owner_and_member();
        let owner_device = DeviceID::from_pubkey(&owner_pub);
        // Broadcast mode blocking EVERYONE — owner still posts
        let md = md_with_bool(MetadataKey::AllowMemberSendMessages, false);
        assert!(state.can_author_op(&owner_device, &OpType::MsgAdd, &md));
    }

    #[test]
    fn test_admin_can_grant_subset_of_own_rights() {
        // Owner promotes Alice with can_invite + can_add_admins.
        // Alice can promote Bob with can_invite (subset).
        let mut state = MembershipState::new();
        let (create_op, gid, owner_pub, owner_priv) = make_group_create();
        state.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let alice_invite = make_invite(gid, owner_pub, &owner_priv, alice_pub, 2, 200, Role::Member);
        state.apply_member_invite(&alice_invite).unwrap();
        state
            .apply_member_accept(&make_accept(gid, alice_pub, &alice_priv, alice_invite.op_id, 3, 300))
            .unwrap();

        let alice_rights = AdminRights { can_invite: true, can_add_admins: true, ..AdminRights::all_false() };
        let alice_promote = make_role_set_full(
            gid, owner_pub, &owner_priv, alice_pub, Role::Admin, Some(alice_rights), None, 4, 400,
        );
        state.apply_role_set(&alice_promote).unwrap();

        let (bob_pub, bob_priv) = keypair();
        let bob_invite = make_invite(gid, owner_pub, &owner_priv, bob_pub, 5, 500, Role::Member);
        state.apply_member_invite(&bob_invite).unwrap();
        state
            .apply_member_accept(&make_accept(gid, bob_pub, &bob_priv, bob_invite.op_id, 6, 600))
            .unwrap();

        // Alice grants Bob can_invite (subset of her rights) → succeeds
        let bob_promote = make_role_set_full(
            gid, alice_pub, &alice_priv, bob_pub, Role::Admin,
            Some(AdminRights { can_invite: true, ..AdminRights::all_false() }),
            None, 7, 700,
        );
        state.apply_role_set(&bob_promote).unwrap();

        let bob_device = DeviceID::from_pubkey(&bob_pub);
        assert_eq!(state.members.get(&bob_device).unwrap().role, Role::Admin);
    }
}
