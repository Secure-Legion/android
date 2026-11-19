/// Message CRDT — add, edit, delete, and react to messages.
///
/// Messages are stored as immutable entries keyed by `msg_id`. Edits use LWW
/// (Last-Writer-Wins) semantics by lamport with OpID tie-break. Deletes are
/// permanent tombstones — once deleted, edits are silently ignored.
///
/// Reactions are a per-(device, emoji) map with boolean present/absent state.

use std::collections::BTreeMap;
use thiserror::Error;

use crate::crdt::ids::{DeviceID, OpID};
use crate::crdt::membership::MembershipState;
use crate::crdt::ops::{
    MsgAddPayload, MsgDeletePayload, MsgEditPayload, OpEnvelope, ReactionSetPayload, Role,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("Message with this msg_id already exists")]
    MessageAlreadyExists,

    #[error("Message not found: {0}")]
    MessageNotFound(String),

    #[error("Only the original author can edit this message")]
    NotMessageAuthor,

    #[error("Not authorized to delete this message")]
    DeleteNotAuthorized,

    #[error("Message already deleted")]
    AlreadyDeleted,

    #[error("Payload decode error: {0}")]
    PayloadDecode(String),
}

// ---------------------------------------------------------------------------
// MessageEntry
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MessageEntry {
    pub msg_id: [u8; 32],
    pub author: DeviceID,
    /// The MsgAdd op that created this message.
    pub create_op: OpID,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    /// Wall-clock timestamp from the create op (UX only).
    pub timestamp_ms: u64,
    /// Tombstone flag — once true, edits are silently ignored.
    pub deleted: bool,
    /// Lamport of the last applied edit (for LWW).
    pub last_edit_lamport: u64,
    /// OpID of the last applied edit (for LWW tie-break).
    pub last_edit_op: Option<OpID>,
    /// Reactions: (reactor DeviceID, emoji string) → present.
    pub reactions: BTreeMap<(DeviceID, String), bool>,
}

// ---------------------------------------------------------------------------
// MessageState
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MessageState {
    pub(crate) messages: BTreeMap<[u8; 32], MessageEntry>,
}

impl MessageState {
    pub fn new() -> Self {
        MessageState {
            messages: BTreeMap::new(),
        }
    }

    /// Read-only access to the message map.
    pub fn messages(&self) -> &BTreeMap<[u8; 32], MessageEntry> {
        &self.messages
    }

    /// Get a message by its msg_id.
    pub fn get_message(&self, msg_id: &[u8; 32]) -> Option<&MessageEntry> {
        self.messages.get(msg_id)
    }

    /// Total message count (including tombstoned).
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    // -----------------------------------------------------------------------
    // Apply functions
    // -----------------------------------------------------------------------

    /// Apply a MsgAdd op. Creates a new MessageEntry if msg_id not already seen.
    ///
    /// The op is always stored (idempotent skip if duplicate). Rendering is
    /// gated by membership state separately (in Phase 3's `renderable_messages`).
    pub fn apply_msg_add(&mut self, op: &OpEnvelope) -> Result<(), MessageError> {
        let payload: MsgAddPayload = op
            .decode_payload()
            .map_err(|e| MessageError::PayloadDecode(e.to_string()))?;

        // Idempotent: skip if msg_id already exists
        if self.messages.contains_key(&payload.msg_id) {
            return Ok(());
        }

        let author = DeviceID::from_pubkey(&op.author_pubkey);

        let entry = MessageEntry {
            msg_id: payload.msg_id,
            author,
            create_op: op.op_id,
            ciphertext: payload.ciphertext,
            nonce: payload.nonce,
            timestamp_ms: op.timestamp_ms,
            deleted: false,
            last_edit_lamport: op.lamport,
            last_edit_op: None,
            reactions: BTreeMap::new(),
        };

        self.messages.insert(payload.msg_id, entry);
        Ok(())
    }

    /// Apply a MsgEdit op. LWW: only applies if this op supersedes the last edit.
    ///
    /// - Author must be the original message author.
    /// - Silently ignored if the message is deleted (tombstone is permanent).
    /// - Silently ignored if this op is dominated by a newer edit.
    pub fn apply_msg_edit(&mut self, op: &OpEnvelope) -> Result<(), MessageError> {
        let payload: MsgEditPayload = op
            .decode_payload()
            .map_err(|e| MessageError::PayloadDecode(e.to_string()))?;

        let msg = self
            .messages
            .get(&payload.msg_id)
            .ok_or_else(|| MessageError::MessageNotFound(hex::encode(payload.msg_id)))?;

        // Only the original author can edit
        let author = DeviceID::from_pubkey(&op.author_pubkey);
        if author != msg.author {
            return Err(MessageError::NotMessageAuthor);
        }

        // Deleted messages ignore edits (tombstone is permanent)
        if msg.deleted {
            return Ok(());
        }

        // LWW: only apply if this op supersedes the current edit
        let dominated = op.lamport < msg.last_edit_lamport
            || (op.lamport == msg.last_edit_lamport
                && match &msg.last_edit_op {
                    Some(existing_op) => op.op_id <= *existing_op,
                    None => op.op_id <= msg.create_op,
                });

        if dominated {
            return Ok(()); // silently ignore stale edit
        }

        // Apply the edit
        let msg = self.messages.get_mut(&payload.msg_id).unwrap();
        msg.ciphertext = payload.new_ciphertext;
        msg.nonce = payload.nonce;
        msg.last_edit_lamport = op.lamport;
        msg.last_edit_op = Some(op.op_id);

        Ok(())
    }

    /// Apply a MsgDelete op. Tombstones the message permanently.
    ///
    /// - Author must be original message author OR an admin/owner (via membership).
    /// - Silently ignored if already deleted.
    pub fn apply_msg_delete(
        &mut self,
        op: &OpEnvelope,
        membership: &MembershipState,
    ) -> Result<(), MessageError> {
        let payload: MsgDeletePayload = op
            .decode_payload()
            .map_err(|e| MessageError::PayloadDecode(e.to_string()))?;

        let msg = self
            .messages
            .get(&payload.msg_id)
            .ok_or_else(|| MessageError::MessageNotFound(hex::encode(payload.msg_id)))?;

        // Already deleted — idempotent
        if msg.deleted {
            return Ok(());
        }

        let author = DeviceID::from_pubkey(&op.author_pubkey);

        // Authorization: original author can always delete their own messages.
        // Admin/Owner can delete anyone's messages.
        if author != msg.author {
            let is_privileged = membership
                .get_active_member(&author)
                .map(|m| m.role == Role::Owner || m.role == Role::Admin)
                .unwrap_or(false);

            if !is_privileged {
                return Err(MessageError::DeleteNotAuthorized);
            }
        }

        let msg = self.messages.get_mut(&payload.msg_id).unwrap();
        msg.deleted = true;

        Ok(())
    }

    /// Apply a ReactionSet op. Upserts (author, emoji) → present.
    ///
    /// Silently ignored if the message doesn't exist or is deleted.
    pub fn apply_reaction_set(&mut self, op: &OpEnvelope) -> Result<(), MessageError> {
        let payload: ReactionSetPayload = op
            .decode_payload()
            .map_err(|e| MessageError::PayloadDecode(e.to_string()))?;

        let msg = match self.messages.get_mut(&payload.msg_id) {
            Some(m) => m,
            None => return Ok(()), // message not seen yet — silently drop
        };

        // Skip reactions on deleted messages
        if msg.deleted {
            return Ok(());
        }

        let author = DeviceID::from_pubkey(&op.author_pubkey);
        msg.reactions.insert((author, payload.emoji), payload.present);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::ids::GroupID;
    use crate::crdt::membership::MembershipState;
    use crate::crdt::ops::{
        GroupCreatePayload, MemberAcceptPayload, MemberInvitePayload, OpEnvelope, OpType,
    };

    fn keypair() -> ([u8; 32], [u8; 32]) {
        crate::crypto::signing::generate_keypair()
    }

    fn test_group_id(pubkey: &[u8; 32]) -> GroupID {
        let creator = DeviceID::from_pubkey(pubkey);
        GroupID::new(&creator, &[0xBB; 32])
    }

    /// Helper: set up a group with owner + one active member, return everything needed.
    fn setup_group_with_member() -> (
        MembershipState,
        GroupID,
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        let (owner_pub, owner_priv) = keypair();
        let gid = test_group_id(&owner_pub);
        let mut membership = MembershipState::new();

        let create_payload = GroupCreatePayload {
            group_name: "Test".into(),
            encrypted_group_secret: vec![1, 2, 3],
        };
        let create_op = OpEnvelope::create_signed(
            gid,
            OpType::GroupCreate,
            &create_payload,
            1,
            100,
            owner_pub,
            &owner_priv,
        )
        .unwrap();
        membership.apply_group_create(&create_op).unwrap();

        let (alice_pub, alice_priv) = keypair();
        let alice_device = DeviceID::from_pubkey(&alice_pub);
        let invite_payload = MemberInvitePayload {
            invited_device_id: alice_device,
            invited_pubkey: alice_pub,
            role: Role::Member,
            encrypted_group_secret: vec![4, 5, 6],
        };
        let invite_op = OpEnvelope::create_signed(
            gid,
            OpType::MemberInvite,
            &invite_payload,
            2,
            200,
            owner_pub,
            &owner_priv,
        )
        .unwrap();
        membership.apply_member_invite(&invite_op).unwrap();

        let accept_payload = MemberAcceptPayload {
            invite_op_id: invite_op.op_id,
        };
        let accept_op = OpEnvelope::create_signed(
            gid,
            OpType::MemberAccept,
            &accept_payload,
            3,
            300,
            alice_pub,
            &alice_priv,
        )
        .unwrap();
        membership.apply_member_accept(&accept_op).unwrap();

        (membership, gid, owner_pub, owner_priv, alice_pub, alice_priv)
    }

    fn make_msg_add(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        msg_id: [u8; 32],
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MsgAddPayload {
            msg_id,
            ciphertext: vec![0xAA, 0xBB, 0xCC],
            nonce: [0x11; 24],
        };
        OpEnvelope::create_signed(
            gid,
            OpType::MsgAdd,
            &payload,
            lamport,
            nonce,
            author_pub,
            author_priv,
        )
        .unwrap()
    }

    fn make_msg_edit(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        msg_id: [u8; 32],
        new_ciphertext: Vec<u8>,
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MsgEditPayload {
            msg_id,
            new_ciphertext,
            nonce: [0x22; 24],
        };
        OpEnvelope::create_signed(
            gid,
            OpType::MsgEdit,
            &payload,
            lamport,
            nonce,
            author_pub,
            author_priv,
        )
        .unwrap()
    }

    fn make_msg_delete(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
        msg_id: [u8; 32],
        lamport: u64,
        nonce: u64,
    ) -> OpEnvelope {
        let payload = MsgDeletePayload { msg_id };
        OpEnvelope::create_signed(
            gid,
            OpType::MsgDelete,
            &payload,
            lamport,
            nonce,
            author_pub,
            author_priv,
        )
        .unwrap()
    }

    fn make_reaction(
        gid: GroupID,
        author_pub: [u8; 32],
        author_priv: &[u8; 32],
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
            author_pub,
            author_priv,
        )
        .unwrap()
    }

    // -------------------------------------------------------------------
    // MsgAdd
    // -------------------------------------------------------------------

    #[test]
    fn test_msg_add_creates_entry() {
        let (_membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x01; 32];
        let op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&op).unwrap();

        assert_eq!(messages.message_count(), 1);
        let msg = messages.get_message(&msg_id).unwrap();
        assert_eq!(msg.author, DeviceID::from_pubkey(&alice_pub));
        assert!(!msg.deleted);
        assert_eq!(msg.ciphertext, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_msg_add_duplicate_idempotent() {
        let (_membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x02; 32];
        let op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);

        messages.apply_msg_add(&op).unwrap();
        messages.apply_msg_add(&op).unwrap(); // duplicate — no error

        assert_eq!(messages.message_count(), 1);
    }

    // -------------------------------------------------------------------
    // MsgEdit — LWW
    // -------------------------------------------------------------------

    #[test]
    fn test_msg_edit_updates_content() {
        let (_membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x03; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        let edit_op = make_msg_edit(
            gid,
            alice_pub,
            &alice_priv,
            msg_id,
            vec![0xDD, 0xEE],
            5,
            500,
        );
        messages.apply_msg_edit(&edit_op).unwrap();

        let msg = messages.get_message(&msg_id).unwrap();
        assert_eq!(msg.ciphertext, vec![0xDD, 0xEE]);
        assert_eq!(msg.last_edit_lamport, 5);
        assert!(msg.last_edit_op.is_some());
    }

    #[test]
    fn test_msg_edit_stale_ignored() {
        let (_membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x04; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Edit at lamport=6
        let edit1 = make_msg_edit(
            gid,
            alice_pub,
            &alice_priv,
            msg_id,
            vec![0x11],
            6,
            600,
        );
        messages.apply_msg_edit(&edit1).unwrap();

        // Stale edit at lamport=5 — should be ignored
        let edit2 = make_msg_edit(
            gid,
            alice_pub,
            &alice_priv,
            msg_id,
            vec![0x22],
            5,
            500,
        );
        messages.apply_msg_edit(&edit2).unwrap();

        let msg = messages.get_message(&msg_id).unwrap();
        assert_eq!(msg.ciphertext, vec![0x11]); // unchanged
    }

    #[test]
    fn test_msg_edit_lww_tiebreak_converges() {
        let (_membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let msg_id = [0x05; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);

        // Two edits at same lamport, different nonces
        let edit_a = make_msg_edit(
            gid,
            alice_pub,
            &alice_priv,
            msg_id,
            vec![0xAA],
            5,
            100,
        );
        let edit_b = make_msg_edit(
            gid,
            alice_pub,
            &alice_priv,
            msg_id,
            vec![0xBB],
            5,
            999,
        );

        // Order A then B
        let mut state_ab = MessageState::new();
        state_ab.apply_msg_add(&add_op).unwrap();
        state_ab.apply_msg_edit(&edit_a).unwrap();
        state_ab.apply_msg_edit(&edit_b).unwrap();

        // Order B then A
        let mut state_ba = MessageState::new();
        state_ba.apply_msg_add(&add_op).unwrap();
        state_ba.apply_msg_edit(&edit_b).unwrap();
        state_ba.apply_msg_edit(&edit_a).unwrap();

        // Must converge
        assert_eq!(
            state_ab.get_message(&msg_id).unwrap().ciphertext,
            state_ba.get_message(&msg_id).unwrap().ciphertext,
        );
    }

    #[test]
    fn test_msg_edit_wrong_author_rejected() {
        let (_membership, gid, owner_pub, owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x06; 32];

        // Alice creates message
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Owner tries to edit Alice's message — should fail
        let edit_op = make_msg_edit(
            gid,
            owner_pub,
            &owner_priv,
            msg_id,
            vec![0xFF],
            5,
            500,
        );
        let err = messages.apply_msg_edit(&edit_op).unwrap_err();
        assert!(matches!(err, MessageError::NotMessageAuthor));
    }

    // -------------------------------------------------------------------
    // MsgDelete — tombstone
    // -------------------------------------------------------------------

    #[test]
    fn test_msg_delete_tombstones() {
        let (membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x07; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Alice deletes her own message
        let del_op = make_msg_delete(gid, alice_pub, &alice_priv, msg_id, 5, 500);
        messages.apply_msg_delete(&del_op, &membership).unwrap();

        let msg = messages.get_message(&msg_id).unwrap();
        assert!(msg.deleted);
    }

    #[test]
    fn test_msg_delete_by_admin() {
        let (membership, gid, owner_pub, owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x08; 32];

        // Alice creates message
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Owner deletes Alice's message — should succeed (Owner is privileged)
        let del_op = make_msg_delete(gid, owner_pub, &owner_priv, msg_id, 5, 500);
        messages.apply_msg_delete(&del_op, &membership).unwrap();

        assert!(messages.get_message(&msg_id).unwrap().deleted);
    }

    #[test]
    fn test_msg_delete_by_unprivileged_rejected() {
        let (membership, gid, owner_pub, owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x09; 32];

        // Owner creates message
        let add_op = make_msg_add(gid, owner_pub, &owner_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Alice (Member) tries to delete Owner's message — should fail
        let del_op = make_msg_delete(gid, alice_pub, &alice_priv, msg_id, 5, 500);
        let err = messages.apply_msg_delete(&del_op, &membership).unwrap_err();
        assert!(matches!(err, MessageError::DeleteNotAuthorized));
    }

    #[test]
    fn test_delete_wins_over_later_edit() {
        let (membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x0A; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Delete at lamport=5
        let del_op = make_msg_delete(gid, alice_pub, &alice_priv, msg_id, 5, 500);
        messages.apply_msg_delete(&del_op, &membership).unwrap();

        // Edit at lamport=6 (arrives after delete) — should be silently ignored
        let edit_op = make_msg_edit(
            gid,
            alice_pub,
            &alice_priv,
            msg_id,
            vec![0xFF],
            6,
            600,
        );
        messages.apply_msg_edit(&edit_op).unwrap(); // no error

        let msg = messages.get_message(&msg_id).unwrap();
        assert!(msg.deleted);
        assert_eq!(msg.ciphertext, vec![0xAA, 0xBB, 0xCC]); // original, not edited
    }

    #[test]
    fn test_double_delete_idempotent() {
        let (membership, gid, _owner_pub, _owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x0B; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        let del1 = make_msg_delete(gid, alice_pub, &alice_priv, msg_id, 5, 500);
        messages.apply_msg_delete(&del1, &membership).unwrap();

        let del2 = make_msg_delete(gid, alice_pub, &alice_priv, msg_id, 6, 600);
        messages.apply_msg_delete(&del2, &membership).unwrap(); // no error
    }

    // -------------------------------------------------------------------
    // Reactions
    // -------------------------------------------------------------------

    #[test]
    fn test_reaction_add_and_remove() {
        let (_membership, gid, owner_pub, owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x0C; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Owner adds a reaction
        let react_add = make_reaction(gid, owner_pub, &owner_priv, msg_id, "\u{1F44D}", true, 5, 500);
        messages.apply_reaction_set(&react_add).unwrap();

        let owner_device = DeviceID::from_pubkey(&owner_pub);
        let msg = messages.get_message(&msg_id).unwrap();
        assert_eq!(
            msg.reactions.get(&(owner_device, "\u{1F44D}".to_string())),
            Some(&true)
        );

        // Owner removes the reaction
        let react_remove =
            make_reaction(gid, owner_pub, &owner_priv, msg_id, "\u{1F44D}", false, 6, 600);
        messages.apply_reaction_set(&react_remove).unwrap();

        let msg = messages.get_message(&msg_id).unwrap();
        assert_eq!(
            msg.reactions.get(&(owner_device, "\u{1F44D}".to_string())),
            Some(&false)
        );
    }

    #[test]
    fn test_reaction_on_deleted_message_ignored() {
        let (membership, gid, owner_pub, owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x0D; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        let del_op = make_msg_delete(gid, alice_pub, &alice_priv, msg_id, 5, 500);
        messages.apply_msg_delete(&del_op, &membership).unwrap();

        // Reaction on deleted message — silently ignored
        let react = make_reaction(gid, owner_pub, &owner_priv, msg_id, "\u{1F602}", true, 6, 600);
        messages.apply_reaction_set(&react).unwrap();

        let msg = messages.get_message(&msg_id).unwrap();
        assert!(msg.reactions.is_empty());
    }

    #[test]
    fn test_reaction_on_unknown_message_ignored() {
        let (_membership, gid, owner_pub, owner_priv, _alice_pub, _alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let unknown_id = [0xFF; 32];

        let react = make_reaction(gid, owner_pub, &owner_priv, unknown_id, "\u{1F44D}", true, 4, 400);
        messages.apply_reaction_set(&react).unwrap(); // no error
    }

    #[test]
    fn test_multiple_users_react() {
        let (_membership, gid, owner_pub, owner_priv, alice_pub, alice_priv) =
            setup_group_with_member();

        let mut messages = MessageState::new();
        let msg_id = [0x0E; 32];
        let add_op = make_msg_add(gid, alice_pub, &alice_priv, msg_id, 4, 400);
        messages.apply_msg_add(&add_op).unwrap();

        // Both react with same emoji
        let react_owner =
            make_reaction(gid, owner_pub, &owner_priv, msg_id, "\u{1F44D}", true, 5, 500);
        let react_alice =
            make_reaction(gid, alice_pub, &alice_priv, msg_id, "\u{1F44D}", true, 6, 600);

        messages.apply_reaction_set(&react_owner).unwrap();
        messages.apply_reaction_set(&react_alice).unwrap();

        let msg = messages.get_message(&msg_id).unwrap();
        assert_eq!(msg.reactions.len(), 2);

        let owner_device = DeviceID::from_pubkey(&owner_pub);
        let alice_device = DeviceID::from_pubkey(&alice_pub);
        assert_eq!(
            msg.reactions.get(&(owner_device, "\u{1F44D}".to_string())),
            Some(&true)
        );
        assert_eq!(
            msg.reactions.get(&(alice_device, "\u{1F44D}".to_string())),
            Some(&true)
        );
    }
}
