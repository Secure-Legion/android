//! Per-installation signatures over account-scoped group operations.
//!
//! This codec does not mutate membership or install roster trust. Live callers
//! must authorize through the latest durably pinned roster. Historical callers
//! need an exact already-accepted local operation hash or permanent account-root
//! ratification; an operation timestamp is never proof of pre-revocation use.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use secure_device_protocol::{
    AuthorizationError, DeviceCertificate, DeviceRoster, CAP_GROUPS, CERTIFICATE_LEN,
};
use securelegion::crdt::{
    ids::{DeviceID, GroupID, OpID},
    limits::MAX_OP_PAYLOAD_BYTES,
    ops::{OpEnvelope, OpType},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
pub mod api;
pub mod delivery;
pub mod epoch;
pub mod history;
mod key_state;
mod message_cipher;
pub mod state;
pub(crate) fn group_key_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

const MAGIC: &[u8; 6] = b"SLGO01";
const DOMAIN: &[u8] = b"secure-legion-group-device-operation-v1\0";
const RATIFY_MAGIC: &[u8; 6] = b"SLGR01";
const RATIFY_DOMAIN: &[u8] = b"secure-legion-group-operation-ratification-v1\0";
pub const MAX_OPERATION_BYTES: usize = MAX_OP_PAYLOAD_BYTES + 4096;
pub const MAX_PARENT_HEADS: usize = 64;
const MAX_SAFE: u64 = (1 << 53) - 1;
const MAX_TIMESTAMP: u64 = 8_640_000_000_000_000;

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("malformed delegated group operation")]
    Malformed,
    #[error("invalid delegated group signature")]
    Signature,
    #[error("device signing key does not match its account certificate")]
    WrongSigner,
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
}
pub type Result<T> = std::result::Result<T, GroupError>;

#[derive(Clone)]
pub struct DelegatedOperation {
    encoded: Vec<u8>,
    certificate: DeviceCertificate,
    operation: OpEnvelope,
}

impl std::fmt::Debug for DelegatedOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedOperation")
            .field("operation_id", &self.operation.op_id)
            .field("kind", &self.operation.op_type)
            .finish_non_exhaustive()
    }
}

impl DelegatedOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn create<P: Serialize>(
        certificate: DeviceCertificate,
        device_seed: &[u8; 32],
        group: GroupID,
        kind: OpType,
        payload: &P,
        parents: Vec<OpID>,
        lamport: u64,
        nonce: u64,
        timestamp_ms: u64,
    ) -> Result<Self> {
        let signer = SigningKey::from_bytes(device_seed);
        if signer.verifying_key().to_bytes() != certificate.claims().device_ed {
            return Err(GroupError::WrongSigner);
        }
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(payload, &mut payload_bytes)
            .map_err(|_| GroupError::Malformed)?;
        let operation = OpEnvelope {
            group_id: group,
            op_id: OpID::new(
                DeviceID::from_pubkey(&certificate.claims().device_ed),
                lamport,
                nonce,
            ),
            parent_heads: parents,
            lamport,
            timestamp_ms,
            op_type: kind,
            payload: payload_bytes,
            author_pubkey: certificate.claims().account_ed,
            signature: [0; 64],
        };
        validate_inner(&operation, &certificate)?;
        let inner = operation.to_bytes().map_err(|_| GroupError::Malformed)?;
        let mut encoded = Vec::with_capacity(6 + CERTIFICATE_LEN + 4 + inner.len() + 64);
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(certificate.encoded());
        encoded.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&inner);
        let signature = signer.sign(&transcript(DOMAIN, &encoded));
        encoded.extend_from_slice(&signature.to_bytes());
        Self::verify(&encoded, &operation.author_pubkey)
    }

    /// Cryptographic/canonical parsing only. This does not grant current use.
    pub fn verify(encoded: &[u8], pinned_account: &[u8; 32]) -> Result<Self> {
        let prefix = 6 + CERTIFICATE_LEN + 4;
        if encoded.len() < prefix + 64
            || encoded.len() > MAX_OPERATION_BYTES
            || &encoded[..6] != MAGIC
        {
            return Err(GroupError::Malformed);
        }
        let certificate =
            DeviceCertificate::verify(&encoded[6..6 + CERTIFICATE_LEN], pinned_account)?;
        let len = u32::from_be_bytes(encoded[prefix - 4..prefix].try_into().unwrap()) as usize;
        if len == 0 || prefix + len + 64 != encoded.len() {
            return Err(GroupError::Malformed);
        }
        let inner = &encoded[prefix..prefix + len];
        let operation = OpEnvelope::from_bytes(inner).map_err(|_| GroupError::Malformed)?;
        if operation
            .to_bytes()
            .map_err(|_| GroupError::Malformed)?
            .as_slice()
            != inner
        {
            return Err(GroupError::Malformed);
        }
        validate_inner(&operation, &certificate)?;
        let key = VerifyingKey::from_bytes(&certificate.claims().device_ed)
            .map_err(|_| GroupError::Signature)?;
        let signature =
            Signature::from_slice(&encoded[prefix + len..]).map_err(|_| GroupError::Signature)?;
        key.verify_strict(&transcript(DOMAIN, &encoded[..prefix + len]), &signature)
            .map_err(|_| GroupError::Signature)?;
        Ok(Self {
            encoded: encoded.to_vec(),
            certificate,
            operation,
        })
    }

    /// Roster continuity must be checked against the actual persisted prior
    /// roster by the host. Reusing a cached certificate cannot revive a device.
    pub fn authorize_current(
        &self,
        roster: &DeviceRoster,
        previous: Option<&DeviceRoster>,
        now: u64,
    ) -> Result<()> {
        authorize_group_certificate(&self.certificate, roster, previous, now)
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    pub fn operation(&self) -> &OpEnvelope {
        &self.operation
    }
    pub fn certificate(&self) -> &DeviceCertificate {
        &self.certificate
    }
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.encoded).into()
    }
}

pub(crate) fn authorize_group_certificate(
    certificate: &DeviceCertificate,
    roster: &DeviceRoster,
    previous: Option<&DeviceRoster>,
    now: u64,
) -> Result<()> {
    if roster.account_ed() != &certificate.claims().account_ed {
        return Err(AuthorizationError::WrongAccount.into());
    }
    roster.check_update(previous, now)?;
    let current = roster.active_device(&certificate.claims().device_id_bytes(), CAP_GROUPS, now)?;
    if current.certificate().claims().device_ed != certificate.claims().device_ed
        || current.certificate().claims().device_x != certificate.claims().device_x
    {
        return Err(GroupError::WrongSigner);
    }
    Ok(())
}

fn validate_inner(op: &OpEnvelope, cert: &DeviceCertificate) -> Result<()> {
    let claims = cert.claims();
    if claims.capabilities & CAP_GROUPS == 0
        || claims.device_ed == claims.account_ed
        || DeviceID::from_pubkey(&claims.device_ed) == DeviceID::from_pubkey(&claims.account_ed)
        || op.author_pubkey != claims.account_ed
        || op.op_id.author != DeviceID::from_pubkey(&claims.device_ed)
        || op.op_id.lamport != op.lamport
        || op.lamport == 0
        || op.lamport > MAX_SAFE
        || op.timestamp_ms > MAX_TIMESTAMP
        || op.signature != [0; 64]
        || op.parent_heads.len() > MAX_PARENT_HEADS
        || op.payload.is_empty()
        || op.payload.len() > MAX_OP_PAYLOAD_BYTES
    {
        return Err(GroupError::Malformed);
    }
    let mut parents = op.parent_heads.clone();
    parents.sort();
    parents.dedup();
    if parents != op.parent_heads
        || parents
            .iter()
            .any(|p| p == &op.op_id || p.lamport >= op.lamport)
    {
        return Err(GroupError::Malformed);
    }
    validate_payload(op)?;
    Ok(())
}

/// New delegated payloads have one typed CBOR representation. The pinned
/// legacy codec stays unchanged. Reject ignored/duplicate fields, trailing
/// bytes and a membership ID that does not belong to its claimed account.
fn validate_payload(op: &OpEnvelope) -> Result<()> {
    use securelegion::crdt::ops::*;
    fn canonical<T: serde::de::DeserializeOwned + Serialize>(op: &OpEnvelope) -> Result<T> {
        let value: T = op.decode_payload().map_err(|_| GroupError::Malformed)?;
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).map_err(|_| GroupError::Malformed)?;
        if encoded != op.payload {
            return Err(GroupError::Malformed);
        }
        Ok(value)
    }
    let text = |s: &str, max: usize| s.len() <= max && !s.chars().any(char::is_control);
    let valid = match op.op_type {
        OpType::GroupCreate => {
            let p: GroupCreatePayload = canonical(op)?;
            !p.group_name.trim().is_empty()
                && text(&p.group_name, 256)
                && p.encrypted_group_secret.len() == 32
        }
        OpType::MemberInvite => {
            let p: MemberInvitePayload = canonical(op)?;
            p.invited_device_id == DeviceID::from_pubkey(&p.invited_pubkey)
                && p.encrypted_group_secret.len() == 32
                && matches!(p.role, Role::Member | Role::ReadOnly)
        }
        OpType::MemberAccept => {
            let _: MemberAcceptPayload = canonical(op)?;
            true
        }
        OpType::MemberRemove => {
            let p: MemberRemovePayload = canonical(op)?;
            !matches!(p.reason, RemoveReason::Leave) || !p.ban
        }
        OpType::MemberUnban => {
            let _: MemberUnbanPayload = canonical(op)?;
            true
        }
        OpType::RoleSet => {
            let p: RoleSetPayload = canonical(op)?;
            p.custom_title.as_ref().is_none_or(|s| text(s, 32))
                && (p.new_role == Role::Admin || p.admin_rights.is_none())
        }
        OpType::MsgAdd => {
            let p: MsgAddPayload = canonical(op)?;
            !p.ciphertext.is_empty() && p.ciphertext.len() <= 60 * 1024
        }
        OpType::MsgEdit => {
            let p: MsgEditPayload = canonical(op)?;
            !p.new_ciphertext.is_empty() && p.new_ciphertext.len() <= 60 * 1024
        }
        OpType::MsgDelete => {
            let _: MsgDeletePayload = canonical(op)?;
            true
        }
        OpType::ReactionSet => {
            let p: ReactionSetPayload = canonical(op)?;
            !p.emoji.is_empty() && text(&p.emoji, 64)
        }
        OpType::MetadataSet => {
            let p: MetadataSetPayload = canonical(op)?;
            match p.key {
                MetadataKey::Name | MetadataKey::Topic => {
                    std::str::from_utf8(&p.value).is_ok_and(|s| text(s, 1024))
                }
                MetadataKey::Avatar => p.value.len() <= 32 * 1024,
                _ => p.value.as_slice() == [0] || p.value.as_slice() == [1],
            }
        }
        OpType::GroupDelete => {
            let p: GroupDeletePayload = canonical(op)?;
            p.reason.as_ref().is_none_or(|s| text(s, 1024))
        }
    };
    if !valid {
        return Err(GroupError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_device_protocol::{
        onion_from_public_key, DeviceClaims, RosterEntry, ALL_CAPABILITIES, CAP_CHAT,
        ML_KEM_PUBLIC_LEN,
    };
    use securelegion::crdt::ops::GroupCreatePayload;
    use x25519_dalek::{PublicKey, StaticSecret};
    const ROOT: [u8; 32] = [1; 32];

    fn root_public() -> [u8; 32] {
        SigningKey::from_bytes(&ROOT).verifying_key().to_bytes()
    }
    fn entry(n: u8, issued: u64, expires: u64, caps: u32) -> RosterEntry {
        let ed = SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes();
        let x = PublicKey::from(&StaticSecret::from([n + 30; 32])).to_bytes();
        let kem = [n; ML_KEM_PUBLIC_LEN];
        let onion = onion_from_public_key(&ed).unwrap();
        let cert = DeviceCertificate::issue(
            DeviceClaims {
                account_ed: root_public(),
                device_ed: ed,
                device_x: x,
                ml_kem_public_hash: Sha256::digest(kem).into(),
                onion: onion
                    .strip_suffix(".onion")
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                issued_at_ms: issued,
                expires_at_ms: expires,
                capabilities: caps,
            },
            &ROOT,
        )
        .unwrap();
        RosterEntry::new(cert, kem, format!("Synthetic {n}")).unwrap()
    }
    fn full() -> DeviceRoster {
        let primary = entry(10, 1000, 1_000_000, ALL_CAPABILITIES);
        DeviceRoster::issue(
            &ROOT,
            1,
            1000,
            primary.certificate().claims().device_id_bytes(),
            vec![primary, entry(11, 1000, 1_000_000, CAP_GROUPS)],
        )
        .unwrap()
    }
    fn group() -> GroupID {
        GroupID::new(&DeviceID::from_pubkey(&root_public()), &[5; 32])
    }
    fn make(n: u8) -> DelegatedOperation {
        DelegatedOperation::create(
            entry(n, 1000, 1_000_000, CAP_GROUPS).certificate().clone(),
            &[n; 32],
            group(),
            OpType::GroupCreate,
            &GroupCreatePayload {
                group_name: "Synthetic group".into(),
                encrypted_group_secret: vec![7; 32],
            },
            vec![],
            1,
            42,
            2000,
        )
        .unwrap()
    }

    #[test]
    fn independent_devices_keep_one_logical_account_without_root_signing() {
        let a = make(10);
        let b = make(11);
        assert_eq!(a.operation().author_pubkey, root_public());
        assert_eq!(b.operation().author_pubkey, root_public());
        assert_ne!(a.operation().op_id, b.operation().op_id);
        assert_ne!(
            a.operation().op_id.author,
            DeviceID::from_pubkey(&root_public())
        );
        assert_eq!(a.operation().signature, [0; 64]);
        assert!(a.operation().verify().is_err()); // Never strip its authorization wrapper.
        a.authorize_current(&full(), None, 2000).unwrap();
        b.authorize_current(&full(), None, 2000).unwrap();
        assert!(!format!("{a:?}").contains("payload"));
    }

    #[test]
    fn canonical_wrapper_rejects_tampering_wrong_root_and_trailing_data() {
        let op = make(11);
        for index in [0, 20, 6 + CERTIFICATE_LEN, op.encoded().len() - 1] {
            let mut bad = op.encoded().to_vec();
            bad[index] ^= 1;
            assert!(DelegatedOperation::verify(&bad, &root_public()).is_err());
        }
        let mut bad = op.encoded().to_vec();
        bad.push(0);
        assert!(DelegatedOperation::verify(&bad, &root_public()).is_err());
        let other = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        assert!(DelegatedOperation::verify(op.encoded(), &other).is_err());
        assert!(DelegatedOperation::create(
            op.certificate().clone(),
            &[12; 32],
            group(),
            OpType::GroupCreate,
            &GroupCreatePayload {
                group_name: "Synthetic".into(),
                encrypted_group_secret: vec![]
            },
            vec![],
            1,
            1,
            2000
        )
        .is_err());
    }

    #[test]
    fn an_old_certificate_or_roster_cannot_revive_removed_authority() {
        let op = make(11);
        let previous = full();
        let primary = entry(10, 1000, 1_000_000, ALL_CAPABILITIES);
        let current = DeviceRoster::issue(
            &ROOT,
            2,
            2000,
            primary.certificate().claims().device_id_bytes(),
            vec![primary],
        )
        .unwrap();
        assert!(DelegatedOperation::verify(op.encoded(), &root_public()).is_ok());
        assert!(op
            .authorize_current(&current, Some(&previous), 3000)
            .is_err());
        assert!(op
            .authorize_current(&previous, Some(&current), 3000)
            .is_err());
        let old_hash = op.hash();
        let proof = RootRatification::issue(&op, &ROOT).unwrap();
        RootRatification::verify(proof.encoded(), &op).unwrap();
        assert_eq!(old_hash, op.hash()); // Approval proof does not change operation identity.
    }

    #[test]
    fn renewing_the_same_device_authority_preserves_its_signed_operations() {
        let old = entry(11, 1000, 3000, CAP_GROUPS);
        let op = DelegatedOperation::create(
            old.certificate().clone(),
            &[11; 32],
            group(),
            OpType::GroupCreate,
            &GroupCreatePayload {
                group_name: "Synthetic".into(),
                encrypted_group_secret: vec![7; 32],
            },
            vec![],
            1,
            1,
            2000,
        )
        .unwrap();
        let primary = entry(10, 1000, 1_000_000, ALL_CAPABILITIES);
        let current = DeviceRoster::issue(
            &ROOT,
            2,
            2000,
            primary.certificate().claims().device_id_bytes(),
            vec![primary, entry(11, 2000, 1_000_000, CAP_GROUPS)],
        )
        .unwrap();
        op.authorize_current(&current, None, 4000).unwrap();
    }

    #[test]
    fn permanent_ratification_binds_the_exact_operation_and_its_root() {
        let op = make(11);
        let proof = RootRatification::issue(&op, &ROOT).unwrap();
        assert!(RootRatification::issue(&op, &[2; 32]).is_err());
        assert!(RootRatification::verify(proof.encoded(), &make(10)).is_err());
        for index in [0, 6, 38, 133] {
            let mut bad = *proof.encoded();
            bad[index] ^= 1;
            assert!(RootRatification::verify(&bad, &op).is_err());
        }
    }

    #[test]
    fn invalid_heads_clocks_and_non_group_certificates_fail_before_signing() {
        let payload = GroupCreatePayload {
            group_name: "Synthetic".into(),
            encrypted_group_secret: vec![],
        };
        let cert = entry(11, 1000, 1_000_000, CAP_GROUPS).certificate().clone();
        let mut copied_root = cert.claims().clone();
        copied_root.account_ed = copied_root.device_ed;
        let copied_root = DeviceCertificate::issue(copied_root, &[11; 32]).unwrap();
        assert!(DelegatedOperation::create(
            copied_root,
            &[11; 32],
            group(),
            OpType::GroupCreate,
            &payload,
            vec![],
            1,
            1,
            2000
        )
        .is_err());
        let first = OpID::new(DeviceID::from_pubkey(&[3; 32]), 1, 1);
        let second = OpID::new(DeviceID::from_pubkey(&[4; 32]), 1, 2);
        assert!(DelegatedOperation::create(
            cert.clone(),
            &[11; 32],
            group(),
            OpType::GroupCreate,
            &payload,
            vec![],
            0,
            1,
            2000
        )
        .is_err());
        assert!(DelegatedOperation::create(
            cert.clone(),
            &[11; 32],
            group(),
            OpType::GroupCreate,
            &payload,
            vec![first, first],
            2,
            1,
            2000
        )
        .is_err());
        let mut sorted = vec![first, second];
        sorted.sort();
        sorted.reverse();
        assert!(DelegatedOperation::create(
            cert.clone(),
            &[11; 32],
            group(),
            OpType::GroupCreate,
            &payload,
            sorted,
            2,
            1,
            2000
        )
        .is_err());
        assert!(DelegatedOperation::create(
            entry(11, 1000, 1_000_000, CAP_CHAT).certificate().clone(),
            &[11; 32],
            group(),
            OpType::GroupCreate,
            &payload,
            vec![],
            1,
            1,
            2000
        )
        .is_err());
    }
}

fn transcript(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + bytes.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(bytes);
    out
}

/// Permanent approval of one exact device operation by its account root,
/// equivalent in authority to an ordinary root-signed legacy operation. Hosts
/// may issue this only for locally approved operations; never blindly ratify
/// untrusted packets or infer past authority from their wall-clock timestamps.
#[derive(Clone, Debug)]
pub struct RootRatification {
    encoded: [u8; 134],
}
impl RootRatification {
    pub fn issue(operation: &DelegatedOperation, account_seed: &[u8; 32]) -> Result<Self> {
        Self::issue_exact(
            operation.hash(),
            &operation.operation.author_pubkey,
            account_seed,
        )
    }
    pub(crate) fn issue_exact(
        hash: [u8; 32],
        account: &[u8; 32],
        account_seed: &[u8; 32],
    ) -> Result<Self> {
        let signer = SigningKey::from_bytes(account_seed);
        if &signer.verifying_key().to_bytes() != account {
            return Err(GroupError::WrongSigner);
        }
        let mut encoded = [0u8; 134];
        encoded[..6].copy_from_slice(RATIFY_MAGIC);
        encoded[6..38].copy_from_slice(&hash);
        encoded[38..70].copy_from_slice(account);
        let signature = signer.sign(&transcript(RATIFY_DOMAIN, &encoded[..70]));
        encoded[70..].copy_from_slice(&signature.to_bytes());
        Self::verify_exact(&encoded, hash, account)
    }
    pub fn verify(encoded: &[u8], operation: &DelegatedOperation) -> Result<Self> {
        Self::verify_exact(
            encoded,
            operation.hash(),
            &operation.operation.author_pubkey,
        )
    }
    pub(crate) fn verify_exact(encoded: &[u8], hash: [u8; 32], account: &[u8; 32]) -> Result<Self> {
        if encoded.len() != 134
            || &encoded[..6] != RATIFY_MAGIC
            || encoded[6..38] != hash
            || &encoded[38..70] != account
        {
            return Err(GroupError::Malformed);
        }
        VerifyingKey::from_bytes(account)
            .map_err(|_| GroupError::Signature)?
            .verify_strict(
                &transcript(RATIFY_DOMAIN, &encoded[..70]),
                &Signature::from_slice(&encoded[70..]).map_err(|_| GroupError::Signature)?,
            )
            .map_err(|_| GroupError::Signature)?;
        Ok(Self {
            encoded: encoded.try_into().map_err(|_| GroupError::Malformed)?,
        })
    }
    pub fn encoded(&self) -> &[u8; 134] {
        &self.encoded
    }
}
