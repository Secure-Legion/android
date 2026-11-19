//! Explicit group-key epoch codec. This is not an ordinary core metadata op.
//! Canonical parsing/signatures grant no membership or rotation authority.
//! The state adapter verifies the predecessor, removal coverage and roles.
//! The signed membership digest describes the source snapshot; concurrent
//! legitimate membership views need not have an identical digest.
use crate::{
    authorize_group_certificate, transcript, GroupError, Result, MAX_PARENT_HEADS, MAX_SAFE,
    MAX_TIMESTAMP,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use secure_device_protocol::{DeviceCertificate, DeviceRoster, CAP_GROUPS, CERTIFICATE_LEN};
use securelegion::crdt::ids::{DeviceID, GroupID, OpID};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 6] = b"SLGE01";
const DOMAIN: &[u8] = b"secure-legion-group-key-epoch-v1\0";
pub const MAX_EXPOSURES: usize = 128;
const FIXED_LEN: usize = 6 + CERTIFICATE_LEN + 32 + 32 + 8 + 1 + 1 + 32 + 32 + 32 + 64;
pub const MAX_ENCODED_LEN: usize = FIXED_LEN + 32 * (MAX_PARENT_HEADS + MAX_EXPOSURES);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochHeader {
    pub group_id: GroupID,
    pub op_id: OpID,
    pub timestamp_ms: u64,
    pub parent_heads: Vec<OpID>,
    /// Bounded delta of removal/key-exposure events, at most one per account.
    /// Coverage from previous_epoch is inherited. The state adapter resolves
    /// these signed records and enforces exact target scope.
    pub removal_frontier: Vec<OpID>,
    pub previous_epoch: [u8; 32],
    pub membership_digest: [u8; 32],
}

#[derive(Clone)]
pub struct EpochOperation {
    encoded: Zeroizing<Vec<u8>>,
    certificate: DeviceCertificate,
    header: EpochHeader,
    key: Zeroizing<[u8; 32]>,
}
impl std::fmt::Debug for EpochOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochOperation")
            .field("operation_id", &self.header.op_id)
            .finish_non_exhaustive()
    }
}

fn put_id(out: &mut Vec<u8>, id: &OpID) {
    out.extend_from_slice(id.author.as_bytes());
    out.extend_from_slice(&id.lamport.to_be_bytes());
    out.extend_from_slice(&id.nonce.to_be_bytes());
}
fn read_id(bytes: &[u8]) -> OpID {
    OpID::new(
        DeviceID::from_bytes(bytes[..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
    )
}
fn validate(header: &EpochHeader, cert: &DeviceCertificate, key: &[u8; 32]) -> Result<()> {
    let claims = cert.claims();
    if claims.capabilities & CAP_GROUPS == 0
        || claims.device_ed == claims.account_ed
        || DeviceID::from_pubkey(&claims.device_ed) == DeviceID::from_pubkey(&claims.account_ed)
        || header.op_id.author != DeviceID::from_pubkey(&claims.device_ed)
        || header.op_id.lamport < 2
        || header.op_id.lamport > MAX_SAFE
        || header.timestamp_ms > MAX_TIMESTAMP
        || header.parent_heads.len() > MAX_PARENT_HEADS
        || header.removal_frontier.len() > MAX_EXPOSURES
        || header.previous_epoch == [0; 32]
        || header.membership_digest == [0; 32]
        || *key == [0; 32]
        || header
            .parent_heads
            .iter()
            .any(|id| id.lamport == 0 || id.lamport >= header.op_id.lamport)
        || header.parent_heads.windows(2).any(|w| w[0] >= w[1])
        || header
            .removal_frontier
            .iter()
            .any(|id| id.lamport == 0 || id.lamport >= header.op_id.lamport)
        || header.removal_frontier.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(GroupError::Malformed);
    }
    Ok(())
}
impl EpochOperation {
    pub fn create(
        certificate: DeviceCertificate,
        device_seed: &[u8; 32],
        header: EpochHeader,
        key: [u8; 32],
    ) -> Result<Self> {
        let key = Zeroizing::new(key);
        validate(&header, &certificate, &key)?;
        let signer = SigningKey::from_bytes(device_seed);
        if signer.verifying_key().to_bytes() != certificate.claims().device_ed {
            return Err(GroupError::WrongSigner);
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(
            FIXED_LEN + 32 * (header.parent_heads.len() + header.removal_frontier.len()),
        ));
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(certificate.encoded());
        encoded.extend_from_slice(header.group_id.as_bytes());
        put_id(&mut encoded, &header.op_id);
        encoded.extend_from_slice(&header.timestamp_ms.to_be_bytes());
        encoded.push(header.parent_heads.len() as u8);
        for parent in &header.parent_heads {
            put_id(&mut encoded, parent);
        }
        encoded.push(header.removal_frontier.len() as u8);
        for event in &header.removal_frontier {
            put_id(&mut encoded, event);
        }
        encoded.extend_from_slice(&header.previous_epoch);
        encoded.extend_from_slice(&header.membership_digest);
        encoded.extend_from_slice(key.as_ref());
        let signed = Zeroizing::new(transcript(DOMAIN, &encoded));
        encoded.extend_from_slice(&signer.sign(&signed).to_bytes());
        Self::verify(&encoded, &certificate.claims().account_ed)
    }
    pub fn verify(bytes: &[u8], pinned_account: &[u8; 32]) -> Result<Self> {
        if bytes.len() < FIXED_LEN || bytes.len() > MAX_ENCODED_LEN || &bytes[..6] != MAGIC {
            return Err(GroupError::Malformed);
        }
        let certificate =
            DeviceCertificate::verify(&bytes[6..6 + CERTIFICATE_LEN], pinned_account)?;
        let start = 6 + CERTIFICATE_LEN;
        let group_id = GroupID::from_bytes(bytes[start..start + 32].try_into().unwrap());
        let op_id = read_id(&bytes[start + 32..start + 64]);
        let timestamp_ms = u64::from_be_bytes(bytes[start + 64..start + 72].try_into().unwrap());
        let count = usize::from(bytes[start + 72]);
        if count > MAX_PARENT_HEADS || bytes.len() < FIXED_LEN + 32 * count {
            return Err(GroupError::Malformed);
        }
        let mut at = start + 73;
        let mut parent_heads = Vec::with_capacity(count);
        for _ in 0..count {
            parent_heads.push(read_id(&bytes[at..at + 32]));
            at += 32;
        }
        let exposure_count = usize::from(bytes[at]);
        at += 1;
        if exposure_count > MAX_EXPOSURES
            || bytes.len() != FIXED_LEN + 32 * (count + exposure_count)
        {
            return Err(GroupError::Malformed);
        }
        let mut removal_frontier = Vec::with_capacity(exposure_count);
        for _ in 0..exposure_count {
            removal_frontier.push(read_id(&bytes[at..at + 32]));
            at += 32;
        }
        let previous_epoch = bytes[at..at + 32].try_into().unwrap();
        at += 32;
        let membership_digest = bytes[at..at + 32].try_into().unwrap();
        at += 32;
        let key = Zeroizing::new(<[u8; 32]>::try_from(&bytes[at..at + 32]).unwrap());
        at += 32;
        let header = EpochHeader {
            group_id,
            op_id,
            timestamp_ms,
            parent_heads,
            removal_frontier,
            previous_epoch,
            membership_digest,
        };
        validate(&header, &certificate, &key)?;
        let transcript = Zeroizing::new(transcript(DOMAIN, &bytes[..at]));
        VerifyingKey::from_bytes(&certificate.claims().device_ed)
            .map_err(|_| GroupError::Signature)?
            .verify_strict(
                &transcript,
                &Signature::from_slice(&bytes[at..]).map_err(|_| GroupError::Signature)?,
            )
            .map_err(|_| GroupError::Signature)?;
        Ok(Self {
            encoded: Zeroizing::new(bytes.to_vec()),
            certificate,
            header,
            key,
        })
    }
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
    pub fn certificate(&self) -> &DeviceCertificate {
        &self.certificate
    }
    pub fn header(&self) -> &EpochHeader {
        &self.header
    }
    /// Private state material, never diagnostics or public transport metadata.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.encoded).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_device_protocol::{
        onion_from_public_key, DeviceClaims, RosterEntry, ALL_CAPABILITIES, CAP_CHAT,
        ML_KEM_PUBLIC_LEN,
    };
    use x25519_dalek::{PublicKey, StaticSecret};
    fn public(n: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()
    }
    fn entry(leaf: u8, caps: u32, expires: u64) -> RosterEntry {
        let kem = [leaf; ML_KEM_PUBLIC_LEN];
        let onion = onion_from_public_key(&public(leaf)).unwrap();
        RosterEntry::new(
            DeviceCertificate::issue(
                DeviceClaims {
                    account_ed: public(1),
                    device_ed: public(leaf),
                    device_x: PublicKey::from(&StaticSecret::from([leaf + 30; 32])).to_bytes(),
                    ml_kem_public_hash: Sha256::digest(kem).into(),
                    onion: onion
                        .strip_suffix(".onion")
                        .unwrap()
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    issued_at_ms: 1000,
                    expires_at_ms: expires,
                    capabilities: caps,
                },
                &[1; 32],
            )
            .unwrap(),
            kem,
            "Synthetic".into(),
        )
        .unwrap()
    }
    fn header() -> EpochHeader {
        EpochHeader {
            group_id: GroupID::from_bytes([3; 32]),
            op_id: OpID::new(DeviceID::from_pubkey(&public(11)), 3, 7),
            timestamp_ms: 2000,
            parent_heads: vec![OpID::new(DeviceID::from_pubkey(&public(11)), 2, 6)],
            removal_frontier: vec![],
            previous_epoch: [4; 32],
            membership_digest: [5; 32],
        }
    }
    fn make() -> EpochOperation {
        EpochOperation::create(
            entry(11, CAP_GROUPS, 10000).certificate().clone(),
            &[11; 32],
            header(),
            [9; 32],
        )
        .unwrap()
    }
    #[test]
    fn explicit_epoch_round_trip_binds_every_field_and_does_not_expose_secret_in_debug() {
        let op = make();
        let decoded = EpochOperation::verify(op.encoded(), &public(1)).unwrap();
        assert_eq!(decoded.header(), &header());
        assert_eq!(decoded.key(), &[9; 32]);
        assert_eq!(decoded.hash(), op.hash());
        let display = format!("{op:?}");
        assert!(!display.contains("key:"));
        assert!(!display.contains("encoded"));
        assert!(EpochOperation::verify(op.encoded(), &public(2)).is_err());
        for offset in [
            12,
            6 + CERTIFICATE_LEN,
            6 + CERTIFICATE_LEN + 40,
            6 + CERTIFICATE_LEN + 64,
            op.encoded().len() - 65,
            op.encoded().len() - 1,
        ] {
            let mut bad = op.encoded().to_vec();
            bad[offset] ^= 1;
            assert!(EpochOperation::verify(&bad, &public(1)).is_err());
        }
        assert!(
            EpochOperation::verify(&op.encoded()[..op.encoded().len() - 1], &public(1)).is_err()
        );
        let mut extra = op.encoded().to_vec();
        extra.push(0);
        assert!(EpochOperation::verify(&extra, &public(1)).is_err());
        assert!(crate::DelegatedOperation::verify(op.encoded(), &public(1)).is_err());
    }
    #[test]
    fn epoch_heads_clocks_signer_capabilities_and_weak_keys_fail_closed() {
        let cert = entry(11, CAP_GROUPS, 10000).certificate().clone();
        assert!(EpochOperation::create(cert.clone(), &[12; 32], header(), [9; 32]).is_err());
        assert!(EpochOperation::create(
            entry(11, CAP_CHAT, 10000).certificate().clone(),
            &[11; 32],
            header(),
            [9; 32]
        )
        .is_err());
        assert!(EpochOperation::create(cert.clone(), &[11; 32], header(), [0; 32]).is_err());
        for change in 0..7 {
            let mut h = header();
            match change {
                0 => h.op_id.lamport = 1,
                1 => h.op_id.lamport = MAX_SAFE + 1,
                2 => h.timestamp_ms = MAX_TIMESTAMP + 1,
                3 => h.op_id.author = DeviceID::from_pubkey(&public(12)),
                4 => h.parent_heads.push(h.parent_heads[0]),
                5 => h.previous_epoch = [0; 32],
                _ => h.membership_digest = [0; 32],
            }
            assert!(EpochOperation::create(cert.clone(), &[11; 32], h, [9; 32]).is_err());
        }
    }
    #[test]
    fn epoch_uses_highest_current_device_authority_and_supports_renewed_leaf_keys() {
        let op = make();
        let primary = entry(10, ALL_CAPABILITIES, 100000);
        let roster = DeviceRoster::issue(
            &[1; 32],
            2,
            2000,
            primary.certificate().claims().device_id_bytes(),
            vec![primary.clone(), entry(11, CAP_GROUPS, 100000)],
        )
        .unwrap();
        op.authorize_current(&roster, None, 20000).unwrap();
        let revoked = DeviceRoster::issue(
            &[1; 32],
            3,
            2000,
            primary.certificate().claims().device_id_bytes(),
            vec![primary],
        )
        .unwrap();
        assert!(op
            .authorize_current(&revoked, Some(&roster), 20000)
            .is_err());
        assert!(op
            .authorize_current(&roster, Some(&revoked), 20000)
            .is_err());
    }
}
