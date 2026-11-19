//! Exact-bundle receipts for authenticated history replication. A receipt is
//! not permission to apply a live foreign operation using historical roles.
use crate::{transcript, GroupError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use secure_device_protocol::{DeviceCertificate, DeviceRoster, CERTIFICATE_LEN};
use securelegion::crdt::ids::GroupID;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 6] = b"SLGH01";
const DOMAIN: &[u8] = b"secure-legion-group-history-receipt-v1\0";
pub const RECEIPT_LEN: usize = 6 + CERTIFICATE_LEN + 32 + 32 + 64;
pub const MAX_HISTORY_BYTES: usize = 24 * 1024 * 1024;

#[derive(Clone)]
pub struct HistoryReceipt {
    encoded: [u8; RECEIPT_LEN],
    certificate: DeviceCertificate,
}
impl HistoryReceipt {
    /// The host may sign only the exact committed, previously validated log.
    pub fn issue(
        certificate: DeviceCertificate,
        seed: &[u8; 32],
        group: GroupID,
        committed: &[u8],
    ) -> Result<Self, GroupError> {
        if committed.is_empty() || committed.len() > MAX_HISTORY_BYTES {
            return Err(GroupError::Malformed);
        }
        let signer = SigningKey::from_bytes(seed);
        if signer.verifying_key().to_bytes() != certificate.claims().device_ed
            || certificate.claims().device_ed == certificate.claims().account_ed
        {
            return Err(GroupError::WrongSigner);
        }
        let mut encoded = [0u8; RECEIPT_LEN];
        encoded[..6].copy_from_slice(MAGIC);
        encoded[6..6 + CERTIFICATE_LEN].copy_from_slice(certificate.encoded());
        let offset = 6 + CERTIFICATE_LEN;
        encoded[offset..offset + 32].copy_from_slice(group.as_bytes());
        encoded[offset + 32..offset + 64].copy_from_slice(&Sha256::digest(committed));
        let signature = signer.sign(&transcript(DOMAIN, &encoded[..RECEIPT_LEN - 64]));
        encoded[RECEIPT_LEN - 64..].copy_from_slice(&signature.to_bytes());
        Self::verify(&encoded, &certificate.claims().account_ed, group, committed)
    }
    pub fn verify(
        encoded: &[u8],
        account: &[u8; 32],
        group: GroupID,
        committed: &[u8],
    ) -> Result<Self, GroupError> {
        if encoded.len() != RECEIPT_LEN
            || !encoded.starts_with(MAGIC)
            || committed.is_empty()
            || committed.len() > MAX_HISTORY_BYTES
        {
            return Err(GroupError::Malformed);
        }
        let certificate = DeviceCertificate::verify(&encoded[6..6 + CERTIFICATE_LEN], account)?;
        let offset = 6 + CERTIFICATE_LEN;
        if encoded[offset..offset + 32] != *group.as_bytes()
            || encoded[offset + 32..offset + 64] != Sha256::digest(committed)[..]
            || certificate.claims().device_ed == *account
        {
            return Err(GroupError::Malformed);
        }
        VerifyingKey::from_bytes(&certificate.claims().device_ed)
            .map_err(|_| GroupError::Signature)?
            .verify_strict(
                &transcript(DOMAIN, &encoded[..RECEIPT_LEN - 64]),
                &Signature::from_slice(&encoded[RECEIPT_LEN - 64..])
                    .map_err(|_| GroupError::Signature)?,
            )
            .map_err(|_| GroupError::Signature)?;
        Ok(Self {
            encoded: encoded.try_into().unwrap(),
            certificate,
        })
    }
    pub fn authorize_current(
        &self,
        roster: &DeviceRoster,
        capabilities: u32,
        now: u64,
    ) -> Result<(), GroupError> {
        if roster.account_ed() != &self.certificate.claims().account_ed {
            return Err(GroupError::WrongSigner);
        }
        roster.check_update(None, now)?;
        let entry = roster.active_device(
            &self.certificate.claims().device_id_bytes(),
            capabilities,
            now,
        )?;
        if entry.certificate().claims().device_ed != self.certificate.claims().device_ed
            || entry.certificate().claims().device_x != self.certificate.claims().device_x
        {
            return Err(GroupError::WrongSigner);
        }
        Ok(())
    }
    pub fn encoded(&self) -> &[u8; RECEIPT_LEN] {
        &self.encoded
    }
    pub fn certificate(&self) -> &DeviceCertificate {
        &self.certificate
    }
}
