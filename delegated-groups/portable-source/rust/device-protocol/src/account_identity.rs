use crate::{
    authorization::{strong_ed, strong_x},
    AuthorizationError, ML_KEM_PUBLIC_LEN,
};
use ed25519_dalek::{Signature, Signer, SigningKey};

pub const ACCOUNT_IDENTITY_LEN: usize = 6 + 32 + 32 + ML_KEM_PUBLIC_LEN + 64;
const MAGIC: &[u8; 6] = b"SLAP01";
const DOMAIN: &[u8] = b"secure-legion-account-public-identity-v1\0";
const BODY_LEN: usize = ACCOUNT_IDENTITY_LEN - 64;

/// A root-signed public identity tuple, without account or device private keys.
/// It permits a delegated installation to preserve existing account/contact
/// identifiers without possessing the account root or any active chat chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPublicIdentity {
    account_ed: [u8; 32],
    account_x: [u8; 32],
    account_kem: [u8; ML_KEM_PUBLIC_LEN],
    encoded: [u8; ACCOUNT_IDENTITY_LEN],
}

impl AccountPublicIdentity {
    pub fn issue(
        seed: &[u8; 32],
        account_x: [u8; 32],
        account_kem: [u8; ML_KEM_PUBLIC_LEN],
    ) -> Result<Self, AuthorizationError> {
        let signer = SigningKey::from_bytes(seed);
        let account_ed = signer.verifying_key().to_bytes();
        strong_ed(&account_ed)?;
        strong_x(&account_x)?;
        let mut encoded = [0; ACCOUNT_IDENTITY_LEN];
        encoded[..6].copy_from_slice(MAGIC);
        encoded[6..38].copy_from_slice(&account_ed);
        encoded[38..70].copy_from_slice(&account_x);
        encoded[70..BODY_LEN].copy_from_slice(&account_kem);
        let signature = signer.sign(&[DOMAIN, &encoded[..BODY_LEN]].concat());
        encoded[BODY_LEN..].copy_from_slice(&signature.to_bytes());
        Self::verify(&encoded, &account_ed)
    }

    pub fn verify(encoded: &[u8], pinned_account: &[u8; 32]) -> Result<Self, AuthorizationError> {
        if encoded.len() != ACCOUNT_IDENTITY_LEN || &encoded[..6] != MAGIC {
            return Err(AuthorizationError::Malformed);
        }
        let account_ed = encoded[6..38]
            .try_into()
            .map_err(|_| AuthorizationError::Malformed)?;
        if &account_ed != pinned_account {
            return Err(AuthorizationError::WrongAccount);
        }
        let account_x = encoded[38..70]
            .try_into()
            .map_err(|_| AuthorizationError::Malformed)?;
        strong_x(&account_x)?;
        let signature = Signature::from_bytes(
            &encoded[BODY_LEN..]
                .try_into()
                .map_err(|_| AuthorizationError::Malformed)?,
        );
        strong_ed(pinned_account)?
            .verify_strict(&[DOMAIN, &encoded[..BODY_LEN]].concat(), &signature)
            .map_err(|_| AuthorizationError::Signature)?;
        Ok(Self {
            account_ed,
            account_x,
            account_kem: encoded[70..BODY_LEN]
                .try_into()
                .map_err(|_| AuthorizationError::Malformed)?,
            encoded: encoded
                .try_into()
                .map_err(|_| AuthorizationError::Malformed)?,
        })
    }

    pub fn account_ed(&self) -> &[u8; 32] {
        &self.account_ed
    }
    pub fn account_x(&self) -> &[u8; 32] {
        &self.account_x
    }
    pub fn account_kem(&self) -> &[u8; ML_KEM_PUBLIC_LEN] {
        &self.account_kem
    }
    pub fn encoded(&self) -> &[u8; ACCOUNT_IDENTITY_LEN] {
        &self.encoded
    }
}
