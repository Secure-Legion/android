use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const CERTIFICATE_LEN: usize = 274;
pub const ML_KEM_PUBLIC_LEN: usize = 1568;
pub const MAX_DEVICES: usize = 8;
pub const MAX_ROSTER_LEN: usize = 32 * 1024;
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
pub const CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
pub const MAX_CERTIFICATE_LIFETIME_MS: u64 = 366 * 24 * 60 * 60 * 1000;
pub const CAP_CHAT: u32 = 1;
pub const CAP_SYNC: u32 = 2;
pub const CAP_GROUPS: u32 = 4;
pub const ALL_CAPABILITIES: u32 = CAP_CHAT | CAP_SYNC | CAP_GROUPS;

const CERT_MAGIC: &[u8; 6] = b"SLDC01";
const ROSTER_MAGIC: &[u8; 6] = b"SLDR01";
const CERT_DOMAIN: &[u8] = b"secure-legion-device-certificate-v1\0";
const ROSTER_DOMAIN: &[u8] = b"secure-legion-device-roster-v1\0";
const CERT_BODY_LEN: usize = CERTIFICATE_LEN - 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("malformed device authorization")]
    Malformed,
    #[error("invalid public key")]
    InvalidKey,
    #[error("account identity does not match the pinned identity")]
    WrongAccount,
    #[error("invalid device authorization signature")]
    Signature,
    #[error("invalid onion service address")]
    Onion,
    #[error("invalid authorization lifetime")]
    Lifetime,
    #[error("device authorization has expired or is not yet valid")]
    Inactive,
    #[error("device is not authorized for this operation")]
    Unauthorized,
    #[error("roster epoch rollback")]
    Rollback,
    #[error("conflicting rosters at the same epoch")]
    Fork,
    #[error("duplicate or unsorted device entries")]
    Order,
    #[error("device roster limit exceeded")]
    Limit,
}

type Result<T> = std::result::Result<T, AuthorizationError>;

/// SHA-256("secure-legion-device-v1" || Ed25519 || X25519), matching the
/// identity already stored in Desktop's protected device-key vault.
pub fn device_id_bytes(ed: &[u8; 32], x: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"secure-legion-device-v1");
    hash.update(ed);
    hash.update(x);
    hash.finalize().into()
}

pub fn device_id(ed: &[u8; 32], x: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(device_id_bytes(ed, x))
}

pub(crate) fn strong_ed(key: &[u8; 32]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| AuthorizationError::InvalidKey)?;
    if key.is_weak() {
        return Err(AuthorizationError::InvalidKey);
    }
    Ok(key)
}

pub(crate) fn strong_x(key: &[u8; 32]) -> Result<()> {
    // A public validation scalar, never a session secret. Reject non-canonical
    // field encodings and all small-order inputs (including non-zero ones).
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    if key.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less {
        return Err(AuthorizationError::InvalidKey);
    }
    let shared = StaticSecret::from([0x42; 32]).diffie_hellman(&PublicKey::from(*key));
    if !shared.was_contributory() {
        return Err(AuthorizationError::InvalidKey);
    }
    Ok(())
}

fn valid_onion(onion: &[u8; 56]) -> Result<()> {
    if !onion
        .iter()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(b))
    {
        return Err(AuthorizationError::Onion);
    }
    let upper: Vec<u8> = onion.iter().map(u8::to_ascii_uppercase).collect();
    let decoded = BASE32_NOPAD
        .decode(&upper)
        .map_err(|_| AuthorizationError::Onion)?;
    if decoded.len() != 35 || decoded[34] != 3 {
        return Err(AuthorizationError::Onion);
    }
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(&decoded[..32]);
    hash.update([3]);
    if decoded[32..34] != hash.finalize()[..2] {
        return Err(AuthorizationError::Onion);
    }
    Ok(())
}

pub fn onion_from_public_key(service_ed: &[u8; 32]) -> Result<String> {
    strong_ed(service_ed)?;
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(service_ed);
    hash.update([3]);
    let mut address = service_ed.to_vec();
    address.extend_from_slice(&hash.finalize()[..2]);
    address.push(3);
    Ok(BASE32_NOPAD.encode(&address).to_ascii_lowercase() + ".onion")
}

fn valid_time(value: u64) -> bool {
    value > 0 && value <= MAX_SAFE_INTEGER
}

fn signed_message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    [domain, body].concat()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceClaims {
    pub account_ed: [u8; 32],
    pub device_ed: [u8; 32],
    pub device_x: [u8; 32],
    pub ml_kem_public_hash: [u8; 32],
    /// Canonical v3 hostname without the .onion suffix.
    pub onion: [u8; 56],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub capabilities: u32,
}

impl DeviceClaims {
    fn validate(&self) -> Result<()> {
        strong_ed(&self.account_ed)?;
        strong_ed(&self.device_ed)?;
        strong_x(&self.device_x)?;
        valid_onion(&self.onion)?;
        if !valid_time(self.issued_at_ms)
            || !valid_time(self.expires_at_ms)
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_CERTIFICATE_LIFETIME_MS
        {
            return Err(AuthorizationError::Lifetime);
        }
        if self.capabilities == 0 || self.capabilities & !ALL_CAPABILITIES != 0 {
            return Err(AuthorizationError::Unauthorized);
        }
        Ok(())
    }

    pub fn device_id(&self) -> String {
        device_id(&self.device_ed, &self.device_x)
    }

    pub fn device_id_bytes(&self) -> [u8; 32] {
        device_id_bytes(&self.device_ed, &self.device_x)
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CERT_BODY_LEN);
        out.extend_from_slice(CERT_MAGIC);
        out.extend_from_slice(&self.account_ed);
        out.extend_from_slice(&self.device_ed);
        out.extend_from_slice(&self.device_x);
        out.extend_from_slice(&self.ml_kem_public_hash);
        out.extend_from_slice(&self.onion);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        if &reader.array::<6>()? != CERT_MAGIC {
            return Err(AuthorizationError::Malformed);
        }
        let claims = Self {
            account_ed: reader.array()?,
            device_ed: reader.array()?,
            device_x: reader.array()?,
            ml_kem_public_hash: reader.array()?,
            onion: reader.array()?,
            issued_at_ms: reader.u64()?,
            expires_at_ms: reader.u64()?,
            capabilities: u32::from_be_bytes(reader.array()?),
        };
        claims.validate()?;
        Ok(claims)
    }
}

/// The fields are immutable so callers cannot accidentally use modified claims
/// with an earlier verified signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    claims: DeviceClaims,
    encoded: [u8; CERTIFICATE_LEN],
}

impl DeviceCertificate {
    pub fn issue(claims: DeviceClaims, account_seed: &[u8; 32]) -> Result<Self> {
        claims.validate()?;
        let signer = SigningKey::from_bytes(account_seed);
        if signer.verifying_key().to_bytes() != claims.account_ed {
            return Err(AuthorizationError::WrongAccount);
        }
        let mut encoded = claims.body();
        encoded.extend_from_slice(
            &signer
                .sign(&signed_message(CERT_DOMAIN, &encoded))
                .to_bytes(),
        );
        Self::verify(&encoded, &claims.account_ed)
    }

    pub fn verify(encoded: &[u8], pinned_account: &[u8; 32]) -> Result<Self> {
        if encoded.len() != CERTIFICATE_LEN {
            return Err(AuthorizationError::Malformed);
        }
        let mut reader = Reader(encoded);
        let claims = DeviceClaims::read(&mut reader)?;
        if &claims.account_ed != pinned_account {
            return Err(AuthorizationError::WrongAccount);
        }
        let signature = Signature::from_bytes(&reader.array()?);
        strong_ed(pinned_account)?
            .verify_strict(
                &signed_message(CERT_DOMAIN, &encoded[..CERT_BODY_LEN]),
                &signature,
            )
            .map_err(|_| AuthorizationError::Signature)?;
        Ok(Self {
            claims,
            encoded: encoded
                .try_into()
                .map_err(|_| AuthorizationError::Malformed)?,
        })
    }

    pub fn claims(&self) -> &DeviceClaims {
        &self.claims
    }

    pub fn encoded(&self) -> &[u8; CERTIFICATE_LEN] {
        &self.encoded
    }

    fn authorize(&self, required: u32, now_ms: u64) -> Result<()> {
        if !valid_time(now_ms)
            || now_ms.saturating_add(CLOCK_SKEW_MS) < self.claims.issued_at_ms
            || now_ms >= self.claims.expires_at_ms
        {
            return Err(AuthorizationError::Inactive);
        }
        if required == 0
            || required & !ALL_CAPABILITIES != 0
            || self.claims.capabilities & required != required
        {
            return Err(AuthorizationError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    certificate: DeviceCertificate,
    ml_kem_public: [u8; ML_KEM_PUBLIC_LEN],
    name: String,
}

impl RosterEntry {
    pub fn new(
        certificate: DeviceCertificate,
        ml_kem_public: [u8; ML_KEM_PUBLIC_LEN],
        name: String,
    ) -> Result<Self> {
        if name.is_empty()
            || name.len() > 512
            || name.chars().count() > 128
            || name.chars().any(char::is_control)
        {
            return Err(AuthorizationError::Malformed);
        }
        let hash: [u8; 32] = Sha256::digest(ml_kem_public).into();
        if certificate.claims.ml_kem_public_hash != hash {
            return Err(AuthorizationError::InvalidKey);
        }
        Ok(Self {
            certificate,
            ml_kem_public,
            name,
        })
    }

    pub fn certificate(&self) -> &DeviceCertificate {
        &self.certificate
    }
    pub fn ml_kem_public(&self) -> &[u8; ML_KEM_PUBLIC_LEN] {
        &self.ml_kem_public
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRoster {
    account_ed: [u8; 32],
    epoch: u64,
    issued_at_ms: u64,
    primary_id: [u8; 32],
    entries: Vec<RosterEntry>,
    encoded: Vec<u8>,
}

impl DeviceRoster {
    pub fn issue(
        account_seed: &[u8; 32],
        epoch: u64,
        issued_at_ms: u64,
        primary_id: [u8; 32],
        mut entries: Vec<RosterEntry>,
    ) -> Result<Self> {
        // Sort the wire representation; verification never silently reorders it.
        entries.sort_by_key(|entry| entry.certificate.claims.device_id());
        let account_ed = SigningKey::from_bytes(account_seed)
            .verifying_key()
            .to_bytes();
        Self::validate_fields(&account_ed, epoch, issued_at_ms, &primary_id, &entries)?;
        let mut encoded = Vec::with_capacity(MAX_ROSTER_LEN);
        encoded.extend_from_slice(ROSTER_MAGIC);
        encoded.extend_from_slice(&account_ed);
        encoded.extend_from_slice(&epoch.to_be_bytes());
        encoded.extend_from_slice(&issued_at_ms.to_be_bytes());
        encoded.extend_from_slice(&primary_id);
        encoded.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for entry in &entries {
            encoded.extend_from_slice(entry.certificate.encoded());
            encoded.extend_from_slice(&entry.ml_kem_public);
            encoded.extend_from_slice(&(entry.name.len() as u16).to_be_bytes());
            encoded.extend_from_slice(entry.name.as_bytes());
        }
        let signer = SigningKey::from_bytes(account_seed);
        encoded.extend_from_slice(
            &signer
                .sign(&signed_message(ROSTER_DOMAIN, &encoded))
                .to_bytes(),
        );
        Self::verify(&encoded, &account_ed)
    }

    pub fn verify(encoded: &[u8], pinned_account: &[u8; 32]) -> Result<Self> {
        if encoded.len() > MAX_ROSTER_LEN {
            return Err(AuthorizationError::Limit);
        }
        let body_len = encoded
            .len()
            .checked_sub(64)
            .ok_or(AuthorizationError::Malformed)?;
        let mut reader = Reader(&encoded[..body_len]);
        if &reader.array::<6>()? != ROSTER_MAGIC {
            return Err(AuthorizationError::Malformed);
        }
        let account_ed = reader.array()?;
        if &account_ed != pinned_account {
            return Err(AuthorizationError::WrongAccount);
        }
        let epoch = reader.u64()?;
        let issued_at_ms = reader.u64()?;
        let primary_id = reader.array()?;
        let count = u16::from_be_bytes(reader.array()?) as usize;
        if count == 0 || count > MAX_DEVICES {
            return Err(AuthorizationError::Limit);
        }
        // Verify the enclosing signature before parsing device public keys.
        let signature_bytes: [u8; 64] = encoded[body_len..]
            .try_into()
            .map_err(|_| AuthorizationError::Malformed)?;
        strong_ed(pinned_account)?
            .verify_strict(
                &signed_message(ROSTER_DOMAIN, &encoded[..body_len]),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| AuthorizationError::Signature)?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let certificate =
                DeviceCertificate::verify(reader.take(CERTIFICATE_LEN)?, pinned_account)?;
            let ml_kem_public = reader.array()?;
            let name_len = u16::from_be_bytes(reader.array()?) as usize;
            if name_len > 512 {
                return Err(AuthorizationError::Limit);
            }
            let name = std::str::from_utf8(reader.take(name_len)?)
                .map_err(|_| AuthorizationError::Malformed)?
                .to_owned();
            entries.push(RosterEntry::new(certificate, ml_kem_public, name)?);
        }
        if !reader.0.is_empty() {
            return Err(AuthorizationError::Malformed);
        }
        Self::validate_fields(&account_ed, epoch, issued_at_ms, &primary_id, &entries)?;
        Ok(Self {
            account_ed,
            epoch,
            issued_at_ms,
            primary_id,
            entries,
            encoded: encoded.to_vec(),
        })
    }

    fn validate_fields(
        account: &[u8; 32],
        epoch: u64,
        issued: u64,
        primary: &[u8; 32],
        entries: &[RosterEntry],
    ) -> Result<()> {
        if epoch == 0 || epoch > MAX_SAFE_INTEGER || !valid_time(issued) {
            return Err(AuthorizationError::Malformed);
        }
        if entries.is_empty() || entries.len() > MAX_DEVICES {
            return Err(AuthorizationError::Limit);
        }
        let mut previous = None;
        let mut found_primary = false;
        for (index, entry) in entries.iter().enumerate() {
            let claims = entry.certificate.claims();
            if &claims.account_ed != account {
                return Err(AuthorizationError::WrongAccount);
            }
            if claims.issued_at_ms > issued {
                return Err(AuthorizationError::Lifetime);
            }
            let id = claims.device_id();
            if previous.as_ref().is_some_and(|last| last >= &id) {
                return Err(AuthorizationError::Order);
            }
            if entries[..index].iter().any(|other| {
                let other = other.certificate.claims();
                other.device_ed == claims.device_ed
                    || other.device_x == claims.device_x
                    || other.onion == claims.onion
            }) {
                return Err(AuthorizationError::Order);
            }
            previous = Some(id);
            if &claims.device_id_bytes() == primary {
                entry.certificate.authorize(ALL_CAPABILITIES, issued)?;
                found_primary = true;
            }
        }
        if !found_primary {
            return Err(AuthorizationError::Unauthorized);
        }
        Ok(())
    }

    pub fn account_ed(&self) -> &[u8; 32] {
        &self.account_ed
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }
    pub fn primary_id(&self) -> &[u8; 32] {
        &self.primary_id
    }
    pub fn entries(&self) -> &[RosterEntry] {
        &self.entries
    }
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Call against the last DURABLY accepted roster. Persist the result and
    /// any dependent session/outbox changes in the same database transaction.
    pub fn check_update(&self, previous: Option<&Self>, now_ms: u64) -> Result<()> {
        if !valid_time(now_ms) || self.issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
            return Err(AuthorizationError::Inactive);
        }
        if let Some(old) = previous {
            if self.account_ed != old.account_ed {
                return Err(AuthorizationError::WrongAccount);
            }
            if self.epoch < old.epoch {
                return Err(AuthorizationError::Rollback);
            }
            if self.epoch == old.epoch && self.encoded != old.encoded {
                return Err(AuthorizationError::Fork);
            }
            if self.epoch > old.epoch && self.issued_at_ms < old.issued_at_ms {
                return Err(AuthorizationError::Rollback);
            }
        }
        Ok(())
    }

    /// Authorize ONLY through the latest persisted roster. A certificate copied
    /// from an old roster cannot restore a device omitted by a newer epoch.
    pub fn active_device(&self, id: &[u8; 32], required: u32, now_ms: u64) -> Result<&RosterEntry> {
        self.check_update(None, now_ms)?;
        let entry = self
            .entries
            .iter()
            .find(|entry| &entry.certificate.claims.device_id_bytes() == id)
            .ok_or(AuthorizationError::Unauthorized)?;
        entry.certificate.authorize(required, now_ms)?;
        Ok(entry)
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.0.len() {
            return Err(AuthorizationError::Malformed);
        }
        let (out, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| AuthorizationError::Malformed)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}
