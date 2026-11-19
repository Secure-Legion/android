//! Bounded public-data API for platform bindings. Private account seeds are a
//! separate argument and never enter JSON, return values, or error messages.

use crate::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::Deserialize;
use serde_json::{json, Value};

pub const MAX_API_LEN: usize = 128 * 1024;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    OnionFromPublicKey {
        service_ed: String,
    },
    IssueAccountIdentity {
        account_x: String,
        account_kem: String,
    },
    VerifyAccountIdentity {
        identity: String,
        pinned_account: String,
    },
    IssueCertificate {
        claims: ClaimsInput,
    },
    VerifyCertificate {
        certificate: String,
        pinned_account: String,
    },
    IssueRoster {
        epoch: u64,
        issued_at_ms: u64,
        primary_device_id: String,
        entries: Vec<EntryInput>,
    },
    VerifyRoster {
        roster: String,
        pinned_account: String,
        previous_roster: Option<String>,
        now_ms: u64,
        authorize: Option<AuthorizeInput>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimsInput {
    account_ed: String,
    device_ed: String,
    device_x: String,
    ml_kem_public_hash: String,
    onion: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    capabilities: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryInput {
    certificate: String,
    ml_kem_public: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeInput {
    device_id: String,
    capabilities: u32,
}

fn decoded<const N: usize>(value: &str) -> std::result::Result<[u8; N], AuthorizationError> {
    if value.len() != N.div_ceil(3) * 4 {
        return Err(AuthorizationError::Malformed);
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| AuthorizationError::Malformed)?;
    decoded
        .try_into()
        .map_err(|_| AuthorizationError::Malformed)
}

fn decode_roster(
    value: &str,
    account: &[u8; 32],
) -> std::result::Result<DeviceRoster, AuthorizationError> {
    if value.len() > MAX_ROSTER_LEN.div_ceil(3) * 4 {
        return Err(AuthorizationError::Limit);
    }
    let encoded = STANDARD
        .decode(value)
        .map_err(|_| AuthorizationError::Malformed)?;
    DeviceRoster::verify(&encoded, account)
}

fn decode_id(value: &str) -> std::result::Result<[u8; 32], AuthorizationError> {
    if value.len() != 43 {
        return Err(AuthorizationError::Malformed);
    }
    let id = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorizationError::Malformed)?;
    id.try_into().map_err(|_| AuthorizationError::Malformed)
}

fn certificate_json(certificate: &DeviceCertificate) -> Value {
    let c = certificate.claims();
    json!({
        "certificate": STANDARD.encode(certificate.encoded()),
        "device_id": c.device_id(),
        "account_ed": STANDARD.encode(c.account_ed),
        "device_ed": STANDARD.encode(c.device_ed),
        "device_x": STANDARD.encode(c.device_x),
        "ml_kem_public_hash": STANDARD.encode(c.ml_kem_public_hash),
        "onion": std::str::from_utf8(&c.onion).expect("validated ASCII onion"),
        "issued_at_ms": c.issued_at_ms,
        "expires_at_ms": c.expires_at_ms,
        "capabilities": c.capabilities,
    })
}

fn roster_json(roster: &DeviceRoster) -> Value {
    json!({
        "roster": STANDARD.encode(roster.encoded()),
        "account_ed": STANDARD.encode(roster.account_ed()),
        "epoch": roster.epoch(),
        "issued_at_ms": roster.issued_at_ms(),
        "primary_device_id": URL_SAFE_NO_PAD.encode(roster.primary_id()),
        "entries": roster.entries().iter().map(|entry| json!({
            "certificate": certificate_json(entry.certificate()),
            "ml_kem_public": STANDARD.encode(entry.ml_kem_public()),
            "name": entry.name(),
        })).collect::<Vec<_>>(),
    })
}

fn account_identity_json(identity: &AccountPublicIdentity) -> Value {
    json!({"identity": STANDARD.encode(identity.encoded()),
        "account_ed": STANDARD.encode(identity.account_ed()),
        "account_x": STANDARD.encode(identity.account_x()),
        "account_kem": STANDARD.encode(identity.account_kem())})
}

pub fn execute(
    request: &[u8],
    account_seed: Option<&[u8; 32]>,
) -> std::result::Result<Vec<u8>, AuthorizationError> {
    if request.len() > MAX_API_LEN {
        return Err(AuthorizationError::Limit);
    }
    let request: Request =
        serde_json::from_slice(request).map_err(|_| AuthorizationError::Malformed)?;
    let value = match request {
        Request::OnionFromPublicKey { service_ed } => {
            if account_seed.is_some() {
                return Err(AuthorizationError::Malformed);
            }
            json!({"onion": onion_from_public_key(&decoded(&service_ed)?)?})
        }
        Request::IssueAccountIdentity {
            account_x,
            account_kem,
        } => account_identity_json(&AccountPublicIdentity::issue(
            account_seed.ok_or(AuthorizationError::Unauthorized)?,
            decoded(&account_x)?,
            decoded(&account_kem)?,
        )?),
        Request::VerifyAccountIdentity {
            identity,
            pinned_account,
        } => {
            if account_seed.is_some() {
                return Err(AuthorizationError::Malformed);
            }
            account_identity_json(&AccountPublicIdentity::verify(
                &decoded::<ACCOUNT_IDENTITY_LEN>(&identity)?,
                &decoded(&pinned_account)?,
            )?)
        }
        Request::IssueCertificate { claims } => {
            let claims = DeviceClaims {
                account_ed: decoded(&claims.account_ed)?,
                device_ed: decoded(&claims.device_ed)?,
                device_x: decoded(&claims.device_x)?,
                ml_kem_public_hash: decoded(&claims.ml_kem_public_hash)?,
                onion: claims
                    .onion
                    .as_bytes()
                    .try_into()
                    .map_err(|_| AuthorizationError::Onion)?,
                issued_at_ms: claims.issued_at_ms,
                expires_at_ms: claims.expires_at_ms,
                capabilities: claims.capabilities,
            };
            certificate_json(&DeviceCertificate::issue(
                claims,
                account_seed.ok_or(AuthorizationError::Unauthorized)?,
            )?)
        }
        Request::VerifyCertificate {
            certificate,
            pinned_account,
        } => {
            if account_seed.is_some() {
                return Err(AuthorizationError::Malformed);
            }
            certificate_json(&DeviceCertificate::verify(
                &decoded::<CERTIFICATE_LEN>(&certificate)?,
                &decoded(&pinned_account)?,
            )?)
        }
        Request::IssueRoster {
            epoch,
            issued_at_ms,
            primary_device_id,
            entries,
        } => {
            let seed = account_seed.ok_or(AuthorizationError::Unauthorized)?;
            let account = ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .to_bytes();
            if entries.len() > MAX_DEVICES {
                return Err(AuthorizationError::Limit);
            }
            let entries = entries
                .into_iter()
                .map(|entry| {
                    RosterEntry::new(
                        DeviceCertificate::verify(
                            &decoded::<CERTIFICATE_LEN>(&entry.certificate)?,
                            &account,
                        )?,
                        decoded(&entry.ml_kem_public)?,
                        entry.name,
                    )
                })
                .collect::<std::result::Result<Vec<_>, AuthorizationError>>()?;
            roster_json(&DeviceRoster::issue(
                seed,
                epoch,
                issued_at_ms,
                decode_id(&primary_device_id)?,
                entries,
            )?)
        }
        Request::VerifyRoster {
            roster,
            pinned_account,
            previous_roster,
            now_ms,
            authorize,
        } => {
            if account_seed.is_some() {
                return Err(AuthorizationError::Malformed);
            }
            let account = decoded(&pinned_account)?;
            let roster = decode_roster(&roster, &account)?;
            let previous = previous_roster
                .as_deref()
                .map(|old| decode_roster(old, &account))
                .transpose()?;
            roster.check_update(previous.as_ref(), now_ms)?;
            if let Some(authorize) = authorize {
                roster.active_device(
                    &decode_id(&authorize.device_id)?,
                    authorize.capabilities,
                    now_ms,
                )?;
            }
            roster_json(&roster)
        }
    };
    serde_json::to_vec(&value).map_err(|_| AuthorizationError::Malformed)
}
