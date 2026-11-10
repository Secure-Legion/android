//! Fixed synthetic public fixtures; no real account or device material.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use secure_device_protocol::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};

fn entry(tag: u8) -> RosterEntry {
    let mut address = vec![tag; 32];
    let mut checksum = Sha3_256::new();
    checksum.update(b".onion checksum");
    checksum.update(&address);
    checksum.update([3]);
    address.extend_from_slice(&checksum.finalize()[..2]);
    address.push(3);
    let owner = [7; 32];
    let claims = DeviceClaims {
        account_ed: SigningKey::from_bytes(&owner).verifying_key().to_bytes(),
        device_ed: SigningKey::from_bytes(&[tag; 32])
            .verifying_key()
            .to_bytes(),
        device_x: PublicKey::from(&StaticSecret::from([tag; 32])).to_bytes(),
        ml_kem_public_hash: Sha256::digest([tag; ML_KEM_PUBLIC_LEN]).into(),
        onion: data_encoding::BASE32_NOPAD
            .encode(&address)
            .to_ascii_lowercase()
            .as_bytes()
            .try_into()
            .unwrap(),
        issued_at_ms: 1_792_512_000_000,
        expires_at_ms: 1_792_512_000_000 + MAX_CERTIFICATE_LIFETIME_MS,
        capabilities: ALL_CAPABILITIES,
    };
    RosterEntry::new(
        DeviceCertificate::issue(claims, &owner).unwrap(),
        [tag; ML_KEM_PUBLIC_LEN],
        format!("Device {tag}"),
    )
    .unwrap()
}

fn main() {
    let primary = entry(11);
    let linked = entry(22);
    let primary_id = primary.certificate().claims().device_id_bytes();
    let initial = DeviceRoster::issue(
        &[7; 32],
        1,
        1_792_512_000_000,
        primary_id,
        vec![primary.clone(), linked],
    )
    .unwrap();
    let revoked =
        DeviceRoster::issue(&[7; 32], 2, 1_792_512_000_000, primary_id, vec![primary]).unwrap();
    let verified = api::execute(&serde_json::to_vec(&json!({
        "operation": "verify_roster", "roster": STANDARD.encode(initial.encoded()),
        "pinned_account": STANDARD.encode(initial.account_ed()), "now_ms": initial.issued_at_ms(),
    })).unwrap(), None).unwrap();
    let vector = json!({
        "protocol": "secure-device-authorization-v1", "synthetic_only": true,
        "note": "Authorization codec fixture only. KEM fields are fixed public test bytes, not a live peer.",
        "initial": serde_json::from_slice::<serde_json::Value>(&verified).unwrap(),
        "revoked_roster": STANDARD.encode(revoked.encoded()),
        "account_identity": STANDARD.encode(AccountPublicIdentity::issue(&[7;32],PublicKey::from(&StaticSecret::from([33;32])).to_bytes(),[33;ML_KEM_PUBLIC_LEN]).unwrap().encoded()),
    });
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
