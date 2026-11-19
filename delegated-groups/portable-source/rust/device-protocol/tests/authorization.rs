use ed25519_dalek::{Signer, SigningKey};
use secure_device_protocol::*;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};

const NOW: u64 = 1_792_512_000_000;
const OWNER: [u8; 32] = [7; 32];

#[test]
fn published_public_fixtures_match_the_normative_validator() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/mobile/device-authorization-v1-vectors.json"
    ))
    .unwrap();
    let initial = STANDARD
        .decode(fixture["initial"]["roster"].as_str().unwrap())
        .unwrap();
    let revoked = STANDARD
        .decode(fixture["revoked_roster"].as_str().unwrap())
        .unwrap();
    let initial = DeviceRoster::verify(&initial, &root()).unwrap();
    let revoked = DeviceRoster::verify(&revoked, &root()).unwrap();
    assert_eq!(initial, roster(1, true));
    assert_eq!(revoked, roster(2, false));
    assert!(revoked.check_update(Some(&initial), NOW).is_ok());
    assert_eq!(
        initial.check_update(Some(&revoked), NOW),
        Err(AuthorizationError::Rollback)
    );
}

fn root() -> [u8; 32] {
    SigningKey::from_bytes(&OWNER).verifying_key().to_bytes()
}

fn onion(tag: u8) -> [u8; 56] {
    let mut decoded = vec![tag; 32];
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(&decoded);
    hash.update([3]);
    decoded.extend_from_slice(&hash.finalize()[..2]);
    decoded.push(3);
    data_encoding::BASE32_NOPAD
        .encode(&decoded)
        .to_ascii_lowercase()
        .as_bytes()
        .try_into()
        .unwrap()
}

fn claims(tag: u8) -> DeviceClaims {
    DeviceClaims {
        account_ed: root(),
        device_ed: SigningKey::from_bytes(&[tag; 32])
            .verifying_key()
            .to_bytes(),
        device_x: PublicKey::from(&StaticSecret::from([tag; 32])).to_bytes(),
        ml_kem_public_hash: Sha256::digest([tag; ML_KEM_PUBLIC_LEN]).into(),
        onion: onion(tag),
        issued_at_ms: NOW,
        expires_at_ms: NOW + MAX_CERTIFICATE_LIFETIME_MS,
        capabilities: ALL_CAPABILITIES,
    }
}

fn entry(tag: u8) -> RosterEntry {
    RosterEntry::new(
        DeviceCertificate::issue(claims(tag), &OWNER).unwrap(),
        [tag; ML_KEM_PUBLIC_LEN],
        format!("Device {tag}"),
    )
    .unwrap()
}

fn roster(epoch: u64, linked: bool) -> DeviceRoster {
    let mut entries = vec![entry(11)];
    if linked {
        entries.push(entry(22));
    }
    DeviceRoster::issue(&OWNER, epoch, NOW, claims(11).device_id_bytes(), entries).unwrap()
}

fn resign_roster(mut bytes: Vec<u8>) -> Vec<u8> {
    let body_len = bytes.len() - 64;
    let signature = SigningKey::from_bytes(&OWNER).sign(
        &[
            b"secure-legion-device-roster-v1\0".as_slice(),
            &bytes[..body_len],
        ]
        .concat(),
    );
    bytes[body_len..].copy_from_slice(&signature.to_bytes());
    bytes
}

#[test]
fn certificates_preserve_existing_vault_ids_and_bind_every_byte() {
    let certificate = DeviceCertificate::issue(claims(11), &OWNER).unwrap();
    assert_eq!(certificate.encoded().len(), 274);
    assert_eq!(certificate.claims().device_id().len(), 43);
    // Independently checked with Python hashlib and PyNaCl's Ed25519/X25519.
    assert_eq!(
        certificate.claims().device_id(),
        "qsznX5VAYRwKRVZd_iBd17i76if5NnOMgLCl5qXVgAQ"
    );
    assert_eq!(
        DeviceCertificate::verify(certificate.encoded(), &root()).unwrap(),
        certificate
    );
    // Includes magic, all public keys, KEM hash, endpoint, times, capabilities,
    // and signature. No changed byte may authenticate.
    for offset in 0..CERTIFICATE_LEN {
        let mut tampered = *certificate.encoded();
        tampered[offset] ^= 1;
        assert!(
            DeviceCertificate::verify(&tampered, &root()).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn certificate_requires_pinned_account_and_matching_issuer() {
    let wrong = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let certificate = DeviceCertificate::issue(claims(11), &OWNER).unwrap();
    assert_eq!(
        DeviceCertificate::verify(certificate.encoded(), &wrong),
        Err(AuthorizationError::WrongAccount)
    );
    assert_eq!(
        DeviceCertificate::issue(claims(11), &[8; 32]),
        Err(AuthorizationError::WrongAccount)
    );
    for len in [0, 1, CERTIFICATE_LEN - 1, CERTIFICATE_LEN + 1] {
        assert_eq!(
            DeviceCertificate::verify(&vec![0; len], &root()),
            Err(AuthorizationError::Malformed)
        );
    }
}

#[test]
fn certificate_rejects_weak_keys_invalid_onions_unknown_scopes_and_bad_lifetimes() {
    let mut bad = claims(11);
    bad.device_ed = [0; 32];
    assert_eq!(
        DeviceCertificate::issue(bad, &OWNER),
        Err(AuthorizationError::InvalidKey)
    );
    for x in [
        [0; 32],
        {
            let mut x = [0; 32];
            x[0] = 1;
            x
        },
        [0xff; 32],
        {
            let mut p = [0xff; 32];
            p[0] = 0xed;
            p[31] = 0x7f;
            p
        },
    ] {
        let mut bad = claims(11);
        bad.device_x = x;
        assert_eq!(
            DeviceCertificate::issue(bad, &OWNER),
            Err(AuthorizationError::InvalidKey)
        );
    }
    for bad_onion in [[b'a'; 56], [b'A'; 56], [b'1'; 56], {
        let mut bad = onion(11);
        bad[0] = if bad[0] == b'a' { b'b' } else { b'a' };
        bad
    }] {
        let mut bad = claims(11);
        bad.onion = bad_onion;
        assert_eq!(
            DeviceCertificate::issue(bad, &OWNER),
            Err(AuthorizationError::Onion)
        );
    }
    for capabilities in [0, 8, u32::MAX] {
        let mut bad = claims(11);
        bad.capabilities = capabilities;
        assert_eq!(
            DeviceCertificate::issue(bad, &OWNER),
            Err(AuthorizationError::Unauthorized)
        );
    }
    for (issued, expires) in [
        (0, NOW),
        (NOW, NOW),
        (NOW, NOW - 1),
        (NOW, MAX_SAFE_INTEGER + 1),
        (NOW, NOW + MAX_CERTIFICATE_LIFETIME_MS + 1),
    ] {
        let mut bad = claims(11);
        bad.issued_at_ms = issued;
        bad.expires_at_ms = expires;
        assert_eq!(
            DeviceCertificate::issue(bad, &OWNER),
            Err(AuthorizationError::Lifetime)
        );
    }
}

#[test]
fn roster_is_canonical_independent_of_input_order_and_rejects_modified_wire() {
    let forward = roster(1, true);
    let reverse = DeviceRoster::issue(
        &OWNER,
        1,
        NOW,
        claims(11).device_id_bytes(),
        vec![entry(22), entry(11)],
    )
    .unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(
        DeviceRoster::verify(forward.encoded(), &root()).unwrap(),
        forward
    );
    for offset in [
        0,
        6,
        38,
        46,
        54,
        86,
        88,
        300,
        2000,
        forward.encoded().len() - 1,
    ] {
        let mut tampered = forward.encoded().to_vec();
        tampered[offset] ^= 1;
        assert!(DeviceRoster::verify(&tampered, &root()).is_err());
    }
    // Even correctly signed noncanonical ordering is invalid.
    let mut bytes = forward.encoded().to_vec();
    let entry_len = CERTIFICATE_LEN + ML_KEM_PUBLIC_LEN + 2 + "Device 11".len();
    let first = bytes[88..88 + entry_len].to_vec();
    let second = bytes[88 + entry_len..88 + 2 * entry_len].to_vec();
    bytes[88..88 + entry_len].copy_from_slice(&second);
    bytes[88 + entry_len..88 + 2 * entry_len].copy_from_slice(&first);
    assert_eq!(
        DeviceRoster::verify(&resign_roster(bytes), &root()),
        Err(AuthorizationError::Order)
    );
}

#[test]
fn roster_bounds_untrusted_lengths_and_rejects_trailing_bytes() {
    let encoded = roster(1, true).encoded().to_vec();
    for len in 0..encoded.len() {
        assert!(
            DeviceRoster::verify(&encoded[..len], &root()).is_err(),
            "prefix {len}"
        );
    }
    assert_eq!(
        DeviceRoster::verify(&vec![0; MAX_ROSTER_LEN + 1], &root()),
        Err(AuthorizationError::Limit)
    );
    let mut count = encoded.clone();
    count[86..88].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        DeviceRoster::verify(&resign_roster(count), &root()),
        Err(AuthorizationError::Limit)
    );
    let mut name = encoded.clone();
    let offset = 88 + CERTIFICATE_LEN + ML_KEM_PUBLIC_LEN;
    name[offset..offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        DeviceRoster::verify(&resign_roster(name), &root()),
        Err(AuthorizationError::Limit)
    );
    let mut trailing = encoded.clone();
    trailing.insert(trailing.len() - 64, 0);
    assert_eq!(
        DeviceRoster::verify(&resign_roster(trailing), &root()),
        Err(AuthorizationError::Malformed)
    );
    let mut wrong_root = root();
    wrong_root[0] ^= 1;
    assert_eq!(
        DeviceRoster::verify(&encoded, &wrong_root),
        Err(AuthorizationError::WrongAccount)
    );
}

#[test]
fn epoch_pinning_prevents_revoked_device_rollback_and_detects_forks() {
    let old = roster(1, true);
    let revoked = roster(2, false);
    let linked_id = claims(22).device_id_bytes();
    assert!(old.active_device(&linked_id, CAP_CHAT, NOW).is_ok());
    assert_eq!(
        revoked.active_device(&linked_id, CAP_CHAT, NOW),
        Err(AuthorizationError::Unauthorized)
    );
    assert_eq!(
        old.check_update(Some(&revoked), NOW),
        Err(AuthorizationError::Rollback)
    );
    assert!(revoked.check_update(Some(&old), NOW).is_ok());
    assert!(old.check_update(Some(&old), NOW).is_ok());
    assert_eq!(
        roster(1, false).check_update(Some(&old), NOW),
        Err(AuthorizationError::Fork)
    );
    let older_time = DeviceRoster::issue(
        &OWNER,
        3,
        NOW - 1,
        claims(11).device_id_bytes(),
        vec![{
            let mut c = claims(11);
            c.issued_at_ms = NOW - 2;
            c.expires_at_ms = c.issued_at_ms + MAX_CERTIFICATE_LIFETIME_MS;
            RosterEntry::new(
                DeviceCertificate::issue(c, &OWNER).unwrap(),
                [11; ML_KEM_PUBLIC_LEN],
                "Primary".to_owned(),
            )
            .unwrap()
        }],
    )
    .unwrap();
    assert_eq!(
        older_time.check_update(Some(&revoked), NOW),
        Err(AuthorizationError::Rollback)
    );
}

#[test]
fn live_authorization_enforces_expiry_clock_bounds_and_each_scope() {
    let primary = entry(11);
    let mut limited = claims(22);
    limited.capabilities = CAP_SYNC;
    let limited = RosterEntry::new(
        DeviceCertificate::issue(limited, &OWNER).unwrap(),
        [22; ML_KEM_PUBLIC_LEN],
        "Linked".to_owned(),
    )
    .unwrap();
    let roster = DeviceRoster::issue(
        &OWNER,
        1,
        NOW,
        claims(11).device_id_bytes(),
        vec![primary, limited],
    )
    .unwrap();
    let id = claims(22).device_id_bytes();
    assert!(roster.active_device(&id, CAP_SYNC, NOW).is_ok());
    for caps in [0, CAP_CHAT, CAP_GROUPS, CAP_CHAT | CAP_SYNC, 8] {
        assert_eq!(
            roster.active_device(&id, caps, NOW),
            Err(AuthorizationError::Unauthorized)
        );
    }
    assert!(roster
        .active_device(&id, CAP_SYNC, NOW - CLOCK_SKEW_MS)
        .is_ok());
    assert_eq!(
        roster.active_device(&id, CAP_SYNC, NOW - CLOCK_SKEW_MS - 1),
        Err(AuthorizationError::Inactive)
    );
    assert_eq!(
        roster.active_device(&id, CAP_SYNC, NOW + MAX_CERTIFICATE_LIFETIME_MS),
        Err(AuthorizationError::Inactive)
    );
    assert_eq!(
        roster.active_device(&id, CAP_SYNC, 0),
        Err(AuthorizationError::Inactive)
    );
}

#[test]
fn roster_rejects_duplicate_keys_bad_names_missing_primary_and_kem_substitution() {
    assert_eq!(
        DeviceRoster::issue(
            &OWNER,
            1,
            NOW,
            claims(11).device_id_bytes(),
            vec![entry(11), entry(11)]
        ),
        Err(AuthorizationError::Order)
    );
    let mut duplicate = claims(22);
    duplicate.device_ed = claims(11).device_ed;
    let duplicate = RosterEntry::new(
        DeviceCertificate::issue(duplicate, &OWNER).unwrap(),
        [22; ML_KEM_PUBLIC_LEN],
        "Duplicate".to_owned(),
    )
    .unwrap();
    assert_eq!(
        DeviceRoster::issue(
            &OWNER,
            1,
            NOW,
            claims(11).device_id_bytes(),
            vec![entry(11), duplicate]
        ),
        Err(AuthorizationError::Order)
    );
    assert_eq!(
        DeviceRoster::issue(&OWNER, 1, NOW, [0; 32], vec![entry(11)]),
        Err(AuthorizationError::Unauthorized)
    );
    assert_eq!(
        RosterEntry::new(
            DeviceCertificate::issue(claims(11), &OWNER).unwrap(),
            [22; ML_KEM_PUBLIC_LEN],
            "Changed KEM".to_owned()
        ),
        Err(AuthorizationError::InvalidKey)
    );
    for name in [
        "".to_owned(),
        "a\0b".to_owned(),
        "New\nDevice".to_owned(),
        "a".repeat(129),
        "😀".repeat(129),
    ] {
        assert_eq!(
            RosterEntry::new(
                DeviceCertificate::issue(claims(11), &OWNER).unwrap(),
                [11; ML_KEM_PUBLIC_LEN],
                name
            ),
            Err(AuthorizationError::Malformed)
        );
    }
    for epoch in [0, MAX_SAFE_INTEGER + 1] {
        assert_eq!(
            DeviceRoster::issue(
                &OWNER,
                epoch,
                NOW,
                claims(11).device_id_bytes(),
                vec![entry(11)]
            ),
            Err(AuthorizationError::Malformed)
        );
    }
    assert_eq!(
        DeviceRoster::issue(&OWNER, 1, NOW, claims(11).device_id_bytes(), vec![]),
        Err(AuthorizationError::Limit)
    );
    assert_eq!(
        DeviceRoster::issue(
            &OWNER,
            1,
            NOW,
            claims(11).device_id_bytes(),
            (11..20).map(entry).collect()
        ),
        Err(AuthorizationError::Limit)
    );
}
