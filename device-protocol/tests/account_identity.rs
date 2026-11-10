use ed25519_dalek::SigningKey;
use secure_device_protocol::*;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn published_account_identity_fixture_matches_the_portable_codec() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/device-authorization-v1-vectors.json"
    ))
    .unwrap();
    let encoded = STANDARD
        .decode(fixture["account_identity"].as_str().unwrap())
        .unwrap();
    let identity = AccountPublicIdentity::issue(
        &[7; 32],
        PublicKey::from(&StaticSecret::from([33; 32])).to_bytes(),
        [33; ML_KEM_PUBLIC_LEN],
    )
    .unwrap();
    assert_eq!(identity.encoded().as_slice(), encoded);
    assert_eq!(
        AccountPublicIdentity::verify(&encoded, identity.account_ed()).unwrap(),
        identity
    );
}

#[test]
fn account_identity_authenticates_legacy_public_tuple_without_private_material() {
    let seed = [7; 32];
    let root = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let x = PublicKey::from(&StaticSecret::from([19; 32])).to_bytes();
    let identity = AccountPublicIdentity::issue(&seed, x, [23; ML_KEM_PUBLIC_LEN]).unwrap();
    assert_eq!(identity.encoded().len(), 1702);
    assert_eq!(identity.account_ed(), &root);
    assert_eq!(identity.account_x(), &x);
    assert_eq!(
        AccountPublicIdentity::verify(identity.encoded(), &root).unwrap(),
        identity
    );
    // Changes anywhere in the public tuple or signature fail authentication.
    for offset in [0, 6, 38, 70, 1000, 1638, 1701] {
        let mut changed = *identity.encoded();
        changed[offset] ^= 1;
        assert!(AccountPublicIdentity::verify(&changed, &root).is_err());
    }
    let wrong = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    assert_eq!(
        AccountPublicIdentity::verify(identity.encoded(), &wrong),
        Err(AuthorizationError::WrongAccount)
    );
    for len in [0, 1, 1701, 1703] {
        assert_eq!(
            AccountPublicIdentity::verify(&vec![0; len], &root),
            Err(AuthorizationError::Malformed)
        );
    }
    assert_eq!(
        AccountPublicIdentity::issue(&seed, [0; 32], [23; ML_KEM_PUBLIC_LEN]),
        Err(AuthorizationError::InvalidKey)
    );
}

#[test]
fn onion_address_is_the_standard_ed25519_seed_service_identity() {
    let service = SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes();
    assert_eq!(
        onion_from_public_key(&service).unwrap(),
        "m27h4mzmpjctgmv5tufh67nqkx24l3y2a2w2m3mywop3naimi45n2uid.onion"
    );
    assert_eq!(
        onion_from_public_key(&[0; 32]),
        Err(AuthorizationError::InvalidKey)
    );
}
