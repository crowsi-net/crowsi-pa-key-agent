use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_pa_key_agent::{
    authenticate_passkey, create_passkey_authentication_challenge, passkey_status,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support::{assertion, owner_json, register};

mod support;

const CURRENT: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";

#[test]
fn current_passkey_opens_one_session_and_consumes_its_evidence() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[24_u8; 32]).into()).expect("P-256 key");
    register(&credential, root.path(), &signing, CURRENT);
    let challenge_path = root.path().join("authentication-challenge.json");
    let challenge = create_passkey_authentication_challenge(&credential, &challenge_path, CURRENT)
        .expect("challenge");
    let assertion_path = root.path().join("authentication-assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &signing, 1));

    let receipt = authenticate_passkey(&challenge_path, &assertion_path, &credential, CURRENT)
        .expect("authentication");

    assert_eq!(
        receipt.schema,
        "crowsi://policy-authority/passkey-authentication-receipt/v1"
    );
    assert!(!receipt.contains_secret_values);
    assert_eq!(passkey_status(&credential, CURRENT).state, "ready");
    assert!(!challenge_path.exists());
    assert!(!assertion_path.exists());
}

#[test]
fn invalid_authentication_preserves_registered_passkey_and_evidence() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[25_u8; 32]).into()).expect("P-256 key");
    register(&credential, root.path(), &signing, CURRENT);
    let before = fs::read(&credential).expect("before");
    let challenge_path = root.path().join("authentication-challenge.json");
    let challenge = create_passkey_authentication_challenge(&credential, &challenge_path, CURRENT)
        .expect("challenge");
    let assertion_path = root.path().join("authentication-assertion.json");
    let wrong = SigningKey::from_bytes((&[26_u8; 32]).into()).expect("wrong key");
    owner_json(&assertion_path, &assertion(&challenge, &wrong, 1));

    assert!(authenticate_passkey(&challenge_path, &assertion_path, &credential, CURRENT,).is_err());
    assert_eq!(fs::read(&credential).expect("after"), before);
    assert!(challenge_path.exists());
    assert!(assertion_path.exists());
}
