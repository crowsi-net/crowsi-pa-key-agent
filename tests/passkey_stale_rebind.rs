use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_pa_key_agent::{create_passkey_rebind_challenge, passkey_status, rebind_passkey};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{assertion, owner_json, register};

const OLD: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const CURRENT: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";

#[test]
fn existing_authenticator_rebinds_stale_registration() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[18_u8; 32]).into()).expect("P-256 key");
    register(&credential, root.path(), &signing, OLD);
    let status = passkey_status(&credential, CURRENT);
    assert_eq!(status.state, "stale");
    assert_eq!(status.reason_code, "pa-passkey-pa-binding-stale");

    let challenge_path = root.path().join("rebind-challenge.json");
    let challenge = create_passkey_rebind_challenge(&credential, &challenge_path, CURRENT)
        .expect("rebind challenge");
    let assertion_path = root.path().join("rebind-assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &signing, 1));
    let receipt =
        rebind_passkey(&challenge_path, &assertion_path, &credential, CURRENT).expect("rebind");

    assert_eq!(receipt.pa_public_key_sha256, CURRENT);
    assert_eq!(receipt.sign_count, 1);
    assert_eq!(passkey_status(&credential, CURRENT).state, "ready");
    assert!(!challenge_path.exists());
    assert!(!assertion_path.exists());
}

#[test]
fn invalid_assertion_preserves_stale_registration_and_evidence() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[19_u8; 32]).into()).expect("P-256 key");
    register(&credential, root.path(), &signing, OLD);
    let before = fs::read(&credential).expect("before");
    let challenge_path = root.path().join("rebind-challenge.json");
    let challenge = create_passkey_rebind_challenge(&credential, &challenge_path, CURRENT)
        .expect("rebind challenge");
    let wrong = SigningKey::from_bytes((&[20_u8; 32]).into()).expect("wrong key");
    let assertion_path = root.path().join("rebind-assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &wrong, 1));

    assert!(rebind_passkey(&challenge_path, &assertion_path, &credential, CURRENT).is_err());
    assert_eq!(fs::read(&credential).expect("after"), before);
    assert!(challenge_path.exists());
    assert!(assertion_path.exists());
}

#[test]
fn current_registration_cannot_enter_rebind_flow() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[21_u8; 32]).into()).expect("P-256 key");
    register(&credential, root.path(), &signing, CURRENT);
    let challenge = root.path().join("rebind-challenge.json");
    assert!(create_passkey_rebind_challenge(&credential, &challenge, CURRENT).is_err());
    assert!(!challenge.exists());
}

fn private_root() -> tempfile::TempDir {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}
