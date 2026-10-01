#![cfg(feature = "bootstrap-authorizer-internal")]

use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_pa_key_agent::{create_challenge, stage_passkey_registration};
use p256::ecdsa::SigningKey;
use serde_json::json;

#[path = "passkey_recovery_registration/support.rs"]
mod recovery_support;
use crate::support;
use recovery_support::{private_root, retired_files};
use support::{owner_json, register, registration::registration_response};

const BINDING: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

#[test]
fn unrecognized_state_requires_scoped_revoke_before_fresh_registration() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    let unrecognized = br#"{"schema":"unrecognized-passkey","public":"metadata"}"#;
    fs::write(&credential, unrecognized).expect("unrecognized state");
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).expect("mode");
    let signing = SigningKey::from_bytes((&[12_u8; 32]).into()).expect("P-256 key");

    let (challenge, response) = ceremony(root.path(), &signing);

    assert!(stage_only(&challenge, &response, &credential, root.path()).is_err());
    assert!(retired_files(root.path()).is_empty());
    assert_eq!(fs::read(&credential).expect("preserved"), unrecognized);
}

#[test]
fn invalid_webauthn_evidence_never_replaces_existing_state() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    owner_json(&credential, &json!({ "schema": "unrecognized-passkey" }));
    let before = fs::read(&credential).expect("before");
    let signing = SigningKey::from_bytes((&[13_u8; 32]).into()).expect("P-256 key");
    let (challenge, response) = ceremony(root.path(), &signing);
    let mut invalid = registration_response_value(&response);
    invalid["client_data_json_b64url"] = json!("aW52YWxpZA");
    owner_json(&response, &invalid);

    assert!(stage_only(&challenge, &response, &credential, root.path()).is_err());
    assert_eq!(fs::read(&credential).expect("after"), before);
    assert!(retired_files(root.path()).is_empty());
}

#[test]
fn current_valid_registration_cannot_be_overwritten() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    let first = SigningKey::from_bytes((&[14_u8; 32]).into()).expect("first key");
    register(&credential, root.path(), &first, BINDING);
    let before = fs::read(&credential).expect("before");
    let second = SigningKey::from_bytes((&[15_u8; 32]).into()).expect("second key");
    let (challenge, response) = ceremony(root.path(), &second);

    assert!(stage_only(&challenge, &response, &credential, root.path()).is_err());
    assert_eq!(fs::read(&credential).expect("after"), before);
    assert!(retired_files(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn unsafe_existing_registration_path_is_rejected_without_touching_target() {
    use std::os::unix::fs::symlink;
    let root = private_root();
    let target = root.path().join("outside.json");
    owner_json(&target, &json!({ "schema": "must-remain" }));
    let credential = root.path().join("passkey.json");
    symlink(&target, &credential).expect("symlink");
    let signing = SigningKey::from_bytes((&[16_u8; 32]).into()).expect("P-256 key");
    let (challenge, response) = ceremony(root.path(), &signing);

    assert!(stage_only(&challenge, &response, &credential, root.path()).is_err());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&target).expect("target"))
            .expect("JSON")["schema"],
        "must-remain"
    );
    assert!(retired_files(root.path()).is_empty());
}

#[test]
fn permissive_existing_registration_is_rejected_before_evidence_consumption() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    fs::write(&credential, b"unrecognized").expect("unrecognized state");
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o644)).expect("mode");
    let signing = SigningKey::from_bytes((&[17_u8; 32]).into()).expect("P-256 key");
    let (challenge, response) = ceremony(root.path(), &signing);

    assert!(stage_only(&challenge, &response, &credential, root.path()).is_err());
    assert_eq!(fs::read(&credential).expect("after"), b"unrecognized");
    assert!(challenge.exists());
    assert!(response.exists());
    assert!(retired_files(root.path()).is_empty());
}

fn ceremony(
    root: &std::path::Path,
    signing: &SigningKey,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let challenge_path = root.join("fresh-challenge.json");
    let challenge = create_challenge(
        &challenge_path,
        "register",
        "localhost",
        "http://localhost:4173",
        BINDING,
    )
    .expect("challenge");
    let response_path = root.join("fresh-response.json");
    owner_json(&response_path, &registration_response(&challenge, signing));
    (challenge_path, response_path)
}

fn stage_only(
    challenge: &std::path::Path,
    response: &std::path::Path,
    credential: &std::path::Path,
    root: &std::path::Path,
) -> crowsi_pa_key_agent::Result<crowsi_pa_key_agent::PasskeyChallengeV1> {
    stage_passkey_registration(
        challenge,
        response,
        &root.join("candidate.json"),
        &root.join("proof.json"),
        credential,
        BINDING,
    )
}

fn registration_response_value(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).expect("response")).expect("JSON")
}
