use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{
    PaKeyError, create_credential_challenge, initialize, issue_credential_authorization,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support::{
    assertion, authorization_files, identity_evidence, owner_json, pa_binding, register, request,
    share_identity_trust_key,
};

#[test]
fn altered_device_identity_is_rejected_without_consuming_user_proof() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[55_u8; 32]).into()).expect("P-256 key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let request_path = root.path().join("request.json");
    owner_json(&request_path, &request());
    let (identity, identity_status, identity_trust) = identity_evidence(root.path(), "original");
    let challenge_path = root.path().join("challenge.json");
    let challenge = create_credential_challenge(
        authorization_files(
            &state,
            &credential,
            &request_path,
            &identity,
            &identity_status,
            &identity_trust,
        ),
        &challenge_path,
        &pa_binding(&pa.public_key_hex),
        "http://localhost:4213",
    )
    .expect("challenge");
    let assertion_path = root.path().join("assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &signing, 1));

    let mut altered: serde_json::Value =
        serde_json::from_slice(&fs::read(&identity).expect("identity")).expect("json");
    altered["device_id"] = "device:attacker".into();
    owner_json(&identity, &altered);
    let result = issue_credential_authorization(
        &store,
        authorization_files(
            &state,
            &credential,
            &request_path,
            &identity,
            &identity_status,
            &identity_trust,
        ),
        &challenge_path,
        &assertion_path,
        &root.path().join("authorization.json"),
    );
    assert!(matches!(result, Err(PaKeyError::Authorization)));
    assert!(challenge_path.exists());
    assert!(assertion_path.exists());
}

#[test]
// PA-05: assertion signing authority cannot forge current revocation status.
fn pa_05_assertion_and_status_trust_keys_must_be_distinct() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[59_u8; 32]).into()).expect("P-256 key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let request_path = root.path().join("request.json");
    owner_json(&request_path, &request());
    let (identity, status, trust) = identity_evidence(root.path(), "shared-trust-key");
    share_identity_trust_key(&status, &trust);
    assert!(matches!(
        create_credential_challenge(
            authorization_files(
                &state,
                &credential,
                &request_path,
                &identity,
                &status,
                &trust
            ),
            &root.path().join("challenge.json"),
            &pa_binding(&pa.public_key_hex),
            "http://localhost:4213",
        ),
        Err(PaKeyError::Authorization)
    ));
}
