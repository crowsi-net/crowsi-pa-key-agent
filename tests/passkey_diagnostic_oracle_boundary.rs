use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{
    PaKeyError, create_credential_challenge, initialize, issue_credential_authorization, status,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{
    assertion, authorization_files, identity_evidence, owner_json, pa_binding, register, request,
};

#[test]
fn normal_authentication_does_not_expose_registration_diagnostics() {
    let root = tempdir().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    initialize(&store, &state, "memory-test").expect("PA");
    let pa = status(&store, &state).expect("status");
    let binding = pa_binding(&pa.public_key_hex);
    let credential = root.path().join("passkey.json");
    let registered = SigningKey::from_bytes((&[93_u8; 32]).into()).expect("key");
    register(&credential, root.path(), &registered, &binding);

    let request_path = root.path().join("request.json");
    owner_json(&request_path, &request());
    let (identity, identity_status, identity_trust) = identity_evidence(root.path(), "diagnostic");
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
        &binding,
        "http://localhost:4213",
    )
    .expect("challenge");
    let assertion_path = root.path().join("assertion.json");
    let wrong = SigningKey::from_bytes((&[94_u8; 32]).into()).expect("key");
    owner_json(&assertion_path, &assertion(&challenge, &wrong, 1));

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
    assert!(matches!(result, Err(PaKeyError::UserVerification)));
}
