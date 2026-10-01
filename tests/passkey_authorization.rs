use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_local_control_bridge::IpcAuthorizationEnvelopeV2;
use crowsi_pa_key_agent::{
    create_credential_challenge, destroy, initialize, issue_credential_authorization,
    passkey_status,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{
    assertion, authorization_files, identity_evidence, owner_json, pa_binding, register, request,
};

#[test]
fn verified_passkey_issues_one_owner_only_envelope() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("P-256 key");

    let pa = crowsi_pa_key_agent::status(&store, &state).expect("PA status");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let request_path = root.path().join("request.json");
    let request = request();
    owner_json(&request_path, &request);
    let (identity, identity_status, identity_trust) = identity_evidence(root.path(), "primary");
    let challenge_path = root.path().join("authorize-challenge.json");
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
    let output = root.path().join("authorization.json");
    let receipt = issue_credential_authorization(
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
        &output,
    )
    .expect("authorization");

    assert_eq!(receipt.state, "issued");
    assert!(!challenge_path.exists());
    assert!(!assertion_path.exists());
    let envelope: IpcAuthorizationEnvelopeV2 =
        serde_json::from_slice(&fs::read(&output).expect("envelope")).expect("schema");
    assert_eq!(envelope.request, request);
    let document = envelope.authorization.document;
    assert_eq!(document.pairwise_subject, "pairwise:crowsi:owner");
    assert_eq!(document.device_id, "device:primary");
    assert_eq!(document.device_proof_key_ref, "device-proof:primary");
    assert_eq!(document.session_ref, "sref_service_crowsi_primary");
    assert_eq!(document.device_posture_revision, 2);
    assert_eq!(document.subject_revocation_epoch, 1);
    assert_eq!(document.service_revocation_epoch, 2);
    assert_eq!(document.device_revocation_epoch, 3);
    assert_eq!(document.session_revocation_epoch, 4);
    assert_eq!(
        fs::metadata(output).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn a_new_pa_generation_rejects_the_previous_passkey() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let first = initialize(&store, &state, "memory-test").expect("first PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[8_u8; 32]).into()).expect("P-256 key");
    let first_binding = pa_binding(&first.public_key_hex);
    register(&credential, root.path(), &signing, &first_binding);
    assert_eq!(passkey_status(&credential, &first_binding).state, "ready");

    destroy(&store, &state, &first.public_key_hex).expect("simulate interrupted prior reset");
    let second = initialize(&store, &state, "memory-test").expect("second PA");
    let second_binding = pa_binding(&second.public_key_hex);
    assert_eq!(passkey_status(&credential, &second_binding).state, "stale");

    let request_path = root.path().join("new-request.json");
    owner_json(&request_path, &request());
    let (identity, identity_status, identity_trust) =
        identity_evidence(root.path(), "new-generation");
    let challenge_path = root.path().join("new-challenge.json");
    assert!(
        create_credential_challenge(
            authorization_files(
                &state,
                &credential,
                &request_path,
                &identity,
                &identity_status,
                &identity_trust,
            ),
            &challenge_path,
            &second_binding,
            "http://localhost:4213",
        )
        .is_err()
    );
    assert!(!challenge_path.exists());
}
