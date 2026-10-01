use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_local_control_bridge::{BridgeAction, ControlRequestV1, IpcAuthorizationEnvelopeV2};
use crowsi_pa_key_agent::{
    create_credential_challenge, initialize, issue_credential_authorization,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{
    assertion, authorization_files, identity_evidence, owner_json, pa_binding, register,
};

#[test]
fn verified_owner_can_issue_one_exact_github_observer_envelope() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[31_u8; 32]).into()).expect("P-256 key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );

    let request = github_request();
    let request_path = root.path().join("github-request.json");
    owner_json(&request_path, &request);
    let (identity, identity_status, identity_trust) = identity_evidence(root.path(), "github");
    let challenge_path = root.path().join("github-challenge.json");
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
    .expect("GitHub challenge");
    assert_eq!(challenge.operation, "github-provider-observe");
    let assertion_path = root.path().join("github-assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &signing, 1));
    let output = root.path().join("github-authorization.json");

    issue_credential_authorization(
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
    .expect("GitHub authorization");

    let envelope: IpcAuthorizationEnvelopeV2 =
        serde_json::from_slice(&fs::read(output).expect("envelope")).expect("schema");
    assert_eq!(envelope.request, request);
    assert_eq!(
        envelope.authorization.document.workload_id,
        "spiffe://crowsi/local/coela-github-app"
    );
    assert_eq!(
        envelope.authorization.document.actor_profile_id,
        "profile-github-observer-operator"
    );
    assert!(envelope.authorization.document.user_verification);
}

#[test]
fn github_observer_policy_rejects_broader_resources_and_purposes() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[32_u8; 32]).into()).expect("P-256 key");
    let binding = pa_binding(&pa.public_key_hex);
    register(&credential, root.path(), &signing, &binding);
    for request in [
        ControlRequestV1 {
            resource: "crowsi://credentials/github-app".into(),
            ..github_request()
        },
        ControlRequestV1 {
            purpose: "repository-write".into(),
            ..github_request()
        },
    ] {
        let request_path = root.path().join(format!("{}.json", request.purpose));
        owner_json(&request_path, &request);
        let (identity, identity_status, identity_trust) =
            identity_evidence(root.path(), &request.request_id);
        let result = create_credential_challenge(
            authorization_files(
                &state,
                &credential,
                &request_path,
                &identity,
                &identity_status,
                &identity_trust,
            ),
            &root.path().join(format!("{}.challenge", request.purpose)),
            &binding,
            "http://localhost:4213",
        );
        assert!(result.is_err());
    }
}

fn github_request() -> ControlRequestV1 {
    ControlRequestV1 {
        schema: "crowsi://local-control/request/v1".into(),
        request_id: "request-github-observe-1".into(),
        action: BridgeAction::ObserveProvider,
        resource: "crowsi://credentials/github-app/github-repository-observer-coela".into(),
        purpose: "github-app-jwt-signing".into(),
        body_sha256: format!("sha256:{}", "b".repeat(64)),
    }
}
