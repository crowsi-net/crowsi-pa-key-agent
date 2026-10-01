use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{
    PaDestructionIntentV1, create_destruction_challenge, destroy_trust_domain_authorized,
    initialize,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{assertion, owner_json, pa_binding, register};

#[test]
fn consumed_destruction_evidence_cannot_be_replayed() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[71_u8; 32]).into()).expect("key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let intent = PaDestructionIntentV1 {
        schema: "crowsi://policy-authority/trust-domain-destruction-intent/v1".into(),
        operation_id: "12341234123412341234123412341234".into(),
        scope: "local-trust-domain".into(),
        expected_public_key_hex: pa.public_key_hex,
        impact_digest_sha256: format!("sha256:{}", "7".repeat(64)),
    };
    let intent_path = root.path().join("intent.json");
    owner_json(&intent_path, &intent);
    let challenge_path = root.path().join("challenge.json");
    let challenge =
        create_destruction_challenge(&store, &state, &credential, &intent_path, &challenge_path)
            .expect("challenge");
    let assertion_path = root.path().join("assertion.json");
    let assertion = assertion(&challenge, &signing, 1);
    owner_json(&assertion_path, &assertion);

    destroy_trust_domain_authorized(
        &store,
        &state,
        &credential,
        &intent_path,
        &challenge_path,
        &assertion_path,
    )
    .expect("first use");
    owner_json(&intent_path, &intent);
    owner_json(&challenge_path, &challenge);
    owner_json(&assertion_path, &assertion);

    assert!(
        destroy_trust_domain_authorized(
            &store,
            &state,
            &credential,
            &intent_path,
            &challenge_path,
            &assertion_path,
        )
        .is_err()
    );
    assert!(!state.exists());
    assert!(!credential.exists());
    assert!(intent_path.exists());
    assert!(challenge_path.exists());
    assert!(assertion_path.exists());
}
