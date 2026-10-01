use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{
    PaDestructionIntentV1, destroy, destroy_trust_domain_authorized, initialize,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{assertion, local_challenge, owner_json, pa_binding, register};

#[test]
fn old_passkey_generation_preserves_current_authority() {
    let root = private_root();
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let old = initialize(&store, &state, "memory-test").expect("old PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[31_u8; 32]).into()).expect("key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&old.public_key_hex),
    );
    destroy(&store, &state, &old.public_key_hex).expect("interrupted prior reset");
    let current = initialize(&store, &state, "memory-test").expect("new PA");
    let intent_path = root.path().join("intent.json");
    owner_json(&intent_path, &intent(&current.public_key_hex));
    let challenge_path = root.path().join("challenge.json");
    let challenge = local_challenge(
        &challenge_path,
        "credential-enroll",
        &format!("sha256:{}", "b".repeat(64)),
    );
    let assertion_path = root.path().join("assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &signing, 1));

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
    assert_eq!(
        crowsi_pa_key_agent::status(&store, &state)
            .expect("current")
            .public_key_hex,
        current.public_key_hex
    );
    assert_all_present([
        &state,
        &credential,
        &intent_path,
        &challenge_path,
        &assertion_path,
    ]);
}

fn intent(public_key: &str) -> PaDestructionIntentV1 {
    PaDestructionIntentV1 {
        schema: "crowsi://policy-authority/trust-domain-destruction-intent/v1".into(),
        operation_id: "fedcba9876543210fedcba9876543210".into(),
        scope: "local-trust-domain".into(),
        expected_public_key_hex: public_key.into(),
        impact_digest_sha256: format!("sha256:{}", "c".repeat(64)),
    }
}

fn private_root() -> tempfile::TempDir {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}

fn assert_all_present<const N: usize>(paths: [&std::path::Path; N]) {
    assert!(paths.into_iter().all(std::path::Path::exists));
}
