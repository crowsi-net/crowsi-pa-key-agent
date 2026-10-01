use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{
    PaDestructionIntentV1, create_destruction_challenge, destroy_trust_domain_authorized,
    initialize, preflight_trust_domain_destruction,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{assertion, owner_json, pa_binding, register};

const IMPACT: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn passkey_authorizes_one_exact_local_trust_domain_destruction() {
    let root = private_root();
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[21_u8; 32]).into()).expect("P-256 key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let intent_path = root.path().join("destruction-intent.json");
    let intent = intent(&pa.public_key_hex, "0123456789abcdef0123456789abcdef");
    owner_json(&intent_path, &intent);

    let preflight = preflight_trust_domain_destruction(&store, &state, &credential, &intent_path)
        .expect("preflight");
    assert_eq!(preflight.operation_id, intent.operation_id);
    let challenge_path = root.path().join("destruction-challenge.json");
    let challenge =
        create_destruction_challenge(&store, &state, &credential, &intent_path, &challenge_path)
            .expect("challenge");
    assert_eq!(challenge.operation, "trust-domain-destroy");
    assert_eq!(challenge.binding_sha256, preflight.intent_digest_sha256);
    let assertion_path = root.path().join("destruction-assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &signing, 1));

    let receipt = destroy_trust_domain_authorized(
        &store,
        &state,
        &credential,
        &intent_path,
        &challenge_path,
        &assertion_path,
    )
    .expect("authorized destruction");

    assert_eq!(receipt.operation_id, intent.operation_id);
    assert_eq!(receipt.impact_digest_sha256, IMPACT);
    assert_eq!(receipt.passkey_registration, "revoked");
    for path in [
        &state,
        &credential,
        &intent_path,
        &challenge_path,
        &assertion_path,
    ] {
        assert!(!path.exists(), "{} remains", path.display());
    }
}

#[test]
fn tampered_intent_preserves_authority_and_authorization_evidence() {
    let root = private_root();
    let store = MemoryStore::default();
    let (state, credential, signing, pa) = authority(&store, root.path(), 22);
    let intent_path = root.path().join("intent.json");
    owner_json(
        &intent_path,
        &intent(&pa.public_key_hex, "1".repeat(32).as_str()),
    );
    let challenge_path = root.path().join("challenge.json");
    let challenge =
        create_destruction_challenge(&store, &state, &credential, &intent_path, &challenge_path)
            .expect("challenge");
    owner_json(
        &intent_path,
        &intent(&pa.public_key_hex, "2".repeat(32).as_str()),
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
    assert_all_present([
        &state,
        &credential,
        &intent_path,
        &challenge_path,
        &assertion_path,
    ]);
}

fn authority(
    store: &MemoryStore,
    root: &std::path::Path,
    seed: u8,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    SigningKey,
    crowsi_pa_key_agent::PaKeyStateV1,
) {
    let state = root.join("pa.json");
    let pa = initialize(store, &state, "memory-test").expect("PA");
    let credential = root.join("passkey.json");
    let signing = SigningKey::from_bytes((&[seed; 32]).into()).expect("P-256 key");
    register(&credential, root, &signing, &pa_binding(&pa.public_key_hex));
    (state, credential, signing, pa)
}

fn intent(public_key: &str, operation_id: &str) -> PaDestructionIntentV1 {
    PaDestructionIntentV1 {
        schema: "crowsi://policy-authority/trust-domain-destruction-intent/v1".into(),
        operation_id: operation_id.into(),
        scope: "local-trust-domain".into(),
        expected_public_key_hex: public_key.into(),
        impact_digest_sha256: IMPACT.into(),
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
