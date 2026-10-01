use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{
    PaDestructionIntentV1, destroy_trust_domain_authorized, destruction_intent_digest, initialize,
    preflight_trust_domain_destruction,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{assertion, local_challenge, owner_json, pa_binding, register};

#[test]
fn wrong_operation_is_rejected_before_evidence_consumption() {
    let fixture = fixture(41);
    let challenge = local_challenge(
        &fixture.challenge,
        "credential-enroll",
        &destruction_intent_digest(&fixture.intent),
    );
    owner_json(
        &fixture.assertion,
        &assertion(&challenge, &fixture.signing, 1),
    );

    assert!(finish(&fixture).is_err());
    fixture.assert_preserved();
}

#[test]
fn invalid_signature_preserves_the_trust_domain() {
    let fixture = fixture(42);
    let challenge = crowsi_pa_key_agent::create_destruction_challenge(
        &fixture.store,
        &fixture.state,
        &fixture.credential,
        &fixture.intent_path,
        &fixture.challenge,
    )
    .expect("challenge");
    let wrong_key = SigningKey::from_bytes((&[43_u8; 32]).into()).expect("wrong key");
    owner_json(&fixture.assertion, &assertion(&challenge, &wrong_key, 1));

    assert!(finish(&fixture).is_err());
    fixture.assert_preserved();
}

#[test]
fn closed_intent_rejects_unknown_fields_without_mutation() {
    let fixture = fixture(44);
    let mut value = serde_json::to_value(&fixture.intent).expect("intent JSON");
    value["unreviewed_scope"] = serde_json::json!("all-services");
    owner_json(&fixture.intent_path, &value);

    assert!(
        preflight_trust_domain_destruction(
            &fixture.store,
            &fixture.state,
            &fixture.credential,
            &fixture.intent_path,
        )
        .is_err()
    );
    assert!(fixture.state.exists());
    assert!(fixture.credential.exists());
    assert!(fixture.intent_path.exists());
}

struct Fixture {
    store: MemoryStore,
    _root: tempfile::TempDir,
    state: std::path::PathBuf,
    credential: std::path::PathBuf,
    intent_path: std::path::PathBuf,
    challenge: std::path::PathBuf,
    assertion: std::path::PathBuf,
    intent: PaDestructionIntentV1,
    signing: SigningKey,
}

impl Fixture {
    fn assert_preserved(&self) {
        for path in [
            &self.state,
            &self.credential,
            &self.intent_path,
            &self.challenge,
            &self.assertion,
        ] {
            assert!(path.exists(), "{} missing", path.display());
        }
    }
}

fn fixture(seed: u8) -> Fixture {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[seed; 32]).into()).expect("key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let intent = intent(&pa.public_key_hex);
    let intent_path = root.path().join("intent.json");
    owner_json(&intent_path, &intent);
    Fixture {
        store,
        state,
        credential,
        intent_path,
        challenge: root.path().join("challenge.json"),
        assertion: root.path().join("assertion.json"),
        intent,
        signing,
        _root: root,
    }
}

fn finish(
    fixture: &Fixture,
) -> crowsi_pa_key_agent::Result<crowsi_pa_key_agent::PaAuthorizedTrustDestructionV1> {
    destroy_trust_domain_authorized(
        &fixture.store,
        &fixture.state,
        &fixture.credential,
        &fixture.intent_path,
        &fixture.challenge,
        &fixture.assertion,
    )
}

fn intent(public_key: &str) -> PaDestructionIntentV1 {
    PaDestructionIntentV1 {
        schema: "crowsi://policy-authority/trust-domain-destruction-intent/v1".into(),
        operation_id: "11112222333344445555666677778888".into(),
        scope: "local-trust-domain".into(),
        expected_public_key_hex: public_key.into(),
        impact_digest_sha256: format!("sha256:{}", "d".repeat(64)),
    }
}
