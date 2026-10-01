use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{
    PaDestructionIntentV1, create_destruction_challenge, destroy_trust_domain_authorized,
    initialize,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support::{owner_json, pa_binding, register};

pub(super) struct Fixture {
    store: MemoryStore,
    _root: tempfile::TempDir,
    state: std::path::PathBuf,
    pub(super) credential: std::path::PathBuf,
    intent: std::path::PathBuf,
    challenge_path: std::path::PathBuf,
    pub(super) assertion: std::path::PathBuf,
    pub(super) signing: SigningKey,
}

impl Fixture {
    pub(super) fn challenge(&self) -> crowsi_pa_key_agent::PasskeyChallengeV1 {
        create_destruction_challenge(
            &self.store,
            &self.state,
            &self.credential,
            &self.intent,
            &self.challenge_path,
        )
        .expect("challenge")
    }

    pub(super) fn finish(
        &self,
    ) -> crowsi_pa_key_agent::Result<crowsi_pa_key_agent::PaAuthorizedTrustDestructionV1> {
        destroy_trust_domain_authorized(
            &self.store,
            &self.state,
            &self.credential,
            &self.intent,
            &self.challenge_path,
            &self.assertion,
        )
    }

    pub(super) fn assert_preserved(&self) {
        for path in [
            &self.state,
            &self.credential,
            &self.intent,
            &self.challenge_path,
            &self.assertion,
        ] {
            assert!(path.exists(), "{} missing", path.display());
        }
    }
}

pub(super) fn fixture(seed: u8) -> Fixture {
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
    let intent = root.path().join("intent.json");
    owner_json(
        &intent,
        &PaDestructionIntentV1 {
            schema: "crowsi://policy-authority/trust-domain-destruction-intent/v1".into(),
            operation_id: "abcdefabcdefabcdefabcdefabcdefab".into(),
            scope: "local-trust-domain".into(),
            expected_public_key_hex: pa.public_key_hex,
            impact_digest_sha256: format!("sha256:{}", "f".repeat(64)),
        },
    );
    Fixture {
        store,
        state,
        credential,
        intent,
        challenge_path: root.path().join("challenge.json"),
        assertion: root.path().join("assertion.json"),
        signing,
        _root: root,
    }
}
