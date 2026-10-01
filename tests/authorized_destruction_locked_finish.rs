use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicBool, Ordering},
};

use crowsi_credential_broker::{
    BrokerError, CredentialEntry, CredentialMetadata, CredentialStore, MemoryStore, Result,
    SecretRef,
};
use crowsi_pa_key_agent::{
    PaDestructionIntentV1, create_destruction_challenge, destroy_trust_domain_authorized,
    initialize,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support;
use support::{assertion, owner_json, pa_binding, register};

#[test]
fn custody_denial_before_finish_preserves_all_state_and_evidence() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = LockableStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[51_u8; 32]).into()).expect("key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let intent_path = root.path().join("intent.json");
    owner_json(&intent_path, &intent(&pa.public_key_hex));
    let challenge_path = root.path().join("challenge.json");
    let challenge =
        create_destruction_challenge(&store, &state, &credential, &intent_path, &challenge_path)
            .expect("challenge");
    let assertion_path = root.path().join("assertion.json");
    owner_json(&assertion_path, &assertion(&challenge, &signing, 1));
    store.locked.store(true, Ordering::SeqCst);

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
    for path in [
        &state,
        &credential,
        &intent_path,
        &challenge_path,
        &assertion_path,
    ] {
        assert!(path.exists(), "{} missing", path.display());
    }
}

#[test]
fn custody_denial_prevents_challenge_creation_without_mutation() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = LockableStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[52_u8; 32]).into()).expect("key");
    register(
        &credential,
        root.path(),
        &signing,
        &pa_binding(&pa.public_key_hex),
    );
    let intent_path = root.path().join("intent.json");
    owner_json(&intent_path, &intent(&pa.public_key_hex));
    let challenge_path = root.path().join("challenge.json");
    store.locked.store(true, Ordering::SeqCst);

    assert!(
        create_destruction_challenge(&store, &state, &credential, &intent_path, &challenge_path,)
            .is_err()
    );
    assert!(state.exists() && credential.exists() && intent_path.exists());
    assert!(!challenge_path.exists());
}

#[derive(Default)]
struct LockableStore {
    inner: MemoryStore,
    locked: AtomicBool,
}

impl CredentialStore for LockableStore {
    fn put(&self, entry: CredentialEntry) -> Result<()> {
        self.inner.put(entry)
    }
    fn metadata(&self, reference: &SecretRef) -> Result<CredentialMetadata> {
        self.available()?;
        self.inner.metadata(reference)
    }
    fn get(&self, reference: &SecretRef, revision: &str) -> Result<CredentialEntry> {
        self.available()?;
        self.inner.get(reference, revision)
    }
    fn delete(&self, reference: &SecretRef) -> Result<()> {
        self.available()?;
        self.inner.delete(reference)
    }
}

impl LockableStore {
    fn available(&self) -> Result<()> {
        (!self.locked.load(Ordering::SeqCst))
            .then_some(())
            .ok_or(BrokerError::BackendDenied)
    }
}

fn intent(public_key: &str) -> PaDestructionIntentV1 {
    PaDestructionIntentV1 {
        schema: "crowsi://policy-authority/trust-domain-destruction-intent/v1".into(),
        operation_id: "99990000111122223333444455556666".into(),
        scope: "local-trust-domain".into(),
        expected_public_key_hex: public_key.into(),
        impact_digest_sha256: format!("sha256:{}", "e".repeat(64)),
    }
}
