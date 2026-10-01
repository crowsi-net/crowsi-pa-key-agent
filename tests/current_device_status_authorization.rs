use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, thread};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{PaKeyError, create_credential_challenge, initialize};
use ed25519_dalek::{Signer as _, SigningKey as IdentitySigningKey};
use ihat_identity_assertion_contracts::{CurrentDeviceStatusV1, canonical_current_status_payload};
use p256::ecdsa::SigningKey;
use tempfile::{TempDir, tempdir};

use crate::support::{
    authorization_files, identity_evidence, owner_json, pa_binding, register, request,
};

struct Fixture {
    root: TempDir,
    state: PathBuf,
    credential: PathBuf,
    request: PathBuf,
    identity: PathBuf,
    status: PathBuf,
    trust: PathBuf,
    binding: String,
}

impl Fixture {
    fn challenge(&self, name: &str) -> Result<(), PaKeyError> {
        create_credential_challenge(
            authorization_files(
                &self.state,
                &self.credential,
                &self.request,
                &self.identity,
                &self.status,
                &self.trust,
            ),
            &self.root.path().join(name),
            &self.binding,
            "http://localhost:4213",
        )
        .map(|_| ())
    }
}

#[test]
// PA-01: revocation freshness is independently signed and assertion-bound.
fn pa_01_current_status_rejects_a_still_signed_stale_device_assertion() {
    let fixture = fixture("revoked");
    let mut status: CurrentDeviceStatusV1 =
        serde_json::from_slice(&fs::read(&fixture.status).expect("status")).expect("JSON");
    status.revocation_epochs.device += 1;
    let signer = IdentitySigningKey::from_bytes(&[42; 32]);
    status.signature = hex::encode(
        signer
            .sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    owner_json(&fixture.status, &status);
    assert!(matches!(
        fixture.challenge("challenge.json"),
        Err(PaKeyError::Authorization)
    ));
}

#[test]
// PA-02: a fresh status nonce authorizes at most one PA challenge after reopen.
fn pa_02_current_status_nonce_is_durably_one_use() {
    let fixture = fixture("one-use");
    fixture
        .challenge("challenge-a.json")
        .expect("first challenge");
    assert!(matches!(
        fixture.challenge("challenge-b.json"),
        Err(PaKeyError::Authorization)
    ));
}

#[test]
// PA-03: concurrent consumption has exactly one winner.
fn pa_03_current_status_nonce_has_one_concurrent_winner() {
    let fixture = fixture("concurrent");
    let inputs = ["challenge-a.json", "challenge-b.json"].map(|name| {
        let state = fixture.state.clone();
        let credential = fixture.credential.clone();
        let request = fixture.request.clone();
        let identity = fixture.identity.clone();
        let status = fixture.status.clone();
        let trust = fixture.trust.clone();
        let output = fixture.root.path().join(name);
        let binding = fixture.binding.clone();
        thread::spawn(move || {
            create_credential_challenge(
                authorization_files(&state, &credential, &request, &identity, &status, &trust),
                &output,
                &binding,
                "http://localhost:4213",
            )
        })
    });
    let results = inputs.map(|handle| handle.join().expect("thread"));
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PaKeyError::Authorization)))
            .count(),
        1
    );
}

#[test]
// PA-04: a substituted nonce ledger is rejected before challenge creation.
fn pa_04_nonce_ledger_symlink_is_rejected() {
    let fixture = fixture("ledger-symlink");
    let outside = fixture.root.path().join("outside");
    fs::create_dir(&outside).expect("outside");
    std::os::unix::fs::symlink(
        &outside,
        fixture.root.path().join(".identity-status-nonces-v1"),
    )
    .expect("symlink");
    assert!(matches!(
        fixture.challenge("challenge.json"),
        Err(PaKeyError::UnsafePath)
    ));
}

fn fixture(suffix: &str) -> Fixture {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let store = MemoryStore::default();
    let state = root.path().join("pa.json");
    let pa = initialize(&store, &state, "memory-test").expect("PA");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[58_u8; 32]).into()).expect("P-256 key");
    let binding = pa_binding(&pa.public_key_hex);
    register(&credential, root.path(), &signing, &binding);
    let request_path = root.path().join("request.json");
    owner_json(&request_path, &request());
    let (identity, status, trust) = identity_evidence(root.path(), suffix);
    Fixture {
        root,
        state,
        credential,
        request: request_path,
        identity,
        status,
        trust,
        binding,
    }
}
