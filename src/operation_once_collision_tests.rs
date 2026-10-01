use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;

use crate::{PaKeyError, operation_once_test_support::Fixture};

#[test]
fn same_request_id_with_a_different_target_proof_is_rejected() {
    let root = private_root();
    let ledger = root.path().join("replay");
    fs::create_dir(&ledger).expect("ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).expect("ledger mode");
    let state_path = root.path().join("state.json");
    let store = MemoryStore::default();
    crate::initialize(&store, &state_path, "test-custody").expect("state");
    let mut fixture = Fixture::new();
    fixture.config.0.replay_directory = ledger.to_string_lossy().into_owned();
    let wire = serde_json::to_vec(&fixture.request).expect("request");
    crate::operation_once_runtime::authorize(
        &store,
        &fixture.config,
        &fs::read(state_path).expect("state wire"),
        &wire,
        fixture.now,
    )
    .expect("first");
    let mut changed = fixture.request.clone();
    changed.target_device_proof.custody_revision = format!("rev1:{}", "d4".repeat(32));
    changed.sign_intent.expected_revision = changed.target_device_proof.custody_revision.clone();
    let digest = crowsi_credential_authority_contracts::target_device_proof_digest(
        &changed.target_device_proof,
    )
    .expect("digest");
    changed.sign_intent.digest_sha256 = format!("sha256:{}", hex::encode(digest));
    let changed_wire = serde_json::to_vec(&changed).expect("changed wire");
    assert!(
        crowsi_windows_operation_contracts::decode_operation_authorize_once_request(&changed_wire)
            .is_ok()
    );
    assert!(matches!(
        crate::operation_once_runtime::recover_wire(&fixture.config, &changed_wire, fixture.now),
        Err(PaKeyError::Authorization)
    ));
}

fn private_root() -> tempfile::TempDir {
    let base = std::env::current_dir().expect("cwd");
    let root = tempfile::Builder::new()
        .prefix(".pa-collision-")
        .tempdir_in(base)
        .expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}
