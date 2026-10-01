use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{destroy, diagnose, initialize, status};
use tempfile::tempdir;

#[test]
fn initialization_keeps_secret_out_of_public_state_and_is_idempotent() {
    let directory = tempdir().expect("private directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let state_path = directory.path().join("public-state.json");
    let store = MemoryStore::default();

    let first = initialize(&store, &state_path, "memory-test").expect("initialize");
    let second = initialize(&store, &state_path, "memory-test").expect("idempotent");
    assert_eq!(first.public_key_hex, second.public_key_hex);
    assert_eq!(first.credential_revision, second.credential_revision);
    assert_eq!(first.authorization_issuance, "blocked");
    assert_eq!(
        first.reason_code,
        "phishing-resistant-user-verification-required"
    );

    let encoded = fs::read_to_string(&state_path).expect("public state");
    assert!(!encoded.contains("private"));
    assert!(!encoded.contains("seed"));
    assert!(encoded.contains("\"contains_secret_values\": false"));
    assert_eq!(
        fs::metadata(&state_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(status(&store, &state_path).expect("status"), first);
}

#[test]
fn existing_public_state_without_custody_fails_closed() {
    let directory = tempdir().expect("private directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let state_path = directory.path().join("public-state.json");
    let source = MemoryStore::default();
    initialize(&source, &state_path, "memory-test").expect("fixture");

    let empty = MemoryStore::default();
    assert!(initialize(&empty, &state_path, "memory-test").is_err());
}

#[test]
fn destruction_is_bound_to_the_current_public_key() {
    let directory = tempdir().expect("private directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let state_path = directory.path().join("public-state.json");
    let store = MemoryStore::default();
    let state = initialize(&store, &state_path, "memory-test").expect("initialize");

    assert!(destroy(&store, &state_path, &"0".repeat(64)).is_err());
    assert!(state_path.exists());
    let receipt = destroy(&store, &state_path, &state.public_key_hex).expect("destroy");
    assert_eq!(receipt.state, "destroyed");
    assert!(!receipt.contains_secret_values);
    assert!(!state_path.exists());
    assert_eq!(diagnose(&store, &state_path).state, "not-initialized");
}
