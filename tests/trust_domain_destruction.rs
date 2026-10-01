use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{destroy_trust_domain, diagnose, initialize};
use tempfile::tempdir;

#[test]
fn trust_domain_destruction_revokes_the_server_passkey_registration() {
    let directory = private_directory();
    let state = directory.path().join("public-state.json");
    let passkey = directory.path().join("passkey.json");
    let store = MemoryStore::default();
    let authority = initialize(&store, &state, "memory-test").expect("initialize");
    owner_file(&passkey, br#"{"unrecognized_passkey":"still-present"}"#);

    let receipt = destroy_trust_domain(&store, &state, &passkey, &authority.public_key_hex)
        .expect("destroy trust domain");

    assert_eq!(receipt.pa_key, "destroyed");
    assert_eq!(receipt.public_state, "destroyed");
    assert_eq!(receipt.passkey_registration, "revoked");
    assert!(!state.exists());
    assert!(!passkey.exists());
    assert_eq!(diagnose(&store, &state).state, "not-initialized");
}

#[test]
fn stale_confirmation_preserves_all_trust_domain_state() {
    let directory = private_directory();
    let state = directory.path().join("public-state.json");
    let passkey = directory.path().join("passkey.json");
    let store = MemoryStore::default();
    initialize(&store, &state, "memory-test").expect("initialize");
    owner_file(&passkey, b"{}");

    assert!(destroy_trust_domain(&store, &state, &passkey, &"0".repeat(64)).is_err());
    assert!(state.exists());
    assert!(passkey.exists());
}

#[test]
fn unsafe_passkey_path_preserves_the_authority() {
    let directory = private_directory();
    let state = directory.path().join("public-state.json");
    let passkey = directory.path().join("passkey.json");
    let outside = directory.path().join("missing-target.json");
    let store = MemoryStore::default();
    let authority = initialize(&store, &state, "memory-test").expect("initialize");
    symlink(&outside, &passkey).expect("symlink fixture");

    assert!(destroy_trust_domain(&store, &state, &passkey, &authority.public_key_hex,).is_err());
    assert!(state.exists());
}

fn private_directory() -> tempfile::TempDir {
    let value = tempdir().expect("private directory");
    fs::set_permissions(value.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    value
}

fn owner_file(path: &std::path::Path, value: &[u8]) {
    fs::write(path, value).expect("write owner file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner mode");
}
