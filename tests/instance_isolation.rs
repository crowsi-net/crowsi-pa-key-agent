use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{destroy_trust_domain, initialize, status};
use tempfile::tempdir;

#[test]
fn destroying_one_instance_does_not_change_another_instance() {
    let first_root = private_root();
    let second_root = private_root();
    let first_store = MemoryStore::default();
    let second_store = MemoryStore::default();
    let first_state = first_root.path().join("public-state.json");
    let second_state = second_root.path().join("public-state.json");
    let first_passkey = first_root.path().join("passkey.json");
    let second_passkey = second_root.path().join("passkey.json");
    let first = initialize(&first_store, &first_state, "instance-a").expect("first PA");
    let second = initialize(&second_store, &second_state, "instance-b").expect("second PA");
    owner_file(&first_passkey);
    owner_file(&second_passkey);

    destroy_trust_domain(
        &first_store,
        &first_state,
        &first_passkey,
        &first.public_key_hex,
    )
    .expect("destroy first");

    assert_eq!(
        status(&second_store, &second_state).expect("second status"),
        second
    );
    assert!(second_passkey.exists());
}

fn private_root() -> tempfile::TempDir {
    let value = tempdir().expect("private root");
    fs::set_permissions(value.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    value
}

fn owner_file(path: &std::path::Path) {
    fs::write(path, b"{}").expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner mode");
}
