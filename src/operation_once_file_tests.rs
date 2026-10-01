use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use crate::{PaKeyError, operation_once_test_support::Fixture};
use crowsi_credential_broker::MemoryStore;

#[test]
fn pa_06_owner_file_is_fd_first_bounded_and_rejects_link_or_mode_substitution() {
    let root = private_root();
    let file = root.path().join("config.json");
    fs::write(&file, b"{}\n").expect("write");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("mode");
    assert_eq!(
        crate::operation_once_files::read_owner(&file, 16).expect("safe owner file"),
        b"{}\n"
    );

    let hardlink = root.path().join("hardlink.json");
    fs::hard_link(&file, &hardlink).expect("hardlink");
    assert!(matches!(
        crate::operation_once_files::read_owner(&file, 16),
        Err(PaKeyError::UnsafePath)
    ));

    let target = root.path().join("target.json");
    fs::write(&target, b"{}\n").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("mode");
    let link = root.path().join("link.json");
    symlink(&target, &link).expect("symlink");
    assert!(matches!(
        crate::operation_once_files::read_owner(&link, 16),
        Err(PaKeyError::UnsafePath)
    ));
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("mode");
    assert!(matches!(
        crate::operation_once_files::read_owner(&target, 16),
        Err(PaKeyError::UnsafePath)
    ));
}

#[test]
fn pa_06_writable_ancestor_and_oversize_fail_closed() {
    let root = private_root();
    let file = root.path().join("input.json");
    fs::write(&file, b"0123456789").expect("write");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(matches!(
        crate::operation_once_files::read_owner(&file, 9),
        Err(PaKeyError::UnsafePath)
    ));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770)).expect("mode");
    assert!(matches!(
        crate::operation_once_files::read_owner(&file, 16),
        Err(PaKeyError::UnsafePath)
    ));
}

#[test]
fn pa_06_operation_response_is_durable_and_substitution_is_rejected() {
    let root = private_root();
    let state_path = root.path().join("state.json");
    let store = MemoryStore::default();
    crate::initialize(&store, &state_path, "test-custody").expect("state");
    let ledger = root.path().join("replay");
    fs::create_dir(&ledger).expect("ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).expect("ledger mode");
    let mut fixture = Fixture::new();
    fixture.config.0.replay_directory = ledger.to_string_lossy().into_owned();
    let state = fs::read(state_path).expect("state wire");
    let wire = serde_json::to_vec(&fixture.request).expect("request");
    let first = crate::operation_once_runtime::authorize(
        &store,
        &fixture.config,
        &state,
        &wire,
        fixture.now,
    )
    .expect("first authorization");
    let exact = crate::operation_once_runtime::authorize(
        &MemoryStore::default(),
        &fixture.config,
        b"ignored",
        &wire,
        fixture.now + 20,
    )
    .expect("exact recovery");
    assert_eq!(exact, first);
    let mut renamed = fixture.request.clone();
    renamed.sign_intent.request_id = "caller-selected-replay-id".into();
    assert!(matches!(
        crate::operation_once_ledger::recover(&ledger, &renamed, fixture.now + 20),
        Err(PaKeyError::Authorization)
    ));
    let entries = fs::read_dir(&ledger)
        .expect("entries")
        .collect::<Result<Vec<_>, _>>()
        .expect("entries");
    assert_eq!(entries.len(), 3);
    let receipt = entries
        .iter()
        .find(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("operation-once-v2-") && name != "operation-once-v2-watermark.json"
        })
        .expect("receipt");
    let text = fs::read_to_string(receipt.path()).expect("ledger");
    for forbidden in [
        "device-b",
        "proof-key-b",
        "operation-nonce",
        "passkey-target-b",
    ] {
        assert!(!text.contains(forbidden));
    }
    assert!(text.contains("\"contains_secret_values\":false"));
}

pub(crate) fn private_root() -> tempfile::TempDir {
    let base = std::env::current_dir().expect("cwd");
    let root = tempfile::Builder::new()
        .prefix(".pa-once-")
        .tempdir_in(base)
        .expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}
