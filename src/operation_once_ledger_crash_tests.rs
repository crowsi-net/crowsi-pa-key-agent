use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::Path};

use crowsi_credential_broker::MemoryStore;

use crate::operation_once_recovery_support::Setup;

#[test]
fn partial_completed_write_recovers_from_prepared_without_reminting_time() {
    let setup = Setup::new();
    setup.prepare();
    let ledger = Path::new(&setup.fixture.config.0.replay_directory);
    let pending = ledger.join(crate::operation_once_ledger_dir::TEMP_NAME);
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)
        .expect("partial pending");
    file.write_all(b"{").expect("partial write");
    file.sync_all().expect("partial sync");
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).expect("pending mode");
    let recovered = crate::operation_once_runtime::authorize(
        &setup.store,
        &setup.fixture.config,
        &setup.state,
        &setup.request,
        setup.fixture.now + 1,
    )
    .expect("prepared recovery");
    assert_eq!(
        recovered.pa_authorization.issued_at_epoch_s,
        setup.fixture.now
    );
    assert!(!pending.exists());
}

#[test]
fn completed_temp_fsync_cut_is_promoted_and_returned_before_custody() {
    let setup = Setup::new();
    setup.prepare();
    let ledger = Path::new(&setup.fixture.config.0.replay_directory);
    let request =
        crowsi_windows_operation_contracts::decode_operation_authorize_once_request(&setup.request)
            .expect("request");
    let name = crate::operation_once_digest::Binding::new(&request)
        .expect("binding")
        .file_name();
    let receipt_path = ledger.join(name);
    let prepared = fs::read(&receipt_path).expect("prepared receipt");
    let response = setup.authorize_wire(&setup.store, setup.fixture.now, &setup.state);
    let completed = fs::read(&receipt_path).expect("completed receipt");
    fs::write(&receipt_path, prepared).expect("restore pre-rename final");
    fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).expect("receipt mode");
    let pending = ledger.join(crate::operation_once_ledger_dir::TEMP_NAME);
    fs::write(&pending, completed).expect("completed pending");
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).expect("pending mode");
    let recovered = crate::operation_once_runtime::authorize_wire_checked(
        &MemoryStore::default(),
        &setup.fixture.config,
        b"ignored-state",
        &setup.request,
        setup.fixture.now + 1,
        |_| panic!("completed recovery must not access custody"),
    )
    .expect("promoted completed response");
    assert_eq!(recovered, response);
    assert!(!pending.exists());
}
