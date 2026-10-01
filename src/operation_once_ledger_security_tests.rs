use std::fs;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};

use crate::{
    PaKeyError, operation_once_ledger_test_support::BareLedger,
    operation_once_recovery_support::Setup,
};

#[test]
fn receipt_symlink_hardlink_fifo_and_oversize_fail_closed() {
    let symlink = BareLedger::new();
    symlink.symlink(&BareLedger::entry_name('a'));
    symlink.assert_rejected();

    let hardlink = BareLedger::new();
    hardlink.hardlink(&BareLedger::entry_name('b'));
    hardlink.assert_rejected();

    let fifo = BareLedger::new();
    fifo.fifo(&BareLedger::entry_name('c'));
    fifo.assert_rejected();

    let oversize = BareLedger::new();
    let oversize_bytes =
        usize::try_from(crate::operation_once_record::MAX_RECORD_BYTES).expect("record bound") + 1;
    oversize.write(&BareLedger::entry_name('d'), &vec![b'x'; oversize_bytes]);
    oversize.assert_rejected();
}

#[test]
fn lock_symlink_hardlink_and_fifo_fail_closed_without_blocking() {
    let symlink = BareLedger::new();
    symlink.symlink(crate::operation_once_ledger_dir::LOCK_NAME);
    symlink.assert_rejected();

    let hardlink = BareLedger::new();
    hardlink.hardlink(crate::operation_once_ledger_dir::LOCK_NAME);
    hardlink.assert_rejected();

    let fifo = BareLedger::new();
    fifo.fifo(crate::operation_once_ledger_dir::LOCK_NAME);
    fifo.assert_rejected();
}

#[test]
fn watermark_and_pending_link_substitution_fail_closed() {
    let watermark = BareLedger::new();
    watermark.symlink(crate::operation_once_ledger_dir::WATERMARK_NAME);
    watermark.assert_rejected();

    let pending = BareLedger::new();
    pending.symlink(crate::operation_once_ledger_dir::TEMP_NAME);
    pending.assert_rejected();
}

#[test]
fn unknown_or_noncanonical_receipt_file_fails_closed() {
    let unknown = BareLedger::new();
    unknown.write("unknown.json", b"{}");
    unknown.assert_rejected();

    let invalid = BareLedger::new();
    invalid.write(&BareLedger::entry_name('e'), b"{}");
    invalid.assert_rejected();
}

#[test]
fn cached_response_field_substitution_fails_closed() {
    let setup = Setup::new();
    setup.authorize_wire(&setup.store, setup.fixture.now, &setup.state);
    let request =
        crowsi_windows_operation_contracts::decode_operation_authorize_once_request(&setup.request)
            .expect("request");
    let name = crate::operation_once_digest::Binding::new(&request)
        .expect("binding")
        .file_name();
    let path = std::path::Path::new(&setup.fixture.config.0.replay_directory).join(name);
    let mut record: crate::operation_once_record::Record =
        serde_json::from_slice(&fs::read(&path).expect("receipt")).expect("record");
    let mut response = crowsi_windows_operation_contracts::decode_operation_request(
        &record.response().expect("response").expect("completed"),
    )
    .expect("operation request");
    response.credential_id = "substituted-credential".into();
    let wire = crate::operation_once_digest::response_wire(&response).expect("canonical response");
    record.response_digest_sha256 = Some(crate::operation_once_digest::response_digest(&wire));
    record.response_wire_base64 = Some(STANDARD_NO_PAD.encode(wire));
    fs::write(path, serde_json::to_vec(&record).expect("tampered receipt")).expect("write");
    assert!(matches!(
        crate::operation_once_runtime::recover_wire(
            &setup.fixture.config,
            &setup.request,
            setup.fixture.now
        ),
        Err(PaKeyError::State)
    ));
}
