use std::{fs, os::unix::fs::PermissionsExt};

use crate::{PaKeyError, operation_once_ledger_test_support::BareLedger};

#[test]
fn entry_and_byte_quota_reject_at_boundary_and_remain_rejected_after_restart() {
    let setup = BareLedger::new();
    let pin = pin(&setup);
    for index in 0..crate::operation_once_ledger_scan::MAX_ENTRIES {
        let request = request(&setup, index);
        let binding = crate::operation_once_digest::Binding::new(&request).expect("binding");
        let record = crate::operation_once_record::Record::prepared(
            &binding,
            setup.fixture.now,
            request.target_device_proof.expires_at_epoch_s,
            pin.clone(),
        )
        .expect("record");
        let wire = crate::operation_once_ledger_codec::encode(&record).expect("wire");
        let path = setup.ledger.join(binding.file_name());
        fs::write(&path, wire).expect("receipt");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }
    let candidate = request(&setup, crate::operation_once_ledger_scan::MAX_ENTRIES);
    for _ in 0..2 {
        let mut transaction = crate::operation_once_ledger::Transaction::open(
            &setup.ledger,
            &candidate,
            setup.fixture.now,
        )
        .expect("bounded scan");
        assert!(matches!(
            transaction.prepare(
                setup.fixture.now,
                candidate.target_device_proof.expires_at_epoch_s,
                pin.clone()
            ),
            Err(PaKeyError::State)
        ));
    }
    assert_eq!(
        crate::operation_once_ledger_scan::MAX_TOTAL_BYTES,
        crate::operation_once_ledger_scan::MAX_ENTRIES as u64
            * crate::operation_once_record::MAX_RECORD_BYTES
    );
}

fn request(
    setup: &BareLedger,
    index: usize,
) -> crowsi_windows_operation_contracts::OperationAuthorizeOnceRequestV2 {
    let mut request = setup.fixture.request.clone();
    let revision = format!("rev1:{index:064x}");
    request.target_device_proof.custody_revision = revision.clone();
    request.sign_intent.expected_revision = revision;
    request.sign_intent.request_id = format!("quota-request-{index:03}");
    let digest = crowsi_credential_authority_contracts::target_device_proof_digest(
        &request.target_device_proof,
    )
    .expect("proof digest");
    request.sign_intent.digest_sha256 = format!("sha256:{}", hex::encode(digest));
    request
}

fn pin(setup: &BareLedger) -> crate::operation_once_pin::PreparedPin {
    let state = crate::PaKeyStateV1::new(
        hex::encode(setup.fixture.pa.verifying_key().to_bytes()),
        "a1".repeat(16),
        "quota-test",
    );
    crate::operation_once_pin::PreparedPin::new(
        &state,
        &setup.fixture.config.0.credential_mappings[0],
    )
    .expect("pin")
}
