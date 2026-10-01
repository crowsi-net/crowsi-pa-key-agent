use std::{fs, os::unix::fs::PermissionsExt};

use crate::{PaKeyError, operation_once_ledger_test_support::BareLedger};

#[test]
fn legacy_consumed_proof_is_a_bounded_tombstone_not_a_remint_path() {
    let setup = BareLedger::new();
    let binding =
        crate::operation_once_digest::Binding::new(&setup.fixture.request).expect("binding");
    let name = crate::operation_once_legacy::file_name(&binding).expect("legacy name");
    let path = setup.ledger.join(name);
    let wire = crate::operation_once_legacy::test_wire(&binding, 120, 134);
    assert!(wire.ends_with(b"\n"), "v1 consume appended one newline");
    fs::write(&path, wire).expect("legacy receipt");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(matches!(
        crate::operation_once_ledger::recover(
            &setup.ledger,
            &setup.fixture.request,
            setup.fixture.now
        ),
        Err(PaKeyError::Authorization)
    ));
    let pruned = crate::operation_once_ledger::recover(&setup.ledger, &changed(&setup), 800)
        .expect("forward prune");
    assert!(pruned.is_none());
    assert!(!path.exists());
    assert!(matches!(
        crate::operation_once_ledger::recover(
            &setup.ledger,
            &setup.fixture.request,
            setup.fixture.now
        ),
        Err(PaKeyError::State)
    ));
}

fn changed(
    setup: &BareLedger,
) -> crowsi_windows_operation_contracts::OperationAuthorizeOnceRequestV2 {
    let mut request = setup.fixture.request.clone();
    request.target_device_proof.custody_revision = format!("rev1:{}", "ef".repeat(32));
    request.sign_intent.expected_revision = request.target_device_proof.custody_revision.clone();
    let digest = crowsi_credential_authority_contracts::target_device_proof_digest(
        &request.target_device_proof,
    )
    .expect("digest");
    request.sign_intent.digest_sha256 = format!("sha256:{}", hex::encode(digest));
    request
}
