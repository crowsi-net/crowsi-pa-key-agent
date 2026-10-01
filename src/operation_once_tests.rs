use crate::operation_once_verify;

use super::operation_once_test_support::Fixture;

#[test]
// PA-06: operation authorization accepts only independently signed current evidence and exact custody mapping.
fn pa_06_verifies_complete_signed_evidence_and_closed_mapping() {
    let fixture = Fixture::new();
    let selected = operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now)
        .expect("verified evidence");
    assert_eq!(selected.custody_credential_id, "custody-device-key-b");
    assert_eq!(
        selected.expected_revision,
        fixture.request.sign_intent.expected_revision
    );
}

#[test]
fn pa_06_accepts_fresh_current_identity_issued_after_finish() {
    let fixture = Fixture::new();
    assert_ne!(
        fixture.fresh().identity_nonce,
        fixture.current().assertion.nonce
    );
    assert!(fixture.fresh().issued_at_epoch_s <= fixture.current().assertion.issued_at_epoch_s);
    assert!(
        fixture.current().assertion.issued_at_epoch_s
            <= fixture.request.target_device_proof.issued_at_epoch_s
    );
    assert!(operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now).is_ok());
}

#[test]
fn pa_06_rejects_identity_status_and_fresh_uv_signature_or_key_substitution() {
    for case in 0..4 {
        let mut fixture = Fixture::new();
        match case {
            0 => fixture.current_mut().assertion.signature = "00".repeat(64),
            1 => fixture.current_mut().current_status.signature = "00".repeat(64),
            2 => fixture.fresh_mut().signature = "00".repeat(64),
            _ => {
                fixture.fresh_mut().account_binding_sha256 = "ff".repeat(32);
                fixture.resign_fresh();
            }
        }
        assert!(
            operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now).is_err()
        );
    }
    let mut fixture = Fixture::new();
    fixture.config.0.current_status_public_key_hex =
        fixture.config.0.identity_public_key_hex.clone();
    assert!(operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now).is_err());
}

#[test]
fn pa_06_rejects_time_edges_and_evidence_expiry_reordering() {
    let fixture = Fixture::new();
    assert!(operation_once_verify::verify(&fixture.request, &fixture.config, 133).is_ok());
    for now in [99, 134, 140, 150] {
        assert!(operation_once_verify::verify(&fixture.request, &fixture.config, now).is_err());
    }
    let mut proof_before_uv = Fixture::new();
    proof_before_uv
        .request
        .target_device_proof
        .issued_at_epoch_s = 109;
    proof_before_uv.rebind_sign_digest();
    assert!(
        operation_once_verify::verify(
            &proof_before_uv.request,
            &proof_before_uv.config,
            proof_before_uv.now
        )
        .is_err()
    );
    let mut proof_after_status = Fixture::new();
    proof_after_status
        .current_mut()
        .assertion
        .expires_at_epoch_s = 133;
    proof_after_status
        .current_mut()
        .current_status
        .expires_at_epoch_s = 133;
    proof_after_status.resign_current();
    assert!(
        operation_once_verify::verify(
            &proof_after_status.request,
            &proof_after_status.config,
            proof_after_status.now
        )
        .is_err()
    );
    let mut proof_after_fresh = Fixture::new();
    proof_after_fresh
        .request
        .target_device_proof
        .expires_at_epoch_s = 136;
    proof_after_fresh.rebind_sign_digest();
    assert!(
        operation_once_verify::verify(
            &proof_after_fresh.request,
            &proof_after_fresh.config,
            proof_after_fresh.now
        )
        .is_err()
    );
}

#[test]
fn op_16_mapping_selects_custody_id_revision_class_not_proof_key_ref() {
    let mut fixture = Fixture::new();
    assert_ne!(
        fixture.request.sign_intent.credential_id,
        fixture.request.target_device_proof.device_proof_key_ref
    );
    fixture.config.0.credential_mappings[0].custody_credential_id = "caller-key".into();
    assert!(operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now).is_err());
    let mut fixture = Fixture::new();
    fixture.config.0.credential_mappings[0].expected_revision = format!("rev1:{}", "d4".repeat(32));
    assert!(operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now).is_err());
    let mut fixture = Fixture::new();
    fixture.request.target_device_proof.key_id = "different-proof-key".into();
    fixture.rebind_sign_digest();
    assert!(operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now).is_err());
}
