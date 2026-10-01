use crowsi_windows_operation_contracts::{
    OPERATION_AUTHORIZATION_AUDIENCE, OperationOnlyAction, operation_request_digest,
};
use ed25519_dalek::{Signature, Verifier};

use crate::{operation_once_document, operation_once_test_support::Fixture, operation_once_verify};

#[test]
fn op_16_output_is_exact_fully_bound_short_lived_request() {
    let fixture = Fixture::new();
    let mapping = operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now)
        .expect("evidence");
    let output = operation_once_document::build(
        &fixture.request,
        mapping,
        "pa-operation-key:1",
        &fixture.pa,
        fixture.now,
    )
    .expect("document");
    assert_eq!(
        output.current_device_status,
        fixture.current().current_status
    );
    assert_eq!(
        output.pa_authorization.binding.audience,
        OPERATION_AUTHORIZATION_AUDIENCE
    );
    assert_eq!(output.pa_authorization.binding.action, "sign:ed25519");
    assert_eq!(output.pa_authorization.expires_at_epoch_s, 134);
    for boundary in [
        fixture.now + 60,
        fixture.current().assertion.expires_at_epoch_s,
        fixture.current().current_status.expires_at_epoch_s,
        fixture.fresh().expires_at_epoch_s,
        fixture.request.target_device_proof.expires_at_epoch_s,
        fixture.request.prepared.expires_at_epoch_s,
    ] {
        assert!(output.pa_authorization.expires_at_epoch_s <= boundary);
    }
    assert_eq!(
        output.pa_authorization.binding.request_digest_sha256,
        operation_request_digest(&output).expect("digest")
    );
    assert!(matches!(output.action, OperationOnlyAction::Sign { .. }));
    let signature = Signature::try_from(
        hex::decode(&output.pa_authorization.signature_hex)
            .expect("hex")
            .as_slice(),
    )
    .expect("signature");
    let bytes =
        crowsi_windows_operation_contracts::authorization_signing_bytes(&output.pa_authorization)
            .expect("bytes");
    fixture
        .pa
        .verifying_key()
        .verify(&bytes, &signature)
        .expect("PA signature");
}
