use crowsi_pa_key_agent::{
    PasskeyRegistrationDiagnosticEventV1, PasskeyRegistrationProofRejection,
};
use serde_json::json;

#[test]
fn diagnostic_projection_has_only_bounded_non_sensitive_attributes() {
    let event = PasskeyRegistrationDiagnosticEventV1::new(
        PasskeyRegistrationProofRejection::UserVerification,
        "8f0f7c78-84e6-4b81-ae63-9a7a1db64385".into(),
        1_786_011_300_000,
    )
    .expect("valid occurrence time");
    assert_eq!(
        serde_json::to_value(event).expect("serialize diagnostic"),
        json!({
            "schema": "crowsi://service-telemetry/diagnostic-event/v1",
            "event_id": "8f0f7c78-84e6-4b81-ae63-9a7a1db64385",
            "occurred_at_unix_ms": 1_786_011_300_000_i64,
            "component": "crowsi-pa-key-agent",
            "operation": "passkey-registration",
            "phase": "possession-proof",
            "outcome": "rejected",
            "reason_code": "pa-passkey-proof-user-verification-rejected",
            "contains_sensitive_values": false
        })
    );
    assert!(
        PasskeyRegistrationDiagnosticEventV1::new(
            PasskeyRegistrationProofRejection::UserVerification,
            "8f0f7c78-84e6-4b81-ae63-9a7a1db64385".into(),
            0,
        )
        .is_none()
    );
    assert!(
        PasskeyRegistrationDiagnosticEventV1::new(
            PasskeyRegistrationProofRejection::UserVerification,
            "not-random".into(),
            1,
        )
        .is_none()
    );
}
