use serde::Serialize;

use crate::PasskeyRegistrationProofRejection;

/// Redacted attributes for an optional service-telemetry event envelope.
///
/// The telemetry owner adds occurrence time and correlation. `WebAuthn` evidence
/// is deliberately absent from this projection and must not be added as labels.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRegistrationDiagnosticEventV1 {
    schema: &'static str,
    event_id: String,
    occurred_at_unix_ms: i64,
    component: &'static str,
    operation: &'static str,
    phase: &'static str,
    outcome: &'static str,
    reason_code: &'static str,
    contains_sensitive_values: bool,
}

impl PasskeyRegistrationDiagnosticEventV1 {
    #[must_use]
    pub fn new(
        reason: PasskeyRegistrationProofRejection,
        event_id: String,
        occurred_at_unix_ms: i64,
    ) -> Option<Self> {
        (occurred_at_unix_ms > 0 && valid_event_id(&event_id)).then(|| Self {
            schema: "crowsi://service-telemetry/diagnostic-event/v1",
            event_id,
            occurred_at_unix_ms,
            component: "crowsi-pa-key-agent",
            operation: "passkey-registration",
            phase: "possession-proof",
            outcome: "rejected",
            reason_code: reason.reason_code(),
            contains_sensitive_values: false,
        })
    }
}

fn valid_event_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
        })
}
