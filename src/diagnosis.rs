use std::path::Path;

use crowsi_credential_broker::{BrokerError, CredentialStore};

use crate::{PaKeyDiagnosisV1, initialization::reference, model::DIAGNOSIS_SCHEMA, state_file};

/// Diagnoses custody without exposing or creating key material.
#[must_use]
pub fn diagnose<S: CredentialStore>(store: &S, state_path: &Path) -> PaKeyDiagnosisV1 {
    let Ok(state) = state_file::load(state_path) else {
        return result(
            "unavailable",
            "invalid",
            "unknown",
            None,
            "pa-public-state-invalid",
        );
    };
    let Ok(reference) = reference() else {
        return result(
            "unavailable",
            presence(state.as_ref()),
            "unknown",
            None,
            "pa-key-reference-invalid",
        );
    };
    match (state, store.metadata(&reference)) {
        (None, Err(BrokerError::NotFound)) => result(
            "not-initialized",
            "absent",
            "absent",
            None,
            "pa-key-not-initialized",
        ),
        (Some(public), Ok(metadata))
            if metadata.revision().as_str() == public.credential_revision =>
        {
            result(
                "ready",
                "present",
                "verified",
                Some(public.public_key_hex),
                "ready",
            )
        }
        (public, Err(BrokerError::BackendDenied)) => result(
            "unavailable",
            presence(public.as_ref()),
            "locked",
            public.map(|value| value.public_key_hex),
            "pa-custody-access-denied",
        ),
        (public, Err(BrokerError::BackendUnavailable)) => result(
            "unavailable",
            presence(public.as_ref()),
            "unknown",
            public.map(|value| value.public_key_hex),
            "pa-custody-provider-unavailable",
        ),
        (public, _) => result(
            "unavailable",
            presence(public.as_ref()),
            "inconsistent",
            public.map(|value| value.public_key_hex),
            "pa-state-inconsistent",
        ),
    }
}

fn presence<T>(value: Option<&T>) -> &'static str {
    if value.is_some() { "present" } else { "absent" }
}

fn result(
    state: &'static str,
    public_state: &'static str,
    key_binding: &'static str,
    public_key_hex: Option<String>,
    reason_code: &'static str,
) -> PaKeyDiagnosisV1 {
    PaKeyDiagnosisV1 {
        schema: DIAGNOSIS_SCHEMA,
        state,
        public_state,
        key_binding,
        public_key_hex,
        reason_code,
        contains_secret_values: false,
    }
}
