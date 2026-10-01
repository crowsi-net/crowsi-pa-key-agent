use std::path::Path;

#[cfg(feature = "owner-local-bootstrap")]
use crowsi_credential_broker::CredentialStore;
use crowsi_credential_broker::PlatformCustodyStore;
use crowsi_pa_key_agent::PaKeyError;
#[cfg(feature = "owner-local-bootstrap")]
use crowsi_pa_key_agent::{
    confirm_passkey_registration, create_challenge, stage_passkey_registration, status,
};
use serde_json::Value;

#[cfg(feature = "owner-local-bootstrap")]
use crate::cli::{pa_binding, require_available};

/// Runs registration only in the explicit owner-local deployment artifact.
pub fn challenge(
    store: &PlatformCustodyStore,
    state: &Path,
    output: &Path,
    rp_id: &str,
    origin: &str,
) -> Result<Value, PaKeyError> {
    #[cfg(feature = "owner-local-bootstrap")]
    {
        require_available(store)?;
        challenge_with_store(store, state, output, rp_id, origin)
    }
    #[cfg(not(feature = "owner-local-bootstrap"))]
    {
        let _ = (store, state, output, rp_id, origin);
        Err(PaKeyError::BootstrapUnavailable)
    }
}

pub fn stage(
    store: &PlatformCustodyStore,
    state: &Path,
    challenge: &Path,
    response: &Path,
    candidate: &Path,
    proof: &Path,
    credential: &Path,
) -> Result<Value, PaKeyError> {
    #[cfg(feature = "owner-local-bootstrap")]
    {
        require_available(store)?;
        let pa = status(store, state)?;
        encoded(stage_passkey_registration(
            challenge,
            response,
            candidate,
            proof,
            credential,
            &pa_binding(&pa.public_key_hex),
        )?)
    }
    #[cfg(not(feature = "owner-local-bootstrap"))]
    {
        let _ = (
            store, state, challenge, response, candidate, proof, credential,
        );
        Err(PaKeyError::BootstrapUnavailable)
    }
}

pub fn confirm(
    store: &PlatformCustodyStore,
    state: &Path,
    candidate: &Path,
    proof: &Path,
    assertion: &Path,
    credential: &Path,
) -> Result<Value, PaKeyError> {
    #[cfg(feature = "owner-local-bootstrap")]
    {
        require_available(store)?;
        let pa = status(store, state)?;
        encoded(confirm_passkey_registration(
            proof,
            assertion,
            candidate,
            credential,
            &pa_binding(&pa.public_key_hex),
        )?)
    }
    #[cfg(not(feature = "owner-local-bootstrap"))]
    {
        let _ = (store, state, candidate, proof, assertion, credential);
        Err(PaKeyError::BootstrapUnavailable)
    }
}

#[cfg(feature = "owner-local-bootstrap")]
fn challenge_with_store<S: CredentialStore>(
    store: &S,
    state: &Path,
    output: &Path,
    rp_id: &str,
    origin: &str,
) -> Result<Value, PaKeyError> {
    let pa = status(store, state)?;
    encoded(create_challenge(
        output,
        "register",
        rp_id,
        origin,
        &pa_binding(&pa.public_key_hex),
    )?)
}

#[cfg(feature = "owner-local-bootstrap")]
fn encoded(value: impl serde::Serialize) -> Result<Value, PaKeyError> {
    serde_json::to_value(value).map_err(|_| PaKeyError::Encoding)
}

#[cfg(all(test, feature = "owner-local-bootstrap"))]
#[path = "cli_passkey_registration_tests.rs"]
mod tests;
