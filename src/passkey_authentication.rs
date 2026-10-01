use std::path::Path;

use serde::Serialize;

use crate::{
    PaKeyError, PasskeyChallengeV1, Result, private_json,
    private_json_replacement::quarantine_and_replace,
    webauthn_assertion::{counter, decode, verify_assertion_signature, verify_ceremony_data},
    webauthn_challenge::{create_context_bound_challenge, now, valid_challenge},
    webauthn_model::{PasskeyAssertionV1, PasskeyCredentialV1},
    webauthn_verifier::{credential_digest, read_current_passkey},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PasskeyAuthenticationReceiptV1 {
    pub schema: &'static str,
    pub authenticated_at_epoch_s: i64,
    pub contains_secret_values: bool,
}

/// Creates a one-use challenge bound to the current PA and registered Passkey.
///
/// # Errors
///
/// Returns an error when the credential is not current or either owner-only path is unsafe.
pub fn create_passkey_authentication_challenge(
    credential_path: &Path,
    output_path: &Path,
    expected_pa_binding: &str,
) -> Result<PasskeyChallengeV1> {
    let credential = read_current_passkey(credential_path, expected_pa_binding)?;
    let context = credential_digest(&credential)?;
    create_context_bound_challenge(
        output_path,
        "passkey-authentication",
        &credential.rp_id,
        &credential.origin,
        expected_pa_binding,
        Some(&context),
    )
}

/// Verifies a UV assertion and atomically advances the registered credential state.
///
/// # Errors
///
/// Returns an error when evidence, origin, binding, signature, counter, or owner-only files differ
/// from the exact challenge. Rejected evidence is retained for the caller to remove as one unit.
pub fn authenticate_passkey(
    challenge_path: &Path,
    assertion_path: &Path,
    credential_path: &Path,
    expected_pa_binding: &str,
) -> Result<PasskeyAuthenticationReceiptV1> {
    let original = private_json::read_owner_bytes(credential_path)?;
    let credential = read_current_passkey(credential_path, expected_pa_binding)?;
    let challenge: PasskeyChallengeV1 = private_json::read_owner(challenge_path)?;
    let assertion: PasskeyAssertionV1 = private_json::read_owner(assertion_path)?;
    let context = credential_digest(&credential)?;
    let exact = valid_challenge(&challenge, "passkey-authentication")
        && challenge.binding_sha256 == expected_pa_binding
        && challenge.context_sha256.as_deref() == Some(context.as_str())
        && challenge.rp_id == credential.rp_id
        && challenge.origin == credential.origin
        && assertion.credential_id_b64url == credential.credential_id_b64url;
    if !exact {
        return Err(PaKeyError::UserVerification);
    }
    let client = decode(&assertion.client_data_json_b64url)?;
    let authenticator = decode(&assertion.authenticator_data_b64url)?;
    verify_ceremony_data(&client, &authenticator, &challenge, "webauthn.get")?;
    verify_assertion_signature(&credential, &assertion, &client, &authenticator)?;
    let next_counter = counter(&authenticator)?;
    if credential.sign_count > 0 && next_counter <= credential.sign_count {
        return Err(PaKeyError::UserVerification);
    }
    private_json::ensure_owner_bytes(credential_path, &original)?;
    private_json::ensure_owner(challenge_path, &challenge)?;
    private_json::ensure_owner(assertion_path, &assertion)?;
    let updated = PasskeyCredentialV1 {
        sign_count: next_counter.max(credential.sign_count),
        ..credential
    };
    private_json::remove_owner(challenge_path)?;
    private_json::remove_owner(assertion_path)?;
    quarantine_and_replace(credential_path, &updated)?;
    Ok(PasskeyAuthenticationReceiptV1 {
        schema: "crowsi://policy-authority/passkey-authentication-receipt/v1",
        authenticated_at_epoch_s: now(),
        contains_secret_values: false,
    })
}
