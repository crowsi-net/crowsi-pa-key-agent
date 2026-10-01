use std::path::Path;

use crate::{
    PaKeyError, PasskeyChallengeV1, PasskeyCredentialV1, Result, private_json,
    private_json_replacement::quarantine_and_replace,
    webauthn_assertion::{counter, decode, verify_assertion_signature, verify_ceremony_data},
    webauthn_challenge::{create_context_bound_challenge, valid_challenge},
    webauthn_model::PasskeyAssertionV1,
    webauthn_verifier::{credential_digest, read_stale_candidate},
};

/// Creates a current-PA-bound assertion challenge for one existing authenticator key.
///
/// # Errors
///
/// Rejects current, unrecognized, or unsafe credential state and unsafe output paths.
pub fn create_passkey_rebind_challenge(
    credential_path: &Path,
    output_path: &Path,
    expected_pa_binding: &str,
) -> Result<PasskeyChallengeV1> {
    let credential = read_stale_candidate(credential_path)?;
    if credential.pa_public_key_sha256 == expected_pa_binding {
        return Err(PaKeyError::UserVerification);
    }
    let context = credential_digest(&credential)?;
    create_context_bound_challenge(
        output_path,
        "passkey-rebind",
        &credential.rp_id,
        &credential.origin,
        expected_pa_binding,
        Some(&context),
    )
}

/// Rebinds only after the existing authenticator proves user-verified key possession.
///
/// # Errors
///
/// Preserves all credential and ceremony state on invalid or mismatched evidence.
pub fn rebind_passkey(
    challenge_path: &Path,
    assertion_path: &Path,
    credential_path: &Path,
    expected_pa_binding: &str,
) -> Result<PasskeyCredentialV1> {
    let original = private_json::read_owner_bytes(credential_path)?;
    let credential = read_stale_candidate(credential_path)?;
    if credential.pa_public_key_sha256 == expected_pa_binding {
        return Err(PaKeyError::UserVerification);
    }
    let challenge: PasskeyChallengeV1 = private_json::read_owner(challenge_path)?;
    let assertion: PasskeyAssertionV1 = private_json::read_owner(assertion_path)?;
    let context = credential_digest(&credential)?;
    let exact = valid_challenge(&challenge, "passkey-rebind")
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
    let rebound = PasskeyCredentialV1 {
        pa_public_key_sha256: expected_pa_binding.into(),
        sign_count: next_counter.max(credential.sign_count),
        ..credential
    };
    private_json::remove_owner(challenge_path)?;
    private_json::remove_owner(assertion_path)?;
    quarantine_and_replace(credential_path, &rebound)?;
    Ok(rebound)
}
