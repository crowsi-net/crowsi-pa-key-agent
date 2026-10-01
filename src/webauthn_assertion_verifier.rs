use std::path::Path;

use crate::{
    PaKeyError, Result, private_json,
    webauthn_assertion::{counter, decode, verify_assertion_signature, verify_ceremony_data},
    webauthn_challenge::valid_challenge,
    webauthn_model::{PasskeyAssertionV1, PasskeyChallengeV1, PasskeyCredentialV1},
    webauthn_verifier::read_current_passkey,
};

pub(crate) struct VerifiedAssertion {
    pub challenge: PasskeyChallengeV1,
    pub assertion: PasskeyAssertionV1,
    pub credential: PasskeyCredentialV1,
    pub next_counter: u32,
}

pub(crate) fn verify_assertion(
    challenge_path: &Path,
    assertion_path: &Path,
    credential_path: &Path,
    expected_operation: &str,
    expected_request_binding: &str,
    expected_context_binding: Option<&str>,
    expected_pa_binding: &str,
) -> Result<VerifiedAssertion> {
    let challenge: PasskeyChallengeV1 = private_json::read_owner(challenge_path)?;
    let assertion: PasskeyAssertionV1 = private_json::read_owner(assertion_path)?;
    let credential = read_current_passkey(credential_path, expected_pa_binding)?;
    let exact = valid_challenge(&challenge, expected_operation)
        && challenge.binding_sha256 == expected_request_binding
        && challenge.context_sha256.as_deref() == expected_context_binding
        && assertion.credential_id_b64url == credential.credential_id_b64url
        && challenge.rp_id == credential.rp_id
        && crate::webauthn_challenge::valid_local_origin(&challenge.rp_id, &challenge.origin);
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
    Ok(VerifiedAssertion {
        challenge,
        assertion,
        credential,
        next_counter,
    })
}

pub(crate) fn commit_assertion(
    challenge_path: &Path,
    assertion_path: &Path,
    credential_path: &Path,
    verified: VerifiedAssertion,
) -> Result<(PasskeyChallengeV1, String)> {
    private_json::ensure_owner(challenge_path, &verified.challenge)?;
    private_json::ensure_owner(assertion_path, &verified.assertion)?;
    private_json::ensure_owner(credential_path, &verified.credential)?;
    private_json::remove_owner(challenge_path)?;
    private_json::remove_owner(assertion_path)?;
    let mut credential = verified.credential;
    credential.sign_count = verified.next_counter.max(credential.sign_count);
    let credential_id = credential.credential_id_b64url.clone();
    private_json::replace(credential_path, &credential)?;
    Ok((verified.challenge, credential_id))
}
