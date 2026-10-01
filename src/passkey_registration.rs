use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{
    PaKeyError, PasskeyChallengeV1, PasskeyCredentialV1, Result,
    passkey_registration_proof::{verify_evidence, verify_state},
    private_json,
    webauthn_assertion::{counter, decode, verify_ceremony_data},
    webauthn_attested::verify_attested_credential,
    webauthn_challenge::{create_context_bound_challenge, now, valid_challenge},
    webauthn_model::{PasskeyAssertionV1, PasskeyRegistrationCandidateV1, PasskeyRegistrationV1},
};

/// Stages only attested candidate data and returns a separate possession challenge.
///
/// # Errors
///
/// Rejects unsafe paths, any existing registration, malformed attested
/// data, PA mismatches, or unavailable owner-only evidence storage.
pub fn stage_passkey_registration(
    challenge_path: &Path,
    response_path: &Path,
    candidate_path: &Path,
    proof_path: &Path,
    credential_path: &Path,
    expected_binding: &str,
) -> Result<PasskeyChallengeV1> {
    let target = registration_target(credential_path)?;
    let challenge: PasskeyChallengeV1 = private_json::read_owner(challenge_path)?;
    let response: PasskeyRegistrationV1 = private_json::read_owner(response_path)?;
    if !valid_challenge(&challenge, "register")
        || challenge.binding_sha256 != expected_binding
        || response.credential_id_b64url.is_empty()
    {
        return Err(PaKeyError::UserVerification);
    }
    let client = decode(&response.client_data_json_b64url)?;
    let authenticator = decode(&response.authenticator_data_b64url)?;
    verify_ceremony_data(&client, &authenticator, &challenge, "webauthn.create")?;
    verify_attested_credential(
        &authenticator,
        &response.credential_id_b64url,
        &response.public_key_spki_b64url,
    )?;
    let credential = PasskeyCredentialV1 {
        schema: "crowsi://policy-authority/passkey-credential/v1".into(),
        credential_id_b64url: response.credential_id_b64url,
        public_key_spki_b64url: response.public_key_spki_b64url,
        rp_id: challenge.rp_id,
        origin: challenge.origin,
        pa_public_key_sha256: expected_binding.into(),
        sign_count: counter(&authenticator)?,
        registered_at_epoch_s: now(),
    };
    let candidate = PasskeyRegistrationCandidateV1 {
        schema: "crowsi://policy-authority/passkey-registration-candidate/v1".into(),
        credential,
        target_sha256: target,
    };
    private_json::write_new(candidate_path, &candidate)?;
    let context = candidate_digest(&candidate)?;
    let proof = match create_context_bound_challenge(
        proof_path,
        "passkey-registration-proof",
        &candidate.credential.rp_id,
        &candidate.credential.origin,
        expected_binding,
        Some(&context),
    ) {
        Ok(value) => value,
        Err(error) => {
            private_json::remove_owner(candidate_path)?;
            return Err(error);
        }
    };
    private_json::remove_owner(challenge_path)?;
    private_json::remove_owner(response_path)?;
    Ok(proof)
}

/// Commits a candidate only after a second user-verified signature by that key.
///
/// # Errors
///
/// Rejects expired, replayed, changed, or incorrectly signed proof state and
/// preserves the previously active credential when commit cannot begin.
pub fn confirm_passkey_registration(
    proof_path: &Path,
    assertion_path: &Path,
    candidate_path: &Path,
    credential_path: &Path,
    expected_binding: &str,
) -> Result<PasskeyCredentialV1> {
    let target = registration_target(credential_path)?;
    let proof: PasskeyChallengeV1 = private_json::read_owner(proof_path)?;
    let assertion: PasskeyAssertionV1 = private_json::read_owner(assertion_path)?;
    let mut candidate: PasskeyRegistrationCandidateV1 = private_json::read_owner(candidate_path)?;
    let credential = &candidate.credential;
    let candidate_context = candidate_digest(&candidate)?;
    verify_state(
        &candidate,
        &target,
        &proof,
        &assertion,
        expected_binding,
        &candidate_context,
    )
    .map_err(PaKeyError::PasskeyRegistrationProof)?;
    let observed_counter = verify_evidence(credential, &proof, &assertion)
        .map_err(PaKeyError::PasskeyRegistrationProof)?;
    // Some Windows authenticators expose the makeCredential counter again on
    // their first assertion. Equality is safe only before this key is trusted.
    if credential.sign_count > 0 && observed_counter < credential.sign_count {
        return Err(PaKeyError::PasskeyRegistrationProof(
            crate::PasskeyRegistrationProofRejection::Counter,
        ));
    }
    let next_counter = observed_counter.max(credential.sign_count);
    if registration_target(credential_path)? != target {
        return Err(PaKeyError::State);
    }
    private_json::ensure_owner(proof_path, &proof)?;
    private_json::ensure_owner(assertion_path, &assertion)?;
    private_json::ensure_owner(candidate_path, &candidate)?;
    private_json::remove_owner(proof_path)?;
    private_json::remove_owner(assertion_path)?;
    private_json::remove_owner(candidate_path)?;
    candidate.credential.sign_count = next_counter;
    private_json::write_new(credential_path, &candidate.credential)?;
    Ok(candidate.credential)
}

fn registration_target(path: &Path) -> Result<String> {
    (!private_json::owner_file_present(path)?)
        .then(|| "absent".into())
        .ok_or(PaKeyError::UserVerification)
}

fn candidate_digest(candidate: &PasskeyRegistrationCandidateV1) -> Result<String> {
    let encoded = serde_json::to_vec(candidate).map_err(|_| PaKeyError::Encoding)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
}
