use std::path::Path;

use crowsi_credential_broker::CredentialStore;
use crowsi_local_control_bridge::{
    ControlRequestV1, IpcAuthorizationEnvelopeV2, SenderProof, SignedAuthorization,
    canonical_authorization, canonical_request, sha256_digest,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    CredentialAuthorizationFiles, PaKeyError, Result, authorization_document,
    control_authorization_policy,
    initialization::reference,
    private_json, status,
    webauthn_assertion_verifier::{commit_assertion, verify_assertion},
    webauthn_challenge::now,
    webauthn_model::{PasskeyChallengeV1, PasskeyCredentialV1},
};

/// Creates an owner-only Passkey challenge bound to one exact request.
///
/// # Errors
///
/// Rejects malformed request metadata, unsafe paths, or unavailable randomness.
pub fn create_credential_challenge(
    files: CredentialAuthorizationFiles<'_>,
    output_path: &Path,
    expected_pa_binding: &str,
    origin: &str,
) -> Result<PasskeyChallengeV1> {
    let credential: PasskeyCredentialV1 = private_json::read_owner(files.credential)?;
    if credential.pa_public_key_sha256 != expected_pa_binding {
        return Err(PaKeyError::UserVerification);
    }
    let request: ControlRequestV1 = private_json::read_owner(files.request)?;
    let policy = control_authorization_policy::require(&request)?;
    let identity = crate::identity_authorization::verify(
        files.identity_assertion,
        files.identity_status,
        files.identity_trust,
    )?;
    let identity_binding = crate::identity_authorization::binding(&identity);
    if private_json::owner_file_present(output_path)? {
        return Err(PaKeyError::State);
    }
    private_json::validate_parent(output_path)?;
    crate::identity_nonce::consume(files.state, identity.status())?;
    crate::webauthn_challenge::create_context_bound_challenge(
        output_path,
        policy.operation,
        &credential.rp_id,
        origin,
        &sha256_digest(&canonical_request(&request)),
        Some(&identity_binding),
    )
}

#[derive(Debug, Serialize)]
pub struct AuthorizationReceiptV1 {
    pub schema: &'static str,
    pub state: &'static str,
    pub request_id: String,
    pub reservation_id: String,
    pub expires_at_epoch_s: i64,
    pub contains_secret_values: bool,
}

/// Verifies user presence and signs one short-lived credential authorization.
///
/// # Errors
///
/// Rejects invalid Passkey evidence, request mismatch, unavailable PA custody,
/// unsafe state paths, or signing and persistence failures.
pub fn issue_credential_authorization<S: CredentialStore>(
    store: &S,
    files: CredentialAuthorizationFiles<'_>,
    challenge_path: &Path,
    assertion_path: &Path,
    output_path: &Path,
) -> Result<AuthorizationReceiptV1> {
    let state = status(store, files.state)?;
    let request: ControlRequestV1 = private_json::read_owner(files.request)?;
    let policy = control_authorization_policy::require(&request)?;
    let request_binding = sha256_digest(&canonical_request(&request));
    let pa_binding = sha256_digest(state.public_key_hex.as_bytes());
    let identity = crate::identity_authorization::verify(
        files.identity_assertion,
        files.identity_status,
        files.identity_trust,
    )?;
    let identity_binding = crate::identity_authorization::binding(&identity);
    let verified = verify_assertion(
        challenge_path,
        assertion_path,
        files.credential,
        policy.operation,
        &request_binding,
        Some(&identity_binding),
        &pa_binding,
    )?;
    let (challenge, _credential_id) =
        commit_assertion(challenge_path, assertion_path, files.credential, verified)?;
    let entry = store
        .get(&reference()?, &state.credential_revision)
        .map_err(|_| PaKeyError::Custody)?;
    let mut sender_seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(sender_seed.as_mut()).map_err(|_| PaKeyError::Entropy)?;
    let sender = SigningKey::from_bytes(&sender_seed);
    let issued = now();
    let reservation_id = format!("reservation-{}", challenge.ceremony_id);
    let document = authorization_document::build(
        &request,
        &sender,
        identity.assertion(),
        identity.status().expires_at_epoch_s,
        &reservation_id,
        issued,
        &policy,
    );
    let expires_at_epoch_s = document.expires_at_epoch_s;
    let envelope = entry.into_secret().expose(|bytes| {
        let seed: [u8; 32] = bytes.try_into().map_err(|_| PaKeyError::State)?;
        let pa = SigningKey::from_bytes(&seed);
        Ok::<_, PaKeyError>(IpcAuthorizationEnvelopeV2 {
            schema: "crowsi://local-control/ipc-envelope/v2".into(),
            request: request.clone(),
            authorization: SignedAuthorization {
                signature_hex: hex::encode(pa.sign(&canonical_authorization(&document)).to_bytes()),
                document,
            },
            sender_proof: SenderProof {
                signature_hex: hex::encode(sender.sign(&canonical_request(&request)).to_bytes()),
            },
        })
    })?;
    private_json::write_new(output_path, &envelope)?;
    Ok(AuthorizationReceiptV1 {
        schema: "crowsi://policy-authority/credential-authorization-receipt/v1",
        state: "issued",
        request_id: request.request_id,
        reservation_id,
        expires_at_epoch_s,
        contains_secret_values: false,
    })
}
