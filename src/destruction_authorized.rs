use std::path::Path;

use crowsi_credential_broker::CredentialStore;

use crate::{
    PaAuthorizedTrustDestructionV1, PaKeyError, Result,
    destruction::{delete_key, preflight as custody_preflight},
    destruction_intent::{DestructionContext, load_context},
    destruction_model::AUTHORIZED_RECEIPT_SCHEMA,
    private_json, state_file,
    webauthn_assertion_verifier::{VerifiedAssertion, verify_assertion},
};

/// Destroys one local PA trust domain after exact Passkey authorization.
///
/// # Errors
///
/// Rejects stale generations, altered intent or assertion evidence, unsafe files,
/// failed user verification, and unavailable custody before destructive mutation.
#[allow(clippy::too_many_arguments)]
pub fn destroy_trust_domain_authorized<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    credential_path: &Path,
    intent_path: &Path,
    challenge_path: &Path,
    assertion_path: &Path,
) -> Result<PaAuthorizedTrustDestructionV1> {
    let prepared = load_context(store, state_path, credential_path, intent_path)?;
    let verified = verify_assertion(
        challenge_path,
        assertion_path,
        credential_path,
        "trust-domain-destroy",
        &prepared.intent_digest,
        None,
        &prepared.pa_binding,
    )?;
    let final_context = load_context(store, state_path, credential_path, intent_path)?;
    validate_unchanged(&prepared, &final_context, &verified)?;
    custody_preflight(store, state_path, &prepared.intent.expected_public_key_hex)?;
    verify_evidence(
        intent_path,
        challenge_path,
        assertion_path,
        credential_path,
        &prepared,
        &verified,
    )?;
    consume_evidence(intent_path, challenge_path, assertion_path)?;
    private_json::remove_owner(credential_path)?;
    delete_key(store)?;
    state_file::destroy(state_path)?;
    Ok(receipt(prepared))
}

fn validate_unchanged(
    prepared: &DestructionContext,
    current: &DestructionContext,
    verified: &VerifiedAssertion,
) -> Result<()> {
    let exact = prepared.authority == current.authority
        && prepared.intent == current.intent
        && prepared.credential == current.credential
        && prepared.intent_digest == current.intent_digest
        && verified.credential == prepared.credential;
    exact.then_some(()).ok_or(PaKeyError::State)
}

fn verify_evidence(
    intent_path: &Path,
    challenge_path: &Path,
    assertion_path: &Path,
    credential_path: &Path,
    context: &DestructionContext,
    verified: &VerifiedAssertion,
) -> Result<()> {
    private_json::ensure_owner(intent_path, &context.intent)?;
    private_json::ensure_owner(challenge_path, &verified.challenge)?;
    private_json::ensure_owner(assertion_path, &verified.assertion)?;
    private_json::ensure_owner(credential_path, &context.credential)
}

fn consume_evidence(
    intent_path: &Path,
    challenge_path: &Path,
    assertion_path: &Path,
) -> Result<()> {
    private_json::remove_owner(challenge_path)?;
    private_json::remove_owner(assertion_path)?;
    private_json::remove_owner(intent_path)
}

fn receipt(context: DestructionContext) -> PaAuthorizedTrustDestructionV1 {
    PaAuthorizedTrustDestructionV1 {
        schema: AUTHORIZED_RECEIPT_SCHEMA.into(),
        state: "destroyed".into(),
        operation_id: context.intent.operation_id,
        scope: context.intent.scope,
        impact_digest_sha256: context.intent.impact_digest_sha256,
        intent_digest_sha256: context.intent_digest,
        pa_key: "destroyed".into(),
        public_state: "destroyed".into(),
        passkey_registration: "revoked".into(),
        contains_secret_values: false,
    }
}
