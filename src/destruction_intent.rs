use std::path::Path;

use crowsi_credential_broker::CredentialStore;
use crowsi_local_control_bridge::sha256_digest;

use crate::{
    PaDestructionIntentV1, PaDestructionPreflightV1, PaKeyError, PaKeyStateV1, PasskeyChallengeV1,
    PasskeyCredentialV1, Result, destruction_model::PREFLIGHT_SCHEMA, private_json, status,
    webauthn_challenge::create_bound_challenge, webauthn_verifier::read_current_passkey,
};

pub(crate) struct DestructionContext {
    pub authority: PaKeyStateV1,
    pub credential: PasskeyCredentialV1,
    pub intent: PaDestructionIntentV1,
    pub intent_digest: String,
    pub pa_binding: String,
}

/// Validates all native destruction targets without mutating them.
///
/// # Errors
///
/// Rejects unsafe files, unavailable custody, stale generations, and invalid intents.
pub fn preflight_trust_domain_destruction<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    credential_path: &Path,
    intent_path: &Path,
) -> Result<PaDestructionPreflightV1> {
    let context = load_context(store, state_path, credential_path, intent_path)?;
    Ok(PaDestructionPreflightV1 {
        schema: PREFLIGHT_SCHEMA.into(),
        state: "ready".into(),
        operation_id: context.intent.operation_id,
        scope: context.intent.scope,
        impact_digest_sha256: context.intent.impact_digest_sha256,
        intent_digest_sha256: context.intent_digest,
        pa_public_key_sha256: context.pa_binding,
        passkey_registration: "ready".into(),
        contains_secret_values: false,
    })
}

/// Creates an owner-only challenge bound to one exact destruction intent.
///
/// # Errors
///
/// Performs the complete read-only preflight before creating any challenge.
pub fn create_destruction_challenge<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    credential_path: &Path,
    intent_path: &Path,
    output_path: &Path,
) -> Result<PasskeyChallengeV1> {
    let context = load_context(store, state_path, credential_path, intent_path)?;
    create_bound_challenge(
        output_path,
        "trust-domain-destroy",
        &context.credential.rp_id,
        &context.credential.origin,
        &context.intent_digest,
    )
}

pub(crate) fn load_context<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    credential_path: &Path,
    intent_path: &Path,
) -> Result<DestructionContext> {
    let intent: PaDestructionIntentV1 = private_json::read_owner(intent_path)?;
    if !intent.valid() {
        return Err(PaKeyError::Authorization);
    }
    let authority = status(store, state_path)?;
    if intent.expected_public_key_hex != authority.public_key_hex {
        return Err(PaKeyError::Confirmation);
    }
    let pa_binding = sha256_digest(authority.public_key_hex.as_bytes());
    let credential = read_current_passkey(credential_path, &pa_binding)?;
    let intent_digest = destruction_intent_digest(&intent);
    Ok(DestructionContext {
        authority,
        credential,
        intent,
        intent_digest,
        pa_binding,
    })
}

#[must_use]
pub fn destruction_intent_digest(intent: &PaDestructionIntentV1) -> String {
    sha256_digest(&canonical_intent(intent))
}

fn canonical_intent(intent: &PaDestructionIntentV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    put(
        &mut bytes,
        "crowsi.policy-authority.trust-domain-destruction-intent.v1",
    );
    for value in [
        intent.schema.as_str(),
        intent.operation_id.as_str(),
        intent.scope.as_str(),
        intent.expected_public_key_hex.as_str(),
        intent.impact_digest_sha256.as_str(),
    ] {
        put(&mut bytes, value);
    }
    bytes
}

fn put(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
