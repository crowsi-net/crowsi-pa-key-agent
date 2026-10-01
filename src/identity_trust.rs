use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use ihat_identity_assertion_contracts::AssertionVerifier;
use serde::Deserialize;

use crate::{PaKeyError, Result, private_json};

const TRUST_SCHEMA: &str = "crowsi://policy-authority/identity-trust/v2";
const AUDIENCE: &str = "crowsi-policy-administrator";
const SERVICE: &str = "service:crowsi";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityTrustV2 {
    schema: String,
    issuer: String,
    audience: String,
    service_id: String,
    assertion_key_id: String,
    assertion_public_key_hex: String,
    status_key_id: String,
    status_public_key_hex: String,
}

pub(crate) struct IdentityTrust {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) service_id: String,
    pub(crate) assertion: PinnedVerifier,
    pub(crate) status: PinnedVerifier,
}

pub(crate) struct PinnedVerifier {
    key_id: String,
    key: VerifyingKey,
}

impl AssertionVerifier for PinnedVerifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        decode_signature(signature).is_some_and(|signature| {
            key_id == self.key_id && self.key.verify_strict(payload, &signature).is_ok()
        })
    }
}

pub(crate) fn read(path: &Path) -> Result<IdentityTrust> {
    let value: IdentityTrustV2 = private_json::read_owner(path)?;
    if value.schema != TRUST_SCHEMA
        || value.audience != AUDIENCE
        || value.service_id != SERVICE
        || invalid(&value.issuer, 512)
    {
        return Err(PaKeyError::Authorization);
    }
    let assertion = verifier(value.assertion_key_id, &value.assertion_public_key_hex)?;
    let status = verifier(value.status_key_id, &value.status_public_key_hex)?;
    if assertion.key.to_bytes() == status.key.to_bytes() {
        return Err(PaKeyError::Authorization);
    }
    Ok(IdentityTrust {
        issuer: value.issuer,
        audience: value.audience,
        service_id: value.service_id,
        assertion,
        status,
    })
}

fn verifier(key_id: String, encoded: &str) -> Result<PinnedVerifier> {
    if invalid(&key_id, 128) {
        return Err(PaKeyError::Authorization);
    }
    let bytes: [u8; 32] = hex::decode(encoded)
        .map_err(|_| PaKeyError::Authorization)?
        .try_into()
        .map_err(|_| PaKeyError::Authorization)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| PaKeyError::Authorization)?;
    if key.is_weak() {
        return Err(PaKeyError::Authorization);
    }
    Ok(PinnedVerifier { key_id, key })
}

fn invalid(value: &str, maximum: usize) -> bool {
    value.is_empty() || value.len() > maximum || value.chars().any(char::is_control)
}

fn decode_signature(value: &str) -> Option<Signature> {
    Signature::try_from(hex::decode(value).ok()?.as_slice()).ok()
}
