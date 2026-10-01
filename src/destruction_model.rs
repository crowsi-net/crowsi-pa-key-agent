use serde::{Deserialize, Serialize};

pub const INTENT_SCHEMA: &str = "crowsi://policy-authority/trust-domain-destruction-intent/v1";
pub const PREFLIGHT_SCHEMA: &str =
    "crowsi://policy-authority/trust-domain-destruction-preflight/v1";
pub const AUTHORIZED_RECEIPT_SCHEMA: &str =
    "crowsi://policy-authority/authorized-trust-domain-destruction-receipt/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaDestructionIntentV1 {
    pub schema: String,
    pub operation_id: String,
    pub scope: String,
    pub expected_public_key_hex: String,
    pub impact_digest_sha256: String,
}

impl PaDestructionIntentV1 {
    pub(crate) fn valid(&self) -> bool {
        self.schema == INTENT_SCHEMA
            && lower_hex(&self.operation_id, 32)
            && self.scope == "local-trust-domain"
            && lower_hex(&self.expected_public_key_hex, 64)
            && digest(&self.impact_digest_sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaDestructionPreflightV1 {
    pub schema: String,
    pub state: String,
    pub operation_id: String,
    pub scope: String,
    pub impact_digest_sha256: String,
    pub intent_digest_sha256: String,
    pub pa_public_key_sha256: String,
    pub passkey_registration: String,
    pub contains_secret_values: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaAuthorizedTrustDestructionV1 {
    pub schema: String,
    pub state: String,
    pub operation_id: String,
    pub scope: String,
    pub impact_digest_sha256: String,
    pub intent_digest_sha256: String,
    pub pa_key: String,
    pub public_state: String,
    pub passkey_registration: String,
    pub contains_secret_values: bool,
}

fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|suffix| lower_hex(suffix, 64))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
