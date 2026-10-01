use serde::{Deserialize, Serialize};

pub const STATE_SCHEMA: &str = "crowsi://policy-authority/key-state/v1";
pub const DIAGNOSIS_SCHEMA: &str = "crowsi://policy-authority/diagnosis/v1";
pub const DESTRUCTION_SCHEMA: &str = "crowsi://policy-authority/destruction-receipt/v1";
pub const TRUST_DESTRUCTION_SCHEMA: &str = "crowsi://policy-authority/trust-domain-destruction/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaKeyStateV1 {
    pub schema: String,
    pub state: String,
    pub key_id: String,
    pub key_version: u32,
    pub algorithm: String,
    pub public_key_hex: String,
    pub credential_revision: String,
    pub custody: String,
    pub registered_at_epoch_s: i64,
    pub authorization_issuance: String,
    pub reason_code: String,
    pub contains_secret_values: bool,
}

impl PaKeyStateV1 {
    pub(crate) fn new(public_key_hex: String, revision: String, custody: &str) -> Self {
        Self {
            schema: STATE_SCHEMA.into(),
            state: "ready".into(),
            key_id: "pa-credential-authorization-1".into(),
            key_version: 1,
            algorithm: "Ed25519".into(),
            public_key_hex,
            credential_revision: revision,
            custody: custody.into(),
            registered_at_epoch_s: unix_time(),
            authorization_issuance: "blocked".into(),
            reason_code: "phishing-resistant-user-verification-required".into(),
            contains_secret_values: false,
        }
    }

    pub(crate) fn valid(&self) -> bool {
        self.schema == STATE_SCHEMA
            && self.state == "ready"
            && self.key_version == 1
            && self.algorithm == "Ed25519"
            && self.public_key_hex.len() == 64
            && self.public_key_hex.bytes().all(lowercase_hex)
            && self.credential_revision.len() == 32
            && self.credential_revision.bytes().all(lowercase_hex)
            && !self.custody.is_empty()
            && self.registered_at_epoch_s > 0
            && self.authorization_issuance == "blocked"
            && self.reason_code == "phishing-resistant-user-verification-required"
            && !self.contains_secret_values
    }
}

fn lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaKeyDiagnosisV1 {
    pub schema: &'static str,
    pub state: &'static str,
    pub public_state: &'static str,
    pub key_binding: &'static str,
    pub public_key_hex: Option<String>,
    pub reason_code: &'static str,
    pub contains_secret_values: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaKeyDestructionV1 {
    pub schema: &'static str,
    pub state: &'static str,
    pub key_id: String,
    pub destroyed_public_key_hex: String,
    pub contains_secret_values: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaTrustDestructionV1 {
    pub schema: &'static str,
    pub state: &'static str,
    pub pa_key: &'static str,
    pub public_state: &'static str,
    pub passkey_registration: &'static str,
    pub destroyed_public_key_hex: String,
    pub contains_secret_values: bool,
}
