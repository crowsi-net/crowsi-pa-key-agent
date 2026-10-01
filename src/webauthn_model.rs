use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCredentialV1 {
    pub schema: String,
    pub credential_id_b64url: String,
    pub public_key_spki_b64url: String,
    pub rp_id: String,
    pub origin: String,
    pub pa_public_key_sha256: String,
    pub sign_count: u32,
    pub registered_at_epoch_s: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyChallengeV1 {
    pub schema: String,
    pub ceremony_id: String,
    pub operation: String,
    pub challenge_b64url: String,
    pub rp_id: String,
    pub origin: String,
    pub binding_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_sha256: Option<String>,
    pub expires_at_epoch_s: i64,
}

#[cfg(feature = "bootstrap-authorizer-internal")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct PasskeyRegistrationV1 {
    pub credential_id_b64url: String,
    pub client_data_json_b64url: String,
    pub authenticator_data_b64url: String,
    pub public_key_spki_b64url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct PasskeyAssertionV1 {
    pub credential_id_b64url: String,
    pub client_data_json_b64url: String,
    pub authenticator_data_b64url: String,
    pub signature_b64url: String,
}

#[cfg(feature = "bootstrap-authorizer-internal")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasskeyRegistrationCandidateV1 {
    pub schema: String,
    pub credential: PasskeyCredentialV1,
    pub target_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PasskeyStatusV1 {
    pub schema: &'static str,
    pub state: &'static str,
    pub credential_id_b64url: Option<String>,
    pub rp_id: Option<String>,
    pub origin: Option<String>,
    pub pa_public_key_sha256: Option<String>,
    pub reason_code: &'static str,
    pub contains_secret_values: bool,
}

#[derive(Deserialize)]
pub(crate) struct ClientData {
    #[serde(rename = "type")]
    pub kind: String,
    pub challenge: String,
    pub origin: String,
    #[serde(default, rename = "crossOrigin")]
    pub cross_origin: bool,
}
