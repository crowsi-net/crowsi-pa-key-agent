use crowsi_windows_operation_contracts::OperationOnlyCredentialClass;
use serde::{Deserialize, Serialize};

use crate::{PaKeyError, Result};

pub(crate) const ROOT_TRUST_PATH: &str =
    "/etc/crowsi/policy-authority/operation-authorize-once-v2.json";
pub(crate) const CONFIG_SCHEMA: &str =
    "crowsi://policy-authority/operation-authorization-config/v2";
pub(crate) const ROOT_SCHEMA: &str =
    "crowsi://policy-authority/operation-authorization-root-trust/v2";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationAuthorizationRootTrustV2 {
    pub schema: String,
    pub configuration_key_id: String,
    pub configuration_public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationCredentialMappingV1 {
    pub opaque_owner_ref: String,
    pub service_id: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub custody_credential_id: String,
    pub expected_revision: String,
    pub credential_class: OperationOnlyCredentialClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationAuthorizationConfigV2 {
    pub schema: String,
    pub deployment_role: String,
    pub identity_issuer: String,
    pub identity_audience: String,
    pub identity_key_id: String,
    pub identity_public_key_hex: String,
    pub current_status_key_id: String,
    pub current_status_public_key_hex: String,
    pub fresh_uv_key_id: String,
    pub fresh_uv_public_key_hex: String,
    pub fresh_uv_account_binding_sha256: String,
    pub authority_response_key_id: String,
    pub authority_response_public_key_hex: String,
    pub minimum_identity_config_generation: u64,
    pub pa_state_path: String,
    pub custody_config_path: String,
    pub replay_directory: String,
    pub credential_mappings: Vec<OperationCredentialMappingV1>,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub configuration_key_id: String,
    pub signature: String,
}

#[derive(Clone)]
pub(crate) struct VerifiedOperationConfig(
    pub(crate) OperationAuthorizationConfigV2,
    pub(crate) String,
);

pub(crate) fn verify(
    config_wire: &[u8],
    root_wire: &[u8],
    now: u64,
) -> Result<VerifiedOperationConfig> {
    let config: OperationAuthorizationConfigV2 = strict(config_wire, 262_144)?;
    let root: OperationAuthorizationRootTrustV2 = strict(root_wire, 16_384)?;
    crate::operation_once_config_validate::validate(&config, &root, now)?;
    let payload = crate::operation_once_crypto::canonical_without_signature(
        b"CROWSI-PA-OPERATION-AUTHORIZATION-CONFIG-V2\0",
        &config,
    )?;
    crate::operation_once_crypto::verify_signature(
        &root.configuration_public_key_hex,
        &config.signature,
        &payload,
    )?;
    Ok(VerifiedOperationConfig(
        config,
        root.configuration_public_key_hex,
    ))
}

fn strict<T: for<'de> Deserialize<'de>>(wire: &[u8], max: usize) -> Result<T> {
    if wire.is_empty() || wire.len() > max {
        return Err(PaKeyError::Authorization);
    }
    let mut decoder = serde_json::Deserializer::from_slice(wire);
    let value = T::deserialize(&mut decoder).map_err(|_| PaKeyError::Authorization)?;
    decoder.end().map_err(|_| PaKeyError::Authorization)?;
    Ok(value)
}

pub(crate) fn roles_distinct(value: &OperationAuthorizationConfigV2) -> bool {
    let ids = [
        &value.identity_key_id,
        &value.current_status_key_id,
        &value.fresh_uv_key_id,
        &value.authority_response_key_id,
        &value.configuration_key_id,
    ];
    let keys = [
        &value.identity_public_key_hex,
        &value.current_status_public_key_hex,
        &value.fresh_uv_public_key_hex,
        &value.authority_response_public_key_hex,
    ];
    ids.iter()
        .enumerate()
        .all(|(index, item)| !ids[..index].contains(item))
        && keys
            .iter()
            .enumerate()
            .all(|(index, item)| !keys[..index].contains(item))
}
