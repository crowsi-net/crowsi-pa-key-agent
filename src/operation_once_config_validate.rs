use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

use crowsi_windows_operation_contracts::{
    OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_SERVICE_ID, OperationOnlyCredentialClass,
};

use crate::{
    PaKeyError, Result,
    operation_once_config::{
        CONFIG_SCHEMA, OperationAuthorizationConfigV2, OperationAuthorizationRootTrustV2,
        ROOT_SCHEMA,
    },
};

pub(crate) fn validate(
    value: &OperationAuthorizationConfigV2,
    root: &OperationAuthorizationRootTrustV2,
    now: u64,
) -> Result<()> {
    let current = value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 31_536_000;
    let exact = value.schema == CONFIG_SCHEMA
        && root.schema == ROOT_SCHEMA
        && value.deployment_role == "managed-device-endpoint"
        && value.identity_audience == OPERATION_AUTHORIZATION_AUDIENCE
        && value.configuration_key_id == root.configuration_key_id
        && current
        && id(&value.identity_issuer, 512)
        && id(&value.identity_key_id, 128)
        && key(&value.identity_public_key_hex)
        && id(&value.current_status_key_id, 128)
        && key(&value.current_status_public_key_hex)
        && id(&value.fresh_uv_key_id, 128)
        && key(&value.fresh_uv_public_key_hex)
        && digest(&value.fresh_uv_account_binding_sha256)
        && id(&value.authority_response_key_id, 128)
        && key(&value.authority_response_public_key_hex)
        && value.minimum_identity_config_generation > 0
        && id(&root.configuration_key_id, 128)
        && key(&root.configuration_public_key_hex)
        && ![
            &value.identity_public_key_hex,
            &value.current_status_public_key_hex,
            &value.fresh_uv_public_key_hex,
            &value.authority_response_public_key_hex,
        ]
        .contains(&&root.configuration_public_key_hex)
        && signature(&value.signature)
        && crate::operation_once_config::roles_distinct(value)
        && paths(value)
        && mappings(value);
    exact.then_some(()).ok_or(PaKeyError::Authorization)
}

fn mappings(value: &OperationAuthorizationConfigV2) -> bool {
    if value.credential_mappings.len() != 1 {
        return false;
    }
    let mut tuples = BTreeSet::new();
    value.credential_mappings.iter().all(|mapping| {
        let tuple = (
            &mapping.opaque_owner_ref,
            &mapping.service_id,
            &mapping.device_id,
            &mapping.device_proof_key_ref,
        );
        mapping.opaque_owner_ref.starts_with("psa_")
            && id(&mapping.opaque_owner_ref, 128)
            && mapping.service_id == OPERATION_SERVICE_ID
            && id(&mapping.device_id, 128)
            && id(&mapping.device_proof_key_ref, 240)
            && id(&mapping.custody_credential_id, 128)
            && revision(&mapping.expected_revision)
            && mapping.credential_class == OperationOnlyCredentialClass::Ed25519SigningKey
            && tuples.insert(tuple)
    })
}

fn paths(value: &OperationAuthorizationConfigV2) -> bool {
    [
        &value.pa_state_path,
        &value.custody_config_path,
        &value.replay_directory,
    ]
    .iter()
    .all(|item| absolute(item))
}
fn absolute(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && value.len() <= 4096
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
fn id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn key(value: &str) -> bool {
    value.len() == 64 && lower_hex(value)
}
fn digest(value: &str) -> bool {
    value.len() == 64 && lower_hex(value)
}
fn signature(value: &str) -> bool {
    value.len() == 128 && lower_hex(value)
}
fn revision(value: &str) -> bool {
    value.len() == 69 && value.starts_with("rev1:") && lower_hex(&value[5..])
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
