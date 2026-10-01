use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointFreshUvTrustV2, EndpointIdentityTrustV2,
    VerifiedEndpointApprovalV2, verify_endpoint_approval_at,
};
use crowsi_windows_operation_contracts::{
    OperationAuthorizeOnceRequestV2, decode_operation_authorize_once_request,
};

use crate::{
    PaKeyError, Result,
    operation_once_config::{OperationCredentialMappingV1, VerifiedOperationConfig},
};

pub(crate) fn verify<'a>(
    request: &OperationAuthorizeOnceRequestV2,
    config: &'a VerifiedOperationConfig,
    now: u64,
) -> Result<&'a OperationCredentialMappingV1> {
    strict_contract(request)?;
    let config = &config.0;
    if !crate::operation_once_config::roles_distinct(config)
        || now < config.issued_at_epoch_s
        || now >= config.expires_at_epoch_s
    {
        return Err(PaKeyError::Authorization);
    }
    let approval = verify_endpoint_approval_at(
        &request.selected_identity_exchange,
        &request.selected_begin_exchange,
        &request.finish_exchange,
        &request.current_identity_exchange,
        &request.prepared,
        &request.management_request.command,
        &EndpointAuthorityResponseTrustV2 {
            minimum_config_generation: config.minimum_identity_config_generation,
            key_id: &config.authority_response_key_id,
            public_key_hex: &config.authority_response_public_key_hex,
        },
        &EndpointIdentityTrustV2 {
            issuer: &config.identity_issuer,
            audience: &config.identity_audience,
            assertion_key_id: &config.identity_key_id,
            assertion_public_key_hex: &config.identity_public_key_hex,
            current_status_key_id: &config.current_status_key_id,
            current_status_public_key_hex: &config.current_status_public_key_hex,
            now_epoch_s: now,
        },
        &EndpointFreshUvTrustV2 {
            account_binding_sha256: &config.fresh_uv_account_binding_sha256,
            key_id: &config.fresh_uv_key_id,
            public_key_hex: &config.fresh_uv_public_key_hex,
            now_epoch_s: now,
        },
    )
    .map_err(|_| PaKeyError::Authorization)?;
    if !time_order(&approval, request, now) || !sender_distinct(&approval, config) {
        return Err(PaKeyError::Authorization);
    }
    select_mapping(request, config)
}

fn strict_contract(request: &OperationAuthorizeOnceRequestV2) -> Result<()> {
    let wire = serde_json::to_vec(request).map_err(|_| PaKeyError::Authorization)?;
    decode_operation_authorize_once_request(&wire)
        .map(|_| ())
        .map_err(|_| PaKeyError::Authorization)
}

fn time_order(
    approval: &VerifiedEndpointApprovalV2<'_>,
    value: &OperationAuthorizeOnceRequestV2,
    now: u64,
) -> bool {
    let assertion = &approval.current_identity.assertion;
    let status = &approval.current_identity.current_status;
    let fresh = approval.fresh_uv;
    let proof = &value.target_device_proof;
    let prepared = &value.prepared;
    fresh.issued_at_epoch_s <= assertion.issued_at_epoch_s
        && fresh.issued_at_epoch_s <= status.issued_at_epoch_s
        && assertion.issued_at_epoch_s <= proof.issued_at_epoch_s
        && status.issued_at_epoch_s <= proof.issued_at_epoch_s
        && proof.expires_at_epoch_s <= fresh.expires_at_epoch_s
        && proof.expires_at_epoch_s <= assertion.expires_at_epoch_s
        && proof.expires_at_epoch_s <= status.expires_at_epoch_s
        && proof.expires_at_epoch_s <= prepared.expires_at_epoch_s
        && prepared.issued_at_epoch_s <= now
        && now < prepared.expires_at_epoch_s
        && proof.issued_at_epoch_s <= now
        && now < proof.expires_at_epoch_s
}

fn sender_distinct(
    approval: &VerifiedEndpointApprovalV2<'_>,
    config: &crate::operation_once_config::OperationAuthorizationConfigV2,
) -> bool {
    let sender = approval.current_session_sender_key_id;
    sender == approval.selected_session_sender_key_id
        && sender != config.configuration_key_id
        && sender != config.authority_response_key_id
        && sender != config.identity_key_id
        && sender != config.current_status_key_id
        && sender != config.fresh_uv_key_id
}

fn select_mapping<'a>(
    request: &OperationAuthorizeOnceRequestV2,
    config: &'a crate::operation_once_config::OperationAuthorizationConfigV2,
) -> Result<&'a OperationCredentialMappingV1> {
    let proof = &request.target_device_proof;
    let intent = &request.sign_intent;
    let mut values = config.credential_mappings.iter().filter(|mapping| {
        mapping.opaque_owner_ref == proof.owner_ref
            && mapping.service_id == proof.service_id
            && mapping.device_id == proof.target_device_ref
            && mapping.device_proof_key_ref == proof.device_proof_key_ref
    });
    let mapping = values.next().ok_or(PaKeyError::Authorization)?;
    if values.next().is_some()
        || mapping.custody_credential_id != intent.credential_id
        || mapping.expected_revision != intent.expected_revision
        || mapping.expected_revision != proof.custody_revision
        || mapping.credential_class != intent.credential_class
    {
        return Err(PaKeyError::Authorization);
    }
    Ok(mapping)
}
