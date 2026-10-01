use crowsi_windows_operation_contracts::{
    OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_AUTHORIZATION_ISSUER,
    OPERATION_AUTHORIZATION_SCHEMA, OPERATION_REQUEST_SCHEMA, OPERATION_WORKLOAD_ID,
    OperationAuthorizeOnceRequestV2, OperationBinding, OperationOnlyAction, OperationOnlyRequest,
    PaOperationAuthorization, authorization_signing_bytes, operation_request_digest,
};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{FreshUvV1, IdentityEvidenceMetadata};

use crate::{PaKeyError, Result, operation_once_config::OperationCredentialMappingV1};

pub(crate) fn build(
    request: &OperationAuthorizeOnceRequestV2,
    mapping: &OperationCredentialMappingV1,
    pa_key_id: &str,
    pa: &SigningKey,
    now: u64,
) -> Result<OperationOnlyRequest> {
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
        &request.current_identity_exchange,
    )
    .map_err(|_| PaKeyError::Authorization)?;
    let fresh = crowsi_credential_authority_contracts::fresh_uv_from_finish_exchange(
        &request.finish_exchange,
        &request.management_request.command,
    )
    .map_err(|_| PaKeyError::Authorization)?;
    let status = &identity.current_status;
    let expires = expiry(request, identity, fresh, now);
    if expires <= now {
        return Err(PaKeyError::Authorization);
    }
    let mut output = OperationOnlyRequest {
        schema: OPERATION_REQUEST_SCHEMA.into(),
        request_id: request.sign_intent.request_id.clone(),
        credential_id: mapping.custody_credential_id.clone(),
        expected_revision: mapping.expected_revision.clone(),
        credential_class: mapping.credential_class,
        action: OperationOnlyAction::Sign {
            algorithm: request.sign_intent.algorithm,
            digest_sha256: request.sign_intent.digest_sha256.clone(),
        },
        current_device_status: status.clone(),
        pa_authorization: PaOperationAuthorization {
            schema: OPERATION_AUTHORIZATION_SCHEMA.into(),
            issuer: OPERATION_AUTHORIZATION_ISSUER.into(),
            key_id: pa_key_id.into(),
            binding: OperationBinding {
                service_id: status.service_id.clone(),
                pairwise_subject: status.pairwise_subject.clone(),
                device_id: status.device_id.clone(),
                device_proof_key_ref: status.device_proof_key_ref.clone(),
                session_ref: status.session_ref.clone(),
                device_posture: status.device_posture.state.clone(),
                device_posture_revision: status.device_posture.revision,
                subject_revocation_epoch: status.revocation_epochs.subject,
                service_revocation_epoch: status.revocation_epochs.service,
                device_revocation_epoch: status.revocation_epochs.device,
                session_revocation_epoch: status.revocation_epochs.session,
                workload_id: OPERATION_WORKLOAD_ID.into(),
                audience: OPERATION_AUTHORIZATION_AUDIENCE.into(),
                action: "sign:ed25519".into(),
                request_digest_sha256: String::new(),
                nonce: status.nonce.clone(),
            },
            issued_at_epoch_s: now,
            expires_at_epoch_s: expires,
            signature_hex: String::new(),
        },
    };
    output.pa_authorization.binding.request_digest_sha256 =
        operation_request_digest(&output).map_err(|_| PaKeyError::Authorization)?;
    let bytes = authorization_signing_bytes(&output.pa_authorization)
        .map_err(|_| PaKeyError::Authorization)?;
    output.pa_authorization.signature_hex = hex::encode(pa.sign(&bytes).to_bytes());
    Ok(output)
}

fn expiry(
    value: &OperationAuthorizeOnceRequestV2,
    identity: &IdentityEvidenceMetadata,
    fresh: &FreshUvV1,
    now: u64,
) -> u64 {
    [
        now.saturating_add(60),
        identity.assertion.expires_at_epoch_s,
        identity.current_status.expires_at_epoch_s,
        fresh.expires_at_epoch_s,
        value.target_device_proof.expires_at_epoch_s,
        value.prepared.expires_at_epoch_s,
    ]
    .into_iter()
    .min()
    .unwrap_or(now)
}
