use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementCommandV2, ManagementIntentV2, ManagementRequestV2,
    TargetDeviceProofBindingV2, WebAuthnAssertionV2,
};
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

pub(super) fn prepared() -> EndpointPreparedOperationV2 {
    EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "a1".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: "session-a".into(),
        pairwise_subject: "psu_owner_pairwise".into(),
        opaque_owner_ref: "psa_owner_abcdefghijklmnopqrst".into(),
        source_identity_nonce: "source-identity-nonce".into(),
        nonce: "operation-nonce".into(),
        issued_at_epoch_s: 50,
        expires_at_epoch_s: 150,
        intent: ManagementIntentV2::DeviceTransfer {
            service_id: "service:crowsi".into(),
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-transfer-1".into()],
            expected_snapshot_revision: 7,
            nonce: "transfer-nonce".into(),
        },
        revocation: None,
    }
}

pub(super) fn management(operation_id: &str) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: "crowsi://credential-authority/management-request/v2".into(),
        request_id: "management-request-1".into(),
        command: ManagementCommandV2::TargetApprove {
            operation_id: operation_id.into(),
            expected_state_revision: 8,
            attempt_id: "uv-attempt-1".into(),
            assertion: WebAuthnAssertionV2 {
                credential_id: "passkey-target-b".into(),
                client_data_json_base64url: "Y2xpZW50LWRhdGE".into(),
                authenticator_data_base64url: "YXV0aGVudGljYXRvci1kYXRh".into(),
                signature_der_base64url: "c2lnbmF0dXJlLWRlcg".into(),
            },
        },
    }
}

pub(super) fn proof(
    identity: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    digest: &str,
) -> TargetDeviceProofBindingV2 {
    TargetDeviceProofBindingV2 {
        schema: "crowsi://identity/target-device-key-proof/v2".into(),
        owner_ref: prepared.opaque_owner_ref.clone(),
        service_id: "service:crowsi".into(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        operation_id: prepared.operation_id.clone(),
        challenge_digest_sha256: digest.into(),
        source_device_ref: prepared.source_device_ref.clone(),
        target_device_ref: identity.assertion.device_id.clone(),
        device_proof_key_ref: "proof-key-b".into(),
        custody_revision: revision(),
        status_nonce: identity.current_status.nonce.clone(),
        issued_at_epoch_s: 114,
        expires_at_epoch_s: 134,
        nonce: prepared.nonce.clone(),
        key_id: "proof-key-b".into(),
    }
}

pub(super) fn revision() -> String {
    format!("rev1:{}", "c3".repeat(32))
}
