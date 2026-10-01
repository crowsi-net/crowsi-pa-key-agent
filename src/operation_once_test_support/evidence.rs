use crowsi_credential_authority_contracts::EndpointPreparedOperationV2;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    AuthenticatorKindDto, CurrentDeviceStatusV1, DeviceIdentityAssertionV1, DevicePostureV1,
    FreshUvV1, IdentityEvidenceMetadata, RevocationEpochsV1, canonical_assertion_payload,
    canonical_current_status_payload, canonical_fresh_uv,
};

pub(crate) struct Keys {
    pub identity: SigningKey,
    pub status: SigningKey,
    pub fresh: SigningKey,
    pub authority: SigningKey,
}

impl Keys {
    pub fn new() -> Self {
        Self {
            identity: SigningKey::from_bytes(&[1; 32]),
            status: SigningKey::from_bytes(&[2; 32]),
            fresh: SigningKey::from_bytes(&[3; 32]),
            authority: SigningKey::from_bytes(&[4; 32]),
        }
    }
}

pub(super) fn selected(keys: &Keys) -> IdentityEvidenceMetadata {
    identity(keys, 60, 90, "selected-identity-nonce")
}

pub(super) fn current(keys: &Keys) -> IdentityEvidenceMetadata {
    identity(keys, 112, 140, "submission-current-nonce")
}

fn identity(keys: &Keys, issued: u64, expires: u64, nonce: &str) -> IdentityEvidenceMetadata {
    let posture = DevicePostureV1 {
        state: "compliant".into(),
        revision: 4,
    };
    let epochs = RevocationEpochsV1 {
        subject: 2,
        service: 3,
        device: 5,
        session: 7,
    };
    let mut assertion = DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: "ihat-authority".into(),
        audience: "crowsi-windows-custody-provider".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "psu_owner_pairwise".into(),
        device_id: "device-b".into(),
        device_proof_key_ref: "proof-key-b".into(),
        session_ref: "session-b".into(),
        device_posture: posture.clone(),
        revocation_epochs: epochs.clone(),
        issued_at_epoch_s: issued,
        expires_at_epoch_s: expires,
        nonce: nonce.into(),
        key_id: "identity-key-1".into(),
        signature: String::new(),
    };
    assertion.signature = hex::encode(
        keys.identity
            .sign(&canonical_assertion_payload(&assertion))
            .to_bytes(),
    );
    let mut status = CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: assertion.issuer.clone(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        device_id: assertion.device_id.clone(),
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        session_ref: assertion.session_ref.clone(),
        device_posture: posture,
        revocation_epochs: epochs,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: expires,
        nonce: nonce.into(),
        key_id: "status-key-1".into(),
        signature: String::new(),
    };
    status.signature = hex::encode(
        keys.status
            .sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    IdentityEvidenceMetadata {
        assertion,
        current_status: status,
    }
}

pub(super) fn fresh(
    keys: &Keys,
    selected: &IdentityEvidenceMetadata,
    prepared: &EndpointPreparedOperationV2,
    digest: &str,
) -> FreshUvV1 {
    let assertion = &selected.assertion;
    let epochs = &assertion.revocation_epochs;
    let mut value = FreshUvV1 {
        schema: "ihat://identity/authority-host/fresh-uv/v1".into(),
        proof_id: "fresh-proof-1".into(),
        credential_id: "passkey-target-b".into(),
        authenticator_key_fingerprint: "a4".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: 110,
        expires_at_epoch_s: 135,
        challenge: "fresh-challenge-1".into(),
        attempt_id: "uv-attempt-1".into(),
        identity_nonce: assertion.nonce.clone(),
        source_device_id: assertion.device_id.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        session_ref: assertion.session_ref.clone(),
        operation_digest_sha256: digest.into(),
        subject_epoch: epochs.subject,
        service_epoch: epochs.service,
        device_epoch: epochs.device,
        session_epoch: epochs.session,
        account_binding_sha256: "b2".repeat(32),
        key_id: "fresh-key-1".into(),
        signature: String::new(),
    };
    value.signature = hex::encode(
        keys.fresh
            .sign(&canonical_fresh_uv(&value).expect("fresh payload"))
            .to_bytes(),
    );
    value
}
