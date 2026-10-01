use crowsi_local_control_bridge::{ControlAuthorizationV2, ControlRequestV1};
use ed25519_dalek::SigningKey;
use ihat_identity_assertion_contracts::DeviceIdentityAssertionV1;

use crate::control_authorization_policy::ControlAuthorizationPolicy;

pub(crate) fn build(
    request: &ControlRequestV1,
    sender: &SigningKey,
    identity: &DeviceIdentityAssertionV1,
    status_expires_at_epoch_s: u64,
    reservation: &str,
    issued: i64,
    policy: &ControlAuthorizationPolicy,
) -> ControlAuthorizationV2 {
    ControlAuthorizationV2 {
        schema: "crowsi://local-control/authorization/v2".into(),
        issuer: "crowsi-policy-administrator".into(),
        audience: "crowsi-local-control-bridge".into(),
        service_id: identity.service_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        device_id: identity.device_id.clone(),
        device_proof_key_ref: identity.device_proof_key_ref.clone(),
        session_ref: identity.session_ref.clone(),
        device_posture: identity.device_posture.state.clone(),
        device_posture_revision: identity.device_posture.revision,
        subject_revocation_epoch: identity.revocation_epochs.subject,
        service_revocation_epoch: identity.revocation_epochs.service,
        device_revocation_epoch: identity.revocation_epochs.device,
        session_revocation_epoch: identity.revocation_epochs.session,
        workload_id: policy.workload_id.into(),
        actor_profile_id: policy.actor_profile_id.into(),
        assurance: "phishing-resistant".into(),
        user_verification: true,
        sender_public_key_hex: hex::encode(sender.verifying_key().to_bytes()),
        request_id: request.request_id.clone(),
        action: request.action,
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        body_sha256: request.body_sha256.clone(),
        reservation_id: reservation.into(),
        issued_at_epoch_s: issued,
        expires_at_epoch_s: expiry(identity, status_expires_at_epoch_s, issued),
    }
}

fn expiry(value: &DeviceIdentityAssertionV1, status_expires: u64, issued: i64) -> i64 {
    i64::try_from(value.expires_at_epoch_s)
        .unwrap_or(i64::MAX)
        .min(i64::try_from(status_expires).unwrap_or(i64::MAX))
        .min(issued.saturating_add(30))
}
