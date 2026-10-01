use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use ihat_identity_assertion_contracts::{
    CurrentDeviceStatusV1, DeviceIdentityAssertionV1, DevicePostureV1, RevocationEpochsV1,
    canonical_assertion_payload, canonical_current_status_payload,
};

use super::owner_json;

pub fn identity_evidence(root: &Path, suffix: &str) -> (PathBuf, PathBuf, PathBuf) {
    let assertion_signer = SigningKey::from_bytes(&[41; 32]);
    let status_signer = SigningKey::from_bytes(&[42; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut assertion = assertion(suffix, now);
    assertion.signature = hex::encode(
        assertion_signer
            .sign(&canonical_assertion_payload(&assertion))
            .to_bytes(),
    );
    let assertion_path = root.join(format!("identity-{suffix}.json"));
    let status_path = root.join(format!("identity-status-{suffix}.json"));
    let trust_path = root.join(format!("identity-trust-{suffix}.json"));
    owner_json(&assertion_path, &assertion);
    let mut status = status(&assertion, now);
    status.signature = hex::encode(
        status_signer
            .sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    owner_json(&status_path, &status);
    owner_json(&trust_path, &trust(&assertion_signer, &status_signer));
    (assertion_path, status_path, trust_path)
}

pub fn share_identity_trust_key(status_path: &Path, trust_path: &Path) {
    let signer = SigningKey::from_bytes(&[41; 32]);
    let mut status: CurrentDeviceStatusV1 =
        serde_json::from_slice(&std::fs::read(status_path).expect("status")).expect("JSON");
    status.signature = hex::encode(
        signer
            .sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    owner_json(status_path, &status);
    let mut trust: serde_json::Value =
        serde_json::from_slice(&std::fs::read(trust_path).expect("trust")).expect("JSON");
    trust["status_public_key_hex"] = trust["assertion_public_key_hex"].clone();
    owner_json(trust_path, &trust);
}

fn assertion(suffix: &str, now: u64) -> DeviceIdentityAssertionV1 {
    DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: "ihat-identity-runtime".into(),
        audience: "crowsi-policy-administrator".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise:crowsi:owner".into(),
        device_id: format!("device:{suffix}"),
        device_proof_key_ref: format!("device-proof:{suffix}"),
        session_ref: format!("sref_service_crowsi_{suffix}"),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 2,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 1,
            service: 2,
            device: 3,
            session: 4,
        },
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 120,
        nonce: format!("identity-nonce:{suffix}"),
        key_id: "identity-key:1".into(),
        signature: String::new(),
    }
}

fn status(value: &DeviceIdentityAssertionV1, now: u64) -> CurrentDeviceStatusV1 {
    CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: value.issuer.clone(),
        audience: value.audience.clone(),
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        device_id: value.device_id.clone(),
        device_proof_key_ref: value.device_proof_key_ref.clone(),
        session_ref: value.session_ref.clone(),
        device_posture: value.device_posture.clone(),
        revocation_epochs: value.revocation_epochs.clone(),
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 30,
        nonce: value.nonce.clone(),
        key_id: "identity-status-key:1".into(),
        signature: String::new(),
    }
}

fn trust(assertion: &SigningKey, status: &SigningKey) -> serde_json::Value {
    serde_json::json!({
        "schema": "crowsi://policy-authority/identity-trust/v2",
        "issuer": "ihat-identity-runtime",
        "audience": "crowsi-policy-administrator",
        "service_id": "service:crowsi",
        "assertion_key_id": "identity-key:1",
        "assertion_public_key_hex": hex::encode(assertion.verifying_key().to_bytes()),
        "status_key_id": "identity-status-key:1",
        "status_public_key_hex": hex::encode(status.verifying_key().to_bytes())
    })
}
