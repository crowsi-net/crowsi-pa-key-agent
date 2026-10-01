use crowsi_windows_operation_contracts::OperationOnlyCredentialClass;
use ed25519_dalek::{Signer, SigningKey};

use crate::operation_once_config::{
    OperationAuthorizationConfigV2, OperationCredentialMappingV1, VerifiedOperationConfig,
};

use super::evidence::Keys;

pub(crate) fn verified(keys: &Keys) -> VerifiedOperationConfig {
    VerifiedOperationConfig(
        OperationAuthorizationConfigV2 {
            schema: crate::operation_once_config::CONFIG_SCHEMA.into(),
            deployment_role: "managed-device-endpoint".into(),
            identity_issuer: "ihat-authority".into(),
            identity_audience: "crowsi-windows-custody-provider".into(),
            identity_key_id: "identity-key-1".into(),
            identity_public_key_hex: hex::encode(keys.identity.verifying_key().to_bytes()),
            current_status_key_id: "status-key-1".into(),
            current_status_public_key_hex: hex::encode(keys.status.verifying_key().to_bytes()),
            fresh_uv_key_id: "fresh-key-1".into(),
            fresh_uv_public_key_hex: hex::encode(keys.fresh.verifying_key().to_bytes()),
            fresh_uv_account_binding_sha256: "b2".repeat(32),
            authority_response_key_id: "authority-key-1".into(),
            authority_response_public_key_hex: hex::encode(
                keys.authority.verifying_key().to_bytes(),
            ),
            minimum_identity_config_generation: 7,
            pa_state_path: "/owner/pa-state.json".into(),
            custody_config_path: "/owner/custody.json".into(),
            replay_directory: "/owner/pa-operation-replay".into(),
            credential_mappings: vec![OperationCredentialMappingV1 {
                opaque_owner_ref: "psa_owner_abcdefghijklmnopqrst".into(),
                service_id: "service:crowsi".into(),
                device_id: "device-b".into(),
                device_proof_key_ref: "proof-key-b".into(),
                custody_credential_id: "custody-device-key-b".into(),
                expected_revision: super::target::revision(),
                credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
            }],
            issued_at_epoch_s: 90,
            expires_at_epoch_s: 200,
            configuration_key_id: "configuration-key-1".into(),
            signature: "44".repeat(64),
        },
        hex::encode(SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes()),
    )
}

pub(crate) fn wires(keys: &Keys) -> (Vec<u8>, Vec<u8>) {
    let root = SigningKey::from_bytes(&[5; 32]);
    let mut config = verified(keys).0;
    config.signature.clear();
    let payload = crate::operation_once_crypto::canonical_without_signature(
        b"CROWSI-PA-OPERATION-AUTHORIZATION-CONFIG-V2\0",
        &config,
    )
    .expect("payload");
    config.signature = hex::encode(root.sign(&payload).to_bytes());
    let root = serde_json::json!({
        "schema": crate::operation_once_config::ROOT_SCHEMA,
        "configuration_key_id": config.configuration_key_id.clone(),
        "configuration_public_key_hex": hex::encode(root.verifying_key().to_bytes()),
    });
    (
        serde_json::to_vec(&config).expect("config"),
        serde_json::to_vec(&root).expect("root"),
    )
}
