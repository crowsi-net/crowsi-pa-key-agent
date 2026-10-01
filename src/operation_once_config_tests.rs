use ed25519_dalek::{Signer, SigningKey};

use crate::{operation_once_config, operation_once_test_support::evidence::Keys};

#[test]
fn pa_06_root_signature_pins_the_closed_current_config_and_mapping() {
    let keys = Keys::new();
    let (config, root) = crate::operation_once_test_support::config::wires(&keys);
    let verified = operation_once_config::verify(&config, &root, 120).expect("verified config");
    let mapping = &verified.0.credential_mappings[0];
    assert_eq!(mapping.device_proof_key_ref, "proof-key-b");
    assert_eq!(mapping.custody_credential_id, "custody-device-key-b");
    assert_ne!(mapping.device_proof_key_ref, mapping.custody_credential_id);

    let mut substituted: serde_json::Value = serde_json::from_slice(&config).expect("value");
    substituted["credential_mappings"][0]["custody_credential_id"] = "caller-key".into();
    assert!(
        operation_once_config::verify(&serde_json::to_vec(&substituted).expect("wire"), &root, 120)
            .is_err()
    );
}

#[test]
fn pa_06_operation_authorization_trust_is_current_v2_only() {
    assert_eq!(
        operation_once_config::CONFIG_SCHEMA,
        "crowsi://policy-authority/operation-authorization-config/v2"
    );
    assert_eq!(
        operation_once_config::ROOT_SCHEMA,
        "crowsi://policy-authority/operation-authorization-root-trust/v2"
    );
    assert_eq!(
        operation_once_config::ROOT_TRUST_PATH,
        "/etc/crowsi/policy-authority/operation-authorize-once-v2.json"
    );
}

#[test]
fn pa_06_config_rejects_unknown_trailing_old_stale_and_oversized_input() {
    let keys = Keys::new();
    let (config, root) = crate::operation_once_test_support::config::wires(&keys);
    let mut unknown: serde_json::Value = serde_json::from_slice(&config).expect("value");
    unknown["authority_executable"] = "/tmp/legacy".into();
    assert!(
        operation_once_config::verify(&serde_json::to_vec(&unknown).expect("wire"), &root, 120)
            .is_err()
    );
    let mut trailing = config.clone();
    trailing.extend_from_slice(b" {}");
    assert!(operation_once_config::verify(&trailing, &root, 120).is_err());
    let mut old: serde_json::Value = serde_json::from_slice(&config).expect("value");
    old["schema"] = "crowsi://policy-authority/operation-authorization-config/v1".into();
    assert!(
        operation_once_config::verify(&serde_json::to_vec(&old).expect("wire"), &root, 120)
            .is_err()
    );
    let mut old_root: serde_json::Value = serde_json::from_slice(&root).expect("root");
    old_root["schema"] = "crowsi://policy-authority/operation-authorization-root-trust/v1".into();
    assert!(
        operation_once_config::verify(
            &config,
            &serde_json::to_vec(&old_root).expect("root wire"),
            120,
        )
        .is_err()
    );
    assert!(operation_once_config::verify(&config, &root, 200).is_err());
    assert!(operation_once_config::verify(&vec![b' '; 262_145], &root, 120).is_err());
}

#[test]
fn pa_06_configuration_key_is_distinct_from_ihat_roles() {
    let keys = Keys::new();
    let mut config = crate::operation_once_test_support::config::verified(&keys).0;
    let root_key = SigningKey::from_bytes(&[1; 32]);
    let payload = crate::operation_once_crypto::canonical_without_signature(
        b"CROWSI-PA-OPERATION-AUTHORIZATION-CONFIG-V2\0",
        &config,
    )
    .expect("payload");
    config.signature = hex::encode(root_key.sign(&payload).to_bytes());
    let root = serde_json::to_vec(&serde_json::json!({
        "schema": operation_once_config::ROOT_SCHEMA,
        "configuration_key_id": config.configuration_key_id.clone(),
        "configuration_public_key_hex": hex::encode(root_key.verifying_key().to_bytes()),
    }))
    .expect("root");
    assert!(
        operation_once_config::verify(&serde_json::to_vec(&config).expect("config"), &root, 120)
            .is_err()
    );
}
