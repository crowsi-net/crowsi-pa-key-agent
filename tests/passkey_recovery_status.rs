use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_pa_key_agent::passkey_status;
use p256::ecdsa::SigningKey;
use serde_json::json;
use tempfile::tempdir;

use crate::support;
use support::{owner_json, register};

const FIRST_BINDING: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const SECOND_BINDING: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn missing_invalid_and_stale_registrations_are_distinct() {
    let root = private_root();
    let credential = root.path().join("passkey.json");
    let missing = passkey_status(&credential, FIRST_BINDING);
    assert_eq!(missing.state, "not-registered");
    assert_eq!(missing.reason_code, "pa-passkey-not-registered");

    owner_json(
        &credential,
        &json!({
            "schema": "crowsi://policy-authority/passkey-credential/v1",
            "credential_id_b64url": "invalid-without-pa-binding"
        }),
    );
    let invalid = passkey_status(&credential, FIRST_BINDING);
    assert_eq!(invalid.state, "invalid");
    assert_eq!(invalid.reason_code, "pa-passkey-registration-invalid");

    fs::remove_file(&credential).expect("remove invalid fixture");
    let signing = SigningKey::from_bytes((&[11_u8; 32]).into()).expect("P-256 key");
    register(&credential, root.path(), &signing, FIRST_BINDING);
    let stale = passkey_status(&credential, SECOND_BINDING);
    assert_eq!(stale.state, "stale");
    assert_eq!(stale.reason_code, "pa-passkey-pa-binding-stale");
}

fn private_root() -> tempfile::TempDir {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}
