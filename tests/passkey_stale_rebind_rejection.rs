use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_pa_key_agent::{
    PasskeyChallengeV1, create_passkey_rebind_challenge, passkey_status, rebind_passkey,
};
use p256::ecdsa::SigningKey;
use serde_json::json;
use tempfile::tempdir;

use crate::support;
use support::{assertion, assertion_with_flags, owner_json, register};

const OLD: &str = "sha256:8888888888888888888888888888888888888888888888888888888888888888";
const CURRENT: &str = "sha256:9999999999999999999999999999999999999999999999999999999999999999";

#[test]
fn record_with_unknown_field_is_not_rebindable() {
    let fixture = stale(51, 0);
    let mut value = read(&fixture.credential);
    value["untrusted_provenance"] = json!("caller");
    owner_json(&fixture.credential, &value);

    let status = passkey_status(&fixture.credential, CURRENT);
    assert_eq!(status.state, "invalid");
    assert!(
        create_passkey_rebind_challenge(&fixture.credential, &fixture.challenge, CURRENT).is_err()
    );
}

#[test]
fn expired_or_wrong_context_challenge_preserves_evidence() {
    for mutation in ["expired", "context"] {
        let fixture = stale(if mutation == "expired" { 52 } else { 53 }, 0);
        let challenge =
            create_passkey_rebind_challenge(&fixture.credential, &fixture.challenge, CURRENT)
                .expect("challenge");
        let mut changed = serde_json::to_value(challenge).expect("challenge JSON");
        if mutation == "expired" {
            changed["expires_at_epoch_s"] = json!(1);
        } else {
            changed["context_sha256"] = json!(format!("sha256:{}", "f".repeat(64)));
        }
        owner_json(&fixture.challenge, &changed);
        let changed: PasskeyChallengeV1 = serde_json::from_value(changed).expect("challenge");
        owner_json(
            &fixture.assertion,
            &assertion(&changed, &fixture.signing, 1),
        );
        let before = fs::read(&fixture.credential).expect("credential");

        assert!(finish(&fixture).is_err());
        assert_eq!(fs::read(&fixture.credential).expect("after"), before);
        assert!(fixture.challenge.exists());
        assert!(fixture.assertion.exists());
    }
}

#[test]
fn rebind_requires_uv_and_increasing_counter() {
    let no_uv = stale(54, 0);
    let challenge = create_passkey_rebind_challenge(&no_uv.credential, &no_uv.challenge, CURRENT)
        .expect("challenge");
    owner_json(
        &no_uv.assertion,
        &assertion_with_flags(&challenge, &no_uv.signing, 1, 0x01),
    );
    assert!(finish(&no_uv).is_err());

    let downgrade = stale(55, 2);
    let challenge =
        create_passkey_rebind_challenge(&downgrade.credential, &downgrade.challenge, CURRENT)
            .expect("challenge");
    owner_json(
        &downgrade.assertion,
        &assertion(&challenge, &downgrade.signing, 1),
    );
    assert!(finish(&downgrade).is_err());
}

struct Fixture {
    _root: tempfile::TempDir,
    credential: std::path::PathBuf,
    challenge: std::path::PathBuf,
    assertion: std::path::PathBuf,
    signing: SigningKey,
}

fn stale(seed: u8, counter: u32) -> Fixture {
    let root = tempdir().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let credential = root.path().join("passkey.json");
    let signing = SigningKey::from_bytes((&[seed; 32]).into()).expect("key");
    register(&credential, root.path(), &signing, OLD);
    let mut value = read(&credential);
    value["sign_count"] = json!(counter);
    owner_json(&credential, &value);
    Fixture {
        credential,
        challenge: root.path().join("challenge.json"),
        assertion: root.path().join("assertion.json"),
        signing,
        _root: root,
    }
}

fn finish(
    fixture: &Fixture,
) -> crowsi_pa_key_agent::Result<crowsi_pa_key_agent::PasskeyCredentialV1> {
    rebind_passkey(
        &fixture.challenge,
        &fixture.assertion,
        &fixture.credential,
        CURRENT,
    )
}

fn read(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).expect("file")).expect("JSON")
}
