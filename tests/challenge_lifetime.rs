#![cfg(feature = "bootstrap-authorizer-internal")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

use crowsi_pa_key_agent::create_challenge;
use tempfile::tempdir;

#[test]
fn challenge_allows_a_bounded_external_authenticator_window() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let path = root.path().join("challenge.json");
    let challenge = create_challenge(
        &path,
        "credential-enroll",
        "localhost",
        "http://localhost:4203",
        &format!("sha256:{}", "a".repeat(64)),
    )
    .expect("challenge");
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("supported epoch");

    assert!(challenge.expires_at_epoch_s - now >= 170);
    assert!(challenge.expires_at_epoch_s - now <= 180);
}
