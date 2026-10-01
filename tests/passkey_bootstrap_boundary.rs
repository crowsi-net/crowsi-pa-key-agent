#![cfg(not(feature = "owner-local-bootstrap"))]

use std::process::Command;

const REASON: &str = "crowsi-pa-key-agent: pa-passkey-bootstrap-authorizer-not-provisioned";

#[test]
fn registration_commands_close_before_custody_or_path_access() {
    for arguments in [challenge(), stage(), confirmation()] {
        let output = Command::new(env!("CARGO_BIN_EXE_crowsi-pa-key-agent"))
            .args(arguments)
            .args(["--custody", "/not-present/custody.json"])
            .output()
            .expect("binary executes");
        assert_eq!(output.status.code(), Some(78));
        assert_eq!(String::from_utf8_lossy(&output.stderr).trim(), REASON);
        assert!(output.stdout.is_empty());
    }
}

fn challenge() -> Vec<&'static str> {
    vec![
        "passkey-register-challenge",
        "--state",
        "/not-present/state",
        "--challenge",
        "/not-present/challenge",
        "--rp-id",
        "localhost",
        "--origin",
        "http://localhost:4203",
    ]
}

fn stage() -> Vec<&'static str> {
    vec![
        "passkey-register-stage",
        "--state",
        "/not-present/state",
        "--challenge",
        "/not-present/challenge",
        "--response",
        "/not-present/response",
        "--candidate",
        "/not-present/candidate",
        "--proof-challenge",
        "/not-present/proof",
        "--credential",
        "/not-present/credential",
    ]
}

fn confirmation() -> Vec<&'static str> {
    vec![
        "passkey-register-confirm",
        "--state",
        "/not-present/state",
        "--candidate",
        "/not-present/candidate",
        "--proof-challenge",
        "/not-present/proof",
        "--assertion",
        "/not-present/assertion",
        "--credential",
        "/not-present/credential",
    ]
}
