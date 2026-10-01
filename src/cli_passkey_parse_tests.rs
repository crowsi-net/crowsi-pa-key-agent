use super::parse;
use crate::{
    cli_parse::{Command, RegistrationCommand},
    cli_passkey_registration_dispatch::bootstrap_blocked,
};

#[test]
fn registration_challenge_preserves_every_authorized_argument() {
    let arguments = [
        "passkey-register-challenge",
        "--state",
        "/private/public-state.json",
        "--challenge",
        "/private/challenge.json",
        "--rp-id",
        "localhost",
        "--origin",
        "http://localhost:4203",
    ]
    .map(String::from);
    let command = parse(&arguments)
        .expect("valid command")
        .expect("recognized command");
    match command {
        Command::Registration(RegistrationCommand::Challenge {
            state,
            challenge,
            rp_id,
            origin,
        }) => {
            assert_eq!(state.to_str(), Some("/private/public-state.json"));
            assert_eq!(challenge.to_str(), Some("/private/challenge.json"));
            assert_eq!(rp_id, "localhost");
            assert_eq!(origin, "http://localhost:4203");
        }
        _ => panic!("wrong command"),
    }
}

#[test]
fn rebind_commands_require_ordered_absolute_paths() {
    let arguments = [
        "passkey-rebind",
        "--state",
        "/state",
        "--credential",
        "/credential",
        "--challenge",
        "/challenge",
        "--assertion",
        "/assertion",
    ]
    .map(String::from);
    assert!(parse(&arguments).is_ok_and(|value| value.is_some()));
    let mut relative = arguments;
    relative[8] = "assertion".into();
    assert!(parse(&relative).is_err());
}

#[test]
fn authentication_commands_require_ordered_absolute_paths() {
    let challenge = [
        "passkey-authentication-challenge",
        "--state",
        "/state",
        "--credential",
        "/credential",
        "--challenge",
        "/challenge",
    ]
    .map(String::from);
    assert!(parse(&challenge).is_ok_and(|value| value.is_some()));

    let assertion = [
        "passkey-authenticate",
        "--state",
        "/state",
        "--credential",
        "/credential",
        "--challenge",
        "/challenge",
        "--assertion",
        "/assertion",
    ]
    .map(String::from);
    assert!(parse(&assertion).is_ok_and(|value| value.is_some()));
    let mut relative = assertion;
    relative[8] = "assertion".into();
    assert!(parse(&relative).is_err());
}

#[test]
fn staged_registration_requires_every_ordered_owner_path() {
    let stage = [
        "passkey-register-stage",
        "--state",
        "/state",
        "--challenge",
        "/initial",
        "--response",
        "/response",
        "--candidate",
        "/candidate",
        "--proof-challenge",
        "/proof",
        "--credential",
        "/credential",
    ]
    .map(String::from);
    assert!(parse(&stage).is_ok_and(|value| value.is_some()));
    let mut missing = stage.to_vec();
    missing.pop();
    assert!(parse(&missing).is_err());

    let confirm = [
        "passkey-register-confirm",
        "--state",
        "/state",
        "--candidate",
        "/candidate",
        "--proof-challenge",
        "/proof",
        "--assertion",
        "/assertion",
        "--credential",
        "/credential",
    ]
    .map(String::from);
    assert!(parse(&confirm).is_ok_and(|value| value.is_some()));
    let parsed = parse(&confirm)
        .expect("valid command")
        .expect("recognized command");
    assert_eq!(
        bootstrap_blocked(&parsed),
        !cfg!(feature = "owner-local-bootstrap")
    );
}

#[test]
fn lost_passkey_recovery_requires_exact_order_and_absolute_managed_paths() {
    let arguments = [
        "passkey-recovery-revoke",
        "--state",
        "/private/policy-authority/public-state.json",
        "--credential",
        "/private/policy-authority/passkey.json",
        "--confirm-public-key",
        &"a".repeat(64),
        "--confirmation",
        "revoke-lost-passkey-registration",
    ]
    .map(String::from);
    assert!(parse(&arguments).is_ok_and(|value| value.is_some()));

    let mut relative = arguments.clone();
    relative[4] = "passkey.json".into();
    assert!(parse(&relative).is_err());
    let mut reordered = arguments;
    reordered.swap(5, 7);
    assert!(parse(&reordered).is_err());
}
