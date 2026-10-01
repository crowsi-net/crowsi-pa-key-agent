use super::parse;

#[test]
fn challenge_requires_exact_identity_evidence_paths() {
    let arguments = [
        "credential-authorization-challenge",
        "--state",
        "/state",
        "--credential",
        "/credential",
        "--request",
        "/request",
        "--identity-assertion",
        "/identity",
        "--identity-status",
        "/status",
        "--identity-trust",
        "/trust",
        "--challenge",
        "/challenge",
        "--origin",
        "http://localhost:4213",
    ]
    .map(String::from);
    assert!(parse(&arguments).is_ok_and(|value| value.is_some()));
    let mut missing = arguments.to_vec();
    missing.drain(9..=10);
    assert!(parse(&missing).is_err());
    let mut relative = arguments.clone();
    relative[12] = "trust".into();
    assert!(parse(&relative).is_err());

    let mut missing_origin = arguments.to_vec();
    missing_origin.truncate(missing_origin.len() - 2);
    assert!(parse(&missing_origin).is_err());
}

#[test]
fn authorize_requires_identity_evidence_before_output() {
    let arguments = [
        "credential-authorize",
        "--state",
        "/state",
        "--credential",
        "/credential",
        "--challenge",
        "/challenge",
        "--assertion",
        "/passkey-assertion",
        "--request",
        "/request",
        "--identity-assertion",
        "/identity",
        "--identity-status",
        "/status",
        "--identity-trust",
        "/trust",
        "--output",
        "/output",
    ]
    .map(String::from);
    assert!(parse(&arguments).is_ok_and(|value| value.is_some()));
    let mut reordered = arguments;
    reordered.swap(13, 15);
    assert!(parse(&reordered).is_err());
}
