use super::{DestructionCommand, parse, recognizes};

#[test]
fn authorized_destruction_commands_accept_only_ordered_absolute_paths() {
    let preflight = strings(&[
        "trust-domain-destroy-preflight",
        "--state",
        "/state.json",
        "--credential",
        "/credential.json",
        "--intent",
        "/intent.json",
    ]);
    assert!(matches!(
        parse(&preflight),
        Ok(DestructionCommand::Preflight { .. })
    ));
    let challenge = strings(&[
        "trust-domain-destroy-challenge",
        "--state",
        "/state.json",
        "--credential",
        "/credential.json",
        "--intent",
        "/intent.json",
        "--challenge",
        "/challenge.json",
    ]);
    assert!(matches!(
        parse(&challenge),
        Ok(DestructionCommand::Challenge { .. })
    ));
    let finish = strings(&[
        "trust-domain-destroy-finish",
        "--state",
        "/state.json",
        "--credential",
        "/credential.json",
        "--intent",
        "/intent.json",
        "--challenge",
        "/challenge.json",
        "--assertion",
        "/assertion.json",
    ]);
    assert!(matches!(
        parse(&finish),
        Ok(DestructionCommand::Finish { .. })
    ));
}

#[test]
fn removed_public_destroy_name_and_relative_paths_are_rejected() {
    assert!(!recognizes("destroy"));
    let native = strings(&[
        "destroy-native",
        "--state",
        "/state.json",
        "--credential",
        "/credential.json",
        "--confirm-public-key",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]);
    assert!(matches!(
        parse(&native),
        Ok(DestructionCommand::Native { .. })
    ));
    assert!(
        parse(&strings(&[
            "trust-domain-destroy-preflight",
            "--state",
            "relative.json",
            "--credential",
            "/credential.json",
            "--intent",
            "/intent.json",
        ]))
        .is_err()
    );
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}
