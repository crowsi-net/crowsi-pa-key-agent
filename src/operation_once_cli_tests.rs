use std::os::unix::fs::PermissionsExt;

use crate::PaKeyError;

#[test]
fn pa_06_cli_is_one_finite_exact_operation() {
    for arguments in [
        vec![],
        vec!["operation-authorize-once"],
        vec!["operation-authorize-once", "--config", "relative.json"],
        vec!["operation-authorize-once", "--config", "/absolute.json"],
        vec![
            "operation-authorize-once",
            "--config",
            "/absolute.json",
            "--config-sha256",
        ],
        vec![
            "operation-authorize-once",
            "--config-sha256",
            concat!("sha256:", "11"),
            "--config",
            "/absolute.json",
        ],
        vec![
            "operation-authorize-once",
            "--config",
            "/absolute.json",
            "--config-sha256",
            concat!("SHA256:", "11"),
        ],
        vec![
            "operation-authorize-once",
            "--config",
            "/absolute.json",
            "--config-sha256",
            concat!("sha256:0x", "11"),
        ],
        vec![
            "operation-authorize-once",
            "--config",
            "/absolute.json",
            "--config-sha256",
            concat!("sha256:sha256:", "11"),
        ],
        vec!["get", "--config", "/absolute.json"],
        vec!["put", "--config", "/absolute.json"],
        vec!["delete", "--config", "/absolute.json"],
    ] {
        let arguments = arguments.into_iter().map(String::from).collect::<Vec<_>>();
        let result = crate::operation_once_cli::run(&arguments, &b""[..], Vec::new());
        assert!(matches!(result, Err(PaKeyError::Usage)));
    }
    let exact = vec![
        "operation-authorize-once".into(),
        "--config".into(),
        "/absolute.json".into(),
        "--config-sha256".into(),
        format!("sha256:{}", "11".repeat(32)),
    ];
    let (path, digest) = crate::operation_once_cli::config_arguments(&exact).expect("exact argv");
    assert_eq!(path, std::path::Path::new("/absolute.json"));
    assert_eq!(digest, exact[4]);
}

#[test]
fn pa_06_cli_has_fixed_root_bounded_stdio_and_no_environment_or_generic_surface() {
    let source = concat!(
        include_str!("operation_once_cli.rs"),
        include_str!("operation_once_config.rs"),
        include_str!("main.rs")
    );
    for required in [
        "operation-authorize-once",
        "--config",
        "--config-sha256",
        "take(65_537)",
        "/etc/crowsi/policy-authority/operation-authorize-once-v2.json",
    ] {
        assert!(source.contains(required), "missing CLI ratchet: {required}");
    }
    for forbidden in [
        "std::env::var",
        "GetSecret",
        "PutSecret",
        "DeleteSecret",
        "get-secret",
        "put-secret",
        "delete-secret",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden CLI surface: {forbidden}"
        );
    }
}

#[test]
fn pa_06_cli_validates_root_and_config_then_recovers_before_state_or_custody() {
    let source = include_str!("operation_once_cli.rs");
    let config = source
        .find("operation_once_config::verify")
        .expect("config");
    let recover = source.find("recover_wire").expect("recover");
    let state = source.find("pa_state_path").expect("state");
    let custody = source.find("custody_config_path").expect("custody");
    assert!(config < recover && recover < state && state < custody);
}

#[test]
fn pa_06_wrong_config_digest_cannot_emit_input_or_output() {
    use sha2::{Digest, Sha256};

    let root = super::operation_once_file_tests::private_root();
    let path = root.path().join("config.json");
    std::fs::write(&path, br#"{"secret":"must-not-escape"}"#).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let arguments = vec![
        "operation-authorize-once".into(),
        "--config".into(),
        path.to_str().expect("utf8 path").into(),
        "--config-sha256".into(),
        format!("sha256:{}", hex::encode(Sha256::digest(b"wrong"))),
    ];
    let mut output = Vec::new();
    let result = crate::operation_once_cli::run(
        &arguments,
        &b"stdin-secret-must-not-escape"[..],
        &mut output,
    );
    assert!(matches!(result, Err(PaKeyError::Authorization)));
    assert!(output.is_empty());
}
