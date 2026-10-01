use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{PaKeyError, operation_once_test_support::Fixture};

#[test]
// OP-16: PA returns one complete request and replays only the exact durable response.
fn op_16_runtime_uses_independent_pa_key_and_recovers_exact_response() {
    let root = private_root();
    let state_path = root.path().join("public-state.json");
    let store = MemoryStore::default();
    let state = crate::initialize(&store, &state_path, "test-custody").expect("PA state");
    let mut fixture = Fixture::new();
    fixture.config.0.replay_directory = private_ledger(&root).to_string_lossy().into_owned();
    let state_wire = fs::read(&state_path).expect("state wire");
    let request_wire = serde_json::to_vec(&fixture.request).expect("request wire");
    let output = crate::operation_once_runtime::authorize(
        &store,
        &fixture.config,
        &state_wire,
        &request_wire,
        fixture.now,
    )
    .expect("authorized");
    assert_eq!(output.pa_authorization.key_id, state.key_id);
    assert_ne!(
        output.credential_id,
        output.current_device_status.device_proof_key_ref
    );
    assert_ne!(output.credential_id, output.pa_authorization.key_id);
    let recovered = crate::operation_once_runtime::authorize(
        &MemoryStore::default(),
        &fixture.config,
        b"invalid-state-must-not-be-read",
        &request_wire,
        fixture.now + 61,
    )
    .expect("durable exact recovery");
    assert_eq!(recovered, output);
}

#[test]
fn op_16_pa_key_must_differ_from_the_root_configuration_key() {
    let root = private_root();
    let state_path = root.path().join("public-state.json");
    let store = MemoryStore::default();
    let state = crate::initialize(&store, &state_path, "test-custody").expect("PA state");
    let mut fixture = Fixture::new();
    fixture.config.1 = state.public_key_hex;
    fixture.config.0.replay_directory = private_ledger(&root).to_string_lossy().into_owned();
    let result = crate::operation_once_runtime::authorize(
        &store,
        &fixture.config,
        &fs::read(state_path).expect("state wire"),
        &serde_json::to_vec(&fixture.request).expect("request wire"),
        fixture.now,
    );
    assert!(matches!(result, Err(PaKeyError::Authorization)));
}

#[test]
fn op_16_session_sender_key_cannot_alias_the_pa_key() {
    let root = private_root();
    let state_path = root.path().join("public-state.json");
    let store = MemoryStore::default();
    let state = crate::initialize(&store, &state_path, "test-custody").expect("PA state");
    let mut fixture = Fixture::new();
    fixture.config.0.replay_directory = private_ledger(&root).to_string_lossy().into_owned();
    for exchange in [
        &mut fixture.request.selected_identity_exchange,
        &mut fixture.request.current_identity_exchange,
    ] {
        let [AuthorityEvidence::Signed(sender)] = exchange.request.evidence.as_mut_slice() else {
            unreachable!()
        };
        sender.key_id.clone_from(&state.key_id);
    }
    let result = crate::operation_once_runtime::authorize(
        &store,
        &fixture.config,
        &fs::read(state_path).expect("state wire"),
        &serde_json::to_vec(&fixture.request).expect("request wire"),
        fixture.now,
    );
    assert!(matches!(result, Err(PaKeyError::Authorization)));
}

#[test]
fn op_16_source_orders_prepare_build_and_commit_before_return() {
    let source = include_str!("operation_once_runtime.rs");
    let fresh = source.find("fresh_entry").expect("fresh");
    let build = source.find("build_with_secret").expect("build");
    let complete = source.find("transaction.complete").expect("complete");
    let returned = source.rfind("Ok(response)").expect("return");
    assert!(fresh < build && build < complete && complete < returned);
    let authority = include_str!("operation_once_runtime_authority.rs");
    let metadata = authority.find(".metadata").expect("metadata");
    let prepare = authority.find("transaction.prepare").expect("prepare");
    assert!(metadata < prepare);
    let public = include_str!("lib.rs");
    for forbidden in [
        "pub use operation_once_runtime",
        "pub fn get",
        "pub fn put",
        "pub fn delete",
    ] {
        assert!(!public.contains(forbidden));
    }
}

fn private_root() -> tempfile::TempDir {
    let base = std::env::current_dir().expect("cwd");
    let root = tempfile::Builder::new()
        .prefix(".pa-runtime-")
        .tempdir_in(base)
        .expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}

fn private_ledger(root: &tempfile::TempDir) -> std::path::PathBuf {
    let ledger = root.path().join("replay");
    fs::create_dir(&ledger).expect("ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).expect("ledger mode");
    ledger
}
