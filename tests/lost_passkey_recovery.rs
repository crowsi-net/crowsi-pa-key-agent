use std::os::unix::fs::symlink;

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::{PaKeyError, initialize, revoke_lost_passkey_registration, status};

#[path = "lost_passkey_recovery/support.rs"]
mod recovery_support;
use recovery_support::{owner_file, private_root};

const CONFIRMATION: &str = "revoke-lost-passkey-registration";

#[test]
fn lost_authenticator_recovery_revokes_only_the_server_registration() {
    let root = private_root();
    let store = MemoryStore::default();
    let state = root.path().join("public-state.json");
    let credential = root.path().join("passkey.json");
    let external_credential = root.path().join("external-service.json");
    let pa = initialize(&store, &state, "memory").expect("PA");
    owner_file(&credential, br#"{"schema":"damaged-registration"}"#);
    owner_file(&external_credential, br#"{"token":"must-remain"}"#);
    let receipt = revoke_lost_passkey_registration(
        &store,
        &state,
        &credential,
        &pa.public_key_hex,
        CONFIRMATION,
    )
    .expect("targeted recovery");
    assert_eq!(receipt.state, "completed");
    assert_eq!(receipt.scope, "server-passkey-registration");
    assert_eq!(receipt.pa_key, "retained");
    assert_eq!(receipt.public_state, "retained");
    assert_eq!(receipt.passkey_registration, "revoked");
    assert_eq!(receipt.authenticator_credential, "unchanged");
    assert_eq!(receipt.public_key_hex, pa.public_key_hex);
    assert!(!receipt.contains_secret_values);
    assert!(!credential.exists());
    assert!(external_credential.exists());
    assert_eq!(status(&store, &state).expect("PA remains"), pa);
}

#[test]
fn missing_server_registration_is_an_idempotent_absence() {
    let root = private_root();
    let store = MemoryStore::default();
    let state = root.path().join("public-state.json");
    let credential = root.path().join("passkey.json");
    let pa = initialize(&store, &state, "memory").expect("PA");
    let receipt = revoke_lost_passkey_registration(
        &store,
        &state,
        &credential,
        &pa.public_key_hex,
        CONFIRMATION,
    )
    .expect("missing registration");
    assert_eq!(receipt.passkey_registration, "absent");
    assert_eq!(status(&store, &state).expect("PA remains"), pa);
}

#[test]
fn stale_confirmation_and_wrong_phrase_preserve_everything() {
    let root = private_root();
    let store = MemoryStore::default();
    let state = root.path().join("public-state.json");
    let credential = root.path().join("passkey.json");
    let pa = initialize(&store, &state, "memory").expect("PA");
    owner_file(&credential, b"{}");

    let mismatched = revoke_lost_passkey_registration(
        &store,
        &state,
        &credential,
        &"0".repeat(64),
        CONFIRMATION,
    );
    assert!(matches!(mismatched, Err(PaKeyError::RecoveryConfirmation)));
    let wrong_phrase = revoke_lost_passkey_registration(
        &store,
        &state,
        &credential,
        &pa.public_key_hex,
        "destroy-everything",
    );
    assert!(matches!(
        wrong_phrase,
        Err(PaKeyError::RecoveryConfirmation)
    ));
    assert!(credential.exists());
    assert_eq!(status(&store, &state).expect("PA remains"), pa);
}

#[test]
fn recovery_cannot_be_used_as_an_arbitrary_owner_file_delete() {
    let root = private_root();
    let store = MemoryStore::default();
    let state = root.path().join("public-state.json");
    let unrelated = root.path().join("external-service.json");
    let pa = initialize(&store, &state, "memory").expect("PA");
    owner_file(&unrelated, b"{}");

    let result = revoke_lost_passkey_registration(
        &store,
        &state,
        &unrelated,
        &pa.public_key_hex,
        CONFIRMATION,
    );

    assert!(matches!(result, Err(PaKeyError::UnsafePath)));
    assert!(unrelated.exists());
    assert_eq!(status(&store, &state).expect("PA remains"), pa);
}

#[test]
fn symlinked_registration_is_rejected_and_its_target_is_preserved() {
    let root = private_root();
    let store = MemoryStore::default();
    let state = root.path().join("public-state.json");
    let credential = root.path().join("passkey.json");
    let outside = root.path().join("outside.json");
    let pa = initialize(&store, &state, "memory").expect("PA");
    owner_file(&outside, b"{}");
    symlink(&outside, &credential).expect("symlink fixture");

    let result = revoke_lost_passkey_registration(
        &store,
        &state,
        &credential,
        &pa.public_key_hex,
        CONFIRMATION,
    );

    assert!(matches!(result, Err(PaKeyError::UnsafePath)));
    assert!(credential.exists());
    assert!(outside.exists());
    assert_eq!(status(&store, &state).expect("PA remains"), pa);
}
