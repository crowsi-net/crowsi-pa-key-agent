use std::fs;

use crowsi_credential_broker::MemoryStore;

use crate::{PaKeyError, operation_once_recovery_support::*};

#[test]
fn prepared_retry_after_ttl_keeps_first_time_and_pinned_old_key() {
    let setup = Setup::new();
    setup.prepare();
    let recovered = crate::operation_once_runtime::authorize(
        &setup.store,
        &setup.fixture.config,
        &setup.state,
        &setup.request,
        setup.fixture.now + 61,
    )
    .expect("pinned prepared retry");
    assert_eq!(
        recovered.pa_authorization.issued_at_epoch_s,
        setup.fixture.now
    );
}

#[test]
fn prepared_retry_uses_retained_old_revision_after_public_state_rotation() {
    let setup = Setup::new();
    setup.prepare();
    let replacement_root = private_root(".pa-state-rotation-");
    let replacement_path = replacement_root.path().join("state.json");
    let replacement_store = MemoryStore::default();
    crate::initialize(&replacement_store, &replacement_path, "replacement").expect("replacement");
    let mut rotated_config = setup.fixture.config.clone();
    rotated_config.0.credential_mappings[0].custody_credential_id = "new-current-mapping".into();
    let response = crate::operation_once_runtime::authorize(
        &setup.store,
        &rotated_config,
        &fs::read(replacement_path).expect("replacement state"),
        &setup.request,
        setup.fixture.now + 1,
    )
    .expect("retained old revision");
    let original: crate::PaKeyStateV1 = serde_json::from_slice(&setup.state).expect("old state");
    assert_eq!(response.pa_authorization.key_id, original.key_id);
}

#[test]
fn new_key_cannot_substitute_when_pinned_old_revision_is_gone() {
    let setup = Setup::new();
    setup.prepare();
    let replacement_root = private_root(".pa-key-substitution-");
    let replacement_path = replacement_root.path().join("state.json");
    let replacement = MemoryStore::default();
    crate::initialize(&replacement, &replacement_path, "replacement").expect("replacement");
    let result = crate::operation_once_runtime::authorize(
        &replacement,
        &setup.fixture.config,
        &fs::read(replacement_path).expect("replacement state"),
        &setup.request,
        setup.fixture.now + 1,
    );
    assert!(matches!(result, Err(PaKeyError::Custody)));
}
