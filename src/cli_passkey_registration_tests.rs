use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;
use crowsi_pa_key_agent::initialize;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::challenge_with_store;

#[test]
fn owner_local_challenge_uses_the_live_pa_binding() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let state = root.path().join("public-state.json");
    let challenge = root.path().join("challenge.json");
    let store = MemoryStore::default();
    let pa = initialize(&store, &state, "memory").expect("PA");

    let value = challenge_with_store(
        &store,
        &state,
        &challenge,
        "localhost",
        "http://localhost:4203",
    )
    .expect("challenge");

    assert_eq!(value["operation"], "register");
    assert_eq!(value["rp_id"], "localhost");
    assert_eq!(value["origin"], "http://localhost:4203");
    assert_eq!(
        value["binding_sha256"],
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(pa.public_key_hex.as_bytes()))
        )
    );
    assert_eq!(
        fs::metadata(challenge)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn owner_local_challenge_rejects_an_untrusted_origin() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let state = root.path().join("public-state.json");
    let store = MemoryStore::default();
    initialize(&store, &state, "memory").expect("PA");

    let result = challenge_with_store(
        &store,
        &state,
        &root.path().join("challenge.json"),
        "localhost",
        "http://127.0.0.1:4203",
    );

    assert!(result.is_err());
}
