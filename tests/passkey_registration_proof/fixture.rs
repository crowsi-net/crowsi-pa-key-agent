use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_pa_key_agent::{
    confirm_passkey_registration, create_challenge, stage_passkey_registration,
};
use p256::ecdsa::SigningKey;
use tempfile::tempdir;

use crate::support::{owner_json, registration::registration_response};

pub const BINDING: &str = "sha256:6666666666666666666666666666666666666666666666666666666666666666";

pub struct Fixture {
    /// Keeps the owner-only temporary directory alive for every derived path.
    #[allow(dead_code)]
    pub root: tempfile::TempDir,
    pub initial: std::path::PathBuf,
    pub response: std::path::PathBuf,
    pub candidate: std::path::PathBuf,
    pub proof: std::path::PathBuf,
    pub assertion: std::path::PathBuf,
    pub credential: std::path::PathBuf,
    pub challenge: crowsi_pa_key_agent::PasskeyChallengeV1,
    pub signing: SigningKey,
}

pub fn stage(
    fixture: &Fixture,
) -> crowsi_pa_key_agent::Result<crowsi_pa_key_agent::PasskeyChallengeV1> {
    stage_passkey_registration(
        &fixture.initial,
        &fixture.response,
        &fixture.candidate,
        &fixture.proof,
        &fixture.credential,
        BINDING,
    )
}

pub fn confirm(
    fixture: &Fixture,
) -> crowsi_pa_key_agent::Result<crowsi_pa_key_agent::PasskeyCredentialV1> {
    confirm_passkey_registration(
        &fixture.proof,
        &fixture.assertion,
        &fixture.candidate,
        &fixture.credential,
        BINDING,
    )
}

pub fn ceremony(seed: u8) -> Fixture {
    let root = tempdir().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let initial = root.path().join("initial.json");
    let challenge = create_challenge(
        &initial,
        "register",
        "localhost",
        "http://localhost:4173",
        BINDING,
    )
    .expect("challenge");
    let signing = SigningKey::from_bytes((&[seed; 32]).into()).expect("key");
    let response = root.path().join("response.json");
    owner_json(&response, &registration_response(&challenge, &signing));
    Fixture {
        candidate: root.path().join("candidate.json"),
        proof: root.path().join("proof.json"),
        assertion: root.path().join("assertion.json"),
        credential: root.path().join("passkey.json"),
        root,
        initial,
        response,
        challenge,
        signing,
    }
}
