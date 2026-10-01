#![cfg(feature = "bootstrap-authorizer-internal")]

use std::fs;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_pa_key_agent::passkey_status;
use p256::ecdsa::SigningKey;
use serde_json::json;

use crate::passkey_registration_fixture as fixture;
use crate::support;
use fixture::{BINDING, ceremony, confirm, stage};
use support::registration::{registration_response, synthetic_registration_response};
use support::{assertion, owner_json, register};

const OLD: &str = "sha256:7777777777777777777777777777777777777777777777777777777777777777";

#[test]
fn thirty_seven_byte_synthetic_registration_is_rejected_before_staging() {
    let fixture = ceremony(31);
    owner_json(
        &fixture.response,
        &synthetic_registration_response(&fixture.challenge, &fixture.signing),
    );
    assert!(stage(&fixture).is_err());
    assert!(!fixture.candidate.exists());
    assert!(!fixture.proof.exists());
    assert!(!fixture.credential.exists());
}

#[test]
fn mismatched_candidate_key_proof_never_commits() {
    let fixture = ceremony(32);
    let proof = stage(&fixture).expect("stage");
    assert!(!fixture.credential.exists());
    let wrong = SigningKey::from_bytes((&[33_u8; 32]).into()).expect("wrong key");
    owner_json(&fixture.assertion, &assertion(&proof, &wrong, 1));
    assert!(confirm(&fixture).is_err());
    assert!(!fixture.credential.exists());
    assert!(fixture.candidate.exists());
    assert!(fixture.proof.exists());
}

#[test]
fn attested_id_and_cose_key_must_match_browser_fields() {
    let id_fixture = ceremony(36);
    let mut id_response = registration_response(&id_fixture.challenge, &id_fixture.signing);
    id_response["credential_id_b64url"] = json!("b3RoZXI");
    owner_json(&id_fixture.response, &id_response);
    assert!(stage(&id_fixture).is_err());

    let key_fixture = ceremony(37);
    let other = SigningKey::from_bytes((&[38_u8; 32]).into()).expect("other key");
    let other_response = registration_response(&key_fixture.challenge, &other);
    let mut key_response = registration_response(&key_fixture.challenge, &key_fixture.signing);
    key_response["public_key_spki_b64url"] = other_response["public_key_spki_b64url"].clone();
    owner_json(&key_fixture.response, &key_response);
    assert!(stage(&key_fixture).is_err());
}

#[test]
fn client_data_origin_must_include_the_challenged_port() {
    let fixture = ceremony(40);
    let response = registration_response(&fixture.challenge, &fixture.signing);
    owner_json(
        &fixture.response,
        &with_origin(response, "http://localhost"),
    );

    assert!(stage(&fixture).is_err());
    assert!(!fixture.candidate.exists());
    assert!(!fixture.credential.exists());
}

#[test]
fn proof_commits_once_and_consumed_evidence_cannot_replay() {
    let fixture = ceremony(34);
    let proof = stage(&fixture).expect("stage");
    owner_json(&fixture.assertion, &assertion(&proof, &fixture.signing, 1));
    confirm(&fixture).expect("confirm");
    let status = passkey_status(&fixture.credential, BINDING);
    assert_eq!(status.state, "ready");
    assert_eq!(status.rp_id.as_deref(), Some("localhost"));
    assert_eq!(status.origin.as_deref(), Some("http://localhost:4173"));
    assert!(!fixture.candidate.exists());
    assert!(!fixture.proof.exists());
    assert!(!fixture.assertion.exists());
    assert!(confirm(&fixture).is_err());
}

#[test]
fn possession_proof_origin_must_include_the_challenged_port() {
    let fixture = ceremony(41);
    let proof = stage(&fixture).expect("stage");
    let assertion = assertion(&proof, &fixture.signing, 1);
    owner_json(
        &fixture.assertion,
        &with_origin(assertion, "http://localhost"),
    );

    assert!(confirm(&fixture).is_err());
    assert!(!fixture.credential.exists());
}

#[test]
fn proof_is_bound_to_the_exact_staged_candidate() {
    let fixture = ceremony(39);
    let proof = stage(&fixture).expect("stage");
    let mut candidate: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.candidate).expect("candidate")).expect("JSON");
    candidate["credential"]["registered_at_epoch_s"] = json!(1);
    owner_json(&fixture.candidate, &candidate);
    owner_json(&fixture.assertion, &assertion(&proof, &fixture.signing, 1));
    assert!(confirm(&fixture).is_err());
    assert!(!fixture.credential.exists());
    assert!(fixture.candidate.exists());
    assert!(fixture.proof.exists());
}

#[test]
fn stale_valid_credential_can_only_use_rebind() {
    let fixture = ceremony(35);
    register(
        &fixture.credential,
        fixture.root.path(),
        &fixture.signing,
        OLD,
    );
    let before = fs::read(&fixture.credential).expect("credential");
    assert!(stage(&fixture).is_err());
    assert_eq!(fs::read(&fixture.credential).expect("after"), before);
    assert!(fixture.initial.exists());
    assert!(fixture.response.exists());
}

fn with_origin(mut evidence: serde_json::Value, origin: &str) -> serde_json::Value {
    let encoded = evidence["client_data_json_b64url"]
        .as_str()
        .expect("clientDataJSON");
    let mut client: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("base64url")).expect("JSON");
    client["origin"] = json!(origin);
    evidence["client_data_json_b64url"] =
        json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client).expect("JSON")));
    evidence
}
