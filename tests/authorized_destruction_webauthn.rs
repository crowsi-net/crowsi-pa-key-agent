use std::fs;

use crowsi_pa_key_agent::PasskeyCredentialV1;

#[path = "authorized_destruction_webauthn/support.rs"]
mod fixture_support;
use crate::support::{assertion, assertion_with_flags, owner_json};
use fixture_support::fixture;

#[test]
fn user_presence_without_user_verification_is_rejected() {
    let fixture = fixture(61);
    let challenge = fixture.challenge();
    owner_json(
        &fixture.assertion,
        &assertion_with_flags(&challenge, &fixture.signing, 1, 0x01),
    );

    assert!(fixture.finish().is_err());
    fixture.assert_preserved();
}

#[test]
fn non_increasing_authenticator_counter_is_rejected() {
    let fixture = fixture(62);
    let mut credential: PasskeyCredentialV1 =
        serde_json::from_slice(&fs::read(&fixture.credential).expect("credential"))
            .expect("credential JSON");
    credential.sign_count = 5;
    owner_json(&fixture.credential, &credential);
    let challenge = fixture.challenge();
    owner_json(
        &fixture.assertion,
        &assertion(&challenge, &fixture.signing, 5),
    );

    assert!(fixture.finish().is_err());
    fixture.assert_preserved();
}

#[test]
fn counter_downgrade_to_zero_is_rejected_after_counter_support_is_observed() {
    let fixture = fixture(63);
    let mut credential: PasskeyCredentialV1 =
        serde_json::from_slice(&fs::read(&fixture.credential).expect("credential"))
            .expect("credential JSON");
    credential.sign_count = 5;
    owner_json(&fixture.credential, &credential);
    let challenge = fixture.challenge();
    owner_json(
        &fixture.assertion,
        &assertion(&challenge, &fixture.signing, 0),
    );
    assert!(fixture.finish().is_err());
    fixture.assert_preserved();
}

#[test]
fn backup_state_without_backup_eligibility_is_rejected() {
    let fixture = fixture(64);
    let challenge = fixture.challenge();
    owner_json(
        &fixture.assertion,
        &assertion_with_flags(&challenge, &fixture.signing, 1, 0x15),
    );
    assert!(fixture.finish().is_err());
    fixture.assert_preserved();
}
