use std::fs;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_pa_key_agent::PaKeyError;
use serde_json::Value;

use crate::passkey_registration_fixture as fixture;
use crate::support::{assertion, owner_json};
use fixture::{ceremony, confirm, stage};

pub(super) fn verify_mutation(
    reason: &str,
    change: impl FnOnce(&fixture::Fixture, &crowsi_pa_key_agent::PasskeyChallengeV1),
) {
    let fixture = ceremony(90);
    let proof = stage(&fixture).expect("stage");
    owner_json(&fixture.assertion, &assertion(&proof, &fixture.signing, 1));
    change(&fixture, &proof);
    assert_reason(&confirm(&fixture), reason);
}

pub(super) fn assert_reason(
    result: &crowsi_pa_key_agent::Result<crowsi_pa_key_agent::PasskeyCredentialV1>,
    reason: &str,
) {
    let Err(PaKeyError::PasskeyRegistrationProof(actual)) = result else {
        panic!("expected registration proof diagnostic");
    };
    assert_eq!(
        actual.reason_code(),
        format!("pa-passkey-proof-{reason}-rejected")
    );
}

pub(super) fn mutate(path: &std::path::Path, change: impl FnOnce(&mut Value)) {
    let mut value = serde_json::from_slice(&fs::read(path).expect("read")).expect("JSON");
    change(&mut value);
    owner_json(path, &value);
}

pub(super) fn decode_field(value: &Value, name: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value[name].as_str().expect("field"))
        .expect("base64url")
}

pub(super) fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}
