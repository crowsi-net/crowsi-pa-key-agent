#![cfg(feature = "bootstrap-authorizer-internal")]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey;
use serde_json::json;

#[path = "passkey_registration_diagnostics/authenticity.rs"]
mod authenticity;
#[path = "passkey_registration_diagnostics/support.rs"]
mod diagnostic_support;
use crate::passkey_registration_fixture as fixture;
use crate::support;
use diagnostic_support::{assert_reason, decode_field, digest, mutate, verify_mutation};
use fixture::{ceremony, confirm, stage};
use support::registration::registration_response_with_count;
use support::{assertion, assertion_with_flags, owner_json};

#[test]
fn state_bindings_have_bounded_diagnostics() {
    verify_mutation("candidate", |fixture, _| {
        mutate(&fixture.candidate, |value| {
            value["schema"] = json!("invalid");
        });
    });
    verify_mutation("challenge", |fixture, _| {
        mutate(&fixture.proof, |value| {
            value["operation"] = json!("invalid");
        });
    });
    verify_mutation("context", |fixture, _| {
        mutate(&fixture.proof, |value| {
            value["context_sha256"] = json!(digest('1'));
        });
    });
    verify_mutation("rp-id", |fixture, _| {
        mutate(&fixture.proof, |value| value["rp_id"] = json!("invalid"));
    });
    verify_mutation("origin", |fixture, _| {
        mutate(&fixture.proof, |value| {
            value["origin"] = json!("http://localhost:1");
        });
    });
    verify_mutation("credential-id", |fixture, _| {
        mutate(&fixture.assertion, |value| {
            value["credential_id_b64url"] = json!("b3RoZXI");
        });
    });
}

#[test]
fn browser_evidence_has_bounded_diagnostics() {
    verify_mutation("client-data", |fixture, _| {
        mutate(&fixture.assertion, |value| {
            value["client_data_json_b64url"] = json!(URL_SAFE_NO_PAD.encode(b"not-json"));
        });
    });
    verify_mutation("user-verification", |fixture, proof| {
        owner_json(
            &fixture.assertion,
            &assertion_with_flags(proof, &fixture.signing, 1, 0x01),
        );
    });
    verify_mutation("signature", |fixture, proof| {
        let wrong = SigningKey::from_bytes((&[91_u8; 32]).into()).expect("key");
        owner_json(&fixture.assertion, &assertion(proof, &wrong, 1));
    });
}

#[test]
fn authenticator_rejections_identify_only_the_safe_failure_class() {
    verify_mutation("authenticator-encoding", |fixture, _| {
        mutate(&fixture.assertion, |value| {
            value["authenticator_data_b64url"] = json!("***");
        });
    });
    verify_mutation("authenticator-length", |fixture, _| {
        mutate(&fixture.assertion, |value| {
            value["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 36]));
        });
    });
    verify_mutation("user-presence", |fixture, proof| {
        owner_json(
            &fixture.assertion,
            &assertion_with_flags(proof, &fixture.signing, 1, 0x04),
        );
    });
    verify_mutation("user-verification", |fixture, proof| {
        owner_json(
            &fixture.assertion,
            &assertion_with_flags(proof, &fixture.signing, 1, 0x01),
        );
    });
    verify_mutation("backup-flags", |fixture, proof| {
        owner_json(
            &fixture.assertion,
            &assertion_with_flags(proof, &fixture.signing, 1, 0x15),
        );
    });
}

#[test]
fn authenticator_hash_and_counter_are_distinguished() {
    verify_mutation("rp-id", |fixture, _| {
        mutate(&fixture.assertion, |value| {
            let mut auth = decode_field(value, "authenticator_data_b64url");
            auth[0] ^= 0xff;
            value["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode(auth));
        });
    });

    let fixture = ceremony(92);
    owner_json(
        &fixture.response,
        &registration_response_with_count(&fixture.challenge, &fixture.signing, 2),
    );
    let proof = stage(&fixture).expect("stage");
    owner_json(&fixture.assertion, &assertion(&proof, &fixture.signing, 1));
    assert_reason(&confirm(&fixture), "counter");
}
