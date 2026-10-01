#![cfg(feature = "bootstrap-authorizer-internal")]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

use crate::passkey_registration_fixture as fixture;
use crate::support;

use fixture::{ceremony, confirm, stage};
use support::{assertion, owner_json};

#[test]
fn chromium_cred_protect_and_windows_zero_counter_can_register() {
    let fixture = ceremony(43);
    let mut response =
        support::registration::registration_response(&fixture.challenge, &fixture.signing);
    response["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode(
        support::attested::registration_auth_data_with_cred_protect(
            &fixture.challenge.rp_id,
            &fixture.signing
        )
    ));
    owner_json(&fixture.response, &response);

    let proof = stage(&fixture).expect("extension-bearing registration stage");
    owner_json(&fixture.assertion, &assertion(&proof, &fixture.signing, 0));
    let credential = confirm(&fixture).expect("Windows-style zero-counter proof");

    assert_eq!(credential.sign_count, 0);
    assert_eq!(credential.rp_id, "localhost");
    assert_eq!(credential.origin, "http://localhost:4173");
}

#[test]
fn first_windows_proof_accepts_initial_counter_equality_but_not_downgrade() {
    for (seed, proof_count, accepted) in [(55, 1, true), (56, 0, false)] {
        let fixture = ceremony(seed);
        let mut response =
            support::registration::registration_response(&fixture.challenge, &fixture.signing);
        let encoded = response["authenticator_data_b64url"]
            .as_str()
            .expect("registration authenticator data");
        let mut auth = URL_SAFE_NO_PAD.decode(encoded).expect("base64url");
        auth[33..37].copy_from_slice(&1_u32.to_be_bytes());
        response["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode(auth));
        owner_json(&fixture.response, &response);

        let proof = stage(&fixture).expect("registration stage");
        owner_json(
            &fixture.assertion,
            &assertion(&proof, &fixture.signing, proof_count),
        );
        assert_eq!(confirm(&fixture).is_ok(), accepted);
    }
}

#[test]
fn a_complete_empty_extension_map_is_valid() {
    let fixture = ceremony(49);
    let mut auth =
        support::attested::registration_auth_data(&fixture.challenge.rp_id, &fixture.signing);
    auth[32] |= 0x80;
    auth.push(0xa0);
    let mut response =
        support::registration::registration_response(&fixture.challenge, &fixture.signing);
    response["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode(auth));
    owner_json(&fixture.response, &response);

    let proof = stage(&fixture).expect("empty authenticator extension map");
    owner_json(&fixture.assertion, &assertion(&proof, &fixture.signing, 0));
    assert!(confirm(&fixture).is_ok());
}

#[test]
fn extension_flag_requires_one_complete_cbor_map() {
    let invalid = [
        (44, Vec::new()),
        (45, vec![0xa1, 0x61, b'x']),
        (46, vec![0xa2, 0x61, b'x', 0xf5, 0x61, b'x', 0xf4]),
        (47, vec![0xa1, 0x61, b'x', 0xf5, 0x00]),
    ];
    for (seed, extension) in invalid {
        let fixture = ceremony(seed);
        let mut auth =
            support::attested::registration_auth_data(&fixture.challenge.rp_id, &fixture.signing);
        auth[32] |= 0x80;
        auth.extend(extension);
        let mut response =
            support::registration::registration_response(&fixture.challenge, &fixture.signing);
        response["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode(auth));
        owner_json(&fixture.response, &response);
        assert!(stage(&fixture).is_err());
    }
}

#[test]
fn extension_bytes_without_extension_flag_are_rejected() {
    let fixture = ceremony(48);
    let mut auth =
        support::attested::registration_auth_data(&fixture.challenge.rp_id, &fixture.signing);
    auth.extend_from_slice(&[0xa1, 0x61, b'x', 0xf5]);
    let mut response =
        support::registration::registration_response(&fixture.challenge, &fixture.signing);
    response["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode(auth));
    owner_json(&fixture.response, &response);
    assert!(stage(&fixture).is_err());
}

#[test]
fn credential_key_requires_ctap2_canonical_cbor() {
    const KEY: usize = 37 + 18 + b"credential-1".len();
    for (seed, variant) in [(51, 0), (52, 1), (53, 2), (54, 3)] {
        let fixture = ceremony(seed);
        let mut auth =
            support::attested::registration_auth_data(&fixture.challenge.rp_id, &fixture.signing);
        match variant {
            0 => {
                auth.splice(KEY..KEY + 5, [0xa5, 0x03, 0x26, 0x01, 0x02]);
            }
            1 => {
                auth.splice(KEY..KEY + 3, [0xa5, 0x18, 0x01, 0x02]);
            }
            2 => {
                auth.splice(KEY + 8..KEY + 10, [0x59, 0x00, 0x20]);
            }
            _ => {
                auth[KEY] = 0xbf;
                auth.push(0xff);
            }
        }
        let mut response =
            support::registration::registration_response(&fixture.challenge, &fixture.signing);
        response["authenticator_data_b64url"] = json!(URL_SAFE_NO_PAD.encode(auth));
        owner_json(&fixture.response, &response);
        assert!(stage(&fixture).is_err());
    }
}
