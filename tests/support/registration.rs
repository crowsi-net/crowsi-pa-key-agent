use std::path::Path;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_pa_key_agent::PasskeyChallengeV1;
#[cfg(not(feature = "bootstrap-authorizer-internal"))]
use crowsi_pa_key_agent::PasskeyCredentialV1;
#[cfg(feature = "bootstrap-authorizer-internal")]
use crowsi_pa_key_agent::{
    confirm_passkey_registration, create_challenge, stage_passkey_registration,
};
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use serde_json::json;

#[cfg(feature = "bootstrap-authorizer-internal")]
use super::assertion;
use super::{attested, client_data, owner_json};

pub fn register(credential: &Path, root: &Path, signing: &SigningKey, binding: &str) {
    register_implementation(credential, root, signing, binding);
}

#[cfg(feature = "bootstrap-authorizer-internal")]
fn register_implementation(credential: &Path, root: &Path, signing: &SigningKey, binding: &str) {
    let initial = root.join("register-challenge.json");
    let challenge = create_challenge(
        &initial,
        "register",
        "localhost",
        "http://localhost:4173",
        binding,
    )
    .expect("challenge");
    let response = root.join("register-response.json");
    owner_json(&response, &registration_response(&challenge, signing));
    let candidate = root.join("register-candidate.json");
    let proof_path = root.join("register-proof.json");
    let proof = stage_passkey_registration(
        &initial,
        &response,
        &candidate,
        &proof_path,
        credential,
        binding,
    )
    .expect("stage");
    let proof_assertion = root.join("register-proof-assertion.json");
    owner_json(&proof_assertion, &assertion(&proof, signing, 0));
    confirm_passkey_registration(
        &proof_path,
        &proof_assertion,
        &candidate,
        credential,
        binding,
    )
    .expect("register");
}

#[cfg(not(feature = "bootstrap-authorizer-internal"))]
fn register_implementation(credential: &Path, _root: &Path, signing: &SigningKey, binding: &str) {
    let public_key = signing.verifying_key().to_public_key_der().expect("SPKI");
    owner_json(
        credential,
        &PasskeyCredentialV1 {
            schema: "crowsi://policy-authority/passkey-credential/v1".into(),
            credential_id_b64url: "Y3JlZGVudGlhbC0x".into(),
            public_key_spki_b64url: URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
            rp_id: "localhost".into(),
            origin: "http://localhost:4173".into(),
            pa_public_key_sha256: binding.into(),
            sign_count: 0,
            registered_at_epoch_s: 1,
        },
    );
}

pub fn registration_response(
    challenge: &PasskeyChallengeV1,
    signing: &SigningKey,
) -> serde_json::Value {
    registration_response_with_count(challenge, signing, 0)
}

pub fn registration_response_with_count(
    challenge: &PasskeyChallengeV1,
    signing: &SigningKey,
    count: u32,
) -> serde_json::Value {
    json!({
        "credential_id_b64url": "Y3JlZGVudGlhbC0x",
        "client_data_json_b64url": client_data(challenge, "webauthn.create"),
        "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(
            attested::registration_auth_data_with_count(&challenge.rp_id, signing, count)),
        "public_key_spki_b64url": URL_SAFE_NO_PAD.encode(
            signing.verifying_key().to_public_key_der().expect("SPKI").as_bytes())
    })
}

pub fn synthetic_registration_response(
    challenge: &PasskeyChallengeV1,
    signing: &SigningKey,
) -> serde_json::Value {
    json!({
        "credential_id_b64url": "Y3JlZGVudGlhbC0x",
        "client_data_json_b64url": client_data(challenge, "webauthn.create"),
        "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(
            attested::assertion_auth_data(&challenge.rp_id, 0, 0x05)),
        "public_key_spki_b64url": URL_SAFE_NO_PAD.encode(
            signing.verifying_key().to_public_key_der().expect("SPKI").as_bytes())
    })
}
