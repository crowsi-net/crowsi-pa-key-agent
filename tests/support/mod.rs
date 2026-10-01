#![allow(dead_code)]

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_local_control_bridge::{BridgeAction, ControlRequestV1};
use crowsi_pa_key_agent::{CredentialAuthorizationFiles, PasskeyChallengeV1};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::json;
use sha2::{Digest, Sha256};

pub mod attested;
mod identity;
pub mod registration;
#[allow(unused_imports)]
pub use identity::{identity_evidence, share_identity_trust_key};
#[allow(unused_imports)]
pub use registration::register;

pub fn authorization_files<'a>(
    state: &'a Path,
    credential: &'a Path,
    request: &'a Path,
    identity_assertion: &'a Path,
    identity_status: &'a Path,
    identity_trust: &'a Path,
) -> CredentialAuthorizationFiles<'a> {
    CredentialAuthorizationFiles::new(
        state,
        credential,
        request,
        identity_assertion,
        identity_status,
        identity_trust,
    )
}

pub fn pa_binding(public_key: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(public_key.as_bytes()))
    )
}

pub fn local_challenge(path: &Path, operation: &str, binding: &str) -> PasskeyChallengeV1 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock");
    let value = PasskeyChallengeV1 {
        schema: "crowsi://policy-authority/passkey-challenge/v1".into(),
        ceremony_id: format!("ceremony-{}", "a".repeat(32)),
        operation: operation.into(),
        challenge_b64url: "c".repeat(43),
        rp_id: "localhost".into(),
        origin: "http://localhost:4173".into(),
        binding_sha256: binding.into(),
        context_sha256: None,
        expires_at_epoch_s: i64::try_from(now.as_secs()).expect("epoch") + 120,
    };
    owner_json(path, &value);
    value
}

pub fn assertion(
    challenge: &PasskeyChallengeV1,
    signing: &SigningKey,
    count: u32,
) -> serde_json::Value {
    assertion_with_flags(challenge, signing, count, 0x05)
}

pub fn assertion_with_flags(
    challenge: &PasskeyChallengeV1,
    signing: &SigningKey,
    count: u32,
    flags: u8,
) -> serde_json::Value {
    let client = URL_SAFE_NO_PAD
        .decode(client_data(challenge, "webauthn.get"))
        .expect("client");
    let auth = attested::assertion_auth_data(&challenge.rp_id, count, flags);
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    let signature: Signature = signing.sign(&signed);
    json!({
        "credential_id_b64url": "Y3JlZGVudGlhbC0x",
        "client_data_json_b64url": URL_SAFE_NO_PAD.encode(client),
        "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(auth),
        "signature_b64url": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    })
}

#[allow(dead_code)]
pub fn request() -> ControlRequestV1 {
    ControlRequestV1 {
        schema: "crowsi://local-control/request/v1".into(),
        request_id: "request-passkey-1".into(),
        action: BridgeAction::EnrollCredential,
        resource: format!("credential-{}", "a".repeat(64)),
        purpose: "credential-enrollment".into(),
        body_sha256: format!("sha256:{}", "b".repeat(64)),
    }
}

pub fn owner_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).expect("JSON")).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn client_data(challenge: &PasskeyChallengeV1, kind: &str) -> String {
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "type": kind, "challenge": challenge.challenge_b64url,
            "origin": challenge.origin, "crossOrigin": false
        }))
        .expect("client data"),
    )
}
