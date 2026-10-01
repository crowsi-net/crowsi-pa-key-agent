use std::path::Path;

use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
use sha2::{Digest, Sha256};

use crate::{
    PaKeyError, Result, private_json,
    webauthn_assertion::decode,
    webauthn_challenge::{valid_digest, valid_local_origin},
    webauthn_model::{PasskeyCredentialV1, PasskeyStatusV1},
};

#[must_use]
pub fn passkey_status(credential_path: &Path, expected_binding: &str) -> PasskeyStatusV1 {
    match private_json::owner_file_present(credential_path) {
        Ok(false) => projected_status("not-registered", "pa-passkey-not-registered", None),
        Err(_) => projected_status("invalid", "pa-passkey-registration-invalid", None),
        Ok(true) => match read_valid_passkey(credential_path) {
            Ok(value) if value.pa_public_key_sha256 == expected_binding => {
                projected_status("ready", "ready", Some(value))
            }
            Ok(value) => projected_status("stale", "pa-passkey-pa-binding-stale", Some(value)),
            Err(_) => projected_status("invalid", "pa-passkey-registration-invalid", None),
        },
    }
}

pub(crate) fn read_current_passkey(
    credential_path: &Path,
    expected_binding: &str,
) -> Result<PasskeyCredentialV1> {
    let value = read_valid_passkey(credential_path)?;
    if value.pa_public_key_sha256 != expected_binding {
        return Err(PaKeyError::UserVerification);
    }
    Ok(value)
}

pub(crate) fn read_valid_passkey(credential_path: &Path) -> Result<PasskeyCredentialV1> {
    let value: PasskeyCredentialV1 = private_json::read_owner(credential_path)?;
    validate_credential(&value)?;
    Ok(value)
}

pub(crate) fn read_stale_candidate(path: &Path) -> Result<PasskeyCredentialV1> {
    read_valid_passkey(path)
}

pub(crate) fn credential_digest(credential: &PasskeyCredentialV1) -> Result<String> {
    let encoded = serde_json::to_vec(credential).map_err(|_| PaKeyError::Encoding)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
}

fn validate_credential(value: &PasskeyCredentialV1) -> Result<()> {
    let credential_id = decode(&value.credential_id_b64url)?;
    let public = decode(&value.public_key_spki_b64url)?;
    let valid = value.schema == "crowsi://policy-authority/passkey-credential/v1"
        && !credential_id.is_empty()
        && valid_digest(&value.pa_public_key_sha256)
        && valid_local_origin(&value.rp_id, &value.origin)
        && value.registered_at_epoch_s > 0;
    if !valid {
        return Err(PaKeyError::UserVerification);
    }
    VerifyingKey::from_public_key_der(&public).map_err(|_| PaKeyError::UserVerification)?;
    Ok(())
}

fn projected_status(
    state: &'static str,
    reason_code: &'static str,
    credential: Option<PasskeyCredentialV1>,
) -> PasskeyStatusV1 {
    PasskeyStatusV1 {
        schema: "crowsi://policy-authority/passkey-status/v1",
        state,
        credential_id_b64url: credential
            .as_ref()
            .map(|value| value.credential_id_b64url.clone()),
        rp_id: credential.as_ref().map(|value| value.rp_id.clone()),
        origin: credential.as_ref().map(|value| value.origin.clone()),
        pa_public_key_sha256: credential.map(|value| value.pa_public_key_sha256),
        reason_code,
        contains_secret_values: false,
    }
}
