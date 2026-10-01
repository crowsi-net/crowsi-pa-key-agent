use std::path::Path;

use crowsi_credential_broker::CredentialStore;
use serde::Serialize;

use crate::{PaKeyError, Result, private_json, status};

const CONFIRMATION: &str = "revoke-lost-passkey-registration";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LostPasskeyRecoveryReceiptV1 {
    pub schema: &'static str,
    pub state: &'static str,
    pub scope: &'static str,
    pub pa_key: &'static str,
    pub public_state: &'static str,
    pub passkey_registration: &'static str,
    pub authenticator_credential: &'static str,
    pub public_key_hex: String,
    pub contains_secret_values: bool,
}

/// Revokes only Coela's canonical server-side Passkey registration.
///
/// This is the recovery boundary for a lost authenticator. The current PA key
/// must still be available to the owner-local process and remains untouched.
/// The authenticator-side credential is outside this process and is unchanged.
///
/// # Errors
///
/// Rejects stale confirmation, unavailable custody, non-canonical paths, or a
/// registration file that is not an owner-only regular file.
pub fn revoke_lost_passkey_registration<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    credential_path: &Path,
    expected_public_key_hex: &str,
    confirmation: &str,
) -> Result<LostPasskeyRecoveryReceiptV1> {
    if confirmation != CONFIRMATION {
        return Err(PaKeyError::RecoveryConfirmation);
    }
    validate_canonical_paths(state_path, credential_path)?;
    let state = status(store, state_path)?;
    if state.public_key_hex != expected_public_key_hex {
        return Err(PaKeyError::RecoveryConfirmation);
    }
    let passkey_registration = if private_json::remove_owner_if_present(credential_path)? {
        "revoked"
    } else {
        "absent"
    };
    Ok(LostPasskeyRecoveryReceiptV1 {
        schema: "crowsi://policy-authority/lost-passkey-recovery-receipt/v1",
        state: "completed",
        scope: "server-passkey-registration",
        pa_key: "retained",
        public_state: "retained",
        passkey_registration,
        authenticator_credential: "unchanged",
        public_key_hex: state.public_key_hex,
        contains_secret_values: false,
    })
}

fn validate_canonical_paths(state: &Path, credential: &Path) -> Result<()> {
    let expected_names = state.file_name().and_then(|name| name.to_str())
        == Some("public-state.json")
        && credential.file_name().and_then(|name| name.to_str()) == Some("passkey.json");
    let shared_parent = state.parent().is_some() && state.parent() == credential.parent();
    (state.is_absolute() && credential.is_absolute() && expected_names && shared_parent)
        .then_some(())
        .ok_or(PaKeyError::UnsafePath)
}
