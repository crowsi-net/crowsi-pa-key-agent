use std::path::Path;

use crowsi_credential_broker::{BrokerError, CredentialStore};

use crate::{
    PaKeyDestructionV1, PaKeyError, PaTrustDestructionV1, Result,
    initialization::reference,
    model::{DESTRUCTION_SCHEMA, TRUST_DESTRUCTION_SCHEMA},
    private_json, state_file,
};

/// Deletes only the PA key bound to the exact current public projection.
///
/// # Errors
///
/// Refuses missing, mismatched, denied, or inconsistent custody.
pub fn destroy<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    expected_public_key_hex: &str,
) -> Result<PaKeyDestructionV1> {
    let state = preflight(store, state_path, expected_public_key_hex)?;
    delete_key(store)?;
    state_file::destroy(state_path)?;
    Ok(PaKeyDestructionV1 {
        schema: DESTRUCTION_SCHEMA,
        state: "destroyed",
        key_id: state.key_id,
        destroyed_public_key_hex: state.public_key_hex,
        contains_secret_values: false,
    })
}

/// Revokes the relying-party Passkey registration before deleting its PA anchor.
///
/// # Errors
///
/// Refuses stale confirmation, unsafe files, denied custody, or inconsistent state.
pub fn destroy_trust_domain<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    credential_path: &Path,
    expected_public_key_hex: &str,
) -> Result<PaTrustDestructionV1> {
    preflight(store, state_path, expected_public_key_hex)?;
    let passkey = if private_json::remove_owner_if_present(credential_path)? {
        "revoked"
    } else {
        "absent"
    };
    let receipt = destroy(store, state_path, expected_public_key_hex)?;
    Ok(PaTrustDestructionV1 {
        schema: TRUST_DESTRUCTION_SCHEMA,
        state: "destroyed",
        pa_key: "destroyed",
        public_state: "destroyed",
        passkey_registration: passkey,
        destroyed_public_key_hex: receipt.destroyed_public_key_hex,
        contains_secret_values: false,
    })
}

pub(crate) fn preflight<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    expected_public_key_hex: &str,
) -> Result<crate::PaKeyStateV1> {
    let state = state_file::load(state_path)?.ok_or(PaKeyError::State)?;
    if state.public_key_hex != expected_public_key_hex {
        return Err(PaKeyError::Confirmation);
    }
    match store.metadata(&reference()?) {
        Ok(metadata) if metadata.revision().as_str() == state.credential_revision => Ok(state),
        Err(BrokerError::NotFound) => Ok(state),
        Err(error) => Err(map_custody(&error)),
        Ok(_) => Err(PaKeyError::State),
    }
}

pub(crate) fn delete_key<S: CredentialStore>(store: &S) -> Result<()> {
    match store.delete(&reference()?) {
        Ok(()) | Err(BrokerError::NotFound) => Ok(()),
        Err(error) => Err(map_custody(&error)),
    }
}

fn map_custody(error: &BrokerError) -> PaKeyError {
    match error {
        BrokerError::BackendDenied => PaKeyError::CustodyDenied,
        _ => PaKeyError::Custody,
    }
}
