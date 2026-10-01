use std::path::Path;

use crowsi_credential_broker::PlatformCustodyStore;
use crowsi_pa_key_agent::{
    PaKeyError, authenticate_passkey, create_passkey_authentication_challenge,
    create_passkey_rebind_challenge, passkey_status as project_passkey, rebind_passkey,
    revoke_lost_passkey_registration, status,
};
use serde_json::Value;

use crate::cli::{pa_binding, require_available};

pub fn passkey_status(
    store: &PlatformCustodyStore,
    state: &Path,
    credential: &Path,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    let pa = status(store, state)?;
    encoded(project_passkey(credential, &pa_binding(&pa.public_key_hex)))
}

pub fn recover_lost_passkey(
    store: &PlatformCustodyStore,
    state: &Path,
    credential: &Path,
    expected_public_key: &str,
    confirmation: &str,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    encoded(revoke_lost_passkey_registration(
        store,
        state,
        credential,
        expected_public_key,
        confirmation,
    )?)
}

pub fn rebind_challenge(
    store: &PlatformCustodyStore,
    state: &Path,
    credential: &Path,
    challenge: &Path,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    let pa = status(store, state)?;
    encoded(create_passkey_rebind_challenge(
        credential,
        challenge,
        &pa_binding(&pa.public_key_hex),
    )?)
}

pub fn rebind(
    store: &PlatformCustodyStore,
    state: &Path,
    credential: &Path,
    challenge: &Path,
    assertion: &Path,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    let pa = status(store, state)?;
    encoded(rebind_passkey(
        challenge,
        assertion,
        credential,
        &pa_binding(&pa.public_key_hex),
    )?)
}

pub fn authentication_challenge(
    store: &PlatformCustodyStore,
    state: &Path,
    credential: &Path,
    challenge: &Path,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    let pa = status(store, state)?;
    encoded(create_passkey_authentication_challenge(
        credential,
        challenge,
        &pa_binding(&pa.public_key_hex),
    )?)
}

pub fn authenticate(
    store: &PlatformCustodyStore,
    state: &Path,
    credential: &Path,
    challenge: &Path,
    assertion: &Path,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    let pa = status(store, state)?;
    encoded(authenticate_passkey(
        challenge,
        assertion,
        credential,
        &pa_binding(&pa.public_key_hex),
    )?)
}

fn encoded(value: impl serde::Serialize) -> Result<Value, PaKeyError> {
    serde_json::to_value(value).map_err(|_| PaKeyError::Encoding)
}
