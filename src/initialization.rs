use std::path::Path;

use crowsi_credential_broker::{
    BrokerError, CredentialEntry, CredentialStore, SecretRef, SecretScope, SecretValue,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::{PaKeyError, PaKeyStateV1, Result, state_file};

const KEY_ID: &str = "pa-credential-authorization-1";

/// Creates the first PA signing key or verifies the already registered key.
///
/// # Errors
///
/// Fails when entropy, custody, owner-only state, or an existing binding is invalid.
pub fn initialize<S: CredentialStore>(
    store: &S,
    state_path: &Path,
    custody: &str,
) -> Result<PaKeyStateV1> {
    let reference = reference()?;
    match store.metadata(&reference) {
        Ok(metadata) => restore(
            store,
            state_path,
            custody,
            &reference,
            metadata.revision().as_str(),
        ),
        Err(BrokerError::NotFound) => create(store, state_path, custody, &reference),
        Err(error) => Err(map_custody(&error)),
    }
}

/// Reads public state only after matching it to the current custody revision.
///
/// # Errors
///
/// Fails when state is unsafe, absent, malformed, or no longer matches custody.
pub fn status<S: CredentialStore>(store: &S, state_path: &Path) -> Result<PaKeyStateV1> {
    let state = state_file::load(state_path)?.ok_or(PaKeyError::State)?;
    let metadata = store
        .metadata(&reference()?)
        .map_err(|error| map_custody(&error))?;
    (metadata.revision().as_str() == state.credential_revision)
        .then_some(state)
        .ok_or(PaKeyError::State)
}

fn create<S: CredentialStore>(
    store: &S,
    path: &Path,
    custody: &str,
    reference: &SecretRef,
) -> Result<PaKeyStateV1> {
    if state_file::load(path)?.is_some() {
        return Err(PaKeyError::State);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| PaKeyError::Entropy)?;
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let secret = SecretValue::new(seed.to_vec()).map_err(|_| PaKeyError::Custody)?;
    let entry = CredentialEntry::new(reference.clone(), ["localhost".into()], secret)
        .map_err(|_| PaKeyError::Custody)?;
    store.put(entry).map_err(|error| map_custody(&error))?;
    let revision = store
        .metadata(reference)
        .map_err(|error| map_custody(&error))?
        .revision()
        .as_str()
        .to_owned();
    let state = PaKeyStateV1::new(hex::encode(public), revision, custody);
    state_file::persist(path, &state)?;
    Ok(state)
}

fn restore<S: CredentialStore>(
    store: &S,
    path: &Path,
    custody: &str,
    reference: &SecretRef,
    revision: &str,
) -> Result<PaKeyStateV1> {
    let entry = store
        .get(reference, revision)
        .map_err(|error| map_custody(&error))?;
    let public = entry.into_secret().expose(|bytes| {
        let seed: [u8; 32] = bytes.try_into().map_err(|_| PaKeyError::State)?;
        Ok::<_, PaKeyError>(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    })?;
    let state = PaKeyStateV1::new(hex::encode(public), revision.into(), custody);
    state_file::persist(path, &state)?;
    status(store, path)
}

pub(crate) fn reference() -> Result<SecretRef> {
    let scope = SecretScope::new(
        "coela",
        "crowsi-policy-authority",
        "policy-authorization",
        "local-control-bridge",
    )
    .map_err(|_| PaKeyError::State)?;
    SecretRef::new(KEY_ID, scope).map_err(|_| PaKeyError::State)
}

fn map_custody(error: &BrokerError) -> PaKeyError {
    match error {
        BrokerError::BackendDenied => PaKeyError::CustodyDenied,
        _ => PaKeyError::Custody,
    }
}
