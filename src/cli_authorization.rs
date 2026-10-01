use std::path::Path;

use crowsi_credential_broker::PlatformCustodyStore;
use crowsi_pa_key_agent::{
    CredentialAuthorizationFiles, PaKeyError, create_credential_challenge,
    issue_credential_authorization, status,
};
use serde_json::Value;

use crate::cli::{pa_binding, require_available};

pub fn challenge(
    store: &PlatformCustodyStore,
    files: CredentialAuthorizationFiles<'_>,
    challenge: &Path,
    origin: &str,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    let pa = status(store, files.state)?;
    encoded(create_credential_challenge(
        files,
        challenge,
        &pa_binding(&pa.public_key_hex),
        origin,
    )?)
}

pub fn authorize(
    store: &PlatformCustodyStore,
    files: CredentialAuthorizationFiles<'_>,
    challenge: &Path,
    assertion: &Path,
    output: &Path,
) -> Result<Value, PaKeyError> {
    require_available(store)?;
    encoded(issue_credential_authorization(
        store, files, challenge, assertion, output,
    )?)
}

fn encoded(value: impl serde::Serialize) -> Result<Value, PaKeyError> {
    serde_json::to_value(value).map_err(|_| PaKeyError::Encoding)
}
