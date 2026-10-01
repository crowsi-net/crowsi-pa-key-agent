use std::path::Path;

use crowsi_credential_broker::{BrokerError, PlatformCustodyConfigV1, PlatformCustodyStore};

use crate::{PaKeyError, private_json};

/// Loads the exact owner-only platform custody runtime selected by the caller.
///
/// # Errors
///
/// Rejects unsafe files, invalid runtime contracts, unavailable providers, and denied custody.
pub fn load_store(path: &Path) -> Result<PlatformCustodyStore, PaKeyError> {
    let bytes = private_json::read_owner_bytes(path)?;
    load_store_bytes(bytes.as_slice())
}

pub(crate) fn load_store_bytes(bytes: &[u8]) -> Result<PlatformCustodyStore, PaKeyError> {
    let config = PlatformCustodyConfigV1::parse(bytes).map_err(|_| PaKeyError::CustodyDenied)?;
    PlatformCustodyStore::new(&config).map_err(|error| match error {
        BrokerError::AccessDenied | BrokerError::BackendDenied => PaKeyError::CustodyDenied,
        BrokerError::BackendUnavailable => PaKeyError::CustodyUnavailable,
        _ => PaKeyError::Custody,
    })
}
