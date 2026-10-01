use std::{
    io::{Read, Write},
    path::Path,
};

use crowsi_credential_broker::{CustodyAvailabilityError, PlatformCustodyStore};

use crate::{PaKeyError, Result};

/// Runs the finite, purpose-specific operation authorization port.
///
/// # Errors
/// Rejects any argument, path, config, evidence, custody, replay, or output failure.
pub fn run(arguments: &[String], mut input: impl Read, mut output: impl Write) -> Result<()> {
    let (config_path, config_digest) = config_arguments(arguments)?;
    let config_wire = crate::operation_once_config_input::read(config_path, config_digest)?;
    let now = now()?;
    let root_wire = crate::operation_once_files::read_root(
        Path::new(crate::operation_once_config::ROOT_TRUST_PATH),
        16_384,
    )?;
    let config = crate::operation_once_config::verify(&config_wire, &root_wire, now)?;
    let mut request = Vec::new();
    input
        .by_ref()
        .take(65_537)
        .read_to_end(&mut request)
        .map_err(|_| PaKeyError::Authorization)?;
    if request.len() > 65_536 {
        return Err(PaKeyError::Authorization);
    }
    if let Some(encoded) = crate::operation_once_runtime::recover_wire(&config, &request, now)? {
        return write_response(&mut output, &encoded);
    }
    let state_wire =
        crate::operation_once_files::read_owner(Path::new(&config.0.pa_state_path), 65_536)?;
    let custody_wire =
        crate::operation_once_files::read_owner(Path::new(&config.0.custody_config_path), 65_536)?;
    let store = crate::custody::load_store_bytes(&custody_wire)?;
    let encoded = crate::operation_once_runtime::authorize_wire_checked(
        &store,
        &config,
        &state_wire,
        &request,
        now,
        available,
    )?;
    write_response(&mut output, &encoded)
}

fn write_response(output: &mut impl Write, encoded: &[u8]) -> Result<()> {
    output
        .write_all(encoded)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.flush())
        .map_err(|_| PaKeyError::Encoding)
}

pub(crate) fn config_arguments(arguments: &[String]) -> Result<(&Path, &str)> {
    if arguments.len() != 5
        || arguments[0] != "operation-authorize-once"
        || arguments[1] != "--config"
        || arguments[3] != "--config-sha256"
        || !Path::new(&arguments[2]).is_absolute()
    {
        return Err(PaKeyError::Usage);
    }
    Ok((Path::new(&arguments[2]), arguments[4].as_str()))
}

fn available(store: &PlatformCustodyStore) -> Result<()> {
    store.availability().map_err(|error| match error {
        CustodyAvailabilityError::Unavailable => PaKeyError::CustodyUnavailable,
        CustodyAvailabilityError::Denied => PaKeyError::CustodyDenied,
    })
}

fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| PaKeyError::Authorization)
}
