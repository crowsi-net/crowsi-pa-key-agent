use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use ihat_identity_assertion_contracts::CurrentDeviceStatusV1;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{PaKeyError, Result, private_json};

const DIRECTORY: &str = ".identity-status-nonces-v1";

#[derive(Serialize)]
struct ConsumedNonce<'a> {
    schema: &'static str,
    nonce_digest: &'a str,
    issued_at_epoch_s: u64,
    expires_at_epoch_s: u64,
    contains_secret_values: bool,
}

pub(crate) fn consume(state_path: &Path, status: &CurrentDeviceStatusV1) -> Result<()> {
    private_json::validate_file(state_path)?;
    let directory = ledger_directory(state_path)?;
    ensure_directory(&directory)?;
    let digest = nonce_digest(status);
    let path = directory.join(&digest);
    let value = ConsumedNonce {
        schema: "crowsi://policy-authority/consumed-identity-status/v1",
        nonce_digest: &digest,
        issued_at_epoch_s: status.issued_at_epoch_s,
        expires_at_epoch_s: status.expires_at_epoch_s,
        contains_secret_values: false,
    };
    let encoded = serde_json::to_vec(&value).map_err(|_| PaKeyError::Encoding)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => PaKeyError::Authorization,
            _ => PaKeyError::State,
        })?;
    file.write_all(&encoded)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .and_then(|()| File::open(&directory)?.sync_all())
        .map_err(|_| PaKeyError::State)
}

fn nonce_digest(status: &CurrentDeviceStatusV1) -> String {
    let mut value = b"CROWSI-PA-IDENTITY-STATUS-NONCE-V1\n".to_vec();
    record(&mut value, status.issuer.as_bytes());
    record(&mut value, status.nonce.as_bytes());
    hex::encode(Sha256::digest(value))
}

fn record(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(value);
}

fn ledger_directory(state_path: &Path) -> Result<PathBuf> {
    Ok(state_path
        .parent()
        .ok_or(PaKeyError::UnsafePath)?
        .join(DIRECTORY))
}

fn ensure_directory(path: &Path) -> Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PaKeyError::State)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(PaKeyError::State),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    let valid = metadata.is_dir()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o700
        && path.canonicalize().ok().as_deref() == Some(path);
    valid.then_some(()).ok_or(PaKeyError::UnsafePath)
}
