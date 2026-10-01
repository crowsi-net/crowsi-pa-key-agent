use std::{
    fs::{OpenOptions, read, remove_file, rename, symlink_metadata},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use serde::{Serialize, de::DeserializeOwned};

use crate::{PaKeyError, Result};

const MAX_BYTES: u64 = 65_536;

pub(crate) fn read_owner<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_owner_bytes(path)?).map_err(|_| PaKeyError::Encoding)
}

pub(crate) fn read_owner_bytes(path: &Path) -> Result<Vec<u8>> {
    validate_file(path)?;
    let metadata = symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    if metadata.len() > MAX_BYTES {
        return Err(PaKeyError::State);
    }
    read(path).map_err(|_| PaKeyError::State)
}

pub(crate) fn write_new<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    validate_parent(path)?;
    let encoded = serde_json::to_vec_pretty(value).map_err(|_| PaKeyError::Encoding)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| PaKeyError::State)?;
    file.write_all(&encoded)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| PaKeyError::State)
}

pub(crate) fn ensure_owner<T>(path: &Path, expected: &T) -> Result<()>
where
    T: DeserializeOwned + PartialEq,
{
    (&read_owner::<T>(path)? == expected)
        .then_some(())
        .ok_or(PaKeyError::State)
}

pub(crate) fn ensure_owner_bytes(path: &Path, expected: &[u8]) -> Result<()> {
    (read_owner_bytes(path)? == expected)
        .then_some(())
        .ok_or(PaKeyError::State)
}

pub(crate) fn remove_owner(path: &Path) -> Result<()> {
    remove_owner_if_present(path)?
        .then_some(())
        .ok_or(PaKeyError::State)
}

pub(crate) fn remove_owner_if_present(path: &Path) -> Result<bool> {
    match symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(PaKeyError::State),
        Ok(_) => {}
    }
    validate_file(path)?;
    remove_file(path).map_err(|_| PaKeyError::State)?;
    Ok(true)
}

pub(crate) fn owner_file_present(path: &Path) -> Result<bool> {
    match symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PaKeyError::State),
        Ok(_) => {
            validate_file(path)?;
            Ok(true)
        }
    }
}

pub(crate) fn replace<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    validate_file(path)?;
    let name = path
        .file_name()
        .and_then(|item| item.to_str())
        .ok_or(PaKeyError::UnsafePath)?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    write_new(&temporary, value)?;
    rename(&temporary, path).map_err(|_| PaKeyError::State)
}

pub(crate) fn validate_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(PaKeyError::UnsafePath);
    }
    let parent = path.parent().ok_or(PaKeyError::UnsafePath)?;
    let metadata = symlink_metadata(parent).map_err(|_| PaKeyError::UnsafePath)?;
    let owner = nix::unistd::Uid::effective().as_raw();
    let valid = parent.canonicalize().ok().as_deref() == Some(parent)
        && metadata.is_dir()
        && metadata.uid() == owner
        && metadata.permissions().mode() & 0o777 == 0o700;
    valid.then_some(()).ok_or(PaKeyError::UnsafePath)
}

pub(crate) fn validate_file(path: &Path) -> Result<()> {
    validate_parent(path)?;
    let metadata = symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    let owner = nix::unistd::Uid::effective().as_raw();
    let valid = metadata.is_file()
        && metadata.uid() == owner
        && metadata.permissions().mode() & 0o777 == 0o600;
    valid.then_some(()).ok_or(PaKeyError::UnsafePath)
}
