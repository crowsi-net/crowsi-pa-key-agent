use std::{
    fs::{OpenOptions, hard_link, read, remove_file, symlink_metadata},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::{PaKeyError, PaKeyStateV1, Result};

pub(crate) fn load(path: &Path) -> Result<Option<PaKeyStateV1>> {
    if !path.exists() {
        return Ok(None);
    }
    validate_file(path)?;
    let bytes = read(path).map_err(|_| PaKeyError::State)?;
    if bytes.len() > 16_384 {
        return Err(PaKeyError::State);
    }
    let state: PaKeyStateV1 = serde_json::from_slice(&bytes).map_err(|_| PaKeyError::State)?;
    state
        .valid()
        .then_some(state)
        .ok_or(PaKeyError::State)
        .map(Some)
}

pub(crate) fn persist(path: &Path, state: &PaKeyStateV1) -> Result<()> {
    validate_parent(path)?;
    if let Some(current) = load(path)? {
        return (current.public_key_hex == state.public_key_hex
            && current.credential_revision == state.credential_revision)
            .then_some(())
            .ok_or(PaKeyError::State);
    }
    let temporary = temporary_path(path)?;
    let result = write_new(&temporary, state).and_then(|()| {
        hard_link(&temporary, path).map_err(|_| PaKeyError::State)?;
        validate_file(path)
    });
    let _ = remove_file(temporary);
    result
}

pub(crate) fn destroy(path: &Path) -> Result<()> {
    validate_file(path)?;
    remove_file(path).map_err(|_| PaKeyError::State)?;
    let parent = path.parent().ok_or(PaKeyError::UnsafePath)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PaKeyError::State)
}

fn write_new(path: &Path, state: &PaKeyStateV1) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(state).map_err(|_| PaKeyError::Encoding)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| PaKeyError::State)?;
    file.write_all(&encoded)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| PaKeyError::State)
}

fn validate_parent(path: &Path) -> Result<()> {
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

fn validate_file(path: &Path) -> Result<()> {
    validate_parent(path)?;
    let metadata = symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    let valid = metadata.is_file()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o600;
    valid.then_some(()).ok_or(PaKeyError::UnsafePath)
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PaKeyError::UnsafePath)?;
    Ok(path.with_file_name(format!(".{name}.{}.tmp", std::process::id())))
}
