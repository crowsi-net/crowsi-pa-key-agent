use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

use crate::{PaKeyError, Result, operation_once_file_meta::FileMetadata};

pub(crate) fn read_owner(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    read(
        path,
        nix::unistd::Uid::effective().as_raw(),
        Some(0o600),
        maximum,
    )
}

pub(crate) fn read_root(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    read(path, 0, None, maximum)
}

fn read(path: &Path, uid: u32, mode: Option<u32>, maximum: u64) -> Result<Vec<u8>> {
    let chain_owner = if uid == 0 {
        0
    } else {
        nix::unistd::Uid::effective().as_raw()
    };
    validate_chain(path, chain_owner)?;
    let before = fs::symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    let before_value = FileMetadata::new(&before);
    if !before_value.valid_file(&before, uid, mode, maximum) {
        return Err(PaKeyError::UnsafePath);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| PaKeyError::UnsafePath)?;
    let opened = file.metadata().map_err(|_| PaKeyError::UnsafePath)?;
    let opened_value = FileMetadata::new(&opened);
    if opened_value != before_value || !opened_value.valid_file(&opened, uid, mode, maximum) {
        return Err(PaKeyError::UnsafePath);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PaKeyError::Authorization)?;
    let after = file.metadata().map_err(|_| PaKeyError::UnsafePath)?;
    let path_after = fs::symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    if FileMetadata::new(&after) != before_value
        || FileMetadata::new(&path_after) != before_value
        || u64::try_from(bytes.len()).ok() != Some(before.len())
    {
        return Err(PaKeyError::UnsafePath);
    }
    Ok(bytes)
}

pub(crate) fn open_owner_directory(path: &Path) -> Result<(File, FileMetadata)> {
    validate_chain(path, nix::unistd::Uid::effective().as_raw())?;
    let metadata = fs::symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    let value = FileMetadata::new(&metadata);
    if !value.valid_directory(&metadata, nix::unistd::Uid::effective().as_raw())
        || !value.exact_mode(0o700)
    {
        return Err(PaKeyError::UnsafePath);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| PaKeyError::UnsafePath)?;
    let opened = FileMetadata::new(&directory.metadata().map_err(|_| PaKeyError::UnsafePath)?);
    if !value.same_directory_identity(opened) {
        return Err(PaKeyError::UnsafePath);
    }
    Ok((directory, value))
}

pub(crate) fn fd_child(directory: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), name))
}

fn validate_chain(path: &Path, owner: u32) -> Result<()> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(PaKeyError::UnsafePath);
    }
    let mut current = PathBuf::from("/");
    let root = fs::symlink_metadata(&current).map_err(|_| PaKeyError::UnsafePath)?;
    if !FileMetadata::new(&root).valid_directory(&root, owner) {
        return Err(PaKeyError::UnsafePath);
    }
    for component in path.parent().ok_or(PaKeyError::UnsafePath)?.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => return Err(PaKeyError::UnsafePath),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| PaKeyError::UnsafePath)?;
        if !FileMetadata::new(&metadata).valid_directory(&metadata, owner) {
            return Err(PaKeyError::UnsafePath);
        }
    }
    Ok(())
}

pub(crate) fn directory_unchanged(
    path: &Path,
    directory: &File,
    expected: FileMetadata,
) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| PaKeyError::UnsafePath)?;
    let fd_metadata = directory.metadata().map_err(|_| PaKeyError::UnsafePath)?;
    let path_value = FileMetadata::new(&path_metadata);
    let fd_value = FileMetadata::new(&fd_metadata);
    (path_value.same_directory_identity(fd_value)
        && expected.same_directory_identity(fd_value)
        && fd_value.valid_directory(&fd_metadata, nix::unistd::Uid::effective().as_raw())
        && fd_value.exact_mode(0o700))
    .then_some(())
    .ok_or(PaKeyError::UnsafePath)
}
