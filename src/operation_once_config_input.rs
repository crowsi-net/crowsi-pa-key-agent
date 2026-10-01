use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::{PaKeyError, Result, operation_once_file_meta::FileMetadata};

const MAXIMUM_CONFIG_BYTES: u64 = 262_144;

pub(crate) fn read(path: &Path, expected_digest: &str) -> Result<Vec<u8>> {
    read_with_hooks(path, expected_digest, || Ok(()), || Ok(()))
}

#[cfg(test)]
pub(crate) fn read_with_test_hooks(
    path: &Path,
    expected_digest: &str,
    before_open: impl FnOnce() -> Result<()>,
    after_open: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    read_with_hooks(path, expected_digest, before_open, after_open)
}

fn read_with_hooks(
    path: &Path,
    expected_digest: &str,
    before_open: impl FnOnce() -> Result<()>,
    after_open: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    let expected = parse_digest(expected_digest)?;
    let parent = path.parent().ok_or(PaKeyError::UnsafePath)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .ok_or(PaKeyError::UnsafePath)?;
    let (directory, directory_metadata) =
        crate::operation_once_files::open_owner_directory(parent)?;
    let fd_path = crate::operation_once_files::fd_child(&directory, name);
    let before = fs::symlink_metadata(&fd_path).map_err(|_| PaKeyError::UnsafePath)?;
    let before_value = FileMetadata::new(&before);
    if !before_value.valid_file(
        &before,
        nix::unistd::Uid::effective().as_raw(),
        Some(0o600),
        MAXIMUM_CONFIG_BYTES,
    ) {
        return Err(PaKeyError::UnsafePath);
    }
    before_open()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(&fd_path)
        .map_err(|_| PaKeyError::UnsafePath)?;
    after_open()?;
    verify_metadata(&file, &fd_path, path, before_value)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAXIMUM_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PaKeyError::UnsafePath)?;
    verify_metadata(&file, &fd_path, path, before_value)?;
    crate::operation_once_files::directory_unchanged(parent, &directory, directory_metadata)?;
    if u64::try_from(bytes.len()).ok() != Some(before.len()) {
        return Err(PaKeyError::UnsafePath);
    }
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    (actual == expected)
        .then_some(bytes)
        .ok_or(PaKeyError::Authorization)
}

fn parse_digest(value: &str) -> Result<[u8; 32]> {
    let encoded = value.strip_prefix("sha256:").ok_or(PaKeyError::Usage)?;
    if encoded.len() != 64
        || !encoded
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(PaKeyError::Usage);
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut digest).map_err(|_| PaKeyError::Usage)?;
    Ok(digest)
}

fn verify_metadata(
    file: &std::fs::File,
    fd_path: &Path,
    original_path: &Path,
    expected: FileMetadata,
) -> Result<()> {
    let opened = file.metadata().map_err(|_| PaKeyError::UnsafePath)?;
    let pinned = fs::symlink_metadata(fd_path).map_err(|_| PaKeyError::UnsafePath)?;
    let original = fs::symlink_metadata(original_path).map_err(|_| PaKeyError::UnsafePath)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    (FileMetadata::new(&opened) == expected
        && FileMetadata::new(&pinned) == expected
        && FileMetadata::new(&original) == expected
        && expected.valid_file(&opened, uid, Some(0o600), MAXIMUM_CONFIG_BYTES))
    .then_some(())
    .ok_or(PaKeyError::UnsafePath)
}
