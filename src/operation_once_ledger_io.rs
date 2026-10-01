use std::{
    fs::OpenOptions,
    io::Write,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};

use nix::fcntl::{RenameFlags, renameat, renameat2};

use crate::{PaKeyError, Result, operation_once_file_meta::FileMetadata};

pub(crate) fn replace(
    directory: &crate::operation_once_ledger_dir::LedgerDir,
    name: &str,
    wire: &[u8],
    exists: bool,
) -> Result<()> {
    write_temporary(directory, wire)?;
    rename_temporary(directory, name, exists)
}

pub(crate) fn write_temporary(
    directory: &crate::operation_once_ledger_dir::LedgerDir,
    wire: &[u8],
) -> Result<()> {
    if wire.is_empty()
        || u64::try_from(wire.len()).ok() > Some(crate::operation_once_record::MAX_RECORD_BYTES)
    {
        return Err(PaKeyError::State);
    }
    let path = directory.child(crate::operation_once_ledger_dir::TEMP_NAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(&path)
        .map_err(|_| PaKeyError::State)?;
    file.write_all(wire)
        .and_then(|()| file.sync_all())
        .map_err(|_| PaKeyError::State)?;
    let opened = file.metadata().map_err(|_| PaKeyError::State)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| PaKeyError::State)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    let value = FileMetadata::new(&opened);
    (value == FileMetadata::new(&named)
        && value.valid_file(
            &opened,
            uid,
            Some(0o600),
            crate::operation_once_record::MAX_RECORD_BYTES,
        )
        && opened.len() == wire.len() as u64)
        .then_some(())
        .ok_or(PaKeyError::State)
}

pub(crate) fn rename_temporary(
    directory: &crate::operation_once_ledger_dir::LedgerDir,
    name: &str,
    exists: bool,
) -> Result<()> {
    let fd = directory.file.as_raw_fd();
    let renamed = if exists {
        renameat(
            Some(fd),
            crate::operation_once_ledger_dir::TEMP_NAME,
            Some(fd),
            name,
        )
    } else {
        renameat2(
            Some(fd),
            crate::operation_once_ledger_dir::TEMP_NAME,
            Some(fd),
            name,
            RenameFlags::RENAME_NOREPLACE,
        )
    };
    renamed.map_err(|_| PaKeyError::State)?;
    directory.sync()
}
