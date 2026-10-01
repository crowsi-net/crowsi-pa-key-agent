use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
};

use nix::fcntl::{Flock, FlockArg};

use crate::{PaKeyError, Result, operation_once_file_meta::FileMetadata};

pub(crate) struct LockedLedger {
    pub(crate) directory: crate::operation_once_ledger_dir::LedgerDir,
    _lock: Flock<File>,
}

impl LockedLedger {
    pub(crate) fn acquire(path: &std::path::Path) -> Result<Self> {
        let directory = crate::operation_once_ledger_dir::LedgerDir::open(path)?;
        let lock_path = directory.child(crate::operation_once_ledger_dir::LOCK_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(&lock_path)
            .map_err(|_| PaKeyError::State)?;
        let lock = Flock::lock(file, FlockArg::LockExclusive).map_err(|_| PaKeyError::State)?;
        validate(&lock_path, &lock)?;
        directory.sync()?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
}

fn validate(path: &std::path::Path, file: &File) -> Result<()> {
    let opened = file.metadata().map_err(|_| PaKeyError::State)?;
    let named = fs::symlink_metadata(path).map_err(|_| PaKeyError::State)?;
    let opened_value = FileMetadata::new(&opened);
    let named_value = FileMetadata::new(&named);
    let uid = nix::unistd::Uid::effective().as_raw();
    (opened_value == named_value
        && opened_value.valid_file_with_minimum(&opened, uid, Some(0o600), 64, 0))
    .then_some(())
    .ok_or(PaKeyError::State)
}
