use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

use crate::{PaKeyError, Result, operation_once_file_meta::FileMetadata};

pub(crate) const LOCK_NAME: &str = "operation-once-v2.lock";
pub(crate) const TEMP_NAME: &str = ".operation-once-v2.pending";
pub(crate) const WATERMARK_NAME: &str = "operation-once-v2-watermark.json";
const MAX_NAMES: usize = 133;

pub(crate) struct LedgerDir {
    path: PathBuf,
    pub(crate) file: File,
    expected: FileMetadata,
}

impl LedgerDir {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let (file, expected) = crate::operation_once_files::open_owner_directory(path)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            expected,
        })
    }

    pub(crate) fn verify(&self) -> Result<()> {
        crate::operation_once_files::directory_unchanged(&self.path, &self.file, self.expected)
    }

    pub(crate) fn child(&self, name: &str) -> PathBuf {
        crate::operation_once_files::fd_child(&self.file, name)
    }

    pub(crate) fn names(&self) -> Result<Vec<String>> {
        self.verify()?;
        let mut names = Vec::new();
        for entry in fs::read_dir(self.child(".")).map_err(|_| PaKeyError::State)? {
            let name = entry
                .map_err(|_| PaKeyError::State)?
                .file_name()
                .into_string()
                .map_err(|_| PaKeyError::State)?;
            if name.len() > 255 || names.len() >= MAX_NAMES {
                return Err(PaKeyError::State);
            }
            names.push(name);
        }
        names.sort();
        self.verify()?;
        Ok(names)
    }

    pub(crate) fn read(&self, name: &str, maximum: u64, minimum: u64) -> Result<Vec<u8>> {
        let path = self.child(name);
        let before = fs::symlink_metadata(&path).map_err(|_| PaKeyError::State)?;
        let expected = FileMetadata::new(&before);
        let uid = nix::unistd::Uid::effective().as_raw();
        if !expected.valid_file_with_minimum(&before, uid, Some(0o600), maximum, minimum) {
            return Err(PaKeyError::State);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| PaKeyError::State)?;
        let opened = file.metadata().map_err(|_| PaKeyError::State)?;
        if FileMetadata::new(&opened) != expected {
            return Err(PaKeyError::State);
        }
        let mut wire = Vec::new();
        file.by_ref()
            .take(maximum.saturating_add(1))
            .read_to_end(&mut wire)
            .map_err(|_| PaKeyError::State)?;
        let after = file.metadata().map_err(|_| PaKeyError::State)?;
        let named = fs::symlink_metadata(&path).map_err(|_| PaKeyError::State)?;
        let exact = FileMetadata::new(&after) == expected
            && FileMetadata::new(&named) == expected
            && u64::try_from(wire.len()).ok() == Some(after.len());
        exact.then_some(wire).ok_or(PaKeyError::State)
    }

    pub(crate) fn remove(&self, name: &str) -> Result<()> {
        nix::unistd::unlinkat(
            Some(self.file.as_raw_fd()),
            name,
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|_| PaKeyError::State)?;
        self.sync()
    }

    pub(crate) fn sync(&self) -> Result<()> {
        self.file.sync_all().map_err(|_| PaKeyError::State)?;
        self.verify()
    }
}
