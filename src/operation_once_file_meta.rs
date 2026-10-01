use std::{
    fs::Metadata,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct FileMetadata {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileMetadata {
    pub(crate) fn new(value: &Metadata) -> Self {
        Self {
            dev: value.dev(),
            ino: value.ino(),
            uid: value.uid(),
            gid: value.gid(),
            mode: value.permissions().mode(),
            nlink: value.nlink(),
            len: value.len(),
            mtime: value.mtime(),
            mtime_nsec: value.mtime_nsec(),
            ctime: value.ctime(),
            ctime_nsec: value.ctime_nsec(),
        }
    }

    pub(crate) fn valid_file(
        self,
        value: &Metadata,
        uid: u32,
        mode: Option<u32>,
        maximum: u64,
    ) -> bool {
        self.valid_file_with_minimum(value, uid, mode, maximum, 1)
    }

    pub(crate) fn valid_file_with_minimum(
        self,
        value: &Metadata,
        uid: u32,
        mode: Option<u32>,
        maximum: u64,
        minimum: u64,
    ) -> bool {
        value.is_file()
            && !value.file_type().is_symlink()
            && self.uid == uid
            && self.nlink == 1
            && self.len >= minimum
            && self.len <= maximum
            && mode.map_or(self.mode & 0o022 == 0, |expected| {
                self.mode & 0o777 == expected
            })
    }

    pub(crate) fn valid_directory(self, value: &Metadata, owner: u32) -> bool {
        value.is_dir()
            && !value.file_type().is_symlink()
            && (self.uid == 0 || self.uid == owner)
            && self.mode & 0o022 == 0
    }

    pub(crate) fn exact_mode(self, mode: u32) -> bool {
        self.mode & 0o777 == mode
    }

    pub(crate) fn same_directory_identity(self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.uid == other.uid
            && self.gid == other.gid
            && self.mode == other.mode
            && self.nlink == other.nlink
    }
}
