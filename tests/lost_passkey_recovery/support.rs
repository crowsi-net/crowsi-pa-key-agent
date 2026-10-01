use std::{fs, os::unix::fs::PermissionsExt};

use tempfile::tempdir;

pub(super) fn private_root() -> tempfile::TempDir {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    root
}

pub(super) fn owner_file(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner mode");
}
