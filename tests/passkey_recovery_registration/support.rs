use std::{fs, os::unix::fs::PermissionsExt};

use tempfile::tempdir;

pub(super) fn retired_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(root)
        .expect("directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("passkey.retired-"))
        })
        .collect()
}

pub(super) fn private_root() -> tempfile::TempDir {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}
