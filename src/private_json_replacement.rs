use std::{
    fs::{File, remove_file, rename},
    path::Path,
};

use serde::Serialize;

use crate::{PaKeyError, Result, private_json};

/// Replaces one validated owner file atomically without retaining retired state.
pub(crate) fn quarantine_and_replace<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    private_json::validate_file(path)?;
    let name = path
        .file_name()
        .and_then(|item| item.to_str())
        .ok_or(PaKeyError::UnsafePath)?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| PaKeyError::Entropy)?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", hex::encode(nonce)));
    if let Err(error) = private_json::write_new(&temporary, value).and_then(|()| {
        private_json::validate_file(path)?;
        rename(&temporary, path).map_err(|_| PaKeyError::State)
    }) {
        let _ = remove_file(&temporary);
        return Err(error);
    }
    // Rename is the commit point; a later directory fsync error must not report rollback.
    let _ = sync_parent(path);
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(PaKeyError::UnsafePath)?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| PaKeyError::State)
}
