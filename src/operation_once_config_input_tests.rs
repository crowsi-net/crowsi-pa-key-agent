use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::PaKeyError;

#[test]
fn pa_06_config_digest_is_exact_lowercase_and_verified_before_use() {
    let root = private_root();
    let file = root.path().join("config.json");
    let wire = b"{\"schema\":\"test\"}\n";
    write_owner(&file, wire);
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(wire)));
    assert_eq!(
        crate::operation_once_config_input::read(&file, &digest).expect("pinned config"),
        wire
    );
    let malformed = vec![
        String::new(),
        "11".repeat(32),
        format!("SHA256:{}", "11".repeat(32)),
        format!("sha256:{}", "AA".repeat(32)),
        format!("sha256:0x{}", "11".repeat(32)),
        format!("sha256:sha256:{}", "11".repeat(32)),
    ];
    for value in malformed {
        assert!(matches!(
            crate::operation_once_config_input::read(&file, &value),
            Err(PaKeyError::Usage)
        ));
    }
    assert!(matches!(
        crate::operation_once_config_input::read(&file, &format!("sha256:{}", "00".repeat(32))),
        Err(PaKeyError::Authorization)
    ));
}

#[test]
fn pa_06_config_rejects_symlink_hardlink_fifo_and_oversize() {
    let root = private_root();
    let digest = format!("sha256:{}", "00".repeat(32));
    let target = root.path().join("target.json");
    write_owner(&target, b"{}");
    let link = root.path().join("link.json");
    symlink(&target, &link).expect("symlink");
    rejects_config(&link, &digest);
    let hardlink = root.path().join("hardlink.json");
    fs::hard_link(&target, &hardlink).expect("hardlink");
    rejects_config(&target, &digest);
    let fifo = root.path().join("config.fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).expect("fifo");
    rejects_config(&fifo, &digest);
    let large = root.path().join("large.json");
    write_owner(&large, &vec![b'x'; 262_145]);
    rejects_config(&large, &digest);
}

#[test]
fn pa_06_config_rejects_swap_and_restore_path_fd_mismatch() {
    let root = private_root();
    let file = root.path().join("config.json");
    let saved = root.path().join("saved.json");
    let wire = b"{\"trusted\":true}\n";
    write_owner(&file, wire);
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(wire)));
    let before = || {
        fs::rename(&file, &saved).map_err(|_| PaKeyError::UnsafePath)?;
        write_owner(&file, b"{\"trusted\":false}");
        Ok(())
    };
    let after = || {
        fs::remove_file(&file).map_err(|_| PaKeyError::UnsafePath)?;
        fs::rename(&saved, &file).map_err(|_| PaKeyError::UnsafePath)
    };
    assert!(matches!(
        crate::operation_once_config_input::read_with_test_hooks(&file, &digest, before, after),
        Err(PaKeyError::UnsafePath)
    ));
    assert_eq!(fs::read(&file).expect("restored"), wire);
    assert!(!saved.exists(), "saved name must no longer exist");
}

#[test]
fn pa_06_config_rejects_symlinked_or_writable_parent() {
    let root = private_root();
    let real = root.path().join("real");
    fs::create_dir(&real).expect("real parent");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("mode");
    let file = real.join("config.json");
    write_owner(&file, b"{}");
    let linked = root.path().join("linked");
    symlink(&real, &linked).expect("parent symlink");
    rejects_config(
        &linked.join("config.json"),
        &format!("sha256:{}", "00".repeat(32)),
    );
    fs::set_permissions(&real, fs::Permissions::from_mode(0o770)).expect("mode");
    rejects_config(&file, &format!("sha256:{}", "00".repeat(32)));
}

fn private_root() -> tempfile::TempDir {
    let base = std::env::current_dir().expect("cwd");
    let root = tempfile::Builder::new()
        .prefix(".pa-config-")
        .tempdir_in(base)
        .expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}

fn write_owner(path: &Path, wire: &[u8]) {
    fs::write(path, wire).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn rejects_config(path: &Path, digest: &str) {
    assert!(matches!(
        crate::operation_once_config_input::read(path, digest),
        Err(PaKeyError::UnsafePath)
    ));
}
