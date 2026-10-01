use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use crate::{PaKeyError, operation_once_test_support::Fixture};

pub(crate) struct BareLedger {
    pub root: tempfile::TempDir,
    pub ledger: PathBuf,
    pub fixture: Fixture,
}

impl BareLedger {
    pub(crate) fn new() -> Self {
        let root = super::operation_once_recovery_support::private_root(".pa-ledger-security-");
        let ledger = root.path().join("replay");
        fs::create_dir(&ledger).expect("ledger");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).expect("ledger mode");
        let mut fixture = Fixture::new();
        fixture.config.0.replay_directory = ledger.to_string_lossy().into_owned();
        Self {
            root,
            ledger,
            fixture,
        }
    }

    pub(crate) fn entry_name(byte: char) -> String {
        format!("operation-once-v2-{}.json", byte.to_string().repeat(64))
    }

    pub(crate) fn write(&self, name: &str, wire: &[u8]) -> PathBuf {
        let path = self.ledger.join(name);
        fs::write(&path, wire).expect("write poison");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("poison mode");
        path
    }

    pub(crate) fn assert_rejected(&self) {
        assert!(matches!(
            crate::operation_once_ledger::recover(
                &self.ledger,
                &self.fixture.request,
                self.fixture.now
            ),
            Err(PaKeyError::State)
        ));
    }

    pub(crate) fn fifo(&self, name: &str) {
        nix::unistd::mkfifo(
            &self.ledger.join(name),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("fifo");
    }

    pub(crate) fn symlink(&self, name: &str) {
        let target = self.root.path().join("symlink-target");
        if !target.exists() {
            fs::write(&target, b"{}").expect("target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
        }
        std::os::unix::fs::symlink(target, self.ledger.join(name)).expect("symlink");
    }

    pub(crate) fn hardlink(&self, name: &str) {
        let target = self.root.path().join("hardlink-target");
        fs::write(&target, b"{}").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
        fs::hard_link(target, self.ledger.join(name)).expect("hardlink");
    }
}
