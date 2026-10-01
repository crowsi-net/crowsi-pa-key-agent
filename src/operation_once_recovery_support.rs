use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_broker::MemoryStore;

use crate::operation_once_test_support::Fixture;

pub(crate) struct Setup {
    pub _root: tempfile::TempDir,
    pub fixture: Fixture,
    pub store: MemoryStore,
    pub state: Vec<u8>,
    pub request: Vec<u8>,
}

impl Setup {
    pub(crate) fn new() -> Self {
        let root = private_root(".pa-recovery-");
        let state_path = root.path().join("state.json");
        let ledger = root.path().join("replay");
        fs::create_dir(&ledger).expect("ledger");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).expect("ledger mode");
        let store = MemoryStore::default();
        crate::initialize(&store, &state_path, "test-custody").expect("state");
        let mut fixture = Fixture::new();
        fixture.config.0.replay_directory = ledger.to_string_lossy().into_owned();
        let request = serde_json::to_vec(&fixture.request).expect("request");
        Self {
            state: fs::read(state_path).expect("state wire"),
            _root: root,
            fixture,
            store,
            request,
        }
    }

    pub(crate) fn authorize_wire(&self, store: &MemoryStore, now: u64, state: &[u8]) -> Vec<u8> {
        crate::operation_once_runtime::authorize_wire_checked(
            store,
            &self.fixture.config,
            state,
            &self.request,
            now,
            |_| Ok(()),
        )
        .expect("authorization")
    }

    pub(crate) fn prepare(&self) {
        let request = crowsi_windows_operation_contracts::decode_operation_authorize_once_request(
            &self.request,
        )
        .expect("request");
        let state: crate::PaKeyStateV1 = serde_json::from_slice(&self.state).expect("state");
        let mapping = &self.fixture.config.0.credential_mappings[0];
        let pin = crate::operation_once_pin::PreparedPin::new(&state, mapping).expect("pin");
        let mut transaction = crate::operation_once_ledger::Transaction::open(
            std::path::Path::new(&self.fixture.config.0.replay_directory),
            &request,
            self.fixture.now,
        )
        .expect("transaction");
        transaction
            .prepare(
                self.fixture.now,
                request.target_device_proof.expires_at_epoch_s,
                pin,
            )
            .expect("prepared");
    }
}

pub(crate) fn private_root(prefix: &str) -> tempfile::TempDir {
    let base = std::env::current_dir().expect("cwd");
    let root = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(base)
        .expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    root
}
