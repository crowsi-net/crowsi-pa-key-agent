use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crowsi_credential_broker::{
    CredentialEntry, CredentialMetadata, CredentialStore, MemoryStore, SecretRef,
};

use crate::operation_once_test_support::Fixture;

#[derive(Default)]
struct CountedStore {
    inner: MemoryStore,
    metadata_calls: AtomicUsize,
    get_calls: AtomicUsize,
}

impl CredentialStore for CountedStore {
    fn put(&self, entry: CredentialEntry) -> crowsi_credential_broker::Result<()> {
        self.inner.put(entry)
    }

    fn metadata(
        &self,
        reference: &SecretRef,
    ) -> crowsi_credential_broker::Result<CredentialMetadata> {
        self.metadata_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.metadata(reference)
    }

    fn get(
        &self,
        reference: &SecretRef,
        revision: &str,
    ) -> crowsi_credential_broker::Result<CredentialEntry> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(reference, revision)
    }

    fn delete(&self, reference: &SecretRef) -> crowsi_credential_broker::Result<()> {
        self.inner.delete(reference)
    }
}

#[test]
fn concurrent_exact_calls_have_one_custody_winner_and_one_response() {
    let base = std::env::current_dir().expect("cwd");
    let root = tempfile::Builder::new()
        .prefix(".pa-concurrent-")
        .tempdir_in(base)
        .expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let ledger = root.path().join("replay");
    fs::create_dir(&ledger).expect("ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).expect("ledger mode");
    let state_path = root.path().join("state.json");
    let store = Arc::new(CountedStore::default());
    crate::initialize(&*store, &state_path, "test-custody").expect("state");
    store.metadata_calls.store(0, Ordering::SeqCst);
    store.get_calls.store(0, Ordering::SeqCst);
    let state = Arc::new(fs::read(state_path).expect("state wire"));
    let mut fixture = Fixture::new();
    fixture.config.0.replay_directory = ledger.to_string_lossy().into_owned();
    let config = Arc::new(fixture.config.clone());
    let request = Arc::new(serde_json::to_vec(&fixture.request).expect("request"));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let (store, state, config, request) = (
            Arc::clone(&store),
            Arc::clone(&state),
            Arc::clone(&config),
            Arc::clone(&request),
        );
        threads.push(std::thread::spawn(move || {
            crate::operation_once_runtime::authorize(&*store, &config, &state, &request, 120)
                .expect("exact concurrent authorization")
        }));
    }
    let outputs = threads
        .into_iter()
        .map(|thread| thread.join().expect("thread"))
        .collect::<Vec<_>>();
    assert!(outputs.iter().all(|output| output == &outputs[0]));
    assert_eq!(store.metadata_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.get_calls.load(Ordering::SeqCst), 1);
}
