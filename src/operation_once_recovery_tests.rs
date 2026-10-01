use crowsi_credential_broker::MemoryStore;

use crate::{PaKeyError, operation_once_recovery_support::Setup};

#[test]
fn stdout_loss_restart_and_expired_ttl_return_exact_canonical_bytes() {
    let setup = Setup::new();
    let first = setup.authorize_wire(&setup.store, setup.fixture.now, &setup.state);
    let recovered = crate::operation_once_runtime::authorize_wire_checked(
        &MemoryStore::default(),
        &setup.fixture.config,
        b"state-must-not-be-read",
        &setup.request,
        setup.fixture.now + 61,
        |_| panic!("custody must not be checked on exact recovery"),
    )
    .expect("restart recovery after live TTL");
    assert_eq!(recovered, first);
    let pretty_request = serde_json::to_vec_pretty(&setup.fixture.request).expect("pretty request");
    assert_eq!(
        crate::operation_once_runtime::recover_wire(
            &setup.fixture.config,
            &pretty_request,
            setup.fixture.now + 61
        )
        .expect("canonical request recovery")
        .expect("cached response"),
        first
    );
    let decoded = crowsi_windows_operation_contracts::decode_operation_request(&first)
        .expect("canonical response");
    assert_eq!(
        crate::operation_once_digest::response_wire(&decoded).expect("canonical"),
        first
    );
}

#[test]
fn same_proof_request_and_field_substitution_are_rejected() {
    let setup = Setup::new();
    setup.authorize_wire(&setup.store, setup.fixture.now, &setup.state);
    for (request_id, credential_id) in [
        ("substituted-request", "custody-device-key-b"),
        ("custody-request-1", "substituted-credential"),
    ] {
        let mut request = setup.fixture.request.clone();
        request.sign_intent.request_id = request_id.into();
        request.sign_intent.credential_id = credential_id.into();
        let wire = serde_json::to_vec(&request).expect("wire");
        assert!(matches!(
            crate::operation_once_runtime::recover_wire(
                &setup.fixture.config,
                &wire,
                setup.fixture.now
            ),
            Err(PaKeyError::Authorization)
        ));
    }
}
