use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use crate::{PaKeyError, operation_once_recovery_support::Setup};

#[test]
fn clock_forward_prune_then_restart_rollback_cannot_reuse_or_rebind_proof() {
    let setup = Setup::new();
    setup.authorize_wire(&setup.store, setup.fixture.now, &setup.state);
    let forward =
        crate::operation_once_runtime::recover_wire(&setup.fixture.config, &setup.request, 800)
            .expect("forward scan");
    assert!(forward.is_none(), "receipt is outside bounded retention");
    let watermark_path = std::path::Path::new(&setup.fixture.config.0.replay_directory)
        .join(crate::operation_once_ledger_dir::WATERMARK_NAME);
    let watermark_at_800 = fs::read(&watermark_path).expect("forward watermark");
    assert!(matches!(
        crate::operation_once_runtime::recover_wire(
            &setup.fixture.config,
            &setup.request,
            setup.fixture.now
        ),
        Err(PaKeyError::State)
    ));
    assert_eq!(
        fs::read(&watermark_path).expect("rollback watermark"),
        watermark_at_800
    );
    let mut rebound = setup.fixture.request.clone();
    rebound.sign_intent.request_id = "rollback-rebinding".into();
    let rebound = serde_json::to_vec(&rebound).expect("rebound");
    assert!(matches!(
        crate::operation_once_runtime::recover_wire(
            &setup.fixture.config,
            &rebound,
            setup.fixture.now
        ),
        Err(PaKeyError::State)
    ));
    assert_eq!(
        fs::read(watermark_path).expect("rebound watermark"),
        watermark_at_800
    );
}

#[test]
fn watermark_is_owner_only_bounded_and_excluded_from_receipt_quota() {
    let setup = Setup::new();
    setup.authorize_wire(&setup.store, setup.fixture.now, &setup.state);
    let path = std::path::Path::new(&setup.fixture.config.0.replay_directory)
        .join(crate::operation_once_ledger_dir::WATERMARK_NAME);
    let metadata = fs::symlink_metadata(&path).expect("watermark");
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), nix::unistd::Uid::effective().as_raw());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(metadata.len() <= 256);
    let source = include_str!("operation_once_ledger_scan.rs");
    assert!(source.contains("WATERMARK_NAME"));
    let watermark = include_str!("operation_once_ledger_watermark.rs");
    let update = watermark
        .find("operation_once_ledger_io::replace")
        .expect("update");
    let scan = source.find("record.retain_until_epoch_s").expect("prune");
    assert!(update > 0 && scan > 0);
}
