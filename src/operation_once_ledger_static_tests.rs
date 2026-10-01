#[test]
fn pa_06_file_source_ratchets_full_metadata_and_fd_relative_ledger() {
    let files = include_str!("operation_once_files.rs");
    let metadata = include_str!("operation_once_file_meta.rs");
    for required in [
        "symlink_metadata",
        "O_NOFOLLOW",
        "FileMetadata::new(&opened)",
        "FileMetadata::new(&after)",
        "FileMetadata::new(&path_after)",
        "nlink",
    ] {
        assert!(
            files.contains(required) || metadata.contains(required),
            "missing file ratchet: {required}"
        );
    }
    let ledger = concat!(
        include_str!("operation_once_ledger.rs"),
        include_str!("operation_once_ledger_dir.rs"),
        include_str!("operation_once_ledger_io.rs"),
        include_str!("operation_once_ledger_lock.rs")
    );
    assert!(ledger.contains("/proc/self/fd/") || files.contains("/proc/self/fd/"));
    for forbidden in ["println!", "eprintln!", "display()", "to_string_lossy"] {
        assert!(!files.contains(forbidden) && !ledger.contains(forbidden));
    }
}

#[test]
fn ledger_source_commits_time_before_prune_and_response_before_return() {
    let scan = include_str!("operation_once_ledger_scan.rs");
    let advance = scan.find("watermark::advance").expect("watermark");
    let prune = scan.find("retain_until_epoch_s").expect("prune");
    assert!(advance < prune);
    let runtime = include_str!("operation_once_runtime.rs");
    let complete = runtime.find("transaction.complete").expect("commit");
    let returned = runtime.rfind("Ok(response)").expect("return");
    assert!(complete < returned);
    let policy = concat!(include_str!("../README.md"), include_str!("../SECURITY.md"));
    for invariant in [
        "subprocess completion time",
        "durable monotonic wall-time watermark",
        "retained old custody revision",
    ] {
        assert!(policy.contains(invariant), "missing policy: {invariant}");
    }
}
