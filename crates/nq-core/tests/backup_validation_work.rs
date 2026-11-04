//! Backup must not multiply full-history work as it crosses crate boundaries.

use nq_core::engine::EngineError;
use nq_core::engine::{append_genesis, backup_store, validate_semantic_history};
use nq_store::{OpenValidation, SemanticCertification, Store, StoreError};
use std::cell::Cell;
use std::path::Path;

fn sqlite_work<T>(source: &Store, operation: impl FnOnce() -> T) -> (T, u64) {
    nq_store::start_sql_work_count();
    source.count_sql_work_on_this_handle();
    let result = operation();
    let work = nq_store::stop_sql_work_count().expect("SQLite work counting enabled");
    (result, work)
}

#[test]
fn backup_work_is_bounded_by_source_and_destination_verification() {
    let directory = tempfile::tempdir().expect("private fixture directory");
    let path = directory.path().join("source.db");
    let destination = directory.path().join("backup.db");
    let mut source = Store::initialize(&path).expect("initialize real SQLite store");
    append_genesis(&mut source, None).expect("record genuine store genesis");

    let (_, structural) = sqlite_work(&source, || source.validate().expect("full store laws"));
    let (_, semantic) = sqlite_work(&source, || {
        validate_semantic_history(&source).expect("full typed history")
    });
    assert!(
        structural > 0 && semantic > 0,
        "controls must measure SQL work"
    );
    let (_, backup) = sqlite_work(&source, || {
        backup_store(&source, &destination).expect("actual core backup")
    });

    // One complete structural and typed audit for each of source and copy,
    // plus a generous fixed allowance for copy admission and RO bootstrap.
    // The controls exercise validation independently of the backup path.
    // A third structural pass through a discarded/reopened copy exceeds it.
    let budget = 2 * (structural + semantic) + 8_000;
    assert!(
        backup <= budget,
        "backup repeated full validation: work={backup}, budget={budget}, \
         full_structural={structural}, full_semantic={semantic}"
    );
    assert!(destination.is_file());
    let restored = Store::open_read_only(&destination).expect("independently reopen backup");
    restored
        .validate()
        .expect("independent complete structural audit");
    validate_semantic_history(&restored).expect("independent complete typed audit");
}

fn store_with_watermark(root: &Path) -> Store {
    let path = root.join("source.db");
    let mut source = Store::initialize(&path).expect("initialize source");
    append_genesis(&mut source, None).expect("source genesis");
    drop(source);
    let source = Store::open(&path).expect("validated source open");
    source
        .record_validation_watermark(SemanticCertification::NotEstablished, "backup-test-rules")
        .expect("record structural watermark")
        .expect("writable source with one genesis records its watermark");
    source
}

#[test]
fn backup_callback_receives_full_read_only_validation_despite_applicable_watermark() {
    let source_root = tempfile::tempdir().unwrap();
    let copy_root = tempfile::tempdir().unwrap();
    let source = store_with_watermark(source_root.path());
    let destination = copy_root.path().join("copy.db");
    std::fs::copy(
        nq_store::watermark_path(source.path().unwrap()),
        nq_store::watermark_path(&destination),
    )
    .expect("place the applicable source watermark beside the future copy");
    let (artifact, ()) = source
        .backup_verified_with(&destination, |copy| {
            assert!(matches!(copy.open_validation(), OpenValidation::Full(_)));
            assert!(!copy.admits_writes());
            assert!(copy.applied_watermark().is_none());
            Ok::<(), StoreError>(())
        })
        .expect("fully verified copy");
    assert_eq!(artifact.path, destination);
    // The fixture really contains an applicable watermark: an ordinary RO
    // open would apply it, while the backup callback above did not.
    let ordinary = Store::open_read_only(&destination).expect("ordinary copy open");
    assert!(matches!(
        ordinary.open_validation(),
        OpenValidation::SinceWatermark(_)
    ));
}

#[test]
fn backup_callback_error_keeps_its_type_and_removes_only_the_owned_copy() {
    let source_root = tempfile::tempdir().unwrap();
    let copy_root = tempfile::tempdir().unwrap();
    let source = store_with_watermark(source_root.path());
    let destination = copy_root.path().join("copy.db");
    let error = source
        .backup_verified_with(&destination, |_| {
            Err::<(), EngineError>(EngineError::DiagnosticUnsupported(
                "verifier-declined".into(),
            ))
        })
        .expect_err("additional verifier refuses the copied data");
    assert!(
        matches!(error, EngineError::DiagnosticUnsupported(message) if message == "verifier-declined")
    );
    assert_eq!(std::fs::read_dir(copy_root.path()).unwrap().count(), 0);
    source.validate().expect("source remains valid");
    source
        .backup_verified(&destination)
        .expect("next ordinary backup succeeds");
}

#[test]
fn backup_additional_verification_does_not_hold_the_source_operation_guard() {
    let source_root = tempfile::tempdir().unwrap();
    let copy_root = tempfile::tempdir().unwrap();
    let source = store_with_watermark(source_root.path());
    let destination = copy_root.path().join("copy.db");
    let source_path = source.path().unwrap();
    source
        .backup_verified_with(&destination, |_| {
            // This is a real independent writable connection and checkpoint
            // admission. A retained source guard would refuse it.
            let writer = Store::open(source_path).expect("source writer can open during callback");
            writer
                .checkpoint_wal()
                .expect("source write admission during callback");
            Ok::<(), StoreError>(())
        })
        .expect("verification does not prolong the source lease");
}

#[test]
fn backup_full_validation_still_refuses_a_foreign_destination_watermark() {
    let source_root = tempfile::tempdir().unwrap();
    let foreign_root = tempfile::tempdir().unwrap();
    let copy_root = tempfile::tempdir().unwrap();
    let source = store_with_watermark(source_root.path());
    let foreign = store_with_watermark(foreign_root.path());
    let destination = copy_root.path().join("copy.db");
    let sidecar = nq_store::watermark_path(&destination);
    std::fs::copy(nq_store::watermark_path(foreign.path().unwrap()), &sidecar).unwrap();
    let original_sidecar = std::fs::read(&sidecar).unwrap();
    let called = Cell::new(false);
    let error = source
        .backup_verified_with(&destination, |_| {
            called.set(true);
            Ok::<(), StoreError>(())
        })
        .expect_err("forcing full validation must preserve foreign-store refusal");
    assert!(
        matches!(error, StoreError::Integrity(message) if message.contains("does not belong to this database"))
    );
    assert!(!called.get());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(sidecar).unwrap(), original_sidecar);
}
