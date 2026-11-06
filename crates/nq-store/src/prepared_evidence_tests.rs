// Real Store transactions and existing public-data fixtures. These establish
// source custody and fallback laws; Core separately checks typed evaluations.

fn resolve_freshness(
    store: &mut Store,
    prepared: PreparedEvidenceSnapshot,
) -> Result<EvidenceSnapshot, StoreError> {
    store.commit_evaluations_prepared_validated(
        prepared,
        |_, _| Ok(()),
        |_, view, _, snapshot| {
            assert_eq!(snapshot, view.evidence_snapshot(&["fixture-a".to_owned()])?);
            Ok((Vec::new(), snapshot))
        },
    )
}

fn file_store(path: &Path) -> (Store, String) {
    let mut store = Store::initialize(path).unwrap();
    let profile = append_fixture_descriptor(&mut store);
    commit_admitted(
        &mut store,
        "fixture-a",
        "prepared-first",
        &profile,
        document(json!({"state":"healthy"})),
        b"first".to_vec(),
    );
    (store, profile)
}

#[test]
fn unchanged_prepared_freshness_matches_the_full_guarded_snapshot() {
    let (mut store, profile) = configured_store();
    commit_admitted(
        &mut store,
        "fixture-a",
        "prepared-first",
        &profile,
        document(json!({"state":"healthy"})),
        b"first".to_vec(),
    );
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    assert_eq!(proof.snapshot().reports.len(), 1);
    let snapshot = resolve_freshness(&mut store, proof).unwrap();
    assert_eq!(snapshot.reports[0].report_id, "report-prepared-first");
    store.validate().unwrap();
}

#[test]
fn unchanged_prepared_collection_matches_full_source_and_current_occurrence() {
    let (mut store, profile) = configured_store();
    let pending = retention_collection(&mut store, &profile, "prepared-current", TIME);
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    assert!(proof.snapshot().reports.is_empty());
    let result = store
        .commit_admitted_collection_prepared_validated(
            &pending,
            proof,
            |_, _| Ok(()),
            |view, receipt, snapshot| {
                assert_eq!(snapshot, view.evidence_snapshot(&["fixture-a".to_owned()])?);
                assert_eq!(snapshot.reports.len(), 1);
                assert_eq!(snapshot.reports[0].report_id, "report-prepared-current");
                assert_eq!(
                    Some(snapshot.reports[0].report_sequence),
                    receipt.report_sequence
                );
                Ok::<_, StoreError>(AdmittedCollectionCompletion {
                    value: (),
                    evaluations: Vec::new(),
                    diagnostic_artifact: None,
                    status: StatusEventInput {
                        status_event_id: "status-prepared-current".into(),
                        component_kind: "instance".into(),
                        component_id: "fixture-a".into(),
                        state: "healthy".into(),
                        code: "report_complete".into(),
                        observed_at: TIME.into(),
                        detail: document(json!({"schema":"nq.collection_outcome.v2",
                        "instance_id":"fixture-a", "run_id":pending.run.run_id,
                        "result":{"outcome":"admitted","report_id":"report-prepared-current",
                        "report_status":"complete","semantic_digest":receipt.semantic_digest,
                        "evaluations":[]}})),
                    },
                })
            },
        )
        .unwrap();
    assert!(matches!(result, ProviderIntakeCommit::Committed { .. }));
    store.validate().unwrap();
}

#[test]
fn same_connection_dml_after_preparation_is_reconciled_before_build() {
    let (mut store, profile) = configured_store();
    commit_admitted(
        &mut store,
        "fixture-a",
        "prepared-first",
        &profile,
        document(json!({"state":"healthy"})),
        b"first".to_vec(),
    );
    let trigger: String = store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='immutable_admitted_reports_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    store
        .connection
        .execute_batch("DROP TRIGGER immutable_admitted_reports_update")
        .unwrap();
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    let original = proof.snapshot().reports[0].canonical_json.clone();
    let changed = document(json!({"changed":"same connection"}));
    let error = store
        .commit_evaluations_prepared_validated::<(), StoreError, _, _>(
            proof,
            |same, _| {
                same.connection.execute(
                    "UPDATE admitted_reports SET canonical_json=?1",
                    [changed.as_bytes()],
                )?;
                Ok(())
            },
            |_, _, _, _| panic!("changed source must refuse before the builder"),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        StoreError::Refused(Refusal::HistoryChanged(_))
    ));
    // The validation callback's own mutation is rolled back with the operation.
    assert_eq!(
        store
            .connection
            .query_row("SELECT canonical_json FROM admitted_reports", [], |row| row
                .get::<_, Vec<u8>>(0))
            .unwrap(),
        original
    );
    store.connection.execute_batch(&trigger).unwrap();
    store.validate().unwrap();
}

#[test]
fn foreign_committed_source_substitution_is_not_accepted_from_the_proof() {
    let root = tempdir().unwrap();
    let path = root.path().join("prepared-substitution.db");
    let (mut store, _) = file_store(&path);
    let trigger: String = store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='immutable_admitted_reports_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    store
        .connection
        .execute_batch("DROP TRIGGER immutable_admitted_reports_update")
        .unwrap();
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    let original = proof.snapshot().reports[0].canonical_json.clone();
    let foreign = Connection::open(&path).unwrap();
    foreign
        .execute(
            "UPDATE admitted_reports SET canonical_json=?1",
            [document(json!({"changed":"foreign commit"})).as_bytes()],
        )
        .unwrap();
    let error = resolve_freshness(&mut store, proof).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Refused(Refusal::HistoryChanged(_))
    ));
    foreign
        .execute("UPDATE admitted_reports SET canonical_json=?1", [&original])
        .unwrap();
    drop(foreign);
    store.connection.execute_batch(&trigger).unwrap();
    store.validate().unwrap();
}

#[test]
fn same_instance_append_invalidates_complete_source_membership() {
    let root = tempdir().unwrap();
    let path = root.path().join("prepared-append.db");
    let (mut store, profile) = file_store(&path);
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    let mut foreign = Store::open(&path).unwrap();
    commit_admitted(
        &mut foreign,
        "fixture-a",
        "prepared-late",
        &profile,
        document(json!({"state":"different testimony"})),
        b"late".to_vec(),
    );
    drop(foreign);
    let error = resolve_freshness(&mut store, proof).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Refused(Refusal::HistoryChanged(_))
    ));
    store.validate().unwrap();
}

#[test]
fn unrelated_instance_commit_falls_back_and_preserves_success() {
    let root = tempdir().unwrap();
    let path = root.path().join("prepared-unrelated.db");
    let (mut store, profile) = file_store(&path);
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    let mut foreign = Store::open(&path).unwrap();
    commit_admitted(
        &mut foreign,
        "fixture-b",
        "prepared-other",
        &profile,
        document(json!({"state":"healthy"})),
        b"other".to_vec(),
    );
    drop(foreign);
    let snapshot = resolve_freshness(&mut store, proof).unwrap();
    assert_eq!(snapshot.reports.len(), 1);
    assert_eq!(snapshot.reports[0].instance_id, "fixture-a");
    store.validate().unwrap();
}

#[test]
fn same_connection_rollback_keeps_exact_source_and_allows_fallback() {
    let (mut store, profile) = configured_store();
    commit_admitted(
        &mut store,
        "fixture-a",
        "prepared-first",
        &profile,
        document(json!({"state":"healthy"})),
        b"first".to_vec(),
    );
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    store
        .connection
        .execute_batch("BEGIN; UPDATE retention_state SET delete_enabled=1; ROLLBACK")
        .unwrap();
    assert_eq!(
        resolve_freshness(&mut store, proof).unwrap().reports.len(),
        1
    );
    store.validate().unwrap();
}

#[test]
fn foreign_rollback_keeps_exact_source_and_success() {
    let root = tempdir().unwrap();
    let path = root.path().join("prepared-rollback.db");
    let (mut store, _) = file_store(&path);
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    let foreign = Connection::open(&path).unwrap();
    foreign
        .execute_batch("BEGIN; UPDATE retention_state SET delete_enabled=1; ROLLBACK")
        .unwrap();
    drop(foreign);
    assert_eq!(
        resolve_freshness(&mut store, proof).unwrap().reports.len(),
        1
    );
    store.validate().unwrap();
}

#[test]
fn another_handle_proof_uses_full_reconciliation_without_a_new_refusal() {
    let root = tempdir().unwrap();
    let path = root.path().join("prepared-handle.db");
    let (mut first, _) = file_store(&path);
    let proof = first.prepare_evidence_snapshot("fixture-a").unwrap();
    drop(first);
    let mut second = Store::open(&path).unwrap();
    assert_eq!(
        resolve_freshness(&mut second, proof).unwrap().reports.len(),
        1
    );
    second.validate().unwrap();
}

#[test]
fn same_connection_schema_change_preserves_snapshot_parity() {
    let (mut store, profile) = configured_store();
    commit_admitted(
        &mut store,
        "fixture-a",
        "prepared-first",
        &profile,
        document(json!({"state":"healthy"})),
        b"first".to_vec(),
    );
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    store
        .connection
        .execute_batch("CREATE TABLE prepared_cookie_fixture(value INTEGER)")
        .unwrap();
    assert_eq!(
        resolve_freshness(&mut store, proof).unwrap().reports.len(),
        1
    );
    store
        .connection
        .execute_batch("DROP TABLE prepared_cookie_fixture")
        .unwrap();
    store.validate().unwrap();
}

#[test]
fn prepared_snapshot_retention_generation_change_keeps_its_refusal() {
    let root = tempdir().unwrap();
    let path = root.path().join("prepared-expiry.db");
    let mut store = retention_window_fixture(&path, 2);
    let proof = store.prepare_evidence_snapshot("fixture-a").unwrap();
    let generation = proof.retention_generation();
    let result = retention_window_expire(&mut store).unwrap();
    assert!(result.boundary.generation > generation);
    let error = resolve_freshness(&mut store, proof).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Refused(Refusal::HistoryChanged(_))
    ));
    store.validate().unwrap();
}

#[test]
fn exact_current_reader_requires_instance_identity_sequence_and_full_source() {
    let (mut store, profile) = configured_store();
    let receipt = commit_admitted(
        &mut store,
        "fixture-a",
        "prepared-first",
        &profile,
        document(json!({"state":"healthy"})),
        b"first".to_vec(),
    );
    let sequence = receipt.report_sequence.unwrap();
    for (instance, id, at) in [
        ("fixture-b", "report-prepared-first", sequence),
        ("fixture-a", "report-wrong", sequence),
        ("fixture-a", "report-prepared-first", sequence + 1),
    ] {
        assert!(
            prepared_evidence::current_admitted_report(&store.connection, instance, id, at)
                .is_err()
        );
    }
    assert_eq!(
        prepared_evidence::current_admitted_report(
            &store.connection,
            "fixture-a",
            "report-prepared-first",
            sequence
        )
        .unwrap()
        .report_id,
        "report-prepared-first"
    );
}
