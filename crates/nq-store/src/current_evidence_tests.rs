// Included in prepared_evidence_tests: reuse its real Store transactions and
// the parent public-data fixtures. This is a separate, explicitly narrower
// proof; no expectation below weakens PreparedEvidenceSnapshot.

fn current_lineage(profile: &str) -> EvaluationFindingLineage {
    EvaluationFindingLineage {
        instance_id: "fixture-a".into(),
        detector_id: "fixture.unhealthy".into(),
        detector_version: "1".into(),
        detector_digest: digest("detector-v1"),
        profile_id: "fixture.health".into(),
        profile_version: "1".into(),
        profile_digest: profile.into(),
        profile_semantic_id: digest("profile-semantic"),
        subject_json: document(json!({"fixture":"finding"})).as_bytes().to_vec(),
        condition_name: "fixture.unhealthy".into(),
        basis_json: document(json!({"profile":"fixture.health"}))
            .as_bytes()
            .to_vec(),
    }
}

fn current_source_fixture(count: usize) -> (Store, String) {
    let (mut store, profile) = configured_store();
    for index in 1..=count {
        commit_admitted(
            &mut store,
            "fixture-a",
            &format!("current-{index:03}"),
            &profile,
            document(json!({"state":"healthy"})),
            b"same fixture bytes".to_vec(),
        );
    }
    (store, profile)
}

fn resolve_current(
    store: &mut Store,
    proof: PreparedCurrentEvidenceSnapshot,
) -> Result<EvidenceSnapshot, StoreError> {
    store.commit_evaluations_current_prepared_validated(
        proof,
        |_, _| Ok(()),
        |_, _, _, snapshot| Ok((Vec::new(), snapshot)),
    )
}

fn assert_current_history_changed(result: Result<EvidenceSnapshot, StoreError>) {
    assert!(matches!(
        result,
        Err(StoreError::Refused(Refusal::HistoryChanged(_)))
    ));
}

#[test]
fn current_evidence_head_body_and_sql_work_do_not_follow_unreferenced_history() {
    let mut measured = Vec::new();
    for count in [1, 64] {
        let (mut store, profile) = current_source_fixture(count);
        let lineage = current_lineage(&profile);
        start_sql_work_count();
        history_scope::install_sql_work_counter(&store.connection);
        let proof = store
            .prepare_current_evidence_snapshot(&lineage)
            .unwrap()
            .unwrap();
        let work = stop_sql_work_count().unwrap();
        assert_eq!(
            proof.retention_generation(),
            store.retention_generation().unwrap()
        );
        let snapshot = proof.snapshot();
        assert_eq!(snapshot.reports.len(), 1);
        assert!(snapshot.expired_citations.is_empty());
        assert_eq!(
            snapshot.reports[0].report_id,
            format!("report-current-{count:03}")
        );
        assert_eq!(
            snapshot.watermarks[0].max_report_sequence,
            i64::try_from(count).unwrap()
        );
        let body_bytes = snapshot
            .reports
            .iter()
            .map(|row| row.canonical_json.len())
            .sum::<usize>();
        assert!(
            work > 0,
            "the existing real SQL counter must observe preparation"
        );
        println!(
            "current_evidence retained_rows={count} selected_rows=1 body_bytes={body_bytes} sql_work={work}"
        );
        measured.push((body_bytes, work));
        let expected = proof.snapshot().clone();
        assert_eq!(resolve_current(&mut store, proof).unwrap(), expected);
        assert_eq!(
            store
                .evidence_snapshot(&["fixture-a".into()])
                .unwrap()
                .reports
                .len(),
            count,
            "scoped selection never removes retained source"
        );
        store.validate().unwrap();
    }
    assert_eq!(measured[0].0, measured[1].0);
    assert!(
        measured[1].1 <= measured[0].1 + 512,
        "current-evidence SQL work must seek the head, not traverse 63 additional reports: {measured:?}"
    );
}

#[test]
fn current_evidence_old_unreferenced_bytes_are_outside_only_the_scoped_proof() {
    let (mut store, profile) = current_source_fixture(2);
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
    let current = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    let full = store.prepare_evidence_snapshot("fixture-a").unwrap();
    let original = full.snapshot().reports[0].canonical_json.clone();
    store
        .connection
        .execute(
            "UPDATE admitted_reports SET canonical_json=?1 WHERE report_id='report-current-001'",
            [document(json!({"changed":"unreferenced old bytes"})).as_bytes()],
        )
        .unwrap();
    let narrowed = resolve_current(&mut store, current)
        .expect("unreferenced old bytes are outside the current proof");
    assert_eq!(narrowed.reports.len(), 1);
    assert_eq!(narrowed.reports[0].report_id, "report-current-002");
    assert_current_history_changed(resolve_freshness(&mut store, full));
    // The intentional substitution does not become globally valid testimony.
    // Restore the exact source and trigger before asserting Store integrity.
    store
        .connection
        .execute(
            "UPDATE admitted_reports SET canonical_json=?1 WHERE report_id='report-current-001'",
            [&original],
        )
        .unwrap();
    store.connection.execute_batch(&trigger).unwrap();
    store.validate().unwrap();
}

#[test]
fn current_evidence_selected_head_and_citation_body_changes_still_refuse() {
    for selected_id in ["report-current-001", "report-current-002"] {
        let (mut store, profile) = current_source_fixture(2);
        append_current_finding(&mut store, &profile, "opened", "report-current-001", true);
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
        let proof = store
            .prepare_current_evidence_snapshot(&current_lineage(&profile))
            .unwrap()
            .unwrap();
        let original = proof
            .snapshot()
            .reports
            .iter()
            .find(|row| row.report_id == selected_id)
            .unwrap()
            .canonical_json
            .clone();
        store
            .connection
            .execute(
                "UPDATE admitted_reports SET canonical_json=?1 WHERE report_id=?2",
                params![
                    document(json!({"changed":"selected support bytes"})).as_bytes(),
                    selected_id
                ],
            )
            .unwrap();
        assert_current_history_changed(resolve_current(&mut store, proof));
        store
            .connection
            .execute(
                "UPDATE admitted_reports SET canonical_json=?1 WHERE report_id=?2",
                params![&original, selected_id],
            )
            .unwrap();
        store.connection.execute_batch(&trigger).unwrap();
        store.validate().unwrap();
    }
}

#[test]
fn current_evidence_absolute_head_append_refuses_even_for_an_unmatched_lineage() {
    for mismatched_lineage in [false, true] {
        let (mut store, profile) = current_source_fixture(1);
        let mut lineage = current_lineage(&profile);
        if mismatched_lineage {
            lineage.subject_json = document(json!("different:subject")).as_bytes().to_vec();
        }
        let proof = store
            .prepare_current_evidence_snapshot(&lineage)
            .unwrap()
            .unwrap();
        commit_admitted(
            &mut store,
            "fixture-a",
            "current-later",
            &profile,
            document(json!({"state":"different testimony"})),
            b"later".to_vec(),
        );
        assert_current_history_changed(resolve_current(&mut store, proof));
        store.validate().unwrap();
    }
}

#[test]
fn current_evidence_other_instance_append_reconciles_without_conflict() {
    let (mut store, profile) = current_source_fixture(2);
    let proof = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    let expected = proof.snapshot().clone();
    commit_admitted(
        &mut store,
        "fixture-b",
        "current-other",
        &profile,
        document(json!({"state":"healthy"})),
        b"other".to_vec(),
    );
    assert_eq!(resolve_current(&mut store, proof).unwrap(), expected);
    store.validate().unwrap();
}

fn append_current_finding(
    store: &mut Store,
    profile: &str,
    suffix: &str,
    cited: &str,
    opened: bool,
) {
    append_current_finding_state(store, profile, suffix, cited, opened, false);
}

fn append_current_finding_state(
    store: &mut Store,
    profile: &str,
    suffix: &str,
    cited: &str,
    opened: bool,
    resolved: bool,
) {
    let snapshot = store.evidence_snapshot(&["fixture-a".into()]).unwrap();
    let report = snapshot
        .reports
        .iter()
        .find(|row| row.report_id == cited)
        .unwrap();
    let evaluation = EvaluationInput {
        evaluation_id: format!("evaluation-current-{suffix}"),
        trigger_run_id: None,
        detector_id: "fixture.unhealthy".into(),
        detector_version: "1".into(),
        detector_digest: digest("detector-v1"),
        evaluator_artifact_digest: digest("evaluator-artifact"),
        started_at: TIME.into(),
        evaluated_at: TIME.into(),
        outcome: if resolved {
            "condition_explicitly_absent"
        } else {
            "condition_present"
        }
        .into(),
        detail: document(json!({})),
        profile: evaluation_profile(profile),
        watermarks: snapshot.watermarks.clone(),
        refusal: None,
    };
    let finding = FindingEventInput {
        event_id: format!("event-current-{suffix}"),
        finding_id: "finding-current-evidence".into(),
        event_kind: if resolved {
            "resolved"
        } else if opened {
            "opened"
        } else {
            "updated"
        }
        .into(),
        instance_id: "fixture-a".into(),
        profile_id: "fixture.health".into(),
        profile_version: "1".into(),
        profile_digest: profile.into(),
        subject: document(json!({"fixture":"finding"})),
        condition_name: "fixture.unhealthy".into(),
        condition_state: if resolved {
            "explicitly_absent"
        } else {
            "present"
        }
        .into(),
        visibility_state: "sufficient".into(),
        operator_work_state: if opened {
            "unacknowledged"
        } else {
            "acknowledged"
        }
        .into(),
        severity: "warning".into(),
        summary: "Fixture is unhealthy".into(),
        limitations: document(json!([])),
        safe_next_checks: document(json!([])),
        freshness: document(json!({"state":"current"})),
        basis: document(json!({"profile":"fixture.health"})),
        refusal: None,
        origin_mode: "native".into(),
        historical_refs: document(json!([])),
        observed_at: Some(TIME.into()),
        received_at: Some(TIME.into()),
        created_at: TIME.into(),
        evidence: vec![FindingEvidenceInput {
            ordinal: 0,
            report_id: report.report_id.clone(),
            report_semantic_digest: report.semantic_digest.clone(),
            observation_ordinal: Some(0),
            observed_at: TIME.into(),
            received_at: TIME.into(),
        }],
    };
    store
        .commit_evaluation(&evaluation, Some(&finding))
        .unwrap();
}

#[test]
fn current_evidence_finding_citations_are_reselected_inside_the_writer_guard() {
    for replace_citation in [false, true] {
        let (mut store, profile) = current_source_fixture(3);
        append_current_finding(&mut store, &profile, "opened", "report-current-001", true);
        let proof = store
            .prepare_current_evidence_snapshot(&current_lineage(&profile))
            .unwrap()
            .unwrap();
        assert_eq!(
            proof.snapshot().reports.len(),
            2,
            "head plus older current citation"
        );
        assert_eq!(proof.snapshot().watermarks[0].max_report_sequence, 3);
        assert!(
            proof
                .snapshot()
                .reports
                .iter()
                .any(|row| row.report_id == "report-current-001")
        );
        let expected = proof.snapshot().clone();
        append_current_finding(
            &mut store,
            &profile,
            "updated",
            if replace_citation {
                "report-current-002"
            } else {
                "report-current-001"
            },
            false,
        );
        let resolved = resolve_current(&mut store, proof);
        if replace_citation {
            assert_current_history_changed(resolved);
        } else {
            assert_eq!(
                resolved.unwrap(),
                expected,
                "operator-only event with identical support does not conflict"
            );
        }
        store.validate().unwrap();
    }
}

#[test]
fn current_evidence_retention_generation_change_keeps_its_refusal() {
    let root = tempdir().unwrap();
    let mut store = retention_window_fixture(&root.path().join("current-expiry.db"), 2);
    let profile: String = store.connection.query_row(
        "SELECT profile_digest FROM profile_descriptor_snapshots WHERE profile_id='fixture.health' AND profile_version='1'",
        [], |row| row.get(0),
    ).unwrap();
    let proof = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    let generation = proof.retention_generation();
    assert!(
        retention_window_expire(&mut store)
            .unwrap()
            .boundary
            .generation
            > generation
    );
    assert_current_history_changed(resolve_current(&mut store, proof));
    store.validate().unwrap();
}

#[test]
fn current_evidence_admitted_commit_adds_only_its_exact_current_occurrence() {
    let (mut store, profile) = current_source_fixture(2);
    let pending = retention_collection(&mut store, &profile, "current-new", TIME);
    let proof = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    let old_head = proof.snapshot().reports[0].clone();
    let result = store.commit_admitted_collection_current_prepared_validated(
        &pending, proof, |_, _| Ok(()), |_, receipt, snapshot| {
            assert_eq!(snapshot.reports.len(), 2);
            assert_eq!(snapshot.reports[0], old_head);
            assert_eq!(snapshot.reports[1].report_id, "report-current-new");
            assert_eq!(Some(snapshot.reports[1].report_sequence), receipt.report_sequence);
            assert_eq!(snapshot.watermarks[0].max_report_sequence, snapshot.reports[1].report_sequence);
            Ok::<_, StoreError>(AdmittedCollectionCompletion {
                value: (), evaluations: Vec::new(), diagnostic_artifact: None,
                status: StatusEventInput {
                    status_event_id: "status-current-new".into(), component_kind: "instance".into(),
                    component_id: "fixture-a".into(), state: "healthy".into(), code: "report_complete".into(),
                    observed_at: TIME.into(), detail: document(json!({"schema":"nq.collection_outcome.v2",
                        "instance_id":"fixture-a", "run_id":pending.run.run_id,
                        "result":{"outcome":"admitted", "report_id":"report-current-new",
                            "report_status":"complete", "semantic_digest":receipt.semantic_digest, "evaluations":[]}})),
                },
            })
        },
    ).unwrap();
    assert!(matches!(result, ProviderIntakeCommit::Committed { .. }));
    store.validate().unwrap();
}

fn compact_current_citation_fixture() -> (Store, String) {
    let (mut store, profile) = current_source_fixture(3);
    append_current_finding(&mut store, &profile, "opened", "report-current-001", true);
    append_current_finding_state(
        &mut store,
        &profile,
        "resolved",
        "report-current-001",
        false,
        true,
    );
    store
        .expire_ordinary_before("2100-01-01T00:00:00Z")
        .unwrap();
    let compact: bool = store
        .connection
        .query_row(
            "SELECT source_expired FROM admitted_reports WHERE report_id='report-current-001'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        compact,
        "real expiry must compact the resolved finding's released source"
    );
    (store, profile)
}

#[test]
fn current_evidence_retains_only_its_exact_compact_citation_metadata() {
    let (mut store, profile) = compact_current_citation_fixture();
    let proof = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    let snapshot = proof.snapshot();
    assert_eq!(snapshot.reports.len(), 1);
    assert_eq!(snapshot.reports[0].report_id, "report-current-003");
    assert_eq!(snapshot.watermarks[0].max_report_sequence, 3);
    assert_eq!(snapshot.expired_citations.len(), 1);
    assert_eq!(
        snapshot.expired_citations[0].report_id,
        "report-current-001"
    );
    assert_eq!(snapshot.expired_citations[0].canonical_json, b"{}");
    let expected = snapshot.clone();
    assert_eq!(resolve_current(&mut store, proof).unwrap(), expected);
    store.validate().unwrap();
}

#[test]
fn current_evidence_compact_citation_metadata_substitution_refuses() {
    let (mut store, profile) = compact_current_citation_fixture();
    let proof = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    let original = proof.snapshot().expired_citations[0].received_at.clone();
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
    store.connection.execute("UPDATE admitted_reports SET received_at='2099-01-01T00:00:00.000Z' WHERE report_id='report-current-001'", []).unwrap();
    assert_current_history_changed(resolve_current(&mut store, proof));
    store
        .connection
        .execute(
            "UPDATE admitted_reports SET received_at=?1 WHERE report_id='report-current-001'",
            [&original],
        )
        .unwrap();
    store.connection.execute_batch(&trigger).unwrap();
    store.validate().unwrap();
}

#[test]
fn current_evidence_missing_cited_source_never_disappears_during_initial_selection() {
    let (mut store, profile) = current_source_fixture(2);
    append_current_finding(&mut store, &profile, "opened", "report-current-001", true);
    let proof = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    let trigger: String = store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='immutable_admitted_reports_delete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    store.connection.execute_batch("PRAGMA foreign_keys=OFF;
        DROP TRIGGER immutable_admitted_reports_delete;
        CREATE TEMP TABLE removed_current_source AS SELECT * FROM admitted_reports WHERE report_id='report-current-001';
        DELETE FROM admitted_reports WHERE report_id='report-current-001';").unwrap();
    assert!(
        store
            .prepare_current_evidence_snapshot(&current_lineage(&profile))
            .is_err(),
        "a missing citation target cannot be hidden by a join"
    );
    assert!(
        resolve_current(&mut store, proof).is_err(),
        "selected citation deletion also refuses guarded resolution"
    );
    store
        .connection
        .execute_batch(
            "INSERT INTO admitted_reports SELECT * FROM removed_current_source;
        DROP TABLE removed_current_source;",
        )
        .unwrap();
    store.connection.execute_batch(&trigger).unwrap();
    store
        .connection
        .execute_batch("PRAGMA foreign_keys=ON")
        .unwrap();
    store.validate().unwrap();
}

#[test]
fn current_evidence_cited_digest_mismatch_never_disappears_during_initial_selection() {
    let (mut store, profile) = current_source_fixture(2);
    append_current_finding(&mut store, &profile, "opened", "report-current-001", true);
    let original: String = store.connection.query_row("SELECT report_semantic_digest FROM finding_evidence WHERE event_id='event-current-opened'", [], |row| row.get(0)).unwrap();
    let trigger: String = store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='immutable_finding_evidence_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    store
        .connection
        .execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER immutable_finding_evidence_update;")
        .unwrap();
    store.connection.execute("UPDATE finding_evidence SET report_semantic_digest=?1 WHERE event_id='event-current-opened'", [digest("substituted-citation")]).unwrap();
    assert!(
        store
            .prepare_current_evidence_snapshot(&current_lineage(&profile))
            .is_err(),
        "a mismatched citation digest cannot be hidden by a join"
    );
    store.connection.execute("UPDATE finding_evidence SET report_semantic_digest=?1 WHERE event_id='event-current-opened'", [&original]).unwrap();
    store.connection.execute_batch(&trigger).unwrap();
    store
        .connection
        .execute_batch("PRAGMA foreign_keys=ON")
        .unwrap();
    store.validate().unwrap();
}

#[test]
fn current_evidence_compact_absolute_head_returns_fallback_without_scanning_backwards() {
    let (mut store, profile) = current_source_fixture(2);
    let original: (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = store.connection.query_row(
        "SELECT canonical_json, validated_report_json, next_checkpoint_json FROM admitted_reports WHERE report_id='report-current-002'", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    // Deliberate compact-head input, not a globally valid expiry verdict.
    // Ordinary retention protects its head; restore it exactly after fallback.
    store.connection.execute_batch("UPDATE retention_state SET delete_enabled=1;
        UPDATE admitted_reports SET source_expired=1, canonical_json=CAST('{}' AS BLOB), validated_report_json=CAST('{}' AS BLOB), next_checkpoint_json=NULL WHERE report_id='report-current-002';
        UPDATE retention_state SET delete_enabled=0;").unwrap();
    assert!(
        store
            .prepare_current_evidence_snapshot(&current_lineage(&profile))
            .unwrap()
            .is_none()
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
    store.connection.execute("UPDATE admitted_reports SET source_expired=0, canonical_json=?1, validated_report_json=?2, next_checkpoint_json=?3 WHERE report_id='report-current-002'",
        params![original.0, original.1, original.2]).unwrap();
    store.connection.execute_batch(&trigger).unwrap();
    store.validate().unwrap();
}

#[test]
fn current_evidence_diagnostic_artifact_is_refused_while_the_full_api_accepts_it() {
    for current_only in [false, true] {
        let (mut store, profile) = configured_store();
        let suffix = "current-diagnostic-guard";
        let (run_id, artifact_id, result) = diagnostic_artifact_fixture_with_current_proof(
            &mut store,
            suffix,
            &profile,
            &format!("evaluation-{suffix}"),
            current_only,
        );
        if current_only {
            assert!(matches!(result, Err(StoreError::Invariant(message))
                if message.contains("ordinary only")));
            assert_eq!(
                store
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM watcher_runs WHERE run_id=?1",
                        [&run_id],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                0,
                "ordinary-only refusal rolls back the complete admitted occurrence"
            );
            assert!(matches!(
                store
                    .diagnostic_artifact(&artifact_id, &["nq.diagnostic_execution.v1"])
                    .unwrap(),
                DiagnosticArtifactLookup::NotFound
            ));
        } else {
            assert!(
                matches!(result, Ok(ProviderIntakeCommit::Committed { .. })),
                "the same well-formed diagnostic fixture is supported by the existing full API"
            );
        }
        store.validate().unwrap();
    }
}

#[test]
fn current_evidence_new_current_finding_support_without_report_append_refuses() {
    let (mut store, profile) = current_source_fixture(2);
    let proof = store
        .prepare_current_evidence_snapshot(&current_lineage(&profile))
        .unwrap()
        .unwrap();
    assert_eq!(proof.snapshot().reports.len(), 1);
    append_current_finding(&mut store, &profile, "appeared", "report-current-001", true);
    assert_current_history_changed(resolve_current(&mut store, proof));
    store.validate().unwrap();
}
