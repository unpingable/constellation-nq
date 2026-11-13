// These exercise the public Store selectors against the real current schema,
// including its foreign keys and insertion constraints. The bulk row fixtures
// isolate paging; they do not claim to be complete engine-semantic histories.

const HISTORY: usize = 2_048;
const PAGE: u32 = 32;

/// Disposable resource observation using the same owning Store fixtures.
/// No SQL work counter runs during timing. This measures late-page reads,
/// not complete engine validation, collection freshness or production cost.
#[test]
#[ignore = "explicit native paging CPU observation; no latency acceptance threshold"]
fn history_paging_resource_measurement() {
    let repeats = std::env::var("NQ_PAGING_REPEATS")
        .ok()
        .map(|value| value.parse::<usize>().expect("repeat count"))
        .unwrap_or(2_000);
    assert!((1..=20_000).contains(&repeats));
    let cpu_ticks = || {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let (_, fields) = stat.rsplit_once(')').unwrap();
        let fields = fields.split_whitespace().collect::<Vec<_>>();
        fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
    };
    for (kind, name) in [
        (Rows::Runs, "watcher"),
        (Rows::Reports, "reports"),
        (Rows::Artifacts, "artifacts"),
        (Rows::LegacyGaps, "legacy"),
    ] {
        let store = paging_store(kind);
        let suffix = format!("page-{:05}", HISTORY - 64);
        let run_cursor = format!("run-{suffix}");
        let report_cursor = format!("report-{suffix}");
        let read_page = || match kind {
            Rows::Runs => std::hint::black_box(
                store
                    .watcher_run_outcomes_bounded(PAGE, Some(&run_cursor))
                    .unwrap(),
            )
            .len(),
            Rows::Reports => std::hint::black_box(
                store
                    .admitted_report_ids_bounded(PAGE, Some(&report_cursor))
                    .unwrap(),
            )
            .len(),
            Rows::Artifacts => std::hint::black_box(
                store
                    .diagnostic_artifact_commitments_bounded(PAGE, Some((HISTORY - 64) as u64))
                    .unwrap(),
            )
            .len(),
            Rows::LegacyGaps => std::hint::black_box(
                store
                    .legacy_provider_intake_gaps_bounded(PAGE, Some(&run_cursor))
                    .unwrap(),
            )
            .len(),
        };
        assert_eq!(read_page(), PAGE as usize);
        let start_cpu = cpu_ticks();
        let start = std::time::Instant::now();
        let rows: usize = (0..repeats)
            .map(|_| std::hint::black_box(read_page()))
            .sum();
        let wall_us = start.elapsed().as_micros();
        let cpu = cpu_ticks() - start_cpu;
        assert_eq!(rows, repeats * PAGE as usize);
        eprintln!(
            "PAGING_RESOURCE kind={name} history={HISTORY} repeats={repeats} rows={rows} cpu_ticks={cpu} wall_us={wall_us}"
        );
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Rows {
    Runs,
    Reports,
    Artifacts,
    LegacyGaps,
}

fn paging_store(rows: Rows) -> Store {
    let (mut store, profile) = configured_store();
    append_fixture_admission(&mut store, &profile, "fixture-a", "paging-admission");
    let admission = store.admission("paging-admission").unwrap().unwrap();
    let raw_digest = digest("{}");
    let transaction = store.connection.transaction().unwrap();
    if rows == Rows::Reports {
        transaction
            .execute("UPDATE retention_state SET delete_enabled=1", [])
            .unwrap();
    }
    for offset in 0..HISTORY {
        // Lexical selectors must not accidentally follow insertion order.
        let index = if rows == Rows::Artifacts {
            offset
        } else {
            HISTORY - 1 - offset
        };
        let suffix = format!("page-{index:05}");
        let mut run = run("fixture-a", &suffix, &profile);
        if rows != Rows::Runs || index % 2 == 0 {
            run.admission_id = Some("paging-admission".into());
        }
        insert_run(&transaction, &run).unwrap();
        match rows {
            Rows::Runs => {}
            Rows::Reports => {
                let compact = index % 8 == 0;
                let raw: &[u8] = if compact { b"" } else { b"{}" };
                let submission = format!("submission-{suffix}");
                transaction.execute(
                    "INSERT INTO raw_submissions (submission_id,run_id,raw_bytes,raw_sha256,received_at,protocol_outcome,admission_outcome,source_expired)
                     VALUES (?1,?2,?3,?4,?5,'valid_report','admitted',?6)",
                    params![submission, run.run_id, raw, raw_digest, TIME, i64::from(compact)],
                ).unwrap();
                transaction.execute(
                    "INSERT INTO admitted_reports (report_id,submission_id,instance_id,profile_id,profile_version,profile_digest,observed_at,received_at,report_status,canonical_json,semantic_digest,validated_report_json,judgment_schema_version,judgment_digest,admission_context_digest,admitted_at,source_expired)
                     VALUES (?1,?2,'fixture-a','fixture.health','1',?3,?4,?4,'complete',CAST('{}' AS BLOB),?5,CAST('{}' AS BLOB),?6,?5,?7,?4,?8)",
                    params![format!("report-{suffix}"), submission, profile, TIME, raw_digest, JUDGMENT_SCHEMA_VERSION, admission.admission_context_digest, i64::from(compact)],
                ).unwrap();
            }
            Rows::Artifacts => {
                let artifact = digest(&format!("paging-artifact-{index:05}"));
                transaction.execute(
                    "INSERT INTO diagnostic_artifact_commitments (artifact_id,contract_schema,canonical_bytes_sha256,canonical_bytes_length,committed_at)
                     VALUES (?1,'fixture.paging.v1',?2,2,?3)",
                    params![artifact, raw_digest, TIME],
                ).unwrap();
                transaction.execute(
                    "INSERT INTO local_diagnostic_artifact_origins (artifact_id,run_id,completed_at) VALUES (?1,?2,?3)",
                    params![artifact, run.run_id, TIME],
                ).unwrap();
            }
            Rows::LegacyGaps => {
                transaction.execute(
                    "INSERT INTO legacy_v3_watcher_run_intake_gaps (run_id,source_schema_version,source_schema_artifact_digest,limitation_code,detail_json,migrated_at)
                     VALUES (?1,3,?2,'provider_intake_not_recorded',CAST('{\"fixture\":\"paging\"}' AS BLOB),?3)",
                    params![run.run_id, SCHEMA_V3_ARTIFACT_DIGEST, TIME],
                ).unwrap();
            }
        }
    }
    if rows == Rows::Reports {
        transaction
            .execute("UPDATE retention_state SET delete_enabled=0", [])
            .unwrap();
    }
    transaction.commit().unwrap();
    store
}

fn measured<T>(store: &Store, read: impl FnOnce() -> T) -> (T, u64) {
    start_sql_work_count();
    store.count_sql_work_on_this_handle();
    let value = read();
    (value, stop_sql_work_count().unwrap())
}

fn assert_seek_work(label: &str, early: u64, late: u64) {
    eprintln!("history paging {label}: early={early} late={late}");
    assert!(early > 0, "the native SQLite work counter must be active");
    assert!(
        late <= early + 1_024,
        "{label} must seek past the retained prefix rather than re-read it: early={early} late={late}"
    );
}

#[test]
fn retained_history_watcher_pages_seek_past_the_prefix() {
    let store = paging_store(Rows::Runs);
    let (early, early_work) = measured(&store, || {
        store.watcher_run_outcomes_bounded(PAGE, None).unwrap()
    });
    let cursor = format!("run-page-{:05}", HISTORY - PAGE as usize - 1);
    let (late, late_work) = measured(&store, || {
        store
            .watcher_run_outcomes_bounded(PAGE, Some(&cursor))
            .unwrap()
    });
    for (page, start) in [(&early, 0), (&late, HISTORY - PAGE as usize)] {
        assert_eq!(page.len(), PAGE as usize);
        for (offset, row) in page.iter().enumerate() {
            let index = start + offset;
            let bound = index % 2 == 0;
            assert_eq!(row.run_id, format!("run-page-{index:05}"));
            assert_eq!(row.request_id, format!("request-page-{index:05}"));
            assert_eq!(row.instance_id, "fixture-a");
            assert_eq!(row.profile_id, "fixture.health");
            assert_eq!(row.profile_version, "1");
            assert_eq!(row.profile_digest, fixture_descriptor_digest());
            assert_eq!(row.admission_id, bound.then(|| "paging-admission".into()));
            assert_eq!(row.admission_instance_id, bound.then(|| "fixture-a".into()));
            assert_eq!(
                row.admission_profile_id,
                bound.then(|| "fixture.health".into())
            );
            assert_eq!(row.admission_profile_version, bound.then(|| "1".into()));
            assert_eq!(
                row.admission_profile_digest,
                bound.then(fixture_descriptor_digest)
            );
            assert_eq!(
                row.profile_semantic_id,
                bound.then(|| fixture_identity().profile_semantic_id.into_string())
            );
            assert_eq!(
                row.admission_detector_identity_digest,
                bound.then(|| fixture_identity().detector_identity_digest.into_string())
            );
            assert_eq!(
                row.admission_evaluator_artifact_digest,
                bound.then(|| fixture_identity().evaluator_artifact_digest.into_string())
            );
            assert_eq!(row.acquisition_outcome, "response");
            assert_eq!(
                row.resource_outcome_json,
                run("fixture-a", "unused", &row.profile_digest)
                    .resource_outcome
                    .as_bytes()
            );
        }
    }
    assert_eq!(
        store.watcher_run_outcomes_bounded(PAGE, Some("")).unwrap(),
        early
    );
    assert!(
        store
            .watcher_run_outcomes_bounded(PAGE, Some("run-page-02047"))
            .unwrap()
            .is_empty()
    );
    assert_seek_work("watcher runs", early_work, late_work);
}

#[test]
fn retained_history_report_pages_seek_and_exclude_compact_sources() {
    let store = paging_store(Rows::Reports);
    let (early, early_work) = measured(&store, || {
        store.admitted_report_ids_bounded(PAGE, None).unwrap()
    });
    let start = HISTORY - 64;
    let cursor = format!("report-page-{:05}", start - 1);
    let (late, late_work) = measured(&store, || {
        store
            .admitted_report_ids_bounded(PAGE, Some(&cursor))
            .unwrap()
    });
    let expected = |start| {
        (start..HISTORY)
            .filter(|index| index % 8 != 0)
            .take(PAGE as usize)
            .map(|index| format!("report-page-{index:05}"))
            .collect::<Vec<_>>()
    };
    assert_eq!(early, expected(0));
    assert_eq!(late, expected(start));
    assert_eq!(
        store.admitted_report_ids_bounded(PAGE, Some("")).unwrap(),
        early
    );
    assert!(
        store
            .admitted_report_ids_bounded(PAGE, Some("report-page-02047"))
            .unwrap()
            .is_empty()
    );
    assert_seek_work("admitted reports", early_work, late_work);
}

#[test]
fn retained_history_artifact_pages_seek_in_sequence_order() {
    let store = paging_store(Rows::Artifacts);
    let (early, early_work) = measured(&store, || {
        store
            .diagnostic_artifact_commitments_bounded(PAGE, None)
            .unwrap()
    });
    let after = (HISTORY - PAGE as usize) as u64;
    let (late, late_work) = measured(&store, || {
        store
            .diagnostic_artifact_commitments_bounded(PAGE, Some(after))
            .unwrap()
    });
    for (page, start) in [(&early, 0), (&late, HISTORY - PAGE as usize)] {
        assert_eq!(page.len(), PAGE as usize);
        for (offset, row) in page.iter().enumerate() {
            let index = start + offset;
            assert_eq!(row.artifact_sequence, (index + 1) as u64);
            assert_eq!(
                row.artifact_id.as_str(),
                digest(&format!("paging-artifact-{index:05}"))
            );
            assert_eq!(row.contract_schema, "fixture.paging.v1");
            assert_eq!(row.canonical_bytes_sha256.as_str(), digest("{}"));
            assert_eq!(row.canonical_bytes_length, 2);
            assert_eq!(row.committed_at, TIME);
            assert_eq!(
                row.origin,
                DiagnosticArtifactOrigin::Local {
                    run_id: format!("run-page-{index:05}"),
                    evaluation_id: None,
                    completed_at: TIME.into(),
                }
            );
        }
    }
    assert_eq!(
        store
            .diagnostic_artifact_commitments_bounded(PAGE, Some(0))
            .unwrap(),
        early
    );
    assert!(
        store
            .diagnostic_artifact_commitments_bounded(PAGE, Some(HISTORY as u64))
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .diagnostic_artifact_commitments_bounded(PAGE, Some(u64::MAX))
            .is_err()
    );
    assert_seek_work("diagnostic artifacts", early_work, late_work);
}

#[test]
fn retained_history_legacy_gap_pages_seek_past_the_prefix() {
    let store = paging_store(Rows::LegacyGaps);
    let (early, early_work) = measured(&store, || {
        store
            .legacy_provider_intake_gaps_bounded(PAGE, None)
            .unwrap()
    });
    let cursor = format!("run-page-{:05}", HISTORY - PAGE as usize - 1);
    let (late, late_work) = measured(&store, || {
        store
            .legacy_provider_intake_gaps_bounded(PAGE, Some(&cursor))
            .unwrap()
    });
    for (page, start) in [(&early, 0), (&late, HISTORY - PAGE as usize)] {
        assert_eq!(page.len(), PAGE as usize);
        for (offset, row) in page.iter().enumerate() {
            assert_eq!(row.run_id, format!("run-page-{:05}", start + offset));
            assert_eq!(row.source_schema_version, 3);
            assert_eq!(row.source_schema_artifact_digest, SCHEMA_V3_ARTIFACT_DIGEST);
            assert_eq!(row.limitation_code, "provider_intake_not_recorded");
            assert_eq!(row.detail_json, b"{\"fixture\":\"paging\"}");
            assert_eq!(row.migrated_at, TIME);
        }
    }
    assert_eq!(
        store
            .legacy_provider_intake_gaps_bounded(PAGE, Some(""))
            .unwrap(),
        early
    );
    assert!(
        store
            .legacy_provider_intake_gaps_bounded(PAGE, Some("run-page-02047"))
            .unwrap()
            .is_empty()
    );
    assert_seek_work("legacy provider gaps", early_work, late_work);
}

#[test]
fn history_paging_keeps_empty_results_and_limit_refusals() {
    let store = Store::initialize_in_memory().unwrap();
    assert!(
        store
            .watcher_run_outcomes_bounded(PAGE, None)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .admitted_report_ids_bounded(PAGE, None)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .diagnostic_artifact_commitments_bounded(PAGE, None)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .legacy_provider_intake_gaps_bounded(PAGE, None)
            .unwrap()
            .is_empty()
    );
    for limit in [0, MAX_PUBLIC_QUERY_ROWS + 1] {
        assert!(store.watcher_run_outcomes_bounded(limit, None).is_err());
        assert!(store.admitted_report_ids_bounded(limit, None).is_err());
        assert!(
            store
                .diagnostic_artifact_commitments_bounded(limit, None)
                .is_err()
        );
        assert!(
            store
                .legacy_provider_intake_gaps_bounded(limit, None)
                .is_err()
        );
    }
}
