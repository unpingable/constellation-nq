// Profile-neutral named-successor context selection. Reuse the established
// admitted helper fixture; filesystem-capacity law/native acquisition is not
// substituted or requalified by this test. ExactCurrent already reconstructs
// only the newly admitted occurrence; this targets duplicate context traversal.
mod successor_context_reuse {
    use super::*;

    fn admitted_history(root: &Path, prior: usize) -> (CollectionEngine, WatcherConfig) {
        assert!(prior > 0);
        let (mut engine, watcher, _) = admitted_host_diagnostic_fixture(
            root,
            "successor-context-reuse-genesis",
            b"successor-context-reuse-evaluator",
        )
        .expect("the real named-successor helper consumer must execute");
        engine
            .diagnostic_execute(&watcher)
            .expect("initial fresh-instance diagnostic");
        for index in 1..prior {
            engine
                .diagnostic_acquire_successor_local(&watcher, &format!("context-seed-{index}"))
                .expect("retained named predecessor");
        }
        (engine, watcher)
    }

    // These counters observe their named consumers, not all source BLOB reads
    // or process resource use. In particular, ordinary PREPARED_SOURCE counters
    // do not cover the named successor's complete snapshots.
    fn measure_existing_successor_phase<T>(operation: impl FnOnce() -> T) -> (T, Value) {
        let selectors = CONTEXT_SELECTOR_CALLS.with(std::cell::Cell::get);
        let validations = CONTEXT_SELECTOR_VALIDATIONS.with(std::cell::Cell::get);
        let reconstructions = RECONSTRUCTIONS.with(std::cell::Cell::get);
        let hashes = MEMO_BODY_BYTES_HASHED.with(std::cell::Cell::get);
        nq_store::start_sql_work_count();
        let started = std::time::Instant::now();
        let value = operation();
        let elapsed_micros = started.elapsed().as_micros();
        let sql_operations = nq_store::stop_sql_work_count().expect("SQL counting was active");
        assert!(
            sql_operations > 0,
            "each measured phase must observe real SQL work"
        );
        (
            value,
            json!({
                "context_selector_calls": CONTEXT_SELECTOR_CALLS.with(std::cell::Cell::get) - selectors,
                "context_validations": CONTEXT_SELECTOR_VALIDATIONS.with(std::cell::Cell::get) - validations,
                "report_reconstructions": RECONSTRUCTIONS.with(std::cell::Cell::get) - reconstructions,
                "memo_raw_bytes_hashed": MEMO_BODY_BYTES_HASHED.with(std::cell::Cell::get) - hashes,
                "sqlite_vm_operations": sql_operations,
                "instrumented_elapsed_micros": elapsed_micros,
            }),
        )
    }

    /// Characterize the existing complete-source contract at two finite sizes.
    /// A lost occurrence, changed replay or unqualified artifact must fail;
    /// work growth itself is reported, not declared a correctness failure.
    /// This uses the real generic host fixture, not the filesystem-capacity law.
    #[test]
    #[ignore = "bounded 1/64 real-helper characterization; run explicitly and serially"]
    fn named_successor_full_contract_work_at_one_and_sixty_four_reports() {
        for prior in [1usize, 64] {
            let root = tempfile::tempdir().unwrap();
            let (mut engine, watcher) = admitted_history(root.path(), prior);
            // Setup, its cache warming and this inventory are outside all
            // measured phases. Each size starts in its own temporary store.
            let before = engine
                .store
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                .unwrap();
            assert_eq!(before.reports.len(), prior);
            let retained_raw_bytes: usize = before
                .reports
                .iter()
                .map(|row| row.canonical_json.len())
                .sum();
            drop(before);
            let acquisition_id = "full-contract-work-current";
            let (artifact, acquire_work) = measure_existing_successor_phase(|| {
                engine.store.count_sql_work_on_this_handle();
                engine
                    .diagnostic_acquire_successor_local(&watcher, acquisition_id)
                    .expect("real named successor acquisition")
            });
            let original = artifact.canonical_bytes().unwrap();
            let SupportedDiagnosticExecution::V2(value) = &artifact else {
                panic!("local v2 artifact");
            };
            assert_eq!(value.inputs.selected.len(), 1);
            assert_eq!(value.inputs.admitted.len(), 1);
            assert_eq!(
                value.outcome.condition,
                DiagnosticConditionV1::ExplicitlyAbsent
            );

            let (replay, replay_work) = measure_existing_successor_phase(|| {
                engine.store.count_sql_work_on_this_handle();
                engine
                    .diagnostic_replay_local_successor(&watcher, acquisition_id)
                    .expect("same-handle replay")
            });
            assert_eq!(replay.canonical_bytes().unwrap(), original);
            let (admission, qualify_work) = measure_existing_successor_phase(|| {
                engine.store.count_sql_work_on_this_handle();
                qualify_diagnostic_admission(&engine.store, artifact.artifact_id().as_digest())
                    .expect("existing full qualification")
            });
            admission.validate().expect("valid admission carrier");
            assert_eq!(
                &admission.artifact.artifact_id,
                artifact.artifact_id().as_digest()
            );
            assert_eq!(
                admission.artifact.canonical_bytes_sha256,
                nq_protocol::sha256_bytes(&original)
            );

            let config = engine.config.clone();
            drop(engine);
            // This is one writable engine reopen after the above operations,
            // not three independent CLI process opens or a cold-cache trial.
            let (mut reopened, reopen_work) = measure_existing_successor_phase(|| {
                let identity = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(
                    b"successor-context-reuse-evaluator",
                ));
                CollectionEngine::open_with_evaluator_identity(&config, Ok(identity))
                    .expect("real engine reopen")
            });
            assert_eq!(
                reopened
                    .diagnostic_replay_local_successor(&watcher, acquisition_id)
                    .unwrap()
                    .canonical_bytes()
                    .unwrap(),
                original
            );
            assert_eq!(
                reopened
                    .store
                    .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                    .unwrap()
                    .reports
                    .len(),
                prior + 1,
                "replay, qualification and reopen never collect another occurrence"
            );
            println!(
                "successor_full_contract_work {}",
                json!({
                    "retained_reports_before": prior,
                    "retained_raw_bytes_before": retained_raw_bytes,
                    "profile": watcher.profile,
                    "acquire": acquire_work,
                    "same_handle_replay": replay_work,
                    "same_handle_qualify": qualify_work,
                    "writable_engine_reopen_after_qualify": reopen_work,
                })
            );
        }
    }

    #[test]
    fn named_successor_does_not_repeat_context_selection_in_one_snapshot() {
        let mut measured = Vec::new();
        for prior in [1usize, 8] {
            let root = tempfile::tempdir().unwrap();
            let (mut engine, watcher) = admitted_history(root.path(), prior);
            let acquisition_id = "context-reuse-current";
            assert!(
                engine
                    .store
                    .local_successor_acquisition(acquisition_id)
                    .unwrap()
                    .is_none()
            );
            let before = engine
                .store
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                .unwrap();
            assert_eq!(before.reports.len(), prior);
            let intakes_before = engine
                .store
                .provider_intakes_bounded(100, None)
                .unwrap()
                .len();
            let selector_before = CONTEXT_SELECTOR_CALLS.with(std::cell::Cell::get);
            let hashes_before = MEMO_BODY_BYTES_HASHED.with(std::cell::Cell::get);
            let artifact = engine
                .diagnostic_acquire_successor_local(&watcher, acquisition_id)
                .expect("actual named acquire/collect_internal path");
            let selector_calls =
                CONTEXT_SELECTOR_CALLS.with(std::cell::Cell::get) - selector_before;
            let hashed_bytes = MEMO_BODY_BYTES_HASHED.with(std::cell::Cell::get) - hashes_before;

            let SupportedDiagnosticExecution::V2(value) = &artifact else {
                panic!("native v2 artifact");
            };
            assert_eq!(
                value.inputs.selection_rule.id,
                "nq.deliberate_successor_single_admitted_report"
            );
            assert_eq!(value.inputs.selected.len(), 1);
            assert_eq!(value.inputs.admitted.len(), 1);
            assert_eq!(
                value.outcome.condition,
                DiagnosticConditionV1::ExplicitlyAbsent
            );
            let acquisition = engine
                .store
                .local_successor_acquisition(acquisition_id)
                .unwrap()
                .unwrap();
            let current = engine
                .store
                .admitted_collection_for_run(&acquisition.run_id)
                .unwrap()
                .unwrap();
            assert_eq!(current.report_sequence, i64::try_from(prior + 1).unwrap());
            let after = engine
                .store
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                .unwrap();
            assert_eq!(
                after.reports.len(),
                prior + 1,
                "complete retained source is unchanged"
            );
            assert_eq!(after.reports.last().unwrap().report_id, current.report_id);
            assert_eq!(
                engine
                    .store
                    .provider_intakes_bounded(100, None)
                    .unwrap()
                    .len(),
                intakes_before + 1
            );
            assert_eq!(
                successor_phases(&engine.config, acquisition_id),
                vec!["provider_invocation_started", "provider_intake_completed"]
            );

            let replay = engine
                .diagnostic_replay_local_successor(&watcher, acquisition_id)
                .unwrap();
            assert_eq!(
                artifact.canonical_bytes().unwrap(),
                replay.canonical_bytes().unwrap()
            );
            let repeat = engine
                .diagnostic_acquire_successor_local(&watcher, acquisition_id)
                .unwrap();
            assert_eq!(
                artifact.canonical_bytes().unwrap(),
                repeat.canonical_bytes().unwrap()
            );
            assert_eq!(
                engine
                    .store
                    .provider_intakes_bounded(100, None)
                    .unwrap()
                    .len(),
                intakes_before + 1,
                "the named occurrence replays without another provider invocation"
            );
            validate_semantic_history(&engine.store)
                .expect("full authority/fence/watermark/citation/artifact correspondence");
            println!(
                "successor_context prior_rows={prior} committed_rows={} selector_calls={selector_calls} canonical_bind_bytes={hashed_bytes}",
                prior + 1
            );
            measured.push((prior, selector_calls));
        }
        // There are two distinct immutable sources: pre-dispatch history N,
        // and the guarded post-insertion source N+1. The latter's witness
        // check and evaluator must share one context selection, not visit it
        // independently. This budget is on the real public acquisition path.
        for (prior, selector_calls) in measured {
            assert!(
                selector_calls <= prior + (prior + 1),
                "named successor must select one guarded snapshot once: prior_rows={prior}, selector_calls={selector_calls}, maximum={}",
                prior + (prior + 1)
            );
        }
    }

    #[test]
    fn named_successor_full_context_keeps_invalid_older_source_refusal_with_healthy_current() {
        let root = tempfile::tempdir().unwrap();
        let (mut engine, watcher) = admitted_history(root.path(), 1);
        engine
            .diagnostic_acquire_successor_local(&watcher, "context-invalid-control")
            .unwrap();
        let profile = resolve(&watcher).unwrap();
        let digest = profile.descriptor().digest().unwrap();
        let mut snapshot = engine
            .store
            .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
            .unwrap();
        assert_eq!(snapshot.reports.len(), 2);
        let current = snapshot.reports.last().unwrap();
        assert_eq!(current.report_status, "complete");
        let current_id = current.report_id.clone();
        require_successor_diagnostic_snapshot(&snapshot, &watcher, digest.as_str(), &current_id)
            .expect("the real healthy successor has a prior witness and exact current input");
        // This is a negative source-vector fixture, not a passing Store. Only
        // the old canonical source is substituted; the real newest report and
        // all stored source/authority/fence records remain untouched.
        snapshot.reports[0].canonical_json = b"{ }".to_vec();
        let before = RECONSTRUCTIONS.with(std::cell::Cell::get);
        let witness_error = require_successor_diagnostic_snapshot(
            &snapshot,
            &watcher,
            digest.as_str(),
            &current_id,
        )
        .err()
        .expect("older invalid context still refuses the witness selection");
        let evaluation_error = prepare_instance_evaluations(
            &watcher,
            profile,
            None,
            &snapshot,
            &[],
            engine
                .require_evaluator_identity()
                .unwrap()
                .artifact_digest()
                .as_str(),
            EvaluationReportSelection::ExactCurrent(&current_id),
        )
        .err()
        .expect("ExactCurrent does not narrow full context validation");
        assert!(
            witness_error.to_string().contains("not canonical"),
            "{witness_error}"
        );
        assert!(
            evaluation_error.to_string().contains("not canonical"),
            "{evaluation_error}"
        );
        assert_eq!(
            RECONSTRUCTIONS.with(std::cell::Cell::get),
            before,
            "invalid context refuses before reconstructing the healthy current report"
        );
        validate_semantic_history(&engine.store)
            .expect("negative source copy never changes stored history");
    }

    #[test]
    fn named_successor_still_requires_prior_matching_history_before_dispatch() {
        let root = tempfile::tempdir().unwrap();
        let (mut engine, watcher, _) = admitted_host_diagnostic_fixture(
            root.path(),
            "context-missing-prior",
            b"context-missing-prior-evaluator",
        )
        .expect("the existing admitted helper fixture must execute");
        let error = engine
            .diagnostic_acquire_successor_local(&watcher, "context-no-prior")
            .err()
            .expect("a named successor needs a retained matching predecessor");
        assert!(matches!(error, EngineError::DiagnosticUnsupported(message)
            if message.contains("requires prior matching history")));
        assert!(
            engine
                .store
                .local_successor_acquisition("context-no-prior")
                .unwrap()
                .is_none()
        );
        assert!(
            engine
                .store
                .provider_intakes_bounded(10, None)
                .unwrap()
                .is_empty()
        );
        assert!(
            engine
                .store
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                .unwrap()
                .reports
                .is_empty()
        );
    }
}
