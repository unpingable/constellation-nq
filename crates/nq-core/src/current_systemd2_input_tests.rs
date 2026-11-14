// A real ordinary v2 helper consumer, not a descriptor-name eligibility test.
// Only the healthy no-finding case requires one body. An open finding may
// additionally require its older citation; full preparation retains its law.
mod current_systemd2_input {
    use super::*;

    fn systemd2_testimony(
        watcher: &WatcherConfig,
        observed_at: DateTime<Utc>,
        present: bool,
        failed: bool,
    ) -> nq_protocol::EvidenceReport {
        let mut report = testimony(
            watcher,
            &nq_profiles::systemd_unit_v2::MODULE,
            observed_at,
            present,
            failed,
        );
        if failed {
            report.errors[0].code = nq_protocol::ErrorCode::new("query_timeout").unwrap();
        }
        nq_protocol::validate_report(&report).unwrap();
        report
    }

    #[test]
    fn systemd2_ordinary_freshness_materializes_only_current_source_as_history_grows() {
        let root = tempfile::tempdir().unwrap();
        let profile = &nq_profiles::systemd_unit_v2::MODULE;
        let (mut engine, watcher, _) = live_fixture_for_profile(root.path(), profile, false);
        assert_eq!(watcher.profile.version, 2);
        assert_eq!(
            watcher.scope.value["schema"],
            nq_profiles::systemd_unit_v2::SCOPE_SCHEMA
        );
        let mut collected = 0;
        let mut measured = Vec::new();
        for retained in [1usize, 8] {
            while collected < retained {
                let outcome = engine.collect(&watcher).expect("actual admitted v2 helper");
                assert!(outcome.is_success());
                collected += 1;
            }
            let before = engine.store.latest_evaluation_sequence().unwrap();
            PREPARED_SOURCE_ROWS_MATERIALIZED.with(|count| count.set(0));
            PREPARED_SOURCE_BYTES_MATERIALIZED.with(|count| count.set(0));
            assert_eq!(engine.freshness_sweep(&watcher).unwrap(), 1);
            let source_rows = PREPARED_SOURCE_ROWS_MATERIALIZED.with(std::cell::Cell::get);
            let source_bytes = PREPARED_SOURCE_BYTES_MATERIALIZED.with(std::cell::Cell::get);
            let full = engine
                .store
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                .unwrap();
            assert_eq!(
                full.reports.len(),
                retained,
                "complete Store history remains available"
            );
            let newest = full.reports.last().unwrap();
            let newest_bytes = newest.canonical_json.len();
            assert!(newest_bytes > 0);
            assert_eq!(newest.report_sequence, i64::try_from(retained).unwrap());
            let latest = engine.store.latest_evaluation_sequence().unwrap();
            assert_eq!(latest, before + 1);
            let (_, envelope, _) = validate_single_evaluation(&engine.store, latest).unwrap();
            assert_eq!(envelope.result.state, DetectorState::ExplicitlyAbsent);
            assert!(envelope.result.refusal.is_none());
            assert_eq!(
                envelope.watermark.max_report_sequence,
                u64::try_from(retained).unwrap()
            );
            assert_eq!(envelope.result.evidence.len(), 1);
            assert_eq!(envelope.result.evidence[0].report_id, newest.report_id);
            assert_eq!(
                envelope.result.evidence[0].report_digest,
                newest.semantic_digest
            );
            assert!(engine.store.finding_snapshots().unwrap().is_empty());
            assert_eq!(
                envelope.profile.profile_semantic_id,
                profile_semantic_id(profile.descriptor()).unwrap()
            );
            validate_semantic_history(&engine.store)
                .expect("full source and canonical evaluation correspondence");
            println!(
                "systemd2_current retained={retained} source_rows={source_rows} source_bytes={source_bytes} newest_bytes={newest_bytes}"
            );
            measured.push((retained, source_rows, source_bytes, newest_bytes));
        }
        // All real collection, current-result and full-history checks above
        // finish before the work budget. Baseline v2 materializes eight rows.
        for (retained, rows, bytes, newest_bytes) in measured {
            assert_eq!(
                rows, 1,
                "ordinary systemd v2 must materialize only current support: retained={retained}"
            );
            assert_eq!(
                bytes, newest_bytes,
                "healthy v2 has no older finding citation to fetch"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn systemd2_failed_head_holds_prior_citation_and_partial_is_profile_refused() {
        let root = tempfile::tempdir().unwrap();
        let profile = &nq_profiles::systemd_unit_v2::MODULE;
        let (mut engine, watcher, template) = live_fixture_for_profile(root.path(), profile, true);
        assert!(engine.collect(&watcher).unwrap().is_success());
        let before = engine.store.finding_snapshots().unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].condition_state, "present");
        let failed = systemd2_testimony(&watcher, Utc::now(), false, true);
        fs::write(&template, canonical(&failed).unwrap().as_bytes()).unwrap();
        let outcome = engine
            .collect(&watcher)
            .expect("real failed testimony is admitted");
        let CollectionResult::Admitted {
            report_status,
            evaluations,
            ..
        } = &outcome.result
        else {
            panic!("failed v2 testimony must remain admitted evidence: {outcome:?}");
        };
        assert_eq!(report_status, "failed");
        let [evaluation] = evaluations.as_slice() else {
            panic!("one v2 detector");
        };
        assert_eq!(evaluation.result.state, DetectorState::CannotEvaluate);
        let GovernedRefusalOrigin::Profile(refusal) =
            &evaluation.result.refusal.as_ref().unwrap().origin
        else {
            panic!("the compiled v2 owner retains its refusal");
        };
        assert_eq!(
            refusal
                .refusal
                .details
                .get("failure_code")
                .map(String::as_str),
            Some("query_timeout")
        );
        assert_eq!(
            refusal.refusal.details.get("reason").map(String::as_str),
            Some("incomplete_systemd_unit_coverage")
        );
        let after = engine.store.finding_snapshots().unwrap();
        assert_eq!(after[0].finding_id, before[0].finding_id);
        assert_eq!(after[0].condition_state, "present");
        assert_eq!(
            after[0].evidence_json, before[0].evidence_json,
            "unknown retains exact earlier citation"
        );
        let reports = engine
            .store
            .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
            .unwrap();
        assert_eq!(reports.reports.len(), 2);
        assert_eq!(reports.reports.last().unwrap().report_status, "failed");
        assert_eq!(evaluation.watermark.max_report_sequence, 2);
        let evaluation_sequence = engine.store.latest_evaluation_sequence().unwrap();

        // Partial is protocol-valid testimony, but v2 does not admit partial
        // unit coverage. Exercise the actual refusal before Store admission;
        // never manufacture a partial DetectorReport as admitted evidence.
        let mut partial = systemd2_testimony(&watcher, Utc::now(), false, false);
        partial.status = nq_protocol::ReportStatus::Partial;
        partial.coverage[0].state = nq_protocol::CoverageState::Partial;
        partial.errors = failed.errors.clone();
        nq_protocol::validate_report(&partial).expect("valid partial protocol testimony");
        fs::write(&template, canonical(&partial).unwrap().as_bytes()).unwrap();
        let rejected = engine
            .collect(&watcher)
            .expect("ordinary v2 partial refusal is persisted");
        let CollectionResult::Rejected { refusal } = &rejected.result else {
            panic!("partial v2 testimony must be profile-refused: {rejected:?}");
        };
        let GovernedRefusalOrigin::Profile(refusal) = &refusal.origin else {
            panic!("profile boundary");
        };
        assert_eq!(refusal.refusal.profile.version, 2);
        assert_eq!(
            refusal.refusal.code,
            nq_profiles::ProfileRefusalCode::InconsistentReport
        );
        assert_eq!(
            engine.store.latest_evaluation_sequence().unwrap(),
            evaluation_sequence
        );
        assert_eq!(
            engine
                .store
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                .unwrap()
                .reports,
            reports.reports
        );
        assert_eq!(engine.store.finding_snapshots().unwrap(), after);
        let statuses = engine.store.status_snapshots().unwrap();
        let status = statuses
            .iter()
            .find(|row| row.component_kind == "instance" && row.component_id == watcher.instance_id)
            .unwrap();
        assert_eq!(status.state, "failed");
        assert_eq!(status.code, "report_rejected");
        assert_eq!(
            decode_collection_outcome(status.detail_json.as_bytes()).unwrap(),
            rejected
        );
        validate_semantic_history(&engine.store)
            .expect("failed and rejected custody retain exact semantic history");
    }

    #[test]
    fn systemd2_full_and_newest_inputs_have_identical_complete_fixed_clock_results() {
        let now = parse_timestamp("2026-11-14T02:00:00.000Z").unwrap();
        let profile = &nq_profiles::systemd_unit_v2::MODULE;
        let watcher = question(Path::new("/fixture"), profile);
        let older = occurrence(
            &watcher,
            profile,
            &systemd2_testimony(&watcher, now - Duration::seconds(1), false, false),
            1,
        );
        for (case, age, present, failed, expected) in [
            ("present", 1, true, false, DetectorState::Present),
            ("absent", 0, false, false, DetectorState::ExplicitlyAbsent),
            (
                "reliance_edge",
                60,
                false,
                false,
                DetectorState::ExplicitlyAbsent,
            ),
            ("stale", 61, false, false, DetectorState::CannotEvaluate),
            ("future", -1, false, false, DetectorState::CannotEvaluate),
            ("failed", 1, false, true, DetectorState::CannotEvaluate),
        ] {
            let latest = occurrence(
                &watcher,
                profile,
                &systemd2_testimony(&watcher, now - Duration::seconds(age), present, failed),
                2,
            );
            // Reversed input order makes the sequence, not slice position,
            // select the newest admitted occurrence, including failed/stale.
            let reports = [latest.clone(), older.clone()];
            let full = DetectorInput {
                instance_id: &watcher.instance_id,
                evaluated_at: now,
                watermark: EvidenceWatermark(2),
                reports: &reports,
                threshold_policy: None,
            };
            let newest = DetectorInput {
                reports: std::slice::from_ref(&latest),
                ..full
            };
            let detector = profile.detectors()[0];
            let result = detector.evaluate(&full);
            assert_eq!(result.state, expected, "v2 {case}");
            assert_eq!(
                result,
                detector.evaluate(&newest),
                "complete v2 DetectorResult parity: {case}"
            );
        }
    }
}
