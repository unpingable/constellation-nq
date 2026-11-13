// Included inside engine.rs's existing tests module. This fixture exercises the
// real ordinary preparation consumer; it deliberately keeps the complete Store
// source and matching indices. It claims no Store snapshot or whole-operation
// resource bound.
mod current_report_preparation {
    use super::*;

    const MACHINE: &str = "0123456789abcdef0123456789abcdef";

    fn audited_profiles() -> [&'static dyn ProfileModule; 3] {
        [
            &nq_profiles::host_io::MODULE,
            &nq_profiles::host_memory::MODULE,
            &nq_profiles::systemd_unit_v3::MODULE,
        ]
    }

    fn question(root: &Path, profile: &'static dyn ProfileModule) -> WatcherConfig {
        let mut watcher = holes_engine_config(&root.join("nq.db")).watchers.remove(0);
        let descriptor = profile.descriptor();
        watcher.instance_id = format!("current-report-{}", Uuid::new_v4());
        watcher.profile = ProfileSelection {
            id: descriptor.profile.id.clone(),
            version: descriptor.profile.version,
        };
        let (kind, schema, subject, value) = match descriptor.profile.id.as_str() {
            nq_profiles::host_io::PROFILE_ID => (
                nq_profiles::host_io::SCOPE_KIND,
                nq_profiles::host_io::SCOPE_SCHEMA,
                nq_profiles::host_io::subject_for(MACHINE),
                json!({"machine_id": MACHINE}),
            ),
            nq_profiles::host_memory::PROFILE_ID => (
                nq_profiles::host_memory::SCOPE_KIND,
                nq_profiles::host_memory::SCOPE_SCHEMA,
                nq_profiles::host_memory::subject_for(MACHINE),
                json!({"machine_id": MACHINE}),
            ),
            nq_profiles::systemd_unit_v3::PROFILE_ID => (
                nq_profiles::systemd_unit_v3::SCOPE_KIND,
                nq_profiles::systemd_unit_v3::SCOPE_SCHEMA,
                nq_profiles::systemd_unit_v3::subject_for(MACHINE, "cron.service"),
                json!({"machine_id": MACHINE, "unit_name": "cron.service"}),
            ),
            other => panic!("unaudited fixture profile {other}"),
        };
        watcher.subject = subject;
        watcher.scope = ScopeConfig {
            kind: kind.to_owned(),
            value,
        };
        watcher.scope.value["schema"] = json!(schema);
        watcher.vantage = VantageConfig {
            kind: "local".to_owned(),
            value: json!({}),
        };
        watcher.capability_ceiling = descriptor
            .capabilities
            .iter()
            .map(|capability| capability.name.clone())
            .collect();
        watcher.threshold_policy = None;
        watcher
    }

    fn testimony(
        watcher: &WatcherConfig,
        profile: &'static dyn ProfileModule,
        observed_at: DateTime<Utc>,
        present: bool,
        failed: bool,
    ) -> nq_protocol::EvidenceReport {
        let descriptor = profile.descriptor();
        let capabilities = &watcher.capability_ceiling;
        let systemd = descriptor.profile.id == nq_profiles::systemd_unit_v3::PROFILE_ID;
        let io = descriptor.profile.id == nq_profiles::host_io::PROFILE_ID;
        let coverage = descriptor.coverage[0].name.clone();
        let mut payload = if systemd {
            json!({
                "machine_id": MACHINE, "unit_name": "cron.service", "load_state": "loaded",
                "active_state": if present { "failed" } else { "active" },
                "sub_state": if present { "failed" } else { "running" },
                "boot_id": "7e3e2a67-f95e-437a-b6c6-d2bf99d44e0c"
            })
        } else {
            let pressure = if present { 3_000 } else { 0 };
            let line = json!({"avg10_centipercent": 0, "avg60_centipercent": pressure,
                "avg300_centipercent": 0, "total_microseconds": 100});
            json!({"machine_id": MACHINE, "boot_age_seconds": 3_600,
                "some": line, "full": line})
        };
        payload["evidence_basis"] = json!({
            "scope": watcher.scope, "vantage": watcher.vantage,
            "access_path": if systemd { "systemd_dbus" } else { "procfs_pressure" },
            "basis": if systemd { "manager_snapshot" } else { "kernel_snapshot" },
            "regime": "normal", "capabilities_used": capabilities
        });
        let observations = if failed {
            Vec::new()
        } else {
            vec![json!({"ordinal": 0,
                "kind": if systemd { "systemd_unit_state_snapshot" } else if io {
                    "io_pressure_snapshot"
                } else { "memory_pressure_snapshot" },
                "subject": watcher.subject, "observed_at": observed_at, "payload": payload})]
        };
        let errors = if failed {
            vec![json!({"code": "backend_failed", "severity": "error",
                "message": "bounded fixture acquisition failed", "retriable": true})]
        } else {
            Vec::new()
        };
        let report: nq_protocol::EvidenceReport = serde_json::from_value(json!({
            "schema": nq_protocol::EVIDENCE_REPORT_SCHEMA,
            "profile": {"id": descriptor.profile.id,
                "version": descriptor.profile.version.to_string(),
                "digest": descriptor.digest().unwrap().as_str()},
            "binding": {"subject": watcher.subject, "scope": watcher.scope,
                "vantage": watcher.vantage},
            "observed_at": observed_at, "status": if failed { "failed" } else { "complete" },
            "coverage": [{"kind": coverage, "state": if failed { "unavailable" } else { "complete" }}],
            "observations": observations, "errors": errors, "used_capabilities": capabilities,
            "backend": {"implementation": {"name": "current-report-fixture", "version": "1"}, "tools": []}
        })).unwrap();
        nq_protocol::validate_report(&report).expect("real protocol report");
        report
    }

    fn occurrence(
        watcher: &WatcherConfig,
        profile: &'static dyn ProfileModule,
        report: &nq_protocol::EvidenceReport,
        sequence: u64,
    ) -> DetectorReport {
        let context = ValidationContext {
            instance_id: watcher.instance_id.clone(),
            request_subject: watcher.subject.clone(),
            scope: ScopeGrant {
                kind: watcher.scope.kind.clone(),
                value: watcher.scope.value.clone(),
            },
            vantage: VantageGrant {
                kind: watcher.vantage.kind.clone(),
                value: watcher.vantage.value.clone(),
            },
            granted_capabilities: watcher.capability_ceiling.clone(),
            received_at: report.observed_at + Duration::seconds(1),
            max_observations: 1,
            max_future_skew: Duration::seconds(5),
        };
        let normalized = ProfileReportInput::from_protocol_with_digest(report).unwrap();
        DetectorReport {
            report_id: format!("report:{}:{sequence}", watcher.instance_id),
            report_sequence: sequence,
            report: profile
                .validate(&context, &normalized)
                .expect("actual compiled profile admits fixture"),
        }
    }

    // Reuse the existing helper/admission/ordinary-collection path. Only the
    // public helper testimony changes; no direct SQL or manufactured admissions.
    fn live_fixture(root: &Path, present: bool) -> (CollectionEngine, WatcherConfig, PathBuf) {
        let profile = &nq_profiles::host_io::MODULE;
        let (mut config, original, _) = host_diagnostic_fixture(root);
        let mut watcher = question(root, profile);
        watcher.command = original.command;
        let template = root.join("current-report.json");
        fs::write(
            &template,
            canonical(&testimony(&watcher, profile, Utc::now(), present, false))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        watcher.command.env = BTreeMap::from([(
            "NQ_CURRENT_REPORT_TEMPLATE".to_owned(),
            template.to_string_lossy().into_owned(),
        )]);
        fs::write(&watcher.command.args[0], r#"import datetime, json, os, sys
request = json.load(sys.stdin)
echo = dict(request)
del echo["schema"]
with open(os.environ["NQ_CURRENT_REPORT_TEMPLATE"], encoding="utf-8") as source:
    report = json.load(source)
observed = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
report.update(profile=request["profile"], binding=request["binding"], observed_at=observed)
for observation in report["observations"]:
    observation["observed_at"] = observed
json.dump({"schema":"nq.helper.response.v1", "echo":echo, "outcome":{"kind":"report", "report":report}}, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
"#).unwrap();
        config.watchers = vec![watcher.clone()];
        let mut store = Store::initialize_with_capacity(
            &config.database_path,
            config.retention.horizon_seconds,
            config.retention.byte_ceiling,
            config.retention.reserve_bytes,
            config.retention.auxiliary_bytes,
        )
        .unwrap();
        append_profile_descriptor(&mut store, profile).unwrap();
        store
            .append_genesis(&GenesisInput {
                genesis_id: format!("genesis:{}", watcher.instance_id),
                legacy_manifest_digest: None,
                created_at: timestamp(Utc::now()),
                detail: canonical(&json!({"fixture":"current-report"})).unwrap(),
            })
            .unwrap();
        drop(store);
        let mut engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Ok(EvaluatorRuntimeIdentity::for_test(
                nq_protocol::sha256_bytes(b"current-report-fixture"),
            )),
        )
        .unwrap();
        engine
            .watcher_action(&watcher, "admit")
            .expect("native fixture admission must execute");
        (engine, watcher, template)
    }

    fn evict_own_reports(instance_id: &str) {
        let mut memo = admitted_report_memo().lock().unwrap();
        let keys: Vec<_> = memo
            .entries
            .iter()
            .filter(|(_, entry)| entry.row.instance_id == instance_id)
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            let removed = memo.entries.remove(&key).unwrap();
            memo.bytes = memo.bytes.saturating_sub(removed.weight);
        }
    }

    #[test]
    fn audited_current_profile_preparation_retains_only_newest_detector_report() {
        for count in [1, 64] {
            let root = tempfile::tempdir().unwrap();
            let (mut engine, watcher, _) = live_fixture(root.path(), false);
            let profile = resolve(&watcher).unwrap();
            for _ in 0..count {
                assert!(engine.collect(&watcher).unwrap().is_success());
            }
            evict_own_reports(&watcher.instance_id);
            let before = RECONSTRUCTIONS.with(std::cell::Cell::get);
            let (source, prepared) =
                PreparedHistoricalReports::prepare(&mut engine.store, &watcher, profile).unwrap();
            let validations = RECONSTRUCTIONS.with(std::cell::Cell::get) - before;
            assert_eq!(
                validations, count,
                "cold preparation must retain every original profile validation"
            );
            assert_eq!(
                source.snapshot().reports.len(),
                count,
                "complete source custody is preserved"
            );
            assert_eq!(
                prepared.matching_indices,
                (0..count).collect::<Vec<_>>(),
                "finding/context membership is preserved"
            );
            let latest = source.snapshot().reports.last().unwrap();
            println!(
                "current_report_preparation source_rows={count} profile_validations={validations} matching_rows={} retained_detector_reports={}",
                prepared.matching_indices.len(),
                prepared.reports.len()
            );
            assert_eq!(prepared.reports.last().unwrap().report_id, latest.report_id);
            assert_eq!(
                prepared.reports.len(),
                1,
                "audited current-only detector preparation must not retain history-sized report copies"
            );
        }
    }

    #[test]
    fn audited_full_and_newest_inputs_have_identical_fixed_clock_results() {
        let now = parse_timestamp("2026-11-13T12:00:00.000Z").unwrap();
        for profile in audited_profiles() {
            let watcher = question(Path::new("/fixture"), profile);
            let older = occurrence(
                &watcher,
                profile,
                &testimony(&watcher, profile, now - Duration::seconds(1), false, false),
                1,
            );
            for (case, age, present, failed, expected) in [
                ("present", 1, true, false, DetectorState::Present),
                ("absent", 1, false, false, DetectorState::ExplicitlyAbsent),
                ("failed", 1, false, true, DetectorState::CannotEvaluate),
                ("stale", 121, false, false, DetectorState::CannotEvaluate),
                ("future", -1, false, false, DetectorState::CannotEvaluate),
            ] {
                let latest = occurrence(
                    &watcher,
                    profile,
                    &testimony(
                        &watcher,
                        profile,
                        now - Duration::seconds(age),
                        present,
                        failed,
                    ),
                    2,
                );
                // Newest first deliberately prevents accidental slice-order authority.
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
                let full_result = detector.evaluate(&full);
                assert_eq!(
                    full_result.state,
                    expected,
                    "{} {case}",
                    profile.descriptor().profile.id
                );
                assert_eq!(
                    full_result,
                    detector.evaluate(&newest),
                    "complete DetectorResult parity for {} {case}",
                    profile.descriptor().profile.id
                );
            }
        }
    }

    #[test]
    fn audited_unknown_keeps_the_open_conditions_older_citation() {
        let root = tempfile::tempdir().unwrap();
        let (mut engine, watcher, template) = live_fixture(root.path(), true);
        assert!(engine.collect(&watcher).unwrap().is_success());
        let before = engine.store.finding_snapshots().unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].condition_state, "present");
        fs::write(
            template,
            canonical(&testimony(
                &watcher,
                resolve(&watcher).unwrap(),
                Utc::now(),
                false,
                true,
            ))
            .unwrap()
            .as_bytes(),
        )
        .unwrap();
        let outcome = engine.collect(&watcher).unwrap();
        let CollectionResult::Admitted { evaluations, .. } = outcome.result else {
            panic!("failed testimony is admitted evidence")
        };
        assert_eq!(evaluations[0].result.state, DetectorState::CannotEvaluate);
        let after = engine.store.finding_snapshots().unwrap();
        assert_eq!(after[0].condition_state, "present");
        assert_eq!(after[0].finding_id, before[0].finding_id);
        assert_eq!(
            after[0].evidence_json, before[0].evidence_json,
            "unknown re-cites the retained decision"
        );
        validate_semantic_history(&engine.store)
            .expect("unknown preserves exact evaluation/finding history");
    }

    #[test]
    fn audited_cold_preparation_still_refuses_an_invalid_older_profile_report() {
        let profile = &nq_profiles::host_io::MODULE;
        let watcher = question(Path::new("/fixture"), profile);
        let now = parse_timestamp("2026-11-13T12:00:00.000Z").unwrap();
        let mut rows: Vec<_> = (1..=2)
            .map(|sequence| {
                let report = testimony(&watcher, profile, now - Duration::seconds(1), false, false);
                let admitted = occurrence(&watcher, profile, &report, sequence);
                nq_store::AdmittedReportRow {
                    report_sequence: i64::try_from(sequence).unwrap(),
                    report_id: admitted.report_id,
                    instance_id: watcher.instance_id.clone(),
                    profile_id: watcher.profile.id.clone(),
                    profile_version: watcher.profile.version.to_string(),
                    profile_digest: profile.descriptor().digest().unwrap().as_str().to_owned(),
                    observed_at: timestamp(report.observed_at),
                    received_at: timestamp(now),
                    report_status: "complete".to_owned(),
                    canonical_json: canonical(&report).unwrap().as_bytes().to_vec(),
                    semantic_digest: admitted.report.report_digest,
                }
            })
            .collect();
        // Keep canonical/protocol/context validity and an exact source digest;
        // only the old profile payload disagrees with its enrolled machine.
        let mut older: nq_protocol::EvidenceReport =
            serde_json::from_slice(&rows[0].canonical_json).unwrap();
        older.observations[0].payload["machine_id"] = json!("ffffffffffffffffffffffffffffffff");
        nq_protocol::validate_report(&older).unwrap();
        let document = canonical(&older).unwrap();
        rows[0].semantic_digest = document.digest().to_owned();
        rows[0].canonical_json = document.as_bytes().to_vec();
        let snapshot = EvidenceSnapshot {
            watermarks: Vec::new(),
            reports: rows,
            expired_citations: Vec::new(),
        };
        let error = prepare_instance_evaluations(
            &watcher,
            profile,
            None,
            &snapshot,
            &[],
            nq_protocol::sha256_bytes(b"current-report-fixture").as_str(),
            EvaluationReportSelection::AllMatching,
        )
        .err()
        .expect("an invalid older profile report must still refuse cold preparation");
        assert!(
            error.to_string().contains("no longer validates"),
            "original profile refusal: {error}"
        );
    }
}
