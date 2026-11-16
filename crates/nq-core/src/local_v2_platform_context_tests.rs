// The producer surface is frozen by the run's admission, while the current
// kernel remains separately observed metadata. This fixture runs real helper
// acquisition and the ordinary history readers; it never edits a stored row.

#[allow(clippy::too_many_lines)]
fn assert_local_v2_platform_drift_roundtrip(mode: &str) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let evaluator_label = b"local-v2-platform-context-evaluator";
    let (mut engine, watcher, mode_path) = admitted_host_diagnostic_fixture(
        directory.path(),
        "local-v2-platform-context",
        evaluator_label,
    )
    .expect("the real helper consumer must run for this regression");
    let original = engine
        .diagnostic_execute(&watcher)
        .expect("initial admitted diagnostic");
    let SupportedDiagnosticExecution::V2(original_v2) = &original else {
        panic!("initial local diagnostic is v2");
    };
    let original_build = original_v2.producer.build.clone();
    let original_id = original.artifact_id().as_digest().clone();
    let original_bytes = original.canonical_bytes().expect("original export");
    let provenance = qualify_diagnostic_admission(&engine.store, &original_id)
        .expect("initial admitted provenance");
    let report_id = provenance
        .judgment
        .expect("initial report judgment")
        .report_id;
    let admission_id = provenance.provider.source_admission_id;
    let admitted = engine
        .store
        .admission(&admission_id)
        .expect("admission lookup")
        .expect("frozen admission");
    assert_eq!(admitted.platform_runtime_version, "test");
    let config = engine.config.clone();
    drop(engine);

    let identity = || {
        EvaluatorRuntimeIdentity::for_test_with_platform_runtime(
            nq_protocol::sha256_bytes(evaluator_label),
            "test-kernel-after-reboot",
        )
    };
    let mut engine = CollectionEngine::open_with_evaluator_identity(&config, Ok(identity()))
        .expect("reopen under another kernel with the same evaluator artifact");
    assert_eq!(
        engine
            .verify_admitted(&report_id)
            .expect("ambient platform drift is recorded, not refused")
            .platform_observations,
        vec![PlatformObservation::RuntimeDrift {
            admitted: "test".to_owned(),
            current: "test-kernel-after-reboot".to_owned(),
        }]
    );
    fs::write(&mode_path, format!("{mode}\n")).expect("select real helper outcome");
    let successor = engine
        .diagnostic_acquire_successor_local(&watcher, "platform-drift-successor")
        .expect("one ordinary successor after ambient platform drift");
    let SupportedDiagnosticExecution::V2(successor_v2) = &successor else {
        panic!("local successor is v2");
    };
    assert_eq!(
        successor_v2.producer.build, original_build,
        "producer.build must use frozen source-admission metadata"
    );
    // Reproduce the old emitter's exact otherwise-valid ambient-kernel build
    // in memory. The durable admission remains unchanged, and even a descriptor
    // matching the currently running evaluator must not replace its context.
    let mut ambient_admission = admitted.clone();
    ambient_admission.platform_runtime_version = "test-kernel-after-reboot".to_owned();
    let ambient_build = local_v2_historical_surface(
        &successor_v2.profile,
        &successor_v2.question,
        &ambient_admission,
    )
    .expect("derive the legacy ambient-kernel descriptor")
    .build;
    assert_ne!(ambient_build, original_build);
    let mut malformed = successor_v2.clone();
    malformed.producer.build = ambient_build;
    malformed.artifact_id = malformed
        .computed_artifact_id()
        .expect("reseal only the in-memory substitution fixture");
    let malformed = SupportedDiagnosticExecution::decode_canonical(
        &malformed
            .canonical_bytes()
            .expect("canonical substituted bytes"),
    )
    .expect("legacy-shaped substitution is structurally valid");
    let run = engine
        .store
        .watcher_run_outcome(successor.run_id().as_str())
        .expect("exact retained successor run lookup")
        .expect("successor run is retained");
    let refusal = match validate_local_v2_provider_correspondence(&engine.store, &malformed, &run) {
        Err(EngineError::Invariant(message)) => message,
        Err(other) => panic!("unexpected legacy-build refusal: {other}"),
        Ok(_) => panic!("ambient-kernel producer.build must not qualify against frozen admission"),
    };
    assert_eq!(
        refusal,
        format!(
            "local v2 diagnostic artifact {} substitutes its exact diagnostic semantic surface: producer.build",
            malformed.artifact_id().as_digest().as_str()
        )
    );
    let successor_id = successor.artifact_id().as_digest().clone();
    let successor_bytes = successor.canonical_bytes().expect("successor export");
    assert_ne!(original_id, successor_id);
    validate_diagnostic_artifact_history(&engine.store)
        .expect("new artifact must not poison global historical validation");
    let retained = engine
        .store
        .admission(&admission_id)
        .expect("admission lookup")
        .expect("same admission remains");
    assert_eq!(
        retained.platform_runtime_version,
        admitted.platform_runtime_version
    );
    assert_eq!(retained.lock_json, admitted.lock_json);
    assert_eq!(
        retained.admission_context_digest,
        admitted.admission_context_digest
    );
    drop(engine);

    let store = Store::open_read_only(&config.database_path).expect("read-only reopen");
    for (id, bytes) in [
        (&original_id, &original_bytes),
        (&successor_id, &successor_bytes),
    ] {
        let inspected = reopen_diagnostic_artifact(&store, id).expect("old/new exact inspection");
        assert_eq!(
            inspected
                .canonical_bytes()
                .expect("old/new canonical export")
                .as_slice(),
            bytes.as_slice()
        );
        let qualified = qualify_diagnostic_admission(&store, id)
            .expect("old/new strict historical qualification after reopen");
        assert_eq!(qualified.provider.source_admission_id, admission_id);
    }
    drop(store);
    let mut reopened = CollectionEngine::open_with_evaluator_identity(&config, Ok(identity()))
        .expect("ordinary writable engine reopen preserves old and new history");
    let later = reopened
        .diagnostic_acquire_successor_local(&watcher, "platform-drift-later")
        .expect("later acquisition remains live after reopen");
    let SupportedDiagnosticExecution::V2(later) = later else {
        panic!("later local successor is v2");
    };
    assert_eq!(later.producer.build, original_build);
    qualify_diagnostic_admission(&reopened.store, &later.artifact_id.0)
        .expect("later artifact also qualifies without changing admission");
}

#[test]
fn local_v2_producer_build_uses_admitted_platform_after_runtime_drift() {
    assert_local_v2_platform_drift_roundtrip("present");
}

#[test]
fn local_v2_producer_build_non_success_uses_admitted_platform_after_runtime_drift() {
    assert_local_v2_platform_drift_roundtrip("no_response");
}
