//! Backend-independent store contract.
//!
//! These tests live outside the crate, so they can only use the public store
//! API — never database connections, low-level pragmas, triggers, or raw
//! queries. They fix the
//! *behavioral* contract every backend must satisfy: exact raw custody, admitted
//! evidence that is enumerable and verifiable, append-only identity, admission
//! binding, and a verified backup that round-trips. A future non-SQLite backend
//! is an earned successor only if it passes these in full.

use nq_protocol::Sha256Digest;
use nq_store::{
    AdmissionIdentity, AdmissionInput, AdmittedCollectionCompletion, BindingEventInput,
    BindingMaterializationInput, CanonicalDocument, CollectionInput, DiagnosticArtifactByteState,
    DiagnosticArtifactImportDisposition, DiagnosticArtifactImportInput, DiagnosticArtifactLookup,
    DiagnosticArtifactOrigin, DiagnosticArtifactSchemaSupport, ProfileDescriptorInput,
    ProviderIntakeCommit, ProviderIntakeInput, RefusalInput, ReportInput, RunInput,
    RunResultStatusInput, StatusEventInput, Store, StoreError, SubmissionDisposition,
    SubmissionInput, UnavailableDiagnosticArtifactImportInput, detector_suite_identity_digest,
};
use serde_json::{Value, json};

const TS: &str = "2026-07-16T12:00:00.000Z";
const PROFILE: &str = "contract.fixture";
const INSTANCE: &str = "contract-instance";

#[allow(clippy::needless_pass_by_value)]
fn doc(value: Value) -> CanonicalDocument {
    CanonicalDocument::from_serializable(&value).expect("canonical document")
}

fn digest(label: &str) -> Sha256Digest {
    nq_protocol::sha256_bytes(label.as_bytes())
}

fn digest_str(label: &str) -> String {
    digest(label).as_str().to_owned()
}

fn seed_descriptor(store: &mut Store) -> String {
    let descriptor = doc(json!({ "profile": PROFILE }));
    let profile_digest = descriptor.digest().to_owned();
    store
        .begin_writer_session()
        .expect("begin writer session")
        .append_profile_descriptor(&ProfileDescriptorInput {
            profile_id: PROFILE.to_owned(),
            profile_version: "1".to_owned(),
            descriptor,
            recorded_at: TS.to_owned(),
        })
        .expect("append descriptor");
    profile_digest
}

fn identity() -> AdmissionIdentity {
    AdmissionIdentity {
        profile_semantic_id: digest("semantic"),
        detector_identity_digest: detector_suite_identity_digest(Vec::<String>::new())
            .expect("empty contract detector suite identity"),
        evaluator_source_digest: digest("source"),
        evaluator_artifact_digest: digest("artifact"),
        helper_artifact_digest: digest("helper"),
        config_digest: digest("config"),
        protocol_version: "1.0".to_owned(),
        target_triple: "x86_64-unknown-linux-gnu".to_owned(),
        artifact_identity_method: "fixture".to_owned(),
        platform_runtime_version: "test".to_owned(),
    }
}

fn admission_input(admission_id: &str, profile_digest: &str) -> AdmissionInput {
    AdmissionInput {
        admission_id: admission_id.to_owned(),
        instance_id: INSTANCE.to_owned(),
        identity: identity(),
        execution_chain: doc(json!({})),
        profile_id: PROFILE.to_owned(),
        profile_version: "1".to_owned(),
        profile_digest: profile_digest.to_owned(),
        capability_grant: doc(json!([])),
        conformance: doc(json!({})),
        lock: doc(json!({})),
        admitted_at: TS.to_owned(),
        operator_identity: doc(json!({})),
    }
}

fn run(suffix: &str, admission_id: Option<&str>, profile_digest: &str) -> RunInput {
    RunInput {
        run_id: format!("run-{suffix}"),
        request_id: format!("req-{suffix}"),
        instance_id: INSTANCE.to_owned(),
        admission_id: admission_id.map(str::to_owned),
        binding_digest: digest_str("binding"),
        checkpoint_contract_digest: digest_str("checkpoint"),
        profile_id: PROFILE.to_owned(),
        profile_version: "1".to_owned(),
        profile_digest: profile_digest.to_owned(),
        carrier: "stdio".to_owned(),
        started_at: TS.to_owned(),
        deadline_at: TS.to_owned(),
        finished_at: TS.to_owned(),
        acquisition_outcome: "response".to_owned(),
        execution_identity: doc(json!({})),
        resource_outcome: doc(json!({
            "schema": "nq.run_resource_outcome.v1",
            "duration_ms": 1,
            "exit_code": 0,
            "hard_limits": {
                "address_space_bytes_per_process": 1,
                "cpu_seconds_per_process": 1,
                "processes_per_execution_uid": 1,
                "open_files_per_process": 1,
                "file_bytes_per_regular_file": 1,
                "core_bytes": 0
            },
            "stdout_bytes_retained": 0,
            "stderr_bytes_retained": 0,
            "stderr_hex": "",
            "outcome": {"outcome": "response"}
        })),
    }
}

fn admitted_report(suffix: &str, profile_digest: &str) -> ReportInput {
    let evidence = nq_protocol::EvidenceReport {
        schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
        profile: nq_protocol::ProfileBinding {
            id: nq_protocol::ProfileId::new(PROFILE).expect("profile id"),
            version: nq_protocol::ProfileVersion::new("1").expect("profile version"),
            digest: Sha256Digest::parse(profile_digest.to_owned()).expect("profile digest"),
        },
        binding: nq_protocol::SubjectBinding {
            subject: nq_protocol::SubjectId::new(format!("contract:{suffix}")).expect("subject"),
            scope: nq_protocol::ScopeBinding {
                kind: nq_protocol::ScopeKind::new("fixture").expect("scope kind"),
                value: json!({"suffix": suffix}),
            },
            vantage: nq_protocol::VantageBinding {
                kind: nq_protocol::VantageKind::new("local").expect("vantage kind"),
                value: json!({}),
            },
        },
        observed_at: chrono::DateTime::parse_from_rfc3339(TS)
            .expect("observed time")
            .with_timezone(&chrono::Utc),
        status: nq_protocol::ReportStatus::Complete,
        coverage: Vec::new(),
        observations: Vec::new(),
        errors: Vec::new(),
        used_capabilities: Vec::new(),
        backend: nq_protocol::BackendProvenance {
            implementation: nq_protocol::BackendIdentity {
                name: nq_protocol::ImplementationName::new("contract-fixture")
                    .expect("implementation"),
                version: Some("1".to_owned()),
                digest: None,
            },
            tools: Vec::new(),
        },
        next_checkpoint: None,
    };
    nq_protocol::validate_report(&evidence).expect("valid evidence report");
    let canonical_report =
        CanonicalDocument::from_serializable(&evidence).expect("canonical evidence report");
    ReportInput {
        report_id: format!("report-{suffix}"),
        instance_id: INSTANCE.to_owned(),
        profile_id: PROFILE.to_owned(),
        profile_version: "1".to_owned(),
        profile_digest: profile_digest.to_owned(),
        observed_at: TS.to_owned(),
        received_at: TS.to_owned(),
        report_status: "complete".to_owned(),
        validated_report: doc(json!({
            "schema": "nq.store_contract.validated_report.v1",
            "instance_id": INSTANCE,
            "report_digest": canonical_report.digest(),
            "profile": {"id": PROFILE, "version": 1},
            "profile_digest": profile_digest,
            "status": "complete",
            "observed_at": TS,
            "received_at": TS,
        })),
        canonical_report,
        next_checkpoint: None,
        admitted_at: TS.to_owned(),
        observations: Vec::new(),
        coverage: Vec::new(),
        errors: Vec::new(),
    }
}

#[allow(clippy::too_many_lines)]
fn provider_collection(
    store: &mut Store,
    mut run: RunInput,
    submission: Option<SubmissionInput>,
) -> CollectionInput {
    let source_admission_id = run.admission_id.clone().expect("bound fixture run");
    let admission = store
        .admission(&source_admission_id)
        .expect("admission query")
        .expect("admission exists");
    CanonicalDocument::from_canonical_bytes(admission.lock_json.clone())
        .expect("source lock canonical")
        .digest()
        .clone_into(&mut run.binding_digest);
    let binding_event_id = uuid::Uuid::new_v4().to_string();
    let operation_id = uuid::Uuid::new_v4().to_string();
    store
        .begin_writer_session()
        .expect("begin writer session")
        .begin_binding_transition(
            &BindingEventInput {
                binding_event_id: binding_event_id.clone(),
                instance_id: run.instance_id.clone(),
                event_kind: "activate".to_owned(),
                admission_id: Some(source_admission_id.clone()),
                binding_digest: run.binding_digest.clone(),
                occurred_at: TS.to_owned(),
                reason_code: Some("store_contract".to_owned()),
                detail: doc(json!({})),
            },
            &BindingMaterializationInput {
                materialization_event_id: uuid::Uuid::new_v4().to_string(),
                operation_id: operation_id.clone(),
                instance_id: run.instance_id.clone(),
                binding_event_id: binding_event_id.clone(),
                phase: "intent".to_owned(),
                occurred_at: TS.to_owned(),
                detail: doc(json!({})),
            },
        )
        .expect("activate provider admission");
    store
        .begin_writer_session()
        .expect("begin writer session")
        .complete_binding_materialization(&BindingMaterializationInput {
            materialization_event_id: uuid::Uuid::new_v4().to_string(),
            operation_id,
            instance_id: run.instance_id.clone(),
            binding_event_id,
            phase: "completed".to_owned(),
            occurred_at: TS.to_owned(),
            detail: doc(json!({})),
        })
        .expect("complete provider binding");
    let provider = store
        .provider_admission_for_source(&source_admission_id)
        .expect("provider admission query")
        .expect("provider admission exists");
    let raw_bytes = submission
        .as_ref()
        .map_or_else(Vec::new, |submission| submission.raw_bytes.clone());
    let received_at = submission.as_ref().map_or_else(
        || run.finished_at.clone(),
        |submission| submission.received_at.clone(),
    );
    let (interpretation_kind, interpretation) = match submission.as_ref() {
        Some(SubmissionInput {
            disposition: SubmissionDisposition::Admitted(report),
            ..
        }) => (
            "candidate_report".to_owned(),
            report.canonical_report.clone(),
        ),
        Some(SubmissionInput {
            disposition: SubmissionDisposition::Rejected { refusal },
            ..
        }) => ("protocol_rejected".to_owned(), refusal.detail.clone()),
        None => ("unavailable".to_owned(), doc(Value::Null)),
    };
    let attempt_id = format!("attempt-{}", run.run_id);
    let provider_admission_id = provider.provider_admission_id;
    let idempotency_key = nq_store::provider_idempotency_key(&provider_admission_id, &attempt_id)
        .expect("provider idempotency identity");
    CollectionInput {
        intake: ProviderIntakeInput {
            intake_id: format!("intake-{}", run.run_id),
            attempt_id,
            idempotency_key,
            request_id: run.request_id.clone(),
            provider_admission_id,
            source_admission_id,
            provider_sequence: None,
            origin_carrier: run.carrier.clone(),
            deadline_at: run.deadline_at.clone(),
            checkpoint_contract_digest: run.checkpoint_contract_digest.clone(),
            execution_identity_digest: Sha256Digest::parse(
                run.execution_identity.digest().to_owned(),
            )
            .expect("execution identity digest"),
            admission_context_digest: Sha256Digest::parse(admission.admission_context_digest)
                .expect("admission context digest"),
            provider_semantic_id: Sha256Digest::parse(provider.provider_semantic_id)
                .expect("provider semantic identity"),
            provider_artifact_digest: Sha256Digest::parse(provider.provider_artifact_digest)
                .expect("provider artifact identity"),
            provider_protocol_identity: provider.provider_protocol_identity,
            provider_config_digest: Sha256Digest::parse(provider.provider_config_digest)
                .expect("provider configuration identity"),
            binding_digest: run.binding_digest.clone(),
            instance_id: run.instance_id.clone(),
            profile_id: run.profile_id.clone(),
            profile_version: run.profile_version.clone(),
            profile_digest: run.profile_digest.clone(),
            profile_semantic_id: Sha256Digest::parse(admission.profile_semantic_id)
                .expect("profile semantic identity"),
            evaluator_artifact_digest: Sha256Digest::parse(admission.evaluator_artifact_digest)
                .expect("evaluator artifact identity"),
            context: doc(json!({"schema": "nq.store_contract.provider_context.v1"})),
            interpretation_kind,
            interpretation,
            native_outcome_kind: run.acquisition_outcome.clone(),
            native_outcome: run.resource_outcome.clone(),
            raw_bytes,
            started_at: run.started_at.clone(),
            finished_at: run.finished_at.clone(),
            received_at,
        },
        run,
        submission,
    }
}

fn committed_receipt(commit: ProviderIntakeCommit<()>) -> nq_store::CollectionReceipt {
    match commit {
        ProviderIntakeCommit::Committed { receipt, .. } => receipt,
        ProviderIntakeCommit::Replayed { .. } => panic!("fresh contract fixture replayed"),
    }
}

fn commit_admitted_fixture(
    store: &mut Store,
    collection: &CollectionInput,
) -> Result<(), StoreError> {
    let run_id = collection.run.run_id.clone();
    let instance_id = collection.run.instance_id.clone();
    let (report_id, report_status) = match &collection
        .submission
        .as_ref()
        .expect("admitted fixture submission")
        .disposition
    {
        SubmissionDisposition::Admitted(report) => {
            (report.report_id.clone(), report.report_status.clone())
        }
        SubmissionDisposition::Rejected { .. } => panic!("admitted fixture disposition"),
    };
    store
        .begin_writer_session()?
        .commit_admitted_collection(collection, |_view, receipt| {
            Ok::<_, StoreError>(AdmittedCollectionCompletion {
                value: (),
                evaluations: Vec::new(),
                diagnostic_artifact: None,
                status: StatusEventInput {
                    status_event_id: format!("status-{run_id}"),
                    component_kind: "instance".to_owned(),
                    component_id: instance_id.clone(),
                    state: "healthy".to_owned(),
                    code: "report_complete".to_owned(),
                    detail: doc(json!({
                        "schema": "nq.collection_outcome.v2",
                        "instance_id": instance_id,
                        "run_id": run_id,
                        "result": {
                            "outcome": "admitted",
                            "report_id": report_id,
                            "report_status": report_status,
                            "semantic_digest": receipt.semantic_digest,
                            "evaluations": [],
                        },
                    })),
                    observed_at: TS.to_owned(),
                },
            })
        })
        .map(|_| ())
}

/// Seed one admitted report and return its identifiers.
fn seed_admitted(store: &mut Store, suffix: &str) -> (String, String, String) {
    let profile_digest = seed_descriptor(store);
    let admission_id = uuid::Uuid::new_v4().to_string();
    store
        .begin_writer_session()
        .expect("begin writer session")
        .append_admission(&admission_input(&admission_id, &profile_digest))
        .expect("append admission");
    let submission_id = format!("submission-{suffix}");
    let collection = provider_collection(
        store,
        run(suffix, Some(&admission_id), &profile_digest),
        Some(SubmissionInput {
            submission_id: submission_id.clone(),
            raw_bytes: format!("raw-{suffix}").into_bytes(),
            received_at: TS.to_owned(),
            protocol_outcome: "valid_report".to_owned(),
            disposition: SubmissionDisposition::Admitted(admitted_report(suffix, &profile_digest)),
        }),
    );
    commit_admitted_fixture(store, &collection).expect("commit admitted collection");
    (submission_id, format!("report-{suffix}"), admission_id)
}

#[test]
fn a_fresh_store_validates_and_holds_no_evidence() {
    let mut store = Store::initialize_in_memory().expect("initialize");
    store.validate().expect("fresh store validates");
    let snapshot = store
        .evidence_snapshot(&[INSTANCE.to_owned()])
        .expect("snapshot");
    assert!(snapshot.reports.is_empty());
}

#[test]
fn rejected_custody_is_byte_exact_and_is_not_a_report() {
    let mut store = Store::initialize_in_memory().expect("initialize");
    let profile_digest = seed_descriptor(&mut store);
    let admission_id = uuid::Uuid::new_v4().to_string();
    store
        .begin_writer_session()
        .expect("begin writer session")
        .append_admission(&admission_input(&admission_id, &profile_digest))
        .expect("append provider admission");
    let raw = b"exact rejected helper bytes".to_vec();
    let collection = provider_collection(
        &mut store,
        run("rej", Some(&admission_id), &profile_digest),
        Some(SubmissionInput {
            submission_id: "submission-rej".to_owned(),
            raw_bytes: raw.clone(),
            received_at: TS.to_owned(),
            protocol_outcome: "rejected".to_owned(),
            disposition: SubmissionDisposition::Rejected {
                refusal: RefusalInput {
                    refusal_id: "refusal-rej".to_owned(),
                    source_kind: "protocol".to_owned(),
                    responsible_instance_id: INSTANCE.to_owned(),
                    boundary: "response_frame".to_owned(),
                    code: "malformed".to_owned(),
                    profile_semantic_id: None,
                    detail: doc(json!({"offset": 7, "reason": "malformed"})),
                    created_at: TS.to_owned(),
                },
            },
        }),
    );
    let result = RunResultStatusInput {
        run_id: collection.run.run_id.clone(),
        status: StatusEventInput {
            status_event_id: "status-rej".to_owned(),
            component_kind: "instance".to_owned(),
            component_id: INSTANCE.to_owned(),
            state: "failed".to_owned(),
            code: "collection_failed".to_owned(),
            detail: doc(json!({"run_id": collection.run.run_id})),
            observed_at: TS.to_owned(),
        },
    };
    let receipt = committed_receipt(
        store
            .begin_writer_session()
            .expect("begin writer session")
            .commit_non_success_collection(&collection, &result)
            .expect("commit rejected collection"),
    );
    assert_eq!(receipt.refusal_id.as_deref(), Some("refusal-rej"));
    assert_eq!(
        store.raw_submission_bytes("submission-rej").expect("query"),
        Some(raw),
        "rejected custody is retained byte-for-byte"
    );
    assert_eq!(
        store
            .report_id_for_submission("submission-rej")
            .expect("query"),
        None,
        "a rejected submission never becomes an admitted report"
    );
    let rows = store.rejected_custody(10).expect("enumerate rejection");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].refusal_id, "refusal-rej");
    assert_eq!(rows[0].code, "malformed");
    assert_eq!(rows[0].detail_json, br#"{"offset":7,"reason":"malformed"}"#);
    assert_eq!(
        store
            .rejected_custody_by_refusal_id("refusal-rej")
            .expect("lookup rejection by stable refusal id"),
        Some(rows[0].clone())
    );
    assert_eq!(
        store
            .rejected_custody_by_refusal_id("refusal-missing")
            .expect("missing refusal lookup is not an error"),
        None
    );
}

#[test]
fn an_admitted_report_is_enumerable_and_verifiable() {
    let mut store = Store::initialize_in_memory().expect("initialize");
    let (submission_id, report_id, _admission_id) = seed_admitted(&mut store, "a");
    assert_eq!(
        store
            .report_id_for_submission(&submission_id)
            .expect("query"),
        Some(report_id.clone())
    );
    let snapshot = store
        .evidence_snapshot(&[INSTANCE.to_owned()])
        .expect("snapshot");
    assert_eq!(snapshot.reports.len(), 1);
    assert_eq!(snapshot.reports[0].report_id, report_id);
    // The persisted admission is authenticable from its own stored bytes.
    let verified = store
        .verify_admitted_snapshot(&report_id)
        .expect("historical admission authenticates");
    assert_eq!(verified.report_id, report_id);
    assert!(!verified.evaluator_artifact_digest.is_empty());
}

#[test]
fn an_admission_identity_is_append_only() {
    let mut store = Store::initialize_in_memory().expect("initialize");
    let profile_digest = seed_descriptor(&mut store);
    store
        .begin_writer_session()
        .expect("begin writer session")
        .append_admission(&admission_input("admission-x", &profile_digest))
        .expect("first admission");
    assert!(
        store
            .begin_writer_session()
            .expect("begin writer session")
            .append_admission(&admission_input("admission-x", &profile_digest))
            .is_err(),
        "an admission identity cannot be reused or overwritten"
    );
}

#[test]
fn an_admitted_report_requires_a_run_bound_to_an_admission() {
    let mut store = Store::initialize_in_memory().expect("initialize");
    let profile_digest = seed_descriptor(&mut store);
    let admission_id = uuid::Uuid::new_v4().to_string();
    store
        .begin_writer_session()
        .expect("begin writer session")
        .append_admission(&admission_input(&admission_id, &profile_digest))
        .expect("append provider admission");
    let mut collection = provider_collection(
        &mut store,
        run("unbound", Some(&admission_id), &profile_digest),
        Some(SubmissionInput {
            submission_id: "submission-unbound".to_owned(),
            raw_bytes: b"raw".to_vec(),
            received_at: TS.to_owned(),
            protocol_outcome: "valid_report".to_owned(),
            disposition: SubmissionDisposition::Admitted(admitted_report(
                "unbound",
                &profile_digest,
            )),
        }),
    );
    collection.run.admission_id = None;
    let error = commit_admitted_fixture(&mut store, &collection)
        .expect_err("an admitted report requires an admission-bound run");
    let _ = error;
}

#[test]
fn a_verified_backup_round_trips_the_evidence() {
    let directory = tempfile::tempdir().expect("temp dir");
    let live = directory.path().join("live.db");
    let backup = directory.path().join("backup.db");
    let (_submission, report_id, _admission) = {
        let mut store = Store::initialize_unqualified_storage(&live).expect("initialize on disk");
        let ids = seed_admitted(&mut store, "b");
        store.backup_verified(&backup).expect("verified backup");
        ids
    };
    // The backup opens, validates, and carries the same admitted evidence,
    // independent of the live database.
    let mut restored = Store::open(&backup).expect("open backup");
    restored.validate().expect("backup validates");
    let snapshot = restored
        .evidence_snapshot(&[INSTANCE.to_owned()])
        .expect("snapshot");
    assert_eq!(snapshot.reports.len(), 1);
    assert_eq!(snapshot.reports[0].report_id, report_id);
}

#[test]
fn diagnostic_artifact_custody_round_trips_without_collapsing_identity_or_availability() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("artifact.db");
    let artifact_id = digest("contract-artifact-identity");
    let artifact = doc(json!({
        "schema": "nq.diagnostic_execution.v1",
        "artifact_id": artifact_id.as_str(),
        "result": "fixture",
    }));
    assert_ne!(artifact_id.as_str(), artifact.digest());
    {
        let mut store =
            Store::initialize_unqualified_storage(&database).expect("initialize artifact store");
        let receipt = store
            .begin_writer_session()
            .expect("begin writer session")
            .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                import_id: "contract-import".to_owned(),
                artifact_id: artifact_id.clone(),
                contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                canonical_bytes: artifact.clone(),
                imported_at: TS.to_owned(),
            })
            .expect("import exact artifact");
        assert_eq!(
            receipt.disposition,
            DiagnosticArtifactImportDisposition::Committed
        );
    }
    let mut reopened = Store::open(&database).expect("reopen artifact store");
    let DiagnosticArtifactLookup::Found(access) = reopened
        .diagnostic_artifact(&artifact_id, &["nq.diagnostic_execution.v1"])
        .expect("lookup exact artifact")
    else {
        panic!("artifact commitment missing after restart");
    };
    assert_eq!(
        access.schema_support,
        DiagnosticArtifactSchemaSupport::Supported
    );
    assert!(matches!(
        access.commitment.origin,
        DiagnosticArtifactOrigin::Imported { import_id, .. }
            if import_id == "contract-import"
    ));
    assert!(matches!(
        access.byte_state,
        DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes }
            if canonical_bytes == artifact
    ));

    let unavailable_id = digest("contract-unavailable-artifact");
    let unavailable_bytes = doc(json!({
        "schema": "nq.future_diagnostic_execution.v2",
        "artifact_id": unavailable_id.as_str(),
    }));
    reopened
        .begin_writer_session()
        .expect("begin writer session")
        .import_unavailable_diagnostic_artifact(&UnavailableDiagnosticArtifactImportInput {
            import_id: "contract-unavailable-import".to_owned(),
            artifact_id: unavailable_id.clone(),
            contract_schema: "nq.future_diagnostic_execution.v2".to_owned(),
            canonical_bytes_sha256: Sha256Digest::parse(unavailable_bytes.digest().to_owned())
                .expect("typed full-byte digest"),
            canonical_bytes_length: u64::try_from(unavailable_bytes.as_bytes().len())
                .expect("fixture length"),
            imported_at: TS.to_owned(),
        })
        .expect("commit unavailable artifact");
    let DiagnosticArtifactLookup::Found(unavailable) = reopened
        .diagnostic_artifact(&unavailable_id, &["nq.diagnostic_execution.v1"])
        .expect("lookup unavailable artifact")
    else {
        panic!("unavailable commitment missing");
    };
    assert!(matches!(
        unavailable.schema_support,
        DiagnosticArtifactSchemaSupport::Unsupported { contract_schema }
            if contract_schema == "nq.future_diagnostic_execution.v2"
    ));
    assert_eq!(
        unavailable.byte_state,
        DiagnosticArtifactByteState::CommittedUnavailable
    );
}
