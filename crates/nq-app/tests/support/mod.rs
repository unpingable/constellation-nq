#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use nq_core::admission::{ADMISSION_SCHEMA, AdmittedProfile, ConformanceReceipt, OperatorIdentity};
use nq_core::engine::{GovernedRefusal, GovernedRefusalOrigin, RunResourceOutcomeV1};
use nq_core::{
    AdmissionLock, AdmissionManager, ExecutionIdentity, ProviderIdentitySchema, ProviderIdentityV1,
    ProviderIntakeContextSchema, ProviderIntakeContextV1, ProviderIntakeRecordV1,
    ProviderIntakeSchema, ProviderKind, ProviderResponseInterpretationV1,
};
use nq_helper_sandbox::ExecutionAccount;
use nq_profiles::profile_semantic_id;
use nq_protocol::{
    Capability, EvidenceReport, HelperRequest, HelperResponse, InstanceId, MonotonicClock,
    MonotonicDeadline, ProfileBinding, ProfileId, ProfileVersion, RequestId, ScopeBinding,
    ScopeKind, Sha256Digest, SubjectBinding, SubjectId, VantageBinding, VantageKind,
};
use nq_runtime_dependency_authority::{
    test_support::RawAuthorityFixture, verify_for_establishment,
};
use nq_store::{
    AdmissionIdentity, AdmissionInput, BindingEventInput, BindingMaterializationInput,
    CanonicalDocument, CollectionInput, ProviderIntakeInput, RunInput, Store,
    SubmissionDisposition, SubmissionInput,
};
use serde_json::json;

fn document(value: &impl serde::Serialize) -> CanonicalDocument {
    CanonicalDocument::from_serializable(value).expect("fixture document canonicalizes")
}

fn timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp is RFC3339")
        .with_timezone(&Utc)
}

/// Provision one test-only Gen4 Store through the same sealed authority and
/// Store-owned transaction surfaces used by production runtime integration.
/// This is intentionally not exposed by the shipped CLI: the bounded Gen4
/// campaign has no production A2 adapter.
#[allow(dead_code)]
pub fn initialize_gen4_test_store(config_path: &Path) {
    let config = nq_core::config::NqConfig::load(config_path).expect("load test configuration");
    if let Some(parent) = config.database_path.parent() {
        fs::create_dir_all(parent).expect("database parent");
    }
    fs::create_dir_all(&config.admissions_dir).expect("admissions directory");
    fs::set_permissions(&config.admissions_dir, fs::Permissions::from_mode(0o700))
        .expect("admissions mode");
    fs::create_dir_all(&config.helper_runtime_dir).expect("helper runtime directory");
    fs::set_permissions(
        &config.helper_runtime_dir,
        fs::Permissions::from_mode(0o711),
    )
    .expect("helper runtime mode");

    let mut store = Store::initialize(&config.database_path).expect("initialize Gen4 test Store");
    {
        let mut session = store
            .begin_writer_session()
            .expect("profile writer session");
        for profile in nq_profiles::all_profiles() {
            nq_core::engine::append_profile_descriptor(&mut session, *profile)
                .expect("compiled profile descriptor");
        }
    }

    let authority = RawAuthorityFixture::fresh_genesis();
    let custody = authority.custody();
    let presented = authority.presented_set();
    let expectations = authority.activation_expectations();
    store
        .with_runtime_authority_writer_session(
            |brand, session| -> Result<(), nq_store::StoreError> {
                let resolved =
                    verify_for_establishment(brand, &custody, &presented, None, &expectations)?;
                session.establish_runtime_dependency_trust_root(&resolved)?;
                Ok(())
            },
        )
        .expect("establish Gen4 test authority");

    let mut session = store.begin_writer_session().expect("status writer session");
    nq_core::engine::record_component_status(
        &mut session,
        "database",
        "local",
        "healthy",
        "initialized",
        &json!({"schema_version": nq_store::SCHEMA_VERSION}),
    )
    .expect("database status");
    nq_core::engine::record_component_status(
        &mut session,
        "profile_catalog",
        "compiled",
        "healthy",
        "catalog_loaded",
        &json!({"profile_count": nq_profiles::all_profiles().len()}),
    )
    .expect("profile catalog status");
}

fn fixture_conformance() -> ConformanceReceipt {
    ConformanceReceipt {
        tool_version: "nq-app-provider-fixture-v1".to_owned(),
        protocol_passed: true,
        protocol_corpus_digest: nq_protocol::sha256_bytes(b"nq-app provider fixture corpus")
            .into_string(),
        protocol_fixtures_checked: 1,
        dry_collection_passed: true,
        dry_report_digest: Some(
            nq_protocol::sha256_bytes(b"nq-app provider fixture dry report").into_string(),
        ),
    }
}

fn fixture_capability_grant(profile_id: &str) -> BTreeSet<String> {
    if profile_id == nq_profiles::host::PROFILE_ID {
        BTreeSet::from(["read_procfs".to_owned()])
    } else {
        BTreeSet::new()
    }
}

fn fixture_execution(suffix: &str) -> ExecutionIdentity {
    ExecutionIdentity {
        execution_account: Some(ExecutionAccount {
            configured: "991".to_owned(),
            name: "nq-app-fixture".to_owned(),
            uid: 991,
            gid: 991,
            debug_same_identity: false,
        }),
        configured_path: PathBuf::from(format!("/fixture/provider-{suffix}")),
        resolved_path: PathBuf::from(format!("/fixture/provider-{suffix}")),
        sha256: nq_protocol::sha256_bytes(format!("helper-{suffix}").as_bytes()).into_string(),
        size: 1,
        device: 1,
        inode: 1,
        mode: 0o100_755,
        modified_ns: "0".to_owned(),
        fixed_argv: Vec::new(),
        working_directory: None,
        working_directory_identity: None,
        execution_chain: Vec::new(),
        startup_runtime: None,
    }
}

/// Append a fully typed source admission from which schema v4 derives the
/// distinct local-provider admission. Nothing in the helper response can mint
/// this identity.
pub fn append_typed_admission(
    store: &mut Store,
    suffix: &str,
    instance_id: &str,
    profile_id: &str,
    profile_version: u32,
    profile_digest: &str,
    admitted_at: &str,
) -> String {
    let profile = nq_profiles::resolve_profile(profile_id, profile_version)
        .expect("provider fixture uses a compiled profile");
    let semantic_id =
        profile_semantic_id(profile.descriptor()).expect("compiled profile semantic identity");
    let admission_id = uuid::Uuid::new_v4().to_string();
    let execution = fixture_execution(suffix);
    let conformance = fixture_conformance();
    let lock = AdmissionLock {
        schema: ADMISSION_SCHEMA.to_owned(),
        admission_id: admission_id.clone(),
        instance_id: instance_id.to_owned(),
        config_digest: nq_protocol::sha256_bytes(format!("config-{suffix}").as_bytes())
            .into_string(),
        execution,
        profile: AdmittedProfile {
            id: profile_id.to_owned(),
            version: profile_version,
            digest: profile_digest.to_owned(),
        },
        protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
        granted_capabilities: fixture_capability_grant(profile_id),
        conformance,
        admitted_at: timestamp(admitted_at),
        operator: OperatorIdentity {
            uid: 991,
            gid: 991,
            login_hint: Some("nq-app-fixture".to_owned()),
        },
    };
    AdmissionManager
        .binding_digest(&lock)
        .expect("typed fixture admission lock validates");
    let digest = |label: &str| nq_protocol::sha256_bytes(format!("{label}-{suffix}").as_bytes());
    store
        .begin_writer_session()
        .expect("begin writer session")
        .append_admission(&AdmissionInput {
            admission_id: admission_id.clone(),
            instance_id: instance_id.to_owned(),
            identity: AdmissionIdentity {
                profile_semantic_id: Sha256Digest::parse(semantic_id.as_str().to_owned())
                    .expect("semantic identity is a digest"),
                detector_identity_digest: nq_store::detector_suite_identity_digest(
                    profile.detectors().iter().map(|detector| {
                        detector
                            .descriptor()
                            .digest()
                            .expect("compiled detector identity")
                    }),
                )
                .expect("compiled detector suite identity"),
                evaluator_source_digest: digest("source"),
                evaluator_artifact_digest: digest("evaluator"),
                helper_artifact_digest: Sha256Digest::parse(lock.execution.sha256.clone())
                    .expect("helper artifact identity"),
                config_digest: Sha256Digest::parse(lock.config_digest.clone())
                    .expect("configuration identity"),
                protocol_version: lock.protocol_version.clone(),
                target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                artifact_identity_method: "test-fixture".to_owned(),
                platform_runtime_version: "test".to_owned(),
            },
            execution_chain: document(&lock.execution),
            profile_id: profile_id.to_owned(),
            profile_version: profile_version.to_string(),
            profile_digest: profile_digest.to_owned(),
            capability_grant: document(&lock.granted_capabilities),
            conformance: document(&lock.conformance),
            lock: document(&lock),
            admitted_at: admitted_at.to_owned(),
            operator_identity: document(&lock.operator),
        })
        .expect("append typed governing admission");
    admission_id
}

/// Exact provider-native carrier represented by an app-level surface fixture.
#[allow(dead_code)] // Each integration-test crate exercises a different closed subset.
pub enum ProviderFixtureResponse {
    /// No complete response bytes were available.
    Unavailable,
    /// The exact helper refusal is read from rejected custody and framed as a
    /// correlated helper response.
    HelperRefusal,
    /// A protocol-valid candidate report that NQ will refuse semantically.
    CandidateReport(Box<EvidenceReport>),
}

/// Construct the NQ-owned request used by a typed provider fixture. Its binding
/// follows the compiled profile and never comes from the provider response.
pub fn provider_request(run: &RunInput) -> HelperRequest {
    let (subject, scope_kind, scope_value) = match run.profile_id.as_str() {
        nq_profiles::conformance::PROFILE_ID => (
            "conformance:fixture",
            "fixture",
            json!({"id": "fixture", "nonce": "nonce"}),
        ),
        nq_profiles::host::PROFILE_ID => ("host:fixture", "host", json!({"id": "fixture"})),
        other => panic!("unsupported provider fixture profile {other}"),
    };
    let capabilities = fixture_capability_grant(&run.profile_id)
        .into_iter()
        .map(|capability| Capability::new(capability).expect("fixture capability"))
        .collect();
    HelperRequest::builder(
        RequestId::new(run.request_id.clone()).expect("fixture request identity"),
        InstanceId::new(run.instance_id.clone()).expect("fixture instance identity"),
        ProfileBinding {
            id: ProfileId::new(run.profile_id.clone()).expect("fixture profile identity"),
            version: ProfileVersion::new(run.profile_version.clone())
                .expect("fixture profile version"),
            digest: Sha256Digest::parse(run.profile_digest.clone())
                .expect("fixture profile digest"),
        },
        SubjectBinding {
            subject: SubjectId::new(subject).expect("fixture subject"),
            scope: ScopeBinding {
                kind: ScopeKind::new(scope_kind).expect("fixture scope"),
                value: scope_value,
            },
            vantage: VantageBinding {
                kind: VantageKind::new("local").expect("fixture vantage"),
                value: json!({}),
            },
        },
        MonotonicDeadline {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns: 10_000,
        },
    )
    .capabilities(capabilities)
    .build()
    .expect("typed provider fixture request")
}

/// Construct a typed, independently reopenable local-provider graph for
/// public-surface fixtures. Raw bytes are the exact outer helper response, not
/// a parsed report surrogate.
#[allow(clippy::too_many_lines)]
pub fn provider_collection(
    store: &mut Store,
    mut run: RunInput,
    mut submission: Option<SubmissionInput>,
    response: ProviderFixtureResponse,
    occurred_at: &str,
) -> CollectionInput {
    let source_admission_id = run
        .admission_id
        .as_deref()
        .expect("provider fixture run has an admission")
        .to_owned();
    let admission = store
        .admission(&source_admission_id)
        .expect("read fixture source admission")
        .expect("fixture source admission exists");
    let lock_document = CanonicalDocument::from_canonical_bytes(admission.lock_json.clone())
        .expect("fixture source lock is canonical");
    let lock: AdmissionLock =
        serde_json::from_slice(lock_document.as_bytes()).expect("fixture source lock is typed");
    run.binding_digest = AdmissionManager
        .binding_digest(&lock)
        .expect("fixture source lock validates");
    run.execution_identity = document(&lock.execution);

    let event_id = uuid::Uuid::new_v4().to_string();
    let operation_id = uuid::Uuid::new_v4().to_string();
    store
        .begin_writer_session()
        .expect("begin writer session")
        .begin_binding_transition(
            &BindingEventInput {
                binding_event_id: event_id.clone(),
                instance_id: run.instance_id.clone(),
                event_kind: "activate".to_owned(),
                admission_id: Some(source_admission_id.clone()),
                binding_digest: run.binding_digest.clone(),
                occurred_at: occurred_at.to_owned(),
                reason_code: Some("provider_intake_fixture".to_owned()),
                detail: document(&json!({"fixture": "typed_provider_intake"})),
            },
            &BindingMaterializationInput {
                materialization_event_id: uuid::Uuid::new_v4().to_string(),
                operation_id: operation_id.clone(),
                instance_id: run.instance_id.clone(),
                binding_event_id: event_id.clone(),
                phase: "intent".to_owned(),
                occurred_at: occurred_at.to_owned(),
                detail: document(&json!({"fixture": "typed_provider_intake"})),
            },
        )
        .expect("activate fixture provider admission");
    store
        .begin_writer_session()
        .expect("begin writer session")
        .complete_binding_materialization(&BindingMaterializationInput {
            materialization_event_id: uuid::Uuid::new_v4().to_string(),
            operation_id,
            instance_id: run.instance_id.clone(),
            binding_event_id: event_id,
            phase: "completed".to_owned(),
            occurred_at: occurred_at.to_owned(),
            detail: document(&json!({"fixture": "typed_provider_intake"})),
        })
        .expect("complete fixture provider binding");

    let provider_admission = store
        .provider_admission_for_source(&source_admission_id)
        .expect("read derived provider admission")
        .expect("derived provider admission exists");
    let request = provider_request(&run);
    let interpretation = match response {
        ProviderFixtureResponse::Unavailable => {
            assert!(
                submission.is_none(),
                "unavailable response has no submission"
            );
            ProviderResponseInterpretationV1::NotAvailable
        }
        ProviderFixtureResponse::HelperRefusal => {
            let submission = submission
                .as_ref()
                .expect("helper refusal retains rejected custody");
            let SubmissionDisposition::Rejected { refusal } = &submission.disposition else {
                panic!("helper refusal fixture must retain rejected custody")
            };
            let governed: GovernedRefusal = serde_json::from_slice(refusal.detail.as_bytes())
                .expect("helper refusal custody is typed");
            let GovernedRefusalOrigin::Helper(refusal) = governed.origin else {
                panic!("helper fixture custody must contain a helper refusal")
            };
            ProviderResponseInterpretationV1::Validated {
                response: HelperResponse::refusal(&request, refusal),
            }
        }
        ProviderFixtureResponse::CandidateReport(report) => {
            nq_protocol::validate_report(&report)
                .expect("fixture candidate report is protocol-valid");
            ProviderResponseInterpretationV1::Validated {
                response: HelperResponse::report(&request, *report),
            }
        }
    };
    let raw_bytes = match &interpretation {
        ProviderResponseInterpretationV1::NotAvailable => Vec::new(),
        ProviderResponseInterpretationV1::Validated { response } => {
            nq_protocol::encode_ndjson(response).expect("frame exact fixture response")
        }
        ProviderResponseInterpretationV1::ProtocolRejected { .. } => {
            unreachable!("these surface fixtures use only typed valid responses")
        }
    };
    if let Some(submission) = &mut submission {
        submission.raw_bytes.clone_from(&raw_bytes);
    }
    match &interpretation {
        ProviderResponseInterpretationV1::Validated { response } => assert_eq!(
            nq_protocol::parse_response(&request, &raw_bytes)
                .expect("framed fixture response validates against its exact request"),
            *response,
        ),
        ProviderResponseInterpretationV1::NotAvailable => {
            assert!(
                raw_bytes.is_empty(),
                "unavailable intake has no complete bytes"
            );
        }
        ProviderResponseInterpretationV1::ProtocolRejected { .. } => unreachable!(),
    }
    let received_at = submission.as_ref().map_or_else(
        || run.finished_at.clone(),
        |submission| submission.received_at.clone(),
    );
    let mut native: RunResourceOutcomeV1 =
        serde_json::from_slice(run.resource_outcome.as_bytes()).expect("typed native outcome");
    native.stdout_bytes_retained = raw_bytes.len();
    run.resource_outcome = document(&native);

    let parse = |field: &str, value: &str| {
        Sha256Digest::parse(value.to_owned())
            .unwrap_or_else(|error| panic!("invalid fixture {field}: {error}"))
    };
    let conformance = lock.conformance.clone();
    let provider = ProviderIdentityV1 {
        schema: ProviderIdentitySchema::V1,
        kind: ProviderKind::LocalHelper,
        provider_semantic_id: parse(
            "provider semantic identity",
            &provider_admission.provider_semantic_id,
        ),
        provider_admission_id: parse(
            "provider admission identity",
            &provider_admission.provider_admission_id,
        ),
        source_admission_id: source_admission_id.clone(),
        binding_digest: parse("binding digest", &run.binding_digest),
        artifact_digest: parse(
            "provider artifact digest",
            &admission.helper_artifact_digest,
        ),
        execution_identity_digest: parse(
            "execution identity digest",
            run.execution_identity.digest(),
        ),
        configuration_digest: parse("provider configuration digest", &admission.config_digest),
        protocol_identity: admission.protocol_version.clone(),
        conformance_corpus_digest: parse(
            "conformance corpus digest",
            &conformance.protocol_corpus_digest,
        ),
        conformance_tool_version: conformance.tool_version.clone(),
        conformance,
        profile_semantic_id: parse("profile semantic identity", &admission.profile_semantic_id),
        evaluator_artifact_digest: parse(
            "evaluator artifact digest",
            &admission.evaluator_artifact_digest,
        ),
        admission_context_digest: parse(
            "admission context digest",
            &admission.admission_context_digest,
        ),
    };
    provider
        .verify_historical()
        .expect("fixture provider identity is historically coherent");

    let intake_id = format!("intake-{}", run.run_id);
    let attempt_id = format!("attempt-{}", run.run_id);
    let idempotency_key =
        nq_store::provider_idempotency_key(provider.provider_admission_id.as_str(), &attempt_id)
            .expect("provider idempotency identity");
    let deadline_at = timestamp(&run.deadline_at);
    let context = ProviderIntakeContextV1 {
        schema: ProviderIntakeContextSchema::V1,
        intake_id: intake_id.clone(),
        attempt_id: attempt_id.clone(),
        run_id: run.run_id.clone(),
        request: request.clone(),
        provider: provider.clone(),
        origin_carrier: run.carrier.clone(),
        deadline_at,
        checkpoint_contract_digest: parse(
            "checkpoint contract digest",
            &run.checkpoint_contract_digest,
        ),
    };
    let interpretation_kind = match &interpretation {
        ProviderResponseInterpretationV1::NotAvailable => "unavailable",
        ProviderResponseInterpretationV1::ProtocolRejected { .. } => "protocol_rejected",
        ProviderResponseInterpretationV1::Validated { response } => match &response.outcome {
            nq_protocol::ResponseOutcome::Refusal { .. } => "provider_refusal",
            nq_protocol::ResponseOutcome::Report { .. } => "candidate_report",
        },
    };
    let record = ProviderIntakeRecordV1 {
        schema: ProviderIntakeSchema::V1,
        intake_id: intake_id.clone(),
        attempt_id: attempt_id.clone(),
        idempotency_key: idempotency_key.clone(),
        run_id: run.run_id.clone(),
        request_id: run.request_id.clone(),
        request: request.clone(),
        provider: provider.clone(),
        origin_carrier: run.carrier.clone(),
        deadline_at,
        request_digest: nq_protocol::semantic_digest(&request).expect("fixture request digest"),
        context_digest: nq_protocol::semantic_digest(&context).expect("fixture context digest"),
        checkpoint_contract_digest: context.checkpoint_contract_digest.clone(),
        started_at: timestamp(&run.started_at),
        finished_at: timestamp(&run.finished_at),
        received_at: timestamp(&received_at),
        native_outcome: native.clone(),
        raw_length: raw_bytes.len(),
        raw_sha256: nq_protocol::sha256_bytes(&raw_bytes),
        provider_sequence: None,
        interpretation: interpretation.clone(),
    };
    record
        .verify_historical_raw(&raw_bytes)
        .expect("fixture intake is independently reopenable");
    let intake = ProviderIntakeInput {
        intake_id,
        idempotency_key,
        attempt_id,
        request_id: run.request_id.clone(),
        provider_admission_id: provider.provider_admission_id.as_str().to_owned(),
        source_admission_id,
        provider_sequence: None,
        origin_carrier: run.carrier.clone(),
        deadline_at: run.deadline_at.clone(),
        checkpoint_contract_digest: run.checkpoint_contract_digest.clone(),
        execution_identity_digest: provider.execution_identity_digest.clone(),
        admission_context_digest: provider.admission_context_digest.clone(),
        provider_semantic_id: provider.provider_semantic_id.clone(),
        provider_artifact_digest: provider.artifact_digest.clone(),
        provider_protocol_identity: provider.protocol_identity.clone(),
        provider_config_digest: provider.configuration_digest.clone(),
        binding_digest: run.binding_digest.clone(),
        instance_id: run.instance_id.clone(),
        profile_id: run.profile_id.clone(),
        profile_version: run.profile_version.clone(),
        profile_digest: run.profile_digest.clone(),
        profile_semantic_id: provider.profile_semantic_id.clone(),
        evaluator_artifact_digest: provider.evaluator_artifact_digest.clone(),
        context: document(&context),
        interpretation_kind: interpretation_kind.to_owned(),
        interpretation: document(&interpretation),
        native_outcome_kind: run.acquisition_outcome.clone(),
        native_outcome: run.resource_outcome.clone(),
        raw_bytes,
        started_at: run.started_at.clone(),
        finished_at: run.finished_at.clone(),
        received_at,
    };
    CollectionInput {
        intake,
        run,
        submission,
    }
}
