//! Black-box semantic-transport checks through the shipped operator binary.

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chrono::{Duration, Utc};
use nq_core::engine::{
    CollectionOutcome, CollectionResult, GovernedRefusal, GovernedRefusalOrigin, RunHardLimits,
    RunResourceOutcomeSchema, RunResourceOutcomeV1,
};
use nq_core::runner::{AcquisitionOutcome, ExchangeTimeoutPhase};
use nq_profiles::{
    ProfileRefusalCode, RefusalBoundary as ProfileRefusalBoundary,
    ReportInput as ProfileReportInput, ValidationContext, profile_semantic_id,
};
use nq_protocol::{
    BackendIdentity, BackendProvenance, Capability, CoverageDeclaration, CoverageKind,
    CoverageState, EvidenceReport, ImplementationName, InstanceId, Observation, ObservationKind,
    Refusal, RefusalBoundary, RefusalCode, ReportStatus,
};
use nq_store::{
    CanonicalDocument, ProfileDescriptorInput, RefusalInput, RunInput, RunResultStatusInput,
    StatusEventInput, Store, SubmissionDisposition, SubmissionInput,
};
use serde_json::{Value, json};

const TEST_TIME: &str = "2026-07-20T12:00:00Z";
const PROFILE_ID: &str = "nq.conformance";

fn document(value: &impl serde::Serialize) -> CanonicalDocument {
    CanonicalDocument::from_serializable(value).expect("fixture document canonicalizes")
}

fn write_config(root: &Path, database: &Path) -> PathBuf {
    let config = root.join("nq.toml");
    fs::write(
        &config,
        format!(
            "schema = \"nq.config.v1\"\ndatabase_path = \"{}\"\nsocket_path = \"{}\"\n\
             admissions_dir = \"{}\"\nhelper_runtime_dir = \"{}\"\n",
            database.display(),
            root.join("nqd.sock").display(),
            root.join("admissions").display(),
            root.join("helpers").display(),
        ),
    )
    .expect("write config");
    config
}

fn write_refusal_config(root: &Path, database: &Path) -> PathBuf {
    let helper = root.join("refusing-helper.py");
    fs::write(
        &helper,
        r#"#!/usr/bin/env python3
import json
import os
import sys

request = json.loads(sys.stdin.readline())
mode_path = os.environ["NQ_REFUSAL_MODE_PATH"]
mode = open(mode_path, encoding="utf-8").read().strip()
transient = mode == "transient"
echo_fields = (
    "protocol_version", "request_id", "instance_id", "profile", "binding",
    "granted_capabilities", "checkpoint", "deadline", "bounds"
)
echo = {key: request[key] for key in echo_fields if key in request}
response = {
    "schema": "nq.helper.response.v1",
    "echo": echo,
    "outcome": {
        "kind": "refusal",
        "refusal": {
            "responsible_instance_id": request["instance_id"],
            "boundary": "collection",
            "code": "collection_failed",
            "message": "backend collection failed",
            "retriable": transient,
            "details": (
                {"attempt": 1, "errno": "EAGAIN"}
                if transient else {"device": "nvme0", "errno": "ENODEV"}
            ),
        },
    },
}
print(json.dumps(response, allow_nan=False, sort_keys=True, separators=(",", ":")))
"#,
    )
    .expect("write refusing helper");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755))
        .expect("make refusing helper executable");
    fs::write(root.join("refusal-mode"), b"transient\n").expect("write refusal mode");
    let config = root.join("refusal.toml");
    fs::write(
        &config,
        format!(
            r#"schema = "nq.config.v1"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"

[[watchers]]
instance_id = "dry-refusal"
subject = "conformance:fixture"
scope = {{ kind = "fixture", value = {{ id = "fixture", nonce = "nonce" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = []

[watchers.command]
executable = "/usr/bin/python3"
args = ["{}"]
env = {{ NQ_REFUSAL_MODE_PATH = "{}" }}
execution_account = "{}"
allow_same_identity_in_debug = true
working_directory = "{}"

[watchers.profile]
id = "nq.conformance"
version = 1

[watchers.schedule]
interval_seconds = 60
jitter_seconds = 0
deadline_ms = 5000
retry_backoff_seconds = 1
max_retry_backoff_seconds = 10

[watchers.resources]
max_response_bytes = 1048576
max_stderr_bytes = 65536
max_observations = 4
max_address_space_bytes = 536870912
max_cpu_seconds = 60
max_processes = 32
max_open_files = 128
max_file_bytes = 67108864
"#,
            database.display(),
            root.join("refusal.sock").display(),
            root.join("refusal-admissions").display(),
            root.join("refusal-helpers").display(),
            helper.display(),
            root.join("refusal-mode").display(),
            nix::unistd::geteuid().as_raw(),
            root.display(),
        ),
    )
    .expect("write refusal config");
    config
}

fn run(nq: &Path, config: &Path, arguments: &[&str]) -> Output {
    Command::new(nq)
        .arg("--config")
        .arg(config)
        .arg("--json")
        .args(arguments)
        .output()
        .expect("shipped nq binary executes")
}

#[allow(clippy::needless_pass_by_value)]
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command output is JSON")
}

fn archive_inventory(root: &Path) -> Vec<(String, String)> {
    fn walk(root: &Path, directory: &Path, entries: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(directory).expect("read archive inventory") {
            let path = entry.expect("archive inventory entry").path();
            let relative = path
                .strip_prefix(root)
                .expect("inventory path is under archive")
                .to_string_lossy()
                .into_owned();
            let metadata = fs::symlink_metadata(&path).expect("archive inventory metadata");
            if metadata.file_type().is_dir() {
                entries.push((relative, "directory".to_owned()));
                walk(root, &path, entries);
            } else if metadata.file_type().is_file() {
                let digest = nq_protocol::sha256_bytes(
                    &fs::read(&path).expect("read exact archive inventory bytes"),
                )
                .into_string();
                entries.push((relative, digest));
            } else {
                entries.push((relative, "unsupported-file-type".to_owned()));
            }
        }
    }

    let mut entries = Vec::new();
    walk(root, root, &mut entries);
    entries.sort();
    entries
}

fn helper_result(
    instance_id: &str,
    run_id: &str,
    refusal_id: &str,
    retriable: bool,
    details: Value,
) -> (CollectionOutcome, GovernedRefusal) {
    let refusal = GovernedRefusal::helper(
        refusal_id.to_owned(),
        Refusal {
            responsible_instance_id: InstanceId::new(instance_id).expect("instance token"),
            boundary: RefusalBoundary::Collection,
            code: RefusalCode::CollectionFailed,
            message: "backend collection failed".to_owned(),
            retriable,
            details,
        },
    );
    (
        CollectionOutcome::rejected(instance_id.to_owned(), run_id.to_owned(), refusal.clone()),
        refusal,
    )
}

fn append_fixture_descriptor(store: &mut Store, profile_id: &str, version: u32) -> String {
    let descriptor = nq_profiles::resolve_profile(profile_id, version).map_or_else(
        || {
            document(&json!({
                "profile": {"id": profile_id, "version": version},
                "fixture": "semantic-transport",
            }))
        },
        |profile| document(profile.descriptor()),
    );
    let digest = descriptor.digest().to_owned();
    store
        .append_profile_descriptor(&ProfileDescriptorInput {
            profile_id: profile_id.to_owned(),
            profile_version: version.to_string(),
            descriptor,
            recorded_at: TEST_TIME.to_owned(),
        })
        .expect("append fixture descriptor");
    digest
}

fn resource_document(
    outcome: AcquisitionOutcome,
    stdout_bytes_retained: usize,
) -> CanonicalDocument {
    document(&RunResourceOutcomeV1 {
        schema: RunResourceOutcomeSchema::V1,
        duration_ms: 1,
        exit_code: Some(0),
        hard_limits: RunHardLimits {
            address_space_bytes_per_process: 1,
            cpu_seconds_per_process: 1,
            processes_per_execution_uid: 1,
            open_files_per_process: 1,
            file_bytes_per_regular_file: 1,
            core_bytes: 0,
        },
        stdout_bytes_retained,
        stderr_bytes_retained: 0,
        stderr_hex: String::new(),
        outcome,
    })
}

fn append_admission(
    store: &mut Store,
    suffix: &str,
    instance_id: &str,
    profile_id: &str,
    profile_version: u32,
    profile_digest: &str,
) -> String {
    support::append_typed_admission(
        store,
        suffix,
        instance_id,
        profile_id,
        profile_version,
        profile_digest,
        TEST_TIME,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn seed_result(
    store: &mut Store,
    profile_id: &str,
    profile_version: u32,
    profile_digest: &str,
    suffix: &str,
    outcome: &CollectionOutcome,
    refusal: &GovernedRefusal,
    state: &str,
    status_code: &str,
) {
    let instance_id = outcome.instance_id().to_owned();
    let run_id = outcome.run_id.as_deref().expect("rejection has run");
    let (source_kind, boundary, code, profile_semantic_id, protocol_outcome) = match &refusal.origin
    {
        GovernedRefusalOrigin::Helper(source) => (
            "protocol",
            serde_json::to_value(source.boundary).expect("boundary serializes"),
            serde_json::to_value(source.code).expect("code serializes"),
            None,
            "valid_refusal",
        ),
        GovernedRefusalOrigin::Profile(source) => (
            "profile",
            serde_json::to_value(source.refusal.boundary).expect("boundary serializes"),
            serde_json::to_value(source.refusal.code).expect("code serializes"),
            Some(source.profile_semantic_id.as_str().to_owned()),
            "valid_report",
        ),
        other => panic!("unsupported fixture refusal origin: {other:?}"),
    };
    let boundary = boundary.as_str().expect("boundary is token").to_owned();
    let code = code.as_str().expect("code is token").to_owned();
    let admission_id = append_admission(
        store,
        suffix,
        &instance_id,
        profile_id,
        profile_version,
        profile_digest,
    );
    let run = RunInput {
        run_id: run_id.to_owned(),
        request_id: format!("request-{suffix}"),
        instance_id: instance_id.clone(),
        admission_id: Some(admission_id),
        binding_digest: nq_protocol::sha256_bytes(b"binding").into_string(),
        checkpoint_contract_digest: nq_protocol::sha256_bytes(b"checkpoint").into_string(),
        profile_id: profile_id.to_owned(),
        profile_version: profile_version.to_string(),
        profile_digest: profile_digest.to_owned(),
        carrier: "stdio".to_owned(),
        started_at: TEST_TIME.to_owned(),
        deadline_at: TEST_TIME.to_owned(),
        finished_at: TEST_TIME.to_owned(),
        acquisition_outcome: "response".to_owned(),
        execution_identity: document(&json!({"fixture": true})),
        resource_outcome: resource_document(
            AcquisitionOutcome::Response,
            format!("rejected-{suffix}").len(),
        ),
    };
    let submission = SubmissionInput {
        submission_id: format!("submission-{suffix}"),
        raw_bytes: format!("rejected-{suffix}").into_bytes(),
        received_at: TEST_TIME.to_owned(),
        protocol_outcome: protocol_outcome.to_owned(),
        disposition: SubmissionDisposition::Rejected {
            refusal: RefusalInput {
                refusal_id: refusal.refusal_id.clone(),
                source_kind: source_kind.to_owned(),
                responsible_instance_id: instance_id.clone(),
                boundary,
                code,
                profile_semantic_id,
                detail: document(refusal),
                created_at: TEST_TIME.to_owned(),
            },
        },
    };
    assert_eq!(
        protocol_outcome, "valid_refusal",
        "profile candidates use the separate typed report fixture"
    );
    let collection = support::provider_collection(
        store,
        run,
        Some(submission),
        support::ProviderFixtureResponse::HelperRefusal,
        TEST_TIME,
    );
    store
        .commit_non_success_collection(
            &collection,
            &RunResultStatusInput {
                run_id: run_id.to_owned(),
                status: StatusEventInput {
                    status_event_id: uuid::Uuid::new_v4().to_string(),
                    component_kind: "instance".to_owned(),
                    component_id: instance_id,
                    state: state.to_owned(),
                    code: status_code.to_owned(),
                    detail: document(outcome),
                    observed_at: TEST_TIME.to_owned(),
                },
            },
        )
        .expect("atomically commit rejected custody and canonical status");
}

fn seed_acquisition_result(
    store: &mut Store,
    profile_digest: &str,
    suffix: &str,
    outcome: &CollectionOutcome,
) {
    let instance_id = outcome.instance_id().to_owned();
    let run_id = outcome.run_id.as_deref().expect("acquisition has run");
    let CollectionResult::AcquisitionFailed { failure } = &outcome.result else {
        panic!("acquisition fixture must carry acquisition failure");
    };
    let admission_id = append_admission(store, suffix, &instance_id, PROFILE_ID, 1, profile_digest);
    let run = RunInput {
        run_id: run_id.to_owned(),
        request_id: format!("request-{suffix}"),
        instance_id: instance_id.clone(),
        admission_id: Some(admission_id),
        binding_digest: nq_protocol::sha256_bytes(b"binding").into_string(),
        checkpoint_contract_digest: nq_protocol::sha256_bytes(b"checkpoint").into_string(),
        profile_id: PROFILE_ID.to_owned(),
        profile_version: "1".to_owned(),
        profile_digest: profile_digest.to_owned(),
        carrier: "unix".to_owned(),
        started_at: TEST_TIME.to_owned(),
        deadline_at: TEST_TIME.to_owned(),
        finished_at: TEST_TIME.to_owned(),
        acquisition_outcome: "timeout".to_owned(),
        execution_identity: document(&json!({"fixture": true})),
        resource_outcome: resource_document(failure.outcome.clone(), 0),
    };
    let collection = support::provider_collection(
        store,
        run,
        None,
        support::ProviderFixtureResponse::Unavailable,
        TEST_TIME,
    );
    store
        .commit_non_success_collection(
            &collection,
            &RunResultStatusInput {
                run_id: run_id.to_owned(),
                status: StatusEventInput {
                    status_event_id: uuid::Uuid::new_v4().to_string(),
                    component_kind: "instance".to_owned(),
                    component_id: instance_id,
                    state: "failed".to_owned(),
                    code: "collection_failed".to_owned(),
                    detail: document(outcome),
                    observed_at: TEST_TIME.to_owned(),
                },
            },
        )
        .expect("atomically commit acquisition failure and canonical status");
}

fn invalid_profile_candidate(request: &nq_protocol::HelperRequest) -> EvidenceReport {
    let observed_at = chrono::DateTime::parse_from_rfc3339(TEST_TIME)
        .expect("fixture observation time")
        .with_timezone(&Utc);
    let backend = BackendProvenance {
        implementation: BackendIdentity {
            name: ImplementationName::new("typed-surface-fixture").expect("backend identity"),
            version: Some("1".to_owned()),
            digest: None,
        },
        tools: Vec::new(),
    };
    let (coverage, observation_kind, payload, used_capabilities) = match request.profile.id.as_str()
    {
        nq_profiles::conformance::PROFILE_ID => (
            vec![CoverageDeclaration {
                kind: CoverageKind::new("echo").expect("echo coverage"),
                subject: None,
                state: CoverageState::Complete,
                detail: None,
            }],
            ObservationKind::new("echo").expect("echo observation"),
            json!({
                "evidence_basis": {
                    "scope": request.binding.scope,
                    "vantage": request.binding.vantage,
                    "access_path": "process",
                    "basis": "request_echo",
                    "regime": "conformance",
                    "capabilities_used": [],
                }
                // Deliberately lacks the required nonce. The protocol
                // accepts this opaque profile payload; the compiled
                // profile produces the typed refusal below.
            }),
            Vec::new(),
        ),
        nq_profiles::host::PROFILE_ID => (
            ["host_identity", "uptime", "load"]
                .into_iter()
                .map(|kind| CoverageDeclaration {
                    kind: CoverageKind::new(kind).expect("host coverage"),
                    subject: None,
                    state: CoverageState::Complete,
                    detail: None,
                })
                .collect(),
            ObservationKind::new("host_snapshot").expect("host observation"),
            json!({
                "evidence_basis": {
                    "scope": request.binding.scope,
                    "vantage": request.binding.vantage,
                    "access_path": "procfs",
                    "basis": "kernel_snapshot",
                    "regime": "normal",
                    "capabilities_used": ["read_procfs"],
                },
                "hostname": "fixture",
                "uptime_seconds": 1,
                // Protocol-valid JSON, but explicitly invalid under the
                // compiled host profile.
                "cpu_count": 0,
                "load_1m": 0.5,
            }),
            vec![Capability::new("read_procfs").expect("host capability")],
        ),
        other => panic!("unsupported profile refusal fixture {other}"),
    };
    let report = EvidenceReport {
        schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
        profile: request.profile.clone(),
        binding: request.binding.clone(),
        observed_at,
        status: ReportStatus::Complete,
        coverage,
        observations: vec![Observation {
            ordinal: 0,
            kind: observation_kind,
            subject: request.binding.subject.clone(),
            observed_at,
            payload,
        }],
        errors: Vec::new(),
        used_capabilities,
        backend,
        next_checkpoint: None,
    };
    nq_protocol::validate_report(&report).expect("candidate is valid at the common protocol layer");
    report
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn seed_profile_result(
    store: &mut Store,
    profile_id: &str,
    profile_version: u32,
    profile_digest: &str,
    suffix: &str,
) -> CollectionOutcome {
    let instance_id = format!("profile-{suffix}");
    let run_id = format!("run-profile-{suffix}");
    let admission_id = append_admission(
        store,
        suffix,
        &instance_id,
        profile_id,
        profile_version,
        profile_digest,
    );
    let run = RunInput {
        run_id: run_id.clone(),
        request_id: format!("request-profile-{suffix}"),
        instance_id: instance_id.clone(),
        admission_id: Some(admission_id),
        binding_digest: nq_protocol::sha256_bytes(b"replaced-by-typed-support").into_string(),
        checkpoint_contract_digest: nq_protocol::sha256_bytes(
            format!("checkpoint-profile-{suffix}").as_bytes(),
        )
        .into_string(),
        profile_id: profile_id.to_owned(),
        profile_version: profile_version.to_string(),
        profile_digest: profile_digest.to_owned(),
        carrier: "stdio".to_owned(),
        started_at: TEST_TIME.to_owned(),
        deadline_at: TEST_TIME.to_owned(),
        finished_at: TEST_TIME.to_owned(),
        acquisition_outcome: "response".to_owned(),
        execution_identity: document(&json!({"replaced_by": "typed_support"})),
        resource_outcome: resource_document(AcquisitionOutcome::Response, 0),
    };
    let request = support::provider_request(&run);
    let report = invalid_profile_candidate(&request);
    let profile = nq_profiles::resolve_profile(profile_id, profile_version)
        .expect("profile refusal fixture uses a compiled profile");
    let report_digest =
        nq_protocol::semantic_digest(&report).expect("candidate report semantic digest");
    let normalized = ProfileReportInput::from_protocol(&report, &report_digest)
        .expect("candidate report normalizes");
    let context =
        ValidationContext::from_request(&request, timestamp(TEST_TIME), Duration::seconds(60));
    let profile_refusal = profile
        .validate(&context, &normalized)
        .expect_err("candidate is refused by compiled profile semantics");
    assert_eq!(
        profile_refusal.boundary,
        ProfileRefusalBoundary::Observation
    );
    assert_eq!(profile_refusal.code, ProfileRefusalCode::InvalidPayload);
    let refusal = GovernedRefusal::profile(
        format!("refusal-profile-{suffix}"),
        profile_semantic_id(profile.descriptor()).expect("profile semantic identity"),
        profile_refusal,
    );
    let outcome = CollectionOutcome::rejected(instance_id.clone(), run_id.clone(), refusal.clone());
    let GovernedRefusalOrigin::Profile(governed_profile) = &refusal.origin else {
        unreachable!("constructed a profile refusal")
    };
    let submission = SubmissionInput {
        submission_id: format!("submission-profile-{suffix}"),
        raw_bytes: Vec::new(),
        received_at: TEST_TIME.to_owned(),
        protocol_outcome: "valid_report".to_owned(),
        disposition: SubmissionDisposition::Rejected {
            refusal: RefusalInput {
                refusal_id: refusal.refusal_id.clone(),
                source_kind: "profile".to_owned(),
                responsible_instance_id: instance_id.clone(),
                boundary: serde_json::to_value(governed_profile.refusal.boundary)
                    .expect("profile boundary serializes")
                    .as_str()
                    .expect("profile boundary token")
                    .to_owned(),
                code: serde_json::to_value(governed_profile.refusal.code)
                    .expect("profile code serializes")
                    .as_str()
                    .expect("profile code token")
                    .to_owned(),
                profile_semantic_id: Some(governed_profile.profile_semantic_id.as_str().to_owned()),
                detail: document(&refusal),
                created_at: TEST_TIME.to_owned(),
            },
        },
    };
    let collection = support::provider_collection(
        store,
        run,
        Some(submission),
        support::ProviderFixtureResponse::CandidateReport(Box::new(report)),
        TEST_TIME,
    );
    store
        .commit_non_success_collection(
            &collection,
            &RunResultStatusInput {
                run_id,
                status: StatusEventInput {
                    status_event_id: uuid::Uuid::new_v4().to_string(),
                    component_kind: "instance".to_owned(),
                    component_id: instance_id,
                    state: "failed".to_owned(),
                    code: "report_rejected".to_owned(),
                    detail: document(&outcome),
                    observed_at: TEST_TIME.to_owned(),
                },
            },
        )
        .expect("atomically commit typed profile refusal and raw candidate custody");
    outcome
}

fn timestamp(value: &str) -> chrono::DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

struct TransportOutcomes {
    helper_transient: CollectionOutcome,
    helper_permanent: CollectionOutcome,
    timeout_write: CollectionOutcome,
    timeout_read: CollectionOutcome,
    profile_report: CollectionOutcome,
    profile_observation: CollectionOutcome,
}

#[allow(clippy::too_many_lines)]
fn seed_transport_store(database: &Path) -> TransportOutcomes {
    let mut store = Store::initialize(database).expect("initialize store");
    let profile_digest = append_fixture_descriptor(&mut store, PROFILE_ID, 1);
    let conformance_digest = profile_digest.clone();
    let host_digest = append_fixture_descriptor(&mut store, "nq.host", 1);
    let (transient, transient_refusal) = helper_result(
        "transport-transient",
        "run-transient",
        "refusal-transient",
        true,
        json!({"attempt": 1, "errno": "EAGAIN"}),
    );
    let (permanent, permanent_refusal) = helper_result(
        "transport-permanent",
        "run-permanent",
        "refusal-permanent",
        false,
        json!({"device": "nvme0", "errno": "ENODEV"}),
    );
    seed_result(
        &mut store,
        PROFILE_ID,
        1,
        &profile_digest,
        "transient",
        &transient,
        &transient_refusal,
        "degraded",
        "helper_refused",
    );
    seed_result(
        &mut store,
        PROFILE_ID,
        1,
        &profile_digest,
        "permanent",
        &permanent,
        &permanent_refusal,
        "degraded",
        "helper_refused",
    );

    let timeout_write = CollectionOutcome::acquisition_failed(
        "timeout-write".to_owned(),
        "run-timeout-write".to_owned(),
        AcquisitionOutcome::ExchangeTimeout {
            phase: ExchangeTimeoutPhase::WriteRequest,
        },
    )
    .expect("write timeout carrier");
    let timeout_read = CollectionOutcome::acquisition_failed(
        "timeout-read".to_owned(),
        "run-timeout-read".to_owned(),
        AcquisitionOutcome::ExchangeTimeout {
            phase: ExchangeTimeoutPhase::ReadResponse,
        },
    )
    .expect("read timeout carrier");
    seed_acquisition_result(&mut store, &profile_digest, "timeout-write", &timeout_write);
    seed_acquisition_result(&mut store, &profile_digest, "timeout-read", &timeout_read);

    let profile_report = seed_profile_result(
        &mut store,
        "nq.conformance",
        1,
        &conformance_digest,
        "report",
    );
    let profile_observation =
        seed_profile_result(&mut store, "nq.host", 1, &host_digest, "observation");
    store.validate().expect("transport store validates");
    TransportOutcomes {
        helper_transient: transient,
        helper_permanent: permanent,
        timeout_write,
        timeout_read,
        profile_report,
        profile_observation,
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn cli_and_cold_archive_reopen_exact_same_code_refusal_payloads() {
    let nq = Path::new(env!("CARGO_BIN_EXE_nq"));
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    let database = root.join("nq.db");
    let config = write_config(root, &database);
    let outcomes = seed_transport_store(&database);

    let status = success(run(nq, &config, &["status", "export"]));
    assert_eq!(status["schema"], "nq.status_snapshot.v3");
    let components = status["components"].as_array().expect("status components");
    let component = |id: &str| {
        components
            .iter()
            .find(|component| component["id"] == id)
            .unwrap_or_else(|| panic!("missing status component {id}"))
    };
    assert_eq!(component("transport-transient")["code"], "helper_refused");
    assert_eq!(component("transport-permanent")["code"], "helper_refused");
    assert_eq!(
        component("transport-transient")["detail"]["result"],
        serde_json::to_value(&outcomes.helper_transient).expect("transient serializes")
    );
    assert_eq!(
        component("transport-permanent")["detail"]["result"],
        serde_json::to_value(&outcomes.helper_permanent).expect("permanent serializes")
    );
    assert_eq!(component("timeout-write")["code"], "collection_failed");
    assert_eq!(component("timeout-read")["code"], "collection_failed");
    assert_eq!(
        component("timeout-write")["detail"]["result"],
        serde_json::to_value(&outcomes.timeout_write).expect("write timeout serializes")
    );
    assert_eq!(
        component("timeout-read")["detail"]["result"],
        serde_json::to_value(&outcomes.timeout_read).expect("read timeout serializes")
    );
    assert_eq!(
        component("timeout-write")["detail"]["result"]["result"]["failure"]["class"],
        "timeout"
    );
    assert_eq!(
        component("timeout-read")["detail"]["result"]["result"]["failure"]["class"],
        "timeout"
    );
    assert_eq!(
        component("timeout-write")["detail"]["result"]["result"]["failure"]["outcome"]["phase"],
        "write_request"
    );
    assert_eq!(
        component("timeout-read")["detail"]["result"]["result"]["failure"]["outcome"]["phase"],
        "read_response"
    );
    assert_ne!(
        component("timeout-write")["detail"],
        component("timeout-read")["detail"]
    );
    assert_eq!(component("profile-report")["code"], "report_rejected");
    assert_eq!(component("profile-observation")["code"], "report_rejected");
    assert_eq!(
        component("profile-report")["detail"]["result"],
        serde_json::to_value(&outcomes.profile_report).expect("report refusal serializes")
    );
    assert_eq!(
        component("profile-observation")["detail"]["result"],
        serde_json::to_value(&outcomes.profile_observation)
            .expect("observation refusal serializes")
    );
    let report_refusal = &component("profile-report")["detail"]["result"]["result"]["refusal"];
    let observation_refusal =
        &component("profile-observation")["detail"]["result"]["result"]["refusal"];
    assert_eq!(
        report_refusal["origin"]["payload"]["refusal"]["profile"]["id"],
        "nq.conformance"
    );
    assert_eq!(
        report_refusal["origin"]["payload"]["refusal"]["boundary"],
        "observation"
    );
    assert_eq!(
        observation_refusal["origin"]["payload"]["refusal"]["profile"]["id"],
        "nq.host"
    );
    assert_eq!(
        observation_refusal["origin"]["payload"]["refusal"]["boundary"],
        "observation"
    );
    assert_eq!(
        report_refusal["origin"]["payload"]["refusal"]["code"],
        "invalid_payload"
    );
    assert_eq!(
        report_refusal["origin"]["payload"]["refusal"]["code"],
        observation_refusal["origin"]["payload"]["refusal"]["code"],
        "different compiled profiles retain distinct payloads under the same refusal code"
    );
    assert!(
        report_refusal["origin"]["payload"]["profile_semantic_id"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_ne!(
        report_refusal["origin"]["payload"]["profile_semantic_id"],
        observation_refusal["origin"]["payload"]["profile_semantic_id"]
    );
    assert_ne!(
        report_refusal["refusal_id"],
        observation_refusal["refusal_id"]
    );
    assert_ne!(report_refusal, observation_refusal);

    let live_custody = success(run(nq, &config, &["refusals", "export", "--limit", "10"]));
    assert_eq!(live_custody["schema"], "nq.rejected_custody.v1");
    let live_records = live_custody["records"]
        .as_array()
        .expect("live custody records");
    assert_eq!(live_records.len(), 4);
    let custody_refusal = |id: &str| {
        &live_records
            .iter()
            .find(|record| record["refusal"]["refusal_id"] == id)
            .unwrap_or_else(|| panic!("missing custody refusal {id}"))["refusal"]
    };
    let transient_refusal = custody_refusal("refusal-transient");
    let permanent_refusal = custody_refusal("refusal-permanent");
    assert_eq!(transient_refusal["origin"]["payload"]["retriable"], true);
    assert_eq!(permanent_refusal["origin"]["payload"]["retriable"], false);
    assert_ne!(
        transient_refusal["refusal_id"],
        permanent_refusal["refusal_id"]
    );
    assert_ne!(transient_refusal, permanent_refusal);
    let report_custody = custody_refusal("refusal-profile-report");
    let observation_custody = custody_refusal("refusal-profile-observation");
    assert_eq!(report_custody, report_refusal);
    assert_eq!(observation_custody, observation_refusal);

    let archive = root.join("archive");
    let archive_report = success(run(
        nq,
        &config,
        &[
            "admin",
            "archive",
            "--destination",
            archive.to_str().expect("archive path"),
        ],
    ));
    assert_eq!(archive_report["archive_format"], "nq.cold_archive.v1");
    assert_eq!(archive_report["source_openable"], true);
    let sealed_inventory = archive_inventory(&archive);

    let archived_nq = archive.join("bin/nq");
    let verified = success(run(
        &archived_nq,
        &config,
        &[
            "admin",
            "archive-verify",
            archive.to_str().expect("archive path"),
        ],
    ));
    assert_eq!(verified["integrity_verified"], true);
    assert_eq!(verified["historical_database_verified"], true);
    assert_eq!(
        verified["historical_admitted_report_semantics_verified"],
        true
    );
    assert_eq!(verified["historical_admitted_reports_verified"], 0);
    assert_eq!(verified["historical_status_semantics_verified"], true);
    assert_eq!(verified["historical_status_events_verified"], 6);
    assert_eq!(
        verified["historical_rejected_custody_semantics_verified"],
        true
    );
    assert_eq!(verified["historical_rejected_custody_records_verified"], 4);
    assert_eq!(
        verified["historical_evaluation_refusal_semantics_verified"],
        true
    );
    assert_eq!(verified["historical_evaluation_records_verified"], 0);
    assert_eq!(verified["grants_authority"], false);
    assert_eq!(archive_inventory(&archive), sealed_inventory);

    let archived_database = archive.join("db/nq.db");
    let archived_store =
        Store::open_immutable(&archived_database).expect("reopen archived store immutably");
    let reopened = nq_core::engine::rejected_custody_snapshot(&archived_store, 10)
        .expect("typed archive reopen");
    assert_eq!(
        serde_json::to_value(&reopened.records).expect("reopened records serialize"),
        live_custody["records"]
    );
    drop(archived_store);

    // Exercise the preserved executable against the preserved database, not
    // the live installation or adjacent SQL rows.
    let reopen_root = root.join("reopen");
    fs::create_dir_all(&reopen_root).expect("create reopen directory");
    let archived_config = write_config(&reopen_root, &archived_database);
    let archived_status = success(run(&archived_nq, &archived_config, &["status", "export"]));
    assert_eq!(archived_status["components"], status["components"]);
    let archived_custody = success(run(
        &archived_nq,
        &archived_config,
        &["refusals", "export", "--limit", "10"],
    ));
    assert_eq!(archived_custody["records"], live_custody["records"]);
    assert_eq!(
        archive_inventory(&archive),
        sealed_inventory,
        "verify and preserved read surfaces changed sealed bytes or inventory"
    );
}

#[test]
fn structured_watcher_test_emits_the_canonical_typed_refusal() {
    let nq = Path::new(env!("CARGO_BIN_EXE_nq"));
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = directory.path().join("refusal.db");
    let config = write_refusal_config(directory.path(), &database);
    assert_eq!(success(run(nq, &config, &["init"]))["initialized"], true);

    let transient_output = run(nq, &config, &["watcher", "test", "dry-refusal"]);
    assert!(
        !transient_output.status.success(),
        "helper refusal must exit non-zero"
    );
    fs::write(directory.path().join("refusal-mode"), b"permanent\n").expect("switch refusal mode");
    let permanent_output = run(nq, &config, &["watcher", "test", "dry-refusal"]);
    assert!(
        !permanent_output.status.success(),
        "helper refusal must exit non-zero"
    );

    let parse = |output: &Output| {
        let canonical = output
            .stdout
            .strip_suffix(b"\n")
            .expect("structured refusal has one trailing newline");
        let envelope: Value = serde_json::from_slice(canonical).expect("typed refusal JSON");
        assert_eq!(
            nq_protocol::canonical_json_bytes(&envelope)
                .expect("parsed refusal envelope canonicalizes"),
            canonical
        );
        envelope
    };
    let transient = parse(&transient_output);
    let permanent = parse(&permanent_output);
    for envelope in [&transient, &permanent] {
        assert_eq!(envelope["schema"], "nq.watcher_action_error.v1");
        assert_eq!(envelope["instance_id"], "dry-refusal");
        assert_eq!(envelope["action"], "test");
        assert_eq!(
            envelope["failure"]["kind"], "governed_refusal",
            "unexpected watcher failure: {envelope}"
        );
        assert_eq!(
            envelope["failure"]["payload"]["schema"],
            "nq.governed_refusal.v1"
        );
        assert_eq!(envelope["failure"]["payload"]["origin"]["kind"], "helper");
    }

    let transient_refusal = &transient["failure"]["payload"];
    let permanent_refusal = &permanent["failure"]["payload"];
    for refusal in [transient_refusal, permanent_refusal] {
        assert_eq!(
            refusal["origin"]["payload"]["responsible_instance_id"],
            "dry-refusal"
        );
        assert_eq!(refusal["origin"]["payload"]["boundary"], "collection");
        assert_eq!(refusal["origin"]["payload"]["code"], "collection_failed");
    }
    assert_eq!(transient_refusal["origin"]["payload"]["retriable"], true);
    assert_eq!(permanent_refusal["origin"]["payload"]["retriable"], false);
    assert_eq!(
        transient_refusal["origin"]["payload"]["details"]["errno"],
        "EAGAIN"
    );
    assert_eq!(
        permanent_refusal["origin"]["payload"]["details"]["errno"],
        "ENODEV"
    );
    assert_ne!(
        transient_refusal["refusal_id"],
        permanent_refusal["refusal_id"]
    );
    assert_ne!(transient_refusal, permanent_refusal);
}
