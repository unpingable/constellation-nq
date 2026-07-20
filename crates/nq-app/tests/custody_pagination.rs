//! Black-box pagination checks through the shipped rejected-custody CLI.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use nq_core::engine::{
    CollectionOutcome, GovernedRefusal, RunHardLimits, RunResourceOutcomeSchema,
    RunResourceOutcomeV1,
};
use nq_core::runner::AcquisitionOutcome;
use nq_profiles::profile_semantic_id;
use nq_protocol::{InstanceId, Refusal, RefusalBoundary, RefusalCode, Sha256Digest};
use nq_store::{
    AdmissionIdentity, AdmissionInput, CanonicalDocument, CollectionInput, ProfileDescriptorInput,
    RefusalInput, RunInput, RunResultStatusInput, StatusEventInput, Store, SubmissionDisposition,
    SubmissionInput,
};
use serde_json::{Value, json};
use uuid::Uuid;

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

fn append_profile(store: &mut Store) -> String {
    let profile = nq_profiles::resolve_profile(PROFILE_ID, 1).expect("compiled fixture profile");
    let descriptor = document(profile.descriptor());
    let digest = descriptor.digest().to_owned();
    store
        .append_profile_descriptor(&ProfileDescriptorInput {
            profile_id: PROFILE_ID.to_owned(),
            profile_version: "1".to_owned(),
            descriptor,
            recorded_at: TEST_TIME.to_owned(),
        })
        .expect("append profile descriptor");
    digest
}

fn append_admission(
    store: &mut Store,
    suffix: &str,
    instance_id: &str,
    profile_digest: &str,
) -> String {
    let profile = nq_profiles::resolve_profile(PROFILE_ID, 1).expect("compiled fixture profile");
    let semantic_id =
        profile_semantic_id(profile.descriptor()).expect("compiled profile semantic identity");
    let digest = |label: &str| nq_protocol::sha256_bytes(label.as_bytes());
    let admission_id = format!("admission-{suffix}");
    store
        .append_admission(&AdmissionInput {
            admission_id: admission_id.clone(),
            instance_id: instance_id.to_owned(),
            identity: AdmissionIdentity {
                profile_semantic_id: Sha256Digest::parse(semantic_id.as_str())
                    .expect("semantic identity digest"),
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
                helper_artifact_digest: digest("helper"),
                config_digest: digest("config"),
                protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                target_triple: "fixture-target".to_owned(),
                artifact_identity_method: "fixture".to_owned(),
                platform_runtime_version: "fixture".to_owned(),
            },
            execution_chain: document(&json!({"fixture": true})),
            profile_id: PROFILE_ID.to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.to_owned(),
            capability_grant: document(&json!([])),
            conformance: document(&json!({"fixture": true})),
            lock: document(&json!({"fixture": true})),
            admitted_at: TEST_TIME.to_owned(),
            operator_identity: document(&json!({"fixture": true})),
        })
        .expect("append governing admission");
    admission_id
}

fn seed_helper_refusal(
    store: &mut Store,
    profile_digest: &str,
    suffix: &str,
    retriable: bool,
    details: Value,
) -> GovernedRefusal {
    let instance_id = format!("transport-{suffix}");
    let run_id = format!("run-{suffix}");
    let refusal = GovernedRefusal::helper(
        format!("refusal-{suffix}"),
        Refusal {
            responsible_instance_id: InstanceId::new(instance_id.clone()).expect("instance token"),
            boundary: RefusalBoundary::Collection,
            code: RefusalCode::CollectionFailed,
            message: "backend collection failed".to_owned(),
            retriable,
            details,
        },
    );
    let admission_id = append_admission(store, suffix, &instance_id, profile_digest);
    let outcome = CollectionOutcome::rejected(instance_id.clone(), run_id.clone(), refusal.clone());
    let collection = CollectionInput {
        run: RunInput {
            run_id: run_id.clone(),
            request_id: format!("request-{suffix}"),
            instance_id: instance_id.clone(),
            admission_id: Some(admission_id),
            binding_digest: nq_protocol::sha256_bytes(b"binding").into_string(),
            checkpoint_contract_digest: nq_protocol::sha256_bytes(b"checkpoint").into_string(),
            profile_id: PROFILE_ID.to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.to_owned(),
            carrier: "stdio".to_owned(),
            started_at: TEST_TIME.to_owned(),
            deadline_at: TEST_TIME.to_owned(),
            finished_at: TEST_TIME.to_owned(),
            acquisition_outcome: "response".to_owned(),
            execution_identity: document(&json!({"fixture": true})),
            resource_outcome: document(&RunResourceOutcomeV1 {
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
                stdout_bytes_retained: format!("rejected-{suffix}").len(),
                stderr_bytes_retained: 0,
                stderr_hex: String::new(),
                outcome: AcquisitionOutcome::Response,
            }),
        },
        submission: Some(SubmissionInput {
            submission_id: format!("submission-{suffix}"),
            raw_bytes: format!("rejected-{suffix}").into_bytes(),
            received_at: TEST_TIME.to_owned(),
            protocol_outcome: "valid_refusal".to_owned(),
            disposition: SubmissionDisposition::Rejected {
                refusal: RefusalInput {
                    refusal_id: refusal.refusal_id.clone(),
                    source_kind: "protocol".to_owned(),
                    responsible_instance_id: instance_id.clone(),
                    boundary: "collection".to_owned(),
                    code: "collection_failed".to_owned(),
                    profile_semantic_id: None,
                    detail: document(&refusal),
                    created_at: TEST_TIME.to_owned(),
                },
            },
        }),
    };
    store
        .commit_non_success_collection(
            &collection,
            &RunResultStatusInput {
                run_id,
                status: StatusEventInput {
                    status_event_id: Uuid::new_v4().to_string(),
                    component_kind: "instance".to_owned(),
                    component_id: instance_id,
                    state: "degraded".to_owned(),
                    code: "helper_refused".to_owned(),
                    detail: document(&outcome),
                    observed_at: TEST_TIME.to_owned(),
                },
            },
        )
        .expect("atomically commit non-success collection");
    refusal
}

#[test]
fn cli_pages_same_code_refusals_without_losing_payloads() {
    let nq = Path::new(env!("CARGO_BIN_EXE_nq"));
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = directory.path().join("nq.db");
    let config = write_config(directory.path(), &database);
    let mut store = Store::initialize(&database).expect("initialize store");
    let profile_digest = append_profile(&mut store);
    let transient = seed_helper_refusal(
        &mut store,
        &profile_digest,
        "a",
        true,
        json!({"attempt": 1, "errno": "EAGAIN"}),
    );
    let permanent = seed_helper_refusal(
        &mut store,
        &profile_digest,
        "b",
        false,
        json!({"device": "nvme0", "errno": "ENODEV"}),
    );
    store.validate().expect("fixture store validates");
    drop(store);

    let first = success(run(nq, &config, &["refusals", "export", "--limit", "1"]));
    assert_eq!(first["schema"], "nq.rejected_custody.v1");
    assert_eq!(first["records"].as_array().expect("first page").len(), 1);
    assert_eq!(first["records"][0]["submission_id"], "submission-a");
    assert_eq!(
        first["records"][0]["refusal"],
        serde_json::to_value(&transient).expect("transient refusal serializes")
    );

    let second = success(run(
        nq,
        &config,
        &[
            "refusals",
            "export",
            "--limit",
            "1",
            "--after",
            "submission-a",
        ],
    ));
    assert_eq!(second["records"].as_array().expect("second page").len(), 1);
    assert_eq!(second["records"][0]["submission_id"], "submission-b");
    assert_eq!(
        second["records"][0]["refusal"],
        serde_json::to_value(&permanent).expect("permanent refusal serializes")
    );
    assert_eq!(
        first["records"][0]["refusal"]["origin"]["payload"]["code"],
        second["records"][0]["refusal"]["origin"]["payload"]["code"]
    );
    assert_ne!(
        first["records"][0]["refusal"],
        second["records"][0]["refusal"]
    );

    let end = success(run(
        nq,
        &config,
        &[
            "refusals",
            "export",
            "--limit",
            "1",
            "--after",
            "submission-b",
        ],
    ));
    assert_eq!(end["records"], json!([]));

    for invalid in [
        ["refusals", "export", "--limit", "0"],
        ["refusals", "export", "--limit", "1001"],
        ["refusals", "export", "--after", "submission%2Da"],
    ] {
        let output = run(nq, &config, &invalid);
        assert!(
            !output.status.success(),
            "invalid page must fail closed: {invalid:?}"
        );
    }
}
