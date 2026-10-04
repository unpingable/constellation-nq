//! Black-box contract tests through the shipped `nq` binary.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn run(nq: &str, config: &Path, arguments: &[&str]) -> Output {
    Command::new(nq)
        .arg("--config")
        .arg(config)
        .args(arguments)
        .output()
        .expect("shipped nq binary must execute")
}

#[allow(clippy::needless_pass_by_value)]
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command output must be JSON")
}

#[test]
#[allow(clippy::too_many_lines)]
fn init_admit_collect_and_public_exports_use_only_shipped_surfaces() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("nq.db");
    let admissions = root.join("admissions");
    let helpers = root.join("helpers");
    let socket = root.join("nqd.sock");
    let config_path = root.join("nq.toml");
    let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../helpers/python-conformance/nq_conformance_helper.py")
        .canonicalize()
        .expect("Python conformance helper");

    let config = format!(
        r#"schema = "nq.config.v1"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"

[[watchers]]
instance_id = "conformance.primary"
subject = "conformance:fixture-e2e"
scope = {{ kind = "fixture", value = {{ id = "fixture-e2e", nonce = "e2e-nonce" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = []

[watchers.command]
executable = "{}"
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
        socket.display(),
        admissions.display(),
        helpers.display(),
        helper.display(),
        nix::unistd::geteuid().as_raw(),
        root.display(),
    );
    fs::write(&config_path, config).expect("write test config");

    let corpus = success(run(nq, &config_path, &["protocol", "check"]));
    assert_eq!(corpus["schema"], "nq.protocol.conformance_receipt.v1");
    assert_eq!(corpus["fixtures_checked"], 12);

    let initialized = success(run(nq, &config_path, &["init"]));
    assert_eq!(initialized["initialized"], true);

    let tested_output = run(
        nq,
        &config_path,
        &["watcher", "test", "conformance.primary"],
    );
    if !tested_output.status.success()
        && String::from_utf8_lossy(&tested_output.stderr).contains("spawn_failed")
        && fs::read_to_string("/proc/self/attr/current")
            .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
    {
        eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
        return;
    }
    let tested = success(tested_output);
    assert_eq!(tested["outcome"], "tested");
    assert_eq!(tested["report_status"], "complete");

    let admitted = success(run(
        nq,
        &config_path,
        &["watcher", "admit", "conformance.primary"],
    ));
    assert_eq!(admitted["outcome"], "activated");
    assert!(admissions.join("conformance.primary.json").is_file());

    let collected_output = run(
        nq,
        &config_path,
        &["--json", "collect", "conformance.primary"],
    );
    assert!(
        collected_output.status.success(),
        "structured collection failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&collected_output.stdout),
        String::from_utf8_lossy(&collected_output.stderr)
    );
    let reopened = nq_core::decode_collection_outcome_ndjson(
        &collected_output.stdout,
        collected_output.stdout.len(),
    )
    .expect("shipped structured collection output must strictly reopen");
    let collected = serde_json::to_value(reopened).expect("reopened collection serializes");
    assert_eq!(collected["schema"], "nq.collection_outcome.v2");
    assert_eq!(collected["result"]["outcome"], "admitted");
    assert_eq!(collected["result"]["report_status"], "complete");
    assert_eq!(collected["result"]["evaluations"], serde_json::json!([]));

    // Query-only export joins the exact five-field evidence reference to
    // verified admission custody, with no second helper invocation.
    let store = nq_store::Store::open_read_only(&database).expect("read-only custody");
    let source = store
        .admitted_collection_for_run(collected["run_id"].as_str().expect("run id"))
        .expect("source query")
        .expect("admitted report");
    let report: nq_protocol::EvidenceReport =
        serde_json::from_slice(&source.canonical_json).expect("native report");
    let observation = report.observations.first().expect("source observation");
    let exact = serde_json::json!({"report_id":source.report_id,"report_sequence":source.report_sequence,"report_digest":source.semantic_digest,"observation_ordinal":observation.ordinal,"observed_at":observation.observed_at});
    let index = store
        .admitted_evidence_reference(
            &source.report_id,
            &source.semantic_digest,
            Some(observation.ordinal),
        )
        .unwrap()
        .unwrap();
    let indexed_at = observation
        .observed_at
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(
        index.observation_observed_at.as_deref(),
        Some(indexed_at.as_str())
    );
    drop(store);
    let reference = root.join("evidence-reference.json");
    fs::write(&reference, serde_json::to_vec(&exact).unwrap()).unwrap();
    let reference_path = reference.to_str().unwrap();
    let exported = success(run(
        nq,
        &config_path,
        &["observations", "export", "--reference", reference_path],
    ));
    assert_eq!(exported["schema"], "nq.admitted-observation-export/v1");
    assert_eq!(exported["evidence"], exact);
    assert_eq!(
        exported["observation"],
        serde_json::to_value(observation).unwrap()
    );
    assert_eq!(exported["standing"], "historical_custody_only");
    assert_eq!(exported["reference_time_basis"], "native_observation_time");
    let projected_at = chrono::DateTime::parse_from_rfc3339(&indexed_at)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut indexed_reference = exact.clone();
    indexed_reference["observed_at"] = serde_json::json!(projected_at);
    fs::write(&reference, serde_json::to_vec(&indexed_reference).unwrap()).unwrap();
    let projected = success(run(
        nq,
        &config_path,
        &["observations", "export", "--reference", reference_path],
    ));
    assert_eq!(projected["evidence"], indexed_reference);
    assert_eq!(projected["observation"], exported["observation"]);
    assert_eq!(
        projected["reference_time_basis"],
        if projected_at == observation.observed_at {
            "native_observation_time"
        } else {
            "evaluation_millisecond_projection"
        }
    );
    let mut changed_fraction = projected_at + chrono::Duration::nanoseconds(2);
    if changed_fraction == observation.observed_at {
        changed_fraction += chrono::Duration::nanoseconds(1);
    }
    assert_eq!(
        changed_fraction.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        indexed_at
    );
    for (field, changed) in [
        ("observed_at", serde_json::json!(changed_fraction)),
        ("report_id", serde_json::json!("absent")),
        ("report_sequence", serde_json::json!(999)),
        (
            "report_digest",
            serde_json::json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("observation_ordinal", serde_json::json!(999)),
        ("observed_at", serde_json::json!("2000-01-01T00:00:00Z")),
    ] {
        let mut substituted = exact.clone();
        substituted[field] = changed;
        fs::write(&reference, serde_json::to_vec(&substituted).unwrap()).unwrap();
        assert!(
            !run(
                nq,
                &config_path,
                &["observations", "export", "--reference", reference_path]
            )
            .status
            .success(),
            "{field} substitution must refuse"
        );
    }
    let mut extra = exact.clone();
    extra["current"] = serde_json::json!(true);
    fs::write(&reference, serde_json::to_vec(&extra).unwrap()).unwrap();
    assert!(
        !run(
            nq,
            &config_path,
            &["observations", "export", "--reference", reference_path]
        )
        .status
        .success()
    );
    fs::write(&reference, serde_json::to_vec(&exact).unwrap()).unwrap();

    let findings = success(run(nq, &config_path, &["findings", "export"]));
    assert_eq!(findings, serde_json::json!([]));

    let status = success(run(nq, &config_path, &["status", "export"]));
    assert_eq!(status["schema"], "nq.status_snapshot.v3");
    let instance = status["components"]
        .as_array()
        .and_then(|components| {
            components
                .iter()
                .find(|component| component["kind"] == "instance")
        })
        .expect("instance status component");
    assert_eq!(instance["state"], "healthy");

    let queried = run(
        nq,
        &config_path,
        &[
            "query",
            "SELECT * FROM public_status_snapshot_v1",
            "--limit",
            "10",
        ],
    );
    assert!(!queried.status.success());
    assert!(
        String::from_utf8_lossy(&queried.stderr)
            .contains("nq.status_snapshot.v1 cannot emit governed collection results; use v3")
    );

    let revoked = success(run(
        nq,
        &config_path,
        &["watcher", "revoke", "conformance.primary"],
    ));
    assert_eq!(revoked["outcome"], "revoked");
    assert!(!admissions.join("conformance.primary.json").exists());
    assert_eq!(
        success(run(
            nq,
            &config_path,
            &["observations", "export", "--reference", reference_path]
        )),
        exported
    );
    let retained = revoked["retained_lock"]
        .as_str()
        .expect("retained lock path")
        .to_owned();
    assert!(Path::new(&retained).is_file());

    let refused = run(nq, &config_path, &["collect", "conformance.primary"]);
    assert!(!refused.status.success());
    let refused_json: Value =
        serde_json::from_slice(&refused.stdout).expect("refused collection JSON");
    assert_eq!(refused_json["schema"], "nq.collection_outcome.v1");
    assert_eq!(refused_json["result"]["outcome"], "admission_refused");

    let rolled_back = success(run(
        nq,
        &config_path,
        &["watcher", "rollback", "conformance.primary", &retained],
    ));
    assert_eq!(rolled_back["outcome"], "rolled_back");
    assert!(admissions.join("conformance.primary.json").is_file());
    let recollected = success(run(nq, &config_path, &["collect", "conformance.primary"]));
    assert_eq!(recollected["schema"], "nq.collection_outcome.v2");
    assert_eq!(recollected["result"]["outcome"], "admitted");

    nq_store::Store::open(&database)
        .expect("open database through library for integrity assertion")
        .validate()
        .expect("black-box-created database remains valid");
}
