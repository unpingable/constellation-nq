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

[[witnesses]]
instance_id = "conformance.primary"
subject = "conformance:fixture-e2e"
scope = {{ kind = "fixture", value = {{ id = "fixture-e2e", nonce = "e2e-nonce" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = []

[witnesses.command]
executable = "{}"
execution_account = "{}"
allow_same_identity_in_debug = true
working_directory = "{}"

[witnesses.profile]
id = "nq.conformance"
version = 1

[witnesses.schedule]
interval_seconds = 60
jitter_seconds = 0
deadline_ms = 5000
retry_backoff_seconds = 1
max_retry_backoff_seconds = 10

[witnesses.resources]
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
        &["witness", "test", "conformance.primary"],
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
        &["witness", "admit", "conformance.primary"],
    ));
    assert_eq!(admitted["outcome"], "activated");
    assert!(admissions.join("conformance.primary.json").is_file());

    let collected = success(run(nq, &config_path, &["collect", "conformance.primary"]));
    assert_eq!(collected["outcome"], "admitted");
    assert_eq!(collected["report_status"], "complete");

    let findings = success(run(nq, &config_path, &["findings", "export"]));
    assert_eq!(findings, serde_json::json!([]));

    let status = success(run(nq, &config_path, &["status", "export"]));
    assert_eq!(status["schema"], "nq.status_snapshot.v1");
    let instance = status["components"]
        .as_array()
        .and_then(|components| {
            components
                .iter()
                .find(|component| component["kind"] == "instance")
        })
        .expect("instance status component");
    assert_eq!(instance["state"], "healthy");

    let queried = success(run(
        nq,
        &config_path,
        &[
            "query",
            "SELECT * FROM public_status_snapshot_v1",
            "--limit",
            "10",
        ],
    ));
    assert!(queried.as_array().is_some_and(|rows| rows.len() >= 4));

    let revoked = success(run(
        nq,
        &config_path,
        &["witness", "revoke", "conformance.primary"],
    ));
    assert_eq!(revoked["outcome"], "revoked");
    assert!(!admissions.join("conformance.primary.json").exists());
    let retained = revoked["retained_lock"]
        .as_str()
        .expect("retained lock path")
        .to_owned();
    assert!(Path::new(&retained).is_file());

    let refused = run(nq, &config_path, &["collect", "conformance.primary"]);
    assert!(!refused.status.success());
    let refused_json: Value =
        serde_json::from_slice(&refused.stdout).expect("refused collection JSON");
    assert_eq!(refused_json["outcome"], "admission_refused");

    let rolled_back = success(run(
        nq,
        &config_path,
        &["witness", "rollback", "conformance.primary", &retained],
    ));
    assert_eq!(rolled_back["outcome"], "rolled_back");
    assert!(admissions.join("conformance.primary.json").is_file());
    let recollected = success(run(nq, &config_path, &["collect", "conformance.primary"]));
    assert_eq!(recollected["outcome"], "admitted");

    nq_store::Store::open(&database)
        .expect("open database through library for integrity assertion")
        .validate()
        .expect("black-box-created database remains valid");
}
