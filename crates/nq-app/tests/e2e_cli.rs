//! Black-box contract tests through the shipped `nq` binary.

mod support;

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
fn init_admit_and_public_exports_use_only_shipped_surfaces() {
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
        r#"schema = "nq.config.v2"
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

[watchers.invocation]
deadline_ms = 5000

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

    let retired_init = run(nq, &config_path, &["init"]);
    assert!(!retired_init.status.success());
    assert!(
        String::from_utf8_lossy(&retired_init.stderr)
            .contains("requires the governed HostRoleRuntime authority path")
    );
    assert!(!database.exists(), "retired init must not create a Store");
    support::initialize_gen4_test_store(&config_path);

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

    for ungoverned in [
        &["collect", "conformance.primary"][..],
        &["diagnostics", "execute", "conformance.primary"][..],
        &["diagnostics", "run", "conformance.primary"][..],
    ] {
        let refused = run(nq, &config_path, ungoverned);
        assert!(
            !refused.status.success(),
            "unratified invocation surface unexpectedly executed: {ungoverned:?}"
        );
    }

    let findings = success(run(nq, &config_path, &["findings", "export"]));
    assert_eq!(findings, serde_json::json!([]));

    let status = success(run(nq, &config_path, &["status", "export"]));
    assert_eq!(status["schema"], "nq.status_snapshot.v3");
    assert!(
        status["components"]
            .as_array()
            .is_some_and(|components| components
                .iter()
                .all(|component| component["kind"] != "instance")),
        "admission alone must not fabricate a diagnostic instance result"
    );

    let revoked = success(run(
        nq,
        &config_path,
        &["watcher", "revoke", "conformance.primary"],
    ));
    assert_eq!(revoked["outcome"], "revoked");
    assert!(!admissions.join("conformance.primary.json").exists());
    let retained = revoked["retained_lock"]
        .as_str()
        .expect("retained lock path")
        .to_owned();
    assert!(Path::new(&retained).is_file());

    let rolled_back = success(run(
        nq,
        &config_path,
        &["watcher", "rollback", "conformance.primary", &retained],
    ));
    assert_eq!(rolled_back["outcome"], "rolled_back");
    assert!(admissions.join("conformance.primary.json").is_file());

    nq_store::Store::open(&database)
        .expect("open database through library for integrity assertion")
        .validate()
        .expect("black-box-created database remains valid");
}
