//! A watcher admitted through the `nq` CLI must be collectable and evaluable
//! by `nqd`. Admission binds the admitting process's executable as the
//! evaluator, so `nqd` must run the same artifact (it execs `nq daemon`).
//! The profile has a detector: the conformance profile has none, which is
//! how the separate-binary defect stayed hidden.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn nq_command(nq: &str, config: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new(nq);
    command.arg("--config").arg(config).args(arguments);
    command
}

fn host_helper(nq: &str) -> Option<PathBuf> {
    let path = Path::new(nq).parent()?.join("nq-host-helper");
    path.is_file().then_some(path)
}

#[test]
#[allow(clippy::too_many_lines)]
fn nqd_evaluates_a_detector_watcher_admitted_by_the_nq_cli() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let nqd = env!("CARGO_BIN_EXE_nqd");
    let Some(helper) = host_helper(nq) else {
        eprintln!("skipping: nq-host-helper is not built beside nq (run the workspace tests)");
        return;
    };
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let config_path = root.join("nq.toml");
    fs::write(
        &config_path,
        format!(
            r#"schema = "nq.config.v1"
database_path = "{db}"
socket_path = "{sock}"
admissions_dir = "{adm}"
helper_runtime_dir = "{run}"

[[watchers]]
instance_id = "host-local"
carrier = "stdio"
subject = "host:daemon-evaluator-test"
capability_ceiling = ["read_procfs", "read_system_info"]
checkpoint_policy = "disabled"

[watchers.command]
executable = "{helper}"
args = []
env = {{}}
execution_account = "{uid}"
allow_same_identity_in_debug = true
working_directory = "{root}"

[watchers.profile]
id = "nq.host"
version = 1

[watchers.scope]
kind = "host"
value = {{ id = "daemon-evaluator-test" }}

[watchers.vantage]
kind = "local"
value = {{}}

[watchers.schedule]
interval_seconds = 60
jitter_seconds = 0
deadline_ms = 5000
retry_backoff_seconds = 1
max_retry_backoff_seconds = 10

[watchers.resources]
max_response_bytes = 1048576
max_stderr_bytes = 65536
max_observations = 1
max_address_space_bytes = 536870912
max_cpu_seconds = 60
max_processes = 32
max_open_files = 128
max_file_bytes = 67108864
"#,
            db = root.join("nq.db").display(),
            sock = root.join("nqd.sock").display(),
            adm = root.join("admissions").display(),
            run = root.join("helpers").display(),
            helper = helper.display(),
            uid = nix::unistd::geteuid().as_raw(),
            root = root.display(),
        ),
    )
    .expect("configuration");

    let initialized = nq_command(nq, &config_path, &["init"])
        .output()
        .expect("init");
    assert!(
        initialized.status.success(),
        "init: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let admitted = nq_command(nq, &config_path, &["watcher", "admit", "host-local"])
        .output()
        .expect("admit");
    if !admitted.status.success()
        && String::from_utf8_lossy(&admitted.stderr).contains("spawn_failed")
        && fs::read_to_string("/proc/self/attr/current")
            .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
    {
        eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
        return;
    }
    assert!(
        admitted.status.success(),
        "admit: {}",
        String::from_utf8_lossy(&admitted.stderr)
    );

    let collected = Command::new(nqd)
        .arg("--config")
        .arg(&config_path)
        .arg("--once")
        .env("RUST_LOG", "info")
        .output()
        .expect("nqd --once");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&collected.stdout),
        String::from_utf8_lossy(&collected.stderr)
    );
    assert!(
        !log.contains("uses evaluator artifact"),
        "nqd refused the CLI admission's evaluator binding:\n{log}"
    );
    assert!(collected.status.success(), "nqd --once failed:\n{log}");
    assert!(
        log.contains("collection admitted")
            && log.contains(r#""outcome":"admitted""#)
            && log.contains(r#""schema":"nq.evaluation_envelope.v2""#)
            && log.contains(r#""evaluator_artifact_digest":"sha256:"#),
        "nqd did not admit and evaluate the watcher:\n{log}"
    );
}
