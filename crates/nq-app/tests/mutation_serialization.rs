//! Hostile black-box concurrency checks across independent `nq` processes.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

fn command(nq: &str, config: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new(nq);
    command.arg("--config").arg(config).args(arguments);
    command
}

fn daemon_command(nqd: &str, config: &Path) -> Command {
    let mut command = Command::new(nqd);
    command.arg("--config").arg(config).arg("--once");
    command
}

fn success(output: &Output) -> bool {
    output.status.success()
}

#[test]
#[allow(clippy::too_many_lines)]
fn daemon_collection_and_cli_revocation_are_serialized_across_processes() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let nqd = env!("CARGO_BIN_EXE_nqd");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let config_path = root.join("nq.toml");
    let helper_path = root.join("slow_helper.py");
    let marker = root.join("helper-started");
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../helpers/python-conformance/nq_conformance_helper.py");
    let source = fs::read_to_string(source_path).expect("Python specimen source");
    let needle = "_connection: socket.socket | None = None\n";
    let replacement = r#"_connection: socket.socket | None = None

if os.environ.get("NQ_CONCURRENCY_MARKER"):
    with open(os.environ["NQ_CONCURRENCY_MARKER"], "w", encoding="utf-8") as marker:
        marker.write("started")
    time.sleep(0.9)
"#;
    let slow_source = source.replacen(needle, replacement, 1);
    assert_ne!(slow_source, source, "test delay hook inserted");
    fs::write(&helper_path, slow_source).expect("slow helper copy");
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o755))
        .expect("helper executable mode");

    fs::write(
        &config_path,
        format!(
            r#"schema = "nq.config.v1"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"

[[witnesses]]
instance_id = "concurrent.primary"
subject = "conformance:concurrent"
scope = {{ kind = "fixture", value = {{ id = "concurrent", nonce = "serialized" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = []

[witnesses.command]
executable = "{}"
env = {{ NQ_CONCURRENCY_MARKER = "{}" }}
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
            root.join("nq.db").display(),
            root.join("nqd.sock").display(),
            root.join("admissions").display(),
            root.join("helpers").display(),
            helper_path.display(),
            marker.display(),
            nix::unistd::geteuid().as_raw(),
            root.display(),
        ),
    )
    .expect("configuration");

    let initialized = command(nq, &config_path, &["init"])
        .output()
        .expect("initialize command");
    assert!(success(&initialized));
    let admitted = command(
        nq,
        &config_path,
        &["witness", "admit", "concurrent.primary"],
    )
    .output()
    .expect("admission command");
    if !success(&admitted)
        && String::from_utf8_lossy(&admitted.stderr).contains("spawn_failed")
        && fs::read_to_string("/proc/self/attr/current")
            .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
    {
        eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
        return;
    }
    assert!(
        success(&admitted),
        "admission failed: {}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    fs::remove_file(&marker).expect("remove admission marker");

    let collection = daemon_command(nqd, &config_path)
        .spawn()
        .expect("collection process");
    let wait_started = Instant::now();
    while !marker.exists() && wait_started.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists(), "collection helper never started");

    let revoke_started = Instant::now();
    let mut revoke = command(
        nq,
        &config_path,
        &["witness", "revoke", "concurrent.primary"],
    )
    .spawn()
    .expect("revocation process");
    thread::sleep(Duration::from_millis(200));
    assert!(
        revoke.try_wait().expect("poll revocation").is_none(),
        "revocation overtook an already-bound collection"
    );

    let collection_output = collection.wait_with_output().expect("collection output");
    assert!(
        success(&collection_output),
        "collection failed: {}",
        String::from_utf8_lossy(&collection_output.stderr)
    );
    let revoke_output = revoke.wait_with_output().expect("revocation output");
    assert!(
        success(&revoke_output),
        "revocation failed: {}",
        String::from_utf8_lossy(&revoke_output.stderr)
    );
    assert!(
        revoke_started.elapsed() >= Duration::from_millis(650),
        "revocation did not wait for the bounded collection"
    );
    assert!(!root.join("admissions/concurrent.primary.json").exists());

    let store = nq_store::Store::open(root.join("nq.db")).expect("open resulting store");
    assert_eq!(
        store
            .latest_binding("concurrent.primary")
            .expect("binding query")
            .expect("binding event")
            .event_kind,
        "revoke"
    );
    assert!(
        store
            .pending_binding_materialization("concurrent.primary")
            .expect("materialization query")
            .is_none()
    );
}
