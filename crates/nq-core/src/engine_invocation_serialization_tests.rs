//! Admission mutation remains serialized with an already-bound invocation.
//!
//! This qualification used to drive the shipped `nqd --once` bypass. It now
//! exercises the same lock boundary entirely inside nq-core, where raw
//! collection is available only to tests.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use nq_profiles::resolve_profile;
use nq_store::Store;

use crate::config::NqConfig;
use crate::engine::{CollectionEngine, append_profile_descriptor};

const DELAY_HOOK: &str = r#"_connection: socket.socket | None = None

if os.environ.get("NQ_CONCURRENCY_MARKER"):
    with open(os.environ["NQ_CONCURRENCY_MARKER"], "w", encoding="utf-8") as marker:
        marker.write("started")
    time.sleep(0.9)
"#;

fn concurrency_config(root: &Path, helper_path: &Path, marker: &Path) -> NqConfig {
    NqConfig::from_toml(&format!(
        r#"schema = "nq.config.v2"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"

[[watchers]]
instance_id = "concurrent.primary"
subject = "conformance:concurrent"
scope = {{ kind = "fixture", value = {{ id = "concurrent", nonce = "serialized" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = []

[watchers.command]
executable = "{}"
env = {{ NQ_CONCURRENCY_MARKER = "{}" }}
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
        root.join("nq.db").display(),
        root.join("nqd.sock").display(),
        root.join("admissions").display(),
        root.join("helpers").display(),
        helper_path.display(),
        marker.display(),
        nix::unistd::geteuid().as_raw(),
        root.display(),
    ))
    .expect("configuration")
}

#[test]
fn bound_collection_and_revocation_are_serialized_without_a_shipped_bypass() {
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let helper_path = root.join("slow_helper.py");
    let marker = root.join("helper-started");
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../helpers/python-conformance/nq_conformance_helper.py");
    let source = fs::read_to_string(source_path).expect("Python specimen source");
    let needle = "_connection: socket.socket | None = None\n";
    let slow_source = source.replacen(needle, DELAY_HOOK, 1);
    assert_ne!(slow_source, source, "test delay hook inserted");
    fs::write(&helper_path, slow_source).expect("slow helper copy");
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o755))
        .expect("helper executable mode");

    let config = concurrency_config(root, &helper_path, &marker);
    fs::create_dir(root.join("admissions")).expect("admissions directory");
    fs::set_permissions(root.join("admissions"), fs::Permissions::from_mode(0o700))
        .expect("admissions mode");
    fs::create_dir(root.join("helpers")).expect("helper runtime directory");
    fs::set_permissions(root.join("helpers"), fs::Permissions::from_mode(0o711))
        .expect("helper runtime mode");
    let profile = resolve_profile("nq.conformance", 1).expect("compiled profile");
    let mut store = Store::initialize(root.join("nq.db")).expect("initialize store");
    append_profile_descriptor(&mut store, profile).expect("append profile descriptor");
    drop(store);

    let watcher = config
        .watcher("concurrent.primary")
        .expect("configured watcher")
        .clone();
    let mut admission_engine = CollectionEngine::open(&config).expect("open admission engine");
    let admission = admission_engine.watcher_action(&watcher, "admit");
    if admission.as_ref().is_err_and(|error| {
        error.to_string().contains("spawn_failed")
            && fs::read_to_string("/proc/self/attr/current")
                .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
    }) {
        eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
        return;
    }
    admission.expect("dry collection and admission succeed");
    fs::remove_file(&marker).expect("remove admission marker");
    drop(admission_engine);

    let collection_config = config.clone();
    let collection_watcher = watcher.clone();
    let collection = thread::spawn(move || {
        let mut engine =
            CollectionEngine::open(&collection_config).expect("open collection engine");
        engine
            .collect(&collection_watcher)
            .expect("bounded collection")
    });

    let wait_started = Instant::now();
    while !marker.exists() && wait_started.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists(), "collection helper never started");

    let revoke_config = config.clone();
    let revoke_watcher = watcher.clone();
    let revoke_started = Instant::now();
    let revoke = thread::spawn(move || {
        let mut engine = CollectionEngine::open(&revoke_config).expect("open revoke engine");
        engine
            .revoke_binding(&revoke_watcher)
            .expect("revoke binding")
    });
    thread::sleep(Duration::from_millis(200));
    assert!(
        !revoke.is_finished(),
        "revocation overtook an already-bound collection"
    );

    collection.join().expect("collection thread");
    revoke.join().expect("revocation thread");
    assert!(
        revoke_started.elapsed() >= Duration::from_millis(650),
        "revocation did not wait for the bounded collection"
    );
    assert!(!root.join("admissions/concurrent.primary.json").exists());

    let store = Store::open(root.join("nq.db")).expect("open resulting store");
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
