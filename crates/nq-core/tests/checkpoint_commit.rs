//! Checkpoints advance only through a committed admitted report.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nq_core::config::NqConfig;
use nq_core::engine::{
    CollectionEngine, CollectionResult, GovernedRefusalOrigin, append_profile_descriptor,
    checkpoint_contract_digest, validate_compiled_config,
};
use nq_profiles::resolve_profile;
use nq_store::Store;
use serde_json::{Value, json};

// This end-to-end test drives the real engine, so evaluator identity comes from
// the platform provider (`CollectionEngine::open`) exactly as in production —
// there is no fabricated fixture identity to inject.

const CHECKPOINT_HELPER: &str = r#"#!/usr/bin/python3
import datetime
import json
import os
import pathlib
import sys

state_path = pathlib.Path(os.environ["CHECKPOINT_STATE"])
log_path = pathlib.Path(os.environ["CHECKPOINT_LOG"])
try:
    sequence = int(state_path.read_text(encoding="utf-8")) + 1
except FileNotFoundError:
    sequence = 1
state_path.write_text(str(sequence), encoding="utf-8")

request = json.load(sys.stdin)
with log_path.open("a", encoding="utf-8") as log:
    json.dump(
        {"sequence": sequence, "checkpoint": request.get("checkpoint")},
        log,
        sort_keys=True,
        separators=(",", ":"),
    )
    log.write("\n")

observed_at = (
    datetime.datetime.now(datetime.timezone.utc)
    .isoformat(timespec="microseconds")
    .replace("+00:00", "Z")
)
binding = request["binding"]
nonce = binding["scope"]["value"]["nonce"]
candidate = {
    1: "dry-candidate",
    2: "admitted-1",
    3: "rejected-candidate",
    4: "admitted-2",
    5: "admitted-3",
}.get(sequence, f"admitted-{sequence}")

report = {
    "schema": "nq.evidence_report.v1",
    "profile": request["profile"],
    "binding": binding,
    "observed_at": observed_at,
    "status": "complete",
    "coverage": [{"kind": "echo", "state": "complete"}],
    "observations": [{
        "ordinal": 0,
        "kind": "echo",
        "subject": binding["subject"],
        "observed_at": observed_at,
        "payload": {
            "evidence_basis": {
                "scope": binding["scope"],
                "vantage": binding["vantage"],
                "access_path": "process",
                "basis": "request_echo",
                "regime": "conformance",
                "capabilities_used": [],
            },
            "nonce": nonce,
        },
    }],
    "errors": [],
    "used_capabilities": [],
    "backend": {
        "implementation": {"name": "checkpoint-fixture", "version": "1"},
        "tools": [],
    },
    "next_checkpoint": {"value": {"cursor": candidate}},
}

# This remains a valid protocol report, but compiled profile validation rejects
# it. Its candidate checkpoint must therefore never become request state.
if sequence == 3:
    report["observations"][0]["payload"]["nonce"] = "wrong-nonce"

echo = dict(request)
del echo["schema"]
response = {
    "schema": "nq.helper.response.v1",
    "echo": echo,
    "outcome": {"kind": "report", "report": report},
}
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
"#;

fn checkpoint_config(root: &Path) -> NqConfig {
    let state_root = root.join("state");
    let runtime_root = root.join("run");
    let database = state_root.join("nq.db");
    let helper = root.join("checkpoint_helper.py");
    let state = root.join("helper.state");
    let log = root.join("requests.ndjson");
    NqConfig::from_toml(&format!(
        r#"schema = "nq.config.v2"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"

[[watchers]]
instance_id = "checkpoint.primary"
subject = "conformance:checkpoint"
scope = {{ kind = "fixture", value = {{ id = "checkpoint", nonce = "expected-nonce" }} }}
vantage = {{ kind = "local", value = {{}} }}
checkpoint_policy = "advance_after_admission"

[watchers.command]
executable = "/usr/bin/python3"
args = ["{}"]
env = {{ CHECKPOINT_STATE = "{}", CHECKPOINT_LOG = "{}" }}
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
max_observations = 1
max_address_space_bytes = 536870912
max_cpu_seconds = 60
max_processes = 32
max_open_files = 128
max_file_bytes = 67108864
"#,
        database.display(),
        runtime_root.join("nqd.sock").display(),
        state_root.join("admissions").display(),
        runtime_root.join("helpers").display(),
        helper.display(),
        state.display(),
        log.display(),
        nix::unistd::geteuid().as_raw(),
        root.display(),
    ))
    .expect("valid test configuration")
}

fn assert_checkpoint_sequence(log: &Path) {
    let requests: Vec<Value> = fs::read_to_string(log)
        .expect("read helper request log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("logged request JSON"))
        .collect();
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[0]["checkpoint"], Value::Null); // admission dry run
    assert_eq!(requests[1]["checkpoint"], Value::Null); // dry candidate was not committed
    assert_eq!(
        requests[2]["checkpoint"],
        json!({"value": {"cursor": "admitted-1"}})
    );
    assert_eq!(
        requests[3]["checkpoint"],
        json!({"value": {"cursor": "admitted-1"}}),
        "the rejected candidate must not replace the admitted checkpoint"
    );
    assert_eq!(
        requests[4]["checkpoint"],
        json!({"value": {"cursor": "admitted-2"}})
    );
    assert_eq!(
        requests[5]["checkpoint"],
        Value::Null,
        "rotation dry collection never receives an active cursor"
    );
    assert_eq!(
        requests[6]["checkpoint"],
        Value::Null,
        "a new admission cannot inherit the preceding admission's cursor"
    );
}

#[test]
fn only_committed_admitted_reports_advance_the_next_request_checkpoint() {
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("state").join("nq.db");
    let helper = root.join("checkpoint_helper.py");
    let log = root.join("requests.ndjson");
    fs::write(&helper, CHECKPOINT_HELPER).expect("write checkpoint helper");

    let config = checkpoint_config(root);
    validate_compiled_config(&config).expect("compiled profile accepts binding");
    let state_root = database.parent().expect("database parent");
    fs::create_dir(state_root).expect("create state root");
    fs::set_permissions(state_root, fs::Permissions::from_mode(0o700)).expect("state root mode");
    fs::create_dir(&config.admissions_dir).expect("create admissions root");
    fs::set_permissions(&config.admissions_dir, fs::Permissions::from_mode(0o700))
        .expect("admissions root mode");
    let runtime_root = config
        .helper_runtime_dir
        .parent()
        .expect("helper runtime parent");
    fs::create_dir(runtime_root).expect("create runtime root");
    fs::set_permissions(runtime_root, fs::Permissions::from_mode(0o751))
        .expect("runtime root mode");
    fs::create_dir(&config.helper_runtime_dir).expect("create helper runtime root");
    fs::set_permissions(
        &config.helper_runtime_dir,
        fs::Permissions::from_mode(0o711),
    )
    .expect("helper runtime root mode");

    let profile = resolve_profile("nq.conformance", 1).expect("compiled conformance profile");
    let mut store = Store::initialize(&database).expect("initialize test store");
    append_profile_descriptor(&mut store, profile).expect("append profile descriptor");
    drop(store);

    let watcher = config
        .watcher("checkpoint.primary")
        .expect("configured watcher")
        .clone();
    let mut engine = CollectionEngine::open(&config).expect("open collection engine");
    let admission = engine.watcher_action(&watcher, "admit");
    if admission.as_ref().is_err_and(|error| {
        error.to_string().contains("spawn_failed")
            && fs::read_to_string("/proc/self/attr/current")
                .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
    }) {
        eprintln!("skipping: sandbox AppArmor denies executable memfds");
        return;
    }
    admission.expect("dry collection and admission succeed");

    assert!(matches!(
        engine.collect(&watcher).expect("first collection").result,
        CollectionResult::Admitted { .. }
    ));
    assert!(matches!(
        engine.collect(&watcher).expect("rejected collection").result,
        CollectionResult::Rejected { refusal }
            if matches!(refusal.origin, GovernedRefusalOrigin::Profile(_))
    ));
    assert!(matches!(
        engine
            .collect(&watcher)
            .expect("second admitted collection")
            .result,
        CollectionResult::Admitted { .. }
    ));
    assert!(matches!(
        engine
            .collect(&watcher)
            .expect("third admitted collection")
            .result,
        CollectionResult::Admitted { .. }
    ));
    engine
        .watcher_action(&watcher, "rotate")
        .expect("rotation obtains a new admission binding");
    assert!(matches!(
        engine
            .collect(&watcher)
            .expect("post-rotation collection")
            .result,
        CollectionResult::Admitted { .. }
    ));
    drop(engine);

    assert_checkpoint_sequence(&log);

    let store = Store::open(&database).expect("reopen test store");
    let manager = nq_core::AdmissionManager;
    let lock = manager
        .load(&config.admissions_dir.join("checkpoint.primary.json"))
        .expect("active lock");
    let binding_digest = manager.binding_digest(&lock).expect("binding digest");
    let profile_digest = profile.descriptor().digest().expect("profile digest");
    let contract =
        checkpoint_contract_digest(&watcher, &lock, &binding_digest, profile_digest.as_str())
            .expect("checkpoint contract");
    let latest: Value = serde_json::from_slice(
        &store
            .latest_checkpoint("checkpoint.primary", &contract)
            .expect("query latest checkpoint")
            .expect("latest checkpoint exists"),
    )
    .expect("stored checkpoint JSON");
    assert_eq!(latest, json!({"cursor": "admitted-7"}));
}
