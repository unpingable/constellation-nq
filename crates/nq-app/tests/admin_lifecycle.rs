//! Black-box administrative lifecycle checks through the shipped `nq` binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn run(nq: &str, config: &Path, arguments: &[&str]) -> Output {
    Command::new(nq)
        .arg("--config")
        .arg(config)
        .arg("--json")
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

#[allow(clippy::needless_pass_by_value)]
fn failure(output: Output) -> String {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8(output.stderr).expect("diagnostic must be UTF-8")
}

fn write_config(root: &Path, name: &str, database: &Path) -> PathBuf {
    let path = root.join(format!("{name}.toml"));
    let contents = format!(
        r#"schema = "nq.config.v1"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"
"#,
        database.display(),
        root.join(format!("{name}.sock")).display(),
        root.join(format!("{name}-admissions")).display(),
        root.join(format!("{name}-helpers")).display(),
    );
    fs::write(&path, contents).expect("write test configuration");
    path
}

fn sha256_file(path: &Path) -> String {
    let digest = Sha256::digest(fs::read(path).expect("read digest input"));
    format!("sha256:{digest:x}")
}

fn write_fixture(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).expect("write exact diagnostic artifact fixture");
    path
}

fn artifact_id(bytes: &[u8]) -> String {
    serde_json::from_slice::<Value>(bytes).expect("fixture is JSON")["artifact_id"]
        .as_str()
        .expect("fixture artifact identity")
        .to_owned()
}

const HOST_DIAGNOSTIC_HELPER: &str = r#"import datetime
import json
import os
import sys

request = json.load(sys.stdin)
echo = dict(request)
del echo["schema"]
observed_at = (
    datetime.datetime.now(datetime.timezone.utc)
    .isoformat(timespec="microseconds")
    .replace("+00:00", "Z")
)
binding = request["binding"]
capabilities = request["granted_capabilities"]
report = {
    "schema": "nq.evidence_report.v1",
    "profile": request["profile"],
    "binding": binding,
    "observed_at": observed_at,
    "status": "complete",
    "coverage": [
        {"kind": "host_identity", "state": "complete"},
        {"kind": "uptime", "state": "complete"},
        {"kind": "load", "state": "complete"},
    ],
    "observations": [{
        "ordinal": 0,
        "kind": "host_snapshot",
        "subject": binding["subject"],
        "observed_at": observed_at,
        "payload": {
            "evidence_basis": {
                "scope": binding["scope"],
                "vantage": binding["vantage"],
                "access_path": "procfs_sysinfo",
                "basis": "kernel_snapshot",
                "regime": "normal",
                "capabilities_used": capabilities,
            },
            "hostname": "diagnostic-fixture",
            "uptime_seconds": 3600,
            "cpu_count": 4,
            "load_1m": 1.0,
        },
    }],
    "errors": [],
    "used_capabilities": capabilities,
    "backend": {
        "implementation": {"name": "host-diagnostic-fixture", "version": "1"},
        "tools": [],
    },
}
mode_path = os.environ.get("NQ_DIAGNOSTIC_TEST_MODE")
mode = ""
if mode_path:
    with open(mode_path, "r", encoding="utf-8") as source:
        mode = source.read().strip()
if mode == "helper_refusal":
    refusal = {
        "responsible_instance_id": request["instance_id"],
        "boundary": "collection",
        "code": "collection_failed",
        "message": "bounded host collection refused",
        "retriable": True,
        "details": {"errno": "EAGAIN"},
    }
    response = {
        "schema": "nq.helper.response.v1",
        "echo": echo,
        "outcome": {"kind": "refusal", "refusal": refusal},
    }
else:
    response = {
        "schema": "nq.helper.response.v1",
        "echo": echo,
        "outcome": {"kind": "report", "report": report},
    }
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
"#;

fn write_host_diagnostic_config(root: &Path, database: &Path) -> PathBuf {
    write_host_diagnostic_config_with_mode(root, database, None)
}

fn write_host_diagnostic_config_with_mode(
    root: &Path,
    database: &Path,
    mode: Option<&Path>,
) -> PathBuf {
    let helper = root.join("host-diagnostic-helper.py");
    fs::write(&helper, HOST_DIAGNOSTIC_HELPER).expect("write host diagnostic helper");
    let config = root.join("host-diagnostic.toml");
    let environment = mode.map_or_else(
        || "{}".to_owned(),
        |path| format!(r#"{{ NQ_DIAGNOSTIC_TEST_MODE = "{}" }}"#, path.display()),
    );
    fs::write(
        &config,
        format!(
            r#"schema = "nq.config.v1"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"

[[watchers]]
instance_id = "host-diagnostic.primary"
carrier = "stdio"
subject = "host:diagnostic-fixture"
capability_ceiling = ["read_procfs", "read_system_info"]
checkpoint_policy = "disabled"

[watchers.command]
executable = "/usr/bin/python3"
args = ["{}"]
env = {}
execution_account = "{}"
allow_same_identity_in_debug = true
working_directory = "{}"

[watchers.profile]
id = "nq.host"
version = 1

[watchers.scope]
kind = "host"
value = {{ id = "diagnostic-fixture" }}

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
            database.display(),
            root.join("host-diagnostic.sock").display(),
            root.join("host-diagnostic-admissions").display(),
            root.join("host-diagnostic-helpers").display(),
            helper.display(),
            environment,
            nix::unistd::geteuid().as_raw(),
            root.display(),
        ),
    )
    .expect("write host diagnostic configuration");
    config
}

#[allow(clippy::too_many_lines)] // Keep the hostile same-run commitment rewrite one auditable transaction.
fn reseal_local_v2_artifact(
    database: &Path,
    original_bytes: &[u8],
    mutate: impl FnOnce(&mut nq_core::diagnostic_execution_v2::DiagnosticExecutionV2),
) -> String {
    use nq_core::diagnostic_execution_v2::DiagnosticExecutionV2;

    let mut artifact =
        DiagnosticExecutionV2::decode_canonical(original_bytes).expect("live v2 artifact reopens");
    let old_id = artifact.artifact_id.as_digest().as_str().to_owned();
    mutate(&mut artifact);
    artifact.artifact_id = artifact
        .computed_artifact_id()
        .expect("changed artifact can be resealed");
    let changed_bytes = artifact
        .canonical_bytes()
        .expect("changed artifact remains a valid v2 contract");
    DiagnosticExecutionV2::decode_canonical(&changed_bytes)
        .expect("resealed hostile artifact strictly reopens");
    let new_id = artifact.artifact_id.as_digest().as_str().to_owned();
    assert_ne!(
        new_id, old_id,
        "hostile mutation must change artifact identity"
    );
    let full_bytes_digest = nq_protocol::sha256_bytes(&changed_bytes).into_string();
    let changed_length = i64::try_from(changed_bytes.len()).expect("artifact length fits SQLite");

    let mut connection = Connection::open(database).expect("open local artifact fixture");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("disable foreign keys for coherent identity reseal");
    let trigger_names = [
        "immutable_diagnostic_artifact_commitments_update",
        "immutable_diagnostic_artifact_payloads_update",
        "immutable_local_diagnostic_artifact_origins_update",
    ];
    let mut trigger_sql = Vec::new();
    for name in trigger_names {
        let sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("read exact trigger {name}: {error}"));
        trigger_sql.push((name, sql));
    }

    let transaction = connection
        .transaction()
        .expect("begin coherent hostile reseal transaction");
    for (name, _) in &trigger_sql {
        transaction
            .execute_batch(&format!("DROP TRIGGER \"{name}\";"))
            .unwrap_or_else(|error| panic!("drop exact trigger {name}: {error}"));
    }
    assert_eq!(
        transaction
            .execute(
                "UPDATE diagnostic_artifact_commitments
                 SET artifact_id = ?1, canonical_bytes_sha256 = ?2,
                     canonical_bytes_length = ?3
                 WHERE artifact_id = ?4",
                rusqlite::params![new_id, full_bytes_digest, changed_length, old_id],
            )
            .expect("replace exact commitment identity"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE diagnostic_artifact_payloads
                 SET artifact_id = ?1, canonical_bytes = ?2
                 WHERE artifact_id = ?3",
                rusqlite::params![new_id, changed_bytes, old_id],
            )
            .expect("replace exact payload identity and bytes"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE local_diagnostic_artifact_origins
                 SET artifact_id = ?1
                 WHERE artifact_id = ?2",
                rusqlite::params![new_id, old_id],
            )
            .expect("replace exact local origin identity"),
        1
    );
    for (name, sql) in &trigger_sql {
        transaction
            .execute_batch(&format!("{sql};"))
            .unwrap_or_else(|error| panic!("restore exact trigger {name}: {error}"));
    }
    transaction
        .commit()
        .expect("commit coherent hostile reseal");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("restore foreign key enforcement");

    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare foreign key audit");
    assert!(
        foreign_key_check
            .query([])
            .expect("run foreign key audit")
            .next()
            .expect("read foreign key audit")
            .is_none(),
        "hostile reseal must preserve relational integrity"
    );
    drop(foreign_key_check);
    for (name, expected_sql) in trigger_sql {
        let restored_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("reopen exact trigger {name}: {error}"));
        assert_eq!(restored_sql, expected_sql, "trigger {name} changed");
    }
    new_id
}

#[allow(clippy::too_many_lines)] // Keep the hostile cross-plane reseal one auditable transaction.
fn reseal_local_run_only_refusal_chain(database: &Path, original_bytes: &[u8]) -> String {
    use nq_core::GovernedRefusalOrigin;
    use nq_core::diagnostic_execution_v2::DiagnosticExecutionV2;
    use nq_store::{CanonicalDocument, Store};

    let mut artifact =
        DiagnosticExecutionV2::decode_canonical(original_bytes).expect("live v2 artifact reopens");
    let old_id = artifact.artifact_id.as_digest().as_str().to_owned();
    let run_id = artifact.run_id.as_str().to_owned();
    let [refused] = artifact.inputs.refused.as_mut_slice() else {
        panic!("run-only fixture must carry exactly one refused input");
    };
    let GovernedRefusalOrigin::Helper(helper) = &mut refused.refusal.origin else {
        panic!("run-only fixture must preserve a helper-origin refusal");
    };
    helper.retriable = false;
    helper.details = serde_json::json!({
        "errno": "ENODEV",
        "coherently_resealed": true,
    });
    let substituted_refusal = refused.refusal.clone();
    artifact.outcome.refusals = vec![substituted_refusal.clone()];
    artifact.artifact_id = artifact
        .computed_artifact_id()
        .expect("changed artifact can be resealed");
    let changed_bytes = artifact
        .canonical_bytes()
        .expect("changed artifact remains a valid v2 contract");
    DiagnosticExecutionV2::decode_canonical(&changed_bytes)
        .expect("resealed hostile artifact strictly reopens");
    let new_id = artifact.artifact_id.as_digest().as_str().to_owned();
    assert_ne!(
        new_id, old_id,
        "hostile mutation must change artifact identity"
    );
    let full_bytes_digest = nq_protocol::sha256_bytes(&changed_bytes).into_string();
    let changed_length = i64::try_from(changed_bytes.len()).expect("artifact length fits SQLite");

    let mut connection = Connection::open(database).expect("open local artifact fixture");
    let status_bytes: Vec<u8> = connection
        .query_row(
            "SELECT detail_json FROM status_events WHERE run_id = ?1",
            [&run_id],
            |row| row.get(0),
        )
        .expect("read canonical run result");
    let mut outcome: nq_core::CollectionOutcome =
        serde_json::from_slice(&status_bytes).expect("decode canonical run result");
    let nq_core::CollectionResult::Rejected { refusal } = &mut outcome.result else {
        panic!("run-only fixture must have a rejected canonical result");
    };
    *refusal = substituted_refusal.clone();
    outcome
        .validate()
        .expect("substituted canonical result remains structurally valid");
    let status_document =
        CanonicalDocument::from_serializable(&outcome).expect("canonicalize substituted result");
    let refusal_document = CanonicalDocument::from_serializable(&substituted_refusal)
        .expect("canonicalize substituted refusal");

    let acknowledgment_bytes: Vec<u8> = connection
        .query_row(
            "SELECT detail_json FROM provider_intake_acknowledgments WHERE run_id = ?1",
            [&run_id],
            |row| row.get(0),
        )
        .expect("read provider acknowledgment");
    let mut acknowledgment: Value =
        serde_json::from_slice(&acknowledgment_bytes).expect("decode provider acknowledgment");
    acknowledgment["canonical_result_digest"] = Value::String(status_document.digest().to_owned());
    let acknowledgment_document = CanonicalDocument::from_serializable(&acknowledgment)
        .expect("canonicalize substituted acknowledgment");

    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("disable foreign keys for coherent cross-plane reseal");
    let trigger_names = [
        "immutable_refusals_update",
        "immutable_status_events_update",
        "immutable_provider_intake_acknowledgments_update",
        "immutable_diagnostic_artifact_commitments_update",
        "immutable_diagnostic_artifact_payloads_update",
        "immutable_local_diagnostic_artifact_origins_update",
    ];
    let mut trigger_sql = Vec::new();
    for name in trigger_names {
        let sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("read exact trigger {name}: {error}"));
        trigger_sql.push((name, sql));
    }

    let transaction = connection
        .transaction()
        .expect("begin coherent cross-plane reseal transaction");
    for (name, _) in &trigger_sql {
        transaction
            .execute_batch(&format!("DROP TRIGGER \"{name}\";"))
            .unwrap_or_else(|error| panic!("drop exact trigger {name}: {error}"));
    }
    assert_eq!(
        transaction
            .execute(
                "UPDATE refusals SET detail_json = ?1 WHERE refusal_id = ?2",
                rusqlite::params![refusal_document.as_bytes(), substituted_refusal.refusal_id],
            )
            .expect("replace exact typed refusal"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE status_events SET detail_json = ?1 WHERE run_id = ?2",
                rusqlite::params![status_document.as_bytes(), run_id],
            )
            .expect("replace exact canonical run result"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE provider_intake_acknowledgments
                 SET detail_json = ?1, acknowledgment_digest = ?2
                 WHERE run_id = ?3",
                rusqlite::params![
                    acknowledgment_document.as_bytes(),
                    acknowledgment_document.digest(),
                    run_id
                ],
            )
            .expect("reseal exact provider acknowledgment"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE diagnostic_artifact_commitments
                 SET artifact_id = ?1, canonical_bytes_sha256 = ?2,
                     canonical_bytes_length = ?3
                 WHERE artifact_id = ?4",
                rusqlite::params![new_id, full_bytes_digest, changed_length, old_id],
            )
            .expect("replace exact commitment identity"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE diagnostic_artifact_payloads
                 SET artifact_id = ?1, canonical_bytes = ?2
                 WHERE artifact_id = ?3",
                rusqlite::params![new_id, changed_bytes, old_id],
            )
            .expect("replace exact payload identity and bytes"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE local_diagnostic_artifact_origins
                 SET artifact_id = ?1
                 WHERE artifact_id = ?2",
                rusqlite::params![new_id, old_id],
            )
            .expect("replace exact local origin identity"),
        1
    );
    for (name, sql) in &trigger_sql {
        transaction
            .execute_batch(&format!("{sql};"))
            .unwrap_or_else(|error| panic!("restore exact trigger {name}: {error}"));
    }
    transaction
        .commit()
        .expect("commit coherent cross-plane reseal");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("restore foreign key enforcement");

    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare foreign key audit");
    assert!(
        foreign_key_check
            .query([])
            .expect("run foreign key audit")
            .next()
            .expect("read foreign key audit")
            .is_none(),
        "hostile reseal must preserve relational integrity"
    );
    drop(foreign_key_check);
    for (name, expected_sql) in trigger_sql {
        let restored_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("reopen exact trigger {name}: {error}"));
        assert_eq!(restored_sql, expected_sql, "trigger {name} changed");
    }
    drop(connection);

    let store =
        Store::open_read_only(database).expect("coherently resealed store stays structural");
    nq_core::engine::validate_diagnostic_artifact_history(&store)
        .expect("artifact-only reopening trusts the coherently resealed downstream result");
    let provider_error = nq_core::engine::validate_provider_intake_history(&store)
        .expect_err("raw provider interpretation must reject the downstream substitution");
    assert!(
        provider_error.to_string().contains("does not correspond"),
        "unexpected provider correspondence refusal: {provider_error}"
    );
    new_id
}

struct SemanticMutation {
    name: &'static str,
    mutate: fn(&mut nq_core::diagnostic_execution_v2::DiagnosticExecutionV2),
    expected_field: &'static str,
}

struct UpgradeReceipt {
    from_version: i64,
    to_version: i64,
    result: String,
    backup_digest: String,
    backup_location: String,
    migrations_json: String,
    verification_json: String,
}

fn read_only_upgrade_receipts(database: &Path) -> Vec<UpgradeReceipt> {
    let connection = Connection::open(database).expect("open upgraded database");
    let mut statement = connection
        .prepare(
            "SELECT from_schema_version, to_schema_version, result,
                    backup_digest, backup_location,
                    CAST(migrations_json AS TEXT), CAST(verification_json AS TEXT)
             FROM upgrade_receipts
             ORDER BY from_schema_version, to_schema_version",
        )
        .expect("prepare durable upgrade receipt query");
    statement
        .query_map([], |row| {
            Ok(UpgradeReceipt {
                from_version: row.get(0)?,
                to_version: row.get(1)?,
                result: row.get(2)?,
                backup_digest: row.get(3)?,
                backup_location: row.get(4)?,
                migrations_json: row.get(5)?,
                verification_json: row.get(6)?,
            })
        })
        .expect("read durable upgrade receipts")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("decode durable upgrade receipts")
}

fn read_only_upgrade_receipt(database: &Path) -> UpgradeReceipt {
    let mut receipts = read_only_upgrade_receipts(database);
    assert_eq!(receipts.len(), 1, "upgrade must append exactly one receipt");
    receipts.pop().expect("one receipt exists")
}

fn write_exact_v3_database(path: &Path, include_historical_run: bool) {
    let connection = Connection::open(path).expect("create exact v3 fixture");
    connection
        .execute_batch(include_str!("../../nq-store/src/schema_v3.sql"))
        .expect("install qualified v3 schema");
    connection
        .execute(
            "INSERT INTO schema_metadata (
                singleton, product, schema_version, schema_artifact_digest, initialized_at
             ) VALUES (1, 'nq-ng', 3, ?1, '2026-07-20T12:00:00.000Z')",
            [nq_store::SCHEMA_V3_ARTIFACT_DIGEST],
        )
        .expect("record exact v3 schema identity");
    if include_historical_run {
        let digest_a = format!("sha256:{}", "a".repeat(64));
        let digest_b = format!("sha256:{}", "b".repeat(64));
        connection
            .execute(
                "INSERT INTO watcher_runs (
                    run_id, request_id, instance_id, admission_id, binding_digest,
                    checkpoint_contract_digest, profile_id, profile_version,
                    profile_digest, carrier, started_at, deadline_at, finished_at,
                    acquisition_outcome, execution_identity_json, resource_outcome_json
                 ) VALUES (
                    'v3-run', 'v3-request', 'v3-instance', NULL, ?1, ?2,
                    'nq.conformance', '1', ?1, 'stdio',
                    '2026-07-20T12:00:00.000Z', '2026-07-20T12:00:01.000Z',
                    '2026-07-20T12:00:00.500Z', 'spawn_failed', X'7B7D', X'7B7D'
                 )",
                rusqlite::params![digest_a, digest_b],
            )
            .expect("insert historical v3 run");
        connection
            .execute_batch(
                "INSERT INTO status_events (
                    status_event_id, component_kind, component_id, run_id, state,
                    code, detail_json, observed_at
                 ) VALUES (
                    'v3-status', 'instance', 'v3-instance', 'v3-run', 'degraded',
                    'spawn_failed', X'7B7D', '2026-07-20T12:00:00.500Z'
                 );
                 INSERT INTO status_current (
                    component_kind, component_id, latest_status_event_id
                 ) VALUES ('instance', 'v3-instance', 'v3-status');",
            )
            .expect("insert historical v3 result");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn backup_restore_and_already_current_upgrade_are_verified_and_non_destructive() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("nq.db");
    let config = write_config(root, "active", &database);

    assert_eq!(success(run(nq, &config, &["init"]))["initialized"], true);
    let doctor = success(run(nq, &config, &["doctor"]));
    assert_eq!(doctor["diagnostic_artifacts"]["state"], "empty");
    assert_ne!(doctor["diagnostic_artifacts"]["state"], "current");
    let status_before = success(run(nq, &config, &["status", "export"]));
    let findings_before = success(run(nq, &config, &["findings", "export"]));

    let backup = root.join("manual-backup.db");
    let backup_result = success(run(nq, &config, &["backup", backup.to_str().unwrap()]));
    assert_eq!(backup_result["verified"], true);
    assert_eq!(backup_result["sha256"], sha256_file(&backup));
    assert_eq!(backup_result["diagnostic_artifacts"]["commitments"], 0);
    assert_eq!(
        backup_result["diagnostic_artifacts"]["structurally_preserved"],
        true
    );
    assert_eq!(
        backup_result["diagnostic_artifacts"]["all_required_bytes_available"],
        true
    );
    nq_store::Store::open(&backup)
        .expect("manual backup opens")
        .validate()
        .expect("manual backup validates");
    let backup_bytes = fs::read(&backup).expect("snapshot manual backup");
    assert!(
        failure(run(nq, &config, &["backup", backup.to_str().unwrap()])).contains("already exists")
    );
    assert_eq!(fs::read(&backup).unwrap(), backup_bytes);

    let restored = root.join("restored.db");
    let restore_result = success(run(
        nq,
        &config,
        &[
            "restore",
            backup.to_str().unwrap(),
            restored.to_str().unwrap(),
        ],
    ));
    assert_eq!(restore_result["sha256"], backup_result["sha256"]);
    assert_eq!(
        restore_result["diagnostic_artifacts"],
        backup_result["diagnostic_artifacts"]
    );
    let restored_bytes = fs::read(&restored).expect("snapshot restored database");
    assert!(
        failure(run(
            nq,
            &config,
            &[
                "restore",
                backup.to_str().unwrap(),
                restored.to_str().unwrap()
            ],
        ))
        .contains("already exists")
    );
    assert_eq!(fs::read(&restored).unwrap(), restored_bytes);

    let invalid = root.join("invalid.db");
    let invalid_destination = root.join("invalid-restore.db");
    fs::write(&invalid, b"not an nq-ng SQLite database").expect("write invalid backup");
    failure(run(
        nq,
        &config,
        &[
            "restore",
            invalid.to_str().unwrap(),
            invalid_destination.to_str().unwrap(),
        ],
    ));
    assert!(!invalid_destination.exists());

    let upgrade_directory = root.join("upgrade-backups");
    let upgraded = success(run(
        nq,
        &config,
        &[
            "admin",
            "upgrade",
            "--backup-directory",
            upgrade_directory.to_str().unwrap(),
        ],
    ));
    assert_eq!(upgraded["result"], "already_current");
    let upgrade_backup = PathBuf::from(upgraded["backup"].as_str().unwrap());
    let upgrade_digest = upgraded["backup_digest"].as_str().unwrap();
    assert_eq!(sha256_file(&upgrade_backup), upgrade_digest);
    assert_eq!(
        upgrade_backup.file_name().unwrap().to_str().unwrap(),
        format!("nq-{}.db", upgrade_digest.strip_prefix("sha256:").unwrap())
    );
    nq_store::Store::open(&upgrade_backup)
        .expect("upgrade backup opens")
        .validate()
        .expect("upgrade backup validates");
    let status_after = success(run(nq, &config, &["status", "export"]));
    assert_eq!(status_after["schema"], status_before["schema"]);
    assert_eq!(status_after["components"], status_before["components"]);
    assert_eq!(
        success(run(nq, &config, &["findings", "export"])),
        findings_before
    );

    let receipt = read_only_upgrade_receipt(&database);
    assert_eq!(receipt.from_version, nq_store::SCHEMA_VERSION);
    assert_eq!(receipt.to_version, nq_store::SCHEMA_VERSION);
    assert_eq!(receipt.result, "already_current");
    assert_eq!(receipt.backup_digest, upgrade_digest);
    assert_eq!(
        receipt.backup_location,
        upgrade_backup.display().to_string()
    );
    assert_eq!(receipt.migrations_json, "[]");
    assert_eq!(
        serde_json::from_str::<Value>(&receipt.verification_json).unwrap()["integrity"],
        "ok"
    );

    let incompatible = root.join("incompatible.db");
    fs::copy(&backup, &incompatible).expect("copy compatible artifact");
    let connection = Connection::open(&incompatible).expect("open incompatible fixture");
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .expect("disable fixture WAL");
    connection
        .pragma_update(None, "user_version", nq_store::SCHEMA_VERSION + 1)
        .expect("set incompatible schema version");
    drop(connection);
    let incompatible_before = fs::read(&incompatible).expect("snapshot incompatible database");
    let incompatible_config = write_config(root, "incompatible", &incompatible);
    let refused_directory = root.join("refused-upgrade-backups");
    let diagnostic = failure(run(
        nq,
        &incompatible_config,
        &[
            "admin",
            "upgrade",
            "--backup-directory",
            refused_directory.to_str().unwrap(),
        ],
    ));
    assert!(diagnostic.contains("database schema version"));
    assert!(diagnostic.contains("incompatible"));
    assert_eq!(fs::read(&incompatible).unwrap(), incompatible_before);
    assert_eq!(fs::read_dir(refused_directory).unwrap().count(), 0);

    // A restore source can be a verified live SQLite database. Keep a
    // committed status event only in its WAL while the CLI copies it; the
    // destination must contain that logical state rather than a stale copy of
    // the main database file.
    let wal_database = root.join("wal-source.db");
    let wal_config = write_config(root, "wal-source", &wal_database);
    success(run(nq, &wal_config, &["init"]));
    let wal_connection = Connection::open(&wal_database).expect("open live WAL source");
    wal_connection
        .execute_batch(
            "PRAGMA wal_autocheckpoint = 0;
             BEGIN IMMEDIATE;
             INSERT INTO status_events (
                 status_event_id, component_kind, component_id, state, code,
                 detail_json, observed_at
             ) VALUES (
                 'wal-only-event', 'daemon', 'wal-probe', 'healthy', 'wal_visible',
                 X'7B7D', '2026-07-16T12:00:00.000Z'
             );
             INSERT INTO status_current (
                 component_kind, component_id, latest_status_event_id
             ) VALUES ('daemon', 'wal-probe', 'wal-only-event');
             COMMIT;",
        )
        .expect("commit state to live WAL");
    let wal_destination = root.join("wal-restored.db");
    success(run(
        nq,
        &wal_config,
        &[
            "restore",
            wal_database.to_str().unwrap(),
            wal_destination.to_str().unwrap(),
        ],
    ));
    let restored_connection =
        Connection::open(&wal_destination).expect("open WAL-consistent restore");
    let restored_wal_event: i64 = restored_connection
        .query_row(
            "SELECT COUNT(*) FROM status_events WHERE status_event_id = 'wal-only-event'",
            [],
            |row| row.get(0),
        )
        .expect("query restored WAL state");
    assert_eq!(restored_wal_event, 1);
}

#[test]
fn backup_and_restore_report_preserved_artifact_custody_without_claiming_full_replay() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("custody.db");
    let config = write_config(root, "custody", &database);
    success(run(nq, &config, &["init"]));

    let mut store = nq_store::Store::open(&database).expect("open artifact store");
    let unavailable_id = nq_protocol::sha256_bytes(b"supported-unavailable-artifact");
    store
        .import_unavailable_diagnostic_artifact(
            &nq_store::UnavailableDiagnosticArtifactImportInput {
                import_id: "import:supported-unavailable".to_owned(),
                artifact_id: unavailable_id,
                contract_schema: nq_core::diagnostic_execution::DIAGNOSTIC_EXECUTION_SCHEMA
                    .to_owned(),
                canonical_bytes_sha256: nq_protocol::sha256_bytes(
                    b"unavailable-canonical-byte-commitment",
                ),
                canonical_bytes_length: 37,
                imported_at: "2026-07-28T12:00:00Z".to_owned(),
            },
        )
        .expect("commit explicit supported unavailable custody");
    drop(store);
    let unavailable_doctor = run(nq, &config, &["doctor"]);
    assert!(!unavailable_doctor.status.success());
    let unavailable_doctor_json: Value =
        serde_json::from_slice(&unavailable_doctor.stdout).expect("failed doctor emits JSON");
    assert_eq!(
        unavailable_doctor_json["diagnostic_artifacts"]["state"],
        "committed_unavailable"
    );

    let mut store = nq_store::Store::open(&database).expect("reopen artifact store");
    let unsupported_id = nq_protocol::sha256_bytes(b"unsupported-available-artifact");
    let unsupported = nq_store::CanonicalDocument::from_serializable(&serde_json::json!({
        "schema": "nq.diagnostic_execution.future",
        "artifact_id": unsupported_id.as_str(),
    }))
    .expect("canonical unsupported artifact");
    store
        .import_diagnostic_artifact(&nq_store::DiagnosticArtifactImportInput {
            import_id: "import:unsupported-available".to_owned(),
            artifact_id: unsupported_id,
            contract_schema: "nq.diagnostic_execution.future".to_owned(),
            canonical_bytes: unsupported,
            imported_at: "2026-07-28T12:01:00Z".to_owned(),
        })
        .expect("commit unsupported available custody");
    drop(store);

    let doctor = run(nq, &config, &["doctor"]);
    assert!(!doctor.status.success());
    let doctor_json: Value =
        serde_json::from_slice(&doctor.stdout).expect("failed doctor still emits JSON");
    assert_eq!(doctor_json["diagnostic_artifacts"]["state"], "unsupported");

    let backup = root.join("custody-backup.db");
    let backup_receipt = success(run(nq, &config, &["backup", backup.to_str().unwrap()]));
    let artifacts = &backup_receipt["diagnostic_artifacts"];
    assert_eq!(artifacts["commitments"], 2);
    assert_eq!(artifacts["supported_available"], 0);
    assert_eq!(artifacts["supported_committed_unavailable"], 1);
    assert_eq!(artifacts["unsupported_available"], 1);
    assert_eq!(artifacts["unsupported_committed_unavailable"], 0);
    assert_eq!(artifacts["structurally_preserved"], true);
    assert_eq!(artifacts["all_required_bytes_available"], false);
    assert_eq!(artifacts["full_replay_available"], false);

    let restored = root.join("custody-restored.db");
    let restore_receipt = success(run(
        nq,
        &config,
        &[
            "restore",
            backup.to_str().unwrap(),
            restored.to_str().unwrap(),
        ],
    ));
    assert_eq!(restore_receipt["diagnostic_artifacts"], *artifacts);
    nq_store::Store::open(&restored)
        .expect("open restored custody")
        .validate()
        .expect("structurally preserved unavailable custody validates");
}

#[test]
#[allow(clippy::too_many_lines)]
fn exact_v3_upgrade_accepts_typed_empty_history_and_refuses_semantic_or_schema_drift() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("qualified-v3.db");
    write_exact_v3_database(&database, false);
    let config = write_config(root, "qualified-v3", &database);
    let backup_directory = root.join("v3-upgrade-backups");

    let upgraded = success(run(
        nq,
        &config,
        &[
            "admin",
            "upgrade",
            "--backup-directory",
            backup_directory.to_str().unwrap(),
        ],
    ));
    assert_eq!(upgraded["result"], "migrated");
    assert_eq!(upgraded["from_schema_version"], 3);
    assert_eq!(upgraded["schema_version"], nq_store::SCHEMA_VERSION);
    assert_eq!(upgraded["historical_provider_intake"], "explicit_gap_only");

    let v3_backup = PathBuf::from(upgraded["v3_backup"].as_str().unwrap());
    let v3_backup_digest = upgraded["v3_backup_digest"].as_str().unwrap();
    assert_eq!(sha256_file(&v3_backup), v3_backup_digest);
    assert_eq!(
        nq_store::Store::database_schema_version(&v3_backup).expect("inspect v3 backup"),
        3
    );
    assert!(matches!(
        nq_store::Store::open(&v3_backup),
        Err(nq_store::StoreError::SchemaVersionMismatch {
            found: 3,
            supported: nq_store::SCHEMA_VERSION,
        })
    ));
    let v4_backup = PathBuf::from(upgraded["v4_backup"].as_str().unwrap());
    let v4_backup_digest = upgraded["v4_backup_digest"].as_str().unwrap();
    assert_eq!(sha256_file(&v4_backup), v4_backup_digest);
    assert_eq!(
        nq_store::Store::database_schema_version(&v4_backup).expect("inspect v4 backup"),
        4
    );
    let v5_backup = PathBuf::from(upgraded["v5_backup"].as_str().unwrap());
    let v5_backup_digest = upgraded["v5_backup_digest"].as_str().unwrap();
    assert_eq!(sha256_file(&v5_backup), v5_backup_digest);
    assert_eq!(
        nq_store::Store::database_schema_version(&v5_backup).expect("inspect v5 backup"),
        5
    );
    let v6_backup = PathBuf::from(upgraded["v6_backup"].as_str().unwrap());
    let v6_backup_digest = upgraded["v6_backup_digest"].as_str().unwrap();
    assert_eq!(sha256_file(&v6_backup), v6_backup_digest);
    assert_eq!(
        nq_store::Store::database_schema_version(&v6_backup).expect("inspect v6 backup"),
        6
    );
    let store = nq_store::Store::open(&database).expect("open migrated v4 store");
    store.validate().expect("validate migrated v4 store");
    assert!(
        store
            .provider_intakes_bounded(10, None)
            .expect("enumerate real intakes")
            .is_empty(),
        "migration must not invent provider intake"
    );
    let gaps = store
        .legacy_provider_intake_gaps_bounded(10, None)
        .expect("enumerate explicit v3 gaps");
    assert!(gaps.is_empty());
    drop(store);

    let receipts = read_only_upgrade_receipts(&database);
    assert_eq!(receipts.len(), 5, "v3 to v8 requires five exact receipts");
    let receipt = &receipts[0];
    assert_eq!(receipt.from_version, 3);
    assert_eq!(receipt.to_version, 4);
    assert_eq!(receipt.result, "migrated");
    assert_eq!(receipt.backup_digest, v3_backup_digest);
    assert_eq!(receipt.backup_location, v3_backup.display().to_string());
    assert_eq!(
        serde_json::from_str::<Value>(&receipt.migrations_json).unwrap(),
        serde_json::json!(["schema_v3_to_v4_provider_intake"])
    );
    let verification: Value = serde_json::from_str(&receipt.verification_json).unwrap();
    assert_eq!(verification["provider_intakes_synthesized"], false);
    assert_eq!(verification["acknowledgments_synthesized"], false);
    let receipt = &receipts[1];
    assert_eq!(receipt.from_version, 4);
    assert_eq!(receipt.to_version, 5);
    assert_eq!(receipt.result, "migrated");
    assert_eq!(receipt.backup_digest, v4_backup_digest);
    assert_eq!(receipt.backup_location, v4_backup.display().to_string());
    assert_eq!(
        serde_json::from_str::<Value>(&receipt.migrations_json).unwrap(),
        serde_json::json!(["schema_v4_to_v5_diagnostic_artifacts"])
    );
    let verification: Value = serde_json::from_str(&receipt.verification_json).unwrap();
    assert_eq!(verification["diagnostic_artifacts_synthesized"], false);
    let receipt = &receipts[2];
    assert_eq!(receipt.from_version, 5);
    assert_eq!(receipt.to_version, 6);
    assert_eq!(receipt.result, "migrated");
    assert_eq!(receipt.backup_digest, v5_backup_digest);
    assert_eq!(receipt.backup_location, v5_backup.display().to_string());
    assert_eq!(
        serde_json::from_str::<Value>(&receipt.migrations_json).unwrap(),
        serde_json::json!(["schema_v5_to_v6_continuity_prerequisites"])
    );
    let verification: Value = serde_json::from_str(&receipt.verification_json).unwrap();
    assert_eq!(verification["continuity_intents_synthesized"], false);
    let receipt = &receipts[3];
    assert_eq!(receipt.from_version, 6);
    assert_eq!(receipt.to_version, 7);
    assert_eq!(receipt.result, "migrated");
    assert_eq!(receipt.backup_digest, v6_backup_digest);
    assert_eq!(receipt.backup_location, v6_backup.display().to_string());
    assert_eq!(
        serde_json::from_str::<Value>(&receipt.migrations_json).unwrap(),
        serde_json::json!(["schema_v6_to_v7_substrate_origin"])
    );
    let verification: Value = serde_json::from_str(&receipt.verification_json).unwrap();
    assert_eq!(verification["substrate_origin_intents_synthesized"], false);
    let receipt = &receipts[4];
    assert_eq!(receipt.from_version, 7);
    assert_eq!(receipt.to_version, nq_store::SCHEMA_VERSION);
    assert_eq!(receipt.result, "migrated");
    let v7_backup = PathBuf::from(&receipt.backup_location);
    assert_eq!(sha256_file(&v7_backup), receipt.backup_digest);
    assert_eq!(
        nq_store::Store::database_schema_version(&v7_backup).expect("inspect v7 backup"),
        7
    );
    assert_eq!(
        serde_json::from_str::<Value>(&receipt.migrations_json).unwrap(),
        serde_json::json!(["schema_v7_to_v8_bounded_recurrence"])
    );
    let verification: Value = serde_json::from_str(&receipt.verification_json).unwrap();
    assert_eq!(verification["recurrence_authority_synthesized"], false);

    let semantic_invalid = root.join("semantic-invalid-v3.db");
    write_exact_v3_database(&semantic_invalid, true);
    let semantic_invalid_before = fs::read(&semantic_invalid).expect("snapshot invalid v3");
    let semantic_invalid_config = write_config(root, "semantic-invalid-v3", &semantic_invalid);
    let semantic_refused_directory = root.join("semantic-invalid-v3-backups");
    let diagnostic = failure(run(
        nq,
        &semantic_invalid_config,
        &[
            "admin",
            "upgrade",
            "--backup-directory",
            semantic_refused_directory.to_str().unwrap(),
        ],
    ));
    assert!(
        diagnostic.contains("watcher run v3-run")
            && (diagnostic.contains("resource outcome") || diagnostic.contains("admission")),
        "unexpected typed-v3 refusal: {diagnostic}"
    );
    assert_eq!(
        fs::read(&semantic_invalid).unwrap(),
        semantic_invalid_before,
        "semantic refusal must not mutate the schema-v3 source"
    );
    assert_eq!(
        nq_store::Store::database_schema_version(&semantic_invalid)
            .expect("semantic-invalid schema remains inspectable"),
        3
    );
    assert_eq!(
        fs::read_dir(&semantic_refused_directory).unwrap().count(),
        0,
        "semantic source refusal occurs before backup creation"
    );

    let modified = root.join("modified-v3.db");
    write_exact_v3_database(&modified, false);
    let connection = Connection::open(&modified).expect("open modified v3 fixture");
    connection
        .execute_batch("DROP INDEX watcher_runs_by_instance;")
        .expect("modify v3 schema shape");
    drop(connection);
    let modified_before = fs::read(&modified).expect("snapshot modified v3");
    let modified_config = write_config(root, "modified-v3", &modified);
    let refused_directory = root.join("modified-v3-backups");
    let diagnostic = failure(run(
        nq,
        &modified_config,
        &[
            "admin",
            "upgrade",
            "--backup-directory",
            refused_directory.to_str().unwrap(),
        ],
    ));
    assert!(diagnostic.contains("schema-v3 definition fingerprint"));
    assert_eq!(fs::read(&modified).unwrap(), modified_before);
    assert_eq!(fs::read_dir(refused_directory).unwrap().count(), 0);
}

#[test]
fn diagnostic_import_operation_identity_refuses_different_evidence() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("nq.db");
    let config = write_config(root, "import-conflict", &database);
    success(run(nq, &config, &["init"]));

    let first_bytes = include_bytes!(
        "../../../diagnostic-contract-v2/fixtures/valid/completed_bounded_clock.json"
    );
    let second_bytes =
        include_bytes!("../../../diagnostic-contract-v2/fixtures/valid/provider_no_response.json");
    let first = write_fixture(root, "first.json", first_bytes);
    let second = write_fixture(root, "second.json", second_bytes);
    let operation = "import:stable-operation";

    let receipt = success(run(
        nq,
        &config,
        &[
            "diagnostics",
            "import",
            first.to_str().unwrap(),
            "--import-id",
            operation,
        ],
    ));
    assert_eq!(receipt["import_id"], operation);
    assert_eq!(receipt["artifact_id"], artifact_id(first_bytes));
    assert_eq!(receipt["disposition"], "committed");

    let diagnostic = failure(run(
        nq,
        &config,
        &[
            "diagnostics",
            "import",
            second.to_str().unwrap(),
            "--import-id",
            operation,
        ],
    ));
    assert!(
        diagnostic.contains("provider intake replay conflict")
            && diagnostic.contains("was reused for different evidence"),
        "unexpected import replay refusal: {diagnostic}"
    );

    let exported = run(
        nq,
        &config,
        &["diagnostics", "export", &artifact_id(first_bytes)],
    );
    assert!(
        exported.status.success(),
        "original artifact must remain exportable after conflict: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(exported.stdout, first_bytes);
}

#[test]
#[allow(clippy::too_many_lines)]
fn diagnostic_export_import_restart_and_same_operation_replay_preserve_exact_receipt() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let source_database = root.join("source.db");
    let source_config = write_config(root, "source", &source_database);
    let target_database = root.join("target.db");
    let target_config = write_config(root, "target", &target_database);
    success(run(nq, &source_config, &["init"]));
    success(run(nq, &target_config, &["init"]));

    let fixture_bytes = include_bytes!(
        "../../../diagnostic-contract-v2/fixtures/valid/completed_unqualified_clock.json"
    );
    let fixture = write_fixture(root, "source-artifact.json", fixture_bytes);
    let source_receipt = success(run(
        nq,
        &source_config,
        &[
            "diagnostics",
            "import",
            fixture.to_str().unwrap(),
            "--import-id",
            "import:source-custody",
        ],
    ));
    let id = artifact_id(fixture_bytes);
    assert_eq!(source_receipt["artifact_id"], id);

    let exported = run(nq, &source_config, &["diagnostics", "export", id.as_str()]);
    assert!(
        exported.status.success(),
        "source export failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(exported.stdout, fixture_bytes);
    let transfer = write_fixture(root, "exported-transfer.json", &exported.stdout);
    let operation = "import:cross-store-transfer";

    let first_receipt = success(run(
        nq,
        &target_config,
        &[
            "diagnostics",
            "import",
            transfer.to_str().unwrap(),
            "--import-id",
            operation,
        ],
    ));
    assert_eq!(first_receipt["disposition"], "committed");
    assert_eq!(first_receipt["artifact_id"], id);
    assert_eq!(
        first_receipt["canonical_bytes_sha256"],
        sha256_file(&transfer)
    );

    // Every CLI invocation is a fresh process. Reissuing the exact operation
    // therefore exercises restart-safe replay rather than an in-memory cache.
    let replay_receipt = success(run(
        nq,
        &target_config,
        &[
            "diagnostics",
            "import",
            transfer.to_str().unwrap(),
            "--import-id",
            operation,
        ],
    ));
    assert_eq!(
        replay_receipt, first_receipt,
        "same-operation replay must return the original durable receipt, including its time"
    );

    let inspected = success(run(
        nq,
        &target_config,
        &["diagnostics", "inspect", id.as_str()],
    ));
    assert_eq!(inspected["lookup_state"], "found");
    assert_eq!(inspected["commitment"]["artifact_id"], id);
    assert_eq!(
        inspected["commitment"]["origin"]["import_id"],
        "import:cross-store-transfer"
    );
    assert_eq!(
        inspected["commitment"]["origin"]["imported_at"],
        first_receipt["imported_at"]
    );
    assert_eq!(inspected["byte_state"]["state"], "verified_available");
    let qualification_error = failure(run(
        nq,
        &target_config,
        &["diagnostics", "qualify", id.as_str()],
    ));
    assert!(
        qualification_error.contains("imported custody"),
        "imported bytes must not acquire local admission provenance: {qualification_error}"
    );
    let doctor = success(run(nq, &target_config, &["doctor"]));
    assert_eq!(
        doctor["diagnostic_artifacts"]["state"],
        "available_supported"
    );
    assert_ne!(doctor["diagnostic_artifacts"]["state"], "current");

    let target_export = run(nq, &target_config, &["diagnostics", "export", id.as_str()]);
    assert!(
        target_export.status.success(),
        "target export failed: {}",
        String::from_utf8_lossy(&target_export.stderr)
    );
    assert_eq!(target_export.stdout, fixture_bytes);
}

#[test]
#[allow(clippy::too_many_lines)]
fn doctor_and_restore_refuse_resealed_local_artifact_semantic_substitution() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let live_database = root.join("live.db");
    let live_config = write_host_diagnostic_config(root, &live_database);
    success(run(nq, &live_config, &["init"]));

    let admission = run(
        nq,
        &live_config,
        &["watcher", "admit", "host-diagnostic.primary"],
    );
    assert!(
        admission.status.success(),
        "host fixture admission failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&admission.stdout),
        String::from_utf8_lossy(&admission.stderr)
    );
    let execution = run(
        nq,
        &live_config,
        &["diagnostics", "execute", "host-diagnostic.primary"],
    );
    assert!(
        execution.status.success(),
        "live diagnostic execution failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&execution.stdout),
        String::from_utf8_lossy(&execution.stderr)
    );
    let original = nq_core::diagnostic_execution_v2::DiagnosticExecutionV2::decode_canonical(
        &execution.stdout,
    )
    .expect("actual CLI execution emits strict v2 bytes");
    assert_eq!(
        original
            .canonical_bytes()
            .expect("live artifact canonical bytes"),
        execution.stdout
    );
    let qualification = success(run(
        nq,
        &live_config,
        &[
            "diagnostics",
            "qualify",
            original.artifact_id.as_digest().as_str(),
        ],
    ));
    let typed_qualification: nq_core::DiagnosticAdmissionProvenanceV1 =
        serde_json::from_value(qualification.clone())
            .expect("actual nq output uses the closed admission-provenance schema");
    typed_qualification
        .validate()
        .expect("actual nq output validates as exact admission provenance");
    assert_eq!(
        qualification["schema"],
        "nq.diagnostic_admission_provenance.v1"
    );
    assert_eq!(
        qualification["artifact"]["artifact_id"],
        original.artifact_id.as_digest().as_str()
    );
    assert_eq!(
        qualification["source"]["source_id"],
        original.producer.node_id
    );
    assert_eq!(qualification["disposition"], "admitted_report");
    assert_eq!(
        qualification["provider"]["profile_semantic_id"],
        original.profile_semantic_id.as_str()
    );
    assert!(qualification["judgment"].is_object());
    let qualification_replay = success(run(
        nq,
        &live_config,
        &[
            "diagnostics",
            "qualify",
            original.artifact_id.as_digest().as_str(),
        ],
    ));
    assert_eq!(
        qualification_replay, qualification,
        "reopening the same local artifact must return the same exact admission provenance"
    );

    let pristine = root.join("pristine.db");
    success(run(
        nq,
        &live_config,
        &["backup", pristine.to_str().unwrap()],
    ));
    let mutations = [
        SemanticMutation {
            name: "claim-outcome",
            mutate: |artifact| {
                artifact.claims[0].proposition =
                    "hostile structurally-valid replacement proposition".to_owned();
                artifact.outcome.summary =
                    "hostile structurally-valid replacement summary".to_owned();
            },
            expected_field: "claims, outcome",
        },
        SemanticMutation {
            name: "subject",
            mutate: |artifact| {
                artifact.subject.id = "host:substituted-subject".to_owned();
            },
            expected_field: "provider request binding",
        },
        SemanticMutation {
            name: "vantage",
            mutate: |artifact| {
                artifact.vantage.version = "substituted-generation".to_owned();
            },
            expected_field: "vantage",
        },
        SemanticMutation {
            name: "producer-build",
            mutate: |artifact| {
                artifact.producer.build.version = "hostile-build-generation".to_owned();
                artifact.producer.build.digest =
                    nq_protocol::sha256_bytes(b"hostile producer build descriptor");
            },
            expected_field: "producer.build",
        },
        SemanticMutation {
            name: "producer-cohort",
            mutate: |artifact| {
                artifact.producer.cohort.version = "hostile-cohort-generation".to_owned();
                artifact.producer.cohort.digest =
                    nq_protocol::sha256_bytes(b"hostile producer cohort descriptor");
            },
            expected_field: "producer.cohort",
        },
        SemanticMutation {
            name: "clock-qualification",
            mutate: |artifact| {
                use nq_core::diagnostic_execution_v2::ClockQualificationV2;
                artifact.attempt_interval.qualification = ClockQualificationV2::Bounded {
                    maximum_error_ms: 1,
                    basis: nq_core::diagnostic_execution::SemanticIdentityV1 {
                        id: "hostile.clock_qualification".to_owned(),
                        version: "1".to_owned(),
                        digest: nq_protocol::sha256_bytes(b"hostile clock qualification basis"),
                    },
                };
                artifact.inputs.received[0].acquisition.qualification =
                    artifact.attempt_interval.qualification.clone();
            },
            expected_field: "attempt_interval.qualification",
        },
        SemanticMutation {
            name: "limitations",
            mutate: |artifact| artifact.limitations.clear(),
            expected_field: "limitations",
        },
        SemanticMutation {
            name: "nonclaims",
            mutate: |artifact| artifact.nonclaims.clear(),
            expected_field: "nonclaims",
        },
        SemanticMutation {
            name: "question",
            mutate: |artifact| {
                artifact.question.id = "nq.host.hostile_question".to_owned();
                artifact.question.version = "hostile-question-generation".to_owned();
                artifact.question.digest =
                    nq_protocol::sha256_bytes(b"hostile bounded question descriptor");
            },
            expected_field: "question",
        },
        SemanticMutation {
            name: "completed-at",
            mutate: |artifact| {
                artifact.completed_at = artifact.attempt_interval.ended_at;
            },
            expected_field: "completion time",
        },
    ];

    for (index, mutation) in mutations.into_iter().enumerate() {
        let database = root.join(format!("semantic-substitution-{}.db", mutation.name));
        fs::copy(&pristine, &database).expect("copy pristine logical backup");
        let hostile_id = reseal_local_v2_artifact(&database, &execution.stdout, mutation.mutate);
        let config = write_config(
            root,
            &format!("semantic-substitution-{}", mutation.name),
            &database,
        );

        let diagnostic = failure(run(nq, &config, &["doctor"]));
        assert!(
            diagnostic.contains(hostile_id.as_str())
                && diagnostic.contains(mutation.expected_field),
            "doctor did not identify {} semantic substitution: {diagnostic}",
            mutation.name
        );
        for operation in [
            vec!["diagnostics", "inspect", hostile_id.as_str()],
            vec!["diagnostics", "export", hostile_id.as_str()],
        ] {
            let diagnostic = failure(run(nq, &config, &operation));
            assert!(
                diagnostic.contains(hostile_id.as_str())
                    && diagnostic.contains(mutation.expected_field),
                "{} laundered {} through retrieval: {diagnostic}",
                operation[1],
                mutation.name
            );
        }

        let destination = root.join(format!("hostile-restore-{index}.db"));
        let restore_diagnostic = failure(run(
            nq,
            &config,
            &[
                "restore",
                database.to_str().unwrap(),
                destination.to_str().unwrap(),
            ],
        ));
        assert!(
            restore_diagnostic.contains(hostile_id.as_str())
                && restore_diagnostic.contains(mutation.expected_field),
            "restore did not identify {} semantic substitution: {restore_diagnostic}",
            mutation.name
        );
        assert!(
            !destination.exists(),
            "semantic refusal must precede restore destination creation"
        );
    }
}

#[test]
fn inspect_and_export_refuse_coherently_resealed_local_provider_result() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("provider-result-reseal.db");
    let mode = root.join("provider-result-mode");
    fs::write(&mode, "complete\n").expect("select admissible helper response");
    let config = write_host_diagnostic_config_with_mode(root, &database, Some(&mode));
    success(run(nq, &config, &["init"]));

    let admission = run(
        nq,
        &config,
        &["watcher", "admit", "host-diagnostic.primary"],
    );
    assert!(
        admission.status.success(),
        "host fixture admission failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&admission.stdout),
        String::from_utf8_lossy(&admission.stderr)
    );
    fs::write(&mode, "helper_refusal\n").expect("select run-only helper refusal");
    let execution = run(
        nq,
        &config,
        &["diagnostics", "execute", "host-diagnostic.primary"],
    );
    assert!(
        execution.status.success(),
        "run-only diagnostic execution failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&execution.stdout),
        String::from_utf8_lossy(&execution.stderr)
    );
    let original = nq_core::diagnostic_execution_v2::DiagnosticExecutionV2::decode_canonical(
        &execution.stdout,
    )
    .expect("actual CLI execution emits strict v2 bytes");
    assert_eq!(original.inputs.refused.len(), 1);
    assert!(original.claims.is_empty());
    assert!(original.primary_claim_id.is_none());

    let hostile_id = reseal_local_run_only_refusal_chain(&database, &execution.stdout);
    for operation in [
        vec!["diagnostics", "inspect", hostile_id.as_str()],
        vec!["diagnostics", "export", hostile_id.as_str()],
    ] {
        let diagnostic = failure(run(nq, &config, &operation));
        assert!(
            diagnostic.contains("does not correspond"),
            "{} laundered a provider/status/acknowledgment/artifact reseal: {diagnostic}",
            operation[1]
        );
    }
}

#[test]
fn doctor_and_restore_refuse_corrupt_supported_artifact_bytes() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let database = root.join("corrupt.db");
    let config = write_config(root, "corrupt", &database);
    success(run(nq, &config, &["init"]));

    let fixture_bytes = include_bytes!(
        "../../../diagnostic-contract-v2/fixtures/valid/completed_bounded_clock.json"
    );
    let fixture = write_fixture(root, "corruption-source.json", fixture_bytes);
    let id = artifact_id(fixture_bytes);
    success(run(
        nq,
        &config,
        &[
            "diagnostics",
            "import",
            fixture.to_str().unwrap(),
            "--import-id",
            "import:corruption-source",
        ],
    ));

    let connection = Connection::open(&database).expect("open corruption fixture");
    let trigger_name = "immutable_diagnostic_artifact_payloads_update";
    let trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            [trigger_name],
            |row| row.get(0),
        )
        .expect("read exact payload trigger");
    connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             DROP TRIGGER \"{trigger_name}\";
             UPDATE diagnostic_artifact_payloads
             SET canonical_bytes = X'7B7D'
             WHERE artifact_id = '{id}';
             {trigger_sql};
             COMMIT;"
        ))
        .expect("commit bounded payload corruption and restore exact trigger");
    let restored_trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            [trigger_name],
            |row| row.get(0),
        )
        .expect("reopen exact payload trigger");
    assert_eq!(restored_trigger_sql, trigger_sql);
    drop(connection);

    let doctor_output = run(nq, &config, &["doctor"]);
    assert!(!doctor_output.status.success());
    let doctor_json: Value =
        serde_json::from_slice(&doctor_output.stdout).expect("corrupt doctor emits JSON");
    assert_eq!(doctor_json["diagnostic_artifacts"]["state"], "corrupt");
    let doctor_diagnostic =
        String::from_utf8(doctor_output.stderr).expect("doctor diagnostic is UTF-8");
    assert!(
        doctor_diagnostic.contains(id.as_str())
            && doctor_diagnostic.contains("failed byte verification"),
        "doctor did not identify corrupt exact bytes: {doctor_diagnostic}"
    );

    let destination = root.join("corrupt-restore-destination.db");
    let restore_diagnostic = failure(run(
        nq,
        &config,
        &[
            "restore",
            database.to_str().unwrap(),
            destination.to_str().unwrap(),
        ],
    ));
    assert!(
        restore_diagnostic.contains(id.as_str())
            && restore_diagnostic.contains("failed byte verification"),
        "restore did not identify corrupt exact bytes: {restore_diagnostic}"
    );
    assert!(
        !destination.exists(),
        "corrupt source refusal must precede restore destination creation"
    );
}
