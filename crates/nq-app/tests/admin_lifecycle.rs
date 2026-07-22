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

struct UpgradeReceipt {
    from_version: i64,
    to_version: i64,
    result: String,
    backup_digest: String,
    backup_location: String,
    migrations_json: String,
    verification_json: String,
}

fn read_only_upgrade_receipt(database: &Path) -> UpgradeReceipt {
    let connection = Connection::open(database).expect("open upgraded database");
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM upgrade_receipts", [], |row| {
            row.get(0)
        })
        .expect("count upgrade receipts");
    assert_eq!(count, 1, "upgrade must append exactly one receipt");
    connection
        .query_row(
            "SELECT from_schema_version, to_schema_version, result,
                    backup_digest, backup_location,
                    CAST(migrations_json AS TEXT), CAST(verification_json AS TEXT)
             FROM upgrade_receipts",
            [],
            |row| {
                Ok(UpgradeReceipt {
                    from_version: row.get(0)?,
                    to_version: row.get(1)?,
                    result: row.get(2)?,
                    backup_digest: row.get(3)?,
                    backup_location: row.get(4)?,
                    migrations_json: row.get(5)?,
                    verification_json: row.get(6)?,
                })
            },
        )
        .expect("read durable upgrade receipt")
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
    let status_before = success(run(nq, &config, &["status", "export"]));
    let findings_before = success(run(nq, &config, &["findings", "export"]));

    let backup = root.join("manual-backup.db");
    let backup_result = success(run(nq, &config, &["backup", backup.to_str().unwrap()]));
    assert_eq!(backup_result["verified"], true);
    assert_eq!(backup_result["sha256"], sha256_file(&backup));
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

    let backup = PathBuf::from(upgraded["backup"].as_str().unwrap());
    let backup_digest = upgraded["backup_digest"].as_str().unwrap();
    assert_eq!(sha256_file(&backup), backup_digest);
    assert_eq!(
        nq_store::Store::database_schema_version(&backup).expect("inspect v3 backup"),
        3
    );
    assert!(matches!(
        nq_store::Store::open(&backup),
        Err(nq_store::StoreError::SchemaVersionMismatch {
            found: 3,
            supported: nq_store::SCHEMA_VERSION,
        })
    ));

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

    let receipt = read_only_upgrade_receipt(&database);
    assert_eq!(receipt.from_version, 3);
    assert_eq!(receipt.to_version, nq_store::SCHEMA_VERSION);
    assert_eq!(receipt.result, "migrated");
    assert_eq!(receipt.backup_digest, backup_digest);
    assert_eq!(receipt.backup_location, backup.display().to_string());
    assert_eq!(
        serde_json::from_str::<Value>(&receipt.migrations_json).unwrap(),
        serde_json::json!(["schema_v3_to_v4_provider_intake"])
    );
    let verification: Value = serde_json::from_str(&receipt.verification_json).unwrap();
    assert_eq!(verification["provider_intakes_synthesized"], false);
    assert_eq!(verification["acknowledgments_synthesized"], false);

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
