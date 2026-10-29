//! NQ #27 declared protected holes, end to end through the shipped surfaces:
//! a finding opens, is confirmed over several collections, resolves, its
//! notification custody reaches a terminal state, and expiry cycles (each
//! `nq collect` attempts expiry with a one-second horizon) reclaim its
//! closure. Every consumer that reads across the declared gap either handles
//! it or refuses naming the boundary.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use nq_store::{
    CanonicalDocument, NotificationAttemptInput, NotificationDeliveryEventInput,
    NotificationDeliveryIntentInput, NotificationInput, Store,
};
use serde_json::{Value, json};

/// A host-profile helper whose one-minute load comes from a file, so a test
/// can open (8.0 on 4 CPUs) and resolve (1.0) the load-pressure finding.
const LOAD_HELPER: &str = include_str!("fixtures/host_load.py");

const INSTANCE: &str = "retention.lifecycle";

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    database: PathBuf,
    load: PathBuf,
}

fn nq() -> &'static str {
    env!("CARGO_BIN_EXE_nq")
}

fn run(fixture: &Fixture, arguments: &[&str]) -> Output {
    Command::new(nq())
        .arg("--config")
        .arg(&fixture.config)
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

fn document(value: &Value) -> CanonicalDocument {
    CanonicalDocument::from_serializable(value).expect("fixture document")
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Initialize and admit the watcher; `None` when the sandbox cannot execute
/// helpers here (the same skip the other end-to-end tests apply).
fn fixture() -> Option<Fixture> {
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path().to_path_buf();
    let database = root.join("nq.db");
    let script = root.join("load_helper.py");
    let load = root.join("load");
    fs::write(&script, LOAD_HELPER).expect("write helper");
    fs::write(&load, "8.0\n").expect("write load");
    let config = root.join("nq.toml");
    fs::write(
        &config,
        format!(
            r#"schema = "nq.config.v1"
database_path = "{database}"
socket_path = "{socket}"
admissions_dir = "{admissions}"
helper_runtime_dir = "{helpers}"

[retention]
horizon_seconds = 1

[[watchers]]
instance_id = "{INSTANCE}"
subject = "host:retention-lifecycle"
scope = {{ kind = "host", value = {{ id = "retention-lifecycle" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = ["read_procfs", "read_system_info"]

[watchers.command]
executable = "/usr/bin/python3"
args = ["{script}"]
env = {{ NQ_TEST_LOAD_FILE = "{load}" }}
execution_account = "{uid}"
allow_same_identity_in_debug = true
working_directory = "{root}"

[watchers.profile]
id = "nq.host"
version = 1
"#,
            database = database.display(),
            socket = root.join("nqd.sock").display(),
            admissions = root.join("admissions").display(),
            helpers = root.join("helpers").display(),
            script = script.display(),
            load = load.display(),
            uid = nix::unistd::geteuid().as_raw(),
            root = root.display(),
        ),
    )
    .expect("write config");
    let fixture = Fixture {
        _directory: directory,
        root,
        config,
        database,
        load,
    };
    success(run(&fixture, &["init"]));
    let tested = run(&fixture, &["watcher", "test", INSTANCE]);
    if !tested.status.success()
        && String::from_utf8_lossy(&tested.stderr).contains("spawn_failed")
        && fs::read_to_string("/proc/self/attr/current")
            .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
    {
        eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
        return None;
    }
    success(tested);
    success(run(&fixture, &["watcher", "admit", INSTANCE]));
    Some(fixture)
}

/// One collection with the given load, after the previous history aged past
/// the one-second horizon (so this collection's expiry attempt is due).
fn collect(fixture: &Fixture, load: f64) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(&fixture.load, format!("{load}\n")).expect("write load");
    let output = run(fixture, &["collect", INSTANCE]);
    assert!(
        output.status.success(),
        "collect failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// (revision, kind, evaluation source_expired, event_id), in revision order.
fn finding_events(database: &Path) -> Vec<(i64, String, i64, String)> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("probe");
    let mut statement = connection
        .prepare("SELECT f.event_revision, f.event_kind, e.source_expired, f.event_id FROM finding_events f JOIN evaluation_runs e ON e.evaluation_id=f.evaluation_id ORDER BY f.event_revision")
        .expect("finding query");
    statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("finding rows")
}

fn notification(id: &str, event: &str) -> NotificationInput {
    NotificationInput {
        notification_id: id.to_owned(),
        idempotency_key: format!("key-{id}"),
        finding_event_id: Some(event.to_owned()),
        destination_kind: "fixture".into(),
        payload: document(&json!({"fixture": id})),
        available_at: now(),
        max_attempts: 3,
        created_at: now(),
    }
}

fn intent(store: &mut Store, id: &str, event: &str) {
    store
        .retain_notification_delivery(
            &notification(id, event),
            &NotificationDeliveryIntentInput {
                notification_id: id.to_owned(),
                stable_event_id: event.to_owned(),
                attention_kind: "operator_assertion".into(),
                attention_receipt_digest: None,
                attention_policy_id: "fixture-policy".into(),
                attention_policy_digest: nq_protocol::sha256_bytes(b"policy").as_str().to_owned(),
                transition_id: format!("transition-{id}"),
                route_reference: "fixture-route".into(),
                destination_identity: "fixture-destination".into(),
                content_digest: nq_protocol::sha256_bytes(id.as_bytes()).as_str().to_owned(),
                intent: document(&json!({"fixture": id})),
                created_at: now(),
            },
        )
        .expect("delivery intent");
}

fn delivery_event(store: &mut Store, id: &str, number: u32, outcome: &str) {
    store
        .append_notification_delivery_event(&NotificationDeliveryEventInput {
            notification_id: id.to_owned(),
            event_number: number,
            occurred_at: now(),
            outcome: outcome.into(),
            detail: document(&json!({})),
        })
        .expect("delivery event");
}

/// GET `path` from the shipped local API serving this database.
fn api_get(fixture: &Fixture, path: &str) -> (u16, Value) {
    let socket = fixture.root.join("api.sock");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let server = runtime.spawn(nq_app::api::serve_unix(
        socket.clone(),
        fixture.database.clone(),
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !socket.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).expect("connect API");
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: local\r\n\r\n").as_bytes())
        .expect("request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("response");
    server.abort();
    drop(runtime);
    let _ = fs::remove_file(&socket);
    let text = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("HTTP response");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

#[test]
#[allow(clippy::too_many_lines)]
fn resolved_finding_closure_is_reclaimed_and_every_reader_declares_the_gap() {
    let Some(fixture) = fixture() else {
        return;
    };
    // Opened, then confirmed by two more present collections.
    collect(&fixture, 8.0);
    let opened = finding_events(&fixture.database);
    assert_eq!(opened.len(), 1, "{opened:?}");
    assert_eq!(opened[0].1, "opened");
    // Notification custody for the opening event, pending while the finding
    // is confirmed. (The typed delivery-intent path is exercised by the
    // unknown-custody test below and by the nq-core custody tests; a fixture
    // intent document is not an archivable typed intent.)
    {
        let mut store = Store::open(&fixture.database).expect("store");
        store
            .enqueue_notification(&notification("lifecycle-legacy", &opened[0].3))
            .expect("legacy outbox");
    }
    collect(&fixture, 8.0);
    collect(&fixture, 8.0);
    // Resolved.
    collect(&fixture, 1.0);
    let events = finding_events(&fixture.database);
    assert_eq!(
        events
            .iter()
            .map(|event| event.1.as_str())
            .collect::<Vec<_>>(),
        ["opened", "updated", "updated", "resolved"],
        "{events:?}"
    );
    assert_eq!(
        events[0].2, 0,
        "pending custody keeps the opening closure: {events:?}"
    );
    // Custody reaches terminal states.
    {
        let mut store = Store::open(&fixture.database).expect("store");
        store
            .append_notification_attempt(&NotificationAttemptInput {
                notification_id: "lifecycle-legacy".into(),
                attempt_number: 1,
                attempted_at: now(),
                outcome: "delivered".into(),
                delivery_identity: None,
                detail: document(&json!({})),
            })
            .expect("legacy delivered");
    }
    // Expiry cycles: every later collection attempts expiry.
    collect(&fixture, 1.0);
    collect(&fixture, 1.0);
    collect(&fixture, 1.0);

    // The closure is compacted; the finding's own history rows are intact.
    let events = finding_events(&fixture.database);
    assert_eq!(
        events.len(),
        4,
        "finding events are never deleted: {events:?}"
    );
    assert!(
        events.iter().all(|event| event.2 == 1),
        "every released decision is a compact record: {events:?}"
    );

    let doctor = success(run(&fixture, &["doctor"]));
    let retention = &doctor["retention"];
    assert!(retention["generation"].as_i64().unwrap() > 0, "{doctor}");
    assert_eq!(
        retention["islands_by_root"]["released_pending"], 0,
        "{doctor}"
    );
    assert_eq!(
        retention["islands_by_root"]["notification_custody"], 0,
        "{doctor}"
    );
    assert_eq!(retention["custody_pending_events"], 0, "{doctor}");
    assert!(
        retention["compact_evaluations"].as_i64().unwrap() >= 4,
        "{doctor}"
    );
    let residue = &retention["residue"];
    assert_eq!(residue["compact_evaluations"], retention["compact_evaluations"], "{doctor}");
    assert!(residue["compact_raw_submissions"].as_i64().unwrap() >= 1, "{doctor}");
    assert!(residue["anchor_runs"].as_i64().unwrap() >= 1, "{doctor}");
    assert!(residue["finding_events"].as_i64().unwrap() >= 4, "{doctor}");
    assert!(
        doctor["expiry_schedule"]["quantum_seconds"]
            .as_u64()
            .is_some(),
        "{doctor}"
    );

    // Status export still reports the lineage, with its last evaluation.
    let status = success(run(&fixture, &["status", "export"]));
    let lineage = status["components"]
        .as_array()
        .expect("components")
        .iter()
        .find(|component| component["kind"] == "evaluation")
        .unwrap_or_else(|| panic!("the lineage stays in status: {status}"));
    assert_eq!(lineage["code"], "condition_explicitly_absent", "{lineage}");
    assert!(
        lineage["observed_at"].is_string(),
        "last-evaluated time: {lineage}"
    );

    // Findings export reports the resolved finding with its decision marked
    // as made from a source that has since expired.
    let findings = success(run(&fixture, &["findings", "export"]));
    let finding = findings
        .as_array()
        .expect("findings")
        .first()
        .unwrap_or_else(|| panic!("the resolved finding is reported: {findings}"))
        .clone();
    assert_eq!(
        finding["condition"]["state"], "explicitly_absent",
        "{finding}"
    );
    assert_eq!(finding["source_expired"], true, "{finding}");

    // The first evaluations page names the floor and a contiguous resume.
    let (code, gone) = api_get(&fixture, "/v1/evaluations?limit=10");
    assert_eq!(code, 410, "{gone}");
    assert_eq!(gone["error"], "history_expired");
    let floor = gone["expired_through_evaluation_sequence"]
        .as_i64()
        .unwrap();
    let through = gone["resume"]["through_sequence"].as_i64().unwrap();
    assert_eq!(gone["resume"]["after_sequence"].as_i64(), Some(floor));
    let (code, page) = api_get(
        &fixture,
        &format!("/v1/evaluations?limit=100&after={floor}&through={through}"),
    );
    assert_eq!(code, 200, "{page}");
    let sequences: Vec<i64> = page["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|record| record["sequence"].as_i64().expect("sequence"))
        .collect();
    assert_eq!(
        sequences,
        ((floor + 1)..=through).collect::<Vec<_>>(),
        "the resume page is contiguous from the floor"
    );
    // The CLI export refuses naming the boundary and the resume interval.
    let refused = run(&fixture, &["evaluations", "export"]);
    assert!(!refused.status.success());
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        message.contains("history_expired") && message.contains(&format!("--after {floor}")),
        "{message}"
    );

    // Explicit deep validation is full and reports bounded coverage.
    let validated = success(run(&fixture, &["admin", "validate", "--full"]));
    assert_eq!(validated["validated"], "full");
    assert_eq!(validated["history"]["coverage"], "bounded");

    // The archive declares the boundary and never claims complete history.
    let archive = fixture.root.join("archive");
    success(run(
        &fixture,
        &[
            "admin",
            "archive",
            "--destination",
            archive.to_str().unwrap(),
        ],
    ));
    let metadata: Value =
        serde_json::from_slice(&fs::read(archive.join("ARCHIVE.json")).unwrap()).unwrap();
    assert_eq!(metadata["complete_history"], false, "{metadata}");
    assert!(metadata["retention"]["generation"].as_i64().unwrap() > 0);
    assert!(
        metadata["retention"]["compact_counts"]["evaluations"]
            .as_i64()
            .unwrap()
            >= 4
    );
    assert!(metadata["retention"]["islands_by_root"].is_object());
    let verified = Command::new(archive.join("bin/nq"))
        .args(["--json", "admin", "archive-verify"])
        .arg(&archive)
        .output()
        .expect("archived verifier");
    let verified = success(verified);
    assert_eq!(verified["historical_complete_history"], false, "{verified}");
}

#[test]
fn unknown_notification_custody_keeps_its_island_through_every_expiry() {
    let Some(fixture) = fixture() else {
        return;
    };
    collect(&fixture, 8.0);
    let opened = finding_events(&fixture.database);
    {
        let mut store = Store::open(&fixture.database).expect("store");
        intent(&mut store, "lifecycle-unknown", &opened[0].3);
        delivery_event(&mut store, "lifecycle-unknown", 1, "claimed");
        delivery_event(&mut store, "lifecycle-unknown", 2, "unknown");
    }
    collect(&fixture, 1.0);
    for _ in 0..3 {
        collect(&fixture, 1.0);
    }
    let events = finding_events(&fixture.database);
    assert_eq!(events[0].1, "opened");
    assert_eq!(
        events[0].2, 0,
        "unknown custody keeps the opening closure full: {events:?}"
    );
    let doctor = success(run(&fixture, &["doctor"]));
    let retention = &doctor["retention"];
    assert!(retention["generation"].as_i64().unwrap() > 0, "{doctor}");
    assert_eq!(retention["custody_unknown_events"], 1, "{doctor}");
    assert!(
        retention["islands_by_root"]["notification_custody"]
            .as_i64()
            .unwrap()
            >= 1,
        "{doctor}"
    );
}
