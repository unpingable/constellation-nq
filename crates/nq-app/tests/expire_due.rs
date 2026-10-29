//! `nq admin expire-due`: the scheduled ordinary-history expiry a local
//! successor acquisition would run, exposed so a caller can run it before it
//! seals an occurrence. Exercised through the shipped binary with a
//! one-second horizon (a 60 s expiry quantum).

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use serde_json::Value;

const LOAD_HELPER: &str = include_str!("fixtures/host_load.py");
const INSTANCE: &str = "expire.due";

struct Fixture {
    _directory: tempfile::TempDir,
    config: PathBuf,
    load: PathBuf,
}

fn command(fixture: &Fixture, arguments: &[&str], phases: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nq"));
    command
        .arg("--config")
        .arg(&fixture.config)
        .arg("--json")
        .args(arguments);
    if phases {
        command.env("NQ_DIAGNOSTIC_PHASE_TIMING", "1");
    }
    command.output().expect("shipped nq binary executes")
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

/// One `admin expire-due` run with phase timing: (report, phases on stderr).
fn expire_due(fixture: &Fixture) -> (Value, String) {
    let output = command(fixture, &["admin", "expire-due"], true);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let report = success(output);
    assert_eq!(report["schema"], "nq.admin.expire_due.v1", "{report}");
    assert_conforms(&report);
    (report, stderr)
}

/// The persisted schedule hint `doctor` derives from the committed cutoff.
fn last_committed(fixture: &Fixture) -> Value {
    success(command(fixture, &["doctor"], false))["expiry_schedule"]["last_committed_at"].clone()
}

/// Every actual report has exactly the shape of the shared vector's report
/// with the same attempt: the same fields, each of the same JSON type, and
/// the same scope.
fn assert_conforms(report: &Value) {
    fn shape(value: &Value) -> Vec<(String, &'static str)> {
        value
            .as_object()
            .expect("report object")
            .iter()
            .map(|(field, value)| {
                let kind = match value {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Number(number) if number.is_u64() => "unsigned",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                };
                (field.clone(), kind)
            })
            .collect()
    }
    let vector: Value = serde_json::from_str(include_str!("fixtures/expire_due_report_v1.json"))
        .expect("shared vector");
    let expected = vector["reports"]
        .as_array()
        .expect("vector reports")
        .iter()
        .find(|expected| expected["attempt"] == report["attempt"])
        .unwrap_or_else(|| panic!("attempt outside the shared vector: {report}"));
    assert_eq!(shape(report), shape(expected), "{report}");
    assert_eq!(report["scope"], expected["scope"], "{report}");
}

fn ran_phase(stderr: &str, phase: &str) -> bool {
    stderr.contains(&format!("phase={phase} event=start"))
}

/// A due completion commits exactly when the retention generation advances;
/// only then does the persisted cutoff move and the schedule clear. Deleted
/// rows are not the commit signal: floors can move with none deleted.
/// Returns whether the attempt committed.
fn assert_completed_invariants(report: &Value, before_hint: &Value, after_hint: &Value) -> bool {
    assert_eq!(report["attempt"], "completed", "{report}");
    assert_eq!(report["scope"], "engine_validated_expiry", "{report}");
    let before = report["generation_before"]
        .as_i64()
        .expect("generation_before");
    let after = report["generation_after"]
        .as_i64()
        .expect("generation_after");
    if after == before {
        assert_eq!(
            after_hint, before_hint,
            "no commit leaves the persisted cutoff: {report}"
        );
        assert_eq!(
            report["scheduled_expiry_pending"], true,
            "no committed cutoff: the next acquisition would still be due: {report}"
        );
        false
    } else {
        assert!(after > before, "{report}");
        assert_ne!(
            after_hint, before_hint,
            "a commit records a new cutoff: {report}"
        );
        assert_eq!(report["scheduled_expiry_pending"], false, "{report}");
        true
    }
}

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
subject = "host:expire-due"
scope = {{ kind = "host", value = {{ id = "expire-due" }} }}
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
        config,
        load,
    };
    success(command(&fixture, &["init"], false));
    let tested = command(&fixture, &["watcher", "test", INSTANCE], false);
    if !tested.status.success()
        && String::from_utf8_lossy(&tested.stderr).contains("spawn_failed")
        && fs::read_to_string("/proc/self/attr/current")
            .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
    {
        eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
        return None;
    }
    success(tested);
    success(command(&fixture, &["watcher", "admit", INSTANCE], false));
    Some(fixture)
}

fn collect(fixture: &Fixture, load: f64) {
    std::thread::sleep(Duration::from_millis(1_100));
    fs::write(&fixture.load, format!("{load}\n")).expect("write load");
    success(command(fixture, &["collect", INSTANCE], false));
}

#[test]
#[allow(clippy::too_many_lines)]
fn admin_expire_due_commits_once_per_quantum_and_states_its_scope() {
    let Some(fixture) = fixture() else {
        return;
    };

    // No committed expiry yet: the attempt is due and runs through the
    // engine. The generation and persisted cutoff classify whether it
    // committed.
    let hint = last_committed(&fixture);
    let (initial, phases) = expire_due(&fixture);
    let committed = assert_completed_invariants(&initial, &hint, &last_committed(&fixture));
    eprintln!(
        "no-op characterisation (empty history): committed={committed} snapshot_validation_ran={}",
        ran_phase(&phases, "expiry.snapshot_validation")
    );

    // Ordinary collections keep their own expiry behaviour and commit one.
    collect(&fixture, 8.0);
    collect(&fixture, 1.0);
    let doctor = success(command(&fixture, &["doctor"], false));
    assert!(
        doctor["expiry_schedule"]["last_committed_at"].is_string(),
        "fixture precondition: a collection committed an expiry: {doctor}"
    );

    // Inside the quantum: deferred from the persisted schedule alone, with no
    // engine open and no expiry attempt, and no validation claim.
    let (deferred, phases) = expire_due(&fixture);
    assert_eq!(deferred["attempt"], "deferred", "{deferred}");
    assert_eq!(deferred["scope"], "schedule_hint_only", "{deferred}");
    assert_eq!(deferred["scheduled_expiry_pending"], false, "{deferred}");
    assert!(
        deferred["next_attempt_in_seconds"].as_u64().is_some(),
        "{deferred}"
    );
    assert!(
        !ran_phase(&phases, "core.expiry_attempt") && !ran_phase(&phases, "expiry.prefix_probe"),
        "a deferred run attempts nothing: {phases}"
    );

    // Past the quantum: the due attempt commits and clears the schedule.
    std::thread::sleep(Duration::from_secs(61));
    let hint = last_committed(&fixture);
    let (due, phases) = expire_due(&fixture);
    assert!(
        assert_completed_invariants(&due, &hint, &last_committed(&fixture)),
        "fixture precondition: the aged collection history commits: {due}"
    );
    assert!(ran_phase(&phases, "core.expiry_attempt"), "{phases}");

    // The commit is the persisted hint: the next run defers at once.
    let (again, _) = expire_due(&fixture);
    assert_eq!(again["attempt"], "deferred", "{again}");
    let doctor = success(command(&fixture, &["doctor"], false));
    assert_eq!(
        doctor["retention"]["generation"].as_i64(),
        due["generation_after"].as_i64(),
        "{doctor}"
    );
    // Readers reopen on the new boundary.
    success(command(&fixture, &["status", "export"], false));

    // No-op characterisation after aged history: another quantum with no new
    // collection. Whatever the plan finds, the invariants hold; whether the
    // snapshot validation ran (the costly no-op kind) is reported.
    std::thread::sleep(Duration::from_secs(61));
    let hint = last_committed(&fixture);
    let (later, phases) = expire_due(&fixture);
    let committed = assert_completed_invariants(&later, &hint, &last_committed(&fixture));
    eprintln!(
        "no-op characterisation (aged history): committed={committed} deleted_rows={} snapshot_validation_ran={} candidate_validation_ran={}",
        later["deleted_rows"],
        ran_phase(&phases, "expiry.snapshot_validation"),
        ran_phase(&phases, "expiry.candidate_validation")
    );
}
