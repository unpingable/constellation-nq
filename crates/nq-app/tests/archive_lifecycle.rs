//! `nq admin archive` on a schema-v14 store through the shipped binaries: an
//! interrupted archive leaves the live store and its lock usable, a repeated
//! archive seals and verifies with its own verifier, and `nqd` restarts after.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

fn run(nq: &Path, config: &Path, arguments: &[&str]) -> Output {
    Command::new(nq)
        .arg("--config")
        .arg(config)
        .arg("--json")
        .args(arguments)
        .output()
        .expect("nq executes")
}

#[allow(clippy::needless_pass_by_value)]
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

fn member(database: &Path, suffix: &str) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn assert_lock_released(lock: &Path, inode: u64) {
    assert_eq!(
        fs::symlink_metadata(lock).expect("live lock").ino(),
        inode,
        "the live lock was replaced"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)
        .expect("open live lock");
    drop(
        nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| error)
            .expect("no process retains the live guard"),
    );
}

fn stop_records(database: &Path) -> i64 {
    rusqlite::Connection::open(database)
        .expect("open live store")
        .query_row(
            "SELECT COUNT(*) FROM status_events
             WHERE component_kind = 'daemon' AND component_id = 'nqd' AND code = 'stopped'",
            [],
            |row| row.get(0),
        )
        .expect("count stop records")
}

fn run_and_stop_nqd(config: &Path, socket: &Path) {
    let _ = fs::remove_file(socket);
    let daemon = Command::new(env!("CARGO_BIN_EXE_nqd"))
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("nqd");
    let started = Instant::now();
    while !socket.exists() && started.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "nqd never bound its socket");
    thread::sleep(Duration::from_millis(500));
    let pid = nix::unistd::Pid::from_raw(i32::try_from(daemon.id()).expect("pid"));
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).expect("SIGTERM");
    let output = daemon.wait_with_output().expect("nqd exit");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "nqd stop failed:\n{log}");
    assert!(
        log.contains("write-ahead log checkpointed at stop"),
        "{log}"
    );
}

#[test]
fn interrupted_archive_leaves_the_live_store_usable_and_a_repeat_seals() {
    let nq = PathBuf::from(env!("CARGO_BIN_EXE_nq"));
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    let database = root.join("nq.db");
    let socket = root.join("nqd.sock");
    let config = root.join("nq.toml");
    fs::write(
        &config,
        format!(
            "schema = \"nq.config.v1\"\ndatabase_path = \"{}\"\nsocket_path = \"{}\"\n\
             admissions_dir = \"{}\"\nhelper_runtime_dir = \"{}\"\n",
            database.display(),
            socket.display(),
            root.join("admissions").display(),
            root.join("helpers").display(),
        ),
    )
    .expect("configuration");
    success(run(&nq, &config, &["init"]));
    run_and_stop_nqd(&config, &socket);
    assert_eq!(stop_records(&database), 1);
    let lock = member(&database, ".capacity.lock");
    let lock_inode = fs::symlink_metadata(&lock).expect("live lock").ino();

    // Interrupt an archive while it is staging.
    let archives = root.join("archives");
    fs::create_dir(&archives).expect("archive parent");
    let destination = archives.join("nq-archive");
    let mut child = Command::new(&nq)
        .arg("--config")
        .arg(&config)
        .args(["admin", "archive", "--destination"])
        .arg(&destination)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("archive process");
    let started = Instant::now();
    let staging = loop {
        let partial = fs::read_dir(&archives)
            .expect("archive parent")
            .map(|entry| entry.expect("entry").path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".nq-archive-"))
            });
        if let Some(partial) = partial {
            break partial;
        }
        assert!(
            child.try_wait().expect("archive status").is_none(),
            "archive finished before it could be interrupted"
        );
        assert!(started.elapsed() < Duration::from_secs(60), "no staging");
        thread::sleep(Duration::from_millis(1));
    };
    thread::sleep(Duration::from_millis(50));
    assert!(
        child.try_wait().expect("archive status").is_none(),
        "archive finished before it could be interrupted"
    );
    child.kill().expect("SIGKILL the archive");
    assert!(!child.wait().expect("archive exit").success());

    // Nothing was sealed at the destination; the live lock is the same inode
    // and the kernel released the dead process's guard.
    assert!(!destination.exists(), "an interrupted archive sealed");
    assert_lock_released(&lock, lock_inode);
    success(run(&nq, &config, &["doctor"]));
    let _ = fs::remove_dir_all(&staging);

    // A repeated archive seals, and the sealed verifier accepts it.
    let sealed = success(run(
        &nq,
        &config,
        &[
            "admin",
            "archive",
            "--destination",
            destination.to_str().expect("UTF-8 path"),
        ],
    ));
    assert_eq!(sealed["source_openable"], true, "{sealed}");
    let mut database_entries = fs::read_dir(destination.join("db"))
        .expect("archived db directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("name")
        })
        .collect::<Vec<_>>();
    database_entries.sort();
    assert_eq!(database_entries, ["nq.db"]);
    let verify = Command::new(destination.join("bin/nq"))
        .arg("--json")
        .args(["admin", "archive-verify"])
        .arg(&destination)
        .output()
        .expect("archived verifier");
    let verified = success(verify);
    assert_eq!(verified["integrity_verified"], true, "{verified}");
    assert_eq!(verified["historical_database_verified"], true, "{verified}");
    assert_eq!(
        verified["historical_status_events_verified"],
        rusqlite::Connection::open(&database)
            .expect("open live store")
            .query_row("SELECT COUNT(*) FROM status_events", [], |row| row
                .get::<_, i64>(0))
            .expect("live status events"),
        "the archive holds every live status event"
    );
    assert_eq!(
        fs::read_dir(&archives).expect("archive parent").count(),
        1,
        "only the sealed archive remains"
    );
    assert_lock_released(&lock, lock_inode);

    // The live store restarts and records after archiving.
    run_and_stop_nqd(&config, &socket);
    assert_eq!(stop_records(&database), 2);
    assert_lock_released(&lock, lock_inode);
}
