//! `nqd` stops gracefully on SIGTERM (systemd's stop signal), not only SIGINT.

use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn sigterm_stops_nqd_and_closes_the_store() {
    let nq = env!("CARGO_BIN_EXE_nq");
    let nqd = env!("CARGO_BIN_EXE_nqd");
    let directory = tempfile::tempdir().expect("temporary test directory");
    let root = directory.path();
    let config = root.join("nq.toml");
    let database = root.join("nq.db");
    let socket = root.join("nqd.sock");
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
    let initialized = Command::new(nq)
        .arg("--config")
        .arg(&config)
        .arg("init")
        .output()
        .expect("initialize command");
    assert!(
        initialized.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let daemon = Command::new(nqd)
        .arg("--config")
        .arg(&config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("nqd");
    let pid = nix::unistd::Pid::from_raw(i32::try_from(daemon.id()).expect("pid"));
    let started = Instant::now();
    while !socket.exists() && started.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "nqd never bound its socket");
    // The socket is bound before the signal handler is installed; give the
    // daemon a moment to reach its wait.
    thread::sleep(Duration::from_millis(500));
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).expect("send SIGTERM");
    let output = daemon.wait_with_output().expect("nqd exit");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "nqd did not stop cleanly on SIGTERM ({:?}):\n{log}",
        output.status
    );
    assert!(log.contains("termination requested"), "{log}");
    assert!(
        log.contains("write-ahead log checkpointed at stop"),
        "{log}"
    );
    // Closing never checkpoints (an unbudgeted write); the stop runs one
    // bounded TRUNCATE checkpoint instead, so the WAL is empty or absent and
    // the main file alone holds the stopped record.
    let wal = root.join("nq.db-wal");
    assert!(
        fs::metadata(&wal).map_or(true, |metadata| metadata.len() == 0),
        "the stop left committed frames in the write-ahead log"
    );
    let main_only_root = tempfile::tempdir().expect("main-file copy directory");
    let main_only = main_only_root.path().join("nq.db");
    fs::copy(&database, &main_only).expect("copy the main file alone");
    let code: String = rusqlite::Connection::open(&main_only)
        .expect("open main-file copy")
        .query_row(
            "SELECT code FROM status_events
             WHERE component_kind = 'daemon' AND component_id = 'nqd'
             ORDER BY status_sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("daemon status in the main file");
    assert_eq!(code, "stopped", "the main file holds the stop");
    // The persistent capacity lock remains, released.
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("nq.db.capacity.lock"))
        .expect("capacity lock remains");
    drop(
        nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| error)
            .expect("no process retains the capacity guard"),
    );
    let connection = rusqlite::Connection::open(&database).expect("open store");
    let code: String = connection
        .query_row(
            "SELECT code FROM status_events
             WHERE component_kind = 'daemon' AND component_id = 'nqd'
             ORDER BY status_sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("daemon status");
    assert_eq!(code, "stopped", "the stop was recorded");
}
