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
    // Every connection closed: the last close checkpoints and removes the WAL.
    assert!(
        !root.join("nq.db-wal").exists(),
        "the write-ahead log survived the stop"
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
