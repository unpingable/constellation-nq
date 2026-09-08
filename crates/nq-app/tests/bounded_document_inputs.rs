//! Local regular-file boundary controls; no classic executable or source needed.
#![cfg(target_os = "linux")]
use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn refused(args: &[&str]) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nq"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("nonregular input blocked before bounded acquisition: {args:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("regular file"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn nonregular_documents_and_docket_executable_refuse_before_acquisition() {
    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let producer = format!("sha256:{}", "0".repeat(64));
    let request = root.path().join("request.json");
    std::fs::write(&request, br#"{"attempt":"test","subject":"test","consumer":"nightshift-readonly","purpose":"continue_observing","claim":"docket_attempt_settled","evaluated_at":"2026-09-08T00:00:00Z","continuity_support":null}"#).unwrap();
    for input in [&fifo as &Path, Path::new("/dev/null")] {
        let path = input.to_str().unwrap();
        refused(&[
            "repository-state",
            "replay",
            "--artifact",
            path,
            "--producer-sha256",
            &producer,
        ]);
        refused(&[
            "bounded-predicate",
            "admit",
            "--inventory",
            path,
            "--profiles",
            "missing",
            "--output",
            "-",
        ]);
        refused(&[
            "campaign-stage-qualification",
            "evaluate",
            "--profile",
            path,
            "--evidence",
            "missing",
            "--evaluated-at-unix-ms",
            "0",
        ]);
        refused(&[
            "docket-purpose-support",
            "--request",
            path,
            "--docket-binary",
            "missing",
            "--docket-sha256",
            &producer,
            "--state",
            "missing",
            "--snapshot-history",
            root.path().to_str().unwrap(),
        ]);
        refused(&[
            "docket-purpose-support",
            "--request",
            request.to_str().unwrap(),
            "--docket-binary",
            path,
            "--docket-sha256",
            &producer,
            "--state",
            "missing",
            "--snapshot-history",
            root.path().to_str().unwrap(),
        ]);
    }
}
