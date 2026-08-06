//! Matrix V3 CSH-10 hostile evidence runner: "child process inherits loaded
//! key/fd" — refused through the runtime enforcement path, fail-closed, with
//! a valid negative control and no vacuous success.
//!
//! Anchor `v2-csh-10-hostile` is implemented here. This runner is also the
//! assigned home of anchors `v2-sg-wu-07-hostile` and `v2-sg-n-30-hostile`;
//! those rows will be added later as further `#[test]` functions reusing the
//! shared probe helpers and the re-exec child role, without restructuring.
//!
//! The hostile case perturbs the real load-bearing boundary:
//!
//! 1. Same-thread hostile attempt (the exact production attack shape): while
//!    the current thread holds the `C2ForkFence` (standing in for the signer
//!    secret-live interval), a same-thread `C2ForkFence::acquire()` — the
//!    first step of the production spawn choke — must fail closed as
//!    non-reentrant.
//! 2. Cross-thread serialization: while one thread holds the fence, a
//!    contender thread's `acquire()` must not complete within a bounded
//!    negative window and must complete within a generous window after
//!    release.
//! 3. Process-boundary probe: the parent re-execs this test binary (the
//!    established `current_exe` + `--exact` + env-marker pattern) while
//!    holding a live custody-analog interval with a real O_CLOEXEC marker fd
//!    open. The child enumerates `/proc/self/fd` and must find no foreign
//!    fd. The decoy control repeats the probe with the marker deliberately
//!    made inheritable and must detect it, proving the clean probe is
//!    non-vacuous.
//! 4. Compile-time binding: the committed `tests/ui/c2/v2-csh-10.stderr`
//!    must still be exactly the E0616 private-field refusal, binding the
//!    compile-time half of the row to this runtime half.
//!
//! Spawning helper processes is test-only evidence gathering; production
//! sources gain no process creation.

mod c2_signer_hostile {
    #[path = "csh-10.rs"]
    pub mod csh_10;
}

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nq_helper_sandbox::C2ForkFence;

use crate::c2_signer_hostile::csh_10::{
    ConcreteSignerHostileCaseV2, Csh10Observations, Csh10RefusalV2,
    construct_csh_10_child_process_inherits_loaded_key_fd,
    verify_csh_10_child_process_inherits_loaded_key_fd,
};

/// Environment marker gating the re-exec child role; the value is the
/// `dev:ino` identity of the parent marker file the child must not hold.
const CHILD_ROLE_ENV: &str = "NQ_STORE_CSH10_CHILD_FD_PROBE";
/// Exact test name re-executed as the fd-table probe child.
const CHILD_TEST_NAME: &str = "v2_csh_10_child_fd_probe";
/// Prefix of the single structured result line the child prints.
const PROBE_LINE_PREFIX: &str = "NQ-CSH10-FD-PROBE ";
/// Bounded negative window: a blocked contender must never complete inside
/// it.
const NEGATIVE_WINDOW: Duration = Duration::from_millis(250);
/// Generous positive window for contender start and post-release completion.
const POSITIVE_WINDOW: Duration = Duration::from_secs(30);
/// Exact refusal message of the non-reentrant fence, distinguishing the
/// intended fail-closed refusal from any other acquisition error.
const NON_REENTRANT_REFUSAL: &str = "C2 fork fence is non-reentrant";

/// Parsed result of one re-exec child fd-table probe.
#[derive(Debug)]
struct FdProbeReport {
    /// Whether the child process exited successfully.
    status_success: bool,
    /// Total fd count the child enumerated, if it reported one.
    total_fds: Option<usize>,
    /// Foreign fd numbers the child reported (`None` means the child printed
    /// no structured result line at all).
    foreign_fds: Option<Vec<String>>,
}

/// Re-exec this test binary as the fd-table probe child and parse its
/// structured result line. The marker file must stay open across the spawn.
fn spawn_fd_probe_child(marker_path: &Path) -> Result<FdProbeReport, String> {
    let metadata =
        std::fs::metadata(marker_path).map_err(|error| format!("marker metadata: {error}"))?;
    let identity = format!("{}:{}", metadata.dev(), metadata.ino());
    let executable =
        std::env::current_exe().map_err(|error| format!("current test executable: {error}"))?;
    let output = Command::new(executable)
        .arg("--exact")
        .arg(CHILD_TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_ROLE_ENV, identity)
        .output()
        .map_err(|error| format!("spawn fd-probe child: {error}"))?;
    let stdout =
        String::from_utf8(output.stdout).map_err(|error| format!("child stdout: {error}"))?;
    Ok(parse_fd_probe_report(output.status.success(), &stdout))
}

/// Parse the child's single structured result line
/// (`NQ-CSH10-FD-PROBE total=<n> foreign-fds=none|fd,fd,...`).
fn parse_fd_probe_report(status_success: bool, stdout: &str) -> FdProbeReport {
    let mut report = FdProbeReport {
        status_success,
        total_fds: None,
        foreign_fds: None,
    };
    let Some(line) = stdout.lines().find(|l| l.starts_with(PROBE_LINE_PREFIX)) else {
        return report;
    };
    for token in line[PROBE_LINE_PREFIX.len()..].split_whitespace() {
        if let Some(total) = token.strip_prefix("total=") {
            report.total_fds = total.parse().ok();
        } else if let Some(foreign) = token.strip_prefix("foreign-fds=") {
            report.foreign_fds = Some(if foreign == "none" {
                Vec::new()
            } else {
                foreign.split(',').map(str::to_owned).collect()
            });
        }
    }
    report
}

/// Read the fd-status flags of `file`.
fn fd_flags(file: &std::fs::File) -> Result<FdFlag, String> {
    fcntl(file.as_raw_fd(), FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .map_err(|error| format!("F_GETFD on marker: {error}"))
}

/// Replace the fd-status flags of `file`.
fn set_fd_flags(file: &std::fs::File, flags: FdFlag) -> Result<(), String> {
    fcntl(file.as_raw_fd(), FcntlArg::F_SETFD(flags))
        .map(|_| ())
        .map_err(|error| format!("F_SETFD on marker: {error}"))
}

/// Enumerate `/proc/self/fd` and collect every fd whose target carries the
/// `dev:ino` identity of the parent marker file.
fn inspect_fd_table(identity: &str) -> Result<(usize, Vec<String>), String> {
    let (dev, ino) = identity
        .split_once(':')
        .ok_or_else(|| format!("malformed marker identity {identity:?}"))?;
    let dev: u64 = dev
        .parse()
        .map_err(|error| format!("marker identity device: {error}"))?;
    let ino: u64 = ino
        .parse()
        .map_err(|error| format!("marker identity inode: {error}"))?;
    let entries = std::fs::read_dir("/proc/self/fd")
        .map_err(|error| format!("read /proc/self/fd: {error}"))?;
    let mut total = 0_usize;
    let mut foreign = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("iterate /proc/self/fd: {error}"))?;
        total += 1;
        let metadata =
            std::fs::metadata(entry.path()).map_err(|error| format!("stat fd entry: {error}"))?;
        if metadata.dev() == dev && metadata.ino() == ino {
            foreign.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok((total, foreign))
}

/// Re-exec child role: inspect the inherited fd table and report any fd that
/// resolves to the parent marker identity. A clean table prints
/// `foreign-fds=none` and lets the harness exit 0; any foreign fd prints the
/// fd list and exits non-zero with the diagnostic. A no-op pass when not
/// invoked under the marker environment variable.
#[test]
fn v2_csh_10_child_fd_probe() {
    let Ok(identity) = std::env::var(CHILD_ROLE_ENV) else {
        return;
    };
    match inspect_fd_table(&identity) {
        Ok((total, foreign)) if foreign.is_empty() => {
            println!("{PROBE_LINE_PREFIX}total={total} foreign-fds=none");
        }
        Ok((total, foreign)) => {
            println!(
                "{PROBE_LINE_PREFIX}total={total} foreign-fds={}",
                foreign.join(",")
            );
            let _ = std::io::stdout().flush();
            std::process::exit(2);
        }
        Err(message) => {
            println!("{PROBE_LINE_PREFIX}error={message}");
            let _ = std::io::stdout().flush();
            std::process::exit(3);
        }
    }
}

/// Matrix V3 anchor `v2-csh-10-hostile`: a child process must not inherit
/// the loaded key/fd. Perturbs the real load-bearing boundary — the shared
/// fork fence and the fd-custody analog — and requires the exact refusal.
#[test]
fn v2_csh_10_hostile() {
    // Setup, before the protected interval begins: two real marker files
    // stand in for the loaded key/fd held in signer custody. Keeping them
    // open across the re-exec spawns makes the fd-table probe non-vacuous.
    let directory = tempfile::tempdir().expect("marker directory");
    let clean_marker = tempfile::NamedTempFile::new_in(directory.path()).expect("clean marker");
    let decoy_marker = tempfile::NamedTempFile::new_in(directory.path()).expect("decoy marker");
    let mut clean_file = clean_marker.as_file();
    writeln!(clean_file, "csh-10 clean custody-analog marker").expect("write clean marker");
    let mut decoy_file = decoy_marker.as_file();
    writeln!(decoy_file, "csh-10 decoy inheritance marker").expect("write decoy marker");
    let clean_path = clean_marker.path().to_path_buf();
    let decoy_path = decoy_marker.path().to_path_buf();
    let directory_path = directory.path().to_path_buf();

    // Probes 1–3 run with the fence held by this thread, standing in for the
    // signer secret-live interval.
    let guard = C2ForkFence::acquire().expect("initial fence acquisition in a fresh test process");

    // Probe 1: the production spawn choke's first step on the SAME thread
    // must fail closed immediately as non-reentrant — and for exactly that
    // reason, not any other acquisition error.
    let same_thread_reacquire_refused = match C2ForkFence::acquire() {
        Err(error) => error.to_string() == NON_REENTRANT_REFUSAL,
        Ok(extra) => {
            // The fence was reentrant: a hard violation. Drop the extra guard
            // so fence state stays consistent, and record the failure.
            drop(extra);
            false
        }
    };

    // Probe 2: a contender thread must be excluded while the fence is held
    // and must acquire promptly after release. Capacity-1 sync channels keep
    // every send non-blocking so the contender can never wedge the join.
    let (started_tx, started_rx) = sync_channel::<()>(1);
    let (done_tx, done_rx) = sync_channel::<Result<(), String>>(1);
    let contender = std::thread::spawn(move || {
        let _ = started_tx.send(());
        let verdict = match C2ForkFence::acquire() {
            Ok(guard) => {
                drop(guard);
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        };
        let _ = done_tx.send(verdict);
    });
    let contender_started = started_rx.recv_timeout(POSITIVE_WINDOW).is_ok();
    let cross_thread_excluded_while_held = contender_started
        && matches!(
            done_rx.recv_timeout(NEGATIVE_WINDOW),
            Err(RecvTimeoutError::Timeout)
        );

    // Probe 3: the two-process fd-inheritance probes, with the custody-analog
    // interval live. Nothing may panic while the guard is held (a panic would
    // poison the process-global fence), so every failure is captured into a
    // report or boolean and asserted only after release.
    let clean_probe = (|| -> Result<FdProbeReport, String> {
        let flags = fd_flags(clean_marker.as_file())?;
        set_fd_flags(clean_marker.as_file(), flags | FdFlag::FD_CLOEXEC)?;
        if !fd_flags(clean_marker.as_file())?.contains(FdFlag::FD_CLOEXEC) {
            return Err("clean marker O_CLOEXEC would not stay set".to_string());
        }
        spawn_fd_probe_child(&clean_path)
    })();
    let child_inherited_no_parent_fd = clean_probe.as_ref().is_ok_and(|report| {
        report.status_success
            && report.total_fds.is_some_and(|total| total >= 3)
            && report.foreign_fds.as_ref().is_some_and(Vec::is_empty)
    });

    // Decoy control: deliberately make the second marker inheritable (clear
    // O_CLOEXEC) before the spawn. The same child probe MUST then detect and
    // report the inherited fd — without this control the clean probe would
    // be vacuous.
    let decoy_fd = decoy_marker.as_file().as_raw_fd().to_string();
    let decoy_probe = (|| -> Result<FdProbeReport, String> {
        let flags = fd_flags(decoy_marker.as_file())?;
        set_fd_flags(decoy_marker.as_file(), flags & !FdFlag::FD_CLOEXEC)?;
        if fd_flags(decoy_marker.as_file())?.contains(FdFlag::FD_CLOEXEC) {
            return Err("decoy marker O_CLOEXEC would not clear".to_string());
        }
        spawn_fd_probe_child(&decoy_path)
    })();
    let decoy_inheritance_detected = decoy_probe.as_ref().is_ok_and(|report| {
        !report.status_success
            && report
                .foreign_fds
                .as_ref()
                .is_some_and(|fds| fds.contains(&decoy_fd))
    });

    // The PID nonce: the protected interval must not have crossed a process
    // boundary despite both re-exec spawns.
    let process_identity_stable_across_spawn = guard.verify_same_process().is_ok();
    drop(guard);

    // Positive half of probe 2, after release.
    let cross_thread_acquired_after_release =
        matches!(done_rx.recv_timeout(POSITIVE_WINDOW), Ok(Ok(())));
    contender
        .join()
        .expect("contender thread must finish without panicking");

    // Probe 4: bind the compile-time half — the committed expected diagnostic
    // must still be exactly the E0616 privacy refusal and nothing else.
    let diagnostic = std::fs::read_to_string("tests/ui/c2/v2-csh-10.stderr")
        .expect("committed CSH-10 expected diagnostic");
    let error_count = diagnostic.matches("error[").count() + diagnostic.matches("\nerror:").count();
    let compile_fail_stderr_exact = diagnostic.contains("error[E0616]")
        && diagnostic.contains("field `owner_pid` of struct `C2ForkFenceGuard` is private")
        && error_count == 1
        && !diagnostic.contains("warning");

    // Tempfile auto-cleanup: dropping the markers and the directory must
    // remove the whole tree, leaving nothing behind.
    drop(clean_marker);
    drop(decoy_marker);
    drop(directory);
    assert!(
        !clean_path.exists() && !decoy_path.exists() && !directory_path.exists(),
        "tempfile auto-cleanup must remove the marker directory tree"
    );

    let observations = Csh10Observations {
        same_thread_reacquire_refused,
        cross_thread_excluded_while_held,
        cross_thread_acquired_after_release,
        process_identity_stable_across_spawn,
        child_inherited_no_parent_fd,
        decoy_inheritance_detected,
        compile_fail_stderr_exact,
    };
    let outcome = construct_csh_10_child_process_inherits_loaded_key_fd(&observations)
        .unwrap_or_else(|mismatch| {
            panic!(
                "CSH-10 hostile evidence incomplete: {mismatch}\n\
                 clean probe: {clean_probe:?}\ndecoy probe: {decoy_probe:?}"
            )
        });
    verify_csh_10_child_process_inherits_loaded_key_fd(&outcome)
        .expect("CSH-10 verification of the constructed outcome");
    assert_eq!(outcome.case, ConcreteSignerHostileCaseV2::Csh10);
    assert_eq!(
        outcome.refusal,
        Csh10RefusalV2::ChildProcessInheritsLoadedKeyFdRefused
    );
}
