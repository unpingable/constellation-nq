//! Matrix V3 CSH-10 hostile evidence runner: "child process inherits loaded
//! key/fd" — refused through the runtime enforcement path, fail-closed, with
//! a valid negative control and no vacuous success.
//!
//! Anchor `v2-csh-10-hostile` is implemented here. This runner is also the
//! assigned home of anchors `v2-sg-wu-07-hostile` and `v2-sg-n-30-hostile`,
//! implemented below as further `#[test]` functions reusing the shared probe
//! helpers and the re-exec child role:
//!
//! - `v2-sg-wu-07-hostile`: two-process/exec/shutdown observation of the
//!   shared fence — while the parent holds the fence, re-exec children
//!   acquire their own per-process fences (observation, not enforcement, per
//!   the V3 amendment), two concurrent alias children do so independently, a
//!   child spawned after the parent interval ends finds no residual fence
//!   state, and same-thread reentry in the parent remains refused (the
//!   enforcement half). Layer: fence/process boundary.
//! - `v2-sg-n-30-hostile`: hostile two-process/copy behavior — the child
//!   process cannot obtain the parent's fence standing or any signer
//!   capability (compile-boundary E0603 stderr still exact; fd-table clean;
//!   fence fresh per process), and a filesystem-copied Store directory opens
//!   only as an independent instance whose sole public cross-instance
//!   declaration grants no authority. Layers: compile boundary, fence/fd
//!   process boundary, public Store substrate. The custody-driving surface
//!   and the cross-process permanent C2 lock are crate-private at this
//!   checkpoint; nothing beyond the observable public behavior is asserted.
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
use nq_store::{Store, StoreError};

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
/// Environment marker gating the fence-probe half of the re-exec child role;
/// its value is an opaque run token (presence gates the role).
const FENCE_CHILD_ROLE_ENV: &str = "NQ_STORE_SG_WU_07_CHILD_FENCE_PROBE";
/// Prefix of the single structured result line the fence-probe child prints.
const FENCE_LINE_PREFIX: &str = "NQ-SG-WU-07-FENCE ";

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

/// Parsed result of one re-exec child fence probe.
#[derive(Debug)]
struct FenceProbeReport {
    /// Whether the child process exited successfully.
    status_success: bool,
    /// The child process's own pid, if it reported one.
    pid: Option<u32>,
    /// The child's structured result line, if it printed one.
    line: Option<String>,
}

/// Build the re-exec command for the fence-probe child role. The caller
/// decides whether to run it to completion or race several concurrently.
fn fence_probe_command() -> Result<Command, String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("current test executable: {error}"))?;
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(CHILD_TEST_NAME)
        .arg("--nocapture")
        .env(FENCE_CHILD_ROLE_ENV, "run");
    Ok(command)
}

/// Parse the child's single structured fence-probe result line
/// (`NQ-SG-WU-07-FENCE pid=<pid> acquired=ok same-process=ok
/// reentry-refused=exact`).
fn parse_fence_probe_report(status_success: bool, stdout: &[u8]) -> FenceProbeReport {
    let stdout = String::from_utf8_lossy(stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with(FENCE_LINE_PREFIX))
        .map(str::to_owned);
    let pid = line.as_deref().and_then(|line| {
        line.split_whitespace()
            .find_map(|token| token.strip_prefix("pid="))
            .and_then(|pid| pid.parse().ok())
    });
    FenceProbeReport {
        status_success,
        pid,
        line,
    }
}

/// Re-exec this test binary as the fence-probe child and parse its
/// structured result line.
fn spawn_fence_probe_child() -> Result<FenceProbeReport, String> {
    let output = fence_probe_command()?
        .output()
        .map_err(|error| format!("spawn fence-probe child: {error}"))?;
    Ok(parse_fence_probe_report(
        output.status.success(),
        &output.stdout,
    ))
}

/// Assert one fence-probe child exited successfully with the exact expected
/// tokens, returning its pid for cross-process identity checks.
fn require_fence_probe_ok(report: &FenceProbeReport, context: &str) -> u32 {
    assert!(
        report.status_success,
        "{context}: fence-probe child must exit 0: {report:?}"
    );
    let line = report.line.as_ref().unwrap_or_else(|| {
        panic!("{context}: fence-probe child printed no result line: {report:?}")
    });
    for token in ["acquired=ok", "same-process=ok", "reentry-refused=exact"] {
        assert!(
            line.contains(token),
            "{context}: fence-probe line must contain {token:?}: {line}"
        );
    }
    report
        .pid
        .unwrap_or_else(|| panic!("{context}: fence-probe line must carry a pid: {line}"))
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
/// fd list and exits non-zero with the diagnostic. When the fence-probe
/// marker is also (or instead) present, the child additionally acquires its
/// OWN process's fence, proves the same-process binding, and requires the
/// exact non-reentrant refusal on a same-thread second acquire — the
/// non-vacuous control proving the child's fence is real. A no-op pass when
/// not invoked under either marker environment variable.
#[test]
fn v2_csh_10_child_fd_probe() {
    if let Ok(identity) = std::env::var(CHILD_ROLE_ENV) {
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
    if std::env::var(FENCE_CHILD_ROLE_ENV).is_ok() {
        child_fence_probe();
    }
}

/// Fence-probe half of the re-exec child role: acquire THIS process's fence
/// immediately after exec (proving no fence-interval state is inherited
/// across the process boundary), verify the same-process binding, and
/// require the exact non-reentrant refusal on a same-thread reacquire.
fn child_fence_probe() {
    let guard = match C2ForkFence::acquire() {
        Ok(guard) => guard,
        Err(error) => {
            println!("{FENCE_LINE_PREFIX}error=fence-acquire-refused:{error}");
            let _ = std::io::stdout().flush();
            std::process::exit(3);
        }
    };
    if guard.verify_same_process().is_err() {
        println!("{FENCE_LINE_PREFIX}error=not-same-process");
        let _ = std::io::stdout().flush();
        std::process::exit(2);
    }
    let reentry_exact = match C2ForkFence::acquire() {
        Err(error) => error.to_string() == NON_REENTRANT_REFUSAL,
        Ok(extra) => {
            drop(extra);
            false
        }
    };
    drop(guard);
    if !reentry_exact {
        println!("{FENCE_LINE_PREFIX}error=reentry-not-refused-exactly");
        let _ = std::io::stdout().flush();
        std::process::exit(2);
    }
    println!(
        "{FENCE_LINE_PREFIX}pid={} acquired=ok same-process=ok reentry-refused=exact",
        std::process::id()
    );
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

/// Matrix V3 anchor `v2-sg-wu-07-hostile`: "two-process/alias/copy/fork/
/// exec/shutdown law ...; process, fork, exec and shutdown evidence observes
/// but does not enforce the shared fence".
///
/// Layer covered: the fence/process boundary. While the parent holds the
/// fence, (i) a re-exec child acquires its own process fence — exec discards
/// the parent's in-memory fence state, so the child's fresh acquisition
/// observes (not enforces, per the V3 amendment) that no fence-interval
/// state crosses the boundary; (ii) two concurrent alias children do the
/// same independently of each other; (iii) after the parent's interval ends,
/// a further child finds no residual fence state and the parent re-acquires
/// cleanly (the shutdown observation — the parent test process cannot exit
/// mid-test, so interval shutdown is the honest analog); (iv) within the
/// parent, same-thread reentry remains refused with the exact message (the
/// enforcement half). The child's own non-reentrant reacquire control proves
/// its fence is real, not a vacuous pass.
#[test]
fn v2_sg_wu_07_hostile() {
    let parent_pid = std::process::id();
    let guard = C2ForkFence::acquire().expect("initial fence acquisition in a fresh test process");

    // Nothing may panic while the guard is held (a panic would poison the
    // process-global fence), so every child result is captured into a value
    // and asserted only after release.
    //
    // (i) One re-exec child, while the parent fence is held.
    let first_child = spawn_fence_probe_child();

    // (ii) Two concurrent alias children, spawned before either is awaited.
    let concurrent_children = (|| -> Result<(FenceProbeReport, FenceProbeReport), String> {
        let mut first_command = fence_probe_command()?;
        let mut second_command = fence_probe_command()?;
        first_command.stdout(std::process::Stdio::piped());
        second_command.stdout(std::process::Stdio::piped());
        let first = first_command
            .spawn()
            .map_err(|error| format!("spawn first concurrent child: {error}"))?;
        let second = second_command
            .spawn()
            .map_err(|error| format!("spawn second concurrent child: {error}"))?;
        let first_output = first
            .wait_with_output()
            .map_err(|error| format!("await first concurrent child: {error}"))?;
        let second_output = second
            .wait_with_output()
            .map_err(|error| format!("await second concurrent child: {error}"))?;
        Ok((
            parse_fence_probe_report(first_output.status.success(), &first_output.stdout),
            parse_fence_probe_report(second_output.status.success(), &second_output.stdout),
        ))
    })();

    // (iv) The enforcement half: same-thread reentry in the parent remains
    // refused, and for exactly the non-reentrant reason.
    let same_thread_reacquire_refused = match C2ForkFence::acquire() {
        Err(error) => error.to_string() == NON_REENTRANT_REFUSAL,
        Ok(extra) => {
            drop(extra);
            false
        }
    };

    let parent_identity_stable = guard.verify_same_process().is_ok();
    drop(guard);

    // (iii) Shutdown observation: after the parent's interval ended, a
    // further child finds no residual fence state, and the parent's own
    // re-acquisition confirms nothing lingers in this process either.
    let post_shutdown_child = spawn_fence_probe_child();
    let parent_reacquired_after_shutdown = C2ForkFence::acquire()
        .map(|guard| guard.verify_same_process().is_ok())
        .unwrap_or(false);

    let first_child = first_child.expect("spawn first fence-probe child");
    let first_pid = require_fence_probe_ok(&first_child, "SG-WU-07 (i)");
    assert_ne!(
        first_pid, parent_pid,
        "SG-WU-07 (i): the child fence owner is its own process, not the parent"
    );

    let (alias_a, alias_b) = concurrent_children.expect("spawn concurrent fence-probe children");
    let alias_a_pid = require_fence_probe_ok(&alias_a, "SG-WU-07 (ii) first alias");
    let alias_b_pid = require_fence_probe_ok(&alias_b, "SG-WU-07 (ii) second alias");
    assert_ne!(
        alias_a_pid, alias_b_pid,
        "SG-WU-07 (ii): alias children are independent processes"
    );
    assert!(
        alias_a_pid != parent_pid && alias_b_pid != parent_pid,
        "SG-WU-07 (ii): alias fences are owned by the children, not the parent"
    );

    assert!(
        same_thread_reacquire_refused,
        "SG-WU-07 (iv): same-thread reentry must remain refused as non-reentrant"
    );
    assert!(
        parent_identity_stable,
        "SG-WU-07: the protected interval must not have crossed a process boundary"
    );

    let post_shutdown_child = post_shutdown_child.expect("spawn post-shutdown fence-probe child");
    require_fence_probe_ok(&post_shutdown_child, "SG-WU-07 (iii)");
    assert!(
        parent_reacquired_after_shutdown,
        "SG-WU-07 (iii): the parent must re-acquire cleanly after interval shutdown"
    );
}

/// Matrix V3 anchor `v2-sg-n-30-hostile`: "Two-process, alias, copied
/// Store/key, fork, child, namespace, cross-occurrence, cross-role, and
/// cross-domain behavior follows the exact local custody law and makes no
/// estate claim ... PID and process-epoch observation occurs after the
/// process boundary and cannot serialize it".
///
/// Layers covered: the compile boundary (the committed E0603 private-module
/// refusal is still exact — the child cannot even name a signer capability),
/// the fd/fence process boundary (the child inherits no custody fd and only
/// a fresh, pid-bound fence while the parent holds its own), and the public
/// Store substrate (a filesystem-copied Store directory opens only as an
/// independent instance: physically distinct, equally valid, and the sole
/// cross-instance declaration the public API can build for it grants no
/// authority). Every refusal is classified exactly. The custody-driving
/// surface and the cross-process permanent C2 lock are crate-private; the
/// compile boundary and the per-process observations are the honest evidence
/// at this checkpoint.
#[test]
fn v2_sg_n_30_hostile() {
    // Compile boundary: the committed expected diagnostic must still be
    // exactly the E0603 privacy refusal and nothing else.
    let diagnostic = std::fs::read_to_string("tests/ui/c2/v2-scf-17.stderr")
        .expect("committed SCF-17 expected diagnostic");
    let error_count = diagnostic.matches("error[").count() + diagnostic.matches("\nerror:").count();
    let compile_fail_stderr_exact = diagnostic.contains("error[E0603]")
        && diagnostic.contains("module `custody` is private")
        && error_count == 1
        && !diagnostic.contains("warning");

    // Process boundary: while the parent holds its fence and a live
    // O_CLOEXEC custody-analog fd, the child inherits no foreign fd and only
    // a fresh fence of its own. The decoy-positive control for the fd probe
    // lives in `v2_csh_10_hostile` above and is not repeated here.
    let directory = tempfile::tempdir().expect("n-30 hostile directory");
    let marker = tempfile::NamedTempFile::new_in(directory.path()).expect("custody-analog marker");
    writeln!(marker.as_file(), "sg-n-30 custody analog").expect("write marker");
    let clean_setup = (|| -> Result<(), String> {
        let flags = fd_flags(marker.as_file())?;
        set_fd_flags(marker.as_file(), flags | FdFlag::FD_CLOEXEC)?;
        if !fd_flags(marker.as_file())?.contains(FdFlag::FD_CLOEXEC) {
            return Err("marker O_CLOEXEC would not stay set".to_string());
        }
        Ok(())
    })();
    let guard = C2ForkFence::acquire().expect("parent fence acquisition");
    let fd_probe = clean_setup.and_then(|()| spawn_fd_probe_child(marker.path()));
    let fence_child = spawn_fence_probe_child();
    let parent_identity_stable = guard.verify_same_process().is_ok();
    drop(guard);

    let fd_probe = fd_probe.expect("fd-table probe setup and spawn");
    assert!(
        fd_probe.status_success
            && fd_probe.total_fds.is_some_and(|total| total >= 3)
            && fd_probe.foreign_fds.as_ref().is_some_and(Vec::is_empty),
        "SG-N-30: the child must inherit no custody fd: {fd_probe:?}"
    );
    let fence_child = fence_child.expect("spawn fence-probe child");
    let child_pid = require_fence_probe_ok(&fence_child, "SG-N-30 fence");
    assert_ne!(
        child_pid,
        std::process::id(),
        "SG-N-30: the child's fence standing is its own, never the parent's"
    );
    assert!(
        parent_identity_stable,
        "SG-N-30: process-epoch observation stays bound to this process"
    );

    // Copied Store/key: a filesystem copy of the resource directory's Store
    // opens as an independent instance and yields no standing over the
    // original.
    let db_path = directory.path().join("original.sqlite3");
    let original = Store::initialize_unqualified_storage(&db_path).expect("initialize store");
    original.validate().expect("fresh store validates");
    let schema = Store::database_schema_version(&db_path).expect("original schema version");
    drop(original);

    let copy_directory = tempfile::tempdir().expect("copy directory");
    let copy_path = copy_directory.path().join("copy.sqlite3");
    std::fs::copy(&db_path, &copy_path).expect("copy the store file");
    let original_metadata = std::fs::metadata(&db_path).expect("original metadata");
    let copy_metadata = std::fs::metadata(&copy_path).expect("copy metadata");
    assert_ne!(
        (original_metadata.dev(), original_metadata.ino()),
        (copy_metadata.dev(), copy_metadata.ino()),
        "SG-N-30: the copy must be a physically distinct instance"
    );
    let copy_store = Store::open(&copy_path).expect("copied store opens independently");
    copy_store.validate().expect("copied store validates");
    assert_eq!(
        Store::database_schema_version(&copy_path).expect("copy schema version"),
        schema,
        "SG-N-30: the copy carries the same persisted facts but no standing"
    );
    drop(copy_store);

    // No estate claim: the sole cross-instance declaration the public API
    // can build for the copy explicitly grants no authority.
    let declaration = Store::build_restore_declaration(&db_path, &copy_path)
        .expect("restore declaration for the copy");
    let declaration_json: serde_json::Value =
        serde_json::from_slice(&declaration.canonical_bytes).expect("declaration canonical JSON");
    assert_eq!(
        declaration_json["grants_authority"],
        serde_json::Value::Bool(false),
        "SG-N-30: the only public declaration for the copy grants no authority"
    );

    // Every refusal classified exactly: opening an absent artifact refuses
    // with exactly `NotInitialized` (proving the opens above are not
    // vacuously succeeding).
    let missing_refusal_exact = matches!(
        Store::open(directory.path().join("absent.sqlite3")),
        Err(StoreError::NotInitialized(_))
    );
    assert!(
        missing_refusal_exact,
        "SG-N-30: the missing-artifact refusal must be exactly NotInitialized"
    );
    assert!(
        compile_fail_stderr_exact,
        "SG-N-30: the compile boundary must remain exactly E0603:\n{diagnostic}"
    );
}
