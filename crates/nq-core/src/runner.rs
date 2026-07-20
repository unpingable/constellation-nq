//! Bounded one-shot stdio helper execution.

use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nq_helper_sandbox::{child_has_exited, isolate_command_with_limits};
use serde::{Deserialize, Serialize};

use crate::config::{CommandConfig, ResourceLimits};
use crate::identity::VerifiedLaunch;

/// Complete bounded capture of one process attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunCapture {
    /// Wall-clock start used for audit presentation, not deadline enforcement.
    pub started_at: DateTime<Utc>,
    /// Wall-clock finish.
    pub finished_at: DateTime<Utc>,
    /// Monotonic elapsed duration.
    pub duration_ms: u64,
    /// Process exit code, if an exit status was obtained.
    pub exit_code: Option<i32>,
    /// Exact captured stdout, including the required newline when present.
    pub stdout: Vec<u8>,
    /// Bounded stderr logs.
    pub stderr: Vec<u8>,
    /// Acquisition-plane outcome.
    pub outcome: AcquisitionOutcome,
}

impl RunCapture {
    /// Return the single JSON frame without its newline only after acquisition
    /// succeeded.
    #[must_use]
    pub fn response_frame(&self) -> Option<&[u8]> {
        if self.outcome == AcquisitionOutcome::Response {
            self.stdout.strip_suffix(b"\n")
        } else {
            None
        }
    }
}

/// Closed phase vocabulary for persistent-carrier exchange timeouts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeTimeoutPhase {
    /// The admitted request frame could not be written before the deadline.
    WriteRequest,
    /// A complete response frame was not read before the deadline.
    ReadResponse,
}

/// Acquisition outcomes. Protocol and admission results are deliberately not
/// represented here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcquisitionOutcome {
    /// One validly framed JSON object and a zero exit code were obtained.
    Response,
    /// The process could not be spawned.
    SpawnFailed {
        /// Operating-system spawn error.
        message: String,
    },
    /// Request transmission failed.
    RequestWriteFailed {
        /// Pipe write error.
        message: String,
    },
    /// Deadline expired and the process group was terminated and reaped.
    Timeout,
    /// A persistent-carrier deadline expired in a named exchange phase.
    ExchangeTimeout {
        /// Closed phase at which the exchange deadline expired.
        phase: ExchangeTimeoutPhase,
    },
    /// Stdout exceeded the configured bound.
    OutputTooLarge,
    /// Stderr exceeded the configured bound.
    StderrTooLarge,
    /// Process exited without returning any bytes.
    Eof,
    /// Stdout did not contain exactly one LF-terminated frame.
    MalformedFraming {
        /// Exact framing violation.
        message: String,
    },
    /// Frame was not UTF-8 JSON object syntax.
    MalformedJson {
        /// JSON parse or top-level shape error.
        message: String,
    },
    /// Process exited unsuccessfully. A report emitted before this outcome is
    /// retained as raw custody but is not a successful exchange.
    ExitNonzero {
        /// Conventional exit code, or `None` when terminated by signal.
        code: Option<i32>,
    },
    /// Persistent helper exited before or during an exchange.
    HelperExited {
        /// Conventional exit code, or `None` when terminated by signal.
        code: Option<i32>,
    },
    /// Persistent carrier disconnected before a complete response.
    Disconnect {
        /// Exact socket diagnostic.
        message: String,
    },
    /// Persistent helper startup failed after process spawn or socket setup.
    CarrierStartupFailed {
        /// Exact supervised-startup diagnostic.
        message: String,
    },
    /// No persistent helper connection was available for the exchange.
    NotRunning,
    /// Process I/O or wait failed.
    IoFailed {
        /// Process wait or pipe error.
        message: String,
    },
}

/// Compatibility alias used by callers that focus on failed acquisition.
pub type AcquisitionFailure = AcquisitionOutcome;

/// Fixed-argv stdio runner.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdioRunner;

impl StdioRunner {
    /// Execute exactly one request. `request_json` must be a JSON document
    /// without framing bytes; the runner appends exactly one LF.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn run(
        &self,
        command: &CommandConfig,
        request_json: &[u8],
        deadline: Duration,
        limits: &ResourceLimits,
    ) -> RunCapture {
        match VerifiedLaunch::open(command) {
            Ok(launch) => self.run_verified(&launch, request_json, deadline, limits),
            Err(error) => failed_spawn_capture(error.to_string()),
        }
    }

    /// Execute one request using an already-qualified descriptor-bound launch.
    ///
    /// Pathnames are not consulted for executable, interpreter, script, or
    /// existing path-like fixed-argument bytes.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn run_verified(
        &self,
        launch: &VerifiedLaunch,
        request_json: &[u8],
        deadline: Duration,
        limits: &ResourceLimits,
    ) -> RunCapture {
        let started_at = Utc::now();
        let started = Instant::now();
        let mut child = match spawn(launch, limits) {
            Ok(child) => child,
            Err(error) => {
                return capture(
                    started_at,
                    started,
                    None,
                    Vec::new(),
                    Vec::new(),
                    AcquisitionOutcome::SpawnFailed {
                        message: error.to_string(),
                    },
                );
            }
        };

        let (Some(stdout), Some(stderr), Some(stdin)) =
            (child.stdout.take(), child.stderr.take(), child.stdin.take())
        else {
            terminate_and_reap(&mut child);
            return capture(
                started_at,
                started,
                None,
                Vec::new(),
                Vec::new(),
                AcquisitionOutcome::IoFailed {
                    message: "spawned helper is missing a configured pipe".into(),
                },
            );
        };

        let stdout_overflow = Arc::new(AtomicBool::new(false));
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let stdout_receiver = spawn_reader(
            stdout,
            limits.max_response_bytes,
            Arc::clone(&stdout_overflow),
        );
        let stderr_receiver = spawn_reader(
            stderr,
            limits.max_stderr_bytes,
            Arc::clone(&stderr_overflow),
        );

        let mut framed_request = Vec::with_capacity(request_json.len() + 1);
        framed_request.extend_from_slice(request_json);
        framed_request.push(b'\n');
        let (writer_sender, writer_receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut stdin = stdin;
            let result = stdin
                .write_all(&framed_request)
                .and_then(|()| stdin.flush());
            let _ = writer_sender.send(result);
        });

        let mut forced_outcome = None;
        let status = loop {
            if stdout_overflow.load(Ordering::Relaxed) {
                forced_outcome = Some(AcquisitionOutcome::OutputTooLarge);
                terminate_and_reap(&mut child);
                break None;
            }
            if stderr_overflow.load(Ordering::Relaxed) {
                forced_outcome = Some(AcquisitionOutcome::StderrTooLarge);
                terminate_and_reap(&mut child);
                break None;
            }
            if started.elapsed() >= deadline {
                forced_outcome = Some(AcquisitionOutcome::Timeout);
                terminate_and_reap(&mut child);
                break None;
            }
            match child_has_exited(child.id()) {
                Ok(true) => match reap_exited_group(&mut child) {
                    Ok(status) => break Some(status),
                    Err(error) => {
                        forced_outcome = Some(AcquisitionOutcome::IoFailed {
                            message: error.to_string(),
                        });
                        break None;
                    }
                },
                Ok(false) => thread::sleep(Duration::from_millis(5)),
                Err(error) => {
                    forced_outcome = Some(AcquisitionOutcome::IoFailed {
                        message: error.to_string(),
                    });
                    terminate_and_reap(&mut child);
                    break None;
                }
            }
        };

        let writer_result = receive_writer(&writer_receiver);
        let stdout_read = receive_reader(&stdout_receiver, "stdout");
        let stderr_read = receive_reader(&stderr_receiver, "stderr");
        let stdout = stdout_read.bytes;
        let stderr = stderr_read.bytes;
        let exit_code = status.as_ref().and_then(ExitStatus::code);

        let outcome = forced_outcome.unwrap_or_else(|| {
            if let Err(error) = writer_result {
                return AcquisitionOutcome::RequestWriteFailed {
                    message: error.to_string(),
                };
            }
            if let Some(error) = stdout_read.error.or(stderr_read.error) {
                return AcquisitionOutcome::IoFailed { message: error };
            }
            let Some(status) = status else {
                return AcquisitionOutcome::IoFailed {
                    message: "helper produced no exit status".into(),
                };
            };
            if !status.success() {
                return AcquisitionOutcome::ExitNonzero {
                    code: status.code(),
                };
            }
            validate_frame(&stdout)
        });

        capture(started_at, started, exit_code, stdout, stderr, outcome)
    }
}

fn spawn(launch: &VerifiedLaunch, limits: &ResourceLimits) -> io::Result<Child> {
    let config = launch.command();
    launch.spawn(|command| {
        command
            .current_dir(launch.working_directory())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("TZ", "UTC")
            .env("HOME", "/nonexistent")
            .envs(&config.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        isolate_command_with_limits(
            command,
            launch.execution_account(),
            limits.isolation_limits(),
        );
    })
}

fn failed_spawn_capture(message: String) -> RunCapture {
    let started_at = Utc::now();
    let started = Instant::now();
    capture(
        started_at,
        started,
        None,
        Vec::new(),
        Vec::new(),
        AcquisitionOutcome::SpawnFailed { message },
    )
}

struct PipeRead {
    bytes: Vec<u8>,
    error: Option<String>,
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> Receiver<PipeRead> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(limit.min(64 * 1024));
        let mut buffer = [0_u8; 8192];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(read) => read,
                Err(error) => {
                    let _ = sender.send(PipeRead {
                        bytes: retained,
                        error: Some(error.to_string()),
                    });
                    return;
                }
            };
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_sub(retained.len());
            let copy = remaining.min(read);
            retained.extend_from_slice(&buffer[..copy]);
            if copy < read {
                overflow.store(true, Ordering::Relaxed);
            }
            // Continue draining even after overflow so a child can never turn
            // an output-limit failure into a pipe-capacity timeout.
        }
        let _ = sender.send(PipeRead {
            bytes: retained,
            error: None,
        });
    });
    receiver
}

fn receive_reader(receiver: &Receiver<PipeRead>, pipe: &str) -> PipeRead {
    match receiver.recv_timeout(Duration::from_millis(100)) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => PipeRead {
            bytes: Vec::new(),
            error: Some(format!("{pipe} did not close after helper termination")),
        },
        Err(RecvTimeoutError::Disconnected) => PipeRead {
            bytes: Vec::new(),
            error: Some(format!("{pipe} reader terminated unexpectedly")),
        },
    }
}

fn receive_writer(receiver: &Receiver<io::Result<()>>) -> io::Result<()> {
    match receiver.recv_timeout(Duration::from_millis(100)) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "request pipe did not close after termination",
        )),
        Err(RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("request writer terminated unexpectedly"))
        }
    }
}

fn validate_frame(stdout: &[u8]) -> AcquisitionOutcome {
    if stdout.is_empty() {
        return AcquisitionOutcome::Eof;
    }
    if !stdout.ends_with(b"\n") {
        return AcquisitionOutcome::MalformedFraming {
            message: "response must end with LF".into(),
        };
    }
    if stdout[..stdout.len() - 1].contains(&b'\n') {
        return AcquisitionOutcome::MalformedFraming {
            message: "expected exactly one response frame".into(),
        };
    }
    let frame = &stdout[..stdout.len() - 1];
    if frame.ends_with(b"\r") {
        return AcquisitionOutcome::MalformedFraming {
            message: "CRLF framing is not canonical".into(),
        };
    }
    match serde_json::from_slice::<serde_json::Value>(frame) {
        Ok(serde_json::Value::Object(_)) => AcquisitionOutcome::Response,
        Ok(_) => AcquisitionOutcome::MalformedJson {
            message: "top-level response must be an object".into(),
        },
        Err(error) => AcquisitionOutcome::MalformedJson {
            message: error.to_string(),
        },
    }
}

fn terminate_and_reap(child: &mut Child) {
    let group = Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX));
    signal_group_or_abort(group, Signal::SIGTERM);
    let grace = Instant::now();
    loop {
        match child_has_exited(child.id()) {
            Ok(false) if grace.elapsed() < Duration::from_millis(100) => {
                thread::sleep(Duration::from_millis(5));
            }
            _ => break,
        }
    }
    signal_group_or_abort(group, Signal::SIGKILL);
    let _ = child.wait();
}

fn reap_exited_group(child: &mut Child) -> io::Result<ExitStatus> {
    let group = Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX));
    signal_group_or_abort(group, Signal::SIGTERM);
    thread::sleep(Duration::from_millis(5));
    signal_group_or_abort(group, Signal::SIGKILL);
    child.wait()
}

fn signal_group_or_abort(group: Pid, signal_value: Signal) {
    match signal::killpg(group, signal_value) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(error) => {
            eprintln!(
                "nq: cannot contain helper process group {} with {signal_value:?}: {error}",
                group.as_raw()
            );
            std::process::abort();
        }
    }
}

fn capture(
    started_at: DateTime<Utc>,
    started: Instant,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    outcome: AcquisitionOutcome,
) -> RunCapture {
    let duration = started.elapsed();
    RunCapture {
        started_at,
        finished_at: Utc::now(),
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        exit_code,
        stdout,
        stderr,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::OnceLock;

    use super::*;

    fn shell(script: &str) -> CommandConfig {
        CommandConfig {
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".into(), script.into()],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: PathBuf::from("/tmp"),
        }
    }

    fn limits(bytes: usize) -> ResourceLimits {
        ResourceLimits {
            max_response_bytes: bytes,
            max_stderr_bytes: bytes,
            max_observations: 10,
            ..ResourceLimits::default()
        }
    }

    fn python_script(source: &str) -> String {
        format!("import sys\nsys.stdin.read()\nprint('{{\"source\":\"{source}\"}}')\n")
    }

    fn sealed_execution_available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            let directory = tempfile::tempdir().expect("memfd execution probe directory");
            let command = CommandConfig {
                executable: PathBuf::from("/bin/true"),
                args: Vec::new(),
                env: BTreeMap::new(),
                execution_account: nix::unistd::geteuid().as_raw().to_string(),
                allow_same_identity_in_debug: true,
                working_directory: directory.path().to_path_buf(),
            };
            let launch = VerifiedLaunch::open(&command).expect("qualify memfd execution probe");
            match launch.spawn(|child| {
                child
                    .current_dir(launch.working_directory())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
            }) {
                Ok(mut child) => child
                    .wait()
                    .expect("wait for memfd execution probe")
                    .success(),
                Err(error)
                    if error.kind() == io::ErrorKind::PermissionDenied
                        && fs::read_to_string("/proc/self/attr/current")
                            .is_ok_and(|profile| profile.contains("unpriv_bwrap")) =>
                {
                    eprintln!(
                        "skipping execution assertion: sandbox AppArmor denies executable memfds"
                    );
                    false
                }
                Err(error) => panic!("sealed memfd execution probe failed: {error}"),
            }
        })
    }

    #[test]
    fn accepts_exactly_one_json_line() {
        if !sealed_execution_available() {
            return;
        }
        let result = StdioRunner.run(
            &shell("read request; printf '{\"ok\":true}\\n'"),
            br#"{"request":true}"#,
            Duration::from_secs(1),
            &limits(1024),
        );
        assert_eq!(result.outcome, AcquisitionOutcome::Response);
        assert_eq!(result.response_frame(), Some(br#"{"ok":true}"#.as_slice()));
    }

    #[test]
    fn distinguishes_eof_nonzero_and_extra_frames() {
        if !sealed_execution_available() {
            return;
        }
        let eof = StdioRunner.run(
            &shell("read request"),
            b"{}",
            Duration::from_secs(1),
            &limits(1024),
        );
        assert_eq!(eof.outcome, AcquisitionOutcome::Eof);

        let nonzero = StdioRunner.run(
            &shell("read request; exit 7"),
            b"{}",
            Duration::from_secs(1),
            &limits(1024),
        );
        assert_eq!(
            nonzero.outcome,
            AcquisitionOutcome::ExitNonzero { code: Some(7) }
        );

        let extra = StdioRunner.run(
            &shell("read request; printf '{}\\n{}\\n'"),
            b"{}",
            Duration::from_secs(1),
            &limits(1024),
        );
        assert!(matches!(
            extra.outcome,
            AcquisitionOutcome::MalformedFraming { .. }
        ));
    }

    #[test]
    fn output_over_pipe_capacity_is_not_timeout() {
        if !sealed_execution_available() {
            return;
        }
        let result = StdioRunner.run(
            &shell("read request; head -c 131072 /dev/zero"),
            b"{}",
            Duration::from_secs(2),
            &limits(1024),
        );
        assert_eq!(result.outcome, AcquisitionOutcome::OutputTooLarge);
    }

    #[test]
    fn timeout_terminates_process_group() {
        if !sealed_execution_available() {
            return;
        }
        let result = StdioRunner.run(
            &shell("read request; sleep 10"),
            b"{}",
            Duration::from_millis(25),
            &limits(1024),
        );
        assert_eq!(result.outcome, AcquisitionOutcome::Timeout);
        assert!(result.duration_ms < 1_000);
    }

    #[test]
    fn stderr_has_independent_bound() {
        if !sealed_execution_available() {
            return;
        }
        let result = StdioRunner.run(
            &shell("read request; head -c 4096 /dev/zero >&2; printf '{}\\n'"),
            b"{}",
            Duration::from_secs(1),
            &limits(32),
        );
        assert_eq!(result.outcome, AcquisitionOutcome::StderrTooLarge);
    }

    #[test]
    fn descendant_cannot_hold_capture_pipes_open_after_helper_exit() {
        if !sealed_execution_available() {
            return;
        }
        let result = StdioRunner.run(
            &shell("read request; sleep 10 & printf '{}\\n'"),
            b"{}",
            Duration::from_secs(1),
            &limits(1024),
        );
        assert_eq!(result.outcome, AcquisitionOutcome::Response);
        assert!(result.duration_ms < 1_000);
    }

    #[test]
    fn replaced_root_executable_path_cannot_redirect_verified_launch() {
        if !sealed_execution_available() {
            return;
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let helper = directory.path().join("helper");
        fs::copy("/bin/sh", &helper).expect("copy qualified shell");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let command = CommandConfig {
            executable: helper.clone(),
            args: vec![
                "-c".into(),
                "read ignored; printf '{\"source\":\"qualified-root\"}\\n'".into(),
            ],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: directory.path().to_path_buf(),
        };
        let launch = VerifiedLaunch::open(&command).expect("qualify copied executable");

        fs::rename(&helper, directory.path().join("qualified-shell")).unwrap();
        fs::copy("/bin/false", &helper).expect("replace configured pathname");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();

        let capture = StdioRunner.run_verified(
            &launch,
            br#"{"request":true}"#,
            Duration::from_secs(2),
            &limits(1024),
        );
        assert_eq!(capture.outcome, AcquisitionOutcome::Response);
        assert_eq!(
            capture.response_frame(),
            Some(br#"{"source":"qualified-root"}"#.as_slice())
        );
    }

    #[test]
    fn same_inode_native_source_mutation_cannot_change_sealed_launch() {
        if !sealed_execution_available() {
            return;
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let helper = directory.path().join("helper");
        fs::copy("/bin/sh", &helper).expect("copy qualified shell");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let command = CommandConfig {
            executable: helper.clone(),
            args: vec![
                "-c".into(),
                "read ignored; printf '{\"source\":\"qualified-native\"}\\n'".into(),
            ],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: directory.path().to_path_buf(),
        };
        let launch = VerifiedLaunch::open(&command).expect("qualify copied executable");
        let inode = fs::metadata(&helper).unwrap().ino();

        fs::copy("/bin/false", &helper).expect("mutate configured inode in place");
        assert_eq!(fs::metadata(&helper).unwrap().ino(), inode);

        let capture = StdioRunner.run_verified(
            &launch,
            br#"{"request":true}"#,
            Duration::from_secs(2),
            &limits(1024),
        );
        assert_eq!(capture.outcome, AcquisitionOutcome::Response);
        assert_eq!(
            capture.response_frame(),
            Some(br#"{"source":"qualified-native"}"#.as_slice())
        );
    }

    #[test]
    fn replaced_script_and_env_shebang_paths_execute_only_retained_bytes() {
        if !sealed_execution_available() {
            return;
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        for direct in [false, true] {
            let script = directory.path().join(if direct {
                "direct-helper.py"
            } else {
                "argument-helper.py"
            });
            let mut source = python_script("qualified-script");
            if direct {
                source.insert_str(0, "#!/usr/bin/env python3\n");
            }
            fs::write(&script, source).unwrap();
            if direct {
                fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let command = CommandConfig {
                executable: if direct {
                    script.clone()
                } else {
                    PathBuf::from("/usr/bin/python3")
                },
                args: if direct {
                    Vec::new()
                } else {
                    vec![script.display().to_string()]
                },
                env: BTreeMap::new(),
                execution_account: nix::unistd::geteuid().as_raw().to_string(),
                allow_same_identity_in_debug: true,
                working_directory: directory.path().to_path_buf(),
            };
            let launch = VerifiedLaunch::open(&command).expect("qualify script chain");

            fs::rename(&script, script.with_extension("qualified")).unwrap();
            fs::write(&script, python_script("replacement-script")).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

            let capture = StdioRunner.run_verified(
                &launch,
                br#"{"request":true}"#,
                Duration::from_secs(2),
                &limits(1024),
            );
            assert_eq!(capture.outcome, AcquisitionOutcome::Response);
            assert_eq!(
                capture.response_frame(),
                Some(br#"{"source":"qualified-script"}"#.as_slice())
            );
        }
    }

    #[test]
    fn same_inode_script_source_mutation_cannot_change_sealed_launch() {
        if !sealed_execution_available() {
            return;
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let script = directory.path().join("helper.py");
        fs::write(&script, python_script("qualified-script")).unwrap();
        let command = CommandConfig {
            executable: PathBuf::from("/usr/bin/python3"),
            args: vec![script.display().to_string()],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: directory.path().to_path_buf(),
        };
        let launch = VerifiedLaunch::open(&command).expect("qualify script argument");
        let inode = fs::metadata(&script).unwrap().ino();
        fs::write(&script, python_script("mutated-script")).unwrap();
        assert_eq!(fs::metadata(&script).unwrap().ino(), inode);

        let capture = StdioRunner.run_verified(
            &launch,
            br#"{"request":true}"#,
            Duration::from_secs(2),
            &limits(1024),
        );
        assert_eq!(capture.outcome, AcquisitionOutcome::Response);
        assert_eq!(
            capture.response_frame(),
            Some(br#"{"source":"qualified-script"}"#.as_slice())
        );
    }

    #[test]
    fn bare_cwd_relative_script_argument_executes_only_qualified_snapshot() {
        if !sealed_execution_available() {
            return;
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let script = directory.path().join("helper.py");
        fs::write(&script, python_script("qualified-bare-argument")).unwrap();
        let command = CommandConfig {
            executable: PathBuf::from("/usr/bin/python3"),
            args: vec!["helper.py".into()],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: directory.path().to_path_buf(),
        };
        let launch = VerifiedLaunch::open(&command).expect("qualify bare script argument");
        assert!(launch.identity().execution_chain.iter().any(|artifact| {
            artifact.role == crate::identity::ArtifactRole::FixedArgument
                && artifact.fixed_argument.as_deref() == Some("helper.py")
        }));

        fs::rename(&script, directory.path().join("qualified.py")).unwrap();
        fs::write(&script, python_script("replacement-bare-argument")).unwrap();

        let capture = StdioRunner.run_verified(
            &launch,
            br#"{"request":true}"#,
            Duration::from_secs(2),
            &limits(1024),
        );
        assert_eq!(capture.outcome, AcquisitionOutcome::Response);
        assert_eq!(
            capture.response_frame(),
            Some(br#"{"source":"qualified-bare-argument"}"#.as_slice())
        );
    }

    #[test]
    fn cwd_rename_and_replacement_cannot_redirect_verified_launch() {
        if !sealed_execution_available() {
            return;
        }
        let root = tempfile::tempdir().expect("temporary directory");
        let configured_cwd = root.path().join("cwd");
        fs::create_dir(&configured_cwd).unwrap();
        fs::write(configured_cwd.join("marker.txt"), "qualified-cwd").unwrap();
        let command = CommandConfig {
            executable: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".into(),
                "read ignored; value=$(cat marker.txt); printf '{\"source\":\"%s\"}\\n' \"$value\""
                    .into(),
            ],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: configured_cwd.clone(),
        };
        let launch = VerifiedLaunch::open(&command).expect("qualify cwd descriptor");

        fs::rename(&configured_cwd, root.path().join("qualified-cwd")).unwrap();
        fs::create_dir(&configured_cwd).unwrap();
        fs::write(configured_cwd.join("marker.txt"), "replacement-cwd").unwrap();

        let capture = StdioRunner.run_verified(
            &launch,
            br#"{"request":true}"#,
            Duration::from_secs(2),
            &limits(1024),
        );
        assert_eq!(capture.outcome, AcquisitionOutcome::Response);
        assert_eq!(
            capture.response_frame(),
            Some(br#"{"source":"qualified-cwd"}"#.as_slice())
        );
    }

    #[test]
    fn distinct_uid_executes_restrictive_snapshot_and_timeout_reaps_when_permitted() {
        let account = ["nobody", "65534"]
            .into_iter()
            .find_map(|candidate| nq_helper_sandbox::resolve_account(candidate, false).ok());
        let Some(account) = account else {
            eprintln!("skipping distinct-UID launch: no isolated local account");
            return;
        };
        let directory = tempfile::tempdir().expect("temporary directory");
        let helper = directory.path().join("private-helper");
        fs::copy("/bin/sh", &helper).expect("copy restrictive executable");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
            .expect("restrict source mode");
        let command = CommandConfig {
            executable: helper.clone(),
            args: vec![
                "-c".into(),
                "printf '{\"uid\":%s,\"gid\":%s}\\n' \"$(id -u)\" \"$(id -g)\"".into(),
            ],
            env: BTreeMap::new(),
            execution_account: account.configured.clone(),
            allow_same_identity_in_debug: false,
            working_directory: PathBuf::from("/tmp"),
        };
        let capture = StdioRunner.run(
            &command,
            br#"{"request":true}"#,
            Duration::from_secs(1),
            &limits(1024),
        );
        if matches!(
            &capture.outcome,
            AcquisitionOutcome::SpawnFailed { message }
                if message.contains("Operation not permitted") || message.contains("Permission denied")
                    || message.contains("runtime/deployment object is not root-owned")
        ) {
            eprintln!(
                "skipping distinct-UID launch: host lacks helper-drop capabilities or a root-owned runtime"
            );
            return;
        }
        assert_eq!(capture.outcome, AcquisitionOutcome::Response);
        let response: serde_json::Value =
            serde_json::from_slice(capture.response_frame().expect("response frame"))
                .expect("response JSON");
        assert_eq!(response["uid"], account.uid);
        assert_eq!(response["gid"], account.gid);
        assert_eq!(
            fs::metadata(&helper).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let timeout_command = CommandConfig {
            executable: helper,
            args: vec![
                "-c".into(),
                "printf '%d\\n' $$ >&2; trap '' TERM; sleep 10".into(),
            ],
            env: BTreeMap::new(),
            execution_account: account.configured,
            allow_same_identity_in_debug: false,
            working_directory: PathBuf::from("/tmp"),
        };
        let timed_out = StdioRunner.run(
            &timeout_command,
            br#"{"request":true}"#,
            Duration::from_millis(30),
            &limits(1024),
        );
        assert_eq!(timed_out.outcome, AcquisitionOutcome::Timeout);
        let child_pid: i32 = String::from_utf8_lossy(&timed_out.stderr)
            .lines()
            .next()
            .expect("helper PID log")
            .parse()
            .expect("numeric helper PID");
        assert_eq!(
            signal::kill(Pid::from_raw(child_pid), None),
            Err(nix::errno::Errno::ESRCH),
            "timed-out distinct-UID process must be reaped"
        );
    }
}
