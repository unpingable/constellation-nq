//! Supervised persistent helper execution over a private Unix-domain socket.
//!
//! The carrier owns the helper process, its process group, and a uniquely named
//! daemon-owned `0730` runtime directory whose group is the isolated helper's
//! primary GID. The helper receives the socket path through
//! [`NQ_HELPER_SOCKET_ENV`] and creates a `0600` stream socket there. The
//! daemon takes exact-inode custody of that socket before connecting. On Linux,
//! every connection is authenticated with `SO_PEERCRED` against the direct
//! child PID and admitted helper UID/primary GID.
//!
//! This module is intentionally an acquisition transport. It establishes one
//! bounded NDJSON response for each request, but common protocol validation and
//! profile admission remain separate result planes.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Pid, getegid, geteuid};
use nq_helper_sandbox::{
    ExecutionAccount, IsolationLimits, ValidatedRuntimeRoot, child_has_exited,
    isolate_command_with_limits, open_runtime_root, prepare_runtime_directory,
    reclaim_runtime_directory, take_unix_socket_custody,
};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use thiserror::Error;

use crate::config::CommandConfig;
use crate::identity::VerifiedLaunch;

/// Environment variable containing the NQ-owned Unix socket pathname.
pub const NQ_HELPER_SOCKET_ENV: &str = "NQ_HELPER_SOCKET";

/// Environment variable containing the NQ-owned watcher instance identifier.
pub const NQ_HELPER_INSTANCE_ENV: &str = "NQ_HELPER_INSTANCE_ID";

/// Environment variable through which the supervisor declares the UID that owns
/// the helper's socket directory. Under supervision the directory is
/// daemon-owned (mode 0730, granting only the helper's primary group write), so
/// the helper must not assume it owns its own containment; its own directory
/// check is diagnostic and validates against this declared owner, while the
/// authoritative directory and socket custody checks are enforced parent-side.
pub const NQ_HELPER_SOCKET_DIR_OWNER_ENV: &str = "NQ_HELPER_SOCKET_DIR_OWNER_UID";

const SOCKET_FILE_NAME: &str = "helper.sock";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const TERMINATION_GRACE: Duration = Duration::from_millis(100);

/// Launch-time policy for one persistent helper.
#[derive(Debug, Clone)]
pub struct UnixRunnerOptions {
    /// Existing root below which a unique private runtime directory is made.
    pub runtime_root: PathBuf,
    /// Stable NQ-owned instance identity exposed to the helper.
    pub instance_id: String,
    /// Maximum time allowed for socket creation, listening, and authentication.
    pub startup_timeout: Duration,
    /// Maximum stderr bytes retained between exchanges.
    pub max_stderr_bytes: usize,
    /// UID required in the socket metadata and Linux peer credentials.
    pub expected_uid: u32,
    /// Primary GID bound to the helper's private runtime-directory access.
    pub expected_gid: u32,
    /// Hard OS limits installed in the persistent helper process.
    pub isolation_limits: IsolationLimits,
}

impl UnixRunnerOptions {
    /// Construct options for a helper inheriting the daemon's effective UID.
    #[must_use]
    pub fn inherited_identity(
        runtime_root: impl Into<PathBuf>,
        instance_id: impl Into<String>,
        startup_timeout: Duration,
        max_stderr_bytes: usize,
    ) -> Self {
        Self {
            runtime_root: runtime_root.into(),
            instance_id: instance_id.into(),
            startup_timeout,
            max_stderr_bytes,
            expected_uid: geteuid().as_raw(),
            expected_gid: getegid().as_raw(),
            isolation_limits: IsolationLimits::default(),
        }
    }

    /// Construct options bound to an admitted helper execution account.
    #[must_use]
    pub fn for_account(
        runtime_root: impl Into<PathBuf>,
        instance_id: impl Into<String>,
        startup_timeout: Duration,
        max_stderr_bytes: usize,
        account: &ExecutionAccount,
    ) -> Self {
        Self {
            runtime_root: runtime_root.into(),
            instance_id: instance_id.into(),
            startup_timeout,
            max_stderr_bytes,
            expected_uid: account.uid,
            expected_gid: account.gid,
            isolation_limits: IsolationLimits::default(),
        }
    }

    /// Replace the default hard process limits with the admitted configuration.
    #[must_use]
    pub fn with_isolation_limits(mut self, limits: IsolationLimits) -> Self {
        self.isolation_limits = limits;
        self
    }
}

/// The startup boundary that prevented a persistent helper from becoming
/// usable. Stderr is retained separately in [`UnixLaunchError`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UnixLaunchFailure {
    /// The supplied runner options are not safe or meaningful.
    #[error("invalid Unix helper configuration: {message}")]
    InvalidConfiguration {
        /// Exact validation failure.
        message: String,
    },
    /// A private runtime directory could not be created or secured.
    #[error("could not prepare private helper directory: {message}")]
    RuntimeDirectory {
        /// Operating-system failure.
        message: String,
    },
    /// The fixed helper command could not be spawned.
    #[error("could not spawn Unix helper: {message}")]
    SpawnFailed {
        /// Operating-system spawn failure.
        message: String,
    },
    /// The child exited before a socket exchange could be established.
    #[error("Unix helper exited during startup with code {code:?}")]
    HelperExited {
        /// Conventional exit code, or `None` when terminated by signal.
        code: Option<i32>,
    },
    /// Startup exceeded its monotonic deadline.
    #[error("Unix helper did not become ready before its startup deadline")]
    Timeout,
    /// The helper created something other than a Unix stream socket.
    #[error("helper socket path is not a Unix socket")]
    NotSocket,
    /// Socket permissions were not exactly `0600` before connection.
    #[error("helper socket mode is {actual:#05o}; expected 0o600")]
    SocketPermissions {
        /// Observed permission bits.
        actual: u32,
    },
    /// The filesystem owner did not match the expected execution UID.
    #[error("helper socket UID is {actual}; expected {expected}")]
    SocketOwner {
        /// Expected helper UID.
        expected: u32,
        /// Observed socket UID.
        actual: u32,
    },
    /// The filesystem group did not match the expected execution GID. Ownership
    /// is checked as UID and GID separately; one does not stand in for the other.
    #[error("helper socket GID is {actual}; expected {expected}")]
    SocketGroup {
        /// Expected helper GID.
        expected: u32,
        /// Observed socket GID.
        actual: u32,
    },
    /// Linux `SO_PEERCRED` could not be obtained.
    #[error("could not read Linux SO_PEERCRED: {message}")]
    PeerCredentialsUnavailable {
        /// Socket-option failure.
        message: String,
    },
    /// The connected process was not the direct supervised child.
    #[error(
        "helper peer credentials were pid={actual_pid}, uid={actual_uid}, gid={actual_gid}; expected pid={expected_pid}, uid={expected_uid}, gid={expected_gid}"
    )]
    PeerCredentialMismatch {
        /// Direct child PID allocated by `spawn`.
        expected_pid: u32,
        /// Expected execution UID.
        expected_uid: u32,
        /// Primary helper GID bound by admission.
        expected_gid: u32,
        /// PID reported by the kernel.
        actual_pid: i32,
        /// UID reported by the kernel.
        actual_uid: u32,
        /// GID reported by the kernel.
        actual_gid: u32,
    },
    /// The child exceeded its startup stderr allowance.
    #[error("Unix helper exceeded its stderr limit during startup")]
    StderrTooLarge,
    /// Socket metadata, connection, or process supervision failed.
    #[error("Unix helper startup I/O failed: {message}")]
    IoFailed {
        /// Operating-system failure.
        message: String,
    },
    /// The carrier requires Linux peer credentials.
    #[error("the supervised Unix helper carrier requires Linux SO_PEERCRED")]
    UnsupportedPlatform,
}

/// Complete typed startup failure with bounded helper logs.
#[derive(Debug, Error)]
#[error("{failure}")]
pub struct UnixLaunchError {
    /// Exact startup boundary that failed.
    pub failure: UnixLaunchFailure,
    /// Bounded stderr captured before the failed child was reaped.
    pub stderr: Vec<u8>,
}

/// Phase in which an absolute request deadline expired.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnixIoPhase {
    /// Waiting to write all request framing bytes.
    WriteRequest,
    /// Waiting for the single response frame.
    ReadResponse,
}

/// Acquisition outcome for one exchange on a persistent helper connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum UnixAcquisitionOutcome {
    /// One bounded LF-terminated top-level JSON object was received.
    Response,
    /// The caller supplied bytes that cannot form one request line.
    InvalidRequestFraming {
        /// Exact local framing failure.
        message: String,
    },
    /// The request could not be completely written.
    RequestWriteFailed {
        /// Operating-system write failure.
        message: String,
    },
    /// The absolute monotonic deadline expired.
    Timeout {
        /// I/O phase active at expiry.
        phase: UnixIoPhase,
    },
    /// The response exceeded the negotiated byte bound.
    OutputTooLarge,
    /// Persistent helper logs exceeded their configured bound.
    StderrTooLarge,
    /// The peer cleanly closed before emitting any response bytes.
    Eof,
    /// The connected transport was lost or closed partway through a frame.
    Disconnect {
        /// Exact disconnect condition.
        message: String,
    },
    /// Bytes did not form exactly one canonical LF-terminated line.
    MalformedFraming {
        /// Exact framing violation.
        message: String,
    },
    /// The frame was not a top-level UTF-8 JSON object.
    MalformedJson {
        /// JSON or top-level shape failure.
        message: String,
    },
    /// The persistent child exited between exchanges or while awaiting data.
    HelperExited {
        /// Conventional exit code, or `None` when terminated by signal.
        code: Option<i32>,
    },
    /// No live connection exists; the caller must invoke `restart`.
    NotRunning,
    /// Process or socket I/O failed without a more specific classification.
    IoFailed {
        /// Operating-system failure.
        message: String,
    },
}

/// Complete bounded capture of one persistent socket exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixExchangeCapture {
    /// Wall-clock start used for audit presentation, not deadlines.
    pub started_at: DateTime<Utc>,
    /// Wall-clock finish.
    pub finished_at: DateTime<Utc>,
    /// Monotonic elapsed duration.
    pub duration_ms: u64,
    /// PID that owned the authenticated connection.
    pub helper_pid: Option<u32>,
    /// Exact response bytes, including LF when a complete line was read.
    pub response: Vec<u8>,
    /// Bounded stderr accrued since the previous exchange.
    pub stderr: Vec<u8>,
    /// Acquisition-plane result.
    pub outcome: UnixAcquisitionOutcome,
}

impl UnixExchangeCapture {
    /// Return the response JSON without its LF only after acquisition succeeds.
    #[must_use]
    pub fn response_frame(&self) -> Option<&[u8]> {
        if self.outcome == UnixAcquisitionOutcome::Response {
            self.response.strip_suffix(b"\n")
        } else {
            None
        }
    }
}

/// Supervised long-lived Unix helper.
///
/// Calls to [`Self::exchange`] require exclusive access, which makes the v1
/// request/response sequencing rule structural. Any ambiguous transport state
/// terminates and reaps the process group; [`Self::restart`] creates a fresh
/// child and authenticated connection in the same private directory.
#[derive(Debug)]
pub struct UnixRunner {
    launch: VerifiedLaunch,
    options: UnixRunnerOptions,
    socket_directory: TempDir,
    runtime_root: ValidatedRuntimeRoot,
    socket_directory_path: PathBuf,
    socket_path: PathBuf,
    state: Option<ProcessState>,
}

impl UnixRunner {
    /// Launch, supervise, connect to, and authenticate one persistent helper.
    ///
    /// # Errors
    ///
    /// Returns [`UnixLaunchError`] if private-path preparation, process spawn,
    /// bounded connection, socket validation, or peer authentication fails.
    pub fn launch(
        command: &CommandConfig,
        options: UnixRunnerOptions,
    ) -> Result<Self, UnixLaunchError> {
        let launch = VerifiedLaunch::open(command).map_err(|error| {
            bare_launch_error(UnixLaunchFailure::SpawnFailed {
                message: error.to_string(),
            })
        })?;
        Self::launch_verified(launch, options)
    }

    /// Launch from an already-qualified descriptor-bound command.
    ///
    /// The retained descriptors remain owned by this runner and are reused
    /// for every clean persistent-helper restart.
    ///
    /// # Errors
    ///
    /// Returns a typed startup failure if descriptor validation, private-path
    /// setup, spawn, socket authentication, or bounded startup fails.
    pub fn launch_verified(
        launch: VerifiedLaunch,
        options: UnixRunnerOptions,
    ) -> Result<Self, UnixLaunchError> {
        validate_options(&launch, &options).map_err(bare_launch_error)?;
        let (runtime_root, socket_directory, socket_directory_path) =
            create_private_directory(&options).map_err(bare_launch_error)?;
        let socket_path = socket_directory_path.join(SOCKET_FILE_NAME);
        if socket_path.as_os_str().as_encoded_bytes().len() >= unix_path_limit() {
            return Err(bare_launch_error(UnixLaunchFailure::InvalidConfiguration {
                message: "private helper socket path is too long for AF_UNIX".into(),
            }));
        }

        let mut runner = Self {
            launch,
            options,
            socket_directory,
            runtime_root,
            socket_directory_path,
            socket_path,
            state: None,
        };
        runner.start()?;
        Ok(runner)
    }

    /// Private socket path supplied to the helper process.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Private per-instance parent directory owned by this runner.
    #[must_use]
    pub fn socket_directory(&self) -> &Path {
        &self.socket_directory_path
    }

    /// PID of the currently authenticated child, if one is running.
    #[must_use]
    pub fn child_pid(&self) -> Option<u32> {
        self.state.as_ref().map(|state| state.child.id())
    }

    /// Whether the runner currently owns a connection. This does not perform a
    /// process-system call; an exited child is observed by the next exchange.
    #[must_use]
    pub fn has_connection(&self) -> bool {
        self.state.is_some()
    }

    /// Execute exactly one request/response exchange.
    ///
    /// `request_json` is the JSON document without framing bytes; this method
    /// appends exactly one LF. `max_response_bytes` includes the required LF.
    /// A zero deadline or response bound deterministically fails without I/O.
    #[must_use]
    pub fn exchange(
        &mut self,
        request_json: &[u8],
        deadline: Duration,
        max_response_bytes: usize,
    ) -> UnixExchangeCapture {
        let started_at = Utc::now();
        let started = Instant::now();
        let helper_pid = self.child_pid();

        if self.state.is_none() {
            return exchange_capture(
                started_at,
                started,
                helper_pid,
                Vec::new(),
                Vec::new(),
                UnixAcquisitionOutcome::NotRunning,
            );
        }

        let request = match prepare_request(request_json, deadline, max_response_bytes) {
            Ok(request) => request,
            Err(outcome) => {
                return self.local_exchange_failure(started_at, started, helper_pid, outcome);
            }
        };

        if let Some(outcome) = self.preflight() {
            return self.fail_exchange(started_at, started, helper_pid, Vec::new(), outcome);
        }

        let write_result = self
            .state
            .as_mut()
            .map_or(Err(UnixAcquisitionOutcome::NotRunning), |state| {
                write_bounded(state, &request, started, deadline)
            });
        if let Err(outcome) = write_result {
            return self.fail_exchange(started_at, started, helper_pid, Vec::new(), outcome);
        }

        let response_result = self.state.as_mut().map_or_else(
            || Err((Vec::new(), UnixAcquisitionOutcome::NotRunning)),
            |state| read_bounded(state, started, deadline, max_response_bytes),
        );
        let response = match response_result {
            Ok(response) => response,
            Err((response, outcome)) => {
                return self.fail_exchange(started_at, started, helper_pid, response, outcome);
            }
        };

        if self
            .state
            .as_ref()
            .is_some_and(|state| state.stderr_overflow.load(Ordering::Acquire))
        {
            return self.fail_exchange(
                started_at,
                started,
                helper_pid,
                response,
                UnixAcquisitionOutcome::StderrTooLarge,
            );
        }
        let stderr = self
            .state
            .as_ref()
            .map_or_else(Vec::new, |state| take_stderr(&state.stderr));
        exchange_capture(
            started_at,
            started,
            helper_pid,
            response,
            stderr,
            UnixAcquisitionOutcome::Response,
        )
    }

    /// Terminate any old process group, remove its socket, and establish a new
    /// child and authenticated connection.
    ///
    /// # Errors
    ///
    /// Returns [`UnixLaunchError`] when the replacement helper cannot become
    /// ready within the configured startup deadline.
    pub fn restart(&mut self) -> Result<(), UnixLaunchError> {
        self.shutdown();
        self.start()
    }

    /// Terminate and reap the owned process group. Calling this more than once
    /// is harmless. A subsequent exchange returns `NotRunning` until restart.
    pub fn shutdown(&mut self) {
        if let Some(state) = self.state.take() {
            let _ = stop_process(state);
        }
        remove_owned_socket(&self.socket_path);
        let _ = reclaim_runtime_directory(self.socket_directory.path());
    }

    fn start(&mut self) -> Result<(), UnixLaunchError> {
        self.runtime_root.revalidate().map_err(|error| {
            bare_launch_error(UnixLaunchFailure::RuntimeDirectory {
                message: error.to_string(),
            })
        })?;
        validate_private_directory_alias(self.socket_directory.path(), &self.socket_directory_path)
            .map_err(bare_launch_error)?;
        remove_owned_socket_checked(&self.socket_path).map_err(bare_launch_error)?;
        prepare_runtime_directory(
            self.socket_directory.path(),
            self.launch.execution_account(),
        )
        .map_err(|error| {
            bare_launch_error(UnixLaunchFailure::RuntimeDirectory {
                message: error.to_string(),
            })
        })?;
        let stderr = Arc::new(Mutex::new(Vec::with_capacity(
            self.options.max_stderr_bytes.min(64 * 1024),
        )));
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let mut child =
            spawn_helper(&self.launch, &self.options, &self.socket_path).map_err(|error| {
                bare_launch_error(UnixLaunchFailure::SpawnFailed {
                    message: error.to_string(),
                })
            })?;
        let expected_pid = child.id();
        let stderr_pipe = child.stderr.take().expect("piped helper stderr");
        let stderr_thread = spawn_stderr_reader(
            stderr_pipe,
            self.options.max_stderr_bytes,
            Arc::clone(&stderr),
            Arc::clone(&stderr_overflow),
        );

        let connection = connect_bounded(
            &mut child,
            &self.socket_path,
            expected_pid,
            &self.options,
            &stderr_overflow,
        );
        let stream = match connection {
            Ok(stream) => stream,
            Err(failure) => {
                let status = terminate_and_reap(&mut child);
                let _ = stderr_thread.join();
                let stderr = take_stderr(&stderr);
                let failure = match (failure, status) {
                    (UnixLaunchFailure::HelperExited { code: None }, Some(status)) => {
                        UnixLaunchFailure::HelperExited {
                            code: status.code(),
                        }
                    }
                    (failure, _) => failure,
                };
                return Err(UnixLaunchError { failure, stderr });
            }
        };

        self.state = Some(ProcessState {
            child,
            stream,
            stderr,
            stderr_overflow,
            stderr_thread: Some(stderr_thread),
        });
        Ok(())
    }

    fn preflight(&mut self) -> Option<UnixAcquisitionOutcome> {
        let state = self.state.as_mut().expect("preflight requires state");
        if state.stderr_overflow.load(Ordering::Acquire) {
            return Some(UnixAcquisitionOutcome::StderrTooLarge);
        }
        match child_has_exited(state.child.id()) {
            Ok(true) => return Some(UnixAcquisitionOutcome::HelperExited { code: None }),
            Ok(false) => {}
            Err(error) => {
                return Some(UnixAcquisitionOutcome::IoFailed {
                    message: format!("could not inspect helper process: {error}"),
                });
            }
        }

        let mut byte = [0_u8; 1];
        match state.stream.read(&mut byte) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => None,
            Ok(0) => Some(UnixAcquisitionOutcome::Eof),
            Ok(_) => Some(UnixAcquisitionOutcome::MalformedFraming {
                message: "helper emitted unsolicited bytes before a request".into(),
            }),
            Err(error) if is_disconnect(&error) => Some(UnixAcquisitionOutcome::Disconnect {
                message: error.to_string(),
            }),
            Err(error) => Some(UnixAcquisitionOutcome::IoFailed {
                message: error.to_string(),
            }),
        }
    }

    fn fail_exchange(
        &mut self,
        started_at: DateTime<Utc>,
        started: Instant,
        helper_pid: Option<u32>,
        response: Vec<u8>,
        outcome: UnixAcquisitionOutcome,
    ) -> UnixExchangeCapture {
        let (stderr, status) = self
            .state
            .take()
            .map_or_else(|| (Vec::new(), None), stop_process);
        let outcome = match (outcome, status) {
            (UnixAcquisitionOutcome::HelperExited { code: None }, Some(status)) => {
                UnixAcquisitionOutcome::HelperExited {
                    code: status.code(),
                }
            }
            (outcome, _) => outcome,
        };
        remove_owned_socket(&self.socket_path);
        exchange_capture(started_at, started, helper_pid, response, stderr, outcome)
    }

    fn local_exchange_failure(
        &self,
        started_at: DateTime<Utc>,
        started: Instant,
        helper_pid: Option<u32>,
        outcome: UnixAcquisitionOutcome,
    ) -> UnixExchangeCapture {
        let stderr = self
            .state
            .as_ref()
            .map_or_else(Vec::new, |state| take_stderr(&state.stderr));
        exchange_capture(started_at, started, helper_pid, Vec::new(), stderr, outcome)
    }
}

impl Drop for UnixRunner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Debug)]
struct ProcessState {
    child: Child,
    stream: UnixStream,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_overflow: Arc<AtomicBool>,
    stderr_thread: Option<thread::JoinHandle<io::Result<()>>>,
}

fn validate_options(
    launch: &VerifiedLaunch,
    options: &UnixRunnerOptions,
) -> Result<(), UnixLaunchFailure> {
    let command = launch.command();
    if !command.executable.is_absolute() {
        return Err(UnixLaunchFailure::InvalidConfiguration {
            message: "helper executable must be absolute".into(),
        });
    }
    if !command.working_directory.is_absolute() {
        return Err(UnixLaunchFailure::InvalidConfiguration {
            message: "helper working directory must be absolute".into(),
        });
    }
    if !options.runtime_root.is_absolute() {
        return Err(UnixLaunchFailure::InvalidConfiguration {
            message: "helper runtime root must be absolute".into(),
        });
    }
    if options.startup_timeout.is_zero() {
        return Err(UnixLaunchFailure::InvalidConfiguration {
            message: "startup timeout must be greater than zero".into(),
        });
    }
    if options.isolation_limits.address_space_bytes == 0
        || options.isolation_limits.cpu_seconds == 0
        || options.isolation_limits.processes == 0
        || options.isolation_limits.open_files == 0
    {
        return Err(UnixLaunchFailure::InvalidConfiguration {
            message: "hard process limits other than file_bytes must be non-zero".into(),
        });
    }
    if options.expected_uid != launch.execution_account().uid
        || options.expected_gid != launch.execution_account().gid
    {
        return Err(UnixLaunchFailure::InvalidConfiguration {
            message: "runner execution identity differs from the qualified helper account".into(),
        });
    }
    if options.instance_id.is_empty()
        || options.instance_id.len() > 128
        || !options
            .instance_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(UnixLaunchFailure::InvalidConfiguration {
            message: "instance ID must be 1..=128 ASCII identifier characters".into(),
        });
    }
    Ok(())
}

fn create_private_directory(
    options: &UnixRunnerOptions,
) -> Result<(ValidatedRuntimeRoot, TempDir, PathBuf), UnixLaunchFailure> {
    let runtime_root = open_runtime_root(&options.runtime_root).map_err(|error| {
        UnixLaunchFailure::RuntimeDirectory {
            message: error.to_string(),
        }
    })?;
    let prefix: String = options.instance_id.chars().take(24).collect();
    let directory = tempfile::Builder::new()
        .prefix(&format!("{prefix}-"))
        .tempdir_in(runtime_root.descriptor_path())
        .map_err(|error| UnixLaunchFailure::RuntimeDirectory {
            message: error.to_string(),
        })?;
    fs::set_permissions(
        directory.path(),
        fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
    )
    .map_err(|error| UnixLaunchFailure::RuntimeDirectory {
        message: error.to_string(),
    })?;
    let name = directory
        .path()
        .file_name()
        .ok_or_else(|| UnixLaunchFailure::RuntimeDirectory {
            message: "temporary runtime directory has no final component".into(),
        })?;
    let visible_path = runtime_root.canonical_path().join(name);
    validate_private_directory_alias(directory.path(), &visible_path)?;
    runtime_root
        .revalidate()
        .map_err(|error| UnixLaunchFailure::RuntimeDirectory {
            message: error.to_string(),
        })?;
    Ok((runtime_root, directory, visible_path))
}

fn validate_private_directory_alias(
    descriptor_path: &Path,
    visible_path: &Path,
) -> Result<(), UnixLaunchFailure> {
    let descriptor_metadata = fs::symlink_metadata(descriptor_path).map_err(|error| {
        UnixLaunchFailure::RuntimeDirectory {
            message: error.to_string(),
        }
    })?;
    let visible_metadata = fs::symlink_metadata(visible_path).map_err(|error| {
        UnixLaunchFailure::RuntimeDirectory {
            message: error.to_string(),
        }
    })?;
    let mode = descriptor_metadata.permissions().mode() & 0o7777;
    if !descriptor_metadata.is_dir()
        || !visible_metadata.is_dir()
        || descriptor_metadata.dev() != visible_metadata.dev()
        || descriptor_metadata.ino() != visible_metadata.ino()
        || descriptor_metadata.uid() != geteuid().as_raw()
        || descriptor_metadata.gid() != getegid().as_raw()
        || mode != PRIVATE_DIRECTORY_MODE
    {
        return Err(UnixLaunchFailure::RuntimeDirectory {
            message: format!(
                "private directory must be one daemon-owned inode with mode 0700; observed uid={}, gid={}, mode={mode:#06o}",
                descriptor_metadata.uid(),
                descriptor_metadata.gid()
            ),
        });
    }
    Ok(())
}

fn spawn_helper(
    launch: &VerifiedLaunch,
    options: &UnixRunnerOptions,
    socket_path: &Path,
) -> io::Result<Child> {
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
            .envs(sanitized_additional_env(&config.env))
            .env(NQ_HELPER_SOCKET_ENV, socket_path)
            .env(NQ_HELPER_INSTANCE_ENV, &options.instance_id)
            .env(
                NQ_HELPER_SOCKET_DIR_OWNER_ENV,
                geteuid().as_raw().to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        isolate_command_with_limits(
            command,
            launch.execution_account(),
            options.isolation_limits,
        );
    })
}

fn sanitized_additional_env(
    env: &BTreeMap<String, String>,
) -> impl Iterator<Item = (&String, &String)> {
    env.iter().filter(|(key, _)| {
        key.as_str() != NQ_HELPER_SOCKET_ENV
            && key.as_str() != NQ_HELPER_INSTANCE_ENV
            && key.as_str() != NQ_HELPER_SOCKET_DIR_OWNER_ENV
    })
}

fn connect_bounded(
    child: &mut Child,
    socket_path: &Path,
    child_process_id: u32,
    options: &UnixRunnerOptions,
    stderr_overflow: &AtomicBool,
) -> Result<UnixStream, UnixLaunchFailure> {
    let started = Instant::now();
    let mut pending_validation_failure = None;
    let mut pending_connection = None;
    let mut socket_in_daemon_custody = false;
    loop {
        if stderr_overflow.load(Ordering::Acquire) {
            return Err(UnixLaunchFailure::StderrTooLarge);
        }
        match child_has_exited(child.id()) {
            Ok(true) => return Err(UnixLaunchFailure::HelperExited { code: None }),
            Ok(false) => {}
            Err(error) => {
                return Err(UnixLaunchFailure::IoFailed {
                    message: format!("could not inspect helper process: {error}"),
                });
            }
        }

        let (socket_owner, socket_group) = if socket_in_daemon_custody {
            (geteuid().as_raw(), getegid().as_raw())
        } else {
            (options.expected_uid, options.expected_gid)
        };
        match inspect_socket(socket_path, socket_owner, socket_group) {
            Ok(false) => {}
            Ok(true) => {
                if !socket_in_daemon_custody {
                    take_unix_socket_custody(
                        socket_path,
                        options.expected_uid,
                        options.expected_gid,
                    )
                    .map_err(|error| UnixLaunchFailure::IoFailed {
                        message: format!("could not take helper socket custody: {error}"),
                    })?;
                    socket_in_daemon_custody = true;
                }
                let attempt = if let Some(stream) = pending_connection.take() {
                    finish_nonblocking_connect(stream)
                } else {
                    begin_nonblocking_connect(socket_path)
                };
                match attempt {
                    Ok(ConnectAttempt::Connected(stream)) => {
                        verify_peer(
                            &stream,
                            child_process_id,
                            options.expected_uid,
                            options.expected_gid,
                        )?;
                        return Ok(stream);
                    }
                    Ok(ConnectAttempt::Pending(stream)) => pending_connection = Some(stream),
                    Ok(ConnectAttempt::Retry) => {}
                    Err(failure) => return Err(failure),
                }
            }
            Err(
                failure @ (UnixLaunchFailure::SocketPermissions { .. }
                | UnixLaunchFailure::SocketOwner { .. }
                | UnixLaunchFailure::SocketGroup { .. }),
            ) if !socket_in_daemon_custody => {
                // `bind` precedes a helper's chmod/chown. Permit that narrow
                // setup window, but report the exact last validation failure
                // if the deadline expires.
                pending_validation_failure = Some(failure);
            }
            Err(failure) => return Err(failure),
        }

        let elapsed = started.elapsed();
        if elapsed >= options.startup_timeout {
            return Err(pending_validation_failure.unwrap_or(UnixLaunchFailure::Timeout));
        }
        thread::sleep(POLL_INTERVAL.min(options.startup_timeout.saturating_sub(elapsed)));
    }
}

enum ConnectAttempt {
    Connected(UnixStream),
    Pending(UnixStream),
    Retry,
}

fn begin_nonblocking_connect(path: &Path) -> Result<ConnectAttempt, UnixLaunchFailure> {
    let address = UnixAddr::new(path).map_err(|error| UnixLaunchFailure::IoFailed {
        message: format!("invalid helper socket address: {error}"),
    })?;
    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|error| UnixLaunchFailure::IoFailed {
        message: format!("could not allocate helper socket: {error}"),
    })?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => Ok(ConnectAttempt::Connected(UnixStream::from(descriptor))),
        Err(Errno::EINPROGRESS | Errno::EAGAIN) => {
            Ok(ConnectAttempt::Pending(UnixStream::from(descriptor)))
        }
        Err(Errno::ENOENT | Errno::ECONNREFUSED | Errno::EINTR) => Ok(ConnectAttempt::Retry),
        Err(error) => Err(UnixLaunchFailure::IoFailed {
            message: format!("could not connect to helper socket: {error}"),
        }),
    }
}

fn finish_nonblocking_connect(stream: UnixStream) -> Result<ConnectAttempt, UnixLaunchFailure> {
    if let Some(error) = stream
        .take_error()
        .map_err(|error| UnixLaunchFailure::IoFailed {
            message: format!("could not inspect pending helper connection: {error}"),
        })?
    {
        return if matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
        ) {
            Ok(ConnectAttempt::Retry)
        } else {
            Err(UnixLaunchFailure::IoFailed {
                message: format!("pending helper connection failed: {error}"),
            })
        };
    }
    match stream.peer_addr() {
        Ok(_) => Ok(ConnectAttempt::Connected(stream)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotConnected
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(ConnectAttempt::Pending(stream))
        }
        Err(error) => Err(UnixLaunchFailure::IoFailed {
            message: format!("could not inspect pending helper peer: {error}"),
        }),
    }
}

#[allow(clippy::similar_names)]
fn inspect_socket(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<bool, UnixLaunchFailure> {
    // `symlink_metadata` never follows a symlink, so a symlinked socket path is
    // rejected as "not a socket" rather than inspected through its target.
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(UnixLaunchFailure::IoFailed {
                message: format!("could not inspect helper socket: {error}"),
            });
        }
    };
    // Type, permissions, and ownership are separate predicates; all must hold.
    if !metadata.file_type().is_socket() {
        return Err(UnixLaunchFailure::NotSocket);
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != PRIVATE_SOCKET_MODE {
        return Err(UnixLaunchFailure::SocketPermissions { actual: mode });
    }
    let actual_uid = metadata.uid();
    if actual_uid != expected_uid {
        return Err(UnixLaunchFailure::SocketOwner {
            expected: expected_uid,
            actual: actual_uid,
        });
    }
    let actual_gid = metadata.gid();
    if actual_gid != expected_gid {
        return Err(UnixLaunchFailure::SocketGroup {
            expected: expected_gid,
            actual: actual_gid,
        });
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn verify_peer(
    stream: &UnixStream,
    child_process_id: u32,
    execution_user_id: u32,
    execution_group_id: u32,
) -> Result<(), UnixLaunchFailure> {
    let credentials = getsockopt(stream, PeerCredentials).map_err(|error| {
        UnixLaunchFailure::PeerCredentialsUnavailable {
            message: error.to_string(),
        }
    })?;
    let peer_process_id = credentials.pid();
    let peer_user_id = credentials.uid();
    let peer_group_id = credentials.gid();
    if i64::from(peer_process_id) != i64::from(child_process_id)
        || peer_user_id != execution_user_id
        || peer_group_id != execution_group_id
    {
        return Err(UnixLaunchFailure::PeerCredentialMismatch {
            expected_pid: child_process_id,
            expected_uid: execution_user_id,
            expected_gid: execution_group_id,
            actual_pid: peer_process_id,
            actual_uid: peer_user_id,
            actual_gid: peer_group_id,
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_peer(
    _stream: &UnixStream,
    _child_process_id: u32,
    _execution_user_id: u32,
    _execution_group_id: u32,
) -> Result<(), UnixLaunchFailure> {
    Err(UnixLaunchFailure::UnsupportedPlatform)
}

fn prepare_request(
    request_json: &[u8],
    deadline: Duration,
    max_response_bytes: usize,
) -> Result<Vec<u8>, UnixAcquisitionOutcome> {
    if request_json.is_empty() || request_json.contains(&b'\n') || request_json.contains(&b'\r') {
        return Err(UnixAcquisitionOutcome::InvalidRequestFraming {
            message: "request must be one non-empty document without CR or LF".into(),
        });
    }
    let Some(request_len) = request_json.len().checked_add(1) else {
        return Err(UnixAcquisitionOutcome::InvalidRequestFraming {
            message: "request frame length overflowed".into(),
        });
    };
    if request_len > nq_protocol::MAX_REQUEST_FRAME_BYTES {
        return Err(UnixAcquisitionOutcome::InvalidRequestFraming {
            message: format!(
                "request is {request_len} bytes; limit is {}",
                nq_protocol::MAX_REQUEST_FRAME_BYTES
            ),
        });
    }
    if max_response_bytes == 0 {
        return Err(UnixAcquisitionOutcome::OutputTooLarge);
    }
    if deadline.is_zero() {
        return Err(UnixAcquisitionOutcome::Timeout {
            phase: UnixIoPhase::WriteRequest,
        });
    }

    let mut request = Vec::with_capacity(request_len);
    request.extend_from_slice(request_json);
    request.push(b'\n');
    Ok(request)
}

fn write_bounded(
    state: &mut ProcessState,
    request: &[u8],
    started: Instant,
    deadline: Duration,
) -> Result<(), UnixAcquisitionOutcome> {
    let mut written = 0;
    while written < request.len() {
        if state.stderr_overflow.load(Ordering::Acquire) {
            return Err(UnixAcquisitionOutcome::StderrTooLarge);
        }
        if started.elapsed() >= deadline {
            return Err(UnixAcquisitionOutcome::Timeout {
                phase: UnixIoPhase::WriteRequest,
            });
        }
        match state.stream.write(&request[written..]) {
            Ok(0) => {
                return Err(UnixAcquisitionOutcome::Disconnect {
                    message: "socket closed while writing the request".into(),
                });
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Some(outcome) = observe_wait_state(state) {
                    return Err(outcome);
                }
                sleep_until_poll(started, deadline);
            }
            Err(error) if is_disconnect(&error) => {
                return Err(UnixAcquisitionOutcome::Disconnect {
                    message: error.to_string(),
                });
            }
            Err(error) => {
                return Err(UnixAcquisitionOutcome::RequestWriteFailed {
                    message: error.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn read_bounded(
    state: &mut ProcessState,
    started: Instant,
    deadline: Duration,
    max_response_bytes: usize,
) -> Result<Vec<u8>, (Vec<u8>, UnixAcquisitionOutcome)> {
    let mut response = Vec::with_capacity(max_response_bytes.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    loop {
        if state.stderr_overflow.load(Ordering::Acquire) {
            return Err((response, UnixAcquisitionOutcome::StderrTooLarge));
        }
        if started.elapsed() >= deadline {
            return Err((
                response,
                UnixAcquisitionOutcome::Timeout {
                    phase: UnixIoPhase::ReadResponse,
                },
            ));
        }
        let remaining_with_sentinel = max_response_bytes
            .saturating_sub(response.len())
            .saturating_add(1);
        let read_bound = buffer.len().min(remaining_with_sentinel);
        match state.stream.read(&mut buffer[..read_bound]) {
            Ok(0) if response.is_empty() => {
                return Err((response, UnixAcquisitionOutcome::Eof));
            }
            Ok(0) => {
                return Err((
                    response,
                    UnixAcquisitionOutcome::Disconnect {
                        message: "peer closed partway through the response frame".into(),
                    },
                ));
            }
            Ok(count) => {
                response.extend_from_slice(&buffer[..count]);
                if response.len() > max_response_bytes {
                    return Err((response, UnixAcquisitionOutcome::OutputTooLarge));
                }
                if let Some(newline) = response.iter().position(|byte| *byte == b'\n') {
                    if newline + 1 != response.len() {
                        return Err((
                            response,
                            UnixAcquisitionOutcome::MalformedFraming {
                                message: "helper emitted bytes after the response LF".into(),
                            },
                        ));
                    }
                    if response[..newline].contains(&b'\r') {
                        return Err((
                            response,
                            UnixAcquisitionOutcome::MalformedFraming {
                                message: "response frame must not contain CR".into(),
                            },
                        ));
                    }
                    return validate_response_json(response);
                }
                if response.len() == max_response_bytes {
                    return Err((response, UnixAcquisitionOutcome::OutputTooLarge));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Some(outcome) = observe_wait_state(state) {
                    return Err((response, outcome));
                }
                sleep_until_poll(started, deadline);
            }
            Err(error) if is_disconnect(&error) => {
                return Err((
                    response,
                    UnixAcquisitionOutcome::Disconnect {
                        message: error.to_string(),
                    },
                ));
            }
            Err(error) => {
                return Err((
                    response,
                    UnixAcquisitionOutcome::IoFailed {
                        message: error.to_string(),
                    },
                ));
            }
        }
    }
}

fn validate_response_json(response: Vec<u8>) -> Result<Vec<u8>, (Vec<u8>, UnixAcquisitionOutcome)> {
    let body = &response[..response.len() - 1];
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(_)) => Ok(response),
        Ok(_) => Err((
            response,
            UnixAcquisitionOutcome::MalformedJson {
                message: "top-level response must be an object".into(),
            },
        )),
        Err(error) => Err((
            response,
            UnixAcquisitionOutcome::MalformedJson {
                message: error.to_string(),
            },
        )),
    }
}

fn observe_wait_state(state: &mut ProcessState) -> Option<UnixAcquisitionOutcome> {
    if state.stderr_overflow.load(Ordering::Acquire) {
        return Some(UnixAcquisitionOutcome::StderrTooLarge);
    }
    match child_has_exited(state.child.id()) {
        Ok(true) => Some(UnixAcquisitionOutcome::HelperExited { code: None }),
        Ok(false) => None,
        Err(error) => Some(UnixAcquisitionOutcome::IoFailed {
            message: format!("could not inspect helper process: {error}"),
        }),
    }
}

fn sleep_until_poll(started: Instant, deadline: Duration) {
    let remaining = deadline.saturating_sub(started.elapsed());
    if !remaining.is_zero() {
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn is_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn spawn_stderr_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    retained: Arc<Mutex<Vec<u8>>>,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            let mut output = lock_unpoisoned(&retained);
            let remaining = limit.saturating_sub(output.len());
            let copy = remaining.min(count);
            output.extend_from_slice(&buffer[..copy]);
            if copy < count {
                overflow.store(true, Ordering::Release);
            }
            // Continue draining after overflow so pipe capacity can never turn
            // a log-limit outcome into a request timeout.
        }
    })
}

fn take_stderr(stderr: &Mutex<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *lock_unpoisoned(stderr))
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn stop_process(mut state: ProcessState) -> (Vec<u8>, Option<ExitStatus>) {
    let _ = state.stream.shutdown(std::net::Shutdown::Both);
    let status = terminate_and_reap(&mut state.child);
    if let Some(stderr_thread) = state.stderr_thread.take() {
        let _ = stderr_thread.join();
    }
    (take_stderr(&state.stderr), status)
}

fn terminate_and_reap(child: &mut Child) -> Option<ExitStatus> {
    let group = i32::try_from(child.id()).ok().map(Pid::from_raw);
    if let Some(group) = group {
        signal_group_or_abort(group, Signal::SIGTERM);
    } else {
        eprintln!("nq: helper PID cannot be represented as a process group");
        std::process::abort();
    }

    let started = Instant::now();
    while started.elapsed() < TERMINATION_GRACE {
        match child_has_exited(child.id()) {
            Ok(false) => thread::sleep(POLL_INTERVAL),
            Ok(true) | Err(_) => break,
        }
    }

    // Kill the group even when its leader already exited: descendants may
    // still hold pipes or the socket and must not escape supervision.
    if let Some(group) = group {
        signal_group_or_abort(group, Signal::SIGKILL);
    }
    child.wait().ok()
}

fn signal_group_or_abort(group: Pid, signal_value: Signal) {
    match signal::killpg(group, signal_value) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(error) => {
            eprintln!(
                "nq: cannot contain helper process group {} with {signal_value:?}: {error}",
                group.as_raw()
            );
            std::process::abort();
        }
    }
}

fn remove_owned_socket_checked(path: &Path) -> Result<(), UnixLaunchFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(|error| UnixLaunchFailure::IoFailed {
                message: format!("could not remove old helper socket: {error}"),
            })
        }
        Ok(_) => Err(UnixLaunchFailure::NotSocket),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(UnixLaunchFailure::IoFailed {
            message: format!("could not inspect old helper socket: {error}"),
        }),
    }
}

fn remove_owned_socket(path: &Path) {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
        let _ = fs::remove_file(path);
    }
}

fn exchange_capture(
    started_at: DateTime<Utc>,
    started: Instant,
    helper_pid: Option<u32>,
    response: Vec<u8>,
    stderr: Vec<u8>,
    outcome: UnixAcquisitionOutcome,
) -> UnixExchangeCapture {
    UnixExchangeCapture {
        started_at,
        finished_at: Utc::now(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        helper_pid,
        response,
        stderr,
        outcome,
    }
}

fn bare_launch_error(failure: UnixLaunchFailure) -> UnixLaunchError {
    UnixLaunchError {
        failure,
        stderr: Vec::new(),
    }
}

// Linux sockaddr_un::sun_path is 108 bytes including the terminating NUL.
const fn unix_path_limit() -> usize {
    108
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_socket_enforces_type_mode_owner_and_group_separately() {
        use std::os::unix::net::UnixListener;
        let directory = tempfile::tempdir().expect("temp dir");
        let socket = directory.path().join("helper.sock");
        let _listener = UnixListener::bind(&socket).expect("bind unix socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(PRIVATE_SOCKET_MODE))
            .expect("socket mode");
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();

        // Correct type, mode, owner, and group pass.
        assert!(matches!(inspect_socket(&socket, uid, gid), Ok(true)));

        // A wrong group is rejected even with the right owner: GID is its own
        // predicate and does not fold into UID.
        assert!(matches!(
            inspect_socket(&socket, uid, gid.wrapping_add(1)),
            Err(UnixLaunchFailure::SocketGroup { .. })
        ));
        // A wrong owner is rejected even with the right group.
        assert!(matches!(
            inspect_socket(&socket, uid.wrapping_add(1), gid),
            Err(UnixLaunchFailure::SocketOwner { .. })
        ));

        // A wrong mode is rejected regardless of ownership.
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).expect("loosen mode");
        assert!(matches!(
            inspect_socket(&socket, uid, gid),
            Err(UnixLaunchFailure::SocketPermissions { .. })
        ));

        // A regular file at the socket path is not a socket.
        let regular = directory.path().join("regular");
        fs::write(&regular, b"x").expect("write regular file");
        fs::set_permissions(&regular, fs::Permissions::from_mode(PRIVATE_SOCKET_MODE))
            .expect("regular mode");
        assert!(matches!(
            inspect_socket(&regular, uid, gid),
            Err(UnixLaunchFailure::NotSocket)
        ));
    }

    const PYTHON_HELPER: &str = r#"
import json
import os
import socket
import sys
import time

path = os.environ["NQ_HELPER_SOCKET"]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
os.chmod(path, 0o600)
server.listen(1)
connection, _ = server.accept()
reader = connection.makefile("rb")
while True:
    line = reader.readline()
    if not line:
        break
    request = json.loads(line)
    mode = request.get("mode", "echo")
    if mode == "eof":
        connection.close()
        break
    if mode == "partial":
        connection.sendall(b'{"ok":')
        connection.close()
        break
    if mode == "extra":
        connection.sendall(b'{}\n{}\n')
        continue
    if mode == "timeout":
        time.sleep(10)
        continue
    if mode == "oversize":
        connection.sendall(b'{"value":"' + (b'x' * 4096) + b'"}\n')
        continue
    if mode == "stderr":
        os.write(2, b'x' * 4096)
        time.sleep(0.05)
    response = {"instance": os.environ["NQ_HELPER_INSTANCE_ID"], "sequence": request["sequence"]}
    connection.sendall(json.dumps(response, separators=(",", ":")).encode() + b'\n')
"#;

    struct PythonFixture {
        _source_directory: tempfile::TempDir,
        command: CommandConfig,
        script_argument: String,
    }

    fn python_fixture(script: &str) -> PythonFixture {
        python_fixture_for_identity(
            script,
            nix::unistd::geteuid().as_raw().to_string(),
            true,
            None,
        )
    }

    fn python_fixture_for_identity(
        script: &str,
        execution_account: String,
        allow_same_identity_in_debug: bool,
        working_directory: Option<PathBuf>,
    ) -> PythonFixture {
        let source_directory = tempfile::tempdir().expect("Python fixture directory");
        let script_path = source_directory.path().join("helper.py");
        fs::write(&script_path, script).expect("write Python fixture");
        let script_argument = script_path.to_string_lossy().into_owned();
        let command = CommandConfig {
            executable: PathBuf::from("/usr/bin/python3"),
            args: vec![script_argument.clone()],
            env: BTreeMap::new(),
            execution_account,
            allow_same_identity_in_debug,
            working_directory: working_directory
                .unwrap_or_else(|| source_directory.path().to_path_buf()),
        };
        PythonFixture {
            _source_directory: source_directory,
            command,
            script_argument,
        }
    }

    fn assert_fixed_argument_retained(launch: &VerifiedLaunch, argument: &str) {
        assert!(
            launch.identity().execution_chain.iter().any(|artifact| {
                artifact.role == crate::identity::ArtifactRole::FixedArgument
                    && artifact.fixed_argument.as_deref() == Some(argument)
            }),
            "Python fixture must be retained as an exact fixed-argument artifact"
        );
    }

    fn retained_python_launch(fixture: &PythonFixture) -> VerifiedLaunch {
        let launch = VerifiedLaunch::open(&fixture.command).expect("qualify Python fixture");
        assert_fixed_argument_retained(&launch, &fixture.script_argument);
        launch
    }

    fn command_that_must_not_spawn() -> CommandConfig {
        CommandConfig {
            executable: PathBuf::from("/bin/true"),
            args: Vec::new(),
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: PathBuf::from("/tmp"),
        }
    }

    fn runtime_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("runtime root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o711))
            .expect("secure runtime root mode");
        root
    }

    fn launch_with(
        script: &str,
        max_stderr_bytes: usize,
    ) -> (tempfile::TempDir, PythonFixture, UnixRunner) {
        let root = runtime_root();
        let options = UnixRunnerOptions::inherited_identity(
            root.path(),
            "test.instance",
            Duration::from_secs(2),
            max_stderr_bytes,
        );
        let fixture = python_fixture(script);
        let launch = retained_python_launch(&fixture);
        let runner = UnixRunner::launch_verified(launch, options).expect("launch helper");
        (root, fixture, runner)
    }

    fn unix_socket_tests_available() -> bool {
        let directory = tempfile::tempdir().expect("AF_UNIX probe directory");
        match std::os::unix::net::UnixListener::bind(directory.path().join("probe.sock")) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: execution sandbox denies AF_UNIX sockets");
                false
            }
            Err(error) => panic!("could not probe AF_UNIX test support: {error}"),
        }
    }

    #[test]
    fn unsafe_or_aliased_runtime_root_is_rejected_before_spawn() {
        let unsafe_root = tempfile::tempdir().expect("unsafe runtime root");
        fs::set_permissions(unsafe_root.path(), fs::Permissions::from_mode(0o777))
            .expect("relax runtime root");
        let options = UnixRunnerOptions::inherited_identity(
            unsafe_root.path(),
            "unsafe.root",
            Duration::from_secs(1),
            1024,
        );
        let error = UnixRunner::launch(&command_that_must_not_spawn(), options)
            .expect_err("world-writable runtime root must fail closed");
        assert!(
            matches!(error.failure, UnixLaunchFailure::RuntimeDirectory { .. }),
            "unexpected failure: {error:?}"
        );

        let unsafe_parent = tempfile::tempdir().expect("unsafe runtime ancestor");
        fs::set_permissions(unsafe_parent.path(), fs::Permissions::from_mode(0o777))
            .expect("relax runtime ancestor");
        let nested_root = unsafe_parent.path().join("helpers");
        fs::create_dir(&nested_root).expect("nested runtime root");
        fs::set_permissions(&nested_root, fs::Permissions::from_mode(0o711))
            .expect("secure nested runtime root itself");
        let options = UnixRunnerOptions::inherited_identity(
            &nested_root,
            "unsafe.ancestor",
            Duration::from_secs(1),
            1024,
        );
        let error = UnixRunner::launch(&command_that_must_not_spawn(), options)
            .expect_err("replaceable runtime ancestor must fail closed");
        assert!(
            matches!(error.failure, UnixLaunchFailure::RuntimeDirectory { .. }),
            "unexpected failure: {error:?}"
        );

        let real_root = runtime_root();
        let alias_parent = tempfile::tempdir().expect("runtime alias parent");
        let alias = alias_parent.path().join("helpers");
        std::os::unix::fs::symlink(real_root.path(), &alias).expect("runtime root symlink");
        let options = UnixRunnerOptions::inherited_identity(
            &alias,
            "aliased.root",
            Duration::from_secs(1),
            1024,
        );
        let error = UnixRunner::launch(&command_that_must_not_spawn(), options)
            .expect_err("symlinked runtime root must fail closed");
        assert!(
            matches!(error.failure, UnixLaunchFailure::RuntimeDirectory { .. }),
            "unexpected failure: {error:?}"
        );
    }

    #[test]
    fn persistent_exchange_uses_private_authenticated_socket() {
        if !unix_socket_tests_available() {
            return;
        }
        let (_root, _fixture, mut runner) = launch_with(PYTHON_HELPER, 1024);
        let pid = runner.child_pid().expect("child PID");
        assert_eq!(
            fs::metadata(runner.socket_directory())
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o730
        );
        assert_eq!(
            fs::metadata(runner.socket_path())
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        for sequence in 1..=2 {
            let request = format!(r#"{{"sequence":{sequence}}}"#);
            let capture = runner.exchange(request.as_bytes(), Duration::from_secs(1), 1024);
            assert_eq!(capture.outcome, UnixAcquisitionOutcome::Response);
            assert_eq!(capture.helper_pid, Some(pid));
            let value: serde_json::Value =
                serde_json::from_slice(capture.response_frame().expect("response frame"))
                    .expect("response JSON");
            assert_eq!(value["instance"], "test.instance");
            assert_eq!(value["sequence"], sequence);
        }
        assert_eq!(runner.child_pid(), Some(pid));
    }

    #[test]
    fn persistent_restart_reuses_qualified_script_descriptor_after_path_swap() {
        if !unix_socket_tests_available() {
            return;
        }
        let root = runtime_root();
        let script = root.path().join("persistent_helper.py");
        fs::write(&script, PYTHON_HELPER).expect("write qualified persistent helper");
        let command = CommandConfig {
            executable: PathBuf::from("/usr/bin/python3"),
            args: vec![script.display().to_string()],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: root.path().to_path_buf(),
        };
        let options = UnixRunnerOptions::inherited_identity(
            root.path(),
            "restart.instance",
            Duration::from_secs(2),
            1024,
        );
        let launch = VerifiedLaunch::open(&command).expect("qualify persistent helper");
        assert_fixed_argument_retained(&launch, &script.to_string_lossy());
        let mut runner =
            UnixRunner::launch_verified(launch, options).expect("launch qualified helper");
        let first = runner.exchange(br#"{"sequence":1}"#, Duration::from_secs(1), 1024);
        assert_eq!(first.outcome, UnixAcquisitionOutcome::Response);
        runner.shutdown();

        fs::rename(&script, script.with_extension("qualified")).unwrap();
        fs::write(&script, "raise SystemExit(91)\n").unwrap();
        runner
            .restart()
            .expect("restart uses retained qualified script bytes");
        let second = runner.exchange(br#"{"sequence":2}"#, Duration::from_secs(1), 1024);
        assert_eq!(second.outcome, UnixAcquisitionOutcome::Response);
        let response: serde_json::Value =
            serde_json::from_slice(second.response_frame().expect("persistent response frame"))
                .unwrap();
        assert_eq!(response["sequence"], 2);
    }

    #[test]
    fn eof_partial_disconnect_and_extra_frame_are_distinct() {
        if !unix_socket_tests_available() {
            return;
        }
        let (_root, _fixture, mut runner) = launch_with(PYTHON_HELPER, 1024);
        let eof = runner.exchange(
            br#"{"mode":"eof","sequence":1}"#,
            Duration::from_secs(1),
            1024,
        );
        assert_eq!(eof.outcome, UnixAcquisitionOutcome::Eof);
        assert!(!runner.has_connection());

        runner.restart().expect("restart after EOF");
        let partial = runner.exchange(
            br#"{"mode":"partial","sequence":2}"#,
            Duration::from_secs(1),
            1024,
        );
        assert!(matches!(
            partial.outcome,
            UnixAcquisitionOutcome::Disconnect { .. }
        ));

        runner.restart().expect("restart after disconnect");
        let extra = runner.exchange(
            br#"{"mode":"extra","sequence":3}"#,
            Duration::from_secs(1),
            1024,
        );
        assert!(matches!(
            extra.outcome,
            UnixAcquisitionOutcome::MalformedFraming { .. }
        ));
    }

    #[test]
    fn timeout_and_output_limit_invalidate_then_restart_cleanly() {
        if !unix_socket_tests_available() {
            return;
        }
        let (_root, _fixture, mut runner) = launch_with(PYTHON_HELPER, 1024);
        let timeout = runner.exchange(
            br#"{"mode":"timeout","sequence":1}"#,
            Duration::from_millis(25),
            1024,
        );
        assert_eq!(
            timeout.outcome,
            UnixAcquisitionOutcome::Timeout {
                phase: UnixIoPhase::ReadResponse
            }
        );
        assert!(timeout.duration_ms < 1_000);

        runner.restart().expect("restart after timeout");
        let oversized = runner.exchange(
            br#"{"mode":"oversize","sequence":2}"#,
            Duration::from_secs(1),
            64,
        );
        assert_eq!(oversized.outcome, UnixAcquisitionOutcome::OutputTooLarge);

        runner.restart().expect("restart after oversized response");
        let healthy = runner.exchange(br#"{"sequence":3}"#, Duration::from_secs(1), 1024);
        assert_eq!(healthy.outcome, UnixAcquisitionOutcome::Response);
    }

    #[test]
    fn stderr_is_drained_and_bounded_independently() {
        if !unix_socket_tests_available() {
            return;
        }
        let (_root, _fixture, mut runner) = launch_with(PYTHON_HELPER, 32);
        let capture = runner.exchange(
            br#"{"mode":"stderr","sequence":1}"#,
            Duration::from_secs(1),
            1024,
        );
        assert_eq!(capture.outcome, UnixAcquisitionOutcome::StderrTooLarge);
        assert_eq!(capture.stderr.len(), 32);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_uid_mismatch_is_rejected() {
        if !unix_socket_tests_available() {
            return;
        }
        let root = runtime_root();
        let mut options = UnixRunnerOptions::inherited_identity(
            root.path(),
            "wrong.uid",
            Duration::from_secs(1),
            1024,
        );
        options.expected_uid = if options.expected_uid == u32::MAX {
            0
        } else {
            options.expected_uid + 1
        };
        let fixture = python_fixture(PYTHON_HELPER);
        let launch = retained_python_launch(&fixture);
        let error =
            UnixRunner::launch_verified(launch, options).expect_err("UID mismatch must fail");
        assert!(matches!(
            error.failure,
            UnixLaunchFailure::InvalidConfiguration { .. }
        ));
    }

    #[test]
    fn socket_mode_is_enforced_before_connect() {
        if !unix_socket_tests_available() {
            return;
        }
        let script = PYTHON_HELPER.replace("os.chmod(path, 0o600)", "os.chmod(path, 0o660)");
        let root = runtime_root();
        let options = UnixRunnerOptions::inherited_identity(
            root.path(),
            "wrong.mode",
            Duration::from_secs(2),
            1024,
        );
        let fixture = python_fixture(&script);
        let launch = retained_python_launch(&fixture);
        let error = UnixRunner::launch_verified(launch, options)
            .expect_err("socket mode mismatch must fail");
        assert_eq!(
            error.failure,
            UnixLaunchFailure::SocketPermissions { actual: 0o660 }
        );
    }

    #[test]
    fn distinct_identity_socket_custody_timeout_and_restart_work_when_permitted() {
        if !unix_socket_tests_available() {
            return;
        }
        let account = ["nobody", "65534"]
            .into_iter()
            .find_map(|candidate| nq_helper_sandbox::resolve_account(candidate, false).ok());
        let Some(account) = account else {
            eprintln!("skipping distinct-UID Unix launch: no isolated local account");
            return;
        };
        let root = runtime_root();
        let fixture = python_fixture_for_identity(
            PYTHON_HELPER,
            account.configured.clone(),
            false,
            Some(PathBuf::from("/")),
        );
        let launch = match VerifiedLaunch::open(&fixture.command) {
            Ok(launch) => {
                assert_fixed_argument_retained(&launch, &fixture.script_argument);
                launch
            }
            Err(error)
                if error.to_string().contains("Operation not permitted")
                    || error.to_string().contains("Permission denied") =>
            {
                eprintln!("skipping distinct-UID Unix launch: parent lacks required capabilities");
                return;
            }
            Err(error) => panic!("distinct-UID Unix qualification failed: {error}"),
        };
        let options = UnixRunnerOptions::for_account(
            root.path(),
            "distinct.instance",
            Duration::from_secs(2),
            1024,
            &account,
        );
        let mut runner = match UnixRunner::launch_verified(launch, options) {
            Ok(runner) => runner,
            Err(error)
                if error.to_string().contains("Operation not permitted")
                    || error.to_string().contains("Permission denied") =>
            {
                eprintln!("skipping distinct-UID Unix launch: parent lacks required capabilities");
                return;
            }
            Err(error) => panic!("distinct-UID Unix launch failed: {error}"),
        };
        let directory = fs::symlink_metadata(runner.socket_directory()).unwrap();
        assert_eq!(directory.uid(), geteuid().as_raw());
        assert_eq!(directory.gid(), account.gid);
        assert_eq!(directory.mode() & 0o777, 0o730);
        let socket = fs::symlink_metadata(runner.socket_path()).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.uid(), geteuid().as_raw());
        assert_eq!(socket.gid(), getegid().as_raw());
        assert_eq!(socket.mode() & 0o777, 0o600);

        let first_pid = runner.child_pid().expect("first distinct helper PID");
        let timeout = runner.exchange(
            br#"{"mode":"timeout","sequence":1}"#,
            Duration::from_millis(25),
            1024,
        );
        assert_eq!(
            timeout.outcome,
            UnixAcquisitionOutcome::Timeout {
                phase: UnixIoPhase::ReadResponse
            }
        );
        assert_eq!(
            signal::kill(Pid::from_raw(i32::try_from(first_pid).unwrap()), None),
            Err(Errno::ESRCH),
            "timed-out distinct helper must be reaped"
        );

        runner.restart().expect("restart distinct helper");
        let second_pid = runner.child_pid().expect("replacement helper PID");
        assert_ne!(first_pid, second_pid);
        let healthy = runner.exchange(br#"{"sequence":2}"#, Duration::from_secs(1), 1024);
        assert_eq!(healthy.outcome, UnixAcquisitionOutcome::Response);
        runner.shutdown();
        assert_eq!(
            signal::kill(Pid::from_raw(i32::try_from(second_pid).unwrap()), None),
            Err(Errno::ESRCH),
            "shut-down distinct helper must be reaped"
        );
    }

    #[test]
    fn response_shape_validation_is_transport_independent() {
        assert!(validate_response_json(b"{\"ok\":true}\n".to_vec()).is_ok());
        let (_, outcome) = validate_response_json(b"[]\n".to_vec()).expect_err("array must fail");
        assert!(matches!(
            outcome,
            UnixAcquisitionOutcome::MalformedJson { .. }
        ));
        let (_, outcome) =
            validate_response_json(b"{nope}\n".to_vec()).expect_err("invalid JSON must fail");
        assert!(matches!(
            outcome,
            UnixAcquisitionOutcome::MalformedJson { .. }
        ));
    }

    #[test]
    fn runner_is_send_between_blocking_tasks() {
        fn assert_send<T: Send>() {}
        assert_send::<UnixRunner>();
    }
}
