//! Race-detecting executable and interpreter-chain identity.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, SealFlag, fcntl};
use nix::sys::memfd::{MemFdCreateFlag, memfd_create};
use nix::sys::stat::{Mode, fchmod};
use nq_helper_sandbox::{ExecutionAccount, resolve_account};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::CommandConfig;
use crate::runtime::{
    RuntimeDirectoryIdentity, RuntimeObjectRole, RuntimeProbe, StartupRuntimeIdentity,
    discover_startup_runtime, qualify_directory_ancestry, require_directory_descriptor_policy,
};

/// Maximum interpreter recursion accepted for script execution chains.
const MAX_CHAIN_DEPTH: usize = 4;

/// Maximum bytes accepted from any one executable, interpreter, wrapper, or
/// existing fixed-argument file before it is hashed or snapshotted.
pub const MAX_LAUNCH_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;

/// Maximum aggregate bytes accepted across one helper's complete execution
/// chain before any launch snapshots are retained.
pub const MAX_LAUNCH_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum number of byte artifacts retained for one helper launch, including
/// the root executable and all interpreters, wrappers, and existing fixed files.
pub const MAX_LAUNCH_ARTIFACTS: usize = 32;

/// Maximum long-lived file descriptors owned by one verified launch: one for
/// each byte artifact plus the descriptor-bound working directory.
pub const MAX_LAUNCH_RETAINED_FDS: usize = MAX_LAUNCH_ARTIFACTS + 1;

/// Maximum aggregate logical bytes held in sealed launch snapshots by one NQ
/// process. Reservation is atomic and released when a [`VerifiedLaunch`] drops.
pub const MAX_RESIDENT_LAUNCH_BYTES: u64 = 512 * 1024 * 1024;

/// Serializes the narrow parent-side `FD_CLOEXEC` handoff around `fork`/`exec`.
/// Every production helper launch uses this boundary.
static DESCRIPTOR_LAUNCH: Mutex<()> = Mutex::new(());

/// Process-wide logical-byte custody for retained launch snapshots.
static RESIDENT_LAUNCH_BYTES: AtomicU64 = AtomicU64::new(0);

/// Identity of every executable byte artifact in an execution chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionIdentity {
    /// Exact helper account resolved from the configured name or numeric UID.
    /// Standalone artifact inspection has no launch account; admitted commands
    /// always carry `Some`.
    pub execution_account: Option<ExecutionAccount>,
    /// Configured path before canonical resolution.
    pub configured_path: PathBuf,
    /// Canonical executable path opened for hashing.
    pub resolved_path: PathBuf,
    /// Digest of the opened executable bytes.
    pub sha256: String,
    /// Byte length.
    pub size: u64,
    /// Filesystem device.
    pub device: u64,
    /// Filesystem inode.
    pub inode: u64,
    /// Unix mode bits.
    pub mode: u32,
    /// Nanosecond mtime, used only as an additional drift signal.
    pub modified_ns: String,
    /// Fixed argument vector bound to this execution identity.
    pub fixed_argv: Vec<String>,
    /// Working directory used to resolve path-like fixed arguments.
    pub working_directory: Option<PathBuf>,
    /// Exact opened directory identity used as the launch cwd.
    pub working_directory_identity: Option<ExecutionDirectory>,
    /// Script/interpreter chain, excluding this root artifact.
    pub execution_chain: Vec<ExecutionArtifact>,
    /// Startup ELF loader/shared-object identity discovered against the exact
    /// retained launch snapshots. Standalone byte inspection has no runtime
    /// qualification; admitted commands always carry `Some`.
    pub startup_runtime: Option<StartupRuntimeIdentity>,
}

/// Identity of the directory from which the fixed helper executes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionDirectory {
    /// Canonical directory path at qualification time.
    pub path: PathBuf,
    /// Filesystem device.
    pub device: u64,
    /// Filesystem inode.
    pub inode: u64,
    /// Unix mode bits.
    pub mode: u32,
    /// Owning Unix user ID.
    pub owner: u32,
    /// Owning Unix group ID.
    pub group: u32,
    /// Lexical and canonical identity of every configured path ancestor.
    pub ancestry: Vec<RuntimeDirectoryIdentity>,
}

/// A script interpreter or fixed wrapper artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionArtifact {
    /// Role within the chain.
    pub role: ArtifactRole,
    /// Canonical path.
    pub path: PathBuf,
    /// Digest of opened bytes.
    pub sha256: String,
    /// Byte length.
    pub size: u64,
    /// Filesystem device.
    pub device: u64,
    /// Filesystem inode.
    pub inode: u64,
    /// Fixed argument supplied by a shebang, if any.
    pub fixed_argument: Option<String>,
}

/// Execution-chain artifact role.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    /// Kernel-selected script interpreter.
    Interpreter,
    /// Fixed program selected by a known interpreter wrapper such as
    /// `/usr/bin/env` under NQ's sanitized `PATH`.
    WrapperTarget,
    /// Existing regular file named by a fixed path-like argument.
    FixedArgument,
}

/// Executable resolution or drift failure.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The configured helper execution account is missing or unsafe.
    #[error("invalid helper execution account: {message}")]
    ExecutionAccount {
        /// Account lookup or isolation-policy diagnostic.
        message: String,
    },
    /// Path is not an absolute executable reference.
    #[error("executable path must be absolute: {0}")]
    RelativePath(PathBuf),
    /// Resolution or reading failed.
    #[error("cannot identify executable {path}: {source}")]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// Artifact is not a regular executable file.
    #[error("artifact is not a regular executable file: {0}")]
    NotExecutable(PathBuf),
    /// Configured working directory is not a directory.
    #[error("working directory is not a real directory: {0}")]
    NotDirectory(PathBuf),
    /// Script header is invalid or unsafe.
    #[error("invalid script interpreter in {path}: {message}")]
    InvalidShebang {
        /// Script path.
        path: PathBuf,
        /// Reason.
        message: String,
    },
    /// Interpreter nesting exceeded the hard limit.
    #[error("execution chain is deeper than {MAX_CHAIN_DEPTH}")]
    ChainTooDeep,
    /// One byte artifact exceeded the per-artifact launch limit.
    #[error(
        "execution artifact {path} is {actual_bytes} bytes; maximum is {MAX_LAUNCH_ARTIFACT_BYTES}"
    )]
    ArtifactTooLarge {
        /// Artifact rejected directly from its opened descriptor metadata.
        path: PathBuf,
        /// Exact descriptor length observed before hashing.
        actual_bytes: u64,
    },
    /// The execution chain contained too many retained byte artifacts.
    #[error(
        "execution chain contains {actual_artifacts} artifacts; maximum is {MAX_LAUNCH_ARTIFACTS}"
    )]
    TooManyArtifacts {
        /// Artifact count that would have been required.
        actual_artifacts: usize,
    },
    /// The complete execution chain exceeded the aggregate byte limit.
    #[error("execution chain contains {actual_bytes} bytes; maximum is {MAX_LAUNCH_TOTAL_BYTES}")]
    AggregateTooLarge {
        /// Aggregate descriptor length that would have been required.
        actual_bytes: u64,
    },
    /// This process already retains too many launch snapshot bytes.
    #[error(
        "launch snapshots would retain {requested_bytes} more bytes while {resident_bytes} are resident; process maximum is {MAX_RESIDENT_LAUNCH_BYTES}"
    )]
    ResidentBudgetExceeded {
        /// Bytes requested for the new verified launch.
        requested_bytes: u64,
        /// Bytes already reserved by live verified launches.
        resident_bytes: u64,
    },
    /// Recomputed identity differs from admission.
    #[error("binary drift for {path}: {field}")]
    Drift {
        /// Affected executable.
        path: PathBuf,
        /// Differing identity component.
        field: &'static str,
    },
    /// Linux descriptor execution could not be established safely.
    #[error("descriptor-bound launch is unavailable: {message}")]
    DescriptorLaunch {
        /// Exact descriptor or `/proc` failure.
        message: String,
    },
    /// Startup loader/shared-object discovery or deployment policy failed.
    #[error("unsafe or unsupported startup runtime for {path}: {message}")]
    RuntimeChain {
        /// Native object, runtime artifact, or ancestor that failed.
        path: PathBuf,
        /// Bounded policy or discovery diagnostic.
        message: String,
    },
}

impl ExecutionIdentity {
    /// Open and hash an executable and its kernel interpreter chain.
    ///
    /// # Errors
    ///
    /// Returns a path, file-type, shebang, chain-depth, or I/O diagnostic.
    pub fn resolve(path: &Path) -> Result<Self, IdentityError> {
        Self::resolve_parts(path, &[], None, None)
    }

    /// Open and hash a configured executable, its interpreter chain, and
    /// existing files named by absolute or working-directory-relative fixed
    /// argv entries (including bare names).
    ///
    /// # Errors
    ///
    /// Returns a path, file-type, shebang, chain-depth, or I/O diagnostic.
    pub fn resolve_command(command: &CommandConfig) -> Result<Self, IdentityError> {
        let launch = VerifiedLaunch::open(command)?;
        Ok(launch.identity.clone())
    }

    fn resolve_command_base(command: &CommandConfig) -> Result<Self, IdentityError> {
        let execution_account = resolve_account(
            &command.execution_account,
            command.allow_same_identity_in_debug,
        )
        .map_err(|error| IdentityError::ExecutionAccount {
            message: error.to_string(),
        })?;
        Self::resolve_parts(
            &command.executable,
            &command.args,
            Some(&command.working_directory),
            Some(execution_account),
        )
    }

    fn resolve_parts(
        path: &Path,
        fixed_argv: &[String],
        working_directory: Option<&Path>,
        execution_account: Option<ExecutionAccount>,
    ) -> Result<Self, IdentityError> {
        if !path.is_absolute() {
            return Err(IdentityError::RelativePath(path.to_path_buf()));
        }
        let mut budget = ArtifactBudget::default();
        let opened = open_artifact(path, &mut budget)?;
        let mut execution_chain = Vec::new();
        collect_interpreters(&opened, &mut execution_chain, 0, &mut budget)?;
        collect_fixed_argument_files(
            fixed_argv,
            working_directory,
            &mut execution_chain,
            &mut budget,
        )?;
        let working_directory_identity = working_directory
            .map(|directory| open_directory_identity(directory, execution_account.as_ref()))
            .transpose()?;
        Ok(Self {
            execution_account,
            configured_path: path.to_path_buf(),
            resolved_path: opened.resolved_path,
            sha256: opened.sha256,
            size: opened.size,
            device: opened.device,
            inode: opened.inode,
            mode: opened.mode,
            modified_ns: opened.modified_ns,
            fixed_argv: fixed_argv.to_vec(),
            working_directory: working_directory.map(Path::to_path_buf),
            working_directory_identity,
            execution_chain,
            startup_runtime: None,
        })
    }

    /// Validate the persisted execution identity against the same artifact,
    /// byte, and descriptor budgets used while opening a command.
    ///
    /// # Errors
    ///
    /// Returns a typed resource-limit error for an oversized or overlong
    /// identity, including an identity decoded from an admission record.
    pub fn validate_bounds(&self) -> Result<(), IdentityError> {
        let mut budget = ArtifactBudget::default();
        let mut seen_inodes = BTreeSet::new();
        budget.reserve(&self.resolved_path, self.size)?;
        seen_inodes.insert((self.device, self.inode));
        for artifact in &self.execution_chain {
            budget.reserve(&artifact.path, artifact.size)?;
            seen_inodes.insert((artifact.device, artifact.inode));
        }
        if let Some(runtime) = &self.startup_runtime {
            runtime.validate_and_reserve(&mut budget, &mut seen_inodes)?;
        }
        debug_assert!(budget.artifacts < MAX_LAUNCH_RETAINED_FDS);
        Ok(())
    }

    fn snapshot_bytes(&self) -> u64 {
        self.execution_chain
            .iter()
            .fold(self.size, |total, artifact| total + artifact.size)
    }

    /// Re-open the configured execution chain and distinguish binary drift.
    ///
    /// # Errors
    ///
    /// Returns the exact identity field that drifted or a resolution error.
    pub fn verify_current(&self) -> Result<(), IdentityError> {
        self.validate_bounds()?;
        let current = if let Some(account) = &self.execution_account {
            let working_directory = self.working_directory.clone().ok_or_else(|| {
                descriptor_error("qualified command has no configured working directory")
            })?;
            Self::resolve_command(&CommandConfig {
                executable: self.configured_path.clone(),
                args: self.fixed_argv.clone(),
                env: BTreeMap::default(),
                execution_account: account.configured.clone(),
                allow_same_identity_in_debug: account.debug_same_identity,
                working_directory,
            })?
        } else {
            Self::resolve_parts(
                &self.configured_path,
                &self.fixed_argv,
                self.working_directory.as_deref(),
                None,
            )?
        };
        self.verify_matches(&current)
    }

    /// Compare an already-opened execution identity with this qualified
    /// identity without consulting a pathname again.
    ///
    /// # Errors
    ///
    /// Returns the first differing execution fact.
    pub fn verify_matches(&self, current: &Self) -> Result<(), IdentityError> {
        self.validate_bounds()?;
        current.validate_bounds()?;
        compare_field(
            self.execution_account == current.execution_account,
            &self.configured_path,
            "execution_account",
        )?;
        compare_field(
            self.configured_path == current.configured_path,
            &self.configured_path,
            "configured_path",
        )?;
        compare_field(
            self.fixed_argv == current.fixed_argv,
            &self.configured_path,
            "fixed_argv",
        )?;
        compare_field(
            self.working_directory == current.working_directory,
            &self.configured_path,
            "working_directory",
        )?;
        compare_field(
            self.working_directory_identity == current.working_directory_identity,
            &self.configured_path,
            "working_directory_identity",
        )?;
        compare_field(
            self.resolved_path == current.resolved_path,
            &self.resolved_path,
            "resolved_path",
        )?;
        compare_field(self.sha256 == current.sha256, &self.resolved_path, "sha256")?;
        compare_field(self.size == current.size, &self.resolved_path, "size")?;
        compare_field(self.device == current.device, &self.resolved_path, "device")?;
        compare_field(self.inode == current.inode, &self.resolved_path, "inode")?;
        compare_field(self.mode == current.mode, &self.resolved_path, "mode")?;
        compare_field(
            self.modified_ns == current.modified_ns,
            &self.resolved_path,
            "modified_ns",
        )?;
        compare_field(
            self.execution_chain == current.execution_chain,
            &self.resolved_path,
            "execution_chain",
        )?;
        compare_field(
            self.startup_runtime == current.startup_runtime,
            &self.resolved_path,
            "startup_runtime",
        )?;
        Ok(())
    }
}

/// A Linux launch qualification that owns the exact opened byte artifacts.
///
/// The final executable and every script-like fixed argument are copied into
/// sealed, digest-verified memfd snapshots and addressed as `/proc/self/fd/*`.
/// The working directory is likewise retained by descriptor. Path replacement
/// or in-place source mutation after construction therefore cannot redirect or
/// alter the child. Persistent helpers retain this object across restarts.
#[derive(Debug)]
pub struct VerifiedLaunch {
    identity: ExecutionIdentity,
    command: CommandConfig,
    retained: Vec<RetainedArtifact>,
    working_directory: RetainedDirectory,
    executable: PathBuf,
    argv: Vec<OsString>,
    _resident_reservation: ResidentReservation,
}

impl VerifiedLaunch {
    /// Open, hash, retain, and plan one fixed helper command.
    ///
    /// # Errors
    ///
    /// Returns if any artifact changes between identity construction and the
    /// retained open, if a shebang chain is inconsistent, or if Linux proc-fd
    /// execution is unavailable.
    pub fn open(command: &CommandConfig) -> Result<Self, IdentityError> {
        if !cfg!(target_os = "linux") {
            return Err(descriptor_error(
                "descriptor-bound helper launch currently requires Linux",
            ));
        }
        let identity = ExecutionIdentity::resolve_command_base(command)?;
        Self::retain_identity(command, identity)
    }

    fn retain_identity(
        command: &CommandConfig,
        mut identity: ExecutionIdentity,
    ) -> Result<Self, IdentityError> {
        identity.validate_bounds()?;
        let resident_reservation = ResidentReservation::acquire(identity.snapshot_bytes())?;
        let mut budget = ArtifactBudget::default();
        let mut retained = Vec::with_capacity(identity.execution_chain.len() + 1);
        retained.push(retain_root(&identity, &mut budget)?);
        for artifact in &identity.execution_chain {
            retained.push(retain_chain_artifact(artifact, &mut budget)?);
        }
        debug_assert!(retained.len() < MAX_LAUNCH_RETAINED_FDS);
        let working_directory = retain_directory(
            identity
                .working_directory_identity
                .as_ref()
                .ok_or_else(|| descriptor_error("qualified working directory is absent"))?,
        )?;
        let (executable, argv) = build_launch_plan(&identity, &retained)?;
        identity.startup_runtime = Some(discover_for_retained(&identity, &retained)?);
        identity.validate_bounds()?;
        let launch = Self {
            identity,
            command: command.clone(),
            retained,
            working_directory,
            executable,
            argv,
            _resident_reservation: resident_reservation,
        };
        Ok(launch)
    }

    /// Open a command only if every retained artifact exactly matches an
    /// independently qualified expected identity.
    ///
    /// # Errors
    ///
    /// Refuses replacement bytes before any child can be spawned.
    pub fn open_expected(
        command: &CommandConfig,
        expected: &ExecutionIdentity,
    ) -> Result<Self, IdentityError> {
        if !cfg!(target_os = "linux") {
            return Err(descriptor_error(
                "descriptor-bound helper launch currently requires Linux",
            ));
        }
        expected.validate_bounds()?;
        let current = ExecutionIdentity::resolve_command_base(command)?;
        // Runtime discovery requires the retained memfds. Compare every base
        // fact first while substituting only the independently admitted
        // runtime field, then compare the real discovery after retention.
        let mut comparable = current.clone();
        comparable
            .startup_runtime
            .clone_from(&expected.startup_runtime);
        expected.verify_matches(&comparable)?;
        // Do not allocate any memfd snapshots until the independently admitted
        // identity matches. The second descriptor pass below still detects a
        // mutation between comparison and retention.
        let launch = Self::retain_identity(command, current)?;
        expected.verify_matches(&launch.identity)?;
        Ok(launch)
    }

    /// Exact identity computed from the retained artifacts.
    #[must_use]
    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    /// Exact resolved account that the helper must execute under.
    #[must_use]
    pub(crate) fn execution_account(&self) -> &ExecutionAccount {
        self.identity
            .execution_account
            .as_ref()
            .expect("VerifiedLaunch is only constructed from CommandConfig")
    }

    /// Original fixed command metadata used for environment setup. Executable,
    /// path-like arguments, and working directory are replaced by the retained
    /// launch plan and must not be taken from this value.
    #[must_use]
    pub(crate) fn command(&self) -> &CommandConfig {
        &self.command
    }

    /// Descriptor path for the exact working directory qualified at open.
    #[must_use]
    pub(crate) fn working_directory(&self) -> &Path {
        &self.working_directory.proc_path
    }

    /// Spawn through the retained descriptors after applying caller-owned
    /// stdio, environment, and process-group settings.
    pub(crate) fn spawn(&self, configure: impl FnOnce(&mut Command)) -> io::Result<Child> {
        self.verify_retained().map_err(identity_io)?;
        let mut command = Command::new(&self.executable);
        command.args(&self.argv);
        configure(&mut command);

        let descriptors = self.inherited_descriptors();
        spawn_with_inherited_descriptors(&mut command, &descriptors)
    }

    fn verify_retained(&self) -> Result<(), IdentityError> {
        for artifact in &self.retained {
            artifact.verify()?;
        }
        self.working_directory.verify()?;
        let account = self.execution_account();
        let expected_directory = self
            .identity
            .working_directory_identity
            .as_ref()
            .ok_or_else(|| descriptor_error("qualified working directory is absent"))?;
        require_directory_descriptor_policy(
            &self.working_directory.file,
            &expected_directory.path,
            account,
            !account.debug_same_identity,
        )?;
        let configured_directory = self
            .identity
            .working_directory
            .as_ref()
            .ok_or_else(|| descriptor_error("configured working directory is absent"))?;
        let current_ancestry = qualify_directory_ancestry(
            configured_directory,
            account,
            !account.debug_same_identity,
        )?;
        compare_field(
            current_ancestry == expected_directory.ancestry,
            configured_directory,
            "working_directory_ancestry",
        )?;
        let current_runtime = discover_for_retained(&self.identity, &self.retained)?;
        compare_field(
            self.identity.startup_runtime.as_ref() == Some(&current_runtime),
            &self.identity.resolved_path,
            "startup_runtime",
        )
    }

    fn inherited_descriptors(&self) -> Vec<RawFd> {
        self.retained
            .iter()
            .map(|artifact| artifact.file.as_raw_fd())
            .collect()
    }
}

fn discover_for_retained(
    identity: &ExecutionIdentity,
    retained: &[RetainedArtifact],
) -> Result<StartupRuntimeIdentity, IdentityError> {
    let account = identity
        .execution_account
        .as_ref()
        .ok_or_else(|| descriptor_error("startup runtime has no execution account"))?;
    let root = retained
        .first()
        .ok_or_else(|| descriptor_error("startup runtime has no retained root"))?;
    let mut probes = vec![RuntimeProbe {
        role: RuntimeObjectRole::Root,
        source_path: &root.path,
        proc_path: &root.proc_path,
        file: &root.file,
        prefix: &root.prefix,
    }];
    for (index, artifact) in identity.execution_chain.iter().enumerate() {
        let role = match artifact.role {
            ArtifactRole::Interpreter => RuntimeObjectRole::Interpreter,
            ArtifactRole::WrapperTarget => RuntimeObjectRole::WrapperTarget,
            ArtifactRole::FixedArgument => continue,
        };
        let retained_artifact = retained.get(index + 1).ok_or_else(|| {
            descriptor_error("startup runtime references an absent retained artifact")
        })?;
        probes.push(RuntimeProbe {
            role,
            source_path: &retained_artifact.path,
            proc_path: &retained_artifact.proc_path,
            file: &retained_artifact.file,
            prefix: &retained_artifact.prefix,
        });
    }

    let mut budget = ArtifactBudget::default();
    let mut seen_inodes = BTreeSet::new();
    budget.reserve(&identity.resolved_path, identity.size)?;
    seen_inodes.insert((identity.device, identity.inode));
    for artifact in &identity.execution_chain {
        budget.reserve(&artifact.path, artifact.size)?;
        seen_inodes.insert((artifact.device, artifact.inode));
    }
    discover_startup_runtime(&probes, account, &mut budget, &mut seen_inodes)
}

pub(crate) fn spawn_with_inherited_descriptors(
    command: &mut Command,
    descriptors: &[RawFd],
) -> io::Result<Child> {
    let _guard = DESCRIPTOR_LAUNCH
        .lock()
        .map_err(|_| io::Error::other("descriptor launch lock is poisoned"))?;
    let original_flags = make_inheritable(descriptors)?;
    let spawned = command.spawn();
    let restored = restore_descriptor_flags(descriptors, &original_flags);
    match (spawned, restored) {
        (Ok(child), Ok(())) => Ok(child),
        (Err(error), Ok(())) => Err(error),
        (Ok(mut child), Err(error)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
        (Err(spawn_error), Err(restore_error)) => Err(io::Error::other(format!(
            "spawn failed ({spawn_error}) and descriptor flags could not be restored ({restore_error})"
        ))),
    }
}

#[derive(Debug)]
struct RetainedArtifact {
    file: File,
    path: PathBuf,
    proc_path: PathBuf,
    sha256: String,
    size: u64,
    device: u64,
    inode: u64,
    mode: u32,
    prefix: Vec<u8>,
}

#[derive(Debug)]
struct RetainedDirectory {
    file: File,
    path: PathBuf,
    proc_path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
}

impl RetainedArtifact {
    fn verify(&self) -> Result<(), IdentityError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|source| io_error(&self.path, source))?;
        compare_field(metadata.is_file(), &self.path, "descriptor_file_type")?;
        compare_field(metadata.len() == self.size, &self.path, "descriptor_size")?;
        compare_field(
            metadata.dev() == self.device,
            &self.path,
            "descriptor_device",
        )?;
        compare_field(metadata.ino() == self.inode, &self.path, "descriptor_inode")?;
        compare_field(
            metadata.mode() & 0o777 == self.mode,
            &self.path,
            "descriptor_mode",
        )?;
        verify_seals(&self.file, &self.path)?;
        compare_field(
            hash_descriptor(&self.file, self.size)? == self.sha256,
            &self.path,
            "descriptor_sha256",
        )
    }
}

impl RetainedDirectory {
    fn verify(&self) -> Result<(), IdentityError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|source| io_error(&self.path, source))?;
        compare_field(metadata.is_dir(), &self.path, "directory_descriptor_type")?;
        compare_field(
            metadata.dev() == self.device,
            &self.path,
            "directory_descriptor_device",
        )?;
        compare_field(
            metadata.ino() == self.inode,
            &self.path,
            "directory_descriptor_inode",
        )?;
        compare_field(
            metadata.mode() == self.mode,
            &self.path,
            "directory_descriptor_mode",
        )?;
        compare_field(
            metadata.uid() == self.owner,
            &self.path,
            "directory_descriptor_owner",
        )?;
        compare_field(
            metadata.gid() == self.group,
            &self.path,
            "directory_descriptor_group",
        )
    }
}

fn retain_root(
    identity: &ExecutionIdentity,
    budget: &mut ArtifactBudget,
) -> Result<RetainedArtifact, IdentityError> {
    let opened = open_artifact(&identity.resolved_path, budget)?;
    compare_field(
        opened.resolved_path == identity.resolved_path,
        &identity.resolved_path,
        "retained_resolved_path",
    )?;
    compare_field(
        opened.sha256 == identity.sha256,
        &identity.resolved_path,
        "retained_sha256",
    )?;
    compare_field(
        opened.size == identity.size,
        &identity.resolved_path,
        "retained_size",
    )?;
    compare_field(
        opened.device == identity.device,
        &identity.resolved_path,
        "retained_device",
    )?;
    compare_field(
        opened.inode == identity.inode,
        &identity.resolved_path,
        "retained_inode",
    )?;
    compare_field(
        opened.mode == identity.mode,
        &identity.resolved_path,
        "retained_mode",
    )?;
    compare_field(
        opened.modified_ns == identity.modified_ns,
        &identity.resolved_path,
        "retained_modified_ns",
    )?;
    retained(opened, true)
}

fn retain_chain_artifact(
    expected: &ExecutionArtifact,
    budget: &mut ArtifactBudget,
) -> Result<RetainedArtifact, IdentityError> {
    let opened = if expected.role == ArtifactRole::FixedArgument {
        open_regular_artifact(&expected.path, budget)?
    } else {
        open_artifact(&expected.path, budget)?
    };
    compare_field(
        opened.resolved_path == expected.path,
        &expected.path,
        "retained_chain_path",
    )?;
    compare_field(
        opened.sha256 == expected.sha256,
        &expected.path,
        "retained_chain_sha256",
    )?;
    compare_field(
        opened.size == expected.size,
        &expected.path,
        "retained_chain_size",
    )?;
    compare_field(
        opened.device == expected.device,
        &expected.path,
        "retained_chain_device",
    )?;
    compare_field(
        opened.inode == expected.inode,
        &expected.path,
        "retained_chain_inode",
    )?;
    retained(opened, expected.role != ArtifactRole::FixedArgument)
}

fn retained(opened: OpenedArtifact, executable: bool) -> Result<RetainedArtifact, IdentityError> {
    let source_path = opened.resolved_path;
    let source_digest = opened.sha256;
    let source_size = opened.size;
    let mut snapshot = create_executable_memfd()?;
    copy_exact_bytes(&opened.file, &mut snapshot, source_size, &source_path)?;
    let snapshot_mode = if executable { 0o555 } else { 0o444 };
    fchmod(
        snapshot.as_raw_fd(),
        Mode::from_bits_truncate(snapshot_mode),
    )
    .map_err(|error| {
        descriptor_error(format!(
            "cannot apply mode to snapshot for {}: {error}",
            source_path.display()
        ))
    })?;
    let seals = required_seals();
    fcntl(snapshot.as_raw_fd(), FcntlArg::F_ADD_SEALS(seals)).map_err(|error| {
        descriptor_error(format!(
            "cannot seal snapshot for {}: {error}",
            source_path.display()
        ))
    })?;
    verify_seals(&snapshot, &source_path)?;

    let writable_descriptor = snapshot.as_raw_fd();
    let writable_proc_path = PathBuf::from(format!("/proc/self/fd/{writable_descriptor}"));
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(&writable_proc_path)
        .map_err(|error| {
            descriptor_error(format!(
                "cannot reopen sealed snapshot for {} read-only: {error}",
                source_path.display()
            ))
        })?;
    drop(snapshot);

    let metadata = file
        .metadata()
        .map_err(|source| io_error(&source_path, source))?;
    compare_field(metadata.is_file(), &source_path, "snapshot_file_type")?;
    compare_field(metadata.len() == source_size, &source_path, "snapshot_size")?;
    compare_field(
        hash_descriptor(&file, source_size)? == source_digest,
        &source_path,
        "snapshot_sha256",
    )?;
    verify_seals(&file, &source_path)?;

    let descriptor = file.as_raw_fd();
    let proc_path = PathBuf::from(format!("/proc/self/fd/{descriptor}"));
    let proc_metadata =
        fs::metadata(&proc_path).map_err(|source| IdentityError::DescriptorLaunch {
            message: format!("cannot inspect {}: {source}", proc_path.display()),
        })?;
    compare_field(
        proc_metadata.dev() == metadata.dev() && proc_metadata.ino() == metadata.ino(),
        &source_path,
        "snapshot_proc_fd_identity",
    )?;
    let prefix = read_prefix(&file, &source_path)?;
    Ok(RetainedArtifact {
        file,
        path: source_path,
        proc_path,
        sha256: source_digest,
        size: source_size,
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: snapshot_mode,
        prefix,
    })
}

fn create_executable_memfd() -> Result<File, IdentityError> {
    let base_flags = MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING;
    let executable_flags = base_flags | MemFdCreateFlag::from_bits_retain(libc::MFD_EXEC);
    let descriptor = match memfd_create(c"nq-launch", executable_flags) {
        Ok(descriptor) => descriptor,
        // MFD_EXEC was introduced after memfd_create. Old kernels reject the
        // unknown bit; their original memfd behavior remains executable.
        Err(Errno::EINVAL) => memfd_create(c"nq-launch", base_flags).map_err(|error| {
            descriptor_error(format!("cannot create executable launch snapshot: {error}"))
        })?,
        Err(error) => {
            return Err(descriptor_error(format!(
                "cannot create executable launch snapshot: {error}"
            )));
        }
    };
    Ok(descriptor.into())
}

fn copy_exact_bytes(
    source: &File,
    destination: &mut File,
    size: u64,
    path: &Path,
) -> Result<(), IdentityError> {
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while offset < size {
        let remaining = usize::try_from(size - offset).unwrap_or(usize::MAX);
        let chunk_size = remaining.min(buffer.len());
        let read = source
            .read_at(&mut buffer[..chunk_size], offset)
            .map_err(|source| io_error(path, source))?;
        if read == 0 {
            return Err(descriptor_error(format!(
                "source {} became shorter while snapshotting",
                path.display()
            )));
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|error| descriptor_error(format!("cannot write launch snapshot: {error}")))?;
        offset = offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    destination
        .flush()
        .map_err(|error| descriptor_error(format!("cannot flush launch snapshot: {error}")))
}

fn read_prefix(file: &File, path: &Path) -> Result<Vec<u8>, IdentityError> {
    let mut prefix = vec![0_u8; 4096];
    let prefix_len = file
        .read_at(&mut prefix, 0)
        .map_err(|source| io_error(path, source))?;
    prefix.truncate(prefix_len);
    Ok(prefix)
}

fn required_seals() -> SealFlag {
    SealFlag::F_SEAL_WRITE | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_SEAL
}

fn verify_seals(file: &File, path: &Path) -> Result<(), IdentityError> {
    let raw = fcntl(file.as_raw_fd(), FcntlArg::F_GET_SEALS).map_err(|error| {
        descriptor_error(format!(
            "cannot inspect snapshot seals for {}: {error}",
            path.display()
        ))
    })?;
    let actual = SealFlag::from_bits_truncate(raw);
    compare_field(actual.contains(required_seals()), path, "snapshot_seals")
}

fn retain_directory(expected: &ExecutionDirectory) -> Result<RetainedDirectory, IdentityError> {
    let file = open_directory(&expected.path)?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(&expected.path, source))?;
    compare_field(
        metadata.dev() == expected.device,
        &expected.path,
        "retained_cwd_descriptor_device",
    )?;
    compare_field(
        metadata.ino() == expected.inode,
        &expected.path,
        "retained_cwd_descriptor_inode",
    )?;
    compare_field(
        metadata.mode() == expected.mode,
        &expected.path,
        "retained_cwd_descriptor_mode",
    )?;
    compare_field(
        metadata.uid() == expected.owner,
        &expected.path,
        "retained_cwd_descriptor_owner",
    )?;
    compare_field(
        metadata.gid() == expected.group,
        &expected.path,
        "retained_cwd_descriptor_group",
    )?;
    let descriptor = file.as_raw_fd();
    let proc_path = PathBuf::from(format!("/proc/self/fd/{descriptor}"));
    let proc_metadata = fs::metadata(&proc_path).map_err(|source| {
        descriptor_error(format!(
            "cannot inspect retained working directory {}: {source}",
            proc_path.display()
        ))
    })?;
    compare_field(
        proc_metadata.dev() == expected.device && proc_metadata.ino() == expected.inode,
        &expected.path,
        "retained_cwd_proc_fd_identity",
    )?;
    Ok(RetainedDirectory {
        file,
        path: expected.path.clone(),
        proc_path,
        device: expected.device,
        inode: expected.inode,
        mode: expected.mode,
        owner: expected.owner,
        group: expected.group,
    })
}

fn build_launch_plan(
    identity: &ExecutionIdentity,
    retained: &[RetainedArtifact],
) -> Result<(PathBuf, Vec<OsString>), IdentityError> {
    let argv = identity
        .fixed_argv
        .iter()
        .map(|argument| {
            identity
                .execution_chain
                .iter()
                .enumerate()
                .find(|(_, artifact)| {
                    artifact.role == ArtifactRole::FixedArgument
                        && artifact.fixed_argument.as_deref() == Some(argument)
                })
                .map_or_else(
                    || OsString::from(argument),
                    |(index, _)| retained[index + 1].proc_path.as_os_str().to_owned(),
                )
        })
        .collect();
    let mut cursor = 0;
    let plan = plan_program(identity, retained, 0, argv, &mut cursor)?;
    if identity.execution_chain[cursor..]
        .iter()
        .any(|artifact| artifact.role != ArtifactRole::FixedArgument)
    {
        return Err(descriptor_error(
            "retained interpreter chain contains an unused executable",
        ));
    }
    Ok(plan)
}

fn plan_program(
    identity: &ExecutionIdentity,
    retained: &[RetainedArtifact],
    program_index: usize,
    caller_argv: Vec<OsString>,
    cursor: &mut usize,
) -> Result<(PathBuf, Vec<OsString>), IdentityError> {
    let program = retained
        .get(program_index)
        .ok_or_else(|| descriptor_error("launch plan references an absent descriptor"))?;
    let Some((interpreter, argument)) = parse_shebang(&program.prefix, &program.path)? else {
        return Ok((program.proc_path.clone(), caller_argv));
    };
    let expected_interpreter = identity
        .execution_chain
        .get(*cursor)
        .ok_or_else(|| descriptor_error("script interpreter is absent from qualified identity"))?;
    if expected_interpreter.role != ArtifactRole::Interpreter {
        return Err(descriptor_error(
            "qualified execution chain is not ordered by interpreter",
        ));
    }
    let resolved_interpreter =
        fs::canonicalize(&interpreter).map_err(|source| io_error(&interpreter, source))?;
    compare_field(
        resolved_interpreter == expected_interpreter.path,
        &program.path,
        "launch_interpreter_path",
    )?;
    *cursor += 1;
    let interpreter_index = *cursor;

    if expected_interpreter.path == Path::new("/usr/bin/env") {
        let command = argument
            .ok_or_else(|| descriptor_error("/usr/bin/env launch is missing its fixed command"))?;
        compare_field(
            expected_interpreter.fixed_argument.as_deref() == Some(command.as_str()),
            &program.path,
            "launch_wrapper_command",
        )?;
        let target = identity
            .execution_chain
            .get(*cursor)
            .ok_or_else(|| descriptor_error("env wrapper target is absent"))?;
        if target.role != ArtifactRole::WrapperTarget {
            return Err(descriptor_error(
                "env wrapper target has the wrong qualified role",
            ));
        }
        *cursor += 1;
        let mut argv = Vec::with_capacity(caller_argv.len() + 1);
        argv.push(program.proc_path.as_os_str().to_owned());
        argv.extend(caller_argv);
        return plan_program(identity, retained, *cursor, argv, cursor);
    }

    let mut argv = Vec::with_capacity(caller_argv.len() + 2);
    if let Some(argument) = argument {
        argv.push(argument.into());
    }
    argv.push(program.proc_path.as_os_str().to_owned());
    argv.extend(caller_argv);
    plan_program(identity, retained, interpreter_index, argv, cursor)
}

fn hash_descriptor(file: &File, expected_size: u64) -> Result<String, IdentityError> {
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while offset < expected_size {
        let remaining = usize::try_from(expected_size - offset).unwrap_or(usize::MAX);
        let chunk_size = buffer.len().min(remaining);
        let read = file
            .read_at(&mut buffer[..chunk_size], offset)
            .map_err(|source| IdentityError::DescriptorLaunch {
                message: format!("cannot hash launch descriptor: {source}"),
            })?;
        if read == 0 {
            return Err(descriptor_error(format!(
                "launch descriptor became shorter than its {expected_size}-byte bound while hashing"
            )));
        }
        hasher.update(&buffer[..read]);
        offset = offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn make_inheritable(descriptors: &[RawFd]) -> io::Result<Vec<FdFlag>> {
    let mut original = Vec::with_capacity(descriptors.len());
    for &descriptor in descriptors {
        let flags = match descriptor_flags(descriptor) {
            Ok(flags) => flags,
            Err(error) => {
                let _ = restore_descriptor_flags(&descriptors[..original.len()], &original);
                return Err(error);
            }
        };
        if let Err(error) = fcntl(descriptor, FcntlArg::F_SETFD(flags - FdFlag::FD_CLOEXEC)) {
            let _ = restore_descriptor_flags(&descriptors[..original.len()], &original);
            return Err(io::Error::other(error));
        }
        original.push(flags);
    }
    Ok(original)
}

fn restore_descriptor_flags(descriptors: &[RawFd], flags: &[FdFlag]) -> io::Result<()> {
    let mut first_error = None;
    for (&descriptor, flags) in descriptors.iter().zip(flags) {
        if let Err(error) = fcntl(descriptor, FcntlArg::F_SETFD(*flags)) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), |error| Err(io::Error::other(error)))
}

fn descriptor_flags(descriptor: RawFd) -> io::Result<FdFlag> {
    fcntl(descriptor, FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .map_err(io::Error::other)
}

fn descriptor_error(message: impl Into<String>) -> IdentityError {
    IdentityError::DescriptorLaunch {
        message: message.into(),
    }
}

fn identity_io(error: IdentityError) -> io::Error {
    io::Error::other(error)
}

fn compare_field(ok: bool, path: &Path, field: &'static str) -> Result<(), IdentityError> {
    if ok {
        Ok(())
    } else {
        Err(IdentityError::Drift {
            path: path.to_path_buf(),
            field,
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct ArtifactBudget {
    artifacts: usize,
    total_bytes: u64,
}

impl ArtifactBudget {
    pub(crate) fn reserve(&mut self, path: &Path, size: u64) -> Result<(), IdentityError> {
        if size > MAX_LAUNCH_ARTIFACT_BYTES {
            return Err(IdentityError::ArtifactTooLarge {
                path: path.to_path_buf(),
                actual_bytes: size,
            });
        }
        let artifacts = self.artifacts.saturating_add(1);
        if artifacts > MAX_LAUNCH_ARTIFACTS {
            return Err(IdentityError::TooManyArtifacts {
                actual_artifacts: artifacts,
            });
        }
        let total_bytes =
            self.total_bytes
                .checked_add(size)
                .ok_or(IdentityError::AggregateTooLarge {
                    actual_bytes: u64::MAX,
                })?;
        if total_bytes > MAX_LAUNCH_TOTAL_BYTES {
            return Err(IdentityError::AggregateTooLarge {
                actual_bytes: total_bytes,
            });
        }
        self.artifacts = artifacts;
        self.total_bytes = total_bytes;
        Ok(())
    }
}

#[derive(Debug)]
struct ResidentReservation {
    bytes: u64,
}

impl ResidentReservation {
    fn acquire(bytes: u64) -> Result<Self, IdentityError> {
        let mut resident = RESIDENT_LAUNCH_BYTES.load(Ordering::Acquire);
        loop {
            let Some(next) = resident.checked_add(bytes) else {
                return Err(IdentityError::ResidentBudgetExceeded {
                    requested_bytes: bytes,
                    resident_bytes: resident,
                });
            };
            if next > MAX_RESIDENT_LAUNCH_BYTES {
                return Err(IdentityError::ResidentBudgetExceeded {
                    requested_bytes: bytes,
                    resident_bytes: resident,
                });
            }
            match RESIDENT_LAUNCH_BYTES.compare_exchange_weak(
                resident,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self { bytes }),
                Err(current) => resident = current,
            }
        }
    }
}

impl Drop for ResidentReservation {
    fn drop(&mut self) {
        let previous = RESIDENT_LAUNCH_BYTES.fetch_sub(self.bytes, Ordering::AcqRel);
        debug_assert!(previous >= self.bytes);
    }
}

struct OpenedArtifact {
    file: File,
    resolved_path: PathBuf,
    sha256: String,
    size: u64,
    device: u64,
    inode: u64,
    mode: u32,
    modified_ns: String,
    prefix: Vec<u8>,
}

fn open_directory_identity(
    path: &Path,
    account: Option<&ExecutionAccount>,
) -> Result<ExecutionDirectory, IdentityError> {
    let resolved = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let file = open_directory(&resolved)?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(&resolved, source))?;
    if !metadata.is_dir() {
        return Err(IdentityError::NotDirectory(resolved));
    }
    let ancestry = account
        .map(|account| qualify_directory_ancestry(path, account, !account.debug_same_identity))
        .transpose()?
        .unwrap_or_default();
    Ok(ExecutionDirectory {
        path: resolved,
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        owner: metadata.uid(),
        group: metadata.gid(),
        ancestry,
    })
}

fn open_directory(path: &Path) -> Result<File, IdentityError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.is_dir() {
        return Err(IdentityError::NotDirectory(path.to_path_buf()));
    }
    Ok(file)
}

fn open_artifact(
    path: &Path,
    budget: &mut ArtifactBudget,
) -> Result<OpenedArtifact, IdentityError> {
    open_artifact_with_mode(path, true, budget)
}

fn open_regular_artifact(
    path: &Path,
    budget: &mut ArtifactBudget,
) -> Result<OpenedArtifact, IdentityError> {
    open_artifact_with_mode(path, false, budget)
}

fn open_artifact_with_mode(
    path: &Path,
    require_executable: bool,
    budget: &mut ArtifactBudget,
) -> Result<OpenedArtifact, IdentityError> {
    let resolved_path = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&resolved_path)
        .map_err(|source| io_error(&resolved_path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(&resolved_path, source))?;
    if !metadata.is_file() || (require_executable && metadata.mode() & 0o111 == 0) {
        return Err(IdentityError::NotExecutable(resolved_path));
    }
    // Descriptor metadata is the allocation boundary: sparse or otherwise
    // oversized files are refused before prefix allocation, hashing, or memfd
    // creation. The same shared budget accounts for the complete chain.
    budget.reserve(&resolved_path, metadata.len())?;

    let prefix = read_prefix(&file, &resolved_path)?;
    let sha256 = hash_descriptor(&file, metadata.len())?;
    let metadata_after = file
        .metadata()
        .map_err(|source| io_error(&resolved_path, source))?;
    compare_field(
        metadata_after.len() == metadata.len()
            && metadata_after.dev() == metadata.dev()
            && metadata_after.ino() == metadata.ino()
            && metadata_after.mode() == metadata.mode()
            && metadata_after.mtime() == metadata.mtime()
            && metadata_after.mtime_nsec() == metadata.mtime_nsec(),
        &resolved_path,
        "source_changed_while_hashing",
    )?;

    Ok(OpenedArtifact {
        file,
        resolved_path,
        sha256,
        size: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        modified_ns: (i128::from(metadata.mtime()) * 1_000_000_000
            + i128::from(metadata.mtime_nsec()))
        .to_string(),
        prefix,
    })
}

fn collect_interpreters(
    opened: &OpenedArtifact,
    chain: &mut Vec<ExecutionArtifact>,
    depth: usize,
    budget: &mut ArtifactBudget,
) -> Result<(), IdentityError> {
    if depth >= MAX_CHAIN_DEPTH {
        return Err(IdentityError::ChainTooDeep);
    }
    let path = &opened.resolved_path;
    let Some((interpreter, argument)) = parse_shebang(&opened.prefix, path)? else {
        return Ok(());
    };
    let interpreter_opened = open_artifact(&interpreter, budget)?;
    chain.push(execution_artifact(
        &interpreter_opened,
        ArtifactRole::Interpreter,
        argument.clone(),
    ));
    if interpreter_opened.resolved_path == Path::new("/usr/bin/env") {
        let command = argument
            .as_deref()
            .ok_or_else(|| IdentityError::InvalidShebang {
                path: path.clone(),
                message: "/usr/bin/env shebang requires one fixed command".into(),
            })?;
        if command.starts_with('-') || command.contains('/') {
            return Err(IdentityError::InvalidShebang {
                path: path.clone(),
                message: "only a single bare command is accepted after /usr/bin/env".into(),
            });
        }
        let target =
            resolve_sanitized_path(command).ok_or_else(|| IdentityError::InvalidShebang {
                path: path.clone(),
                message: format!("wrapper target {command:?} is absent from sanitized PATH"),
            })?;
        let target_opened = open_artifact(&target, budget)?;
        chain.push(execution_artifact(
            &target_opened,
            ArtifactRole::WrapperTarget,
            None,
        ));
        if target_opened.prefix.starts_with(b"#!") {
            collect_interpreters(&target_opened, chain, depth + 1, budget)?;
        }
        return Ok(());
    }
    if interpreter_opened.prefix.starts_with(b"#!") {
        collect_interpreters(&interpreter_opened, chain, depth + 1, budget)?;
    }
    Ok(())
}

fn execution_artifact(
    opened: &OpenedArtifact,
    role: ArtifactRole,
    fixed_argument: Option<String>,
) -> ExecutionArtifact {
    ExecutionArtifact {
        role,
        path: opened.resolved_path.clone(),
        sha256: opened.sha256.clone(),
        size: opened.size,
        device: opened.device,
        inode: opened.inode,
        fixed_argument,
    }
}

fn collect_fixed_argument_files(
    fixed_argv: &[String],
    working_directory: Option<&Path>,
    chain: &mut Vec<ExecutionArtifact>,
    budget: &mut ArtifactBudget,
) -> Result<(), IdentityError> {
    for argument in fixed_argv {
        let argument_path = Path::new(argument);
        let candidate = if argument_path.is_absolute() {
            Some(argument_path.to_path_buf())
        } else {
            working_directory.map(|directory| directory.join(argument_path))
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let metadata = match fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(io_error(&candidate, source)),
        };
        if !metadata.is_file() {
            continue;
        }
        let opened = open_regular_artifact(&candidate, budget)?;
        chain.push(execution_artifact(
            &opened,
            ArtifactRole::FixedArgument,
            Some(argument.clone()),
        ));
    }
    Ok(())
}

fn resolve_sanitized_path(command: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(command))
        .find(|candidate| candidate.is_file())
}

fn parse_shebang(
    prefix: &[u8],
    path: &Path,
) -> Result<Option<(PathBuf, Option<String>)>, IdentityError> {
    if !prefix.starts_with(b"#!") {
        return Ok(None);
    }
    let end = prefix
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(prefix.len());
    let line = std::str::from_utf8(&prefix[2..end]).map_err(|_| IdentityError::InvalidShebang {
        path: path.to_path_buf(),
        message: "header is not UTF-8".into(),
    })?;
    let line = line.trim_end_matches('\r').trim();
    let mut parts = line.split_whitespace();
    let interpreter = parts.next().ok_or_else(|| IdentityError::InvalidShebang {
        path: path.to_path_buf(),
        message: "missing interpreter".into(),
    })?;
    let interpreter = PathBuf::from(interpreter);
    if !interpreter.is_absolute() {
        return Err(IdentityError::InvalidShebang {
            path: path.to_path_buf(),
            message: "interpreter path must be absolute".into(),
        });
    }
    let remainder: Vec<_> = parts.collect();
    if remainder.len() > 1 {
        return Err(IdentityError::InvalidShebang {
            path: path.to_path_buf(),
            message: "more than one shebang argument is ambiguous".into(),
        });
    }
    Ok(Some((
        interpreter,
        remainder.first().map(|value| (*value).to_owned()),
    )))
}

fn io_error(path: &Path, source: io::Error) -> IdentityError {
    IdentityError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn hashes_opened_executable_and_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.py");
        fs::write(&path, b"#!/usr/bin/env python3\nprint('ok')\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let identity = ExecutionIdentity::resolve(&path).unwrap();
        assert_eq!(identity.sha256.len(), 71);
        assert_eq!(identity.execution_chain.len(), 2);
        assert_eq!(
            identity.execution_chain[1].role,
            ArtifactRole::WrapperTarget
        );
        identity.verify_current().unwrap();
    }

    #[test]
    fn detects_replaced_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper");
        fs::write(&path, b"first").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let identity = ExecutionIdentity::resolve(&path).unwrap();
        fs::write(&path, b"second").unwrap();
        let error = identity.verify_current().unwrap_err();
        assert!(matches!(error, IdentityError::Drift { .. }));
    }

    #[test]
    fn rejects_non_executable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"data").unwrap();
        assert!(matches!(
            ExecutionIdentity::resolve(&path),
            Err(IdentityError::NotExecutable(_))
        ));
    }

    #[test]
    fn bare_cwd_relative_script_argument_is_byte_identified() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("helper.py");
        fs::write(&script, b"print('first')\n").unwrap();
        let command = CommandConfig {
            executable: PathBuf::from("/usr/bin/python3"),
            args: vec!["helper.py".into()],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: dir.path().to_path_buf(),
        };
        let identity = ExecutionIdentity::resolve_command(&command).unwrap();
        assert!(identity.execution_chain.iter().any(|artifact| {
            artifact.role == ArtifactRole::FixedArgument
                && artifact.path == script.canonicalize().unwrap()
                && artifact.fixed_argument.as_deref() == Some("helper.py")
        }));
        fs::write(&script, b"print('second')\n").unwrap();
        assert!(matches!(
            identity.verify_current(),
            Err(IdentityError::Drift {
                field: "execution_chain",
                ..
            })
        ));
    }

    #[test]
    fn expected_identity_refuses_path_replacement_before_launch() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("helper.py");
        fs::write(&script, b"print('qualified')\n").unwrap();
        let command = CommandConfig {
            executable: PathBuf::from("/usr/bin/python3"),
            args: vec![script.display().to_string()],
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: dir.path().to_path_buf(),
        };
        let expected = ExecutionIdentity::resolve_command(&command).unwrap();
        fs::rename(&script, dir.path().join("qualified.py")).unwrap();
        fs::write(&script, b"print('replacement')\n").unwrap();

        assert!(matches!(
            VerifiedLaunch::open_expected(&command, &expected),
            Err(IdentityError::Drift { .. })
        ));
    }

    #[test]
    fn launch_snapshots_are_digest_verified_and_fully_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("helper");
        fs::copy("/bin/true", &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o777)).unwrap();
        let command = CommandConfig {
            executable,
            args: Vec::new(),
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: dir.path().to_path_buf(),
        };
        let launch = VerifiedLaunch::open(&command).expect("qualify native executable");
        launch.verify_retained().expect("verify sealed snapshot");

        for artifact in &launch.retained {
            let raw = fcntl(artifact.file.as_raw_fd(), FcntlArg::F_GET_SEALS).unwrap();
            let seals = SealFlag::from_bits_truncate(raw);
            assert!(seals.contains(required_seals()));

            let write_open_error = OpenOptions::new()
                .write(true)
                .open(&artifact.proc_path)
                .expect_err("snapshot mode admitted a write-only descriptor");
            assert_eq!(write_open_error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(artifact.mode, 0o555);
            artifact.verify().expect("snapshot remains unchanged");
        }
    }

    #[test]
    fn same_inode_native_source_mutation_leaves_snapshot_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("helper");
        fs::copy("/bin/true", &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let command = CommandConfig {
            executable: executable.clone(),
            args: Vec::new(),
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: dir.path().to_path_buf(),
        };
        let launch = VerifiedLaunch::open(&command).expect("qualify native executable");
        let inode = fs::metadata(&executable).unwrap().ino();
        let snapshot_digest = launch.retained[0].sha256.clone();

        fs::copy("/bin/false", &executable).unwrap();
        assert_eq!(fs::metadata(&executable).unwrap().ino(), inode);
        assert_ne!(
            ExecutionIdentity::resolve(&executable).unwrap().sha256,
            snapshot_digest
        );
        launch.retained[0]
            .verify()
            .expect("sealed snapshot retains qualified bytes");
        assert_eq!(
            hash_descriptor(&launch.retained[0].file, launch.retained[0].size).unwrap(),
            snapshot_digest
        );
    }

    #[test]
    fn expected_identity_refuses_working_directory_replacement() {
        let root = tempfile::tempdir().unwrap();
        let configured_cwd = root.path().join("cwd");
        fs::create_dir(&configured_cwd).unwrap();
        let command = CommandConfig {
            executable: PathBuf::from("/bin/true"),
            args: Vec::new(),
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: configured_cwd.clone(),
        };
        let expected = ExecutionIdentity::resolve_command(&command).unwrap();
        fs::rename(&configured_cwd, root.path().join("qualified-cwd")).unwrap();
        fs::create_dir(&configured_cwd).unwrap();

        assert!(matches!(
            VerifiedLaunch::open_expected(&command, &expected),
            Err(IdentityError::Drift {
                field: "working_directory_identity",
                ..
            })
        ));
    }

    #[test]
    fn retained_working_directory_is_pinned_but_ancestry_drift_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let configured_cwd = root.path().join("cwd");
        fs::create_dir(&configured_cwd).unwrap();
        let command = CommandConfig {
            executable: PathBuf::from("/bin/true"),
            args: Vec::new(),
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: configured_cwd.clone(),
        };
        let launch = VerifiedLaunch::open(&command).unwrap();
        let expected = launch
            .identity()
            .working_directory_identity
            .as_ref()
            .unwrap();

        fs::rename(&configured_cwd, root.path().join("qualified-cwd")).unwrap();
        fs::create_dir(&configured_cwd).unwrap();
        assert!(matches!(
            launch.verify_retained(),
            Err(IdentityError::Drift {
                field: "working_directory_ancestry",
                ..
            })
        ));

        let retained = fs::metadata(launch.working_directory()).unwrap();
        let replacement = fs::metadata(&configured_cwd).unwrap();
        assert_eq!(
            (retained.dev(), retained.ino()),
            (expected.device, expected.inode)
        );
        assert_ne!(
            (replacement.dev(), replacement.ino()),
            (expected.device, expected.inode)
        );
    }

    fn debug_command(executable: PathBuf, args: Vec<String>, cwd: &Path) -> CommandConfig {
        CommandConfig {
            executable,
            args,
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: cwd.to_path_buf(),
        }
    }

    fn create_sparse_file(path: &Path, size: u64, executable: bool) {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .expect("create sparse artifact");
        file.set_len(size).expect("size sparse artifact");
        if executable {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .expect("make sparse artifact executable");
        }
    }

    #[test]
    fn rejects_huge_sparse_artifact_from_fstat_before_hashing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let executable = directory.path().join("huge-helper");
        create_sparse_file(&executable, MAX_LAUNCH_ARTIFACT_BYTES + 1, true);

        assert!(matches!(
            ExecutionIdentity::resolve(&executable),
            Err(IdentityError::ArtifactTooLarge {
                actual_bytes,
                ..
            }) if actual_bytes == MAX_LAUNCH_ARTIFACT_BYTES + 1
        ));
    }

    #[test]
    fn expected_launch_rejects_huge_same_inode_replacement_before_snapshotting() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let executable = directory.path().join("helper");
        fs::write(&executable, b"qualified").expect("write helper");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("make helper executable");
        let command = debug_command(executable.clone(), Vec::new(), directory.path());
        let expected = ExecutionIdentity::resolve_command(&command).expect("qualify helper");
        let original_inode = fs::metadata(&executable).expect("helper metadata").ino();

        OpenOptions::new()
            .write(true)
            .open(&executable)
            .expect("open replacement")
            .set_len(MAX_LAUNCH_ARTIFACT_BYTES + 1)
            .expect("grow same inode");
        assert_eq!(
            fs::metadata(&executable)
                .expect("replacement metadata")
                .ino(),
            original_inode
        );
        assert!(matches!(
            VerifiedLaunch::open_expected(&command, &expected),
            Err(IdentityError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_too_many_existing_fixed_argument_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut arguments = Vec::new();
        for index in 0..MAX_LAUNCH_ARTIFACTS {
            let path = directory.path().join(format!("fixed-{index}"));
            fs::write(&path, b"x").expect("write fixed file");
            arguments.push(path.display().to_string());
        }
        let command = debug_command(PathBuf::from("/bin/true"), arguments, directory.path());

        assert!(matches!(
            ExecutionIdentity::resolve_command(&command),
            Err(IdentityError::TooManyArtifacts {
                actual_artifacts
            }) if actual_artifacts == MAX_LAUNCH_ARTIFACTS + 1
        ));
    }

    #[test]
    fn rejects_aggregate_sparse_artifact_overflow() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first = directory.path().join("first-large-fixed");
        let second = directory.path().join("second-large-fixed");
        create_sparse_file(&first, MAX_LAUNCH_ARTIFACT_BYTES, false);
        create_sparse_file(&second, MAX_LAUNCH_ARTIFACT_BYTES, false);
        let command = debug_command(
            PathBuf::from("/bin/true"),
            vec![first.display().to_string(), second.display().to_string()],
            directory.path(),
        );

        assert!(matches!(
            ExecutionIdentity::resolve_command(&command),
            Err(IdentityError::AggregateTooLarge { actual_bytes })
                if actual_bytes > MAX_LAUNCH_TOTAL_BYTES
        ));
    }

    #[test]
    fn refuses_a_single_reservation_larger_than_the_process_snapshot_budget() {
        assert!(matches!(
            ResidentReservation::acquire(MAX_RESIDENT_LAUNCH_BYTES + 1),
            Err(IdentityError::ResidentBudgetExceeded {
                requested_bytes,
                ..
            }) if requested_bytes == MAX_RESIDENT_LAUNCH_BYTES + 1
        ));
    }
}
