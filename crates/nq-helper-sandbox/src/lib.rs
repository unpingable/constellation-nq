//! Narrow Linux child-isolation boundary for watcher helper processes.
//!
//! This is deliberately the only NQ-ng crate permitted to contain unsafe
//! code. Its public surface is safe: resolve one local execution account and
//! attach a fixed, async-signal-safe child hook to a [`std::process::Command`].

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

use nix::fcntl::AtFlags;
use nix::unistd::{Gid, Uid, User, chown, fchownat, getegid, geteuid};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const RUNTIME_ROOT_MODE: u32 = 0o711;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const X86_X32_SYSCALL_BIT: u32 = 0x4000_0000;
const CLONE_NEWTIME: u32 = 0x0000_0080;
const FORBIDDEN_CLONE_FLAGS: u32 = CLONE_NEWTIME
    | libc::CLONE_PARENT.unsigned_abs()
    | libc::CLONE_NEWCGROUP.unsigned_abs()
    | libc::CLONE_NEWIPC.unsigned_abs()
    | libc::CLONE_NEWNET.unsigned_abs()
    | libc::CLONE_NEWNS.unsigned_abs()
    | libc::CLONE_NEWPID.unsigned_abs()
    | libc::CLONE_NEWUSER.unsigned_abs()
    | libc::CLONE_NEWUTS.unsigned_abs();
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("nq-helper-sandbox supports only Linux AMD64 and ARM64 in v1");
const MAX_XATTR_NAME_BYTES: usize = 64 * 1024;
const POSIX_ACCESS_ACL: &[u8] = b"system.posix_acl_access";
const POSIX_DEFAULT_ACL: &[u8] = b"system.posix_acl_default";

/// Serializes every production helper spawn against a Store-integrity secret
/// interval.  The lock protects only the process-creation boundary; it grants
/// no signing, Store, or helper authority.
static C2_PROCESS_FENCE: Mutex<()> = Mutex::new(());

/// Process-local guard held while Store-integrity secret bytes are live.
///
/// This type intentionally exposes no lock or authority accessor.  Its sole
/// purpose is to make a production helper spawn mutually exclusive with the
/// key-open/load/sign/recheck/drop interval.
pub struct C2SecretProcessGuard {
    _guard: MutexGuard<'static, ()>,
    owner_pid: u32,
}

impl C2SecretProcessGuard {
    /// Refuse if an ungoverned process split occurred while the guard was
    /// held.  Production `Command::spawn` is prevented by the shared fence;
    /// this check also catches an unexpected external `fork` in the child.
    pub fn verify_same_process(&self) -> io::Result<()> {
        if std::process::id() != self.owner_pid {
            return Err(io::Error::other(
                "Store-integrity secret interval crossed a process boundary",
            ));
        }
        Ok(())
    }
}

/// Enter the process-wide Store-integrity secret interval.
///
/// The guard is deliberately non-`Send` through its `MutexGuard`, preventing
/// transfer of the live-secret interval to another thread.
pub fn enter_c2_secret_process_interval() -> io::Result<C2SecretProcessGuard> {
    let guard = C2_PROCESS_FENCE
        .lock()
        .map_err(|_| io::Error::other("C2 process fence is poisoned"))?;
    Ok(C2SecretProcessGuard {
        _guard: guard,
        owner_pid: std::process::id(),
    })
}

/// Run one parent-side process-creation boundary while no Store-integrity
/// secret interval is active.
pub fn with_c2_process_spawn_fence<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let _guard = C2_PROCESS_FENCE
        .lock()
        .map_err(|_| io::Error::other("C2 process fence is poisoned"))?;
    operation()
}

/// Exact local account identity bound into an admission and helper launch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAccount {
    /// Human name or decimal UID supplied in configuration.
    pub configured: String,
    /// Account database name resolved at qualification time.
    pub name: String,
    /// Exact target Unix user ID.
    pub uid: u32,
    /// Exact target primary Unix group ID.
    pub gid: u32,
    /// Whether the debug-only same-identity exception is active.
    pub debug_same_identity: bool,
}

/// Hard operating-system limits installed in every helper process before exec.
///
/// Address space, CPU, and file-size limits are per process; the process limit
/// is Linux's per-real-UID `RLIMIT_NPROC`. The packaged systemd unit adds an
/// aggregate service ceiling, while deployments that require mutually
/// independent process accounting must use a distinct execution account for
/// each trust domain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IsolationLimits {
    /// Maximum virtual address space for one process.
    pub address_space_bytes: u64,
    /// Maximum cumulative CPU seconds for one process.
    pub cpu_seconds: u64,
    /// Maximum processes/threads for the real execution UID.
    pub processes: u64,
    /// Maximum descriptors open in one process.
    pub open_files: u64,
    /// Maximum size of one regular file written by a process.
    pub file_bytes: u64,
}

impl Default for IsolationLimits {
    fn default() -> Self {
        Self {
            address_space_bytes: 512 * 1024 * 1024,
            cpu_seconds: 60,
            processes: 32,
            open_files: 128,
            file_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Pinned, package-compatible root for per-helper runtime directories.
///
/// Construction rejects aliases and symlinks, ownership other than the
/// current daemon UID/GID, permissions other than `0711`, and any access or
/// default POSIX ACL that effectively grants write access to a non-owner.
/// The open directory descriptor keeps the validated inode alive while child
/// directories are created below it.
#[derive(Debug)]
pub struct ValidatedRuntimeRoot {
    descriptor: fs::File,
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
}

impl ValidatedRuntimeRoot {
    /// Canonical path that was validated and must be used in helper-visible
    /// Unix socket paths.
    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Stable `/proc/self/fd` path used to create a directory beneath the
    /// pinned root inode without reopening the configured pathname.
    #[must_use]
    pub fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.descriptor.as_raw_fd()))
    }

    /// Recheck that the configured pathname still resolves to the pinned,
    /// package-compatible inode.
    ///
    /// # Errors
    ///
    /// Returns if the path was replaced, aliased, re-owned, relaxed, or given
    /// a write-granting POSIX ACL after initial validation.
    pub fn revalidate(&self) -> io::Result<()> {
        let canonical = fs::canonicalize(&self.canonical_path)?;
        if canonical != self.canonical_path {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper runtime root is no longer its canonical path",
            ));
        }
        let path_metadata = fs::symlink_metadata(&self.canonical_path)?;
        let descriptor_metadata = self.descriptor.metadata()?;
        validate_runtime_root_metadata(&path_metadata)?;
        validate_runtime_root_metadata(&descriptor_metadata)?;
        if path_metadata.dev() != self.device
            || path_metadata.ino() != self.inode
            || descriptor_metadata.dev() != self.device
            || descriptor_metadata.ino() != self.inode
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper runtime root changed after validation",
            ));
        }
        validate_runtime_root_ancestors(&self.canonical_path)?;
        require_no_posix_acl(&self.descriptor)
    }
}

/// Open and pin the trusted `/run/nq/helpers`-style runtime root.
///
/// # Errors
///
/// Returns if `path` is not an absolute canonical real directory owned by the
/// current daemon UID/GID with exact mode `0711`, if it grants non-owner write
/// access through a POSIX ACL, or if it changes during validation.
pub fn open_runtime_root(path: &Path) -> io::Result<ValidatedRuntimeRoot> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "helper runtime root must be absolute",
        ));
    }
    let canonical_path = fs::canonicalize(path)?;
    if canonical_path != path {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper runtime root must be its canonical path without symlinks or aliases",
        ));
    }
    let descriptor = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = descriptor.metadata()?;
    validate_runtime_root_metadata(&metadata)?;
    validate_runtime_root_ancestors(&canonical_path)?;
    require_no_posix_acl(&descriptor)?;
    let root = ValidatedRuntimeRoot {
        device: metadata.dev(),
        inode: metadata.ino(),
        descriptor,
        canonical_path,
    };
    root.revalidate()?;
    Ok(root)
}

/// Local-account resolution or isolation-policy failure.
#[derive(Debug, Error)]
pub enum AccountError {
    /// The configured account token is empty or malformed.
    #[error("invalid helper execution account {0:?}")]
    Invalid(String),
    /// Local user database lookup failed.
    #[error("cannot resolve helper execution account {account:?}: {message}")]
    Lookup {
        /// Configured account token.
        account: String,
        /// Local lookup diagnostic.
        message: String,
    },
    /// No local account matched the configured name or numeric UID.
    #[error("helper execution account does not exist: {0}")]
    Unknown(String),
    /// Root is never a valid watcher execution identity.
    #[error("helper execution account {account} resolves to root identity")]
    Root {
        /// Configured account token.
        account: String,
    },
    /// Production helpers must not share the daemon identity.
    #[error("helper execution UID {uid} is the current daemon/operator UID")]
    SameIdentity {
        /// Rejected shared UID.
        uid: u32,
    },
    /// Production helpers must not share the daemon primary group.
    #[error("helper execution GID {gid} is the current daemon/operator GID")]
    SameGroup {
        /// Rejected shared GID.
        gid: u32,
    },
    /// The same-identity exception cannot be enabled in a release build.
    #[error("allow_same_identity_in_debug is unavailable in release builds")]
    DebugOverrideUnavailable,
}

/// Resolve a configured human account name or decimal UID through the local
/// account database and enforce the helper/daemon separation policy.
///
/// Numeric UIDs must have a passwd entry because that entry supplies the exact
/// primary GID admitted with the helper.
///
/// # Errors
///
/// Returns a typed lookup or isolation-policy failure.
pub fn resolve_account(
    configured: &str,
    allow_same_identity_in_debug: bool,
) -> Result<ExecutionAccount, AccountError> {
    if configured.is_empty()
        || configured.len() > 255
        || configured
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(AccountError::Invalid(configured.to_owned()));
    }
    let user = if configured.bytes().all(|byte| byte.is_ascii_digit()) {
        let uid = configured
            .parse::<u32>()
            .map_err(|_| AccountError::Invalid(configured.to_owned()))?;
        User::from_uid(Uid::from_raw(uid)).map_err(|error| AccountError::Lookup {
            account: configured.to_owned(),
            message: error.to_string(),
        })?
    } else {
        User::from_name(configured).map_err(|error| AccountError::Lookup {
            account: configured.to_owned(),
            message: error.to_string(),
        })?
    }
    .ok_or_else(|| AccountError::Unknown(configured.to_owned()))?;

    let uid = user.uid.as_raw();
    let gid = user.gid.as_raw();
    if uid == 0 || gid == 0 {
        return Err(AccountError::Root {
            account: configured.to_owned(),
        });
    }
    if allow_same_identity_in_debug && !cfg!(debug_assertions) {
        return Err(AccountError::DebugOverrideUnavailable);
    }
    let same_user = uid == geteuid().as_raw();
    let same_group = gid == getegid().as_raw();
    let debug_exception =
        cfg!(debug_assertions) && allow_same_identity_in_debug && same_user && same_group;
    if same_user && !debug_exception {
        return Err(AccountError::SameIdentity { uid });
    }
    if same_group && !debug_exception {
        return Err(AccountError::SameGroup { gid });
    }
    Ok(ExecutionAccount {
        configured: configured.to_owned(),
        name: user.name,
        uid,
        gid,
        debug_same_identity: same_user || same_group,
    })
}

/// Attach the fixed Linux child-isolation hook for an already resolved
/// execution account.
///
/// The hook uses only direct syscalls after `fork`: supplementary groups are
/// cleared, all real/effective/saved IDs are set, capability sets and ambient
/// capabilities are cleared, and `no_new_privs` is enabled. The explicit
/// debug same-identity exception skips privileged identity/group changes so
/// unprivileged black-box tests can execute, but still clears capabilities and
/// enables `no_new_privs`.
///
/// Isolation failures surface later from [`Command::spawn`]; this function
/// itself only records the hook.
pub fn isolate_command(command: &mut Command, account: &ExecutionAccount) {
    isolate_command_with_limits(command, account, IsolationLimits::default());
}

/// Attach the fixed Linux child-isolation hook with explicit hard limits.
///
/// The hook also places the direct child in a process group whose ID is its
/// PID, then installs a seccomp filter that prevents it and every descendant
/// from changing process groups, reparenting a clone to the supervisor, or
/// entering another namespace. Fork and ordinary thread creation remain
/// available; `clone3` deliberately reports `ENOSYS` so libc can fall back to
/// the filterable legacy `clone` ABI.
///
/// Isolation failures surface later from [`Command::spawn`]; this function
/// itself only records the hook.
pub fn isolate_command_with_limits(
    command: &mut Command,
    account: &ExecutionAccount,
    limits: IsolationLimits,
) {
    let uid = account.uid;
    let gid = account.gid;
    let debug_same_identity = account.debug_same_identity;
    let expected_parent_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    // SAFETY: the closure captures only integers and calls async-signal-safe
    // Linux syscalls. It performs no allocation, locking, or environment work
    // after fork. This crate is the project's intentionally isolated unsafe
    // process-launch boundary.
    unsafe {
        command.pre_exec(move || {
            child_isolate(uid, gid, debug_same_identity, expected_parent_pid, limits)
        });
    }
}

/// Observe whether an owned child has exited without reaping its process-group
/// leader.
///
/// Keeping the leader waitable until its descendants have been killed prevents
/// numeric process-group reuse between exit observation and cleanup.
///
/// # Errors
///
/// Returns an OS error when `pid` is invalid, is not a waitable child of this
/// process, or Linux `waitid(WNOWAIT)` fails.
pub fn child_has_exited(pid: u32) -> io::Result<bool> {
    let _signed_pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "child PID exceeds i32"))?;
    // `waitid` specifies that a zeroed `si_pid` denotes no waitable event for
    // WNOHANG. The initialized object remains local and the kernel receives its
    // exact writable size.
    let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: the PID is a plain positive integer, `information` is writable
    // for one complete siginfo_t, and WNOWAIT explicitly preserves child
    // waitability for the caller's later `Child::wait`.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            information.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful waitid initialized the object (and the object began
    // zeroed for the WNOHANG/no-event case). libc's accessor reads only the
    // siginfo PID field.
    let observed_pid = unsafe { information.assume_init().si_pid() };
    Ok(observed_pid != 0)
}

/// Refuse a descriptor whose inode carries a POSIX access or default ACL.
///
/// NQ's deployment checks deliberately reason about the ordinary owner,
/// group, and other mode bits. An extended ACL could grant write access that
/// those bits do not describe, so supported helper/runtime paths must not use
/// one. Filesystems that report ACL/xattr support as unavailable are accepted;
/// all other inspection errors fail closed. The xattr-name list is bounded
/// before allocation.
///
/// # Errors
///
/// Returns a permission error when a POSIX ACL is present, an invalid-data
/// error for an oversized or malformed xattr-name list, or the underlying
/// descriptor inspection error.
pub fn require_no_posix_acl(file: &File) -> io::Result<()> {
    let descriptor = file.as_raw_fd();
    // SAFETY: `flistxattr` receives a valid borrowed descriptor and either a
    // null zero-length probe or the exact writable allocation below. No
    // pointer escapes the call.
    let required = unsafe { libc::flistxattr(descriptor, std::ptr::null_mut(), 0) };
    if required < 0 {
        let error = io::Error::last_os_error();
        if xattrs_unavailable(&error) {
            return Ok(());
        }
        return Err(error);
    }
    let required = usize::try_from(required)
        .map_err(|_| io::Error::other("negative xattr-name list length"))?;
    if required > MAX_XATTR_NAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xattr-name list exceeds {MAX_XATTR_NAME_BYTES} bytes"),
        ));
    }
    if required == 0 {
        return Ok(());
    }
    let mut names = vec![0_u8; required];
    // SAFETY: `names` is writable for exactly `names.len()` bytes for the
    // duration of this call, and the descriptor remains borrowed and valid.
    let actual = unsafe {
        libc::flistxattr(
            descriptor,
            names.as_mut_ptr().cast::<libc::c_char>(),
            names.len(),
        )
    };
    if actual < 0 {
        return Err(io::Error::last_os_error());
    }
    let actual =
        usize::try_from(actual).map_err(|_| io::Error::other("negative xattr-name list length"))?;
    if actual != names.len() || names.last() != Some(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xattr-name list changed or is malformed",
        ));
    }
    if contains_posix_acl(&names) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "POSIX access/default ACL is outside the supported deployment policy",
        ));
    }
    Ok(())
}

fn xattrs_unavailable(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .is_some_and(|code| code == libc::ENOTSUP || code == libc::EOPNOTSUPP)
}

fn contains_posix_acl(names: &[u8]) -> bool {
    names
        .split(|byte| *byte == 0)
        .any(|name| name == POSIX_ACCESS_ACL || name == POSIX_DEFAULT_ACL)
}

/// Grant a watcher primary group write/traverse access to a freshly created
/// daemon-owned private runtime directory.
///
/// The resulting mode is `0730`: the daemon retains ownership and cleanup
/// custody, while the helper can bind the exact socket path but cannot list
/// the random directory. Parent runtime directories must be traverse-only for
/// non-daemon identities.
///
/// # Errors
///
/// Returns if the path is not the same regular directory throughout the
/// custody transition or ownership/mode changes fail.
pub fn prepare_runtime_directory(path: &Path, account: &ExecutionAccount) -> io::Result<()> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "helper runtime path is not a directory",
        ));
    }
    let device = before.dev();
    let inode = before.ino();
    chown(path, Some(geteuid()), Some(Gid::from_raw(account.gid))).map_err(io::Error::from)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o730))?;
    let after = fs::symlink_metadata(path)?;
    if !after.is_dir()
        || after.dev() != device
        || after.ino() != inode
        || after.uid() != geteuid().as_raw()
        || after.gid() != account.gid
        || after.mode() & 0o777 != 0o730
    {
        return Err(io::Error::other(
            "helper runtime directory changed during custody transition",
        ));
    }
    Ok(())
}

/// Reclaim a private helper directory after its supervised process is reaped
/// so descriptor-safe recursive cleanup can run as the daemon.
///
/// # Errors
///
/// Returns when ownership or permission restoration fails.
pub fn reclaim_runtime_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "helper runtime path is not a directory",
        ));
    }
    chown(path, Some(geteuid()), Some(getegid())).map_err(io::Error::from)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

/// Take exact inode custody of a helper-created Unix socket before connecting.
///
/// The socket must be helper-owned and `0600`. An `O_PATH|O_NOFOLLOW`
/// descriptor pins that inode for `fchownat(AT_EMPTY_PATH)`. No
/// pathname-following mutation occurs after the pin; a helper replacement is
/// detected by the final device/inode check without touching its target.
///
/// # Errors
///
/// Returns for a symlink, non-socket, wrong owner/mode, replacement race, or
/// failed custody syscall.
pub fn take_unix_socket_custody(
    path: &Path,
    expected_user: u32,
    expected_group: u32,
) -> io::Result<()> {
    take_unix_socket_custody_inner(path, expected_user, expected_group, || Ok(()))
}

fn take_unix_socket_custody_inner<F>(
    path: &Path,
    expected_user: u32,
    expected_group: u32,
    after_pin: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_socket()
        || before.uid() != expected_user
        || before.gid() != expected_group
        || before.mode() & 0o777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper socket lacks the required type, owner, or 0600 mode",
        ));
    }

    let descriptor = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let pinned = descriptor.metadata()?;
    if !pinned.file_type().is_socket()
        || pinned.dev() != before.dev()
        || pinned.ino() != before.ino()
        || pinned.uid() != expected_user
        || pinned.gid() != expected_group
        || pinned.mode() & 0o777 != 0o600
    {
        return Err(io::Error::other(
            "helper socket changed before custody could be pinned",
        ));
    }
    after_pin()?;
    fchownat(
        Some(descriptor.as_raw_fd()),
        Path::new(""),
        Some(geteuid()),
        Some(getegid()),
        AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;

    let after = fs::symlink_metadata(path)?;
    if !after.file_type().is_socket()
        || after.dev() != pinned.dev()
        || after.ino() != pinned.ino()
        || after.uid() != geteuid().as_raw()
        || after.gid() != getegid().as_raw()
        || after.mode() & 0o777 != 0o600
    {
        return Err(io::Error::other(
            "helper socket changed during custody transition",
        ));
    }
    Ok(())
}

fn validate_runtime_root_metadata(metadata: &fs::Metadata) -> io::Result<()> {
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.gid() != getegid().as_raw()
        || mode != RUNTIME_ROOT_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "helper runtime root must be a daemon-owned directory with exact mode 0711; observed uid={}, gid={}, mode={mode:#06o}",
                metadata.uid(),
                metadata.gid()
            ),
        ));
    }
    Ok(())
}

fn validate_runtime_root_ancestors(path: &Path) -> io::Result<()> {
    let filesystem_root = fs::symlink_metadata(Path::new("/"))?;
    let trusted_root_uid = filesystem_root.uid();
    let daemon_uid = geteuid().as_raw();
    let mut current = path.parent();
    while let Some(ancestor) = current {
        let descriptor = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(ancestor)?;
        let metadata = descriptor.metadata()?;
        let path_metadata = fs::symlink_metadata(ancestor)?;
        let mode = metadata.mode() & 0o7777;
        let trusted_owner = metadata.uid() == trusted_root_uid || metadata.uid() == daemon_uid;
        let root_owned_sticky_directory =
            metadata.uid() == trusted_root_uid && mode & libc::S_ISVTX != 0;
        if !metadata.is_dir()
            || !path_metadata.is_dir()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || !trusted_owner
            || (mode & 0o022 != 0 && !root_owned_sticky_directory)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "helper runtime ancestor {} is not root/daemon owned and protected from replacement (uid={}, mode={mode:#06o})",
                    ancestor.display(),
                    metadata.uid()
                ),
            ));
        }
        require_no_posix_acl(&descriptor)?;
        if ancestor == Path::new("/") {
            break;
        }
        current = ancestor.parent();
    }
    Ok(())
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn child_isolate(
    uid: u32,
    gid: u32,
    debug_same_identity: bool,
    expected_parent_pid: i32,
    limits: IsolationLimits,
) -> io::Result<()> {
    // Establish the process-group boundary before dropping privilege. Calling
    // setpgid(0, 0) again is harmless when Command::process_group(0) already
    // performed the same transition in its internal child setup.
    // SAFETY: zero/zero selects the calling process and its own PID.
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if !debug_same_identity {
        // SAFETY: null with a zero count is the defined setgroups form for an
        // empty supplementary-group vector.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: plain integer IDs; failure is returned directly to spawn.
        if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: plain integer IDs; failure is returned directly to spawn.
        if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    install_resource_limits(limits)?;

    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: pointers reference fixed-layout stack objects for the duration
    // of the Linux capset syscall.
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL ignores the trailing zero arguments.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS accepts the fixed value one and zero tail.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    install_containment_filter()?;
    // Credential changes clear PDEATHSIG, so install it only after every ID
    // transition and then close the death-before-prctl race explicitly.
    // SAFETY: fixed prctl operation and signal value.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getppid is async-signal-safe and takes no pointers.
    if unsafe { libc::getppid() } != expected_parent_pid {
        // SAFETY: self-directed SIGKILL cannot invoke user-space handlers and
        // prevents an orphaned helper from reaching exec.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    // SAFETY: PR_SET_DUMPABLE accepts the fixed value zero.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn install_resource_limits(limits: IsolationLimits) -> io::Result<()> {
    macro_rules! set_limit {
        ($resource:expr, $value:expr) => {{
            let value = libc::rlim_t::try_from($value).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "resource limit exceeds rlim_t")
            })?;
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            // SAFETY: `limit` is a fully initialized stack value borrowed only
            // for this syscall, and every resource selector is a fixed Linux
            // RLIMIT constant.
            if unsafe { libc::setrlimit($resource, &limit) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }};
    }

    set_limit!(libc::RLIMIT_AS, limits.address_space_bytes);
    set_limit!(libc::RLIMIT_CPU, limits.cpu_seconds);
    set_limit!(libc::RLIMIT_NPROC, limits.processes);
    set_limit!(libc::RLIMIT_NOFILE, limits.open_files);
    set_limit!(libc::RLIMIT_FSIZE, limits.file_bytes);
    set_limit!(libc::RLIMIT_CORE, 0_u64);
    Ok(())
}

const fn filter_statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn filter_jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

fn install_containment_filter() -> io::Result<()> {
    // Classic BPF instruction encodings from linux/filter.h. The program
    // validates the native audit architecture, rejects the x86-64 x32 syscall
    // namespace, and then prevents every supported process-group/namespace
    // escape or supervisor reparenting. The legacy clone flags live directly
    // in arg0; clone3's indirect argument cannot be inspected by cBPF and
    // therefore returns ENOSYS.
    const BPF_LOAD_WORD_ABSOLUTE: u16 = 0x20;
    const BPF_JUMP_EQUAL: u16 = 0x15;
    const BPF_JUMP_BITS_SET: u16 = 0x45;
    const BPF_RETURN: u16 = 0x06;
    const SECCOMP_NR_OFFSET: u32 = 0;
    const SECCOMP_ARCH_OFFSET: u32 = 4;
    const SECCOMP_ARG0_OFFSET: u32 = 16;
    let syscall_setsid = u32::try_from(libc::SYS_setsid).expect("native setsid syscall number");
    let syscall_setpgid = u32::try_from(libc::SYS_setpgid).expect("native setpgid syscall number");
    let syscall_unshare = u32::try_from(libc::SYS_unshare).expect("native unshare syscall number");
    let syscall_setns = u32::try_from(libc::SYS_setns).expect("native setns syscall number");
    let syscall_clone3 = u32::try_from(libc::SYS_clone3).expect("native clone3 syscall number");
    let syscall_clone = u32::try_from(libc::SYS_clone).expect("native clone syscall number");
    let errno_enosys = libc::ENOSYS.unsigned_abs();
    let errno_eperm = libc::EPERM.unsigned_abs();

    let mut instructions = [
        filter_statement(BPF_LOAD_WORD_ABSOLUTE, SECCOMP_ARCH_OFFSET),
        filter_jump(BPF_JUMP_EQUAL, AUDIT_ARCH_NATIVE, 1, 0),
        filter_statement(BPF_RETURN, SECCOMP_RET_KILL_PROCESS),
        filter_statement(BPF_LOAD_WORD_ABSOLUTE, SECCOMP_NR_OFFSET),
        filter_jump(BPF_JUMP_BITS_SET, X86_X32_SYSCALL_BIT, 0, 1),
        filter_statement(BPF_RETURN, SECCOMP_RET_ERRNO | errno_enosys),
        filter_jump(BPF_JUMP_EQUAL, syscall_setsid, 0, 1),
        filter_statement(BPF_RETURN, SECCOMP_RET_ERRNO | errno_eperm),
        filter_jump(BPF_JUMP_EQUAL, syscall_setpgid, 0, 1),
        filter_statement(BPF_RETURN, SECCOMP_RET_ERRNO | errno_eperm),
        filter_jump(BPF_JUMP_EQUAL, syscall_unshare, 0, 1),
        filter_statement(BPF_RETURN, SECCOMP_RET_ERRNO | errno_eperm),
        filter_jump(BPF_JUMP_EQUAL, syscall_setns, 0, 1),
        filter_statement(BPF_RETURN, SECCOMP_RET_ERRNO | errno_eperm),
        filter_jump(BPF_JUMP_EQUAL, syscall_clone3, 0, 1),
        filter_statement(BPF_RETURN, SECCOMP_RET_ERRNO | errno_enosys),
        filter_jump(BPF_JUMP_EQUAL, syscall_clone, 0, 3),
        filter_statement(BPF_LOAD_WORD_ABSOLUTE, SECCOMP_ARG0_OFFSET),
        filter_jump(BPF_JUMP_BITS_SET, FORBIDDEN_CLONE_FLAGS, 0, 1),
        filter_statement(BPF_RETURN, SECCOMP_RET_ERRNO | errno_eperm),
        filter_statement(BPF_RETURN, SECCOMP_RET_ALLOW),
    ];
    let length = u16::try_from(instructions.len()).expect("fixed seccomp program length");
    let program = libc::sock_fprog {
        len: length,
        filter: instructions.as_mut_ptr(),
    };
    // SAFETY: no_new_privs is already set. `program` and its fixed instruction
    // array remain valid for the complete prctl call and are copied by the
    // kernel before it returns.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &raw const program,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};
    use std::thread;
    use std::time::{Duration, Instant};

    const CLONE_PARENT_PROBE_ENV: &str = "NQ_TEST_CLONE_PARENT_PROBE";
    const CLONE_PARENT_SUPERVISOR_ENV: &str = "NQ_TEST_CLONE_PARENT_SUPERVISOR";

    #[test]
    fn c2_secret_interval_excludes_process_spawn_interval() {
        let secret = enter_c2_secret_process_interval().expect("enter secret interval");
        secret.verify_same_process().expect("same process");
        let (entered_tx, entered_rx) = sync_channel(0);
        let waiter = thread::spawn(move || {
            with_c2_process_spawn_fence(|| {
                entered_tx.send(()).expect("report spawn interval");
                Ok(())
            })
            .expect("enter spawn interval");
        });
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout),
            "spawn interval entered while signer secret was live"
        );
        drop(secret);
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("spawn interval enters after secret release");
        waiter.join().expect("join spawn waiter");
    }

    fn status_field<'a>(status: &'a str, name: &str) -> &'a str {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map_or_else(|| panic!("missing /proc status field {name}"), str::trim)
    }

    fn isolated_status(account: &ExecutionAccount) -> io::Result<String> {
        let mut command = Command::new("/bin/cat");
        command.arg("/proc/self/status");
        isolate_command(&mut command, account);
        let output = command.output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "isolated status child exited {:?}",
                output.status.code()
            )));
        }
        String::from_utf8(output.stdout).map_err(io::Error::other)
    }

    #[test]
    fn debug_override_is_explicit_for_the_current_non_root_account() {
        let current = geteuid().as_raw();
        if current == 0 {
            eprintln!("skipping same-identity test for root build account");
            return;
        }
        assert!(matches!(
            resolve_account(&current.to_string(), false),
            Err(AccountError::SameIdentity { .. })
        ));
        if cfg!(debug_assertions) {
            let account = resolve_account(&current.to_string(), true).expect("debug exception");
            assert!(account.debug_same_identity);
        } else {
            assert!(matches!(
                resolve_account(&current.to_string(), true),
                Err(AccountError::DebugOverrideUnavailable)
            ));
        }
    }

    #[test]
    fn root_is_always_refused() {
        assert!(matches!(
            resolve_account("0", true),
            Err(AccountError::Root { .. })
        ));
    }

    #[test]
    fn socket_symlink_swap_never_mutates_the_replacement_target() {
        let directory = tempfile::tempdir().expect("socket custody directory");
        let socket = directory.path().join("helper.sock");
        let displaced = directory.path().join("displaced.sock");
        let target = directory.path().join("unrelated-state");
        let _listener = match std::os::unix::net::UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping socket swap test: execution sandbox denies AF_UNIX bind");
                return;
            }
            Err(error) => panic!("bind test socket: {error}"),
        };
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("socket mode");
        fs::write(&target, b"operator state").expect("write unrelated target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("target mode");
        let before = fs::symlink_metadata(&target).expect("target metadata");

        let error =
            take_unix_socket_custody_inner(&socket, geteuid().as_raw(), getegid().as_raw(), || {
                fs::rename(&socket, &displaced)?;
                std::os::unix::fs::symlink(&target, &socket)
            })
            .expect_err("pathname replacement must fail closed");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::Other | io::ErrorKind::PermissionDenied
        ));

        let after = fs::symlink_metadata(&target).expect("target metadata after attack");
        assert_eq!(after.dev(), before.dev());
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
        assert_eq!(after.mode() & 0o7777, before.mode() & 0o7777);
        assert_eq!(fs::read(&target).expect("target bytes"), b"operator state");
    }

    #[test]
    fn debug_child_still_has_no_capabilities_and_no_new_privileges() {
        if !cfg!(debug_assertions) {
            return;
        }
        let current = geteuid().as_raw();
        if current == 0 {
            return;
        }
        let account = resolve_account(&current.to_string(), true).expect("debug account");
        let status = isolated_status(&account).expect("spawn isolated debug child");
        for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            assert_eq!(status_field(&status, field), "0000000000000000");
        }
        assert_eq!(status_field(&status, "NoNewPrivs:"), "1");
    }

    #[test]
    fn child_is_group_leader_with_hard_limits_and_descendants_cannot_escape() {
        if !cfg!(debug_assertions) || geteuid().is_root() {
            return;
        }
        if !Path::new("/usr/bin/setsid").is_file() {
            eprintln!("skipping process-group escape test: /usr/bin/setsid is absent");
            return;
        }
        let account = resolve_account(&geteuid().as_raw().to_string(), true)
            .expect("debug execution account");
        assert_eq!(
            IsolationLimits::default().processes,
            32,
            "the production default process ceiling must remain explicit"
        );
        let limits = IsolationLimits {
            // This test needs descendants in order to probe process-group and
            // setsid containment. It does not test the production NPROC
            // default, so leave room for the host UID's unrelated processes.
            processes: 256,
            open_files: 96,
            ..IsolationLimits::default()
        };
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "read pid comm state ppid pgrp rest < /proc/self/stat; while IFS= read -r line; do case \"$line\" in 'Max open files'*) set -- $line; nofile=$4 ;; 'Max processes'*) set -- $line; nproc=$3 ;; esac; done < /proc/self/limits; printf '%s %s %s %s\\n' \"$pid\" \"$pgrp\" \"$nofile\" \"$nproc\"; /bin/sh -c '/usr/bin/setsid /bin/true'; test $? -ne 0",
        ]);
        isolate_command_with_limits(&mut command, &account, limits);
        let output = command.output().expect("spawn contained shell");
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("Cannot fork")
        {
            eprintln!(
                "skipping process-group escape assertion: host UID already saturates RLIMIT_NPROC=256"
            );
            return;
        }
        assert!(
            output.status.success(),
            "escape probe unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let fields: Vec<_> = std::str::from_utf8(&output.stdout)
            .expect("probe output UTF-8")
            .split_ascii_whitespace()
            .collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], fields[1], "child PID must equal its PGID");
        assert_eq!(fields[2], "96", "RLIMIT_NOFILE must be installed");
        assert_eq!(fields[3], "256", "test RLIMIT_NPROC must be installed");
    }

    #[test]
    fn legacy_clone_parent_forms_are_denied_without_orphaning_waitable_children() {
        let executable = std::env::current_exe().expect("current sandbox test executable");
        let output = Command::new(executable)
            .args([
                "--exact",
                "tests::clone_parent_probe_supervisor",
                "--nocapture",
            ])
            .env(CLONE_PARENT_SUPERVISOR_ENV, "1")
            .output()
            .expect("launch isolated clone-parent probe supervisor");
        assert!(
            output.status.success(),
            "clone-parent probe supervisor failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn clone_parent_probe_supervisor() {
        if std::env::var_os(CLONE_PARENT_SUPERVISOR_ENV).is_none() {
            return;
        }

        let user_id = geteuid().as_raw();
        let primary_group_id = getegid().as_raw();
        let account = ExecutionAccount {
            configured: user_id.to_string(),
            name: "clone-parent-probe".to_owned(),
            uid: user_id,
            gid: primary_group_id,
            debug_same_identity: true,
        };
        let executable = std::env::current_exe().expect("current sandbox test executable");
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "tests::clone_parent_raw_syscall_probe",
                "--nocapture",
            ])
            .env(CLONE_PARENT_PROBE_ENV, "1");
        isolate_command(&mut command, &account);
        let output = command
            .output()
            .expect("launch contained clone-parent syscall probe");

        // A vulnerable probe creates direct children of this supervisor. Reap
        // every child class before asserting so a failed regression cannot
        // itself leak a zombie into the outer test harness.
        let mut unexpected_children = Vec::new();
        let started = Instant::now();
        loop {
            let mut status = 0;
            // SAFETY: `status` is writable for one wait status, -1 selects any
            // direct child, and __WALL includes both SIGCHLD and exit-signal-zero
            // clone children.
            let result =
                unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG | libc::__WALL) };
            if result > 0 {
                unexpected_children.push((result, status));
                continue;
            }
            if result == 0 && started.elapsed() < Duration::from_secs(1) {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                break;
            }
            panic!(
                "unexpected waitpid result while checking clone-parent custody: result={result}, error={}",
                io::Error::last_os_error()
            );
        }

        assert!(
            unexpected_children.is_empty(),
            "contained probe created direct supervisor children: {unexpected_children:?}"
        );
        assert!(
            output.status.success(),
            "contained clone-parent syscall probe failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn clone_parent_raw_syscall_probe() {
        if std::env::var_os(CLONE_PARENT_PROBE_ENV).is_none() {
            return;
        }

        let forms = [
            ("sigchld", libc::SIGCHLD.unsigned_abs()),
            ("exit-signal-zero", 0_u32),
        ];
        let mut outcomes = Vec::with_capacity(forms.len());
        for (index, (name, exit_signal)) in forms.into_iter().enumerate() {
            let flags = libc::CLONE_PARENT.unsigned_abs() | exit_signal;
            // SAFETY: this is a hostile syscall probe. Without the filter, a
            // zero return is the new child and exits immediately without
            // touching shared Rust state; the original process records the
            // returned PID. With the filter, no child is created and EPERM is
            // returned before clone interprets the null optional arguments.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::c_ulong::from(flags),
                    0_usize,
                    0_usize,
                    0_usize,
                    0_usize,
                )
            };
            if result == 0 {
                // SAFETY: `_exit` terminates only the raw clone child and runs
                // no allocation, destructors, or test-harness code.
                unsafe {
                    libc::_exit(90 + i32::try_from(index).unwrap_or(9));
                }
            }
            outcomes.push((name, result, io::Error::last_os_error().raw_os_error()));
        }

        for (name, result, error) in outcomes {
            assert_eq!(
                result, -1,
                "{name} CLONE_PARENT unexpectedly created a child"
            );
            assert_eq!(error, Some(libc::EPERM), "{name} CLONE_PARENT errno");
        }
    }

    #[test]
    fn exit_observation_preserves_waitability() {
        if !cfg!(debug_assertions) || geteuid().is_root() {
            return;
        }
        let account = resolve_account(&geteuid().as_raw().to_string(), true)
            .expect("debug execution account");
        let mut command = Command::new("/bin/true");
        isolate_command(&mut command, &account);
        let mut child = command.spawn().expect("spawn waitable child");
        let started = Instant::now();
        while !child_has_exited(child.id()).expect("observe child without reaping") {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(child_has_exited(child.id()).expect("child remains waitable"));
        assert!(child.wait().expect("reap observed child").success());
    }

    #[test]
    fn distinct_identity_clears_groups_ids_caps_and_reaps_when_permitted() {
        let account = ["nobody", "65534"]
            .into_iter()
            .find_map(|candidate| resolve_account(candidate, false).ok());
        let Some(account) = account else {
            eprintln!("skipping distinct-identity test: no non-root target account");
            return;
        };
        let status = match isolated_status(&account) {
            Ok(status) => status,
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("skipping distinct-identity test: process lacks UID/GID capabilities");
                return;
            }
            Err(error) => panic!("distinct-identity child failed: {error}"),
        };
        let uid_values: Vec<_> = status_field(&status, "Uid:")
            .split_ascii_whitespace()
            .collect();
        let gid_values: Vec<_> = status_field(&status, "Gid:")
            .split_ascii_whitespace()
            .collect();
        assert_eq!(uid_values, vec![account.uid.to_string(); 4]);
        assert_eq!(gid_values, vec![account.gid.to_string(); 4]);
        assert!(status_field(&status, "Groups:").is_empty());
        for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            assert_eq!(status_field(&status, field), "0000000000000000");
        }
        assert_eq!(status_field(&status, "NoNewPrivs:"), "1");
    }

    #[test]
    fn packaged_service_declares_only_the_required_parent_capabilities() {
        let unit = include_str!("../../../packaging/systemd/nqd.service");
        assert!(unit.contains("User=nq\nGroup=nq\n"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        let capabilities = "CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL";
        assert!(unit.contains(&format!("CapabilityBoundingSet={capabilities}")));
        assert!(unit.contains(&format!("AmbientCapabilities={capabilities}")));
        for forbidden in ["CAP_DAC_OVERRIDE", "CAP_SYS_ADMIN", "CAP_SETPCAP"] {
            assert!(!unit.contains(forbidden));
        }
        for resource in [
            "TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M",
            "LimitNOFILE=4096",
            "LimitFSIZE=1G",
            "LimitCORE=0",
            "TasksMax=256",
            "MemoryMax=2G",
            "MemorySwapMax=0",
            "CPUQuota=200%",
        ] {
            assert!(unit.contains(resource));
        }

        let sysusers = include_str!("../../../packaging/systemd/nq.sysusers");
        assert!(sysusers.contains("u nq-helper"));
        let tmpfiles = include_str!("../../../packaging/systemd/nq.tmpfiles");
        assert!(tmpfiles.contains("d /run/nq                     0751 nq   nq"));
        assert!(tmpfiles.contains("d /run/nq/helpers             0711 nq   nq"));
        for example in [
            include_str!("../../../examples/nq.toml"),
            include_str!("../../../examples/nq-host.toml"),
        ] {
            assert!(example.contains("execution_account = \"nq-helper\""));
            assert!(example.contains("working_directory = \"/usr/lib/nq/helpers\""));
            assert!(!example.contains("allow_same_identity_in_debug"));
        }

        let operations = include_str!("../../../docs/OPERATIONS.md");
        for property in [
            "--property=PrivateTmp=yes",
            "--property='TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M /var/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M'",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=RestrictNamespaces=yes",
            "--property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'",
            "--property=ReadOnlyPaths=/etc/nq",
            "--property='ReadWritePaths=/var/lib/nq /run/nq'",
            "--property=LimitNOFILE=4096",
            "--property=LimitFSIZE=1G",
            "--property=LimitCORE=0",
            "--property=TasksMax=256",
            "--property=MemoryMax=2G",
            "--property=MemorySwapMax=0",
            "--property=CPUQuota=200%",
        ] {
            assert!(operations.contains(property));
        }
        assert!(operations.contains("failure and denial-of-service domain"));
    }
}
