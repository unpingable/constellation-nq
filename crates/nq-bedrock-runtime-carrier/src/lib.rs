//! Inert runtime carrier with exact, durable, one-use release admission.

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, Flock, FlockArg, fcntl};
use nix::unistd::Uid;
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};
use thiserror::Error;

const BINDING_SCHEMA: &str = "nq.bedrock_runtime_carrier_binding.v1";
const RELEASE_SCHEMA: &str = "nq.bedrock_runtime_release.v1";
const BINDING_DOMAIN: &[u8] = b"nq.bedrock_runtime_carrier_binding.v1\0";
const RELEASE_DOMAIN: &[u8] = b"nq.bedrock_runtime_release.v1\0";

/// Exact executable and occurrence identity held inert until release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingV1 {
    /// Closed contract name.
    pub schema: String,
    /// Fresh durable NQ occurrence identity.
    pub occurrence_id: String,
    /// Coordination domain whose fence must precede release.
    pub coordination_domain_id: String,
    /// Exact mechanics identity qualified for this occurrence.
    pub mechanics_digest: Sha256Digest,
    /// Exact runtime recheck evidence identity.
    pub runtime_recheck_digest: Sha256Digest,
    /// Exact durable claim/fence identity.
    pub claim_id: Sha256Digest,
    /// Digest of the fixed executable admitted by the carrier.
    pub executable_digest: Sha256Digest,
    /// Exact argument vector; no shell is involved.
    pub arguments: Vec<String>,
}

/// Exact one-use signal for one binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReleaseV1 {
    /// Closed contract name.
    pub schema: String,
    /// Domain-separated identity of the exact binding.
    pub binding_id: Sha256Digest,
    /// Repeated occurrence identity.
    pub occurrence_id: String,
    /// Repeated coordination-domain identity.
    pub coordination_domain_id: String,
    /// Repeated mechanics identity.
    pub mechanics_digest: Sha256Digest,
    /// Repeated runtime recheck identity.
    pub runtime_recheck_digest: Sha256Digest,
    /// Repeated durable claim/fence identity.
    pub claim_id: Sha256Digest,
    /// Fresh one-use nonce.
    pub release_nonce: String,
}

/// Durable carrier decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseDecision {
    /// This process durably admitted and invoked the exact executable once.
    Invoked {
        /// Exact release identity.
        release_id: Sha256Digest,
        /// Process exit status, when representable.
        exit_code: Option<i32>,
    },
    /// A completed release was observed on restart; it was not invoked again.
    AlreadyComplete {
        /// Exact release identity.
        release_id: Sha256Digest,
        /// Retained process exit status, when representable.
        exit_code: Option<i32>,
    },
    /// A durable claim lacks a known outcome; it was not invoked again.
    OutcomeUnknown {
        /// Exact release identity requiring explicit reconciliation.
        release_id: Sha256Digest,
    },
    /// The exact release currently has a live invocation lock.
    InFlight {
        /// Exact release identity that must not yet be reconciled.
        release_id: Sha256Digest,
    },
}

/// Closed carrier failure.
#[derive(Debug, Error)]
pub enum CarrierError {
    /// A filesystem operation failed.
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON was malformed or outside the closed model.
    #[error("release input is not exact canonical JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Canonical serialization failed.
    #[error("canonical serialization failed: {0}")]
    Canonical(#[from] nq_protocol::CanonicalizationError),
    /// Durable state failed.
    #[error("durable release state failed: {0}")]
    Store(#[from] rusqlite::Error),
    /// Contract identity or field validation failed.
    #[error("release refused: {0}")]
    Refused(String),
}

/// Runs the exact executable without a shell.
pub trait Runner {
    /// Invoke the executable with the exact argument vector.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the process cannot be started or waited for.
    fn run(
        &mut self,
        executable: &File,
        invocation_fence: &File,
        arguments: &[String],
    ) -> std::io::Result<ExitStatus>;
}

/// Production process runner.
pub struct ProcessRunner;
impl Runner for ProcessRunner {
    fn run(
        &mut self,
        executable: &File,
        invocation_fence: &File,
        arguments: &[String],
    ) -> std::io::Result<ExitStatus> {
        let anchored = format!("/proc/self/fd/{}", executable.as_raw_fd());
        fcntl(
            invocation_fence.as_raw_fd(),
            FcntlArg::F_SETFD(FdFlag::empty()),
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
        let result = Command::new(anchored).args(arguments).status();
        let restore = fcntl(
            invocation_fence.as_raw_fd(),
            FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
        );
        restore.map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
        result
    }
}

/// Waits inertly for a release file. A timeout returns without invocation.
///
/// # Errors
///
/// Returns a closed carrier failure for any invalid input or state operation.
pub fn hold_until_release<R: Runner>(
    binding_path: &Path,
    release_path: &Path,
    state_path: &Path,
    executable: &Path,
    max_wait: Option<Duration>,
    runner: &mut R,
) -> Result<Option<ReleaseDecision>, CarrierError> {
    let started = Instant::now();
    loop {
        if release_path.try_exists()? {
            return try_release(binding_path, release_path, state_path, executable, runner)
                .map(Some);
        }
        if max_wait.is_some_and(|limit| started.elapsed() >= limit) {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Validates and durably consumes one exact release before invoking anything.
///
/// # Errors
///
/// Returns a closed carrier failure before invocation for any invalid binding.
pub fn try_release<R: Runner>(
    binding_path: &Path,
    release_path: &Path,
    state_path: &Path,
    executable: &Path,
    runner: &mut R,
) -> Result<ReleaseDecision, CarrierError> {
    let binding: RuntimeBindingV1 = read_canonical(binding_path)?;
    let release: RuntimeReleaseV1 = read_canonical(release_path)?;
    validate_binding(&binding)?;
    validate_release(&binding, &release)?;
    let bound_executable = open_bound_executable(executable)?;
    if sha256_open_file(&bound_executable)? != binding.executable_digest {
        return Err(CarrierError::Refused(
            "executable digest differs from binding".into(),
        ));
    }
    let release_id = domain_digest(RELEASE_DOMAIN, &release)?;
    let store = open_state(state_path)?;
    store.connection.execute_batch("BEGIN IMMEDIATE")?;
    let existing: Option<(String, String, Option<i32>, i64, i64)> = store.connection.query_row(
        "SELECT release_id,state,exit_code,lock_dev,lock_ino FROM consumed WHERE occurrence_id=?1",
        [&binding.occurrence_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?;
    if let Some((existing_id, state, exit_code, lock_dev, lock_ino)) = existing {
        store.connection.execute_batch("COMMIT")?;
        if existing_id != release_id.as_str() {
            return Err(CarrierError::Refused(
                "occurrence already consumed by a different release".into(),
            ));
        }
        if state == "complete" {
            return Ok(ReleaseDecision::AlreadyComplete {
                release_id,
                exit_code,
            });
        }
        let expected = (
            u64::try_from(lock_dev)
                .map_err(|_| CarrierError::Refused("negative lock device".into()))?,
            u64::try_from(lock_ino)
                .map_err(|_| CarrierError::Refused("negative lock inode".into()))?,
        );
        return if store
            .invocation_lock(&release_id, Some(expected))?
            .is_none()
        {
            Ok(ReleaseDecision::InFlight { release_id })
        } else {
            Ok(ReleaseDecision::OutcomeUnknown { release_id })
        };
    }
    let Some((invocation_lock, lock_dev, lock_ino)) = store.invocation_lock(&release_id, None)?
    else {
        store.connection.execute_batch("ROLLBACK")?;
        return Ok(ReleaseDecision::InFlight { release_id });
    };
    let lock_dev = i64::try_from(lock_dev)
        .map_err(|_| CarrierError::Refused("lock device exceeds SQLite integer".into()))?;
    let lock_ino = i64::try_from(lock_ino)
        .map_err(|_| CarrierError::Refused("lock inode exceeds SQLite integer".into()))?;
    store.connection.execute(
        "INSERT INTO consumed(occurrence_id,release_id,binding_id,state,lock_dev,lock_ino) VALUES (?1,?2,?3,'claimed',?4,?5)",
        params![binding.occurrence_id, release_id.as_str(), release.binding_id.as_str(), lock_dev, lock_ino],
    )?;
    store.connection.execute_batch("COMMIT")?;
    let invocation_fence = invocation_lock;
    let Ok(status) = runner.run(&bound_executable, &invocation_fence, &binding.arguments) else {
        return Ok(ReleaseDecision::OutcomeUnknown { release_id });
    };
    let updated = store.connection.execute(
        "UPDATE consumed SET state='complete',exit_code=?2 WHERE release_id=?1 AND state='claimed'",
        params![release_id.as_str(), status.code()],
    )?;
    if updated != 1 {
        return Err(CarrierError::Refused(
            "completion transition did not update exactly one claimed release".into(),
        ));
    }
    Ok(ReleaseDecision::Invoked {
        release_id,
        exit_code: status.code(),
    })
}

type RetainedOutcomeRow = (String, Option<i32>, Option<String>, i64, i64);

/// Resolves one durable unknown outcome without re-invoking the executable.
///
/// # Errors
///
/// Refuses missing, already-differently-resolved, or unsafe durable state.
pub fn reconcile_unknown(
    state_path: &Path,
    release_id: &Sha256Digest,
    exit_code: Option<i32>,
    outcome_evidence_digest: &Sha256Digest,
) -> Result<ReleaseDecision, CarrierError> {
    let store = open_state(state_path)?;
    store.connection.execute_batch("BEGIN IMMEDIATE")?;
    let existing: Option<RetainedOutcomeRow> = store.connection.query_row(
        "SELECT state,exit_code,outcome_evidence_digest,lock_dev,lock_ino FROM consumed WHERE release_id=?1",
        [release_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?;
    let Some((state, retained_exit, retained_evidence, lock_dev, lock_ino)) = existing else {
        store.connection.execute_batch("ROLLBACK")?;
        return Err(CarrierError::Refused("release identity is absent".into()));
    };
    if state == "complete" {
        store.connection.execute_batch("COMMIT")?;
        if retained_exit == exit_code
            && retained_evidence.as_deref() == Some(outcome_evidence_digest.as_str())
        {
            return Ok(ReleaseDecision::AlreadyComplete {
                release_id: release_id.clone(),
                exit_code,
            });
        }
        return Err(CarrierError::Refused(
            "release already has a different retained outcome".into(),
        ));
    }
    let expected = (
        u64::try_from(lock_dev)
            .map_err(|_| CarrierError::Refused("negative lock device".into()))?,
        u64::try_from(lock_ino).map_err(|_| CarrierError::Refused("negative lock inode".into()))?,
    );
    let Some((_invocation_lock, _, _)) = store.invocation_lock(release_id, Some(expected))? else {
        store.connection.execute_batch("ROLLBACK")?;
        return Err(CarrierError::Refused(
            "release still has a live invocation".into(),
        ));
    };
    let updated = store.connection.execute(
        "UPDATE consumed SET state='complete',exit_code=?2,outcome_evidence_digest=?3 WHERE release_id=?1 AND state='claimed'",
        params![release_id.as_str(), exit_code, outcome_evidence_digest.as_str()],
    )?;
    if updated != 1 {
        store.connection.execute_batch("ROLLBACK")?;
        return Err(CarrierError::Refused(
            "reconciliation did not update exactly one claimed release".into(),
        ));
    }
    store.connection.execute_batch("COMMIT")?;
    Ok(ReleaseDecision::AlreadyComplete {
        release_id: release_id.clone(),
        exit_code,
    })
}

struct StateStore {
    connection: Connection,
    anchored_directory: PathBuf,
    _directory: File,
}

impl StateStore {
    fn invocation_lock(
        &self,
        release_id: &Sha256Digest,
        expected_identity: Option<(u64, u64)>,
    ) -> Result<Option<(Flock<File>, u64, u64)>, CarrierError> {
        let name = format!(
            "{}.invocation.lock",
            release_id.as_str().trim_start_matches("sha256:")
        );
        let path = self.anchored_directory.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || expected_identity
                .is_some_and(|identity| identity != (metadata.dev(), metadata.ino()))
        {
            return Err(CarrierError::Refused(
                "invocation lock identity or permissions differ".into(),
            ));
        }
        let dev = metadata.dev();
        let ino = metadata.ino();
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => Ok(Some((lock, dev, ino))),
            Err((_, error)) if error == Errno::EWOULDBLOCK => Ok(None),
            Err((_, error)) => Err(CarrierError::Refused(format!(
                "cannot acquire invocation lock: {error}"
            ))),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn open_state(path: &Path) -> Result<StateStore, CarrierError> {
    if !path.is_absolute() {
        return Err(CarrierError::Refused("state path must be absolute".into()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| CarrierError::Refused("state path has no parent".into()))?;
    let filename = match path.components().next_back() {
        Some(Component::Normal(name)) if name != OsStr::new("") => name,
        _ => return Err(CarrierError::Refused("state filename is not exact".into())),
    };
    let before = fs::symlink_metadata(parent)?;
    if before.file_type().is_symlink()
        || !before.is_dir()
        || before.uid() != Uid::effective().as_raw()
        || before.permissions().mode() & 0o077 != 0
        || fs::canonicalize(parent)? != parent
    {
        return Err(CarrierError::Refused(
            "state parent is not an exact private owned directory".into(),
        ));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    let opened = directory.metadata()?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(CarrierError::Refused(
            "state parent changed while opening".into(),
        ));
    }
    let anchored = PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        directory.as_raw_fd(),
        filename.to_string_lossy()
    ));
    let existed = fs::symlink_metadata(&anchored).ok();
    if existed.as_ref().is_some_and(|metadata| {
        metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
    }) {
        return Err(CarrierError::Refused(
            "state file is not an exact private owned regular file".into(),
        ));
    }
    let state_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&anchored)?;
    let state_metadata = state_file.metadata()?;
    if !state_metadata.is_file()
        || state_metadata.uid() != Uid::effective().as_raw()
        || state_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CarrierError::Refused(
            "state file permission boundary changed".into(),
        ));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let after_parent = fs::symlink_metadata(parent)?;
    let after_state = fs::symlink_metadata(path)?;
    if after_parent.dev() != opened.dev()
        || after_parent.ino() != opened.ino()
        || after_state.dev() != state_metadata.dev()
        || after_state.ino() != state_metadata.ino()
    {
        return Err(CarrierError::Refused(
            "state pathname changed while SQLite opened".into(),
        ));
    }
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
         CREATE TABLE IF NOT EXISTS consumed(
           occurrence_id TEXT PRIMARY KEY,
           release_id TEXT NOT NULL UNIQUE,
           binding_id TEXT NOT NULL,
           state TEXT NOT NULL CHECK(state IN ('claimed','complete')),
           exit_code INTEGER,
           outcome_evidence_digest TEXT,
           lock_dev INTEGER NOT NULL,
           lock_ino INTEGER NOT NULL);",
    )?;
    Ok(StateStore {
        connection,
        anchored_directory: anchored
            .parent()
            .expect("anchored state has parent")
            .to_path_buf(),
        _directory: directory,
    })
}

fn read_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    path: &Path,
) -> Result<T, CarrierError> {
    let bytes = fs::read(path)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err(CarrierError::Refused(
            "input bytes are not exact RFC 8785 JSON".into(),
        ));
    }
    Ok(value)
}

fn validate_binding(binding: &RuntimeBindingV1) -> Result<(), CarrierError> {
    if binding.schema != BINDING_SCHEMA
        || binding.occurrence_id.is_empty()
        || binding.coordination_domain_id.is_empty()
    {
        return Err(CarrierError::Refused(
            "invalid binding schema or empty identity".into(),
        ));
    }
    if binding.arguments.is_empty()
        || binding
            .arguments
            .iter()
            .any(|argument| argument.contains('\0'))
    {
        return Err(CarrierError::Refused(
            "argument vector is empty or contains NUL".into(),
        ));
    }
    Ok(())
}

fn validate_release(
    binding: &RuntimeBindingV1,
    release: &RuntimeReleaseV1,
) -> Result<(), CarrierError> {
    if release.schema != RELEASE_SCHEMA || release.release_nonce.is_empty() {
        return Err(CarrierError::Refused(
            "invalid release schema or empty nonce".into(),
        ));
    }
    if release.binding_id != domain_digest(BINDING_DOMAIN, binding)?
        || release.occurrence_id != binding.occurrence_id
        || release.coordination_domain_id != binding.coordination_domain_id
        || release.mechanics_digest != binding.mechanics_digest
        || release.runtime_recheck_digest != binding.runtime_recheck_digest
        || release.claim_id != binding.claim_id
    {
        return Err(CarrierError::Refused(
            "release does not exactly bind the held runtime".into(),
        ));
    }
    Ok(())
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Sha256Digest, CarrierError> {
    let canonical = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&canonical);
    Ok(sha256_bytes(&preimage))
}

fn open_bound_executable(path: &Path) -> Result<File, CarrierError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.permissions().mode() & 0o111 == 0
        || before.permissions().mode() & 0o022 != 0
    {
        return Err(CarrierError::Refused(
            "executable is not an exact nonwritable regular file".into(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.size() != before.size()
        || opened.mtime() != before.mtime()
        || opened.mtime_nsec() != before.mtime_nsec()
    {
        return Err(CarrierError::Refused(
            "executable changed while being opened".into(),
        ));
    }
    Ok(file)
}

fn sha256_open_file(file: &File) -> Result<Sha256Digest, CarrierError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8_192];
    let mut offset = 0_u64;
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset += u64::try_from(read).expect("buffer length fits u64");
    }
    Ok(
        Sha256Digest::parse(format!("sha256:{:x}", hasher.finalize()))
            .expect("SHA-256 formatting is valid"),
    )
}

#[cfg(test)]
mod tests;
