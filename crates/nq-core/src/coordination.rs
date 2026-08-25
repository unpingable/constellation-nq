//! Cross-process serialization for one watcher instance.
//!
//! `SQLite` serializes individual commits, but a collection and an admission
//! transition span helper execution, durable history, and active-lock
//! materialization.  Those operations need a wider, per-instance critical
//! section shared by `nqd` and every `nq` process.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Process-scoped exclusive ownership of one instance's collection/binding
/// lifecycle. The lock is released when this value is dropped.
#[derive(Debug)]
pub struct InstanceGuard {
    _lock: Flock<File>,
    path: PathBuf,
}

/// Process-scoped serialization for one deployment-declared recurrence
/// coordination domain. The clear-text domain is never used as a path.
#[derive(Debug)]
pub struct CoordinationDomainGuard {
    _lock: Flock<File>,
    path: PathBuf,
}

/// Failure to establish the per-instance critical section.
#[derive(Debug, Error)]
pub enum CoordinationError {
    /// Instance identifiers are also filenames and must retain the configured
    /// lexical constraints at this lower trust boundary.
    #[error("invalid instance identifier for coordination: {0}")]
    InvalidInstance(String),
    /// Filesystem setup or lock acquisition failed.
    #[error("instance coordination at {path}: {source}")]
    Io {
        /// Coordination artifact.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The kernel rejected advisory-lock acquisition.
    #[error("cannot acquire instance coordination lock {path}: {message}")]
    Lock {
        /// Coordination lock path.
        path: PathBuf,
        /// Kernel diagnostic.
        message: String,
    },
}

impl InstanceGuard {
    /// Block until this process exclusively owns the instance lifecycle.
    ///
    /// The lock directory is derived from the database path, so even two
    /// processes holding different or drifting admission-directory intent
    /// still serialize operations over the same durable store.
    ///
    /// # Errors
    ///
    /// Returns when the identifier is unsafe, the private lock directory
    /// cannot be prepared, or the kernel lock cannot be acquired.
    pub fn acquire(
        database_path: &Path,
        instance_id: &str,
        operation: &str,
    ) -> Result<Self, CoordinationError> {
        if !valid_instance_id(instance_id) {
            return Err(CoordinationError::InvalidInstance(instance_id.to_owned()));
        }
        let directory = lock_directory(database_path)?;
        let directory_file = ensure_private_directory(&directory)?;
        let path = directory.join(format!("{instance_id}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        drop(directory_file);
        if !file
            .metadata()
            .map_err(|source| io_error(&path, source))?
            .is_file()
        {
            return Err(CoordinationError::Io {
                path,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "coordination artifact is not a regular file",
                ),
            });
        }
        let mut lock = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, error)| {
            CoordinationError::Lock {
                path: path.clone(),
                message: error.to_string(),
            }
        })?;
        lock.set_len(0).map_err(|source| io_error(&path, source))?;
        lock.seek(SeekFrom::Start(0))
            .map_err(|source| io_error(&path, source))?;
        writeln!(
            lock,
            "pid={} operation={}",
            std::process::id(),
            sanitize_operation(operation)
        )
        .and_then(|()| lock.sync_data())
        .map_err(|source| io_error(&path, source))?;
        Ok(Self { _lock: lock, path })
    }

    /// Filesystem path carrying this process's kernel lock.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl CoordinationDomainGuard {
    /// Block until this process owns the local worker boundary for the exact
    /// deployment-declared coordination domain. Durable fencing in `nq-store`
    /// remains authoritative across crashes; this guard only closes the race
    /// between concurrent local tick evaluators.
    ///
    /// # Errors
    ///
    /// Refuses an invalid domain identity, an unsafe coordination directory or
    /// lock file, or any failure to acquire and persist the local kernel lock.
    pub fn acquire(
        database_path: &Path,
        domain_id: &str,
        operation: &str,
    ) -> Result<Self, CoordinationError> {
        if domain_id.is_empty() || domain_id.len() > 1024 || domain_id.chars().any(char::is_control)
        {
            return Err(CoordinationError::InvalidInstance(domain_id.to_owned()));
        }
        let key = format!(
            "domain-{}",
            hex::encode(Sha256::digest(domain_id.as_bytes()))
        );
        let directory = lock_directory(database_path)?;
        let directory_file = ensure_private_directory(&directory)?;
        let path = directory.join(format!("{key}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        drop(directory_file);
        if !file
            .metadata()
            .map_err(|source| io_error(&path, source))?
            .is_file()
        {
            return Err(CoordinationError::Io {
                path,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "coordination artifact is not a regular file",
                ),
            });
        }
        let mut lock = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, error)| {
            CoordinationError::Lock {
                path: path.clone(),
                message: error.to_string(),
            }
        })?;
        lock.set_len(0).map_err(|source| io_error(&path, source))?;
        lock.seek(SeekFrom::Start(0))
            .map_err(|source| io_error(&path, source))?;
        writeln!(
            lock,
            "pid={} domain_digest={} operation={}",
            std::process::id(),
            key,
            sanitize_operation(operation)
        )
        .and_then(|()| lock.sync_data())
        .map_err(|source| io_error(&path, source))?;
        Ok(Self { _lock: lock, path })
    }

    /// Filesystem path carrying this process's kernel lock.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn valid_instance_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn lock_directory(database_path: &Path) -> Result<PathBuf, CoordinationError> {
    let canonical =
        std::fs::canonicalize(database_path).map_err(|source| io_error(database_path, source))?;
    let metadata = std::fs::metadata(&canonical).map_err(|source| io_error(&canonical, source))?;
    if !metadata.is_file() {
        return Err(CoordinationError::Io {
            path: canonical,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "coordination database is not a regular file",
            ),
        });
    }
    let mut value = OsString::from(canonical.as_os_str());
    value.push(format!(
        ".{:x}-{:x}.instance-locks",
        metadata.dev(),
        metadata.ino()
    ));
    Ok(PathBuf::from(value))
}

fn ensure_private_directory(path: &Path) -> Result<File, CoordinationError> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(io_error(path, source)),
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoordinationError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "coordination directory is not a real directory",
            ),
        });
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(path, source))?;
    Ok(directory)
}

fn sanitize_operation(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}

fn io_error(path: &Path, source: std::io::Error) -> CoordinationError {
    CoordinationError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    const CHILD_ENV: &str = "NQ_COORDINATION_LOCK_CHILD";
    const CHILD_DATABASE_ENV: &str = "NQ_COORDINATION_LOCK_DATABASE";
    const CHILD_DOMAIN_ENV: &str = "NQ_COORDINATION_LOCK_DOMAIN";

    // This is a deliberately ordinary test (rather than ignored) so a parent
    // test can re-exec the test binary and select it by exact name. In the
    // normal harness it is a no-op.
    #[test]
    fn cross_process_lock_holder() {
        let Ok(root) = std::env::var(CHILD_ENV) else {
            return;
        };
        let root = PathBuf::from(root);
        let database =
            std::env::var(CHILD_DATABASE_ENV).map_or_else(|_| root.join("nq.db"), PathBuf::from);
        let _guard = InstanceGuard::acquire(&database, "shared", "child").expect("child lock");
        std::fs::write(root.join("child-ready"), b"ready").expect("ready marker");
        thread::sleep(Duration::from_millis(500));
    }

    #[test]
    fn cross_process_domain_lock_holder() {
        let Ok(root) = std::env::var(CHILD_DOMAIN_ENV) else {
            return;
        };
        let root = PathBuf::from(root);
        let database = root.join("nq.db");
        let _guard =
            CoordinationDomainGuard::acquire(&database, "shared:provider/domain", "child-domain")
                .expect("child domain lock");
        std::fs::write(root.join("domain-child-ready"), b"ready").expect("ready marker");
        thread::sleep(Duration::from_millis(500));
    }

    #[test]
    fn serializes_two_processes_for_the_same_instance() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        let alias = directory.path().join("database-alias.db");
        std::fs::write(&database, b"database identity").expect("database fixture");
        symlink(&database, &alias).expect("database alias");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("coordination::tests::cross_process_lock_holder")
            .arg("--nocapture")
            .env(CHILD_ENV, directory.path())
            .env(CHILD_DATABASE_ENV, &alias)
            .spawn()
            .expect("spawn child test process");
        let ready = directory.path().join("child-ready");
        let wait_started = Instant::now();
        while !ready.exists() && wait_started.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "child never acquired coordination lock");

        let started = Instant::now();
        let _guard =
            InstanceGuard::acquire(&database, "shared", "parent").expect("parent after alias");
        assert!(
            started.elapsed() >= Duration::from_millis(350),
            "parent entered the instance critical section before child exit"
        );
        assert!(child.wait().expect("child status").success());
    }

    #[test]
    fn different_instances_do_not_block_each_other() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        std::fs::write(&database, b"database identity").expect("database fixture");
        let _first = InstanceGuard::acquire(&database, "first", "test").expect("first");
        let started = Instant::now();
        let _second = InstanceGuard::acquire(&database, "second", "test").expect("second");
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn coordination_domains_are_explicit_and_path_safe() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        std::fs::write(&database, b"database identity").expect("database fixture");
        let first =
            CoordinationDomainGuard::acquire(&database, "linode:labelwatch-host/provider", "tick")
                .expect("domain guard");
        assert!(first.path().file_name().is_some_and(|name| {
            name.to_string_lossy().starts_with("domain-")
                && !name.to_string_lossy().contains("labelwatch")
        }));
        let _independent =
            CoordinationDomainGuard::acquire(&database, "linode:another-host/provider", "tick")
                .expect("independent domain");
    }

    #[test]
    fn serializes_two_processes_for_the_same_coordination_domain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        std::fs::write(&database, b"database identity").expect("database fixture");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("coordination::tests::cross_process_domain_lock_holder")
            .arg("--nocapture")
            .env(CHILD_DOMAIN_ENV, directory.path())
            .spawn()
            .expect("spawn child test process");
        let ready = directory.path().join("domain-child-ready");
        let wait_started = Instant::now();
        while !ready.exists() && wait_started.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "child never acquired domain lock");
        let started = Instant::now();
        let _guard =
            CoordinationDomainGuard::acquire(&database, "shared:provider/domain", "parent-domain")
                .expect("parent domain lock");
        assert!(started.elapsed() >= Duration::from_millis(350));
        assert!(child.wait().expect("child status").success());
    }

    #[test]
    fn refuses_a_symlinked_coordination_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        std::fs::write(&database, b"database identity").expect("database fixture");
        let lock_directory = lock_directory(&database).expect("derived lock directory");
        let redirect = directory.path().join("redirect");
        std::fs::create_dir(&redirect).expect("redirect directory");
        symlink(&redirect, &lock_directory).expect("hostile coordination symlink");
        assert!(matches!(
            InstanceGuard::acquire(&database, "fixture", "test"),
            Err(CoordinationError::Io { .. })
        ));
    }
}
