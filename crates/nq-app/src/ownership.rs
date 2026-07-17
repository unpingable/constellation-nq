//! Exclusive local ownership shared by daemon and maintenance workflows.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use nix::fcntl::{Flock, FlockArg};
use nix::libc;

/// Process-lifetime exclusive ownership of one nq-ng database.
pub(crate) type DatabaseOwnership = Flock<File>;

/// Acquire the nonblocking database owner lock used by `nqd` and explicit
/// schema maintenance.
pub(crate) fn acquire(database: &Path, operation: &str) -> Result<DatabaseOwnership> {
    let path = lock_path(database)?;
    let parent = path
        .parent()
        .context("database owner lock must have a parent directory")?;
    std::fs::create_dir_all(parent)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("cannot open database owner lock {}", path.display()))?;
    if !file.metadata()?.is_file() {
        return Err(anyhow!(
            "database owner lock {} is not a regular file",
            path.display()
        ));
    }
    let mut lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
        anyhow!(
            "cannot acquire exclusive database ownership for {operation} at {}: {error}",
            path.display()
        )
    })?;
    lock.set_len(0)?;
    lock.seek(SeekFrom::Start(0))?;
    writeln!(lock, "pid={} operation={operation}", std::process::id())?;
    lock.sync_data()?;
    Ok(lock)
}

fn lock_path(database: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(database)
        .with_context(|| format!("cannot identify database {}", database.display()))?;
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "database {} is not a regular file",
            canonical.display()
        ));
    }
    let mut value = OsString::from(canonical.as_os_str());
    value.push(format!(
        ".{:x}-{:x}.nqd.lock",
        metadata.dev(),
        metadata.ino()
    ));
    Ok(PathBuf::from(value))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn ownership_is_exclusive_and_released_on_drop() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        std::fs::write(&database, b"database identity").expect("database fixture");
        let first = acquire(&database, "first").expect("first owner");
        assert!(acquire(&database, "second").is_err());
        drop(first);
        drop(acquire(&database, "third").expect("lock released"));
    }

    #[test]
    fn symlink_alias_cannot_evade_database_ownership() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("nq.db");
        let alias = directory.path().join("alias.db");
        std::fs::write(&database, b"database identity").expect("database fixture");
        symlink(&database, &alias).expect("database alias");

        let _first = acquire(&database, "first").expect("first owner");
        assert!(acquire(&alias, "alias").is_err());
    }
}
