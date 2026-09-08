//! Bounded local regular-file reads. No FIFO/device opening, pathname re-open
//! interval, or atomic-content-snapshot claim. Linux procfs is required.
use anyhow::{Result, ensure};
use std::{fs::File, io::Read, path::Path};

#[cfg(target_os = "linux")]
fn capture(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let reference = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        reference.metadata()?.is_file(),
        "input must be a regular file, not a symlink, FIFO or device"
    );
    Ok(reference)
}

/// Open a readable descriptor only after capturing and checking a regular inode.
/// Callers retaining this descriptor may hash and execute that same inode; this
/// does not seal its contents or its dynamic runtime dependencies.
pub fn open_regular(path: &Path) -> Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let reference = capture(path)?;
        Ok(File::open(format!(
            "/proc/self/fd/{}",
            reference.as_raw_fd()
        ))?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        anyhow::bail!("regular descriptor custody requires Linux procfs")
    }
}

#[cfg(target_os = "linux")]
fn read_captured(reference: &File, limit: usize) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    ensure!(
        reference.metadata()?.len() <= limit as u64,
        "input exceeds byte bound"
    );
    // The still-open O_PATH descriptor owns this inode. Opening its procfs
    // reference cannot select a replacement at the caller's pathname.
    let input = File::open(format!("/proc/self/fd/{}", reference.as_raw_fd()))?;
    let bound = u64::try_from(limit)?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("input limit overflow"))?;
    let mut bytes = Vec::new();
    input.take(bound).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds byte bound");
    Ok(bytes)
}

pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        read_captured(&capture(path)?, limit)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, limit);
        anyhow::bail!("bounded input descriptor custody requires Linux procfs")
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn exact_bound_nonregular_and_pathname_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("record");
        std::fs::write(&path, b"old").unwrap();
        assert_eq!(read(&path, 3).unwrap(), b"old");
        assert!(read(&path, 2).is_err());
        let held = capture(&path).unwrap();
        std::fs::rename(&path, root.path().join("original")).unwrap();
        std::fs::write(&path, b"new").unwrap();
        assert_eq!(read_captured(&held, 3).unwrap(), b"old");
        assert_eq!(read(&path, 3).unwrap(), b"new");
        let fifo = root.path().join("fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(read(&fifo, 3).is_err());
        assert!(open_regular(&fifo).is_err());
        assert!(read(Path::new("/dev/null"), 3).is_err());
        assert!(open_regular(Path::new("/dev/null")).is_err());
        assert!(read(root.path(), 3).is_err());
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read(&link, 3).is_err());
    }
}
