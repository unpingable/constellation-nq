//! Trusted identity of the running evaluator executable.
//!
//! The identity of the process that judges evidence is neither configuration nor
//! a helper claim: it is a kernel-observed fact about the executing artifact.
//!
//! This module is the *only* place an [`EvaluatorRuntimeIdentity`] can come into
//! being. In production it is produced solely by the platform provider
//! (`resolve`) reached through `resolved`; there is no public constructor, no
//! public field, no public provider trait a caller could implement, and no
//! public injection point. A production caller therefore cannot manufacture a
//! "trusted" identity — the door is locked and there is no key-cutting machine
//! beside it. Test fixtures exist only under `#[cfg(test)]`.

use std::fs::File;
use std::io::{self, Read};
use std::sync::LazyLock;

use nq_protocol::Sha256Digest;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Compile-time build target triple, emitted by `build.rs`. This is the target
/// the evaluator was actually built for, not a runtime `uname` reconstruction.
const TARGET_TRIPLE: &str = env!("NQ_TARGET");

/// Versioned identifier of the identity-observation method. Bump it when the
/// mechanism changes so a persisted method string is never silently
/// reinterpreted as a different observation.
const LINUX_METHOD: &str = "linux-proc-self-exe-fd-sha256-v1";

/// Source of `platform_runtime_version`: the Linux kernel release string
/// (`uname -r` equivalent). This is deliberately one precise fact — the kernel
/// release — not a blend of kernel, provider, and libc versions.
#[cfg(target_os = "linux")]
const KERNEL_RELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

/// Sealed, trusted identity of the running evaluator.
///
/// Constructible only within this module: in production by the platform provider
/// below, in tests by the `#[cfg(test)]` fixture. Fields are private and there is
/// no public constructor. Deliberately **not** `Deserialize`: a trusted runtime
/// fact must not be reconstitutable from arbitrary bytes — persisted admission
/// context uses the store's own record types, never this.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorRuntimeIdentity {
    artifact_digest: Sha256Digest,
    target_triple: String,
    artifact_identity_method: String,
    platform_runtime_version: String,
}

impl EvaluatorRuntimeIdentity {
    /// SHA-256 of the exact running executable bytes.
    #[must_use]
    pub fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    /// Compile-time build target triple.
    #[must_use]
    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    /// Versioned identifier of how the artifact digest was observed.
    #[must_use]
    pub fn artifact_identity_method(&self) -> &str {
        &self.artifact_identity_method
    }

    /// Platform runtime version (on Linux, the kernel release string).
    #[must_use]
    pub fn platform_runtime_version(&self) -> &str {
        &self.platform_runtime_version
    }

    /// Test-only fixture identity. Never compiled into a shipping binary, so a
    /// production path cannot reach it.
    #[cfg(test)]
    pub(crate) fn for_test(artifact_digest: Sha256Digest) -> Self {
        Self {
            artifact_digest,
            target_triple: TARGET_TRIPLE.to_owned(),
            artifact_identity_method: "test-fixture-v1".to_owned(),
            platform_runtime_version: "test".to_owned(),
        }
    }
}

/// A structured refusal to establish evaluator identity. There is no fabricated
/// value and no fallback: an unresolved identity becomes an admission refusal.
#[derive(Debug, Error)]
pub enum EvaluatorIdentityError {
    /// The running executable could not be opened or `fstat`ed.
    #[error("cannot open the running executable: {0}")]
    Open(io::Error),
    /// The opened running executable is not a regular file.
    #[error("the running executable is not a regular file")]
    NotRegularFile,
    /// The running executable could not be read for hashing.
    #[error("cannot read the running executable: {0}")]
    Read(io::Error),
    /// The platform runtime version could not be read.
    #[error("cannot read the platform runtime version: {0}")]
    PlatformRuntimeVersion(io::Error),
    /// The platform has no trusted evaluator-identity provider.
    #[error("evaluator identity is unsupported on this platform ({0}); admission is refused")]
    UnsupportedPlatform(&'static str),
}

/// Process-wide cached identity of the running evaluator. Resolved once — open
/// the artifact, hash through the descriptor — and reused by every engine.
static RESOLVED: LazyLock<Result<EvaluatorRuntimeIdentity, String>> =
    LazyLock::new(|| resolve().map_err(|error| error.to_string()));

/// The process-cached resolution. Production `CollectionEngine::open` calls
/// exactly this; there is no other entry point into evaluator identity.
pub(crate) fn resolved() -> Result<EvaluatorRuntimeIdentity, String> {
    RESOLVED.clone()
}

/// Hash the bytes of an already-opened file through its descriptor.
///
/// The caller holds the descriptor to the running artifact; this never re-opens
/// a pathname, so a concurrent rename, replacement, or deletion of the on-disk
/// path cannot redirect the hash to different bytes.
fn hash_open_file(mut file: &File) -> Result<Sha256Digest, io::Error> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    Ok(Sha256Digest::parse(digest).expect("sha256 hex is a valid digest"))
}

/// The Linux provider: identify the running artifact through `/proc/self/exe`.
#[cfg(target_os = "linux")]
fn resolve() -> Result<EvaluatorRuntimeIdentity, EvaluatorIdentityError> {
    // Rust's `File::open` sets `O_CLOEXEC`. The `/proc/self/exe` magic symlink
    // resolves to the running inode even when the on-disk path was replaced or
    // deleted ("(deleted)"), so this descriptor identifies the exact executing
    // artifact. `fstat` and the hash both go through this one descriptor.
    let file = File::open("/proc/self/exe").map_err(EvaluatorIdentityError::Open)?;
    let metadata = file.metadata().map_err(EvaluatorIdentityError::Open)?;
    if !metadata.is_file() {
        return Err(EvaluatorIdentityError::NotRegularFile);
    }
    let artifact_digest = hash_open_file(&file).map_err(EvaluatorIdentityError::Read)?;
    let platform_runtime_version = std::fs::read_to_string(KERNEL_RELEASE_PATH)
        .map_err(EvaluatorIdentityError::PlatformRuntimeVersion)?
        .trim()
        .to_owned();
    Ok(EvaluatorRuntimeIdentity {
        artifact_digest,
        target_triple: TARGET_TRIPLE.to_owned(),
        artifact_identity_method: LINUX_METHOD.to_owned(),
        platform_runtime_version,
    })
}

/// Unsupported platforms refuse rather than fall back to `current_exe()`,
/// pathname hashing, package metadata, or an "unknown" sentinel.
#[cfg(not(target_os = "linux"))]
fn resolve() -> Result<EvaluatorRuntimeIdentity, EvaluatorIdentityError> {
    Err(EvaluatorIdentityError::UnsupportedPlatform(
        std::env::consts::OS,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn linux_provider_identifies_the_running_artifact() {
        // On the (Linux) test host the real provider must succeed and stamp the
        // versioned method id, a sha256 digest, and the compile-time triple.
        let identity = resolve().expect("linux provider resolves");
        assert_eq!(identity.artifact_identity_method(), LINUX_METHOD);
        assert!(identity.artifact_digest().as_str().starts_with("sha256:"));
        assert_eq!(identity.target_triple(), TARGET_TRIPLE);
        assert!(!identity.platform_runtime_version().is_empty());
    }

    #[test]
    fn hashing_through_the_descriptor_survives_path_replacement() {
        // Open a file, then rename and replace the path before hashing. Hashing
        // through the held descriptor must still return the original bytes'
        // digest, proving identity follows the descriptor, not the pathname.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("artifact");
        let moved = dir.path().join("artifact.moved");
        std::fs::write(&path, b"original running bytes").expect("write artifact");

        let file = File::open(&path).expect("open artifact");
        std::fs::rename(&path, &moved).expect("rename out from under the descriptor");
        std::fs::write(&path, b"different impostor bytes").expect("replace the path");

        let through_fd = hash_open_file(&file).expect("hash through descriptor");
        let expected = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"original running bytes"))
        );
        assert_eq!(through_fd.as_str(), expected);
        // And it is not the impostor now sitting at the original path.
        let impostor = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"different impostor bytes"))
        );
        assert_ne!(through_fd.as_str(), impostor);
    }

    #[test]
    fn hash_is_stable_and_content_addressed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bin");
        let mut file = File::create(&path).expect("create");
        file.write_all(b"abc").expect("write");
        drop(file);
        let handle = File::open(&path).expect("open");
        let digest = hash_open_file(&handle).expect("hash");
        assert_eq!(
            digest.as_str(),
            format!("sha256:{}", hex::encode(Sha256::digest(b"abc")))
        );
    }
}
