//! Shared bounded artifact write/compare only. Each source owns its key/core law.
use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotContext {
    pub history_scope: Sha256Digest,
    pub snapshot_key: Sha256Digest,
    pub core_digest: Sha256Digest,
}
pub(crate) fn record(
    directory: &std::path::Path,
    snapshot_key: Sha256Digest,
    core_digest: Sha256Digest,
    schema: &str,
) -> Result<SnapshotContext, String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let metadata = std::fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("history must be existing nonsymlink directory".into());
    }
    let scope = std::fs::canonicalize(directory).map_err(|e| e.to_string())?;
    let context = SnapshotContext {
        history_scope: semantic_digest(&scope).map_err(|e| e.to_string())?,
        snapshot_key,
        core_digest,
    };
    let record =
        serde_json::json!({"schema":schema,"key":context.snapshot_key,"core":context.core_digest});
    let bytes = nq_protocol::canonical_json_bytes(&record).map_err(|e| e.to_string())?;
    let path = scope.join(format!(
        "{}.json",
        context
            .snapshot_key
            .to_string()
            .trim_start_matches("sha256:")
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            std::fs::File::open(&scope)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // O_NONBLOCK prevents a substituted FIFO from hanging intake;
            // O_NOFOLLOW excludes symlinks. Context assumes trusted directory.
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&path)
                .map_err(|e| e.to_string())?;
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("history record not regular".into());
            }
            let mut stored = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(1025)
                .read_to_end(&mut stored)
                .map_err(|e| e.to_string())?;
            if stored != bytes {
                return Err("SnapshotSubstitution or incomplete local history record".into());
            }
            // A concurrent creator may have written the full bytes but not yet
            // synced. Duplicate success must establish its own durability.
            file.sync_all().map_err(|e| e.to_string())?;
            std::fs::File::open(&scope)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
        Err(e) => return Err(e.to_string()),
    }
    Ok(context)
}
