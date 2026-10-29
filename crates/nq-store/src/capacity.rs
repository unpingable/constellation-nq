//! Conservative SQLite capacity admission. Callers serialize admission through
//! transaction completion and use the same policy for every writable entrypoint.

use crate::StoreError;
use nix::sys::resource::{getrlimit, Resource, RLIM_INFINITY};
use nix::sys::statvfs::statvfs;
use rusqlite::{config::DbConfig, Connection};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Requested history duration; capacity refusal never reduces this duration.
pub const DEFAULT_HORIZON_SECONDS: u64 = 7 * 24 * 60 * 60;
// Includes an explicit allowance for SQLite SHM, validation/envelope sidecars,
// filesystem allocation rounding and simultaneous sidecar replacement.
const FIXED_ALLOWANCE: u64 = 4 * 1024 * 1024;
const MIN_PAGES: u64 = 256;
// Bundled SQLite sqlite3SectorSize() clamps every VFS result to 65536
// (sqlite3.c MAX_SECTOR_SIZE). FULL commits may repeat the final WAL
// frame until the next sector boundary; do not assume powersafe overwrite.
const MAX_SQLITE_SECTOR_BYTES: u64 = 65_536;
const SHM_REGION_BYTES: u64 = 32_768;
const SHM_FRAMES_PER_REGION: u64 = 4096;
// Bundled WALINDEX_HDR_SIZE consumes 34 page-map entries in the first
// region (sqlite3.c HASHTABLE_NPAGE_ONE=4062); later regions hold 4096.
const SHM_FIRST_REGION_FRAMES: u64 = 4062;

/// Operator intent, persisted together with the effective envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapacityPolicy {
    /// History duration, independent of available capacity.
    pub horizon_seconds: u64,
    /// Explicit aggregate ceiling; absent means capacity minus reserve.
    pub byte_ceiling: Option<u64>,
    /// Free filesystem bytes that this store must leave unallocated.
    pub reserve_bytes: u64,
    /// Whether explicit restore may resolve the reserve on its new filesystem.
    /// Ordinary reopen always keeps the recorded effective reserve.
    pub reserve_is_automatic: bool,
    /// Additional admitted sidecars or maintenance allocations.
    pub auxiliary_bytes: u64,
}

/// An actual filesystem and process file-limit observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapacityObservation {
    /// Device identity of the store directory.
    pub device: u64,
    /// Bytes currently available to this execution identity.
    pub available_bytes: u64,
    /// Total destination filesystem bytes.
    pub total_bytes: u64,
    /// Unallocated inodes available to this execution identity.
    pub available_inodes: u64,
    /// Applicable soft per-file limit; None denotes unlimited.
    pub file_limit_bytes: Option<u64>,
    /// Existing store main/WAL/SHM/journal and housekeeping allocated or logical bytes.
    pub occupied_bytes: u64,
    /// Exact known housekeeping paths and surviving owned temporary sidecars.
    pub auxiliary_occupied_bytes: u64,
}

/// A resource refusal: the envelope, reserve, inodes or per-file limit do not
/// admit the operation now. Callers may retry later; nothing was written.
fn refusal(message: impl Into<String>) -> StoreError {
    StoreError::Refused(crate::Refusal::Capacity(message.into()))
}

/// Another reader or writer prevents the bounded write path right now.
fn contention(message: impl Into<String>) -> StoreError {
    StoreError::Refused(crate::Refusal::Contention(message.into()))
}

/// A persisted envelope or store file that cannot be honoured at all: a
/// configuration or integrity fault, not a transient refusal.
fn envelope_fault(message: impl Into<String>) -> StoreError {
    StoreError::Invariant(format!("capacity refused: {}", message.into()))
}

fn add(left: u64, right: u64) -> Result<u64, StoreError> {
    left.checked_add(right)
        .ok_or_else(|| refusal("byte arithmetic overflow"))
}

/// Observe the destination without opening SQLite or performing a write.
pub fn observe(path: &Path) -> Result<CapacityObservation, StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| refusal("database has no parent"))?;
    let fs = statvfs(parent).map_err(|error| refusal(error.to_string()))?;
    let (limit, _) =
        getrlimit(Resource::RLIMIT_FSIZE).map_err(|error| refusal(error.to_string()))?;
    let available_bytes = fs
        .blocks_available()
        .checked_mul(fs.fragment_size())
        .ok_or_else(|| refusal("filesystem capacity overflow"))?;
    let mut occupied_bytes = 0;
    for candidate in store_files(path) {
        match std::fs::metadata(candidate) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(envelope_fault("store member is not a regular file"));
                }
                occupied_bytes = add(
                    occupied_bytes,
                    metadata.len().max(
                        metadata
                            .blocks()
                            .checked_mul(512)
                            .ok_or_else(|| refusal("allocated byte overflow"))?,
                    ),
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let auxiliary_occupied_bytes = auxiliary_occupancy(path)?;
    occupied_bytes = add(occupied_bytes, auxiliary_occupied_bytes)?;
    Ok(CapacityObservation {
        auxiliary_occupied_bytes,
        device: std::fs::metadata(parent)?.dev(),
        total_bytes: fs
            .blocks()
            .checked_mul(fs.fragment_size())
            .ok_or_else(|| refusal("filesystem total overflow"))?,
        available_bytes,
        available_inodes: fs.files_available(),
        file_limit_bytes: (limit != RLIM_INFINITY).then_some(limit),
        occupied_bytes,
    })
}

fn store_files(path: &Path) -> Vec<PathBuf> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            PathBuf::from(name)
        })
        .collect()
}

/// Resolve the admitted automatic policy from actual filesystem capacity.
/// Automatic reserve is at least 1 GiB and one fifth of total capacity;
/// the automatic ceiling uses only half of free bytes above that reserve.
pub fn resolve_policy(
    horizon_seconds: u64,
    byte_ceiling: Option<u64>,
    reserve_bytes: Option<u64>,
    auxiliary_bytes: Option<u64>,
    observed: &CapacityObservation,
) -> Result<CapacityPolicy, StoreError> {
    if horizon_seconds == 0 {
        return Err(refusal("retention horizon must be positive"));
    }
    let fifth = observed.total_bytes / 5 + u64::from(observed.total_bytes % 5 != 0);
    Ok(CapacityPolicy {
        horizon_seconds,
        byte_ceiling,
        reserve_bytes: reserve_bytes.unwrap_or((1024 * 1024 * 1024).max(fifth)),
        reserve_is_automatic: reserve_bytes.is_none(),
        auxiliary_bytes: auxiliary_bytes.unwrap_or(64 * 1024 * 1024),
    })
}

/// Versioned, serializable conservative operating envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatingEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Original operator intent; it must not silently contract on reopen.
    pub policy: CapacityPolicy,
    /// Admission measurement.
    pub observed: CapacityObservation,
    /// Aggregate bound covering a full main file and full transaction WAL.
    pub aggregate_bytes: u64,
    /// Database page size used to derive frame bounds.
    pub page_size: u64,
    /// Main database page ceiling.
    pub max_pages: u64,
    /// Main-file ceiling.
    pub main_bytes: u64,
    /// Full-database WAL frame allowance, including WAL header.
    pub wal_bytes: u64,
}

impl OperatingEnvelope {
    /// Derive a conservative bound from actual capacity and applicable limits.
    pub fn derive(
        policy: CapacityPolicy,
        observed: CapacityObservation,
        page_size: u64,
        existing_pages: u64,
    ) -> Result<Self, StoreError> {
        if policy.horizon_seconds == 0
            || !page_size.is_power_of_two()
            || !(512..=65536).contains(&page_size)
        {
            return Err(refusal("invalid horizon or SQLite page size"));
        }
        if policy.reserve_is_automatic
            && policy.reserve_bytes
                != resolve_policy(
                    policy.horizon_seconds,
                    policy.byte_ceiling,
                    None,
                    Some(policy.auxiliary_bytes),
                    &observed,
                )?
                .reserve_bytes
        {
            return Err(refusal(
                "automatic reserve differs from admission observation",
            ));
        }
        if observed.available_inodes < 8 {
            return Err(refusal("insufficient free inodes"));
        }
        let capacity = add(observed.available_bytes, observed.occupied_bytes)?
            .checked_sub(policy.reserve_bytes)
            .ok_or_else(|| refusal("filesystem reserve unavailable"))?;
        let automatic = add(
            observed.occupied_bytes,
            observed
                .available_bytes
                .checked_sub(policy.reserve_bytes)
                .ok_or_else(|| refusal("filesystem reserve unavailable"))?
                / 2,
        )?;
        let aggregate_bytes = policy.byte_ceiling.unwrap_or(automatic);
        if aggregate_bytes > capacity {
            return Err(refusal("requested ceiling exceeds capacity minus reserve"));
        }
        let frame_bytes = add(page_size, 24)?;
        let padding_frames = (MAX_SQLITE_SECTOR_BYTES - 1).div_ceil(frame_bytes);
        let padding_bytes = padding_frames
            .checked_mul(frame_bytes)
            .ok_or_else(|| refusal("sector padding overflow"))?;
        let overhead = add(
            add(FIXED_ALLOWANCE, policy.auxiliary_bytes)?,
            add(
                SHM_REGION_BYTES + (SHM_FRAMES_PER_REGION - SHM_FIRST_REGION_FRAMES) * 8,
                add(padding_bytes, padding_frames * 8)?,
            )?,
        )?;
        let usable = aggregate_bytes
            .checked_sub(add(overhead, 32)?)
            .ok_or_else(|| refusal("ceiling cannot cover fixed allowance"))?;
        let mut max_pages = usable
            / add(
                page_size
                    .checked_mul(2)
                    .ok_or_else(|| refusal("page arithmetic overflow"))?,
                32,
            )?;
        if let Some(limit) = observed.file_limit_bytes {
            let margin = page_size.max(4096);
            let usable_file = limit
                .checked_sub(margin)
                .ok_or_else(|| refusal("per-file limit below required margin"))?;
            max_pages = max_pages
                .min(usable_file / page_size)
                .min(usable_file.saturating_sub(add(32, padding_bytes)?) / frame_bytes);
        }
        // SQLite's maximum page count is 2^32-2 for the bundled modern engine.
        max_pages = max_pages.min(4_294_967_294);
        if max_pages < MIN_PAGES || existing_pages > max_pages {
            return Err(refusal(
                "main-file or WAL allowance cannot fit current store",
            ));
        }
        let main_bytes = max_pages
            .checked_mul(page_size)
            .ok_or_else(|| refusal("main bound overflow"))?;
        let wal_bytes = add(
            32,
            add(max_pages, padding_frames)?
                .checked_mul(frame_bytes)
                .ok_or_else(|| refusal("WAL bound overflow"))?,
        )?;
        let shm_bytes = shm_allowance(add(max_pages, padding_frames)?)?;
        if add(
            add(add(main_bytes, wal_bytes)?, shm_bytes)?,
            add(FIXED_ALLOWANCE, policy.auxiliary_bytes)?,
        )? > aggregate_bytes
        {
            return Err(refusal("aggregate bound calculation failed"));
        }
        Ok(Self {
            schema_version: 2,
            policy,
            observed,
            aggregate_bytes,
            page_size,
            max_pages,
            main_bytes,
            wal_bytes,
        })
    }

    /// Recheck filesystem reserve and device before any SQLite write/open.
    pub fn preflight(&self, path: &Path) -> Result<(), StoreError> {
        let expected = Self::derive(
            self.policy.clone(),
            self.observed.clone(),
            self.page_size,
            0,
        )?;
        if &expected != self {
            return Err(envelope_fault(
                "persisted envelope fields disagree with derivation",
            ));
        }
        let current = observe(path)?;
        if self.schema_version != 2 || current.device != self.observed.device {
            return Err(envelope_fault(
                "unsupported envelope or changed filesystem identity",
            ));
        }
        if current.auxiliary_occupied_bytes > add(FIXED_ALLOWANCE, self.policy.auxiliary_bytes)? {
            return Err(refusal("known sidecars exceed housekeeping allowance"));
        }
        if current.available_inodes < 8 {
            return Err(refusal("insufficient free inodes"));
        }
        let remaining = self
            .aggregate_bytes
            .checked_sub(current.occupied_bytes)
            .ok_or_else(|| refusal("existing store exceeds aggregate ceiling"))?;
        if current.available_bytes < add(self.policy.reserve_bytes, remaining)? {
            return Err(refusal(
                "filesystem cannot preserve reserve and admitted envelope",
            ));
        }
        let shm_bound = shm_allowance(wal_frame_ceiling(self)?)?;
        if current.file_limit_bytes.is_some_and(|limit| {
            limit
                < self
                    .main_bytes
                    .max(self.wal_bytes)
                    .max(shm_bound)
                    .saturating_add(self.page_size.max(4096))
        }) {
            return Err(refusal(
                "current per-file limit is below persisted envelope",
            ));
        }
        for (index, candidate) in store_files(path).into_iter().enumerate() {
            if let Ok(metadata) = std::fs::metadata(candidate) {
                let cap = match index {
                    0 => self.main_bytes,
                    1 => self.wal_bytes,
                    2 => shm_allowance(wal_frame_ceiling(self)?)?,
                    _ => self.wal_bytes,
                };
                if metadata.len() > cap {
                    return Err(refusal("existing SQLite file exceeds envelope"));
                }
            }
        }
        Ok(())
    }
}

fn shm_allowance(max_pages: u64) -> Result<u64, StoreError> {
    let indexed = add(max_pages, SHM_FRAMES_PER_REGION - SHM_FIRST_REGION_FRAMES)?;
    let regions = add(indexed, SHM_FRAMES_PER_REGION - 1)? / SHM_FRAMES_PER_REGION;
    regions
        .checked_mul(SHM_REGION_BYTES)
        .ok_or_else(|| refusal("SHM bound overflow"))
}

/// Disable implicit checkpoint/spill paths and apply the main-file page ceiling.
/// Invoke immediately after opening a connection, before persistent PRAGMAs.
pub fn configure(connection: &Connection, envelope: &OperatingEnvelope) -> Result<(), StoreError> {
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    connection.pragma_update(None, "cache_spill", "OFF")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "wal_autocheckpoint", 0)?;
    let page_size: u64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    if page_size != envelope.page_size {
        return Err(envelope_fault("page size differs from persisted envelope"));
    }
    let actual: u64 = connection.query_row(
        &format!("PRAGMA max_page_count={}", envelope.max_pages),
        [],
        |row| row.get(0),
    )?;
    if actual != envelope.max_pages {
        return Err(envelope_fault("SQLite could not apply page ceiling"));
    }
    Ok(())
}

/// Require successful WAL truncation before reserving one full-database write.
/// Caller holds common operation serialization through the following commit.
///
/// This is the strict form for explicit checkpoints, initialization,
/// restore and upgrades, whose purpose is a truncated WAL. Ordinary write
/// transactions use [`checkpoint_or_bound_before_write`].
pub fn checkpoint_before_write(
    connection: &Connection,
    path: &Path,
    envelope: &OperatingEnvelope,
) -> Result<(), StoreError> {
    envelope.preflight(path)?;
    if truncate_checkpoint_busy(connection)? {
        return Err(contention(CHECKPOINT_CONTENTION));
    }
    apply_page_ceiling(connection, envelope.max_pages)?;
    envelope.preflight(path)
}

/// Admit one ordinary write transaction. A successful TRUNCATE checkpoint
/// admits it exactly as [`checkpoint_before_write`] does. When a reader (or
/// writer) keeps the checkpoint from resetting the WAL, the write is still
/// admitted if it provably cannot take the WAL past the envelope's
/// `wal_bytes`: this connection's page ceiling is lowered by the frames the
/// WAL file may already hold, and the write is refused with the same
/// contention refusal only when the database already exceeds that lowered
/// ceiling. The next admitted write restores the envelope's ceiling.
///
/// With `cache_spill` off, one transaction appends at most one frame per page
/// of the database it commits plus the sector padding, which is exactly the
/// envelope's full-database WAL allowance with `max_pages` replaced by the
/// lowered ceiling; the frames already in the file use up the difference.
/// Caller holds common operation serialization through the following commit.
pub fn checkpoint_or_bound_before_write(
    connection: &Connection,
    path: &Path,
    envelope: &OperatingEnvelope,
) -> Result<(), StoreError> {
    checkpoint_or_bound_using(connection, path, envelope, truncate_checkpoint_busy)
}

// Store owns these connections and configures busy_timeout itself. Keep this
// private: replacing a timeout cannot restore an arbitrary caller busy handler.
// Strict checkpoints and the public connection helper retain their wait policy.
pub(super) fn checkpoint_or_bound_before_store_write(
    connection: &Connection,
    path: &Path,
    envelope: &OperatingEnvelope,
) -> Result<(), StoreError> {
    checkpoint_or_bound_using(connection, path, envelope, truncate_checkpoint_without_wait)
}

fn checkpoint_or_bound_using(
    connection: &Connection,
    path: &Path,
    envelope: &OperatingEnvelope,
    checkpoint: fn(&Connection) -> Result<bool, StoreError>,
) -> Result<(), StoreError> {
    envelope.preflight(path)?;
    let ceiling = if checkpoint(connection)? {
        contended_page_ceiling(connection, path, envelope)?
            .ok_or_else(|| contention(CHECKPOINT_CONTENTION))?
    } else {
        envelope.max_pages
    };
    apply_page_ceiling(connection, ceiling)?;
    PAGE_CEILING_LOWERED.with(|lowered| lowered.set(ceiling < envelope.max_pages));
    envelope.preflight(path)
}

thread_local! {
    /// Whether the write transaction this thread is admitting or running
    /// was admitted under a page ceiling lowered for a held WAL.
    static PAGE_CEILING_LOWERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Scope of one admitted write transaction: clears the lowered-ceiling mark
/// when the transaction (or a failed attempt to begin it) ends.
pub(crate) struct CeilingScope(());

impl CeilingScope {
    pub(crate) fn begin() -> Self {
        Self(())
    }
}

impl Drop for CeilingScope {
    fn drop(&mut self) {
        PAGE_CEILING_LOWERED.with(|lowered| lowered.set(false));
    }
}

/// SQLite's disk-full from a write admitted under a lowered page ceiling is
/// the held reader's WAL, not capacity: report it as that contention.
pub(crate) fn classify_sqlite_error(error: rusqlite::Error) -> StoreError {
    let full = matches!(
        &error,
        rusqlite::Error::SqliteFailure(code, _) if code.code == rusqlite::ErrorCode::DiskFull
    );
    if full && PAGE_CEILING_LOWERED.with(std::cell::Cell::get) {
        return contention(format!(
            "{CHECKPOINT_CONTENTION}: this write needs more pages than the page ceiling the \
             held WAL leaves ({error})"
        ));
    }
    StoreError::Sqlite(error)
}

const CHECKPOINT_CONTENTION: &str = "reader or writer prevents bounded WAL checkpoint";

// Avoid spending the write-lock timeout on an optional reset before the
// existing bounded-WAL fallback. Copying checkpoint pages may still take IO.
// Restore before propagating either query outcome; a restoration error refuses
// admission rather than proceeding with an altered actual write-lock timeout.
fn truncate_checkpoint_without_wait(connection: &Connection) -> Result<bool, StoreError> {
    let timeout_ms: u64 = connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    connection.busy_timeout(std::time::Duration::ZERO)?;
    let checkpoint = truncate_checkpoint_busy(connection);
    connection.busy_timeout(std::time::Duration::from_millis(timeout_ms))?;
    checkpoint
}

fn truncate_checkpoint_busy(connection: &Connection) -> Result<bool, StoreError> {
    let (busy, _, _): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    Ok(busy != 0)
}

/// The page ceiling under which one more transaction keeps the WAL file
/// inside `wal_bytes`, or `None` when the current database already exceeds
/// it. Every byte of the WAL file past its header counts as resident frames,
/// whether or not SQLite still considers them valid, so the measurement is
/// conservative. The caller's serialization guard keeps cooperating writers
/// from appending between this measurement and its commit.
fn contended_page_ceiling(
    connection: &Connection,
    path: &Path,
    envelope: &OperatingEnvelope,
) -> Result<Option<u64>, StoreError> {
    let wal_len = match std::fs::metadata(&store_files(path)[1]) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    let resident_frames = wal_len
        .saturating_sub(32)
        .div_ceil(add(envelope.page_size, 24)?);
    let pages: u64 = connection.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    Ok(envelope
        .max_pages
        .checked_sub(resident_frames)
        .filter(|ceiling| pages <= *ceiling))
}

fn apply_page_ceiling(connection: &Connection, pages: u64) -> Result<(), StoreError> {
    let current: u64 = connection.query_row("PRAGMA max_page_count", [], |row| row.get(0))?;
    if current == pages {
        return Ok(());
    }
    let actual: u64 =
        connection.query_row(&format!("PRAGMA max_page_count={pages}"), [], |row| {
            row.get(0)
        })?;
    if actual != pages {
        return Err(envelope_fault("SQLite could not apply page ceiling"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(bytes: u64) -> CapacityObservation {
        CapacityObservation {
            device: 1,
            available_bytes: bytes,
            total_bytes: bytes,
            available_inodes: 100,
            file_limit_bytes: None,
            occupied_bytes: 0,
            auxiliary_occupied_bytes: 0,
        }
    }
    fn policy(ceiling: u64) -> CapacityPolicy {
        CapacityPolicy {
            horizon_seconds: DEFAULT_HORIZON_SECONDS,
            byte_ceiling: Some(ceiling),
            reserve_bytes: 1024 * 1024 * 1024,
            reserve_is_automatic: false,
            auxiliary_bytes: 0,
        }
    }
    #[test]
    fn explicit_restore_preserves_reserve_intent_across_filesystem_sizes() {
        let source = observation(32 * 1024 * 1024 * 1024);
        let target = observation(16 * 1024 * 1024 * 1024);
        let automatic = resolve_policy(DEFAULT_HORIZON_SECONDS, None, None, None, &source).unwrap();
        let restored = policy_for_restore(&automatic, &target).unwrap();
        assert!(restored.reserve_is_automatic);
        assert_ne!(restored.reserve_bytes, automatic.reserve_bytes);
        assert_eq!(
            restored,
            resolve_policy(DEFAULT_HORIZON_SECONDS, None, None, None, &target).unwrap()
        );
        let envelope = OperatingEnvelope::derive(restored, target.clone(), 4096, 0).unwrap();
        // Reopen matches its recorded admission measurement, not new free space.
        let mut later = target;
        later.available_bytes -= 1024 * 1024;
        assert_eq!(
            envelope.policy,
            policy_for_restore(&envelope.policy, &later).unwrap()
        );

        let explicit = resolve_policy(
            DEFAULT_HORIZON_SECONDS,
            None,
            Some(automatic.reserve_bytes),
            None,
            &source,
        )
        .unwrap();
        assert_ne!(
            explicit, automatic,
            "equal bytes do not establish equal intent"
        );
        assert_eq!(policy_for_restore(&explicit, &later).unwrap(), explicit);
    }

    #[test]
    fn envelope_without_reserve_origin_is_not_inferred() {
        let envelope = OperatingEnvelope::derive(
            policy(8 * 1024 * 1024 * 1024),
            observation(24 * 1024 * 1024 * 1024),
            4096,
            0,
        )
        .unwrap();
        let mut document = serde_json::to_value(envelope).unwrap();
        document["policy"]
            .as_object_mut()
            .unwrap()
            .remove("reserve_is_automatic");
        assert!(serde_json::from_value::<OperatingEnvelope>(document).is_err());
    }
    #[test]
    fn insufficient_capacity_refuses_without_reducing_horizon() {
        let requested = policy(8 * 1024 * 1024 * 1024);
        assert!(OperatingEnvelope::derive(
            requested.clone(),
            observation(8 * 1024 * 1024 * 1024),
            4096,
            0
        )
        .is_err());
        assert_eq!(requested.horizon_seconds, 604800);
    }
    #[test]
    fn bound_reserves_full_database_and_full_wal() {
        let envelope = OperatingEnvelope::derive(
            policy(8 * 1024 * 1024 * 1024),
            observation(24 * 1024 * 1024 * 1024),
            4096,
            1,
        )
        .unwrap();
        assert!(envelope.main_bytes < 4 * 1024 * 1024 * 1024);
        assert!(
            envelope.main_bytes + envelope.wal_bytes + FIXED_ALLOWANCE <= envelope.aggregate_bytes
        );
        assert_eq!(
            envelope.wal_bytes,
            32 + (envelope.max_pages + (MAX_SQLITE_SECTOR_BYTES - 1).div_ceil(4120)) * 4120
        );
    }
    #[test]
    fn per_file_limit_caps_wal_as_well_as_main() {
        let mut observed = observation(32 * 1024 * 1024);
        observed.file_limit_bytes = Some(2 * 1024 * 1024);
        let mut requested = policy(16 * 1024 * 1024);
        requested.reserve_bytes = 0;
        let envelope = OperatingEnvelope::derive(requested, observed, 4096, 1).unwrap();
        assert!(envelope.wal_bytes + 4096 <= 2 * 1024 * 1024);
        assert!(envelope.main_bytes + 4096 <= 2 * 1024 * 1024);
    }
    #[test]
    fn tiny_limit_and_existing_oversized_store_refuse() {
        let mut observed = observation(32 * 1024 * 1024);
        observed.file_limit_bytes = Some(512);
        let mut requested = policy(16 * 1024 * 1024);
        requested.reserve_bytes = 0;
        assert!(OperatingEnvelope::derive(requested.clone(), observed, 4096, 1).is_err());
        assert!(
            OperatingEnvelope::derive(requested, observation(32 * 1024 * 1024), 4096, 10_000)
                .is_err()
        );
    }
    #[test]
    fn automatic_budget_preserves_reserve_and_unallocated_half() {
        let observed = observation(32 * 1024 * 1024 * 1024);
        let requested =
            resolve_policy(DEFAULT_HORIZON_SECONDS, None, None, None, &observed).unwrap();
        assert_eq!(requested.reserve_bytes, observed.total_bytes / 5 + 1);
        assert_eq!(requested.auxiliary_bytes, 64 * 1024 * 1024);
        let envelope =
            OperatingEnvelope::derive(requested.clone(), observed.clone(), 4096, 0).unwrap();
        assert_eq!(
            envelope.aggregate_bytes,
            (observed.available_bytes - requested.reserve_bytes) / 2
        );
        assert_eq!(envelope.policy.horizon_seconds, DEFAULT_HORIZON_SECONDS);
    }

    #[test]
    fn filesystem_total_sets_reserve_independently_of_available_bytes() {
        let mut observed = observation(2 * 1024 * 1024 * 1024);
        observed.total_bytes = 32 * 1024 * 1024 * 1024;
        let requested =
            resolve_policy(DEFAULT_HORIZON_SECONDS, None, None, None, &observed).unwrap();
        assert!(OperatingEnvelope::derive(requested, observed, 4096, 0).is_err());
    }

    #[test]
    fn full_commit_sector_padding_is_reserved_at_the_limit() {
        for page_size in [512_u64, 4096, 65536] {
            let frame = page_size + 24;
            let padding = (MAX_SQLITE_SECTOR_BYTES - 1).div_ceil(frame);
            for remainder in 1..MAX_SQLITE_SECTOR_BYTES {
                let extra = (MAX_SQLITE_SECTOR_BYTES - remainder).div_ceil(frame);
                assert!(extra <= padding);
            }
            let envelope = OperatingEnvelope::derive(
                policy(8 * 1024 * 1024 * 1024),
                observation(32 * 1024 * 1024 * 1024),
                page_size,
                0,
            )
            .unwrap();
            assert_eq!(
                envelope.wal_bytes,
                32 + (envelope.max_pages + padding) * frame
            );
            assert!(
                envelope.main_bytes
                    + envelope.wal_bytes
                    + shm_allowance(envelope.max_pages + padding).unwrap()
                    + FIXED_ALLOWANCE
                    + envelope.policy.auxiliary_bytes
                    <= envelope.aggregate_bytes
            );
        }
    }

    #[test]
    fn first_shm_region_header_is_charged_at_frame_boundaries() {
        assert_eq!(shm_allowance(4062).unwrap(), 32768);
        assert_eq!(shm_allowance(4063).unwrap(), 65536);
        assert_eq!(shm_allowance(4096).unwrap(), 65536);
        assert_eq!(shm_allowance(8158).unwrap(), 65536);
        assert_eq!(shm_allowance(8159).unwrap(), 98304);
    }

    fn status(index: usize, detail_bytes: usize) -> crate::StatusEventInput {
        crate::StatusEventInput {
            status_event_id: format!("capacity-status-{index}"),
            component_kind: "daemon".into(),
            component_id: "capacity-fixture".into(),
            state: "healthy".into(),
            code: "capacity_sample".into(),
            detail: crate::CanonicalDocument::from_serializable(&serde_json::json!({
                "qualification": "bounded capacity fixture", "sample": "x".repeat(detail_bytes)
            }))
            .unwrap(),
            observed_at: "2026-10-09T00:00:00Z".into(),
        }
    }

    fn tiny_store() -> (tempfile::TempDir, PathBuf, crate::Store) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nq.db");
        let store = crate::Store::initialize_with_capacity(
            &path,
            DEFAULT_HORIZON_SECONDS,
            Some(8 * 1024 * 1024),
            Some(0),
            Some(0),
        )
        .unwrap();
        (root, path, store)
    }

    fn stored_status_ids(store: &crate::Store) -> Vec<String> {
        store
            .connection
            .prepare("SELECT status_event_id FROM status_events ORDER BY status_sequence")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn expected_capacity_error(error: &StoreError) -> bool {
        match error {
            StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _)) => {
                code.code == rusqlite::ErrorCode::DiskFull
            }
            StoreError::Refused(crate::Refusal::Capacity(_) | crate::Refusal::Contention(_)) => {
                assert!(error.is_refusal());
                assert!(error.to_string().starts_with("capacity refused: "), "{error}");
                true
            }
            _ => false,
        }
    }

    #[test]
    fn real_sqlite_ceiling_preserves_prior_rows_and_refused_retries_are_bounded() {
        let (_root, path, mut store) = tiny_store();
        let envelope = store.capacity.clone().unwrap();
        let mut committed = Vec::new();
        let mut first_refusal = None;
        // At most 8 MiB of input; database allocation remains inside the
        // admitted 8-MiB envelope. This loop cannot grow without a bound.
        for index in 0..128 {
            let input = status(index, 64 * 1024);
            match store.record_status(&input) {
                Ok(()) => committed.push(input.status_event_id),
                Err(error) => {
                    assert!(
                        expected_capacity_error(&error),
                        "unexpected refusal: {error}"
                    );
                    first_refusal = Some(index);
                    break;
                }
            }
            assert!(observe(&path).unwrap().occupied_bytes <= envelope.aggregate_bytes);
        }
        let refused_index = first_refusal.expect("bounded fixture must reach its page ceiling");
        assert!(!committed.is_empty());
        assert_eq!(stored_status_ids(&store), committed);
        let baseline = observe(&path).unwrap().occupied_bytes;
        assert!(baseline <= envelope.aggregate_bytes);
        for retry in 0..3 {
            let error = store
                .record_status(&status(refused_index + retry, 64 * 1024))
                .unwrap_err();
            assert!(
                expected_capacity_error(&error),
                "unexpected retry refusal: {error}"
            );
            assert_eq!(stored_status_ids(&store), committed);
            assert!(observe(&path).unwrap().occupied_bytes <= baseline);
        }
        drop(store);
        let restored = crate::Store::open(&path).unwrap();
        assert_eq!(stored_status_ids(&restored), committed);
        assert!(!restored.status_snapshots().unwrap().is_empty());
        assert!(observe(&path).unwrap().occupied_bytes <= envelope.aggregate_bytes);
        restored.validate().unwrap();
    }

    fn hold_reader(path: &Path) -> Connection {
        let reader =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let _: i64 = reader
            .query_row("SELECT COUNT(*) FROM status_events", [], |row| row.get(0))
            .unwrap();
        reader
    }

    fn page_count(store: &crate::Store) -> u64 {
        store
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap()
    }

    fn max_page_count(store: &crate::Store) -> u64 {
        store
            .connection
            .query_row("PRAGMA max_page_count", [], |row| row.get(0))
            .unwrap()
    }

    /// Extend the WAL file with zero bytes past its last valid frame, as a
    /// long-unreset WAL would be. SQLite ignores bytes after the last valid
    /// commit frame and overwrites them on the next append.
    fn pad_wal_to_frames(path: &Path, envelope: &OperatingEnvelope, frames: u64) {
        let wal = sidecar(path, "-wal");
        let current = std::fs::metadata(&wal).unwrap().len();
        let target = 32 + frames * (envelope.page_size + 24);
        assert!(target >= current, "fixture WAL already holds more frames");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&wal)
            .unwrap()
            .set_len(target)
            .unwrap();
    }

    #[test]
    fn held_reader_ordinary_write_does_not_wait_for_opportunistic_checkpoint() {
        let (_root, path, mut store) = tiny_store();
        let envelope = store.capacity.clone().unwrap();
        store.record_status(&status(0, 1024)).unwrap();
        let reader = hold_reader(&path);
        let before: i64 = reader
            .query_row("SELECT COUNT(*) FROM status_events", [], |r| r.get(0))
            .unwrap();
        store
            .connection
            .busy_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let started = std::time::Instant::now();
        store.record_status(&status(1, 1024)).unwrap();
        let elapsed = started.elapsed();
        let timeout: u64 = store
            .connection
            .pragma_query_value(None, "busy_timeout", |r| r.get(0))
            .unwrap();
        assert_eq!(
            timeout, 1000,
            "actual write-lock waits retain their configured policy"
        );
        assert_eq!(
            reader
                .query_row::<i64, _, _>("SELECT COUNT(*) FROM status_events", [], |r| r.get(0))
                .unwrap(),
            before
        );
        assert_eq!(
            stored_status_ids(&store).len(),
            usize::try_from(before).unwrap() + 1
        );
        assert!(max_page_count(&store) < envelope.max_pages);
        assert!(std::fs::metadata(sidecar(&path, "-wal")).unwrap().len() <= envelope.wal_bytes);
        assert!(observe(&path).unwrap().occupied_bytes <= envelope.aggregate_bytes);
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "the optional checkpoint must not consume the one-second busy wait: {elapsed:?}"
        );
    }

    #[test]
    fn nonwaiting_checkpoint_restores_timeout_after_query_error() {
        let (_root, _path, store) = tiny_store();
        store
            .connection
            .busy_timeout(std::time::Duration::from_millis(731))
            .unwrap();
        store.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(
            truncate_checkpoint_without_wait(&store.connection).is_err(),
            "checkpointing inside this connection's transaction must fail"
        );
        let timeout: u64 = store
            .connection
            .pragma_query_value(None, "busy_timeout", |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, 731, "restore before propagating the query error");
        store.connection.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn ordinary_write_retains_its_actual_writer_lock_wait() {
        let (_root, path, mut store) = tiny_store();
        store.record_status(&status(0, 1024)).unwrap();
        store
            .connection
            .busy_timeout(std::time::Duration::from_millis(100))
            .unwrap();
        let other_writer = Connection::open(&path).unwrap();
        other_writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let before = stored_status_ids(&store);
        let started = std::time::Instant::now();
        let error = store.record_status(&status(1, 1024)).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(error, StoreError::Sqlite(rusqlite::Error::SqliteFailure(ref code, _))
            if code.code == rusqlite::ErrorCode::DatabaseBusy),
            "{error:?}"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(75),
            "only the checkpoint hint skips waiting, not actual writer contention: {elapsed:?}"
        );
        assert_eq!(stored_status_ids(&store), before);
        assert_eq!(
            store
                .connection
                .pragma_query_value::<u64, _>(None, "busy_timeout", |r| r.get(0))
                .unwrap(),
            100
        );
        other_writer.execute_batch("ROLLBACK").unwrap();
        store.record_status(&status(1, 1024)).unwrap();
    }

    #[test]
    fn held_reader_admits_a_write_that_cannot_exceed_the_wal_bound() {
        let (_root, path, mut store) = tiny_store();
        let envelope = store.capacity.clone().unwrap();
        store.record_status(&status(0, 1024)).unwrap();
        store
            .connection
            .busy_timeout(std::time::Duration::from_millis(10))
            .unwrap();
        let reader = hold_reader(&path);
        let wal = sidecar(&path, "-wal");
        let resident = std::fs::metadata(&wal).unwrap().len();
        let prior = stored_status_ids(&store);
        store.record_status(&status(1, 1024)).unwrap();
        assert_eq!(stored_status_ids(&store).len(), prior.len() + 1);
        // The reader keeps the WAL from resetting: the commit is appended.
        let grown = std::fs::metadata(&wal).unwrap().len();
        assert!(grown > resident);
        assert!(grown <= envelope.wal_bytes);
        assert!(observe(&path).unwrap().occupied_bytes <= envelope.aggregate_bytes);
        // While contended, this connection's page ceiling leaves room for the
        // resident frames; the reader's snapshot is unchanged.
        assert!(max_page_count(&store) < envelope.max_pages);
        let seen: i64 = reader
            .query_row("SELECT COUNT(*) FROM status_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(usize::try_from(seen).unwrap(), prior.len());
        // An explicit checkpoint still requires the truncation.
        let error = store.checkpoint_wal().unwrap_err();
        assert!(
            matches!(error, StoreError::Refused(crate::Refusal::Contention(ref text)) if text.contains("prevents bounded WAL checkpoint")),
            "{error:?}"
        );
        reader.execute_batch("ROLLBACK").unwrap();
        drop(reader);
        store.record_status(&status(2, 1024)).unwrap();
        assert_eq!(stored_status_ids(&store).len(), prior.len() + 2);
        assert_eq!(max_page_count(&store), envelope.max_pages);
        assert!(std::fs::metadata(&wal).unwrap().len() < grown);
        store.checkpoint_wal().unwrap();
        assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
        store.validate().unwrap();
    }

    #[test]
    fn held_reader_refuses_a_write_that_could_exceed_the_wal_bound() {
        let (_root, path, mut store) = tiny_store();
        let envelope = store.capacity.clone().unwrap();
        store.record_status(&status(0, 1024)).unwrap();
        store
            .connection
            .busy_timeout(std::time::Duration::from_millis(10))
            .unwrap();
        let reader = hold_reader(&path);
        let pages = page_count(&store);
        // One resident frame more than a full rewrite of the current pages
        // leaves room for: the next transaction could pass the WAL bound.
        pad_wal_to_frames(&path, &envelope, envelope.max_pages - pages + 1);
        let prior = stored_status_ids(&store);
        let error = store.record_status(&status(1, 1024)).unwrap_err();
        assert!(
            matches!(error, StoreError::Refused(crate::Refusal::Contention(ref text)) if text.contains("prevents bounded WAL checkpoint")),
            "{error:?}"
        );
        assert!(error.is_refusal());
        assert!(
            error
                .to_string()
                .starts_with("capacity refused: reader or writer prevents bounded WAL checkpoint")
        );
        assert_eq!(stored_status_ids(&store), prior);
        reader.execute_batch("ROLLBACK").unwrap();
        drop(reader);
        store.record_status(&status(1, 1024)).unwrap();
        assert_eq!(stored_status_ids(&store).len(), prior.len() + 1);
        assert_eq!(max_page_count(&store), envelope.max_pages);
        store.validate().unwrap();
    }

    #[test]
    fn held_reader_caps_the_transaction_at_the_remaining_wal_bound() {
        let (_root, path, mut store) = tiny_store();
        let envelope = store.capacity.clone().unwrap();
        store.record_status(&status(0, 1024)).unwrap();
        store
            .connection
            .busy_timeout(std::time::Duration::from_millis(10))
            .unwrap();
        let reader = hold_reader(&path);
        let pages = page_count(&store);
        let free: u64 = store
            .connection
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))
            .unwrap();
        assert!(free < 16, "fixture must need new pages for 64 KiB");
        // Exactly a full rewrite of the current pages fits: the write is
        // admitted, but may not grow the database at all.
        pad_wal_to_frames(&path, &envelope, envelope.max_pages - pages);
        let prior = stored_status_ids(&store);
        let error = store.record_status(&status(1, 64 * 1024)).unwrap_err();
        // Not a disk-full: the held reader's WAL, not capacity, stopped it.
        assert!(
            matches!(&error, StoreError::Refused(crate::Refusal::Contention(text)) if text.starts_with("reader or writer prevents bounded WAL checkpoint") && text.contains("page ceiling")),
            "{error:?}"
        );
        assert!(error.is_refusal());
        assert_eq!(stored_status_ids(&store), prior);
        assert!(std::fs::metadata(sidecar(&path, "-wal")).unwrap().len() <= envelope.wal_bytes);
        reader.execute_batch("ROLLBACK").unwrap();
        drop(reader);
        store.record_status(&status(1, 64 * 1024)).unwrap();
        assert_eq!(stored_status_ids(&store).len(), prior.len() + 1);
        assert_eq!(max_page_count(&store), envelope.max_pages);
        store.validate().unwrap();
        // Without a held reader the envelope's own page ceiling still
        // surfaces as SQLite's disk-full capacity refusal.
        let full = (2..256)
            .find_map(|index| store.record_status(&status(index, 64 * 1024)).err())
            .expect("the envelope's page ceiling is reached");
        assert!(
            matches!(&full, StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _)) if code.code == rusqlite::ErrorCode::DiskFull),
            "{full:?}"
        );
    }

    #[test]
    fn held_reader_does_not_bypass_the_envelope_preflight() {
        let (_root, path, mut store) = tiny_store();
        let envelope = store.capacity.clone().unwrap();
        store.record_status(&status(0, 1024)).unwrap();
        store
            .connection
            .busy_timeout(std::time::Duration::from_millis(10))
            .unwrap();
        let reader = hold_reader(&path);
        let wal = sidecar(&path, "-wal");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&wal)
            .unwrap()
            .set_len(envelope.wal_bytes + 1)
            .unwrap();
        let prior = stored_status_ids(&store);
        let error = store.record_status(&status(1, 1024)).unwrap_err();
        assert!(
            matches!(error, StoreError::Refused(crate::Refusal::Capacity(_))),
            "{error:?}"
        );
        assert_eq!(stored_status_ids(&store), prior);
        reader.execute_batch("ROLLBACK").unwrap();
        drop(reader);
    }

    #[test]
    fn capacity_refusals_are_typed_and_configuration_faults_are_not() {
        assert!(refusal("insufficient free inodes").is_refusal());
        assert!(matches!(
            refusal("insufficient free inodes"),
            StoreError::Refused(crate::Refusal::Capacity(_))
        ));
        assert!(contention("reader or writer prevents bounded WAL checkpoint").is_refusal());
        let fault = envelope_fault("page size differs from persisted envelope");
        assert!(!fault.is_refusal());
        assert!(matches!(fault, StoreError::Invariant(ref text) if text.starts_with("capacity refused: ")));
        let full = StoreError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        ));
        assert!(full.is_refusal());
        assert!(!StoreError::Integrity("x".into()).is_refusal());
        assert!(!StoreError::Invariant("x".into()).is_refusal());
    }

    #[test]
    fn concurrent_operation_guard_refuses_without_committing() {
        let (_root, path, first) = tiny_store();
        let mut second = crate::Store::open(&path).unwrap();
        let held = operation_guard(&path).unwrap();
        let error =
            operation_guard_with_timeout(&path, std::time::Duration::from_millis(10)).unwrap_err();
        assert!(
            matches!(error, StoreError::Refused(crate::Refusal::Contention(ref text)) if text.contains("concurrent writer owns operation guard"))
        );
        assert!(stored_status_ids(&first).is_empty());
        assert!(stored_status_ids(&second).is_empty());
        drop(held);
        second.record_status(&status(0, 1024)).unwrap();
        assert_eq!(stored_status_ids(&first).len(), 1);
    }

    fn lock_path(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(".capacity.lock");
        PathBuf::from(name)
    }

    fn sidecar(path: &Path, suffix: &str) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    }

    #[test]
    fn operation_guard_never_holds_a_lock_file_unlinked_from_the_database_path() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nq.db");
        let first = operation_guard(&path).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter_path = path.clone();
        let waiter = std::thread::spawn(move || {
            let guard =
                operation_guard_with_timeout(&waiter_path, std::time::Duration::from_secs(10));
            sender.send(()).unwrap();
            guard
        });
        // The waiter has opened the original lock inode and is polling it.
        std::thread::sleep(std::time::Duration::from_millis(100));
        // The original inode is unlinked and a cooperating writer's locked
        // replacement takes its name in one rename, before the original
        // holder releases: the waiter never sees an unheld name.
        let staged = root.path().join("replacement.lock");
        let replacement = nix::fcntl::Flock::lock(
            std::fs::File::create(&staged).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, error)| error)
        .unwrap();
        std::fs::rename(&staged, lock_path(&path)).unwrap();
        drop(first);
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "a guard on the unlinked inode must not coexist with the path's guard"
        );
        drop(replacement);
        receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let guard = waiter.join().unwrap().unwrap();
        let held = guard.metadata().unwrap();
        let named = std::fs::symlink_metadata(lock_path(&path)).unwrap();
        assert_eq!((held.dev(), held.ino()), (named.dev(), named.ino()));
    }

    #[test]
    fn a_failed_verified_backup_leaves_no_destination_lock() {
        let (_root, path, mut store) = tiny_store();
        store.record_status(&status(0, 1024)).unwrap();
        let copy_root = tempfile::tempdir().unwrap();
        let copy = copy_root.path().join("nq.db");
        crate::BACKUP_VERIFY_FAULT_FOR_TEST.with(|armed| armed.set(true));
        let error = store.backup_verified(&copy).expect_err("injected fault");
        assert!(error.to_string().contains("injected backup verification fault"));
        let left: Vec<_> = std::fs::read_dir(copy_root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "failed backup left {left:?}");
        // The source's own lock is untouched and a later backup succeeds.
        assert!(lock_path(&path).exists());
        store.backup_verified(&copy).expect("backup after a failed attempt");
    }

    #[test]
    fn closed_private_copy_sidecars_are_retired_under_their_own_guard() {
        let (_root, path, mut store) = tiny_store();
        store.record_status(&status(0, 1024)).unwrap();
        drop(store);
        let copy_root = tempfile::tempdir().unwrap();
        let copy = copy_root.path().join("nq.db");
        crate::Store::open_read_only(&path)
            .unwrap()
            .backup_verified(&copy)
            .unwrap();
        let archived = crate::Store::open(&copy).unwrap();
        archived.prepare_archive_copy().unwrap();
        drop(archived);
        std::fs::write(sidecar(&copy, "-shm"), [0_u8; 32]).unwrap();
        std::fs::write(sidecar(&copy, "-wal"), []).unwrap();
        assert!(lock_path(&copy).is_file());

        retire_private_copy_sidecars(&copy).unwrap();

        let mut names = std::fs::read_dir(copy_root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["nq.db"]);
        drop(crate::Store::open_immutable(&copy).unwrap());
        // The source store's own lock is untouched by retiring the copy's.
        assert!(lock_path(&path).is_file());
    }

    #[test]
    fn a_private_copy_with_committed_wal_frames_is_not_retired() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nq.db");
        drop(
            crate::Store::initialize_with_capacity(
                &path,
                DEFAULT_HORIZON_SECONDS,
                Some(8 * 1024 * 1024),
                Some(0),
                Some(0),
            )
            .unwrap(),
        );
        let mut store = crate::Store::open(&path).unwrap();
        store.record_status(&status(0, 1024)).unwrap();
        drop(store);
        let wal = std::fs::metadata(sidecar(&path, "-wal")).unwrap().len();
        assert!(wal > 0, "the last commit remains WAL-resident after close");

        let error = retire_private_copy_sidecars(&path).unwrap_err();
        assert!(
            matches!(error, StoreError::Integrity(ref text) if text.contains("write-ahead log")),
            "{error:?}"
        );
        assert_eq!(
            std::fs::metadata(sidecar(&path, "-wal")).unwrap().len(),
            wal
        );
        assert!(lock_path(&path).is_file());
        assert!(sidecar(&path, "-shm").is_file());
    }

    #[test]
    fn a_held_guard_prevents_retiring_its_lock() {
        let (_root, path, store) = tiny_store();
        drop(store);
        let held = operation_guard(&path).unwrap();
        let before = std::fs::symlink_metadata(lock_path(&path)).unwrap().ino();
        let error =
            retire_private_copy_sidecars_with_timeout(&path, std::time::Duration::from_millis(10))
                .unwrap_err();
        assert!(
            matches!(error, StoreError::Refused(crate::Refusal::Contention(ref text)) if text.contains("concurrent writer owns operation guard"))
        );
        assert_eq!(
            std::fs::symlink_metadata(lock_path(&path)).unwrap().ino(),
            before
        );
        drop(held);
    }

    #[test]
    fn explicit_wal_checkpoint_folds_the_last_commit_or_refuses_and_keeps_it() {
        let (_root, path, mut store) = tiny_store();
        store.record_status(&status(0, 1024)).unwrap();
        let wal = sidecar(&path, "-wal");
        let resident = std::fs::metadata(&wal).unwrap().len();
        assert!(resident > 0);
        let main_only = |label: &str| -> i64 {
            let copy_root = tempfile::tempdir().unwrap();
            let copy = copy_root.path().join("nq.db");
            std::fs::copy(&path, &copy).unwrap();
            Connection::open(&copy)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM status_events", [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("{label}: {error}"))
        };
        assert_eq!(main_only("before"), 0, "the commit is WAL-resident");

        let reader =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let _: i64 = reader
            .query_row("SELECT COUNT(*) FROM status_events", [], |row| row.get(0))
            .unwrap();
        let error = store.checkpoint_wal().unwrap_err();
        assert!(
            matches!(error, StoreError::Refused(crate::Refusal::Contention(ref text)) if text.contains("prevents bounded WAL checkpoint")),
            "{error:?}"
        );
        // A reader's snapshot blocks the reset, not the backfill already
        // admitted by the preflight: the WAL itself is kept.
        assert!(std::fs::metadata(&wal).unwrap().len() >= resident);
        reader.execute_batch("ROLLBACK").unwrap();
        drop(reader);

        store.checkpoint_wal().unwrap();
        assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
        assert_eq!(main_only("checkpointed"), 1);
        drop(store);
        assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
        assert_eq!(
            stored_status_ids(&crate::Store::open(&path).unwrap()).len(),
            1
        );
    }

    #[test]
    fn leftover_cold_rollback_journal_is_charged_without_removal() {
        let (_root, path, mut store) = tiny_store();
        store.record_status(&status(0, 1024)).unwrap();
        let before = observe(&path).unwrap().occupied_bytes;
        let mut name = path.as_os_str().to_owned();
        name.push("-journal");
        let journal = PathBuf::from(name);
        std::fs::write(&journal, [0_u8; 1024]).unwrap();
        assert!(observe(&path).unwrap().occupied_bytes >= before + 1024);
        store.capacity.as_ref().unwrap().preflight(&path).unwrap();
        assert_eq!(std::fs::metadata(&journal).unwrap().len(), 1024);
        assert_eq!(stored_status_ids(&store).len(), 1);
        std::fs::remove_file(&journal).unwrap();
        store.record_status(&status(1, 1024)).unwrap();
    }

    #[test]
    fn unavailable_advisory_watermark_preserves_open_and_allocates_no_temporary() {
        let (_root, path, mut store) = tiny_store();
        let watermark = crate::watermark_path(&path);
        std::fs::create_dir(&watermark).unwrap();
        let metadata = std::fs::metadata(&watermark).unwrap();
        assert!(observe(&path).unwrap().auxiliary_occupied_bytes >= metadata.blocks() * 512);
        let error = preflight_watermark(&path, 128).unwrap_err();
        assert!(matches!(error, StoreError::WatermarkWrite(_)));
        store.record_status(&status(0, 1024)).unwrap();
        drop(store);
        let reopened = crate::Store::open(&path).unwrap();
        assert_eq!(stored_status_ids(&reopened).len(), 1);
        assert!(watermark.is_dir());
        assert!(!std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")
            }));
    }

    #[test]
    fn real_delete_journal_crash_recovers_prior_committed_rows() {
        let (_root, path, mut store) = tiny_store();
        store.record_status(&status(0, 1024)).unwrap();
        store.prepare_archive_copy().unwrap();
        drop(store);
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "capacity::tests::crash_after_delete_journal_write",
                "--ignored",
            ])
            .env("NQ_CAPACITY_CRASH_FIXTURE", &path)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(
            journal_recovery_extent(&path).unwrap().is_some(),
            "fixture created a real SQLite hot journal"
        );
        let reopened = crate::Store::open(&path).unwrap();
        assert_eq!(stored_status_ids(&reopened), vec!["capacity-status-0"]);
        reopened.validate().unwrap();
        assert!(journal_recovery_extent(&path).unwrap().is_none());
        assert!(observe(&path).unwrap().occupied_bytes <= 8 * 1024 * 1024);
    }

    #[test]
    #[ignore = "subprocess qualification helper"]
    fn crash_after_delete_journal_write() {
        let Ok(path) = std::env::var("NQ_CAPACITY_CRASH_FIXTURE") else {
            return;
        };
        let connection = Connection::open(path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA cache_size=1; PRAGMA cache_spill=ON; PRAGMA synchronous=FULL; BEGIN IMMEDIATE;").unwrap();
        for index in 1000..1008 {
            let input = status(index, 64 * 1024);
            connection.execute("INSERT INTO status_events(status_event_id,component_kind,component_id,state,code,detail_json,observed_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![input.status_event_id,input.component_kind,input.component_id,input.state,input.code,input.detail.as_bytes(),input.observed_at]).unwrap();
        }
        // Deliberately bypass connection Drop in this isolated crash fixture.
        std::process::exit(0);
    }

    #[test]
    fn cold_wal_bootstrap_refuses_small_file_limit_before_shm_creation() {
        let (_root, path, mut store) = tiny_store();
        store.record_status(&status(0, 1024)).unwrap();
        drop(store);
        let mut wal_name = path.as_os_str().to_owned();
        wal_name.push("-wal");
        assert!(std::fs::metadata(PathBuf::from(wal_name)).unwrap().len() > 32);
        let mut shm_name = path.as_os_str().to_owned();
        shm_name.push("-shm");
        let shm = PathBuf::from(shm_name);
        match std::fs::remove_file(&shm) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove owned cold SHM fixture: {error}"),
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "capacity::tests::small_limit_bootstrap_helper",
                "--ignored",
            ])
            .env("NQ_CAPACITY_SMALL_LIMIT_FIXTURE", &path)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(
            !shm.exists(),
            "bootstrap refusal must precede SQLite SHM allocation"
        );
        let reopened = crate::Store::open(&path).unwrap();
        assert_eq!(stored_status_ids(&reopened).len(), 1);
    }

    #[test]
    #[ignore = "subprocess qualification helper"]
    fn small_limit_bootstrap_helper() {
        let Ok(path) = std::env::var("NQ_CAPACITY_SMALL_LIMIT_FIXTURE") else {
            return;
        };
        nix::sys::resource::setrlimit(Resource::RLIMIT_FSIZE, 8192, 8192).unwrap();
        let error = crate::Store::open(&path)
            .err()
            .expect("bootstrap must refuse");
        assert!(matches!(error, StoreError::Refused(crate::Refusal::Capacity(ref text)) if text.contains("bootstrap SHM")));
        for error in [
            crate::Store::database_schema_version(&path).err(),
            crate::Store::open_read_only(&path).err(),
            crate::Store::open_v3_upgrade_source_read_only(&path).err(),
            crate::Store::open_v4_upgrade_source_read_only(&path).err(),
        ] {
            assert!(
                matches!(error, Some(StoreError::Refused(crate::Refusal::Capacity(ref text))) if text.contains("bootstrap SHM"))
            );
        }
    }

    #[test]
    fn arithmetic_overflow_refuses() {
        let mut observed = observation(u64::MAX);
        observed.occupied_bytes = 1;
        assert!(OperatingEnvelope::derive(policy(1024), observed, 4096, 0).is_err());
    }
}

/// Cooperating-writer guard retained through SQLite commit or rollback.
pub(crate) type OperationGuard = nix::fcntl::Flock<std::fs::File>;

pub(crate) fn operation_guard(path: &Path) -> Result<OperationGuard, StoreError> {
    operation_guard_with_timeout(path, std::time::Duration::from_secs(5))
}

fn operation_guard_with_timeout(
    path: &Path,
    timeout: std::time::Duration,
) -> Result<OperationGuard, StoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(envelope_fault("database requires an unaliased regular pathname"));
        }
    }
    let lock = capacity_lock_path(path)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(&lock)?;
        if !file.metadata()?.is_file() {
            return Err(envelope_fault("capacity lock is not a regular file"));
        }
        let error = match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        {
            Ok(guard) => {
                // The lock is the inode currently named by the lock path. A
                // guard won on an inode that was unlinked (by the owner of a
                // private copy) or replaced while this process waited would
                // coexist with a guard on the named inode, so it is dropped and
                // the current name is locked instead.
                let held = guard.metadata()?;
                match std::fs::symlink_metadata(&lock) {
                    Ok(named) if (named.dev(), named.ino()) == (held.dev(), held.ino()) => {
                        return Ok(guard);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                nix::errno::Errno::EWOULDBLOCK
            }
            Err((_, error)) => error,
        };
        if !matches!(
            error,
            nix::errno::Errno::EWOULDBLOCK | nix::errno::Errno::EINTR
        ) {
            return Err(refusal(format!(
                "operation guard acquisition failed: {error}"
            )));
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(contention(format!(
                "concurrent writer owns operation guard after bounded wait: {error}"
            )));
        }
        std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(2)));
    }
}

pub(crate) fn capacity_lock_path(path: &Path) -> Result<PathBuf, StoreError> {
    let parent = std::fs::canonicalize(
        path.parent()
            .ok_or_else(|| refusal("database has no parent"))?,
    )?;
    let mut name = path
        .file_name()
        .ok_or_else(|| refusal("database has no file name"))?
        .to_owned();
    name.push(".capacity.lock");
    Ok(parent.join(name))
}

/// Remove the SQLite and capacity sidecars of a private database copy whose
/// connections have all closed, such as an archive staging copy.
///
/// The caller must own the copy exclusively: it was created under a fresh
/// private path by this process and no connection to it remains open. The
/// copy's own operation guard is acquired first (a bounded wait), so a lock
/// held by any other cooperating process is never removed, and the lock file
/// is unlinked while that guard is held; a waiter on the unlinked inode
/// re-locks the current name (see `operation_guard_with_timeout`). A
/// non-empty write-ahead log or a rollback journal holds committed or
/// uncommitted state that is not in the main file and is refused, leaving
/// every member in place. The empty WAL and the SHM index carry no state.
///
/// # Errors
///
/// Returns a refusal when another process holds the copy's guard, and an
/// integrity error when the main file does not hold the complete copy.
pub fn retire_private_copy_sidecars(path: &Path) -> Result<(), StoreError> {
    retire_private_copy_sidecars_with_timeout(path, std::time::Duration::from_secs(5))
}

fn retire_private_copy_sidecars_with_timeout(
    path: &Path,
    timeout: std::time::Duration,
) -> Result<(), StoreError> {
    let member = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    };
    let guard = operation_guard_with_timeout(path, timeout)?;
    match std::fs::symlink_metadata(member("-journal")) {
        Ok(_) => {
            return Err(StoreError::Integrity(
                "private copy has a rollback journal; its main file is not complete".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut removable = Vec::new();
    for suffix in ["-wal", "-shm"] {
        match std::fs::symlink_metadata(member(suffix)) {
            Ok(metadata) if !metadata.is_file() => {
                return Err(envelope_fault("private copy sidecar is not a regular file"));
            }
            Ok(metadata) if suffix == "-wal" && metadata.len() != 0 => {
                return Err(StoreError::Integrity(format!(
                    "private copy write-ahead log holds {} bytes not in its main file",
                    metadata.len()
                )));
            }
            Ok(_) => removable.push(member(suffix)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    for sidecar in removable {
        std::fs::remove_file(sidecar)?;
    }
    std::fs::remove_file(capacity_lock_path(path)?)?;
    drop(guard);
    Ok(())
}

pub(crate) struct GuardedTransaction<'a> {
    pub(crate) transaction: rusqlite::Transaction<'a>,
    // Ownership is retained solely for its destructor after SQLite completion.
    #[allow(dead_code)]
    pub(crate) guard: Option<OperationGuard>,
    // Declared after the transaction, so it drops after the rollback.
    #[allow(dead_code)]
    pub(crate) ceiling: CeilingScope,
}
impl<'a> std::ops::Deref for GuardedTransaction<'a> {
    type Target = rusqlite::Transaction<'a>;
    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}
impl GuardedTransaction<'_> {
    pub(crate) fn commit(self) -> Result<(), rusqlite::Error> {
        self.transaction.commit()
    }
    #[allow(dead_code)]
    pub(crate) fn rollback(self) -> Result<(), rusqlite::Error> {
        self.transaction.rollback()
    }
}

pub(crate) fn admit_maintenance(
    path: &Path,
    horizon: u64,
    ceiling: Option<u64>,
    reserve: Option<u64>,
    auxiliary: Option<u64>,
) -> Result<(OperationGuard, OperatingEnvelope), StoreError> {
    let observed = observe(path)?;
    if observed.file_limit_bytes.is_some_and(|limit| limit < 8192) {
        return Err(refusal(
            "per-file limit cannot admit maintenance inspection",
        ));
    }
    let guard = operation_guard(path)?;
    bootstrap_preflight(path)?;
    recover_hot_journal(path)?;
    let read = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    read.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    let page_size = read.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let pages = read.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let policy = resolve_policy(horizon, ceiling, reserve, auxiliary, &observed)?;
    let envelope = OperatingEnvelope::derive(policy, observed, page_size, pages)?;
    envelope.preflight(path)?;
    Ok((guard, envelope))
}

/// Admit maintenance of an established store under its persisted operating
/// envelope, exactly as recorded: nothing is re-derived or resized.
pub(crate) fn admit_persisted_maintenance(
    path: &Path,
) -> Result<(OperationGuard, OperatingEnvelope), StoreError> {
    let observed = observe(path)?;
    if observed.file_limit_bytes.is_some_and(|limit| limit < 8192) {
        return Err(refusal(
            "per-file limit cannot admit maintenance inspection",
        ));
    }
    let guard = operation_guard(path)?;
    bootstrap_preflight(path)?;
    recover_hot_journal(path)?;
    let read = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    read.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    let bytes: Vec<u8> = read.query_row(
        "SELECT capacity_json FROM retention_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let envelope: OperatingEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
        StoreError::Invariant(format!("persisted capacity envelope invalid: {error}"))
    })?;
    envelope.preflight(path)?;
    Ok((guard, envelope))
}

pub(crate) fn admit_backup_destination(
    source: &Path,
    destination: &Path,
) -> Result<(OperationGuard, OperationGuard, OperatingEnvelope), StoreError> {
    let source_guard = operation_guard(source)?;
    let destination_guard = operation_guard(destination)?;
    bootstrap_preflight(source)?;
    let read = Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    read.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    let page_size = read.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let pages = read.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let observed = observe(destination)?;
    let policy = resolve_policy(DEFAULT_HORIZON_SECONDS, None, None, None, &observed)?;
    let envelope = OperatingEnvelope::derive(policy, observed, page_size, pages)?;
    envelope.preflight(destination)?;
    Ok((source_guard, destination_guard, envelope))
}

pub(crate) fn configure_backup_target(
    connection: &Connection,
    envelope: &OperatingEnvelope,
) -> Result<(), StoreError> {
    connection.pragma_update(None, "page_size", envelope.page_size)?;
    configure(connection, envelope)
}

pub(crate) fn admit_backup_from_connection(
    source: &Connection,
    destination: &Path,
) -> Result<(OperationGuard, OperatingEnvelope), StoreError> {
    let guard = operation_guard(destination)?;
    let page_size = source.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let pages = source.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let observed = observe(destination)?;
    let policy = resolve_policy(DEFAULT_HORIZON_SECONDS, None, None, None, &observed)?;
    let envelope = OperatingEnvelope::derive(policy, observed, page_size, pages)?;
    envelope.preflight(destination)?;
    Ok((guard, envelope))
}

fn wal_frame_ceiling(envelope: &OperatingEnvelope) -> Result<u64, StoreError> {
    Ok((envelope.wal_bytes - 32) / add(envelope.page_size, 24)?)
}

fn auxiliary_occupancy(database: &Path) -> Result<u64, StoreError> {
    let parent = database
        .parent()
        .ok_or_else(|| refusal("database has no parent"))?;
    let stem = database
        .file_name()
        .ok_or_else(|| refusal("database has no basename"))?
        .to_string_lossy();
    let watermark = format!("{stem}.validation-watermark.json");
    let capacity_lock = format!("{stem}.capacity.lock");
    let mut bytes = 0;
    for (index, entry) in std::fs::read_dir(parent)?.enumerate() {
        if index >= 100_000 {
            return Err(refusal("sidecar directory exceeds bounded inspection"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == capacity_lock
            || name == watermark
            || name.starts_with(&format!("{watermark}.tmp-"))
            || (name.starts_with(&format!("{stem}.")) && name.ends_with(".nqd.lock"))
        {
            let metadata = std::fs::symlink_metadata(entry.path())?;
            // An unavailable advisory watermark cannot prevent ordinary
            // operation. Charge its own allocation without adopting directory
            // contents or following a symlink; watermark writing refuses it
            // separately before allocating a replacement temporary.
            if !metadata.is_file() && name != watermark {
                return Err(refusal("known sidecar is not a regular file"));
            }
            bytes = add(
                bytes,
                metadata.len().max(
                    metadata
                        .blocks()
                        .checked_mul(512)
                        .ok_or_else(|| refusal("sidecar allocation overflow"))?,
                ),
            )?;
        }
    }
    Ok(bytes)
}

/// Bound the exact encoded watermark and simultaneous old/new sidecar allocation.
/// The Store caller already holds its cooperating operation guard.
pub(crate) fn preflight_watermark(database: &Path, encoded_bytes: usize) -> Result<(), StoreError> {
    match std::fs::symlink_metadata(crate::watermark_path(database)) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(StoreError::WatermarkWrite(
                "validation watermark destination is not a regular file; no replacement temporary allocated".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(StoreError::WatermarkWrite(error.to_string())),
    }
    bootstrap_preflight(database)?;
    let read = Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    read.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    let bytes: Vec<u8> = read.query_row(
        "SELECT capacity_json FROM retention_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let envelope: OperatingEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| refusal(format!("invalid watermark operating envelope: {error}")))?;
    envelope.preflight(database)?;
    let observed = observe(database)?;
    let encoded_bytes =
        u64::try_from(encoded_bytes).map_err(|_| refusal("watermark length overflow"))?;
    if observed
        .file_limit_bytes
        .is_some_and(|limit| encoded_bytes > limit.saturating_sub(4096))
    {
        return Err(refusal("encoded watermark exceeds current per-file limit"));
    }
    let fragment = statvfs(
        database
            .parent()
            .ok_or_else(|| refusal("database has no parent"))?,
    )
    .map_err(|error| refusal(error.to_string()))?
    .fragment_size()
    .max(4096);
    let allocation = encoded_bytes
        .div_ceil(fragment)
        .checked_mul(fragment)
        .ok_or_else(|| refusal("watermark allocation overflow"))?;
    if add(observed.auxiliary_occupied_bytes, allocation)?
        > add(FIXED_ALLOWANCE, envelope.policy.auxiliary_bytes)?
    {
        return Err(refusal(
            "watermark replacement exceeds housekeeping allowance",
        ));
    }
    if add(observed.occupied_bytes, allocation)? > envelope.aggregate_bytes
        || observed.available_bytes < add(envelope.policy.reserve_bytes, allocation)?
    {
        return Err(refusal(
            "watermark replacement exceeds aggregate or filesystem reserve",
        ));
    }
    Ok(())
}

/// Explicit restore receipt: original intent and the new destination admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreCapacityAdmission {
    /// Source envelope copied from the verified backup.
    pub prior: OperatingEnvelope,
    /// Replacement envelope admitted on the restore destination.
    pub current: OperatingEnvelope,
}

/// Re-admit only an explicitly restored current-schema copy. Ordinary open
/// never calls this function and never fills a missing or partial envelope.
/// The caller retains this receipt before publishing the validated copy.
pub fn readmit_restored_copy(path: &Path) -> Result<RestoreCapacityAdmission, StoreError> {
    let observation = observe(path)?;
    if observation
        .file_limit_bytes
        .is_some_and(|limit| limit < 8192)
    {
        return Err(refusal("per-file limit cannot admit restore inspection"));
    }
    let _guard = operation_guard(path)?;
    bootstrap_preflight(path)?;
    let verified = crate::Store::open_read_only(path)?;
    verified.validate()?;
    drop(verified);
    let read = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    read.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    let bytes: Vec<u8> = read.query_row(
        "SELECT capacity_json FROM retention_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let prior: OperatingEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| refusal(format!("restore envelope invalid or incomplete: {error}")))?;
    let expected = OperatingEnvelope::derive(
        prior.policy.clone(),
        prior.observed.clone(),
        prior.page_size,
        0,
    )?;
    if prior != expected {
        return Err(refusal(
            "restore source envelope derivation is inconsistent",
        ));
    }
    let page_size = read.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let pages = read.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    drop(read);
    if prior.observed.device == observation.device && prior.preflight(path).is_ok() {
        return Ok(RestoreCapacityAdmission {
            current: prior.clone(),
            prior,
        });
    }
    let target = observe(path)?;
    let policy = policy_for_restore(&prior.policy, &target)?;
    let current = OperatingEnvelope::derive(policy, target, page_size, pages)?;
    current.preflight(path)?;
    let mut connection =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    configure(&connection, &current)?;
    checkpoint_before_write(&connection, path, &current)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let latest: Vec<u8> = transaction.query_row(
        "SELECT capacity_json FROM retention_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if latest != bytes {
        return Err(refusal("restore envelope changed after inspection"));
    }
    let document = crate::CanonicalDocument::from_serializable(&current)?;
    transaction.execute(
        "UPDATE retention_state SET capacity_json=?1 WHERE singleton=1",
        [document.as_bytes()],
    )?;
    transaction.commit()?;
    // Publish a standalone main file rather than leaving authority-bearing WAL
    // beside the temporary pathname that the restore caller will rename/link.
    checkpoint_before_write(&connection, path, &current)?;
    Ok(RestoreCapacityAdmission { prior, current })
}

fn policy_for_restore(
    prior: &CapacityPolicy,
    target: &CapacityObservation,
) -> Result<CapacityPolicy, StoreError> {
    resolve_policy(
        prior.horizon_seconds,
        prior.byte_ceiling,
        (!prior.reserve_is_automatic).then_some(prior.reserve_bytes),
        Some(prior.auxiliary_bytes),
        target,
    )
}

// SQLite first rollback header bounds original dbSize; later journal records
// with page numbers above that value are ignored by pager_playback_one_page.
// A max_page_count PRAGMA cannot replace this check: playback raises mxPgno.
fn journal_recovery_extent(path: &Path) -> Result<Option<u64>, StoreError> {
    use std::io::Read;
    let mut name = path.as_os_str().to_owned();
    name.push("-journal");
    let mut file = match std::fs::File::open(PathBuf::from(name)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() == 0 {
        return Ok(None);
    }
    let mut header = [0_u8; 28];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    if header[..8] != [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7] {
        return Ok(None);
    }
    let pages = u64::from(u32::from_be_bytes(header[16..20].try_into().unwrap()));
    let mut page_size = u64::from(u32::from_be_bytes(header[24..28].try_into().unwrap()));
    if page_size == 0 {
        let mut database = std::fs::File::open(path)?;
        let mut db_header = [0_u8; 18];
        database.read_exact(&mut db_header)?;
        if &db_header[..16] != b"SQLite format 3\0" {
            return Err(refusal(
                "legacy recovery lacks a valid database page-size header",
            ));
        }
        page_size = u64::from(u16::from_be_bytes(db_header[16..18].try_into().unwrap()));
        if page_size == 1 {
            page_size = 65536;
        }
    }
    if !page_size.is_power_of_two() || !(512..=65536).contains(&page_size) {
        return Err(refusal("rollback recovery page size is unsupported"));
    }
    Ok(Some(pages.checked_mul(page_size).ok_or_else(|| {
        refusal("rollback original extent overflow")
    })?))
}

/// Bound storage effects of SQLite metadata inspection before its first query.
/// This is allocation headroom, not a substitute for the persisted policy.
pub(crate) fn bootstrap_preflight(path: &Path) -> Result<Option<u64>, StoreError> {
    use std::io::Read;
    let observed = observe(path)?;
    if observed.available_inodes < 8 {
        return Err(refusal("insufficient bootstrap inodes"));
    }
    let mut wal_name = path.as_os_str().to_owned();
    wal_name.push("-wal");
    let mut frame_count = 0;
    match std::fs::File::open(PathBuf::from(wal_name)) {
        Ok(mut wal) => {
            let length = wal.metadata()?.len();
            let mut header = [0_u8; 12];
            let mut page_size = 512;
            if wal.read_exact(&mut header).is_ok() {
                let candidate = u64::from(u32::from_be_bytes(header[8..12].try_into().unwrap()));
                if candidate.is_power_of_two() && (512..=65536).contains(&candidate) {
                    page_size = candidate;
                }
            }
            frame_count = length.saturating_sub(32) / (page_size + 24);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let shm_bytes = shm_allowance(frame_count.max(1))?;
    let recovery_extent = journal_recovery_extent(path)?;
    let largest_write = shm_bytes.max(recovery_extent.unwrap_or(0));
    if observed
        .file_limit_bytes
        .is_some_and(|limit| limit < largest_write.saturating_add(4096))
    {
        return Err(refusal(
            "per-file limit cannot cover bootstrap SHM or rollback recovery extent",
        ));
    }
    // Full main rewrite headroom is conservative for copying filesystems;
    // the journal also remains charged in observed existing occupancy.
    let required = add(
        add(shm_bytes, recovery_extent.unwrap_or(0))?,
        FIXED_ALLOWANCE,
    )?;
    if observed.available_bytes < required {
        return Err(refusal(
            "filesystem cannot cover bootstrap SHM and rollback rewrite headroom",
        ));
    }
    Ok(recovery_extent)
}

/// Caller holds the common operation guard. SQLite itself validates/replays
/// the journal; this layer only bounds its possible original main extent.
pub(crate) fn recover_hot_journal(path: &Path) -> Result<(), StoreError> {
    if bootstrap_preflight(path)?.is_none() {
        return Ok(());
    }
    let connection =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    connection.pragma_update(None, "cache_spill", "OFF")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "wal_autocheckpoint", 0)?;
    let _: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    Ok(())
}
