//! Type-level sole-writer law for the NQ Store.
//!
//! Every production mutator of Store state requires a borrowed
//! [`StoreWriterSession`] in its type signature. The session is an
//! unforgeable capability: it can only be constructed by
//! [`Store::begin_writer_session`], which acquires the per-store-path
//! process write lock (non-reentrant) and refuses while the store is
//! fenced. It carries no trust root, activation, capacity, or receipts;
//! it is not a universal authority record.

use std::collections::BTreeMap;
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};

use nix::fcntl::{FlockArg, flock};

use crate::capacity_backend::{
    ClosedC2StoreBackendV1, closed_backend_lock_inode_key_v1,
    verify_rr_06_sole_post_receipt_constructor,
};
use crate::global_failure_journal::{
    C2PostCompletionGRefusalV1, verify_n_45a_post_completion_candidate_g_refusal,
};
use crate::store_generation::lock::{C2StoreGenerationLockV1, LockInodeKey};
use crate::store_generation::records::{
    PhysicalStoreGenerationIdentityV1, StoreOccurrenceIdentityV1,
};
use crate::store_generation::{
    C2_BOOTSTRAP_EXTENT_V1, C2_GLOBAL_REFUSAL_EXTENT_V1, C2_LOCK_FILE_V1,
};
use crate::{Store, StoreError, pragma_i64};
use nq_runtime_dependency_authority::{
    ResolvedControllingActivation, VerificationBrand, VerifiedActivationRevocation,
    VerifiedMigrationClassification, VerifiedOperatorAuthorityRotation,
    VerifiedResidentActivationSuccessor, VerifiedV7CardinalityDisposition,
};

/// Shared per-store-path writer state: one process-local non-reentrant
/// write lock and the write fence. The C2 filesystem lock layer is a
/// later, separate stage; this is the process layer only.
struct PathLockState {
    write_mutex: Mutex<()>,
    fenced: AtomicBool,
}

/// Exact maintenance exclusion held across both the process mutex and one
/// kernel `flock`.  For a not-yet-created destination the flock is taken on
/// the nearest existing retained ancestor, conservatively serializing sibling
/// maintenance operations without creating a sidecar before authorization.
pub(crate) struct MaintenanceLockGuard {
    _process: MutexGuard<'static, ()>,
    flock_file: File,
}

impl Drop for MaintenanceLockGuard {
    fn drop(&mut self) {
        let _ = flock(self.flock_file.as_raw_fd(), FlockArg::Unlock);
    }
}

static GEN4_PATH_WRITER_LOCKS: LazyLock<Mutex<BTreeMap<PathBuf, &'static PathLockState>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static C2_LOCK_INODE_WRITER_LOCKS: LazyLock<Mutex<BTreeMap<LockInodeKey, &'static PathLockState>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static IN_MEMORY_WRITER_KEYS: AtomicU64 = AtomicU64::new(1);

const LEGACY_C2_SESSION_REFUSAL: &str =
    "legacy writer-session construction is forbidden for a C2-governed Store root";

/// Inert writer-session refusal classifications used by the exact V2 row
/// verifiers.  No variant contains a Store, backend, lock, descriptor,
/// standing value, or session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2WriterSessionRefusalV1 {
    LegacyBeginOnGovernedRoot,
    C2RootMarkerMissing,
    ClosedBackendMismatch,
    OccurrenceMismatch,
    PhysicalGenerationMismatch,
    ProjectionCandidateSetMalformed,
    SessionIsNotC2Ordinary,
}

/// Exact success classifications for the five V2 rows assigned to this
/// module.  These are inert audit witnesses, not additional constructors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum C2WriterSessionLawV1 {
    ImmutableWUStoreWriterSessionCompleteCAPH23SoleWriterOwnerWriterVerified,
    ImmutableSEAMLegacySessionLegacyBeginWriterSessionVerificationBrandVerified,
}

/// WU-10/N-60 row witness. It borrows the already constructed session and
/// cannot be converted into Store authority.
pub(crate) struct C2WriterSessionLawWitnessV1<'session, 'store> {
    session: &'session StoreWriterSession<'store>,
    law: C2WriterSessionLawV1,
}

/// N-15 association between one already closed backend and the sole ordinary
/// session that retains that same backend borrow.
pub(crate) struct ClosedBackendOrdinarySessionAssociationV1<'session, 'store> {
    backend: &'session ClosedC2StoreBackendV1<'store>,
    session: &'session StoreWriterSession<'store>,
}

/// SEAM-04 proof that the Gen4 occurrence coordinate and C2 physical Store-
/// generation coordinate occupy different nominal types and different
/// session fields.
pub(crate) struct C2WriterIdentitySplitWitnessV1<'session> {
    occurrence: &'session StoreOccurrenceIdentityV1,
    physical_generation: &'session PhysicalStoreGenerationIdentityV1,
}

/// SEAM-05 records one observed hard refusal of the legacy constructor.  It
/// contains only inert scalar state.
pub(crate) struct C2LegacySessionRefusalWitnessV1 {
    law: C2WriterSessionLawV1,
}

/// Closed input to the C2 writer-fence setter.
///
/// Construction requires one already verified, predecessor-bound G refusal
/// and the retained generation lock for the same occurrence and physical
/// generation.  It is deliberately neither cloneable nor serializable and
/// contains no Boolean authority shortcut.
pub(crate) struct VerifiedGReconciliationFenceV1 {
    lock_inode: LockInodeKey,
}

/// Derive one process fence command from exact verified G correspondence.
pub(crate) fn verify_c2_g_reconciliation_fence_v1(
    refusal: &C2PostCompletionGRefusalV1,
    lock: &C2StoreGenerationLockV1,
) -> Result<VerifiedGReconciliationFenceV1, C2WriterSessionRefusalV1> {
    verify_n_45a_post_completion_candidate_g_refusal(refusal)
        .map_err(|_| C2WriterSessionRefusalV1::ProjectionCandidateSetMalformed)?;
    if refusal.record().occurrence_id() != lock.carrier().occurrence_id
        || refusal.record().physical_store_generation_identity()
            != &lock.carrier().physical_store_generation_identity
    {
        return Err(C2WriterSessionRefusalV1::PhysicalGenerationMismatch);
    }
    Ok(VerifiedGReconciliationFenceV1 {
        lock_inode: lock.inode_key(),
    })
}

/// The sole production C2 fence setter.  The verified input fixes the exact
/// retained lock inode; callers cannot select a path, inode, or Boolean fence
/// state independently of the verified G/reconciliation result.
pub(crate) fn set_c2_writer_fence_from_verified_g_reconciliation_v1(
    fence: &VerifiedGReconciliationFenceV1,
) {
    c2_inode_lock_state(fence.lock_inode)
        .fenced
        .store(true, Ordering::SeqCst);
}

fn gen4_path_lock_state(key: &Path) -> &'static PathLockState {
    let mut registry = GEN4_PATH_WRITER_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.entry(key.to_path_buf()).or_insert_with(|| {
        Box::leak(Box::new(PathLockState {
            write_mutex: Mutex::new(()),
            fenced: AtomicBool::new(false),
        }))
    })
}

fn c2_inode_lock_state(key: LockInodeKey) -> &'static PathLockState {
    let mut registry = C2_LOCK_INODE_WRITER_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *registry.entry(key).or_insert_with(|| {
        Box::leak(Box::new(PathLockState {
            write_mutex: Mutex::new(()),
            fenced: AtomicBool::new(false),
        }))
    })
}

/// Derive the writer key for a store: the canonical path, or a unique
/// in-memory identity.
pub(crate) fn writer_key_for_path(path: Option<&Path>) -> PathBuf {
    match path {
        Some(path) => canonicalize_for_writer_key(path),
        None => PathBuf::from(format!(
            "in-memory://{}",
            IN_MEMORY_WRITER_KEYS.fetch_add(1, Ordering::Relaxed)
        )),
    }
}

/// Canonicalize a store path for lock-key purposes. The database file may
/// not exist yet (initialize), so fall back to the nearest existing
/// ancestor and reattach the remaining suffix: two spellings of one store
/// must resolve to one lock, never two.
fn canonicalize_for_writer_key(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    let mut ancestor = path;
    loop {
        match std::fs::canonicalize(ancestor) {
            Ok(canonical_ancestor) => {
                return match path.strip_prefix(ancestor) {
                    Ok(suffix) => {
                        let mut key = canonical_ancestor;
                        key.push(suffix);
                        key
                    }
                    Err(_) => canonical_ancestor,
                };
            }
            Err(_) => match ancestor.parent() {
                Some(parent) => ancestor = parent,
                None => return path.to_path_buf(),
            },
        }
    }
}

/// Return whether durable state is already inside the C2 governance boundary.
///
/// A projection row is sufficient to fence the legacy path but is never used
/// to mint C2 standing.  Likewise, any fixed C2 carrier is sufficient to
/// refuse legacy mutation during an incomplete installation.  The sidecar
/// check is refusal-only: a path or file name cannot construct a C2 session.
fn has_c2_governance_marker(store: &Store) -> Result<bool, StoreError> {
    let projection_table: i64 = store.connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema \
         WHERE type = 'table' AND name = 'c2_installation_projection'",
        [],
        |row| row.get(0),
    )?;
    if projection_table == 1 {
        let projected: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM c2_installation_projection",
            [],
            |row| row.get(0),
        )?;
        if projected != 0 {
            return Ok(true);
        }
    }

    let Some(database_path) = store.path.as_deref() else {
        return Ok(false);
    };
    let Some(root) = database_path.parent() else {
        return Ok(false);
    };
    Ok([
        C2_LOCK_FILE_V1,
        C2_BOOTSTRAP_EXTENT_V1,
        C2_GLOBAL_REFUSAL_EXTENT_V1,
    ]
    .into_iter()
    .any(|name| root.join(name).exists()))
}

fn refuse_legacy_begin_for_c2(store: &Store) -> Result<(), StoreError> {
    if has_c2_governance_marker(store)? {
        Err(StoreError::Invariant(LEGACY_C2_SESSION_REFUSAL.into()))
    } else {
        Ok(())
    }
}

/// Check the rebuildable SQLite projection only for contradiction with the
/// authoritative inputs. Absence is admissible because this projection is
/// disposable; duplicates or a present mismatch refuse.
fn verify_c2_projection_if_present(
    store: &Store,
    occurrence: &StoreOccurrenceIdentityV1,
    physical_generation: &PhysicalStoreGenerationIdentityV1,
) -> Result<(), C2WriterSessionRefusalV1> {
    let mut statement = store
        .connection
        .prepare(
            "SELECT occurrence_id, physical_store_generation_identity \
             FROM c2_installation_projection \
             ORDER BY projection_identity LIMIT 2",
        )
        .map_err(|_| C2WriterSessionRefusalV1::ProjectionCandidateSetMalformed)?;
    let candidates = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| C2WriterSessionRefusalV1::ProjectionCandidateSetMalformed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| C2WriterSessionRefusalV1::ProjectionCandidateSetMalformed)?;
    match candidates.as_slice() {
        [] => Ok(()),
        [(projected_occurrence, _)] if projected_occurrence != occurrence.as_str() => {
            Err(C2WriterSessionRefusalV1::OccurrenceMismatch)
        }
        [(_, projected_generation)]
            if projected_generation != physical_generation.digest().as_str() =>
        {
            Err(C2WriterSessionRefusalV1::PhysicalGenerationMismatch)
        }
        [(_, _)] => Ok(()),
        _ => Err(C2WriterSessionRefusalV1::ProjectionCandidateSetMalformed),
    }
}

/// Acquire the per-path process write lock for the maintenance class
/// (schema migrations and backup/preservation paths), which operate on
/// closed paths under their own exclusive recovery transactions. Keys
/// are deduplicated and acquired in sorted order.
pub(crate) fn acquire_maintenance_locks(
    paths: &[&Path],
) -> Result<Vec<MaintenanceLockGuard>, StoreError> {
    let mut keys = paths
        .iter()
        .map(|path| writer_key_for_path(Some(path)))
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    let mut guards = Vec::with_capacity(keys.len());
    for key in keys {
        let state = gen4_path_lock_state(&key);
        if state.fenced.load(Ordering::SeqCst) {
            return Err(StoreError::WriteFenced(key.display().to_string()));
        }
        let process = state
            .write_mutex
            .try_lock()
            .map_err(|_| StoreError::WriterSessionUnavailable(key.display().to_string()))?;
        let mut existing = key.as_path();
        while !existing.exists() {
            existing = existing
                .parent()
                .ok_or_else(|| StoreError::WriterSessionUnavailable(key.display().to_string()))?;
        }
        let flock_file = File::open(existing)?;
        flock(flock_file.as_raw_fd(), FlockArg::LockExclusiveNonblock)
            .map_err(|_| StoreError::WriterSessionUnavailable(key.display().to_string()))?;
        guards.push(MaintenanceLockGuard {
            _process: process,
            flock_file,
        });
    }
    Ok(guards)
}

/// Test and future-C2 fence control: fence a store path so all session
/// construction and every session method refuses.
#[cfg(test)]
pub(crate) fn fence_store_writes_for_test(key: &Path) {
    gen4_path_lock_state(key)
        .fenced
        .store(true, Ordering::SeqCst);
}

/// Unforgeable writer capability for exactly one store.
///
/// Not `Clone`, not `Copy`, not `Serialize`, not `Deserialize`, not
/// `Default`, and not publicly constructible. It borrows its store
/// mutably for its entire lifetime, so it cannot outlive the store,
/// cannot migrate to another store or generation, and cannot be
/// replayed after `Drop`.
pub struct StoreWriterSession<'store, Brand = ()> {
    store: &'store mut Store,
    state: &'static PathLockState,
    _guard: MutexGuard<'static, ()>,
    store_key: PathBuf,
    occurrence: Option<StoreOccurrenceIdentityV1>,
    physical_generation: Option<PhysicalStoreGenerationIdentityV1>,
    closed_c2_backend: Option<&'store ClosedC2StoreBackendV1<'store>>,
    genesis: Option<String>,
    _brand: PhantomData<fn(Brand) -> Brand>,
}

impl<'store> StoreWriterSession<'store, ()> {
    pub(crate) fn begin(store: &'store mut Store) -> Result<Self, StoreError> {
        refuse_legacy_begin_for_c2(store)?;
        let schema_version = pragma_i64(&store.connection, "user_version")?;
        if schema_version != crate::SCHEMA_VERSION {
            return Err(StoreError::SchemaVersionMismatch {
                found: schema_version,
                supported: crate::SCHEMA_VERSION,
            });
        }
        Self::begin_with_brand(store, true, true)
    }
}

impl<'store, 'id> StoreWriterSession<'store, VerificationBrand<'id>> {
    pub(crate) fn begin_runtime_authority(
        store: &'store mut Store,
        _brand: &VerificationBrand<'id>,
    ) -> Result<Self, StoreError> {
        // This Gen4 authority-event path remains valid only before C2
        // governance. Exact C2 transition effects use their closed branded
        // coordinator/append consumer instead of this compatibility surface.
        refuse_legacy_begin_for_c2(store)?;
        // Authority operations derive and recheck their exact occurrence or
        // zero/multiple cardinality inside their own Store transaction.  The
        // session therefore must not preselect a genesis identity.
        Self::begin_with_brand(store, false, false)
    }

    /// Atomically establish the occurrence-bound immutable dependency root
    /// from sealed verification evidence.  Neither this session nor the
    /// evidence can be converted into the other.
    pub fn establish_runtime_dependency_trust_root(
        &mut self,
        evidence: &ResolvedControllingActivation<'id>,
    ) -> Result<crate::RuntimeDependencyEstablishmentReceipt, StoreError> {
        self.check_fence()?;
        self.store
            .establish_runtime_dependency_trust_root_bare(evidence)
    }

    /// Persist an authentic non-accepted migration disposition and permanently
    /// evidence-freeze the predecessor occurrence without establishing a root.
    pub fn classify_runtime_authority_migration(
        &mut self,
        evidence: &VerifiedMigrationClassification<'id>,
    ) -> Result<crate::RuntimeAuthorityMigrationFreezeReceipt, StoreError> {
        self.check_fence()?;
        self.store.freeze_runtime_authority_migration_bare(evidence)
    }

    /// Persist an authentic absent, singleton-empty, or multiple-genesis disposition and freeze
    /// the non-migratable schema-v7 predecessor without establishing it.
    pub fn classify_v7_cardinality_disposition(
        &mut self,
        evidence: &VerifiedV7CardinalityDisposition<'id>,
    ) -> Result<crate::RuntimeAuthorityCardinalityFreezeReceipt, StoreError> {
        self.check_fence()?;
        self.store.freeze_v7_cardinality_disposition_bare(evidence)
    }

    /// Append one verified Store-resident A1 rotation.
    pub fn append_runtime_operator_authority_rotation(
        &mut self,
        event: &VerifiedOperatorAuthorityRotation<'id>,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_verified_runtime_authority_event(
            "runtime_operator_authority_rotations",
            event.record_digest(),
            event.canonical_bytes(),
            event.resulting_candidate_set_digest(),
            |current| event.reverify_store_owned_presented_set(current),
        )
    }

    /// Append one verified Store-resident successor A2 activation.
    pub fn append_runtime_resident_activation_successor(
        &mut self,
        event: &VerifiedResidentActivationSuccessor<'id>,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_verified_runtime_authority_event(
            "runtime_resident_activation_successors",
            event.record_digest(),
            event.canonical_bytes(),
            event.resulting_candidate_set_digest(),
            |current| event.reverify_store_owned_presented_set(current),
        )
    }

    /// Append one verified prospective activation revocation.
    pub fn append_runtime_activation_revocation(
        &mut self,
        event: &VerifiedActivationRevocation<'id>,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_verified_runtime_authority_event(
            "runtime_activation_revocations",
            event.record_digest(),
            event.canonical_bytes(),
            event.resulting_candidate_set_digest(),
            |current| event.reverify_store_owned_presented_set(current),
        )
    }
}

impl<'store, Brand> StoreWriterSession<'store, Brand> {
    fn begin_with_brand(
        store: &'store mut Store,
        prepare_persistent_writer: bool,
        bind_unambiguous_genesis: bool,
    ) -> Result<Self, StoreError> {
        store.ensure_runtime_authority_not_frozen()?;
        let state = gen4_path_lock_state(&store.writer_key);
        if state.fenced.load(Ordering::SeqCst) {
            return Err(StoreError::WriteFenced(
                store.writer_key.display().to_string(),
            ));
        }
        let guard = state.write_mutex.try_lock().map_err(|_| {
            StoreError::WriterSessionUnavailable(store.writer_key.display().to_string())
        })?;
        let genesis = if bind_unambiguous_genesis {
            store.genesis_for_writer_session()?
        } else {
            None
        };
        let store_key = store.writer_key.clone();
        let session = Self {
            store,
            state,
            _guard: guard,
            store_key,
            occurrence: None,
            physical_generation: None,
            closed_c2_backend: None,
            genesis,
            _brand: PhantomData,
        };
        // Connection preparation occurs only after the unforgeable session
        // value exists and owns the process mutex. This preserves Gen4
        // behavior while enforcing the CAP-H23 constructor-before-effect
        // ordering.
        if prepare_persistent_writer {
            session.store.prepare_writer_connection()?;
        }
        Ok(session)
    }

    /// The exact store identity this session is bound to.
    #[cfg(test)]
    pub(crate) fn store_key(&self) -> &Path {
        &self.store_key
    }

    /// The sole genesis identity recorded at construction, when present.
    #[cfg(test)]
    pub(crate) fn genesis(&self) -> Option<&str> {
        self.genesis.as_deref()
    }

    fn check_fence(&self) -> Result<(), StoreError> {
        if self.state.fenced.load(Ordering::SeqCst) {
            return Err(StoreError::WriteFenced(
                self.store_key.display().to_string(),
            ));
        }
        Ok(())
    }

    /// Explicitly close the session. `Drop` is equivalent.
    pub fn finish(self) -> Result<(), StoreError> {
        drop(self);
        Ok(())
    }
}

fn c2_session_store_error(refusal: C2WriterSessionRefusalV1) -> StoreError {
    StoreError::Invariant(format!("C2 writer-session refused: {refusal:?}"))
}

fn verify_live_c2_ordinary_session(
    session: &StoreWriterSession<'_>,
) -> Result<(), C2WriterSessionRefusalV1> {
    let backend = session
        .closed_c2_backend
        .ok_or(C2WriterSessionRefusalV1::SessionIsNotC2Ordinary)?;
    verify_rr_06_sole_post_receipt_constructor(backend)
        .map_err(|_| C2WriterSessionRefusalV1::ClosedBackendMismatch)?;
    let occurrence = session
        .occurrence
        .as_ref()
        .ok_or(C2WriterSessionRefusalV1::OccurrenceMismatch)?;
    let _physical_generation = session
        .physical_generation
        .as_ref()
        .ok_or(C2WriterSessionRefusalV1::PhysicalGenerationMismatch)?;
    if session.genesis.as_deref() != Some(occurrence.as_str()) {
        return Err(C2WriterSessionRefusalV1::OccurrenceMismatch);
    }
    if session.state.fenced.load(Ordering::SeqCst) {
        return Err(C2WriterSessionRefusalV1::SessionIsNotC2Ordinary);
    }
    Ok(())
}

/// N-60 is the sole ordinary C2 writer-session constructor in this module.
///
/// Its caller must already have performed the complete P-06 resolution and
/// backend close. This function rechecks the live closed backend, the exact
/// Store occurrence, a present projection for contradiction, the C2 root
/// marker, the process mutex, and the fence. The retained backend in turn
/// retains the verified exclusive flock. No special brand or generic signer
/// surface is created.
pub(crate) fn construct_n_60_ordinary_session_requires_closed_state_process_mutex<'store>(
    store: &'store mut Store,
    closed_backend: &'store ClosedC2StoreBackendV1<'store>,
    occurrence: &StoreOccurrenceIdentityV1,
    physical_generation: &PhysicalStoreGenerationIdentityV1,
) -> Result<StoreWriterSession<'store>, StoreError> {
    store.ensure_runtime_authority_not_frozen()?;
    if !has_c2_governance_marker(store)? {
        return Err(c2_session_store_error(
            C2WriterSessionRefusalV1::C2RootMarkerMissing,
        ));
    }
    verify_rr_06_sole_post_receipt_constructor(closed_backend)
        .map_err(|_| c2_session_store_error(C2WriterSessionRefusalV1::ClosedBackendMismatch))?;
    let genesis = store.genesis_for_writer_session()?;
    if genesis.as_deref() != Some(occurrence.as_str()) {
        return Err(c2_session_store_error(
            C2WriterSessionRefusalV1::OccurrenceMismatch,
        ));
    }
    verify_c2_projection_if_present(store, occurrence, physical_generation)
        .map_err(c2_session_store_error)?;

    let inode_key = closed_backend_lock_inode_key_v1(closed_backend)
        .map_err(|_| c2_session_store_error(C2WriterSessionRefusalV1::ClosedBackendMismatch))?;
    let state = c2_inode_lock_state(inode_key);
    if state.fenced.load(Ordering::SeqCst) {
        return Err(StoreError::WriteFenced(
            store.writer_key.display().to_string(),
        ));
    }
    let guard = state.write_mutex.try_lock().map_err(|_| {
        StoreError::WriterSessionUnavailable(store.writer_key.display().to_string())
    })?;
    let store_key = store.writer_key.clone();
    let session = StoreWriterSession {
        store,
        state,
        _guard: guard,
        store_key,
        occurrence: Some(occurrence.clone()),
        physical_generation: Some(physical_generation.clone()),
        closed_c2_backend: Some(closed_backend),
        genesis,
        _brand: PhantomData,
    };
    // This runs only after the session capability exists and retains both the
    // process mutex and closed-backend/exclusive-flock correspondence.
    session.store.prepare_writer_connection()?;
    Ok(session)
}

/// N-60 exact live verifier. It never constructs or upgrades authority.
pub(crate) fn verify_n_60_ordinary_session_requires_closed_state_process_mutex(
    session: &StoreWriterSession<'_>,
) -> Result<(), C2WriterSessionRefusalV1> {
    verify_live_c2_ordinary_session(session)
}

/// WU-10 named CAP-H23 census witness. This is deliberately not a second
/// ordinary-session constructor.
pub(crate) fn construct_wu_10_immutable_wu_storewritersession_complete_cap_h23_sole<
    'session,
    'store,
>(
    session: &'session StoreWriterSession<'store>,
) -> Result<C2WriterSessionLawWitnessV1<'session, 'store>, C2WriterSessionRefusalV1> {
    verify_live_c2_ordinary_session(session)?;
    Ok(C2WriterSessionLawWitnessV1 {
        session,
        law: C2WriterSessionLawV1::
            ImmutableWUStoreWriterSessionCompleteCAPH23SoleWriterOwnerWriterVerified,
    })
}

/// WU-10 confirms the inert census witness still borrows one live C2 ordinary
/// session and nothing else.
pub(crate) fn verify_wu_10_immutable_wu_storewritersession_complete_cap_h23_sole(
    witness: &C2WriterSessionLawWitnessV1<'_, '_>,
) -> Result<(), C2WriterSessionRefusalV1> {
    if witness.law
        != C2WriterSessionLawV1::
            ImmutableWUStoreWriterSessionCompleteCAPH23SoleWriterOwnerWriterVerified
    {
        return Err(C2WriterSessionRefusalV1::SessionIsNotC2Ordinary);
    }
    verify_live_c2_ordinary_session(witness.session)
}

/// N-15 associates the session only with the exact backend borrow it retains.
pub(crate) fn construct_n_15_closed_backend_ordinary_session_association<'session, 'store>(
    backend: &'session ClosedC2StoreBackendV1<'store>,
    session: &'session StoreWriterSession<'store>,
) -> Result<ClosedBackendOrdinarySessionAssociationV1<'session, 'store>, C2WriterSessionRefusalV1> {
    verify_live_c2_ordinary_session(session)?;
    let retained = session
        .closed_c2_backend
        .ok_or(C2WriterSessionRefusalV1::SessionIsNotC2Ordinary)?;
    if !std::ptr::eq(retained, backend) {
        return Err(C2WriterSessionRefusalV1::ClosedBackendMismatch);
    }
    Ok(ClosedBackendOrdinarySessionAssociationV1 { backend, session })
}

/// N-15 exact close-before-session association verifier.
pub(crate) fn verify_n_15_close_then_begin_session_order(
    association: &ClosedBackendOrdinarySessionAssociationV1<'_, '_>,
) -> Result<(), C2WriterSessionRefusalV1> {
    verify_live_c2_ordinary_session(association.session)?;
    match association.session.closed_c2_backend {
        Some(retained) if std::ptr::eq(retained, association.backend) => Ok(()),
        _ => Err(C2WriterSessionRefusalV1::ClosedBackendMismatch),
    }
}

/// SEAM-04 produces a nominally typed occurrence/physical-generation split
/// from one already verified C2 session.
pub(crate) fn construct_seam_04_immutable_seam_identity_split_existing_writer_session<
    'borrow,
    'store,
>(
    session: &'borrow StoreWriterSession<'store>,
) -> Result<C2WriterIdentitySplitWitnessV1<'borrow>, C2WriterSessionRefusalV1> {
    verify_live_c2_ordinary_session(session)?;
    Ok(C2WriterIdentitySplitWitnessV1 {
        occurrence: session
            .occurrence
            .as_ref()
            .ok_or(C2WriterSessionRefusalV1::OccurrenceMismatch)?,
        physical_generation: session
            .physical_generation
            .as_ref()
            .ok_or(C2WriterSessionRefusalV1::PhysicalGenerationMismatch)?,
    })
}

/// SEAM-04 refuses either coordinate being absent or the legacy occurrence
/// accessor being used as a physical-generation compatibility alias.
pub(crate) fn verify_seam_04_immutable_seam_identity_split_existing_writer_session(
    witness: &C2WriterIdentitySplitWitnessV1<'_>,
) -> Result<(), C2WriterSessionRefusalV1> {
    if witness.occurrence.as_str().is_empty() {
        return Err(C2WriterSessionRefusalV1::OccurrenceMismatch);
    }
    if witness.physical_generation.digest().as_str().is_empty()
        || witness.physical_generation.digest().as_str() == witness.occurrence.as_str()
    {
        return Err(C2WriterSessionRefusalV1::PhysicalGenerationMismatch);
    }
    Ok(())
}

/// SEAM-05 executes and records the required hard refusal of the legacy
/// ordinary constructor for a C2-governed root. It cannot return a session.
fn construct_seam_05_immutable_seam_legacy_session_legacy_begin_writer(
    store: &mut Store,
) -> Result<C2LegacySessionRefusalWitnessV1, C2WriterSessionRefusalV1> {
    if !has_c2_governance_marker(store)
        .map_err(|_| C2WriterSessionRefusalV1::ProjectionCandidateSetMalformed)?
    {
        return Err(C2WriterSessionRefusalV1::C2RootMarkerMissing);
    }
    // Exercise the sole Store-owned legacy factory.  Calling the private
    // session constructor here would create a second constructor edge even
    // though this route only expects refusal.
    match store.begin_writer_session() {
        Err(StoreError::Invariant(message)) if message == LEGACY_C2_SESSION_REFUSAL => {
            Ok(C2LegacySessionRefusalWitnessV1 {
                law: C2WriterSessionLawV1::
                    ImmutableSEAMLegacySessionLegacyBeginWriterSessionVerificationBrandVerified,
            })
        }
        Ok(session) => {
            drop(session);
            Err(C2WriterSessionRefusalV1::LegacyBeginOnGovernedRoot)
        }
        Err(_) => Err(C2WriterSessionRefusalV1::LegacyBeginOnGovernedRoot),
    }
}

/// SEAM-05 exact inert-refusal verifier.
pub(crate) fn verify_seam_05_immutable_seam_legacy_session_legacy_begin_writer(
    witness: &C2LegacySessionRefusalWitnessV1,
) -> Result<(), C2WriterSessionRefusalV1> {
    if witness.law
        == C2WriterSessionLawV1::
            ImmutableSEAMLegacySessionLegacyBeginWriterSessionVerificationBrandVerified
    {
        Ok(())
    } else {
        Err(C2WriterSessionRefusalV1::LegacyBeginOnGovernedRoot)
    }
}

#[cfg(test)]
use crate::GenesisInput;
use crate::governed_custody::{
    CustodiedAcquisition, GovernedAcquisitionCustodyInput, GovernedCustody,
    GovernedCustodyReservation, GovernedCustodyState, GovernedDerivationCustodyClaim,
    GovernedProjectionRecovery, GovernedProjectionVerification, GovernedProtectedTerminalInput,
    GovernedProtectedTerminalization,
};
use crate::{
    AdmissionInput, AdmittedCollectionCompletion, AdmittedCollectionView,
    AdmittedRunLevelDiagnosticCompletion, BindingEventInput, BindingMaterializationInput,
    CollectionInput, CollectionReceipt, DiagnosticArtifactCommitInput,
    DiagnosticArtifactImportInput, DiagnosticArtifactImportReceipt, EvaluationInput,
    EvaluationReceipt, FindingEventInput, GovernedCustodyCommitment, GovernedProjectionPublication,
    LegacyReferenceInput, NonSuccessCollectionArtifactCommit, ProfileDescriptorInput,
    ProviderIntakeCommit, RunResultStatusInput, RuntimeRecordAppendReceipt,
    RuntimeRecordBatchInput, StatusEventInput, UnavailableDiagnosticArtifactImportInput,
    UpgradeReceiptInput,
};
use nq_protocol::Sha256Digest;

/// The complete public mutation surface of the Store. Each method checks
/// the write fence and forwards to the crate-internal implementation.
impl StoreWriterSession<'_, ()> {
    /// Append one profile descriptor snapshot.
    pub fn append_profile_descriptor(
        &mut self,
        descriptor: &ProfileDescriptorInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_profile_descriptor(descriptor)
    }

    /// Append one admission with its local provider admission.
    pub fn append_admission(&mut self, admission: &AdmissionInput) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_admission(admission)
    }

    /// Begin one binding transition with its materialization intent.
    pub fn begin_binding_transition(
        &mut self,
        event: &BindingEventInput,
        intent: &BindingMaterializationInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.begin_binding_transition(event, intent)
    }

    /// Complete one binding materialization.
    pub fn complete_binding_materialization(
        &mut self,
        completion: &BindingMaterializationInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.complete_binding_materialization(completion)
    }

    /// Atomically append one admitted collection.
    pub fn commit_collection(
        &mut self,
        collection: &CollectionInput,
    ) -> Result<CollectionReceipt, StoreError> {
        self.check_fence()?;
        Store::commit_collection(collection)
    }

    /// Append one runtime-ledger batch with its checkpoint.
    pub fn append_runtime_records(
        &mut self,
        batch: &RuntimeRecordBatchInput,
    ) -> Result<RuntimeRecordAppendReceipt, StoreError> {
        self.check_fence()?;
        self.store.append_runtime_records(batch)
    }

    /// Import one unavailable diagnostic artifact.
    pub fn import_unavailable_diagnostic_artifact(
        &mut self,
        input: &UnavailableDiagnosticArtifactImportInput,
    ) -> Result<DiagnosticArtifactImportReceipt, StoreError> {
        self.check_fence()?;
        self.store.import_unavailable_diagnostic_artifact(input)
    }

    /// Import one diagnostic artifact with exact bytes.
    pub fn import_diagnostic_artifact(
        &mut self,
        input: &DiagnosticArtifactImportInput,
    ) -> Result<DiagnosticArtifactImportReceipt, StoreError> {
        self.check_fence()?;
        self.store.import_diagnostic_artifact(input)
    }

    /// Atomically append one admitted collection with a caller-built completion.
    pub fn commit_admitted_collection<T, E, F>(
        &mut self,
        collection: &CollectionInput,
        build: F,
    ) -> Result<ProviderIntakeCommit<T>, E>
    where
        E: From<StoreError>,
        F: FnOnce(
            &AdmittedCollectionView<'_, '_>,
            &CollectionReceipt,
        ) -> Result<AdmittedCollectionCompletion<T>, E>,
    {
        self.check_fence().map_err(E::from)?;
        self.store.commit_admitted_collection(collection, build)
    }

    /// Atomically append one run-level admitted diagnostic collection.
    pub fn commit_admitted_run_level_diagnostic<T, E, F>(
        &mut self,
        collection: &CollectionInput,
        build: F,
    ) -> Result<ProviderIntakeCommit<T>, E>
    where
        E: From<StoreError>,
        F: FnOnce(
            &AdmittedCollectionView<'_, '_>,
            &CollectionReceipt,
        ) -> Result<AdmittedRunLevelDiagnosticCompletion<T>, E>,
    {
        self.check_fence().map_err(E::from)?;
        self.store
            .commit_admitted_run_level_diagnostic(collection, build)
    }

    /// Atomically seal and publish one governed admitted run-level diagnostic.
    pub fn commit_governed_admitted_run_level_diagnostic_with_publication<T, E, F, G, H>(
        &mut self,
        collection: &CollectionInput,
        build: F,
        custody: &mut GovernedCustody,
        build_final_closure: G,
        after_final_seal: H,
    ) -> Result<ProviderIntakeCommit<T>, E>
    where
        E: From<StoreError>,
        F: FnOnce(&CollectionReceipt) -> Result<AdmittedRunLevelDiagnosticCompletion<T>, E>,
        G: FnOnce(&GovernedProjectionPublication) -> Result<Vec<u8>, E>,
        H: FnOnce(&GovernedCustodyCommitment) -> Result<(), E>,
    {
        self.check_fence().map_err(E::from)?;
        self.store
            .commit_governed_admitted_run_level_diagnostic_with_publication(
                collection,
                build,
                custody,
                build_final_closure,
                after_final_seal,
            )
    }

    /// Atomically append one run-bearing non-success collection.
    pub fn commit_non_success_collection(
        &mut self,
        collection: &CollectionInput,
        result: &RunResultStatusInput,
    ) -> Result<ProviderIntakeCommit<()>, StoreError> {
        self.check_fence()?;
        self.store.commit_non_success_collection(collection, result)
    }

    /// Atomically append one non-success collection with its artifact.
    pub fn commit_non_success_collection_with_artifact(
        &mut self,
        collection: &CollectionInput,
        result: &RunResultStatusInput,
        diagnostic_artifact: Option<&DiagnosticArtifactCommitInput>,
    ) -> Result<NonSuccessCollectionArtifactCommit, StoreError> {
        self.check_fence()?;
        self.store.commit_non_success_collection_with_artifact(
            collection,
            result,
            diagnostic_artifact,
        )
    }

    /// Atomically append one governed non-success run-level diagnostic.
    pub fn commit_governed_non_success_run_level_diagnostic(
        &mut self,
        collection: &CollectionInput,
        result: &RunResultStatusInput,
        diagnostic_artifact: &DiagnosticArtifactCommitInput,
    ) -> Result<NonSuccessCollectionArtifactCommit, StoreError> {
        self.check_fence()?;
        self.store.commit_governed_non_success_run_level_diagnostic(
            collection,
            result,
            diagnostic_artifact,
        )
    }

    /// Atomically seal and publish one governed non-success run-level diagnostic.
    pub fn commit_governed_non_success_run_level_diagnostic_with_publication<E, G, H>(
        &mut self,
        collection: &CollectionInput,
        result: &RunResultStatusInput,
        diagnostic_artifact: &DiagnosticArtifactCommitInput,
        custody: &mut GovernedCustody,
        build_final_closure: G,
        after_final_seal: H,
    ) -> Result<NonSuccessCollectionArtifactCommit, E>
    where
        E: From<StoreError>,
        G: FnOnce(&GovernedProjectionPublication) -> Result<Vec<u8>, E>,
        H: FnOnce(&GovernedCustodyCommitment) -> Result<(), E>,
    {
        self.check_fence().map_err(E::from)?;
        self.store
            .commit_governed_non_success_run_level_diagnostic_with_publication(
                collection,
                result,
                diagnostic_artifact,
                custody,
                build_final_closure,
                after_final_seal,
            )
    }

    /// Append one evaluation with an optional finding event.
    pub fn commit_evaluation(
        &mut self,
        evaluation: &EvaluationInput,
        finding: Option<&FindingEventInput>,
    ) -> Result<EvaluationReceipt, StoreError> {
        self.check_fence()?;
        self.store.commit_evaluation(evaluation, finding)
    }

    /// Append one status event.
    pub fn record_status(&mut self, status: &StatusEventInput) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.record_status(status)
    }

    /// Append the store's sole genesis record.
    #[cfg(test)]
    pub fn append_genesis(&mut self, genesis: &GenesisInput) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_genesis(genesis)
    }

    /// Append an opaque historical reference.
    pub fn append_legacy_reference(
        &mut self,
        reference: &LegacyReferenceInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_legacy_reference(reference)
    }

    /// Append one schema-upgrade receipt.
    pub fn append_upgrade_receipt(
        &mut self,
        receipt: &UpgradeReceiptInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_upgrade_receipt(receipt)
    }

    /// Reserve governed custody: create the exact arena for one reservation.
    pub fn reserve_governed_custody(
        &mut self,
        reservation: GovernedCustodyReservation,
        exact_dependency_closure_bytes: &[u8],
    ) -> Result<GovernedCustody, StoreError> {
        self.check_fence()?;
        self.store
            .reserve_governed_custody(reservation, exact_dependency_closure_bytes)
    }

    /// Recover every pending governed projection at startup.
    pub fn recover_pending_governed_projections(
        &mut self,
    ) -> Result<Vec<GovernedProjectionRecovery>, StoreError> {
        self.check_fence()?;
        self.store.recover_pending_governed_projections()
    }

    /// Recover one pending governed projection and mark it indexed.
    pub fn recover_governed_projection_and_mark_indexed(
        &mut self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProjectionRecovery, StoreError> {
        self.check_fence()?;
        self.store
            .recover_governed_projection_and_mark_indexed(reservation_record_id)
    }

    /// Verify one sealed governed projection and mark it indexed.
    pub fn verify_governed_projection_and_mark_indexed(
        &mut self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProjectionVerification, StoreError> {
        self.check_fence()?;
        self.store
            .verify_governed_projection_and_mark_indexed(reservation_record_id)
    }

    /// Claim the exact execution launch in governed custody.
    pub fn claim_custody_launch(
        &mut self,
        custody: &mut GovernedCustody,
        execution_launch_record_id: Sha256Digest,
        claimed_at: String,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        custody.claim_launch(execution_launch_record_id, claimed_at)
    }

    /// Seal the exact provider acquisition in governed custody.
    pub fn seal_custody_acquisition(
        &mut self,
        custody: &mut GovernedCustody,
        input: GovernedAcquisitionCustodyInput,
    ) -> Result<CustodiedAcquisition, StoreError> {
        self.check_fence()?;
        custody.seal_acquisition(input)
    }

    /// Claim the exact derivation in governed custody.
    pub fn claim_custody_derivation(
        &mut self,
        custody: &mut GovernedCustody,
        claim: GovernedDerivationCustodyClaim,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        custody.claim_derivation(claim)
    }

    /// Terminalize the exact claimed launch in governed custody.
    pub fn terminalize_custody_immediate_launch(
        &mut self,
        custody: &mut GovernedCustody,
        input: GovernedProtectedTerminalInput,
    ) -> Result<GovernedProtectedTerminalization, StoreError> {
        self.check_fence()?;
        custody.terminalize_immediate_launch(input)
    }

    /// Reopen custody state after an indeterminate write.
    pub fn reopen_custody_state_after_indeterminate_write(
        &mut self,
        custody: &mut GovernedCustody,
    ) -> Result<GovernedCustodyState, StoreError> {
        self.check_fence()?;
        custody.reopen_state_after_indeterminate_write()
    }
}

impl StoreWriterSession<'_> {
    /// The sole Gen4 genesis/occurrence identity this session is bound to,
    /// when present.
    ///
    /// This compatibility accessor is intentionally occurrence-only. It is
    /// never a C2 physical Store-generation identity and cannot satisfy the
    /// C2 physical-generation accessor below.
    #[must_use]
    pub fn bound_generation(&self) -> Option<&str> {
        self.genesis.as_deref()
    }

    /// Exact nominal Store occurrence for a C2 ordinary session.
    #[must_use]
    pub(crate) fn bound_c2_occurrence(&self) -> Option<&StoreOccurrenceIdentityV1> {
        self.occurrence.as_ref()
    }

    /// Exact physical Store-generation identity for a C2 ordinary session.
    /// This has no string or occurrence compatibility alias.
    #[must_use]
    pub(crate) fn bound_c2_physical_generation(
        &self,
    ) -> Option<&PhysicalStoreGenerationIdentityV1> {
        self.physical_generation.as_ref()
    }

    /// Rebuild the runtime-record lookup projection.
    pub fn rebuild_runtime_record_lookup(
        &mut self,
    ) -> Result<crate::RuntimeRecordLookupStatus, StoreError> {
        self.check_fence()?;
        self.store.rebuild_runtime_record_lookup()
    }

    /// Rebuild the current status projection.
    pub fn rebuild_status_current_projection(&mut self) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.rebuild_status_current_projection()
    }

    /// Rebuild the current finding and status projections.
    pub fn rebuild_current_projections(&mut self) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.rebuild_current_projections()
    }

    /// Enqueue one notification.
    pub fn enqueue_notification(
        &mut self,
        notification: &crate::NotificationInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.enqueue_notification(notification)
    }

    /// Append one notification delivery attempt.
    pub fn append_notification_attempt(
        &mut self,
        attempt: &crate::NotificationAttemptInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_notification_attempt(attempt)
    }

    /// Append one retention tombstone.
    pub fn append_retention_tombstone(
        &mut self,
        tombstone: &crate::RetentionTombstoneInput,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store.append_retention_tombstone(tombstone)
    }
}
