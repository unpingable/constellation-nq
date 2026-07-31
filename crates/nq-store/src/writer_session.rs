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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};

use crate::{Store, StoreError};

/// Shared per-store-path writer state: one process-local non-reentrant
/// write lock and the write fence. The C2 filesystem lock layer is a
/// later, separate stage; this is the process layer only.
struct PathLockState {
    write_mutex: Mutex<()>,
    fenced: AtomicBool,
}

static STORE_WRITER_LOCKS: LazyLock<Mutex<BTreeMap<PathBuf, &'static PathLockState>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static IN_MEMORY_WRITER_KEYS: AtomicU64 = AtomicU64::new(1);

fn path_lock_state(key: &Path) -> &'static PathLockState {
    let mut registry = STORE_WRITER_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.entry(key.to_path_buf()).or_insert_with(|| {
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

/// Acquire the per-path process write lock for the maintenance class
/// (schema migrations and backup/preservation paths), which operate on
/// closed paths under their own exclusive recovery transactions. Keys
/// are deduplicated and acquired in sorted order.
pub(crate) fn acquire_maintenance_locks(
    paths: &[&Path],
) -> Result<Vec<MutexGuard<'static, ()>>, StoreError> {
    let mut keys = paths
        .iter()
        .map(|path| writer_key_for_path(Some(path)))
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    let mut guards = Vec::with_capacity(keys.len());
    for key in keys {
        let state = path_lock_state(&key);
        if state.fenced.load(Ordering::SeqCst) {
            return Err(StoreError::WriteFenced(key.display().to_string()));
        }
        guards.push(
            state
                .write_mutex
                .try_lock()
                .map_err(|_| StoreError::WriterSessionUnavailable(key.display().to_string()))?,
        );
    }
    Ok(guards)
}

/// Test and future-C2 fence control: fence a store path so all session
/// construction and every session method refuses.
#[cfg(test)]
pub(crate) fn fence_store_writes_for_test(key: &Path) {
    path_lock_state(key).fenced.store(true, Ordering::SeqCst);
}

/// Unforgeable writer capability for exactly one store.
///
/// Not `Clone`, not `Copy`, not `Serialize`, not `Deserialize`, not
/// `Default`, and not publicly constructible. It borrows its store
/// mutably for its entire lifetime, so it cannot outlive the store,
/// cannot migrate to another store or generation, and cannot be
/// replayed after `Drop`.
pub struct StoreWriterSession<'store> {
    store: &'store mut Store,
    state: &'static PathLockState,
    _guard: MutexGuard<'static, ()>,
    store_key: PathBuf,
    genesis: Option<String>,
}

impl<'store> StoreWriterSession<'store> {
    pub(crate) fn begin(store: &'store mut Store) -> Result<Self, StoreError> {
        let state = path_lock_state(&store.writer_key);
        if state.fenced.load(Ordering::SeqCst) {
            return Err(StoreError::WriteFenced(
                store.writer_key.display().to_string(),
            ));
        }
        let guard = state.write_mutex.try_lock().map_err(|_| {
            StoreError::WriterSessionUnavailable(store.writer_key.display().to_string())
        })?;
        let genesis = store.genesis_for_writer_session()?;
        let store_key = store.writer_key.clone();
        Ok(Self {
            store,
            state,
            _guard: guard,
            store_key,
            genesis,
        })
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
    EvaluationReceipt, FindingEventInput, GenesisInput, GovernedCustodyCommitment,
    GovernedProjectionPublication, LegacyReferenceInput, NonSuccessCollectionArtifactCommit,
    ProfileDescriptorInput, ProviderIntakeCommit, RunResultStatusInput, RuntimeRecordAppendReceipt,
    RuntimeRecordBatchInput, StatusEventInput, UnavailableDiagnosticArtifactImportInput,
    UpgradeReceiptInput,
};
use nq_protocol::Sha256Digest;

/// The complete public mutation surface of the Store. Each method checks
/// the write fence and forwards to the crate-internal implementation.
impl StoreWriterSession<'_> {
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

    /// Establish the immutable dependency-admission trust root for this store.
    pub fn establish_runtime_dependency_trust_root(
        &mut self,
        trust_anchor_id: &Sha256Digest,
    ) -> Result<(), StoreError> {
        self.check_fence()?;
        self.store
            .establish_runtime_dependency_trust_root(trust_anchor_id)
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
    /// The sole genesis identity this session is bound to, when present.
    #[must_use]
    pub fn bound_generation(&self) -> Option<&str> {
        self.genesis.as_deref()
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
