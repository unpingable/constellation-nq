//! Contract-to-schema-v7 dependency-bound runtime ledger bridge.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use nix::time::{ClockId, clock_gettime};
use nq_host_role_contract::{
    ExternalRecordCatalog, IdentityCatalog, IdentityKind, IdentityRef, RecordRef, RuntimeRecordSet,
    RuntimeSchema, Timestamp, Token, ValidatedRuntimeRecord, ValidationContext,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use nq_runtime_dependency_authority::{
    ActivationContext, ActivationExpectations, EstablishmentArm, GenesisAuthorityCustody,
    MigrationReceiptBytes, PresentedAuthoritySet, RestartExpectations,
    V7CardinalityDispositionBytes, resolve_for_restart, verify_for_establishment,
    verify_nonaccepted_migration_classification, verify_v7_cardinality_disposition,
    with_verification_brand,
};
use nq_store::{
    BackupArtifact, CanonicalDocument, GovernedCustodyInventoryEntry, GovernedCustodyReservation,
    GovernedProtectedFailureAccess, MAX_PUBLIC_QUERY_ROWS,
    RuntimeAuthorityCardinalityFreezeReceipt, RuntimeAuthorityMigrationFreezeReceipt,
    RuntimeCheckpointDependencyBinding, RuntimeCheckpointDependencyInput,
    RuntimeDependencyGenerationByteState, RuntimeLedgerCheckpoint, RuntimeRecordAppendDisposition,
    RuntimeRecordBatchInput, RuntimeRecordInput, RuntimeRecordRow, Store, StoreError,
    runtime_record_batch_digest,
};
use serde_json::{Value, json};

use super::{
    AuthenticatedRuntimeDependencyClosure, DependencyCustodyError, ExactDependencyCustodyBinding,
    ExternalDependencyAvailability, GovernedPrelaunchRequest, InspectorPage, InspectorProjection,
    InspectorProjectionState, NativeDeadlinePrelaunchRequest, NativeDeadlineProvenance,
    PreparedGovernedInvocation, Result, RuntimeDependencies, RuntimeError,
    prelaunch::exact_append_membership, production_identity,
};

const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";
const LINUX_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[cfg(feature = "test-support")]
#[path = "test_support.rs"]
pub mod test_support;

/// One exact canonical record proposed for atomic append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendRecord {
    /// Declared immutable record identity.
    pub record_id: String,
    /// Exact record schema.
    pub record_schema: String,
    /// Exact canonical bytes.
    pub canonical_bytes: Vec<u8>,
    /// RFC 3339 time attached to this ledger entry.
    pub committed_at: String,
}

impl AppendRecord {
    /// Constructs an append from a validated contract record.
    #[must_use]
    pub fn from_contract(record: &ValidatedRuntimeRecord, committed_at: impl Into<String>) -> Self {
        Self {
            record_id: record.record_id().to_string(),
            record_schema: record.schema().as_str().to_owned(),
            canonical_bytes: record.canonical_bytes().to_vec(),
            committed_at: committed_at.into(),
        }
    }

    /// Constructs the sole opaque external record class admitted to the
    /// runtime ledger.
    ///
    /// Validation of canonical bytes and exact schema happens before append.
    #[must_use]
    pub fn provider_intake(
        record_id: impl Into<String>,
        canonical_bytes: Vec<u8>,
        committed_at: impl Into<String>,
    ) -> Self {
        Self {
            record_id: record_id.into(),
            record_schema: PROVIDER_INTAKE_SCHEMA.to_owned(),
            canonical_bytes,
            committed_at: committed_at.into(),
        }
    }
}

/// One atomic runtime append request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendRequest {
    /// Immutable checkpoint identity chosen by the caller.
    pub checkpoint_id: String,
    /// Ordered exact records committed by the checkpoint.
    pub records: Vec<AppendRecord>,
}

/// Runtime-level append disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendDisposition {
    /// A new atomic checkpoint was committed.
    Committed,
    /// The current checkpoint was replayed byte-for-byte.
    ExactReplay,
}

/// Result of an append or exact replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    /// Runtime-level disposition.
    pub disposition: AppendDisposition,
    /// Immutable resulting checkpoint.
    pub checkpoint: RuntimeLedgerCheckpoint,
}

/// Immutable read frontier plus exact restart-dependency binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    /// Ledger frontier; absent only for an empty ledger.
    pub checkpoint: Option<RuntimeLedgerCheckpoint>,
    /// Identity of the exact catalog/reference pair used to reopen the graph.
    pub dependency_binding_digest: Sha256Digest,
}

/// Exact checkpoint-pinned page from the canonical ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReadPage {
    /// Immutable snapshot used for the read.
    pub snapshot: RuntimeSnapshot,
    /// Exclusive sequence cursor.
    pub after_record_sequence: u64,
    /// Exact canonical ledger rows.
    pub records: Vec<RuntimeRecordRow>,
    /// Cursor for another page, absent when complete.
    pub next_after_record_sequence: Option<u64>,
    /// Whether this page completes the snapshot.
    pub complete: bool,
}

/// One exact materialized record in a historical execution-binding closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalMaterializedRecord {
    /// Exact immutable reference.
    pub reference: RecordRef,
    /// Immutable ledger position.
    pub record_sequence: u64,
    /// Exact canonical bytes.
    pub canonical_bytes: Vec<u8>,
    /// Caller-supplied ledger commit time.
    pub committed_at: String,
}

/// Exact, historical dependency closure of one V2 execution binding.
///
/// This resolves what the immutable binding actually named. It does not
/// consult a mutable current role/cohort/witness topology.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalTopology {
    /// Exact V2 binding reference.
    pub binding: RecordRef,
    /// Literal diagnostic identity tuple from the binding.
    pub diagnostic: Value,
    /// Materialized transitive dependency closure.
    pub materialized_records: Vec<HistoricalMaterializedRecord>,
    /// Exact dependencies admitted outside the ledger.
    pub external_references: Vec<RecordRef>,
    /// Exact production identity descriptors carried by the closure.
    pub identities: Vec<IdentityRef>,
}

#[derive(Debug, Clone)]
enum PreparedRecord {
    Contract(ValidatedRuntimeRecord),
    ProviderIntake(RecordRef),
}

struct ReopenedState {
    checkpoint: Option<RuntimeLedgerCheckpoint>,
    rows: Vec<RuntimeRecordRow>,
    rows_by_id: BTreeMap<String, RuntimeRecordRow>,
    records: RuntimeRecordSet,
    provider_intakes: BTreeMap<String, RecordRef>,
    checkpoint_dependencies: BTreeMap<String, RuntimeDependencies>,
    inspector: InspectorProjection,
}

struct GovernedPreflight {
    request_id: String,
    production: super::GovernedProductionIdentity,
    outer_request: RecordRef,
    invocation_decision: RecordRef,
    custody_reservation: RecordRef,
    execution_launch: RecordRef,
    launched_at: String,
    raw_capacity_bytes: u64,
    dependency_closure_capacity_bytes: u64,
    diagnostic_artifact_capacity_bytes: u64,
    projection_capsule_capacity_bytes: u64,
    final_capacity_bytes: u64,
    protected_failure_capacity_bytes: u64,
    complete_records: RuntimeRecordSet,
}

struct NativeDeadlineSample {
    realtime_before_ns: u64,
    boottime_at_ns: u64,
    realtime_after_ns: u64,
    boot_epoch: Sha256Digest,
}

/// Exogenous enrolled-resident tuple against which native A2 authority is
/// verified.  It carries no Store occurrence, root, migration, diagnostic,
/// capacity, Docket, or effect authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAuthorityResidentBinding {
    /// Exact enrolled resident identity.
    pub resident_identity: String,
    /// Exact enrolled resident generation.
    pub resident_generation: u64,
    /// Exact host role.
    pub host_role: String,
    /// Exact host-role manifest generation.
    pub role_manifest_generation: u64,
    /// Closed runtime/backend authority domain.
    pub domain: String,
    /// Minimum supported governing policy version.
    pub policy_floor: u64,
}

trait NativeDeadlineSource {
    fn read_boot_id(&mut self) -> Result<Vec<u8>>;
    fn realtime_ns(&mut self) -> Result<u64>;
    fn boottime_ns(&mut self) -> Result<u64>;
}

struct LinuxNativeDeadlineSource;

impl NativeDeadlineSource for LinuxNativeDeadlineSource {
    fn read_boot_id(&mut self) -> Result<Vec<u8>> {
        fs::read(LINUX_BOOT_ID_PATH)
            .map_err(|_| RuntimeError::NativeDeadlineBootIdentityUnavailable)
    }

    fn realtime_ns(&mut self) -> Result<u64> {
        linux_clock_ns(ClockId::CLOCK_REALTIME, "CLOCK_REALTIME")
    }

    fn boottime_ns(&mut self) -> Result<u64> {
        linux_clock_ns(ClockId::CLOCK_BOOTTIME, "CLOCK_BOOTTIME")
    }
}

/// Restart-safe host-role runtime over one schema-v7 [`Store`].
pub struct HostRoleRuntime {
    store: Store,
    dependencies: RuntimeDependencies,
    checkpoint: Option<RuntimeLedgerCheckpoint>,
    rows: Vec<RuntimeRecordRow>,
    rows_by_id: BTreeMap<String, RuntimeRecordRow>,
    records: RuntimeRecordSet,
    provider_intakes: BTreeMap<String, RecordRef>,
    checkpoint_dependencies: BTreeMap<String, RuntimeDependencies>,
    inspector: InspectorProjection,
    custody_frontiers: Vec<GovernedCustodyInventoryEntry>,
}

impl HostRoleRuntime {
    /// Initializes a new governed schema-v8 occurrence and opens an empty
    /// host-role runtime.
    ///
    /// # Errors
    ///
    /// Refuses an existing database, invalid dependencies, or store
    /// initialization failure.
    pub fn initialize(
        path: impl AsRef<Path>,
        dependencies: RuntimeDependencies,
        authority_custody: &GenesisAuthorityCustody,
        resident: &RuntimeAuthorityResidentBinding,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut created = false;
        let established = (|| -> Result<Store> {
            let mut store = Store::initialize_runtime_authority_candidate(&path)?;
            created = true;
            store.require_runtime_authority_initialization_candidate()?;
            let trust_root = dependencies.custody().trust_anchor_id()?;
            let expectations = fresh_authority_expectations(resident, trust_root);
            let presented = PresentedAuthoritySet::default();

            // Cryptographic and tuple refusal occurs before any authority
            // write. Store repeats exact verification against its own
            // enumeration inside the establishment transaction.
            with_verification_brand(|brand| {
                verify_for_establishment(&brand, authority_custody, &presented, None, &expectations)
                    .map(drop)
            })?;
            store.with_runtime_authority_writer_session(
                |brand, session| -> std::result::Result<(), StoreError> {
                    let resolved = verify_for_establishment(
                        brand,
                        authority_custody,
                        &presented,
                        None,
                        &expectations,
                    )?;
                    session.establish_runtime_dependency_trust_root(&resolved)?;
                    Ok(())
                },
            )?;
            store.consume_runtime_authority_initialization_candidate();
            Ok(store)
        })();
        let store = match established {
            Ok(store) => store,
            Err(error) => {
                if created {
                    remove_failed_fresh_store(&path);
                }
                return Err(error);
            }
        };
        Self::from_store(store, dependencies, authority_custody, resident)
    }

    /// Opens an existing established schema-v8 Store and resolves authority
    /// read-only from the receipt-pinned genesis chain.
    ///
    /// # Errors
    ///
    /// Refuses corruption, dependency substitution, unsupported schemas,
    /// unresolved references, or any failed contract join.
    pub fn open(
        path: impl AsRef<Path>,
        dependencies: RuntimeDependencies,
        authority_custody: &GenesisAuthorityCustody,
        resident: &RuntimeAuthorityResidentBinding,
    ) -> Result<Self> {
        Self::from_store(
            Store::open(path)?,
            dependencies,
            authority_custody,
            resident,
        )
    }

    /// Migrate one exact backup-preserved schema-v7 occurrence through the
    /// one-use accepted migration arm, then reopen it under the ordinary
    /// read-only restart law.
    ///
    /// # Errors
    ///
    /// Refuses an inexact backup, an invalid or previously consumed migration
    /// receipt, authority or occurrence mismatch, an invalid source graph, or
    /// any failed contract join during the read-only reopen.
    pub fn migrate_v7_runtime_authority(
        path: impl AsRef<Path>,
        backup: &BackupArtifact,
        dependencies: RuntimeDependencies,
        authority_custody: &GenesisAuthorityCustody,
        migration_receipt: &MigrationReceiptBytes,
        resident: &RuntimeAuthorityResidentBinding,
    ) -> Result<Self> {
        let path = path.as_ref();
        {
            let source = Store::open_v7_upgrade_source_read_only(path)?;
            if source.runtime_dependency_trust_root()?.is_some()
                || source.runtime_ledger_checkpoint()?.is_some()
            {
                // Re-earn the complete pre-R2 runtime graph semantics before
                // migrating any rooted or ledger-bearing source.
                let _ = Self::reopen_state(&source, &dependencies)?;
            }
        }
        let mut store = Store::open_v7_runtime_authority_migration_source(path, backup)?;
        let occurrence = store.sole_genesis_id()?;
        let trust_root = dependencies.custody().trust_anchor_id()?;
        let migration = store.runtime_authority_migration_expectations()?;
        let expectations = ActivationExpectations {
            genesis_context: ActivationContext::MigrationGenesis,
            expected_occurrence_id: Some(occurrence),
            resident_identity: resident.resident_identity.clone(),
            resident_generation: resident.resident_generation,
            host_role: resident.host_role.clone(),
            role_manifest_generation: resident.role_manifest_generation,
            trust_anchor_id: trust_root,
            domain: resident.domain.clone(),
            policy_floor: resident.policy_floor,
            migration: Some(migration),
        };
        let presented = PresentedAuthoritySet::default();
        store.with_runtime_authority_writer_session(
            |brand, session| -> std::result::Result<(), StoreError> {
                let resolved = verify_for_establishment(
                    brand,
                    authority_custody,
                    &presented,
                    Some(migration_receipt),
                    &expectations,
                )?;
                session.establish_runtime_dependency_trust_root(&resolved)?;
                Ok(())
            },
        )?;
        Self::from_store(store, dependencies, authority_custody, resident)
    }

    /// Authenticates and durably freezes an explicit non-accepted disposition
    /// for one exact schema-v7 predecessor occurrence.
    ///
    /// This migration operation never establishes a root or returns a runtime.
    /// `observed`, `superseded`, and `refused` all make the predecessor
    /// permanently read-only; `accepted` is confined to
    /// [`Self::migrate_v7_runtime_authority`].
    pub fn classify_v7_runtime_authority(
        path: impl AsRef<Path>,
        backup: &BackupArtifact,
        dependencies: &RuntimeDependencies,
        authority_custody: &GenesisAuthorityCustody,
        migration_receipt: &MigrationReceiptBytes,
        resident: &RuntimeAuthorityResidentBinding,
    ) -> Result<RuntimeAuthorityMigrationFreezeReceipt> {
        let path = path.as_ref();
        let mut store = Store::open_v7_runtime_authority_migration_source(path, backup)?;
        let occurrence = store.sole_genesis_id()?;
        let trust_root = dependencies.custody().trust_anchor_id()?;
        let migration = store.runtime_authority_migration_expectations()?;
        let expectations = ActivationExpectations {
            genesis_context: ActivationContext::MigrationGenesis,
            expected_occurrence_id: Some(occurrence),
            resident_identity: resident.resident_identity.clone(),
            resident_generation: resident.resident_generation,
            host_role: resident.host_role.clone(),
            role_manifest_generation: resident.role_manifest_generation,
            trust_anchor_id: trust_root,
            domain: resident.domain.clone(),
            policy_floor: resident.policy_floor,
            migration: Some(migration),
        };
        let presented = PresentedAuthoritySet::default();
        store
            .with_runtime_authority_writer_session(
                |brand, session| -> std::result::Result<_, StoreError> {
                    let classification = verify_nonaccepted_migration_classification(
                        brand,
                        authority_custody,
                        &presented,
                        migration_receipt,
                        &expectations,
                    )?;
                    session.classify_runtime_authority_migration(&classification)
                },
            )
            .map_err(Into::into)
    }

    /// Authenticates and durably freezes an explicit disposition for a
    /// schema-v7 source with an absent, singleton-empty, or multiple genesis
    /// census.
    ///
    /// This path uses only the exogenous genesis A1 key from custody.  It does
    /// not inspect A2 as Store occurrence standing and cannot establish or
    /// migrate the source.
    pub fn classify_v7_nonmigratable_cardinality(
        path: impl AsRef<Path>,
        backup: &BackupArtifact,
        authority_custody: &GenesisAuthorityCustody,
        signed_disposition: &V7CardinalityDispositionBytes,
        resident: &RuntimeAuthorityResidentBinding,
    ) -> Result<RuntimeAuthorityCardinalityFreezeReceipt> {
        let mut store = Store::open_v7_runtime_authority_migration_source(path, backup)?;
        let expectations = store.runtime_authority_cardinality_disposition_expectations(
            &resident.domain,
            resident.policy_floor,
        )?;
        store
            .with_runtime_authority_writer_session(
                |brand, session| -> std::result::Result<_, StoreError> {
                    let classification = verify_v7_cardinality_disposition(
                        brand,
                        authority_custody.genesis_a1_bytes(),
                        signed_disposition,
                        &expectations,
                    )?;
                    session.classify_v7_cardinality_disposition(&classification)
                },
            )
            .map_err(Into::into)
    }

    /// Opens an already constructed store.
    ///
    /// This is useful for bounded in-memory qualification while retaining the
    /// same validation path as file-backed restart.
    ///
    /// # Errors
    ///
    /// Refuses every condition described by [`Self::open`].
    pub fn from_store(
        mut store: Store,
        dependencies: RuntimeDependencies,
        authority_custody: &GenesisAuthorityCustody,
        resident: &RuntimeAuthorityResidentBinding,
    ) -> Result<Self> {
        store.validate()?;
        resolve_store_runtime_authority(&mut store, &dependencies, authority_custody, resident)?;
        let custody_frontiers = store.governed_custody_inventory()?;
        let reopened = Self::reopen_state(&store, &dependencies)?;
        Ok(Self {
            store,
            dependencies,
            checkpoint: reopened.checkpoint,
            rows: reopened.rows,
            rows_by_id: reopened.rows_by_id,
            records: reopened.records,
            provider_intakes: reopened.provider_intakes,
            checkpoint_dependencies: reopened.checkpoint_dependencies,
            inspector: reopened.inspector,
            custody_frontiers,
        })
    }

    /// Returns exact restart dependencies.
    #[must_use]
    pub const fn dependencies(&self) -> &RuntimeDependencies {
        &self.dependencies
    }

    /// Consume this already established runtime and return its governed Store.
    ///
    /// This does not expose the Store-private authority-session factory. The
    /// returned Store already carries the immutable root and establishment
    /// receipt produced by one of the two named runtime lifecycle routes.
    #[must_use]
    pub fn into_store(self) -> Store {
        self.store
    }

    /// Captures the current immutable ledger/dependency frontier.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeSnapshot {
        let dependency_binding_digest = self
            .checkpoint
            .as_ref()
            .and_then(|checkpoint| {
                self.checkpoint_dependencies
                    .get(&checkpoint.checkpoint_id)
                    .map(RuntimeDependencies::generation_id)
            })
            .unwrap_or_else(|| self.dependencies.generation_id())
            .clone();
        RuntimeSnapshot {
            checkpoint: self.checkpoint.clone(),
            dependency_binding_digest,
        }
    }

    /// Returns the number of contract-owned materialized records.
    ///
    /// Opaque provider-intake records remain separately counted.
    #[must_use]
    pub fn contract_record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns the number of ledger-resident opaque provider-intake records.
    #[must_use]
    pub fn provider_intake_count(&self) -> usize {
        self.provider_intakes.len()
    }

    /// Return the exact physical custody frontiers classified during startup.
    ///
    /// These entries are storage/recovery facts only. They do not resume work
    /// or establish diagnostic outcomes. A newly prepared occurrence retains
    /// its exclusive live custody handle, so it is inspected through
    /// [`PreparedGovernedInvocation::live_custody_state`] rather than by
    /// reopening the arena behind that handle.
    #[must_use]
    pub fn custody_frontiers(&self) -> &[GovernedCustodyInventoryEntry] {
        &self.custody_frontiers
    }

    /// Re-read one exact protected-failure carrier without interpreting it.
    ///
    /// # Errors
    ///
    /// Refuses an unreadable, corrupt, substituted, or concurrently locked
    /// custody arena.
    pub fn protected_failure(
        &self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProtectedFailureAccess> {
        self.store
            .governed_protected_failure(reservation_record_id)
            .map_err(RuntimeError::from)
    }

    /// Atomically appends records for custody only after validating the
    /// complete resulting graph.
    ///
    /// The runtime derives the expected predecessor from its owned ledger
    /// frontier. A batch cannot splice into history. Exact replay is supported
    /// only for the current checkpoint; mixed replay/new batches are refused.
    ///
    /// This is intentionally crate-private. Allowing downstream callers to
    /// append invocation, launch, execution-binding, provider-intake, delivery,
    /// or inspector records through a generic custody API would bypass the
    /// governed occurrence path.
    fn append_custody_only(&mut self, request: &AppendRequest) -> Result<AppendResult> {
        Sha256Digest::parse(request.checkpoint_id.clone())
            .map_err(|_| RuntimeError::ReplayBatchMismatch)?;
        let prepared = request
            .records
            .iter()
            .map(Self::prepare_append_record)
            .collect::<Result<Vec<_>>>()?;
        let mut batch_ids = BTreeSet::new();
        for record in &request.records {
            if !batch_ids.insert(record.record_id.as_str()) {
                return Err(RuntimeError::ReplayBatchMismatch);
            }
        }

        let mut existing_count = 0_usize;
        for record in &request.records {
            if let Some(existing) = self.rows_by_id.get(&record.record_id) {
                if existing.record_schema != record.record_schema
                    || existing.canonical_bytes.as_bytes() != record.canonical_bytes
                    || existing.committed_at != record.committed_at
                {
                    return Err(RuntimeError::RecordIdentitySubstitution(
                        record.record_id.clone(),
                    ));
                }
                existing_count += 1;
            }
        }
        if existing_count > 0 && existing_count < request.records.len() {
            return Err(RuntimeError::MixedReplayBatch);
        }
        if existing_count == request.records.len() && !request.records.is_empty() {
            return self.replay_current(request);
        }

        let mut candidate_records = self.records.clone();
        let mut candidate_provider_intakes = self.provider_intakes.clone();
        let mut batch_contract_records = RuntimeRecordSet::new();
        for record in &prepared {
            match record {
                PreparedRecord::Contract(record) => {
                    candidate_records.insert(record.clone())?;
                    batch_contract_records.insert(record.clone())?;
                }
                PreparedRecord::ProviderIntake(reference) => {
                    candidate_provider_intakes
                        .insert(reference.record_id.to_string(), reference.clone());
                }
            }
        }
        self.dependencies
            .validate_graph_dependencies(&batch_contract_records)?;
        let context = combined_historical_validation_context(
            self.checkpoint_dependencies
                .values()
                .chain(std::iter::once(&self.dependencies)),
            candidate_provider_intakes.values().cloned(),
        )?;
        candidate_records.validate(&context)?;

        let predecessor = self.checkpoint.as_ref();
        let batch = RuntimeRecordBatchInput {
            checkpoint_id: request.checkpoint_id.clone(),
            expected_predecessor_checkpoint_id: predecessor
                .map(|checkpoint| checkpoint.checkpoint_id.clone()),
            expected_predecessor_ledger_root: predecessor
                .map(|checkpoint| checkpoint.checkpoint_ledger_root.clone()),
            dependency: self.store_dependency_input()?,
            records: request
                .records
                .iter()
                .map(Self::store_input)
                .collect::<Result<Vec<_>>>()?,
        };
        let receipt = self
            .store
            .begin_writer_session()?
            .append_runtime_records(&batch)?;
        let reopened = Self::reopen_state(&self.store, &self.dependencies)?;
        self.install_reopened(reopened);
        Ok(AppendResult {
            disposition: match receipt.disposition {
                RuntimeRecordAppendDisposition::Committed => AppendDisposition::Committed,
                RuntimeRecordAppendDisposition::Replayed => AppendDisposition::ExactReplay,
            },
            checkpoint: receipt.checkpoint,
        })
    }

    /// Validates and durably commits one two-phase governed prelaunch.
    ///
    /// Physical exact-byte custody is allocated first. The request, accepted
    /// decision, and reservation then commit as one checkpoint. The launch
    /// record commits in a second checkpoint before its one-use arena claim.
    /// The returned value is storage-only material for a core-private permit;
    /// it cannot launch a provider or construct a diagnostic binding.
    ///
    /// # Errors
    ///
    /// Refuses graph, admission, identity, template, replay, or durable-custody
    /// failure. Exact replay never creates a second prepared invocation.
    ///
    /// This compatibility path does not earn runtime-owned native-deadline
    /// provenance. Use [`Self::prepare_native_deadline_invocation`] when core
    /// must receive an exact Linux boot epoch and `CLOCK_BOOTTIME` expiry.
    #[allow(clippy::needless_pass_by_value)]
    pub fn prepare_governed_invocation(
        &mut self,
        request: GovernedPrelaunchRequest,
    ) -> Result<PreparedGovernedInvocation> {
        self.prepare_governed_invocation_inner(request, None)
    }

    /// Constructs and commits one launch from runtime-owned Linux clock and
    /// boot-identity observations.
    ///
    /// The caller supplies no launch carrier, wall-clock launch timestamp,
    /// monotonic observation, boot epoch, attempt deadline, or deadline
    /// evaluation. The runtime requires the exact effective cohort to name one
    /// typed native-clock qualification, brackets `CLOCK_BOOTTIME` with direct
    /// `CLOCK_REALTIME` observations, binds the bracket to exact procfs
    /// boot-id bytes, seals a deadline evaluation, derives the launch, and
    /// commits both records in one launch checkpoint.
    ///
    /// # Errors
    ///
    /// Refuses before launch on graph, qualification, request-bound, boot-id,
    /// clock, deadline, custody, or persistence failure.
    #[allow(clippy::needless_pass_by_value)]
    pub fn prepare_native_deadline_invocation(
        &mut self,
        request: NativeDeadlinePrelaunchRequest,
    ) -> Result<PreparedGovernedInvocation> {
        self.prepare_native_deadline_invocation_with_source(request, &mut LinuxNativeDeadlineSource)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_native_deadline_invocation_with_source(
        &mut self,
        request: NativeDeadlinePrelaunchRequest,
        source: &mut impl NativeDeadlineSource,
    ) -> Result<PreparedGovernedInvocation> {
        if request.maximum_bracket_width_ns > MAX_SAFE_INTEGER
            || request.bracket_policy.kind != IdentityKind::Policy
            || request.reservation_custody.records.iter().any(|record| {
                matches!(
                    record.record_schema.as_str(),
                    "nq.execution_launch.v1" | "nq.deadline_evaluation.v1"
                )
            })
        {
            return Err(RuntimeError::NativeDeadlinePolicyInvalid);
        }

        let candidate = self.validated_reservation_candidate(&request.reservation_custody)?;
        let outer_request = required_record(
            &candidate,
            &request.outer_request_record_id,
            RuntimeSchema::DiagnosticInvocationRequestV1,
        )?;
        let decision = required_record(
            &candidate,
            &request.invocation_decision_record_id,
            RuntimeSchema::InvocationDecisionV1,
        )?;
        let reservation = required_record(
            &candidate,
            &request.custody_reservation_record_id,
            RuntimeSchema::CustodyReservationV1,
        )?;
        if decision.record().as_value()["decision"] != "accepted"
            || reservation.record().as_value()["decision"] != "reserved"
        {
            return Err(RuntimeError::PrelaunchNotAcceptedReservedLaunched);
        }

        let request_value = outer_request.record().as_value();
        let reservation_value = reservation.record().as_value();
        let activation_reference: RecordRef =
            serde_json::from_value(reservation_value["activation"].clone())?;
        let activation = exact_record(
            &candidate,
            &activation_reference,
            RuntimeSchema::RuntimeActivationV1,
        )?;
        let clock_qualification =
            exact_cohort_clock_qualification(&candidate, activation, outer_request)?;

        let sample = sample_native_deadline(source)?;
        let realtime_before = realtime_timestamp(sample.realtime_before_ns)?;
        let realtime_after = realtime_timestamp(sample.realtime_after_ns)?;
        let realtime_before_instant = Timestamp::parse(realtime_before.clone())?.instant();
        let realtime_after_instant = Timestamp::parse(realtime_after.clone())?.instant();
        let not_before =
            Timestamp::parse(required_text(&request_value["time_bounds"], "not_before")?)?
                .instant();
        let request_deadline =
            Timestamp::parse(required_text(&request_value["time_bounds"], "deadline")?)?.instant();
        let maximum_execution_ms = request_value["time_bounds"]["maximum_execution_ms"]
            .as_u64()
            .ok_or(RuntimeError::NativeDeadlinePolicyInvalid)?;
        let maximum_execution_ms_i64 = i64::try_from(maximum_execution_ms)
            .map_err(|_| RuntimeError::NativeDeadlinePolicyInvalid)?;
        let signed_bracket_ns = realtime_after_instant
            .signed_duration_since(realtime_before_instant)
            .num_nanoseconds()
            .ok_or(RuntimeError::NativeDeadlineClockInvalid(
                "CLOCK_REALTIME bracket",
            ))?;
        let bracket_width_ns = u64::try_from(signed_bracket_ns).unwrap_or(0);
        if bracket_width_ns > MAX_SAFE_INTEGER {
            return Err(RuntimeError::NativeDeadlineClockInvalid(
                "CLOCK_REALTIME bracket",
            ));
        }
        let attempt_deadline_instant = realtime_after_instant
            .checked_add_signed(Duration::milliseconds(maximum_execution_ms_i64))
            .ok_or(RuntimeError::NativeDeadlineClockInvalid(
                "CLOCK_REALTIME deadline",
            ))?;
        let attempt_deadline = attempt_deadline_instant.to_rfc3339_opts(SecondsFormat::Nanos, true);
        let boottime_expiry_ns = sample
            .boottime_at_ns
            .checked_add(maximum_execution_ms.checked_mul(1_000_000).ok_or(
                RuntimeError::NativeDeadlineClockInvalid("CLOCK_BOOTTIME expiry"),
            )?)
            .ok_or(RuntimeError::NativeDeadlineClockInvalid(
                "CLOCK_BOOTTIME expiry",
            ))?;

        let mut violations = Vec::new();
        if signed_bracket_ns < 0 {
            violations.push("realtime_bracket_reversed");
        }
        if request_deadline <= not_before {
            violations.push("invalid_request_window");
        }
        if bracket_width_ns > request.maximum_bracket_width_ns {
            violations.push("bracket_too_wide");
        }
        if realtime_after_instant < not_before {
            violations.push("before_not_before");
        }
        if realtime_after_instant >= request_deadline {
            violations.push("request_deadline_exhausted");
        }
        if attempt_deadline_instant > request_deadline {
            violations.push("execution_budget_exceeds_request_deadline");
        }

        let mut deadline_value = json!({
            "schema": "nq.deadline_evaluation.v1",
            "evaluation_id": sha256_bytes(b"runtime-owned deadline identity placeholder"),
            "namespace": request_value["namespace"],
            "outer_request": outer_request.exact_reference(),
            "activation": activation_reference,
            "clock_qualification": clock_qualification,
            "clock": request_value["time_bounds"]["clock"],
            "request_bounds": {
                "not_before": request_value["time_bounds"]["not_before"],
                "deadline": request_value["time_bounds"]["deadline"],
                "maximum_execution_ms": maximum_execution_ms,
            },
            "bracket_policy": {
                "policy": request.bracket_policy,
                "maximum_width_ns": request.maximum_bracket_width_ns,
            },
            "sample": {
                "realtime_before": realtime_before,
                "boottime_at_ns": sample.boottime_at_ns.to_string(),
                "realtime_after": realtime_after,
                "bracket_width_ns": bracket_width_ns,
                "boot_epoch": sample.boot_epoch,
            },
            "derived": {
                "launched_at": realtime_after,
                "attempt_deadline": attempt_deadline,
                "boottime_expiry_ns": boottime_expiry_ns.to_string(),
            },
            "decision": {
                "state": if violations.is_empty() { "accepted" } else { "refused" },
                "violations": violations,
            },
            "nonclaims": [
                "does not reference or authorize an execution launch",
                "does not establish source-evidence freshness or Nightshift currentness",
                "does not grant reliance, authorization, or action",
            ],
        });
        seal_semantic_identity(&mut deadline_value, "evaluation_id")?;
        let deadline = ValidatedRuntimeRecord::validate_value(deadline_value)?;
        let deadline_violations = deadline.record().as_value()["decision"]["violations"]
            .as_array()
            .expect("validated deadline violations");
        if !deadline_violations.is_empty() {
            let summary = deadline_violations
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            return Err(RuntimeError::NativeDeadlineRefused(summary));
        }

        let deadline_reference = deadline.exact_reference();
        let launched_at = deadline.record().as_value()["derived"]["launched_at"].clone();
        let attempt_deadline = deadline.record().as_value()["derived"]["attempt_deadline"].clone();
        let mut launch_value = json!({
            "schema": "nq.execution_launch.v1",
            "launch_id": sha256_bytes(b"runtime-owned launch identity placeholder"),
            "namespace": request_value["namespace"],
            "node": request_value["target"]["node"],
            "outer_request": outer_request.exact_reference(),
            "invocation_decision": decision.exact_reference(),
            "activation_snapshot": activation.exact_reference(),
            "custody_reservation": reservation.exact_reference(),
            "profile": request_value["profile"],
            "selected_witness_attachments":
                request_value["expected_binding"]["witness_attachments"],
            "prelaunch_checks": {
                "authentication": request_value["authentication_evidence"],
                "invocation_authorization": request_value["invocation_authorization"],
                "generation_match": request.generation_match,
                "deadline": deadline_reference,
                "capability": request.capability,
                "custody": reservation_value["reservation_commit"],
            },
            "launch_commit": request.launch_commit,
            "launched_at": launched_at,
            "attempt_deadline": attempt_deadline,
            "maximum_execution_ms": maximum_execution_ms,
            "clock": request_value["time_bounds"]["clock"],
            "status": "launched",
            "nonclaims": [
                "launch does not establish diagnostic success",
                "launch does not create recurrence or another invocation",
            ],
        });
        seal_semantic_identity(&mut launch_value, "launch_id")?;
        let launch = ValidatedRuntimeRecord::validate_value(launch_value)?;
        let launch_reference = launch.exact_reference();
        let checkpoint_id = semantic_digest(&json!({
            "schema": "nq.runtime_owned_launch_checkpoint.v1",
            "deadline_evaluation": deadline_reference,
            "execution_launch": launch_reference,
        }))?;
        let committed_at = deadline.record().as_value()["derived"]["launched_at"]
            .as_str()
            .expect("validated launched_at")
            .to_owned();
        let provenance = NativeDeadlineProvenance {
            evaluation: deadline.exact_reference(),
            clock_qualification: clock_qualification.clone(),
            boot_epoch: sample.boot_epoch,
            boottime_observed_ns: sample.boottime_at_ns,
            boottime_expiry_ns,
        };
        let governed = GovernedPrelaunchRequest {
            reservation_custody: request.reservation_custody,
            launch_custody: AppendRequest {
                checkpoint_id: checkpoint_id.to_string(),
                records: vec![
                    AppendRecord::from_contract(&deadline, committed_at.clone()),
                    AppendRecord::from_contract(&launch, committed_at),
                ],
            },
            outer_request_record_id: request.outer_request_record_id,
            invocation_decision_record_id: request.invocation_decision_record_id,
            custody_reservation_record_id: request.custody_reservation_record_id,
            execution_launch_record_id: launch.record_id().clone(),
        };
        self.prepare_governed_invocation_inner(governed, Some(provenance))
    }

    fn validated_reservation_candidate(
        &self,
        reservation: &AppendRequest,
    ) -> Result<RuntimeRecordSet> {
        let mut candidate = self.records.clone();
        let mut provider_intakes = self.provider_intakes.clone();
        let mut batch_records = RuntimeRecordSet::new();
        for input in &reservation.records {
            match Self::prepare_append_record(input)? {
                PreparedRecord::Contract(record) => {
                    candidate.insert(record.clone())?;
                    batch_records.insert(record)?;
                }
                PreparedRecord::ProviderIntake(reference) => {
                    provider_intakes.insert(reference.record_id.to_string(), reference);
                }
            }
        }
        self.dependencies
            .validate_graph_dependencies(&batch_records)?;
        let context = combined_historical_validation_context(
            self.checkpoint_dependencies
                .values()
                .chain(std::iter::once(&self.dependencies)),
            provider_intakes.values().cloned(),
        )?;
        candidate.validate(&context)?;
        Ok(candidate)
    }

    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    fn prepare_governed_invocation_inner(
        &mut self,
        request: GovernedPrelaunchRequest,
        native_deadline: Option<NativeDeadlineProvenance>,
    ) -> Result<PreparedGovernedInvocation> {
        let preflight = self.preflight_governed(&request, native_deadline.as_ref())?;
        if self
            .rows_by_id
            .contains_key(request.execution_launch_record_id.as_str())
        {
            return Err(RuntimeError::PrelaunchReplayCannotRerun);
        }

        let dependency_custody_bytes = self.dependencies.custody().canonical_closure_bytes()?;
        let dependency_custody_digest = self.dependencies.custody().custody_digest()?;
        let trust_anchor_id = self.dependencies.custody().trust_anchor_id()?;
        let reservation_batch = self.store_batch_for(&request.reservation_custody)?;
        let reservation_batch_digest = runtime_record_batch_digest(&reservation_batch)?;
        let reservation_checkpoint_records =
            exact_append_membership(&request.reservation_custody.records)?;
        let launch_checkpoint_records = exact_append_membership(&request.launch_custody.records)?;
        let reservation_spec = GovernedCustodyReservation {
            reservation_record_id: request.custody_reservation_record_id.clone(),
            reservation_manifest_digest: preflight.custody_reservation.bytes_digest.clone(),
            outer_request_record_id: request.outer_request_record_id.clone(),
            outer_request_id: preflight.request_id.clone(),
            outer_request_digest: preflight.outer_request.bytes_digest.clone(),
            dependency_generation_id: self.dependencies.generation_id().clone(),
            dependency_generation_custody_digest: dependency_custody_digest,
            trust_anchor_id,
            prelaunch_checkpoint_id: Sha256Digest::parse(
                request.reservation_custody.checkpoint_id.clone(),
            )
            .map_err(|_| RuntimeError::PrelaunchCheckpointMismatch)?,
            prelaunch_checkpoint_digest: reservation_batch_digest,
            dependency_closure_capacity_bytes: preflight.dependency_closure_capacity_bytes,
            raw_capacity_bytes: preflight.raw_capacity_bytes,
            diagnostic_artifact_capacity_bytes: preflight.diagnostic_artifact_capacity_bytes,
            projection_capsule_capacity_bytes: preflight.projection_capsule_capacity_bytes,
            final_capacity_bytes: preflight.final_capacity_bytes,
            protected_failure_capacity_bytes: preflight.protected_failure_capacity_bytes,
        };
        let mut physical_custody = self
            .store
            .begin_writer_session()?
            .reserve_governed_custody(reservation_spec.clone(), &dependency_custody_bytes)?;

        let reservation_result = self.append_custody_only(&request.reservation_custody)?;
        if reservation_result.disposition != AppendDisposition::Committed {
            return Err(RuntimeError::PrelaunchReplayCannotRerun);
        }
        if self.checkpoint.as_ref() != Some(&reservation_result.checkpoint)
            || reservation_result.checkpoint.batch_digest
                != reservation_spec.prelaunch_checkpoint_digest
        {
            return Err(RuntimeError::PrelaunchCheckpointMismatch);
        }

        let launch_result = self.append_custody_only(&request.launch_custody)?;
        if launch_result.disposition != AppendDisposition::Committed
            || self.checkpoint.as_ref() != Some(&launch_result.checkpoint)
        {
            return Err(RuntimeError::PrelaunchReplayCannotRerun);
        }
        if reservation_result.checkpoint.record_count
            != u64::try_from(reservation_checkpoint_records.len())
                .map_err(|_| RuntimeError::PrelaunchCheckpointMismatch)?
            || launch_result.checkpoint.record_count
                != u64::try_from(launch_checkpoint_records.len())
                    .map_err(|_| RuntimeError::PrelaunchCheckpointMismatch)?
        {
            return Err(RuntimeError::PrelaunchCheckpointMismatch);
        }
        self.store.begin_writer_session()?.claim_custody_launch(
            &mut physical_custody,
            request.execution_launch_record_id.clone(),
            preflight.launched_at.clone(),
        )?;
        let mut historical_dependencies_by_generation = BTreeMap::new();
        for dependencies in self
            .checkpoint_dependencies
            .values()
            .chain(std::iter::once(&self.dependencies))
        {
            historical_dependencies_by_generation
                .entry(dependencies.generation_id().clone())
                .or_insert_with(|| dependencies.clone());
        }
        let historical_dependencies = historical_dependencies_by_generation
            .into_values()
            .collect::<Vec<_>>();
        let historical_validation_context = combined_historical_validation_context(
            historical_dependencies.iter(),
            self.provider_intakes.values().cloned(),
        )?;

        Ok(PreparedGovernedInvocation {
            request_id: preflight.request_id,
            production: preflight.production,
            reservation_checkpoint: reservation_result.checkpoint,
            launch_checkpoint: launch_result.checkpoint,
            reservation_checkpoint_records,
            launch_checkpoint_records,
            outer_request: preflight.outer_request,
            invocation_decision: preflight.invocation_decision,
            custody_reservation: preflight.custody_reservation,
            execution_launch: preflight.execution_launch,
            prelaunch_records: preflight.complete_records,
            existing_provider_intakes: self.provider_intakes.values().cloned().collect(),
            historical_validation_context,
            historical_dependencies,
            dependencies: self.dependencies.clone(),
            dependency_custody_bytes,
            custody_reservation_spec: reservation_spec,
            native_deadline,
            live_custody: physical_custody,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn preflight_governed(
        &self,
        request: &GovernedPrelaunchRequest,
        native_deadline: Option<&NativeDeadlineProvenance>,
    ) -> Result<GovernedPreflight> {
        let expected_launch_record_count = if native_deadline.is_some() { 2 } else { 1 };
        if request.launch_custody.records.len() != expected_launch_record_count
            || !request.launch_custody.records.iter().any(|record| {
                record.record_id == request.execution_launch_record_id.as_str()
                    && record.record_schema == RuntimeSchema::ExecutionLaunchV1.as_str()
            })
            || request
                .reservation_custody
                .records
                .iter()
                .any(|record| record.record_id == request.execution_launch_record_id.as_str())
        {
            return Err(RuntimeError::PrelaunchNotAcceptedReservedLaunched);
        }
        if let Some(native_deadline) = native_deadline
            && (!request.launch_custody.records.iter().any(|record| {
                record.record_id == native_deadline.evaluation.record_id.as_str()
                    && record.record_schema == RuntimeSchema::DeadlineEvaluationV1.as_str()
            }) || request
                .reservation_custody
                .records
                .iter()
                .any(|record| record.record_schema == RuntimeSchema::DeadlineEvaluationV1.as_str()))
        {
            return Err(RuntimeError::NativeDeadlineProvenanceMismatch);
        }
        let mut reservation_candidate = self.records.clone();
        let mut provider_intakes = self.provider_intakes.clone();
        let mut reservation_batch_records = RuntimeRecordSet::new();
        for input in &request.reservation_custody.records {
            match Self::prepare_append_record(input)? {
                PreparedRecord::Contract(record) => {
                    reservation_candidate.insert(record.clone())?;
                    reservation_batch_records.insert(record)?;
                }
                PreparedRecord::ProviderIntake(reference) => {
                    provider_intakes.insert(reference.record_id.to_string(), reference);
                }
            }
        }
        self.dependencies
            .validate_graph_dependencies(&reservation_batch_records)?;
        let reservation_context = combined_historical_validation_context(
            self.checkpoint_dependencies
                .values()
                .chain(std::iter::once(&self.dependencies)),
            provider_intakes.values().cloned(),
        )?;
        reservation_candidate.validate(&reservation_context)?;
        let mut candidate = reservation_candidate;
        let mut launch_batch_records = RuntimeRecordSet::new();
        for input in &request.launch_custody.records {
            match Self::prepare_append_record(input)? {
                PreparedRecord::Contract(record) => {
                    candidate.insert(record.clone())?;
                    launch_batch_records.insert(record)?;
                }
                PreparedRecord::ProviderIntake(_) => {
                    return Err(RuntimeError::PrelaunchNotAcceptedReservedLaunched);
                }
            }
        }
        self.dependencies
            .validate_graph_dependencies(&launch_batch_records)?;
        candidate.validate(&reservation_context)?;

        let outer_request = required_record(
            &candidate,
            &request.outer_request_record_id,
            RuntimeSchema::DiagnosticInvocationRequestV1,
        )?;
        let decision = required_record(
            &candidate,
            &request.invocation_decision_record_id,
            RuntimeSchema::InvocationDecisionV1,
        )?;
        let reservation = required_record(
            &candidate,
            &request.custody_reservation_record_id,
            RuntimeSchema::CustodyReservationV1,
        )?;
        let launch = required_record(
            &candidate,
            &request.execution_launch_record_id,
            RuntimeSchema::ExecutionLaunchV1,
        )?;
        if let Some(native_deadline) = native_deadline {
            let deadline = required_record(
                &candidate,
                &native_deadline.evaluation.record_id,
                RuntimeSchema::DeadlineEvaluationV1,
            )?;
            if deadline.exact_reference() != native_deadline.evaluation
                || launch.record().as_value()["prelaunch_checks"]["deadline"]
                    != Value::from(native_deadline.evaluation.clone())
                || deadline.record().as_value()["clock_qualification"]
                    != Value::from(native_deadline.clock_qualification.clone())
                || deadline.record().as_value()["sample"]["boot_epoch"]
                    != native_deadline.boot_epoch.as_str()
                || deadline.record().as_value()["sample"]["boottime_at_ns"].as_str()
                    != Some(&native_deadline.boottime_observed_ns.to_string())
                || deadline.record().as_value()["derived"]["boottime_expiry_ns"].as_str()
                    != Some(&native_deadline.boottime_expiry_ns.to_string())
                || deadline.record().as_value()["decision"]["state"] != "accepted"
                || deadline.record().as_value()["decision"]["violations"]
                    .as_array()
                    .is_none_or(|violations| !violations.is_empty())
            {
                return Err(RuntimeError::NativeDeadlineProvenanceMismatch);
            }
            let selection = candidate.select_launch_correspondence(&launch.exact_reference())?;
            if selection.launch() != &launch.exact_reference()
                || selection.outer_request() != &outer_request.exact_reference()
                || selection.activation()
                    != &serde_json::from_value::<RecordRef>(
                        launch.record().as_value()["activation_snapshot"].clone(),
                    )?
                || selection.native_clock_qualification() != &native_deadline.clock_qualification
                || selection.deadline_evaluation() != &native_deadline.evaluation
            {
                return Err(RuntimeError::NativeDeadlineProvenanceMismatch);
            }
        }
        if decision.record().as_value()["decision"] != "accepted"
            || reservation.record().as_value()["decision"] != "reserved"
            || launch.record().as_value()["status"] != "launched"
        {
            return Err(RuntimeError::PrelaunchNotAcceptedReservedLaunched);
        }

        let request_value = outer_request.record().as_value();
        let launch_value = launch.record().as_value();
        let activation_ref: RecordRef =
            serde_json::from_value(launch_value["activation_snapshot"].clone())?;
        let activation = required_record(
            &candidate,
            &activation_ref.record_id,
            RuntimeSchema::RuntimeActivationV1,
        )?;
        let node: IdentityRef = serde_json::from_value(request_value["target"]["node"].clone())?;
        let subject: IdentityRef =
            serde_json::from_value(request_value["target"]["subject"].clone())?;
        let vantage: IdentityRef =
            serde_json::from_value(request_value["target"]["vantage"].clone())?;
        let cohort: IdentityRef = serde_json::from_value(
            activation.record().as_value()["static_profile_cohort"].clone(),
        )?;
        let request_id = request_value["request_id"]
            .as_str()
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?
            .to_owned();
        let launched_at = launch_value["launched_at"]
            .as_str()
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?
            .to_owned();
        let component_bounds = reservation.record().as_value()["component_bounds"]
            .as_object()
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        let raw_capacity_bytes = component_bounds
            .get("raw_evidence_bytes")
            .and_then(Value::as_u64)
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        let dependency_closure_capacity_bytes = component_bounds
            .get("dependency_closure_bytes")
            .and_then(Value::as_u64)
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        let diagnostic_artifact_capacity_bytes = component_bounds
            .get("diagnostic_artifact_bytes")
            .and_then(Value::as_u64)
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        // The capsule is the complete exact Store projection carrier: it is
        // charged wholly to the reservation's projection component. It must
        // never borrow normalization or delivery-ledger capacity.
        let projection_capsule_capacity_bytes = component_bounds
            .get("projected_bytes")
            .and_then(Value::as_u64)
            .filter(|capacity| *capacity > 0)
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        let reserved_bytes = reservation.record().as_value()["reserved_bytes"]
            .as_u64()
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        let final_capacity_bytes = reserved_bytes
            .checked_sub(raw_capacity_bytes)
            .and_then(|remaining| remaining.checked_sub(dependency_closure_capacity_bytes))
            .filter(|capacity| *capacity > 0)
            .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        let protected_failure_capacity_bytes =
            reservation.record().as_value()["protected_failure_reserve_bytes"]
                .as_u64()
                .ok_or(RuntimeError::PrelaunchIdentityMismatch)?;
        Ok(GovernedPreflight {
            request_id,
            production: production_identity(node, subject, vantage, cohort),
            outer_request: outer_request.exact_reference(),
            invocation_decision: decision.exact_reference(),
            custody_reservation: reservation.exact_reference(),
            execution_launch: launch.exact_reference(),
            launched_at,
            raw_capacity_bytes,
            dependency_closure_capacity_bytes,
            diagnostic_artifact_capacity_bytes,
            projection_capsule_capacity_bytes,
            final_capacity_bytes,
            protected_failure_capacity_bytes,
            complete_records: candidate,
        })
    }

    fn store_batch_for(&self, request: &AppendRequest) -> Result<RuntimeRecordBatchInput> {
        let predecessor = self.checkpoint.as_ref();
        Ok(RuntimeRecordBatchInput {
            checkpoint_id: request.checkpoint_id.clone(),
            expected_predecessor_checkpoint_id: predecessor
                .map(|checkpoint| checkpoint.checkpoint_id.clone()),
            expected_predecessor_ledger_root: predecessor
                .map(|checkpoint| checkpoint.checkpoint_ledger_root.clone()),
            dependency: self.store_dependency_input()?,
            records: request
                .records
                .iter()
                .map(Self::store_input)
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn replay_current(&mut self, request: &AppendRequest) -> Result<AppendResult> {
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or(RuntimeError::ReplayCheckpointMismatch)?;
        if checkpoint.checkpoint_id != request.checkpoint_id
            || checkpoint.record_count
                != u64::try_from(request.records.len())
                    .map_err(|_| RuntimeError::ReplayBatchMismatch)?
        {
            return Err(RuntimeError::ReplayCheckpointMismatch);
        }
        let committed = self
            .rows
            .iter()
            .filter(|row| row.checkpoint_id == checkpoint.checkpoint_id)
            .collect::<Vec<_>>();
        if committed.len() != request.records.len()
            || committed
                .iter()
                .zip(&request.records)
                .any(|(actual, expected)| {
                    actual.record_id != expected.record_id
                        || actual.record_schema != expected.record_schema
                        || actual.canonical_bytes.as_bytes() != expected.canonical_bytes
                        || actual.committed_at != expected.committed_at
                })
        {
            return Err(RuntimeError::ReplayBatchMismatch);
        }
        let batch = RuntimeRecordBatchInput {
            checkpoint_id: request.checkpoint_id.clone(),
            expected_predecessor_checkpoint_id: checkpoint.predecessor_checkpoint_id.clone(),
            expected_predecessor_ledger_root: checkpoint.predecessor_ledger_root.clone(),
            dependency: Self::store_dependency_input_for(
                self.checkpoint_dependencies
                    .get(&checkpoint.checkpoint_id)
                    .ok_or_else(|| {
                        RuntimeError::CheckpointDependencyMissing(checkpoint.checkpoint_id.clone())
                    })?,
            )?,
            records: request
                .records
                .iter()
                .map(Self::store_input)
                .collect::<Result<Vec<_>>>()?,
        };
        let receipt = self
            .store
            .begin_writer_session()?
            .append_runtime_records(&batch)?;
        if receipt.disposition != RuntimeRecordAppendDisposition::Replayed {
            return Err(RuntimeError::ReplayBatchMismatch);
        }
        Ok(AppendResult {
            disposition: AppendDisposition::ExactReplay,
            checkpoint: receipt.checkpoint,
        })
    }

    fn store_dependency_input(&self) -> Result<RuntimeCheckpointDependencyInput> {
        Self::store_dependency_input_for(&self.dependencies)
    }

    fn store_dependency_input_for(
        dependencies: &RuntimeDependencies,
    ) -> Result<RuntimeCheckpointDependencyInput> {
        Ok(RuntimeCheckpointDependencyInput {
            dependency_generation_id: dependencies.generation_id().clone(),
            trust_anchor_id: dependencies.custody().trust_anchor_id()?,
            canonical_custody: CanonicalDocument::from_canonical_bytes(
                dependencies.custody().canonical_closure_bytes()?,
            )?,
        })
    }

    /// Reads one exact page pinned to an immutable snapshot.
    ///
    /// # Errors
    ///
    /// Refuses a dependency mismatch, invalid checkpoint, cursor, or store
    /// failure.
    pub fn read_page(
        &self,
        snapshot: &RuntimeSnapshot,
        after_record_sequence: u64,
        limit: u32,
    ) -> Result<RuntimeReadPage> {
        self.verify_snapshot(snapshot)?;
        let page = self.store.runtime_record_page(
            snapshot.checkpoint.as_ref(),
            after_record_sequence,
            limit,
        )?;
        Ok(RuntimeReadPage {
            snapshot: snapshot.clone(),
            after_record_sequence: page.after_record_sequence,
            records: page.records,
            next_after_record_sequence: page.next_after_record_sequence,
            complete: page.complete,
        })
    }

    /// Reads one exact immutable record within a supplied snapshot.
    ///
    /// # Errors
    ///
    /// Refuses an absent record, a record appended after the snapshot, a
    /// dependency mismatch, or store failure.
    pub fn read_exact(
        &self,
        snapshot: &RuntimeSnapshot,
        record_id: &str,
    ) -> Result<RuntimeRecordRow> {
        self.verify_snapshot(snapshot)?;
        let row = self
            .store
            .runtime_record(record_id)?
            .ok_or_else(|| RuntimeError::RecordMissing(record_id.to_owned()))?;
        let through = snapshot
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.last_record_sequence);
        if row.record_sequence > through {
            return Err(RuntimeError::RecordOutsideSnapshot(record_id.to_owned()));
        }
        Ok(row)
    }

    /// Resolves the exact materialized and off-ledger dependency closure of
    /// one historical V2 execution binding.
    ///
    /// # Errors
    ///
    /// Refuses an absent/non-binding record, dependency substitution, a
    /// snapshot mismatch, or an unexpectedly missing validated dependency.
    pub fn resolve_historical_topology(
        &self,
        snapshot: &RuntimeSnapshot,
        binding_id: &Sha256Digest,
    ) -> Result<HistoricalTopology> {
        let binding_row = self.read_exact(snapshot, binding_id.as_str())?;
        if binding_row.record_schema != RuntimeSchema::ExecutionIdentityBindingV2.as_str() {
            return Err(RuntimeError::NotExecutionBinding(binding_id.to_string()));
        }
        let binding =
            ValidatedRuntimeRecord::decode_canonical(binding_row.canonical_bytes.as_bytes())?;
        let mut pending = vec![binding.exact_reference()];
        let mut visited = BTreeSet::new();
        let mut materialized = BTreeMap::<RecordRef, HistoricalMaterializedRecord>::new();
        let mut external = BTreeSet::<RecordRef>::new();
        let mut identities = BTreeSet::<IdentityRef>::new();
        while let Some(reference) = pending.pop() {
            if !visited.insert(reference.clone()) {
                continue;
            }
            if let Some(row) = self.rows_by_id.get(reference.record_id.as_str()) {
                let through = snapshot
                    .checkpoint
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.last_record_sequence);
                if row.record_sequence > through {
                    return Err(RuntimeError::RecordOutsideSnapshot(
                        reference.record_id.to_string(),
                    ));
                }
                if row.record_schema != reference.schema.as_str()
                    || row.canonical_bytes_sha256 != reference.bytes_digest
                {
                    return Err(RuntimeError::HistoricalDependencyMissing(
                        reference.record_id.to_string(),
                    ));
                }
                let value: Value = serde_json::from_slice(row.canonical_bytes.as_bytes())?;
                let mut nested_identities = Vec::new();
                let mut nested_references = Vec::new();
                collect_carriers(&value, &mut nested_identities, &mut nested_references)?;
                identities.extend(nested_identities);
                pending.extend(nested_references);
                materialized.insert(
                    reference.clone(),
                    HistoricalMaterializedRecord {
                        reference,
                        record_sequence: row.record_sequence,
                        canonical_bytes: row.canonical_bytes.as_bytes().to_vec(),
                        committed_at: row.committed_at.clone(),
                    },
                );
            } else if self
                .checkpoint_dependencies
                .get(&binding_row.checkpoint_id)
                .ok_or_else(|| {
                    RuntimeError::CheckpointDependencyMissing(binding_row.checkpoint_id.clone())
                })?
                .external_dependency_snapshot()
                .dependencies
                .iter()
                .any(|dependency| dependency.reference == reference)
            {
                external.insert(reference);
            } else {
                return Err(RuntimeError::HistoricalDependencyMissing(
                    reference.record_id.to_string(),
                ));
            }
        }
        let diagnostic = binding
            .record()
            .as_value()
            .get("diagnostic")
            .cloned()
            .ok_or(RuntimeError::LedgerCarrierMismatch(
                "execution binding diagnostic",
            ))?;
        Ok(HistoricalTopology {
            binding: binding.exact_reference(),
            diagnostic,
            materialized_records: materialized.into_values().collect(),
            external_references: external.into_iter().collect(),
            identities: identities.into_iter().collect(),
        })
    }

    /// Reports whether the disposable inspector projection is available.
    #[must_use]
    pub fn inspector_projection_state(&self) -> InspectorProjectionState {
        self.inspector.state()
    }

    /// Discards the non-authoritative inspector index.
    ///
    /// Canonical ledger bytes and runtime semantics are unchanged.
    pub fn discard_inspector_projection(&mut self) {
        self.inspector.discard();
    }

    /// Reconstructs the disposable inspector index from canonical rows.
    pub fn rebuild_inspector_projection(&mut self) {
        self.inspector = InspectorProjection::rebuilt(&self.rows);
    }

    /// Reads one immutable inspector page.
    ///
    /// # Errors
    ///
    /// Refuses a discarded projection, invalid page bound, or snapshot from
    /// another dependency closure.
    pub fn inspector_page(
        &self,
        snapshot: &RuntimeSnapshot,
        after_record_sequence: u64,
        limit: u32,
    ) -> Result<InspectorPage> {
        self.verify_snapshot(snapshot)?;
        if self.inspector.state() != InspectorProjectionState::Available {
            return Err(RuntimeError::InspectorProjectionUnavailable);
        }
        if limit == 0 || limit > MAX_PUBLIC_QUERY_ROWS {
            return Err(RuntimeError::InvalidInspectorPage);
        }
        let through = snapshot
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.last_record_sequence);
        let entries = self.inspector.entries_after(
            after_record_sequence,
            through,
            usize::try_from(limit).map_err(|_| RuntimeError::InvalidInspectorPage)?,
        );
        let last = entries
            .last()
            .map_or(after_record_sequence, |entry| entry.record_sequence);
        let complete = last >= through;
        Ok(InspectorPage {
            checkpoint_id: snapshot
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.checkpoint_id.clone()),
            dependency_binding_digest: snapshot.dependency_binding_digest.clone(),
            after_record_sequence,
            entries,
            next_after_record_sequence: (!complete).then_some(last),
            complete,
        })
    }

    fn verify_snapshot(&self, snapshot: &RuntimeSnapshot) -> Result<()> {
        let expected = snapshot
            .checkpoint
            .as_ref()
            .map(|checkpoint| {
                self.checkpoint_dependencies
                    .get(&checkpoint.checkpoint_id)
                    .map(RuntimeDependencies::generation_id)
                    .ok_or_else(|| {
                        RuntimeError::CheckpointDependencyMissing(checkpoint.checkpoint_id.clone())
                    })
            })
            .transpose()?
            .unwrap_or_else(|| self.dependencies.generation_id());
        if &snapshot.dependency_binding_digest != expected {
            return Err(RuntimeError::SnapshotDependencyMismatch);
        }
        Ok(())
    }

    fn prepare_append_record(input: &AppendRecord) -> Result<PreparedRecord> {
        let canonical = CanonicalDocument::from_canonical_bytes(input.canonical_bytes.clone())?;
        let value: Value = serde_json::from_slice(canonical.as_bytes())?;
        let observed_schema = value
            .get("schema")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::LedgerCarrierMismatch("top-level schema"))?;
        if observed_schema != input.record_schema {
            return Err(RuntimeError::LedgerCarrierMismatch("record schema"));
        }
        let record_id = Sha256Digest::parse(input.record_id.clone())
            .map_err(|_| RuntimeError::LedgerCarrierMismatch("record identity"))?;
        match RuntimeSchema::parse(&input.record_schema) {
            Ok(_) => {
                let record = ValidatedRuntimeRecord::decode_canonical(canonical.as_bytes())?;
                if record.record_id() != &record_id
                    || record.schema().as_str() != input.record_schema
                    || record.bytes_digest().as_str() != canonical.digest()
                {
                    return Err(RuntimeError::LedgerCarrierMismatch(
                        "typed runtime record identity",
                    ));
                }
                Ok(PreparedRecord::Contract(record))
            }
            Err(_) if input.record_schema == PROVIDER_INTAKE_SCHEMA => {
                if !value.is_object() {
                    return Err(RuntimeError::InvalidProviderIntakeCarrier);
                }
                Ok(PreparedRecord::ProviderIntake(RecordRef {
                    schema: Token::parse(PROVIDER_INTAKE_SCHEMA)?,
                    record_id,
                    bytes_digest: sha256_bytes(canonical.as_bytes()),
                }))
            }
            Err(_) => Err(RuntimeError::UnsupportedLedgerSchema(
                input.record_schema.clone(),
            )),
        }
    }

    fn store_input(input: &AppendRecord) -> Result<RuntimeRecordInput> {
        Ok(RuntimeRecordInput {
            record_id: input.record_id.clone(),
            record_schema: input.record_schema.clone(),
            canonical_bytes: CanonicalDocument::from_canonical_bytes(
                input.canonical_bytes.clone(),
            )?,
            committed_at: input.committed_at.clone(),
        })
    }

    fn reopen_state(store: &Store, dependencies: &RuntimeDependencies) -> Result<ReopenedState> {
        let trust_root = store
            .runtime_dependency_trust_root()?
            .ok_or(RuntimeError::DependencyTrustRootNotEstablished)?;
        let supplied_anchor = dependencies.custody().trust_anchor_id()?;
        if supplied_anchor != trust_root {
            return Err(RuntimeError::DependencyTrustAnchorSubstitution {
                expected: trust_root,
                observed: supplied_anchor,
            });
        }
        let checkpoint = store.runtime_ledger_checkpoint()?;
        let rows = read_complete_ledger(store, checkpoint.as_ref())?;
        let mut rows_by_id = BTreeMap::new();
        let mut records = RuntimeRecordSet::new();
        let mut provider_intakes = BTreeMap::new();
        let mut checkpoint_dependencies = BTreeMap::new();
        let mut checkpoint_records = BTreeMap::<String, RuntimeRecordSet>::new();
        for row in &rows {
            if !checkpoint_dependencies.contains_key(&row.checkpoint_id) {
                let checkpoint_dependency =
                    reopen_checkpoint_dependencies(store, &row.checkpoint_id, &trust_root)?;
                checkpoint_dependencies.insert(row.checkpoint_id.clone(), checkpoint_dependency);
            }
            if row.canonical_bytes.digest() != row.canonical_bytes_sha256.as_str() {
                return Err(RuntimeError::LedgerCarrierMismatch(
                    "stored canonical bytes digest",
                ));
            }
            let input = AppendRecord {
                record_id: row.record_id.clone(),
                record_schema: row.record_schema.clone(),
                canonical_bytes: row.canonical_bytes.as_bytes().to_vec(),
                committed_at: row.committed_at.clone(),
            };
            match Self::prepare_append_record(&input)? {
                PreparedRecord::Contract(record) => {
                    records.insert(record.clone())?;
                    checkpoint_records
                        .entry(row.checkpoint_id.clone())
                        .or_default()
                        .insert(record)?;
                }
                PreparedRecord::ProviderIntake(reference) => {
                    provider_intakes.insert(row.record_id.clone(), reference);
                }
            }
            if rows_by_id
                .insert(row.record_id.clone(), row.clone())
                .is_some()
            {
                return Err(RuntimeError::RecordIdentitySubstitution(
                    row.record_id.clone(),
                ));
            }
        }
        for (checkpoint_id, batch_records) in &checkpoint_records {
            checkpoint_dependencies
                .get(checkpoint_id)
                .ok_or_else(|| RuntimeError::CheckpointDependencyMissing(checkpoint_id.clone()))?
                .validate_graph_dependencies(batch_records)?;
        }
        let context = combined_historical_validation_context(
            checkpoint_dependencies.values(),
            provider_intakes.values().cloned(),
        )?;
        records.validate(&context)?;
        let inspector = InspectorProjection::rebuilt(&rows);
        Ok(ReopenedState {
            checkpoint,
            rows,
            rows_by_id,
            records,
            provider_intakes,
            checkpoint_dependencies,
            inspector,
        })
    }

    fn install_reopened(&mut self, reopened: ReopenedState) {
        self.checkpoint = reopened.checkpoint;
        self.rows = reopened.rows;
        self.rows_by_id = reopened.rows_by_id;
        self.records = reopened.records;
        self.provider_intakes = reopened.provider_intakes;
        self.checkpoint_dependencies = reopened.checkpoint_dependencies;
        self.inspector = reopened.inspector;
    }
}

fn fresh_authority_expectations(
    resident: &RuntimeAuthorityResidentBinding,
    trust_anchor_id: Sha256Digest,
) -> ActivationExpectations {
    ActivationExpectations {
        genesis_context: ActivationContext::FreshGenesis,
        expected_occurrence_id: None,
        resident_identity: resident.resident_identity.clone(),
        resident_generation: resident.resident_generation,
        host_role: resident.host_role.clone(),
        role_manifest_generation: resident.role_manifest_generation,
        trust_anchor_id,
        domain: resident.domain.clone(),
        policy_floor: resident.policy_floor,
        migration: None,
    }
}

fn resolve_store_runtime_authority(
    store: &mut Store,
    dependencies: &RuntimeDependencies,
    custody: &GenesisAuthorityCustody,
    resident: &RuntimeAuthorityResidentBinding,
) -> Result<()> {
    let dependency_anchor = dependencies.custody().trust_anchor_id()?;
    store.with_runtime_authority_restart_snapshot(|snapshot| {
        let receipt = snapshot.receipt;
        let root = snapshot.root;
        let occurrence = snapshot.occurrence_id;
        if root != dependency_anchor {
            return Err(RuntimeError::DependencyTrustAnchorSubstitution {
                expected: root,
                observed: dependency_anchor,
            });
        }
        let transcript = &receipt.transcript;
        if transcript.occurrence_id() != occurrence
            || transcript.trust_anchor_id() != &root
            || transcript.domain() != resident.domain
        {
            return Err(nq_store::StoreError::EstablishmentTranscriptMismatch.into());
        }
        let (genesis_context, expected_migration_receipt_digest) = match transcript.arm() {
            EstablishmentArm::Genesis => (ActivationContext::FreshGenesis, None),
            EstablishmentArm::Migration => (
                ActivationContext::MigrationGenesis,
                Some(
                    transcript
                        .migration_receipt_digest()
                        .ok_or(nq_store::StoreError::EstablishmentMigrationMismatch)?
                        .clone(),
                ),
            ),
        };
        let expectations = RestartExpectations {
            genesis_context,
            expected_occurrence_id: occurrence,
            expected_chain_root_activation_digest: transcript
                .chain_root_activation_digest()
                .clone(),
            expected_establishment_tip_digest: transcript
                .controlling_tip_digest_at_establishment()
                .clone(),
            expected_genesis_operator_authority_digest: transcript
                .genesis_operator_authority_digest()
                .clone(),
            expected_genesis_operator_key_generation: transcript.genesis_operator_key_generation(),
            expected_establishment_cut: transcript.establishment_cut().clone(),
            expected_establishment_policy_version: transcript.policy_version(),
            expected_establishment_candidate_set_digest: transcript.candidate_set_digest().clone(),
            resident_identity: resident.resident_identity.clone(),
            resident_generation: resident.resident_generation,
            host_role: resident.host_role.clone(),
            role_manifest_generation: resident.role_manifest_generation,
            trust_anchor_id: root,
            domain: resident.domain.clone(),
            policy_floor: resident.policy_floor,
            expected_custody_digest: transcript.custody_digest().clone(),
            expected_migration_receipt_digest,
        };
        let _resolved = resolve_for_restart(
            custody,
            &snapshot.presented,
            snapshot.migration_receipt.as_ref(),
            &expectations,
        )?;
        Ok(())
    })
}

fn remove_failed_fresh_store(path: &Path) {
    let _ = fs::remove_file(path);
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = fs::remove_file(sidecar);
    }
}

fn linux_clock_ns(clock_id: ClockId, name: &'static str) -> Result<u64> {
    let sample =
        clock_gettime(clock_id).map_err(|_| RuntimeError::NativeDeadlineClockUnavailable(name))?;
    let seconds = u64::try_from(sample.tv_sec())
        .map_err(|_| RuntimeError::NativeDeadlineClockInvalid(name))?;
    let nanoseconds = u64::try_from(sample.tv_nsec())
        .map_err(|_| RuntimeError::NativeDeadlineClockInvalid(name))?;
    if nanoseconds >= 1_000_000_000 {
        return Err(RuntimeError::NativeDeadlineClockInvalid(name));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(RuntimeError::NativeDeadlineClockInvalid(name))
}

fn sample_native_deadline(source: &mut impl NativeDeadlineSource) -> Result<NativeDeadlineSample> {
    let boot_before = source.read_boot_id()?;
    validate_linux_boot_id(&boot_before)?;
    let realtime_before_ns = source.realtime_ns()?;
    let boottime_at_ns = source.boottime_ns()?;
    let realtime_after_ns = source.realtime_ns()?;
    let boot_after = source.read_boot_id()?;
    validate_linux_boot_id(&boot_after)?;
    if boot_before != boot_after {
        return Err(RuntimeError::NativeDeadlineBootIdentityChanged);
    }
    Ok(NativeDeadlineSample {
        realtime_before_ns,
        boottime_at_ns,
        realtime_after_ns,
        boot_epoch: sha256_bytes(&boot_before),
    })
}

fn validate_linux_boot_id(bytes: &[u8]) -> Result<()> {
    let Some((uuid, suffix)) = bytes.split_last().map(|(last, prefix)| (prefix, *last)) else {
        return Err(RuntimeError::NativeDeadlineBootIdentityMalformed);
    };
    if suffix != b'\n' || uuid.len() != 36 {
        return Err(RuntimeError::NativeDeadlineBootIdentityMalformed);
    }
    for (index, byte) in uuid.iter().copied().enumerate() {
        let expected_hyphen = matches!(index, 8 | 13 | 18 | 23);
        if (expected_hyphen && byte != b'-')
            || (!expected_hyphen && !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(RuntimeError::NativeDeadlineBootIdentityMalformed);
        }
    }
    Ok(())
}

fn realtime_timestamp(nanoseconds: u64) -> Result<String> {
    let seconds = i64::try_from(nanoseconds / 1_000_000_000)
        .map_err(|_| RuntimeError::NativeDeadlineClockInvalid("CLOCK_REALTIME"))?;
    let subsecond = u32::try_from(nanoseconds % 1_000_000_000)
        .map_err(|_| RuntimeError::NativeDeadlineClockInvalid("CLOCK_REALTIME"))?;
    DateTime::<Utc>::from_timestamp(seconds, subsecond)
        .ok_or(RuntimeError::NativeDeadlineClockInvalid("CLOCK_REALTIME"))
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

fn reopen_checkpoint_dependencies(
    store: &Store,
    checkpoint_id: &str,
    trust_root: &Sha256Digest,
) -> Result<RuntimeDependencies> {
    let access = store
        .runtime_checkpoint_dependency(checkpoint_id)?
        .ok_or_else(|| RuntimeError::CheckpointDependencyMissing(checkpoint_id.to_owned()))?;
    let (generation_id, trust_anchor_id, custody_digest, custody_length) = match access.binding {
        RuntimeCheckpointDependencyBinding::LegacyUnbound { .. } => {
            return Err(RuntimeError::LegacyCheckpointDependencyUnbound(
                checkpoint_id.to_owned(),
            ));
        }
        RuntimeCheckpointDependencyBinding::Authenticated {
            dependency_generation_id,
            trust_anchor_id,
            canonical_bytes_sha256,
            canonical_bytes_length,
        } => (
            dependency_generation_id,
            trust_anchor_id,
            canonical_bytes_sha256,
            canonical_bytes_length,
        ),
    };
    if trust_anchor_id != *trust_root {
        return Err(RuntimeError::DependencyTrustAnchorSubstitution {
            expected: trust_root.clone(),
            observed: trust_anchor_id,
        });
    }
    let canonical_custody = match access.byte_state {
        Some(RuntimeDependencyGenerationByteState::VerifiedAvailable { canonical_custody }) => {
            canonical_custody
        }
        Some(RuntimeDependencyGenerationByteState::CommittedUnavailable) => {
            return Err(RuntimeError::CheckpointDependencyUnavailable(
                checkpoint_id.to_owned(),
            ));
        }
        Some(RuntimeDependencyGenerationByteState::Corrupt { reason }) => {
            return Err(RuntimeError::CheckpointDependencyCorrupt {
                checkpoint_id: checkpoint_id.to_owned(),
                reason,
            });
        }
        None => {
            return Err(RuntimeError::CheckpointDependencyMissing(
                checkpoint_id.to_owned(),
            ));
        }
    };
    let binding = ExactDependencyCustodyBinding::new(
        generation_id,
        trust_anchor_id,
        custody_digest,
        custody_length,
    )
    .map_err(|error| checkpoint_dependency_binding_error(checkpoint_id, error))?;
    AuthenticatedRuntimeDependencyClosure::reopen_bound(canonical_custody.as_bytes(), &binding)
        .map_err(|error| checkpoint_dependency_binding_error(checkpoint_id, error))
}

fn checkpoint_dependency_binding_error(
    checkpoint_id: &str,
    error: DependencyCustodyError,
) -> RuntimeError {
    match error {
        DependencyCustodyError::CustodyBindingLengthZero
        | DependencyCustodyError::CustodyLengthOverflow
        | DependencyCustodyError::CustodyLengthMismatch { .. }
        | DependencyCustodyError::CustodyDigestMismatch { .. } => {
            RuntimeError::CheckpointDependencyCorrupt {
                checkpoint_id: checkpoint_id.to_owned(),
                reason: error.to_string(),
            }
        }
        other => RuntimeError::from(other),
    }
}

fn combined_historical_validation_context<'a>(
    dependencies: impl IntoIterator<Item = &'a RuntimeDependencies>,
    provider_intakes: impl IntoIterator<Item = RecordRef>,
) -> Result<ValidationContext> {
    let mut identities = IdentityCatalog::new();
    let mut external_records = ExternalRecordCatalog::new();
    for dependency in dependencies {
        for identity in &dependency.catalog_snapshot().identities {
            identities.insert(identity.clone())?;
        }
        for external in &dependency.external_dependency_snapshot().dependencies {
            if external.availability != ExternalDependencyAvailability::CommittedUnavailable {
                external_records.insert(external.reference.clone());
            }
        }
    }
    for provider_intake in provider_intakes {
        external_records.insert(provider_intake);
    }
    Ok(ValidationContext {
        identities,
        external_records,
    })
}

fn required_record<'a>(
    records: &'a RuntimeRecordSet,
    record_id: &Sha256Digest,
    schema: RuntimeSchema,
) -> Result<&'a ValidatedRuntimeRecord> {
    let record = records
        .get(record_id)
        .ok_or_else(|| RuntimeError::PrelaunchRecordMissing(record_id.to_string()))?;
    if record.schema() != schema {
        return Err(RuntimeError::PrelaunchRecordSchemaMismatch {
            record_id: record_id.clone(),
            expected: schema.as_str(),
            observed: record.schema().as_str(),
        });
    }
    Ok(record)
}

fn exact_record<'a>(
    records: &'a RuntimeRecordSet,
    reference: &RecordRef,
    schema: RuntimeSchema,
) -> Result<&'a ValidatedRuntimeRecord> {
    let record = required_record(records, &reference.record_id, schema)?;
    if record.exact_reference() != *reference {
        return Err(RuntimeError::NativeDeadlineClockQualificationMissing);
    }
    Ok(record)
}

#[allow(clippy::too_many_lines)]
fn exact_cohort_clock_qualification(
    records: &RuntimeRecordSet,
    activation: &ValidatedRuntimeRecord,
    request: &ValidatedRuntimeRecord,
) -> Result<RecordRef> {
    let activation_value = activation.record().as_value();
    let request_value = request.record().as_value();
    let cohort_reference: RecordRef =
        serde_json::from_value(activation_value["cohort_manifest"].clone())?;
    let cohort = exact_record(
        records,
        &cohort_reference,
        RuntimeSchema::StaticProfileCohortManifestV1,
    )?;
    let cohort_value = cohort.record().as_value();
    let cohort_identity: IdentityRef = serde_json::from_value(cohort_value["cohort"].clone())?;
    let cohort_generation = required_text(cohort_value, "generation")?;
    let semantics_digest = cohort_semantics_digest(cohort_value)?;
    let subject_platform_reference: RecordRef =
        serde_json::from_value(activation_value["relations"]["subject_platform"].clone())?;
    let subject_platform = exact_record(
        records,
        &subject_platform_reference,
        RuntimeSchema::HostRoleRelationV1,
    )?;
    if subject_platform.record().as_value()["relation_kind"] != "subject_platform"
        || subject_platform.record().as_value()["left"] != request_value["target"]["subject"]
    {
        return Err(RuntimeError::NativeDeadlineClockQualificationMissing);
    }
    let platform = &subject_platform.record().as_value()["right"];
    let clock = &request_value["time_bounds"]["clock"];
    let compatible_builds = cohort_value["compatible_builds"]
        .as_array()
        .ok_or(RuntimeError::NativeDeadlineClockQualificationMissing)?;
    let qualification_references = cohort_value["qualification_records"]
        .as_array()
        .ok_or(RuntimeError::NativeDeadlineClockQualificationMissing)?;
    let mut candidates = Vec::new();
    for value in qualification_references {
        let reference: RecordRef = serde_json::from_value(value.clone())?;
        if reference.schema.as_str() != RuntimeSchema::NativeClockQualificationV1.as_str() {
            continue;
        }
        let qualification = exact_record(
            records,
            &reference,
            RuntimeSchema::NativeClockQualificationV1,
        )?;
        let value = qualification.record().as_value();
        if value["namespace"] == cohort_value["namespace"]
            && value["cohort"] == serde_json::to_value(&cohort_identity)?
            && value["cohort_generation"] == cohort_generation
            && value["cohort_semantics_digest"] == semantics_digest.as_str()
            && value["production_clock"] == *clock
            && value["platform"] == *platform
            && compatible_builds
                .iter()
                .filter(|build| **build == value["production_build"])
                .count()
                == 1
        {
            candidates.push(qualification.exact_reference());
        }
    }
    let [qualification] = candidates.as_slice() else {
        return Err(RuntimeError::NativeDeadlineClockQualificationMissing);
    };
    Ok(qualification.clone())
}

fn cohort_semantics_digest(cohort: &Value) -> Result<Sha256Digest> {
    let object = cohort
        .as_object()
        .ok_or(RuntimeError::NativeDeadlineClockQualificationMissing)?;
    let mut body = serde_json::Map::new();
    body.insert(
        "semantic_schema".to_owned(),
        Value::String("nq.static_profile_cohort_semantics.v1".to_owned()),
    );
    for field in [
        "namespace",
        "cohort",
        "generation",
        "effective_interval",
        "members",
        "compatible_builds",
        "protocol_store_compatibility",
        "nonclaims",
    ] {
        body.insert(
            field.to_owned(),
            object
                .get(field)
                .cloned()
                .ok_or(RuntimeError::NativeDeadlineClockQualificationMissing)?,
        );
    }
    Ok(semantic_digest(&Value::Object(body))?)
}

fn required_text<'a>(value: &'a Value, field: &'static str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(RuntimeError::NativeDeadlinePolicyInvalid)
}

fn seal_semantic_identity(value: &mut Value, identity_field: &'static str) -> Result<()> {
    let object = value
        .as_object_mut()
        .ok_or(RuntimeError::NativeDeadlinePolicyInvalid)?;
    object.remove(identity_field);
    let identity = semantic_digest(&Value::Object(object.clone()))?;
    object.insert(
        identity_field.to_owned(),
        Value::String(identity.to_string()),
    );
    let canonical = canonical_json_bytes(value)?;
    if canonical.is_empty() {
        return Err(RuntimeError::NativeDeadlinePolicyInvalid);
    }
    Ok(())
}

fn read_complete_ledger(
    store: &Store,
    checkpoint: Option<&RuntimeLedgerCheckpoint>,
) -> Result<Vec<RuntimeRecordRow>> {
    let mut rows = Vec::new();
    let mut after = 0_u64;
    loop {
        let page = store.runtime_record_page(checkpoint, after, MAX_PUBLIC_QUERY_ROWS)?;
        rows.extend(page.records);
        if page.complete {
            break;
        }
        after = page
            .next_after_record_sequence
            .ok_or(RuntimeError::LedgerCarrierMismatch(
                "runtime page continuation",
            ))?;
    }
    Ok(rows)
}

fn collect_carriers(
    value: &Value,
    identities: &mut Vec<IdentityRef>,
    references: &mut Vec<RecordRef>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                identities.push(serde_json::from_value(value.clone())?);
            } else if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                references.push(serde_json::from_value(value.clone())?);
            } else {
                for child in object.values() {
                    collect_carriers(child, identities, references)?;
                }
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_carriers(child, identities, references)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use nq_host_role_contract::{
        IdentityId, IdentityKind, IdentityVersion, RuntimeSchema, ValidatedRuntimeRecord,
    };
    use nq_protocol::{canonical_json_bytes, semantic_digest, sha256_bytes};
    use nq_runtime_dependency_authority::GenesisAuthorityCustody;
    use nq_runtime_dependency_authority::test_support::{
        FIXTURE_DOMAIN, FIXTURE_HOST_ROLE, FIXTURE_RESIDENT_GENERATION, FIXTURE_RESIDENT_ID,
        FIXTURE_ROLE_MANIFEST_GENERATION, RawAuthorityFixture,
    };
    use nq_runtime_dependency_authority::verify_resident_activation_successor;
    use nq_store::{
        GovernedAcquisitionCustodyInput, GovernedCustodyInventoryEntry,
        GovernedCustodyRecoveryClass, GovernedCustodyReservationLedgerBinding,
        GovernedCustodyState, GovernedDerivationCustodyClaim, GovernedProtectedFailureAccess,
        GovernedProtectedTerminalClass, GovernedProtectedTerminalDeadlineCompliance,
        GovernedProtectedTerminalDisposition, GovernedProtectedTerminalInput,
        GovernedProtectedTerminalReason, Store,
    };
    use serde_json::{Map, Value, json};
    use tempfile::tempdir;

    use super::super::{
        GovernedPrelaunchRequest, RuntimeError, dependency::tests::authenticated_runtime_fixture,
    };
    use super::*;

    const RECORDS: &str =
        include_str!("../../nq-host-role-contract/assets/host-role-runtime-records.v1.json");

    fn test_resident_binding() -> RuntimeAuthorityResidentBinding {
        RuntimeAuthorityResidentBinding {
            resident_identity: FIXTURE_RESIDENT_ID.to_owned(),
            resident_generation: FIXTURE_RESIDENT_GENERATION,
            host_role: FIXTURE_HOST_ROLE.to_owned(),
            role_manifest_generation: FIXTURE_ROLE_MANIFEST_GENERATION,
            domain: FIXTURE_DOMAIN.to_owned(),
            policy_floor: 1,
        }
    }

    fn initialize_test_runtime(
        path: impl AsRef<Path>,
        dependencies: RuntimeDependencies,
    ) -> Result<HostRoleRuntime> {
        let anchor = dependencies.custody().trust_anchor_id()?;
        let authority = RawAuthorityFixture::fresh_genesis_with_anchor(anchor);
        HostRoleRuntime::initialize(
            path,
            dependencies,
            &authority.custody(),
            &test_resident_binding(),
        )
    }

    fn open_test_runtime(
        path: impl AsRef<Path>,
        dependencies: RuntimeDependencies,
    ) -> Result<HostRoleRuntime> {
        let anchor = dependencies.custody().trust_anchor_id()?;
        let authority = RawAuthorityFixture::fresh_genesis_with_anchor(anchor);
        HostRoleRuntime::open(
            path,
            dependencies,
            &authority.custody(),
            &test_resident_binding(),
        )
    }

    fn runtime_store_file_family(path: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        std::iter::once("")
            .chain(["-journal", "-wal", "-shm"])
            .map(|suffix| {
                let mut member = path.as_os_str().to_os_string();
                member.push(suffix);
                let member = std::path::PathBuf::from(member);
                (
                    suffix.to_owned(),
                    member
                        .exists()
                        .then(|| std::fs::read(member).expect("Store family member")),
                )
            })
            .collect()
    }

    fn establish_runtime_authority_fixture(
        path: &Path,
        dependencies: RuntimeDependencies,
    ) -> RawAuthorityFixture {
        let anchor = dependencies
            .custody()
            .trust_anchor_id()
            .expect("fixture anchor");
        let authority = RawAuthorityFixture::fresh_genesis_with_anchor(anchor);
        drop(
            HostRoleRuntime::initialize(
                path,
                dependencies,
                &authority.custody(),
                &test_resident_binding(),
            )
            .expect("Gen4 runtime establishes"),
        );
        authority
    }

    #[test]
    fn gen4_invalid_genesis_authority_refuses_before_creating_store_bytes() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("invalid-authority.sqlite");
        let runtime_fixture = fixture();
        let authority = RawAuthorityFixture::fresh_genesis_with_anchor(
            runtime_fixture
                .dependencies
                .custody()
                .trust_anchor_id()
                .expect("fixture anchor"),
        );
        let valid = authority.custody();
        let mut invalid_a2 = valid.genesis_a2_bytes().to_vec();
        invalid_a2.push(b' ');
        let invalid = GenesisAuthorityCustody::new(valid.genesis_a1_bytes().to_vec(), invalid_a2);

        assert!(
            HostRoleRuntime::initialize(
                &database,
                runtime_fixture.dependencies,
                &invalid,
                &test_resident_binding(),
            )
            .is_err()
        );
        assert_eq!(
            runtime_store_file_family(&database),
            vec![
                (String::new(), None),
                ("-journal".to_owned(), None),
                ("-wal".to_owned(), None),
                ("-shm".to_owned(), None),
            ],
            "pre-establishment authority refusal created Store bytes"
        );
    }

    #[test]
    fn gen4_open_refuses_wrong_custody_and_resident_without_writing() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("wrong-restart-authority.sqlite");
        let runtime_fixture = fixture();
        let correct =
            establish_runtime_authority_fixture(&database, runtime_fixture.dependencies.clone());
        let before = runtime_store_file_family(&database);
        let wrong = RawAuthorityFixture::fresh_genesis_with_anchor(sha256_bytes(b"other anchor"));

        assert!(
            HostRoleRuntime::open(
                &database,
                runtime_fixture.dependencies.clone(),
                &wrong.custody(),
                &test_resident_binding(),
            )
            .is_err()
        );
        assert_eq!(runtime_store_file_family(&database), before);

        let mut wrong_resident = test_resident_binding();
        wrong_resident.resident_identity = "resident/attacker".to_owned();
        assert!(
            HostRoleRuntime::open(
                &database,
                runtime_fixture.dependencies,
                &correct.custody(),
                &wrong_resident,
            )
            .is_err()
        );
        assert_eq!(
            runtime_store_file_family(&database),
            before,
            "restart authority refusals changed Store bytes or sidecars"
        );
    }

    #[test]
    fn gen4_open_refuses_missing_receipt_without_repair_or_write() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("missing-receipt.sqlite");
        let runtime_fixture = fixture();
        let authority =
            establish_runtime_authority_fixture(&database, runtime_fixture.dependencies.clone());
        {
            let connection = rusqlite::Connection::open(&database).expect("tamper fixture");
            connection
                .execute_batch(
                    "DROP TRIGGER immutable_runtime_dependency_establishment_receipts_delete;
                     DELETE FROM runtime_dependency_establishment_receipts;
                     CREATE TRIGGER immutable_runtime_dependency_establishment_receipts_delete BEFORE DELETE ON runtime_dependency_establishment_receipts BEGIN SELECT RAISE(ABORT, 'append-only table'); END;",
                )
                .expect("construct missing-receipt hostile Store");
        }
        let before = runtime_store_file_family(&database);

        assert!(matches!(
            HostRoleRuntime::open(
                &database,
                runtime_fixture.dependencies,
                &authority.custody(),
                &test_resident_binding(),
            ),
            Err(RuntimeError::Store(StoreError::EstablishmentReceiptMissing))
        ));
        assert_eq!(
            runtime_store_file_family(&database),
            before,
            "ordinary restart repaired or wrote a missing receipt"
        );
    }

    #[test]
    fn gen4_open_refuses_malformed_store_resident_authority_without_filtering_or_write() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("malformed-authority.sqlite");
        let runtime_fixture = fixture();
        let authority =
            establish_runtime_authority_fixture(&database, runtime_fixture.dependencies.clone());
        let malformed = b"{";
        let malformed_digest = sha256_bytes(malformed);
        {
            let connection = rusqlite::Connection::open(&database).expect("hostile fixture");
            connection
                .execute(
                    "INSERT INTO runtime_resident_activation_successors (
                        record_id, canonical_bytes, canonical_bytes_sha256,
                        canonical_bytes_length, committed_at
                     ) VALUES (?1, ?2, ?3, ?4, '2026-08-01T00:00:00Z')",
                    rusqlite::params![
                        malformed_digest.as_str(),
                        malformed,
                        malformed_digest.as_str(),
                        malformed.len(),
                    ],
                )
                .expect("insert malformed but exactly digested resident record");
        }
        let before = runtime_store_file_family(&database);

        assert!(matches!(
            HostRoleRuntime::open(
                &database,
                runtime_fixture.dependencies,
                &authority.custody(),
                &test_resident_binding(),
            ),
            Err(RuntimeError::RuntimeAuthority(_)
                | RuntimeError::Store(StoreError::RuntimeAuthority(_)))
        ));
        assert_eq!(
            runtime_store_file_family(&database),
            before,
            "invalid resident authority was filtered, repaired, or wrote a refusal artifact"
        );
    }

    #[test]
    fn gen4_open_refuses_sql_identity_substitution_for_each_native_family_without_writing() {
        let directory = tempdir().expect("native identity hostile directory");
        for (label, table, expected_family, family) in [
            (
                "operator",
                "runtime_operator_authority_rotations",
                "operator_authority_rotation",
                0_u8,
            ),
            (
                "activation",
                "runtime_resident_activation_successors",
                "resident_activation_successor",
                1_u8,
            ),
            (
                "revocation",
                "runtime_activation_revocations",
                "activation_revocation",
                2_u8,
            ),
        ] {
            let database = directory
                .path()
                .join(format!("sql-identity-{label}.sqlite"));
            let runtime_fixture = fixture();
            let mut authority = establish_runtime_authority_fixture(
                &database,
                runtime_fixture.dependencies.clone(),
            );
            let bytes = match family {
                0 => authority.append_operator_rotation(),
                1 => authority.append_activation_successor(),
                2 => authority.append_current_activation_revocation(),
                _ => unreachable!("closed native authority family"),
            };
            let malicious_id = sha256_bytes(format!("malicious SQL identity/{label}").as_bytes());
            {
                let connection = rusqlite::Connection::open(&database).expect("hostile fixture");
                connection
                    .execute(
                        &format!(
                            "INSERT INTO {table} (
                                record_id, canonical_bytes, canonical_bytes_sha256,
                                canonical_bytes_length, committed_at
                             ) VALUES (?1, ?2, ?3, ?4, '2026-08-01T00:00:00Z')"
                        ),
                        rusqlite::params![
                            malicious_id.as_str(),
                            &bytes,
                            sha256_bytes(&bytes).as_str(),
                            i64::try_from(bytes.len()).expect("native hostile length"),
                        ],
                    )
                    .expect("insert exact bytes under substituted SQL identity");
            }
            let before = runtime_store_file_family(&database);
            assert!(matches!(
                HostRoleRuntime::open(
                    &database,
                    runtime_fixture.dependencies,
                    &authority.custody(),
                    &test_resident_binding(),
                ),
                Err(RuntimeError::Store(
                    StoreError::AuthorityNativeRecordIdentityMismatch { family, .. }
                )) if family == expected_family
            ));
            assert_eq!(
                runtime_store_file_family(&database),
                before,
                "{label} SQL identity refusal changed Store bytes or sidecars"
            );
        }
    }

    #[test]
    fn gen4_runtime_reopens_after_a_lawful_activation_successor() {
        let directory = tempdir().expect("successor reopen directory");
        let database = directory.path().join("successor-reopen.sqlite");
        let runtime_fixture = fixture();
        let dependencies = runtime_fixture.dependencies;
        let anchor = dependencies
            .custody()
            .trust_anchor_id()
            .expect("successor dependency anchor");
        let mut authority = RawAuthorityFixture::fresh_genesis_with_anchor(anchor);
        let custody = authority.custody();
        let runtime = HostRoleRuntime::initialize(
            &database,
            dependencies.clone(),
            &custody,
            &test_resident_binding(),
        )
        .expect("initialize successor runtime");
        let mut store = runtime.into_store();
        let current = store
            .runtime_authority_presented_set()
            .expect("genesis candidate set");
        let successor = authority.append_activation_successor();
        let expectations = authority.activation_expectations();
        store
            .with_runtime_authority_writer_session(|brand, session| {
                let verified = verify_resident_activation_successor(
                    brand,
                    &custody,
                    &current,
                    &successor,
                    None,
                    &expectations,
                )?;
                session.append_runtime_resident_activation_successor(&verified)
            })
            .expect("append lawful activation successor");
        drop(store);

        let reopened =
            HostRoleRuntime::open(&database, dependencies, &custody, &test_resident_binding())
                .expect("production restart resolves successor tip");
        assert_eq!(
            reopened
                .into_store()
                .runtime_authority_presented_set()
                .expect("reopened authority set")
                .records()
                .len(),
            1
        );
    }

    #[test]
    fn checkpoint_context_wraps_only_exact_binding_failures_as_corruption() {
        for error in [
            DependencyCustodyError::CustodyBindingLengthZero,
            DependencyCustodyError::CustodyLengthOverflow,
            DependencyCustodyError::CustodyLengthMismatch {
                expected: 17,
                observed: 19,
            },
            DependencyCustodyError::CustodyDigestMismatch {
                expected: sha256_bytes(b"expected"),
                observed: sha256_bytes(b"observed"),
            },
        ] {
            assert!(matches!(
                checkpoint_dependency_binding_error("checkpoint", error),
                RuntimeError::CheckpointDependencyCorrupt { checkpoint_id, .. }
                    if checkpoint_id == "checkpoint"
            ));
        }
        assert!(matches!(
            checkpoint_dependency_binding_error(
                "checkpoint",
                DependencyCustodyError::DuplicateExternalSourceRequirement,
            ),
            RuntimeError::DuplicateExternalSourceRequirement
        ));
    }

    struct Fixture {
        dependencies: RuntimeDependencies,
        request: GovernedPrelaunchRequest,
        dependency_anchor_id: Sha256Digest,
        runtime_identities: Vec<IdentityRef>,
        external_inputs: Vec<(RecordRef, Vec<u8>)>,
        operation_authorizations: Vec<RecordRef>,
        authentication: Vec<RecordRef>,
        resolver: IdentityRef,
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> Fixture {
        fixture_with_configuration(false, false)
    }

    #[allow(clippy::too_many_lines)]
    fn native_fixture() -> Fixture {
        fixture_with_configuration(true, false)
    }

    #[allow(clippy::too_many_lines)]
    fn diagnostic_capacity_one_under_fixture() -> Fixture {
        fixture_with_configuration(false, true)
    }

    #[allow(clippy::too_many_lines)]
    fn fixture_with_configuration(
        include_native_qualifications: bool,
        diagnostic_capacity_one_under: bool,
    ) -> Fixture {
        let document: Value = serde_json::from_str(RECORDS).expect("runtime contract specimen");
        let mut values = document["records"]
            .as_object()
            .expect("records")
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        let original_records = values
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    ValidatedRuntimeRecord::validate_value(value.clone())
                        .unwrap_or_else(|error| panic!("{name}: {error}")),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let original_closure = transitive_runtime_closure(
            &original_records,
            [
                original_records["request"].exact_reference(),
                original_records["invocation_decision"].exact_reference(),
                original_records["custody_reservation"].exact_reference(),
                original_records["execution_launch"].exact_reference(),
            ],
        );
        values.retain(|name, _| original_closure.contains_key(name));
        let original_refs = exact_runtime_refs(&values);
        increase_fixture_dependency_capacity(&mut values);
        if diagnostic_capacity_one_under {
            reduce_fixture_diagnostic_capacity_one_byte(&mut values);
        }
        let mut external_inputs = install_production_identity_descriptors(&mut values);
        stabilize_runtime_references(&mut values, original_refs);
        if include_native_qualifications {
            let pre_qualification_refs = exact_runtime_refs(&values);
            install_native_qualifications(&mut values);
            stabilize_runtime_references(&mut values, pre_qualification_refs);
        }
        let original_refs = exact_runtime_refs(&values);
        external_inputs.extend(replace_external_references(&mut values));
        stabilize_runtime_references(&mut values, original_refs);
        let records = values
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    ValidatedRuntimeRecord::validate_value(value.clone())
                        .unwrap_or_else(|error| panic!("{name}: {error}")),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let request_record = records["request"].clone();
        let decision = records["invocation_decision"].clone();
        let reservation = records["custody_reservation"].clone();
        let launch = records["execution_launch"].clone();
        let closure = transitive_runtime_closure(
            &records,
            [
                request_record.exact_reference(),
                decision.exact_reference(),
                reservation.exact_reference(),
                launch.exact_reference(),
            ],
        );
        let mut identities = Vec::new();
        let mut external_refs = BTreeSet::new();
        for record in closure.values() {
            collect_test_carriers(
                record.record().as_value(),
                &mut identities,
                &mut external_refs,
            );
        }
        let (resolver, resolver_source) =
            production_identity_source(IdentityKind::Resolver, "nq-production-resolver", "1");
        identities.push(resolver.clone());
        external_inputs.push(resolver_source);
        for identity in &identities {
            let descriptor = external_inputs
                .iter()
                .find(|(reference, _)| {
                    reference.bytes_digest == identity.descriptor_digest
                        && reference.schema.as_str() == "nq.production_identity_descriptor.v1"
                })
                .unwrap_or_else(|| panic!("descriptor bytes for {identity:?}"));
            external_refs.insert(descriptor.0.clone());
        }
        let external_by_ref = external_inputs.into_iter().collect::<BTreeMap<_, _>>();
        let exact_external_inputs = external_refs
            .iter()
            .map(|reference| {
                (
                    reference.clone(),
                    external_by_ref
                        .get(reference)
                        .unwrap_or_else(|| panic!("external bytes for {reference:?}"))
                        .clone(),
                )
            })
            .collect::<Vec<_>>();
        let operation_authorizations = closure
            .values()
            .filter(|record| record.schema() == RuntimeSchema::OperationAuthorizationV1)
            .map(ValidatedRuntimeRecord::exact_reference)
            .collect::<Vec<_>>();
        let authentication: RecordRef = serde_json::from_value(
            request_record.record().as_value()["authentication_evidence"].clone(),
        )
        .expect("authentication reference");
        identities.sort();
        identities.dedup();
        let runtime_identities = identities.clone();
        let retained_external_inputs = exact_external_inputs.clone();
        let retained_operation_authorizations = operation_authorizations.clone();
        let retained_authentication = vec![authentication.clone()];
        let dependencies = authenticated_runtime_fixture(
            41,
            identities,
            exact_external_inputs,
            operation_authorizations,
            vec![authentication],
        );
        let dependency_anchor_id = dependencies
            .custody()
            .trust_anchor_id()
            .expect("trust anchor");

        let mut reservation_records = closure
            .values()
            .filter(|record| record.record_id() != launch.record_id())
            .map(|record| AppendRecord::from_contract(record, "2026-07-29T21:00:00Z"))
            .collect::<Vec<_>>();
        reservation_records.sort_by(|left, right| left.record_id.cmp(&right.record_id));
        let launch_record = AppendRecord::from_contract(&launch, "2026-07-29T21:00:01Z");
        Fixture {
            dependencies,
            request: GovernedPrelaunchRequest {
                reservation_custody: AppendRequest {
                    checkpoint_id: sha256_bytes(b"runtime-reservation-checkpoint").to_string(),
                    records: reservation_records,
                },
                launch_custody: AppendRequest {
                    checkpoint_id: sha256_bytes(b"runtime-launch-checkpoint").to_string(),
                    records: vec![launch_record],
                },
                outer_request_record_id: request_record.record_id().clone(),
                invocation_decision_record_id: decision.record_id().clone(),
                custody_reservation_record_id: reservation.record_id().clone(),
                execution_launch_record_id: launch.record_id().clone(),
            },
            dependency_anchor_id,
            runtime_identities,
            external_inputs: retained_external_inputs,
            operation_authorizations: retained_operation_authorizations,
            authentication: retained_authentication,
            resolver,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn install_native_qualifications(values: &mut BTreeMap<String, Value>) {
        let cohort = &values["cohort_manifest"];
        let cohort_semantics_digest =
            cohort_semantics_digest(cohort).expect("cohort semantics digest");
        let namespace = cohort["namespace"].clone();
        let cohort_identity = cohort["cohort"].clone();
        let cohort_generation = cohort["generation"].clone();
        let production_build = cohort["compatible_builds"][0].clone();
        let production_profile = cohort["members"]["profiles"][0].clone();
        let production_question = cohort["members"]["questions"][0].clone();
        let qualification_evidence = cohort["qualification_records"][0].clone();
        let production_clock = values["request"]["time_bounds"]["clock"].clone();
        let platform = values["subject_platform_relation"]["right"].clone();
        let mut profile = json!({
            "schema": "nq.native_profile_qualification.v1",
            "qualification_id": sha256_bytes(b"native profile placeholder"),
            "namespace": namespace,
            "cohort": cohort_identity,
            "cohort_generation": cohort_generation,
            "cohort_semantics_digest": cohort_semantics_digest,
            "production_profile": production_profile,
            "production_question": production_question,
            "production_build": production_build,
            "native_profile": {
                "descriptor_schema": "nq.profile_descriptor.v1",
                "profile_id": "nq.conformance",
                "profile_version": 1,
                "descriptor_digest": sha256_bytes(b"native profile descriptor"),
                "semantic_identity_schema": "nq.profile_semantic_id.v1",
                "semantic_identity_digest": sha256_bytes(b"native profile semantic identity"),
                "evaluator_source_digest": sha256_bytes(b"native evaluator source"),
                "helper_protocol_version": "nq.helper.v1",
                "detector_closure": {
                    "schema": "nq.detector_closure.v1",
                    "identity_digest": sha256_bytes(b"native detector closure"),
                    "detector_count": 0,
                },
            },
            "native_evaluator": {
                "artifact_digest": sha256_bytes(b"native evaluator artifact"),
                "artifact_identity_method": "linux-proc-self-exe-fd-sha256-v1",
                "target_triple": "x86_64-unknown-linux-gnu",
            },
            "qualification_evidence": [qualification_evidence],
            "nonclaims": [
                "relates production and native identities but does not equate them",
                "does not establish invocation, reliance, authorization, or action",
            ],
        });
        seal_semantic_identity(&mut profile, "qualification_id").expect("profile identity");
        let profile = ValidatedRuntimeRecord::validate_value(profile).expect("profile qualifier");

        let mut clock = json!({
            "schema": "nq.native_clock_qualification.v1",
            "qualification_id": sha256_bytes(b"native clock placeholder"),
            "namespace": values["cohort_manifest"]["namespace"],
            "cohort": values["cohort_manifest"]["cohort"],
            "cohort_generation": values["cohort_manifest"]["generation"],
            "cohort_semantics_digest": cohort_semantics_digest,
            "production_clock": production_clock,
            "production_build": values["cohort_manifest"]["compatible_builds"][0],
            "platform": platform,
            "absolute_time": {
                "semantic_identity_digest": sha256_bytes(b"native CLOCK_REALTIME semantics"),
                "observation_method": "clock_gettime-clock-realtime-v1",
                "clock_id": "CLOCK_REALTIME",
                "epoch": "unix",
                "unit": "nanosecond",
                "accuracy_qualification": {
                    "status": "unqualified",
                },
            },
            "boottime": {
                "semantic_identity_digest": sha256_bytes(b"native CLOCK_BOOTTIME semantics"),
                "observation_method": "clock_gettime-clock-boottime-v1",
                "clock_id": "CLOCK_BOOTTIME",
                "boot_epoch_binding_method": "linux-boot-id-v1",
                "unit": "nanosecond",
                "suspend_semantics": "includes_suspended_time",
            },
            "wall_to_monotonic_bridge": {
                "semantic_identity_digest": sha256_bytes(b"native clock bracket semantics"),
                "method": "realtime-boottime-bracket-v1",
            },
            "runner_watchdog": {
                "method": "std-instant-v1",
                "relation_to_governed_deadline": "auxiliary_non_equivalent",
            },
            "qualification_evidence": [
                values["cohort_manifest"]["qualification_records"][0],
            ],
            "nonclaims": [
                "UTC accuracy remains unqualified",
                "does not establish cross-host clock coherence",
                "runner watchdog is not the governed deadline",
            ],
        });
        seal_semantic_identity(&mut clock, "qualification_id").expect("clock identity");
        let clock = ValidatedRuntimeRecord::validate_value(clock).expect("clock qualifier");

        values.get_mut("cohort_manifest").expect("cohort manifest")["qualification_records"]
            .as_array_mut()
            .expect("qualification records")
            .extend([
                Value::from(profile.exact_reference()),
                Value::from(clock.exact_reference()),
            ]);
        values.insert(
            "native_profile_qualification".to_owned(),
            profile.record().as_value().clone(),
        );
        values.insert(
            "native_clock_qualification".to_owned(),
            clock.record().as_value().clone(),
        );
    }

    fn opaque_append(label: &str, committed_at: &str) -> AppendRequest {
        let canonical_bytes = canonical_json_bytes(&json!({
            "schema": PROVIDER_INTAKE_SCHEMA,
            "fixture": label,
        }))
        .expect("opaque provider intake");
        AppendRequest {
            checkpoint_id: sha256_bytes(format!("checkpoint:{label}").as_bytes()).to_string(),
            records: vec![AppendRecord::provider_intake(
                sha256_bytes(format!("record:{label}").as_bytes()).to_string(),
                canonical_bytes,
                committed_at,
            )],
        }
    }

    fn final_provider_intake(label: &str) -> AppendRecord {
        let canonical_bytes = canonical_json_bytes(&json!({
            "schema": PROVIDER_INTAKE_SCHEMA,
            "intake_id": format!("intake:{label}"),
            "fixture": label,
        }))
        .expect("opaque provider intake");
        AppendRecord::provider_intake(
            sha256_bytes(&canonical_bytes).to_string(),
            canonical_bytes,
            "2026-07-29T21:00:03Z",
        )
    }

    fn exact_prepared_record<'a>(
        prepared: &'a PreparedGovernedInvocation,
        reference: &RecordRef,
    ) -> &'a ValidatedRuntimeRecord {
        let record = prepared
            .prelaunch_records()
            .get(&reference.record_id)
            .unwrap_or_else(|| panic!("prepared record {reference:?}"));
        assert_eq!(record.exact_reference(), *reference);
        record
    }

    fn identity_descriptor_reference(
        prepared: &PreparedGovernedInvocation,
        identity: &IdentityRef,
    ) -> RecordRef {
        prepared
            .historical_dependencies
            .iter()
            .flat_map(|dependencies| {
                dependencies
                    .external_dependency_snapshot()
                    .dependencies
                    .iter()
            })
            .find(|dependency| {
                dependency.reference.bytes_digest == identity.descriptor_digest
                    && dependency.reference.schema.as_str()
                        == "nq.production_identity_descriptor.v1"
            })
            .unwrap_or_else(|| panic!("identity descriptor for {identity:?}"))
            .reference
            .clone()
    }

    fn resolved_binding_source(
        prepared: &PreparedGovernedInvocation,
        source: &ValidatedRuntimeRecord,
        pointer: &str,
        identity: &IdentityRef,
    ) -> Value {
        json!({
            "identity": identity,
            "source_artifact": source.exact_reference(),
            "source_pointer": pointer,
            "descriptor": identity_descriptor_reference(prepared, identity),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn final_execution_binding(
        prepared: &PreparedGovernedInvocation,
        resolver: &IdentityRef,
        provider_intake: &RecordRef,
    ) -> ValidatedRuntimeRecord {
        let request = exact_prepared_record(prepared, prepared.outer_request());
        let launch = exact_prepared_record(prepared, prepared.execution_launch());
        let activation_reference: RecordRef =
            serde_json::from_value(launch.record().as_value()["activation_snapshot"].clone())
                .expect("activation reference");
        let activation = exact_prepared_record(prepared, &activation_reference);
        let activation_value = activation.record().as_value();
        let relation = |name: &str| {
            let reference: RecordRef =
                serde_json::from_value(activation_value["relations"][name].clone())
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
            exact_prepared_record(prepared, &reference)
        };
        let node_subject = relation("node_subject");
        let subject_platform = relation("subject_platform");
        let node_vantage = relation("node_vantage");
        let role_reference: RecordRef =
            serde_json::from_value(activation_value["role_manifest"].clone())
                .expect("role manifest");
        let role = exact_prepared_record(prepared, &role_reference);
        let cohort_reference: RecordRef =
            serde_json::from_value(activation_value["cohort_manifest"].clone())
                .expect("cohort manifest");
        let cohort = exact_prepared_record(prepared, &cohort_reference);
        let witness_reference: RecordRef = serde_json::from_value(
            launch.record().as_value()["selected_witness_attachments"][0].clone(),
        )
        .expect("selected witness");
        let witness = exact_prepared_record(prepared, &witness_reference);

        let node: IdentityRef =
            serde_json::from_value(activation_value["node"].clone()).expect("node");
        let subject: IdentityRef =
            serde_json::from_value(node_subject.record().as_value()["right"].clone())
                .expect("subject");
        let platform: IdentityRef =
            serde_json::from_value(subject_platform.record().as_value()["right"].clone())
                .expect("platform");
        let vantage: IdentityRef =
            serde_json::from_value(node_vantage.record().as_value()["right"].clone())
                .expect("vantage");
        let role_identity: IdentityRef =
            serde_json::from_value(role.record().as_value()["role"].clone())
                .expect("role identity");
        let cohort_identity: IdentityRef =
            serde_json::from_value(cohort.record().as_value()["cohort"].clone())
                .expect("cohort identity");
        let witness_identity: IdentityRef =
            serde_json::from_value(witness.record().as_value()["witness"].clone())
                .expect("witness identity");
        let requested_profile: IdentityRef =
            serde_json::from_value(request.record().as_value()["profile"].clone())
                .expect("requested profile");
        let profiles = cohort.record().as_value()["members"]["profiles"]
            .as_array()
            .expect("cohort profiles");
        let profile_index = profiles
            .iter()
            .position(|profile| profile == &request.record().as_value()["profile"])
            .expect("requested profile in cohort");
        let enrollment_reference: RecordRef =
            serde_json::from_value(activation_value["enrollment"].clone()).expect("enrollment");

        let mut binding = json!({
            "schema": RuntimeSchema::ExecutionIdentityBindingV2.as_str(),
            "binding_id": sha256_bytes(b"final binding placeholder"),
            "diagnostic": {
                "schema": "nq.diagnostic_execution.v2",
                "artifact_id": sha256_bytes(b"final diagnostic artifact"),
                "file_bytes_digest": sha256_bytes(b"final diagnostic artifact bytes"),
                "request_id": prepared.request_id(),
            },
            "namespace": request.record().as_value()["namespace"],
            "resolver": resolver,
            "outer_request": request.exact_reference(),
            "invocation_decision": prepared.invocation_decision(),
            "execution_launch": launch.exact_reference(),
            "enrollment": enrollment_reference,
            "activation": activation.exact_reference(),
            "source_relations": activation_value["relations"],
            "role_manifest": role.exact_reference(),
            "static_profile_cohort_manifest": cohort.exact_reference(),
            "witness_attachments": [witness.exact_reference()],
            "provider_attempts": [provider_intake],
            "resolved_references": {
                "node": resolved_binding_source(prepared, activation, "/node", &node),
                "subject":
                    resolved_binding_source(prepared, node_subject, "/right", &subject),
                "platform":
                    resolved_binding_source(prepared, subject_platform, "/right", &platform),
                "vantage":
                    resolved_binding_source(prepared, node_vantage, "/right", &vantage),
                "role": resolved_binding_source(prepared, role, "/role", &role_identity),
                "static_profile_cohort":
                    resolved_binding_source(prepared, cohort, "/cohort", &cohort_identity),
                "witness":
                    resolved_binding_source(prepared, witness, "/witness", &witness_identity),
                "diagnostic_profile": resolved_binding_source(
                    prepared,
                    cohort,
                    &format!("/members/profiles/{profile_index}"),
                    &requested_profile,
                ),
            },
            "binding_result": "resolved",
            "nonclaims": [
                "does not modify nq.diagnostic_execution.v2 bytes",
                "does not establish reliance or authorization",
            ],
        });
        seal_semantic_identity(&mut binding, "binding_id").expect("binding identity");
        ValidatedRuntimeRecord::validate_value(binding).expect("execution binding")
    }

    fn extra_identity(id: &str) -> IdentityRef {
        IdentityRef {
            kind: IdentityKind::Capability,
            id: IdentityId::parse(id).expect("extra identity"),
            version: IdentityVersion::parse("v1").expect("extra identity version"),
            descriptor_digest: sha256_bytes(format!("extra:{id}:v1").as_bytes()),
        }
    }

    #[derive(Clone, Copy)]
    enum ScriptedFailure {
        FirstBootRead,
        FirstRealtime,
        Boottime,
        SecondRealtime,
        SecondBootRead,
    }

    struct ScriptedDeadlineSource {
        realtime: [u64; 2],
        boottime: u64,
        boot_id: Vec<u8>,
        changed_boot_id: Option<Vec<u8>>,
        failure: Option<ScriptedFailure>,
        realtime_reads: usize,
        boot_reads: usize,
    }

    impl ScriptedDeadlineSource {
        fn accepted() -> Self {
            Self {
                realtime: [
                    realtime_ns("2026-07-28T22:02:02.000000000Z"),
                    realtime_ns("2026-07-28T22:02:02.000001000Z"),
                ],
                boottime: 10_000_000_000_000_000,
                boot_id: b"01234567-89ab-cdef-0123-456789abcdef\n".to_vec(),
                changed_boot_id: None,
                failure: None,
                realtime_reads: 0,
                boot_reads: 0,
            }
        }
    }

    impl NativeDeadlineSource for ScriptedDeadlineSource {
        fn read_boot_id(&mut self) -> Result<Vec<u8>> {
            let read = self.boot_reads;
            self.boot_reads += 1;
            if matches!(
                (self.failure, read),
                (Some(ScriptedFailure::FirstBootRead), 0)
                    | (Some(ScriptedFailure::SecondBootRead), 1)
            ) {
                return Err(RuntimeError::NativeDeadlineBootIdentityUnavailable);
            }
            if read == 1
                && let Some(changed) = &self.changed_boot_id
            {
                return Ok(changed.clone());
            }
            Ok(self.boot_id.clone())
        }

        fn realtime_ns(&mut self) -> Result<u64> {
            let read = self.realtime_reads;
            self.realtime_reads += 1;
            if matches!(
                (self.failure, read),
                (Some(ScriptedFailure::FirstRealtime), 0)
                    | (Some(ScriptedFailure::SecondRealtime), 1)
            ) {
                return Err(RuntimeError::NativeDeadlineClockUnavailable(
                    "CLOCK_REALTIME",
                ));
            }
            Ok(self.realtime[read])
        }

        fn boottime_ns(&mut self) -> Result<u64> {
            if matches!(self.failure, Some(ScriptedFailure::Boottime)) {
                return Err(RuntimeError::NativeDeadlineClockUnavailable(
                    "CLOCK_BOOTTIME",
                ));
            }
            Ok(self.boottime)
        }
    }

    fn realtime_ns(value: &str) -> u64 {
        u64::try_from(
            Timestamp::parse(value)
                .expect("timestamp")
                .instant()
                .timestamp_nanos_opt()
                .expect("nanoseconds"),
        )
        .expect("positive realtime")
    }

    fn native_request(fixture: &Fixture) -> NativeDeadlinePrelaunchRequest {
        let launch: Value =
            serde_json::from_slice(&fixture.request.launch_custody.records[0].canonical_bytes)
                .expect("generic launch");
        let reservation = fixture
            .request
            .reservation_custody
            .records
            .iter()
            .find(|record| {
                record.record_id == fixture.request.custody_reservation_record_id.as_str()
            })
            .expect("reservation");
        let reservation: Value =
            serde_json::from_slice(&reservation.canonical_bytes).expect("reservation");
        NativeDeadlinePrelaunchRequest {
            reservation_custody: fixture.request.reservation_custody.clone(),
            outer_request_record_id: fixture.request.outer_request_record_id.clone(),
            invocation_decision_record_id: fixture.request.invocation_decision_record_id.clone(),
            custody_reservation_record_id: fixture.request.custody_reservation_record_id.clone(),
            generation_match: serde_json::from_value(
                launch["prelaunch_checks"]["generation_match"].clone(),
            )
            .expect("generation check"),
            capability: serde_json::from_value(launch["prelaunch_checks"]["capability"].clone())
                .expect("capability check"),
            launch_commit: serde_json::from_value(launch["launch_commit"].clone())
                .expect("launch commit"),
            bracket_policy: serde_json::from_value(reservation["calculation_rule"].clone())
                .expect("bracket policy"),
            maximum_bracket_width_ns: 100_000,
        }
    }

    #[test]
    fn native_deadline_is_runtime_owned_exact_and_supports_long_boottime() {
        let fixture = native_fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("native-deadline.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies.clone()).expect("runtime");
        let mut source = ScriptedDeadlineSource::accepted();
        let prepared = runtime
            .prepare_native_deadline_invocation_with_source(native_request(&fixture), &mut source)
            .expect("runtime-owned deadline");
        let provenance = prepared.native_deadline().expect("native provenance");
        assert!(provenance.boottime_observed_ns() > MAX_SAFE_INTEGER);
        assert_eq!(
            provenance.boottime_expiry_ns(),
            provenance.boottime_observed_ns() + 30_000_000_000
        );
        assert_eq!(
            provenance.boot_epoch(),
            &sha256_bytes(b"01234567-89ab-cdef-0123-456789abcdef\n")
        );
        assert_eq!(
            prepared.live_custody_state().expect("live custody"),
            GovernedCustodyState::LaunchClaimed
        );

        let snapshot = runtime.snapshot();
        let deadline_row = runtime
            .read_exact(&snapshot, provenance.evaluation().record_id.as_str())
            .expect("deadline row");
        let launch_row = runtime
            .read_exact(&snapshot, prepared.execution_launch().record_id.as_str())
            .expect("launch row");
        let deadline: Value =
            serde_json::from_slice(deadline_row.canonical_bytes.as_bytes()).expect("deadline JSON");
        let launch: Value =
            serde_json::from_slice(launch_row.canonical_bytes.as_bytes()).expect("launch JSON");
        assert_eq!(
            launch["prelaunch_checks"]["deadline"],
            Value::from(provenance.evaluation().clone())
        );
        assert_eq!(
            deadline["clock_qualification"],
            Value::from(provenance.clock_qualification().clone())
        );
        assert_eq!(deadline["derived"]["launched_at"], launch["launched_at"]);
        assert_eq!(
            deadline["derived"]["attempt_deadline"],
            launch["attempt_deadline"]
        );
        assert_eq!(
            deadline["derived"]["boottime_expiry_ns"],
            provenance.boottime_expiry_ns().to_string()
        );
        assert_eq!(
            deadline_row.checkpoint_id, launch_row.checkpoint_id,
            "deadline and launch commit atomically in the launch checkpoint"
        );
    }

    #[test]
    fn typed_deadline_submitted_through_generic_path_cannot_gain_native_provenance() {
        let emitted_fixture = native_fixture();
        let directory = tempdir().expect("directory");
        let emitted_database = directory.path().join("emitted.db");
        let mut emitted_runtime =
            initialize_test_runtime(&emitted_database, emitted_fixture.dependencies.clone())
                .expect("emitting runtime");
        let mut source = ScriptedDeadlineSource::accepted();
        let emitted = emitted_runtime
            .prepare_native_deadline_invocation_with_source(
                native_request(&emitted_fixture),
                &mut source,
            )
            .expect("native emission");
        let snapshot = emitted_runtime.snapshot();
        let deadline = emitted_runtime
            .read_exact(
                &snapshot,
                emitted
                    .native_deadline()
                    .expect("native deadline")
                    .evaluation()
                    .record_id
                    .as_str(),
            )
            .expect("deadline row");
        let launch = emitted_runtime
            .read_exact(&snapshot, emitted.execution_launch().record_id.as_str())
            .expect("launch row");
        drop(emitted);

        let supplied_fixture = native_fixture();
        let mut generic = supplied_fixture.request;
        generic.reservation_custody.records.push(AppendRecord {
            record_id: deadline.record_id,
            record_schema: deadline.record_schema,
            canonical_bytes: deadline.canonical_bytes.as_bytes().to_vec(),
            committed_at: deadline.committed_at,
        });
        generic.launch_custody.records = vec![AppendRecord {
            record_id: launch.record_id.clone(),
            record_schema: launch.record_schema,
            canonical_bytes: launch.canonical_bytes.as_bytes().to_vec(),
            committed_at: launch.committed_at,
        }];
        generic.execution_launch_record_id =
            Sha256Digest::parse(launch.record_id).expect("launch identity");

        let supplied_database = directory.path().join("supplied.db");
        let mut supplied_runtime =
            initialize_test_runtime(&supplied_database, supplied_fixture.dependencies)
                .expect("supplied runtime");
        let prepared = supplied_runtime
            .prepare_governed_invocation(generic)
            .expect("generic path may retain exact caller-supplied carrier");
        assert!(
            prepared.native_deadline().is_none(),
            "only runtime-owned construction may mint native provenance"
        );
    }

    #[test]
    fn native_source_failures_refuse_before_any_launch_or_custody_commit() {
        for (index, failure) in [
            ScriptedFailure::FirstBootRead,
            ScriptedFailure::FirstRealtime,
            ScriptedFailure::Boottime,
            ScriptedFailure::SecondRealtime,
            ScriptedFailure::SecondBootRead,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = native_fixture();
            let directory = tempdir().expect("directory");
            let database = directory.path().join(format!("source-failure-{index}.db"));
            let mut runtime =
                initialize_test_runtime(&database, fixture.dependencies.clone()).expect("runtime");
            let mut source = ScriptedDeadlineSource::accepted();
            source.failure = Some(failure);
            assert!(
                runtime
                    .prepare_native_deadline_invocation_with_source(
                        native_request(&fixture),
                        &mut source,
                    )
                    .is_err()
            );
            assert!(
                runtime.snapshot().checkpoint.is_none(),
                "source refusal cannot commit reservation or launch"
            );
            assert_eq!(runtime.contract_record_count(), 0);
            assert!(
                !database
                    .with_file_name(format!("source-failure-{index}.db.nq-custody-v1"))
                    .exists()
            );
        }

        let fixture = native_fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("boot-rebind.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies.clone()).expect("runtime");
        let mut source = ScriptedDeadlineSource::accepted();
        source.changed_boot_id = Some(b"fedcba98-7654-3210-fedc-ba9876543210\n".to_vec());
        assert!(matches!(
            runtime.prepare_native_deadline_invocation_with_source(
                native_request(&fixture),
                &mut source,
            ),
            Err(RuntimeError::NativeDeadlineBootIdentityChanged)
        ));
        assert!(runtime.snapshot().checkpoint.is_none());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One fail-closed custody-authority sequence is intentional.
    fn exact_prepared_owns_terminal_authority_but_reopened_launch_does_not() {
        let directory = tempdir().expect("directory");

        let first = fixture();
        let first_database = directory.path().join("owned-terminal.db");
        let mut first_runtime =
            initialize_test_runtime(&first_database, first.dependencies).expect("runtime");
        let mut prepared = first_runtime
            .prepare_governed_invocation(first.request)
            .expect("prepared");
        let launch_id = prepared.execution_launch().record_id.clone();
        let mut session_store = Store::open(&first_database).expect("session store");
        let mut session = session_store
            .begin_writer_session()
            .expect("writer session");
        let substituted_launch = sha256_bytes(b"another exact launch occurrence");
        let error = prepared
            .terminalize_immediate_launch(
                &mut session,
                GovernedProtectedTerminalInput {
                    execution_launch_record_id: substituted_launch,
                    terminal_class: GovernedProtectedTerminalClass::PreEffectRefusal,
                    reason: GovernedProtectedTerminalReason {
                        code: "hostile.launch_substitution".to_owned(),
                        detail: "a prepared occurrence cannot terminalize another launch"
                            .to_owned(),
                    },
                    launch_attempt_deadline: "2026-07-28T22:02:32Z".to_owned(),
                    terminalized_at: "2026-07-28T22:02:03Z".to_owned(),
                    deadline_compliance:
                        GovernedProtectedTerminalDeadlineCompliance::WithinDeadline,
                },
            )
            .expect_err("prepared occurrence is exact-launch bound");
        assert!(matches!(
            error,
            RuntimeError::PreparedCustodyLaunchSubstitution
        ));
        assert_eq!(
            prepared
                .live_custody_state()
                .expect("substitution leaves launch live"),
            GovernedCustodyState::LaunchClaimed
        );
        let terminal_input = GovernedProtectedTerminalInput {
            execution_launch_record_id: launch_id,
            terminal_class: GovernedProtectedTerminalClass::PreEffectRefusal,
            reason: GovernedProtectedTerminalReason {
                code: "runtime.native_correspondence_refused".to_owned(),
                detail: "exact prepared occurrence refused before provider effect".to_owned(),
            },
            launch_attempt_deadline: "2026-07-28T22:02:32Z".to_owned(),
            terminalized_at: "2026-07-28T22:02:03Z".to_owned(),
            deadline_compliance: GovernedProtectedTerminalDeadlineCompliance::WithinDeadline,
        };
        let terminalized = prepared
            .terminalize_immediate_launch(&mut session, terminal_input)
            .expect("owned immediate terminal");
        assert_eq!(
            terminalized.disposition,
            GovernedProtectedTerminalDisposition::Terminalized
        );
        assert_eq!(
            prepared.live_custody_state().expect("terminal state"),
            GovernedCustodyState::FailedIndeterminate
        );

        let second = fixture();
        let second_database = directory.path().join("reopened-terminal.db");
        let mut second_runtime =
            initialize_test_runtime(&second_database, second.dependencies).expect("runtime");
        let second_prepared = second_runtime
            .prepare_governed_invocation(second.request)
            .expect("prepared");
        let reservation = second_prepared.custody_reservation_spec().clone();
        let launch_id = second_prepared.execution_launch().record_id.clone();
        drop(second_prepared);
        drop(second_runtime);

        let mut store = Store::open(&second_database).expect("store");
        let mut reopened = store
            .open_governed_custody(reservation)
            .expect("reopened nonterminal launch");
        let error = store
            .begin_writer_session()
            .expect("writer session")
            .terminalize_custody_immediate_launch(
                &mut reopened,
                GovernedProtectedTerminalInput {
                    execution_launch_record_id: launch_id,
                    terminal_class: GovernedProtectedTerminalClass::PreEffectRefusal,
                    reason: GovernedProtectedTerminalReason {
                        code: "hostile.reopened_terminal".to_owned(),
                        detail: "reopened custody must not mint no-further-execution authority"
                            .to_owned(),
                    },
                    launch_attempt_deadline: "2026-07-28T22:02:32Z".to_owned(),
                    terminalized_at: "2026-07-28T22:02:03Z".to_owned(),
                    deadline_compliance:
                        GovernedProtectedTerminalDeadlineCompliance::WithinDeadline,
                },
            )
            .expect_err("reopened launch has no immediate terminal authority");
        assert!(
            error
                .to_string()
                .contains("reopened in-flight launch has no exact no-further-execution fence")
        );
        assert_eq!(
            reopened.state().expect("still nonterminal"),
            GovernedCustodyState::LaunchClaimed
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn prepared_custody_forwarders_preserve_exact_launch_and_pre_final_transition_order() {
        let fixture = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("ordered-forwarders.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let mut prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared");
        let exact_launch = prepared.execution_launch().record_id.clone();
        let reservation = prepared.custody_reservation_spec().clone();
        let mut session_store = Store::open(&database).expect("session store");
        let mut session = session_store
            .begin_writer_session()
            .expect("writer session");

        let wrong_launch = sha256_bytes(b"foreign launch occurrence");
        let error = prepared
            .seal_acquisition(
                &mut session,
                GovernedAcquisitionCustodyInput {
                    execution_launch_record_id: wrong_launch,
                    provider_intake_record_id: sha256_bytes(b"foreign provider intake"),
                    exact_provider_intake_bytes: b"{\"schema\":\"nq.provider_intake.v1\"}".to_vec(),
                    exact_raw_provider_bytes: b"foreign raw bytes".to_vec(),
                },
            )
            .expect_err("another launch cannot use this prepared custody");
        assert!(matches!(
            error,
            RuntimeError::PreparedCustodyLaunchSubstitution
        ));

        let claim = GovernedDerivationCustodyClaim {
            derivation_id: sha256_bytes(b"ordered derivation"),
            dependency_generation_id: reservation.dependency_generation_id.clone(),
            dependency_generation_custody_digest: reservation
                .dependency_generation_custody_digest
                .clone(),
            trust_anchor_id: reservation.trust_anchor_id.clone(),
            evaluation_id: Some("evaluation-ordered".to_owned()),
            profile_semantic_id: sha256_bytes(b"ordered profile semantics"),
            evaluator_identity_digest: sha256_bytes(b"ordered evaluator identity"),
            evaluator_artifact_digest: sha256_bytes(b"ordered evaluator artifact"),
            derived_at: "2026-07-28T22:02:04Z".to_owned(),
            clock_identity: sha256_bytes(b"ordered clock"),
            clock_qualification_digest: semantic_digest(&json!({
                "state": "unqualified",
                "code": "ordered_test_unqualified",
                "detail": "the ordered custody test establishes no finite UTC-error bound",
            }))
            .expect("clock qualification identity"),
        };
        assert!(
            prepared
                .claim_derivation(&mut session, claim.clone())
                .is_err(),
            "derivation cannot skip acquisition custody"
        );
        assert_eq!(
            prepared.live_custody_state().expect("launch remains live"),
            GovernedCustodyState::LaunchClaimed
        );

        let acquisition = prepared
            .seal_acquisition(
                &mut session,
                GovernedAcquisitionCustodyInput {
                    execution_launch_record_id: exact_launch.clone(),
                    provider_intake_record_id: sha256_bytes(b"ordered provider intake"),
                    exact_provider_intake_bytes: b"{\"schema\":\"nq.provider_intake.v1\"}".to_vec(),
                    exact_raw_provider_bytes: b"ordered raw bytes".to_vec(),
                },
            )
            .expect("exact launch acquisition seals");
        assert_eq!(acquisition.execution_launch_record_id, exact_launch);
        assert_eq!(
            prepared.live_custody_state().expect("acquisition state"),
            GovernedCustodyState::AcquisitionSealed
        );
        assert!(
            prepared
                .seal_acquisition(
                    &mut session,
                    GovernedAcquisitionCustodyInput {
                        execution_launch_record_id: exact_launch,
                        provider_intake_record_id: sha256_bytes(b"second provider intake"),
                        exact_provider_intake_bytes: b"{\"schema\":\"nq.provider_intake.v1\"}"
                            .to_vec(),
                        exact_raw_provider_bytes: b"second raw bytes".to_vec(),
                    }
                )
                .is_err(),
            "acquisition seals exactly once"
        );
        assert_eq!(
            prepared
                .live_custody_state()
                .expect("failed skips preserve state"),
            GovernedCustodyState::AcquisitionSealed
        );

        prepared
            .claim_derivation(&mut session, claim.clone())
            .expect("derivation follows acquisition");
        assert_eq!(
            prepared.live_custody_state().expect("derivation state"),
            GovernedCustodyState::DerivationClaimed
        );
        assert!(
            prepared.claim_derivation(&mut session, claim).is_err(),
            "derivation claim is one-use"
        );
        assert_eq!(
            prepared
                .live_custody_state()
                .expect("derivation remains pending Store-owned publication"),
            GovernedCustodyState::DerivationClaimed
        );
    }

    #[test]
    fn governed_prelaunch_is_two_phase_physically_reserved_and_one_use() {
        let fixture = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        let reopened_dependencies = fixture.dependencies.clone();
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let request = fixture.request.clone();
        let request_reservation_id = request.custody_reservation_record_id.clone();
        let prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        assert_eq!(prepared.reservation_checkpoint().checkpoint_sequence, 1);
        assert_eq!(prepared.launch_checkpoint().checkpoint_sequence, 2);
        assert!(
            prepared.reservation_checkpoint().last_record_sequence
                < prepared.launch_checkpoint().first_record_sequence
        );
        assert_eq!(
            prepared.live_custody_state().expect("live custody state"),
            GovernedCustodyState::LaunchClaimed
        );
        assert_eq!(
            prepared
                .dependencies()
                .custody()
                .reopen(&fixture.dependency_anchor_id)
                .expect("historical dependency reopen")
                .generation_id(),
            prepared.dependencies().generation_id()
        );
        assert_eq!(
            prepared.dependency_custody_bytes(),
            prepared
                .dependencies()
                .custody()
                .canonical_closure_bytes()
                .expect("closure bytes")
        );
        let reservation_spec = prepared.custody_reservation_spec().clone();
        let dependency_custody_bytes = prepared.dependency_custody_bytes().to_vec();
        drop(prepared);
        let custody_store = Store::open(&database).expect("custody store");
        let custody = custody_store
            .open_governed_custody(reservation_spec)
            .expect("reopen custody after exact prepared ownership ends");
        assert_eq!(
            custody
                .dependency_closure_bytes()
                .expect("physical dependency closure"),
            dependency_custody_bytes
        );
        drop(custody);
        assert!(matches!(
            runtime.prepare_governed_invocation(request),
            Err(RuntimeError::PrelaunchReplayCannotRerun)
        ));
        drop(runtime);

        let reopened = open_test_runtime(&database, reopened_dependencies)
            .expect("restart classifies physical frontier");
        let [GovernedCustodyInventoryEntry::Verified(frontier)] = reopened.custody_frontiers()
        else {
            panic!("one verified startup frontier");
        };
        assert_eq!(frontier.state, GovernedCustodyState::LaunchClaimed);
        assert_eq!(
            frontier.reservation_ledger_binding,
            GovernedCustodyReservationLedgerBinding::Exact
        );
        assert_eq!(
            frontier.recovery_class,
            GovernedCustodyRecoveryClass::LaunchedWithoutAcquisition
        );
        assert_eq!(frontier.reservation_record_id, request_reservation_id);
        assert_eq!(
            reopened
                .protected_failure(&frontier.reservation_record_id)
                .expect("protected-failure read"),
            GovernedProtectedFailureAccess::NotPresent {
                arena_state: GovernedCustodyState::LaunchClaimed,
            }
        );
    }

    #[test]
    fn governed_prelaunch_refuses_graph_and_capacity_substitution() {
        let first = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("graph.db");
        let mut runtime = initialize_test_runtime(&database, first.dependencies).expect("runtime");
        let mut request = first.request;
        let launch = &mut request.launch_custody.records[0];
        let mut value: Value =
            serde_json::from_slice(&launch.canonical_bytes).expect("launch bytes");
        value["status"] = json!("not_launched");
        launch.canonical_bytes = canonical_json_bytes(&value).expect("hostile launch");
        assert!(runtime.prepare_governed_invocation(request).is_err());

        let second = fixture();
        let database = directory.path().join("capacity.db");
        let mut runtime = initialize_test_runtime(&database, second.dependencies).expect("runtime");
        let mut request = second.request;
        let reservation = request
            .reservation_custody
            .records
            .iter_mut()
            .find(|record| record.record_id == request.custody_reservation_record_id.as_str())
            .expect("reservation");
        let mut value: Value =
            serde_json::from_slice(&reservation.canonical_bytes).expect("reservation bytes");
        value["reserved_bytes"] = json!(1);
        reservation.canonical_bytes = canonical_json_bytes(&value).expect("hostile reservation");
        assert!(runtime.prepare_governed_invocation(request).is_err());
        assert!(
            !database
                .with_file_name("capacity.db.nq-custody-v1")
                .exists()
        );
    }

    #[test]
    fn prepared_retains_diagnostic_capacity_separately_from_final_partition() {
        let directory = tempdir().expect("directory");
        let baseline = fixture();
        let mut baseline_runtime = initialize_test_runtime(
            directory.path().join("diagnostic-capacity-baseline.db"),
            baseline.dependencies,
        )
        .expect("baseline runtime");
        let baseline = baseline_runtime
            .prepare_governed_invocation(baseline.request)
            .expect("baseline prepared invocation");

        let one_under = diagnostic_capacity_one_under_fixture();
        let mut one_under_runtime = initialize_test_runtime(
            directory.path().join("diagnostic-capacity-one-under.db"),
            one_under.dependencies,
        )
        .expect("one-under runtime");
        let one_under = one_under_runtime
            .prepare_governed_invocation(one_under.request)
            .expect("one-under prepared invocation");

        assert_eq!(
            one_under.diagnostic_artifact_capacity_bytes() + 1,
            baseline.diagnostic_artifact_capacity_bytes()
        );
        assert_eq!(
            one_under
                .custody_reservation_spec()
                .diagnostic_artifact_capacity_bytes,
            one_under.diagnostic_artifact_capacity_bytes()
        );
        assert_eq!(
            one_under.custody_reservation_spec().final_capacity_bytes,
            baseline.custody_reservation_spec().final_capacity_bytes,
            "aggregate final capacity deliberately remains unchanged"
        );
    }

    #[test]
    fn prepared_final_batch_is_source_complete_frozen_and_pure() {
        let fixture = fixture();
        let expected_reservation_records =
            exact_append_membership(&fixture.request.reservation_custody.records)
                .expect("reservation membership");
        let expected_launch_records =
            exact_append_membership(&fixture.request.launch_custody.records)
                .expect("launch membership");
        let resolver = fixture.resolver.clone();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("qualified-final-batch.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        let frozen_frontier = runtime.snapshot();

        assert_eq!(
            prepared.reservation_checkpoint_records(),
            expected_reservation_records
        );
        assert_eq!(
            prepared.launch_checkpoint_records(),
            expected_launch_records
        );

        let provider_intake = final_provider_intake("qualified");
        let provider_reference = exact_append_membership(std::slice::from_ref(&provider_intake))
            .expect("provider reference")
            .remove(0);
        let binding = final_execution_binding(&prepared, &resolver, &provider_reference);
        let binding_reference = binding.exact_reference();
        let qualified = prepared
            .qualify_final_batch(provider_intake, binding)
            .expect("source-complete final batch");

        assert_eq!(qualified.provider_intake(), &provider_reference);
        assert_eq!(qualified.execution_binding(), &binding_reference);
        assert_eq!(
            qualified.runtime_records(),
            &[provider_reference, binding_reference]
        );
        assert_eq!(qualified.batch().records.len(), 2);
        assert_eq!(
            qualified
                .batch()
                .expected_predecessor_checkpoint_id
                .as_deref(),
            Some(prepared.launch_checkpoint().checkpoint_id.as_str())
        );
        assert_eq!(
            qualified.batch().expected_predecessor_ledger_root.as_ref(),
            Some(&prepared.launch_checkpoint().checkpoint_ledger_root)
        );
        assert_eq!(
            &qualified.batch().dependency.dependency_generation_id,
            prepared.dependencies().generation_id()
        );
        assert_eq!(
            qualified.batch_digest(),
            &runtime_record_batch_digest(qualified.batch()).expect("batch digest")
        );
        assert_eq!(
            runtime.snapshot(),
            frozen_frontier,
            "qualification owns no append authority"
        );
    }

    #[test]
    fn final_batch_refuses_descriptor_source_substitution() {
        let fixture = fixture();
        let resolver = fixture.resolver.clone();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("source-substitution.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        let provider_intake = final_provider_intake("source-substitution");
        let provider_reference = exact_append_membership(std::slice::from_ref(&provider_intake))
            .expect("provider reference")
            .remove(0);
        let binding = final_execution_binding(&prepared, &resolver, &provider_reference);
        let mut hostile = binding.record().as_value().clone();
        hostile["resolved_references"]["node"]["descriptor"] =
            hostile["resolved_references"]["subject"]["descriptor"].clone();
        seal_semantic_identity(&mut hostile, "binding_id").expect("hostile binding identity");
        let hostile =
            ValidatedRuntimeRecord::validate_value(hostile).expect("structural hostile binding");

        let error = prepared
            .qualify_final_batch(provider_intake, hostile)
            .expect_err("descriptor substitution must fail source-complete validation");
        assert!(matches!(
            error,
            RuntimeError::Contract(
                nq_host_role_contract::ContractError::BindingDescriptorDigestMismatch(_)
                    | nq_host_role_contract::ContractError::BindingDescriptorPreimageMismatch(_)
            )
        ));
    }

    #[test]
    fn final_batch_refuses_missing_historical_source_bytes() {
        let fixture = fixture();
        let resolver = fixture.resolver.clone();
        let runtime_identities = fixture.runtime_identities.clone();
        let external_inputs = fixture.external_inputs.clone();
        let operation_authorizations = fixture.operation_authorizations.clone();
        let authentication = fixture.authentication.clone();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("missing-historical-source.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let mut prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        let provider_intake = final_provider_intake("missing-historical-source");
        let provider_reference = exact_append_membership(std::slice::from_ref(&provider_intake))
            .expect("provider reference")
            .remove(0);
        let binding = final_execution_binding(&prepared, &resolver, &provider_reference);
        let missing_descriptor: RecordRef = serde_json::from_value(
            binding.record().as_value()["resolved_references"]["node"]["descriptor"].clone(),
        )
        .expect("node descriptor");
        let dependencies_without_source = authenticated_runtime_fixture(
            41,
            runtime_identities,
            external_inputs
                .into_iter()
                .filter(|(reference, _)| reference != &missing_descriptor)
                .collect(),
            operation_authorizations,
            authentication,
        );
        prepared.historical_dependencies = vec![dependencies_without_source];

        let error = prepared
            .qualify_final_batch(provider_intake, binding)
            .expect_err("missing exact historical bytes must refuse");
        assert!(matches!(
            error,
            RuntimeError::HistoricalDependencyMissing(record_id)
                if record_id == missing_descriptor.record_id.to_string()
        ));
    }

    #[test]
    fn final_batch_ignores_unselected_exact_dependency_sources() {
        let fixture = fixture();
        assert!(
            fixture.external_inputs.len() > 9,
            "fixture must carry exact dependency sources outside the selected binding corpus"
        );
        let resolver = fixture.resolver.clone();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("unselected-sources.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        let provider_intake = final_provider_intake("unselected-sources");
        let provider_reference = exact_append_membership(std::slice::from_ref(&provider_intake))
            .expect("provider reference")
            .remove(0);
        let binding = final_execution_binding(&prepared, &resolver, &provider_reference);

        prepared
            .qualify_final_batch(provider_intake, binding)
            .expect("unselected exact dependencies are not admitted as binding sources");
    }

    #[test]
    fn final_batch_source_qualifies_prior_historical_bindings() {
        let fixture = fixture();
        let resolver = fixture.resolver.clone();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("historical-binding-sources.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let mut prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");

        let prior_provider = final_provider_intake("prior-historical");
        let prior_provider_reference =
            exact_append_membership(std::slice::from_ref(&prior_provider))
                .expect("prior provider reference")
                .remove(0);
        let prior_binding =
            final_execution_binding(&prepared, &resolver, &prior_provider_reference);
        prepared
            .prelaunch_records
            .insert(prior_binding)
            .expect("prior historical binding");
        prepared
            .historical_validation_context
            .external_records
            .insert(prior_provider_reference);

        let current_provider = final_provider_intake("current-historical");
        let current_provider_reference =
            exact_append_membership(std::slice::from_ref(&current_provider))
                .expect("current provider reference")
                .remove(0);
        let current_binding =
            final_execution_binding(&prepared, &resolver, &current_provider_reference);

        prepared
            .qualify_final_batch(current_provider, current_binding)
            .expect("complete graph source-qualifies prior and current bindings");
    }

    #[test]
    fn topology_changed_bindings_use_separate_historical_source_corpora() {
        let fixture = fixture();
        let historical_dependencies = fixture.dependencies.clone();
        let historical_resolver = fixture.resolver.clone();
        let historical_resolver_descriptor = fixture
            .external_inputs
            .iter()
            .find(|(reference, _)| {
                reference.bytes_digest == historical_resolver.descriptor_digest
                    && reference.schema.as_str() == "nq.production_identity_descriptor.v1"
            })
            .expect("historical resolver descriptor")
            .0
            .clone();
        let (current_resolver, current_resolver_source) =
            production_identity_source(IdentityKind::Resolver, "nq-production-resolver", "2");
        let mut current_identities = fixture
            .runtime_identities
            .clone()
            .into_iter()
            .filter(|identity| identity != &historical_resolver)
            .collect::<Vec<_>>();
        current_identities.push(current_resolver.clone());
        let mut current_external = fixture
            .external_inputs
            .clone()
            .into_iter()
            .filter(|(reference, _)| reference != &historical_resolver_descriptor)
            .collect::<Vec<_>>();
        current_external.push(current_resolver_source);
        let current_dependencies = authenticated_runtime_fixture(
            41,
            current_identities,
            current_external,
            fixture.operation_authorizations.clone(),
            fixture.authentication.clone(),
        );
        assert!(
            !current_dependencies
                .external_dependency_snapshot()
                .dependencies
                .iter()
                .any(|dependency| dependency.reference == historical_resolver_descriptor)
        );

        let directory = tempdir().expect("directory");
        let database = directory.path().join("topology-changed-source-corpora.db");
        let mut runtime =
            initialize_test_runtime(&database, current_dependencies).expect("current runtime");
        let mut prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("current prepared invocation");
        prepared
            .historical_dependencies
            .push(historical_dependencies);
        prepared.historical_validation_context = combined_historical_validation_context(
            prepared.historical_dependencies.iter(),
            std::iter::empty(),
        )
        .expect("two-generation historical context");

        let historical_provider = final_provider_intake("historical-topology");
        let historical_provider_reference =
            exact_append_membership(std::slice::from_ref(&historical_provider))
                .expect("historical provider reference")
                .remove(0);
        let historical_binding = final_execution_binding(
            &prepared,
            &historical_resolver,
            &historical_provider_reference,
        );
        prepared
            .prelaunch_records
            .insert(historical_binding)
            .expect("historical topology binding");
        prepared
            .historical_validation_context
            .external_records
            .insert(historical_provider_reference);

        let current_provider = final_provider_intake("current-topology");
        let current_provider_reference =
            exact_append_membership(std::slice::from_ref(&current_provider))
                .expect("current provider reference")
                .remove(0);
        let current_binding =
            final_execution_binding(&prepared, &current_resolver, &current_provider_reference);

        prepared
            .qualify_final_batch(current_provider, current_binding)
            .expect("each topology generation receives its own closed source corpus");
    }

    #[test]
    fn prepared_final_batch_cannot_be_reinterpreted_by_current_generation() {
        let fixture = fixture();
        let resolver = fixture.resolver.clone();
        let g1_generation = fixture.dependencies.generation_id().clone();
        let mut g2_identities = fixture.runtime_identities.clone();
        g2_identities.push(extra_identity("capability/final-batch-g2-only"));
        let g2 = authenticated_runtime_fixture(
            41,
            g2_identities,
            fixture.external_inputs.clone(),
            fixture.operation_authorizations.clone(),
            fixture.authentication.clone(),
        );
        assert_ne!(g2.generation_id(), &g1_generation);

        let directory = tempdir().expect("directory");
        let database = directory.path().join("frozen-final-generation.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("g1 runtime");
        let prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("g1 prepared invocation");
        let g1_launch = prepared.launch_checkpoint().clone();
        drop(runtime);

        let mut runtime = open_test_runtime(&database, g2.clone()).expect("g2 runtime");
        let g2_frontier = runtime
            .append_custody_only(&opaque_append(
                "final-batch-g2-current",
                "2026-07-29T21:05:00Z",
            ))
            .expect("g2 frontier")
            .checkpoint;
        drop(runtime);

        let provider_intake = final_provider_intake("frozen-g1");
        let provider_reference = exact_append_membership(std::slice::from_ref(&provider_intake))
            .expect("provider reference")
            .remove(0);
        let binding = final_execution_binding(&prepared, &resolver, &provider_reference);
        let qualified = prepared
            .qualify_final_batch(provider_intake, binding)
            .expect("prepared G1 semantics remain exact");

        assert_eq!(
            qualified.batch().dependency.dependency_generation_id,
            g1_generation
        );
        assert_eq!(
            qualified
                .batch()
                .expected_predecessor_checkpoint_id
                .as_deref(),
            Some(g1_launch.checkpoint_id.as_str())
        );
        assert_ne!(
            qualified
                .batch()
                .expected_predecessor_checkpoint_id
                .as_deref(),
            Some(g2_frontier.checkpoint_id.as_str())
        );
        assert_ne!(
            qualified.batch().dependency.dependency_generation_id,
            *g2.generation_id()
        );
    }

    #[test]
    fn startup_inventory_keeps_an_unreadable_arena_entry_visible() {
        let fixture = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("inventory.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies.clone()).expect("runtime");
        runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        drop(runtime);

        let root = database.with_file_name("inventory.db.nq-custody-v1");
        std::fs::write(root.join("unexpected-entry"), b"not an arena")
            .expect("hostile custody-root entry");
        let reopened = open_test_runtime(&database, fixture.dependencies).expect("runtime reopens");
        assert_eq!(reopened.custody_frontiers().len(), 2);
        assert!(reopened.custody_frontiers().iter().any(|entry| {
            matches!(
                entry,
                GovernedCustodyInventoryEntry::Unreadable { relative_path, reason }
                    if relative_path == std::path::Path::new("unexpected-entry")
                        && reason.contains("custody arena")
            )
        }));
    }

    #[test]
    fn startup_inventory_reports_a_committed_reservation_with_missing_arena_bytes() {
        let fixture = fixture();
        let dependencies = fixture.dependencies.clone();
        let reservation_id = fixture.request.custody_reservation_record_id.clone();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("missing-arena.db");
        let mut runtime =
            initialize_test_runtime(&database, fixture.dependencies).expect("runtime");
        let prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        let reservation_manifest_digest = prepared
            .custody_reservation_spec()
            .reservation_manifest_digest
            .clone();
        drop(prepared);
        drop(runtime);
        let inventory_runtime =
            open_test_runtime(&database, dependencies.clone()).expect("inventory runtime");
        let [GovernedCustodyInventoryEntry::Verified(frontier)] =
            inventory_runtime.custody_frontiers()
        else {
            panic!("one verified frontier");
        };
        let arena_path = database
            .with_file_name("missing-arena.db.nq-custody-v1")
            .join(&frontier.relative_path);
        drop(inventory_runtime);
        std::fs::remove_file(arena_path).expect("remove disposable arena specimen");

        let reopened =
            open_test_runtime(&database, dependencies).expect("ledger remains inspectable");
        assert_eq!(
            reopened.custody_frontiers(),
            &[
                GovernedCustodyInventoryEntry::MissingForCommittedReservation {
                    reservation_record_id: reservation_id.clone(),
                    reservation_manifest_digest,
                }
            ]
        );
        assert_eq!(
            reopened
                .protected_failure(&reservation_id)
                .expect("missing-arena protected-failure read"),
            GovernedProtectedFailureAccess::ArenaMissing
        );
    }

    #[test]
    fn g1_checkpoint_reopens_when_g2_omits_g1_only_identity_and_external_dependency() {
        let first = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("historical-generations.db");
        let g1_generation = first.dependencies.generation_id().clone();
        let g1_only_identity = first.runtime_identities[0].clone();
        let g1_external = first.external_inputs[0].0.clone();
        let mut runtime =
            initialize_test_runtime(&database, first.dependencies).expect("g1 runtime");
        let prepared = runtime
            .prepare_governed_invocation(first.request)
            .expect("g1 governed invocation");
        let g1_launch_checkpoint = prepared.launch_checkpoint().clone();
        let g1_record_count = runtime.contract_record_count();
        drop(prepared);
        drop(runtime);

        let g2_identities = first
            .runtime_identities
            .into_iter()
            .filter(|identity| identity != &g1_only_identity)
            .collect::<Vec<_>>();
        let g2 = authenticated_runtime_fixture(41, g2_identities, vec![], vec![], vec![]);
        assert_eq!(
            g2.custody().trust_anchor_id().expect("g2 anchor"),
            first.dependency_anchor_id
        );
        assert_ne!(g2.generation_id(), &g1_generation);
        assert!(!g2.catalog_snapshot().identities.contains(&g1_only_identity));
        assert!(
            !g2.external_dependency_snapshot()
                .dependencies
                .iter()
                .any(|dependency| dependency.reference == g1_external)
        );

        let mut runtime =
            open_test_runtime(&database, g2.clone()).expect("g1 reopened under g2 current");
        assert_eq!(runtime.contract_record_count(), g1_record_count);
        let g2_append = opaque_append("g2-opaque", "2026-07-29T21:01:00Z");
        let g2_checkpoint = runtime
            .append_custody_only(&g2_append)
            .expect("g2 append without reinterpreting g1")
            .checkpoint;
        drop(runtime);

        let runtime = open_test_runtime(&database, g2.clone()).expect("restart after g2");
        assert_eq!(runtime.contract_record_count(), g1_record_count);
        assert_eq!(runtime.provider_intake_count(), 1);
        let store = Store::open(&database).expect("store");
        let g1_access = store
            .runtime_checkpoint_dependency(&g1_launch_checkpoint.checkpoint_id)
            .expect("g1 dependency access")
            .expect("g1 dependency binding");
        let g2_access = store
            .runtime_checkpoint_dependency(&g2_checkpoint.checkpoint_id)
            .expect("g2 dependency access")
            .expect("g2 dependency binding");
        assert!(matches!(
            g1_access.binding,
            RuntimeCheckpointDependencyBinding::Authenticated {
                dependency_generation_id,
                ..
            } if dependency_generation_id == g1_generation
        ));
        assert!(matches!(
            g2_access.binding,
            RuntimeCheckpointDependencyBinding::Authenticated {
                dependency_generation_id,
                ..
            } if dependency_generation_id == *g2.generation_id()
        ));
    }

    #[test]
    fn same_anchor_superset_generation_is_distinct_and_preserves_g1_history() {
        let first = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("same-anchor-superset.db");
        let g1_generation = first.dependencies.generation_id().clone();
        let mut runtime =
            initialize_test_runtime(&database, first.dependencies).expect("g1 runtime");
        runtime
            .prepare_governed_invocation(first.request)
            .expect("g1 governed invocation");
        drop(runtime);

        let mut g2_identities = first.runtime_identities;
        let added = extra_identity("capability/g2-only");
        g2_identities.push(added.clone());
        let g2 = authenticated_runtime_fixture(
            41,
            g2_identities,
            first.external_inputs,
            first.operation_authorizations,
            first.authentication,
        );
        assert_eq!(
            g2.custody().trust_anchor_id().expect("g2 anchor"),
            first.dependency_anchor_id
        );
        assert_ne!(g2.generation_id(), &g1_generation);
        assert!(g2.catalog_snapshot().identities.contains(&added));

        let mut runtime = open_test_runtime(&database, g2.clone()).expect("g2 current");
        runtime
            .append_custody_only(&opaque_append(
                "same-anchor-superset",
                "2026-07-29T21:02:00Z",
            ))
            .expect("g2 checkpoint");
        drop(runtime);
        open_test_runtime(&database, g2).expect("both generations reopen after restart");
    }

    #[test]
    fn later_generation_cannot_select_a_new_dependency_trust_root() {
        let first = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("bootstrap-root-substitution.db");
        let expected_anchor = first.dependency_anchor_id.clone();
        let mut runtime =
            initialize_test_runtime(&database, first.dependencies).expect("g1 runtime");
        let prepared = runtime
            .prepare_governed_invocation(first.request)
            .expect("g1 governed invocation");
        let g1_frontier = prepared.launch_checkpoint().clone();
        drop(prepared);
        drop(runtime);

        let g2 = authenticated_runtime_fixture(
            42,
            first.runtime_identities,
            first.external_inputs,
            first.operation_authorizations,
            first.authentication,
        );
        let observed_anchor = g2.custody().trust_anchor_id().expect("g2 anchor");
        assert_ne!(observed_anchor, expected_anchor);
        let Err(error) = open_test_runtime(&database, g2) else {
            panic!("current dependency generation selected a new bootstrap root");
        };
        assert!(matches!(
            error,
            RuntimeError::DependencyTrustAnchorSubstitution {
                expected,
                observed,
            } if expected == expected_anchor && observed == observed_anchor
        ));
        let store = Store::open(&database).expect("store remains readable");
        assert_eq!(
            store
                .runtime_dependency_trust_root()
                .expect("bootstrap trust root"),
            Some(expected_anchor)
        );
        assert_eq!(
            store
                .runtime_ledger_checkpoint()
                .expect("frontier after rejected root"),
            Some(g1_frontier)
        );
    }

    #[test]
    fn conflicting_g2_identity_cannot_reinterpret_g1_or_commit_a_new_checkpoint() {
        let first = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("identity-conflict.db");
        let mut runtime =
            initialize_test_runtime(&database, first.dependencies).expect("g1 runtime");
        let prepared = runtime
            .prepare_governed_invocation(first.request)
            .expect("g1 governed invocation");
        let g1_frontier = prepared.launch_checkpoint().clone();
        drop(prepared);
        drop(runtime);

        let target = first.runtime_identities[0].clone();
        let mut conflicting = target.clone();
        conflicting.descriptor_digest = sha256_bytes(b"hostile conflicting descriptor");
        let g2_identities = first
            .runtime_identities
            .into_iter()
            .map(|identity| {
                if identity == target {
                    conflicting.clone()
                } else {
                    identity
                }
            })
            .collect();
        let g2 = authenticated_runtime_fixture(41, g2_identities, vec![], vec![], vec![]);
        let mut runtime = open_test_runtime(&database, g2).expect("g1 exact reopen");
        let error = runtime
            .append_custody_only(&opaque_append("conflicting-g2", "2026-07-29T21:03:00Z"))
            .expect_err("historical/current identity substitution must fail closed");
        assert!(matches!(error, RuntimeError::Contract(_)));
        assert_eq!(
            runtime.snapshot().checkpoint.as_ref(),
            Some(&g1_frontier),
            "rejected G2 reinterpretation cannot advance the ledger"
        );
        assert_eq!(
            Store::open(&database)
                .expect("store")
                .runtime_ledger_checkpoint()
                .expect("frontier")
                .as_ref(),
            Some(&g1_frontier)
        );
    }

    fn exact_runtime_refs(values: &BTreeMap<String, Value>) -> BTreeMap<String, RecordRef> {
        values
            .iter()
            .map(|(name, value)| {
                let record = ValidatedRuntimeRecord::validate_value(value.clone())
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
                (name.clone(), record.exact_reference())
            })
            .collect()
    }

    fn increase_fixture_dependency_capacity(values: &mut BTreeMap<String, Value>) {
        let reservation = values
            .get_mut("custody_reservation")
            .expect("custody reservation");
        let previous = reservation["component_bounds"]["dependency_closure_bytes"]
            .as_u64()
            .expect("dependency capacity");
        let replacement = 262_144_u64;
        let increase = replacement
            .checked_sub(previous)
            .expect("larger dependency capacity");
        reservation["component_bounds"]["dependency_closure_bytes"] = json!(replacement);
        for field in ["reserved_bytes", "total_required_bytes"] {
            reservation[field] = json!(
                reservation[field]
                    .as_u64()
                    .expect("reservation total")
                    .checked_add(increase)
                    .expect("reservation total capacity")
            );
        }
    }

    fn reduce_fixture_diagnostic_capacity_one_byte(values: &mut BTreeMap<String, Value>) {
        let reservation = values
            .get_mut("custody_reservation")
            .expect("custody reservation");
        let capacity = reservation["component_bounds"]["diagnostic_artifact_bytes"]
            .as_u64()
            .expect("diagnostic artifact capacity");
        reservation["component_bounds"]["diagnostic_artifact_bytes"] = json!(
            capacity
                .checked_sub(1)
                .expect("positive diagnostic artifact capacity")
        );
        reservation["total_required_bytes"] = json!(
            reservation["total_required_bytes"]
                .as_u64()
                .expect("reservation total")
                .checked_sub(1)
                .expect("positive reservation total")
        );
    }

    fn install_production_identity_descriptors(
        values: &mut BTreeMap<String, Value>,
    ) -> Vec<(RecordRef, Vec<u8>)> {
        let mut sources = BTreeMap::<(String, String, String), (RecordRef, Vec<u8>)>::new();
        for value in values.values_mut() {
            rewrite_identity_descriptors(value, &mut sources);
        }
        sources.into_values().collect()
    }

    fn rewrite_identity_descriptors(
        value: &mut Value,
        sources: &mut BTreeMap<(String, String, String), (RecordRef, Vec<u8>)>,
    ) {
        match value {
            Value::Object(object)
                if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) =>
            {
                let key = (
                    object["kind"].as_str().expect("identity kind").to_owned(),
                    object["id"].as_str().expect("identity id").to_owned(),
                    object["version"]
                        .as_str()
                        .expect("identity version")
                        .to_owned(),
                );
                let (reference, _) = sources.entry(key.clone()).or_insert_with(|| {
                    let bytes = canonical_json_bytes(&json!({
                        "schema": "nq.production_identity_descriptor.v1",
                        "kind": key.0,
                        "id": key.1,
                        "version": key.2,
                    }))
                    .expect("production identity descriptor");
                    let bytes_digest = sha256_bytes(&bytes);
                    (
                        RecordRef {
                            schema: Token::parse("nq.production_identity_descriptor.v1")
                                .expect("descriptor schema"),
                            record_id: semantic_digest(
                                &serde_json::from_slice::<Value>(&bytes).expect("descriptor value"),
                            )
                            .expect("descriptor identity"),
                            bytes_digest: bytes_digest.clone(),
                        },
                        bytes,
                    )
                });
                object.insert(
                    "descriptor_digest".to_owned(),
                    Value::String(reference.bytes_digest.to_string()),
                );
            }
            Value::Object(object) => {
                for child in object.values_mut() {
                    rewrite_identity_descriptors(child, sources);
                }
            }
            Value::Array(array) => {
                for child in array {
                    rewrite_identity_descriptors(child, sources);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    fn production_identity_source(
        kind: IdentityKind,
        id: &str,
        version: &str,
    ) -> (IdentityRef, (RecordRef, Vec<u8>)) {
        let kind_value = serde_json::to_value(kind).expect("identity kind");
        let bytes = canonical_json_bytes(&json!({
            "schema": "nq.production_identity_descriptor.v1",
            "kind": kind_value,
            "id": id,
            "version": version,
        }))
        .expect("production identity descriptor");
        let bytes_digest = sha256_bytes(&bytes);
        let reference = RecordRef {
            schema: Token::parse("nq.production_identity_descriptor.v1")
                .expect("descriptor schema"),
            record_id: semantic_digest(
                &serde_json::from_slice::<Value>(&bytes).expect("descriptor value"),
            )
            .expect("descriptor identity"),
            bytes_digest: bytes_digest.clone(),
        };
        (
            IdentityRef {
                kind,
                id: IdentityId::parse(id).expect("identity id"),
                version: IdentityVersion::parse(version).expect("identity version"),
                descriptor_digest: bytes_digest,
            },
            (reference, bytes),
        )
    }

    fn replace_external_references(
        values: &mut BTreeMap<String, Value>,
    ) -> Vec<(RecordRef, Vec<u8>)> {
        let mut references = BTreeSet::new();
        for value in values.values() {
            collect_record_references_for_test(value, &mut references);
        }
        let mut replacements = BTreeMap::new();
        let mut exact = Vec::new();
        for reference in references {
            if RuntimeSchema::parse(reference.schema.as_str()).is_ok()
                || reference.schema.as_str() == PROVIDER_INTAKE_SCHEMA
            {
                continue;
            }
            let bytes = canonical_json_bytes(&json!({
                "schema": reference.schema,
                "fixture_source_record_id": reference.record_id,
            }))
            .expect("external bytes");
            let replacement = RecordRef {
                schema: reference.schema.clone(),
                record_id: semantic_digest(&json!({
                    "schema": reference.schema,
                    "fixture_source_record_id": reference.record_id,
                }))
                .expect("external identity"),
                bytes_digest: sha256_bytes(&bytes),
            };
            replacements.insert(reference, replacement.clone());
            exact.push((replacement, bytes));
        }
        for value in values.values_mut() {
            replace_record_references(value, &replacements);
        }
        exact
    }

    fn stabilize_runtime_references(
        values: &mut BTreeMap<String, Value>,
        mut prior: BTreeMap<String, RecordRef>,
    ) {
        for _ in 0..64 {
            for value in values.values_mut() {
                refresh_self_identity(value);
            }
            repair_invocation_authorization(values);
            repair_decision_request_digest(values);
            repair_administrative_authorizations(values);
            for value in values.values_mut() {
                refresh_self_identity(value);
            }
            let current = values
                .iter()
                .map(|(name, value)| {
                    let schema =
                        RuntimeSchema::parse(value["schema"].as_str().expect("runtime schema"))
                            .expect("known schema");
                    let record_id: Sha256Digest =
                        serde_json::from_value(value[schema.record_id_field()].clone())
                            .expect("record id");
                    (
                        name.clone(),
                        RecordRef {
                            schema: Token::parse(schema.as_str()).expect("schema token"),
                            record_id,
                            bytes_digest: sha256_bytes(
                                &canonical_json_bytes(value).expect("record bytes"),
                            ),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let replacements = prior
                .iter()
                .filter_map(|(name, old)| {
                    let new = &current[name];
                    (old != new).then(|| (old.clone(), new.clone()))
                })
                .collect::<BTreeMap<_, _>>();
            let mut changed = false;
            for value in values.values_mut() {
                changed |= replace_record_references(value, &replacements);
            }
            prior = current;
            if !changed {
                for value in values.values_mut() {
                    refresh_self_identity(value);
                }
                return;
            }
        }
        panic!("runtime fixture references did not stabilize");
    }

    #[allow(clippy::filter_map_bool_then)]
    fn repair_invocation_authorization(values: &mut BTreeMap<String, Value>) {
        let requests = values
            .iter()
            .filter_map(|(name, value)| {
                (value["schema"] == RuntimeSchema::DiagnosticInvocationRequestV1.as_str())
                    .then(|| (name.clone(), value.clone()))
            })
            .collect::<Vec<_>>();
        for (_name, request) in requests {
            let reference: RecordRef =
                serde_json::from_value(request["invocation_authorization"].clone())
                    .expect("invocation authorization reference");
            let Some(authorization_name) = values.iter().find_map(|(name, value)| {
                (value["schema"] == RuntimeSchema::OperationAuthorizationV1.as_str()
                    && value["authorization_id"] == reference.record_id.as_str())
                .then(|| name.clone())
            }) else {
                continue;
            };
            let authorization = values
                .get_mut(&authorization_name)
                .expect("invocation authorization");
            authorization["binding"] = json!({
                "request_preimage_digest": request["request_preimage_digest"],
                "node": request["target"]["node"],
                "subject": request["target"]["subject"],
                "vantage": request["target"]["vantage"],
                "profile": request["profile"],
                "activation_id": request["expected_binding"]["activation"]["record_id"],
                "activation_generation": request["expected_binding"]["activation_generation"],
                "role_manifest_id": request["expected_binding"]["role_manifest"]["record_id"],
                "role_generation": request["expected_binding"]["role_generation"],
                "cohort_manifest_id": request["expected_binding"]["cohort_manifest"]["record_id"],
                "cohort_generation": request["expected_binding"]["cohort_generation"],
                "witness_attachment_ids": request["expected_binding"]["witness_attachments"]
                    .as_array()
                    .expect("witness attachments")
                    .iter()
                    .map(|reference| reference["record_id"].clone())
                    .collect::<Vec<_>>(),
                "purpose_digest": semantic_digest(&request["purpose"])
                    .expect("purpose digest"),
                "time_bounds_digest": semantic_digest(&request["time_bounds"])
                    .expect("time bounds digest"),
                "delivery_binding_digest": semantic_digest(&request["delivery"])
                    .expect("delivery digest"),
            });
        }
    }

    fn repair_decision_request_digest(values: &mut BTreeMap<String, Value>) {
        let Some(request_digest) = values.values().find_map(|value| {
            (value["schema"] == RuntimeSchema::DiagnosticInvocationRequestV1.as_str())
                .then(|| value["request_digest"].clone())
        }) else {
            return;
        };
        for value in values.values_mut() {
            if value["schema"] == RuntimeSchema::InvocationDecisionV1.as_str() {
                value["request_digest"] = request_digest.clone();
            }
        }
    }

    #[allow(clippy::filter_map_bool_then)]
    fn repair_administrative_authorizations(values: &mut BTreeMap<String, Value>) {
        let by_id = values
            .iter()
            .map(|(name, value)| {
                let schema =
                    RuntimeSchema::parse(value["schema"].as_str().expect("runtime schema"))
                        .expect("known schema");
                let record_id: Sha256Digest =
                    serde_json::from_value(value[schema.record_id_field()].clone())
                        .expect("record id");
                (record_id, name.clone())
            })
            .collect::<BTreeMap<_, _>>();
        let mut consumers = BTreeMap::<Sha256Digest, Vec<String>>::new();
        for (name, value) in values.iter() {
            let schema =
                RuntimeSchema::parse(value["schema"].as_str().expect("schema")).expect("schema");
            let Some(field) = administrative_authority_field_for_test(schema) else {
                continue;
            };
            let reference: RecordRef =
                serde_json::from_value(value[field].clone()).expect("authority reference");
            consumers
                .entry(reference.record_id)
                .or_default()
                .push(name.clone());
        }

        let authorizations = values
            .iter()
            .filter_map(|(name, value)| {
                (value["schema"] == RuntimeSchema::OperationAuthorizationV1.as_str()
                    && value["scope"] == "administrative_lifecycle")
                    .then(|| {
                        let record_id: Sha256Digest =
                            serde_json::from_value(value["authorization_id"].clone())
                                .expect("authorization identity");
                        (name.clone(), record_id)
                    })
            })
            .collect::<Vec<_>>();
        for (authorization_name, authorization_id) in authorizations {
            let mut memo = BTreeMap::new();
            let mut visiting = BTreeSet::new();
            let mut authorized_records = consumers
                .get(&authorization_id)
                .into_iter()
                .flatten()
                .map(|consumer_name| {
                    let consumer = &values[consumer_name];
                    let schema =
                        RuntimeSchema::parse(consumer["schema"].as_str().expect("consumer schema"))
                            .expect("consumer schema");
                    let record_id: Sha256Digest =
                        serde_json::from_value(consumer[schema.record_id_field()].clone())
                            .expect("consumer identity");
                    let preimage = administrative_neutral_digest_for_test(
                        values,
                        &by_id,
                        consumer_name,
                        &mut memo,
                        &mut visiting,
                    );
                    json!({
                        "schema": schema.as_str(),
                        "record_id": record_id,
                        "record_preimage_digest": preimage,
                    })
                })
                .collect::<Vec<_>>();
            authorized_records.sort_by(|left, right| {
                let left_key = (
                    left["schema"].as_str().expect("schema"),
                    left["record_id"].as_str().expect("record id"),
                );
                let right_key = (
                    right["schema"].as_str().expect("schema"),
                    right["record_id"].as_str().expect("record id"),
                );
                left_key.cmp(&right_key)
            });
            let authorization = values.get_mut(&authorization_name).expect("authorization");
            authorization["binding"]["authorized_records"] = Value::Array(authorized_records);
            let mut snapshot = authorization["binding"]
                .as_object()
                .expect("binding")
                .clone();
            snapshot.remove("input_snapshot_digest");
            snapshot.insert("operation".to_owned(), authorization["operation"].clone());
            authorization["binding"]["input_snapshot_digest"] = Value::String(
                semantic_digest(&Value::Object(snapshot))
                    .expect("authorization snapshot")
                    .to_string(),
            );
        }
    }

    fn administrative_authority_field_for_test(schema: RuntimeSchema) -> Option<&'static str> {
        match schema {
            RuntimeSchema::NodeEnrollmentV1 => Some("enrollment_authorization"),
            RuntimeSchema::RuntimeActivationV1 => Some("activation_authorization"),
            RuntimeSchema::WitnessAttachmentV1 => Some("attachment_authorization"),
            RuntimeSchema::HostRoleRelationV1
            | RuntimeSchema::HostRoleLifecycleEventV1
            | RuntimeSchema::WitnessLifecycleEventV1
            | RuntimeSchema::NodeKeyLifecycleEventV1
            | RuntimeSchema::RestoreActivationProofV1
            | RuntimeSchema::DecommissionCutV1 => Some("administrative_authorization"),
            _ => None,
        }
    }

    fn administrative_neutral_digest_for_test(
        values: &BTreeMap<String, Value>,
        by_id: &BTreeMap<Sha256Digest, String>,
        name: &str,
        memo: &mut BTreeMap<String, Sha256Digest>,
        visiting: &mut BTreeSet<String>,
    ) -> Sha256Digest {
        if let Some(digest) = memo.get(name) {
            return digest.clone();
        }
        assert!(
            visiting.insert(name.to_owned()),
            "authority-neutral dependency cycle"
        );
        let record = &values[name];
        let schema =
            RuntimeSchema::parse(record["schema"].as_str().expect("schema")).expect("schema");
        let authority_field =
            administrative_authority_field_for_test(schema).expect("administrative consumer");
        let mut preimage = record
            .as_object()
            .expect("administrative consumer object")
            .clone();
        preimage.remove(authority_field);
        let preimage = neutralize_administrative_references_for_test(
            values,
            by_id,
            Value::Object(preimage),
            memo,
            visiting,
        );
        let digest = semantic_digest(&preimage).expect("authority-neutral digest");
        visiting.remove(name);
        memo.insert(name.to_owned(), digest.clone());
        digest
    }

    fn neutralize_administrative_references_for_test(
        values: &BTreeMap<String, Value>,
        by_id: &BTreeMap<Sha256Digest, String>,
        value: Value,
        memo: &mut BTreeMap<String, Sha256Digest>,
        visiting: &mut BTreeSet<String>,
    ) -> Value {
        match value {
            Value::Object(object)
                if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
            {
                let reference: RecordRef = serde_json::from_value(Value::Object(object.clone()))
                    .expect("record reference");
                if let Some(name) = by_id.get(&reference.record_id) {
                    let target = &values[name];
                    let schema =
                        RuntimeSchema::parse(target["schema"].as_str().expect("target schema"))
                            .expect("target schema");
                    if administrative_authority_field_for_test(schema).is_some() {
                        let digest = administrative_neutral_digest_for_test(
                            values, by_id, name, memo, visiting,
                        );
                        return json!({
                            "schema": schema.as_str(),
                            "record_id": reference.record_id,
                            "record_preimage_digest": digest,
                        });
                    }
                }
                Value::Object(object)
            }
            Value::Object(object) => Value::Object(
                object
                    .into_iter()
                    .map(|(key, child)| {
                        (
                            key,
                            neutralize_administrative_references_for_test(
                                values, by_id, child, memo, visiting,
                            ),
                        )
                    })
                    .collect::<Map<_, _>>(),
            ),
            Value::Array(array) => Value::Array(
                array
                    .into_iter()
                    .map(|child| {
                        neutralize_administrative_references_for_test(
                            values, by_id, child, memo, visiting,
                        )
                    })
                    .collect(),
            ),
            primitive => primitive,
        }
    }

    fn refresh_self_identity(value: &mut Value) {
        let schema = RuntimeSchema::parse(value["schema"].as_str().expect("schema"))
            .expect("runtime schema");
        if schema == RuntimeSchema::DiagnosticInvocationRequestV1 {
            let mut preimage = value.clone();
            let preimage = preimage.as_object_mut().expect("request object");
            preimage.remove("request_digest");
            preimage.remove("request_preimage_digest");
            preimage.remove("invocation_authorization");
            value["request_preimage_digest"] = Value::String(
                semantic_digest(&Value::Object(preimage.clone()))
                    .expect("request preimage")
                    .to_string(),
            );
        } else if !matches!(
            schema,
            RuntimeSchema::NativeProfileQualificationV1
                | RuntimeSchema::NativeClockQualificationV1
                | RuntimeSchema::DeadlineEvaluationV1
        ) {
            return;
        }
        let object = value.as_object_mut().expect("runtime record object");
        object.remove(schema.record_id_field());
        let identity = semantic_digest(&Value::Object(object.clone())).expect("record identity");
        object.insert(
            schema.record_id_field().into(),
            Value::String(identity.to_string()),
        );
    }

    fn replace_record_references(
        value: &mut Value,
        replacements: &BTreeMap<RecordRef, RecordRef>,
    ) -> bool {
        match value {
            Value::Object(object)
                if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
            {
                let Ok(reference) =
                    serde_json::from_value::<RecordRef>(Value::Object(object.clone()))
                else {
                    return false;
                };
                if let Some(replacement) = replacements.get(&reference) {
                    *value = serde_json::to_value(replacement).expect("replacement");
                    true
                } else {
                    false
                }
            }
            Value::Object(object) => object.values_mut().fold(false, |changed, child| {
                replace_record_references(child, replacements) || changed
            }),
            Value::Array(array) => array.iter_mut().fold(false, |changed, child| {
                replace_record_references(child, replacements) || changed
            }),
            _ => false,
        }
    }

    fn collect_record_references_for_test(value: &Value, references: &mut BTreeSet<RecordRef>) {
        match value {
            Value::Object(object)
                if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
            {
                references.insert(serde_json::from_value(value.clone()).expect("record reference"));
            }
            Value::Object(object) => {
                for child in object.values() {
                    collect_record_references_for_test(child, references);
                }
            }
            Value::Array(array) => {
                for child in array {
                    collect_record_references_for_test(child, references);
                }
            }
            _ => {}
        }
    }

    fn collect_test_carriers(
        value: &Value,
        identities: &mut Vec<IdentityRef>,
        references: &mut BTreeSet<RecordRef>,
    ) {
        match value {
            Value::Object(object) => {
                let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
                if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                    identities.push(serde_json::from_value(value.clone()).expect("identity"));
                } else if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                    let reference: RecordRef =
                        serde_json::from_value(value.clone()).expect("reference");
                    if RuntimeSchema::parse(reference.schema.as_str()).is_err()
                        && reference.schema.as_str() != PROVIDER_INTAKE_SCHEMA
                    {
                        references.insert(reference);
                    }
                } else {
                    for child in object.values() {
                        collect_test_carriers(child, identities, references);
                    }
                }
            }
            Value::Array(array) => {
                for child in array {
                    collect_test_carriers(child, identities, references);
                }
            }
            _ => {}
        }
    }

    fn transitive_runtime_closure(
        records: &BTreeMap<String, ValidatedRuntimeRecord>,
        roots: impl IntoIterator<Item = RecordRef>,
    ) -> BTreeMap<String, ValidatedRuntimeRecord> {
        let by_id = records
            .iter()
            .map(|(name, record)| (record.record_id().clone(), (name, record)))
            .collect::<BTreeMap<_, _>>();
        let mut pending = roots.into_iter().collect::<Vec<_>>();
        let mut selected = BTreeMap::new();
        while let Some(reference) = pending.pop() {
            if RuntimeSchema::parse(reference.schema.as_str()).is_err() {
                continue;
            }
            let (name, record) = by_id
                .get(&reference.record_id)
                .unwrap_or_else(|| panic!("runtime dependency {reference:?}"));
            if selected.contains_key(*name) {
                continue;
            }
            let mut nested = BTreeSet::new();
            collect_record_references_for_test(record.record().as_value(), &mut nested);
            if record.schema() == RuntimeSchema::OperationAuthorizationV1
                && record.record().as_value()["scope"] == "administrative_lifecycle"
            {
                for authorized in record.record().as_value()["binding"]["authorized_records"]
                    .as_array()
                    .expect("authorized records")
                {
                    let record_id: Sha256Digest =
                        serde_json::from_value(authorized["record_id"].clone())
                            .expect("authorized record id");
                    let (_, consumer) = by_id
                        .get(&record_id)
                        .unwrap_or_else(|| panic!("authorized consumer {record_id}"));
                    assert_eq!(
                        consumer.schema().as_str(),
                        authorized["schema"].as_str().expect("authorized schema")
                    );
                    nested.insert(consumer.exact_reference());
                }
            }
            pending.extend(nested);
            selected.insert((*name).clone(), (*record).clone());
        }
        selected
    }
}
