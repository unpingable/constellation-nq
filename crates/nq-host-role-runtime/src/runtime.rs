//! Contract-to-schema-v7 dependency-bound runtime ledger bridge.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use nq_host_role_contract::{
    ExternalRecordCatalog, IdentityCatalog, IdentityRef, RecordRef, RuntimeRecordSet,
    RuntimeSchema, Token, ValidatedRuntimeRecord, ValidationContext,
};
use nq_protocol::{Sha256Digest, sha256_bytes};
use nq_store::{
    CanonicalDocument, GovernedCustodyInventoryEntry, GovernedCustodyReservation,
    GovernedProtectedFailureAccess, MAX_PUBLIC_QUERY_ROWS, RuntimeCheckpointDependencyBinding,
    RuntimeCheckpointDependencyInput, RuntimeDependencyGenerationByteState,
    RuntimeLedgerCheckpoint, RuntimeRecordAppendDisposition, RuntimeRecordBatchInput,
    RuntimeRecordInput, RuntimeRecordRow, Store, runtime_record_batch_digest,
};
use serde_json::Value;

use crate::{
    ExternalDependencyAvailability, GovernedPrelaunchRequest, InspectorPage, InspectorProjection,
    InspectorProjectionState, PreparedGovernedInvocation, Result, RuntimeDependencies,
    RuntimeError, production_identity,
};

const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";

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
    production: crate::GovernedProductionIdentity,
    outer_request: RecordRef,
    invocation_decision: RecordRef,
    custody_reservation: RecordRef,
    execution_launch: RecordRef,
    launched_at: String,
    raw_capacity_bytes: u64,
    dependency_closure_capacity_bytes: u64,
    final_capacity_bytes: u64,
    protected_failure_capacity_bytes: u64,
    complete_records: RuntimeRecordSet,
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
    /// Initializes a new schema-v7 store and opens an empty host-role runtime.
    ///
    /// # Errors
    ///
    /// Refuses an existing database, invalid dependencies, or store
    /// initialization failure.
    pub fn initialize(path: impl AsRef<Path>, dependencies: RuntimeDependencies) -> Result<Self> {
        let mut store = Store::initialize(path)?;
        let trust_root = dependencies.custody().trust_anchor_id()?;
        store.establish_runtime_dependency_trust_root(&trust_root)?;
        Self::from_store(store, dependencies)
    }

    /// Opens an existing schema-v7 store and validates the complete ledger.
    ///
    /// # Errors
    ///
    /// Refuses corruption, dependency substitution, unsupported schemas,
    /// unresolved references, or any failed contract join.
    pub fn open(path: impl AsRef<Path>, dependencies: RuntimeDependencies) -> Result<Self> {
        Self::from_store(Store::open(path)?, dependencies)
    }

    /// Opens an already constructed store.
    ///
    /// This is useful for bounded in-memory qualification while retaining the
    /// same validation path as file-backed restart.
    ///
    /// # Errors
    ///
    /// Refuses every condition described by [`Self::open`].
    pub fn from_store(store: Store, dependencies: RuntimeDependencies) -> Result<Self> {
        store.validate()?;
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

    /// Return the exact physical custody frontiers classified during startup
    /// or the most recent governed prelaunch.
    ///
    /// These entries are storage/recovery facts only. They do not resume work
    /// or establish diagnostic outcomes.
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
        let receipt = self.store.append_runtime_records(&batch)?;
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
    #[allow(clippy::needless_pass_by_value)]
    pub fn prepare_governed_invocation(
        &mut self,
        request: GovernedPrelaunchRequest,
    ) -> Result<PreparedGovernedInvocation> {
        let preflight = self.preflight_governed(&request)?;
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
            final_capacity_bytes: preflight.final_capacity_bytes,
            protected_failure_capacity_bytes: preflight.protected_failure_capacity_bytes,
        };
        let mut physical_custody = self
            .store
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
        physical_custody.claim_launch(
            request.execution_launch_record_id.clone(),
            preflight.launched_at.clone(),
        )?;
        drop(physical_custody);
        self.custody_frontiers = self.store.governed_custody_inventory()?;

        Ok(PreparedGovernedInvocation {
            request_id: preflight.request_id,
            production: preflight.production,
            reservation_checkpoint: reservation_result.checkpoint,
            launch_checkpoint: launch_result.checkpoint,
            outer_request: preflight.outer_request,
            invocation_decision: preflight.invocation_decision,
            custody_reservation: preflight.custody_reservation,
            execution_launch: preflight.execution_launch,
            prelaunch_records: preflight.complete_records,
            existing_provider_intakes: self.provider_intakes.values().cloned().collect(),
            dependencies: self.dependencies.clone(),
            dependency_custody_bytes,
            custody_reservation_spec: reservation_spec,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn preflight_governed(&self, request: &GovernedPrelaunchRequest) -> Result<GovernedPreflight> {
        if request.launch_custody.records.len() != 1
            || request.launch_custody.records[0].record_id
                != request.execution_launch_record_id.as_str()
            || request
                .reservation_custody
                .records
                .iter()
                .any(|record| record.record_id == request.execution_launch_record_id.as_str())
        {
            return Err(RuntimeError::PrelaunchNotAcceptedReservedLaunched);
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
        let receipt = self.store.append_runtime_records(&batch)?;
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
    if canonical_custody.digest() != custody_digest.as_str()
        || u64::try_from(canonical_custody.as_bytes().len()).map_err(|_| {
            RuntimeError::CheckpointDependencyCorrupt {
                checkpoint_id: checkpoint_id.to_owned(),
                reason: "dependency custody length overflowed".to_owned(),
            }
        })? != custody_length
    {
        return Err(RuntimeError::CheckpointDependencyCorrupt {
            checkpoint_id: checkpoint_id.to_owned(),
            reason: "dependency custody differs from its checkpoint commitment".to_owned(),
        });
    }
    let custody = crate::RuntimeDependencyGenerationCustody::decode_canonical_closure(
        canonical_custody.as_bytes(),
    )?;
    if custody.generation_id() != &generation_id || custody.trust_anchor_id()? != *trust_root {
        return Err(RuntimeError::RuntimeDependencyGenerationSubstitution);
    }
    custody.reopen(trust_root)
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
    use nq_store::{
        GovernedCustodyInventoryEntry, GovernedCustodyRecoveryClass,
        GovernedCustodyReservationLedgerBinding, GovernedCustodyState,
        GovernedProtectedFailureAccess, Store,
    };
    use serde_json::{Map, Value, json};
    use tempfile::tempdir;

    use super::*;
    use crate::{
        GovernedPrelaunchRequest, RuntimeError, dependency::tests::authenticated_runtime_fixture,
    };

    const RECORDS: &str =
        include_str!("../../nq-host-role-contract/assets/host-role-runtime-records.v1.json");

    struct Fixture {
        dependencies: RuntimeDependencies,
        request: GovernedPrelaunchRequest,
        dependency_anchor_id: Sha256Digest,
        runtime_identities: Vec<IdentityRef>,
        external_inputs: Vec<(RecordRef, Vec<u8>)>,
        operation_authorizations: Vec<RecordRef>,
        authentication: Vec<RecordRef>,
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> Fixture {
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
        let external_inputs = replace_external_references(&mut values);
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
        }
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

    fn extra_identity(id: &str) -> IdentityRef {
        IdentityRef {
            kind: IdentityKind::Capability,
            id: IdentityId::parse(id).expect("extra identity"),
            version: IdentityVersion::parse("v1").expect("extra identity version"),
            descriptor_digest: sha256_bytes(format!("extra:{id}:v1").as_bytes()),
        }
    }

    #[test]
    fn governed_prelaunch_is_two_phase_physically_reserved_and_one_use() {
        let fixture = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        let reopened_dependencies = fixture.dependencies.clone();
        let mut runtime =
            HostRoleRuntime::initialize(&database, fixture.dependencies).expect("runtime");
        let request = fixture.request.clone();
        let prepared = runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        assert_eq!(prepared.reservation_checkpoint().checkpoint_sequence, 1);
        assert_eq!(prepared.launch_checkpoint().checkpoint_sequence, 2);
        assert!(
            prepared.reservation_checkpoint().last_record_sequence
                < prepared.launch_checkpoint().first_record_sequence
        );
        let custody_store = Store::open(&database).expect("custody store");
        let custody = custody_store
            .open_governed_custody(prepared.custody_reservation_spec().clone())
            .expect("reopen custody");
        assert_eq!(
            custody.state().expect("custody state"),
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
        assert_eq!(
            custody
                .dependency_closure_bytes()
                .expect("physical dependency closure"),
            prepared.dependency_custody_bytes()
        );
        drop(custody);
        let [GovernedCustodyInventoryEntry::Verified(frontier)] = runtime.custody_frontiers()
        else {
            panic!("one verified custody frontier");
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
        assert_eq!(
            frontier.reservation_record_id,
            request.custody_reservation_record_id
        );
        assert_eq!(
            runtime
                .protected_failure(&frontier.reservation_record_id)
                .expect("protected-failure read"),
            GovernedProtectedFailureAccess::NotPresent {
                arena_state: GovernedCustodyState::LaunchClaimed,
            }
        );
        drop(prepared);
        assert!(matches!(
            runtime.prepare_governed_invocation(request),
            Err(RuntimeError::PrelaunchReplayCannotRerun)
        ));
        drop(runtime);

        let reopened = HostRoleRuntime::open(&database, reopened_dependencies)
            .expect("restart classifies physical frontier");
        let [GovernedCustodyInventoryEntry::Verified(frontier)] = reopened.custody_frontiers()
        else {
            panic!("one verified startup frontier");
        };
        assert_eq!(
            frontier.recovery_class,
            GovernedCustodyRecoveryClass::LaunchedWithoutAcquisition
        );
    }

    #[test]
    fn governed_prelaunch_refuses_graph_and_capacity_substitution() {
        let first = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("graph.db");
        let mut runtime =
            HostRoleRuntime::initialize(&database, first.dependencies).expect("runtime");
        let mut request = first.request;
        let launch = &mut request.launch_custody.records[0];
        let mut value: Value =
            serde_json::from_slice(&launch.canonical_bytes).expect("launch bytes");
        value["status"] = json!("not_launched");
        launch.canonical_bytes = canonical_json_bytes(&value).expect("hostile launch");
        assert!(runtime.prepare_governed_invocation(request).is_err());

        let second = fixture();
        let database = directory.path().join("capacity.db");
        let mut runtime =
            HostRoleRuntime::initialize(&database, second.dependencies).expect("runtime");
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
    fn startup_inventory_keeps_an_unreadable_arena_entry_visible() {
        let fixture = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("inventory.db");
        let mut runtime =
            HostRoleRuntime::initialize(&database, fixture.dependencies.clone()).expect("runtime");
        runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        drop(runtime);

        let root = database.with_file_name("inventory.db.nq-custody-v1");
        std::fs::write(root.join("unexpected-entry"), b"not an arena")
            .expect("hostile custody-root entry");
        let reopened =
            HostRoleRuntime::open(&database, fixture.dependencies).expect("runtime reopens");
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
            HostRoleRuntime::initialize(&database, fixture.dependencies).expect("runtime");
        runtime
            .prepare_governed_invocation(fixture.request)
            .expect("prepared invocation");
        let [GovernedCustodyInventoryEntry::Verified(frontier)] = runtime.custody_frontiers()
        else {
            panic!("one verified frontier");
        };
        let arena_path = database
            .with_file_name("missing-arena.db.nq-custody-v1")
            .join(&frontier.relative_path);
        let reservation_manifest_digest = frontier.reservation_manifest_digest.clone();
        drop(runtime);
        std::fs::remove_file(arena_path).expect("remove disposable arena specimen");

        let reopened =
            HostRoleRuntime::open(&database, dependencies).expect("ledger remains inspectable");
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
            HostRoleRuntime::initialize(&database, first.dependencies).expect("g1 runtime");
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
            HostRoleRuntime::open(&database, g2.clone()).expect("g1 reopened under g2 current");
        assert_eq!(runtime.contract_record_count(), g1_record_count);
        let g2_append = opaque_append("g2-opaque", "2026-07-29T21:01:00Z");
        let g2_checkpoint = runtime
            .append_custody_only(&g2_append)
            .expect("g2 append without reinterpreting g1")
            .checkpoint;
        drop(runtime);

        let runtime = HostRoleRuntime::open(&database, g2.clone()).expect("restart after g2");
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
            HostRoleRuntime::initialize(&database, first.dependencies).expect("g1 runtime");
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

        let mut runtime = HostRoleRuntime::open(&database, g2.clone()).expect("g2 current");
        runtime
            .append_custody_only(&opaque_append(
                "same-anchor-superset",
                "2026-07-29T21:02:00Z",
            ))
            .expect("g2 checkpoint");
        drop(runtime);
        HostRoleRuntime::open(&database, g2).expect("both generations reopen after restart");
    }

    #[test]
    fn later_generation_cannot_select_a_new_dependency_trust_root() {
        let first = fixture();
        let directory = tempdir().expect("directory");
        let database = directory.path().join("bootstrap-root-substitution.db");
        let expected_anchor = first.dependency_anchor_id.clone();
        let mut runtime =
            HostRoleRuntime::initialize(&database, first.dependencies).expect("g1 runtime");
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
        let Err(error) = HostRoleRuntime::open(&database, g2) else {
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
            HostRoleRuntime::initialize(&database, first.dependencies).expect("g1 runtime");
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
        let mut runtime = HostRoleRuntime::open(&database, g2).expect("g1 exact reopen");
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
        if schema != RuntimeSchema::DiagnosticInvocationRequestV1 {
            return;
        }
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
