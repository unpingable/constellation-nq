//! Durable governed prelaunch support.
//!
//! This module ends at authenticated graph validation, physical reservation,
//! ledger commitment, and a one-use launch claim. It deliberately contains no
//! provider invocation, engine result source, finalizer, or execution-binding
//! constructor.

use std::collections::BTreeSet;

use nq_host_role_contract::{
    ExecutionBindingSourceCorpus, IdentityRef, RecordRef, RuntimeRecordSet, RuntimeSchema, Token,
    ValidatedRuntimeRecord, ValidationContext,
};
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use nq_store::{
    CanonicalDocument, CustodiedAcquisition, GovernedAcquisitionCustodyInput, GovernedCustody,
    GovernedCustodyCommitment, GovernedCustodyReservation, GovernedCustodyState,
    GovernedDerivationCustodyClaim, GovernedProtectedTerminalInput,
    GovernedProtectedTerminalization, RuntimeCheckpointDependencyInput, RuntimeLedgerCheckpoint,
    RuntimeRecordBatchInput, RuntimeRecordInput, runtime_record_batch_digest,
};
use serde_json::{Value, json};

use crate::{
    ExternalDependencyAvailability, Result, RuntimeDependencies, RuntimeError,
    runtime::{AppendRecord, AppendRequest},
};

const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";
const PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA: &str = "nq.production_identity_descriptor.v1";
const FINAL_CHECKPOINT_SCHEMA: &str = "nq.governed_final_runtime_checkpoint.v1";
const BINDING_SOURCE_SLOTS: [&str; 8] = [
    "node",
    "subject",
    "platform",
    "vantage",
    "role",
    "static_profile_cohort",
    "witness",
    "diagnostic_profile",
];

/// Two-phase prelaunch plan.
///
/// `reservation_custody` contains the request, accepted decision, and reserved
/// custody closure. `launch_custody` contains the exact launch record and is
/// appended only after physical reservation and the reservation checkpoint
/// have committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedPrelaunchRequest {
    /// First atomic checkpoint: request, accepted decision, and reservation.
    pub reservation_custody: AppendRequest,
    /// Second atomic checkpoint containing the exact launch record.
    pub launch_custody: AppendRequest,
    /// Exact outer request record identity.
    pub outer_request_record_id: Sha256Digest,
    /// Exact accepted decision record identity.
    pub invocation_decision_record_id: Sha256Digest,
    /// Exact custody-reservation record identity.
    pub custody_reservation_record_id: Sha256Digest,
    /// Exact execution-launch record identity.
    pub execution_launch_record_id: Sha256Digest,
}

/// Caller-supplied non-temporal material for a runtime-owned deadline launch.
///
/// Unlike [`GovernedPrelaunchRequest`], this request has no execution-launch
/// carrier, launch timestamp, attempt deadline, monotonic sample, boot epoch,
/// or deadline-evaluation record. The runtime constructs those values from
/// its own Linux clock and boot-identity observations.
///
/// The three record references are already-governed prelaunch evidence. They
/// remain exact inputs; possession of them grants no invocation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDeadlinePrelaunchRequest {
    /// First atomic checkpoint: request, accepted decision, reservation, and
    /// the complete prelaunch graph other than the runtime-owned deadline and
    /// launch records.
    pub reservation_custody: AppendRequest,
    /// Exact outer request record identity.
    pub outer_request_record_id: Sha256Digest,
    /// Exact accepted decision record identity.
    pub invocation_decision_record_id: Sha256Digest,
    /// Exact custody-reservation record identity.
    pub custody_reservation_record_id: Sha256Digest,
    /// Exact generation-compatibility evidence referenced by the launch.
    pub generation_match: RecordRef,
    /// Exact capability evidence referenced by the launch.
    pub capability: RecordRef,
    /// Exact durable launch-commit evidence referenced by the launch.
    pub launch_commit: RecordRef,
    /// Identified policy governing the realtime/boottime sample bracket.
    pub bracket_policy: IdentityRef,
    /// Maximum accepted width of the runtime-owned realtime bracket.
    pub maximum_bracket_width_ns: u64,
}

/// Unforgeable-by-construction runtime-owned deadline provenance.
///
/// Fields are private and this type has no public constructor. An ordinary
/// caller can create deadline-shaped contract records, but cannot attach this
/// provenance to a [`PreparedGovernedInvocation`].
#[derive(Debug, PartialEq, Eq)]
pub struct NativeDeadlineProvenance {
    pub(crate) evaluation: RecordRef,
    pub(crate) clock_qualification: RecordRef,
    pub(crate) boot_epoch: Sha256Digest,
    pub(crate) boottime_observed_ns: u64,
    pub(crate) boottime_expiry_ns: u64,
}

impl NativeDeadlineProvenance {
    /// Return the exact runtime-constructed deadline evaluation.
    #[must_use]
    pub const fn evaluation(&self) -> &RecordRef {
        &self.evaluation
    }

    /// Return the exact cohort-qualified native clock correspondence.
    #[must_use]
    pub const fn clock_qualification(&self) -> &RecordRef {
        &self.clock_qualification
    }

    /// Return the exact digest of the Linux boot-id bytes sampled for launch.
    #[must_use]
    pub const fn boot_epoch(&self) -> &Sha256Digest {
        &self.boot_epoch
    }

    /// Return the exact `CLOCK_BOOTTIME` observation in nanoseconds.
    #[must_use]
    pub const fn boottime_observed_ns(&self) -> u64 {
        self.boottime_observed_ns
    }

    /// Return the exact governed `CLOCK_BOOTTIME` expiry in nanoseconds.
    #[must_use]
    pub const fn boottime_expiry_ns(&self) -> u64 {
        self.boottime_expiry_ns
    }
}

/// Exact production identity recovered from the validated runtime graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedProductionIdentity {
    pub(crate) node: IdentityRef,
    pub(crate) subject: IdentityRef,
    pub(crate) vantage: IdentityRef,
    pub(crate) cohort: IdentityRef,
}

impl GovernedProductionIdentity {
    /// Return the exact enrolled NQ node.
    #[must_use]
    pub const fn node(&self) -> &IdentityRef {
        &self.node
    }

    /// Return the exact diagnostic subject.
    #[must_use]
    pub const fn subject(&self) -> &IdentityRef {
        &self.subject
    }

    /// Return the exact vantage generation.
    #[must_use]
    pub const fn vantage(&self) -> &IdentityRef {
        &self.vantage
    }

    /// Return the exact static-profile cohort generation.
    #[must_use]
    pub const fn cohort(&self) -> &IdentityRef {
        &self.cohort
    }
}

/// Source-qualified terminal runtime batch for one prepared invocation.
///
/// This carrier is constructible only through
/// [`PreparedGovernedInvocation::qualify_final_batch`]. It exposes the exact
/// store batch and immutable references required by NQ core's atomic
/// diagnostic projection, but owns no append handle and grants no generic
/// runtime mutation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedGovernedFinalBatch {
    batch: RuntimeRecordBatchInput,
    batch_digest: Sha256Digest,
    provider_intake: RecordRef,
    execution_binding: RecordRef,
    runtime_records: [RecordRef; 2],
}

impl QualifiedGovernedFinalBatch {
    /// Return the exact source-qualified store batch.
    #[must_use]
    pub const fn batch(&self) -> &RuntimeRecordBatchInput {
        &self.batch
    }

    /// Return the exact canonical batch digest.
    #[must_use]
    pub const fn batch_digest(&self) -> &Sha256Digest {
        &self.batch_digest
    }

    /// Return the exact opaque provider-intake record.
    #[must_use]
    pub const fn provider_intake(&self) -> &RecordRef {
        &self.provider_intake
    }

    /// Return the exact source-qualified V2 execution binding.
    #[must_use]
    pub const fn execution_binding(&self) -> &RecordRef {
        &self.execution_binding
    }

    /// Return the closed ordered checkpoint membership.
    #[must_use]
    pub const fn runtime_records(&self) -> &[RecordRef; 2] {
        &self.runtime_records
    }
}

/// Non-cloneable result of a validated and durably claimed prelaunch.
///
/// This is not an execution grant. It exposes only the exact material NQ core
/// must privately revalidate, the immutable storage reservation specification,
/// and narrow custody transitions for this exact one-use launch. It cannot
/// launch a provider, schedule work, construct a diagnostic binding, or expose
/// the underlying custody handle.
pub struct PreparedGovernedInvocation {
    pub(crate) request_id: String,
    pub(crate) production: GovernedProductionIdentity,
    pub(crate) reservation_checkpoint: RuntimeLedgerCheckpoint,
    pub(crate) launch_checkpoint: RuntimeLedgerCheckpoint,
    pub(crate) reservation_checkpoint_records: Vec<RecordRef>,
    pub(crate) launch_checkpoint_records: Vec<RecordRef>,
    pub(crate) outer_request: RecordRef,
    pub(crate) invocation_decision: RecordRef,
    pub(crate) custody_reservation: RecordRef,
    pub(crate) execution_launch: RecordRef,
    pub(crate) prelaunch_records: RuntimeRecordSet,
    pub(crate) existing_provider_intakes: Vec<RecordRef>,
    pub(crate) historical_validation_context: ValidationContext,
    pub(crate) historical_dependencies: Vec<RuntimeDependencies>,
    pub(crate) dependencies: RuntimeDependencies,
    pub(crate) dependency_custody_bytes: Vec<u8>,
    pub(crate) custody_reservation_spec: GovernedCustodyReservation,
    pub(crate) native_deadline: Option<NativeDeadlineProvenance>,
    pub(crate) live_custody: GovernedCustody,
}

impl PreparedGovernedInvocation {
    fn require_exact_launch(&self, launch: &Sha256Digest) -> Result<()> {
        if launch != &self.execution_launch.record_id {
            return Err(crate::RuntimeError::PreparedCustodyLaunchSubstitution);
        }
        Ok(())
    }

    /// Return the exact authorized outer request occurrence.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Return the graph-resolved production identity.
    #[must_use]
    pub const fn production_identity(&self) -> &GovernedProductionIdentity {
        &self.production
    }

    /// Return the committed reservation checkpoint.
    #[must_use]
    pub const fn reservation_checkpoint(&self) -> &RuntimeLedgerCheckpoint {
        &self.reservation_checkpoint
    }

    /// Return the committed launch checkpoint.
    #[must_use]
    pub const fn launch_checkpoint(&self) -> &RuntimeLedgerCheckpoint {
        &self.launch_checkpoint
    }

    /// Return the exact ordered reservation-checkpoint membership.
    #[must_use]
    pub fn reservation_checkpoint_records(&self) -> &[RecordRef] {
        &self.reservation_checkpoint_records
    }

    /// Return the exact ordered launch-checkpoint membership.
    #[must_use]
    pub fn launch_checkpoint_records(&self) -> &[RecordRef] {
        &self.launch_checkpoint_records
    }

    /// Return the exact outer request reference.
    #[must_use]
    pub const fn outer_request(&self) -> &RecordRef {
        &self.outer_request
    }

    /// Return the exact accepted invocation-decision reference.
    #[must_use]
    pub const fn invocation_decision(&self) -> &RecordRef {
        &self.invocation_decision
    }

    /// Return the exact custody-reservation reference.
    #[must_use]
    pub const fn custody_reservation(&self) -> &RecordRef {
        &self.custody_reservation
    }

    /// Return the exact execution-launch reference.
    #[must_use]
    pub const fn execution_launch(&self) -> &RecordRef {
        &self.execution_launch
    }

    /// Return the complete prelaunch graph frozen at launch.
    #[must_use]
    pub const fn prelaunch_records(&self) -> &RuntimeRecordSet {
        &self.prelaunch_records
    }

    /// Return the exact provider-intake references preceding this invocation.
    #[must_use]
    pub fn existing_provider_intakes(&self) -> &[RecordRef] {
        &self.existing_provider_intakes
    }

    /// Return the authenticated dependency generation frozen at launch.
    #[must_use]
    pub const fn dependencies(&self) -> &RuntimeDependencies {
        &self.dependencies
    }

    /// Return the exact dependency-generation custody carrier.
    #[must_use]
    pub fn dependency_custody_bytes(&self) -> &[u8] {
        &self.dependency_custody_bytes
    }

    /// Return the immutable physical reservation specification.
    #[must_use]
    pub const fn custody_reservation_spec(&self) -> &GovernedCustodyReservation {
        &self.custody_reservation_spec
    }

    /// Return the exact ratified diagnostic-artifact component bound.
    ///
    /// This is intentionally distinct from the larger final-closure
    /// partition, which also carries binding, closure, and index material.
    #[must_use]
    pub const fn diagnostic_artifact_capacity_bytes(&self) -> u64 {
        self.custody_reservation_spec
            .diagnostic_artifact_capacity_bytes
    }

    /// Return runtime-owned native-deadline provenance when this invocation
    /// used the sealed native preparation path.
    ///
    /// The generic 3A preparation path always returns `None`, even if a caller
    /// supplied a deadline-shaped record.
    #[must_use]
    pub const fn native_deadline(&self) -> Option<&NativeDeadlineProvenance> {
        self.native_deadline.as_ref()
    }

    /// Return the durable state of the exact live custody handle retained by
    /// this one-use prepared occurrence.
    ///
    /// This is a physical custody fact, not a diagnostic disposition.
    ///
    /// # Errors
    ///
    /// Refuses an unreadable or corrupt arena.
    pub fn live_custody_state(&self) -> Result<GovernedCustodyState> {
        self.live_custody.state().map_err(Into::into)
    }

    /// Qualify the only terminal runtime write set accepted for this launch.
    ///
    /// The method accepts exactly one opaque provider-intake append and one
    /// already validated V2 execution-binding record. It reconstructs the
    /// binding's transitive historical runtime graph, admits only the exact
    /// source and descriptor bytes selected by that binding, and invokes the
    /// contract's source-complete validation entry point. The resulting batch
    /// remains bound to the dependency generation and launch frontier frozen
    /// in this prepared token.
    ///
    /// This is a pure qualification step. It performs no append, custody
    /// transition, provider invocation, diagnostic derivation, scheduling, or
    /// authorization.
    ///
    /// # Errors
    ///
    /// Refuses malformed provider custody, a non-V2 or graph-incompatible
    /// binding, source substitution or unavailability, an extraneous selected
    /// source, dependency-generation mismatch, or an invalid final batch.
    pub fn qualify_final_batch(
        &self,
        provider_intake: AppendRecord,
        execution_binding: ValidatedRuntimeRecord,
    ) -> Result<QualifiedGovernedFinalBatch> {
        if execution_binding.schema() != RuntimeSchema::ExecutionIdentityBindingV2 {
            return Err(RuntimeError::NotExecutionBinding(
                execution_binding.record_id().to_string(),
            ));
        }
        let provider_intake_ref = exact_provider_intake_reference(&provider_intake)?;
        let execution_binding_ref = execution_binding.exact_reference();
        let committed_at = provider_intake.committed_at.clone();
        let binding_append = AppendRecord::from_contract(&execution_binding, committed_at);

        let mut batch_contract_records = RuntimeRecordSet::new();
        batch_contract_records.insert(execution_binding.clone())?;
        self.dependencies
            .validate_graph_dependencies(&batch_contract_records)?;

        let binding_graph = self.complete_historical_graph(execution_binding)?;
        let mut context = self.historical_validation_context.clone();
        context.external_records.insert(provider_intake_ref.clone());
        let historical_bindings = binding_graph
            .records()
            .filter(|record| record.schema() == RuntimeSchema::ExecutionIdentityBindingV2)
            .map(ValidatedRuntimeRecord::exact_reference)
            .collect::<Vec<_>>();
        for historical_binding in historical_bindings {
            let sources = self.binding_selected_sources(&binding_graph, &historical_binding)?;
            binding_graph.validate_execution_binding_with_sources(
                &context,
                &historical_binding,
                &sources,
            )?;
        }

        let checkpoint_id = semantic_digest(&json!({
            "schema": FINAL_CHECKPOINT_SCHEMA,
            "execution_launch": self.execution_launch,
            "dependency_generation_id": self.dependencies.generation_id(),
            "provider_intake": provider_intake_ref,
            "execution_binding": execution_binding_ref,
            "committed_at": provider_intake.committed_at,
        }))?;
        let batch = RuntimeRecordBatchInput {
            checkpoint_id: checkpoint_id.to_string(),
            expected_predecessor_checkpoint_id: Some(self.launch_checkpoint.checkpoint_id.clone()),
            expected_predecessor_ledger_root: Some(
                self.launch_checkpoint.checkpoint_ledger_root.clone(),
            ),
            dependency: dependency_input(&self.dependencies)?,
            records: vec![
                store_record_input(provider_intake)?,
                store_record_input(binding_append)?,
            ],
        };
        let batch_digest = runtime_record_batch_digest(&batch)?;
        let runtime_records = [provider_intake_ref.clone(), execution_binding_ref.clone()];
        Ok(QualifiedGovernedFinalBatch {
            batch,
            batch_digest,
            provider_intake: provider_intake_ref,
            execution_binding: execution_binding_ref,
            runtime_records,
        })
    }

    fn complete_historical_graph(
        &self,
        execution_binding: ValidatedRuntimeRecord,
    ) -> Result<RuntimeRecordSet> {
        let mut graph = self.prelaunch_records.clone();
        graph.insert(execution_binding)?;
        Ok(graph)
    }

    fn binding_selected_sources(
        &self,
        binding_graph: &RuntimeRecordSet,
        execution_binding: &RecordRef,
    ) -> Result<ExecutionBindingSourceCorpus> {
        let execution_binding = binding_graph
            .get(&execution_binding.record_id)
            .filter(|record| record.exact_reference() == *execution_binding)
            .ok_or_else(|| {
                RuntimeError::HistoricalDependencyMissing(execution_binding.record_id.to_string())
            })?;
        let mut corpus = ExecutionBindingSourceCorpus::new();
        let value = execution_binding.record().as_value();
        let resolution_entries =
            value["resolved_references"]
                .as_object()
                .ok_or(RuntimeError::LedgerCarrierMismatch(
                    "execution binding resolved references",
                ))?;
        for slot in BINDING_SOURCE_SLOTS {
            let entry =
                resolution_entries[slot]
                    .as_object()
                    .ok_or(RuntimeError::LedgerCarrierMismatch(
                        "execution binding resolved source",
                    ))?;
            let source: RecordRef = serde_json::from_value(entry["source_artifact"].clone())?;
            let descriptor: RecordRef = serde_json::from_value(entry["descriptor"].clone())?;
            self.insert_exact_binding_source(&mut corpus, binding_graph, &source)?;
            self.insert_exact_binding_source(&mut corpus, binding_graph, &descriptor)?;
        }

        let resolver: IdentityRef = serde_json::from_value(value["resolver"].clone())?;
        let resolver_candidates = self
            .historical_dependencies
            .iter()
            .flat_map(|dependencies| {
                dependencies
                    .external_dependency_snapshot()
                    .dependencies
                    .iter()
            })
            .filter(|dependency| {
                dependency.reference.schema.as_str() == PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA
                    && dependency.reference.bytes_digest == resolver.descriptor_digest
            })
            .map(|dependency| dependency.reference.clone())
            .collect::<BTreeSet<_>>();
        for reference in resolver_candidates {
            self.insert_exact_binding_source(&mut corpus, binding_graph, &reference)?;
        }
        Ok(corpus)
    }

    fn insert_exact_binding_source(
        &self,
        corpus: &mut ExecutionBindingSourceCorpus,
        binding_graph: &RuntimeRecordSet,
        reference: &RecordRef,
    ) -> Result<()> {
        if RuntimeSchema::parse(reference.schema.as_str()).is_ok() {
            let record = binding_graph.get(&reference.record_id).ok_or_else(|| {
                RuntimeError::HistoricalDependencyMissing(reference.record_id.to_string())
            })?;
            if record.exact_reference() != *reference {
                return Err(RuntimeError::HistoricalDependencyMissing(
                    reference.record_id.to_string(),
                ));
            }
            corpus.insert_record(record)?;
            return Ok(());
        }
        let mut exact_bytes = None;
        let mut unavailable = false;
        for dependency in self
            .historical_dependencies
            .iter()
            .flat_map(|dependencies| {
                dependencies
                    .external_dependency_snapshot()
                    .dependencies
                    .iter()
            })
            .filter(|dependency| dependency.reference == *reference)
        {
            if dependency.availability == ExternalDependencyAvailability::CommittedUnavailable {
                unavailable = true;
                continue;
            }
            let bytes = hex::decode(
                dependency
                    .exact_bytes_hex
                    .as_deref()
                    .ok_or(RuntimeError::ExternalDependencyAvailabilityMismatch)?,
            )
            .map_err(|_| RuntimeError::ExternalDependencyBytesMalformed)?;
            match &exact_bytes {
                Some(existing) if existing != &bytes => {
                    return Err(RuntimeError::ExternalDependencyByteSubstitution(
                        reference.record_id.to_string(),
                    ));
                }
                Some(_) => {}
                None => exact_bytes = Some(bytes),
            }
        }
        if let Some(bytes) = exact_bytes {
            corpus.insert_canonical(reference.clone(), bytes)?;
            return Ok(());
        }
        if unavailable {
            return Err(RuntimeError::ExternalDependencyUnavailable(
                reference.record_id.to_string(),
            ));
        }
        Err(RuntimeError::HistoricalDependencyMissing(
            reference.record_id.to_string(),
        ))
    }

    /// Seal and reopen exact provider-intake and raw bytes through this
    /// prepared occurrence's live custody handle.
    ///
    /// This is a physical custody transition only. It assigns no provider,
    /// evidence, diagnostic, reliance, or authorization standing.
    ///
    /// # Errors
    ///
    /// Refuses launch substitution, capacity overflow, replay, or persistence
    /// failure.
    pub fn seal_acquisition(
        &mut self,
        input: GovernedAcquisitionCustodyInput,
    ) -> Result<CustodiedAcquisition> {
        self.require_exact_launch(&input.execution_launch_record_id)?;
        self.live_custody
            .seal_acquisition(input)
            .map_err(Into::into)
    }

    /// Claim one derivation transition over the exact sealed acquisition.
    ///
    /// This retains the one-use custody handle inside the prepared token and
    /// assigns no semantic validity itself.
    ///
    /// # Errors
    ///
    /// Refuses a missing/substituted acquisition, replay, or persistence
    /// failure.
    pub fn claim_derivation(&mut self, claim: GovernedDerivationCustodyClaim) -> Result<()> {
        self.live_custody
            .claim_derivation(claim)
            .map_err(Into::into)
    }

    /// Seal exact bytes of a core-validated complete closure.
    ///
    /// The runtime forwards only to the already-owned custody handle. It does
    /// not validate or mint NQ semantics.
    ///
    /// # Errors
    ///
    /// Refuses a missing derivation claim, capacity overflow, malformed store
    /// carrier, replay, or persistence failure.
    pub fn seal_final_closure(
        &mut self,
        exact_closure_bytes: Vec<u8>,
    ) -> Result<GovernedCustodyCommitment> {
        self.live_custody
            .seal_final_closure(exact_closure_bytes)
            .map_err(Into::into)
    }

    /// Reopen exact final-closure bytes without refreshing or interpreting
    /// them.
    ///
    /// # Errors
    ///
    /// Refuses unreadable or corrupt custody.
    pub fn final_closure_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.live_custody.final_closure_bytes().map_err(Into::into)
    }

    /// Terminalize the exact launch using the one-use custody authority owned
    /// by this prepared occurrence.
    ///
    /// A merely reopened custody handle cannot perform this transition. The
    /// method records custody-only failure/refusal material; it does not create
    /// an NQ diagnostic disposition.
    ///
    /// # Errors
    ///
    /// Refuses substitution, invalid ordering/deadline classification, a
    /// nonterminal handle reopened after restart, or persistence failure.
    pub fn terminalize_immediate_launch(
        &mut self,
        input: GovernedProtectedTerminalInput,
    ) -> Result<GovernedProtectedTerminalization> {
        self.require_exact_launch(&input.execution_launch_record_id)?;
        self.live_custody
            .terminalize_immediate_launch(input)
            .map_err(Into::into)
    }
}

pub(crate) fn exact_append_membership(records: &[AppendRecord]) -> Result<Vec<RecordRef>> {
    records.iter().map(exact_append_reference).collect()
}

fn exact_append_reference(record: &AppendRecord) -> Result<RecordRef> {
    let canonical = CanonicalDocument::from_canonical_bytes(record.canonical_bytes.clone())?;
    let value: Value = serde_json::from_slice(canonical.as_bytes())?;
    if value.get("schema").and_then(Value::as_str) != Some(record.record_schema.as_str()) {
        return Err(RuntimeError::LedgerCarrierMismatch("record schema"));
    }
    let record_id = Sha256Digest::parse(record.record_id.clone())
        .map_err(|_| RuntimeError::LedgerCarrierMismatch("record identity"))?;
    match RuntimeSchema::parse(&record.record_schema) {
        Ok(_) => {
            let typed = ValidatedRuntimeRecord::decode_canonical(canonical.as_bytes())?;
            if typed.record_id() != &record_id
                || typed.schema().as_str() != record.record_schema
                || typed.bytes_digest().as_str() != canonical.digest()
            {
                return Err(RuntimeError::LedgerCarrierMismatch(
                    "typed runtime record identity",
                ));
            }
            Ok(typed.exact_reference())
        }
        Err(_) if record.record_schema == PROVIDER_INTAKE_SCHEMA => {
            if !value.is_object() {
                return Err(RuntimeError::InvalidProviderIntakeCarrier);
            }
            Ok(RecordRef {
                schema: Token::parse(PROVIDER_INTAKE_SCHEMA)?,
                record_id,
                bytes_digest: sha256_bytes(canonical.as_bytes()),
            })
        }
        Err(_) => Err(RuntimeError::UnsupportedLedgerSchema(
            record.record_schema.clone(),
        )),
    }
}

fn exact_provider_intake_reference(record: &AppendRecord) -> Result<RecordRef> {
    let reference = exact_append_reference(record)?;
    if reference.schema.as_str() != PROVIDER_INTAKE_SCHEMA {
        return Err(RuntimeError::InvalidProviderIntakeCarrier);
    }
    Ok(reference)
}

fn store_record_input(record: AppendRecord) -> Result<RuntimeRecordInput> {
    Ok(RuntimeRecordInput {
        record_id: record.record_id,
        record_schema: record.record_schema,
        canonical_bytes: CanonicalDocument::from_canonical_bytes(record.canonical_bytes)?,
        committed_at: record.committed_at,
    })
}

fn dependency_input(
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

pub(crate) fn production_identity(
    node: IdentityRef,
    subject: IdentityRef,
    vantage: IdentityRef,
    cohort: IdentityRef,
) -> GovernedProductionIdentity {
    GovernedProductionIdentity {
        node,
        subject,
        vantage,
        cohort,
    }
}
