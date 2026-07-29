//! Opaque exact-byte custody for one governed diagnostic invocation.
//!
//! This module deliberately exposes storage mechanics only. A Store-owned
//! verifier may advance the physical index frontier only after exact arena/SQL
//! correspondence is reopened from a reservation identity. It does not
//! establish native provider correspondence, an evaluator occurrence,
//! diagnostic semantic validity, reliance, or authority; those semantic checks
//! belong to `nq-core` and its consumers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::custody_arena::{
    AcquisitionCarrier, ArenaFailureCarrierCandidate, ArenaInventoryEntry, ArenaLayout,
    ArenaPrelaunchBinding, ArenaState, CustodyArena, DerivationClaim, DerivedV2ClosureCandidate,
    acquisition_carrier_capacity_bound,
};
use crate::{
    CanonicalDocument, DiagnosticArtifactByteState, DiagnosticArtifactLookup,
    DiagnosticArtifactOrigin, MAX_PUBLIC_QUERY_ROWS, RuntimeCheckpointDependencyBinding,
    RuntimeDependencyGenerationByteState, RuntimeLedgerCheckpoint, RuntimeRecordRow, Store,
    StoreError, canonical_document_schema, diagnostic_artifact_execution_binding_on_connection,
    diagnostic_artifact_on_connection, runtime_checkpoint_by_id_on_connection,
    runtime_checkpoint_dependency_on_connection, runtime_record_by_id_on_connection,
    validate_diagnostic_artifact_invariants, validate_provider_intake_invariants,
    validate_runtime_record_ledger,
};

/// Store-internal carrier schema used to keep the exact core-validated closure
/// in a preallocated custody arena.
///
/// This is an on-disk storage format, not an NQ/Nightshift product contract.
/// Its presence alone establishes no diagnostic or reliance semantics.
pub const GOVERNED_CUSTODY_CLOSURE_SCHEMA: &str = "nq.governed_execution_custody_closure.v1";
/// Corrected closure schema that keeps evaluator semantic identity distinct
/// from executable identity and represents clock qualification without a
/// numeric sentinel.
pub const GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA: &str = "nq.governed_execution_custody_closure.v2";

const MAX_GOVERNED_CLOSURE_TEXT_BYTES: usize = 256;

/// One exact immutable runtime-record reference retained by a governed closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedClosureRecordReference {
    pub schema: String,
    pub record_id: Sha256Digest,
    pub bytes_digest: Sha256Digest,
}

impl TryFrom<&RuntimeRecordRow> for GovernedClosureRecordReference {
    type Error = StoreError;

    fn try_from(value: &RuntimeRecordRow) -> Result<Self, Self::Error> {
        Ok(Self {
            schema: value.record_schema.clone(),
            record_id: Sha256Digest::parse(value.record_id.clone()).map_err(|error| {
                StoreError::Integrity(format!(
                    "runtime record {} has invalid semantic identity: {error}",
                    value.record_id
                ))
            })?,
            bytes_digest: value.canonical_bytes_sha256.clone(),
        })
    }
}

/// Exact checkpoint identity and complete ordered membership retained by a
/// governed closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedClosureCheckpointInput {
    pub checkpoint_id: Sha256Digest,
    pub batch_digest: Sha256Digest,
    pub runtime_records: Vec<GovernedClosureRecordReference>,
}

/// Exact prelaunch records and checkpoint frontiers retained by a governed
/// closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedClosurePrelaunchInput {
    pub outer_request: GovernedClosureRecordReference,
    pub invocation_decision: GovernedClosureRecordReference,
    pub reservation_checkpoint: GovernedClosureCheckpointInput,
    pub launch_checkpoint: GovernedClosureCheckpointInput,
}

/// Exact provider occurrence retained by a governed closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedClosureAcquisitionInput {
    pub execution_launch_record_id: Sha256Digest,
    pub provider_intake: GovernedClosureRecordReference,
    pub intake_id: String,
    pub raw_provider_bytes_digest: Sha256Digest,
}

/// Exact derivation-custody correspondence retained by a V2 closure.
///
/// These are storage identities. Their presence does not establish that the
/// evaluator ran or that its diagnostic conclusion is valid.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedClosureDerivationInput {
    pub derivation_id: Sha256Digest,
    pub dependency_generation_id: Sha256Digest,
    pub dependency_generation_custody_digest: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub evaluation_id: Option<String>,
    pub profile_semantic_id: Sha256Digest,
    pub evaluator_semantic_digest: Sha256Digest,
    pub evaluator_artifact_digest: Sha256Digest,
    pub derived_at: String,
    pub clock_identity: Sha256Digest,
    pub clock_qualification_digest: Sha256Digest,
}

/// Exact local SQL origin retained by a governed closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedClosureLocalOriginInput {
    pub run_id: String,
    pub evaluation_id: Option<String>,
    pub completed_at: String,
}

/// Exact authenticated dependency generation retained by a governed closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedClosureDependencyGenerationInput {
    pub checkpoint_id: Sha256Digest,
    pub checkpoint_digest: Sha256Digest,
    pub generation_id: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub custody_bytes_digest: Sha256Digest,
}

/// Complete storage-only input for one exact V2 custody closure.
///
/// NQ core remains responsible for validating the diagnostic and every native
/// semantic correspondence before asking Store to encode this carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedExecutionCustodyClosureV2Input {
    pub reservation: GovernedClosureRecordReference,
    pub prelaunch: GovernedClosurePrelaunchInput,
    pub acquisition: GovernedClosureAcquisitionInput,
    pub derivation: GovernedClosureDerivationInput,
    pub diagnostic: CanonicalDocument,
    /// Exact pre-effect diagnostic component bound from the custody
    /// reservation. This governs encoding but is not duplicated into the
    /// closure schema.
    pub diagnostic_artifact_capacity_bytes: u64,
    pub local_origin: GovernedClosureLocalOriginInput,
    pub execution_binding: GovernedClosureRecordReference,
    pub runtime_records: Vec<GovernedClosureRecordReference>,
    pub dependency_generation: GovernedClosureDependencyGenerationInput,
}

/// Planned immutable inputs used to size one V2 closure before physical
/// reservation or provider effect.
///
/// The runtime supplies the exact record references and checkpoint membership
/// it has already encoded for its planned atomic appends. This function does
/// not inspect mutable Store state or establish that those appends occurred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedExecutionCustodyClosureV2CapacityInput {
    pub reservation: GovernedClosureRecordReference,
    pub prelaunch: GovernedClosurePrelaunchInput,
    pub execution_launch_record_id: Sha256Digest,
    pub dependency_generation_id: Sha256Digest,
    pub dependency_generation_custody_digest: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub diagnostic_artifact_capacity_bytes: u64,
}

/// Separate diagnostic and final-carrier bounds for one planned V2 closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedExecutionCustodyClosureV2Capacity {
    pub diagnostic_artifact_capacity_bytes: u64,
    pub final_closure_capacity_bytes: u64,
}

/// Encode a conservative final-carrier bound from exact planned prelaunch
/// membership without consulting Store state.
///
/// This is a sizing result, not proof that the planned checkpoints committed
/// or that a diagnostic execution is semantically valid.
pub fn governed_execution_custody_closure_v2_capacity_bound(
    input: &GovernedExecutionCustodyClosureV2CapacityInput,
) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> {
    if input.diagnostic_artifact_capacity_bytes == 0 {
        return Err(StoreError::Invariant(
            "maximum diagnostic canonical length must be positive".into(),
        ));
    }
    validate_governed_closure_v2_prelaunch(
        &input.reservation,
        &input.prelaunch,
        &input.execution_launch_record_id,
    )?;
    let final_closure_capacity_bytes = governed_closure_v2_capacity_bound_from_exact_prelaunch(
        input.reservation.clone(),
        input.prelaunch.clone(),
        input.execution_launch_record_id.clone(),
        &input.dependency_generation_id,
        &input.dependency_generation_custody_digest,
        &input.trust_anchor_id,
        input.diagnostic_artifact_capacity_bytes,
    )?;
    Ok(GovernedExecutionCustodyClosureV2Capacity {
        diagnostic_artifact_capacity_bytes: input.diagnostic_artifact_capacity_bytes,
        final_closure_capacity_bytes,
    })
}

#[derive(Serialize)]
struct GovernedExecutionCustodyClosureV2Preimage {
    schema: &'static str,
    reservation: GovernedClosureRecordReference,
    prelaunch: GovernedClosurePrelaunchInput,
    acquisition: GovernedClosureAcquisitionInput,
    derivation: GovernedClosureDerivationInput,
    diagnostic: Value,
    local_origin: GovernedClosureLocalOriginInput,
    execution_binding: GovernedClosureRecordReference,
    runtime_records: Vec<GovernedClosureRecordReference>,
    dependency_generation: GovernedClosureDependencyGenerationInput,
}

#[derive(Serialize)]
struct GovernedExecutionCustodyClosureV2Document {
    schema: &'static str,
    closure_id: Sha256Digest,
    reservation: GovernedClosureRecordReference,
    prelaunch: GovernedClosurePrelaunchInput,
    acquisition: GovernedClosureAcquisitionInput,
    derivation: GovernedClosureDerivationInput,
    diagnostic: Value,
    local_origin: GovernedClosureLocalOriginInput,
    execution_binding: GovernedClosureRecordReference,
    runtime_records: Vec<GovernedClosureRecordReference>,
    dependency_generation: GovernedClosureDependencyGenerationInput,
}

/// Exact canonical V2 custody closure produced by the Store-owned encoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedExecutionCustodyClosureV2 {
    closure_id: Sha256Digest,
    canonical_bytes: CanonicalDocument,
}

impl GovernedExecutionCustodyClosureV2 {
    /// Build one exact storage carrier and derive its semantic self-identity.
    ///
    /// This checks only closed storage shape and correspondence. It does not
    /// validate or assign diagnostic standing.
    pub fn build(input: GovernedExecutionCustodyClosureV2Input) -> Result<Self, StoreError> {
        validate_governed_closure_v2_input(&input)?;
        let diagnostic: Value =
            serde_json::from_slice(input.diagnostic.as_bytes()).map_err(|error| {
                StoreError::CanonicalJson(format!(
                    "governed V2 diagnostic cannot be decoded: {error}"
                ))
            })?;
        let preimage = GovernedExecutionCustodyClosureV2Preimage {
            schema: GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA,
            reservation: input.reservation,
            prelaunch: input.prelaunch,
            acquisition: input.acquisition,
            derivation: input.derivation,
            diagnostic,
            local_origin: input.local_origin,
            execution_binding: input.execution_binding,
            runtime_records: input.runtime_records,
            dependency_generation: input.dependency_generation,
        };
        let closure_id = semantic_digest(&preimage).map_err(|error| {
            StoreError::Invariant(format!(
                "governed V2 closure identity cannot be derived: {error}"
            ))
        })?;
        let document = GovernedExecutionCustodyClosureV2Document {
            schema: preimage.schema,
            closure_id: closure_id.clone(),
            reservation: preimage.reservation,
            prelaunch: preimage.prelaunch,
            acquisition: preimage.acquisition,
            derivation: preimage.derivation,
            diagnostic: preimage.diagnostic,
            local_origin: preimage.local_origin,
            execution_binding: preimage.execution_binding,
            runtime_records: preimage.runtime_records,
            dependency_generation: preimage.dependency_generation,
        };
        let canonical_bytes = CanonicalDocument::from_serializable(&document)?;
        Ok(Self {
            closure_id,
            canonical_bytes,
        })
    }

    #[must_use]
    pub const fn closure_id(&self) -> &Sha256Digest {
        &self.closure_id
    }

    #[must_use]
    pub const fn canonical_bytes(&self) -> &CanonicalDocument {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn into_canonical_bytes(self) -> CanonicalDocument {
        self.canonical_bytes
    }
}

fn validate_governed_closure_v2_text(label: &str, value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > MAX_GOVERNED_CLOSURE_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::Invariant(format!(
            "governed V2 closure {label} must contain 1..=256 non-control bytes"
        )));
    }
    Ok(())
}

fn validate_governed_closure_v2_prelaunch(
    reservation: &GovernedClosureRecordReference,
    prelaunch: &GovernedClosurePrelaunchInput,
    execution_launch_record_id: &Sha256Digest,
) -> Result<(), StoreError> {
    for (label, reference, schema) in [
        ("reservation", reservation, "nq.custody_reservation.v1"),
        (
            "outer request",
            &prelaunch.outer_request,
            "nq.diagnostic_invocation_request.v1",
        ),
        (
            "invocation decision",
            &prelaunch.invocation_decision,
            "nq.invocation_decision.v1",
        ),
    ] {
        if reference.schema != schema {
            return Err(StoreError::Invariant(format!(
                "governed V2 closure {label} has incompatible schema"
            )));
        }
    }
    if prelaunch.reservation_checkpoint.runtime_records.is_empty()
        || prelaunch.launch_checkpoint.runtime_records.is_empty()
    {
        return Err(StoreError::Invariant(
            "governed V2 closure prelaunch checkpoint is empty".into(),
        ));
    }
    let unique_exact = |records: &[GovernedClosureRecordReference],
                        expected: &GovernedClosureRecordReference| {
        records.iter().filter(|record| *record == expected).count() == 1
    };
    let unique_schema = |records: &[GovernedClosureRecordReference], schema: &str| {
        records
            .iter()
            .filter(|record| record.schema == schema)
            .count()
            == 1
    };
    if !unique_exact(
        &prelaunch.reservation_checkpoint.runtime_records,
        reservation,
    ) || !unique_exact(
        &prelaunch.reservation_checkpoint.runtime_records,
        &prelaunch.outer_request,
    ) || !unique_exact(
        &prelaunch.reservation_checkpoint.runtime_records,
        &prelaunch.invocation_decision,
    ) || !unique_schema(
        &prelaunch.reservation_checkpoint.runtime_records,
        "nq.custody_reservation.v1",
    ) || !unique_schema(
        &prelaunch.reservation_checkpoint.runtime_records,
        "nq.diagnostic_invocation_request.v1",
    ) || !unique_schema(
        &prelaunch.reservation_checkpoint.runtime_records,
        "nq.invocation_decision.v1",
    ) {
        return Err(StoreError::Invariant(
            "governed V2 closure omits or duplicates an exact prelaunch storage reference".into(),
        ));
    }
    let launch_records = prelaunch
        .launch_checkpoint
        .runtime_records
        .iter()
        .filter(|record| record.schema == "nq.execution_launch.v1")
        .collect::<Vec<_>>();
    let [launch] = launch_records.as_slice() else {
        return Err(StoreError::Invariant(
            "governed V2 closure requires exactly one execution launch".into(),
        ));
    };
    let deadline_count = prelaunch
        .launch_checkpoint
        .runtime_records
        .iter()
        .filter(|record| record.schema == "nq.deadline_evaluation.v1")
        .count();
    if !matches!(
        (
            prelaunch.launch_checkpoint.runtime_records.len(),
            deadline_count
        ),
        (1, 0) | (2, 1)
    ) {
        return Err(StoreError::Invariant(
            "governed V2 closure launch checkpoint requires one legacy launch or one deadline-plus-launch pair"
                .into(),
        ));
    }
    if launch.record_id != *execution_launch_record_id {
        return Err(StoreError::Invariant(
            "governed V2 closure execution launch identity does not join exactly".into(),
        ));
    }
    Ok(())
}

fn validate_governed_closure_v2_input(
    input: &GovernedExecutionCustodyClosureV2Input,
) -> Result<(), StoreError> {
    validate_governed_closure_v2_prelaunch(
        &input.reservation,
        &input.prelaunch,
        &input.acquisition.execution_launch_record_id,
    )?;
    for (label, reference, schema) in [
        (
            "provider intake",
            &input.acquisition.provider_intake,
            "nq.provider_intake.v1",
        ),
        (
            "execution binding",
            &input.execution_binding,
            "nq.execution_identity_binding.v2",
        ),
    ] {
        if reference.schema != schema {
            return Err(StoreError::Invariant(format!(
                "governed V2 closure {label} has incompatible schema"
            )));
        }
    }
    for (label, value) in [
        ("intake identity", input.acquisition.intake_id.as_str()),
        ("derivation time", input.derivation.derived_at.as_str()),
        ("run identity", input.local_origin.run_id.as_str()),
        ("completion time", input.local_origin.completed_at.as_str()),
    ] {
        validate_governed_closure_v2_text(label, value)?;
    }
    if let Some(evaluation_id) = &input.derivation.evaluation_id {
        validate_governed_closure_v2_text("derivation evaluation identity", evaluation_id)?;
    }
    if let Some(evaluation_id) = &input.local_origin.evaluation_id {
        validate_governed_closure_v2_text("local evaluation identity", evaluation_id)?;
    }
    let diagnostic_schema = canonical_document_schema(&input.diagnostic)?;
    if diagnostic_schema != "nq.diagnostic_execution.v2" {
        return Err(StoreError::Invariant(
            "governed V2 closure requires exact diagnostic_execution.v2 bytes".into(),
        ));
    }
    let diagnostic_length = u64::try_from(input.diagnostic.as_bytes().len()).map_err(|_| {
        StoreError::Invariant("governed V2 diagnostic length exceeds address space".into())
    })?;
    if input.diagnostic_artifact_capacity_bytes == 0
        || diagnostic_length > input.diagnostic_artifact_capacity_bytes
    {
        return Err(StoreError::Invariant(
            "governed V2 diagnostic exceeds its pre-effect component bound".into(),
        ));
    }
    if input.runtime_records.is_empty() {
        return Err(StoreError::Invariant(
            "governed V2 closure terminal write set is empty".into(),
        ));
    }
    let unique_exact = |records: &[GovernedClosureRecordReference],
                        expected: &GovernedClosureRecordReference| {
        records.iter().filter(|record| *record == expected).count() == 1
    };
    if !unique_exact(&input.runtime_records, &input.execution_binding)
        || !unique_exact(&input.runtime_records, &input.acquisition.provider_intake)
    {
        return Err(StoreError::Invariant(
            "governed V2 closure omits or duplicates an exact storage reference".into(),
        ));
    }
    if input.runtime_records.len() != 2 {
        return Err(StoreError::Invariant(
            "governed V2 closure terminal write set must contain exactly provider intake and execution binding"
                .into(),
        ));
    }
    if input.derivation.dependency_generation_id != input.dependency_generation.generation_id
        || input.derivation.dependency_generation_custody_digest
            != input.dependency_generation.custody_bytes_digest
        || input.derivation.trust_anchor_id != input.dependency_generation.trust_anchor_id
        || input.derivation.evaluation_id != input.local_origin.evaluation_id
        || input.derivation.derived_at != input.local_origin.completed_at
    {
        return Err(StoreError::Invariant(
            "governed V2 closure storage identities do not join exactly".into(),
        ));
    }
    Ok(())
}

/// Canonical store-owned terminal carrier for one launched occurrence that
/// cannot reach a complete V2 closure.
///
/// The document records a custody terminal, not a diagnostic disposition,
/// reliance decision, authorization, or action result.
pub const GOVERNED_PROTECTED_TERMINAL_SCHEMA: &str = "nq.governed_protected_terminal.v1";

/// Return the exact arena payload capacity required to encode the two supplied
/// opaque acquisition maxima.
///
/// The result includes the acquisition carrier's eight-byte framing length and
/// its canonical typed header. It deliberately does not guess either payload
/// bound and does not include the arena section's separately allocated physical
/// header.
pub fn governed_acquisition_capacity_bound(
    max_provider_intake_bytes: u64,
    max_raw_bytes: u64,
) -> Result<u64, StoreError> {
    acquisition_carrier_capacity_bound(max_provider_intake_bytes, max_raw_bytes)
        .map_err(custody_error)
}

/// Exact immutable identity and capacity bound established before launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCustodyReservation {
    pub reservation_record_id: Sha256Digest,
    pub reservation_manifest_digest: Sha256Digest,
    pub outer_request_record_id: Sha256Digest,
    pub outer_request_id: String,
    pub outer_request_digest: Sha256Digest,
    pub dependency_generation_id: Sha256Digest,
    pub dependency_generation_custody_digest: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub prelaunch_checkpoint_id: Sha256Digest,
    pub prelaunch_checkpoint_digest: Sha256Digest,
    pub dependency_closure_capacity_bytes: u64,
    pub raw_capacity_bytes: u64,
    /// Pre-effect maximum canonical diagnostic bytes used to size this
    /// occurrence.
    ///
    /// This remains separate from the larger final-closure carrier partition:
    /// callers must account for both the artifact and its storage envelope.
    /// The exact custody-reservation record binds this policy value; the arena
    /// stores only that record's digest and does not independently reinterpret
    /// the sizing policy.
    pub diagnostic_artifact_capacity_bytes: u64,
    pub final_capacity_bytes: u64,
    pub protected_failure_capacity_bytes: u64,
}

impl GovernedCustodyReservation {
    fn prelaunch(&self) -> ArenaPrelaunchBinding {
        ArenaPrelaunchBinding {
            reservation_record_id: self.reservation_record_id.clone(),
            reservation_manifest_digest: self.reservation_manifest_digest.clone(),
            outer_request_record_id: self.outer_request_record_id.clone(),
            outer_request_id: self.outer_request_id.clone(),
            outer_request_digest: self.outer_request_digest.clone(),
            dependency_generation_id: self.dependency_generation_id.clone(),
            dependency_generation_custody_digest: self.dependency_generation_custody_digest.clone(),
            trust_anchor_id: self.trust_anchor_id.clone(),
            prelaunch_checkpoint_id: self.prelaunch_checkpoint_id.clone(),
            prelaunch_checkpoint_digest: self.prelaunch_checkpoint_digest.clone(),
        }
    }

    fn layout(&self) -> Result<ArenaLayout, StoreError> {
        if self.diagnostic_artifact_capacity_bytes == 0 {
            return Err(StoreError::Invariant(
                "governed custody diagnostic artifact capacity must be positive".into(),
            ));
        }
        ArenaLayout::new(
            self.dependency_closure_capacity_bytes,
            self.raw_capacity_bytes,
            self.final_capacity_bytes,
            self.protected_failure_capacity_bytes,
        )
        .map_err(custody_error)
    }
}

/// Public storage state for one arena.
///
/// These are custody states, not diagnostic outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedCustodyState {
    Reserved,
    LaunchClaimed,
    AcquisitionSealed,
    DerivationClaimed,
    FinalClosureIndexPending,
    FinalClosureIndexed,
    FailedIndeterminate,
    ExpiredUnlaunched,
}

impl From<ArenaState> for GovernedCustodyState {
    fn from(value: ArenaState) -> Self {
        match value {
            ArenaState::Reserved => Self::Reserved,
            ArenaState::Claimed => Self::LaunchClaimed,
            ArenaState::RawEvidenceSealed => Self::AcquisitionSealed,
            ArenaState::DerivationClaimed => Self::DerivationClaimed,
            ArenaState::FinalV2SealedIndexPending => Self::FinalClosureIndexPending,
            ArenaState::FinalV2SealedIndexed => Self::FinalClosureIndexed,
            ArenaState::FailedIndeterminate => Self::FailedIndeterminate,
            ArenaState::ExpiredUnlaunched => Self::ExpiredUnlaunched,
        }
    }
}

/// Restart classification of one exact physical custody frontier.
///
/// This is a storage/recovery classification only. It is not a diagnostic
/// result and grants no right to rerun a provider or evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedCustodyRecoveryClass {
    /// Physical capacity exists, but the arena has no physical launch claim.
    ///
    /// This alone does not say whether a SQLite launch record exists; the
    /// future Store-owned launch/index join remains a separate obligation.
    ReservationWithoutPhysicalLaunchClaim,
    /// A launch was durably claimed, but no provider occurrence was sealed.
    LaunchedWithoutAcquisition,
    /// Provider bytes are sealed and may be reopened without reacquisition.
    AcquisitionAwaitingDerivation,
    /// A derivation claim exists without a final closure; it must not mint a
    /// second evaluation occurrence.
    DerivationWithoutFinalClosure,
    /// Exact final bytes exist, but their SQLite projection has not been
    /// independently verified.
    FinalClosureAwaitingProjection,
    /// Exact final bytes reached the projection-verified frontier.
    ///
    /// This physical state bit records the completed transition; it is not a
    /// current integrity oracle. Readers that need present correspondence must
    /// rerun the reservation-only verifier, especially after later SQL
    /// corruption.
    Indexed,
    /// One exact protected failure carrier terminalized the invocation.
    ProtectedFailure,
    /// An unlaunched reservation was terminally expired.
    ExpiredUnlaunched,
}

impl From<ArenaState> for GovernedCustodyRecoveryClass {
    fn from(value: ArenaState) -> Self {
        match value {
            ArenaState::Reserved => Self::ReservationWithoutPhysicalLaunchClaim,
            ArenaState::Claimed => Self::LaunchedWithoutAcquisition,
            ArenaState::RawEvidenceSealed => Self::AcquisitionAwaitingDerivation,
            ArenaState::DerivationClaimed => Self::DerivationWithoutFinalClosure,
            ArenaState::FinalV2SealedIndexPending => Self::FinalClosureAwaitingProjection,
            ArenaState::FinalV2SealedIndexed => Self::Indexed,
            ArenaState::FailedIndeterminate => Self::ProtectedFailure,
            ArenaState::ExpiredUnlaunched => Self::ExpiredUnlaunched,
        }
    }
}

/// Exact relationship between one physical arena and the immutable runtime
/// ledger's custody-reservation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedCustodyReservationLedgerBinding {
    Exact,
    NoCommittedReservation,
    ReservationDigestMismatch {
        ledger_digest: Sha256Digest,
        arena_digest: Sha256Digest,
    },
}

/// Verified physical state of one durable governed-custody arena.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCustodyInspection {
    pub relative_path: PathBuf,
    pub reservation_record_id: Sha256Digest,
    pub reservation_manifest_digest: Sha256Digest,
    pub reservation_ledger_binding: GovernedCustodyReservationLedgerBinding,
    pub outer_request_record_id: Sha256Digest,
    pub outer_request_id: String,
    pub dependency_generation_id: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub state: GovernedCustodyState,
    pub recovery_class: GovernedCustodyRecoveryClass,
    pub arena_sequence: u64,
    pub execution_launch_record_id: Option<Sha256Digest>,
    pub final_closure: Option<GovernedCustodyCommitment>,
    pub protected_failure: Option<GovernedCustodyCommitment>,
    pub recovered_torn_superblock: bool,
}

/// One entry discovered in the database-owned custody directory.
///
/// Unreadable entries remain visible. They are not silently dropped and do
/// not become a diagnostic conclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedCustodyInventoryEntry {
    Verified(Box<GovernedCustodyInspection>),
    MissingForCommittedReservation {
        reservation_record_id: Sha256Digest,
        reservation_manifest_digest: Sha256Digest,
    },
    Unreadable {
        relative_path: PathBuf,
        reason: String,
    },
}

/// Exact protected-failure bytes from one terminal custody arena.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProtectedFailure {
    pub reservation_record_id: Sha256Digest,
    pub bytes_digest: Sha256Digest,
    pub exact_bytes: Vec<u8>,
}

/// Orthogonal arena/failure availability for one protected-failure read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedProtectedFailureAccess {
    ArenaMissing,
    NotPresent { arena_state: GovernedCustodyState },
    VerifiedAvailable(GovernedProtectedFailure),
}

/// Why a launched occurrence ended without a complete V2 closure.
///
/// These remain separate custody-terminal classes. Neither is a diagnostic
/// outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProtectedTerminalClass {
    /// Core refused before any provider effect was permitted.
    PreEffectRefusal,
    /// A postlaunch failure prevented complete V2 closure.
    PostlaunchFailure,
}

/// The exact deadline assessment supplied at terminalization time.
///
/// `NotEstablished` is a first-class result. Reopening this carrier never
/// recomputes or refreshes the assessment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProtectedTerminalDeadlineCompliance {
    WithinDeadline,
    DeadlineReachedOrExceeded,
    NotEstablished,
}

/// Exact typed reason retained inside one custody terminal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProtectedTerminalReason {
    pub code: String,
    pub detail: String,
}

/// Caller-supplied occurrence facts for immediate terminalization.
///
/// Reservation and request identities are not caller fields; the custody
/// handle supplies them from its immutable prelaunch binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProtectedTerminalInput {
    pub execution_launch_record_id: Sha256Digest,
    pub terminal_class: GovernedProtectedTerminalClass,
    pub reason: GovernedProtectedTerminalReason,
    pub launch_attempt_deadline: String,
    pub terminalized_at: String,
    pub deadline_compliance: GovernedProtectedTerminalDeadlineCompliance,
}

/// Exact reservation identity retained by a protected terminal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProtectedTerminalReservation {
    pub record_id: Sha256Digest,
    pub manifest_digest: Sha256Digest,
}

/// Exact outer-request identity retained by a protected terminal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProtectedTerminalRequest {
    pub record_id: Sha256Digest,
    pub request_id: String,
    pub bytes_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GovernedProtectedTerminalMode {
    ImmediateOwnedLaunch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GovernedProtectedTerminalStanding {
    CustodyOnly,
}

/// Typed canonical document committed to the protected-failure arena.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProtectedTerminalDocument {
    pub schema: String,
    pub terminal_id: Sha256Digest,
    pub reservation: GovernedProtectedTerminalReservation,
    pub outer_request: GovernedProtectedTerminalRequest,
    pub execution_launch_record_id: Sha256Digest,
    pub launch_claimed_at: String,
    terminalization_mode: GovernedProtectedTerminalMode,
    pub terminal_class: GovernedProtectedTerminalClass,
    pub reason: GovernedProtectedTerminalReason,
    pub launch_attempt_deadline: String,
    pub terminalized_at: String,
    pub deadline_compliance: GovernedProtectedTerminalDeadlineCompliance,
    standing: GovernedProtectedTerminalStanding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct GovernedProtectedTerminalPreimage {
    schema: String,
    reservation: GovernedProtectedTerminalReservation,
    outer_request: GovernedProtectedTerminalRequest,
    execution_launch_record_id: Sha256Digest,
    launch_claimed_at: String,
    terminalization_mode: GovernedProtectedTerminalMode,
    terminal_class: GovernedProtectedTerminalClass,
    reason: GovernedProtectedTerminalReason,
    launch_attempt_deadline: String,
    terminalized_at: String,
    deadline_compliance: GovernedProtectedTerminalDeadlineCompliance,
    standing: GovernedProtectedTerminalStanding,
}

/// Canonical self-identified protected terminal and its exact committed bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProtectedTerminal {
    document: GovernedProtectedTerminalDocument,
    exact_bytes: Vec<u8>,
}

impl GovernedProtectedTerminal {
    fn create(
        reservation: &GovernedCustodyReservation,
        launch_claimed_at: String,
        input: GovernedProtectedTerminalInput,
    ) -> Result<Self, StoreError> {
        validate_terminal_reason(&input.reason)?;
        validate_terminal_times(
            &launch_claimed_at,
            &input.launch_attempt_deadline,
            &input.terminalized_at,
            input.deadline_compliance,
        )?;
        let preimage = GovernedProtectedTerminalPreimage {
            schema: GOVERNED_PROTECTED_TERMINAL_SCHEMA.to_owned(),
            reservation: GovernedProtectedTerminalReservation {
                record_id: reservation.reservation_record_id.clone(),
                manifest_digest: reservation.reservation_manifest_digest.clone(),
            },
            outer_request: GovernedProtectedTerminalRequest {
                record_id: reservation.outer_request_record_id.clone(),
                request_id: reservation.outer_request_id.clone(),
                bytes_digest: reservation.outer_request_digest.clone(),
            },
            execution_launch_record_id: input.execution_launch_record_id,
            launch_claimed_at,
            terminalization_mode: GovernedProtectedTerminalMode::ImmediateOwnedLaunch,
            terminal_class: input.terminal_class,
            reason: input.reason,
            launch_attempt_deadline: input.launch_attempt_deadline,
            terminalized_at: input.terminalized_at,
            deadline_compliance: input.deadline_compliance,
            standing: GovernedProtectedTerminalStanding::CustodyOnly,
        };
        let terminal_id = semantic_digest(&preimage).map_err(|error| {
            StoreError::Invariant(format!(
                "protected terminal identity cannot be derived: {error}"
            ))
        })?;
        let document = GovernedProtectedTerminalDocument {
            schema: preimage.schema,
            terminal_id,
            reservation: preimage.reservation,
            outer_request: preimage.outer_request,
            execution_launch_record_id: preimage.execution_launch_record_id,
            launch_claimed_at: preimage.launch_claimed_at,
            terminalization_mode: preimage.terminalization_mode,
            terminal_class: preimage.terminal_class,
            reason: preimage.reason,
            launch_attempt_deadline: preimage.launch_attempt_deadline,
            terminalized_at: preimage.terminalized_at,
            deadline_compliance: preimage.deadline_compliance,
            standing: preimage.standing,
        };
        let exact_bytes = canonical_json_bytes(&document).map_err(|error| {
            StoreError::Invariant(format!("protected terminal cannot be encoded: {error}"))
        })?;
        Self::from_exact_bytes(exact_bytes)
    }

    /// Reopen one exact canonical protected terminal without refreshing its
    /// deadline assessment or assigning diagnostic standing.
    pub fn from_exact_bytes(exact_bytes: Vec<u8>) -> Result<Self, StoreError> {
        let document: GovernedProtectedTerminalDocument = serde_json::from_slice(&exact_bytes)
            .map_err(|error| {
                StoreError::Invariant(format!("protected terminal cannot be decoded: {error}"))
            })?;
        if document.schema != GOVERNED_PROTECTED_TERMINAL_SCHEMA
            || document.terminalization_mode != GovernedProtectedTerminalMode::ImmediateOwnedLaunch
            || document.standing != GovernedProtectedTerminalStanding::CustodyOnly
            || canonical_json_bytes(&document).map_err(|error| {
                StoreError::Invariant(format!(
                    "protected terminal cannot be canonicalized: {error}"
                ))
            })? != exact_bytes
        {
            return Err(StoreError::Invariant(
                "protected terminal schema, mode, standing, or canonical bytes differ".into(),
            ));
        }
        validate_terminal_reason(&document.reason)?;
        validate_terminal_times(
            &document.launch_claimed_at,
            &document.launch_attempt_deadline,
            &document.terminalized_at,
            document.deadline_compliance,
        )?;
        let preimage = GovernedProtectedTerminalPreimage {
            schema: document.schema.clone(),
            reservation: document.reservation.clone(),
            outer_request: document.outer_request.clone(),
            execution_launch_record_id: document.execution_launch_record_id.clone(),
            launch_claimed_at: document.launch_claimed_at.clone(),
            terminalization_mode: document.terminalization_mode,
            terminal_class: document.terminal_class,
            reason: document.reason.clone(),
            launch_attempt_deadline: document.launch_attempt_deadline.clone(),
            terminalized_at: document.terminalized_at.clone(),
            deadline_compliance: document.deadline_compliance,
            standing: document.standing,
        };
        let expected_id = semantic_digest(&preimage).map_err(|error| {
            StoreError::Invariant(format!(
                "protected terminal identity cannot be reopened: {error}"
            ))
        })?;
        if expected_id != document.terminal_id {
            return Err(StoreError::Invariant(
                "protected terminal identity differs from its exact preimage".into(),
            ));
        }
        Ok(Self {
            document,
            exact_bytes,
        })
    }

    /// Return the typed immutable document.
    #[must_use]
    pub const fn document(&self) -> &GovernedProtectedTerminalDocument {
        &self.document
    }

    /// Return the exact canonical bytes committed to protected custody.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

/// Whether an immediate terminalization wrote once or reopened the exact same
/// already-terminal carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedProtectedTerminalDisposition {
    Terminalized,
    AlreadyTerminalized,
}

/// Result of immediate protected terminalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProtectedTerminalization {
    pub disposition: GovernedProtectedTerminalDisposition,
    pub terminal: GovernedProtectedTerminal,
    pub commitment: GovernedCustodyCommitment,
}

/// Result of comparing one sealed governed closure with the store's exact
/// committed SQL projection.
///
/// This is a storage-correspondence result only. It does not establish that
/// NQ core produced a semantically valid diagnostic, that a consumer may rely
/// on it, or that any action is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProjectionVerification {
    pub reservation_record_id: Sha256Digest,
    pub closure_id: Sha256Digest,
    pub diagnostic_artifact_id: Sha256Digest,
    pub runtime_checkpoint_id: Sha256Digest,
    pub disposition: GovernedProjectionVerificationDisposition,
}

/// Whether exact projection verification advanced the physical frontier or
/// idempotently reverified an already-indexed frontier.
///
/// Neither disposition assigns provider, diagnostic, reliance, or authority
/// semantics. Public callers can assemble matching storage projections; native
/// semantic correspondence remains an independent NQ-core obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedProjectionVerificationDisposition {
    Indexed,
    AlreadyIndexed,
}

/// Exact opaque provider occurrence bytes reopened from durable custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodiedAcquisition {
    pub execution_launch_record_id: Sha256Digest,
    pub provider_intake_record_id: Sha256Digest,
    pub exact_provider_intake_bytes: Vec<u8>,
    pub exact_raw_provider_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ExactRuntimeRecordReference {
    schema: String,
    record_id: Sha256Digest,
    bytes_digest: Sha256Digest,
}

impl ExactRuntimeRecordReference {
    fn matches(&self, record: &RuntimeRecordRow) -> bool {
        self.schema == record.record_schema
            && self.record_id.as_str() == record.record_id
            && self.bytes_digest == record.canonical_bytes_sha256
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionAcquisition {
    execution_launch_record_id: Sha256Digest,
    provider_intake: ExactRuntimeRecordReference,
    intake_id: String,
    raw_provider_bytes_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionLocalOrigin {
    run_id: String,
    evaluation_id: Option<String>,
    completed_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionCheckpoint {
    checkpoint_id: Sha256Digest,
    batch_digest: Sha256Digest,
    runtime_records: Vec<ExactRuntimeRecordReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionPrelaunch {
    outer_request: ExactRuntimeRecordReference,
    invocation_decision: ExactRuntimeRecordReference,
    reservation_checkpoint: GovernedProjectionCheckpoint,
    launch_checkpoint: GovernedProjectionCheckpoint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionDerivation {
    derivation_id: Sha256Digest,
    dependency_generation_id: Sha256Digest,
    dependency_generation_custody_digest: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    evaluation_id: Option<String>,
    profile_semantic_id: Sha256Digest,
    #[serde(default)]
    evaluator_semantic_digest: Option<Sha256Digest>,
    evaluator_artifact_digest: Sha256Digest,
    derived_at: String,
    clock_identity: Sha256Digest,
    #[serde(default)]
    clock_uncertainty_ms: Option<u64>,
    #[serde(default)]
    clock_qualification_digest: Option<Sha256Digest>,
}

impl GovernedProjectionDerivation {
    fn matches(&self, claim: &DerivationClaim) -> bool {
        self.derivation_id == claim.derivation_id
            && self.dependency_generation_id == claim.dependency_generation_id
            && self.dependency_generation_custody_digest
                == claim.dependency_generation_custody_digest
            && self.trust_anchor_id == claim.trust_anchor_id
            && self.evaluation_id == claim.evaluation_id
            && self.profile_semantic_id == claim.profile_semantic_id
            && self.evaluator_semantic_digest == claim.evaluator_semantic_digest
            && self.evaluator_artifact_digest == claim.evaluator_artifact_digest
            && self.derived_at == claim.derived_at
            && self.clock_identity == claim.clock_identity
            && self.clock_uncertainty_ms == claim.clock_uncertainty_ms
            && self.clock_qualification_digest == claim.clock_qualification_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionDependencyGeneration {
    checkpoint_id: Sha256Digest,
    checkpoint_digest: Sha256Digest,
    generation_id: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    custody_bytes_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct GovernedProjectionClosure {
    schema: String,
    closure_id: Sha256Digest,
    reservation: ExactRuntimeRecordReference,
    prelaunch: GovernedProjectionPrelaunch,
    acquisition: GovernedProjectionAcquisition,
    derivation: GovernedProjectionDerivation,
    diagnostic: Value,
    local_origin: GovernedProjectionLocalOrigin,
    execution_binding: ExactRuntimeRecordReference,
    runtime_records: Vec<ExactRuntimeRecordReference>,
    dependency_generation: GovernedProjectionDependencyGeneration,
}

impl From<&AcquisitionCarrier> for CustodiedAcquisition {
    fn from(value: &AcquisitionCarrier) -> Self {
        Self {
            execution_launch_record_id: value.execution_launch_record_id.clone(),
            provider_intake_record_id: value.provider_intake_record_id.clone(),
            exact_provider_intake_bytes: value.exact_provider_intake_bytes.clone(),
            exact_raw_provider_bytes: value.exact_raw_provider_bytes.clone(),
        }
    }
}

/// Exact opaque acquisition bytes supplied only after the real provider
/// occurrence has completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedAcquisitionCustodyInput {
    pub execution_launch_record_id: Sha256Digest,
    pub provider_intake_record_id: Sha256Digest,
    pub exact_provider_intake_bytes: Vec<u8>,
    pub exact_raw_provider_bytes: Vec<u8>,
}

/// Durable derivation occurrence metadata.
///
/// The store checks only identity continuity with the prelaunch generation.
/// It does not establish that an evaluator ran or that any result is valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedDerivationCustodyClaim {
    pub derivation_id: Sha256Digest,
    pub dependency_generation_id: Sha256Digest,
    pub dependency_generation_custody_digest: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub evaluation_id: Option<String>,
    pub profile_semantic_id: Sha256Digest,
    /// Semantic evaluator identity carried by the V2 diagnostic contract.
    ///
    /// This is deliberately distinct from the executable artifact digest.
    pub evaluator_identity_digest: Sha256Digest,
    pub evaluator_artifact_digest: Sha256Digest,
    pub derived_at: String,
    pub clock_identity: Sha256Digest,
    pub clock_qualification_digest: Sha256Digest,
}

impl From<GovernedDerivationCustodyClaim> for DerivationClaim {
    fn from(value: GovernedDerivationCustodyClaim) -> Self {
        Self {
            derivation_id: value.derivation_id,
            dependency_generation_id: value.dependency_generation_id,
            dependency_generation_custody_digest: value.dependency_generation_custody_digest,
            trust_anchor_id: value.trust_anchor_id,
            evaluation_id: value.evaluation_id,
            profile_semantic_id: value.profile_semantic_id,
            evaluator_semantic_digest: Some(value.evaluator_identity_digest),
            evaluator_artifact_digest: value.evaluator_artifact_digest,
            derived_at: value.derived_at,
            clock_identity: value.clock_identity,
            clock_uncertainty_ms: None,
            clock_qualification_digest: Some(value.clock_qualification_digest),
        }
    }
}

fn terminal_timestamp(value: &str, field: &str) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            StoreError::Invariant(format!(
                "protected terminal {field} is not an RFC 3339 instant: {error}"
            ))
        })
}

fn validate_terminal_reason(reason: &GovernedProtectedTerminalReason) -> Result<(), StoreError> {
    if reason.code.is_empty()
        || reason.code.len() > 128
        || !reason
            .code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
        || reason.detail.is_empty()
        || reason.detail.len() > 2_048
        || reason.detail.bytes().any(|byte| byte == 0)
    {
        return Err(StoreError::Invariant(
            "protected terminal reason is empty, oversized, or malformed".into(),
        ));
    }
    Ok(())
}

fn validate_terminal_times(
    launch_claimed_at: &str,
    launch_attempt_deadline: &str,
    terminalized_at: &str,
    compliance: GovernedProtectedTerminalDeadlineCompliance,
) -> Result<(), StoreError> {
    let claimed = terminal_timestamp(launch_claimed_at, "launch_claimed_at")?;
    let deadline = terminal_timestamp(launch_attempt_deadline, "launch_attempt_deadline")?;
    let terminalized = terminal_timestamp(terminalized_at, "terminalized_at")?;
    if terminalized < claimed {
        return Err(StoreError::Invariant(
            "protected terminal predates its exact physical launch claim".into(),
        ));
    }
    let ordering_matches = match compliance {
        GovernedProtectedTerminalDeadlineCompliance::WithinDeadline => terminalized < deadline,
        GovernedProtectedTerminalDeadlineCompliance::DeadlineReachedOrExceeded => {
            terminalized >= deadline
        }
        GovernedProtectedTerminalDeadlineCompliance::NotEstablished => true,
    };
    if !ordering_matches {
        return Err(StoreError::Invariant(
            "protected terminal deadline assessment contradicts its retained exact instants".into(),
        ));
    }
    Ok(())
}

/// Digest and byte length of one durably sealed arena section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCustodyCommitment {
    pub bytes_digest: Sha256Digest,
    pub byte_length: u64,
}

/// Lifetime-locked exact-byte custody handle.
///
/// The handle intentionally has no provider-launch, evaluator, execution
/// binding, or authority API.
pub struct GovernedCustody {
    database_path: PathBuf,
    reservation: GovernedCustodyReservation,
    arena: CustodyArena,
    immediate_launch_record_id: Option<Sha256Digest>,
}

impl GovernedCustody {
    pub(crate) fn reserve(
        database_path: &Path,
        reservation: GovernedCustodyReservation,
        exact_dependency_closure_bytes: &[u8],
    ) -> Result<Self, StoreError> {
        let arena = CustodyArena::create(
            database_path,
            reservation.prelaunch(),
            reservation.layout()?,
            exact_dependency_closure_bytes,
        )
        .map_err(custody_error)?;
        Ok(Self {
            database_path: database_path.to_path_buf(),
            reservation,
            arena,
            immediate_launch_record_id: None,
        })
    }

    pub(crate) fn open(
        database_path: &Path,
        reservation: GovernedCustodyReservation,
    ) -> Result<Self, StoreError> {
        let arena =
            CustodyArena::open(database_path, &reservation.prelaunch()).map_err(custody_error)?;
        let observed = arena.inspection().map_err(custody_error)?;
        if observed.layout != reservation.layout()? {
            return Err(StoreError::Invariant(
                "governed custody layout differs from its exact reservation".into(),
            ));
        }
        Ok(Self {
            database_path: database_path.to_path_buf(),
            reservation,
            arena,
            immediate_launch_record_id: None,
        })
    }

    /// Return the exact reservation used to open this handle.
    #[must_use]
    pub const fn reservation(&self) -> &GovernedCustodyReservation {
        &self.reservation
    }

    /// Return the current durable custody state.
    pub fn state(&self) -> Result<GovernedCustodyState, StoreError> {
        Ok(self.arena.inspection().map_err(custody_error)?.state.into())
    }

    /// Return the digest-derived arena path relative to the database-owned
    /// custody root.
    pub fn relative_path(&self) -> Result<PathBuf, StoreError> {
        self.arena
            .relative_path_from(&self.database_path)
            .map_err(custody_error)
    }

    /// Durably claim one exact launch identity.
    pub fn claim_launch(
        &mut self,
        execution_launch_record_id: Sha256Digest,
        claimed_at: String,
    ) -> Result<(), StoreError> {
        self.arena
            .claim(execution_launch_record_id.clone(), claimed_at)
            .map_err(custody_error)?;
        self.immediate_launch_record_id = Some(execution_launch_record_id);
        Ok(())
    }

    /// Seal and immediately reopen exact opaque provider-intake and raw bytes.
    pub fn seal_acquisition(
        &mut self,
        input: GovernedAcquisitionCustodyInput,
    ) -> Result<CustodiedAcquisition, StoreError> {
        let token = self
            .arena
            .seal_acquisition(AcquisitionCarrier {
                execution_launch_record_id: input.execution_launch_record_id,
                provider_intake_record_id: input.provider_intake_record_id,
                exact_provider_intake_bytes: input.exact_provider_intake_bytes,
                exact_raw_provider_bytes: input.exact_raw_provider_bytes,
            })
            .map_err(custody_error)?;
        Ok(CustodiedAcquisition::from(token.carrier()))
    }

    /// Reopen the exact opaque acquisition carrier without refreshing it.
    pub fn acquisition(&self) -> Result<CustodiedAcquisition, StoreError> {
        let token = self.arena.reopen_raw_token().map_err(custody_error)?;
        Ok(CustodiedAcquisition::from(token.carrier()))
    }

    /// Reopen the exact authenticated dependency-generation closure pinned
    /// before launch.
    pub fn dependency_closure_bytes(&self) -> Result<Vec<u8>, StoreError> {
        self.arena.dependency_closure_bytes().map_err(custody_error)
    }

    /// Durably claim that core has completed one derivation over the reopened
    /// acquisition. This operation assigns no semantic standing itself.
    pub fn claim_derivation(
        &mut self,
        claim: GovernedDerivationCustodyClaim,
    ) -> Result<(), StoreError> {
        let raw = self.arena.reopen_raw_token().map_err(custody_error)?;
        self.arena
            .claim_derivation(raw, claim.into())
            .map(|_| ())
            .map_err(custody_error)
    }

    #[cfg(test)]
    pub(crate) fn claim_legacy_derivation_v1_for_reopen_test(
        &mut self,
        claim: DerivationClaim,
    ) -> Result<(), StoreError> {
        let raw = self.arena.reopen_raw_token().map_err(custody_error)?;
        self.arena
            .claim_derivation(raw, claim)
            .map(|_| ())
            .map_err(custody_error)
    }

    /// Seal exact bytes of a core-validated complete closure.
    ///
    /// The store validates only the internal carrier's canonical top-level
    /// schema and self-identity. It does not validate nested NQ semantics.
    pub fn seal_final_closure(
        &mut self,
        exact_closure_bytes: Vec<u8>,
    ) -> Result<GovernedCustodyCommitment, StoreError> {
        let embedded_diagnostic_bytes =
            governed_closure_embedded_diagnostic_length(&exact_closure_bytes)?;
        if embedded_diagnostic_bytes > self.reservation.diagnostic_artifact_capacity_bytes {
            return Err(StoreError::Invariant(format!(
                "governed V2 diagnostic requires {embedded_diagnostic_bytes} bytes but its pre-effect component bound is {}",
                self.reservation.diagnostic_artifact_capacity_bytes
            )));
        }
        let derivation = self
            .arena
            .reopen_derivation_token()
            .map_err(custody_error)?;
        let candidate = DerivedV2ClosureCandidate::from_store_internal_precursor(
            derivation,
            exact_closure_bytes,
        )
        .map_err(custody_error)?;
        let token = self
            .arena
            .seal_final_v2_closure(candidate)
            .map_err(custody_error)?;
        let bytes = self
            .arena
            .final_v2_closure_bytes()
            .map_err(custody_error)?
            .ok_or_else(|| {
                StoreError::Invariant("sealed final custody closure is unavailable".into())
            })?;
        let inspection = self.arena.inspection().map_err(custody_error)?;
        let section = inspection.final_v2_closure.ok_or_else(|| {
            StoreError::Invariant("sealed final custody commitment is absent".into())
        })?;
        // Retain token ownership inside the durable state transition. Indexing
        // must reopen and verify the final section independently.
        drop(token);
        debug_assert_eq!(
            nq_protocol::sha256_bytes(&bytes),
            section.payload_digest().clone()
        );
        Ok(GovernedCustodyCommitment {
            bytes_digest: section.payload_digest().clone(),
            byte_length: section.payload_length(),
        })
    }

    /// Return exact final-closure carrier bytes, if committed.
    pub fn final_closure_bytes(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.arena.final_v2_closure_bytes().map_err(custody_error)
    }

    /// Return exact protected-failure bytes without interpreting them as a
    /// diagnostic outcome.
    pub fn protected_failure_bytes(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.arena.protected_failure_bytes().map_err(custody_error)
    }

    /// Terminalize the exact launch claimed by this live custody handle.
    ///
    /// This method is deliberately unavailable for a merely reopened
    /// nonterminal launch. A restart loses the in-memory one-use launch
    /// authority, and storage alone cannot prove that no prior executor can
    /// still perform work. Exact replay of an already committed terminal is
    /// idempotent because it performs no new transition.
    pub fn terminalize_immediate_launch(
        &mut self,
        input: GovernedProtectedTerminalInput,
    ) -> Result<GovernedProtectedTerminalization, StoreError> {
        let inspection = self.arena.inspection().map_err(custody_error)?;
        let actual_launch = inspection
            .execution_launch_record_id
            .as_ref()
            .ok_or_else(|| {
                StoreError::Invariant(
                    "protected terminal requires an exact physical launch claim".into(),
                )
            })?;
        if actual_launch != &input.execution_launch_record_id {
            return Err(StoreError::Invariant(
                "protected terminal launch identity differs from the physical launch claim".into(),
            ));
        }
        let launch_claimed_at = inspection.claimed_at.clone().ok_or_else(|| {
            StoreError::Invariant("protected terminal launch claim time is absent".into())
        })?;
        let terminal =
            GovernedProtectedTerminal::create(&self.reservation, launch_claimed_at, input)?;
        if inspection.state == ArenaState::FailedIndeterminate {
            let existing = self
                .arena
                .protected_failure_bytes()
                .map_err(custody_error)?
                .ok_or_else(|| {
                    StoreError::Invariant(
                        "terminal custody state has no protected terminal bytes".into(),
                    )
                })?;
            if existing != terminal.exact_bytes {
                return Err(StoreError::Invariant(
                    "launched occurrence is already terminalized by different exact bytes".into(),
                ));
            }
            let terminal = GovernedProtectedTerminal::from_exact_bytes(existing)?;
            return Ok(GovernedProtectedTerminalization {
                disposition: GovernedProtectedTerminalDisposition::AlreadyTerminalized,
                commitment: GovernedCustodyCommitment {
                    bytes_digest: sha256_bytes(terminal.exact_bytes()),
                    byte_length: u64::try_from(terminal.exact_bytes().len()).map_err(|_| {
                        StoreError::Invariant(
                            "protected terminal byte length exceeds address space".into(),
                        )
                    })?,
                },
                terminal,
            });
        }
        if self.immediate_launch_record_id.as_ref() != Some(actual_launch) {
            return Err(StoreError::Invariant(
                "reopened in-flight launch has no exact no-further-execution fence; recovery terminalization is unavailable"
                    .into(),
            ));
        }
        if !matches!(
            inspection.state,
            ArenaState::Claimed | ArenaState::RawEvidenceSealed | ArenaState::DerivationClaimed
        ) {
            return Err(StoreError::Invariant(
                "only an in-flight launched occurrence can enter protected terminal custody".into(),
            ));
        }
        if terminal.document.terminal_class == GovernedProtectedTerminalClass::PreEffectRefusal
            && inspection.state != ArenaState::Claimed
        {
            return Err(StoreError::Invariant(
                "pre-effect refusal cannot terminalize an occurrence after acquisition custody"
                    .into(),
            ));
        }
        let candidate =
            ArenaFailureCarrierCandidate::parse_protected_terminal(terminal.exact_bytes.clone())
                .map_err(custody_error)?;
        let section = self
            .arena
            .seal_failure(candidate, ArenaState::FailedIndeterminate)
            .map_err(custody_error)?;
        let reopened = self
            .arena
            .protected_failure_bytes()
            .map_err(custody_error)?
            .ok_or_else(|| {
                StoreError::Invariant("committed protected terminal cannot be reopened".into())
            })?;
        if reopened != terminal.exact_bytes {
            return Err(StoreError::Invariant(
                "reopened protected terminal differs from committed exact bytes".into(),
            ));
        }
        Ok(GovernedProtectedTerminalization {
            disposition: GovernedProtectedTerminalDisposition::Terminalized,
            commitment: GovernedCustodyCommitment {
                bytes_digest: section.payload_digest().clone(),
                byte_length: section.payload_length(),
            },
            terminal,
        })
    }

    /// Reopen a typed protected terminal without refreshing any retained fact.
    pub fn protected_terminal(&self) -> Result<Option<GovernedProtectedTerminal>, StoreError> {
        self.arena
            .protected_failure_bytes()
            .map_err(custody_error)?
            .map(GovernedProtectedTerminal::from_exact_bytes)
            .transpose()
    }
}

impl Store {
    /// Physically reserve exact-byte custody before any provider launch.
    pub fn reserve_governed_custody(
        &self,
        reservation: GovernedCustodyReservation,
        exact_dependency_closure_bytes: &[u8],
    ) -> Result<GovernedCustody, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "governed custody requires a filesystem-backed initialized store".into(),
            )
        })?;
        GovernedCustody::reserve(database_path, reservation, exact_dependency_closure_bytes)
    }

    /// Reopen and verify one exact governed custody reservation.
    pub fn open_governed_custody(
        &self,
        reservation: GovernedCustodyReservation,
    ) -> Result<GovernedCustody, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "governed custody requires a filesystem-backed initialized store".into(),
            )
        })?;
        GovernedCustody::open(database_path, reservation)
    }

    /// Inspect every physical governed-custody frontier owned by this store.
    ///
    /// This is the startup/recovery read surface. It reports exact durable
    /// states and corrupt entries without resuming work, minting failure
    /// carriers, or assigning diagnostic standing.
    #[allow(clippy::too_many_lines)] // One closed reconciliation keeps omissions visible.
    pub fn governed_custody_inventory(
        &self,
    ) -> Result<Vec<GovernedCustodyInventoryEntry>, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "governed custody inventory requires a filesystem-backed initialized store".into(),
            )
        })?;
        let mut expected_reservations = self
            .connection
            .prepare(
                "SELECT record_id, canonical_bytes_sha256
                 FROM runtime_record_ledger
                 WHERE record_schema = 'nq.custody_reservation.v1'
                 ORDER BY record_id",
            )?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(record_id, digest)| {
                Ok((
                    Sha256Digest::parse(record_id).map_err(|error| {
                        StoreError::Integrity(format!(
                            "custody-reservation ledger identity is invalid: {error}"
                        ))
                    })?,
                    Sha256Digest::parse(digest).map_err(|error| {
                        StoreError::Integrity(format!(
                            "custody-reservation ledger digest is invalid: {error}"
                        ))
                    })?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
        let physical = CustodyArena::inventory(
            database_path,
            usize::try_from(MAX_PUBLIC_QUERY_ROWS).unwrap_or(1_000),
        )
        .map_err(custody_error)?;
        let mut inventory =
            Vec::with_capacity(physical.len().saturating_add(expected_reservations.len()));
        for entry in physical {
            inventory.push(match entry {
                ArenaInventoryEntry::Verified {
                    relative_path,
                    inspection,
                } => {
                    let reservation_ledger_binding =
                        match expected_reservations.remove(&inspection.reservation_id) {
                            None => GovernedCustodyReservationLedgerBinding::NoCommittedReservation,
                            Some(ledger_digest)
                                if ledger_digest
                                    == inspection.prelaunch.reservation_manifest_digest =>
                            {
                                GovernedCustodyReservationLedgerBinding::Exact
                            }
                            Some(ledger_digest) => {
                                GovernedCustodyReservationLedgerBinding::ReservationDigestMismatch {
                                    ledger_digest,
                                    arena_digest: inspection
                                        .prelaunch
                                        .reservation_manifest_digest
                                        .clone(),
                                }
                            }
                        };
                    GovernedCustodyInventoryEntry::Verified(Box::new(GovernedCustodyInspection {
                        relative_path,
                        reservation_record_id: inspection.reservation_id,
                        reservation_manifest_digest: inspection
                            .prelaunch
                            .reservation_manifest_digest,
                        reservation_ledger_binding,
                        outer_request_record_id: inspection.prelaunch.outer_request_record_id,
                        outer_request_id: inspection.prelaunch.outer_request_id,
                        dependency_generation_id: inspection.prelaunch.dependency_generation_id,
                        trust_anchor_id: inspection.prelaunch.trust_anchor_id,
                        state: inspection.state.into(),
                        recovery_class: inspection.state.into(),
                        arena_sequence: inspection.sequence,
                        execution_launch_record_id: inspection.execution_launch_record_id,
                        final_closure: inspection.final_v2_closure.map(|section| {
                            GovernedCustodyCommitment {
                                bytes_digest: section.payload_digest().clone(),
                                byte_length: section.payload_length(),
                            }
                        }),
                        protected_failure: inspection.protected_failure.map(|section| {
                            GovernedCustodyCommitment {
                                bytes_digest: section.payload_digest().clone(),
                                byte_length: section.payload_length(),
                            }
                        }),
                        recovered_torn_superblock: inspection.recovered_torn_superblock,
                    }))
                }
                ArenaInventoryEntry::Unreadable {
                    relative_path,
                    reason,
                } => GovernedCustodyInventoryEntry::Unreadable {
                    relative_path,
                    reason,
                },
            });
        }
        inventory.extend(expected_reservations.into_iter().map(
            |(reservation_record_id, reservation_manifest_digest)| {
                GovernedCustodyInventoryEntry::MissingForCommittedReservation {
                    reservation_record_id,
                    reservation_manifest_digest,
                }
            },
        ));
        if inventory.len() > usize::try_from(MAX_PUBLIC_QUERY_ROWS).unwrap_or(1_000) {
            return Err(StoreError::Invariant(format!(
                "combined custody inventory exceeds {MAX_PUBLIC_QUERY_ROWS} entries"
            )));
        }
        Ok(inventory)
    }

    /// Read one exact protected-failure carrier by its reservation identity.
    ///
    /// A missing arena, a verified arena without a failure, and verified
    /// protected-failure bytes remain distinct. Corrupt or unreadable custody
    /// refuses instead of being represented as absence.
    pub fn governed_protected_failure(
        &self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProtectedFailureAccess, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "protected-failure retrieval requires a filesystem-backed initialized store".into(),
            )
        })?;
        let Some(arena) = CustodyArena::open_by_reservation(database_path, reservation_record_id)
            .map_err(custody_error)?
        else {
            return Ok(GovernedProtectedFailureAccess::ArenaMissing);
        };
        let state: GovernedCustodyState = arena.inspection().map_err(custody_error)?.state.into();
        let Some(exact_bytes) = arena.protected_failure_bytes().map_err(custody_error)? else {
            return Ok(GovernedProtectedFailureAccess::NotPresent { arena_state: state });
        };
        Ok(GovernedProtectedFailureAccess::VerifiedAvailable(
            GovernedProtectedFailure {
                reservation_record_id: reservation_record_id.clone(),
                bytes_digest: nq_protocol::sha256_bytes(&exact_bytes),
                exact_bytes,
            },
        ))
    }

    /// Reopen exact committed prelaunch membership and verify that the
    /// preselected diagnostic and final-closure partitions satisfy the pure
    /// V2 encoder bound.
    ///
    /// This check is intended after the reservation and launch checkpoints
    /// commit but before provider effect. It verifies storage capacity only.
    #[allow(clippy::too_many_lines)]
    pub fn verify_governed_execution_custody_closure_v2_capacity(
        &self,
        reservation: &GovernedCustodyReservation,
        launch_checkpoint_id: &Sha256Digest,
    ) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            StoreError::Invariant(
                "governed capacity verification requires a filesystem-backed store".into(),
            )
        })?;
        let _arena = GovernedCustody::open(database_path, reservation.clone())?;
        let snapshot = self.connection.unchecked_transaction()?;
        validate_runtime_record_ledger(&snapshot)?;
        let reservation_checkpoint = runtime_checkpoint_by_id_on_connection(
            &snapshot,
            reservation.prelaunch_checkpoint_id.as_str(),
        )?
        .ok_or_else(|| {
            projection_integrity(
                &reservation.reservation_record_id,
                "reservation checkpoint is absent during capacity verification",
            )
        })?;
        let reservation_records = checkpoint_runtime_records(
            &snapshot,
            &reservation.reservation_record_id,
            &reservation_checkpoint,
        )?;
        let reservation_record = unique_checkpoint_record_by_schema(
            &reservation.reservation_record_id,
            &reservation_records,
            "nq.custody_reservation.v1",
            "custody reservation",
        )?;
        let outer_request_record = unique_checkpoint_record_by_schema(
            &reservation.reservation_record_id,
            &reservation_records,
            "nq.diagnostic_invocation_request.v1",
            "outer request",
        )?;
        let invocation_decision_record = unique_checkpoint_record_by_schema(
            &reservation.reservation_record_id,
            &reservation_records,
            "nq.invocation_decision.v1",
            "invocation decision",
        )?;
        if reservation_checkpoint.batch_digest != reservation.prelaunch_checkpoint_digest
            || reservation_checkpoint.checkpoint_id != reservation.prelaunch_checkpoint_id.as_str()
            || reservation_record.record_id != reservation.reservation_record_id.as_str()
            || reservation_record.canonical_bytes_sha256 != reservation.reservation_manifest_digest
            || outer_request_record.record_id != reservation.outer_request_record_id.as_str()
            || outer_request_record.canonical_bytes_sha256 != reservation.outer_request_digest
        {
            return Err(projection_integrity(
                &reservation.reservation_record_id,
                "reservation checkpoint differs from exact physical reservation input",
            ));
        }
        let (diagnostic_capacity, final_capacity) =
            governed_reservation_capacity_components(reservation_record)?;
        if diagnostic_capacity != reservation.diagnostic_artifact_capacity_bytes
            || final_capacity != reservation.final_capacity_bytes
        {
            return Err(projection_integrity(
                &reservation.reservation_record_id,
                "caller capacity differs from the exact custody reservation record",
            ));
        }

        let launch_checkpoint =
            runtime_checkpoint_by_id_on_connection(&snapshot, launch_checkpoint_id.as_str())?
                .ok_or_else(|| {
                    projection_integrity(
                        &reservation.reservation_record_id,
                        "launch checkpoint is absent during capacity verification",
                    )
                })?;
        if launch_checkpoint.predecessor_checkpoint_id.as_deref()
            != Some(reservation_checkpoint.checkpoint_id.as_str())
        {
            return Err(projection_integrity(
                &reservation.reservation_record_id,
                "launch checkpoint does not immediately follow reservation checkpoint",
            ));
        }
        let launch_records = checkpoint_runtime_records(
            &snapshot,
            &reservation.reservation_record_id,
            &launch_checkpoint,
        )?;
        let launch_record = unique_checkpoint_record_by_schema(
            &reservation.reservation_record_id,
            &launch_records,
            "nq.execution_launch.v1",
            "execution launch",
        )?;
        let deadline_records = launch_records
            .iter()
            .filter(|record| record.record_schema == "nq.deadline_evaluation.v1")
            .collect::<Vec<_>>();
        match deadline_records.as_slice() {
            [] if launch_records.len() == 1 => {}
            [deadline] if launch_records.len() == 2 => verify_native_launch_checkpoint(
                &reservation.reservation_record_id,
                deadline,
                launch_record,
                &reservation_records,
                outer_request_record,
                invocation_decision_record,
                reservation_record,
            )?,
            _ => {
                return Err(projection_integrity(
                    &reservation.reservation_record_id,
                    "capacity verification requires one legacy launch or one exact deadline-plus-launch pair",
                ));
            }
        }
        verify_capacity_checkpoint_dependency(
            &snapshot,
            &reservation.reservation_record_id,
            &reservation_checkpoint.checkpoint_id,
            reservation,
        )?;
        verify_capacity_checkpoint_dependency(
            &snapshot,
            &reservation.reservation_record_id,
            &launch_checkpoint.checkpoint_id,
            reservation,
        )?;
        let capacity = governed_execution_custody_closure_v2_capacity_bound(
            &GovernedExecutionCustodyClosureV2CapacityInput {
                reservation: reservation_record.try_into()?,
                prelaunch: GovernedClosurePrelaunchInput {
                    outer_request: outer_request_record.try_into()?,
                    invocation_decision: invocation_decision_record.try_into()?,
                    reservation_checkpoint: GovernedClosureCheckpointInput {
                        checkpoint_id: reservation.prelaunch_checkpoint_id.clone(),
                        batch_digest: reservation_checkpoint.batch_digest,
                        runtime_records: reservation_records
                            .iter()
                            .map(GovernedClosureRecordReference::try_from)
                            .collect::<Result<Vec<_>, _>>()?,
                    },
                    launch_checkpoint: GovernedClosureCheckpointInput {
                        checkpoint_id: launch_checkpoint_id.clone(),
                        batch_digest: launch_checkpoint.batch_digest,
                        runtime_records: launch_records
                            .iter()
                            .map(GovernedClosureRecordReference::try_from)
                            .collect::<Result<Vec<_>, _>>()?,
                    },
                },
                execution_launch_record_id: Sha256Digest::parse(launch_record.record_id.clone())
                    .map_err(|error| {
                        projection_integrity(
                            &reservation.reservation_record_id,
                            format!("execution launch identity is invalid: {error}"),
                        )
                    })?,
                dependency_generation_id: reservation.dependency_generation_id.clone(),
                dependency_generation_custody_digest: reservation
                    .dependency_generation_custody_digest
                    .clone(),
                trust_anchor_id: reservation.trust_anchor_id.clone(),
                diagnostic_artifact_capacity_bytes: diagnostic_capacity,
            },
        )?;
        if capacity.final_closure_capacity_bytes > final_capacity {
            return Err(projection_integrity(
                &reservation.reservation_record_id,
                format!(
                    "final closure requires {} bytes but exact reservation provides {final_capacity}",
                    capacity.final_closure_capacity_bytes
                ),
            ));
        }
        drop(snapshot);
        Ok(capacity)
    }

    /// Verify that one sealed physical closure corresponds exactly to the
    /// already-committed SQL artifact, local origin, execution binding,
    /// provider occurrence, runtime-record batch, and dependency generation,
    /// then durably mark the arena indexed.
    ///
    /// The reservation identity is the only caller input. All verdict-shaped
    /// bytes and row identities are reopened from store-owned custody. A
    /// missing or mismatching projection leaves an index-pending arena
    /// unchanged. Repeating the operation on an indexed arena rechecks the
    /// complete correspondence instead of trusting the prior state bit.
    ///
    /// This method proves storage correspondence only. NQ core remains
    /// responsible for native provider, evaluator, profile, and diagnostic
    /// semantic validation before sealing the closure.
    #[allow(clippy::too_many_lines)] // One closed comparison keeps omissions auditable.
    pub fn verify_governed_projection_and_mark_indexed(
        &self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProjectionVerification, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "projection verification requires a filesystem-backed initialized store",
            )
        })?;
        let mut arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "physical custody arena is absent")
            })?;
        let inspection = arena.inspection().map_err(custody_error)?;
        if inspection.reservation_id != *reservation_record_id {
            return Err(projection_integrity(
                reservation_record_id,
                "arena reservation identity differs",
            ));
        }
        let disposition = match inspection.state {
            ArenaState::FinalV2SealedIndexPending => {
                GovernedProjectionVerificationDisposition::Indexed
            }
            ArenaState::FinalV2SealedIndexed => {
                GovernedProjectionVerificationDisposition::AlreadyIndexed
            }
            state => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!("arena state {state:?} has no final projection to verify"),
                ));
            }
        };
        let exact_closure_bytes = arena
            .final_v2_closure_bytes()
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "final closure bytes are absent")
            })?;
        let closure: GovernedProjectionClosure = serde_json::from_slice(&exact_closure_bytes)
            .map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("final closure shape is incompatible: {error}"),
                )
            })?;
        if !matches!(
            closure.schema.as_str(),
            GOVERNED_CUSTODY_CLOSURE_SCHEMA | GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA
        ) {
            return Err(projection_integrity(
                reservation_record_id,
                "final closure schema differs",
            ));
        }

        // One SQLite read transaction gives every row comparison below one
        // immutable projection snapshot. The arena sections are themselves
        // sealed and immutable at these frontiers.
        let snapshot = self.connection.unchecked_transaction()?;
        validate_runtime_record_ledger(&snapshot)?;
        validate_provider_intake_invariants(&snapshot)?;
        validate_diagnostic_artifact_invariants(&snapshot)?;

        let reservation_record = exact_runtime_record(
            &snapshot,
            reservation_record_id,
            &closure.reservation,
            "custody reservation",
        )?;
        if closure.reservation.schema != "nq.custody_reservation.v1"
            || closure.reservation.record_id != *reservation_record_id
            || closure.reservation.bytes_digest != inspection.prelaunch.reservation_manifest_digest
            || reservation_record.checkpoint_id
                != inspection.prelaunch.prelaunch_checkpoint_id.as_str()
        {
            return Err(projection_integrity(
                reservation_record_id,
                "reservation reference differs from the arena prelaunch binding",
            ));
        }
        let (diagnostic_capacity, final_capacity) =
            governed_reservation_capacity_components(&reservation_record)?;
        let embedded_diagnostic_length =
            governed_closure_embedded_diagnostic_length(&exact_closure_bytes)?;
        if final_capacity != inspection.layout.final_capacity()
            || embedded_diagnostic_length > diagnostic_capacity
        {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic or final closure capacity differs from exact reservation custody",
            ));
        }
        let outer_request_record = exact_runtime_record(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.outer_request,
            "outer request",
        )?;
        let invocation_decision_record = exact_runtime_record(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.invocation_decision,
            "accepted invocation decision",
        )?;
        let (reservation_checkpoint, reservation_checkpoint_records) = exact_checkpoint(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.reservation_checkpoint,
            "reservation",
        )?;
        if reservation_checkpoint.checkpoint_id
            != inspection.prelaunch.prelaunch_checkpoint_id.as_str()
            || reservation_checkpoint.batch_digest
                != inspection.prelaunch.prelaunch_checkpoint_digest
            || reservation_record.checkpoint_id != reservation_checkpoint.checkpoint_id
            || closure.prelaunch.outer_request.record_id
                != inspection.prelaunch.outer_request_record_id
            || closure.prelaunch.outer_request.bytes_digest
                != inspection.prelaunch.outer_request_digest
        {
            return Err(projection_integrity(
                reservation_record_id,
                "reservation checkpoint identity, digest, or arena binding differs",
            ));
        }
        if !checkpoint_has_unique_exact_record(
            &reservation_checkpoint_records,
            &outer_request_record,
            "nq.diagnostic_invocation_request.v1",
        ) || !checkpoint_has_unique_exact_record(
            &reservation_checkpoint_records,
            &invocation_decision_record,
            "nq.invocation_decision.v1",
        ) || !checkpoint_has_unique_exact_record(
            &reservation_checkpoint_records,
            &reservation_record,
            "nq.custody_reservation.v1",
        ) || exact_json_string(
            reservation_record_id,
            &invocation_decision_record,
            "decision",
        )?
        .as_deref()
            != Some("accepted")
        {
            return Err(projection_integrity(
                reservation_record_id,
                "reservation checkpoint membership or accepted-decision state differs",
            ));
        }

        let (launch_checkpoint, launch_checkpoint_records) = exact_checkpoint(
            &snapshot,
            reservation_record_id,
            &closure.prelaunch.launch_checkpoint,
            "launch",
        )?;
        let launch_records = launch_checkpoint_records
            .iter()
            .filter(|record| record.record_schema == "nq.execution_launch.v1")
            .collect::<Vec<_>>();
        let [launch_record] = launch_records.as_slice() else {
            return Err(projection_integrity(
                reservation_record_id,
                "launch checkpoint does not contain exactly one execution launch",
            ));
        };
        let launch_record = *launch_record;
        if launch_record.record_schema != "nq.execution_launch.v1"
            || launch_record.record_id
                != inspection
                    .execution_launch_record_id
                    .as_ref()
                    .map(Sha256Digest::as_str)
                    .unwrap_or_default()
            || launch_record.record_id != closure.acquisition.execution_launch_record_id.as_str()
            || launch_checkpoint.predecessor_checkpoint_id.as_deref()
                != Some(reservation_checkpoint.checkpoint_id.as_str())
            || inspection.claimed_at.as_deref()
                != exact_json_string(reservation_record_id, launch_record, "launched_at")?
                    .as_deref()
        {
            return Err(projection_integrity(
                reservation_record_id,
                "launch checkpoint membership, predecessor, or physical claim time differs",
            ));
        }
        let deadline_records = launch_checkpoint_records
            .iter()
            .filter(|record| record.record_schema == "nq.deadline_evaluation.v1")
            .collect::<Vec<_>>();
        match deadline_records.as_slice() {
            [] if launch_checkpoint_records.len() == 1 => {
                // Compatibility for already-committed launch-only checkpoints.
                // This shape has no native-deadline provenance to upgrade.
            }
            [deadline_record] if launch_checkpoint_records.len() == 2 => {
                verify_native_launch_checkpoint(
                    reservation_record_id,
                    deadline_record,
                    launch_record,
                    &reservation_checkpoint_records,
                    &outer_request_record,
                    &invocation_decision_record,
                    &reservation_record,
                )?;
            }
            _ => {
                return Err(projection_integrity(
                    reservation_record_id,
                    "launch checkpoint is neither one legacy launch nor one exact deadline-plus-launch pair",
                ));
            }
        }
        let physical_derivation = inspection.derivation_claim.as_ref().ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "final physical frontier has no derivation claim",
            )
        })?;
        if !closure.derivation.matches(physical_derivation)
            || closure.derivation.dependency_generation_id
                != closure.dependency_generation.generation_id
            || closure.derivation.dependency_generation_custody_digest
                != closure.dependency_generation.custody_bytes_digest
            || closure.derivation.trust_anchor_id != closure.dependency_generation.trust_anchor_id
            || closure.derivation.evaluation_id != closure.local_origin.evaluation_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "sealed derivation differs from the complete physical claim or local origin",
            ));
        }

        let exact_diagnostic_bytes =
            canonical_json_bytes(&closure.diagnostic).map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("embedded diagnostic cannot be canonicalized: {error}"),
                )
            })?;
        let diagnostic_schema = closure
            .diagnostic
            .get("schema")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "embedded diagnostic schema is absent",
                )
            })?;
        if diagnostic_schema != "nq.diagnostic_execution.v2" {
            return Err(projection_integrity(
                reservation_record_id,
                "only the production V2 diagnostic contract may be indexed",
            ));
        }
        let diagnostic_evaluator_digest = closure
            .diagnostic
            .pointer("/evaluator/digest")
            .and_then(Value::as_str);
        let evaluator_corresponds = match closure.schema.as_str() {
            GOVERNED_CUSTODY_CLOSURE_SCHEMA => {
                closure.derivation.evaluator_semantic_digest.is_none()
                    && diagnostic_evaluator_digest
                        == Some(closure.derivation.evaluator_artifact_digest.as_str())
            }
            GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA => closure
                .derivation
                .evaluator_semantic_digest
                .as_ref()
                .is_some_and(|identity| diagnostic_evaluator_digest == Some(identity.as_str())),
            _ => false,
        };
        if closure
            .diagnostic
            .pointer("/profile_semantic_id")
            .and_then(Value::as_str)
            != Some(closure.derivation.profile_semantic_id.as_str())
            || !evaluator_corresponds
            || closure
                .diagnostic
                .pointer("/completed_at")
                .and_then(Value::as_str)
                != Some(closure.derivation.derived_at.as_str())
            || closure.local_origin.completed_at != closure.derivation.derived_at
            || closure
                .diagnostic
                .pointer("/execution_clock/digest")
                .and_then(Value::as_str)
                != Some(closure.derivation.clock_identity.as_str())
        {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic profile, evaluator, derivation time, or clock differs from custody",
            ));
        }
        let clock_qualification = closure
            .diagnostic
            .pointer("/attempt_interval/qualification")
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "diagnostic clock qualification is absent",
                )
            })?;
        let clock_corresponds = match closure.schema.as_str() {
            GOVERNED_CUSTODY_CLOSURE_SCHEMA => {
                closure.derivation.clock_qualification_digest.is_none()
                    && closure
                        .derivation
                        .clock_uncertainty_ms
                        .is_some_and(|uncertainty| {
                            clock_qualification.get("state").and_then(Value::as_str)
                                == Some("bounded")
                                && clock_qualification
                                    .get("maximum_error_ms")
                                    .and_then(Value::as_u64)
                                    == Some(uncertainty)
                        })
            }
            GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA => {
                closure.derivation.clock_uncertainty_ms.is_none()
                    && matches!(
                        clock_qualification.get("state").and_then(Value::as_str),
                        Some("bounded" | "unqualified")
                    )
                    && closure
                        .derivation
                        .clock_qualification_digest
                        .as_ref()
                        .is_some_and(|expected| {
                            semantic_digest(clock_qualification)
                                .is_ok_and(|actual| actual == *expected)
                        })
            }
            _ => false,
        };
        if !clock_corresponds {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic clock qualification differs from custody",
            ));
        }
        let diagnostic_artifact_id = Sha256Digest::parse(
            closure
                .diagnostic
                .get("artifact_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    projection_integrity(
                        reservation_record_id,
                        "embedded diagnostic artifact identity is absent",
                    )
                })?
                .to_owned(),
        )
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("embedded diagnostic identity is invalid: {error}"),
            )
        })?;
        let DiagnosticArtifactLookup::Found(artifact) = diagnostic_artifact_on_connection(
            &snapshot,
            &diagnostic_artifact_id,
            &[diagnostic_schema],
        )?
        else {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic artifact SQL commitment is absent",
            ));
        };
        let DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes } =
            &artifact.byte_state
        else {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic artifact bytes are unavailable or corrupt",
            ));
        };
        if canonical_bytes.as_bytes() != exact_diagnostic_bytes
            || artifact.commitment.contract_schema != diagnostic_schema
        {
            return Err(projection_integrity(
                reservation_record_id,
                "embedded diagnostic differs from its exact SQL commitment",
            ));
        }
        match &artifact.commitment.origin {
            DiagnosticArtifactOrigin::Local {
                run_id,
                evaluation_id,
                completed_at,
                execution_binding_record_id,
            } if run_id == &closure.local_origin.run_id
                && evaluation_id == &closure.local_origin.evaluation_id
                && completed_at == &closure.local_origin.completed_at
                && execution_binding_record_id.as_deref()
                    == Some(closure.execution_binding.record_id.as_str()) => {}
            _ => {
                return Err(projection_integrity(
                    reservation_record_id,
                    "diagnostic local origin differs from the sealed closure",
                ));
            }
        }

        let binding = diagnostic_artifact_execution_binding_on_connection(
            &snapshot,
            &diagnostic_artifact_id,
        )?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "diagnostic execution binding is absent",
            )
        })?;
        if !closure
            .execution_binding
            .matches(&binding.execution_binding)
            || closure.execution_binding.schema != "nq.execution_identity_binding.v2"
        {
            return Err(projection_integrity(
                reservation_record_id,
                "execution binding reference differs from SQL",
            ));
        }
        if binding.outer_request != outer_request_record
            || binding.invocation_decision != invocation_decision_record
            || binding.execution_launch != *launch_record
            || binding.outer_request.record_id
                != inspection.prelaunch.outer_request_record_id.as_str()
            || binding.outer_request_id != inspection.prelaunch.outer_request_id
            || closure.acquisition.execution_launch_record_id.as_str()
                != binding.execution_launch.record_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "request or launch binding differs from the physical arena",
            ));
        }
        let [(provider_record, provider_attempt)] = binding.provider_attempts.as_slice() else {
            return Err(projection_integrity(
                reservation_record_id,
                "one physical acquisition requires exactly one SQL provider attempt",
            ));
        };
        if !closure.acquisition.provider_intake.matches(provider_record)
            || closure.acquisition.provider_intake.schema != "nq.provider_intake.v1"
            || closure.acquisition.intake_id != provider_attempt.intake_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "provider-attempt binding differs from the sealed closure",
            ));
        }
        let acquisition = arena.acquisition_for_projection().map_err(custody_error)?;
        if acquisition.execution_launch_record_id != closure.acquisition.execution_launch_record_id
            || acquisition.provider_intake_record_id
                != closure.acquisition.provider_intake.record_id
            || acquisition.exact_provider_intake_bytes != provider_record.canonical_bytes.as_bytes()
        {
            return Err(projection_integrity(
                reservation_record_id,
                "physical provider-intake carrier differs from SQL",
            ));
        }
        let provider_projection = snapshot
            .query_row(
                "SELECT intake_digest, raw_sha256, profile_semantic_id,
                        evaluator_artifact_digest, raw_bytes
                 FROM provider_intake_attempts WHERE intake_id = ?1",
                [&closure.acquisition.intake_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "provider intake SQL row is absent")
            })?;
        let (
            provider_intake_digest,
            provider_raw_digest,
            provider_profile_semantic_id,
            provider_evaluator_artifact_digest,
            raw_provider_bytes,
        ) = provider_projection;
        if provider_intake_digest != provider_record.record_id
            || provider_raw_digest != closure.acquisition.raw_provider_bytes_digest.as_str()
            || provider_profile_semantic_id != closure.derivation.profile_semantic_id.as_str()
            || provider_evaluator_artifact_digest
                != closure.derivation.evaluator_artifact_digest.as_str()
            || sha256_bytes(&raw_provider_bytes) != closure.acquisition.raw_provider_bytes_digest
            || raw_provider_bytes != acquisition.exact_raw_provider_bytes
        {
            return Err(projection_integrity(
                reservation_record_id,
                "physical raw acquisition differs from the SQL provider occurrence",
            ));
        }

        let checkpoint_id = Sha256Digest::parse(binding.execution_binding.checkpoint_id.clone())
            .map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("projection checkpoint identity is invalid: {error}"),
                )
            })?;
        if checkpoint_id != closure.dependency_generation.checkpoint_id {
            return Err(projection_integrity(
                reservation_record_id,
                "closure dependency checkpoint differs from the binding batch",
            ));
        }
        let checkpoint = runtime_checkpoint_by_id_on_connection(&snapshot, checkpoint_id.as_str())?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "projection checkpoint is absent")
            })?;
        let checkpoint_records =
            checkpoint_runtime_records(&snapshot, reservation_record_id, &checkpoint)?;
        if checkpoint.batch_digest != closure.dependency_generation.checkpoint_digest
            || checkpoint.record_count
                != u64::try_from(checkpoint_records.len()).map_err(|_| {
                    projection_integrity(
                        reservation_record_id,
                        "projection checkpoint record count overflowed",
                    )
                })?
            || closure.runtime_records.len() != checkpoint_records.len()
            || closure
                .runtime_records
                .iter()
                .zip(&checkpoint_records)
                .any(|(reference, record)| !reference.matches(record))
            || !checkpoint_records
                .iter()
                .any(|record| record.record_id == binding.execution_binding.record_id)
            || !checkpoint_records
                .iter()
                .any(|record| record.record_id == provider_record.record_id)
        {
            return Err(projection_integrity(
                reservation_record_id,
                "sealed runtime-record write set differs from the exact SQL checkpoint",
            ));
        }

        let dependency_bytes = arena.dependency_closure_bytes().map_err(custody_error)?;
        if sha256_bytes(&dependency_bytes) != closure.dependency_generation.custody_bytes_digest
            || closure.dependency_generation.generation_id
                != inspection.prelaunch.dependency_generation_id
            || closure.dependency_generation.trust_anchor_id != inspection.prelaunch.trust_anchor_id
        {
            return Err(projection_integrity(
                reservation_record_id,
                "sealed dependency generation differs from arena prelaunch",
            ));
        }
        verify_checkpoint_dependency(
            &snapshot,
            reservation_record_id,
            &reservation_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )?;
        verify_checkpoint_dependency(
            &snapshot,
            reservation_record_id,
            &launch_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )?;
        verify_checkpoint_dependency(
            &snapshot,
            reservation_record_id,
            &checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )?;
        drop(snapshot);

        if disposition == GovernedProjectionVerificationDisposition::Indexed {
            let token = arena.reopen_final_token().map_err(custody_error)?;
            arena.mark_indexed(token).map_err(custody_error)?;
            drop(arena);
            let reopened = CustodyArena::open_by_reservation(database_path, reservation_record_id)
                .map_err(custody_error)?
                .ok_or_else(|| {
                    projection_integrity(
                        reservation_record_id,
                        "indexed arena disappeared during durable reopen",
                    )
                })?;
            let reopened_inspection = reopened.inspection().map_err(custody_error)?;
            if reopened_inspection.state != ArenaState::FinalV2SealedIndexed
                || reopened
                    .final_v2_closure_bytes()
                    .map_err(custody_error)?
                    .as_deref()
                    != Some(exact_closure_bytes.as_slice())
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "indexed transition did not durably preserve the exact closure",
                ));
            }
        }

        Ok(GovernedProjectionVerification {
            reservation_record_id: reservation_record_id.clone(),
            closure_id: closure.closure_id,
            diagnostic_artifact_id,
            runtime_checkpoint_id: checkpoint_id,
            disposition,
        })
    }
}

fn exact_checkpoint(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    expected: &GovernedProjectionCheckpoint,
    label: &str,
) -> Result<(RuntimeLedgerCheckpoint, Vec<RuntimeRecordRow>), StoreError> {
    let checkpoint =
        runtime_checkpoint_by_id_on_connection(connection, expected.checkpoint_id.as_str())?
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    format!("{label} checkpoint is absent"),
                )
            })?;
    if checkpoint.batch_digest != expected.batch_digest {
        return Err(projection_integrity(
            reservation_record_id,
            format!("{label} checkpoint digest differs from its sealed reference"),
        ));
    }
    let records = checkpoint_runtime_records(connection, reservation_record_id, &checkpoint)?;
    if checkpoint.record_count
        != u64::try_from(records.len()).map_err(|_| {
            projection_integrity(
                reservation_record_id,
                format!("{label} checkpoint record count overflowed"),
            )
        })?
        || expected.runtime_records.len() != records.len()
        || expected
            .runtime_records
            .iter()
            .zip(&records)
            .any(|(reference, record)| !reference.matches(record))
    {
        return Err(projection_integrity(
            reservation_record_id,
            format!("{label} checkpoint membership differs from its sealed reference"),
        ));
    }
    Ok((checkpoint, records))
}

fn checkpoint_has_unique_exact_record(
    records: &[RuntimeRecordRow],
    expected: &RuntimeRecordRow,
    schema: &str,
) -> bool {
    expected.record_schema == schema
        && records
            .iter()
            .filter(|record| record.record_schema == schema)
            .count()
            == 1
        && records.iter().any(|record| record == expected)
}

fn unique_checkpoint_record_by_schema<'a>(
    reservation_record_id: &Sha256Digest,
    records: &'a [RuntimeRecordRow],
    schema: &str,
    label: &str,
) -> Result<&'a RuntimeRecordRow, StoreError> {
    let matches = records
        .iter()
        .filter(|record| record.record_schema == schema)
        .collect::<Vec<_>>();
    let [record] = matches.as_slice() else {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint requires exactly one {label}"),
        ));
    };
    Ok(record)
}

fn verify_capacity_checkpoint_dependency(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    checkpoint_id: &str,
    reservation: &GovernedCustodyReservation,
) -> Result<(), StoreError> {
    let access = runtime_checkpoint_dependency_on_connection(connection, checkpoint_id)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                format!("checkpoint {checkpoint_id} has no dependency binding"),
            )
        })?;
    let RuntimeCheckpointDependencyBinding::Authenticated {
        dependency_generation_id,
        trust_anchor_id,
        canonical_bytes_sha256,
        ..
    } = access.binding
    else {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} has only a legacy dependency binding"),
        ));
    };
    let Some(RuntimeDependencyGenerationByteState::VerifiedAvailable { canonical_custody }) =
        access.byte_state
    else {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} dependency bytes are unavailable or corrupt"),
        ));
    };
    if dependency_generation_id != reservation.dependency_generation_id
        || trust_anchor_id != reservation.trust_anchor_id
        || canonical_bytes_sha256 != reservation.dependency_generation_custody_digest
        || sha256_bytes(canonical_custody.as_bytes())
            != reservation.dependency_generation_custody_digest
    {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} dependency identity differs from reservation"),
        ));
    }
    Ok(())
}

fn governed_closure_v2_capacity_bound_from_exact_prelaunch(
    reservation_reference: GovernedClosureRecordReference,
    prelaunch: GovernedClosurePrelaunchInput,
    execution_launch_record_id: Sha256Digest,
    dependency_generation_id: &Sha256Digest,
    dependency_generation_custody_digest: &Sha256Digest,
    trust_anchor_id: &Sha256Digest,
    maximum_diagnostic_canonical_bytes: u64,
) -> Result<u64, StoreError> {
    let digest = sha256_bytes(b"governed V2 fixed-width capacity placeholder");
    let other_digest = sha256_bytes(b"governed V2 distinct evaluator artifact placeholder");
    // A quote has the largest JSON expansion among non-control one-byte
    // characters admitted by the bounded identity law.
    let maximum_text = "\"".repeat(MAX_GOVERNED_CLOSURE_TEXT_BYTES);
    let provider_intake = GovernedClosureRecordReference {
        schema: "nq.provider_intake.v1".into(),
        record_id: digest.clone(),
        bytes_digest: digest.clone(),
    };
    let execution_binding = GovernedClosureRecordReference {
        schema: "nq.execution_identity_binding.v2".into(),
        record_id: digest.clone(),
        bytes_digest: digest.clone(),
    };
    let document = GovernedExecutionCustodyClosureV2Document {
        schema: GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA,
        closure_id: digest.clone(),
        reservation: reservation_reference,
        prelaunch,
        acquisition: GovernedClosureAcquisitionInput {
            execution_launch_record_id,
            provider_intake: provider_intake.clone(),
            intake_id: maximum_text.clone(),
            raw_provider_bytes_digest: digest.clone(),
        },
        derivation: GovernedClosureDerivationInput {
            derivation_id: digest.clone(),
            dependency_generation_id: dependency_generation_id.clone(),
            dependency_generation_custody_digest: dependency_generation_custody_digest.clone(),
            trust_anchor_id: trust_anchor_id.clone(),
            evaluation_id: Some(maximum_text.clone()),
            profile_semantic_id: digest.clone(),
            evaluator_semantic_digest: digest.clone(),
            evaluator_artifact_digest: other_digest,
            derived_at: maximum_text.clone(),
            clock_identity: digest.clone(),
            clock_qualification_digest: digest.clone(),
        },
        diagnostic: Value::Null,
        local_origin: GovernedClosureLocalOriginInput {
            run_id: maximum_text.clone(),
            evaluation_id: Some(maximum_text.clone()),
            completed_at: maximum_text,
        },
        execution_binding: execution_binding.clone(),
        runtime_records: vec![provider_intake, execution_binding],
        dependency_generation: GovernedClosureDependencyGenerationInput {
            checkpoint_id: digest.clone(),
            checkpoint_digest: digest.clone(),
            generation_id: dependency_generation_id.clone(),
            trust_anchor_id: trust_anchor_id.clone(),
            custody_bytes_digest: dependency_generation_custody_digest.clone(),
        },
    };
    let template = canonical_json_bytes(&document).map_err(|error| {
        StoreError::Invariant(format!(
            "governed V2 capacity template cannot be encoded: {error}"
        ))
    })?;
    let template_length = u64::try_from(template.len())
        .map_err(|_| StoreError::Invariant("governed V2 template length overflowed".into()))?;
    template_length
        .checked_sub(u64::try_from(b"null".len()).expect("fixed null length"))
        .and_then(|length| length.checked_add(maximum_diagnostic_canonical_bytes))
        .ok_or_else(|| StoreError::Invariant("governed V2 capacity bound overflowed".into()))
}

fn governed_closure_embedded_diagnostic_length(
    exact_closure_bytes: &[u8],
) -> Result<u64, StoreError> {
    let closure: Value = serde_json::from_slice(exact_closure_bytes).map_err(|error| {
        StoreError::Invariant(format!(
            "governed closure cannot be decoded for diagnostic capacity: {error}"
        ))
    })?;
    let diagnostic = closure.get("diagnostic").ok_or_else(|| {
        StoreError::Invariant(
            "governed closure has no diagnostic for component-capacity verification".into(),
        )
    })?;
    let exact_diagnostic = canonical_json_bytes(diagnostic).map_err(|error| {
        StoreError::Invariant(format!(
            "governed closure diagnostic cannot be canonically sized: {error}"
        ))
    })?;
    u64::try_from(exact_diagnostic.len())
        .map_err(|_| StoreError::Invariant("governed diagnostic length overflowed".into()))
}

fn governed_reservation_capacity_components(
    reservation_record: &RuntimeRecordRow,
) -> Result<(u64, u64), StoreError> {
    let value: Value = serde_json::from_slice(reservation_record.canonical_bytes.as_bytes())
        .map_err(|error| {
            StoreError::Integrity(format!(
                "custody reservation {} cannot be decoded: {error}",
                reservation_record.record_id
            ))
        })?;
    let components = value
        .get("component_bounds")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StoreError::Integrity(format!(
                "custody reservation {} has no component bounds",
                reservation_record.record_id
            ))
        })?;
    let component = |name: &str| {
        components.get(name).and_then(Value::as_u64).ok_or_else(|| {
            StoreError::Integrity(format!(
                "custody reservation {} has no exact {name} component",
                reservation_record.record_id
            ))
        })
    };
    let diagnostic = component("diagnostic_artifact_bytes")?;
    let raw = component("raw_evidence_bytes")?;
    let dependency = component("dependency_closure_bytes")?;
    let reserved = value
        .get("reserved_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            StoreError::Integrity(format!(
                "custody reservation {} has no exact reserved_bytes",
                reservation_record.record_id
            ))
        })?;
    let final_capacity = reserved
        .checked_sub(raw)
        .and_then(|remaining| remaining.checked_sub(dependency))
        .filter(|capacity| *capacity > 0)
        .ok_or_else(|| {
            StoreError::Integrity(format!(
                "custody reservation {} cannot derive a positive final partition",
                reservation_record.record_id
            ))
        })?;
    Ok((diagnostic, final_capacity))
}

#[allow(clippy::too_many_lines)] // The native deadline/launch join is intentionally explicit.
fn verify_native_launch_checkpoint(
    reservation_record_id: &Sha256Digest,
    deadline_record: &RuntimeRecordRow,
    launch_record: &RuntimeRecordRow,
    reservation_checkpoint_records: &[RuntimeRecordRow],
    outer_request_record: &RuntimeRecordRow,
    invocation_decision_record: &RuntimeRecordRow,
    reservation_record: &RuntimeRecordRow,
) -> Result<(), StoreError> {
    let deadline = exact_json_value(reservation_record_id, deadline_record)?;
    let launch = exact_json_value(reservation_record_id, launch_record)?;
    let deadline_reference = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/prelaunch_checks/deadline",
    )?;
    let launch_outer_request = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/outer_request",
    )?;
    let launch_decision = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/invocation_decision",
    )?;
    let launch_reservation = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/custody_reservation",
    )?;
    let deadline_outer_request = exact_json_reference(
        reservation_record_id,
        deadline_record,
        &deadline,
        "/outer_request",
    )?;
    let deadline_activation = exact_json_reference(
        reservation_record_id,
        deadline_record,
        &deadline,
        "/activation",
    )?;
    let launch_activation = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/activation_snapshot",
    )?;
    let clock_qualification = exact_json_reference(
        reservation_record_id,
        deadline_record,
        &deadline,
        "/clock_qualification",
    )?;

    let exact_topology_reference = |reference: &ExactRuntimeRecordReference, schema: &str| {
        reference.schema == schema
            && reservation_checkpoint_records
                .iter()
                .any(|record| reference.matches(record))
    };
    let deadline_violations_are_empty = deadline
        .pointer("/decision/violations")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    if !deadline_reference.matches(deadline_record)
        || deadline_reference.schema != "nq.deadline_evaluation.v1"
        || !launch_outer_request.matches(outer_request_record)
        || !deadline_outer_request.matches(outer_request_record)
        || !launch_decision.matches(invocation_decision_record)
        || !launch_reservation.matches(reservation_record)
        || deadline_activation != launch_activation
        || !exact_topology_reference(&deadline_activation, "nq.runtime_activation.v1")
        || !exact_topology_reference(&clock_qualification, "nq.native_clock_qualification.v1")
        || deadline.pointer("/decision/state").and_then(Value::as_str) != Some("accepted")
        || !deadline_violations_are_empty
        || deadline.pointer("/derived/launched_at") != launch.get("launched_at")
        || deadline.pointer("/derived/attempt_deadline") != launch.get("attempt_deadline")
        || deadline.get("clock") != launch.get("clock")
        || deadline.pointer("/request_bounds/maximum_execution_ms")
            != launch.get("maximum_execution_ms")
    {
        return Err(projection_integrity(
            reservation_record_id,
            "native deadline provenance or its exact deadline-to-launch join differs",
        ));
    }
    Ok(())
}

fn checkpoint_runtime_records(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    checkpoint: &RuntimeLedgerCheckpoint,
) -> Result<Vec<RuntimeRecordRow>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT record_id FROM runtime_record_ledger
         WHERE checkpoint_id = ?1 ORDER BY record_sequence",
    )?;
    statement
        .query_map([&checkpoint.checkpoint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|record_id| {
            runtime_record_by_id_on_connection(connection, &record_id)?.ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    format!(
                        "checkpoint {} lost runtime record {record_id}",
                        checkpoint.checkpoint_id
                    ),
                )
            })
        })
        .collect()
}

fn exact_json_string(
    reservation_record_id: &Sha256Digest,
    record: &RuntimeRecordRow,
    field: &str,
) -> Result<Option<String>, StoreError> {
    let value = exact_json_value(reservation_record_id, record)?;
    Ok(value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

fn exact_json_value(
    reservation_record_id: &Sha256Digest,
    record: &RuntimeRecordRow,
) -> Result<Value, StoreError> {
    serde_json::from_slice(record.canonical_bytes.as_bytes()).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!(
                "runtime record {} cannot be decoded: {error}",
                record.record_id
            ),
        )
    })
}

fn exact_json_reference(
    reservation_record_id: &Sha256Digest,
    record: &RuntimeRecordRow,
    value: &Value,
    pointer: &str,
) -> Result<ExactRuntimeRecordReference, StoreError> {
    serde_json::from_value(value.pointer(pointer).cloned().ok_or_else(|| {
        projection_integrity(
            reservation_record_id,
            format!(
                "runtime record {} has no exact reference at {pointer}",
                record.record_id
            ),
        )
    })?)
    .map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!(
                "runtime record {} has an invalid exact reference at {pointer}: {error}",
                record.record_id
            ),
        )
    })
}

fn exact_runtime_record(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    reference: &ExactRuntimeRecordReference,
    label: &str,
) -> Result<RuntimeRecordRow, StoreError> {
    let record = runtime_record_by_id_on_connection(connection, reference.record_id.as_str())?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                format!("{label} runtime record is absent"),
            )
        })?;
    if !reference.matches(&record) {
        return Err(projection_integrity(
            reservation_record_id,
            format!("{label} runtime record differs from its sealed reference"),
        ));
    }
    Ok(record)
}

fn verify_checkpoint_dependency(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    checkpoint_id: &str,
    expected: &GovernedProjectionDependencyGeneration,
    exact_dependency_bytes: &[u8],
) -> Result<(), StoreError> {
    let access = runtime_checkpoint_dependency_on_connection(connection, checkpoint_id)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                format!("checkpoint {checkpoint_id} has no dependency binding"),
            )
        })?;
    let RuntimeCheckpointDependencyBinding::Authenticated {
        dependency_generation_id,
        trust_anchor_id,
        canonical_bytes_sha256,
        ..
    } = access.binding
    else {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} has only a legacy dependency binding"),
        ));
    };
    let Some(RuntimeDependencyGenerationByteState::VerifiedAvailable { canonical_custody }) =
        access.byte_state
    else {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} dependency bytes are unavailable or corrupt"),
        ));
    };
    if dependency_generation_id != expected.generation_id
        || trust_anchor_id != expected.trust_anchor_id
        || canonical_bytes_sha256 != expected.custody_bytes_digest
        || canonical_custody.as_bytes() != exact_dependency_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            format!("checkpoint {checkpoint_id} dependency closure differs"),
        ));
    }
    Ok(())
}

fn projection_integrity(
    reservation_record_id: &Sha256Digest,
    message: impl std::fmt::Display,
) -> StoreError {
    StoreError::Integrity(format!(
        "governed projection {reservation_record_id} failed exact correspondence: {message}"
    ))
}

fn custody_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Invariant(format!("governed exact-byte custody failed: {error}"))
}

#[cfg(test)]
mod tests {
    use nq_protocol::{canonical_json_bytes, semantic_digest, sha256_bytes};
    use serde_json::{Map, Value, json};
    use tempfile::tempdir;

    use super::*;
    use crate::custody_arena::ArenaFailureCarrierCandidate;

    fn digest(label: &str) -> Sha256Digest {
        sha256_bytes(label.as_bytes())
    }

    fn reservation(dependency_bytes: &[u8]) -> GovernedCustodyReservation {
        GovernedCustodyReservation {
            reservation_record_id: digest("reservation"),
            reservation_manifest_digest: digest("reservation-manifest"),
            outer_request_record_id: digest("outer-request-record"),
            outer_request_id: "outer-request-001".into(),
            outer_request_digest: digest("outer-request"),
            dependency_generation_id: digest("dependency-generation"),
            dependency_generation_custody_digest: sha256_bytes(dependency_bytes),
            trust_anchor_id: digest("trust-anchor"),
            prelaunch_checkpoint_id: digest("prelaunch-checkpoint"),
            prelaunch_checkpoint_digest: digest("prelaunch-checkpoint-bytes"),
            dependency_closure_capacity_bytes: 4_096,
            raw_capacity_bytes: 4_096,
            diagnostic_artifact_capacity_bytes: 4_096,
            final_capacity_bytes: 4_096,
            protected_failure_capacity_bytes: 4_096,
        }
    }

    fn governed_reference(label: &str, schema: &str) -> GovernedClosureRecordReference {
        GovernedClosureRecordReference {
            schema: schema.to_owned(),
            record_id: digest(&format!("{label}-record")),
            bytes_digest: digest(&format!("{label}-bytes")),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn governed_v2_builder_fixture(
        label: &str,
        use_maximum_text: bool,
    ) -> (
        GovernedCustodyReservation,
        GovernedExecutionCustodyClosureV2Input,
        Vec<u8>,
    ) {
        let dependency_bytes = format!("exact dependency closure {label}").into_bytes();
        let mut reservation = reservation(&dependency_bytes);
        reservation.reservation_record_id = digest(&format!("{label}-reservation"));
        reservation.reservation_manifest_digest = digest(&format!("{label}-reservation-manifest"));
        reservation.outer_request_record_id = digest(&format!("{label}-outer-request"));
        reservation.outer_request_digest = digest(&format!("{label}-outer-request-bytes"));
        reservation.dependency_generation_id = digest(&format!("{label}-dependency-generation"));
        reservation.dependency_generation_custody_digest = sha256_bytes(&dependency_bytes);
        reservation.trust_anchor_id = digest(&format!("{label}-trust-anchor"));
        reservation.prelaunch_checkpoint_id = digest(&format!("{label}-reservation-checkpoint"));
        reservation.prelaunch_checkpoint_digest =
            digest(&format!("{label}-reservation-checkpoint-bytes"));

        let reservation_reference = GovernedClosureRecordReference {
            schema: "nq.custody_reservation.v1".into(),
            record_id: reservation.reservation_record_id.clone(),
            bytes_digest: reservation.reservation_manifest_digest.clone(),
        };
        let outer_request = GovernedClosureRecordReference {
            schema: "nq.diagnostic_invocation_request.v1".into(),
            record_id: reservation.outer_request_record_id.clone(),
            bytes_digest: reservation.outer_request_digest.clone(),
        };
        let invocation_decision =
            governed_reference(&format!("{label}-decision"), "nq.invocation_decision.v1");
        let execution_launch =
            governed_reference(&format!("{label}-launch"), "nq.execution_launch.v1");
        let provider_intake =
            governed_reference(&format!("{label}-provider"), "nq.provider_intake.v1");
        let execution_binding = governed_reference(
            &format!("{label}-binding"),
            "nq.execution_identity_binding.v2",
        );
        let text = if use_maximum_text {
            "\"".repeat(MAX_GOVERNED_CLOSURE_TEXT_BYTES)
        } else {
            format!("{label}-bounded")
        };
        let diagnostic = CanonicalDocument::from_serializable(&json!({
            "schema": "nq.diagnostic_execution.v2",
            "fixture": label,
            "padding": "diagnostic-payload",
        }))
        .expect("canonical diagnostic");
        let diagnostic_artifact_capacity_bytes =
            u64::try_from(diagnostic.as_bytes().len()).expect("bounded canonical diagnostic");
        let input = GovernedExecutionCustodyClosureV2Input {
            reservation: reservation_reference.clone(),
            prelaunch: GovernedClosurePrelaunchInput {
                outer_request: outer_request.clone(),
                invocation_decision: invocation_decision.clone(),
                reservation_checkpoint: GovernedClosureCheckpointInput {
                    checkpoint_id: reservation.prelaunch_checkpoint_id.clone(),
                    batch_digest: reservation.prelaunch_checkpoint_digest.clone(),
                    runtime_records: vec![
                        outer_request,
                        invocation_decision,
                        reservation_reference,
                    ],
                },
                launch_checkpoint: GovernedClosureCheckpointInput {
                    checkpoint_id: digest(&format!("{label}-launch-checkpoint")),
                    batch_digest: digest(&format!("{label}-launch-checkpoint-bytes")),
                    runtime_records: vec![execution_launch.clone()],
                },
            },
            acquisition: GovernedClosureAcquisitionInput {
                execution_launch_record_id: execution_launch.record_id,
                provider_intake: provider_intake.clone(),
                intake_id: text.clone(),
                raw_provider_bytes_digest: digest(&format!("{label}-raw-provider")),
            },
            derivation: GovernedClosureDerivationInput {
                derivation_id: digest(&format!("{label}-derivation")),
                dependency_generation_id: reservation.dependency_generation_id.clone(),
                dependency_generation_custody_digest: reservation
                    .dependency_generation_custody_digest
                    .clone(),
                trust_anchor_id: reservation.trust_anchor_id.clone(),
                evaluation_id: Some(text.clone()),
                profile_semantic_id: digest(&format!("{label}-profile-semantic")),
                evaluator_semantic_digest: digest(&format!("{label}-evaluator-semantic")),
                evaluator_artifact_digest: digest(&format!("{label}-evaluator-artifact")),
                derived_at: text.clone(),
                clock_identity: digest(&format!("{label}-clock")),
                clock_qualification_digest: digest(&format!("{label}-clock-qualification")),
            },
            diagnostic,
            diagnostic_artifact_capacity_bytes,
            local_origin: GovernedClosureLocalOriginInput {
                run_id: text.clone(),
                evaluation_id: Some(text.clone()),
                completed_at: text,
            },
            execution_binding: execution_binding.clone(),
            runtime_records: vec![provider_intake, execution_binding],
            dependency_generation: GovernedClosureDependencyGenerationInput {
                checkpoint_id: digest(&format!("{label}-final-checkpoint")),
                checkpoint_digest: digest(&format!("{label}-final-checkpoint-bytes")),
                generation_id: reservation.dependency_generation_id.clone(),
                trust_anchor_id: reservation.trust_anchor_id.clone(),
                custody_bytes_digest: reservation.dependency_generation_custody_digest.clone(),
            },
        };
        (reservation, input, dependency_bytes)
    }

    #[test]
    fn governed_v2_builder_derives_one_canonical_self_identity() {
        let (_, input, _) = governed_v2_builder_fixture("builder", false);
        let built =
            GovernedExecutionCustodyClosureV2::build(input.clone()).expect("typed V2 closure");
        let replay = GovernedExecutionCustodyClosureV2::build(input).expect("deterministic replay");
        assert_eq!(built, replay);
        assert_eq!(
            built.canonical_bytes().digest(),
            sha256_bytes(built.canonical_bytes().as_bytes()).as_str()
        );

        let value: Value =
            serde_json::from_slice(built.canonical_bytes().as_bytes()).expect("closure JSON");
        assert_eq!(value["schema"], GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA);
        assert!(value["derivation"].get("clock_uncertainty_ms").is_none());
        assert!(
            value["derivation"]
                .get("evaluator_semantic_digest")
                .is_some()
        );
        assert!(
            value["derivation"]
                .get("evaluator_artifact_digest")
                .is_some()
        );
        let mut preimage = value.as_object().expect("closure object").clone();
        preimage.remove("closure_id");
        assert_eq!(
            semantic_digest(&preimage).expect("closure self identity"),
            *built.closure_id()
        );
        assert_eq!(
            value["closure_id"],
            Value::String(built.closure_id().to_string())
        );
    }

    #[test]
    fn governed_v2_builder_rejects_storage_shape_and_join_substitution() {
        let (_, original, _) = governed_v2_builder_fixture("hostile-builder", false);

        let mut equal_evaluator_digests = original.clone();
        equal_evaluator_digests.derivation.evaluator_artifact_digest = equal_evaluator_digests
            .derivation
            .evaluator_semantic_digest
            .clone();
        GovernedExecutionCustodyClosureV2::build(equal_evaluator_digests)
            .expect("structural separation does not require unequal values");

        let mut unicode_boundary = original.clone();
        unicode_boundary.local_origin.run_id = "é".repeat(MAX_GOVERNED_CLOSURE_TEXT_BYTES / 2);
        GovernedExecutionCustodyClosureV2::build(unicode_boundary)
            .expect("maximum non-control UTF-8 identity remains admissible");

        let mut oversized_text = original.clone();
        oversized_text.local_origin.run_id = "x".repeat(MAX_GOVERNED_CLOSURE_TEXT_BYTES + 1);
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(oversized_text),
            Err(StoreError::Invariant(message)) if message.contains("1..=256")
        ));

        let mut duplicate_reservation_schema = original.clone();
        duplicate_reservation_schema
            .prelaunch
            .reservation_checkpoint
            .runtime_records
            .push(governed_reference(
                "duplicate-reservation",
                "nq.custody_reservation.v1",
            ));
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(duplicate_reservation_schema),
            Err(StoreError::Invariant(message)) if message.contains("omits or duplicates")
        ));

        let mut extraneous_launch = original.clone();
        extraneous_launch
            .prelaunch
            .launch_checkpoint
            .runtime_records
            .push(governed_reference(
                "extraneous-launch-member",
                "nq.host_role_lifecycle_event.v1",
            ));
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(extraneous_launch),
            Err(StoreError::Invariant(message)) if message.contains("deadline-plus-launch")
        ));

        let mut extra_terminal = original.clone();
        extra_terminal.runtime_records.push(governed_reference(
            "extra-terminal",
            "nq.host_role_lifecycle_event.v1",
        ));
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(extra_terminal),
            Err(StoreError::Invariant(message)) if message.contains("terminal write set")
        ));

        let mut dependency_substitution = original.clone();
        dependency_substitution.dependency_generation.generation_id =
            digest("substituted-generation");
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(dependency_substitution),
            Err(StoreError::Invariant(message)) if message.contains("do not join")
        ));

        let mut evaluation_substitution = original.clone();
        evaluation_substitution.local_origin.evaluation_id =
            Some("different-evaluation".to_owned());
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(evaluation_substitution),
            Err(StoreError::Invariant(message)) if message.contains("do not join")
        ));

        let mut wrong_contract = original;
        wrong_contract.diagnostic = CanonicalDocument::from_serializable(&json!({
            "schema": "nq.diagnostic_execution.v1",
        }))
        .expect("wrong canonical contract");
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(wrong_contract),
            Err(StoreError::Invariant(message)) if message.contains("diagnostic_execution.v2")
        ));

        let (_, mut undersized_diagnostic, _) =
            governed_v2_builder_fixture("undersized-diagnostic", false);
        undersized_diagnostic.diagnostic_artifact_capacity_bytes =
            u64::try_from(undersized_diagnostic.diagnostic.as_bytes().len())
                .expect("diagnostic length")
                - 1;
        assert!(matches!(
            GovernedExecutionCustodyClosureV2::build(undersized_diagnostic),
            Err(StoreError::Invariant(message)) if message.contains("component bound")
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn governed_v2_capacity_bound_is_exact_and_bound_minus_one_refuses() {
        let (mut reservation, input, dependency_bytes) =
            governed_v2_builder_fixture("capacity", true);
        let maximum_diagnostic_canonical_bytes =
            u64::try_from(input.diagnostic.as_bytes().len()).expect("diagnostic length");
        reservation.diagnostic_artifact_capacity_bytes = maximum_diagnostic_canonical_bytes;
        let capacity = governed_execution_custody_closure_v2_capacity_bound(
            &GovernedExecutionCustodyClosureV2CapacityInput {
                reservation: input.reservation.clone(),
                prelaunch: input.prelaunch.clone(),
                execution_launch_record_id: input.acquisition.execution_launch_record_id.clone(),
                dependency_generation_id: reservation.dependency_generation_id.clone(),
                dependency_generation_custody_digest: reservation
                    .dependency_generation_custody_digest
                    .clone(),
                trust_anchor_id: reservation.trust_anchor_id.clone(),
                diagnostic_artifact_capacity_bytes: maximum_diagnostic_canonical_bytes,
            },
        )
        .expect("capacity bound");
        assert_eq!(
            capacity.diagnostic_artifact_capacity_bytes,
            maximum_diagnostic_canonical_bytes
        );
        let bound = capacity.final_closure_capacity_bytes;
        let closure =
            GovernedExecutionCustodyClosureV2::build(input.clone()).expect("maximal closure");
        assert_eq!(
            u64::try_from(closure.canonical_bytes().as_bytes().len()).expect("closure length"),
            bound
        );

        reservation.final_capacity_bytes = bound;
        let directory = tempdir().expect("exact-capacity directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let mut exact =
            GovernedCustody::reserve(&database, reservation.clone(), dependency_bytes.as_slice())
                .expect("exact-capacity reservation");
        exact
            .claim_launch(
                input.acquisition.execution_launch_record_id.clone(),
                "2026-07-29T22:29:00Z".into(),
            )
            .expect("claim exact launch");
        exact
            .seal_acquisition(GovernedAcquisitionCustodyInput {
                execution_launch_record_id: input.acquisition.execution_launch_record_id.clone(),
                provider_intake_record_id: input.acquisition.provider_intake.record_id.clone(),
                exact_provider_intake_bytes: b"provider".to_vec(),
                exact_raw_provider_bytes: b"raw".to_vec(),
            })
            .expect("seal exact acquisition");
        exact
            .claim_derivation(GovernedDerivationCustodyClaim {
                derivation_id: input.derivation.derivation_id.clone(),
                dependency_generation_id: input.derivation.dependency_generation_id.clone(),
                dependency_generation_custody_digest: input
                    .derivation
                    .dependency_generation_custody_digest
                    .clone(),
                trust_anchor_id: input.derivation.trust_anchor_id.clone(),
                // The physical capacity test does not assert the later
                // semantic projection join; keep the arena header compact.
                evaluation_id: Some("capacity-evaluation".into()),
                profile_semantic_id: input.derivation.profile_semantic_id.clone(),
                evaluator_identity_digest: input.derivation.evaluator_semantic_digest.clone(),
                evaluator_artifact_digest: input.derivation.evaluator_artifact_digest.clone(),
                derived_at: "2026-07-29T22:30:00Z".into(),
                clock_identity: input.derivation.clock_identity.clone(),
                clock_qualification_digest: input.derivation.clock_qualification_digest.clone(),
            })
            .expect("claim exact derivation");
        let commitment = exact
            .seal_final_closure(closure.canonical_bytes().as_bytes().to_vec())
            .expect("exact bound accepts closure");
        assert_eq!(commitment.byte_length, bound);

        let mut short_reservation = reservation.clone();
        let short_input = input;
        let short_dependency_bytes = dependency_bytes;
        let short_closure = closure;
        assert_eq!(
            u64::try_from(short_closure.canonical_bytes().as_bytes().len())
                .expect("short closure length"),
            bound
        );
        short_reservation.final_capacity_bytes = bound - 1;
        let short_database = directory.path().join("nq-short.db");
        create_database_placeholder(&short_database);
        let mut short = GovernedCustody::reserve(
            &short_database,
            short_reservation.clone(),
            short_dependency_bytes.as_slice(),
        )
        .expect("short reservation");
        short
            .claim_launch(
                short_input.acquisition.execution_launch_record_id.clone(),
                "2026-07-29T22:29:00Z".into(),
            )
            .expect("claim short launch");
        short
            .seal_acquisition(GovernedAcquisitionCustodyInput {
                execution_launch_record_id: short_input
                    .acquisition
                    .execution_launch_record_id
                    .clone(),
                provider_intake_record_id: short_input
                    .acquisition
                    .provider_intake
                    .record_id
                    .clone(),
                exact_provider_intake_bytes: b"provider".to_vec(),
                exact_raw_provider_bytes: b"raw".to_vec(),
            })
            .expect("seal short acquisition");
        short
            .claim_derivation(GovernedDerivationCustodyClaim {
                derivation_id: short_input.derivation.derivation_id.clone(),
                dependency_generation_id: short_input.derivation.dependency_generation_id.clone(),
                dependency_generation_custody_digest: short_input
                    .derivation
                    .dependency_generation_custody_digest
                    .clone(),
                trust_anchor_id: short_input.derivation.trust_anchor_id.clone(),
                evaluation_id: Some("capacity-evaluation".into()),
                profile_semantic_id: short_input.derivation.profile_semantic_id.clone(),
                evaluator_identity_digest: short_input.derivation.evaluator_semantic_digest.clone(),
                evaluator_artifact_digest: short_input.derivation.evaluator_artifact_digest.clone(),
                derived_at: "2026-07-29T22:30:00Z".into(),
                clock_identity: short_input.derivation.clock_identity.clone(),
                clock_qualification_digest: short_input
                    .derivation
                    .clock_qualification_digest
                    .clone(),
            })
            .expect("claim short derivation");
        assert!(matches!(
            short.seal_final_closure(short_closure.canonical_bytes().as_bytes().to_vec()),
            Err(StoreError::Invariant(message)) if message.contains("capacity is")
        ));
        drop(short);
        let short =
            GovernedCustody::open(&short_database, short_reservation).expect("reopen short arena");
        assert_eq!(
            short.state().expect("short state"),
            GovernedCustodyState::DerivationClaimed
        );
    }

    fn create_database_placeholder(path: &Path) {
        std::fs::File::create(path).expect("database placeholder");
    }

    fn protected_failure_bytes(
        reservation: &GovernedCustodyReservation,
        launch: &Sha256Digest,
    ) -> Vec<u8> {
        let mut value = Map::new();
        value.insert(
            "schema".into(),
            Value::String("nq.governed_custody_failure.v1".into()),
        );
        value.insert(
            "reservation_id".into(),
            Value::String(reservation.reservation_record_id.to_string()),
        );
        value.insert(
            "outer_request_id".into(),
            Value::String(reservation.outer_request_id.clone()),
        );
        value.insert("claim_id".into(), Value::String(launch.as_str().to_owned()));
        value.insert(
            "outcome".into(),
            Value::String("indeterminate_write_refusal".into()),
        );
        value.insert(
            "failed_at".into(),
            Value::String("2026-07-29T22:30:00Z".into()),
        );
        let failure_id = semantic_digest(&value).expect("failure identity");
        value.insert("failure_id".into(), Value::String(failure_id.to_string()));
        canonical_json_bytes(&value).expect("failure carrier")
    }

    fn terminal_input(
        launch: &Sha256Digest,
        class: GovernedProtectedTerminalClass,
        reason_code: &str,
    ) -> GovernedProtectedTerminalInput {
        GovernedProtectedTerminalInput {
            execution_launch_record_id: launch.clone(),
            terminal_class: class,
            reason: GovernedProtectedTerminalReason {
                code: reason_code.into(),
                detail: format!("exact {reason_code} detail"),
            },
            launch_attempt_deadline: "2026-07-29T22:31:00Z".into(),
            terminalized_at: "2026-07-29T22:30:00Z".into(),
            deadline_compliance: GovernedProtectedTerminalDeadlineCompliance::WithinDeadline,
        }
    }

    #[test]
    fn immediate_terminal_is_canonical_typed_custody_only_and_exactly_idempotent() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("protected-terminal-launch");
        let mut custody = GovernedCustody::reserve(&database, reservation.clone(), dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");
        let input = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PreEffectRefusal,
            "native_clock_correspondence_unavailable",
        );
        let committed = custody
            .terminalize_immediate_launch(input.clone())
            .expect("immediate terminal");
        assert_eq!(
            committed.disposition,
            GovernedProtectedTerminalDisposition::Terminalized
        );
        assert_eq!(
            committed.terminal.document().reservation.record_id,
            reservation.reservation_record_id
        );
        assert_eq!(
            committed.terminal.document().outer_request.record_id,
            reservation.outer_request_record_id
        );
        assert_eq!(
            committed.terminal.document().execution_launch_record_id,
            launch
        );
        assert_eq!(
            committed.terminal.document().deadline_compliance,
            GovernedProtectedTerminalDeadlineCompliance::WithinDeadline
        );
        let value: Value =
            serde_json::from_slice(committed.terminal.exact_bytes()).expect("terminal JSON");
        assert_eq!(value["standing"], "custody_only");
        assert!(value.get("diagnostic_outcome").is_none());
        assert!(value.get("reliance").is_none());
        assert!(value.get("authorization").is_none());
        assert!(value.get("action").is_none());
        assert_eq!(
            canonical_json_bytes(&value).expect("canonical terminal"),
            committed.terminal.exact_bytes()
        );
        assert_eq!(
            sha256_bytes(committed.terminal.exact_bytes()),
            committed.commitment.bytes_digest
        );

        let replay = custody
            .terminalize_immediate_launch(input)
            .expect("exact replay is idempotent");
        assert_eq!(
            replay.disposition,
            GovernedProtectedTerminalDisposition::AlreadyTerminalized
        );
        assert_eq!(replay.terminal, committed.terminal);
        assert_eq!(
            custody
                .protected_terminal()
                .expect("typed terminal read")
                .expect("terminal present"),
            committed.terminal
        );

        let changed = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PreEffectRefusal,
            "different_refusal",
        );
        assert!(matches!(
            custody.terminalize_immediate_launch(changed),
            Err(StoreError::Invariant(message))
                if message.contains("already terminalized by different exact bytes")
        ));
    }

    #[test]
    fn protected_terminal_substitution_and_wrong_launch_fail_closed() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("exact-launch");
        let wrong_launch = digest("wrong-launch");
        let mut custody = GovernedCustody::reserve(&database, reservation.clone(), dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");
        assert!(matches!(
            custody.terminalize_immediate_launch(terminal_input(
                &wrong_launch,
                GovernedProtectedTerminalClass::PreEffectRefusal,
                "wrong_launch"
            )),
            Err(StoreError::Invariant(message))
                if message.contains("launch identity differs")
        ));
        assert_eq!(
            custody.state().expect("state"),
            GovernedCustodyState::LaunchClaimed
        );

        let terminal = GovernedProtectedTerminal::create(
            &reservation,
            "2026-07-29T22:29:00Z".into(),
            terminal_input(
                &launch,
                GovernedProtectedTerminalClass::PreEffectRefusal,
                "substitution",
            ),
        )
        .expect("terminal");
        let mut value: Value =
            serde_json::from_slice(terminal.exact_bytes()).expect("terminal JSON");
        value["reservation"]["record_id"] = Value::String(digest("substituted").to_string());
        let mut preimage = value.as_object().expect("object").clone();
        preimage.remove("terminal_id");
        value["terminal_id"] = Value::String(
            semantic_digest(&preimage)
                .expect("substituted self identity")
                .to_string(),
        );
        let substituted = canonical_json_bytes(&value).expect("substituted canonical bytes");
        GovernedProtectedTerminal::from_exact_bytes(substituted.clone())
            .expect("substitution remains internally self-consistent");
        let candidate = ArenaFailureCarrierCandidate::parse_protected_terminal(substituted)
            .expect("typed candidate");
        assert!(matches!(
            custody
                .arena
                .seal_failure(candidate, ArenaState::FailedIndeterminate),
            Err(crate::custody_arena::ArenaError::Invalid(message))
                if message.contains("differs from reservation")
        ));
    }

    #[test]
    fn postlaunch_failure_remains_distinct_from_pre_effect_refusal() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("postlaunch-failure-launch");
        let mut custody = GovernedCustody::reserve(&database, reservation, dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");
        custody
            .seal_acquisition(GovernedAcquisitionCustodyInput {
                execution_launch_record_id: launch.clone(),
                provider_intake_record_id: digest("postlaunch-provider-intake"),
                exact_provider_intake_bytes: b"exact provider intake".to_vec(),
                exact_raw_provider_bytes: b"partial raw response".to_vec(),
            })
            .expect("seal acquisition");

        assert!(matches!(
            custody.terminalize_immediate_launch(terminal_input(
                &launch,
                GovernedProtectedTerminalClass::PreEffectRefusal,
                "late_pre_effect_label"
            )),
            Err(StoreError::Invariant(message))
                if message.contains("after acquisition custody")
        ));
        let terminal = custody
            .terminalize_immediate_launch(terminal_input(
                &launch,
                GovernedProtectedTerminalClass::PostlaunchFailure,
                "evaluation_cannot_close",
            ))
            .expect("postlaunch protected terminal");
        assert_eq!(
            terminal.terminal.document().terminal_class,
            GovernedProtectedTerminalClass::PostlaunchFailure
        );
        assert_eq!(
            terminal.terminal.document().reason.code,
            "evaluation_cannot_close"
        );
        assert_eq!(
            custody.state().expect("state"),
            GovernedCustodyState::FailedIndeterminate
        );
    }

    #[test]
    fn reopened_inflight_launch_cannot_substitute_time_for_a_recovery_fence() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("recovery-launch");
        let mut custody = GovernedCustody::reserve(&database, reservation.clone(), dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");
        drop(custody);

        let mut reopened =
            GovernedCustody::open(&database, reservation).expect("reopen in-flight custody");
        let timely = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PostlaunchFailure,
            "recovery_without_fence",
        );
        assert!(matches!(
            reopened.terminalize_immediate_launch(timely),
            Err(StoreError::Invariant(message))
                if message.contains("no exact no-further-execution fence")
        ));

        let mut late = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PostlaunchFailure,
            "late_recovery_is_not_a_fence",
        );
        late.terminalized_at = "2026-07-29T22:32:00Z".into();
        late.deadline_compliance =
            GovernedProtectedTerminalDeadlineCompliance::DeadlineReachedOrExceeded;
        assert!(matches!(
            reopened.terminalize_immediate_launch(late),
            Err(StoreError::Invariant(message))
                if message.contains("no exact no-further-execution fence")
        ));
        assert_eq!(
            reopened.state().expect("state"),
            GovernedCustodyState::LaunchClaimed
        );
    }

    #[test]
    fn deadline_assessment_is_exact_and_not_inferred_or_refreshed() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("deadline-launch");
        let mut custody = GovernedCustody::reserve(&database, reservation.clone(), dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");

        let mut contradictory = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PreEffectRefusal,
            "contradictory_deadline",
        );
        contradictory.deadline_compliance =
            GovernedProtectedTerminalDeadlineCompliance::DeadlineReachedOrExceeded;
        assert!(matches!(
            custody.terminalize_immediate_launch(contradictory),
            Err(StoreError::Invariant(message))
                if message.contains("deadline assessment contradicts")
        ));

        let mut unknown = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PreEffectRefusal,
            "clock_correspondence_missing",
        );
        unknown.deadline_compliance = GovernedProtectedTerminalDeadlineCompliance::NotEstablished;
        let committed = custody
            .terminalize_immediate_launch(unknown)
            .expect("explicitly unestablished deadline");
        drop(custody);
        let reopened = GovernedCustody::open(&database, reservation).expect("reopen terminal");
        let reopened_terminal = reopened
            .protected_terminal()
            .expect("typed terminal read")
            .expect("terminal present");
        assert_eq!(
            reopened_terminal.document().deadline_compliance,
            GovernedProtectedTerminalDeadlineCompliance::NotEstablished
        );
        assert_eq!(reopened_terminal, committed.terminal);
    }

    #[test]
    fn startup_inventory_and_protected_failure_read_preserve_terminal_bytes() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        let store = Store::initialize(&database).expect("store");
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("launch");
        let mut custody = GovernedCustody::reserve(&database, reservation.clone(), dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");
        let exact_failure = protected_failure_bytes(&reservation, &launch);
        custody
            .arena
            .seal_failure(
                ArenaFailureCarrierCandidate::parse_precursor(exact_failure.clone())
                    .expect("failure precursor"),
                ArenaState::FailedIndeterminate,
            )
            .expect("terminal protected failure");
        drop(custody);

        let inventory = store
            .governed_custody_inventory()
            .expect("startup inventory");
        let [GovernedCustodyInventoryEntry::Verified(frontier)] = inventory.as_slice() else {
            panic!("one verified frontier");
        };
        assert_eq!(
            frontier.recovery_class,
            GovernedCustodyRecoveryClass::ProtectedFailure
        );
        assert_eq!(
            frontier.reservation_ledger_binding,
            GovernedCustodyReservationLedgerBinding::NoCommittedReservation
        );
        assert_eq!(
            frontier.protected_failure,
            Some(GovernedCustodyCommitment {
                bytes_digest: sha256_bytes(&exact_failure),
                byte_length: u64::try_from(exact_failure.len()).expect("failure length"),
            })
        );
        let reopened = store
            .governed_protected_failure(&reservation.reservation_record_id)
            .expect("protected failure read");
        let GovernedProtectedFailureAccess::VerifiedAvailable(reopened) = reopened else {
            panic!("protected failure exists");
        };
        assert_eq!(reopened.exact_bytes, exact_failure);
        assert_eq!(reopened.bytes_digest, sha256_bytes(&reopened.exact_bytes));
    }
}
