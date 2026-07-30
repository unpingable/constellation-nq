//! Opaque exact-byte custody for one governed diagnostic invocation.
//!
//! This module deliberately exposes storage mechanics only. A Store-owned
//! verifier may advance the physical index frontier only after exact arena/SQL
//! correspondence is reopened from a reservation identity. It does not
//! establish native provider correspondence, an evaluator occurrence,
//! diagnostic semantic validity, reliance, or authority; those semantic checks
//! belong to `nq-core` and its consumers.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::cell::RefCell;

use chrono::{DateTime, Utc};
use nq_host_role_contract::{IdentityRef, RecordRef, Timestamp, Token};
use nq_host_role_dependency_custody::{
    AuthenticatedRuntimeDependencyClosure, AuthoritySourcePurpose, AuthoritySourceRequirement,
    AuthoritySourceState, ExactDependencyCustodyBinding, ExternalDependencyAvailability,
    ExternalSourcePurpose, ExternalSourceRequirement, ExternalSourceState,
};
use nq_protocol::{
    GovernedDerivationIdentityInput, GovernedDerivationRecordRef, Sha256Digest,
    canonical_json_bytes, governed_derivation_identity, semantic_digest, sha256_bytes,
};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::custody_arena::{
    AcquisitionCarrier, ArenaFailureCarrierCandidate, ArenaInventoryEntry, ArenaLayout,
    ArenaPrelaunchBinding, ArenaState, ArenaStateInventoryEntry, CustodyArena, DerivationClaim,
    DerivedV2ClosureCandidate, FinalSealIntentDisposition, acquisition_carrier_capacity_bound,
};
use crate::governed_projection_capsule::{
    GovernedProjectionCapsule, GovernedProjectionCapsuleInput, ReopenedGovernedProjectionPlan,
};
use crate::{
    CanonicalDocument, DiagnosticArtifactByteState, DiagnosticArtifactLookup,
    DiagnosticArtifactOrigin, MAX_PUBLIC_QUERY_ROWS, RuntimeCheckpointDependencyBinding,
    RuntimeDependencyGenerationByteState, RuntimeLedgerCheckpoint, RuntimeRecordRow, Store,
    StoreError, canonical_document_schema, diagnostic_artifact_execution_binding_on_connection,
    diagnostic_artifact_on_connection, runtime_checkpoint_by_id_on_connection,
    runtime_checkpoint_dependency_on_connection, runtime_dependency_trust_root_on_connection,
    runtime_record_batch_digest, runtime_record_by_id_on_connection,
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
/// Restart-recoverable closure that binds the exact inert SQL projection
/// capsule staged before final physical sealing.
pub const GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA: &str = "nq.governed_execution_custody_closure.v3";
const GOVERNED_PROJECTION_CORRESPONDENCE_REFUSAL_SCHEMA: &str =
    "nq.governed_projection_correspondence_refusal.v1";

const MAX_GOVERNED_CLOSURE_TEXT_BYTES: usize = 256;
const MAX_PROJECTION_REFUSAL_DETAIL_BYTES: usize = 1_024;

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

/// Complete input for a restart-recoverable V3 custody closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedExecutionCustodyClosureV3Input {
    pub v2: GovernedExecutionCustodyClosureV2Input,
    pub projection_capsule: GovernedProjectionCapsule,
    pub projection_capsule_capacity_bytes: u64,
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
    pub projection_capsule_capacity_bytes: u64,
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

/// Conservative V3 bound: the exact V2 envelope plus the complete declared
/// projection-capsule capacity physically embedded in the final section.
#[allow(dead_code)] // Publicly re-exported contract helper; product path uses the committed verifier.
pub fn governed_execution_custody_closure_v3_capacity_bound(
    input: &GovernedExecutionCustodyClosureV2CapacityInput,
) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> {
    let mut capacity = governed_execution_custody_closure_v2_capacity_bound(input)?;
    if input.projection_capsule_capacity_bytes == 0 {
        return Err(StoreError::Invariant(
            "projection capsule capacity must be positive".into(),
        ));
    }
    let capsule_field_length = u64::try_from(b",\"projection_capsule\":".len())
        .map_err(|_| StoreError::Invariant("V3 capsule field length overflowed".into()))?;
    let capsule_length = capsule_field_length
        .checked_add(input.projection_capsule_capacity_bytes)
        .ok_or_else(|| StoreError::Invariant("V3 capsule bound length overflowed".into()))?;
    capacity.final_closure_capacity_bytes = capacity
        .final_closure_capacity_bytes
        .checked_add(capsule_length)
        .ok_or_else(|| StoreError::Invariant("V3 final closure capacity overflowed".into()))?;
    Ok(capacity)
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

#[derive(Serialize)]
struct GovernedExecutionCustodyClosureV3Preimage {
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
    projection_capsule: Value,
}

#[derive(Serialize)]
struct GovernedExecutionCustodyClosureV3Document {
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
    projection_capsule: Value,
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

/// Exact canonical V3 closure with the complete inert projection capsule
/// physically embedded in the preallocated final section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedExecutionCustodyClosureV3 {
    closure_id: Sha256Digest,
    canonical_bytes: CanonicalDocument,
}

impl GovernedExecutionCustodyClosureV3 {
    pub fn build(input: GovernedExecutionCustodyClosureV3Input) -> Result<Self, StoreError> {
        validate_governed_closure_v2_input(&input.v2)?;
        if input.projection_capsule.reservation_record_id() != &input.v2.reservation.record_id {
            return Err(StoreError::Invariant(
                "governed V3 projection capsule differs from the exact reservation".into(),
            ));
        }
        let capsule_length = u64::try_from(
            input.projection_capsule.canonical_bytes().as_bytes().len(),
        )
        .map_err(|_| StoreError::Invariant("projection capsule length overflowed".into()))?;
        if capsule_length == 0 || capsule_length > input.projection_capsule_capacity_bytes {
            return Err(StoreError::Invariant(format!(
                "governed V3 projection capsule requires {capsule_length} bytes but exact pre-effect capacity is {}",
                input.projection_capsule_capacity_bytes
            )));
        }
        let diagnostic: Value = serde_json::from_slice(input.v2.diagnostic.as_bytes())
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        let capsule: Value =
            serde_json::from_slice(input.projection_capsule.canonical_bytes().as_bytes())
                .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        let preimage = GovernedExecutionCustodyClosureV3Preimage {
            schema: GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA,
            reservation: input.v2.reservation,
            prelaunch: input.v2.prelaunch,
            acquisition: input.v2.acquisition,
            derivation: input.v2.derivation,
            diagnostic,
            local_origin: input.v2.local_origin,
            execution_binding: input.v2.execution_binding,
            runtime_records: input.v2.runtime_records,
            dependency_generation: input.v2.dependency_generation,
            projection_capsule: capsule,
        };
        let closure_id =
            semantic_digest(&preimage).map_err(|error| StoreError::Invariant(error.to_string()))?;
        let document = GovernedExecutionCustodyClosureV3Document {
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
            projection_capsule: preimage.projection_capsule,
        };
        Ok(Self {
            closure_id,
            canonical_bytes: CanonicalDocument::from_serializable(&document)?,
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
    /// Exact reservation component available for the physically embedded
    /// restart projection capsule.
    pub projection_capsule_capacity_bytes: u64,
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
        if self.projection_capsule_capacity_bytes == 0 {
            return Err(StoreError::Invariant(
                "governed custody projection capsule capacity must be positive".into(),
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
    FinalSealIntent,
    FinalClosureIndexPending,
    FinalClosureIndexed,
    FinalClosureProjectionRefused,
    FinalClosureCommittedUnavailable,
    FinalClosureCorrupt,
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
            ArenaState::FinalV2SealIntent => Self::FinalSealIntent,
            ArenaState::FinalV2SealedIndexPending => Self::FinalClosureIndexPending,
            ArenaState::FinalV2SealedIndexed => Self::FinalClosureIndexed,
            ArenaState::FinalV2ProjectionRefused => Self::FinalClosureProjectionRefused,
            ArenaState::FinalV2SealCommittedUnavailable => Self::FinalClosureCommittedUnavailable,
            ArenaState::FinalV2SealCorrupt => Self::FinalClosureCorrupt,
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
    /// Exact final bytes were committed by identity before their physical
    /// frame was adjudicated.
    FinalSealAwaitingAdjudication,
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
    /// Exact final bytes remain available, but their Store projection failed a
    /// deterministic cross-correspondence gate and is terminally refused.
    FinalClosureProjectionRefused,
    /// A durable final-seal intent had no exact physical frame on recovery.
    FinalClosureCommittedUnavailable,
    /// A durable final-seal intent reopened with a substituted or corrupt
    /// physical frame.
    FinalClosureCorrupt,
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
            ArenaState::FinalV2SealIntent => Self::FinalSealAwaitingAdjudication,
            ArenaState::FinalV2SealedIndexPending => Self::FinalClosureAwaitingProjection,
            ArenaState::FinalV2SealedIndexed => Self::Indexed,
            ArenaState::FinalV2ProjectionRefused => Self::FinalClosureProjectionRefused,
            ArenaState::FinalV2SealCommittedUnavailable => Self::FinalClosureCommittedUnavailable,
            ArenaState::FinalV2SealCorrupt => Self::FinalClosureCorrupt,
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
/// recomputes or refreshes the assessment. Its retained wall-clock instants
/// make no ordering claim; the one-use physical custody transition establishes
/// that terminalization followed the launch claim.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GovernedProjectionVerificationPhase {
    /// SQL rows exist only inside the caller-owned transaction and may still
    /// be rolled back before a projection-local refusal is made durable.
    UncommittedReplay,
    /// SQL rows are already durable. A disagreement is global correspondence
    /// corruption and cannot be blamed on, or terminalize, the sealed arena.
    DurableProjection,
}

/// Restart result for one exact sealed V3 projection.
///
/// Unavailable or corrupt capsule custody leaves the arena index-pending and
/// never reruns provider, profile, or evaluator semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernedProjectionRecovery {
    Recovered(GovernedProjectionVerification),
    AlreadyIndexed(GovernedProjectionVerification),
    CapsuleCommittedUnavailable {
        reservation_record_id: Sha256Digest,
        capsule_id: Sha256Digest,
    },
    CapsuleCorrupt {
        reservation_record_id: Sha256Digest,
        reason: String,
    },
    CorrespondenceRefused {
        reservation_record_id: Sha256Digest,
        refusal_id: Sha256Digest,
        reason: String,
    },
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
        let evaluation_matches = match (
            self.evaluation_id.as_ref(),
            claim.evaluation_id.as_ref(),
            claim.evaluation_id_digest.as_ref(),
        ) {
            (None, None, None) => true,
            (Some(expected), Some(observed), None) => expected == observed,
            (Some(expected), None, Some(observed)) => {
                sha256_bytes(expected.as_bytes()) == *observed
            }
            _ => false,
        };
        self.derivation_id == claim.derivation_id
            && self.dependency_generation_id == claim.dependency_generation_id
            && self.dependency_generation_custody_digest
                == claim.dependency_generation_custody_digest
            && self.trust_anchor_id == claim.trust_anchor_id
            && evaluation_matches
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
    #[serde(default)]
    projection_capsule: Option<Value>,
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
            evaluation_id_digest: value
                .evaluation_id
                .as_ref()
                .map(|identity| sha256_bytes(identity.as_bytes())),
            evaluation_id: None,
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
    let ordering_matches = match compliance {
        GovernedProtectedTerminalDeadlineCompliance::WithinDeadline => {
            terminalized >= claimed && terminalized < deadline
        }
        GovernedProtectedTerminalDeadlineCompliance::DeadlineReachedOrExceeded => {
            terminalized >= claimed && terminalized >= deadline
        }
        // These are wall-clock representations. When the governed runtime has
        // not established their correspondence, a backwards clock step after
        // the physical launch claim must not strand the one-use occurrence.
        // The physical custody transition supplies occurrence ordering; this
        // carrier deliberately makes no deadline-compliance claim.
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
    pub(crate) fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub(crate) fn reservation_record_id(&self) -> &Sha256Digest {
        &self.reservation.reservation_record_id
    }

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

    /// Reopen only the durable custody frontier after an indeterminate
    /// physical write on this same one-use handle.
    ///
    /// This grants no provider retry, derivation, projection, or diagnostic
    /// authority. It permits the original launch owner to distinguish a
    /// pre-final frontier from a committed final-seal frontier.
    pub fn reopen_state_after_indeterminate_write(
        &mut self,
    ) -> Result<GovernedCustodyState, StoreError> {
        self.arena
            .reopen_after_indeterminate_write()
            .map(Into::into)
            .map_err(custody_error)
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
    pub(crate) fn seal_final_closure(
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
    /// commit but before provider effect. It verifies committed SQL
    /// correspondence and storage sizing only. It deliberately does not
    /// reopen the arena: the prepared invocation retains the exact live
    /// custody handle across this call, and this sizing result grants no arena
    /// authority.
    #[allow(clippy::too_many_lines)]
    pub fn verify_governed_execution_custody_closure_v2_capacity(
        &self,
        reservation: &GovernedCustodyReservation,
        launch_checkpoint_id: &Sha256Digest,
    ) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> {
        self.verify_governed_execution_custody_closure_capacity_on_one_snapshot(
            reservation,
            launch_checkpoint_id,
            false,
        )
    }

    /// Verify the same committed prelaunch frontier against the larger V3
    /// envelope that physically embeds the bounded projection capsule.
    pub fn verify_governed_execution_custody_closure_v3_capacity(
        &self,
        reservation: &GovernedCustodyReservation,
        launch_checkpoint_id: &Sha256Digest,
    ) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> {
        self.verify_governed_execution_custody_closure_capacity_on_one_snapshot(
            reservation,
            launch_checkpoint_id,
            true,
        )
    }

    /// Select, authenticate, and size one V2 or provisional V3 closure under a
    /// single SQLite snapshot.
    ///
    /// The physical reservation binds `projected_bytes`; the caller cannot
    /// select that component after source authentication. This closes the
    /// Store correspondence boundary only. It does not establish the later C1
    /// claim that the provisional projection component is the final pure
    /// closed V3 capsule-bound manifest.
    #[allow(clippy::too_many_lines)]
    fn verify_governed_execution_custody_closure_capacity_on_one_snapshot(
        &self,
        reservation: &GovernedCustodyReservation,
        launch_checkpoint_id: &Sha256Digest,
        include_projection_capsule: bool,
    ) -> Result<GovernedExecutionCustodyClosureV2Capacity, StoreError> {
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
        let (diagnostic_capacity, projection_capsule_capacity, final_capacity) =
            governed_reservation_capacity_components(reservation_record)?;
        if diagnostic_capacity != reservation.diagnostic_artifact_capacity_bytes
            || projection_capsule_capacity != reservation.projection_capsule_capacity_bytes
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
        verify_declared_physical_launch_checkpoint(
            &reservation.reservation_record_id,
            &launch_records,
            launch_record,
            &reservation_records,
            outer_request_record,
            invocation_decision_record,
            reservation_record,
        )?;
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
        let authenticated_sources = resolve_authenticated_physical_prelaunch_sources(
            &snapshot,
            &reservation.reservation_record_id,
            &reservation_checkpoint,
            &reservation_records,
            outer_request_record,
            invocation_decision_record,
            reservation_record,
            &launch_checkpoint,
            launch_record,
            None,
        )?;
        let capacity_input = GovernedExecutionCustodyClosureV2CapacityInput {
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
            projection_capsule_capacity_bytes: projection_capsule_capacity,
        };
        let capacity = if include_projection_capsule {
            governed_execution_custody_closure_v3_capacity_bound(&capacity_input)
        } else {
            governed_execution_custody_closure_v2_capacity_bound(&capacity_input)
        }?;
        if capacity.final_closure_capacity_bytes > final_capacity {
            return Err(projection_integrity(
                &reservation.reservation_record_id,
                format!(
                    "{} final closure requires {} bytes but exact reservation provides {final_capacity}",
                    if include_projection_capsule {
                        "V3"
                    } else {
                        "V2"
                    },
                    capacity.final_closure_capacity_bytes
                ),
            ));
        }
        drop(authenticated_sources);
        drop(snapshot);
        Ok(capacity)
    }

    /// Recover the exact SQL projection bound into one sealed V3 closure.
    ///
    /// Recovery decodes only the inert store-owned capsule and replays the
    /// existing atomic Store commit.  It never invokes a provider, profile, or
    /// evaluator and never changes a diagnostic result.
    #[allow(clippy::too_many_lines)]
    pub fn recover_governed_projection_and_mark_indexed(
        &mut self,
        reservation_record_id: &Sha256Digest,
    ) -> Result<GovernedProjectionRecovery, StoreError> {
        let database_path = self.path().ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "projection recovery requires a filesystem-backed initialized store",
            )
        })?;
        let arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "physical custody arena is absent")
            })?;
        let inspection = arena.inspection().map_err(custody_error)?;
        let state = inspection.state;
        if state == ArenaState::FinalV2ProjectionRefused {
            let refusal_error =
                verified_projection_refusal_with_arena(&arena, reservation_record_id)?
                    .0
                    .as_store_error();
            return projection_refusal_recovery(refusal_error);
        }
        drop(arena);
        if state == ArenaState::FinalV2SealedIndexed {
            return self
                .verify_governed_projection_and_mark_indexed(reservation_record_id)
                .map(GovernedProjectionRecovery::AlreadyIndexed);
        }
        if state != ArenaState::FinalV2SealedIndexPending {
            return Err(projection_integrity(
                reservation_record_id,
                format!("arena state {state:?} has no sealed projection to recover"),
            ));
        }

        if let Err(error) = self.commit_reopened_governed_projection(reservation_record_id) {
            return match error {
                error @ StoreError::GovernedProjectionCorrespondenceRefused { .. } => {
                    projection_refusal_recovery(error)
                }
                error => Err(error),
            };
        }
        let verification =
            self.verify_governed_projection_and_mark_indexed(reservation_record_id)?;
        Ok(match verification.disposition {
            GovernedProjectionVerificationDisposition::Indexed => {
                GovernedProjectionRecovery::Recovered(verification)
            }
            GovernedProjectionVerificationDisposition::AlreadyIndexed => {
                GovernedProjectionRecovery::AlreadyIndexed(verification)
            }
        })
    }

    /// Recover every exact final-pending V3 projection visible at resident
    /// execution startup.
    ///
    /// The scan is bounded by the ordinary custody-inventory limit. Exact V3
    /// plans are ordered by their sealed global status sequence and replayed
    /// in one SQLite IMMEDIATE transaction, the same publication frontier used
    /// by every ordinary writer. Pre-V3, unreadable, corrupt, gapped, or
    /// substituted pending fronts refuse startup; they remain inspectable
    /// through the read-only custody inventory and never fabricate a
    /// projection.
    ///
    /// Every attempted recovery is Store-owned and therefore cannot invoke a
    /// provider, profile, evaluator, schedule, or external consumer.
    #[allow(clippy::too_many_lines)] // Recovery keeps the one locked replay/terminalization transaction legible.
    pub fn recover_pending_governed_projections(
        &mut self,
    ) -> Result<Vec<GovernedProjectionRecovery>, StoreError> {
        let database_path = self.path().map(Path::to_path_buf).ok_or_else(|| {
            StoreError::Invariant(
                "projection startup recovery requires a filesystem-backed initialized store".into(),
            )
        })?;
        let mut recovered = Vec::new();
        loop {
            let transaction = self.immediate_recovery_transaction()?;
            let adjudicated = adjudicate_final_seal_intents(&database_path)?;
            if let Some(terminal) = adjudicated
                .iter()
                .find(|entry| entry.disposition != FinalSealIntentDisposition::Promoted)
            {
                return Err(projection_integrity(
                    &terminal.reservation_record_id,
                    format!(
                        "durable final-seal intent reached terminal custody state {:?}",
                        terminal.disposition
                    ),
                ));
            }
            let pending = match pending_v3_projection_plans(&database_path, &transaction) {
                Ok(pending) => pending,
                Err(error @ StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }) => {
                    let terminal = terminalize_projection_local_mismatch(&database_path, &error)?;
                    transaction.commit()?;
                    recovered.push(projection_refusal_recovery(terminal)?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            if pending.is_empty() {
                drop(pending);
                transaction.commit()?;
                break;
            }
            if let Err(error) =
                crate::preflight_reopened_governed_projection_batch(&transaction, &pending)
            {
                if matches!(
                    error,
                    StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }
                ) {
                    let terminal = terminalize_projection_local_mismatch(&database_path, &error)?;
                    drop(pending);
                    transaction.commit()?;
                    recovered.push(projection_refusal_recovery(terminal)?);
                    continue;
                }
                return Err(error);
            }
            // One explicit SAVEPOINT owns the complete replay batch. A typed
            // local mismatch may become a physical terminal refusal only
            // after rollback and RELEASE both succeed, while the outer
            // IMMEDIATE publication fence remains held.
            crate::begin_governed_projection_replay_savepoint(&transaction)?;
            let mut local_mismatch = None;
            for projection in &pending {
                crate::replay_reopened_governed_projection_on_transaction(
                    &transaction,
                    &projection.reservation_record_id,
                    &projection.plan,
                )?;
                if let Err(error) = crate::maybe_inject_governed_projection_post_insert_test_fault(
                    &transaction,
                    &projection.reservation_record_id,
                ) {
                    if matches!(
                        error,
                        StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }
                    ) {
                        local_mismatch = Some(error);
                        break;
                    }
                    return Err(error);
                }
                if let Err(error) = verify_pending_governed_projection_on_connection(
                    &transaction,
                    &database_path,
                    projection,
                    match projection.sql_footprint {
                        crate::GovernedProjectionSqlFootprint::Absent => {
                            GovernedProjectionVerificationPhase::UncommittedReplay
                        }
                        crate::GovernedProjectionSqlFootprint::ExistingExact => {
                            GovernedProjectionVerificationPhase::DurableProjection
                        }
                    },
                ) {
                    if matches!(
                        error,
                        StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }
                    ) {
                        local_mismatch = Some(error);
                        break;
                    }
                    return Err(error);
                }
            }
            if let Some(error) = local_mismatch {
                crate::rollback_and_release_governed_projection_replay_savepoint(&transaction)?;
                let terminal = terminalize_projection_local_mismatch(&database_path, &error)?;
                drop(pending);
                transaction.commit()?;
                recovered.push(projection_refusal_recovery(terminal)?);
                continue;
            }
            crate::release_governed_projection_replay_savepoint(&transaction)?;
            let pending_ids = pending
                .iter()
                .map(|projection| projection.reservation_record_id.clone())
                .collect::<Vec<_>>();
            drop(pending);
            transaction.commit()?;

            for reservation_record_id in pending_ids {
                let verification =
                    self.verify_governed_projection_and_mark_indexed(&reservation_record_id)?;
                recovered.push(match verification.disposition {
                    GovernedProjectionVerificationDisposition::Indexed => {
                        GovernedProjectionRecovery::Recovered(verification)
                    }
                    GovernedProjectionVerificationDisposition::AlreadyIndexed => {
                        GovernedProjectionRecovery::AlreadyIndexed(verification)
                    }
                });
            }
            break;
        }
        Ok(recovered)
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
        let snapshot = self.connection.unchecked_transaction()?;
        let verification = Self::verify_governed_projection_on_connection(
            &snapshot,
            database_path,
            reservation_record_id,
            GovernedProjectionVerificationPhase::DurableProjection,
            true,
        )?;
        snapshot.commit()?;
        Ok(verification)
    }

    #[allow(clippy::too_many_lines)] // One closed comparison keeps omissions auditable.
    fn verify_governed_projection_on_connection(
        connection: &rusqlite::Connection,
        database_path: &Path,
        reservation_record_id: &Sha256Digest,
        phase: GovernedProjectionVerificationPhase,
        mark_indexed: bool,
    ) -> Result<GovernedProjectionVerification, StoreError> {
        Self::verify_governed_projection_on_connection_with_sources(
            connection,
            database_path,
            reservation_record_id,
            phase,
            mark_indexed,
            None,
        )
    }

    #[allow(clippy::too_many_lines)] // One closed comparison keeps omissions auditable.
    fn verify_governed_projection_on_connection_with_sources<'snapshot>(
        connection: &'snapshot rusqlite::Connection,
        database_path: &Path,
        reservation_record_id: &Sha256Digest,
        phase: GovernedProjectionVerificationPhase,
        mark_indexed: bool,
        sources: Option<&IndependentGovernedProjectionSources<'snapshot>>,
    ) -> Result<GovernedProjectionVerification, StoreError> {
        let mut arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(reservation_record_id, "physical custody arena is absent")
            })?;
        let exact_closure_bytes = if mark_indexed {
            arena.final_v2_closure_bytes().map_err(custody_error)?
        } else {
            None
        };
        let verification = Self::verify_governed_projection_with_arena(
            connection,
            reservation_record_id,
            &mut arena,
            phase,
            mark_indexed,
            sources,
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
        drop(arena);
        if mark_indexed
            && verification.disposition == GovernedProjectionVerificationDisposition::Indexed
        {
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
                || reopened.final_v2_closure_bytes().map_err(custody_error)? != exact_closure_bytes
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "indexed transition did not durably preserve the exact closure",
                ));
            }
        }
        Ok(verification)
    }

    #[allow(clippy::too_many_lines)] // One closed comparison keeps omissions auditable.
    fn verify_governed_projection_with_arena<'snapshot>(
        connection: &'snapshot rusqlite::Connection,
        reservation_record_id: &Sha256Digest,
        arena: &mut CustodyArena,
        phase: GovernedProjectionVerificationPhase,
        mark_indexed: bool,
        sources: Option<&IndependentGovernedProjectionSources<'snapshot>>,
    ) -> Result<GovernedProjectionVerification, StoreError> {
        // V3 correspondence is checked against physical custody and the
        // committed prelaunch ledger before this verifier is allowed to rely
        // on any SQL result rows. Recovery uses this exact same gate before it
        // inserts those rows.
        let _ = match sources {
            Some(sources) => prevalidate_governed_v3_projection_with_sources(
                connection,
                reservation_record_id,
                arena,
                sources,
            ),
            None => prevalidate_governed_v3_projection_with_arena(
                connection,
                reservation_record_id,
                arena,
            ),
        }
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
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
            GOVERNED_CUSTODY_CLOSURE_SCHEMA
                | GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA
                | GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA
        ) {
            return Err(projection_integrity(
                reservation_record_id,
                "final closure schema differs",
            ));
        }

        // Callers either hold the global IMMEDIATE writer fence or consume an
        // already-committed append-only snapshot. The arena sections are
        // themselves sealed and immutable at these frontiers.
        validate_runtime_record_ledger(connection)?;
        validate_provider_intake_invariants(connection)?;
        validate_diagnostic_artifact_invariants(connection)?;
        let sealed_projection_capsule = match (closure.schema.as_str(), &closure.projection_capsule)
        {
            (GOVERNED_CUSTODY_CLOSURE_SCHEMA | GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA, None) => None,
            (GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA, Some(sealed_capsule)) => {
                let capsule_bytes = canonical_json_bytes(sealed_capsule).map_err(|error| {
                    projection_integrity(
                        reservation_record_id,
                        format!("embedded projection capsule is not canonicalizable: {error}"),
                    )
                })?;
                let capsule =
                    GovernedProjectionCapsule::decode(capsule_bytes).map_err(|error| {
                        projection_integrity(
                            reservation_record_id,
                            format!("embedded projection capsule is corrupt: {error}"),
                        )
                    })?;
                if capsule.reservation_record_id() != reservation_record_id {
                    return Err(projection_integrity(
                        reservation_record_id,
                        "embedded projection capsule reservation differs",
                    ));
                }
                Some(capsule)
            }
            _ => {
                return Err(projection_integrity(
                    reservation_record_id,
                    "projection capsule presence is incompatible with closure schema",
                ));
            }
        };

        let reservation_record = exact_runtime_record(
            connection,
            reservation_record_id,
            &closure.reservation,
            "custody reservation",
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
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
        let (diagnostic_capacity, projection_capsule_capacity, final_capacity) =
            governed_reservation_capacity_components(&reservation_record)?;
        let embedded_diagnostic_length =
            governed_closure_embedded_diagnostic_length(&exact_closure_bytes)?;
        let embedded_capsule_length = sealed_projection_capsule
            .as_ref()
            .map(|capsule| {
                u64::try_from(capsule.canonical_bytes().as_bytes().len()).map_err(|_| {
                    projection_integrity(
                        reservation_record_id,
                        "embedded projection capsule length overflowed",
                    )
                })
            })
            .transpose()?
            .unwrap_or(0);
        if final_capacity != inspection.layout.final_capacity()
            || embedded_diagnostic_length > diagnostic_capacity
            || embedded_capsule_length > projection_capsule_capacity
        {
            return Err(projection_integrity(
                reservation_record_id,
                "diagnostic, projection capsule, or final closure capacity differs from exact reservation custody",
            ));
        }
        let outer_request_record = exact_runtime_record(
            connection,
            reservation_record_id,
            &closure.prelaunch.outer_request,
            "outer request",
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
        let invocation_decision_record = exact_runtime_record(
            connection,
            reservation_record_id,
            &closure.prelaunch.invocation_decision,
            "accepted invocation decision",
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
        let (reservation_checkpoint, reservation_checkpoint_records) = exact_checkpoint(
            connection,
            reservation_record_id,
            &closure.prelaunch.reservation_checkpoint,
            "reservation",
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
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
            connection,
            reservation_record_id,
            &closure.prelaunch.launch_checkpoint,
            "launch",
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
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
        verify_declared_physical_launch_checkpoint(
            reservation_record_id,
            &launch_checkpoint_records,
            launch_record,
            &reservation_checkpoint_records,
            &outer_request_record,
            &invocation_decision_record,
            &reservation_record,
        )?;
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
            GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA | GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA => closure
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
            GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA | GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA => {
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
            connection,
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
            connection,
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
        if let Some(capsule) = &sealed_projection_capsule {
            let exact_diagnostic = CanonicalDocument::from_canonical_bytes(
                canonical_json_bytes(&closure.diagnostic).map_err(|error| {
                    projection_integrity(
                        reservation_record_id,
                        format!("embedded diagnostic cannot be canonicalized: {error}"),
                    )
                })?,
            )?;
            let plan =
                capsule.reopen_plan(&acquisition.exact_raw_provider_bytes, exact_diagnostic)?;
            validate_reopened_projection_plan(
                reservation_record_id,
                &closure,
                &acquisition,
                &plan,
            )?;
            let (acknowledgment, canonical_result) = crate::provider_acknowledgment_for_intake(
                connection,
                &plan.collection.intake.intake_id,
            )?
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "sealed capsule acknowledgment SQL row is absent",
                )
            })?;
            let receipt =
                crate::collection_receipt_for_run(connection, &plan.collection.run.run_id)?;
            let publication = crate::governed_projection_publication(
                connection,
                &receipt,
                &plan.status,
                &acknowledgment,
            )?;
            if publication != plan.publication
                || canonical_result.as_bytes() != plan.status.detail.as_bytes()
                || !crate::status_event_matches(
                    connection,
                    &plan.status,
                    &plan.collection.run.run_id,
                )?
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "sealed capsule report, status, or acknowledgment publication differs from SQL",
                ));
            }
        }
        let provider_projection = connection
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
        let checkpoint =
            runtime_checkpoint_by_id_on_connection(connection, checkpoint_id.as_str())?
                .ok_or_else(|| {
                    projection_integrity(reservation_record_id, "projection checkpoint is absent")
                })?;
        let checkpoint_records =
            checkpoint_runtime_records(connection, reservation_record_id, &checkpoint)?;
        if checkpoint.predecessor_checkpoint_id.as_deref()
            != Some(launch_checkpoint.checkpoint_id.as_str())
            || checkpoint.predecessor_ledger_root.as_ref()
                != Some(&launch_checkpoint.checkpoint_ledger_root)
            || checkpoint.batch_digest != closure.dependency_generation.checkpoint_digest
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
            connection,
            reservation_record_id,
            &reservation_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
        verify_checkpoint_dependency(
            connection,
            reservation_record_id,
            &launch_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
        verify_checkpoint_dependency(
            connection,
            reservation_record_id,
            &checkpoint.checkpoint_id,
            &closure.dependency_generation,
            &dependency_bytes,
        )
        .map_err(|error| projection_error_for_phase(reservation_record_id, phase, error))?;
        if mark_indexed && disposition == GovernedProjectionVerificationDisposition::Indexed {
            let token = arena.reopen_final_token().map_err(custody_error)?;
            arena.mark_indexed(token).map_err(custody_error)?;
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
        return Err(projection_local_mismatch(
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
        return Err(projection_local_mismatch(
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
    let canonical_custody = match access.byte_state {
        Some(RuntimeDependencyGenerationByteState::VerifiedAvailable { canonical_custody }) => {
            canonical_custody
        }
        Some(RuntimeDependencyGenerationByteState::CommittedUnavailable) => {
            return Err(projection_integrity(
                reservation_record_id,
                format!(
                    "checkpoint {checkpoint_id} runtime dependency payload is committed-unavailable"
                ),
            ));
        }
        Some(RuntimeDependencyGenerationByteState::Corrupt { reason }) => {
            return Err(projection_integrity(
                reservation_record_id,
                format!(
                    "checkpoint {checkpoint_id} runtime dependency payload is corrupt or substituted: {reason}"
                ),
            ));
        }
        None => {
            return Err(projection_integrity(
                reservation_record_id,
                format!("checkpoint {checkpoint_id} has no dependency byte state"),
            ));
        }
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
) -> Result<(u64, u64, u64), StoreError> {
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
    let projection_capsule = component("projected_bytes")?;
    if projection_capsule == 0 {
        return Err(StoreError::Integrity(format!(
            "custody reservation {} has no positive projected_bytes component",
            reservation_record.record_id
        )));
    }
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
    Ok((diagnostic, projection_capsule, final_capacity))
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
        return Err(projection_local_mismatch(
            reservation_record_id,
            "native deadline provenance or its exact deadline-to-launch join differs",
        ));
    }
    Ok(())
}

/// Verify the exact physical launch checkpoint from the launch record's own
/// declared shape.
///
/// `prelaunch_checks` absent is the historical launch-only form. A present
/// declaration is native and must retain one exact deadline member. Physical
/// checkpoint cardinality never selects the interpretation: deleting a
/// declared native dependency cannot downgrade the launch into legacy form.
///
/// Every failure here compares independently custodied physical records and
/// is therefore global integrity, never an arena-local projection refusal.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One physical-checkpoint verifier preserves the exact launch correspondence boundary.
fn verify_declared_physical_launch_checkpoint(
    reservation_record_id: &Sha256Digest,
    launch_checkpoint_records: &[RuntimeRecordRow],
    launch_record: &RuntimeRecordRow,
    reservation_checkpoint_records: &[RuntimeRecordRow],
    outer_request_record: &RuntimeRecordRow,
    invocation_decision_record: &RuntimeRecordRow,
    reservation_record: &RuntimeRecordRow,
) -> Result<(), StoreError> {
    let launch = exact_json_value(reservation_record_id, launch_record)?;
    if launch.get("status").and_then(Value::as_str) != Some("launched") {
        return Err(projection_integrity(
            reservation_record_id,
            "physical execution launch status is not launched",
        ));
    }
    match launch.get("prelaunch_checks") {
        None => {
            const NATIVE_ONLY_TOP_LEVEL_FIELDS: [&str; 12] = [
                "attempt_deadline",
                "maximum_execution_ms",
                "clock",
                "activation_snapshot",
                "custody_reservation",
                "launch_id",
                "namespace",
                "node",
                "profile",
                "selected_witness_attachments",
                "launch_commit",
                "nonclaims",
            ];
            if let Some(field) = NATIVE_ONLY_TOP_LEVEL_FIELDS
                .into_iter()
                .find(|field| launch.get(*field).is_some())
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!("legacy physical launch declaration retains native-only field {field}"),
                ));
            }
            if launch_checkpoint_records.len() != 1
                || !checkpoint_has_unique_exact_record(
                    launch_checkpoint_records,
                    launch_record,
                    "nq.execution_launch.v1",
                )
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "legacy physical launch declaration requires one exact launch-only checkpoint",
                ));
            }
            let outer_request = exact_json_reference(
                reservation_record_id,
                launch_record,
                &launch,
                "/outer_request",
            )?;
            let invocation_decision = exact_json_reference(
                reservation_record_id,
                launch_record,
                &launch,
                "/invocation_decision",
            )?;
            if !outer_request.matches(outer_request_record)
                || !invocation_decision.matches(invocation_decision_record)
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "legacy physical launch request or decision reference differs from independent prelaunch custody",
                ));
            }
        }
        Some(Value::Object(prelaunch_checks)) => {
            const NATIVE_PRELAUNCH_CHECK_FIELDS: [&str; 6] = [
                "authentication",
                "invocation_authorization",
                "generation_match",
                "deadline",
                "capability",
                "custody",
            ];
            let unsupported = prelaunch_checks
                .keys()
                .find(|field| !NATIVE_PRELAUNCH_CHECK_FIELDS.contains(&field.as_str()));
            let missing = NATIVE_PRELAUNCH_CHECK_FIELDS
                .into_iter()
                .find(|field| !prelaunch_checks.contains_key(*field));
            if unsupported.is_some() || missing.is_some() {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!(
                        "native physical launch prelaunch_checks does not have the exact v1 key set (unsupported {unsupported:?}, missing {missing:?})"
                    ),
                ));
            }
            for field in [
                "authentication",
                "invocation_authorization",
                "generation_match",
                "capability",
                "custody",
            ] {
                let _ = exact_json_reference(
                    reservation_record_id,
                    launch_record,
                    &launch,
                    &format!("/prelaunch_checks/{field}"),
                )?;
            }
            let outer_request = exact_json_value(reservation_record_id, outer_request_record)?;
            let invocation_decision =
                exact_json_value(reservation_record_id, invocation_decision_record)?;
            let reservation = exact_json_value(reservation_record_id, reservation_record)?;
            for (field, source_record, source, source_pointer, source_label) in [
                (
                    "authentication",
                    outer_request_record,
                    &outer_request,
                    "/authentication_evidence",
                    "outer request authentication_evidence",
                ),
                (
                    "invocation_authorization",
                    outer_request_record,
                    &outer_request,
                    "/invocation_authorization",
                    "outer request invocation_authorization",
                ),
                (
                    "custody",
                    reservation_record,
                    &reservation,
                    "/reservation_commit",
                    "reservation reservation_commit",
                ),
            ] {
                let declared = exact_json_reference(
                    reservation_record_id,
                    launch_record,
                    &launch,
                    &format!("/prelaunch_checks/{field}"),
                )?;
                let expected = exact_json_reference(
                    reservation_record_id,
                    source_record,
                    source,
                    source_pointer,
                )?;
                if declared != expected {
                    return Err(projection_integrity(
                        reservation_record_id,
                        format!(
                            "native physical launch prelaunch check {field} differs from {source_label}"
                        ),
                    ));
                }
            }
            for (field, source_pointer) in [
                ("authentication_evidence", "/authentication_evidence"),
                ("invocation_authorization", "/invocation_authorization"),
            ] {
                let decision_reference = exact_json_reference(
                    reservation_record_id,
                    invocation_decision_record,
                    &invocation_decision,
                    &format!("/{field}"),
                )?;
                let request_reference = exact_json_reference(
                    reservation_record_id,
                    outer_request_record,
                    &outer_request,
                    source_pointer,
                )?;
                if decision_reference != request_reference {
                    return Err(projection_integrity(
                        reservation_record_id,
                        format!("accepted invocation decision {field} differs from outer request"),
                    ));
                }
            }
            // Decode the declaration before selecting a physical deadline.
            // This makes a missing or malformed member global even when the
            // checkpoint was also reduced to one launch record.
            let declared_deadline = exact_json_reference(
                reservation_record_id,
                launch_record,
                &launch,
                "/prelaunch_checks/deadline",
            )?;
            let deadline_records = launch_checkpoint_records
                .iter()
                .filter(|record| record.record_schema == "nq.deadline_evaluation.v1")
                .collect::<Vec<_>>();
            let [deadline_record] = deadline_records.as_slice() else {
                return Err(projection_integrity(
                    reservation_record_id,
                    "native physical launch declaration requires exactly one deadline record",
                ));
            };
            if launch_checkpoint_records.len() != 2
                || !checkpoint_has_unique_exact_record(
                    launch_checkpoint_records,
                    launch_record,
                    "nq.execution_launch.v1",
                )
                || declared_deadline.schema != "nq.deadline_evaluation.v1"
                || !declared_deadline.matches(deadline_record)
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "native physical launch declaration differs from its exact deadline-plus-launch checkpoint",
                ));
            }
            verify_native_launch_checkpoint(
                reservation_record_id,
                deadline_record,
                launch_record,
                reservation_checkpoint_records,
                outer_request_record,
                invocation_decision_record,
                reservation_record,
            )
            .map_err(globalize_projection_local_mismatch)?;
        }
        Some(_) => {
            return Err(projection_integrity(
                reservation_record_id,
                "physical launch prelaunch_checks declaration is not an object",
            ));
        }
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

fn host_role_record_ref(
    reservation_record_id: &Sha256Digest,
    reference: &ExactRuntimeRecordReference,
    label: &str,
) -> Result<RecordRef, StoreError> {
    Ok(RecordRef {
        schema: Token::parse(reference.schema.clone()).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("{label} schema is not one bounded contract token: {error}"),
            )
        })?,
        record_id: reference.record_id.clone(),
        bytes_digest: reference.bytes_digest.clone(),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One derivation preserves the exact prelaunch requirement closure.
fn derive_physical_prelaunch_requirements(
    reservation_record_id: &Sha256Digest,
    reservation_checkpoint_records: &[RuntimeRecordRow],
    outer_request_record: &RuntimeRecordRow,
    invocation_decision_record: &RuntimeRecordRow,
    reservation_record: &RuntimeRecordRow,
    launch_record: &RuntimeRecordRow,
) -> Result<PhysicalPrelaunchRequirements, StoreError> {
    if reservation_record.record_id != reservation_record_id.as_str() {
        return Err(projection_integrity(
            reservation_record_id,
            "Store-selected custody reservation identity differs",
        ));
    }
    let outer_request = exact_json_value(reservation_record_id, outer_request_record)?;
    let invocation_decision = exact_json_value(reservation_record_id, invocation_decision_record)?;
    let reservation = exact_json_value(reservation_record_id, reservation_record)?;
    let launch = exact_json_value(reservation_record_id, launch_record)?;

    let request_authentication = exact_json_reference(
        reservation_record_id,
        outer_request_record,
        &outer_request,
        "/authentication_evidence",
    )?;
    let decision_authentication = exact_json_reference(
        reservation_record_id,
        invocation_decision_record,
        &invocation_decision,
        "/authentication_evidence",
    )?;
    let launch_authentication = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/prelaunch_checks/authentication",
    )?;
    if request_authentication != decision_authentication
        || request_authentication != launch_authentication
    {
        return Err(projection_integrity(
            reservation_record_id,
            "invocation-authentication reference differs across request, decision, and launch",
        ));
    }

    let request_authorization = exact_json_reference(
        reservation_record_id,
        outer_request_record,
        &outer_request,
        "/invocation_authorization",
    )?;
    let decision_authorization = exact_json_reference(
        reservation_record_id,
        invocation_decision_record,
        &invocation_decision,
        "/invocation_authorization",
    )?;
    let launch_authorization = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/prelaunch_checks/invocation_authorization",
    )?;
    if request_authorization != decision_authorization
        || request_authorization != launch_authorization
    {
        return Err(projection_integrity(
            reservation_record_id,
            "operation-authorization reference differs across request, decision, and launch",
        ));
    }
    // Operation authorizations are classified by their closed purpose and
    // scope, not by schema membership alone: a valid full topology closure
    // also carries administrative and sensitive-read authorizations, which
    // remain visible as noncontributors. Exactly one invocation-purpose
    // candidate is required; any authorization outside the closed purpose
    // vocabulary, and any additional invocation-purpose authority, refuses.
    let mut invocation_authorizations = Vec::new();
    for authorization_record in reservation_checkpoint_records
        .iter()
        .filter(|record| record.record_schema == "nq.operation_authorization.v1")
    {
        let authorization = exact_json_value(reservation_record_id, authorization_record)?;
        let scope = authorization.get("scope").and_then(Value::as_str);
        let operation = authorization.get("operation").and_then(Value::as_str);
        match (scope, operation) {
            (Some("diagnostic_invocation"), Some("diagnostic.invoke")) => {
                invocation_authorizations.push(authorization_record);
            }
            (Some("administrative_lifecycle" | "sensitive_read"), _) => {}
            _ => {
                return Err(projection_integrity(
                    reservation_record_id,
                    "reservation checkpoint operation authorization carries no closed purpose",
                ));
            }
        }
    }
    let [operation_authorization_record] = invocation_authorizations.as_slice() else {
        return Err(projection_integrity(
            reservation_record_id,
            "reservation checkpoint requires exactly one materialized operation authorization",
        ));
    };
    if request_authorization.schema != "nq.operation_authorization.v1"
        || !request_authorization.matches(operation_authorization_record)
    {
        return Err(projection_integrity(
            reservation_record_id,
            "materialized operation authorization differs from the exact physical reference",
        ));
    }

    let reservation_commit = exact_json_reference(
        reservation_record_id,
        reservation_record,
        &reservation,
        "/reservation_commit",
    )?;
    let launch_custody = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/prelaunch_checks/custody",
    )?;
    if reservation_commit != launch_custody {
        return Err(projection_integrity(
            reservation_record_id,
            "custody reservation-commit reference differs between reservation and launch",
        ));
    }
    let generation_match = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/prelaunch_checks/generation_match",
    )?;
    let capability = exact_json_reference(
        reservation_record_id,
        launch_record,
        &launch,
        "/prelaunch_checks/capability",
    )?;

    let external = vec![
        (
            ExternalSourcePurpose::InvocationAuthentication,
            host_role_record_ref(
                reservation_record_id,
                &request_authentication,
                "invocation-authentication reference",
            )?,
        ),
        (
            ExternalSourcePurpose::GenerationMatch,
            host_role_record_ref(
                reservation_record_id,
                &generation_match,
                "generation-match reference",
            )?,
        ),
        (
            ExternalSourcePurpose::Capability,
            host_role_record_ref(reservation_record_id, &capability, "capability reference")?,
        ),
        (
            ExternalSourcePurpose::CustodyReservationCommit,
            host_role_record_ref(
                reservation_record_id,
                &reservation_commit,
                "custody-reservation-commit reference",
            )?,
        ),
    ];
    let authority = vec![
        (
            AuthoritySourcePurpose::InvocationAuthentication,
            host_role_record_ref(
                reservation_record_id,
                &request_authentication,
                "invocation-authentication authority reference",
            )?,
        ),
        (
            AuthoritySourcePurpose::OperationAuthorization,
            host_role_record_ref(
                reservation_record_id,
                &request_authorization,
                "operation-authorization authority reference",
            )?,
        ),
    ];

    Ok(PhysicalPrelaunchRequirements {
        outer_request_record_id: Sha256Digest::parse(outer_request_record.record_id.clone())
            .map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("outer-request runtime record identity is invalid: {error}"),
                )
            })?,
        invocation_decision_record_id: Sha256Digest::parse(
            invocation_decision_record.record_id.clone(),
        )
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("invocation-decision runtime record identity is invalid: {error}"),
            )
        })?,
        launch_record_id: Sha256Digest::parse(launch_record.record_id.clone()).map_err(
            |error| {
                projection_integrity(
                    reservation_record_id,
                    format!("execution-launch runtime record identity is invalid: {error}"),
                )
            },
        )?,
        external,
        authority,
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
        return Err(projection_local_mismatch(
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
    let canonical_custody = match access.byte_state {
        Some(RuntimeDependencyGenerationByteState::VerifiedAvailable { canonical_custody }) => {
            canonical_custody
        }
        Some(RuntimeDependencyGenerationByteState::CommittedUnavailable) => {
            return Err(projection_integrity(
                reservation_record_id,
                format!(
                    "checkpoint {checkpoint_id} runtime dependency payload is committed-unavailable"
                ),
            ));
        }
        Some(RuntimeDependencyGenerationByteState::Corrupt { reason }) => {
            return Err(projection_integrity(
                reservation_record_id,
                format!(
                    "checkpoint {checkpoint_id} runtime dependency payload is corrupt or substituted: {reason}"
                ),
            ));
        }
        None => {
            return Err(projection_integrity(
                reservation_record_id,
                format!("checkpoint {checkpoint_id} has no dependency byte state"),
            ));
        }
    };
    if dependency_generation_id != expected.generation_id
        || trust_anchor_id != expected.trust_anchor_id
        || canonical_bytes_sha256 != expected.custody_bytes_digest
        || canonical_custody.as_bytes() != exact_dependency_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "checkpoint {checkpoint_id} dependency closure is substituted or differs from sealed custody"
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One closed exact-plan comparison keeps omissions auditable.
fn validate_reopened_projection_plan(
    reservation_record_id: &Sha256Digest,
    closure: &GovernedProjectionClosure,
    acquisition: &AcquisitionCarrier,
    plan: &ReopenedGovernedProjectionPlan,
) -> Result<(), StoreError> {
    let exact_diagnostic = canonical_json_bytes(&closure.diagnostic).map_err(|error| {
        projection_local_mismatch(
            reservation_record_id,
            format!("sealed diagnostic cannot be canonicalized: {error}"),
        )
    })?;
    let artifact_id = closure
        .diagnostic
        .get("artifact_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            projection_local_mismatch(
                reservation_record_id,
                "sealed diagnostic artifact identity is absent",
            )
        })?;
    if plan.diagnostic.contract_schema != "nq.diagnostic_execution.v2"
        || plan.diagnostic.artifact_id.as_str() != artifact_id
        || plan.diagnostic.canonical_bytes.as_bytes() != exact_diagnostic
        || plan.diagnostic.local_origin.run_id != closure.local_origin.run_id
        || plan.diagnostic.local_origin.evaluation_id != closure.local_origin.evaluation_id
        || plan.diagnostic.local_origin.completed_at != closure.local_origin.completed_at
        || plan.collection.run.run_id != closure.local_origin.run_id
        || plan.status.component_kind != "diagnostic_execution"
        || plan.status.component_id != closure.local_origin.run_id
    {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule diagnostic, run, status, or local origin differs from sealed closure",
        ));
    }
    let binding = plan
        .diagnostic
        .local_origin
        .execution_binding
        .as_ref()
        .ok_or_else(|| {
            projection_local_mismatch(
                reservation_record_id,
                "capsule diagnostic has no production execution binding",
            )
        })?;
    if binding.execution_binding_record_id != closure.execution_binding.record_id.as_str()
        || binding.outer_request_record_id != closure.prelaunch.outer_request.record_id.as_str()
        || binding.invocation_decision_record_id
            != closure.prelaunch.invocation_decision.record_id.as_str()
        || binding.execution_launch_record_id
            != closure.acquisition.execution_launch_record_id.as_str()
        || binding.runtime_records.checkpoint_id
            != closure.dependency_generation.checkpoint_id.as_str()
        || runtime_record_batch_digest(&binding.runtime_records).map_err(|error| {
            projection_local_mismatch(
                reservation_record_id,
                format!("capsule terminal batch is invalid: {error}"),
            )
        })? != closure.dependency_generation.checkpoint_digest
        || binding.runtime_records.dependency.dependency_generation_id
            != closure.dependency_generation.generation_id
        || binding.runtime_records.dependency.trust_anchor_id
            != closure.dependency_generation.trust_anchor_id
        || sha256_bytes(
            binding
                .runtime_records
                .dependency
                .canonical_custody
                .as_bytes(),
        ) != closure.dependency_generation.custody_bytes_digest
    {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule execution binding or terminal checkpoint differs from sealed closure",
        ));
    }
    if binding.runtime_records.records.len() != closure.runtime_records.len()
        || binding
            .runtime_records
            .records
            .iter()
            .zip(&closure.runtime_records)
            .any(|(record, expected)| {
                record.record_id != expected.record_id.as_str()
                    || record.record_schema != expected.schema
                    || record.canonical_bytes.digest() != expected.bytes_digest.as_str()
            })
    {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule terminal write set differs from sealed ordered membership",
        ));
    }
    let provider_record_id =
        crate::provider_intake_record_id(&plan.collection.intake).map_err(|error| {
            projection_local_mismatch(
                reservation_record_id,
                format!("capsule provider record identity is invalid: {error}"),
            )
        })?;
    if provider_record_id != closure.acquisition.provider_intake.record_id
        || provider_record_id != acquisition.provider_intake_record_id
        || plan.collection.intake.intake_id != closure.acquisition.intake_id
        || plan.collection.intake.raw_bytes != acquisition.exact_raw_provider_bytes
        || sha256_bytes(&plan.collection.intake.raw_bytes)
            != closure.acquisition.raw_provider_bytes_digest
    {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule provider intake differs from sealed physical acquisition",
        ));
    }
    let provider_records = binding
        .runtime_records
        .records
        .iter()
        .filter(|record| record.record_schema == "nq.provider_intake.v1")
        .collect::<Vec<_>>();
    let [provider_record] = provider_records.as_slice() else {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule terminal batch does not contain exactly one provider intake",
        ));
    };
    if provider_record.record_id != provider_record_id.as_str()
        || provider_record.canonical_bytes.as_bytes() != acquisition.exact_provider_intake_bytes
    {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule provider record bytes differ from physical custody",
        ));
    }
    let [provider_attempt] = binding.provider_attempts.as_slice() else {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule binding does not contain exactly one provider attempt",
        ));
    };
    if provider_attempt.provider_attempt_record_id != provider_record_id.as_str()
        || provider_attempt.intake_id != closure.acquisition.intake_id
    {
        return Err(projection_local_mismatch(
            reservation_record_id,
            "capsule provider-attempt binding differs from sealed acquisition",
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

fn projection_error_for_phase(
    reservation_record_id: &Sha256Digest,
    phase: GovernedProjectionVerificationPhase,
    error: StoreError,
) -> StoreError {
    match (phase, error) {
        (
            GovernedProjectionVerificationPhase::DurableProjection,
            StoreError::GovernedProjectionLocalCorrespondenceMismatch { reason, .. },
        ) => projection_integrity(reservation_record_id, reason),
        (_, error) => error,
    }
}

pub(crate) fn globalize_projection_local_mismatch(error: StoreError) -> StoreError {
    match error {
        StoreError::GovernedProjectionLocalCorrespondenceMismatch {
            reservation_record_id,
            reason,
        } => projection_integrity(&reservation_record_id, reason),
        error => error,
    }
}

pub(crate) fn projection_local_mismatch(
    reservation_record_id: &Sha256Digest,
    message: impl std::fmt::Display,
) -> StoreError {
    StoreError::GovernedProjectionLocalCorrespondenceMismatch {
        reservation_record_id: reservation_record_id.clone(),
        reason: message.to_string(),
    }
}

fn is_projection_local_correspondence_error(
    reservation_record_id: &Sha256Digest,
    error: &StoreError,
) -> bool {
    matches!(
        error,
        StoreError::GovernedProjectionLocalCorrespondenceMismatch {
            reservation_record_id: observed,
            ..
        } if observed == reservation_record_id
    )
}

fn custody_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Invariant(format!("governed exact-byte custody failed: {error}"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionRefusalClosureCommitment {
    byte_length: u64,
    bytes_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionRefusalReason {
    code: String,
    detail: String,
    source_error_digest: Sha256Digest,
    truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ProjectionCorrespondenceRefusalPreimage {
    schema: String,
    reservation_record_id: Sha256Digest,
    execution_launch_record_id: Sha256Digest,
    final_closure: ProjectionRefusalClosureCommitment,
    reason: ProjectionRefusalReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCorrespondenceRefusalDocument {
    schema: String,
    refusal_id: Sha256Digest,
    reservation_record_id: Sha256Digest,
    execution_launch_record_id: Sha256Digest,
    final_closure: ProjectionRefusalClosureCommitment,
    reason: ProjectionRefusalReason,
}

impl ProjectionCorrespondenceRefusalDocument {
    fn from_error(
        reservation_record_id: Sha256Digest,
        execution_launch_record_id: Sha256Digest,
        final_closure: ProjectionRefusalClosureCommitment,
        error: &StoreError,
    ) -> Result<(Self, Vec<u8>), StoreError> {
        let source = error.to_string();
        let (detail, truncated) = bounded_utf8_prefix(&source, MAX_PROJECTION_REFUSAL_DETAIL_BYTES);
        let preimage = ProjectionCorrespondenceRefusalPreimage {
            schema: GOVERNED_PROJECTION_CORRESPONDENCE_REFUSAL_SCHEMA.to_owned(),
            reservation_record_id,
            execution_launch_record_id,
            final_closure,
            reason: ProjectionRefusalReason {
                code: "exact_correspondence_refused".into(),
                detail,
                source_error_digest: sha256_bytes(source.as_bytes()),
                truncated,
            },
        };
        let refusal_id = semantic_digest(&preimage).map_err(|encode_error| {
            StoreError::Invariant(format!(
                "projection-refusal identity cannot be derived: {encode_error}"
            ))
        })?;
        let document = Self {
            schema: preimage.schema,
            refusal_id,
            reservation_record_id: preimage.reservation_record_id,
            execution_launch_record_id: preimage.execution_launch_record_id,
            final_closure: preimage.final_closure,
            reason: preimage.reason,
        };
        let exact_bytes = canonical_json_bytes(&document).map_err(|encode_error| {
            StoreError::Invariant(format!(
                "projection-refusal carrier cannot be encoded: {encode_error}"
            ))
        })?;
        Ok((document, exact_bytes))
    }

    fn from_exact_bytes(exact_bytes: &[u8]) -> Result<Self, StoreError> {
        let document: Self = serde_json::from_slice(exact_bytes).map_err(|error| {
            StoreError::Integrity(format!(
                "projection-refusal carrier cannot be decoded: {error}"
            ))
        })?;
        if document.schema != GOVERNED_PROJECTION_CORRESPONDENCE_REFUSAL_SCHEMA
            || document.reason.code != "exact_correspondence_refused"
            || document.reason.detail.len() > MAX_PROJECTION_REFUSAL_DETAIL_BYTES
            || canonical_json_bytes(&document).map_err(|error| {
                StoreError::Integrity(format!(
                    "projection-refusal carrier cannot be canonicalized: {error}"
                ))
            })? != exact_bytes
        {
            return Err(StoreError::Integrity(
                "projection-refusal schema, reason, bound, or canonical bytes differ".into(),
            ));
        }
        let preimage = ProjectionCorrespondenceRefusalPreimage {
            schema: document.schema.clone(),
            reservation_record_id: document.reservation_record_id.clone(),
            execution_launch_record_id: document.execution_launch_record_id.clone(),
            final_closure: document.final_closure.clone(),
            reason: document.reason.clone(),
        };
        if semantic_digest(&preimage).map_err(|error| {
            StoreError::Integrity(format!(
                "projection-refusal identity cannot be reopened: {error}"
            ))
        })? != document.refusal_id
        {
            return Err(StoreError::Integrity(
                "projection-refusal identity differs from its exact preimage".into(),
            ));
        }
        Ok(document)
    }

    fn as_store_error(&self) -> StoreError {
        StoreError::GovernedProjectionCorrespondenceRefused {
            reservation_record_id: self.reservation_record_id.clone(),
            refusal_id: self.refusal_id.clone(),
            reason: self.reason.detail.clone(),
        }
    }
}

fn bounded_utf8_prefix(input: &str, maximum_bytes: usize) -> (String, bool) {
    if input.len() <= maximum_bytes {
        return (input.to_owned(), false);
    }
    let mut end = maximum_bytes;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    (input[..end].to_owned(), true)
}

#[derive(Clone, Debug)]
pub(crate) struct PendingGovernedProjection<'snapshot> {
    pub(crate) reservation_record_id: Sha256Digest,
    /// Exact launch identity independently retained by physical arena custody.
    ///
    /// Whole-batch SQL-frontier qualification must anchor here, never in the
    /// capsule-owned execution binding that it is itself evaluating.
    pub(crate) physical_execution_launch_record_id: Sha256Digest,
    pub(crate) plan: ReopenedGovernedProjectionPlan,
    pub(crate) sql_footprint: crate::GovernedProjectionSqlFootprint,
    sources: IndependentGovernedProjectionSources<'snapshot>,
    snapshot: PhantomData<&'snapshot rusqlite::Connection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhysicalGovernedProjectionFootprint {
    Absent,
    Present,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedExternalSourceSummary {
    purpose: ExternalSourcePurpose,
    reference: RecordRef,
    availability: ExternalDependencyAvailability,
    exact_bytes_digest: Sha256Digest,
    exact_bytes_length: u64,
    admission_receipt_id: Sha256Digest,
    admitted_by: IdentityRef,
    admitted_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedAuthoritySourceSummary {
    purpose: AuthoritySourcePurpose,
    reference: RecordRef,
    admission_receipt_id: Sha256Digest,
    admitted_by: IdentityRef,
    admitted_at: Timestamp,
}

/// Store-private, transaction-bound summary of one completely authenticated
/// physical prelaunch source set.
///
/// This is deliberately neither serializable nor publicly constructible. It
/// is useful only while the caller continues evaluating the exact checkpoint
/// and arena context from which it was derived. A later transaction must
/// authenticate again.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedPhysicalPrelaunchSources<'snapshot> {
    reservation_record_id: Sha256Digest,
    outer_request_record_id: Sha256Digest,
    invocation_decision_record_id: Sha256Digest,
    launch_record_id: Sha256Digest,
    reservation_checkpoint_id: String,
    reservation_checkpoint_digest: Sha256Digest,
    launch_checkpoint_id: String,
    launch_checkpoint_digest: Sha256Digest,
    dependency_generation_id: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    custody_digest: Sha256Digest,
    custody_length: u64,
    requirement_set_digest: Sha256Digest,
    external: Vec<AuthenticatedExternalSourceSummary>,
    authority: Vec<AuthenticatedAuthoritySourceSummary>,
    snapshot: PhantomData<&'snapshot rusqlite::Connection>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct R0bAuthenticatedSourceModes {
    pub external: Vec<(ExternalSourcePurpose, ExternalDependencyAvailability)>,
}

#[cfg(test)]
thread_local! {
    static R0B_AUTHENTICATED_SOURCE_MODES: RefCell<Vec<R0bAuthenticatedSourceModes>> =
        const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_r0b_authenticated_source_modes(sources: &AuthenticatedPhysicalPrelaunchSources<'_>) {
    R0B_AUTHENTICATED_SOURCE_MODES.with(|observations| {
        observations.borrow_mut().push(R0bAuthenticatedSourceModes {
            external: sources
                .external
                .iter()
                .map(|source| (source.purpose, source.availability))
                .collect(),
        });
    });
}

#[cfg(test)]
pub(super) fn take_r0b_authenticated_source_modes() -> Vec<R0bAuthenticatedSourceModes> {
    R0B_AUTHENTICATED_SOURCE_MODES.with(RefCell::take)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum R0bRequirementContextMutation {
    Exact,
    OmitExternal,
    DuplicateExternal,
    ExtraneousExternal,
    SwapExternalPurposes,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct R0bRequirementContextCounts {
    pub external: usize,
    pub authority: usize,
}

impl AuthenticatedPhysicalPrelaunchSources<'_> {
    #[allow(clippy::too_many_arguments)] // Exact historical context is deliberately explicit at this seam.
    fn require_same_context(
        &self,
        reservation_record_id: &Sha256Digest,
        reservation_checkpoint: &RuntimeLedgerCheckpoint,
        reservation_checkpoint_records: &[RuntimeRecordRow],
        outer_request_record: &RuntimeRecordRow,
        invocation_decision_record: &RuntimeRecordRow,
        reservation_record: &RuntimeRecordRow,
        launch_checkpoint: &RuntimeLedgerCheckpoint,
        launch_record: &RuntimeRecordRow,
        dependency_generation_id: &Sha256Digest,
        trust_anchor_id: &Sha256Digest,
        custody_digest: &Sha256Digest,
        exact_dependency_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let custody_length = u64::try_from(exact_dependency_bytes.len()).map_err(|_| {
            projection_integrity(
                reservation_record_id,
                "authenticated dependency custody length overflowed",
            )
        })?;
        let requirements = derive_physical_prelaunch_requirements(
            reservation_record_id,
            reservation_checkpoint_records,
            outer_request_record,
            invocation_decision_record,
            reservation_record,
            launch_record,
        )?;
        let requirement_set_digest =
            physical_requirement_set_digest(&requirements.external, &requirements.authority)
                .map_err(|error| {
                    projection_integrity(
                        reservation_record_id,
                        format!("physical prelaunch requirement set cannot be rebound: {error}"),
                    )
                })?;
        let exact_external = self
            .external
            .iter()
            .map(|source| (source.purpose, source.reference.clone()))
            .collect::<Vec<_>>();
        let exact_authority = self
            .authority
            .iter()
            .map(|source| (source.purpose, source.reference.clone()))
            .collect::<Vec<_>>();
        if self.reservation_record_id != *reservation_record_id
            || self.outer_request_record_id != requirements.outer_request_record_id
            || self.invocation_decision_record_id != requirements.invocation_decision_record_id
            || self.launch_record_id != requirements.launch_record_id
            || self.reservation_checkpoint_id != reservation_checkpoint.checkpoint_id
            || self.reservation_checkpoint_digest != reservation_checkpoint.batch_digest
            || self.launch_checkpoint_id != launch_checkpoint.checkpoint_id
            || self.launch_checkpoint_digest != launch_checkpoint.batch_digest
            || self.dependency_generation_id != *dependency_generation_id
            || self.trust_anchor_id != *trust_anchor_id
            || self.custody_digest != *custody_digest
            || self.custody_length != custody_length
            || sha256_bytes(exact_dependency_bytes) != self.custody_digest
            || exact_external != requirements.external
            || exact_authority != requirements.authority
            || requirement_set_digest != self.requirement_set_digest
        {
            return Err(projection_integrity(
                reservation_record_id,
                "authenticated prelaunch source summary differs from its Store-selected context",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn r0b_verify_requirement_context_for_test(
    store: &Store,
    reservation_record_id: &Sha256Digest,
    mutation: R0bRequirementContextMutation,
) -> Result<R0bRequirementContextCounts, StoreError> {
    let database_path = store.path().ok_or_else(|| {
        StoreError::Invariant("R0b requirement-context control needs a file-backed Store".into())
    })?;
    let arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "R0b requirement-context control cannot reopen its custody arena",
            )
        })?;
    let sources = resolve_independent_governed_projection_sources(
        &store.connection,
        reservation_record_id,
        &arena,
    )?;
    let mut authenticated = sources.authenticated_prelaunch_sources.clone();
    let exact_counts = R0bRequirementContextCounts {
        external: authenticated.external.len(),
        authority: authenticated.authority.len(),
    };
    match mutation {
        R0bRequirementContextMutation::Exact => {}
        R0bRequirementContextMutation::OmitExternal => {
            authenticated
                .external
                .pop()
                .expect("R0b exact requirement set has an external source");
        }
        R0bRequirementContextMutation::DuplicateExternal => {
            let duplicate = authenticated
                .external
                .first()
                .expect("R0b exact requirement set has an external source")
                .clone();
            authenticated.external.push(duplicate);
        }
        R0bRequirementContextMutation::ExtraneousExternal => {
            let mut extraneous = authenticated
                .external
                .first()
                .expect("R0b exact requirement set has an external source")
                .clone();
            extraneous.reference.record_id =
                sha256_bytes(b"nq.test.r0b.extraneous-external-source.v1");
            authenticated.external.push(extraneous);
        }
        R0bRequirementContextMutation::SwapExternalPurposes => {
            assert!(
                authenticated.external.len() >= 2,
                "R0b exact requirement set has two external roles"
            );
            let first = authenticated.external[0].purpose;
            authenticated.external[0].purpose = authenticated.external[1].purpose;
            authenticated.external[1].purpose = first;
        }
    }
    authenticated.require_same_context(
        reservation_record_id,
        &sources.reservation_checkpoint,
        &sources.reservation_checkpoint_records,
        &sources.outer_request_record,
        &sources.invocation_decision_record,
        &sources.reservation_record,
        &sources.launch_checkpoint,
        &sources.launch_record,
        &sources.dependency.generation_id,
        &sources.dependency.trust_anchor_id,
        &sources.dependency.custody_bytes_digest,
        &sources.exact_dependency_bytes,
    )?;
    Ok(exact_counts)
}

#[cfg(test)]
pub(super) fn r0b_verify_checkpoint_dependency_with_arena_bytes_for_test(
    store: &Store,
    reservation_record_id: &Sha256Digest,
    checkpoint_id: &str,
) -> Result<(), StoreError> {
    let database_path = store.path().ok_or_else(|| {
        StoreError::Invariant("R0b checkpoint-byte control needs a file-backed Store".into())
    })?;
    let arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "R0b checkpoint-byte control cannot reopen its custody arena",
            )
        })?;
    let exact_dependency_bytes = arena.dependency_closure_bytes().map_err(custody_error)?;
    let checkpoint = runtime_checkpoint_by_id_on_connection(&store.connection, checkpoint_id)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                format!("R0b checkpoint-byte control cannot find checkpoint {checkpoint_id}"),
            )
        })?;
    let access = runtime_checkpoint_dependency_on_connection(&store.connection, checkpoint_id)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                format!("R0b checkpoint-byte control cannot find binding {checkpoint_id}"),
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
            format!("R0b checkpoint-byte control found a legacy binding {checkpoint_id}"),
        ));
    };
    let expected = GovernedProjectionDependencyGeneration {
        checkpoint_id: Sha256Digest::parse(checkpoint.checkpoint_id).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("R0b checkpoint-byte control found an invalid checkpoint ID: {error}"),
            )
        })?,
        checkpoint_digest: checkpoint.batch_digest,
        generation_id: dependency_generation_id,
        trust_anchor_id,
        custody_bytes_digest: canonical_bytes_sha256,
    };
    verify_checkpoint_dependency(
        &store.connection,
        reservation_record_id,
        checkpoint_id,
        &expected,
        &exact_dependency_bytes,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PhysicalPrelaunchRequirements {
    outer_request_record_id: Sha256Digest,
    invocation_decision_record_id: Sha256Digest,
    launch_record_id: Sha256Digest,
    external: Vec<(ExternalSourcePurpose, RecordRef)>,
    authority: Vec<(AuthoritySourcePurpose, RecordRef)>,
}

const fn external_source_purpose_name(purpose: ExternalSourcePurpose) -> &'static str {
    match purpose {
        ExternalSourcePurpose::InvocationAuthentication => "invocation_authentication",
        ExternalSourcePurpose::GenerationMatch => "generation_match",
        ExternalSourcePurpose::Capability => "capability",
        ExternalSourcePurpose::CustodyReservationCommit => "custody_reservation_commit",
    }
}

const fn authority_source_purpose_name(purpose: AuthoritySourcePurpose) -> &'static str {
    match purpose {
        AuthoritySourcePurpose::InvocationAuthentication => "invocation_authentication",
        AuthoritySourcePurpose::OperationAuthorization => "operation_authorization",
    }
}

fn authenticated_requirement_set_digest(
    external: &[AuthenticatedExternalSourceSummary],
    authority: &[AuthenticatedAuthoritySourceSummary],
) -> Result<Sha256Digest, nq_protocol::CanonicalizationError> {
    semantic_digest(&serde_json::json!({
        "schema": "nq.store_authenticated_prelaunch_requirement_set.v1",
        "external": external.iter().map(|source| serde_json::json!({
            "purpose": external_source_purpose_name(source.purpose),
            "reference": source.reference,
        })).collect::<Vec<_>>(),
        "authority": authority.iter().map(|source| serde_json::json!({
            "purpose": authority_source_purpose_name(source.purpose),
            "reference": source.reference,
        })).collect::<Vec<_>>(),
    }))
}

fn physical_requirement_set_digest(
    external: &[(ExternalSourcePurpose, RecordRef)],
    authority: &[(AuthoritySourcePurpose, RecordRef)],
) -> Result<Sha256Digest, nq_protocol::CanonicalizationError> {
    semantic_digest(&serde_json::json!({
        "schema": "nq.store_authenticated_prelaunch_requirement_set.v1",
        "external": external.iter().map(|(purpose, reference)| serde_json::json!({
            "purpose": external_source_purpose_name(*purpose),
            "reference": reference,
        })).collect::<Vec<_>>(),
        "authority": authority.iter().map(|(purpose, reference)| serde_json::json!({
            "purpose": authority_source_purpose_name(*purpose),
            "reference": reference,
        })).collect::<Vec<_>>(),
    }))
}

/// Native identities decoded from the arena-retained provider-intake record.
///
/// `nq-store` deliberately does not depend on the semantic `nq-core` type.
/// This bounded projection therefore decodes only the identity surface needed
/// for whole-batch collision attribution, while the exact provider bytes
/// remain authoritative custody.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct IndependentProviderIntakeIdentity {
    schema: String,
    intake_id: String,
    attempt_id: String,
    idempotency_key: String,
    run_id: String,
    request_id: String,
    request: Value,
    request_digest: Sha256Digest,
    raw_length: usize,
    raw_sha256: Sha256Digest,
}

/// Independently reopened physical and append-only sources for one pending
/// projection.
///
/// Every selector in this structure comes from the custody arena header or
/// from a record selected by that header. The final closure and projection
/// capsule are claims compared against these sources; they never select them.
#[derive(Clone, Debug)]
struct IndependentGovernedProjectionSources<'snapshot> {
    selected_superblock_digest: Sha256Digest,
    acquisition: AcquisitionCarrier,
    provider_intake_identity: IndependentProviderIntakeIdentity,
    dependency: GovernedProjectionDependencyGeneration,
    exact_dependency_bytes: Vec<u8>,
    authenticated_prelaunch_sources: AuthenticatedPhysicalPrelaunchSources<'snapshot>,
    reservation_checkpoint: RuntimeLedgerCheckpoint,
    reservation_checkpoint_records: Vec<RuntimeRecordRow>,
    reservation_record: RuntimeRecordRow,
    diagnostic_artifact_capacity_bytes: u64,
    outer_request_record: RuntimeRecordRow,
    outer_request_id: String,
    invocation_decision_record: RuntimeRecordRow,
    launch_checkpoint: RuntimeLedgerCheckpoint,
    launch_checkpoint_records: Vec<RuntimeRecordRow>,
    launch_record: RuntimeRecordRow,
    derivation_claim: DerivationClaim,
    physical_footprint: PhysicalGovernedProjectionFootprint,
    snapshot: PhantomData<&'snapshot rusqlite::Connection>,
}

fn decode_independent_provider_intake_identity(
    reservation_record_id: &Sha256Digest,
    acquisition: &AcquisitionCarrier,
) -> Result<IndependentProviderIntakeIdentity, StoreError> {
    let canonical_provider_intake =
        CanonicalDocument::from_canonical_bytes(acquisition.exact_provider_intake_bytes.clone())
            .map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!("physical provider-intake bytes are not canonical: {error}"),
                )
            })?;
    let identity: IndependentProviderIntakeIdentity =
        serde_json::from_slice(canonical_provider_intake.as_bytes()).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("physical provider-intake identity surface cannot be decoded: {error}"),
            )
        })?;
    if identity.schema != "nq.provider_intake.v1" {
        return Err(projection_integrity(
            reservation_record_id,
            "physical provider-intake identity surface has an incompatible schema",
        ));
    }
    if identity.request.get("request_id").and_then(Value::as_str)
        != Some(identity.request_id.as_str())
        || semantic_digest(&identity.request).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("physical provider-intake request digest cannot be derived: {error}"),
            )
        })? != identity.request_digest
    {
        return Err(projection_integrity(
            reservation_record_id,
            "physical provider-intake complete request identity or digest differs",
        ));
    }
    if identity.raw_length != acquisition.exact_raw_provider_bytes.len()
        || identity.raw_sha256 != sha256_bytes(&acquisition.exact_raw_provider_bytes)
    {
        return Err(projection_integrity(
            reservation_record_id,
            "physical provider-intake raw length or digest differs from exact raw custody",
        ));
    }
    for (label, value) in [
        ("intake_id", identity.intake_id.as_str()),
        ("attempt_id", identity.attempt_id.as_str()),
        ("idempotency_key", identity.idempotency_key.as_str()),
        ("run_id", identity.run_id.as_str()),
        ("request_id", identity.request_id.as_str()),
    ] {
        crate::validate_bounded_identity(label, value).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("physical provider-intake {label} is invalid: {error}"),
            )
        })?;
    }
    Sha256Digest::parse(identity.idempotency_key.clone()).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("physical provider-intake idempotency key is invalid: {error}"),
        )
    })?;
    Ok(identity)
}

fn classify_physical_governed_projection_footprint(
    connection: &rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    acquisition: &AcquisitionCarrier,
) -> Result<PhysicalGovernedProjectionFootprint, StoreError> {
    let provider_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_intake_attempts WHERE intake_digest = ?1",
        [acquisition.provider_intake_record_id.as_str()],
        |row| row.get(0),
    )?;
    let runtime_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_record_ledger WHERE record_id = ?1",
        [acquisition.provider_intake_record_id.as_str()],
        |row| row.get(0),
    )?;
    match (provider_rows, runtime_rows) {
        (0, 0) => Ok(PhysicalGovernedProjectionFootprint::Absent),
        (1, 1) => {
            let runtime_record = runtime_record_by_id_on_connection(
                connection,
                acquisition.provider_intake_record_id.as_str(),
            )?
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "physical provider runtime record disappeared during footprint resolution",
                )
            })?;
            let exact_raw_bytes: Vec<u8> = connection.query_row(
                "SELECT raw_bytes FROM provider_intake_attempts WHERE intake_digest = ?1",
                [acquisition.provider_intake_record_id.as_str()],
                |row| row.get(0),
            )?;
            if runtime_record.record_schema != "nq.provider_intake.v1"
                || runtime_record.canonical_bytes.as_bytes()
                    != acquisition.exact_provider_intake_bytes
                || exact_raw_bytes != acquisition.exact_raw_provider_bytes
            {
                return Err(projection_integrity(
                    reservation_record_id,
                    "physical provider occurrence differs from the arena acquisition carrier",
                ));
            }
            Ok(PhysicalGovernedProjectionFootprint::Present)
        }
        (providers, runtime) => Err(projection_integrity(
            reservation_record_id,
            format!(
                "physical provider footprint is partial or duplicated: {providers} provider rows and {runtime} runtime rows"
            ),
        )),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn resolve_authenticated_physical_prelaunch_sources<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    reservation_checkpoint: &RuntimeLedgerCheckpoint,
    reservation_checkpoint_records: &[RuntimeRecordRow],
    outer_request_record: &RuntimeRecordRow,
    invocation_decision_record: &RuntimeRecordRow,
    reservation_record: &RuntimeRecordRow,
    launch_checkpoint: &RuntimeLedgerCheckpoint,
    launch_record: &RuntimeRecordRow,
    arena_dependency_bytes: Option<&[u8]>,
) -> Result<AuthenticatedPhysicalPrelaunchSources<'snapshot>, StoreError> {
    let select_dependency = |checkpoint: &RuntimeLedgerCheckpoint| -> Result<_, StoreError> {
        let access =
            runtime_checkpoint_dependency_on_connection(connection, &checkpoint.checkpoint_id)?
                .ok_or_else(|| {
                    projection_integrity(
                        reservation_record_id,
                        format!(
                            "checkpoint {} has no dependency binding",
                            checkpoint.checkpoint_id
                        ),
                    )
                })?;
        let RuntimeCheckpointDependencyBinding::Authenticated {
            dependency_generation_id,
            trust_anchor_id,
            canonical_bytes_sha256,
            canonical_bytes_length,
        } = access.binding
        else {
            return Err(projection_integrity(
                reservation_record_id,
                format!(
                    "checkpoint {} has only a legacy dependency binding",
                    checkpoint.checkpoint_id
                ),
            ));
        };
        let canonical_custody = match access.byte_state {
            Some(RuntimeDependencyGenerationByteState::VerifiedAvailable { canonical_custody }) => {
                canonical_custody
            }
            Some(RuntimeDependencyGenerationByteState::CommittedUnavailable) => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!(
                        "checkpoint {} dependency custody is committed-unavailable",
                        checkpoint.checkpoint_id
                    ),
                ));
            }
            Some(RuntimeDependencyGenerationByteState::Corrupt { reason }) => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!(
                        "checkpoint {} dependency custody is corrupt or substituted: {reason}",
                        checkpoint.checkpoint_id
                    ),
                ));
            }
            None => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!(
                        "checkpoint {} has no dependency byte state",
                        checkpoint.checkpoint_id
                    ),
                ));
            }
        };
        if u64::try_from(canonical_custody.as_bytes().len()).map_err(|_| {
            projection_integrity(
                reservation_record_id,
                format!(
                    "checkpoint {} dependency custody length overflowed",
                    checkpoint.checkpoint_id
                ),
            )
        })? != canonical_bytes_length
            || sha256_bytes(canonical_custody.as_bytes()) != canonical_bytes_sha256
        {
            return Err(projection_integrity(
                reservation_record_id,
                format!(
                    "checkpoint {} dependency payload differs from its Store commitment",
                    checkpoint.checkpoint_id
                ),
            ));
        }
        Ok((
            dependency_generation_id,
            trust_anchor_id,
            canonical_bytes_sha256,
            canonical_bytes_length,
            canonical_custody.as_bytes().to_vec(),
        ))
    };

    let reservation_dependency = select_dependency(reservation_checkpoint)?;
    let launch_dependency = select_dependency(launch_checkpoint)?;
    if reservation_dependency != launch_dependency {
        return Err(projection_integrity(
            reservation_record_id,
            "reservation and launch checkpoints select different dependency custody",
        ));
    }
    let (
        dependency_generation_id,
        trust_anchor_id,
        custody_digest,
        custody_length,
        exact_dependency_bytes,
    ) = reservation_dependency;
    let bootstrap_root =
        runtime_dependency_trust_root_on_connection(connection)?.ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "authenticated dependency custody has no immutable Store bootstrap root",
            )
        })?;
    if bootstrap_root != trust_anchor_id {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "dependency custody selected root {trust_anchor_id}, not Store bootstrap root {bootstrap_root}"
            ),
        ));
    }
    if let Some(arena_dependency_bytes) = arena_dependency_bytes
        && arena_dependency_bytes != exact_dependency_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            "arena dependency custody differs from the exact Store payload",
        ));
    }

    let binding = ExactDependencyCustodyBinding::new(
        dependency_generation_id.clone(),
        bootstrap_root.clone(),
        custody_digest.clone(),
        custody_length,
    )
    .map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!(
                "dependency-custody binding for generation {dependency_generation_id} is invalid: {error}"
            ),
        )
    })?;
    let dependencies =
        AuthenticatedRuntimeDependencyClosure::reopen_bound(&exact_dependency_bytes, &binding)
            .map_err(|error| {
                projection_integrity(
                    reservation_record_id,
                    format!(
                        "authenticated dependency reopen failed for generation {dependency_generation_id}, root {bootstrap_root}, digest {custody_digest}, length {custody_length}: {error}"
                    ),
                )
            })?;

    let requirements = derive_physical_prelaunch_requirements(
        reservation_record_id,
        reservation_checkpoint_records,
        outer_request_record,
        invocation_decision_record,
        reservation_record,
        launch_record,
    )?;
    let external_requirements = requirements
        .external
        .iter()
        .map(|(purpose, reference)| match purpose {
            ExternalSourcePurpose::InvocationAuthentication => {
                ExternalSourceRequirement::invocation_authentication(reference.clone())
            }
            ExternalSourcePurpose::GenerationMatch => {
                ExternalSourceRequirement::generation_match(reference.clone())
            }
            ExternalSourcePurpose::Capability => {
                ExternalSourceRequirement::capability(reference.clone())
            }
            ExternalSourcePurpose::CustodyReservationCommit => {
                ExternalSourceRequirement::custody_reservation_commit(reference.clone())
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("physical external-source requirement is invalid: {error}"),
            )
        })?;
    let authority_requirements = requirements
        .authority
        .iter()
        .map(|(purpose, reference)| match purpose {
            AuthoritySourcePurpose::InvocationAuthentication => {
                AuthoritySourceRequirement::invocation_authentication(reference.clone())
            }
            AuthoritySourcePurpose::OperationAuthorization => {
                AuthoritySourceRequirement::operation_authorization(reference.clone())
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("physical authority-source requirement is invalid: {error}"),
            )
        })?;
    let resolution = dependencies
        .resolve_sources(&external_requirements, &authority_requirements)
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!(
                    "closed source resolution failed for dependency generation {dependency_generation_id}: {error}"
                ),
            )
        })?;

    let mut external = Vec::with_capacity(4);
    for result in resolution.external() {
        let purpose = result.requirement().purpose();
        let reference = result.requirement().reference().clone();
        match result.state() {
            ExternalSourceState::Available {
                availability,
                exact_bytes,
                admission_receipt_id,
                admitted_by,
                admitted_at,
            } => {
                external.push(AuthenticatedExternalSourceSummary {
                    purpose,
                    reference,
                    availability: *availability,
                    exact_bytes_digest: sha256_bytes(exact_bytes),
                    exact_bytes_length: u64::try_from(exact_bytes.len()).map_err(|_| {
                        projection_integrity(
                            reservation_record_id,
                            format!(
                                "{} source exact-byte length overflowed",
                                external_source_purpose_name(purpose)
                            ),
                        )
                    })?,
                    admission_receipt_id: (*admission_receipt_id).clone(),
                    admitted_by: (*admitted_by).clone(),
                    admitted_at: (*admitted_at).clone(),
                });
            }
            ExternalSourceState::Missing => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!(
                        "{} source {} is absent from authenticated dependency generation {}",
                        external_source_purpose_name(purpose),
                        reference.record_id,
                        dependency_generation_id
                    ),
                ));
            }
            ExternalSourceState::CommittedUnavailable {
                admission_receipt_id,
                ..
            } => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!(
                        "{} source {} is committed-unavailable under admission receipt {}",
                        external_source_purpose_name(purpose),
                        reference.record_id,
                        admission_receipt_id
                    ),
                ));
            }
        }
    }

    let mut authority = Vec::with_capacity(2);
    for result in resolution.authority() {
        let purpose = result.requirement().purpose();
        let reference = result.requirement().reference().clone();
        match result.state() {
            AuthoritySourceState::Admitted {
                admission_receipt_id,
                admitted_by,
                admitted_at,
            } => {
                authority.push(AuthenticatedAuthoritySourceSummary {
                    purpose,
                    reference,
                    admission_receipt_id: (*admission_receipt_id).clone(),
                    admitted_by: (*admitted_by).clone(),
                    admitted_at: (*admitted_at).clone(),
                });
            }
            AuthoritySourceState::RequiredAdmissionMissing => {
                return Err(projection_integrity(
                    reservation_record_id,
                    format!(
                        "{} authority admission for source {} is absent from dependency generation {}",
                        authority_source_purpose_name(purpose),
                        reference.record_id,
                        dependency_generation_id
                    ),
                ));
            }
        }
    }
    let requirement_set_digest = authenticated_requirement_set_digest(&external, &authority)
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("authenticated requirement set cannot be identified: {error}"),
            )
        })?;
    let expected_requirement_set_digest =
        physical_requirement_set_digest(&requirements.external, &requirements.authority).map_err(
            |error| {
                projection_integrity(
                    reservation_record_id,
                    format!("physical requirement set cannot be identified: {error}"),
                )
            },
        )?;
    if external.len() != 4
        || authority.len() != 2
        || requirement_set_digest != expected_requirement_set_digest
    {
        return Err(projection_integrity(
            reservation_record_id,
            "authenticated source resolution is not the complete six-purpose physical requirement set",
        ));
    }

    let sources = AuthenticatedPhysicalPrelaunchSources {
        reservation_record_id: reservation_record_id.clone(),
        outer_request_record_id: requirements.outer_request_record_id,
        invocation_decision_record_id: requirements.invocation_decision_record_id,
        launch_record_id: requirements.launch_record_id,
        reservation_checkpoint_id: reservation_checkpoint.checkpoint_id.clone(),
        reservation_checkpoint_digest: reservation_checkpoint.batch_digest.clone(),
        launch_checkpoint_id: launch_checkpoint.checkpoint_id.clone(),
        launch_checkpoint_digest: launch_checkpoint.batch_digest.clone(),
        dependency_generation_id,
        trust_anchor_id: bootstrap_root,
        custody_digest,
        custody_length,
        requirement_set_digest,
        external,
        authority,
        snapshot: PhantomData,
    };
    #[cfg(test)]
    record_r0b_authenticated_source_modes(&sources);
    Ok(sources)
}

#[allow(clippy::too_many_lines)]
fn resolve_independent_governed_projection_sources<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    arena: &CustodyArena,
) -> Result<IndependentGovernedProjectionSources<'snapshot>, StoreError> {
    let inspection = arena.inspection().map_err(custody_error)?;
    if inspection.reservation_id != *reservation_record_id {
        return Err(projection_integrity(
            reservation_record_id,
            "arena reservation identity differs",
        ));
    }
    if !matches!(
        inspection.state,
        ArenaState::FinalV2SealedIndexPending | ArenaState::FinalV2SealedIndexed
    ) {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "arena state {:?} has no sealed projection sources",
                inspection.state
            ),
        ));
    }

    validate_runtime_record_ledger(connection)?;
    validate_provider_intake_invariants(connection)?;
    validate_diagnostic_artifact_invariants(connection)?;

    let acquisition = arena.acquisition_for_projection().map_err(custody_error)?;
    let provider_intake_identity =
        decode_independent_provider_intake_identity(reservation_record_id, &acquisition)?;
    let exact_dependency_bytes = arena.dependency_closure_bytes().map_err(custody_error)?;
    if sha256_bytes(&exact_dependency_bytes)
        != inspection.prelaunch.dependency_generation_custody_digest
    {
        return Err(projection_integrity(
            reservation_record_id,
            "physical dependency bytes differ from the arena prelaunch commitment",
        ));
    }
    let dependency = GovernedProjectionDependencyGeneration {
        checkpoint_id: inspection.prelaunch.prelaunch_checkpoint_id.clone(),
        checkpoint_digest: inspection.prelaunch.prelaunch_checkpoint_digest.clone(),
        generation_id: inspection.prelaunch.dependency_generation_id.clone(),
        trust_anchor_id: inspection.prelaunch.trust_anchor_id.clone(),
        custody_bytes_digest: inspection
            .prelaunch
            .dependency_generation_custody_digest
            .clone(),
    };
    verify_checkpoint_dependency(
        connection,
        reservation_record_id,
        inspection.prelaunch.prelaunch_checkpoint_id.as_str(),
        &dependency,
        &exact_dependency_bytes,
    )?;

    let reservation_checkpoint = runtime_checkpoint_by_id_on_connection(
        connection,
        inspection.prelaunch.prelaunch_checkpoint_id.as_str(),
    )?
    .ok_or_else(|| {
        projection_integrity(
            reservation_record_id,
            "arena-bound reservation checkpoint is absent",
        )
    })?;
    if reservation_checkpoint.batch_digest != inspection.prelaunch.prelaunch_checkpoint_digest {
        return Err(projection_integrity(
            reservation_record_id,
            "arena-bound reservation checkpoint differs from physical prelaunch custody",
        ));
    }
    let reservation_checkpoint_records =
        checkpoint_runtime_records(connection, reservation_record_id, &reservation_checkpoint)?;
    let reservation_record =
        runtime_record_by_id_on_connection(connection, reservation_record_id.as_str())?
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "arena-bound custody-reservation runtime record is absent",
                )
            })?;
    let outer_request_record = runtime_record_by_id_on_connection(
        connection,
        inspection.prelaunch.outer_request_record_id.as_str(),
    )?
    .ok_or_else(|| {
        projection_integrity(
            reservation_record_id,
            "arena-bound outer-request runtime record is absent",
        )
    })?;
    let outer_request_id =
        exact_json_string(reservation_record_id, &outer_request_record, "request_id")?.ok_or_else(
            || {
                projection_integrity(
                    reservation_record_id,
                    "arena-bound outer-request runtime record has no request identity",
                )
            },
        )?;
    crate::validate_bounded_identity("outer request_id", &outer_request_id).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("arena-bound outer request identity is invalid: {error}"),
        )
    })?;
    let invocation_decisions = reservation_checkpoint_records
        .iter()
        .filter(|record| record.record_schema == "nq.invocation_decision.v1")
        .collect::<Vec<_>>();
    let [invocation_decision_record] = invocation_decisions.as_slice() else {
        return Err(projection_integrity(
            reservation_record_id,
            "arena-bound reservation checkpoint lacks exactly one invocation decision",
        ));
    };
    let invocation_decision_record = (*invocation_decision_record).clone();
    if reservation_record.record_schema != "nq.custody_reservation.v1"
        || reservation_record.canonical_bytes_sha256
            != inspection.prelaunch.reservation_manifest_digest
        || outer_request_record.record_schema != "nq.diagnostic_invocation_request.v1"
        || outer_request_record.canonical_bytes_sha256 != inspection.prelaunch.outer_request_digest
        || !checkpoint_has_unique_exact_record(
            &reservation_checkpoint_records,
            &outer_request_record,
            "nq.diagnostic_invocation_request.v1",
        )
        || !checkpoint_has_unique_exact_record(
            &reservation_checkpoint_records,
            &invocation_decision_record,
            "nq.invocation_decision.v1",
        )
        || !checkpoint_has_unique_exact_record(
            &reservation_checkpoint_records,
            &reservation_record,
            "nq.custody_reservation.v1",
        )
        || exact_json_string(
            reservation_record_id,
            &invocation_decision_record,
            "decision",
        )?
        .as_deref()
            != Some("accepted")
    {
        return Err(projection_integrity(
            reservation_record_id,
            "arena-bound reservation checkpoint source is corrupt or incomplete",
        ));
    }
    let (diagnostic_artifact_capacity_bytes, _projection_capsule_capacity, final_capacity) =
        governed_reservation_capacity_components(&reservation_record)?;
    if final_capacity != inspection.layout.final_capacity() {
        return Err(projection_integrity(
            reservation_record_id,
            "arena final capacity differs from the exact custody reservation",
        ));
    }
    if outer_request_id != inspection.prelaunch.outer_request_id {
        return Err(projection_integrity(
            reservation_record_id,
            "arena-bound outer request identity differs from physical prelaunch custody",
        ));
    }

    let physical_launch_id = inspection
        .execution_launch_record_id
        .as_ref()
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "physical custody has no execution-launch identity",
            )
        })?;
    if acquisition.execution_launch_record_id != *physical_launch_id {
        return Err(projection_integrity(
            reservation_record_id,
            "physical acquisition launch differs from the arena launch claim",
        ));
    }
    let launch_record =
        runtime_record_by_id_on_connection(connection, physical_launch_id.as_str())?.ok_or_else(
            || {
                projection_integrity(
                    reservation_record_id,
                    "physical execution-launch runtime record is absent",
                )
            },
        )?;
    if launch_record.record_schema != "nq.execution_launch.v1" {
        return Err(projection_integrity(
            reservation_record_id,
            "physical execution-launch record has an incompatible schema",
        ));
    }
    let launch_checkpoint =
        runtime_checkpoint_by_id_on_connection(connection, &launch_record.checkpoint_id)?
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "physical execution-launch checkpoint is absent",
                )
            })?;
    verify_checkpoint_dependency(
        connection,
        reservation_record_id,
        &launch_checkpoint.checkpoint_id,
        &dependency,
        &exact_dependency_bytes,
    )?;
    let launch_checkpoint_records =
        checkpoint_runtime_records(connection, reservation_record_id, &launch_checkpoint)?;
    let launch_records = launch_checkpoint_records
        .iter()
        .filter(|record| record.record_schema == "nq.execution_launch.v1")
        .collect::<Vec<_>>();
    if launch_records.as_slice() != [&launch_record]
        || launch_checkpoint.predecessor_checkpoint_id.as_deref()
            != Some(reservation_checkpoint.checkpoint_id.as_str())
        || launch_checkpoint.predecessor_ledger_root.as_ref()
            != Some(&reservation_checkpoint.checkpoint_ledger_root)
        || inspection.claimed_at.as_deref()
            != exact_json_string(reservation_record_id, &launch_record, "launched_at")?.as_deref()
    {
        return Err(projection_integrity(
            reservation_record_id,
            "physical launch checkpoint membership, predecessor, or claim time differs",
        ));
    }
    verify_declared_physical_launch_checkpoint(
        reservation_record_id,
        &launch_checkpoint_records,
        &launch_record,
        &reservation_checkpoint_records,
        &outer_request_record,
        &invocation_decision_record,
        &reservation_record,
    )?;
    let authenticated_prelaunch_sources = resolve_authenticated_physical_prelaunch_sources(
        connection,
        reservation_record_id,
        &reservation_checkpoint,
        &reservation_checkpoint_records,
        &outer_request_record,
        &invocation_decision_record,
        &reservation_record,
        &launch_checkpoint,
        &launch_record,
        Some(&exact_dependency_bytes),
    )?;

    let derivation_claim = inspection.derivation_claim.clone().ok_or_else(|| {
        projection_integrity(
            reservation_record_id,
            "final physical frontier has no derivation claim",
        )
    })?;
    if derivation_claim.dependency_generation_id != dependency.generation_id
        || derivation_claim.dependency_generation_custody_digest != dependency.custody_bytes_digest
        || derivation_claim.trust_anchor_id != dependency.trust_anchor_id
    {
        return Err(projection_integrity(
            reservation_record_id,
            "physical derivation claim differs from arena-bound dependency custody",
        ));
    }
    let physical_footprint = classify_physical_governed_projection_footprint(
        connection,
        reservation_record_id,
        &acquisition,
    )?;
    Ok(IndependentGovernedProjectionSources {
        selected_superblock_digest: inspection.selected_superblock_digest,
        acquisition,
        provider_intake_identity,
        dependency,
        exact_dependency_bytes,
        authenticated_prelaunch_sources,
        reservation_checkpoint,
        reservation_checkpoint_records,
        reservation_record,
        diagnostic_artifact_capacity_bytes,
        outer_request_record,
        outer_request_id,
        invocation_decision_record,
        launch_checkpoint,
        launch_checkpoint_records,
        launch_record,
        derivation_claim,
        physical_footprint,
        snapshot: PhantomData,
    })
}

fn remember_independent_governed_projection_source_identities(
    owners: &mut BTreeMap<String, Sha256Digest>,
    reservation_record_id: &Sha256Digest,
    sources: &IndependentGovernedProjectionSources<'_>,
) -> Result<(), StoreError> {
    for (class, value) in [
        (
            "runtime_record_id",
            sources.reservation_record.record_id.as_str(),
        ),
        (
            "runtime_record_id",
            sources.outer_request_record.record_id.as_str(),
        ),
        (
            "runtime_record_id",
            sources.invocation_decision_record.record_id.as_str(),
        ),
        (
            "runtime_record_id",
            sources.launch_record.record_id.as_str(),
        ),
        (
            "runtime_checkpoint_id",
            sources.reservation_checkpoint.checkpoint_id.as_str(),
        ),
        (
            "runtime_checkpoint_id",
            sources.launch_checkpoint.checkpoint_id.as_str(),
        ),
        (
            "outer_request_record_id",
            sources.outer_request_record.record_id.as_str(),
        ),
        (
            "invocation_decision_record_id",
            sources.invocation_decision_record.record_id.as_str(),
        ),
        (
            "execution_launch_record_id",
            sources.launch_record.record_id.as_str(),
        ),
        (
            "runtime_record_id",
            sources.acquisition.provider_intake_record_id.as_str(),
        ),
        (
            "provider_attempt_binding.provider_attempt_record_id",
            sources.acquisition.provider_intake_record_id.as_str(),
        ),
        (
            "intake_id",
            sources.provider_intake_identity.intake_id.as_str(),
        ),
        (
            "intake_idempotency",
            sources.provider_intake_identity.idempotency_key.as_str(),
        ),
        (
            "intake_attempt",
            sources.provider_intake_identity.attempt_id.as_str(),
        ),
        (
            "intake_request",
            sources.provider_intake_identity.request_id.as_str(),
        ),
        ("run_id", sources.provider_intake_identity.run_id.as_str()),
        (
            "run_request",
            sources.provider_intake_identity.request_id.as_str(),
        ),
        (
            "provider_attempt_binding.intake_id",
            sources.provider_intake_identity.intake_id.as_str(),
        ),
        ("outer_request_id", sources.outer_request_id.as_str()),
    ] {
        crate::remember_governed_projection_identity(owners, reservation_record_id, class, value)?;
    }
    for record in sources
        .reservation_checkpoint_records
        .iter()
        .chain(&sources.launch_checkpoint_records)
    {
        crate::remember_governed_projection_identity(
            owners,
            reservation_record_id,
            "runtime_record_id",
            &record.record_id,
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ReopenedGovernedProjectionCandidate<'snapshot> {
    reservation_record_id: Sha256Digest,
    physical_execution_launch_record_id: Sha256Digest,
    plan: ReopenedGovernedProjectionPlan,
    physical_footprint: PhysicalGovernedProjectionFootprint,
    sources: IndependentGovernedProjectionSources<'snapshot>,
}

#[allow(clippy::too_many_lines)] // One pre-SQL gate keeps every correspondence omission visible.
fn prevalidate_governed_v3_projection_before_sql<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    database_path: &Path,
    reservation_record_id: &Sha256Digest,
    sources: &IndependentGovernedProjectionSources<'snapshot>,
) -> Result<Option<PendingGovernedProjection<'snapshot>>, StoreError> {
    let arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(reservation_record_id, "physical custody arena is absent")
        })?;
    prevalidate_governed_v3_projection_with_sources(
        connection,
        reservation_record_id,
        &arena,
        sources,
    )
}

fn projection_error_before_plan(
    reservation_record_id: &Sha256Digest,
    physical_footprint: PhysicalGovernedProjectionFootprint,
    reason: impl std::fmt::Display,
) -> StoreError {
    match physical_footprint {
        PhysicalGovernedProjectionFootprint::Absent => {
            projection_local_mismatch(reservation_record_id, reason)
        }
        PhysicalGovernedProjectionFootprint::Present => projection_integrity(
            reservation_record_id,
            format!("{reason}; the arena-selected physical provider footprint is already present"),
        ),
    }
}

#[allow(clippy::too_many_lines)] // Reopening validates one sealed capsule against every independent physical source.
fn shallow_reopen_governed_v3_projection_with_arena<'snapshot>(
    reservation_record_id: &Sha256Digest,
    arena: &CustodyArena,
    sources: &IndependentGovernedProjectionSources<'snapshot>,
) -> Result<Option<ReopenedGovernedProjectionCandidate<'snapshot>>, StoreError> {
    let inspection = arena.inspection().map_err(custody_error)?;
    if inspection.reservation_id != *reservation_record_id {
        return Err(projection_integrity(
            reservation_record_id,
            "arena reservation identity differs",
        ));
    }
    if !matches!(
        inspection.state,
        ArenaState::FinalV2SealedIndexPending | ArenaState::FinalV2SealedIndexed
    ) {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "arena state {:?} has no sealed projection to prevalidate",
                inspection.state
            ),
        ));
    }
    if inspection.selected_superblock_digest != sources.selected_superblock_digest {
        return Err(projection_integrity(
            reservation_record_id,
            "arena frontier changed after independent source resolution",
        ));
    }
    let exact_closure_bytes = arena
        .final_v2_closure_bytes()
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(reservation_record_id, "final closure bytes are absent")
        })?;
    let exact_closure_value: Value =
        serde_json::from_slice(&exact_closure_bytes).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("final closure shape is incompatible: {error}"),
            )
        })?;
    if canonical_json_bytes(&exact_closure_value).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("final closure cannot be canonicalized: {error}"),
        )
    })? != exact_closure_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            "final closure bytes are not exact canonical JSON",
        ));
    }
    let closure: GovernedProjectionClosure = serde_json::from_value(exact_closure_value.clone())
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("final closure shape is incompatible: {error}"),
            )
        })?;
    if closure.schema != GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA {
        return Err(projection_integrity(
            reservation_record_id,
            "historical pre-V3 closure cannot earn authenticated complete-verification standing",
        ));
    }
    let mut closure_preimage = exact_closure_value.as_object().cloned().ok_or_else(|| {
        projection_integrity(reservation_record_id, "final closure is not an object")
    })?;
    closure_preimage.remove("closure_id");
    if semantic_digest(&closure_preimage).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("final closure identity cannot be derived: {error}"),
        )
    })? != closure.closure_id
    {
        return Err(projection_integrity(
            reservation_record_id,
            "final closure identity differs from its exact preimage",
        ));
    }

    let acquisition = &sources.acquisition;

    let Some(sealed_capsule) = closure.projection_capsule.as_ref() else {
        return Err(projection_error_before_plan(
            reservation_record_id,
            sources.physical_footprint,
            "sealed V3 closure has no embedded projection capsule",
        ));
    };
    let capsule_bytes = match canonical_json_bytes(sealed_capsule) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(projection_error_before_plan(
                reservation_record_id,
                sources.physical_footprint,
                format!("embedded projection capsule is not canonicalizable: {error}"),
            ));
        }
    };
    let capsule = match GovernedProjectionCapsule::decode(capsule_bytes) {
        Ok(capsule) => capsule,
        Err(error) => {
            return Err(projection_error_before_plan(
                reservation_record_id,
                sources.physical_footprint,
                format!("embedded projection capsule is corrupt: {error}"),
            ));
        }
    };
    if capsule.reservation_record_id() != reservation_record_id {
        return Err(projection_error_before_plan(
            reservation_record_id,
            sources.physical_footprint,
            "embedded projection capsule reservation differs",
        ));
    }
    let exact_diagnostic_bytes = match canonical_json_bytes(&closure.diagnostic) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(projection_error_before_plan(
                reservation_record_id,
                sources.physical_footprint,
                format!("embedded diagnostic cannot be canonicalized: {error}"),
            ));
        }
    };
    let exact_diagnostic = match CanonicalDocument::from_canonical_bytes(exact_diagnostic_bytes) {
        Ok(diagnostic) => diagnostic,
        Err(error) => {
            return Err(projection_error_before_plan(
                reservation_record_id,
                sources.physical_footprint,
                format!("embedded diagnostic is not one canonical document: {error}"),
            ));
        }
    };
    let plan = match capsule.reopen_plan(&acquisition.exact_raw_provider_bytes, exact_diagnostic) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(projection_error_before_plan(
                reservation_record_id,
                sources.physical_footprint,
                format!("embedded projection capsule cannot reopen its exact plan: {error}"),
            ));
        }
    };
    Ok(Some(ReopenedGovernedProjectionCandidate {
        reservation_record_id: reservation_record_id.clone(),
        physical_execution_launch_record_id: sources.acquisition.execution_launch_record_id.clone(),
        plan,
        physical_footprint: sources.physical_footprint,
        sources: sources.clone(),
    }))
}

fn classify_reopened_governed_projection_candidate<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    candidate: ReopenedGovernedProjectionCandidate<'snapshot>,
) -> Result<PendingGovernedProjection<'snapshot>, StoreError> {
    let sql_footprint =
        crate::classify_reopened_governed_projection_footprint_after_owner_registration(
            connection,
            &candidate.reservation_record_id,
            &candidate.plan,
        )?;
    let physical_sql_footprint = match candidate.physical_footprint {
        PhysicalGovernedProjectionFootprint::Absent => {
            crate::GovernedProjectionSqlFootprint::Absent
        }
        PhysicalGovernedProjectionFootprint::Present => {
            crate::GovernedProjectionSqlFootprint::ExistingExact
        }
    };
    if sql_footprint != physical_sql_footprint {
        return Err(projection_integrity(
            &candidate.reservation_record_id,
            format!(
                "capsule-selected SQL footprint {sql_footprint:?} differs from arena-selected physical footprint {physical_sql_footprint:?}"
            ),
        ));
    }
    Ok(PendingGovernedProjection {
        reservation_record_id: candidate.reservation_record_id,
        physical_execution_launch_record_id: candidate.physical_execution_launch_record_id,
        plan: candidate.plan,
        sql_footprint,
        sources: candidate.sources,
        snapshot: PhantomData,
    })
}

#[allow(clippy::too_many_lines)] // One pre-SQL gate keeps every correspondence omission visible.
fn prevalidate_governed_v3_projection_with_sources<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    arena: &CustodyArena,
    sources: &IndependentGovernedProjectionSources<'snapshot>,
) -> Result<Option<PendingGovernedProjection<'snapshot>>, StoreError> {
    let inspection = arena.inspection().map_err(custody_error)?;
    if inspection.reservation_id != *reservation_record_id {
        return Err(projection_integrity(
            reservation_record_id,
            "arena reservation identity differs",
        ));
    }
    if !matches!(
        inspection.state,
        ArenaState::FinalV2SealedIndexPending | ArenaState::FinalV2SealedIndexed
    ) {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "arena state {:?} has no sealed projection to prevalidate",
                inspection.state
            ),
        ));
    }
    if inspection.selected_superblock_digest != sources.selected_superblock_digest {
        return Err(projection_integrity(
            reservation_record_id,
            "arena frontier changed after authenticated source selection",
        ));
    }
    sources
        .authenticated_prelaunch_sources
        .require_same_context(
            reservation_record_id,
            &sources.reservation_checkpoint,
            &sources.reservation_checkpoint_records,
            &sources.outer_request_record,
            &sources.invocation_decision_record,
            &sources.reservation_record,
            &sources.launch_checkpoint,
            &sources.launch_record,
            &sources.dependency.generation_id,
            &sources.dependency.trust_anchor_id,
            &sources.dependency.custody_bytes_digest,
            &sources.exact_dependency_bytes,
        )?;
    let exact_closure_bytes = arena
        .final_v2_closure_bytes()
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(reservation_record_id, "final closure bytes are absent")
        })?;
    let exact_closure_value: Value =
        serde_json::from_slice(&exact_closure_bytes).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("final closure shape is incompatible: {error}"),
            )
        })?;
    if canonical_json_bytes(&exact_closure_value).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("final closure cannot be canonicalized: {error}"),
        )
    })? != exact_closure_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            "final closure bytes are not exact canonical JSON",
        ));
    }
    let closure: GovernedProjectionClosure = serde_json::from_value(exact_closure_value.clone())
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("final closure shape is incompatible: {error}"),
            )
        })?;
    if closure.schema != GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA {
        return Err(projection_integrity(
            reservation_record_id,
            "historical pre-V3 closure cannot earn authenticated complete-verification standing",
        ));
    }
    let mut closure_preimage = exact_closure_value.as_object().cloned().ok_or_else(|| {
        projection_integrity(reservation_record_id, "final closure is not an object")
    })?;
    closure_preimage.remove("closure_id");
    if semantic_digest(&closure_preimage).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("final closure identity cannot be derived: {error}"),
        )
    })? != closure.closure_id
    {
        return Err(projection_integrity(
            reservation_record_id,
            "final closure identity differs from its exact preimage",
        ));
    }

    let acquisition = &sources.acquisition;

    let sealed_capsule = closure.projection_capsule.as_ref().ok_or_else(|| {
        projection_integrity(
            reservation_record_id,
            "sealed V3 closure has no embedded projection capsule",
        )
    })?;
    let capsule = GovernedProjectionCapsule::decode(canonical_json_bytes(sealed_capsule).map_err(
        |error| {
            projection_integrity(
                reservation_record_id,
                format!("embedded projection capsule is not canonicalizable: {error}"),
            )
        },
    )?)
    .map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("embedded projection capsule is corrupt: {error}"),
        )
    })?;
    if capsule.reservation_record_id() != reservation_record_id {
        return Err(projection_integrity(
            reservation_record_id,
            "embedded projection capsule reservation differs",
        ));
    }
    let exact_diagnostic = CanonicalDocument::from_canonical_bytes(
        canonical_json_bytes(&closure.diagnostic).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("embedded diagnostic cannot be canonicalized: {error}"),
            )
        })?,
    )
    .map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("embedded diagnostic is not one canonical document: {error}"),
        )
    })?;
    let diagnostic_file_bytes_digest = sha256_bytes(exact_diagnostic.as_bytes());
    let plan = capsule
        .reopen_plan(&acquisition.exact_raw_provider_bytes, exact_diagnostic)
        .map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("embedded projection capsule cannot reopen its exact plan: {error}"),
            )
        })?;
    let sql_footprint = crate::classify_reopened_governed_projection_footprint(
        connection,
        reservation_record_id,
        &plan,
    )?;
    let physical_sql_footprint = match sources.physical_footprint {
        PhysicalGovernedProjectionFootprint::Absent => {
            crate::GovernedProjectionSqlFootprint::Absent
        }
        PhysicalGovernedProjectionFootprint::Present => {
            crate::GovernedProjectionSqlFootprint::ExistingExact
        }
    };
    if sql_footprint != physical_sql_footprint {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "capsule-selected SQL footprint {sql_footprint:?} differs from arena-selected physical footprint {physical_sql_footprint:?}"
            ),
        ));
    }
    let deep_correspondence = (|| -> Result<(), StoreError> {
        crate::validate_reopened_governed_projection_plan_before_insert(
            reservation_record_id,
            &plan,
        )
        .map_err(|error| {
            projection_local_mismatch(
                reservation_record_id,
                format!("embedded projection plan is invalid before insertion: {error}"),
            )
        })?;
        validate_reopened_projection_plan(reservation_record_id, &closure, acquisition, &plan)?;
        let rebuilt_capsule = GovernedProjectionCapsule::build(&GovernedProjectionCapsuleInput {
            reservation_record_id: reservation_record_id.clone(),
            collection: plan.collection.clone(),
            diagnostic_artifact: plan.diagnostic.clone(),
            status: plan.status.clone(),
            mode: plan.mode,
            expected_semantic_digest: plan.expected_semantic_digest.clone(),
            publication: plan.publication.clone(),
        })
        .map_err(|error| {
            projection_local_mismatch(
                reservation_record_id,
                format!("embedded projection capsule cannot be rebuilt: {error}"),
            )
        })?;
        if rebuilt_capsule.canonical_bytes().as_bytes() != capsule.canonical_bytes().as_bytes() {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "reopened projection plan does not reproduce the exact sealed capsule",
            ));
        }

        // From here onward the closure is compared only with the independently
        // selected bundle resolved before capsule decoding.
        let reservation_checkpoint = &sources.reservation_checkpoint;
        let reservation_checkpoint_records = &sources.reservation_checkpoint_records;
        let reservation_record = &sources.reservation_record;
        let outer_request_record = &sources.outer_request_record;
        let invocation_decision_record = &sources.invocation_decision_record;
        if !closure.reservation.matches(reservation_record) {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "custody reservation runtime record differs from its sealed reference",
            ));
        }
        if closure.reservation.schema != "nq.custody_reservation.v1"
            || closure.reservation.record_id != *reservation_record_id
            || closure.reservation.bytes_digest != inspection.prelaunch.reservation_manifest_digest
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "reservation reference differs from the arena prelaunch binding",
            ));
        }
        if governed_closure_embedded_diagnostic_length(&exact_closure_bytes)?
            > sources.diagnostic_artifact_capacity_bytes
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "embedded diagnostic exceeds exact reservation capacity",
            ));
        }

        if !closure
            .prelaunch
            .outer_request
            .matches(outer_request_record)
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "outer request runtime record differs from its sealed reference",
            ));
        }
        if !closure
            .prelaunch
            .invocation_decision
            .matches(invocation_decision_record)
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "accepted invocation decision runtime record differs from its sealed reference",
            ));
        }
        if closure
            .prelaunch
            .reservation_checkpoint
            .checkpoint_id
            .as_str()
            != reservation_checkpoint.checkpoint_id
            || closure.prelaunch.reservation_checkpoint.batch_digest
                != reservation_checkpoint.batch_digest
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "reservation checkpoint digest differs from its sealed reference",
            ));
        }
        if closure
            .prelaunch
            .reservation_checkpoint
            .runtime_records
            .len()
            != reservation_checkpoint_records.len()
            || closure
                .prelaunch
                .reservation_checkpoint
                .runtime_records
                .iter()
                .zip(reservation_checkpoint_records)
                .any(|(reference, record)| !reference.matches(record))
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "reservation checkpoint membership differs from its sealed reference",
            ));
        }
        if closure.prelaunch.outer_request.record_id != inspection.prelaunch.outer_request_record_id
            || closure.prelaunch.outer_request.bytes_digest
                != inspection.prelaunch.outer_request_digest
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "reservation checkpoint or accepted-decision correspondence differs",
            ));
        }

        let launch_record = &sources.launch_record;
        let launch_checkpoint = &sources.launch_checkpoint;
        let launch_checkpoint_records = &sources.launch_checkpoint_records;
        if closure.prelaunch.launch_checkpoint.checkpoint_id.as_str()
            != launch_checkpoint.checkpoint_id
            || closure.prelaunch.launch_checkpoint.batch_digest != launch_checkpoint.batch_digest
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "launch checkpoint digest differs from its sealed reference",
            ));
        }
        if closure.prelaunch.launch_checkpoint.runtime_records.len()
            != launch_checkpoint_records.len()
            || closure
                .prelaunch
                .launch_checkpoint
                .runtime_records
                .iter()
                .zip(launch_checkpoint_records)
                .any(|(reference, record)| !reference.matches(record))
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "launch checkpoint membership differs from its sealed reference",
            ));
        }
        if launch_record.record_id != closure.acquisition.execution_launch_record_id.as_str()
            || inspection.execution_launch_record_id.as_ref()
                != Some(&sources.acquisition.execution_launch_record_id)
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "launch checkpoint, predecessor, or physical claim correspondence differs",
            ));
        }
        let physical_derivation = &sources.derivation_claim;
        if !closure.derivation.matches(physical_derivation)
            || closure.derivation.dependency_generation_id
                != closure.dependency_generation.generation_id
            || closure.derivation.dependency_generation_custody_digest
                != closure.dependency_generation.custody_bytes_digest
            || closure.derivation.trust_anchor_id != closure.dependency_generation.trust_anchor_id
            || closure.derivation.evaluation_id != closure.local_origin.evaluation_id
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "sealed derivation differs from the complete physical claim or local origin",
            ));
        }
        let diagnostic_schema = closure
            .diagnostic
            .get("schema")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                projection_local_mismatch(
                    reservation_record_id,
                    "embedded diagnostic schema is absent",
                )
            })?;
        if diagnostic_schema != "nq.diagnostic_execution.v2" {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "only the production V2 diagnostic contract may be projected",
            ));
        }
        if closure
            .diagnostic
            .pointer("/profile_semantic_id")
            .and_then(Value::as_str)
            != Some(closure.derivation.profile_semantic_id.as_str())
            || closure
                .diagnostic
                .pointer("/evaluator/digest")
                .and_then(Value::as_str)
                != closure
                    .derivation
                    .evaluator_semantic_digest
                    .as_ref()
                    .map(Sha256Digest::as_str)
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
            return Err(projection_local_mismatch(
                reservation_record_id,
                "diagnostic profile, evaluator, derivation time, or clock differs from custody",
            ));
        }
        let clock_qualification = closure
            .diagnostic
            .pointer("/attempt_interval/qualification")
            .ok_or_else(|| {
                projection_local_mismatch(
                    reservation_record_id,
                    "diagnostic clock qualification is absent",
                )
            })?;
        if closure.derivation.clock_uncertainty_ms.is_some()
            || !matches!(
                clock_qualification.get("state").and_then(Value::as_str),
                Some("bounded" | "unqualified")
            )
            || closure
                .derivation
                .clock_qualification_digest
                .as_ref()
                .is_none_or(|expected| {
                    semantic_digest(clock_qualification).map_or(true, |actual| actual != *expected)
                })
        {
            return Err(projection_local_mismatch(
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
                    projection_local_mismatch(
                        reservation_record_id,
                        "embedded diagnostic artifact identity is absent",
                    )
                })?
                .to_owned(),
        )
        .map_err(|error| {
            projection_local_mismatch(
                reservation_record_id,
                format!("embedded diagnostic artifact identity is invalid: {error}"),
            )
        })?;
        let execution_launch_record_id = Sha256Digest::parse(launch_record.record_id.clone())
            .map_err(|error| {
                projection_local_mismatch(
                    reservation_record_id,
                    format!("execution-launch record identity is invalid: {error}"),
                )
            })?;
        let evaluator_semantic_digest = closure
            .derivation
            .evaluator_semantic_digest
            .as_ref()
            .ok_or_else(|| {
                projection_local_mismatch(
                    reservation_record_id,
                    "governed V3 derivation has no evaluator semantic identity",
                )
            })?;
        let clock_qualification_digest = closure
            .derivation
            .clock_qualification_digest
            .as_ref()
            .ok_or_else(|| {
                projection_local_mismatch(
                    reservation_record_id,
                    "governed V3 derivation has no clock-qualification identity",
                )
            })?;
        let recomputed_derivation_id =
            governed_derivation_identity(&GovernedDerivationIdentityInput {
                diagnostic_artifact_id: &diagnostic_artifact_id,
                diagnostic_file_bytes_digest: &diagnostic_file_bytes_digest,
                provider_intake: GovernedDerivationRecordRef {
                    schema: &closure.acquisition.provider_intake.schema,
                    record_id: &closure.acquisition.provider_intake.record_id,
                    bytes_digest: &closure.acquisition.provider_intake.bytes_digest,
                },
                execution_launch: GovernedDerivationRecordRef {
                    schema: &launch_record.record_schema,
                    record_id: &execution_launch_record_id,
                    bytes_digest: &launch_record.canonical_bytes_sha256,
                },
                dependency_generation_id: &closure.derivation.dependency_generation_id,
                dependency_generation_custody_digest: &closure
                    .derivation
                    .dependency_generation_custody_digest,
                trust_anchor_id: &closure.derivation.trust_anchor_id,
                profile_semantic_id: &closure.derivation.profile_semantic_id,
                evaluator_semantic_digest,
                evaluator_artifact_digest: &closure.derivation.evaluator_artifact_digest,
                derived_at: &closure.derivation.derived_at,
                clock_identity: &closure.derivation.clock_identity,
                clock_qualification_digest,
            })
            .map_err(|error| {
                projection_local_mismatch(
                    reservation_record_id,
                    format!("governed derivation identity cannot be recomputed: {error}"),
                )
            })?;
        if recomputed_derivation_id != closure.derivation.derivation_id {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "governed derivation identity differs from exact native inputs",
            ));
        }
        if plan.collection.intake.profile_semantic_id != closure.derivation.profile_semantic_id
            || plan.collection.intake.evaluator_artifact_digest
                != closure.derivation.evaluator_artifact_digest
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "capsule provider semantic or evaluator artifact identity differs from derivation",
            ));
        }

        let binding = plan
            .diagnostic
            .local_origin
            .execution_binding
            .as_ref()
            .ok_or_else(|| {
                projection_local_mismatch(
                    reservation_record_id,
                    "capsule diagnostic has no execution binding",
                )
            })?;
        let outer_request_id =
            exact_json_string(reservation_record_id, outer_request_record, "request_id")?
                .ok_or_else(|| {
                    projection_integrity(
                        reservation_record_id,
                        "exact outer-request record has no request identity",
                    )
                })?;
        let plan_diagnostic_value: Value = serde_json::from_slice(
            plan.diagnostic.canonical_bytes.as_bytes(),
        )
        .map_err(|error| {
            projection_local_mismatch(
                reservation_record_id,
                format!("capsule diagnostic cannot be decoded: {error}"),
            )
        })?;
        if binding.outer_request_id != outer_request_id
            || binding.outer_request_id != inspection.prelaunch.outer_request_id
            || plan_diagnostic_value
                .pointer("/request_id")
                .and_then(Value::as_str)
                != Some(outer_request_id.as_str())
            || plan.collection.intake.request_id != plan.collection.run.request_id
            || plan.collection.run.request_id == outer_request_id
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "capsule child request and sealed outer request identities collapse or fail their exact bindings",
            ));
        }
        let provider_records = binding
            .runtime_records
            .records
            .iter()
            .filter(|record| record.record_schema == "nq.provider_intake.v1")
            .count();
        let execution_binding_records = binding
            .runtime_records
            .records
            .iter()
            .filter(|record| record.record_schema == "nq.execution_identity_binding.v2")
            .count();
        if binding.runtime_records.records.len() != 2
            || closure.runtime_records.len() != 2
            || provider_records != 1
            || execution_binding_records != 1
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "terminal checkpoint must contain exactly one provider intake and one execution binding",
            ));
        }
        if binding
            .runtime_records
            .expected_predecessor_checkpoint_id
            .as_deref()
            != Some(launch_checkpoint.checkpoint_id.as_str())
            || binding
                .runtime_records
                .expected_predecessor_ledger_root
                .as_ref()
                != Some(&launch_checkpoint.checkpoint_ledger_root)
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "terminal checkpoint does not continue the exact sealed launch frontier",
            ));
        }
        let dependency_bytes = &sources.exact_dependency_bytes;
        if sha256_bytes(dependency_bytes) != closure.dependency_generation.custody_bytes_digest
            || closure.dependency_generation.generation_id != sources.dependency.generation_id
            || closure.dependency_generation.trust_anchor_id != sources.dependency.trust_anchor_id
            || binding
                .runtime_records
                .dependency
                .canonical_custody
                .as_bytes()
                != dependency_bytes.as_slice()
        {
            return Err(projection_local_mismatch(
                reservation_record_id,
                "terminal dependency generation differs from sealed arena custody",
            ));
        }
        verify_checkpoint_dependency(
            connection,
            reservation_record_id,
            &reservation_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            dependency_bytes,
        )?;
        verify_checkpoint_dependency(
            connection,
            reservation_record_id,
            &launch_checkpoint.checkpoint_id,
            &closure.dependency_generation,
            dependency_bytes,
        )?;

        Ok(())
    })();
    if let Err(error) = deep_correspondence {
        return Err(match sources.physical_footprint {
            PhysicalGovernedProjectionFootprint::Absent => error,
            PhysicalGovernedProjectionFootprint::Present => {
                globalize_projection_local_mismatch(error)
            }
        });
    }

    Ok(Some(PendingGovernedProjection {
        reservation_record_id: reservation_record_id.clone(),
        physical_execution_launch_record_id: acquisition.execution_launch_record_id.clone(),
        plan,
        sql_footprint,
        sources: sources.clone(),
        snapshot: PhantomData,
    }))
}

fn prevalidate_governed_v3_projection_with_arena<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    reservation_record_id: &Sha256Digest,
    arena: &CustodyArena,
) -> Result<Option<PendingGovernedProjection<'snapshot>>, StoreError> {
    let exact_closure_bytes = arena
        .final_v2_closure_bytes()
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(reservation_record_id, "final closure bytes are absent")
        })?;
    let exact_closure_value: Value =
        serde_json::from_slice(&exact_closure_bytes).map_err(|error| {
            projection_integrity(
                reservation_record_id,
                format!("final closure shape is incompatible: {error}"),
            )
        })?;
    if canonical_json_bytes(&exact_closure_value).map_err(|error| {
        projection_integrity(
            reservation_record_id,
            format!("final closure cannot be canonicalized: {error}"),
        )
    })? != exact_closure_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            "final closure bytes are not exact canonical JSON",
        ));
    }
    if exact_closure_value.get("schema").and_then(Value::as_str)
        != Some(GOVERNED_CUSTODY_CLOSURE_V3_SCHEMA)
    {
        return Err(projection_integrity(
            reservation_record_id,
            "historical pre-V3 closure cannot earn authenticated complete-verification standing",
        ));
    }

    // For V3, authenticate every Store-selected source before any capsule is
    // decoded or any arena-local mismatch can be adjudicated.
    let sources =
        resolve_independent_governed_projection_sources(connection, reservation_record_id, arena)?;
    prevalidate_governed_v3_projection_with_sources(
        connection,
        reservation_record_id,
        arena,
        &sources,
    )
}

fn terminalize_projection_correspondence_refusal(
    database_path: &Path,
    reservation_record_id: &Sha256Digest,
    correspondence_error: &StoreError,
) -> Result<StoreError, StoreError> {
    let mut arena = CustodyArena::open_by_reservation(database_path, reservation_record_id)
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(reservation_record_id, "physical custody arena is absent")
        })?;
    let (terminal_error, original_final_bytes, exact_refusal_bytes) =
        terminalize_projection_correspondence_refusal_with_arena(
            &mut arena,
            reservation_record_id,
            correspondence_error,
        )?;
    drop(arena);

    let reopened = CustodyArena::open_by_reservation(database_path, reservation_record_id)
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "projection-refused arena disappeared during durable reopen",
            )
        })?;
    let (_, reopened_final_bytes, reopened_refusal_bytes) =
        verified_projection_refusal_with_arena(&reopened, reservation_record_id)?;
    if reopened_final_bytes != original_final_bytes || reopened_refusal_bytes != exact_refusal_bytes
    {
        return Err(projection_integrity(
            reservation_record_id,
            "projection-refusal transition did not preserve exact final and reason bytes",
        ));
    }
    Ok(terminal_error)
}

fn projection_refusal_recovery(
    error: StoreError,
) -> Result<GovernedProjectionRecovery, StoreError> {
    match error {
        StoreError::GovernedProjectionCorrespondenceRefused {
            reservation_record_id,
            refusal_id,
            reason,
        } => Ok(GovernedProjectionRecovery::CorrespondenceRefused {
            reservation_record_id,
            refusal_id,
            reason,
        }),
        error => Err(error),
    }
}

fn verified_projection_refusal_with_arena(
    arena: &CustodyArena,
    reservation_record_id: &Sha256Digest,
) -> Result<(ProjectionCorrespondenceRefusalDocument, Vec<u8>, Vec<u8>), StoreError> {
    let inspection = arena.inspection().map_err(custody_error)?;
    if inspection.state != ArenaState::FinalV2ProjectionRefused {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "projection-refusal reopen requires terminal state, found {:?}",
                inspection.state
            ),
        ));
    }
    let exact_refusal_bytes = arena
        .protected_failure_bytes()
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "projection-refused arena has no exact refusal carrier",
            )
        })?;
    let document = ProjectionCorrespondenceRefusalDocument::from_exact_bytes(&exact_refusal_bytes)?;
    let original_final_bytes = arena
        .final_v2_closure_bytes()
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "projection-refused arena has no exact final-closure bytes",
            )
        })?;
    let final_section = inspection.final_v2_closure.as_ref().ok_or_else(|| {
        projection_integrity(
            reservation_record_id,
            "projection-refused arena has no final-closure commitment",
        )
    })?;
    if document.reservation_record_id != *reservation_record_id
        || inspection.reservation_id != *reservation_record_id
        || inspection.execution_launch_record_id.as_ref()
            != Some(&document.execution_launch_record_id)
        || document.final_closure.byte_length != final_section.payload_length()
        || document.final_closure.bytes_digest != *final_section.payload_digest()
        || u64::try_from(original_final_bytes.len()).map_err(|_| {
            projection_integrity(
                reservation_record_id,
                "projection-refused final-closure length exceeds u64",
            )
        })? != document.final_closure.byte_length
        || sha256_bytes(&original_final_bytes) != document.final_closure.bytes_digest
    {
        return Err(projection_integrity(
            reservation_record_id,
            "projection-refusal carrier differs from its exact launch or final closure",
        ));
    }
    Ok((document, original_final_bytes, exact_refusal_bytes))
}

fn terminalize_projection_correspondence_refusal_with_arena(
    arena: &mut CustodyArena,
    reservation_record_id: &Sha256Digest,
    correspondence_error: &StoreError,
) -> Result<(StoreError, Vec<u8>, Vec<u8>), StoreError> {
    let inspection = arena.inspection().map_err(custody_error)?;
    if inspection.state == ArenaState::FinalV2ProjectionRefused {
        let (document, original_final_bytes, exact_refusal_bytes) =
            verified_projection_refusal_with_arena(arena, reservation_record_id)?;
        return Ok((
            document.as_store_error(),
            original_final_bytes,
            exact_refusal_bytes,
        ));
    }
    if inspection.state != ArenaState::FinalV2SealedIndexPending {
        return Err(projection_integrity(
            reservation_record_id,
            format!(
                "cannot terminalize correspondence from arena state {:?}",
                inspection.state
            ),
        ));
    }
    let execution_launch_record_id =
        inspection
            .execution_launch_record_id
            .clone()
            .ok_or_else(|| {
                projection_integrity(
                    reservation_record_id,
                    "index-pending arena has no execution-launch identity",
                )
            })?;
    let final_section = inspection.final_v2_closure.clone().ok_or_else(|| {
        projection_integrity(
            reservation_record_id,
            "index-pending arena has no final-closure commitment",
        )
    })?;
    let original_final_bytes = arena
        .final_v2_closure_bytes()
        .map_err(custody_error)?
        .ok_or_else(|| {
            projection_integrity(
                reservation_record_id,
                "index-pending arena has no exact final-closure bytes",
            )
        })?;
    let (document, exact_refusal_bytes) = ProjectionCorrespondenceRefusalDocument::from_error(
        reservation_record_id.clone(),
        execution_launch_record_id,
        ProjectionRefusalClosureCommitment {
            byte_length: final_section.payload_length(),
            bytes_digest: final_section.payload_digest().clone(),
        },
        correspondence_error,
    )?;
    let candidate = ArenaFailureCarrierCandidate::parse_projection_correspondence_refusal(
        exact_refusal_bytes.clone(),
    )
    .map_err(custody_error)?;
    arena
        .refuse_final_projection(candidate)
        .map_err(custody_error)?;
    let terminal_inspection = arena.inspection().map_err(custody_error)?;
    if terminal_inspection.state != ArenaState::FinalV2ProjectionRefused
        || arena
            .final_v2_closure_bytes()
            .map_err(custody_error)?
            .as_deref()
            != Some(original_final_bytes.as_slice())
        || arena
            .protected_failure_bytes()
            .map_err(custody_error)?
            .as_deref()
            != Some(exact_refusal_bytes.as_slice())
    {
        return Err(projection_integrity(
            reservation_record_id,
            "projection-refusal transition did not preserve exact final and reason bytes",
        ));
    }
    Ok((
        document.as_store_error(),
        original_final_bytes,
        exact_refusal_bytes,
    ))
}

pub(crate) fn terminalize_projection_local_mismatch(
    database_path: &Path,
    error: &StoreError,
) -> Result<StoreError, StoreError> {
    let StoreError::GovernedProjectionLocalCorrespondenceMismatch {
        reservation_record_id,
        ..
    } = error
    else {
        return Err(StoreError::Invariant(
            "only one typed projection-local mismatch may be terminalized".into(),
        ));
    };
    terminalize_projection_correspondence_refusal(database_path, reservation_record_id, error)
}

pub(crate) fn prevalidate_governed_v3_projection_with_custody<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    custody: &GovernedCustody,
) -> Result<Option<PendingGovernedProjection<'snapshot>>, StoreError> {
    let reservation_record_id = &custody.reservation.reservation_record_id;
    let mut owners = BTreeMap::new();
    let sources = resolve_independent_governed_projection_sources(
        connection,
        reservation_record_id,
        &custody.arena,
    )?;
    remember_independent_governed_projection_source_identities(
        &mut owners,
        reservation_record_id,
        &sources,
    )?;
    let candidate = match shallow_reopen_governed_v3_projection_with_arena(
        reservation_record_id,
        &custody.arena,
        &sources,
    ) {
        Ok(value) => value,
        Err(error @ StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }) => {
            // Even a capsule-independent local refusal must wait for global
            // allocator/ledger qualification under the same IMMEDIATE fence.
            crate::preflight_reopened_governed_projection_batch(connection, &[])?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    crate::remember_reopened_governed_projection_identities(
        reservation_record_id,
        &candidate.plan,
        &mut owners,
    )?;
    let shallow = classify_reopened_governed_projection_candidate(connection, candidate)?;
    let batch_local = match crate::preflight_reopened_governed_projection_batch(
        connection,
        std::slice::from_ref(&shallow),
    ) {
        Ok(()) => None,
        Err(error @ StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }) => {
            Some(error)
        }
        Err(error) => return Err(error),
    };
    let deep = match prevalidate_governed_v3_projection_with_sources(
        connection,
        reservation_record_id,
        &custody.arena,
        &sources,
    ) {
        Ok(Some(deep)) => deep,
        Ok(None) => {
            return Err(projection_integrity(
                reservation_record_id,
                "V3 projection became a pre-V3 closure during deep validation",
            ));
        }
        Err(error @ StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }) => {
            return Err(batch_local.unwrap_or(error));
        }
        Err(error) => return Err(error),
    };
    if deep.sql_footprint != shallow.sql_footprint {
        return Err(projection_integrity(
            reservation_record_id,
            "SQL footprint changed between shallow and deep validation",
        ));
    }
    if let Some(error) = batch_local {
        return Err(error);
    }
    Ok(Some(shallow))
}

struct PostInsertGovernedProjectionSources<'snapshot> {
    sources: IndependentGovernedProjectionSources<'snapshot>,
}

fn transition_prevalidated_sources_after_replay_insert<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    prevalidated: &PendingGovernedProjection<'snapshot>,
) -> Result<PostInsertGovernedProjectionSources<'snapshot>, StoreError> {
    if prevalidated.sources.physical_footprint != PhysicalGovernedProjectionFootprint::Absent {
        return Err(projection_integrity(
            &prevalidated.reservation_record_id,
            "pre-insert authenticated source bundle did not observe an absent SQL projection",
        ));
    }
    let mut sources = prevalidated.sources.clone();
    let post_insert_footprint = classify_physical_governed_projection_footprint(
        connection,
        &prevalidated.reservation_record_id,
        &sources.acquisition,
    )?;
    if post_insert_footprint != PhysicalGovernedProjectionFootprint::Present {
        return Err(projection_integrity(
            &prevalidated.reservation_record_id,
            "post-insert replay phase did not produce the exact physical SQL projection",
        ));
    }
    // The six authenticated dependency/authority sources, root, checkpoints,
    // records, and arena bindings remain the one prevalidated bundle. Only
    // the SQL publication footprint is phase-relative: the same IMMEDIATE
    // transaction intentionally changes it from Absent to Present.
    sources.physical_footprint = post_insert_footprint;
    Ok(PostInsertGovernedProjectionSources { sources })
}

pub(crate) fn verify_governed_projection_after_replay_insert_with_custody<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    custody: &mut GovernedCustody,
    prevalidated: &PendingGovernedProjection<'snapshot>,
) -> Result<GovernedProjectionVerification, StoreError> {
    if prevalidated.reservation_record_id != custody.reservation.reservation_record_id {
        return Err(projection_integrity(
            &custody.reservation.reservation_record_id,
            "prevalidated projection belongs to another custody reservation",
        ));
    }
    let post_insert =
        transition_prevalidated_sources_after_replay_insert(connection, prevalidated)?;
    Store::verify_governed_projection_with_arena(
        connection,
        &custody.reservation.reservation_record_id,
        &mut custody.arena,
        GovernedProjectionVerificationPhase::UncommittedReplay,
        false,
        Some(&post_insert.sources),
    )
}

pub(crate) fn verify_pending_governed_projection_on_connection<'snapshot>(
    connection: &'snapshot rusqlite::Connection,
    database_path: &Path,
    pending: &PendingGovernedProjection<'snapshot>,
    phase: GovernedProjectionVerificationPhase,
) -> Result<GovernedProjectionVerification, StoreError> {
    match phase {
        GovernedProjectionVerificationPhase::UncommittedReplay => {
            let post_insert =
                transition_prevalidated_sources_after_replay_insert(connection, pending)?;
            Store::verify_governed_projection_on_connection_with_sources(
                connection,
                database_path,
                &pending.reservation_record_id,
                phase,
                false,
                Some(&post_insert.sources),
            )
        }
        GovernedProjectionVerificationPhase::DurableProjection => {
            if pending.sources.physical_footprint != PhysicalGovernedProjectionFootprint::Present {
                return Err(projection_integrity(
                    &pending.reservation_record_id,
                    "durable verification reused a pre-insert SQL projection footprint",
                ));
            }
            Store::verify_governed_projection_on_connection_with_sources(
                connection,
                database_path,
                &pending.reservation_record_id,
                phase,
                false,
                Some(&pending.sources),
            )
        }
    }
}

pub(crate) fn terminalize_projection_local_mismatch_with_custody(
    custody: &mut GovernedCustody,
    error: &StoreError,
) -> Result<StoreError, StoreError> {
    let reservation_record_id = custody.reservation.reservation_record_id.clone();
    if !is_projection_local_correspondence_error(&reservation_record_id, error) {
        return Err(StoreError::Invariant(
            "only this custody handle's typed projection-local mismatch may be terminalized".into(),
        ));
    }
    terminalize_projection_correspondence_refusal_with_arena(
        &mut custody.arena,
        &reservation_record_id,
        error,
    )
    .map(|(terminal_error, _, _)| terminal_error)
}

pub(crate) fn terminalize_projection_incompatible_closure_with_custody(
    custody: &mut GovernedCustody,
    reason: impl std::fmt::Display,
) -> Result<StoreError, StoreError> {
    let error = projection_local_mismatch(&custody.reservation.reservation_record_id, reason);
    terminalize_projection_local_mismatch_with_custody(custody, &error)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FinalSealIntentAdjudication {
    pub(crate) reservation_record_id: Sha256Digest,
    pub(crate) disposition: FinalSealIntentDisposition,
}

/// Adjudicate every explicitly committed final-seal intent.
///
/// This may be called only while the caller owns the Store-wide SQLite
/// IMMEDIATE publication lock. It opens no provider/evaluator path. Exact
/// staged bytes advance to index-pending; absence or substitution advances to
/// an inspectable terminal custody state.
pub(crate) fn adjudicate_final_seal_intents(
    database_path: &Path,
) -> Result<Vec<FinalSealIntentAdjudication>, StoreError> {
    let inventory = CustodyArena::state_inventory_unlocked(
        database_path,
        usize::try_from(MAX_PUBLIC_QUERY_ROWS).unwrap_or(1_000),
    )
    .map_err(custody_error)?;
    let mut adjudicated = Vec::new();
    for entry in inventory {
        let (reservation_record_id, state) = match entry {
            ArenaStateInventoryEntry::Verified {
                reservation_id,
                state,
                ..
            } => (reservation_id, state),
            ArenaStateInventoryEntry::Unreadable {
                relative_path,
                reason,
            } => {
                return Err(StoreError::Integrity(format!(
                    "governed final-seal adjudication cannot inspect arena {}: {reason}",
                    relative_path.display()
                )));
            }
        };
        if state != ArenaState::FinalV2SealIntent {
            continue;
        }
        let mut arena = CustodyArena::open_by_reservation(database_path, &reservation_record_id)
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(
                    &reservation_record_id,
                    "final-seal-intent arena disappeared during adjudication",
                )
            })?;
        let disposition = arena
            .adjudicate_final_v2_seal_intent()
            .map_err(custody_error)?;
        adjudicated.push(FinalSealIntentAdjudication {
            reservation_record_id,
            disposition,
        });
    }
    Ok(adjudicated)
}

/// Reopen exact final-pending V3 projection plans from physical custody.
///
/// Callers use this only while holding the SQLite IMMEDIATE publication lock.
/// The scan is bounded and ordered by the sealed global status publication
/// sequence. An unreadable, malformed, or incomparable arena refuses the
/// publication gate rather than being omitted.
#[allow(clippy::too_many_lines)] // One bounded scan preserves ordering, ownership, and refusal correspondence.
pub(crate) fn pending_v3_projection_plans<'snapshot>(
    database_path: &Path,
    connection: &'snapshot rusqlite::Connection,
) -> Result<Vec<PendingGovernedProjection<'snapshot>>, StoreError> {
    let mut pending = Vec::new();
    let mut owners = BTreeMap::new();
    let mut first_shallow_local_mismatch = None;
    let mut source_bundles = Vec::new();
    for entry in CustodyArena::state_inventory_unlocked(
        database_path,
        usize::try_from(MAX_PUBLIC_QUERY_ROWS).unwrap_or(1_000),
    )
    .map_err(custody_error)?
    {
        let (reservation_record_id, state) = match entry {
            ArenaStateInventoryEntry::Verified {
                reservation_id,
                state,
                ..
            } => (reservation_id, state),
            ArenaStateInventoryEntry::Unreadable {
                relative_path,
                reason,
            } => {
                return Err(StoreError::Integrity(format!(
                    "governed publication gate cannot inspect arena {}: {reason}",
                    relative_path.display()
                )));
            }
        };
        // A terminal refusal is no longer unpublished work only after exact
        // final and refusal bytes reopen and validate. Header-only inventory
        // cannot justify skipping this arena.
        if state == ArenaState::FinalV2ProjectionRefused {
            let arena = CustodyArena::open_by_reservation(database_path, &reservation_record_id)
                .map_err(custody_error)?
                .ok_or_else(|| {
                    projection_integrity(
                        &reservation_record_id,
                        "projection-refused arena disappeared during full reopen",
                    )
                })?;
            verified_projection_refusal_with_arena(&arena, &reservation_record_id)?;
            continue;
        }
        if state != ArenaState::FinalV2SealedIndexPending {
            continue;
        }
        let arena = CustodyArena::open_by_reservation(database_path, &reservation_record_id)
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(
                    &reservation_record_id,
                    "pending arena disappeared during independent source resolution",
                )
            })?;
        let sources = resolve_independent_governed_projection_sources(
            connection,
            &reservation_record_id,
            &arena,
        )?;
        remember_independent_governed_projection_source_identities(
            &mut owners,
            &reservation_record_id,
            &sources,
        )?;
        source_bundles.push((reservation_record_id, sources));
    }

    // Decode every capsule only after all independent arena-selected sources
    // are globally resolved and registered. Keep local decoding failures
    // pending until every other arena has had a chance to expose a global
    // defect.
    let mut candidates = Vec::new();
    for (reservation_record_id, sources) in source_bundles {
        let arena = CustodyArena::open_by_reservation(database_path, &reservation_record_id)
            .map_err(custody_error)?
            .ok_or_else(|| {
                projection_integrity(
                    &reservation_record_id,
                    "pending arena disappeared during capsule reopen",
                )
            })?;
        match shallow_reopen_governed_v3_projection_with_arena(
            &reservation_record_id,
            &arena,
            &sources,
        ) {
            Ok(Some(candidate)) => candidates.push(candidate),
            Ok(None) => {
                return Err(projection_integrity(
                    &reservation_record_id,
                    "ordinary publication is fenced by an unrecoverable pre-V3 pending closure",
                ));
            }
            Err(error @ StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }) => {
                if first_shallow_local_mismatch.is_none() {
                    first_shallow_local_mismatch = Some(error);
                }
            }
            Err(error) => return Err(error),
        }
    }

    // Register the complete owner set before consulting any SQL footprint.
    // Inventory order therefore cannot decide which arena appears to own a
    // colliding identity.
    for candidate in &candidates {
        crate::remember_reopened_governed_projection_identities(
            &candidate.reservation_record_id,
            &candidate.plan,
            &mut owners,
        )?;
    }
    for candidate in candidates {
        pending.push(classify_reopened_governed_projection_candidate(
            connection, candidate,
        )?);
    }
    pending.sort_by(|left, right| {
        left.plan
            .publication
            .status_sequence
            .cmp(&right.plan.publication.status_sequence)
            .then_with(|| left.reservation_record_id.cmp(&right.reservation_record_id))
    });

    // Finish every global/whole-batch footprint check before permitting any
    // arena-local mismatch to become a durable refusal.
    let mut first_local_mismatch = first_shallow_local_mismatch;
    if let Err(error) = crate::preflight_reopened_governed_projection_batch(connection, &pending) {
        match error {
            error @ StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. } => {
                if first_local_mismatch.is_none() {
                    first_local_mismatch = Some(error);
                }
            }
            error => return Err(error),
        }
    }

    // Deep-check every successfully reopened candidate even after one local
    // mismatch. Any later global corruption dominates and leaves every arena
    // pending. Only an all-global-clean batch may expose one deterministic
    // local refusal for terminalization.
    for projection in &pending {
        match prevalidate_governed_v3_projection_before_sql(
            connection,
            database_path,
            &projection.reservation_record_id,
            &projection.sources,
        ) {
            Ok(Some(deep)) => {
                if deep.sql_footprint != projection.sql_footprint {
                    return Err(projection_integrity(
                        &projection.reservation_record_id,
                        "SQL footprint changed between shallow and deep validation",
                    ));
                }
            }
            Ok(None) => {
                return Err(projection_integrity(
                    &projection.reservation_record_id,
                    "V3 projection became a pre-V3 closure during deep validation",
                ));
            }
            Err(error @ StoreError::GovernedProjectionLocalCorrespondenceMismatch { .. }) => {
                if first_local_mismatch.is_none() {
                    first_local_mismatch = Some(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(error) = first_local_mismatch {
        return Err(error);
    }
    Ok(pending)
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
            projection_capsule_capacity_bytes: 4_096,
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
                projection_capsule_capacity_bytes: reservation.projection_capsule_capacity_bytes,
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
    fn unestablished_clock_correspondence_permits_wall_rollback_without_minting_compliance() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("wall-rollback-launch");
        let mut custody = GovernedCustody::reserve(&database, reservation.clone(), dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");

        let mut rolled_back = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PreEffectRefusal,
            "wall_clock_correspondence_not_established",
        );
        rolled_back.terminalized_at = "2026-07-29T22:28:00Z".into();
        rolled_back.deadline_compliance =
            GovernedProtectedTerminalDeadlineCompliance::NotEstablished;
        let committed = custody
            .terminalize_immediate_launch(rolled_back)
            .expect("physical terminal transition does not depend on wall ordering");
        assert_eq!(
            committed.terminal.document().terminalized_at,
            "2026-07-29T22:28:00Z"
        );
        assert_eq!(
            committed.terminal.document().deadline_compliance,
            GovernedProtectedTerminalDeadlineCompliance::NotEstablished
        );

        drop(custody);
        let reopened =
            GovernedCustody::open(&database, reservation).expect("reopen terminal custody");
        let terminal = reopened
            .protected_terminal()
            .expect("typed terminal read")
            .expect("terminal present");
        assert_eq!(terminal, committed.terminal);
        assert_eq!(
            terminal.document().deadline_compliance,
            GovernedProtectedTerminalDeadlineCompliance::NotEstablished
        );
    }

    #[test]
    fn established_deadline_assessments_retain_strict_wall_ordering_laws() {
        for (name, compliance) in [
            (
                "within",
                GovernedProtectedTerminalDeadlineCompliance::WithinDeadline,
            ),
            (
                "reached",
                GovernedProtectedTerminalDeadlineCompliance::DeadlineReachedOrExceeded,
            ),
        ] {
            let directory = tempdir().expect("directory");
            let database = directory.path().join("nq.db");
            create_database_placeholder(&database);
            let dependencies = b"exact dependency closure";
            let reservation = reservation(dependencies);
            let launch = digest(&format!("strict-{name}-launch"));
            let mut custody = GovernedCustody::reserve(&database, reservation, dependencies)
                .expect("reserve custody");
            custody
                .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
                .expect("launch claim");
            let mut wall_rollback = terminal_input(
                &launch,
                GovernedProtectedTerminalClass::PreEffectRefusal,
                &format!("strict_{name}_wall_rollback"),
            );
            wall_rollback.terminalized_at = "2026-07-29T22:28:00Z".into();
            wall_rollback.deadline_compliance = compliance;
            assert!(matches!(
                custody.terminalize_immediate_launch(wall_rollback),
                Err(StoreError::Invariant(message))
                    if message.contains("deadline assessment contradicts")
            ));
        }

        let directory = tempdir().expect("directory");
        let database = directory.path().join("nq.db");
        create_database_placeholder(&database);
        let dependencies = b"exact dependency closure";
        let reservation = reservation(dependencies);
        let launch = digest("strict-deadline-relation-launch");
        let mut custody = GovernedCustody::reserve(&database, reservation, dependencies)
            .expect("reserve custody");
        custody
            .claim_launch(launch.clone(), "2026-07-29T22:29:00Z".into())
            .expect("launch claim");
        let mut before_deadline = terminal_input(
            &launch,
            GovernedProtectedTerminalClass::PreEffectRefusal,
            "deadline_not_yet_reached",
        );
        before_deadline.deadline_compliance =
            GovernedProtectedTerminalDeadlineCompliance::DeadlineReachedOrExceeded;
        assert!(matches!(
            custody.terminalize_immediate_launch(before_deadline),
            Err(StoreError::Invariant(message))
                if message.contains("deadline assessment")
        ));
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
