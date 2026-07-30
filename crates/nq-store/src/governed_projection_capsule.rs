//! Exact, inert replay carrier for one governed SQL projection.
//!
//! A capsule is prepared only after NQ core has derived the complete
//! diagnostic result, but before the physical final closure is sealed.  It
//! contains the exact Store inputs needed to repeat the already-decided SQL
//! projection after restart.  It contains no provider command, profile,
//! evaluator, scheduling, reliance, authorization, or action capability.

use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CanonicalDocument, CollectionInput, CoverageInput, DiagnosticArtifactCommitInput,
    DiagnosticArtifactExecutionBindingInput, DiagnosticArtifactLocalOriginInput,
    DiagnosticArtifactProviderAttemptBindingInput, ObservationInput, ProviderIntakeInput,
    RefusalInput, ReportErrorInput, ReportInput, RunInput, RuntimeCheckpointDependencyInput,
    RuntimeRecordBatchInput, RuntimeRecordInput, StatusEventInput, StoreError,
    SubmissionDisposition, SubmissionInput,
};

pub const GOVERNED_PROJECTION_CAPSULE_SCHEMA: &str = "nq.governed_projection_capsule.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProjectionCapsuleMode {
    Admitted,
    NonSuccess,
}

#[derive(Clone, Debug)]
pub struct GovernedProjectionCapsuleInput {
    pub reservation_record_id: Sha256Digest,
    pub collection: CollectionInput,
    pub diagnostic_artifact: DiagnosticArtifactCommitInput,
    pub status: StatusEventInput,
    pub mode: GovernedProjectionCapsuleMode,
    pub expected_semantic_digest: Option<Sha256Digest>,
    /// Exact database-publication identities allocated inside the projection
    /// transaction before the physical final closure is sealed.
    pub publication: GovernedProjectionPublication,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProjectionPublication {
    /// Admitted-report publication order. Non-success projections carry none.
    pub report_sequence: Option<i64>,
    /// Immutable status-event publication order.
    pub status_sequence: i64,
    /// Exact durable provider-acknowledgment identity.
    pub acknowledgment_id: String,
    /// Exact acknowledgment commit time chosen for this publication.
    pub acknowledgment_committed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProjectionCapsule {
    capsule_id: Sha256Digest,
    reservation_record_id: Sha256Digest,
    canonical_bytes: CanonicalDocument,
}

impl GovernedProjectionCapsule {
    pub fn build(input: &GovernedProjectionCapsuleInput) -> Result<Self, StoreError> {
        validate_capsule_input(input)?;
        Self::build_validated(input)
    }

    fn build_validated(input: &GovernedProjectionCapsuleInput) -> Result<Self, StoreError> {
        let preimage = capsule_preimage(input)?;
        let capsule_id = semantic_digest(&preimage)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        let document = CapsuleDocument {
            schema: GOVERNED_PROJECTION_CAPSULE_SCHEMA.to_owned(),
            capsule_id: capsule_id.clone(),
            reservation_record_id: preimage.reservation_record_id,
            mode: preimage.mode,
            expected_semantic_digest: preimage.expected_semantic_digest,
            publication: preimage.publication,
            raw_capture: preimage.raw_capture,
            collection: preimage.collection,
            diagnostic: preimage.diagnostic,
            status: preimage.status,
        };
        let canonical_bytes = CanonicalDocument::from_serializable(&document)?;
        Ok(Self {
            capsule_id,
            reservation_record_id: input.reservation_record_id.clone(),
            canonical_bytes,
        })
    }

    pub fn decode(exact_bytes: Vec<u8>) -> Result<Self, StoreError> {
        let canonical_bytes = CanonicalDocument::from_canonical_bytes(exact_bytes)?;
        let document: CapsuleDocument = serde_json::from_slice(canonical_bytes.as_bytes())
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        if document.schema != GOVERNED_PROJECTION_CAPSULE_SCHEMA {
            return Err(StoreError::Invariant(
                "governed projection capsule schema is unsupported".into(),
            ));
        }
        let expected = semantic_digest(&document.preimage())
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        if expected != document.capsule_id {
            return Err(StoreError::Integrity(
                "governed projection capsule identity differs from its exact preimage".into(),
            ));
        }
        Ok(Self {
            capsule_id: document.capsule_id,
            reservation_record_id: document.reservation_record_id,
            canonical_bytes,
        })
    }

    #[must_use]
    pub const fn capsule_id(&self) -> &Sha256Digest {
        &self.capsule_id
    }

    #[must_use]
    pub const fn reservation_record_id(&self) -> &Sha256Digest {
        &self.reservation_record_id
    }

    #[must_use]
    pub const fn canonical_bytes(&self) -> &CanonicalDocument {
        &self.canonical_bytes
    }

    pub(crate) fn reopen_plan(
        &self,
        exact_raw_capture: &[u8],
        exact_diagnostic: CanonicalDocument,
    ) -> Result<ReopenedGovernedProjectionPlan, StoreError> {
        let document: CapsuleDocument = serde_json::from_slice(self.canonical_bytes.as_bytes())
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        document.reopen_plan(exact_raw_capture, exact_diagnostic)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReopenedGovernedProjectionPlan {
    pub(crate) collection: CollectionInput,
    pub(crate) diagnostic: DiagnosticArtifactCommitInput,
    pub(crate) status: StatusEventInput,
    pub(crate) mode: GovernedProjectionCapsuleMode,
    pub(crate) expected_semantic_digest: Option<Sha256Digest>,
    pub(crate) publication: GovernedProjectionPublication,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapsuleDiagnostic {
    artifact_id: Sha256Digest,
    contract_schema: String,
    canonical_bytes_digest: Sha256Digest,
    local_origin: DiagnosticLocalOriginCarrier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ByteCommitment {
    byte_length: u64,
    bytes_digest: Sha256Digest,
}

impl ByteCommitment {
    fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self {
            byte_length: u64::try_from(bytes.len())
                .map_err(|_| StoreError::Invariant("capsule byte length overflowed".into()))?,
            bytes_digest: sha256_bytes(bytes),
        })
    }

    fn verify(&self, bytes: &[u8]) -> Result<(), StoreError> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| StoreError::Invariant("capsule byte length overflowed".into()))?;
        if self.byte_length != length || self.bytes_digest != sha256_bytes(bytes) {
            return Err(StoreError::Integrity(
                "governed projection capsule raw capture differs from sealed custody".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CapsulePreimage {
    schema: String,
    reservation_record_id: Sha256Digest,
    mode: GovernedProjectionCapsuleMode,
    expected_semantic_digest: Option<Sha256Digest>,
    publication: GovernedProjectionPublication,
    raw_capture: ByteCommitment,
    collection: CollectionCarrier,
    diagnostic: CapsuleDiagnostic,
    status: StatusCarrier,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CapsuleDocument {
    schema: String,
    capsule_id: Sha256Digest,
    reservation_record_id: Sha256Digest,
    mode: GovernedProjectionCapsuleMode,
    expected_semantic_digest: Option<Sha256Digest>,
    publication: GovernedProjectionPublication,
    raw_capture: ByteCommitment,
    collection: CollectionCarrier,
    diagnostic: CapsuleDiagnostic,
    status: StatusCarrier,
}

impl CapsuleDocument {
    fn preimage(&self) -> CapsulePreimage {
        CapsulePreimage {
            schema: self.schema.clone(),
            reservation_record_id: self.reservation_record_id.clone(),
            mode: self.mode,
            expected_semantic_digest: self.expected_semantic_digest.clone(),
            publication: self.publication.clone(),
            raw_capture: self.raw_capture.clone(),
            collection: self.collection.clone(),
            diagnostic: self.diagnostic.clone(),
            status: self.status.clone(),
        }
    }

    fn reopen_plan(
        self,
        exact_raw_capture: &[u8],
        exact_diagnostic: CanonicalDocument,
    ) -> Result<ReopenedGovernedProjectionPlan, StoreError> {
        self.raw_capture.verify(exact_raw_capture)?;
        let collection = self.collection.reopen(exact_raw_capture)?;
        Ok(ReopenedGovernedProjectionPlan {
            collection,
            diagnostic: self.diagnostic.reopen(exact_diagnostic)?,
            status: self.status.reopen()?,
            mode: self.mode,
            expected_semantic_digest: self.expected_semantic_digest,
            publication: self.publication,
        })
    }
}

fn capsule_preimage(input: &GovernedProjectionCapsuleInput) -> Result<CapsulePreimage, StoreError> {
    Ok(CapsulePreimage {
        schema: GOVERNED_PROJECTION_CAPSULE_SCHEMA.to_owned(),
        reservation_record_id: input.reservation_record_id.clone(),
        mode: input.mode,
        expected_semantic_digest: input.expected_semantic_digest.clone(),
        publication: input.publication.clone(),
        raw_capture: ByteCommitment::from_bytes(&input.collection.intake.raw_bytes)?,
        collection: CollectionCarrier::from_input(&input.collection)?,
        diagnostic: CapsuleDiagnostic::from_input(&input.diagnostic_artifact)?,
        status: StatusCarrier::from_input(&input.status)?,
    })
}

fn validate_capsule_input(input: &GovernedProjectionCapsuleInput) -> Result<(), StoreError> {
    crate::validate_collection(&input.collection)?;
    if input.collection.run.run_id != input.diagnostic_artifact.local_origin.run_id
        || input.collection.run.run_id != input.status.component_id
        || input.status.component_kind != "diagnostic_execution"
        || input.diagnostic_artifact.contract_schema != "nq.diagnostic_execution.v2"
    {
        return Err(StoreError::Invariant(
            "governed projection capsule run, diagnostic, or status binding differs".into(),
        ));
    }
    match (
        input.mode,
        &input.expected_semantic_digest,
        input
            .collection
            .submission
            .as_ref()
            .map(|submission| &submission.disposition),
    ) {
        (
            GovernedProjectionCapsuleMode::Admitted,
            Some(_),
            Some(SubmissionDisposition::Admitted(_)),
        )
        | (
            GovernedProjectionCapsuleMode::NonSuccess,
            None,
            None | Some(SubmissionDisposition::Rejected { .. }),
        ) => {}
        _ => {
            return Err(StoreError::Invariant(
                "governed projection capsule mode, submission branch, and report digest differ"
                    .into(),
            ));
        }
    }
    let binding = input
        .diagnostic_artifact
        .local_origin
        .execution_binding
        .as_ref()
        .ok_or_else(|| {
            StoreError::Invariant(
                "governed production capsule requires an execution binding".into(),
            )
        })?;
    if input
        .diagnostic_artifact
        .local_origin
        .evaluation_id
        .is_some()
        || input.collection.intake.provider_sequence.is_some()
        || binding.provider_attempts.len() != 1
        || binding.runtime_records.records.len() != 2
    {
        return Err(StoreError::Invariant(
            "governed production capsule requires local-helper sequence absence, no evaluation, one provider attempt, and two terminal runtime records"
                .into(),
        ));
    }
    if input.publication.status_sequence <= 0
        || input.publication.acknowledgment_id.is_empty()
        || input.publication.acknowledgment_id.len() > 256
        || chrono::DateTime::parse_from_rfc3339(&input.publication.acknowledgment_committed_at)
            .is_err()
        || match input.mode {
            GovernedProjectionCapsuleMode::Admitted => input
                .publication
                .report_sequence
                .is_none_or(|sequence| sequence <= 0),
            GovernedProjectionCapsuleMode::NonSuccess => {
                input.publication.report_sequence.is_some()
            }
        }
    {
        return Err(StoreError::Invariant(
            "governed projection capsule publication identity is invalid".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CollectionCarrier {
    intake: ProviderIntakeCarrier,
    run: RunCarrier,
    submission: Option<SubmissionCarrier>,
}

impl CollectionCarrier {
    fn from_input(input: &CollectionInput) -> Result<Self, StoreError> {
        if input
            .submission
            .as_ref()
            .is_some_and(|submission| submission.raw_bytes != input.intake.raw_bytes)
        {
            return Err(StoreError::Invariant(
                "governed capsule submission bytes differ from provider raw custody".into(),
            ));
        }
        Ok(Self {
            intake: ProviderIntakeCarrier::from_input(&input.intake)?,
            run: RunCarrier::from_input(&input.run)?,
            submission: input
                .submission
                .as_ref()
                .map(SubmissionCarrier::from_input)
                .transpose()?,
        })
    }

    fn reopen(self, raw_bytes: &[u8]) -> Result<CollectionInput, StoreError> {
        Ok(CollectionInput {
            intake: self.intake.reopen(raw_bytes)?,
            run: self.run.reopen()?,
            submission: self
                .submission
                .map(|submission| submission.reopen(raw_bytes))
                .transpose()?,
        })
    }
}

macro_rules! value {
    ($document:expr) => {{
        serde_json::from_slice::<Value>($document.as_bytes())
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?
    }};
}

#[allow(clippy::needless_pass_by_value)] // Callers consume decoded carriers immediately.
fn reopen_document(value: Value) -> Result<CanonicalDocument, StoreError> {
    CanonicalDocument::from_canonical_bytes(
        canonical_json_bytes(&value)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?,
    )
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderIntakeCarrier {
    intake_id: String,
    attempt_id: String,
    idempotency_key: String,
    request_id: String,
    provider_admission_id: String,
    source_admission_id: String,
    provider_sequence: Option<String>,
    origin_carrier: String,
    deadline_at: String,
    checkpoint_contract_digest: String,
    execution_identity_digest: Sha256Digest,
    admission_context_digest: Sha256Digest,
    provider_semantic_id: Sha256Digest,
    provider_artifact_digest: Sha256Digest,
    provider_protocol_identity: String,
    provider_config_digest: Sha256Digest,
    binding_digest: String,
    instance_id: String,
    profile_id: String,
    profile_version: String,
    profile_digest: String,
    profile_semantic_id: Sha256Digest,
    evaluator_artifact_digest: Sha256Digest,
    context: Value,
    interpretation_kind: String,
    interpretation: Value,
    native_outcome_kind: String,
    native_outcome: Value,
    started_at: String,
    finished_at: String,
    received_at: String,
}

impl ProviderIntakeCarrier {
    fn from_input(input: &ProviderIntakeInput) -> Result<Self, StoreError> {
        Ok(Self {
            intake_id: input.intake_id.clone(),
            attempt_id: input.attempt_id.clone(),
            idempotency_key: input.idempotency_key.clone(),
            request_id: input.request_id.clone(),
            provider_admission_id: input.provider_admission_id.clone(),
            source_admission_id: input.source_admission_id.clone(),
            provider_sequence: input.provider_sequence.clone(),
            origin_carrier: input.origin_carrier.clone(),
            deadline_at: input.deadline_at.clone(),
            checkpoint_contract_digest: input.checkpoint_contract_digest.clone(),
            execution_identity_digest: input.execution_identity_digest.clone(),
            admission_context_digest: input.admission_context_digest.clone(),
            provider_semantic_id: input.provider_semantic_id.clone(),
            provider_artifact_digest: input.provider_artifact_digest.clone(),
            provider_protocol_identity: input.provider_protocol_identity.clone(),
            provider_config_digest: input.provider_config_digest.clone(),
            binding_digest: input.binding_digest.clone(),
            instance_id: input.instance_id.clone(),
            profile_id: input.profile_id.clone(),
            profile_version: input.profile_version.clone(),
            profile_digest: input.profile_digest.clone(),
            profile_semantic_id: input.profile_semantic_id.clone(),
            evaluator_artifact_digest: input.evaluator_artifact_digest.clone(),
            context: value!(input.context),
            interpretation_kind: input.interpretation_kind.clone(),
            interpretation: value!(input.interpretation),
            native_outcome_kind: input.native_outcome_kind.clone(),
            native_outcome: value!(input.native_outcome),
            started_at: input.started_at.clone(),
            finished_at: input.finished_at.clone(),
            received_at: input.received_at.clone(),
        })
    }

    fn reopen(self, raw_bytes: &[u8]) -> Result<ProviderIntakeInput, StoreError> {
        Ok(ProviderIntakeInput {
            intake_id: self.intake_id,
            attempt_id: self.attempt_id,
            idempotency_key: self.idempotency_key,
            request_id: self.request_id,
            provider_admission_id: self.provider_admission_id,
            source_admission_id: self.source_admission_id,
            provider_sequence: self.provider_sequence,
            origin_carrier: self.origin_carrier,
            deadline_at: self.deadline_at,
            checkpoint_contract_digest: self.checkpoint_contract_digest,
            execution_identity_digest: self.execution_identity_digest,
            admission_context_digest: self.admission_context_digest,
            provider_semantic_id: self.provider_semantic_id,
            provider_artifact_digest: self.provider_artifact_digest,
            provider_protocol_identity: self.provider_protocol_identity,
            provider_config_digest: self.provider_config_digest,
            binding_digest: self.binding_digest,
            instance_id: self.instance_id,
            profile_id: self.profile_id,
            profile_version: self.profile_version,
            profile_digest: self.profile_digest,
            profile_semantic_id: self.profile_semantic_id,
            evaluator_artifact_digest: self.evaluator_artifact_digest,
            context: reopen_document(self.context)?,
            interpretation_kind: self.interpretation_kind,
            interpretation: reopen_document(self.interpretation)?,
            native_outcome_kind: self.native_outcome_kind,
            native_outcome: reopen_document(self.native_outcome)?,
            raw_bytes: raw_bytes.to_vec(),
            started_at: self.started_at,
            finished_at: self.finished_at,
            received_at: self.received_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RunCarrier {
    run_id: String,
    request_id: String,
    instance_id: String,
    admission_id: Option<String>,
    binding_digest: String,
    checkpoint_contract_digest: String,
    profile_id: String,
    profile_version: String,
    profile_digest: String,
    carrier: String,
    started_at: String,
    deadline_at: String,
    finished_at: String,
    acquisition_outcome: String,
    execution_identity: Value,
    resource_outcome: Value,
}

impl RunCarrier {
    fn from_input(input: &RunInput) -> Result<Self, StoreError> {
        Ok(Self {
            run_id: input.run_id.clone(),
            request_id: input.request_id.clone(),
            instance_id: input.instance_id.clone(),
            admission_id: input.admission_id.clone(),
            binding_digest: input.binding_digest.clone(),
            checkpoint_contract_digest: input.checkpoint_contract_digest.clone(),
            profile_id: input.profile_id.clone(),
            profile_version: input.profile_version.clone(),
            profile_digest: input.profile_digest.clone(),
            carrier: input.carrier.clone(),
            started_at: input.started_at.clone(),
            deadline_at: input.deadline_at.clone(),
            finished_at: input.finished_at.clone(),
            acquisition_outcome: input.acquisition_outcome.clone(),
            execution_identity: value!(input.execution_identity),
            resource_outcome: value!(input.resource_outcome),
        })
    }

    fn reopen(self) -> Result<RunInput, StoreError> {
        Ok(RunInput {
            run_id: self.run_id,
            request_id: self.request_id,
            instance_id: self.instance_id,
            admission_id: self.admission_id,
            binding_digest: self.binding_digest,
            checkpoint_contract_digest: self.checkpoint_contract_digest,
            profile_id: self.profile_id,
            profile_version: self.profile_version,
            profile_digest: self.profile_digest,
            carrier: self.carrier,
            started_at: self.started_at,
            deadline_at: self.deadline_at,
            finished_at: self.finished_at,
            acquisition_outcome: self.acquisition_outcome,
            execution_identity: reopen_document(self.execution_identity)?,
            resource_outcome: reopen_document(self.resource_outcome)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "disposition")]
enum SubmissionDispositionCarrier {
    Rejected { refusal: RefusalCarrier },
    Admitted { report: ReportCarrier },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SubmissionCarrier {
    submission_id: String,
    received_at: String,
    protocol_outcome: String,
    disposition: SubmissionDispositionCarrier,
}

impl SubmissionCarrier {
    fn from_input(input: &SubmissionInput) -> Result<Self, StoreError> {
        Ok(Self {
            submission_id: input.submission_id.clone(),
            received_at: input.received_at.clone(),
            protocol_outcome: input.protocol_outcome.clone(),
            disposition: match &input.disposition {
                SubmissionDisposition::Rejected { refusal } => {
                    SubmissionDispositionCarrier::Rejected {
                        refusal: RefusalCarrier::from_input(refusal)?,
                    }
                }
                SubmissionDisposition::Admitted(report) => SubmissionDispositionCarrier::Admitted {
                    report: ReportCarrier::from_input(report)?,
                },
            },
        })
    }

    fn reopen(self, raw_bytes: &[u8]) -> Result<SubmissionInput, StoreError> {
        Ok(SubmissionInput {
            submission_id: self.submission_id,
            raw_bytes: raw_bytes.to_vec(),
            received_at: self.received_at,
            protocol_outcome: self.protocol_outcome,
            disposition: match self.disposition {
                SubmissionDispositionCarrier::Rejected { refusal } => {
                    SubmissionDisposition::Rejected {
                        refusal: refusal.reopen()?,
                    }
                }
                SubmissionDispositionCarrier::Admitted { report } => {
                    SubmissionDisposition::Admitted(report.reopen()?)
                }
            },
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RefusalCarrier {
    refusal_id: String,
    source_kind: String,
    responsible_instance_id: String,
    boundary: String,
    code: String,
    profile_semantic_id: Option<String>,
    detail: Value,
    created_at: String,
}

impl RefusalCarrier {
    fn from_input(input: &RefusalInput) -> Result<Self, StoreError> {
        Ok(Self {
            refusal_id: input.refusal_id.clone(),
            source_kind: input.source_kind.clone(),
            responsible_instance_id: input.responsible_instance_id.clone(),
            boundary: input.boundary.clone(),
            code: input.code.clone(),
            profile_semantic_id: input.profile_semantic_id.clone(),
            detail: value!(input.detail),
            created_at: input.created_at.clone(),
        })
    }

    fn reopen(self) -> Result<RefusalInput, StoreError> {
        Ok(RefusalInput {
            refusal_id: self.refusal_id,
            source_kind: self.source_kind,
            responsible_instance_id: self.responsible_instance_id,
            boundary: self.boundary,
            code: self.code,
            profile_semantic_id: self.profile_semantic_id,
            detail: reopen_document(self.detail)?,
            created_at: self.created_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CoverageCarrier {
    ordinal: u32,
    coverage_kind: String,
    coverage_state: String,
    detail: Value,
}

impl CoverageCarrier {
    fn from_input(input: &CoverageInput) -> Result<Self, StoreError> {
        Ok(Self {
            ordinal: input.ordinal,
            coverage_kind: input.coverage_kind.clone(),
            coverage_state: input.coverage_state.clone(),
            detail: value!(input.detail),
        })
    }

    fn reopen(self) -> Result<CoverageInput, StoreError> {
        Ok(CoverageInput {
            ordinal: self.ordinal,
            coverage_kind: self.coverage_kind,
            coverage_state: self.coverage_state,
            detail: reopen_document(self.detail)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationCarrier {
    ordinal: u32,
    kind: String,
    subject: Value,
    observed_at: String,
    payload: Value,
    coverage: Vec<CoverageCarrier>,
}

impl ObservationCarrier {
    fn from_input(input: &ObservationInput) -> Result<Self, StoreError> {
        Ok(Self {
            ordinal: input.ordinal,
            kind: input.kind.clone(),
            subject: value!(input.subject),
            observed_at: input.observed_at.clone(),
            payload: value!(input.payload),
            coverage: input
                .coverage
                .iter()
                .map(CoverageCarrier::from_input)
                .collect::<Result<_, _>>()?,
        })
    }

    fn reopen(self) -> Result<ObservationInput, StoreError> {
        Ok(ObservationInput {
            ordinal: self.ordinal,
            kind: self.kind,
            subject: reopen_document(self.subject)?,
            observed_at: self.observed_at,
            payload: reopen_document(self.payload)?,
            coverage: self
                .coverage
                .into_iter()
                .map(CoverageCarrier::reopen)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReportErrorCarrier {
    ordinal: u32,
    code: String,
    detail: Value,
}

impl ReportErrorCarrier {
    fn from_input(input: &ReportErrorInput) -> Result<Self, StoreError> {
        Ok(Self {
            ordinal: input.ordinal,
            code: input.code.clone(),
            detail: value!(input.detail),
        })
    }

    fn reopen(self) -> Result<ReportErrorInput, StoreError> {
        Ok(ReportErrorInput {
            ordinal: self.ordinal,
            code: self.code,
            detail: reopen_document(self.detail)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReportCarrier {
    report_id: String,
    instance_id: String,
    profile_id: String,
    profile_version: String,
    profile_digest: String,
    observed_at: String,
    received_at: String,
    report_status: String,
    canonical_report: Value,
    validated_report: Value,
    next_checkpoint: Option<Value>,
    admitted_at: String,
    observations: Vec<ObservationCarrier>,
    coverage: Vec<CoverageCarrier>,
    errors: Vec<ReportErrorCarrier>,
}

impl ReportCarrier {
    fn from_input(input: &ReportInput) -> Result<Self, StoreError> {
        Ok(Self {
            report_id: input.report_id.clone(),
            instance_id: input.instance_id.clone(),
            profile_id: input.profile_id.clone(),
            profile_version: input.profile_version.clone(),
            profile_digest: input.profile_digest.clone(),
            observed_at: input.observed_at.clone(),
            received_at: input.received_at.clone(),
            report_status: input.report_status.clone(),
            canonical_report: value!(input.canonical_report),
            validated_report: value!(input.validated_report),
            next_checkpoint: input
                .next_checkpoint
                .as_ref()
                .map(|value| {
                    serde_json::from_slice(value.as_bytes())
                        .map_err(|error| StoreError::CanonicalJson(error.to_string()))
                })
                .transpose()?,
            admitted_at: input.admitted_at.clone(),
            observations: input
                .observations
                .iter()
                .map(ObservationCarrier::from_input)
                .collect::<Result<_, _>>()?,
            coverage: input
                .coverage
                .iter()
                .map(CoverageCarrier::from_input)
                .collect::<Result<_, _>>()?,
            errors: input
                .errors
                .iter()
                .map(ReportErrorCarrier::from_input)
                .collect::<Result<_, _>>()?,
        })
    }

    fn reopen(self) -> Result<ReportInput, StoreError> {
        Ok(ReportInput {
            report_id: self.report_id,
            instance_id: self.instance_id,
            profile_id: self.profile_id,
            profile_version: self.profile_version,
            profile_digest: self.profile_digest,
            observed_at: self.observed_at,
            received_at: self.received_at,
            report_status: self.report_status,
            canonical_report: reopen_document(self.canonical_report)?,
            validated_report: reopen_document(self.validated_report)?,
            next_checkpoint: self.next_checkpoint.map(reopen_document).transpose()?,
            admitted_at: self.admitted_at,
            observations: self
                .observations
                .into_iter()
                .map(ObservationCarrier::reopen)
                .collect::<Result<_, _>>()?,
            coverage: self
                .coverage
                .into_iter()
                .map(CoverageCarrier::reopen)
                .collect::<Result<_, _>>()?,
            errors: self
                .errors
                .into_iter()
                .map(ReportErrorCarrier::reopen)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusCarrier {
    status_event_id: String,
    component_kind: String,
    component_id: String,
    state: String,
    code: String,
    detail: Value,
    observed_at: String,
}

impl StatusCarrier {
    fn from_input(input: &StatusEventInput) -> Result<Self, StoreError> {
        Ok(Self {
            status_event_id: input.status_event_id.clone(),
            component_kind: input.component_kind.clone(),
            component_id: input.component_id.clone(),
            state: input.state.clone(),
            code: input.code.clone(),
            detail: value!(input.detail),
            observed_at: input.observed_at.clone(),
        })
    }

    fn reopen(self) -> Result<StatusEventInput, StoreError> {
        Ok(StatusEventInput {
            status_event_id: self.status_event_id,
            component_kind: self.component_kind,
            component_id: self.component_id,
            state: self.state,
            code: self.code,
            detail: reopen_document(self.detail)?,
            observed_at: self.observed_at,
        })
    }
}

impl CapsuleDiagnostic {
    fn from_input(input: &DiagnosticArtifactCommitInput) -> Result<Self, StoreError> {
        Ok(Self {
            artifact_id: input.artifact_id.clone(),
            contract_schema: input.contract_schema.clone(),
            canonical_bytes_digest: Sha256Digest::parse(input.canonical_bytes.digest().to_owned())
                .map_err(|error| StoreError::Invariant(error.to_string()))?,
            local_origin: DiagnosticLocalOriginCarrier::from_input(&input.local_origin)?,
        })
    }

    fn reopen(
        self,
        canonical_bytes: CanonicalDocument,
    ) -> Result<DiagnosticArtifactCommitInput, StoreError> {
        if Sha256Digest::parse(canonical_bytes.digest().to_owned())
            .map_err(|error| StoreError::Invariant(error.to_string()))?
            != self.canonical_bytes_digest
        {
            return Err(StoreError::Integrity(
                "capsule diagnostic bytes differ from their exact commitment".into(),
            ));
        }
        Ok(DiagnosticArtifactCommitInput {
            artifact_id: self.artifact_id,
            contract_schema: self.contract_schema,
            canonical_bytes,
            local_origin: self.local_origin.reopen()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticLocalOriginCarrier {
    run_id: String,
    evaluation_id: Option<String>,
    completed_at: String,
    execution_binding: Option<DiagnosticExecutionBindingCarrier>,
}

impl DiagnosticLocalOriginCarrier {
    fn from_input(input: &DiagnosticArtifactLocalOriginInput) -> Result<Self, StoreError> {
        Ok(Self {
            run_id: input.run_id.clone(),
            evaluation_id: input.evaluation_id.clone(),
            completed_at: input.completed_at.clone(),
            execution_binding: input
                .execution_binding
                .as_ref()
                .map(DiagnosticExecutionBindingCarrier::from_input)
                .transpose()?,
        })
    }

    fn reopen(self) -> Result<DiagnosticArtifactLocalOriginInput, StoreError> {
        Ok(DiagnosticArtifactLocalOriginInput {
            run_id: self.run_id,
            evaluation_id: self.evaluation_id,
            completed_at: self.completed_at,
            execution_binding: self
                .execution_binding
                .map(DiagnosticExecutionBindingCarrier::reopen)
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticExecutionBindingCarrier {
    runtime_records: RuntimeRecordBatchCarrier,
    execution_binding_record_id: String,
    outer_request_record_id: String,
    invocation_decision_record_id: String,
    execution_launch_record_id: String,
    outer_request_id: String,
    provider_attempts: Vec<ProviderAttemptBindingCarrier>,
}

impl DiagnosticExecutionBindingCarrier {
    fn from_input(input: &DiagnosticArtifactExecutionBindingInput) -> Result<Self, StoreError> {
        Ok(Self {
            runtime_records: RuntimeRecordBatchCarrier::from_input(&input.runtime_records)?,
            execution_binding_record_id: input.execution_binding_record_id.clone(),
            outer_request_record_id: input.outer_request_record_id.clone(),
            invocation_decision_record_id: input.invocation_decision_record_id.clone(),
            execution_launch_record_id: input.execution_launch_record_id.clone(),
            outer_request_id: input.outer_request_id.clone(),
            provider_attempts: input
                .provider_attempts
                .iter()
                .map(ProviderAttemptBindingCarrier::from_input)
                .collect(),
        })
    }

    fn reopen(self) -> Result<DiagnosticArtifactExecutionBindingInput, StoreError> {
        Ok(DiagnosticArtifactExecutionBindingInput {
            runtime_records: self.runtime_records.reopen()?,
            execution_binding_record_id: self.execution_binding_record_id,
            outer_request_record_id: self.outer_request_record_id,
            invocation_decision_record_id: self.invocation_decision_record_id,
            execution_launch_record_id: self.execution_launch_record_id,
            outer_request_id: self.outer_request_id,
            provider_attempts: self
                .provider_attempts
                .into_iter()
                .map(ProviderAttemptBindingCarrier::reopen)
                .collect(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderAttemptBindingCarrier {
    provider_attempt_record_id: String,
    intake_id: String,
}

impl ProviderAttemptBindingCarrier {
    fn from_input(input: &DiagnosticArtifactProviderAttemptBindingInput) -> Self {
        Self {
            provider_attempt_record_id: input.provider_attempt_record_id.clone(),
            intake_id: input.intake_id.clone(),
        }
    }

    fn reopen(self) -> DiagnosticArtifactProviderAttemptBindingInput {
        DiagnosticArtifactProviderAttemptBindingInput {
            provider_attempt_record_id: self.provider_attempt_record_id,
            intake_id: self.intake_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRecordBatchCarrier {
    checkpoint_id: String,
    expected_predecessor_checkpoint_id: Option<String>,
    expected_predecessor_ledger_root: Option<Sha256Digest>,
    dependency: RuntimeDependencyCarrier,
    records: Vec<RuntimeRecordCarrier>,
}

impl RuntimeRecordBatchCarrier {
    fn from_input(input: &RuntimeRecordBatchInput) -> Result<Self, StoreError> {
        Ok(Self {
            checkpoint_id: input.checkpoint_id.clone(),
            expected_predecessor_checkpoint_id: input.expected_predecessor_checkpoint_id.clone(),
            expected_predecessor_ledger_root: input.expected_predecessor_ledger_root.clone(),
            dependency: RuntimeDependencyCarrier::from_input(&input.dependency)?,
            records: input
                .records
                .iter()
                .map(RuntimeRecordCarrier::from_input)
                .collect::<Result<_, _>>()?,
        })
    }

    fn reopen(self) -> Result<RuntimeRecordBatchInput, StoreError> {
        Ok(RuntimeRecordBatchInput {
            checkpoint_id: self.checkpoint_id,
            expected_predecessor_checkpoint_id: self.expected_predecessor_checkpoint_id,
            expected_predecessor_ledger_root: self.expected_predecessor_ledger_root,
            dependency: self.dependency.reopen()?,
            records: self
                .records
                .into_iter()
                .map(RuntimeRecordCarrier::reopen)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDependencyCarrier {
    dependency_generation_id: Sha256Digest,
    trust_anchor_id: Sha256Digest,
    canonical_custody: Value,
    canonical_custody_digest: Sha256Digest,
}

impl RuntimeDependencyCarrier {
    fn from_input(input: &RuntimeCheckpointDependencyInput) -> Result<Self, StoreError> {
        Ok(Self {
            dependency_generation_id: input.dependency_generation_id.clone(),
            trust_anchor_id: input.trust_anchor_id.clone(),
            canonical_custody: value!(input.canonical_custody),
            canonical_custody_digest: Sha256Digest::parse(
                input.canonical_custody.digest().to_owned(),
            )
            .map_err(|error| StoreError::Invariant(error.to_string()))?,
        })
    }

    fn reopen(self) -> Result<RuntimeCheckpointDependencyInput, StoreError> {
        let canonical_custody = reopen_document(self.canonical_custody)?;
        if Sha256Digest::parse(canonical_custody.digest().to_owned())
            .map_err(|error| StoreError::Invariant(error.to_string()))?
            != self.canonical_custody_digest
        {
            return Err(StoreError::Integrity(
                "capsule dependency custody differs from its exact commitment".into(),
            ));
        }
        Ok(RuntimeCheckpointDependencyInput {
            dependency_generation_id: self.dependency_generation_id,
            trust_anchor_id: self.trust_anchor_id,
            canonical_custody,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRecordCarrier {
    record_id: String,
    record_schema: String,
    canonical_bytes: Value,
    canonical_bytes_digest: Sha256Digest,
    committed_at: String,
}

impl RuntimeRecordCarrier {
    fn from_input(input: &RuntimeRecordInput) -> Result<Self, StoreError> {
        Ok(Self {
            record_id: input.record_id.clone(),
            record_schema: input.record_schema.clone(),
            canonical_bytes: value!(input.canonical_bytes),
            canonical_bytes_digest: Sha256Digest::parse(input.canonical_bytes.digest().to_owned())
                .map_err(|error| StoreError::Invariant(error.to_string()))?,
            committed_at: input.committed_at.clone(),
        })
    }

    fn reopen(self) -> Result<RuntimeRecordInput, StoreError> {
        let canonical_bytes = reopen_document(self.canonical_bytes)?;
        if Sha256Digest::parse(canonical_bytes.digest().to_owned())
            .map_err(|error| StoreError::Invariant(error.to_string()))?
            != self.canonical_bytes_digest
        {
            return Err(StoreError::Integrity(
                "capsule runtime record differs from its exact commitment".into(),
            ));
        }
        Ok(RuntimeRecordInput {
            record_id: self.record_id,
            record_schema: self.record_schema,
            canonical_bytes,
            committed_at: self.committed_at,
        })
    }
}

/// Serialize one typed production branch with nonempty collection members and
/// unambiguous marker values.
///
/// This is a serializer-shape witness, not a material maximal capsule.  The
/// capacity evaluator replaces each marker/collection/scalar family with its
/// independently committed maximum and cross-checks that symbolic traversal
/// against a separate hand-derived canonical-JSON formula.  Some admitted
/// descriptor maxima are intentionally too large to materialize safely.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionCapsuleOutcomeBranchV1 {
    Admitted,
    NonSuccessNoSubmission,
    #[serde(rename = "non_success_rejected_submission")]
    NonSuccessRejected,
}

#[cfg(test)]
impl ProjectionCapsuleOutcomeBranchV1 {
    pub(crate) const ALL: [Self; 3] = [
        Self::Admitted,
        Self::NonSuccessNoSubmission,
        Self::NonSuccessRejected,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::NonSuccessNoSubmission => "non_success_no_submission",
            Self::NonSuccessRejected => "non_success_rejected",
        }
    }
}

#[cfg(test)]
pub(crate) fn projection_capsule_symbolic_shape_witness_v1(
    branch: ProjectionCapsuleOutcomeBranchV1,
) -> Result<Value, StoreError> {
    projection_capsule_scaled_cardinality_witness_v1(branch, 1, 1, 1)
}

/// Serialize an exact typed production branch at tractable collection counts.
///
/// This is test evidence for the production carrier and canonical serializer,
/// not a claim that the ratified product cardinality maxima were materialized.
#[cfg(test)]
#[allow(clippy::too_many_lines)] // One exhaustive typed production carrier specimen.
pub(crate) fn projection_capsule_scaled_cardinality_witness_v1(
    branch: ProjectionCapsuleOutcomeBranchV1,
    observation_count: u32,
    report_coverage_count: u32,
    report_error_count: u32,
) -> Result<Value, StoreError> {
    const MAX_TIME: &str = "2026-07-29T12:34:56.123456789+23:59";
    fn marker(slot: &str) -> Value {
        Value::String(format!("__nq_bound_source:{slot}__"))
    }
    fn text() -> String {
        "\0".repeat(256)
    }
    fn digest() -> Sha256Digest {
        sha256_bytes(b"nq-v3-projection-capacity-shape-witness")
    }
    fn coverage() -> CoverageCarrier {
        CoverageCarrier {
            ordinal: 4_095,
            coverage_kind: text(),
            coverage_state: text(),
            detail: marker("coverage_detail"),
        }
    }
    let observation_template = ObservationCarrier {
        ordinal: 0,
        kind: text(),
        subject: marker("observation_subject"),
        observed_at: MAX_TIME.into(),
        payload: marker("observation_payload"),
        coverage: vec![coverage()],
    };
    let observations = (0..observation_count)
        .map(|ordinal| {
            let mut observation = observation_template.clone();
            observation.ordinal = ordinal;
            observation
        })
        .collect();
    let report_coverage = (0..report_coverage_count)
        .map(|ordinal| {
            let mut item = coverage();
            item.ordinal = ordinal;
            item
        })
        .collect();
    let report_errors = (0..report_error_count)
        .map(|ordinal| ReportErrorCarrier {
            ordinal,
            code: text(),
            detail: marker("report_error_detail"),
        })
        .collect();
    let report = ReportCarrier {
        report_id: text(),
        instance_id: text(),
        profile_id: text(),
        profile_version: text(),
        profile_digest: text(),
        observed_at: MAX_TIME.into(),
        received_at: MAX_TIME.into(),
        report_status: text(),
        canonical_report: marker("canonical_report"),
        validated_report: marker("validated_report"),
        next_checkpoint: Some(marker("next_checkpoint")),
        admitted_at: MAX_TIME.into(),
        observations,
        coverage: report_coverage,
        errors: report_errors,
    };
    let refusal = RefusalCarrier {
        refusal_id: text(),
        source_kind: text(),
        responsible_instance_id: text(),
        boundary: text(),
        code: text(),
        profile_semantic_id: Some(text()),
        detail: marker("refusal_detail"),
        created_at: MAX_TIME.into(),
    };
    let submission = match branch {
        ProjectionCapsuleOutcomeBranchV1::Admitted => Some(SubmissionCarrier {
            submission_id: text(),
            received_at: MAX_TIME.into(),
            protocol_outcome: text(),
            disposition: SubmissionDispositionCarrier::Admitted { report },
        }),
        ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission => None,
        ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected => Some(SubmissionCarrier {
            submission_id: text(),
            received_at: MAX_TIME.into(),
            protocol_outcome: text(),
            disposition: SubmissionDispositionCarrier::Rejected { refusal },
        }),
    };
    let runtime_record = || RuntimeRecordCarrier {
        record_id: text(),
        record_schema: text(),
        canonical_bytes: marker("runtime_record_canonical_bytes"),
        canonical_bytes_digest: digest(),
        committed_at: MAX_TIME.into(),
    };
    let runtime_records = RuntimeRecordBatchCarrier {
        checkpoint_id: text(),
        expected_predecessor_checkpoint_id: Some(text()),
        expected_predecessor_ledger_root: Some(digest()),
        dependency: RuntimeDependencyCarrier {
            dependency_generation_id: digest(),
            trust_anchor_id: digest(),
            canonical_custody: marker("exact_authenticated_dependency_custody"),
            canonical_custody_digest: digest(),
        },
        records: vec![runtime_record(), runtime_record()],
    };
    let document = CapsuleDocument {
        schema: GOVERNED_PROJECTION_CAPSULE_SCHEMA.into(),
        capsule_id: digest(),
        reservation_record_id: digest(),
        mode: if branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
            GovernedProjectionCapsuleMode::Admitted
        } else {
            GovernedProjectionCapsuleMode::NonSuccess
        },
        expected_semantic_digest: if branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
            Some(digest())
        } else {
            None
        },
        publication: GovernedProjectionPublication {
            report_sequence: if branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
                Some(9_007_199_254_740_991)
            } else {
                None
            },
            status_sequence: 9_007_199_254_740_991,
            acknowledgment_id: text(),
            acknowledgment_committed_at: MAX_TIME.into(),
        },
        raw_capture: ByteCommitment {
            byte_length: 16_777_217,
            bytes_digest: digest(),
        },
        collection: CollectionCarrier {
            intake: ProviderIntakeCarrier {
                intake_id: text(),
                attempt_id: text(),
                idempotency_key: text(),
                request_id: text(),
                provider_admission_id: text(),
                source_admission_id: text(),
                provider_sequence: None,
                origin_carrier: text(),
                deadline_at: MAX_TIME.into(),
                checkpoint_contract_digest: text(),
                execution_identity_digest: digest(),
                admission_context_digest: digest(),
                provider_semantic_id: digest(),
                provider_artifact_digest: digest(),
                provider_protocol_identity: text(),
                provider_config_digest: digest(),
                binding_digest: text(),
                instance_id: text(),
                profile_id: text(),
                profile_version: text(),
                profile_digest: text(),
                profile_semantic_id: digest(),
                evaluator_artifact_digest: digest(),
                context: marker("provider_intake_context"),
                interpretation_kind: text(),
                interpretation: marker("provider_intake_interpretation"),
                native_outcome_kind: text(),
                native_outcome: marker("provider_intake_native_outcome"),
                started_at: MAX_TIME.into(),
                finished_at: MAX_TIME.into(),
                received_at: MAX_TIME.into(),
            },
            run: RunCarrier {
                run_id: text(),
                request_id: text(),
                instance_id: text(),
                admission_id: Some(text()),
                binding_digest: text(),
                checkpoint_contract_digest: text(),
                profile_id: text(),
                profile_version: text(),
                profile_digest: text(),
                carrier: text(),
                started_at: MAX_TIME.into(),
                deadline_at: MAX_TIME.into(),
                finished_at: MAX_TIME.into(),
                acquisition_outcome: text(),
                execution_identity: marker("run_execution_identity"),
                resource_outcome: marker("run_resource_outcome"),
            },
            submission,
        },
        diagnostic: CapsuleDiagnostic {
            artifact_id: digest(),
            contract_schema: "nq.diagnostic_execution.v2".into(),
            canonical_bytes_digest: digest(),
            local_origin: DiagnosticLocalOriginCarrier {
                run_id: text(),
                evaluation_id: None,
                completed_at: MAX_TIME.into(),
                execution_binding: Some(DiagnosticExecutionBindingCarrier {
                    runtime_records,
                    execution_binding_record_id: text(),
                    outer_request_record_id: text(),
                    invocation_decision_record_id: text(),
                    execution_launch_record_id: text(),
                    outer_request_id: text(),
                    provider_attempts: vec![ProviderAttemptBindingCarrier {
                        provider_attempt_record_id: text(),
                        intake_id: text(),
                    }],
                }),
            },
        },
        status: StatusCarrier {
            status_event_id: text(),
            component_kind: "diagnostic_execution".into(),
            component_id: text(),
            state: text(),
            code: text(),
            detail: marker("status_detail"),
            observed_at: MAX_TIME.into(),
        },
    };
    serde_json::to_value(document).map_err(|error| StoreError::CanonicalJson(error.to_string()))
}
