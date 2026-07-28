//! Canonical contract for one bounded NQ diagnostic execution.
//!
//! The evaluation engine has one deliberately narrow producer for this
//! contract: the exact current `nq.host/v1` load-pressure profile/detector, a
//! fresh instance, one newly admitted report, and a determinate detector
//! result. The artifact commits atomically with the ordinary
//! custody/evaluation transaction, and the engine reopens the committed bytes
//! before returning them. The bounded producer preserves a compiled detector's
//! governed `cannot_evaluate` result as a refused diagnostic rather than
//! manufacturing a condition. Schema-v5 custody supports exact restart-safe
//! inspection, export, and import; it does not broaden the deliberately narrow
//! live producer or reconstruct artifacts for older history. A
//! producer-selected evidence list is never treated as complete input
//! accounting.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire schema for one immutable bounded diagnostic execution.
pub const DIAGNOSTIC_EXECUTION_SCHEMA: &str = "nq.diagnostic_execution.v1";

/// The canonicalization implementation used for v1 identity.
pub const DIAGNOSTIC_CANONICALIZATION_ID: &str = "rfc8785-jcs";

/// Closed diagnostic-execution schema identity.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticExecutionSchema {
    /// First complete input-accounting artifact.
    #[serde(rename = "nq.diagnostic_execution.v1")]
    V1,
}

macro_rules! string_identity {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(
            /// Exact opaque identity text.
            pub String,
        );

        impl $name {
            /// Returns the exact identity text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

macro_rules! digest_identity {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(
            /// Exact algorithm-qualified content digest.
            pub Sha256Digest,
        );

        impl $name {
            /// Returns the exact algorithm-qualified digest.
            #[must_use]
            pub fn as_digest(&self) -> &Sha256Digest {
                &self.0
            }
        }
    };
}

string_identity!(
    DiagnosticRequestId,
    "Opaque identity of one diagnostic request occurrence."
);
string_identity!(
    DiagnosticRunId,
    "Opaque identity of one diagnostic execution/run occurrence."
);
digest_identity!(
    DiagnosticArtifactId,
    "Self-identity of one complete diagnostic artifact."
);
digest_identity!(
    RawArtifactId,
    "Content identity of exact admitted or earliest-boundary-redacted bytes."
);
digest_identity!(
    NormalizedArtifactId,
    "Content identity of the admitted normalized evidence bytes."
);
digest_identity!(
    ProjectedArtifactId,
    "Content identity of the exact evidence projection evaluated."
);

/// An identified semantic rule, policy, binding, or implementation.
///
/// `id` is the logical identity, `version` is its exact generation, and
/// `digest` commits to the descriptor bytes for that generation.  For a
/// vantage or scope this denotes the concrete logical instance/generation, not
/// merely its vocabulary type.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIdentityV1 {
    /// Stable logical identity.
    pub id: String,
    /// Exact version or generation.
    pub version: String,
    /// Canonical descriptor digest.
    pub digest: Sha256Digest,
}

/// Producer identity retained without granting consumer reliance.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticProducerV1 {
    /// Logical NQ node identity.
    pub node_id: String,
    /// Exact NQ build identity.
    pub build: SemanticIdentityV1,
    /// Exact compiled cohort/catalog identity.
    pub cohort: SemanticIdentityV1,
}

/// Exact subject and bounded scope.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSubjectV1 {
    /// Logical subject identity.
    pub id: String,
    /// Exact bounded scope instance/generation.
    pub scope: SemanticIdentityV1,
}

/// Source acquisition interval.
///
/// Receipt, transport, custody, and derivation times never refresh this
/// interval.  Consumers must account for `clock_uncertainty_ms` when deriving
/// age.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionIntervalV1 {
    /// Earliest source acquisition time represented.
    pub started_at: DateTime<Utc>,
    /// Latest source acquisition time represented.
    pub ended_at: DateTime<Utc>,
    /// Clock source/quality identity.
    pub clock: SemanticIdentityV1,
    /// Symmetric bounded clock uncertainty.
    pub clock_uncertainty_ms: u64,
}

/// One declared input obligation.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedInputV1 {
    /// Occurrence identity of this expectation.
    pub expectation_id: String,
    /// Profile-owned semantic role.
    pub role: String,
    /// Whether absence blocks complete coverage.
    pub required: bool,
}

/// Capture mode of bytes retained as the raw artifact.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCaptureModeV1 {
    /// The raw artifact contains exact source bytes.
    ExactSource,
    /// Sensitive material was transformed at the earliest governed boundary.
    EarliestBoundaryRedacted,
}

/// Evidence byte availability at diagnostic derivation time.
///
/// This is immutable historical testimony. A later availability change
/// requires a distinct custody/read artifact; that surface is not implemented
/// by this foundation.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAvailabilityV1 {
    /// Bytes were directly queryable through the supported product surface.
    Online,
    /// Bytes were archived and retrievable through a supported operation.
    ArchivedRetrievable,
    /// Integrity commitment existed but bytes were not then retrievable.
    CommittedUnavailable,
}

/// One input occurrence received into NQ custody.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedInputV1 {
    /// Occurrence identity, distinct from content identity.
    pub input_id: String,
    /// Exact expectation this occurrence answers.
    pub expectation_id: String,
    /// Content identity of exact admitted or earliest-boundary-redacted bytes.
    pub raw_artifact_id: RawArtifactId,
    /// Whether the committed bytes are exact source or boundary-redacted.
    pub capture_mode: RawCaptureModeV1,
    /// Exact capture/redaction policy applied before ordinary raw custody.
    pub capture_policy: SemanticIdentityV1,
    /// Historical byte availability at the derivation instant.
    pub availability_at_derivation: EvidenceAvailabilityV1,
    /// Source acquisition interval.
    pub acquisition: AcquisitionIntervalV1,
    /// NQ custody receipt time; never a source-freshness time.
    pub received_at: DateTime<Utc>,
}

/// One received input admitted under an exact rule.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedInputV1 {
    /// Received input occurrence.
    pub input_id: String,
    /// Exact rule that admitted the received occurrence.
    pub admission_rule: SemanticIdentityV1,
    /// Identity of the normalized evidence bytes.
    pub normalized_artifact_id: NormalizedArtifactId,
    /// Exact normalization rule identity.
    pub normalization_rule: SemanticIdentityV1,
    /// Identity of the exact projected evidence bytes.
    pub projected_artifact_id: ProjectedArtifactId,
    /// Exact per-input projection rule identity.
    pub projection_rule: SemanticIdentityV1,
}

/// One received input refused or found invalid.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedInputV1 {
    /// Received input occurrence.
    pub input_id: String,
    /// Immutable refusal identity.
    pub refusal_id: String,
    /// Stable refusal code.
    pub code: String,
    /// Bounded diagnostic detail.
    pub reason: String,
}

/// Failure before a received input occurrence could enter custody.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputFailureKindV1 {
    /// The expected provider returned no qualifying occurrence.
    Missing,
    /// NQ observed no provider response before its acquisition boundary.
    ///
    /// This is provider-level NQ input accounting.  It is not Nightshift's
    /// receiver-side observation that NQ itself did not respond.
    NoResponse,
    /// Provider invocation failed.
    AcquisitionFailed,
    /// The configured provider cannot supply the expected role.
    Unsupported,
}

/// One expected input that produced no received occurrence.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailedInputV1 {
    /// Exact unsatisfied expectation.
    pub expectation_id: String,
    /// Immutable failure identity.
    pub failure_id: String,
    /// Typed acquisition failure.
    pub kind: InputFailureKindV1,
    /// Bounded diagnostic detail.
    pub reason: String,
}

/// One admitted input deliberately excluded by an identified selection law.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedInputV1 {
    /// Admitted input occurrence.
    pub input_id: String,
    /// Exact projected evidence identity.
    pub projected_artifact_id: ProjectedArtifactId,
    /// Stable exclusion code.
    pub code: String,
    /// Exact bounded rationale.
    pub reason: String,
}

/// One admitted input selected for diagnostic evaluation.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedInputV1 {
    /// Admitted input occurrence.
    pub input_id: String,
    /// Exact projected evidence identity.
    pub projected_artifact_id: ProjectedArtifactId,
    /// Profile-owned semantic role in this evaluation.
    pub role: String,
}

/// Complete input accounting for the bounded question.
///
/// Each set-like array is sorted by unsigned UTF-8 bytes of its identity
/// field. This is deliberately distinct from JCS's UTF-16 object-key order.
/// Validation closes only this artifact's declared denominator. Binding that
/// denominator to the admitted profile/catalog manifest remains an engine
/// integration obligation and is not proved by this transport contract.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticInputAccountingV1 {
    /// Identified law selecting admitted inputs.
    pub selection_rule: SemanticIdentityV1,
    /// Complete declared denominator.
    pub expected: Vec<ExpectedInputV1>,
    /// All occurrences that entered raw custody.
    pub received: Vec<ReceivedInputV1>,
    /// Received occurrences admitted for semantic use.
    pub admitted: Vec<AdmittedInputV1>,
    /// Received occurrences refused or invalid.
    pub refused: Vec<RefusedInputV1>,
    /// Expected inputs for which no occurrence entered custody.
    pub failed: Vec<FailedInputV1>,
    /// Admitted occurrences excluded by the selection rule.
    pub excluded: Vec<ExcludedInputV1>,
    /// Admitted occurrences selected for evaluation.
    pub selected: Vec<SelectedInputV1>,
}

/// Per-question state binding.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticStateBindingV1 {
    /// Stable binding identity.
    pub binding_id: String,
    /// Profile-owned state vocabulary entry.
    pub kind: String,
    /// Canonical state value.
    pub value: String,
    /// Lexicographically ordered selected inputs that establish this binding.
    pub supporting_input_ids: Vec<String>,
}

/// Status of one exported claim.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticClaimStatusV1 {
    /// Dependencies establish the proposition.
    Established,
    /// Dependencies establish the bounded negation.
    Refuted,
    /// Available evidence does not determine the proposition.
    Unknown,
    /// Admitted dependencies disagree.
    Contradictory,
}

/// One claim and its exact dependency/state frontier.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticClaimV1 {
    /// Stable claim identity within the bounded question.
    pub claim_id: String,
    /// Human-readable bounded proposition.
    pub proposition: String,
    /// Exact claim status.
    pub status: DiagnosticClaimStatusV1,
    /// Effect this claim has on the bounded condition, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_effect: Option<DiagnosticConditionV1>,
    /// Selected input occurrences on which this claim depends.
    pub dependency_input_ids: Vec<String>,
    /// State bindings applicable to this claim.
    pub state_binding_ids: Vec<String>,
    /// Lexicographically ordered distinctions this claim requires.
    ///
    /// A required distinction may not be named as omitted by the artifact's
    /// exported projection.
    pub required_distinctions: Vec<String>,
    /// Claim-local material limitations.
    pub limitations: Vec<String>,
    /// Claim-local explicit nonclaims.
    pub nonclaims: Vec<String>,
}

/// Derivation completion status.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticDerivationV1 {
    /// The bounded evaluator completed under its declared law.
    Completed,
    /// A valid but incomplete derived result exists.
    Partial,
    /// The responsible NQ boundary refused.
    Refused,
    /// The profile/evaluator does not support the question.
    Unsupported,
}

/// Bounded condition status.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticConditionV1 {
    /// The bounded condition is present.
    Present,
    /// The bounded diagnostic condition is current and clean.
    Clean,
    /// Adequate closed-world evidence establishes bounded absence.
    ExplicitlyAbsent,
    /// The bounded condition is unresolved.
    Unresolved,
    /// The condition does not apply to the bound state.
    NotApplicable,
}

/// Compatibility/coherence status of the evidence used.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCoherenceV1 {
    /// One joint state/history is established under the identified model.
    JointlyEstablished,
    /// Only tested pairs are compatible.
    PairwiseOnly,
    /// Admitted evidence contradicts.
    Contradictory,
    /// Evidence applies to incompatible states.
    StateIncompatible,
    /// Available evidence cannot determine joint coherence.
    Insufficient,
    /// No coherence evaluation was performed.
    NotEvaluated,
}

/// Coverage status for the bounded question.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCoverageV1 {
    /// Every required declared input is admitted and accounted for.
    Complete,
    /// Some useful coverage exists, but the denominator is not complete.
    Partial,
    /// No qualifying required coverage exists.
    Missing,
}

/// Exact NQ refusal attached to a refused outcome.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRefusalV1 {
    /// Stable refusal code.
    pub code: String,
    /// Bounded refusal detail.
    pub reason: String,
}

/// NQ-owned bounded diagnostic outcome.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticOutcomeV1 {
    /// Evaluation completion/refusal status.
    pub derivation: DiagnosticDerivationV1,
    /// Bounded condition status.
    pub condition: DiagnosticConditionV1,
    /// Evidence compatibility status.
    pub coherence: DiagnosticCoherenceV1,
    /// Declared-denominator coverage status.
    pub coverage: DiagnosticCoverageV1,
    /// Concise bounded result.
    pub summary: String,
    /// Required exactly when `derivation` is `refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<DiagnosticRefusalV1>,
}

/// Typed limitation class.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLimitationKindV1 {
    /// Projection erased a distinction.
    ProjectionLoss,
    /// Required evidence is missing.
    MissingEvidence,
    /// Evidence is stale.
    StaleEvidence,
    /// Evidence applies to another state.
    StateMismatch,
    /// Evidence contradicts.
    Contradiction,
    /// The expected denominator is incomplete.
    CoverageGap,
    /// Failure-domain separation is not established.
    UnverifiedSeparation,
    /// Evidence is identified but unavailable.
    UnavailableEvidence,
    /// Bounded profile-specific limitation.
    Other,
}

/// One material diagnostic limitation.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticLimitationV1 {
    /// Typed limitation class.
    pub kind: DiagnosticLimitationKindV1,
    /// Stable profile-owned code.
    pub code: String,
    /// Bounded detail.
    pub detail: String,
}

/// One distinction deliberately erased by an exported projection.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OmittedDistinctionV1 {
    /// Stable profile-owned distinction code.
    pub code: String,
    /// Bounded description of the erased distinction.
    pub detail: String,
}

/// Exact exported projection and its declared information loss.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticProjectionV1 {
    /// Exact projection implementation/contract identity.
    pub identity: SemanticIdentityV1,
    /// Lexicographically ordered distinctions erased by this projection.
    pub omitted_distinctions: Vec<OmittedDistinctionV1>,
}

/// One immutable bounded NQ diagnostic artifact.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticExecutionV1 {
    /// Exact wire schema.
    pub schema: DiagnosticExecutionSchema,
    /// Self-identity: SHA-256 of JCS bytes with this field omitted.
    pub artifact_id: DiagnosticArtifactId,
    /// Exact canonicalization identity.
    pub canonicalization: SemanticIdentityV1,
    /// Producer disclosure; consumers still apply their own reliance.
    pub producer: DiagnosticProducerV1,
    /// Request occurrence identity.
    pub request_id: DiagnosticRequestId,
    /// Execution/run occurrence identity.
    pub run_id: DiagnosticRunId,
    /// Exact bounded question identity.
    pub question: SemanticIdentityV1,
    /// Exact subject and scope.
    pub subject: DiagnosticSubjectV1,
    /// Exact compiled profile identity.
    pub profile: SemanticIdentityV1,
    /// Concrete logical vantage identity/generation.
    pub vantage: SemanticIdentityV1,
    /// Profile-owned state-model identity.
    pub state_model: SemanticIdentityV1,
    /// Exact evaluator identity.
    pub evaluator: SemanticIdentityV1,
    /// Exact threshold/baseline policy identity.
    pub threshold_policy: SemanticIdentityV1,
    /// Exact exported projection identity and omitted-distinction contract.
    pub projection: DiagnosticProjectionV1,
    /// Clock governing NQ execution and custody times.
    pub execution_clock: SemanticIdentityV1,
    /// Diagnostic execution start under `execution_clock`; never source
    /// acquisition time.
    pub started_at: DateTime<Utc>,
    /// Diagnostic derivation completion under `execution_clock`; never source
    /// acquisition time.
    pub completed_at: DateTime<Utc>,
    /// NQ-owned interval for the bounded acquisition attempt.
    ///
    /// A refused or unsupported diagnostic may have no exported claim, but it
    /// still has an attributable attempt interval. Claim freshness is derived
    /// from every exact dependency input interval; observations made under
    /// different clocks are never collapsed into this interval.
    pub attempt_interval: AcquisitionIntervalV1,
    /// Complete input accounting.
    pub inputs: DiagnosticInputAccountingV1,
    /// Per-question state bindings.
    pub state_bindings: Vec<DiagnosticStateBindingV1>,
    /// Exact exported claim surface.
    pub claims: Vec<DiagnosticClaimV1>,
    /// Claim that supplies the bounded top-level outcome, when one was
    /// derived.  Refused/unsupported outcomes may export no claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_claim_id: Option<String>,
    /// Bounded diagnostic outcome.
    pub outcome: DiagnosticOutcomeV1,
    /// Artifact-wide material limitations.
    pub limitations: Vec<DiagnosticLimitationV1>,
    /// Explicit statements this artifact does not establish.
    pub nonclaims: Vec<String>,
}

/// Structural, identity, or canonical-byte failure.
#[derive(Debug, Error)]
pub enum DiagnosticExecutionError {
    /// JSON could not be decoded under the closed schema.
    #[error("diagnostic artifact cannot be decoded: {0}")]
    Decode(#[from] serde_json::Error),
    /// Canonical JSON could not be produced.
    #[error("diagnostic artifact cannot be canonicalized: {0}")]
    Canonical(#[from] nq_protocol::CanonicalizationError),
    /// Input bytes were valid JSON but not the unique canonical encoding.
    #[error("diagnostic artifact bytes are not canonical JCS")]
    NonCanonical,
    /// A closed contract invariant failed.
    #[error("diagnostic artifact invariant failed: {0}")]
    Invariant(String),
}

#[derive(Serialize)]
struct CanonicalizationDescriptor<'a> {
    id: &'a str,
    version: &'a str,
}

/// Returns the only canonicalization identity accepted by this v1
/// implementation.
///
/// # Errors
///
/// Returns a canonicalization failure only if the fixed descriptor cannot be
/// represented as JCS.
pub fn diagnostic_canonicalization_identity() -> Result<SemanticIdentityV1, DiagnosticExecutionError>
{
    let descriptor = CanonicalizationDescriptor {
        id: DIAGNOSTIC_CANONICALIZATION_ID,
        version: "1",
    };
    Ok(SemanticIdentityV1 {
        id: descriptor.id.to_owned(),
        version: descriptor.version.to_owned(),
        digest: semantic_digest(&descriptor)?,
    })
}

#[derive(Serialize)]
struct DiagnosticExecutionPreimage<'a> {
    schema: DiagnosticExecutionSchema,
    canonicalization: &'a SemanticIdentityV1,
    producer: &'a DiagnosticProducerV1,
    request_id: &'a DiagnosticRequestId,
    run_id: &'a DiagnosticRunId,
    question: &'a SemanticIdentityV1,
    subject: &'a DiagnosticSubjectV1,
    profile: &'a SemanticIdentityV1,
    vantage: &'a SemanticIdentityV1,
    state_model: &'a SemanticIdentityV1,
    evaluator: &'a SemanticIdentityV1,
    threshold_policy: &'a SemanticIdentityV1,
    projection: &'a DiagnosticProjectionV1,
    execution_clock: &'a SemanticIdentityV1,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    attempt_interval: &'a AcquisitionIntervalV1,
    inputs: &'a DiagnosticInputAccountingV1,
    state_bindings: &'a [DiagnosticStateBindingV1],
    claims: &'a [DiagnosticClaimV1],
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_claim_id: Option<&'a str>,
    outcome: &'a DiagnosticOutcomeV1,
    limitations: &'a [DiagnosticLimitationV1],
    nonclaims: &'a [String],
}

impl DiagnosticExecutionV1 {
    fn preimage(&self) -> DiagnosticExecutionPreimage<'_> {
        DiagnosticExecutionPreimage {
            schema: self.schema,
            canonicalization: &self.canonicalization,
            producer: &self.producer,
            request_id: &self.request_id,
            run_id: &self.run_id,
            question: &self.question,
            subject: &self.subject,
            profile: &self.profile,
            vantage: &self.vantage,
            state_model: &self.state_model,
            evaluator: &self.evaluator,
            threshold_policy: &self.threshold_policy,
            projection: &self.projection,
            execution_clock: &self.execution_clock,
            started_at: self.started_at,
            completed_at: self.completed_at,
            attempt_interval: &self.attempt_interval,
            inputs: &self.inputs,
            state_bindings: &self.state_bindings,
            claims: &self.claims,
            primary_claim_id: self.primary_claim_id.as_deref(),
            outcome: &self.outcome,
            limitations: &self.limitations,
            nonclaims: &self.nonclaims,
        }
    }

    /// Computes the self-identity without asserting producer authority.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization error if the preimage is not representable.
    pub fn computed_artifact_id(&self) -> Result<DiagnosticArtifactId, DiagnosticExecutionError> {
        Ok(DiagnosticArtifactId(semantic_digest(&self.preimage())?))
    }

    /// Validates the closed contract and self-identity.
    ///
    /// This proves structural conformance only.  It does not authenticate the
    /// producer, admit evidence, or grant consumer reliance.
    ///
    /// # Errors
    ///
    /// Returns the first exact invariant failure.
    pub fn validate(&self) -> Result<(), DiagnosticExecutionError> {
        require_identity("canonicalization", &self.canonicalization)?;
        if self.canonicalization != diagnostic_canonicalization_identity()? {
            return invariant("unknown canonicalization identity");
        }
        require_token("producer.node_id", &self.producer.node_id)?;
        require_identity("producer.build", &self.producer.build)?;
        require_identity("producer.cohort", &self.producer.cohort)?;
        require_token("request_id", self.request_id.as_str())?;
        require_token("run_id", self.run_id.as_str())?;
        require_identity("question", &self.question)?;
        require_token("subject.id", &self.subject.id)?;
        require_identity("subject.scope", &self.subject.scope)?;
        require_identity("profile", &self.profile)?;
        require_identity("vantage", &self.vantage)?;
        require_identity("state_model", &self.state_model)?;
        require_identity("evaluator", &self.evaluator)?;
        require_identity("threshold_policy", &self.threshold_policy)?;
        validate_projection(&self.projection)?;
        require_identity("execution_clock", &self.execution_clock)?;
        if self.started_at > self.completed_at {
            return invariant("started_at is after completed_at");
        }
        validate_interval(&self.attempt_interval)?;
        if self.attempt_interval.clock != self.execution_clock {
            return invariant("attempt interval does not use execution_clock");
        }
        if self.attempt_interval.started_at < self.started_at
            || self.attempt_interval.ended_at > self.completed_at
        {
            return invariant("attempt interval falls outside diagnostic execution");
        }
        validate_inputs(self)?;
        validate_state_bindings(&self.state_bindings, &self.inputs)?;
        validate_claims(self)?;
        validate_outcome(self)?;
        require_utf8_byte_sorted_unique(
            "limitations",
            self.limitations
                .iter()
                .map(|limitation| limitation.code.as_str()),
        )?;
        for limitation in &self.limitations {
            require_token("limitation.code", &limitation.code)?;
            require_token("limitation.detail", &limitation.detail)?;
        }
        require_utf8_byte_sorted_unique("nonclaims", self.nonclaims.iter().map(String::as_str))?;
        for nonclaim in &self.nonclaims {
            require_token("nonclaim", nonclaim)?;
        }
        if self.artifact_id != self.computed_artifact_id()? {
            return invariant("artifact_id does not match the canonical preimage");
        }
        Ok(())
    }

    /// Returns the unique canonical bytes after full validation.
    ///
    /// # Errors
    ///
    /// Returns structural, identity, or canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiagnosticExecutionError> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Decodes only the unique canonical bytes for a valid artifact.
    ///
    /// # Errors
    ///
    /// Rejects unknown fields, noncanonical JSON, malformed references, and a
    /// substituted self-identity.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DiagnosticExecutionError> {
        let artifact: Self = serde_json::from_slice(bytes)?;
        artifact.validate()?;
        if canonical_json_bytes(&artifact)? != bytes {
            return Err(DiagnosticExecutionError::NonCanonical);
        }
        Ok(artifact)
    }
}

fn validate_projection(
    projection: &DiagnosticProjectionV1,
) -> Result<(), DiagnosticExecutionError> {
    require_identity("projection.identity", &projection.identity)?;
    require_utf8_byte_sorted_unique(
        "projection.omitted_distinctions",
        projection
            .omitted_distinctions
            .iter()
            .map(|distinction| distinction.code.as_str()),
    )?;
    for distinction in &projection.omitted_distinctions {
        require_token("projection.omitted_distinction.code", &distinction.code)?;
        require_token("projection.omitted_distinction.detail", &distinction.detail)?;
    }
    Ok(())
}

fn validate_inputs(artifact: &DiagnosticExecutionV1) -> Result<(), DiagnosticExecutionError> {
    let inputs = &artifact.inputs;
    require_identity("inputs.selection_rule", &inputs.selection_rule)?;
    require_utf8_byte_sorted_unique(
        "inputs.expected",
        inputs
            .expected
            .iter()
            .map(|item| item.expectation_id.as_str()),
    )?;
    let mut expected = BTreeSet::new();
    for item in &inputs.expected {
        require_token("expectation_id", &item.expectation_id)?;
        require_token("expected.role", &item.role)?;
        insert_unique(&mut expected, &item.expectation_id, "expectation_id")?;
    }
    require_utf8_byte_sorted_unique(
        "inputs.received",
        inputs.received.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut received = BTreeMap::new();
    let mut response_count: BTreeMap<&str, usize> = BTreeMap::new();
    for item in &inputs.received {
        require_token("input_id", &item.input_id)?;
        require_token("received.expectation_id", &item.expectation_id)?;
        if !expected.contains(item.expectation_id.as_str()) {
            return invariant("received input references an unknown expectation");
        }
        require_identity("received.capture_policy", &item.capture_policy)?;
        validate_interval(&item.acquisition)?;
        if item.received_at > artifact.completed_at {
            return invariant("received_at is later than diagnostic completion");
        }
        if received.insert(item.input_id.as_str(), item).is_some() {
            return invariant("duplicate input_id");
        }
        *response_count.entry(&item.expectation_id).or_default() += 1;
    }
    require_utf8_byte_sorted_unique(
        "inputs.failed",
        inputs
            .failed
            .iter()
            .map(|item| item.expectation_id.as_str()),
    )?;
    let mut failed_expectations = BTreeSet::new();
    let mut failure_ids = BTreeSet::new();
    for item in &inputs.failed {
        require_token("failed.expectation_id", &item.expectation_id)?;
        require_token("failure_id", &item.failure_id)?;
        require_token("failed.reason", &item.reason)?;
        if !expected.contains(item.expectation_id.as_str()) {
            return invariant("failed input references an unknown expectation");
        }
        insert_unique(
            &mut failed_expectations,
            &item.expectation_id,
            "failed expectation",
        )?;
        insert_unique(&mut failure_ids, &item.failure_id, "failure_id")?;
        *response_count.entry(&item.expectation_id).or_default() += 1;
    }
    for expectation in &expected {
        if response_count.get(expectation).copied() != Some(1) {
            return invariant(
                "each expectation must have exactly one received occurrence or failure",
            );
        }
    }
    validate_admission_partition(inputs, &received)
}

fn validate_admission_partition(
    inputs: &DiagnosticInputAccountingV1,
    received: &BTreeMap<&str, &ReceivedInputV1>,
) -> Result<(), DiagnosticExecutionError> {
    require_utf8_byte_sorted_unique(
        "inputs.admitted",
        inputs.admitted.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut admitted = BTreeMap::new();
    for item in &inputs.admitted {
        require_identity("admitted.admission_rule", &item.admission_rule)?;
        require_identity("admitted.normalization_rule", &item.normalization_rule)?;
        require_identity("admitted.projection_rule", &item.projection_rule)?;
        if !received.contains_key(item.input_id.as_str()) {
            return invariant("admitted input references an unknown received input");
        }
        if admitted.insert(item.input_id.as_str(), item).is_some() {
            return invariant("duplicate admitted input");
        }
    }
    require_utf8_byte_sorted_unique(
        "inputs.refused",
        inputs.refused.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut refused = BTreeSet::new();
    let mut refusal_ids = BTreeSet::new();
    for item in &inputs.refused {
        require_token("refused.input_id", &item.input_id)?;
        require_token("refused.refusal_id", &item.refusal_id)?;
        require_token("refused.code", &item.code)?;
        require_token("refused.reason", &item.reason)?;
        if !received.contains_key(item.input_id.as_str()) {
            return invariant("refused input references an unknown received input");
        }
        insert_unique(&mut refused, &item.input_id, "refused input")?;
        insert_unique(&mut refusal_ids, &item.refusal_id, "refusal_id")?;
    }
    for input_id in received.keys() {
        let outcomes =
            usize::from(admitted.contains_key(input_id)) + usize::from(refused.contains(*input_id));
        if outcomes != 1 {
            return invariant("each received input must be exactly admitted or refused");
        }
    }
    validate_selection_partition(inputs, &admitted, received)
}

fn validate_selection_partition(
    inputs: &DiagnosticInputAccountingV1,
    admitted: &BTreeMap<&str, &AdmittedInputV1>,
    received: &BTreeMap<&str, &ReceivedInputV1>,
) -> Result<(), DiagnosticExecutionError> {
    let expected: BTreeMap<&str, &ExpectedInputV1> = inputs
        .expected
        .iter()
        .map(|item| (item.expectation_id.as_str(), item))
        .collect();
    require_utf8_byte_sorted_unique(
        "inputs.selected",
        inputs.selected.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut selected = BTreeMap::new();
    for item in &inputs.selected {
        require_token("selected.role", &item.role)?;
        let Some(admission) = admitted.get(item.input_id.as_str()) else {
            return invariant("selected input is not admitted");
        };
        if item.projected_artifact_id != admission.projected_artifact_id {
            return invariant("selected input substitutes projected identity");
        }
        let occurrence = received
            .get(item.input_id.as_str())
            .expect("admitted inputs were checked against received");
        let expectation = expected
            .get(occurrence.expectation_id.as_str())
            .expect("received inputs were checked against expected");
        if item.role != expectation.role {
            return invariant("selected input role differs from its expected role");
        }
        if selected.insert(item.input_id.as_str(), item).is_some() {
            return invariant("duplicate selected input");
        }
    }
    require_utf8_byte_sorted_unique(
        "inputs.excluded",
        inputs.excluded.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut excluded = BTreeMap::new();
    for item in &inputs.excluded {
        require_token("excluded.code", &item.code)?;
        require_token("excluded.reason", &item.reason)?;
        let Some(admission) = admitted.get(item.input_id.as_str()) else {
            return invariant("excluded input is not admitted");
        };
        if item.projected_artifact_id != admission.projected_artifact_id {
            return invariant("excluded input substitutes projected identity");
        }
        if excluded.insert(item.input_id.as_str(), item).is_some() {
            return invariant("duplicate excluded input");
        }
    }
    for input_id in admitted.keys() {
        let outcomes = usize::from(selected.contains_key(input_id))
            + usize::from(excluded.contains_key(input_id));
        if outcomes != 1 {
            return invariant("each admitted input must be exactly selected or excluded");
        }
    }
    Ok(())
}

fn validate_state_bindings(
    bindings: &[DiagnosticStateBindingV1],
    inputs: &DiagnosticInputAccountingV1,
) -> Result<(), DiagnosticExecutionError> {
    let selected: BTreeSet<&str> = inputs
        .selected
        .iter()
        .map(|item| item.input_id.as_str())
        .collect();
    require_utf8_byte_sorted_unique(
        "state_bindings",
        bindings.iter().map(|binding| binding.binding_id.as_str()),
    )?;
    let mut ids = BTreeSet::new();
    for binding in bindings {
        require_token("binding_id", &binding.binding_id)?;
        require_token("state_binding.kind", &binding.kind)?;
        require_token("state_binding.value", &binding.value)?;
        insert_unique(&mut ids, &binding.binding_id, "binding_id")?;
        if binding.supporting_input_ids.is_empty() {
            return invariant("state binding has no supporting input");
        }
        require_utf8_byte_sorted_unique(
            "state_binding.supporting_input_ids",
            binding.supporting_input_ids.iter().map(String::as_str),
        )?;
        let mut supporting = BTreeSet::new();
        for input_id in &binding.supporting_input_ids {
            if !selected.contains(input_id.as_str()) {
                return invariant("state binding references a non-selected input");
            }
            insert_unique(&mut supporting, input_id, "state supporting input")?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_claims(artifact: &DiagnosticExecutionV1) -> Result<(), DiagnosticExecutionError> {
    let selected: BTreeMap<&str, &SelectedInputV1> = artifact
        .inputs
        .selected
        .iter()
        .map(|item| (item.input_id.as_str(), item))
        .collect();
    let bindings: BTreeMap<&str, &DiagnosticStateBindingV1> = artifact
        .state_bindings
        .iter()
        .map(|binding| (binding.binding_id.as_str(), binding))
        .collect();
    let omitted_distinctions: BTreeSet<&str> = artifact
        .projection
        .omitted_distinctions
        .iter()
        .map(|distinction| distinction.code.as_str())
        .collect();
    require_utf8_byte_sorted_unique(
        "claims",
        artifact.claims.iter().map(|claim| claim.claim_id.as_str()),
    )?;
    let mut claims = BTreeSet::new();
    let mut any_contradictory = false;
    for claim in &artifact.claims {
        require_token("claim_id", &claim.claim_id)?;
        require_token("claim.proposition", &claim.proposition)?;
        insert_unique(&mut claims, &claim.claim_id, "claim_id")?;
        any_contradictory |= claim.status == DiagnosticClaimStatusV1::Contradictory;
        if matches!(
            claim.status,
            DiagnosticClaimStatusV1::Established
                | DiagnosticClaimStatusV1::Refuted
                | DiagnosticClaimStatusV1::Contradictory
        ) && claim.dependency_input_ids.is_empty()
        {
            return invariant("determinate or contradictory claim has no selected dependency");
        }
        require_utf8_byte_sorted_unique(
            "claim.dependency_input_ids",
            claim.dependency_input_ids.iter().map(String::as_str),
        )?;
        let mut dependencies = BTreeSet::new();
        for input_id in &claim.dependency_input_ids {
            if !selected.contains_key(input_id.as_str()) {
                return invariant("claim references a non-selected input");
            }
            insert_unique(&mut dependencies, input_id, "claim dependency")?;
        }
        require_utf8_byte_sorted_unique(
            "claim.state_binding_ids",
            claim.state_binding_ids.iter().map(String::as_str),
        )?;
        let mut state_ids = BTreeSet::new();
        for binding_id in &claim.state_binding_ids {
            let Some(binding) = bindings.get(binding_id.as_str()) else {
                return invariant("claim references an unknown state binding");
            };
            insert_unique(&mut state_ids, binding_id, "claim state binding")?;
            if binding
                .supporting_input_ids
                .iter()
                .any(|input_id| !dependencies.contains(input_id.as_str()))
            {
                return invariant(
                    "claim state binding depends on input outside the claim dependency frontier",
                );
            }
        }
        require_utf8_byte_sorted_unique(
            "claim.required_distinctions",
            claim.required_distinctions.iter().map(String::as_str),
        )?;
        for distinction in &claim.required_distinctions {
            require_token("claim.required_distinction", distinction)?;
            if omitted_distinctions.contains(distinction.as_str()) {
                return invariant("claim requires a distinction omitted by the projection");
            }
        }
        require_utf8_byte_sorted_unique(
            "claim.limitations",
            claim.limitations.iter().map(String::as_str),
        )?;
        for limitation in &claim.limitations {
            require_token("claim limitation", limitation)?;
        }
        require_utf8_byte_sorted_unique(
            "claim.nonclaims",
            claim.nonclaims.iter().map(String::as_str),
        )?;
        for nonclaim in &claim.nonclaims {
            require_token("claim nonclaim", nonclaim)?;
        }
        if claim.condition_effect.is_some_and(|effect| {
            matches!(
                effect,
                DiagnosticConditionV1::Present
                    | DiagnosticConditionV1::Clean
                    | DiagnosticConditionV1::ExplicitlyAbsent
                    | DiagnosticConditionV1::NotApplicable
            )
        }) && claim.status != DiagnosticClaimStatusV1::Established
        {
            return invariant("determinate condition effect requires an established claim");
        }
        if matches!(
            claim.status,
            DiagnosticClaimStatusV1::Unknown
                | DiagnosticClaimStatusV1::Contradictory
                | DiagnosticClaimStatusV1::Refuted
        ) && claim
            .condition_effect
            .is_some_and(|effect| effect != DiagnosticConditionV1::Unresolved)
        {
            return invariant("non-established claim may only leave the condition unresolved");
        }
        if claim.condition_effect.is_some()
            && artifact.primary_claim_id.as_deref() != Some(claim.claim_id.as_str())
        {
            return invariant("non-primary claim carries a condition effect");
        }
    }
    match artifact.primary_claim_id.as_deref() {
        Some(primary) if !claims.contains(primary) => {
            return invariant("primary_claim_id does not identify an exported claim");
        }
        None if matches!(
            artifact.outcome.derivation,
            DiagnosticDerivationV1::Completed | DiagnosticDerivationV1::Partial
        ) =>
        {
            return invariant("completed or partial outcome has no primary claim");
        }
        Some(_)
            if matches!(
                artifact.outcome.derivation,
                DiagnosticDerivationV1::Refused | DiagnosticDerivationV1::Unsupported
            ) =>
        {
            return invariant("refused or unsupported outcome exports a primary claim");
        }
        _ => {}
    }
    if matches!(
        artifact.outcome.derivation,
        DiagnosticDerivationV1::Refused | DiagnosticDerivationV1::Unsupported
    ) && !artifact.claims.is_empty()
    {
        return invariant("refused or unsupported outcome exports claims");
    }
    if let Some(primary_id) = artifact.primary_claim_id.as_deref() {
        let primary = artifact
            .claims
            .iter()
            .find(|claim| claim.claim_id == primary_id)
            .expect("primary identity checked above");
        if primary.condition_effect != Some(artifact.outcome.condition) {
            return invariant("primary claim condition effect differs from outcome condition");
        }
        let determinate = matches!(
            artifact.outcome.condition,
            DiagnosticConditionV1::Present
                | DiagnosticConditionV1::Clean
                | DiagnosticConditionV1::ExplicitlyAbsent
                | DiagnosticConditionV1::NotApplicable
        );
        if determinate && primary.state_binding_ids.is_empty() {
            return invariant("primary determinate claim has no state binding");
        }
        if (primary.status == DiagnosticClaimStatusV1::Contradictory)
            != (artifact.outcome.coherence == DiagnosticCoherenceV1::Contradictory)
        {
            return invariant("primary contradiction differs from outcome coherence");
        }
    } else if artifact.outcome.coherence == DiagnosticCoherenceV1::Contradictory {
        return invariant("contradictory outcome has no primary contradictory claim");
    }
    if any_contradictory != (artifact.outcome.coherence == DiagnosticCoherenceV1::Contradictory) {
        return invariant("exported claim dissent differs from outcome coherence");
    }
    Ok(())
}

fn validate_outcome(artifact: &DiagnosticExecutionV1) -> Result<(), DiagnosticExecutionError> {
    let outcome = &artifact.outcome;
    require_token("outcome.summary", &outcome.summary)?;
    match (&outcome.derivation, &outcome.refusal) {
        (DiagnosticDerivationV1::Refused, Some(refusal)) => {
            require_token("outcome.refusal.code", &refusal.code)?;
            require_token("outcome.refusal.reason", &refusal.reason)?;
        }
        (DiagnosticDerivationV1::Refused, None) => {
            return invariant("refused outcome has no refusal");
        }
        (_, Some(_)) => return invariant("non-refused outcome carries a refusal"),
        (_, None) => {}
    }
    if outcome.condition == DiagnosticConditionV1::ExplicitlyAbsent
        && (outcome.derivation != DiagnosticDerivationV1::Completed
            || outcome.coverage != DiagnosticCoverageV1::Complete
            || outcome.coherence != DiagnosticCoherenceV1::JointlyEstablished)
    {
        return invariant(
            "explicit absence requires completed derivation, complete coverage, and joint coherence",
        );
    }
    if outcome.condition == DiagnosticConditionV1::Clean
        && (outcome.derivation != DiagnosticDerivationV1::Completed
            || outcome.coverage != DiagnosticCoverageV1::Complete
            || outcome.coherence != DiagnosticCoherenceV1::JointlyEstablished)
    {
        return invariant(
            "clean condition requires completed derivation, complete coverage, and joint coherence",
        );
    }
    if outcome.derivation == DiagnosticDerivationV1::Refused
        && outcome.condition != DiagnosticConditionV1::Unresolved
    {
        return invariant("refused outcome must have unresolved condition");
    }
    if outcome.derivation == DiagnosticDerivationV1::Unsupported
        && outcome.condition != DiagnosticConditionV1::Unresolved
    {
        return invariant("unsupported outcome must have unresolved condition");
    }
    if matches!(
        outcome.coherence,
        DiagnosticCoherenceV1::Contradictory | DiagnosticCoherenceV1::StateIncompatible
    ) && outcome.condition != DiagnosticConditionV1::Unresolved
    {
        return invariant("contradictory/state-incompatible evidence cannot clear a condition");
    }
    if outcome.coverage == DiagnosticCoverageV1::Complete {
        let received_expectations: BTreeMap<&str, &str> = artifact
            .inputs
            .received
            .iter()
            .map(|input| (input.expectation_id.as_str(), input.input_id.as_str()))
            .collect();
        let admitted: BTreeSet<&str> = artifact
            .inputs
            .admitted
            .iter()
            .map(|input| input.input_id.as_str())
            .collect();
        let selected: BTreeSet<&str> = artifact
            .inputs
            .selected
            .iter()
            .map(|input| input.input_id.as_str())
            .collect();
        let required: Vec<&ExpectedInputV1> = artifact
            .inputs
            .expected
            .iter()
            .filter(|expectation| expectation.required)
            .collect();
        if required.is_empty() {
            return invariant("complete coverage has no required expectation");
        }
        for expectation in required {
            let Some(input_id) = received_expectations.get(expectation.expectation_id.as_str())
            else {
                return invariant("complete coverage omits a required expected input");
            };
            if !admitted.contains(input_id) {
                return invariant("complete coverage includes refused required testimony");
            }
            if !selected.contains(input_id) {
                return invariant("complete coverage excludes required testimony");
            }
        }
    }
    Ok(())
}

fn validate_interval(interval: &AcquisitionIntervalV1) -> Result<(), DiagnosticExecutionError> {
    require_identity("acquisition.clock", &interval.clock)?;
    if interval.started_at > interval.ended_at {
        return invariant("acquisition interval starts after it ends");
    }
    Ok(())
}

fn require_identity(
    field: &str,
    identity: &SemanticIdentityV1,
) -> Result<(), DiagnosticExecutionError> {
    require_token(&format!("{field}.id"), &identity.id)?;
    require_token(&format!("{field}.version"), &identity.version)
}

fn require_token(field: &str, value: &str) -> Result<(), DiagnosticExecutionError> {
    if value.trim().is_empty() {
        return invariant(format!("{field} is empty"));
    }
    Ok(())
}

fn insert_unique<'a>(
    values: &mut BTreeSet<&'a str>,
    value: &'a str,
    field: &str,
) -> Result<(), DiagnosticExecutionError> {
    if !values.insert(value) {
        return invariant(format!("duplicate {field}"));
    }
    Ok(())
}

fn require_utf8_byte_sorted_unique<'a>(
    field: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), DiagnosticExecutionError> {
    let mut previous: Option<&str> = None;
    for value in values {
        if previous.is_some_and(|prior| prior.as_bytes() >= value.as_bytes()) {
            return invariant(format!(
                "{field} must be strictly ordered by unsigned UTF-8 bytes and unique"
            ));
        }
        previous = Some(value);
    }
    Ok(())
}

fn invariant<T>(message: impl Into<String>) -> Result<T, DiagnosticExecutionError> {
    Err(DiagnosticExecutionError::Invariant(message.into()))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn digest(label: &str) -> Sha256Digest {
        nq_protocol::sha256_bytes(label.as_bytes())
    }

    fn identity(id: &str) -> SemanticIdentityV1 {
        SemanticIdentityV1 {
            id: id.to_owned(),
            version: "1".to_owned(),
            digest: digest(id),
        }
    }

    fn time(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 27, 20, 0, second)
            .single()
            .expect("valid fixture time")
    }

    #[allow(clippy::too_many_lines)]
    fn positive() -> DiagnosticExecutionV1 {
        let acquisition = AcquisitionIntervalV1 {
            started_at: time(1),
            ended_at: time(2),
            clock: identity("clock.utc.provider"),
            clock_uncertainty_ms: 5,
        };
        let mut artifact = DiagnosticExecutionV1 {
            schema: DiagnosticExecutionSchema::V1,
            artifact_id: DiagnosticArtifactId(digest("placeholder")),
            canonicalization: diagnostic_canonicalization_identity().unwrap(),
            producer: DiagnosticProducerV1 {
                node_id: "nq-node:fixture".to_owned(),
                build: identity("nq-build"),
                cohort: identity("nq-cohort"),
            },
            request_id: DiagnosticRequestId("request:001".to_owned()),
            run_id: DiagnosticRunId("run:001".to_owned()),
            question: identity("diagnostic:host-load"),
            subject: DiagnosticSubjectV1 {
                id: "host:fixture".to_owned(),
                scope: identity("scope:host"),
            },
            profile: identity("profile:host"),
            vantage: identity("vantage:host-local"),
            state_model: identity("state-model:boot"),
            evaluator: identity("evaluator:nq"),
            threshold_policy: identity("threshold:load"),
            projection: DiagnosticProjectionV1 {
                identity: identity("projection:load-full"),
                omitted_distinctions: vec![],
            },
            execution_clock: identity("clock.utc.nq"),
            started_at: time(3),
            completed_at: time(4),
            attempt_interval: AcquisitionIntervalV1 {
                started_at: time(3),
                ended_at: time(4),
                clock: identity("clock.utc.nq"),
                clock_uncertainty_ms: 1,
            },
            inputs: DiagnosticInputAccountingV1 {
                selection_rule: identity("selection:newest-current"),
                expected: vec![ExpectedInputV1 {
                    expectation_id: "expected:host-snapshot".to_owned(),
                    role: "host_snapshot".to_owned(),
                    required: true,
                }],
                received: vec![ReceivedInputV1 {
                    input_id: "input:001".to_owned(),
                    expectation_id: "expected:host-snapshot".to_owned(),
                    raw_artifact_id: RawArtifactId(digest("raw")),
                    capture_mode: RawCaptureModeV1::ExactSource,
                    capture_policy: identity("capture:exact-source-v1"),
                    availability_at_derivation: EvidenceAvailabilityV1::Online,
                    acquisition: acquisition.clone(),
                    received_at: time(3),
                }],
                admitted: vec![AdmittedInputV1 {
                    input_id: "input:001".to_owned(),
                    admission_rule: identity("admission:host-v1"),
                    normalized_artifact_id: NormalizedArtifactId(digest("normalized")),
                    normalization_rule: identity("normalization:host-v1"),
                    projected_artifact_id: ProjectedArtifactId(digest("projected")),
                    projection_rule: identity("projection-rule:host-load-v1"),
                }],
                refused: vec![],
                failed: vec![],
                excluded: vec![],
                selected: vec![SelectedInputV1 {
                    input_id: "input:001".to_owned(),
                    projected_artifact_id: ProjectedArtifactId(digest("projected")),
                    role: "host_snapshot".to_owned(),
                }],
            },
            state_bindings: vec![DiagnosticStateBindingV1 {
                binding_id: "state:boot-a".to_owned(),
                kind: "boot_epoch".to_owned(),
                value: "boot-a".to_owned(),
                supporting_input_ids: vec!["input:001".to_owned()],
            }],
            claims: vec![DiagnosticClaimV1 {
                claim_id: "claim:load-pressure".to_owned(),
                proposition: "host load pressure is absent".to_owned(),
                status: DiagnosticClaimStatusV1::Established,
                condition_effect: Some(DiagnosticConditionV1::ExplicitlyAbsent),
                dependency_input_ids: vec!["input:001".to_owned()],
                state_binding_ids: vec!["state:boot-a".to_owned()],
                required_distinctions: vec!["boot_epoch".to_owned()],
                limitations: vec!["one snapshot does not identify a cause".to_owned()],
                nonclaims: vec!["no remediation is authorized".to_owned()],
            }],
            primary_claim_id: Some("claim:load-pressure".to_owned()),
            outcome: DiagnosticOutcomeV1 {
                derivation: DiagnosticDerivationV1::Completed,
                condition: DiagnosticConditionV1::ExplicitlyAbsent,
                coherence: DiagnosticCoherenceV1::JointlyEstablished,
                coverage: DiagnosticCoverageV1::Complete,
                summary: "complete current testimony places load below threshold".to_owned(),
                refusal: None,
            },
            limitations: vec![],
            nonclaims: vec![
                "this artifact grants no reliance or authorization".to_owned(),
                "this artifact reports one bounded diagnostic execution".to_owned(),
            ],
        };
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        artifact
    }

    fn refused() -> DiagnosticExecutionV1 {
        let mut artifact = positive();
        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        artifact.inputs.refused = vec![RefusedInputV1 {
            input_id: "input:001".to_owned(),
            refusal_id: "refusal:001".to_owned(),
            code: "schema_mismatch".to_owned(),
            reason: "provider response did not match the admitted schema".to_owned(),
        }];
        artifact.outcome = DiagnosticOutcomeV1 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "NQ refused the received provider response".to_owned(),
            refusal: Some(DiagnosticRefusalV1 {
                code: "input_refused".to_owned(),
                reason: "required received testimony was refused".to_owned(),
            }),
        };
        artifact.state_bindings.clear();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        artifact
    }

    fn provider_no_response() -> DiagnosticExecutionV1 {
        let mut artifact = positive();
        artifact.inputs.received.clear();
        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        artifact.inputs.failed = vec![FailedInputV1 {
            expectation_id: "expected:host-snapshot".to_owned(),
            failure_id: "failure:no-response".to_owned(),
            kind: InputFailureKindV1::NoResponse,
            reason: "the provider returned no response before its deadline".to_owned(),
        }];
        artifact.state_bindings.clear();
        artifact.claims = vec![DiagnosticClaimV1 {
            claim_id: "claim:provider-testimony".to_owned(),
            proposition: "required provider testimony is available".to_owned(),
            status: DiagnosticClaimStatusV1::Unknown,
            condition_effect: Some(DiagnosticConditionV1::Unresolved),
            dependency_input_ids: vec![],
            state_binding_ids: vec![],
            required_distinctions: vec![],
            limitations: vec!["required provider testimony was not received".to_owned()],
            nonclaims: vec!["the monitored subject is not established absent".to_owned()],
        }];
        artifact.primary_claim_id = Some("claim:provider-testimony".to_owned());
        artifact.outcome = DiagnosticOutcomeV1 {
            derivation: DiagnosticDerivationV1::Partial,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "required provider testimony was not received".to_owned(),
            refusal: None,
        };
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        artifact
    }

    fn projection_collision(label: &str) -> DiagnosticExecutionV1 {
        let mut artifact = positive();
        artifact.inputs.received[0].raw_artifact_id = RawArtifactId(digest(label));
        artifact.projection.omitted_distinctions = vec![OmittedDistinctionV1 {
            code: "workflow_attempt".to_owned(),
            detail: "the child projection erased workflow-attempt identity".to_owned(),
        }];
        artifact.claims[0].required_distinctions = vec!["workflow_attempt".to_owned()];
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        artifact
    }

    #[test]
    fn positive_artifact_round_trips_as_unique_canonical_bytes() {
        let artifact = positive();
        let bytes = artifact.canonical_bytes().unwrap();
        assert_eq!(
            DiagnosticExecutionV1::decode_canonical(&bytes).unwrap(),
            artifact
        );
    }

    #[test]
    fn object_key_reformatting_is_rejected_even_when_json_decodes() {
        let artifact = positive();
        let pretty = serde_json::to_vec_pretty(&artifact).unwrap();
        assert!(matches!(
            DiagnosticExecutionV1::decode_canonical(&pretty),
            Err(DiagnosticExecutionError::NonCanonical)
        ));
    }

    #[test]
    fn selected_identity_substitution_is_rejected() {
        let mut artifact = positive();
        artifact.inputs.selected[0].projected_artifact_id = ProjectedArtifactId(digest("other"));
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(artifact.validate().is_err());
    }

    #[test]
    fn declared_denominator_rejects_unsatisfied_required_input() {
        let mut artifact = positive();
        artifact.inputs.expected.push(ExpectedInputV1 {
            expectation_id: "expected:mount".to_owned(),
            role: "mount_state".to_owned(),
            required: true,
        });
        artifact.inputs.failed.push(FailedInputV1 {
            expectation_id: "expected:mount".to_owned(),
            failure_id: "failure:mount".to_owned(),
            kind: InputFailureKindV1::Missing,
            reason: "mount testimony was not acquired".to_owned(),
        });
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "complete coverage omits a required expected input"
        ));
    }

    #[test]
    fn clean_and_explicit_absence_remain_distinct_determinate_conditions() {
        assert_ne!(
            serde_json::to_value(DiagnosticConditionV1::Clean).unwrap(),
            serde_json::to_value(DiagnosticConditionV1::ExplicitlyAbsent).unwrap()
        );
        let mut artifact = positive();
        artifact.claims[0].condition_effect = Some(DiagnosticConditionV1::Clean);
        artifact.outcome.condition = DiagnosticConditionV1::Clean;
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(artifact.validate().is_ok());
    }

    #[test]
    fn omitted_distinctions_are_ordered_and_block_dependent_claims() {
        let mut artifact = positive();
        artifact.projection.omitted_distinctions = vec![
            OmittedDistinctionV1 {
                code: "workflow_attempt".to_owned(),
                detail: "attempt identity was erased".to_owned(),
            },
            OmittedDistinctionV1 {
                code: "boot_epoch".to_owned(),
                detail: "boot identity was erased".to_owned(),
            },
        ];
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("projection.omitted_distinctions")
        ));

        artifact.projection.omitted_distinctions.swap(0, 1);
        artifact.claims[0].required_distinctions = vec!["workflow_attempt".to_owned()];
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "claim requires a distinction omitted by the projection"
        ));
    }

    #[test]
    fn raw_normalized_projected_chain_is_exact() {
        let mut artifact = positive();
        artifact.inputs.selected[0].projected_artifact_id =
            ProjectedArtifactId(digest("substituted-projection"));
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "selected input substitutes projected identity"
        ));
    }

    #[test]
    fn raw_capture_mode_policy_and_derivation_availability_are_explicit() {
        let exact = positive();
        let mut redacted = positive();
        redacted.inputs.received[0].capture_mode = RawCaptureModeV1::EarliestBoundaryRedacted;
        redacted.inputs.received[0].capture_policy = identity("redaction:bounded-v1");
        redacted.inputs.received[0].availability_at_derivation =
            EvidenceAvailabilityV1::ArchivedRetrievable;
        redacted.artifact_id = redacted.computed_artifact_id().unwrap();
        assert!(redacted.validate().is_ok());
        assert_ne!(exact.artifact_id, redacted.artifact_id);
        assert_ne!(
            exact.inputs.received[0].capture_mode,
            redacted.inputs.received[0].capture_mode
        );
    }

    #[test]
    fn set_like_arrays_must_be_lexicographically_ordered() {
        let mut artifact = positive();
        artifact.nonclaims.swap(0, 1);
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("nonclaims must be strictly ordered by unsigned UTF-8 bytes")
        ));
    }

    #[test]
    fn set_order_is_unsigned_utf8_bytes_not_jcs_utf16_key_order() {
        let mut artifact = positive();
        artifact.nonclaims = vec![
            "z".to_owned(),
            "\u{e000}".to_owned(),
            "\u{10000}".to_owned(),
        ];
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(artifact.validate().is_ok());

        artifact.nonclaims.swap(1, 2);
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("unsigned UTF-8 bytes")
        ));
    }

    #[test]
    fn complete_coverage_requires_required_testimony_to_be_selected() {
        let mut artifact = positive();
        let selected = artifact.inputs.selected.pop().unwrap();
        artifact.inputs.excluded.push(ExcludedInputV1 {
            input_id: selected.input_id,
            projected_artifact_id: selected.projected_artifact_id,
            code: "not_selected".to_owned(),
            reason: "selection law excluded the occurrence".to_owned(),
        });
        artifact.state_bindings.clear();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome.condition = DiagnosticConditionV1::Unresolved;
        artifact.outcome.derivation = DiagnosticDerivationV1::Refused;
        artifact.outcome.refusal = Some(DiagnosticRefusalV1 {
            code: "required_input_excluded".to_owned(),
            reason: "required testimony was not selected".to_owned(),
        });
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "complete coverage excludes required testimony"
        ));
    }

    #[test]
    fn only_primary_claim_may_affect_condition_and_effect_must_match() {
        let mut artifact = positive();
        let mut secondary = artifact.claims[0].clone();
        secondary.claim_id = "claim:secondary".to_owned();
        secondary.condition_effect = Some(DiagnosticConditionV1::ExplicitlyAbsent);
        artifact.claims.push(secondary);
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "non-primary claim carries a condition effect"
        ));

        let mut artifact = positive();
        artifact.claims[0].condition_effect = Some(DiagnosticConditionV1::Clean);
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "primary claim condition effect differs from outcome condition"
        ));
    }

    #[test]
    fn refusal_cannot_smuggle_a_non_primary_claim() {
        let mut artifact = refused();
        let mut smuggled = positive().claims.remove(0);
        smuggled.status = DiagnosticClaimStatusV1::Unknown;
        smuggled.condition_effect = None;
        smuggled.dependency_input_ids.clear();
        smuggled.state_binding_ids.clear();
        smuggled.required_distinctions.clear();
        artifact.claims.push(smuggled);
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "refused or unsupported outcome exports claims"
        ));
    }

    #[test]
    fn state_binding_support_must_fit_claim_dependency_frontier() {
        let mut artifact = positive();
        artifact.inputs.expected.push(ExpectedInputV1 {
            expectation_id: "expected:mount".to_owned(),
            role: "mount_state".to_owned(),
            required: false,
        });
        artifact.inputs.received.push(ReceivedInputV1 {
            input_id: "input:002".to_owned(),
            expectation_id: "expected:mount".to_owned(),
            raw_artifact_id: RawArtifactId(digest("raw-mount")),
            capture_mode: RawCaptureModeV1::ExactSource,
            capture_policy: identity("capture:exact-source-v1"),
            availability_at_derivation: EvidenceAvailabilityV1::Online,
            acquisition: AcquisitionIntervalV1 {
                started_at: time(1),
                ended_at: time(2),
                clock: identity("clock.utc.provider"),
                clock_uncertainty_ms: 5,
            },
            received_at: time(3),
        });
        artifact.inputs.admitted.push(AdmittedInputV1 {
            input_id: "input:002".to_owned(),
            admission_rule: identity("admission:host-v1"),
            normalized_artifact_id: NormalizedArtifactId(digest("normalized-mount")),
            normalization_rule: identity("normalization:host-v1"),
            projected_artifact_id: ProjectedArtifactId(digest("projected-mount")),
            projection_rule: identity("projection-rule:mount-v1"),
        });
        artifact.inputs.selected.push(SelectedInputV1 {
            input_id: "input:002".to_owned(),
            projected_artifact_id: ProjectedArtifactId(digest("projected-mount")),
            role: "mount_state".to_owned(),
        });
        artifact.state_bindings[0]
            .supporting_input_ids
            .push("input:002".to_owned());
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message
                    == "claim state binding depends on input outside the claim dependency frontier"
        ));
    }

    #[test]
    fn execution_attempt_uses_the_declared_execution_clock() {
        let mut artifact = positive();
        artifact.attempt_interval.clock = identity("clock.utc.other");
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "attempt interval does not use execution_clock"
        ));
    }

    #[test]
    fn absent_primary_is_absent_from_self_identity_preimage() {
        let artifact = refused();
        let value = serde_json::to_value(artifact.preimage()).unwrap();
        assert!(value.get("primary_claim_id").is_none());
    }

    #[test]
    fn selected_role_cannot_relabel_the_expected_input() {
        let mut artifact = positive();
        artifact.inputs.selected[0].role = "different_role".to_owned();
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "selected input role differs from its expected role"
        ));
    }

    #[test]
    fn material_dissent_cannot_be_hidden_in_a_secondary_claim() {
        let mut artifact = positive();
        let mut secondary = artifact.claims[0].clone();
        secondary.claim_id = "claim:secondary".to_owned();
        secondary.status = DiagnosticClaimStatusV1::Contradictory;
        secondary.condition_effect = None;
        artifact.claims.push(secondary);
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message == "exported claim dissent differs from outcome coherence"
        ));
    }

    #[test]
    fn lossy_projection_collision_refuses_both_underlying_states() {
        let matching = projection_collision("e-match-raw");
        let mismatching = projection_collision("e-mismatch-raw");
        assert_ne!(matching.artifact_id, mismatching.artifact_id);
        assert_eq!(
            matching.inputs.admitted[0].projected_artifact_id,
            mismatching.inputs.admitted[0].projected_artifact_id
        );
        for artifact in [matching, mismatching] {
            assert!(matches!(
                artifact.validate(),
                Err(DiagnosticExecutionError::Invariant(message))
                    if message == "claim requires a distinction omitted by the projection"
            ));
        }
    }

    #[test]
    fn refused_and_provider_no_response_are_distinct_canonical_artifacts() {
        let refused = refused();
        let no_response = provider_no_response();
        assert!(refused.validate().is_ok());
        assert!(no_response.validate().is_ok());
        assert_ne!(refused.artifact_id, no_response.artifact_id);
        assert_ne!(
            refused.canonical_bytes().unwrap(),
            no_response.canonical_bytes().unwrap()
        );
        assert_eq!(refused.inputs.refused.len(), 1);
        assert!(matches!(
            no_response.inputs.failed[0].kind,
            InputFailureKindV1::NoResponse
        ));
    }

    #[test]
    fn checked_in_vectors_are_exact_canonical_payloads() {
        let positive_bytes =
            include_bytes!("../../../audit/nq-nightshift-stage6-foundation/vectors/positive.json");
        let refused_bytes =
            include_bytes!("../../../audit/nq-nightshift-stage6-foundation/vectors/refused.json");
        let no_response_bytes = include_bytes!(
            "../../../audit/nq-nightshift-stage6-foundation/vectors/provider_no_response.json"
        );
        let collision_match_bytes = include_bytes!(
            "../../../audit/nq-nightshift-stage6-foundation/vectors/hostile_projection_collision_match.json"
        );
        let collision_mismatch_bytes = include_bytes!(
            "../../../audit/nq-nightshift-stage6-foundation/vectors/hostile_projection_collision_mismatch.json"
        );
        assert_eq!(positive().canonical_bytes().unwrap(), positive_bytes);
        assert_eq!(refused().canonical_bytes().unwrap(), refused_bytes);
        assert_eq!(
            provider_no_response().canonical_bytes().unwrap(),
            no_response_bytes
        );
        assert_eq!(
            DiagnosticExecutionV1::decode_canonical(positive_bytes).unwrap(),
            positive()
        );
        assert_eq!(
            DiagnosticExecutionV1::decode_canonical(refused_bytes).unwrap(),
            refused()
        );
        assert_eq!(
            DiagnosticExecutionV1::decode_canonical(no_response_bytes).unwrap(),
            provider_no_response()
        );
        let collision_match: DiagnosticExecutionV1 =
            serde_json::from_slice(collision_match_bytes).unwrap();
        let collision_mismatch: DiagnosticExecutionV1 =
            serde_json::from_slice(collision_mismatch_bytes).unwrap();
        for (bytes, artifact) in [
            (collision_match_bytes.as_slice(), collision_match.clone()),
            (
                collision_mismatch_bytes.as_slice(),
                collision_mismatch.clone(),
            ),
        ] {
            assert_eq!(canonical_json_bytes(&artifact).unwrap(), bytes);
            assert_eq!(
                artifact.computed_artifact_id().unwrap(),
                artifact.artifact_id
            );
            assert!(matches!(
                DiagnosticExecutionV1::decode_canonical(bytes),
                Err(DiagnosticExecutionError::Invariant(message))
                    if message == "claim requires a distinction omitted by the projection"
            ));
        }
        assert_ne!(
            collision_match.inputs.received[0].raw_artifact_id,
            collision_mismatch.inputs.received[0].raw_artifact_id
        );
        assert_eq!(
            collision_match.inputs.admitted[0].projected_artifact_id,
            collision_mismatch.inputs.admitted[0].projected_artifact_id
        );
    }

    #[test]
    fn explicit_absence_requires_complete_joint_evidence() {
        let mut artifact = positive();
        artifact.outcome.coverage = DiagnosticCoverageV1::Partial;
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(artifact.validate().is_err());
    }

    #[test]
    fn nq_refusal_does_not_collapse_complete_coverage() {
        let mut artifact = positive();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV1 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Complete,
            summary: "NQ refused despite complete admitted testimony".to_owned(),
            refusal: Some(DiagnosticRefusalV1 {
                code: "policy_refusal".to_owned(),
                reason: "the evaluator declined this bounded derivation".to_owned(),
            }),
        };
        artifact.artifact_id = artifact.computed_artifact_id().unwrap();
        assert!(artifact.validate().is_ok());
    }
}
