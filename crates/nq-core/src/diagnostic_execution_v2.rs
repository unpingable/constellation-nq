//! Candidate canonical contract for one bounded NQ diagnostic execution.
//!
//! This module is an additive wire contract. It does not replace or alter
//! `nq.diagnostic_execution.v1`; strict supported-version dispatch keeps both
//! contracts independently reopenable.
//!
//! V2 closes two distinctions that v1 cannot represent:
//!
//! - outcome and received-input refusals retain the exact versioned
//!   [`GovernedRefusal`] rather than a code/reason projection; and
//! - acquisition intervals distinguish a supported bounded clock-error claim
//!   from an explicitly unqualified clock. An unqualified clock never carries
//!   a fabricated numeric uncertainty.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest};
use serde::{Deserialize, Serialize};

use crate::{
    diagnostic_execution::{
        AdmittedInputV1, DiagnosticArtifactId, DiagnosticClaimStatusV1, DiagnosticCoherenceV1,
        DiagnosticConditionV1, DiagnosticCoverageV1, DiagnosticDerivationV1,
        DiagnosticExecutionError, DiagnosticLimitationV1, DiagnosticProducerV1,
        DiagnosticProjectionV1, DiagnosticRequestId, DiagnosticRunId, DiagnosticStateBindingV1,
        DiagnosticSubjectV1, EvidenceAvailabilityV1, ExcludedInputV1, ExpectedInputV1,
        RawArtifactId, RawCaptureModeV1, SelectedInputV1, SemanticIdentityV1,
        diagnostic_canonicalization_identity,
    },
    engine::{AcquisitionFailure, AcquisitionFailureClass, GovernedRefusal, GovernedRefusalOrigin},
};

/// Wire schema for the candidate second diagnostic-execution contract.
pub const DIAGNOSTIC_EXECUTION_V2_SCHEMA: &str = "nq.diagnostic_execution.v2";

/// Closed v2 diagnostic-execution schema identity.
///
/// This is deliberately a separate enum from v1. Adding a v2 variant to the
/// v1 enum would let the old struct deserialize a document under the wrong
/// semantic contract.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticExecutionSchemaV2 {
    /// Exact-refusal and explicit-clock-qualification contract.
    #[serde(rename = "nq.diagnostic_execution.v2")]
    V2,
}

/// Producer testimony about the relationship between one interval's timestamp
/// values and UTC.
///
/// `Bounded` is still producer testimony, not consumer reliance. A downstream
/// consumer must separately establish that its evaluation clock is comparable
/// under an identified consumer-owned policy.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClockQualificationV2 {
    /// An identified qualification basis supports a symmetric maximum error.
    Bounded {
        /// Inclusive symmetric upper bound on UTC error.
        maximum_error_ms: u64,
        /// Exact rule, measurement, or qualification identity supporting the
        /// bound.
        basis: SemanticIdentityV1,
    },
    /// No finite clock-error bound was established.
    Unqualified {
        /// Stable machine-readable reason.
        code: String,
        /// Bounded operator-facing explanation.
        detail: String,
    },
}

/// Source acquisition interval with explicit clock qualification.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionIntervalV2 {
    /// Earliest source acquisition timestamp represented.
    pub started_at: DateTime<Utc>,
    /// Latest source acquisition timestamp represented.
    pub ended_at: DateTime<Utc>,
    /// Exact clock source/generation identity.
    pub clock: SemanticIdentityV1,
    /// Whether a finite UTC-error bound was actually established.
    pub qualification: ClockQualificationV2,
}

/// One input occurrence received into NQ custody.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedInputV2 {
    /// Occurrence identity, distinct from content identity.
    pub input_id: String,
    /// Exact expectation this occurrence answers.
    pub expectation_id: String,
    /// Exact provider-intake occurrence from which custody originated.
    pub provider_intake_id: String,
    /// Content identity of exact admitted or earliest-boundary-redacted bytes.
    pub raw_artifact_id: RawArtifactId,
    /// Whether the committed bytes are exact source or boundary-redacted.
    pub capture_mode: RawCaptureModeV1,
    /// Exact capture/redaction policy applied before ordinary raw custody.
    pub capture_policy: SemanticIdentityV1,
    /// Historical byte availability at the derivation instant.
    pub availability_at_derivation: EvidenceAvailabilityV1,
    /// Source acquisition interval.
    pub acquisition: AcquisitionIntervalV2,
    /// NQ custody receipt time; never a source-freshness time.
    pub received_at: DateTime<Utc>,
}

/// Binding of a profile-origin refusal carried by one refused input.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileRefusalBindingV2 {
    /// The refusal was produced by the diagnostic artifact's own profile.
    ArtifactProfile,
    /// The refused input role intentionally carries testimony from another
    /// identified profile.
    ForeignInputRole {
        /// Exact expected input role occupied by the foreign-profile result.
        role: String,
    },
}

/// One received input refused or found invalid.
///
/// The exact originating carrier is retained. No code/reason projection is
/// allowed to replace it.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedInputV2 {
    /// Received input occurrence.
    pub input_id: String,
    /// Exact versioned refusal from its responsible boundary.
    pub refusal: GovernedRefusal,
    /// Required for profile-origin refusals and forbidden for other origins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_binding: Option<ProfileRefusalBindingV2>,
}

/// Explicit statement that a failed acquisition retained no response bytes.
///
/// This value is checked against provider intake during live emission. If any
/// bytes entered custody, the occurrence belongs in `received` and an
/// acquisition-origin refusal belongs in `refused`; it is not a failed input.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedAcquisitionCustodyV2 {
    /// The provider-intake occurrence retained no response bytes.
    NoBytesRetained,
}

/// Typed unsupported classification.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedCodeV2 {
    /// The selected diagnostic profile does not implement the bounded
    /// question.
    QuestionUnsupported,
    /// The declared provider cannot supply the required capability.
    ProviderCapabilityUnavailable,
    /// The bound platform does not expose the required capability.
    PlatformCapabilityUnavailable,
    /// The required contract generation is unsupported.
    ContractVersionUnsupported,
}

/// Exact location from which an unsupported conclusion arose.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnsupportedOriginV2 {
    /// The diagnostic profile itself does not support the bounded question.
    DiagnosticProfile,
    /// One expected input is unsupported.
    ExpectedInput {
        /// Exact failed-input occurrence carrying this cause.
        failure_id: String,
    },
}

/// Identified typed unsupported cause.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedCauseV2 {
    /// Immutable unsupported-cause identity.
    pub unsupported_id: String,
    /// Exact origin of this cause.
    pub origin: UnsupportedOriginV2,
    /// Closed unsupported classification.
    pub code: UnsupportedCodeV2,
    /// Exact capability/profile/contract identity found unsupported.
    pub capability: SemanticIdentityV1,
    /// Bounded operator-facing detail; never the only classification.
    pub detail: String,
}

/// Exact reason an expected input produced no received occurrence.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FailedInputCauseV2 {
    /// The declared closed inventory found no occurrence, without claiming a
    /// provider invocation failure.
    Missing {
        /// Bounded reason for the closed-world miss.
        reason: String,
    },
    /// An invocation occurred but produced no qualifying provider response.
    ProviderNoResponse {
        /// Exact provider-intake occurrence for the failed attempt.
        provider_intake_id: String,
        /// Exact acquisition attempt interval.
        attempt: AcquisitionIntervalV2,
        /// Explicit assertion that no response bytes entered raw custody.
        raw_custody: FailedAcquisitionCustodyV2,
        /// Exact acquisition failure, including dependent outcome fields.
        failure: AcquisitionFailure,
    },
    /// Acquisition failed in a way distinct from provider non-response.
    AcquisitionFailed {
        /// Exact provider-intake occurrence for the failed attempt.
        provider_intake_id: String,
        /// Exact acquisition attempt interval.
        attempt: AcquisitionIntervalV2,
        /// Explicit assertion that no response bytes entered raw custody.
        raw_custody: FailedAcquisitionCustodyV2,
        /// Exact acquisition failure, including dependent outcome fields.
        failure: AcquisitionFailure,
    },
    /// The configured provider cannot supply the expected input role.
    Unsupported {
        /// Typed, identified unsupported cause.
        unsupported: UnsupportedCauseV2,
    },
}

/// One expected input that produced no received occurrence.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailedInputV2 {
    /// Exact unsatisfied expectation.
    pub expectation_id: String,
    /// Immutable failure occurrence identity.
    pub failure_id: String,
    /// Exact typed failure.
    pub cause: FailedInputCauseV2,
}

/// Complete input accounting for the bounded question.
///
/// Each set-like array is sorted by unsigned UTF-8 bytes of the identity field
/// named by validation. Every expectation has exactly one received occurrence
/// or failed-input occurrence; every received input is exactly admitted or
/// refused; and every admitted input is exactly selected or excluded.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticInputAccountingV2 {
    /// Identified law selecting admitted inputs.
    pub selection_rule: SemanticIdentityV1,
    /// Complete declared denominator.
    pub expected: Vec<ExpectedInputV1>,
    /// All occurrences that entered raw custody.
    pub received: Vec<ReceivedInputV2>,
    /// Received occurrences admitted for semantic use.
    pub admitted: Vec<AdmittedInputV1>,
    /// Received occurrences refused or invalid.
    pub refused: Vec<RefusedInputV2>,
    /// Expected inputs for which no occurrence entered custody.
    pub failed: Vec<FailedInputV2>,
    /// Admitted occurrences excluded by the selection rule.
    pub excluded: Vec<ExcludedInputV1>,
    /// Admitted occurrences selected for evaluation.
    pub selected: Vec<SelectedInputV1>,
}

/// One claim and its exact selected-input, refusal, failure, and state
/// dependency frontier.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticClaimV2 {
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
    /// Exact refused-input carrier identities on which this claim depends.
    pub dependency_refusal_ids: Vec<String>,
    /// Exact failed-input occurrence identities on which this claim depends.
    pub dependency_failure_ids: Vec<String>,
    /// State bindings applicable to this claim.
    pub state_binding_ids: Vec<String>,
    /// Lexicographically ordered distinctions this claim requires.
    pub required_distinctions: Vec<String>,
    /// Claim-local material limitations.
    pub limitations: Vec<String>,
    /// Claim-local explicit nonclaims.
    pub nonclaims: Vec<String>,
}

/// NQ-owned bounded diagnostic outcome with exact refusal and unsupported
/// carriers.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticOutcomeV2 {
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
    /// Exact sorted refusal frontier. Required for `refused`, empty otherwise.
    pub refusals: Vec<GovernedRefusal>,
    /// Exact sorted unsupported frontier. Required for `unsupported`, empty
    /// otherwise.
    pub unsupported: Vec<UnsupportedCauseV2>,
}

/// One immutable bounded NQ diagnostic artifact under the candidate v2
/// contract.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticExecutionV2 {
    /// Exact wire schema.
    pub schema: DiagnosticExecutionSchemaV2,
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
    /// Exact declared profile descriptor identity.
    pub profile: SemanticIdentityV1,
    /// Composite descriptor/protocol/evaluator semantic identity of the
    /// compiled profile.
    pub profile_semantic_id: Sha256Digest,
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
    /// Diagnostic execution start under `execution_clock`.
    pub started_at: DateTime<Utc>,
    /// Diagnostic derivation completion under `execution_clock`.
    pub completed_at: DateTime<Utc>,
    /// NQ-owned interval for the bounded acquisition attempt.
    pub attempt_interval: AcquisitionIntervalV2,
    /// Complete input accounting.
    pub inputs: DiagnosticInputAccountingV2,
    /// Per-question state bindings.
    pub state_bindings: Vec<DiagnosticStateBindingV1>,
    /// Exact exported claim surface.
    pub claims: Vec<DiagnosticClaimV2>,
    /// Claim that supplies the bounded top-level outcome, when one was
    /// derived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_claim_id: Option<String>,
    /// Bounded diagnostic outcome.
    pub outcome: DiagnosticOutcomeV2,
    /// Artifact-wide material limitations.
    pub limitations: Vec<DiagnosticLimitationV1>,
    /// Explicit statements this artifact does not establish.
    pub nonclaims: Vec<String>,
}

#[derive(Serialize)]
struct DiagnosticExecutionV2Preimage<'a> {
    schema: DiagnosticExecutionSchemaV2,
    canonicalization: &'a SemanticIdentityV1,
    producer: &'a DiagnosticProducerV1,
    request_id: &'a DiagnosticRequestId,
    run_id: &'a DiagnosticRunId,
    question: &'a SemanticIdentityV1,
    subject: &'a DiagnosticSubjectV1,
    profile: &'a SemanticIdentityV1,
    profile_semantic_id: &'a Sha256Digest,
    vantage: &'a SemanticIdentityV1,
    state_model: &'a SemanticIdentityV1,
    evaluator: &'a SemanticIdentityV1,
    threshold_policy: &'a SemanticIdentityV1,
    projection: &'a DiagnosticProjectionV1,
    execution_clock: &'a SemanticIdentityV1,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    attempt_interval: &'a AcquisitionIntervalV2,
    inputs: &'a DiagnosticInputAccountingV2,
    state_bindings: &'a [DiagnosticStateBindingV1],
    claims: &'a [DiagnosticClaimV2],
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_claim_id: Option<&'a str>,
    outcome: &'a DiagnosticOutcomeV2,
    limitations: &'a [DiagnosticLimitationV1],
    nonclaims: &'a [String],
}

impl DiagnosticExecutionV2 {
    fn preimage(&self) -> DiagnosticExecutionV2Preimage<'_> {
        DiagnosticExecutionV2Preimage {
            schema: self.schema,
            canonicalization: &self.canonicalization,
            producer: &self.producer,
            request_id: &self.request_id,
            run_id: &self.run_id,
            question: &self.question,
            subject: &self.subject,
            profile: &self.profile,
            profile_semantic_id: &self.profile_semantic_id,
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
    /// Returns an error if canonical preimage serialization fails.
    pub fn computed_artifact_id(&self) -> Result<DiagnosticArtifactId, DiagnosticExecutionError> {
        Ok(DiagnosticArtifactId(semantic_digest(&self.preimage())?))
    }

    /// Validates the closed v2 contract and self-identity.
    ///
    /// This establishes structural and contract-semantic conformance only. It
    /// does not authenticate the producer, qualify a clock for a consumer,
    /// grant reliance, authorize anything, or perform action.
    ///
    /// # Errors
    ///
    /// Returns an invariant or canonicalization error when any closed-contract
    /// rule or the self-identity check fails.
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
    /// Returns an error if contract validation or canonical serialization
    /// fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiagnosticExecutionError> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Decodes only unique canonical bytes for a valid v2 artifact.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, non-canonical, unknown, or
    /// contract-invalid input.
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

fn validate_interval(interval: &AcquisitionIntervalV2) -> Result<(), DiagnosticExecutionError> {
    require_identity("acquisition.clock", &interval.clock)?;
    if interval.started_at > interval.ended_at {
        return invariant("acquisition interval starts after it ends");
    }
    match &interval.qualification {
        ClockQualificationV2::Bounded { basis, .. } => {
            require_identity("acquisition.qualification.basis", basis)?;
        }
        ClockQualificationV2::Unqualified { code, detail } => {
            require_token("acquisition.qualification.code", code)?;
            require_token("acquisition.qualification.detail", detail)?;
        }
    }
    Ok(())
}

fn validate_inputs(artifact: &DiagnosticExecutionV2) -> Result<(), DiagnosticExecutionError> {
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
    let mut provider_intake_ids = BTreeSet::new();
    let mut response_count: BTreeMap<&str, usize> = BTreeMap::new();
    for item in &inputs.received {
        require_token("input_id", &item.input_id)?;
        require_token("received.expectation_id", &item.expectation_id)?;
        require_token("received.provider_intake_id", &item.provider_intake_id)?;
        if !expected.contains(item.expectation_id.as_str()) {
            return invariant("received input references an unknown expectation");
        }
        insert_unique(
            &mut provider_intake_ids,
            &item.provider_intake_id,
            "provider_intake_id",
        )?;
        require_identity("received.capture_policy", &item.capture_policy)?;
        validate_interval(&item.acquisition)?;
        validate_contributing_attempt_interval(
            &item.acquisition,
            &artifact.attempt_interval,
            "received",
        )?;
        if item.received_at < item.acquisition.ended_at || item.received_at > artifact.completed_at
        {
            return invariant(
                "received_at falls before acquisition completion or after diagnostic completion",
            );
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
    let mut unsupported_ids = BTreeSet::new();
    for item in &inputs.failed {
        require_token("failed.expectation_id", &item.expectation_id)?;
        require_token("failure_id", &item.failure_id)?;
        if !expected.contains(item.expectation_id.as_str()) {
            return invariant("failed input references an unknown expectation");
        }
        insert_unique(
            &mut failed_expectations,
            &item.expectation_id,
            "failed expectation",
        )?;
        insert_unique(&mut failure_ids, &item.failure_id, "failure_id")?;
        validate_failed_input_cause(
            &item.cause,
            &item.failure_id,
            &artifact.attempt_interval,
            &mut provider_intake_ids,
            &mut unsupported_ids,
        )?;
        *response_count.entry(&item.expectation_id).or_default() += 1;
    }
    for expectation in &expected {
        if response_count.get(expectation).copied() != Some(1) {
            return invariant(
                "each expectation must have exactly one received occurrence or failure",
            );
        }
    }
    validate_admission_partition(artifact, &received)
}

fn validate_failed_input_cause<'a>(
    cause: &'a FailedInputCauseV2,
    failure_id: &str,
    diagnostic_attempt: &AcquisitionIntervalV2,
    provider_intake_ids: &mut BTreeSet<&'a str>,
    unsupported_ids: &mut BTreeSet<&'a str>,
) -> Result<(), DiagnosticExecutionError> {
    match cause {
        FailedInputCauseV2::Missing { reason } => {
            require_token("failed.reason", reason)?;
        }
        FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id,
            attempt,
            failure,
            ..
        } => {
            require_token("failed.provider_intake_id", provider_intake_id)?;
            insert_unique(
                provider_intake_ids,
                provider_intake_id,
                "provider_intake_id",
            )?;
            validate_interval(attempt)?;
            validate_contributing_attempt_interval(attempt, diagnostic_attempt, "failed")?;
            failure
                .validate()
                .map_err(|error| DiagnosticExecutionError::Invariant(error.to_string()))?;
            if !matches!(
                failure.class,
                AcquisitionFailureClass::Timeout
                    | AcquisitionFailureClass::Eof
                    | AcquisitionFailureClass::HelperExited
                    | AcquisitionFailureClass::Disconnect
            ) {
                return invariant(
                    "provider_no_response carries an acquisition-failure class that observed a different failure mode",
                );
            }
        }
        FailedInputCauseV2::AcquisitionFailed {
            provider_intake_id,
            attempt,
            failure,
            ..
        } => {
            require_token("failed.provider_intake_id", provider_intake_id)?;
            insert_unique(
                provider_intake_ids,
                provider_intake_id,
                "provider_intake_id",
            )?;
            validate_interval(attempt)?;
            validate_contributing_attempt_interval(attempt, diagnostic_attempt, "failed")?;
            failure
                .validate()
                .map_err(|error| DiagnosticExecutionError::Invariant(error.to_string()))?;
            if matches!(
                failure.class,
                AcquisitionFailureClass::Timeout
                    | AcquisitionFailureClass::Eof
                    | AcquisitionFailureClass::HelperExited
                    | AcquisitionFailureClass::Disconnect
            ) {
                return invariant(
                    "acquisition_failed carries a provider-no-response failure class",
                );
            }
        }
        FailedInputCauseV2::Unsupported { unsupported } => {
            validate_unsupported_cause(unsupported)?;
            insert_unique(
                unsupported_ids,
                &unsupported.unsupported_id,
                "unsupported_id",
            )?;
            match &unsupported.origin {
                UnsupportedOriginV2::ExpectedInput {
                    failure_id: referenced,
                } if referenced == failure_id => {}
                UnsupportedOriginV2::ExpectedInput { .. } => {
                    return invariant("unsupported input cause references a different failure_id");
                }
                UnsupportedOriginV2::DiagnosticProfile => {
                    return invariant(
                        "failed-input unsupported cause cannot claim diagnostic-profile scope",
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_contributing_attempt_interval(
    attempt: &AcquisitionIntervalV2,
    diagnostic_attempt: &AcquisitionIntervalV2,
    kind: &str,
) -> Result<(), DiagnosticExecutionError> {
    if attempt.clock != diagnostic_attempt.clock {
        return invariant(format!(
            "{kind} acquisition attempt does not use the diagnostic execution clock"
        ));
    }
    if attempt.qualification != diagnostic_attempt.qualification {
        return invariant(format!(
            "{kind} acquisition attempt changes the diagnostic clock qualification"
        ));
    }
    if attempt.started_at < diagnostic_attempt.started_at
        || attempt.ended_at > diagnostic_attempt.ended_at
    {
        return invariant(format!(
            "{kind} acquisition attempt falls outside the diagnostic attempt"
        ));
    }
    Ok(())
}

fn validate_unsupported_cause(
    unsupported: &UnsupportedCauseV2,
) -> Result<(), DiagnosticExecutionError> {
    require_token("unsupported.unsupported_id", &unsupported.unsupported_id)?;
    require_identity("unsupported.capability", &unsupported.capability)?;
    require_token("unsupported.detail", &unsupported.detail)?;
    match &unsupported.origin {
        UnsupportedOriginV2::DiagnosticProfile => {}
        UnsupportedOriginV2::ExpectedInput { failure_id } => {
            require_token("unsupported.failure_id", failure_id)?;
        }
    }
    Ok(())
}

fn validate_admission_partition(
    artifact: &DiagnosticExecutionV2,
    received: &BTreeMap<&str, &ReceivedInputV2>,
) -> Result<(), DiagnosticExecutionError> {
    let inputs = &artifact.inputs;
    let expected: BTreeMap<&str, &ExpectedInputV1> = inputs
        .expected
        .iter()
        .map(|item| (item.expectation_id.as_str(), item))
        .collect();
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
    let mut refused = BTreeMap::new();
    let mut refusal_ids = BTreeSet::new();
    for item in &inputs.refused {
        require_token("refused.input_id", &item.input_id)?;
        item.refusal
            .validate_transport()
            .map_err(|error| DiagnosticExecutionError::Invariant(error.to_string()))?;
        let occurrence = received.get(item.input_id.as_str()).ok_or_else(|| {
            DiagnosticExecutionError::Invariant(
                "refused input references an unknown received input".to_owned(),
            )
        })?;
        let expectation = expected
            .get(occurrence.expectation_id.as_str())
            .expect("received inputs were checked against expected");
        validate_input_refusal_binding(artifact, item, &expectation.role)?;
        if refused.insert(item.input_id.as_str(), item).is_some() {
            return invariant("duplicate refused input");
        }
        insert_unique(
            &mut refusal_ids,
            item.refusal.refusal_id.as_str(),
            "refusal_id",
        )?;
    }
    for input_id in received.keys() {
        let outcomes = usize::from(admitted.contains_key(input_id))
            + usize::from(refused.contains_key(input_id));
        if outcomes != 1 {
            return invariant("each received input must be exactly admitted or refused");
        }
    }
    validate_selection_partition(inputs, &admitted, received)
}

fn validate_input_refusal_binding(
    artifact: &DiagnosticExecutionV2,
    input: &RefusedInputV2,
    expected_role: &str,
) -> Result<(), DiagnosticExecutionError> {
    match (&input.refusal.origin, &input.profile_binding) {
        (
            GovernedRefusalOrigin::Profile(profile),
            Some(ProfileRefusalBindingV2::ArtifactProfile),
        ) => {
            if profile.profile_semantic_id.as_str() != artifact.profile_semantic_id.as_str()
                || profile.refusal.profile.id != artifact.profile.id
                || profile.refusal.profile.version.to_string() != artifact.profile.version
            {
                return invariant(
                    "artifact-profile input refusal disagrees with artifact profile identity",
                );
            }
            if profile.refusal.boundary == nq_profiles::RefusalBoundary::Detector {
                return invariant(
                    "detector refusal cannot be represented as a refused input from the artifact profile",
                );
            }
        }
        (
            GovernedRefusalOrigin::Profile(profile),
            Some(ProfileRefusalBindingV2::ForeignInputRole { role }),
        ) => {
            require_token("refused.profile_binding.role", role)?;
            if role != expected_role {
                return invariant(
                    "foreign-profile refusal role differs from the expected input role",
                );
            }
            if profile.profile_semantic_id.as_str() == artifact.profile_semantic_id.as_str()
                && profile.refusal.profile.id == artifact.profile.id
                && profile.refusal.profile.version.to_string() == artifact.profile.version
            {
                return invariant(
                    "artifact-profile refusal is mislabeled as a foreign-profile input role",
                );
            }
        }
        (GovernedRefusalOrigin::Profile(_), None) => {
            return invariant("profile-origin input refusal has no explicit profile binding");
        }
        (_, Some(_)) => {
            return invariant("non-profile input refusal carries a profile binding");
        }
        (_, None) => {}
    }
    Ok(())
}

fn validate_selection_partition(
    inputs: &DiagnosticInputAccountingV2,
    admitted: &BTreeMap<&str, &AdmittedInputV1>,
    received: &BTreeMap<&str, &ReceivedInputV2>,
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
    inputs: &DiagnosticInputAccountingV2,
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
fn validate_claims(artifact: &DiagnosticExecutionV2) -> Result<(), DiagnosticExecutionError> {
    let selected: BTreeMap<&str, &SelectedInputV1> = artifact
        .inputs
        .selected
        .iter()
        .map(|item| (item.input_id.as_str(), item))
        .collect();
    let refusal_ids: BTreeSet<&str> = artifact
        .inputs
        .refused
        .iter()
        .map(|item| item.refusal.refusal_id.as_str())
        .collect();
    let failure_ids: BTreeSet<&str> = artifact
        .inputs
        .failed
        .iter()
        .map(|item| item.failure_id.as_str())
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
        if claim.dependency_input_ids.is_empty()
            && claim.dependency_refusal_ids.is_empty()
            && claim.dependency_failure_ids.is_empty()
        {
            return invariant("claim has no exact dependency");
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
            "claim.dependency_refusal_ids",
            claim.dependency_refusal_ids.iter().map(String::as_str),
        )?;
        let mut refusal_dependencies = BTreeSet::new();
        for refusal_id in &claim.dependency_refusal_ids {
            if !refusal_ids.contains(refusal_id.as_str()) {
                return invariant("claim references an unknown refused-input carrier");
            }
            insert_unique(
                &mut refusal_dependencies,
                refusal_id,
                "claim refusal dependency",
            )?;
        }
        require_utf8_byte_sorted_unique(
            "claim.dependency_failure_ids",
            claim.dependency_failure_ids.iter().map(String::as_str),
        )?;
        let mut failure_dependencies = BTreeSet::new();
        for failure_id in &claim.dependency_failure_ids {
            if !failure_ids.contains(failure_id.as_str()) {
                return invariant("claim references an unknown failed-input occurrence");
            }
            insert_unique(
                &mut failure_dependencies,
                failure_id,
                "claim failure dependency",
            )?;
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

#[allow(clippy::too_many_lines)]
fn validate_outcome(artifact: &DiagnosticExecutionV2) -> Result<(), DiagnosticExecutionError> {
    let outcome = &artifact.outcome;
    require_token("outcome.summary", &outcome.summary)?;
    require_utf8_byte_sorted_unique(
        "outcome.refusals",
        outcome
            .refusals
            .iter()
            .map(|refusal| refusal.refusal_id.as_str()),
    )?;
    for refusal in &outcome.refusals {
        refusal
            .validate_transport()
            .map_err(|error| DiagnosticExecutionError::Invariant(error.to_string()))?;
    }
    require_utf8_byte_sorted_unique(
        "outcome.unsupported",
        outcome
            .unsupported
            .iter()
            .map(|cause| cause.unsupported_id.as_str()),
    )?;
    for unsupported in &outcome.unsupported {
        validate_unsupported_cause(unsupported)?;
    }
    match outcome.derivation {
        DiagnosticDerivationV1::Refused => {
            if outcome.refusals.is_empty() {
                return invariant("refused outcome has no exact governed refusal");
            }
            if !outcome.unsupported.is_empty() {
                return invariant("refused outcome also carries unsupported causes");
            }
            validate_outcome_refusal_correspondence(artifact)?;
        }
        DiagnosticDerivationV1::Unsupported => {
            if outcome.unsupported.is_empty() {
                return invariant("unsupported outcome has no typed unsupported cause");
            }
            if !outcome.refusals.is_empty() {
                return invariant("unsupported outcome also carries refusals");
            }
            validate_outcome_unsupported_correspondence(artifact)?;
        }
        DiagnosticDerivationV1::Completed | DiagnosticDerivationV1::Partial => {
            if !outcome.refusals.is_empty() {
                return invariant("non-refused outcome carries a refusal frontier");
            }
            if !outcome.unsupported.is_empty() {
                return invariant("non-unsupported outcome carries an unsupported frontier");
            }
        }
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

fn validate_outcome_refusal_correspondence(
    artifact: &DiagnosticExecutionV2,
) -> Result<(), DiagnosticExecutionError> {
    let input_refusals: BTreeMap<&str, &GovernedRefusal> = artifact
        .inputs
        .refused
        .iter()
        .map(|input| (input.refusal.refusal_id.as_str(), &input.refusal))
        .collect();
    if !input_refusals.is_empty() {
        let outcome_refusals: BTreeMap<&str, &GovernedRefusal> = artifact
            .outcome
            .refusals
            .iter()
            .map(|refusal| (refusal.refusal_id.as_str(), refusal))
            .collect();
        if input_refusals != outcome_refusals {
            return invariant(
                "received-input refusal outcome must preserve the complete exact refusal frontier",
            );
        }
        return Ok(());
    }

    if artifact.outcome.refusals.len() != 1 {
        return invariant(
            "detector refusal without refused inputs must carry exactly one governed refusal",
        );
    }
    let refusal = &artifact.outcome.refusals[0];
    let GovernedRefusalOrigin::Profile(profile) = &refusal.origin else {
        return invariant(
            "diagnostic refusal without a refused input must be profile-origin detector refusal",
        );
    };
    if profile.profile_semantic_id.as_str() != artifact.profile_semantic_id.as_str()
        || profile.refusal.profile.id != artifact.profile.id
        || profile.refusal.profile.version.to_string() != artifact.profile.version
        || profile.refusal.boundary != nq_profiles::RefusalBoundary::Detector
        || profile.refusal.code != nq_profiles::ProfileRefusalCode::CannotEvaluate
        || profile.refusal.message != artifact.outcome.summary
    {
        return invariant(
            "detector refusal disagrees with artifact profile, semantic identity, boundary, code, or summary",
        );
    }
    Ok(())
}

fn validate_outcome_unsupported_correspondence(
    artifact: &DiagnosticExecutionV2,
) -> Result<(), DiagnosticExecutionError> {
    let input_unsupported: BTreeMap<&str, &UnsupportedCauseV2> = artifact
        .inputs
        .failed
        .iter()
        .filter_map(|input| match &input.cause {
            FailedInputCauseV2::Unsupported { unsupported } => {
                Some((unsupported.unsupported_id.as_str(), unsupported))
            }
            _ => None,
        })
        .collect();
    if !input_unsupported.is_empty() {
        let outcome_unsupported: BTreeMap<&str, &UnsupportedCauseV2> = artifact
            .outcome
            .unsupported
            .iter()
            .map(|cause| (cause.unsupported_id.as_str(), cause))
            .collect();
        if input_unsupported != outcome_unsupported {
            return invariant(
                "unsupported outcome must preserve the complete exact input-unsupported frontier",
            );
        }
        return Ok(());
    }

    if artifact.outcome.unsupported.len() != 1 {
        return invariant(
            "profile-level unsupported outcome must carry exactly one identified cause",
        );
    }
    let unsupported = &artifact.outcome.unsupported[0];
    if unsupported.origin != UnsupportedOriginV2::DiagnosticProfile
        || unsupported.code != UnsupportedCodeV2::QuestionUnsupported
        || unsupported.capability != artifact.question
    {
        return invariant(
            "profile-level unsupported cause disagrees with the bounded question identity",
        );
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
    use std::collections::BTreeMap;

    use chrono::TimeZone as _;
    use nq_profiles::ProfileModule as _;
    use nq_protocol::{InstanceId, Refusal, RefusalBoundary, RefusalCode};
    use serde_json::json;

    use super::*;
    use crate::{
        diagnostic_execution::{
            DiagnosticLimitationKindV1, NormalizedArtifactId, OmittedDistinctionV1,
            ProjectedArtifactId,
        },
        engine::{AcquisitionRefusal, GovernedRefusal},
        runner::AcquisitionOutcome,
    };

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
        Utc.with_ymd_and_hms(2026, 7, 28, 18, 0, second)
            .single()
            .expect("valid fixture time")
    }

    fn unqualified_interval(start: u32, end: u32) -> AcquisitionIntervalV2 {
        AcquisitionIntervalV2 {
            started_at: time(start),
            ended_at: time(end),
            clock: identity("clock:local-realtime"),
            qualification: ClockQualificationV2::Unqualified {
                code: "absolute_clock_quality_unqualified".to_owned(),
                detail: "no finite UTC-error bound was established".to_owned(),
            },
        }
    }

    fn profile_identity() -> (SemanticIdentityV1, Sha256Digest) {
        let descriptor = nq_profiles::host::MODULE.descriptor();
        let descriptor_digest = descriptor.digest().expect("profile descriptor digest");
        let semantic =
            nq_profiles::profile_semantic_id(descriptor).expect("profile semantic identity");
        (
            SemanticIdentityV1 {
                id: descriptor.profile.id.clone(),
                version: descriptor.profile.version.to_string(),
                digest: Sha256Digest::parse(descriptor_digest.as_str().to_owned())
                    .expect("typed descriptor digest"),
            },
            Sha256Digest::parse(semantic.as_str().to_owned()).expect("typed semantic id"),
        )
    }

    fn received() -> ReceivedInputV2 {
        ReceivedInputV2 {
            input_id: "input:001".to_owned(),
            expectation_id: "expected:host-snapshot".to_owned(),
            provider_intake_id: "intake:001".to_owned(),
            raw_artifact_id: RawArtifactId(digest("raw")),
            capture_mode: RawCaptureModeV1::ExactSource,
            capture_policy: identity("capture:exact"),
            availability_at_derivation: EvidenceAvailabilityV1::Online,
            acquisition: unqualified_interval(1, 2),
            received_at: time(3),
        }
    }

    fn completed() -> DiagnosticExecutionV2 {
        let (profile, profile_semantic_id) = profile_identity();
        let projected = ProjectedArtifactId(digest("projected"));
        let mut artifact = DiagnosticExecutionV2 {
            schema: DiagnosticExecutionSchemaV2::V2,
            artifact_id: DiagnosticArtifactId(digest("placeholder")),
            canonicalization: diagnostic_canonicalization_identity()
                .expect("canonicalization identity"),
            producer: DiagnosticProducerV1 {
                node_id: "nq-node:fixture".to_owned(),
                build: identity("build:nq"),
                cohort: identity("cohort:host"),
            },
            request_id: DiagnosticRequestId("request:001".to_owned()),
            run_id: DiagnosticRunId("run:001".to_owned()),
            question: identity("nq.host.load_pressure"),
            subject: DiagnosticSubjectV1 {
                id: "host:fixture".to_owned(),
                scope: identity("scope:host"),
            },
            profile,
            profile_semantic_id,
            vantage: identity("vantage:host-local"),
            state_model: identity("state-model:subject"),
            evaluator: identity("evaluator:nq"),
            threshold_policy: identity("threshold:load"),
            projection: DiagnosticProjectionV1 {
                identity: identity("projection:load"),
                omitted_distinctions: Vec::<OmittedDistinctionV1>::new(),
            },
            execution_clock: identity("clock:local-realtime"),
            started_at: time(0),
            completed_at: time(4),
            attempt_interval: unqualified_interval(0, 4),
            inputs: DiagnosticInputAccountingV2 {
                selection_rule: identity("selection:fresh-single"),
                expected: vec![ExpectedInputV1 {
                    expectation_id: "expected:host-snapshot".to_owned(),
                    role: "host_snapshot".to_owned(),
                    required: true,
                }],
                received: vec![received()],
                admitted: vec![AdmittedInputV1 {
                    input_id: "input:001".to_owned(),
                    admission_rule: identity("admission:host"),
                    normalized_artifact_id: NormalizedArtifactId(digest("normalized")),
                    normalization_rule: identity("normalization:host"),
                    projected_artifact_id: projected.clone(),
                    projection_rule: identity("projection-rule:host"),
                }],
                refused: vec![],
                failed: vec![],
                excluded: vec![],
                selected: vec![SelectedInputV1 {
                    input_id: "input:001".to_owned(),
                    projected_artifact_id: projected,
                    role: "host_snapshot".to_owned(),
                }],
            },
            state_bindings: vec![DiagnosticStateBindingV1 {
                binding_id: "state:subject".to_owned(),
                kind: "subject_identity".to_owned(),
                value: "host:fixture".to_owned(),
                supporting_input_ids: vec!["input:001".to_owned()],
            }],
            claims: vec![DiagnosticClaimV2 {
                claim_id: "claim:load-pressure".to_owned(),
                proposition: "bounded load pressure is explicitly absent".to_owned(),
                status: DiagnosticClaimStatusV1::Established,
                condition_effect: Some(DiagnosticConditionV1::ExplicitlyAbsent),
                dependency_input_ids: vec!["input:001".to_owned()],
                dependency_refusal_ids: vec![],
                dependency_failure_ids: vec![],
                state_binding_ids: vec!["state:subject".to_owned()],
                required_distinctions: vec!["subject_identity".to_owned()],
                limitations: vec![],
                nonclaims: vec!["no causal explanation is established".to_owned()],
            }],
            primary_claim_id: Some("claim:load-pressure".to_owned()),
            outcome: DiagnosticOutcomeV2 {
                derivation: DiagnosticDerivationV1::Completed,
                condition: DiagnosticConditionV1::ExplicitlyAbsent,
                coherence: DiagnosticCoherenceV1::JointlyEstablished,
                coverage: DiagnosticCoverageV1::Complete,
                summary: "bounded load pressure is absent".to_owned(),
                refusals: vec![],
                unsupported: vec![],
            },
            limitations: vec![DiagnosticLimitationV1 {
                kind: DiagnosticLimitationKindV1::Other,
                code: "boot_state_unbound".to_owned(),
                detail: "boot generation is not established".to_owned(),
            }],
            nonclaims: vec![
                "this artifact grants no authorization".to_owned(),
                "this artifact grants no consumer reliance".to_owned(),
            ],
        };
        artifact.artifact_id = artifact.computed_artifact_id().expect("artifact id");
        artifact
    }

    fn detector_refusal() -> GovernedRefusal {
        let semantic = nq_profiles::profile_semantic_id(nq_profiles::host::MODULE.descriptor())
            .expect("profile semantic identity");
        GovernedRefusal::profile(
            "refusal:detector:001".to_owned(),
            semantic,
            nq_profiles::ProfileRefusal {
                instance_id: "host-witness:fixture".to_owned(),
                profile: nq_profiles::host::MODULE.descriptor().profile.clone(),
                boundary: nq_profiles::RefusalBoundary::Detector,
                code: nq_profiles::ProfileRefusalCode::CannotEvaluate,
                message: "complete load testimony is unavailable".to_owned(),
                details: BTreeMap::from([
                    ("expected_coverage".to_owned(), "load".to_owned()),
                    ("observed_coverage".to_owned(), "identity,uptime".to_owned()),
                ]),
            },
        )
    }

    fn helper_refusal_named(refusal_id: &str, instance_id: &str) -> GovernedRefusal {
        GovernedRefusal::helper(
            refusal_id.to_owned(),
            Refusal {
                responsible_instance_id: InstanceId::new(instance_id).expect("valid instance"),
                boundary: RefusalBoundary::Collection,
                code: RefusalCode::CollectionFailed,
                message: "provider could not collect the required input".to_owned(),
                retriable: true,
                details: json!({"errno": "EAGAIN", "phase": "snapshot"}),
            },
        )
    }

    fn helper_refusal() -> GovernedRefusal {
        helper_refusal_named("refusal:input:001", "host-witness:fixture")
    }

    fn reseal(artifact: &mut DiagnosticExecutionV2) {
        artifact.artifact_id = artifact.computed_artifact_id().expect("artifact id");
    }

    #[test]
    fn completed_artifact_round_trips_with_unqualified_clock_explicit() {
        let artifact = completed();
        let bytes = artifact.canonical_bytes().expect("canonical v2 artifact");
        let reopened =
            DiagnosticExecutionV2::decode_canonical(&bytes).expect("strict v2 reopening");
        assert_eq!(reopened, artifact);
        assert!(matches!(
            reopened.attempt_interval.qualification,
            ClockQualificationV2::Unqualified { .. }
        ));
        assert!(
            !bytes
                .windows(b"clock_uncertainty_ms".len())
                .any(|window| window == b"clock_uncertainty_ms")
        );
    }

    #[test]
    fn bounded_clock_requires_an_identified_basis() {
        let mut artifact = completed();
        artifact.attempt_interval.qualification = ClockQualificationV2::Bounded {
            maximum_error_ms: 10,
            basis: SemanticIdentityV1 {
                id: String::new(),
                version: "1".to_owned(),
                digest: digest("clock-basis"),
            },
        };
        reseal(&mut artifact);
        assert!(matches!(
            artifact.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("qualification.basis.id")
        ));
    }

    #[test]
    fn received_input_custody_must_follow_its_qualified_attempt() {
        let mut before_acquisition = completed();
        before_acquisition.inputs.received[0].received_at = time(1);
        reseal(&mut before_acquisition);
        assert!(matches!(
            before_acquisition.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("received_at falls before acquisition completion")
        ));

        let mut changed_qualification = completed();
        changed_qualification.inputs.received[0]
            .acquisition
            .qualification = ClockQualificationV2::Bounded {
            maximum_error_ms: 10,
            basis: identity("clock-qualification:substituted"),
        };
        reseal(&mut changed_qualification);
        assert!(matches!(
            changed_qualification.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("changes the diagnostic clock qualification")
        ));
    }

    #[test]
    fn detector_refusal_retains_exact_governed_carrier() {
        let mut artifact = completed();
        let refusal = detector_refusal();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Partial,
            summary: "complete load testimony is unavailable".to_owned(),
            refusals: vec![refusal.clone()],
            unsupported: vec![],
        };
        reseal(&mut artifact);

        let bytes = artifact
            .canonical_bytes()
            .expect("canonical refusal artifact");
        let reopened =
            DiagnosticExecutionV2::decode_canonical(&bytes).expect("strict refusal reopening");
        assert_eq!(reopened.outcome.refusals, vec![refusal]);
        let GovernedRefusalOrigin::Profile(profile) = &reopened.outcome.refusals[0].origin else {
            panic!("detector refusal remains profile-origin");
        };
        assert_eq!(
            profile.refusal.boundary,
            nq_profiles::RefusalBoundary::Detector
        );
        assert_eq!(
            profile.refusal.details["observed_coverage"],
            "identity,uptime"
        );
    }

    #[test]
    fn same_code_detector_refusals_with_different_details_remain_distinct() {
        let mut first = completed();
        let first_refusal = detector_refusal();
        first.claims.clear();
        first.primary_claim_id = None;
        first.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Partial,
            summary: "complete load testimony is unavailable".to_owned(),
            refusals: vec![first_refusal],
            unsupported: vec![],
        };
        reseal(&mut first);

        let mut second = first.clone();
        let GovernedRefusal {
            origin: GovernedRefusalOrigin::Profile(profile),
            ..
        } = &mut second.outcome.refusals[0]
        else {
            panic!("profile refusal fixture");
        };
        profile
            .refusal
            .details
            .insert("observed_coverage".to_owned(), "identity".to_owned());
        reseal(&mut second);

        assert_ne!(first.artifact_id, second.artifact_id);
        assert_ne!(
            first.canonical_bytes().expect("first bytes"),
            second.canonical_bytes().expect("second bytes")
        );
    }

    #[test]
    fn received_input_refusal_is_not_reclassified_as_acquisition_failure() {
        let mut artifact = completed();
        let refusal = helper_refusal();
        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        artifact.inputs.refused = vec![RefusedInputV2 {
            input_id: "input:001".to_owned(),
            refusal: refusal.clone(),
            profile_binding: None,
        }];
        artifact.state_bindings.clear();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "required received testimony was refused".to_owned(),
            refusals: vec![refusal.clone()],
            unsupported: vec![],
        };
        reseal(&mut artifact);

        artifact.validate().expect("exact input refusal is valid");
        assert_eq!(artifact.outcome.refusals, vec![refusal]);
        assert!(artifact.inputs.failed.is_empty());

        let mut substituted = artifact.clone();
        substituted.outcome.refusals = vec![helper_refusal()];
        substituted.outcome.refusals[0].refusal_id = "refusal:substituted".to_owned();
        reseal(&mut substituted);
        assert!(matches!(
            substituted.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("complete exact refusal frontier")
        ));
    }

    #[test]
    fn multiple_received_input_refusals_are_preserved_without_selection() {
        let mut artifact = completed();
        artifact.inputs.expected.push(ExpectedInputV1 {
            expectation_id: "expected:remote-snapshot".to_owned(),
            role: "remote_snapshot".to_owned(),
            required: true,
        });
        let mut second_received = received();
        second_received.input_id = "input:002".to_owned();
        second_received.expectation_id = "expected:remote-snapshot".to_owned();
        second_received.provider_intake_id = "intake:002".to_owned();
        second_received.raw_artifact_id = RawArtifactId(digest("raw:002"));
        artifact.inputs.received.push(second_received);
        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        let first = helper_refusal_named("refusal:input:001", "host-witness:fixture");
        let second = helper_refusal_named("refusal:input:002", "remote-witness:fixture");
        artifact.inputs.refused = vec![
            RefusedInputV2 {
                input_id: "input:001".to_owned(),
                refusal: first.clone(),
                profile_binding: None,
            },
            RefusedInputV2 {
                input_id: "input:002".to_owned(),
                refusal: second.clone(),
                profile_binding: None,
            },
        ];
        artifact.state_bindings.clear();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "both required inputs were refused".to_owned(),
            refusals: vec![first, second],
            unsupported: vec![],
        };
        reseal(&mut artifact);
        artifact
            .validate()
            .expect("complete sorted refusal frontier is valid");

        let mut dropped = artifact.clone();
        dropped.outcome.refusals.pop();
        reseal(&mut dropped);
        assert!(matches!(
            dropped.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("complete exact refusal frontier")
        ));
    }

    #[test]
    fn foreign_profile_input_refusal_is_role_bound_and_historically_reopenable() {
        let mut artifact = completed();
        let mut refusal = detector_refusal();
        refusal.refusal_id = "refusal:foreign:001".to_owned();
        let GovernedRefusalOrigin::Profile(profile) = &mut refusal.origin else {
            panic!("profile refusal fixture");
        };
        profile.refusal.profile = nq_profiles::ProfileKey::new("retired.foreign.profile", 7);
        profile.refusal.boundary = nq_profiles::RefusalBoundary::Report;
        profile.refusal.code = nq_profiles::ProfileRefusalCode::InvalidPayload;
        profile.refusal.message = "foreign input report was invalid".to_owned();

        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        artifact.inputs.refused = vec![RefusedInputV2 {
            input_id: "input:001".to_owned(),
            refusal: refusal.clone(),
            profile_binding: Some(ProfileRefusalBindingV2::ForeignInputRole {
                role: "host_snapshot".to_owned(),
            }),
        }];
        artifact.state_bindings.clear();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "foreign profile input was refused".to_owned(),
            refusals: vec![refusal],
            unsupported: vec![],
        };
        reseal(&mut artifact);

        let bytes = artifact
            .canonical_bytes()
            .expect("retired foreign profile remains transport-valid");
        DiagnosticExecutionV2::decode_canonical(&bytes)
            .expect("historical reopening does not consult current catalog");

        let mut unbound = artifact;
        unbound.inputs.refused[0].profile_binding = None;
        reseal(&mut unbound);
        assert!(matches!(
            unbound.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("no explicit profile binding")
        ));
    }

    #[test]
    fn retained_acquisition_failure_bytes_use_received_and_refused_custody() {
        let mut artifact = completed();
        let failure =
            AcquisitionFailure::from_outcome(AcquisitionOutcome::ExitNonzero { code: Some(23) })
                .expect("exit failure");
        let refusal = GovernedRefusal::acquisition(
            "refusal:acquisition:001".to_owned(),
            AcquisitionRefusal {
                responsible_instance_id: "host-witness:fixture".to_owned(),
                failure,
            },
        );
        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        artifact.inputs.refused = vec![RefusedInputV2 {
            input_id: "input:001".to_owned(),
            refusal: refusal.clone(),
            profile_binding: None,
        }];
        artifact.state_bindings.clear();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "retained partial response failed acquisition".to_owned(),
            refusals: vec![refusal],
            unsupported: vec![],
        };
        reseal(&mut artifact);
        artifact
            .validate()
            .expect("retained bytes remain a received occurrence");
        assert_eq!(artifact.inputs.received.len(), 1);
        assert!(artifact.inputs.failed.is_empty());
    }

    fn failed_artifact(cause: FailedInputCauseV2) -> DiagnosticExecutionV2 {
        let mut artifact = completed();
        artifact.inputs.received.clear();
        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        artifact.inputs.failed = vec![FailedInputV2 {
            expectation_id: "expected:host-snapshot".to_owned(),
            failure_id: "failure:001".to_owned(),
            cause,
        }];
        artifact.state_bindings.clear();
        artifact.claims = vec![DiagnosticClaimV2 {
            claim_id: "claim:provider-testimony".to_owned(),
            proposition: "required provider testimony is available".to_owned(),
            status: DiagnosticClaimStatusV1::Unknown,
            condition_effect: Some(DiagnosticConditionV1::Unresolved),
            dependency_input_ids: vec![],
            dependency_refusal_ids: vec![],
            dependency_failure_ids: vec!["failure:001".to_owned()],
            state_binding_ids: vec![],
            required_distinctions: vec![],
            limitations: vec!["required provider testimony was not received".to_owned()],
            nonclaims: vec!["subject absence is not established".to_owned()],
        }];
        artifact.primary_claim_id = Some("claim:provider-testimony".to_owned());
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Partial,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::Insufficient,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "required provider testimony is unavailable".to_owned(),
            refusals: vec![],
            unsupported: vec![],
        };
        reseal(&mut artifact);
        artifact
    }

    #[test]
    fn partial_claim_retains_exact_failure_dependency() {
        let failure =
            AcquisitionFailure::from_outcome(AcquisitionOutcome::Timeout).expect("timeout failure");
        let artifact = failed_artifact(FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure,
        });
        artifact
            .validate()
            .expect("partial claim names exact failure");
        assert_eq!(
            artifact.claims[0].dependency_failure_ids,
            vec!["failure:001"]
        );

        let mut substituted = artifact;
        substituted.claims[0].dependency_failure_ids = vec!["failure:not-the-source".to_owned()];
        reseal(&mut substituted);
        assert!(matches!(
            substituted.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("unknown failed-input occurrence")
        ));
    }

    #[test]
    fn top_level_unsupported_requires_typed_identified_exact_cause() {
        let unsupported = UnsupportedCauseV2 {
            unsupported_id: "unsupported:provider:001".to_owned(),
            origin: UnsupportedOriginV2::ExpectedInput {
                failure_id: "failure:001".to_owned(),
            },
            code: UnsupportedCodeV2::ProviderCapabilityUnavailable,
            capability: identity("capability:host-snapshot"),
            detail: "provider does not implement the required snapshot".to_owned(),
        };
        let mut artifact = failed_artifact(FailedInputCauseV2::Unsupported {
            unsupported: unsupported.clone(),
        });
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Unsupported,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "required provider capability is unsupported".to_owned(),
            refusals: vec![],
            unsupported: vec![unsupported],
        };
        reseal(&mut artifact);
        artifact
            .validate()
            .expect("typed unsupported input frontier is valid");

        let mut erased = artifact;
        erased.outcome.unsupported.clear();
        reseal(&mut erased);
        assert!(matches!(
            erased.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("no typed unsupported cause")
        ));
    }

    #[test]
    fn profile_level_unsupported_is_bound_to_the_bounded_question() {
        let mut artifact = completed();
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Unsupported,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Partial,
            summary: "profile does not implement this bounded question".to_owned(),
            refusals: vec![],
            unsupported: vec![UnsupportedCauseV2 {
                unsupported_id: "unsupported:question:001".to_owned(),
                origin: UnsupportedOriginV2::DiagnosticProfile,
                code: UnsupportedCodeV2::QuestionUnsupported,
                capability: artifact.question.clone(),
                detail: "question is outside this profile generation".to_owned(),
            }],
        };
        reseal(&mut artifact);
        artifact
            .validate()
            .expect("profile unsupported cause is question-bound");

        let mut substituted = artifact;
        substituted.outcome.unsupported[0].capability = identity("nq.host.different_question");
        reseal(&mut substituted);
        assert!(matches!(
            substituted.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("bounded question identity")
        ));
    }

    #[test]
    fn provider_no_response_retains_exact_timeout_outcome() {
        let failure = AcquisitionFailure::from_outcome(AcquisitionOutcome::Timeout)
            .expect("timeout is acquisition failure");
        let artifact = failed_artifact(FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure: failure.clone(),
        });
        artifact.validate().expect("provider no-response artifact");
        let FailedInputCauseV2::ProviderNoResponse {
            failure: reopened, ..
        } = &artifact.inputs.failed[0].cause
        else {
            panic!("provider no-response remains distinct");
        };
        assert_eq!(reopened, &failure);

        let mut outside = artifact;
        let FailedInputCauseV2::ProviderNoResponse { attempt, .. } =
            &mut outside.inputs.failed[0].cause
        else {
            panic!("provider no-response fixture");
        };
        attempt.ended_at = time(5);
        reseal(&mut outside);
        assert!(matches!(
            outside.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("outside the diagnostic attempt")
        ));
    }

    #[test]
    fn acquisition_failure_retains_exact_spawn_error() {
        let failure = AcquisitionFailure::from_outcome(AcquisitionOutcome::SpawnFailed {
            message: "ENOENT: helper binary absent".to_owned(),
        })
        .expect("spawn failure");
        let artifact = failed_artifact(FailedInputCauseV2::AcquisitionFailed {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure: failure.clone(),
        });
        artifact.validate().expect("acquisition-failure artifact");
        let FailedInputCauseV2::AcquisitionFailed {
            failure: reopened, ..
        } = &artifact.inputs.failed[0].cause
        else {
            panic!("acquisition failure remains distinct");
        };
        assert_eq!(reopened, &failure);
    }

    #[test]
    fn no_response_and_acquisition_failure_classes_cannot_be_substituted() {
        let spawn = AcquisitionFailure::from_outcome(AcquisitionOutcome::SpawnFailed {
            message: "spawn failed".to_owned(),
        })
        .expect("spawn failure");
        let timeout =
            AcquisitionFailure::from_outcome(AcquisitionOutcome::Timeout).expect("timeout failure");
        let no_response = failed_artifact(FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure: spawn,
        });
        assert!(matches!(
            no_response.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("provider_no_response")
        ));
        let acquisition = failed_artifact(FailedInputCauseV2::AcquisitionFailed {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure: timeout,
        });
        assert!(matches!(
            acquisition.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("acquisition_failed")
        ));

        let not_running = AcquisitionFailure::from_outcome(AcquisitionOutcome::NotRunning)
            .expect("not-running failure");
        let no_invocation = failed_artifact(FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure: not_running,
        });
        assert!(matches!(
            no_invocation.validate(),
            Err(DiagnosticExecutionError::Invariant(message))
                if message.contains("provider_no_response")
        ));
    }

    #[test]
    #[ignore = "explicit maintainer operation for the checked language-neutral corpus"]
    #[allow(clippy::too_many_lines)]
    fn regenerate_language_neutral_v2_fixtures() {
        use std::{fs, path::PathBuf};

        let output = std::env::var_os("NQ_V2_FIXTURE_ROOT")
            .map(PathBuf::from)
            .expect("NQ_V2_FIXTURE_ROOT must identify the sibling asset directory");
        let valid_root = output.join("fixtures/valid");
        let hostile_root = output.join("fixtures/hostile");
        fs::create_dir_all(&valid_root).expect("create valid fixture directory");
        fs::create_dir_all(&hostile_root).expect("create hostile fixture directory");

        let completed_unqualified = completed();
        let mut completed_bounded = completed();
        let bounded = ClockQualificationV2::Bounded {
            maximum_error_ms: 25,
            basis: identity("clock-qualification:fixture"),
        };
        completed_bounded.attempt_interval.qualification = bounded.clone();
        completed_bounded.inputs.received[0]
            .acquisition
            .qualification = bounded;
        reseal(&mut completed_bounded);

        let mut detector_a = completed();
        let detector_a_refusal = detector_refusal();
        detector_a.claims.clear();
        detector_a.primary_claim_id = None;
        detector_a.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Partial,
            summary: "complete load testimony is unavailable".to_owned(),
            refusals: vec![detector_a_refusal],
            unsupported: vec![],
        };
        reseal(&mut detector_a);
        let mut detector_b = detector_a.clone();
        let GovernedRefusalOrigin::Profile(profile) = &mut detector_b.outcome.refusals[0].origin
        else {
            panic!("profile refusal fixture");
        };
        profile
            .refusal
            .details
            .insert("observed_coverage".to_owned(), "identity".to_owned());
        reseal(&mut detector_b);

        let mut received_refused = completed();
        let received_refusal = helper_refusal();
        received_refused.inputs.admitted.clear();
        received_refused.inputs.selected.clear();
        received_refused.inputs.refused = vec![RefusedInputV2 {
            input_id: "input:001".to_owned(),
            refusal: received_refusal.clone(),
            profile_binding: None,
        }];
        received_refused.state_bindings.clear();
        received_refused.claims.clear();
        received_refused.primary_claim_id = None;
        received_refused.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "required received testimony was refused".to_owned(),
            refusals: vec![received_refusal],
            unsupported: vec![],
        };
        reseal(&mut received_refused);

        let timeout =
            AcquisitionFailure::from_outcome(AcquisitionOutcome::Timeout).expect("timeout failure");
        let provider_no_response = failed_artifact(FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure: timeout.clone(),
        });
        let spawn = AcquisitionFailure::from_outcome(AcquisitionOutcome::SpawnFailed {
            message: "ENOENT: helper binary absent".to_owned(),
        })
        .expect("spawn failure");
        let acquisition_failed = failed_artifact(FailedInputCauseV2::AcquisitionFailed {
            provider_intake_id: "intake:failed:001".to_owned(),
            attempt: unqualified_interval(1, 2),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure: spawn.clone(),
        });

        let unsupported = UnsupportedCauseV2 {
            unsupported_id: "unsupported:provider:001".to_owned(),
            origin: UnsupportedOriginV2::ExpectedInput {
                failure_id: "failure:001".to_owned(),
            },
            code: UnsupportedCodeV2::ProviderCapabilityUnavailable,
            capability: identity("capability:host-snapshot"),
            detail: "provider does not implement the required snapshot".to_owned(),
        };
        let mut typed_unsupported = failed_artifact(FailedInputCauseV2::Unsupported {
            unsupported: unsupported.clone(),
        });
        typed_unsupported.claims.clear();
        typed_unsupported.primary_claim_id = None;
        typed_unsupported.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Unsupported,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "required provider capability is unsupported".to_owned(),
            refusals: vec![],
            unsupported: vec![unsupported],
        };
        reseal(&mut typed_unsupported);

        let mut multiple_refusals = completed();
        multiple_refusals.inputs.expected.push(ExpectedInputV1 {
            expectation_id: "expected:remote-snapshot".to_owned(),
            role: "remote_snapshot".to_owned(),
            required: true,
        });
        let mut second_received = received();
        second_received.input_id = "input:002".to_owned();
        second_received.expectation_id = "expected:remote-snapshot".to_owned();
        second_received.provider_intake_id = "intake:002".to_owned();
        second_received.raw_artifact_id = RawArtifactId(digest("raw:002"));
        multiple_refusals.inputs.received.push(second_received);
        multiple_refusals.inputs.admitted.clear();
        multiple_refusals.inputs.selected.clear();
        let first_refusal = helper_refusal_named("refusal:input:001", "host-witness:fixture");
        let second_refusal = helper_refusal_named("refusal:input:002", "remote-witness:fixture");
        multiple_refusals.inputs.refused = vec![
            RefusedInputV2 {
                input_id: "input:001".to_owned(),
                refusal: first_refusal.clone(),
                profile_binding: None,
            },
            RefusedInputV2 {
                input_id: "input:002".to_owned(),
                refusal: second_refusal.clone(),
                profile_binding: None,
            },
        ];
        multiple_refusals.state_bindings.clear();
        multiple_refusals.claims.clear();
        multiple_refusals.primary_claim_id = None;
        multiple_refusals.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "both required inputs were refused".to_owned(),
            refusals: vec![first_refusal, second_refusal],
            unsupported: vec![],
        };
        reseal(&mut multiple_refusals);

        let mut retained_acquisition_refusal = completed();
        let exit_failure =
            AcquisitionFailure::from_outcome(AcquisitionOutcome::ExitNonzero { code: Some(23) })
                .expect("exit failure");
        let exact_acquisition_refusal = GovernedRefusal::acquisition(
            "refusal:acquisition:001".to_owned(),
            AcquisitionRefusal {
                responsible_instance_id: "host-witness:fixture".to_owned(),
                failure: exit_failure,
            },
        );
        retained_acquisition_refusal.inputs.admitted.clear();
        retained_acquisition_refusal.inputs.selected.clear();
        retained_acquisition_refusal.inputs.refused = vec![RefusedInputV2 {
            input_id: "input:001".to_owned(),
            refusal: exact_acquisition_refusal.clone(),
            profile_binding: None,
        }];
        retained_acquisition_refusal.state_bindings.clear();
        retained_acquisition_refusal.claims.clear();
        retained_acquisition_refusal.primary_claim_id = None;
        retained_acquisition_refusal.outcome = DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: "retained partial response failed acquisition".to_owned(),
            refusals: vec![exact_acquisition_refusal],
            unsupported: vec![],
        };
        reseal(&mut retained_acquisition_refusal);

        let mut received_before_acquisition = completed_unqualified.clone();
        received_before_acquisition.inputs.received[0].received_at = time(1);
        reseal(&mut received_before_acquisition);

        let valid = vec![
            ("completed_unqualified_clock.json", completed_unqualified),
            ("completed_bounded_clock.json", completed_bounded),
            ("detector_refusal_detail_a.json", detector_a),
            ("detector_refusal_detail_b.json", detector_b),
            ("received_input_refusal.json", received_refused),
            ("provider_no_response.json", provider_no_response.clone()),
            ("acquisition_failure.json", acquisition_failed.clone()),
            ("typed_unsupported.json", typed_unsupported.clone()),
            ("multiple_input_refusals.json", multiple_refusals.clone()),
            (
                "retained_acquisition_refusal.json",
                retained_acquisition_refusal,
            ),
        ];
        for (name, artifact) in valid {
            let bytes = artifact.canonical_bytes().expect("valid canonical fixture");
            fs::write(valid_root.join(name), bytes).expect("write valid fixture");
        }

        let mut no_response_with_spawn = provider_no_response;
        let FailedInputCauseV2::ProviderNoResponse { failure, .. } =
            &mut no_response_with_spawn.inputs.failed[0].cause
        else {
            panic!("provider-no-response fixture");
        };
        *failure = spawn;
        reseal(&mut no_response_with_spawn);

        let mut acquisition_with_timeout = acquisition_failed;
        let FailedInputCauseV2::AcquisitionFailed { failure, .. } =
            &mut acquisition_with_timeout.inputs.failed[0].cause
        else {
            panic!("acquisition-failure fixture");
        };
        *failure = timeout;
        reseal(&mut acquisition_with_timeout);

        let mut missing_refusal_member = multiple_refusals;
        missing_refusal_member.outcome.refusals.pop();
        reseal(&mut missing_refusal_member);

        let mut substituted_failure_dependency =
            failed_artifact(FailedInputCauseV2::ProviderNoResponse {
                provider_intake_id: "intake:failed:001".to_owned(),
                attempt: unqualified_interval(1, 2),
                raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
                failure: AcquisitionFailure::from_outcome(AcquisitionOutcome::Timeout)
                    .expect("timeout failure"),
            });
        substituted_failure_dependency.claims[0].dependency_failure_ids =
            vec!["failure:not-the-source".to_owned()];
        reseal(&mut substituted_failure_dependency);

        let mut missing_unsupported_frontier = typed_unsupported;
        missing_unsupported_frontier.outcome.unsupported.clear();
        reseal(&mut missing_unsupported_frontier);

        let hostile = [
            ("no_response_with_spawn.json", no_response_with_spawn),
            (
                "acquisition_failure_with_timeout.json",
                acquisition_with_timeout,
            ),
            (
                "missing_refusal_frontier_member.json",
                missing_refusal_member,
            ),
            (
                "substituted_failure_dependency.json",
                substituted_failure_dependency,
            ),
            (
                "missing_unsupported_frontier.json",
                missing_unsupported_frontier,
            ),
            (
                "received_before_acquisition.json",
                received_before_acquisition,
            ),
        ];
        for (name, artifact) in hostile {
            let bytes = canonical_json_bytes(&artifact).expect("hostile canonical fixture");
            fs::write(hostile_root.join(name), bytes).expect("write hostile fixture");
        }
    }

    #[test]
    fn checked_language_neutral_v2_corpus_matches_rust_contract() {
        let valid: &[&[u8]] = &[
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/acquisition_failure.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/completed_bounded_clock.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/completed_unqualified_clock.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/detector_refusal_detail_a.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/detector_refusal_detail_b.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/multiple_input_refusals.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/provider_no_response.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/received_input_refusal.json"
            ),
            include_bytes!(
                "../../../diagnostic-contract-v2/fixtures/valid/retained_acquisition_refusal.json"
            ),
            include_bytes!("../../../diagnostic-contract-v2/fixtures/valid/typed_unsupported.json"),
        ];
        for bytes in valid {
            let artifact =
                DiagnosticExecutionV2::decode_canonical(bytes).expect("checked valid fixture");
            assert_eq!(
                artifact.canonical_bytes().expect("fixture reserialization"),
                *bytes
            );
        }

        let hostile: &[(&[u8], &str)] = &[
            (
                include_bytes!(
                    "../../../diagnostic-contract-v2/fixtures/hostile/acquisition_failure_with_timeout.json"
                ),
                "acquisition_failed carries a provider-no-response failure class",
            ),
            (
                include_bytes!(
                    "../../../diagnostic-contract-v2/fixtures/hostile/missing_refusal_frontier_member.json"
                ),
                "complete exact refusal frontier",
            ),
            (
                include_bytes!(
                    "../../../diagnostic-contract-v2/fixtures/hostile/missing_unsupported_frontier.json"
                ),
                "unsupported outcome has no typed unsupported cause",
            ),
            (
                include_bytes!(
                    "../../../diagnostic-contract-v2/fixtures/hostile/no_response_with_spawn.json"
                ),
                "provider_no_response carries an acquisition-failure class",
            ),
            (
                include_bytes!(
                    "../../../diagnostic-contract-v2/fixtures/hostile/received_before_acquisition.json"
                ),
                "received_at falls before acquisition completion",
            ),
            (
                include_bytes!(
                    "../../../diagnostic-contract-v2/fixtures/hostile/substituted_failure_dependency.json"
                ),
                "claim references an unknown failed-input occurrence",
            ),
        ];
        for (bytes, expected) in hostile {
            assert!(matches!(
                DiagnosticExecutionV2::decode_canonical(bytes),
                Err(DiagnosticExecutionError::Invariant(message))
                    if message.contains(expected)
            ));
        }
    }

    #[test]
    fn v1_document_is_not_a_v2_document() {
        let bytes = include_bytes!("../../../diagnostic-contract/fixtures/valid/positive.json");
        assert!(DiagnosticExecutionV2::decode_canonical(bytes).is_err());
    }
}
