//! Transport-neutral profile validation input and admitted output.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::descriptor::{ProfileDescriptor, ProfileDigest, ProfileKey, vocabulary_contains};

/// Report status after a successful helper protocol exchange.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticReportStatus {
    /// The helper declares all controlled coverage complete.
    Complete,
    /// The helper returned useful but incomplete testimony.
    Partial,
    /// The helper returned valid testimony explaining why it collected none.
    Failed,
}

/// State of one controlled coverage declaration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCoverageState {
    /// The coverage class was completely observed within the declared bounds.
    Complete,
    /// The coverage class was observed incompletely.
    Partial,
    /// The coverage class could not be observed.
    Unavailable,
}

/// Transport-neutral input for one coverage declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageInput {
    /// Controlled coverage name.
    pub name: String,
    /// Optional child subject named by the coverage declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Declared state.
    pub state: SemanticCoverageState,
    /// Optional bounded structured detail; it cannot create coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

/// Transport-neutral input for one observation.
///
/// This boundary is deliberately local and protocol-shaped today. It can also
/// normalize a future custody carrier without giving that carrier semantic
/// authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationInput {
    /// Controlled observation kind.
    pub kind: String,
    /// Profile-validated subject identity.
    pub subject: String,
    /// Position within the immutable report.
    pub ordinal: u32,
    /// Time the helper says it made this observation.
    pub observed_at: DateTime<Utc>,
    /// Strictly bounded, profile-owned typed payload.
    pub payload: Value,
}

/// Transport-neutral report passed to compiled profile semantics only after
/// helper protocol validation succeeds.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportInput {
    /// Canonical semantic digest of the complete protocol report.
    pub report_digest: String,
    /// Profile identity declared by the helper report.
    pub profile: ProfileKey,
    /// Descriptor digest declared by the helper report.
    pub profile_digest: String,
    /// Helper-declared report state.
    pub status: SemanticReportStatus,
    /// Overall observation time.
    pub observed_at: DateTime<Utc>,
    /// Complete set of controlled coverage declarations.
    pub coverage: Vec<CoverageInput>,
    /// Ordered observations.
    pub observations: Vec<ObservationInput>,
    /// Number of ordered structured errors retained with the protocol report.
    pub error_count: u32,
    /// Number of structured errors with error severity.
    pub failure_error_count: u32,
    /// Capability subset the report declares it exercised.
    pub used_capabilities: BTreeSet<String>,
}

impl ReportInput {
    /// Normalizes a protocol report after common protocol validation.
    ///
    /// `report_digest` must be the canonical semantic digest of the complete
    /// [`nq_protocol::EvidenceReport`], not a digest of this reduced view.
    ///
    /// # Errors
    ///
    /// Returns [`ReportNormalizationError`] when the protocol profile version
    /// cannot be represented by the compiled numeric version vocabulary.
    pub fn from_protocol(
        report: &nq_protocol::EvidenceReport,
        report_digest: &nq_protocol::Sha256Digest,
    ) -> Result<Self, ReportNormalizationError> {
        let version = report
            .profile
            .version
            .as_str()
            .parse::<u32>()
            .map_err(|_| {
                ReportNormalizationError::ProfileVersion(report.profile.version.to_string())
            })?;
        let status = match report.status {
            nq_protocol::ReportStatus::Complete => SemanticReportStatus::Complete,
            nq_protocol::ReportStatus::Partial => SemanticReportStatus::Partial,
            nq_protocol::ReportStatus::Failed => SemanticReportStatus::Failed,
        };
        let coverage = report
            .coverage
            .iter()
            .map(|declaration| CoverageInput {
                name: declaration.kind.to_string(),
                subject: declaration.subject.as_ref().map(ToString::to_string),
                state: match declaration.state {
                    nq_protocol::CoverageState::Complete => SemanticCoverageState::Complete,
                    nq_protocol::CoverageState::Partial => SemanticCoverageState::Partial,
                    nq_protocol::CoverageState::Unavailable => SemanticCoverageState::Unavailable,
                },
                detail: declaration.detail.clone(),
            })
            .collect();
        let observations = report
            .observations
            .iter()
            .map(|observation| ObservationInput {
                kind: observation.kind.to_string(),
                subject: observation.subject.to_string(),
                ordinal: observation.ordinal,
                observed_at: observation.observed_at,
                payload: observation.payload.clone(),
            })
            .collect();
        let error_count = u32::try_from(report.errors.len()).unwrap_or(u32::MAX);
        let failure_error_count = u32::try_from(
            report
                .errors
                .iter()
                .filter(|error| error.severity == nq_protocol::ErrorSeverity::Error)
                .count(),
        )
        .unwrap_or(u32::MAX);
        let used_capabilities = report
            .used_capabilities
            .iter()
            .map(ToString::to_string)
            .collect();

        Ok(Self {
            report_digest: report_digest.to_string(),
            profile: ProfileKey::new(report.profile.id.to_string(), version),
            profile_digest: report.profile.digest.to_string(),
            status,
            observed_at: report.observed_at,
            coverage,
            observations,
            error_count,
            failure_error_count,
            used_capabilities,
        })
    }

    /// Computes the protocol semantic digest and then normalizes the report.
    ///
    /// # Errors
    ///
    /// Returns [`ReportNormalizationError`] if canonicalization or numeric
    /// profile-version normalization fails.
    pub fn from_protocol_with_digest(
        report: &nq_protocol::EvidenceReport,
    ) -> Result<Self, ReportNormalizationError> {
        let digest = nq_protocol::semantic_digest(report)
            .map_err(|error| ReportNormalizationError::Canonicalization(error.to_string()))?;
        Self::from_protocol(report, &digest)
    }
}

/// Failure to normalize a protocol-valid report into profile input.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReportNormalizationError {
    /// The wire profile version is a safe protocol token but not a v1 integer.
    #[error("profile version {0:?} is not an unsigned integer")]
    ProfileVersion(String),
    /// Semantic report canonicalization failed.
    #[error("report canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Exact request scope selected by NQ.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeGrant {
    /// Controlled scope kind.
    pub kind: String,
    /// Bounded profile-owned scope value copied exactly from the request.
    pub value: Value,
}

/// Exact request vantage selected by NQ.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VantageGrant {
    /// Controlled vantage kind.
    pub kind: String,
    /// Bounded profile-owned vantage value copied exactly from the request.
    pub value: Value,
}

/// NQ-owned runtime binding against which a profile validates testimony.
#[derive(Clone, Debug)]
pub struct ValidationContext {
    /// Exact responsible witness instance.
    pub instance_id: String,
    /// Exact request subject.
    pub request_subject: String,
    /// Scope selected by configuration and admission.
    pub scope: ScopeGrant,
    /// Named collection vantage.
    pub vantage: VantageGrant,
    /// Capability subset actually granted to this request.
    pub granted_capabilities: BTreeSet<String>,
    /// NQ receive time used for future-clock checks.
    pub received_at: DateTime<Utc>,
    /// Request-level bound, which may only narrow the profile limit.
    pub max_observations: u32,
    /// Maximum tolerated helper clock lead.
    pub max_future_skew: Duration,
}

impl ValidationContext {
    /// Builds an exact NQ-owned semantic binding from a validated request.
    #[must_use]
    pub fn from_request(
        request: &nq_protocol::HelperRequest,
        received_at: DateTime<Utc>,
        max_future_skew: Duration,
    ) -> Self {
        Self {
            instance_id: request.instance_id.to_string(),
            request_subject: request.binding.subject.to_string(),
            scope: ScopeGrant {
                kind: request.binding.scope.kind.to_string(),
                value: request.binding.scope.value.clone(),
            },
            vantage: VantageGrant {
                kind: request.binding.vantage.kind.to_string(),
                value: request.binding.vantage.value.clone(),
            },
            granted_capabilities: request
                .granted_capabilities
                .iter()
                .map(ToString::to_string)
                .collect(),
            received_at,
            max_observations: request.bounds.max_observations,
            max_future_skew,
        }
    }
}

/// Common envelope embedded in each profile-owned payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBasis {
    /// Scope claimed for this observation.
    pub scope: ScopeGrant,
    /// Exact named vantage used for this observation.
    pub vantage: VantageGrant,
    /// Controlled access path.
    pub access_path: String,
    /// Controlled evidence basis.
    pub basis: String,
    /// Controlled operating regime.
    pub regime: String,
    /// Capabilities the helper says this observation actually exercised.
    #[serde(default)]
    pub capabilities_used: BTreeSet<String>,
}

/// Boundary that produced a semantic refusal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalBoundary {
    /// Profile descriptor or identity resolution.
    Profile,
    /// Whole-report validation.
    Report,
    /// Controlled coverage validation.
    Coverage,
    /// Individual observation validation.
    Observation,
    /// Detector evaluation.
    Detector,
}

/// Typed profile refusal code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRefusalCode {
    /// The requested profile is not compiled into this binary.
    UnknownProfile,
    /// A controlled observation kind was unknown.
    UnknownObservationKind,
    /// A controlled coverage class was unknown.
    UnknownCoverage,
    /// A controlled coverage class appeared more than once.
    DuplicateCoverage,
    /// A required controlled coverage declaration was absent.
    MissingCoverage,
    /// Coverage and report status disagree.
    CoverageStatusMismatch,
    /// Report state overclaims what the contained testimony supports.
    ReportStatusOverclaim,
    /// Observation cardinality exceeds a hard or request limit.
    ObservationLimitExceeded,
    /// Canonical payload bytes exceed the profile limit.
    PayloadLimitExceeded,
    /// Observation ordinals are duplicate, sparse, or unordered.
    InvalidOrdinal,
    /// A subject is outside the NQ-owned request binding.
    SubjectEscape,
    /// A claimed scope is outside the NQ-owned scope binding.
    ScopeEscape,
    /// A claimed vantage is outside the NQ-owned vantage binding.
    VantageEscape,
    /// A capability is unknown or outside the NQ-owned grant.
    CapabilityEscape,
    /// An access path is outside the profile vocabulary.
    UnknownAccessPath,
    /// An evidence basis is outside the profile vocabulary.
    UnknownBasis,
    /// A regime is outside the profile vocabulary.
    UnknownRegime,
    /// An observation time is implausibly in the future.
    FutureObservation,
    /// Profile payload did not match its strict typed schema.
    InvalidPayload,
    /// Payload fields contradict coverage or another observation.
    InconsistentReport,
    /// Helper output attempted to assert authority or detector semantics.
    ForbiddenHelperAssertion,
    /// Evaluation has insufficient current evidence.
    CannotEvaluate,
}

/// Typed explanation retaining the exact instance and failing boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRefusal {
    /// Exact responsible NQ-owned instance.
    pub instance_id: String,
    /// Profile being validated or evaluated.
    pub profile: ProfileKey,
    /// Boundary that refused the input.
    pub boundary: RefusalBoundary,
    /// Stable reason code.
    pub code: ProfileRefusalCode,
    /// Concise operator-facing explanation.
    pub message: String,
    /// Bounded machine-readable context.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl ProfileRefusal {
    pub(crate) fn new(
        context: &ValidationContext,
        descriptor: &ProfileDescriptor,
        boundary: RefusalBoundary,
        code: ProfileRefusalCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            instance_id: context.instance_id.clone(),
            profile: descriptor.profile.clone(),
            boundary,
            code,
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    pub(crate) fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

/// Observation admitted under an exact compiled profile descriptor.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedObservation {
    /// Controlled observation kind.
    pub kind: String,
    /// Validated subject.
    pub subject: String,
    /// Report ordinal.
    pub ordinal: u32,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
    /// Canonical profile payload retained without flattening.
    pub payload: Value,
}

/// Immutable admitted semantic report.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedReport {
    /// Exact NQ-owned instance that produced the request binding.
    pub instance_id: String,
    /// Canonical semantic identity of the source protocol report.
    pub report_digest: String,
    /// Exact profile contract.
    pub profile: ProfileKey,
    /// Canonical profile descriptor digest.
    pub profile_digest: ProfileDigest,
    /// Helper-declared report state, validated against its contents.
    pub status: SemanticReportStatus,
    /// Overall report observation time.
    pub observed_at: DateTime<Utc>,
    /// Complete controlled coverage map.
    pub coverage: BTreeMap<String, SemanticCoverageState>,
    /// Strictly validated ordered observations.
    pub observations: Vec<AdmittedObservation>,
    /// Original structured-error count.
    pub error_count: u32,
    /// Number of retained errors with collection-error severity.
    pub failure_error_count: u32,
    /// Profile-known capability subset actually exercised by the report.
    pub used_capabilities: BTreeSet<String>,
    /// NQ receive time. This is not an observation time.
    pub received_at: DateTime<Utc>,
}

/// Result of compiled profile admission.
pub type ValidationResult = Result<ValidatedReport, ProfileRefusal>;

/// Applies laws shared by every compiled profile.
pub(crate) fn validate_common(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    report: &ReportInput,
) -> ValidationResult {
    let descriptor_digest = validate_profile_binding(descriptor, context, report)?;
    let coverage = validate_coverage(descriptor, context, &report.coverage)?;
    let coverage_count = u32::try_from(report.coverage.len()).unwrap_or(u32::MAX);
    if coverage_count > descriptor.limits.max_coverage_declarations {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Coverage,
            ProfileRefusalCode::ObservationLimitExceeded,
            "report exceeds the coverage declaration limit",
        ));
    }
    validate_status(descriptor, context, report, &coverage)?;
    let observations = validate_observations(descriptor, context, &report.observations)?;

    Ok(ValidatedReport {
        instance_id: context.instance_id.clone(),
        report_digest: report.report_digest.clone(),
        profile: descriptor.profile.clone(),
        profile_digest: descriptor_digest,
        status: report.status,
        observed_at: report.observed_at,
        coverage,
        observations,
        error_count: report.error_count,
        failure_error_count: report.failure_error_count,
        used_capabilities: report.used_capabilities.clone(),
        received_at: context.received_at,
    })
}

fn validate_profile_binding(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    report: &ReportInput,
) -> Result<ProfileDigest, ProfileRefusal> {
    let descriptor_digest = descriptor.digest().map_err(|error| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            error.to_string(),
        )
    })?;
    if report.profile != descriptor.profile || report.profile_digest != descriptor_digest.as_str() {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::UnknownProfile,
            "report profile identity or descriptor digest does not match the compiled profile",
        )
        .with_detail(
            "declared_profile",
            format!("{}/v{}", report.profile.id, report.profile.version),
        )
        .with_detail("declared_digest", report.profile_digest.clone()));
    }

    for capability in &report.used_capabilities {
        let known = vocabulary_contains(&descriptor.capabilities, capability);
        let granted = context.granted_capabilities.contains(capability);
        if !known || !granted {
            return Err(ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Report,
                ProfileRefusalCode::CapabilityEscape,
                "report exercised a capability outside the profile or request grant",
            )
            .with_detail("capability", capability.clone()));
        }
    }
    Ok(descriptor_digest)
}

fn validate_observations(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    inputs: &[ObservationInput],
) -> Result<Vec<AdmittedObservation>, ProfileRefusal> {
    let hard_limit = descriptor
        .limits
        .max_observations
        .min(context.max_observations);
    let observation_count = u32::try_from(inputs.len()).unwrap_or(u32::MAX);
    if observation_count > hard_limit {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Report,
            ProfileRefusalCode::ObservationLimitExceeded,
            "report exceeds the effective observation limit",
        )
        .with_detail("limit", hard_limit.to_string())
        .with_detail("actual", observation_count.to_string()));
    }

    let mut observations = Vec::with_capacity(inputs.len());
    for (position, observation) in inputs.iter().enumerate() {
        let expected_ordinal = u32::try_from(position).unwrap_or(u32::MAX);
        validate_observation(descriptor, context, observation, expected_ordinal)?;
        observations.push(AdmittedObservation {
            kind: observation.kind.clone(),
            subject: observation.subject.clone(),
            ordinal: observation.ordinal,
            observed_at: observation.observed_at,
            payload: observation.payload.clone(),
        });
    }
    Ok(observations)
}

fn validate_observation(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    observation: &ObservationInput,
    expected_ordinal: u32,
) -> Result<(), ProfileRefusal> {
    if observation.ordinal != expected_ordinal {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::InvalidOrdinal,
            "observation ordinals must be contiguous and ordered from zero",
        )
        .with_detail("expected", expected_ordinal.to_string())
        .with_detail("actual", observation.ordinal.to_string()));
    }
    if !descriptor.knows_observation_kind(&observation.kind) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::UnknownObservationKind,
            "observation kind is outside the compiled vocabulary",
        )
        .with_detail("kind", observation.kind.clone()));
    }
    validate_observation_subject(descriptor, context, observation)?;
    validate_observation_payload(descriptor, context, observation)?;
    if observation.observed_at > context.received_at + context.max_future_skew {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::FutureObservation,
            "observation time exceeds the allowed clock lead",
        ));
    }
    reject_forbidden_assertions(descriptor, context, &observation.payload)
}

fn validate_observation_subject(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    observation: &ObservationInput,
) -> Result<(), ProfileRefusal> {
    let subject_bytes = u32::try_from(observation.subject.len()).unwrap_or(u32::MAX);
    let valid_namespace = observation
        .subject
        .starts_with(&descriptor.subjects.namespace);
    let exact_subject = !descriptor.subjects.exact_request_subject
        || observation.subject == context.request_subject;
    if subject_bytes <= descriptor.limits.max_subject_bytes && valid_namespace && exact_subject {
        return Ok(());
    }
    Err(ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Observation,
        ProfileRefusalCode::SubjectEscape,
        "observation subject is outside the request binding",
    )
    .with_detail("subject", observation.subject.clone())
    .with_detail("request_subject", context.request_subject.clone()))
}

fn validate_observation_payload(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    observation: &ObservationInput,
) -> Result<(), ProfileRefusal> {
    let canonical_payload =
        nq_protocol::canonical_json_bytes(&observation.payload).map_err(|error| {
            ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Observation,
                ProfileRefusalCode::InvalidPayload,
                "observation payload cannot be canonicalized",
            )
            .with_detail("error", error.to_string())
        })?;
    let payload_bytes = u32::try_from(canonical_payload.len()).unwrap_or(u32::MAX);
    if payload_bytes <= descriptor.limits.max_payload_bytes {
        return Ok(());
    }
    Err(ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Observation,
        ProfileRefusalCode::PayloadLimitExceeded,
        "observation payload exceeds the profile limit",
    )
    .with_detail("limit", descriptor.limits.max_payload_bytes.to_string())
    .with_detail("actual", payload_bytes.to_string()))
}

/// Validates the common basis envelope against compiled vocabulary and the
/// exact NQ-owned request binding.
pub(crate) fn validate_basis(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    basis: &EvidenceBasis,
) -> Result<(), ProfileRefusal> {
    if basis.scope != context.scope {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::ScopeEscape,
            "payload scope differs from the request scope",
        ));
    }
    if !vocabulary_contains(&descriptor.scope_kinds, &basis.scope.kind) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::ScopeEscape,
            "payload scope kind is outside the profile vocabulary",
        ));
    }
    if basis.vantage != context.vantage
        || !vocabulary_contains(&descriptor.vantages, &basis.vantage.kind)
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::VantageEscape,
            "payload vantage differs from the request or profile vocabulary",
        ));
    }
    if !vocabulary_contains(&descriptor.access_paths, &basis.access_path) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::UnknownAccessPath,
            "payload access path is outside the compiled vocabulary",
        ));
    }
    if !vocabulary_contains(&descriptor.bases, &basis.basis) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::UnknownBasis,
            "payload basis is outside the compiled vocabulary",
        ));
    }
    if !vocabulary_contains(&descriptor.regimes, &basis.regime) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::UnknownRegime,
            "payload regime is outside the compiled vocabulary",
        ));
    }

    for capability in &basis.capabilities_used {
        let known = vocabulary_contains(&descriptor.capabilities, capability);
        let granted = context.granted_capabilities.contains(capability);
        if !known || !granted {
            return Err(ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Observation,
                ProfileRefusalCode::CapabilityEscape,
                "payload exercised a capability outside the request grant",
            )
            .with_detail("capability", capability.clone()));
        }
    }

    Ok(())
}

fn validate_coverage(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    declarations: &[CoverageInput],
) -> Result<BTreeMap<String, SemanticCoverageState>, ProfileRefusal> {
    let mut coverage = BTreeMap::new();
    for declaration in declarations {
        if !descriptor.knows_coverage(&declaration.name) {
            return Err(ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Coverage,
                ProfileRefusalCode::UnknownCoverage,
                "coverage class is outside the compiled vocabulary",
            )
            .with_detail("coverage", declaration.name.clone()));
        }
        if declaration
            .subject
            .as_ref()
            .is_some_and(|subject| subject != &context.request_subject)
        {
            return Err(ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Coverage,
                ProfileRefusalCode::SubjectEscape,
                "coverage subject is outside the request binding",
            )
            .with_detail("subject", declaration.subject.clone().unwrap_or_default()));
        }
        if let Some(detail) = &declaration.detail {
            let bytes = nq_protocol::canonical_json_bytes(detail).map_err(|error| {
                ProfileRefusal::new(
                    context,
                    descriptor,
                    RefusalBoundary::Coverage,
                    ProfileRefusalCode::InvalidPayload,
                    "coverage detail cannot be canonicalized",
                )
                .with_detail("error", error.to_string())
            })?;
            if bytes.len() > descriptor.limits.max_payload_bytes as usize {
                return Err(ProfileRefusal::new(
                    context,
                    descriptor,
                    RefusalBoundary::Coverage,
                    ProfileRefusalCode::PayloadLimitExceeded,
                    "coverage detail exceeds the profile payload limit",
                ));
            }
        }
        if coverage
            .insert(declaration.name.clone(), declaration.state)
            .is_some()
        {
            return Err(ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Coverage,
                ProfileRefusalCode::DuplicateCoverage,
                "coverage class appears more than once",
            )
            .with_detail("coverage", declaration.name.clone()));
        }
    }

    for term in &descriptor.coverage {
        if !coverage.contains_key(&term.name) {
            return Err(ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Coverage,
                ProfileRefusalCode::MissingCoverage,
                "required coverage declaration is missing",
            )
            .with_detail("coverage", term.name.clone()));
        }
    }
    Ok(coverage)
}

fn validate_status(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    report: &ReportInput,
    coverage: &BTreeMap<String, SemanticCoverageState>,
) -> Result<(), ProfileRefusal> {
    let all_complete = coverage
        .values()
        .all(|state| *state == SemanticCoverageState::Complete);
    let all_unavailable = coverage
        .values()
        .all(|state| *state == SemanticCoverageState::Unavailable);

    let valid = match report.status {
        SemanticReportStatus::Complete => all_complete && report.failure_error_count == 0,
        SemanticReportStatus::Partial => {
            !all_complete && !all_unavailable && report.error_count > 0
        }
        SemanticReportStatus::Failed => {
            all_unavailable && report.observations.is_empty() && report.failure_error_count > 0
        }
    };
    if valid {
        return Ok(());
    }

    Err(ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Report,
        ProfileRefusalCode::ReportStatusOverclaim,
        "report status is not supported by coverage, observations, and errors",
    ))
}

fn reject_forbidden_assertions(
    descriptor: &ProfileDescriptor,
    context: &ValidationContext,
    payload: &Value,
) -> Result<(), ProfileRefusal> {
    const FORBIDDEN: [&str; 7] = [
        "admission",
        "authoritative_for",
        "authorization",
        "claim",
        "detector",
        "remediation",
        "severity",
    ];
    let Some(object) = payload.as_object() else {
        return Ok(());
    };
    if let Some(key) = FORBIDDEN.iter().find(|key| object.contains_key(**key)) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::ForbiddenHelperAssertion,
            "helper payload attempted to assert NQ-owned semantics or authority",
        )
        .with_detail("field", *key));
    }
    Ok(())
}
