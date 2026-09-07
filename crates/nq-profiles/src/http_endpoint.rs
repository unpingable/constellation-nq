//! `nq.http_endpoint/v1`: controller-vantage bounded HTTP testimony.

use std::{any::Any, collections::BTreeMap, sync::LazyLock};

use chrono::Duration;
use nq_protocol::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CardinalityLimits, DETECTOR_DESCRIPTOR_SCHEMA, Detector, DetectorDescriptor, DetectorEvidence,
    DetectorInput, DetectorReport, DetectorResult, DetectorRuleParameters, DetectorState,
    EvidenceBasis, FreshnessPolicy, ProfileDescriptor, ProfileModule, ProfileProjection,
    ProfileRefusal, ProfileRefusalCode, ProjectionResult, RefusalBoundary, SemanticCoverageState,
    SemanticReportStatus, SubjectRules, ValidatedReport, ValidationContext, ValidationResult,
    VocabularyTerm,
    descriptor::PROFILE_DESCRIPTOR_SCHEMA,
    validation::{ReportInput, ScopeGrant, validate_basis, validate_common},
};

/// Stable profile identifier.
pub const PROFILE_ID: &str = "nq.http_endpoint";
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 1;
/// Exact accepted external policy schema.
pub const THRESHOLD_POLICY_SCHEMA: &str = "nq.operator_beta.http_endpoint_threshold_policy.v1";
/// Stable external policy family.
pub const THRESHOLD_POLICY_ID: &str = "nq.http_endpoint.postcondition.threshold_policy";
/// Stable compiled detector identifier.
pub const DETECTOR_ID: &str = "nq.http_endpoint.postcondition";

/// Stateless controller-vantage HTTP profile.
#[derive(Debug)]
pub struct HttpEndpointProfile;

/// Singleton module registered by the compile-time registry.
pub static MODULE: HttpEndpointProfile = HttpEndpointProfile;

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "http_endpoint".to_owned(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Controller-vantage bounded HTTP endpoint".to_owned(),
    observation_kinds: vec![VocabularyTerm::new(
        "http_response",
        "A bounded HTTP response observed from one exact controller vantage",
    )],
    coverage: vec![VocabularyTerm::new(
        "http_endpoint_response",
        "The bounded request and response exchange",
    )],
    subjects: SubjectRules {
        namespace: "sha256:".to_owned(),
        exact_request_subject: true,
    },
    scope_kinds: vec![VocabularyTerm::new(
        "http_endpoint",
        "One exact endpoint locator and bounded request",
    )],
    vantages: vec![VocabularyTerm::new(
        "controller_http",
        "Observation from one exact controller instance",
    )],
    access_paths: vec![VocabularyTerm::new(
        "http_tcp",
        "Bounded DNS, TCP, and HTTP acquisition",
    )],
    bases: vec![VocabularyTerm::new(
        "http_response",
        "Exact bounded HTTP response status and body digest",
    )],
    regimes: vec![VocabularyTerm::new(
        "normal",
        "Read-only controller-vantage HTTP acquisition",
    )],
    capabilities: vec![VocabularyTerm::new(
        "read_http_endpoint",
        "Issue the exact bounded HTTP GET request",
    )],
    freshness: FreshnessPolicy {
        reliance_seconds: 60,
        alignment_seconds: 0,
    },
    limits: CardinalityLimits {
        max_observations: 1,
        max_payload_bytes: 16_384,
        max_subject_bytes: 71,
        max_coverage_declarations: 1,
    },
    disturbance_assumptions: vec![
        "One HTTP response does not establish global reachability or future state".to_owned(),
        "Controller reachability does not establish target-local systemd state or effect causation"
            .to_owned(),
    ],
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpScope {
    schema: String,
    subject_identity: String,
    controller_vantage_identity: String,
    endpoint: String,
    method: String,
    redirect_policy: String,
    max_response_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpVantage {
    controller_vantage_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpResponsePayload {
    evidence_basis: EvidenceBasis,
    controller_vantage_identity: String,
    endpoint: String,
    method: String,
    redirect_policy: String,
    status: u16,
    body_sha256: Sha256Digest,
    body_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticIdentityValue {
    id: String,
    version: String,
    digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpThresholdPolicy {
    schema: String,
    fixture_run_id: String,
    subject_identity: String,
    request_scope: SemanticIdentityValue,
    expected_status: u16,
    expected_body_sha256: Sha256Digest,
}

/// Typed rebuildable HTTP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpEndpointProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Exact governed subject.
    pub subject: String,
    /// Exact controller-vantage identity.
    pub controller_vantage_identity: String,
    /// Literal endpoint locator.
    pub endpoint: String,
    /// Observed HTTP status.
    pub status: u16,
    /// Exact observed body digest.
    pub body_sha256: Sha256Digest,
    /// Number of bounded body bytes hashed.
    pub body_bytes: u32,
}

impl ProfileProjection for HttpEndpointProjection {
    fn profile(&self) -> &crate::ProfileKey {
        &self.profile
    }

    fn ordinal(&self) -> u32 {
        self.ordinal
    }

    fn canonical_json(&self) -> Value {
        json!({
            "profile": self.profile,
            "ordinal": self.ordinal,
            "subject": self.subject,
            "controller_vantage_identity": self.controller_vantage_identity,
            "endpoint": self.endpoint,
            "status": self.status,
            "body_sha256": self.body_sha256,
            "body_bytes": self.body_bytes,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ProfileModule for HttpEndpointProfile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &DESCRIPTOR
    }

    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal> {
        validate_binding(context, self.descriptor()).map(|_| ())
    }

    fn validate_threshold_policy(
        &self,
        context: &ValidationContext,
        policy: Option<&crate::ThresholdPolicyInput>,
    ) -> Result<(), ProfileRefusal> {
        validate_threshold_policy_binding(context, policy).map(|_| ())
    }

    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult {
        let (scope, vantage) = validate_binding(context, self.descriptor())?;
        let admitted = validate_common(self.descriptor(), context, report)?;
        if admitted.status == SemanticReportStatus::Failed {
            return Ok(admitted);
        }
        validate_cardinality(context, self.descriptor(), &admitted)?;
        for observation in &admitted.observations {
            let payload: HttpResponsePayload = serde_json::from_value(observation.payload.clone())
                .map_err(|error| invalid_payload(context, self.descriptor(), error.to_string()))?;
            validate_basis(self.descriptor(), context, &payload.evidence_basis)?;
            if payload.evidence_basis.capabilities_used != admitted.used_capabilities {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "payload capabilities differ from report used_capabilities",
                ));
            }
            if observation.observed_at != admitted.observed_at {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "HTTP observation time must equal report observation time",
                ));
            }
            if payload.controller_vantage_identity != vantage.controller_vantage_identity
                || payload.controller_vantage_identity != scope.controller_vantage_identity
                || payload.endpoint != scope.endpoint
                || payload.method != scope.method
                || payload.redirect_policy != scope.redirect_policy
                || payload.body_bytes > scope.max_response_bytes
            {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "HTTP payload differs from the exact request scope or response bound",
                ));
            }
        }
        Ok(admitted)
    }

    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        let mut rows: Vec<Box<dyn ProfileProjection>> =
            Vec::with_capacity(report.observations.len());
        for observation in &report.observations {
            let payload: HttpResponsePayload = serde_json::from_value(observation.payload.clone())
                .map_err(|error| projection_failure(report, error.to_string()))?;
            rows.push(Box::new(HttpEndpointProjection {
                profile: report.profile.clone(),
                ordinal: observation.ordinal,
                subject: observation.subject.clone(),
                controller_vantage_identity: payload.controller_vantage_identity,
                endpoint: payload.endpoint,
                status: payload.status,
                body_sha256: payload.body_sha256,
                body_bytes: payload.body_bytes,
            }));
        }
        Ok(rows)
    }

    fn detectors(&self) -> &'static [&'static dyn Detector] {
        &DETECTORS
    }
}

fn validate_binding(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
) -> Result<(HttpScope, HttpVantage), ProfileRefusal> {
    if Sha256Digest::parse(context.request_subject.clone()).is_err() {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::SubjectEscape,
            "HTTP subject must be an algorithm-qualified SHA-256 identity",
        ));
    }
    if context.scope.kind != "http_endpoint" {
        return Err(scope_refusal(
            context,
            descriptor,
            "HTTP scope kind must be http_endpoint",
        ));
    }
    let scope: HttpScope =
        serde_json::from_value(context.scope.value.clone()).map_err(|error| {
            scope_refusal(context, descriptor, &format!("invalid HTTP scope: {error}"))
        })?;
    if scope.schema != "nq.operator_beta.http_endpoint_scope.v1"
        || scope.subject_identity != context.request_subject
        || scope.controller_vantage_identity.is_empty()
        || scope.controller_vantage_identity.len() > 512
        || !valid_endpoint(&scope.endpoint)
        || scope.method != "GET"
        || scope.redirect_policy != "refuse"
        || scope.max_response_bytes == 0
        || scope.max_response_bytes > 65_536
    {
        return Err(scope_refusal(
            context,
            descriptor,
            "HTTP scope violates the closed endpoint and response bounds",
        ));
    }
    if context.vantage.kind != "controller_http" {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "HTTP vantage kind must be controller_http",
        ));
    }
    let vantage: HttpVantage =
        serde_json::from_value(context.vantage.value.clone()).map_err(|error| {
            ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Profile,
                ProfileRefusalCode::VantageEscape,
                format!("invalid controller HTTP vantage: {error}"),
            )
        })?;
    if vantage.controller_vantage_identity != scope.controller_vantage_identity
        || vantage.controller_vantage_identity.is_empty()
        || vantage.controller_vantage_identity.len() > 512
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "HTTP vantage identity differs from the request scope",
        ));
    }
    Ok((scope, vantage))
}

fn validate_threshold_policy_binding(
    context: &ValidationContext,
    input: Option<&crate::ThresholdPolicyInput>,
) -> Result<HttpThresholdPolicy, ProfileRefusal> {
    let descriptor = &DESCRIPTOR;
    validate_binding(context, descriptor)?;
    let Some(input) = input else {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            "HTTP profile requires one exact external threshold policy",
        ));
    };
    input.verify_digest().map_err(|error| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            error.clone(),
        )
    })?;
    let policy: HttpThresholdPolicy =
        serde_json::from_value(input.value.clone()).map_err(|error| {
            ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Profile,
                ProfileRefusalCode::InvalidPayload,
                format!("invalid HTTP threshold policy: {error}"),
            )
        })?;
    let profile = json!({
        "id": descriptor.profile.id,
        "version": descriptor.profile.version.to_string(),
        "digest": descriptor.digest().map_err(|error| ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            error.to_string(),
        ))?.as_str(),
    });
    let request_scope = SemanticIdentityValue {
        id: format!("nq.scope.{}", context.scope.kind),
        version: descriptor.profile.version.to_string(),
        digest: nq_protocol::semantic_digest(&json!({
            "schema": "nq.diagnostic_scope.v1",
            "subject": context.request_subject,
            "scope": context.scope,
            "profile": profile,
        }))
        .map_err(|error| {
            ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Profile,
                ProfileRefusalCode::InvalidPayload,
                error.to_string(),
            )
        })?,
    };
    if input.id != THRESHOLD_POLICY_ID
        || input.version != policy.fixture_run_id
        || input.version.is_empty()
        || input.version.len() > 255
        || policy.schema != THRESHOLD_POLICY_SCHEMA
        || policy.subject_identity != context.request_subject
        || policy.request_scope != request_scope
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            "HTTP threshold policy violates its exact identity or request binding",
        ));
    }
    Ok(policy)
}
fn valid_endpoint(value: &str) -> bool {
    value.len() <= 2_048
        && value.starts_with("http://")
        && !value.contains('@')
        && !value.contains('#')
        && value.ends_with("/healthz")
}

fn validate_cardinality(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    report: &ValidatedReport,
) -> Result<(), ProfileRefusal> {
    let coverage = report.coverage.get("http_endpoint_response").copied();
    match (report.status, coverage, report.observations.len()) {
        (SemanticReportStatus::Complete, Some(SemanticCoverageState::Complete), 1)
        | (SemanticReportStatus::Partial, Some(SemanticCoverageState::Partial), 0 | 1) => Ok(()),
        _ => Err(inconsistent(
            context,
            descriptor,
            "HTTP report status, coverage, and observation cardinality disagree",
        )),
    }
}

fn scope_refusal(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    message: &str,
) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Profile,
        ProfileRefusalCode::ScopeEscape,
        message,
    )
}

fn invalid_payload(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    message: impl Into<String>,
) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Observation,
        ProfileRefusalCode::InvalidPayload,
        message,
    )
}

fn inconsistent(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    message: &str,
) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Report,
        ProfileRefusalCode::InconsistentReport,
        message,
    )
}

fn projection_failure(report: &ValidatedReport, error: String) -> ProfileRefusal {
    ProfileRefusal {
        instance_id: report.instance_id.clone(),
        profile: report.profile.clone(),
        boundary: RefusalBoundary::Observation,
        code: ProfileRefusalCode::InvalidPayload,
        message: "admitted HTTP payload could not be projected".to_owned(),
        details: BTreeMap::from([("error".to_owned(), error)]),
    }
}

/// Compiled HTTP endpoint postcondition detector.
#[derive(Debug)]
pub struct HttpPostconditionDetector;

/// Singleton detector revision.
pub static HTTP_POSTCONDITION_DETECTOR: HttpPostconditionDetector = HttpPostconditionDetector;

static DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> = LazyLock::new(|| DetectorDescriptor {
    schema: DETECTOR_DESCRIPTOR_SCHEMA.to_owned(),
    id: DETECTOR_ID.to_owned(),
    version: 1,
    profile: DESCRIPTOR.profile.clone(),
    profile_digest: DESCRIPTOR
        .digest()
        .unwrap_or_else(|error| panic!("compiled HTTP descriptor must canonicalize: {error}")),
    title: "HTTP endpoint postcondition mismatch".to_owned(),
    condition: "http_endpoint_postcondition_not_met".to_owned(),
    parameters: DetectorRuleParameters::HttpEndpointPostcondition {
        threshold_policy_schema: THRESHOLD_POLICY_SCHEMA.to_owned(),
    },
});

static DETECTORS: [&'static dyn Detector; 1] = [&HTTP_POSTCONDITION_DETECTOR];

impl Detector for HttpPostconditionDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &DETECTOR_DESCRIPTOR
    }

    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult {
        let descriptor = self.descriptor();
        let Some(policy_input) = input.threshold_policy else {
            return cannot_evaluate(
                input,
                descriptor,
                "the exact HTTP threshold policy is unavailable",
                "missing_threshold_policy",
            );
        };
        if let Err(error) = policy_input.verify_digest() {
            return cannot_evaluate(input, descriptor, &error, "policy_digest_mismatch");
        }
        let Ok(policy) = serde_json::from_value::<HttpThresholdPolicy>(policy_input.value.clone())
        else {
            return cannot_evaluate(
                input,
                descriptor,
                "the HTTP threshold policy has the wrong closed shape",
                "invalid_threshold_policy",
            );
        };
        if policy_input.id != THRESHOLD_POLICY_ID
            || policy_input.version != policy.fixture_run_id
            || policy.schema != THRESHOLD_POLICY_SCHEMA
        {
            return cannot_evaluate(
                input,
                descriptor,
                "the HTTP threshold policy identity does not match its content",
                "threshold_policy_identity_mismatch",
            );
        }
        let Some(occurrence) =
            newest_current_report(input, descriptor, &DESCRIPTOR, "http_endpoint_response")
        else {
            return cannot_evaluate(
                input,
                descriptor,
                "no complete current HTTP testimony is available",
                "missing_or_stale_testimony",
            );
        };
        let Some(observation) = occurrence.report.observations.first() else {
            return cannot_evaluate(
                input,
                descriptor,
                "complete HTTP testimony has no observation",
                "inconsistent_observation",
            );
        };
        let Ok(payload) =
            serde_json::from_value::<HttpResponsePayload>(observation.payload.clone())
        else {
            return cannot_evaluate(
                input,
                descriptor,
                "admitted HTTP testimony cannot be projected",
                "projection_failure",
            );
        };
        let Ok(scope_identity) = diagnostic_scope_identity(
            &occurrence.report,
            &observation.subject,
            &payload.evidence_basis.scope,
        ) else {
            return cannot_evaluate(
                input,
                descriptor,
                "HTTP request scope cannot be identified",
                "scope_identity_failure",
            );
        };
        if policy.subject_identity != observation.subject || policy.request_scope != scope_identity
        {
            return cannot_evaluate(
                input,
                descriptor,
                "HTTP threshold policy is bound to another subject or scope",
                "policy_binding_mismatch",
            );
        }
        let mismatch = payload.status != policy.expected_status
            || payload.body_sha256 != policy.expected_body_sha256;
        detector_result(
            input,
            descriptor,
            occurrence,
            observation,
            mismatch,
            if mismatch {
                "the observed HTTP response differs from the admitted policy"
            } else {
                "the observed HTTP response equals the admitted policy"
            },
        )
    }
}

fn newest_current_report<'a>(
    input: &'a DetectorInput<'a>,
    descriptor: &DetectorDescriptor,
    profile: &ProfileDescriptor,
    coverage: &str,
) -> Option<&'a DetectorReport> {
    let occurrence = input.reports.iter().max_by_key(|row| row.report_sequence)?;
    let report = &occurrence.report;
    if report.profile != profile.profile
        || report.profile_digest != descriptor.profile_digest
        || report.status != SemanticReportStatus::Complete
        || report.coverage.get(coverage) != Some(&SemanticCoverageState::Complete)
    {
        return None;
    }
    let age = input.evaluated_at.signed_duration_since(report.observed_at);
    let reliance = Duration::seconds(i64::try_from(profile.freshness.reliance_seconds).ok()?);
    if age < Duration::zero() || age > reliance {
        return None;
    }
    Some(occurrence)
}

fn diagnostic_scope_identity(
    report: &ValidatedReport,
    subject: &str,
    scope: &ScopeGrant,
) -> Result<SemanticIdentityValue, String> {
    let profile = json!({
        "id": report.profile.id,
        "version": report.profile.version.to_string(),
        "digest": report.profile_digest.as_str(),
    });
    let digest = nq_protocol::semantic_digest(&json!({
        "schema": "nq.diagnostic_scope.v1",
        "subject": subject,
        "scope": scope,
        "profile": profile,
    }))
    .map_err(|error| error.to_string())?;
    Ok(SemanticIdentityValue {
        id: format!("nq.scope.{}", scope.kind),
        version: report.profile.version.to_string(),
        digest,
    })
}

fn cannot_evaluate(
    input: &DetectorInput<'_>,
    descriptor: &DetectorDescriptor,
    summary: &str,
    reason: &str,
) -> DetectorResult {
    DetectorResult::cannot_evaluate_with_details(
        input,
        descriptor,
        summary,
        vec!["Missing, stale, or invalid policy/evidence cannot establish absence".to_owned()],
        BTreeMap::from([("reason".to_owned(), reason.to_owned())]),
    )
}

fn detector_result(
    input: &DetectorInput<'_>,
    descriptor: &DetectorDescriptor,
    occurrence: &DetectorReport,
    observation: &crate::AdmittedObservation,
    mismatch: bool,
    summary: &str,
) -> DetectorResult {
    DetectorResult {
        state: if mismatch {
            DetectorState::Present
        } else {
            DetectorState::ExplicitlyAbsent
        },
        condition: descriptor.condition.clone(),
        summary: summary.to_owned(),
        evidence: vec![DetectorEvidence {
            report_id: occurrence.report_id.clone(),
            report_sequence: occurrence.report_sequence,
            report_digest: occurrence.report.report_digest.clone(),
            observation_ordinal: Some(observation.ordinal),
            observed_at: observation.observed_at,
        }],
        limitations: vec![
            "One controller-vantage response does not establish systemd state, global reachability, or effect causation"
                .to_owned(),
        ],
        refusal: None,
        watermark: input.watermark,
    }
}
