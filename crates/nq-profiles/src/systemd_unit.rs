//! `nq.systemd_unit/v1`: target-local bounded systemd unit testimony.

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
    operator_beta_subject::ServiceSubject,
    validation::{ReportInput, ScopeGrant, validate_basis, validate_common},
};

/// Stable profile identifier.
pub const PROFILE_ID: &str = "nq.systemd_unit";
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 1;
/// Exact accepted external policy schema.
pub const THRESHOLD_POLICY_SCHEMA: &str = "nq.operator_beta.systemd_unit_threshold_policy.v1";
/// Stable external policy family.
pub const THRESHOLD_POLICY_ID: &str = "nq.systemd_unit.postcondition.threshold_policy";
/// Stable compiled detector identifier.
pub const DETECTOR_ID: &str = "nq.systemd_unit.postcondition";

/// Stateless target-local systemd profile.
#[derive(Debug)]
pub struct SystemdUnitProfile;

/// Singleton module registered by the compile-time registry.
pub static MODULE: SystemdUnitProfile = SystemdUnitProfile;

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "systemd_unit".to_owned(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Target-local systemd unit state".to_owned(),
    observation_kinds: vec![VocabularyTerm::new(
        "systemd_unit_snapshot",
        "A bounded property snapshot for one exact systemd unit",
    )],
    coverage: vec![VocabularyTerm::new(
        "systemd_unit_state",
        "The requested systemd unit properties",
    )],
    subjects: SubjectRules {
        namespace: "sha256:".to_owned(),
        exact_request_subject: true,
    },
    scope_kinds: vec![VocabularyTerm::new(
        "systemd_unit",
        "One exact machine, unit, and requested property set",
    )],
    vantages: vec![VocabularyTerm::new(
        "target_local",
        "Observation by a process on the target machine",
    )],
    access_paths: vec![VocabularyTerm::new(
        "systemd_dbus",
        "The target-local org.freedesktop.systemd1 system bus interface",
    )],
    bases: vec![VocabularyTerm::new(
        "systemd_properties",
        "A bounded set of manager and unit properties",
    )],
    regimes: vec![VocabularyTerm::new(
        "normal",
        "Read-only target-local property acquisition",
    )],
    capabilities: vec![VocabularyTerm::new(
        "read_systemd_unit",
        "Read the exact bounded unit properties",
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
        "Reading systemd properties does not establish effect causation".to_owned(),
        "One target-local snapshot does not establish controller reachability".to_owned(),
    ],
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SystemdScope {
    schema: String,
    subject_identity: String,
    target_machine_identity: String,
    unit_name: String,
    unit_file_sha256: Sha256Digest,
    manager_interface: String,
    properties: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SystemdSnapshotPayload {
    evidence_basis: EvidenceBasis,
    target_machine_identity: String,
    unit_name: String,
    unit_file_sha256: Sha256Digest,
    manager_object_path: String,
    unit_object_path: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    unit_file_state: String,
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
struct SystemdThresholdPolicy {
    schema: String,
    fixture_run_id: String,
    service_subject: Value,
    subject_identity: String,
    request_scope: SemanticIdentityValue,
    expected_load_state: String,
    expected_active_state: String,
    expected_sub_state: String,
    expected_unit_file_state: String,
}

/// Typed rebuildable systemd snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdUnitProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Exact governed subject.
    pub subject: String,
    /// Exact target machine identity.
    pub target_machine_identity: String,
    /// Exact systemd unit name.
    pub unit_name: String,
    /// Exact installed unit-file digest.
    pub unit_file_sha256: Sha256Digest,
    /// Observed load state.
    pub load_state: String,
    /// Observed active state.
    pub active_state: String,
    /// Observed substate.
    pub sub_state: String,
    /// Observed unit-file state.
    pub unit_file_state: String,
}

impl ProfileProjection for SystemdUnitProjection {
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
            "target_machine_identity": self.target_machine_identity,
            "unit_name": self.unit_name,
            "unit_file_sha256": self.unit_file_sha256,
            "load_state": self.load_state,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
            "unit_file_state": self.unit_file_state,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ProfileModule for SystemdUnitProfile {
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
        let scope = validate_binding(context, self.descriptor())?;
        let admitted = validate_common(self.descriptor(), context, report)?;
        if admitted.status == SemanticReportStatus::Failed {
            return Ok(admitted);
        }
        validate_cardinality(context, self.descriptor(), &admitted)?;
        for observation in &admitted.observations {
            let payload: SystemdSnapshotPayload =
                serde_json::from_value(observation.payload.clone()).map_err(|error| {
                    invalid_payload(context, self.descriptor(), error.to_string())
                })?;
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
                    "systemd observation time must equal report observation time",
                ));
            }
            if payload.target_machine_identity != scope.target_machine_identity
                || payload.unit_name != scope.unit_name
                || payload.unit_file_sha256 != scope.unit_file_sha256
            {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "systemd payload target differs from the exact request scope",
                ));
            }
            for value in [
                &payload.manager_object_path,
                &payload.unit_object_path,
                &payload.load_state,
                &payload.active_state,
                &payload.sub_state,
                &payload.unit_file_state,
            ] {
                if value.is_empty() || value.len() > 512 {
                    return Err(invalid_payload(
                        context,
                        self.descriptor(),
                        "systemd state and object-path strings must contain 1 through 512 bytes",
                    ));
                }
            }
        }
        Ok(admitted)
    }

    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        let mut rows: Vec<Box<dyn ProfileProjection>> =
            Vec::with_capacity(report.observations.len());
        for observation in &report.observations {
            let payload: SystemdSnapshotPayload =
                serde_json::from_value(observation.payload.clone())
                    .map_err(|error| projection_failure(report, error.to_string()))?;
            rows.push(Box::new(SystemdUnitProjection {
                profile: report.profile.clone(),
                ordinal: observation.ordinal,
                subject: observation.subject.clone(),
                target_machine_identity: payload.target_machine_identity,
                unit_name: payload.unit_name,
                unit_file_sha256: payload.unit_file_sha256,
                load_state: payload.load_state,
                active_state: payload.active_state,
                sub_state: payload.sub_state,
                unit_file_state: payload.unit_file_state,
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
) -> Result<SystemdScope, ProfileRefusal> {
    if Sha256Digest::parse(context.request_subject.clone()).is_err() {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::SubjectEscape,
            "systemd subject must be an algorithm-qualified SHA-256 identity",
        ));
    }
    if context.scope.kind != "systemd_unit" {
        return Err(scope_refusal(
            context,
            descriptor,
            "systemd scope kind must be systemd_unit",
        ));
    }
    let scope: SystemdScope =
        serde_json::from_value(context.scope.value.clone()).map_err(|error| {
            scope_refusal(
                context,
                descriptor,
                &format!("invalid systemd scope: {error}"),
            )
        })?;
    let expected_properties = ["LoadState", "ActiveState", "SubState", "UnitFileState"];
    if scope.schema != "nq.operator_beta.systemd_unit_scope.v1"
        || scope.subject_identity != context.request_subject
        || scope.target_machine_identity.is_empty()
        || scope.target_machine_identity.len() > 512
        || !valid_unit_name(&scope.unit_name)
        || scope.manager_interface != "org.freedesktop.systemd1"
        || scope
            .properties
            .iter()
            .map(String::as_str)
            .ne(expected_properties)
    {
        return Err(scope_refusal(
            context,
            descriptor,
            "systemd scope violates the closed target and property binding",
        ));
    }
    if context.vantage.kind != "target_local" || context.vantage.value != json!({}) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "systemd vantage must be empty target_local",
        ));
    }
    Ok(scope)
}

#[allow(clippy::too_many_lines)]
fn validate_threshold_policy_binding(
    context: &ValidationContext,
    input: Option<&crate::ThresholdPolicyInput>,
) -> Result<SystemdThresholdPolicy, ProfileRefusal> {
    let descriptor = &DESCRIPTOR;
    validate_binding(context, descriptor)?;
    let Some(input) = input else {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            "systemd profile requires one exact external threshold policy",
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
    let policy: SystemdThresholdPolicy =
        serde_json::from_value(input.value.clone()).map_err(|error| {
            ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Profile,
                ProfileRefusalCode::InvalidPayload,
                format!("invalid systemd threshold policy: {error}"),
            )
        })?;
    let service_subject = ServiceSubject::parse(&policy.service_subject).map_err(|error| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            error,
        )
    })?;
    let subject_identity = service_subject.identity().map_err(|error| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            error,
        )
    })?;
    let scope: SystemdScope = serde_json::from_value(context.scope.value.clone())
        .map_err(|_| scope_refusal(context, descriptor, "invalid systemd scope"))?;
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
    let expected_values = [
        &policy.expected_load_state,
        &policy.expected_active_state,
        &policy.expected_sub_state,
        &policy.expected_unit_file_state,
    ];
    if input.id != THRESHOLD_POLICY_ID
        || input.version != policy.fixture_run_id
        || input.version.is_empty()
        || input.version.len() > 255
        || policy.schema != THRESHOLD_POLICY_SCHEMA
        || service_subject.fixture_run_id != policy.fixture_run_id
        || service_subject.target_machine_identity != scope.target_machine_identity
        || service_subject.unit_name != scope.unit_name
        || service_subject.unit_file_sha256 != scope.unit_file_sha256
        || subject_identity != context.request_subject
        || policy.subject_identity != context.request_subject
        || policy.request_scope != request_scope
        || expected_values
            .iter()
            .any(|value| value.is_empty() || value.len() > 512)
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::InvalidPayload,
            "systemd threshold policy violates its exact identity, binding, or value bounds",
        ));
    }
    Ok(policy)
}
fn valid_unit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.ends_with(".service")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@:-".contains(&byte))
}

fn validate_cardinality(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    report: &ValidatedReport,
) -> Result<(), ProfileRefusal> {
    let coverage = report.coverage.get("systemd_unit_state").copied();
    match (report.status, coverage, report.observations.len()) {
        (SemanticReportStatus::Complete, Some(SemanticCoverageState::Complete), 1)
        | (SemanticReportStatus::Partial, Some(SemanticCoverageState::Partial), 0 | 1) => Ok(()),
        _ => Err(inconsistent(
            context,
            descriptor,
            "systemd report status, coverage, and observation cardinality disagree",
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
        message: "admitted systemd payload could not be projected".to_owned(),
        details: BTreeMap::from([("error".to_owned(), error)]),
    }
}

/// Compiled systemd postcondition detector.
#[derive(Debug)]
pub struct SystemdPostconditionDetector;

/// Singleton detector revision.
pub static SYSTEMD_POSTCONDITION_DETECTOR: SystemdPostconditionDetector =
    SystemdPostconditionDetector;

static DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> = LazyLock::new(|| DetectorDescriptor {
    schema: DETECTOR_DESCRIPTOR_SCHEMA.to_owned(),
    id: DETECTOR_ID.to_owned(),
    version: 1,
    profile: DESCRIPTOR.profile.clone(),
    profile_digest: DESCRIPTOR
        .digest()
        .unwrap_or_else(|error| panic!("compiled systemd descriptor must canonicalize: {error}")),
    title: "Systemd unit postcondition mismatch".to_owned(),
    condition: "systemd_unit_postcondition_not_met".to_owned(),
    parameters: DetectorRuleParameters::SystemdUnitPostcondition {
        threshold_policy_schema: THRESHOLD_POLICY_SCHEMA.to_owned(),
    },
});

static DETECTORS: [&'static dyn Detector; 1] = [&SYSTEMD_POSTCONDITION_DETECTOR];

impl Detector for SystemdPostconditionDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &DETECTOR_DESCRIPTOR
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult {
        let descriptor = self.descriptor();
        let Some(policy_input) = input.threshold_policy else {
            return cannot_evaluate(
                input,
                descriptor,
                "the exact systemd threshold policy is unavailable",
                "missing_threshold_policy",
            );
        };
        if let Err(error) = policy_input.verify_digest() {
            return cannot_evaluate(input, descriptor, &error, "policy_digest_mismatch");
        }
        let Ok(policy) =
            serde_json::from_value::<SystemdThresholdPolicy>(policy_input.value.clone())
        else {
            return cannot_evaluate(
                input,
                descriptor,
                "the systemd threshold policy has the wrong closed shape",
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
                "the systemd threshold policy identity does not match its content",
                "threshold_policy_identity_mismatch",
            );
        }
        let Some(occurrence) =
            newest_current_report(input, descriptor, &DESCRIPTOR, "systemd_unit_state")
        else {
            return cannot_evaluate(
                input,
                descriptor,
                "no complete current systemd testimony is available",
                "missing_or_stale_testimony",
            );
        };
        let Some(observation) = occurrence.report.observations.first() else {
            return cannot_evaluate(
                input,
                descriptor,
                "complete systemd testimony has no observation",
                "inconsistent_observation",
            );
        };
        let Ok(payload) =
            serde_json::from_value::<SystemdSnapshotPayload>(observation.payload.clone())
        else {
            return cannot_evaluate(
                input,
                descriptor,
                "admitted systemd testimony cannot be projected",
                "projection_failure",
            );
        };
        let Ok(service_subject) = ServiceSubject::parse(&policy.service_subject) else {
            return cannot_evaluate(
                input,
                descriptor,
                "the retained service-subject preimage has the wrong closed shape",
                "service_subject_invalid",
            );
        };
        if service_subject.fixture_run_id != policy.fixture_run_id
            || service_subject.identity().ok().as_deref() != Some(&observation.subject)
            || service_subject.target_machine_identity != payload.target_machine_identity
            || service_subject.unit_name != payload.unit_name
            || service_subject.unit_file_sha256 != payload.unit_file_sha256
        {
            return cannot_evaluate(
                input,
                descriptor,
                "the retained service-subject preimage does not bind the admitted testimony",
                "service_subject_identity_mismatch",
            );
        }
        let Ok(scope_identity) = diagnostic_scope_identity(
            &occurrence.report,
            &observation.subject,
            &payload.evidence_basis.scope,
        ) else {
            return cannot_evaluate(
                input,
                descriptor,
                "systemd request scope cannot be identified",
                "scope_identity_failure",
            );
        };
        if policy.subject_identity != observation.subject || policy.request_scope != scope_identity
        {
            return cannot_evaluate(
                input,
                descriptor,
                "systemd threshold policy is bound to another subject or scope",
                "policy_binding_mismatch",
            );
        }
        let mismatch = payload.load_state != policy.expected_load_state
            || payload.active_state != policy.expected_active_state
            || payload.sub_state != policy.expected_sub_state
            || payload.unit_file_state != policy.expected_unit_file_state;
        detector_result(
            input,
            descriptor,
            occurrence,
            observation,
            mismatch,
            if mismatch {
                "the observed systemd unit tuple differs from the admitted policy"
            } else {
                "the observed systemd unit tuple equals the admitted policy"
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
    let occurrence = input
        .reports
        .iter()
        .filter(|row| row.report.instance_id == input.instance_id)
        .max_by_key(|row| row.report_sequence)?;
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
    let profile_digest = report.profile_digest.as_str();
    let profile = json!({
        "id": report.profile.id,
        "version": report.profile.version.to_string(),
        "digest": profile_digest,
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
            "One target-local systemd snapshot does not establish HTTP reachability or effect causation"
                .to_owned(),
        ],
        refusal: None,
        watermark: input.watermark,
    }
}
