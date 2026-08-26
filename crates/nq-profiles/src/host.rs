//! `nq.host/v1`: bounded local host identity, uptime, and load testimony.

use std::{any::Any, collections::BTreeMap, sync::LazyLock};

use chrono::Duration;
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
    validation::{ReportInput, validate_basis, validate_common},
};

/// Stable profile identifier.
pub const PROFILE_ID: &str = "nq.host";
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 1;

/// Stateless local-host profile module.
#[derive(Debug)]
pub struct HostProfile;

/// Singleton module registered by the compile-time registry.
pub static MODULE: HostProfile = HostProfile;

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "host".to_owned(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Local host state".to_owned(),
    observation_kinds: vec![VocabularyTerm::new(
        "host_snapshot",
        "A bounded identity, uptime, CPU, and one-minute-load snapshot",
    )],
    coverage: vec![
        VocabularyTerm::new("host_identity", "The local kernel hostname"),
        VocabularyTerm::new("uptime", "Elapsed time since the local kernel booted"),
        VocabularyTerm::new("load", "CPU count and one-minute scheduler load"),
    ],
    subjects: SubjectRules {
        namespace: "host:".to_owned(),
        exact_request_subject: true,
    },
    scope_kinds: vec![VocabularyTerm::new("host", "One exact local host")],
    vantages: vec![VocabularyTerm::new(
        "local",
        "Observation from a process on the subject host",
    )],
    access_paths: vec![
        VocabularyTerm::new("procfs", "Linux procfs files opened by the helper"),
        VocabularyTerm::new("sysinfo", "Linux kernel system-information interfaces"),
        VocabularyTerm::new(
            "procfs_sysinfo",
            "A composite snapshot using both procfs and local kernel information",
        ),
    ],
    bases: vec![VocabularyTerm::new(
        "kernel_snapshot",
        "A bounded local kernel state snapshot",
    )],
    regimes: vec![VocabularyTerm::new(
        "normal",
        "Non-invasive observation without an induced workload",
    )],
    capabilities: vec![
        VocabularyTerm::new("read_procfs", "Read bounded local procfs state"),
        VocabularyTerm::new(
            "read_system_info",
            "Read bounded local kernel system information",
        ),
    ],
    freshness: FreshnessPolicy {
        reliance_seconds: 300,
        alignment_seconds: 30,
    },
    limits: CardinalityLimits {
        max_observations: 1,
        max_payload_bytes: 8_192,
        max_subject_bytes: 512,
        max_coverage_declarations: 3,
    },
    disturbance_assumptions: vec![
        "Reading kernel counters does not materially alter host load".to_owned(),
        "One local vantage does not establish external reachability or global health".to_owned(),
    ],
});

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HostSnapshotPayload {
    evidence_basis: EvidenceBasis,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    uptime_seconds: Option<u64>,
    #[serde(default)]
    cpu_count: Option<u32>,
    #[serde(default)]
    load_1m: Option<f64>,
    #[serde(default)]
    passive_sample: Option<nq_protocol::SignedPassiveHostLoadSampleV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HostScope {
    id: String,
}

/// Typed rebuildable view of one admitted host snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct HostSnapshotProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Validated host subject.
    pub subject: String,
    /// Kernel hostname, when covered.
    pub hostname: Option<String>,
    /// Elapsed seconds since boot, when covered.
    pub uptime_seconds: Option<u64>,
    /// Logical CPU count, when covered.
    pub cpu_count: Option<u32>,
    /// One-minute scheduler load, when covered.
    pub load_1m: Option<f64>,
    /// Exact validated evidence basis.
    pub evidence_basis: EvidenceBasis,
}

impl ProfileProjection for HostSnapshotProjection {
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
            "hostname": self.hostname,
            "uptime_seconds": self.uptime_seconds,
            "cpu_count": self.cpu_count,
            "load_1m": self.load_1m,
            "evidence_basis": self.evidence_basis,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ProfileModule for HostProfile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &DESCRIPTOR
    }

    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal> {
        validate_binding(context, self.descriptor())
    }

    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult {
        validate_binding(context, self.descriptor())?;
        let admitted = validate_common(self.descriptor(), context, report)?;
        if admitted.status == SemanticReportStatus::Failed {
            return Ok(admitted);
        }
        if admitted.observations.len() != 1 {
            return Err(inconsistent(
                context,
                "a non-failed host report requires exactly one host snapshot",
            ));
        }

        let observation = &admitted.observations[0];
        let payload = parse_payload(context, self.descriptor(), &observation.payload)?;
        validate_basis(self.descriptor(), context, &payload.evidence_basis)?;
        if payload.evidence_basis.capabilities_used != admitted.used_capabilities {
            return Err(inconsistent(
                context,
                "payload capabilities differ from report used_capabilities",
            ));
        }
        validate_access_capability(context, self.descriptor(), &payload.evidence_basis)?;
        validate_passive_sample(
            context,
            self.descriptor(),
            observation.observed_at,
            &payload,
        )?;

        if observation.observed_at != admitted.observed_at {
            return Err(inconsistent(
                context,
                "host snapshot time must equal the report observation time",
            ));
        }
        if payload.hostname.as_ref().is_some_and(String::is_empty)
            || payload
                .hostname
                .as_ref()
                .is_some_and(|value| value.len() > 255)
        {
            return Err(invalid_payload(
                context,
                self.descriptor(),
                "hostname must contain 1 through 255 UTF-8 bytes when present",
            ));
        }
        if payload.cpu_count == Some(0) {
            return Err(invalid_payload(
                context,
                self.descriptor(),
                "CPU count must be greater than zero when present",
            ));
        }
        if payload
            .load_1m
            .is_some_and(|value| !value.is_finite() || value.is_sign_negative())
        {
            return Err(invalid_payload(
                context,
                self.descriptor(),
                "one-minute load must be finite and non-negative when present",
            ));
        }

        require_coverage_consistency(
            context,
            &admitted,
            "host_identity",
            payload.hostname.is_some(),
        )?;
        require_coverage_consistency(
            context,
            &admitted,
            "uptime",
            payload.uptime_seconds.is_some(),
        )?;
        let load_fields =
            usize::from(payload.cpu_count.is_some()) + usize::from(payload.load_1m.is_some());
        let load_state = admitted.coverage.get("load").copied();
        match (load_state, load_fields) {
            (Some(SemanticCoverageState::Complete), 2)
            | (Some(SemanticCoverageState::Partial), 1 | 2)
            | (Some(SemanticCoverageState::Unavailable), 0) => {}
            _ => {
                return Err(inconsistent(
                    context,
                    "load coverage contradicts CPU count or load fields",
                ));
            }
        }

        Ok(admitted)
    }

    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        let mut rows: Vec<Box<dyn ProfileProjection>> =
            Vec::with_capacity(report.observations.len());
        for observation in &report.observations {
            let payload: HostSnapshotPayload = serde_json::from_value(observation.payload.clone())
                .map_err(|error| projection_failure(report, error.to_string()))?;
            rows.push(Box::new(HostSnapshotProjection {
                profile: report.profile.clone(),
                ordinal: observation.ordinal,
                subject: observation.subject.clone(),
                hostname: payload.hostname,
                uptime_seconds: payload.uptime_seconds,
                cpu_count: payload.cpu_count,
                load_1m: payload.load_1m,
                evidence_basis: payload.evidence_basis,
            }));
        }
        Ok(rows)
    }

    fn detectors(&self) -> &'static [&'static dyn Detector] {
        &DETECTORS
    }
}

fn validate_passive_sample(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    observed_at: chrono::DateTime<chrono::Utc>,
    payload: &HostSnapshotPayload,
) -> Result<(), ProfileRefusal> {
    let Some(sample) = &payload.passive_sample else {
        return Ok(());
    };
    if payload.evidence_basis.access_path != "procfs_sysinfo"
        || payload.evidence_basis.basis != "kernel_snapshot"
        || payload.evidence_basis.regime != "normal"
    {
        return Err(inconsistent(
            context,
            "passive sample must retain the exact underlying procfs/sysinfo kernel basis",
        ));
    }
    sample.validate_structure().map_err(|error| {
        invalid_payload(context, descriptor, "invalid passive sample custody")
            .with_detail("error", error)
    })?;
    let parsed_load = sample
        .payload
        .load_1m_token
        .parse::<f64>()
        .map_err(|error| {
            invalid_payload(context, descriptor, "invalid passive load token")
                .with_detail("error", error.to_string())
        })?;
    if sample.payload.binding != *context_request_binding(context)?
        || sample.payload.observed_at != observed_at
        || payload.load_1m != Some(parsed_load)
        || payload.cpu_count != Some(sample.payload.logical_cpu_count)
        || payload.hostname.is_some()
        || payload.uptime_seconds.is_some()
    {
        return Err(inconsistent(
            context,
            "passive sample raw facts or binding differ from the host snapshot projection",
        ));
    }
    Ok(())
}

fn validate_binding(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
) -> Result<(), ProfileRefusal> {
    if context.scope.kind != "host" {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "host scope kind must be host",
        ));
    }
    let scope: HostScope =
        serde_json::from_value(context.scope.value.clone()).map_err(|error| {
            ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Profile,
                ProfileRefusalCode::ScopeEscape,
                "host scope requires exactly one bounded id string",
            )
            .with_detail("error", error.to_string())
        })?;
    if scope.id.is_empty()
        || scope.id.len() > 255
        || context.request_subject != format!("host:{}", scope.id)
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "host scope does not correlate with its request subject or bounds",
        ));
    }
    if context.vantage.kind != "local" || context.vantage.value != json!({}) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "host vantage must be the empty local vantage",
        ));
    }
    Ok(())
}

/// Operational detector for load relative to logical CPU count.
#[derive(Debug)]
pub struct HostLoadPressureDetector;

/// Singleton detector revision.
pub static HOST_LOAD_PRESSURE_DETECTOR: HostLoadPressureDetector = HostLoadPressureDetector;

static HOST_LOAD_DESCRIPTOR: LazyLock<DetectorDescriptor> = LazyLock::new(|| DetectorDescriptor {
    schema: DETECTOR_DESCRIPTOR_SCHEMA.to_owned(),
    id: "nq.host.load_pressure".to_owned(),
    version: 1,
    profile: DESCRIPTOR.profile.clone(),
    profile_digest: DESCRIPTOR
        .digest()
        .unwrap_or_else(|error| panic!("compiled host descriptor must canonicalize: {error}")),
    title: "Sustained host load pressure".to_owned(),
    condition: "host_load_pressure".to_owned(),
    parameters: DetectorRuleParameters::LoadPressure {
        normalized_load_threshold_millis: 2000,
    },
});

static DETECTORS: [&'static dyn Detector; 1] = [&HOST_LOAD_PRESSURE_DETECTOR];

impl Detector for HostLoadPressureDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &HOST_LOAD_DESCRIPTOR
    }

    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult {
        let descriptor = self.descriptor();
        let occurrence = match newest_current_report(input, descriptor) {
            Ok(occurrence) => occurrence,
            Err(result) => return *result,
        };
        let report = &occurrence.report;

        let Some(observation) = report
            .observations
            .iter()
            .find(|observation| observation.kind == "host_snapshot")
        else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "the newest report has no host snapshot",
                vec!["Missing observations cannot establish absence".to_owned()],
                BTreeMap::from([
                    ("observation_kind".to_owned(), "host_snapshot".to_owned()),
                    ("reason".to_owned(), "missing_observation".to_owned()),
                ]),
            );
        };
        let Ok(payload) =
            serde_json::from_value::<HostSnapshotPayload>(observation.payload.clone())
        else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "the admitted host snapshot cannot be projected",
                vec!["Projection failure requires operator inspection".to_owned()],
                BTreeMap::from([
                    ("observation_kind".to_owned(), "host_snapshot".to_owned()),
                    ("reason".to_owned(), "projection_failure".to_owned()),
                ]),
            );
        };
        let (Some(cpu_count), Some(load_1m)) = (payload.cpu_count, payload.load_1m) else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "complete load coverage has no complete load value",
                vec!["Inconsistent admitted evidence cannot establish absence".to_owned()],
                BTreeMap::from([
                    ("reason".to_owned(), "inconsistent_observation".to_owned()),
                    ("required_fields".to_owned(), "cpu_count,load_1m".to_owned()),
                ]),
            );
        };

        let normalized_load = load_1m / f64::from(cpu_count);
        let threshold_millis = match descriptor.parameters {
            DetectorRuleParameters::LoadPressure {
                normalized_load_threshold_millis,
            } => normalized_load_threshold_millis,
        };
        let threshold = f64::from(threshold_millis) / 1000.0;
        let state = load_pressure_state(normalized_load, threshold_millis);
        DetectorResult {
            state,
            condition: descriptor.condition.clone(),
            summary: if state == DetectorState::Present {
                format!(
                    "one-minute load reached the detector threshold of {threshold:.2}x logical CPU count"
                )
            } else {
                "current complete coverage places one-minute load below the detector threshold"
                    .to_owned()
            },
            evidence: vec![DetectorEvidence {
                report_id: occurrence.report_id.clone(),
                report_sequence: occurrence.report_sequence,
                report_digest: report.report_digest.clone(),
                observation_ordinal: Some(observation.ordinal),
                observed_at: observation.observed_at,
            }],
            limitations: vec![
                "One scheduler snapshot does not identify the workload causing load".to_owned(),
            ],
            refusal: None,
            watermark: input.watermark,
        }
    }
}

/// Pure load-pressure decision, separated so a test can prove the threshold data
/// governs the verdict independently of the compiled descriptor.
fn load_pressure_state(normalized_load: f64, threshold_millis: u32) -> DetectorState {
    if normalized_load >= f64::from(threshold_millis) / 1000.0 {
        DetectorState::Present
    } else {
        DetectorState::ExplicitlyAbsent
    }
}

fn newest_current_report<'a>(
    input: &DetectorInput<'a>,
    descriptor: &DetectorDescriptor,
) -> Result<&'a DetectorReport, Box<DetectorResult>> {
    let Some(report) = input
        .reports
        .iter()
        .filter(|report| report.report.instance_id == input.instance_id)
        .max_by_key(|report| report.report_sequence)
    else {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "no admitted host testimony is available",
            vec!["Missing testimony cannot establish absence".to_owned()],
            BTreeMap::from([("reason".to_owned(), "missing_testimony".to_owned())]),
        )));
    };
    let admitted = &report.report;
    if admitted.profile != descriptor.profile
        || admitted.profile_digest != descriptor.profile_digest
    {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest testimony uses a different profile contract",
            vec!["Profile revisions are never silently combined".to_owned()],
            profile_contract_mismatch_details(admitted, descriptor),
        )));
    }
    if admitted.status != SemanticReportStatus::Complete
        || admitted.coverage.get("load") != Some(&SemanticCoverageState::Complete)
    {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest host testimony lacks complete load coverage",
            vec!["A newer partial or failed report is not shadowed by older success".to_owned()],
            incomplete_load_coverage_details(admitted),
        )));
    }

    let age = input
        .evaluated_at
        .signed_duration_since(admitted.observed_at);
    let reliance =
        Duration::seconds(i64::try_from(DESCRIPTOR.freshness.reliance_seconds).unwrap_or(i64::MAX));
    if age < Duration::zero() || age > reliance {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest host testimony is outside its freshness window",
            vec!["Staleness removes reliance; it does not negate testimony".to_owned()],
            invalid_freshness_details(age),
        )));
    }
    Ok(report)
}

fn profile_contract_mismatch_details(
    admitted: &ValidatedReport,
    descriptor: &DetectorDescriptor,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "actual_profile_digest".to_owned(),
            admitted.profile_digest.as_str().to_owned(),
        ),
        ("actual_profile_id".to_owned(), admitted.profile.id.clone()),
        (
            "actual_profile_version".to_owned(),
            admitted.profile.version.to_string(),
        ),
        (
            "expected_profile_digest".to_owned(),
            descriptor.profile_digest.as_str().to_owned(),
        ),
        (
            "expected_profile_id".to_owned(),
            descriptor.profile.id.clone(),
        ),
        (
            "expected_profile_version".to_owned(),
            descriptor.profile.version.to_string(),
        ),
        ("reason".to_owned(), "profile_contract_mismatch".to_owned()),
    ])
}

fn incomplete_load_coverage_details(admitted: &ValidatedReport) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "load_coverage_state".to_owned(),
            coverage_state_name(admitted.coverage.get("load")).to_owned(),
        ),
        ("reason".to_owned(), "incomplete_load_coverage".to_owned()),
        (
            "report_status".to_owned(),
            report_status_name(admitted.status).to_owned(),
        ),
    ])
}

fn invalid_freshness_details(age: Duration) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("age_seconds".to_owned(), age.num_seconds().to_string()),
        (
            "freshness_relation".to_owned(),
            if age < Duration::zero() {
                "future"
            } else {
                "stale"
            }
            .to_owned(),
        ),
        ("reason".to_owned(), "invalid_freshness".to_owned()),
        (
            "reliance_seconds".to_owned(),
            DESCRIPTOR.freshness.reliance_seconds.to_string(),
        ),
    ])
}

fn report_status_name(status: SemanticReportStatus) -> &'static str {
    match status {
        SemanticReportStatus::Complete => "complete",
        SemanticReportStatus::Partial => "partial",
        SemanticReportStatus::Failed => "failed",
    }
}

fn coverage_state_name(state: Option<&SemanticCoverageState>) -> &'static str {
    match state {
        Some(SemanticCoverageState::Complete) => "complete",
        Some(SemanticCoverageState::Partial) => "partial",
        Some(SemanticCoverageState::Unavailable) => "unavailable",
        None => "missing",
    }
}

fn parse_payload(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    value: &Value,
) -> Result<HostSnapshotPayload, ProfileRefusal> {
    serde_json::from_value(value.clone()).map_err(|error| {
        invalid_payload(
            context,
            descriptor,
            "host payload does not match nq.host/v1",
        )
        .with_detail("error", error.to_string())
    })
}

fn validate_access_capability(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    basis: &EvidenceBasis,
) -> Result<(), ProfileRefusal> {
    let required: &[&str] = match basis.access_path.as_str() {
        "procfs" => &["read_procfs"],
        "sysinfo" => &["read_system_info"],
        "procfs_sysinfo" => &["read_procfs", "read_system_info"],
        _ => return Ok(()),
    };
    if basis.capabilities_used.len() != required.len()
        || !required
            .iter()
            .all(|capability| basis.capabilities_used.contains(*capability))
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Observation,
            ProfileRefusalCode::CapabilityEscape,
            "host access path must declare exactly its exercised capabilities",
        )
        .with_detail("required", required.join(",")));
    }
    Ok(())
}

fn context_request_binding(
    context: &ValidationContext,
) -> Result<Box<nq_protocol::SubjectBinding>, ProfileRefusal> {
    Ok(Box::new(nq_protocol::SubjectBinding {
        subject: nq_protocol::SubjectId::new(context.request_subject.clone()).map_err(|error| {
            invalid_payload(context, &DESCRIPTOR, "invalid passive request subject")
                .with_detail("error", error.to_string())
        })?,
        scope: nq_protocol::ScopeBinding {
            kind: nq_protocol::ScopeKind::new(context.scope.kind.clone()).map_err(|error| {
                invalid_payload(context, &DESCRIPTOR, "invalid passive request scope")
                    .with_detail("error", error.to_string())
            })?,
            value: context.scope.value.clone(),
        },
        vantage: nq_protocol::VantageBinding {
            kind: nq_protocol::VantageKind::new(context.vantage.kind.clone()).map_err(|error| {
                invalid_payload(context, &DESCRIPTOR, "invalid passive request vantage")
                    .with_detail("error", error.to_string())
            })?,
            value: context.vantage.value.clone(),
        },
    }))
}

fn require_coverage_consistency(
    context: &ValidationContext,
    report: &ValidatedReport,
    coverage_name: &str,
    field_present: bool,
) -> Result<(), ProfileRefusal> {
    let state = report.coverage.get(coverage_name).copied();
    let consistent = matches!(
        (state, field_present),
        (
            Some(SemanticCoverageState::Complete | SemanticCoverageState::Partial),
            true
        ) | (Some(SemanticCoverageState::Unavailable), false)
    );
    if consistent {
        Ok(())
    } else {
        Err(inconsistent(
            context,
            &format!("{coverage_name} coverage contradicts its payload field"),
        ))
    }
}

fn inconsistent(context: &ValidationContext, message: &str) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        &DESCRIPTOR,
        RefusalBoundary::Report,
        ProfileRefusalCode::InconsistentReport,
        message,
    )
}

fn invalid_payload(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
    message: &str,
) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        descriptor,
        RefusalBoundary::Observation,
        ProfileRefusalCode::InvalidPayload,
        message,
    )
}

fn projection_failure(report: &ValidatedReport, error: String) -> ProfileRefusal {
    ProfileRefusal {
        instance_id: report.instance_id.clone(),
        profile: report.profile.clone(),
        boundary: RefusalBoundary::Observation,
        code: ProfileRefusalCode::InvalidPayload,
        message: "admitted host payload could not be projected".to_owned(),
        details: BTreeMap::from([("error".to_owned(), error)]),
    }
}

#[cfg(test)]
mod tests {
    use super::{DetectorState, load_pressure_state};

    #[test]
    fn load_pressure_state_is_parametric_in_the_threshold() {
        // Fixed normalized load; only the threshold moves the verdict. If
        // evaluation ignored the descriptor parameter and hard-coded a constant,
        // this would not hold for both thresholds.
        assert_eq!(load_pressure_state(2.5, 2000), DetectorState::Present);
        assert_eq!(
            load_pressure_state(2.5, 3000),
            DetectorState::ExplicitlyAbsent
        );
        // The boundary is inclusive at exactly the threshold.
        assert_eq!(load_pressure_state(2.0, 2000), DetectorState::Present);
        assert_eq!(
            load_pressure_state(1.999, 2000),
            DetectorState::ExplicitlyAbsent
        );
    }
}
