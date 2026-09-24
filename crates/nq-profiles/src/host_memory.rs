//! `nq.host_memory/v1`: bounded local testimony about kernel memory pressure
//! stall accounting (PSI) for one exact machine.
//!
//! The condition is defined on the kernel's own `some avg60` figure from
//! `/proc/pressure/memory`, read in one cut. It is not a memory-sufficiency,
//! OOM-risk, swap-health, or service-impact claim, and "absent" means only
//! that the decaying stall share is below the threshold now.

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

/// Profile identifier.
pub const PROFILE_ID: &str = "nq.host_memory";
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 1;
/// Detector identifier.
pub const DETECTOR_ID: &str = "nq.host_memory.pressure_stall";
/// Scope kind.
pub const SCOPE_KIND: &str = "host_memory";
/// Exact scope value schema.
pub const SCOPE_SCHEMA: &str = "nq.host_memory_scope.v1";
/// Subject namespace (`host:<machine-id>`).
pub const SUBJECT_PREFIX: &str = "host:";
/// Observation kind.
pub const OBSERVATION_KIND: &str = "memory_pressure_snapshot";
/// The one coverage class.
pub const COVERAGE_KIND: &str = "memory_pressure_stall";
/// Controlled access path.
pub const ACCESS_PATH: &str = "procfs_pressure";
/// Required capabilities; partial grants are refused.
pub const CAPABILITIES: [&str; 2] = ["read_machine_identity", "read_procfs"];
/// Compiled threshold on `some avg60`, in hundredths of a percent (10.00 %).
pub const SOME_AVG60_THRESHOLD_CENTIPERCENT: u32 = 1_000;
/// Compiled warm-up guard: below this boot age the averages understate.
pub const MINIMUM_BOOT_AGE_SECONDS: u32 = 180;
/// Largest counter accepted in a payload (I-JSON safe integer).
pub const MAX_SAFE_COUNTER: u64 = (1 << 53) - 1;

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| {
    ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "host_memory".to_owned(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Local kernel memory pressure stall".to_owned(),
    observation_kinds: vec![VocabularyTerm::new(
        OBSERVATION_KIND,
        "One read of /proc/pressure/memory with the boot age at the read",
    )],
    coverage: vec![VocabularyTerm::new(
        COVERAGE_KIND,
        "Kernel PSI memory some/full averages and totals",
    )],
    subjects: SubjectRules {
        namespace: SUBJECT_PREFIX.to_owned(),
        exact_request_subject: true,
    },
    scope_kinds: vec![VocabularyTerm::new(
        SCOPE_KIND,
        "One exact machine identity",
    )],
    vantages: vec![VocabularyTerm::new(
        "local",
        "Observation from a process on the machine whose kernel is read",
    )],
    access_paths: vec![VocabularyTerm::new(
        ACCESS_PATH,
        "A bounded read-only open of /proc/pressure/memory",
    )],
    bases: vec![VocabularyTerm::new(
        "kernel_snapshot",
        "A bounded local kernel accounting snapshot",
    )],
    regimes: vec![VocabularyTerm::new(
        "normal",
        "Read-only observation that registers no PSI trigger and induces no load",
    )],
    capabilities: vec![
        VocabularyTerm::new(CAPABILITIES[0], "Read /etc/machine-id"),
        VocabularyTerm::new(CAPABILITIES[1], "Read bounded local procfs state"),
    ],
    freshness: FreshnessPolicy {
        reliance_seconds: 120,
        alignment_seconds: 0,
    },
    limits: CardinalityLimits {
        max_observations: 1,
        max_payload_bytes: 8_192,
        max_subject_bytes: 64,
        max_coverage_declarations: 1,
    },
    disturbance_assumptions: vec![
        "Reading PSI averages does not alter memory state".to_owned(),
        "One PSI cut establishes a kernel-reported stall share only; it is not a memory sufficiency, OOM-risk, swap, or service-impact claim".to_owned(),
    ],
}
});

/// Exact scope value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMemoryScope {
    /// Must equal [`SCOPE_SCHEMA`].
    pub schema: String,
    /// 32 lowercase hex characters from `/etc/machine-id`.
    pub machine_id: String,
}

/// One PSI line, in exact integer hundredths of a percent and microseconds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PressureLine {
    /// `avg10` in hundredths of a percent.
    pub avg10_centipercent: u32,
    /// `avg60` in hundredths of a percent.
    pub avg60_centipercent: u32,
    /// `avg300` in hundredths of a percent.
    pub avg300_centipercent: u32,
    /// Cumulative stall microseconds since boot (recorded, never differenced).
    pub total_microseconds: u64,
}

/// Payload of one `memory_pressure_snapshot` observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPressurePayload {
    /// Exact evidence basis.
    pub evidence_basis: EvidenceBasis,
    /// Machine identity read during this observation.
    pub machine_id: String,
    /// `CLOCK_BOOTTIME` seconds at the read; the warm-up guard input.
    pub boot_age_seconds: u64,
    /// The `some` line.
    pub some: PressureLine,
    /// The `full` line.
    pub full: PressureLine,
}

/// Typed rebuildable view of one admitted snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryPressureProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Validated subject.
    pub subject: String,
    /// Exact validated payload.
    pub payload: MemoryPressurePayload,
}

impl ProfileProjection for MemoryPressureProjection {
    fn profile(&self) -> &crate::ProfileKey {
        &self.profile
    }
    fn ordinal(&self) -> u32 {
        self.ordinal
    }
    fn canonical_json(&self) -> Value {
        json!({"profile": self.profile, "ordinal": self.ordinal, "subject": self.subject, "payload": self.payload})
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Expected subject for a machine id.
#[must_use]
pub fn subject_for(machine_id: &str) -> String {
    format!("{SUBJECT_PREFIX}{machine_id}")
}

/// Parse one PSI percentage (`12.34`) into hundredths, refusing anything else.
///
/// # Errors
///
/// Returns a message when the text is not `<digits>.<two digits>` within 100.00.
pub fn parse_centipercent(text: &str) -> Result<u32, String> {
    let (whole, fraction) = text
        .split_once('.')
        .ok_or_else(|| format!("{text}: expected two decimals"))?;
    if whole.is_empty()
        || whole.len() > 3
        || fraction.len() != 2
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("{text}: not a PSI percentage"));
    }
    let value = whole.parse::<u32>().map_err(|e| e.to_string())? * 100
        + fraction.parse::<u32>().map_err(|e| e.to_string())?;
    if value > 10_000 {
        return Err(format!("{text}: exceeds 100.00"));
    }
    Ok(value)
}

/// Parse the two-line `/proc/pressure/memory` text.
///
/// # Errors
///
/// Returns a message when either line is missing, malformed, or out of range.
pub fn parse_pressure_file(text: &str) -> Result<(PressureLine, PressureLine), String> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(kind) = fields.next() else { continue };
        let mut values: BTreeMap<&str, &str> = BTreeMap::new();
        for field in fields {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| format!("{line}: field without '='"))?;
            if value.starts_with('+') || values.insert(key, value).is_some() {
                return Err(format!("{line}: duplicate or signed field {key}"));
            }
        }
        let get = |key: &str| {
            values
                .get(key)
                .copied()
                .ok_or_else(|| format!("{line}: missing {key}"))
        };
        let parsed = PressureLine {
            avg10_centipercent: parse_centipercent(get("avg10")?)?,
            avg60_centipercent: parse_centipercent(get("avg60")?)?,
            avg300_centipercent: parse_centipercent(get("avg300")?)?,
            total_microseconds: get("total")?
                .parse::<u64>()
                .map_err(|e| format!("{line}: total: {e}"))?,
        };
        match kind {
            "some" if some.is_none() => some = Some(parsed),
            "full" if full.is_none() => full = Some(parsed),
            other => return Err(format!("unexpected or duplicate PSI line kind {other}")),
        }
    }
    match (some, full) {
        (Some(some), Some(full)) => Ok((some, full)),
        _ => Err("PSI file must contain both some and full lines".to_owned()),
    }
}

/// Validate a scope value against the request subject.
///
/// # Errors
///
/// Returns a message describing the first violated rule.
pub fn validate_scope_value(
    value: &Value,
    request_subject: &str,
) -> Result<HostMemoryScope, String> {
    let scope: HostMemoryScope = serde_json::from_value(value.clone())
        .map_err(|error| format!("scope must be exactly {SCOPE_SCHEMA}: {error}"))?;
    if scope.schema != SCOPE_SCHEMA {
        return Err(format!("scope schema must be {SCOPE_SCHEMA}"));
    }
    if !is_lower_hex(&scope.machine_id, 32) {
        return Err("machine_id must be 32 lowercase hex characters".to_owned());
    }
    if request_subject != subject_for(&scope.machine_id) {
        return Err("subject must equal host:<machine_id>".to_owned());
    }
    Ok(scope)
}

/// Validate payload consistency against the scope.
///
/// # Errors
///
/// Returns a message describing the first violated rule.
pub fn validate_payload_against_scope(
    payload: &MemoryPressurePayload,
    scope: &HostMemoryScope,
) -> Result<(), String> {
    if payload.machine_id != scope.machine_id {
        return Err("payload machine_id must equal the request scope".to_owned());
    }
    for line in [&payload.some, &payload.full] {
        if line.avg10_centipercent > 10_000
            || line.avg60_centipercent > 10_000
            || line.avg300_centipercent > 10_000
        {
            return Err("PSI averages must not exceed 100.00".to_owned());
        }
        if line.total_microseconds > MAX_SAFE_COUNTER {
            return Err("PSI total exceeds the safe integer bound".to_owned());
        }
    }
    if payload.boot_age_seconds > MAX_SAFE_COUNTER {
        return Err("boot age exceeds the safe integer bound".to_owned());
    }
    // The only internal disagreement PSI can have: full is a subset of some.
    if payload.full.avg10_centipercent > payload.some.avg10_centipercent
        || payload.full.avg60_centipercent > payload.some.avg60_centipercent
        || payload.full.avg300_centipercent > payload.some.avg300_centipercent
        || payload.full.total_microseconds > payload.some.total_microseconds
    {
        return Err("full stall figures cannot exceed some stall figures".to_owned());
    }
    Ok(())
}

/// The compiled law. `None` while the averages are warming up after boot.
#[must_use]
pub fn pressure_stall_state(
    payload: &MemoryPressurePayload,
    threshold_centipercent: u32,
    minimum_boot_age_seconds: u32,
) -> Option<DetectorState> {
    if payload.boot_age_seconds < u64::from(minimum_boot_age_seconds) {
        return None;
    }
    Some(
        if payload.some.avg60_centipercent >= threshold_centipercent {
            DetectorState::Present
        } else {
            DetectorState::ExplicitlyAbsent
        },
    )
}

/// Stateless profile module.
#[derive(Debug)]
pub struct HostMemoryProfile;
/// Registry singleton.
pub static MODULE: HostMemoryProfile = HostMemoryProfile;

fn validate_binding(
    context: &ValidationContext,
    descriptor: &ProfileDescriptor,
) -> Result<(), ProfileRefusal> {
    if context.scope.kind != SCOPE_KIND {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "memory scope kind must be host_memory",
        ));
    }
    validate_scope_value(&context.scope.value, &context.request_subject).map_err(|message| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "memory scope does not correlate with its request subject or bounds",
        )
        .with_detail("error", message)
    })?;
    if context.vantage.kind != "local" || context.vantage.value != json!({}) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "memory vantage must be the empty local vantage",
        ));
    }
    Ok(())
}

impl ProfileModule for HostMemoryProfile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &DESCRIPTOR
    }

    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal> {
        validate_binding(context, self.descriptor())
    }

    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult {
        let descriptor = self.descriptor();
        validate_binding(context, descriptor)?;
        let admitted = validate_common(descriptor, context, report)?;
        if admitted.status == SemanticReportStatus::Failed {
            return Ok(admitted);
        }
        if admitted.observations.len() != 1 {
            return Err(inconsistent(
                context,
                "a non-failed memory report requires exactly one snapshot",
            ));
        }
        let observation = &admitted.observations[0];
        let payload: MemoryPressurePayload = serde_json::from_value(observation.payload.clone())
            .map_err(|error| {
                invalid_payload(
                    context,
                    "memory payload does not match the compiled contract",
                )
                .with_detail("error", error.to_string())
            })?;
        validate_basis(descriptor, context, &payload.evidence_basis)?;
        if payload.evidence_basis.capabilities_used != admitted.used_capabilities {
            return Err(inconsistent(
                context,
                "payload capabilities differ from report used_capabilities",
            ));
        }
        if payload.evidence_basis.access_path != ACCESS_PATH
            || payload.evidence_basis.capabilities_used.len() != CAPABILITIES.len()
            || !CAPABILITIES
                .iter()
                .all(|c| payload.evidence_basis.capabilities_used.contains(*c))
        {
            return Err(ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Observation,
                ProfileRefusalCode::CapabilityEscape,
                "memory access path must declare exactly its two exercised capabilities",
            ));
        }
        if observation.observed_at != admitted.observed_at {
            return Err(inconsistent(
                context,
                "memory snapshot time must equal the report observation time",
            ));
        }
        let scope = validate_scope_value(&context.scope.value, &context.request_subject)
            .map_err(|message| invalid_payload(context, &message))?;
        validate_payload_against_scope(&payload, &scope)
            .map_err(|message| invalid_payload(context, &message))?;
        if admitted.coverage.get(COVERAGE_KIND) != Some(&SemanticCoverageState::Complete) {
            return Err(inconsistent(
                context,
                "a memory snapshot requires complete memory_pressure_stall coverage",
            ));
        }
        Ok(admitted)
    }

    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        let mut rows: Vec<Box<dyn ProfileProjection>> =
            Vec::with_capacity(report.observations.len());
        for observation in &report.observations {
            let payload: MemoryPressurePayload =
                serde_json::from_value(observation.payload.clone()).map_err(|error| {
                    ProfileRefusal {
                        instance_id: report.instance_id.clone(),
                        profile: report.profile.clone(),
                        boundary: RefusalBoundary::Observation,
                        code: ProfileRefusalCode::InvalidPayload,
                        message: "admitted memory payload could not be projected".to_owned(),
                        details: BTreeMap::from([("error".to_owned(), error.to_string())]),
                    }
                })?;
            rows.push(Box::new(MemoryPressureProjection {
                profile: report.profile.clone(),
                ordinal: observation.ordinal,
                subject: observation.subject.clone(),
                payload,
            }));
        }
        Ok(rows)
    }

    fn detectors(&self) -> &'static [&'static dyn Detector] {
        &DETECTORS
    }
}

/// Memory pressure-stall detector.
#[derive(Debug)]
pub struct PressureStallDetector;
/// Singleton detector revision.
pub static PRESSURE_STALL_DETECTOR: PressureStallDetector = PressureStallDetector;

static DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> = LazyLock::new(|| DetectorDescriptor {
    schema: DETECTOR_DESCRIPTOR_SCHEMA.to_owned(),
    id: DETECTOR_ID.to_owned(),
    version: 1,
    profile: DESCRIPTOR.profile.clone(),
    profile_digest: DESCRIPTOR
        .digest()
        .unwrap_or_else(|error| panic!("compiled memory descriptor must canonicalize: {error}")),
    title: "Kernel memory pressure stall".to_owned(),
    condition: "memory_pressure_stall".to_owned(),
    parameters: DetectorRuleParameters::MemoryPressureStall {
        some_avg60_threshold_centipercent: SOME_AVG60_THRESHOLD_CENTIPERCENT,
        minimum_boot_age_seconds: MINIMUM_BOOT_AGE_SECONDS,
    },
});

static DETECTORS: [&'static dyn Detector; 1] = [&PRESSURE_STALL_DETECTOR];

impl Detector for PressureStallDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &DETECTOR_DESCRIPTOR
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
            .find(|o| o.kind == OBSERVATION_KIND)
        else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "the newest report has no memory pressure snapshot",
                vec!["Missing observations cannot establish absence".to_owned()],
                BTreeMap::from([("reason".to_owned(), "missing_observation".to_owned())]),
            );
        };
        let Ok(payload) =
            serde_json::from_value::<MemoryPressurePayload>(observation.payload.clone())
        else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "the admitted memory snapshot cannot be projected",
                vec!["Projection failure requires operator inspection".to_owned()],
                BTreeMap::from([("reason".to_owned(), "projection_failure".to_owned())]),
            );
        };
        let DetectorRuleParameters::MemoryPressureStall {
            some_avg60_threshold_centipercent: threshold,
            minimum_boot_age_seconds: minimum_boot_age,
        } = descriptor.parameters
        else {
            unreachable!("memory detector descriptor uses only memory pressure parameters")
        };
        let Some(state) = pressure_stall_state(&payload, threshold, minimum_boot_age) else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "PSI averages are still warming up after boot",
                vec!["A freshly booted kernel understates decaying averages".to_owned()],
                BTreeMap::from([
                    ("reason".to_owned(), "psi_average_warming_up".to_owned()),
                    (
                        "boot_age_seconds".to_owned(),
                        payload.boot_age_seconds.to_string(),
                    ),
                    (
                        "minimum_boot_age_seconds".to_owned(),
                        minimum_boot_age.to_string(),
                    ),
                ]),
            );
        };
        DetectorResult {
            state,
            condition: descriptor.condition.clone(),
            summary: if state == DetectorState::Present {
                "kernel PSI memory some avg60 reached the detector threshold of 10.00%".to_owned()
            } else {
                "current complete PSI coverage places memory some avg60 below the detector threshold".to_owned()
            },
            evidence: vec![DetectorEvidence {
                report_id: occurrence.report_id.clone(),
                report_sequence: occurrence.report_sequence,
                report_digest: report.report_digest.clone(),
                observation_ordinal: Some(observation.ordinal),
                observed_at: observation.observed_at,
            }],
            limitations: vec![
                "One PSI cut does not identify the workload or cgroup that stalled".to_owned(),
                "The condition is kernel stall accounting, not memory sufficiency, OOM risk, swap health, or service impact".to_owned(),
                "avg60 is a decaying average carrying about three minutes of history; it establishes neither persistence nor the current instant".to_owned(),
            ],
            refusal: None,
            watermark: input.watermark,
        }
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
            "no admitted memory testimony is available",
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
            BTreeMap::from([("reason".to_owned(), "profile_contract_mismatch".to_owned())]),
        )));
    }
    if admitted.status != SemanticReportStatus::Complete
        || admitted.coverage.get(COVERAGE_KIND) != Some(&SemanticCoverageState::Complete)
    {
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest memory testimony lacks complete memory_pressure_stall coverage",
            vec!["A newer failed report is not shadowed by older success".to_owned()],
            BTreeMap::from([
                ("reason".to_owned(), "incomplete_memory_coverage".to_owned()),
                (
                    "failure_error_count".to_owned(),
                    admitted.failure_error_count.to_string(),
                ),
            ]),
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
            "the newest memory testimony is outside its freshness window",
            vec!["Staleness removes reliance; it does not negate testimony".to_owned()],
            BTreeMap::from([
                ("age_seconds".to_owned(), age.num_seconds().to_string()),
                ("reason".to_owned(), "invalid_freshness".to_owned()),
                (
                    "reliance_seconds".to_owned(),
                    DESCRIPTOR.freshness.reliance_seconds.to_string(),
                ),
            ]),
        )));
    }
    Ok(report)
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

fn invalid_payload(context: &ValidationContext, message: &str) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        &DESCRIPTOR,
        RefusalBoundary::Observation,
        ProfileRefusalCode::InvalidPayload,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(boot_age: u64, some60: u32, full60: u32) -> MemoryPressurePayload {
        MemoryPressurePayload {
            evidence_basis: EvidenceBasis {
                scope: crate::ScopeGrant {
                    kind: SCOPE_KIND.to_owned(),
                    value: json!({}),
                },
                vantage: crate::VantageGrant {
                    kind: "local".to_owned(),
                    value: json!({}),
                },
                access_path: ACCESS_PATH.to_owned(),
                basis: "kernel_snapshot".to_owned(),
                regime: "normal".to_owned(),
                capabilities_used: CAPABILITIES.iter().map(|c| (*c).to_owned()).collect(),
            },
            machine_id: "1a5b08928e884e73bf4f60a3c73ef497".to_owned(),
            boot_age_seconds: boot_age,
            some: PressureLine {
                avg10_centipercent: 0,
                avg60_centipercent: some60,
                avg300_centipercent: 0,
                total_microseconds: 311_022_455,
            },
            full: PressureLine {
                avg10_centipercent: 0,
                avg60_centipercent: full60,
                avg300_centipercent: 0,
                total_microseconds: 304_797_313,
            },
        }
    }

    #[test]
    fn psi_text_from_the_real_host_parses_to_exact_hundredths() {
        let text = "some avg10=0.00 avg60=0.00 avg300=0.00 total=311022455\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=304797313\n";
        let (some, full) = parse_pressure_file(text).expect("parse");
        assert_eq!(some.total_microseconds, 311_022_455);
        assert_eq!(full.avg60_centipercent, 0);
        assert_eq!(parse_centipercent("12.34"), Ok(1_234));
        assert_eq!(parse_centipercent("100.00"), Ok(10_000));
        assert!(parse_centipercent("100.01").is_err());
        assert!(parse_centipercent("1.5").is_err());
        assert!(parse_centipercent("1e2").is_err());
        assert!(parse_pressure_file("some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n").is_err());
        let dup = "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\nsome avg10=0.00 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n";
        assert!(parse_pressure_file(dup).is_err(), "duplicate line");
        assert!(parse_pressure_file("some avg10=0.00 avg60=0.00 avg300=0.00 total=+1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n").is_err(), "signed total");
    }

    #[test]
    fn law_is_inclusive_and_warm_up_refuses() {
        assert_eq!(
            pressure_stall_state(&payload(1_000, 0, 0), 1_000, 180),
            Some(DetectorState::ExplicitlyAbsent)
        );
        assert_eq!(
            pressure_stall_state(&payload(1_000, 1_000, 0), 1_000, 180),
            Some(DetectorState::Present)
        );
        assert_eq!(
            pressure_stall_state(&payload(1_000, 999, 0), 1_000, 180),
            Some(DetectorState::ExplicitlyAbsent)
        );
        assert_eq!(
            pressure_stall_state(&payload(179, 5_000, 0), 1_000, 180),
            None
        );
    }

    #[test]
    fn scope_and_payload_consistency_are_exact() {
        let value =
            json!({"schema": SCOPE_SCHEMA, "machine_id": "1a5b08928e884e73bf4f60a3c73ef497"});
        let scope =
            validate_scope_value(&value, "host:1a5b08928e884e73bf4f60a3c73ef497").expect("scope");
        assert!(validate_scope_value(&value, "host:crow").is_err());
        validate_payload_against_scope(&payload(1_000, 10, 5), &scope).expect("consistent");
        assert!(
            validate_payload_against_scope(&payload(1_000, 10, 11), &scope).is_err(),
            "full above some"
        );
        let mut other = payload(1_000, 0, 0);
        other.machine_id = "ffffffffffffffffffffffffffffffff".to_owned();
        assert!(validate_payload_against_scope(&other, &scope).is_err());
    }
}
