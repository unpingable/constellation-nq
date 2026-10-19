//! `nq.host_io/v1`: bounded local testimony about kernel I/O pressure stall
//! accounting (PSI) for one exact machine.
//!
//! The condition is defined on the kernel's own `full avg60` figure from
//! `/proc/pressure/io`, read in one cut: the share of the last minute in
//! which every non-idle task was stalled on I/O (NQ #28; labelwatch-host ran
//! at 45–67 % during Monitor #22). It is not a device-health, throughput,
//! queue-depth, or service-impact claim, and "absent" means only that the
//! decaying stall share is below the threshold now. The PSI line parser and
//! its exact integer representation are shared with `nq.host_memory/v1`.

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
pub const PROFILE_ID: &str = "nq.host_io";
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 1;
/// Detector identifier.
pub const DETECTOR_ID: &str = "nq.host_io.pressure_stall";
/// Scope kind.
pub const SCOPE_KIND: &str = "host_io";
/// Exact scope value schema.
pub const SCOPE_SCHEMA: &str = "nq.host_io_scope.v1";
/// Subject namespace (`host:<machine-id>`).
pub const SUBJECT_PREFIX: &str = "host:";
/// Observation kind.
pub const OBSERVATION_KIND: &str = "io_pressure_snapshot";
/// The one coverage class.
pub const COVERAGE_KIND: &str = "io_pressure_stall";
/// Controlled access path.
pub const ACCESS_PATH: &str = "procfs_pressure";
/// The closed set of typed failure codes the I/O helper may emit. The meaning
/// of each code belongs to this module; the texts are shared with the memory
/// and filesystem lists and mean nothing outside the profile that carried
/// them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoFailureCode {
    /// `/etc/machine-id` could not be read (retriable).
    MachineIdentityUnavailable,
    /// The live machine identity is not the enrolled one.
    MachineIdentityMismatch,
    /// The pressure file could not be read.
    PsiReadFailed,
    /// The pressure file was not in the expected form.
    PsiMalformed,
    /// The kernel provides no I/O pressure accounting.
    PsiNotProvided,
    /// The boot clock could not be read (retriable).
    BootClockUnavailable,
}

impl IoFailureCode {
    /// Every code, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::MachineIdentityUnavailable,
        Self::MachineIdentityMismatch,
        Self::PsiReadFailed,
        Self::PsiMalformed,
        Self::PsiNotProvided,
        Self::BootClockUnavailable,
    ];

    /// The wire code, exactly as the helper emits it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachineIdentityUnavailable => "machine_identity_unavailable",
            Self::MachineIdentityMismatch => "machine_identity_mismatch",
            Self::PsiReadFailed => "psi_read_failed",
            Self::PsiMalformed => "psi_malformed",
            Self::PsiNotProvided => "psi_not_provided",
            Self::BootClockUnavailable => "boot_clock_unavailable",
        }
    }

    /// Exact lookup; anything else is not an I/O code.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|known| known.as_str() == code)
    }

    /// Every wire token, in declaration order: the published vocabulary,
    /// derived from the enum so it cannot drift from it.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        static TOKENS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
            IoFailureCode::ALL
                .iter()
                .map(|code| code.as_str())
                .collect()
        });
        &TOKENS
    }
}

/// Required capabilities; partial grants are refused.
pub const CAPABILITIES: [&str; 2] = ["read_machine_identity", "read_procfs"];
/// Compiled threshold on `full avg60`, in hundredths of a percent (25.00 %):
/// the stall-time fraction crow's `host-pressure` vmalert rule warns at over
/// ten minutes, on the decaying one-minute average the kernel publishes.
pub const FULL_AVG60_THRESHOLD_CENTIPERCENT: u32 = 2_500;
/// Compiled warm-up guard: below this boot age the averages understate.
pub const MINIMUM_BOOT_AGE_SECONDS: u32 = 180;
pub use crate::host_memory::{MAX_SAFE_COUNTER, PressureLine, parse_pressure_file};

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| {
    ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "host_io".to_owned(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Local kernel I/O pressure stall".to_owned(),
    observation_kinds: vec![VocabularyTerm::new(
        OBSERVATION_KIND,
        "One read of /proc/pressure/io with the boot age at the read",
    )],
    coverage: vec![VocabularyTerm::new(
        COVERAGE_KIND,
        "Kernel PSI I/O some/full averages and totals",
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
        "A bounded read-only open of /proc/pressure/io",
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
        "Reading PSI averages does not alter I/O state".to_owned(),
        "One PSI cut establishes a kernel-reported stall share only; it is not a device-health, throughput, queue-depth, or service-impact claim".to_owned(),
    ],
}
});

/// Exact scope value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostIoScope {
    /// Must equal [`SCOPE_SCHEMA`].
    pub schema: String,
    /// 32 lowercase hex characters from `/etc/machine-id`.
    pub machine_id: String,
}

/// Payload of one `io_pressure_snapshot` observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IoPressurePayload {
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
pub struct IoPressureProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Validated subject.
    pub subject: String,
    /// Exact validated payload.
    pub payload: IoPressurePayload,
}

impl ProfileProjection for IoPressureProjection {
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

/// Validate a scope value against the request subject.
///
/// # Errors
///
/// Returns a message describing the first violated rule.
pub fn validate_scope_value(value: &Value, request_subject: &str) -> Result<HostIoScope, String> {
    let scope: HostIoScope = serde_json::from_value(value.clone())
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
    payload: &IoPressurePayload,
    scope: &HostIoScope,
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

/// The compiled law, on `full avg60`: the share of the last minute in which
/// every non-idle task was stalled on I/O. `some` counts a single stalled
/// task and is high on any busy disk; `full` is the figure that says the
/// machine as a whole was waiting. `None` while the averages are warming up
/// after boot.
#[must_use]
pub fn pressure_stall_state(
    payload: &IoPressurePayload,
    threshold_centipercent: u32,
    minimum_boot_age_seconds: u32,
) -> Option<DetectorState> {
    if payload.boot_age_seconds < u64::from(minimum_boot_age_seconds) {
        return None;
    }
    Some(
        if payload.full.avg60_centipercent >= threshold_centipercent {
            DetectorState::Present
        } else {
            DetectorState::ExplicitlyAbsent
        },
    )
}

/// Stateless profile module.
#[derive(Debug)]
pub struct HostIoProfile;
/// Registry singleton.
pub static MODULE: HostIoProfile = HostIoProfile;

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
            "I/O scope kind must be host_io",
        ));
    }
    validate_scope_value(&context.scope.value, &context.request_subject).map_err(|message| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "I/O scope does not correlate with its request subject or bounds",
        )
        .with_detail("error", message)
    })?;
    if context.vantage.kind != "local" || context.vantage.value != json!({}) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "I/O vantage must be the empty local vantage",
        ));
    }
    Ok(())
}

impl ProfileModule for HostIoProfile {
    fn failure_codes(&self) -> &'static [&'static str] {
        IoFailureCode::tokens()
    }
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
                "a non-failed I/O report requires exactly one snapshot",
            ));
        }
        let observation = &admitted.observations[0];
        let payload: IoPressurePayload = serde_json::from_value(observation.payload.clone())
            .map_err(|error| {
                invalid_payload(context, "I/O payload does not match the compiled contract")
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
                "I/O access path must declare exactly its two exercised capabilities",
            ));
        }
        if observation.observed_at != admitted.observed_at {
            return Err(inconsistent(
                context,
                "I/O snapshot time must equal the report observation time",
            ));
        }
        let scope = validate_scope_value(&context.scope.value, &context.request_subject)
            .map_err(|message| invalid_payload(context, &message))?;
        validate_payload_against_scope(&payload, &scope)
            .map_err(|message| invalid_payload(context, &message))?;
        if admitted.coverage.get(COVERAGE_KIND) != Some(&SemanticCoverageState::Complete) {
            return Err(inconsistent(
                context,
                "an I/O snapshot requires complete io_pressure_stall coverage",
            ));
        }
        Ok(admitted)
    }

    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        let mut rows: Vec<Box<dyn ProfileProjection>> =
            Vec::with_capacity(report.observations.len());
        for observation in &report.observations {
            let payload: IoPressurePayload = serde_json::from_value(observation.payload.clone())
                .map_err(|error| ProfileRefusal {
                    instance_id: report.instance_id.clone(),
                    profile: report.profile.clone(),
                    boundary: RefusalBoundary::Observation,
                    code: ProfileRefusalCode::InvalidPayload,
                    message: "admitted I/O payload could not be projected".to_owned(),
                    details: BTreeMap::from([("error".to_owned(), error.to_string())]),
                })?;
            rows.push(Box::new(IoPressureProjection {
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

/// I/O pressure-stall detector.
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
        .unwrap_or_else(|error| panic!("compiled I/O descriptor must canonicalize: {error}")),
    title: "Kernel I/O pressure stall".to_owned(),
    condition: "io_pressure_stall".to_owned(),
    parameters: DetectorRuleParameters::IoPressureStall {
        full_avg60_threshold_centipercent: FULL_AVG60_THRESHOLD_CENTIPERCENT,
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
                "the newest report has no I/O pressure snapshot",
                vec!["Missing observations cannot establish absence".to_owned()],
                BTreeMap::from([("reason".to_owned(), "missing_observation".to_owned())]),
            );
        };
        let Ok(payload) = serde_json::from_value::<IoPressurePayload>(observation.payload.clone())
        else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "the admitted I/O snapshot cannot be projected",
                vec!["Projection failure requires operator inspection".to_owned()],
                BTreeMap::from([("reason".to_owned(), "projection_failure".to_owned())]),
            );
        };
        let DetectorRuleParameters::IoPressureStall {
            full_avg60_threshold_centipercent: threshold,
            minimum_boot_age_seconds: minimum_boot_age,
        } = descriptor.parameters
        else {
            unreachable!("I/O detector descriptor uses only I/O pressure parameters")
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
                format!(
                    "kernel PSI I/O full avg60 reached the detector threshold of {}.{:02}%",
                    threshold / 100,
                    threshold % 100
                )
            } else {
                "current complete PSI coverage places I/O full avg60 below the detector threshold".to_owned()
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
                "The condition is kernel stall accounting on full stalls, not device health, throughput, queue depth, or service impact".to_owned(),
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
            "no admitted I/O testimony is available",
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
        let mut details = BTreeMap::from([
            ("reason".to_owned(), "incomplete_io_coverage".to_owned()),
            (
                "failure_error_count".to_owned(),
                admitted.failure_error_count.to_string(),
            ),
        ]);
        // The owner's typed code travels with the refusal when the report
        // carries exactly one collection error and that code is in this
        // module's closed list; NQ copies it and interprets nothing.
        if let Some(failure) = admitted.single_failure_error()
            && let Some(code) = IoFailureCode::parse(&failure.code)
        {
            details.insert("failure_code".to_owned(), code.as_str().to_owned());
            details.insert(
                "failure_retriable".to_owned(),
                failure.retriable.to_string(),
            );
        }
        return Err(Box::new(DetectorResult::cannot_evaluate_with_details(
            input,
            descriptor,
            "the newest I/O testimony lacks complete io_pressure_stall coverage",
            vec!["A newer failed report is not shadowed by older success".to_owned()],
            details,
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
            "the newest I/O testimony is outside its freshness window",
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

    fn payload(boot_age: u64, some60: u32, full60: u32) -> IoPressurePayload {
        IoPressurePayload {
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

    /// The law reads `full`, not `some`: a busy disk with one stalled task
    /// at a time is not a stalled machine.
    #[test]
    fn law_is_inclusive_on_full_stalls_and_warm_up_refuses() {
        assert_eq!(
            pressure_stall_state(&payload(1_000, 0, 0), 2_500, 180),
            Some(DetectorState::ExplicitlyAbsent)
        );
        assert_eq!(
            pressure_stall_state(&payload(1_000, 9_000, 2_500), 2_500, 180),
            Some(DetectorState::Present)
        );
        assert_eq!(
            pressure_stall_state(&payload(1_000, 9_000, 2_499), 2_500, 180),
            Some(DetectorState::ExplicitlyAbsent),
            "some alone never establishes the condition"
        );
        assert_eq!(
            pressure_stall_state(&payload(179, 9_000, 9_000), 2_500, 180),
            None
        );
        // labelwatch-host during Monitor #22 (2026-10-18): full avg60 at
        // 67 % is the condition the profile exists for.
        assert_eq!(
            pressure_stall_state(
                &payload(86_400, 7_800, 6_700),
                FULL_AVG60_THRESHOLD_CENTIPERCENT,
                MINIMUM_BOOT_AGE_SECONDS
            ),
            Some(DetectorState::Present)
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
