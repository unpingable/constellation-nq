//! `nq.systemd_unit/v2`: bounded local testimony about whether the systemd
//! system manager presently reports one exact unit as loaded and active.
//!
//! The requirement is compiled (`LoadState=loaded`, `ActiveState=active`,
//! exactly). Every other state the manager reports, including `failed`,
//! transitional states, `not-found` and `masked`, is an observed unexpected
//! state, not an inability to evaluate. `active` is the manager's unit state
//! only: it is not a service operational, reachability, or application health
//! claim, and nothing here authorizes a restart or any other actuation.
//!
//! v1 (`crate::systemd_unit`) is the operator-beta fixture contract and is
//! untouched; this revision shares only the profile id.

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

/// Profile identifier (shared with the untouched v1 fixture contract).
pub const PROFILE_ID: &str = crate::systemd_unit::PROFILE_ID;
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 2;
/// Detector identifier.
pub const DETECTOR_ID: &str = "nq.systemd_unit.required_active";
/// Scope kind.
pub const SCOPE_KIND: &str = "systemd_unit";
/// Exact scope value schema.
pub const SCOPE_SCHEMA: &str = "nq.systemd_unit_scope.v2";
/// Subject namespace (`systemd-unit:<machine-id>/<unit-name>`).
pub const SUBJECT_PREFIX: &str = "systemd-unit:";
/// Observation kind.
pub const OBSERVATION_KIND: &str = "systemd_unit_state_snapshot";
/// The one coverage class.
pub const COVERAGE_KIND: &str = "systemd_unit_state";
/// Controlled access path.
pub const ACCESS_PATH: &str = "systemd_dbus";
/// Required capabilities; partial grants are refused.
pub const CAPABILITIES: [&str; 1] = ["read_systemd_unit"];
/// Compiled requirement on `LoadState`.
pub const REQUIRED_LOAD_STATE: &str = "loaded";
/// Compiled requirement on `ActiveState`.
pub const REQUIRED_ACTIVE_STATE: &str = "active";
/// The systemd 255 `LoadState` vocabulary (`systemctl --state=help`). A value
/// outside it is not interpreted.
pub const LOAD_STATES: [&str; 7] = [
    "stub",
    "loaded",
    "not-found",
    "bad-setting",
    "error",
    "merged",
    "masked",
];
/// The systemd 255 `ActiveState` vocabulary. A value outside it (for
/// example a later systemd's `refreshing`) is not interpreted.
pub const ACTIVE_STATES: [&str; 7] = [
    "active",
    "reloading",
    "inactive",
    "failed",
    "activating",
    "deactivating",
    "maintenance",
];
/// Largest admitted unit name (systemd's own bound, without the NUL).
pub const MAX_UNIT_NAME_BYTES: usize = 255;
/// Largest admitted subject: prefix, 32-hex machine id, `/`, longest name.
pub const MAX_SUBJECT_BYTES: u32 = 301;
const _: () =
    assert!(MAX_SUBJECT_BYTES as usize == SUBJECT_PREFIX.len() + 32 + 1 + MAX_UNIT_NAME_BYTES);
/// Largest admitted `SubState` token.
pub const MAX_SUB_STATE_BYTES: usize = 64;

/// The closed set of typed failure codes the systemd branch of the helper
/// may emit: every case in which the manager could not answer the question.
/// An unexpected unit state is never one of these; it is an observation.
/// The meaning of each code belongs to this module; `machine_identity_mismatch`
/// shares its text with the filesystem and memory lists and means nothing
/// outside the profile that carried it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdUnitFailureCode {
    /// The system bus could not be reached (retriable).
    SystemBusUnavailable,
    /// The systemd manager interface was unavailable (retriable).
    ManagerUnavailable,
    /// A manager call exceeded the request deadline (retriable).
    QueryTimeout,
    /// A manager call returned an error (retriable).
    QueryFailed,
    /// A reply did not decode as its documented type.
    ReplyMalformed,
    /// The manager's machine identity is not the enrolled one.
    MachineIdentityMismatch,
    /// The manager did not return exactly one unit row.
    UnitListCardinality,
    /// The row names another unit: the requested name is an alias or the unit
    /// follows another.
    UnitNameNotCanonical,
    /// `LoadState` or `ActiveState` is outside the systemd 255 vocabulary, or
    /// `SubState` is not a bounded token.
    UnitStateUnrecognized,
}

impl SystemdUnitFailureCode {
    /// Every code, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::SystemBusUnavailable,
        Self::ManagerUnavailable,
        Self::QueryTimeout,
        Self::QueryFailed,
        Self::ReplyMalformed,
        Self::MachineIdentityMismatch,
        Self::UnitListCardinality,
        Self::UnitNameNotCanonical,
        Self::UnitStateUnrecognized,
    ];

    /// The wire code, exactly as the helper emits it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemBusUnavailable => "system_bus_unavailable",
            Self::ManagerUnavailable => "manager_unavailable",
            Self::QueryTimeout => "query_timeout",
            Self::QueryFailed => "query_failed",
            Self::ReplyMalformed => "reply_malformed",
            Self::MachineIdentityMismatch => "machine_identity_mismatch",
            Self::UnitListCardinality => "unit_list_cardinality",
            Self::UnitNameNotCanonical => "unit_name_not_canonical",
            Self::UnitStateUnrecognized => "unit_state_unrecognized",
        }
    }

    /// Exact lookup; anything else is not a systemd unit code.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|known| known.as_str() == code)
    }

    /// Every wire token, in declaration order: the published vocabulary,
    /// derived from the enum so it cannot drift from it.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        static TOKENS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
            SystemdUnitFailureCode::ALL
                .iter()
                .map(|code| code.as_str())
                .collect()
        });
        &TOKENS
    }
}

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| {
    ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "systemd_unit".to_owned(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Local systemd unit required active state".to_owned(),
    observation_kinds: vec![VocabularyTerm::new(
        OBSERVATION_KIND,
        "The system manager's load, active and sub state for one exact unit in one cut",
    )],
    coverage: vec![VocabularyTerm::new(
        COVERAGE_KIND,
        "The manager-reported state of the requested unit",
    )],
    subjects: SubjectRules {
        namespace: SUBJECT_PREFIX.to_owned(),
        exact_request_subject: true,
    },
    scope_kinds: vec![VocabularyTerm::new(
        SCOPE_KIND,
        "One exact machine identity and one canonical system-manager unit name",
    )],
    vantages: vec![VocabularyTerm::new(
        "local",
        "Observation from a process on the machine whose system manager is read",
    )],
    access_paths: vec![VocabularyTerm::new(
        ACCESS_PATH,
        "Read-only calls to org.freedesktop.systemd1 on the local system bus",
    )],
    bases: vec![VocabularyTerm::new(
        "manager_snapshot",
        "A bounded system-manager unit state snapshot",
    )],
    regimes: vec![VocabularyTerm::new(
        "normal",
        "Read-only observation that starts, stops, reloads or enqueues nothing",
    )],
    capabilities: vec![VocabularyTerm::new(
        CAPABILITIES[0],
        "Read the machine identity and one unit's state from the system manager",
    )],
    freshness: FreshnessPolicy {
        reliance_seconds: 60,
        alignment_seconds: 0,
    },
    limits: CardinalityLimits {
        max_observations: 1,
        max_payload_bytes: 4_096,
        max_subject_bytes: MAX_SUBJECT_BYTES,
        max_coverage_declarations: 1,
    },
    disturbance_assumptions: vec![
        "Reading unit state loads an unloaded unit into manager memory, as systemctl show does; it changes no unit state, job, file or configuration".to_owned(),
        "One manager cut establishes the reported unit state only; it is not a service operational, reachability, dependency, or application health claim".to_owned(),
    ],
}
});

/// Exact scope value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitScope {
    /// Must equal [`SCOPE_SCHEMA`].
    pub schema: String,
    /// 32 lowercase hex characters: the system manager's machine identity.
    pub machine_id: String,
    /// The unit's canonical name (never an alias).
    pub unit_name: String,
}

/// Payload of one `systemd_unit_state_snapshot` observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitStatePayload {
    /// Exact evidence basis.
    pub evidence_basis: EvidenceBasis,
    /// Machine identity the manager reported during this observation.
    pub machine_id: String,
    /// Canonical unit name the manager reported.
    pub unit_name: String,
    /// `LoadState`, verbatim.
    pub load_state: String,
    /// `ActiveState`, verbatim.
    pub active_state: String,
    /// `SubState`, verbatim; recorded, not part of the law.
    pub sub_state: String,
}

/// Typed rebuildable view of one admitted snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdUnitStateProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Validated subject.
    pub subject: String,
    /// Exact validated payload.
    pub payload: SystemdUnitStatePayload,
}

impl ProfileProjection for SystemdUnitStateProjection {
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

/// Whether a name is admitted by this revision: a plain `.service` unit
/// name of at most 255 bytes over `[A-Za-z0-9:_.-]`. Templates and instances
/// (`@`) and escaped names (`\`) are outside this revision.
#[must_use]
pub fn valid_unit_name(value: &str) -> bool {
    value.len() <= MAX_UNIT_NAME_BYTES
        && value.len() > ".service".len()
        && value.ends_with(".service")
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_.-".contains(&byte))
}

/// Whether a `SubState` is a bounded lowercase token.
#[must_use]
pub fn valid_sub_state(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SUB_STATE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Expected subject for a machine id and unit name.
#[must_use]
pub fn subject_for(machine_id: &str, unit_name: &str) -> String {
    format!("{SUBJECT_PREFIX}{machine_id}/{unit_name}")
}

/// Validate a scope value against the request subject.
///
/// # Errors
///
/// Returns a message describing the first violated rule.
pub fn validate_scope_value(
    value: &Value,
    request_subject: &str,
) -> Result<SystemdUnitScope, String> {
    let scope: SystemdUnitScope = serde_json::from_value(value.clone())
        .map_err(|error| format!("scope must be exactly {SCOPE_SCHEMA}: {error}"))?;
    if scope.schema != SCOPE_SCHEMA {
        return Err(format!("scope schema must be {SCOPE_SCHEMA}"));
    }
    if !is_lower_hex(&scope.machine_id, 32) {
        return Err("machine_id must be 32 lowercase hex characters".to_owned());
    }
    if !valid_unit_name(&scope.unit_name) {
        return Err(
            "unit_name must be a plain .service name over [A-Za-z0-9:_.-] of at most 255 bytes"
                .to_owned(),
        );
    }
    if request_subject != subject_for(&scope.machine_id, &scope.unit_name) {
        return Err("subject must equal systemd-unit:<machine_id>/<unit_name>".to_owned());
    }
    Ok(scope)
}

/// Validate payload consistency against the scope and the closed vocabularies.
///
/// # Errors
///
/// Returns a message describing the first violated rule.
pub fn validate_payload_against_scope(
    payload: &SystemdUnitStatePayload,
    scope: &SystemdUnitScope,
) -> Result<(), String> {
    if payload.machine_id != scope.machine_id {
        return Err("payload machine_id must equal the request scope".to_owned());
    }
    if payload.unit_name != scope.unit_name {
        return Err("payload unit_name must equal the request scope".to_owned());
    }
    if !LOAD_STATES.contains(&payload.load_state.as_str()) {
        return Err("load_state is outside the systemd 255 vocabulary".to_owned());
    }
    if !ACTIVE_STATES.contains(&payload.active_state.as_str()) {
        return Err("active_state is outside the systemd 255 vocabulary".to_owned());
    }
    if !valid_sub_state(&payload.sub_state) {
        return Err("sub_state must be a bounded lowercase token".to_owned());
    }
    Ok(())
}

/// The compiled law: `ExplicitlyAbsent` exactly when the manager reports the
/// required load and active states; `Present` for every other admitted state.
#[must_use]
pub fn required_active_state(
    payload: &SystemdUnitStatePayload,
    required_load_state: &str,
    required_active_state: &str,
) -> DetectorState {
    if payload.load_state == required_load_state && payload.active_state == required_active_state {
        DetectorState::ExplicitlyAbsent
    } else {
        DetectorState::Present
    }
}

/// Stateless profile module.
#[derive(Debug)]
pub struct SystemdUnitV2Profile;
/// Registry singleton.
pub static MODULE: SystemdUnitV2Profile = SystemdUnitV2Profile;

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
            "systemd unit scope kind must be systemd_unit",
        ));
    }
    validate_scope_value(&context.scope.value, &context.request_subject).map_err(|message| {
        ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "systemd unit scope does not correlate with its request subject or bounds",
        )
        .with_detail("error", message)
    })?;
    if context.vantage.kind != "local" || context.vantage.value != json!({}) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "systemd unit vantage must be the empty local vantage",
        ));
    }
    Ok(())
}

impl ProfileModule for SystemdUnitV2Profile {
    fn failure_codes(&self) -> &'static [&'static str] {
        SystemdUnitFailureCode::tokens()
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
                "a non-failed systemd unit report requires exactly one snapshot",
            ));
        }
        let observation = &admitted.observations[0];
        let payload: SystemdUnitStatePayload = serde_json::from_value(observation.payload.clone())
            .map_err(|error| {
                invalid_payload(
                    context,
                    "systemd unit payload does not match the compiled contract",
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
                "systemd unit access path must declare exactly its one exercised capability",
            ));
        }
        if observation.observed_at != admitted.observed_at {
            return Err(inconsistent(
                context,
                "systemd unit snapshot time must equal the report observation time",
            ));
        }
        let scope = validate_scope_value(&context.scope.value, &context.request_subject)
            .map_err(|message| invalid_payload(context, &message))?;
        validate_payload_against_scope(&payload, &scope)
            .map_err(|message| invalid_payload(context, &message))?;
        if admitted.coverage.get(COVERAGE_KIND) != Some(&SemanticCoverageState::Complete) {
            return Err(inconsistent(
                context,
                "a systemd unit snapshot requires complete systemd_unit_state coverage",
            ));
        }
        Ok(admitted)
    }

    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        let mut rows: Vec<Box<dyn ProfileProjection>> =
            Vec::with_capacity(report.observations.len());
        for observation in &report.observations {
            let payload: SystemdUnitStatePayload =
                serde_json::from_value(observation.payload.clone()).map_err(|error| {
                    ProfileRefusal {
                        instance_id: report.instance_id.clone(),
                        profile: report.profile.clone(),
                        boundary: RefusalBoundary::Observation,
                        code: ProfileRefusalCode::InvalidPayload,
                        message: "admitted systemd unit payload could not be projected".to_owned(),
                        details: BTreeMap::from([("error".to_owned(), error.to_string())]),
                    }
                })?;
            rows.push(Box::new(SystemdUnitStateProjection {
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

/// Required-active detector.
#[derive(Debug)]
pub struct RequiredActiveDetector;
/// Singleton detector revision.
pub static REQUIRED_ACTIVE_DETECTOR: RequiredActiveDetector = RequiredActiveDetector;

static DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> = LazyLock::new(|| DetectorDescriptor {
    schema: DETECTOR_DESCRIPTOR_SCHEMA.to_owned(),
    id: DETECTOR_ID.to_owned(),
    version: 1,
    profile: DESCRIPTOR.profile.clone(),
    profile_digest: DESCRIPTOR.digest().unwrap_or_else(|error| {
        panic!("compiled systemd unit v2 descriptor must canonicalize: {error}")
    }),
    title: "Required systemd unit not reported active".to_owned(),
    condition: "systemd_unit_not_active".to_owned(),
    parameters: DetectorRuleParameters::SystemdUnitRequiredActive {
        required_load_state: REQUIRED_LOAD_STATE.to_owned(),
        required_active_state: REQUIRED_ACTIVE_STATE.to_owned(),
    },
});

static DETECTORS: [&'static dyn Detector; 1] = [&REQUIRED_ACTIVE_DETECTOR];

impl Detector for RequiredActiveDetector {
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
                "the newest report has no systemd unit state snapshot",
                vec!["Missing observations cannot establish absence".to_owned()],
                BTreeMap::from([("reason".to_owned(), "missing_observation".to_owned())]),
            );
        };
        let Ok(payload) =
            serde_json::from_value::<SystemdUnitStatePayload>(observation.payload.clone())
        else {
            return DetectorResult::cannot_evaluate_with_details(
                input,
                descriptor,
                "the admitted systemd unit snapshot cannot be projected",
                vec!["Projection failure requires operator inspection".to_owned()],
                BTreeMap::from([("reason".to_owned(), "projection_failure".to_owned())]),
            );
        };
        let DetectorRuleParameters::SystemdUnitRequiredActive {
            required_load_state,
            required_active_state: required_active,
        } = &descriptor.parameters
        else {
            unreachable!("systemd unit v2 detector descriptor uses only required-active parameters")
        };
        let state = required_active_state(&payload, required_load_state, required_active);
        DetectorResult {
            state,
            condition: descriptor.condition.clone(),
            summary: if state == DetectorState::Present {
                "the system manager reports the unit in a state other than loaded and active"
                    .to_owned()
            } else {
                "the system manager reports the unit loaded and active".to_owned()
            },
            evidence: vec![DetectorEvidence {
                report_id: occurrence.report_id.clone(),
                report_sequence: occurrence.report_sequence,
                report_digest: report.report_digest.clone(),
                observation_ordinal: Some(observation.ordinal),
                observed_at: observation.observed_at,
            }],
            limitations: vec![
                "An active unit state is not a service operational, reachability, dependency, or application health claim, and does not establish that a main process is running (active/exited is active)".to_owned(),
                "An inactive, failed, transitional, masked, or not-found state is not an outage or user-visible impact claim, and names no cause".to_owned(),
                "One manager cut does not establish which unit definition is loaded or whether it matches disk".to_owned(),
                "Nothing here authorizes a restart, reload, or any other actuation".to_owned(),
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
            "no admitted systemd unit testimony is available",
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
            (
                "reason".to_owned(),
                "incomplete_systemd_unit_coverage".to_owned(),
            ),
            (
                "failure_error_count".to_owned(),
                admitted.failure_error_count.to_string(),
            ),
        ]);
        // The owner's typed code travels with the refusal when the report
        // carries exactly one collection error and that code is in this
        // module's closed list; NQ copies it and interprets nothing.
        if let Some(failure) = admitted.single_failure_error()
            && let Some(code) = SystemdUnitFailureCode::parse(&failure.code)
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
            "the newest systemd unit testimony lacks complete systemd_unit_state coverage",
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
            "the newest systemd unit testimony is outside its freshness window",
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

    const MACHINE: &str = "1a5b08928e884e73bf4f60a3c73ef497";

    fn payload(load: &str, active: &str, sub: &str) -> SystemdUnitStatePayload {
        SystemdUnitStatePayload {
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
                basis: "manager_snapshot".to_owned(),
                regime: "normal".to_owned(),
                capabilities_used: CAPABILITIES.iter().map(|c| (*c).to_owned()).collect(),
            },
            machine_id: MACHINE.to_owned(),
            unit_name: "cron.service".to_owned(),
            load_state: load.to_owned(),
            active_state: active.to_owned(),
            sub_state: sub.to_owned(),
        }
    }

    #[test]
    fn only_loaded_and_active_is_the_expected_state() {
        let law = |load, active, sub| {
            required_active_state(
                &payload(load, active, sub),
                REQUIRED_LOAD_STATE,
                REQUIRED_ACTIVE_STATE,
            )
        };
        assert_eq!(
            law("loaded", "active", "running"),
            DetectorState::ExplicitlyAbsent
        );
        // SubState is recorded, not judged.
        assert_eq!(
            law("loaded", "active", "exited"),
            DetectorState::ExplicitlyAbsent
        );
        for (load, active, sub) in [
            ("loaded", "inactive", "dead"),
            ("loaded", "failed", "failed"),
            ("loaded", "activating", "auto-restart"),
            ("loaded", "activating", "start"),
            ("loaded", "deactivating", "stop-sigterm"),
            ("loaded", "reloading", "reload"),
            ("loaded", "maintenance", "cleaning"),
            ("not-found", "inactive", "dead"),
            ("masked", "inactive", "dead"),
            ("bad-setting", "inactive", "dead"),
            ("error", "inactive", "dead"),
            // An active unit whose definition failed to reload is still not loaded.
            ("error", "active", "running"),
        ] {
            assert_eq!(
                law(load, active, sub),
                DetectorState::Present,
                "{load}/{active}/{sub}"
            );
        }
    }

    #[test]
    fn scope_is_exact_and_canonical_names_only() {
        let subject = subject_for(MACHINE, "cron.service");
        assert_eq!(
            subject,
            "systemd-unit:1a5b08928e884e73bf4f60a3c73ef497/cron.service"
        );
        let value =
            json!({"schema": SCOPE_SCHEMA, "machine_id": MACHINE, "unit_name": "cron.service"});
        let scope = validate_scope_value(&value, &subject).expect("scope");
        for wrong_subject in [
            "systemd-unit:1a5b08928e884e73bf4f60a3c73ef497/rsyslog.service",
            "systemd-unit:ffffffffffffffffffffffffffffffff/cron.service",
            "host:1a5b08928e884e73bf4f60a3c73ef497",
            "systemd-unit:1a5b08928e884e73bf4f60a3c73ef497/cron.service/",
        ] {
            assert!(
                validate_scope_value(&value, wrong_subject).is_err(),
                "{wrong_subject}"
            );
        }
        for name in [
            "",
            ".service",
            "cron",
            "cron.socket",
            "getty@tty1.service",
            "foo@.service",
            "a\\x2db.service",
            "a/b.service",
            "a b.service",
            &format!("{}.service", "a".repeat(248)),
        ] {
            assert!(!valid_unit_name(name), "{name}");
        }
        assert!(valid_unit_name(&format!("{}.service", "a".repeat(247))));
        assert!(valid_unit_name("systemd-journald.service"));
        assert!(valid_unit_name("dbus-org.freedesktop.timesync1.service"));
        let extra = json!({"schema": SCOPE_SCHEMA, "machine_id": MACHINE, "unit_name": "cron.service", "unit_file_sha256": "sha256:00"});
        assert!(
            validate_scope_value(&extra, &subject).is_err(),
            "closed scope"
        );
        let upper = json!({"schema": SCOPE_SCHEMA, "machine_id": MACHINE.to_uppercase(), "unit_name": "cron.service"});
        assert!(validate_scope_value(&upper, &subject).is_err());

        validate_payload_against_scope(&payload("loaded", "active", "running"), &scope)
            .expect("consistent");
        let mut other_unit = payload("loaded", "active", "running");
        other_unit.unit_name = "rsyslog.service".to_owned();
        assert!(validate_payload_against_scope(&other_unit, &scope).is_err());
        let mut other_machine = payload("loaded", "active", "running");
        other_machine.machine_id = "ffffffffffffffffffffffffffffffff".to_owned();
        assert!(validate_payload_against_scope(&other_machine, &scope).is_err());
        for (load, active, sub) in [
            ("loaded", "refreshing", "running"),
            ("Loaded", "active", "running"),
            ("loaded", "active", ""),
            ("loaded", "active", "Running"),
            ("loaded", "active", &"x".repeat(65)),
        ] {
            assert!(
                validate_payload_against_scope(&payload(load, active, sub), &scope).is_err(),
                "{load}/{active}/{sub}"
            );
        }
    }

    #[test]
    fn owner_codes_are_closed_and_round_trip() {
        for code in SystemdUnitFailureCode::ALL {
            assert_eq!(SystemdUnitFailureCode::parse(code.as_str()), Some(code));
        }
        assert_eq!(SystemdUnitFailureCode::tokens().len(), 9);
        for foreign in [
            "psi_not_provided",
            "not_a_mountpoint",
            "systemd_unit_cardinality",
            "systemd_machine_identity_mismatch",
            "",
        ] {
            assert_eq!(SystemdUnitFailureCode::parse(foreign), None, "{foreign}");
        }
    }
}
