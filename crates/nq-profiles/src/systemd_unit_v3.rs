//! Boot-bound systemd testimony. Logical machine/unit identity survives reboot;
//! the native observation names the boot in which the manager cut was acquired.
//! A consumer must compare that boot with independently acquired present boot
//! evidence. Merely replaying this profile cannot establish present reliance.

use crate::{
    Detector, DetectorDescriptor, DetectorInput, DetectorResult, ProfileDescriptor, ProfileModule,
    ProfileProjection, ProfileRefusal, ProfileRefusalCode, ProjectionResult, RefusalBoundary,
    SemanticCoverageState, SemanticReportStatus, ValidatedReport, ValidationContext,
    ValidationResult, systemd_unit_v2 as v2,
    validation::{ReportInput, validate_basis, validate_common},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{any::Any, collections::BTreeMap, sync::LazyLock};

pub use v2::{
    ACCESS_PATH, CAPABILITIES, COVERAGE_KIND, OBSERVATION_KIND, PROFILE_ID, SCOPE_KIND,
    SUBJECT_PREFIX, subject_for,
};
pub const PROFILE_VERSION: u32 = 3;
pub const SCOPE_SCHEMA: &str = "nq.systemd_unit_scope.v3";
pub const DETECTOR_ID: &str = v2::DETECTOR_ID;
pub const DETECTOR_VERSION: u32 = 2;

/// Failure codes introduced by the boot-bound acquisition boundary. Existing
/// manager failures keep their v2 owner codes through the explicitly named variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdUnitFailureCode {
    Manager(v2::SystemdUnitFailureCode),
    BootIdentityUnavailable,
    BootIdentityMalformed,
    BootIdentityChanged,
}
impl SystemdUnitFailureCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manager(code) => code.as_str(),
            Self::BootIdentityUnavailable => "boot_identity_unavailable",
            Self::BootIdentityMalformed => "boot_identity_malformed",
            Self::BootIdentityChanged => "boot_identity_changed",
        }
    }
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        static TOKENS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
            let mut codes = v2::SystemdUnitFailureCode::tokens().to_vec();
            codes.extend([
                "boot_identity_unavailable",
                "boot_identity_malformed",
                "boot_identity_changed",
            ]);
            codes
        });
        &TOKENS
    }
}

/// Canonical Linux boot UUID spelling. This identifies an occurrence, not a host.
#[must_use]
pub fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value != "00000000-0000-0000-0000-000000000000"
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitScope {
    pub schema: String,
    pub machine_id: String,
    pub unit_name: String,
}
impl SystemdUnitScope {
    #[must_use]
    pub fn manager_scope(&self) -> v2::SystemdUnitScope {
        v2::SystemdUnitScope {
            schema: v2::SCOPE_SCHEMA.into(),
            machine_id: self.machine_id.clone(),
            unit_name: self.unit_name.clone(),
        }
    }
}

/// The exact existing manager payload plus a mandatory acquired boot identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitStatePayload {
    pub evidence_basis: crate::EvidenceBasis,
    pub machine_id: String,
    pub unit_name: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub boot_id: String,
}
impl SystemdUnitStatePayload {
    fn manager_payload(&self) -> v2::SystemdUnitStatePayload {
        v2::SystemdUnitStatePayload {
            evidence_basis: self.evidence_basis.clone(),
            machine_id: self.machine_id.clone(),
            unit_name: self.unit_name.clone(),
            load_state: self.load_state.clone(),
            active_state: self.active_state.clone(),
            sub_state: self.sub_state.clone(),
        }
    }
}

/// Validate stable enrollment. Boot identity is deliberately absent from scope.
/// # Errors
/// Refuses malformed scope or a different logical subject.
pub fn validate_scope_value(value: &Value, subject: &str) -> Result<SystemdUnitScope, String> {
    let scope: SystemdUnitScope =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    if scope.schema != SCOPE_SCHEMA {
        return Err(format!("scope schema must be {SCOPE_SCHEMA}"));
    }
    v2::validate_scope_value(
        &serde_json::to_value(scope.manager_scope()).map_err(|error| error.to_string())?,
        subject,
    )?;
    Ok(scope)
}

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| {
    let mut descriptor = v2::MODULE.descriptor().clone();
    descriptor.profile.version = PROFILE_VERSION;
    descriptor.title = "Boot-bound local systemd unit required active state".into();
    descriptor.observation_kinds[0].description =
        "The acquired boot identity and manager load, active and sub state for one exact unit"
            .into();
    descriptor.disturbance_assumptions.push("Boot identity is read before and after the manager cut; equality names the acquisition boot, not present consumer reliance after reboot".into());
    descriptor
});
static DETECTOR_DESCRIPTOR: LazyLock<DetectorDescriptor> = LazyLock::new(|| {
    let mut descriptor = v2::REQUIRED_ACTIVE_DETECTOR.descriptor().clone();
    descriptor.version = DETECTOR_VERSION;
    descriptor.profile = DESCRIPTOR.profile.clone();
    descriptor.profile_digest = DESCRIPTOR.digest().expect("compiled v3 descriptor");
    descriptor
});

#[derive(Debug)]
pub struct SystemdUnitV3Profile;
pub static MODULE: SystemdUnitV3Profile = SystemdUnitV3Profile;

fn refusal(context: &ValidationContext, message: &str) -> ProfileRefusal {
    ProfileRefusal::new(
        context,
        &DESCRIPTOR,
        RefusalBoundary::Observation,
        ProfileRefusalCode::InvalidPayload,
        message,
    )
}
impl ProfileModule for SystemdUnitV3Profile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &DESCRIPTOR
    }
    fn failure_codes(&self) -> &'static [&'static str] {
        SystemdUnitFailureCode::tokens()
    }
    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal> {
        if context.scope.kind != SCOPE_KIND {
            return Err(refusal(context, "scope kind must be systemd_unit"));
        }
        validate_scope_value(&context.scope.value, &context.request_subject)
            .map_err(|message| refusal(context, &message))?;
        if context.vantage.kind != "local" || context.vantage.value != json!({}) {
            return Err(refusal(context, "vantage must be empty local"));
        }
        Ok(())
    }
    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult {
        self.validate_binding(context)?;
        let admitted = validate_common(&DESCRIPTOR, context, report)?;
        if admitted.status == SemanticReportStatus::Failed {
            return Ok(admitted);
        }
        let [observation] = admitted.observations.as_slice() else {
            return Err(refusal(
                context,
                "exactly one boot-bound snapshot is required",
            ));
        };
        let payload: SystemdUnitStatePayload = serde_json::from_value(observation.payload.clone())
            .map_err(|error| refusal(context, &error.to_string()))?;
        if !valid_boot_id(&payload.boot_id) {
            return Err(refusal(
                context,
                "boot_id must be a canonical nonzero lowercase UUID",
            ));
        }
        validate_basis(&DESCRIPTOR, context, &payload.evidence_basis)?;
        if payload.evidence_basis.capabilities_used != admitted.used_capabilities
            || payload.evidence_basis.capabilities_used.len() != 1
            || !payload
                .evidence_basis
                .capabilities_used
                .contains(CAPABILITIES[0])
            || payload.evidence_basis.access_path != ACCESS_PATH
        {
            return Err(refusal(
                context,
                "systemd acquisition requires its exact exercised capability and access path",
            ));
        }
        if observation.observed_at != admitted.observed_at
            || admitted.coverage.get(COVERAGE_KIND) != Some(&SemanticCoverageState::Complete)
        {
            return Err(refusal(
                context,
                "snapshot time and complete coverage must match the report",
            ));
        }
        let scope = validate_scope_value(&context.scope.value, &context.request_subject)
            .map_err(|message| refusal(context, &message))?;
        v2::validate_payload_against_scope(&payload.manager_payload(), &scope.manager_scope())
            .map_err(|message| refusal(context, &message))?;
        Ok(admitted)
    }
    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        report
            .observations
            .iter()
            .map(|observation| {
                let payload: SystemdUnitStatePayload =
                    serde_json::from_value(observation.payload.clone()).map_err(|error| {
                        ProfileRefusal {
                            instance_id: report.instance_id.clone(),
                            profile: report.profile.clone(),
                            boundary: RefusalBoundary::Observation,
                            code: ProfileRefusalCode::InvalidPayload,
                            message: error.to_string(),
                            details: BTreeMap::new(),
                        }
                    })?;
                Ok(Box::new(BootBoundProjection {
                    profile: report.profile.clone(),
                    ordinal: observation.ordinal,
                    subject: observation.subject.clone(),
                    payload,
                }) as Box<dyn ProfileProjection>)
            })
            .collect()
    }
    fn detectors(&self) -> &'static [&'static dyn Detector] {
        &DETECTORS
    }
}
#[derive(Debug)]
struct BootBoundProjection {
    profile: crate::ProfileKey,
    ordinal: u32,
    subject: String,
    payload: SystemdUnitStatePayload,
}
impl ProfileProjection for BootBoundProjection {
    fn profile(&self) -> &crate::ProfileKey {
        &self.profile
    }
    fn ordinal(&self) -> u32 {
        self.ordinal
    }
    fn canonical_json(&self) -> Value {
        json!({"profile":self.profile,"ordinal":self.ordinal,"subject":self.subject,"payload":self.payload})
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
#[derive(Debug)]
struct RequiredActiveDetector;
static DETECTOR: RequiredActiveDetector = RequiredActiveDetector;
static DETECTORS: [&'static dyn Detector; 1] = [&DETECTOR];
impl Detector for RequiredActiveDetector {
    fn descriptor(&self) -> &'static DetectorDescriptor {
        &DETECTOR_DESCRIPTOR
    }
    fn evaluate(&self, input: &DetectorInput<'_>) -> DetectorResult {
        let occurrence = match v2::newest_current_report(input, self.descriptor()) {
            Ok(report) => report,
            Err(result) => return *result,
        };
        let Some(observation) = occurrence.report.observations.first() else {
            return DetectorResult::cannot_evaluate(
                input,
                self.descriptor(),
                "missing boot-bound observation",
                vec!["Missing testimony cannot establish absence".into()],
            );
        };
        let Ok(payload) =
            serde_json::from_value::<SystemdUnitStatePayload>(observation.payload.clone())
        else {
            return DetectorResult::cannot_evaluate(
                input,
                self.descriptor(),
                "invalid boot-bound observation",
                vec!["No invented boot identity".into()],
            );
        };
        if !valid_boot_id(&payload.boot_id) {
            return DetectorResult::cannot_evaluate(
                input,
                self.descriptor(),
                "invalid acquired boot identity",
                vec!["No invented boot identity".into()],
            );
        }
        let state = v2::required_active_state(
            &payload.manager_payload(),
            v2::REQUIRED_LOAD_STATE,
            v2::REQUIRED_ACTIVE_STATE,
        );
        DetectorResult {
            state,
            condition: self.descriptor().condition.clone(),
            summary: format!("the system manager reports the unit {} in acquired boot {}", payload.active_state, payload.boot_id),
            evidence: vec![crate::DetectorEvidence {
                report_id: occurrence.report_id.clone(),
                report_sequence: occurrence.report_sequence,
                report_digest: occurrence.report.report_digest.clone(),
                observation_ordinal: Some(observation.ordinal),
                observed_at: observation.observed_at,
            }],
            limitations: vec![
                "Manager state does not establish HTTP, application health, effect causation or authority".into(),
                "Acquired boot identity requires independent comparison with the current boot before present reliance".into(),
            ],
            refusal: None,
            watermark: input.watermark,
        }
    }
}
