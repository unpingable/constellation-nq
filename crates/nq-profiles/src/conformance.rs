//! `nq.conformance/v1`: a deliberately tiny language-neutral echo profile.

use std::{any::Any, collections::BTreeMap, sync::LazyLock};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CardinalityLimits, Detector, EvidenceBasis, FreshnessPolicy, ProfileDescriptor, ProfileModule,
    ProfileProjection, ProfileRefusal, ProfileRefusalCode, ProjectionResult, RefusalBoundary,
    SemanticCoverageState, SemanticReportStatus, SubjectRules, ValidatedReport, ValidationContext,
    ValidationResult, VocabularyTerm,
    descriptor::PROFILE_DESCRIPTOR_SCHEMA,
    validation::{ReportInput, validate_basis, validate_common},
};

/// Stable profile identifier.
pub const PROFILE_ID: &str = "nq.conformance";
/// Compiled semantic version.
pub const PROFILE_VERSION: u32 = 1;

/// Stateless conformance profile module.
#[derive(Debug)]
pub struct ConformanceProfile;

/// Singleton module registered by the compile-time registry.
pub static MODULE: ConformanceProfile = ConformanceProfile;

static DESCRIPTOR: LazyLock<ProfileDescriptor> = LazyLock::new(|| ProfileDescriptor {
    schema: PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
    family: "conformance".to_owned(),
    profile: crate::ProfileKey::new(PROFILE_ID, PROFILE_VERSION),
    title: "Protocol conformance echo".to_owned(),
    observation_kinds: vec![VocabularyTerm::new(
        "echo",
        "A bounded nonce echoed by a language-neutral helper",
    )],
    coverage: vec![VocabularyTerm::new(
        "echo",
        "Whether the requested echo was returned",
    )],
    subjects: SubjectRules {
        namespace: "conformance:".to_owned(),
        exact_request_subject: true,
    },
    scope_kinds: vec![VocabularyTerm::new(
        "fixture",
        "A conformance fixture scope",
    )],
    vantages: vec![VocabularyTerm::new("local", "The local supervised process")],
    access_paths: vec![VocabularyTerm::new(
        "process",
        "A supervised local process exchange",
    )],
    bases: vec![VocabularyTerm::new(
        "request_echo",
        "The nonce carried by the current bounded request",
    )],
    regimes: vec![VocabularyTerm::new(
        "conformance",
        "Protocol conformance, not operational diagnosis",
    )],
    capabilities: Vec::new(),
    freshness: FreshnessPolicy {
        reliance_seconds: 60,
        alignment_seconds: 0,
    },
    limits: CardinalityLimits {
        max_observations: 1,
        max_payload_bytes: 2_048,
        max_subject_bytes: 256,
        max_coverage_declarations: 1,
    },
    disturbance_assumptions: vec![
        "The echo fixture exercises serialization and validation only".to_owned(),
        "A successful echo establishes no operational condition or authority".to_owned(),
    ],
});

static DETECTORS: [&'static dyn Detector; 0] = [];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EchoPayload {
    evidence_basis: EvidenceBasis,
    nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FixtureScope {
    id: String,
    nonce: String,
}

/// Typed rebuildable view of an admitted conformance echo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EchoProjection {
    profile: crate::ProfileKey,
    /// Source observation ordinal.
    pub ordinal: u32,
    /// Bounded nonce returned by the helper.
    pub nonce: String,
}

impl ProfileProjection for EchoProjection {
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
            "nonce": self.nonce,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ProfileModule for ConformanceProfile {
    fn descriptor(&self) -> &'static ProfileDescriptor {
        &DESCRIPTOR
    }

    fn validate_binding(&self, context: &ValidationContext) -> Result<(), ProfileRefusal> {
        validate_binding(context, self.descriptor()).map(|_| ())
    }

    fn validate(&self, context: &ValidationContext, report: &ReportInput) -> ValidationResult {
        let binding = validate_binding(context, self.descriptor())?;
        let admitted = validate_common(self.descriptor(), context, report)?;
        if admitted.status == SemanticReportStatus::Failed {
            return Ok(admitted);
        }

        let echo_coverage = admitted.coverage.get("echo").copied().ok_or_else(|| {
            ProfileRefusal::new(
                context,
                self.descriptor(),
                RefusalBoundary::Coverage,
                ProfileRefusalCode::MissingCoverage,
                "echo coverage is absent",
            )
        })?;

        match echo_coverage {
            SemanticCoverageState::Complete if admitted.observations.len() != 1 => {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "complete echo coverage requires exactly one observation",
                ));
            }
            SemanticCoverageState::Unavailable if !admitted.observations.is_empty() => {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "unavailable echo coverage cannot contain an observation",
                ));
            }
            _ => {}
        }

        for observation in &admitted.observations {
            let payload: EchoPayload = serde_json::from_value(observation.payload.clone())
                .map_err(|_| {
                    ProfileRefusal::new(
                        context,
                        self.descriptor(),
                        RefusalBoundary::Observation,
                        ProfileRefusalCode::InvalidPayload,
                        "echo payload does not match nq.conformance/v1",
                    )
                    .with_detail("decode_state", "typed_payload_decode_failed")
                })?;
            validate_basis(self.descriptor(), context, &payload.evidence_basis)?;
            if payload.evidence_basis.capabilities_used != admitted.used_capabilities {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "payload capabilities differ from report used_capabilities",
                ));
            }
            if payload.nonce.is_empty() || payload.nonce.len() > 256 {
                return Err(ProfileRefusal::new(
                    context,
                    self.descriptor(),
                    RefusalBoundary::Observation,
                    ProfileRefusalCode::InvalidPayload,
                    "echo nonce must contain 1 through 256 UTF-8 bytes",
                ));
            }
            if binding.nonce != payload.nonce {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "echo nonce differs from the NQ-owned request parameter",
                ));
            }
            if observation.observed_at != admitted.observed_at {
                return Err(inconsistent(
                    context,
                    self.descriptor(),
                    "echo observation time must equal the report observation time",
                ));
            }
        }

        Ok(admitted)
    }

    fn project(&self, report: &ValidatedReport) -> ProjectionResult {
        let mut rows: Vec<Box<dyn ProfileProjection>> =
            Vec::with_capacity(report.observations.len());
        for observation in &report.observations {
            let payload: EchoPayload = serde_json::from_value(observation.payload.clone())
                .map_err(|_| projection_failure(report))?;
            rows.push(Box::new(EchoProjection {
                profile: report.profile.clone(),
                ordinal: observation.ordinal,
                nonce: payload.nonce,
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
) -> Result<FixtureScope, ProfileRefusal> {
    if context.scope.kind != "fixture" {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "conformance scope kind must be fixture",
        ));
    }
    let scope: FixtureScope =
        serde_json::from_value(context.scope.value.clone()).map_err(|_| {
            ProfileRefusal::new(
                context,
                descriptor,
                RefusalBoundary::Profile,
                ProfileRefusalCode::ScopeEscape,
                "conformance scope requires exactly bounded id and nonce strings",
            )
            .with_detail("decode_state", "typed_scope_decode_failed")
        })?;
    if scope.id.is_empty()
        || scope.id.len() > 128
        || scope.nonce.is_empty()
        || scope.nonce.len() > 256
        || context.request_subject != format!("conformance:{}", scope.id)
    {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::ScopeEscape,
            "conformance scope does not correlate with its request subject or bounds",
        ));
    }
    if context.vantage.kind != "local" || context.vantage.value != json!({}) {
        return Err(ProfileRefusal::new(
            context,
            descriptor,
            RefusalBoundary::Profile,
            ProfileRefusalCode::VantageEscape,
            "conformance vantage must be the empty local vantage",
        ));
    }
    Ok(scope)
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

fn projection_failure(report: &ValidatedReport) -> ProfileRefusal {
    ProfileRefusal {
        instance_id: report.instance_id.clone(),
        profile: report.profile.clone(),
        boundary: RefusalBoundary::Observation,
        code: ProfileRefusalCode::InvalidPayload,
        message: "admitted conformance payload could not be projected".to_owned(),
        details: BTreeMap::from([(
            "decode_state".to_owned(),
            "typed_payload_decode_failed".to_owned(),
        )]),
    }
}
