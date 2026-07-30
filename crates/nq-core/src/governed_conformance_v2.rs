//! Dedicated zero-detector V2 derivation for the governed conformance seam.
//!
//! `nq.conformance/v1` validates one exact provider echo and deliberately has
//! no detector.  Treating that profile as though it had a synthetic detector
//! would mint an evaluation occurrence that never happened.  This module
//! instead derives one run-level diagnostic artifact directly from the exact
//! provider-intake carrier and the compiled conformance profile.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use nq_profiles::{
    ProfileModule, ProfileRefusal, ProfileRefusalCode, RefusalBoundary, ReportInput,
    SemanticReportStatus, ValidatedReport, ValidationContext, profile_semantic_id,
};
use nq_protocol::{
    InstanceId, Refusal as HelperRefusal, RefusalBoundary as HelperRefusalBoundary,
    RefusalCode as HelperRefusalCode, ResponseOutcome, Sha256Digest,
};

use crate::{
    diagnostic_execution::{
        AdmittedInputV1, DiagnosticArtifactId, DiagnosticClaimStatusV1, DiagnosticCoherenceV1,
        DiagnosticConditionV1, DiagnosticCoverageV1, DiagnosticDerivationV1,
        DiagnosticLimitationV1, DiagnosticProducerV1, DiagnosticProjectionV1, DiagnosticRequestId,
        DiagnosticRunId, DiagnosticStateBindingV1, DiagnosticSubjectV1, EvidenceAvailabilityV1,
        ExpectedInputV1, NormalizedArtifactId, ProjectedArtifactId, RawArtifactId,
        RawCaptureModeV1, SelectedInputV1, SemanticIdentityV1,
        diagnostic_canonicalization_identity,
    },
    diagnostic_execution_v2::{
        AcquisitionIntervalV2, ClockQualificationV2, DiagnosticClaimV2,
        DiagnosticExecutionSchemaV2, DiagnosticExecutionV2, DiagnosticInputAccountingV2,
        DiagnosticOutcomeV2, FailedAcquisitionCustodyV2, FailedInputCauseV2, FailedInputV2,
        ProfileRefusalBindingV2, ReceivedInputV2, RefusedInputV2,
    },
    engine::{
        AcquisitionFailure, AcquisitionFailureClass, AcquisitionRefusal, EngineError,
        GovernedRefusal, ProtocolRejection, ProtocolRejectionBoundary, ProtocolRejectionCode,
        ProtocolRejectionFailure,
    },
    provider_intake::{
        ProviderIntakeCapacityBound, ProviderIntakeRecordV1, ProviderResponseInterpretationV1,
    },
    runner::AcquisitionOutcome,
};

const EXPECTED_INPUT_ID: &str = "expected:governed-conformance-echo";
const EXPECTED_ROLE: &str = "governed_conformance_echo";
const TESTIMONY_CLAIM_ID: &str = "claim:governed-conformance-testimony";
const ECHO_CLAIM_ID: &str = "claim:governed-conformance-echo";
const INCOMPLETE_STATE_ID: &str = "state:governed-conformance-incomplete-report";
const ECHO_STATE_ID: &str = "state:governed-conformance-echo";
const ADMITTED_REPORT_STATUS_KIND: &str = "admitted_report_status";
const REQUEST_ECHO_KIND: &str = "request_echo";
const TESTIMONY_PROPOSITION: &str = "required governed conformance testimony is available";
const INCOMPLETE_ECHO_PROPOSITION: &str =
    "the admitted provider response establishes the exact bounded conformance echo";
const COMPLETE_ECHO_PROPOSITION: &str =
    "the admitted provider response returned the exact bounded conformance echo";
const SEMANTIC_REPORT_STATUS_DISTINCTION: &str = "semantic_report_status";
const PROVIDER_INTAKE_OCCURRENCE_DISTINCTION: &str = "provider_intake_occurrence";
const NO_QUALIFYING_RESPONSE_LIMITATION: &str = "no qualifying provider response entered custody";
const INCOMPLETE_COVERAGE_LIMITATION: &str =
    "the admitted report did not establish complete echo coverage";
const SUBJECT_ABSENCE_NONCLAIM: &str = "subject absence is not established";
const PROVIDER_FAILURE_NONCLAIM: &str = "provider failure does not establish subject absence";
const HOST_HEALTH_NONCLAIM: &str = "no host health condition is established";
const AUTHORIZATION_NONCLAIM: &str = "no operational authorization is established";
const REFUSED_SUMMARY: &str = "governed conformance testimony was explicitly refused";
const UNAVAILABLE_SUMMARY: &str = "required governed conformance testimony is unavailable";
const PARTIAL_REPORT_SUMMARY: &str =
    "the governed conformance provider returned admitted but incomplete testimony";
const FAILED_REPORT_SUMMARY: &str =
    "the governed conformance provider returned an admitted failed report";
const COMPLETE_SUMMARY: &str = "the bounded governed conformance echo was admitted";
const NORMALIZATION_REFUSAL_MESSAGE: &str =
    "protocol report could not enter conformance validation";
const NORMALIZATION_STAGE_KEY: &str = "stage";
const NORMALIZATION_STAGE_VALUE: &str = "protocol_normalization";
const NORMALIZATION_STATE_KEY: &str = "decode_state";
const NORMALIZATION_STATE_VALUE: &str = "typed_report_normalization_failed";

/// Every fixed string that can enter the derived artifact through this module.
///
/// The capacity specimen uses the longest member rather than an unexplained
/// magic allowance. Provider-derived representations and caller-supplied
/// context fields are accounted separately.
const ARTIFACT_STATIC_TEXTS: &[&str] = &[
    EXPECTED_INPUT_ID,
    EXPECTED_ROLE,
    TESTIMONY_CLAIM_ID,
    ECHO_CLAIM_ID,
    INCOMPLETE_STATE_ID,
    ECHO_STATE_ID,
    ADMITTED_REPORT_STATUS_KIND,
    REQUEST_ECHO_KIND,
    TESTIMONY_PROPOSITION,
    INCOMPLETE_ECHO_PROPOSITION,
    COMPLETE_ECHO_PROPOSITION,
    SEMANTIC_REPORT_STATUS_DISTINCTION,
    PROVIDER_INTAKE_OCCURRENCE_DISTINCTION,
    NO_QUALIFYING_RESPONSE_LIMITATION,
    INCOMPLETE_COVERAGE_LIMITATION,
    SUBJECT_ABSENCE_NONCLAIM,
    PROVIDER_FAILURE_NONCLAIM,
    HOST_HEALTH_NONCLAIM,
    AUTHORIZATION_NONCLAIM,
    REFUSED_SUMMARY,
    UNAVAILABLE_SUMMARY,
    PARTIAL_REPORT_SUMMARY,
    FAILED_REPORT_SUMMARY,
    COMPLETE_SUMMARY,
    NORMALIZATION_REFUSAL_MESSAGE,
    NORMALIZATION_STAGE_KEY,
    NORMALIZATION_STAGE_VALUE,
    NORMALIZATION_STATE_KEY,
    NORMALIZATION_STATE_VALUE,
];

/// Exact already-qualified production surface used for one conformance
/// derivation.
///
/// Construction remains private to nq-core.  It carries no live provider
/// authority and cannot itself invoke anything.
#[derive(Clone)]
pub(crate) struct GovernedConformanceArtifactContext {
    pub producer: DiagnosticProducerV1,
    pub request_id: DiagnosticRequestId,
    pub run_id: DiagnosticRunId,
    pub question: SemanticIdentityV1,
    pub subject: DiagnosticSubjectV1,
    pub profile: SemanticIdentityV1,
    pub profile_semantic_id: Sha256Digest,
    pub vantage: SemanticIdentityV1,
    pub state_model: SemanticIdentityV1,
    pub evaluator: SemanticIdentityV1,
    pub threshold_policy: SemanticIdentityV1,
    pub projection: DiagnosticProjectionV1,
    pub execution_clock: SemanticIdentityV1,
    pub clock_qualification: ClockQualificationV2,
    pub started_at: DateTime<Utc>,
    pub capture_policy: SemanticIdentityV1,
    pub admission_rule: SemanticIdentityV1,
    pub normalization_rule: SemanticIdentityV1,
    pub projection_rule: SemanticIdentityV1,
    pub selection_rule: SemanticIdentityV1,
    pub limitations: Vec<DiagnosticLimitationV1>,
    pub nonclaims: Vec<String>,
}

/// Exact profile-admission material paired with an admitted V2 artifact.
///
/// Persistence consumes this already-derived pair. It must not parse the raw
/// response again or rerun the compiled profile to rediscover either value.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GovernedConformanceAdmittedPersistenceV2 {
    pub report: nq_protocol::EvidenceReport,
    pub validated_report: ValidatedReport,
}

/// Closed origin class for one exact governed refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GovernedConformanceRefusalKindV2 {
    Helper,
    Protocol,
    Profile,
}

/// Closed custody/response class for a terminal acquisition failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GovernedConformanceAcquisitionKindV2 {
    /// A provider response was expected, but the exact failure class proves
    /// that none arrived and no source bytes entered custody.
    ProviderNoResponse,
    /// No source bytes entered custody, but the failure is not a provider
    /// no-response claim.
    NoBytesRetained,
    /// Source bytes entered custody before acquisition failed.
    BytesRetained,
}

/// Exact already-derived material required by the persistence branch.
///
/// This enum is deliberately private to nq-core and carries no live admission
/// or invocation authority. Its variants prevent the effectful engine from
/// deciding a second time what the terminal provider intake meant.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GovernedConformancePersistenceV2 {
    Admitted(Box<GovernedConformanceAdmittedPersistenceV2>),
    Refused {
        kind: GovernedConformanceRefusalKindV2,
        refusal: GovernedRefusal,
    },
    AcquisitionFailed {
        kind: GovernedConformanceAcquisitionKindV2,
        failure: AcquisitionFailure,
        /// Exact acquisition-origin refusal when retained bytes made the
        /// terminal Store result a rejection. No-byte failures have none.
        refusal: Option<GovernedRefusal>,
    },
}

/// One pure V2 derivation paired with the exact typed material to persist.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GovernedConformanceDerivationV2 {
    pub artifact: DiagnosticExecutionV2,
    pub persistence: GovernedConformancePersistenceV2,
}

/// Conservative pre-effect bound for the only V2 artifact shape this module
/// can derive.
///
/// `structural_superset_bytes` is the exact canonical length of a deliberately
/// over-complete one-input artifact containing the admitted, refused, failed,
/// selected, state, claim, and outcome shapes simultaneously. No live branch
/// can contain all of them. `dynamic_source_bytes` then accounts twice for the
/// largest bounded provider-derived representation because an exact refusal
/// may occur once in input accounting and once in the outcome frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub(crate) struct GovernedConformanceArtifactCapacity {
    pub structural_superset_bytes: u64,
    pub dynamic_source_bytes: u64,
    pub canonical_artifact_bytes: u64,
}

fn capacity_error(detail: impl Into<String>) -> EngineError {
    EngineError::Invariant(format!(
        "governed conformance V2 capacity cannot be established: {}",
        detail.into()
    ))
}

fn largest_fixed_refusal_shell(
    responsible_instance_id: &str,
    refusal_id: &str,
) -> Result<GovernedRefusal, EngineError> {
    let acquisition = GovernedRefusal::acquisition(
        refusal_id.to_owned(),
        AcquisitionRefusal {
            responsible_instance_id: responsible_instance_id.to_owned(),
            failure: AcquisitionFailure::from_outcome(AcquisitionOutcome::IoFailed {
                message: String::new(),
            })
            .expect("a non-response outcome always creates a failure"),
        },
    );
    let helper = GovernedRefusal::helper(
        refusal_id.to_owned(),
        HelperRefusal {
            responsible_instance_id: InstanceId::new(responsible_instance_id.to_owned())
                .map_err(|error| capacity_error(error.to_string()))?,
            boundary: HelperRefusalBoundary::Collection,
            code: HelperRefusalCode::CollectionFailed,
            message: String::new(),
            retriable: false,
            details: serde_json::Value::Null,
        },
    );
    let protocol = GovernedRefusal::protocol(
        refusal_id.to_owned(),
        ProtocolRejection {
            responsible_instance_id: responsible_instance_id.to_owned(),
            boundary: ProtocolRejectionBoundary::Response,
            code: ProtocolRejectionCode::InvalidResponse,
            failure: ProtocolRejectionFailure::InvalidFraming,
        },
    );
    let profile = GovernedRefusal::profile(
        refusal_id.to_owned(),
        profile_semantic_id(nq_profiles::conformance::MODULE.descriptor())
            .map_err(|error| capacity_error(error.to_string()))?,
        ProfileRefusal {
            instance_id: responsible_instance_id.to_owned(),
            profile: nq_profiles::conformance::MODULE
                .descriptor()
                .profile
                .clone(),
            boundary: RefusalBoundary::Observation,
            code: ProfileRefusalCode::InvalidPayload,
            message: String::new(),
            details: BTreeMap::new(),
        },
    );
    [acquisition, helper, protocol, profile]
        .into_iter()
        .map(|candidate| {
            nq_protocol::canonical_json_bytes(&candidate)
                .map(|bytes| (bytes.len(), candidate))
                .map_err(|error| capacity_error(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max_by_key(|(length, _)| *length)
        .map(|(_, refusal)| refusal)
        .ok_or_else(|| capacity_error("closed refusal shell set is empty"))
}

/// Compute the pre-effect canonical artifact maximum for this exact
/// zero-detector profile.
///
/// The conformance path has one expected input and no selection fan-out. Raw
/// provider-derived material can enter the artifact only as one projected
/// state value or as one refusal/failure carrier. The latter is duplicated at
/// most once between input accounting and the outcome frontier. The provider
/// intake calculator already includes worst-case RFC 8785 escaping for the
/// admitted response, protocol rejection, and bounded native acquisition
/// detail. All profile-owned parser diagnostics on this path are closed static
/// codes; exact source bytes remain in raw custody.
#[allow(clippy::too_many_lines)]
pub(crate) fn governed_conformance_artifact_capacity_bound(
    context: &GovernedConformanceArtifactContext,
    provider_intake_id: &str,
    responsible_instance_id: &str,
    provider_bound: ProviderIntakeCapacityBound,
) -> Result<GovernedConformanceArtifactCapacity, EngineError> {
    let fill = ARTIFACT_STATIC_TEXTS
        .iter()
        .copied()
        .max_by_key(|value| value.len())
        .ok_or_else(|| capacity_error("closed artifact static-text set is empty"))?
        .to_owned();
    let digest = nq_protocol::sha256_bytes(b"governed-conformance-v2-capacity");
    let input_id = digest.to_string();
    let refusal = largest_fixed_refusal_shell(responsible_instance_id, digest.as_str())?;
    let interval = AcquisitionIntervalV2 {
        started_at: DateTime::<Utc>::MAX_UTC,
        ended_at: DateTime::<Utc>::MAX_UTC,
        clock: context.execution_clock.clone(),
        qualification: context.clock_qualification.clone(),
    };
    let projected_artifact_id = ProjectedArtifactId(digest.clone());
    let state_binding_id = digest.to_string();
    let claim_id = digest.to_string();
    let shell = DiagnosticExecutionV2 {
        schema: DiagnosticExecutionSchemaV2::V2,
        artifact_id: DiagnosticArtifactId(digest.clone()),
        canonicalization: diagnostic_canonicalization_identity()
            .map_err(|error| capacity_error(error.to_string()))?,
        producer: context.producer.clone(),
        request_id: context.request_id.clone(),
        run_id: context.run_id.clone(),
        question: context.question.clone(),
        subject: context.subject.clone(),
        profile: context.profile.clone(),
        profile_semantic_id: context.profile_semantic_id.clone(),
        vantage: context.vantage.clone(),
        state_model: context.state_model.clone(),
        evaluator: context.evaluator.clone(),
        threshold_policy: context.threshold_policy.clone(),
        projection: context.projection.clone(),
        execution_clock: context.execution_clock.clone(),
        started_at: context.started_at,
        completed_at: DateTime::<Utc>::MAX_UTC,
        attempt_interval: interval.clone(),
        inputs: DiagnosticInputAccountingV2 {
            selection_rule: context.selection_rule.clone(),
            expected: vec![ExpectedInputV1 {
                expectation_id: input_id.clone(),
                role: fill.clone(),
                required: true,
            }],
            received: vec![ReceivedInputV2 {
                input_id: input_id.clone(),
                expectation_id: input_id.clone(),
                provider_intake_id: provider_intake_id.to_owned(),
                raw_artifact_id: RawArtifactId(digest.clone()),
                capture_mode: RawCaptureModeV1::ExactSource,
                capture_policy: context.capture_policy.clone(),
                availability_at_derivation: EvidenceAvailabilityV1::Online,
                acquisition: interval.clone(),
                received_at: DateTime::<Utc>::MAX_UTC,
            }],
            admitted: vec![AdmittedInputV1 {
                input_id: input_id.clone(),
                admission_rule: context.admission_rule.clone(),
                normalized_artifact_id: NormalizedArtifactId(digest.clone()),
                normalization_rule: context.normalization_rule.clone(),
                projected_artifact_id: projected_artifact_id.clone(),
                projection_rule: context.projection_rule.clone(),
            }],
            refused: vec![RefusedInputV2 {
                input_id: input_id.clone(),
                refusal: refusal.clone(),
                profile_binding: Some(ProfileRefusalBindingV2::ArtifactProfile),
            }],
            failed: vec![FailedInputV2 {
                expectation_id: input_id.clone(),
                failure_id: input_id.clone(),
                cause: FailedInputCauseV2::AcquisitionFailed {
                    provider_intake_id: provider_intake_id.to_owned(),
                    attempt: interval,
                    raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
                    failure: AcquisitionFailure::from_outcome(AcquisitionOutcome::IoFailed {
                        message: String::new(),
                    })
                    .expect("a non-response outcome always creates a failure"),
                },
            }],
            excluded: vec![],
            selected: vec![SelectedInputV1 {
                input_id: input_id.clone(),
                projected_artifact_id,
                role: fill.clone(),
            }],
        },
        state_bindings: vec![DiagnosticStateBindingV1 {
            binding_id: state_binding_id.clone(),
            kind: fill.clone(),
            value: fill.clone(),
            supporting_input_ids: vec![input_id.clone()],
        }],
        claims: vec![DiagnosticClaimV2 {
            claim_id: claim_id.clone(),
            proposition: fill.clone(),
            status: DiagnosticClaimStatusV1::Unknown,
            condition_effect: Some(DiagnosticConditionV1::Unresolved),
            dependency_input_ids: vec![input_id.clone()],
            dependency_refusal_ids: vec![refusal.refusal_id.clone()],
            dependency_failure_ids: vec![input_id],
            state_binding_ids: vec![state_binding_id],
            required_distinctions: vec![fill.clone()],
            limitations: vec![fill.clone()],
            nonclaims: vec![fill.clone()],
        }],
        primary_claim_id: Some(claim_id),
        outcome: DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::Insufficient,
            coverage: DiagnosticCoverageV1::Partial,
            summary: fill,
            refusals: vec![refusal],
            unsupported: vec![],
        },
        limitations: context.limitations.clone(),
        nonclaims: context.nonclaims.clone(),
    };
    let structural_superset_bytes = u64::try_from(
        nq_protocol::canonical_json_bytes(&shell)
            .map_err(|error| capacity_error(error.to_string()))?
            .len(),
    )
    .map_err(|_| capacity_error("structural shell length exceeds u64"))?;
    let dynamic_unit = provider_bound
        .interpretation_bytes
        .max(provider_bound.native_detail_bytes);
    let dynamic_source_bytes = dynamic_unit
        .checked_mul(2)
        .ok_or_else(|| capacity_error("dynamic provider representation overflowed"))?;
    let canonical_artifact_bytes = structural_superset_bytes
        .checked_add(dynamic_source_bytes)
        .ok_or_else(|| capacity_error("artifact representation overflowed"))?;
    Ok(GovernedConformanceArtifactCapacity {
        structural_superset_bytes,
        dynamic_source_bytes,
        canonical_artifact_bytes,
    })
}

fn occurrence_id(kind: &str, intake: &ProviderIntakeRecordV1) -> Result<String, EngineError> {
    Ok(nq_protocol::semantic_digest(&serde_json::json!({
        "schema": "nq.governed_conformance_occurrence.v1",
        "kind": kind,
        "intake_id": intake.intake_id,
        "attempt_id": intake.attempt_id,
        "run_id": intake.run_id,
        "request_id": intake.request_id,
        "raw_sha256": intake.raw_sha256,
    }))
    .map_err(|error| EngineError::Canonical(error.to_string()))?
    .to_string())
}

fn interval(
    context: &GovernedConformanceArtifactContext,
    intake: &ProviderIntakeRecordV1,
) -> AcquisitionIntervalV2 {
    AcquisitionIntervalV2 {
        started_at: intake.started_at,
        ended_at: intake.finished_at,
        clock: context.execution_clock.clone(),
        qualification: context.clock_qualification.clone(),
    }
}

fn expected_inputs(context: &GovernedConformanceArtifactContext) -> DiagnosticInputAccountingV2 {
    DiagnosticInputAccountingV2 {
        selection_rule: context.selection_rule.clone(),
        expected: vec![ExpectedInputV1 {
            expectation_id: EXPECTED_INPUT_ID.to_owned(),
            role: EXPECTED_ROLE.to_owned(),
            required: true,
        }],
        received: Vec::new(),
        admitted: Vec::new(),
        refused: Vec::new(),
        failed: Vec::new(),
        excluded: Vec::new(),
        selected: Vec::new(),
    }
}

fn received_input(
    context: &GovernedConformanceArtifactContext,
    intake: &ProviderIntakeRecordV1,
) -> Result<ReceivedInputV2, EngineError> {
    Ok(ReceivedInputV2 {
        input_id: occurrence_id("received_input", intake)?,
        expectation_id: EXPECTED_INPUT_ID.to_owned(),
        provider_intake_id: intake.intake_id.clone(),
        raw_artifact_id: RawArtifactId(intake.raw_sha256.clone()),
        capture_mode: RawCaptureModeV1::ExactSource,
        capture_policy: context.capture_policy.clone(),
        availability_at_derivation: EvidenceAvailabilityV1::Online,
        acquisition: interval(context, intake),
        received_at: intake.received_at,
    })
}

#[allow(clippy::too_many_arguments)]
fn seal(
    context: GovernedConformanceArtifactContext,
    completed_at: DateTime<Utc>,
    attempt_interval: AcquisitionIntervalV2,
    inputs: DiagnosticInputAccountingV2,
    state_bindings: Vec<DiagnosticStateBindingV1>,
    claims: Vec<DiagnosticClaimV2>,
    primary_claim_id: Option<String>,
    outcome: DiagnosticOutcomeV2,
) -> Result<DiagnosticExecutionV2, EngineError> {
    let mut artifact = DiagnosticExecutionV2 {
        schema: DiagnosticExecutionSchemaV2::V2,
        artifact_id: DiagnosticArtifactId(nq_protocol::sha256_bytes(
            b"governed-conformance-v2-placeholder",
        )),
        canonicalization: diagnostic_canonicalization_identity()
            .map_err(|error| EngineError::Canonical(error.to_string()))?,
        producer: context.producer,
        request_id: context.request_id,
        run_id: context.run_id,
        question: context.question,
        subject: context.subject,
        profile: context.profile,
        profile_semantic_id: context.profile_semantic_id,
        vantage: context.vantage,
        state_model: context.state_model,
        evaluator: context.evaluator,
        threshold_policy: context.threshold_policy,
        projection: context.projection,
        execution_clock: context.execution_clock,
        started_at: context.started_at,
        completed_at,
        attempt_interval,
        inputs,
        state_bindings,
        claims,
        primary_claim_id,
        outcome,
        limitations: context.limitations,
        nonclaims: context.nonclaims,
    };
    artifact.artifact_id = artifact
        .computed_artifact_id()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    artifact
        .canonical_bytes()
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    Ok(artifact)
}

fn refusal_id(origin: &str, intake: &ProviderIntakeRecordV1) -> Result<String, EngineError> {
    occurrence_id(&format!("{origin}_refusal"), intake)
}

fn refused_artifact(
    context: GovernedConformanceArtifactContext,
    intake: &ProviderIntakeRecordV1,
    refusal: GovernedRefusal,
    profile_binding: Option<ProfileRefusalBindingV2>,
) -> Result<DiagnosticExecutionV2, EngineError> {
    let attempt_interval = interval(&context, intake);
    let mut inputs = expected_inputs(&context);
    let received = received_input(&context, intake)?;
    inputs.refused.push(RefusedInputV2 {
        input_id: received.input_id.clone(),
        refusal: refusal.clone(),
        profile_binding,
    });
    inputs.received.push(received);
    seal(
        context,
        intake.received_at,
        attempt_interval,
        inputs,
        vec![],
        vec![],
        None,
        DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Refused,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Partial,
            summary: REFUSED_SUMMARY.to_owned(),
            refusals: vec![refusal],
            unsupported: vec![],
        },
    )
}

fn no_bytes_failure_artifact(
    context: GovernedConformanceArtifactContext,
    intake: &ProviderIntakeRecordV1,
    failure: AcquisitionFailure,
) -> Result<DiagnosticExecutionV2, EngineError> {
    let attempt_interval = interval(&context, intake);
    let mut inputs = expected_inputs(&context);
    let cause = if provider_no_response(&failure) {
        FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id: intake.intake_id.clone(),
            attempt: attempt_interval.clone(),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure,
        }
    } else {
        FailedInputCauseV2::AcquisitionFailed {
            provider_intake_id: intake.intake_id.clone(),
            attempt: attempt_interval.clone(),
            raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
            failure,
        }
    };
    let failure_id = occurrence_id("failed_input", intake)?;
    inputs.failed.push(FailedInputV2 {
        expectation_id: EXPECTED_INPUT_ID.to_owned(),
        failure_id: failure_id.clone(),
        cause,
    });
    let claim_id = TESTIMONY_CLAIM_ID.to_owned();
    seal(
        context,
        intake.received_at,
        attempt_interval,
        inputs,
        vec![],
        vec![DiagnosticClaimV2 {
            claim_id: claim_id.clone(),
            proposition: TESTIMONY_PROPOSITION.to_owned(),
            status: DiagnosticClaimStatusV1::Unknown,
            condition_effect: Some(DiagnosticConditionV1::Unresolved),
            dependency_input_ids: vec![],
            dependency_refusal_ids: vec![],
            dependency_failure_ids: vec![failure_id],
            state_binding_ids: vec![],
            required_distinctions: vec![],
            limitations: vec![NO_QUALIFYING_RESPONSE_LIMITATION.to_owned()],
            nonclaims: vec![SUBJECT_ABSENCE_NONCLAIM.to_owned()],
        }],
        Some(claim_id),
        DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Partial,
            condition: DiagnosticConditionV1::Unresolved,
            coherence: DiagnosticCoherenceV1::NotEvaluated,
            coverage: DiagnosticCoverageV1::Missing,
            summary: UNAVAILABLE_SUMMARY.to_owned(),
            refusals: vec![],
            unsupported: vec![],
        },
    )
}

fn provider_no_response(failure: &AcquisitionFailure) -> bool {
    matches!(
        failure.class,
        AcquisitionFailureClass::Timeout
            | AcquisitionFailureClass::Eof
            | AcquisitionFailureClass::HelperExited
            | AcquisitionFailureClass::Disconnect
    )
}

#[allow(clippy::too_many_lines)]
fn admitted_artifact(
    context: GovernedConformanceArtifactContext,
    intake: &ProviderIntakeRecordV1,
    report: &nq_protocol::EvidenceReport,
) -> Result<(DiagnosticExecutionV2, ValidatedReport), EngineError> {
    let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
    let native_profile_semantic_id = profile_semantic_id(profile.descriptor())
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let report_digest = nq_protocol::semantic_digest(report)
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let normalization_refusal_id = refusal_id("normalization", intake)?;
    let normalized = ReportInput::from_protocol(report, &report_digest).map_err(|_| {
        EngineError::GovernedRefusal(Box::new(GovernedRefusal::profile(
            normalization_refusal_id,
            native_profile_semantic_id.clone(),
            ProfileRefusal {
                instance_id: intake.request.instance_id.to_string(),
                profile: profile.descriptor().profile.clone(),
                boundary: RefusalBoundary::Report,
                code: ProfileRefusalCode::InvalidPayload,
                message: NORMALIZATION_REFUSAL_MESSAGE.to_owned(),
                details: BTreeMap::from([
                    (
                        NORMALIZATION_STAGE_KEY.to_owned(),
                        NORMALIZATION_STAGE_VALUE.to_owned(),
                    ),
                    (
                        NORMALIZATION_STATE_KEY.to_owned(),
                        NORMALIZATION_STATE_VALUE.to_owned(),
                    ),
                ]),
            },
        )))
    })?;
    let reliance_seconds =
        i64::try_from(profile.descriptor().freshness.reliance_seconds).map_err(|_| {
            EngineError::Invariant(
                "compiled conformance freshness exceeds the supported duration".to_owned(),
            )
        })?;
    let validation_context = ValidationContext::from_request(
        &intake.request,
        intake.received_at,
        Duration::seconds(reliance_seconds),
    );
    let profile_refusal_id = refusal_id("profile", intake)?;
    let validated = profile
        .validate(&validation_context, &normalized)
        .map_err(|refusal| {
            EngineError::GovernedRefusal(Box::new(GovernedRefusal::profile(
                profile_refusal_id,
                native_profile_semantic_id.clone(),
                refusal,
            )))
        })?;
    let projection_refusal_id = refusal_id("projection", intake)?;
    let projected = profile.project(&validated).map_err(|refusal| {
        EngineError::GovernedRefusal(Box::new(GovernedRefusal::profile(
            projection_refusal_id,
            native_profile_semantic_id,
            refusal,
        )))
    })?;
    let normalized_id = NormalizedArtifactId(
        nq_protocol::semantic_digest(&validated)
            .map_err(|error| EngineError::Canonical(error.to_string()))?,
    );
    let projected_document = if validated.status == SemanticReportStatus::Complete {
        let [projection] = projected.as_slice() else {
            return Err(EngineError::Invariant(
                "complete admitted conformance echo projection is not exactly one row".to_owned(),
            ));
        };
        projection.canonical_json()
    } else {
        serde_json::Value::Array(
            projected
                .iter()
                .map(|projection| projection.canonical_json())
                .collect(),
        )
    };
    let projected_id = ProjectedArtifactId(
        nq_protocol::semantic_digest(&projected_document)
            .map_err(|error| EngineError::Canonical(error.to_string()))?,
    );
    let received = received_input(&context, intake)?;
    let input_id = received.input_id.clone();
    let mut inputs = expected_inputs(&context);
    inputs.received.push(received);
    inputs.admitted.push(AdmittedInputV1 {
        input_id: input_id.clone(),
        admission_rule: context.admission_rule.clone(),
        normalized_artifact_id: normalized_id,
        normalization_rule: context.normalization_rule.clone(),
        projected_artifact_id: projected_id.clone(),
        projection_rule: context.projection_rule.clone(),
    });
    inputs.selected.push(SelectedInputV1 {
        input_id: input_id.clone(),
        projected_artifact_id: projected_id.clone(),
        role: EXPECTED_ROLE.to_owned(),
    });

    if validated.status != SemanticReportStatus::Complete {
        let state_binding_id = INCOMPLETE_STATE_ID.to_owned();
        let claim_id = TESTIMONY_CLAIM_ID.to_owned();
        let state = serde_json::json!({
            "status": validated.status,
            "coverage": validated.coverage,
            "error_count": validated.error_count,
            "failure_error_count": validated.failure_error_count,
            "projected_artifact_id": projected_id,
        });
        let coverage = if validated.status == SemanticReportStatus::Partial {
            DiagnosticCoverageV1::Partial
        } else {
            DiagnosticCoverageV1::Missing
        };
        let summary = if validated.status == SemanticReportStatus::Partial {
            PARTIAL_REPORT_SUMMARY
        } else {
            FAILED_REPORT_SUMMARY
        };
        let attempt_interval = interval(&context, intake);
        let artifact = seal(
            context,
            intake.received_at,
            attempt_interval,
            inputs,
            vec![DiagnosticStateBindingV1 {
                binding_id: state_binding_id.clone(),
                kind: ADMITTED_REPORT_STATUS_KIND.to_owned(),
                value: String::from_utf8(
                    nq_protocol::canonical_json_bytes(&state)
                        .map_err(|error| EngineError::Canonical(error.to_string()))?,
                )
                .map_err(|error| EngineError::Canonical(error.to_string()))?,
                supporting_input_ids: vec![input_id.clone()],
            }],
            vec![DiagnosticClaimV2 {
                claim_id: claim_id.clone(),
                proposition: INCOMPLETE_ECHO_PROPOSITION.to_owned(),
                status: DiagnosticClaimStatusV1::Unknown,
                condition_effect: Some(DiagnosticConditionV1::Unresolved),
                dependency_input_ids: vec![input_id],
                dependency_refusal_ids: vec![],
                dependency_failure_ids: vec![],
                state_binding_ids: vec![state_binding_id],
                required_distinctions: vec![SEMANTIC_REPORT_STATUS_DISTINCTION.to_owned()],
                limitations: vec![INCOMPLETE_COVERAGE_LIMITATION.to_owned()],
                nonclaims: vec![
                    AUTHORIZATION_NONCLAIM.to_owned(),
                    PROVIDER_FAILURE_NONCLAIM.to_owned(),
                ],
            }],
            Some(claim_id),
            DiagnosticOutcomeV2 {
                derivation: DiagnosticDerivationV1::Partial,
                condition: DiagnosticConditionV1::Unresolved,
                coherence: DiagnosticCoherenceV1::Insufficient,
                coverage,
                summary: summary.to_owned(),
                refusals: vec![],
                unsupported: vec![],
            },
        )?;
        return Ok((artifact, validated));
    }
    let state_binding_id = ECHO_STATE_ID.to_owned();
    let claim_id = ECHO_CLAIM_ID.to_owned();
    let attempt_interval = interval(&context, intake);
    let artifact = seal(
        context,
        intake.received_at,
        attempt_interval,
        inputs,
        vec![DiagnosticStateBindingV1 {
            binding_id: state_binding_id.clone(),
            kind: REQUEST_ECHO_KIND.to_owned(),
            value: String::from_utf8(
                nq_protocol::canonical_json_bytes(&projected_document)
                    .map_err(|error| EngineError::Canonical(error.to_string()))?,
            )
            .map_err(|error| EngineError::Canonical(error.to_string()))?,
            supporting_input_ids: vec![input_id.clone()],
        }],
        vec![DiagnosticClaimV2 {
            claim_id: claim_id.clone(),
            proposition: COMPLETE_ECHO_PROPOSITION.to_owned(),
            status: DiagnosticClaimStatusV1::Established,
            condition_effect: Some(DiagnosticConditionV1::NotApplicable),
            dependency_input_ids: vec![input_id],
            dependency_refusal_ids: vec![],
            dependency_failure_ids: vec![],
            state_binding_ids: vec![state_binding_id],
            required_distinctions: vec![PROVIDER_INTAKE_OCCURRENCE_DISTINCTION.to_owned()],
            limitations: vec![],
            nonclaims: vec![
                HOST_HEALTH_NONCLAIM.to_owned(),
                AUTHORIZATION_NONCLAIM.to_owned(),
            ],
        }],
        Some(claim_id),
        DiagnosticOutcomeV2 {
            derivation: DiagnosticDerivationV1::Completed,
            condition: DiagnosticConditionV1::NotApplicable,
            coherence: DiagnosticCoherenceV1::JointlyEstablished,
            coverage: DiagnosticCoverageV1::Complete,
            summary: COMPLETE_SUMMARY.to_owned(),
            refusals: vec![],
            unsupported: vec![],
        },
    )?;
    Ok((artifact, validated))
}

/// Derive exactly one zero-detector V2 artifact from a verified provider-intake
/// carrier.
///
/// This is a pure interpretation boundary.  It never invokes a provider,
/// changes topology, schedules work, establishes consumer reliance, or grants
/// authorization.
#[allow(clippy::too_many_lines)]
pub(crate) fn derive_governed_conformance_v2(
    context: GovernedConformanceArtifactContext,
    intake: &ProviderIntakeRecordV1,
    raw_bytes: &[u8],
) -> Result<GovernedConformanceDerivationV2, EngineError> {
    intake.verify_historical_raw(raw_bytes)?;
    if context.run_id.as_str() != intake.run_id
        || intake.raw_length != raw_bytes.len()
        || intake.raw_sha256 != nq_protocol::sha256_bytes(raw_bytes)
        || context.profile_semantic_id.as_str()
            != profile_semantic_id(nq_profiles::conformance::MODULE.descriptor())
                .map_err(|error| EngineError::Canonical(error.to_string()))?
                .as_str()
    {
        return Err(EngineError::Invariant(
            "governed conformance context differs from the exact provider intake or compiled profile"
                .to_owned(),
        ));
    }
    let attempt_interval = interval(&context, intake);
    if context.started_at > intake.started_at || attempt_interval.ended_at > intake.received_at {
        return Err(EngineError::Invariant(
            "governed conformance occurrence times are not ordered".to_owned(),
        ));
    }

    match &intake.interpretation {
        ProviderResponseInterpretationV1::Validated { response } => match &response.outcome {
            ResponseOutcome::Report { report } => {
                match admitted_artifact(context.clone(), intake, report) {
                    Ok((artifact, validated_report)) => Ok(GovernedConformanceDerivationV2 {
                        artifact,
                        persistence: GovernedConformancePersistenceV2::Admitted(Box::new(
                            GovernedConformanceAdmittedPersistenceV2 {
                                report: report.clone(),
                                validated_report,
                            },
                        )),
                    }),
                    Err(EngineError::GovernedRefusal(refusal)) => {
                        let refusal = *refusal;
                        let artifact = refused_artifact(
                            context,
                            intake,
                            refusal.clone(),
                            Some(ProfileRefusalBindingV2::ArtifactProfile),
                        )?;
                        Ok(GovernedConformanceDerivationV2 {
                            artifact,
                            persistence: GovernedConformancePersistenceV2::Refused {
                                kind: GovernedConformanceRefusalKindV2::Profile,
                                refusal,
                            },
                        })
                    }
                    Err(error) => Err(error),
                }
            }
            ResponseOutcome::Refusal { refusal } => {
                let refusal =
                    GovernedRefusal::helper(refusal_id("helper", intake)?, refusal.clone());
                let artifact = refused_artifact(context, intake, refusal.clone(), None)?;
                Ok(GovernedConformanceDerivationV2 {
                    artifact,
                    persistence: GovernedConformancePersistenceV2::Refused {
                        kind: GovernedConformanceRefusalKindV2::Helper,
                        refusal,
                    },
                })
            }
        },
        ProviderResponseInterpretationV1::ProtocolRejected { rejection } => {
            let refusal =
                GovernedRefusal::protocol(refusal_id("protocol", intake)?, rejection.clone());
            let artifact = refused_artifact(context, intake, refusal.clone(), None)?;
            Ok(GovernedConformanceDerivationV2 {
                artifact,
                persistence: GovernedConformancePersistenceV2::Refused {
                    kind: GovernedConformanceRefusalKindV2::Protocol,
                    refusal,
                },
            })
        }
        ProviderResponseInterpretationV1::NotAvailable if raw_bytes.is_empty() => {
            let failure = AcquisitionFailure::from_outcome(intake.native_outcome.outcome.clone())
                .ok_or_else(|| {
                EngineError::Invariant(
                    "provider response cannot be represented as a no-byte failure".to_owned(),
                )
            })?;
            let kind = if provider_no_response(&failure) {
                GovernedConformanceAcquisitionKindV2::ProviderNoResponse
            } else {
                GovernedConformanceAcquisitionKindV2::NoBytesRetained
            };
            let artifact = no_bytes_failure_artifact(context, intake, failure.clone())?;
            Ok(GovernedConformanceDerivationV2 {
                artifact,
                persistence: GovernedConformancePersistenceV2::AcquisitionFailed {
                    kind,
                    failure,
                    refusal: None,
                },
            })
        }
        ProviderResponseInterpretationV1::NotAvailable => {
            let failure = AcquisitionFailure::from_outcome(intake.native_outcome.outcome.clone())
                .ok_or_else(|| {
                EngineError::Invariant(
                    "provider response cannot justify retained acquisition refusal".to_owned(),
                )
            })?;
            let refusal = GovernedRefusal::acquisition(
                refusal_id("acquisition", intake)?,
                AcquisitionRefusal {
                    responsible_instance_id: intake.request.instance_id.to_string(),
                    failure: failure.clone(),
                },
            );
            let artifact = refused_artifact(context, intake, refusal.clone(), None)?;
            Ok(GovernedConformanceDerivationV2 {
                artifact,
                persistence: GovernedConformancePersistenceV2::AcquisitionFailed {
                    kind: GovernedConformanceAcquisitionKindV2::BytesRetained,
                    failure,
                    refusal: Some(refusal),
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Duration;
    use nq_protocol::{
        BackendIdentity, BackendProvenance, CoverageDeclaration, CoverageKind, CoverageState,
        ErrorCode, ErrorSeverity, EvidenceReport, HelperRequest, HelperResponse,
        ImplementationName, InstanceId, MonotonicDeadline, Observation, ObservationKind,
        ProfileBinding, ProfileId, ProfileVersion, Refusal, RefusalBoundary as NativeBoundary,
        RefusalCode, ReportError, ReportStatus, RequestId, ScopeBinding, ScopeKind, SubjectBinding,
        SubjectId, VantageBinding, VantageKind,
    };
    use serde_json::json;

    use super::*;
    use crate::{
        admission::ConformanceReceipt,
        diagnostic_execution::{DiagnosticLimitationKindV1, OmittedDistinctionV1},
        engine::{
            GovernedRefusalOrigin, RunHardLimits, RunResourceOutcomeSchema, RunResourceOutcomeV1,
        },
        provider_intake::{
            ProviderIdentitySchema, ProviderIdentityV1, ProviderIntakeContextSchema,
            ProviderIntakeContextV1, ProviderIntakeSchema, ProviderKind, interpret_response,
        },
        runner::RunCapture,
    };

    fn at(offset_ms: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-29T12:00:00.000Z")
            .expect("fixture time")
            .with_timezone(&Utc)
            + Duration::milliseconds(offset_ms)
    }

    fn identity(id: &str) -> SemanticIdentityV1 {
        SemanticIdentityV1 {
            id: id.to_owned(),
            version: "fixture-v1".to_owned(),
            digest: nq_protocol::semantic_digest(&json!({
                "schema": "nq.test.semantic_identity.v1",
                "id": id,
                "version": "fixture-v1",
            }))
            .expect("semantic identity"),
        }
    }

    fn request(suffix: &str) -> HelperRequest {
        let descriptor = nq_profiles::conformance::MODULE.descriptor();
        HelperRequest::builder(
            RequestId::new(format!("request-{suffix}")).expect("request identity"),
            InstanceId::new("conformance-fixture.instance").expect("instance identity"),
            ProfileBinding {
                id: ProfileId::new(descriptor.profile.id.clone()).expect("profile id"),
                version: ProfileVersion::new(descriptor.profile.version.to_string())
                    .expect("profile version"),
                digest: Sha256Digest::parse(
                    descriptor
                        .digest()
                        .expect("profile descriptor digest")
                        .as_str()
                        .to_owned(),
                )
                .expect("profile digest"),
            },
            SubjectBinding {
                subject: SubjectId::new("conformance:governed-v2").expect("subject"),
                scope: ScopeBinding {
                    kind: ScopeKind::new("fixture").expect("scope kind"),
                    value: json!({
                        "id": "governed-v2",
                        "nonce": "exact-nonce",
                    }),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").expect("vantage"),
                    value: json!({}),
                },
            },
            MonotonicDeadline {
                clock: nq_protocol::MonotonicClock::LinuxBoottime,
                expires_at_ns: 10_000_000_000,
            },
        )
        .build()
        .expect("conformance request")
    }

    fn provider_identity() -> ProviderIdentityV1 {
        let conformance = ConformanceReceipt {
            tool_version: "governed-v2-fixture".to_owned(),
            protocol_passed: true,
            protocol_corpus_digest: nq_protocol::sha256_bytes(b"fixture protocol corpus")
                .into_string(),
            protocol_fixtures_checked: 1,
            dry_collection_passed: true,
            dry_report_digest: Some(nq_protocol::sha256_bytes(b"fixture dry report").into_string()),
        };
        let conformance_document = nq_store::CanonicalDocument::from_serializable(&conformance)
            .expect("canonical conformance receipt");
        ProviderIdentityV1 {
            schema: ProviderIdentitySchema::V1,
            kind: ProviderKind::LocalHelper,
            provider_semantic_id: nq_store::local_provider_semantic_id(
                nq_protocol::HELPER_PROTOCOL_VERSION,
                &conformance_document,
            )
            .expect("provider semantic identity"),
            provider_admission_id: nq_protocol::sha256_bytes(b"provider admission"),
            source_admission_id: "source-admission-fixture".to_owned(),
            binding_digest: nq_protocol::sha256_bytes(b"binding"),
            artifact_digest: nq_protocol::sha256_bytes(b"provider artifact"),
            execution_identity_digest: nq_protocol::sha256_bytes(b"execution identity"),
            configuration_digest: nq_protocol::sha256_bytes(b"configuration"),
            protocol_identity: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            conformance_corpus_digest: Sha256Digest::parse(
                conformance.protocol_corpus_digest.clone(),
            )
            .expect("corpus digest"),
            conformance_tool_version: conformance.tool_version.clone(),
            conformance,
            profile_semantic_id: nq_protocol::sha256_bytes(b"profile semantics"),
            evaluator_artifact_digest: nq_protocol::sha256_bytes(b"evaluator artifact"),
            admission_context_digest: nq_protocol::sha256_bytes(b"admission context"),
        }
    }

    fn report(request: &HelperRequest, status: ReportStatus) -> EvidenceReport {
        let observed_at = at(0);
        let (coverage, observations, errors) = match status {
            ReportStatus::Complete => (
                CoverageState::Complete,
                vec![Observation {
                    ordinal: 0,
                    kind: ObservationKind::new("echo").expect("observation kind"),
                    subject: request.binding.subject.clone(),
                    observed_at,
                    payload: json!({
                        "evidence_basis": {
                            "scope": request.binding.scope,
                            "vantage": request.binding.vantage,
                            "access_path": "process",
                            "basis": "request_echo",
                            "regime": "conformance",
                            "capabilities_used": [],
                        },
                        "nonce": "exact-nonce",
                    }),
                }],
                vec![],
            ),
            ReportStatus::Partial => (
                CoverageState::Partial,
                vec![Observation {
                    ordinal: 0,
                    kind: ObservationKind::new("echo").expect("observation kind"),
                    subject: request.binding.subject.clone(),
                    observed_at,
                    payload: json!({
                        "evidence_basis": {
                            "scope": request.binding.scope,
                            "vantage": request.binding.vantage,
                            "access_path": "process",
                            "basis": "request_echo",
                            "regime": "conformance",
                            "capabilities_used": [],
                        },
                        "nonce": "exact-nonce",
                    }),
                }],
                vec![ReportError {
                    code: ErrorCode::new("partial_echo").expect("error code"),
                    severity: ErrorSeverity::Warning,
                    message: "bounded partial testimony".to_owned(),
                    subject: None,
                    observation_ordinal: Some(0),
                    retriable: false,
                }],
            ),
            ReportStatus::Failed => (
                CoverageState::Unavailable,
                vec![],
                vec![ReportError {
                    code: ErrorCode::new("echo_failed").expect("error code"),
                    severity: ErrorSeverity::Error,
                    message: "bounded failed testimony".to_owned(),
                    subject: None,
                    observation_ordinal: None,
                    retriable: true,
                }],
            ),
        };
        EvidenceReport {
            schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
            profile: request.profile.clone(),
            binding: request.binding.clone(),
            observed_at,
            status,
            coverage: vec![CoverageDeclaration {
                kind: CoverageKind::new("echo").expect("coverage kind"),
                subject: None,
                state: coverage,
                detail: None,
            }],
            observations,
            errors,
            used_capabilities: vec![],
            backend: BackendProvenance {
                implementation: BackendIdentity {
                    name: ImplementationName::new("governed-v2-fixture").expect("implementation"),
                    version: Some("1".to_owned()),
                    digest: None,
                },
                tools: vec![],
            },
            next_checkpoint: None,
        }
    }

    fn response_bytes(response: &HelperResponse) -> Vec<u8> {
        nq_protocol::encode_ndjson(response).expect("response frame")
    }

    fn intake(
        suffix: &str,
        request: HelperRequest,
        raw: &[u8],
        outcome: AcquisitionOutcome,
    ) -> ProviderIntakeRecordV1 {
        let started_at = at(0);
        let finished_at = at(1);
        let provider = provider_identity();
        let intake_id = format!("intake-{suffix}");
        let attempt_id = format!("attempt-{suffix}");
        let run_id = format!("run-{suffix}");
        let deadline_at = at(10_000);
        let checkpoint_contract_digest = nq_protocol::sha256_bytes(b"checkpoint contract");
        let capture = RunCapture {
            started_at,
            finished_at,
            duration_ms: 1,
            exit_code: (outcome == AcquisitionOutcome::Response).then_some(0),
            stdout: raw.to_owned(),
            stderr: vec![],
            outcome: outcome.clone(),
        };
        let interpretation = interpret_response(&request, &capture);
        let request_digest =
            nq_protocol::semantic_digest(&request).expect("request semantic identity");
        let context_digest = nq_protocol::semantic_digest(&ProviderIntakeContextV1 {
            schema: ProviderIntakeContextSchema::V1,
            intake_id: intake_id.clone(),
            attempt_id: attempt_id.clone(),
            run_id: run_id.clone(),
            request: request.clone(),
            provider: provider.clone(),
            origin_carrier: "stdio".to_owned(),
            deadline_at,
            checkpoint_contract_digest: checkpoint_contract_digest.clone(),
        })
        .expect("context semantic identity");
        let record = ProviderIntakeRecordV1 {
            schema: ProviderIntakeSchema::V1,
            intake_id,
            attempt_id: attempt_id.clone(),
            idempotency_key: nq_store::provider_idempotency_key(
                provider.provider_admission_id.as_str(),
                &attempt_id,
            )
            .expect("idempotency key"),
            run_id,
            request_id: request.request_id.to_string(),
            request,
            provider,
            origin_carrier: "stdio".to_owned(),
            deadline_at,
            request_digest,
            context_digest,
            checkpoint_contract_digest,
            started_at,
            finished_at,
            received_at: finished_at,
            native_outcome: RunResourceOutcomeV1 {
                schema: RunResourceOutcomeSchema::V1,
                duration_ms: 1,
                exit_code: capture.exit_code,
                hard_limits: RunHardLimits {
                    address_space_bytes_per_process: 1,
                    cpu_seconds_per_process: 1,
                    processes_per_execution_uid: 1,
                    open_files_per_process: 1,
                    file_bytes_per_regular_file: 1,
                    core_bytes: 0,
                },
                stdout_bytes_retained: raw.len(),
                stderr_bytes_retained: 0,
                stderr_hex: String::new(),
                outcome,
            },
            raw_length: raw.len(),
            raw_sha256: nq_protocol::sha256_bytes(raw),
            provider_sequence: None,
            interpretation,
        };
        record
            .verify_historical_raw(raw)
            .expect("historical intake remains exactly reconstructible");
        record
    }

    fn context(intake: &ProviderIntakeRecordV1) -> GovernedConformanceArtifactContext {
        let profile_semantic_id =
            profile_semantic_id(nq_profiles::conformance::MODULE.descriptor())
                .expect("profile semantic identity");
        let profile_semantic_id = Sha256Digest::parse(profile_semantic_id.as_str().to_owned())
            .expect("typed semantic id");
        GovernedConformanceArtifactContext {
            producer: DiagnosticProducerV1 {
                node_id: "node:fixture".to_owned(),
                build: identity("nq-build"),
                cohort: identity("cohort"),
            },
            request_id: DiagnosticRequestId(intake.request_id.clone()),
            run_id: DiagnosticRunId(intake.run_id.clone()),
            question: identity("conformance-question"),
            subject: DiagnosticSubjectV1 {
                id: intake.request.binding.subject.to_string(),
                scope: identity("conformance-scope"),
            },
            profile: SemanticIdentityV1 {
                id: nq_profiles::conformance::PROFILE_ID.to_owned(),
                version: nq_profiles::conformance::PROFILE_VERSION.to_string(),
                digest: profile_semantic_id.clone(),
            },
            profile_semantic_id,
            vantage: identity("local-vantage"),
            state_model: identity("conformance-state-model"),
            evaluator: identity("conformance-evaluator"),
            threshold_policy: identity("no-threshold"),
            projection: DiagnosticProjectionV1 {
                identity: identity("conformance-projection"),
                omitted_distinctions: vec![OmittedDistinctionV1 {
                    code: "backend_presentation".to_owned(),
                    detail: "backend presentation is not diagnostic truth".to_owned(),
                }],
            },
            execution_clock: identity("fixture-clock"),
            clock_qualification: ClockQualificationV2::Bounded {
                maximum_error_ms: 1,
                basis: identity("fixture-clock-qualification"),
            },
            started_at: intake.started_at,
            capture_policy: identity("exact-source-capture"),
            admission_rule: identity("compiled-profile-admission"),
            normalization_rule: identity("conformance-normalization"),
            projection_rule: identity("conformance-projection-rule"),
            selection_rule: identity("single-expected-echo"),
            limitations: vec![DiagnosticLimitationV1 {
                kind: DiagnosticLimitationKindV1::Other,
                code: "fixture_scope".to_owned(),
                detail: "conformance only".to_owned(),
            }],
            nonclaims: vec![AUTHORIZATION_NONCLAIM.to_owned()],
        }
    }

    fn capacity_for(
        context: &GovernedConformanceArtifactContext,
        intake: &ProviderIntakeRecordV1,
    ) -> GovernedConformanceArtifactCapacity {
        let interpretation_bytes = nq_protocol::canonical_json_bytes(&intake.interpretation)
            .expect("canonical interpretation")
            .len();
        let native_bytes = nq_protocol::canonical_json_bytes(&intake.native_outcome.outcome)
            .expect("canonical native outcome")
            .len();
        governed_conformance_artifact_capacity_bound(
            context,
            &intake.intake_id,
            intake.request.instance_id.as_str(),
            ProviderIntakeCapacityBound {
                canonical_record_bytes: 0,
                raw_capture_bytes: u64::try_from(intake.raw_length).expect("raw length"),
                stderr_hex_bytes: 0,
                native_detail_bytes: u64::try_from(native_bytes.saturating_mul(6))
                    .expect("native bound"),
                interpretation_bytes: u64::try_from(interpretation_bytes.saturating_mul(6))
                    .expect("interpretation bound"),
            },
        )
        .expect("finite diagnostic capacity")
    }

    fn derive_case(intake: &ProviderIntakeRecordV1, raw: &[u8]) -> GovernedConformanceDerivationV2 {
        let derivation = derive_governed_conformance_v2(context(intake), intake, raw)
            .expect("terminal family derives");
        let artifact = &derivation.artifact;
        artifact.validate().expect("derived V2 artifact validates");
        let canonical = artifact.canonical_bytes().expect("canonical artifact");
        let bound = capacity_for(&context(intake), intake);
        assert!(
            u64::try_from(canonical.len()).expect("artifact length")
                <= bound.canonical_artifact_bytes,
            "actual {} exceeded conservative {} for {}",
            canonical.len(),
            bound.canonical_artifact_bytes,
            intake.intake_id,
        );
        assert_eq!(
            artifact
                .inputs
                .received
                .first()
                .map(|input| &input.raw_artifact_id),
            (!raw.is_empty()).then_some(&RawArtifactId(nq_protocol::sha256_bytes(raw))),
        );
        assert!(
            artifact
                .nonclaims
                .iter()
                .any(|claim| claim == AUTHORIZATION_NONCLAIM)
        );
        assert_eq!(
            intake.raw_sha256,
            nq_protocol::sha256_bytes(raw),
            "derivation cannot replace the exact source bytes"
        );
        derivation
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn terminal_families_preserve_outcomes_exact_input_identity_and_non_authority() {
        let complete_request = request("complete");
        let complete_report = report(&complete_request, ReportStatus::Complete);
        let complete_raw = response_bytes(&HelperResponse::report(
            &complete_request,
            complete_report.clone(),
        ));
        let complete_intake = intake(
            "complete",
            complete_request,
            &complete_raw,
            AcquisitionOutcome::Response,
        );
        let complete = derive_case(&complete_intake, &complete_raw);
        assert_eq!(
            complete.artifact.outcome.derivation,
            DiagnosticDerivationV1::Completed
        );
        assert_eq!(
            complete.artifact.outcome.coverage,
            DiagnosticCoverageV1::Complete
        );
        assert_eq!(
            complete.artifact.claims[0].status,
            DiagnosticClaimStatusV1::Established
        );
        assert_eq!(
            complete.artifact.claims[0].condition_effect,
            Some(DiagnosticConditionV1::NotApplicable)
        );
        assert!(
            complete.artifact.claims[0]
                .nonclaims
                .iter()
                .any(|claim| claim == AUTHORIZATION_NONCLAIM)
        );
        assert!(matches!(
            &complete.persistence,
            GovernedConformancePersistenceV2::Admitted(admitted)
                if admitted.report == complete_report
                    && admitted.validated_report.status == SemanticReportStatus::Complete
        ));

        for (suffix, status, expected_coverage, expected_summary) in [
            (
                "partial",
                ReportStatus::Partial,
                DiagnosticCoverageV1::Partial,
                PARTIAL_REPORT_SUMMARY,
            ),
            (
                "failed",
                ReportStatus::Failed,
                DiagnosticCoverageV1::Missing,
                FAILED_REPORT_SUMMARY,
            ),
        ] {
            let request = request(suffix);
            let source_report = report(&request, status);
            let raw = response_bytes(&HelperResponse::report(&request, source_report.clone()));
            let intake = intake(suffix, request, &raw, AcquisitionOutcome::Response);
            let derivation = derive_case(&intake, &raw);
            let artifact = &derivation.artifact;
            assert_eq!(artifact.outcome.derivation, DiagnosticDerivationV1::Partial);
            assert_eq!(artifact.outcome.coverage, expected_coverage);
            assert_eq!(artifact.outcome.summary, expected_summary);
            assert_eq!(artifact.claims[0].status, DiagnosticClaimStatusV1::Unknown);
            assert!(
                artifact.claims[0]
                    .nonclaims
                    .iter()
                    .any(|claim| claim == AUTHORIZATION_NONCLAIM)
            );
            let expected_status = match status {
                ReportStatus::Complete => SemanticReportStatus::Complete,
                ReportStatus::Partial => SemanticReportStatus::Partial,
                ReportStatus::Failed => SemanticReportStatus::Failed,
            };
            assert!(matches!(
                &derivation.persistence,
                GovernedConformancePersistenceV2::Admitted(admitted)
                    if admitted.report == source_report
                        && admitted.validated_report.status == expected_status
            ));
        }

        let helper_request = request("helper-refusal");
        let helper_refusal = Refusal {
            responsible_instance_id: helper_request.instance_id.clone(),
            boundary: NativeBoundary::Collection,
            code: RefusalCode::CollectionFailed,
            message: "exact helper refusal".to_owned(),
            retriable: true,
            details: json!({"errno": "EAGAIN", "attempt": 3}),
        };
        let helper_raw = response_bytes(&HelperResponse::refusal(
            &helper_request,
            helper_refusal.clone(),
        ));
        let helper_intake = intake(
            "helper-refusal",
            helper_request,
            &helper_raw,
            AcquisitionOutcome::Response,
        );
        let helper = derive_case(&helper_intake, &helper_raw);
        assert!(matches!(
            &helper.artifact.outcome.refusals[0].origin,
            GovernedRefusalOrigin::Helper(source)
                if source == &helper_refusal && source.details["attempt"] == 3
        ));
        assert!(matches!(
            &helper.persistence,
            GovernedConformancePersistenceV2::Refused {
                kind: GovernedConformanceRefusalKindV2::Helper,
                refusal,
            } if refusal == &helper.artifact.outcome.refusals[0]
        ));

        let protocol_request = request("protocol-rejection");
        let protocol_raw = b"{\"broken\":}\n".to_vec();
        let protocol_intake = intake(
            "protocol-rejection",
            protocol_request,
            &protocol_raw,
            AcquisitionOutcome::Response,
        );
        let protocol = derive_case(&protocol_intake, &protocol_raw);
        assert!(matches!(
            protocol.artifact.outcome.refusals[0].origin,
            GovernedRefusalOrigin::Protocol(_)
        ));
        assert!(matches!(
            &protocol.persistence,
            GovernedConformancePersistenceV2::Refused {
                kind: GovernedConformanceRefusalKindV2::Protocol,
                refusal,
            } if refusal == &protocol.artifact.outcome.refusals[0]
        ));

        let profile_request = request("profile-refusal");
        let mut invalid_report = report(&profile_request, ReportStatus::Complete);
        invalid_report.observations[0].payload["nonce"] = json!("wrong-nonce");
        let profile_raw = response_bytes(&HelperResponse::report(&profile_request, invalid_report));
        let profile_intake = intake(
            "profile-refusal",
            profile_request,
            &profile_raw,
            AcquisitionOutcome::Response,
        );
        let profile = derive_case(&profile_intake, &profile_raw);
        assert!(matches!(
            &profile.artifact.outcome.refusals[0].origin,
            GovernedRefusalOrigin::Profile(source)
                if source.refusal.code == ProfileRefusalCode::InconsistentReport
                    && profile.artifact.inputs.refused[0].profile_binding
                        == Some(ProfileRefusalBindingV2::ArtifactProfile)
        ));
        assert!(matches!(
            &profile.persistence,
            GovernedConformancePersistenceV2::Refused {
                kind: GovernedConformanceRefusalKindV2::Profile,
                refusal,
            } if refusal == &profile.artifact.outcome.refusals[0]
        ));

        let no_bytes_request = request("no-bytes");
        let no_bytes = vec![];
        let no_bytes_intake = intake(
            "no-bytes",
            no_bytes_request,
            &no_bytes,
            AcquisitionOutcome::Eof,
        );
        let unavailable = derive_case(&no_bytes_intake, &no_bytes);
        assert!(unavailable.artifact.inputs.received.is_empty());
        assert!(matches!(
            unavailable.artifact.inputs.failed[0].cause,
            FailedInputCauseV2::ProviderNoResponse {
                raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
                ..
            }
        ));
        assert!(matches!(
            &unavailable.persistence,
            GovernedConformancePersistenceV2::AcquisitionFailed {
                kind: GovernedConformanceAcquisitionKindV2::ProviderNoResponse,
                failure,
                refusal: None,
            } if failure.outcome == AcquisitionOutcome::Eof
        ));

        let failed_before_response_request = request("no-retained-bytes");
        let failed_before_response_raw = vec![];
        let failed_before_response_intake = intake(
            "no-retained-bytes",
            failed_before_response_request,
            &failed_before_response_raw,
            AcquisitionOutcome::SpawnFailed {
                message: "bounded spawn failure".to_owned(),
            },
        );
        let failed_before_response =
            derive_case(&failed_before_response_intake, &failed_before_response_raw);
        assert!(matches!(
            &failed_before_response.persistence,
            GovernedConformancePersistenceV2::AcquisitionFailed {
                kind: GovernedConformanceAcquisitionKindV2::NoBytesRetained,
                failure,
                refusal: None,
            } if failure.outcome
                == AcquisitionOutcome::SpawnFailed {
                    message: "bounded spawn failure".to_owned()
                }
        ));

        let retained_request = request("retained-bytes");
        let retained_raw = b"provider emitted incomplete retained bytes".to_vec();
        let retained_intake = intake(
            "retained-bytes",
            retained_request,
            &retained_raw,
            AcquisitionOutcome::IoFailed {
                message: "bounded read failure".to_owned(),
            },
        );
        let retained = derive_case(&retained_intake, &retained_raw);
        assert_eq!(retained.artifact.inputs.received.len(), 1);
        assert!(matches!(
            &retained.artifact.outcome.refusals[0].origin,
            GovernedRefusalOrigin::Acquisition(source)
                if source.failure.outcome
                    == AcquisitionOutcome::IoFailed {
                        message: "bounded read failure".to_owned()
                    }
        ));
        assert!(matches!(
            &retained.persistence,
            GovernedConformancePersistenceV2::AcquisitionFailed {
                kind: GovernedConformanceAcquisitionKindV2::BytesRetained,
                failure,
                refusal: Some(refusal),
            } if failure.outcome
                == AcquisitionOutcome::IoFailed {
                    message: "bounded read failure".to_owned()
                }
                && refusal == &retained.artifact.outcome.refusals[0]
        ));
    }

    #[test]
    fn static_capacity_source_is_closed_unique_and_load_bearing() {
        let expected = BTreeSet::from([
            EXPECTED_INPUT_ID,
            EXPECTED_ROLE,
            TESTIMONY_CLAIM_ID,
            ECHO_CLAIM_ID,
            INCOMPLETE_STATE_ID,
            ECHO_STATE_ID,
            ADMITTED_REPORT_STATUS_KIND,
            REQUEST_ECHO_KIND,
            TESTIMONY_PROPOSITION,
            INCOMPLETE_ECHO_PROPOSITION,
            COMPLETE_ECHO_PROPOSITION,
            SEMANTIC_REPORT_STATUS_DISTINCTION,
            PROVIDER_INTAKE_OCCURRENCE_DISTINCTION,
            NO_QUALIFYING_RESPONSE_LIMITATION,
            INCOMPLETE_COVERAGE_LIMITATION,
            SUBJECT_ABSENCE_NONCLAIM,
            PROVIDER_FAILURE_NONCLAIM,
            HOST_HEALTH_NONCLAIM,
            AUTHORIZATION_NONCLAIM,
            REFUSED_SUMMARY,
            UNAVAILABLE_SUMMARY,
            PARTIAL_REPORT_SUMMARY,
            FAILED_REPORT_SUMMARY,
            COMPLETE_SUMMARY,
            NORMALIZATION_REFUSAL_MESSAGE,
            NORMALIZATION_STAGE_KEY,
            NORMALIZATION_STAGE_VALUE,
            NORMALIZATION_STATE_KEY,
            NORMALIZATION_STATE_VALUE,
        ]);
        let actual = ARTIFACT_STATIC_TEXTS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            actual.len(),
            ARTIFACT_STATIC_TEXTS.len(),
            "duplicate capacity entries can disguise an omitted source"
        );
        assert_eq!(
            ARTIFACT_STATIC_TEXTS
                .iter()
                .max_by_key(|value| value.len())
                .expect("nonempty closed set")
                .len(),
            INCOMPLETE_ECHO_PROPOSITION.len(),
            "the structural specimen must be driven by the actual longest fixed source"
        );
    }
}
