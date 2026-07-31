//! End-to-end collection, admission, evaluation, and public read-model wiring.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use nix::time::{ClockId, clock_gettime};
use nq_host_role_contract::{
    IdentityKind, IdentityRef, LaunchCorrespondenceSelection, RecordRef, RuntimeSchema,
    ValidatedRuntimeRecord,
};
use nq_host_role_runtime::{
    CustodyRecord, ExternalDependencyAvailability, PreparedGovernedInvocation, RuntimeDependencies,
};
use nq_profiles::{
    DetectorInput, DetectorReport, DetectorState, EVALUATOR_SOURCE_DIGEST, EvidenceWatermark,
    ProfileModule, ProfileSemanticId, ReportInput as ProfileReportInput, ScopeGrant,
    SemanticReportStatus, ValidatedReport, ValidationContext, VantageGrant, profile_semantic_id,
};
use nq_protocol::{
    Capability, Checkpoint, CollectionBounds, HelperRequest, InstanceId, MonotonicClock,
    MonotonicDeadline, ProfileBinding, ProfileId, ProfileVersion, RequestId, ResponseOutcome,
    ScopeBinding, ScopeKind, Sha256Digest, SubjectBinding, SubjectId, VantageBinding, VantageKind,
};
use nq_store::{
    AdmissionIdentity, AdmissionInput, AdmittedCollectionCompletion, BindingEventInput,
    BindingMaterializationInput, CanonicalDocument, CollectionInput, CoverageInput,
    DiagnosticArtifactByteState, DiagnosticArtifactCommitInput, DiagnosticArtifactLocalOriginInput,
    DiagnosticArtifactLookup, DiagnosticArtifactOrigin, DiagnosticArtifactSchemaSupport,
    EvaluationCommitInput, EvaluationInput, EvaluationProfileBinding, EvidenceSnapshot,
    FindingEventInput, FindingEvidenceInput, FindingSnapshotRow, GenesisInput,
    GovernedAcquisitionCustodyInput, GovernedProjectionCapsule, GovernedProjectionCapsuleInput,
    GovernedProjectionCapsuleMode, GovernedProtectedTerminalClass,
    GovernedProtectedTerminalDeadlineCompliance, GovernedProtectedTerminalInput,
    GovernedProtectedTerminalReason, ObservationInput, ProfileDescriptorInput, StoreWriterSession,
    ProviderIntakeCommit, ProviderIntakeInput, ProviderIntakePreflight, RefusalInput,
    ReportErrorInput, ReportInput, RunInput, RunResultStatusInput, StatusEventInput, Store,
    SubmissionDisposition, SubmissionInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::admission::{
    AdmissionError, AdmissionLock, AdmissionManager, CandidateEvidence, ConformanceReceipt,
};
use crate::config::{
    Carrier, CheckpointPolicy, NqConfig, ScopeConfig, VantageConfig, WatcherConfig,
};
use crate::coordination::{CoordinationError, InstanceGuard};
use crate::diagnostic_execution::{
    AdmittedInputV1, DiagnosticArtifactId, DiagnosticClaimStatusV1, DiagnosticCoherenceV1,
    DiagnosticConditionV1, DiagnosticCoverageV1, DiagnosticDerivationV1,
    DiagnosticLimitationKindV1, DiagnosticLimitationV1, DiagnosticProducerV1,
    DiagnosticProjectionV1, DiagnosticRequestId, DiagnosticRunId, DiagnosticStateBindingV1,
    DiagnosticSubjectV1, EvidenceAvailabilityV1, ExpectedInputV1, NormalizedArtifactId,
    ProjectedArtifactId, RawArtifactId, RawCaptureModeV1, SelectedInputV1, SemanticIdentityV1,
    diagnostic_canonicalization_identity,
};
use crate::diagnostic_execution_supported::{
    SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS, SupportedDiagnosticExecution,
};
use crate::diagnostic_execution_v2::{
    AcquisitionIntervalV2, ClockQualificationV2, DIAGNOSTIC_EXECUTION_V2_SCHEMA, DiagnosticClaimV2,
    DiagnosticExecutionSchemaV2, DiagnosticExecutionV2, DiagnosticInputAccountingV2,
    DiagnosticOutcomeV2, FailedAcquisitionCustodyV2, FailedInputCauseV2, FailedInputV2,
    ProfileRefusalBindingV2, ReceivedInputV2, RefusedInputV2,
};
use crate::evaluator_identity::EvaluatorRuntimeIdentity;
use crate::governed_conformance_v2::{
    GovernedConformanceAcquisitionKindV2, GovernedConformanceArtifactCapacity,
    GovernedConformanceArtifactContext, GovernedConformanceDerivationV2,
    GovernedConformancePersistenceV2, GovernedConformanceRefusalKindV2,
    derive_governed_conformance_v2, governed_conformance_artifact_capacity_bound,
};
use crate::governed_custody_projection::construct_governed_custody_projection_v2;
use crate::governed_derivation::construct_governed_derivation_claim;
use crate::governed_execution_binding::construct_governed_execution_binding_v2;
use crate::identity::{ExecutionIdentity, VerifiedLaunch};
use crate::provider_intake::{
    ProviderAttempt, ProviderIntakeContextV1, ProviderIntakeError, ProviderIntakeRecordV1,
    ProviderIntakeV1, ProviderKind, ProviderResponseInterpretationV1, VerifiedProvider,
    interpret_response, provider_intake_capacity_bound,
};
use crate::public::{
    ComponentKind, ComponentStatus, ComponentStatusDetailV2, ComponentStatusDetailV3,
    ComponentStatusV2, ComponentStatusV3, ConditionState, ConditionView, DetectorIdentity,
    EVALUATION_HISTORY_SCHEMA, EvaluationHistoryPageV1, EvaluationHistoryRecordV1,
    FINDING_SNAPSHOT_SCHEMA, FindingSnapshotV3, HealthState, OriginMode, PublicEvidenceReference,
    PublicProfileIdentity, REJECTED_CUSTODY_SCHEMA, RejectedCustodySnapshotV1, RejectedCustodyV1,
    STATUS_SNAPSHOT_SCHEMA, STATUS_SNAPSHOT_V2_SCHEMA, STATUS_SNAPSHOT_V3_SCHEMA, Severity,
    StatusSnapshotV1, StatusSnapshotV2, StatusSnapshotV3, VisibilityState, VisibilityView,
};
use crate::runner::{AcquisitionOutcome, ExchangeTimeoutPhase, RunCapture, StdioRunner};
use crate::unix_runner::{
    UnixAcquisitionOutcome, UnixExchangeCapture, UnixIoPhase, UnixRunner, UnixRunnerOptions,
};

/// Engine-level failures. Expected watcher outcomes are returned as
/// [`CollectionOutcome`] and still committed when applicable.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Generic store failure.
    #[error(transparent)]
    Store(#[from] nq_store::StoreError),
    /// Admission construction or verification failed before a bounded
    /// invocation began.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// Per-instance collection/binding serialization failed.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// Provider identity, attempt, or raw-custody construction failed.
    #[error(transparent)]
    ProviderIntake(#[from] ProviderIntakeError),
    /// The governed host-role runtime or its exact custody transition refused.
    #[error(transparent)]
    HostRoleRuntime(#[from] nq_host_role_runtime::RuntimeError),
    /// Local filesystem failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The configured profile is not compiled.
    #[error("profile {id} v{version} is not compiled")]
    UnknownProfile {
        /// Profile ID.
        id: String,
        /// Profile version.
        version: u32,
    },
    /// The deliberately bounded live diagnostic producer cannot represent this
    /// execution without losing required input distinctions.
    #[error("diagnostic execution unsupported: {0}")]
    DiagnosticUnsupported(String),
    /// The native host-role seam refused before provider effect after
    /// terminalizing the exact already-claimed custody occurrence.
    #[error("governed diagnostic execution refused at {code:?}: {detail}")]
    GovernedExecutionRefused {
        /// Closed native seam check that refused.
        code: GovernedExecutionRefusalCode,
        /// Bounded operator-readable explanation.
        detail: String,
    },
    /// A strict identity token could not be constructed.
    #[error("invalid protocol identity: {0}")]
    Token(String),
    /// Protocol serialization, framing, or echo validation failed in a context
    /// that must itself succeed (such as admission dry collection).
    #[error("helper protocol failure: {0}")]
    Protocol(String),
    /// Compiled profile refused a dry collection or admitted-row reconstruction.
    #[error("profile validation failure: {0}")]
    Profile(String),
    /// Canonical JSON conversion failed.
    #[error("canonical document failure: {0}")]
    Canonical(String),
    /// Durable data contradicted an invariant expected after admission.
    #[error("engine invariant failed: {0}")]
    Invariant(String),
    /// An expected, canonical refusal returned by a dry watcher exchange.
    #[error("{0}")]
    GovernedRefusal(Box<GovernedRefusal>),
    /// A typed acquisition failure returned by a dry watcher exchange.
    #[error("{0}")]
    AcquisitionFailed(Box<AcquisitionFailure>),
}

/// Closed production vocabulary for native governed pre-effect refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedExecutionRefusalCode {
    /// The opaque prepared closure was absent, malformed, or substituted.
    PreparedClosureInvalid,
    /// The outer request occurrence differed.
    OuterRequestSubstitution,
    /// Node, subject, or vantage identity differed.
    ProductionIdentitySubstitution,
    /// The exact topology was not effective at the launch occurrence.
    TopologyNotActive,
    /// No unique effective node/key lifecycle authority existed.
    NodeLifecycleAuthorityUnavailable,
    /// Witness lifecycle continuity could not be established.
    WitnessLifecycleContinuityUnavailable,
    /// The compiled and requested profiles differed.
    ProfileIncompatible,
    /// The selected witness binding differed.
    WitnessBindingMismatch,
    /// The selected provider-admission record differed.
    ProviderAdmissionMismatch,
    /// The configured watcher could not be resolved uniquely.
    WatcherResolutionFailed,
    /// The active helper admission differed.
    ActiveAdmissionMismatch,
    /// Provider or provider-build identity differed.
    ProviderIdentityMismatch,
    /// The conformance witness requested a nonempty host access surface.
    AccessSurfaceNotEmpty,
    /// Native subject, scope, nonce, or vantage binding differed.
    NativeBindingMismatch,
    /// Production identity descriptor custody or resolution failed.
    ProductionDescriptorCorrespondenceUnavailable,
    /// Compiled profile/evaluator correspondence could not be established.
    NativeProfileCorrespondenceUnavailable,
    /// Native clock/deadline correspondence could not be established.
    NativeClockCorrespondenceUnavailable,
    /// Acquisition custody capacity/correspondence could not be established.
    NativeCustodyCorrespondenceUnavailable,
    /// Final diagnostic/closure custody could not be established.
    NativeFinalCustodyCorrespondenceUnavailable,
    /// The exact request or launch deadline was reached or invalid.
    DeadlineExpired,
    /// The retained executable could not be qualified for launch.
    LaunchQualificationFailed,
}

impl GovernedExecutionRefusalCode {
    /// Stable machine-readable reason code retained by protected terminal
    /// custody.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreparedClosureInvalid => "prepared_closure_invalid",
            Self::OuterRequestSubstitution => "outer_request_substitution",
            Self::ProductionIdentitySubstitution => "production_identity_substitution",
            Self::TopologyNotActive => "topology_not_active",
            Self::NodeLifecycleAuthorityUnavailable => "node_lifecycle_authority_unavailable",
            Self::WitnessLifecycleContinuityUnavailable => {
                "witness_lifecycle_continuity_unavailable"
            }
            Self::ProfileIncompatible => "profile_incompatible",
            Self::WitnessBindingMismatch => "witness_binding_mismatch",
            Self::ProviderAdmissionMismatch => "provider_admission_mismatch",
            Self::WatcherResolutionFailed => "watcher_resolution_failed",
            Self::ActiveAdmissionMismatch => "active_admission_mismatch",
            Self::ProviderIdentityMismatch => "provider_identity_mismatch",
            Self::AccessSurfaceNotEmpty => "access_surface_not_empty",
            Self::NativeBindingMismatch => "native_binding_mismatch",
            Self::ProductionDescriptorCorrespondenceUnavailable => {
                "production_descriptor_correspondence_unavailable"
            }
            Self::NativeProfileCorrespondenceUnavailable => {
                "native_profile_correspondence_unavailable"
            }
            Self::NativeClockCorrespondenceUnavailable => "native_clock_correspondence_unavailable",
            Self::NativeCustodyCorrespondenceUnavailable => {
                "native_custody_correspondence_unavailable"
            }
            Self::NativeFinalCustodyCorrespondenceUnavailable => {
                "native_final_custody_correspondence_unavailable"
            }
            Self::DeadlineExpired => "deadline_expired",
            Self::LaunchQualificationFailed => "launch_qualification_failed",
        }
    }
}

#[cfg(test)]
#[path = "engine_checkpoint_commit_tests.rs"]
mod checkpoint_commit_tests;

#[cfg(test)]
#[path = "engine_governed_effect_tests.rs"]
mod governed_effect_tests;
#[cfg(test)]
#[path = "engine_invocation_serialization_tests.rs"]
mod invocation_serialization_tests;

/// Result of an operator watcher test/admission workflow.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WatcherActionOutcome {
    /// Dry collection validated without changing active state.
    Tested {
        /// Instance tested.
        instance_id: String,
        /// Canonical dry-report digest.
        report_digest: String,
        /// Validated report state.
        report_status: String,
    },
    /// A new admission was activated.
    Activated {
        /// Instance activated.
        instance_id: String,
        /// Opaque admission identity.
        admission_id: String,
        /// Digest binding subsequent runs.
        binding_digest: String,
        /// Active lock path.
        lock_path: PathBuf,
        /// Whether an earlier active lock was archived.
        previous_lock_archived: bool,
    },
}

/// Result of a rollback or revocation binding transition.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BindingActionOutcome {
    /// A historical admission became active.
    RolledBack {
        /// Exact instance.
        instance_id: String,
        /// Activated admission.
        admission_id: String,
        /// Active binding digest.
        binding_digest: String,
        /// Derived active lock materialization.
        lock_path: PathBuf,
    },
    /// The active admission was revoked and retained in durable history.
    Revoked {
        /// Exact instance.
        instance_id: String,
        /// Revoked admission.
        admission_id: String,
        /// Retained derived historical materialization.
        retained_lock: PathBuf,
    },
}

/// Exact schema of the canonical collection-result carrier.
pub const COLLECTION_OUTCOME_V1_SCHEMA: &str = "nq.collection_outcome.v1";
/// Admitted carrier schema with exact evaluation envelopes.
pub const COLLECTION_OUTCOME_V2_SCHEMA: &str = "nq.collection_outcome.v2";
/// Current collection carrier schema for newly admitted results.
pub const COLLECTION_OUTCOME_SCHEMA: &str = COLLECTION_OUTCOME_V2_SCHEMA;

/// Exact schema of the canonical refusal carrier embedded in collection results.
pub const GOVERNED_REFUSAL_SCHEMA: &str = "nq.governed_refusal.v1";

/// Exact schema of persisted watcher-run resource and acquisition testimony.
pub const RUN_RESOURCE_OUTCOME_SCHEMA: &str = "nq.run_resource_outcome.v1";

/// Exact schema of persisted governed detector evaluation results.
pub const EVALUATION_RESULT_SCHEMA: &str = "nq.evaluation_result.v1";
/// Closed canonical envelope carrying every engine-owned evaluation identity.
pub const EVALUATION_ENVELOPE_SCHEMA: &str = "nq.evaluation_envelope.v2";

/// Closed collection-result schema identity. Deserialization rejects any other
/// string instead of interpreting future bytes under this version.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum CollectionOutcomeSchema {
    /// First lossless result transport.
    #[serde(rename = "nq.collection_outcome.v1")]
    V1,
    /// Admitted result carrying exact committed evaluation envelopes.
    #[serde(rename = "nq.collection_outcome.v2")]
    V2,
}

/// Closed governed-refusal schema identity.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum GovernedRefusalSchema {
    /// First lossless refusal transport.
    #[serde(rename = "nq.governed_refusal.v1")]
    V1,
}

/// Closed schema identity for persisted watcher-run resource testimony.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum RunResourceOutcomeSchema {
    /// First exact acquisition/resource envelope.
    #[serde(rename = "nq.run_resource_outcome.v1")]
    V1,
}

/// Exact hard limits recorded with one watcher run.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunHardLimits {
    /// Maximum virtual address space for each helper process.
    pub address_space_bytes_per_process: u64,
    /// Maximum CPU seconds for each helper process.
    pub cpu_seconds_per_process: u64,
    /// Maximum processes under the execution identity.
    pub processes_per_execution_uid: u64,
    /// Maximum open files for each helper process.
    pub open_files_per_process: u64,
    /// Maximum bytes for each regular file.
    pub file_bytes_per_regular_file: u64,
    /// Core files are always disabled.
    pub core_bytes: u64,
}

/// Versioned authoritative acquisition testimony persisted on `watcher_runs`.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunResourceOutcomeV1 {
    /// Closed resource-outcome schema identity.
    pub schema: RunResourceOutcomeSchema,
    /// Monotonic elapsed duration.
    pub duration_ms: u64,
    /// Helper exit code when one was obtained.
    pub exit_code: Option<i32>,
    /// Exact enforced resource ceilings.
    pub hard_limits: RunHardLimits,
    /// Number of retained standard-output bytes.
    pub stdout_bytes_retained: usize,
    /// Number of retained standard-error bytes.
    pub stderr_bytes_retained: usize,
    /// Exact retained standard error encoded losslessly as lowercase hex.
    pub stderr_hex: String,
    /// Exact typed acquisition outcome, including timeout phase and details.
    pub outcome: AcquisitionOutcome,
}

/// Closed schema identity for governed detector evaluation results.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum EvaluationResultSchema {
    /// First evaluation carrier using canonical governed refusals.
    #[serde(rename = "nq.evaluation_result.v1")]
    V1,
}

/// Canonical compiled profile identity governing a detector evaluation.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationProfileIdentity {
    /// Declared profile key/version.
    pub profile: nq_profiles::ProfileKey,
    /// Canonical descriptor identity.
    pub profile_digest: nq_profiles::ProfileDigest,
    /// Composite descriptor/protocol/evaluator semantic identity.
    pub profile_semantic_id: ProfileSemanticId,
}

/// Exact engine-owned binding under which one detector evaluation ran.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationContextV1 {
    /// Responsible watcher instance.
    pub instance_id: String,
    /// Bound subject identity.
    pub subject: String,
    /// Exact profile-owned scope.
    pub scope: ScopeConfig,
    /// Exact profile-owned vantage.
    pub vantage: VantageConfig,
}

/// Closed schema identity for the complete canonical evaluation envelope.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum EvaluationEnvelopeSchema {
    /// First lossless envelope around the governed v1 detector payload.
    #[serde(rename = "nq.evaluation_envelope.v2")]
    V2,
}

/// Exact compiled detector identity used by one evaluation.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationDetectorIdentity {
    /// Stable detector name.
    pub id: String,
    /// Compiled detector version.
    pub version: String,
    /// Digest of the exact compiled descriptor.
    pub digest: String,
}

/// Instance-qualified durable watermark captured for one evaluation.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationWatermarkV2 {
    /// Instance whose admitted history was evaluated.
    pub instance_id: String,
    /// Highest admitted report sequence visible to the evaluation.
    pub max_report_sequence: u64,
    /// Exact receipt time of that report, absent only for an empty watermark.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watermark_received_at: Option<DateTime<Utc>>,
}

/// Complete canonical evaluation carrier. SQL and finding columns are strict
/// projections of this object; they are never independent sources of meaning.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationEnvelopeV2 {
    /// Closed envelope schema.
    pub schema: EvaluationEnvelopeSchema,
    /// Stable evaluation identity.
    pub evaluation_id: String,
    /// Admitted collection run that triggered this evaluation, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_run_id: Option<String>,
    /// Exact watcher binding evaluated.
    pub context: EvaluationContextV1,
    /// Exact compiled detector evaluated.
    pub detector: EvaluationDetectorIdentity,
    /// Running evaluator artifact identity.
    pub evaluator_artifact_digest: Sha256Digest,
    /// Exact compiled profile identity.
    pub profile: EvaluationProfileIdentity,
    /// Evaluation start time.
    pub started_at: DateTime<Utc>,
    /// Evaluation completion time.
    pub evaluated_at: DateTime<Utc>,
    /// Instance-qualified evidence watermark.
    pub watermark: EvaluationWatermarkV2,
    /// Governed detector-owned result payload.
    pub result: EvaluationResultV1,
}

impl EvaluationEnvelopeV2 {
    fn validate(&self) -> Result<(), EngineError> {
        if self.evaluation_id.is_empty()
            || self.detector.id.is_empty()
            || self.detector.version.is_empty()
            || Sha256Digest::parse(self.detector.digest.clone()).is_err()
            || self.context.instance_id.is_empty()
            || self.context.subject.is_empty()
            || self.profile != self.result.profile
            || self.watermark.instance_id != self.context.instance_id
            || self.result.watermark.0 != self.watermark.max_report_sequence
            || self.started_at > self.evaluated_at
            || self.result.condition.is_empty()
            || (self.result.state == DetectorState::CannotEvaluate) != self.result.refusal.is_some()
        {
            return Err(EngineError::Invariant(
                "evaluation envelope has inconsistent identity, context, time, watermark, profile, or refusal cardinality".into(),
            ));
        }
        if let Some(refusal) = &self.result.refusal {
            refusal.validate()?;
            let GovernedRefusalOrigin::Profile(profile) = &refusal.origin else {
                return Err(EngineError::Invariant(
                    "detector evaluation refusal must be profile-origin".into(),
                ));
            };
            if profile.refusal.instance_id != self.context.instance_id
                || profile.refusal.profile != self.profile.profile
                || profile.profile_semantic_id != self.profile.profile_semantic_id
            {
                return Err(EngineError::Invariant(
                    "evaluation refusal disagrees with envelope context or profile".into(),
                ));
            }
            if profile.refusal.boundary != nq_profiles::RefusalBoundary::Detector
                || profile.refusal.code != nq_profiles::ProfileRefusalCode::CannotEvaluate
                || profile.refusal.message != self.result.summary
                || !self.result.evidence.is_empty()
            {
                return Err(EngineError::Invariant(
                    "cannot_evaluate refusal disagrees with the exact detector producer invariant"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// Exact detector result persisted without flattening a profile refusal.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResultV1 {
    /// Closed result schema.
    pub schema: EvaluationResultSchema,
    /// Exact compiled profile identity under which evaluation occurred.
    pub profile: EvaluationProfileIdentity,
    /// Exact detector state.
    pub state: DetectorState,
    /// Detector-owned condition identity.
    pub condition: String,
    /// Bounded detector summary.
    pub summary: String,
    /// Exact admitted evidence references.
    pub evidence: Vec<nq_profiles::DetectorEvidence>,
    /// Material evaluation limitations.
    pub limitations: Vec<String>,
    /// Canonical governed refusal required for `CannotEvaluate`.
    pub refusal: Option<GovernedRefusal>,
    /// Exact database watermark used by the detector.
    pub watermark: EvidenceWatermark,
}

/// Whether a later independent acquisition can be classified as retryable
/// without guessing from an operator-facing message.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    /// A later independent attempt may succeed.
    Retriable,
    /// Repeating the same admitted request cannot repair this failure.
    NonRetriable,
    /// The source outcome does not prove either classification.
    Unspecified,
}

/// Stable coarse classification retained alongside the exact acquisition
/// outcome. The exact outcome remains authoritative; this value is an index,
/// not a substitute for dependent fields such as timeout phase.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionFailureClass {
    /// The helper process could not be created.
    SpawnFailed,
    /// The canonical request could not be written to the helper.
    RequestWriteFailed,
    /// A one-shot or phase-specific exchange deadline expired.
    Timeout,
    /// Standard output exceeded the admitted byte limit.
    OutputTooLarge,
    /// Standard error exceeded the admitted byte limit.
    StderrTooLarge,
    /// The helper returned no response bytes.
    Eof,
    /// Returned bytes violated the one-frame transport contract.
    MalformedFraming,
    /// Returned bytes were not valid JSON for protocol processing.
    MalformedJson,
    /// A one-shot helper exited unsuccessfully.
    ExitNonzero,
    /// A persistent helper exited before completing the exchange.
    HelperExited,
    /// The persistent transport disconnected before a complete response.
    Disconnect,
    /// The supervised persistent carrier could not become ready.
    CarrierStartupFailed,
    /// No persistent helper connection existed for the exchange.
    NotRunning,
    /// Another process I/O or wait operation failed.
    IoFailed,
}

/// Lossless acquisition failure: a stable class and retry disposition paired
/// with the complete source outcome.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionFailure {
    /// Stable coarse index for querying the failure family.
    pub class: AcquisitionFailureClass,
    /// Retry classification proved by the originating boundary.
    pub retry: RetryDisposition,
    /// Complete authoritative acquisition outcome, including dependent fields.
    pub outcome: AcquisitionOutcome,
}

/// Acquisition refusal linked to retained raw custody. The responsible
/// instance is explicit because an acquisition outcome itself has no identity.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionRefusal {
    /// Watcher instance responsible for the retained raw submission.
    pub responsible_instance_id: String,
    /// Exact acquisition failure that justified rejection.
    pub failure: AcquisitionFailure,
}

impl AcquisitionFailure {
    /// Convert one non-response acquisition outcome exactly once at the engine
    /// boundary. `Response` is not a failure and therefore has no carrier.
    #[must_use]
    pub fn from_outcome(outcome: AcquisitionOutcome) -> Option<Self> {
        let (class, retry) = match &outcome {
            AcquisitionOutcome::Response => return None,
            AcquisitionOutcome::SpawnFailed { .. } => (
                AcquisitionFailureClass::SpawnFailed,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::RequestWriteFailed { .. } => (
                AcquisitionFailureClass::RequestWriteFailed,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::Timeout | AcquisitionOutcome::ExchangeTimeout { .. } => (
                AcquisitionFailureClass::Timeout,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::OutputTooLarge => (
                AcquisitionFailureClass::OutputTooLarge,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::StderrTooLarge => (
                AcquisitionFailureClass::StderrTooLarge,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::Eof => {
                (AcquisitionFailureClass::Eof, RetryDisposition::Unspecified)
            }
            AcquisitionOutcome::MalformedFraming { .. } => (
                AcquisitionFailureClass::MalformedFraming,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::MalformedJson { .. } => (
                AcquisitionFailureClass::MalformedJson,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::ExitNonzero { .. } => (
                AcquisitionFailureClass::ExitNonzero,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::HelperExited { .. } => (
                AcquisitionFailureClass::HelperExited,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::Disconnect { .. } => (
                AcquisitionFailureClass::Disconnect,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::CarrierStartupFailed { .. } => (
                AcquisitionFailureClass::CarrierStartupFailed,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::NotRunning => (
                AcquisitionFailureClass::NotRunning,
                RetryDisposition::Unspecified,
            ),
            AcquisitionOutcome::IoFailed { .. } => (
                AcquisitionFailureClass::IoFailed,
                RetryDisposition::Unspecified,
            ),
        };
        Some(Self {
            class,
            retry,
            outcome,
        })
    }

    /// Verify that query projections agree with the authoritative outcome.
    ///
    /// # Errors
    ///
    /// Returns when a persisted or transported class/retry projection was
    /// substituted for the values proved by the exact acquisition outcome.
    pub fn validate(&self) -> Result<(), EngineError> {
        let expected = Self::from_outcome(self.outcome.clone()).ok_or_else(|| {
            EngineError::Invariant("response cannot be represented as acquisition failure".into())
        })?;
        if self.class != expected.class || self.retry != expected.retry {
            return Err(EngineError::Invariant(
                "acquisition failure projections disagree with its exact outcome".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Display for AcquisitionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(encoded) => formatter.write_str(&encoded),
            Err(_) => formatter.write_str("acquisition failure could not be rendered"),
        }
    }
}

/// Exact admission boundary that refused a collection before helper launch.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRefusalBoundary {
    /// Lookup or verification of the active admission binding.
    ActiveBinding,
    /// Verification of the executable or runtime identity.
    ExecutionIdentity,
    /// Admission-time conformance execution or comparison.
    Conformance,
    /// Durable store access or invariant enforcement.
    Storage,
    /// Per-instance lock acquisition or coordination.
    Coordination,
    /// Compiled profile resolution or validation.
    Profile,
    /// Helper protocol identity, framing, or validation.
    Protocol,
    /// Canonical serialization of governed material.
    Serialization,
    /// Filesystem materialization of an admitted binding.
    Materialization,
    /// An internal invariant not attributable to another boundary.
    Internal,
}

/// Stable admission refusal code. Dependent information remains in the typed
/// details value and is never reconstructed from this projection.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRefusalCode {
    /// No active binding exists for the watcher instance.
    MissingActiveBinding,
    /// The helper executable identity could not be verified.
    BinaryIdentityInvalid,
    /// Config bytes no longer match the active admission.
    ConfigDrift,
    /// Compiled profile identity no longer matches the admission.
    ProfileDrift,
    /// Helper protocol identity no longer matches the admission.
    ProtocolDrift,
    /// The durable or materialized binding could not be decoded.
    MalformedBinding,
    /// Admission conformance did not pass.
    ConformanceFailed,
    /// Reopened conformance evidence differs from the active admission.
    ConformanceDrift,
    /// A store operation failed.
    StoreFailure,
    /// Per-instance coordination failed.
    CoordinationFailure,
    /// The configured profile is not compiled into this product.
    UnknownProfile,
    /// A protocol identity token was invalid.
    InvalidIdentityToken,
    /// Protocol processing failed outside a retained collection run.
    ProtocolFailure,
    /// Profile processing failed outside a retained collection run.
    ProfileFailure,
    /// Canonical serialization failed.
    CanonicalizationFailure,
    /// An admission filesystem object could not be materialized.
    MaterializationFailure,
    /// A required engine invariant did not hold.
    InvariantViolation,
    /// A typed refusal or acquisition failure propagated from an earlier boundary.
    UpstreamRefusal,
}

/// Structured dependent admission-refusal payload.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdmissionRefusalDetails {
    /// The refusal code is complete without dependent details.
    None,
    /// Executable identity verification failed.
    BinaryIdentity {
        /// Exact identity-verifier reason.
        message: String,
    },
    /// Configuration no longer matches an active binding.
    ConfigDrift {
        /// Instance identity recorded by the binding verifier.
        observed_instance_id: String,
    },
    /// Profile identity no longer matches an active binding.
    ProfileDrift {
        /// Instance identity recorded by the binding verifier.
        observed_instance_id: String,
        /// Exact profile mismatch proved by verification.
        message: String,
    },
    /// Protocol identity no longer matches an active binding.
    ProtocolDrift {
        /// Instance identity recorded by the binding verifier.
        observed_instance_id: String,
    },
    /// An active binding could not be decoded or satisfy its invariants.
    MalformedBinding {
        /// Instance identity decoded before the malformed field, or `unknown`.
        observed_instance_id: String,
        /// Exact malformed-binding reason.
        message: String,
    },
    /// Admission conformance did not pass.
    ConformanceFailed {
        /// Exact conformance failure.
        message: String,
    },
    /// Reopened conformance evidence differs from the active admission.
    ConformanceDrift {
        /// Instance identity recorded by the conformance verifier.
        observed_instance_id: String,
        /// Exact conformance mismatch.
        message: String,
    },
    /// Durable store access or verification failed.
    Storage {
        /// Exact store diagnostic.
        message: String,
    },
    /// Per-instance coordination failed.
    Coordination {
        /// Exact coordination diagnostic.
        message: String,
    },
    /// Identity of a configured profile that could not be resolved.
    ProfileIdentity {
        /// Stable profile identifier.
        id: String,
        /// Exact profile version.
        version: u32,
    },
    /// A protocol identity token was invalid.
    IdentityToken {
        /// Exact token diagnostic.
        message: String,
    },
    /// Protocol processing failed outside retained run custody.
    Protocol {
        /// Exact protocol diagnostic.
        message: String,
    },
    /// Profile processing failed outside retained run custody.
    ProfileProcessing {
        /// Exact profile diagnostic.
        message: String,
    },
    /// Canonical serialization failed.
    Canonicalization {
        /// Exact canonicalization diagnostic.
        message: String,
    },
    /// An admission filesystem object could not be materialized.
    Materialization {
        /// Exact path when the source error retained one.
        path: Option<String>,
        /// Exact filesystem diagnostic.
        message: String,
    },
    /// An internal engine invariant failed.
    Invariant {
        /// Exact invariant diagnostic.
        message: String,
    },
    /// An upstream governed refusal preserved without projection.
    Governed {
        /// Complete canonical refusal.
        refusal: Box<GovernedRefusal>,
    },
    /// An upstream acquisition failure preserved without projection.
    Acquisition {
        /// Complete acquisition failure.
        failure: AcquisitionFailure,
    },
}

/// Canonical refusal produced before a run exists.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRefusal {
    /// Watcher instance whose admission was refused.
    pub responsible_instance_id: String,
    /// Exact boundary that refused admission.
    pub boundary: AdmissionRefusalBoundary,
    /// Stable refusal classification.
    pub code: AdmissionRefusalCode,
    /// Dependent typed facts required to interpret the code.
    pub details: AdmissionRefusalDetails,
}

impl AdmissionRefusal {
    /// Validate the refusal's dependent payload and responsible instance.
    ///
    /// # Errors
    ///
    /// Returns when the code selects the wrong detail variant, a nested typed
    /// refusal is invalid, or its responsible instance differs from this
    /// admission refusal.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.responsible_instance_id.is_empty() {
            return Err(EngineError::Invariant(
                "admission refusal responsible instance cannot be empty".into(),
            ));
        }
        let valid = match (&self.boundary, &self.code, &self.details) {
            (
                AdmissionRefusalBoundary::ActiveBinding,
                AdmissionRefusalCode::MissingActiveBinding,
                AdmissionRefusalDetails::None,
            ) => true,
            (
                AdmissionRefusalBoundary::ExecutionIdentity,
                AdmissionRefusalCode::BinaryIdentityInvalid,
                AdmissionRefusalDetails::BinaryIdentity { message },
            )
            | (
                AdmissionRefusalBoundary::Conformance,
                AdmissionRefusalCode::ConformanceFailed,
                AdmissionRefusalDetails::ConformanceFailed { message },
            )
            | (
                AdmissionRefusalBoundary::Storage,
                AdmissionRefusalCode::StoreFailure,
                AdmissionRefusalDetails::Storage { message },
            )
            | (
                AdmissionRefusalBoundary::Coordination,
                AdmissionRefusalCode::CoordinationFailure,
                AdmissionRefusalDetails::Coordination { message },
            )
            | (
                AdmissionRefusalBoundary::Protocol,
                AdmissionRefusalCode::InvalidIdentityToken,
                AdmissionRefusalDetails::IdentityToken { message },
            )
            | (
                AdmissionRefusalBoundary::Protocol,
                AdmissionRefusalCode::ProtocolFailure,
                AdmissionRefusalDetails::Protocol { message },
            )
            | (
                AdmissionRefusalBoundary::Profile,
                AdmissionRefusalCode::ProfileFailure,
                AdmissionRefusalDetails::ProfileProcessing { message },
            )
            | (
                AdmissionRefusalBoundary::Serialization,
                AdmissionRefusalCode::CanonicalizationFailure,
                AdmissionRefusalDetails::Canonicalization { message },
            )
            | (
                AdmissionRefusalBoundary::Materialization,
                AdmissionRefusalCode::MaterializationFailure,
                AdmissionRefusalDetails::Materialization { message, .. },
            )
            | (
                AdmissionRefusalBoundary::Internal,
                AdmissionRefusalCode::InvariantViolation,
                AdmissionRefusalDetails::Invariant { message },
            ) => !message.is_empty(),
            (
                AdmissionRefusalBoundary::ActiveBinding,
                AdmissionRefusalCode::ConfigDrift,
                AdmissionRefusalDetails::ConfigDrift {
                    observed_instance_id,
                },
            )
            | (
                AdmissionRefusalBoundary::ActiveBinding,
                AdmissionRefusalCode::ProtocolDrift,
                AdmissionRefusalDetails::ProtocolDrift {
                    observed_instance_id,
                },
            ) => !observed_instance_id.is_empty(),
            (
                AdmissionRefusalBoundary::ActiveBinding,
                AdmissionRefusalCode::ProfileDrift,
                AdmissionRefusalDetails::ProfileDrift {
                    observed_instance_id,
                    message,
                },
            )
            | (
                AdmissionRefusalBoundary::ActiveBinding,
                AdmissionRefusalCode::MalformedBinding,
                AdmissionRefusalDetails::MalformedBinding {
                    observed_instance_id,
                    message,
                },
            )
            | (
                AdmissionRefusalBoundary::Conformance,
                AdmissionRefusalCode::ConformanceDrift,
                AdmissionRefusalDetails::ConformanceDrift {
                    observed_instance_id,
                    message,
                },
            ) => !observed_instance_id.is_empty() && !message.is_empty(),
            (
                AdmissionRefusalBoundary::Profile,
                AdmissionRefusalCode::UnknownProfile,
                AdmissionRefusalDetails::ProfileIdentity { id, .. },
            ) => !id.is_empty(),
            (
                _,
                AdmissionRefusalCode::UpstreamRefusal,
                AdmissionRefusalDetails::Governed { refusal },
            ) => {
                refusal.validate()?;
                if refusal.responsible_instance_id() != self.responsible_instance_id {
                    return Err(EngineError::Invariant(
                        "nested governed refusal lost its admission instance association".into(),
                    ));
                }
                true
            }
            (
                _,
                AdmissionRefusalCode::UpstreamRefusal,
                AdmissionRefusalDetails::Acquisition { failure },
            ) => {
                failure.validate()?;
                true
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(EngineError::Invariant(
                "admission refusal code disagrees with its typed details".into(),
            ))
        }
    }
}

/// Typed classification of a response that could not be decoded and validated
/// as the exact helper protocol response.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonErrorCategory {
    /// An underlying reader or writer failed.
    Io,
    /// JSON syntax was malformed.
    Syntax,
    /// Valid JSON could not be mapped to the required data type.
    Data,
    /// Input ended before a complete JSON value was available.
    Eof,
}

/// Structured JSON parser/serializer error facts. The diagnostic is dependent
/// context; category and location remain independently typed.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredJsonError {
    /// Stable serde JSON error category.
    pub category: JsonErrorCategory,
    /// One-based source line, or zero when unavailable.
    pub line: usize,
    /// One-based source column, or zero when unavailable.
    pub column: usize,
    /// Exact parser diagnostic retained as dependent context.
    pub diagnostic: String,
}

/// Structured canonicalization failure mirror.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolCanonicalizationFailure {
    /// Serialization into canonical JSON failed.
    Serialization {
        /// Structured serializer failure.
        error: StructuredJsonError,
    },
    /// An integer could not be represented exactly in canonical JSON.
    UnsafeInteger {
        /// Exact decimal integer value that was rejected.
        value: String,
    },
}

/// Exhaustive owned mirror of `nq_protocol::ValidationError` suitable for
/// versioned persistence and reopening.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolValidationFailure {
    /// A protocol document declared the wrong schema identity.
    InvalidSchema {
        /// Kind of document being validated.
        document: String,
        /// Required schema identity.
        expected: String,
        /// Schema identity actually supplied.
        actual: String,
    },
    /// The helper used an incompatible protocol version.
    InvalidProtocolVersion {
        /// Required protocol version.
        expected: String,
        /// Protocol version actually supplied.
        actual: String,
    },
    /// A named protocol field failed a semantic predicate.
    InvalidField {
        /// Stable field path.
        field: String,
        /// Exact validation reason.
        reason: String,
    },
    /// A bounded collection exceeded its admitted cardinality.
    BoundExceeded {
        /// Stable field path for the bounded collection.
        field: String,
        /// Maximum admitted cardinality.
        limit: usize,
        /// Cardinality actually supplied.
        actual: usize,
    },
    /// A field that must be unique contained a duplicate value.
    Duplicate {
        /// Stable field path.
        field: String,
        /// Exact duplicated value.
        value: String,
    },
    /// A response did not echo a request-bound field exactly.
    EchoMismatch {
        /// Stable field path that disagreed.
        field: String,
    },
    /// A helper claimed a capability outside its grant.
    CapabilityEscape {
        /// Exact escaped capability.
        capability: nq_protocol::Capability,
    },
    /// Canonicalization of a named field failed during validation.
    Canonicalization {
        /// Stable field path.
        field: String,
        /// Exact canonicalization failure.
        source: ProtocolCanonicalizationFailure,
    },
}

/// Typed classification of a response that could not be decoded and validated
/// as the exact helper protocol response.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolRejectionFailure {
    /// The response frame exceeded the admitted byte bound.
    FrameTooLarge {
        /// Maximum admitted frame size in bytes.
        limit: usize,
        /// Actual frame size in bytes.
        actual: usize,
    },
    /// The response did not contain exactly one LF-terminated frame.
    InvalidFraming,
    /// The framed response was not valid JSON of the required shape.
    InvalidJson {
        /// Structured parser failure.
        error: StructuredJsonError,
    },
    /// The decoded protocol response failed semantic validation.
    Validation {
        /// Exact validation failure.
        error: ProtocolValidationFailure,
    },
    /// Canonical response verification failed.
    Canonicalization {
        /// Exact canonicalization failure.
        error: ProtocolCanonicalizationFailure,
    },
}

/// Canonical protocol-plane rejection created from one exact parse failure.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRejectionBoundary {
    /// Parsing and validation of helper response bytes.
    Response,
}

/// Closed protocol-rejection vocabulary.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRejectionCode {
    /// The response could not satisfy the helper response contract.
    InvalidResponse,
}

/// Canonical protocol-plane rejection created from one exact parse failure.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRejection {
    /// Watcher instance responsible for the rejected response.
    pub responsible_instance_id: String,
    /// Exact protocol boundary that rejected the bytes.
    pub boundary: ProtocolRejectionBoundary,
    /// Stable coarse rejection classification.
    pub code: ProtocolRejectionCode,
    /// Complete typed dependent failure.
    pub failure: ProtocolRejectionFailure,
}

/// A compiled-profile refusal bound to the exact semantic implementation that
/// produced it. Profile key/version identifies the declared namespace; this
/// identity additionally binds descriptor, protocol semantics, and evaluator
/// source closure.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProfileRefusal {
    /// Exact semantic identity of the compiled profile implementation.
    pub profile_semantic_id: ProfileSemanticId,
    /// Complete typed refusal returned by that compiled profile boundary.
    #[serde(with = "strict_profile_refusal")]
    pub refusal: nq_profiles::ProfileRefusal,
}

/// Exact refusal origin. Helper and profile variants embed their authoritative
/// source objects rather than copying selected display fields.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GovernedRefusalOrigin {
    /// Acquisition failed after raw bytes requiring custody were retained.
    Acquisition(AcquisitionRefusal),
    /// Helper response bytes failed protocol parsing or validation.
    Protocol(ProtocolRejection),
    /// The helper returned an explicit protocol refusal.
    Helper(nq_protocol::Refusal),
    /// The compiled profile rejected an otherwise valid report.
    Profile(GovernedProfileRefusal),
}

mod strict_profile_refusal {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize)]
    struct StrictProfileRefusalRef<'a> {
        instance_id: &'a str,
        profile: &'a nq_profiles::ProfileKey,
        boundary: nq_profiles::RefusalBoundary,
        code: nq_profiles::ProfileRefusalCode,
        message: &'a str,
        details: &'a BTreeMap<String, String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictProfileRefusal {
        instance_id: String,
        profile: nq_profiles::ProfileKey,
        boundary: nq_profiles::RefusalBoundary,
        code: nq_profiles::ProfileRefusalCode,
        message: String,
        details: BTreeMap<String, String>,
    }

    pub(super) fn serialize<S>(
        refusal: &nq_profiles::ProfileRefusal,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        StrictProfileRefusalRef {
            instance_id: &refusal.instance_id,
            profile: &refusal.profile,
            boundary: refusal.boundary,
            code: refusal.code,
            message: &refusal.message,
            details: &refusal.details,
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<nq_profiles::ProfileRefusal, D::Error>
    where
        D: Deserializer<'de>,
    {
        let refusal = StrictProfileRefusal::deserialize(deserializer)?;
        Ok(nq_profiles::ProfileRefusal {
            instance_id: refusal.instance_id,
            profile: refusal.profile,
            boundary: refusal.boundary,
            code: refusal.code,
            message: refusal.message,
            details: refusal.details,
        })
    }
}

/// Stable, explicitly versioned refusal carrier reused by persistence, dry
/// watcher errors, collection results, status, API, CLI, and historical reopen.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRefusal {
    /// Closed refusal-carrier schema identity.
    pub schema: GovernedRefusalSchema,
    /// Stable NQ-owned refusal identity used for durable linkage.
    pub refusal_id: String,
    /// Complete authoritative refusal from its originating boundary.
    pub origin: GovernedRefusalOrigin,
}

impl GovernedRefusal {
    /// Wrap a retained acquisition refusal in the canonical carrier.
    #[must_use]
    pub fn acquisition(refusal_id: String, refusal: AcquisitionRefusal) -> Self {
        Self {
            schema: GovernedRefusalSchema::V1,
            refusal_id,
            origin: GovernedRefusalOrigin::Acquisition(refusal),
        }
    }

    /// Wrap a protocol response rejection in the canonical carrier.
    #[must_use]
    pub fn protocol(refusal_id: String, refusal: ProtocolRejection) -> Self {
        Self {
            schema: GovernedRefusalSchema::V1,
            refusal_id,
            origin: GovernedRefusalOrigin::Protocol(refusal),
        }
    }

    /// Wrap an explicit helper refusal in the canonical carrier.
    #[must_use]
    pub fn helper(refusal_id: String, refusal: nq_protocol::Refusal) -> Self {
        Self {
            schema: GovernedRefusalSchema::V1,
            refusal_id,
            origin: GovernedRefusalOrigin::Helper(refusal),
        }
    }

    /// Wrap a compiled-profile refusal in the canonical carrier.
    #[must_use]
    pub fn profile(
        refusal_id: String,
        profile_semantic_id: ProfileSemanticId,
        refusal: nq_profiles::ProfileRefusal,
    ) -> Self {
        Self {
            schema: GovernedRefusalSchema::V1,
            refusal_id,
            origin: GovernedRefusalOrigin::Profile(GovernedProfileRefusal {
                profile_semantic_id,
                refusal,
            }),
        }
    }

    /// Return the responsible watcher instance from the authoritative origin.
    #[must_use]
    pub fn responsible_instance_id(&self) -> &str {
        match &self.origin {
            GovernedRefusalOrigin::Acquisition(refusal) => &refusal.responsible_instance_id,
            GovernedRefusalOrigin::Protocol(refusal) => &refusal.responsible_instance_id,
            GovernedRefusalOrigin::Helper(refusal) => refusal.responsible_instance_id.as_str(),
            GovernedRefusalOrigin::Profile(profile) => &profile.refusal.instance_id,
        }
    }

    /// Validate the versioned transport without consulting the current
    /// compiled profile catalog.
    ///
    /// This is the historical reopening boundary. It preserves the exact
    /// typed refusal and its internal dependent-field invariants even after a
    /// profile generation leaves a later binary. It does not establish that
    /// the profile is currently compiled or admissible for new work.
    ///
    /// # Errors
    ///
    /// Returns when a refusal lacks a stable identity, an acquisition carrier
    /// is internally inconsistent, or a typed origin is structurally invalid.
    pub fn validate_transport(&self) -> Result<(), EngineError> {
        if self.refusal_id.is_empty() {
            return Err(EngineError::Invariant(
                "governed refusal identity cannot be empty".into(),
            ));
        }
        if self.responsible_instance_id().is_empty() {
            return Err(EngineError::Invariant(
                "governed refusal responsible instance cannot be empty".into(),
            ));
        }
        match &self.origin {
            GovernedRefusalOrigin::Acquisition(refusal) => refusal.failure.validate()?,
            GovernedRefusalOrigin::Protocol(refusal) => {
                if refusal.responsible_instance_id.is_empty() {
                    return Err(EngineError::Invariant(
                        "protocol refusal responsible instance cannot be empty".into(),
                    ));
                }
            }
            GovernedRefusalOrigin::Helper(refusal) => {
                let expected = match refusal.code {
                    nq_protocol::RefusalCode::UnsupportedProtocol => {
                        nq_protocol::RefusalBoundary::Protocol
                    }
                    nq_protocol::RefusalCode::UnknownProfile
                    | nq_protocol::RefusalCode::ProfileDigestMismatch => {
                        nq_protocol::RefusalBoundary::Profile
                    }
                    nq_protocol::RefusalCode::UnsupportedScope => {
                        nq_protocol::RefusalBoundary::Scope
                    }
                    nq_protocol::RefusalCode::UnsupportedVantage => {
                        nq_protocol::RefusalBoundary::Vantage
                    }
                    nq_protocol::RefusalCode::CapabilityDenied => {
                        nq_protocol::RefusalBoundary::Capability
                    }
                    nq_protocol::RefusalCode::DeadlineExpired => {
                        nq_protocol::RefusalBoundary::Deadline
                    }
                    nq_protocol::RefusalCode::BoundsUnsupported
                    | nq_protocol::RefusalCode::ResourceExhausted => {
                        nq_protocol::RefusalBoundary::Resource
                    }
                    nq_protocol::RefusalCode::CheckpointInvalid => {
                        nq_protocol::RefusalBoundary::Checkpoint
                    }
                    nq_protocol::RefusalCode::CollectionFailed => {
                        nq_protocol::RefusalBoundary::Collection
                    }
                    nq_protocol::RefusalCode::InternalError => {
                        nq_protocol::RefusalBoundary::Internal
                    }
                };
                if refusal.boundary != expected || refusal.message.is_empty() {
                    return Err(EngineError::Invariant(
                        "helper refusal code, boundary, or message is invalid".into(),
                    ));
                }
            }
            GovernedRefusalOrigin::Profile(profile) => {
                let refusal = &profile.refusal;
                if refusal.profile.id.is_empty() || refusal.message.is_empty() {
                    return Err(EngineError::Invariant(
                        "profile refusal identity or message is empty".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate stable identity and origin-specific dependent invariants for
    /// current live use.
    ///
    /// # Errors
    ///
    /// Returns when a refusal lacks a stable identity or an acquisition-origin
    /// refusal contains projections that disagree with its exact outcome.
    pub fn validate(&self) -> Result<(), EngineError> {
        self.validate_transport()?;
        if let GovernedRefusalOrigin::Profile(profile) = &self.origin {
            let refusal = &profile.refusal;
            let compiled = nq_profiles::resolve_profile_key(&refusal.profile).ok_or_else(|| {
                EngineError::Invariant(format!(
                    "profile refusal names uncompiled profile {}/{}",
                    refusal.profile.id, refusal.profile.version
                ))
            })?;
            let expected = profile_semantic_id(compiled.descriptor())
                .map_err(|error| EngineError::Canonical(error.to_string()))?;
            if profile.profile_semantic_id != expected {
                return Err(EngineError::Invariant(format!(
                    "profile refusal semantic identity disagrees with compiled profile {}/{}",
                    refusal.profile.id, refusal.profile.version
                )));
            }
        }
        Ok(())
    }
}

impl fmt::Display for GovernedRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(encoded) => formatter.write_str(&encoded),
            Err(_) => formatter.write_str("governed refusal could not be rendered"),
        }
    }
}

/// Typed result inside the versioned collection envelope.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum CollectionResult {
    /// A report passed acquisition, protocol, and profile admission.
    Admitted {
        /// Stable NQ-owned admitted-report identity.
        report_id: String,
        /// Exact profile-validated report status.
        report_status: String,
        /// Canonical semantic digest of the admitted report.
        semantic_digest: String,
        /// Exact ordered detector evaluations committed from the report.
        evaluations: Vec<EvaluationEnvelopeV2>,
    },
    /// The active admission could not bind a run; no helper was launched.
    AdmissionRefused {
        /// Complete typed admission refusal.
        refusal: AdmissionRefusal,
    },
    /// The exact process/carrier acquisition failure.
    AcquisitionFailed {
        /// Complete typed acquisition failure.
        failure: AcquisitionFailure,
    },
    /// Protocol, helper, or profile refusal retained as rejected custody.
    Rejected {
        /// Stable linked governed refusal.
        refusal: GovernedRefusal,
    },
}

/// Persisted canonical result of one explicitly requested bounded collection.
/// Common association fields occur once and every dependent result remains in
/// its authoritative typed object.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionOutcome {
    /// Closed collection-carrier schema identity.
    pub schema: CollectionOutcomeSchema,
    /// Exact watcher instance associated with the result.
    pub instance_id: String,
    /// Stable run identity, absent only when admission prevented a run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Complete typed result payload.
    pub result: CollectionResult,
}

impl CollectionOutcome {
    /// Construct an admitted collection result with its durable identities.
    #[must_use]
    pub fn admitted(
        instance_id: String,
        run_id: String,
        report_id: String,
        report_status: String,
        semantic_digest: String,
        evaluations: Vec<EvaluationEnvelopeV2>,
    ) -> Self {
        Self {
            schema: CollectionOutcomeSchema::V2,
            instance_id,
            run_id: Some(run_id),
            result: CollectionResult::Admitted {
                report_id,
                report_status,
                semantic_digest,
                evaluations,
            },
        }
    }

    /// Construct an admission refusal for an attempt that created no run.
    #[must_use]
    pub fn admission_refused(instance_id: String, refusal: AdmissionRefusal) -> Self {
        Self {
            schema: CollectionOutcomeSchema::V1,
            instance_id,
            run_id: None,
            result: CollectionResult::AdmissionRefused { refusal },
        }
    }

    /// Construct a failure only from a non-response acquisition outcome.
    ///
    /// # Errors
    ///
    /// Returns an invariant error when passed the successful `Response`
    /// outcome, which cannot justify an acquisition failure.
    pub fn acquisition_failed(
        instance_id: String,
        run_id: String,
        outcome: AcquisitionOutcome,
    ) -> Result<Self, EngineError> {
        let failure = AcquisitionFailure::from_outcome(outcome).ok_or_else(|| {
            EngineError::Invariant("response cannot be represented as acquisition failure".into())
        })?;
        Ok(Self {
            schema: CollectionOutcomeSchema::V1,
            instance_id,
            run_id: Some(run_id),
            result: CollectionResult::AcquisitionFailed { failure },
        })
    }

    /// Construct a rejected result linked to its stable governed refusal.
    #[must_use]
    pub fn rejected(instance_id: String, run_id: String, refusal: GovernedRefusal) -> Self {
        Self {
            schema: CollectionOutcomeSchema::V1,
            instance_id,
            run_id: Some(run_id),
            result: CollectionResult::Rejected { refusal },
        }
    }

    /// Exact responsible instance.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Whether this one-shot invocation produced an admitted complete or
    /// partial report.
    ///
    /// A valid `failed` report remains durable provider testimony, but does not
    /// satisfy the bounded request. This predicate has no cadence, retry,
    /// freshness, or posture meaning.
    #[must_use]
    pub fn has_admitted_usable_report(&self) -> bool {
        matches!(
            &self.result,
            CollectionResult::Admitted { report_status, .. } if report_status != "failed"
        )
    }

    /// Validate cross-field associations after deserializing persisted bytes.
    ///
    /// # Errors
    ///
    /// Returns an invariant error if run presence, instance association, or
    /// source outcome contradicts the typed result variant.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.instance_id.is_empty() {
            return Err(EngineError::Invariant(
                "collection result instance identity cannot be empty".into(),
            ));
        }
        if self.run_id.as_deref() == Some("") {
            return Err(EngineError::Invariant(
                "collection result run identity cannot be empty".into(),
            ));
        }
        match &self.result {
            CollectionResult::Admitted { .. } | CollectionResult::AcquisitionFailed { .. }
                if self.run_id.is_none() =>
            {
                Err(EngineError::Invariant(
                    "collection result requires a run identity".into(),
                ))
            }
            CollectionResult::AdmissionRefused { refusal } => {
                if self.schema != CollectionOutcomeSchema::V1 || self.run_id.is_some() {
                    return Err(EngineError::Invariant(
                        "admission refusal cannot claim an unstarted run".into(),
                    ));
                }
                refusal.validate()?;
                if refusal.responsible_instance_id != self.instance_id {
                    return Err(EngineError::Invariant(
                        "admission refusal lost its responsible instance".into(),
                    ));
                }
                Ok(())
            }
            CollectionResult::Rejected { refusal } => {
                if self.schema != CollectionOutcomeSchema::V1 || self.run_id.is_none() {
                    return Err(EngineError::Invariant(
                        "rejected collection requires a run identity".into(),
                    ));
                }
                if refusal.responsible_instance_id() != self.instance_id {
                    return Err(EngineError::Invariant(
                        "governed refusal lost its responsible instance".into(),
                    ));
                }
                refusal.validate()?;
                Ok(())
            }
            CollectionResult::AcquisitionFailed { failure } => {
                if self.schema != CollectionOutcomeSchema::V1 {
                    return Err(EngineError::Invariant(
                        "non-admitted collection result requires v1 schema".into(),
                    ));
                }
                failure.validate()
            }
            CollectionResult::Admitted {
                report_id,
                report_status,
                semantic_digest,
                evaluations,
            } => {
                let run_id = self.run_id.as_deref().unwrap_or_default();
                let ordered = evaluations.windows(2).all(|pair| {
                    (
                        &pair[0].detector.id,
                        &pair[0].detector.version,
                        &pair[0].evaluation_id,
                    ) < (
                        &pair[1].detector.id,
                        &pair[1].detector.version,
                        &pair[1].evaluation_id,
                    )
                });
                if self.schema != CollectionOutcomeSchema::V2
                    || report_id.is_empty()
                    || !matches!(report_status.as_str(), "complete" | "partial" | "failed")
                    || Sha256Digest::parse(semantic_digest.clone()).is_err()
                    || evaluations.iter().any(|evaluation| {
                        evaluation.validate().is_err()
                            || evaluation.trigger_run_id.as_deref() != Some(run_id)
                            || evaluation.context.instance_id != self.instance_id
                    })
                    || !ordered
                {
                    return Err(EngineError::Invariant(
                        "admitted result identity, status, digest, schema, or evaluation linkage is invalid".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Decode an exact canonical collection-result document and validate all
/// dependent typed invariants.
///
/// # Errors
///
/// Returns when bytes are not exact canonical JSON, the strict nested schema
/// cannot decode, or any identity, projection, association, or vocabulary
/// invariant fails validation.
pub fn decode_collection_outcome(bytes: &[u8]) -> Result<CollectionOutcome, EngineError> {
    let document = CanonicalDocument::from_canonical_bytes(bytes.to_vec())?;
    let outcome: CollectionOutcome =
        serde_json::from_slice(document.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!("collection result cannot decode: {error}"))
        })?;
    outcome.validate()?;
    if canonical(&outcome)?.as_bytes() != document.as_bytes() {
        return Err(EngineError::Invariant(
            "collection result does not round-trip to exact canonical typed bytes".into(),
        ));
    }
    Ok(outcome)
}

/// Decode the product's one-record NDJSON collection-result carrier.
///
/// Protocol framing is checked first, then the exact body is reopened through
/// the same canonical typed decoder used for persistence and status surfaces.
/// This prevents permissive JSON decoding from accepting duplicate fields or
/// a noncanonical body whose last value merely happens to deserialize.
///
/// # Errors
///
/// Returns when the NDJSON framing, canonical JSON representation, nested
/// schema, or any governed result invariant is invalid.
pub fn decode_collection_outcome_ndjson(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<CollectionOutcome, EngineError> {
    let framed: CollectionOutcome = nq_protocol::decode_ndjson(bytes, max_bytes)
        .map_err(|error| EngineError::Protocol(error.to_string()))?;
    framed.validate()?;
    let body = bytes.strip_suffix(b"\n").ok_or_else(|| {
        EngineError::Protocol("collection result NDJSON frame lacks terminal newline".into())
    })?;
    let exact = decode_collection_outcome(body)?;
    if exact != framed {
        return Err(EngineError::Invariant(
            "framed collection result differs from exact canonical body".into(),
        ));
    }
    Ok(exact)
}

fn decode_governed_refusal(bytes: &[u8], context: &str) -> Result<GovernedRefusal, EngineError> {
    let document = CanonicalDocument::from_canonical_bytes(bytes.to_vec())?;
    let refusal: GovernedRefusal =
        serde_json::from_slice(document.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "{context} cannot decode as governed refusal: {error}"
            ))
        })?;
    refusal.validate()?;
    if canonical(&refusal)?.as_bytes() != document.as_bytes() {
        return Err(EngineError::Invariant(format!(
            "{context} does not round-trip to exact canonical bytes"
        )));
    }
    Ok(refusal)
}

/// End-to-end collection, admission, evaluation, and public read-model engine
/// over one explicitly opened compatible database.
pub struct CollectionEngine {
    config: NqConfig,
    store: Store,
    startup_projection_recovery: Vec<nq_store::GovernedProjectionRecovery>,
    admission: AdmissionManager,
    runner: StdioRunner,
    unix_runners: BTreeMap<String, BoundUnixRunner>,
    /// The running evaluator's trusted identity, resolved once from the platform
    /// provider at open, or a structured reason it could not be established.
    /// Admission and collection fail closed on the error side.
    evaluator_identity: Result<EvaluatorRuntimeIdentity, String>,
}

/// Catalog-resolved production identity surface for one V2 execution.
///
/// This carrier does not establish that the referenced topology is active or
/// authorized. The host-role runtime supplies it only after committing the
/// exact activation snapshot and later records the full
/// `nq.execution_identity_binding.v2` companion.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DiagnosticProductionIdentityV2 {
    /// Enrolled logical NQ node identity.
    node_id: String,
    /// Catalog-resolved subject identity.
    subject_id: String,
    /// Catalog-resolved vantage generation.
    vantage: SemanticIdentityV1,
    /// Exact active static-profile-cohort generation.
    cohort: SemanticIdentityV1,
}

#[derive(Clone)]
struct DiagnosticInvocationContext {
    request_id: Option<DiagnosticRequestId>,
    production: Option<DiagnosticProductionIdentityV2>,
}

#[derive(Debug)]
struct CollectionExecution {
    #[cfg_attr(not(test), allow(dead_code))]
    outcome: CollectionOutcome,
    diagnostic: Option<SupportedDiagnosticExecution>,
    diagnostic_artifact_id: Option<Sha256Digest>,
}

impl CollectionExecution {
    fn without_diagnostic(outcome: CollectionOutcome) -> Self {
        Self {
            outcome,
            diagnostic: None,
            diagnostic_artifact_id: None,
        }
    }
}

type DiagnosticCollectionPath = fn(
    &mut CollectionEngine,
    &WatcherConfig,
    Option<&DiagnosticInvocationContext>,
) -> Result<CollectionExecution, EngineError>;

// Keep the closed diagnostic producer path typechecked as one implementation
// unit while its only product entry remains deliberately withheld. Publishing
// an invocation method before terminal custody exists would strand an already
// claimed launch occurrence; this compile-time reference exposes no callable
// API and performs no work.
const _: DiagnosticCollectionPath = CollectionEngine::collect_internal;

const INITIAL_DIAGNOSTIC_PROFILE_DIGEST: &str =
    "sha256:c8c10fed1cc5598d953b4defbc98e8c106fc59e035c249d43681698a5c7b4ff9";
const INITIAL_DIAGNOSTIC_DETECTOR_ID: &str = "nq.host.load_pressure";
const INITIAL_DIAGNOSTIC_DETECTOR_VERSION: u32 = 1;
const INITIAL_DIAGNOSTIC_DETECTOR_DIGEST: &str =
    "sha256:7de797da3d9d3a6ae8e21e5d77b95095453336cd38f606ffb3eb29ff6a32e2cf";

fn validate_diagnostic_production_identity(
    production: &DiagnosticProductionIdentityV2,
) -> Result<(), EngineError> {
    for (field, value) in [
        ("node_id", production.node_id.as_str()),
        ("subject_id", production.subject_id.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 255
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(EngineError::Invariant(format!(
                "production diagnostic {field} is empty, oversized, or contains whitespace"
            )));
        }
    }
    for (field, identity) in [
        ("vantage", &production.vantage),
        ("cohort", &production.cohort),
    ] {
        if identity.id.is_empty()
            || identity.version.is_empty()
            || identity
                .id
                .bytes()
                .chain(identity.version.bytes())
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(EngineError::Invariant(format!(
                "production diagnostic {field} identity is malformed"
            )));
        }
    }
    Ok(())
}

fn semantic_identity_from_production(identity: &IdentityRef) -> SemanticIdentityV1 {
    SemanticIdentityV1 {
        id: identity.id.as_str().to_owned(),
        version: identity.version.as_str().to_owned(),
        digest: identity.descriptor_digest.clone(),
    }
}

type NativeGovernedPreEffectRefusalCode = GovernedExecutionRefusalCode;

#[allow(dead_code)]
#[derive(Debug)]
struct NativeGovernedPreEffectRefusal {
    code: NativeGovernedPreEffectRefusalCode,
    detail: String,
}

fn native_governed_refusal(
    code: NativeGovernedPreEffectRefusalCode,
    detail: impl Into<String>,
) -> NativeGovernedPreEffectRefusal {
    NativeGovernedPreEffectRefusal {
        code,
        detail: detail.into(),
    }
}

fn native_governed_record<'a>(
    prepared: &'a PreparedGovernedInvocation,
    reference: &RecordRef,
    expected_schema: RuntimeSchema,
) -> Result<&'a ValidatedRuntimeRecord, NativeGovernedPreEffectRefusal> {
    let record = prepared
        .prelaunch_records()
        .get(&reference.record_id)
        .ok_or_else(|| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::PreparedClosureInvalid,
                format!(
                    "prepared invocation is missing {} {}",
                    expected_schema.as_str(),
                    reference.record_id
                ),
            )
        })?;
    if record.schema() != expected_schema || record.exact_reference() != *reference {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::PreparedClosureInvalid,
            format!(
                "prepared invocation substituted exact {} {}",
                expected_schema.as_str(),
                reference.record_id
            ),
        ));
    }
    Ok(record)
}

fn validate_governed_occurrence_window(
    request_clock: &IdentityRef,
    launch_clock: &IdentityRef,
    not_before: DateTime<Utc>,
    request_deadline: DateTime<Utc>,
    launched_at: DateTime<Utc>,
    attempt_deadline: DateTime<Utc>,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    if request_clock != launch_clock
        || request_clock.kind != IdentityKind::Clock
        || not_before > launched_at
        || launched_at >= attempt_deadline
        || attempt_deadline > request_deadline
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::DeadlineExpired,
            "request and launch lack one exact production clock and ordered occurrence window",
        ));
    }
    Ok(())
}

fn validate_native_profile_correspondence(
    production_profile: &IdentityRef,
    provider_admission: &RecordRef,
    active_lock: &AdmissionLock,
    compiled_profile: &'static dyn ProfileModule,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    let compiled = compiled_profile.descriptor();
    let compiled_digest = compiled.digest().map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    if provider_admission.schema.as_str() != nq_store::LOCAL_PROVIDER_ADMISSION_SCHEMA
        || production_profile.kind != IdentityKind::DiagnosticProfile
        || production_profile.id.as_str() != active_lock.profile.id
        || production_profile.version.as_str() != active_lock.profile.version.to_string()
        || active_lock.profile.id != compiled.profile.id
        || active_lock.profile.version != compiled.profile.version
        || active_lock.profile.digest != compiled_digest.as_str()
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            "production profile Q, exact provider admission R, active R.profile, and compiled native profile S do not preserve one explicit id/version mapping with S's independent native descriptor digest",
        ));
    }
    Ok(())
}

fn require_typed_profile_qualification(
    prepared: &PreparedGovernedInvocation,
    production_profile: &IdentityRef,
    compiled_profile: &'static dyn ProfileModule,
    evaluator: &EvaluatorRuntimeIdentity,
) -> Result<LaunchCorrespondenceSelection, NativeGovernedPreEffectRefusal> {
    let selection = prepared
        .prelaunch_records()
        .select_launch_correspondence(prepared.execution_launch())
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                format!("typed launch correspondence refused: {error}"),
            )
        })?;
    let qualifier = native_governed_record(
        prepared,
        selection.native_profile_qualification(),
        RuntimeSchema::NativeProfileQualificationV1,
    )?;
    let value = qualifier.record().as_value();
    let compiled = compiled_profile.descriptor();
    let descriptor_digest = compiled.digest().map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    let semantic = profile_semantic_id(compiled).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    let empty_detector_closure = nq_store::detector_suite_identity_digest(Vec::<String>::new())
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                error.to_string(),
            )
        })?;
    let expected_profile = serde_json::to_value(production_profile).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    let evaluator_source =
        Sha256Digest::parse(EVALUATOR_SOURCE_DIGEST.to_owned()).map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                error.to_string(),
            )
        })?;
    if value["production_profile"] != expected_profile
        || selection.production_question().kind != IdentityKind::DiagnosticQuestion
        || value["production_question"]
            != serde_json::to_value(selection.production_question()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                    error.to_string(),
                )
            })?
        || value["native_profile"]["descriptor_schema"] != nq_profiles::PROFILE_DESCRIPTOR_SCHEMA
        || value["native_profile"]["profile_id"] != compiled.profile.id
        || value["native_profile"]["profile_version"] != u64::from(compiled.profile.version)
        || value["native_profile"]["descriptor_digest"] != descriptor_digest.as_str()
        || value["native_profile"]["semantic_identity_schema"]
            != nq_profiles::PROFILE_SEMANTIC_ID_SCHEMA
        || value["native_profile"]["semantic_identity_digest"] != semantic.as_str()
        || value["native_profile"]["evaluator_source_digest"] != evaluator_source.as_str()
        || value["native_profile"]["helper_protocol_version"]
            != nq_protocol::HELPER_PROTOCOL_VERSION
        || value["native_profile"]["detector_closure"]["schema"] != "nq.detector_closure.v1"
        || value["native_profile"]["detector_closure"]["identity_digest"]
            != empty_detector_closure.as_str()
        || value["native_profile"]["detector_closure"]["detector_count"] != 0
        || !compiled_profile.detectors().is_empty()
        || value["native_evaluator"]["artifact_digest"] != evaluator.artifact_digest().as_str()
        || value["native_evaluator"]["artifact_identity_method"]
            != evaluator.artifact_identity_method()
        || value["native_evaluator"]["target_triple"] != evaluator.target_triple()
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            "selected typed qualifier does not preserve the exact production question/profile, compiled zero-detector native profile semantics, or independently observed evaluator artifact",
        ));
    }
    Ok(selection)
}

fn require_native_clock_correspondence(
    prepared: &PreparedGovernedInvocation,
    selection: &LaunchCorrespondenceSelection,
    production_clock: &IdentityRef,
) -> Result<StdDuration, NativeGovernedPreEffectRefusal> {
    let qualifier = native_governed_record(
        prepared,
        selection.native_clock_qualification(),
        RuntimeSchema::NativeClockQualificationV1,
    )?;
    let deadline = native_governed_record(
        prepared,
        selection.deadline_evaluation(),
        RuntimeSchema::DeadlineEvaluationV1,
    )?;
    let provenance = prepared.native_deadline().ok_or_else(|| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
            "generic or caller-supplied deadline records cannot acquire native clock provenance",
        )
    })?;
    let qualifier_value = qualifier.record().as_value();
    let deadline_value = deadline.record().as_value();
    if provenance.clock_qualification() != selection.native_clock_qualification()
        || provenance.evaluation() != selection.deadline_evaluation()
        || qualifier_value["production_clock"]
            != serde_json::to_value(production_clock).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
                    error.to_string(),
                )
            })?
        || qualifier_value["absolute_time"]["observation_method"]
            != "clock_gettime-clock-realtime-v1"
        || qualifier_value["absolute_time"]["clock_id"] != "CLOCK_REALTIME"
        || qualifier_value["absolute_time"]["epoch"] != "unix"
        || qualifier_value["absolute_time"]["unit"] != "nanosecond"
        || qualifier_value["absolute_time"]["accuracy_qualification"]["status"] != "unqualified"
        || qualifier_value["boottime"]["observation_method"] != "clock_gettime-clock-boottime-v1"
        || qualifier_value["boottime"]["clock_id"] != "CLOCK_BOOTTIME"
        || qualifier_value["boottime"]["boot_epoch_binding_method"] != "linux-boot-id-v1"
        || qualifier_value["boottime"]["unit"] != "nanosecond"
        || qualifier_value["boottime"]["suspend_semantics"] != "includes_suspended_time"
        || qualifier_value["wall_to_monotonic_bridge"]["method"] != "realtime-boottime-bracket-v1"
        || qualifier_value["runner_watchdog"]["method"] != "std-instant-v1"
        || qualifier_value["runner_watchdog"]["relation_to_governed_deadline"]
            != "auxiliary_non_equivalent"
        || deadline_value["clock_qualification"]
            != serde_json::to_value(selection.native_clock_qualification()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
                    error.to_string(),
                )
            })?
        || deadline_value["decision"]["state"] != "accepted"
        || !deadline_value["decision"]["violations"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || deadline_value["sample"]["boot_epoch"] != provenance.boot_epoch().as_str()
        || deadline_value["sample"]["boottime_at_ns"].as_str()
            != Some(&provenance.boottime_observed_ns().to_string())
        || deadline_value["derived"]["boottime_expiry_ns"].as_str()
            != Some(&provenance.boottime_expiry_ns().to_string())
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
            "selected typed clock/deadline carrier does not match the runtime-owned CLOCK_REALTIME/CLOCK_BOOTTIME/boot-id occurrence",
        ));
    }

    let boot_bytes = fs::read("/proc/sys/kernel/random/boot_id").map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
            format!("current Linux boot identity cannot be read: {error}"),
        )
    })?;
    if nq_protocol::sha256_bytes(&boot_bytes) != *provenance.boot_epoch() {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
            "current Linux boot epoch differs from the runtime-owned launch epoch",
        ));
    }
    let observed = boottime_ns().map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    if observed < provenance.boottime_observed_ns() || observed >= provenance.boottime_expiry_ns() {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::DeadlineExpired,
            "the exact runtime-owned CLOCK_BOOTTIME launch window is not currently open",
        ));
    }
    Ok(StdDuration::from_nanos(
        provenance.boottime_expiry_ns() - observed,
    ))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn governed_conformance_artifact_context(
    prepared: &PreparedGovernedInvocation,
    selection: &LaunchCorrespondenceSelection,
    production_profile: &IdentityRef,
    production_clock: &IdentityRef,
    native_request: &HelperRequest,
    provider_attempt: &NativeGovernedProviderAttemptPlan,
    evaluator: &EvaluatorRuntimeIdentity,
    launched_at: DateTime<Utc>,
) -> Result<GovernedConformanceArtifactContext, NativeGovernedPreEffectRefusal> {
    let qualifier = native_governed_record(
        prepared,
        selection.native_profile_qualification(),
        RuntimeSchema::NativeProfileQualificationV1,
    )?;
    let production_build: IdentityRef = serde_json::from_value(
        qualifier.record().as_value()["production_build"].clone(),
    )
    .map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    if production_build.kind != IdentityKind::Build {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
            "native profile qualification production build is not a build identity",
        ));
    }
    validate_authenticated_production_descriptor(
        prepared.dependencies(),
        &production_build,
        "build",
    )?;

    let semantic = |id: &str, version: &str, descriptor: &Value| {
        semantic_identity(id, version, descriptor).map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                error.to_string(),
            )
        })
    };
    let production = prepared.production_identity();
    let native_profile_semantic =
        profile_semantic_id(nq_profiles::conformance::MODULE.descriptor()).map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                error.to_string(),
            )
        })?;
    let evaluator_descriptor = json!({
        "schema": "nq.native_evaluator_identity.v1",
        "artifact_digest": evaluator.artifact_digest(),
        "artifact_identity_method": evaluator.artifact_identity_method(),
        "target_triple": evaluator.target_triple(),
        "platform_runtime_version": evaluator.platform_runtime_version(),
        "evaluator_source_digest": EVALUATOR_SOURCE_DIGEST,
    });
    let scope_descriptor = json!({
        "schema": "nq.governed_conformance_scope.v1",
        "production_subject": production.subject(),
        "native_subject": native_request.binding.subject,
        "native_scope": native_request.binding.scope,
    });
    let state_model_descriptor = json!({
        "schema": "nq.governed_conformance_state_model.v1",
        "profile_semantic_id": native_profile_semantic.as_str(),
        "state_binding": "exact_request_echo",
    });
    let no_threshold_descriptor = json!({
        "schema": "nq.no_threshold_policy.v1",
        "profile_semantic_id": native_profile_semantic.as_str(),
        "hysteresis": "none",
    });
    let projection_descriptor = json!({
        "schema": "nq.governed_conformance_projection.v1",
        "profile_semantic_id": native_profile_semantic.as_str(),
        "fields": ["nonce"],
        "omitted_distinctions": [],
    });
    let capture_descriptor = json!({
        "schema": "nq.local_helper_exact_capture_policy.v1",
        "provider_request_id": native_request.request_id,
        "maximum_response_bytes": native_request.bounds.max_response_bytes,
        "capture_mode": "exact_source",
    });
    let admission_descriptor = json!({
        "schema": "nq.compiled_profile_admission_rule.v1",
        "profile_semantic_id": native_profile_semantic.as_str(),
        "helper_protocol_version": nq_protocol::HELPER_PROTOCOL_VERSION,
    });
    let normalization_descriptor = json!({
        "schema": "nq.conformance_normalization_rule.v1",
        "profile_semantic_id": native_profile_semantic.as_str(),
        "helper_protocol_version": nq_protocol::HELPER_PROTOCOL_VERSION,
    });
    let projection_rule_descriptor = json!({
        "schema": "nq.conformance_projection_rule.v1",
        "profile_semantic_id": native_profile_semantic.as_str(),
        "projection": projection_descriptor,
    });
    let selection_descriptor = json!({
        "schema": "nq.governed_conformance_selection_rule.v1",
        "expected_role": "governed_conformance_echo",
        "cardinality": "exactly_one",
        "production_question": selection.production_question(),
    });

    let mut limitations = vec![DiagnosticLimitationV1 {
        kind: DiagnosticLimitationKindV1::Other,
        code: "clock_accuracy_unqualified".to_owned(),
        detail:
            "the native runtime bound the occurrence monotonically but established no finite UTC error"
                .to_owned(),
    }];
    limitations.sort_by(|left, right| left.code.as_bytes().cmp(right.code.as_bytes()));
    let mut nonclaims = vec![
        "this artifact does not establish host health".to_owned(),
        "this artifact does not establish Nightshift posture or recurrence".to_owned(),
        "this artifact grants no consumer reliance".to_owned(),
        "this artifact grants no operational authorization or action".to_owned(),
    ];
    nonclaims.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    Ok(GovernedConformanceArtifactContext {
        producer: DiagnosticProducerV1 {
            node_id: production.node().id.as_str().to_owned(),
            build: semantic_identity_from_production(&production_build),
            cohort: semantic_identity_from_production(production.cohort()),
        },
        request_id: DiagnosticRequestId(prepared.request_id().to_owned()),
        run_id: DiagnosticRunId(provider_attempt.run_id.clone()),
        question: semantic_identity_from_production(selection.production_question()),
        subject: DiagnosticSubjectV1 {
            id: production.subject().id.as_str().to_owned(),
            scope: semantic(
                "nq.governed_conformance_scope",
                "1",
                &scope_descriptor,
            )?,
        },
        profile: semantic_identity_from_production(production_profile),
        profile_semantic_id: Sha256Digest::parse(native_profile_semantic.as_str().to_owned())
            .map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                    error.to_string(),
                )
            })?,
        vantage: semantic_identity_from_production(production.vantage()),
        state_model: semantic(
            "nq.governed_conformance_state_model",
            "1",
            &state_model_descriptor,
        )?,
        evaluator: semantic("nq.native_evaluator", "1", &evaluator_descriptor)?,
        threshold_policy: semantic(
            "nq.conformance_no_threshold",
            "1",
            &no_threshold_descriptor,
        )?,
        projection: DiagnosticProjectionV1 {
            identity: semantic(
                "nq.governed_conformance_projection",
                "1",
                &projection_descriptor,
            )?,
            omitted_distinctions: vec![],
        },
        execution_clock: semantic_identity_from_production(production_clock),
        clock_qualification: ClockQualificationV2::Unqualified {
            code: "utc_accuracy_unqualified".to_owned(),
            detail:
                "the runtime established CLOCK_REALTIME/CLOCK_BOOTTIME correspondence but no finite UTC error bound"
                    .to_owned(),
        },
        started_at: launched_at,
        capture_policy: semantic(
            "nq.local_helper_exact_capture_policy",
            "1",
            &capture_descriptor,
        )?,
        admission_rule: semantic(
            "nq.compiled_profile_admission_rule",
            "1",
            &admission_descriptor,
        )?,
        normalization_rule: semantic(
            "nq.conformance_normalization_rule",
            "1",
            &normalization_descriptor,
        )?,
        projection_rule: semantic(
            "nq.conformance_projection_rule",
            "1",
            &projection_rule_descriptor,
        )?,
        selection_rule: semantic(
            "nq.governed_conformance_selection_rule",
            "1",
            &selection_descriptor,
        )?,
        limitations,
        nonclaims,
    })
}

fn require_effective_node_and_key_authority(
    prepared: &PreparedGovernedInvocation,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    prepared
        .prelaunch_records()
        .require_effective_launch_lifecycle(prepared.execution_launch())
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NodeLifecycleAuthorityUnavailable,
                format!(
                    "launch lacks one unique effective node/key/witness lifecycle prefix: {error}"
                ),
            )
        })
}

fn require_native_custody_correspondence(
    store: &Store,
    prepared: &PreparedGovernedInvocation,
    watcher: &WatcherConfig,
    request: &HelperRequest,
    provider: &VerifiedProvider,
    attempt: &NativeGovernedProviderAttemptPlan,
    artifact_context: &GovernedConformanceArtifactContext,
) -> Result<GovernedConformanceArtifactCapacity, NativeGovernedPreEffectRefusal> {
    let reservation = prepared.custody_reservation_spec();
    let dependency_bytes =
        u64::try_from(prepared.dependency_custody_bytes().len()).map_err(|_| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
                "exact dependency closure length exceeds native u64 capacity",
            )
        })?;
    let provider_intake_bound = provider_intake_capacity_bound(
        request,
        provider,
        &watcher.resources,
        &attempt.intake_id,
        &attempt.attempt_id,
        &attempt.run_id,
        &attempt.origin_carrier,
        &attempt.checkpoint_contract_digest,
    )
    .map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    let acquisition_bound = nq_store::governed_acquisition_capacity_bound(
        provider_intake_bound.canonical_record_bytes,
        provider_intake_bound.raw_capture_bytes,
    )
    .map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    require_native_acquisition_partition_capacity(
        reservation.dependency_closure_capacity_bytes,
        reservation.raw_capacity_bytes,
        dependency_bytes,
        acquisition_bound,
    )?;
    let diagnostic_bound = governed_conformance_artifact_capacity_bound(
        artifact_context,
        &attempt.intake_id,
        request.instance_id.as_str(),
        provider_intake_bound,
    )
    .map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeFinalCustodyCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    require_native_diagnostic_partition_capacity(
        reservation.diagnostic_artifact_capacity_bytes,
        diagnostic_bound.canonical_artifact_bytes,
    )?;
    let launch_checkpoint_id = Sha256Digest::parse(
        prepared.launch_checkpoint().checkpoint_id.clone(),
    )
    .map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeFinalCustodyCorrespondenceUnavailable,
            format!("launch checkpoint identity cannot be reopened: {error}"),
        )
    })?;
    let final_capacity = store
        .verify_governed_execution_custody_closure_v3_capacity(reservation, &launch_checkpoint_id)
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeFinalCustodyCorrespondenceUnavailable,
                error.to_string(),
            )
        })?;
    if final_capacity.diagnostic_artifact_capacity_bytes
        != reservation.diagnostic_artifact_capacity_bytes
        || final_capacity.final_closure_capacity_bytes > reservation.final_capacity_bytes
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeFinalCustodyCorrespondenceUnavailable,
            "committed Store capacity result differs from the exact prepared reservation",
        ));
    }
    Ok(diagnostic_bound)
}

fn require_native_diagnostic_partition_capacity(
    diagnostic_capacity_bytes: u64,
    diagnostic_bound_bytes: u64,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    if diagnostic_bound_bytes > diagnostic_capacity_bytes {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeFinalCustodyCorrespondenceUnavailable,
            format!(
                "governed conformance diagnostic requires {diagnostic_bound_bytes} bytes but exact reservation provides {diagnostic_capacity_bytes}",
            ),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct NativeGovernedProviderAttemptPlan {
    intake_id: String,
    attempt_id: String,
    run_id: String,
    origin_carrier: String,
    checkpoint_contract_digest: Sha256Digest,
}

#[allow(clippy::too_many_arguments)]
fn native_governed_provider_attempt_plan(
    prepared: &PreparedGovernedInvocation,
    watcher: &WatcherConfig,
    active_lock: &AdmissionLock,
    admission_verification: &crate::admission::AdmissionVerification,
    profile_digest: &str,
    request: &HelperRequest,
    provider: &VerifiedProvider,
) -> Result<NativeGovernedProviderAttemptPlan, NativeGovernedPreEffectRefusal> {
    let occurrence_id = |kind: &str| {
        nq_protocol::semantic_digest(&json!({
            "schema": "nq.governed_native_provider_occurrence.v1",
            "kind": kind,
            "outer_request_id": prepared.request_id(),
            "execution_launch": prepared.execution_launch(),
            "native_request_id": request.request_id,
            "provider_admission_id": provider.identity().provider_admission_id,
        }))
        .map(Sha256Digest::into_string)
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
                error.to_string(),
            )
        })
    };
    let checkpoint_contract_digest = checkpoint_contract_digest(
        watcher,
        active_lock,
        &admission_verification.binding_digest,
        profile_digest,
    )
    .and_then(|digest| {
        Sha256Digest::parse(digest).map_err(|error| EngineError::Invariant(error.to_string()))
    })
    .map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
            error.to_string(),
        )
    })?;
    let plan = NativeGovernedProviderAttemptPlan {
        intake_id: occurrence_id("provider_intake")?,
        attempt_id: occurrence_id("provider_attempt")?,
        run_id: occurrence_id("watcher_run")?,
        origin_carrier: carrier_name(watcher.carrier).to_owned(),
        checkpoint_contract_digest,
    };
    if plan.intake_id == plan.attempt_id
        || plan.intake_id == plan.run_id
        || plan.attempt_id == plan.run_id
        || plan.attempt_id == request.request_id.as_str()
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
            "derived native provider occurrence identities are not pairwise distinct",
        ));
    }
    Ok(plan)
}

fn require_native_acquisition_partition_capacity(
    dependency_capacity_bytes: u64,
    raw_capacity_bytes: u64,
    dependency_bytes: u64,
    acquisition_bytes: u64,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    if dependency_bytes > dependency_capacity_bytes {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
            format!(
                "exact dependency closure requires {dependency_bytes} bytes but the reservation permits {dependency_capacity_bytes}"
            ),
        ));
    }
    if acquisition_bytes > raw_capacity_bytes {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
            format!(
                "conservative native provider-intake acquisition carrier requires {acquisition_bytes} bytes but the reservation permits {raw_capacity_bytes}"
            ),
        ));
    }
    Ok(())
}

fn validate_exact_provider_admission(
    provider_admission_ref: &RecordRef,
    provider_admission: &nq_store::LocalProviderAdmissionRow,
    actual_provider_admission_id: &Sha256Digest,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    if actual_provider_admission_id.as_str() != provider_admission.provider_admission_id
        || provider_admission.contract_digest != provider_admission.provider_admission_id
        || nq_protocol::sha256_bytes(&provider_admission.contract_json).as_str()
            != provider_admission.provider_admission_id
        || provider_admission_ref.schema.as_str() != nq_store::LOCAL_PROVIDER_ADMISSION_SCHEMA
        || provider_admission_ref.record_id.as_str() != provider_admission.provider_admission_id
        || provider_admission_ref.bytes_digest.as_str() != provider_admission.contract_digest
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProviderAdmissionMismatch,
            "selected witness does not name the exact NQ-derived local-provider admission",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
struct NativeGovernedPreEffectCandidate {
    watcher: WatcherConfig,
    profile: &'static dyn ProfileModule,
    active_lock: AdmissionLock,
    admission_verification: crate::admission::AdmissionVerification,
    verified_launch: VerifiedLaunch,
    verified_provider: VerifiedProvider,
    provider_admission: nq_store::LocalProviderAdmissionRow,
    selected_witness: RecordRef,
    launch_correspondence: LaunchCorrespondenceSelection,
    production_clock: IdentityRef,
    native_request: HelperRequest,
    provider_attempt: NativeGovernedProviderAttemptPlan,
    artifact_context: GovernedConformanceArtifactContext,
    artifact_capacity: GovernedConformanceArtifactCapacity,
    absolute_deadline: DateTime<Utc>,
    remaining_budget: StdDuration,
}

/// Private one-use carrier for the first native governed execution half.
///
/// This value is deliberately neither cloneable nor serializable. It owns the
/// opaque runtime token and the retained executable descriptors, but it has no
/// method that can spawn the provider. A later effectful half must consume it,
/// recheck the absolute deadline, and terminalize every claimed occurrence.
///
/// No such half is wired here. In addition to the explicit profile/clock
/// correspondence refusals below, `nq.conformance/v1` has zero detectors while
/// the current V2 producer assumes exactly one. That is a separate later-slice
/// blocker, not a reason to fabricate a diagnostic result in this seam.
#[allow(dead_code)]
struct NativeGovernedExecutionPlan {
    prepared: PreparedGovernedInvocation,
    candidate: NativeGovernedPreEffectCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum GovernedProjectionFailpoint {
    None,
    AfterFinalSealBeforeSql,
    AfterSqlBeforeIndexMark,
}

enum NativeGovernedSqlCommitPlan {
    Admitted {
        collection: CollectionInput,
        outcome: CollectionOutcome,
        status: StatusEventInput,
        expected_semantic_digest: Sha256Digest,
    },
    NonSuccess {
        collection: CollectionInput,
        outcome: CollectionOutcome,
        result: RunResultStatusInput,
    },
}

impl NativeGovernedSqlCommitPlan {
    fn projection_capsule_input(
        &self,
        reservation_record_id: Sha256Digest,
        diagnostic_artifact: DiagnosticArtifactCommitInput,
        publication: nq_store::GovernedProjectionPublication,
    ) -> GovernedProjectionCapsuleInput {
        match self {
            Self::Admitted {
                collection,
                status,
                expected_semantic_digest,
                ..
            } => GovernedProjectionCapsuleInput {
                reservation_record_id,
                collection: collection.clone(),
                diagnostic_artifact,
                status: status.clone(),
                mode: GovernedProjectionCapsuleMode::Admitted,
                expected_semantic_digest: Some(expected_semantic_digest.clone()),
                publication,
            },
            Self::NonSuccess {
                collection, result, ..
            } => GovernedProjectionCapsuleInput {
                reservation_record_id,
                collection: collection.clone(),
                diagnostic_artifact,
                status: result.status.clone(),
                mode: GovernedProjectionCapsuleMode::NonSuccess,
                expected_semantic_digest: None,
                publication,
            },
        }
    }
}

fn governed_persistence_occurrence_id(
    kind: &'static str,
    intake: &ProviderIntakeRecordV1,
) -> Result<String, EngineError> {
    nq_protocol::semantic_digest(&json!({
        "schema": "nq.governed_conformance_persistence_occurrence.v1",
        "kind": kind,
        "intake_id": intake.intake_id,
        "attempt_id": intake.attempt_id,
        "run_id": intake.run_id,
        "request_id": intake.request_id,
        "raw_sha256": intake.raw_sha256,
    }))
    .map(Sha256Digest::into_string)
    .map_err(|error| EngineError::Canonical(error.to_string()))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn prepare_native_governed_sql_commit(
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    intake: &ProviderIntakeRecordV1,
    intake_input: ProviderIntakeInput,
    run: RunInput,
    persistence: GovernedConformancePersistenceV2,
) -> Result<NativeGovernedSqlCommitPlan, EngineError> {
    let received_at = timestamp(intake.received_at);
    let raw_bytes = intake_input.raw_bytes.clone();
    let (submission, outcome) = match persistence {
        GovernedConformancePersistenceV2::Admitted(admitted) => {
            let report_id = governed_persistence_occurrence_id("admitted_report", intake)?;
            let submission_id = governed_persistence_occurrence_id("admitted_submission", intake)?;
            let semantic_digest = nq_protocol::semantic_digest(&admitted.report)
                .map_err(|error| EngineError::Canonical(error.to_string()))?;
            let report_status = semantic_report_status(admitted.validated_report.status).to_owned();
            let stored_report = store_report(
                &report_id,
                watcher,
                profile,
                &admitted.report,
                &admitted.validated_report,
                intake.received_at,
            )?;
            let outcome = CollectionOutcome::admitted(
                watcher.instance_id.clone(),
                run.run_id.clone(),
                report_id,
                report_status,
                semantic_digest.to_string(),
                Vec::new(),
            );
            let status = governed_execution_status_event(watcher, intake, &outcome)?;
            return Ok(NativeGovernedSqlCommitPlan::Admitted {
                collection: CollectionInput {
                    intake: intake_input,
                    run,
                    submission: Some(SubmissionInput {
                        submission_id,
                        raw_bytes,
                        received_at,
                        protocol_outcome: "valid_report".to_owned(),
                        disposition: SubmissionDisposition::Admitted(stored_report),
                    }),
                },
                outcome,
                status,
                expected_semantic_digest: semantic_digest,
            });
        }
        GovernedConformancePersistenceV2::Refused { kind, refusal } => {
            let expected_origin = match kind {
                GovernedConformanceRefusalKindV2::Helper => {
                    matches!(&refusal.origin, GovernedRefusalOrigin::Helper(_))
                }
                GovernedConformanceRefusalKindV2::Protocol => {
                    matches!(&refusal.origin, GovernedRefusalOrigin::Protocol(_))
                }
                GovernedConformanceRefusalKindV2::Profile => {
                    matches!(&refusal.origin, GovernedRefusalOrigin::Profile(_))
                }
            };
            if !expected_origin || raw_bytes.is_empty() {
                return Err(EngineError::Invariant(
                    "governed refusal persistence kind or exact raw custody differs from its derivation"
                        .to_owned(),
                ));
            }
            let protocol_outcome = match kind {
                GovernedConformanceRefusalKindV2::Helper => "valid_refusal",
                GovernedConformanceRefusalKindV2::Protocol => "rejected",
                GovernedConformanceRefusalKindV2::Profile => "valid_report",
            };
            let stored = stored_governed_refusal(&refusal, intake.received_at)?;
            let submission_id = governed_persistence_occurrence_id("refused_submission", intake)?;
            let outcome = CollectionOutcome::rejected(
                watcher.instance_id.clone(),
                run.run_id.clone(),
                refusal,
            );
            (
                Some(SubmissionInput {
                    submission_id,
                    raw_bytes,
                    received_at,
                    protocol_outcome: protocol_outcome.to_owned(),
                    disposition: SubmissionDisposition::Rejected { refusal: stored },
                }),
                outcome,
            )
        }
        GovernedConformancePersistenceV2::AcquisitionFailed {
            kind,
            failure,
            refusal,
        } => match kind {
            GovernedConformanceAcquisitionKindV2::ProviderNoResponse
            | GovernedConformanceAcquisitionKindV2::NoBytesRetained => {
                if !raw_bytes.is_empty() || refusal.is_some() {
                    return Err(EngineError::Invariant(
                        "no-byte governed acquisition persistence retained bytes or a refusal"
                            .to_owned(),
                    ));
                }
                (
                    None,
                    CollectionOutcome {
                        schema: CollectionOutcomeSchema::V1,
                        instance_id: watcher.instance_id.clone(),
                        run_id: Some(run.run_id.clone()),
                        result: CollectionResult::AcquisitionFailed { failure },
                    },
                )
            }
            GovernedConformanceAcquisitionKindV2::BytesRetained => {
                let refusal = refusal.ok_or_else(|| {
                    EngineError::Invariant(
                        "retained governed acquisition failure has no exact refusal".to_owned(),
                    )
                })?;
                if raw_bytes.is_empty()
                    || !matches!(
                        &refusal.origin,
                        GovernedRefusalOrigin::Acquisition(source) if source.failure == failure
                    )
                {
                    return Err(EngineError::Invariant(
                        "retained governed acquisition bytes, failure, and refusal do not join"
                            .to_owned(),
                    ));
                }
                let stored = stored_governed_refusal(&refusal, intake.received_at)?;
                let submission_id =
                    governed_persistence_occurrence_id("acquisition_refusal_submission", intake)?;
                let outcome = CollectionOutcome::rejected(
                    watcher.instance_id.clone(),
                    run.run_id.clone(),
                    refusal,
                );
                (
                    Some(SubmissionInput {
                        submission_id,
                        raw_bytes,
                        received_at,
                        protocol_outcome: "not_validated".to_owned(),
                        disposition: SubmissionDisposition::Rejected { refusal: stored },
                    }),
                    outcome,
                )
            }
        },
    };
    let status = governed_execution_status_event(watcher, intake, &outcome)?;
    Ok(NativeGovernedSqlCommitPlan::NonSuccess {
        collection: CollectionInput {
            intake: intake_input,
            run,
            submission,
        },
        result: RunResultStatusInput {
            run_id: outcome.run_id.clone().ok_or_else(|| {
                EngineError::Invariant(
                    "governed postlaunch result lost its watcher run identity".to_owned(),
                )
            })?,
            status,
        },
        outcome,
    })
}

/// Total result of attempting to construct the private pre-effect plan.
///
/// Refusal retains the opaque prepared occurrence so a future finalizer can
/// commit the exact refusal instead of stranding or rerunning the launch.
#[allow(dead_code)]
enum NativeGovernedPreEffectOutcome {
    Ready(Box<NativeGovernedExecutionPlan>),
    Refused {
        prepared: Box<PreparedGovernedInvocation>,
        refusal: NativeGovernedPreEffectRefusal,
    },
}

fn governed_launch_attempt_deadline(
    prepared: &PreparedGovernedInvocation,
) -> Result<String, EngineError> {
    let launch = native_governed_record(
        prepared,
        prepared.execution_launch(),
        RuntimeSchema::ExecutionLaunchV1,
    )
    .map_err(|refusal| {
        EngineError::Invariant(format!(
            "protected terminal cannot reopen the exact execution launch: {}",
            refusal.detail
        ))
    })?;
    launch.record().as_value()["attempt_deadline"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            EngineError::Invariant(
                "protected terminal cannot recover the exact launch attempt deadline".to_owned(),
            )
        })
}

fn governed_protected_terminal_input(
    prepared: &PreparedGovernedInvocation,
    terminal_class: GovernedProtectedTerminalClass,
    reason_code: String,
    detail: impl Into<String>,
) -> Result<GovernedProtectedTerminalInput, EngineError> {
    let detail: String = detail.into();
    Ok(GovernedProtectedTerminalInput {
        execution_launch_record_id: prepared.execution_launch().record_id.clone(),
        terminal_class,
        reason: GovernedProtectedTerminalReason {
            code: reason_code,
            detail: bounded_governed_terminal_detail(&detail),
        },
        launch_attempt_deadline: governed_launch_attempt_deadline(prepared)?,
        terminalized_at: timestamp(Utc::now()),
        // The host-role runtime has an exact monotonic deadline carrier, but
        // this failure record is constructed after a failed seam step. Do not
        // mint a finite wall-clock comparison merely because both strings can
        // be parsed.
        deadline_compliance: GovernedProtectedTerminalDeadlineCompliance::NotEstablished,
    })
}

fn bounded_governed_terminal_detail(detail: &str) -> String {
    const MAX_BYTES: usize = 2_048;
    const SUFFIX: &str = "[truncated]";

    let mut detail = detail.replace('\0', "\\0");
    if detail.is_empty() {
        return "no additional failure detail was available".to_owned();
    }
    if detail.len() <= MAX_BYTES {
        return detail;
    }
    let mut end = MAX_BYTES - SUFFIX.len();
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    detail.push_str(SUFFIX);
    detail
}

fn terminalize_native_pre_effect_refusal(
    session: &mut StoreWriterSession<'_>,
    prepared: &mut PreparedGovernedInvocation,
    refusal: NativeGovernedPreEffectRefusal,
) -> EngineError {
    let NativeGovernedPreEffectRefusal { code, detail } = refusal;
    let detail = bounded_governed_terminal_detail(&detail);
    let input = governed_protected_terminal_input(
        prepared,
        GovernedProtectedTerminalClass::PreEffectRefusal,
        format!("nq.native_pre_effect.{}", code.as_str()),
        detail.clone(),
    );
    match input.and_then(|input| {
        prepared
            .terminalize_immediate_launch(session, input)
            .map(|_| ())
            .map_err(EngineError::from)
    }) {
        Ok(()) => EngineError::GovernedExecutionRefused { code, detail },
        Err(terminal_error) => EngineError::Invariant(format!(
            "native governed pre-effect refusal {code:?} could not terminalize its exact launch: {terminal_error}; original refusal: {detail}"
        )),
    }
}

fn terminalize_native_postlaunch_failure(
    session: &mut StoreWriterSession<'_>,
    prepared: &mut PreparedGovernedInvocation,
    stage: &'static str,
    failure: EngineError,
) -> EngineError {
    let detail = bounded_governed_terminal_detail(&failure.to_string());
    let input = governed_protected_terminal_input(
        prepared,
        GovernedProtectedTerminalClass::PostlaunchFailure,
        format!("nq.native_postlaunch.{stage}"),
        detail.clone(),
    );
    match input.and_then(|input| {
        prepared
            .terminalize_immediate_launch(session, input)
            .map(|_| ())
            .map_err(EngineError::from)
    }) {
        Ok(()) => failure,
        Err(terminal_error) => EngineError::Invariant(format!(
            "native governed postlaunch failure at {stage} could not terminalize its exact launch: {terminal_error}; original failure: {detail}"
        )),
    }
}

fn handle_native_governed_publication_failure(
    session: &mut StoreWriterSession<'_>,
    prepared: &mut PreparedGovernedInvocation,
    failure: EngineError,
) -> EngineError {
    let state = match prepared.live_custody_state() {
        Ok(state) => state,
        Err(initial_error) => match prepared.reopen_custody_state_after_indeterminate_write(session) {
            Ok(state) => state,
            Err(reopen_error) => {
                return EngineError::Invariant(format!(
                    "governed publication failed and its durable custody frontier could not be reopened: initial state error: {initial_error}; reopen error: {reopen_error}; publication failure: {failure}"
                ));
            }
        },
    };
    match state {
        nq_store::GovernedCustodyState::Reserved
        | nq_store::GovernedCustodyState::LaunchClaimed
        | nq_store::GovernedCustodyState::AcquisitionSealed
        | nq_store::GovernedCustodyState::DerivationClaimed => {
            terminalize_native_postlaunch_failure(
                session,
                prepared,
                "final_projection_publication",
                failure,
            )
        }
        nq_store::GovernedCustodyState::FinalSealIntent
        | nq_store::GovernedCustodyState::FinalClosureIndexPending
        | nq_store::GovernedCustodyState::FinalClosureIndexed
        | nq_store::GovernedCustodyState::FinalClosureProjectionRefused
        | nq_store::GovernedCustodyState::FinalClosureCommittedUnavailable
        | nq_store::GovernedCustodyState::FinalClosureCorrupt
        | nq_store::GovernedCustodyState::FailedIndeterminate
        | nq_store::GovernedCustodyState::ExpiredUnlaunched => failure,
    }
}

fn native_timestamp(
    value: &Value,
    field: &str,
) -> Result<DateTime<Utc>, NativeGovernedPreEffectRefusal> {
    let encoded = value[field].as_str().ok_or_else(|| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::PreparedClosureInvalid,
            format!("{field} is absent from the governed prelaunch"),
        )
    })?;
    DateTime::parse_from_rfc3339(encoded)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::PreparedClosureInvalid,
                format!("{field} is not an RFC 3339 instant: {error}"),
            )
        })
}

fn validate_prepared_dependency_custody(
    prepared: &PreparedGovernedInvocation,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    let exact_dependency_bytes = prepared
        .dependencies()
        .custody()
        .canonical_closure_bytes()
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::PreparedClosureInvalid,
                error.to_string(),
            )
        })?;
    if exact_dependency_bytes != prepared.dependency_custody_bytes() {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::PreparedClosureInvalid,
            "prepared dependency-generation bytes differ from the authenticated dependency object",
        ));
    }
    Ok(())
}

fn selected_governed_witness<'a>(
    prepared: &'a PreparedGovernedInvocation,
    launch: &ValidatedRuntimeRecord,
) -> Result<(RecordRef, &'a ValidatedRuntimeRecord), NativeGovernedPreEffectRefusal> {
    let selected = launch.record().as_value()["selected_witness_attachments"]
        .as_array()
        .ok_or_else(|| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::WitnessBindingMismatch,
                "execution launch has no closed witness selection",
            )
        })?;
    let [selected] = selected.as_slice() else {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::WitnessBindingMismatch,
            "conformance execution requires exactly one selected witness",
        ));
    };
    let selected: RecordRef = serde_json::from_value(selected.clone()).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::WitnessBindingMismatch,
            error.to_string(),
        )
    })?;
    let witness = native_governed_record(prepared, &selected, RuntimeSchema::WitnessAttachmentV1)?;
    Ok((selected, witness))
}

fn conformance_attachment_has_zero_access(
    witness: &Value,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    for field in ["privileges", "namespaces", "resources"] {
        if !witness[field].as_array().is_some_and(Vec::is_empty) {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::AccessSurfaceNotEmpty,
                format!("nq.conformance/v1 selected witness declares nonempty {field}"),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn exact_conformance_native_request(
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    child_request_id: RequestId,
    expires_at_ns: u64,
) -> Result<HelperRequest, NativeGovernedPreEffectRefusal> {
    let descriptor = profile.descriptor();
    let profile_digest = descriptor.digest().map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProfileIncompatible,
            error.to_string(),
        )
    })?;
    let request = HelperRequest {
        schema: nq_protocol::HELPER_REQUEST_SCHEMA.to_owned(),
        protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
        request_id: child_request_id,
        instance_id: InstanceId::new(watcher.instance_id.clone()).map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
                error.to_string(),
            )
        })?,
        profile: ProfileBinding {
            id: ProfileId::new(descriptor.profile.id.clone()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProfileIncompatible,
                    error.to_string(),
                )
            })?,
            version: ProfileVersion::new(descriptor.profile.version.to_string()).map_err(
                |error| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::ProfileIncompatible,
                        error.to_string(),
                    )
                },
            )?,
            digest: Sha256Digest::parse(profile_digest.as_str().to_owned()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProfileIncompatible,
                    error.to_string(),
                )
            })?,
        },
        binding: SubjectBinding {
            subject: SubjectId::new(watcher.subject.clone()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
                    error.to_string(),
                )
            })?,
            scope: ScopeBinding {
                kind: ScopeKind::new(watcher.scope.kind.clone()).map_err(|error| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
                        error.to_string(),
                    )
                })?,
                value: watcher.scope.value.clone(),
            },
            vantage: VantageBinding {
                kind: VantageKind::new(watcher.vantage.kind.clone()).map_err(|error| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
                        error.to_string(),
                    )
                })?,
                value: watcher.vantage.value.clone(),
            },
        },
        granted_capabilities: Vec::new(),
        checkpoint: None,
        deadline: MonotonicDeadline {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns,
        },
        bounds: CollectionBounds {
            max_response_bytes: u32::try_from(watcher.resources.max_response_bytes)
                .unwrap_or(u32::MAX),
            max_observations: u32::try_from(watcher.resources.max_observations)
                .unwrap_or(u32::MAX)
                .min(descriptor.limits.max_observations),
            max_payload_bytes: descriptor.limits.max_payload_bytes,
            max_coverage_entries: descriptor.limits.max_coverage_declarations,
            max_report_errors: 128,
            max_checkpoint_bytes: 65_536,
        },
    };
    nq_protocol::validate_request(&request).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
            error.to_string(),
        )
    })?;
    let context = ValidationContext::from_request(&request, Utc::now(), Duration::seconds(60));
    profile.validate_binding(&context).map_err(|refusal| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
            format!(
                "native conformance subject/scope/nonce/vantage refused at {:?}/{:?}: {}",
                refusal.boundary, refusal.code, refusal.message
            ),
        )
    })?;
    Ok(request)
}

fn native_child_request_id(
    outer_request_id: &str,
    execution_launch: &RecordRef,
) -> Result<RequestId, NativeGovernedPreEffectRefusal> {
    let digest = nq_protocol::semantic_digest(&json!({
        "schema": "nq.governed_native_child_request.v1",
        "outer_request_id": outer_request_id,
        "execution_launch": execution_launch,
    }))
    .map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
            error.to_string(),
        )
    })?;
    let suffix = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
            "derived child-request digest lacks its algorithm qualifier",
        )
    })?;
    let child = RequestId::new(format!("nq-provider-{suffix}")).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
            error.to_string(),
        )
    })?;
    if child.as_str() == outer_request_id {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch,
            "native provider request identity collapsed into the outer diagnostic request identity",
        ));
    }
    Ok(child)
}

const PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA: &str = "nq.production_identity_descriptor.v1";

fn validate_descriptor_catalog_uniqueness(
    identities: &[IdentityRef],
    expected: &IdentityRef,
    slot: &str,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    let aliases = identities
        .iter()
        .filter(|identity| identity.descriptor_digest == expected.descriptor_digest)
        .collect::<Vec<_>>();
    if aliases.as_slice() != [expected] {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!(
                "{slot} descriptor digest resolves to {} production identity keys rather than one exact key",
                aliases.len()
            ),
        ));
    }
    Ok(())
}

fn validate_production_identity_descriptor_bytes(
    expected: &IdentityRef,
    bytes: &[u8],
    slot: &str,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} descriptor is not JSON: {error}"),
        )
    })?;
    let canonical = nq_protocol::canonical_json_bytes(&value).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} descriptor cannot be canonicalized: {error}"),
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} descriptor is not an object"),
        )
    })?;
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_kind = serde_json::to_value(expected.kind).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} kind cannot be represented: {error}"),
        )
    })?;
    if canonical != bytes
        || nq_protocol::sha256_bytes(bytes) != expected.descriptor_digest
        || keys != BTreeSet::from(["schema", "kind", "id", "version"])
        || value["schema"] != PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA
        || value["kind"] != expected_kind
        || value["id"].as_str() != Some(expected.id.as_str())
        || value["version"].as_str() != Some(expected.version.as_str())
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} descriptor preimage is absent, aliased, or substituted"),
        ));
    }
    Ok(())
}

fn validate_authenticated_production_descriptor(
    dependencies: &RuntimeDependencies,
    expected: &IdentityRef,
    slot: &str,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    validate_descriptor_catalog_uniqueness(
        &dependencies.catalog_snapshot().identities,
        expected,
        slot,
    )?;
    let sources = dependencies
        .external_dependency_snapshot()
        .dependencies
        .iter()
        .filter(|dependency| {
            dependency.reference.schema.as_str() == PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA
                && dependency.reference.bytes_digest == expected.descriptor_digest
        })
        .collect::<Vec<_>>();
    let [source] = sources.as_slice() else {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!(
                "{slot} descriptor digest resolves to {} authenticated exact-byte sources rather than one",
                sources.len()
            ),
        ));
    };
    if !matches!(
        source.availability,
        ExternalDependencyAvailability::Online | ExternalDependencyAvailability::ArchivedRetrieved
    ) {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} descriptor bytes are committed but unavailable"),
        ));
    }
    let encoded = source.exact_bytes_hex.as_deref().ok_or_else(|| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} authenticated descriptor has no exact bytes"),
        )
    })?;
    let bytes = hex::decode(encoded).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} descriptor bytes are not canonical hexadecimal: {error}"),
        )
    })?;
    if hex::encode(&bytes) != encoded
        || nq_protocol::sha256_bytes(&bytes) != source.reference.bytes_digest
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable,
            format!("{slot} authenticated descriptor bytes were substituted"),
        ));
    }
    validate_production_identity_descriptor_bytes(expected, &bytes, slot)
}

fn validate_production_activation_seam(
    prepared: &PreparedGovernedInvocation,
    launch: &ValidatedRuntimeRecord,
    selected_witness: &RecordRef,
    witness: &ValidatedRuntimeRecord,
    subject: &IdentityRef,
    vantage: &IdentityRef,
) -> Result<(), NativeGovernedPreEffectRefusal> {
    let launch_value = launch.record().as_value();
    let activation_ref: RecordRef =
        serde_json::from_value(launch_value["activation_snapshot"].clone()).map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                error.to_string(),
            )
        })?;
    let activation = native_governed_record(
        prepared,
        &activation_ref,
        RuntimeSchema::RuntimeActivationV1,
    )?;
    let activation_value = activation.record().as_value();
    let relations = activation_value["relations"].as_object().ok_or_else(|| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
            "active production binding has no closed relation set",
        )
    })?;
    for (field, expected) in [("node_subject", subject), ("node_vantage", vantage)] {
        let relation_ref: RecordRef =
            serde_json::from_value(relations.get(field).cloned().ok_or_else(|| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                    format!("active production binding lacks {field}"),
                )
            })?)
            .map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                    error.to_string(),
                )
            })?;
        let relation =
            native_governed_record(prepared, &relation_ref, RuntimeSchema::HostRoleRelationV1)?;
        if relation.record().as_value()["left"] != activation_value["node"]
            || relation.record().as_value()["right"]
                != serde_json::to_value(expected).map_err(|error| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                        error.to_string(),
                    )
                })?
        {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                format!("request target differs from exact active {field} relation"),
            ));
        }
    }
    let witness_value = witness.record().as_value();
    let selected_witness_value = serde_json::to_value(selected_witness).map_err(|error| {
        native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::WitnessBindingMismatch,
            error.to_string(),
        )
    })?;
    if !activation_value["witness_attachments"]
        .as_array()
        .is_some_and(|attachments| attachments.contains(&selected_witness_value))
        || witness_value["node"] != activation_value["node"]
        || witness_value["role_manifest"] != activation_value["role_manifest"]
    {
        return Err(native_governed_refusal(
            NativeGovernedPreEffectRefusalCode::WitnessBindingMismatch,
            "selected witness is outside the exact active node/role topology",
        ));
    }
    validate_authenticated_production_descriptor(prepared.dependencies(), subject, "subject")?;
    validate_authenticated_production_descriptor(prepared.dependencies(), vantage, "vantage")
}

#[derive(Clone)]
struct DiagnosticEmissionBase {
    producer: DiagnosticProducerV1,
    request_id: DiagnosticRequestId,
    run_id: DiagnosticRunId,
    question: SemanticIdentityV1,
    subject: DiagnosticSubjectV1,
    profile: SemanticIdentityV1,
    profile_semantic_id: Sha256Digest,
    vantage: SemanticIdentityV1,
    state_model: SemanticIdentityV1,
    evaluator: SemanticIdentityV1,
    threshold_policy: SemanticIdentityV1,
    projection: DiagnosticProjectionV1,
    execution_clock: SemanticIdentityV1,
    started_at: DateTime<Utc>,
    attempt_interval: AcquisitionIntervalV2,
    capture_policy: SemanticIdentityV1,
    admission_rule: SemanticIdentityV1,
    normalization_rule: SemanticIdentityV1,
    selection_rule: SemanticIdentityV1,
    limitations: Vec<DiagnosticLimitationV1>,
    nonclaims: Vec<String>,
    expected_evaluator_artifact_digest: Sha256Digest,
    expected_profile_semantic_id: ProfileSemanticId,
    expected_instance_id: String,
    expected_scope: ScopeConfig,
    expected_vantage: VantageConfig,
}

impl DiagnosticEmissionBase {
    fn seal(
        self,
        inputs: DiagnosticInputAccountingV2,
        state_bindings: Vec<DiagnosticStateBindingV1>,
        claims: Vec<DiagnosticClaimV2>,
        primary_claim_id: Option<String>,
        outcome: DiagnosticOutcomeV2,
    ) -> Result<DiagnosticExecutionV2, EngineError> {
        // A run-only diagnostic completes at the independently retained
        // terminal acquisition boundary. Do not add a second unpersisted wall
        // clock sample that historical reopening could not reconstruct.
        let completed_at = self.attempt_interval.ended_at;
        let mut artifact = DiagnosticExecutionV2 {
            schema: DiagnosticExecutionSchemaV2::V2,
            artifact_id: DiagnosticArtifactId(nq_protocol::sha256_bytes(
                b"diagnostic-execution-artifact-placeholder",
            )),
            canonicalization: diagnostic_canonicalization_identity()
                .map_err(|error| EngineError::Canonical(error.to_string()))?,
            producer: self.producer,
            request_id: self.request_id,
            run_id: self.run_id,
            question: self.question,
            subject: self.subject,
            profile: self.profile,
            profile_semantic_id: self.profile_semantic_id,
            vantage: self.vantage,
            state_model: self.state_model,
            evaluator: self.evaluator,
            threshold_policy: self.threshold_policy,
            projection: self.projection,
            execution_clock: self.execution_clock,
            started_at: self.started_at,
            completed_at,
            attempt_interval: self.attempt_interval,
            inputs,
            state_bindings,
            claims,
            primary_claim_id,
            outcome,
            limitations: self.limitations,
            nonclaims: self.nonclaims,
        };
        artifact.artifact_id = artifact
            .computed_artifact_id()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        artifact
            .canonical_bytes()
            .map_err(|error| EngineError::Invariant(error.to_string()))?;
        Ok(artifact)
    }
}

#[derive(Clone)]
struct DiagnosticEmissionContext {
    producer: DiagnosticProducerV1,
    request_id: DiagnosticRequestId,
    run_id: DiagnosticRunId,
    question: SemanticIdentityV1,
    subject: DiagnosticSubjectV1,
    profile: SemanticIdentityV1,
    profile_semantic_id: Sha256Digest,
    vantage: SemanticIdentityV1,
    state_model: SemanticIdentityV1,
    evaluator: SemanticIdentityV1,
    threshold_policy: SemanticIdentityV1,
    projection: DiagnosticProjectionV1,
    execution_clock: SemanticIdentityV1,
    started_at: DateTime<Utc>,
    attempt_interval: AcquisitionIntervalV2,
    inputs: DiagnosticInputAccountingV2,
    state_bindings: Vec<DiagnosticStateBindingV1>,
    limitations: Vec<DiagnosticLimitationV1>,
    nonclaims: Vec<String>,
    expected_evaluator_artifact_digest: Sha256Digest,
    expected_profile_semantic_id: ProfileSemanticId,
    expected_instance_id: String,
    expected_scope: ScopeConfig,
    expected_vantage: VantageConfig,
    report_id: String,
    report_complete: bool,
}

impl DiagnosticEmissionContext {
    #[allow(clippy::too_many_lines)]
    fn finish(
        &self,
        evaluation: &EvaluationEnvelopeV2,
        detector_reports: &[DetectorReport],
    ) -> Result<DiagnosticExecutionV2, EngineError> {
        if evaluation.detector.id != self.question.id
            || evaluation.detector.version != self.question.version
            || evaluation.detector.digest != self.question.digest.as_str()
            || evaluation.evaluator_artifact_digest != self.expected_evaluator_artifact_digest
            || evaluation.profile.profile.id != self.profile.id
            || evaluation.profile.profile.version.to_string() != self.profile.version
            || evaluation.profile.profile_digest.as_str() != self.profile.digest.as_str()
            || evaluation.profile.profile_semantic_id != self.expected_profile_semantic_id
            || evaluation.result.profile != evaluation.profile
            || evaluation.context.instance_id != self.expected_instance_id
            || evaluation.context.subject != self.subject.id
            || evaluation.context.scope != self.expected_scope
            || evaluation.context.vantage != self.expected_vantage
            || evaluation.trigger_run_id.as_deref() != Some(self.run_id.as_str())
            || evaluation.watermark.instance_id != self.expected_instance_id
            || evaluation.watermark.max_report_sequence == 0
            || evaluation.result.watermark.0 != evaluation.watermark.max_report_sequence
        {
            return Err(EngineError::Invariant(
                "prepared evaluation differs from the diagnostic emission context".into(),
            ));
        }

        let [detector_report] = detector_reports else {
            return Err(EngineError::Invariant(
                "diagnostic execution requires exactly one detector input report".into(),
            ));
        };
        if detector_report.report_id != self.report_id
            || detector_report.report_sequence != evaluation.watermark.max_report_sequence
        {
            return Err(EngineError::Invariant(
                "detector input occurrence differs from the diagnostic emission context".into(),
            ));
        }
        if detector_report.report.observed_at < self.attempt_interval.started_at
            || detector_report.report.observed_at > self.attempt_interval.ended_at
            || detector_report
                .report
                .observations
                .iter()
                .any(|observation| {
                    observation.observed_at < self.attempt_interval.started_at
                        || observation.observed_at > self.attempt_interval.ended_at
                })
        {
            return Err(EngineError::DiagnosticUnsupported(
                "source observation time is not bounded by the NQ-owned helper execution interval"
                    .into(),
            ));
        }

        let report_sequence = evaluation.watermark.max_report_sequence;
        let projection_document = canonical(&json!({
            "schema": "nq.detector_input_projection.v1",
            "instance_id": evaluation.context.instance_id,
            "evaluated_at": evaluation.evaluated_at,
            "watermark": report_sequence,
            "reports": [{
                "report_id": self.report_id,
                "report_sequence": report_sequence,
                "report": detector_report.report,
            }],
        }))?;
        let projected_artifact_id =
            ProjectedArtifactId(nq_protocol::sha256_bytes(projection_document.as_bytes()));
        let mut inputs = self.inputs.clone();
        let [admitted] = inputs.admitted.as_mut_slice() else {
            return Err(EngineError::Invariant(
                "diagnostic input accounting does not have exactly one admitted input".into(),
            ));
        };
        admitted.projected_artifact_id = projected_artifact_id.clone();
        let [selected] = inputs.selected.as_mut_slice() else {
            return Err(EngineError::Invariant(
                "diagnostic input accounting does not have exactly one selected input".into(),
            ));
        };
        selected.projected_artifact_id = projected_artifact_id;

        if matches!(
            evaluation.result.state,
            DetectorState::Present | DetectorState::ExplicitlyAbsent
        ) && (evaluation.result.evidence.is_empty()
            || evaluation.result.evidence.iter().any(|evidence| {
                evidence.report_id != self.report_id
                    || evidence.report_sequence != report_sequence
                    || evidence.report_digest != detector_report.report.report_digest
                    || match evidence.observation_ordinal {
                        Some(ordinal) => {
                            !detector_report
                                .report
                                .observations
                                .iter()
                                .any(|observation| {
                                    observation.ordinal == ordinal
                                        && timestamp(observation.observed_at)
                                            == timestamp(evidence.observed_at)
                                })
                        }
                        None => {
                            timestamp(detector_report.report.observed_at)
                                != timestamp(evidence.observed_at)
                        }
                    }
            }))
        {
            return Err(EngineError::Invariant(
                "determinate diagnostic evidence differs from the exact detector input".into(),
            ));
        }
        let (claims, primary_claim_id, outcome) = diagnostic_result_from_evaluation(
            evaluation,
            &inputs,
            &self.state_bindings,
            self.report_complete,
        )?;

        // The detector evaluation is the bounded semantic completion event.
        // Its exact time is already independently retained with the evaluation;
        // a later sealing-clock sample would be producer-self-asserted and
        // impossible to reconstruct on historical reopening.
        let completed_at = evaluation.evaluated_at;
        let mut artifact = DiagnosticExecutionV2 {
            schema: DiagnosticExecutionSchemaV2::V2,
            artifact_id: DiagnosticArtifactId(nq_protocol::sha256_bytes(
                b"diagnostic-execution-artifact-placeholder",
            )),
            canonicalization: diagnostic_canonicalization_identity()
                .map_err(|error| EngineError::Canonical(error.to_string()))?,
            producer: self.producer.clone(),
            request_id: self.request_id.clone(),
            run_id: self.run_id.clone(),
            question: self.question.clone(),
            subject: self.subject.clone(),
            profile: self.profile.clone(),
            profile_semantic_id: self.profile_semantic_id.clone(),
            vantage: self.vantage.clone(),
            state_model: self.state_model.clone(),
            evaluator: self.evaluator.clone(),
            threshold_policy: self.threshold_policy.clone(),
            projection: self.projection.clone(),
            execution_clock: self.execution_clock.clone(),
            started_at: self.started_at,
            completed_at,
            attempt_interval: self.attempt_interval.clone(),
            inputs,
            state_bindings: self.state_bindings.clone(),
            claims,
            primary_claim_id,
            outcome,
            limitations: self.limitations.clone(),
            nonclaims: self.nonclaims.clone(),
        };
        artifact.artifact_id = artifact
            .computed_artifact_id()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        artifact
            .canonical_bytes()
            .map_err(|error| EngineError::Invariant(error.to_string()))?;
        Ok(artifact)
    }
}

fn diagnostic_result_from_evaluation(
    evaluation: &EvaluationEnvelopeV2,
    inputs: &DiagnosticInputAccountingV2,
    state_bindings: &[DiagnosticStateBindingV1],
    report_complete: bool,
) -> Result<(Vec<DiagnosticClaimV2>, Option<String>, DiagnosticOutcomeV2), EngineError> {
    match evaluation.result.state {
        DetectorState::Present | DetectorState::ExplicitlyAbsent => {
            if !report_complete {
                return Err(EngineError::Invariant(
                    "determinate diagnostic result came from incomplete report coverage".into(),
                ));
            }
            let condition = match evaluation.result.state {
                DetectorState::Present => DiagnosticConditionV1::Present,
                DetectorState::ExplicitlyAbsent => DiagnosticConditionV1::ExplicitlyAbsent,
                DetectorState::CannotEvaluate => unreachable!(),
            };
            let claim_id = format!("claim:{}", evaluation.result.condition);
            let mut claim_limitations = evaluation.result.limitations.clone();
            claim_limitations.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            claim_limitations.dedup();
            let mut claim_nonclaims = vec![
                "the causal source of the bounded condition is not established".to_owned(),
                "the host boot or deployment generation is not established".to_owned(),
            ];
            claim_nonclaims.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            let claim = DiagnosticClaimV2 {
                claim_id: claim_id.clone(),
                proposition: match condition {
                    DiagnosticConditionV1::Present => {
                        format!(
                            "bounded condition {} is present",
                            evaluation.result.condition
                        )
                    }
                    DiagnosticConditionV1::ExplicitlyAbsent => format!(
                        "bounded condition {} is explicitly absent",
                        evaluation.result.condition
                    ),
                    _ => unreachable!(),
                },
                status: DiagnosticClaimStatusV1::Established,
                condition_effect: Some(condition),
                dependency_input_ids: inputs
                    .selected
                    .iter()
                    .map(|input| input.input_id.clone())
                    .collect(),
                dependency_refusal_ids: Vec::new(),
                dependency_failure_ids: Vec::new(),
                state_binding_ids: state_bindings
                    .iter()
                    .map(|binding| binding.binding_id.clone())
                    .collect(),
                required_distinctions: vec!["subject_identity".to_owned()],
                limitations: claim_limitations,
                nonclaims: claim_nonclaims,
            };
            Ok((
                vec![claim],
                Some(claim_id),
                DiagnosticOutcomeV2 {
                    derivation: DiagnosticDerivationV1::Completed,
                    condition,
                    coherence: DiagnosticCoherenceV1::JointlyEstablished,
                    coverage: DiagnosticCoverageV1::Complete,
                    summary: evaluation.result.summary.clone(),
                    refusals: Vec::new(),
                    unsupported: Vec::new(),
                },
            ))
        }
        DetectorState::CannotEvaluate => {
            let refusal = evaluation.result.refusal.as_ref().ok_or_else(|| {
                EngineError::Invariant(
                    "cannot_evaluate diagnostic has no governed detector refusal".into(),
                )
            })?;
            let GovernedRefusalOrigin::Profile(_) = &refusal.origin else {
                return Err(EngineError::Invariant(
                    "cannot_evaluate diagnostic refusal is not profile-origin".into(),
                ));
            };
            Ok((
                Vec::new(),
                None,
                DiagnosticOutcomeV2 {
                    derivation: DiagnosticDerivationV1::Refused,
                    condition: DiagnosticConditionV1::Unresolved,
                    coherence: DiagnosticCoherenceV1::NotEvaluated,
                    coverage: DiagnosticCoverageV1::Partial,
                    summary: evaluation.result.summary.clone(),
                    refusals: vec![refusal.clone()],
                    unsupported: Vec::new(),
                },
            ))
        }
    }
}

struct BoundUnixRunner {
    binding_digest: Option<String>,
    runner: UnixRunner,
}

/// The result of verifying a historical admitted report.
///
/// Its existence is the verdict: verification confirmed that the admission was
/// validly made and its stored judgment is intact, under a current evaluator
/// whose identity matches the admitted one. It may carry recorded ambient
/// observations that qualify the *present* context without altering the
/// *historical* verdict. Verification never re-evaluates and never mutates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReportVerification {
    /// The verified admitted report.
    pub report_id: String,
    /// The admission whose context the report was verified against.
    pub admission_id: String,
    /// The instance both belong to.
    pub instance_id: String,
    /// Recorded ambient observations that qualify the present context.
    pub platform_observations: Vec<PlatformObservation>,
}

/// A recorded ambient-drift observation. It qualifies the context in which a
/// historical admission is inspected; it does not refuse or reinterpret it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformObservation {
    /// The platform runtime version (kernel release) differs from admission
    /// time. Recorded context only — a kernel upgrade does not invalidate a
    /// prior admission, whose identity deliberately excludes the kernel.
    RuntimeDrift {
        /// The platform runtime version recorded at admission.
        admitted: String,
        /// The platform runtime version observed now.
        current: String,
    },
}

/// Why verification refused. Each variant preserves the specific reason rather
/// than flattening every mismatch into "digest changed"; none of them mutate the
/// store or re-run the evaluator.
#[derive(Debug, Error)]
pub enum VerificationRefusal {
    /// The stored admission snapshot failed authentication (corruption,
    /// substitution, broken binding, or an unsupported judgment schema).
    #[error("stored admission snapshot failed authentication: {0}")]
    SnapshotUnauthenticated(#[from] nq_store::SnapshotVerificationError),
    /// The current evaluator identity could not be observed, so drift cannot be
    /// assessed. Fails closed.
    #[error("current evaluator identity is unverifiable: {0}")]
    CurrentIdentityUnverifiable(String),
    /// The identity-observation method changed, so the admitted and current
    /// artifact digests are not comparable.
    #[error("evaluator identity method changed: admitted {admitted}, current {current}")]
    MethodIncompatible {
        /// The identity-observation method recorded at admission.
        admitted: String,
        /// The identity-observation method in effect now.
        current: String,
    },
    /// The running evaluator artifact differs from the admitted one.
    #[error("evaluator artifact drift: admitted {admitted}, current {current}")]
    EvaluatorArtifactDrift {
        /// The evaluator artifact digest recorded at admission.
        admitted: String,
        /// The evaluator artifact digest observed now.
        current: String,
    },
}

impl CollectionEngine {
    /// Open an initialized exactly compatible store and resolve the running
    /// evaluator's identity from the platform provider.
    ///
    /// Identity enters the engine only here and only from the provider — there
    /// is no caller-supplied identity, no provider parameter, and no public
    /// constructor for [`EvaluatorRuntimeIdentity`]. On an unsupported or
    /// unverifiable platform the identity resolves to a structured refusal and
    /// admission and collection fail closed.
    ///
    /// # Errors
    ///
    /// Returns a version, integrity, or database-opening error.
    pub fn open(config: &NqConfig) -> Result<Self, EngineError> {
        let mut store = Store::open(&config.database_path)?;
        let startup_projection_recovery = store
            .begin_writer_session()?
            .recover_pending_governed_projections()?;
        validate_provider_intake_history(&store)?;
        validate_diagnostic_artifact_history(&mut store)?;
        Ok(Self {
            config: config.clone(),
            store,
            startup_projection_recovery,
            admission: AdmissionManager,
            runner: StdioRunner,
            unix_runners: BTreeMap::new(),
            evaluator_identity: crate::evaluator_identity::resolved(),
        })
    }

    /// Test-only constructor that installs a specific evaluator identity (or a
    /// refusal) without consulting the platform provider. Gated on `cfg(test)`
    /// so no shipping binary and no downstream crate can reach it.
    #[cfg(test)]
    pub(crate) fn open_with_evaluator_identity(
        config: &NqConfig,
        evaluator_identity: Result<EvaluatorRuntimeIdentity, String>,
    ) -> Result<Self, EngineError> {
        let mut store = Store::open(&config.database_path)?;
        let startup_projection_recovery = store
            .begin_writer_session()?
            .recover_pending_governed_projections()?;
        validate_provider_intake_history(&store)?;
        validate_diagnostic_artifact_history(&mut store)?;
        Ok(Self {
            config: config.clone(),
            store,
            startup_projection_recovery,
            admission: AdmissionManager,
            runner: StdioRunner,
            unix_runners: BTreeMap::new(),
            evaluator_identity,
        })
    }

    /// Exact Store-owned projection recoveries attempted while this execution
    /// runtime opened.
    ///
    /// This is startup custody state, not a diagnostic result.  Unavailable or
    /// corrupt capsules remain durably inspectable through the custody
    /// inventory and never become successful projections.
    #[must_use]
    pub fn startup_projection_recovery(&self) -> &[nq_store::GovernedProjectionRecovery] {
        &self.startup_projection_recovery
    }

    /// The running evaluator identity, or a typed refusal carrying the exact
    /// reason it could not be established.
    fn require_evaluator_identity(&self) -> Result<&EvaluatorRuntimeIdentity, EngineError> {
        self.evaluator_identity.as_ref().map_err(|reason| {
            EngineError::Invariant(format!("evaluator runtime identity unavailable: {reason}"))
        })
    }

    /// Assemble the full, typed admission-context identity. Every constituent
    /// except the running evaluator artifact is derived here from the profile,
    /// the compiled evaluator source, or the admission lock; the store computes
    /// `admission_context_digest` from the result.
    fn admission_identity(
        &self,
        profile: &'static dyn ProfileModule,
        lock: &AdmissionLock,
    ) -> Result<AdmissionIdentity, EngineError> {
        let evaluator = self.require_evaluator_identity()?;
        let profile_semantic = profile_semantic_id(profile.descriptor())
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        Ok(AdmissionIdentity {
            profile_semantic_id: parse_identity_digest(
                "profile_semantic_id",
                profile_semantic.as_str(),
            )?,
            detector_identity_digest: detector_identity_digest(profile)?,
            evaluator_source_digest: parse_identity_digest(
                "evaluator_source_digest",
                EVALUATOR_SOURCE_DIGEST,
            )?,
            evaluator_artifact_digest: evaluator.artifact_digest().clone(),
            helper_artifact_digest: parse_identity_digest(
                "helper_artifact_digest",
                &lock.execution.sha256,
            )?,
            config_digest: parse_identity_digest("config_digest", &lock.config_digest)?,
            protocol_version: lock.protocol_version.clone(),
            target_triple: evaluator.target_triple().to_owned(),
            artifact_identity_method: evaluator.artifact_identity_method().to_owned(),
            platform_runtime_version: evaluator.platform_runtime_version().to_owned(),
        })
    }

    /// Seal the live local-helper provider from the independently verified
    /// admission, retained executable descriptors, durable admission context,
    /// compiled profile semantics, and current evaluator identity. Provider
    /// response fields do not participate in this construction.
    fn verified_local_provider(
        &self,
        profile: &'static dyn ProfileModule,
        lock: &AdmissionLock,
        verification: &crate::admission::AdmissionVerification,
        execution: &ExecutionIdentity,
    ) -> Result<VerifiedProvider, EngineError> {
        let durable = self.store.admission(&lock.admission_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "active provider admission {} has no durable admission record",
                lock.admission_id
            ))
        })?;
        let provider_admission = self
            .store
            .provider_admission_for_source(&lock.admission_id)?
            .ok_or_else(|| {
                EngineError::Invariant(format!(
                    "helper admission {} has no distinct derived provider admission",
                    lock.admission_id
                ))
            })?;
        let semantic = profile_semantic_id(profile.descriptor())
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        if durable.instance_id != lock.instance_id
            || durable.config_digest != lock.config_digest
            || durable.helper_artifact_digest != execution.sha256
            || durable.profile_id != lock.profile.id
            || durable.profile_version != lock.profile.version.to_string()
            || durable.profile_digest != lock.profile.digest
            || durable.profile_semantic_id != semantic.as_str()
            || durable.protocol_version != lock.protocol_version
            || durable.lock_json != canonical(lock)?.as_bytes()
        {
            return Err(EngineError::Invariant(format!(
                "active provider admission {} differs from its durable identity or semantics",
                lock.admission_id
            )));
        }
        VerifiedProvider::local_helper(
            lock,
            verification,
            execution,
            &semantic,
            parse_identity_digest(
                "admission evaluator artifact digest",
                &durable.evaluator_artifact_digest,
            )?,
            &durable.admission_context_digest,
            &provider_admission,
        )
        .map_err(EngineError::from)
    }

    fn resolve_governed_conformance_watcher(
        &self,
        provider_admission_ref: &RecordRef,
    ) -> Result<
        (
            WatcherConfig,
            AdmissionLock,
            nq_store::LocalProviderAdmissionRow,
        ),
        NativeGovernedPreEffectRefusal,
    > {
        let mut matching = Vec::new();
        for watcher in &self.config.watchers {
            let Some(lock) = self.authoritative_active_lock(watcher).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::WatcherResolutionFailed,
                    error.to_string(),
                )
            })?
            else {
                continue;
            };
            let Some(provider_admission) = self
                .store
                .provider_admission_for_source(&lock.admission_id)
                .map_err(|error| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::ProviderAdmissionMismatch,
                        error.to_string(),
                    )
                })?
            else {
                continue;
            };
            if provider_admission_ref.schema.as_str() == nq_store::LOCAL_PROVIDER_ADMISSION_SCHEMA
                && provider_admission_ref.record_id.as_str()
                    == provider_admission.provider_admission_id
                && provider_admission_ref.bytes_digest.as_str()
                    == provider_admission.contract_digest
            {
                matching.push((watcher.clone(), lock, provider_admission));
            }
        }
        let [matching] = matching.as_mut_slice() else {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::WatcherResolutionFailed,
                format!(
                    "selected provider admission {} resolves to {} active configured watchers",
                    provider_admission_ref.record_id,
                    matching.len()
                ),
            ));
        };
        Ok((matching.0.clone(), matching.1.clone(), matching.2.clone()))
    }

    #[allow(clippy::too_many_lines)]
    fn check_native_governed_pre_effects(
        &self,
        prepared: &PreparedGovernedInvocation,
    ) -> Result<NativeGovernedPreEffectCandidate, NativeGovernedPreEffectRefusal> {
        // `PreparedGovernedInvocation` is an opaque, non-deserializable token
        // issued only after the runtime validates the complete graph against
        // every checkpoint's historical dependency generation. Core must not
        // revalidate that historical graph under only the current generation.
        // It independently rechecks the exact selected native seam below.
        validate_prepared_dependency_custody(prepared)?;
        let request = native_governed_record(
            prepared,
            prepared.outer_request(),
            RuntimeSchema::DiagnosticInvocationRequestV1,
        )?;
        let launch = native_governed_record(
            prepared,
            prepared.execution_launch(),
            RuntimeSchema::ExecutionLaunchV1,
        )?;
        let request_value = request.record().as_value();
        let launch_value = launch.record().as_value();
        if request_value["request_id"].as_str() != Some(prepared.request_id())
            || launch_value["outer_request"]
                != serde_json::to_value(prepared.outer_request()).map_err(|error| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::OuterRequestSubstitution,
                        error.to_string(),
                    )
                })?
        {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::OuterRequestSubstitution,
                "outer request identity or exact launch occurrence differs from the opaque prepared token",
            ));
        }

        let production = prepared.production_identity();
        let request_node: IdentityRef =
            serde_json::from_value(request_value["target"]["node"].clone()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                    error.to_string(),
                )
            })?;
        let request_subject: IdentityRef = serde_json::from_value(
            request_value["target"]["subject"].clone(),
        )
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                error.to_string(),
            )
        })?;
        let request_vantage: IdentityRef = serde_json::from_value(
            request_value["target"]["vantage"].clone(),
        )
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                error.to_string(),
            )
        })?;
        if &request_node != production.node()
            || &request_subject != production.subject()
            || &request_vantage != production.vantage()
        {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProductionIdentitySubstitution,
                "request and opaque prepared token do not bind one node/subject/vantage occurrence",
            ));
        }

        let (selected_witness, witness) = selected_governed_witness(prepared, launch)?;
        let witness_value = witness.record().as_value();
        if witness_value["node"]
            != serde_json::to_value(production.node()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::WitnessBindingMismatch,
                    error.to_string(),
                )
            })?
        {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::WitnessBindingMismatch,
                "selected witness is not attached to the prepared node",
            ));
        }
        validate_production_activation_seam(
            prepared,
            launch,
            &selected_witness,
            witness,
            &request_subject,
            &request_vantage,
        )?;
        require_effective_node_and_key_authority(prepared)?;

        let launched_at = native_timestamp(launch_value, "launched_at")?;

        let requested_profile: IdentityRef =
            serde_json::from_value(request_value["profile"].clone()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProfileIncompatible,
                    error.to_string(),
                )
            })?;
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let profile_digest = profile.descriptor().digest().map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProfileIncompatible,
                error.to_string(),
            )
        })?;
        if requested_profile.kind != IdentityKind::DiagnosticProfile
            || launch_value["profile"] != request_value["profile"]
            || witness_value["supported_profiles"]
                .as_array()
                .is_none_or(|profiles: &Vec<Value>| {
                    profiles.len() != 1 || profiles[0] != request_value["profile"]
                })
        {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProfileIncompatible,
                "request, launch, selected witness, and compiled nq.conformance/v1 do not name one exact profile",
            ));
        }
        validate_authenticated_production_descriptor(
            prepared.dependencies(),
            &requested_profile,
            "diagnostic_profile",
        )?;
        conformance_attachment_has_zero_access(witness_value)?;

        let declared_provider: IdentityRef =
            serde_json::from_value(witness_value["provider"].clone()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProviderIdentityMismatch,
                    error.to_string(),
                )
            })?;
        let declared_build: IdentityRef =
            serde_json::from_value(witness_value["provider_build"].clone()).map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProviderIdentityMismatch,
                    error.to_string(),
                )
            })?;
        validate_authenticated_production_descriptor(
            prepared.dependencies(),
            &declared_provider,
            "provider",
        )?;
        validate_authenticated_production_descriptor(
            prepared.dependencies(),
            &declared_build,
            "provider_build",
        )?;

        let provider_admission_ref: RecordRef = serde_json::from_value(
            witness_value["provider_admission"].clone(),
        )
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProviderAdmissionMismatch,
                error.to_string(),
            )
        })?;
        let (watcher, active_lock, provider_admission) =
            self.resolve_governed_conformance_watcher(&provider_admission_ref)?;
        if watcher.profile.id != nq_profiles::conformance::PROFILE_ID
            || watcher.profile.version != nq_profiles::conformance::PROFILE_VERSION
            || watcher.carrier != Carrier::Stdio
            || watcher.checkpoint_policy != CheckpointPolicy::Disabled
            || !watcher.capability_ceiling.is_empty()
            || !active_lock.granted_capabilities.is_empty()
            || !profile.descriptor().capabilities.is_empty()
        {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::AccessSurfaceNotEmpty,
                "resolved conformance watcher/profile/lock has a mismatched profile, subject, carrier, checkpoint, or nonempty capability surface",
            ));
        }
        validate_native_profile_correspondence(
            &requested_profile,
            &provider_admission_ref,
            &active_lock,
            profile,
        )?;
        let evaluator = self.require_evaluator_identity().map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable,
                error.to_string(),
            )
        })?;
        let launch_correspondence =
            require_typed_profile_qualification(prepared, &requested_profile, profile, evaluator)?;

        let maximum_execution_ms =
            launch_value["maximum_execution_ms"]
                .as_u64()
                .ok_or_else(|| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                        "launch maximum execution budget is absent",
                    )
                })?;
        if maximum_execution_ms > watcher.invocation.deadline_ms {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                "outer launch execution budget broadens the exact admitted watcher maximum",
            ));
        }
        let request_clock: IdentityRef = serde_json::from_value(
            request_value["time_bounds"]["clock"].clone(),
        )
        .map_err(|error| {
            native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                error.to_string(),
            )
        })?;
        let launch_clock: IdentityRef = serde_json::from_value(launch_value["clock"].clone())
            .map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                    error.to_string(),
                )
            })?;
        validate_authenticated_production_descriptor(
            prepared.dependencies(),
            &request_clock,
            "clock",
        )?;
        let remaining_budget =
            require_native_clock_correspondence(prepared, &launch_correspondence, &request_clock)?;
        let not_before = native_timestamp(&request_value["time_bounds"], "not_before")?;
        let request_deadline = native_timestamp(&request_value["time_bounds"], "deadline")?;
        let attempt_deadline = native_timestamp(launch_value, "attempt_deadline")?;
        validate_governed_occurrence_window(
            &request_clock,
            &launch_clock,
            not_before,
            request_deadline,
            launched_at,
            attempt_deadline,
        )?;
        if remaining_budget > StdDuration::from_millis(maximum_execution_ms) {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                "runtime-owned remaining CLOCK_BOOTTIME window exceeds the exact launch maximum",
            ));
        }

        let verified_launch =
            VerifiedLaunch::open_expected(&watcher.command, &active_lock.execution).map_err(
                |error| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::LaunchQualificationFailed,
                        error.to_string(),
                    )
                },
            )?;
        let admission_verification = self
            .admission
            .verify_opened_execution(
                &watcher,
                &active_lock,
                profile_digest.as_str(),
                nq_protocol::HELPER_PROTOCOL_VERSION,
                verified_launch.identity(),
            )
            .map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ActiveAdmissionMismatch,
                    error.to_string(),
                )
            })?;
        let verified_provider = self
            .verified_local_provider(
                profile,
                &active_lock,
                &admission_verification,
                verified_launch.identity(),
            )
            .map_err(|error| {
                native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::ProviderIdentityMismatch,
                    error.to_string(),
                )
            })?;
        validate_exact_provider_admission(
            &provider_admission_ref,
            &provider_admission,
            &verified_provider.identity().provider_admission_id,
        )?;
        let provider_identity = verified_provider.identity();
        if declared_provider.kind != IdentityKind::Provider
            || declared_build.kind != IdentityKind::Build
            || provider_identity.kind != ProviderKind::LocalHelper
        {
            return Err(native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::ProviderIdentityMismatch,
                "attachment provider/build kinds or NQ's independently derived provider kind are incompatible",
            ));
        }

        let child_request_id =
            native_child_request_id(prepared.request_id(), prepared.execution_launch())?;
        let native_request = exact_conformance_native_request(
            &watcher,
            profile,
            child_request_id,
            prepared
                .native_deadline()
                .ok_or_else(|| {
                    native_governed_refusal(
                        NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
                        "runtime-owned native deadline provenance disappeared after qualification",
                    )
                })?
                .boottime_expiry_ns(),
        )?;
        let provider_attempt = native_governed_provider_attempt_plan(
            prepared,
            &watcher,
            &active_lock,
            &admission_verification,
            profile_digest.as_str(),
            &native_request,
            &verified_provider,
        )?;
        let artifact_context = governed_conformance_artifact_context(
            prepared,
            &launch_correspondence,
            &requested_profile,
            &request_clock,
            &native_request,
            &provider_attempt,
            evaluator,
            launched_at,
        )?;
        let artifact_capacity = require_native_custody_correspondence(
            &self.store,
            prepared,
            &watcher,
            &native_request,
            &verified_provider,
            &provider_attempt,
            &artifact_context,
        )?;
        Ok(NativeGovernedPreEffectCandidate {
            watcher,
            profile,
            active_lock,
            admission_verification,
            verified_launch,
            verified_provider,
            provider_admission,
            selected_witness,
            launch_correspondence,
            production_clock: request_clock,
            native_request,
            provider_attempt,
            artifact_context,
            artifact_capacity,
            absolute_deadline: attempt_deadline,
            remaining_budget,
        })
    }

    /// Private ownership transition from an opaque runtime occurrence into the
    /// pre-effect execution plan.
    ///
    /// Every check borrows the token first. Only the positive branch moves it
    /// into an execution plan; the negative branch retains it for exact
    /// terminal refusal custody. This method exposes no provider-spawn path.
    #[allow(dead_code)]
    fn plan_native_governed_conformance(
        &self,
        prepared: PreparedGovernedInvocation,
    ) -> NativeGovernedPreEffectOutcome {
        match self.check_native_governed_pre_effects(&prepared) {
            Ok(candidate) => {
                NativeGovernedPreEffectOutcome::Ready(Box::new(NativeGovernedExecutionPlan {
                    prepared,
                    candidate,
                }))
            }
            Err(refusal) => NativeGovernedPreEffectOutcome::Refused {
                prepared: Box::new(prepared),
                refusal,
            },
        }
    }

    /// Execute one already-prepared governed conformance request.
    ///
    /// The host-role runtime owns request/topology preparation and the one-use
    /// custody token. This method revalidates the exact native seam, performs
    /// one bounded local-helper effect, derives one zero-detector V2 artifact,
    /// commits its complete SQL/runtime projection, and reopens the immutable
    /// result. It neither schedules another request nor grants reliance,
    /// authorization, dispatch, or action authority.
    ///
    /// # Errors
    ///
    /// A pre-effect refusal first terminalizes the exact claimed launch. Any
    /// failure after provider dispatch but before complete closure likewise
    /// records a protected postlaunch terminal. Once final custody is sealed,
    /// a later SQL/index error leaves the occurrence explicitly index-pending
    /// for recovery and never reruns the provider.
    pub fn execute_prepared_governed_conformance(
        &mut self,
        prepared: PreparedGovernedInvocation,
    ) -> Result<DiagnosticExecutionV2, EngineError> {
        self.execute_prepared_governed_conformance_inner(
            prepared,
            GovernedProjectionFailpoint::None,
        )
    }

    #[cfg(test)]
    fn execute_prepared_governed_conformance_with_failpoint(
        &mut self,
        prepared: PreparedGovernedInvocation,
        failpoint: GovernedProjectionFailpoint,
    ) -> Result<DiagnosticExecutionV2, EngineError> {
        self.execute_prepared_governed_conformance_inner(prepared, failpoint)
    }

    fn execute_prepared_governed_conformance_inner(
        &mut self,
        prepared: PreparedGovernedInvocation,
        failpoint: GovernedProjectionFailpoint,
    ) -> Result<DiagnosticExecutionV2, EngineError> {
        match self.plan_native_governed_conformance(prepared) {
            NativeGovernedPreEffectOutcome::Ready(plan) => {
                self.execute_native_governed_conformance_plan(*plan, failpoint)
            }
            NativeGovernedPreEffectOutcome::Refused {
                mut prepared,
                refusal,
            } => {
                let mut session = self.store.begin_writer_session()?;
                Err(terminalize_native_pre_effect_refusal(
                    &mut session,
                    &mut prepared,
                    refusal,
                ))
            }
        }
    }

    // The `&mut after_final_seal` reborrow at each publication attempt is
    // load-bearing: the Store takes the callback as a by-value `FnOnce`
    // generic, and the recovery-retry loop below must be able to publish
    // again after `GovernedProjectionRecoveryRequired`. Passing the closure
    // itself would move it on the first attempt.
    #[allow(clippy::too_many_lines, clippy::needless_borrows_for_generic_args)]
    fn execute_native_governed_conformance_plan(
        &mut self,
        plan: NativeGovernedExecutionPlan,
        failpoint: GovernedProjectionFailpoint,
    ) -> Result<DiagnosticExecutionV2, EngineError> {
        let NativeGovernedExecutionPlan {
            mut prepared,
            candidate,
        } = plan;
        let NativeGovernedPreEffectCandidate {
            watcher,
            profile,
            active_lock,
            admission_verification,
            verified_launch,
            verified_provider,
            provider_admission: _provider_admission,
            selected_witness: _selected_witness,
            launch_correspondence,
            production_clock,
            native_request,
            provider_attempt,
            artifact_context,
            artifact_capacity,
            absolute_deadline,
            remaining_budget,
        } = candidate;

        let fresh_remaining = match require_native_clock_correspondence(
            &prepared,
            &launch_correspondence,
            &production_clock,
        ) {
            Ok(remaining) if remaining <= remaining_budget => remaining,
            Ok(_) => {
                let refusal = native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeClockCorrespondenceUnavailable,
                    "the runtime-owned monotonic execution window widened after pre-effect qualification",
                );
                return Err({
                        let mut session = self.store.begin_writer_session()?;
                        terminalize_native_pre_effect_refusal(&mut session, &mut prepared, refusal)
                    });
            }
            Err(refusal) => {
                return Err({
                        let mut session = self.store.begin_writer_session()?;
                        terminalize_native_pre_effect_refusal(&mut session, &mut prepared, refusal)
                    });
            }
        };
        if fresh_remaining > StdDuration::from_millis(watcher.invocation.deadline_ms) {
            let refusal = native_governed_refusal(
                NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                "the final runtime-owned watchdog broadens the admitted watcher deadline",
            );
            return Err({
                    let mut session = self.store.begin_writer_session()?;
                    terminalize_native_pre_effect_refusal(&mut session, &mut prepared, refusal)
                });
        }

        match self.store.provider_intake(&provider_attempt.intake_id) {
            Ok(None) => {}
            Ok(Some(_)) => {
                let refusal = native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
                    "the exact governed provider-intake occurrence already exists; provider replay is forbidden",
                );
                return Err({
                        let mut session = self.store.begin_writer_session()?;
                        terminalize_native_pre_effect_refusal(&mut session, &mut prepared, refusal)
                    });
            }
            Err(error) => {
                let refusal = native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
                    error.to_string(),
                );
                return Err({
                        let mut session = self.store.begin_writer_session()?;
                        terminalize_native_pre_effect_refusal(&mut session, &mut prepared, refusal)
                    });
            }
        }

        let request_json = match nq_protocol::canonical_json_bytes(&native_request) {
            Ok(bytes) => bytes,
            Err(error) => {
                let refusal = native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
                    error.to_string(),
                );
                return Err({
                        let mut session = self.store.begin_writer_session()?;
                        terminalize_native_pre_effect_refusal(&mut session, &mut prepared, refusal)
                    });
            }
        };
        let evaluator_artifact_digest = verified_provider
            .identity()
            .evaluator_artifact_digest
            .clone();
        let native_boottime_expiry_ns = native_request.deadline.expires_at_ns;
        let attempt = match ProviderAttempt::new_governed(
            provider_attempt.intake_id.clone(),
            provider_attempt.attempt_id.clone(),
            provider_attempt.run_id.clone(),
            native_request,
            verified_provider,
            provider_attempt.origin_carrier.clone(),
            absolute_deadline,
            provider_attempt.checkpoint_contract_digest.as_str(),
        ) {
            Ok(attempt) => attempt,
            Err(error) => {
                let refusal = native_governed_refusal(
                    NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable,
                    error.to_string(),
                );
                return Err({
                        let mut session = self.store.begin_writer_session()?;
                        terminalize_native_pre_effect_refusal(&mut session, &mut prepared, refusal)
                    });
            }
        };

        // This is the only provider effect in the path. Every fallible step
        // below must either reach a complete final closure or terminalize this
        // exact launch as a postlaunch custody failure.
        let capture = StdioRunner::run_verified_until_boottime(
            &verified_launch,
            &request_json,
            native_boottime_expiry_ns,
            &watcher.resources,
        );
        let mut custody_session = self.store.begin_writer_session()?;
        macro_rules! postlaunch {
            ($stage:literal, $expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        return Err(terminalize_native_postlaunch_failure(
                            &mut custody_session,
                            &mut prepared,
                            $stage,
                            error,
                        ));
                    }
                }
            };
        }

        let intake = postlaunch!(
            "provider_intake",
            ProviderIntakeV1::from_capture(attempt, capture, &watcher.resources)
                .map_err(EngineError::from)
        );
        let run = postlaunch!(
            "run_projection",
            (|| {
                Ok::<_, EngineError>(RunInput {
                    run_id: provider_attempt.run_id.clone(),
                    request_id: intake.record().request_id.clone(),
                    instance_id: watcher.instance_id.clone(),
                    admission_id: Some(active_lock.admission_id.clone()),
                    binding_digest: admission_verification.binding_digest.clone(),
                    checkpoint_contract_digest: provider_attempt
                        .checkpoint_contract_digest
                        .to_string(),
                    profile_id: watcher.profile.id.clone(),
                    profile_version: watcher.profile.version.to_string(),
                    profile_digest: intake.record().request.profile.digest.to_string(),
                    carrier: intake.record().origin_carrier.clone(),
                    started_at: timestamp(intake.record().started_at),
                    deadline_at: deadline_timestamp(intake.record().deadline_at),
                    finished_at: timestamp(intake.record().finished_at),
                    acquisition_outcome: acquisition_code(&intake.record().native_outcome.outcome)
                        .to_owned(),
                    execution_identity: canonical(&active_lock.execution)?,
                    resource_outcome: canonical(&intake.record().native_outcome)?,
                })
            })()
        );
        let intake_input = postlaunch!(
            "provider_store_projection",
            intake.to_store_input(&run).map_err(EngineError::from)
        );
        let provider_record_id = postlaunch!(
            "provider_record_identity",
            nq_store::provider_intake_record_id(&intake_input).map_err(EngineError::from)
        );
        let exact_provider_intake_bytes = postlaunch!(
            "provider_record_canonicalization",
            nq_protocol::canonical_json_bytes(intake.record())
                .map_err(|error| EngineError::Canonical(error.to_string()))
        );
        let provider_intake_ref = postlaunch!(
            "provider_record_reference",
            (|| {
                Ok::<_, EngineError>(RecordRef {
                    schema: nq_host_role_contract::Token::parse(nq_store::PROVIDER_INTAKE_SCHEMA)
                        .map_err(|error| EngineError::Invariant(error.to_string()))?,
                    record_id: provider_record_id.clone(),
                    bytes_digest: nq_protocol::sha256_bytes(&exact_provider_intake_bytes),
                })
            })()
        );
        let provider_append = CustodyRecord::provider_intake(
            provider_record_id.to_string(),
            exact_provider_intake_bytes.clone(),
            timestamp(intake.record().received_at),
        );
        let sealed_acquisition = postlaunch!(
            "acquisition_custody",
            prepared
                .seal_acquisition(&mut custody_session, GovernedAcquisitionCustodyInput {
                    execution_launch_record_id: prepared.execution_launch().record_id.clone(),
                    provider_intake_record_id: provider_record_id.clone(),
                    exact_provider_intake_bytes: exact_provider_intake_bytes.clone(),
                    exact_raw_provider_bytes: intake.raw_bytes().to_vec(),
                })
                .map_err(EngineError::from)
        );
        if sealed_acquisition.execution_launch_record_id != prepared.execution_launch().record_id
            || sealed_acquisition.provider_intake_record_id != provider_record_id
            || sealed_acquisition.exact_provider_intake_bytes != exact_provider_intake_bytes
            || sealed_acquisition.exact_raw_provider_bytes != intake.raw_bytes()
        {
            return Err(terminalize_native_postlaunch_failure(
                &mut custody_session,
                &mut prepared,
                "acquisition_reopen",
                EngineError::Invariant(
                    "reopened governed acquisition differs from the exact provider occurrence"
                        .to_owned(),
                ),
            ));
        }

        let GovernedConformanceDerivationV2 {
            artifact,
            persistence,
        } = postlaunch!(
            "diagnostic_derivation",
            derive_governed_conformance_v2(artifact_context, intake.record(), intake.raw_bytes(),)
        );
        let artifact_length = postlaunch!(
            "diagnostic_capacity",
            artifact
                .canonical_bytes()
                .map(|bytes| bytes.len())
                .map_err(|error| EngineError::Canonical(error.to_string()))
        );
        if u64::try_from(artifact_length)
            .ok()
            .is_none_or(|length| length > artifact_capacity.canonical_artifact_bytes)
        {
            return Err(terminalize_native_postlaunch_failure(
                &mut custody_session,
                &mut prepared,
                "diagnostic_capacity",
                EngineError::Invariant(
                    "actual governed diagnostic exceeds its exact pre-effect derived bound"
                        .to_owned(),
                ),
            ));
        }

        let execution_binding = postlaunch!(
            "execution_binding",
            construct_governed_execution_binding_v2(&prepared, &artifact, &provider_intake_ref,)
                .map_err(|error| EngineError::Invariant(error.to_string()))
        );
        let qualified = postlaunch!(
            "terminal_batch_qualification",
            prepared
                .qualify_final_batch(provider_append, execution_binding)
                .map_err(EngineError::from)
        );
        let derivation_claim = postlaunch!(
            "derivation_identity",
            construct_governed_derivation_claim(
                &artifact,
                &provider_intake_ref,
                prepared.execution_launch(),
                prepared.dependencies(),
                &evaluator_artifact_digest,
            )
        );
        postlaunch!(
            "derivation_custody",
            prepared
                .claim_derivation(&mut custody_session, derivation_claim.clone())
                .map_err(EngineError::from)
        );
        let projection = postlaunch!(
            "final_custody_projection",
            construct_governed_custody_projection_v2(
                &prepared,
                &qualified,
                &artifact,
                &provider_intake_ref,
                &intake.record().intake_id,
                &intake.record().raw_sha256,
                &derivation_claim,
            )
            .map_err(|error| EngineError::Invariant(error.to_string()))
        );
        let sql_plan = postlaunch!(
            "sql_projection_preparation",
            prepare_native_governed_sql_commit(
                &watcher,
                profile,
                intake.record(),
                intake_input,
                run,
                persistence,
            )
        );
        let reservation_record_id = prepared
            .custody_reservation_spec()
            .reservation_record_id
            .clone();
        let final_checkpoint_id = Sha256Digest::parse(qualified.batch().checkpoint_id.clone())
            .map_err(|error| EngineError::Invariant(error.to_string()))?;
        let diagnostic_commit = projection.diagnostic.clone();
        let capsule_capacity = prepared.projection_capsule_capacity_bytes();
        let mut projection = Some(projection);
        let mut sealed_closure_id = None;
        let expected_commitment = std::cell::RefCell::new(None);
        let mut build_final_closure =
            |publication: &nq_store::GovernedProjectionPublication| -> Result<Vec<u8>, EngineError> {
                let projection_capsule = GovernedProjectionCapsule::build(
                    &sql_plan.projection_capsule_input(
                        reservation_record_id.clone(),
                        diagnostic_commit.clone(),
                        publication.clone(),
                    ),
                )?;
                let projection = projection
                    .take()
                    .ok_or_else(|| {
                        EngineError::Invariant(
                            "governed projection pre-commit seal callback ran twice".into(),
                        )
                    })?
                    .bind_projection_capsule(projection_capsule, capsule_capacity)
                    .map_err(|error| EngineError::Invariant(error.to_string()))?;
                let closure_id = projection.closure.closure_id().clone();
                let exact_closure_bytes =
                    projection.closure.canonical_bytes().as_bytes().to_vec();
                let closure_digest = nq_protocol::sha256_bytes(&exact_closure_bytes);
                let closure_length = u64::try_from(exact_closure_bytes.len()).map_err(|_| {
                    EngineError::Invariant(
                        "governed final closure length exceeds the supported identity range"
                            .to_owned(),
                    )
                })?;
                *expected_commitment.borrow_mut() = Some((closure_digest, closure_length));
                sealed_closure_id = Some(closure_id);
                Ok(exact_closure_bytes)
            };
        let mut after_final_seal =
            |commitment: &nq_store::GovernedCustodyCommitment| -> Result<(), EngineError> {
                let expected = expected_commitment.borrow();
                let (closure_digest, closure_length) = expected.as_ref().ok_or_else(|| {
                    EngineError::Invariant(
                        "governed final closure commitment was checked before construction".into(),
                    )
                })?;
                if commitment.bytes_digest != *closure_digest
                    || commitment.byte_length != *closure_length
                {
                    return Err(EngineError::Invariant(
                        "sealed governed final closure reopened with different bytes".to_owned(),
                    ));
                }
                if failpoint == GovernedProjectionFailpoint::AfterFinalSealBeforeSql {
                    return Err(EngineError::Invariant(
                        "test failpoint: after final seal before SQL projection".into(),
                    ));
                }
                Ok(())
            };

        // SQL publication order is allocated first under one IMMEDIATE
        // transaction. Store then seals the exact capsule/final closure before
        // attempting any SQL row, while that same transaction owns the global
        // publication gate. Only after sealing succeeds may SQL insertion and
        // commit occur.
        let mut publish = || -> Result<CollectionOutcome, EngineError> {
            Ok(match &sql_plan {
                NativeGovernedSqlCommitPlan::Admitted {
                    collection,
                    outcome,
                    status,
                    expected_semantic_digest,
                } => {
                    let committed = custody_session
                        .commit_governed_admitted_run_level_diagnostic_with_publication(
                            collection,
                            |receipt| {
                                if receipt.semantic_digest.as_deref()
                                    != Some(expected_semantic_digest.as_str())
                                    || receipt.report_sequence.is_none()
                                {
                                    return Err(EngineError::Invariant(
                                "governed admitted receipt differs from the exact derived report"
                                    .to_owned(),
                            ));
                                }
                                Ok(nq_store::AdmittedRunLevelDiagnosticCompletion {
                                    value: outcome.clone(),
                                    diagnostic_artifact: diagnostic_commit.clone(),
                                    status: status.clone(),
                                })
                            },
                            prepared.store_projection_custody(),
                            &mut build_final_closure,
                            &mut after_final_seal,
                        )?;
                    match committed {
                        ProviderIntakeCommit::Committed { value, .. } => value,
                        ProviderIntakeCommit::Replayed {
                            canonical_result, ..
                        } => {
                            let reopened = decode_collection_outcome(canonical_result.as_bytes())?;
                            if &reopened != outcome {
                                return Err(EngineError::Invariant(
                                    "governed admitted replay resolved to another result"
                                        .to_owned(),
                                ));
                            }
                            reopened
                        }
                    }
                }
                NativeGovernedSqlCommitPlan::NonSuccess {
                    collection,
                    outcome,
                    result,
                } => {
                    let committed = custody_session
                        .commit_governed_non_success_run_level_diagnostic_with_publication(
                            collection,
                            result,
                            &diagnostic_commit,
                            prepared.store_projection_custody(),
                            &mut build_final_closure,
                            &mut after_final_seal,
                        )?;
                    match committed.intake {
                        ProviderIntakeCommit::Committed { .. } => outcome.clone(),
                        ProviderIntakeCommit::Replayed {
                            canonical_result, ..
                        } => {
                            let reopened = decode_collection_outcome(canonical_result.as_bytes())?;
                            if &reopened != outcome {
                                return Err(EngineError::Invariant(
                                    "governed non-success replay resolved to another result"
                                        .to_owned(),
                                ));
                            }
                            reopened
                        }
                    }
                }
            })
        };
        let stored_outcome = loop {
            match publish() {
                Ok(outcome) => break outcome,
                Err(EngineError::Store(
                    nq_store::StoreError::GovernedProjectionRecoveryRequired(_),
                )) => {
                    // The Store recovered an older exact pending projection
                    // while holding the global publication lock. Retry this
                    // already-derived plan; never invoke the provider again.
                }
                Err(error) => {
                    return Err(handle_native_governed_publication_failure(
                        &mut custody_session,
                        &mut prepared,
                        error,
                    ));
                }
            }
        };
        drop(custody_session);
        let closure_id = sealed_closure_id.ok_or_else(|| {
            EngineError::Invariant(
                "governed SQL publication completed without sealing its exact final closure"
                    .to_owned(),
            )
        })?;
        stored_outcome.validate()?;
        if failpoint == GovernedProjectionFailpoint::AfterSqlBeforeIndexMark {
            return Err(EngineError::Invariant(
                "test failpoint: after SQL projection before index mark".into(),
            ));
        }

        drop(prepared);
        let indexed = self
            .store
            .begin_writer_session()?
            .verify_governed_projection_and_mark_indexed(&reservation_record_id)?;
        if indexed.closure_id != closure_id
            || indexed.diagnostic_artifact_id != *artifact.artifact_id.as_digest()
            || indexed.runtime_checkpoint_id != final_checkpoint_id
        {
            return Err(EngineError::Invariant(
                "indexed governed projection differs from the exact completed occurrence"
                    .to_owned(),
            ));
        }
        let reopened = reopen_diagnostic_artifact(&self.store, artifact.artifact_id.as_digest())?;
        let SupportedDiagnosticExecution::V2(reopened) = reopened else {
            return Err(EngineError::Invariant(
                "governed V2 persistence reopened under another contract".to_owned(),
            ));
        };
        if reopened != artifact {
            return Err(EngineError::Invariant(
                "governed V2 persistence changed the exact diagnostic artifact".to_owned(),
            ));
        }
        Ok(reopened)
    }

    /// Verify a historical admitted report (read-only; no re-evaluation).
    ///
    /// Order matters: authenticate the stored snapshot from persisted data
    /// first, rejecting corruption or substitution before consulting any present
    /// runtime state; then observe the current sealed identity; then compare,
    /// distinguishing artifact drift (refuse), method incompatibility (refuse),
    /// and platform drift (recorded, non-refusing). Verification may confirm or
    /// reject the historical admission; it may never recreate it under present
    /// conditions, refresh a binding, or ask the evaluator what it thinks today.
    ///
    /// # Errors
    ///
    /// Returns a [`VerificationRefusal`] preserving the exact reason.
    pub fn verify_admitted(
        &self,
        report_id: &str,
    ) -> Result<AdmittedReportVerification, VerificationRefusal> {
        // Steps 1-2: authenticate the stored snapshot and verify the stored
        // judgment, purely from persisted data. Corruption/substitution/broken
        // binding/unsupported schema are rejected here, before runtime state.
        let snapshot = self.store.verify_admitted_snapshot(report_id)?;

        // Step 3: observe the current sealed identity; fail closed if absent.
        let current = self
            .require_evaluator_identity()
            .map_err(|error| VerificationRefusal::CurrentIdentityUnverifiable(error.to_string()))?;

        // Step 4: compare, distinguishing the reason.
        // Digests observed by different methods are not comparable.
        if snapshot.artifact_identity_method != current.artifact_identity_method() {
            return Err(VerificationRefusal::MethodIncompatible {
                admitted: snapshot.artifact_identity_method,
                current: current.artifact_identity_method().to_owned(),
            });
        }
        if snapshot.evaluator_artifact_digest != current.artifact_digest().as_str() {
            return Err(VerificationRefusal::EvaluatorArtifactDrift {
                admitted: snapshot.evaluator_artifact_digest,
                current: current.artifact_digest().as_str().to_owned(),
            });
        }
        // Platform drift is recorded ambient context, never a refusal.
        let mut platform_observations = Vec::new();
        if snapshot.platform_runtime_version != current.platform_runtime_version() {
            platform_observations.push(PlatformObservation::RuntimeDrift {
                admitted: snapshot.platform_runtime_version.clone(),
                current: current.platform_runtime_version().to_owned(),
            });
        }

        Ok(AdmittedReportVerification {
            report_id: snapshot.report_id,
            admission_id: snapshot.admission_id,
            instance_id: snapshot.instance_id,
            platform_observations,
        })
    }

    /// Test, admit, or rotate a configured helper.
    ///
    /// # Errors
    ///
    /// Returns a typed acquisition, protocol, profile, admission, or durable
    /// storage error. A failed workflow never silently refreshes a lock.
    #[allow(clippy::too_many_lines)]
    pub fn watcher_action(
        &mut self,
        watcher: &WatcherConfig,
        action: &str,
    ) -> Result<WatcherActionOutcome, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            &format!("watcher-{action}"),
        )?;
        self.reconcile_pending_binding(watcher)?;
        let previous = if matches!(action, "admit" | "rotate") {
            self.authoritative_active_lock(watcher)?
        } else {
            None
        };
        let profile = resolve(watcher)?;
        // Bind conformance to the exact bytes that existed before the dry
        // exchange, then prove they did not change while the helper ran.
        let execution_before =
            ExecutionIdentity::resolve_command(&watcher.command).map_err(AdmissionError::from)?;
        let launch = VerifiedLaunch::open_expected(&watcher.command, &execution_before)
            .map_err(AdmissionError::from)?;
        let corpus = nq_protocol::verify_embedded_conformance_corpus()
            .map_err(|error| EngineError::Protocol(error.to_string()))?;
        let dry = self.dry_exchange(watcher, profile, launch)?;
        execution_before
            .verify_current()
            .map_err(AdmissionError::from)?;
        let status = semantic_report_status(dry.validated.status).to_owned();
        if action == "test" {
            self.stop_unix_runner(&watcher.instance_id);
            return Ok(WatcherActionOutcome::Tested {
                instance_id: watcher.instance_id.clone(),
                report_digest: dry.report_digest,
                report_status: status,
            });
        }
        if !matches!(action, "admit" | "rotate") {
            return Err(EngineError::Invariant(format!(
                "unsupported watcher action {action}"
            )));
        }

        let descriptor_digest = profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let lock = AdmissionManager::candidate_with_execution(
            watcher,
            CandidateEvidence {
                profile_digest: descriptor_digest.as_str().to_owned(),
                protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                // Until an optional helper support-description exchange is
                // standardized, the compiled profile vocabulary is the
                // mechanically possible set. Admission still intersects it
                // with the configured ceiling; a helper can only narrow
                // further by using fewer capabilities in each report.
                declared_capabilities: profile
                    .descriptor()
                    .capabilities
                    .iter()
                    .map(|term| term.name.clone())
                    .collect(),
                conformance: ConformanceReceipt {
                    tool_version: corpus.version.verifier_version,
                    protocol_passed: true,
                    protocol_corpus_digest: corpus.version.corpus_digest.to_string(),
                    protocol_fixtures_checked: corpus.fixtures_checked,
                    dry_collection_passed: true,
                    dry_report_digest: Some(dry.report_digest),
                },
            },
            execution_before.clone(),
        )?;
        let verification = self.admission.verify_opened_execution(
            watcher,
            &lock,
            descriptor_digest.as_str(),
            nq_protocol::HELPER_PROTOCOL_VERSION,
            &execution_before,
        )?;

        // Assemble the typed admission-context identity before taking a mutable
        // store borrow. This refuses (fail closed) when the running evaluator
        // identity is unavailable, rather than admitting under a fabricated one.
        let identity = self.admission_identity(profile, &lock)?;
        self.store.begin_writer_session()?.append_admission(&AdmissionInput {
            admission_id: lock.admission_id.clone(),
            instance_id: lock.instance_id.clone(),
            identity,
            execution_chain: canonical(&lock.execution)?,
            profile_id: lock.profile.id.clone(),
            profile_version: lock.profile.version.to_string(),
            profile_digest: lock.profile.digest.clone(),
            capability_grant: canonical(&lock.granted_capabilities)?,
            conformance: canonical(&lock.conformance)?,
            lock: canonical(&lock)?,
            admitted_at: timestamp(lock.admitted_at),
            operator_identity: canonical(&lock.operator)?,
        })?;

        let archived = previous.is_some();
        let lock_path =
            self.transition_binding(watcher, "activate", Some(&lock), previous.as_ref(), action)?;
        // Every binding change creates a new helper lifetime. A dry-collection
        // process is never silently promoted into the active persistent one.
        self.stop_unix_runner(&watcher.instance_id);
        Ok(WatcherActionOutcome::Activated {
            instance_id: watcher.instance_id.clone(),
            admission_id: lock.admission_id,
            binding_digest: verification.binding_digest,
            lock_path,
            previous_lock_archived: archived,
        })
    }

    /// Execute and persist one admitted collection attempt.
    ///
    /// # Errors
    ///
    /// Returns only local engine/storage failures. Expected helper, protocol,
    /// and admission outcomes are retained and returned as `CollectionOutcome`.
    #[cfg(test)]
    fn collect(&mut self, watcher: &WatcherConfig) -> Result<CollectionOutcome, EngineError> {
        self.collect_internal(watcher, None)
            .map(|execution| execution.outcome)
    }

    /// Execute one admitted collection and emit its exact bounded diagnostic.
    ///
    /// This is a deliberately narrow first live producer for
    /// `nq.diagnostic_execution.v2`. It is sealed to the exact current
    /// `nq.host/v1` load-pressure profile/detector identities and a fresh
    /// evaluation context containing exactly the newly admitted report. The
    /// fresh-history restriction keeps complete input accounting truthful until
    /// history-aware manifests exist. Admitted determinate results, detector
    /// refusals, received-input refusals, and no-byte acquisition failures are
    /// committed as immutable artifacts in the same transaction as their
    /// originating collection. Admission refusals create no run and therefore
    /// cannot be recast as execution artifacts.
    ///
    /// # Errors
    ///
    /// Returns when the profile does not have exactly one compiled detector,
    /// collection fails locally, admission creates no run, or the completed
    /// collection cannot emit exact v2 input accounting.
    #[cfg(test)]
    fn diagnostic_execute(
        &mut self,
        watcher: &WatcherConfig,
    ) -> Result<SupportedDiagnosticExecution, EngineError> {
        let invocation = DiagnosticInvocationContext {
            request_id: None,
            production: None,
        };
        let execution = self.collect_internal(watcher, Some(&invocation))?;
        execution.diagnostic.ok_or_else(|| {
            EngineError::DiagnosticUnsupported(format!(
                "collection for {} produced no admitted determinate diagnostic execution; inspect the retained collection outcome",
                watcher.instance_id
            ))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn collect_internal(
        &mut self,
        watcher: &WatcherConfig,
        diagnostic_invocation: Option<&DiagnosticInvocationContext>,
    ) -> Result<CollectionExecution, EngineError> {
        let emit_diagnostic = diagnostic_invocation.is_some();
        let diagnostic_request_id =
            diagnostic_invocation.and_then(|context| context.request_id.as_ref());
        let diagnostic_production =
            diagnostic_invocation.and_then(|context| context.production.as_ref());
        let _guard =
            InstanceGuard::acquire(&self.config.database_path, &watcher.instance_id, "collect")?;
        // Fail closed before any persistence: a collection stamps evaluator
        // identity onto its finding events, so refuse up front when it is
        // unavailable rather than commit an admitted report and only then refuse
        // at evaluation, leaving a durable report behind.
        self.require_evaluator_identity()?;
        self.reconcile_pending_binding(watcher)?;
        let profile = resolve(watcher)?;
        let diagnostic_node_id =
            match diagnostic_invocation.and_then(|context| context.production.as_ref()) {
                Some(production) => Some(production.node_id.clone()),
                None if emit_diagnostic => Some(format!(
                    "nq-store-genesis:{}",
                    self.store.sole_genesis_id()?
                )),
                None => None,
            };
        let descriptor_digest = profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        if emit_diagnostic {
            require_initial_diagnostic_profile(profile, descriptor_digest.as_str())?;
            let snapshot = self
                .store
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))?;
            require_empty_diagnostic_history(&snapshot, watcher, descriptor_digest.as_str())?;
        }
        let authoritative = match self.authoritative_active_lock(watcher) {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                self.stop_unix_runner(&watcher.instance_id);
                let outcome = CollectionOutcome::admission_refused(
                    watcher.instance_id.clone(),
                    AdmissionRefusal {
                        responsible_instance_id: watcher.instance_id.clone(),
                        boundary: AdmissionRefusalBoundary::ActiveBinding,
                        code: AdmissionRefusalCode::MissingActiveBinding,
                        details: AdmissionRefusalDetails::None,
                    },
                );
                self.record_instance_status(watcher, &outcome)?;
                return Ok(CollectionExecution::without_diagnostic(outcome));
            }
            Err(error) => {
                self.stop_unix_runner(&watcher.instance_id);
                let refusal = admission_refusal_from_engine(
                    &watcher.instance_id,
                    AdmissionRefusalBoundary::ActiveBinding,
                    error,
                );
                let outcome =
                    CollectionOutcome::admission_refused(watcher.instance_id.clone(), refusal);
                self.record_instance_status(watcher, &outcome)?;
                return Ok(CollectionExecution::without_diagnostic(outcome));
            }
        };
        let lock = match (|| {
            let lock = authoritative;
            let launch = VerifiedLaunch::open_expected(&watcher.command, &lock.execution)?;
            self.admission
                .verify_opened_execution(
                    watcher,
                    &lock,
                    descriptor_digest.as_str(),
                    nq_protocol::HELPER_PROTOCOL_VERSION,
                    launch.identity(),
                )
                .map(|verification| (lock, verification, launch))
        })() {
            Ok(binding) => binding,
            Err(error) => {
                self.stop_unix_runner(&watcher.instance_id);
                let refusal = admission_refusal(&watcher.instance_id, error);
                let outcome =
                    CollectionOutcome::admission_refused(watcher.instance_id.clone(), refusal);
                self.record_instance_status(watcher, &outcome)?;
                return Ok(CollectionExecution::without_diagnostic(outcome));
            }
        };
        let (lock, verification, launch) = lock;
        let provider =
            self.verified_local_provider(profile, &lock, &verification, launch.identity())?;
        let provider_identity = provider.identity().clone();
        let checkpoint_contract_digest = checkpoint_contract_digest(
            watcher,
            &lock,
            &verification.binding_digest,
            descriptor_digest.as_str(),
        )?;
        let checkpoint = match watcher.checkpoint_policy {
            CheckpointPolicy::Disabled => None,
            CheckpointPolicy::AdvanceAfterAdmission => self
                .store
                .latest_checkpoint(&watcher.instance_id, &checkpoint_contract_digest)?
                .map(|bytes| serde_json::from_slice(&bytes).map(|value| Checkpoint { value }))
                .transpose()
                .map_err(|error| {
                    EngineError::Invariant(format!("stored checkpoint cannot decode: {error}"))
                })?,
        };
        let request = build_request(watcher, profile, &lock.granted_capabilities, checkpoint)?;
        let request_json = nq_protocol::canonical_json_bytes(&request)
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        // These are three independent identities: the provider intake and
        // application-level attempt are fixed before dispatch, while the
        // watcher run remains the current local-origin subtype.
        let intake_id = Uuid::new_v4().to_string();
        let attempt_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let attempt = ProviderAttempt::new(
            intake_id,
            attempt_id,
            run_id.clone(),
            request.clone(),
            provider,
            carrier_name(watcher.carrier).to_owned(),
            watcher.invocation.deadline_ms,
            &checkpoint_contract_digest,
        )?;
        let capture = self.run_capture(
            watcher,
            &request_json,
            Some(&verification.binding_digest),
            launch,
        );
        let intake = ProviderIntakeV1::from_capture(attempt, capture.clone(), &watcher.resources)?;
        let run = RunInput {
            run_id: run_id.clone(),
            request_id: request.request_id.to_string(),
            instance_id: watcher.instance_id.clone(),
            admission_id: Some(lock.admission_id.clone()),
            binding_digest: verification.binding_digest,
            checkpoint_contract_digest,
            profile_id: watcher.profile.id.clone(),
            profile_version: watcher.profile.version.to_string(),
            profile_digest: descriptor_digest.as_str().to_owned(),
            carrier: intake.record().origin_carrier.clone(),
            started_at: timestamp(capture.started_at),
            deadline_at: deadline_timestamp(intake.record().deadline_at),
            finished_at: timestamp(capture.finished_at),
            acquisition_outcome: acquisition_code(&capture.outcome).to_owned(),
            execution_identity: canonical(&lock.execution)?,
            resource_outcome: canonical(&intake.record().native_outcome)?,
        };
        let intake_input = intake.to_store_input(&run)?;
        match self.store.preflight_provider_intake(&intake_input)? {
            ProviderIntakePreflight::New => {}
            ProviderIntakePreflight::Existing {
                acknowledgment,
                canonical_result,
            } => {
                let outcome = decode_collection_outcome(canonical_result.as_bytes())?;
                let diagnostic_artifact_id = emit_diagnostic
                    .then(|| {
                        self.store
                            .diagnostic_artifact_id_for_run(&acknowledgment.run_id)
                    })
                    .transpose()?
                    .flatten();
                let diagnostic = diagnostic_artifact_id
                    .as_ref()
                    .map(|artifact_id| reopen_diagnostic_artifact(&self.store, artifact_id))
                    .transpose()?;
                return Ok(CollectionExecution {
                    outcome,
                    diagnostic,
                    diagnostic_artifact_id,
                });
            }
        }

        if capture.outcome != AcquisitionOutcome::Response {
            let (submission, custody_refusal) =
                rejected_transport_submission(&run_id, watcher, &capture)?;
            let outcome = if let Some(refusal) = custody_refusal {
                CollectionOutcome::rejected(watcher.instance_id.clone(), run_id.clone(), refusal)
            } else {
                CollectionOutcome::acquisition_failed(
                    watcher.instance_id.clone(),
                    run_id.clone(),
                    capture.outcome.clone(),
                )?
            };
            let diagnostic = diagnostic_node_id
                .as_deref()
                .map(|node_id| {
                    prepare_non_success_diagnostic(
                        node_id,
                        watcher,
                        profile,
                        &provider_identity,
                        diagnostic_request_id,
                        &request,
                        diagnostic_production,
                        &run_id,
                        &intake_input.intake_id,
                        submission
                            .as_ref()
                            .map(|submission| submission.raw_bytes.as_slice()),
                        &capture,
                        self.require_evaluator_identity()?,
                        &outcome,
                    )
                })
                .transpose()?;
            return self.commit_non_success_collection(
                watcher,
                intake_input,
                run,
                submission,
                outcome,
                diagnostic.as_ref(),
            );
        }

        let raw = intake.raw_bytes().to_vec();
        let response = match intake.record().interpretation.clone() {
            ProviderResponseInterpretationV1::NotAvailable => {
                return Err(EngineError::Invariant(
                    "response acquisition has no provider response interpretation".into(),
                ));
            }
            ProviderResponseInterpretationV1::ProtocolRejected { rejection } => {
                let refusal = GovernedRefusal::protocol(Uuid::new_v4().to_string(), rejection);
                let stored_refusal = stored_governed_refusal(&refusal, capture.finished_at)?;
                let submission = SubmissionInput {
                    submission_id: Uuid::new_v4().to_string(),
                    raw_bytes: raw,
                    received_at: timestamp(capture.finished_at),
                    protocol_outcome: "rejected".into(),
                    disposition: SubmissionDisposition::Rejected {
                        refusal: stored_refusal,
                    },
                };
                let outcome = CollectionOutcome::rejected(
                    watcher.instance_id.clone(),
                    run_id.clone(),
                    refusal,
                );
                let diagnostic = diagnostic_node_id
                    .as_deref()
                    .map(|node_id| {
                        prepare_non_success_diagnostic(
                            node_id,
                            watcher,
                            profile,
                            &provider_identity,
                            diagnostic_request_id,
                            &request,
                            diagnostic_production,
                            &run_id,
                            &intake_input.intake_id,
                            Some(submission.raw_bytes.as_slice()),
                            &capture,
                            self.require_evaluator_identity()?,
                            &outcome,
                        )
                    })
                    .transpose()?;
                return self.commit_non_success_collection(
                    watcher,
                    intake_input,
                    run,
                    Some(submission),
                    outcome,
                    diagnostic.as_ref(),
                );
            }
            ProviderResponseInterpretationV1::Validated { response } => response,
        };

        match response.outcome {
            ResponseOutcome::Refusal { refusal } => {
                let refusal = GovernedRefusal::helper(Uuid::new_v4().to_string(), refusal);
                let stored_refusal = stored_governed_refusal(&refusal, capture.finished_at)?;
                let submission = SubmissionInput {
                    submission_id: Uuid::new_v4().to_string(),
                    raw_bytes: raw,
                    received_at: timestamp(capture.finished_at),
                    protocol_outcome: "valid_refusal".into(),
                    disposition: SubmissionDisposition::Rejected {
                        refusal: stored_refusal,
                    },
                };
                let outcome = CollectionOutcome::rejected(
                    watcher.instance_id.clone(),
                    run_id.clone(),
                    refusal,
                );
                let diagnostic = diagnostic_node_id
                    .as_deref()
                    .map(|node_id| {
                        prepare_non_success_diagnostic(
                            node_id,
                            watcher,
                            profile,
                            &provider_identity,
                            diagnostic_request_id,
                            &request,
                            diagnostic_production,
                            &run_id,
                            &intake_input.intake_id,
                            Some(submission.raw_bytes.as_slice()),
                            &capture,
                            self.require_evaluator_identity()?,
                            &outcome,
                        )
                    })
                    .transpose()?;
                self.commit_non_success_collection(
                    watcher,
                    intake_input,
                    run,
                    Some(submission),
                    outcome,
                    diagnostic.as_ref(),
                )
            }
            ResponseOutcome::Report { report } => {
                let report_digest = nq_protocol::semantic_digest(&report)
                    .map_err(|error| EngineError::Canonical(error.to_string()))?;
                let normalized = match ProfileReportInput::from_protocol(&report, &report_digest) {
                    Ok(normalized) => normalized,
                    Err(error) => {
                        let refusal = governed_profile_refusal(
                            Uuid::new_v4().to_string(),
                            profile,
                            profile_normalization_refusal(&watcher.instance_id, profile, &error),
                        )?;
                        let stored_refusal =
                            stored_governed_refusal(&refusal, capture.finished_at)?;
                        let submission = SubmissionInput {
                            submission_id: Uuid::new_v4().to_string(),
                            raw_bytes: raw,
                            received_at: timestamp(capture.finished_at),
                            protocol_outcome: "valid_report".into(),
                            disposition: SubmissionDisposition::Rejected {
                                refusal: stored_refusal,
                            },
                        };
                        let outcome = CollectionOutcome::rejected(
                            watcher.instance_id.clone(),
                            run_id.clone(),
                            refusal,
                        );
                        let diagnostic = diagnostic_node_id
                            .as_deref()
                            .map(|node_id| {
                                prepare_non_success_diagnostic(
                                    node_id,
                                    watcher,
                                    profile,
                                    &provider_identity,
                                    diagnostic_request_id,
                                    &request,
                                    diagnostic_production,
                                    &run_id,
                                    &intake_input.intake_id,
                                    Some(submission.raw_bytes.as_slice()),
                                    &capture,
                                    self.require_evaluator_identity()?,
                                    &outcome,
                                )
                            })
                            .transpose()?;
                        return self.commit_non_success_collection(
                            watcher,
                            intake_input,
                            run,
                            Some(submission),
                            outcome,
                            diagnostic.as_ref(),
                        );
                    }
                };
                // Profile validation is part of the durable semantic record.
                // Bind it to the exact millisecond-precision custody time that
                // the store can reopen, rather than transient sub-millisecond
                // process-clock precision that would be discarded at commit.
                let durable_received_at = parse_timestamp(&timestamp(capture.finished_at))?;
                let context = ValidationContext::from_request(
                    &request,
                    durable_received_at,
                    Duration::seconds(60),
                );
                match profile.validate(&context, &normalized) {
                    Err(refusal) => {
                        let refusal =
                            governed_profile_refusal(Uuid::new_v4().to_string(), profile, refusal)?;
                        let stored_refusal =
                            stored_governed_refusal(&refusal, capture.finished_at)?;
                        let submission = SubmissionInput {
                            submission_id: Uuid::new_v4().to_string(),
                            raw_bytes: raw,
                            received_at: timestamp(capture.finished_at),
                            protocol_outcome: "valid_report".into(),
                            disposition: SubmissionDisposition::Rejected {
                                refusal: stored_refusal,
                            },
                        };
                        let outcome = CollectionOutcome::rejected(
                            watcher.instance_id.clone(),
                            run_id.clone(),
                            refusal,
                        );
                        let diagnostic = diagnostic_node_id
                            .as_deref()
                            .map(|node_id| {
                                prepare_non_success_diagnostic(
                                    node_id,
                                    watcher,
                                    profile,
                                    &provider_identity,
                                    diagnostic_request_id,
                                    &request,
                                    diagnostic_production,
                                    &run_id,
                                    &intake_input.intake_id,
                                    Some(submission.raw_bytes.as_slice()),
                                    &capture,
                                    self.require_evaluator_identity()?,
                                    &outcome,
                                )
                            })
                            .transpose()?;
                        self.commit_non_success_collection(
                            watcher,
                            intake_input,
                            run,
                            Some(submission),
                            outcome,
                            diagnostic.as_ref(),
                        )
                    }
                    Ok(validated) => {
                        let report_id = Uuid::new_v4().to_string();
                        let report_status = semantic_report_status(validated.status).to_owned();
                        let submission_id = Uuid::new_v4().to_string();
                        let stored_report = store_report(
                            &report_id,
                            watcher,
                            profile,
                            &report,
                            &validated,
                            capture.finished_at,
                        )?;
                        let diagnostic_context = diagnostic_node_id
                            .as_deref()
                            .map(|node_id| {
                                prepare_diagnostic_emission(
                                    node_id,
                                    watcher,
                                    profile,
                                    &provider_identity,
                                    diagnostic_request_id,
                                    &request,
                                    diagnostic_production,
                                    &run_id,
                                    &report_id,
                                    &intake_input.intake_id,
                                    &raw,
                                    &normalized,
                                    &validated,
                                    &capture,
                                    self.require_evaluator_identity()?,
                                )
                            })
                            .transpose()?;
                        let submission = SubmissionInput {
                            submission_id,
                            raw_bytes: raw,
                            received_at: timestamp(capture.finished_at),
                            protocol_outcome: "valid_report".into(),
                            disposition: SubmissionDisposition::Admitted(stored_report),
                        };
                        validate_evaluation_refusal_history(&self.store)?;
                        let evaluator_artifact_digest = self
                            .require_evaluator_identity()?
                            .artifact_digest()
                            .as_str()
                            .to_owned();
                        let collection = CollectionInput {
                            intake: intake_input,
                            run,
                            submission: Some(submission),
                        };
                        let committed = self.store.begin_writer_session()?.commit_admitted_collection(
                            &collection,
                            |view, receipt| {
                                let snapshot = view.evidence_snapshot(std::slice::from_ref(
                                    &watcher.instance_id,
                                ))?;
                                if emit_diagnostic {
                                    require_fresh_diagnostic_snapshot(
                                        &snapshot,
                                        watcher,
                                        descriptor_digest.as_str(),
                                        &report_id,
                                    )?;
                                }
                                let current_findings = view.finding_snapshots()?;
                                let prepared = prepare_instance_evaluations(
                                    watcher,
                                    profile,
                                    Some(&run_id),
                                    &snapshot,
                                    &current_findings,
                                    &evaluator_artifact_digest,
                                )?;
                                let (diagnostic_artifact_id, diagnostic_artifact) =
                                    if let Some(context) = diagnostic_context.as_ref() {
                                        let [evaluation] = prepared.as_slice() else {
                                            return Err(EngineError::Invariant(
                                                "diagnostic execution requires exactly one prepared evaluation"
                                                    .into(),
                                            ));
                                        };
                                        let artifact = context.finish(
                                            &evaluation.envelope,
                                            &evaluation.detector_reports,
                                        )?;
                                        let artifact_id = artifact.artifact_id.0.clone();
                                        let canonical_bytes =
                                            CanonicalDocument::from_canonical_bytes(
                                                artifact.canonical_bytes().map_err(|error| {
                                                    EngineError::Canonical(error.to_string())
                                                })?,
                                            )?;
                                        (
                                            Some(artifact_id.clone()),
                                            Some(DiagnosticArtifactCommitInput {
                                                artifact_id,
                                                contract_schema:
                                                    DIAGNOSTIC_EXECUTION_V2_SCHEMA.to_owned(),
                                                canonical_bytes,
                                                local_origin:
                                                    DiagnosticArtifactLocalOriginInput {
                                                        run_id: run_id.clone(),
                                                        evaluation_id: Some(
                                                            evaluation
                                                                .envelope
                                                                .evaluation_id
                                                                .clone(),
                                                        ),
                                                        completed_at: timestamp(
                                                            artifact.completed_at,
                                                        ),
                                                        execution_binding: None,
                                                    },
                                            }),
                                        )
                                    } else {
                                        (None, None)
                                    };
                                let evaluations = prepared
                                    .iter()
                                    .map(|prepared| prepared.envelope.clone())
                                    .collect();
                                let outcome = CollectionOutcome::admitted(
                                    watcher.instance_id.clone(),
                                    run_id.clone(),
                                    report_id.clone(),
                                    report_status.clone(),
                                    receipt.semantic_digest.clone().ok_or_else(|| {
                                        EngineError::Invariant(
                                            "admitted collection returned no semantic digest"
                                                .into(),
                                        )
                                    })?,
                                    evaluations,
                                );
                                validate_provider_input_downstream_correspondence(
                                    &collection.intake,
                                    &outcome,
                                )?;
                                Ok::<_, EngineError>(AdmittedCollectionCompletion {
                                    status: instance_status_event(watcher, &outcome)?,
                                    evaluations: prepared
                                        .into_iter()
                                        .map(|prepared| prepared.commit)
                                        .collect(),
                                    diagnostic_artifact,
                                    value: CollectionExecution {
                                        outcome,
                                        diagnostic: None,
                                        diagnostic_artifact_id,
                                    },
                                })
                            },
                        )?;
                        match committed {
                            ProviderIntakeCommit::Committed { mut value, .. } => {
                                if let Some(artifact_id) = value.diagnostic_artifact_id.as_ref() {
                                    value.diagnostic =
                                        Some(reopen_diagnostic_artifact(&self.store, artifact_id)?);
                                }
                                Ok(value)
                            }
                            ProviderIntakeCommit::Replayed {
                                acknowledgment,
                                canonical_result,
                                ..
                            } => {
                                let outcome =
                                    decode_collection_outcome(canonical_result.as_bytes())?;
                                let diagnostic_artifact_id = emit_diagnostic
                                    .then(|| {
                                        self.store
                                            .diagnostic_artifact_id_for_run(&acknowledgment.run_id)
                                    })
                                    .transpose()?
                                    .flatten();
                                let diagnostic = diagnostic_artifact_id
                                    .as_ref()
                                    .map(|artifact_id| {
                                        reopen_diagnostic_artifact(&self.store, artifact_id)
                                    })
                                    .transpose()?;
                                Ok(CollectionExecution {
                                    outcome,
                                    diagnostic,
                                    diagnostic_artifact_id,
                                })
                            }
                        }
                    }
                }
            }
        }
    }

    /// Activate one retained historical admission under the same serialized,
    /// crash-recoverable transition protocol used by admission and rotation.
    ///
    /// # Errors
    ///
    /// Returns when the historical lock is not a byte-exact durable admission,
    /// no longer verifies against current local facts, or cannot be
    /// materialized durably.
    pub fn rollback_binding(
        &mut self,
        watcher: &WatcherConfig,
        historical: &Path,
    ) -> Result<BindingActionOutcome, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            "watcher-rollback",
        )?;
        self.reconcile_pending_binding(watcher)?;
        let previous = self.authoritative_active_lock(watcher)?;
        let profile = resolve(watcher)?;
        let lock = self.admission.load(historical)?;
        let verification = self.admission.verify(
            watcher,
            &lock,
            profile
                .descriptor()
                .digest()
                .map_err(|error| EngineError::Canonical(error.to_string()))?
                .as_str(),
            nq_protocol::HELPER_PROTOCOL_VERSION,
        )?;
        let durable = self.store.admission(&lock.admission_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "historical lock {} has no durable admission record",
                lock.admission_id
            ))
        })?;
        if durable.instance_id != watcher.instance_id
            || durable.lock_json != canonical(&lock)?.as_bytes()
        {
            return Err(EngineError::Invariant(format!(
                "historical lock {} differs from its durable admission record",
                lock.admission_id
            )));
        }
        let lock_path = self.transition_binding(
            watcher,
            "rollback",
            Some(&lock),
            previous.as_ref(),
            "operator_rollback",
        )?;
        self.stop_unix_runner(&watcher.instance_id);
        Ok(BindingActionOutcome::RolledBack {
            instance_id: watcher.instance_id.clone(),
            admission_id: lock.admission_id,
            binding_digest: verification.binding_digest,
            lock_path,
        })
    }

    /// Revoke the exact active authoritative admission. The lock remains in
    /// immutable `SQLite` admission history and in a derived history path; no
    /// active lock is left behind.
    ///
    /// # Errors
    ///
    /// Returns when there is no active authoritative binding or the durable
    /// transition/materialization cannot complete.
    pub fn revoke_binding(
        &mut self,
        watcher: &WatcherConfig,
    ) -> Result<BindingActionOutcome, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            "watcher-revoke",
        )?;
        self.reconcile_pending_binding(watcher)?;
        let previous = self.authoritative_active_lock(watcher)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "instance {} has no active authoritative admission",
                watcher.instance_id
            ))
        })?;
        let admission_id = previous.admission_id.clone();
        let retained_lock = history_lock_path(&self.config.admissions_dir, &previous);
        self.transition_binding(
            watcher,
            "revoke",
            None,
            Some(&previous),
            "operator_revocation",
        )?;
        self.stop_unix_runner(&watcher.instance_id);
        Ok(BindingActionOutcome::Revoked {
            instance_id: watcher.instance_id.clone(),
            admission_id,
            retained_lock,
        })
    }

    fn transition_binding(
        &mut self,
        watcher: &WatcherConfig,
        event_kind: &str,
        desired_lock: Option<&AdmissionLock>,
        previous_lock: Option<&AdmissionLock>,
        reason_code: &str,
    ) -> Result<PathBuf, EngineError> {
        let operation_id = Uuid::new_v4().to_string();
        let binding_event_id = Uuid::new_v4().to_string();
        let binding_digest = desired_lock
            .or(previous_lock)
            .ok_or_else(|| EngineError::Invariant("binding transition has no lock basis".into()))
            .and_then(|lock| Ok(self.admission.binding_digest(lock)?))?;
        let plan = BindingMaterializationPlan {
            schema: BINDING_MATERIALIZATION_PLAN_SCHEMA.to_owned(),
            operation_id: operation_id.clone(),
            instance_id: watcher.instance_id.clone(),
            binding_event_id: binding_event_id.clone(),
            admissions_root: AdmissionRootIdentity::resolve(&self.config.admissions_dir)?,
            desired_lock: desired_lock.cloned(),
            previous_lock: previous_lock.cloned(),
        };
        plan.validate()?;
        let plan_document = canonical(&plan)?;
        let occurred_at = timestamp(Utc::now());
        let event = BindingEventInput {
            binding_event_id: binding_event_id.clone(),
            instance_id: watcher.instance_id.clone(),
            event_kind: event_kind.to_owned(),
            admission_id: desired_lock.map(|lock| lock.admission_id.clone()),
            binding_digest,
            occurred_at: occurred_at.clone(),
            reason_code: Some(reason_code.to_owned()),
            detail: canonical(&json!({
                "schema": "nq.binding_event_detail.v1",
                "materialization_operation_id": operation_id,
                "previous_admission_id": previous_lock.map(|lock| &lock.admission_id),
            }))?,
        };
        let intent = BindingMaterializationInput {
            materialization_event_id: Uuid::new_v4().to_string(),
            operation_id: operation_id.clone(),
            instance_id: watcher.instance_id.clone(),
            binding_event_id: binding_event_id.clone(),
            phase: "intent".to_owned(),
            occurred_at,
            detail: plan_document.clone(),
        };
        self.store
            .begin_writer_session()?
            .begin_binding_transition(&event, &intent)?;
        // From this point onward SQLite is authoritative. A failure or process
        // death leaves the intent pending for the next lock holder to replay.
        self.apply_binding_materialization(&plan)?;
        self.store
            .begin_writer_session()?
            .complete_binding_materialization(&binding_materialization_completion(
                &plan,
                &plan_document,
            )?)?;
        Ok(self.active_lock_path(watcher))
    }

    fn reconcile_pending_binding(&mut self, watcher: &WatcherConfig) -> Result<bool, EngineError> {
        let Some(pending) = self
            .store
            .pending_binding_materialization(&watcher.instance_id)?
        else {
            return Ok(false);
        };
        let document = CanonicalDocument::from_canonical_bytes(pending.detail_json.clone())?;
        let plan: BindingMaterializationPlan = serde_json::from_slice(document.as_bytes())
            .map_err(|error| {
                EngineError::Invariant(format!(
                    "pending binding materialization {} cannot decode: {error}",
                    pending.operation_id
                ))
            })?;
        plan.validate()?;
        if plan.operation_id != pending.operation_id
            || plan.instance_id != watcher.instance_id
            || plan.binding_event_id != pending.binding_event_id
        {
            return Err(EngineError::Invariant(format!(
                "pending binding materialization {} metadata disagrees with its plan",
                pending.operation_id
            )));
        }
        self.apply_binding_materialization(&plan)?;
        self.store
            .begin_writer_session()?
            .complete_binding_materialization(&binding_materialization_completion(
                &plan, &document,
            )?)?;
        self.stop_unix_runner(&watcher.instance_id);
        Ok(true)
    }

    fn apply_binding_materialization(
        &self,
        plan: &BindingMaterializationPlan,
    ) -> Result<(), EngineError> {
        plan.validate()?;
        let current_root = AdmissionRootIdentity::resolve(&self.config.admissions_dir)?;
        if current_root != plan.admissions_root {
            return Err(EngineError::Invariant(format!(
                "pending binding materialization {} targets a different admissions root",
                plan.operation_id
            )));
        }
        let (root_handle, admissions_root) = plan.admissions_root.open_retained()?;
        let active_path = admissions_root.join(format!("{}.json", plan.instance_id));
        let current = if active_path.exists() {
            Some(self.admission.load(&active_path)?)
        } else {
            None
        };
        let current_digest = current
            .as_ref()
            .map(|lock| self.admission.binding_digest(lock))
            .transpose()?;
        let desired_digest = plan
            .desired_lock
            .as_ref()
            .map(|lock| self.admission.binding_digest(lock))
            .transpose()?;
        let previous_digest = plan
            .previous_lock
            .as_ref()
            .map(|lock| self.admission.binding_digest(lock))
            .transpose()?;
        if current_digest.is_some()
            && current_digest != desired_digest
            && current_digest != previous_digest
        {
            return Err(EngineError::Invariant(format!(
                "active lock for {} changed outside its pending materialization",
                plan.instance_id
            )));
        }

        if let Some(previous) = &plan.previous_lock {
            archive_active_lock(&admissions_root, previous)?;
        }
        if let Some(desired) = &plan.desired_lock {
            self.admission.activate(&admissions_root, desired)?;
        } else {
            if current.is_none() && plan.previous_lock.is_none() {
                return Err(EngineError::Invariant(
                    "revocation materialization has no previous lock".into(),
                ));
            }
            match fs::remove_file(&active_path) {
                Ok(()) => root_handle.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn authoritative_active_lock(
        &self,
        watcher: &WatcherConfig,
    ) -> Result<Option<AdmissionLock>, EngineError> {
        let active_path = self.active_lock_path(watcher);
        let latest = self.store.latest_binding(&watcher.instance_id)?;
        let Some(latest) = latest else {
            if active_path.exists() {
                return Err(EngineError::Invariant(format!(
                    "instance {} has an active lock but no authoritative binding event",
                    watcher.instance_id
                )));
            }
            return Ok(None);
        };
        if matches!(latest.event_kind.as_str(), "revoke" | "quiesce") {
            if active_path.exists() {
                return Err(EngineError::Invariant(format!(
                    "instance {} is durably {} but still has an active lock",
                    watcher.instance_id, latest.event_kind
                )));
            }
            return Ok(None);
        }
        let admission_id = latest.admission_id.as_deref().ok_or_else(|| {
            EngineError::Invariant(format!(
                "active binding event {} lacks admission identity",
                latest.binding_event_id
            ))
        })?;
        let durable = self.store.admission(admission_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "active binding references missing admission {admission_id}"
            ))
        })?;
        let document = CanonicalDocument::from_canonical_bytes(durable.lock_json)?;
        let expected: AdmissionLock =
            serde_json::from_slice(document.as_bytes()).map_err(|error| {
                EngineError::Invariant(format!(
                    "durable admission {admission_id} lock cannot decode: {error}"
                ))
            })?;
        let expected_digest = self.admission.binding_digest(&expected)?;
        if durable.instance_id != watcher.instance_id
            || expected.instance_id != watcher.instance_id
            || expected.admission_id != admission_id
            || expected_digest != latest.binding_digest
        {
            return Err(EngineError::Invariant(format!(
                "active binding event {} disagrees with admission {}",
                latest.binding_event_id, admission_id
            )));
        }
        let materialized = self.admission.load(&active_path)?;
        if materialized != expected {
            return Err(EngineError::Invariant(format!(
                "active lock materialization for {} differs from authoritative admission {}",
                watcher.instance_id, admission_id
            )));
        }
        Ok(Some(materialized))
    }

    fn dry_exchange(
        &mut self,
        watcher: &WatcherConfig,
        profile: &'static dyn ProfileModule,
        launch: VerifiedLaunch,
    ) -> Result<DryExchange, EngineError> {
        let request = build_request(watcher, profile, &watcher.capability_ceiling, None)?;
        let request_json = nq_protocol::canonical_json_bytes(&request)
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let capture = self.run_capture(watcher, &request_json, None, launch);
        let response = match interpret_response(&request, &capture) {
            ProviderResponseInterpretationV1::NotAvailable => {
                let failure =
                    AcquisitionFailure::from_outcome(capture.outcome).ok_or_else(|| {
                        EngineError::Invariant(
                            "response cannot be a dry acquisition failure".into(),
                        )
                    })?;
                return Err(EngineError::AcquisitionFailed(Box::new(failure)));
            }
            ProviderResponseInterpretationV1::ProtocolRejected { rejection } => {
                return Err(EngineError::GovernedRefusal(Box::new(
                    GovernedRefusal::protocol(Uuid::new_v4().to_string(), rejection),
                )));
            }
            ProviderResponseInterpretationV1::Validated { response } => response,
        };
        let report = match response.outcome {
            ResponseOutcome::Report { report } => report,
            ResponseOutcome::Refusal { refusal } => {
                return Err(EngineError::GovernedRefusal(Box::new(
                    GovernedRefusal::helper(Uuid::new_v4().to_string(), refusal),
                )));
            }
        };
        let digest = nq_protocol::semantic_digest(&report)
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let input = match ProfileReportInput::from_protocol(&report, &digest) {
            Ok(input) => input,
            Err(error) => {
                let refusal = profile_normalization_refusal(&watcher.instance_id, profile, &error);
                return Err(EngineError::GovernedRefusal(Box::new(
                    governed_profile_refusal(Uuid::new_v4().to_string(), profile, refusal)?,
                )));
            }
        };
        let context =
            ValidationContext::from_request(&request, capture.finished_at, Duration::seconds(60));
        let validated = match profile.validate(&context, &input) {
            Ok(validated) => validated,
            Err(refusal) => {
                return Err(EngineError::GovernedRefusal(Box::new(
                    governed_profile_refusal(Uuid::new_v4().to_string(), profile, refusal)?,
                )));
            }
        };
        Ok(DryExchange {
            report_digest: digest.to_string(),
            validated,
        })
    }

    fn run_capture(
        &mut self,
        watcher: &WatcherConfig,
        request_json: &[u8],
        binding_digest: Option<&str>,
        launch: VerifiedLaunch,
    ) -> RunCapture {
        let deadline = StdDuration::from_millis(watcher.invocation.deadline_ms);
        match watcher.carrier {
            Carrier::Stdio => {
                self.runner
                    .run_verified(&launch, request_json, deadline, &watcher.resources)
            }
            Carrier::Unix => {
                self.run_unix_capture(watcher, request_json, deadline, binding_digest, launch)
            }
        }
    }

    fn run_unix_capture(
        &mut self,
        watcher: &WatcherConfig,
        request_json: &[u8],
        deadline: StdDuration,
        binding_digest: Option<&str>,
        launch: VerifiedLaunch,
    ) -> RunCapture {
        let started_at = Utc::now();
        let started = Instant::now();
        if self
            .unix_runners
            .get(&watcher.instance_id)
            .is_some_and(|active| active.binding_digest.as_deref() != binding_digest)
        {
            self.stop_unix_runner(&watcher.instance_id);
        }
        if !self.unix_runners.contains_key(&watcher.instance_id) {
            let options = UnixRunnerOptions::for_account(
                &self.config.helper_runtime_dir,
                &watcher.instance_id,
                deadline,
                watcher.resources.max_stderr_bytes,
                launch.execution_account(),
            )
            .with_isolation_limits(watcher.resources.isolation_limits());
            match UnixRunner::launch_verified(launch, options) {
                Ok(runner) => {
                    self.unix_runners.insert(
                        watcher.instance_id.clone(),
                        BoundUnixRunner {
                            binding_digest: binding_digest.map(str::to_owned),
                            runner,
                        },
                    );
                }
                Err(error) => {
                    return RunCapture {
                        started_at,
                        finished_at: Utc::now(),
                        duration_ms: elapsed_ms(started),
                        exit_code: None,
                        stdout: Vec::new(),
                        stderr: error.stderr,
                        outcome: AcquisitionOutcome::CarrierStartupFailed {
                            message: crate::runner::bounded_acquisition_detail(
                                error.failure.to_string(),
                            ),
                        },
                    };
                }
            }
        }

        let remaining = deadline.saturating_sub(started.elapsed());
        let exchange = self
            .unix_runners
            .get_mut(&watcher.instance_id)
            .expect("runner inserted above")
            .runner
            .exchange(
                request_json,
                remaining,
                watcher.resources.max_response_bytes,
            );
        let keep_running = exchange.outcome == UnixAcquisitionOutcome::Response;
        let capture = normalize_unix_capture(started_at, started, exchange);
        if !keep_running {
            self.stop_unix_runner(&watcher.instance_id);
        }
        capture
    }

    fn stop_unix_runner(&mut self, instance_id: &str) {
        if let Some(mut active) = self.unix_runners.remove(instance_id) {
            active.runner.shutdown();
        }
    }

    /// Terminate a persistent helper when its active lock has been removed or
    /// replaced since the runner was bound. This lightweight check compares
    /// canonical lock identity; the next collection still performs complete
    /// executable/profile/config verification.
    ///
    /// # Errors
    ///
    /// Returns only unexpected local errors while reading a present lock.
    pub fn quiesce_if_binding_changed(
        &mut self,
        watcher: &WatcherConfig,
    ) -> Result<bool, EngineError> {
        let Some(expected) = self
            .unix_runners
            .get(&watcher.instance_id)
            .and_then(|active| active.binding_digest.clone())
        else {
            return Ok(false);
        };
        let path = self.active_lock_path(watcher);
        let actual = self
            .admission
            .load(&path)
            .and_then(|lock| self.admission.binding_digest(&lock));
        match actual {
            Ok(actual) if actual == expected => Ok(false),
            Ok(_) | Err(AdmissionError::Io { .. }) => {
                self.stop_unix_runner(&watcher.instance_id);
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn active_lock_path(&self, watcher: &WatcherConfig) -> PathBuf {
        self.config
            .admissions_dir
            .join(format!("{}.json", watcher.instance_id))
    }

    fn record_instance_status(
        &mut self,
        watcher: &WatcherConfig,
        outcome: &CollectionOutcome,
    ) -> Result<(), EngineError> {
        if outcome.instance_id != watcher.instance_id {
            return Err(EngineError::Invariant(format!(
                "cannot record instance status {} from result for {}",
                watcher.instance_id, outcome.instance_id
            )));
        }
        let status = instance_status_event(watcher, outcome)?;
        self.store.begin_writer_session()?.record_status(&status)?;
        Ok(())
    }

    fn commit_non_success_collection(
        &mut self,
        watcher: &WatcherConfig,
        intake: ProviderIntakeInput,
        run: RunInput,
        submission: Option<SubmissionInput>,
        outcome: CollectionOutcome,
        diagnostic: Option<&DiagnosticExecutionV2>,
    ) -> Result<CollectionExecution, EngineError> {
        let run_id = outcome.run_id.as_deref().ok_or_else(|| {
            EngineError::Invariant("non-success collection outcome has no run identity".into())
        })?;
        if run.run_id != run_id {
            return Err(EngineError::Invariant(format!(
                "non-success outcome run {run_id} disagrees with collection run {}",
                run.run_id
            )));
        }
        validate_provider_input_downstream_correspondence(&intake, &outcome)?;
        let result = RunResultStatusInput {
            run_id: run_id.to_owned(),
            status: instance_status_event(watcher, &outcome)?,
        };
        let artifact_commit = diagnostic
            .map(|artifact| {
                let canonical_bytes = CanonicalDocument::from_canonical_bytes(
                    artifact
                        .canonical_bytes()
                        .map_err(|error| EngineError::Canonical(error.to_string()))?,
                )?;
                Ok::<_, EngineError>(DiagnosticArtifactCommitInput {
                    artifact_id: artifact.artifact_id.0.clone(),
                    contract_schema: DIAGNOSTIC_EXECUTION_V2_SCHEMA.to_owned(),
                    canonical_bytes,
                    local_origin: DiagnosticArtifactLocalOriginInput {
                        run_id: run_id.to_owned(),
                        evaluation_id: None,
                        completed_at: timestamp(artifact.completed_at),
                        execution_binding: None,
                    },
                })
            })
            .transpose()?;
        let completion = self.store.begin_writer_session()?.commit_non_success_collection_with_artifact(
            &CollectionInput {
                intake,
                run,
                submission,
            },
            &result,
            artifact_commit.as_ref(),
        )?;
        let stored_outcome = match &completion.intake {
            ProviderIntakeCommit::Committed { .. } => outcome,
            ProviderIntakeCommit::Replayed {
                canonical_result, ..
            } => {
                let reopened = decode_collection_outcome(canonical_result.as_bytes())?;
                if reopened != outcome {
                    return Err(EngineError::Invariant(
                        "idempotent provider replay resolved to a different canonical outcome"
                            .into(),
                    ));
                }
                reopened
            }
        };
        let reopened_diagnostic = completion
            .diagnostic_artifact_id
            .as_ref()
            .map(|artifact_id| reopen_diagnostic_artifact(&self.store, artifact_id))
            .transpose()?;
        if reopened_diagnostic.is_some() != completion.diagnostic_artifact_id.is_some() {
            return Err(EngineError::Invariant(
                "non-success diagnostic reopening lost its committed artifact identity".into(),
            ));
        }
        Ok(CollectionExecution {
            outcome: stored_outcome,
            diagnostic: reopened_diagnostic,
            diagnostic_artifact_id: completion.diagnostic_artifact_id,
        })
    }
}

/// Reopen one exact current diagnostic artifact through durable store custody.
///
/// Query indexes only locate the immutable artifact commitment. This reader
/// separately requires current-schema support, verified byte availability,
/// strict canonical decoding, and agreement with the requested self-identity.
///
/// # Errors
///
/// Returns a typed engine failure when the commitment is missing, its schema is
/// unsupported, its bytes are unavailable or corrupt, or strict contract
/// reopening fails.
pub fn reopen_diagnostic_artifact(
    store: &Store,
    artifact_id: &Sha256Digest,
) -> Result<SupportedDiagnosticExecution, EngineError> {
    let DiagnosticArtifactLookup::Found(access) =
        store.diagnostic_artifact(artifact_id, SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS)?
    else {
        return Err(EngineError::DiagnosticUnsupported(format!(
            "diagnostic artifact {artifact_id} is not committed"
        )));
    };
    if let DiagnosticArtifactSchemaSupport::Unsupported { contract_schema } = access.schema_support
    {
        return Err(EngineError::DiagnosticUnsupported(format!(
            "diagnostic artifact {artifact_id} uses unsupported contract schema {contract_schema}"
        )));
    }
    let document = match access.byte_state {
        DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes } => canonical_bytes,
        DiagnosticArtifactByteState::CommittedUnavailable => {
            return Err(EngineError::DiagnosticUnsupported(format!(
                "diagnostic artifact {artifact_id} is committed but its exact bytes are unavailable"
            )));
        }
        DiagnosticArtifactByteState::Corrupt { reason } => {
            return Err(EngineError::Invariant(format!(
                "diagnostic artifact {artifact_id} failed byte verification: {reason}"
            )));
        }
    };
    let artifact = SupportedDiagnosticExecution::decode_canonical(document.as_bytes())
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    if artifact.artifact_id().as_digest() != artifact_id {
        return Err(EngineError::Invariant(format!(
            "diagnostic artifact lookup identity {artifact_id} differs from reopened {}",
            artifact.artifact_id().as_digest()
        )));
    }
    Ok(artifact)
}

/// Exact historical diagnostic-artifact reopening counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactHistoryVerification {
    /// Total immutable commitments visited.
    pub commitments: usize,
    /// Current-schema artifacts whose exact bytes reopened strictly.
    pub supported_available: usize,
    /// Current-schema commitments whose bytes are explicitly unavailable.
    pub supported_committed_unavailable: usize,
    /// Available canonical bytes under an unsupported contract schema.
    pub unsupported_available: usize,
    /// Unsupported-schema commitments whose bytes are explicitly unavailable.
    pub unsupported_committed_unavailable: usize,
}

/// Exhaustively verify diagnostic-artifact commitments without fabricating
/// unavailable bytes or interpreting unknown contract schemas.
///
/// # Errors
///
/// Returns on corrupt committed bytes, an invalid current contract, cursor
/// inconsistency, or count overflow.
#[allow(clippy::too_many_lines)] // Keep one exhaustive fail-closed audit over every byte-state branch.
pub fn validate_diagnostic_artifact_history(
    store: &mut Store,
) -> Result<DiagnosticArtifactHistoryVerification, EngineError> {
    let mut verification = DiagnosticArtifactHistoryVerification {
        commitments: 0,
        supported_available: 0,
        supported_committed_unavailable: 0,
        unsupported_available: 0,
        unsupported_committed_unavailable: 0,
    };
    let mut after = None;
    loop {
        let commitments = store
            .diagnostic_artifact_commitments_bounded(nq_store::MAX_PUBLIC_QUERY_ROWS, after)?;
        if commitments.is_empty() {
            return Ok(verification);
        }
        let page_len = commitments.len();
        for commitment in commitments {
            after = Some(commitment.artifact_sequence);
            let DiagnosticArtifactLookup::Found(access) = store.diagnostic_artifact(
                &commitment.artifact_id,
                SUPPORTED_DIAGNOSTIC_EXECUTION_SCHEMAS,
            )?
            else {
                return Err(EngineError::Invariant(format!(
                    "diagnostic artifact index lost commitment {}",
                    commitment.artifact_id
                )));
            };
            match (access.schema_support, access.byte_state) {
                (
                    DiagnosticArtifactSchemaSupport::Supported,
                    DiagnosticArtifactByteState::VerifiedAvailable { .. },
                ) => {
                    let artifact = reopen_diagnostic_artifact(store, &commitment.artifact_id)?;
                    if let DiagnosticArtifactOrigin::Local {
                        run_id,
                        evaluation_id,
                        completed_at,
                        execution_binding_record_id,
                    } = &commitment.origin
                    {
                        let SupportedDiagnosticExecution::V2(local_v2_artifact) = &artifact else {
                            return Err(EngineError::DiagnosticUnsupported(format!(
                                "local diagnostic artifact {} uses frozen v1, whose local semantic correspondence was never retained",
                                commitment.artifact_id
                            )));
                        };
                        if artifact.run_id().as_str() != run_id {
                            return Err(EngineError::Invariant(format!(
                                "local diagnostic artifact {} claims run {} but its durable origin names {run_id}",
                                commitment.artifact_id,
                                artifact.run_id().as_str()
                            )));
                        }
                        if timestamp(local_v2_artifact.completed_at) != *completed_at {
                            return Err(EngineError::Invariant(format!(
                                "local diagnostic artifact {} substitutes its exact completion time",
                                commitment.artifact_id
                            )));
                        }
                        let run = store.watcher_run_outcome(run_id)?.ok_or_else(|| {
                            EngineError::Invariant(format!(
                                "local diagnostic artifact {} origin run {run_id} is missing",
                                commitment.artifact_id
                            ))
                        })?;
                        let production_binding =
                            store.diagnostic_artifact_execution_binding(&commitment.artifact_id)?;
                        if execution_binding_record_id.as_deref()
                            != production_binding
                                .as_ref()
                                .map(|binding| binding.execution_binding.record_id.as_str())
                        {
                            return Err(EngineError::Invariant(format!(
                                "local diagnostic artifact {} production-binding origin differs from its exact runtime-ledger linkage",
                                commitment.artifact_id
                            )));
                        }
                        if let Some(binding) = &production_binding {
                            validate_governed_run_level_v2_origin_shape(
                                local_v2_artifact,
                                evaluation_id.as_deref(),
                            )?;
                            validate_production_v2_execution_binding(
                                store,
                                local_v2_artifact,
                                binding,
                            )?;
                            validate_governed_run_level_v2_history(
                                store,
                                local_v2_artifact,
                                &run,
                                binding,
                            )?;
                        } else {
                            if artifact.profile().id != run.profile_id
                                || artifact.profile().version != run.profile_version
                                || artifact.profile().digest.as_str() != run.profile_digest
                            {
                                return Err(EngineError::Invariant(format!(
                                    "local diagnostic artifact {} substitutes its profile origin",
                                    commitment.artifact_id
                                )));
                            }
                            if artifact.request_id().as_str() != run.request_id {
                                return Err(EngineError::Invariant(format!(
                                    "pre-production local diagnostic artifact {} substitutes its child provider request origin",
                                    commitment.artifact_id
                                )));
                            }
                            let local_v2_context = validate_local_v2_provider_correspondence(
                                store, &artifact, &run, None,
                            )?;
                            if let Some(evaluation_id) = evaluation_id {
                                let admitted =
                                    store.admitted_collection_for_run(run_id)?.ok_or_else(|| {
                                        EngineError::Invariant(format!(
                                            "local diagnostic artifact {} origin run {run_id} is not one admitted collection",
                                            commitment.artifact_id
                                        ))
                                    })?;
                                if admitted.evaluations != 1 {
                                    return Err(EngineError::Invariant(format!(
                                        "local diagnostic artifact {} requires exactly one origin evaluation; durable run {run_id} has {}",
                                        commitment.artifact_id, admitted.evaluations
                                    )));
                                }
                                let evaluation =
                                    store.evaluation_origin(evaluation_id)?.ok_or_else(|| {
                                        EngineError::Invariant(format!(
                                            "local diagnostic artifact {} origin evaluation {evaluation_id} is missing",
                                            commitment.artifact_id
                                        ))
                                    })?;
                                if evaluation.trigger_run_id.as_deref() != Some(run_id.as_str()) {
                                    return Err(EngineError::Invariant(format!(
                                        "local diagnostic artifact {} origin evaluation {evaluation_id} does not belong to run {run_id}",
                                        commitment.artifact_id
                                    )));
                                }
                                let envelope = reopen_exact_evaluation(store, &evaluation)?;
                                validate_evaluated_diagnostic_correspondence(
                                    store,
                                    &artifact,
                                    &run,
                                    &local_v2_context,
                                    &envelope,
                                )?;
                            } else {
                                validate_run_only_diagnostic_correspondence(
                                    store,
                                    &artifact,
                                    run_id,
                                    &local_v2_context,
                                )?;
                            }
                        }
                    }
                    verification.supported_available = verification
                        .supported_available
                        .checked_add(1)
                        .ok_or_else(|| {
                            EngineError::Invariant(
                                "diagnostic artifact verification count overflowed".into(),
                            )
                        })?;
                }
                (
                    DiagnosticArtifactSchemaSupport::Supported,
                    DiagnosticArtifactByteState::CommittedUnavailable,
                ) => {
                    verification.supported_committed_unavailable = verification
                        .supported_committed_unavailable
                        .checked_add(1)
                        .ok_or_else(|| {
                            EngineError::Invariant(
                                "diagnostic artifact verification count overflowed".into(),
                            )
                        })?;
                }
                (
                    DiagnosticArtifactSchemaSupport::Unsupported { .. },
                    DiagnosticArtifactByteState::VerifiedAvailable { .. },
                ) => {
                    verification.unsupported_available = verification
                        .unsupported_available
                        .checked_add(1)
                        .ok_or_else(|| {
                            EngineError::Invariant(
                                "diagnostic artifact verification count overflowed".into(),
                            )
                        })?;
                }
                (
                    DiagnosticArtifactSchemaSupport::Unsupported { .. },
                    DiagnosticArtifactByteState::CommittedUnavailable,
                ) => {
                    verification.unsupported_committed_unavailable = verification
                        .unsupported_committed_unavailable
                        .checked_add(1)
                        .ok_or_else(|| {
                            EngineError::Invariant(
                                "diagnostic artifact verification count overflowed".into(),
                            )
                        })?;
                }
                (_, DiagnosticArtifactByteState::Corrupt { reason }) => {
                    return Err(EngineError::Invariant(format!(
                        "diagnostic artifact {} failed byte verification: {reason}",
                        commitment.artifact_id
                    )));
                }
            }
            verification.commitments =
                verification.commitments.checked_add(1).ok_or_else(|| {
                    EngineError::Invariant(
                        "diagnostic artifact verification count overflowed".into(),
                    )
                })?;
        }
        if page_len < nq_store::MAX_PUBLIC_QUERY_ROWS as usize {
            return Ok(verification);
        }
    }
}

fn runtime_record_value(
    record: &nq_store::RuntimeRecordRow,
    purpose: &str,
) -> Result<Value, EngineError> {
    serde_json::from_slice(record.canonical_bytes.as_bytes()).map_err(|error| {
        EngineError::Invariant(format!(
            "{purpose} runtime record {} cannot decode: {error}",
            record.record_id
        ))
    })
}

fn required_object_field<'a>(
    value: &'a Value,
    field: &str,
    purpose: &str,
) -> Result<&'a serde_json::Map<String, Value>, EngineError> {
    value.get(field).and_then(Value::as_object).ok_or_else(|| {
        EngineError::Invariant(format!("{purpose} has no required object field {field}"))
    })
}

fn required_string_field<'a>(
    value: &'a Value,
    field: &str,
    purpose: &str,
) -> Result<&'a str, EngineError> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        EngineError::Invariant(format!("{purpose} has no required string field {field}"))
    })
}

fn runtime_reference_matches(reference: &Value, record: &nq_store::RuntimeRecordRow) -> bool {
    reference.as_object().is_some_and(|object| {
        object.get("schema").and_then(Value::as_str) == Some(record.record_schema.as_str())
            && object.get("record_id").and_then(Value::as_str) == Some(record.record_id.as_str())
            && object.get("bytes_digest").and_then(Value::as_str)
                == Some(record.canonical_bytes_sha256.as_str())
    })
}

fn reopen_runtime_reference(
    store: &Store,
    reference: &Value,
    purpose: &str,
) -> Result<nq_store::RuntimeRecordRow, EngineError> {
    let record_id = required_string_field(reference, "record_id", purpose)?;
    let record = store.runtime_record(record_id)?.ok_or_else(|| {
        EngineError::Invariant(format!(
            "{purpose} references missing immutable runtime record {record_id}"
        ))
    })?;
    if !runtime_reference_matches(reference, &record) {
        return Err(EngineError::Invariant(format!(
            "{purpose} substitutes the schema or exact bytes of runtime record {record_id}"
        )));
    }
    Ok(record)
}

fn contract_identity_matches(
    value: &Value,
    expected_kind: &str,
    identity: &SemanticIdentityV1,
) -> bool {
    value.as_object().is_some_and(|object| {
        object.get("kind").and_then(Value::as_str) == Some(expected_kind)
            && object.get("id").and_then(Value::as_str) == Some(identity.id.as_str())
            && object.get("version").and_then(Value::as_str) == Some(identity.version.as_str())
            && object.get("descriptor_digest").and_then(Value::as_str)
                == Some(identity.digest.as_str())
    })
}

fn contract_identities_equal(left: &Value, right: &Value) -> bool {
    left.is_object()
        && right.is_object()
        && ["kind", "id", "version", "descriptor_digest"]
            .into_iter()
            .all(|field| {
                left.get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| right.get(field).and_then(Value::as_str) == Some(value))
            })
}

fn resolved_binding_identity<'a>(
    binding_value: &'a Value,
    name: &str,
    artifact_id: &str,
) -> Result<&'a Value, EngineError> {
    required_object_field(
        binding_value,
        "resolved_references",
        "production execution binding",
    )?
    .get(name)
    .and_then(|resolved| resolved.get("identity"))
    .ok_or_else(|| {
        EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} binding has no resolved {name} identity"
        ))
    })
}

fn validate_historical_topology_relation(
    store: &Store,
    artifact_id: &str,
    activation_relations: &serde_json::Map<String, Value>,
    binding_relations: &serde_json::Map<String, Value>,
    relation: (&str, &str),
    expected_left: &Value,
    expected_right: &Value,
) -> Result<(), EngineError> {
    let (field, relation_kind) = relation;
    let activation_reference = activation_relations.get(field).ok_or_else(|| {
        EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} activation has no {field} relation"
        ))
    })?;
    let binding_reference = binding_relations.get(field).ok_or_else(|| {
        EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} binding has no {field} source relation"
        ))
    })?;
    if activation_reference != binding_reference {
        return Err(EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} substitutes its {field} relation between activation and binding"
        )));
    }
    let relation = reopen_runtime_reference(
        store,
        activation_reference,
        "production execution topology relation",
    )?;
    let relation_value = runtime_record_value(&relation, "production execution topology relation")?;
    if relation.record_schema != "nq.host_role_relation.v1"
        || relation_value.get("relation_id").and_then(Value::as_str)
            != Some(relation.record_id.as_str())
        || relation_value.get("relation_kind").and_then(Value::as_str) != Some(relation_kind)
        || !relation_value
            .get("left")
            .is_some_and(|left| contract_identities_equal(left, expected_left))
        || !relation_value
            .get("right")
            .is_some_and(|right| contract_identities_equal(right, expected_right))
    {
        return Err(EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} {field} relation does not recover its exact {relation_kind} endpoints"
        )));
    }
    Ok(())
}

/// Verify the exact historical production companion for a local V2 artifact.
///
/// This deliberately follows only immutable record references named by the
/// execution binding. It never consults a current role, cohort, enrollment, or
/// topology projection, so later rehome, retirement, or generation changes
/// cannot reinterpret the execution.
#[allow(clippy::too_many_lines)]
fn validate_production_v2_execution_binding(
    store: &Store,
    artifact: &DiagnosticExecutionV2,
    binding: &nq_store::DiagnosticArtifactExecutionBinding,
) -> Result<(), EngineError> {
    let artifact_id = artifact.artifact_id.0.as_str();
    let binding_value =
        runtime_record_value(&binding.execution_binding, "production execution binding")?;
    let request_value = runtime_record_value(&binding.outer_request, "outer diagnostic request")?;
    let decision_value = runtime_record_value(&binding.invocation_decision, "invocation decision")?;
    let launch_value = runtime_record_value(&binding.execution_launch, "execution launch")?;

    if binding.execution_binding.record_schema != "nq.execution_identity_binding.v2"
        || binding.outer_request.record_schema != "nq.diagnostic_invocation_request.v1"
        || binding.invocation_decision.record_schema != "nq.invocation_decision.v1"
        || binding.execution_launch.record_schema != "nq.execution_launch.v1"
        || binding_value.get("binding_id").and_then(Value::as_str)
            != Some(binding.execution_binding.record_id.as_str())
        || binding_value.get("binding_result").and_then(Value::as_str) != Some("resolved")
        || decision_value.get("decision").and_then(Value::as_str) != Some("accepted")
        || launch_value.get("status").and_then(Value::as_str) != Some("launched")
    {
        return Err(EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} is linked to a non-resolved, non-accepted, or non-launched invocation"
        )));
    }
    for (reference, record, purpose) in [
        (
            binding_value.get("outer_request"),
            &binding.outer_request,
            "outer request",
        ),
        (
            binding_value.get("invocation_decision"),
            &binding.invocation_decision,
            "invocation decision",
        ),
        (
            binding_value.get("execution_launch"),
            &binding.execution_launch,
            "execution launch",
        ),
        (
            decision_value.get("request"),
            &binding.outer_request,
            "decision request",
        ),
        (
            launch_value.get("outer_request"),
            &binding.outer_request,
            "launch request",
        ),
        (
            launch_value.get("invocation_decision"),
            &binding.invocation_decision,
            "launch decision",
        ),
    ] {
        if !reference.is_some_and(|reference| runtime_reference_matches(reference, record)) {
            return Err(EngineError::Invariant(format!(
                "production diagnostic artifact {artifact_id} substitutes its exact {purpose} linkage"
            )));
        }
    }
    let request_id =
        required_string_field(&request_value, "request_id", "outer diagnostic request")?;
    let request_digest =
        required_string_field(&request_value, "request_digest", "outer diagnostic request")?;
    if request_id != binding.outer_request_id
        || artifact.request_id.as_str() != binding.outer_request_id
        || request_digest != binding.outer_request.record_id
        || decision_value.get("request_digest").and_then(Value::as_str)
            != Some(binding.outer_request.record_id.as_str())
    {
        return Err(EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} substitutes its exact outer request identity"
        )));
    }

    let node = resolved_binding_identity(&binding_value, "node", artifact_id)?;
    let subject = resolved_binding_identity(&binding_value, "subject", artifact_id)?;
    let vantage = resolved_binding_identity(&binding_value, "vantage", artifact_id)?;
    let cohort = resolved_binding_identity(&binding_value, "static_profile_cohort", artifact_id)?;
    let profile = resolved_binding_identity(&binding_value, "diagnostic_profile", artifact_id)?;
    let role = resolved_binding_identity(&binding_value, "role", artifact_id)?;
    let platform = resolved_binding_identity(&binding_value, "platform", artifact_id)?;
    if node.get("kind").and_then(Value::as_str) != Some("nq_node")
        || node.get("id").and_then(Value::as_str) != Some(artifact.producer.node_id.as_str())
        || subject.get("kind").and_then(Value::as_str) != Some("subject")
        || subject.get("id").and_then(Value::as_str) != Some(artifact.subject.id.as_str())
        || !contract_identity_matches(vantage, "vantage", &artifact.vantage)
        || !contract_identity_matches(cohort, "static_cohort", &artifact.producer.cohort)
        || !contract_identity_matches(profile, "diagnostic_profile", &artifact.profile)
    {
        return Err(EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} substitutes its resolved node, subject, vantage, cohort, or profile identity"
        )));
    }

    let target =
        required_object_field(&request_value, "target", "outer diagnostic request target")?;
    for (field, expected) in [("node", node), ("subject", subject), ("vantage", vantage)] {
        let actual = target.get(field).ok_or_else(|| {
            EngineError::Invariant(format!(
                "production diagnostic artifact {artifact_id} outer request has no target {field}"
            ))
        })?;
        if !contract_identities_equal(actual, expected) {
            return Err(EngineError::Invariant(format!(
                "production diagnostic artifact {artifact_id} outer request target {field} differs from its resolved execution binding"
            )));
        }
    }
    let requested_profile = request_value.get("profile").ok_or_else(|| {
        EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} outer request has no profile"
        ))
    })?;
    if !contract_identities_equal(requested_profile, profile) {
        return Err(EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} outer request profile differs from its resolved execution binding"
        )));
    }

    let activation_reference = binding_value.get("activation").ok_or_else(|| {
        EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} binding has no activation reference"
        ))
    })?;
    let activation = reopen_runtime_reference(
        store,
        activation_reference,
        "production execution activation",
    )?;
    if activation.record_schema != "nq.runtime_activation.v1" {
        return Err(EngineError::Invariant(format!(
            "production diagnostic artifact {artifact_id} uses an incompatible activation record"
        )));
    }
    let activation_value = runtime_record_value(&activation, "production execution activation")?;
    for (field, expected) in [
        ("node", node),
        ("static_profile_cohort", cohort),
        ("role", role),
    ] {
        let actual = activation_value.get(field).ok_or_else(|| {
            EngineError::Invariant(format!(
                "production diagnostic artifact {artifact_id} activation has no {field} identity"
            ))
        })?;
        if !contract_identities_equal(actual, expected) {
            return Err(EngineError::Invariant(format!(
                "production diagnostic artifact {artifact_id} activation {field} differs from its resolved historical binding"
            )));
        }
    }
    let activation_relations = required_object_field(
        &activation_value,
        "relations",
        "production execution activation",
    )?;
    let binding_relations = required_object_field(
        &binding_value,
        "source_relations",
        "production execution binding",
    )?;
    validate_historical_topology_relation(
        store,
        artifact_id,
        activation_relations,
        binding_relations,
        ("node_subject", "node_subject"),
        node,
        subject,
    )?;
    validate_historical_topology_relation(
        store,
        artifact_id,
        activation_relations,
        binding_relations,
        ("subject_platform", "subject_platform"),
        subject,
        platform,
    )?;
    validate_historical_topology_relation(
        store,
        artifact_id,
        activation_relations,
        binding_relations,
        ("node_vantage", "node_vantage"),
        node,
        vantage,
    )?;
    validate_historical_topology_relation(
        store,
        artifact_id,
        activation_relations,
        binding_relations,
        ("node_role", "node_role"),
        node,
        role,
    )?;
    validate_historical_topology_relation(
        store,
        artifact_id,
        activation_relations,
        binding_relations,
        ("node_static_profile_cohort", "node_static_profile_cohort"),
        node,
        cohort,
    )?;
    Ok(())
}

fn historical_runtime_reference(
    row: &nq_store::RuntimeRecordRow,
    purpose: &str,
) -> Result<RecordRef, EngineError> {
    Ok(RecordRef {
        schema: nq_host_role_contract::Token::parse(row.record_schema.clone()).map_err(
            |error| {
                EngineError::Invariant(format!(
                    "{purpose} runtime schema is not a contract token: {error}"
                ))
            },
        )?,
        record_id: Sha256Digest::parse(row.record_id.clone()).map_err(|error| {
            EngineError::Invariant(format!(
                "{purpose} runtime identity is not SHA-256: {error}"
            ))
        })?,
        bytes_digest: row.canonical_bytes_sha256.clone(),
    })
}

fn reopen_historical_runtime_snapshot(
    store: &Store,
    checkpoint: &nq_store::RuntimeLedgerCheckpoint,
) -> Result<nq_host_role_contract::RuntimeRecordSet, EngineError> {
    let mut records = nq_host_role_contract::RuntimeRecordSet::new();
    let mut after = 0;
    loop {
        let page =
            store.runtime_record_page(Some(checkpoint), after, nq_store::MAX_PUBLIC_QUERY_ROWS)?;
        if page.checkpoint.as_ref() != Some(checkpoint) {
            return Err(EngineError::Invariant(format!(
                "historical runtime snapshot substituted exact checkpoint {}",
                checkpoint.checkpoint_id
            )));
        }
        for row in &page.records {
            let validated = ValidatedRuntimeRecord::decode_canonical(
                row.canonical_bytes.as_bytes(),
            )
            .map_err(|error| {
                EngineError::Invariant(format!(
                    "historical runtime record {} failed typed reopening: {error}",
                    row.record_id
                ))
            })?;
            let reference = historical_runtime_reference(row, "historical runtime record")?;
            if validated.exact_reference() != reference {
                return Err(EngineError::Invariant(format!(
                    "historical runtime record {} substituted its schema, identity, or exact bytes",
                    row.record_id
                )));
            }
            records.insert(validated).map_err(|error| {
                EngineError::Invariant(format!(
                    "historical runtime snapshot at {} refused record {}: {error}",
                    checkpoint.checkpoint_id, row.record_id
                ))
            })?;
        }
        if page.complete {
            return Ok(records);
        }
        let next = page.next_after_record_sequence.ok_or_else(|| {
            EngineError::Invariant(format!(
                "historical runtime snapshot at {} omitted its next exact cursor",
                checkpoint.checkpoint_id
            ))
        })?;
        if next <= after {
            return Err(EngineError::Invariant(format!(
                "historical runtime snapshot at {} did not advance its exact cursor",
                checkpoint.checkpoint_id
            )));
        }
        after = next;
    }
}

fn production_identity_matches_semantic(
    production: &IdentityRef,
    semantic: &SemanticIdentityV1,
) -> bool {
    production.id.as_str() == semantic.id
        && production.version.as_str() == semantic.version
        && production.descriptor_digest == semantic.digest
}

fn validate_governed_native_request_correspondence(
    artifact_id: &str,
    outer_request_id: &str,
    launch_reference: &RecordRef,
    provider_request_id: &str,
    run_request_id: &str,
) -> Result<(), EngineError> {
    let expected_child_request =
        native_child_request_id(outer_request_id, launch_reference).map_err(|error| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} cannot recover its exact native child request: {}",
                error.detail
            ))
        })?;
    if provider_request_id != expected_child_request.as_str()
        || run_request_id != expected_child_request.as_str()
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} substitutes its exact native child request"
        )));
    }
    Ok(())
}

fn validate_governed_attempt_deadline_correspondence(
    artifact_id: &str,
    provider_deadline: DateTime<Utc>,
    launch_deadline: &str,
) -> Result<(), EngineError> {
    let launch_deadline = DateTime::parse_from_rfc3339(launch_deadline)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} launch attempt deadline is not an RFC 3339 instant: {error}"
            ))
        })?;
    if provider_deadline != launch_deadline {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} substitutes its exact launch attempt deadline"
        )));
    }
    Ok(())
}

fn validate_governed_run_level_v2_origin_shape(
    artifact: &DiagnosticExecutionV2,
    evaluation_id: Option<&str>,
) -> Result<(), EngineError> {
    let artifact_id = artifact.artifact_id.0.as_str();
    if evaluation_id.is_some() {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} claims a detector evaluation"
        )));
    }
    let expected_native_semantic =
        profile_semantic_id(nq_profiles::conformance::MODULE.descriptor())
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
    if artifact.profile_semantic_id.as_str() != expected_native_semantic.as_str() {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} is not bound to canonical nq.conformance/v1 semantics"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_governed_run_level_v2_history(
    store: &mut Store,
    artifact: &DiagnosticExecutionV2,
    run: &nq_store::WatcherRunOutcomeRow,
    binding: &nq_store::DiagnosticArtifactExecutionBinding,
) -> Result<(), EngineError> {
    let artifact_id = artifact.artifact_id.0.as_str();
    let expected_native_profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
    let expected_native_descriptor = expected_native_profile.descriptor();
    let expected_native_digest = expected_native_descriptor
        .digest()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let expected_native_semantic = profile_semantic_id(expected_native_descriptor)
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    if let Some(admitted) = store.admitted_collection_for_run(&run.run_id)?
        && admitted.evaluations != 0
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} has {} detector evaluations",
            admitted.evaluations
        )));
    }

    let launch_checkpoint = store
        .runtime_checkpoint_by_id(&binding.execution_launch.checkpoint_id)?
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} lost exact launch checkpoint {}",
                binding.execution_launch.checkpoint_id
            ))
        })?;
    if binding.execution_launch.record_sequence < launch_checkpoint.first_record_sequence
        || binding.execution_launch.record_sequence > launch_checkpoint.last_record_sequence
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} launch is outside its exact historical checkpoint"
        )));
    }
    let runtime = reopen_historical_runtime_snapshot(store, &launch_checkpoint)?;
    let launch_reference =
        historical_runtime_reference(&binding.execution_launch, "production execution launch")?;
    let launch_value = runtime_record_value(
        &binding.execution_launch,
        "production governed execution launch",
    )?;
    let selection = runtime
        .select_launch_correspondence(&launch_reference)
        .map_err(|error| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} failed exact typed launch correspondence: {error}"
            ))
        })?;
    runtime
        .require_effective_launch_lifecycle(&launch_reference)
        .map_err(|error| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} failed historical launch lifecycle: {error}"
            ))
        })?;
    if selection.launch() != &launch_reference
        || selection.outer_request()
            != &historical_runtime_reference(&binding.outer_request, "production outer request")?
        || !production_identity_matches_semantic(
            selection.production_question(),
            &artifact.question,
        )
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} substitutes its exact launch, request, or bounded question"
        )));
    }

    let qualifier = runtime
        .get(&selection.native_profile_qualification().record_id)
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} lost its exact native profile qualifier"
            ))
        })?;
    if qualifier.exact_reference() != *selection.native_profile_qualification() {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} substitutes its native profile qualifier bytes"
        )));
    }
    let qualifier_value = qualifier.record().as_value();
    let native_profile = required_object_field(
        qualifier_value,
        "native_profile",
        "historical native profile qualification",
    )?;
    let native_profile_value = Value::Object(native_profile.clone());
    let detector_closure = required_object_field(
        &native_profile_value,
        "detector_closure",
        "historical native profile qualification",
    )?;
    let qualified_production_profile: IdentityRef = serde_json::from_value(
        qualifier_value
            .get("production_profile")
            .cloned()
            .ok_or_else(|| {
                EngineError::Invariant(
                    "historical native profile qualification has no production profile".into(),
                )
            })?,
    )
    .map_err(|error| {
        EngineError::Invariant(format!(
            "historical production profile identity is malformed: {error}"
        ))
    })?;
    let qualified_question: IdentityRef = serde_json::from_value(
        qualifier_value
            .get("production_question")
            .cloned()
            .ok_or_else(|| {
                EngineError::Invariant(
                    "historical native profile qualification has no production question".into(),
                )
            })?,
    )
    .map_err(|error| {
        EngineError::Invariant(format!(
            "historical production question identity is malformed: {error}"
        ))
    })?;
    if native_profile.get("profile_id").and_then(Value::as_str)
        != Some(nq_profiles::conformance::PROFILE_ID)
        || native_profile
            .get("profile_version")
            .and_then(Value::as_u64)
            != Some(u64::from(nq_profiles::conformance::PROFILE_VERSION))
        || native_profile
            .get("descriptor_digest")
            .and_then(Value::as_str)
            != Some(expected_native_digest.as_str())
        || native_profile
            .get("semantic_identity_digest")
            .and_then(Value::as_str)
            != Some(expected_native_semantic.as_str())
        || detector_closure
            .get("detector_count")
            .and_then(Value::as_u64)
            != Some(0)
        || !production_identity_matches_semantic(&qualified_production_profile, &artifact.profile)
        || !production_identity_matches_semantic(&qualified_question, &artifact.question)
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} does not preserve its exact zero-detector nq.conformance/v1 qualification"
        )));
    }

    let [(provider_record, attempt)] = binding.provider_attempts.as_slice() else {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} is not bound to exactly one provider occurrence"
        )));
    };
    let intake_row = store.provider_intake(&attempt.intake_id)?.ok_or_else(|| {
        EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} lost provider intake {}",
            attempt.intake_id
        ))
    })?;
    let raw = store
        .provider_intake_raw_bytes(&attempt.intake_id)?
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} lost raw custody for provider intake {}",
                attempt.intake_id
            ))
        })?;
    let provider_intake = ProviderIntakeRecordV1::reopen_store_row(&intake_row, &raw)?;
    let provider_document = CanonicalDocument::from_serializable(&provider_intake)?;
    validate_governed_native_request_correspondence(
        artifact_id,
        artifact.request_id.as_str(),
        &launch_reference,
        &provider_intake.request_id,
        &run.request_id,
    )?;
    let launch_attempt_deadline = launch_value
        .get("attempt_deadline")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} launch has no attempt deadline"
            ))
        })?;
    let launch_started_at = launch_value
        .get("launched_at")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} launch has no start instant"
            ))
        })
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|error| {
                    EngineError::Invariant(format!(
                        "production run-level diagnostic artifact {artifact_id} launch start is not an RFC 3339 instant: {error}"
                    ))
                })
        })?;
    validate_governed_attempt_deadline_correspondence(
        artifact_id,
        provider_intake.deadline_at,
        launch_attempt_deadline,
    )?;
    if provider_record.record_schema != "nq.provider_intake.v1"
        || provider_record.record_id != intake_row.intake_digest
        || provider_record.canonical_bytes != provider_document
        || provider_intake.run_id != run.run_id
        || provider_intake.intake_id != attempt.intake_id
        || provider_intake.request.profile.id.as_str() != nq_profiles::conformance::PROFILE_ID
        || provider_intake.request.profile.version.as_str()
            != nq_profiles::conformance::PROFILE_VERSION.to_string()
        || provider_intake.request.profile.digest.as_str() != expected_native_digest.as_str()
        || provider_intake.provider.profile_semantic_id.as_str()
            != expected_native_semantic.as_str()
        || run.profile_id != nq_profiles::conformance::PROFILE_ID
        || run.profile_version != nq_profiles::conformance::PROFILE_VERSION.to_string()
        || run.profile_digest != expected_native_digest.as_str()
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} substitutes its exact native provider occurrence"
        )));
    }
    let contributing_intakes = artifact
        .inputs
        .received
        .iter()
        .map(|input| input.provider_intake_id.as_str())
        .chain(
            artifact
                .inputs
                .failed
                .iter()
                .filter_map(|input| match &input.cause {
                    FailedInputCauseV2::ProviderNoResponse {
                        provider_intake_id, ..
                    }
                    | FailedInputCauseV2::AcquisitionFailed {
                        provider_intake_id, ..
                    } => Some(provider_intake_id.as_str()),
                    FailedInputCauseV2::Missing { .. } | FailedInputCauseV2::Unsupported { .. } => {
                        None
                    }
                }),
        )
        .collect::<BTreeSet<_>>();
    if contributing_intakes != BTreeSet::from([provider_intake.intake_id.as_str()]) {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} substitutes its contributing provider-intake identity"
        )));
    }
    if artifact.started_at != launch_started_at {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} start differs from its exact governed launch"
        )));
    }
    if artifact.attempt_interval.started_at != provider_intake.started_at
        || artifact.attempt_interval.ended_at != provider_intake.finished_at
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} attempt interval differs from its provider-intake acquisition"
        )));
    }
    if artifact.completed_at != provider_intake.received_at {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} completion differs from its provider-intake receipt"
        )));
    }
    validate_provider_interpretation_derivation(&provider_intake, artifact)?;

    let reservation_reference = launch_value.get("custody_reservation").ok_or_else(|| {
        EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} launch has no custody reservation"
        ))
    })?;
    let reservation_record = reopen_runtime_reference(
        store,
        reservation_reference,
        "production governed custody reservation",
    )?;
    let reservation_id = Sha256Digest::parse(reservation_record.record_id.clone())
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let inventory = store.governed_custody_inventory()?;
    let matching = inventory
        .iter()
        .filter_map(|entry| match entry {
            nq_store::GovernedCustodyInventoryEntry::Verified(inspection)
                if inspection.reservation_record_id == reservation_id =>
            {
                Some(inspection.as_ref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [inspection] = matching.as_slice() else {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} has {} verified custody frontiers for reservation {reservation_id}",
            matching.len()
        )));
    };
    if inspection.state != nq_store::GovernedCustodyState::FinalClosureIndexed
        || inspection.execution_launch_record_id.as_ref() != Some(&launch_reference.record_id)
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} governed custody is not one already-indexed exact launch closure"
        )));
    }
    let projection = store
        .begin_writer_session()?
        .verify_governed_projection_and_mark_indexed(&reservation_id)?;
    if projection.disposition != nq_store::GovernedProjectionVerificationDisposition::AlreadyIndexed
        || projection.diagnostic_artifact_id != artifact.artifact_id.0
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} governed projection is not the already-indexed exact artifact"
        )));
    }
    let terminal_checkpoint = store
        .runtime_checkpoint_by_id(projection.runtime_checkpoint_id.as_str())?
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "production run-level diagnostic artifact {artifact_id} lost exact terminal checkpoint {}",
                projection.runtime_checkpoint_id
            ))
        })?;
    if terminal_checkpoint.predecessor_checkpoint_id.as_deref()
        != Some(launch_checkpoint.checkpoint_id.as_str())
        || binding.execution_binding.checkpoint_id != terminal_checkpoint.checkpoint_id
        || provider_record.checkpoint_id != terminal_checkpoint.checkpoint_id
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} substitutes its exact launch or terminal checkpoint"
        )));
    }
    let terminal_page = store.runtime_record_page(
        Some(&terminal_checkpoint),
        launch_checkpoint.last_record_sequence,
        nq_store::MAX_PUBLIC_QUERY_ROWS,
    )?;
    let terminal_ids = terminal_page
        .records
        .iter()
        .map(|row| row.record_id.as_str())
        .collect::<Vec<_>>();
    if !terminal_page.complete
        || terminal_ids
            != [
                provider_record.record_id.as_str(),
                binding.execution_binding.record_id.as_str(),
            ]
    {
        return Err(EngineError::Invariant(format!(
            "production run-level diagnostic artifact {artifact_id} terminal checkpoint membership is incomplete or reordered"
        )));
    }
    Ok(())
}

struct LocalV2HistoryContext {
    provider_intake: ProviderIntakeRecordV1,
    capture_policy: SemanticIdentityV1,
    admission_rule: SemanticIdentityV1,
    normalization_rule: SemanticIdentityV1,
    question: SemanticIdentityV1,
}

fn validate_provider_interpretation_derivation(
    provider_intake: &ProviderIntakeRecordV1,
    artifact: &DiagnosticExecutionV2,
) -> Result<(), EngineError> {
    let provider_refused = matches!(
        &provider_intake.interpretation,
        ProviderResponseInterpretationV1::ProtocolRejected { .. }
            | ProviderResponseInterpretationV1::Validated {
                response: nq_protocol::HelperResponse {
                    outcome: ResponseOutcome::Refusal { .. },
                    ..
                },
            }
    );
    if provider_refused
        && (artifact.outcome.derivation != DiagnosticDerivationV1::Refused
            || artifact
                .claims
                .iter()
                .any(|claim| !matches!(claim.status, DiagnosticClaimStatusV1::Unknown))
            || artifact.inputs.refused.iter().all(|input| {
                artifact
                    .inputs
                    .received
                    .iter()
                    .find(|received| received.input_id == input.input_id)
                    .is_none_or(|received| received.provider_intake_id != provider_intake.intake_id)
            })
            || !artifact.inputs.admitted.is_empty()
            || !artifact.inputs.selected.is_empty())
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} turns an explicit provider refusal into a determinate or admitted result",
            artifact.artifact_id.0
        )));
    }
    if matches!(
        provider_intake.interpretation,
        ProviderResponseInterpretationV1::NotAvailable
    ) && artifact.outcome.derivation == DiagnosticDerivationV1::Completed
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} turns provider no-response into a completed result",
            artifact.artifact_id.0
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_local_v2_provider_correspondence(
    store: &Store,
    artifact: &SupportedDiagnosticExecution,
    run: &nq_store::WatcherRunOutcomeRow,
    production_binding: Option<&nq_store::DiagnosticArtifactExecutionBinding>,
) -> Result<LocalV2HistoryContext, EngineError> {
    let SupportedDiagnosticExecution::V2(artifact) = artifact else {
        return Err(EngineError::DiagnosticUnsupported(
            "local semantic correspondence requires the v2 execution contract".into(),
        ));
    };
    let run_id = run.run_id.as_str();
    let mut provider_intake_ids = BTreeSet::new();
    for input in &artifact.inputs.received {
        provider_intake_ids.insert(input.provider_intake_id.as_str());
    }
    for input in &artifact.inputs.failed {
        match &input.cause {
            FailedInputCauseV2::ProviderNoResponse {
                provider_intake_id, ..
            }
            | FailedInputCauseV2::AcquisitionFailed {
                provider_intake_id, ..
            } => {
                provider_intake_ids.insert(provider_intake_id.as_str());
            }
            FailedInputCauseV2::Missing { .. } | FailedInputCauseV2::Unsupported { .. } => {}
        }
    }
    let [provider_intake_id] = provider_intake_ids.iter().copied().collect::<Vec<_>>()[..] else {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} does not identify exactly one provider intake",
            artifact.artifact_id.0
        )));
    };
    let intake = store.provider_intake(provider_intake_id)?.ok_or_else(|| {
        EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} references missing provider intake {provider_intake_id}",
            artifact.artifact_id.0
        ))
    })?;
    if intake.run_id != run_id
        || intake.profile_id != artifact.profile.id
        || intake.profile_version != artifact.profile.version
        || intake.profile_digest != artifact.profile.digest.as_str()
        || intake.profile_semantic_id != artifact.profile_semantic_id.as_str()
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes provider-intake origin identity",
            artifact.artifact_id.0
        )));
    }
    let raw = store
        .provider_intake_raw_bytes(provider_intake_id)?
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "provider intake {provider_intake_id} lost its raw-custody record"
            ))
        })?;
    let provider_intake = ProviderIntakeRecordV1::reopen_store_row(&intake, &raw)?;
    match production_binding {
        None if intake.request_id != artifact.request_id.as_str() => {
            return Err(EngineError::Invariant(format!(
                "pre-production local v2 diagnostic artifact {} substitutes its child provider request identity",
                artifact.artifact_id.0
            )));
        }
        Some(binding) => {
            if intake.request_id == artifact.request_id.as_str()
                || binding.provider_attempts.len() != 1
                || binding.provider_attempts[0].1.intake_id != provider_intake.intake_id
            {
                return Err(EngineError::Invariant(format!(
                    "production local v2 diagnostic artifact {} collapses or substitutes its outer request and exact child provider attempt",
                    artifact.artifact_id.0
                )));
            }
            let provider_record = &binding.provider_attempts[0].0;
            let exact_provider_document = CanonicalDocument::from_serializable(&provider_intake)?;
            if provider_record.record_id != intake.intake_digest
                || provider_record.record_schema != "nq.provider_intake.v1"
                || provider_record.canonical_bytes != exact_provider_document
            {
                return Err(EngineError::Invariant(format!(
                    "production local v2 diagnostic artifact {} substitutes its exact provider-intake runtime record",
                    artifact.artifact_id.0
                )));
            }
        }
        None => {}
    }
    let request = &provider_intake.request;
    let request_subject = request.binding.subject.to_string();
    let scope = ScopeConfig {
        kind: request.binding.scope.kind.to_string(),
        value: request.binding.scope.value.clone(),
    };
    let vantage = VantageConfig {
        kind: request.binding.vantage.kind.to_string(),
        value: request.binding.vantage.value.clone(),
    };
    if request.instance_id.as_str() != run.instance_id
        || request_subject != artifact.subject.id
        || request.profile.id.as_str() != artifact.profile.id
        || request.profile.version.as_str() != artifact.profile.version
        || request.profile.digest != artifact.profile.digest
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes its exact provider request binding",
            artifact.artifact_id.0
        )));
    }
    let admission_id = run.admission_id.as_deref().ok_or_else(|| {
        EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} has no source admission",
            artifact.artifact_id.0
        ))
    })?;
    let admission = store.admission(admission_id)?.ok_or_else(|| {
        EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} source admission {admission_id} is missing",
            artifact.artifact_id.0
        ))
    })?;
    if provider_intake.provider.source_admission_id != admission_id
        || provider_intake.provider.evaluator_artifact_digest.as_str()
            != admission.evaluator_artifact_digest
        || provider_intake.provider.profile_semantic_id.as_str() != admission.profile_semantic_id
        || artifact.profile_semantic_id.as_str() != admission.profile_semantic_id
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes its admitted judging context",
            artifact.artifact_id.0
        )));
    }

    let node_id = format!("nq-store-genesis:{}", store.sole_genesis_id()?);
    let profile_identity = SemanticIdentityV1 {
        id: request.profile.id.to_string(),
        version: request.profile.version.to_string(),
        digest: request.profile.digest.clone(),
    };
    let expected_question = initial_local_v2_question(&admission.detector_identity_digest)?;
    let historical_surface = local_v2_historical_surface(
        &profile_identity,
        &expected_question,
        &admission.evaluator_artifact_digest,
        &admission.evaluator_source_digest,
        &admission.artifact_identity_method,
        &admission.target_triple,
        &admission.platform_runtime_version,
        &admission.protocol_version,
    )?;
    let expected_scope = semantic_identity(
        format!("nq.scope.{}", scope.kind),
        profile_identity.version.clone(),
        &json!({
            "schema": "nq.diagnostic_scope.v1",
            "subject": request_subject,
            "scope": scope,
            "profile": profile_identity,
        }),
    )?;
    let expected_vantage = semantic_identity(
        format!(
            "nq.vantage.{}.{}.{}",
            vantage.kind, node_id, run.instance_id
        ),
        provider_intake.provider.source_admission_id.clone(),
        &json!({
            "schema": "nq.diagnostic_vantage.v1",
            "node_id": node_id,
            "instance_id": run.instance_id,
            "declared_vantage": vantage,
            "provider": provider_intake.provider,
        }),
    )?;
    let expected_state_model = semantic_identity(
        format!("{}.subject_binding_state", profile_identity.id),
        "1",
        &json!({
            "schema": "nq.subject_binding_state_model.v1",
            "binding_kind": "subject_identity",
            "profile": profile_identity,
        }),
    )?;
    let expected_evaluator = semantic_identity(
        "nq.detector_evaluator",
        "1",
        &json!({
            "schema": "nq.detector_evaluator.v1",
            "artifact_digest": provider_intake.provider.evaluator_artifact_digest,
            "evaluator_source_digest": admission.evaluator_source_digest,
            "detector_digest": expected_question.digest,
        }),
    )?;
    let question_version: u32 = expected_question.version.parse().map_err(|error| {
        EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} has invalid question version: {error}",
            artifact.artifact_id.0
        ))
    })?;
    let expected_threshold_policy = semantic_identity(
        format!("{}.threshold_policy", expected_question.id),
        expected_question.version.clone(),
        &json!({
            "schema": "nq.detector_threshold_policy.v2",
            "detector_id": expected_question.id,
            "detector_version": question_version,
            "detector_digest": expected_question.digest,
        }),
    )?;
    let expected_projection = DiagnosticProjectionV1 {
        identity: semantic_identity(
            "nq.detector_input_projection",
            "1",
            &json!({
                "schema": "nq.detector_input_projection.v1",
                "profile_semantic_id": artifact.profile_semantic_id,
                "detector_id": expected_question.id,
                "detector_version": question_version,
                "detector_digest": expected_question.digest,
                "fields": [
                    "instance_id",
                    "evaluated_at",
                    "watermark",
                    "reports[].report_id",
                    "reports[].report_sequence",
                    "reports[].report",
                ],
            }),
        )?,
        omitted_distinctions: Vec::new(),
    };
    let expected_clock = semantic_identity(
        "nq.local_linux_realtime",
        "1",
        &json!({
            "schema": "nq.local_linux_realtime.v1",
            "source": "CLOCK_REALTIME through chrono::Utc",
            "relationship": "NQ bounds the local helper invocation; admitted source times must fall inside that interval",
        }),
    )?;
    let capture_policy = semantic_identity(
        "nq.capture.exact_provider_response",
        "1",
        &json!({
            "schema": "nq.capture_policy.v1",
            "mode": "exact_source",
            "boundary": "provider_intake",
        }),
    )?;
    let admission_rule = semantic_identity(
        "nq.local_provider_admission",
        "1",
        &json!({
            "schema": "nq.diagnostic_admission_rule.v1",
            "provider_admission_id": provider_intake.provider.provider_admission_id,
            "profile_semantic_id": provider_intake.provider.profile_semantic_id,
        }),
    )?;
    let expected_selection_rule = semantic_identity(
        "nq.fresh_single_admitted_report",
        "1",
        &json!({
            "schema": "nq.diagnostic_selection_rule.v1",
            "question": expected_question,
            "cardinality": "exactly_one_newly_admitted_report_with_no_prior_matching_history",
        }),
    )?;
    let mut substitutions = Vec::new();
    if production_binding.is_none() && artifact.producer.node_id != node_id {
        substitutions.push("producer.node_id");
    }
    if artifact.producer.build != historical_surface.build {
        substitutions.push("producer.build");
    }
    if production_binding.is_none() && artifact.producer.cohort != historical_surface.cohort {
        substitutions.push("producer.cohort");
    }
    if artifact.question != expected_question {
        substitutions.push("question");
    }
    if artifact.subject.scope != expected_scope {
        substitutions.push("subject.scope");
    }
    if production_binding.is_none() && artifact.vantage != expected_vantage {
        substitutions.push("vantage");
    }
    if artifact.state_model != expected_state_model {
        substitutions.push("state_model");
    }
    if artifact.evaluator != expected_evaluator {
        substitutions.push("evaluator");
    }
    if artifact.threshold_policy != expected_threshold_policy {
        substitutions.push("threshold_policy");
    }
    if artifact.projection != expected_projection {
        substitutions.push("projection");
    }
    if artifact.execution_clock != expected_clock {
        substitutions.push("execution_clock");
    }
    if artifact.attempt_interval.qualification != historical_surface.clock_qualification {
        substitutions.push("attempt_interval.qualification");
    }
    if artifact.limitations != historical_surface.limitations {
        substitutions.push("limitations");
    }
    if artifact.nonclaims != historical_surface.nonclaims {
        substitutions.push("nonclaims");
    }
    if artifact.inputs.selection_rule != expected_selection_rule {
        substitutions.push("selection_rule");
    }
    if artifact
        .inputs
        .received
        .iter()
        .any(|input| input.capture_policy != capture_policy)
    {
        substitutions.push("capture_policy");
    }
    if artifact.inputs.admitted.iter().any(|input| {
        input.admission_rule != admission_rule
            || input.normalization_rule != historical_surface.normalization_rule
            || input.projection_rule != artifact.projection.identity
    }) {
        substitutions.push("admission_normalization_or_projection_rule");
    }
    if !substitutions.is_empty() {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes its exact diagnostic semantic surface: {}",
            artifact.artifact_id.0,
            substitutions.join(", ")
        )));
    }
    let intake_started_at = parse_timestamp(&intake.started_at)?;
    let intake_finished_at = parse_timestamp(&intake.finished_at)?;
    let intake_received_at = parse_timestamp(&intake.received_at)?;
    if production_binding.is_none() && artifact.started_at != intake_started_at
        || artifact.attempt_interval.started_at != intake_started_at
        || artifact.attempt_interval.ended_at != intake_finished_at
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes provider attempt timing",
            artifact.artifact_id.0
        )));
    }
    for input in &artifact.inputs.received {
        if input.provider_intake_id == provider_intake_id
            && (input.raw_artifact_id.0.as_str() != intake.raw_sha256
                || input.acquisition != artifact.attempt_interval
                || input.received_at != intake_received_at)
        {
            return Err(EngineError::Invariant(format!(
                "local v2 diagnostic artifact {} substitutes provider raw custody or timing",
                artifact.artifact_id.0
            )));
        }
    }
    for input in &artifact.inputs.failed {
        let (attempt, failure) = match &input.cause {
            FailedInputCauseV2::ProviderNoResponse {
                provider_intake_id: input_provider,
                attempt,
                failure,
                ..
            }
            | FailedInputCauseV2::AcquisitionFailed {
                provider_intake_id: input_provider,
                attempt,
                failure,
                ..
            } if input_provider == provider_intake_id => (attempt, failure),
            _ => continue,
        };
        if attempt != &artifact.attempt_interval {
            return Err(EngineError::Invariant(format!(
                "local v2 diagnostic artifact {} substitutes failed-attempt timing",
                artifact.artifact_id.0
            )));
        }
        if !raw.is_empty() {
            return Err(EngineError::Invariant(format!(
                "local v2 diagnostic artifact {} claims no failed-input bytes but custody retained {}",
                artifact.artifact_id.0,
                raw.len()
            )));
        }
        let native_outcome: RunResourceOutcomeV1 =
            serde_json::from_slice(&intake.native_outcome_json).map_err(|error| {
                EngineError::Invariant(format!(
                    "provider intake {provider_intake_id} native outcome cannot decode: {error}"
                ))
            })?;
        let native_failure = AcquisitionFailure::from_outcome(native_outcome.outcome)
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "provider intake {provider_intake_id} claims response for failed diagnostic input"
            ))
        })?;
        if failure != &native_failure {
            return Err(EngineError::Invariant(format!(
                "local v2 diagnostic artifact {} substitutes its exact acquisition failure",
                artifact.artifact_id.0
            )));
        }
    }
    validate_provider_interpretation_derivation(&provider_intake, artifact)?;
    Ok(LocalV2HistoryContext {
        provider_intake,
        capture_policy,
        admission_rule,
        normalization_rule: historical_surface.normalization_rule,
        question: expected_question,
    })
}

fn reopen_exact_evaluation(
    store: &Store,
    origin: &nq_store::EvaluationOriginRow,
) -> Result<EvaluationEnvelopeV2, EngineError> {
    if origin.evaluation_sequence <= 0 {
        return Err(EngineError::Invariant(format!(
            "evaluation {} has invalid sequence {}",
            origin.evaluation_id, origin.evaluation_sequence
        )));
    }
    let mut rows = store.evaluation_refusal_history_bounded(
        1,
        Some(origin.evaluation_sequence - 1),
        origin.evaluation_sequence,
    )?;
    let [row] = rows.as_mut_slice() else {
        return Err(EngineError::Invariant(format!(
            "evaluation {} cannot be reopened at sequence {}",
            origin.evaluation_id, origin.evaluation_sequence
        )));
    };
    if row.evaluation_id != origin.evaluation_id
        || row.evaluation_sequence != origin.evaluation_sequence
        || row.trigger_run_id != origin.trigger_run_id
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} exact sequence was substituted",
            origin.evaluation_id
        )));
    }
    validate_evaluation_refusal_row(store, row, false)
}

#[allow(clippy::too_many_lines)]
fn validate_evaluated_diagnostic_correspondence(
    store: &Store,
    artifact: &SupportedDiagnosticExecution,
    run: &nq_store::WatcherRunOutcomeRow,
    context: &LocalV2HistoryContext,
    evaluation: &EvaluationEnvelopeV2,
) -> Result<(), EngineError> {
    let SupportedDiagnosticExecution::V2(artifact) = artifact else {
        return Err(EngineError::Invariant(
            "evaluated diagnostic correspondence requires the v2 contract".into(),
        ));
    };
    let request = &context.provider_intake.request;
    let expected_scope = ScopeConfig {
        kind: request.binding.scope.kind.to_string(),
        value: request.binding.scope.value.clone(),
    };
    let expected_vantage = VantageConfig {
        kind: request.binding.vantage.kind.to_string(),
        value: request.binding.vantage.value.clone(),
    };
    if artifact.completed_at != evaluation.evaluated_at {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes its exact evaluation completion time",
            artifact.artifact_id.0
        )));
    }
    if evaluation.trigger_run_id.as_deref() != Some(run.run_id.as_str())
        || evaluation.context.instance_id != run.instance_id
        || evaluation.context.subject != request.binding.subject.as_str()
        || evaluation.context.scope != expected_scope
        || evaluation.context.vantage != expected_vantage
        || evaluation.profile.profile.id != artifact.profile.id
        || evaluation.profile.profile.version.to_string() != artifact.profile.version
        || evaluation.profile.profile_digest.as_str() != artifact.profile.digest.as_str()
        || evaluation.profile.profile_semantic_id.as_str() != artifact.profile_semantic_id.as_str()
        || evaluation.detector.id != artifact.question.id
        || evaluation.detector.version != artifact.question.version
        || evaluation.detector.digest != artifact.question.digest.as_str()
        || evaluation.evaluator_artifact_digest
            != context.provider_intake.provider.evaluator_artifact_digest
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes its exact evaluation context",
            artifact.artifact_id.0
        )));
    }

    let admitted = store
        .admitted_collection_for_run(&run.run_id)?
        .ok_or_else(|| {
            EngineError::Invariant(format!(
                "evaluated diagnostic artifact {} has no admitted source report",
                artifact.artifact_id.0
            ))
        })?;
    if admitted.evaluations != 1
        || evaluation.watermark.instance_id != run.instance_id
        || evaluation.watermark.max_report_sequence
            != u64::try_from(admitted.report_sequence).unwrap_or(u64::MAX)
        || evaluation.result.watermark.0 != evaluation.watermark.max_report_sequence
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes its exact evaluation watermark",
            artifact.artifact_id.0
        )));
    }
    let report_document = CanonicalDocument::from_canonical_bytes(admitted.canonical_json.clone())?;
    let report: nq_protocol::EvidenceReport = serde_json::from_slice(report_document.as_bytes())
        .map_err(|error| {
            EngineError::Invariant(format!(
                "diagnostic source report {} cannot decode: {error}",
                admitted.report_id
            ))
        })?;
    nq_protocol::validate_report(&report).map_err(|error| {
        EngineError::Invariant(format!("invalid diagnostic source report: {error}"))
    })?;
    let report_digest = Sha256Digest::parse(admitted.semantic_digest.clone())
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let normalized = ProfileReportInput::from_protocol(&report, &report_digest)
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let normalized_document = canonical(&normalized)?;
    let admitted_snapshot = store
        .verify_admitted_snapshot(&admitted.report_id)
        .map_err(|error| {
            EngineError::Invariant(format!(
                "diagnostic source report {} failed historical reopening: {error}",
                admitted.report_id
            ))
        })?;
    let validated: ValidatedReport =
        serde_json::from_slice(&admitted_snapshot.validated_report_json).map_err(|error| {
            EngineError::Invariant(format!(
                "diagnostic source report {} has an invalid persisted validated judgment: {error}",
                admitted.report_id
            ))
        })?;
    if canonical(&validated)?.as_bytes() != admitted_snapshot.validated_report_json {
        return Err(EngineError::Invariant(format!(
            "diagnostic source report {} validated judgment is not exact canonical typed bytes",
            admitted.report_id
        )));
    }
    let projection_document = canonical(&json!({
        "schema": "nq.detector_input_projection.v1",
        "instance_id": evaluation.context.instance_id,
        "evaluated_at": evaluation.evaluated_at,
        "watermark": evaluation.watermark.max_report_sequence,
        "reports": [{
            "report_id": admitted.report_id,
            "report_sequence": admitted.report_sequence,
            "report": validated,
        }],
    }))?;
    let projected_artifact_id =
        ProjectedArtifactId(nq_protocol::sha256_bytes(projection_document.as_bytes()));
    let input_id = context.provider_intake.intake_id.clone();
    let expected_inputs = DiagnosticInputAccountingV2 {
        selection_rule: artifact.inputs.selection_rule.clone(),
        expected: vec![ExpectedInputV1 {
            expectation_id: "expected:current_provider_report".to_owned(),
            role: "profile_report".to_owned(),
            required: true,
        }],
        received: vec![ReceivedInputV2 {
            input_id: input_id.clone(),
            expectation_id: "expected:current_provider_report".to_owned(),
            provider_intake_id: input_id.clone(),
            raw_artifact_id: RawArtifactId(context.provider_intake.raw_sha256.clone()),
            capture_mode: RawCaptureModeV1::ExactSource,
            capture_policy: context.capture_policy.clone(),
            availability_at_derivation: EvidenceAvailabilityV1::CommittedUnavailable,
            acquisition: artifact.attempt_interval.clone(),
            received_at: context.provider_intake.received_at,
        }],
        admitted: vec![AdmittedInputV1 {
            input_id: input_id.clone(),
            admission_rule: context.admission_rule.clone(),
            normalized_artifact_id: NormalizedArtifactId(nq_protocol::sha256_bytes(
                normalized_document.as_bytes(),
            )),
            normalization_rule: context.normalization_rule.clone(),
            projected_artifact_id: projected_artifact_id.clone(),
            projection_rule: artifact.projection.identity.clone(),
        }],
        refused: Vec::new(),
        failed: Vec::new(),
        excluded: Vec::new(),
        selected: vec![SelectedInputV1 {
            input_id: input_id.clone(),
            projected_artifact_id,
            role: "profile_report".to_owned(),
        }],
    };
    let expected_state_bindings = vec![DiagnosticStateBindingV1 {
        binding_id: "state:subject_identity".to_owned(),
        kind: "subject_identity".to_owned(),
        value: request.binding.subject.to_string(),
        supporting_input_ids: vec![input_id],
    }];
    let (expected_claims, expected_primary_claim_id, expected_outcome) =
        diagnostic_result_from_evaluation(
            evaluation,
            &expected_inputs,
            &expected_state_bindings,
            admitted.report_status == "complete",
        )?;
    if let (Some(actual), Some(expected)) = (
        artifact.inputs.admitted.first(),
        expected_inputs.admitted.first(),
    ) && actual.projected_artifact_id != expected.projected_artifact_id
    {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes its exact detector input projection: persisted {}, reconstructed {}",
            artifact.artifact_id.0,
            actual.projected_artifact_id.0,
            expected.projected_artifact_id.0
        )));
    }
    let mut substitutions = Vec::new();
    if artifact.inputs != expected_inputs {
        if artifact.inputs.selection_rule != expected_inputs.selection_rule {
            substitutions.push("inputs.selection_rule");
        }
        if artifact.inputs.expected != expected_inputs.expected {
            substitutions.push("inputs.expected");
        }
        if artifact.inputs.received != expected_inputs.received {
            substitutions.push("inputs.received");
        }
        if artifact.inputs.admitted != expected_inputs.admitted {
            substitutions.push("inputs.admitted");
        }
        if artifact.inputs.refused != expected_inputs.refused {
            substitutions.push("inputs.refused");
        }
        if artifact.inputs.failed != expected_inputs.failed {
            substitutions.push("inputs.failed");
        }
        if artifact.inputs.excluded != expected_inputs.excluded {
            substitutions.push("inputs.excluded");
        }
        if artifact.inputs.selected != expected_inputs.selected {
            substitutions.push("inputs.selected");
        }
    }
    if artifact.state_bindings != expected_state_bindings {
        substitutions.push("state_bindings");
    }
    if artifact.claims != expected_claims {
        substitutions.push("claims");
    }
    if artifact.primary_claim_id != expected_primary_claim_id {
        substitutions.push("primary_claim_id");
    }
    if artifact.outcome != expected_outcome {
        substitutions.push("outcome");
    }
    if !substitutions.is_empty() {
        return Err(EngineError::Invariant(format!(
            "local v2 diagnostic artifact {} substitutes the exact persisted evaluation result or dependency frontier: {}",
            artifact.artifact_id.0,
            substitutions.join(", ")
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the closed non-success reconstruction matrix auditable in one place.
fn validate_run_only_diagnostic_correspondence(
    store: &Store,
    artifact: &SupportedDiagnosticExecution,
    run_id: &str,
    context: &LocalV2HistoryContext,
) -> Result<(), EngineError> {
    let SupportedDiagnosticExecution::V2(artifact) = artifact else {
        return Err(EngineError::Invariant(format!(
            "run-only diagnostic artifact {} uses a contract that cannot preserve exact non-success",
            artifact.artifact_id().0
        )));
    };
    if artifact.completed_at != context.provider_intake.finished_at {
        return Err(EngineError::Invariant(format!(
            "run-only diagnostic artifact {} substitutes its exact terminal acquisition time",
            artifact.artifact_id.0
        )));
    }
    if run_id != context.provider_intake.run_id
        || context.provider_intake.request.profile.id.as_str() != artifact.profile.id
        || context.provider_intake.request.profile.version.as_str() != artifact.profile.version
        || context.provider_intake.request.profile.digest != artifact.profile.digest
        || artifact.question != context.question
    {
        return Err(EngineError::Invariant(format!(
            "run-only diagnostic artifact {} substitutes its admitted question",
            artifact.artifact_id.0
        )));
    }
    let result = store.collection_result_for_run(run_id)?.ok_or_else(|| {
        EngineError::Invariant(format!(
            "run-only diagnostic artifact {} has no canonical collection result",
            artifact.artifact_id.0
        ))
    })?;
    let collection = decode_collection_outcome(result.as_bytes())?;
    let input_id = context.provider_intake.intake_id.clone();
    let expected = vec![ExpectedInputV1 {
        expectation_id: "expected:current_provider_report".to_owned(),
        role: "profile_report".to_owned(),
        required: true,
    }];
    let (expected_inputs, expected_claims, expected_primary_claim_id, expected_outcome) =
        match &collection.result {
            CollectionResult::Rejected { refusal } => {
                if context.provider_intake.raw_length == 0 {
                    return Err(EngineError::Invariant(format!(
                        "run-only diagnostic artifact {} claims refusal without retained bytes",
                        artifact.artifact_id.0
                    )));
                }
                let profile_binding = match &refusal.origin {
                    GovernedRefusalOrigin::Profile(_) => {
                        Some(ProfileRefusalBindingV2::ArtifactProfile)
                    }
                    _ => None,
                };
                (
                    DiagnosticInputAccountingV2 {
                        selection_rule: artifact.inputs.selection_rule.clone(),
                        expected,
                        received: vec![ReceivedInputV2 {
                            input_id: input_id.clone(),
                            expectation_id: "expected:current_provider_report".to_owned(),
                            provider_intake_id: input_id.clone(),
                            raw_artifact_id: RawArtifactId(
                                context.provider_intake.raw_sha256.clone(),
                            ),
                            capture_mode: RawCaptureModeV1::ExactSource,
                            capture_policy: context.capture_policy.clone(),
                            availability_at_derivation:
                                EvidenceAvailabilityV1::CommittedUnavailable,
                            acquisition: artifact.attempt_interval.clone(),
                            received_at: context.provider_intake.received_at,
                        }],
                        admitted: Vec::new(),
                        refused: vec![RefusedInputV2 {
                            input_id,
                            refusal: refusal.clone(),
                            profile_binding,
                        }],
                        failed: Vec::new(),
                        excluded: Vec::new(),
                        selected: Vec::new(),
                    },
                    Vec::new(),
                    None,
                    DiagnosticOutcomeV2 {
                        derivation: DiagnosticDerivationV1::Refused,
                        condition: DiagnosticConditionV1::Unresolved,
                        coherence: DiagnosticCoherenceV1::NotEvaluated,
                        coverage: DiagnosticCoverageV1::Missing,
                        summary: "the required provider input was refused".to_owned(),
                        refusals: vec![refusal.clone()],
                        unsupported: Vec::new(),
                    },
                )
            }
            CollectionResult::AcquisitionFailed { failure } => {
                if context.provider_intake.raw_length != 0 {
                    return Err(EngineError::Invariant(format!(
                        "run-only diagnostic artifact {} claims failed input despite retained bytes",
                        artifact.artifact_id.0
                    )));
                }
                let failure_id = format!("failure:{}", context.provider_intake.intake_id);
                let cause = if matches!(
                    failure.class,
                    AcquisitionFailureClass::Timeout
                        | AcquisitionFailureClass::Eof
                        | AcquisitionFailureClass::HelperExited
                        | AcquisitionFailureClass::Disconnect
                ) {
                    FailedInputCauseV2::ProviderNoResponse {
                        provider_intake_id: context.provider_intake.intake_id.clone(),
                        attempt: artifact.attempt_interval.clone(),
                        raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
                        failure: failure.clone(),
                    }
                } else {
                    FailedInputCauseV2::AcquisitionFailed {
                        provider_intake_id: context.provider_intake.intake_id.clone(),
                        attempt: artifact.attempt_interval.clone(),
                        raw_custody: FailedAcquisitionCustodyV2::NoBytesRetained,
                        failure: failure.clone(),
                    }
                };
                let claim_id = "claim:required_provider_input_available".to_owned();
                (
                    DiagnosticInputAccountingV2 {
                        selection_rule: artifact.inputs.selection_rule.clone(),
                        expected,
                        received: Vec::new(),
                        admitted: Vec::new(),
                        refused: Vec::new(),
                        failed: vec![FailedInputV2 {
                            expectation_id: "expected:current_provider_report".to_owned(),
                            failure_id: failure_id.clone(),
                            cause,
                        }],
                        excluded: Vec::new(),
                        selected: Vec::new(),
                    },
                    vec![DiagnosticClaimV2 {
                        claim_id: claim_id.clone(),
                        proposition:
                            "the required provider input is available for diagnostic evaluation"
                                .to_owned(),
                        status: DiagnosticClaimStatusV1::Unknown,
                        condition_effect: Some(DiagnosticConditionV1::Unresolved),
                        dependency_input_ids: Vec::new(),
                        dependency_refusal_ids: Vec::new(),
                        dependency_failure_ids: vec![failure_id],
                        state_binding_ids: Vec::new(),
                        required_distinctions: Vec::new(),
                        limitations: vec![
                            "the bounded subject condition was not evaluated".to_owned(),
                        ],
                        nonclaims: vec![
                            "provider acquisition failure does not establish subject failure"
                                .to_owned(),
                        ],
                    }],
                    Some(claim_id),
                    DiagnosticOutcomeV2 {
                        derivation: DiagnosticDerivationV1::Partial,
                        condition: DiagnosticConditionV1::Unresolved,
                        coherence: DiagnosticCoherenceV1::NotEvaluated,
                        coverage: DiagnosticCoverageV1::Missing,
                        summary: "the required provider input was not acquired".to_owned(),
                        refusals: Vec::new(),
                        unsupported: Vec::new(),
                    },
                )
            }
            CollectionResult::AdmissionRefused { .. } => {
                return Err(EngineError::Invariant(format!(
                    "run-only diagnostic artifact {} claims a collection that created no run",
                    artifact.artifact_id.0
                )));
            }
            CollectionResult::Admitted { .. } => {
                return Err(EngineError::Invariant(format!(
                    "run-only diagnostic artifact {} is bound to admitted collection without an evaluation",
                    artifact.artifact_id.0
                )));
            }
        };
    if artifact.inputs != expected_inputs
        || !artifact.state_bindings.is_empty()
        || artifact.claims != expected_claims
        || artifact.primary_claim_id != expected_primary_claim_id
        || artifact.outcome != expected_outcome
    {
        return Err(EngineError::Invariant(format!(
            "run-only diagnostic artifact {} substitutes its exact non-success result or dependency frontier",
            artifact.artifact_id.0
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InstanceStatusProjection {
    state: &'static str,
    code: &'static str,
}

fn instance_status_projection(
    outcome: &CollectionOutcome,
) -> Result<InstanceStatusProjection, EngineError> {
    outcome.validate()?;
    let (state, code) = match &outcome.result {
        CollectionResult::Admitted { report_status, .. } if report_status == "complete" => {
            ("healthy", "report_complete")
        }
        CollectionResult::Admitted { report_status, .. } if report_status == "partial" => {
            ("degraded", "report_partial")
        }
        CollectionResult::Admitted { .. } => ("failed", "report_failed"),
        CollectionResult::AdmissionRefused { .. } => ("failed", "admission_refused"),
        CollectionResult::AcquisitionFailed { .. }
        | CollectionResult::Rejected {
            refusal:
                GovernedRefusal {
                    origin: GovernedRefusalOrigin::Acquisition(_),
                    ..
                },
        } => ("failed", "collection_failed"),
        CollectionResult::Rejected {
            refusal:
                GovernedRefusal {
                    origin: GovernedRefusalOrigin::Helper(_),
                    ..
                },
        } => ("degraded", "helper_refused"),
        CollectionResult::Rejected { .. } => ("failed", "report_rejected"),
    };
    Ok(InstanceStatusProjection { state, code })
}

fn instance_status_event(
    watcher: &WatcherConfig,
    outcome: &CollectionOutcome,
) -> Result<StatusEventInput, EngineError> {
    if outcome.instance_id != watcher.instance_id {
        return Err(EngineError::Invariant(format!(
            "cannot construct instance status {} from result for {}",
            watcher.instance_id, outcome.instance_id
        )));
    }
    let projection = instance_status_projection(outcome)?;
    Ok(StatusEventInput {
        status_event_id: Uuid::new_v4().to_string(),
        component_kind: "instance".into(),
        component_id: watcher.instance_id.clone(),
        state: projection.state.into(),
        code: projection.code.into(),
        detail: canonical(outcome)?,
        observed_at: timestamp(Utc::now()),
    })
}

fn governed_execution_status_event(
    watcher: &WatcherConfig,
    intake: &ProviderIntakeRecordV1,
    outcome: &CollectionOutcome,
) -> Result<StatusEventInput, EngineError> {
    if outcome.instance_id != watcher.instance_id {
        return Err(EngineError::Invariant(format!(
            "cannot construct governed execution status for {} from result for {}",
            watcher.instance_id, outcome.instance_id
        )));
    }
    outcome.validate()?;
    let run_id = outcome.run_id.as_deref().ok_or_else(|| {
        EngineError::Invariant("governed execution status lost its exact run identity".to_owned())
    })?;
    if intake.run_id != run_id {
        return Err(EngineError::Invariant(
            "governed execution status intake and outcome name different runs".to_owned(),
        ));
    }
    let (state, code) = governed_execution_status_projection(outcome)?;
    let detail = canonical(outcome)?;
    let status_event_id = nq_protocol::semantic_digest(&json!({
        "schema": "nq.diagnostic_execution_status_event.v1",
        "intake_id": intake.intake_id,
        "run_id": run_id,
        "code": code,
        "detail_sha256": detail.digest(),
        "observed_at": timestamp(intake.received_at),
    }))
    .map(Sha256Digest::into_string)
    .map_err(|error| EngineError::Canonical(error.to_string()))?;
    Ok(StatusEventInput {
        status_event_id,
        component_kind: "diagnostic_execution".to_owned(),
        component_id: run_id.to_owned(),
        state: state.to_owned(),
        code: code.to_owned(),
        detail,
        observed_at: timestamp(intake.received_at),
    })
}

fn governed_execution_status_projection(
    outcome: &CollectionOutcome,
) -> Result<(&'static str, &'static str), EngineError> {
    outcome.validate()?;
    let code = match &outcome.result {
        CollectionResult::Admitted { .. } => "diagnostic_execution_completed",
        CollectionResult::AdmissionRefused { .. } => "diagnostic_execution_admission_refused",
        CollectionResult::AcquisitionFailed { .. } => "diagnostic_execution_acquisition_failed",
        CollectionResult::Rejected { .. } => "diagnostic_execution_refused",
    };
    // A bounded processing result is not a health judgment about the subject
    // or watcher instance.
    Ok(("unknown", code))
}

#[derive(Clone, Copy)]
struct FindingLineage<'a> {
    instance_id: &'a str,
    detector_id: &'a str,
    detector_version: &'a str,
    detector_digest: &'a str,
    profile_id: &'a str,
    profile_version: &'a str,
    profile_digest: &'a str,
    profile_semantic_id: &'a str,
    subject_json: &'a str,
    basis_json: &'a str,
}

struct PreparedEvaluation {
    envelope: EvaluationEnvelopeV2,
    commit: EvaluationCommitInput,
    detector_reports: Vec<DetectorReport>,
}

impl FindingLineage<'_> {
    fn matches(self, finding: &nq_store::FindingSnapshotRow) -> bool {
        finding.instance_id == self.instance_id
            && finding.detector_id == self.detector_id
            && finding.detector_version == self.detector_version
            && finding.detector_digest == self.detector_digest
            && finding.profile_id == self.profile_id
            && finding.profile_version == self.profile_version
            && finding.profile_digest == self.profile_digest
            && finding.profile_semantic_id == self.profile_semantic_id
            && finding.subject_json == self.subject_json
            && finding.basis_json == self.basis_json
    }
}

fn find_current_finding<'a>(
    findings: &'a [nq_store::FindingSnapshotRow],
    lineage: &FindingLineage<'_>,
) -> Option<&'a nq_store::FindingSnapshotRow> {
    findings.iter().find(|finding| lineage.matches(finding))
}

#[allow(clippy::too_many_lines)]
fn prepare_instance_evaluations(
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    trigger_run_id: Option<&str>,
    snapshot: &EvidenceSnapshot,
    current_findings: &[FindingSnapshotRow],
    evaluator_artifact_digest: &str,
) -> Result<Vec<PreparedEvaluation>, EngineError> {
    let profile_version = watcher.profile.version.to_string();
    let profile_digest = profile
        .descriptor()
        .digest()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let profile_semantic = profile_semantic_id(profile.descriptor())
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let matching_rows =
        evaluation_context_rows(&snapshot.reports, watcher, profile_digest.as_str())?;
    let reports = matching_rows
        .iter()
        .map(|row| reconstruct_admitted(row, profile))
        .collect::<Result<Vec<_>, _>>()?;
    let latest = matching_rows.iter().max_by_key(|row| row.report_sequence);
    let evaluation_watermark = nq_store::EvaluationWatermark {
        instance_id: watcher.instance_id.clone(),
        max_report_sequence: latest.map_or(0, |row| row.report_sequence),
        watermark_received_at: latest.map(|row| row.received_at.clone()),
    };
    let subject_json = serde_json::to_string(&Value::String(watcher.subject.clone()))
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let mut prepared = Vec::new();
    for detector in profile.detectors() {
        // The durable timestamp format is millisecond precision. Construct the
        // canonical envelope from that same value so historical reopening does
        // not compare truncated SQL text with discarded sub-millisecond state.
        let evaluated_at = parse_timestamp(&timestamp(Utc::now()))?;
        let detector_input = DetectorInput {
            instance_id: &watcher.instance_id,
            evaluated_at,
            watermark: EvidenceWatermark(
                u64::try_from(evaluation_watermark.max_report_sequence).unwrap_or(u64::MAX),
            ),
            reports: &reports,
        };
        let mut result = detector.evaluate(&detector_input);
        // Evidence timestamps are persisted at the schema's millisecond
        // precision. Seal the canonical evaluation from that same durable
        // value so a helper's finer clock precision cannot create a result
        // that commits successfully but later fails exact reopening.
        for evidence in &mut result.evidence {
            evidence.observed_at = parse_timestamp(&timestamp(evidence.observed_at))?;
        }
        let descriptor = detector.descriptor();
        let detector_digest = descriptor.digest().map_err(EngineError::Canonical)?;
        let evaluation_id = Uuid::new_v4().to_string();
        let outcome = match result.state {
            DetectorState::Present => "condition_present",
            DetectorState::ExplicitlyAbsent => "condition_explicitly_absent",
            DetectorState::CannotEvaluate => "cannot_evaluate",
        };
        let governed_refusal = result.refusal.as_ref().map(|refusal| {
            GovernedRefusal::profile(
                Uuid::new_v4().to_string(),
                profile_semantic.clone(),
                refusal.clone(),
            )
        });
        let evaluation_profile = EvaluationProfileIdentity {
            profile: profile.descriptor().profile.clone(),
            profile_digest: profile_digest.clone(),
            profile_semantic_id: profile_semantic.clone(),
        };
        let governed_result = governed_evaluation_result(
            &result,
            evaluation_profile.clone(),
            governed_refusal.clone(),
        )?;
        let envelope = EvaluationEnvelopeV2 {
            schema: EvaluationEnvelopeSchema::V2,
            evaluation_id: evaluation_id.clone(),
            trigger_run_id: trigger_run_id.map(str::to_owned),
            context: EvaluationContextV1 {
                instance_id: watcher.instance_id.clone(),
                subject: watcher.subject.clone(),
                scope: watcher.scope.clone(),
                vantage: watcher.vantage.clone(),
            },
            detector: EvaluationDetectorIdentity {
                id: descriptor.id.clone(),
                version: descriptor.version.to_string(),
                digest: detector_digest.clone(),
            },
            evaluator_artifact_digest: parse_identity_digest(
                "evaluator_artifact_digest",
                evaluator_artifact_digest,
            )?,
            profile: evaluation_profile,
            started_at: evaluated_at,
            evaluated_at,
            watermark: EvaluationWatermarkV2 {
                instance_id: evaluation_watermark.instance_id.clone(),
                max_report_sequence: u64::try_from(evaluation_watermark.max_report_sequence)
                    .unwrap_or(u64::MAX),
                watermark_received_at: evaluation_watermark
                    .watermark_received_at
                    .as_deref()
                    .map(parse_timestamp)
                    .transpose()?,
            },
            result: governed_result,
        };
        let refusal = governed_refusal
            .as_ref()
            .map(|refusal| stored_governed_refusal(refusal, evaluated_at))
            .transpose()?;
        let evaluation = EvaluationInput {
            evaluation_id: evaluation_id.clone(),
            trigger_run_id: trigger_run_id.map(str::to_owned),
            detector_id: descriptor.id.clone(),
            detector_version: descriptor.version.to_string(),
            detector_digest: detector_digest.clone(),
            evaluator_artifact_digest: evaluator_artifact_digest.to_owned(),
            started_at: timestamp(evaluated_at),
            evaluated_at: timestamp(evaluated_at),
            outcome: outcome.into(),
            detail: canonical(&envelope)?,
            profile: EvaluationProfileBinding {
                profile_id: watcher.profile.id.clone(),
                profile_version: profile_version.clone(),
                profile_digest: profile_digest.as_str().to_owned(),
                profile_semantic_id: parse_identity_digest(
                    "profile_semantic_id",
                    profile_semantic.as_str(),
                )?,
            },
            watermarks: vec![evaluation_watermark.clone()],
            refusal,
        };
        let detector_version = descriptor.version.to_string();
        let lineage_basis = canonical(&json!({
            "profile_digest": profile_digest.as_str(),
            "vantage": watcher.vantage,
            "scope": watcher.scope,
        }))?;
        let lineage_basis_json = std::str::from_utf8(lineage_basis.as_bytes())
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let lineage = FindingLineage {
            instance_id: &watcher.instance_id,
            detector_id: &descriptor.id,
            detector_version: &detector_version,
            detector_digest: &detector_digest,
            profile_id: &watcher.profile.id,
            profile_version: &profile_version,
            profile_digest: profile_digest.as_str(),
            profile_semantic_id: profile_semantic.as_str(),
            subject_json: &subject_json,
            basis_json: lineage_basis_json,
        };
        let current = find_current_finding(current_findings, &lineage);
        let finding = build_finding_event(
            watcher,
            profile,
            descriptor,
            &result,
            governed_refusal.as_ref(),
            evaluated_at,
            current,
            &matching_rows,
        )?;
        prepared.push(PreparedEvaluation {
            envelope,
            commit: EvaluationCommitInput {
                evaluation,
                finding,
            },
            detector_reports: reports.clone(),
        });
    }
    prepared.sort_by(|left, right| {
        (
            &left.envelope.detector.id,
            &left.envelope.detector.version,
            &left.envelope.evaluation_id,
        )
            .cmp(&(
                &right.envelope.detector.id,
                &right.envelope.detector.version,
                &right.envelope.evaluation_id,
            ))
    });
    Ok(prepared)
}

fn report_matches_profile_contract(
    report: &nq_store::AdmittedReportRow,
    profile_id: &str,
    profile_version: &str,
    profile_digest: &str,
) -> bool {
    report.profile_id == profile_id
        && report.profile_version == profile_version
        && report.profile_digest == profile_digest
}

fn report_matches_evaluation_context(
    row: &nq_store::AdmittedReportRow,
    watcher: &WatcherConfig,
    profile_digest: &str,
) -> Result<bool, EngineError> {
    if !report_matches_profile_contract(
        row,
        &watcher.profile.id,
        &watcher.profile.version.to_string(),
        profile_digest,
    ) {
        return Ok(false);
    }
    let document = CanonicalDocument::from_canonical_bytes(row.canonical_json.clone())?;
    if document.digest() != row.semantic_digest {
        return Err(EngineError::Invariant(format!(
            "admitted report {} semantic digest was substituted",
            row.report_id
        )));
    }
    let report: nq_protocol::EvidenceReport = serde_json::from_slice(document.as_bytes())
        .map_err(|error| EngineError::Invariant(format!("stored report cannot decode: {error}")))?;
    nq_protocol::validate_report(&report)
        .map_err(|error| EngineError::Invariant(format!("stored report is invalid: {error}")))?;
    Ok(report.profile.id.as_str() == watcher.profile.id
        && report.profile.version.to_string() == watcher.profile.version.to_string()
        && report.profile.digest.as_str() == profile_digest
        && report.binding.subject.as_str() == watcher.subject
        && report.binding.scope.kind.as_str() == watcher.scope.kind
        && report.binding.scope.value == watcher.scope.value
        && report.binding.vantage.kind.as_str() == watcher.vantage.kind
        && report.binding.vantage.value == watcher.vantage.value)
}

fn evaluation_context_rows(
    rows: &[nq_store::AdmittedReportRow],
    watcher: &WatcherConfig,
    profile_digest: &str,
) -> Result<Vec<nq_store::AdmittedReportRow>, EngineError> {
    rows.iter()
        .filter_map(
            |row| match report_matches_evaluation_context(row, watcher, profile_digest) {
                Ok(true) => Some(Ok(row.clone())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            },
        )
        .collect()
}

fn require_initial_diagnostic_profile(
    profile: &'static dyn ProfileModule,
    profile_digest: &str,
) -> Result<(), EngineError> {
    let descriptor = profile.descriptor();
    let [detector] = profile.detectors() else {
        return Err(EngineError::DiagnosticUnsupported(format!(
            "initial diagnostic execution supports exactly one detector; profile {} v{} has {}",
            descriptor.profile.id,
            descriptor.profile.version,
            profile.detectors().len()
        )));
    };
    let detector_descriptor = detector.descriptor();
    let detector_digest = detector_descriptor
        .digest()
        .map_err(EngineError::Canonical)?;
    if descriptor.profile.id != nq_profiles::host::PROFILE_ID
        || descriptor.profile.version != nq_profiles::host::PROFILE_VERSION
        || profile_digest != INITIAL_DIAGNOSTIC_PROFILE_DIGEST
        || detector_descriptor.id != INITIAL_DIAGNOSTIC_DETECTOR_ID
        || detector_descriptor.version != INITIAL_DIAGNOSTIC_DETECTOR_VERSION
        || detector_digest != INITIAL_DIAGNOSTIC_DETECTOR_DIGEST
    {
        return Err(EngineError::DiagnosticUnsupported(format!(
            "initial diagnostic execution is sealed to nq.host/v1 load-pressure semantics; received {} v{} / {} v{}",
            descriptor.profile.id,
            descriptor.profile.version,
            detector_descriptor.id,
            detector_descriptor.version
        )));
    }
    Ok(())
}

fn require_empty_diagnostic_history(
    snapshot: &EvidenceSnapshot,
    watcher: &WatcherConfig,
    profile_digest: &str,
) -> Result<(), EngineError> {
    let matching = evaluation_context_rows(&snapshot.reports, watcher, profile_digest)?;
    if matching.is_empty() {
        return Ok(());
    }
    Err(EngineError::DiagnosticUnsupported(format!(
        "diagnostic execution requires a fresh instance with no prior matching history; found {} reports for {}",
        matching.len(),
        watcher.instance_id
    )))
}

fn require_fresh_diagnostic_snapshot(
    snapshot: &EvidenceSnapshot,
    watcher: &WatcherConfig,
    profile_digest: &str,
    current_report_id: &str,
) -> Result<(), EngineError> {
    let matching = evaluation_context_rows(&snapshot.reports, watcher, profile_digest)?;
    let [report] = matching.as_slice() else {
        return Err(EngineError::Invariant(format!(
            "diagnostic execution requires one fresh admitted report and no prior matching history; found {} reports for {}",
            matching.len(),
            watcher.instance_id
        )));
    };
    if report.report_id != current_report_id || report.instance_id != watcher.instance_id {
        return Err(EngineError::Invariant(
            "diagnostic execution fresh-history snapshot does not identify the current admitted report"
                .into(),
        ));
    }
    Ok(())
}

struct DryExchange {
    report_digest: String,
    validated: ValidatedReport,
}

const BINDING_MATERIALIZATION_PLAN_SCHEMA: &str = "nq.binding_materialization_plan.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingMaterializationPlan {
    schema: String,
    operation_id: String,
    instance_id: String,
    binding_event_id: String,
    admissions_root: AdmissionRootIdentity,
    desired_lock: Option<AdmissionLock>,
    previous_lock: Option<AdmissionLock>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdmissionRootIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
}

impl AdmissionRootIdentity {
    fn resolve(path: &Path) -> Result<Self, EngineError> {
        let canonical_path = fs::canonicalize(path)?;
        let metadata = fs::metadata(&canonical_path)?;
        if !metadata.is_dir() {
            return Err(EngineError::Invariant(format!(
                "admissions root {} is not a directory",
                path.display()
            )));
        }
        Ok(Self {
            canonical_path,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        })
    }

    fn open_retained(&self) -> Result<(File, PathBuf), EngineError> {
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&self.canonical_path)?;
        let metadata = directory.metadata()?;
        let opened = Self {
            canonical_path: self.canonical_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        };
        if &opened != self {
            return Err(EngineError::Invariant(format!(
                "admissions root {} changed before materialization",
                self.canonical_path.display()
            )));
        }
        let retained_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        if fs::metadata(&retained_path)?.ino() != self.inode {
            return Err(EngineError::Invariant(
                "retained admissions-root descriptor identity disagrees".into(),
            ));
        }
        Ok((directory, retained_path))
    }

    fn validate_shape(&self) -> Result<(), EngineError> {
        if !self.canonical_path.is_absolute()
            || self.device == 0
            || self.inode == 0
            || self.mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(EngineError::Invariant(
                "malformed admissions-root identity in materialization plan".into(),
            ));
        }
        Ok(())
    }
}

impl BindingMaterializationPlan {
    fn validate(&self) -> Result<(), EngineError> {
        if self.schema != BINDING_MATERIALIZATION_PLAN_SCHEMA
            || Uuid::parse_str(&self.operation_id).is_err()
            || Uuid::parse_str(&self.binding_event_id).is_err()
            || self.instance_id.is_empty()
            || self.instance_id.len() > 128
            || self.desired_lock.is_none() && self.previous_lock.is_none()
        {
            return Err(EngineError::Invariant(
                "malformed binding materialization plan identity".into(),
            ));
        }
        self.admissions_root.validate_shape()?;
        if !self
            .instance_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(EngineError::Invariant(
                "binding materialization instance is not a safe path component".into(),
            ));
        }
        for lock in [self.desired_lock.as_ref(), self.previous_lock.as_ref()]
            .into_iter()
            .flatten()
        {
            if lock.instance_id != self.instance_id {
                return Err(EngineError::Invariant(format!(
                    "binding materialization {} contains a lock for another instance",
                    self.operation_id
                )));
            }
            AdmissionManager.binding_digest(lock)?;
        }
        Ok(())
    }
}

fn binding_materialization_completion(
    plan: &BindingMaterializationPlan,
    intent: &CanonicalDocument,
) -> Result<BindingMaterializationInput, EngineError> {
    Ok(BindingMaterializationInput {
        materialization_event_id: Uuid::new_v4().to_string(),
        operation_id: plan.operation_id.clone(),
        instance_id: plan.instance_id.clone(),
        binding_event_id: plan.binding_event_id.clone(),
        phase: "completed".to_owned(),
        occurred_at: timestamp(Utc::now()),
        detail: canonical(&json!({
            "schema": "nq.binding_materialization_completion.v1",
            "intent_digest": intent.digest(),
        }))?,
    })
}

fn resolve(watcher: &WatcherConfig) -> Result<&'static dyn ProfileModule, EngineError> {
    nq_profiles::resolve_profile(&watcher.profile.id, watcher.profile.version).ok_or_else(|| {
        EngineError::UnknownProfile {
            id: watcher.profile.id.clone(),
            version: watcher.profile.version,
        }
    })
}

/// Validate every configured binding against the explicitly compiled profile
/// catalog before any directory, database, listener, or helper is touched.
///
/// # Errors
///
/// Returns the exact instance and catalog vocabulary mismatch.
pub fn validate_compiled_config(config: &NqConfig) -> Result<(), EngineError> {
    for watcher in &config.watchers {
        let profile = resolve(watcher)?;
        let descriptor = profile.descriptor();
        if !watcher.subject.starts_with(&descriptor.subjects.namespace) {
            return Err(EngineError::Profile(format!(
                "instance {} subject is outside profile namespace {}",
                watcher.instance_id, descriptor.subjects.namespace
            )));
        }
        if !descriptor
            .scope_kinds
            .iter()
            .any(|term| term.name == watcher.scope.kind)
        {
            return Err(EngineError::Profile(format!(
                "instance {} uses unknown scope kind {}",
                watcher.instance_id, watcher.scope.kind
            )));
        }
        if !descriptor
            .vantages
            .iter()
            .any(|term| term.name == watcher.vantage.kind)
        {
            return Err(EngineError::Profile(format!(
                "instance {} uses unknown vantage {}",
                watcher.instance_id, watcher.vantage.kind
            )));
        }
        if let Some(capability) = watcher.capability_ceiling.iter().find(|capability| {
            !descriptor
                .capabilities
                .iter()
                .any(|term| term.name == capability.as_str())
        }) {
            return Err(EngineError::Profile(format!(
                "instance {} capability ceiling contains profile-unknown {}",
                watcher.instance_id, capability
            )));
        }
        let context = ValidationContext {
            instance_id: watcher.instance_id.clone(),
            request_subject: watcher.subject.clone(),
            scope: ScopeGrant {
                kind: watcher.scope.kind.clone(),
                value: watcher.scope.value.clone(),
            },
            vantage: VantageGrant {
                kind: watcher.vantage.kind.clone(),
                value: watcher.vantage.value.clone(),
            },
            granted_capabilities: watcher.capability_ceiling.clone(),
            received_at: Utc::now(),
            max_observations: u32::try_from(watcher.resources.max_observations)
                .unwrap_or(u32::MAX)
                .min(descriptor.limits.max_observations),
            max_future_skew: Duration::seconds(60),
        };
        profile.validate_binding(&context).map_err(|refusal| {
            EngineError::Profile(format!(
                "instance {} binding refused at {:?}/{:?}: {}",
                watcher.instance_id, refusal.boundary, refusal.code, refusal.message
            ))
        })?;
    }
    Ok(())
}

/// Compute the exact cursor namespace for one admitted execution contract.
/// A new admission or any profile, subject, scope, vantage, or capability
/// change produces a different namespace and therefore cannot inherit a stale
/// helper cursor. V1 profile descriptors do not declare cross-implementation
/// checkpoint portability, so the admission and binding identities are
/// intentionally included and every rotation starts a new cursor namespace.
///
/// # Errors
///
/// Returns when the contract cannot be represented as bounded canonical JSON.
pub fn checkpoint_contract_digest(
    watcher: &WatcherConfig,
    lock: &AdmissionLock,
    binding_digest: &str,
    profile_digest: &str,
) -> Result<String, EngineError> {
    Ok(canonical(&json!({
        "schema": "nq.checkpoint_contract.v1",
        "instance_id": watcher.instance_id,
        "admission_id": lock.admission_id,
        "binding_digest": binding_digest,
        "profile": {
            "id": watcher.profile.id,
            "version": watcher.profile.version,
            "digest": profile_digest,
        },
        "subject": watcher.subject,
        "scope": watcher.scope,
        "vantage": watcher.vantage,
        "granted_capabilities": lock.granted_capabilities,
    }))?
    .digest()
    .to_owned())
}

fn build_request(
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    granted: &BTreeSet<String>,
    checkpoint: Option<Checkpoint>,
) -> Result<HelperRequest, EngineError> {
    let descriptor = profile.descriptor();
    let digest = descriptor
        .digest()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let request = HelperRequest {
        schema: nq_protocol::HELPER_REQUEST_SCHEMA.into(),
        protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.into(),
        request_id: token(RequestId::new(Uuid::new_v4().to_string()))?,
        instance_id: token(InstanceId::new(watcher.instance_id.clone()))?,
        profile: ProfileBinding {
            id: token(ProfileId::new(descriptor.profile.id.clone()))?,
            version: token(ProfileVersion::new(descriptor.profile.version.to_string()))?,
            digest: Sha256Digest::parse(digest.as_str().to_owned())
                .map_err(|error| EngineError::Token(error.to_string()))?,
        },
        binding: SubjectBinding {
            subject: token(SubjectId::new(watcher.subject.clone()))?,
            scope: ScopeBinding {
                kind: token(ScopeKind::new(watcher.scope.kind.clone()))?,
                value: watcher.scope.value.clone(),
            },
            vantage: VantageBinding {
                kind: token(VantageKind::new(watcher.vantage.kind.clone()))?,
                value: watcher.vantage.value.clone(),
            },
        },
        granted_capabilities: granted
            .iter()
            .map(|capability| token(Capability::new(capability.clone())))
            .collect::<Result<_, _>>()?,
        checkpoint,
        deadline: MonotonicDeadline {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns: boottime_ns()?
                .saturating_add(watcher.invocation.deadline_ms.saturating_mul(1_000_000)),
        },
        bounds: CollectionBounds {
            max_response_bytes: u32::try_from(watcher.resources.max_response_bytes)
                .unwrap_or(u32::MAX),
            max_observations: u32::try_from(watcher.resources.max_observations)
                .unwrap_or(u32::MAX)
                .min(descriptor.limits.max_observations),
            max_payload_bytes: descriptor.limits.max_payload_bytes,
            max_coverage_entries: descriptor.limits.max_coverage_declarations,
            max_report_errors: 128,
            max_checkpoint_bytes: 65_536,
        },
    };
    nq_protocol::validate_request(&request)
        .map_err(|error| EngineError::Protocol(error.to_string()))?;
    Ok(request)
}

fn semantic_identity(
    id: impl Into<String>,
    version: impl Into<String>,
    descriptor: &impl Serialize,
) -> Result<SemanticIdentityV1, EngineError> {
    Ok(SemanticIdentityV1 {
        id: id.into(),
        version: version.into(),
        digest: nq_protocol::semantic_digest(descriptor)
            .map_err(|error| EngineError::Canonical(error.to_string()))?,
    })
}

#[derive(Clone)]
struct LocalV2HistoricalSurface {
    build: SemanticIdentityV1,
    cohort: SemanticIdentityV1,
    normalization_rule: SemanticIdentityV1,
    clock_qualification: ClockQualificationV2,
    limitations: Vec<DiagnosticLimitationV1>,
    nonclaims: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn local_v2_historical_surface(
    profile: &SemanticIdentityV1,
    question: &SemanticIdentityV1,
    evaluator_artifact_digest: &str,
    evaluator_source_digest: &str,
    artifact_identity_method: &str,
    target_triple: &str,
    platform_runtime_version: &str,
    protocol_version: &str,
) -> Result<LocalV2HistoricalSurface, EngineError> {
    let build = semantic_identity(
        "nq.evaluator_build",
        "2",
        &json!({
            "schema": "nq.evaluator_build.v2",
            "artifact_digest": evaluator_artifact_digest,
            "artifact_identity_method": artifact_identity_method,
            "target_triple": target_triple,
            "platform_runtime_version": platform_runtime_version,
            "evaluator_source_digest": evaluator_source_digest,
        }),
    )?;
    let cohort = semantic_identity(
        "nq.compiled_diagnostic_cohort",
        "1",
        &json!({
            "schema": "nq.compiled_diagnostic_cohort.v1",
            "evaluator_source_digest": evaluator_source_digest,
            "profile": profile,
            "question": question,
        }),
    )?;
    let normalization_rule = semantic_identity(
        "nq.protocol_report_normalization",
        "1",
        &json!({
            "schema": "nq.diagnostic_normalization_rule.v1",
            "protocol": protocol_version,
            "profile": profile,
        }),
    )?;
    let clock_qualification = ClockQualificationV2::Unqualified {
        code: "absolute_clock_quality_unqualified".to_owned(),
        detail: "the local Linux wall clock has no qualified finite UTC-error bound".to_owned(),
    };
    let limitations = vec![
        DiagnosticLimitationV1 {
            kind: DiagnosticLimitationKindV1::Other,
            code: "absolute_clock_quality_unqualified".to_owned(),
            detail:
                "timestamps share the local Linux wall clock; absolute UTC accuracy is not qualified"
                    .to_owned(),
        },
        DiagnosticLimitationV1 {
            kind: DiagnosticLimitationKindV1::Other,
            code: "boot_or_deployment_state_unbound".to_owned(),
            detail:
                "the current host profile does not export boot or deployment generation identity"
                    .to_owned(),
        },
        DiagnosticLimitationV1 {
            kind: DiagnosticLimitationKindV1::UnverifiedSeparation,
            code: "failure_domain_separation_unverified".to_owned(),
            detail: "this local execution carries no cross-vantage independence warrant"
                .to_owned(),
        },
        DiagnosticLimitationV1 {
            kind: DiagnosticLimitationKindV1::UnavailableEvidence,
            code: "raw_evidence_not_publicly_retrievable".to_owned(),
            detail: "exact raw provider bytes are committed in NQ custody but no supported raw-evidence retrieval surface exists"
                .to_owned(),
        },
    ];
    let nonclaims = vec![
        "agreement with another artifact does not establish independent corroboration".to_owned(),
        "this artifact grants no reliance, authorization, or action".to_owned(),
        "this bounded diagnostic does not establish whole-subject health".to_owned(),
    ];
    Ok(LocalV2HistoricalSurface {
        build,
        cohort,
        normalization_rule,
        clock_qualification,
        limitations,
        nonclaims,
    })
}

fn initial_local_v2_question(
    detector_identity_digest: &str,
) -> Result<SemanticIdentityV1, EngineError> {
    let digest = Sha256Digest::parse(INITIAL_DIAGNOSTIC_DETECTOR_DIGEST.to_owned())
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let expected_suite =
        nq_store::detector_suite_identity_digest(vec![digest.as_str().to_owned()])?;
    if detector_identity_digest != expected_suite.as_str() {
        return Err(EngineError::DiagnosticUnsupported(format!(
            "no frozen v2 detector descriptor maps admitted suite {detector_identity_digest}"
        )));
    }
    Ok(SemanticIdentityV1 {
        id: INITIAL_DIAGNOSTIC_DETECTOR_ID.to_owned(),
        version: INITIAL_DIAGNOSTIC_DETECTOR_VERSION.to_string(),
        digest,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn prepare_diagnostic_emission_base(
    node_id: &str,
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    provider: &crate::provider_intake::ProviderIdentityV1,
    outer_request_id: Option<&DiagnosticRequestId>,
    provider_request: &HelperRequest,
    production: Option<&DiagnosticProductionIdentityV2>,
    run_id: &str,
    capture: &RunCapture,
    evaluator: &EvaluatorRuntimeIdentity,
) -> Result<DiagnosticEmissionBase, EngineError> {
    let detector = profile.detectors().first().ok_or_else(|| {
        EngineError::Invariant("diagnostic execution profile has no detector".into())
    })?;
    let detector_descriptor = detector.descriptor();
    let detector_digest = detector_descriptor
        .digest()
        .map_err(EngineError::Canonical)?;
    let profile_descriptor = profile.descriptor();
    let profile_digest = profile_descriptor
        .digest()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let profile_semantic = profile_semantic_id(profile_descriptor)
        .map_err(|error| EngineError::Canonical(error.to_string()))?;

    let question = SemanticIdentityV1 {
        id: detector_descriptor.id.clone(),
        version: detector_descriptor.version.to_string(),
        digest: Sha256Digest::parse(detector_digest.clone())
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
    };
    let profile_identity = SemanticIdentityV1 {
        id: profile_descriptor.profile.id.clone(),
        version: profile_descriptor.profile.version.to_string(),
        digest: Sha256Digest::parse(profile_digest.as_str().to_owned())
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
    };
    let detector_suite =
        nq_store::detector_suite_identity_digest(vec![question.digest.as_str().to_owned()])?;
    let frozen_question = initial_local_v2_question(detector_suite.as_str())?;
    if question != frozen_question {
        return Err(EngineError::DiagnosticUnsupported(
            "the live detector descriptor has no frozen v2 historical correspondence mapping"
                .into(),
        ));
    }
    let historical_surface = local_v2_historical_surface(
        &profile_identity,
        &question,
        evaluator.artifact_digest().as_str(),
        EVALUATOR_SOURCE_DIGEST,
        evaluator.artifact_identity_method(),
        evaluator.target_triple(),
        evaluator.platform_runtime_version(),
        &provider.protocol_identity,
    )?;
    let scope = semantic_identity(
        format!("nq.scope.{}", watcher.scope.kind),
        profile_descriptor.profile.version.to_string(),
        &json!({
            "schema": "nq.diagnostic_scope.v1",
            "subject": watcher.subject,
            "scope": watcher.scope,
            "profile": profile_identity,
        }),
    )?;
    let vantage = semantic_identity(
        format!(
            "nq.vantage.{}.{}.{}",
            watcher.vantage.kind, node_id, watcher.instance_id
        ),
        provider.source_admission_id.clone(),
        &json!({
            "schema": "nq.diagnostic_vantage.v1",
            "node_id": node_id,
            "instance_id": watcher.instance_id,
            "declared_vantage": watcher.vantage,
            "provider": provider,
        }),
    )?;
    let state_model = semantic_identity(
        format!("{}.subject_binding_state", profile_descriptor.profile.id),
        "1",
        &json!({
            "schema": "nq.subject_binding_state_model.v1",
            "binding_kind": "subject_identity",
            "profile": profile_identity,
        }),
    )?;
    let evaluator_identity = semantic_identity(
        "nq.detector_evaluator",
        "1",
        &json!({
            "schema": "nq.detector_evaluator.v1",
            "artifact_digest": evaluator.artifact_digest(),
            "evaluator_source_digest": EVALUATOR_SOURCE_DIGEST,
            "detector_digest": detector_digest,
        }),
    )?;
    let threshold_policy = semantic_identity(
        format!("{}.threshold_policy", detector_descriptor.id),
        detector_descriptor.version.to_string(),
        &json!({
            "schema": "nq.detector_threshold_policy.v2",
            "detector_id": detector_descriptor.id,
            "detector_version": detector_descriptor.version,
            "detector_digest": detector_digest,
        }),
    )?;
    let projection_identity = semantic_identity(
        "nq.detector_input_projection",
        "1",
        &json!({
            "schema": "nq.detector_input_projection.v1",
            "profile_semantic_id": profile_semantic.as_str(),
            "detector_id": detector_descriptor.id,
            "detector_version": detector_descriptor.version,
            "detector_digest": detector_digest,
            "fields": [
                "instance_id",
                "evaluated_at",
                "watermark",
                "reports[].report_id",
                "reports[].report_sequence",
                "reports[].report",
            ],
        }),
    )?;
    let execution_clock = semantic_identity(
        "nq.local_linux_realtime",
        "1",
        &json!({
            "schema": "nq.local_linux_realtime.v1",
            "source": "CLOCK_REALTIME through chrono::Utc",
            "relationship": "NQ bounds the local helper invocation; admitted source times must fall inside that interval",
        }),
    )?;
    let capture_policy = semantic_identity(
        "nq.capture.exact_provider_response",
        "1",
        &json!({
            "schema": "nq.capture_policy.v1",
            "mode": "exact_source",
            "boundary": "provider_intake",
        }),
    )?;
    let admission_rule = semantic_identity(
        "nq.local_provider_admission",
        "1",
        &json!({
            "schema": "nq.diagnostic_admission_rule.v1",
            "provider_admission_id": provider.provider_admission_id,
            "profile_semantic_id": provider.profile_semantic_id,
        }),
    )?;
    let selection_rule = semantic_identity(
        "nq.fresh_single_admitted_report",
        "1",
        &json!({
            "schema": "nq.diagnostic_selection_rule.v1",
            "question": question,
            "cardinality": "exactly_one_newly_admitted_report_with_no_prior_matching_history",
        }),
    )?;
    let (subject_id, vantage, cohort) = match production {
        Some(production) => {
            validate_diagnostic_production_identity(production)?;
            if production.node_id != node_id {
                return Err(EngineError::Invariant(
                    "production diagnostic node differs from its execution node".to_owned(),
                ));
            }
            (
                production.subject_id.clone(),
                production.vantage.clone(),
                production.cohort.clone(),
            )
        }
        None => (watcher.subject.clone(), vantage, historical_surface.cohort),
    };
    Ok(DiagnosticEmissionBase {
        producer: DiagnosticProducerV1 {
            node_id: node_id.to_owned(),
            build: historical_surface.build,
            cohort,
        },
        request_id: outer_request_id
            .cloned()
            .unwrap_or_else(|| DiagnosticRequestId(provider_request.request_id.to_string())),
        run_id: DiagnosticRunId(run_id.to_owned()),
        question,
        subject: DiagnosticSubjectV1 {
            id: subject_id,
            scope,
        },
        profile: profile_identity,
        profile_semantic_id: Sha256Digest::parse(profile_semantic.as_str().to_owned())
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        vantage,
        state_model,
        evaluator: evaluator_identity,
        threshold_policy,
        projection: DiagnosticProjectionV1 {
            identity: projection_identity,
            omitted_distinctions: Vec::new(),
        },
        execution_clock: execution_clock.clone(),
        started_at: parse_timestamp(&timestamp(capture.started_at))?,
        attempt_interval: AcquisitionIntervalV2 {
            started_at: parse_timestamp(&timestamp(capture.started_at))?,
            ended_at: parse_timestamp(&timestamp(capture.finished_at))?,
            clock: execution_clock,
            qualification: historical_surface.clock_qualification,
        },
        capture_policy,
        admission_rule,
        normalization_rule: historical_surface.normalization_rule,
        selection_rule,
        limitations: historical_surface.limitations,
        nonclaims: historical_surface.nonclaims,
        expected_evaluator_artifact_digest: evaluator.artifact_digest().clone(),
        expected_profile_semantic_id: profile_semantic,
        expected_instance_id: watcher.instance_id.clone(),
        expected_scope: watcher.scope.clone(),
        expected_vantage: watcher.vantage.clone(),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One closed mapping from collection failure to diagnostic artifact.
fn prepare_non_success_diagnostic(
    node_id: &str,
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    provider: &crate::provider_intake::ProviderIdentityV1,
    outer_request_id: Option<&DiagnosticRequestId>,
    provider_request: &HelperRequest,
    production: Option<&DiagnosticProductionIdentityV2>,
    run_id: &str,
    provider_intake_id: &str,
    raw: Option<&[u8]>,
    capture: &RunCapture,
    evaluator: &EvaluatorRuntimeIdentity,
    outcome: &CollectionOutcome,
) -> Result<DiagnosticExecutionV2, EngineError> {
    if outcome.run_id.as_deref() != Some(run_id) || outcome.instance_id != watcher.instance_id {
        return Err(EngineError::Invariant(
            "non-success diagnostic source outcome differs from its run or instance".into(),
        ));
    }
    let base = prepare_diagnostic_emission_base(
        node_id,
        watcher,
        profile,
        provider,
        outer_request_id,
        provider_request,
        production,
        run_id,
        capture,
        evaluator,
    )?;
    let expected = vec![ExpectedInputV1 {
        expectation_id: "expected:current_provider_report".to_owned(),
        role: "profile_report".to_owned(),
        required: true,
    }];
    let selection_rule = base.selection_rule.clone();

    match &outcome.result {
        CollectionResult::Rejected { refusal } => {
            let raw = raw.ok_or_else(|| {
                EngineError::Invariant(
                    "rejected diagnostic input has no retained raw provider bytes".into(),
                )
            })?;
            let input_id = provider_intake_id.to_owned();
            let profile_binding = match &refusal.origin {
                GovernedRefusalOrigin::Profile(_) => Some(ProfileRefusalBindingV2::ArtifactProfile),
                _ => None,
            };
            let inputs = DiagnosticInputAccountingV2 {
                selection_rule,
                expected,
                received: vec![ReceivedInputV2 {
                    input_id: input_id.clone(),
                    expectation_id: "expected:current_provider_report".to_owned(),
                    provider_intake_id: provider_intake_id.to_owned(),
                    raw_artifact_id: RawArtifactId(nq_protocol::sha256_bytes(raw)),
                    capture_mode: RawCaptureModeV1::ExactSource,
                    capture_policy: base.capture_policy.clone(),
                    availability_at_derivation: EvidenceAvailabilityV1::CommittedUnavailable,
                    acquisition: base.attempt_interval.clone(),
                    received_at: parse_timestamp(&timestamp(capture.finished_at))?,
                }],
                admitted: Vec::new(),
                refused: vec![RefusedInputV2 {
                    input_id,
                    refusal: refusal.clone(),
                    profile_binding,
                }],
                failed: Vec::new(),
                excluded: Vec::new(),
                selected: Vec::new(),
            };
            base.seal(
                inputs,
                Vec::new(),
                Vec::new(),
                None,
                DiagnosticOutcomeV2 {
                    derivation: DiagnosticDerivationV1::Refused,
                    condition: DiagnosticConditionV1::Unresolved,
                    coherence: DiagnosticCoherenceV1::NotEvaluated,
                    coverage: DiagnosticCoverageV1::Missing,
                    summary: "the required provider input was refused".to_owned(),
                    refusals: vec![refusal.clone()],
                    unsupported: Vec::new(),
                },
            )
        }
        CollectionResult::AcquisitionFailed { failure } => {
            if raw.is_some() {
                return Err(EngineError::Invariant(
                    "failed-input diagnostic cannot discard retained provider bytes".into(),
                ));
            }
            let failure_id = format!("failure:{provider_intake_id}");
            let common = (
                provider_intake_id.to_owned(),
                base.attempt_interval.clone(),
                FailedAcquisitionCustodyV2::NoBytesRetained,
                failure.clone(),
            );
            let cause = if matches!(
                failure.class,
                AcquisitionFailureClass::Timeout
                    | AcquisitionFailureClass::Eof
                    | AcquisitionFailureClass::HelperExited
                    | AcquisitionFailureClass::Disconnect
            ) {
                FailedInputCauseV2::ProviderNoResponse {
                    provider_intake_id: common.0,
                    attempt: common.1,
                    raw_custody: common.2,
                    failure: common.3,
                }
            } else {
                FailedInputCauseV2::AcquisitionFailed {
                    provider_intake_id: common.0,
                    attempt: common.1,
                    raw_custody: common.2,
                    failure: common.3,
                }
            };
            let claim_id = "claim:required_provider_input_available".to_owned();
            let inputs = DiagnosticInputAccountingV2 {
                selection_rule,
                expected,
                received: Vec::new(),
                admitted: Vec::new(),
                refused: Vec::new(),
                failed: vec![FailedInputV2 {
                    expectation_id: "expected:current_provider_report".to_owned(),
                    failure_id: failure_id.clone(),
                    cause,
                }],
                excluded: Vec::new(),
                selected: Vec::new(),
            };
            base.seal(
                inputs,
                Vec::new(),
                vec![DiagnosticClaimV2 {
                    claim_id: claim_id.clone(),
                    proposition:
                        "the required provider input is available for diagnostic evaluation"
                            .to_owned(),
                    status: DiagnosticClaimStatusV1::Unknown,
                    condition_effect: Some(DiagnosticConditionV1::Unresolved),
                    dependency_input_ids: Vec::new(),
                    dependency_refusal_ids: Vec::new(),
                    dependency_failure_ids: vec![failure_id],
                    state_binding_ids: Vec::new(),
                    required_distinctions: Vec::new(),
                    limitations: vec!["the bounded subject condition was not evaluated".to_owned()],
                    nonclaims: vec![
                        "provider acquisition failure does not establish subject failure"
                            .to_owned(),
                    ],
                }],
                Some(claim_id),
                DiagnosticOutcomeV2 {
                    derivation: DiagnosticDerivationV1::Partial,
                    condition: DiagnosticConditionV1::Unresolved,
                    coherence: DiagnosticCoherenceV1::NotEvaluated,
                    coverage: DiagnosticCoverageV1::Missing,
                    summary: "the required provider input was not acquired".to_owned(),
                    refusals: Vec::new(),
                    unsupported: Vec::new(),
                },
            )
        }
        CollectionResult::AdmissionRefused { .. } => Err(EngineError::DiagnosticUnsupported(
            "admission refusal created no run and cannot be laundered into an execution artifact"
                .into(),
        )),
        CollectionResult::Admitted { .. } => Err(EngineError::Invariant(
            "admitted collection entered non-success diagnostic emission".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn prepare_diagnostic_emission(
    node_id: &str,
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    provider: &crate::provider_intake::ProviderIdentityV1,
    outer_request_id: Option<&DiagnosticRequestId>,
    provider_request: &HelperRequest,
    production: Option<&DiagnosticProductionIdentityV2>,
    run_id: &str,
    report_id: &str,
    input_id: &str,
    raw: &[u8],
    normalized: &ProfileReportInput,
    validated: &ValidatedReport,
    capture: &RunCapture,
    evaluator: &EvaluatorRuntimeIdentity,
) -> Result<DiagnosticEmissionContext, EngineError> {
    let base = prepare_diagnostic_emission_base(
        node_id,
        watcher,
        profile,
        provider,
        outer_request_id,
        provider_request,
        production,
        run_id,
        capture,
        evaluator,
    )?;
    let normalized_document = canonical(normalized)?;
    let projected_artifact_placeholder = ProjectedArtifactId(nq_protocol::sha256_bytes(
        b"pending exact detector input projection",
    ));

    let input_id = input_id.to_owned();
    let inputs = DiagnosticInputAccountingV2 {
        selection_rule: base.selection_rule.clone(),
        expected: vec![ExpectedInputV1 {
            expectation_id: "expected:current_provider_report".to_owned(),
            role: "profile_report".to_owned(),
            required: true,
        }],
        received: vec![ReceivedInputV2 {
            input_id: input_id.clone(),
            expectation_id: "expected:current_provider_report".to_owned(),
            provider_intake_id: input_id.clone(),
            raw_artifact_id: RawArtifactId(nq_protocol::sha256_bytes(raw)),
            capture_mode: RawCaptureModeV1::ExactSource,
            capture_policy: base.capture_policy.clone(),
            availability_at_derivation: EvidenceAvailabilityV1::CommittedUnavailable,
            acquisition: base.attempt_interval.clone(),
            received_at: parse_timestamp(&timestamp(capture.finished_at))?,
        }],
        admitted: vec![AdmittedInputV1 {
            input_id: input_id.clone(),
            admission_rule: base.admission_rule.clone(),
            normalized_artifact_id: NormalizedArtifactId(nq_protocol::sha256_bytes(
                normalized_document.as_bytes(),
            )),
            normalization_rule: base.normalization_rule.clone(),
            projected_artifact_id: projected_artifact_placeholder.clone(),
            projection_rule: base.projection.identity.clone(),
        }],
        refused: Vec::new(),
        failed: Vec::new(),
        excluded: Vec::new(),
        selected: vec![SelectedInputV1 {
            input_id: input_id.clone(),
            projected_artifact_id: projected_artifact_placeholder,
            role: "profile_report".to_owned(),
        }],
    };
    let state_bindings = vec![DiagnosticStateBindingV1 {
        binding_id: "state:subject_identity".to_owned(),
        kind: "subject_identity".to_owned(),
        value: watcher.subject.clone(),
        supporting_input_ids: vec![input_id],
    }];

    Ok(DiagnosticEmissionContext {
        producer: base.producer,
        request_id: base.request_id,
        run_id: base.run_id,
        question: base.question,
        subject: base.subject,
        profile: base.profile,
        profile_semantic_id: base.profile_semantic_id,
        vantage: base.vantage,
        state_model: base.state_model,
        evaluator: base.evaluator,
        threshold_policy: base.threshold_policy,
        projection: base.projection,
        execution_clock: base.execution_clock,
        started_at: base.started_at,
        attempt_interval: base.attempt_interval,
        inputs,
        state_bindings,
        limitations: base.limitations,
        nonclaims: base.nonclaims,
        expected_evaluator_artifact_digest: base.expected_evaluator_artifact_digest,
        expected_profile_semantic_id: base.expected_profile_semantic_id,
        expected_instance_id: base.expected_instance_id,
        expected_scope: base.expected_scope,
        expected_vantage: base.expected_vantage,
        report_id: report_id.to_owned(),
        report_complete: validated.status == SemanticReportStatus::Complete,
    })
}

fn store_report(
    report_id: &str,
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    report: &nq_protocol::EvidenceReport,
    validated: &ValidatedReport,
    received_at: DateTime<Utc>,
) -> Result<ReportInput, EngineError> {
    let coverage: Vec<_> = report
        .coverage
        .iter()
        .enumerate()
        .map(|(ordinal, coverage)| {
            Ok(CoverageInput {
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                coverage_kind: coverage.kind.to_string(),
                coverage_state: enum_token(&coverage.state)?,
                detail: canonical(&json!({
                    "subject": coverage.subject,
                    "detail": coverage.detail,
                }))?,
            })
        })
        .collect::<Result<_, EngineError>>()?;
    let observations = report
        .observations
        .iter()
        .map(|observation| {
            let observation_coverage = report
                .coverage
                .iter()
                .filter(|coverage| {
                    coverage
                        .subject
                        .as_ref()
                        .is_none_or(|subject| subject.as_str() == observation.subject.as_str())
                })
                .enumerate()
                .map(|(ordinal, coverage)| {
                    Ok(CoverageInput {
                        ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                        coverage_kind: coverage.kind.to_string(),
                        coverage_state: enum_token(&coverage.state)?,
                        detail: canonical(&coverage.detail)?,
                    })
                })
                .collect::<Result<_, EngineError>>()?;
            Ok(ObservationInput {
                ordinal: observation.ordinal,
                kind: observation.kind.to_string(),
                subject: canonical(&observation.subject.to_string())?,
                observed_at: timestamp(observation.observed_at),
                payload: canonical(&observation.payload)?,
                coverage: observation_coverage,
            })
        })
        .collect::<Result<_, EngineError>>()?;
    let errors = report
        .errors
        .iter()
        .enumerate()
        .map(|(ordinal, error)| {
            Ok(ReportErrorInput {
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                code: error.code.to_string(),
                detail: canonical(error)?,
            })
        })
        .collect::<Result<_, EngineError>>()?;
    Ok(ReportInput {
        report_id: report_id.to_owned(),
        instance_id: watcher.instance_id.clone(),
        profile_id: profile.descriptor().profile.id.clone(),
        profile_version: profile.descriptor().profile.version.to_string(),
        profile_digest: profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?
            .as_str()
            .to_owned(),
        observed_at: timestamp(validated.observed_at),
        received_at: timestamp(received_at),
        report_status: semantic_report_status(validated.status).into(),
        canonical_report: canonical(report)?,
        // The persisted, versioned admitted judgment. The store binds it to the
        // admission context reached through the run and derives its digest.
        validated_report: canonical(validated)?,
        next_checkpoint: report
            .next_checkpoint
            .as_ref()
            .map(|checkpoint| canonical(&checkpoint.value))
            .transpose()?,
        admitted_at: timestamp(Utc::now()),
        observations,
        coverage,
        errors,
    })
}

fn rejected_transport_submission(
    _run_id: &str,
    watcher: &WatcherConfig,
    capture: &RunCapture,
) -> Result<(Option<SubmissionInput>, Option<GovernedRefusal>), EngineError> {
    // Any retained provider bytes are received-but-refused testimony,
    // including partial output captured before a timeout, EOF, output limit,
    // or carrier failure. Claiming `NoBytesRetained` in those cases would
    // contradict the provider-intake custody record.
    let retains_exact_submission = !capture.stdout.is_empty();
    if !retains_exact_submission {
        return Ok((None, None));
    }
    let failure = AcquisitionFailure::from_outcome(capture.outcome.clone()).ok_or_else(|| {
        EngineError::Invariant("response cannot justify rejected transport custody".into())
    })?;
    let refusal = GovernedRefusal::acquisition(
        Uuid::new_v4().to_string(),
        AcquisitionRefusal {
            responsible_instance_id: watcher.instance_id.clone(),
            failure,
        },
    );
    let stored_refusal = stored_governed_refusal(&refusal, capture.finished_at)?;
    let submission = SubmissionInput {
        submission_id: Uuid::new_v4().to_string(),
        raw_bytes: capture.stdout.clone(),
        received_at: timestamp(capture.finished_at),
        protocol_outcome: "not_validated".into(),
        disposition: SubmissionDisposition::Rejected {
            refusal: stored_refusal,
        },
    };
    Ok((Some(submission), Some(refusal)))
}

pub(crate) fn protocol_rejection(
    instance_id: &str,
    error: nq_protocol::FramingError,
) -> ProtocolRejection {
    let failure = match error {
        nq_protocol::FramingError::TooLarge { limit, actual } => {
            ProtocolRejectionFailure::FrameTooLarge { limit, actual }
        }
        nq_protocol::FramingError::NotExactlyOneLine => ProtocolRejectionFailure::InvalidFraming,
        nq_protocol::FramingError::Json(error) => ProtocolRejectionFailure::InvalidJson {
            error: structured_json_error(&error),
        },
        nq_protocol::FramingError::Validation(error) => ProtocolRejectionFailure::Validation {
            error: protocol_validation_failure(error),
        },
        nq_protocol::FramingError::Canonicalization(error) => {
            ProtocolRejectionFailure::Canonicalization {
                error: protocol_canonicalization_failure(error),
            }
        }
    };
    ProtocolRejection {
        responsible_instance_id: instance_id.to_owned(),
        boundary: ProtocolRejectionBoundary::Response,
        code: ProtocolRejectionCode::InvalidResponse,
        failure,
    }
}

fn profile_normalization_refusal(
    instance_id: &str,
    profile: &'static dyn ProfileModule,
    error: &nq_profiles::ReportNormalizationError,
) -> nq_profiles::ProfileRefusal {
    nq_profiles::ProfileRefusal {
        instance_id: instance_id.to_owned(),
        profile: profile.descriptor().profile.clone(),
        boundary: nq_profiles::RefusalBoundary::Report,
        code: nq_profiles::ProfileRefusalCode::InvalidPayload,
        message: "protocol report could not enter profile validation".into(),
        details: BTreeMap::from([
            ("stage".into(), "protocol_normalization".into()),
            ("error".into(), error.to_string()),
        ]),
    }
}

fn governed_profile_refusal(
    refusal_id: String,
    profile: &'static dyn ProfileModule,
    refusal: nq_profiles::ProfileRefusal,
) -> Result<GovernedRefusal, EngineError> {
    if refusal.profile != profile.descriptor().profile {
        return Err(EngineError::Invariant(format!(
            "profile refusal for {}/{} was produced at compiled profile boundary {}/{}",
            refusal.profile.id,
            refusal.profile.version,
            profile.descriptor().profile.id,
            profile.descriptor().profile.version
        )));
    }
    let semantic_id = profile_semantic_id(profile.descriptor())
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    Ok(GovernedRefusal::profile(refusal_id, semantic_id, refusal))
}

fn structured_json_error(error: &serde_json::Error) -> StructuredJsonError {
    let category = match error.classify() {
        serde_json::error::Category::Io => JsonErrorCategory::Io,
        serde_json::error::Category::Syntax => JsonErrorCategory::Syntax,
        serde_json::error::Category::Data => JsonErrorCategory::Data,
        serde_json::error::Category::Eof => JsonErrorCategory::Eof,
    };
    StructuredJsonError {
        category,
        line: error.line(),
        column: error.column(),
        diagnostic: crate::runner::bounded_acquisition_detail(error.to_string()),
    }
}

fn protocol_canonicalization_failure(
    error: nq_protocol::CanonicalizationError,
) -> ProtocolCanonicalizationFailure {
    match error {
        nq_protocol::CanonicalizationError::Serialization(error) => {
            ProtocolCanonicalizationFailure::Serialization {
                error: structured_json_error(&error),
            }
        }
        nq_protocol::CanonicalizationError::UnsafeInteger(value) => {
            ProtocolCanonicalizationFailure::UnsafeInteger { value }
        }
    }
}

fn protocol_validation_failure(error: nq_protocol::ValidationError) -> ProtocolValidationFailure {
    match error {
        nq_protocol::ValidationError::InvalidSchema {
            document,
            expected,
            actual,
        } => ProtocolValidationFailure::InvalidSchema {
            document: document.to_owned(),
            expected: expected.to_owned(),
            actual,
        },
        nq_protocol::ValidationError::InvalidProtocolVersion { expected, actual } => {
            ProtocolValidationFailure::InvalidProtocolVersion {
                expected: expected.to_owned(),
                actual,
            }
        }
        nq_protocol::ValidationError::InvalidField { field, reason } => {
            ProtocolValidationFailure::InvalidField {
                field: field.to_owned(),
                reason: crate::runner::bounded_acquisition_detail(reason),
            }
        }
        nq_protocol::ValidationError::BoundExceeded {
            field,
            limit,
            actual,
        } => ProtocolValidationFailure::BoundExceeded {
            field: field.to_owned(),
            limit,
            actual,
        },
        nq_protocol::ValidationError::Duplicate { field, value } => {
            ProtocolValidationFailure::Duplicate {
                field: field.to_owned(),
                value,
            }
        }
        nq_protocol::ValidationError::EchoMismatch { field } => {
            ProtocolValidationFailure::EchoMismatch {
                field: field.to_owned(),
            }
        }
        nq_protocol::ValidationError::CapabilityEscape(capability) => {
            ProtocolValidationFailure::CapabilityEscape { capability }
        }
        nq_protocol::ValidationError::Canonicalization { field, source } => {
            ProtocolValidationFailure::Canonicalization {
                field: field.to_owned(),
                source: protocol_canonicalization_failure(source),
            }
        }
    }
}

fn stored_governed_refusal(
    refusal: &GovernedRefusal,
    created_at: DateTime<Utc>,
) -> Result<RefusalInput, EngineError> {
    refusal.validate()?;
    let (source_kind, boundary, code) = governed_refusal_projections(refusal)?;
    Ok(RefusalInput {
        refusal_id: refusal.refusal_id.clone(),
        source_kind,
        responsible_instance_id: refusal.responsible_instance_id().to_owned(),
        boundary,
        code,
        profile_semantic_id: match &refusal.origin {
            GovernedRefusalOrigin::Profile(profile) => {
                Some(profile.profile_semantic_id.as_str().to_owned())
            }
            _ => None,
        },
        detail: canonical(refusal)?,
        created_at: timestamp(created_at),
    })
}

fn governed_refusal_projections(
    refusal: &GovernedRefusal,
) -> Result<(String, String, String), EngineError> {
    let (source_kind, boundary, code) = match &refusal.origin {
        GovernedRefusalOrigin::Acquisition(refusal) => (
            "acquisition".to_owned(),
            "acquisition".to_owned(),
            enum_token(&refusal.failure.class)?,
        ),
        GovernedRefusalOrigin::Protocol(refusal) => (
            "protocol".to_owned(),
            enum_token(&refusal.boundary)?,
            enum_token(&refusal.code)?,
        ),
        // Origin and semantic boundary are independent. Every valid helper
        // ResponseOutcome refusal is helper-protocol testimony even when its
        // exact refusing boundary is profile, collection, or resource.
        GovernedRefusalOrigin::Helper(source) => (
            "protocol".to_owned(),
            enum_token(&source.boundary)?,
            enum_token(&source.code)?,
        ),
        GovernedRefusalOrigin::Profile(profile) => (
            "profile".to_owned(),
            enum_token(&profile.refusal.boundary)?,
            enum_token(&profile.refusal.code)?,
        ),
    };
    Ok((source_kind, boundary, code))
}

fn admission_refusal_from_engine(
    instance_id: &str,
    fallback_boundary: AdmissionRefusalBoundary,
    error: EngineError,
) -> AdmissionRefusal {
    let (boundary, code, details) = match error {
        EngineError::Admission(error) => return admission_refusal(instance_id, error),
        EngineError::Store(error) => (
            AdmissionRefusalBoundary::Storage,
            AdmissionRefusalCode::StoreFailure,
            AdmissionRefusalDetails::Storage {
                message: error.to_string(),
            },
        ),
        EngineError::Coordination(error) => (
            AdmissionRefusalBoundary::Coordination,
            AdmissionRefusalCode::CoordinationFailure,
            AdmissionRefusalDetails::Coordination {
                message: error.to_string(),
            },
        ),
        EngineError::ProviderIntake(error) => (
            AdmissionRefusalBoundary::Internal,
            AdmissionRefusalCode::InvariantViolation,
            AdmissionRefusalDetails::Invariant {
                message: error.to_string(),
            },
        ),
        EngineError::HostRoleRuntime(error) => (
            AdmissionRefusalBoundary::Internal,
            AdmissionRefusalCode::InvariantViolation,
            AdmissionRefusalDetails::Invariant {
                message: error.to_string(),
            },
        ),
        EngineError::Io(error) => (
            AdmissionRefusalBoundary::Materialization,
            AdmissionRefusalCode::MaterializationFailure,
            AdmissionRefusalDetails::Materialization {
                path: None,
                message: error.to_string(),
            },
        ),
        EngineError::UnknownProfile { id, version } => (
            AdmissionRefusalBoundary::Profile,
            AdmissionRefusalCode::UnknownProfile,
            AdmissionRefusalDetails::ProfileIdentity { id, version },
        ),
        EngineError::Token(message) => (
            AdmissionRefusalBoundary::Protocol,
            AdmissionRefusalCode::InvalidIdentityToken,
            AdmissionRefusalDetails::IdentityToken { message },
        ),
        EngineError::Protocol(message) => (
            AdmissionRefusalBoundary::Protocol,
            AdmissionRefusalCode::ProtocolFailure,
            AdmissionRefusalDetails::Protocol { message },
        ),
        EngineError::Profile(message) => (
            AdmissionRefusalBoundary::Profile,
            AdmissionRefusalCode::ProfileFailure,
            AdmissionRefusalDetails::ProfileProcessing { message },
        ),
        EngineError::Canonical(message) => (
            AdmissionRefusalBoundary::Serialization,
            AdmissionRefusalCode::CanonicalizationFailure,
            AdmissionRefusalDetails::Canonicalization { message },
        ),
        EngineError::DiagnosticUnsupported(message) | EngineError::Invariant(message) => (
            AdmissionRefusalBoundary::Internal,
            AdmissionRefusalCode::InvariantViolation,
            AdmissionRefusalDetails::Invariant { message },
        ),
        EngineError::GovernedExecutionRefused { code, detail } => (
            AdmissionRefusalBoundary::Internal,
            AdmissionRefusalCode::InvariantViolation,
            AdmissionRefusalDetails::Invariant {
                message: format!("native governed execution refused at {code:?}: {detail}"),
            },
        ),
        EngineError::GovernedRefusal(refusal) => (
            fallback_boundary,
            AdmissionRefusalCode::UpstreamRefusal,
            AdmissionRefusalDetails::Governed { refusal },
        ),
        EngineError::AcquisitionFailed(failure) => (
            fallback_boundary,
            AdmissionRefusalCode::UpstreamRefusal,
            AdmissionRefusalDetails::Acquisition { failure: *failure },
        ),
    };
    AdmissionRefusal {
        responsible_instance_id: instance_id.to_owned(),
        boundary,
        code,
        details,
    }
}

fn admission_refusal(instance_id: &str, error: AdmissionError) -> AdmissionRefusal {
    let (boundary, code, details) = match error {
        AdmissionError::Binary(error) => (
            AdmissionRefusalBoundary::ExecutionIdentity,
            AdmissionRefusalCode::BinaryIdentityInvalid,
            AdmissionRefusalDetails::BinaryIdentity {
                message: error.to_string(),
            },
        ),
        AdmissionError::ConfigDrift { instance_id } => (
            AdmissionRefusalBoundary::ActiveBinding,
            AdmissionRefusalCode::ConfigDrift,
            AdmissionRefusalDetails::ConfigDrift {
                observed_instance_id: instance_id,
            },
        ),
        AdmissionError::ProfileDrift {
            instance_id,
            message,
        } => (
            AdmissionRefusalBoundary::ActiveBinding,
            AdmissionRefusalCode::ProfileDrift,
            AdmissionRefusalDetails::ProfileDrift {
                observed_instance_id: instance_id,
                message,
            },
        ),
        AdmissionError::ProtocolDrift { instance_id } => (
            AdmissionRefusalBoundary::ActiveBinding,
            AdmissionRefusalCode::ProtocolDrift,
            AdmissionRefusalDetails::ProtocolDrift {
                observed_instance_id: instance_id,
            },
        ),
        AdmissionError::Malformed {
            instance_id,
            message,
        } => (
            AdmissionRefusalBoundary::ActiveBinding,
            AdmissionRefusalCode::MalformedBinding,
            AdmissionRefusalDetails::MalformedBinding {
                observed_instance_id: instance_id,
                message,
            },
        ),
        AdmissionError::ConformanceFailed(message) => (
            AdmissionRefusalBoundary::Conformance,
            AdmissionRefusalCode::ConformanceFailed,
            AdmissionRefusalDetails::ConformanceFailed { message },
        ),
        AdmissionError::ConformanceDrift {
            instance_id,
            message,
        } => (
            AdmissionRefusalBoundary::Conformance,
            AdmissionRefusalCode::ConformanceDrift,
            AdmissionRefusalDetails::ConformanceDrift {
                observed_instance_id: instance_id,
                message,
            },
        ),
        AdmissionError::Io { path, source } => (
            AdmissionRefusalBoundary::Materialization,
            AdmissionRefusalCode::MaterializationFailure,
            AdmissionRefusalDetails::Materialization {
                path: Some(path.display().to_string()),
                message: source.to_string(),
            },
        ),
    };
    AdmissionRefusal {
        responsible_instance_id: instance_id.to_owned(),
        boundary,
        code,
        details,
    }
}

fn reconstruct_admitted(
    row: &nq_store::AdmittedReportRow,
    profile: &'static dyn ProfileModule,
) -> Result<DetectorReport, EngineError> {
    let report: nq_protocol::EvidenceReport = serde_json::from_slice(&row.canonical_json)
        .map_err(|error| EngineError::Invariant(format!("stored report cannot decode: {error}")))?;
    let digest = Sha256Digest::parse(row.semantic_digest.clone())
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let normalized = ProfileReportInput::from_protocol(&report, &digest)
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    let context = ValidationContext {
        instance_id: row.instance_id.clone(),
        request_subject: report.binding.subject.to_string(),
        scope: ScopeGrant {
            kind: report.binding.scope.kind.to_string(),
            value: report.binding.scope.value.clone(),
        },
        vantage: VantageGrant {
            kind: report.binding.vantage.kind.to_string(),
            value: report.binding.vantage.value.clone(),
        },
        granted_capabilities: report
            .used_capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
        received_at: parse_timestamp(&row.received_at)?,
        max_observations: profile.descriptor().limits.max_observations,
        max_future_skew: Duration::seconds(60),
    };
    let validated = profile.validate(&context, &normalized).map_err(|refusal| {
        EngineError::Invariant(format!(
            "previously admitted report {} no longer validates: {}",
            row.report_id, refusal.message
        ))
    })?;
    let report_sequence = u64::try_from(row.report_sequence).map_err(|_| {
        EngineError::Invariant(format!(
            "admitted report {} has a negative durable sequence",
            row.report_id
        ))
    })?;
    if report_sequence == 0 {
        return Err(EngineError::Invariant(format!(
            "admitted report {} has a zero durable sequence",
            row.report_id
        )));
    }
    Ok(DetectorReport {
        report_id: row.report_id.clone(),
        report_sequence,
        report: validated,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
/// Parse an already-`sha256:`-shaped identity string into the typed digest the
/// store requires. A failure here is an internal invariant, not caller input.
fn parse_identity_digest(field: &str, value: &str) -> Result<Sha256Digest, EngineError> {
    Sha256Digest::parse(value).map_err(|_| {
        EngineError::Invariant(format!("{field} is not a valid sha256 digest: {value}"))
    })
}

/// Canonical ordered-set digest of a profile's detector semantic ids. Binds the
/// admitted judging mechanism to the exact detector suite, independent of which
/// detector later produces any one finding.
fn detector_identity_digest(
    profile: &'static dyn ProfileModule,
) -> Result<Sha256Digest, EngineError> {
    let ids: Vec<String> = profile
        .detectors()
        .iter()
        .map(|detector| {
            detector
                .descriptor()
                .digest()
                .map_err(EngineError::Canonical)
        })
        .collect::<Result<_, _>>()?;
    nq_store::detector_suite_identity_digest(ids).map_err(EngineError::from)
}

fn governed_evaluation_result(
    result: &nq_profiles::DetectorResult,
    profile: EvaluationProfileIdentity,
    refusal: Option<GovernedRefusal>,
) -> Result<EvaluationResultV1, EngineError> {
    if (result.state == DetectorState::CannotEvaluate) != refusal.is_some() {
        return Err(EngineError::Invariant(
            "cannot_evaluate requires exactly one canonical governed refusal".into(),
        ));
    }
    match (&result.refusal, &refusal) {
        (
            Some(source),
            Some(GovernedRefusal {
                origin: GovernedRefusalOrigin::Profile(governed),
                ..
            }),
        ) if source == &governed.refusal => {}
        (None, None) => {}
        _ => {
            return Err(EngineError::Invariant(
                "governed evaluation refusal differs from the detector source refusal".into(),
            ));
        }
    }
    Ok(EvaluationResultV1 {
        schema: EvaluationResultSchema::V1,
        profile,
        state: result.state,
        condition: result.condition.clone(),
        summary: result.summary.clone(),
        evidence: result.evidence.clone(),
        limitations: result.limitations.clone(),
        refusal,
        watermark: result.watermark,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_finding_event(
    watcher: &WatcherConfig,
    profile: &'static dyn ProfileModule,
    descriptor: &nq_profiles::DetectorDescriptor,
    result: &nq_profiles::DetectorResult,
    governed_refusal: Option<&GovernedRefusal>,
    evaluated_at: DateTime<Utc>,
    current: Option<&nq_store::FindingSnapshotRow>,
    rows: &[nq_store::AdmittedReportRow],
) -> Result<Option<FindingEventInput>, EngineError> {
    if current.is_none() && result.state != DetectorState::Present {
        return Ok(None);
    }
    if current.is_some_and(|finding| finding.condition_state == "explicitly_absent")
        && result.state == DetectorState::ExplicitlyAbsent
    {
        return Ok(None);
    }
    let event_kind = match (current, result.state) {
        (None, DetectorState::Present) => "opened",
        (Some(existing), DetectorState::Present)
            if existing.condition_state == "explicitly_absent" =>
        {
            "reopened"
        }
        (Some(_), DetectorState::ExplicitlyAbsent) => "resolved",
        (Some(_), _) => "updated",
        (None, _) => return Ok(None),
    };
    let finding_id =
        current.map_or_else(|| Uuid::new_v4().to_string(), |row| row.finding_id.clone());
    let visibility = visibility_for(result, profile, evaluated_at, rows);
    let evidence = if result.evidence.is_empty() {
        current
            .map(|finding| retained_finding_evidence(finding, rows))
            .transpose()?
            .unwrap_or_default()
    } else {
        result
            .evidence
            .iter()
            .enumerate()
            .map(|(ordinal, evidence)| {
                let report_sequence = i64::try_from(evidence.report_sequence).map_err(|_| {
                    EngineError::Invariant(format!(
                        "detector cited report {} with a sequence outside SQLite INTEGER",
                        evidence.report_id
                    ))
                })?;
                let row = rows
                    .iter()
                    .find(|row| {
                        row.report_id == evidence.report_id
                            && row.report_sequence == report_sequence
                            && row.semantic_digest == evidence.report_digest
                    })
                    .ok_or_else(|| {
                        EngineError::Invariant(format!(
                            "detector cited unknown report occurrence {} at sequence {} with digest {}",
                            evidence.report_id,
                            evidence.report_sequence,
                            evidence.report_digest
                        ))
                    })?;
                Ok(FindingEvidenceInput {
                    ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                    report_id: row.report_id.clone(),
                    report_semantic_digest: row.semantic_digest.clone(),
                    observation_ordinal: evidence.observation_ordinal,
                    observed_at: timestamp(evidence.observed_at),
                    received_at: row.received_at.clone(),
                })
            })
            .collect::<Result<Vec<_>, EngineError>>()?
    };
    let newest = evidence
        .iter()
        .filter_map(|evidence| rows.iter().find(|row| row.report_id == evidence.report_id))
        .max_by_key(|row| row.report_sequence);
    Ok(Some(FindingEventInput {
        event_id: Uuid::new_v4().to_string(),
        finding_id,
        event_kind: event_kind.into(),
        instance_id: watcher.instance_id.clone(),
        profile_id: profile.descriptor().profile.id.clone(),
        profile_version: profile.descriptor().profile.version.to_string(),
        profile_digest: profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?
            .as_str()
            .into(),
        subject: canonical(&watcher.subject)?,
        condition_name: descriptor.condition.clone(),
        condition_state: if result.state == DetectorState::CannotEvaluate {
            current.map_or("cannot_evaluate", |finding| {
                finding.condition_state.as_str()
            })
        } else {
            detector_state(result.state)
        }
        .into(),
        visibility_state: visibility.0.into(),
        operator_work_state: current.map_or_else(
            || "unreviewed".to_owned(),
            |row| row.operator_work_state.clone(),
        ),
        severity: match result.state {
            DetectorState::Present => "warning".to_owned(),
            DetectorState::ExplicitlyAbsent => "info".to_owned(),
            DetectorState::CannotEvaluate => {
                current.map_or_else(|| "info".to_owned(), |finding| finding.severity.clone())
            }
        },
        summary: if result.state == DetectorState::CannotEvaluate {
            current.map_or_else(|| result.summary.clone(), |finding| finding.summary.clone())
        } else {
            result.summary.clone()
        },
        limitations: canonical(&result.limitations)?,
        safe_next_checks: canonical(&vec![
            "Inspect the cited admitted evidence".to_owned(),
            "Run `nq watcher test` if collection remains unavailable".to_owned(),
        ])?,
        freshness: canonical(&visibility.1)?,
        basis: canonical(&json!({
            "profile_digest": profile.descriptor().digest().map_err(|error| EngineError::Canonical(error.to_string()))?.as_str(),
            "vantage": watcher.vantage,
            "scope": watcher.scope,
        }))?,
        refusal: governed_refusal.map(canonical).transpose()?,
        origin_mode: "native".into(),
        historical_refs: canonical(&Vec::<String>::new())?,
        observed_at: newest.map(|row| row.observed_at.clone()),
        received_at: newest.map(|row| row.received_at.clone()),
        created_at: timestamp(evaluated_at),
        evidence,
    }))
}

fn retained_finding_evidence(
    finding: &nq_store::FindingSnapshotRow,
    rows: &[nq_store::AdmittedReportRow],
) -> Result<Vec<FindingEvidenceInput>, EngineError> {
    let references: Vec<PublicEvidenceReference> = serde_json::from_str(&finding.evidence_json)
        .map_err(|error| {
            EngineError::Invariant(format!("invalid retained finding evidence: {error}"))
        })?;
    references
        .into_iter()
        .enumerate()
        .map(|(ordinal, reference)| {
            if !rows.iter().any(|row| {
                row.report_id == reference.report_id
                    && row.semantic_digest == reference.semantic_digest
            }) {
                return Err(EngineError::Invariant(format!(
                    "retained finding evidence {} is outside the evaluation watermark",
                    reference.report_id
                )));
            }
            Ok(FindingEvidenceInput {
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                report_id: reference.report_id,
                report_semantic_digest: reference.semantic_digest,
                observation_ordinal: reference.observation_ordinal,
                observed_at: timestamp(reference.observed_at),
                received_at: timestamp(reference.received_at),
            })
        })
        .collect()
}

fn visibility_for(
    result: &nq_profiles::DetectorResult,
    profile: &'static dyn ProfileModule,
    evaluated_at: DateTime<Utc>,
    rows: &[nq_store::AdmittedReportRow],
) -> (&'static str, Value) {
    if result.state != DetectorState::CannotEvaluate {
        return ("sufficient", json!({"state": "current"}));
    }
    let Some(newest) = rows.iter().max_by_key(|row| row.report_sequence) else {
        return ("missing", json!({"state": "missing"}));
    };
    if newest.report_status == "partial" || newest.report_status == "failed" {
        return (
            "partial",
            json!({"state": newest.report_status, "observed_at": newest.observed_at}),
        );
    }
    let observed = parse_timestamp(&newest.observed_at).ok();
    let stale = observed.is_none_or(|observed| {
        evaluated_at.signed_duration_since(observed)
            > Duration::seconds(
                i64::try_from(profile.descriptor().freshness.reliance_seconds).unwrap_or(i64::MAX),
            )
    });
    if stale {
        (
            "stale",
            json!({
                "state": "stale",
                "observed_at": newest.observed_at,
                "reliance_seconds": profile.descriptor().freshness.reliance_seconds,
            }),
        )
    } else {
        ("refused", json!({"state": "cannot_evaluate"}))
    }
}

fn archive_active_lock(
    admissions_dir: &Path,
    previous: &AdmissionLock,
) -> Result<PathBuf, EngineError> {
    let history = history_lock_directory(admissions_dir, previous);
    fs::create_dir_all(&history)?;
    let manager = AdmissionManager;
    Ok(manager.activate(&history, previous)?)
}

fn history_lock_directory(admissions_dir: &Path, lock: &AdmissionLock) -> PathBuf {
    admissions_dir
        .join("history")
        .join(&lock.instance_id)
        .join(&lock.admission_id)
}

fn history_lock_path(admissions_dir: &Path, lock: &AdmissionLock) -> PathBuf {
    history_lock_directory(admissions_dir, lock).join(format!("{}.json", lock.instance_id))
}

fn boottime_ns() -> Result<u64, EngineError> {
    let sample = clock_gettime(ClockId::CLOCK_BOOTTIME)
        .map_err(|error| EngineError::Invariant(format!("CLOCK_BOOTTIME unavailable: {error}")))?;
    let seconds = u64::try_from(sample.tv_sec())
        .map_err(|_| EngineError::Invariant("CLOCK_BOOTTIME returned negative seconds".into()))?;
    let nanoseconds = u64::try_from(sample.tv_nsec()).map_err(|_| {
        EngineError::Invariant("CLOCK_BOOTTIME returned negative nanoseconds".into())
    })?;
    if nanoseconds >= 1_000_000_000 {
        return Err(EngineError::Invariant(
            "CLOCK_BOOTTIME returned invalid nanoseconds".into(),
        ));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| EngineError::Invariant("CLOCK_BOOTTIME overflowed u64".into()))
}

fn token<T>(value: Result<T, nq_protocol::TokenError>) -> Result<T, EngineError> {
    value.map_err(|error| EngineError::Token(error.to_string()))
}

fn canonical<T: Serialize>(value: &T) -> Result<CanonicalDocument, EngineError> {
    CanonicalDocument::from_serializable(value).map_err(EngineError::from)
}

fn enum_token<T: Serialize>(value: &T) -> Result<String, EngineError> {
    serde_json::to_value(value)
        .map_err(|error| EngineError::Canonical(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| EngineError::Canonical("enum did not serialize as a string".into()))
}

fn semantic_report_status(status: SemanticReportStatus) -> &'static str {
    match status {
        SemanticReportStatus::Complete => "complete",
        SemanticReportStatus::Partial => "partial",
        SemanticReportStatus::Failed => "failed",
    }
}

fn normalize_unix_capture(
    started_at: DateTime<Utc>,
    started: Instant,
    capture: UnixExchangeCapture,
) -> RunCapture {
    let exit_code = match &capture.outcome {
        UnixAcquisitionOutcome::HelperExited { code } => *code,
        _ => None,
    };
    RunCapture {
        started_at,
        finished_at: capture.finished_at,
        duration_ms: elapsed_ms(started),
        exit_code,
        stdout: capture.response,
        stderr: capture.stderr,
        outcome: unix_acquisition_outcome(capture.outcome),
    }
}

fn unix_acquisition_outcome(outcome: UnixAcquisitionOutcome) -> AcquisitionOutcome {
    match outcome {
        UnixAcquisitionOutcome::Response => AcquisitionOutcome::Response,
        UnixAcquisitionOutcome::InvalidRequestFraming { message }
        | UnixAcquisitionOutcome::MalformedFraming { message } => {
            AcquisitionOutcome::MalformedFraming {
                message: crate::runner::bounded_acquisition_detail(message),
            }
        }
        UnixAcquisitionOutcome::RequestWriteFailed { message } => {
            AcquisitionOutcome::RequestWriteFailed {
                message: crate::runner::bounded_acquisition_detail(message),
            }
        }
        UnixAcquisitionOutcome::Timeout { phase } => AcquisitionOutcome::ExchangeTimeout {
            phase: match phase {
                UnixIoPhase::WriteRequest => ExchangeTimeoutPhase::WriteRequest,
                UnixIoPhase::ReadResponse => ExchangeTimeoutPhase::ReadResponse,
            },
        },
        UnixAcquisitionOutcome::OutputTooLarge => AcquisitionOutcome::OutputTooLarge,
        UnixAcquisitionOutcome::StderrTooLarge => AcquisitionOutcome::StderrTooLarge,
        UnixAcquisitionOutcome::Eof => AcquisitionOutcome::Eof,
        UnixAcquisitionOutcome::Disconnect { message } => AcquisitionOutcome::Disconnect {
            message: crate::runner::bounded_acquisition_detail(message),
        },
        UnixAcquisitionOutcome::MalformedJson { message } => AcquisitionOutcome::MalformedJson {
            message: crate::runner::bounded_acquisition_detail(message),
        },
        UnixAcquisitionOutcome::HelperExited { code } => AcquisitionOutcome::HelperExited { code },
        UnixAcquisitionOutcome::NotRunning => AcquisitionOutcome::NotRunning,
        UnixAcquisitionOutcome::IoFailed { message } => AcquisitionOutcome::IoFailed {
            message: crate::runner::bounded_acquisition_detail(message),
        },
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::Stdio => "stdio",
        Carrier::Unix => "unix",
    }
}

fn detector_state(state: DetectorState) -> &'static str {
    match state {
        DetectorState::Present => "present",
        DetectorState::ExplicitlyAbsent => "explicitly_absent",
        DetectorState::CannotEvaluate => "cannot_evaluate",
    }
}

pub(crate) fn acquisition_code(outcome: &AcquisitionOutcome) -> &'static str {
    match outcome {
        AcquisitionOutcome::Response => "response",
        AcquisitionOutcome::SpawnFailed { .. } => "spawn_failed",
        AcquisitionOutcome::RequestWriteFailed { .. } => "request_write_failed",
        AcquisitionOutcome::Timeout | AcquisitionOutcome::ExchangeTimeout { .. } => "timeout",
        AcquisitionOutcome::OutputTooLarge => "output_too_large",
        AcquisitionOutcome::StderrTooLarge => "stderr_too_large",
        AcquisitionOutcome::Eof => "eof",
        AcquisitionOutcome::MalformedFraming { .. } => "malformed_framing",
        AcquisitionOutcome::MalformedJson { .. } => "malformed_json",
        AcquisitionOutcome::ExitNonzero { .. } => "exit_nonzero",
        AcquisitionOutcome::HelperExited { .. } => "helper_exited",
        AcquisitionOutcome::Disconnect { .. } => "disconnect",
        AcquisitionOutcome::CarrierStartupFailed { .. } => "carrier_startup_failed",
        AcquisitionOutcome::NotRunning => "not_running",
        AcquisitionOutcome::IoFailed { .. } => "io_failed",
    }
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn deadline_timestamp(value: DateTime<Utc>) -> String {
    if value.timestamp_subsec_nanos().is_multiple_of(1_000_000) {
        timestamp(value)
    } else {
        value.to_rfc3339_opts(SecondsFormat::Nanos, true)
    }
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, EngineError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| EngineError::Invariant(format!("invalid stored timestamp: {error}")))
}

/// Append a compiled descriptor snapshot during explicit initialization.
///
/// # Errors
///
/// Returns a canonicalization or storage error.
pub fn append_profile_descriptor(
    session: &mut StoreWriterSession<'_>,
    module: &dyn ProfileModule,
) -> Result<(), EngineError> {
    let descriptor = module.descriptor();
    session.append_profile_descriptor(&ProfileDescriptorInput {
        profile_id: descriptor.profile.id.clone(),
        profile_version: descriptor.profile.version.to_string(),
        descriptor: canonical(descriptor)?,
        recorded_at: timestamp(Utc::now()),
    })?;
    Ok(())
}

/// Append the fresh-store genesis record. This never imports active legacy
/// state.
///
/// # Errors
///
/// Returns a canonicalization or storage error.
pub fn append_genesis(
    session: &mut StoreWriterSession<'_>,
    legacy_digest: Option<String>,
) -> Result<(), EngineError> {
    session.append_genesis(&GenesisInput {
        genesis_id: Uuid::new_v4().to_string(),
        legacy_manifest_digest: legacy_digest,
        created_at: timestamp(Utc::now()),
        detail: canonical(&json!({
            "schema": "nq.genesis.v1",
            "legacy_state_imported": false,
        }))?,
    })?;
    Ok(())
}

/// Append and project one bounded component-health event.
///
/// # Errors
///
/// Returns when the details cannot be canonicalized, the durable status event
/// violates the storage contract, or a caller tries to emit a legacy
/// scheduler/notification kind that NQ no longer owns.
pub fn record_component_status(
    session: &mut StoreWriterSession<'_>,
    component_kind: &str,
    component_id: &str,
    state: &str,
    code: &str,
    details: &Value,
) -> Result<(), EngineError> {
    if matches!(component_kind, "scheduler" | "notification") {
        return Err(EngineError::Invariant(format!(
            "{component_kind} status is legacy decode-only; current NQ cannot emit it"
        )));
    }
    session.record_status(&StatusEventInput {
        status_event_id: Uuid::new_v4().to_string(),
        component_kind: component_kind.to_owned(),
        component_id: component_id.to_owned(),
        state: state.to_owned(),
        code: code.to_owned(),
        detail: canonical(details)?,
        observed_at: timestamp(Utc::now()),
    })?;
    Ok(())
}

/// Create a consistent `SQLite` backup through the storage boundary.
///
/// # Errors
///
/// Returns when the source, backup, or verification step fails.
pub fn backup_store(store: &mut Store, destination: &Path) -> Result<(), EngineError> {
    validate_semantic_history(store)?;
    let _artifact = store.backup_verified(destination)?;
    let mut reopened = Store::open(destination)?;
    validate_semantic_history(&mut reopened)?;
    Ok(())
}

/// Exhaustively reopen the complete persisted semantic chain.
///
/// This is the shared fail-closed boundary for operations that may disclose or
/// preserve locally produced diagnostic artifacts. It proves admitted and
/// rejected custody, run/status/evaluation correspondence, the provider's raw
/// interpretation through its durable acknowledgment and canonical result, and
/// finally every diagnostic artifact derived from that history.
///
/// Imported diagnostic artifacts deliberately remain custody-only and callers
/// must not use this function to imply producer authentication for them.
///
/// # Errors
///
/// Returns when any persisted history plane is incomplete, corrupt, or does
/// not correspond exactly to the plane from which it was derived.
pub fn validate_semantic_history(
    store: &mut Store,
) -> Result<DiagnosticArtifactHistoryVerification, EngineError> {
    validate_admitted_report_history(store)?;
    validate_watcher_run_history(store)?;
    validate_status_history_v2(store)?;
    validate_rejected_custody_history(store)?;
    validate_evaluation_refusal_history(store)?;
    validate_provider_intake_history(store)?;
    validate_diagnostic_artifact_history(store)
}

/// Exact provider-intake history counts returned by typed reopening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderIntakeHistoryVerification {
    /// Real schema-v4 provider intakes reopened through raw interpretation.
    pub provider_intakes: usize,
    /// Durable acknowledgments matched to the exact canonical result.
    pub acknowledgments: usize,
    /// Released schema-v3 runs retained only as explicit intake gaps.
    pub legacy_gaps: usize,
}

/// Exhaustively reopen provider-intake identity, raw/native semantics, and
/// acknowledgments without granting a current provider admission.
///
/// # Errors
///
/// Returns if paging is incomplete, a typed carrier differs from its durable
/// projections or raw bytes, an acknowledgment is substituted, or a migrated
/// v3 run claims evidence that its source schema never retained.
#[allow(clippy::too_many_lines)]
pub fn validate_provider_intake_history(
    store: &Store,
) -> Result<ProviderIntakeHistoryVerification, EngineError> {
    // Validate the global relational/digest laws once. Paging and exact-ID
    // reopen below then remain linear in append-only history rather than
    // rescanning the complete store for every row.
    store.validate_provider_intake_history_invariants()?;
    let mut provider_intakes = 0usize;
    let mut acknowledgments = 0usize;
    let mut after_intake_id = None;
    loop {
        let page = store.provider_intakes_bounded(
            nq_store::MAX_PUBLIC_QUERY_ROWS,
            after_intake_id.as_deref(),
        )?;
        if page.is_empty() {
            break;
        }
        for row in &page {
            let raw = store
                .provider_intake_raw_bytes(&row.intake_id)?
                .ok_or_else(|| {
                    EngineError::Invariant(format!(
                        "provider intake {} lacks exact raw custody",
                        row.intake_id
                    ))
                })?;
            let record = ProviderIntakeRecordV1::reopen_store_row(row, &raw)?;
            let (acknowledgment, canonical_result) = store
                .provider_intake_acknowledgment(&row.idempotency_key)?
                .ok_or_else(|| {
                    EngineError::Invariant(format!(
                        "provider intake {} lacks a durable acknowledgment",
                        row.intake_id
                    ))
                })?;
            if acknowledgment != row.acknowledgment
                || acknowledgment.canonical_result_digest != canonical_result.digest()
            {
                return Err(EngineError::Invariant(format!(
                    "provider intake {} acknowledgment does not bind its canonical result",
                    row.intake_id
                )));
            }
            let outcome = decode_collection_outcome(canonical_result.as_bytes())?;
            validate_provider_downstream_correspondence(&record, &outcome)?;
            provider_intakes = provider_intakes.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("provider-intake history count overflowed".into())
            })?;
            acknowledgments = acknowledgments.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("provider acknowledgment count overflowed".into())
            })?;
        }
        after_intake_id = page.last().map(|row| row.intake_id.clone());
        if page.len() < nq_store::MAX_PUBLIC_QUERY_ROWS as usize {
            break;
        }
    }

    let mut legacy_gaps = 0usize;
    let mut after_run_id = None;
    loop {
        let page = store.legacy_provider_intake_gaps_bounded(
            nq_store::MAX_PUBLIC_QUERY_ROWS,
            after_run_id.as_deref(),
        )?;
        if page.is_empty() {
            break;
        }
        for gap in &page {
            let detail =
                nq_store::CanonicalDocument::from_canonical_bytes(gap.detail_json.clone())?;
            let expected_detail = nq_store::CanonicalDocument::from_serializable(&json!({
                "schema": "nq.legacy_provider_intake_gap.v1",
                "source_schema_version": 3,
                "source_schema_artifact_digest": nq_store::SCHEMA_V3_ARTIFACT_DIGEST,
                "limitation": "schema v3 did not preserve a versioned provider intake or exact outer raw capture for every acquisition",
                "provider_intake_synthesized": false,
                "acknowledgment_synthesized": false,
            }))?;
            let migrated_at = DateTime::parse_from_rfc3339(&gap.migrated_at).map_err(|error| {
                EngineError::Invariant(format!(
                    "legacy provider-intake gap {} migration time is not RFC3339: {error}",
                    gap.run_id
                ))
            })?;
            if gap.source_schema_version != 3
                || gap.source_schema_artifact_digest != nq_store::SCHEMA_V3_ARTIFACT_DIGEST
                || gap.limitation_code != "provider_intake_not_recorded"
                || detail != expected_detail
                || migrated_at.offset().local_minus_utc() != 0
            {
                return Err(EngineError::Invariant(format!(
                    "legacy provider-intake gap {} substitutes or invents historical evidence",
                    gap.run_id
                )));
            }
            legacy_gaps = legacy_gaps.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("legacy provider-intake gap count overflowed".into())
            })?;
        }
        after_run_id = page.last().map(|gap| gap.run_id.clone());
        if page.len() < nq_store::MAX_PUBLIC_QUERY_ROWS as usize {
            break;
        }
    }

    Ok(ProviderIntakeHistoryVerification {
        provider_intakes,
        acknowledgments,
        legacy_gaps,
    })
}

/// Prove that the exact pre-admission provider interpretation is the source
/// plane of the canonical NQ collection result. This authenticates the stored
/// decision. Profile refusal correspondence reruns only the pinned compiled
/// profile admission law; detector evaluation and stored findings are never
/// recomputed here.
#[allow(clippy::too_many_lines)] // Keep the closed interpretation/result matrix auditable in one place.
fn validate_provider_downstream_correspondence(
    intake: &ProviderIntakeRecordV1,
    outcome: &CollectionOutcome,
) -> Result<(), EngineError> {
    validate_provider_downstream_parts(
        &intake.intake_id,
        &intake.request,
        &intake.run_id,
        intake.finished_at,
        &intake.interpretation,
        &intake.native_outcome.outcome,
        intake.raw_length,
        intake.provider.profile_semantic_id.as_str(),
        outcome,
    )
}

fn validate_provider_input_downstream_correspondence(
    intake: &ProviderIntakeInput,
    outcome: &CollectionOutcome,
) -> Result<(), EngineError> {
    let context: ProviderIntakeContextV1 = serde_json::from_slice(intake.context.as_bytes())
        .map_err(|error| {
            EngineError::Invariant(format!(
                "provider intake {} context is not typed v1 before commit: {error}",
                intake.intake_id
            ))
        })?;
    let interpretation: ProviderResponseInterpretationV1 =
        serde_json::from_slice(intake.interpretation.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "provider intake {} interpretation is not typed v1 before commit: {error}",
                intake.intake_id
            ))
        })?;
    let native_outcome: RunResourceOutcomeV1 =
        serde_json::from_slice(intake.native_outcome.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "provider intake {} native outcome is not typed v1 before commit: {error}",
                intake.intake_id
            ))
        })?;
    if context.intake_id != intake.intake_id
        || context.run_id != outcome.run_id.as_deref().unwrap_or_default()
        || context.request.instance_id.as_str() != intake.instance_id
        || context.request.request_id.as_str() != intake.request_id
        || interpretation.kind() != intake.interpretation_kind
        || acquisition_code(&native_outcome.outcome) != intake.native_outcome_kind
    {
        return Err(EngineError::Invariant(format!(
            "provider intake {} typed source projections disagree before commit",
            intake.intake_id
        )));
    }

    validate_provider_downstream_parts(
        &intake.intake_id,
        &context.request,
        &context.run_id,
        parse_timestamp(&intake.finished_at)?,
        &interpretation,
        &native_outcome.outcome,
        intake.raw_bytes.len(),
        intake.profile_semantic_id.as_str(),
        outcome,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn validate_provider_downstream_parts(
    intake_id: &str,
    request: &HelperRequest,
    run_id: &str,
    finished_at: DateTime<Utc>,
    interpretation: &ProviderResponseInterpretationV1,
    native_outcome: &AcquisitionOutcome,
    raw_length: usize,
    expected_profile_semantic_id: &str,
    outcome: &CollectionOutcome,
) -> Result<(), EngineError> {
    let instance_id = request.instance_id.as_str();
    if outcome.instance_id != instance_id || outcome.run_id.as_deref() != Some(run_id) {
        return Err(EngineError::Invariant(format!(
            "provider intake {intake_id} canonical result names a different instance or run"
        )));
    }

    let corresponds = match (interpretation, &outcome.result) {
        (
            ProviderResponseInterpretationV1::NotAvailable,
            CollectionResult::AcquisitionFailed { failure },
        ) => {
            AcquisitionFailure::from_outcome(native_outcome.clone())
                .is_some_and(|expected| expected == *failure)
                && !(raw_length != 0
                    && matches!(
                        native_outcome,
                        AcquisitionOutcome::MalformedFraming { .. }
                            | AcquisitionOutcome::MalformedJson { .. }
                            | AcquisitionOutcome::ExitNonzero { .. }
                    ))
        }
        (
            ProviderResponseInterpretationV1::NotAvailable,
            CollectionResult::Rejected {
                refusal:
                    GovernedRefusal {
                        origin: GovernedRefusalOrigin::Acquisition(refusal),
                        ..
                    },
            },
        ) => {
            raw_length != 0
                && matches!(
                    native_outcome,
                    AcquisitionOutcome::MalformedFraming { .. }
                        | AcquisitionOutcome::MalformedJson { .. }
                        | AcquisitionOutcome::ExitNonzero { .. }
                )
                && AcquisitionFailure::from_outcome(native_outcome.clone())
                    .is_some_and(|expected| expected == refusal.failure)
                && refusal.responsible_instance_id == outcome.instance_id
        }
        (
            ProviderResponseInterpretationV1::ProtocolRejected { rejection },
            CollectionResult::Rejected {
                refusal:
                    GovernedRefusal {
                        origin: GovernedRefusalOrigin::Protocol(stored),
                        ..
                    },
            },
        ) => stored == rejection,
        (
            ProviderResponseInterpretationV1::Validated {
                response:
                    nq_protocol::HelperResponse {
                        outcome: ResponseOutcome::Refusal { refusal },
                        ..
                    },
            },
            CollectionResult::Rejected {
                refusal:
                    GovernedRefusal {
                        origin: GovernedRefusalOrigin::Helper(stored),
                        ..
                    },
            },
        ) => stored == refusal,
        (
            ProviderResponseInterpretationV1::Validated {
                response:
                    nq_protocol::HelperResponse {
                        outcome: ResponseOutcome::Report { report },
                        ..
                    },
            },
            CollectionResult::Admitted {
                report_id,
                report_status,
                semantic_digest,
                ..
            },
        ) => {
            let expected_status = match report.status {
                nq_protocol::ReportStatus::Complete => "complete",
                nq_protocol::ReportStatus::Partial => "partial",
                nq_protocol::ReportStatus::Failed => "failed",
            };
            !report_id.is_empty()
                && report_status == expected_status
                && nq_protocol::semantic_digest(report)
                    .is_ok_and(|expected| expected.as_str() == semantic_digest)
        }
        (
            ProviderResponseInterpretationV1::Validated {
                response:
                    nq_protocol::HelperResponse {
                        outcome: ResponseOutcome::Report { report },
                        ..
                    },
            },
            CollectionResult::Rejected {
                refusal:
                    GovernedRefusal {
                        origin: GovernedRefusalOrigin::Profile(profile),
                        ..
                    },
            },
        ) => {
            let Some(module) = nq_profiles::resolve_profile_key(&profile.refusal.profile) else {
                return Err(EngineError::Invariant(format!(
                    "provider intake {intake_id} profile refusal names an uncompiled profile"
                )));
            };
            let Ok(report_digest) = nq_protocol::semantic_digest(report) else {
                return Err(EngineError::Invariant(format!(
                    "provider intake {intake_id} candidate report cannot be digested"
                )));
            };
            let expected_refusal = match ProfileReportInput::from_protocol(report, &report_digest) {
                Ok(normalized) => {
                    let context = ValidationContext::from_request(
                        request,
                        finished_at,
                        Duration::seconds(60),
                    );
                    module.validate(&context, &normalized).err()
                }
                Err(error) => Some(profile_normalization_refusal(instance_id, module, &error)),
            };
            profile.refusal.instance_id == outcome.instance_id
                && profile.refusal.profile.id == report.profile.id.as_str()
                && profile.refusal.profile.version.to_string() == report.profile.version.as_str()
                && profile.profile_semantic_id.as_str() == expected_profile_semantic_id
                && profile_semantic_id(module.descriptor())
                    .is_ok_and(|expected| expected == profile.profile_semantic_id)
                && expected_refusal.as_ref() == Some(&profile.refusal)
        }
        _ => false,
    };
    if !corresponds {
        return Err(EngineError::Invariant(format!(
            "provider intake {intake_id} pre-admission interpretation does not correspond to its canonical NQ result"
        )));
    }
    Ok(())
}

/// Exhaustively authenticate every admitted report and its exact
/// submission/run/admission chain in stable report-id order.
///
/// # Errors
///
/// Returns when association cardinality is not exact or any report fails its
/// persisted admission/judgment/projection verification.
pub fn validate_admitted_report_history(store: &Store) -> Result<usize, EngineError> {
    validate_admitted_report_history_with_page_size(store, nq_store::MAX_PUBLIC_QUERY_ROWS)
}

fn validate_admitted_report_history_with_page_size(
    store: &Store,
    page_size: u32,
) -> Result<usize, EngineError> {
    store.validate_admitted_report_associations()?;
    let mut after_report_id: Option<String> = None;
    let mut validated = 0usize;
    loop {
        let page = store.admitted_report_ids_bounded(page_size, after_report_id.as_deref())?;
        if page.is_empty() {
            return Ok(validated);
        }
        let page_len = page.len();
        for report_id in page {
            after_report_id = Some(report_id.clone());
            let snapshot = store
                .verify_admitted_snapshot(&report_id)
                .map_err(|error| {
                    EngineError::Invariant(format!(
                        "admitted report {report_id} failed historical reopening: {error}"
                    ))
                })?;
            let typed: ValidatedReport = serde_json::from_slice(&snapshot.validated_report_json)
                .map_err(|error| {
                    EngineError::Invariant(format!(
                        "admitted report {report_id} is not the strict owned validated-report schema: {error}"
                    ))
                })?;
            if canonical(&typed)?.as_bytes() != snapshot.validated_report_json {
                return Err(EngineError::Invariant(format!(
                    "admitted report {report_id} validated judgment is not exact canonical typed bytes"
                )));
            }
            validated = validated.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("admitted report history count overflowed".into())
            })?;
        }
        if page_len < page_size as usize {
            return Ok(validated);
        }
    }
}

/// Convert stable SQL finding rows into the exact public DTO.
///
/// # Errors
///
/// Returns when a durable row violates the public DTO contract.
pub fn list_findings(store: &Store) -> Result<Vec<FindingSnapshotV3>, EngineError> {
    validate_evaluation_refusal_history(store)?;
    store
        .finding_snapshots()?
        .into_iter()
        .map(finding_from_row)
        .collect()
}

/// Convert one bounded page of stable SQL finding rows into public DTOs.
///
/// # Errors
///
/// Returns when the page bound is invalid or a durable row violates the DTO.
pub fn list_findings_bounded(
    store: &Store,
    limit: u32,
    after_finding_id: Option<&str>,
) -> Result<Vec<FindingSnapshotV3>, EngineError> {
    validate_evaluation_refusal_history(store)?;
    store
        .finding_snapshots_bounded(limit, after_finding_id)?
        .into_iter()
        .map(finding_from_row)
        .collect()
}

/// Convert stable SQL status rows into the exact shared public DTO.
///
/// # Errors
///
/// Returns when a durable row violates the public DTO contract.
pub fn status_snapshot(store: &Store) -> Result<StatusSnapshotV1, EngineError> {
    if validate_evaluation_refusal_history(store)? != 0 {
        return Err(EngineError::Invariant(
            "nq.status_snapshot.v1 cannot emit governed evaluation results; use v3".into(),
        ));
    }
    let components = store
        .status_snapshots()?
        .into_iter()
        .filter(|row| !is_legacy_decode_only_status_kind(&row.component_kind))
        .map(status_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StatusSnapshotV1 {
        schema: STATUS_SNAPSHOT_SCHEMA.into(),
        generated_at: Utc::now(),
        components,
    })
}

/// Convert stable SQL status rows into the lossless typed v2 DTO.
///
/// # Errors
///
/// Returns when an instance row is legacy/unversioned, cannot decode as the
/// canonical collection carrier, or disagrees with its component identity.
pub fn status_snapshot_v2(store: &Store) -> Result<StatusSnapshotV2, EngineError> {
    validate_status_history_v2(store)?;
    if validate_evaluation_refusal_history(store)? != 0 {
        return Err(EngineError::Invariant(
            "nq.status_snapshot.v2 cannot emit governed evaluation results; use v3".into(),
        ));
    }
    let components = store
        .status_snapshots()?
        .into_iter()
        .filter(|row| !is_legacy_decode_only_status_kind(&row.component_kind))
        .map(|row| status_from_row_v2(store, row))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StatusSnapshotV2 {
        schema: STATUS_SNAPSHOT_V2_SCHEMA.into(),
        generated_at: Utc::now(),
        components,
    })
}

/// Build the lossless current status surface, including the latest canonical
/// result from every exact semantic evaluation lineage.
///
/// The evaluation upper bound is explicit and the complete immutable history
/// through that bound is reopened before any latest-result selection occurs.
///
/// # Errors
///
/// Returns when status history, evaluation history, a canonical carrier, or a
/// projection/linkage invariant cannot be proved exactly.
pub fn status_snapshot_v3(store: &Store) -> Result<StatusSnapshotV3, EngineError> {
    const SNAPSHOT_ATTEMPTS: usize = 8;
    let mut captured = None;
    for _ in 0..SNAPSHOT_ATTEMPTS {
        let status_before = store.latest_status_sequence()?;
        // Collection commits evaluations before its admitted status row.
        // Reading current status before the evaluation bound prevents a
        // component from embedding an evaluation beyond that declared bound.
        let status_rows = store.status_snapshots()?;
        let through = store.latest_evaluation_sequence()?;
        validate_status_history_v2(store)?;
        let mut latest: BTreeMap<Vec<u8>, (i64, i64, EvaluationEnvelopeV2)> = BTreeMap::new();
        visit_evaluation_history_through(
            store,
            nq_store::MAX_PUBLIC_QUERY_ROWS,
            through,
            |row, envelope| {
                let key = evaluation_lineage_key(&envelope)?;
                match latest.entry(key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert((row.evaluation_revision, row.evaluation_sequence, envelope));
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry)
                        if row.evaluation_revision > entry.get().0 =>
                    {
                        entry.insert((row.evaluation_revision, row.evaluation_sequence, envelope));
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {}
                }
                Ok(())
            },
        )?;
        let status_after = store.latest_status_sequence()?;
        if status_before == status_after {
            captured = Some((status_rows, through, latest));
            break;
        }
    }
    let Some((status_rows, through, latest)) = captured else {
        return Err(EngineError::Invariant(
            "could not capture one stable status/evaluation snapshot after 8 attempts".into(),
        ));
    };
    let mut components = status_rows
        .into_iter()
        .filter(|row| !is_legacy_decode_only_status_kind(&row.component_kind))
        .map(|row| status_from_row_v3(store, row))
        .collect::<Result<Vec<_>, _>>()?;

    for (_, sequence, result) in latest.into_values() {
        let (state, code) = evaluation_status_projection(&result);
        components.push(ComponentStatusV3 {
            kind: ComponentKind::Evaluation,
            id: result.evaluation_id.clone(),
            state,
            code: code.to_owned(),
            observed_at: result.evaluated_at,
            detail: ComponentStatusDetailV3::Evaluation {
                sequence: u64::try_from(sequence).map_err(|_| {
                    EngineError::Invariant("negative evaluation sequence reached status".into())
                })?,
                result,
            },
        });
    }
    components.sort_by(|left, right| (&left.kind, &left.id).cmp(&(&right.kind, &right.id)));
    Ok(StatusSnapshotV3 {
        schema: STATUS_SNAPSHOT_V3_SCHEMA.into(),
        generated_at: Utc::now(),
        evaluation_through_sequence: u64::try_from(through)
            .map_err(|_| EngineError::Invariant("negative evaluation snapshot boundary".into()))?,
        components,
    })
}

/// Return one exact, bounded page of immutable governed evaluation history.
/// A caller can hold `through_sequence` constant across pages to obtain a
/// finite logical snapshot while later monotone appends remain outside it.
///
/// # Errors
///
/// Returns for an invalid bound, unsupported page size, or any history whose
/// canonical semantics and durable projections cannot be reopened exactly.
#[allow(clippy::too_many_lines)]
pub fn evaluation_history_bounded(
    store: &Store,
    limit: u32,
    after_sequence: Option<u64>,
    through_sequence: Option<u64>,
) -> Result<EvaluationHistoryPageV1, EngineError> {
    if !(1..=nq_store::MAX_PUBLIC_QUERY_ROWS).contains(&limit) {
        return Err(EngineError::Invariant(format!(
            "evaluation history limit must be between 1 and {}",
            nq_store::MAX_PUBLIC_QUERY_ROWS
        )));
    }
    if after_sequence.is_some() && through_sequence.is_none() {
        return Err(EngineError::Invariant(
            "evaluation history continuation requires its frozen upper bound".into(),
        ));
    }
    let current_through = store.latest_evaluation_sequence()?;
    let requested_through = through_sequence
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| EngineError::Invariant("evaluation history bound overflowed".into()))
        })
        .transpose()?
        .unwrap_or(current_through);
    let after = after_sequence
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| EngineError::Invariant("evaluation history cursor overflowed".into()))
        })
        .transpose()?;
    if requested_through > current_through || after.is_some_and(|value| value > requested_through) {
        return Err(EngineError::Invariant(
            "evaluation history cursor or frozen upper bound is not present".into(),
        ));
    }

    let page_rows = store.evaluation_refusal_history_bounded(limit, after, requested_through)?;
    let cursor = after.unwrap_or(0);
    let available = requested_through.checked_sub(cursor).ok_or_else(|| {
        EngineError::Invariant("evaluation history snapshot arithmetic underflowed".into())
    })?;
    let expected_len = usize::try_from(available.min(i64::from(limit)))
        .map_err(|_| EngineError::Invariant("evaluation history page length overflowed".into()))?;
    if page_rows.len() != expected_len {
        return Err(EngineError::Invariant(format!(
            "evaluation history page reopened {} rows; exact frozen sequence requires {expected_len}",
            page_rows.len()
        )));
    }

    let mut reopened = Vec::new();
    reopened.try_reserve(page_rows.len()).map_err(|_| {
        EngineError::Invariant("evaluation history page allocation overflowed".into())
    })?;
    for (offset, row) in page_rows.into_iter().enumerate() {
        let offset = i64::try_from(offset)
            .map_err(|_| EngineError::Invariant("evaluation page offset overflowed".into()))?;
        let expected_sequence = cursor
            .checked_add(offset)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| EngineError::Invariant("evaluation page cursor overflowed".into()))?;
        if row.evaluation_sequence != expected_sequence {
            return Err(EngineError::Invariant(format!(
                "evaluation history expected sequence {expected_sequence}, reopened {}",
                row.evaluation_sequence
            )));
        }
        let envelope = validate_evaluation_refusal_row(store, &row, true)?;
        reopened.push((row, envelope));
    }

    // A continuation page needs the finding state as it stood at its frozen
    // cursor, not today's `finding_current`. Reopen one prior event for each
    // canonical lineage represented on this page; work and retained state are
    // therefore bounded by `limit`, independent of total immutable history.
    let mut replay = BTreeMap::new();
    for (_, envelope) in &reopened {
        let lineage_key = evaluation_lineage_key(envelope)?;
        if replay.contains_key(&lineage_key) {
            continue;
        }
        let lineage = evaluation_finding_lineage(envelope)?;
        if let Some(prior) = store.prior_finding_for_evaluation_lineage(cursor, &lineage)? {
            if prior.event_revision <= 0 {
                return Err(EngineError::Invariant(format!(
                    "finding event {} has invalid prior revision {}",
                    prior.event_id, prior.event_revision
                )));
            }
            replay.insert(
                lineage_key,
                ReplayedFinding {
                    finding_id: prior.finding_id,
                    event_revision: prior.event_revision,
                    condition_state: prior.condition_state,
                },
            );
        }
    }

    let mut records = Vec::new();
    records.try_reserve(reopened.len()).map_err(|_| {
        EngineError::Invariant("evaluation history result allocation overflowed".into())
    })?;
    for (row, result) in reopened {
        validate_evaluation_finding_replay_step(&row, &result, &mut replay)?;
        records.push(EvaluationHistoryRecordV1 {
            sequence: u64::try_from(row.evaluation_sequence).map_err(|_| {
                EngineError::Invariant("negative evaluation sequence reached history".into())
            })?,
            result,
        });
    }
    let has_more = available > i64::from(limit);
    let next_after_sequence = if has_more {
        records.last().map(|record| record.sequence)
    } else {
        None
    };
    Ok(EvaluationHistoryPageV1 {
        schema: EVALUATION_HISTORY_SCHEMA.into(),
        generated_at: Utc::now(),
        limit,
        after_sequence,
        through_sequence: u64::try_from(requested_through)
            .map_err(|_| EngineError::Invariant("negative evaluation history boundary".into()))?,
        records,
        next_after_sequence,
        complete: !has_more,
    })
}

/// Validate every immutable status event through the strict v2 reopening path.
///
/// This audits history rather than only the rebuildable current projection, so
/// a legacy, substituted, or semantically invalid older instance event cannot
/// be hidden by a newer valid event.
///
/// # Errors
///
/// Returns when any page cannot be read or any event violates the v2 component,
/// canonical collection, status-projection, or linked-refusal contract.
pub fn validate_status_history_v2(store: &Store) -> Result<usize, EngineError> {
    const PAGE_SIZE: u32 = 256;
    validate_status_history_v2_with_page_size(store, PAGE_SIZE)
}

fn validate_status_history_v2_with_page_size(
    store: &Store,
    page_size: u32,
) -> Result<usize, EngineError> {
    validate_watcher_run_history_with_page_size(store, page_size)?;
    let mut after_sequence = None;
    let mut validated = 0usize;
    loop {
        let page = store.status_history_bounded(page_size, after_sequence)?;
        if page.is_empty() {
            return Ok(validated);
        }
        let page_len = page.len();
        for row in page {
            after_sequence = Some(row.status_sequence);
            let component = status_component_v2(
                store,
                &row.component_kind,
                row.component_id,
                &row.state,
                row.code,
                &row.detail_json,
                &row.observed_at,
            )?;
            match &component.detail {
                ComponentStatusDetailV2::Collection { result }
                    if row.run_id.as_deref() != result.run_id.as_deref() =>
                {
                    return Err(EngineError::Invariant(format!(
                        "status event {} lost its atomic collection-run association",
                        row.status_event_id
                    )));
                }
                ComponentStatusDetailV2::Diagnostic { .. } if row.run_id.is_some() => {
                    return Err(EngineError::Invariant(format!(
                        "status event {} links a run outside the collection-result contract",
                        row.status_event_id
                    )));
                }
                ComponentStatusDetailV2::Collection { .. }
                | ComponentStatusDetailV2::Diagnostic { .. } => {}
            }
            validated = validated.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("status history event count overflowed".into())
            })?;
        }
        if page_len < page_size as usize {
            return Ok(validated);
        }
    }
}

/// Exhaustively reopen every watcher run under the strict resource-outcome
/// schema and verify its coarse SQL projection. The store additionally proves
/// that each completed admitted or non-success run has one atomic result link.
///
/// # Errors
///
/// Returns on an unsupported/unversioned resource document, a substituted
/// acquisition projection, or missing/duplicate completed-run result linkage.
pub fn validate_watcher_run_history(store: &Store) -> Result<usize, EngineError> {
    validate_watcher_run_history_with_page_size(store, nq_store::MAX_PUBLIC_QUERY_ROWS)
}

fn validate_watcher_run_history_with_page_size(
    store: &Store,
    page_size: u32,
) -> Result<usize, EngineError> {
    store.validate_run_results()?;
    let mut after_run_id: Option<String> = None;
    let mut validated = 0usize;
    loop {
        let page = store.watcher_run_outcomes_bounded(page_size, after_run_id.as_deref())?;
        if page.is_empty() {
            return Ok(validated);
        }
        let page_len = page.len();
        for run in page {
            after_run_id = Some(run.run_id.clone());
            reopen_run_resource_outcome(&run)?;
            validate_run_profile_identity(&run)?;
            validated = validated.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("watcher run history count overflowed".into())
            })?;
        }
        if page_len < page_size as usize {
            return Ok(validated);
        }
    }
}

/// Exhaustively reopen every immutable detector evaluation and prove that its
/// canonical result, refusal row, and optional finding-event copy carry the
/// same governed refusal bytes and stable identity.
///
/// # Errors
///
/// Returns when any evaluation is unversioned, has an invalid refusal count,
/// substitutes profile semantics, or disagrees with its finding event.
pub fn validate_evaluation_refusal_history(store: &Store) -> Result<usize, EngineError> {
    validate_evaluation_refusal_history_with_page_size(store, nq_store::MAX_PUBLIC_QUERY_ROWS)
}

fn validate_evaluation_refusal_history_with_page_size(
    store: &Store,
    page_size: u32,
) -> Result<usize, EngineError> {
    let through_evaluation_sequence = store.latest_evaluation_sequence()?;
    visit_evaluation_history_through(store, page_size, through_evaluation_sequence, |_, _| Ok(()))
}

fn visit_evaluation_history_through<F>(
    store: &Store,
    page_size: u32,
    through_evaluation_sequence: i64,
    mut visit: F,
) -> Result<usize, EngineError>
where
    F: FnMut(
        nq_store::EvaluationRefusalHistoryRow,
        EvaluationEnvelopeV2,
    ) -> Result<(), EngineError>,
{
    store.validate_evaluation_history_invariants()?;
    let mut after_evaluation_sequence = None;
    let mut replay = BTreeMap::new();
    let mut reopened = 0usize;
    loop {
        let page = store.evaluation_refusal_history_bounded(
            page_size,
            after_evaluation_sequence,
            through_evaluation_sequence,
        )?;
        if page.is_empty() {
            return Ok(reopened);
        }
        let page_len = page.len();
        for row in page {
            after_evaluation_sequence = Some(row.evaluation_sequence);
            let envelope = validate_evaluation_refusal_row(store, &row, true)?;
            validate_evaluation_finding_replay_step(&row, &envelope, &mut replay)?;
            visit(row, envelope)?;
            reopened = reopened.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("evaluation history count overflowed".into())
            })?;
        }
        if page_len < page_size as usize {
            return Ok(reopened);
        }
    }
}

#[derive(Clone)]
struct ReplayedFinding {
    finding_id: String,
    event_revision: i64,
    condition_state: String,
}

fn validate_evaluation_finding_replay_step(
    row: &nq_store::EvaluationRefusalHistoryRow,
    envelope: &EvaluationEnvelopeV2,
    lineages: &mut BTreeMap<Vec<u8>, ReplayedFinding>,
) -> Result<(), EngineError> {
    let lineage = evaluation_lineage_key(envelope)?;
    let prior = lineages.get(&lineage).cloned();
    let requires_event = match envelope.result.state {
        DetectorState::Present => true,
        DetectorState::CannotEvaluate => prior.is_some(),
        DetectorState::ExplicitlyAbsent => prior
            .as_ref()
            .is_some_and(|finding| finding.condition_state != "explicitly_absent"),
    };
    if requires_event != row.finding_event_id.is_some() {
        return Err(EngineError::Invariant(format!(
            "evaluation {} {} a finding transition required by canonical history",
            row.evaluation_id,
            if requires_event { "omits" } else { "invents" }
        )));
    }
    let Some(event_id) = row.finding_event_id.as_deref() else {
        return Ok(());
    };
    let finding_id = row.finding_id.as_deref().ok_or_else(|| {
        EngineError::Invariant(format!("finding event {event_id} has no finding identity"))
    })?;
    let event_revision = row.finding_event_revision.ok_or_else(|| {
        EngineError::Invariant(format!("finding event {event_id} has no revision"))
    })?;
    let condition_state = row.finding_condition_state.as_deref().ok_or_else(|| {
        EngineError::Invariant(format!("finding event {event_id} has no condition state"))
    })?;
    match prior {
        None if event_revision != 1 || row.finding_event_kind.as_deref() != Some("opened") => {
            return Err(EngineError::Invariant(format!(
                "finding event {event_id} does not open canonical lineage at revision one"
            )));
        }
        Some(prior)
            if finding_id != prior.finding_id || event_revision != prior.event_revision + 1 =>
        {
            return Err(EngineError::Invariant(format!(
                "finding event {event_id} substitutes canonical prior lineage"
            )));
        }
        _ => {}
    }
    lineages.insert(
        lineage,
        ReplayedFinding {
            finding_id: finding_id.to_owned(),
            event_revision,
            condition_state: condition_state.to_owned(),
        },
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_evaluation_refusal_row(
    store: &Store,
    row: &nq_store::EvaluationRefusalHistoryRow,
    require_current_catalog: bool,
) -> Result<EvaluationEnvelopeV2, EngineError> {
    if !matches!(row.refusal_count, 0 | 1)
        || i64::from(row.refusal_id.is_some()) != row.refusal_count
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} has {} typed refusal associations; expected its exact optional refusal",
            row.evaluation_id, row.refusal_count
        )));
    }
    if !matches!(row.finding_event_count, 0 | 1)
        || i64::from(row.finding_event_id.is_some()) != row.finding_event_count
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} has {} finding-event associations; expected at most one exact event",
            row.evaluation_id, row.finding_event_count
        )));
    }
    let document = CanonicalDocument::from_canonical_bytes(row.detail_json.clone())?;
    let envelope: EvaluationEnvelopeV2 =
        serde_json::from_slice(document.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "evaluation {} cannot decode as {EVALUATION_ENVELOPE_SCHEMA}: {error}",
                row.evaluation_id
            ))
        })?;
    if canonical(&envelope)?.as_bytes() != document.as_bytes() {
        return Err(EngineError::Invariant(format!(
            "evaluation {} result is not exact canonical bytes",
            row.evaluation_id
        )));
    }
    let result = &envelope.result;
    envelope.validate()?;
    if envelope.evaluation_id != row.evaluation_id
        || envelope.trigger_run_id != row.trigger_run_id
        || envelope.detector.id != row.detector_id
        || envelope.detector.version != row.detector_version
        || envelope.detector.digest != row.detector_digest
        || envelope.evaluator_artifact_digest.as_str() != row.evaluator_artifact_digest
        || parse_timestamp(&row.started_at).ok() != Some(envelope.started_at)
        || parse_timestamp(&row.evaluated_at).ok() != Some(envelope.evaluated_at)
        || envelope.profile != result.profile
        || row.evaluation_profile_id != envelope.profile.profile.id
        || row.evaluation_profile_version != result.profile.profile.version.to_string()
        || row.evaluation_profile_digest != result.profile.profile_digest.as_str()
        || row.evaluation_profile_semantic_id != result.profile.profile_semantic_id.as_str()
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} profile identity or semantic projection was substituted",
            row.evaluation_id
        )));
    }
    if require_current_catalog {
        let compiled =
            nq_profiles::resolve_profile_key(&result.profile.profile).ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} names uncompiled profile {}/{}",
                    row.evaluation_id, result.profile.profile.id, result.profile.profile.version
                ))
            })?;
        let compiled_digest = compiled
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let compiled_semantic_id = profile_semantic_id(compiled.descriptor())
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let detector = compiled
            .detectors()
            .iter()
            .find(|detector| {
                let descriptor = detector.descriptor();
                descriptor.id == row.detector_id
                    && descriptor.version.to_string() == row.detector_version
            })
            .ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} names detector {}/{} outside its compiled profile",
                    row.evaluation_id, row.detector_id, row.detector_version
                ))
            })?;
        let detector_descriptor = detector.descriptor();
        let compiled_detector_digest = detector_descriptor
            .digest()
            .map_err(EngineError::Canonical)?;
        if compiled_digest != result.profile.profile_digest
            || compiled_semantic_id != result.profile.profile_semantic_id
            || row.detector_digest != compiled_detector_digest
            || result.condition != detector_descriptor.condition
        {
            return Err(EngineError::Invariant(format!(
                "evaluation {} differs from the current compiled catalog",
                row.evaluation_id
            )));
        }
    }
    if row.finding_event_id.is_some()
        && (row.finding_profile_id.as_deref() != Some(row.evaluation_profile_id.as_str())
            || row.finding_profile_version.as_deref()
                != Some(row.evaluation_profile_version.as_str())
            || row.finding_profile_digest.as_deref()
                != Some(row.evaluation_profile_digest.as_str()))
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} finding profile binding was substituted",
            row.evaluation_id
        )));
    }
    if row.evaluation_revision <= 0
        || Sha256Digest::parse(row.evaluator_artifact_digest.clone()).is_err()
        || parse_timestamp(&row.started_at).is_err()
        || parse_timestamp(&row.evaluated_at).is_err()
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} has invalid durable revision, evaluator identity, or time",
            row.evaluation_id
        )));
    }
    let expected_outcome = match result.state {
        DetectorState::Present => "condition_present",
        DetectorState::ExplicitlyAbsent => "condition_explicitly_absent",
        DetectorState::CannotEvaluate => "cannot_evaluate",
    };
    if row.outcome != expected_outcome
        || (result.state == DetectorState::CannotEvaluate) != result.refusal.is_some()
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} coarse outcome disagrees with its governed result",
            row.evaluation_id
        )));
    }
    validate_evaluation_finding_projection(row, &envelope)?;
    validate_evaluation_watermarks_and_evidence(store, row, &envelope)?;

    match (&result.refusal, &row.refusal_detail_json) {
        (None, None) => {
            if row.refusal_id.is_some() || row.finding_refusal_json.is_some() {
                return Err(EngineError::Invariant(format!(
                    "successful evaluation {} carries refusal projections",
                    row.evaluation_id
                )));
            }
        }
        (Some(refusal), Some(stored)) => {
            let reopened = decode_governed_refusal(
                stored,
                &format!("evaluation {} refusal", row.evaluation_id),
            )?;
            let (source_kind, boundary, code) = governed_refusal_projections(&reopened)?;
            let GovernedRefusalOrigin::Profile(profile) = &reopened.origin else {
                return Err(EngineError::Invariant(format!(
                    "evaluation {} refusal is not profile-origin",
                    row.evaluation_id
                )));
            };
            if refusal != &reopened
                || row.refusal_id.as_deref() != Some(reopened.refusal_id.as_str())
                || row.source_kind.as_deref() != Some(source_kind.as_str())
                || row.responsible_instance_id.as_deref()
                    != Some(reopened.responsible_instance_id())
                || row.boundary.as_deref() != Some(boundary.as_str())
                || row.code.as_deref() != Some(code.as_str())
                || row.profile_id.as_deref() != Some(profile.refusal.profile.id.as_str())
                || row.profile_version.as_deref()
                    != Some(profile.refusal.profile.version.to_string().as_str())
                || row.profile_digest.as_deref() != Some(result.profile.profile_digest.as_str())
                || row.profile_semantic_id.as_deref() != Some(profile.profile_semantic_id.as_str())
                || profile.refusal.profile != result.profile.profile
                || profile.profile_semantic_id != result.profile.profile_semantic_id
            {
                return Err(EngineError::Invariant(format!(
                    "evaluation {} refusal projections or semantic identity were substituted",
                    row.evaluation_id
                )));
            }
            if let Some(finding_refusal) = &row.finding_refusal_json
                && finding_refusal != stored
            {
                return Err(EngineError::Invariant(format!(
                    "evaluation {} finding refusal differs from its refusal row",
                    row.evaluation_id
                )));
            }
        }
        _ => {
            return Err(EngineError::Invariant(format!(
                "evaluation {} result and refusal row disagree",
                row.evaluation_id
            )));
        }
    }
    Ok(envelope)
}

#[allow(clippy::too_many_lines)]
fn validate_evaluation_finding_projection(
    row: &nq_store::EvaluationRefusalHistoryRow,
    envelope: &EvaluationEnvelopeV2,
) -> Result<(), EngineError> {
    let result = &envelope.result;
    let Some(event_id) = row.finding_event_id.as_deref() else {
        if result.state == DetectorState::Present {
            return Err(EngineError::Invariant(format!(
                "present evaluation {} has no durable finding event",
                row.evaluation_id
            )));
        }
        if row.finding_id.is_some()
            || row.finding_event_revision.is_some()
            || row.finding_instance_id.is_some()
            || !row.finding_evidence.is_empty()
        {
            return Err(EngineError::Invariant(format!(
                "evaluation {} has finding testimony without a finding event",
                row.evaluation_id
            )));
        }
        return Ok(());
    };
    let exact_time = row
        .finding_evaluated_at
        .as_deref()
        .and_then(|value| parse_timestamp(value).ok())
        == parse_timestamp(&row.evaluated_at).ok();
    if row
        .finding_event_revision
        .is_none_or(|revision| revision <= 0)
        || row.finding_detector_id.as_deref() != Some(row.detector_id.as_str())
        || row.finding_detector_version.as_deref() != Some(row.detector_version.as_str())
        || row.finding_detector_digest.as_deref() != Some(row.detector_digest.as_str())
        || row.finding_evaluator_artifact_digest.as_deref()
            != Some(row.evaluator_artifact_digest.as_str())
        || row.finding_evaluation_revision != Some(row.evaluation_revision)
        || row.finding_instance_id.as_deref() != Some(envelope.context.instance_id.as_str())
        || row.finding_profile_id.as_deref() != Some(row.evaluation_profile_id.as_str())
        || row.finding_profile_version.as_deref() != Some(row.evaluation_profile_version.as_str())
        || row.finding_profile_digest.as_deref() != Some(row.evaluation_profile_digest.as_str())
        || row.finding_condition_name.as_deref() != Some(result.condition.as_str())
        || !exact_time
    {
        return Err(EngineError::Invariant(format!(
            "finding event {event_id} substitutes its linked evaluation identity"
        )));
    }
    let expected_limitations = canonical(&result.limitations)?;
    let expected_safe_next_checks = canonical(&vec![
        "Inspect the cited admitted evidence".to_owned(),
        "Run `nq watcher test` if collection remains unavailable".to_owned(),
    ])?;
    let expected_historical_refs = canonical(&Vec::<String>::new())?;
    let expected_subject = canonical(&envelope.context.subject)?;
    let expected_basis = canonical(&json!({
        "profile_digest": result.profile.profile_digest.as_str(),
        "vantage": envelope.context.vantage,
        "scope": envelope.context.scope,
    }))?;
    let canonical_field = |name: &str, value: &Option<Vec<u8>>| {
        value
            .as_ref()
            .ok_or_else(|| EngineError::Invariant(format!("finding event {event_id} lacks {name}")))
            .and_then(|bytes| {
                CanonicalDocument::from_canonical_bytes(bytes.clone()).map_err(EngineError::from)
            })
    };
    let limitations = canonical_field("limitations", &row.finding_limitations_json)?;
    let safe_next_checks = canonical_field("safe next checks", &row.finding_safe_next_checks_json)?;
    let freshness = canonical_field("freshness", &row.finding_freshness_json)?;
    let basis = canonical_field("basis", &row.finding_basis_json)?;
    let historical_refs =
        canonical_field("historical references", &row.finding_historical_refs_json)?;
    if limitations != expected_limitations
        || safe_next_checks != expected_safe_next_checks
        || historical_refs != expected_historical_refs
        || basis != expected_basis
        || row.finding_subject_json.as_deref() != Some(expected_subject.as_bytes())
        || row.finding_origin_mode.as_deref() != Some("native")
    {
        return Err(EngineError::Invariant(format!(
            "finding event {event_id} substitutes deterministic outward fields"
        )));
    }
    let (expected_visibility, expected_freshness) = if result.state == DetectorState::CannotEvaluate
    {
        let watermark = row.watermarks.first();
        match watermark {
            None
            | Some(nq_store::EvaluationWatermarkHistoryRow {
                max_report_sequence: 0,
                ..
            }) => ("missing", json!({"state": "missing"})),
            Some(watermark)
                if matches!(
                    watermark.report_status.as_deref(),
                    Some("partial" | "failed")
                ) =>
            {
                (
                    "partial",
                    json!({
                        "state": watermark.report_status,
                        "observed_at": watermark.report_observed_at,
                    }),
                )
            }
            Some(watermark) => {
                let compiled = nq_profiles::resolve_profile_key(&result.profile.profile)
                    .ok_or_else(|| {
                        EngineError::Invariant("evaluation profile disappeared".into())
                    })?;
                let evaluated_at = parse_timestamp(&row.evaluated_at).ok();
                let observed_at = watermark
                    .report_observed_at
                    .as_deref()
                    .and_then(|value| parse_timestamp(value).ok());
                let stale = evaluated_at
                    .zip(observed_at)
                    .is_none_or(|(evaluated, observed)| {
                        evaluated.signed_duration_since(observed)
                            > Duration::seconds(
                                i64::try_from(compiled.descriptor().freshness.reliance_seconds)
                                    .unwrap_or(i64::MAX),
                            )
                    });
                if stale {
                    (
                        "stale",
                        json!({
                            "state": "stale",
                            "observed_at": watermark.report_observed_at,
                            "reliance_seconds": compiled.descriptor().freshness.reliance_seconds,
                        }),
                    )
                } else {
                    ("refused", json!({"state": "cannot_evaluate"}))
                }
            }
        }
    } else {
        ("sufficient", json!({"state": "current"}))
    };
    if row.finding_visibility_state.as_deref() != Some(expected_visibility)
        || freshness != canonical(&expected_freshness)?
    {
        return Err(EngineError::Invariant(format!(
            "finding event {event_id} substitutes visibility or freshness"
        )));
    }
    let expected_severity = match result.state {
        DetectorState::Present => Some("warning"),
        DetectorState::ExplicitlyAbsent => Some("info"),
        DetectorState::CannotEvaluate => row.prior_finding_severity.as_deref(),
    };
    let expected_summary = if result.state == DetectorState::CannotEvaluate {
        row.prior_finding_summary.as_deref()
    } else {
        Some(result.summary.as_str())
    };
    let expected_operator_state = row
        .prior_finding_operator_work_state
        .as_deref()
        .or(Some("unreviewed"));
    if row.finding_severity.as_deref() != expected_severity
        || row.finding_summary.as_deref() != expected_summary
        || row.finding_operator_work_state.as_deref() != expected_operator_state
        || (row.prior_finding_event_id.is_some()
            && row.finding_subject_json != row.prior_finding_subject_json)
    {
        return Err(EngineError::Invariant(format!(
            "finding event {event_id} substitutes retained summary, severity, subject, or operator state"
        )));
    }
    let newest_evidence = row
        .finding_evidence
        .iter()
        .max_by_key(|evidence| evidence.report_sequence);
    let expected_observed_at = newest_evidence.map(|evidence| evidence.report_observed_at.as_str());
    let expected_received_at = newest_evidence.map(|evidence| evidence.report_received_at.as_str());
    let same_optional_time = |stored: Option<&str>, expected: Option<&str>| match (stored, expected)
    {
        (None, None) => true,
        (Some(stored), Some(expected)) => {
            parse_timestamp(stored).ok() == parse_timestamp(expected).ok()
        }
        _ => false,
    };
    if !same_optional_time(row.finding_observed_at.as_deref(), expected_observed_at)
        || !same_optional_time(row.finding_received_at.as_deref(), expected_received_at)
        || !same_optional_time(
            row.finding_created_at.as_deref(),
            Some(row.evaluated_at.as_str()),
        )
    {
        return Err(EngineError::Invariant(format!(
            "finding event {event_id} substitutes evidence or creation time projections"
        )));
    }
    let condition_matches = match result.state {
        DetectorState::Present => row.finding_condition_state.as_deref() == Some("present"),
        DetectorState::ExplicitlyAbsent => {
            row.finding_condition_state.as_deref() == Some("explicitly_absent")
        }
        DetectorState::CannotEvaluate => {
            !matches!(
                row.finding_event_kind.as_deref(),
                Some("opened" | "resolved")
            ) && row.finding_visibility_state.as_deref() != Some("sufficient")
        }
    };
    if !condition_matches {
        return Err(EngineError::Invariant(format!(
            "finding event {event_id} condition disagrees with evaluation {} outcome",
            row.evaluation_id
        )));
    }
    let expected_event_kind = match result.state {
        DetectorState::Present if row.prior_finding_event_id.is_none() => "opened",
        DetectorState::Present
            if row.prior_finding_condition_state.as_deref() == Some("explicitly_absent") =>
        {
            "reopened"
        }
        DetectorState::Present | DetectorState::CannotEvaluate => "updated",
        DetectorState::ExplicitlyAbsent => "resolved",
    };
    if row.finding_event_kind.as_deref() != Some(expected_event_kind)
        || (expected_event_kind != "opened" && row.prior_finding_event_id.is_none())
    {
        return Err(EngineError::Invariant(format!(
            "finding event {event_id} substitutes transition {}; expected {expected_event_kind}",
            row.finding_event_kind.as_deref().unwrap_or("missing")
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_evaluation_watermarks_and_evidence(
    store: &Store,
    row: &nq_store::EvaluationRefusalHistoryRow,
    envelope: &EvaluationEnvelopeV2,
) -> Result<(), EngineError> {
    let result = &envelope.result;
    for watermark in &row.watermarks {
        let exact = if watermark.max_report_sequence == 0 {
            watermark.watermark_received_at.is_none() && watermark.report_received_at.is_none()
        } else {
            watermark.max_report_sequence > 0
                && watermark.watermark_received_at.is_some()
                && watermark.watermark_received_at == watermark.report_received_at
        };
        if !exact {
            return Err(EngineError::Invariant(format!(
                "evaluation {} watermark {}:{} does not reopen to its exact report receipt",
                row.evaluation_id, watermark.instance_id, watermark.max_report_sequence
            )));
        }
        if watermark.max_report_sequence > 0 {
            let canonical = watermark.report_canonical_json.as_deref().ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} nonempty watermark lacks canonical report",
                    row.evaluation_id
                ))
            })?;
            let digest = watermark.report_semantic_digest.as_deref().ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} nonempty watermark lacks report digest",
                    row.evaluation_id
                ))
            })?;
            validate_report_evaluation_context(canonical, digest, envelope, &row.evaluation_id)?;
        } else if watermark.report_canonical_json.is_some()
            || watermark.report_semantic_digest.is_some()
        {
            return Err(EngineError::Invariant(format!(
                "evaluation {} empty watermark invents a canonical report",
                row.evaluation_id
            )));
        }
    }
    if row.watermarks.len() != 1 {
        return Err(EngineError::Invariant(format!(
            "evaluation {} must carry exactly one instance watermark; found {}",
            row.evaluation_id,
            row.watermarks.len()
        )));
    }
    let persisted_watermark = &row.watermarks[0];
    let envelope_receipt = envelope.watermark.watermark_received_at.map(timestamp);
    if persisted_watermark.instance_id != envelope.watermark.instance_id
        || persisted_watermark.instance_id != envelope.context.instance_id
        || u64::try_from(persisted_watermark.max_report_sequence).ok()
            != Some(envelope.watermark.max_report_sequence)
        || persisted_watermark.watermark_received_at != envelope_receipt
        || result.watermark.0 != envelope.watermark.max_report_sequence
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} envelope watermark differs from its sole persisted instance watermark",
            row.evaluation_id
        )));
    }

    let trigger = if let Some(run_id) = row.trigger_run_id.as_deref() {
        let run = store.watcher_run_outcome(run_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "evaluation {} trigger run {run_id} is missing",
                row.evaluation_id
            ))
        })?;
        validate_run_profile_identity(&run)?;
        let admission_evaluator_artifact = run
            .admission_evaluator_artifact_digest
            .as_deref()
            .ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} trigger run {run_id} has no admission evaluator artifact identity",
                    row.evaluation_id
                ))
            })?;
        if row.evaluator_artifact_digest != admission_evaluator_artifact {
            return Err(EngineError::Invariant(format!(
                "evaluation {} trigger run {run_id} substitutes evaluator artifact {} for admission artifact {admission_evaluator_artifact}",
                row.evaluation_id, row.evaluator_artifact_digest
            )));
        }
        let admitted = store.admitted_collection_for_run(run_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "evaluation {} trigger run {run_id} is not admitted",
                row.evaluation_id
            ))
        })?;
        if run.profile_id != row.evaluation_profile_id
            || run.profile_version != row.evaluation_profile_version
            || run.profile_digest != row.evaluation_profile_digest
        {
            return Err(EngineError::Invariant(format!(
                "evaluation {} trigger run {run_id} substitutes its profile binding",
                row.evaluation_id
            )));
        }
        Some((admitted.instance_id, admitted.report_sequence))
    } else {
        None
    };

    let refusal_instance = result
        .refusal
        .as_ref()
        .map(|refusal| refusal.responsible_instance_id().to_owned());
    let mut relevant_instances = [
        Some(envelope.context.instance_id.clone()),
        row.finding_instance_id.clone(),
        refusal_instance,
        trigger.as_ref().map(|(instance, _)| instance.clone()),
    ]
    .into_iter()
    .flatten();
    let relevant_instance = relevant_instances.next();
    if relevant_instances.any(|candidate| Some(candidate.as_str()) != relevant_instance.as_deref())
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} finding, refusal, and trigger identify different instances",
            row.evaluation_id
        )));
    }
    let relevant_watermark = if let Some(instance_id) = relevant_instance.as_deref() {
        row.watermarks
            .iter()
            .find(|watermark| watermark.instance_id == instance_id)
            .ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} has no watermark for responsible instance {instance_id}",
                    row.evaluation_id
                ))
            })?
    } else if let [watermark] = row.watermarks.as_slice() {
        watermark
    } else {
        return Err(EngineError::Invariant(format!(
            "evaluation {} cannot bind its canonical watermark to one persisted instance",
            row.evaluation_id
        )));
    };
    if u64::try_from(relevant_watermark.max_report_sequence).ok() != Some(result.watermark.0) {
        return Err(EngineError::Invariant(format!(
            "evaluation {} canonical watermark differs from persisted watermark for {}",
            row.evaluation_id, relevant_watermark.instance_id
        )));
    }
    if let Some((_, trigger_report_sequence)) = trigger
        && trigger_report_sequence != relevant_watermark.max_report_sequence
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} trigger report is not its exact persisted watermark",
            row.evaluation_id
        )));
    }

    for evidence in &result.evidence {
        let stored = store
            .admitted_evidence_reference(
                &evidence.report_id,
                &evidence.report_digest,
                evidence.observation_ordinal,
            )?
            .ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} evidence {} does not identify an admitted report occurrence",
                    row.evaluation_id, evidence.report_id
                ))
            })?;
        let watermark = row
            .watermarks
            .iter()
            .find(|watermark| watermark.instance_id == stored.instance_id)
            .ok_or_else(|| {
                EngineError::Invariant(format!(
                    "evaluation {} evidence {} is outside every persisted instance watermark",
                    row.evaluation_id, evidence.report_id
                ))
            })?;
        let exact_observed_at = stored
            .observation_observed_at
            .as_deref()
            .unwrap_or(stored.observed_at.as_str());
        validate_report_evaluation_context(
            &stored.canonical_json,
            &evidence.report_digest,
            envelope,
            &row.evaluation_id,
        )?;
        if u64::try_from(stored.report_sequence).ok() != Some(evidence.report_sequence)
            || stored.instance_id != relevant_watermark.instance_id
            || stored.report_sequence > watermark.max_report_sequence
            || parse_timestamp(exact_observed_at).ok() != Some(evidence.observed_at)
            || !stored.observation_exists
        {
            return Err(EngineError::Invariant(format!(
                "evaluation {} evidence {} substitutes its admitted occurrence or watermark",
                row.evaluation_id, evidence.report_id
            )));
        }
    }

    if row.finding_event_id.is_none() {
        if !row.finding_evidence.is_empty() {
            return Err(EngineError::Invariant(format!(
                "evaluation {} has unlinked finding evidence",
                row.evaluation_id
            )));
        }
        return Ok(());
    }
    if result.evidence.is_empty() {
        let retained_exactly = if row.prior_finding_event_id.is_some() {
            row.finding_evidence == row.prior_finding_evidence
        } else {
            row.finding_evidence.is_empty()
        };
        if !retained_exactly {
            return Err(EngineError::Invariant(format!(
                "evaluation {} empty result did not retain exact immediate-prior finding evidence",
                row.evaluation_id
            )));
        }
    } else if row.finding_evidence.len() != result.evidence.len() {
        return Err(EngineError::Invariant(format!(
            "evaluation {} finding evidence differs from its canonical result",
            row.evaluation_id
        )));
    }
    for (index, finding) in row.finding_evidence.iter().enumerate() {
        let expected_ordinal = i64::try_from(index).unwrap_or(i64::MAX);
        let watermark = row
            .watermarks
            .iter()
            .find(|watermark| watermark.instance_id == finding.report_instance_id);
        let exact_observed_at = finding
            .observation_observed_at
            .as_deref()
            .unwrap_or(finding.report_observed_at.as_str());
        if finding.ordinal != expected_ordinal
            || parse_timestamp(&finding.observed_at).ok() != parse_timestamp(exact_observed_at).ok()
            || finding.received_at != finding.report_received_at
            || !finding.observation_exists
            || watermark
                .is_none_or(|watermark| finding.report_sequence > watermark.max_report_sequence)
            || finding.report_instance_id != relevant_watermark.instance_id
        {
            return Err(EngineError::Invariant(format!(
                "evaluation {} finding evidence ordinal {expected_ordinal} is not its exact canonical evidence",
                row.evaluation_id
            )));
        }
        if let Some(canonical_evidence) = result.evidence.get(index) {
            let expected_observation = canonical_evidence.observation_ordinal.map(i64::from);
            if finding.report_id != canonical_evidence.report_id
                || finding.report_semantic_digest != canonical_evidence.report_digest
                || finding.observation_ordinal != expected_observation
                || u64::try_from(finding.report_sequence).ok()
                    != Some(canonical_evidence.report_sequence)
                || parse_timestamp(&finding.observed_at).ok()
                    != Some(canonical_evidence.observed_at)
            {
                return Err(EngineError::Invariant(format!(
                    "evaluation {} finding evidence ordinal {expected_ordinal} differs from its canonical result",
                    row.evaluation_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_report_evaluation_context(
    bytes: &[u8],
    expected_digest: &str,
    envelope: &EvaluationEnvelopeV2,
    evaluation_id: &str,
) -> Result<(), EngineError> {
    let document = CanonicalDocument::from_canonical_bytes(bytes.to_vec())?;
    if document.digest() != expected_digest {
        return Err(EngineError::Invariant(format!(
            "evaluation {evaluation_id} admitted report bytes do not match digest {expected_digest}"
        )));
    }
    let report: nq_protocol::EvidenceReport =
        serde_json::from_slice(document.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "evaluation {evaluation_id} admitted report cannot decode: {error}"
            ))
        })?;
    nq_protocol::validate_report(&report).map_err(|error| {
        EngineError::Invariant(format!(
            "evaluation {evaluation_id} admitted report is invalid: {error}"
        ))
    })?;
    if report.profile.id.as_str() != envelope.profile.profile.id
        || report.profile.version.to_string() != envelope.profile.profile.version.to_string()
        || report.profile.digest.as_str() != envelope.profile.profile_digest.as_str()
        || report.binding.subject.as_str() != envelope.context.subject
        || report.binding.scope.kind.as_str() != envelope.context.scope.kind
        || report.binding.scope.value != envelope.context.scope.value
        || report.binding.vantage.kind.as_str() != envelope.context.vantage.kind
        || report.binding.vantage.value != envelope.context.vantage.value
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {evaluation_id} admitted evidence substitutes its canonical subject, scope, vantage, or profile binding"
        )));
    }
    Ok(())
}

/// Reopen bounded rejected custody as exact typed refusal testimony.
///
/// # Errors
///
/// Fails closed when stored canonical bytes are unversioned, fail to decode,
/// or disagree with any stable SQL projection or originating run identity.
pub fn rejected_custody_snapshot(
    store: &Store,
    limit: u32,
) -> Result<RejectedCustodySnapshotV1, EngineError> {
    rejected_custody_snapshot_bounded(store, limit, None)
}

/// Reopen one bounded page of rejected custody after an immutable submission
/// identity, validating every result against its originating run.
///
/// # Errors
///
/// Returns when the cursor/limit is invalid or any row fails canonical refusal,
/// profile-semantic, acquisition, or run linkage validation.
pub fn rejected_custody_snapshot_bounded(
    store: &Store,
    limit: u32,
    after_submission_id: Option<&str>,
) -> Result<RejectedCustodySnapshotV1, EngineError> {
    validate_rejected_custody_history(store)?;
    let records = store
        .rejected_custody_bounded(limit, after_submission_id)?
        .into_iter()
        .map(|row| rejected_custody_from_row(store, row))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RejectedCustodySnapshotV1 {
        schema: REJECTED_CUSTODY_SCHEMA.into(),
        generated_at: Utc::now(),
        records,
    })
}

/// Exhaustively reopen and validate immutable rejected-custody history.
///
/// The bounded public snapshot is intentionally not used as an archive receipt:
/// this validator pages by immutable submission identity until no rows remain.
///
/// # Errors
///
/// Returns when paging fails or any row cannot prove exact canonical refusal,
/// projection, instance, run, or profile association.
pub fn validate_rejected_custody_history(store: &Store) -> Result<usize, EngineError> {
    validate_rejected_custody_history_with_page_size(store, nq_store::MAX_PUBLIC_QUERY_ROWS)
}

fn validate_rejected_custody_history_with_page_size(
    store: &Store,
    page_size: u32,
) -> Result<usize, EngineError> {
    let mut after_submission_id: Option<String> = None;
    let mut validated = 0usize;
    loop {
        let page = store.rejected_custody_bounded(page_size, after_submission_id.as_deref())?;
        if page.is_empty() {
            return Ok(validated);
        }
        let page_len = page.len();
        for row in page {
            after_submission_id = Some(row.submission_id.clone());
            rejected_custody_from_row(store, row)?;
            validated = validated.checked_add(1).ok_or_else(|| {
                EngineError::Invariant("rejected custody count overflowed".into())
            })?;
        }
        if page_len < page_size as usize {
            return Ok(validated);
        }
    }
}

/// Run a bounded read-only public-view query.
///
/// # Errors
///
/// Returns when the query is not one of the documented exact public-view
/// selects, exceeds the bound, or a row violates its DTO contract.
pub fn public_query(store: &Store, sql: &str, limit: u32) -> Result<Vec<Value>, EngineError> {
    let normalized = sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    match normalized.as_str() {
        "select * from public_finding_snapshot_v3" => {
            validate_evaluation_refusal_history(store)?;
            store
                .finding_snapshots_bounded(limit, None)?
                .into_iter()
                .map(finding_from_row)
                .map(|result| {
                    result.and_then(|value| {
                        serde_json::to_value(value)
                            .map_err(|error| EngineError::Canonical(error.to_string()))
                    })
                })
                .collect()
        }
        "select * from public_status_snapshot_v1" => {
            validate_status_history_v2(store)?;
            if !(1..=nq_store::MAX_PUBLIC_QUERY_ROWS).contains(&limit) {
                return Err(EngineError::Invariant(format!(
                    "status query limit must be between 1 and {}",
                    nq_store::MAX_PUBLIC_QUERY_ROWS
                )));
            }
            store
                .current_status_snapshots_bounded(limit, None)?
                .into_iter()
                .map(status_from_row)
                .map(|result| {
                    result.and_then(|value| {
                        serde_json::to_value(value)
                            .map_err(|error| EngineError::Canonical(error.to_string()))
                    })
                })
                .collect()
        }
        _ => Err(EngineError::Invariant(
            "query must be exactly `SELECT * FROM public_finding_snapshot_v3` or `SELECT * FROM public_status_snapshot_v1`"
                .into(),
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn finding_from_row(row: nq_store::FindingSnapshotRow) -> Result<FindingSnapshotV3, EngineError> {
    let evidence: Vec<PublicEvidenceReference> = serde_json::from_str(&row.evidence_json)
        .map_err(|error| EngineError::Invariant(format!("invalid evidence view JSON: {error}")))?;
    let profile_version = row.profile_version.parse().map_err(|error| {
        EngineError::Invariant(format!("finding profile version is invalid: {error}"))
    })?;
    let profile_key = nq_profiles::ProfileKey::new(row.profile_id.clone(), profile_version);
    let compiled = nq_profiles::resolve_profile_key(&profile_key).ok_or_else(|| {
        EngineError::Invariant(format!(
            "finding {} names uncompiled profile {}/{}",
            row.finding_id, row.profile_id, row.profile_version
        ))
    })?;
    let compiled_digest = compiled
        .descriptor()
        .digest()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let compiled_semantic_id = profile_semantic_id(compiled.descriptor())
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    if row.profile_digest != compiled_digest.as_str()
        || row.profile_semantic_id != compiled_semantic_id.as_str()
    {
        return Err(EngineError::Invariant(format!(
            "finding {} profile digest or semantic identity was substituted",
            row.finding_id
        )));
    }
    if row.refusal_json != row.evaluation_refusal_json {
        return Err(EngineError::Invariant(format!(
            "finding {} refusal differs from evaluation {} canonical refusal",
            row.finding_id, row.evaluation_id
        )));
    }
    let refusal = row
        .refusal_json
        .as_deref()
        .map(|value| {
            decode_governed_refusal(
                value.as_bytes(),
                &format!("finding {} refusal", row.finding_id),
            )
        })
        .transpose()?;
    if let Some(GovernedRefusal {
        origin: GovernedRefusalOrigin::Profile(profile),
        ..
    }) = &refusal
        && (profile.refusal.profile != profile_key
            || profile.profile_semantic_id.as_str() != row.profile_semantic_id)
    {
        return Err(EngineError::Invariant(format!(
            "finding {} profile identity disagrees with its governed refusal",
            row.finding_id
        )));
    }
    Ok(FindingSnapshotV3 {
        schema: FINDING_SNAPSHOT_SCHEMA.into(),
        finding_id: row.finding_id,
        instance_id: row.instance_id,
        detector: DetectorIdentity {
            id: row.detector_id,
            version: row
                .detector_version
                .parse()
                .map_err(|error| EngineError::Invariant(format!("detector version: {error}")))?,
            digest: row.detector_digest,
        },
        profile: PublicProfileIdentity {
            id: row.profile_id,
            version: profile_version,
            digest: row.profile_digest,
            semantic_id: row.profile_semantic_id,
        },
        subject: serde_json::from_str(&row.subject_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        evaluation_revision: u64::try_from(row.evaluation_revision)
            .map_err(|_| EngineError::Invariant("negative evaluation revision".into()))?,
        condition: ConditionView {
            name: row.condition_name,
            state: parse_condition(&row.condition_state)?,
        },
        visibility: VisibilityView {
            state: parse_visibility(&row.visibility_state)?,
            freshness: serde_json::from_str(&row.freshness_json)
                .map_err(|error| EngineError::Invariant(error.to_string()))?,
            basis: serde_json::from_str(&row.basis_json)
                .map_err(|error| EngineError::Invariant(error.to_string()))?,
            refusal,
        },
        operator_work_state: row.operator_work_state,
        severity: parse_severity(&row.severity)?,
        summary: row.summary,
        evidence,
        limitations: serde_json::from_str(&row.limitations_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        safe_next_checks: serde_json::from_str(&row.safe_next_checks_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
        observed_at: row
            .observed_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?,
        received_at: row
            .received_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?,
        evaluated_at: parse_timestamp(&row.evaluated_at)?,
        origin_mode: match row.origin_mode.as_str() {
            "native" => OriginMode::Native,
            "native_with_historical_reference" => OriginMode::NativeWithHistoricalReference,
            value => {
                return Err(EngineError::Invariant(format!(
                    "unknown origin mode {value}"
                )));
            }
        },
        historical_references: serde_json::from_str(&row.historical_refs_json)
            .map_err(|error| EngineError::Invariant(error.to_string()))?,
    })
}

fn status_from_row(row: nq_store::StatusSnapshotRow) -> Result<ComponentStatus, EngineError> {
    let details: Value = serde_json::from_str(&row.detail_json)
        .map_err(|error| EngineError::Invariant(error.to_string()))?;
    if matches!(
        row.component_kind.as_str(),
        "instance" | "diagnostic_execution"
    ) {
        return Err(EngineError::Invariant(
            "nq.status_snapshot.v1 cannot emit governed collection results; use v3".into(),
        ));
    }
    Ok(ComponentStatus {
        kind: parse_component_kind(&row.component_kind)?,
        id: row.component_id,
        state: parse_health_state(&row.state)?,
        code: row.code,
        details,
        observed_at: parse_timestamp(&row.observed_at)?,
    })
}

fn status_from_row_v2(
    store: &Store,
    row: nq_store::StatusSnapshotRow,
) -> Result<ComponentStatusV2, EngineError> {
    status_component_v2(
        store,
        &row.component_kind,
        row.component_id,
        &row.state,
        row.code,
        &row.detail_json,
        &row.observed_at,
    )
}

fn status_from_row_v3(
    store: &Store,
    row: nq_store::StatusSnapshotRow,
) -> Result<ComponentStatusV3, EngineError> {
    let component = status_from_row_v2(store, row)?;
    if component.kind == ComponentKind::Evaluation {
        return Err(EngineError::Invariant(
            "evaluation status must be derived from canonical evaluation_runs, not status_events"
                .into(),
        ));
    }
    let detail = match component.detail {
        ComponentStatusDetailV2::Collection { result } => {
            ComponentStatusDetailV3::Collection { result }
        }
        ComponentStatusDetailV2::Diagnostic { value } => {
            ComponentStatusDetailV3::Diagnostic { value }
        }
    };
    Ok(ComponentStatusV3 {
        kind: component.kind,
        id: component.id,
        state: component.state,
        code: component.code,
        detail,
        observed_at: component.observed_at,
    })
}

fn evaluation_lineage_key(envelope: &EvaluationEnvelopeV2) -> Result<Vec<u8>, EngineError> {
    Ok(canonical(&json!({
        "instance_id": &envelope.context.instance_id,
        "detector": &envelope.detector,
        "profile": &envelope.profile,
        "subject": &envelope.context.subject,
        "scope": &envelope.context.scope,
        "vantage": &envelope.context.vantage,
        "condition": &envelope.result.condition,
    }))?
    .as_bytes()
    .to_vec())
}

fn evaluation_finding_lineage(
    envelope: &EvaluationEnvelopeV2,
) -> Result<nq_store::EvaluationFindingLineage, EngineError> {
    let subject_json = canonical(&envelope.context.subject)?.as_bytes().to_vec();
    let basis_json = canonical(&json!({
        "profile_digest": envelope.result.profile.profile_digest.as_str(),
        "vantage": &envelope.context.vantage,
        "scope": &envelope.context.scope,
    }))?
    .as_bytes()
    .to_vec();
    Ok(nq_store::EvaluationFindingLineage {
        instance_id: envelope.context.instance_id.clone(),
        detector_id: envelope.detector.id.clone(),
        detector_version: envelope.detector.version.clone(),
        detector_digest: envelope.detector.digest.clone(),
        profile_id: envelope.profile.profile.id.clone(),
        profile_version: envelope.profile.profile.version.to_string(),
        profile_digest: envelope.profile.profile_digest.as_str().to_owned(),
        profile_semantic_id: envelope.profile.profile_semantic_id.as_str().to_owned(),
        subject_json,
        condition_name: envelope.result.condition.clone(),
        basis_json,
    })
}

/// Compatibility projection for operator status only. `Healthy` deliberately
/// includes both a present condition and an explicitly absent condition; it
/// must never drive provider intake, admission, testimony, or authority. Those
/// decisions consume the complete [`EvaluationEnvelopeV2`].
fn evaluation_status_projection(envelope: &EvaluationEnvelopeV2) -> (HealthState, &'static str) {
    match envelope.result.state {
        DetectorState::Present => (HealthState::Healthy, "condition_present"),
        DetectorState::ExplicitlyAbsent => (HealthState::Healthy, "condition_explicitly_absent"),
        DetectorState::CannotEvaluate => (HealthState::Degraded, "cannot_evaluate"),
    }
}

fn status_component_v2(
    store: &Store,
    component_kind: &str,
    component_id: String,
    state: &str,
    code: String,
    detail_json: &str,
    observed_at: &str,
) -> Result<ComponentStatusV2, EngineError> {
    let kind = parse_component_kind(component_kind)?;
    if kind == ComponentKind::Evaluation {
        return Err(EngineError::Invariant(
            "generic evaluation status is not authoritative; reopen evaluation_runs".into(),
        ));
    }
    let detail = if matches!(
        kind,
        ComponentKind::Instance | ComponentKind::DiagnosticExecution
    ) {
        let result = decode_collection_outcome(detail_json.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "run-bearing status {component_id} is not a valid versioned collection result: {error}"
            ))
        })?;
        let projection = if kind == ComponentKind::Instance {
            if result.instance_id != component_id {
                return Err(EngineError::Invariant(format!(
                    "instance status {} embeds result for {}",
                    component_id, result.instance_id
                )));
            }
            let projection = instance_status_projection(&result)?;
            (projection.state, projection.code)
        } else {
            if result.run_id.as_deref() != Some(component_id.as_str()) {
                return Err(EngineError::Invariant(format!(
                    "diagnostic-execution status {component_id} embeds another run identity",
                )));
            }
            governed_execution_status_projection(&result)?
        };
        if state != projection.0 || code != projection.1 {
            return Err(EngineError::Invariant(format!(
                "run-bearing status {component_id} projects ({state}, {code}) but its typed result requires ({}, {})",
                projection.0, projection.1
            )));
        }
        validate_collection_run(store, &result)?;
        if let CollectionResult::Rejected { refusal } = &result.result {
            let run_id = result.run_id.as_deref().ok_or_else(|| {
                EngineError::Invariant(format!(
                    "rejected run-bearing status {component_id} has no run identity"
                ))
            })?;
            let custody_row = store
                .rejected_custody_by_refusal_id(&refusal.refusal_id)?
                .ok_or_else(|| {
                    EngineError::Invariant(format!(
                        "rejected run-bearing status {} names refusal {} without linked custody",
                        component_id, refusal.refusal_id
                    ))
                })?;
            let custody = rejected_custody_from_row(store, custody_row)?;
            if custody.run_id != run_id
                || custody.instance_id != result.instance_id
                || custody.refusal != *refusal
            {
                return Err(EngineError::Invariant(format!(
                    "rejected run-bearing status {} disagrees with linked refusal {} or run {}",
                    component_id, refusal.refusal_id, run_id
                )));
            }
        }
        ComponentStatusDetailV2::Collection { result }
    } else {
        ComponentStatusDetailV2::Diagnostic {
            value: serde_json::from_str(detail_json)
                .map_err(|error| EngineError::Invariant(error.to_string()))?,
        }
    };
    Ok(ComponentStatusV2 {
        kind,
        id: component_id,
        state: parse_health_state(state)?,
        code,
        detail,
        observed_at: parse_timestamp(observed_at)?,
    })
}

#[allow(clippy::too_many_lines)]
fn validate_collection_run(store: &Store, result: &CollectionOutcome) -> Result<(), EngineError> {
    let Some(run_id) = result.run_id.as_deref() else {
        return Ok(());
    };
    let run = store.watcher_run_outcome(run_id)?.ok_or_else(|| {
        EngineError::Invariant(format!(
            "collection result names watcher run {run_id} that is not persisted"
        ))
    })?;
    if run.run_id != run_id || run.instance_id != result.instance_id {
        return Err(EngineError::Invariant(format!(
            "collection result run {run_id} disagrees with persisted run instance {}",
            run.instance_id
        )));
    }
    validate_run_profile_identity(&run)?;

    let resource = reopen_run_resource_outcome(&run)?;

    if let CollectionResult::Admitted {
        report_id,
        report_status,
        semantic_digest,
        evaluations,
    } = &result.result
    {
        let admitted = store.admitted_collection_for_run(run_id)?.ok_or_else(|| {
            EngineError::Invariant(format!(
                "admitted collection result for run {run_id} has no exact admitted report"
            ))
        })?;
        let stored_evaluations = usize::try_from(admitted.evaluations).map_err(|_| {
            EngineError::Invariant(format!(
                "admitted collection run {run_id} has an invalid evaluation count"
            ))
        })?;
        if admitted.run_id != run_id
            || admitted.instance_id != result.instance_id
            || admitted.report_id != *report_id
            || admitted.report_status != *report_status
            || admitted.semantic_digest != *semantic_digest
            || stored_evaluations != evaluations.len()
        {
            return Err(EngineError::Invariant(format!(
                "admitted collection result for run {run_id} substitutes its report or evaluation projections"
            )));
        }
        validate_evaluation_refusal_history(store)?;
        let mut persisted = Vec::new();
        let through = store.latest_evaluation_sequence()?;
        let mut after = None;
        loop {
            let page = store.evaluation_refusal_history_bounded(
                nq_store::MAX_PUBLIC_QUERY_ROWS,
                after,
                through,
            )?;
            if page.is_empty() {
                break;
            }
            let page_len = page.len();
            for row in page {
                after = Some(row.evaluation_sequence);
                if row.trigger_run_id.as_deref() == Some(run_id) {
                    let document = CanonicalDocument::from_canonical_bytes(row.detail_json)?;
                    let envelope: EvaluationEnvelopeV2 =
                        serde_json::from_slice(document.as_bytes())
                            .map_err(|error| EngineError::Invariant(error.to_string()))?;
                    persisted.push(envelope);
                }
            }
            if page_len < nq_store::MAX_PUBLIC_QUERY_ROWS as usize {
                break;
            }
        }
        if evaluations.as_slice() != persisted.as_slice() {
            return Err(EngineError::Invariant(format!(
                "admitted collection run {run_id} embeds evaluations different from its exact persisted trigger sequence"
            )));
        }
        store.verify_admitted_snapshot(report_id).map_err(|error| {
            EngineError::Invariant(format!(
                "admitted collection report {report_id} cannot be historically reopened: {error}"
            ))
        })?;
    }

    let expected = match &result.result {
        CollectionResult::Admitted { .. } => &AcquisitionOutcome::Response,
        CollectionResult::AdmissionRefused { .. } => {
            return Err(EngineError::Invariant(
                "admission-refused result cannot name a watcher run".into(),
            ));
        }
        CollectionResult::AcquisitionFailed { failure } => &failure.outcome,
        CollectionResult::Rejected { refusal } => match &refusal.origin {
            GovernedRefusalOrigin::Acquisition(acquisition) => &acquisition.failure.outcome,
            GovernedRefusalOrigin::Protocol(_)
            | GovernedRefusalOrigin::Helper(_)
            | GovernedRefusalOrigin::Profile(_) => &AcquisitionOutcome::Response,
        },
    };
    if resource.outcome != *expected {
        return Err(EngineError::Invariant(format!(
            "collection result for run {run_id} substitutes acquisition testimony from persisted resource outcome"
        )));
    }

    if let CollectionResult::Rejected {
        refusal:
            GovernedRefusal {
                origin: GovernedRefusalOrigin::Profile(profile),
                ..
            },
    } = &result.result
    {
        let compiled =
            nq_profiles::resolve_profile_key(&profile.refusal.profile).ok_or_else(|| {
                EngineError::Invariant(format!(
                    "profile refusal for run {run_id} names uncompiled profile {}/{}",
                    profile.refusal.profile.id, profile.refusal.profile.version
                ))
            })?;
        let compiled_digest = compiled
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
        let stored_semantic_id = run.profile_semantic_id.as_deref().ok_or_else(|| {
            EngineError::Invariant(format!(
                "profile refusal for run {run_id} has no persisted admission semantic identity"
            ))
        })?;
        if run.admission_id.is_none()
            || stored_semantic_id != profile.profile_semantic_id.as_str()
            || run.profile_id != profile.refusal.profile.id
            || run.profile_version != profile.refusal.profile.version.to_string()
            || run.profile_digest != compiled_digest.as_str()
        {
            return Err(EngineError::Invariant(format!(
                "profile refusal for run {run_id} disagrees with its persisted profile semantic identity"
            )));
        }
    }
    Ok(())
}

fn validate_run_profile_identity(
    run: &nq_store::WatcherRunOutcomeRow,
) -> Result<ProfileSemanticId, EngineError> {
    let Some(admission_id) = run.admission_id.as_deref() else {
        return Err(EngineError::Invariant(format!(
            "watcher run {} has no admission proving its profile semantics",
            run.run_id
        )));
    };
    if run.admission_instance_id.as_deref() != Some(run.instance_id.as_str())
        || run.admission_profile_id.as_deref() != Some(run.profile_id.as_str())
        || run.admission_profile_version.as_deref() != Some(run.profile_version.as_str())
        || run.admission_profile_digest.as_deref() != Some(run.profile_digest.as_str())
    {
        return Err(EngineError::Invariant(format!(
            "watcher run {} borrowed admission {admission_id} from another instance or profile binding",
            run.run_id
        )));
    }
    let version = run.profile_version.parse().map_err(|error| {
        EngineError::Invariant(format!(
            "watcher run {} profile version is invalid: {error}",
            run.run_id
        ))
    })?;
    let key = nq_profiles::ProfileKey::new(run.profile_id.clone(), version);
    let compiled = nq_profiles::resolve_profile_key(&key).ok_or_else(|| {
        EngineError::Invariant(format!(
            "watcher run {} names uncompiled profile {}/{}",
            run.run_id, run.profile_id, run.profile_version
        ))
    })?;
    let digest = compiled
        .descriptor()
        .digest()
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let semantic_id = profile_semantic_id(compiled.descriptor())
        .map_err(|error| EngineError::Canonical(error.to_string()))?;
    let detector_identity = detector_identity_digest(compiled)?;
    if run.profile_digest != digest.as_str()
        || run.profile_semantic_id.as_deref() != Some(semantic_id.as_str())
        || run.admission_detector_identity_digest.as_deref() != Some(detector_identity.as_str())
    {
        return Err(EngineError::Invariant(format!(
            "watcher run {} profile digest, semantic identity, or detector suite was substituted",
            run.run_id
        )));
    }
    Ok(semantic_id)
}

fn reopen_run_resource_outcome(
    run: &nq_store::WatcherRunOutcomeRow,
) -> Result<RunResourceOutcomeV1, EngineError> {
    let document = CanonicalDocument::from_canonical_bytes(run.resource_outcome_json.clone())?;
    let resource: RunResourceOutcomeV1 = serde_json::from_slice(document.as_bytes()).map_err(
        |error| {
            EngineError::Invariant(format!(
                "watcher run {} resource outcome cannot decode as {RUN_RESOURCE_OUTCOME_SCHEMA}: {error}",
                run.run_id
            ))
        },
    )?;
    if canonical(&resource)?.as_bytes() != document.as_bytes() {
        return Err(EngineError::Invariant(format!(
            "watcher run {} resource outcome does not round-trip canonically",
            run.run_id
        )));
    }
    let stderr = hex::decode(&resource.stderr_hex).map_err(|error| {
        EngineError::Invariant(format!(
            "watcher run {} stderr testimony is not exact hexadecimal bytes: {error}",
            run.run_id
        ))
    })?;
    if stderr.len() != resource.stderr_bytes_retained {
        return Err(EngineError::Invariant(format!(
            "watcher run {} stderr length disagrees with its retained bytes",
            run.run_id
        )));
    }
    if run.acquisition_outcome != acquisition_code(&resource.outcome) {
        return Err(EngineError::Invariant(format!(
            "watcher run {} acquisition projection {} disagrees with its exact resource outcome",
            run.run_id, run.acquisition_outcome
        )));
    }
    Ok(resource)
}

fn rejected_custody_from_row(
    store: &Store,
    row: nq_store::RejectedCustodyRow,
) -> Result<RejectedCustodyV1, EngineError> {
    let document = CanonicalDocument::from_canonical_bytes(row.detail_json.clone())?;
    let refusal: GovernedRefusal =
        serde_json::from_slice(document.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "typed refusal {} cannot decode: {error}",
                row.refusal_id
            ))
        })?;
    refusal.validate()?;
    let profile_semantic_id = row.profile_semantic_id.clone().ok_or_else(|| {
        EngineError::Invariant(format!(
            "rejected custody {} has no admission proving its profile semantics",
            row.submission_id
        ))
    })?;
    if row.admission_id.is_none() {
        return Err(EngineError::Invariant(format!(
            "rejected custody {} is not linked to an admission",
            row.submission_id
        )));
    }
    if canonical(&refusal)?.as_bytes() != document.as_bytes() {
        return Err(EngineError::Invariant(format!(
            "typed refusal {} does not round-trip to its exact canonical bytes",
            row.refusal_id
        )));
    }
    let (source_kind, boundary, code) = governed_refusal_projections(&refusal)?;
    let expected_protocol_outcome = match &refusal.origin {
        GovernedRefusalOrigin::Acquisition(_) => "not_validated",
        GovernedRefusalOrigin::Protocol(_) => "rejected",
        GovernedRefusalOrigin::Helper(_) => "valid_refusal",
        GovernedRefusalOrigin::Profile(_) => "valid_report",
    };
    if refusal.refusal_id != row.refusal_id
        || refusal.responsible_instance_id() != row.responsible_instance_id
        || row.responsible_instance_id != row.instance_id
        || source_kind != row.source_kind
        || boundary != row.boundary
        || code != row.code
        || row.protocol_outcome != expected_protocol_outcome
    {
        return Err(EngineError::Invariant(format!(
            "rejected custody {} disagrees with its canonical refusal projections",
            row.submission_id
        )));
    }
    if let GovernedRefusalOrigin::Profile(profile_refusal) = &refusal.origin
        && (profile_refusal.refusal.profile.id != row.profile_id
            || profile_refusal.refusal.profile.version.to_string() != row.profile_version
            || row.admission_id.is_none()
            || row.profile_semantic_id.as_deref()
                != Some(profile_refusal.profile_semantic_id.as_str()))
    {
        return Err(EngineError::Invariant(format!(
            "rejected custody {} profile semantic identity disagrees with its refusal",
            row.submission_id
        )));
    }
    validate_collection_run(
        store,
        &CollectionOutcome::rejected(row.instance_id.clone(), row.run_id.clone(), refusal.clone()),
    )?;
    Ok(RejectedCustodyV1 {
        submission_id: row.submission_id,
        run_id: row.run_id,
        request_id: row.request_id,
        instance_id: row.instance_id,
        profile: PublicProfileIdentity {
            id: row.profile_id,
            version: row.profile_version.parse().map_err(|error| {
                EngineError::Invariant(format!("invalid rejected-custody profile version: {error}"))
            })?,
            digest: row.profile_digest,
            semantic_id: profile_semantic_id,
        },
        raw_sha256: row.raw_sha256,
        received_at: parse_timestamp(&row.received_at)?,
        protocol_outcome: row.protocol_outcome,
        refusal,
        created_at: parse_timestamp(&row.created_at)?,
    })
}

fn parse_component_kind(value: &str) -> Result<ComponentKind, EngineError> {
    match value {
        "daemon" => Ok(ComponentKind::Daemon),
        "database" => Ok(ComponentKind::Database),
        "profile_catalog" => Ok(ComponentKind::ProfileCatalog),
        "admission" => Ok(ComponentKind::Admission),
        "scheduler" => Ok(ComponentKind::Scheduler),
        "instance" => Ok(ComponentKind::Instance),
        "diagnostic_execution" => Ok(ComponentKind::DiagnosticExecution),
        "evaluation" => Ok(ComponentKind::Evaluation),
        "notification" => Ok(ComponentKind::Notification),
        _ => Err(EngineError::Invariant(format!("unknown component {value}"))),
    }
}

fn is_legacy_decode_only_status_kind(value: &str) -> bool {
    matches!(value, "scheduler" | "notification")
}

fn parse_health_state(value: &str) -> Result<HealthState, EngineError> {
    match value {
        "healthy" => Ok(HealthState::Healthy),
        "degraded" => Ok(HealthState::Degraded),
        "failed" => Ok(HealthState::Failed),
        "unknown" => Ok(HealthState::Unknown),
        _ => Err(EngineError::Invariant(format!(
            "unknown health state {value}"
        ))),
    }
}

fn parse_condition(value: &str) -> Result<ConditionState, EngineError> {
    match value {
        "present" => Ok(ConditionState::Present),
        "explicitly_absent" => Ok(ConditionState::ExplicitlyAbsent),
        "cannot_evaluate" => Ok(ConditionState::CannotEvaluate),
        _ => Err(EngineError::Invariant(format!(
            "unknown condition state {value}"
        ))),
    }
}

fn parse_visibility(value: &str) -> Result<VisibilityState, EngineError> {
    match value {
        "sufficient" => Ok(VisibilityState::Sufficient),
        "partial" => Ok(VisibilityState::Partial),
        "stale" => Ok(VisibilityState::Stale),
        "missing" => Ok(VisibilityState::Missing),
        "refused" => Ok(VisibilityState::Refused),
        _ => Err(EngineError::Invariant(format!(
            "unknown visibility state {value}"
        ))),
    }
}

fn parse_severity(value: &str) -> Result<Severity, EngineError> {
    match value {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "error" => Ok(Severity::Error),
        "critical" => Ok(Severity::Critical),
        _ => Err(EngineError::Invariant(format!("unknown severity {value}"))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::PermissionsExt;

    use nq_helper_sandbox::ExecutionAccount;

    use crate::admission::{ADMISSION_SCHEMA, AdmittedProfile, OperatorIdentity};
    use crate::config::{
        CommandConfig, InvocationPolicy, ProfileSelection, ResourceLimits, ScopeConfig,
        VantageConfig,
    };
    use crate::provider_intake::{
        ProviderIdentitySchema, ProviderIdentityV1, ProviderIntakeContextSchema,
        ProviderIntakeContextV1, ProviderIntakeSchema, ProviderKind,
    };

    use super::*;

    fn test_runtime_dependency(label: &str) -> nq_store::RuntimeCheckpointDependencyInput {
        let anchor = CanonicalDocument::from_serializable(&json!({
            "schema": "nq.test_dependency_anchor.v1",
            "label": label,
        }))
        .expect("test dependency anchor");
        let trust_anchor_id =
            Sha256Digest::parse(anchor.digest().to_owned()).expect("test anchor digest");
        let generation = CanonicalDocument::from_serializable(&json!({
            "schema": "nq.test_runtime_dependency_generation.v1",
            "label": label,
            "trust_anchor_id": trust_anchor_id,
        }))
        .expect("test dependency generation");
        let dependency_generation_id =
            Sha256Digest::parse(generation.digest().to_owned()).expect("test generation digest");
        let canonical_custody = CanonicalDocument::from_serializable(&json!({
            "schema": "nq.host_role_runtime_dependency_generation_custody.v1",
            "generation_id": dependency_generation_id,
            "generation_canonical_bytes": hex::encode(generation.as_bytes()),
            "identity_catalog_canonical_bytes": "",
            "external_dependency_canonical_bytes": "",
            "authority_admission_canonical_bytes": "",
            "trust_anchor_canonical_bytes": hex::encode(anchor.as_bytes()),
            "admission_receipt_set_canonical_bytes": "",
        }))
        .expect("test dependency custody");
        nq_store::RuntimeCheckpointDependencyInput {
            dependency_generation_id,
            trust_anchor_id,
            canonical_custody,
        }
    }

    const SEMANTIC_TRANSPORT_HELPER: &str = r#"import datetime
import json
import os
import pathlib
import sys

request = json.load(sys.stdin)
mode = pathlib.Path(os.environ["NQ_TEST_MODE"]).read_text(encoding="utf-8").strip()
echo = dict(request)
del echo["schema"]

if mode.startswith("helper_"):
    transient = mode == "helper_transient"
    refusal = {
        "responsible_instance_id": request["instance_id"],
        "boundary": "collection",
        "code": "collection_failed",
        "message": "backend collection failed",
        "retriable": transient,
        "details": {
            "errno": "EAGAIN" if transient else "ENODEV",
            "attempt": 1 if transient else 2,
        },
    }
    outcome = {"kind": "refusal", "refusal": refusal}
else:
    observed_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    binding = request["binding"]
    nonce = binding["scope"]["value"]["nonce"]
    report = {
        "schema": "nq.evidence_report.v1",
        "profile": request["profile"],
        "binding": binding,
        "observed_at": observed_at,
        "status": "complete",
        "coverage": [{"kind": "echo", "state": "complete"}],
        "observations": [{
            "ordinal": 0,
            "kind": "echo",
            "subject": binding["subject"],
            "observed_at": observed_at,
            "payload": {
                "evidence_basis": {
                    "scope": binding["scope"],
                    "vantage": binding["vantage"],
                    "access_path": "process",
                    "basis": "request_echo",
                    "regime": "conformance",
                    "capabilities_used": [],
                },
                "nonce": nonce,
            },
        }],
        "errors": [],
        "used_capabilities": [],
        "backend": {
            "implementation": {"name": "semantic-transport-fixture", "version": "1"},
            "tools": [],
        },
    }
    if mode == "profile_reject":
        del report["observations"][0]["payload"]["nonce"]
    outcome = {"kind": "report", "report": report}

response = {"schema": "nq.helper.response.v1", "echo": echo, "outcome": outcome}
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
"#;

    const HOST_DIAGNOSTIC_HELPER: &str = r#"import datetime
import json
import os
import sys

request = json.load(sys.stdin)
echo = dict(request)
del echo["schema"]
observed_at = (
    datetime.datetime.now(datetime.timezone.utc)
    .isoformat(timespec="microseconds")
    .replace("+00:00", "Z")
)
binding = request["binding"]
capabilities = request["granted_capabilities"]
report = {
    "schema": "nq.evidence_report.v1",
    "profile": request["profile"],
    "binding": binding,
    "observed_at": observed_at,
    "status": "complete",
    "coverage": [
        {"kind": "host_identity", "state": "complete"},
        {"kind": "uptime", "state": "complete"},
        {"kind": "load", "state": "complete"},
    ],
    "observations": [{
        "ordinal": 0,
        "kind": "host_snapshot",
        "subject": binding["subject"],
        "observed_at": observed_at,
        "payload": {
            "evidence_basis": {
                "scope": binding["scope"],
                "vantage": binding["vantage"],
                "access_path": "procfs_sysinfo",
                "basis": "kernel_snapshot",
                "regime": "normal",
                "capabilities_used": capabilities,
            },
            "hostname": "diagnostic-fixture",
            "uptime_seconds": 3600,
            "cpu_count": 4,
            "load_1m": 1.0,
        },
    }],
    "errors": [],
    "used_capabilities": capabilities,
    "backend": {
        "implementation": {"name": "host-diagnostic-fixture", "version": "1"},
        "tools": [],
    },
}
mode_path = os.environ.get("NQ_DIAGNOSTIC_TEST_MODE")
mode = "complete"
if mode_path:
    with open(mode_path, "r", encoding="utf-8") as source:
        mode = source.read().strip()
if mode == "no_response":
    sys.exit(0)
if mode == "partial_bytes_failure":
    sys.stdout.write('{"schema":"nq.helper.response.v1","partial":')
    sys.stdout.flush()
    sys.exit(17)
if mode == "helper_refusal":
    refusal = {
        "responsible_instance_id": request["instance_id"],
        "boundary": "collection",
        "code": "collection_failed",
        "message": "bounded host collection refused",
        "retriable": True,
        "details": {"errno": "EAGAIN"},
    }
    response = {
        "schema": "nq.helper.response.v1",
        "echo": echo,
        "outcome": {"kind": "refusal", "refusal": refusal},
    }
elif mode == "partial":
    report["status"] = "partial"
    report["coverage"][2]["state"] = "partial"
    del report["observations"][0]["payload"]["load_1m"]
    report["errors"] = [{
        "code": "load_partial",
        "severity": "error",
        "message": "one-minute load was unavailable",
        "retriable": True,
    }]
    response = {"schema": "nq.helper.response.v1", "echo": echo, "outcome": {"kind": "report", "report": report}}
else:
    response = {"schema": "nq.helper.response.v1", "echo": echo, "outcome": {"kind": "report", "report": report}}
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
"#;

    fn test_run_resource(outcome: AcquisitionOutcome) -> CanonicalDocument {
        canonical(&RunResourceOutcomeV1 {
            schema: RunResourceOutcomeSchema::V1,
            duration_ms: 1,
            exit_code: (outcome == AcquisitionOutcome::Response).then_some(0),
            hard_limits: RunHardLimits {
                address_space_bytes_per_process: 1,
                cpu_seconds_per_process: 1,
                processes_per_execution_uid: 1,
                open_files_per_process: 1,
                file_bytes_per_regular_file: 1,
                core_bytes: 0,
            },
            stdout_bytes_retained: 0,
            stderr_bytes_retained: 0,
            stderr_hex: String::new(),
            outcome,
        })
        .expect("canonical run resource")
    }

    fn fixture_conformance() -> ConformanceReceipt {
        ConformanceReceipt {
            tool_version: "nq-core-provider-fixture-v1".to_owned(),
            protocol_passed: true,
            protocol_corpus_digest: nq_protocol::sha256_bytes(b"nq-core provider fixture corpus")
                .into_string(),
            protocol_fixtures_checked: 1,
            dry_collection_passed: true,
            dry_report_digest: Some(
                nq_protocol::sha256_bytes(b"nq-core provider fixture dry report").into_string(),
            ),
        }
    }

    fn fixture_capability_grant(profile_id: &str) -> BTreeSet<String> {
        if profile_id == nq_profiles::host::PROFILE_ID {
            BTreeSet::from(["read_procfs".to_owned()])
        } else {
            BTreeSet::new()
        }
    }

    fn fixture_execution(suffix: &str) -> ExecutionIdentity {
        ExecutionIdentity {
            execution_account: Some(ExecutionAccount {
                configured: "991".to_owned(),
                name: "nq-core-fixture".to_owned(),
                uid: 991,
                gid: 991,
                debug_same_identity: false,
            }),
            configured_path: std::path::PathBuf::from(format!("/fixture/provider-{suffix}")),
            resolved_path: std::path::PathBuf::from(format!("/fixture/provider-{suffix}")),
            sha256: nq_protocol::sha256_bytes(format!("helper-{suffix}").as_bytes()).into_string(),
            size: 1,
            device: 1,
            inode: 1,
            mode: 0o100_755,
            modified_ns: "0".to_owned(),
            fixed_argv: Vec::new(),
            working_directory: None,
            working_directory_identity: None,
            execution_chain: Vec::new(),
            startup_runtime: None,
        }
    }

    fn fixture_admission_lock(
        profile: &'static dyn ProfileModule,
        instance_id: &str,
        suffix: &str,
        admission_id: &str,
    ) -> AdmissionLock {
        let descriptor = profile.descriptor();
        AdmissionLock {
            schema: ADMISSION_SCHEMA.to_owned(),
            admission_id: admission_id.to_owned(),
            instance_id: instance_id.to_owned(),
            config_digest: nq_protocol::sha256_bytes(format!("config-{suffix}").as_bytes())
                .into_string(),
            execution: fixture_execution(suffix),
            profile: AdmittedProfile {
                id: descriptor.profile.id.clone(),
                version: descriptor.profile.version,
                digest: descriptor
                    .digest()
                    .expect("fixture profile digest")
                    .as_str()
                    .to_owned(),
            },
            protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            granted_capabilities: fixture_capability_grant(&descriptor.profile.id),
            conformance: fixture_conformance(),
            admitted_at: parse_timestamp("2026-07-20T12:00:00.000Z")
                .expect("fixture admission time"),
            operator: OperatorIdentity {
                uid: 991,
                gid: 991,
                login_hint: Some("nq-core-fixture".to_owned()),
            },
        }
    }

    fn seed_compiled_admission(
        store: &mut Store,
        profile: &'static dyn ProfileModule,
        instance_id: &str,
        suffix: &str,
    ) -> String {
        let descriptor = profile.descriptor();
        let profile_digest = descriptor.digest().expect("profile digest");
        if store
            .profile_descriptor(
                &descriptor.profile.id,
                &descriptor.profile.version.to_string(),
                profile_digest.as_str(),
            )
            .expect("profile descriptor lookup")
            .is_none()
        {
            append_profile_descriptor(
                &mut store.begin_writer_session().expect("writer session"),
                profile,
            )
            .expect("append compiled descriptor");
        }
        let admission_id = Uuid::new_v4().to_string();
        let typed = |label: &str| nq_protocol::sha256_bytes(format!("{label}-{suffix}").as_bytes());
        let lock = fixture_admission_lock(profile, instance_id, suffix, &admission_id);
        store
            .begin_writer_session()
            .expect("writer session")
            .append_admission(&AdmissionInput {
                admission_id: admission_id.clone(),
                instance_id: instance_id.to_owned(),
                identity: AdmissionIdentity {
                    profile_semantic_id: parse_identity_digest(
                        "profile_semantic_id",
                        profile_semantic_id(descriptor)
                            .expect("profile semantic identity")
                            .as_str(),
                    )
                    .expect("typed semantic identity"),
                    detector_identity_digest: detector_identity_digest(profile)
                        .expect("compiled detector suite identity"),
                    evaluator_source_digest: typed("source"),
                    evaluator_artifact_digest: typed("evaluator"),
                    helper_artifact_digest: Sha256Digest::parse(lock.execution.sha256.clone())
                        .expect("helper artifact digest"),
                    config_digest: Sha256Digest::parse(lock.config_digest.clone())
                        .expect("configuration digest"),
                    protocol_version: lock.protocol_version.clone(),
                    target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                    artifact_identity_method: "test-fixture".to_owned(),
                    platform_runtime_version: "test".to_owned(),
                },
                execution_chain: canonical(&lock.execution).expect("execution"),
                profile_id: descriptor.profile.id.clone(),
                profile_version: descriptor.profile.version.to_string(),
                profile_digest: profile_digest.as_str().to_owned(),
                capability_grant: canonical(&lock.granted_capabilities).expect("capability grant"),
                conformance: canonical(&lock.conformance).expect("conformance"),
                lock: canonical(&lock).expect("lock"),
                admitted_at: timestamp(lock.admitted_at),
                operator_identity: canonical(&lock.operator).expect("operator"),
            })
            .expect("append compiled admission");
        admission_id
    }

    fn activate_test_admission(
        store: &mut Store,
        instance_id: &str,
        admission_id: &str,
        binding_digest: &str,
    ) {
        let binding_event_id = Uuid::new_v4().to_string();
        let operation_id = Uuid::new_v4().to_string();
        let occurred_at = "2026-07-20T12:00:00.000Z".to_owned();
        let detail =
            canonical(&json!({"fixture": "provider-intake-binding"})).expect("binding detail");
        store
            .begin_writer_session()
            .expect("writer session")
            .begin_binding_transition(
                &BindingEventInput {
                    binding_event_id: binding_event_id.clone(),
                    instance_id: instance_id.to_owned(),
                    event_kind: "activate".to_owned(),
                    admission_id: Some(admission_id.to_owned()),
                    binding_digest: binding_digest.to_owned(),
                    occurred_at: occurred_at.clone(),
                    reason_code: Some("test_fixture".to_owned()),
                    detail: detail.clone(),
                },
                &BindingMaterializationInput {
                    materialization_event_id: Uuid::new_v4().to_string(),
                    operation_id: operation_id.clone(),
                    instance_id: instance_id.to_owned(),
                    binding_event_id: binding_event_id.clone(),
                    phase: "intent".to_owned(),
                    occurred_at: occurred_at.clone(),
                    detail: detail.clone(),
                },
            )
            .expect("begin provider-intake fixture binding");
        store
            .begin_writer_session()
            .expect("writer session")
            .complete_binding_materialization(&BindingMaterializationInput {
                materialization_event_id: Uuid::new_v4().to_string(),
                operation_id,
                instance_id: instance_id.to_owned(),
                binding_event_id,
                phase: "completed".to_owned(),
                occurred_at,
                detail,
            })
            .expect("complete provider-intake fixture binding");
    }

    fn test_run(
        store: &Store,
        profile: &'static dyn ProfileModule,
        instance_id: &str,
        suffix: &str,
        admission_id: String,
        outcome: AcquisitionOutcome,
    ) -> RunInput {
        let descriptor = profile.descriptor();
        let admission = store
            .admission(&admission_id)
            .expect("read fixture admission")
            .expect("fixture admission exists");
        let lock_document = CanonicalDocument::from_canonical_bytes(admission.lock_json)
            .expect("canonical fixture admission lock");
        let lock: AdmissionLock =
            serde_json::from_slice(lock_document.as_bytes()).expect("typed fixture admission lock");
        assert_eq!(lock.admission_id, admission_id);
        assert_eq!(lock.instance_id, instance_id);
        assert_eq!(lock.profile.id, descriptor.profile.id);
        assert_eq!(lock.profile.version, descriptor.profile.version);
        let binding = canonical(&lock).expect("fixture binding");
        RunInput {
            run_id: format!("run-{suffix}"),
            request_id: format!("request-{suffix}"),
            instance_id: instance_id.to_owned(),
            admission_id: Some(admission_id),
            binding_digest: binding.digest().to_owned(),
            checkpoint_contract_digest: nq_protocol::sha256_bytes(
                format!("checkpoint-{suffix}").as_bytes(),
            )
            .into_string(),
            profile_id: descriptor.profile.id.clone(),
            profile_version: descriptor.profile.version.to_string(),
            profile_digest: descriptor
                .digest()
                .expect("profile digest")
                .as_str()
                .to_owned(),
            carrier: "stdio".to_owned(),
            started_at: "2026-07-20T12:00:00.000Z".to_owned(),
            deadline_at: "2026-07-20T12:00:10.000Z".to_owned(),
            finished_at: "2026-07-20T12:00:01.000Z".to_owned(),
            acquisition_outcome: acquisition_code(&outcome).to_owned(),
            execution_identity: canonical(&lock.execution).expect("execution"),
            resource_outcome: test_run_resource(outcome),
        }
    }

    fn test_collection(
        store: &mut Store,
        run: RunInput,
        submission: Option<SubmissionInput>,
        suffix: &str,
    ) -> CollectionInput {
        test_collection_with_conformance(store, run, submission, suffix)
    }

    #[allow(clippy::too_many_lines)]
    fn test_collection_with_conformance(
        store: &mut Store,
        mut run: RunInput,
        mut submission: Option<SubmissionInput>,
        suffix: &str,
    ) -> CollectionInput {
        let admission_id = run
            .admission_id
            .as_deref()
            .expect("provider intake requires an admission");
        let admission = store
            .admission(admission_id)
            .expect("read fixture admission")
            .expect("fixture admission exists");
        let provider_admission = store
            .provider_admission_for_source(admission_id)
            .expect("read fixture provider admission")
            .expect("fixture provider admission exists");
        if admission.instance_id == run.instance_id {
            let exact_binding_is_current = store
                .latest_binding(&run.instance_id)
                .expect("read fixture binding")
                .is_some_and(|binding| {
                    binding.admission_id.as_deref() == Some(admission_id)
                        && binding.binding_digest == run.binding_digest
                        && matches!(binding.event_kind.as_str(), "activate" | "rollback")
                });
            if !exact_binding_is_current {
                activate_test_admission(store, &run.instance_id, admission_id, &run.binding_digest);
            }
        }
        let parse = |name: &str, value: &str| {
            Sha256Digest::parse(value.to_owned())
                .unwrap_or_else(|error| panic!("invalid fixture {name}: {error}"))
        };
        let conformance = fixture_conformance();
        let conformance_document = canonical(&conformance).expect("fixture conformance");
        let provider_semantic_id = nq_store::local_provider_semantic_id(
            &admission.protocol_version,
            &conformance_document,
        )
        .expect("local provider semantic identity");
        assert_eq!(
            provider_admission.provider_semantic_id,
            provider_semantic_id.as_str(),
            "fixture admission and typed provider identity must share one semantic contract"
        );

        let admitted_protocol_report = submission.as_ref().and_then(|submission| {
            let SubmissionDisposition::Admitted(report) = &submission.disposition else {
                return None;
            };
            Some(
                serde_json::from_slice::<nq_protocol::EvidenceReport>(
                    report.canonical_report.as_bytes(),
                )
                .expect("admitted fixture retains a protocol report"),
            )
        });
        let profile = admitted_protocol_report.as_ref().map_or_else(
            || ProfileBinding {
                id: ProfileId::new(run.profile_id.clone()).expect("fixture profile id"),
                version: ProfileVersion::new(run.profile_version.clone())
                    .expect("fixture profile version"),
                digest: parse("profile digest", &run.profile_digest),
            },
            |report| report.profile.clone(),
        );
        let binding = admitted_protocol_report.as_ref().map_or_else(
            || SubjectBinding {
                subject: SubjectId::new(format!("fixture:{}", run.instance_id))
                    .expect("fixture subject"),
                scope: ScopeBinding {
                    kind: ScopeKind::new("fixture").expect("fixture scope"),
                    value: json!({"instance_id": run.instance_id}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").expect("fixture vantage"),
                    value: json!({}),
                },
            },
            |report| report.binding.clone(),
        );
        let granted_capabilities = fixture_capability_grant(&run.profile_id)
            .into_iter()
            .map(|capability| Capability::new(capability).expect("fixture capability"))
            .collect();
        let request = HelperRequest::builder(
            RequestId::new(run.request_id.clone()).expect("fixture request id"),
            InstanceId::new(run.instance_id.clone()).expect("fixture instance id"),
            profile,
            binding,
            MonotonicDeadline {
                clock: nq_protocol::MonotonicClock::LinuxBoottime,
                expires_at_ns: 10_000,
            },
        )
        .capabilities(granted_capabilities)
        .build()
        .expect("typed provider fixture request");

        if let Some(submission) = &mut submission {
            match submission.protocol_outcome.as_str() {
                "valid_report" => {
                    let report = admitted_protocol_report
                        .clone()
                        .expect("valid-report custody has a protocol report");
                    submission.raw_bytes = nq_protocol::encode_ndjson(
                        &nq_protocol::HelperResponse::report(&request, report),
                    )
                    .expect("framed fixture report");
                }
                "valid_refusal" => {
                    let helper_refusal = match &submission.disposition {
                        SubmissionDisposition::Rejected { refusal } => {
                            let governed: GovernedRefusal =
                                serde_json::from_slice(refusal.detail.as_bytes())
                                    .expect("typed fixture refusal");
                            match governed.origin {
                                GovernedRefusalOrigin::Helper(refusal) => refusal,
                                _ => nq_protocol::Refusal {
                                    responsible_instance_id: request.instance_id.clone(),
                                    boundary: nq_protocol::RefusalBoundary::Collection,
                                    code: nq_protocol::RefusalCode::CollectionFailed,
                                    message: "hostile relabel fixture".to_owned(),
                                    retriable: false,
                                    details: json!({"source": "test_fixture"}),
                                },
                            }
                        }
                        SubmissionDisposition::Admitted(_) => {
                            panic!("valid refusal cannot carry an admitted report")
                        }
                    };
                    submission.raw_bytes = nq_protocol::encode_ndjson(
                        &nq_protocol::HelperResponse::refusal(&request, helper_refusal),
                    )
                    .expect("framed fixture refusal");
                }
                _ => {}
            }
        }

        let raw_bytes = submission
            .as_ref()
            .map_or_else(Vec::new, |submission| submission.raw_bytes.clone());
        let received_at = submission.as_ref().map_or_else(
            || run.finished_at.clone(),
            |submission| submission.received_at.clone(),
        );
        let mut native: RunResourceOutcomeV1 =
            serde_json::from_slice(run.resource_outcome.as_bytes()).expect("typed native outcome");
        native.stdout_bytes_retained = raw_bytes.len();
        run.resource_outcome = canonical(&native).expect("exact fixture native outcome");

        let intake_id = format!("intake-{suffix}");
        let attempt_id = format!("attempt-{suffix}");
        let idempotency_key = nq_store::provider_idempotency_key(
            &provider_admission.provider_admission_id,
            &attempt_id,
        )
        .expect("fixture idempotency identity");
        let execution_identity_digest =
            parse("execution identity digest", run.execution_identity.digest());
        let provider = ProviderIdentityV1 {
            schema: ProviderIdentitySchema::V1,
            kind: ProviderKind::LocalHelper,
            provider_semantic_id,
            provider_admission_id: parse(
                "provider admission identity",
                &provider_admission.provider_admission_id,
            ),
            source_admission_id: admission.admission_id.clone(),
            binding_digest: parse("binding digest", &run.binding_digest),
            artifact_digest: parse(
                "provider artifact digest",
                &admission.helper_artifact_digest,
            ),
            execution_identity_digest: execution_identity_digest.clone(),
            configuration_digest: parse("provider configuration digest", &admission.config_digest),
            protocol_identity: admission.protocol_version.clone(),
            conformance_corpus_digest: parse(
                "conformance corpus digest",
                &conformance.protocol_corpus_digest,
            ),
            conformance_tool_version: conformance.tool_version.clone(),
            conformance,
            profile_semantic_id: parse("profile semantic identity", &admission.profile_semantic_id),
            evaluator_artifact_digest: parse(
                "evaluator artifact digest",
                &admission.evaluator_artifact_digest,
            ),
            admission_context_digest: parse(
                "admission context digest",
                &admission.admission_context_digest,
            ),
        };
        provider
            .verify_historical()
            .expect("fixture historical provider identity");
        let started_at = parse_timestamp(&run.started_at).expect("fixture start time");
        let finished_at = parse_timestamp(&run.finished_at).expect("fixture finish time");
        let received_at_typed = parse_timestamp(&received_at).expect("fixture receive time");
        let deadline_at = parse_timestamp(&run.deadline_at).expect("fixture deadline");
        let capture = RunCapture {
            started_at,
            finished_at,
            duration_ms: native.duration_ms,
            exit_code: native.exit_code,
            stdout: raw_bytes.clone(),
            stderr: hex::decode(&native.stderr_hex).expect("fixture stderr hexadecimal"),
            outcome: native.outcome.clone(),
        };
        let interpretation = interpret_response(&request, &capture);
        let context = ProviderIntakeContextV1 {
            schema: ProviderIntakeContextSchema::V1,
            intake_id: intake_id.clone(),
            attempt_id: attempt_id.clone(),
            run_id: run.run_id.clone(),
            request: request.clone(),
            provider: provider.clone(),
            origin_carrier: run.carrier.clone(),
            deadline_at,
            checkpoint_contract_digest: parse(
                "checkpoint contract digest",
                &run.checkpoint_contract_digest,
            ),
        };
        let context_digest =
            nq_protocol::semantic_digest(&context).expect("fixture context digest");
        let record = ProviderIntakeRecordV1 {
            schema: ProviderIntakeSchema::V1,
            intake_id: intake_id.clone(),
            attempt_id: attempt_id.clone(),
            idempotency_key: idempotency_key.clone(),
            run_id: run.run_id.clone(),
            request_id: run.request_id.clone(),
            request,
            provider: provider.clone(),
            origin_carrier: run.carrier.clone(),
            deadline_at,
            request_digest: nq_protocol::semantic_digest(&context.request)
                .expect("fixture request digest"),
            context_digest,
            checkpoint_contract_digest: context.checkpoint_contract_digest.clone(),
            started_at,
            finished_at,
            received_at: received_at_typed,
            native_outcome: native.clone(),
            raw_length: raw_bytes.len(),
            raw_sha256: nq_protocol::sha256_bytes(&raw_bytes),
            provider_sequence: None,
            interpretation: interpretation.clone(),
        };
        record
            .verify_historical_raw(&raw_bytes)
            .expect("fixture intake is independently reopenable");
        let intake = ProviderIntakeInput {
            intake_id: intake_id.clone(),
            attempt_id: attempt_id.clone(),
            idempotency_key,
            request_id: run.request_id.clone(),
            provider_admission_id: provider_admission.provider_admission_id.clone(),
            source_admission_id: admission.admission_id.clone(),
            provider_sequence: None,
            origin_carrier: run.carrier.clone(),
            deadline_at: run.deadline_at.clone(),
            checkpoint_contract_digest: run.checkpoint_contract_digest.clone(),
            execution_identity_digest,
            admission_context_digest: provider.admission_context_digest.clone(),
            provider_semantic_id: provider.provider_semantic_id.clone(),
            provider_artifact_digest: provider.artifact_digest.clone(),
            provider_protocol_identity: admission.protocol_version.clone(),
            provider_config_digest: provider.configuration_digest.clone(),
            binding_digest: run.binding_digest.clone(),
            instance_id: run.instance_id.clone(),
            profile_id: run.profile_id.clone(),
            profile_version: run.profile_version.clone(),
            profile_digest: run.profile_digest.clone(),
            profile_semantic_id: provider.profile_semantic_id.clone(),
            evaluator_artifact_digest: provider.evaluator_artifact_digest.clone(),
            context: canonical(&context).expect("fixture intake context"),
            interpretation_kind: interpretation.kind().to_owned(),
            interpretation: canonical(&interpretation).expect("fixture provider interpretation"),
            native_outcome_kind: run.acquisition_outcome.clone(),
            native_outcome: run.resource_outcome.clone(),
            raw_bytes,
            started_at: run.started_at.clone(),
            finished_at: run.finished_at.clone(),
            received_at,
        };
        CollectionInput {
            intake,
            run,
            submission,
        }
    }

    #[test]
    fn coarse_healthy_projection_cannot_substitute_for_exact_detector_judgment() {
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        let descriptor = profile.descriptor();
        let detector = profile.detectors()[0].descriptor();
        let profile_identity = EvaluationProfileIdentity {
            profile: descriptor.profile.clone(),
            profile_digest: descriptor.digest().expect("profile digest"),
            profile_semantic_id: profile_semantic_id(descriptor)
                .expect("profile semantic identity"),
        };
        let context = EvaluationContextV1 {
            instance_id: "coarse-health.instance".to_owned(),
            subject: "host:coarse-health".to_owned(),
            scope: ScopeConfig {
                kind: "host".to_owned(),
                value: json!({"id": "coarse-health"}),
            },
            vantage: VantageConfig {
                kind: "local".to_owned(),
                value: json!({}),
            },
        };
        let make =
            |evaluation_id: &str, state: DetectorState, summary: &str| EvaluationEnvelopeV2 {
                schema: EvaluationEnvelopeSchema::V2,
                evaluation_id: evaluation_id.to_owned(),
                trigger_run_id: None,
                context: context.clone(),
                detector: EvaluationDetectorIdentity {
                    id: detector.id.clone(),
                    version: detector.version.to_string(),
                    digest: detector.digest().expect("detector digest"),
                },
                evaluator_artifact_digest: nq_protocol::sha256_bytes(b"coarse-health-evaluator"),
                profile: profile_identity.clone(),
                started_at: parse_timestamp("2026-07-20T12:00:00.000Z").expect("evaluation start"),
                evaluated_at: parse_timestamp("2026-07-20T12:00:01.000Z").expect("evaluation end"),
                watermark: EvaluationWatermarkV2 {
                    instance_id: context.instance_id.clone(),
                    max_report_sequence: 0,
                    watermark_received_at: None,
                },
                result: EvaluationResultV1 {
                    schema: EvaluationResultSchema::V1,
                    profile: profile_identity.clone(),
                    state,
                    condition: detector.condition.clone(),
                    summary: summary.to_owned(),
                    evidence: Vec::new(),
                    limitations: Vec::new(),
                    refusal: None,
                    watermark: EvidenceWatermark(0),
                },
            };
        let present = make(
            "evaluation-coarse-health-present",
            DetectorState::Present,
            "condition is present",
        );
        let absent = make(
            "evaluation-coarse-health-absent",
            DetectorState::ExplicitlyAbsent,
            "condition is explicitly absent",
        );
        present.validate().expect("valid present envelope");
        absent.validate().expect("valid explicit-absence envelope");

        let present_projection = evaluation_status_projection(&present);
        let absent_projection = evaluation_status_projection(&absent);
        assert_eq!(present_projection.0, HealthState::Healthy);
        assert_eq!(absent_projection.0, HealthState::Healthy);
        assert_ne!(present_projection.1, absent_projection.1);
        assert_ne!(
            canonical(&present).expect("present envelope"),
            canonical(&absent).expect("absence envelope")
        );
        assert_ne!(present.result.state, absent.result.state);
    }

    #[allow(clippy::too_many_lines)]
    fn commit_real_host_detector_report(
        store: &mut Store,
        watcher: &WatcherConfig,
        report_id: &str,
        suffix: &str,
        observed_at: DateTime<Utc>,
        load_1m: f64,
        next_checkpoint: Option<Value>,
    ) -> (DetectorReport, String, CollectionInput) {
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        let descriptor = profile.descriptor();
        let profile_digest = descriptor.digest().expect("compiled host digest");
        let received_at = observed_at + Duration::seconds(1);
        let report = nq_protocol::EvidenceReport {
            schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
            profile: ProfileBinding {
                id: ProfileId::new(descriptor.profile.id.clone()).expect("profile id"),
                version: ProfileVersion::new(descriptor.profile.version.to_string())
                    .expect("profile version"),
                digest: Sha256Digest::parse(profile_digest.as_str().to_owned())
                    .expect("profile digest"),
            },
            binding: SubjectBinding {
                subject: SubjectId::new(watcher.subject.clone()).expect("host subject"),
                scope: ScopeBinding {
                    kind: ScopeKind::new(watcher.scope.kind.clone()).expect("host scope"),
                    value: watcher.scope.value.clone(),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new(watcher.vantage.kind.clone()).expect("host vantage"),
                    value: watcher.vantage.value.clone(),
                },
            },
            observed_at,
            status: nq_protocol::ReportStatus::Complete,
            coverage: ["host_identity", "uptime", "load"]
                .into_iter()
                .map(|kind| nq_protocol::CoverageDeclaration {
                    kind: nq_protocol::CoverageKind::new(kind).expect("coverage kind"),
                    subject: None,
                    state: nq_protocol::CoverageState::Complete,
                    detail: None,
                })
                .collect(),
            observations: vec![nq_protocol::Observation {
                ordinal: 0,
                kind: nq_protocol::ObservationKind::new("host_snapshot").expect("observation kind"),
                subject: SubjectId::new(watcher.subject.clone()).expect("host subject"),
                observed_at,
                payload: json!({
                    "evidence_basis": {
                        "scope": {
                            "kind": watcher.scope.kind,
                            "value": watcher.scope.value,
                        },
                        "vantage": {
                            "kind": watcher.vantage.kind,
                            "value": watcher.vantage.value,
                        },
                        "access_path": "procfs",
                        "basis": "kernel_snapshot",
                        "regime": "normal",
                        "capabilities_used": ["read_procfs"],
                    },
                    "hostname": "local",
                    "uptime_seconds": 86_400,
                    "cpu_count": 2,
                    "load_1m": load_1m,
                }),
            }],
            errors: Vec::new(),
            used_capabilities: vec![Capability::new("read_procfs").expect("host capability")],
            backend: nq_protocol::BackendProvenance {
                implementation: nq_protocol::BackendIdentity {
                    name: nq_protocol::ImplementationName::new("real-host-detector-fixture")
                        .expect("backend name"),
                    version: Some("1".to_owned()),
                    digest: None,
                },
                tools: Vec::new(),
            },
            next_checkpoint: next_checkpoint.map(|value| nq_protocol::Checkpoint { value }),
        };
        nq_protocol::validate_report(&report).expect("protocol-valid host report");
        let report_digest = nq_protocol::semantic_digest(&report).expect("host report digest");
        let normalized = ProfileReportInput::from_protocol(&report, &report_digest)
            .expect("normalize real host report");
        let context = ValidationContext {
            instance_id: watcher.instance_id.clone(),
            request_subject: watcher.subject.clone(),
            scope: ScopeGrant {
                kind: watcher.scope.kind.clone(),
                value: watcher.scope.value.clone(),
            },
            vantage: VantageGrant {
                kind: watcher.vantage.kind.clone(),
                value: watcher.vantage.value.clone(),
            },
            granted_capabilities: BTreeSet::from(["read_procfs".to_owned()]),
            received_at,
            max_observations: 1,
            max_future_skew: Duration::seconds(5),
        };
        let validated = profile
            .validate(&context, &normalized)
            .expect("compiled host profile admits the report");
        let admission_id = seed_compiled_admission(store, profile, &watcher.instance_id, suffix);
        let run = test_run(
            store,
            profile,
            &watcher.instance_id,
            suffix,
            admission_id,
            AcquisitionOutcome::Response,
        );
        let stored = store_report(
            report_id,
            watcher,
            profile,
            &report,
            &validated,
            received_at,
        )
        .expect("materialize host report");
        let raw_bytes = nq_protocol::canonical_json_bytes(&report).expect("canonical host report");
        let run_id = run.run_id.clone();
        let evaluator_artifact_digest =
            nq_protocol::sha256_bytes(format!("evaluator-{suffix}").as_bytes()).into_string();
        let collection = test_collection(
            store,
            run,
            Some(SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes,
                received_at: timestamp(received_at),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(stored),
            }),
            suffix,
        );
        let committed = store
            .begin_writer_session()
            .expect("writer session")
            .commit_admitted_collection(&collection, |view, receipt| {
                let snapshot =
                    view.evidence_snapshot(std::slice::from_ref(&watcher.instance_id))?;
                let current_findings = view.finding_snapshots()?;
                let prepared = prepare_instance_evaluations(
                    watcher,
                    profile,
                    Some(&run_id),
                    &snapshot,
                    &current_findings,
                    &evaluator_artifact_digest,
                )?;
                let evaluations = prepared
                    .iter()
                    .map(|prepared| prepared.envelope.clone())
                    .collect();
                let outcome = CollectionOutcome::admitted(
                    watcher.instance_id.clone(),
                    run_id.clone(),
                    report_id.to_owned(),
                    semantic_report_status(validated.status).to_owned(),
                    receipt
                        .semantic_digest
                        .clone()
                        .expect("admitted report digest"),
                    evaluations,
                );
                Ok::<_, EngineError>(AdmittedCollectionCompletion {
                    value: (),
                    evaluations: prepared
                        .into_iter()
                        .map(|prepared| prepared.commit)
                        .collect(),
                    diagnostic_artifact: None,
                    status: instance_status_event(watcher, &outcome)
                        .expect("canonical admitted status"),
                })
            })
            .expect("commit admitted host report");
        let ProviderIntakeCommit::Committed {
            receipt, value: (), ..
        } = committed
        else {
            panic!("fresh fixture intake cannot replay")
        };
        let sequence = u64::try_from(
            receipt
                .report_sequence
                .expect("admitted report has durable sequence"),
        )
        .expect("positive report sequence");
        (
            DetectorReport {
                report_id: report_id.to_owned(),
                report_sequence: sequence,
                report: validated,
            },
            timestamp(received_at),
            collection,
        )
    }

    fn assert_provider_replay_context_conflict(
        store: &mut Store,
        collection: &CollectionInput,
        field: &str,
        mutate: impl FnOnce(&mut ProviderIntakeContextV1),
    ) {
        let mut changed_collection = collection.clone();
        let mut context: ProviderIntakeContextV1 =
            serde_json::from_slice(changed_collection.intake.context.as_bytes())
                .expect("typed replay context");
        mutate(&mut context);
        changed_collection.intake.context =
            canonical(&context).expect("canonical changed replay context");
        let Err(error) = store
            .begin_writer_session()
            .expect("writer session")
            .commit_admitted_collection(
            &changed_collection,
            |_, _| -> Result<AdmittedCollectionCompletion<()>, EngineError> {
                panic!("changed {field} replay must fail before evaluation")
            },
        ) else {
            panic!("changed {field} replay unexpectedly passed")
        };
        assert!(
            matches!(
                error,
                EngineError::Store(nq_store::StoreError::ReplayConflict(_))
            ),
            "changed {field} produced the wrong refusal: {error:?}"
        );
    }

    #[test]
    fn admitted_provider_replay_reopens_stored_decision_without_evaluator_or_checkpoint_rerun() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let database = directory.path().join("provider-replay.db");
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host config");
        let watcher = &config.watchers[0];
        let observed_at = parse_timestamp("2026-07-20T12:00:00.000Z").expect("observation time");
        let mut store = Store::initialize(&database).expect("initialize provider replay store");
        let (report, _, collection) = commit_real_host_detector_report(
            &mut store,
            watcher,
            "report-provider-replay",
            "provider-replay",
            observed_at,
            1.0,
            Some(json!({"cursor": "durably-acknowledged"})),
        );
        let (initial_acknowledgment, initial_result) = store
            .provider_intake_acknowledgment(&collection.intake.idempotency_key)
            .expect("initial acknowledgment lookup")
            .expect("initial acknowledgment");
        let initial_snapshot = store
            .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
            .expect("initial evidence snapshot");
        let initial_checkpoint = store
            .latest_checkpoint(
                &watcher.instance_id,
                &collection.run.checkpoint_contract_digest,
            )
            .expect("initial checkpoint")
            .expect("admitted report advances checkpoint");
        drop(store);

        let mut reopened = Store::open(&database).expect("reopen provider replay store");
        let completion_calls = std::cell::Cell::new(0_u32);
        let replay = reopened
            .begin_writer_session()
            .expect("writer session")
            .commit_admitted_collection(
                &collection,
                |_, _| -> Result<AdmittedCollectionCompletion<()>, EngineError> {
                    completion_calls.set(completion_calls.get() + 1);
                    Err(EngineError::Invariant(
                        "an exact replay must not invoke detector completion".to_owned(),
                    ))
                },
            )
            .expect("exact admitted intake replays from durable history");
        assert_eq!(completion_calls.get(), 0);
        let ProviderIntakeCommit::Replayed {
            receipt,
            acknowledgment,
            canonical_result,
        } = replay
        else {
            panic!("reopened exact attempt must not be committed twice")
        };
        assert_eq!(acknowledgment, initial_acknowledgment);
        assert_eq!(canonical_result, initial_result);
        assert_eq!(
            receipt.report_sequence,
            Some(i64::try_from(report.report_sequence).expect("report sequence fits SQLite"))
        );
        let outcome = decode_collection_outcome(canonical_result.as_bytes())
            .expect("stored collection outcome reopens");
        assert!(matches!(outcome.result, CollectionResult::Admitted { .. }));
        assert_eq!(
            reopened
                .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))
                .expect("reopened evidence snapshot"),
            initial_snapshot
        );
        assert_eq!(
            reopened
                .latest_checkpoint(
                    &watcher.instance_id,
                    &collection.run.checkpoint_contract_digest,
                )
                .expect("reopened checkpoint")
                .expect("checkpoint remains present"),
            initial_checkpoint
        );

        assert_provider_replay_context_conflict(
            &mut reopened,
            &collection,
            "checkpoint",
            |context| {
                context.request.checkpoint = Some(nq_protocol::Checkpoint {
                    value: json!({"cursor": "stale-or-substituted"}),
                });
            },
        );

        assert_provider_replay_context_conflict(&mut reopened, &collection, "subject", |context| {
            context.request.binding.subject =
                SubjectId::new("host:substituted-subject").expect("substituted subject");
        });
        assert_provider_replay_context_conflict(&mut reopened, &collection, "scope", |context| {
            context.request.binding.scope.value = json!({"id": "substituted-scope"});
        });
        assert_provider_replay_context_conflict(&mut reopened, &collection, "vantage", |context| {
            context.request.binding.vantage.value = json!({"namespace": "substituted-vantage"});
        });
    }

    fn committed_host_provider_intake(suffix: &str) -> (nq_store::ProviderIntakeRow, Vec<u8>) {
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host config");
        let watcher = &config.watchers[0];
        let observed_at = parse_timestamp("2026-07-20T12:00:00.000Z").expect("observation time");
        let mut store = Store::initialize_in_memory().expect("provider hostile store");
        let (_, _, collection) = commit_real_host_detector_report(
            &mut store,
            watcher,
            &format!("report-{suffix}"),
            suffix,
            observed_at,
            1.0,
            None,
        );
        let row = store
            .provider_intake(&collection.intake.intake_id)
            .expect("provider intake lookup")
            .expect("provider intake row");
        let raw = store
            .provider_intake_raw_bytes(&row.intake_id)
            .expect("provider raw lookup")
            .expect("provider raw bytes");
        ProviderIntakeRecordV1::reopen_store_row(&row, &raw)
            .expect("baseline provider row reopens");
        (row, raw)
    }

    fn reseal_provider_context(
        row: &mut nq_store::ProviderIntakeRow,
        context: &ProviderIntakeContextV1,
    ) {
        let document = canonical(context).expect("canonical hostile provider context");
        row.context_digest = document.digest().to_owned();
        row.context_json = document.as_bytes().to_vec();
    }

    #[test]
    fn source_grant_rejects_coherently_resealed_request_echo_and_raw_capability() {
        let (mut row, raw) = committed_host_provider_intake("source-capability-hostile");
        let mut duplicate_source_grant = row.clone();
        duplicate_source_grant.source_capability_grant_json =
            canonical(&json!(["read_procfs", "read_procfs"]))
                .expect("canonical duplicate source grant")
                .as_bytes()
                .to_vec();
        assert!(matches!(
            ProviderIntakeRecordV1::reopen_store_row(&duplicate_source_grant, &raw),
            Err(ProviderIntakeError::Invariant(message))
                if message.contains("source admission lock")
        ));
        let mut context: ProviderIntakeContextV1 =
            serde_json::from_slice(&row.context_json).expect("typed provider context");
        let response: nq_protocol::HelperResponse =
            nq_protocol::decode_ndjson(&raw, raw.len()).expect("typed provider response");
        let ResponseOutcome::Report { mut report } = response.outcome else {
            panic!("host fixture returns a candidate report")
        };
        let substituted = Capability::new("read_system_info").expect("host capability");
        context.request.granted_capabilities = vec![substituted.clone()];
        report.used_capabilities = vec![substituted];
        report.observations[0].payload["evidence_basis"]["capabilities_used"] =
            json!(["read_system_info"]);
        let response = nq_protocol::HelperResponse::report(&context.request, report);
        let hostile_raw = nq_protocol::encode_ndjson(&response).expect("hostile framed response");
        nq_protocol::parse_response(&context.request, &hostile_raw)
            .expect("substituted request and response are internally coherent");
        let interpretation = ProviderResponseInterpretationV1::Validated { response };
        let interpretation_document =
            canonical(&interpretation).expect("canonical hostile interpretation");
        row.interpretation_kind = interpretation.kind().to_owned();
        row.interpretation_digest = interpretation_document.digest().to_owned();
        row.interpretation_json = interpretation_document.as_bytes().to_vec();
        row.raw_sha256 = nq_protocol::sha256_bytes(&hostile_raw).into_string();
        row.acknowledgment.raw_sha256 = row.raw_sha256.clone();
        let mut native: RunResourceOutcomeV1 =
            serde_json::from_slice(&row.native_outcome_json).expect("typed native outcome");
        native.stdout_bytes_retained = hostile_raw.len();
        let native_document = canonical(&native).expect("canonical hostile native outcome");
        row.native_outcome_digest = native_document.digest().to_owned();
        row.native_outcome_json = native_document.as_bytes().to_vec();
        reseal_provider_context(&mut row, &context);

        assert!(matches!(
            ProviderIntakeRecordV1::reopen_store_row(&row, &hostile_raw),
            Err(ProviderIntakeError::Invariant(message))
                if message.contains("source admission lock")
        ));
    }

    #[test]
    fn source_lock_rejects_resealed_binding_execution_and_ack_provider_substitution() {
        let (row, raw) = committed_host_provider_intake("source-lock-hostile");
        let mut malformed_source = row.clone();
        let mut source_lock: AdmissionLock =
            serde_json::from_slice(&malformed_source.source_lock_json).expect("typed source lock");
        source_lock.schema = "nq.admission.unsupported".to_owned();
        malformed_source.source_lock_json = canonical(&source_lock)
            .expect("canonical malformed source lock")
            .as_bytes()
            .to_vec();
        assert!(matches!(
            ProviderIntakeRecordV1::reopen_store_row(&malformed_source, &raw),
            Err(ProviderIntakeError::Invariant(message))
                if message.contains("source provider admission lock is invalid")
        ));
        for (label, substitute_binding) in [("binding", true), ("execution", false)] {
            let mut hostile = row.clone();
            let mut context: ProviderIntakeContextV1 =
                serde_json::from_slice(&hostile.context_json).expect("typed provider context");
            let substituted = nq_protocol::sha256_bytes(format!("substituted-{label}").as_bytes());
            if substitute_binding {
                context.provider.binding_digest = substituted.clone();
                hostile.binding_digest = substituted.into_string();
            } else {
                context.provider.execution_identity_digest = substituted.clone();
                hostile.execution_identity_digest = substituted.into_string();
            }
            reseal_provider_context(&mut hostile, &context);
            assert!(matches!(
                ProviderIntakeRecordV1::reopen_store_row(&hostile, &raw),
                Err(ProviderIntakeError::Invariant(message))
                    if message.contains("source admission lock")
            ));
        }

        let mut hostile_ack = row;
        hostile_ack.acknowledgment.provider_admission_id =
            nq_protocol::sha256_bytes(b"substituted acknowledgment provider").into_string();
        assert!(matches!(
            ProviderIntakeRecordV1::reopen_store_row(&hostile_ack, &raw),
            Err(ProviderIntakeError::Invariant(message))
                if message.contains("acknowledgment disagrees")
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn mismatched_provider_refusal_is_rejected_before_atomic_commit_or_acknowledgment() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let database = directory.path().join("precommit-correspondence.db");
        let mut config = NqConfig::from_toml(&host_example_text()).expect("valid host config");
        config.database_path = database.clone();
        config.socket_path = directory.path().join("nqd.sock");
        config.admissions_dir = directory.path().join("admissions");
        config.helper_runtime_dir = directory.path().join("helpers");
        let watcher = config.watchers[0].clone();
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        let mut store = Store::initialize(&database).expect("initialize provider store");
        let admission_id = seed_compiled_admission(
            &mut store,
            profile,
            &watcher.instance_id,
            "precommit-correspondence",
        );
        let run = test_run(
            &store,
            profile,
            &watcher.instance_id,
            "precommit-correspondence",
            admission_id,
            AcquisitionOutcome::Response,
        );
        let run_id = run.run_id.clone();
        let original = nq_protocol::Refusal {
            responsible_instance_id: InstanceId::new(watcher.instance_id.clone())
                .expect("fixture instance identity"),
            boundary: nq_protocol::RefusalBoundary::Collection,
            code: nq_protocol::RefusalCode::CollectionFailed,
            message: "provider collection failed".to_owned(),
            retriable: true,
            details: json!({"errno": "EAGAIN"}),
        };
        let refusal_id = "refusal-precommit-correspondence";
        let governed = GovernedRefusal::helper(refusal_id.to_owned(), original);
        let submission = SubmissionInput {
            submission_id: "submission-precommit-correspondence".to_owned(),
            raw_bytes: Vec::new(),
            received_at: "2026-07-20T12:00:01.000Z".to_owned(),
            protocol_outcome: "valid_refusal".to_owned(),
            disposition: SubmissionDisposition::Rejected {
                refusal: stored_governed_refusal(
                    &governed,
                    parse_timestamp("2026-07-20T12:00:01.000Z").expect("fixture refusal time"),
                )
                .expect("stored helper refusal"),
            },
        };
        let collection = test_collection(
            &mut store,
            run,
            Some(submission),
            "precommit-correspondence",
        );
        drop(store);

        let evaluator = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(
            b"precommit-correspondence-evaluator",
        ));
        let mut engine = CollectionEngine::open_with_evaluator_identity(&config, Ok(evaluator))
            .expect("open provider engine");
        let substituted = nq_protocol::Refusal {
            responsible_instance_id: InstanceId::new(watcher.instance_id.clone())
                .expect("fixture instance identity"),
            boundary: nq_protocol::RefusalBoundary::Collection,
            code: nq_protocol::RefusalCode::CollectionFailed,
            message: "provider collection failed".to_owned(),
            retriable: false,
            details: json!({"errno": "ENODEV"}),
        };
        let outcome = CollectionOutcome::rejected(
            watcher.instance_id.clone(),
            run_id.clone(),
            GovernedRefusal::helper(refusal_id.to_owned(), substituted),
        );
        let idempotency_key = collection.intake.idempotency_key.clone();
        let CollectionInput {
            intake,
            run,
            submission,
        } = collection;
        let error = engine
            .commit_non_success_collection(&watcher, intake, run, submission, outcome, None)
            .expect_err("mismatched source and result planes must fail before commit");
        assert!(matches!(
            error,
            EngineError::Invariant(message) if message.contains("does not correspond")
        ));
        assert!(
            engine
                .store
                .provider_intakes_bounded(10, None)
                .expect("provider intake history")
                .is_empty()
        );
        assert!(
            engine
                .store
                .watcher_run_outcome(&run_id)
                .expect("watcher run lookup")
                .is_none()
        );
        assert!(
            engine
                .store
                .rejected_custody(10)
                .expect("rejected custody")
                .is_empty()
        );
        assert!(
            engine
                .store
                .provider_intake_acknowledgment(&idempotency_key)
                .expect("acknowledgment lookup")
                .is_none()
        );
    }

    fn commit_test_non_success(
        store: &mut Store,
        run: RunInput,
        submission: Option<SubmissionInput>,
        outcome: &CollectionOutcome,
        suffix: &str,
    ) -> nq_store::CollectionReceipt {
        let projection = instance_status_projection(outcome).expect("status projection");
        let result = RunResultStatusInput {
            run_id: run.run_id.clone(),
            status: StatusEventInput {
                status_event_id: format!("status-{suffix}"),
                component_kind: "instance".to_owned(),
                component_id: run.instance_id.clone(),
                state: projection.state.to_owned(),
                code: projection.code.to_owned(),
                detail: canonical(outcome).expect("canonical collection result"),
                observed_at: "2026-07-20T12:00:01.000Z".to_owned(),
            },
        };
        let collection = test_collection(store, run, submission, suffix);
        let committed = store
            .begin_writer_session()
            .expect("writer session")
            .commit_non_success_collection(&collection, &result)
            .expect("commit atomic non-success fixture");
        let ProviderIntakeCommit::Committed { receipt, .. } = committed else {
            panic!("fresh fixture intake cannot replay")
        };
        receipt
    }

    fn host_example_text() -> String {
        include_str!("../../../examples/nq-host.toml").replace(
            "execution_account = \"nq-helper\"",
            &format!(
                "execution_account = \"{}\"\nallow_same_identity_in_debug = true",
                nix::unistd::geteuid().as_raw()
            ),
        )
    }

    fn host_cannot_evaluate_envelope() -> EvaluationEnvelopeV2 {
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host config");
        let watcher = &config.watchers[0];
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        let profile_descriptor = profile.descriptor();
        let detector = profile.detectors()[0];
        let detector_descriptor = detector.descriptor();
        let evaluated_at = parse_timestamp("2026-07-20T12:10:00.000Z").expect("evaluation time");
        let source = detector.evaluate(&DetectorInput {
            instance_id: &watcher.instance_id,
            evaluated_at,
            watermark: EvidenceWatermark(0),
            reports: &[],
        });
        assert_eq!(source.state, DetectorState::CannotEvaluate);
        let profile_identity = EvaluationProfileIdentity {
            profile: profile_descriptor.profile.clone(),
            profile_digest: profile_descriptor.digest().expect("profile digest"),
            profile_semantic_id: profile_semantic_id(profile_descriptor)
                .expect("profile semantic identity"),
        };
        let refusal = GovernedRefusal::profile(
            "refusal-producer-invariant".to_owned(),
            profile_identity.profile_semantic_id.clone(),
            source
                .refusal
                .clone()
                .expect("host detector returns a typed refusal"),
        );
        let result = governed_evaluation_result(&source, profile_identity.clone(), Some(refusal))
            .expect("governed detector result");
        EvaluationEnvelopeV2 {
            schema: EvaluationEnvelopeSchema::V2,
            evaluation_id: "evaluation-producer-invariant".to_owned(),
            trigger_run_id: None,
            context: EvaluationContextV1 {
                instance_id: watcher.instance_id.clone(),
                subject: watcher.subject.clone(),
                scope: watcher.scope.clone(),
                vantage: watcher.vantage.clone(),
            },
            detector: EvaluationDetectorIdentity {
                id: detector_descriptor.id.clone(),
                version: detector_descriptor.version.to_string(),
                digest: detector_descriptor.digest().expect("detector digest"),
            },
            evaluator_artifact_digest: nq_protocol::sha256_bytes(b"producer-invariant-evaluator"),
            profile: profile_identity,
            started_at: evaluated_at,
            evaluated_at,
            watermark: EvaluationWatermarkV2 {
                instance_id: watcher.instance_id.clone(),
                max_report_sequence: 0,
                watermark_received_at: None,
            },
            result,
        }
    }

    fn evaluation_profile_refusal_mut(
        envelope: &mut EvaluationEnvelopeV2,
    ) -> &mut nq_profiles::ProfileRefusal {
        let Some(GovernedRefusal {
            origin: GovernedRefusalOrigin::Profile(profile),
            ..
        }) = envelope.result.refusal.as_mut()
        else {
            panic!("fixture evaluation must retain its profile-origin refusal")
        };
        &mut profile.refusal
    }

    fn assert_cannot_evaluate_producer_invariant_refused(envelope: &EvaluationEnvelopeV2) {
        assert!(matches!(
            envelope.validate(),
            Err(EngineError::Invariant(message))
                if message.contains("exact detector producer invariant")
        ));
    }

    fn binding_recovery_fixture(root: &Path) -> (NqConfig, WatcherConfig, AdmissionLock) {
        fs::create_dir(root.join("admissions")).expect("fixture admissions root");
        let helper = root.join("helper.sh");
        fs::write(&helper, b"#!/bin/sh\nexit 0\n").expect("fixture helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755))
            .expect("fixture helper mode");
        let watcher = WatcherConfig {
            instance_id: "recovery.primary".to_owned(),
            command: CommandConfig {
                executable: helper,
                args: Vec::new(),
                env: BTreeMap::new(),
                execution_account: nix::unistd::geteuid().as_raw().to_string(),
                allow_same_identity_in_debug: true,
                working_directory: root.to_path_buf(),
            },
            carrier: Carrier::Stdio,
            profile: ProfileSelection {
                id: "nq.conformance".to_owned(),
                version: 1,
            },
            subject: "conformance:recovery".to_owned(),
            scope: ScopeConfig {
                kind: "fixture".to_owned(),
                value: json!({"id": "recovery", "nonce": "test"}),
            },
            vantage: VantageConfig {
                kind: "local".to_owned(),
                value: json!({}),
            },
            capability_ceiling: BTreeSet::new(),
            invocation: InvocationPolicy::default(),
            resources: ResourceLimits::default(),
            checkpoint_policy: CheckpointPolicy::Disabled,
        };
        let config = NqConfig {
            schema: crate::config::CONFIG_SCHEMA.to_owned(),
            database_path: root.join("nq.db"),
            socket_path: root.join("nqd.sock"),
            admissions_dir: root.join("admissions"),
            helper_runtime_dir: root.join("helpers"),
            watchers: vec![watcher.clone()],
        };
        let profile = resolve(&watcher).expect("compiled fixture profile");
        let corpus = nq_protocol::verify_embedded_conformance_corpus().expect("corpus");
        let lock = AdmissionManager
            .candidate(
                &watcher,
                CandidateEvidence {
                    profile_digest: profile
                        .descriptor()
                        .digest()
                        .expect("profile digest")
                        .as_str()
                        .to_owned(),
                    protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                    declared_capabilities: BTreeSet::new(),
                    conformance: ConformanceReceipt {
                        tool_version: corpus.version.verifier_version,
                        protocol_passed: true,
                        protocol_corpus_digest: corpus.version.corpus_digest.to_string(),
                        protocol_fixtures_checked: corpus.fixtures_checked,
                        dry_collection_passed: true,
                        dry_report_digest: Some(format!("sha256:{}", "a".repeat(64))),
                    },
                },
            )
            .expect("candidate lock");
        (config, watcher, lock)
    }

    fn host_diagnostic_fixture(root: &Path) -> (NqConfig, WatcherConfig, PathBuf) {
        fs::create_dir(root.join("admissions")).expect("fixture admissions root");
        let script = root.join("host_diagnostic_helper.py");
        let mode = root.join("host_diagnostic_helper.mode");
        fs::write(&script, HOST_DIAGNOSTIC_HELPER).expect("write host diagnostic helper");
        fs::write(&mode, "complete\n").expect("write host diagnostic helper mode");
        let watcher = WatcherConfig {
            instance_id: "host-diagnostic.primary".to_owned(),
            command: CommandConfig {
                executable: PathBuf::from("/usr/bin/python3"),
                args: vec![script.to_string_lossy().into_owned()],
                env: BTreeMap::from([(
                    "NQ_DIAGNOSTIC_TEST_MODE".to_owned(),
                    mode.to_string_lossy().into_owned(),
                )]),
                execution_account: nix::unistd::geteuid().as_raw().to_string(),
                allow_same_identity_in_debug: true,
                working_directory: root.to_path_buf(),
            },
            carrier: Carrier::Stdio,
            profile: ProfileSelection {
                id: nq_profiles::host::PROFILE_ID.to_owned(),
                version: nq_profiles::host::PROFILE_VERSION,
            },
            subject: "host:diagnostic-fixture".to_owned(),
            scope: ScopeConfig {
                kind: "host".to_owned(),
                value: json!({"id": "diagnostic-fixture"}),
            },
            vantage: VantageConfig {
                kind: "local".to_owned(),
                value: json!({}),
            },
            capability_ceiling: BTreeSet::from([
                "read_procfs".to_owned(),
                "read_system_info".to_owned(),
            ]),
            invocation: InvocationPolicy::default(),
            resources: ResourceLimits::default(),
            checkpoint_policy: CheckpointPolicy::Disabled,
        };
        let config = NqConfig {
            schema: crate::config::CONFIG_SCHEMA.to_owned(),
            database_path: root.join("nq.db"),
            socket_path: root.join("nqd.sock"),
            admissions_dir: root.join("admissions"),
            helper_runtime_dir: root.join("helpers"),
            watchers: vec![watcher.clone()],
        };
        (config, watcher, mode)
    }

    fn admitted_host_diagnostic_fixture(
        root: &Path,
        genesis_id: &str,
        evaluator_label: &[u8],
    ) -> Option<(CollectionEngine, WatcherConfig, PathBuf)> {
        let (config, watcher, mode) = host_diagnostic_fixture(root);
        let mut store = Store::initialize(&config.database_path).expect("initialize store");
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            resolve(&watcher).expect("host profile"),
        )
        .expect("profile descriptor");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_genesis(&GenesisInput {
                genesis_id: genesis_id.to_owned(),
                legacy_manifest_digest: None,
                created_at: "2026-07-28T12:00:00.000Z".to_owned(),
                detail: canonical(&json!({"source": "diagnostic-non-success-test"}))
                    .expect("genesis detail"),
            })
            .expect("append genesis");
        drop(store);
        let evaluator =
            EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(evaluator_label));
        let mut engine =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(evaluator)).expect("engine");
        if let Err(error) = engine.watcher_action(&watcher, "admit") {
            if error.to_string().contains("\"class\":\"spawn_failed\"")
                && fs::read_to_string("/proc/self/attr/current")
                    .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
            {
                eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
                return None;
            }
            panic!("fixture admission failed: {error}");
        }
        Some((engine, watcher, mode))
    }

    struct SemanticLineageFixture {
        config: NqConfig,
        profile: &'static dyn ProfileModule,
        detector_version: String,
        detector_digest: String,
        profile_version: String,
        profile_digest: String,
        subject_json: String,
        observed_at: DateTime<Utc>,
        semantic_digest: String,
        finding: nq_store::FindingSnapshotRow,
    }

    impl SemanticLineageFixture {
        fn new() -> Self {
            let config = NqConfig::from_toml(&host_example_text()).expect("valid host example");
            let watcher = &config.watchers[0];
            let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
            let descriptor = profile.detectors()[0].descriptor();
            let detector_version = descriptor.version.to_string();
            let detector_digest = descriptor.digest().expect("compiled detector digest");
            let profile_version = profile.descriptor().profile.version.to_string();
            let profile_digest = profile
                .descriptor()
                .digest()
                .expect("compiled profile digest")
                .as_str()
                .to_owned();
            let subject_json = serde_json::to_string(&Value::String(watcher.subject.clone()))
                .expect("subject JSON");
            let observed_at = Utc::now();
            let semantic_digest = format!("sha256:{}", "a".repeat(64));
            let finding = nq_store::FindingSnapshotRow {
                finding_id: "finding:old-lineage".to_owned(),
                instance_id: watcher.instance_id.clone(),
                detector_id: descriptor.id.clone(),
                detector_version: detector_version.clone(),
                detector_digest: detector_digest.clone(),
                evaluation_revision: 1,
                profile_id: profile.descriptor().profile.id.clone(),
                profile_version: profile_version.clone(),
                profile_digest: profile_digest.clone(),
                profile_semantic_id: profile_semantic_id(profile.descriptor())
                    .expect("compiled profile semantic identity")
                    .as_str()
                    .to_owned(),
                subject_json: subject_json.clone(),
                condition_name: descriptor.condition.clone(),
                condition_state: "present".to_owned(),
                visibility_state: "sufficient".to_owned(),
                operator_work_state: "unreviewed".to_owned(),
                severity: "warning".to_owned(),
                summary: "old compiled semantics found a condition".to_owned(),
                limitations_json: "[]".to_owned(),
                safe_next_checks_json: "[]".to_owned(),
                freshness_json: "{}".to_owned(),
                basis_json: "{}".to_owned(),
                refusal_json: None,
                origin_mode: "native".to_owned(),
                historical_refs_json: "[]".to_owned(),
                observed_at: Some(timestamp(observed_at)),
                received_at: Some(timestamp(observed_at)),
                evaluated_at: timestamp(observed_at),
                evaluation_id: "evaluation:old-lineage".to_owned(),
                evaluation_refusal_json: None,
                evidence_json: serde_json::to_string(&vec![PublicEvidenceReference {
                    report_id: "report:old-lineage".to_owned(),
                    semantic_digest: semantic_digest.clone(),
                    observation_ordinal: None,
                    observed_at,
                    received_at: observed_at,
                }])
                .expect("evidence JSON"),
            };
            Self {
                config,
                profile,
                detector_version,
                detector_digest,
                profile_version,
                profile_digest,
                subject_json,
                observed_at,
                semantic_digest,
                finding,
            }
        }

        fn watcher(&self) -> &WatcherConfig {
            &self.config.watchers[0]
        }

        fn descriptor(&self) -> &'static nq_profiles::DetectorDescriptor {
            self.profile.detectors()[0].descriptor()
        }

        fn lineage(&self) -> FindingLineage<'_> {
            FindingLineage {
                instance_id: &self.watcher().instance_id,
                detector_id: &self.descriptor().id,
                detector_version: &self.detector_version,
                detector_digest: &self.detector_digest,
                profile_id: &self.watcher().profile.id,
                profile_version: &self.profile_version,
                profile_digest: &self.profile_digest,
                profile_semantic_id: &self.finding.profile_semantic_id,
                subject_json: &self.subject_json,
                basis_json: &self.finding.basis_json,
            }
        }

        fn report(
            &self,
            report_sequence: i64,
            report_id: &str,
            semantic_digest: &str,
        ) -> nq_store::AdmittedReportRow {
            nq_store::AdmittedReportRow {
                report_sequence,
                report_id: report_id.to_owned(),
                instance_id: self.watcher().instance_id.clone(),
                profile_id: self.watcher().profile.id.clone(),
                profile_version: self.profile_version.clone(),
                profile_digest: self.profile_digest.clone(),
                observed_at: timestamp(self.observed_at),
                received_at: timestamp(self.observed_at),
                report_status: "complete".to_owned(),
                canonical_json: Vec::new(),
                semantic_digest: semantic_digest.to_owned(),
            }
        }
    }

    #[test]
    fn compiled_config_enforces_profile_owned_binding_correlation() {
        let text =
            host_example_text().replace("value = { id = \"local\" }", "value = { id = \"other\" }");
        let config = NqConfig::from_toml(&text).expect("shape-valid configuration");
        let error = validate_compiled_config(&config).expect_err("subject must correlate to scope");
        assert!(error.to_string().contains("does not correlate"));
    }

    #[test]
    fn compiled_config_accepts_valid_host_binding() {
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host example");
        validate_compiled_config(&config).expect("compiled profile binding");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn pending_authoritative_binding_is_reconciled_but_untracked_tampering_is_not() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (config, watcher, lock) = binding_recovery_fixture(directory.path());
        let profile = resolve(&watcher).expect("profile");
        let mut store = Store::initialize(&config.database_path).expect("initialize store");
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            profile,
        )
        .expect("descriptor");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_admission(&AdmissionInput {
                admission_id: lock.admission_id.clone(),
                instance_id: lock.instance_id.clone(),
                identity: AdmissionIdentity {
                    profile_semantic_id: Sha256Digest::parse(format!("sha256:{}", "b".repeat(64)))
                        .unwrap(),
                    detector_identity_digest: Sha256Digest::parse(format!(
                        "sha256:{}",
                        "c".repeat(64)
                    ))
                    .unwrap(),
                    evaluator_source_digest: Sha256Digest::parse(EVALUATOR_SOURCE_DIGEST).unwrap(),
                    evaluator_artifact_digest: Sha256Digest::parse(format!(
                        "sha256:{}",
                        "d".repeat(64)
                    ))
                    .unwrap(),
                    helper_artifact_digest: Sha256Digest::parse(lock.execution.sha256.clone())
                        .unwrap(),
                    config_digest: Sha256Digest::parse(lock.config_digest.clone()).unwrap(),
                    protocol_version: lock.protocol_version.clone(),
                    target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                    artifact_identity_method: "fixture".to_owned(),
                    platform_runtime_version: "test".to_owned(),
                },
                execution_chain: canonical(&lock.execution).expect("execution JSON"),
                profile_id: lock.profile.id.clone(),
                profile_version: lock.profile.version.to_string(),
                profile_digest: lock.profile.digest.clone(),
                capability_grant: canonical(&lock.granted_capabilities).expect("capability JSON"),
                conformance: canonical(&lock.conformance).expect("conformance JSON"),
                lock: canonical(&lock).expect("lock JSON"),
                admitted_at: timestamp(lock.admitted_at),
                operator_identity: canonical(&lock.operator).expect("operator JSON"),
            })
            .expect("admission");
        drop(store);

        let mut engine = CollectionEngine::open(&config).expect("engine");
        let operation_id = Uuid::new_v4().to_string();
        let binding_event_id = Uuid::new_v4().to_string();
        let plan = BindingMaterializationPlan {
            schema: BINDING_MATERIALIZATION_PLAN_SCHEMA.to_owned(),
            operation_id: operation_id.clone(),
            instance_id: watcher.instance_id.clone(),
            binding_event_id: binding_event_id.clone(),
            admissions_root: AdmissionRootIdentity::resolve(&config.admissions_dir)
                .expect("admissions root identity"),
            desired_lock: Some(lock.clone()),
            previous_lock: None,
        };
        let plan_document = canonical(&plan).expect("plan JSON");
        engine
            .store
            .begin_writer_session()
            .expect("writer session")
            .begin_binding_transition(
                &BindingEventInput {
                    binding_event_id: binding_event_id.clone(),
                    instance_id: watcher.instance_id.clone(),
                    event_kind: "activate".to_owned(),
                    admission_id: Some(lock.admission_id.clone()),
                    binding_digest: AdmissionManager
                        .binding_digest(&lock)
                        .expect("binding digest"),
                    occurred_at: timestamp(Utc::now()),
                    reason_code: Some("crash-window-test".to_owned()),
                    detail: canonical(&json!({})).expect("event detail"),
                },
                &BindingMaterializationInput {
                    materialization_event_id: Uuid::new_v4().to_string(),
                    operation_id,
                    instance_id: watcher.instance_id.clone(),
                    binding_event_id,
                    phase: "intent".to_owned(),
                    occurred_at: timestamp(Utc::now()),
                    detail: plan_document,
                },
            )
            .expect("authoritative event and intent");
        assert!(!config.admissions_dir.join("recovery.primary.json").exists());

        // Simulated crash: drop the process after the SQLite transaction and
        // reopen without ever applying the active file.
        drop(engine);
        let mut drifting_config = config.clone();
        drifting_config.admissions_dir = directory.path().join("different-admissions");
        fs::create_dir(&drifting_config.admissions_dir).expect("drifting admissions root");
        let mut drifting = CollectionEngine::open(&drifting_config).expect("drifting engine");
        assert!(matches!(
            drifting.reconcile_pending_binding(&watcher),
            Err(EngineError::Invariant(message)) if message.contains("different admissions root")
        ));
        assert!(
            drifting
                .store
                .pending_binding_materialization(&watcher.instance_id)
                .expect("pending after drift refusal")
                .is_some(),
            "config drift must leave the original intent recoverable"
        );
        assert!(
            !drifting_config
                .admissions_dir
                .join("recovery.primary.json")
                .exists()
        );
        drop(drifting);

        let mut recovered = CollectionEngine::open(&config).expect("recovered engine");
        assert!(
            recovered
                .reconcile_pending_binding(&watcher)
                .expect("reconcile pending intent")
        );
        assert_eq!(
            recovered
                .authoritative_active_lock(&watcher)
                .expect("authoritative lock")
                .expect("active lock"),
            lock
        );
        assert!(
            recovered
                .store
                .pending_binding_materialization(&watcher.instance_id)
                .expect("pending query")
                .is_none()
        );

        // With no pending intent, a different valid-looking lock is drift and
        // must not be silently overwritten from SQLite.
        let corpus = nq_protocol::verify_embedded_conformance_corpus().expect("corpus");
        let forged = AdmissionManager
            .candidate(
                &watcher,
                CandidateEvidence {
                    profile_digest: lock.profile.digest.clone(),
                    protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                    declared_capabilities: BTreeSet::new(),
                    conformance: ConformanceReceipt {
                        tool_version: corpus.version.verifier_version,
                        protocol_passed: true,
                        protocol_corpus_digest: corpus.version.corpus_digest.to_string(),
                        protocol_fixtures_checked: corpus.fixtures_checked,
                        dry_collection_passed: true,
                        dry_report_digest: Some(format!("sha256:{}", "b".repeat(64))),
                    },
                },
            )
            .expect("second valid lock shape");
        AdmissionManager
            .activate(&config.admissions_dir, &forged)
            .expect("tamper with materialization");
        assert!(matches!(
            recovered.authoritative_active_lock(&watcher),
            Err(EngineError::Invariant(message)) if message.contains("differs from authoritative")
        ));
        assert_eq!(
            AdmissionManager
                .load(&config.admissions_dir.join("recovery.primary.json"))
                .expect("tampered lock remains for diagnosis"),
            forged,
            "ordinary drift must not be auto-healed without a durable pending intent"
        );
    }

    #[test]
    fn boottime_deadline_basis_is_available() {
        assert!(boottime_ns().unwrap() > 0);
    }

    #[test]
    fn missing_testimony_does_not_create_an_absence_finding() {
        assert_eq!(
            detector_state(DetectorState::CannotEvaluate),
            "cannot_evaluate"
        );
        assert_ne!(
            detector_state(DetectorState::CannotEvaluate),
            "explicitly_absent"
        );
    }

    #[test]
    fn evaluation_envelope_rejects_substituted_cannot_evaluate_boundary() {
        let mut envelope = host_cannot_evaluate_envelope();
        envelope.validate().expect("exact producer envelope");
        evaluation_profile_refusal_mut(&mut envelope).boundary =
            nq_profiles::RefusalBoundary::Observation;
        assert_cannot_evaluate_producer_invariant_refused(&envelope);
    }

    #[test]
    fn evaluation_envelope_rejects_substituted_cannot_evaluate_code() {
        let mut envelope = host_cannot_evaluate_envelope();
        evaluation_profile_refusal_mut(&mut envelope).code =
            nq_profiles::ProfileRefusalCode::InvalidPayload;
        assert_cannot_evaluate_producer_invariant_refused(&envelope);
    }

    #[test]
    fn evaluation_envelope_rejects_substituted_cannot_evaluate_message() {
        let mut envelope = host_cannot_evaluate_envelope();
        evaluation_profile_refusal_mut(&mut envelope).message =
            "substituted operator explanation".to_owned();
        assert_cannot_evaluate_producer_invariant_refused(&envelope);
    }

    #[test]
    fn evaluation_envelope_rejects_evidence_on_cannot_evaluate() {
        let mut envelope = host_cannot_evaluate_envelope();
        envelope
            .result
            .evidence
            .push(nq_profiles::DetectorEvidence {
                report_id: "substituted-report".to_owned(),
                report_sequence: 1,
                report_digest: nq_protocol::sha256_bytes(b"substituted-report").into_string(),
                observation_ordinal: Some(0),
                observed_at: envelope.evaluated_at,
            });
        assert_cannot_evaluate_producer_invariant_refused(&envelope);
    }

    #[test]
    fn valid_failed_report_is_not_an_acquisition_failure() {
        let outcome = CollectionOutcome::admitted(
            "x".into(),
            "r".into(),
            "p".into(),
            "failed".into(),
            format!("sha256:{}", "a".repeat(64)),
            Vec::new(),
        );
        assert!(!outcome.has_admitted_usable_report());
        assert!(matches!(outcome.result, CollectionResult::Admitted { .. }));
    }

    #[test]
    fn changed_semantic_identity_cannot_inherit_or_relabel_a_finding() {
        let fixture = SemanticLineageFixture::new();
        let findings = [fixture.finding.clone()];
        let exact = fixture.lineage();
        assert_eq!(
            find_current_finding(&findings, &exact).map(|finding| finding.finding_id.as_str()),
            Some("finding:old-lineage")
        );

        let changed_detector_version = "999".to_owned();
        let changed_detector_digest = format!("sha256:{}", "b".repeat(64));
        let changed_profile_version = "999".to_owned();
        let changed_profile_digest = format!("sha256:{}", "c".repeat(64));
        let changed_profile_semantic_id = format!("sha256:{}", "d".repeat(64));
        let changed_lineages = [
            FindingLineage {
                detector_version: &changed_detector_version,
                ..exact
            },
            FindingLineage {
                detector_digest: &changed_detector_digest,
                ..exact
            },
            FindingLineage {
                profile_version: &changed_profile_version,
                ..exact
            },
            FindingLineage {
                profile_digest: &changed_profile_digest,
                ..exact
            },
            FindingLineage {
                profile_semantic_id: &changed_profile_semantic_id,
                ..exact
            },
        ];
        for changed in changed_lineages {
            assert!(
                find_current_finding(&findings, &changed).is_none(),
                "a changed semantic identity must start a distinct lineage"
            );
        }

        let mut substituted_public_digest = fixture.finding.clone();
        substituted_public_digest.profile_digest = changed_profile_digest.clone();
        assert!(matches!(
            finding_from_row(substituted_public_digest),
            Err(EngineError::Invariant(message))
                if message.contains("profile digest or semantic identity was substituted")
        ));
        let mut substituted_public_semantics = fixture.finding.clone();
        substituted_public_semantics.profile_semantic_id = changed_profile_semantic_id;
        assert!(matches!(
            finding_from_row(substituted_public_semantics),
            Err(EngineError::Invariant(message))
                if message.contains("profile digest or semantic identity was substituted")
        ));

        let old_report = fixture.report(1, "report:old-lineage", &fixture.semantic_digest);
        assert!(report_matches_profile_contract(
            &old_report,
            &fixture.watcher().profile.id,
            &fixture.profile_version,
            &fixture.profile_digest,
        ));
        assert!(
            !report_matches_profile_contract(
                &old_report,
                &fixture.watcher().profile.id,
                &fixture.profile_version,
                &changed_profile_digest,
            ),
            "old-digest evidence must not enter a changed profile contract"
        );
    }

    #[test]
    fn changed_semantics_open_a_distinct_finding_or_no_finding() {
        let fixture = SemanticLineageFixture::new();
        let findings = [fixture.finding.clone()];
        let exact = fixture.lineage();
        let changed_detector_digest = format!("sha256:{}", "b".repeat(64));
        let changed_detector_lineage = FindingLineage {
            detector_digest: &changed_detector_digest,
            ..exact
        };
        let changed_current = find_current_finding(&findings, &changed_detector_lineage);
        assert!(changed_current.is_none());
        let watcher = fixture.watcher();
        let descriptor = fixture.descriptor();
        let detector_input = DetectorInput {
            instance_id: &watcher.instance_id,
            evaluated_at: fixture.observed_at,
            watermark: EvidenceWatermark(1),
            reports: &[],
        };
        let cannot_evaluate = nq_profiles::DetectorResult::cannot_evaluate(
            &detector_input,
            descriptor,
            "the changed detector has no evidence under its exact contract",
            Vec::new(),
        );
        let new_semantic_digest = format!("sha256:{}", "d".repeat(64));
        let new_report = fixture.report(2, "report:new-lineage", &new_semantic_digest);
        let present = nq_profiles::DetectorResult {
            state: DetectorState::Present,
            condition: descriptor.condition.clone(),
            summary: "changed compiled semantics found a condition".to_owned(),
            evidence: vec![nq_profiles::DetectorEvidence {
                report_id: new_report.report_id.clone(),
                report_sequence: 2,
                report_digest: new_semantic_digest,
                observation_ordinal: None,
                observed_at: fixture.observed_at,
            }],
            limitations: Vec::new(),
            refusal: None,
            watermark: EvidenceWatermark(2),
        };
        let opened = build_finding_event(
            watcher,
            fixture.profile,
            descriptor,
            &present,
            None,
            fixture.observed_at,
            changed_current,
            std::slice::from_ref(&new_report),
        )
        .expect("changed lineage finding is well formed")
        .expect("present condition opens a distinct finding lineage");
        assert_ne!(opened.finding_id, findings[0].finding_id);
        assert_eq!(opened.evidence.len(), 1);
        assert_eq!(opened.evidence[0].report_id, "report:new-lineage");

        let event = build_finding_event(
            watcher,
            fixture.profile,
            descriptor,
            &cannot_evaluate,
            None,
            fixture.observed_at,
            changed_current,
            &[],
        )
        .expect("changed lineage evaluation is well formed");
        assert!(
            event.is_none(),
            "cannot-evaluate under changed semantics must not update or retain the old finding"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn finding_transport_uses_only_the_exact_evaluation_context_rows() {
        let fixture = SemanticLineageFixture::new();
        let watcher = fixture.watcher();
        let mut other_boundary = watcher.clone();
        other_boundary.subject = "host:other".to_owned();
        other_boundary.scope.value = json!({"id": "other"});

        let row = |sequence: i64,
                   report_id: &str,
                   boundary: &WatcherConfig,
                   status: nq_protocol::ReportStatus| {
            let report = nq_protocol::EvidenceReport {
                schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
                profile: ProfileBinding {
                    id: ProfileId::new(fixture.profile.descriptor().profile.id.clone())
                        .expect("profile id"),
                    version: ProfileVersion::new(
                        fixture.profile.descriptor().profile.version.to_string(),
                    )
                    .expect("profile version"),
                    digest: Sha256Digest::parse(fixture.profile_digest.clone())
                        .expect("profile digest"),
                },
                binding: SubjectBinding {
                    subject: SubjectId::new(boundary.subject.clone()).expect("subject"),
                    scope: ScopeBinding {
                        kind: ScopeKind::new(boundary.scope.kind.clone()).expect("scope kind"),
                        value: boundary.scope.value.clone(),
                    },
                    vantage: VantageBinding {
                        kind: VantageKind::new(boundary.vantage.kind.clone())
                            .expect("vantage kind"),
                        value: boundary.vantage.value.clone(),
                    },
                },
                observed_at: fixture.observed_at,
                status,
                coverage: Vec::new(),
                observations: Vec::new(),
                errors: Vec::new(),
                used_capabilities: Vec::new(),
                backend: nq_protocol::BackendProvenance {
                    implementation: nq_protocol::BackendIdentity {
                        name: nq_protocol::ImplementationName::new("context-row-fixture")
                            .expect("implementation name"),
                        version: Some("1".to_owned()),
                        digest: None,
                    },
                    tools: Vec::new(),
                },
                next_checkpoint: None,
            };
            nq_protocol::validate_report(&report).expect("protocol-valid context row");
            let canonical = nq_protocol::canonical_json_bytes(&report).expect("canonical report");
            let digest = nq_protocol::semantic_digest(&report)
                .expect("report digest")
                .to_string();
            nq_store::AdmittedReportRow {
                report_sequence: sequence,
                report_id: report_id.to_owned(),
                instance_id: watcher.instance_id.clone(),
                profile_id: fixture.profile.descriptor().profile.id.clone(),
                profile_version: fixture.profile_version.clone(),
                profile_digest: fixture.profile_digest.clone(),
                observed_at: timestamp(fixture.observed_at),
                received_at: timestamp(fixture.observed_at),
                report_status: match status {
                    nq_protocol::ReportStatus::Complete => "complete",
                    nq_protocol::ReportStatus::Partial => "partial",
                    nq_protocol::ReportStatus::Failed => "failed",
                }
                .to_owned(),
                canonical_json: canonical,
                semantic_digest: digest,
            }
        };

        let matching = row(
            1,
            "report:owned-boundary",
            watcher,
            nq_protocol::ReportStatus::Partial,
        );
        let unrelated = row(
            2,
            "report:newer-other-boundary",
            &other_boundary,
            nq_protocol::ReportStatus::Complete,
        );
        let owned = evaluation_context_rows(
            &[matching.clone(), unrelated],
            watcher,
            &fixture.profile_digest,
        )
        .expect("select exact evaluation context");
        assert_eq!(owned, vec![matching.clone()]);

        let detector_input = DetectorInput {
            instance_id: &watcher.instance_id,
            evaluated_at: fixture.observed_at,
            watermark: EvidenceWatermark(1),
            reports: &[],
        };
        let result = nq_profiles::DetectorResult::cannot_evaluate(
            &detector_input,
            fixture.descriptor(),
            "the exact evaluation context is partial",
            Vec::new(),
        );
        let refusal = GovernedRefusal::profile(
            "refusal:owned-boundary".to_owned(),
            profile_semantic_id(fixture.profile.descriptor()).expect("profile semantic identity"),
            result.refusal.clone().expect("typed detector refusal"),
        );
        let mut current = fixture.finding.clone();
        current.evidence_json = serde_json::to_string(&vec![PublicEvidenceReference {
            report_id: matching.report_id.clone(),
            semantic_digest: matching.semantic_digest.clone(),
            observation_ordinal: None,
            observed_at: fixture.observed_at,
            received_at: fixture.observed_at,
        }])
        .expect("current evidence JSON");
        let event = build_finding_event(
            watcher,
            fixture.profile,
            fixture.descriptor(),
            &result,
            Some(&refusal),
            fixture.observed_at,
            Some(&current),
            &owned,
        )
        .expect("owned-boundary finding update")
        .expect("existing finding is updated");
        assert_eq!(event.visibility_state, "partial");
        assert_eq!(
            event.freshness.as_bytes(),
            canonical(&json!({
                "state": "partial",
                "observed_at": matching.observed_at,
            }))
            .expect("expected freshness")
            .as_bytes()
        );
        assert_eq!(event.evidence.len(), 1);
        assert_eq!(event.evidence[0].report_id, matching.report_id);
    }

    #[test]
    fn identical_semantic_reports_keep_exact_detector_evidence_identity() {
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host example");
        let watcher = &config.watchers[0];
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        let descriptor = profile.detectors()[0].descriptor();
        let semantic_digest = format!("sha256:{}", "a".repeat(64));
        let profile_digest = profile
            .descriptor()
            .digest()
            .expect("compiled profile digest")
            .as_str()
            .to_owned();
        let observed_at = Utc::now();
        let old_received_at = timestamp(observed_at);
        let new_received_at = timestamp(observed_at + Duration::seconds(1));
        let report_row =
            |report_sequence, report_id: &str, received_at: &str| nq_store::AdmittedReportRow {
                report_sequence,
                report_id: report_id.to_owned(),
                instance_id: watcher.instance_id.clone(),
                profile_id: profile.descriptor().profile.id.clone(),
                profile_version: profile.descriptor().profile.version.to_string(),
                profile_digest: profile_digest.clone(),
                observed_at: timestamp(observed_at),
                received_at: received_at.to_owned(),
                report_status: "complete".to_owned(),
                canonical_json: Vec::new(),
                semantic_digest: semantic_digest.clone(),
            };
        let rows = [
            report_row(1, "report:old", &old_received_at),
            report_row(2, "report:new", &new_received_at),
        ];
        let result = nq_profiles::DetectorResult {
            state: DetectorState::Present,
            condition: descriptor.condition.clone(),
            summary: "host load pressure is present".to_owned(),
            evidence: vec![nq_profiles::DetectorEvidence {
                report_id: "report:new".to_owned(),
                report_sequence: 2,
                report_digest: semantic_digest,
                observation_ordinal: None,
                observed_at,
            }],
            limitations: Vec::new(),
            refusal: None,
            watermark: EvidenceWatermark(2),
        };

        let event = build_finding_event(
            watcher,
            profile,
            descriptor,
            &result,
            None,
            observed_at + Duration::seconds(2),
            None,
            &rows,
        )
        .expect("exact evidence occurrence resolves")
        .expect("present condition opens a finding");
        assert_eq!(event.evidence[0].report_id, "report:new");
        assert_eq!(event.evidence[0].received_at, new_received_at);
        assert_eq!(event.received_at.as_deref(), Some(new_received_at.as_str()));

        let mut mismatched = result;
        mismatched.evidence[0].report_sequence = 1;
        let error = build_finding_event(
            watcher,
            profile,
            descriptor,
            &mismatched,
            None,
            observed_at + Duration::seconds(2),
            None,
            &rows,
        )
        .expect_err("report ID, durable sequence, and semantic digest must agree");
        assert!(error.to_string().contains("unknown report occurrence"));
    }

    #[test]
    fn collection_fails_closed_when_evaluator_identity_is_unresolved() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (config, watcher, _lock) = binding_recovery_fixture(directory.path());
        Store::initialize(&config.database_path).expect("initialize store");

        // An unresolved (unsupported/unverifiable) identity refuses collection
        // before any persistence, carrying the exact structured reason — never a
        // fabricated fallback.
        let mut refusing = CollectionEngine::open_with_evaluator_identity(
            &config,
            Err("evaluator identity is unsupported on this platform (plan9)".to_owned()),
        )
        .expect("engine opens");
        let error = refusing
            .collect(&watcher)
            .expect_err("collection refuses without a resolved evaluator identity");
        assert!(matches!(
            error,
            EngineError::Invariant(message)
                if message.contains("evaluator runtime identity unavailable")
                    && message.contains("plan9")
        ));

        // A resolved identity clears the identity gate; with no active admission
        // the next step is an ordinary admission refusal, proving the gate is
        // what the first engine tripped on, not helper execution.
        let identity = EvaluatorRuntimeIdentity::for_test(
            Sha256Digest::parse(format!("sha256:{}", "a".repeat(64))).expect("digest"),
        );
        let mut ready =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(identity)).expect("engine");
        let outcome = ready
            .collect(&watcher)
            .expect("collection clears the identity gate");
        assert!(matches!(
            outcome.result,
            CollectionResult::AdmissionRefused { .. }
        ));
    }

    #[test]
    fn governed_occurrence_window_requires_one_exact_production_clock() {
        let clock_descriptor = json!({
            "schema": PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA,
            "kind": "clock",
            "id": "lab/clock-realtime",
            "version": "1",
        });
        let clock_descriptor_bytes = nq_protocol::canonical_json_bytes(&clock_descriptor)
            .expect("production clock descriptor");
        let clock = IdentityRef {
            kind: IdentityKind::Clock,
            id: nq_host_role_contract::IdentityId::parse("lab/clock-realtime")
                .expect("clock identity"),
            version: nq_host_role_contract::IdentityVersion::parse("1").expect("clock version"),
            descriptor_digest: nq_protocol::sha256_bytes(&clock_descriptor_bytes),
        };
        let not_before = parse_timestamp("2026-07-29T12:00:00.000Z").expect("not before");
        let launched_at = parse_timestamp("2026-07-29T12:00:01.000Z").expect("launch");
        let attempt_deadline =
            parse_timestamp("2026-07-29T12:00:03.000Z").expect("attempt deadline");
        let request_deadline =
            parse_timestamp("2026-07-29T12:00:04.000Z").expect("request deadline");

        validate_governed_occurrence_window(
            &clock,
            &clock,
            not_before,
            request_deadline,
            launched_at,
            attempt_deadline,
        )
        .expect("one exact clock and ordered occurrence passes");

        let mut substituted_clock = clock.clone();
        substituted_clock.descriptor_digest =
            nq_protocol::sha256_bytes(b"substituted-governed-clock");
        assert!(matches!(
            validate_governed_occurrence_window(
                &clock,
                &substituted_clock,
                not_before,
                request_deadline,
                launched_at,
                attempt_deadline,
            ),
            Err(NativeGovernedPreEffectRefusal {
                code: NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                ..
            })
        ));
        assert!(matches!(
            validate_governed_occurrence_window(
                &clock,
                &clock,
                not_before,
                request_deadline,
                launched_at + Duration::seconds(2),
                attempt_deadline,
            ),
            Err(NativeGovernedPreEffectRefusal {
                code: NativeGovernedPreEffectRefusalCode::DeadlineExpired,
                ..
            })
        ));
        let unordered = validate_governed_occurrence_window(
            &clock,
            &clock,
            not_before,
            request_deadline,
            launched_at,
            launched_at,
        )
        .expect_err("an empty launch interval refuses");
        assert_eq!(
            unordered.code,
            NativeGovernedPreEffectRefusalCode::DeadlineExpired
        );
        assert!(unordered.detail.contains("production clock"));
    }

    #[test]
    fn conformance_pre_effect_access_surface_is_exactly_empty() {
        let empty = json!({
            "privileges": [],
            "namespaces": [],
            "resources": [],
        });
        conformance_attachment_has_zero_access(&empty)
            .expect("empty conformance access declarations pass");
        for field in ["privileges", "namespaces", "resources"] {
            let mut hostile = empty.clone();
            hostile[field] = if field == "resources" {
                json!([{"kind": "socket", "identity": "unexpected"}])
            } else {
                json!(["unexpected"])
            };
            let refusal = conformance_attachment_has_zero_access(&hostile)
                .expect_err("every declared access surface refuses");
            assert_eq!(
                refusal.code,
                NativeGovernedPreEffectRefusalCode::AccessSurfaceNotEmpty
            );
            assert!(refusal.detail.contains(field));
        }
    }

    #[test]
    fn native_acquisition_partition_accepts_exact_capacity_and_refuses_bound_minus_one() {
        let dependency_bytes = 4_096;
        let acquisition_bytes = 8_192;
        require_native_acquisition_partition_capacity(
            dependency_bytes,
            acquisition_bytes,
            dependency_bytes,
            acquisition_bytes,
        )
        .expect("exact partition capacities pass");

        let raw_refusal = require_native_acquisition_partition_capacity(
            dependency_bytes,
            acquisition_bytes - 1,
            dependency_bytes,
            acquisition_bytes,
        )
        .expect_err("raw capacity bound minus one refuses");
        assert_eq!(
            raw_refusal.code,
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable
        );
        assert!(raw_refusal.detail.contains("provider-intake acquisition"));

        let dependency_refusal = require_native_acquisition_partition_capacity(
            dependency_bytes - 1,
            acquisition_bytes,
            dependency_bytes,
            acquisition_bytes,
        )
        .expect_err("dependency capacity bound minus one refuses");
        assert_eq!(
            dependency_refusal.code,
            NativeGovernedPreEffectRefusalCode::NativeCustodyCorrespondenceUnavailable
        );
        assert!(dependency_refusal.detail.contains("dependency closure"));
    }

    #[test]
    fn production_descriptor_identity_does_not_collapse_into_native_binding() {
        let descriptor = json!({
            "schema": PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA,
            "kind": "subject",
            "id": "lab/host-a",
            "version": "1",
        });
        let bytes =
            nq_protocol::canonical_json_bytes(&descriptor).expect("canonical identity descriptor");
        let identity = IdentityRef {
            kind: IdentityKind::Subject,
            id: nq_host_role_contract::IdentityId::parse("lab/host-a").expect("production subject"),
            version: nq_host_role_contract::IdentityVersion::parse("1")
                .expect("descriptor version"),
            descriptor_digest: nq_protocol::sha256_bytes(&bytes),
        };
        validate_descriptor_catalog_uniqueness(
            std::slice::from_ref(&identity),
            &identity,
            "subject",
        )
        .expect("one exact production key");
        validate_production_identity_descriptor_bytes(&identity, &bytes, "subject")
            .expect("exact descriptor preimage");

        let alias = IdentityRef {
            id: nq_host_role_contract::IdentityId::parse("lab/host-b").expect("hostile alias key"),
            ..identity.clone()
        };
        let refusal = validate_descriptor_catalog_uniqueness(
            &[identity.clone(), alias],
            &identity,
            "subject",
        )
        .expect_err("one descriptor digest cannot identify two production keys");
        assert_eq!(
            refusal.code,
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable
        );
        assert!(refusal.detail.contains("2 production identity keys"));

        let mut substituted = descriptor;
        substituted["id"] = json!("lab/host-b");
        let substituted_bytes =
            nq_protocol::canonical_json_bytes(&substituted).expect("hostile descriptor");
        assert_eq!(
            validate_production_identity_descriptor_bytes(
                &identity,
                &substituted_bytes,
                "subject",
            )
            .expect_err("descriptor substitution refuses")
            .code,
            NativeGovernedPreEffectRefusalCode::ProductionDescriptorCorrespondenceUnavailable
        );

        // Production identity and native helper bindings are deliberately
        // representation-different. Their correspondence is the authenticated
        // activation -> attachment -> provider-admission relation, not string
        // equality.
        assert_ne!(identity.id.as_str(), "conformance:recovery");
    }

    #[test]
    fn native_profile_mapping_preserves_distinct_descriptor_layers() {
        let directory = tempfile::tempdir().expect("profile correspondence fixture");
        let (_config, _watcher, active_lock) = binding_recovery_fixture(directory.path());
        let profile_descriptor = json!({
            "schema": PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA,
            "kind": "diagnostic_profile",
            "id": "nq.conformance",
            "version": "1",
        });
        let profile_bytes = nq_protocol::canonical_json_bytes(&profile_descriptor)
            .expect("production profile descriptor");
        let production_profile = IdentityRef {
            kind: IdentityKind::DiagnosticProfile,
            id: nq_host_role_contract::IdentityId::parse("nq.conformance")
                .expect("production profile"),
            version: nq_host_role_contract::IdentityVersion::parse("1").expect("profile version"),
            descriptor_digest: nq_protocol::sha256_bytes(&profile_bytes),
        };
        let admission_digest = nq_protocol::sha256_bytes(b"local-provider-admission");
        let provider_admission = RecordRef {
            schema: nq_host_role_contract::Token::parse(nq_store::LOCAL_PROVIDER_ADMISSION_SCHEMA)
                .expect("provider admission schema"),
            record_id: admission_digest.clone(),
            bytes_digest: admission_digest,
        };
        let compiled: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        validate_native_profile_correspondence(
            &production_profile,
            &provider_admission,
            &active_lock,
            compiled,
        )
        .expect("Q -> exact R.profile -> compiled S id/version mapping");
        assert_ne!(
            production_profile.descriptor_digest.as_str(),
            compiled
                .descriptor()
                .digest()
                .expect("native compiled descriptor digest")
                .as_str(),
            "production descriptor identity remains distinct from native profile identity"
        );
        let mut hostile_profile = production_profile.clone();
        hostile_profile.id =
            nq_host_role_contract::IdentityId::parse("nq.other").expect("hostile profile");
        assert_eq!(
            validate_native_profile_correspondence(
                &hostile_profile,
                &provider_admission,
                &active_lock,
                compiled,
            )
            .expect_err("different production profile key refuses")
            .code,
            NativeGovernedPreEffectRefusalCode::NativeProfileCorrespondenceUnavailable
        );
    }

    #[test]
    fn conformance_pre_effect_request_binds_subject_scope_nonce_and_local_vantage() {
        let directory = tempfile::tempdir().expect("conformance request fixture");
        let (_config, watcher, _lock) = binding_recovery_fixture(directory.path());
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let outer_request_id = "outer-request-native-conformance";
        let launch_digest = nq_protocol::sha256_bytes(b"governed-native-launch");
        let execution_launch = RecordRef {
            schema: nq_host_role_contract::Token::parse(RuntimeSchema::ExecutionLaunchV1.as_str())
                .expect("execution launch schema"),
            record_id: launch_digest.clone(),
            bytes_digest: launch_digest,
        };
        let child_request_id = native_child_request_id(outer_request_id, &execution_launch)
            .expect("derived child request identity");
        assert_ne!(child_request_id.as_str(), outer_request_id);
        assert_eq!(
            child_request_id,
            native_child_request_id(outer_request_id, &execution_launch)
                .expect("deterministic child request identity")
        );
        let request = exact_conformance_native_request(
            &watcher,
            profile,
            child_request_id.clone(),
            42_000_000_000,
        )
        .expect("exact conformance request");
        assert_eq!(request.request_id, child_request_id);
        assert_eq!(request.binding.subject.as_str(), "conformance:recovery");
        assert_eq!(request.binding.scope.kind.as_str(), "fixture");
        assert_eq!(
            request.binding.scope.value,
            json!({"id": "recovery", "nonce": "test"})
        );
        assert_eq!(request.binding.vantage.kind.as_str(), "local");
        assert_eq!(request.binding.vantage.value, json!({}));
        assert!(request.granted_capabilities.is_empty());
        assert!(request.checkpoint.is_none());

        let mut nonce_substitution = watcher.clone();
        nonce_substitution.scope.value = json!({"id": "recovery", "nonce": ""});
        let refusal = exact_conformance_native_request(
            &nonce_substitution,
            profile,
            native_child_request_id(outer_request_id, &execution_launch)
                .expect("derived child request identity"),
            42_000_000_000,
        )
        .expect_err("empty nonce refuses before any provider effect");
        assert_eq!(
            refusal.code,
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch
        );
        assert!(refusal.detail.contains("subject/scope/nonce/vantage"));

        let mut vantage_substitution = watcher;
        vantage_substitution.vantage.value = json!({"namespace": "host"});
        assert_eq!(
            exact_conformance_native_request(
                &vantage_substitution,
                profile,
                native_child_request_id(outer_request_id, &execution_launch)
                    .expect("derived child request identity"),
                42_000_000_000,
            )
            .expect_err("nonempty local vantage refuses")
            .code,
            NativeGovernedPreEffectRefusalCode::NativeBindingMismatch
        );
    }

    #[test]
    fn governed_provider_admission_requires_exact_nq_derived_carrier() {
        let contract = CanonicalDocument::from_serializable(&json!({
            "schema": nq_store::LOCAL_PROVIDER_ADMISSION_SCHEMA,
            "source_admission_id": "admission:source",
        }))
        .expect("canonical provider admission");
        let provider_admission_id =
            Sha256Digest::parse(contract.digest().to_owned()).expect("provider admission digest");
        let row = nq_store::LocalProviderAdmissionRow {
            provider_admission_id: provider_admission_id.to_string(),
            source_admission_id: "admission:source".to_owned(),
            provider_semantic_id: "provider:semantic".to_owned(),
            provider_artifact_digest: nq_protocol::sha256_bytes(b"provider-artifact").to_string(),
            provider_protocol_identity: "nq.helper_protocol.v1".to_owned(),
            provider_config_digest: nq_protocol::sha256_bytes(b"provider-config").to_string(),
            contract_json: contract.as_bytes().to_vec(),
            contract_digest: provider_admission_id.to_string(),
            source_admitted_at: "2026-07-29T12:00:00.000Z".to_owned(),
            derived_at: "2026-07-29T12:00:01.000Z".to_owned(),
            derivation_kind: "nq_local_helper_provider".to_owned(),
        };
        let reference = RecordRef {
            schema: nq_host_role_contract::Token::parse(nq_store::LOCAL_PROVIDER_ADMISSION_SCHEMA)
                .expect("provider admission schema"),
            record_id: provider_admission_id.clone(),
            bytes_digest: provider_admission_id.clone(),
        };

        validate_exact_provider_admission(&reference, &row, &provider_admission_id)
            .expect("exact NQ provider admission passes");

        assert!(matches!(
            validate_exact_provider_admission(
                &reference,
                &row,
                &nq_protocol::sha256_bytes(b"other-provider-admission"),
            ),
            Err(NativeGovernedPreEffectRefusal {
                code: NativeGovernedPreEffectRefusalCode::ProviderAdmissionMismatch,
                ..
            })
        ));
        let mut substituted_reference = reference;
        substituted_reference.record_id = nq_protocol::sha256_bytes(b"substituted-provider-record");
        assert!(matches!(
            validate_exact_provider_admission(&substituted_reference, &row, &provider_admission_id,),
            Err(NativeGovernedPreEffectRefusal {
                code: NativeGovernedPreEffectRefusalCode::ProviderAdmissionMismatch,
                ..
            })
        ));
    }

    #[test]
    fn governed_run_level_history_accepts_only_exact_zero_evaluation_origin_shape() {
        let mut artifact = DiagnosticExecutionV2::decode_canonical(include_bytes!(
            "../../../diagnostic-contract-v2/fixtures/valid/completed_unqualified_clock.json"
        ))
        .expect("checked V2 fixture");
        assert_ne!(
            artifact.profile.id,
            nq_profiles::conformance::PROFILE_ID,
            "the production diagnostic profile remains distinct from the native child profile"
        );
        artifact.profile_semantic_id = Sha256Digest::parse(
            profile_semantic_id(nq_profiles::conformance::MODULE.descriptor())
                .expect("canonical conformance semantic identity")
                .as_str()
                .to_owned(),
        )
        .expect("canonical conformance semantic digest");

        validate_governed_run_level_v2_origin_shape(&artifact, None)
            .expect("exact governed run-level origin accepts zero evaluations");

        assert!(matches!(
            validate_governed_run_level_v2_origin_shape(
                &artifact,
                Some("evaluation:near-miss"),
            ),
            Err(EngineError::Invariant(message))
                if message.contains("claims a detector evaluation")
        ));

        artifact.profile_semantic_id = Sha256Digest::parse(format!("sha256:{}", "f".repeat(64)))
            .expect("near-miss semantic identity");
        assert!(matches!(
            validate_governed_run_level_v2_origin_shape(&artifact, None),
            Err(EngineError::Invariant(message))
                if message.contains("not bound to canonical nq.conformance/v1 semantics")
        ));
    }

    #[test]
    fn governed_history_requires_exact_derived_native_child_request() {
        let launch_digest = nq_protocol::sha256_bytes(b"historical-governed-launch");
        let launch = RecordRef {
            schema: nq_host_role_contract::Token::parse(RuntimeSchema::ExecutionLaunchV1.as_str())
                .expect("execution launch schema"),
            record_id: launch_digest.clone(),
            bytes_digest: launch_digest,
        };
        let outer_request_id = "outer-request-history-exact";
        let child = native_child_request_id(outer_request_id, &launch)
            .expect("deterministic native child request");

        validate_governed_native_request_correspondence(
            "sha256:artifact",
            outer_request_id,
            &launch,
            child.as_str(),
            child.as_str(),
        )
        .expect("exact provider and run child request correspondence");

        assert!(matches!(
            validate_governed_native_request_correspondence(
                "sha256:artifact",
                outer_request_id,
                &launch,
                "nq-provider-substituted",
                child.as_str(),
            ),
            Err(EngineError::Invariant(message))
                if message.contains("substitutes its exact native child request")
        ));
        assert!(matches!(
            validate_governed_native_request_correspondence(
                "sha256:artifact",
                outer_request_id,
                &launch,
                child.as_str(),
                "nq-provider-substituted",
            ),
            Err(EngineError::Invariant(message))
                if message.contains("substitutes its exact native child request")
        ));
    }

    #[test]
    fn governed_history_binds_provider_deadline_to_exact_launch_instant() {
        let provider_deadline = DateTime::parse_from_rfc3339("2026-07-29T14:00:00.123456789Z")
            .expect("provider deadline")
            .with_timezone(&Utc);

        validate_governed_attempt_deadline_correspondence(
            "sha256:artifact",
            provider_deadline,
            "2026-07-29T10:00:00.123456789-04:00",
        )
        .expect("different RFC 3339 rendering of the exact instant passes");

        for substituted in [
            "2026-07-29T14:00:00.123456788Z",
            "2026-07-29T14:00:00.123456790Z",
        ] {
            assert!(matches!(
                validate_governed_attempt_deadline_correspondence(
                    "sha256:artifact",
                    provider_deadline,
                    substituted,
                ),
                Err(EngineError::Invariant(message))
                    if message.contains("substitutes its exact launch attempt deadline")
            ));
        }
        assert!(matches!(
            validate_governed_attempt_deadline_correspondence(
                "sha256:artifact",
                provider_deadline,
                "not-an-instant",
            ),
            Err(EngineError::Invariant(message))
                if message.contains("is not an RFC 3339 instant")
        ));
    }

    #[test]
    fn historical_runtime_snapshot_is_checkpoint_exact_and_never_latest() {
        fn input(value: &Value) -> nq_store::RuntimeRecordInput {
            let validated = ValidatedRuntimeRecord::validate_value(value.clone())
                .expect("ratified specimen record validates");
            nq_store::RuntimeRecordInput {
                record_id: validated.record_id().to_string(),
                record_schema: validated.schema().as_str().to_owned(),
                canonical_bytes: CanonicalDocument::from_canonical_bytes(
                    validated.canonical_bytes().to_vec(),
                )
                .expect("ratified specimen bytes remain canonical"),
                committed_at: "2026-07-29T14:00:00Z".to_owned(),
            }
        }

        let specimen: Value = serde_json::from_slice(
            nq_host_role_contract::verified_corrected_specimen()
                .expect("verified embedded ratified specimen"),
        )
        .expect("embedded ratified specimen");
        let records = specimen["records"]
            .as_object()
            .expect("ratified specimen records");
        let first = input(&records["role_manifest"]);
        let later = input(&records["cohort_manifest"]);
        let first_id = Sha256Digest::parse(first.record_id.clone()).expect("first record digest");
        let later_id = Sha256Digest::parse(later.record_id.clone()).expect("later record digest");
        let first_checkpoint_id =
            nq_protocol::sha256_bytes(b"history-exact-checkpoint").to_string();
        let later_checkpoint_id =
            nq_protocol::sha256_bytes(b"history-latest-checkpoint").to_string();
        let directory = tempfile::tempdir().expect("store directory");
        let mut store =
            Store::initialize(directory.path().join("nq.db")).expect("runtime history store");
        let dependency = test_runtime_dependency("history-exact-checkpoint");
        store
            .begin_writer_session()
            .expect("writer session")
            .establish_runtime_dependency_trust_root(&dependency.trust_anchor_id)
            .expect("establish test runtime dependency root");
        let first_checkpoint = store
            .begin_writer_session()
            .expect("writer session")
            .append_runtime_records(&nq_store::RuntimeRecordBatchInput {
                checkpoint_id: first_checkpoint_id.clone(),
                expected_predecessor_checkpoint_id: None,
                expected_predecessor_ledger_root: None,
                dependency: dependency.clone(),
                records: vec![first],
            })
            .expect("append first exact runtime checkpoint");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_runtime_records(&nq_store::RuntimeRecordBatchInput {
                checkpoint_id: later_checkpoint_id,
                expected_predecessor_checkpoint_id: Some(first_checkpoint.checkpoint.checkpoint_id),
                expected_predecessor_ledger_root: Some(
                    first_checkpoint.checkpoint.checkpoint_ledger_root,
                ),
                dependency,
                records: vec![later],
            })
            .expect("append later runtime checkpoint");

        let exact = store
            .runtime_checkpoint_by_id(&first_checkpoint_id)
            .expect("exact historical checkpoint lookup")
            .expect("first checkpoint remains available");
        let snapshot = reopen_historical_runtime_snapshot(&store, &exact)
            .expect("exact historical runtime snapshot");
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.get(&first_id).is_some());
        assert!(
            snapshot.get(&later_id).is_none(),
            "later current topology cannot fall into the historical snapshot"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn production_history_uses_exact_execution_binding_not_current_topology() {
        fn digest(byte: char) -> String {
            format!("sha256:{}", byte.to_string().repeat(64))
        }

        fn identity(kind: &str, value: &SemanticIdentityV1) -> Value {
            json!({
                "kind": kind,
                "id": value.id,
                "version": value.version,
                "descriptor_digest": value.digest,
            })
        }

        fn runtime_input(
            record_id: &str,
            record_schema: &str,
            value: &Value,
        ) -> nq_store::RuntimeRecordInput {
            nq_store::RuntimeRecordInput {
                record_id: record_id.to_owned(),
                record_schema: record_schema.to_owned(),
                canonical_bytes: canonical(value).expect("canonical runtime fixture"),
                committed_at: "2026-07-29T14:00:00Z".to_owned(),
            }
        }

        fn reference(record: &nq_store::RuntimeRecordInput) -> Value {
            json!({
                "schema": record.record_schema,
                "record_id": record.record_id,
                "bytes_digest": record.canonical_bytes.digest(),
            })
        }

        fn runtime_row(store: &Store, record_id: &str) -> nq_store::RuntimeRecordRow {
            store
                .runtime_record(record_id)
                .expect("runtime lookup")
                .expect("runtime row")
        }

        let mut artifact = DiagnosticExecutionV2::decode_canonical(include_bytes!(
            "../../../diagnostic-contract-v2/fixtures/valid/completed_unqualified_clock.json"
        ))
        .expect("checked V2 fixture");
        let node = SemanticIdentityV1 {
            id: "lab/node-history".to_owned(),
            version: "1".to_owned(),
            digest: Sha256Digest::parse(digest('1')).expect("node digest"),
        };
        let subject = SemanticIdentityV1 {
            id: "lab/subject-history".to_owned(),
            version: "1".to_owned(),
            digest: Sha256Digest::parse(digest('2')).expect("subject digest"),
        };
        let scope = SemanticIdentityV1 {
            id: "host".to_owned(),
            version: "1".to_owned(),
            digest: Sha256Digest::parse(digest('3')).expect("scope digest"),
        };
        let vantage = SemanticIdentityV1 {
            id: "lab/subject-history/host-local".to_owned(),
            version: "7".to_owned(),
            digest: Sha256Digest::parse(digest('4')).expect("vantage digest"),
        };
        let cohort = SemanticIdentityV1 {
            id: "generic-host/profiles".to_owned(),
            version: "11".to_owned(),
            digest: Sha256Digest::parse(digest('5')).expect("cohort digest"),
        };
        let role_identity = SemanticIdentityV1 {
            id: "generic-host".to_owned(),
            version: "3".to_owned(),
            digest: nq_protocol::sha256_bytes(b"generic-host-role"),
        };
        let platform = SemanticIdentityV1 {
            id: "ubuntu/24.04/amd64".to_owned(),
            version: "1".to_owned(),
            digest: nq_protocol::sha256_bytes(b"ubuntu-platform"),
        };
        artifact.producer.node_id.clone_from(&node.id);
        artifact.producer.cohort = cohort.clone();
        artifact.subject.id.clone_from(&subject.id);
        artifact.vantage = vantage.clone();
        artifact.request_id = DiagnosticRequestId("outer-request-history-001".to_owned());
        artifact.artifact_id = artifact
            .computed_artifact_id()
            .expect("production artifact ID");
        artifact
            .canonical_bytes()
            .expect("mutated production artifact remains canonical");

        let role_id = digest('6');
        let activation_id = digest('7');
        let request_record_id = digest('8');
        let decision_id = digest('9');
        let launch_id = digest('a');
        let binding_id = digest('b');
        let node_subject_id =
            nq_protocol::sha256_bytes(b"history-node-subject-relation").into_string();
        let subject_platform_id =
            nq_protocol::sha256_bytes(b"history-subject-platform-relation").into_string();
        let node_vantage_id =
            nq_protocol::sha256_bytes(b"history-node-vantage-relation").into_string();
        let node_role_id = nq_protocol::sha256_bytes(b"history-node-role-relation").into_string();
        let node_cohort_id =
            nq_protocol::sha256_bytes(b"history-node-cohort-relation").into_string();
        let role = runtime_input(
            &role_id,
            "nq.role_manifest.v1",
            &json!({
                "schema": "nq.role_manifest.v1",
                "subject_scope_classes": [identity("scope", &scope)],
            }),
        );
        let node_subject = runtime_input(
            &node_subject_id,
            "nq.host_role_relation.v1",
            &json!({
                "schema": "nq.host_role_relation.v1",
                "relation_id": node_subject_id,
                "relation_kind": "node_subject",
                "left": identity("nq_node", &node),
                "right": identity("subject", &subject),
            }),
        );
        let subject_platform = runtime_input(
            &subject_platform_id,
            "nq.host_role_relation.v1",
            &json!({
                "schema": "nq.host_role_relation.v1",
                "relation_id": subject_platform_id,
                "relation_kind": "subject_platform",
                "left": identity("subject", &subject),
                "right": identity("platform", &platform),
            }),
        );
        let node_vantage = runtime_input(
            &node_vantage_id,
            "nq.host_role_relation.v1",
            &json!({
                "schema": "nq.host_role_relation.v1",
                "relation_id": node_vantage_id,
                "relation_kind": "node_vantage",
                "left": identity("nq_node", &node),
                "right": identity("vantage", &vantage),
            }),
        );
        let node_role = runtime_input(
            &node_role_id,
            "nq.host_role_relation.v1",
            &json!({
                "schema": "nq.host_role_relation.v1",
                "relation_id": node_role_id,
                "relation_kind": "node_role",
                "left": identity("nq_node", &node),
                "right": identity("role", &role_identity),
            }),
        );
        let node_cohort = runtime_input(
            &node_cohort_id,
            "nq.host_role_relation.v1",
            &json!({
                "schema": "nq.host_role_relation.v1",
                "relation_id": node_cohort_id,
                "relation_kind": "node_static_profile_cohort",
                "left": identity("nq_node", &node),
                "right": identity("static_cohort", &cohort),
            }),
        );
        let exact_relations = json!({
            "node_subject": reference(&node_subject),
            "subject_platform": reference(&subject_platform),
            "node_vantage": reference(&node_vantage),
            "node_role": reference(&node_role),
            "node_static_profile_cohort": reference(&node_cohort),
        });
        let activation = runtime_input(
            &activation_id,
            "nq.runtime_activation.v1",
            &json!({
                "schema": "nq.runtime_activation.v1",
                "node": identity("nq_node", &node),
                "role": identity("role", &role_identity),
                "static_profile_cohort": identity("static_cohort", &cohort),
                "relations": exact_relations.clone(),
                "role_scope": scope.id,
            }),
        );
        let request = runtime_input(
            &request_record_id,
            "nq.diagnostic_invocation_request.v1",
            &json!({
                "schema": "nq.diagnostic_invocation_request.v1",
                "request_id": artifact.request_id,
                "request_digest": request_record_id,
                "target": {
                    "node": identity("nq_node", &node),
                    "subject": identity("subject", &subject),
                    "vantage": identity("vantage", &vantage),
                },
                "profile": identity("diagnostic_profile", &artifact.profile),
            }),
        );
        let decision = runtime_input(
            &decision_id,
            "nq.invocation_decision.v1",
            &json!({
                "schema": "nq.invocation_decision.v1",
                "decision": "accepted",
                "request_digest": request_record_id,
                "request": reference(&request),
            }),
        );
        let launch = runtime_input(
            &launch_id,
            "nq.execution_launch.v1",
            &json!({
                "schema": "nq.execution_launch.v1",
                "status": "launched",
                "outer_request": reference(&request),
                "invocation_decision": reference(&decision),
            }),
        );
        let resolved = json!({
            "node": {"identity": identity("nq_node", &node)},
            "subject": {"identity": identity("subject", &subject)},
            "vantage": {"identity": identity("vantage", &vantage)},
            "static_profile_cohort": {"identity": identity("static_cohort", &cohort)},
            "role": {"identity": identity("role", &role_identity)},
            "platform": {"identity": identity("platform", &platform)},
            "diagnostic_profile": {
                "identity": identity("diagnostic_profile", &artifact.profile)
            },
        });
        let binding_record = runtime_input(
            &binding_id,
            "nq.execution_identity_binding.v2",
            &json!({
                "schema": "nq.execution_identity_binding.v2",
                "binding_id": binding_id,
                "binding_result": "resolved",
                "outer_request": reference(&request),
                "invocation_decision": reference(&decision),
                "execution_launch": reference(&launch),
                "activation": reference(&activation),
                "role_manifest": reference(&role),
                "source_relations": exact_relations.clone(),
                "resolved_references": resolved,
            }),
        );
        let directory = tempfile::tempdir().expect("store directory");
        let mut store =
            Store::initialize(directory.path().join("nq.db")).expect("runtime history store");
        let runtime_dependency = test_runtime_dependency("production-history");
        store
            .begin_writer_session()
            .expect("writer session")
            .establish_runtime_dependency_trust_root(&runtime_dependency.trust_anchor_id)
            .expect("establish test runtime dependency root");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_runtime_records(&nq_store::RuntimeRecordBatchInput {
                checkpoint_id: digest('c'),
                expected_predecessor_checkpoint_id: None,
                expected_predecessor_ledger_root: None,
                dependency: runtime_dependency.clone(),
                records: vec![
                    role.clone(),
                    node_subject.clone(),
                    subject_platform.clone(),
                    node_vantage.clone(),
                    node_role.clone(),
                    node_cohort.clone(),
                    activation.clone(),
                    request.clone(),
                    decision.clone(),
                    launch.clone(),
                    binding_record.clone(),
                ],
            })
            .expect("append exact production history");
        let exact_binding = nq_store::DiagnosticArtifactExecutionBinding {
            execution_binding: runtime_row(&store, &binding_id),
            outer_request: runtime_row(&store, &request_record_id),
            invocation_decision: runtime_row(&store, &decision_id),
            execution_launch: runtime_row(&store, &launch_id),
            outer_request_id: artifact.request_id.0.clone(),
            provider_attempts: Vec::new(),
        };
        validate_production_v2_execution_binding(&store, &artifact, &exact_binding)
            .expect("exact historical production binding verifies");

        let substituted_request_id = digest('d');
        let substituted_request = runtime_input(
            &substituted_request_id,
            "nq.diagnostic_invocation_request.v1",
            &json!({
                "schema": "nq.diagnostic_invocation_request.v1",
                "request_id": "outer-request-substituted",
                "request_digest": substituted_request_id,
                "target": {
                    "node": identity("nq_node", &node),
                    "subject": identity("subject", &subject),
                    "vantage": identity("vantage", &vantage),
                },
                "profile": identity("diagnostic_profile", &artifact.profile),
            }),
        );
        let later_vantage = SemanticIdentityV1 {
            id: "lab/subject-history/rehome".to_owned(),
            version: "2".to_owned(),
            digest: Sha256Digest::parse(digest('e')).expect("later vantage digest"),
        };
        let later_vantage_relation_id =
            nq_protocol::sha256_bytes(b"later-node-vantage-relation").into_string();
        let later_vantage_relation = runtime_input(
            &later_vantage_relation_id,
            "nq.host_role_relation.v1",
            &json!({
                "schema": "nq.host_role_relation.v1",
                "relation_id": later_vantage_relation_id,
                "relation_kind": "node_vantage",
                "left": identity("nq_node", &node),
                "right": identity("vantage", &later_vantage),
            }),
        );
        let mut later_relations = exact_relations.clone();
        later_relations["node_vantage"] = reference(&later_vantage_relation);
        let later_activation = runtime_input(
            &digest('f'),
            "nq.runtime_activation.v1",
            &json!({
                "schema": "nq.runtime_activation.v1",
                "node": identity("nq_node", &node),
                "role": identity("role", &role_identity),
                "static_profile_cohort": identity("static_cohort", &cohort),
                "relations": later_relations,
                "role_scope": scope.id,
            }),
        );
        let first_frontier = store
            .runtime_ledger_checkpoint()
            .expect("runtime frontier")
            .expect("nonempty runtime frontier");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_runtime_records(&nq_store::RuntimeRecordBatchInput {
                checkpoint_id: digest('0'),
                expected_predecessor_checkpoint_id: Some(first_frontier.checkpoint_id),
                expected_predecessor_ledger_root: Some(first_frontier.checkpoint_ledger_root),
                dependency: runtime_dependency.clone(),
                records: vec![
                    substituted_request,
                    later_vantage_relation,
                    later_activation,
                ],
            })
            .expect("append later topology and hostile request");

        let mut hostile_outer = exact_binding.clone();
        hostile_outer.outer_request = runtime_row(&store, &substituted_request_id);
        hostile_outer.outer_request_id = "outer-request-substituted".to_owned();
        assert!(matches!(
            validate_production_v2_execution_binding(&store, &artifact, &hostile_outer),
            Err(EngineError::Invariant(message))
                if message.contains("outer request linkage")
        ));

        let hostile_binding_id = digest('4');
        let hostile_binding_record = runtime_input(
            &hostile_binding_id,
            "nq.execution_identity_binding.v2",
            &json!({
                "schema": "nq.execution_identity_binding.v2",
                "binding_id": hostile_binding_id,
                "binding_result": "resolved",
                "outer_request": reference(&request),
                "invocation_decision": reference(&decision),
                "execution_launch": reference(&launch),
                "activation": reference(&activation),
                "role_manifest": reference(&role),
                "source_relations": exact_relations,
                "resolved_references": {
                    "node": {"identity": identity("nq_node", &node)},
                    "subject": {"identity": identity("subject", &subject)},
                    "vantage": {"identity": identity("vantage", &later_vantage)},
                    "static_profile_cohort": {
                        "identity": identity("static_cohort", &cohort)
                    },
                    "role": {"identity": identity("role", &role_identity)},
                    "platform": {"identity": identity("platform", &platform)},
                    "diagnostic_profile": {
                        "identity": identity("diagnostic_profile", &artifact.profile)
                    },
                },
            }),
        );
        let frontier = store
            .runtime_ledger_checkpoint()
            .expect("hostile binding frontier")
            .expect("nonempty frontier");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_runtime_records(&nq_store::RuntimeRecordBatchInput {
                checkpoint_id: digest('5'),
                expected_predecessor_checkpoint_id: Some(frontier.checkpoint_id),
                expected_predecessor_ledger_root: Some(frontier.checkpoint_ledger_root),
                dependency: runtime_dependency,
                records: vec![hostile_binding_record],
            })
            .expect("append hostile binding");
        let mut hostile_linkage = exact_binding.clone();
        hostile_linkage.execution_binding = runtime_row(&store, &hostile_binding_id);
        assert!(matches!(
            validate_production_v2_execution_binding(&store, &artifact, &hostile_linkage),
            Err(EngineError::Invariant(message))
                if message.contains("resolved node, subject, vantage, cohort, or profile")
        ));

        validate_production_v2_execution_binding(&store, &artifact, &exact_binding)
            .expect("later topology cannot reinterpret the exact historical binding");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn diagnostic_execute_emits_exact_artifact_from_committed_host_evaluation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (config, watcher, _mode) = host_diagnostic_fixture(directory.path());
        let mut store = Store::initialize(&config.database_path).expect("initialize store");
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            resolve(&watcher).expect("host profile"),
        )
        .expect("profile descriptor");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_genesis(&GenesisInput {
                genesis_id: "diagnostic-test-genesis".to_owned(),
                legacy_manifest_digest: None,
                created_at: "2026-07-28T12:00:00.000Z".to_owned(),
                detail: canonical(&json!({"source": "diagnostic-execution-test"}))
                    .expect("genesis detail"),
            })
            .expect("append genesis");
        drop(store);

        let evaluator = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(
            b"diagnostic-execution-test-evaluator",
        ));
        let mut engine =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(evaluator)).expect("engine");
        if let Err(error) = engine.watcher_action(&watcher, "admit") {
            if error.to_string().contains("\"class\":\"spawn_failed\"")
                && fs::read_to_string("/proc/self/attr/current")
                    .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
            {
                eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
                return;
            }
            panic!("fixture admission failed: {error}");
        }

        let emitted = engine
            .diagnostic_execute(&watcher)
            .expect("admitted host execution emits a diagnostic");
        let SupportedDiagnosticExecution::V2(artifact) = emitted else {
            panic!("new live diagnostic executions use the v2 contract");
        };
        artifact.validate().expect("live artifact validates");
        assert_eq!(artifact.schema, DiagnosticExecutionSchemaV2::V2);
        assert_eq!(artifact.subject.id, watcher.subject);
        assert_eq!(artifact.profile.id, nq_profiles::host::PROFILE_ID);
        assert_eq!(artifact.question.id, "nq.host.load_pressure");
        assert_eq!(
            artifact.outcome.derivation,
            DiagnosticDerivationV1::Completed
        );
        assert_eq!(
            artifact.outcome.condition,
            DiagnosticConditionV1::ExplicitlyAbsent
        );
        assert_eq!(artifact.outcome.coverage, DiagnosticCoverageV1::Complete);
        assert_eq!(
            artifact.outcome.coherence,
            DiagnosticCoherenceV1::JointlyEstablished
        );
        assert_eq!(artifact.inputs.expected.len(), 1);
        assert_eq!(artifact.inputs.received.len(), 1);
        assert_eq!(artifact.inputs.admitted.len(), 1);
        assert_eq!(artifact.inputs.selected.len(), 1);
        assert!(artifact.inputs.refused.is_empty());
        assert!(artifact.inputs.failed.is_empty());
        assert!(artifact.inputs.excluded.is_empty());
        assert_eq!(artifact.state_bindings.len(), 1);
        assert_eq!(
            artifact.producer.node_id,
            "nq-store-genesis:diagnostic-test-genesis"
        );

        let original = artifact.canonical_bytes().expect("canonical live bytes");
        let reopened =
            DiagnosticExecutionV2::decode_canonical(&original).expect("exact live bytes reopen");
        assert_eq!(
            reopened
                .canonical_bytes()
                .expect("reopened canonical bytes"),
            original
        );
        let stored_artifact_id = engine
            .store
            .diagnostic_artifact_id_for_run(artifact.run_id.as_str())
            .expect("artifact index lookup")
            .expect("local diagnostic artifact was committed");
        assert_eq!(stored_artifact_id, artifact.artifact_id.0);
        assert_eq!(
            reopen_diagnostic_artifact(&engine.store, &stored_artifact_id)
                .expect("strict durable artifact reopening")
                .canonical_bytes()
                .expect("durable artifact bytes"),
            original
        );
        validate_diagnostic_artifact_history(&mut engine.store)
            .expect("evaluated diagnostic history preserves exact semantics");

        let intakes = engine
            .store
            .provider_intakes_bounded(10, None)
            .expect("provider intake history");
        assert_eq!(intakes.len(), 1);
        let raw = engine
            .store
            .provider_intake_raw_bytes(&intakes[0].intake_id)
            .expect("raw custody lookup")
            .expect("exact response retained");
        assert_eq!(
            artifact.inputs.received[0].raw_artifact_id.0,
            nq_protocol::sha256_bytes(&raw)
        );
        let runs = engine
            .store
            .watcher_run_outcomes_bounded(10, None)
            .expect("watcher run history");
        let [run] = runs.as_slice() else {
            panic!("exactly one watcher run");
        };
        let supported = SupportedDiagnosticExecution::V2(artifact.clone());
        validate_local_v2_provider_correspondence(&engine.store, &supported, run, None)
            .expect("native run, intake, time, and artifact correspondence passes");

        let mut substituted_run = run.clone();
        substituted_run.run_id = "run:substituted".to_owned();
        assert!(matches!(
            validate_local_v2_provider_correspondence(
                &engine.store,
                &supported,
                &substituted_run,
                None,
            ),
            Err(EngineError::Invariant(message))
                if message.contains("substitutes provider-intake origin identity")
        ));

        let mut substituted_intake = artifact.clone();
        substituted_intake.inputs.received[0].provider_intake_id = "intake:substituted".to_owned();
        assert!(matches!(
            validate_local_v2_provider_correspondence(
                &engine.store,
                &SupportedDiagnosticExecution::V2(substituted_intake),
                run,
                None,
            ),
            Err(EngineError::Invariant(message))
                if message.contains("references missing provider intake")
        ));

        let mut backdated = artifact.clone();
        backdated.started_at -= Duration::milliseconds(1);
        assert!(matches!(
            validate_local_v2_provider_correspondence(
                &engine.store,
                &SupportedDiagnosticExecution::V2(backdated),
                run,
                None,
            ),
            Err(EngineError::Invariant(message))
                if message.contains("substitutes provider attempt timing")
        ));

        let error = engine
            .diagnostic_execute(&watcher)
            .expect_err("history-aware input accounting is not silently fabricated");
        assert!(
            error
                .to_string()
                .contains("requires a fresh instance with no prior matching history")
        );
        assert_eq!(
            engine
                .store
                .provider_intakes_bounded(10, None)
                .expect("rolled-back intake history")
                .len(),
            1,
            "the refused second emission leaves no partial collection behind"
        );
        drop(engine);
        let reopened_store =
            Store::open_read_only(&config.database_path).expect("store reopens after restart");
        assert_eq!(
            reopen_diagnostic_artifact(&reopened_store, &stored_artifact_id)
                .expect("artifact survives process restart")
                .canonical_bytes()
                .expect("restart artifact bytes"),
            original
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn diagnostic_execute_preserves_a_live_detector_refusal() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (config, watcher, mode) = host_diagnostic_fixture(directory.path());
        let mut store = Store::initialize(&config.database_path).expect("initialize store");
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            resolve(&watcher).expect("host profile"),
        )
        .expect("profile descriptor");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_genesis(&GenesisInput {
                genesis_id: "diagnostic-refusal-test-genesis".to_owned(),
                legacy_manifest_digest: None,
                created_at: "2026-07-28T12:00:00.000Z".to_owned(),
                detail: canonical(&json!({"source": "diagnostic-refusal-test"}))
                    .expect("genesis detail"),
            })
            .expect("append genesis");
        drop(store);

        let evaluator = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(
            b"diagnostic-refusal-test-evaluator",
        ));
        let mut engine =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(evaluator)).expect("engine");
        if let Err(error) = engine.watcher_action(&watcher, "admit") {
            if error.to_string().contains("\"class\":\"spawn_failed\"")
                && fs::read_to_string("/proc/self/attr/current")
                    .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
            {
                eprintln!("skipping helper execution: sandbox AppArmor denies executable memfds");
                return;
            }
            panic!("fixture admission failed: {error}");
        }
        fs::write(&mode, "partial\n").expect("select partial live report");

        let emitted = engine
            .diagnostic_execute(&watcher)
            .expect("admitted partial host execution emits a diagnostic refusal");
        let SupportedDiagnosticExecution::V2(artifact) = emitted else {
            panic!("new live diagnostic executions use the v2 contract");
        };
        artifact
            .validate()
            .expect("live refusal artifact validates");
        assert_eq!(artifact.outcome.derivation, DiagnosticDerivationV1::Refused);
        assert_eq!(
            artifact.outcome.condition,
            DiagnosticConditionV1::Unresolved
        );
        assert_eq!(
            artifact.outcome.coherence,
            DiagnosticCoherenceV1::NotEvaluated
        );
        assert_eq!(artifact.outcome.coverage, DiagnosticCoverageV1::Partial);
        assert!(artifact.claims.is_empty());
        assert!(artifact.primary_claim_id.is_none());
        let [refusal] = artifact.outcome.refusals.as_slice() else {
            panic!("exactly one governed diagnostic refusal");
        };
        let GovernedRefusalOrigin::Profile(profile) = &refusal.origin else {
            panic!("detector refusal remains profile-origin testimony");
        };
        assert_eq!(
            profile.refusal.code,
            nq_profiles::ProfileRefusalCode::CannotEvaluate
        );
        assert_eq!(
            profile.refusal.message,
            "the newest host testimony lacks complete load coverage"
        );
        assert!(!refusal.refusal_id.is_empty());

        let original = artifact.canonical_bytes().expect("canonical refusal bytes");
        let reopened =
            DiagnosticExecutionV2::decode_canonical(&original).expect("exact refusal bytes reopen");
        assert_eq!(reopened, artifact);
        let artifact_id = artifact.artifact_id.0.clone();
        assert_eq!(
            engine
                .store
                .diagnostic_artifact_id_for_run(artifact.run_id.as_str())
                .expect("refusal artifact index")
                .expect("refusal artifact committed"),
            artifact_id
        );
        validate_diagnostic_artifact_history(&mut engine.store)
            .expect("evaluated refusal history preserves exact semantics");
        drop(engine);
        let reopened_store =
            Store::open_read_only(&config.database_path).expect("store reopens after restart");
        assert_eq!(
            reopen_diagnostic_artifact(&reopened_store, &artifact_id)
                .expect("refusal artifact survives restart")
                .canonical_bytes()
                .expect("reopened refusal bytes"),
            original
        );
    }

    #[test]
    fn diagnostic_execute_persists_exact_received_input_refusal_without_evaluation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let Some((mut engine, watcher, mode)) = admitted_host_diagnostic_fixture(
            directory.path(),
            "diagnostic-input-refusal-test-genesis",
            b"diagnostic-input-refusal-test-evaluator",
        ) else {
            return;
        };
        fs::write(&mode, "helper_refusal\n").expect("select helper refusal");

        let emitted = engine
            .diagnostic_execute(&watcher)
            .expect("run-bearing input refusal emits an exact diagnostic artifact");
        let SupportedDiagnosticExecution::V2(artifact) = emitted else {
            panic!("new live diagnostic executions use the v2 contract");
        };
        artifact
            .validate()
            .expect("input refusal artifact validates");
        assert_eq!(artifact.outcome.derivation, DiagnosticDerivationV1::Refused);
        assert_eq!(
            artifact.outcome.condition,
            DiagnosticConditionV1::Unresolved
        );
        assert_eq!(artifact.outcome.coverage, DiagnosticCoverageV1::Missing);
        assert_eq!(artifact.inputs.received.len(), 1);
        let [refused] = artifact.inputs.refused.as_slice() else {
            panic!("one exact received-input refusal");
        };
        assert!(refused.profile_binding.is_none());
        let GovernedRefusalOrigin::Helper(helper) = &refused.refusal.origin else {
            panic!("helper refusal remains helper-origin testimony");
        };
        assert_eq!(helper.details["errno"], "EAGAIN");
        assert_eq!(
            artifact.outcome.refusals.as_slice(),
            std::slice::from_ref(&refused.refusal)
        );
        assert!(artifact.claims.is_empty());
        assert!(artifact.primary_claim_id.is_none());
        let intakes = engine
            .store
            .provider_intakes_bounded(10, None)
            .expect("provider intake history");
        let [intake_row] = intakes.as_slice() else {
            panic!("one exact provider intake");
        };
        let exact_provider_bytes = engine
            .store
            .provider_intake_raw_bytes(&intake_row.intake_id)
            .expect("provider raw custody")
            .expect("provider raw bytes");
        let intake = ProviderIntakeRecordV1::reopen_store_row(intake_row, &exact_provider_bytes)
            .expect("exact provider intake reopens");
        validate_provider_interpretation_derivation(&intake, &artifact)
            .expect("provider refusal remains a diagnostic refusal");

        let mut laundered = artifact.clone();
        laundered.outcome.derivation = DiagnosticDerivationV1::Completed;
        laundered.outcome.refusals.clear();
        assert!(matches!(
            validate_provider_interpretation_derivation(&intake, &laundered),
            Err(EngineError::Invariant(message))
                if message.contains("turns an explicit provider refusal")
        ));
        let original = artifact.canonical_bytes().expect("canonical refusal bytes");
        let artifact_id = artifact.artifact_id.0.clone();
        validate_diagnostic_artifact_history(&mut engine.store)
            .expect("run-only refusal history verifies semantically");

        drop(engine);
        let mut reopened =
            Store::open_read_only(directory.path().join("nq.db")).expect("reopen store");
        assert_eq!(
            reopen_diagnostic_artifact(&reopened, &artifact_id)
                .expect("reopen input refusal")
                .canonical_bytes()
                .expect("canonical reopened bytes"),
            original
        );
        validate_diagnostic_artifact_history(&mut reopened)
            .expect("restart verification preserves exact refusal");
    }

    #[test]
    fn diagnostic_execute_persists_exact_provider_no_response_without_fabricated_custody() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let Some((mut engine, watcher, mode)) = admitted_host_diagnostic_fixture(
            directory.path(),
            "diagnostic-no-response-test-genesis",
            b"diagnostic-no-response-test-evaluator",
        ) else {
            return;
        };
        fs::write(&mode, "no_response\n").expect("select provider EOF");

        let emitted = engine
            .diagnostic_execute(&watcher)
            .expect("run-bearing provider EOF emits an exact partial diagnostic artifact");
        let SupportedDiagnosticExecution::V2(artifact) = emitted else {
            panic!("new live diagnostic executions use the v2 contract");
        };
        artifact
            .validate()
            .expect("provider-no-response artifact validates");
        assert_eq!(artifact.outcome.derivation, DiagnosticDerivationV1::Partial);
        assert_eq!(
            artifact.outcome.condition,
            DiagnosticConditionV1::Unresolved
        );
        assert_eq!(artifact.outcome.coverage, DiagnosticCoverageV1::Missing);
        assert!(artifact.inputs.received.is_empty());
        assert!(artifact.inputs.refused.is_empty());
        let [failed] = artifact.inputs.failed.as_slice() else {
            panic!("one exact failed input");
        };
        let FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id,
            attempt,
            raw_custody,
            failure,
        } = &failed.cause
        else {
            panic!("EOF remains provider no-response");
        };
        assert_eq!(*raw_custody, FailedAcquisitionCustodyV2::NoBytesRetained);
        assert_eq!(failure.class, AcquisitionFailureClass::Eof);
        assert_eq!(attempt, &artifact.attempt_interval);
        assert_eq!(
            engine
                .store
                .provider_intake_raw_bytes(provider_intake_id)
                .expect("raw-custody lookup")
                .expect("empty custody is explicit"),
            Vec::<u8>::new()
        );
        let [claim] = artifact.claims.as_slice() else {
            panic!("one bounded unknown claim");
        };
        assert_eq!(claim.status, DiagnosticClaimStatusV1::Unknown);
        assert_eq!(
            claim.dependency_failure_ids.as_slice(),
            std::slice::from_ref(&failed.failure_id)
        );
        assert_eq!(
            artifact.primary_claim_id.as_deref(),
            Some(claim.claim_id.as_str())
        );
        let intakes = engine
            .store
            .provider_intakes_bounded(10, None)
            .expect("provider intake history");
        let [intake_row] = intakes.as_slice() else {
            panic!("one exact provider intake");
        };
        let exact_provider_bytes = engine
            .store
            .provider_intake_raw_bytes(&intake_row.intake_id)
            .expect("provider raw custody")
            .expect("explicit empty provider custody");
        let intake = ProviderIntakeRecordV1::reopen_store_row(intake_row, &exact_provider_bytes)
            .expect("exact provider intake reopens");
        validate_provider_interpretation_derivation(&intake, &artifact)
            .expect("provider no-response remains a partial diagnostic");

        let mut laundered = artifact.clone();
        laundered.outcome.derivation = DiagnosticDerivationV1::Completed;
        assert!(matches!(
            validate_provider_interpretation_derivation(&intake, &laundered),
            Err(EngineError::Invariant(message))
                if message.contains("turns provider no-response into a completed result")
        ));
        let original = artifact.canonical_bytes().expect("canonical failure bytes");
        let artifact_id = artifact.artifact_id.0.clone();
        validate_diagnostic_artifact_history(&mut engine.store)
            .expect("run-only failure history verifies semantically");

        drop(engine);
        let mut reopened =
            Store::open_read_only(directory.path().join("nq.db")).expect("reopen store");
        assert_eq!(
            reopen_diagnostic_artifact(&reopened, &artifact_id)
                .expect("reopen provider no-response")
                .canonical_bytes()
                .expect("canonical reopened bytes"),
            original
        );
        validate_diagnostic_artifact_history(&mut reopened)
            .expect("restart verification preserves exact provider failure");
    }

    #[test]
    fn diagnostic_execute_preserves_partial_provider_bytes_as_received_refused_input() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let Some((mut engine, watcher, mode)) = admitted_host_diagnostic_fixture(
            directory.path(),
            "diagnostic-partial-bytes-test-genesis",
            b"diagnostic-partial-bytes-test-evaluator",
        ) else {
            return;
        };
        fs::write(&mode, "partial_bytes_failure\n").expect("select partial-byte failure");

        let emitted = engine
            .diagnostic_execute(&watcher)
            .expect("retained provider bytes emit an exact diagnostic refusal");
        let SupportedDiagnosticExecution::V2(artifact) = emitted else {
            panic!("new live diagnostic executions use the v2 contract");
        };
        artifact
            .validate()
            .expect("partial-byte refusal artifact validates");
        assert_eq!(artifact.outcome.derivation, DiagnosticDerivationV1::Refused);
        assert_eq!(
            artifact.outcome.condition,
            DiagnosticConditionV1::Unresolved
        );
        assert_eq!(artifact.outcome.coverage, DiagnosticCoverageV1::Missing);
        let [received] = artifact.inputs.received.as_slice() else {
            panic!("retained partial bytes are one received input");
        };
        let [refused] = artifact.inputs.refused.as_slice() else {
            panic!("retained partial bytes are one refused input");
        };
        assert_eq!(refused.input_id, received.input_id);
        assert!(artifact.inputs.failed.is_empty());
        let raw = engine
            .store
            .provider_intake_raw_bytes(&received.provider_intake_id)
            .expect("raw-custody lookup")
            .expect("partial bytes retained");
        assert!(!raw.is_empty());
        assert_eq!(received.raw_artifact_id.0, nq_protocol::sha256_bytes(&raw));
        assert_eq!(
            artifact.outcome.refusals.as_slice(),
            std::slice::from_ref(&refused.refusal)
        );
        validate_diagnostic_artifact_history(&mut engine.store)
            .expect("partial-byte refusal preserves exact semantic history");
    }

    #[test]
    fn diagnostic_execute_keeps_pre_run_admission_refusal_outside_artifact_history() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (config, watcher, _mode) = host_diagnostic_fixture(directory.path());
        let mut store = Store::initialize(&config.database_path).expect("initialize store");
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            resolve(&watcher).expect("host profile"),
        )
        .expect("profile descriptor");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_genesis(&GenesisInput {
                genesis_id: "diagnostic-admission-refusal-test-genesis".to_owned(),
                legacy_manifest_digest: None,
                created_at: "2026-07-28T12:00:00.000Z".to_owned(),
                detail: canonical(&json!({"source": "diagnostic-admission-refusal-test"}))
                    .expect("genesis detail"),
            })
            .expect("append genesis");
        drop(store);

        let evaluator = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(
            b"diagnostic-admission-refusal-test-evaluator",
        ));
        let mut engine =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(evaluator)).expect("engine");
        let error = engine
            .diagnostic_execute(&watcher)
            .expect_err("missing active admission cannot become an execution artifact");
        assert!(
            error
                .to_string()
                .contains("produced no admitted determinate diagnostic execution")
        );
        assert!(
            engine
                .store
                .watcher_run_outcomes_bounded(10, None)
                .expect("watcher run history")
                .is_empty()
        );
        assert!(
            engine
                .store
                .provider_intakes_bounded(10, None)
                .expect("provider intake history")
                .is_empty()
        );
        assert!(
            engine
                .store
                .diagnostic_artifact_commitments_bounded(10, None)
                .expect("diagnostic artifact history")
                .is_empty()
        );
        let status = status_snapshot_v3(&engine.store).expect("retained refusal status");
        assert_eq!(status.components.len(), 1);
        assert_eq!(status.components[0].code, "admission_refused");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn collect_persists_exact_helper_and_profile_refusals_through_status() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (mut config, mut watcher, _lock) = binding_recovery_fixture(directory.path());
        let script = directory.path().join("semantic_transport_helper.py");
        let mode = directory.path().join("semantic_transport.mode");
        fs::write(&script, SEMANTIC_TRANSPORT_HELPER).expect("write helper script");
        fs::write(&mode, "report\n").expect("write initial helper mode");
        watcher.command.executable = PathBuf::from("/usr/bin/python3");
        watcher.command.args = vec![script.to_string_lossy().into_owned()];
        watcher.command.env = BTreeMap::from([(
            "NQ_TEST_MODE".to_owned(),
            mode.to_string_lossy().into_owned(),
        )]);
        config.watchers = vec![watcher.clone()];

        let mut store = Store::initialize(&config.database_path).expect("initialize store");
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            resolve(&watcher).expect("profile"),
        )
        .expect("profile descriptor");
        drop(store);
        let evaluator = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(
            b"semantic-transport-evaluator",
        ));
        let mut engine =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(evaluator)).expect("engine");
        engine
            .watcher_action(&watcher, "admit")
            .unwrap_or_else(|error| panic!("fixture admission failed: {error}"));

        fs::write(&mode, "helper_transient\n").expect("select transient refusal");
        let transient = engine.collect(&watcher).expect("collect transient refusal");
        transient.validate().expect("valid transient carrier");
        let transient_id = match &transient.result {
            CollectionResult::Rejected {
                refusal:
                    GovernedRefusal {
                        refusal_id,
                        origin: GovernedRefusalOrigin::Helper(refusal),
                        ..
                    },
            } => {
                assert!(refusal.retriable);
                assert_eq!(refusal.details["errno"], "EAGAIN");
                refusal_id.clone()
            }
            other => panic!("expected helper refusal, got {other:?}"),
        };
        let transient_run_id = transient.run_id.as_deref().expect("transient run identity");
        let transient_stored = engine
            .store
            .provider_intakes_bounded(10, None)
            .expect("enumerate provider intakes")
            .into_iter()
            .find(|row| row.run_id == transient_run_id)
            .expect("transient provider intake");
        let transient_bytes = engine
            .store
            .provider_intake_raw_bytes(&transient_stored.intake_id)
            .expect("read transient raw custody")
            .expect("transient raw bytes");
        let transient_intake =
            ProviderIntakeRecordV1::reopen_store_row(&transient_stored, &transient_bytes)
                .expect("transient intake reopens");
        let mut substituted = transient.clone();
        let CollectionResult::Rejected {
            refusal:
                GovernedRefusal {
                    origin: GovernedRefusalOrigin::Helper(ref mut helper),
                    ..
                },
        } = substituted.result
        else {
            panic!("transient fixture carries a helper refusal")
        };
        helper.retriable = false;
        helper.details = json!({"errno": "ENODEV", "substituted": true});
        assert!(matches!(
            validate_provider_downstream_correspondence(&transient_intake, &substituted),
            Err(EngineError::Invariant(message))
                if message.contains("does not correspond")
        ));
        let transient_status = status_snapshot_v2(&engine.store).expect("transient status");
        let transient_component = transient_status
            .components
            .iter()
            .find(|component| component.id == watcher.instance_id)
            .expect("transient component");
        assert_eq!(transient_component.code, "helper_refused");
        assert_eq!(transient_component.state, HealthState::Degraded);

        fs::write(&mode, "helper_permanent\n").expect("select permanent refusal");
        let permanent = engine.collect(&watcher).expect("collect permanent refusal");
        permanent.validate().expect("valid permanent carrier");
        let permanent_id = match &permanent.result {
            CollectionResult::Rejected {
                refusal:
                    GovernedRefusal {
                        refusal_id,
                        origin: GovernedRefusalOrigin::Helper(refusal),
                        ..
                    },
            } => {
                assert!(!refusal.retriable);
                assert_eq!(refusal.details["errno"], "ENODEV");
                refusal_id.clone()
            }
            other => panic!("expected helper refusal, got {other:?}"),
        };
        assert_ne!(transient_id, permanent_id);

        fs::write(&mode, "profile_reject\n").expect("select profile refusal");
        let profile = engine.collect(&watcher).expect("collect profile refusal");
        profile.validate().expect("valid profile carrier");
        match &profile.result {
            CollectionResult::Rejected {
                refusal:
                    GovernedRefusal {
                        origin: GovernedRefusalOrigin::Profile(refusal),
                        ..
                    },
            } => {
                assert_eq!(refusal.refusal.profile.id, "nq.conformance");
                assert_eq!(
                    refusal.refusal.boundary,
                    nq_profiles::RefusalBoundary::Observation
                );
                assert!(!refusal.refusal.details.is_empty());
            }
            other => panic!("expected profile refusal, got {other:?}"),
        }
        let profile_run_id = profile.run_id.as_deref().expect("profile run identity");
        let profile_stored = engine
            .store
            .provider_intakes_bounded(10, None)
            .expect("enumerate provider intakes")
            .into_iter()
            .find(|row| row.run_id == profile_run_id)
            .expect("profile provider intake");
        let profile_bytes = engine
            .store
            .provider_intake_raw_bytes(&profile_stored.intake_id)
            .expect("read profile raw custody")
            .expect("profile raw bytes");
        let profile_intake =
            ProviderIntakeRecordV1::reopen_store_row(&profile_stored, &profile_bytes)
                .expect("profile intake reopens");
        let mut substituted_profile = profile.clone();
        let CollectionResult::Rejected {
            refusal:
                GovernedRefusal {
                    origin: GovernedRefusalOrigin::Profile(ref mut governed),
                    ..
                },
        } = substituted_profile.result
        else {
            panic!("profile fixture carries a profile refusal")
        };
        governed.refusal.details.insert(
            "coherently_resealed".to_owned(),
            "different stored decision".to_owned(),
        );
        assert!(matches!(
            validate_provider_downstream_correspondence(
                &profile_intake,
                &substituted_profile
            ),
            Err(EngineError::Invariant(message))
                if message.contains("does not correspond")
        ));
        let profile_status = status_snapshot_v2(&engine.store).expect("profile status");
        let profile_component = profile_status
            .components
            .iter()
            .find(|component| component.id == watcher.instance_id)
            .expect("profile component");
        assert_eq!(profile_component.code, "report_rejected");
        assert_eq!(profile_component.state, HealthState::Failed);

        assert_eq!(
            validate_rejected_custody_history(&engine.store).expect("custody history"),
            3
        );
        assert_eq!(
            validate_status_history_v2(&engine.store).expect("status history"),
            3
        );
    }

    #[test]
    fn normalization_failure_maps_to_typed_profile_refusal() {
        let refusal = profile_normalization_refusal(
            "normalization.primary",
            &nq_profiles::conformance::MODULE,
            &nq_profiles::ReportNormalizationError::ProfileVersion("v-next".to_owned()),
        );
        assert_eq!(refusal.instance_id, "normalization.primary");
        assert_eq!(refusal.boundary, nq_profiles::RefusalBoundary::Report);
        assert_eq!(
            refusal.code,
            nq_profiles::ProfileRefusalCode::InvalidPayload
        );
        assert_eq!(
            refusal.details.get("stage").map(String::as_str),
            Some("protocol_normalization")
        );
        let semantic_id = profile_semantic_id(nq_profiles::conformance::MODULE.descriptor())
            .expect("profile semantic identity");
        GovernedRefusal::profile("normalization-refusal".to_owned(), semantic_id, refusal)
            .validate()
            .expect("typed normalization refusal");
    }

    /// Seed one admitted report with a chosen recorded evaluator identity, so a
    /// verification against a chosen *current* identity can be exercised.
    #[allow(clippy::too_many_lines)]
    fn seed_admitted_report(
        db_path: &Path,
        evaluator_artifact_digest: Sha256Digest,
        artifact_identity_method: &str,
        platform_runtime_version: &str,
    ) -> String {
        const TS: &str = "2026-07-16T12:00:00.000Z";
        const ADMISSION_ID: &str = "00000000-0000-4000-8000-000000000001";
        let doc = |value: Value| CanonicalDocument::from_serializable(&value).expect("canonical");
        let sd = |label: &str| nq_protocol::sha256_bytes(label.as_bytes());
        let mut store = Store::initialize(db_path).expect("initialize verify store");
        let descriptor = doc(json!({"profile": "verify.fixture"}));
        let profile_digest = descriptor.digest().to_owned();
        store
            .begin_writer_session()
            .expect("writer session")
            .append_profile_descriptor(&ProfileDescriptorInput {
                profile_id: "verify.fixture".to_owned(),
                profile_version: "1".to_owned(),
                descriptor,
                recorded_at: TS.to_owned(),
            })
            .expect("descriptor");
        let execution = fixture_execution("verify-admitted");
        let conformance = fixture_conformance();
        let lock = AdmissionLock {
            schema: ADMISSION_SCHEMA.to_owned(),
            admission_id: ADMISSION_ID.to_owned(),
            instance_id: "inst-1".to_owned(),
            config_digest: sd("config").into_string(),
            execution,
            profile: AdmittedProfile {
                id: "verify.fixture".to_owned(),
                version: 1,
                digest: profile_digest.clone(),
            },
            protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            granted_capabilities: BTreeSet::new(),
            conformance,
            admitted_at: parse_timestamp(TS).expect("admission time"),
            operator: OperatorIdentity {
                uid: 991,
                gid: 991,
                login_hint: Some("nq-core-verify-fixture".to_owned()),
            },
        };
        let binding = canonical(&lock).expect("admission binding");
        store
            .begin_writer_session()
            .expect("writer session")
            .append_admission(&AdmissionInput {
                admission_id: ADMISSION_ID.to_owned(),
                instance_id: "inst-1".to_owned(),
                identity: AdmissionIdentity {
                    profile_semantic_id: sd("semantic"),
                    detector_identity_digest: nq_store::detector_suite_identity_digest(
                        Vec::<String>::new(),
                    )
                    .expect("empty verification detector suite"),
                    evaluator_source_digest: sd("source"),
                    evaluator_artifact_digest,
                    helper_artifact_digest: Sha256Digest::parse(lock.execution.sha256.clone())
                        .expect("helper artifact digest"),
                    config_digest: Sha256Digest::parse(lock.config_digest.clone())
                        .expect("configuration digest"),
                    protocol_version: lock.protocol_version.clone(),
                    target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                    artifact_identity_method: artifact_identity_method.to_owned(),
                    platform_runtime_version: platform_runtime_version.to_owned(),
                },
                execution_chain: canonical(&lock.execution).expect("execution identity"),
                profile_id: "verify.fixture".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest: profile_digest.clone(),
                capability_grant: canonical(&lock.granted_capabilities).expect("capability grant"),
                conformance: canonical(&lock.conformance).expect("fixture conformance"),
                lock: binding.clone(),
                admitted_at: TS.to_owned(),
                operator_identity: canonical(&lock.operator).expect("operator identity"),
            })
            .expect("admission");
        activate_test_admission(&mut store, "inst-1", ADMISSION_ID, binding.digest());
        let run = RunInput {
            run_id: "run-1".to_owned(),
            request_id: "req-1".to_owned(),
            instance_id: "inst-1".to_owned(),
            admission_id: Some(ADMISSION_ID.to_owned()),
            binding_digest: binding.digest().to_owned(),
            checkpoint_contract_digest: sd("checkpoint").as_str().to_owned(),
            profile_id: "verify.fixture".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.clone(),
            carrier: "stdio".to_owned(),
            started_at: TS.to_owned(),
            deadline_at: TS.to_owned(),
            finished_at: TS.to_owned(),
            acquisition_outcome: "response".to_owned(),
            execution_identity: canonical(&lock.execution).expect("execution identity"),
            resource_outcome: doc(json!({
                "schema": "nq.run_resource_outcome.v1",
                "duration_ms": 1,
                "exit_code": 0,
                "hard_limits": {
                    "address_space_bytes_per_process": 1,
                    "cpu_seconds_per_process": 1,
                    "processes_per_execution_uid": 1,
                    "open_files_per_process": 1,
                    "file_bytes_per_regular_file": 1,
                    "core_bytes": 0
                },
                "stdout_bytes_retained": 0,
                "stderr_bytes_retained": 0,
                "stderr_hex": "",
                "outcome": {"outcome": "response"}
            })),
        };
        let protocol_report = nq_protocol::EvidenceReport {
            schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
            profile: ProfileBinding {
                id: ProfileId::new("verify.fixture").expect("profile id"),
                version: ProfileVersion::new("1").expect("profile version"),
                digest: Sha256Digest::parse(profile_digest.clone()).expect("profile digest"),
            },
            binding: SubjectBinding {
                subject: SubjectId::new("verify:fixture").expect("subject"),
                scope: ScopeBinding {
                    kind: ScopeKind::new("fixture").expect("scope"),
                    value: json!({}),
                },
                vantage: VantageBinding {
                    kind: VantageKind::new("local").expect("vantage"),
                    value: json!({}),
                },
            },
            observed_at: parse_timestamp(TS).expect("time"),
            status: nq_protocol::ReportStatus::Complete,
            coverage: Vec::new(),
            observations: Vec::new(),
            errors: Vec::new(),
            used_capabilities: Vec::new(),
            backend: nq_protocol::BackendProvenance {
                implementation: nq_protocol::BackendIdentity {
                    name: nq_protocol::ImplementationName::new("fixture").expect("implementation"),
                    version: Some("1".to_owned()),
                    digest: None,
                },
                tools: Vec::new(),
            },
            next_checkpoint: None,
        };
        nq_protocol::validate_report(&protocol_report).expect("protocol report");
        let canonical_report = canonical(&protocol_report).expect("canonical report");
        let validated_report = doc(json!({
            "schema": "fixture.validated_report.v1",
            "instance_id": "inst-1",
            "report_digest": canonical_report.digest(),
            "profile": {"id": "verify.fixture", "version": 1},
            "profile_digest": profile_digest,
            "status": "complete",
            "observed_at": TS,
            "received_at": TS,
        }));
        let report = ReportInput {
            report_id: "rep-1".to_owned(),
            instance_id: "inst-1".to_owned(),
            profile_id: "verify.fixture".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest,
            observed_at: TS.to_owned(),
            received_at: TS.to_owned(),
            report_status: "complete".to_owned(),
            canonical_report,
            validated_report,
            next_checkpoint: None,
            admitted_at: TS.to_owned(),
            observations: Vec::new(),
            coverage: Vec::new(),
            errors: Vec::new(),
        };
        let collection = test_collection_with_conformance(
            &mut store,
            run,
            Some(SubmissionInput {
                submission_id: "sub-1".to_owned(),
                raw_bytes: b"raw".to_vec(),
                received_at: TS.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report),
            }),
            "verify-admitted",
        );
        store
            .begin_writer_session()
            .expect("writer session")
            .commit_admitted_collection(&collection, |_view, receipt| {
                let outcome = CollectionOutcome::admitted(
                    "inst-1".to_owned(),
                    "run-1".to_owned(),
                    "rep-1".to_owned(),
                    "complete".to_owned(),
                    receipt.semantic_digest.clone().expect("report digest"),
                    Vec::new(),
                );
                Ok::<_, EngineError>(AdmittedCollectionCompletion {
                    value: (),
                    evaluations: Vec::new(),
                    diagnostic_artifact: None,
                    status: StatusEventInput {
                        status_event_id: "status-run-1".to_owned(),
                        component_kind: "instance".to_owned(),
                        component_id: "inst-1".to_owned(),
                        state: "healthy".to_owned(),
                        code: "report_complete".to_owned(),
                        detail: canonical(&outcome).expect("canonical admitted result"),
                        observed_at: TS.to_owned(),
                    },
                })
            })
            .expect("commit admitted report");
        "rep-1".to_owned()
    }

    #[test]
    fn verify_admitted_passes_when_snapshot_and_runtime_agree() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let artifact = nq_protocol::sha256_bytes(b"evaluator-artifact");
        let report = seed_admitted_report(
            &config.database_path,
            artifact.clone(),
            "test-fixture-v1",
            "test",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Ok(EvaluatorRuntimeIdentity::for_test(artifact)),
        )
        .expect("engine");
        let verified = engine
            .verify_admitted(&report)
            .expect("verification passes");
        assert_eq!(verified.report_id, "rep-1");
        assert_eq!(
            verified.admission_id,
            "00000000-0000-4000-8000-000000000001"
        );
        assert!(verified.platform_observations.is_empty());
    }

    #[test]
    fn verify_admitted_refuses_evaluator_artifact_drift() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let report = seed_admitted_report(
            &config.database_path,
            nq_protocol::sha256_bytes(b"admitted-artifact"),
            "test-fixture-v1",
            "test",
        );
        let current = EvaluatorRuntimeIdentity::for_test(nq_protocol::sha256_bytes(b"different"));
        let engine =
            CollectionEngine::open_with_evaluator_identity(&config, Ok(current)).expect("engine");
        assert!(matches!(
            engine.verify_admitted(&report),
            Err(VerificationRefusal::EvaluatorArtifactDrift { .. })
        ));
    }

    #[test]
    fn verify_admitted_refuses_when_the_identity_method_changed() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let artifact = nq_protocol::sha256_bytes(b"artifact");
        // Admitted under an older observation method; digests are not comparable.
        let report = seed_admitted_report(
            &config.database_path,
            artifact.clone(),
            "linux-proc-self-exe-fd-sha256-v0",
            "test",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Ok(EvaluatorRuntimeIdentity::for_test(artifact)),
        )
        .expect("engine");
        assert!(matches!(
            engine.verify_admitted(&report),
            Err(VerificationRefusal::MethodIncompatible { .. })
        ));
    }

    #[test]
    fn verify_admitted_records_platform_drift_without_refusing() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        let artifact = nq_protocol::sha256_bytes(b"artifact");
        let report = seed_admitted_report(
            &config.database_path,
            artifact.clone(),
            "test-fixture-v1",
            "6.1.0-admitted",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Ok(EvaluatorRuntimeIdentity::for_test(artifact)),
        )
        .expect("engine");
        let verified = engine
            .verify_admitted(&report)
            .expect("platform drift still verifies the historical admission");
        assert_eq!(
            verified.platform_observations,
            vec![PlatformObservation::RuntimeDrift {
                admitted: "6.1.0-admitted".to_owned(),
                current: "test".to_owned(),
            }]
        );
    }

    #[test]
    fn verify_admitted_fails_closed_when_current_identity_is_unavailable() {
        let dir = tempfile::tempdir().expect("dir");
        let (config, _watcher, _lock) = binding_recovery_fixture(dir.path());
        // The snapshot authenticates, but the current identity cannot be
        // observed, so drift cannot be assessed and verification fails closed.
        let report = seed_admitted_report(
            &config.database_path,
            nq_protocol::sha256_bytes(b"artifact"),
            "test-fixture-v1",
            "test",
        );
        let engine = CollectionEngine::open_with_evaluator_identity(
            &config,
            Err("evaluator identity is unsupported on this platform".to_owned()),
        )
        .expect("engine");
        assert!(matches!(
            engine.verify_admitted(&report),
            Err(VerificationRefusal::CurrentIdentityUnverifiable(_))
        ));
    }

    #[test]
    fn acquisition_failed_outcome_preserves_exact_same_code_payload() {
        let socket_mode = AcquisitionOutcome::CarrierStartupFailed {
            message: "helper socket mode is 0o660; expected 0o600".to_owned(),
        };
        let spawn = AcquisitionOutcome::CarrierStartupFailed {
            message: "could not spawn Unix helper: Permission denied (os error 13)".to_owned(),
        };
        assert_eq!(acquisition_code(&socket_mode), acquisition_code(&spawn));

        let first = CollectionOutcome::acquisition_failed(
            "conformance-local".to_owned(),
            "00000000-0000-4000-8000-000000000000".to_owned(),
            socket_mode.clone(),
        )
        .expect("typed acquisition failure");
        let second = CollectionOutcome::acquisition_failed(
            "conformance-local".to_owned(),
            "00000000-0000-4000-8000-000000000000".to_owned(),
            spawn.clone(),
        )
        .expect("typed acquisition failure");
        let first_bytes = canonical(&first).expect("canonical first outcome");
        let second_bytes = canonical(&second).expect("canonical second outcome");
        assert_ne!(first_bytes.as_bytes(), second_bytes.as_bytes());
        let reopened = decode_collection_outcome(first_bytes.as_bytes()).expect("reopen outcome");
        assert_eq!(reopened, first);
        assert!(format!("{first:?}").contains("helper socket mode is 0o660"));
    }

    #[test]
    fn canonical_carrier_rejects_substituted_acquisition_projections() {
        let outcome = CollectionOutcome::acquisition_failed(
            "conformance-local".to_owned(),
            "run-timeout".to_owned(),
            AcquisitionOutcome::ExchangeTimeout {
                phase: ExchangeTimeoutPhase::WriteRequest,
            },
        )
        .expect("typed timeout");

        let mut wrong_class = serde_json::to_value(&outcome).expect("serialize carrier");
        wrong_class["result"]["failure"]["class"] = json!("eof");
        let wrong_class: CollectionOutcome =
            serde_json::from_value(wrong_class).expect("shape remains decodable");
        assert!(wrong_class.validate().is_err());

        let mut wrong_retry = serde_json::to_value(&outcome).expect("serialize carrier");
        wrong_retry["result"]["failure"]["retry"] = json!("retriable");
        let wrong_retry: CollectionOutcome =
            serde_json::from_value(wrong_retry).expect("shape remains decodable");
        assert!(wrong_retry.validate().is_err());
    }

    #[test]
    fn collection_outcome_wire_codec_rejects_omitted_extra_duplicate_and_substituted_fields() {
        let outcome = CollectionOutcome::acquisition_failed(
            "conformance-local".to_owned(),
            "run-wire".to_owned(),
            AcquisitionOutcome::ExchangeTimeout {
                phase: ExchangeTimeoutPhase::WriteRequest,
            },
        )
        .expect("typed timeout");
        let exact = canonical(&outcome).expect("canonical carrier");
        assert_eq!(
            decode_collection_outcome(exact.as_bytes()).expect("strict round trip"),
            outcome
        );

        let mut omitted = serde_json::to_value(&outcome).expect("carrier value");
        omitted["result"]
            .as_object_mut()
            .expect("result object")
            .remove("failure");
        let omitted = nq_protocol::canonical_json_bytes(&omitted).expect("canonical omission");
        assert!(decode_collection_outcome(&omitted).is_err());

        let mut extra = serde_json::to_value(&outcome).expect("carrier value");
        extra
            .as_object_mut()
            .expect("carrier object")
            .insert("inferred_detail".to_owned(), json!("write_request"));
        let extra = nq_protocol::canonical_json_bytes(&extra).expect("canonical extra field");
        assert!(decode_collection_outcome(&extra).is_err());

        let mut nested_extra = serde_json::to_value(&outcome).expect("carrier value");
        nested_extra["result"]["failure"]["outcome"]
            .as_object_mut()
            .expect("acquisition outcome object")
            .insert("unsealed_detail".to_owned(), json!("must not be ignored"));
        let nested_extra =
            nq_protocol::canonical_json_bytes(&nested_extra).expect("canonical nested extra");
        assert!(decode_collection_outcome(&nested_extra).is_err());

        let duplicate = format!(
            "{{\"instance_id\":\"conformance-local\",{}}}",
            String::from_utf8_lossy(exact.as_bytes())
                .trim_start_matches('{')
                .trim_end_matches('}')
        );
        assert!(decode_collection_outcome(duplicate.as_bytes()).is_err());

        let mut substituted = serde_json::to_value(&outcome).expect("carrier value");
        substituted["result"]["failure"]["outcome"]["phase"] = json!("read_response");
        let substituted =
            nq_protocol::canonical_json_bytes(&substituted).expect("canonical substitution");
        let reopened = decode_collection_outcome(&substituted).expect("valid distinct timeout");
        assert_ne!(reopened, outcome);

        let mut mismatched = serde_json::to_value(&outcome).expect("carrier value");
        mismatched["result"]["failure"]["class"] = json!("eof");
        let mismatched =
            nq_protocol::canonical_json_bytes(&mismatched).expect("canonical mismatch");
        assert!(decode_collection_outcome(&mismatched).is_err());

        let invalid_status = CollectionOutcome::admitted(
            "conformance-local".to_owned(),
            "run-admitted".to_owned(),
            "report-admitted".to_owned(),
            "successful".to_owned(),
            nq_protocol::sha256_bytes(b"report").to_string(),
            Vec::new(),
        );
        let invalid_status = canonical(&invalid_status).expect("canonical invalid vocabulary");
        assert!(decode_collection_outcome(invalid_status.as_bytes()).is_err());
    }

    #[test]
    fn collection_outcome_validation_checks_nested_admission_payloads_and_instances() {
        let nested = GovernedRefusal::helper(
            "refusal-nested".to_owned(),
            nq_protocol::Refusal {
                responsible_instance_id: InstanceId::new("other.instance").expect("instance"),
                boundary: nq_protocol::RefusalBoundary::Collection,
                code: nq_protocol::RefusalCode::CollectionFailed,
                message: "collection failed".to_owned(),
                retriable: true,
                details: json!({"errno": "EAGAIN"}),
            },
        );
        let wrong_instance = CollectionOutcome::admission_refused(
            "admission.primary".to_owned(),
            AdmissionRefusal {
                responsible_instance_id: "admission.primary".to_owned(),
                boundary: AdmissionRefusalBoundary::Conformance,
                code: AdmissionRefusalCode::UpstreamRefusal,
                details: AdmissionRefusalDetails::Governed {
                    refusal: Box::new(nested),
                },
            },
        );
        assert!(wrong_instance.validate().is_err());

        let invalid_acquisition = CollectionOutcome::admission_refused(
            "admission.primary".to_owned(),
            AdmissionRefusal {
                responsible_instance_id: "admission.primary".to_owned(),
                boundary: AdmissionRefusalBoundary::Conformance,
                code: AdmissionRefusalCode::UpstreamRefusal,
                details: AdmissionRefusalDetails::Acquisition {
                    failure: AcquisitionFailure {
                        class: AcquisitionFailureClass::Eof,
                        retry: RetryDisposition::Unspecified,
                        outcome: AcquisitionOutcome::Timeout,
                    },
                },
            },
        );
        assert!(invalid_acquisition.validate().is_err());
    }

    #[test]
    fn scheduler_and_notification_status_are_legacy_decode_only() {
        let mut store = Store::initialize_in_memory().expect("status store");
        for kind in ["scheduler", "notification"] {
            assert!(matches!(
                record_component_status(
                    &mut store.begin_writer_session().expect("writer session"),
                    kind,
                    "legacy",
                    "healthy",
                    "historical",
                    &json!({"source": "pre-v2"}),
                ),
                Err(EngineError::Invariant(message))
                    if message == format!(
                        "{kind} status is legacy decode-only; current NQ cannot emit it"
                    )
            ));
            store
                .begin_writer_session()
                .expect("writer session")
                .record_status(&StatusEventInput {
                    status_event_id: format!("legacy-{kind}"),
                    component_kind: kind.to_owned(),
                    component_id: "legacy".to_owned(),
                    state: "healthy".to_owned(),
                    code: "historical".to_owned(),
                    detail: canonical(&json!({"source": "pre-v2"})).expect("legacy detail"),
                    observed_at: "2026-07-20T12:00:00.000Z".to_owned(),
                })
                .expect("historical store schema remains reopenable");
        }

        assert_eq!(
            validate_status_history_v2(&store).expect("reopen legacy immutable history"),
            2
        );
        assert!(
            status_snapshot(&store)
                .expect("v1 current status")
                .components
                .is_empty()
        );
        assert!(
            status_snapshot_v2(&store)
                .expect("v2 current status")
                .components
                .is_empty()
        );
        assert!(
            status_snapshot_v3(&store)
                .expect("v3 current status")
                .components
                .is_empty()
        );
        assert!(
            public_query(&store, "SELECT * FROM public_status_snapshot_v1", 10)
                .expect("bounded current-status query")
                .is_empty()
        );

        for index in 0..nq_store::MAX_PUBLIC_QUERY_ROWS {
            store
                .begin_writer_session()
                .expect("writer session")
                .record_status(&StatusEventInput {
                    status_event_id: format!("legacy-notification-{index:04}"),
                    component_kind: "notification".to_owned(),
                    component_id: format!("legacy-{index:04}"),
                    state: "healthy".to_owned(),
                    code: "historical".to_owned(),
                    detail: canonical(&json!({"source": "pre-v2"})).expect("legacy detail"),
                    observed_at: "2026-07-20T12:00:00.000Z".to_owned(),
                })
                .expect("saturate legacy status prefix");
        }
        record_component_status(
            &mut store.begin_writer_session().expect("writer session"),
            "profile_catalog",
            "compiled",
            "healthy",
            "catalog_loaded",
            &json!({"profile_count": 1}),
        )
        .expect("emit current NQ-owned status");

        let bounded = public_query(&store, "SELECT * FROM public_status_snapshot_v1", 1)
            .expect("legacy-saturated bounded current-status query");
        assert_eq!(bounded.len(), 1);
        assert_eq!(bounded[0]["kind"], "profile_catalog");
        assert_eq!(bounded[0]["id"], "compiled");
    }

    #[test]
    fn same_code_admission_upstream_refusal_pair_survives_status_backup_reopen() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let live = directory.path().join("admission-pair.db");
        let backup = directory.path().join("admission-pair-backup.db");
        let mut store = Store::initialize(&live).expect("status store");
        let make = |instance: &str, refusal_id: &str, retriable: bool, errno: &str| {
            let responsible = InstanceId::new(instance).expect("instance token");
            CollectionOutcome::admission_refused(
                instance.to_owned(),
                AdmissionRefusal {
                    responsible_instance_id: instance.to_owned(),
                    boundary: AdmissionRefusalBoundary::Conformance,
                    code: AdmissionRefusalCode::UpstreamRefusal,
                    details: AdmissionRefusalDetails::Governed {
                        refusal: Box::new(GovernedRefusal::helper(
                            refusal_id.to_owned(),
                            nq_protocol::Refusal {
                                responsible_instance_id: responsible,
                                boundary: nq_protocol::RefusalBoundary::Collection,
                                code: nq_protocol::RefusalCode::CollectionFailed,
                                message: "backend collection failed".to_owned(),
                                retriable,
                                details: json!({"errno": errno}),
                            },
                        )),
                    },
                },
            )
        };
        let transient = make("admission.transient", "admission-refusal-a", true, "EAGAIN");
        let permanent = make(
            "admission.permanent",
            "admission-refusal-b",
            false,
            "ENODEV",
        );
        assert_eq!(
            instance_status_projection(&transient).expect("transient projection"),
            instance_status_projection(&permanent).expect("permanent projection")
        );
        assert_ne!(
            canonical(&transient).expect("transient canonical"),
            canonical(&permanent).expect("permanent canonical")
        );
        for (suffix, outcome) in [("transient", &transient), ("permanent", &permanent)] {
            let projection = instance_status_projection(outcome).expect("projection");
            store
                .begin_writer_session()
                .expect("writer session")
                .record_status(&StatusEventInput {
                    status_event_id: format!("status-admission-{suffix}"),
                    component_kind: "instance".to_owned(),
                    component_id: outcome.instance_id.clone(),
                    state: projection.state.to_owned(),
                    code: projection.code.to_owned(),
                    detail: canonical(outcome).expect("canonical admission refusal"),
                    observed_at: "2026-07-20T12:00:00.000Z".to_owned(),
                })
                .expect("record admission refusal status");
        }
        let assert_pair = |store: &Store| {
            let status = status_snapshot_v2(store).expect("typed admission status");
            let nested = |instance: &str| {
                let component = status
                    .components
                    .iter()
                    .find(|component| component.id == instance)
                    .expect("admission component");
                assert_eq!(component.code, "admission_refused");
                let ComponentStatusDetailV2::Collection { result } = &component.detail else {
                    panic!("admission status must remain a collection result")
                };
                let CollectionResult::AdmissionRefused { refusal } = &result.result else {
                    panic!("admission refusal variant")
                };
                let AdmissionRefusalDetails::Governed { refusal } = &refusal.details else {
                    panic!("nested governed refusal")
                };
                let GovernedRefusalOrigin::Helper(helper) = &refusal.origin else {
                    panic!("nested helper refusal")
                };
                (helper.retriable, helper.details.clone())
            };
            assert_eq!(
                nested("admission.transient"),
                (true, json!({"errno": "EAGAIN"}))
            );
            assert_eq!(
                nested("admission.permanent"),
                (false, json!({"errno": "ENODEV"}))
            );
            assert_eq!(
                validate_status_history_v2(store).expect("admission status history"),
                2
            );
        };
        assert_pair(&store);
        store.backup_verified(&backup).expect("verified backup");
        drop(store);
        let reopened = Store::open(&backup).expect("reopen backup");
        assert_pair(&reopened);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn real_host_detector_same_code_refusals_survive_governed_store_and_reopen() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let live = directory.path().join("real-host-evaluations.db");
        let backup = directory.path().join("real-host-evaluations-backup.db");
        let config = NqConfig::from_toml(&host_example_text()).expect("valid host config");
        let watcher = &config.watchers[0];
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        let profile_descriptor = profile.descriptor();
        let profile_digest = profile_descriptor.digest().expect("profile digest");
        let profile_semantic =
            profile_semantic_id(profile_descriptor).expect("profile semantic identity");
        let detector = profile.detectors()[0];
        let detector_descriptor = detector.descriptor();
        let detector_digest = detector_descriptor.digest().expect("detector digest");
        let evaluator_artifact = nq_protocol::sha256_bytes(b"real-host-evaluator");
        let evaluated_at = parse_timestamp("2026-07-20T12:10:00.000Z").expect("evaluation time");
        let observed_at = parse_timestamp("2026-07-20T12:00:00.000Z").expect("report time");

        let mut store = Store::initialize(&live).expect("evaluation store");
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            profile,
        )
        .expect("compiled profile descriptor");
        let commit_result = |store: &mut Store,
                             evaluation_id: &str,
                             refusal_id: &str,
                             result: &nq_profiles::DetectorResult,
                             report_sequence: u64,
                             watermark_received_at: Option<&str>| {
            let governed_refusal = GovernedRefusal::profile(
                refusal_id.to_owned(),
                profile_semantic.clone(),
                result.refusal.clone().expect("real typed host refusal"),
            );
            let evaluation_profile = EvaluationProfileIdentity {
                profile: profile_descriptor.profile.clone(),
                profile_digest: profile_digest.clone(),
                profile_semantic_id: profile_semantic.clone(),
            };
            let governed_result = governed_evaluation_result(
                result,
                evaluation_profile.clone(),
                Some(governed_refusal.clone()),
            )
            .expect("wrap real detector result");
            let envelope = EvaluationEnvelopeV2 {
                schema: EvaluationEnvelopeSchema::V2,
                evaluation_id: evaluation_id.to_owned(),
                trigger_run_id: None,
                context: EvaluationContextV1 {
                    instance_id: watcher.instance_id.clone(),
                    subject: watcher.subject.clone(),
                    scope: watcher.scope.clone(),
                    vantage: watcher.vantage.clone(),
                },
                detector: EvaluationDetectorIdentity {
                    id: detector_descriptor.id.clone(),
                    version: detector_descriptor.version.to_string(),
                    digest: detector_digest.clone(),
                },
                evaluator_artifact_digest: evaluator_artifact.clone(),
                profile: evaluation_profile,
                started_at: evaluated_at,
                evaluated_at,
                watermark: EvaluationWatermarkV2 {
                    instance_id: watcher.instance_id.clone(),
                    max_report_sequence: report_sequence,
                    watermark_received_at: watermark_received_at
                        .map(parse_timestamp)
                        .transpose()
                        .expect("watermark time"),
                },
                result: governed_result,
            };
            store
                .begin_writer_session()
                .expect("writer session")
                .commit_evaluation(
                    &EvaluationInput {
                        evaluation_id: evaluation_id.to_owned(),
                        trigger_run_id: None,
                        detector_id: detector_descriptor.id.clone(),
                        detector_version: detector_descriptor.version.to_string(),
                        detector_digest: detector_digest.clone(),
                        evaluator_artifact_digest: evaluator_artifact.as_str().to_owned(),
                        started_at: timestamp(evaluated_at),
                        evaluated_at: timestamp(evaluated_at),
                        outcome: "cannot_evaluate".to_owned(),
                        detail: canonical(&envelope).expect("canonical real evaluation"),
                        profile: EvaluationProfileBinding {
                            profile_id: profile_descriptor.profile.id.clone(),
                            profile_version: profile_descriptor.profile.version.to_string(),
                            profile_digest: profile_digest.as_str().to_owned(),
                            profile_semantic_id: parse_identity_digest(
                                "profile_semantic_id",
                                profile_semantic.as_str(),
                            )
                            .expect("typed semantic identity"),
                        },
                        watermarks: vec![nq_store::EvaluationWatermark {
                            instance_id: watcher.instance_id.clone(),
                            max_report_sequence: i64::try_from(report_sequence)
                                .expect("report sequence fits SQLite"),
                            watermark_received_at: watermark_received_at.map(str::to_owned),
                        }],
                        refusal: Some(
                            stored_governed_refusal(&governed_refusal, evaluated_at)
                                .expect("stored real host refusal"),
                        ),
                    },
                    None,
                )
                .expect("commit real host evaluation");
            envelope
        };

        let missing = detector.evaluate(&DetectorInput {
            instance_id: &watcher.instance_id,
            evaluated_at,
            watermark: EvidenceWatermark(0),
            reports: &[],
        });
        let missing_envelope = commit_result(
            &mut store,
            "evaluation-real-host-missing",
            "refusal-real-host-missing",
            &missing,
            0,
            None,
        );

        let (stale_report, report_received_at, _) = commit_real_host_detector_report(
            &mut store,
            watcher,
            "report-real-host-stale",
            "real-host-stale",
            observed_at,
            1.0,
            None,
        );
        let report_sequence = stale_report.report_sequence;
        let stale = detector.evaluate(&DetectorInput {
            instance_id: &watcher.instance_id,
            evaluated_at,
            watermark: EvidenceWatermark(report_sequence),
            reports: std::slice::from_ref(&stale_report),
        });
        let stale_envelope = commit_result(
            &mut store,
            "evaluation-real-host-stale",
            "refusal-real-host-stale",
            &stale,
            report_sequence,
            Some(&report_received_at),
        );

        let missing_refusal = missing.refusal.as_ref().expect("typed missing refusal");
        let stale_refusal = stale.refusal.as_ref().expect("typed stale refusal");
        assert_eq!(missing.state, DetectorState::CannotEvaluate);
        assert_eq!(stale.state, DetectorState::CannotEvaluate);
        assert_eq!(missing_refusal.code, stale_refusal.code);
        assert_eq!(missing_refusal.boundary, stale_refusal.boundary);
        assert_eq!(
            missing_refusal.details.get("reason").map(String::as_str),
            Some("missing_testimony")
        );
        assert_eq!(
            stale_refusal.details.get("reason").map(String::as_str),
            Some("invalid_freshness")
        );
        assert_ne!(missing_refusal.details, stale_refusal.details);

        let assert_reopened = |store: &Store| {
            let page = evaluation_history_bounded(store, 10, None, None)
                .expect("reopen real host evaluation history");
            assert!(page.complete);
            assert_eq!(page.records.len(), 3);
            assert_eq!(
                page.records
                    .iter()
                    .find(|record| {
                        record.result.evaluation_id == "evaluation-real-host-missing"
                    })
                    .expect("missing-testimony evaluation")
                    .result,
                missing_envelope
            );
            assert_eq!(
                page.records
                    .iter()
                    .find(|record| record.result.evaluation_id == "evaluation-real-host-stale")
                    .expect("stale-testimony evaluation")
                    .result,
                stale_envelope
            );
            let status = status_snapshot_v3(store).expect("real host v3 status");
            let evaluation = status
                .components
                .iter()
                .find(|component| component.kind == ComponentKind::Evaluation)
                .expect("latest real host evaluation status");
            let ComponentStatusDetailV3::Evaluation { result, .. } = &evaluation.detail else {
                panic!("evaluation status carries exact governed envelope")
            };
            assert_eq!(result, &stale_envelope);
        };
        assert_reopened(&store);
        store.backup_verified(&backup).expect("verified backup");
        drop(store);
        let reopened = Store::open(&backup).expect("reopen verified backup");
        assert_reopened(&reopened);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn exhaustive_history_pagination_crosses_one_row_pages_and_checks_late_rows() {
        let mut store = Store::initialize_in_memory().expect("pagination store");
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            profile,
        )
        .expect("compiled profile descriptor");
        let profile_descriptor = profile.descriptor();
        let profile_digest = profile_descriptor.digest().expect("profile digest");
        let semantic_id = profile_semantic_id(profile_descriptor).expect("profile semantic id");
        let detector = profile.detectors()[0].descriptor();
        let detector_digest = detector.digest().expect("detector digest");

        for suffix in ["a", "b"] {
            let profile_identity = EvaluationProfileIdentity {
                profile: profile_descriptor.profile.clone(),
                profile_digest: profile_digest.clone(),
                profile_semantic_id: semantic_id.clone(),
            };
            let result = EvaluationResultV1 {
                schema: EvaluationResultSchema::V1,
                profile: profile_identity.clone(),
                state: DetectorState::ExplicitlyAbsent,
                condition: detector.condition.clone(),
                summary: format!("explicit absence fixture {suffix}"),
                evidence: Vec::new(),
                limitations: Vec::new(),
                refusal: None,
                watermark: EvidenceWatermark(0),
            };
            let evaluation_id = format!("evaluation-page-{suffix}");
            let evaluator_artifact = nq_protocol::sha256_bytes(b"pagination-evaluator");
            let envelope = EvaluationEnvelopeV2 {
                schema: EvaluationEnvelopeSchema::V2,
                evaluation_id: evaluation_id.clone(),
                trigger_run_id: None,
                context: EvaluationContextV1 {
                    instance_id: "pagination.instance".to_owned(),
                    subject: "pagination:subject".to_owned(),
                    scope: ScopeConfig {
                        kind: "fixture".to_owned(),
                        value: json!({"id": "pagination"}),
                    },
                    vantage: VantageConfig {
                        kind: "local".to_owned(),
                        value: json!({}),
                    },
                },
                detector: EvaluationDetectorIdentity {
                    id: detector.id.clone(),
                    version: detector.version.to_string(),
                    digest: detector_digest.clone(),
                },
                evaluator_artifact_digest: evaluator_artifact.clone(),
                profile: profile_identity,
                started_at: parse_timestamp("2026-07-20T12:00:00.000Z").expect("start"),
                evaluated_at: parse_timestamp("2026-07-20T12:00:01.000Z").expect("end"),
                watermark: EvaluationWatermarkV2 {
                    instance_id: "pagination.instance".to_owned(),
                    max_report_sequence: 0,
                    watermark_received_at: None,
                },
                result,
            };
            store
                .begin_writer_session()
                .expect("writer session")
                .commit_evaluation(
                    &EvaluationInput {
                        evaluation_id,
                        trigger_run_id: None,
                        detector_id: detector.id.clone(),
                        detector_version: detector.version.to_string(),
                        detector_digest: detector_digest.clone(),
                        evaluator_artifact_digest: evaluator_artifact.into_string(),
                        started_at: "2026-07-20T12:00:00.000Z".to_owned(),
                        evaluated_at: "2026-07-20T12:00:01.000Z".to_owned(),
                        outcome: "condition_explicitly_absent".to_owned(),
                        detail: canonical(&envelope).expect("canonical evaluation envelope"),
                        profile: EvaluationProfileBinding {
                            profile_id: profile_descriptor.profile.id.clone(),
                            profile_version: profile_descriptor.profile.version.to_string(),
                            profile_digest: profile_digest.as_str().to_owned(),
                            profile_semantic_id: parse_identity_digest(
                                "profile_semantic_id",
                                semantic_id.as_str(),
                            )
                            .expect("typed semantic id"),
                        },
                        watermarks: vec![nq_store::EvaluationWatermark {
                            instance_id: "pagination.instance".to_owned(),
                            max_report_sequence: 0,
                            watermark_received_at: None,
                        }],
                        refusal: None,
                    },
                    None,
                )
                .expect("commit paged evaluation");
        }
        assert_eq!(
            validate_evaluation_refusal_history_with_page_size(&store, 1)
                .expect("one-row evaluation pages"),
            2
        );
        let bare_v1 = EvaluationResultV1 {
            schema: EvaluationResultSchema::V1,
            profile: EvaluationProfileIdentity {
                profile: profile_descriptor.profile.clone(),
                profile_digest: profile_digest.clone(),
                profile_semantic_id: semantic_id.clone(),
            },
            state: DetectorState::ExplicitlyAbsent,
            condition: detector.condition.clone(),
            summary: "historical unwrapped v1".to_owned(),
            evidence: Vec::new(),
            limitations: Vec::new(),
            refusal: None,
            watermark: EvidenceWatermark(0),
        };
        store
            .begin_writer_session()
            .expect("writer session")
            .commit_evaluation(
                &EvaluationInput {
                    evaluation_id: "evaluation-page-v1-unwrapped".to_owned(),
                    trigger_run_id: None,
                    detector_id: detector.id.clone(),
                    detector_version: detector.version.to_string(),
                    detector_digest: detector_digest.clone(),
                    evaluator_artifact_digest: nq_protocol::sha256_bytes(b"pagination-evaluator")
                        .into_string(),
                    started_at: "2026-07-20T12:00:04.000Z".to_owned(),
                    evaluated_at: "2026-07-20T12:00:05.000Z".to_owned(),
                    outcome: "condition_explicitly_absent".to_owned(),
                    detail: canonical(&bare_v1).expect("preserved bare v1"),
                    profile: EvaluationProfileBinding {
                        profile_id: profile_descriptor.profile.id.clone(),
                        profile_version: profile_descriptor.profile.version.to_string(),
                        profile_digest: profile_digest.as_str().to_owned(),
                        profile_semantic_id: parse_identity_digest(
                            "profile_semantic_id",
                            semantic_id.as_str(),
                        )
                        .expect("semantic id"),
                    },
                    watermarks: vec![nq_store::EvaluationWatermark {
                        instance_id: "pagination.instance".to_owned(),
                        max_report_sequence: 0,
                        watermark_received_at: None,
                    }],
                    refusal: None,
                },
                None,
            )
            .expect("retain incompatible bare v1 evaluation");

        // A public page reopens only the rows it returns. The incompatible
        // third row remains frozen into the same snapshot and fails closed
        // when its page is requested; it cannot poison or be silently skipped
        // by an earlier valid bounded page.
        let first_public = evaluation_history_bounded(&store, 1, None, None)
            .expect("first bounded page does not materialize late history");
        assert_eq!(first_public.through_sequence, 3);
        assert_eq!(first_public.records.len(), 1);
        assert_eq!(
            first_public.records[0].result.result.summary,
            "explicit absence fixture a"
        );
        assert!(!first_public.complete);
        let second_public = evaluation_history_bounded(
            &store,
            1,
            first_public.next_after_sequence,
            Some(first_public.through_sequence),
        )
        .expect("second valid bounded page");
        assert_eq!(second_public.records.len(), 1);
        assert_eq!(
            second_public.records[0].result.result.summary,
            "explicit absence fixture b"
        );
        assert!(!second_public.complete);
        assert!(matches!(
            evaluation_history_bounded(
                &store,
                1,
                second_public.next_after_sequence,
                Some(second_public.through_sequence),
            ),
            Err(EngineError::Invariant(message)) if message.contains(EVALUATION_ENVELOPE_SCHEMA)
        ));
        assert!(matches!(
            validate_evaluation_refusal_history_with_page_size(&store, 1),
            Err(EngineError::Invariant(message)) if message.contains(EVALUATION_ENVELOPE_SCHEMA)
        ));

        store
            .begin_writer_session()
            .expect("writer session")
            .record_status(&StatusEventInput {
                status_event_id: "status-page-valid".to_owned(),
                component_kind: "database".to_owned(),
                component_id: "primary".to_owned(),
                state: "healthy".to_owned(),
                code: "ok".to_owned(),
                detail: canonical(&json!({"integrity": "ok"})).expect("diagnostic detail"),
                observed_at: "2026-07-20T12:00:02.000Z".to_owned(),
            })
            .expect("valid first status page");
        store
            .begin_writer_session()
            .expect("writer session")
            .record_status(&StatusEventInput {
                status_event_id: "status-page-malformed-late".to_owned(),
                component_kind: "instance".to_owned(),
                component_id: "late.invalid".to_owned(),
                state: "degraded".to_owned(),
                code: "collection_failed".to_owned(),
                detail: canonical(&json!({"legacy": "untyped"})).expect("hostile detail"),
                observed_at: "2026-07-20T12:00:03.000Z".to_owned(),
            })
            .expect("store hostile late status");
        assert!(matches!(
            validate_status_history_v2_with_page_size(&store, 1),
            Err(EngineError::Invariant(message))
                if message.contains("not a valid versioned collection result")
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn public_evaluation_history_crosses_the_maximum_page_without_silent_truncation() {
        let mut store = Store::initialize_in_memory().expect("pagination store");
        let profile: &'static dyn ProfileModule = &nq_profiles::host::MODULE;
        append_profile_descriptor(
            &mut store.begin_writer_session().expect("writer session"),
            profile,
        )
        .expect("compiled profile descriptor");
        let profile_descriptor = profile.descriptor();
        let profile_digest = profile_descriptor.digest().expect("profile digest");
        let semantic_id = profile_semantic_id(profile_descriptor).expect("profile semantic id");
        let detector = profile.detectors()[0].descriptor();
        let detector_digest = detector.digest().expect("detector digest");
        let evaluator_artifact = nq_protocol::sha256_bytes(b"maximum-page-evaluator");
        let evaluation_profile = EvaluationProfileIdentity {
            profile: profile_descriptor.profile.clone(),
            profile_digest: profile_digest.clone(),
            profile_semantic_id: semantic_id.clone(),
        };
        let context = EvaluationContextV1 {
            instance_id: "maximum-page.instance".to_owned(),
            subject: "host:maximum-page".to_owned(),
            scope: ScopeConfig {
                kind: "host".to_owned(),
                value: json!({"id": "maximum-page"}),
            },
            vantage: VantageConfig {
                kind: "local".to_owned(),
                value: json!({}),
            },
        };

        for index in 1..=nq_store::MAX_PUBLIC_QUERY_ROWS + 1 {
            let evaluation_id = format!("maximum-page-evaluation-{index:04}");
            let result = EvaluationResultV1 {
                schema: EvaluationResultSchema::V1,
                profile: evaluation_profile.clone(),
                state: DetectorState::ExplicitlyAbsent,
                condition: detector.condition.clone(),
                summary: format!("same-code payload {index}"),
                evidence: Vec::new(),
                limitations: Vec::new(),
                refusal: None,
                watermark: EvidenceWatermark(0),
            };
            let envelope = EvaluationEnvelopeV2 {
                schema: EvaluationEnvelopeSchema::V2,
                evaluation_id: evaluation_id.clone(),
                trigger_run_id: None,
                context: context.clone(),
                detector: EvaluationDetectorIdentity {
                    id: detector.id.clone(),
                    version: detector.version.to_string(),
                    digest: detector_digest.clone(),
                },
                evaluator_artifact_digest: evaluator_artifact.clone(),
                profile: evaluation_profile.clone(),
                started_at: parse_timestamp("2026-07-20T12:00:00.000Z").expect("start"),
                evaluated_at: parse_timestamp("2026-07-20T12:00:01.000Z").expect("end"),
                watermark: EvaluationWatermarkV2 {
                    instance_id: context.instance_id.clone(),
                    max_report_sequence: 0,
                    watermark_received_at: None,
                },
                result,
            };
            store
                .begin_writer_session()
                .expect("writer session")
                .commit_evaluation(
                    &EvaluationInput {
                        evaluation_id,
                        trigger_run_id: None,
                        detector_id: detector.id.clone(),
                        detector_version: detector.version.to_string(),
                        detector_digest: detector_digest.clone(),
                        evaluator_artifact_digest: evaluator_artifact.to_string(),
                        started_at: "2026-07-20T12:00:00.000Z".to_owned(),
                        evaluated_at: "2026-07-20T12:00:01.000Z".to_owned(),
                        outcome: "condition_explicitly_absent".to_owned(),
                        detail: canonical(&envelope).expect("canonical evaluation envelope"),
                        profile: EvaluationProfileBinding {
                            profile_id: profile_descriptor.profile.id.clone(),
                            profile_version: profile_descriptor.profile.version.to_string(),
                            profile_digest: profile_digest.as_str().to_owned(),
                            profile_semantic_id: parse_identity_digest(
                                "profile_semantic_id",
                                semantic_id.as_str(),
                            )
                            .expect("semantic id"),
                        },
                        watermarks: vec![nq_store::EvaluationWatermark {
                            instance_id: context.instance_id.clone(),
                            max_report_sequence: 0,
                            watermark_received_at: None,
                        }],
                        refusal: None,
                    },
                    None,
                )
                .expect("commit evaluation history row");
        }

        let first = evaluation_history_bounded(&store, nq_store::MAX_PUBLIC_QUERY_ROWS, None, None)
            .expect("first maximum-sized page");
        assert_eq!(first.records.len(), 1_000);
        assert!(!first.complete);
        assert_eq!(first.next_after_sequence, Some(1_000));
        assert_eq!(first.through_sequence, 1_001);
        assert_eq!(
            first.records[0].result.result.summary,
            "same-code payload 1"
        );
        assert!(matches!(
            evaluation_history_bounded(&store, 1, first.next_after_sequence, None),
            Err(EngineError::Invariant(message))
                if message == "evaluation history continuation requires its frozen upper bound"
        ));

        let second = evaluation_history_bounded(
            &store,
            nq_store::MAX_PUBLIC_QUERY_ROWS,
            first.next_after_sequence,
            Some(first.through_sequence),
        )
        .expect("late page");
        assert_eq!(second.records.len(), 1);
        assert!(second.complete);
        assert_eq!(second.next_after_sequence, None);
        assert_eq!(
            second.records[0].result.result.summary,
            "same-code payload 1001"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn same_code_protocol_rejection_pair_survives_wire_custody_status_backup_reopen() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let live = directory.path().join("protocol-pair.db");
        let backup = directory.path().join("protocol-pair-backup.db");
        let mut store = Store::initialize(&live).expect("protocol store");
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let cases: [(&str, &[u8]); 2] = [("framing", b"{}\n{}\n"), ("json", b"invalid-json\n")];
        let mut carriers = Vec::new();
        for (suffix, raw_bytes) in cases {
            let instance_id = format!("protocol.{suffix}");
            let framing_error = nq_protocol::decode_ndjson::<nq_protocol::HelperResponse>(
                raw_bytes,
                raw_bytes.len(),
            )
            .expect_err("hostile bytes must be rejected before admission");
            let failure = protocol_rejection(&instance_id, framing_error).failure;
            let admission = seed_compiled_admission(&mut store, profile, &instance_id, suffix);
            let run = test_run(
                &store,
                profile,
                &instance_id,
                suffix,
                admission,
                AcquisitionOutcome::Response,
            );
            let refusal = GovernedRefusal::protocol(
                format!("protocol-refusal-{suffix}"),
                ProtocolRejection {
                    responsible_instance_id: instance_id.clone(),
                    boundary: ProtocolRejectionBoundary::Response,
                    code: ProtocolRejectionCode::InvalidResponse,
                    failure,
                },
            );
            let carrier =
                CollectionOutcome::rejected(instance_id, run.run_id.clone(), refusal.clone());
            let wire = nq_protocol::encode_ndjson(&carrier).expect("encode protocol rejection");
            let decoded = decode_collection_outcome_ndjson(&wire, wire.len())
                .expect("decode protocol rejection");
            assert_eq!(decoded, carrier);
            let submission = SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes: raw_bytes.to_vec(),
                received_at: "2026-07-20T12:00:01.000Z".to_owned(),
                protocol_outcome: "rejected".to_owned(),
                disposition: SubmissionDisposition::Rejected {
                    refusal: stored_governed_refusal(
                        &refusal,
                        DateTime::parse_from_rfc3339("2026-07-20T12:00:01.000Z")
                            .expect("time")
                            .with_timezone(&Utc),
                    )
                    .expect("stored protocol refusal"),
                },
            };
            commit_test_non_success(&mut store, run, Some(submission), &carrier, suffix);
            carriers.push(carrier);
        }
        assert_ne!(
            canonical(&carriers[0]).expect("framing canonical"),
            canonical(&carriers[1]).expect("json canonical")
        );
        let assert_pair = |store: &Store| {
            let custody = rejected_custody_snapshot(store, 10).expect("typed custody");
            assert_eq!(custody.records.len(), 2);
            let mut failures = custody
                .records
                .iter()
                .map(|record| {
                    assert_eq!(record.protocol_outcome, "rejected");
                    let GovernedRefusalOrigin::Protocol(protocol) = &record.refusal.origin else {
                        panic!("protocol refusal origin")
                    };
                    assert_eq!(protocol.code, ProtocolRejectionCode::InvalidResponse);
                    protocol.failure.clone()
                })
                .collect::<Vec<_>>();
            failures.sort_by_key(|failure| {
                matches!(failure, ProtocolRejectionFailure::InvalidJson { .. })
            });
            assert!(matches!(
                failures[0],
                ProtocolRejectionFailure::InvalidFraming
            ));
            assert!(matches!(
                failures[1],
                ProtocolRejectionFailure::InvalidJson { .. }
            ));
            assert_eq!(
                validate_status_history_v2(store).expect("protocol status history"),
                2
            );
            assert_eq!(
                validate_watcher_run_history_with_page_size(store, 1)
                    .expect("one-row watcher-run pages"),
                2
            );
            assert_eq!(
                validate_status_history_v2_with_page_size(store, 1).expect("one-row status pages"),
                2
            );
            assert_eq!(
                validate_rejected_custody_history(store).expect("protocol custody history"),
                2
            );
            assert_eq!(
                validate_rejected_custody_history_with_page_size(store, 1)
                    .expect("one-row custody pages"),
                2
            );
        };
        assert_pair(&store);
        backup_store(&mut store, &backup).expect("semantic backup");
        drop(store);
        let reopened = Store::open(&backup).expect("reopen protocol backup");
        assert_pair(&reopened);

        let mut hostile = Store::initialize_in_memory().expect("hostile protocol store");
        let instance_id = "protocol.substituted";
        let admission =
            seed_compiled_admission(&mut hostile, profile, instance_id, "protocol-substituted");
        let run = test_run(
            &hostile,
            profile,
            instance_id,
            "protocol-substituted",
            admission,
            AcquisitionOutcome::Response,
        );
        let refusal = GovernedRefusal::protocol(
            "protocol-refusal-substituted".to_owned(),
            ProtocolRejection {
                responsible_instance_id: instance_id.to_owned(),
                boundary: ProtocolRejectionBoundary::Response,
                code: ProtocolRejectionCode::InvalidResponse,
                failure: ProtocolRejectionFailure::InvalidFraming,
            },
        );
        let carrier = CollectionOutcome::rejected(
            instance_id.to_owned(),
            run.run_id.clone(),
            refusal.clone(),
        );
        let submission = SubmissionInput {
            submission_id: "submission-protocol-substituted".to_owned(),
            raw_bytes: b"{}\n{}\n".to_vec(),
            received_at: "2026-07-20T12:00:01.000Z".to_owned(),
            // A protocol parse rejection cannot be relabeled as a valid helper
            // refusal merely because both are rejected custody.
            protocol_outcome: "valid_refusal".to_owned(),
            disposition: SubmissionDisposition::Rejected {
                refusal: stored_governed_refusal(
                    &refusal,
                    DateTime::parse_from_rfc3339("2026-07-20T12:00:01.000Z")
                        .expect("time")
                        .with_timezone(&Utc),
                )
                .expect("stored refusal"),
            },
        };
        commit_test_non_success(
            &mut hostile,
            run,
            Some(submission),
            &carrier,
            "protocol-substituted",
        );
        assert!(matches!(
            rejected_custody_snapshot(&hostile, 10),
            Err(EngineError::Invariant(message))
                if message.contains("canonical refusal projections")
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn status_store_and_backup_preserve_same_code_distinct_detail() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let (mut config, first_watcher, _lock) = binding_recovery_fixture(directory.path());
        let mut second_watcher = first_watcher.clone();
        second_watcher.instance_id = "recovery.secondary".to_owned();
        config.watchers.push(second_watcher.clone());
        drop(Store::initialize(&config.database_path).expect("initialize status store"));
        let mut engine = CollectionEngine::open(&config).expect("open engine");
        let outcome = |watcher: &WatcherConfig, run_id: &str, message: &str| {
            CollectionOutcome::acquisition_failed(
                watcher.instance_id.clone(),
                run_id.to_owned(),
                AcquisitionOutcome::CarrierStartupFailed {
                    message: message.to_owned(),
                },
            )
            .expect("typed acquisition outcome")
        };
        let first_message = "helper socket mode is 0o660; expected 0o600";
        let second_message = "could not spawn Unix helper: Permission denied (os error 13)";
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let first_failure = AcquisitionOutcome::CarrierStartupFailed {
            message: first_message.to_owned(),
        };
        let first_admission = seed_compiled_admission(
            &mut engine.store,
            profile,
            &first_watcher.instance_id,
            "status-first",
        );
        let first_run = test_run(
            &engine.store,
            profile,
            &first_watcher.instance_id,
            "status-first",
            first_admission,
            first_failure,
        );
        let first_outcome = outcome(&first_watcher, &first_run.run_id, first_message);
        commit_test_non_success(
            &mut engine.store,
            first_run,
            None,
            &first_outcome,
            "status-first",
        );
        let second_failure = AcquisitionOutcome::CarrierStartupFailed {
            message: second_message.to_owned(),
        };
        let second_admission = seed_compiled_admission(
            &mut engine.store,
            profile,
            &second_watcher.instance_id,
            "status-second",
        );
        let second_run = test_run(
            &engine.store,
            profile,
            &second_watcher.instance_id,
            "status-second",
            second_admission,
            second_failure,
        );
        let second_outcome = outcome(&second_watcher, &second_run.run_id, second_message);
        commit_test_non_success(
            &mut engine.store,
            second_run,
            None,
            &second_outcome,
            "status-second",
        );

        let assert_exact = |snapshot: &StatusSnapshotV2| {
            let first = snapshot
                .components
                .iter()
                .find(|component| component.id == first_watcher.instance_id)
                .expect("first status");
            let second = snapshot
                .components
                .iter()
                .find(|component| component.id == second_watcher.instance_id)
                .expect("second status");
            assert_eq!(first.code, "collection_failed");
            assert_eq!(second.code, "collection_failed");
            let ComponentStatusDetailV2::Collection { result: first } = &first.detail else {
                panic!("instance status must be typed")
            };
            let ComponentStatusDetailV2::Collection { result: second } = &second.detail else {
                panic!("instance status must be typed")
            };
            let CollectionResult::AcquisitionFailed { failure: first } = &first.result else {
                panic!("first acquisition failure")
            };
            let CollectionResult::AcquisitionFailed { failure: second } = &second.result else {
                panic!("second acquisition failure")
            };
            assert_eq!(first.class, second.class);
            assert_eq!(first.retry, RetryDisposition::Unspecified);
            assert_eq!(second.retry, RetryDisposition::Unspecified);
            assert_ne!(first.outcome, second.outcome);
            assert!(matches!(
                &first.outcome,
                AcquisitionOutcome::CarrierStartupFailed { message } if message == first_message
            ));
            assert!(matches!(
                &second.outcome,
                AcquisitionOutcome::CarrierStartupFailed { message } if message == second_message
            ));
        };

        assert_exact(&status_snapshot_v2(&engine.store).expect("live v2 status"));
        let backup = directory.path().join("nq-status-backup.db");
        let artifact = engine
            .store
            .backup_verified(&backup)
            .expect("verified backup");
        drop(engine);
        let reopened = Store::open(&artifact.path).expect("reopen backup");
        assert_exact(&status_snapshot_v2(&reopened).expect("reopened v2 status"));
    }

    #[test]
    fn status_v2_rejects_substituted_state_and_code_projection() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let mut store = Store::initialize(directory.path().join("status.db")).expect("store");
        let outcome = CollectionOutcome::acquisition_failed(
            "projection.primary".to_owned(),
            "run-projection".to_owned(),
            AcquisitionOutcome::Timeout,
        )
        .expect("typed timeout");
        store
            .begin_writer_session()
            .expect("writer session")
            .record_status(&StatusEventInput {
                status_event_id: "status-substituted".to_owned(),
                component_kind: "instance".to_owned(),
                component_id: "projection.primary".to_owned(),
                state: "healthy".to_owned(),
                code: "report_complete".to_owned(),
                detail: canonical(&outcome).expect("canonical outcome"),
                observed_at: timestamp(Utc::now()),
            })
            .expect("record substituted projection");
        assert!(matches!(
            status_snapshot_v2(&store),
            Err(EngineError::Invariant(message)) if message.contains("typed result requires")
        ));

        let acquisition_refusal = GovernedRefusal::acquisition(
            "refusal-acquisition".to_owned(),
            AcquisitionRefusal {
                responsible_instance_id: "projection.primary".to_owned(),
                failure: AcquisitionFailure::from_outcome(AcquisitionOutcome::MalformedJson {
                    message: "not an object".to_owned(),
                })
                .expect("acquisition refusal"),
            },
        );
        let rejected = CollectionOutcome::rejected(
            "projection.primary".to_owned(),
            "run-rejected".to_owned(),
            acquisition_refusal,
        );
        assert_eq!(
            instance_status_projection(&rejected).expect("projection"),
            InstanceStatusProjection {
                state: "failed",
                code: "collection_failed",
            }
        );
    }

    #[test]
    fn run_profile_digest_and_semantic_substitution_fail_closed() {
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let descriptor = profile.descriptor();
        let mut run = nq_store::WatcherRunOutcomeRow {
            run_id: "run-profile-binding".to_owned(),
            request_id: "request-profile-binding".to_owned(),
            instance_id: "profile.binding".to_owned(),
            admission_id: Some("admission-profile-binding".to_owned()),
            profile_id: descriptor.profile.id.clone(),
            profile_version: descriptor.profile.version.to_string(),
            profile_digest: descriptor
                .digest()
                .expect("profile digest")
                .as_str()
                .to_owned(),
            admission_instance_id: Some("profile.binding".to_owned()),
            admission_profile_id: Some(descriptor.profile.id.clone()),
            admission_profile_version: Some(descriptor.profile.version.to_string()),
            admission_profile_digest: Some(
                descriptor
                    .digest()
                    .expect("profile digest")
                    .as_str()
                    .to_owned(),
            ),
            profile_semantic_id: Some(
                profile_semantic_id(descriptor)
                    .expect("profile semantic identity")
                    .as_str()
                    .to_owned(),
            ),
            admission_detector_identity_digest: Some(
                detector_identity_digest(profile)
                    .expect("detector suite identity")
                    .into_string(),
            ),
            admission_evaluator_artifact_digest: Some(
                nq_protocol::sha256_bytes(b"profile-binding-evaluator").into_string(),
            ),
            acquisition_outcome: "response".to_owned(),
            resource_outcome_json: test_run_resource(AcquisitionOutcome::Response)
                .as_bytes()
                .to_vec(),
        };
        validate_run_profile_identity(&run).expect("exact compiled profile binding");
        let mut wrong_admission_instance = run.clone();
        wrong_admission_instance.admission_instance_id = Some("profile.other".to_owned());
        let mut wrong_admission_profile = run.clone();
        wrong_admission_profile.admission_profile_id = Some("nq.other".to_owned());
        let mut wrong_admission_version = run.clone();
        wrong_admission_version.admission_profile_version = Some("999".to_owned());
        let mut wrong_admission_digest = run.clone();
        wrong_admission_digest.admission_profile_digest =
            Some(nq_protocol::sha256_bytes(b"another admission profile descriptor").into_string());
        for substituted in [
            wrong_admission_instance,
            wrong_admission_profile,
            wrong_admission_version,
            wrong_admission_digest,
        ] {
            assert!(matches!(
                validate_run_profile_identity(&substituted),
                Err(EngineError::Invariant(message))
                    if message.contains("borrowed admission admission-profile-binding")
            ));
        }
        let substituted_digest = nq_protocol::sha256_bytes(b"substituted descriptor").into_string();
        run.profile_digest.clone_from(&substituted_digest);
        run.admission_profile_digest = Some(substituted_digest);
        assert!(matches!(
            validate_run_profile_identity(&run),
            Err(EngineError::Invariant(message))
                if message.contains("profile digest, semantic identity, or detector suite was substituted")
        ));
        run.profile_digest = descriptor
            .digest()
            .expect("profile digest")
            .as_str()
            .to_owned();
        run.admission_profile_digest = Some(run.profile_digest.clone());
        run.profile_semantic_id =
            Some(nq_protocol::sha256_bytes(b"substituted semantics").into_string());
        assert!(matches!(
            validate_run_profile_identity(&run),
            Err(EngineError::Invariant(message))
                if message.contains("profile digest, semantic identity, or detector suite was substituted")
        ));
        run.profile_semantic_id = Some(
            profile_semantic_id(descriptor)
                .expect("profile semantic identity")
                .as_str()
                .to_owned(),
        );
        run.admission_detector_identity_digest =
            Some(nq_protocol::sha256_bytes(b"substituted detector suite").into_string());
        assert!(matches!(
            validate_run_profile_identity(&run),
            Err(EngineError::Invariant(message))
                if message.contains("profile digest, semantic identity, or detector suite was substituted")
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn hostile_same_profile_borrowed_admission_fails_on_late_reopen() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let database = directory.path().join("borrowed-admission.db");
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let mut store = Store::initialize(&database).expect("initialize hostile store");
        let owner_admission =
            seed_compiled_admission(&mut store, profile, "binding.owner", "owner");
        let borrower_admission =
            seed_compiled_admission(&mut store, profile, "binding.borrower", "borrower");
        let owner_run = test_run(
            &store,
            profile,
            "binding.owner",
            "a-valid",
            owner_admission.clone(),
            AcquisitionOutcome::Timeout,
        );
        let owner_outcome = CollectionOutcome::acquisition_failed(
            "binding.owner".to_owned(),
            owner_run.run_id.clone(),
            AcquisitionOutcome::Timeout,
        )
        .expect("owner timeout result");
        commit_test_non_success(&mut store, owner_run, None, &owner_outcome, "a-valid");
        let borrower_run = test_run(
            &store,
            profile,
            "binding.borrower",
            "z-borrowed",
            borrower_admission,
            AcquisitionOutcome::Timeout,
        );
        let mut rejected_by_api = borrower_run.clone();
        rejected_by_api.admission_id = Some(owner_admission.clone());
        let borrower_outcome = CollectionOutcome::acquisition_failed(
            "binding.borrower".to_owned(),
            borrower_run.run_id.clone(),
            AcquisitionOutcome::Timeout,
        )
        .expect("borrower timeout result");
        let borrower_projection =
            instance_status_projection(&borrower_outcome).expect("borrower status projection");
        let rejected_collection =
            test_collection(&mut store, rejected_by_api, None, "z-borrowed-api");
        assert!(matches!(
            store
                .begin_writer_session()
                .expect("writer session")
                .commit_non_success_collection(
                &rejected_collection,
                &RunResultStatusInput {
                    run_id: borrower_run.run_id.clone(),
                    status: StatusEventInput {
                        status_event_id: "status-z-borrowed-api".to_owned(),
                        component_kind: "instance".to_owned(),
                        component_id: borrower_run.instance_id.clone(),
                        state: borrower_projection.state.to_owned(),
                        code: borrower_projection.code.to_owned(),
                        detail: canonical(&borrower_outcome).expect("borrower result"),
                        observed_at: "2026-07-20T12:00:01.000Z".to_owned(),
                    },
                },
            ),
            Err(nq_store::StoreError::Invariant(message))
                if message.contains("provider intake identity does not match NQ-owned admission facts")
        ));
        assert_eq!(
            validate_watcher_run_history_with_page_size(&store, 1)
                .expect("exact owner binding reopens"),
            1
        );
        drop(store);

        let hostile = rusqlite::Connection::open(&database).expect("open raw hostile writer");
        assert_eq!(
            hostile
                .execute(
                    "INSERT INTO watcher_runs (
                        run_id, request_id, instance_id, admission_id, binding_digest,
                        checkpoint_contract_digest, profile_id, profile_version,
                        profile_digest, carrier, started_at, deadline_at, finished_at,
                        acquisition_outcome, execution_identity_json, resource_outcome_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                               ?12, ?13, ?14, ?15, ?16)",
                    rusqlite::params![
                        borrower_run.run_id,
                        borrower_run.request_id,
                        borrower_run.instance_id,
                        owner_admission,
                        borrower_run.binding_digest,
                        borrower_run.checkpoint_contract_digest,
                        borrower_run.profile_id,
                        borrower_run.profile_version,
                        borrower_run.profile_digest,
                        borrower_run.carrier,
                        borrower_run.started_at,
                        borrower_run.deadline_at,
                        borrower_run.finished_at,
                        borrower_run.acquisition_outcome,
                        borrower_run.execution_identity.as_bytes(),
                        borrower_run.resource_outcome.as_bytes(),
                    ],
                )
                .expect("insert borrowed same-profile admission outside typed API"),
            1
        );
        assert_eq!(
            hostile
                .execute(
                    "INSERT INTO status_events (
                        status_event_id, component_kind, component_id, run_id,
                        state, code, detail_json, observed_at
                     ) VALUES (?1, 'instance', ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        "status-z-borrowed-hostile",
                        &borrower_run.instance_id,
                        &borrower_run.run_id,
                        borrower_projection.state,
                        borrower_projection.code,
                        canonical(&borrower_outcome)
                            .expect("hostile borrower result")
                            .as_bytes(),
                        "2026-07-20T12:00:01.000Z",
                    ],
                )
                .expect("insert canonical result outside typed API"),
            1
        );
        assert_eq!(
            hostile
                .execute(
                    "INSERT INTO status_current (
                        component_kind, component_id, latest_status_event_id
                     ) VALUES ('instance', ?1, 'status-z-borrowed-hostile')",
                    [&borrower_run.instance_id],
                )
                .expect("materialize hostile canonical result"),
            1
        );
        drop(hostile);

        assert!(matches!(
            Store::open(&database),
            Err(nq_store::StoreError::Integrity(message))
                if message.contains("must have exactly one real provider intake or explicit v3 gap")
        ));
    }

    #[test]
    fn status_history_validation_cannot_hide_legacy_event_behind_typed_current() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let mut store = Store::initialize(directory.path().join("history.db")).expect("store");
        let observed_at = timestamp(Utc::now());
        store
            .begin_writer_session()
            .expect("writer session")
            .record_status(&StatusEventInput {
                status_event_id: "status-legacy".to_owned(),
                component_kind: "instance".to_owned(),
                component_id: "history.primary".to_owned(),
                state: "failed".to_owned(),
                code: "legacy_failure".to_owned(),
                detail: canonical(&json!({"diagnostic": "untyped legacy result"}))
                    .expect("legacy detail"),
                observed_at: observed_at.clone(),
            })
            .expect("record legacy event");
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let admission =
            seed_compiled_admission(&mut store, profile, "history.primary", "history-current");
        let run = test_run(
            &store,
            profile,
            "history.primary",
            "history-current",
            admission,
            AcquisitionOutcome::Timeout,
        );
        let current = CollectionOutcome::acquisition_failed(
            "history.primary".to_owned(),
            run.run_id.clone(),
            AcquisitionOutcome::Timeout,
        )
        .expect("typed current result");
        commit_test_non_success(&mut store, run, None, &current, "history-current");

        assert!(matches!(
            status_snapshot_v2(&store),
            Err(EngineError::Invariant(message)) if message.contains("not a valid versioned collection result")
        ));
        assert!(matches!(
            validate_status_history_v2(&store),
            Err(EngineError::Invariant(message)) if message.contains("not a valid versioned collection result")
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn same_refusal_id_with_different_payload_is_rejected_on_status_reopen() {
        const TIME: &str = "2026-07-20T12:00:00.000Z";
        let directory = tempfile::tempdir().expect("fixture directory");
        let mut store = Store::initialize(directory.path().join("refusal.db")).expect("store");
        let instance = InstanceId::new("refusal.primary").expect("instance");
        let helper_refusal = |retriable: bool, errno: &str| nq_protocol::Refusal {
            responsible_instance_id: instance.clone(),
            boundary: nq_protocol::RefusalBoundary::Collection,
            code: nq_protocol::RefusalCode::CollectionFailed,
            message: "backend collection failed".to_owned(),
            retriable,
            details: json!({"errno": errno}),
        };
        let original =
            GovernedRefusal::helper("refusal-stable".to_owned(), helper_refusal(true, "EAGAIN"));
        let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
        let admission =
            seed_compiled_admission(&mut store, profile, instance.as_str(), "refusal-stable");
        let run = test_run(
            &store,
            profile,
            instance.as_str(),
            "refusal-stable",
            admission,
            AcquisitionOutcome::Response,
        );
        let run_id = run.run_id.clone();
        let valid =
            CollectionOutcome::rejected(instance.to_string(), run_id.clone(), original.clone());
        let submission = SubmissionInput {
            submission_id: "submission-refusal-stable".to_owned(),
            raw_bytes: b"helper refusal\n".to_vec(),
            received_at: "2026-07-20T12:00:01.000Z".to_owned(),
            protocol_outcome: "valid_refusal".to_owned(),
            disposition: SubmissionDisposition::Rejected {
                refusal: stored_governed_refusal(
                    &original,
                    DateTime::parse_from_rfc3339(TIME)
                        .expect("time")
                        .with_timezone(&Utc),
                )
                .expect("stored refusal"),
            },
        };
        commit_test_non_success(&mut store, run, Some(submission), &valid, "refusal-stable");
        assert_eq!(
            validate_rejected_custody_history(&store).expect("validate complete custody"),
            1
        );

        assert!(status_snapshot_v2(&store).is_ok());
        assert_eq!(
            validate_status_history_v2(&store).expect("valid status history"),
            1
        );

        let substituted = CollectionOutcome::rejected(
            instance.to_string(),
            run_id,
            GovernedRefusal::helper("refusal-stable".to_owned(), helper_refusal(false, "ENODEV")),
        );
        store
            .begin_writer_session()
            .expect("writer session")
            .record_status(&StatusEventInput {
                status_event_id: "status-refusal-substituted".to_owned(),
                component_kind: "instance".to_owned(),
                component_id: instance.to_string(),
                state: "degraded".to_owned(),
                code: "helper_refused".to_owned(),
                detail: canonical(&substituted).expect("substituted status detail"),
                observed_at: TIME.to_owned(),
            })
            .expect("record hostile substituted status");
        assert!(matches!(
            status_snapshot_v2(&store),
            Err(EngineError::Invariant(message)) if message.contains("disagrees with linked refusal")
        ));
        assert!(validate_status_history_v2(&store).is_err());
    }

    #[test]
    fn carrier_startup_detail_survives_dry_and_canonical_surfaces() {
        let mode = AcquisitionOutcome::CarrierStartupFailed {
            message: "helper socket mode is 0o660; expected 0o600".to_owned(),
        };
        let timeout = AcquisitionOutcome::CarrierStartupFailed {
            message: "supervised helper did not become ready within 30s".to_owned(),
        };
        assert_eq!(acquisition_code(&mode), acquisition_code(&timeout));
        let render = |outcome: &AcquisitionOutcome| {
            EngineError::AcquisitionFailed(Box::new(
                AcquisitionFailure::from_outcome(outcome.clone()).expect("failure"),
            ))
            .to_string()
        };
        assert!(render(&mode).contains("helper socket mode is 0o660"));
        assert!(render(&timeout).contains("did not become ready within 30s"));
        assert_ne!(render(&mode), render(&timeout));
    }

    /// Release forcing case: persistent-carrier timeout phase is dependent
    /// refusal testimony, not decoration on the coarse `timeout` code.  The
    /// write and read phases must remain distinguishable in the dry-collection
    /// diagnostic and in the canonical `CollectionOutcome` persisted by
    /// `record_instance_status`.
    ///
    #[test]
    fn forcing_exchange_timeout_phase_survives_dry_and_status_surfaces() {
        let write = AcquisitionOutcome::ExchangeTimeout {
            phase: ExchangeTimeoutPhase::WriteRequest,
        };
        let read = AcquisitionOutcome::ExchangeTimeout {
            phase: ExchangeTimeoutPhase::ReadResponse,
        };

        assert_eq!(acquisition_code(&write), "timeout");
        assert_eq!(acquisition_code(&read), "timeout");

        let dry = |outcome: &AcquisitionOutcome| {
            EngineError::AcquisitionFailed(Box::new(
                AcquisitionFailure::from_outcome(outcome.clone()).expect("failure"),
            ))
            .to_string()
        };
        let dry_write = dry(&write);
        let dry_read = dry(&read);
        let status = |outcome: &AcquisitionOutcome| {
            let carrier = CollectionOutcome::acquisition_failed(
                "conformance-local".to_owned(),
                "00000000-0000-4000-8000-000000000000".to_owned(),
                outcome.clone(),
            )
            .expect("typed status outcome");
            canonical(&carrier).expect("status outcome canonicalizes")
        };
        let stored_write = status(&write);
        let stored_read = status(&read);

        assert_ne!(dry_write, dry_read);
        assert!(dry_write.contains("write_request"));
        assert!(dry_read.contains("read_response"));
        assert_ne!(stored_write.as_bytes(), stored_read.as_bytes());
        let reopened =
            decode_collection_outcome(stored_write.as_bytes()).expect("reopen timeout result");
        assert!(matches!(
            reopened.result,
            CollectionResult::AcquisitionFailed {
                failure: AcquisitionFailure {
                    class: AcquisitionFailureClass::Timeout,
                    retry: RetryDisposition::Unspecified,
                    outcome: AcquisitionOutcome::ExchangeTimeout { ref phase },
                },
            } if phase == &ExchangeTimeoutPhase::WriteRequest
        ));
    }

    #[test]
    fn exchange_timeout_phase_is_closed_and_required() {
        let exact = serde_json::to_value(AcquisitionOutcome::ExchangeTimeout {
            phase: ExchangeTimeoutPhase::WriteRequest,
        })
        .expect("timeout value");
        for invalid_phase in [json!(""), json!("connect"), json!(null)] {
            let mut invalid = exact.clone();
            invalid["phase"] = invalid_phase;
            assert!(serde_json::from_value::<AcquisitionOutcome>(invalid).is_err());
        }
        let mut omitted = exact;
        omitted
            .as_object_mut()
            .expect("timeout object")
            .remove("phase");
        assert!(serde_json::from_value::<AcquisitionOutcome>(omitted).is_err());
    }

    /// Release forcing case: `retriable` and structured details are part of a
    /// protocol refusal's typed testimony. Two same-code refusals that differ
    /// in those fields must not become one status event merely because their
    /// operator-facing message is the same.
    #[test]
    fn forcing_protocol_refusal_dependent_fields_survive_collection_status() {
        let instance = InstanceId::new("conformance-local").expect("instance token");
        let transient = nq_protocol::Refusal {
            responsible_instance_id: instance.clone(),
            boundary: nq_protocol::RefusalBoundary::Collection,
            code: nq_protocol::RefusalCode::CollectionFailed,
            message: "backend collection failed".to_owned(),
            retriable: true,
            details: json!({"errno": "EAGAIN", "attempt": 1}),
        };
        let permanent = nq_protocol::Refusal {
            responsible_instance_id: instance,
            boundary: nq_protocol::RefusalBoundary::Collection,
            code: nq_protocol::RefusalCode::CollectionFailed,
            message: "backend collection failed".to_owned(),
            retriable: false,
            details: json!({"errno": "ENODEV", "device": "nvme0"}),
        };
        let source_transient = nq_protocol::canonical_json_bytes(&transient)
            .expect("typed transient refusal canonicalizes");
        let source_permanent = nq_protocol::canonical_json_bytes(&permanent)
            .expect("typed permanent refusal canonicalizes");
        assert_ne!(source_transient, source_permanent);

        let carrier = |refusal_id: &str, refusal: &nq_protocol::Refusal| {
            CollectionOutcome::rejected(
                refusal.responsible_instance_id.to_string(),
                "00000000-0000-4000-8000-000000000000".to_owned(),
                GovernedRefusal::helper(refusal_id.to_owned(), refusal.clone()),
            )
        };
        let transient_carrier = carrier("refusal-transient", &transient);
        let permanent_carrier = carrier("refusal-permanent", &permanent);
        let stored_transient =
            canonical(&transient_carrier).expect("transient status canonicalizes");
        let stored_permanent =
            canonical(&permanent_carrier).expect("permanent status canonicalizes");

        assert_ne!(
            stored_transient.as_bytes(),
            stored_permanent.as_bytes(),
            "typed protocol refusals collapsed in status: {}",
            String::from_utf8_lossy(stored_transient.as_bytes())
        );
        let reopened =
            decode_collection_outcome(stored_transient.as_bytes()).expect("reopen helper refusal");
        assert!(matches!(
            reopened.result,
            CollectionResult::Rejected {
                refusal: GovernedRefusal {
                    origin: GovernedRefusalOrigin::Helper(ref source),
                    ..
                },
            } if source.retriable && source.details == json!({"errno": "EAGAIN", "attempt": 1})
        ));

        let transient_wire =
            nq_protocol::encode_ndjson(&transient_carrier).expect("encode transient carrier");
        let permanent_wire =
            nq_protocol::encode_ndjson(&permanent_carrier).expect("encode permanent carrier");
        assert_ne!(transient_wire, permanent_wire);
        let transient_decoded =
            decode_collection_outcome_ndjson(&transient_wire, transient_wire.len())
                .expect("decode transient carrier");
        let permanent_decoded =
            decode_collection_outcome_ndjson(&permanent_wire, permanent_wire.len())
                .expect("decode permanent carrier");
        transient_decoded
            .validate()
            .expect("validate transient wire");
        permanent_decoded
            .validate()
            .expect("validate permanent wire");
        assert_eq!(transient_decoded, transient_carrier);
        assert_eq!(permanent_decoded, permanent_carrier);
    }

    /// Release forcing case: profile identity, exact refusing boundary, and
    /// structured details remain part of a `ProfileRefusal` even when code and
    /// message coincide.  The status carrier must preserve those dependent
    /// fields instead of reducing both refusals to `plane = profile`.
    #[test]
    fn forcing_profile_refusal_identity_survives_collection_status() {
        let report = nq_profiles::ProfileRefusal {
            instance_id: "conformance-local".to_owned(),
            profile: nq_profiles::ProfileKey::new("nq.conformance", 1),
            boundary: nq_profiles::RefusalBoundary::Report,
            code: nq_profiles::ProfileRefusalCode::InvalidPayload,
            message: "payload is invalid".to_owned(),
            details: BTreeMap::from([("field".to_owned(), "status".to_owned())]),
        };
        let observation = nq_profiles::ProfileRefusal {
            instance_id: "conformance-local".to_owned(),
            profile: nq_profiles::host::MODULE.descriptor().profile.clone(),
            boundary: nq_profiles::RefusalBoundary::Observation,
            code: nq_profiles::ProfileRefusalCode::InvalidPayload,
            message: "payload is invalid".to_owned(),
            details: BTreeMap::from([("ordinal".to_owned(), "4".to_owned())]),
        };
        let source_report =
            nq_protocol::canonical_json_bytes(&report).expect("typed report refusal canonicalizes");
        let source_observation = nq_protocol::canonical_json_bytes(&observation)
            .expect("typed observation refusal canonicalizes");
        assert_ne!(source_report, source_observation);

        let status = |refusal_id: &str, refusal: &nq_profiles::ProfileRefusal| {
            let compiled = nq_profiles::resolve_profile_key(&refusal.profile)
                .expect("test profile is compiled");
            let semantic_id =
                profile_semantic_id(compiled.descriptor()).expect("test profile semantic identity");
            let carrier = CollectionOutcome::rejected(
                refusal.instance_id.clone(),
                "00000000-0000-4000-8000-000000000000".to_owned(),
                GovernedRefusal::profile(refusal_id.to_owned(), semantic_id, refusal.clone()),
            );
            canonical(&carrier).expect("status outcome canonicalizes")
        };
        let stored_report = status("refusal-report", &report);
        let stored_observation = status("refusal-observation", &observation);

        assert_ne!(
            stored_report.as_bytes(),
            stored_observation.as_bytes(),
            "typed profile refusals collapsed in status: {}",
            String::from_utf8_lossy(stored_report.as_bytes())
        );
        let reopened = decode_collection_outcome(stored_observation.as_bytes())
            .expect("reopen profile refusal");
        assert!(matches!(
            reopened.result,
            CollectionResult::Rejected {
                refusal: GovernedRefusal {
                    origin: GovernedRefusalOrigin::Profile(ref source),
                    ..
                },
            } if source.refusal.profile == nq_profiles::host::MODULE.descriptor().profile
                && source.refusal.boundary == nq_profiles::RefusalBoundary::Observation
                && source.refusal.details.get("ordinal").map(String::as_str) == Some("4")
        ));

        let empty_details = CollectionOutcome::rejected(
            "conformance-local".to_owned(),
            "run-empty-profile-details".to_owned(),
            GovernedRefusal::profile(
                "refusal-empty-profile-details".to_owned(),
                profile_semantic_id(nq_profiles::conformance::MODULE.descriptor())
                    .expect("conformance semantic identity"),
                nq_profiles::ProfileRefusal {
                    instance_id: "conformance-local".to_owned(),
                    profile: nq_profiles::ProfileKey::new("nq.conformance", 1),
                    boundary: nq_profiles::RefusalBoundary::Report,
                    code: nq_profiles::ProfileRefusalCode::InvalidPayload,
                    message: "payload is invalid".to_owned(),
                    details: BTreeMap::new(),
                },
            ),
        );
        let mut strict_value =
            serde_json::to_value(&empty_details).expect("strict profile refusal value");
        assert_eq!(
            strict_value["result"]["refusal"]["origin"]["payload"]["refusal"]["details"],
            json!({}),
            "empty structured details remain an explicit governed field"
        );
        strict_value["result"]["refusal"]["origin"]["payload"]["refusal"]
            .as_object_mut()
            .expect("profile refusal payload")
            .remove("details");
        let omitted_details = nq_protocol::canonical_json_bytes(&strict_value)
            .expect("canonical omitted-details fixture");
        assert!(
            decode_collection_outcome(&omitted_details).is_err(),
            "profile refusal details must not default during historical reopen"
        );
    }
}
