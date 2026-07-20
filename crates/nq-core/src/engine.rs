//! End-to-end collection, admission, evaluation, and public read-model wiring.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
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
    EvaluationCommitInput, EvaluationInput, EvaluationProfileBinding, EvidenceSnapshot,
    FindingEventInput, FindingEvidenceInput, FindingSnapshotRow, GenesisInput, ObservationInput,
    ProfileDescriptorInput, RefusalInput, ReportErrorInput, ReportInput, RunInput,
    RunResultStatusInput, StatusEventInput, Store, SubmissionDisposition, SubmissionInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::admission::{
    AdmissionError, AdmissionLock, AdmissionManager, CandidateEvidence, ConformanceReceipt,
};
use crate::config::{
    Carrier, CheckpointPolicy, NqConfig, ResourceLimits, ScopeConfig, VantageConfig, WatcherConfig,
};
use crate::coordination::{CoordinationError, InstanceGuard};
use crate::evaluator_identity::EvaluatorRuntimeIdentity;
use crate::identity::{ExecutionIdentity, VerifiedLaunch};
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
    /// Admission construction or verification failed outside a scheduled
    /// attempt.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// Per-instance collection/binding serialization failed.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
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

    /// Validate stable identity and origin-specific dependent invariants.
    ///
    /// # Errors
    ///
    /// Returns when a refusal lacks a stable identity or an acquisition-origin
    /// refusal contains projections that disagree with its exact outcome.
    pub fn validate(&self) -> Result<(), EngineError> {
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
            GovernedRefusalOrigin::Protocol(_) => {}
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
                let compiled =
                    nq_profiles::resolve_profile_key(&refusal.profile).ok_or_else(|| {
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

/// Persisted canonical result of one scheduled or explicitly requested
/// collection. Common association fields occur once and every dependent result
/// remains in its authoritative typed object.
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

    /// Whether scheduling should resume at its normal cadence. A valid `failed`
    /// report is committed but still asks the scheduler to use retry backoff.
    #[must_use]
    pub fn is_success(&self) -> bool {
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
    admission: AdmissionManager,
    runner: StdioRunner,
    unix_runners: BTreeMap<String, BoundUnixRunner>,
    /// The running evaluator's trusted identity, resolved once from the platform
    /// provider at open, or a structured reason it could not be established.
    /// Admission and collection fail closed on the error side.
    evaluator_identity: Result<EvaluatorRuntimeIdentity, String>,
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
        Ok(Self {
            config: config.clone(),
            store: Store::open(&config.database_path)?,
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
        Ok(Self {
            config: config.clone(),
            store: Store::open(&config.database_path)?,
            admission: AdmissionManager,
            runner: StdioRunner,
            unix_runners: BTreeMap::new(),
            evaluator_identity,
        })
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
        self.store.append_admission(&AdmissionInput {
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
    #[allow(clippy::too_many_lines)]
    pub fn collect(&mut self, watcher: &WatcherConfig) -> Result<CollectionOutcome, EngineError> {
        let _guard =
            InstanceGuard::acquire(&self.config.database_path, &watcher.instance_id, "collect")?;
        // Fail closed before any persistence: a collection stamps evaluator
        // identity onto its finding events, so refuse up front when it is
        // unavailable rather than commit an admitted report and only then refuse
        // at evaluation, leaving a durable report behind.
        self.require_evaluator_identity()?;
        self.reconcile_pending_binding(watcher)?;
        let profile = resolve(watcher)?;
        let descriptor_digest = profile
            .descriptor()
            .digest()
            .map_err(|error| EngineError::Canonical(error.to_string()))?;
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
                return Ok(outcome);
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
                return Ok(outcome);
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
                return Ok(outcome);
            }
        };
        let (lock, verification, launch) = lock;
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
        let capture = self.run_capture(
            watcher,
            &request_json,
            Some(&verification.binding_digest),
            launch,
        );

        let run_id = Uuid::new_v4().to_string();
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
            carrier: carrier_name(watcher.carrier).into(),
            started_at: timestamp(capture.started_at),
            deadline_at: timestamp(
                capture.started_at
                    + Duration::milliseconds(
                        i64::try_from(watcher.schedule.deadline_ms).unwrap_or(i64::MAX),
                    ),
            ),
            finished_at: timestamp(capture.finished_at),
            acquisition_outcome: acquisition_code(&capture.outcome).to_owned(),
            execution_identity: canonical(&lock.execution)?,
            resource_outcome: capture_resource_document(&capture, &watcher.resources)?,
        };

        if capture.outcome != AcquisitionOutcome::Response {
            let (submission, custody_refusal) =
                rejected_transport_submission(&run_id, watcher, &capture)?;
            let outcome = if let Some(refusal) = custody_refusal {
                CollectionOutcome::rejected(watcher.instance_id.clone(), run_id, refusal)
            } else {
                CollectionOutcome::acquisition_failed(
                    watcher.instance_id.clone(),
                    run_id,
                    capture.outcome.clone(),
                )?
            };
            self.commit_non_success_collection(watcher, run, submission, &outcome)?;
            return Ok(outcome);
        }

        let raw = capture.stdout.clone();
        let response = match nq_protocol::parse_response(&request, &raw) {
            Ok(response) => response,
            Err(error) => {
                let refusal = GovernedRefusal::protocol(
                    Uuid::new_v4().to_string(),
                    protocol_rejection(&watcher.instance_id, error),
                );
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
                let outcome =
                    CollectionOutcome::rejected(watcher.instance_id.clone(), run_id, refusal);
                self.commit_non_success_collection(watcher, run, Some(submission), &outcome)?;
                return Ok(outcome);
            }
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
                let outcome =
                    CollectionOutcome::rejected(watcher.instance_id.clone(), run_id, refusal);
                self.commit_non_success_collection(watcher, run, Some(submission), &outcome)?;
                Ok(outcome)
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
                            run_id,
                            refusal,
                        );
                        self.commit_non_success_collection(
                            watcher,
                            run,
                            Some(submission),
                            &outcome,
                        )?;
                        return Ok(outcome);
                    }
                };
                let context = ValidationContext::from_request(
                    &request,
                    capture.finished_at,
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
                            run_id,
                            refusal,
                        );
                        self.commit_non_success_collection(
                            watcher,
                            run,
                            Some(submission),
                            &outcome,
                        )?;
                        Ok(outcome)
                    }
                    Ok(validated) => {
                        let report_id = Uuid::new_v4().to_string();
                        let report_status = semantic_report_status(validated.status).to_owned();
                        let stored_report = store_report(
                            &report_id,
                            watcher,
                            profile,
                            &report,
                            &validated,
                            capture.finished_at,
                        )?;
                        let submission = SubmissionInput {
                            submission_id: Uuid::new_v4().to_string(),
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
                            run,
                            submission: Some(submission),
                        };
                        let (_, outcome) = self.store.commit_admitted_collection(
                            &collection,
                            |view, receipt| {
                                let snapshot = view.evidence_snapshot(std::slice::from_ref(
                                    &watcher.instance_id,
                                ))?;
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
                                Ok::<_, EngineError>(AdmittedCollectionCompletion {
                                    status: instance_status_event(watcher, &outcome)?,
                                    evaluations: prepared
                                        .into_iter()
                                        .map(|prepared| prepared.commit)
                                        .collect(),
                                    value: outcome,
                                })
                            },
                        )?;
                        Ok(outcome)
                    }
                }
            }
        }
    }

    /// Re-evaluate compiled detectors at a new wall-clock time without
    /// collecting or refreshing any evidence.
    ///
    /// # Errors
    ///
    /// Returns when the profile is unavailable, admitted evidence cannot be
    /// reconstructed, or the evaluation cannot be committed atomically.
    pub fn freshness_sweep(&mut self, watcher: &WatcherConfig) -> Result<usize, EngineError> {
        let _guard = InstanceGuard::acquire(
            &self.config.database_path,
            &watcher.instance_id,
            "freshness-sweep",
        )?;
        self.reconcile_pending_binding(watcher)?;
        let profile = resolve(watcher)?;
        self.evaluate_instance(watcher, profile, None)
            .map(|evaluations| evaluations.len())
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
        self.store.begin_binding_transition(&event, &intent)?;
        // From this point onward SQLite is authoritative. A failure or process
        // death leaves the intent pending for the next lock holder to replay.
        self.apply_binding_materialization(&plan)?;
        self.store
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
        if capture.outcome != AcquisitionOutcome::Response {
            let failure = AcquisitionFailure::from_outcome(capture.outcome).ok_or_else(|| {
                EngineError::Invariant("response cannot be a dry acquisition failure".into())
            })?;
            return Err(EngineError::AcquisitionFailed(Box::new(failure)));
        }
        let response = match nq_protocol::parse_response(&request, &capture.stdout) {
            Ok(response) => response,
            Err(error) => {
                return Err(EngineError::GovernedRefusal(Box::new(
                    GovernedRefusal::protocol(
                        Uuid::new_v4().to_string(),
                        protocol_rejection(&watcher.instance_id, error),
                    ),
                )));
            }
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
        let deadline = StdDuration::from_millis(watcher.schedule.deadline_ms);
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
                            message: error.failure.to_string(),
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
        self.store.record_status(&status)?;
        Ok(())
    }

    fn commit_non_success_collection(
        &mut self,
        watcher: &WatcherConfig,
        run: RunInput,
        submission: Option<SubmissionInput>,
        outcome: &CollectionOutcome,
    ) -> Result<(), EngineError> {
        let run_id = outcome.run_id.as_deref().ok_or_else(|| {
            EngineError::Invariant("non-success collection outcome has no run identity".into())
        })?;
        if run.run_id != run_id {
            return Err(EngineError::Invariant(format!(
                "non-success outcome run {run_id} disagrees with collection run {}",
                run.run_id
            )));
        }
        let result = RunResultStatusInput {
            run_id: run_id.to_owned(),
            status: instance_status_event(watcher, outcome)?,
        };
        self.store
            .commit_non_success_collection(&CollectionInput { run, submission }, &result)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate_instance(
        &mut self,
        watcher: &WatcherConfig,
        profile: &'static dyn ProfileModule,
        trigger_run_id: Option<&str>,
    ) -> Result<Vec<EvaluationEnvelopeV2>, EngineError> {
        let snapshot = self
            .store
            .evidence_snapshot(std::slice::from_ref(&watcher.instance_id))?;
        validate_evaluation_refusal_history(&self.store)?;
        let current_findings = self.store.finding_snapshots()?;
        let evaluator_artifact_digest = self
            .require_evaluator_identity()?
            .artifact_digest()
            .as_str()
            .to_owned();
        let prepared = prepare_instance_evaluations(
            watcher,
            profile,
            trigger_run_id,
            &snapshot,
            &current_findings,
            &evaluator_artifact_digest,
        )?;
        let mut evaluations = Vec::with_capacity(prepared.len());
        for prepared in prepared {
            self.store.commit_evaluation(
                &prepared.commit.evaluation,
                prepared.commit.finding.as_ref(),
            )?;
            evaluations.push(prepared.envelope);
        }
        Ok(evaluations)
    }
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
        let result = detector.evaluate(&detector_input);
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
                .saturating_add(watcher.schedule.deadline_ms.saturating_mul(1_000_000)),
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
    let retains_exact_submission = !capture.stdout.is_empty()
        && matches!(
            capture.outcome,
            AcquisitionOutcome::MalformedFraming { .. }
                | AcquisitionOutcome::MalformedJson { .. }
                | AcquisitionOutcome::ExitNonzero { .. }
        );
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

fn protocol_rejection(instance_id: &str, error: nq_protocol::FramingError) -> ProtocolRejection {
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
        diagnostic: error.to_string(),
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
                reason,
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
        EngineError::Invariant(message) => (
            AdmissionRefusalBoundary::Internal,
            AdmissionRefusalCode::InvariantViolation,
            AdmissionRefusalDetails::Invariant { message },
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

fn capture_resource_document(
    capture: &RunCapture,
    limits: &ResourceLimits,
) -> Result<CanonicalDocument, EngineError> {
    canonical(&RunResourceOutcomeV1 {
        schema: RunResourceOutcomeSchema::V1,
        duration_ms: capture.duration_ms,
        exit_code: capture.exit_code,
        hard_limits: RunHardLimits {
            address_space_bytes_per_process: limits.max_address_space_bytes,
            cpu_seconds_per_process: limits.max_cpu_seconds,
            processes_per_execution_uid: limits.max_processes,
            open_files_per_process: limits.max_open_files,
            file_bytes_per_regular_file: limits.max_file_bytes,
            core_bytes: 0,
        },
        stdout_bytes_retained: capture.stdout.len(),
        stderr_bytes_retained: capture.stderr.len(),
        stderr_hex: hex::encode(&capture.stderr),
        outcome: capture.outcome.clone(),
    })
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
    let uptime = fs::read_to_string("/proc/uptime")?;
    let value = uptime
        .split_whitespace()
        .next()
        .ok_or_else(|| EngineError::Invariant("/proc/uptime is empty".into()))?;
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, "0"));
    let seconds = seconds
        .parse::<u64>()
        .map_err(|error| EngineError::Invariant(format!("invalid /proc/uptime: {error}")))?;
    let mut nanos = fraction
        .as_bytes()
        .iter()
        .take(9)
        .fold(0_u64, |value, byte| {
            value
                .saturating_mul(10)
                .saturating_add(u64::from(byte.saturating_sub(b'0')))
        });
    for _ in fraction.len().min(9)..9 {
        nanos = nanos.saturating_mul(10);
    }
    Ok(seconds.saturating_mul(1_000_000_000).saturating_add(nanos))
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
            AcquisitionOutcome::MalformedFraming { message }
        }
        UnixAcquisitionOutcome::RequestWriteFailed { message } => {
            AcquisitionOutcome::RequestWriteFailed { message }
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
        UnixAcquisitionOutcome::Disconnect { message } => {
            AcquisitionOutcome::Disconnect { message }
        }
        UnixAcquisitionOutcome::MalformedJson { message } => {
            AcquisitionOutcome::MalformedJson { message }
        }
        UnixAcquisitionOutcome::HelperExited { code } => AcquisitionOutcome::HelperExited { code },
        UnixAcquisitionOutcome::NotRunning => AcquisitionOutcome::NotRunning,
        UnixAcquisitionOutcome::IoFailed { message } => AcquisitionOutcome::IoFailed { message },
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

fn acquisition_code(outcome: &AcquisitionOutcome) -> &'static str {
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
    store: &mut Store,
    module: &dyn ProfileModule,
) -> Result<(), EngineError> {
    let descriptor = module.descriptor();
    store.append_profile_descriptor(&ProfileDescriptorInput {
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
pub fn append_genesis(store: &mut Store, legacy_digest: Option<String>) -> Result<(), EngineError> {
    store.append_genesis(&GenesisInput {
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
/// Returns when the details cannot be canonicalized or the durable status
/// event violates the storage contract.
pub fn record_component_status(
    store: &mut Store,
    component_kind: &str,
    component_id: &str,
    state: &str,
    code: &str,
    details: &Value,
) -> Result<(), EngineError> {
    store.record_status(&StatusEventInput {
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
pub fn backup_store(store: &Store, destination: &Path) -> Result<(), EngineError> {
    validate_admitted_report_history(store)?;
    validate_watcher_run_history(store)?;
    validate_status_history_v2(store)?;
    validate_rejected_custody_history(store)?;
    validate_evaluation_refusal_history(store)?;
    let _artifact = store.backup_verified(destination)?;
    let reopened = Store::open(destination)?;
    validate_admitted_report_history(&reopened)?;
    validate_watcher_run_history(&reopened)?;
    validate_status_history_v2(&reopened)?;
    validate_rejected_custody_history(&reopened)?;
    validate_evaluation_refusal_history(&reopened)?;
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
        let envelope = validate_evaluation_refusal_row(store, &row)?;
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
            let envelope = validate_evaluation_refusal_row(store, &row)?;
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
    let compiled = nq_profiles::resolve_profile_key(&result.profile.profile).ok_or_else(|| {
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
        || compiled_digest != result.profile.profile_digest
        || compiled_semantic_id != result.profile.profile_semantic_id
        || row.detector_digest != compiled_detector_digest
        || result.condition != detector_descriptor.condition
    {
        return Err(EngineError::Invariant(format!(
            "evaluation {} profile identity or semantic projection was substituted",
            row.evaluation_id
        )));
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
            store
                .status_snapshots_bounded(limit, None)?
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
    if row.component_kind == "instance" {
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
    let detail = if kind == ComponentKind::Instance {
        let result = decode_collection_outcome(detail_json.as_bytes()).map_err(|error| {
            EngineError::Invariant(format!(
                "instance status {component_id} is not a valid versioned collection result: {error}"
            ))
        })?;
        if result.instance_id != component_id {
            return Err(EngineError::Invariant(format!(
                "instance status {} embeds result for {}",
                component_id, result.instance_id
            )));
        }
        let projection = instance_status_projection(&result)?;
        if state != projection.state || code != projection.code {
            return Err(EngineError::Invariant(format!(
                "instance status {component_id} projects ({state}, {code}) but its typed result requires ({}, {})",
                projection.state, projection.code
            )));
        }
        validate_collection_run(store, &result)?;
        if let CollectionResult::Rejected { refusal } = &result.result {
            let run_id = result.run_id.as_deref().ok_or_else(|| {
                EngineError::Invariant(format!(
                    "rejected instance status {component_id} has no run identity"
                ))
            })?;
            let custody_row = store
                .rejected_custody_by_refusal_id(&refusal.refusal_id)?
                .ok_or_else(|| {
                    EngineError::Invariant(format!(
                        "rejected instance status {} names refusal {} without linked custody",
                        component_id, refusal.refusal_id
                    ))
                })?;
            let custody = rejected_custody_from_row(store, custody_row)?;
            if custody.run_id != run_id
                || custody.instance_id != result.instance_id
                || custody.refusal != *refusal
            {
                return Err(EngineError::Invariant(format!(
                    "rejected instance status {} disagrees with linked refusal {} or run {}",
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
        "evaluation" => Ok(ComponentKind::Evaluation),
        "notification" => Ok(ComponentKind::Notification),
        _ => Err(EngineError::Invariant(format!("unknown component {value}"))),
    }
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

    use crate::config::{
        CommandConfig, ProfileSelection, ResourceLimits, ScheduleConfig, ScopeConfig, VantageConfig,
    };

    use super::*;

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
            append_profile_descriptor(store, profile).expect("append compiled descriptor");
        }
        let admission_id = format!("admission-{suffix}");
        let typed = |label: &str| nq_protocol::sha256_bytes(format!("{label}-{suffix}").as_bytes());
        store
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
                    helper_artifact_digest: typed("helper"),
                    config_digest: typed("config"),
                    protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
                    target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                    artifact_identity_method: "test-fixture".to_owned(),
                    platform_runtime_version: "test".to_owned(),
                },
                execution_chain: canonical(&json!({"fixture": suffix})).expect("execution"),
                profile_id: descriptor.profile.id.clone(),
                profile_version: descriptor.profile.version.to_string(),
                profile_digest: profile_digest.as_str().to_owned(),
                capability_grant: canonical(&json!([])).expect("capability grant"),
                conformance: canonical(&json!({"passed": true})).expect("conformance"),
                lock: canonical(&json!({"fixture": suffix})).expect("lock"),
                admitted_at: "2026-07-20T12:00:00.000Z".to_owned(),
                operator_identity: canonical(&json!({"uid": 991})).expect("operator"),
            })
            .expect("append compiled admission");
        admission_id
    }

    fn test_run(
        profile: &'static dyn ProfileModule,
        instance_id: &str,
        suffix: &str,
        admission_id: String,
        outcome: AcquisitionOutcome,
    ) -> RunInput {
        let descriptor = profile.descriptor();
        RunInput {
            run_id: format!("run-{suffix}"),
            request_id: format!("request-{suffix}"),
            instance_id: instance_id.to_owned(),
            admission_id: Some(admission_id),
            binding_digest: nq_protocol::sha256_bytes(format!("binding-{suffix}").as_bytes())
                .into_string(),
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
            execution_identity: canonical(&json!({"fixture": suffix})).expect("execution"),
            resource_outcome: test_run_resource(outcome),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn commit_real_host_detector_report(
        store: &mut Store,
        watcher: &WatcherConfig,
        report_id: &str,
        suffix: &str,
        observed_at: DateTime<Utc>,
        load_1m: f64,
    ) -> (DetectorReport, String) {
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
            next_checkpoint: None,
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
        let collection = CollectionInput {
            run,
            submission: Some(SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes,
                received_at: timestamp(received_at),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(stored),
            }),
        };
        let (receipt, ()) = store
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
                    status: instance_status_event(watcher, &outcome)
                        .expect("canonical admitted status"),
                })
            })
            .expect("commit admitted host report");
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
        )
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
        store
            .commit_non_success_collection(&CollectionInput { run, submission }, &result)
            .expect("commit atomic non-success fixture")
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
            schedule: ScheduleConfig::default(),
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
        append_profile_descriptor(&mut store, profile).expect("descriptor");
        store
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
        assert!(!outcome.is_success());
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
        append_profile_descriptor(&mut store, resolve(&watcher).expect("profile"))
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
        let doc = |value: Value| CanonicalDocument::from_serializable(&value).expect("canonical");
        let sd = |label: &str| nq_protocol::sha256_bytes(label.as_bytes());
        let mut store = Store::initialize(db_path).expect("initialize verify store");
        let descriptor = doc(json!({"profile": "verify.fixture"}));
        let profile_digest = descriptor.digest().to_owned();
        store
            .append_profile_descriptor(&ProfileDescriptorInput {
                profile_id: "verify.fixture".to_owned(),
                profile_version: "1".to_owned(),
                descriptor,
                recorded_at: TS.to_owned(),
            })
            .expect("descriptor");
        store
            .append_admission(&AdmissionInput {
                admission_id: "adm-1".to_owned(),
                instance_id: "inst-1".to_owned(),
                identity: AdmissionIdentity {
                    profile_semantic_id: sd("semantic"),
                    detector_identity_digest: nq_store::detector_suite_identity_digest(
                        Vec::<String>::new(),
                    )
                    .expect("empty verification detector suite"),
                    evaluator_source_digest: sd("source"),
                    evaluator_artifact_digest,
                    helper_artifact_digest: sd("helper"),
                    config_digest: sd("config"),
                    protocol_version: "1.0".to_owned(),
                    target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                    artifact_identity_method: artifact_identity_method.to_owned(),
                    platform_runtime_version: platform_runtime_version.to_owned(),
                },
                execution_chain: doc(json!({})),
                profile_id: "verify.fixture".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest: profile_digest.clone(),
                capability_grant: doc(json!([])),
                conformance: doc(json!({})),
                lock: doc(json!({})),
                admitted_at: TS.to_owned(),
                operator_identity: doc(json!({})),
            })
            .expect("admission");
        let run = RunInput {
            run_id: "run-1".to_owned(),
            request_id: "req-1".to_owned(),
            instance_id: "inst-1".to_owned(),
            admission_id: Some("adm-1".to_owned()),
            binding_digest: sd("binding").as_str().to_owned(),
            checkpoint_contract_digest: sd("checkpoint").as_str().to_owned(),
            profile_id: "verify.fixture".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.clone(),
            carrier: "stdio".to_owned(),
            started_at: TS.to_owned(),
            deadline_at: TS.to_owned(),
            finished_at: TS.to_owned(),
            acquisition_outcome: "response".to_owned(),
            execution_identity: doc(json!({})),
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
        let collection = CollectionInput {
            run,
            submission: Some(SubmissionInput {
                submission_id: "sub-1".to_owned(),
                raw_bytes: b"raw".to_vec(),
                received_at: TS.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report),
            }),
        };
        store
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
        assert_eq!(verified.admission_id, "adm-1");
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
        append_profile_descriptor(&mut store, profile).expect("compiled profile descriptor");
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

        let (stale_report, report_received_at) = commit_real_host_detector_report(
            &mut store,
            watcher,
            "report-real-host-stale",
            "real-host-stale",
            observed_at,
            1.0,
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
        append_profile_descriptor(&mut store, profile).expect("compiled profile descriptor");
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
        append_profile_descriptor(&mut store, profile).expect("compiled profile descriptor");
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
        let failures = [
            ("framing", ProtocolRejectionFailure::InvalidFraming),
            (
                "json",
                ProtocolRejectionFailure::InvalidJson {
                    error: StructuredJsonError {
                        category: JsonErrorCategory::Syntax,
                        line: 1,
                        column: 8,
                        diagnostic: "expected value".to_owned(),
                    },
                },
            ),
        ];
        let mut carriers = Vec::new();
        for (suffix, failure) in failures {
            let instance_id = format!("protocol.{suffix}");
            let admission = seed_compiled_admission(&mut store, profile, &instance_id, suffix);
            let run = test_run(
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
                raw_bytes: format!("invalid-{suffix}\n").into_bytes(),
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
        backup_store(&store, &backup).expect("semantic backup");
        drop(store);
        let reopened = Store::open(&backup).expect("reopen protocol backup");
        assert_pair(&reopened);

        let mut hostile = Store::initialize_in_memory().expect("hostile protocol store");
        let instance_id = "protocol.substituted";
        let admission =
            seed_compiled_admission(&mut hostile, profile, instance_id, "protocol-substituted");
        let run = test_run(
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
            raw_bytes: b"invalid framing\n".to_vec(),
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
        assert!(matches!(
            store.commit_non_success_collection(
                &CollectionInput {
                    run: rejected_by_api,
                    submission: None,
                },
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
                if message.contains("instance or profile identity disagrees")
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

        let reopened = Store::open(&database).expect("physical schema-v3 store reopens");
        let borrowed = reopened
            .watcher_run_outcome("run-z-borrowed")
            .expect("read hostile row")
            .expect("borrowed run exists");
        assert_eq!(borrowed.instance_id, "binding.borrower");
        assert_eq!(
            borrowed.admission_instance_id.as_deref(),
            Some("binding.owner")
        );
        assert!(matches!(
            validate_watcher_run_history_with_page_size(&reopened, 1),
            Err(EngineError::Invariant(message))
                if message.contains("borrowed admission admission-owner")
        ));
    }

    #[test]
    fn status_history_validation_cannot_hide_legacy_event_behind_typed_current() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let mut store = Store::initialize(directory.path().join("history.db")).expect("store");
        let observed_at = timestamp(Utc::now());
        store
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
            received_at: TIME.to_owned(),
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
