//! NQ-ng's local admission, collection, and evaluation engine.
//!
//! The core deliberately depends on compiled profiles and a generic store. It
//! never discovers semantic code at runtime, and helper output cannot create a
//! finding without profile admission and detector evaluation.

pub mod admission;
pub mod config;
pub mod coordination;
pub mod engine;
pub mod evaluator_identity;
pub mod identity;
pub mod provider_intake;
pub mod public;
pub mod runner;
pub mod runtime;
pub mod unix_runner;

pub use admission::{AdmissionLock, AdmissionManager, AdmissionVerification};
pub use config::{MAX_WATCHERS, NqConfig, WatcherConfig};
pub use coordination::{CoordinationError, InstanceGuard};
pub use engine::{
    AcquisitionFailure, AcquisitionFailureClass, AcquisitionRefusal, AdmissionRefusal,
    AdmissionRefusalBoundary, AdmissionRefusalCode, AdmissionRefusalDetails,
    AdmittedReportVerification, BindingActionOutcome, COLLECTION_OUTCOME_SCHEMA,
    COLLECTION_OUTCOME_V1_SCHEMA, COLLECTION_OUTCOME_V2_SCHEMA, CollectionEngine,
    CollectionOutcome, CollectionOutcomeSchema, CollectionResult, EVALUATION_ENVELOPE_SCHEMA,
    EVALUATION_RESULT_SCHEMA, EvaluationContextV1, EvaluationDetectorIdentity,
    EvaluationEnvelopeSchema, EvaluationEnvelopeV2, EvaluationProfileIdentity,
    EvaluationResultSchema, EvaluationResultV1, EvaluationWatermarkV2, GOVERNED_REFUSAL_SCHEMA,
    GovernedProfileRefusal, GovernedRefusal, GovernedRefusalOrigin, GovernedRefusalSchema,
    JsonErrorCategory, PlatformObservation, ProtocolCanonicalizationFailure, ProtocolRejection,
    ProtocolRejectionBoundary, ProtocolRejectionCode, ProtocolRejectionFailure,
    ProtocolValidationFailure, ProviderIntakeHistoryVerification, RUN_RESOURCE_OUTCOME_SCHEMA,
    RetryDisposition, RunHardLimits, RunResourceOutcomeSchema, RunResourceOutcomeV1,
    StructuredJsonError, VerificationRefusal, decode_collection_outcome,
    decode_collection_outcome_ndjson, evaluation_history_bounded, rejected_custody_snapshot,
    rejected_custody_snapshot_bounded, status_snapshot_v2, status_snapshot_v3,
    validate_evaluation_refusal_history, validate_provider_intake_history,
    validate_rejected_custody_history, validate_status_history_v2, validate_watcher_run_history,
};
pub use evaluator_identity::{EvaluatorIdentityError, EvaluatorRuntimeIdentity};
pub use identity::{
    ExecutionArtifact, ExecutionDirectory, ExecutionIdentity, MAX_LAUNCH_ARTIFACT_BYTES,
    MAX_LAUNCH_ARTIFACTS, MAX_LAUNCH_RETAINED_FDS, MAX_LAUNCH_TOTAL_BYTES,
    MAX_RESIDENT_LAUNCH_BYTES, VerifiedLaunch,
};
pub use provider_intake::{
    LOCAL_HELPER_PROVIDER_SEMANTICS_SCHEMA, PROVIDER_IDENTITY_SCHEMA,
    PROVIDER_INTAKE_CONTEXT_SCHEMA, PROVIDER_INTAKE_SCHEMA, ProviderIdentitySchema,
    ProviderIdentityV1, ProviderIntakeContextSchema, ProviderIntakeContextV1, ProviderIntakeError,
    ProviderIntakeRecordV1, ProviderIntakeSchema, ProviderKind, ProviderResponseInterpretationV1,
};
pub use public::{
    ComponentStatusDetailV2, ComponentStatusDetailV3, ComponentStatusV2, ComponentStatusV3,
    EVALUATION_HISTORY_SCHEMA, EvaluationHistoryPageV1, EvaluationHistoryRecordV1,
    FindingSnapshotV3, REJECTED_CUSTODY_SCHEMA, RejectedCustodySnapshotV1, RejectedCustodyV1,
    STATUS_SNAPSHOT_V2_SCHEMA, STATUS_SNAPSHOT_V3_SCHEMA, StatusSnapshotV1, StatusSnapshotV2,
    StatusSnapshotV3,
};
pub use runner::{ExchangeTimeoutPhase, StdioRunner};
pub use runtime::{
    NativeRuntimeIdentity, RuntimeArtifactIdentity, RuntimeArtifactKind, RuntimeDirectoryIdentity,
    RuntimeLinkage, RuntimeMachine, RuntimeObjectBinding, RuntimeObjectRole,
    StartupRuntimeIdentity,
};
pub use unix_runner::{UnixAcquisitionOutcome, UnixRunner, UnixRunnerOptions};
