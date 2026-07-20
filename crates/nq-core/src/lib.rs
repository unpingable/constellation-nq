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
    AdmittedReportVerification, BindingActionOutcome, COLLECTION_OUTCOME_SCHEMA, CollectionEngine,
    CollectionOutcome, CollectionOutcomeSchema, CollectionResult, EVALUATION_RESULT_SCHEMA,
    EvaluationResultSchema, EvaluationResultV1, GOVERNED_REFUSAL_SCHEMA, GovernedProfileRefusal,
    GovernedRefusal, GovernedRefusalOrigin, GovernedRefusalSchema, JsonErrorCategory,
    PlatformObservation, ProtocolCanonicalizationFailure, ProtocolRejection,
    ProtocolRejectionBoundary, ProtocolRejectionCode, ProtocolRejectionFailure,
    ProtocolValidationFailure, RUN_RESOURCE_OUTCOME_SCHEMA, RetryDisposition, RunHardLimits,
    RunResourceOutcomeSchema, RunResourceOutcomeV1, StructuredJsonError, VerificationRefusal,
    decode_collection_outcome, rejected_custody_snapshot, rejected_custody_snapshot_bounded,
    status_snapshot_v2, validate_evaluation_refusal_history, validate_rejected_custody_history,
    validate_status_history_v2, validate_watcher_run_history,
};
pub use evaluator_identity::{EvaluatorIdentityError, EvaluatorRuntimeIdentity};
pub use identity::{
    ExecutionArtifact, ExecutionDirectory, ExecutionIdentity, MAX_LAUNCH_ARTIFACT_BYTES,
    MAX_LAUNCH_ARTIFACTS, MAX_LAUNCH_RETAINED_FDS, MAX_LAUNCH_TOTAL_BYTES,
    MAX_RESIDENT_LAUNCH_BYTES, VerifiedLaunch,
};
pub use public::{
    ComponentStatusDetailV2, ComponentStatusV2, FindingSnapshotV3, REJECTED_CUSTODY_SCHEMA,
    RejectedCustodySnapshotV1, RejectedCustodyV1, STATUS_SNAPSHOT_V2_SCHEMA, StatusSnapshotV1,
    StatusSnapshotV2,
};
pub use runner::{ExchangeTimeoutPhase, StdioRunner};
pub use runtime::{
    NativeRuntimeIdentity, RuntimeArtifactIdentity, RuntimeArtifactKind, RuntimeDirectoryIdentity,
    RuntimeLinkage, RuntimeMachine, RuntimeObjectBinding, RuntimeObjectRole,
    StartupRuntimeIdentity,
};
pub use unix_runner::{UnixAcquisitionOutcome, UnixRunner, UnixRunnerOptions};
