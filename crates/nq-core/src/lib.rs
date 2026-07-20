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
    AdmittedReportVerification, BindingActionOutcome, CollectionEngine, CollectionOutcome,
    PlatformObservation, VerificationRefusal,
};
pub use evaluator_identity::{EvaluatorIdentityError, EvaluatorRuntimeIdentity};
pub use identity::{
    ExecutionArtifact, ExecutionDirectory, ExecutionIdentity, MAX_LAUNCH_ARTIFACT_BYTES,
    MAX_LAUNCH_ARTIFACTS, MAX_LAUNCH_RETAINED_FDS, MAX_LAUNCH_TOTAL_BYTES,
    MAX_RESIDENT_LAUNCH_BYTES, VerifiedLaunch,
};
pub use public::{FindingSnapshotV2, StatusSnapshotV1};
pub use runner::{AcquisitionFailure, StdioRunner};
pub use runtime::{
    NativeRuntimeIdentity, RuntimeArtifactIdentity, RuntimeArtifactKind, RuntimeDirectoryIdentity,
    RuntimeLinkage, RuntimeMachine, RuntimeObjectBinding, RuntimeObjectRole,
    StartupRuntimeIdentity,
};
pub use unix_runner::{UnixAcquisitionOutcome, UnixRunner, UnixRunnerOptions};
