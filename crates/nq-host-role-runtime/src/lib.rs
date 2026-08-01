#![forbid(unsafe_code)]

//! Restart-safe host-role runtime over the canonical NQ runtime-record ledger.
//!
//! The runtime accepts the exact operator-ratified host-role contract records,
//! validates their complete resulting graph before commit, and persists them
//! through NQ's schema-v7 append-only runtime ledger. Every new checkpoint is
//! bound to the exact authenticated dependency-generation custody and trust
//! anchor effective for that checkpoint. One separately persisted bootstrap
//! root constrains every generation in the store occurrence. Historical
//! checkpoints reopen under their own immutable generations; a caller's
//! current generation cannot reinterpret them or select a new root.
//! Dependencies grant no invocation, reliance, authorization, or mutation
//! authority.
//!
//! The generic custody append is deliberately not a downstream API. In
//! particular, a caller cannot bypass governed prelaunch by appending an
//! execution-bearing record directly:
//!
//! ```compile_fail
//! use nq_host_role_runtime::{CustodyAppendRequest, HostRoleRuntime};
//!
//! fn bypass(runtime: &mut HostRoleRuntime, request: &CustodyAppendRequest) {
//!     runtime.append_custody_only(request).unwrap();
//! }
//! ```

mod dependency;
mod inspector;
mod prelaunch;
mod runtime;
#[cfg(feature = "test-support")]
pub use runtime::test_support;

pub use dependency::{
    ADMISSION_RECEIPT_SET_SCHEMA, AUTHORITY_ADMISSION_SNAPSHOT_SCHEMA,
    AdmissionReceiptSetAvailability, AdmissionReceiptSetCustody, AdmissionSignatureAlgorithm,
    AuthenticatedRuntimeDependencyClosure, AuthenticatedSourceResolution, AuthorityAdmission,
    AuthorityAdmissionKind, AuthorityAdmissionSnapshot, AuthoritySourcePurpose,
    AuthoritySourceRequirement, AuthoritySourceResult, AuthoritySourceState,
    DependencyAdmissionKind, DependencyAdmissionReceipt, DependencyCustodyError,
    ED25519_TRUST_ANCHOR_SCHEMA, EXTERNAL_DEPENDENCY_SNAPSHOT_SCHEMA, Ed25519TrustAnchor,
    ExactDependencyCustodyBinding, ExactExternalDependency, ExternalDependencyAvailability,
    ExternalDependencySnapshot, ExternalSourcePurpose, ExternalSourceRequirement,
    ExternalSourceResult, ExternalSourceState, RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA,
    RUNTIME_DEPENDENCY_GENERATION_SCHEMA, RuntimeDependencies, RuntimeDependencyGeneration,
    RuntimeDependencyGenerationCustody, SignedAdmissionReceiptSet,
};
pub use inspector::{InspectorEntry, InspectorPage, InspectorProjection, InspectorProjectionState};
pub use nq_runtime_dependency_authority::{GenesisAuthorityCustody, MigrationReceiptBytes};
pub(crate) use prelaunch::production_identity;
pub use prelaunch::{
    GovernedPrelaunchRequest, GovernedProductionIdentity, NativeDeadlinePrelaunchRequest,
    NativeDeadlineProvenance, PreparedGovernedInvocation, QualifiedGovernedFinalBatch,
};
pub use runtime::{
    AppendDisposition as CustodyAppendDisposition, AppendRecord as CustodyRecord,
    AppendRequest as CustodyAppendRequest, AppendResult as CustodyAppendResult,
    HistoricalMaterializedRecord, HistoricalTopology, HostRoleRuntime,
    RuntimeAuthorityResidentBinding, RuntimeReadPage, RuntimeSnapshot,
};

use nq_protocol::Sha256Digest;
pub use nq_store::{
    GovernedCustodyInspection, GovernedCustodyInventoryEntry, GovernedCustodyRecoveryClass,
    GovernedCustodyReservationLedgerBinding, GovernedCustodyState, GovernedProtectedFailure,
    GovernedProtectedFailureAccess,
};
use thiserror::Error;

/// Result returned by the host-role runtime boundary.
pub type Result<T> = std::result::Result<T, RuntimeError>;

/// Typed refusal from the restart-safe host-role runtime boundary.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Enrolled resident authority verification refused the exact native
    /// custody, chain, scope, cut, signature, or occurrence binding.
    #[error(transparent)]
    RuntimeAuthority(#[from] nq_runtime_dependency_authority::AuthorityError),
    /// The ratified contract carrier or full graph refused the input.
    #[error("host-role contract refusal: {0}")]
    Contract(#[from] nq_host_role_contract::ContractError),
    /// The append-only store refused or could not reopen the input.
    #[error("runtime ledger refusal: {0}")]
    Store(#[from] nq_store::StoreError),
    /// JSON decoding failed at a local persistence-carrier boundary.
    #[error("invalid runtime dependency JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Canonicalization failed.
    #[error("runtime dependency canonicalization failed: {0}")]
    Canonicalization(#[from] nq_protocol::CanonicalizationError),
    /// External-dependency snapshot bytes were valid JSON but not exact
    /// canonical bytes.
    #[error("external-dependency snapshot bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalExternalDependencySnapshot,
    /// External-dependency snapshot identity was unknown.
    #[error("unsupported external-dependency snapshot schema {0}")]
    UnknownExternalDependencySnapshotSchema(String),
    /// External dependencies were not unique and strictly ordered.
    #[error("external-dependency snapshot is not in strict canonical order")]
    ExternalDependencySnapshotNotCanonical,
    /// Authority-admission snapshot bytes were not canonical.
    #[error("authority-admission snapshot bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalAuthorityAdmissionSnapshot,
    /// Authority-admission snapshot identity was unknown.
    #[error("unsupported authority-admission snapshot schema {0}")]
    UnknownAuthorityAdmissionSnapshotSchema(String),
    /// Authority admissions were not unique and strictly ordered.
    #[error("authority-admission snapshot is not in strict canonical order")]
    AuthorityAdmissionSnapshotNotCanonical,
    /// A contract-owned runtime record was incorrectly placed in the
    /// off-ledger reference closure.
    #[error("contract runtime record {0} must be materialized in the runtime ledger")]
    MaterializedRuntimeRecordOffLedger(String),
    /// Provider intake is the sole opaque external schema permitted in the
    /// ledger and cannot be supplied as an off-ledger reference.
    #[error("nq.provider_intake.v1 must be materialized in the runtime ledger")]
    ProviderIntakeOffLedger,
    /// Exact dependency bytes were malformed or not canonical lowercase hex.
    #[error("external dependency exact bytes are not canonical lowercase hexadecimal")]
    ExternalDependencyBytesMalformed,
    /// Availability and exact-byte presence disagreed.
    #[error("external dependency availability disagrees with exact-byte custody")]
    ExternalDependencyAvailabilityMismatch,
    /// Exact bytes disagreed with the referenced digest.
    #[error("external dependency {0} exact bytes differ from its reference")]
    ExternalDependencyByteSubstitution(String),
    /// One external admission receipt was replayed.
    #[error("external dependency admission receipt was replayed")]
    ExternalDependencyReceiptReplay,
    /// One required exact external dependency was absent.
    #[error("external dependency {0} is absent from the pinned closure")]
    ExternalDependencyMissing(String),
    /// One required exact external dependency was committed but unavailable.
    #[error("external dependency {0} exact bytes are currently unavailable")]
    ExternalDependencyUnavailable(String),
    /// An authority admission's purpose did not match its record schema.
    #[error("authority admission purpose does not match its record schema")]
    AuthorityAdmissionKindMismatch,
    /// One authority receipt was replayed.
    #[error("authority admission receipt was replayed")]
    AuthorityAdmissionReceiptReplay,
    /// A materialized operation authorization had not been independently
    /// admitted.
    #[error("operation authorization {0} was not independently admitted")]
    AuthorityRecordNotAdmitted(String),
    /// Request authentication evidence had not been independently admitted.
    #[error("invocation authentication evidence {0} was not independently admitted")]
    AuthenticationEvidenceNotAdmitted(String),
    /// Exact persisted dependency bytes did not match their independently
    /// supplied pin.
    #[error("{dependency} dependency digest differs: expected {expected}, observed {observed}")]
    DependencyDigestMismatch {
        /// Dependency class.
        dependency: &'static str,
        /// Required exact digest.
        expected: Sha256Digest,
        /// Observed exact digest.
        observed: Sha256Digest,
    },
    /// Trust-anchor bytes were valid JSON but not exact canonical bytes.
    #[error("dependency trust-anchor bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalDependencyTrustAnchor,
    /// The bootstrap trust-anchor schema is unsupported.
    #[error("unsupported dependency trust-anchor schema {0}")]
    UnknownDependencyTrustAnchorSchema(String),
    /// The trust anchor did not contain one exact canonical Ed25519 public key.
    #[error("dependency trust-anchor Ed25519 public key is malformed")]
    DependencyTrustAnchorPublicKeyMalformed,
    /// Caller-supplied anchor bytes differed from the independently retained
    /// store/bootstrap root.
    #[error("dependency trust anchor differs: expected {expected}, observed {observed}")]
    DependencyTrustAnchorSubstitution {
        /// Required immutable trust-anchor identity.
        expected: Sha256Digest,
        /// Observed caller-supplied trust-anchor identity.
        observed: Sha256Digest,
    },
    /// The store occurrence has no independently established dependency trust
    /// root, so retained closures cannot authenticate themselves.
    #[error("runtime dependency bootstrap trust root is not established")]
    DependencyTrustRootNotEstablished,
    /// Signed receipt-set bytes were valid JSON but not exact canonical bytes.
    #[error("admission receipt-set bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalAdmissionReceiptSet,
    /// The signed admission receipt-set schema is unsupported.
    #[error("unsupported admission receipt-set schema {0}")]
    UnknownAdmissionReceiptSetSchema(String),
    /// Admission receipts were duplicated or not in strict canonical order.
    #[error("admission receipt set is not in strict canonical order")]
    AdmissionReceiptSetNotCanonical,
    /// One signed admission receipt identity was replayed.
    #[error("dependency admission receipt was replayed")]
    AdmissionReceiptReplay,
    /// Signed receipt bytes were required but committed-unavailable.
    #[error("signed dependency admission receipt set is committed but unavailable")]
    AdmissionReceiptSetUnavailable,
    /// Signed receipt availability disagreed with exact byte custody.
    #[error("signed dependency admission receipt availability disagrees with exact byte custody")]
    AdmissionReceiptSetAvailabilityMismatch,
    /// Retrieved receipt bytes differed from their committed exact-byte digest.
    #[error("signed dependency admission receipt bytes differ from committed custody")]
    AdmissionReceiptSetByteSubstitution,
    /// Receipt-set signature bytes were malformed.
    #[error("dependency admission receipt-set Ed25519 signature is malformed")]
    AdmissionReceiptSetSignatureMalformed,
    /// Receipt-set signature did not verify under the immutable bootstrap root.
    #[error("dependency admission receipt-set signature is invalid")]
    AdmissionReceiptSetSignatureInvalid,
    /// Signed receipt-set trust or generation binding differed.
    #[error("dependency admission receipt set is bound to another trust or dependency generation")]
    AdmissionReceiptSetBindingMismatch,
    /// A dependency snapshot named a receipt not present in the signed set.
    #[error("dependency admission receipt is absent from the signed closed set")]
    DependencyAdmissionReceiptMissing,
    /// A signed receipt differed in reference, purpose, verifier, or time from
    /// the dependency snapshot it purported to admit.
    #[error("dependency admission receipt differs from its admitted dependency")]
    DependencyAdmissionReceiptSubstitution,
    /// The signed closed set carried an admission not used by either snapshot.
    #[error("signed dependency admission receipt set contains an extraneous receipt")]
    ExtraneousDependencyAdmissionReceipt,
    /// Dependency-generation bytes were not canonical.
    #[error("runtime dependency-generation bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalRuntimeDependencyGeneration,
    /// Historical dependency-custody bytes were not canonical.
    #[error("runtime dependency-generation custody is not exact RFC 8785 canonical JSON")]
    NonCanonicalRuntimeDependencyGenerationCustody,
    /// Historical dependency-custody schema is unsupported.
    #[error("unsupported runtime dependency-generation custody schema {0}")]
    UnknownRuntimeDependencyGenerationCustodySchema(String),
    /// Historical dependency-custody component bytes were not canonical
    /// lowercase hexadecimal.
    #[error("runtime dependency-generation custody contains malformed exact bytes")]
    RuntimeDependencyGenerationCustodyMalformed,
    /// The dependency-generation schema is unsupported.
    #[error("unsupported runtime dependency-generation schema {0}")]
    UnknownRuntimeDependencyGenerationSchema(String),
    /// Stored dependency-generation identity or bytes were substituted.
    #[error("runtime dependency-generation custody differs from its authenticated generation")]
    RuntimeDependencyGenerationSubstitution,
    /// A bound dependency reopen was given an impossible empty-byte binding.
    #[error("dependency-custody binding length must be positive")]
    CustodyBindingLengthZero,
    /// Dependency-custody byte length could not be represented as `u64`.
    #[error("dependency-custody byte length exceeds u64")]
    CustodyLengthOverflow,
    /// Exact dependency-custody length differed from its immutable binding.
    #[error("dependency-custody length differs: expected {expected}, observed {observed}")]
    CustodyLengthMismatch {
        /// Required byte length.
        expected: u64,
        /// Observed byte length.
        observed: u64,
    },
    /// Exact dependency-custody digest differed from its immutable binding.
    #[error("dependency-custody digest differs: expected {expected}, observed {observed}")]
    CustodyDigestMismatch {
        /// Required byte digest.
        expected: Sha256Digest,
        /// Observed byte digest.
        observed: Sha256Digest,
    },
    /// An external-source purpose was paired with an ineligible reference.
    #[error("external-source requirement is incompatible with its exact reference")]
    ExternalSourceRequirementInvalid,
    /// An authority purpose was paired with an ineligible reference.
    #[error("authority-source requirement is incompatible with its exact reference")]
    AuthoritySourceRequirementInvalid,
    /// One exact external source requirement was repeated.
    #[error("external-source requirement was duplicated")]
    DuplicateExternalSourceRequirement,
    /// One exact authority requirement was repeated.
    #[error("authority-source requirement was duplicated")]
    DuplicateAuthoritySourceRequirement,
    /// A runtime checkpoint has no exact dependency binding.
    #[error("runtime checkpoint {0} has no dependency binding")]
    CheckpointDependencyMissing(String),
    /// A schema-v6 checkpoint predates authenticated dependency provenance.
    #[error("runtime checkpoint {0} is legacy-unbound and cannot be semantically reopened")]
    LegacyCheckpointDependencyUnbound(String),
    /// A checkpoint's committed dependency bytes cannot currently be read.
    #[error("runtime checkpoint {0} dependency custody is committed but unavailable")]
    CheckpointDependencyUnavailable(String),
    /// A checkpoint's retained dependency bytes disagree with their
    /// commitment or canonical carrier.
    #[error("runtime checkpoint {checkpoint_id} dependency custody is corrupt: {reason}")]
    CheckpointDependencyCorrupt {
        /// Exact checkpoint identity.
        checkpoint_id: String,
        /// Bounded corruption reason.
        reason: String,
    },
    /// A read snapshot belongs to a different dependency closure.
    #[error("runtime snapshot belongs to another dependency binding")]
    SnapshotDependencyMismatch,
    /// Runtime ledger schema was outside the exact contract set and the sole
    /// allowed opaque provider-intake schema.
    #[error("unsupported runtime ledger schema {0}")]
    UnsupportedLedgerSchema(String),
    /// The store row disagreed with its exact contract carrier.
    #[error("runtime ledger row disagrees with its canonical contract carrier: {0}")]
    LedgerCarrierMismatch(&'static str),
    /// Opaque provider-intake bytes did not have the exact allowed schema.
    #[error("opaque provider-intake carrier is malformed")]
    InvalidProviderIntakeCarrier,
    /// One immutable record identity was reused for different bytes or schema.
    #[error("runtime record identity {0} was reused for a substitution")]
    RecordIdentitySubstitution(String),
    /// A batch mixed already committed records with new records.
    #[error("runtime append cannot mix exact replay with new records")]
    MixedReplayBatch,
    /// Exact replay referred to a checkpoint other than the current immutable
    /// frontier.
    #[error("exact replay is supported only for the current checkpoint")]
    ReplayCheckpointMismatch,
    /// Exact replay differed in order, commit time, or record membership.
    #[error("runtime append differs from the committed checkpoint batch")]
    ReplayBatchMismatch,
    /// A read requested an absent immutable record.
    #[error("runtime record {0} is absent")]
    RecordMissing(String),
    /// A record existed only after the supplied immutable snapshot.
    #[error("runtime record {0} is outside the supplied snapshot")]
    RecordOutsideSnapshot(String),
    /// Historical topology was requested from something other than the exact
    /// V2 execution-binding carrier.
    #[error("record {0} is not nq.execution_identity_binding.v2")]
    NotExecutionBinding(String),
    /// A historical dependency unexpectedly disappeared after graph
    /// validation.
    #[error("historical dependency {0} is unavailable")]
    HistoricalDependencyMissing(String),
    /// Inspector projection is intentionally disposable and must be rebuilt.
    #[error("disposable inspector projection is unavailable")]
    InspectorProjectionUnavailable,
    /// Inspector cursor or limit escaped the immutable snapshot.
    #[error("invalid inspector page request")]
    InvalidInspectorPage,
    /// A named prelaunch record was absent.
    #[error("required prelaunch record {0} is absent")]
    PrelaunchRecordMissing(String),
    /// A named prelaunch record used an unexpected schema.
    #[error("prelaunch record {record_id} has schema {observed}; expected {expected}")]
    PrelaunchRecordSchemaMismatch {
        /// Exact record identity.
        record_id: Sha256Digest,
        /// Required schema.
        expected: &'static str,
        /// Observed schema.
        observed: &'static str,
    },
    /// The named prelaunch closure did not end in accepted/reserved/launched.
    #[error("prelaunch closure is not accepted, reserved, and durably launched")]
    PrelaunchNotAcceptedReservedLaunched,
    /// Exact production identities could not be recovered.
    #[error("prelaunch production identity is missing or incompatible")]
    PrelaunchIdentityMismatch,
    /// Exact replay must not launch a second provider attempt.
    #[error("an exact prelaunch replay cannot create another execution grant")]
    PrelaunchReplayCannotRerun,
    /// Durable append returned a different checkpoint than the runtime opened.
    #[error("durable prelaunch checkpoint differs from the reopened frontier")]
    PrelaunchCheckpointMismatch,
    /// A core custody transition named a launch other than the exact prepared
    /// occurrence.
    #[error("custody transition launch identity differs from the exact prepared launch")]
    PreparedCustodyLaunchSubstitution,
    /// The runtime could not read the exact Linux boot-id carrier.
    #[error("runtime-owned deadline refused because Linux boot identity was unavailable")]
    NativeDeadlineBootIdentityUnavailable,
    /// Linux boot identity changed across the runtime-owned clock bracket.
    #[error("runtime-owned deadline refused because Linux boot identity changed while sampling")]
    NativeDeadlineBootIdentityChanged,
    /// The exact Linux boot-id bytes were not the canonical procfs carrier.
    #[error("runtime-owned deadline refused malformed Linux boot identity")]
    NativeDeadlineBootIdentityMalformed,
    /// One required native clock observation failed.
    #[error("runtime-owned deadline refused because {0} was unavailable")]
    NativeDeadlineClockUnavailable(&'static str),
    /// One native clock observation could not be represented exactly.
    #[error("runtime-owned deadline refused an invalid or overflowing {0} observation")]
    NativeDeadlineClockInvalid(&'static str),
    /// The runtime-owned deadline template exceeded the bounded carrier.
    #[error("runtime-owned deadline policy is malformed or outside bounded representation")]
    NativeDeadlinePolicyInvalid,
    /// No unique cohort-named native clock qualification matched the launch.
    #[error("runtime-owned deadline requires one exact cohort clock qualification")]
    NativeDeadlineClockQualificationMissing,
    /// The recomputed runtime-owned deadline refused the launch.
    #[error("runtime-owned deadline evaluation refused launch: {0}")]
    NativeDeadlineRefused(String),
    /// Runtime-owned deadline provenance and the exact launch graph disagreed.
    #[error("runtime-owned deadline provenance differs from the exact launch graph")]
    NativeDeadlineProvenanceMismatch,
}
