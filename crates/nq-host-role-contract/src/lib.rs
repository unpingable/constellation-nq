//! Host-role runtime contract carriers and semantic validation.
//!
//! This crate is the repository-native implementation seam for the
//! operator-ratified Host-Role Runtime Contract v1 at skunkworks commit
//! `d8aba7b728236120e0dfd05ba6feb3e64fc3647d`.
//!
//! It deliberately provides no scheduler, recurrence, posture, IAM service,
//! execution engine, store, transport, UI, or actuation. Possessing a valid
//! record or manifest does not grant permission to invoke a diagnostic or
//! mutate a node.

mod assets;
mod graph;
mod identity;
mod record;
mod schema;

pub use assets::{
    CONTRACT_SOURCE_COMMIT, CONTRACT_SOURCE_PATH, CONTRACT_SOURCE_TREE, ContractPackageManifest,
    ContractSource, SchemaAsset, verified_package_manifest,
};
pub use graph::{ExternalRecordCatalog, RuntimeRecordSet, ValidationContext};
pub use identity::{
    CatalogSnapshot, EffectiveInterval, Generation, IdentityCatalog, IdentityId, IdentityKey,
    IdentityKind, IdentityRef, IdentityVersion, NamespaceId, NamespaceSnapshot, NamespaceVersion,
    RecordRef, Timestamp, Token,
};
pub use record::{
    ArtifactCustodyReceipt, ArtifactDeliveryAttempt, ArtifactDeliveryRecord,
    AuthenticatedArtifactEnvelope, BufferDeliveryPolicy, CustodyReservation, DecommissionCut,
    DecommissionLedgerSnapshot, DiagnosticInvocationRequest, ExecutionIdentityBindingV2,
    ExecutionLaunch, HostRoleLifecycleEvent, HostRoleRelation, InspectorReadReceipt,
    InspectorResultSet, InspectorSnapshot, InvocationDecision, NodeEnrollment,
    NodeKeyLifecycleEvent, OperationAuthorization, RestoreActivationProof, RoleManifest,
    RuntimeActivation, RuntimeRecord, RuntimeSchema, StaticProfileCohortManifest,
    ValidatedRuntimeRecord, WitnessAttachment, WitnessLifecycleEvent,
};

use thiserror::Error;

/// Contract validation result.
pub type Result<T> = std::result::Result<T, ContractError>;

/// Typed refusal returned at the host-role contract boundary.
#[derive(Debug, Error)]
pub enum ContractError {
    /// JSON decoding failed.
    #[error("invalid JSON record: {0}")]
    Json(#[from] serde_json::Error),
    /// RFC 8785 canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] nq_protocol::CanonicalizationError),
    /// Input bytes were valid JSON but not exact canonical bytes.
    #[error("record bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalRecord,
    /// Catalog snapshot bytes were not exact canonical bytes.
    #[error("identity catalog snapshot bytes are not exact RFC 8785 canonical JSON")]
    NonCanonicalCatalogSnapshot,
    /// Top-level record was not an object.
    #[error("runtime record must be a JSON object")]
    RecordMustBeObject,
    /// Schema was absent or not a string.
    #[error("runtime record lacks a string schema")]
    MissingSchema,
    /// Schema is not supported by this package.
    #[error("unsupported runtime schema {0}")]
    UnknownRuntimeSchema(String),
    /// Record identity was absent.
    #[error("runtime record lacks its schema-selected record identity")]
    MissingRecordId,
    /// Top-level fields differed from the closed schema surface.
    #[error("record shape for {schema:?} differs; unknown={unknown:?}, missing={missing:?}")]
    RecordShape {
        /// Record schema.
        schema: RuntimeSchema,
        /// Unknown fields.
        unknown: Vec<String>,
        /// Missing fields.
        missing: Vec<String>,
    },
    /// Nested object escaped its closed shape.
    #[error("nested contract object has an invalid shape at {0}")]
    NestedRecordShape(&'static str),
    /// A required field was absent.
    #[error("missing field {field} in {schema:?}")]
    MissingField {
        /// Schema being read.
        schema: RuntimeSchema,
        /// Missing field.
        field: &'static str,
    },
    /// Expected string field.
    #[error("field {0} must be a string")]
    ExpectedString(&'static str),
    /// Expected object field.
    #[error("field {0} must be an object")]
    ExpectedObject(&'static str),
    /// Expected array field.
    #[error("field must be an array")]
    ExpectedArray,
    /// Expected nonnegative integer field.
    #[error("field {0} must be a nonnegative safe integer")]
    ExpectedUnsigned(&'static str),
    /// Expected Boolean field.
    #[error("field {0} must be a boolean")]
    ExpectedBoolean(&'static str),
    /// Identity path was malformed.
    #[error("invalid production identity path {0:?}")]
    InvalidIdentityPath(String),
    /// Contract token was malformed.
    #[error("invalid bounded contract token {0:?}")]
    InvalidToken(String),
    /// Generation text was malformed.
    #[error("invalid positive generation {0:?}")]
    InvalidGeneration(String),
    /// Timestamp was malformed.
    #[error("invalid RFC 3339 timestamp {0:?}")]
    InvalidTimestamp(String),
    /// Effective interval was empty or reversed.
    #[error("effective interval end must be strictly after its start")]
    InvalidEffectiveInterval,
    /// Identity class differed from the required slot.
    #[error("identity kind mismatch at {field}: expected {expected:?}, got {actual:?}")]
    IdentityKindMismatch {
        /// Field being validated.
        field: &'static str,
        /// Required kind.
        expected: IdentityKind,
        /// Actual kind.
        actual: IdentityKind,
    },
    /// Exact descriptor key was reused with different bytes.
    #[error("identity descriptor substitution")]
    IdentityDescriptorSubstitution,
    /// Persisted catalog snapshot contained no descriptors.
    #[error("identity catalog snapshot must not be empty")]
    EmptyIdentityCatalog,
    /// Persisted catalog snapshot was not in strict canonical order.
    #[error("identity catalog snapshot is not in canonical descriptor order")]
    IdentityCatalogNotCanonical,
    /// Exact identity was absent from the admitted catalog.
    #[error("unresolved identity {kind:?}:{id}@{version}")]
    UnresolvedIdentity {
        /// Identity class.
        kind: IdentityKind,
        /// Identity path.
        id: String,
        /// Identity version.
        version: String,
    },
    /// Array duplicated one exact member.
    #[error("contract array contains a duplicate canonical member")]
    DuplicateArrayMember,
    /// Nonclaim list was absent, empty, or malformed.
    #[error("record nonclaims must be a nonempty unique string list")]
    InvalidNonclaims,
    /// Number escaped exact I-JSON range.
    #[error("integer exceeds the exact I-JSON range")]
    UnsafeInteger,
    /// NQ record tried to own recurrence/posture/comparison/expiry.
    #[error("record contains a Nightshift-owned or forbidden authority field")]
    ForbiddenAuthorityField,
    /// Semantic cohort included topology or operational membership.
    #[error("topology identity cannot occupy a static semantic cohort member slot")]
    TopologyIdentityInSemanticCohort,
    /// Relation kind was unknown.
    #[error("unknown host-role relation kind {0}")]
    UnknownRelationKind(String),
    /// Witness class and witness instance were collapsed.
    #[error("witness class and witness instance must remain distinct identities")]
    WitnessClassInstanceAlias,
    /// Capacity reserve/high-watermark/total ordering was incoherent.
    #[error("buffer/delivery capacity policy is incoherent")]
    InvalidCapacityPolicy,
    /// Buffer/delivery policy changed a ratified custody or authority boundary.
    #[error("buffer/delivery policy contradicts the ratified runtime law")]
    InvalidBufferDeliveryPolicy,
    /// Attempt count and exact durable retry schedule differed.
    #[error("buffer/delivery retry policy is incoherent")]
    InvalidRetryPolicy,
    /// A lifecycle operation named an illegal state edge.
    #[error("runtime lifecycle operation has an invalid state transition")]
    InvalidLifecycleTransition,
    /// A lifecycle proof was omitted or supplied for the wrong operation.
    #[error("runtime lifecycle operation proof does not match the operation")]
    LifecycleProofMismatch,
    /// Restore decision contradicted its exact checks or outputs.
    #[error("restore activation proof has an invalid decision")]
    InvalidRestoreDecision,
    /// A quarantined/replacement restore exposed an activation candidate.
    #[error("restore quarantine or replacement decision exposed activation eligibility")]
    RestoreQuarantineBypass,
    /// Request authorization preimage did not match exact bytes.
    #[error("diagnostic request preimage digest mismatch")]
    RequestPreimageDigestMismatch,
    /// Request self-digest did not match exact bytes.
    #[error("diagnostic request digest mismatch")]
    RequestDigestMismatch,
    /// Decision state was unknown.
    #[error("unknown invocation decision {0}")]
    UnknownInvocationDecision(String),
    /// Authorization decision was malformed.
    #[error("operation authorization decision is not granted/refused")]
    InvalidAuthorizationDecision,
    /// Reservation component arithmetic failed.
    #[error("custody reservation component arithmetic is inconsistent")]
    InvalidReservationArithmetic,
    /// Custody was not committed before launch.
    #[error("custody reservation is not in reserved state")]
    CustodyNotReserved,
    /// Custody reservation was empty or expired.
    #[error("custody reservation expiry does not follow reservation time")]
    ExpiredCustodyReservation,
    /// Launch state was not closed.
    #[error("execution launch must have launched status")]
    InvalidLaunchStatus,
    /// Launch deadline and execution budget disagreed.
    #[error("launch deadline does not equal its exact execution budget")]
    LaunchDeadlineSubstitution,
    /// V2 production binding was not fully resolved.
    #[error("execution identity binding is not resolved")]
    BindingNotResolved,
    /// Diagnostic contract was not V2.
    #[error("binding does not name nq.diagnostic_execution.v2")]
    UnsupportedDiagnosticContract,
    /// Signed pointer projection did not match its digest.
    #[error("signed-field projection digest mismatch")]
    SignedProjectionMismatch,
    /// JSON pointer was malformed.
    #[error("invalid JSON pointer {0}")]
    InvalidJsonPointer(String),
    /// JSON pointer did not resolve.
    #[error("unresolved JSON pointer {0}")]
    UnresolvedJsonPointer(String),
    /// Attempt number was invalid.
    #[error("delivery attempt number must be positive")]
    InvalidAttemptNumber,
    /// Receiver custody incorrectly claimed semantic admission.
    #[error("custody receipt may not claim semantic admission")]
    CustodyReceiptClaimsSemanticAdmission,
    /// Delivery state was unknown.
    #[error("unknown delivery state {0}")]
    UnknownDeliveryState(String),
    /// Inspector result set commitment was substituted.
    #[error("inspector ledger commitment mismatch")]
    InspectorLedgerCommitMismatch,
    /// Inspector page did not bind its result set.
    #[error("inspector page substituted its immutable result set")]
    InspectorSnapshotSubstitution,
    /// Inspector decision was unknown.
    #[error("unknown inspector read decision")]
    InvalidInspectorDecision,
    /// Refused read nevertheless disclosed records or response bytes.
    #[error("refused inspector read disclosed data")]
    RefusedInspectorReadDisclosesData,
    /// Decommission snapshot count, digest, or self-identity differed.
    #[error("decommission ledger snapshot commitment mismatch")]
    DecommissionSnapshotCommitmentMismatch,
    /// Decommission snapshot ledger entries were not in strict canonical order.
    #[error("decommission ledger snapshot entries are not in canonical order")]
    DecommissionSnapshotNotCanonical,
    /// Decommission cut did not atomically fence new requests.
    #[error("decommission cut does not establish the required request fence")]
    DecommissionFenceGap,
    /// Decommission cut named an unsupported result state.
    #[error("decommission cut result state is invalid")]
    InvalidDecommissionState,
    /// Initial/terminal cut predecessor relationship was malformed.
    #[error("decommission predecessor cut relationship is invalid")]
    DecommissionPredecessorMismatch,
    /// Terminal decommission retained unresolved work.
    #[error("terminal decommission retains unresolved work")]
    DecommissionDrainIncomplete,
    /// Content-derived identity did not match its preimage.
    #[error("self identity mismatch at {0}")]
    SelfIdentityMismatch(&'static str),
    /// Embedded asset manifest was substituted.
    #[error("host-role package asset manifest provenance mismatch")]
    AssetManifestSubstitution,
    /// Embedded manifest duplicated a schema.
    #[error("duplicate schema asset {0}")]
    DuplicateSchemaAsset(String),
    /// Embedded manifest named an unknown schema.
    #[error("unknown schema asset {0}")]
    UnknownSchemaAsset(String),
    /// Embedded schema digest differed.
    #[error("schema asset digest mismatch for {0}")]
    SchemaAssetDigestMismatch(String),
    /// Embedded source path differed.
    #[error("schema source path mismatch for {0}")]
    SchemaAssetPathMismatch(String),
    /// Embedded manifest omitted assets.
    #[error("schema asset manifest is incomplete")]
    MissingSchemaAssets,
    /// Embedded manifest omitted one supported schema.
    #[error("missing schema asset {0}")]
    MissingSchemaAsset(String),
    /// Exact embedded JSON Schema rejected a carrier.
    #[error("embedded schema validation failed for {schema:?}: {detail}")]
    SchemaValidation {
        /// Carrier schema.
        schema: RuntimeSchema,
        /// Exact bounded failure location and constraint.
        detail: String,
    },
    /// Record identity was reused by different exact bytes.
    #[error("immutable record identity reused with different exact bytes")]
    DuplicateRecordIdentity,
    /// Exact record reference did not resolve.
    #[error("unresolved record reference {0}")]
    UnresolvedRecordReference(String),
    /// Exact record reference substituted schema or bytes.
    #[error("record reference substituted exact target bytes")]
    RecordReferenceSubstitution,
    /// Immutable record graph contained a cycle.
    #[error("immutable record dependency graph contains a cycle")]
    RecordReferenceCycle,
    /// Relation, role, cohort, or generation join failed.
    #[error("host-role topology or generation join mismatch: {0}")]
    TopologyJoin(&'static str),
    /// Witness privilege, namespace, profile, or slot join failed.
    #[error("witness attachment exceeds or differs from its exact role slot: {0}")]
    WitnessSlotJoin(&'static str),
    /// Request/decision/reservation/launch binding differed.
    #[error("bounded invocation chain substituted an exact dependency: {0}")]
    InvocationJoin(&'static str),
    /// Administrative or diagnostic authorization did not close over its exact use.
    #[error("operation authorization does not close over its exact consumer set: {0}")]
    AuthorizationJoin(&'static str),
    /// Delivery dependency or state chain differed.
    #[error("delivery dependency chain mismatch: {0}")]
    DeliveryJoin(&'static str),
    /// Runtime lifecycle dependency or state chain differed.
    #[error("runtime lifecycle dependency chain mismatch: {0}")]
    LifecycleJoin(&'static str),
    /// Restore or decommission graph dependency differed.
    #[error("restore/decommission dependency chain mismatch: {0}")]
    RetirementJoin(&'static str),
}
