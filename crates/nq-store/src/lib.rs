#![allow(missing_docs, clippy::doc_markdown, clippy::missing_errors_doc)]

//! Durable, profile-neutral storage for nq-ng.
//!
//! The schema deliberately separates byte-for-byte custody from admitted semantic
//! evidence. Durable facts are append-only. The two mutable tables are explicitly
//! rebuildable pointers to the latest finding and status events.
//!
//! The physical custody arena remains deliberately store-private:
//!
//! ```compile_fail
//! use nq_store::custody_arena::CustodyArena;
//! ```
//!
//! Product code can use the exported governed-custody facade only to reserve,
//! seal, reopen, and index exact opaque bytes. That facade cannot launch a
//! provider, parse intake, establish evaluator occurrence, construct a
//! diagnostic binding, or assign semantic standing.

mod custody_arena;
mod governed_custody;

pub use governed_custody::{
    CustodiedAcquisition, GOVERNED_CUSTODY_CLOSURE_SCHEMA, GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA,
    GOVERNED_PROTECTED_TERMINAL_SCHEMA, GovernedAcquisitionCustodyInput,
    GovernedClosureAcquisitionInput, GovernedClosureCheckpointInput,
    GovernedClosureDependencyGenerationInput, GovernedClosureDerivationInput,
    GovernedClosureLocalOriginInput, GovernedClosurePrelaunchInput, GovernedClosureRecordReference,
    GovernedCustody, GovernedCustodyCommitment, GovernedCustodyInspection,
    GovernedCustodyInventoryEntry, GovernedCustodyRecoveryClass, GovernedCustodyReservation,
    GovernedCustodyReservationLedgerBinding, GovernedCustodyState, GovernedDerivationCustodyClaim,
    GovernedExecutionCustodyClosureV2, GovernedExecutionCustodyClosureV2Capacity,
    GovernedExecutionCustodyClosureV2CapacityInput, GovernedExecutionCustodyClosureV2Input,
    GovernedProjectionVerification, GovernedProjectionVerificationDisposition,
    GovernedProtectedFailure, GovernedProtectedFailureAccess, GovernedProtectedTerminal,
    GovernedProtectedTerminalClass, GovernedProtectedTerminalDeadlineCompliance,
    GovernedProtectedTerminalDisposition, GovernedProtectedTerminalDocument,
    GovernedProtectedTerminalInput, GovernedProtectedTerminalReason,
    GovernedProtectedTerminalRequest, GovernedProtectedTerminalReservation,
    GovernedProtectedTerminalization, governed_acquisition_capacity_bound,
    governed_execution_custody_closure_v2_capacity_bound,
};

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{SecondsFormat, Utc};
use nq_protocol::{Sha256Digest, sha256_bytes};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCHEMA: &str = include_str!("schema.sql");
const SCHEMA_V3: &str = include_str!("schema_v3.sql");
const SCHEMA_V4: &str = include_str!("schema_v4.sql");
const SCHEMA_V5: &str = include_str!("schema_v5.sql");
const SCHEMA_V3_TO_V4_PROVIDER: &str = include_str!("schema_v3_to_v4_provider.sql");
const SCHEMA_V4_TO_V5_DIAGNOSTIC_ARTIFACTS: &str =
    include_str!("schema_v4_to_v5_diagnostic_artifacts.sql");
const SCHEMA_V5_TO_V6_RUNTIME_LEDGER: &str = include_str!("schema_v5_to_v6_runtime_ledger.sql");
const SCHEMA_V6_TO_V7_RUNTIME_DEPENDENCIES: &str =
    include_str!("schema_v6_to_v7_runtime_dependencies.sql");
const APPLICATION_ID: i64 = 1_313_951_303;

const SCHEMA_METADATA_V4: &str = r"CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL CHECK (product = 'nq-ng'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 4),
    -- Digest of the exact schema.sql artifact compiled into the writing binary.
    -- Rejects stale provisional-candidate databases at startup; it is NOT a
    -- tamper attestation of the live SQLite schema (which the structural
    -- fingerprint checks separately).
    schema_artifact_digest TEXT NOT NULL CHECK (length(schema_artifact_digest) = 71 AND substr(schema_artifact_digest, 1, 7) = 'sha256:'),
    initialized_at TEXT NOT NULL
) STRICT;";

const SCHEMA_METADATA_V4_TRIGGERS: &str = "CREATE TRIGGER immutable_schema_metadata_update BEFORE UPDATE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;\n\
     CREATE TRIGGER immutable_schema_metadata_delete BEFORE DELETE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;";

const SCHEMA_METADATA_V5: &str = r"CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL CHECK (product = 'nq-ng'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 5),
    -- Digest of the exact schema.sql artifact compiled into the writing binary.
    -- Rejects stale provisional-candidate databases at startup; it is NOT a
    -- tamper attestation of the live SQLite schema (which the structural
    -- fingerprint checks separately).
    schema_artifact_digest TEXT NOT NULL CHECK (length(schema_artifact_digest) = 71 AND substr(schema_artifact_digest, 1, 7) = 'sha256:'),
    initialized_at TEXT NOT NULL
) STRICT;";

const SCHEMA_METADATA_V5_TRIGGERS: &str = "CREATE TRIGGER immutable_schema_metadata_update BEFORE UPDATE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;\n\
     CREATE TRIGGER immutable_schema_metadata_delete BEFORE DELETE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;";

const SCHEMA_METADATA_V6: &str = r"CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL CHECK (product = 'nq-ng'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 6),
    -- Digest of the exact schema.sql artifact compiled into the writing binary.
    -- Rejects stale provisional-candidate databases at startup; it is NOT a
    -- tamper attestation of the live SQLite schema (which the structural
    -- fingerprint checks separately).
    schema_artifact_digest TEXT NOT NULL CHECK (length(schema_artifact_digest) = 71 AND substr(schema_artifact_digest, 1, 7) = 'sha256:'),
    initialized_at TEXT NOT NULL
) STRICT;";

const SCHEMA_METADATA_V6_TRIGGERS: &str = "CREATE TRIGGER immutable_schema_metadata_update BEFORE UPDATE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;\n\
     CREATE TRIGGER immutable_schema_metadata_delete BEFORE DELETE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;";

const SCHEMA_METADATA_V7: &str = r"CREATE TABLE schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL CHECK (product = 'nq-ng'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 7),
    -- Digest of the exact schema.sql artifact compiled into the writing binary.
    -- Rejects stale provisional-candidate databases at startup; it is NOT a
    -- tamper attestation of the live SQLite schema (which the structural
    -- fingerprint checks separately).
    schema_artifact_digest TEXT NOT NULL CHECK (length(schema_artifact_digest) = 71 AND substr(schema_artifact_digest, 1, 7) = 'sha256:'),
    initialized_at TEXT NOT NULL
) STRICT;";

const SCHEMA_METADATA_V7_TRIGGERS: &str = "CREATE TRIGGER immutable_schema_metadata_update BEFORE UPDATE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;\n\
     CREATE TRIGGER immutable_schema_metadata_delete BEFORE DELETE ON schema_metadata BEGIN SELECT RAISE(ABORT, 'append-only table'); END;";

/// Exact schema-artifact digest of the qualified v0.1.0 store. It is retained
/// only to validate an explicit v3-to-v4 upgrade source; normal opening never
/// interprets v3 bytes as current storage.
pub const SCHEMA_V3_ARTIFACT_DIGEST: &str =
    "sha256:3ea4295c7574ed41cc9d4389a216c21103a5b3851509988e300e788292f657e2";

/// Exact schema-artifact digest of the qualified schema-v4 store. It is
/// retained only to validate an explicit v4-to-v5 upgrade source.
pub const SCHEMA_V4_ARTIFACT_DIGEST: &str =
    "sha256:649b514a7cacddf4dbd55dad587947edd8499e9dc1ee6785370654075951cfa1";

/// Exact schema-artifact digest of the qualified schema-v5 store. It is
/// retained only to validate an explicit v5-to-v6 upgrade source.
pub const SCHEMA_V5_ARTIFACT_DIGEST: &str =
    "sha256:91455172d1bed3b5e67ae25b7122015fc3d1197ab9b676511a938d4eb658e94b";

/// Exact schema-artifact digest of the qualified schema-v6 runtime-ledger
/// store. It is retained only to validate an explicit v6-to-v7 upgrade source.
pub const SCHEMA_V6_ARTIFACT_DIGEST: &str =
    "sha256:3785e935c296963ec20ec1b6ba17f87499fab6280df39b3e9619f5062a3ba915";

/// Schema tag bound into every admission-context digest preimage. Bump only when
/// the constituent set or its canonicalization changes.
pub const ADMISSION_CONTEXT_SCHEMA: &str = "nq-ng.admission_context.v1";

/// Version of the persisted admitted-judgment representation. Bound into every
/// `judgment_digest` and stored beside the judgment so 3B verification pins the
/// exact format it is checking.
pub const JUDGMENT_SCHEMA_VERSION: &str = "nq-ng.judgment.v1";

/// First exact NQ provider-intake custody representation.
pub const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";

/// First exact durable-processing acknowledgment representation.
pub const PROVIDER_INTAKE_ACK_SCHEMA: &str = "nq.provider_intake_ack.v1";

/// Canonical root preimage for one globally sequenced runtime record.
pub const RUNTIME_LEDGER_ROOT_SCHEMA: &str = "nq.runtime_ledger_root.v1";

/// Canonical identity preimage for one dependency-bound atomic runtime-record
/// append.
pub const RUNTIME_LEDGER_BATCH_SCHEMA: &str = "nq.runtime_ledger_batch.v2";

const LEGACY_RUNTIME_LEDGER_BATCH_SCHEMA: &str = "nq.runtime_ledger_batch.v1";
const RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA: &str =
    "nq.host_role_runtime_dependency_generation_custody.v1";

/// Closed host-role record vocabulary ratified for the runtime ledger.
///
/// Presence in this list permits exact custody only. It does not establish
/// semantic validity, applicability, standing, reliance, or authority.
pub const SUPPORTED_RUNTIME_RECORD_SCHEMAS: &[&str] = &[
    "nightshift.artifact_custody_receipt.v1",
    "nq.artifact_delivery_attempt.v1",
    "nq.artifact_delivery_record.v1",
    "nq.authenticated_artifact_envelope.v1",
    "nq.buffer_delivery_policy.v1",
    "nq.custody_reservation.v1",
    "nq.deadline_evaluation.v1",
    "nq.decommission_cut.v1",
    "nq.decommission_ledger_snapshot.v1",
    "nq.diagnostic_invocation_request.v1",
    "nq.execution_identity_binding.v2",
    "nq.execution_launch.v1",
    "nq.host_role_lifecycle_event.v1",
    "nq.host_role_relation.v1",
    "nq.inspector_read_receipt.v1",
    "nq.inspector_result_set.v1",
    "nq.inspector_snapshot.v1",
    "nq.invocation_decision.v1",
    "nq.native_clock_qualification.v1",
    "nq.native_profile_qualification.v1",
    "nq.node_enrollment.v1",
    "nq.node_key_lifecycle_event.v1",
    "nq.operation_authorization.v1",
    "nq.restore_activation_proof.v1",
    "nq.role_manifest.v1",
    "nq.runtime_activation.v1",
    "nq.static_profile_cohort_manifest.v1",
    "nq.witness_attachment.v1",
    "nq.witness_lifecycle_event.v1",
];

/// Closed external canonical record classes that the runtime ledger may retain
/// for exact cross-system correspondence.
pub const SUPPORTED_EXTERNAL_RUNTIME_RECORD_SCHEMAS: &[&str] = &["nq.provider_intake.v1"];

/// Closed derivation law for the admitted local helper provider's semantics.
pub const LOCAL_PROVIDER_SEMANTIC_SCHEMA: &str = "nq.local_provider_semantics.v1";

/// NQ-derived, local-helper-only provider admission representation.
pub const LOCAL_PROVIDER_ADMISSION_SCHEMA: &str = "nq.local_provider_admission.v1";
static EXPECTED_SCHEMA_FINGERPRINT: LazyLock<Result<String, String>> = LazyLock::new(|| {
    let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
    connection
        .execute_batch(SCHEMA)
        .map_err(|error| error.to_string())?;
    schema_fingerprint(&connection).map_err(|error| error.to_string())
});
static EXPECTED_SCHEMA_V3_FINGERPRINT: LazyLock<Result<String, String>> = LazyLock::new(|| {
    let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
    connection
        .execute_batch(SCHEMA_V3)
        .map_err(|error| error.to_string())?;
    schema_fingerprint(&connection).map_err(|error| error.to_string())
});
static EXPECTED_SCHEMA_V4_FINGERPRINT: LazyLock<Result<String, String>> = LazyLock::new(|| {
    let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
    connection
        .execute_batch(SCHEMA_V4)
        .map_err(|error| error.to_string())?;
    schema_fingerprint(&connection).map_err(|error| error.to_string())
});
static EXPECTED_SCHEMA_V5_FINGERPRINT: LazyLock<Result<String, String>> = LazyLock::new(|| {
    let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
    connection
        .execute_batch(SCHEMA_V5)
        .map_err(|error| error.to_string())?;
    schema_fingerprint(&connection).map_err(|error| error.to_string())
});
static EXPECTED_SCHEMA_V6_FINGERPRINT: LazyLock<Result<String, String>> = LazyLock::new(|| {
    let mut connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
    connection
        .execute_batch(SCHEMA_V5)
        .map_err(|error| error.to_string())?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(
            "DROP TRIGGER immutable_schema_metadata_update;
             DROP TRIGGER immutable_schema_metadata_delete;
             ALTER TABLE schema_metadata RENAME TO schema_metadata_v5;",
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(SCHEMA_METADATA_V6)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO schema_metadata (
                singleton, product, schema_version, schema_artifact_digest, initialized_at
             )
             SELECT singleton, product, 6, ?1, initialized_at
             FROM schema_metadata_v5",
            [SCHEMA_V6_ARTIFACT_DIGEST],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute("DROP TABLE schema_metadata_v5", [])
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(SCHEMA_METADATA_V6_TRIGGERS)
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(SCHEMA_V5_TO_V6_RUNTIME_LEDGER)
        .map_err(|error| error.to_string())?;
    transaction
        .pragma_update(None, "user_version", 6)
        .map_err(|error| error.to_string())?;
    let fingerprint = schema_fingerprint(&transaction).map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(fingerprint)
});

/// The only schema version understood by this crate.
pub const SCHEMA_VERSION: i64 = 7;

/// Hard ceiling for one page returned through the public read model helpers.
pub const MAX_PUBLIC_QUERY_ROWS: u32 = 1_000;

/// Storage-wide ceiling for any one canonical JSON document.
pub const MAX_STORED_JSON_BYTES: usize = nq_protocol::MAX_RESPONSE_FRAME_BYTES;

/// A materialization plan may contain the previous and desired bounded
/// admission locks plus recovery metadata.
const MAX_BINDING_MATERIALIZATION_BYTES: usize = 3 * 1_048_576;

/// Errors returned at the storage boundary.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A SQLite operation failed.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A filesystem operation failed.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// Explicit initialization was required before opening the database.
    #[error("database is not initialized: {0}")]
    NotInitialized(PathBuf),
    /// Initialization never overwrites an existing SQLite schema.
    #[error("database already contains a schema (user_version {found_version})")]
    AlreadyInitialized { found_version: i64 },
    /// A database belongs to another application.
    #[error("database application id {found} is not nq-ng application id {expected}")]
    ApplicationIdMismatch { found: i64, expected: i64 },
    /// Runtime schema upgrades are forbidden.
    #[error("database schema version {found} is incompatible; this binary requires {supported}")]
    SchemaVersionMismatch { found: i64, supported: i64 },
    /// The database failed an integrity or schema invariant check.
    #[error("database integrity check failed: {0}")]
    Integrity(String),
    /// A document was not valid canonical JSON.
    #[error("canonical JSON error: {0}")]
    CanonicalJson(String),
    /// A core storage invariant was violated before SQL was attempted.
    #[error("storage invariant violated: {0}")]
    Invariant(String),
    /// A repeated provider attempt reused an identity for different evidence or
    /// a different bound context.
    #[error("provider intake replay conflict: {0}")]
    ReplayConflict(String),
}

/// A canonical JSON document and its SHA-256 semantic digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalDocument {
    bytes: Vec<u8>,
    digest: String,
}

impl CanonicalDocument {
    /// Canonicalize a serializable value with the authoritative protocol routine.
    pub fn from_serializable<T: Serialize>(value: &T) -> Result<Self, StoreError> {
        let bytes = nq_protocol::canonical_json_bytes(value)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        validate_document_size(bytes.len())?;
        let digest = sha256_digest(&bytes);
        Ok(Self { bytes, digest })
    }

    /// Accept bytes only when they are already in canonical protocol form.
    pub fn from_canonical_bytes(bytes: Vec<u8>) -> Result<Self, StoreError> {
        validate_document_size(bytes.len())?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        let expected = nq_protocol::canonical_json_bytes(&value)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        if expected != bytes {
            return Err(StoreError::CanonicalJson(
                "document bytes are valid JSON but not canonical".to_owned(),
            ));
        }
        let digest = sha256_digest(&bytes);
        Ok(Self { bytes, digest })
    }

    /// Return the exact canonical bytes persisted by the store.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the lowercase SHA-256 digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// One canonical record to append to the host-role runtime ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecordInput {
    pub record_id: String,
    pub record_schema: String,
    pub canonical_bytes: CanonicalDocument,
    pub committed_at: String,
}

/// Exact dependency-generation custody already authenticated by the host-role
/// runtime and bound into one new runtime-ledger checkpoint.
///
/// The store verifies canonical byte identity and structural correspondence.
/// It does not authenticate signatures or assign semantic standing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCheckpointDependencyInput {
    pub dependency_generation_id: Sha256Digest,
    pub trust_anchor_id: Sha256Digest,
    pub canonical_custody: CanonicalDocument,
}

/// One atomic, idempotent append of one or more runtime records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecordBatchInput {
    pub checkpoint_id: String,
    pub expected_predecessor_checkpoint_id: Option<String>,
    pub expected_predecessor_ledger_root: Option<Sha256Digest>,
    pub dependency: RuntimeCheckpointDependencyInput,
    pub records: Vec<RuntimeRecordInput>,
}

/// Whether one exact runtime-record batch was newly committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeRecordAppendDisposition {
    Committed,
    Replayed,
}

/// Immutable checkpoint at the end of one atomic runtime-record append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeLedgerCheckpoint {
    pub checkpoint_sequence: u64,
    pub checkpoint_id: String,
    pub batch_digest: Sha256Digest,
    pub first_record_sequence: u64,
    pub last_record_sequence: u64,
    pub record_count: u64,
    pub predecessor_checkpoint_id: Option<String>,
    pub predecessor_ledger_root: Option<Sha256Digest>,
    pub checkpoint_ledger_root: Sha256Digest,
    pub committed_at: String,
}

/// Receipt for one exact runtime-record append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecordAppendReceipt {
    pub disposition: RuntimeRecordAppendDisposition,
    pub checkpoint: RuntimeLedgerCheckpoint,
}

/// Immutable dependency provenance bound to one runtime checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCheckpointDependencyBinding {
    /// Schema-v6 history predates authenticated checkpoint dependency binding.
    LegacyUnbound { source_schema_version: u32 },
    /// Exact authenticated dependency generation and its retained commitment.
    Authenticated {
        dependency_generation_id: Sha256Digest,
        trust_anchor_id: Sha256Digest,
        canonical_bytes_sha256: Sha256Digest,
        canonical_bytes_length: u64,
    },
}

/// Current materialization state of one committed dependency closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeDependencyGenerationByteState {
    VerifiedAvailable {
        canonical_custody: CanonicalDocument,
    },
    CommittedUnavailable,
    Corrupt {
        reason: String,
    },
}

/// Orthogonal checkpoint binding and dependency-byte access result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCheckpointDependencyAccess {
    pub checkpoint_id: String,
    pub binding: RuntimeCheckpointDependencyBinding,
    pub byte_state: Option<RuntimeDependencyGenerationByteState>,
}

/// One exactly reopened canonical runtime record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecordRow {
    pub record_sequence: u64,
    pub record_id: String,
    pub record_schema: String,
    pub canonical_bytes: CanonicalDocument,
    pub canonical_bytes_sha256: Sha256Digest,
    pub checkpoint_id: String,
    pub predecessor_record_id: Option<String>,
    pub predecessor_ledger_root: Option<Sha256Digest>,
    pub ledger_root: Sha256Digest,
    pub committed_at: String,
}

/// One page pinned to an immutable checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecordPage {
    pub checkpoint: Option<RuntimeLedgerCheckpoint>,
    pub after_record_sequence: u64,
    pub records: Vec<RuntimeRecordRow>,
    pub next_after_record_sequence: Option<u64>,
    pub complete: bool,
}

/// Integrity state of the disposable runtime-record lookup projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecordLookupStatus {
    pub ledger_records: u64,
    pub lookup_records: u64,
    pub missing_records: u64,
    pub extra_records: u64,
    pub mismatched_records: u64,
}

impl RuntimeRecordLookupStatus {
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.ledger_records == self.lookup_records
            && self.missing_records == 0
            && self.extra_records == 0
            && self.mismatched_records == 0
    }
}

/// One exact provider-attempt record used by a production V2 execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactProviderAttemptBindingInput {
    pub provider_attempt_record_id: String,
    pub intake_id: String,
}

/// Production companion closure for one local V2 artifact.
///
/// The runtime records are appended in the same transaction as the artifact
/// commitment and linkage. Earlier request/decision/launch records may already
/// exist; the terminal binding record is normally part of `runtime_records`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactExecutionBindingInput {
    pub runtime_records: RuntimeRecordBatchInput,
    pub execution_binding_record_id: String,
    pub outer_request_record_id: String,
    pub invocation_decision_record_id: String,
    pub execution_launch_record_id: String,
    pub outer_request_id: String,
    pub provider_attempts: Vec<DiagnosticArtifactProviderAttemptBindingInput>,
}

/// Reopened exact production companion closure for a local V2 artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactExecutionBinding {
    pub execution_binding: RuntimeRecordRow,
    pub outer_request: RuntimeRecordRow,
    pub invocation_decision: RuntimeRecordRow,
    pub execution_launch: RuntimeRecordRow,
    pub outer_request_id: String,
    pub provider_attempts: Vec<(
        RuntimeRecordRow,
        DiagnosticArtifactProviderAttemptBindingInput,
    )>,
}

/// Exact local origin for a diagnostic artifact committed atomically with one
/// collection.
///
/// An admitted detector artifact names its exact evaluation. An admitted
/// run-level production V2 artifact and a run-bearing non-success artifact have
/// no evaluation and retain `None`; the absence is semantic and must never be
/// filled from a later evaluation. The run-level admitted form additionally
/// requires its exact production execution binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactLocalOriginInput {
    pub run_id: String,
    pub evaluation_id: Option<String>,
    pub completed_at: String,
    /// Absent only for explicitly historical/pre-production local artifacts.
    /// A production host-role path must supply the complete V2 companion.
    pub execution_binding: Option<DiagnosticArtifactExecutionBindingInput>,
}

/// Opaque canonical diagnostic artifact to commit with one local collection.
///
/// `artifact_id` is the contract-owned semantic identity. The store derives and
/// separately persists the digest of the complete canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactCommitInput {
    pub artifact_id: Sha256Digest,
    pub contract_schema: String,
    pub canonical_bytes: CanonicalDocument,
    pub local_origin: DiagnosticArtifactLocalOriginInput,
}

/// Opaque canonical diagnostic artifact entering this store through import.
///
/// Import establishes custody only. It does not authenticate the producer,
/// admit the artifact as local testimony, or grant reliance or authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactImportInput {
    pub import_id: String,
    pub artifact_id: Sha256Digest,
    pub contract_schema: String,
    pub canonical_bytes: CanonicalDocument,
    pub imported_at: String,
}

/// Imported custody commitment whose exact bytes are currently unavailable.
///
/// This can never be used as a local execution origin. A later exact import may
/// rematerialize it only when length and complete-byte digest match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnavailableDiagnosticArtifactImportInput {
    pub import_id: String,
    pub artifact_id: Sha256Digest,
    pub contract_schema: String,
    pub canonical_bytes_sha256: Sha256Digest,
    pub canonical_bytes_length: u64,
    pub imported_at: String,
}

/// Immutable origin of one diagnostic-artifact commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticArtifactOrigin {
    Local {
        run_id: String,
        evaluation_id: Option<String>,
        completed_at: String,
        execution_binding_record_id: Option<String>,
    },
    Imported {
        import_id: String,
        imported_at: String,
    },
}

/// Immutable storage commitment independent of current byte availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactCommitment {
    pub artifact_sequence: u64,
    pub artifact_id: Sha256Digest,
    pub contract_schema: String,
    pub canonical_bytes_sha256: Sha256Digest,
    pub canonical_bytes_length: u64,
    pub committed_at: String,
    pub origin: DiagnosticArtifactOrigin,
}

/// Whether the caller declared support for the committed contract schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticArtifactSchemaSupport {
    Supported,
    Unsupported { contract_schema: String },
}

/// Current materialization and verification state of committed artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticArtifactByteState {
    VerifiedAvailable { canonical_bytes: CanonicalDocument },
    CommittedUnavailable,
    Corrupt { reason: String },
}

/// Orthogonal schema-support and byte-access result for one commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactAccess {
    pub commitment: DiagnosticArtifactCommitment,
    pub schema_support: DiagnosticArtifactSchemaSupport,
    pub byte_state: DiagnosticArtifactByteState,
}

/// Exact artifact lookup result. A missing commitment is never reported as
/// committed-but-unavailable.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum DiagnosticArtifactLookup {
    NotFound,
    Found(DiagnosticArtifactAccess),
}

/// Result of a verified opaque artifact import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticArtifactImportDisposition {
    Committed,
    CommittedUnavailable,
    Existing,
    Rematerialized,
}

/// Receipt returned after the import transaction commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticArtifactImportReceipt {
    pub import_id: String,
    pub artifact_id: Sha256Digest,
    pub contract_schema: String,
    pub canonical_bytes_sha256: Sha256Digest,
    pub canonical_bytes_length: u64,
    pub disposition: DiagnosticArtifactImportDisposition,
    pub imported_at: String,
}

/// A compiled profile descriptor snapshot.
#[derive(Clone, Debug)]
pub struct ProfileDescriptorInput {
    pub profile_id: String,
    pub profile_version: String,
    pub descriptor: CanonicalDocument,
    pub recorded_at: String,
}

/// The typed, identity-bearing constituents of an admission context, plus
/// inspectable receipt metadata.
///
/// The seven identity fields (the six digests and `protocol_version`) are the
/// exact preimage of `admission_context_digest`, which the store derives — never
/// a caller outside tests. The digest fields are [`Sha256Digest`] so an
/// arbitrary configuration string cannot be threaded in where an identity is
/// required. `target_triple`, `artifact_identity_method`, and
/// `platform_runtime_version` are retained as receipt metadata and are
/// deliberately excluded from the digest: the artifact digest already fixes the
/// compiled result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionIdentity {
    pub profile_semantic_id: Sha256Digest,
    pub detector_identity_digest: Sha256Digest,
    pub evaluator_source_digest: Sha256Digest,
    pub evaluator_artifact_digest: Sha256Digest,
    pub helper_artifact_digest: Sha256Digest,
    pub config_digest: Sha256Digest,
    pub protocol_version: String,
    pub target_triple: String,
    pub artifact_identity_method: String,
    pub platform_runtime_version: String,
}

/// A machine-produced admission lock and its independently captured identities.
#[derive(Clone, Debug)]
pub struct AdmissionInput {
    pub admission_id: String,
    pub instance_id: String,
    pub identity: AdmissionIdentity,
    pub execution_chain: CanonicalDocument,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub capability_grant: CanonicalDocument,
    pub conformance: CanonicalDocument,
    pub lock: CanonicalDocument,
    pub admitted_at: String,
    pub operator_identity: CanonicalDocument,
}

/// Canonical preimage of an admission context. JCS key ordering makes the field
/// order here irrelevant; the schema tag pins the constituent set.
#[derive(Serialize)]
struct AdmissionContextPreimage<'a> {
    admission_context_schema: &'a str,
    config_digest: &'a Sha256Digest,
    detector_identity_digest: &'a Sha256Digest,
    evaluator_artifact_digest: &'a Sha256Digest,
    evaluator_source_digest: &'a Sha256Digest,
    helper_artifact_digest: &'a Sha256Digest,
    profile_semantic_id: &'a Sha256Digest,
    protocol_version: &'a str,
}

/// Preimage binding a persisted judgment to its schema version and admission
/// context. The report bytes are bound through their own digest.
#[derive(Serialize)]
struct JudgmentPreimage<'a> {
    judgment_schema_version: &'a str,
    admission_context_digest: &'a str,
    validated_report_digest: &'a str,
}

#[derive(Serialize)]
struct ProviderReplayPreimage<'a> {
    schema: &'static str,
    idempotency_key: &'a str,
    attempt_id: &'a str,
    request_id: &'a str,
    provider_admission_id: &'a str,
    source_admission_id: &'a str,
    provider_sequence: &'a Option<String>,
    origin_carrier: &'a str,
    deadline_at: &'a str,
    checkpoint_contract_digest: &'a str,
    execution_identity_digest: &'a Sha256Digest,
    admission_context_digest: &'a Sha256Digest,
    provider_semantic_id: &'a Sha256Digest,
    provider_artifact_digest: &'a Sha256Digest,
    provider_protocol_identity: &'a str,
    provider_config_digest: &'a Sha256Digest,
    binding_digest: &'a str,
    instance_id: &'a str,
    profile_id: &'a str,
    profile_version: &'a str,
    profile_digest: &'a str,
    profile_semantic_id: &'a Sha256Digest,
    evaluator_artifact_digest: &'a Sha256Digest,
    context_digest: &'a str,
    interpretation_kind: &'a str,
    interpretation_digest: &'a str,
    native_outcome_kind: &'a str,
    native_outcome_digest: &'a str,
    raw_sha256: &'a str,
    started_at: &'a str,
    finished_at: &'a str,
}

#[derive(Serialize)]
struct ProviderIdempotencyPreimage<'a> {
    schema: &'static str,
    provider_admission_id: &'a str,
    attempt_id: &'a str,
}

#[derive(Serialize)]
struct LocalProviderSemanticPreimage<'a> {
    schema: &'static str,
    protocol_identity: &'a str,
    conformance: &'a Value,
}

#[derive(Serialize)]
struct LocalProviderAdmissionContract<'a> {
    schema: &'static str,
    source_admission_id: &'a str,
    instance_id: &'a str,
    provider_semantic_id: &'a str,
    provider_artifact_digest: &'a str,
    provider_protocol_identity: &'a str,
    provider_config_digest: &'a str,
    admission_context_digest: &'a str,
    profile_id: &'a str,
    profile_version: &'a str,
    profile_digest: &'a str,
    profile_semantic_id: &'a str,
    evaluator_artifact_digest: &'a str,
    capability_grant_digest: &'a str,
    conformance_digest: &'a str,
    lock_digest: &'a str,
}

#[derive(Serialize)]
struct ProviderIntakeDigestPreimage<'a> {
    schema: &'static str,
    intake_id: &'a str,
    replay_digest: &'a str,
    received_at: &'a str,
}

#[derive(Serialize)]
struct ProviderAcknowledgmentDocument<'a> {
    schema: &'static str,
    acknowledgment_id: &'a str,
    intake_id: &'a str,
    attempt_id: &'a str,
    run_id: &'a str,
    provider_admission_id: &'a str,
    intake_digest: &'a str,
    raw_sha256: &'a str,
    status_event_id: &'a str,
    canonical_result_digest: &'a str,
    committed_at: &'a str,
    establishes: &'static str,
    does_not_establish: [&'static str; 6],
}

struct ProviderIntakeDigests {
    context_digest: String,
    interpretation_digest: String,
    native_outcome_digest: String,
    raw_sha256: String,
    replay_digest: String,
    intake_digest: String,
}

impl AdmissionIdentity {
    /// Derive the algorithm-qualified `admission_context_digest` over exactly the
    /// seven identity-bearing constituents. This is the single implementation of
    /// the preimage law; callers never supply the digest.
    fn context_digest(&self) -> Result<String, StoreError> {
        let preimage = AdmissionContextPreimage {
            admission_context_schema: ADMISSION_CONTEXT_SCHEMA,
            config_digest: &self.config_digest,
            detector_identity_digest: &self.detector_identity_digest,
            evaluator_artifact_digest: &self.evaluator_artifact_digest,
            evaluator_source_digest: &self.evaluator_source_digest,
            helper_artifact_digest: &self.helper_artifact_digest,
            profile_semantic_id: &self.profile_semantic_id,
            protocol_version: &self.protocol_version,
        };
        let bytes = nq_protocol::canonical_json_bytes(&preimage)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        Ok(sha256_digest(&bytes))
    }
}

/// Derive the admission identity of an exact detector suite from its detector
/// descriptor digests. Ordering is not semantic, while duplicate executions
/// are rejected separately at the run boundary.
pub fn detector_suite_identity_digest<I, S>(detector_digests: I) -> Result<Sha256Digest, StoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut digests = detector_digests
        .into_iter()
        .map(|digest| digest.as_ref().to_owned())
        .collect::<Vec<_>>();
    for digest in &digests {
        validate_digest("detector_digest", digest)?;
    }
    digests.sort();
    digests.dedup();
    nq_protocol::semantic_digest(&digests)
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))
}

/// Bind a persisted judgment to its schema version and admission context.
fn judgment_digest(
    admission_context_digest: &str,
    validated_report_digest: &str,
) -> Result<String, StoreError> {
    let preimage = JudgmentPreimage {
        judgment_schema_version: JUDGMENT_SCHEMA_VERSION,
        admission_context_digest,
        validated_report_digest,
    };
    let bytes = nq_protocol::canonical_json_bytes(&preimage)
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    Ok(sha256_digest(&bytes))
}

fn provider_intake_digests(
    intake: &ProviderIntakeInput,
) -> Result<ProviderIntakeDigests, StoreError> {
    let context_digest = intake.context.digest().to_owned();
    let interpretation_digest = intake.interpretation.digest().to_owned();
    let native_outcome_digest = intake.native_outcome.digest().to_owned();
    let raw_sha256 = sha256_digest(&intake.raw_bytes);
    let replay = ProviderReplayPreimage {
        schema: "nq.provider_intake_replay.v1",
        idempotency_key: &intake.idempotency_key,
        attempt_id: &intake.attempt_id,
        request_id: &intake.request_id,
        provider_admission_id: &intake.provider_admission_id,
        source_admission_id: &intake.source_admission_id,
        provider_sequence: &intake.provider_sequence,
        origin_carrier: &intake.origin_carrier,
        deadline_at: &intake.deadline_at,
        checkpoint_contract_digest: &intake.checkpoint_contract_digest,
        execution_identity_digest: &intake.execution_identity_digest,
        admission_context_digest: &intake.admission_context_digest,
        provider_semantic_id: &intake.provider_semantic_id,
        provider_artifact_digest: &intake.provider_artifact_digest,
        provider_protocol_identity: &intake.provider_protocol_identity,
        provider_config_digest: &intake.provider_config_digest,
        binding_digest: &intake.binding_digest,
        instance_id: &intake.instance_id,
        profile_id: &intake.profile_id,
        profile_version: &intake.profile_version,
        profile_digest: &intake.profile_digest,
        profile_semantic_id: &intake.profile_semantic_id,
        evaluator_artifact_digest: &intake.evaluator_artifact_digest,
        context_digest: &context_digest,
        interpretation_kind: &intake.interpretation_kind,
        interpretation_digest: &interpretation_digest,
        native_outcome_kind: &intake.native_outcome_kind,
        native_outcome_digest: &native_outcome_digest,
        raw_sha256: &raw_sha256,
        started_at: &intake.started_at,
        finished_at: &intake.finished_at,
    };
    let replay_bytes = nq_protocol::canonical_json_bytes(&replay)
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    let replay_digest = sha256_digest(&replay_bytes);
    let full = ProviderIntakeDigestPreimage {
        schema: PROVIDER_INTAKE_SCHEMA,
        intake_id: &intake.intake_id,
        replay_digest: &replay_digest,
        received_at: &intake.received_at,
    };
    let full_bytes = nq_protocol::canonical_json_bytes(&full)
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    Ok(ProviderIntakeDigests {
        context_digest,
        interpretation_digest,
        native_outcome_digest,
        raw_sha256,
        replay_digest,
        intake_digest: sha256_digest(&full_bytes),
    })
}

/// Derive the exact record identity the store will assign to this provider
/// intake.
///
/// This is an identity calculation only. It does not admit the intake,
/// establish provider occurrence, validate correspondence with canonical
/// `ProviderIntakeRecordV1` bytes, or authorize persistence.
pub fn provider_intake_record_id(intake: &ProviderIntakeInput) -> Result<Sha256Digest, StoreError> {
    Sha256Digest::parse(provider_intake_digests(intake)?.intake_digest)
        .map_err(|_| StoreError::Invariant("derived provider intake digest is malformed".into()))
}

/// Derive the local provider's semantic identity from NQ-owned admission facts.
///
/// The executable artifact remains a separate identity. This digest binds the
/// closed helper protocol and the exact canonical conformance receipt under
/// which NQ admitted that implementation; a provider cannot mint the value by
/// placing an identity-shaped field in its response.
pub fn local_provider_semantic_id(
    protocol_identity: &str,
    conformance: &CanonicalDocument,
) -> Result<Sha256Digest, StoreError> {
    if protocol_identity.is_empty() || protocol_identity.len() > 128 {
        return Err(StoreError::Invariant(
            "provider protocol identity must be nonempty and bounded".into(),
        ));
    }
    let conformance_value: Value = serde_json::from_slice(conformance.as_bytes())
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    nq_protocol::semantic_digest(&LocalProviderSemanticPreimage {
        schema: LOCAL_PROVIDER_SEMANTIC_SCHEMA,
        protocol_identity,
        conformance: &conformance_value,
    })
    .map_err(|error| StoreError::CanonicalJson(error.to_string()))
}

/// Derive the only accepted replay key for one admitted provider and attempt.
pub fn provider_idempotency_key(
    provider_admission_id: &str,
    attempt_id: &str,
) -> Result<String, StoreError> {
    validate_digest("provider_admission_id", provider_admission_id)?;
    if attempt_id.is_empty() || attempt_id.len() > 256 || attempt_id.chars().any(char::is_control) {
        return Err(StoreError::Invariant(
            "provider attempt identity must be nonempty, bounded, and printable".into(),
        ));
    }
    nq_protocol::semantic_digest(&ProviderIdempotencyPreimage {
        schema: PROVIDER_INTAKE_SCHEMA,
        provider_admission_id,
        attempt_id,
    })
    .map(Sha256Digest::into_string)
    .map_err(|error| StoreError::CanonicalJson(error.to_string()))
}

fn local_provider_admission_contract(
    admission: &AdmissionInput,
    admission_context_digest: &str,
) -> Result<(Sha256Digest, CanonicalDocument), StoreError> {
    let provider_semantic_id =
        local_provider_semantic_id(&admission.identity.protocol_version, &admission.conformance)?;
    let contract = CanonicalDocument::from_serializable(&LocalProviderAdmissionContract {
        schema: LOCAL_PROVIDER_ADMISSION_SCHEMA,
        source_admission_id: &admission.admission_id,
        instance_id: &admission.instance_id,
        provider_semantic_id: provider_semantic_id.as_str(),
        provider_artifact_digest: admission.identity.helper_artifact_digest.as_str(),
        provider_protocol_identity: &admission.identity.protocol_version,
        provider_config_digest: admission.identity.config_digest.as_str(),
        admission_context_digest,
        profile_id: &admission.profile_id,
        profile_version: &admission.profile_version,
        profile_digest: &admission.profile_digest,
        profile_semantic_id: admission.identity.profile_semantic_id.as_str(),
        evaluator_artifact_digest: admission.identity.evaluator_artifact_digest.as_str(),
        capability_grant_digest: admission.capability_grant.digest(),
        conformance_digest: admission.conformance.digest(),
        lock_digest: admission.lock.digest(),
    })?;
    Ok((provider_semantic_id, contract))
}

fn insert_local_provider_admission(
    transaction: &Transaction<'_>,
    admission: &AdmissionInput,
    admission_context_digest: &str,
    derived_at: &str,
    derivation_kind: &str,
) -> Result<LocalProviderAdmissionRow, StoreError> {
    if !matches!(derivation_kind, "admission_append" | "schema_v3_migration")
        || chrono::DateTime::parse_from_rfc3339(derived_at).is_err()
    {
        return Err(StoreError::Invariant(
            "local-provider admission derivation provenance is invalid".into(),
        ));
    }
    let (provider_semantic_id, contract) =
        local_provider_admission_contract(admission, admission_context_digest)?;
    let provider_admission_id = contract.digest().to_owned();
    transaction.execute(
        "INSERT INTO local_provider_admissions (
            provider_admission_id, schema_id, source_admission_id,
            provider_semantic_id, provider_artifact_digest,
            provider_protocol_identity, provider_config_digest,
            contract_json, contract_digest, source_admitted_at, derived_at,
            derivation_kind
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            provider_admission_id,
            LOCAL_PROVIDER_ADMISSION_SCHEMA,
            admission.admission_id,
            provider_semantic_id.as_str(),
            admission.identity.helper_artifact_digest.as_str(),
            admission.identity.protocol_version,
            admission.identity.config_digest.as_str(),
            contract.as_bytes(),
            contract.digest(),
            admission.admitted_at,
            derived_at,
            derivation_kind,
        ],
    )?;
    Ok(LocalProviderAdmissionRow {
        provider_admission_id,
        source_admission_id: admission.admission_id.clone(),
        provider_semantic_id: provider_semantic_id.into_string(),
        provider_artifact_digest: admission
            .identity
            .helper_artifact_digest
            .as_str()
            .to_owned(),
        provider_protocol_identity: admission.identity.protocol_version.clone(),
        provider_config_digest: admission.identity.config_digest.as_str().to_owned(),
        contract_json: contract.as_bytes().to_vec(),
        contract_digest: contract.digest().to_owned(),
        source_admitted_at: admission.admitted_at.clone(),
        derived_at: derived_at.to_owned(),
        derivation_kind: derivation_kind.to_owned(),
    })
}

fn migrate_local_provider_admissions(
    transaction: &Transaction<'_>,
    derived_at: &str,
) -> Result<(), StoreError> {
    let admissions = {
        let mut statement = transaction.prepare(
            "SELECT admission_id, instance_id, config_digest,
                    helper_artifact_digest, profile_semantic_id,
                    detector_identity_digest, evaluator_source_digest,
                    evaluator_artifact_digest, execution_chain_json,
                    profile_id, profile_version, profile_digest,
                    protocol_version, target_triple, artifact_identity_method,
                    platform_runtime_version, capability_grant_json,
                    conformance_json, lock_json, admitted_at,
                    operator_identity_json
             FROM admission_records ORDER BY admission_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                    row.get::<_, Vec<u8>>(18)?,
                    row.get::<_, String>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for row in admissions {
        let parse_digest = |name: &str, value: String| {
            Sha256Digest::parse(value).map_err(|error| {
                StoreError::Integrity(format!("schema-v3 admission has invalid {name}: {error}"))
            })
        };
        let admission = AdmissionInput {
            admission_id: row.0,
            instance_id: row.1,
            identity: AdmissionIdentity {
                config_digest: parse_digest("configuration digest", row.2)?,
                helper_artifact_digest: parse_digest("helper artifact digest", row.3)?,
                profile_semantic_id: parse_digest("profile semantic identity", row.4)?,
                detector_identity_digest: parse_digest("detector identity digest", row.5)?,
                evaluator_source_digest: parse_digest("evaluator source digest", row.6)?,
                evaluator_artifact_digest: parse_digest("evaluator artifact digest", row.7)?,
                protocol_version: row.12,
                target_triple: row.13,
                artifact_identity_method: row.14,
                platform_runtime_version: row.15,
            },
            execution_chain: CanonicalDocument::from_canonical_bytes(row.8)?,
            profile_id: row.9,
            profile_version: row.10,
            profile_digest: row.11,
            capability_grant: CanonicalDocument::from_canonical_bytes(row.16)?,
            conformance: CanonicalDocument::from_canonical_bytes(row.17)?,
            lock: CanonicalDocument::from_canonical_bytes(row.18)?,
            admitted_at: row.19,
            operator_identity: CanonicalDocument::from_canonical_bytes(row.20)?,
        };
        let context_digest = admission.identity.context_digest()?;
        insert_local_provider_admission(
            transaction,
            &admission,
            &context_digest,
            derived_at,
            "schema_v3_migration",
        )?;
    }
    Ok(())
}

/// An immutable transition in an instance's admission binding.
#[derive(Clone, Debug)]
pub struct BindingEventInput {
    pub binding_event_id: String,
    pub instance_id: String,
    pub event_kind: String,
    pub admission_id: Option<String>,
    pub binding_digest: String,
    pub occurred_at: String,
    pub reason_code: Option<String>,
    pub detail: CanonicalDocument,
}

/// One append-only phase of active-lock materialization. An `intent` is
/// committed atomically with its authoritative binding event; `completed` is
/// appended only after the filesystem state and containing directory are
/// durable.
#[derive(Clone, Debug)]
pub struct BindingMaterializationInput {
    pub materialization_event_id: String,
    pub operation_id: String,
    pub instance_id: String,
    pub binding_event_id: String,
    pub phase: String,
    pub occurred_at: String,
    pub detail: CanonicalDocument,
}

/// One completed acquisition attempt. Transport failures have no submission.
#[derive(Clone, Debug)]
pub struct RunInput {
    pub run_id: String,
    pub request_id: String,
    pub instance_id: String,
    pub admission_id: Option<String>,
    pub binding_digest: String,
    pub checkpoint_contract_digest: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub carrier: String,
    pub started_at: String,
    pub deadline_at: String,
    pub finished_at: String,
    pub acquisition_outcome: String,
    pub execution_identity: CanonicalDocument,
    pub resource_outcome: CanonicalDocument,
}

/// One NQ-constructed provider intake before report admission or evaluation.
///
/// Identity fields are checked against the referenced NQ-owned admission and
/// active binding. They are never trusted merely because a provider supplied
/// similarly named fields in its raw payload. `raw_bytes` is the exact outer
/// capture, including empty or partial bytes for attempts that never become a
/// protocol submission.
#[derive(Clone, Debug)]
pub struct ProviderIntakeInput {
    pub intake_id: String,
    pub attempt_id: String,
    pub idempotency_key: String,
    pub request_id: String,
    pub provider_admission_id: String,
    pub source_admission_id: String,
    pub provider_sequence: Option<String>,
    pub origin_carrier: String,
    pub deadline_at: String,
    pub checkpoint_contract_digest: String,
    pub execution_identity_digest: Sha256Digest,
    pub admission_context_digest: Sha256Digest,
    pub provider_semantic_id: Sha256Digest,
    pub provider_artifact_digest: Sha256Digest,
    pub provider_protocol_identity: String,
    pub provider_config_digest: Sha256Digest,
    pub binding_digest: String,
    pub instance_id: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub profile_semantic_id: Sha256Digest,
    pub evaluator_artifact_digest: Sha256Digest,
    pub context: CanonicalDocument,
    pub interpretation_kind: String,
    pub interpretation: CanonicalDocument,
    pub native_outcome_kind: String,
    pub native_outcome: CanonicalDocument,
    pub raw_bytes: Vec<u8>,
    pub started_at: String,
    pub finished_at: String,
    pub received_at: String,
}

/// A typed refusal retained at its exact boundary and responsible instance.
#[derive(Clone, Debug)]
pub struct RefusalInput {
    pub refusal_id: String,
    pub source_kind: String,
    pub responsible_instance_id: String,
    pub boundary: String,
    pub code: String,
    /// Exact compiled profile semantic identity for profile-origin refusals.
    pub profile_semantic_id: Option<String>,
    pub detail: CanonicalDocument,
    pub created_at: String,
}

/// A profile-validated observation; its payload is never flattened into EAV rows.
#[derive(Clone, Debug)]
pub struct ObservationInput {
    pub ordinal: u32,
    pub kind: String,
    pub subject: CanonicalDocument,
    pub observed_at: String,
    pub payload: CanonicalDocument,
    pub coverage: Vec<CoverageInput>,
}

/// One profile-controlled coverage declaration.
#[derive(Clone, Debug)]
pub struct CoverageInput {
    pub ordinal: u32,
    pub coverage_kind: String,
    pub coverage_state: String,
    pub detail: CanonicalDocument,
}

/// One ordered structured report error.
#[derive(Clone, Debug)]
pub struct ReportErrorInput {
    pub ordinal: u32,
    pub code: String,
    pub detail: CanonicalDocument,
}

/// An admitted canonical evidence report, including valid `failed` reports.
#[derive(Clone, Debug)]
pub struct ReportInput {
    pub report_id: String,
    pub instance_id: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub observed_at: String,
    pub received_at: String,
    pub report_status: String,
    /// The source protocol JSON as received; retained as watcher material.
    pub canonical_report: CanonicalDocument,
    /// The canonical admitted judgment (`ValidatedReport`). Persisted losslessly;
    /// 3B verification checks this snapshot rather than re-deriving one. The
    /// store binds it to the admission context reached through the run.
    pub validated_report: CanonicalDocument,
    pub next_checkpoint: Option<CanonicalDocument>,
    pub admitted_at: String,
    pub observations: Vec<ObservationInput>,
    pub coverage: Vec<CoverageInput>,
    pub errors: Vec<ReportErrorInput>,
}

/// The result of protocol validation and profile admission for retained raw bytes.
// The admitted variant carries the full report and is the dominant case; boxing
// it to shrink the delta against the rare rejected variant would add a heap
// allocation on the common admission path for no correctness gain.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum SubmissionDisposition {
    /// The bytes remain a rejected custody artifact and never reach detectors.
    Rejected {
        /// Mandatory typed testimony justifying rejected custody. The coarse
        /// `raw_submissions.rejection_code` projection is derived from this
        /// object's code; callers cannot supply an independent value.
        refusal: RefusalInput,
    },
    /// The bytes produced a strictly validated report.
    Admitted(ReportInput),
}

/// Exact helper output paired with its admission disposition.
#[derive(Clone, Debug)]
pub struct SubmissionInput {
    pub submission_id: String,
    pub raw_bytes: Vec<u8>,
    pub received_at: String,
    pub protocol_outcome: String,
    pub disposition: SubmissionDisposition,
}

/// An atomic run/submission/report commit.
#[derive(Clone, Debug)]
pub struct CollectionInput {
    /// Mandatory provider-intake custody for every schema-v4 write.
    pub intake: ProviderIntakeInput,
    pub run: RunInput,
    pub submission: Option<SubmissionInput>,
}

/// Stable identities assigned during a successful collection commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionReceipt {
    pub raw_sha256: Option<String>,
    pub semantic_digest: Option<String>,
    pub report_sequence: Option<i64>,
    /// Stable identity of the typed refusal linked to rejected custody.
    pub refusal_id: Option<String>,
}

/// Exact acknowledgment returned only after the whole intake transaction is
/// durable. Its meaning is limited to custody and canonical processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableIntakeAcknowledgment {
    pub acknowledgment_id: String,
    pub intake_id: String,
    pub attempt_id: String,
    pub run_id: String,
    pub provider_admission_id: String,
    pub intake_digest: String,
    pub raw_sha256: String,
    pub status_event_id: String,
    pub canonical_result_digest: String,
    pub committed_at: String,
    pub detail_json: Vec<u8>,
}

/// Read-only idempotency decision made before semantic processing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderIntakePreflight {
    /// No durable attempt owns this idempotency identity.
    New,
    /// The exact attempt was already durably processed. The canonical result is
    /// returned from history and must not be re-evaluated under current state.
    Existing {
        acknowledgment: DurableIntakeAcknowledgment,
        canonical_result: CanonicalDocument,
    },
}

/// Atomic provider-intake completion, including the race-closing replay case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderIntakeCommit<T> {
    /// This call committed the intake and may return its freshly built value.
    Committed {
        receipt: CollectionReceipt,
        acknowledgment: DurableIntakeAcknowledgment,
        value: T,
    },
    /// A concurrent or retried call had already committed the exact attempt.
    /// No completion builder ran and the stored canonical result is returned.
    Replayed {
        receipt: CollectionReceipt,
        acknowledgment: DurableIntakeAcknowledgment,
        canonical_result: CanonicalDocument,
    },
}

/// Atomic run-bearing non-success completion plus its exact historical
/// diagnostic-artifact identity, when the original attempt committed one.
///
/// On replay, `diagnostic_artifact_id` is reopened from the original run
/// origin. The store never creates a missing artifact for a completed attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonSuccessCollectionArtifactCommit {
    /// Existing provider-intake commit/replay result.
    pub intake: ProviderIntakeCommit<()>,
    /// Exact artifact bound to the run, or `None` when the original attempt did
    /// not commit an artifact.
    pub diagnostic_artifact_id: Option<Sha256Digest>,
}

#[cfg(test)]
thread_local! {
    static FAIL_NON_SUCCESS_AFTER_ARTIFACT_INSERT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// One NQ-derived admission of the local helper as a candidate-evidence
/// provider. `source_admission_id` names the existing AdmissionLock record;
/// this identity never represents admission of an individual report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalProviderAdmissionRow {
    pub provider_admission_id: String,
    pub source_admission_id: String,
    pub provider_semantic_id: String,
    pub provider_artifact_digest: String,
    pub provider_protocol_identity: String,
    pub provider_config_digest: String,
    pub contract_json: Vec<u8>,
    pub contract_digest: String,
    pub source_admitted_at: String,
    pub derived_at: String,
    pub derivation_kind: String,
}

/// One exhaustively reopenable provider-intake identity and its local origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderIntakeRow {
    pub intake_id: String,
    pub attempt_id: String,
    pub idempotency_key: String,
    pub request_id: String,
    pub provider_admission_id: String,
    pub source_admission_id: String,
    pub provider_sequence: Option<String>,
    pub origin_carrier: String,
    pub deadline_at: String,
    pub checkpoint_contract_digest: String,
    pub execution_identity_digest: String,
    pub admission_context_digest: String,
    pub provider_semantic_id: String,
    pub provider_artifact_digest: String,
    pub provider_protocol_identity: String,
    pub provider_config_digest: String,
    pub binding_digest: String,
    pub instance_id: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub profile_semantic_id: String,
    pub evaluator_artifact_digest: String,
    pub context_json: Vec<u8>,
    pub context_digest: String,
    pub interpretation_kind: String,
    pub interpretation_json: Vec<u8>,
    pub interpretation_digest: String,
    pub native_outcome_kind: String,
    pub native_outcome_json: Vec<u8>,
    pub native_outcome_digest: String,
    pub raw_sha256: String,
    pub started_at: String,
    pub finished_at: String,
    pub received_at: String,
    pub replay_digest: String,
    pub intake_digest: String,
    pub run_id: String,
    /// Exact capability grant from the source admission. Typed historical
    /// reopening uses this independently stored NQ decision to prove that a
    /// resealed request did not acquire provider capabilities retroactively.
    pub source_capability_grant_json: Vec<u8>,
    /// Exact source AdmissionLock bytes from which NQ derived the local
    /// provider admission. Historical reopening authenticates the provider
    /// context against this decision without reactivating it.
    pub source_lock_json: Vec<u8>,
    pub acknowledgment: DurableIntakeAcknowledgment,
}

/// Explicit limitation retained for one schema-v3 run during migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyProviderIntakeGapRow {
    pub run_id: String,
    pub source_schema_version: i64,
    pub source_schema_artifact_digest: String,
    pub limitation_code: String,
    pub detail_json: Vec<u8>,
    pub migrated_at: String,
}

/// One rejected custody artifact with its exact, mandatory typed refusal.
///
/// Raw bytes remain available through [`Store::raw_submission_bytes`]; this
/// bounded row carries their digest and the semantic linkage needed to enumerate
/// and historically reopen rejected custody without reconstructing testimony.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedCustodyRow {
    pub submission_id: String,
    pub run_id: String,
    pub request_id: String,
    pub instance_id: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    /// Admission governing the originating run. A profile-origin refusal must
    /// have one; historical unbound runs retain `None` and cannot be upgraded.
    pub admission_id: Option<String>,
    /// Exact compiled profile semantic identity from that admission.
    pub profile_semantic_id: Option<String>,
    pub raw_sha256: String,
    pub received_at: String,
    pub protocol_outcome: String,
    pub refusal_id: String,
    pub source_kind: String,
    pub responsible_instance_id: String,
    pub boundary: String,
    pub code: String,
    /// Exact canonical refusal document persisted in `refusals.detail_json`.
    pub detail_json: Vec<u8>,
    pub created_at: String,
}

/// Authoritative persisted acquisition testimony and profile binding for one
/// watcher run. The resource document remains exact canonical bytes so core can
/// reopen it under the versioned product schema without store-level guessing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatcherRunOutcomeRow {
    pub run_id: String,
    pub request_id: String,
    pub instance_id: String,
    pub admission_id: Option<String>,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    /// Instance identity carried by the exact joined admission record.
    pub admission_instance_id: Option<String>,
    /// Profile identity carried by the exact joined admission record.
    pub admission_profile_id: Option<String>,
    pub admission_profile_version: Option<String>,
    pub admission_profile_digest: Option<String>,
    pub profile_semantic_id: Option<String>,
    /// Exact detector-suite identity recorded by the joined admission.
    pub admission_detector_identity_digest: Option<String>,
    /// Exact evaluator artifact identity recorded by the joined admission.
    pub admission_evaluator_artifact_digest: Option<String>,
    pub acquisition_outcome: String,
    pub resource_outcome_json: Vec<u8>,
}

/// Stored profile descriptor identity and exact canonical descriptor bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileDescriptorRow {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub descriptor_json: Vec<u8>,
    pub recorded_at: String,
}

/// Stored admission identity sufficient to re-check an active binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRow {
    pub admission_id: String,
    pub instance_id: String,
    pub config_digest: String,
    pub helper_artifact_digest: String,
    pub profile_semantic_id: String,
    pub detector_identity_digest: String,
    pub evaluator_source_digest: String,
    pub evaluator_artifact_digest: String,
    pub admission_context_digest: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub protocol_version: String,
    pub target_triple: String,
    pub artifact_identity_method: String,
    pub platform_runtime_version: String,
    pub lock_json: Vec<u8>,
    pub admitted_at: String,
}

/// An authenticated historical admission snapshot for an admitted report.
///
/// Returned only when the persisted admission context recomputes to its stored
/// digest, the report is bound to exactly that context through its own run and
/// instance, and the stored judgment digest recomputes over the persisted
/// judgment bytes. It carries the *stored* evaluator identity so a caller can
/// compare it against a freshly observed one — the store authenticates the past;
/// it does not observe the present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedSnapshot {
    pub report_id: String,
    pub admission_id: String,
    pub instance_id: String,
    pub admission_context_digest: String,
    pub judgment_schema_version: String,
    pub judgment_digest: String,
    pub validated_report_json: Vec<u8>,
    /// Evaluator identity as it was recorded at admission time.
    pub evaluator_artifact_digest: String,
    pub artifact_identity_method: String,
    pub platform_runtime_version: String,
}

/// Why an admitted report's stored snapshot failed authentication. Each variant
/// preserves the reason instead of flattening every mismatch into "digest
/// changed". None of these consult present runtime state.
#[derive(Debug, Error)]
pub enum SnapshotVerificationError {
    /// No admitted report with this id exists.
    #[error("no admitted report {0}")]
    ReportNotFound(String),
    /// The report's run/instance/context chain is broken or substituted.
    #[error("admitted report binding is broken: {0}")]
    BindingBroken(String),
    /// The persisted admission context does not recompute to its stored digest.
    #[error("admission context is corrupt: {0}")]
    AdmissionContextCorrupt(String),
    /// The persisted judgment does not recompute to its stored digest.
    #[error("stored judgment is corrupt: {0}")]
    JudgmentCorrupt(String),
    /// The judgment was written under a schema version this binary does not
    /// understand, so its digest preimage cannot be honestly recomputed. This is
    /// not corruption — it is an incompatibility to be surfaced, not reinterpreted.
    #[error("judgment schema {stored} is not supported by this binary ({supported})")]
    UnsupportedJudgmentSchema { stored: String, supported: String },
}

/// The persisted admission constituents reached through one report's run, used
/// to recompute the admission context digest with the single store-owned
/// preimage law.
struct StoredAdmissionConstituents {
    submission_outcome: String,
    submission_received_at: String,
    run_instance_id: String,
    run_profile_id: String,
    run_profile_version: String,
    run_profile_digest: String,
    admission_instance_id: String,
    admission_profile_id: String,
    admission_profile_version: String,
    admission_profile_digest: String,
    admission_id: String,
    admission_context_digest: String,
    config_digest: String,
    helper_artifact_digest: String,
    profile_semantic_id: String,
    detector_identity_digest: String,
    evaluator_source_digest: String,
    evaluator_artifact_digest: String,
    protocol_version: String,
    artifact_identity_method: String,
    platform_runtime_version: String,
}

struct StoredAdmittedReport {
    submission_id: String,
    instance_id: String,
    profile_id: String,
    profile_version: String,
    profile_digest: String,
    observed_at: String,
    received_at: String,
    report_status: String,
    semantic_digest: String,
    canonical_json: Vec<u8>,
    next_checkpoint_json: Option<Vec<u8>>,
    validated_report_json: Vec<u8>,
    judgment_schema_version: String,
    judgment_digest: String,
    admission_context_digest: String,
}

struct StoredProviderIntake {
    intake_id: String,
    attempt_id: String,
    idempotency_key: String,
    request_id: String,
    provider_admission_id: String,
    source_admission_id: String,
    provider_sequence: Option<String>,
    origin_carrier: String,
    deadline_at: String,
    checkpoint_contract_digest: String,
    execution_identity_digest: String,
    admission_context_digest: String,
    provider_semantic_id: String,
    provider_artifact_digest: String,
    provider_protocol_identity: String,
    provider_config_digest: String,
    binding_digest: String,
    instance_id: String,
    profile_id: String,
    profile_version: String,
    profile_digest: String,
    profile_semantic_id: String,
    evaluator_artifact_digest: String,
    context_json: Vec<u8>,
    context_digest: String,
    interpretation_kind: String,
    interpretation_json: Vec<u8>,
    interpretation_digest: String,
    native_outcome_kind: String,
    native_outcome_json: Vec<u8>,
    native_outcome_digest: String,
    raw_bytes: Vec<u8>,
    raw_sha256: String,
    started_at: String,
    finished_at: String,
    received_at: String,
    replay_digest: String,
    intake_digest: String,
    run_id: String,
    source_capability_grant_json: Vec<u8>,
    source_lock_json: Vec<u8>,
}

fn canonical_materialized<T: Serialize>(value: &T) -> Result<Vec<u8>, SnapshotVerificationError> {
    nq_protocol::canonical_json_bytes(value)
        .map_err(|error| SnapshotVerificationError::JudgmentCorrupt(error.to_string()))
}

#[allow(clippy::too_many_lines)]
fn verify_admitted_report_materialization(
    connection: &Connection,
    report_id: &str,
    stored: &StoredAdmittedReport,
) -> Result<(), SnapshotVerificationError> {
    let document = CanonicalDocument::from_canonical_bytes(stored.canonical_json.clone())
        .map_err(|error| SnapshotVerificationError::JudgmentCorrupt(error.to_string()))?;
    if document.digest() != stored.semantic_digest {
        return Err(SnapshotVerificationError::JudgmentCorrupt(format!(
            "report {report_id} canonical digest {} does not match stored {}",
            document.digest(),
            stored.semantic_digest
        )));
    }
    let report: nq_protocol::EvidenceReport =
        serde_json::from_slice(document.as_bytes()).map_err(|error| {
            SnapshotVerificationError::JudgmentCorrupt(format!(
                "report {report_id} does not decode as an evidence report: {error}"
            ))
        })?;
    nq_protocol::validate_report(&report).map_err(|error| {
        SnapshotVerificationError::JudgmentCorrupt(format!(
            "report {report_id} violates the protocol contract: {error}"
        ))
    })?;
    let fail = |what: &str| {
        SnapshotVerificationError::BindingBroken(format!(
            "report {report_id} persisted {what} is not an exact materialization of canonical_json"
        ))
    };
    let sql = |error: rusqlite::Error| SnapshotVerificationError::BindingBroken(error.to_string());
    let observations = connection
        .prepare(
            "SELECT ordinal, kind, subject_json, observed_at, payload_json
             FROM observations WHERE report_id = ?1 ORDER BY ordinal",
        )
        .map_err(sql)?
        .query_map([report_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    if observations.len() != report.observations.len() {
        return Err(fail("observations"));
    }
    for (persisted, expected) in observations.iter().zip(&report.observations) {
        if persisted.0 != i64::from(expected.ordinal)
            || persisted.1 != expected.kind.to_string()
            || persisted.2 != canonical_materialized(&expected.subject.to_string())?
            || persisted.3
                != expected
                    .observed_at
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
            || persisted.4 != canonical_materialized(&expected.payload)?
        {
            return Err(fail("observations"));
        }
    }

    let coverage = connection
        .prepare(
            "SELECT ordinal, coverage_kind, coverage_state, detail_json
             FROM report_coverage WHERE report_id = ?1 ORDER BY ordinal",
        )
        .map_err(sql)?
        .query_map([report_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    if coverage.len() != report.coverage.len() {
        return Err(fail("report coverage"));
    }
    for (ordinal, (persisted, expected)) in coverage.iter().zip(&report.coverage).enumerate() {
        let state = serde_json::to_value(expected.state)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned));
        if persisted.0 != i64::try_from(ordinal).unwrap_or(i64::MAX)
            || persisted.1 != expected.kind.to_string()
            || Some(persisted.2.as_str()) != state.as_deref()
            || persisted.3
                != canonical_materialized(&serde_json::json!({
                    "subject": expected.subject,
                    "detail": expected.detail,
                }))?
        {
            return Err(fail("report coverage"));
        }
    }

    for observation in &report.observations {
        let expected: Vec<_> = report
            .coverage
            .iter()
            .filter(|entry| {
                entry
                    .subject
                    .as_ref()
                    .is_none_or(|subject| subject.as_str() == observation.subject.as_str())
            })
            .collect();
        let persisted = connection
            .prepare(
                "SELECT ordinal, coverage_kind, coverage_state, detail_json
                 FROM observation_coverage
                 WHERE report_id = ?1 AND observation_ordinal = ?2 ORDER BY ordinal",
            )
            .map_err(sql)?
            .query_map(params![report_id, observation.ordinal], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        if persisted.len() != expected.len() {
            return Err(fail("observation coverage"));
        }
        for (ordinal, (persisted, expected)) in persisted.iter().zip(expected).enumerate() {
            let state = serde_json::to_value(expected.state)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned));
            if persisted.0 != i64::try_from(ordinal).unwrap_or(i64::MAX)
                || persisted.1 != expected.kind.to_string()
                || Some(persisted.2.as_str()) != state.as_deref()
                || persisted.3 != canonical_materialized(&expected.detail)?
            {
                return Err(fail("observation coverage"));
            }
        }
    }

    let errors = connection
        .prepare(
            "SELECT ordinal, code, detail_json FROM report_errors
             WHERE report_id = ?1 ORDER BY ordinal",
        )
        .map_err(sql)?
        .query_map([report_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    if errors.len() != report.errors.len() {
        return Err(fail("report errors"));
    }
    for (ordinal, (persisted, expected)) in errors.iter().zip(&report.errors).enumerate() {
        if persisted.0 != i64::try_from(ordinal).unwrap_or(i64::MAX)
            || persisted.1 != expected.code.to_string()
            || persisted.2 != canonical_materialized(expected)?
        {
            return Err(fail("report errors"));
        }
    }
    let expected_checkpoint = report
        .next_checkpoint
        .as_ref()
        .map(|checkpoint| canonical_materialized(&checkpoint.value))
        .transpose()?;
    if stored.next_checkpoint_json != expected_checkpoint {
        return Err(fail("next checkpoint"));
    }
    Ok(())
}

impl StoredAdmissionConstituents {
    /// Recompute `admission_context_digest` from the persisted constituents via
    /// the same [`AdmissionIdentity::context_digest`] used to write it. Metadata
    /// (target triple, method, platform) is deliberately absent from the
    /// preimage, so it is left empty here.
    fn recompute_context_digest(&self) -> Result<String, String> {
        let parse = |field: &str, value: &str| {
            Sha256Digest::parse(value).map_err(|_| format!("{field} is not a valid digest"))
        };
        let identity = AdmissionIdentity {
            profile_semantic_id: parse("profile_semantic_id", &self.profile_semantic_id)?,
            detector_identity_digest: parse(
                "detector_identity_digest",
                &self.detector_identity_digest,
            )?,
            evaluator_source_digest: parse(
                "evaluator_source_digest",
                &self.evaluator_source_digest,
            )?,
            evaluator_artifact_digest: parse(
                "evaluator_artifact_digest",
                &self.evaluator_artifact_digest,
            )?,
            helper_artifact_digest: parse("helper_artifact_digest", &self.helper_artifact_digest)?,
            config_digest: parse("config_digest", &self.config_digest)?,
            protocol_version: self.protocol_version.clone(),
            target_triple: String::new(),
            artifact_identity_method: String::new(),
            platform_runtime_version: String::new(),
        };
        identity.context_digest().map_err(|error| error.to_string())
    }
}

/// Latest immutable binding transition for an instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingEventRow {
    pub binding_event_id: String,
    pub instance_id: String,
    pub event_kind: String,
    pub admission_id: Option<String>,
    pub binding_digest: String,
    pub occurred_at: String,
    pub reason_code: Option<String>,
    pub detail_json: Vec<u8>,
}

/// An uncompleted active-lock materialization intent. Its canonical detail is
/// interpreted by the core binding reconciler, not by the generic store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBindingMaterializationRow {
    pub materialization_event_id: String,
    pub operation_id: String,
    pub instance_id: String,
    pub binding_event_id: String,
    pub occurred_at: String,
    pub detail_json: Vec<u8>,
}

/// The version-gated SQLite store.
pub struct Store {
    connection: Connection,
    path: Option<PathBuf>,
}

impl Store {
    /// Read an nq-ng database's declared schema version without accepting or
    /// mutating its contents.
    pub fn database_schema_version(path: impl AsRef<Path>) -> Result<i64, StoreError> {
        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        pragma_i64(&connection, "user_version")
    }

    /// Explicitly create a current schema-v4 store. Existing schemas are never overwritten.
    pub fn initialize(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let existed = path.exists();
        let existing_len = if existed {
            std::fs::metadata(path)?.len()
        } else {
            0
        };
        let mut connection = Connection::open(path)?;
        let object_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if object_count != 0 {
            let found_version = pragma_i64(&connection, "user_version")?;
            return Err(StoreError::AlreadyInitialized { found_version });
        }
        if existed && existing_len != 0 {
            return Err(StoreError::AlreadyInitialized { found_version: 0 });
        }
        configure_connection(&connection, true)?;
        initialize_connection(&mut connection)?;
        let store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        store.validate()?;
        Ok(store)
    }

    /// Open only an already-initialized, exactly compatible schema-v5 store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // Version and application refusal happen before any persistent PRAGMA change.
        configure_connection(&connection, false)?;
        let store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        store.validate()?;
        configure_connection(&store.connection, true)?;
        Ok(store)
    }

    /// Open an exactly compatible store for verification without permitting
    /// SQLite to rewrite database bytes or create journal sidecars.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "query_only", "ON")?;
        let store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        store.validate()?;
        Ok(store)
    }

    /// Open a sealed archive database through SQLite's immutable URI mode.
    /// SQLite neither consults nor creates journal/WAL sidecars for this handle.
    pub fn open_immutable(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";

        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let canonical_path = std::fs::canonicalize(path)?;
        let mut uri = String::from("file:");
        for byte in canonical_path.as_os_str().as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'~') {
                uri.push(char::from(*byte));
            } else {
                uri.push('%');
                uri.push(char::from(HEX[usize::from(byte >> 4)]));
                uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
        uri.push_str("?immutable=1&mode=ro");
        let connection = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let store = Self {
            connection,
            path: Some(canonical_path),
        };
        store.validate()?;
        Ok(store)
    }

    /// Open the exact qualified v0.1.0 schema-v3 store read-only so the
    /// application can run its typed semantic history verifiers before the
    /// separately authorized v3-to-v4 migration. This is not a compatibility
    /// opener: every v3 schema, identity, custody, and store invariant is
    /// validated, and the returned handle cannot write.
    pub fn open_v3_upgrade_source_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "query_only", "ON")?;
        let store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        store.validate_v3_upgrade_source()?;
        Ok(store)
    }

    fn validate_v3_upgrade_source(&self) -> Result<(), StoreError> {
        validate_v3_upgrade_source_connection(&self.connection)
    }

    /// Open the exact qualified schema-v4 store read-only for the separately
    /// authorized v4-to-v5 migration.
    pub fn open_v4_upgrade_source_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "query_only", "ON")?;
        let store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        validate_v4_upgrade_source_connection(&store.connection)?;
        Ok(store)
    }

    /// Open the exact qualified schema-v5 store read-only for the separately
    /// authorized v5-to-v6 runtime-ledger migration.
    pub fn open_v5_upgrade_source_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "query_only", "ON")?;
        let store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        validate_v5_upgrade_source_connection(&store.connection)?;
        Ok(store)
    }

    /// Open the exact qualified schema-v6 store read-only for the separately
    /// authorized v6-to-v7 dependency-binding migration.
    pub fn open_v6_upgrade_source_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.is_file() || std::fs::metadata(path)?.len() == 0 {
            return Err(StoreError::NotInitialized(path.to_path_buf()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "query_only", "ON")?;
        let store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        validate_v6_upgrade_source_connection(&store.connection)?;
        Ok(store)
    }

    /// Checkpoint a writable backup copy and leave it in rollback-journal mode
    /// before archive inventory and sealing.
    pub fn prepare_archive_copy(&self) -> Result<(), StoreError> {
        let checkpoint: (i64, i64, i64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        if checkpoint.0 != 0 || checkpoint.1 != checkpoint.2 {
            return Err(StoreError::Integrity(format!(
                "archive checkpoint did not complete: busy={}, log={}, checkpointed={}",
                checkpoint.0, checkpoint.1, checkpoint.2
            )));
        }
        let journal_mode: String =
            self.connection
                .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("delete") {
            return Err(StoreError::Integrity(format!(
                "archive copy remained in journal mode {journal_mode}"
            )));
        }
        self.validate()
    }

    /// Construct an initialized in-memory store, primarily for conformance tests.
    pub fn initialize_in_memory() -> Result<Self, StoreError> {
        let mut connection = Connection::open_in_memory()?;
        configure_connection(&connection, false)?;
        initialize_connection(&mut connection)?;
        let store = Self {
            connection,
            path: None,
        };
        store.validate()?;
        Ok(store)
    }

    /// Return the backing path, or `None` for an in-memory store.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Verify SQLite integrity, foreign keys, application identity, and schema shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        let version = pragma_i64(&self.connection, "user_version")?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::SchemaVersionMismatch {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        let application_id = pragma_i64(&self.connection, "application_id")?;
        if application_id != APPLICATION_ID {
            return Err(StoreError::ApplicationIdMismatch {
                found: application_id,
                expected: APPLICATION_ID,
            });
        }
        let metadata_version: i64 = self
            .connection
            .query_row(
                "SELECT schema_version FROM schema_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| StoreError::Integrity(format!("schema metadata: {error}")))?;
        if metadata_version != SCHEMA_VERSION {
            return Err(StoreError::Integrity(format!(
                "metadata version {metadata_version} disagrees with user_version {version}"
            )));
        }
        let expected_artifact_digest = schema_artifact_digest();
        // A database written by an earlier provisional schema may lack this
        // column entirely; that is the canonical stale candidate this check
        // exists to catch, so a missing column must yield the same actionable
        // recreation error as a mismatched value, not a raw "no such column".
        let stored_artifact_digest: String = self
            .connection
            .query_row(
                "SELECT schema_artifact_digest FROM schema_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| {
                StoreError::Integrity(format!(
                    "database predates the schema artifact digest recorded by this binary \
                     ({expected_artifact_digest}); it is a stale candidate and must be recreated"
                ))
            })?;
        if stored_artifact_digest != expected_artifact_digest {
            return Err(StoreError::Integrity(format!(
                "schema artifact digest {stored_artifact_digest} was written by a different \
                 schema.sql revision than this binary's {expected_artifact_digest}; this database \
                 is a stale candidate and must be recreated"
            )));
        }
        let quick_check: String =
            self.connection
                .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if quick_check != "ok" {
            return Err(StoreError::Integrity(quick_check));
        }
        let foreign_key_failures: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_check",
            [],
            |row| row.get(0),
        )?;
        if foreign_key_failures != 0 {
            return Err(StoreError::Integrity(format!(
                "{foreign_key_failures} foreign-key violations"
            )));
        }
        validate_required_objects(&self.connection)?;
        let expected = EXPECTED_SCHEMA_FINGERPRINT.as_ref().map_err(|error| {
            StoreError::Integrity(format!("compiled schema cannot be fingerprinted: {error}"))
        })?;
        let actual = schema_fingerprint(&self.connection)?;
        if &actual != expected {
            return Err(StoreError::Integrity(format!(
                "schema definition fingerprint {actual} differs from compiled {expected}"
            )));
        }
        validate_stored_digests(&self.connection)?;
        validate_upgrade_receipts(&self.connection)?;
        validate_all_admission_context_digests(&self.connection)?;
        validate_local_provider_admissions(&self.connection)?;
        validate_provider_intake_invariants(&self.connection)?;
        validate_refusal_invariants(&self.connection)?;
        validate_run_results(&self.connection)?;
        validate_evaluation_refusal_invariants(&self.connection)?;
        validate_diagnostic_artifact_invariants(&self.connection)?;
        validate_runtime_record_ledger(&self.connection)?;
        self.validate_admitted_report_associations()?;
        validate_status_sequence_lower_bound(&self.connection)?;
        validate_projection_invariants(&self.connection)
    }

    /// Append a compiled descriptor snapshot. Its digest is over canonical bytes.
    pub fn append_profile_descriptor(
        &mut self,
        descriptor: &ProfileDescriptorInput,
    ) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO profile_descriptor_snapshots (
                profile_id, profile_version, profile_digest, descriptor_json, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                descriptor.profile_id,
                descriptor.profile_version,
                descriptor.descriptor.digest(),
                descriptor.descriptor.as_bytes(),
                descriptor.recorded_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Read one exact compiled profile descriptor snapshot.
    pub fn profile_descriptor(
        &self,
        profile_id: &str,
        profile_version: &str,
        profile_digest: &str,
    ) -> Result<Option<ProfileDescriptorRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT profile_id, profile_version, profile_digest, descriptor_json, recorded_at
                 FROM profile_descriptor_snapshots
                 WHERE profile_id = ?1 AND profile_version = ?2 AND profile_digest = ?3",
                params![profile_id, profile_version, profile_digest],
                |row| {
                    Ok(ProfileDescriptorRow {
                        profile_id: row.get(0)?,
                        profile_version: row.get(1)?,
                        profile_digest: row.get(2)?,
                        descriptor_json: row.get(3)?,
                        recorded_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Append a fully validated admission record. The store derives
    /// `admission_context_digest` from the typed identity; it is never supplied.
    pub fn append_admission(&mut self, admission: &AdmissionInput) -> Result<(), StoreError> {
        validate_digest("profile_digest", &admission.profile_digest)?;
        let identity = &admission.identity;
        let context_digest = identity.context_digest()?;
        let derived_at = now_utc();
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO admission_records (
                admission_id, instance_id, config_digest, helper_artifact_digest,
                profile_semantic_id, detector_identity_digest, evaluator_source_digest,
                evaluator_artifact_digest, admission_context_digest,
                execution_chain_json, profile_id, profile_version, profile_digest,
                protocol_version, target_triple, artifact_identity_method,
                platform_runtime_version, capability_grant_json, conformance_json,
                lock_json, admitted_at, operator_identity_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
             )",
            params![
                admission.admission_id,
                admission.instance_id,
                identity.config_digest.as_str(),
                identity.helper_artifact_digest.as_str(),
                identity.profile_semantic_id.as_str(),
                identity.detector_identity_digest.as_str(),
                identity.evaluator_source_digest.as_str(),
                identity.evaluator_artifact_digest.as_str(),
                context_digest,
                admission.execution_chain.as_bytes(),
                admission.profile_id,
                admission.profile_version,
                admission.profile_digest,
                identity.protocol_version,
                identity.target_triple,
                identity.artifact_identity_method,
                identity.platform_runtime_version,
                admission.capability_grant.as_bytes(),
                admission.conformance.as_bytes(),
                admission.lock.as_bytes(),
                admission.admitted_at,
                admission.operator_identity.as_bytes(),
            ],
        )?;
        insert_local_provider_admission(
            &transaction,
            admission,
            &context_digest,
            &derived_at,
            "admission_append",
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Read the exact local-provider admission NQ derived from one existing
    /// AdmissionLock record. This is provider admission, not report admission.
    pub fn provider_admission_for_source(
        &self,
        source_admission_id: &str,
    ) -> Result<Option<LocalProviderAdmissionRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT provider_admission_id, source_admission_id,
                        provider_semantic_id, provider_artifact_digest,
                        provider_protocol_identity, provider_config_digest,
                        contract_json, contract_digest, source_admitted_at,
                        derived_at, derivation_kind
                 FROM local_provider_admissions WHERE source_admission_id = ?1",
                [source_admission_id],
                |row| {
                    Ok(LocalProviderAdmissionRow {
                        provider_admission_id: row.get(0)?,
                        source_admission_id: row.get(1)?,
                        provider_semantic_id: row.get(2)?,
                        provider_artifact_digest: row.get(3)?,
                        provider_protocol_identity: row.get(4)?,
                        provider_config_digest: row.get(5)?,
                        contract_json: row.get(6)?,
                        contract_digest: row.get(7)?,
                        source_admitted_at: row.get(8)?,
                        derived_at: row.get(9)?,
                        derivation_kind: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Read one admission lock and its independently captured identities.
    pub fn admission(&self, admission_id: &str) -> Result<Option<AdmissionRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT admission_id, instance_id, config_digest, helper_artifact_digest,
                        profile_semantic_id, detector_identity_digest, evaluator_source_digest,
                        evaluator_artifact_digest, admission_context_digest,
                        profile_id, profile_version, profile_digest, protocol_version,
                        target_triple, artifact_identity_method, platform_runtime_version,
                        lock_json, admitted_at
                 FROM admission_records WHERE admission_id = ?1",
                [admission_id],
                |row| {
                    Ok(AdmissionRow {
                        admission_id: row.get(0)?,
                        instance_id: row.get(1)?,
                        config_digest: row.get(2)?,
                        helper_artifact_digest: row.get(3)?,
                        profile_semantic_id: row.get(4)?,
                        detector_identity_digest: row.get(5)?,
                        evaluator_source_digest: row.get(6)?,
                        evaluator_artifact_digest: row.get(7)?,
                        admission_context_digest: row.get(8)?,
                        profile_id: row.get(9)?,
                        profile_version: row.get(10)?,
                        profile_digest: row.get(11)?,
                        protocol_version: row.get(12)?,
                        target_triple: row.get(13)?,
                        artifact_identity_method: row.get(14)?,
                        platform_runtime_version: row.get(15)?,
                        lock_json: row.get(16)?,
                        admitted_at: row.get(17)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Authenticate the stored snapshot of an admitted report (read-only).
    ///
    /// Recomputes the admission context from its persisted constituents, verifies
    /// the report is bound to exactly that context through its own run and
    /// instance, and recomputes the judgment digest over the persisted judgment
    /// bytes. It never invokes an evaluator, never consults present runtime
    /// state, and never mutates the store; it only confirms or rejects that the
    /// historical admission was validly recorded and is intact.
    #[allow(clippy::too_many_lines)]
    pub fn verify_admitted_snapshot(
        &self,
        report_id: &str,
    ) -> Result<AdmittedSnapshot, SnapshotVerificationError> {
        let report = self
            .connection
            .query_row(
                "SELECT submission_id, instance_id, profile_id, profile_version,
                        profile_digest, observed_at, received_at, report_status,
                        semantic_digest, canonical_json, next_checkpoint_json,
                        validated_report_json,
                        judgment_schema_version, judgment_digest,
                        admission_context_digest
                 FROM admitted_reports WHERE report_id = ?1",
                [report_id],
                |row| {
                    Ok(StoredAdmittedReport {
                        submission_id: row.get(0)?,
                        instance_id: row.get(1)?,
                        profile_id: row.get(2)?,
                        profile_version: row.get(3)?,
                        profile_digest: row.get(4)?,
                        observed_at: row.get(5)?,
                        received_at: row.get(6)?,
                        report_status: row.get(7)?,
                        semantic_digest: row.get(8)?,
                        canonical_json: row.get(9)?,
                        next_checkpoint_json: row.get(10)?,
                        validated_report_json: row.get(11)?,
                        judgment_schema_version: row.get(12)?,
                        judgment_digest: row.get(13)?,
                        admission_context_digest: row.get(14)?,
                    })
                },
            )
            .optional()
            .map_err(|error| SnapshotVerificationError::BindingBroken(error.to_string()))?
            .ok_or_else(|| SnapshotVerificationError::ReportNotFound(report_id.to_owned()))?;
        // Reach the admission through the report's own run. A null admission_id
        // or missing row yields no result: an admitted report whose run has no
        // recorded admission is a broken binding, never a silent pass.
        let admission = self
            .connection
            .query_row(
                "SELECT s.admission_outcome, s.received_at,
                        run.instance_id, run.profile_id, run.profile_version,
                        run.profile_digest, a.instance_id, a.profile_id,
                        a.profile_version, a.profile_digest, a.admission_id,
                        a.admission_context_digest,
                        a.config_digest, a.helper_artifact_digest, a.profile_semantic_id,
                        a.detector_identity_digest, a.evaluator_source_digest,
                        a.evaluator_artifact_digest, a.protocol_version,
                        a.artifact_identity_method, a.platform_runtime_version
                 FROM raw_submissions AS s
                 JOIN watcher_runs AS run ON run.run_id = s.run_id
                 JOIN admission_records AS a ON a.admission_id = run.admission_id
                 WHERE s.submission_id = ?1",
                [&report.submission_id],
                |row| {
                    Ok(StoredAdmissionConstituents {
                        submission_outcome: row.get(0)?,
                        submission_received_at: row.get(1)?,
                        run_instance_id: row.get(2)?,
                        run_profile_id: row.get(3)?,
                        run_profile_version: row.get(4)?,
                        run_profile_digest: row.get(5)?,
                        admission_instance_id: row.get(6)?,
                        admission_profile_id: row.get(7)?,
                        admission_profile_version: row.get(8)?,
                        admission_profile_digest: row.get(9)?,
                        admission_id: row.get(10)?,
                        admission_context_digest: row.get(11)?,
                        config_digest: row.get(12)?,
                        helper_artifact_digest: row.get(13)?,
                        profile_semantic_id: row.get(14)?,
                        detector_identity_digest: row.get(15)?,
                        evaluator_source_digest: row.get(16)?,
                        evaluator_artifact_digest: row.get(17)?,
                        protocol_version: row.get(18)?,
                        artifact_identity_method: row.get(19)?,
                        platform_runtime_version: row.get(20)?,
                    })
                },
            )
            .optional()
            .map_err(|error| SnapshotVerificationError::BindingBroken(error.to_string()))?
            .ok_or_else(|| {
                SnapshotVerificationError::BindingBroken(
                    "the report's run is not bound to a recorded admission".to_owned(),
                )
            })?;

        // The persisted admission context must recompute to its stored digest:
        // a tampered constituent column is corruption, caught before any
        // comparison to the present.
        let recomputed_context = admission.recompute_context_digest().map_err(|error| {
            SnapshotVerificationError::AdmissionContextCorrupt(format!(
                "a persisted constituent is not a valid digest: {error}"
            ))
        })?;
        if recomputed_context != admission.admission_context_digest {
            return Err(SnapshotVerificationError::AdmissionContextCorrupt(format!(
                "recomputed {recomputed_context} does not match stored {}",
                admission.admission_context_digest
            )));
        }

        // The report must bind exactly this admission's context and share its
        // instance the whole way down; another admission's intact context cannot
        // be substituted for this report's.
        if report.admission_context_digest != admission.admission_context_digest {
            return Err(SnapshotVerificationError::BindingBroken(format!(
                "report context {} is not the run's admission context {}",
                report.admission_context_digest, admission.admission_context_digest
            )));
        }
        if admission.submission_outcome != "admitted"
            || report.received_at != admission.submission_received_at
            || report.instance_id != admission.run_instance_id
            || report.instance_id != admission.admission_instance_id
            || report.profile_id != admission.run_profile_id
            || report.profile_version != admission.run_profile_version
            || report.profile_digest != admission.run_profile_digest
            || report.profile_id != admission.admission_profile_id
            || report.profile_version != admission.admission_profile_version
            || report.profile_digest != admission.admission_profile_digest
        {
            return Err(SnapshotVerificationError::BindingBroken(format!(
                "report instance/profile/receipt does not match run {} / admission {}",
                admission.run_instance_id, admission.admission_instance_id
            )));
        }

        // Only recompute a judgment whose schema this binary owns; a foreign
        // schema version is surfaced, never recomputed under the wrong preimage.
        if report.judgment_schema_version != JUDGMENT_SCHEMA_VERSION {
            return Err(SnapshotVerificationError::UnsupportedJudgmentSchema {
                stored: report.judgment_schema_version,
                supported: JUDGMENT_SCHEMA_VERSION.to_owned(),
            });
        }

        // The stored judgment must recompute to its stored digest over exactly
        // the persisted judgment bytes and context — no re-evaluation.
        let validated = CanonicalDocument::from_canonical_bytes(
            report.validated_report_json.clone(),
        )
        .map_err(|error| {
            SnapshotVerificationError::JudgmentCorrupt(format!(
                "persisted judgment is not canonical: {error}"
            ))
        })?;
        let validated_value: Value =
            serde_json::from_slice(validated.as_bytes()).map_err(|error| {
                SnapshotVerificationError::JudgmentCorrupt(format!(
                    "persisted judgment cannot decode: {error}"
                ))
            })?;
        let recomputed_judgment =
            judgment_digest(&report.admission_context_digest, validated.digest())
                .map_err(|error| SnapshotVerificationError::JudgmentCorrupt(error.to_string()))?;
        if recomputed_judgment != report.judgment_digest {
            return Err(SnapshotVerificationError::JudgmentCorrupt(format!(
                "recomputed {recomputed_judgment} does not match stored {}",
                report.judgment_digest
            )));
        }
        let validated_version = validated_value
            .pointer("/profile/version")
            .and_then(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_u64().map(|version| version.to_string()))
            });
        let same_timestamp = |value: Option<&Value>, stored: &str| {
            value
                .and_then(Value::as_str)
                .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).ok())
                .is_some_and(|timestamp| {
                    timestamp.to_rfc3339_opts(SecondsFormat::Millis, true) == stored
                })
        };
        let mut projection_mismatches = Vec::new();
        if validated_value.get("instance_id").and_then(Value::as_str)
            != Some(report.instance_id.as_str())
        {
            projection_mismatches.push("instance_id");
        }
        if validated_value.get("report_digest").and_then(Value::as_str)
            != Some(report.semantic_digest.as_str())
        {
            projection_mismatches.push("report_digest");
        }
        if validated_value
            .pointer("/profile/id")
            .and_then(Value::as_str)
            != Some(report.profile_id.as_str())
        {
            projection_mismatches.push("profile_id");
        }
        if validated_version.as_deref() != Some(report.profile_version.as_str()) {
            projection_mismatches.push("profile_version");
        }
        if validated_value
            .get("profile_digest")
            .and_then(Value::as_str)
            != Some(report.profile_digest.as_str())
        {
            projection_mismatches.push("profile_digest");
        }
        if validated_value.get("status").and_then(Value::as_str)
            != Some(report.report_status.as_str())
        {
            projection_mismatches.push("status");
        }
        if !same_timestamp(validated_value.get("observed_at"), &report.observed_at) {
            projection_mismatches.push("observed_at");
        }
        if !same_timestamp(validated_value.get("received_at"), &report.received_at) {
            projection_mismatches.push("received_at");
        }
        if !projection_mismatches.is_empty() {
            return Err(SnapshotVerificationError::BindingBroken(format!(
                "persisted report projections disagree with its canonical validated judgment: {}",
                projection_mismatches.join(", ")
            )));
        }
        verify_admitted_report_materialization(&self.connection, report_id, &report)?;

        Ok(AdmittedSnapshot {
            report_id: report_id.to_owned(),
            admission_id: admission.admission_id,
            instance_id: report.instance_id,
            admission_context_digest: admission.admission_context_digest,
            judgment_schema_version: JUDGMENT_SCHEMA_VERSION.to_owned(),
            judgment_digest: report.judgment_digest,
            validated_report_json: report.validated_report_json,
            evaluator_artifact_digest: admission.evaluator_artifact_digest,
            artifact_identity_method: admission.artifact_identity_method,
            platform_runtime_version: admission.platform_runtime_version,
        })
    }

    /// Atomically append the authoritative binding transition and the intent
    /// needed to materialize its active-lock filesystem projection.
    ///
    /// A process crash can therefore leave either no transition at all or a
    /// queryable pending intent; it cannot commit a binding event that has no
    /// recovery description.
    pub fn begin_binding_transition(
        &mut self,
        event: &BindingEventInput,
        intent: &BindingMaterializationInput,
    ) -> Result<(), StoreError> {
        validate_binding_event(event)?;
        validate_materialization(intent, "intent")?;
        if intent.instance_id != event.instance_id
            || intent.binding_event_id != event.binding_event_id
        {
            return Err(StoreError::Invariant(
                "binding materialization intent must identify its binding event and instance"
                    .to_owned(),
            ));
        }
        let transaction = self.immediate_transaction()?;
        let pending: i64 = transaction.query_row(
            "SELECT COUNT(*)
             FROM binding_materialization_events AS intent
             WHERE intent.instance_id = ?1 AND intent.phase = 'intent'
               AND NOT EXISTS (
                   SELECT 1 FROM binding_materialization_events AS completed
                   WHERE completed.operation_id = intent.operation_id
                     AND completed.phase = 'completed'
               )",
            [&intent.instance_id],
            |row| row.get(0),
        )?;
        if pending != 0 {
            return Err(StoreError::Invariant(format!(
                "instance {} already has a pending binding materialization",
                intent.instance_id
            )));
        }
        insert_binding_event(&transaction, event)?;
        insert_materialization_event(&transaction, intent)?;
        transaction.commit()?;
        Ok(())
    }

    /// Append proof that one pending active-lock materialization reached
    /// durable filesystem state.
    pub fn complete_binding_materialization(
        &mut self,
        completion: &BindingMaterializationInput,
    ) -> Result<(), StoreError> {
        validate_materialization(completion, "completed")?;
        let transaction = self.immediate_transaction()?;
        let intent_matches: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM binding_materialization_events
             WHERE operation_id = ?1 AND instance_id = ?2
               AND binding_event_id = ?3 AND phase = 'intent'",
            params![
                completion.operation_id,
                completion.instance_id,
                completion.binding_event_id
            ],
            |row| row.get(0),
        )?;
        if intent_matches != 1 {
            return Err(StoreError::Invariant(format!(
                "binding materialization completion {} has no exact intent",
                completion.operation_id
            )));
        }
        insert_materialization_event(&transaction, completion)?;
        transaction.commit()?;
        Ok(())
    }

    /// Return the oldest uncompleted binding materialization for an instance.
    /// Under the per-instance process lock there can be at most one.
    pub fn pending_binding_materialization(
        &self,
        instance_id: &str,
    ) -> Result<Option<PendingBindingMaterializationRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT intent.materialization_event_id, intent.operation_id,
                        intent.instance_id, intent.binding_event_id,
                        intent.occurred_at, intent.detail_json
                 FROM binding_materialization_events AS intent
                 WHERE intent.instance_id = ?1 AND intent.phase = 'intent'
                   AND NOT EXISTS (
                       SELECT 1 FROM binding_materialization_events AS completed
                       WHERE completed.operation_id = intent.operation_id
                         AND completed.phase = 'completed'
                   )
                 ORDER BY intent.materialization_sequence ASC LIMIT 1",
                [instance_id],
                |row| {
                    Ok(PendingBindingMaterializationRow {
                        materialization_event_id: row.get(0)?,
                        operation_id: row.get(1)?,
                        instance_id: row.get(2)?,
                        binding_event_id: row.get(3)?,
                        occurred_at: row.get(4)?,
                        detail_json: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Read the latest binding transition; callers interpret revoke/quiesce as inactive.
    pub fn latest_binding(&self, instance_id: &str) -> Result<Option<BindingEventRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT binding_event_id, instance_id, event_kind, admission_id,
                        binding_digest, occurred_at, reason_code, detail_json
                 FROM instance_binding_events
                 WHERE instance_id = ?1
                 ORDER BY binding_sequence DESC LIMIT 1",
                [instance_id],
                |row| {
                    Ok(BindingEventRow {
                        binding_event_id: row.get(0)?,
                        instance_id: row.get(1)?,
                        event_kind: row.get(2)?,
                        admission_id: row.get(3)?,
                        binding_digest: row.get(4)?,
                        occurred_at: row.get(5)?,
                        reason_code: row.get(6)?,
                        detail_json: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Refuse an incomplete response-only collection.
    ///
    /// Completed non-success and admitted collections must use their atomic
    /// APIs so a watcher run can never become durable without one canonical
    /// result.
    pub fn commit_collection(
        &mut self,
        collection: &CollectionInput,
    ) -> Result<CollectionReceipt, StoreError> {
        validate_collection(collection)?;
        if is_non_success_collection(collection) {
            return Err(StoreError::Invariant(
                "run-bearing non-success collection requires commit_non_success_collection".into(),
            ));
        }
        if is_admitted_collection(collection) {
            return Err(StoreError::Invariant(
                "admitted collection requires atomic evaluations and canonical result".into(),
            ));
        }
        Err(StoreError::Invariant(
            "response collection without a submission cannot prove a canonical completed-run result"
                .into(),
        ))
    }

    /// Return one diagnostic artifact commitment and its current exact-byte
    /// access state.
    ///
    /// `supported_contract_schemas` is consumer capability, not producer
    /// standing. An unsupported schema remains orthogonal to whether its bytes
    /// are available and intact.
    pub fn diagnostic_artifact(
        &self,
        artifact_id: &Sha256Digest,
        supported_contract_schemas: &[&str],
    ) -> Result<DiagnosticArtifactLookup, StoreError> {
        diagnostic_artifact_on_connection(&self.connection, artifact_id, supported_contract_schemas)
    }

    /// Locate the immutable artifact identity committed for one local run.
    pub fn diagnostic_artifact_id_for_run(
        &self,
        run_id: &str,
    ) -> Result<Option<Sha256Digest>, StoreError> {
        diagnostic_artifact_id_for_run_on_connection(&self.connection, run_id)
    }

    /// Atomically append one exact runtime-record batch.
    ///
    /// Repeating the same checkpoint identity and exact batch is idempotent.
    /// Reusing either a checkpoint or record identity for different bytes is a
    /// collision, never an update.
    pub fn append_runtime_records(
        &mut self,
        batch: &RuntimeRecordBatchInput,
    ) -> Result<RuntimeRecordAppendReceipt, StoreError> {
        let transaction = self.immediate_transaction()?;
        let receipt = append_runtime_records_in_transaction(&transaction, batch)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Establish the immutable dependency-admission trust root for this store.
    ///
    /// This is a bootstrap operation, separate from checkpoint append. Exact
    /// replay with the same identity is harmless; selecting another identity
    /// or attempting late establishment after dependency generations exist
    /// refuses.
    pub fn establish_runtime_dependency_trust_root(
        &mut self,
        trust_anchor_id: &Sha256Digest,
    ) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        let existing = runtime_dependency_trust_root_on_connection(&transaction)?;
        match existing {
            Some(existing) if existing == *trust_anchor_id => {}
            Some(existing) => {
                return Err(StoreError::ReplayConflict(format!(
                    "runtime dependency trust root differs: expected {existing}, observed {trust_anchor_id}"
                )));
            }
            None => {
                let migrated_from_v6: bool = transaction.query_row(
                    "SELECT EXISTS (
                        SELECT 1
                        FROM runtime_dependency_binding_migration_boundaries
                        WHERE singleton = 1
                    )",
                    [],
                    |row| row.get(0),
                )?;
                if migrated_from_v6 {
                    return Err(StoreError::Invariant(
                        "post-v6 runtime dependency trust-root bootstrap is unsupported without a separately governed and attributed bootstrap operation"
                            .into(),
                    ));
                }
                let generation_count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM runtime_dependency_generation_commitments",
                    [],
                    |row| row.get(0),
                )?;
                if generation_count != 0 {
                    return Err(StoreError::Integrity(
                        "runtime dependency trust root was absent after dependency generations were committed"
                            .into(),
                    ));
                }
                transaction.execute(
                    "INSERT INTO runtime_dependency_trust_roots (
                        singleton, trust_anchor_id, established_at
                     ) VALUES (1, ?1, ?2)",
                    params![trust_anchor_id.as_str(), now_utc()],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Return the immutable dependency-admission trust root, if established.
    pub fn runtime_dependency_trust_root(&self) -> Result<Option<Sha256Digest>, StoreError> {
        runtime_dependency_trust_root_on_connection(&self.connection)
    }

    /// Reopen one exact runtime record by its immutable identity.
    pub fn runtime_record(&self, record_id: &str) -> Result<Option<RuntimeRecordRow>, StoreError> {
        runtime_record_by_id_on_connection(&self.connection, record_id)
    }

    /// Return the immutable latest checkpoint, or `None` for an empty ledger.
    pub fn runtime_ledger_checkpoint(&self) -> Result<Option<RuntimeLedgerCheckpoint>, StoreError> {
        runtime_ledger_checkpoint_on_connection(&self.connection)
    }

    /// Reopen the exact dependency provenance bound to one checkpoint.
    ///
    /// Missing exact bytes remain committed-unavailable and corrupt bytes are
    /// reported as corrupt. Neither state is filled from a caller's current
    /// dependency generation.
    pub fn runtime_checkpoint_dependency(
        &self,
        checkpoint_id: &str,
    ) -> Result<Option<RuntimeCheckpointDependencyAccess>, StoreError> {
        runtime_checkpoint_dependency_on_connection(&self.connection, checkpoint_id)
    }

    /// Read one bounded page pinned to the supplied immutable checkpoint.
    ///
    /// Passing `None` is valid only for an empty ledger. Callers can retain the
    /// returned checkpoint across pages so later appends never bleed into the
    /// original snapshot.
    pub fn runtime_record_page(
        &self,
        checkpoint: Option<&RuntimeLedgerCheckpoint>,
        after_record_sequence: u64,
        limit: u32,
    ) -> Result<RuntimeRecordPage, StoreError> {
        runtime_record_page_on_connection(
            &self.connection,
            checkpoint,
            after_record_sequence,
            limit,
        )
    }

    /// Inspect the disposable runtime-record lookup projection.
    pub fn runtime_record_lookup_status(&self) -> Result<RuntimeRecordLookupStatus, StoreError> {
        runtime_record_lookup_status_on_connection(&self.connection)
    }

    /// Rebuild the disposable runtime-record lookup projection from the
    /// canonical append-only ledger.
    pub fn rebuild_runtime_record_lookup(
        &mut self,
    ) -> Result<RuntimeRecordLookupStatus, StoreError> {
        let transaction = self.immediate_transaction()?;
        transaction.execute("DELETE FROM runtime_record_lookup", [])?;
        transaction.execute(
            "INSERT INTO runtime_record_lookup (
                record_id, record_sequence, record_schema, ledger_root
             )
             SELECT record_id, record_sequence, record_schema, ledger_root
             FROM runtime_record_ledger ORDER BY record_sequence",
            [],
        )?;
        let status = runtime_record_lookup_status_on_connection(&transaction)?;
        if !status.is_current() {
            return Err(StoreError::Integrity(
                "rebuilt runtime-record lookup does not match canonical ledger".into(),
            ));
        }
        transaction.commit()?;
        Ok(status)
    }

    /// Enumerate exact runtime records of one schema using the verified
    /// disposable lookup projection.
    pub fn runtime_records_by_schema_bounded(
        &self,
        record_schema: &str,
        checkpoint: &RuntimeLedgerCheckpoint,
        after_record_sequence: u64,
        limit: u32,
    ) -> Result<Vec<RuntimeRecordRow>, StoreError> {
        validate_bounded_identity("runtime record_schema", record_schema)?;
        validate_public_limit(limit)?;
        validate_runtime_checkpoint_identity(&self.connection, checkpoint)?;
        let lookup_status = runtime_record_lookup_status_on_connection(&self.connection)?;
        if !lookup_status.is_current() {
            return Err(StoreError::Integrity(
                "runtime-record lookup is stale; rebuild it before schema lookup".into(),
            ));
        }
        let after_sequence = i64::try_from(after_record_sequence)
            .map_err(|_| StoreError::Invariant("runtime-record cursor overflowed".into()))?;
        let through_sequence = i64::try_from(checkpoint.last_record_sequence)
            .map_err(|_| StoreError::Integrity("runtime checkpoint sequence overflowed".into()))?;
        let mut statement = self.connection.prepare(
            "SELECT ledger.record_id
             FROM runtime_record_lookup AS lookup
             JOIN runtime_record_ledger AS ledger
               ON ledger.record_sequence = lookup.record_sequence
              AND ledger.record_id = lookup.record_id
              AND ledger.record_schema = lookup.record_schema
              AND ledger.ledger_root = lookup.ledger_root
             WHERE lookup.record_schema = ?1
               AND lookup.record_sequence > ?2
               AND lookup.record_sequence <= ?3
             ORDER BY lookup.record_sequence
             LIMIT ?4",
        )?;
        let ids = statement
            .query_map(
                params![record_schema, after_sequence, through_sequence, limit],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|record_id| {
                runtime_record_by_id_on_connection(&self.connection, &record_id)?.ok_or_else(|| {
                    StoreError::Integrity(format!(
                        "runtime-record lookup lost canonical record {record_id}"
                    ))
                })
            })
            .collect()
    }

    /// Resolve the exact production execution binding attached to one local
    /// diagnostic artifact. Historical/pre-production artifacts return `None`.
    pub fn diagnostic_artifact_execution_binding(
        &self,
        artifact_id: &Sha256Digest,
    ) -> Result<Option<DiagnosticArtifactExecutionBinding>, StoreError> {
        diagnostic_artifact_execution_binding_on_connection(&self.connection, artifact_id)
    }

    /// Reopen the exact canonical collection result bound to one completed run.
    ///
    /// This is historical status testimony only. It does not re-evaluate the
    /// run or infer diagnostic truth from its local artifact origin.
    pub fn collection_result_for_run(
        &self,
        run_id: &str,
    ) -> Result<Option<CanonicalDocument>, StoreError> {
        let detail = self
            .connection
            .query_row(
                "SELECT detail_json FROM status_events
                 WHERE run_id = ?1
                   AND component_kind = 'instance'",
                [run_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        detail
            .map(|bytes| {
                CanonicalDocument::from_canonical_bytes(bytes).map_err(|error| {
                    StoreError::Integrity(format!(
                        "collection result for run {run_id} is not canonical: {error}"
                    ))
                })
            })
            .transpose()
    }

    /// Enumerate immutable artifact commitments in append order.
    ///
    /// The sequence is only a bounded query cursor. It never participates in
    /// artifact identity or changes the meaning of returned commitments.
    pub fn diagnostic_artifact_commitments_bounded(
        &self,
        limit: u32,
        after_artifact_sequence: Option<u64>,
    ) -> Result<Vec<DiagnosticArtifactCommitment>, StoreError> {
        validate_public_limit(limit)?;
        let after_sequence = after_artifact_sequence
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StoreError::Invariant("artifact sequence cursor overflowed".into()))?;
        let mut statement = self.connection.prepare(
            "SELECT artifact_id FROM diagnostic_artifact_commitments
             WHERE ?1 IS NULL OR artifact_sequence > ?1
             ORDER BY artifact_sequence LIMIT ?2",
        )?;
        let artifact_ids = statement
            .query_map(params![after_sequence, limit], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        artifact_ids
            .into_iter()
            .map(|artifact_id| {
                let artifact_id = Sha256Digest::parse(artifact_id).map_err(|error| {
                    StoreError::Integrity(format!(
                        "diagnostic artifact index contains an invalid identity: {error}"
                    ))
                })?;
                diagnostic_artifact_commitment_on_connection(&self.connection, &artifact_id)?
                    .ok_or_else(|| {
                        StoreError::Integrity(format!(
                            "diagnostic artifact index lost commitment {artifact_id}"
                        ))
                    })
            })
            .collect()
    }

    /// Commit an imported artifact identity whose exact bytes are currently
    /// unavailable.
    ///
    /// This is a custody-only origin and cannot satisfy a local execution
    /// commit. A later exact import must match the committed full-byte digest
    /// and length before the payload can be materialized.
    #[allow(clippy::too_many_lines)]
    pub fn import_unavailable_diagnostic_artifact(
        &mut self,
        input: &UnavailableDiagnosticArtifactImportInput,
    ) -> Result<DiagnosticArtifactImportReceipt, StoreError> {
        validate_bounded_identity("diagnostic artifact import_id", &input.import_id)?;
        validate_bounded_identity(
            "diagnostic artifact contract_schema",
            &input.contract_schema,
        )?;
        let maximum_length = u64::try_from(MAX_STORED_JSON_BYTES).map_err(|_| {
            StoreError::Invariant("diagnostic artifact storage bound overflowed".into())
        })?;
        if input.canonical_bytes_length == 0 || input.canonical_bytes_length > maximum_length {
            return Err(StoreError::Invariant(
                "diagnostic artifact committed byte length is outside storage bounds".into(),
            ));
        }
        if chrono::DateTime::parse_from_rfc3339(&input.imported_at).is_err() {
            return Err(StoreError::Invariant(
                "diagnostic artifact imported_at is not RFC 3339".into(),
            ));
        }
        let transaction = self.immediate_transaction()?;
        if let Some(receipt) = diagnostic_artifact_import_preflight(
            &transaction,
            &input.import_id,
            &input.artifact_id,
            &input.contract_schema,
            &input.canonical_bytes_sha256,
            input.canonical_bytes_length,
            &input.imported_at,
        )? {
            let commitment =
                diagnostic_artifact_commitment_on_connection(&transaction, &input.artifact_id)?
                    .ok_or_else(|| {
                        StoreError::Integrity(
                            "diagnostic artifact import references a missing commitment".into(),
                        )
                    })?;
            if commitment.contract_schema != input.contract_schema
                || commitment.canonical_bytes_sha256 != input.canonical_bytes_sha256
                || commitment.canonical_bytes_length != input.canonical_bytes_length
            {
                return Err(StoreError::ReplayConflict(format!(
                    "diagnostic artifact {} was reused for different schema or exact bytes",
                    input.artifact_id
                )));
            }
            return Ok(receipt);
        }
        let mut created_import_origin = false;
        let disposition = if let Some(commitment) =
            diagnostic_artifact_commitment_on_connection(&transaction, &input.artifact_id)?
        {
            if commitment.contract_schema != input.contract_schema
                || commitment.canonical_bytes_sha256 != input.canonical_bytes_sha256
                || commitment.canonical_bytes_length != input.canonical_bytes_length
            {
                return Err(StoreError::ReplayConflict(format!(
                    "diagnostic artifact {} was reused for different schema or exact bytes",
                    input.artifact_id
                )));
            }
            DiagnosticArtifactImportDisposition::Existing
        } else {
            let byte_length = i64::try_from(input.canonical_bytes_length).map_err(|_| {
                StoreError::Invariant("diagnostic artifact length overflowed".into())
            })?;
            transaction.execute(
                "INSERT INTO diagnostic_artifact_commitments (
                    artifact_id, contract_schema, canonical_bytes_sha256,
                    canonical_bytes_length, committed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    input.artifact_id.as_str(),
                    input.contract_schema,
                    input.canonical_bytes_sha256.as_str(),
                    byte_length,
                    input.imported_at,
                ],
            )?;
            created_import_origin = true;
            DiagnosticArtifactImportDisposition::CommittedUnavailable
        };
        insert_diagnostic_artifact_import_event(
            &transaction,
            &input.import_id,
            &input.artifact_id,
            &input.contract_schema,
            &input.canonical_bytes_sha256,
            input.canonical_bytes_length,
            disposition,
            &input.imported_at,
        )?;
        if created_import_origin {
            transaction.execute(
                "INSERT INTO imported_diagnostic_artifact_origins (
                    artifact_id, import_id, imported_at, initial_outcome
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    input.artifact_id.as_str(),
                    input.import_id,
                    input.imported_at,
                    diagnostic_artifact_import_disposition_name(disposition),
                ],
            )?;
        }
        validate_diagnostic_artifact_invariants(&transaction)?;
        transaction.commit()?;
        Ok(DiagnosticArtifactImportReceipt {
            import_id: input.import_id.clone(),
            artifact_id: input.artifact_id.clone(),
            contract_schema: input.contract_schema.clone(),
            canonical_bytes_sha256: input.canonical_bytes_sha256.clone(),
            canonical_bytes_length: input.canonical_bytes_length,
            disposition,
            imported_at: input.imported_at.clone(),
        })
    }

    /// Verify and commit an opaque canonical artifact received through an
    /// explicit import operation.
    ///
    /// Import establishes custody only. An exact duplicate is idempotent. A
    /// commitment whose bytes became unavailable may be rematerialized only by
    /// bytes matching its original length and complete-byte digest.
    #[allow(clippy::too_many_lines)]
    pub fn import_diagnostic_artifact(
        &mut self,
        input: &DiagnosticArtifactImportInput,
    ) -> Result<DiagnosticArtifactImportReceipt, StoreError> {
        validate_diagnostic_artifact_document(
            &input.artifact_id,
            &input.contract_schema,
            &input.canonical_bytes,
        )?;
        validate_bounded_identity("diagnostic artifact import_id", &input.import_id)?;
        if chrono::DateTime::parse_from_rfc3339(&input.imported_at).is_err() {
            return Err(StoreError::Invariant(
                "diagnostic artifact imported_at is not RFC 3339".into(),
            ));
        }

        let transaction = self.immediate_transaction()?;
        let expected_digest = Sha256Digest::parse(input.canonical_bytes.digest().to_owned())
            .map_err(|error| StoreError::Invariant(error.to_string()))?;
        let expected_length = u64::try_from(input.canonical_bytes.as_bytes().len())
            .map_err(|_| StoreError::Invariant("diagnostic artifact length overflowed".into()))?;

        if let Some(receipt) = diagnostic_artifact_import_preflight(
            &transaction,
            &input.import_id,
            &input.artifact_id,
            &input.contract_schema,
            &expected_digest,
            expected_length,
            &input.imported_at,
        )? {
            let commitment =
                diagnostic_artifact_commitment_on_connection(&transaction, &input.artifact_id)?
                    .ok_or_else(|| {
                        StoreError::Integrity(
                            "diagnostic artifact import references a missing commitment".into(),
                        )
                    })?;
            if commitment.contract_schema != input.contract_schema
                || commitment.canonical_bytes_sha256 != expected_digest
                || commitment.canonical_bytes_length != expected_length
            {
                return Err(StoreError::ReplayConflict(format!(
                    "diagnostic artifact {} was reused for different schema or exact bytes",
                    input.artifact_id
                )));
            }
            return Ok(receipt);
        }
        let existing =
            diagnostic_artifact_commitment_on_connection(&transaction, &input.artifact_id)?;
        let mut created_import_origin = false;
        let disposition = if let Some(commitment) = existing {
            if commitment.contract_schema != input.contract_schema
                || commitment.canonical_bytes_sha256 != expected_digest
                || commitment.canonical_bytes_length != expected_length
            {
                return Err(StoreError::ReplayConflict(format!(
                    "diagnostic artifact {} was reused for different schema or exact bytes",
                    input.artifact_id
                )));
            }
            let stored_bytes = transaction
                .query_row(
                    "SELECT canonical_bytes FROM diagnostic_artifact_payloads
                     WHERE artifact_id = ?1",
                    [input.artifact_id.as_str()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            match stored_bytes {
                Some(bytes) if bytes == input.canonical_bytes.as_bytes() => {
                    DiagnosticArtifactImportDisposition::Existing
                }
                Some(_) => {
                    return Err(StoreError::Integrity(format!(
                        "diagnostic artifact {} payload conflicts with its immutable commitment",
                        input.artifact_id
                    )));
                }
                None => {
                    transaction.execute(
                        "INSERT INTO diagnostic_artifact_payloads (
                            artifact_id, canonical_bytes
                         ) VALUES (?1, ?2)",
                        params![input.artifact_id.as_str(), input.canonical_bytes.as_bytes()],
                    )?;
                    DiagnosticArtifactImportDisposition::Rematerialized
                }
            }
        } else {
            insert_diagnostic_artifact_commitment(
                &transaction,
                &input.artifact_id,
                &input.contract_schema,
                &input.canonical_bytes,
                &input.imported_at,
            )?;
            created_import_origin = true;
            DiagnosticArtifactImportDisposition::Committed
        };
        insert_diagnostic_artifact_import_event(
            &transaction,
            &input.import_id,
            &input.artifact_id,
            &input.contract_schema,
            &expected_digest,
            expected_length,
            disposition,
            &input.imported_at,
        )?;
        if created_import_origin {
            transaction.execute(
                "INSERT INTO imported_diagnostic_artifact_origins (
                    artifact_id, import_id, imported_at, initial_outcome
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    input.artifact_id.as_str(),
                    input.import_id,
                    input.imported_at,
                    diagnostic_artifact_import_disposition_name(disposition),
                ],
            )?;
        }
        validate_diagnostic_artifact_invariants(&transaction)?;
        transaction.commit()?;
        Ok(DiagnosticArtifactImportReceipt {
            import_id: input.import_id.clone(),
            artifact_id: input.artifact_id.clone(),
            contract_schema: input.contract_schema.clone(),
            canonical_bytes_sha256: expected_digest,
            canonical_bytes_length: expected_length,
            disposition,
            imported_at: input.imported_at.clone(),
        })
    }

    /// Atomically append an admitted run, custody, report, detector results,
    /// finding events, and its exact canonical instance result.
    ///
    /// The builder runs after the report sequence is allocated inside the
    /// transaction, so evaluation watermarks can name that exact occurrence.
    /// Any builder or insertion failure rolls the entire collection back.
    pub fn commit_admitted_collection<T, E, F>(
        &mut self,
        collection: &CollectionInput,
        build: F,
    ) -> Result<ProviderIntakeCommit<T>, E>
    where
        E: From<StoreError>,
        F: FnOnce(
            &AdmittedCollectionView<'_, '_>,
            &CollectionReceipt,
        ) -> Result<AdmittedCollectionCompletion<T>, E>,
    {
        self.commit_admitted_collection_inner(
            collection,
            build,
            AdmittedDiagnosticOriginMode::DetectorEvaluation,
        )
    }

    /// Atomically append an admitted run and one run-level production V2
    /// diagnostic without fabricating a detector evaluation.
    ///
    /// The completion type has no evaluation field. Its mandatory artifact
    /// must carry `evaluation_id = None` and one exact production execution
    /// binding committed in the same transaction. Existing detector-oriented
    /// callers remain governed by [`Self::commit_admitted_collection`].
    pub fn commit_admitted_run_level_diagnostic<T, E, F>(
        &mut self,
        collection: &CollectionInput,
        build: F,
    ) -> Result<ProviderIntakeCommit<T>, E>
    where
        E: From<StoreError>,
        F: FnOnce(
            &AdmittedCollectionView<'_, '_>,
            &CollectionReceipt,
        ) -> Result<AdmittedRunLevelDiagnosticCompletion<T>, E>,
    {
        self.commit_admitted_collection_inner(
            collection,
            |view, receipt| {
                let completion = build(view, receipt)?;
                Ok(AdmittedCollectionCompletion {
                    value: completion.value,
                    evaluations: Vec::new(),
                    diagnostic_artifact: Some(completion.diagnostic_artifact),
                    status: completion.status,
                })
            },
            AdmittedDiagnosticOriginMode::RunLevelProduction,
        )
    }

    fn commit_admitted_collection_inner<T, E, F>(
        &mut self,
        collection: &CollectionInput,
        build: F,
        diagnostic_origin_mode: AdmittedDiagnosticOriginMode,
    ) -> Result<ProviderIntakeCommit<T>, E>
    where
        E: From<StoreError>,
        F: FnOnce(
            &AdmittedCollectionView<'_, '_>,
            &CollectionReceipt,
        ) -> Result<AdmittedCollectionCompletion<T>, E>,
    {
        validate_collection(collection).map_err(E::from)?;
        if !is_admitted_collection(collection) {
            return Err(E::from(StoreError::Invariant(
                "atomic admitted completion requires one admitted custody report".into(),
            )));
        }
        let transaction = self.immediate_transaction().map_err(E::from)?;
        if let ProviderIntakePreflight::Existing {
            acknowledgment,
            canonical_result,
        } = provider_intake_preflight_on_connection(&transaction, &collection.intake, true)
            .map_err(E::from)?
        {
            let receipt = collection_receipt_for_run(&transaction, &acknowledgment.run_id)
                .map_err(E::from)?;
            if diagnostic_origin_mode == AdmittedDiagnosticOriginMode::RunLevelProduction {
                validate_admitted_run_level_diagnostic_replay(&transaction, &acknowledgment.run_id)
                    .map_err(E::from)?;
            }
            return Ok(ProviderIntakeCommit::Replayed {
                receipt,
                acknowledgment,
                canonical_result,
            });
        }
        let receipt = insert_collection(&transaction, collection).map_err(E::from)?;
        if receipt.report_sequence.is_none() || receipt.semantic_digest.is_none() {
            return Err(E::from(StoreError::Invariant(
                "admitted collection did not allocate its report identity".into(),
            )));
        }
        let completion = {
            let view = AdmittedCollectionView {
                transaction: &transaction,
            };
            build(&view, &receipt)?
        };
        validate_admitted_completion(collection, &receipt, &completion).map_err(E::from)?;
        for input in &completion.evaluations {
            insert_evaluation(&transaction, &input.evaluation, input.finding.as_ref())
                .map_err(E::from)?;
        }
        if let Some(artifact) = &completion.diagnostic_artifact {
            insert_local_diagnostic_artifact(
                &transaction,
                collection,
                &completion,
                artifact,
                diagnostic_origin_mode,
            )
            .map_err(E::from)?;
        } else if diagnostic_origin_mode == AdmittedDiagnosticOriginMode::RunLevelProduction {
            return Err(E::from(StoreError::Invariant(
                "run-level admitted diagnostic completion requires one exact artifact".into(),
            )));
        }
        insert_status_event(
            &transaction,
            &completion.status,
            Some(&collection.run.run_id),
        )
        .map_err(E::from)?;
        let acknowledgment = insert_provider_acknowledgment(
            &transaction,
            &collection.intake,
            &collection.run.run_id,
            &completion.status,
        )
        .map_err(E::from)?;
        validate_provider_intake_invariants(&transaction).map_err(E::from)?;
        validate_refusal_invariants(&transaction).map_err(E::from)?;
        validate_run_results(&transaction).map_err(E::from)?;
        validate_evaluation_refusal_invariants(&transaction).map_err(E::from)?;
        validate_diagnostic_artifact_invariants(&transaction).map_err(E::from)?;
        transaction
            .commit()
            .map_err(StoreError::from)
            .map_err(E::from)?;
        Ok(ProviderIntakeCommit::Committed {
            receipt,
            acknowledgment,
            value: completion.value,
        })
    }

    /// Atomically append one run-bearing non-success collection and its exact
    /// canonical instance result. A process interruption can expose neither
    /// half without the other.
    pub fn commit_non_success_collection(
        &mut self,
        collection: &CollectionInput,
        result: &RunResultStatusInput,
    ) -> Result<ProviderIntakeCommit<()>, StoreError> {
        self.commit_non_success_collection_with_artifact(collection, result, None)
            .map(|completion| completion.intake)
    }

    /// Atomically append one run-bearing non-success collection, its optional
    /// exact diagnostic artifact, and its canonical result.
    ///
    /// A replay returns the artifact identity already bound to the original
    /// run. It never invokes evaluation and never adds an artifact to a
    /// previously completed attempt.
    pub fn commit_non_success_collection_with_artifact(
        &mut self,
        collection: &CollectionInput,
        result: &RunResultStatusInput,
        diagnostic_artifact: Option<&DiagnosticArtifactCommitInput>,
    ) -> Result<NonSuccessCollectionArtifactCommit, StoreError> {
        validate_collection(collection)?;
        validate_non_success_input(collection, result)?;
        if let Some(artifact) = diagnostic_artifact {
            validate_run_only_diagnostic_artifact(collection, artifact)?;
        }
        let transaction = self.immediate_transaction()?;
        if let ProviderIntakePreflight::Existing {
            acknowledgment,
            canonical_result,
        } = provider_intake_preflight_on_connection(&transaction, &collection.intake, true)?
        {
            let receipt = collection_receipt_for_run(&transaction, &acknowledgment.run_id)?;
            let diagnostic_artifact_id =
                diagnostic_artifact_id_for_run_on_connection(&transaction, &acknowledgment.run_id)?;
            return Ok(NonSuccessCollectionArtifactCommit {
                intake: ProviderIntakeCommit::Replayed {
                    receipt,
                    acknowledgment,
                    canonical_result,
                },
                diagnostic_artifact_id,
            });
        }
        let receipt = insert_collection(&transaction, collection)?;
        validate_refusal_invariants(&transaction)?;
        if let Some(artifact) = diagnostic_artifact {
            insert_run_only_diagnostic_artifact(&transaction, collection, artifact)?;
            if fail_non_success_after_artifact_insert_for_test() {
                return Err(StoreError::Invariant(
                    "injected failure after non-success diagnostic artifact insertion".into(),
                ));
            }
        }
        insert_status_event(&transaction, &result.status, Some(&result.run_id))?;
        let acknowledgment = insert_provider_acknowledgment(
            &transaction,
            &collection.intake,
            &collection.run.run_id,
            &result.status,
        )?;
        validate_provider_intake_invariants(&transaction)?;
        validate_run_results(&transaction)?;
        validate_diagnostic_artifact_invariants(&transaction)?;
        transaction.commit()?;
        Ok(NonSuccessCollectionArtifactCommit {
            intake: ProviderIntakeCommit::Committed {
                receipt,
                acknowledgment,
                value: (),
            },
            diagnostic_artifact_id: diagnostic_artifact
                .map(|artifact| artifact.artifact_id.clone()),
        })
    }

    /// Check an exact provider retry before protocol/profile/evaluator work.
    ///
    /// Current provider admission is required even for a byte-identical retry;
    /// historical acknowledgment reopening is available separately and never
    /// changes a stored decision.
    pub fn preflight_provider_intake(
        &self,
        intake: &ProviderIntakeInput,
    ) -> Result<ProviderIntakePreflight, StoreError> {
        provider_intake_preflight_on_connection(&self.connection, intake, true)
    }

    /// Reopen a durable provider acknowledgment without requiring that its
    /// historical provider admission remains current.
    pub fn provider_intake_acknowledgment(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<(DurableIntakeAcknowledgment, CanonicalDocument)>, StoreError> {
        validate_digest("idempotency_key", idempotency_key)?;
        let intake_id: Option<String> = self
            .connection
            .query_row(
                "SELECT intake_id FROM provider_intake_attempts WHERE idempotency_key = ?1",
                [idempotency_key],
                |row| row.get(0),
            )
            .optional()?;
        intake_id
            .map(|intake_id| provider_acknowledgment_for_intake(&self.connection, &intake_id))
            .transpose()
            .map(Option::flatten)
    }

    /// Reopen one exact provider intake and its durable acknowledgment.
    pub fn provider_intake(
        &self,
        intake_id: &str,
    ) -> Result<Option<ProviderIntakeRow>, StoreError> {
        validate_provider_intake_invariants(&self.connection)?;
        let mut rows = self.provider_intake_rows(1, Some(intake_id), true)?;
        Ok(rows.pop().filter(|row| row.intake_id == intake_id))
    }

    /// Prove the store-wide exact-one-origin, exact-one-acknowledgment, digest,
    /// replay, native-outcome, raw-custody, and v3-gap laws once before an
    /// exhaustive history traversal.
    pub fn validate_provider_intake_history_invariants(&self) -> Result<(), StoreError> {
        validate_provider_intake_invariants(&self.connection)
    }

    /// Page real v4 provider intakes in lexical identity order. Exhaustive
    /// semantic consumers must first call
    /// [`Self::validate_provider_intake_history_invariants`] once for the
    /// traversal rather than rescanning all append-only history per page.
    pub fn provider_intakes_bounded(
        &self,
        limit: u32,
        after_intake_id: Option<&str>,
    ) -> Result<Vec<ProviderIntakeRow>, StoreError> {
        validate_public_limit(limit)?;
        self.provider_intake_rows(limit, after_intake_id, false)
    }

    fn provider_intake_rows(
        &self,
        limit: u32,
        cursor: Option<&str>,
        inclusive: bool,
    ) -> Result<Vec<ProviderIntakeRow>, StoreError> {
        let comparison = if inclusive { ">=" } else { ">" };
        let sql = format!(
            "SELECT intake.intake_id, intake.attempt_id, intake.idempotency_key,
                    intake.request_id, intake.provider_admission_id,
                    intake.admission_context_digest, intake.provider_semantic_id,
                    intake.provider_artifact_digest, intake.provider_protocol_identity,
                    intake.provider_config_digest, intake.binding_digest,
                    intake.instance_id, intake.profile_id, intake.profile_version,
                    intake.profile_digest, intake.profile_semantic_id,
                    intake.evaluator_artifact_digest, intake.context_json,
                    intake.context_digest, intake.interpretation_kind,
                    intake.interpretation_json, intake.interpretation_digest,
                    intake.native_outcome_kind, intake.native_outcome_json,
                    intake.native_outcome_digest, intake.raw_bytes, intake.raw_sha256,
                    intake.started_at, intake.finished_at, intake.received_at,
                    intake.replay_digest, intake.intake_digest,
                    intake.source_admission_id, intake.provider_sequence,
                    intake.origin_carrier, intake.deadline_at,
                    intake.checkpoint_contract_digest,
                    intake.execution_identity_digest, local.run_id,
                    source.capability_grant_json, source.lock_json
             FROM provider_intake_attempts AS intake
             JOIN local_watcher_provider_intakes AS local ON local.intake_id = intake.intake_id
             JOIN admission_records AS source
               ON source.admission_id = intake.source_admission_id
             WHERE ?1 IS NULL OR intake.intake_id {comparison} ?1
             ORDER BY intake.intake_id LIMIT ?2"
        );
        let mut statement = self.connection.prepare(&sql)?;
        let stored = statement
            .query_map(params![cursor, limit], stored_provider_intake_row)?
            .collect::<Result<Vec<_>, _>>()?;
        stored
            .into_iter()
            .map(|stored| {
                let (acknowledgment, _) =
                    provider_acknowledgment_for_intake(&self.connection, &stored.intake_id)?
                        .ok_or_else(|| {
                            StoreError::Integrity(format!(
                                "provider intake {} lacks its acknowledgment",
                                stored.intake_id
                            ))
                        })?;
                Ok(ProviderIntakeRow {
                    intake_id: stored.intake_id,
                    attempt_id: stored.attempt_id,
                    idempotency_key: stored.idempotency_key,
                    request_id: stored.request_id,
                    provider_admission_id: stored.provider_admission_id,
                    source_admission_id: stored.source_admission_id,
                    provider_sequence: stored.provider_sequence,
                    origin_carrier: stored.origin_carrier,
                    deadline_at: stored.deadline_at,
                    checkpoint_contract_digest: stored.checkpoint_contract_digest,
                    execution_identity_digest: stored.execution_identity_digest,
                    admission_context_digest: stored.admission_context_digest,
                    provider_semantic_id: stored.provider_semantic_id,
                    provider_artifact_digest: stored.provider_artifact_digest,
                    provider_protocol_identity: stored.provider_protocol_identity,
                    provider_config_digest: stored.provider_config_digest,
                    binding_digest: stored.binding_digest,
                    instance_id: stored.instance_id,
                    profile_id: stored.profile_id,
                    profile_version: stored.profile_version,
                    profile_digest: stored.profile_digest,
                    profile_semantic_id: stored.profile_semantic_id,
                    evaluator_artifact_digest: stored.evaluator_artifact_digest,
                    context_json: stored.context_json,
                    context_digest: stored.context_digest,
                    interpretation_kind: stored.interpretation_kind,
                    interpretation_json: stored.interpretation_json,
                    interpretation_digest: stored.interpretation_digest,
                    native_outcome_kind: stored.native_outcome_kind,
                    native_outcome_json: stored.native_outcome_json,
                    native_outcome_digest: stored.native_outcome_digest,
                    raw_sha256: stored.raw_sha256,
                    started_at: stored.started_at,
                    finished_at: stored.finished_at,
                    received_at: stored.received_at,
                    replay_digest: stored.replay_digest,
                    intake_digest: stored.intake_digest,
                    run_id: stored.run_id,
                    source_capability_grant_json: stored.source_capability_grant_json,
                    source_lock_json: stored.source_lock_json,
                    acknowledgment,
                })
            })
            .collect()
    }

    /// Fetch the byte-exact outer provider capture, including partial failures.
    pub fn provider_intake_raw_bytes(
        &self,
        intake_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.connection
            .query_row(
                "SELECT raw_bytes FROM provider_intake_attempts WHERE intake_id = ?1",
                [intake_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Page explicit schema-v3 provider-intake limitations without upgrading
    /// them into evidence that was never recorded.
    pub fn legacy_provider_intake_gaps_bounded(
        &self,
        limit: u32,
        after_run_id: Option<&str>,
    ) -> Result<Vec<LegacyProviderIntakeGapRow>, StoreError> {
        validate_public_limit(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT run_id, source_schema_version, source_schema_artifact_digest,
                    limitation_code, detail_json, migrated_at
             FROM legacy_v3_watcher_run_intake_gaps
             WHERE ?1 IS NULL OR run_id > ?1
             ORDER BY run_id LIMIT ?2",
        )?;
        statement
            .query_map(params![after_run_id, limit], |row| {
                Ok(LegacyProviderIntakeGapRow {
                    run_id: row.get(0)?,
                    source_schema_version: row.get(1)?,
                    source_schema_artifact_digest: row.get(2)?,
                    limitation_code: row.get(3)?,
                    detail_json: row.get(4)?,
                    migrated_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Fetch exact raw bytes without a JSON or UTF-8 round trip.
    pub fn raw_submission_bytes(&self, submission_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.connection
            .query_row(
                "SELECT raw_bytes FROM raw_submissions WHERE submission_id = ?1",
                [submission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Reopen the admitted report and exact evaluation count belonging to one
    /// collection run. No time/watermark inference participates in this link.
    pub fn admitted_collection_for_run(
        &self,
        run_id: &str,
    ) -> Result<Option<AdmittedCollectionRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT run.run_id, run.instance_id, report.report_id,
                        report.report_sequence, report.report_status, report.semantic_digest,
                        report.canonical_json,
                        COUNT(evaluation.evaluation_id)
                 FROM watcher_runs AS run
                 JOIN raw_submissions AS submission ON submission.run_id = run.run_id
                 JOIN admitted_reports AS report
                   ON report.submission_id = submission.submission_id
                 LEFT JOIN evaluation_runs AS evaluation
                   ON evaluation.trigger_run_id = run.run_id
                 WHERE run.run_id = ?1 AND submission.admission_outcome = 'admitted'
                 GROUP BY run.run_id, run.instance_id, report.report_id,
                          report.report_sequence, report.report_status,
                          report.semantic_digest, report.canonical_json",
                [run_id],
                |row| {
                    Ok(AdmittedCollectionRow {
                        run_id: row.get(0)?,
                        instance_id: row.get(1)?,
                        report_id: row.get(2)?,
                        report_sequence: row.get(3)?,
                        report_status: row.get(4)?,
                        semantic_digest: row.get(5)?,
                        canonical_json: row.get(6)?,
                        evaluations: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Resolve one canonical detector evidence reference to its exact admitted
    /// report occurrence and optional observation.
    pub fn admitted_evidence_reference(
        &self,
        report_id: &str,
        semantic_digest: &str,
        observation_ordinal: Option<u32>,
    ) -> Result<Option<AdmittedEvidenceReferenceRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT report.instance_id, report.report_sequence,
                        report.observed_at, report.received_at,
                        CASE WHEN ?3 IS NULL THEN 1 ELSE EXISTS (
                            SELECT 1 FROM observations AS observation
                            WHERE observation.report_id = report.report_id
                              AND observation.ordinal = ?3
                        ) END,
                        (SELECT observation.observed_at
                         FROM observations AS observation
                         WHERE observation.report_id = report.report_id
                           AND observation.ordinal = ?3),
                        report.canonical_json
                 FROM admitted_reports AS report
                 WHERE report.report_id = ?1 AND report.semantic_digest = ?2",
                params![report_id, semantic_digest, observation_ordinal],
                |row| {
                    Ok(AdmittedEvidenceReferenceRow {
                        instance_id: row.get(0)?,
                        report_sequence: row.get(1)?,
                        observed_at: row.get(2)?,
                        received_at: row.get(3)?,
                        observation_exists: row.get(4)?,
                        observation_observed_at: row.get(5)?,
                        canonical_json: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Enumerate immutable admitted-report identities in bounded lexical order.
    pub fn admitted_report_ids_bounded(
        &self,
        limit: u32,
        after_report_id: Option<&str>,
    ) -> Result<Vec<String>, StoreError> {
        validate_public_limit(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT report_id FROM admitted_reports
             WHERE ?1 IS NULL OR report_id > ?1
             ORDER BY report_id LIMIT ?2",
        )?;
        statement
            .query_map(params![after_report_id, limit], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Prove exact one-to-one admitted submission/report association and its
    /// complete run/admission identity chain.
    pub fn validate_admitted_report_associations(&self) -> Result<(), StoreError> {
        validate_admitted_report_associations_connection(&self.connection)
    }

    /// Reopen the authoritative acquisition testimony and admitted profile
    /// binding for one exact watcher run.
    pub fn watcher_run_outcome(
        &self,
        run_id: &str,
    ) -> Result<Option<WatcherRunOutcomeRow>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT run.run_id, run.request_id, run.instance_id, run.admission_id,
                        run.profile_id, run.profile_version, run.profile_digest,
                        admission.instance_id, admission.profile_id,
                        admission.profile_version, admission.profile_digest,
                        admission.profile_semantic_id,
                        admission.detector_identity_digest,
                        admission.evaluator_artifact_digest,
                        run.acquisition_outcome, run.resource_outcome_json
                 FROM watcher_runs AS run
                 LEFT JOIN admission_records AS admission
                   ON admission.admission_id = run.admission_id
                 WHERE run.run_id = ?1",
                [run_id],
                |row| {
                    Ok(WatcherRunOutcomeRow {
                        run_id: row.get(0)?,
                        request_id: row.get(1)?,
                        instance_id: row.get(2)?,
                        admission_id: row.get(3)?,
                        profile_id: row.get(4)?,
                        profile_version: row.get(5)?,
                        profile_digest: row.get(6)?,
                        admission_instance_id: row.get(7)?,
                        admission_profile_id: row.get(8)?,
                        admission_profile_version: row.get(9)?,
                        admission_profile_digest: row.get(10)?,
                        profile_semantic_id: row.get(11)?,
                        admission_detector_identity_digest: row.get(12)?,
                        admission_evaluator_artifact_digest: row.get(13)?,
                        acquisition_outcome: row.get(14)?,
                        resource_outcome_json: row.get(15)?,
                    })
                },
            )
            .optional()?;
        if let Some(row) = &row {
            CanonicalDocument::from_canonical_bytes(row.resource_outcome_json.clone()).map_err(
                |error| {
                    StoreError::Integrity(format!(
                        "watcher run {} resource outcome is not exact canonical JSON: {error}",
                        row.run_id
                    ))
                },
            )?;
        }
        Ok(row)
    }

    /// Exhaustively page authoritative watcher-run acquisition testimony by
    /// stable run identity.
    pub fn watcher_run_outcomes_bounded(
        &self,
        limit: u32,
        after_run_id: Option<&str>,
    ) -> Result<Vec<WatcherRunOutcomeRow>, StoreError> {
        validate_public_limit(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT run.run_id, run.request_id, run.instance_id, run.admission_id,
                    run.profile_id, run.profile_version, run.profile_digest,
                    admission.instance_id, admission.profile_id,
                    admission.profile_version, admission.profile_digest,
                    admission.profile_semantic_id,
                    admission.detector_identity_digest,
                    admission.evaluator_artifact_digest,
                    run.acquisition_outcome, run.resource_outcome_json
             FROM watcher_runs AS run
             LEFT JOIN admission_records AS admission
               ON admission.admission_id = run.admission_id
             WHERE ?1 IS NULL OR run.run_id > ?1
             ORDER BY run.run_id
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_run_id, limit], |row| {
            Ok(WatcherRunOutcomeRow {
                run_id: row.get(0)?,
                request_id: row.get(1)?,
                instance_id: row.get(2)?,
                admission_id: row.get(3)?,
                profile_id: row.get(4)?,
                profile_version: row.get(5)?,
                profile_digest: row.get(6)?,
                admission_instance_id: row.get(7)?,
                admission_profile_id: row.get(8)?,
                admission_profile_version: row.get(9)?,
                admission_profile_digest: row.get(10)?,
                profile_semantic_id: row.get(11)?,
                admission_detector_identity_digest: row.get(12)?,
                admission_evaluator_artifact_digest: row.get(13)?,
                acquisition_outcome: row.get(14)?,
                resource_outcome_json: row.get(15)?,
            })
        })?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        for row in &rows {
            CanonicalDocument::from_canonical_bytes(row.resource_outcome_json.clone()).map_err(
                |error| {
                    StoreError::Integrity(format!(
                        "watcher run {} resource outcome is not exact canonical JSON: {error}",
                        row.run_id
                    ))
                },
            )?;
        }
        Ok(rows)
    }

    /// Enumerate rejected custody with its exact linked typed refusal.
    ///
    /// The result is bounded and ordered by immutable run/submission identity.
    /// Validation guarantees that every returned rejection has exactly one
    /// matching refusal; this method never guesses from a coarse code or log.
    pub fn rejected_custody(&self, limit: u32) -> Result<Vec<RejectedCustodyRow>, StoreError> {
        self.rejected_custody_bounded(limit, None)
    }

    /// Read one bounded page of rejected custody after a submission identity.
    ///
    /// The immutable primary-key cursor lets archive verification exhaust the
    /// entire history without treating a full public-response page as proof
    /// that no later custody row exists.
    pub fn rejected_custody_bounded(
        &self,
        limit: u32,
        after_submission_id: Option<&str>,
    ) -> Result<Vec<RejectedCustodyRow>, StoreError> {
        validate_public_limit(limit)?;
        // Refuse rather than expose a partial or ambiguous history if the live
        // connection has acquired an invalid row since it was opened.
        validate_refusal_invariants(&self.connection)?;
        let mut statement = self.connection.prepare(
            "SELECT submission.submission_id, submission.run_id, run.request_id,
                    run.instance_id, run.profile_id, run.profile_version,
                    run.profile_digest, run.admission_id,
                    admission.profile_semantic_id, submission.raw_sha256,
                    submission.received_at, submission.protocol_outcome,
                    refusal.refusal_id, refusal.source_kind,
                    refusal.responsible_instance_id, refusal.boundary,
                    refusal.code, refusal.detail_json, refusal.created_at
             FROM raw_submissions AS submission
             JOIN watcher_runs AS run ON run.run_id = submission.run_id
             LEFT JOIN admission_records AS admission
               ON admission.admission_id = run.admission_id
             JOIN refusals AS refusal
               ON refusal.submission_id = submission.submission_id
             WHERE submission.admission_outcome = 'rejected'
               AND (?1 IS NULL OR submission.submission_id > ?1)
             ORDER BY submission.submission_id
             LIMIT ?2",
        )?;
        let rows =
            statement.query_map(params![after_submission_id, limit], rejected_custody_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Reopen one rejected custody artifact by its stable refusal identity.
    ///
    /// The same store-wide semantic validation as bounded enumeration runs
    /// before lookup, so an ambiguous or invalid historical association refuses
    /// instead of being selected by accident.
    pub fn rejected_custody_by_refusal_id(
        &self,
        refusal_id: &str,
    ) -> Result<Option<RejectedCustodyRow>, StoreError> {
        validate_refusal_invariants(&self.connection)?;
        self.connection
            .query_row(
                "SELECT submission.submission_id, submission.run_id, run.request_id,
                        run.instance_id, run.profile_id, run.profile_version,
                        run.profile_digest, run.admission_id,
                        admission.profile_semantic_id, submission.raw_sha256,
                        submission.received_at, submission.protocol_outcome,
                        refusal.refusal_id, refusal.source_kind,
                        refusal.responsible_instance_id, refusal.boundary,
                        refusal.code, refusal.detail_json, refusal.created_at
                 FROM raw_submissions AS submission
                 JOIN watcher_runs AS run ON run.run_id = submission.run_id
                 LEFT JOIN admission_records AS admission
                   ON admission.admission_id = run.admission_id
                 JOIN refusals AS refusal
                   ON refusal.submission_id = submission.submission_id
                 WHERE submission.admission_outcome = 'rejected'
                   AND refusal.refusal_id = ?1",
                [refusal_id],
                rejected_custody_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Return whether a custody artifact was admitted as a report.
    pub fn report_id_for_submission(
        &self,
        submission_id: &str,
    ) -> Result<Option<String>, StoreError> {
        self.connection
            .query_row(
                "SELECT report_id FROM admitted_reports WHERE submission_id = ?1",
                [submission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Rebuild the two mutable current-state pointers from immutable event history.
    pub fn rebuild_current_projections(&mut self) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        transaction.execute("DELETE FROM finding_current", [])?;
        transaction.execute(
            "INSERT INTO finding_current (finding_id, latest_event_id)
             SELECT event.finding_id, event.event_id
             FROM finding_events AS event
             WHERE NOT EXISTS (
                SELECT 1 FROM finding_events AS later
                WHERE later.finding_id = event.finding_id
                  AND later.event_revision > event.event_revision
             )",
            [],
        )?;
        transaction.execute("DELETE FROM status_current", [])?;
        transaction.execute(
            "INSERT INTO status_current (
                component_kind, component_id, latest_status_event_id
             )
             SELECT event.component_kind, event.component_id, event.status_event_id
             FROM status_events AS event
             WHERE NOT EXISTS (
                SELECT 1 FROM status_events AS later
                WHERE later.component_kind = event.component_kind
                  AND later.component_id = event.component_id
                  AND later.status_sequence > event.status_sequence
             )",
            [],
        )?;
        transaction.commit()?;
        validate_projection_invariants(&self.connection)
    }

    fn immediate_transaction(&mut self) -> Result<Transaction<'_>, StoreError> {
        self.connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)
    }
}

/// An instance-specific database watermark captured within an evaluation transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationWatermark {
    pub instance_id: String,
    pub max_report_sequence: i64,
    pub watermark_received_at: Option<String>,
}

/// One detector evaluation request. Watermarks are captured, not caller supplied.
#[derive(Clone, Debug)]
pub struct EvaluationInput {
    pub evaluation_id: String,
    /// Exact collection run that triggered this evaluation. Freshness-only
    /// reevaluations remain explicitly unbound.
    pub trigger_run_id: Option<String>,
    pub detector_id: String,
    pub detector_version: String,
    pub detector_digest: String,
    /// Artifact digest of the running evaluator (nqd) that produced this
    /// evaluation and its finding events.
    pub evaluator_artifact_digest: String,
    pub started_at: String,
    pub evaluated_at: String,
    pub outcome: String,
    pub detail: CanonicalDocument,
    /// Exact compiled profile identity under which the detector evaluated.
    pub profile: EvaluationProfileBinding,
    /// Exact watermarks returned by [`Store::evidence_snapshot`].
    pub watermarks: Vec<EvaluationWatermark>,
    pub refusal: Option<RefusalInput>,
}

/// One detector result and its optional finding event to append as part of an
/// atomic admitted-collection completion.
#[derive(Clone, Debug)]
pub struct EvaluationCommitInput {
    pub evaluation: EvaluationInput,
    pub finding: Option<FindingEventInput>,
}

/// The authoritative remainder of one admitted collection, constructed after
/// the report has an exact durable sequence but before any part is committed.
#[derive(Clone, Debug)]
pub struct AdmittedCollectionCompletion<T> {
    pub value: T,
    pub evaluations: Vec<EvaluationCommitInput>,
    pub diagnostic_artifact: Option<DiagnosticArtifactCommitInput>,
    pub status: StatusEventInput,
}

/// A run-level admitted diagnostic completion with no detector evaluations.
///
/// The mandatory artifact must identify the admitted run directly and carry
/// an exact production execution binding. This type cannot be used to smuggle
/// detector results around the legacy evaluation laws.
#[derive(Clone, Debug)]
pub struct AdmittedRunLevelDiagnosticCompletion<T> {
    pub value: T,
    pub diagnostic_artifact: DiagnosticArtifactCommitInput,
    pub status: StatusEventInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmittedDiagnosticOriginMode {
    DetectorEvaluation,
    RunLevelProduction,
}

/// Required profile identity for every detector evaluation, independent of
/// whether a finding event is emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationProfileBinding {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub profile_semantic_id: Sha256Digest,
}

/// One exact admitted evidence reference used by a finding event.
#[derive(Clone, Debug)]
pub struct FindingEvidenceInput {
    pub ordinal: u32,
    pub report_id: String,
    pub report_semantic_digest: String,
    pub observation_ordinal: Option<u32>,
    pub observed_at: String,
    pub received_at: String,
}

/// A bounded append-only update to a finding and its rebuildable current projection.
#[derive(Clone, Debug)]
pub struct FindingEventInput {
    pub event_id: String,
    pub finding_id: String,
    pub event_kind: String,
    pub instance_id: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub subject: CanonicalDocument,
    pub condition_name: String,
    pub condition_state: String,
    pub visibility_state: String,
    pub operator_work_state: String,
    pub severity: String,
    pub summary: String,
    pub limitations: CanonicalDocument,
    pub safe_next_checks: CanonicalDocument,
    pub freshness: CanonicalDocument,
    pub basis: CanonicalDocument,
    pub refusal: Option<CanonicalDocument>,
    pub origin_mode: String,
    pub historical_refs: CanonicalDocument,
    pub observed_at: Option<String>,
    pub received_at: Option<String>,
    pub created_at: String,
    pub evidence: Vec<FindingEvidenceInput>,
}

/// The database watermark captured by a committed detector evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationReceipt {
    pub evaluation_id: String,
    pub evaluation_sequence: u64,
    pub evaluation_revision: u64,
    pub watermarks: Vec<EvaluationWatermark>,
}

/// Exact local-run origin of one persisted evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationOriginRow {
    pub evaluation_id: String,
    pub evaluation_sequence: i64,
    pub trigger_run_id: Option<String>,
}

/// An admitted report row sufficient for profile-specific reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReportRow {
    pub report_sequence: i64,
    pub report_id: String,
    pub instance_id: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub observed_at: String,
    pub received_at: String,
    pub report_status: String,
    pub canonical_json: Vec<u8>,
    pub semantic_digest: String,
}

/// A transactionally consistent set of reports and per-instance high-water marks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceSnapshot {
    pub watermarks: Vec<EvaluationWatermark>,
    pub reports: Vec<AdmittedReportRow>,
}

/// One row from the stable `nq.finding_snapshot.v3` public read model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingSnapshotRow {
    pub finding_id: String,
    pub instance_id: String,
    pub detector_id: String,
    pub detector_version: String,
    pub detector_digest: String,
    pub evaluation_revision: i64,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub profile_semantic_id: String,
    pub subject_json: String,
    pub condition_name: String,
    pub condition_state: String,
    pub visibility_state: String,
    pub operator_work_state: String,
    pub severity: String,
    pub summary: String,
    pub limitations_json: String,
    pub safe_next_checks_json: String,
    pub freshness_json: String,
    pub basis_json: String,
    pub refusal_json: Option<String>,
    pub origin_mode: String,
    pub historical_refs_json: String,
    pub observed_at: Option<String>,
    pub received_at: Option<String>,
    pub evaluated_at: String,
    pub evaluation_id: String,
    pub evaluation_refusal_json: Option<String>,
    pub evidence_json: String,
}

/// One component row from the stable `nq.status_snapshot.v1` public read model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusSnapshotRow {
    pub component_kind: String,
    pub component_id: String,
    pub state: String,
    pub code: String,
    pub detail_json: String,
    pub observed_at: String,
}

/// One immutable status event in append order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusEventRow {
    pub status_sequence: i64,
    pub status_event_id: String,
    pub component_kind: String,
    pub component_id: String,
    /// Exact originating run for canonical non-success collection results.
    pub run_id: Option<String>,
    pub state: String,
    pub code: String,
    pub detail_json: String,
    pub observed_at: String,
}

/// One immutable detector evaluation with its exact optional governed refusal
/// and optional finding-event copy, ordered by stable evaluation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationRefusalHistoryRow {
    pub evaluation_id: String,
    /// Store-wide append sequence. Unlike the opaque evaluation UUID, this is
    /// a monotone, gap-free cursor that cannot skip a concurrent later append.
    pub evaluation_sequence: i64,
    pub trigger_run_id: Option<String>,
    pub detector_id: String,
    pub detector_version: String,
    pub detector_digest: String,
    pub evaluator_artifact_digest: String,
    pub evaluation_revision: i64,
    pub started_at: String,
    pub evaluated_at: String,
    pub outcome: String,
    pub detail_json: Vec<u8>,
    pub evaluation_profile_id: String,
    pub evaluation_profile_version: String,
    pub evaluation_profile_digest: String,
    pub evaluation_profile_semantic_id: String,
    pub refusal_id: Option<String>,
    pub source_kind: Option<String>,
    pub responsible_instance_id: Option<String>,
    pub boundary: Option<String>,
    pub code: Option<String>,
    pub profile_id: Option<String>,
    pub profile_version: Option<String>,
    pub profile_digest: Option<String>,
    pub profile_semantic_id: Option<String>,
    pub refusal_detail_json: Option<Vec<u8>>,
    pub finding_event_id: Option<String>,
    pub finding_id: Option<String>,
    pub finding_event_revision: Option<i64>,
    pub finding_event_kind: Option<String>,
    pub finding_instance_id: Option<String>,
    pub finding_detector_id: Option<String>,
    pub finding_detector_version: Option<String>,
    pub finding_detector_digest: Option<String>,
    pub finding_evaluator_artifact_digest: Option<String>,
    pub finding_evaluation_revision: Option<i64>,
    pub finding_profile_id: Option<String>,
    pub finding_profile_version: Option<String>,
    pub finding_profile_digest: Option<String>,
    pub finding_subject_json: Option<Vec<u8>>,
    pub finding_condition_name: Option<String>,
    pub finding_condition_state: Option<String>,
    pub finding_visibility_state: Option<String>,
    pub finding_operator_work_state: Option<String>,
    pub finding_severity: Option<String>,
    pub finding_summary: Option<String>,
    pub finding_limitations_json: Option<Vec<u8>>,
    pub finding_safe_next_checks_json: Option<Vec<u8>>,
    pub finding_freshness_json: Option<Vec<u8>>,
    pub finding_basis_json: Option<Vec<u8>>,
    pub finding_origin_mode: Option<String>,
    pub finding_historical_refs_json: Option<Vec<u8>>,
    pub finding_observed_at: Option<String>,
    pub finding_received_at: Option<String>,
    pub finding_evaluated_at: Option<String>,
    pub finding_created_at: Option<String>,
    pub finding_refusal_json: Option<Vec<u8>>,
    pub prior_finding_event_id: Option<String>,
    pub prior_finding_event_kind: Option<String>,
    pub prior_finding_condition_state: Option<String>,
    pub prior_finding_subject_json: Option<Vec<u8>>,
    pub prior_finding_operator_work_state: Option<String>,
    pub prior_finding_severity: Option<String>,
    pub prior_finding_summary: Option<String>,
    /// Number of typed refusals linked to this evaluation. The history reader
    /// carries the count separately so a duplicate association cannot be
    /// hidden by a row limit on the joined representation.
    pub refusal_count: i64,
    /// Number of finding events linked to this evaluation. At most one is
    /// admissible, and the explicit count prevents a duplicate from being
    /// hidden by a bounded page.
    pub finding_event_count: i64,
    pub watermarks: Vec<EvaluationWatermarkHistoryRow>,
    pub finding_evidence: Vec<FindingEvidenceHistoryRow>,
    pub prior_finding_evidence: Vec<FindingEvidenceHistoryRow>,
}

/// Canonical finding-lineage fields used to reopen the state immediately
/// before a frozen evaluation-history cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationFindingLineage {
    pub instance_id: String,
    pub detector_id: String,
    pub detector_version: String,
    pub detector_digest: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub profile_semantic_id: String,
    pub subject_json: Vec<u8>,
    pub condition_name: String,
    pub basis_json: Vec<u8>,
}

/// Minimal immutable finding state needed to validate the next evaluation in
/// one canonical lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorEvaluationFindingRow {
    pub event_id: String,
    pub finding_id: String,
    pub event_revision: i64,
    pub condition_state: String,
}

/// One persisted evaluation watermark with the actual report reached by its
/// `(instance_id, max_report_sequence)` identity, when non-empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationWatermarkHistoryRow {
    pub instance_id: String,
    pub max_report_sequence: i64,
    pub watermark_received_at: Option<String>,
    pub report_received_at: Option<String>,
    pub report_observed_at: Option<String>,
    pub report_status: Option<String>,
    pub report_canonical_json: Option<Vec<u8>>,
    pub report_semantic_digest: Option<String>,
}

/// One finding-evidence row with the admitted report and observation facts
/// needed for exact semantic reopening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingEvidenceHistoryRow {
    pub ordinal: i64,
    pub report_id: String,
    pub report_semantic_digest: String,
    pub observation_ordinal: Option<i64>,
    pub observed_at: String,
    pub received_at: String,
    pub report_instance_id: String,
    pub report_sequence: i64,
    pub report_observed_at: String,
    pub report_received_at: String,
    pub observation_exists: bool,
    pub observation_observed_at: Option<String>,
}

/// Exact admitted report projections and the number of evaluations durably
/// linked to its originating collection run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedCollectionRow {
    pub run_id: String,
    pub instance_id: String,
    pub report_id: String,
    pub report_sequence: i64,
    pub report_status: String,
    pub semantic_digest: String,
    pub canonical_json: Vec<u8>,
    pub evaluations: i64,
}

/// Exact admitted report occurrence reached by a detector evidence reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedEvidenceReferenceRow {
    pub instance_id: String,
    pub report_sequence: i64,
    pub observed_at: String,
    pub received_at: String,
    pub observation_exists: bool,
    pub observation_observed_at: Option<String>,
    pub canonical_json: Vec<u8>,
}

/// An immutable status event followed by a rebuildable projection update.
#[derive(Clone, Debug)]
pub struct StatusEventInput {
    pub status_event_id: String,
    pub component_kind: String,
    pub component_id: String,
    pub state: String,
    pub code: String,
    pub detail: CanonicalDocument,
    pub observed_at: String,
}

/// Canonical non-success result committed in the same transaction as its run,
/// optional custody bytes, and mandatory typed refusal.
#[derive(Clone, Debug)]
pub struct RunResultStatusInput {
    /// Exact run created by the accompanying collection input.
    pub run_id: String,
    /// Instance status whose canonical detail carries that same run identity.
    pub status: StatusEventInput,
}

/// A durable notification request.
#[derive(Clone, Debug)]
pub struct NotificationInput {
    pub notification_id: String,
    pub idempotency_key: String,
    pub finding_event_id: Option<String>,
    pub destination_kind: String,
    pub payload: CanonicalDocument,
    pub available_at: String,
    pub max_attempts: u32,
    pub created_at: String,
}

/// One immutable delivery attempt.
#[derive(Clone, Debug)]
pub struct NotificationAttemptInput {
    pub notification_id: String,
    pub attempt_number: u32,
    pub attempted_at: String,
    pub outcome: String,
    pub delivery_identity: Option<String>,
    pub detail: CanonicalDocument,
}

/// A logical retention marker. It never rewrites the original evidence row.
#[derive(Clone, Debug)]
pub struct RetentionTombstoneInput {
    pub tombstone_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub target_digest: Option<String>,
    pub reason_code: String,
    pub detail: CanonicalDocument,
    pub created_at: String,
}

/// The fresh-store genesis record and optional frozen legacy-cut digest.
#[derive(Clone, Debug)]
pub struct GenesisInput {
    pub genesis_id: String,
    pub legacy_manifest_digest: Option<String>,
    pub created_at: String,
    pub detail: CanonicalDocument,
}

/// An immutable reference into frozen legacy custody.
#[derive(Clone, Debug)]
pub struct LegacyReferenceInput {
    pub legacy_reference_id: String,
    pub genesis_id: String,
    pub reference_uri: String,
    pub artifact_digest: Option<String>,
    pub detail: CanonicalDocument,
    pub created_at: String,
}

/// A successful or failed explicit administrative upgrade receipt.
#[derive(Clone, Debug)]
pub struct UpgradeReceiptInput {
    pub receipt_id: String,
    pub from_schema_version: u32,
    pub to_schema_version: u32,
    pub migrations: CanonicalDocument,
    pub binary_digest: String,
    pub backup_digest: String,
    pub backup_location: String,
    pub started_at: String,
    pub finished_at: String,
    pub result: String,
    pub operator_identity: CanonicalDocument,
    pub verification: CanonicalDocument,
}

/// A verified SQLite backup artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupArtifact {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Read-only semantic view of the transaction that is assembling one admitted
/// collection. The newly inserted report is visible here, while no partial
/// collection state is visible outside the transaction.
pub struct AdmittedCollectionView<'transaction, 'connection> {
    transaction: &'transaction Transaction<'connection>,
}

impl AdmittedCollectionView<'_, '_> {
    /// Read the exact evidence snapshot including the pending admitted report.
    pub fn evidence_snapshot(
        &self,
        instance_ids: &[String],
    ) -> Result<EvidenceSnapshot, StoreError> {
        evidence_snapshot_from_connection(self.transaction, instance_ids)
    }

    /// Read the current finding projection visible to the pending transaction.
    pub fn finding_snapshots(&self) -> Result<Vec<FindingSnapshotRow>, StoreError> {
        finding_snapshots_from_connection(self.transaction)
    }
}

impl Store {
    /// Create a consistent, verified backup without overwriting an existing path.
    pub fn backup_verified(
        &self,
        destination: impl AsRef<Path>,
    ) -> Result<BackupArtifact, StoreError> {
        self.validate()?;
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StoreError::Invariant(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?,
        );
        let result = (|| {
            let mut target =
                Connection::open_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            {
                let backup = rusqlite::backup::Backup::new(&self.connection, &mut target)?;
                backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
            }
            drop(target);

            // Opening through Store validates identity, schema, integrity, and public views.
            drop(Self::open(destination)?);
            let size_bytes = std::fs::metadata(destination)?.len();
            let sha256 = sha256_file(destination)?;
            Ok(BackupArtifact {
                path: destination.to_path_buf(),
                sha256,
                size_bytes,
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(destination);
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = destination.as_os_str().to_os_string();
                sidecar.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(sidecar));
            }
        }
        result
    }

    /// Create and semantically verify the mandatory pre-upgrade backup of the
    /// exact qualified schema-v3 store. This does not accept v1, v2, stale-v3,
    /// or current-v4 bytes under the upgrade-source identity.
    pub fn backup_v3_verified(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<BackupArtifact, StoreError> {
        let source_store = Self::open_v3_upgrade_source_read_only(source)?;
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StoreError::Invariant(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?,
        );
        let result = (|| {
            let mut target =
                Connection::open_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            {
                let backup = rusqlite::backup::Backup::new(&source_store.connection, &mut target)?;
                backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
            }
            drop(target);
            drop(Self::open_v3_upgrade_source_read_only(destination)?);
            Ok(BackupArtifact {
                path: destination.to_path_buf(),
                sha256: sha256_file(destination)?,
                size_bytes: std::fs::metadata(destination)?.len(),
            })
        })();
        if result.is_err() {
            remove_database_artifact(destination);
        }
        result
    }

    /// Create and verify the mandatory pre-upgrade backup of the exact
    /// qualified schema-v4 store.
    pub fn backup_v4_verified(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<BackupArtifact, StoreError> {
        let source_store = Self::open_v4_upgrade_source_read_only(source)?;
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StoreError::Invariant(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?,
        );
        let result = (|| {
            let mut target =
                Connection::open_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            {
                let backup = rusqlite::backup::Backup::new(&source_store.connection, &mut target)?;
                backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
            }
            drop(target);
            drop(Self::open_v4_upgrade_source_read_only(destination)?);
            Ok(BackupArtifact {
                path: destination.to_path_buf(),
                sha256: sha256_file(destination)?,
                size_bytes: std::fs::metadata(destination)?.len(),
            })
        })();
        if result.is_err() {
            remove_database_artifact(destination);
        }
        result
    }

    /// Create and verify the mandatory pre-upgrade backup of the exact
    /// qualified schema-v5 store.
    pub fn backup_v5_verified(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<BackupArtifact, StoreError> {
        let source_store = Self::open_v5_upgrade_source_read_only(source)?;
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StoreError::Invariant(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?,
        );
        let result = (|| {
            let mut target =
                Connection::open_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            {
                let backup = rusqlite::backup::Backup::new(&source_store.connection, &mut target)?;
                backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
            }
            drop(target);
            drop(Self::open_v5_upgrade_source_read_only(destination)?);
            Ok(BackupArtifact {
                path: destination.to_path_buf(),
                sha256: sha256_file(destination)?,
                size_bytes: std::fs::metadata(destination)?.len(),
            })
        })();
        if result.is_err() {
            remove_database_artifact(destination);
        }
        result
    }

    /// Create and verify the mandatory pre-upgrade backup of the exact
    /// qualified schema-v6 store.
    pub fn backup_v6_verified(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<BackupArtifact, StoreError> {
        let source_store = Self::open_v6_upgrade_source_read_only(source)?;
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StoreError::Invariant(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?,
        );
        let result = (|| {
            let mut target =
                Connection::open_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            {
                let backup = rusqlite::backup::Backup::new(&source_store.connection, &mut target)?;
                backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
            }
            drop(target);
            drop(Self::open_v6_upgrade_source_read_only(destination)?);
            Ok(BackupArtifact {
                path: destination.to_path_buf(),
                sha256: sha256_file(destination)?,
                size_bytes: std::fs::metadata(destination)?.len(),
            })
        })();
        if result.is_err() {
            remove_database_artifact(destination);
        }
        result
    }

    /// Explicitly migrate the exact qualified v0.1.0 schema-v3 store to v4.
    ///
    /// The caller must first create the verified backup named in `receipt`.
    /// Historical runs receive only an explicit limitation marker: the
    /// migration never synthesizes provider intake or acknowledgment evidence.
    #[allow(clippy::too_many_lines)]
    pub fn upgrade_v3_to_v4(
        path: impl AsRef<Path>,
        receipt: &UpgradeReceiptInput,
    ) -> Result<(), StoreError> {
        let path = path.as_ref();
        validate_v3_to_v4_receipt(receipt)?;
        let backup_path = Path::new(&receipt.backup_location);
        if !backup_path.is_file() || sha256_file(backup_path)? != receipt.backup_digest {
            return Err(StoreError::Invariant(
                "v3-to-v4 migration requires the exact verified backup named by its receipt".into(),
            ));
        }
        let source_metadata = std::fs::metadata(path)?;
        let backup_metadata = std::fs::metadata(backup_path)?;
        if std::fs::canonicalize(path)? == std::fs::canonicalize(backup_path)?
            || (source_metadata.dev(), source_metadata.ino())
                == (backup_metadata.dev(), backup_metadata.ino())
        {
            return Err(StoreError::Invariant(
                "v3-to-v4 migration backup must be distinct from the source database".into(),
            ));
        }
        let backup_store = Self::open_v3_upgrade_source_read_only(backup_path)?;
        let backup_logical_digest = v3_logical_state_digest(&backup_store.connection)?;
        let source_store = Self::open_v3_upgrade_source_read_only(path)?;
        let source_logical_digest = v3_logical_state_digest(&source_store.connection)?;
        if source_logical_digest != backup_logical_digest {
            return Err(StoreError::Invariant(format!(
                "v3-to-v4 migration backup logical state {backup_logical_digest} does not match source {source_logical_digest}"
            )));
        }
        drop(source_store);
        drop(backup_store);

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, false)?;
        let mut store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        store.validate_v3_upgrade_source()?;
        {
            let transaction = store.immediate_transaction()?;
            // The read-only preflight above provides an early diagnostic. This
            // second complete validation is authoritative: BEGIN IMMEDIATE now
            // prevents a writer from changing the v3 source between validation
            // and migration. Reopen and rehash the named backup here as well so
            // the receipt is bound to this exact locked logical source state.
            validate_v3_upgrade_source_connection(&transaction)?;
            if sha256_file(backup_path)? != receipt.backup_digest {
                return Err(StoreError::Invariant(
                    "v3-to-v4 migration backup changed after preflight validation".into(),
                ));
            }
            let locked_backup = Self::open_v3_upgrade_source_read_only(backup_path)?;
            let locked_backup_digest = v3_logical_state_digest(&locked_backup.connection)?;
            let locked_source_digest = v3_logical_state_digest(&transaction)?;
            if locked_source_digest != locked_backup_digest {
                return Err(StoreError::Invariant(format!(
                    "v3-to-v4 migration backup logical state {locked_backup_digest} does not match locked source {locked_source_digest}"
                )));
            }
            drop(locked_backup);
            transaction.execute_batch(
                "DROP TRIGGER immutable_schema_metadata_update;
                 DROP TRIGGER immutable_schema_metadata_delete;
                 ALTER TABLE schema_metadata RENAME TO schema_metadata_v3;",
            )?;
            transaction.execute_batch(SCHEMA_METADATA_V4)?;
            transaction.execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version, schema_artifact_digest, initialized_at
                 )
                 SELECT singleton, product, 4, ?1, initialized_at
                 FROM schema_metadata_v3",
                [SCHEMA_V4_ARTIFACT_DIGEST],
            )?;
            transaction.execute("DROP TABLE schema_metadata_v3", [])?;
            transaction.execute_batch(SCHEMA_METADATA_V4_TRIGGERS)?;
            transaction.execute_batch(SCHEMA_V3_TO_V4_PROVIDER)?;
            let migrated_at = now_utc();
            migrate_local_provider_admissions(&transaction, &migrated_at)?;

            let run_ids = {
                let mut statement =
                    transaction.prepare("SELECT run_id FROM watcher_runs ORDER BY run_id")?;
                statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let limitation = CanonicalDocument::from_serializable(&serde_json::json!({
                "schema": "nq.legacy_provider_intake_gap.v1",
                "source_schema_version": 3,
                "source_schema_artifact_digest": SCHEMA_V3_ARTIFACT_DIGEST,
                "limitation": "schema v3 did not preserve a versioned provider intake or exact outer raw capture for every acquisition",
                "provider_intake_synthesized": false,
                "acknowledgment_synthesized": false,
            }))?;
            for run_id in run_ids {
                transaction.execute(
                    "INSERT INTO legacy_v3_watcher_run_intake_gaps (
                        run_id, source_schema_version, source_schema_artifact_digest,
                        limitation_code, detail_json, migrated_at
                     ) VALUES (?1, 3, ?2, 'provider_intake_not_recorded', ?3, ?4)",
                    params![
                        run_id,
                        SCHEMA_V3_ARTIFACT_DIGEST,
                        limitation.as_bytes(),
                        migrated_at,
                    ],
                )?;
            }
            transaction.pragma_update(None, "user_version", 4)?;

            let expected = EXPECTED_SCHEMA_V4_FINGERPRINT.as_ref().map_err(|error| {
                StoreError::Integrity(format!(
                    "compiled v4 schema cannot be fingerprinted after migration: {error}"
                ))
            })?;
            let actual = schema_fingerprint(&transaction)?;
            if &actual != expected {
                return Err(StoreError::Integrity(format!(
                    "migrated v4 schema fingerprint {actual} differs from fresh v4 {expected}"
                )));
            }
            validate_stored_digests(&transaction)?;
            validate_upgrade_receipts(&transaction)?;
            validate_all_admission_context_digests(&transaction)?;
            validate_provider_intake_invariants(&transaction)?;
            validate_refusal_invariants(&transaction)?;
            validate_run_results(&transaction)?;
            validate_evaluation_refusal_invariants(&transaction)?;
            validate_status_sequence_lower_bound(&transaction)?;
            validate_projection_invariants(&transaction)?;
            let mut committed_receipt = receipt.clone();
            committed_receipt.finished_at = now_utc();
            insert_upgrade_receipt(&transaction, &committed_receipt)?;
            validate_upgrade_receipts(&transaction)?;
            validate_local_provider_admissions(&transaction)?;
            transaction.commit()?;
        }
        validate_v4_upgrade_source_connection(&store.connection)?;
        Ok(())
    }

    /// Explicitly migrate the exact qualified schema-v4 store to schema v5.
    ///
    /// No diagnostic artifact is synthesized from schema-v4 history. The
    /// absence of a durable pre-v5 artifact commitment remains distinct from a
    /// committed artifact whose bytes later became unavailable.
    #[allow(clippy::too_many_lines)]
    pub fn upgrade_v4_to_v5(
        path: impl AsRef<Path>,
        receipt: &UpgradeReceiptInput,
    ) -> Result<(), StoreError> {
        let path = path.as_ref();
        validate_v4_to_v5_receipt(receipt)?;
        let backup_path = Path::new(&receipt.backup_location);
        if !backup_path.is_file() || sha256_file(backup_path)? != receipt.backup_digest {
            return Err(StoreError::Invariant(
                "v4-to-v5 migration requires the exact verified backup named by its receipt".into(),
            ));
        }
        let source_metadata = std::fs::metadata(path)?;
        let backup_metadata = std::fs::metadata(backup_path)?;
        if std::fs::canonicalize(path)? == std::fs::canonicalize(backup_path)?
            || (source_metadata.dev(), source_metadata.ino())
                == (backup_metadata.dev(), backup_metadata.ino())
        {
            return Err(StoreError::Invariant(
                "v4-to-v5 migration backup must be distinct from the source database".into(),
            ));
        }
        let backup_store = Self::open_v4_upgrade_source_read_only(backup_path)?;
        let backup_logical_digest = v4_logical_state_digest(&backup_store.connection)?;
        let source_store = Self::open_v4_upgrade_source_read_only(path)?;
        let source_logical_digest = v4_logical_state_digest(&source_store.connection)?;
        if source_logical_digest != backup_logical_digest {
            return Err(StoreError::Invariant(format!(
                "v4-to-v5 migration backup logical state {backup_logical_digest} does not match source {source_logical_digest}"
            )));
        }
        drop(source_store);
        drop(backup_store);

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, false)?;
        let mut store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        validate_v4_upgrade_source_connection(&store.connection)?;
        {
            let transaction = store.immediate_transaction()?;
            validate_v4_upgrade_source_connection(&transaction)?;
            if sha256_file(backup_path)? != receipt.backup_digest {
                return Err(StoreError::Invariant(
                    "v4-to-v5 migration backup changed after preflight validation".into(),
                ));
            }
            let locked_backup = Self::open_v4_upgrade_source_read_only(backup_path)?;
            let locked_backup_digest = v4_logical_state_digest(&locked_backup.connection)?;
            let locked_source_digest = v4_logical_state_digest(&transaction)?;
            if locked_source_digest != locked_backup_digest {
                return Err(StoreError::Invariant(format!(
                    "v4-to-v5 migration backup logical state {locked_backup_digest} does not match locked source {locked_source_digest}"
                )));
            }
            drop(locked_backup);

            transaction.execute_batch(
                "DROP TRIGGER immutable_schema_metadata_update;
                 DROP TRIGGER immutable_schema_metadata_delete;
                 ALTER TABLE schema_metadata RENAME TO schema_metadata_v4;",
            )?;
            transaction.execute_batch(SCHEMA_METADATA_V5)?;
            transaction.execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version, schema_artifact_digest, initialized_at
                 )
                 SELECT singleton, product, 5, ?1, initialized_at
                 FROM schema_metadata_v4",
                [SCHEMA_V5_ARTIFACT_DIGEST],
            )?;
            transaction.execute("DROP TABLE schema_metadata_v4", [])?;
            transaction.execute_batch(SCHEMA_METADATA_V5_TRIGGERS)?;
            transaction.execute_batch(SCHEMA_V4_TO_V5_DIAGNOSTIC_ARTIFACTS)?;
            transaction.pragma_update(None, "user_version", 5)?;

            let expected = EXPECTED_SCHEMA_V5_FINGERPRINT.as_ref().map_err(|error| {
                StoreError::Integrity(format!(
                    "compiled v5 schema cannot be fingerprinted after migration: {error}"
                ))
            })?;
            let actual = schema_fingerprint(&transaction)?;
            if &actual != expected {
                return Err(StoreError::Integrity(format!(
                    "migrated v5 schema fingerprint {actual} differs from exact v5 {expected}"
                )));
            }
            validate_stored_digests(&transaction)?;
            validate_upgrade_receipts(&transaction)?;
            validate_all_admission_context_digests(&transaction)?;
            validate_local_provider_admissions(&transaction)?;
            validate_provider_intake_invariants(&transaction)?;
            validate_refusal_invariants(&transaction)?;
            validate_run_results(&transaction)?;
            validate_evaluation_refusal_invariants(&transaction)?;
            validate_diagnostic_artifact_invariants(&transaction)?;
            validate_status_sequence_lower_bound(&transaction)?;
            validate_projection_invariants(&transaction)?;
            let mut committed_receipt = receipt.clone();
            committed_receipt.finished_at = now_utc();
            insert_upgrade_receipt(&transaction, &committed_receipt)?;
            validate_upgrade_receipts(&transaction)?;
            transaction.commit()?;
        }
        validate_v5_upgrade_source_connection(&store.connection)?;
        Ok(())
    }

    /// Explicitly migrate the exact qualified schema-v5 store to schema v6.
    ///
    /// Existing diagnostic artifacts retain an explicit null production
    /// execution binding. No runtime record, checkpoint, or V2 production
    /// closure is synthesized from pre-v6 history.
    #[allow(clippy::too_many_lines)]
    pub fn upgrade_v5_to_v6(
        path: impl AsRef<Path>,
        receipt: &UpgradeReceiptInput,
    ) -> Result<(), StoreError> {
        let path = path.as_ref();
        validate_v5_to_v6_receipt(receipt)?;
        let backup_path = Path::new(&receipt.backup_location);
        if !backup_path.is_file() || sha256_file(backup_path)? != receipt.backup_digest {
            return Err(StoreError::Invariant(
                "v5-to-v6 migration requires the exact verified backup named by its receipt".into(),
            ));
        }
        let source_metadata = std::fs::metadata(path)?;
        let backup_metadata = std::fs::metadata(backup_path)?;
        if std::fs::canonicalize(path)? == std::fs::canonicalize(backup_path)?
            || (source_metadata.dev(), source_metadata.ino())
                == (backup_metadata.dev(), backup_metadata.ino())
        {
            return Err(StoreError::Invariant(
                "v5-to-v6 migration backup must be distinct from the source database".into(),
            ));
        }
        let backup_store = Self::open_v5_upgrade_source_read_only(backup_path)?;
        let backup_logical_digest = v5_logical_state_digest(&backup_store.connection)?;
        let source_store = Self::open_v5_upgrade_source_read_only(path)?;
        let source_logical_digest = v5_logical_state_digest(&source_store.connection)?;
        if source_logical_digest != backup_logical_digest {
            return Err(StoreError::Invariant(format!(
                "v5-to-v6 migration backup logical state {backup_logical_digest} does not match source {source_logical_digest}"
            )));
        }
        drop(source_store);
        drop(backup_store);

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, false)?;
        let mut store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        validate_v5_upgrade_source_connection(&store.connection)?;
        {
            let transaction = store.immediate_transaction()?;
            validate_v5_upgrade_source_connection(&transaction)?;
            if sha256_file(backup_path)? != receipt.backup_digest {
                return Err(StoreError::Invariant(
                    "v5-to-v6 migration backup changed after preflight validation".into(),
                ));
            }
            let locked_backup = Self::open_v5_upgrade_source_read_only(backup_path)?;
            let locked_backup_digest = v5_logical_state_digest(&locked_backup.connection)?;
            let locked_source_digest = v5_logical_state_digest(&transaction)?;
            if locked_source_digest != locked_backup_digest {
                return Err(StoreError::Invariant(format!(
                    "v5-to-v6 migration backup logical state {locked_backup_digest} does not match locked source {locked_source_digest}"
                )));
            }
            drop(locked_backup);

            transaction.execute_batch(
                "DROP TRIGGER immutable_schema_metadata_update;
                 DROP TRIGGER immutable_schema_metadata_delete;
                 ALTER TABLE schema_metadata RENAME TO schema_metadata_v5;",
            )?;
            transaction.execute_batch(SCHEMA_METADATA_V6)?;
            transaction.execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version, schema_artifact_digest, initialized_at
                 )
                SELECT singleton, product, 6, ?1, initialized_at
                 FROM schema_metadata_v5",
                [SCHEMA_V6_ARTIFACT_DIGEST],
            )?;
            transaction.execute("DROP TABLE schema_metadata_v5", [])?;
            transaction.execute_batch(SCHEMA_METADATA_V6_TRIGGERS)?;
            transaction.execute_batch(SCHEMA_V5_TO_V6_RUNTIME_LEDGER)?;
            transaction.pragma_update(None, "user_version", 6)?;

            let expected = EXPECTED_SCHEMA_V6_FINGERPRINT.as_ref().map_err(|error| {
                StoreError::Integrity(format!(
                    "compiled schema-v6 cannot be fingerprinted after migration: {error}"
                ))
            })?;
            let actual = schema_fingerprint(&transaction)?;
            if &actual != expected {
                return Err(StoreError::Integrity(format!(
                    "migrated v6 schema fingerprint {actual} differs from exact v6 {expected}"
                )));
            }
            validate_stored_digests(&transaction)?;
            validate_upgrade_receipts(&transaction)?;
            validate_all_admission_context_digests(&transaction)?;
            validate_local_provider_admissions(&transaction)?;
            validate_provider_intake_invariants(&transaction)?;
            validate_refusal_invariants(&transaction)?;
            validate_run_results(&transaction)?;
            validate_evaluation_refusal_invariants(&transaction)?;
            validate_diagnostic_artifact_invariants(&transaction)?;
            validate_runtime_record_ledger(&transaction)?;
            validate_status_sequence_lower_bound(&transaction)?;
            validate_projection_invariants(&transaction)?;
            let mut committed_receipt = receipt.clone();
            committed_receipt.finished_at = now_utc();
            insert_upgrade_receipt(&transaction, &committed_receipt)?;
            validate_upgrade_receipts(&transaction)?;
            transaction.commit()?;
        }
        validate_v6_upgrade_source_connection(&store.connection)?;
        Ok(())
    }

    /// Explicitly migrate the exact qualified schema-v6 store to schema v7.
    ///
    /// Existing runtime checkpoints are classified as `legacy_unbound` and
    /// retain their exact schema-v6 batch identities. The migration does not
    /// synthesize a dependency generation, trust anchor, or authenticated
    /// provenance for historical checkpoints.
    #[allow(clippy::too_many_lines)]
    pub fn upgrade_v6_to_v7(
        path: impl AsRef<Path>,
        receipt: &UpgradeReceiptInput,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        validate_v6_to_v7_receipt(receipt)?;
        let backup_path = Path::new(&receipt.backup_location);
        if !backup_path.is_file() || sha256_file(backup_path)? != receipt.backup_digest {
            return Err(StoreError::Invariant(
                "v6-to-v7 migration requires the exact verified backup named by its receipt".into(),
            ));
        }
        let source_metadata = std::fs::metadata(path)?;
        let backup_metadata = std::fs::metadata(backup_path)?;
        if std::fs::canonicalize(path)? == std::fs::canonicalize(backup_path)?
            || (source_metadata.dev(), source_metadata.ino())
                == (backup_metadata.dev(), backup_metadata.ino())
        {
            return Err(StoreError::Invariant(
                "v6-to-v7 migration backup must be distinct from the source database".into(),
            ));
        }
        let backup_store = Self::open_v6_upgrade_source_read_only(backup_path)?;
        let backup_logical_digest = v6_logical_state_digest(&backup_store.connection)?;
        let source_store = Self::open_v6_upgrade_source_read_only(path)?;
        let source_logical_digest = v6_logical_state_digest(&source_store.connection)?;
        if source_logical_digest != backup_logical_digest {
            return Err(StoreError::Invariant(format!(
                "v6-to-v7 migration backup logical state {backup_logical_digest} does not match source {source_logical_digest}"
            )));
        }
        drop(source_store);
        drop(backup_store);

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, false)?;
        let mut store = Self {
            connection,
            path: Some(path.to_path_buf()),
        };
        validate_v6_upgrade_source_connection(&store.connection)?;
        {
            let transaction = store.immediate_transaction()?;
            validate_v6_upgrade_source_connection(&transaction)?;
            if sha256_file(backup_path)? != receipt.backup_digest {
                return Err(StoreError::Invariant(
                    "v6-to-v7 migration backup changed after preflight validation".into(),
                ));
            }
            let locked_backup = Self::open_v6_upgrade_source_read_only(backup_path)?;
            let locked_backup_digest = v6_logical_state_digest(&locked_backup.connection)?;
            let locked_source_digest = v6_logical_state_digest(&transaction)?;
            if locked_source_digest != locked_backup_digest {
                return Err(StoreError::Invariant(format!(
                    "v6-to-v7 migration backup logical state {locked_backup_digest} does not match locked source {locked_source_digest}"
                )));
            }
            drop(locked_backup);

            let legacy_frontier = runtime_ledger_checkpoint_on_connection(&transaction)?;
            let legacy_count = legacy_frontier.as_ref().map_or(Ok(0_i64), |checkpoint| {
                i64::try_from(checkpoint.checkpoint_sequence).map_err(|_| {
                    StoreError::Integrity(
                        "schema-v6 checkpoint sequence exceeds migration capacity".into(),
                    )
                })
            })?;
            transaction.execute_batch(
                "DROP TRIGGER immutable_schema_metadata_update;
                 DROP TRIGGER immutable_schema_metadata_delete;
                 ALTER TABLE schema_metadata RENAME TO schema_metadata_v6;",
            )?;
            transaction.execute_batch(SCHEMA_METADATA_V7)?;
            transaction.execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version, schema_artifact_digest, initialized_at
                 )
                 SELECT singleton, product, 7, ?1, initialized_at
                 FROM schema_metadata_v6",
                [schema_artifact_digest()],
            )?;
            transaction.execute("DROP TABLE schema_metadata_v6", [])?;
            transaction.execute_batch(SCHEMA_METADATA_V7_TRIGGERS)?;
            transaction.execute_batch(SCHEMA_V6_TO_V7_RUNTIME_DEPENDENCIES)?;
            let classified_at = now_utc();
            transaction.execute(
                "INSERT INTO runtime_dependency_binding_migration_boundaries (
                    singleton, source_schema_version, source_schema_artifact_digest,
                    legacy_checkpoint_count, legacy_last_checkpoint_id,
                    legacy_last_checkpoint_root, classified_at
                 ) VALUES (1, 6, ?1, ?2, ?3, ?4, ?5)",
                params![
                    SCHEMA_V6_ARTIFACT_DIGEST,
                    legacy_count,
                    legacy_frontier
                        .as_ref()
                        .map(|checkpoint| checkpoint.checkpoint_id.as_str()),
                    legacy_frontier
                        .as_ref()
                        .map(|checkpoint| checkpoint.checkpoint_ledger_root.as_str()),
                    classified_at,
                ],
            )?;
            transaction.execute(
                "INSERT INTO runtime_checkpoint_dependency_bindings (
                    checkpoint_id, binding_state, dependency_generation_id,
                    trust_anchor_id, canonical_bytes_sha256, source_schema_version
                 )
                 SELECT checkpoint_id, 'legacy_unbound', NULL, NULL, NULL, 6
                 FROM runtime_record_checkpoints
                 ORDER BY checkpoint_sequence",
                [],
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;

            let expected = EXPECTED_SCHEMA_FINGERPRINT.as_ref().map_err(|error| {
                StoreError::Integrity(format!(
                    "compiled schema cannot be fingerprinted after migration: {error}"
                ))
            })?;
            let actual = schema_fingerprint(&transaction)?;
            if &actual != expected {
                return Err(StoreError::Integrity(format!(
                    "migrated v7 schema fingerprint {actual} differs from fresh v7 {expected}"
                )));
            }
            validate_stored_digests(&transaction)?;
            validate_upgrade_receipts(&transaction)?;
            validate_all_admission_context_digests(&transaction)?;
            validate_local_provider_admissions(&transaction)?;
            validate_provider_intake_invariants(&transaction)?;
            validate_refusal_invariants(&transaction)?;
            validate_run_results(&transaction)?;
            validate_evaluation_refusal_invariants(&transaction)?;
            validate_diagnostic_artifact_invariants(&transaction)?;
            validate_runtime_record_ledger(&transaction)?;
            validate_status_sequence_lower_bound(&transaction)?;
            validate_projection_invariants(&transaction)?;
            let mut committed_receipt = receipt.clone();
            committed_receipt.finished_at = now_utc();
            insert_upgrade_receipt(&transaction, &committed_receipt)?;
            validate_upgrade_receipts(&transaction)?;
            transaction.commit()?;
        }
        store.validate()?;
        configure_connection(&store.connection, true)?;
        Ok(store)
    }

    /// Create a consistent, verified backup of a database file that `open`
    /// refuses (incompatible schema, stale candidate) — so an operator can
    /// preserve it before recreation. A backup must be possible *before* a
    /// refusal, never gated behind passing validation. The source is opened
    /// read-only with no schema/identity checks; the copy is verified only for
    /// SQLite-level integrity (`quick_check`), not schema currency, and hashed.
    pub fn backup_incompatible(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<BackupArtifact, StoreError> {
        let source = source.as_ref();
        if !source.is_file() || std::fs::metadata(source)?.len() == 0 {
            return Err(StoreError::NotInitialized(source.to_path_buf()));
        }
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StoreError::Invariant(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?,
        );
        let result = (|| {
            let source_connection = Connection::open_with_flags(
                source,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            let mut target =
                Connection::open_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            {
                let backup = rusqlite::backup::Backup::new(&source_connection, &mut target)?;
                backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
            }
            // Prove the copy is a structurally intact SQLite database, WITHOUT
            // asserting schema currency — preserving an incompatible one is the
            // whole point.
            let quick_check: String =
                target.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
            if quick_check != "ok" {
                return Err(StoreError::Integrity(format!(
                    "backup integrity: {quick_check}"
                )));
            }
            drop(target);
            let size_bytes = std::fs::metadata(destination)?.len();
            let sha256 = sha256_file(destination)?;
            Ok(BackupArtifact {
                path: destination.to_path_buf(),
                sha256,
                size_bytes,
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(destination);
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = destination.as_os_str().to_os_string();
                sidecar.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(sidecar));
            }
        }
        result
    }

    /// Read canonical admitted reports under one consistent SQLite snapshot.
    pub fn evidence_snapshot(
        &mut self,
        instance_ids: &[String],
    ) -> Result<EvidenceSnapshot, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let snapshot = evidence_snapshot_from_connection(&transaction, instance_ids)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Return the newest durably acknowledged non-null checkpoint for one
    /// instance. Rejected submissions, uncommitted reports, and migrated v3
    /// reports lacking a real provider-intake acknowledgment can never advance
    /// the live cursor.
    pub fn latest_checkpoint(
        &self,
        instance_id: &str,
        checkpoint_contract_digest: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        validate_digest("checkpoint_contract_digest", checkpoint_contract_digest)?;
        self.connection
            .query_row(
                "SELECT report.next_checkpoint_json
                 FROM admitted_reports AS report
                 JOIN raw_submissions AS submission
                   ON submission.submission_id = report.submission_id
                 JOIN watcher_runs AS run ON run.run_id = submission.run_id
                 JOIN local_watcher_provider_intakes AS local
                   ON local.run_id = run.run_id
                 JOIN provider_intake_acknowledgments AS acknowledgment
                   ON acknowledgment.intake_id = local.intake_id
                  AND acknowledgment.run_id = run.run_id
                 WHERE report.instance_id = ?1
                   AND report.next_checkpoint_json IS NOT NULL
                   AND run.checkpoint_contract_digest = ?2
                 ORDER BY report.report_sequence DESC LIMIT 1",
                params![instance_id, checkpoint_contract_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Commit an evaluation, its consistent watermark, optional refusal, and finding event.
    #[allow(clippy::too_many_lines)]
    pub fn commit_evaluation(
        &mut self,
        evaluation: &EvaluationInput,
        finding: Option<&FindingEventInput>,
    ) -> Result<EvaluationReceipt, StoreError> {
        if evaluation.trigger_run_id.is_some() {
            return Err(StoreError::Invariant(
                "run-triggered evaluation requires atomic admitted completion".into(),
            ));
        }
        let transaction = self.immediate_transaction()?;
        let receipt = insert_evaluation(&transaction, evaluation, finding)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Read the complete stable finding projection in opaque finding-id order.
    pub fn finding_snapshots(&self) -> Result<Vec<FindingSnapshotRow>, StoreError> {
        finding_snapshots_from_connection(&self.connection)
    }

    /// Read one bounded page of finding snapshots after an opaque finding-id cursor.
    pub fn finding_snapshots_bounded(
        &self,
        limit: u32,
        after_finding_id: Option<&str>,
    ) -> Result<Vec<FindingSnapshotRow>, StoreError> {
        validate_public_limit(limit)?;
        let mut statement = self.connection.prepare(
            "SELECT finding_id, instance_id, detector_id, detector_version,
                    detector_digest, evaluation_revision, profile_id, profile_version,
                    profile_digest, profile_semantic_id, subject_json, condition_name,
                    condition_state, visibility_state,
                    operator_work_state, severity, summary, limitations_json,
                    safe_next_checks_json, freshness_json, basis_json, refusal_json,
                    origin_mode, historical_refs_json, observed_at, received_at,
                    evaluated_at, evaluation_id, evaluation_refusal_json, evidence_json
             FROM public_finding_snapshot_v3
             WHERE ?1 IS NULL OR finding_id > ?1
             ORDER BY finding_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_finding_id, limit], |row| {
            Ok(FindingSnapshotRow {
                finding_id: row.get(0)?,
                instance_id: row.get(1)?,
                detector_id: row.get(2)?,
                detector_version: row.get(3)?,
                detector_digest: row.get(4)?,
                evaluation_revision: row.get(5)?,
                profile_id: row.get(6)?,
                profile_version: row.get(7)?,
                profile_digest: row.get(8)?,
                profile_semantic_id: row.get(9)?,
                subject_json: row.get(10)?,
                condition_name: row.get(11)?,
                condition_state: row.get(12)?,
                visibility_state: row.get(13)?,
                operator_work_state: row.get(14)?,
                severity: row.get(15)?,
                summary: row.get(16)?,
                limitations_json: row.get(17)?,
                safe_next_checks_json: row.get(18)?,
                freshness_json: row.get(19)?,
                basis_json: row.get(20)?,
                refusal_json: row.get(21)?,
                origin_mode: row.get(22)?,
                historical_refs_json: row.get(23)?,
                observed_at: row.get(24)?,
                received_at: row.get(25)?,
                evaluated_at: row.get(26)?,
                evaluation_id: row.get(27)?,
                evaluation_refusal_json: row.get(28)?,
                evidence_json: row.get(29)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Append a status event and atomically advance only its rebuildable pointer.
    pub fn record_status(&mut self, status: &StatusEventInput) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        insert_status_event(&transaction, status, None)?;
        transaction.commit()?;
        Ok(())
    }

    /// Read the stable status projection in component order.
    pub fn status_snapshots(&self) -> Result<Vec<StatusSnapshotRow>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT component_kind, component_id, state, code, detail_json, observed_at
             FROM public_status_snapshot_v1 ORDER BY component_kind, component_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(StatusSnapshotRow {
                component_kind: row.get(0)?,
                component_id: row.get(1)?,
                state: row.get(2)?,
                code: row.get(3)?,
                detail_json: row.get(4)?,
                observed_at: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Return the highest committed immutable status-event sequence.
    pub fn latest_status_sequence(&self) -> Result<i64, StoreError> {
        validate_status_sequence_lower_bound(&self.connection)?;
        self.connection
            .query_row(
                "SELECT COALESCE(MAX(status_sequence), 0) FROM status_events",
                [],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    /// Read one bounded status page after a `(component_kind, component_id)` cursor.
    pub fn status_snapshots_bounded(
        &self,
        limit: u32,
        after_component: Option<(&str, &str)>,
    ) -> Result<Vec<StatusSnapshotRow>, StoreError> {
        validate_public_limit(limit)?;
        let (after_kind, after_id) =
            after_component.map_or((None, None), |(kind, id)| (Some(kind), Some(id)));
        let mut statement = self.connection.prepare(
            "SELECT component_kind, component_id, state, code, detail_json, observed_at
             FROM public_status_snapshot_v1
             WHERE ?1 IS NULL
                OR component_kind > ?1
                OR (component_kind = ?1 AND component_id > ?2)
             ORDER BY component_kind, component_id LIMIT ?3",
        )?;
        let rows = statement.query_map(params![after_kind, after_id, limit], |row| {
            Ok(StatusSnapshotRow {
                component_kind: row.get(0)?,
                component_id: row.get(1)?,
                state: row.get(2)?,
                code: row.get(3)?,
                detail_json: row.get(4)?,
                observed_at: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Read one bounded page of current NQ-owned status after a component
    /// cursor.
    ///
    /// The historical store vocabulary still admits `scheduler` and
    /// `notification` so immutable old rows can be verified. They are excluded
    /// in SQL before applying the caller's limit, preventing a saturated
    /// legacy prefix from hiding a current NQ-owned component.
    pub fn current_status_snapshots_bounded(
        &self,
        limit: u32,
        after_component: Option<(&str, &str)>,
    ) -> Result<Vec<StatusSnapshotRow>, StoreError> {
        validate_public_limit(limit)?;
        let (after_kind, after_id) =
            after_component.map_or((None, None), |(kind, id)| (Some(kind), Some(id)));
        let mut statement = self.connection.prepare(
            "SELECT component_kind, component_id, state, code, detail_json, observed_at
             FROM public_status_snapshot_v1
             WHERE component_kind NOT IN ('scheduler', 'notification')
               AND (
                   ?1 IS NULL
                   OR component_kind > ?1
                   OR (component_kind = ?1 AND component_id > ?2)
               )
             ORDER BY component_kind, component_id LIMIT ?3",
        )?;
        let rows = statement.query_map(params![after_kind, after_id, limit], |row| {
            Ok(StatusSnapshotRow {
                component_kind: row.get(0)?,
                component_id: row.get(1)?,
                state: row.get(2)?,
                code: row.get(3)?,
                detail_json: row.get(4)?,
                observed_at: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Read one bounded page of immutable status history after a sequence.
    ///
    /// This is the semantic-reopen path for archives. It reads source events,
    /// not the rebuildable current projection, so an older unversioned result
    /// cannot be hidden by a newer row for the same component.
    pub fn status_history_bounded(
        &self,
        limit: u32,
        after_sequence: Option<i64>,
    ) -> Result<Vec<StatusEventRow>, StoreError> {
        validate_public_limit(limit)?;
        validate_status_sequence_lower_bound(&self.connection)?;
        if after_sequence.is_some_and(|sequence| sequence < 0) {
            return Err(StoreError::Invariant(
                "status history cursor cannot be negative".into(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT status_sequence, status_event_id, component_kind,
                    component_id, run_id, state, code,
                    CAST(detail_json AS TEXT), observed_at
             FROM status_events
             WHERE status_sequence > COALESCE(?1, 0)
             ORDER BY status_sequence
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_sequence, limit], |row| {
            Ok(StatusEventRow {
                status_sequence: row.get(0)?,
                status_event_id: row.get(1)?,
                component_kind: row.get(2)?,
                component_id: row.get(3)?,
                run_id: row.get(4)?,
                state: row.get(5)?,
                code: row.get(6)?,
                detail_json: row.get(7)?,
                observed_at: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Prove every completed admitted or non-success watcher run has exactly
    /// one atomically linked canonical instance result.
    pub fn validate_run_results(&self) -> Result<(), StoreError> {
        validate_run_results(&self.connection)
    }

    /// Return the highest committed store-wide evaluation sequence.
    pub fn latest_evaluation_sequence(&self) -> Result<i64, StoreError> {
        validate_evaluation_revision_shape(&self.connection)?;
        self.connection
            .query_row(
                "SELECT COALESCE(MAX(evaluation_sequence), 0) FROM evaluation_runs",
                [],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    /// Reopen one exact evaluation origin without scanning bounded history.
    pub fn evaluation_origin(
        &self,
        evaluation_id: &str,
    ) -> Result<Option<EvaluationOriginRow>, StoreError> {
        self.connection
            .query_row(
                "SELECT evaluation_id, evaluation_sequence, trigger_run_id
                 FROM evaluation_runs WHERE evaluation_id = ?1",
                [evaluation_id],
                |row| {
                    Ok(EvaluationOriginRow {
                        evaluation_id: row.get(0)?,
                        evaluation_sequence: row.get(1)?,
                        trigger_run_id: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Read one bounded immutable page of evaluations with exact refusal and
    /// finding-event associations. Both bounds use the stable store-wide
    /// append sequence, so later inserts cannot fall behind a returned cursor.
    #[allow(clippy::too_many_lines)]
    pub fn evaluation_refusal_history_bounded(
        &self,
        limit: u32,
        after_evaluation_sequence: Option<i64>,
        through_evaluation_sequence: i64,
    ) -> Result<Vec<EvaluationRefusalHistoryRow>, StoreError> {
        validate_public_limit(limit)?;
        if after_evaluation_sequence.is_some_and(|sequence| sequence < 0) {
            return Err(StoreError::Invariant(
                "evaluation history cursor cannot be negative".into(),
            ));
        }
        if through_evaluation_sequence < 0
            || after_evaluation_sequence
                .is_some_and(|sequence| sequence > through_evaluation_sequence)
        {
            return Err(StoreError::Invariant(
                "evaluation history snapshot bound is invalid".into(),
            ));
        }
        validate_evaluation_revision_shape(&self.connection)?;
        let mut statement = self.connection.prepare(
            "SELECT evaluation.evaluation_id, evaluation.trigger_run_id,
                    evaluation.detector_id, evaluation.detector_version,
                    evaluation.detector_digest, evaluation.evaluator_artifact_digest,
                    evaluation.evaluation_revision, evaluation.started_at,
                    evaluation.evaluated_at, evaluation.outcome,
                    evaluation.detail_json, evaluation.profile_id,
                    evaluation.profile_version, evaluation.profile_digest,
                    evaluation.profile_semantic_id, refusal.refusal_id,
                    refusal.source_kind, refusal.responsible_instance_id,
                    refusal.boundary, refusal.code, refusal.profile_id,
                    refusal.profile_version, refusal.profile_digest,
                    refusal.profile_semantic_id, refusal.detail_json,
                    finding.event_id, finding.finding_id, finding.event_revision,
                    finding.event_kind, finding.instance_id, finding.detector_id,
                    finding.detector_version, finding.detector_digest,
                    finding.evaluator_artifact_digest, finding.evaluation_revision,
                    finding.profile_id, finding.profile_version,
                    finding.profile_digest, finding.subject_json,
                    finding.condition_name, finding.condition_state,
                    finding.visibility_state, finding.operator_work_state,
                    finding.severity, finding.summary, finding.limitations_json,
                    finding.safe_next_checks_json, finding.freshness_json,
                    finding.basis_json, finding.origin_mode,
                    finding.historical_refs_json, finding.observed_at,
                    finding.received_at, finding.evaluated_at, finding.created_at,
                    finding.refusal_json, prior.event_id, prior.event_kind,
                    prior.condition_state, prior.subject_json,
                    prior.operator_work_state, prior.severity, prior.summary,
                    evaluation.evaluation_sequence,
                    (SELECT COUNT(*) FROM refusals AS linked_refusal
                     WHERE linked_refusal.evaluation_id = evaluation.evaluation_id),
                    (SELECT COUNT(*) FROM finding_events AS linked_finding
                     WHERE linked_finding.evaluation_id = evaluation.evaluation_id)
             FROM evaluation_runs AS evaluation
             LEFT JOIN refusals AS refusal
               ON refusal.evaluation_id = evaluation.evaluation_id
             LEFT JOIN finding_events AS finding
               ON finding.evaluation_id = evaluation.evaluation_id
             LEFT JOIN finding_events AS prior
               ON prior.finding_id = finding.finding_id
              AND prior.event_revision = finding.event_revision - 1
             WHERE evaluation.evaluation_sequence > COALESCE(?1, 0)
               AND evaluation.evaluation_sequence <= ?2
             ORDER BY evaluation.evaluation_sequence
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                after_evaluation_sequence,
                through_evaluation_sequence,
                limit
            ],
            |row| {
                Ok(EvaluationRefusalHistoryRow {
                    evaluation_id: row.get(0)?,
                    evaluation_sequence: row.get(63)?,
                    trigger_run_id: row.get(1)?,
                    detector_id: row.get(2)?,
                    detector_version: row.get(3)?,
                    detector_digest: row.get(4)?,
                    evaluator_artifact_digest: row.get(5)?,
                    evaluation_revision: row.get(6)?,
                    started_at: row.get(7)?,
                    evaluated_at: row.get(8)?,
                    outcome: row.get(9)?,
                    detail_json: row.get(10)?,
                    evaluation_profile_id: row.get(11)?,
                    evaluation_profile_version: row.get(12)?,
                    evaluation_profile_digest: row.get(13)?,
                    evaluation_profile_semantic_id: row.get(14)?,
                    refusal_id: row.get(15)?,
                    source_kind: row.get(16)?,
                    responsible_instance_id: row.get(17)?,
                    boundary: row.get(18)?,
                    code: row.get(19)?,
                    profile_id: row.get(20)?,
                    profile_version: row.get(21)?,
                    profile_digest: row.get(22)?,
                    profile_semantic_id: row.get(23)?,
                    refusal_detail_json: row.get(24)?,
                    finding_event_id: row.get(25)?,
                    finding_id: row.get(26)?,
                    finding_event_revision: row.get(27)?,
                    finding_event_kind: row.get(28)?,
                    finding_instance_id: row.get(29)?,
                    finding_detector_id: row.get(30)?,
                    finding_detector_version: row.get(31)?,
                    finding_detector_digest: row.get(32)?,
                    finding_evaluator_artifact_digest: row.get(33)?,
                    finding_evaluation_revision: row.get(34)?,
                    finding_profile_id: row.get(35)?,
                    finding_profile_version: row.get(36)?,
                    finding_profile_digest: row.get(37)?,
                    finding_subject_json: row.get(38)?,
                    finding_condition_name: row.get(39)?,
                    finding_condition_state: row.get(40)?,
                    finding_visibility_state: row.get(41)?,
                    finding_operator_work_state: row.get(42)?,
                    finding_severity: row.get(43)?,
                    finding_summary: row.get(44)?,
                    finding_limitations_json: row.get(45)?,
                    finding_safe_next_checks_json: row.get(46)?,
                    finding_freshness_json: row.get(47)?,
                    finding_basis_json: row.get(48)?,
                    finding_origin_mode: row.get(49)?,
                    finding_historical_refs_json: row.get(50)?,
                    finding_observed_at: row.get(51)?,
                    finding_received_at: row.get(52)?,
                    finding_evaluated_at: row.get(53)?,
                    finding_created_at: row.get(54)?,
                    finding_refusal_json: row.get(55)?,
                    prior_finding_event_id: row.get(56)?,
                    prior_finding_event_kind: row.get(57)?,
                    prior_finding_condition_state: row.get(58)?,
                    prior_finding_subject_json: row.get(59)?,
                    prior_finding_operator_work_state: row.get(60)?,
                    prior_finding_severity: row.get(61)?,
                    prior_finding_summary: row.get(62)?,
                    refusal_count: row.get(64)?,
                    finding_event_count: row.get(65)?,
                    watermarks: Vec::new(),
                    finding_evidence: Vec::new(),
                    prior_finding_evidence: Vec::new(),
                })
            },
        )?;
        let mut rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for row in &mut rows {
            let mut watermarks = self.connection.prepare(
                "SELECT watermark.instance_id, watermark.max_report_sequence,
                        watermark.watermark_received_at, report.received_at,
                        report.observed_at, report.report_status, report.canonical_json,
                        report.semantic_digest
                 FROM evaluation_watermarks AS watermark
                 LEFT JOIN admitted_reports AS report
                   ON report.instance_id = watermark.instance_id
                  AND report.report_sequence = watermark.max_report_sequence
                 WHERE watermark.evaluation_id = ?1
                 ORDER BY watermark.instance_id",
            )?;
            row.watermarks = watermarks
                .query_map([&row.evaluation_id], |watermark| {
                    Ok(EvaluationWatermarkHistoryRow {
                        instance_id: watermark.get(0)?,
                        max_report_sequence: watermark.get(1)?,
                        watermark_received_at: watermark.get(2)?,
                        report_received_at: watermark.get(3)?,
                        report_observed_at: watermark.get(4)?,
                        report_status: watermark.get(5)?,
                        report_canonical_json: watermark.get(6)?,
                        report_semantic_digest: watermark.get(7)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            if let Some(event_id) = row.finding_event_id.as_deref() {
                row.finding_evidence = finding_evidence_history(&self.connection, event_id)?;
            }
            if let Some(event_id) = row.prior_finding_event_id.as_deref() {
                row.prior_finding_evidence = finding_evidence_history(&self.connection, event_id)?;
            }
        }
        Ok(rows)
    }

    /// Reopen the latest immutable finding event in one exact canonical
    /// lineage at or before an evaluation-sequence cursor.
    ///
    /// This is the continuation-state primitive for bounded evaluation
    /// history. It never consults `finding_current`, whose selected row may be
    /// newer than the caller's frozen history bound.
    pub fn prior_finding_for_evaluation_lineage(
        &self,
        through_evaluation_sequence: i64,
        lineage: &EvaluationFindingLineage,
    ) -> Result<Option<PriorEvaluationFindingRow>, StoreError> {
        if through_evaluation_sequence < 0 {
            return Err(StoreError::Invariant(
                "prior finding cursor cannot be negative".into(),
            ));
        }
        let subject = CanonicalDocument::from_canonical_bytes(lineage.subject_json.clone())?;
        let basis = CanonicalDocument::from_canonical_bytes(lineage.basis_json.clone())?;
        self.connection
            .query_row(
                "SELECT event.event_id, event.finding_id, event.event_revision,
                        event.condition_state
                 FROM finding_events AS event
                 JOIN evaluation_runs AS evaluation
                   ON evaluation.evaluation_id = event.evaluation_id
                 WHERE evaluation.evaluation_sequence <= ?1
                   AND event.instance_id = ?2
                   AND event.detector_id = ?3
                   AND event.detector_version = ?4
                   AND event.detector_digest = ?5
                   AND event.profile_id = ?6
                   AND event.profile_version = ?7
                   AND event.profile_digest = ?8
                   AND evaluation.profile_semantic_id = ?9
                   AND event.subject_json = ?10
                   AND event.condition_name = ?11
                   AND event.basis_json = ?12
                 ORDER BY evaluation.evaluation_sequence DESC
                 LIMIT 1",
                params![
                    through_evaluation_sequence,
                    lineage.instance_id,
                    lineage.detector_id,
                    lineage.detector_version,
                    lineage.detector_digest,
                    lineage.profile_id,
                    lineage.profile_version,
                    lineage.profile_digest,
                    lineage.profile_semantic_id,
                    subject.as_bytes(),
                    lineage.condition_name,
                    basis.as_bytes(),
                ],
                |row| {
                    Ok(PriorEvaluationFindingRow {
                        event_id: row.get(0)?,
                        finding_id: row.get(1)?,
                        event_revision: row.get(2)?,
                        condition_state: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Exhaustively validate storage-level evaluation/refusal/finding
    /// invariants. Archive and whole-history reopeners call this once before
    /// streaming rows; bounded public pages validate only their selected rows.
    pub fn validate_evaluation_history_invariants(&self) -> Result<(), StoreError> {
        validate_evaluation_refusal_invariants(&self.connection)
    }

    /// Enqueue a notification with an application-level idempotency key.
    pub fn enqueue_notification(
        &mut self,
        notification: &NotificationInput,
    ) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO notification_outbox (
                notification_id, idempotency_key, finding_event_id, destination_kind,
                payload_json, available_at, max_attempts, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                notification.notification_id,
                notification.idempotency_key,
                notification.finding_event_id,
                notification.destination_kind,
                notification.payload.as_bytes(),
                notification.available_at,
                notification.max_attempts,
                notification.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Append a bounded notification delivery attempt.
    pub fn append_notification_attempt(
        &mut self,
        attempt: &NotificationAttemptInput,
    ) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO notification_attempts (
                notification_id, attempt_number, attempted_at, outcome,
                delivery_identity, detail_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                attempt.notification_id,
                attempt.attempt_number,
                attempt.attempted_at,
                attempt.outcome,
                attempt.delivery_identity,
                attempt.detail.as_bytes(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Append a logical retention tombstone without refreshing or rewriting evidence.
    pub fn append_retention_tombstone(
        &mut self,
        tombstone: &RetentionTombstoneInput,
    ) -> Result<(), StoreError> {
        if let Some(digest) = &tombstone.target_digest {
            validate_digest("target_digest", digest)?;
        }
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO retention_tombstones (
                tombstone_id, target_kind, target_id, target_digest,
                reason_code, detail_json, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                tombstone.tombstone_id,
                tombstone.target_kind,
                tombstone.target_id,
                tombstone.target_digest,
                tombstone.reason_code,
                tombstone.detail.as_bytes(),
                tombstone.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Append the genesis link for a fresh store.
    pub fn append_genesis(&mut self, genesis: &GenesisInput) -> Result<(), StoreError> {
        if let Some(digest) = &genesis.legacy_manifest_digest {
            validate_digest("legacy_manifest_digest", digest)?;
        }
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO genesis_records (
                genesis_id, legacy_manifest_digest, created_at, detail_json
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                genesis.genesis_id,
                genesis.legacy_manifest_digest,
                genesis.created_at,
                genesis.detail.as_bytes(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Return the sole immutable genesis identity of this initialized store.
    ///
    /// The diagnostic-execution producer uses this as its logical NQ node
    /// generation.  It is deliberately a store-generation identity rather
    /// than a hostname, path, process, or mutable configuration label.
    pub fn sole_genesis_id(&self) -> Result<String, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT genesis_id FROM genesis_records ORDER BY genesis_id LIMIT 2")?;
        let identities = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        match identities.as_slice() {
            [identity] if !identity.is_empty() => Ok(identity.clone()),
            [] => Err(StoreError::Invariant(
                "initialized store has no genesis identity".into(),
            )),
            [_] => Err(StoreError::Invariant(
                "initialized store has an empty genesis identity".into(),
            )),
            _ => Err(StoreError::Invariant(
                "initialized store has more than one genesis identity".into(),
            )),
        }
    }

    /// Append an opaque historical reference; it cannot create current finding state.
    pub fn append_legacy_reference(
        &mut self,
        reference: &LegacyReferenceInput,
    ) -> Result<(), StoreError> {
        if let Some(digest) = &reference.artifact_digest {
            validate_digest("artifact_digest", digest)?;
        }
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO legacy_references (
                legacy_reference_id, genesis_id, reference_uri, artifact_digest,
                detail_json, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                reference.legacy_reference_id,
                reference.genesis_id,
                reference.reference_uri,
                reference.artifact_digest,
                reference.detail.as_bytes(),
                reference.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Append an explicit upgrade receipt. Upgrade orchestration remains outside this crate.
    pub fn append_upgrade_receipt(
        &mut self,
        receipt: &UpgradeReceiptInput,
    ) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        insert_upgrade_receipt(&transaction, receipt)?;
        transaction.commit()?;
        Ok(())
    }
}

fn insert_upgrade_receipt(
    transaction: &Transaction<'_>,
    receipt: &UpgradeReceiptInput,
) -> Result<(), StoreError> {
    validate_digest("binary_digest", &receipt.binary_digest)?;
    validate_digest("backup_digest", &receipt.backup_digest)?;
    validate_upgrade_receipt_times(receipt)?;
    match (receipt.from_schema_version, receipt.to_schema_version) {
        (3, 4) => validate_v3_to_v4_receipt(receipt)?,
        (4, 5) => validate_v4_to_v5_receipt(receipt)?,
        (5, 6) => validate_v5_to_v6_receipt(receipt)?,
        (6, 7) => validate_v6_to_v7_receipt(receipt)?,
        _ => {}
    }
    transaction.execute(
        "INSERT INTO upgrade_receipts (
            receipt_id, from_schema_version, to_schema_version, migrations_json,
            binary_digest, backup_digest, backup_location, started_at, finished_at,
            result, operator_identity_json, verification_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            receipt.receipt_id,
            receipt.from_schema_version,
            receipt.to_schema_version,
            receipt.migrations.as_bytes(),
            receipt.binary_digest,
            receipt.backup_digest,
            receipt.backup_location,
            receipt.started_at,
            receipt.finished_at,
            receipt.result,
            receipt.operator_identity.as_bytes(),
            receipt.verification.as_bytes(),
        ],
    )?;
    Ok(())
}

fn validate_upgrade_receipt_times(receipt: &UpgradeReceiptInput) -> Result<(), StoreError> {
    let started_at = chrono::DateTime::parse_from_rfc3339(&receipt.started_at)
        .map_err(|_| StoreError::Invariant("upgrade receipt started_at is not RFC 3339".into()))?;
    let finished_at = chrono::DateTime::parse_from_rfc3339(&receipt.finished_at)
        .map_err(|_| StoreError::Invariant("upgrade receipt finished_at is not RFC 3339".into()))?;
    if started_at > finished_at {
        return Err(StoreError::Invariant(
            "upgrade receipt finished_at precedes started_at".into(),
        ));
    }
    Ok(())
}

fn validate_v3_to_v4_receipt(receipt: &UpgradeReceiptInput) -> Result<(), StoreError> {
    if receipt.from_schema_version != 3 || receipt.to_schema_version != 4 {
        return Err(StoreError::Invariant(
            "v3-to-v4 migration receipt names the wrong version transition".into(),
        ));
    }
    validate_digest("binary_digest", &receipt.binary_digest)?;
    validate_digest("backup_digest", &receipt.backup_digest)?;
    validate_upgrade_receipt_times(receipt)?;
    let expected_migrations =
        CanonicalDocument::from_serializable(&["schema_v3_to_v4_provider_intake"])?;
    if receipt.migrations != expected_migrations {
        return Err(StoreError::Invariant(
            "v3-to-v4 migration receipt does not name the exact migration vocabulary".into(),
        ));
    }
    if receipt.result != "migrated" {
        return Err(StoreError::Invariant(
            "v3-to-v4 migration receipt result must be exactly migrated".into(),
        ));
    }
    let expected_verification = CanonicalDocument::from_serializable(&serde_json::json!({
        "integrity": "ok",
        "source_schema_version": 3,
        "source_schema_artifact_digest": SCHEMA_V3_ARTIFACT_DIGEST,
        "backup_reopened": true,
        "historical_provider_intake": "explicit_gap_only",
        "provider_intakes_synthesized": false,
        "acknowledgments_synthesized": false,
    }))?;
    if receipt.verification != expected_verification {
        return Err(StoreError::Invariant(
            "v3-to-v4 migration receipt verification does not match the exact closed vocabulary"
                .into(),
        ));
    }
    Ok(())
}

fn validate_v4_to_v5_receipt(receipt: &UpgradeReceiptInput) -> Result<(), StoreError> {
    if receipt.from_schema_version != 4 || receipt.to_schema_version != 5 {
        return Err(StoreError::Invariant(
            "v4-to-v5 migration receipt names the wrong version transition".into(),
        ));
    }
    validate_digest("binary_digest", &receipt.binary_digest)?;
    validate_digest("backup_digest", &receipt.backup_digest)?;
    validate_upgrade_receipt_times(receipt)?;
    let expected_migrations =
        CanonicalDocument::from_serializable(&["schema_v4_to_v5_diagnostic_artifacts"])?;
    if receipt.migrations != expected_migrations {
        return Err(StoreError::Invariant(
            "v4-to-v5 migration receipt does not name the exact migration vocabulary".into(),
        ));
    }
    if receipt.result != "migrated" {
        return Err(StoreError::Invariant(
            "v4-to-v5 migration receipt result must be exactly migrated".into(),
        ));
    }
    let expected_verification = CanonicalDocument::from_serializable(&serde_json::json!({
        "integrity": "ok",
        "source_schema_version": 4,
        "source_schema_artifact_digest": SCHEMA_V4_ARTIFACT_DIGEST,
        "backup_reopened": true,
        "historical_diagnostic_artifacts": "no_durable_commitments",
        "diagnostic_artifacts_synthesized": false,
    }))?;
    if receipt.verification != expected_verification {
        return Err(StoreError::Invariant(
            "v4-to-v5 migration receipt verification does not match the exact closed vocabulary"
                .into(),
        ));
    }
    Ok(())
}

fn validate_v5_to_v6_receipt(receipt: &UpgradeReceiptInput) -> Result<(), StoreError> {
    if receipt.from_schema_version != 5 || receipt.to_schema_version != 6 {
        return Err(StoreError::Invariant(
            "v5-to-v6 migration receipt names the wrong version transition".into(),
        ));
    }
    validate_digest("binary_digest", &receipt.binary_digest)?;
    validate_digest("backup_digest", &receipt.backup_digest)?;
    validate_upgrade_receipt_times(receipt)?;
    let expected_migrations =
        CanonicalDocument::from_serializable(&["schema_v5_to_v6_runtime_ledger"])?;
    if receipt.migrations != expected_migrations {
        return Err(StoreError::Invariant(
            "v5-to-v6 migration receipt does not name the exact migration vocabulary".into(),
        ));
    }
    if receipt.result != "migrated" {
        return Err(StoreError::Invariant(
            "v5-to-v6 migration receipt result must be exactly migrated".into(),
        ));
    }
    let expected_verification = CanonicalDocument::from_serializable(&serde_json::json!({
        "integrity": "ok",
        "source_schema_version": 5,
        "source_schema_artifact_digest": SCHEMA_V5_ARTIFACT_DIGEST,
        "backup_reopened": true,
        "historical_runtime_records": "no_durable_commitments",
        "runtime_records_synthesized": false,
        "diagnostic_execution_bindings_synthesized": false,
    }))?;
    if receipt.verification != expected_verification {
        return Err(StoreError::Invariant(
            "v5-to-v6 migration receipt verification does not match the exact closed vocabulary"
                .into(),
        ));
    }
    Ok(())
}

fn validate_v6_to_v7_receipt(receipt: &UpgradeReceiptInput) -> Result<(), StoreError> {
    if receipt.from_schema_version != 6 || receipt.to_schema_version != 7 {
        return Err(StoreError::Invariant(
            "v6-to-v7 migration receipt names the wrong version transition".into(),
        ));
    }
    validate_digest("binary_digest", &receipt.binary_digest)?;
    validate_digest("backup_digest", &receipt.backup_digest)?;
    validate_upgrade_receipt_times(receipt)?;
    let expected_migrations =
        CanonicalDocument::from_serializable(&["schema_v6_to_v7_runtime_dependencies"])?;
    if receipt.migrations != expected_migrations {
        return Err(StoreError::Invariant(
            "v6-to-v7 migration receipt does not name the exact migration vocabulary".into(),
        ));
    }
    if receipt.result != "migrated" {
        return Err(StoreError::Invariant(
            "v6-to-v7 migration receipt result must be exactly migrated".into(),
        ));
    }
    let expected_verification = CanonicalDocument::from_serializable(&serde_json::json!({
        "integrity": "ok",
        "source_schema_version": 6,
        "source_schema_artifact_digest": SCHEMA_V6_ARTIFACT_DIGEST,
        "backup_reopened": true,
        "historical_dependency_binding": "legacy_unbound",
        "dependency_generations_synthesized": false,
        "trust_anchors_synthesized": false,
    }))?;
    if receipt.verification != expected_verification {
        return Err(StoreError::Invariant(
            "v6-to-v7 migration receipt verification does not match the exact closed vocabulary"
                .into(),
        ));
    }
    Ok(())
}

fn validate_upgrade_receipts(connection: &Connection) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT receipt_id, from_schema_version, to_schema_version,
                migrations_json, binary_digest, backup_digest, backup_location,
                started_at, finished_at, result, operator_identity_json,
                verification_json
         FROM upgrade_receipts ORDER BY receipt_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let receipt_id: String = row.get(0)?;
        let from_schema_version: u32 = row.get(1)?;
        let to_schema_version: u32 = row.get(2)?;
        let receipt = UpgradeReceiptInput {
            receipt_id: receipt_id.clone(),
            from_schema_version,
            to_schema_version,
            migrations: CanonicalDocument::from_canonical_bytes(row.get(3)?).map_err(|error| {
                StoreError::Integrity(format!(
                    "upgrade receipt {receipt_id} migrations are not canonical: {error}"
                ))
            })?,
            binary_digest: row.get(4)?,
            backup_digest: row.get(5)?,
            backup_location: row.get(6)?,
            started_at: row.get(7)?,
            finished_at: row.get(8)?,
            result: row.get(9)?,
            operator_identity: CanonicalDocument::from_canonical_bytes(row.get(10)?).map_err(
                |error| {
                    StoreError::Integrity(format!(
                        "upgrade receipt {receipt_id} operator identity is not canonical: {error}"
                    ))
                },
            )?,
            verification: CanonicalDocument::from_canonical_bytes(row.get(11)?).map_err(
                |error| {
                    StoreError::Integrity(format!(
                        "upgrade receipt {receipt_id} verification is not canonical: {error}"
                    ))
                },
            )?,
        };
        validate_digest("upgrade receipt binary_digest", &receipt.binary_digest)
            .map_err(|error| StoreError::Integrity(format!("{receipt_id}: {error}")))?;
        validate_digest("upgrade receipt backup_digest", &receipt.backup_digest)
            .map_err(|error| StoreError::Integrity(format!("{receipt_id}: {error}")))?;
        validate_upgrade_receipt_times(&receipt)
            .map_err(|error| StoreError::Integrity(format!("{receipt_id}: {error}")))?;
        match (from_schema_version, to_schema_version) {
            (3, 4) => validate_v3_to_v4_receipt(&receipt)
                .map_err(|error| StoreError::Integrity(format!("{receipt_id}: {error}")))?,
            (4, 5) => validate_v4_to_v5_receipt(&receipt)
                .map_err(|error| StoreError::Integrity(format!("{receipt_id}: {error}")))?,
            (5, 6) => validate_v5_to_v6_receipt(&receipt)
                .map_err(|error| StoreError::Integrity(format!("{receipt_id}: {error}")))?,
            (6, 7) => validate_v6_to_v7_receipt(&receipt)
                .map_err(|error| StoreError::Integrity(format!("{receipt_id}: {error}")))?,
            _ => {}
        }
    }
    Ok(())
}

fn validate_bounded_identity(label: &str, value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(StoreError::Invariant(format!(
            "{label} must contain 1..=256 non-control bytes"
        )));
    }
    Ok(())
}

fn diagnostic_artifact_import_disposition_name(
    disposition: DiagnosticArtifactImportDisposition,
) -> &'static str {
    match disposition {
        DiagnosticArtifactImportDisposition::Committed => "committed",
        DiagnosticArtifactImportDisposition::CommittedUnavailable => "committed_unavailable",
        DiagnosticArtifactImportDisposition::Existing => "existing",
        DiagnosticArtifactImportDisposition::Rematerialized => "rematerialized",
    }
}

fn parse_diagnostic_artifact_import_disposition(
    value: &str,
) -> Result<DiagnosticArtifactImportDisposition, StoreError> {
    match value {
        "committed" => Ok(DiagnosticArtifactImportDisposition::Committed),
        "committed_unavailable" => Ok(DiagnosticArtifactImportDisposition::CommittedUnavailable),
        "existing" => Ok(DiagnosticArtifactImportDisposition::Existing),
        "rematerialized" => Ok(DiagnosticArtifactImportDisposition::Rematerialized),
        other => Err(StoreError::Integrity(format!(
            "unknown diagnostic artifact import outcome {other}"
        ))),
    }
}

fn diagnostic_artifact_import_preflight(
    connection: &Connection,
    import_id: &str,
    artifact_id: &Sha256Digest,
    contract_schema: &str,
    canonical_bytes_sha256: &Sha256Digest,
    canonical_bytes_length: u64,
    _imported_at: &str,
) -> Result<Option<DiagnosticArtifactImportReceipt>, StoreError> {
    let existing = connection
        .query_row(
            "SELECT artifact_id, contract_schema, canonical_bytes_sha256,
                    canonical_bytes_length, outcome, imported_at
             FROM diagnostic_artifact_import_events WHERE import_id = ?1",
            [import_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((
        stored_artifact_id,
        stored_contract_schema,
        stored_digest,
        stored_length,
        outcome,
        stored_imported_at,
    )) = existing
    else {
        return Ok(None);
    };
    if stored_artifact_id != artifact_id.as_str()
        || stored_contract_schema != contract_schema
        || stored_digest != canonical_bytes_sha256.as_str()
        || u64::try_from(stored_length).ok() != Some(canonical_bytes_length)
    {
        return Err(StoreError::ReplayConflict(format!(
            "diagnostic artifact import {import_id} was reused for different evidence"
        )));
    }
    Ok(Some(DiagnosticArtifactImportReceipt {
        import_id: import_id.to_owned(),
        artifact_id: artifact_id.clone(),
        contract_schema: stored_contract_schema,
        canonical_bytes_sha256: canonical_bytes_sha256.clone(),
        canonical_bytes_length,
        disposition: parse_diagnostic_artifact_import_disposition(&outcome)?,
        imported_at: stored_imported_at,
    }))
}

#[allow(clippy::too_many_arguments)] // One immutable receipt row binds every exact import field.
fn insert_diagnostic_artifact_import_event(
    transaction: &Transaction<'_>,
    import_id: &str,
    artifact_id: &Sha256Digest,
    contract_schema: &str,
    canonical_bytes_sha256: &Sha256Digest,
    canonical_bytes_length: u64,
    disposition: DiagnosticArtifactImportDisposition,
    imported_at: &str,
) -> Result<(), StoreError> {
    let canonical_bytes_length = i64::try_from(canonical_bytes_length)
        .map_err(|_| StoreError::Invariant("diagnostic artifact length overflowed".into()))?;
    transaction.execute(
        "INSERT INTO diagnostic_artifact_import_events (
            import_id, artifact_id, contract_schema, canonical_bytes_sha256,
            canonical_bytes_length, outcome, imported_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            import_id,
            artifact_id.as_str(),
            contract_schema,
            canonical_bytes_sha256.as_str(),
            canonical_bytes_length,
            diagnostic_artifact_import_disposition_name(disposition),
            imported_at,
        ],
    )?;
    Ok(())
}

fn canonical_document_schema(document: &CanonicalDocument) -> Result<String, StoreError> {
    let value: Value = serde_json::from_slice(document.as_bytes())
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(Value::as_str)
        .filter(|schema| !schema.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            StoreError::Invariant(
                "diagnostic artifact canonical document has no nonempty top-level schema".into(),
            )
        })
}

/// Derive the exact batch identity used by the append-only runtime ledger.
///
/// This does not append, reserve capacity, validate a runtime graph, or grant
/// invocation authority.
pub fn runtime_record_batch_digest(
    batch: &RuntimeRecordBatchInput,
) -> Result<Sha256Digest, StoreError> {
    validate_runtime_checkpoint_dependency(&batch.dependency)?;
    runtime_record_batch_digest_v2(
        &batch.checkpoint_id,
        batch.expected_predecessor_checkpoint_id.as_deref(),
        batch.expected_predecessor_ledger_root.as_ref(),
        &batch.dependency.dependency_generation_id,
        &batch.dependency.trust_anchor_id,
        batch.dependency.canonical_custody.digest(),
        batch.dependency.canonical_custody.as_bytes().len(),
        &batch.records,
    )
}

#[allow(clippy::too_many_arguments)]
fn runtime_record_batch_digest_v2(
    checkpoint_id: &str,
    predecessor_checkpoint_id: Option<&str>,
    predecessor_ledger_root: Option<&Sha256Digest>,
    dependency_generation_id: &Sha256Digest,
    trust_anchor_id: &Sha256Digest,
    dependency_custody_digest: &str,
    dependency_custody_length: usize,
    records: &[RuntimeRecordInput],
) -> Result<Sha256Digest, StoreError> {
    let records = records
        .iter()
        .map(|record| {
            serde_json::json!({
                "record_id": record.record_id,
                "record_schema": record.record_schema,
                "canonical_bytes_sha256": record.canonical_bytes.digest(),
                "canonical_bytes_length": record.canonical_bytes.as_bytes().len(),
                "committed_at": record.committed_at,
            })
        })
        .collect::<Vec<_>>();
    let preimage = CanonicalDocument::from_serializable(&serde_json::json!({
        "schema": RUNTIME_LEDGER_BATCH_SCHEMA,
        "checkpoint_id": checkpoint_id,
        "expected_predecessor_checkpoint_id": predecessor_checkpoint_id,
        "expected_predecessor_ledger_root": predecessor_ledger_root.map(Sha256Digest::as_str),
        "dependency": {
            "dependency_generation_id": dependency_generation_id,
            "trust_anchor_id": trust_anchor_id,
            "canonical_bytes_sha256": dependency_custody_digest,
            "canonical_bytes_length": dependency_custody_length,
        },
        "records": records,
    }))?;
    Sha256Digest::parse(preimage.digest().to_owned())
        .map_err(|error| StoreError::Invariant(error.to_string()))
}

fn legacy_runtime_record_batch_digest(
    checkpoint_id: &str,
    predecessor_checkpoint_id: Option<&str>,
    predecessor_ledger_root: Option<&Sha256Digest>,
    records: &[RuntimeRecordInput],
) -> Result<Sha256Digest, StoreError> {
    let records = records
        .iter()
        .map(|record| {
            serde_json::json!({
                "record_id": record.record_id,
                "record_schema": record.record_schema,
                "canonical_bytes_sha256": record.canonical_bytes.digest(),
                "canonical_bytes_length": record.canonical_bytes.as_bytes().len(),
                "committed_at": record.committed_at,
            })
        })
        .collect::<Vec<_>>();
    let preimage = CanonicalDocument::from_serializable(&serde_json::json!({
        "schema": LEGACY_RUNTIME_LEDGER_BATCH_SCHEMA,
        "checkpoint_id": checkpoint_id,
        "expected_predecessor_checkpoint_id": predecessor_checkpoint_id,
        "expected_predecessor_ledger_root": predecessor_ledger_root.map(Sha256Digest::as_str),
        "records": records,
    }))?;
    Sha256Digest::parse(preimage.digest().to_owned())
        .map_err(|error| StoreError::Invariant(error.to_string()))
}

fn validate_runtime_checkpoint_dependency(
    dependency: &RuntimeCheckpointDependencyInput,
) -> Result<(), StoreError> {
    let value: Value = serde_json::from_slice(dependency.canonical_custody.as_bytes())
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        StoreError::Invariant("runtime dependency custody must be a canonical object".into())
    })?;
    if object.get("schema").and_then(Value::as_str)
        != Some(RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA)
    {
        return Err(StoreError::Invariant(
            "runtime dependency custody uses an unsupported schema".into(),
        ));
    }
    if object.get("generation_id").and_then(Value::as_str)
        != Some(dependency.dependency_generation_id.as_str())
    {
        return Err(StoreError::Invariant(
            "runtime dependency custody generation identity differs from its checkpoint binding"
                .into(),
        ));
    }
    let generation_hex = object
        .get("generation_canonical_bytes")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            StoreError::Invariant("runtime dependency custody lacks exact generation bytes".into())
        })?;
    let generation_bytes = hex::decode(generation_hex).map_err(|_| {
        StoreError::Invariant(
            "runtime dependency custody generation bytes are not canonical hexadecimal".into(),
        )
    })?;
    if hex::encode(&generation_bytes) != generation_hex
        || sha256_bytes(&generation_bytes) != dependency.dependency_generation_id
    {
        return Err(StoreError::Invariant(
            "runtime dependency generation bytes differ from their identity".into(),
        ));
    }
    let generation = CanonicalDocument::from_canonical_bytes(generation_bytes)?;
    let generation_value: Value = serde_json::from_slice(generation.as_bytes())
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    if generation_value
        .get("trust_anchor_id")
        .and_then(Value::as_str)
        != Some(dependency.trust_anchor_id.as_str())
    {
        return Err(StoreError::Invariant(
            "runtime dependency generation names another trust anchor".into(),
        ));
    }
    let anchor_hex = object
        .get("trust_anchor_canonical_bytes")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            StoreError::Invariant("runtime dependency custody lacks trust-anchor bytes".into())
        })?;
    let anchor_bytes = hex::decode(anchor_hex).map_err(|_| {
        StoreError::Invariant(
            "runtime dependency trust-anchor bytes are not canonical hexadecimal".into(),
        )
    })?;
    if hex::encode(&anchor_bytes) != anchor_hex
        || sha256_bytes(&anchor_bytes) != dependency.trust_anchor_id
    {
        return Err(StoreError::Invariant(
            "runtime dependency trust-anchor bytes differ from their identity".into(),
        ));
    }
    let _ = CanonicalDocument::from_canonical_bytes(anchor_bytes)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn runtime_record_root(
    record_sequence: u64,
    record: &RuntimeRecordInput,
    checkpoint_id: &str,
    predecessor_record_id: Option<&str>,
    predecessor_ledger_root: Option<&Sha256Digest>,
) -> Result<Sha256Digest, StoreError> {
    let preimage = CanonicalDocument::from_serializable(&serde_json::json!({
        "schema": RUNTIME_LEDGER_ROOT_SCHEMA,
        "record_sequence": record_sequence,
        "record_id": record.record_id,
        "record_schema": record.record_schema,
        "canonical_bytes_sha256": record.canonical_bytes.digest(),
        "canonical_bytes_length": record.canonical_bytes.as_bytes().len(),
        "checkpoint_id": checkpoint_id,
        "predecessor_record_id": predecessor_record_id,
        "predecessor_ledger_root": predecessor_ledger_root.map(Sha256Digest::as_str),
        "committed_at": record.committed_at,
    }))?;
    Sha256Digest::parse(preimage.digest().to_owned())
        .map_err(|error| StoreError::Invariant(error.to_string()))
}

fn validate_runtime_record_input(record: &RuntimeRecordInput) -> Result<(), StoreError> {
    Sha256Digest::parse(record.record_id.clone()).map_err(|error| {
        StoreError::Invariant(format!(
            "runtime record_id is not a SHA-256 identity: {error}"
        ))
    })?;
    validate_bounded_identity("runtime record_schema", &record.record_schema)?;
    if !SUPPORTED_RUNTIME_RECORD_SCHEMAS.contains(&record.record_schema.as_str())
        && !SUPPORTED_EXTERNAL_RUNTIME_RECORD_SCHEMAS.contains(&record.record_schema.as_str())
    {
        return Err(StoreError::Invariant(format!(
            "runtime record {} uses unsupported schema {}",
            record.record_id, record.record_schema
        )));
    }
    if canonical_document_schema(&record.canonical_bytes)? != record.record_schema {
        return Err(StoreError::Invariant(format!(
            "runtime record {} schema disagrees with its canonical bytes",
            record.record_id
        )));
    }
    if chrono::DateTime::parse_from_rfc3339(&record.committed_at).is_err() {
        return Err(StoreError::Invariant(format!(
            "runtime record {} committed_at is not RFC 3339",
            record.record_id
        )));
    }
    Ok(())
}

fn validate_runtime_record_batch(batch: &RuntimeRecordBatchInput) -> Result<(), StoreError> {
    validate_runtime_checkpoint_dependency(&batch.dependency)?;
    Sha256Digest::parse(batch.checkpoint_id.clone()).map_err(|error| {
        StoreError::Invariant(format!(
            "runtime checkpoint_id is not a SHA-256 identity: {error}"
        ))
    })?;
    if batch.records.is_empty() {
        return Err(StoreError::Invariant(
            "runtime-record append requires at least one record".into(),
        ));
    }
    if batch.records.len() > usize::try_from(MAX_PUBLIC_QUERY_ROWS).unwrap_or(1_000) {
        return Err(StoreError::Invariant(format!(
            "runtime-record append exceeds {MAX_PUBLIC_QUERY_ROWS} records"
        )));
    }
    if batch.expected_predecessor_checkpoint_id.is_some()
        != batch.expected_predecessor_ledger_root.is_some()
    {
        return Err(StoreError::Invariant(
            "runtime-record append predecessor checkpoint and root must be both present or both absent"
                .into(),
        ));
    }
    if let Some(predecessor_id) = &batch.expected_predecessor_checkpoint_id {
        Sha256Digest::parse(predecessor_id.clone()).map_err(|error| {
            StoreError::Invariant(format!(
                "runtime predecessor checkpoint identity is invalid: {error}"
            ))
        })?;
    }
    let mut record_ids = BTreeSet::new();
    for record in &batch.records {
        validate_runtime_record_input(record)?;
        if !record_ids.insert(record.record_id.as_str()) {
            return Err(StoreError::Invariant(format!(
                "runtime-record batch repeats identity {}",
                record.record_id
            )));
        }
    }
    Ok(())
}

fn runtime_checkpoint_by_id_on_connection(
    connection: &Connection,
    checkpoint_id: &str,
) -> Result<Option<RuntimeLedgerCheckpoint>, StoreError> {
    let row = connection
        .query_row(
            "SELECT checkpoint_sequence, checkpoint_id, batch_digest,
                    first_record_sequence, last_record_sequence, record_count,
                    predecessor_checkpoint_id, predecessor_ledger_root,
                    checkpoint_ledger_root, committed_at
             FROM runtime_record_checkpoints WHERE checkpoint_id = ?1",
            [checkpoint_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        checkpoint_sequence,
        checkpoint_id,
        batch_digest,
        first_record_sequence,
        last_record_sequence,
        record_count,
        predecessor_checkpoint_id,
        predecessor_ledger_root,
        checkpoint_ledger_root,
        committed_at,
    )) = row
    else {
        return Ok(None);
    };
    let positive = |label: &str, value: i64| {
        u64::try_from(value).map_err(|_| {
            StoreError::Integrity(format!(
                "runtime checkpoint {checkpoint_id} has invalid {label}"
            ))
        })
    };
    Ok(Some(RuntimeLedgerCheckpoint {
        checkpoint_sequence: positive("checkpoint_sequence", checkpoint_sequence)?,
        checkpoint_id: checkpoint_id.clone(),
        batch_digest: Sha256Digest::parse(batch_digest).map_err(|error| {
            StoreError::Integrity(format!(
                "runtime checkpoint batch digest is invalid: {error}"
            ))
        })?,
        first_record_sequence: positive("first_record_sequence", first_record_sequence)?,
        last_record_sequence: positive("last_record_sequence", last_record_sequence)?,
        record_count: positive("record_count", record_count)?,
        predecessor_checkpoint_id,
        predecessor_ledger_root: predecessor_ledger_root
            .map(Sha256Digest::parse)
            .transpose()
            .map_err(|error| {
                StoreError::Integrity(format!(
                    "runtime checkpoint predecessor root is invalid: {error}"
                ))
            })?,
        checkpoint_ledger_root: Sha256Digest::parse(checkpoint_ledger_root).map_err(|error| {
            StoreError::Integrity(format!("runtime checkpoint root is invalid: {error}"))
        })?,
        committed_at,
    }))
}

#[allow(clippy::too_many_lines)]
fn runtime_checkpoint_dependency_on_connection(
    connection: &Connection,
    checkpoint_id: &str,
) -> Result<Option<RuntimeCheckpointDependencyAccess>, StoreError> {
    let row = connection
        .query_row(
            "SELECT binding_state, dependency_generation_id, trust_anchor_id,
                    canonical_bytes_sha256, source_schema_version
             FROM runtime_checkpoint_dependency_bindings
             WHERE checkpoint_id = ?1",
            [checkpoint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((state, generation, anchor, digest, source_version)) = row else {
        return Ok(None);
    };
    if state == "legacy_unbound" {
        let source_schema_version = source_version
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                StoreError::Integrity(format!(
                    "legacy checkpoint {checkpoint_id} lacks its source schema version"
                ))
            })?;
        if generation.is_some() || anchor.is_some() || digest.is_some() {
            return Err(StoreError::Integrity(format!(
                "legacy checkpoint {checkpoint_id} invents dependency provenance"
            )));
        }
        return Ok(Some(RuntimeCheckpointDependencyAccess {
            checkpoint_id: checkpoint_id.to_owned(),
            binding: RuntimeCheckpointDependencyBinding::LegacyUnbound {
                source_schema_version,
            },
            byte_state: None,
        }));
    }
    if state != "authenticated" || source_version.is_some() {
        return Err(StoreError::Integrity(format!(
            "checkpoint {checkpoint_id} has invalid dependency binding state"
        )));
    }
    let dependency_generation_id = Sha256Digest::parse(generation.ok_or_else(|| {
        StoreError::Integrity(format!(
            "checkpoint {checkpoint_id} lacks dependency generation identity"
        ))
    })?)
    .map_err(|error| StoreError::Integrity(error.to_string()))?;
    let trust_anchor_id = Sha256Digest::parse(anchor.ok_or_else(|| {
        StoreError::Integrity(format!(
            "checkpoint {checkpoint_id} lacks dependency trust-anchor identity"
        ))
    })?)
    .map_err(|error| StoreError::Integrity(error.to_string()))?;
    let trust_root = runtime_dependency_trust_root_on_connection(connection)?.ok_or_else(|| {
        StoreError::Integrity(format!(
            "authenticated checkpoint {checkpoint_id} lacks a bootstrap trust root"
        ))
    })?;
    if trust_anchor_id != trust_root {
        return Err(StoreError::Integrity(format!(
            "checkpoint {checkpoint_id} selected non-bootstrap trust root {trust_anchor_id}; expected {trust_root}"
        )));
    }
    let canonical_bytes_sha256 = Sha256Digest::parse(digest.ok_or_else(|| {
        StoreError::Integrity(format!(
            "checkpoint {checkpoint_id} lacks dependency custody digest"
        ))
    })?)
    .map_err(|error| StoreError::Integrity(error.to_string()))?;
    let commitment = connection
        .query_row(
            "SELECT trust_anchor_id, custody_schema, canonical_bytes_sha256,
                    canonical_bytes_length
             FROM runtime_dependency_generation_commitments
             WHERE dependency_generation_id = ?1",
            [dependency_generation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((committed_anchor, schema, committed_digest, committed_length)) = commitment else {
        return Err(StoreError::Integrity(format!(
            "checkpoint {checkpoint_id} references a missing dependency commitment"
        )));
    };
    if committed_anchor != trust_anchor_id.as_str()
        || schema != RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA
        || committed_digest != canonical_bytes_sha256.as_str()
        || committed_length <= 0
    {
        return Err(StoreError::Integrity(format!(
            "checkpoint {checkpoint_id} dependency binding differs from its commitment"
        )));
    }
    let payload = connection
        .query_row(
            "SELECT canonical_bytes
             FROM runtime_dependency_generation_payloads
             WHERE dependency_generation_id = ?1",
            [dependency_generation_id.as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let byte_state = match payload {
        None => RuntimeDependencyGenerationByteState::CommittedUnavailable,
        Some(bytes) => {
            let actual_length = i64::try_from(bytes.len()).map_err(|_| {
                StoreError::Integrity("runtime dependency custody length overflowed".into())
            })?;
            if actual_length != committed_length {
                RuntimeDependencyGenerationByteState::Corrupt {
                    reason: format!(
                        "stored byte length {actual_length} differs from committed {committed_length}"
                    ),
                }
            } else if sha256_bytes(&bytes) != canonical_bytes_sha256 {
                RuntimeDependencyGenerationByteState::Corrupt {
                    reason: "stored byte digest differs from committed custody".into(),
                }
            } else {
                match CanonicalDocument::from_canonical_bytes(bytes) {
                    Ok(canonical_custody) => {
                        let input = RuntimeCheckpointDependencyInput {
                            dependency_generation_id: dependency_generation_id.clone(),
                            trust_anchor_id: trust_anchor_id.clone(),
                            canonical_custody,
                        };
                        match validate_runtime_checkpoint_dependency(&input) {
                            Ok(()) => RuntimeDependencyGenerationByteState::VerifiedAvailable {
                                canonical_custody: input.canonical_custody,
                            },
                            Err(error) => RuntimeDependencyGenerationByteState::Corrupt {
                                reason: error.to_string(),
                            },
                        }
                    }
                    Err(error) => RuntimeDependencyGenerationByteState::Corrupt {
                        reason: error.to_string(),
                    },
                }
            }
        }
    };
    Ok(Some(RuntimeCheckpointDependencyAccess {
        checkpoint_id: checkpoint_id.to_owned(),
        binding: RuntimeCheckpointDependencyBinding::Authenticated {
            dependency_generation_id,
            trust_anchor_id,
            canonical_bytes_sha256,
            canonical_bytes_length: u64::try_from(committed_length).map_err(|_| {
                StoreError::Integrity(format!(
                    "checkpoint {checkpoint_id} has invalid dependency custody length"
                ))
            })?,
        },
        byte_state: Some(byte_state),
    }))
}

fn runtime_ledger_checkpoint_on_connection(
    connection: &Connection,
) -> Result<Option<RuntimeLedgerCheckpoint>, StoreError> {
    let checkpoint_id = connection
        .query_row(
            "SELECT checkpoint_id FROM runtime_record_checkpoints
             ORDER BY checkpoint_sequence DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    checkpoint_id
        .map(|checkpoint_id| {
            runtime_checkpoint_by_id_on_connection(connection, &checkpoint_id)?.ok_or_else(|| {
                StoreError::Integrity(format!("runtime checkpoint index lost {checkpoint_id}"))
            })
        })
        .transpose()
}

fn runtime_record_by_id_on_connection(
    connection: &Connection,
    record_id: &str,
) -> Result<Option<RuntimeRecordRow>, StoreError> {
    let row = connection
        .query_row(
            "SELECT record_sequence, record_id, record_schema, canonical_bytes,
                    canonical_bytes_sha256, checkpoint_id,
                    predecessor_record_id, predecessor_ledger_root,
                    ledger_root, committed_at
             FROM runtime_record_ledger WHERE record_id = ?1",
            [record_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        record_sequence,
        record_id,
        record_schema,
        canonical_bytes,
        canonical_bytes_sha256,
        checkpoint_id,
        predecessor_record_id,
        predecessor_ledger_root,
        ledger_root,
        committed_at,
    )) = row
    else {
        return Ok(None);
    };
    let record_sequence = u64::try_from(record_sequence).map_err(|_| {
        StoreError::Integrity(format!("runtime record {record_id} has invalid sequence"))
    })?;
    let canonical_bytes =
        CanonicalDocument::from_canonical_bytes(canonical_bytes).map_err(|error| {
            StoreError::Integrity(format!(
                "runtime record {record_id} bytes are not canonical: {error}"
            ))
        })?;
    if canonical_bytes.digest() != canonical_bytes_sha256 {
        return Err(StoreError::Integrity(format!(
            "runtime record {record_id} byte digest disagrees with exact bytes"
        )));
    }
    if canonical_document_schema(&canonical_bytes)
        .map_err(|error| StoreError::Integrity(error.to_string()))?
        != record_schema
    {
        return Err(StoreError::Integrity(format!(
            "runtime record {record_id} schema disagrees with exact bytes"
        )));
    }
    if chrono::DateTime::parse_from_rfc3339(&committed_at).is_err() {
        return Err(StoreError::Integrity(format!(
            "runtime record {record_id} has invalid committed_at"
        )));
    }
    Ok(Some(RuntimeRecordRow {
        record_sequence,
        record_id,
        record_schema,
        canonical_bytes,
        canonical_bytes_sha256: Sha256Digest::parse(canonical_bytes_sha256).map_err(|error| {
            StoreError::Integrity(format!(
                "runtime record canonical-byte digest is invalid: {error}"
            ))
        })?,
        checkpoint_id,
        predecessor_record_id,
        predecessor_ledger_root: predecessor_ledger_root
            .map(Sha256Digest::parse)
            .transpose()
            .map_err(|error| {
                StoreError::Integrity(format!(
                    "runtime record predecessor root is invalid: {error}"
                ))
            })?,
        ledger_root: Sha256Digest::parse(ledger_root).map_err(|error| {
            StoreError::Integrity(format!("runtime record root is invalid: {error}"))
        })?,
        committed_at,
    }))
}

fn runtime_record_by_sequence_on_connection(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<RuntimeRecordRow>, StoreError> {
    let sequence = i64::try_from(sequence)
        .map_err(|_| StoreError::Invariant("runtime record sequence overflowed".into()))?;
    let record_id = connection
        .query_row(
            "SELECT record_id FROM runtime_record_ledger WHERE record_sequence = ?1",
            [sequence],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    record_id
        .map(|record_id| {
            runtime_record_by_id_on_connection(connection, &record_id)?.ok_or_else(|| {
                StoreError::Integrity(format!("runtime record index lost {record_id}"))
            })
        })
        .transpose()
}

fn runtime_record_lookup_status_on_connection(
    connection: &Connection,
) -> Result<RuntimeRecordLookupStatus, StoreError> {
    let (ledger_records, lookup_records, missing_records, extra_records, mismatched_records) =
        connection.query_row(
            "SELECT
                (SELECT COUNT(*) FROM runtime_record_ledger),
                (SELECT COUNT(*) FROM runtime_record_lookup),
                (SELECT COUNT(*) FROM runtime_record_ledger AS ledger
                 WHERE NOT EXISTS (
                    SELECT 1 FROM runtime_record_lookup AS lookup
                    WHERE lookup.record_id = ledger.record_id
                 )),
                (SELECT COUNT(*) FROM runtime_record_lookup AS lookup
                 WHERE NOT EXISTS (
                    SELECT 1 FROM runtime_record_ledger AS ledger
                    WHERE ledger.record_id = lookup.record_id
                 )),
                (SELECT COUNT(*)
                 FROM runtime_record_lookup AS lookup
                 JOIN runtime_record_ledger AS ledger
                   ON ledger.record_id = lookup.record_id
                 WHERE lookup.record_sequence <> ledger.record_sequence
                    OR lookup.record_schema <> ledger.record_schema
                    OR lookup.ledger_root <> ledger.ledger_root)",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )?;
    let count = |label: &str, value: i64| {
        u64::try_from(value)
            .map_err(|_| StoreError::Integrity(format!("negative runtime lookup {label}")))
    };
    Ok(RuntimeRecordLookupStatus {
        ledger_records: count("ledger count", ledger_records)?,
        lookup_records: count("lookup count", lookup_records)?,
        missing_records: count("missing count", missing_records)?,
        extra_records: count("extra count", extra_records)?,
        mismatched_records: count("mismatch count", mismatched_records)?,
    })
}

fn validate_runtime_checkpoint_identity(
    connection: &Connection,
    checkpoint: &RuntimeLedgerCheckpoint,
) -> Result<(), StoreError> {
    let stored = runtime_checkpoint_by_id_on_connection(connection, &checkpoint.checkpoint_id)?
        .ok_or_else(|| {
            StoreError::Invariant(format!(
                "runtime checkpoint {} is not retained",
                checkpoint.checkpoint_id
            ))
        })?;
    if &stored != checkpoint {
        return Err(StoreError::Invariant(format!(
            "runtime checkpoint {} differs from retained identity",
            checkpoint.checkpoint_id
        )));
    }
    Ok(())
}

fn runtime_record_page_on_connection(
    connection: &Connection,
    checkpoint: Option<&RuntimeLedgerCheckpoint>,
    after_record_sequence: u64,
    limit: u32,
) -> Result<RuntimeRecordPage, StoreError> {
    validate_public_limit(limit)?;
    let Some(checkpoint) = checkpoint else {
        if runtime_ledger_checkpoint_on_connection(connection)?.is_some()
            || after_record_sequence != 0
        {
            return Err(StoreError::Invariant(
                "an empty runtime snapshot cannot page a nonempty ledger or nonzero cursor".into(),
            ));
        }
        return Ok(RuntimeRecordPage {
            checkpoint: None,
            after_record_sequence,
            records: Vec::new(),
            next_after_record_sequence: None,
            complete: true,
        });
    };
    validate_runtime_checkpoint_identity(connection, checkpoint)?;
    if after_record_sequence > checkpoint.last_record_sequence {
        return Err(StoreError::Invariant(
            "runtime-record cursor is beyond the pinned checkpoint".into(),
        ));
    }
    let after = i64::try_from(after_record_sequence)
        .map_err(|_| StoreError::Invariant("runtime-record cursor overflowed".into()))?;
    let through = i64::try_from(checkpoint.last_record_sequence)
        .map_err(|_| StoreError::Integrity("runtime checkpoint sequence overflowed".into()))?;
    let fetch_limit = i64::from(limit) + 1;
    let mut statement = connection.prepare(
        "SELECT record_id FROM runtime_record_ledger
         WHERE record_sequence > ?1 AND record_sequence <= ?2
         ORDER BY record_sequence LIMIT ?3",
    )?;
    let mut ids = statement
        .query_map(params![after, through, fetch_limit], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let complete = ids.len() <= usize::try_from(limit).unwrap_or(usize::MAX);
    if !complete {
        ids.pop();
    }
    let records = ids
        .into_iter()
        .map(|record_id| {
            runtime_record_by_id_on_connection(connection, &record_id)?.ok_or_else(|| {
                StoreError::Integrity(format!("runtime record page lost {record_id}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_after_record_sequence = if complete {
        None
    } else {
        records.last().map(|record| record.record_sequence)
    };
    Ok(RuntimeRecordPage {
        checkpoint: Some(checkpoint.clone()),
        after_record_sequence,
        records,
        next_after_record_sequence,
        complete,
    })
}

fn require_runtime_dependency_trust_root(
    transaction: &Transaction<'_>,
    dependency: &RuntimeCheckpointDependencyInput,
) -> Result<(), StoreError> {
    let trust_root =
        runtime_dependency_trust_root_on_connection(transaction)?.ok_or_else(|| {
            StoreError::Invariant(
                "runtime dependency trust root must be established before checkpoint append".into(),
            )
        })?;
    if trust_root != dependency.trust_anchor_id {
        return Err(StoreError::ReplayConflict(format!(
            "runtime dependency generation uses trust anchor {}, but store bootstrap root is {trust_root}",
            dependency.trust_anchor_id
        )));
    }
    Ok(())
}

fn ensure_runtime_dependency_generation(
    transaction: &Transaction<'_>,
    dependency: &RuntimeCheckpointDependencyInput,
) -> Result<(), StoreError> {
    validate_runtime_checkpoint_dependency(dependency)?;
    require_runtime_dependency_trust_root(transaction, dependency)?;
    let existing = transaction
        .query_row(
            "SELECT trust_anchor_id, custody_schema, canonical_bytes_sha256,
                    canonical_bytes_length
             FROM runtime_dependency_generation_commitments
             WHERE dependency_generation_id = ?1",
            [dependency.dependency_generation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let length = i64::try_from(dependency.canonical_custody.as_bytes().len())
        .map_err(|_| StoreError::Invariant("runtime dependency closure is too large".into()))?;
    match existing {
        None => {
            transaction.execute(
                "INSERT INTO runtime_dependency_generation_commitments (
                    dependency_generation_id, trust_anchor_id, custody_schema,
                    canonical_bytes_sha256, canonical_bytes_length, committed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    dependency.dependency_generation_id.as_str(),
                    dependency.trust_anchor_id.as_str(),
                    RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA,
                    dependency.canonical_custody.digest(),
                    length,
                    now_utc(),
                ],
            )?;
            transaction.execute(
                "INSERT INTO runtime_dependency_generation_payloads (
                    dependency_generation_id, canonical_bytes
                 ) VALUES (?1, ?2)",
                params![
                    dependency.dependency_generation_id.as_str(),
                    dependency.canonical_custody.as_bytes(),
                ],
            )?;
        }
        Some((trust_anchor_id, schema, bytes_digest, bytes_length)) => {
            if trust_anchor_id != dependency.trust_anchor_id.as_str()
                || schema != RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA
                || bytes_digest != dependency.canonical_custody.digest()
                || bytes_length != length
            {
                return Err(StoreError::ReplayConflict(format!(
                    "runtime dependency generation {} was reused for substituted custody",
                    dependency.dependency_generation_id
                )));
            }
            let payload = transaction
                .query_row(
                    "SELECT canonical_bytes
                     FROM runtime_dependency_generation_payloads
                     WHERE dependency_generation_id = ?1",
                    [dependency.dependency_generation_id.as_str()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            match payload {
                None => {
                    transaction.execute(
                        "INSERT INTO runtime_dependency_generation_payloads (
                            dependency_generation_id, canonical_bytes
                         ) VALUES (?1, ?2)",
                        params![
                            dependency.dependency_generation_id.as_str(),
                            dependency.canonical_custody.as_bytes(),
                        ],
                    )?;
                }
                Some(bytes) if bytes == dependency.canonical_custody.as_bytes() => {}
                Some(_) => {
                    return Err(StoreError::ReplayConflict(format!(
                        "runtime dependency generation {} has corrupt or substituted bytes",
                        dependency.dependency_generation_id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn runtime_dependency_trust_root_on_connection(
    connection: &Connection,
) -> Result<Option<Sha256Digest>, StoreError> {
    let value = connection
        .query_row(
            "SELECT trust_anchor_id
             FROM runtime_dependency_trust_roots
             WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    value
        .map(|value| {
            Sha256Digest::parse(value).map_err(|_| {
                StoreError::Integrity(
                    "runtime dependency trust root is not a canonical SHA-256 digest".into(),
                )
            })
        })
        .transpose()
}

#[allow(clippy::too_many_lines)]
fn append_runtime_records_in_transaction(
    transaction: &Transaction<'_>,
    batch: &RuntimeRecordBatchInput,
) -> Result<RuntimeRecordAppendReceipt, StoreError> {
    validate_runtime_record_batch(batch)?;
    validate_runtime_record_ledger(transaction)?;
    let batch_digest = runtime_record_batch_digest(batch)?;
    if let Some(existing) =
        runtime_checkpoint_by_id_on_connection(transaction, &batch.checkpoint_id)?
    {
        let dependency_access =
            runtime_checkpoint_dependency_on_connection(transaction, &batch.checkpoint_id)?;
        let dependency_matches = matches!(
            dependency_access,
            Some(RuntimeCheckpointDependencyAccess {
                binding: RuntimeCheckpointDependencyBinding::Authenticated {
                    dependency_generation_id,
                    trust_anchor_id,
                    canonical_bytes_sha256,
                    canonical_bytes_length: _,
                },
                byte_state: Some(RuntimeDependencyGenerationByteState::VerifiedAvailable {
                    canonical_custody,
                }),
                ..
            }) if dependency_generation_id == batch.dependency.dependency_generation_id
                && trust_anchor_id == batch.dependency.trust_anchor_id
                && canonical_bytes_sha256.as_str()
                    == batch.dependency.canonical_custody.digest()
                && canonical_custody == batch.dependency.canonical_custody
        );
        if existing.batch_digest != batch_digest
            || existing.predecessor_checkpoint_id != batch.expected_predecessor_checkpoint_id
            || existing.predecessor_ledger_root != batch.expected_predecessor_ledger_root
            || existing.record_count
                != u64::try_from(batch.records.len()).map_err(|_| {
                    StoreError::Invariant("runtime-record batch size overflowed".into())
                })?
            || !dependency_matches
        {
            return Err(StoreError::ReplayConflict(format!(
                "runtime checkpoint {} was reused for a different batch",
                batch.checkpoint_id
            )));
        }
        for (offset, expected) in batch.records.iter().enumerate() {
            let sequence = existing.first_record_sequence
                + u64::try_from(offset).map_err(|_| {
                    StoreError::Invariant("runtime-record replay offset overflowed".into())
                })?;
            let actual = runtime_record_by_sequence_on_connection(transaction, sequence)?
                .ok_or_else(|| {
                    StoreError::Integrity(format!(
                        "runtime checkpoint {} lost record sequence {sequence}",
                        batch.checkpoint_id
                    ))
                })?;
            if actual.record_id != expected.record_id
                || actual.record_schema != expected.record_schema
                || actual.canonical_bytes != expected.canonical_bytes
                || actual.committed_at != expected.committed_at
                || actual.checkpoint_id != batch.checkpoint_id
            {
                return Err(StoreError::ReplayConflict(format!(
                    "runtime checkpoint {} exact replay differs at sequence {sequence}",
                    batch.checkpoint_id
                )));
            }
        }
        return Ok(RuntimeRecordAppendReceipt {
            disposition: RuntimeRecordAppendDisposition::Replayed,
            checkpoint: existing,
        });
    }

    ensure_runtime_dependency_generation(transaction, &batch.dependency)?;
    let predecessor = runtime_ledger_checkpoint_on_connection(transaction)?;
    let actual_predecessor_checkpoint_id = predecessor
        .as_ref()
        .map(|value| value.checkpoint_id.clone());
    let actual_predecessor_ledger_root = predecessor
        .as_ref()
        .map(|value| value.checkpoint_ledger_root.clone());
    if actual_predecessor_checkpoint_id != batch.expected_predecessor_checkpoint_id
        || actual_predecessor_ledger_root != batch.expected_predecessor_ledger_root
    {
        return Err(StoreError::ReplayConflict(
            "runtime-record append predecessor differs from the declared ledger frontier".into(),
        ));
    }
    for record in &batch.records {
        if let Some(existing) = runtime_record_by_id_on_connection(transaction, &record.record_id)?
        {
            return Err(StoreError::ReplayConflict(format!(
                "runtime record identity {} already belongs to checkpoint {}",
                existing.record_id, existing.checkpoint_id
            )));
        }
    }

    let first_sequence = predecessor
        .as_ref()
        .map_or(1, |value| value.last_record_sequence.saturating_add(1));
    let record_count = u64::try_from(batch.records.len())
        .map_err(|_| StoreError::Invariant("runtime-record batch size overflowed".into()))?;
    let last_sequence = first_sequence
        .checked_add(record_count - 1)
        .ok_or_else(|| StoreError::Invariant("runtime-record sequence overflowed".into()))?;
    let mut predecessor_record_id = predecessor
        .as_ref()
        .map(|value| {
            runtime_record_by_sequence_on_connection(transaction, value.last_record_sequence)?
                .map(|record| record.record_id)
                .ok_or_else(|| {
                    StoreError::Integrity(
                        "runtime ledger frontier lost its predecessor record".into(),
                    )
                })
        })
        .transpose()?;
    let mut predecessor_root = actual_predecessor_ledger_root.clone();
    let mut prepared = Vec::with_capacity(batch.records.len());
    for (offset, record) in batch.records.iter().enumerate() {
        let sequence = first_sequence
            .checked_add(
                u64::try_from(offset).map_err(|_| {
                    StoreError::Invariant("runtime-record offset overflowed".into())
                })?,
            )
            .ok_or_else(|| StoreError::Invariant("runtime-record sequence overflowed".into()))?;
        let root = runtime_record_root(
            sequence,
            record,
            &batch.checkpoint_id,
            predecessor_record_id.as_deref(),
            predecessor_root.as_ref(),
        )?;
        prepared.push((
            sequence,
            record,
            predecessor_record_id.clone(),
            predecessor_root.clone(),
            root.clone(),
        ));
        predecessor_record_id = Some(record.record_id.clone());
        predecessor_root = Some(root);
    }
    let checkpoint_root = predecessor_root.ok_or_else(|| {
        StoreError::Invariant("runtime-record batch produced no checkpoint root".into())
    })?;
    let checkpoint_committed_at = now_utc();
    transaction.execute(
        "INSERT INTO runtime_record_checkpoints (
            checkpoint_id, batch_digest, first_record_sequence,
            last_record_sequence, record_count, predecessor_checkpoint_id,
            predecessor_ledger_root, checkpoint_ledger_root, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            batch.checkpoint_id,
            batch_digest.as_str(),
            i64::try_from(first_sequence)
                .map_err(|_| StoreError::Invariant("runtime first sequence overflowed".into()))?,
            i64::try_from(last_sequence)
                .map_err(|_| StoreError::Invariant("runtime last sequence overflowed".into()))?,
            i64::try_from(record_count)
                .map_err(|_| StoreError::Invariant("runtime record count overflowed".into()))?,
            batch.expected_predecessor_checkpoint_id,
            batch
                .expected_predecessor_ledger_root
                .as_ref()
                .map(Sha256Digest::as_str),
            checkpoint_root.as_str(),
            checkpoint_committed_at,
        ],
    )?;
    transaction.execute(
        "INSERT INTO runtime_checkpoint_dependency_bindings (
            checkpoint_id, binding_state, dependency_generation_id,
            trust_anchor_id, canonical_bytes_sha256, source_schema_version
         ) VALUES (?1, 'authenticated', ?2, ?3, ?4, NULL)",
        params![
            batch.checkpoint_id,
            batch.dependency.dependency_generation_id.as_str(),
            batch.dependency.trust_anchor_id.as_str(),
            batch.dependency.canonical_custody.digest(),
        ],
    )?;
    for (sequence, record, prior_id, prior_root, root) in prepared {
        transaction.execute(
            "INSERT INTO runtime_record_ledger (
                record_sequence, record_id, record_schema, canonical_bytes,
                canonical_bytes_sha256, checkpoint_id, predecessor_record_id,
                predecessor_ledger_root, ledger_root, committed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                i64::try_from(sequence).map_err(|_| StoreError::Invariant(
                    "runtime record sequence overflowed".into()
                ))?,
                record.record_id,
                record.record_schema,
                record.canonical_bytes.as_bytes(),
                record.canonical_bytes.digest(),
                batch.checkpoint_id,
                prior_id,
                prior_root.as_ref().map(Sha256Digest::as_str),
                root.as_str(),
                record.committed_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO runtime_record_lookup (
                record_id, record_sequence, record_schema, ledger_root
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                record.record_id,
                i64::try_from(sequence).map_err(|_| StoreError::Invariant(
                    "runtime lookup sequence overflowed".into()
                ))?,
                record.record_schema,
                root.as_str(),
            ],
        )?;
    }
    validate_runtime_record_ledger(transaction)?;
    let lookup_status = runtime_record_lookup_status_on_connection(transaction)?;
    if !lookup_status.is_current() {
        return Err(StoreError::Integrity(
            "runtime-record append produced a stale lookup projection".into(),
        ));
    }
    let checkpoint = runtime_checkpoint_by_id_on_connection(transaction, &batch.checkpoint_id)?
        .ok_or_else(|| {
            StoreError::Integrity(format!(
                "runtime-record append lost checkpoint {}",
                batch.checkpoint_id
            ))
        })?;
    Ok(RuntimeRecordAppendReceipt {
        disposition: RuntimeRecordAppendDisposition::Committed,
        checkpoint,
    })
}

#[allow(clippy::too_many_lines)]
fn validate_runtime_record_ledger(connection: &Connection) -> Result<(), StoreError> {
    let schema_version = pragma_i64(connection, "user_version")?;
    if !matches!(schema_version, 6 | 7) {
        return Err(StoreError::Integrity(format!(
            "runtime ledger validator does not support schema {schema_version}"
        )));
    }
    let mut expected_sequence = 1_u64;
    let mut predecessor_record_id: Option<String> = None;
    let mut predecessor_root: Option<Sha256Digest> = None;
    let mut statement = connection
        .prepare("SELECT record_id FROM runtime_record_ledger ORDER BY record_sequence")?;
    let record_ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for record_id in record_ids {
        let record =
            runtime_record_by_id_on_connection(connection, &record_id)?.ok_or_else(|| {
                StoreError::Integrity(format!("runtime ledger lost record {record_id}"))
            })?;
        if record.record_sequence != expected_sequence
            || record.predecessor_record_id != predecessor_record_id
            || record.predecessor_ledger_root != predecessor_root
        {
            return Err(StoreError::Integrity(format!(
                "runtime record {} breaks global sequence or predecessor chain",
                record.record_id
            )));
        }
        Sha256Digest::parse(record.record_id.clone()).map_err(|error| {
            StoreError::Integrity(format!("runtime record identity is invalid: {error}"))
        })?;
        let input = RuntimeRecordInput {
            record_id: record.record_id.clone(),
            record_schema: record.record_schema.clone(),
            canonical_bytes: record.canonical_bytes.clone(),
            committed_at: record.committed_at.clone(),
        };
        validate_runtime_record_input(&input)
            .map_err(|error| StoreError::Integrity(error.to_string()))?;
        let expected_root = runtime_record_root(
            record.record_sequence,
            &input,
            &record.checkpoint_id,
            record.predecessor_record_id.as_deref(),
            record.predecessor_ledger_root.as_ref(),
        )
        .map_err(|error| StoreError::Integrity(error.to_string()))?;
        if record.ledger_root != expected_root {
            return Err(StoreError::Integrity(format!(
                "runtime record {} has invalid ledger root",
                record.record_id
            )));
        }
        predecessor_record_id = Some(record.record_id);
        predecessor_root = Some(record.ledger_root);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| StoreError::Integrity("runtime sequence overflowed".into()))?;
    }

    let mut expected_checkpoint_sequence = 1_u64;
    let mut expected_first_record_sequence = 1_u64;
    let mut predecessor_checkpoint_id: Option<String> = None;
    let mut predecessor_checkpoint_root: Option<Sha256Digest> = None;
    let mut statement = connection.prepare(
        "SELECT checkpoint_id FROM runtime_record_checkpoints
         ORDER BY checkpoint_sequence",
    )?;
    let checkpoint_ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for checkpoint_id in checkpoint_ids {
        let checkpoint = runtime_checkpoint_by_id_on_connection(connection, &checkpoint_id)?
            .ok_or_else(|| {
                StoreError::Integrity(format!("runtime ledger lost checkpoint {checkpoint_id}"))
            })?;
        if checkpoint.checkpoint_sequence != expected_checkpoint_sequence
            || checkpoint.first_record_sequence != expected_first_record_sequence
            || checkpoint.predecessor_checkpoint_id != predecessor_checkpoint_id
            || checkpoint.predecessor_ledger_root != predecessor_checkpoint_root
        {
            return Err(StoreError::Integrity(format!(
                "runtime checkpoint {} breaks checkpoint sequence or predecessor chain",
                checkpoint.checkpoint_id
            )));
        }
        Sha256Digest::parse(checkpoint.checkpoint_id.clone()).map_err(|error| {
            StoreError::Integrity(format!("runtime checkpoint identity is invalid: {error}"))
        })?;
        let mut records = Vec::new();
        for sequence in checkpoint.first_record_sequence..=checkpoint.last_record_sequence {
            let record = runtime_record_by_sequence_on_connection(connection, sequence)?
                .ok_or_else(|| {
                    StoreError::Integrity(format!(
                        "runtime checkpoint {} lost record sequence {sequence}",
                        checkpoint.checkpoint_id
                    ))
                })?;
            if record.checkpoint_id != checkpoint.checkpoint_id {
                return Err(StoreError::Integrity(format!(
                    "runtime checkpoint {} contains a record bound elsewhere",
                    checkpoint.checkpoint_id
                )));
            }
            records.push(RuntimeRecordInput {
                record_id: record.record_id,
                record_schema: record.record_schema,
                canonical_bytes: record.canonical_bytes,
                committed_at: record.committed_at,
            });
        }
        let expected_batch_digest = if schema_version == 6 {
            legacy_runtime_record_batch_digest(
                &checkpoint.checkpoint_id,
                checkpoint.predecessor_checkpoint_id.as_deref(),
                checkpoint.predecessor_ledger_root.as_ref(),
                &records,
            )
        } else {
            let dependency = runtime_checkpoint_dependency_on_connection(
                connection,
                &checkpoint.checkpoint_id,
            )?
            .ok_or_else(|| {
                StoreError::Integrity(format!(
                    "runtime checkpoint {} lacks dependency provenance",
                    checkpoint.checkpoint_id
                ))
            })?;
            match dependency.binding {
                RuntimeCheckpointDependencyBinding::LegacyUnbound {
                    source_schema_version: 6,
                } => legacy_runtime_record_batch_digest(
                    &checkpoint.checkpoint_id,
                    checkpoint.predecessor_checkpoint_id.as_deref(),
                    checkpoint.predecessor_ledger_root.as_ref(),
                    &records,
                ),
                RuntimeCheckpointDependencyBinding::LegacyUnbound {
                    source_schema_version,
                } => Err(StoreError::Integrity(format!(
                    "runtime checkpoint {} claims unsupported legacy schema {source_schema_version}",
                    checkpoint.checkpoint_id
                ))),
                RuntimeCheckpointDependencyBinding::Authenticated {
                    dependency_generation_id,
                    trust_anchor_id,
                    canonical_bytes_sha256,
                    canonical_bytes_length,
                } => runtime_record_batch_digest_v2(
                    &checkpoint.checkpoint_id,
                    checkpoint.predecessor_checkpoint_id.as_deref(),
                    checkpoint.predecessor_ledger_root.as_ref(),
                    &dependency_generation_id,
                    &trust_anchor_id,
                    canonical_bytes_sha256.as_str(),
                    usize::try_from(canonical_bytes_length).map_err(|_| {
                        StoreError::Integrity(format!(
                            "runtime checkpoint {} dependency custody length overflowed",
                            checkpoint.checkpoint_id
                        ))
                    })?,
                    &records,
                ),
            }
        }
        .map_err(|error| {
            if schema_version == 6 {
                StoreError::Integrity(format!(
                    "schema-v6 runtime checkpoint {} is invalid: {error}",
                    checkpoint.checkpoint_id
                ))
            } else {
                error
            }
        })
        .map_err(|error| match error {
            StoreError::Integrity(_) => error,
            other => StoreError::Integrity(other.to_string()),
        })?;
        if checkpoint.batch_digest != expected_batch_digest {
            return Err(StoreError::Integrity(format!(
                "runtime checkpoint {} has invalid batch digest",
                checkpoint.checkpoint_id
            )));
        }
        let last_record =
            runtime_record_by_sequence_on_connection(connection, checkpoint.last_record_sequence)?
                .ok_or_else(|| {
                    StoreError::Integrity(format!(
                        "runtime checkpoint {} lost its final record",
                        checkpoint.checkpoint_id
                    ))
                })?;
        if checkpoint.checkpoint_ledger_root != last_record.ledger_root {
            return Err(StoreError::Integrity(format!(
                "runtime checkpoint {} root differs from its final record",
                checkpoint.checkpoint_id
            )));
        }
        if chrono::DateTime::parse_from_rfc3339(&checkpoint.committed_at).is_err() {
            return Err(StoreError::Integrity(format!(
                "runtime checkpoint {} has invalid committed_at",
                checkpoint.checkpoint_id
            )));
        }
        predecessor_checkpoint_id = Some(checkpoint.checkpoint_id);
        predecessor_checkpoint_root = Some(checkpoint.checkpoint_ledger_root);
        expected_first_record_sequence = checkpoint
            .last_record_sequence
            .checked_add(1)
            .ok_or_else(|| StoreError::Integrity("runtime checkpoint overflowed".into()))?;
        expected_checkpoint_sequence =
            expected_checkpoint_sequence.checked_add(1).ok_or_else(|| {
                StoreError::Integrity("runtime checkpoint sequence overflowed".into())
            })?;
    }
    if expected_first_record_sequence != expected_sequence {
        return Err(StoreError::Integrity(
            "runtime checkpoint frontier does not cover the complete record ledger".into(),
        ));
    }
    if schema_version == 7 {
        validate_runtime_dependency_binding_boundary(connection)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_runtime_dependency_binding_boundary(connection: &Connection) -> Result<(), StoreError> {
    let checkpoint_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_record_checkpoints",
        [],
        |row| row.get(0),
    )?;
    let binding_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_checkpoint_dependency_bindings",
        [],
        |row| row.get(0),
    )?;
    if binding_count != checkpoint_count {
        return Err(StoreError::Integrity(format!(
            "runtime dependency binding count {binding_count} differs from checkpoint count {checkpoint_count}"
        )));
    }
    let trust_root = runtime_dependency_trust_root_on_connection(connection)?;
    let authenticated_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_checkpoint_dependency_bindings
         WHERE binding_state = 'authenticated'",
        [],
        |row| row.get(0),
    )?;
    if authenticated_count != 0 && trust_root.is_none() {
        return Err(StoreError::Integrity(
            "authenticated runtime dependency checkpoints lack a bootstrap trust root".into(),
        ));
    }
    if let Some(trust_root) = trust_root {
        let mismatched_generations: i64 = connection.query_row(
            "SELECT COUNT(*)
             FROM runtime_dependency_generation_commitments
             WHERE trust_anchor_id <> ?1",
            [trust_root.as_str()],
            |row| row.get(0),
        )?;
        let mismatched_bindings: i64 = connection.query_row(
            "SELECT COUNT(*)
             FROM runtime_checkpoint_dependency_bindings
             WHERE binding_state = 'authenticated'
               AND trust_anchor_id <> ?1",
            [trust_root.as_str()],
            |row| row.get(0),
        )?;
        if mismatched_generations != 0 || mismatched_bindings != 0 {
            return Err(StoreError::Integrity(
                "runtime dependency generation or checkpoint selected a non-bootstrap trust root"
                    .into(),
            ));
        }
    }
    let legacy_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_checkpoint_dependency_bindings
         WHERE binding_state = 'legacy_unbound'",
        [],
        |row| row.get(0),
    )?;
    let boundary = connection
        .query_row(
            "SELECT source_schema_version, source_schema_artifact_digest,
                    legacy_checkpoint_count, legacy_last_checkpoint_id,
                    legacy_last_checkpoint_root, classified_at
             FROM runtime_dependency_binding_migration_boundaries
             WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    match boundary {
        None if legacy_count == 0 => {}
        None => {
            return Err(StoreError::Integrity(
                "legacy-unbound runtime checkpoints lack a schema-v6 migration boundary".into(),
            ));
        }
        Some((source_version, source_digest, count, last_id, last_root, classified_at)) => {
            if source_version != 6
                || source_digest != SCHEMA_V6_ARTIFACT_DIGEST
                || count != legacy_count
                || count < 0
                || chrono::DateTime::parse_from_rfc3339(&classified_at).is_err()
            {
                return Err(StoreError::Integrity(
                    "runtime dependency migration boundary is invalid".into(),
                ));
            }
            let nonprefix_legacy: i64 = connection.query_row(
                "SELECT COUNT(*)
                 FROM runtime_checkpoint_dependency_bindings AS binding
                 JOIN runtime_record_checkpoints AS checkpoint
                   ON checkpoint.checkpoint_id = binding.checkpoint_id
                 WHERE binding.binding_state = 'legacy_unbound'
                   AND checkpoint.checkpoint_sequence > ?1",
                [count],
                |row| row.get(0),
            )?;
            let prefix_authenticated: i64 = connection.query_row(
                "SELECT COUNT(*)
                 FROM runtime_checkpoint_dependency_bindings AS binding
                 JOIN runtime_record_checkpoints AS checkpoint
                   ON checkpoint.checkpoint_id = binding.checkpoint_id
                 WHERE binding.binding_state = 'authenticated'
                   AND checkpoint.checkpoint_sequence <= ?1",
                [count],
                |row| row.get(0),
            )?;
            if nonprefix_legacy != 0 || prefix_authenticated != 0 {
                return Err(StoreError::Integrity(
                    "schema-v6 legacy dependency bindings are not one exact checkpoint prefix"
                        .into(),
                ));
            }
            if count == 0 {
                if last_id.is_some() || last_root.is_some() {
                    return Err(StoreError::Integrity(
                        "empty schema-v6 boundary invents a legacy frontier".into(),
                    ));
                }
            } else {
                let observed = connection
                    .query_row(
                        "SELECT checkpoint_id, checkpoint_ledger_root
                         FROM runtime_record_checkpoints
                         WHERE checkpoint_sequence = ?1",
                        [count],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                if observed != last_id.zip(last_root) {
                    return Err(StoreError::Integrity(
                        "schema-v6 dependency boundary frontier was substituted".into(),
                    ));
                }
            }
        }
    }
    let unreferenced_commitments: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM runtime_dependency_generation_commitments AS generation
         LEFT JOIN runtime_checkpoint_dependency_bindings AS binding
           ON binding.dependency_generation_id = generation.dependency_generation_id
         WHERE binding.checkpoint_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    if unreferenced_commitments != 0 {
        return Err(StoreError::Integrity(format!(
            "{unreferenced_commitments} runtime dependency commitments are not bound to checkpoints"
        )));
    }
    Ok(())
}

fn runtime_record_reference_matches(value: &Value, record: &RuntimeRecordRow) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == 3
            && object.get("schema").and_then(Value::as_str) == Some(record.record_schema.as_str())
            && object.get("record_id").and_then(Value::as_str) == Some(record.record_id.as_str())
            && object.get("bytes_digest").and_then(Value::as_str)
                == Some(record.canonical_bytes_sha256.as_str())
    })
}

fn diagnostic_artifact_execution_binding_on_connection(
    connection: &Connection,
    artifact_id: &Sha256Digest,
) -> Result<Option<DiagnosticArtifactExecutionBinding>, StoreError> {
    let linkage = connection
        .query_row(
            "SELECT execution_binding_record_id, outer_request_record_id,
                    invocation_decision_record_id, execution_launch_record_id,
                    outer_request_id
             FROM local_diagnostic_artifact_origins WHERE artifact_id = ?1",
            [artifact_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((
        execution_binding_record_id,
        outer_request_record_id,
        invocation_decision_record_id,
        execution_launch_record_id,
        outer_request_id,
    )) = linkage
    else {
        return Ok(None);
    };
    let linkage = match (
        execution_binding_record_id,
        outer_request_record_id,
        invocation_decision_record_id,
        execution_launch_record_id,
        outer_request_id,
    ) {
        (None, None, None, None, None) => return Ok(None),
        (Some(binding), Some(request), Some(decision), Some(launch), Some(request_id)) => {
            (binding, request, decision, launch, request_id)
        }
        _ => {
            return Err(StoreError::Integrity(format!(
                "diagnostic artifact {artifact_id} has a partial production execution binding"
            )));
        }
    };
    let exact_record = |record_id: &str| {
        runtime_record_by_id_on_connection(connection, record_id)?.ok_or_else(|| {
            StoreError::Integrity(format!(
                "diagnostic artifact {artifact_id} binding lost runtime record {record_id}"
            ))
        })
    };
    let execution_binding = exact_record(&linkage.0)?;
    let outer_request = exact_record(&linkage.1)?;
    let invocation_decision = exact_record(&linkage.2)?;
    let execution_launch = exact_record(&linkage.3)?;
    let mut statement = connection.prepare(
        "SELECT provider_attempt_record_id, intake_id
         FROM local_diagnostic_artifact_provider_attempt_bindings
         WHERE artifact_id = ?1 ORDER BY ordinal",
    )?;
    let attempt_links = statement
        .query_map([artifact_id.as_str()], |row| {
            Ok(DiagnosticArtifactProviderAttemptBindingInput {
                provider_attempt_record_id: row.get(0)?,
                intake_id: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let provider_attempts = attempt_links
        .into_iter()
        .map(|attempt| {
            let record = exact_record(&attempt.provider_attempt_record_id)?;
            Ok((record, attempt))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let resolved = DiagnosticArtifactExecutionBinding {
        execution_binding,
        outer_request,
        invocation_decision,
        execution_launch,
        outer_request_id: linkage.4,
        provider_attempts,
    };
    validate_resolved_diagnostic_artifact_execution_binding(connection, artifact_id, &resolved)?;
    Ok(Some(resolved))
}

fn validate_diagnostic_artifact_execution_binding(
    connection: &Connection,
    artifact_id: &Sha256Digest,
    input: &DiagnosticArtifactExecutionBindingInput,
) -> Result<(), StoreError> {
    let resolved = diagnostic_artifact_execution_binding_on_connection(connection, artifact_id)?
        .ok_or_else(|| {
            StoreError::Integrity(format!(
                "diagnostic artifact {artifact_id} lost its production execution binding"
            ))
        })?;
    if resolved.execution_binding.record_id != input.execution_binding_record_id
        || resolved.outer_request.record_id != input.outer_request_record_id
        || resolved.invocation_decision.record_id != input.invocation_decision_record_id
        || resolved.execution_launch.record_id != input.execution_launch_record_id
        || resolved.outer_request_id != input.outer_request_id
        || resolved
            .provider_attempts
            .iter()
            .map(|(_, attempt)| attempt)
            .ne(input.provider_attempts.iter())
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} production binding differs after persistence"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_resolved_diagnostic_artifact_execution_binding(
    connection: &Connection,
    artifact_id: &Sha256Digest,
    binding: &DiagnosticArtifactExecutionBinding,
) -> Result<(), StoreError> {
    if binding.execution_binding.record_schema != "nq.execution_identity_binding.v2"
        || binding.outer_request.record_schema != "nq.diagnostic_invocation_request.v1"
        || binding.invocation_decision.record_schema != "nq.invocation_decision.v1"
        || binding.execution_launch.record_schema != "nq.execution_launch.v1"
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} production binding uses an incompatible record schema"
        )));
    }
    if binding.provider_attempts.is_empty()
        || binding
            .provider_attempts
            .iter()
            .any(|(record, _)| record.record_schema != "nq.provider_intake.v1")
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} requires exact provider-intake record links"
        )));
    }
    let binding_value: Value = serde_json::from_slice(
        binding.execution_binding.canonical_bytes.as_bytes(),
    )
    .map_err(|error| {
        StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} binding cannot decode: {error}"
        ))
    })?;
    if binding_value.get("binding_id").and_then(Value::as_str)
        != Some(binding.execution_binding.record_id.as_str())
        || !binding_value
            .get("outer_request")
            .is_some_and(|value| runtime_record_reference_matches(value, &binding.outer_request))
        || !binding_value
            .get("invocation_decision")
            .is_some_and(|value| {
                runtime_record_reference_matches(value, &binding.invocation_decision)
            })
        || !binding_value
            .get("execution_launch")
            .is_some_and(|value| runtime_record_reference_matches(value, &binding.execution_launch))
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} binding record references differ from exact linked records"
        )));
    }
    let request_value: Value = serde_json::from_slice(
        binding.outer_request.canonical_bytes.as_bytes(),
    )
    .map_err(|error| {
        StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} outer request cannot decode: {error}"
        ))
    })?;
    if request_value.get("request_id").and_then(Value::as_str)
        != Some(binding.outer_request_id.as_str())
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} outer request identity differs from linkage"
        )));
    }
    let launch_value: Value = serde_json::from_slice(
        binding.execution_launch.canonical_bytes.as_bytes(),
    )
    .map_err(|error| {
        StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} launch cannot decode: {error}"
        ))
    })?;
    if !launch_value
        .get("outer_request")
        .is_some_and(|value| runtime_record_reference_matches(value, &binding.outer_request))
        || !launch_value
            .get("invocation_decision")
            .is_some_and(|value| {
                runtime_record_reference_matches(value, &binding.invocation_decision)
            })
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} launch does not bind its exact request and decision"
        )));
    }
    let diagnostic = binding_value
        .get("diagnostic")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StoreError::Integrity(format!(
                "diagnostic artifact {artifact_id} binding has no diagnostic identity"
            ))
        })?;
    let commitment = connection.query_row(
        "SELECT canonical_bytes_sha256 FROM diagnostic_artifact_commitments
         WHERE artifact_id = ?1",
        [artifact_id.as_str()],
        |row| row.get::<_, String>(0),
    )?;
    if diagnostic.get("schema").and_then(Value::as_str) != Some("nq.diagnostic_execution.v2")
        || diagnostic.get("request_id").and_then(Value::as_str)
            != Some(binding.outer_request_id.as_str())
        || diagnostic.get("artifact_id").and_then(Value::as_str) != Some(artifact_id.as_str())
        || diagnostic.get("file_bytes_digest").and_then(Value::as_str) != Some(commitment.as_str())
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} binding does not identify its exact V2 bytes and outer request"
        )));
    }
    let provider_references = binding_value
        .get("provider_attempts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            StoreError::Integrity(format!(
                "diagnostic artifact {artifact_id} binding has no provider-attempt list"
            ))
        })?;
    if provider_references.len() != binding.provider_attempts.len()
        || provider_references
            .iter()
            .zip(&binding.provider_attempts)
            .any(|(reference, (record, _))| !runtime_record_reference_matches(reference, record))
    {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} binding provider attempts differ from exact links"
        )));
    }
    for (record, attempt) in &binding.provider_attempts {
        let (intake_digest, child_request_id): (String, String) = connection
            .query_row(
                "SELECT intake_digest, request_id FROM provider_intake_attempts
                 WHERE intake_id = ?1",
                [&attempt.intake_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| {
                StoreError::Integrity(format!(
                    "diagnostic artifact {artifact_id} provider attempt {} is not retained: {error}",
                    attempt.intake_id
                ))
            })?;
        if record.record_id != intake_digest {
            return Err(StoreError::Integrity(format!(
                "diagnostic artifact {artifact_id} provider record identity is not intake digest {}",
                attempt.intake_id
            )));
        }
        if child_request_id == binding.outer_request_id {
            return Err(StoreError::Integrity(format!(
                "diagnostic artifact {artifact_id} collapses outer and child request identity"
            )));
        }
    }
    Ok(())
}

fn validate_diagnostic_artifact_document(
    artifact_id: &Sha256Digest,
    contract_schema: &str,
    canonical_bytes: &CanonicalDocument,
) -> Result<(), StoreError> {
    validate_bounded_identity("diagnostic artifact contract_schema", contract_schema)?;
    if canonical_document_schema(canonical_bytes)? != contract_schema {
        return Err(StoreError::Invariant(format!(
            "diagnostic artifact {artifact_id} contract schema disagrees with its canonical bytes"
        )));
    }
    Ok(())
}

fn insert_diagnostic_artifact_commitment(
    transaction: &Transaction<'_>,
    artifact_id: &Sha256Digest,
    contract_schema: &str,
    canonical_bytes: &CanonicalDocument,
    committed_at: &str,
) -> Result<(), StoreError> {
    validate_diagnostic_artifact_document(artifact_id, contract_schema, canonical_bytes)?;
    if chrono::DateTime::parse_from_rfc3339(committed_at).is_err() {
        return Err(StoreError::Invariant(
            "diagnostic artifact committed_at is not RFC 3339".into(),
        ));
    }
    let byte_length = i64::try_from(canonical_bytes.as_bytes().len())
        .map_err(|_| StoreError::Invariant("diagnostic artifact length overflowed".into()))?;
    transaction.execute(
        "INSERT INTO diagnostic_artifact_commitments (
            artifact_id, contract_schema, canonical_bytes_sha256,
            canonical_bytes_length, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            artifact_id.as_str(),
            contract_schema,
            canonical_bytes.digest(),
            byte_length,
            committed_at,
        ],
    )?;
    transaction.execute(
        "INSERT INTO diagnostic_artifact_payloads (
            artifact_id, canonical_bytes
         ) VALUES (?1, ?2)",
        params![artifact_id.as_str(), canonical_bytes.as_bytes()],
    )?;
    Ok(())
}

fn diagnostic_artifact_id_for_run_on_connection(
    connection: &Connection,
    run_id: &str,
) -> Result<Option<Sha256Digest>, StoreError> {
    let artifact_id = connection
        .query_row(
            "SELECT artifact_id FROM local_diagnostic_artifact_origins WHERE run_id = ?1",
            [run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    artifact_id
        .map(|value| {
            Sha256Digest::parse(value).map_err(|error| {
                StoreError::Integrity(format!(
                    "local diagnostic artifact for run {run_id} has invalid identity: {error}"
                ))
            })
        })
        .transpose()
}

fn validate_local_diagnostic_artifact_provenance(
    artifact: &DiagnosticArtifactCommitInput,
    run: &RunInput,
) -> Result<(), StoreError> {
    let request_id = artifact
        .local_origin
        .execution_binding
        .as_ref()
        .map_or(run.request_id.as_str(), |binding| {
            binding.outer_request_id.as_str()
        });
    validate_local_diagnostic_artifact_provenance_fields(
        &artifact.canonical_bytes,
        &run.run_id,
        request_id,
        &run.profile_id,
        &run.profile_version,
        &run.profile_digest,
        &artifact.local_origin.completed_at,
    )
}

fn validate_local_diagnostic_artifact_provenance_fields(
    canonical_bytes: &CanonicalDocument,
    run_id: &str,
    request_id: &str,
    profile_id: &str,
    profile_version: &str,
    profile_digest: &str,
    completed_at: &str,
) -> Result<(), StoreError> {
    let value: Value = serde_json::from_slice(canonical_bytes.as_bytes())
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    let string_at = |pointer: &str| {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StoreError::Invariant(format!(
                    "local diagnostic artifact has no string provenance field {pointer}"
                ))
            })
    };
    let artifact_run_id = string_at("/run_id")?;
    let artifact_request_id = string_at("/request_id")?;
    let artifact_profile_id = string_at("/profile/id")?;
    let artifact_profile_version = string_at("/profile/version")?;
    let artifact_profile_digest = string_at("/profile/digest")?;
    let artifact_completed_at = string_at("/completed_at")?;
    let origin_completed_at = chrono::DateTime::parse_from_rfc3339(completed_at).map_err(|_| {
        StoreError::Invariant(
            "local diagnostic artifact origin completed_at is not RFC 3339".into(),
        )
    })?;
    let artifact_completed_at = chrono::DateTime::parse_from_rfc3339(artifact_completed_at)
        .map_err(|_| {
            StoreError::Invariant("local diagnostic artifact completed_at is not RFC 3339".into())
        })?;
    if artifact_run_id != run_id
        || artifact_request_id != request_id
        || artifact_profile_id != profile_id
        || artifact_profile_version != profile_version
        || artifact_profile_digest != profile_digest
        || artifact_completed_at != origin_completed_at
    {
        return Err(StoreError::Invariant(
            "local diagnostic artifact run, request, or profile provenance or completion time differs from its origin".into(),
        ));
    }
    Ok(())
}

fn insert_local_diagnostic_artifact<T>(
    transaction: &Transaction<'_>,
    collection: &CollectionInput,
    completion: &AdmittedCollectionCompletion<T>,
    artifact: &DiagnosticArtifactCommitInput,
    origin_mode: AdmittedDiagnosticOriginMode,
) -> Result<(), StoreError> {
    if artifact.local_origin.run_id != collection.run.run_id {
        return Err(StoreError::Invariant(
            "local diagnostic artifact run differs from its admitted collection".into(),
        ));
    }
    if matches!(
        origin_mode,
        AdmittedDiagnosticOriginMode::RunLevelProduction
    ) && artifact.local_origin.execution_binding.is_none()
    {
        return Err(StoreError::Invariant(
            "admitted run-level diagnostic requires an exact production binding".into(),
        ));
    }
    validate_local_diagnostic_artifact_provenance(artifact, &collection.run)?;
    match origin_mode {
        AdmittedDiagnosticOriginMode::DetectorEvaluation => {
            let evaluation_id =
                artifact
                    .local_origin
                    .evaluation_id
                    .as_deref()
                    .ok_or_else(|| {
                        StoreError::Invariant(
                            "admitted detector diagnostic requires an exact evaluation origin"
                                .into(),
                        )
                    })?;
            let matching_evaluations = completion
                .evaluations
                .iter()
                .filter(|input| input.evaluation.evaluation_id == evaluation_id)
                .collect::<Vec<_>>();
            let [evaluation] = matching_evaluations.as_slice() else {
                return Err(StoreError::Invariant(
                    "local diagnostic artifact requires exactly one evaluation in the same completion"
                        .into(),
                ));
            };
            if evaluation.evaluation.trigger_run_id.as_deref()
                != Some(artifact.local_origin.run_id.as_str())
            {
                return Err(StoreError::Invariant(
                    "local diagnostic artifact evaluation is not triggered by its bound run".into(),
                ));
            }
        }
        AdmittedDiagnosticOriginMode::RunLevelProduction => {
            let binding = artifact
                .local_origin
                .execution_binding
                .as_ref()
                .ok_or_else(|| {
                    StoreError::Invariant(
                        "admitted run-level diagnostic requires an exact production binding".into(),
                    )
                })?;
            let current_provider_record_id = provider_intake_record_id(&collection.intake)?;
            let exact_current_attempts = binding
                .provider_attempts
                .iter()
                .filter(|attempt| {
                    attempt.intake_id == collection.intake.intake_id
                        && attempt.provider_attempt_record_id == current_provider_record_id.as_str()
                })
                .count();
            if !completion.evaluations.is_empty()
                || artifact.local_origin.evaluation_id.is_some()
                || artifact.contract_schema != "nq.diagnostic_execution.v2"
                || binding.provider_attempts.len() != 1
                || exact_current_attempts != 1
            {
                return Err(StoreError::Invariant(
                    "admitted run-level diagnostic requires zero evaluations, no evaluation origin, exactly the current provider attempt, exact production binding, and V2 contract"
                        .into(),
                ));
            }
        }
    }
    insert_local_diagnostic_artifact_rows(transaction, artifact)
}

fn validate_admitted_run_level_diagnostic_replay(
    connection: &Connection,
    run_id: &str,
) -> Result<(), StoreError> {
    validate_diagnostic_artifact_invariants(connection)?;
    let evaluation_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM evaluation_runs WHERE trigger_run_id = ?1",
        [run_id],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare(
        "SELECT local.artifact_id
         FROM local_diagnostic_artifact_origins AS local
         JOIN diagnostic_artifact_commitments AS commitment
           ON commitment.artifact_id = local.artifact_id
         WHERE local.run_id = ?1
           AND local.evaluation_id IS NULL
           AND commitment.contract_schema = 'nq.diagnostic_execution.v2'
           AND local.execution_binding_record_id IS NOT NULL
           AND local.outer_request_record_id IS NOT NULL
           AND local.invocation_decision_record_id IS NOT NULL
           AND local.execution_launch_record_id IS NOT NULL
           AND local.outer_request_id IS NOT NULL",
    )?;
    let artifact_ids = statement
        .query_map([run_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let [artifact_id] = artifact_ids.as_slice() else {
        return Err(StoreError::ReplayConflict(format!(
            "existing admitted run {run_id} is not one exact run-level V2 diagnostic"
        )));
    };
    if evaluation_count != 0 {
        return Err(StoreError::ReplayConflict(format!(
            "existing admitted run {run_id} has detector evaluations"
        )));
    }
    let artifact_id = Sha256Digest::parse(artifact_id.clone()).map_err(|error| {
        StoreError::Integrity(format!(
            "existing run-level diagnostic has invalid artifact identity: {error}"
        ))
    })?;
    if diagnostic_artifact_execution_binding_on_connection(connection, &artifact_id)?.is_none() {
        return Err(StoreError::ReplayConflict(format!(
            "existing admitted run {run_id} has no exact production execution binding"
        )));
    }
    let current_provider_attempts: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM local_diagnostic_artifact_provider_attempt_bindings AS binding
         JOIN local_watcher_provider_intakes AS local
           ON local.intake_id = binding.intake_id
         WHERE binding.artifact_id = ?1
           AND local.run_id = ?2",
        params![artifact_id.as_str(), run_id],
        |row| row.get(0),
    )?;
    let all_provider_attempts: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM local_diagnostic_artifact_provider_attempt_bindings
         WHERE artifact_id = ?1",
        [artifact_id.as_str()],
        |row| row.get(0),
    )?;
    if current_provider_attempts != 1 || all_provider_attempts != 1 {
        return Err(StoreError::ReplayConflict(format!(
            "existing admitted run {run_id} is not bound to exactly its current provider attempt"
        )));
    }
    Ok(())
}

fn validate_run_only_diagnostic_artifact(
    collection: &CollectionInput,
    artifact: &DiagnosticArtifactCommitInput,
) -> Result<(), StoreError> {
    if artifact.local_origin.run_id != collection.run.run_id {
        return Err(StoreError::Invariant(
            "run-only diagnostic artifact differs from its non-success collection run".into(),
        ));
    }
    if artifact.local_origin.evaluation_id.is_some() {
        return Err(StoreError::Invariant(
            "run-only diagnostic artifact cannot claim an evaluation origin".into(),
        ));
    }
    validate_local_diagnostic_artifact_provenance(artifact, &collection.run)
}

fn insert_run_only_diagnostic_artifact(
    transaction: &Transaction<'_>,
    collection: &CollectionInput,
    artifact: &DiagnosticArtifactCommitInput,
) -> Result<(), StoreError> {
    validate_run_only_diagnostic_artifact(collection, artifact)?;
    insert_local_diagnostic_artifact_rows(transaction, artifact)
}

fn fail_non_success_after_artifact_insert_for_test() -> bool {
    #[cfg(test)]
    {
        FAIL_NON_SUCCESS_AFTER_ARTIFACT_INSERT.with(std::cell::Cell::take)
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn insert_local_diagnostic_artifact_rows(
    transaction: &Transaction<'_>,
    artifact: &DiagnosticArtifactCommitInput,
) -> Result<(), StoreError> {
    if let Some(binding) = &artifact.local_origin.execution_binding {
        let receipt = append_runtime_records_in_transaction(transaction, &binding.runtime_records)?;
        if receipt.disposition != RuntimeRecordAppendDisposition::Committed {
            return Err(StoreError::ReplayConflict(
                "a production artifact binding must be committed atomically with its runtime records"
                    .into(),
            ));
        }
    }
    let committed_at = now_utc();
    insert_diagnostic_artifact_commitment(
        transaction,
        &artifact.artifact_id,
        &artifact.contract_schema,
        &artifact.canonical_bytes,
        &committed_at,
    )?;
    transaction.execute(
        "INSERT INTO local_diagnostic_artifact_origins (
            artifact_id, run_id, evaluation_id, completed_at,
            execution_binding_record_id, outer_request_record_id,
            invocation_decision_record_id, execution_launch_record_id,
            outer_request_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            artifact.artifact_id.as_str(),
            artifact.local_origin.run_id,
            artifact.local_origin.evaluation_id,
            artifact.local_origin.completed_at,
            artifact
                .local_origin
                .execution_binding
                .as_ref()
                .map(|binding| binding.execution_binding_record_id.as_str()),
            artifact
                .local_origin
                .execution_binding
                .as_ref()
                .map(|binding| binding.outer_request_record_id.as_str()),
            artifact
                .local_origin
                .execution_binding
                .as_ref()
                .map(|binding| binding.invocation_decision_record_id.as_str()),
            artifact
                .local_origin
                .execution_binding
                .as_ref()
                .map(|binding| binding.execution_launch_record_id.as_str()),
            artifact
                .local_origin
                .execution_binding
                .as_ref()
                .map(|binding| binding.outer_request_id.as_str()),
        ],
    )?;
    if let Some(binding) = &artifact.local_origin.execution_binding {
        if binding.provider_attempts.is_empty() {
            return Err(StoreError::Invariant(
                "production diagnostic binding requires at least one provider attempt".into(),
            ));
        }
        for (ordinal, attempt) in binding.provider_attempts.iter().enumerate() {
            transaction.execute(
                "INSERT INTO local_diagnostic_artifact_provider_attempt_bindings (
                    artifact_id, ordinal, provider_attempt_record_id, intake_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    artifact.artifact_id.as_str(),
                    i64::try_from(ordinal).map_err(|_| StoreError::Invariant(
                        "provider-attempt ordinal overflowed".into()
                    ))?,
                    attempt.provider_attempt_record_id,
                    attempt.intake_id,
                ],
            )?;
        }
        validate_diagnostic_artifact_execution_binding(
            transaction,
            &artifact.artifact_id,
            binding,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep exact commitment/origin reopening in one fail-closed audit.
fn diagnostic_artifact_commitment_on_connection(
    connection: &Connection,
    artifact_id: &Sha256Digest,
) -> Result<Option<DiagnosticArtifactCommitment>, StoreError> {
    let row = connection
        .query_row(
            "SELECT artifact_sequence, artifact_id, contract_schema,
                    canonical_bytes_sha256, canonical_bytes_length, committed_at
             FROM diagnostic_artifact_commitments WHERE artifact_id = ?1",
            [artifact_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((sequence, stored_id, contract_schema, bytes_digest, byte_length, committed_at)) = row
    else {
        return Ok(None);
    };
    if sequence <= 0 || byte_length <= 0 {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {stored_id} has a nonpositive sequence or byte length"
        )));
    }
    validate_bounded_identity(
        "persisted diagnostic artifact contract_schema",
        &contract_schema,
    )
    .map_err(|error| StoreError::Integrity(error.to_string()))?;
    if chrono::DateTime::parse_from_rfc3339(&committed_at).is_err() {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {stored_id} has invalid committed_at"
        )));
    }
    let stored_id = Sha256Digest::parse(stored_id).map_err(|error| {
        StoreError::Integrity(format!("diagnostic artifact identity is invalid: {error}"))
    })?;
    let canonical_bytes_sha256 = Sha256Digest::parse(bytes_digest).map_err(|error| {
        StoreError::Integrity(format!(
            "diagnostic artifact {stored_id} byte digest is invalid: {error}"
        ))
    })?;
    let local_origin = connection
        .query_row(
            "SELECT run_id, evaluation_id, completed_at,
                    execution_binding_record_id
             FROM local_diagnostic_artifact_origins
             WHERE artifact_id = ?1",
            [stored_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?;
    let imported_origin = connection
        .query_row(
            "SELECT import_id, imported_at FROM imported_diagnostic_artifact_origins
             WHERE artifact_id = ?1",
            [stored_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let origin = match (local_origin, imported_origin) {
        (Some((run_id, evaluation_id, completed_at, execution_binding_record_id)), None) => {
            let completed = chrono::DateTime::parse_from_rfc3339(&completed_at).map_err(|_| {
                StoreError::Integrity(format!(
                    "local diagnostic artifact {stored_id} has invalid completed_at"
                ))
            })?;
            let committed =
                chrono::DateTime::parse_from_rfc3339(&committed_at).expect("validated above");
            if completed > committed {
                return Err(StoreError::Integrity(format!(
                    "local diagnostic artifact {stored_id} completes after its custody commitment"
                )));
            }
            DiagnosticArtifactOrigin::Local {
                run_id,
                evaluation_id,
                completed_at,
                execution_binding_record_id,
            }
        }
        (None, Some((import_id, imported_at))) => {
            if chrono::DateTime::parse_from_rfc3339(&imported_at).is_err() {
                return Err(StoreError::Integrity(format!(
                    "diagnostic artifact {stored_id} has invalid imported_at"
                )));
            }
            DiagnosticArtifactOrigin::Imported {
                import_id,
                imported_at,
            }
        }
        (None, None) => {
            return Err(StoreError::Integrity(format!(
                "diagnostic artifact {stored_id} has no exact origin"
            )));
        }
        (Some(_), Some(_)) => {
            return Err(StoreError::Integrity(format!(
                "diagnostic artifact {stored_id} has more than one exact origin"
            )));
        }
    };
    Ok(Some(DiagnosticArtifactCommitment {
        artifact_sequence: u64::try_from(sequence)
            .map_err(|_| StoreError::Integrity("diagnostic artifact sequence overflowed".into()))?,
        artifact_id: stored_id,
        contract_schema,
        canonical_bytes_sha256,
        canonical_bytes_length: u64::try_from(byte_length).map_err(|_| {
            StoreError::Integrity("diagnostic artifact byte length overflowed".into())
        })?,
        committed_at,
        origin,
    }))
}

fn diagnostic_artifact_on_connection(
    connection: &Connection,
    artifact_id: &Sha256Digest,
    supported_contract_schemas: &[&str],
) -> Result<DiagnosticArtifactLookup, StoreError> {
    let Some(commitment) = diagnostic_artifact_commitment_on_connection(connection, artifact_id)?
    else {
        return Ok(DiagnosticArtifactLookup::NotFound);
    };
    let schema_support =
        if supported_contract_schemas.contains(&commitment.contract_schema.as_str()) {
            DiagnosticArtifactSchemaSupport::Supported
        } else {
            DiagnosticArtifactSchemaSupport::Unsupported {
                contract_schema: commitment.contract_schema.clone(),
            }
        };
    let payload = connection
        .query_row(
            "SELECT canonical_bytes FROM diagnostic_artifact_payloads
             WHERE artifact_id = ?1",
            [artifact_id.as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let byte_state = match payload {
        None => DiagnosticArtifactByteState::CommittedUnavailable,
        Some(bytes) => {
            let actual_length = u64::try_from(bytes.len())
                .map_err(|_| StoreError::Integrity("artifact byte length overflowed".into()))?;
            let actual_digest = sha256_digest(&bytes);
            if actual_length != commitment.canonical_bytes_length {
                DiagnosticArtifactByteState::Corrupt {
                    reason: format!(
                        "stored byte length {actual_length} differs from committed {}",
                        commitment.canonical_bytes_length
                    ),
                }
            } else if actual_digest != commitment.canonical_bytes_sha256.as_str() {
                DiagnosticArtifactByteState::Corrupt {
                    reason: format!(
                        "stored byte digest {actual_digest} differs from committed {}",
                        commitment.canonical_bytes_sha256
                    ),
                }
            } else {
                match CanonicalDocument::from_canonical_bytes(bytes) {
                    Err(error) => DiagnosticArtifactByteState::Corrupt {
                        reason: format!("stored bytes are not canonical JSON: {error}"),
                    },
                    Ok(document) => match canonical_document_schema(&document) {
                        Ok(schema) if schema == commitment.contract_schema => {
                            DiagnosticArtifactByteState::VerifiedAvailable {
                                canonical_bytes: document,
                            }
                        }
                        Ok(schema) => DiagnosticArtifactByteState::Corrupt {
                            reason: format!(
                                "stored contract schema {schema} differs from committed {}",
                                commitment.contract_schema
                            ),
                        },
                        Err(error) => DiagnosticArtifactByteState::Corrupt {
                            reason: error.to_string(),
                        },
                    },
                }
            }
        }
    };
    Ok(DiagnosticArtifactLookup::Found(DiagnosticArtifactAccess {
        commitment,
        schema_support,
        byte_state,
    }))
}

fn validate_diagnostic_artifact_invariants(connection: &Connection) -> Result<(), StoreError> {
    validate_diagnostic_artifact_origin_cardinality(connection)?;
    validate_diagnostic_artifact_import_history(connection)?;
    validate_local_diagnostic_artifact_origin_modes(connection)?;
    validate_local_diagnostic_artifact_provenance_history(connection)
}

fn validate_diagnostic_artifact_import_history(connection: &Connection) -> Result<(), StoreError> {
    let invalid_correspondence: Option<(String, String)> = connection
        .query_row(
            "SELECT event.import_id, event.artifact_id
             FROM diagnostic_artifact_import_events AS event
             LEFT JOIN diagnostic_artifact_commitments AS commitment
               ON commitment.artifact_id = event.artifact_id
             LEFT JOIN imported_diagnostic_artifact_origins AS origin
               ON origin.import_id = event.import_id
             WHERE commitment.artifact_id IS NULL
                OR event.contract_schema <> commitment.contract_schema
                OR event.canonical_bytes_sha256 <> commitment.canonical_bytes_sha256
                OR event.canonical_bytes_length <> commitment.canonical_bytes_length
                OR (
                    event.outcome IN ('committed', 'committed_unavailable')
                    AND (
                        origin.artifact_id IS NULL
                        OR origin.artifact_id <> event.artifact_id
                        OR origin.imported_at <> event.imported_at
                        OR origin.initial_outcome <> event.outcome
                        OR commitment.committed_at <> event.imported_at
                    )
                )
                OR (
                    event.outcome IN ('existing', 'rematerialized')
                    AND origin.artifact_id IS NOT NULL
                )
             ORDER BY event.import_sequence
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((import_id, artifact_id)) = invalid_correspondence {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact import receipt {import_id} does not exactly correspond to commitment {artifact_id} and its custody origin"
        )));
    }

    let mut statement = connection.prepare(
        "SELECT import_id, imported_at
         FROM diagnostic_artifact_import_events
         ORDER BY import_sequence",
    )?;
    let events = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (import_id, imported_at) in events {
        if chrono::DateTime::parse_from_rfc3339(&imported_at).is_err() {
            return Err(StoreError::Integrity(format!(
                "diagnostic artifact import receipt {import_id} has invalid imported_at"
            )));
        }
    }
    Ok(())
}

fn validate_diagnostic_artifact_origin_cardinality(
    connection: &Connection,
) -> Result<(), StoreError> {
    let invalid_origin: Option<(String, i64)> = connection
        .query_row(
            "SELECT commitment.artifact_id,
                    (SELECT COUNT(*) FROM local_diagnostic_artifact_origins AS local
                     WHERE local.artifact_id = commitment.artifact_id)
                  + (SELECT COUNT(*) FROM imported_diagnostic_artifact_origins AS imported
                     WHERE imported.artifact_id = commitment.artifact_id) AS origin_count
             FROM diagnostic_artifact_commitments AS commitment
             WHERE (
                    (SELECT COUNT(*) FROM local_diagnostic_artifact_origins AS local
                     WHERE local.artifact_id = commitment.artifact_id)
                  + (SELECT COUNT(*) FROM imported_diagnostic_artifact_origins AS imported
                     WHERE imported.artifact_id = commitment.artifact_id)
                   ) <> 1
             ORDER BY commitment.artifact_sequence LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((artifact_id, count)) = invalid_origin {
        return Err(StoreError::Integrity(format!(
            "diagnostic artifact {artifact_id} requires exactly one origin; found {count}"
        )));
    }
    Ok(())
}

fn validate_local_diagnostic_artifact_origin_modes(
    connection: &Connection,
) -> Result<(), StoreError> {
    let invalid_evaluated_local: Option<String> = connection
        .query_row(
            "SELECT local.artifact_id
             FROM local_diagnostic_artifact_origins AS local
             LEFT JOIN evaluation_runs AS evaluation
               ON evaluation.evaluation_id = local.evaluation_id
             WHERE local.evaluation_id IS NOT NULL
               AND (
                    evaluation.evaluation_id IS NULL
                 OR evaluation.trigger_run_id IS NOT local.run_id
               )
             ORDER BY local.artifact_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(artifact_id) = invalid_evaluated_local {
        return Err(StoreError::Integrity(format!(
            "local diagnostic artifact {artifact_id} run/evaluation linkage disagrees"
        )));
    }
    // Schema v7 is the first format that can retain the exact production
    // binding required by an admitted run-level V2 artifact. During the
    // qualified v4→v5→v6 migration path this validator must retain the older
    // rule rather than preparing references to columns that do not yet exist.
    let admitted_run_level_requirement = if pragma_i64(connection, "user_version")? >= 7 {
        "AND (
             NOT EXISTS (
                 SELECT 1 FROM raw_submissions AS submission
                 WHERE submission.run_id = local.run_id
                   AND submission.admission_outcome = 'admitted'
             )
          OR commitment.contract_schema <> 'nq.diagnostic_execution.v2'
          OR local.execution_binding_record_id IS NULL
          OR local.outer_request_record_id IS NULL
          OR local.invocation_decision_record_id IS NULL
          OR local.execution_launch_record_id IS NULL
          OR local.outer_request_id IS NULL
         )"
    } else {
        ""
    };
    let invalid_run_only_query = format!(
        "SELECT local.artifact_id
             FROM local_diagnostic_artifact_origins AS local
             JOIN watcher_runs AS run ON run.run_id = local.run_id
             JOIN diagnostic_artifact_commitments AS commitment
               ON commitment.artifact_id = local.artifact_id
             WHERE local.evaluation_id IS NULL
               AND (
                    EXISTS (
                        SELECT 1 FROM evaluation_runs AS evaluation
                        WHERE evaluation.trigger_run_id = local.run_id
                    )
                 OR (
                        run.acquisition_outcome = 'response'
                    AND NOT EXISTS (
                        SELECT 1 FROM raw_submissions AS submission
                        WHERE submission.run_id = local.run_id
                          AND submission.admission_outcome = 'rejected'
                    )
                    {admitted_run_level_requirement}
                 )
                 OR NOT EXISTS (
                        SELECT 1 FROM status_events AS status
                        WHERE status.run_id = local.run_id
                          AND status.component_kind = 'instance'
                          AND status.component_id = run.instance_id
                    )
                 OR NOT EXISTS (
                        SELECT 1 FROM provider_intake_acknowledgments AS acknowledgment
                        WHERE acknowledgment.run_id = local.run_id
                    )
               )
             ORDER BY local.artifact_id LIMIT 1"
    );
    let invalid_run_only_local: Option<String> = connection
        .query_row(&invalid_run_only_query, [], |row| row.get(0))
        .optional()?;
    if let Some(artifact_id) = invalid_run_only_local {
        return Err(StoreError::Integrity(format!(
            "run-level diagnostic artifact {artifact_id} is not bound to one canonical non-success run or one exact admitted production execution"
        )));
    }
    Ok(())
}

fn validate_local_diagnostic_artifact_provenance_history(
    connection: &Connection,
) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT artifact_id FROM diagnostic_artifact_commitments
         ORDER BY artifact_sequence",
    )?;
    let artifact_ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for value in artifact_ids {
        let artifact_id = Sha256Digest::parse(value).map_err(|error| {
            StoreError::Integrity(format!("diagnostic artifact identity is invalid: {error}"))
        })?;
        let Some(commitment) =
            diagnostic_artifact_commitment_on_connection(connection, &artifact_id)?
        else {
            return Err(StoreError::Integrity(format!(
                "diagnostic artifact index lost commitment {artifact_id}"
            )));
        };
        let DiagnosticArtifactOrigin::Local {
            run_id,
            completed_at,
            execution_binding_record_id,
            ..
        } = &commitment.origin
        else {
            continue;
        };
        let payload = connection
            .query_row(
                "SELECT canonical_bytes FROM diagnostic_artifact_payloads
                 WHERE artifact_id = ?1",
                [artifact_id.as_str()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(payload) = payload else {
            continue;
        };
        let Ok(document) = CanonicalDocument::from_canonical_bytes(payload) else {
            continue;
        };
        let run_binding = connection
            .query_row(
                "SELECT request_id, profile_id, profile_version, profile_digest
                 FROM watcher_runs WHERE run_id = ?1",
                [run_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::Integrity(format!(
                    "local diagnostic artifact {artifact_id} names missing run {run_id}"
                ))
            })?;
        let production_binding =
            diagnostic_artifact_execution_binding_on_connection(connection, &artifact_id)?;
        if execution_binding_record_id.as_ref()
            != production_binding
                .as_ref()
                .map(|binding| &binding.execution_binding.record_id)
        {
            return Err(StoreError::Integrity(format!(
                "local diagnostic artifact {artifact_id} binding origin disagrees with exact linkage"
            )));
        }
        let expected_request_id = production_binding
            .as_ref()
            .map_or(run_binding.0.as_str(), |binding| {
                binding.outer_request_id.as_str()
            });
        validate_local_diagnostic_artifact_provenance_fields(
            &document,
            run_id,
            expected_request_id,
            &run_binding.1,
            &run_binding.2,
            &run_binding.3,
            completed_at,
        )
        .map_err(|error| {
            StoreError::Integrity(format!(
                "local diagnostic artifact {artifact_id} provenance is invalid: {error}"
            ))
        })?;
    }
    Ok(())
}

fn evidence_snapshot_from_connection(
    connection: &Connection,
    instance_ids: &[String],
) -> Result<EvidenceSnapshot, StoreError> {
    let mut instances = BTreeSet::new();
    instances.extend(instance_ids.iter().cloned());
    let mut watermarks = Vec::with_capacity(instances.len());
    let mut reports = Vec::new();
    for instance_id in instances {
        let max_report_sequence: i64 = connection.query_row(
            "SELECT COALESCE(MAX(report_sequence), 0)
             FROM admitted_reports WHERE instance_id = ?1",
            [&instance_id],
            |row| row.get(0),
        )?;
        let watermark_received_at = if max_report_sequence == 0 {
            None
        } else {
            connection.query_row(
                "SELECT received_at FROM admitted_reports
                 WHERE instance_id = ?1 AND report_sequence = ?2",
                params![instance_id, max_report_sequence],
                |row| row.get(0),
            )?
        };
        watermarks.push(EvaluationWatermark {
            instance_id: instance_id.clone(),
            max_report_sequence,
            watermark_received_at,
        });

        let mut statement = connection.prepare(
            "SELECT report_sequence, report_id, instance_id, profile_id,
                    profile_version, profile_digest, observed_at, received_at,
                    report_status, canonical_json, semantic_digest
             FROM admitted_reports
             WHERE instance_id = ?1 AND report_sequence <= ?2
             ORDER BY report_sequence",
        )?;
        let rows = statement.query_map(params![instance_id, max_report_sequence], |row| {
            Ok(AdmittedReportRow {
                report_sequence: row.get(0)?,
                report_id: row.get(1)?,
                instance_id: row.get(2)?,
                profile_id: row.get(3)?,
                profile_version: row.get(4)?,
                profile_digest: row.get(5)?,
                observed_at: row.get(6)?,
                received_at: row.get(7)?,
                report_status: row.get(8)?,
                canonical_json: row.get(9)?,
                semantic_digest: row.get(10)?,
            })
        })?;
        reports.extend(rows.collect::<Result<Vec<_>, _>>()?);
    }
    Ok(EvidenceSnapshot {
        watermarks,
        reports,
    })
}

fn finding_snapshots_from_connection(
    connection: &Connection,
) -> Result<Vec<FindingSnapshotRow>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT finding_id, instance_id, detector_id, detector_version,
                detector_digest, evaluation_revision, profile_id, profile_version,
                profile_digest, profile_semantic_id, subject_json, condition_name,
                condition_state, visibility_state,
                operator_work_state, severity, summary, limitations_json,
                safe_next_checks_json, freshness_json, basis_json, refusal_json,
                origin_mode, historical_refs_json, observed_at, received_at,
                evaluated_at, evaluation_id, evaluation_refusal_json, evidence_json
         FROM public_finding_snapshot_v3 ORDER BY finding_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(FindingSnapshotRow {
            finding_id: row.get(0)?,
            instance_id: row.get(1)?,
            detector_id: row.get(2)?,
            detector_version: row.get(3)?,
            detector_digest: row.get(4)?,
            evaluation_revision: row.get(5)?,
            profile_id: row.get(6)?,
            profile_version: row.get(7)?,
            profile_digest: row.get(8)?,
            profile_semantic_id: row.get(9)?,
            subject_json: row.get(10)?,
            condition_name: row.get(11)?,
            condition_state: row.get(12)?,
            visibility_state: row.get(13)?,
            operator_work_state: row.get(14)?,
            severity: row.get(15)?,
            summary: row.get(16)?,
            limitations_json: row.get(17)?,
            safe_next_checks_json: row.get(18)?,
            freshness_json: row.get(19)?,
            basis_json: row.get(20)?,
            refusal_json: row.get(21)?,
            origin_mode: row.get(22)?,
            historical_refs_json: row.get(23)?,
            observed_at: row.get(24)?,
            received_at: row.get(25)?,
            evaluated_at: row.get(26)?,
            evaluation_id: row.get(27)?,
            evaluation_refusal_json: row.get(28)?,
            evidence_json: row.get(29)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn configure_connection(connection: &Connection, on_disk: bool) -> Result<(), StoreError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    // With recursive triggers off, the implicit DELETE of an INSERT OR REPLACE
    // does not fire DELETE triggers, which would let a direct-SQL writer replace
    // an append-only parent row (run/submission/admission) and silently
    // invalidate the report->admission-context binding. Enabling it makes the
    // immutability triggers, and therefore that binding, hold against REPLACE.
    connection.pragma_update(None, "recursive_triggers", "ON")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    if on_disk {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
    }
    Ok(())
}

fn initialize_connection(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA)?;
    transaction.execute(
        "INSERT INTO schema_metadata (
            singleton, product, schema_version, schema_artifact_digest, initialized_at
         ) VALUES (1, 'nq-ng', ?1, ?2, ?3)",
        params![SCHEMA_VERSION, schema_artifact_digest(), now_utc()],
    )?;
    transaction.commit()?;
    Ok(())
}

/// Digest of the exact `schema.sql` artifact compiled into this binary. Stored
/// at creation and compared at startup so a database created by a different
/// schema revision is refused rather than opened and misread.
#[must_use]
pub fn schema_artifact_digest() -> String {
    sha256_digest(SCHEMA.as_bytes())
}

fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn validate_v3_upgrade_source_connection(connection: &Connection) -> Result<(), StoreError> {
    let version = pragma_i64(connection, "user_version")?;
    if version != 3 {
        return Err(StoreError::SchemaVersionMismatch {
            found: version,
            supported: 3,
        });
    }
    let application_id = pragma_i64(connection, "application_id")?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::ApplicationIdMismatch {
            found: application_id,
            expected: APPLICATION_ID,
        });
    }
    let metadata: (i64, String) = connection.query_row(
        "SELECT schema_version, schema_artifact_digest
         FROM schema_metadata WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if metadata.0 != 3 || metadata.1 != SCHEMA_V3_ARTIFACT_DIGEST {
        return Err(StoreError::Integrity(
            "schema-v3 metadata does not identify the exact qualified v0.1.0 schema artifact"
                .into(),
        ));
    }
    if sha256_digest(SCHEMA_V3.as_bytes()) != SCHEMA_V3_ARTIFACT_DIGEST {
        return Err(StoreError::Integrity(
            "compiled schema_v3.sql does not match its pinned release digest".into(),
        ));
    }
    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(StoreError::Integrity(quick_check));
    }
    let foreign_key_failures: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_key_failures != 0 {
        return Err(StoreError::Integrity(format!(
            "{foreign_key_failures} schema-v3 foreign-key violations"
        )));
    }
    let expected = EXPECTED_SCHEMA_V3_FINGERPRINT.as_ref().map_err(|error| {
        StoreError::Integrity(format!(
            "compiled v3 schema cannot be fingerprinted: {error}"
        ))
    })?;
    let actual = schema_fingerprint(connection)?;
    if &actual != expected {
        return Err(StoreError::Integrity(format!(
            "schema-v3 definition fingerprint {actual} differs from exact qualified v0.1.0 {expected}"
        )));
    }
    validate_stored_digests(connection)?;
    validate_all_admission_context_digests(connection)?;
    validate_refusal_invariants(connection)?;
    validate_run_results(connection)?;
    validate_evaluation_refusal_invariants(connection)?;
    validate_admitted_report_associations_connection(connection)?;
    validate_status_sequence_lower_bound(connection)?;
    validate_projection_invariants(connection)
}

fn validate_v4_upgrade_source_connection(connection: &Connection) -> Result<(), StoreError> {
    let version = pragma_i64(connection, "user_version")?;
    if version != 4 {
        return Err(StoreError::SchemaVersionMismatch {
            found: version,
            supported: 4,
        });
    }
    let application_id = pragma_i64(connection, "application_id")?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::ApplicationIdMismatch {
            found: application_id,
            expected: APPLICATION_ID,
        });
    }
    let metadata: (i64, String) = connection.query_row(
        "SELECT schema_version, schema_artifact_digest
         FROM schema_metadata WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if metadata.0 != 4 || metadata.1 != SCHEMA_V4_ARTIFACT_DIGEST {
        return Err(StoreError::Integrity(
            "schema-v4 metadata does not identify the exact qualified schema artifact".into(),
        ));
    }
    if sha256_digest(SCHEMA_V4.as_bytes()) != SCHEMA_V4_ARTIFACT_DIGEST {
        return Err(StoreError::Integrity(
            "compiled schema_v4.sql does not match its pinned digest".into(),
        ));
    }
    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(StoreError::Integrity(quick_check));
    }
    let foreign_key_failures: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_key_failures != 0 {
        return Err(StoreError::Integrity(format!(
            "{foreign_key_failures} schema-v4 foreign-key violations"
        )));
    }
    let expected = EXPECTED_SCHEMA_V4_FINGERPRINT.as_ref().map_err(|error| {
        StoreError::Integrity(format!(
            "compiled v4 schema cannot be fingerprinted: {error}"
        ))
    })?;
    let actual = schema_fingerprint(connection)?;
    if &actual != expected {
        return Err(StoreError::Integrity(format!(
            "schema-v4 definition fingerprint {actual} differs from exact qualified v4 {expected}"
        )));
    }
    validate_stored_digests(connection)?;
    validate_upgrade_receipts(connection)?;
    validate_all_admission_context_digests(connection)?;
    validate_local_provider_admissions(connection)?;
    validate_provider_intake_invariants(connection)?;
    validate_refusal_invariants(connection)?;
    validate_run_results(connection)?;
    validate_evaluation_refusal_invariants(connection)?;
    validate_admitted_report_associations_connection(connection)?;
    validate_status_sequence_lower_bound(connection)?;
    validate_projection_invariants(connection)
}

fn validate_v5_upgrade_source_connection(connection: &Connection) -> Result<(), StoreError> {
    let version = pragma_i64(connection, "user_version")?;
    if version != 5 {
        return Err(StoreError::SchemaVersionMismatch {
            found: version,
            supported: 5,
        });
    }
    let application_id = pragma_i64(connection, "application_id")?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::ApplicationIdMismatch {
            found: application_id,
            expected: APPLICATION_ID,
        });
    }
    let metadata: (i64, String) = connection.query_row(
        "SELECT schema_version, schema_artifact_digest
         FROM schema_metadata WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if metadata.0 != 5 || metadata.1 != SCHEMA_V5_ARTIFACT_DIGEST {
        return Err(StoreError::Integrity(
            "schema-v5 metadata does not identify the exact qualified schema artifact".into(),
        ));
    }
    if sha256_digest(SCHEMA_V5.as_bytes()) != SCHEMA_V5_ARTIFACT_DIGEST {
        return Err(StoreError::Integrity(
            "compiled schema_v5.sql does not match its pinned digest".into(),
        ));
    }
    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(StoreError::Integrity(quick_check));
    }
    let foreign_key_failures: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_key_failures != 0 {
        return Err(StoreError::Integrity(format!(
            "{foreign_key_failures} schema-v5 foreign-key violations"
        )));
    }
    let expected = EXPECTED_SCHEMA_V5_FINGERPRINT.as_ref().map_err(|error| {
        StoreError::Integrity(format!(
            "compiled v5 schema cannot be fingerprinted: {error}"
        ))
    })?;
    let actual = schema_fingerprint(connection)?;
    if &actual != expected {
        return Err(StoreError::Integrity(format!(
            "schema-v5 definition fingerprint {actual} differs from exact qualified v5 {expected}"
        )));
    }
    validate_stored_digests(connection)?;
    validate_upgrade_receipts(connection)?;
    validate_all_admission_context_digests(connection)?;
    validate_local_provider_admissions(connection)?;
    validate_provider_intake_invariants(connection)?;
    validate_refusal_invariants(connection)?;
    validate_run_results(connection)?;
    validate_evaluation_refusal_invariants(connection)?;
    validate_diagnostic_artifact_invariants(connection)?;
    validate_admitted_report_associations_connection(connection)?;
    validate_status_sequence_lower_bound(connection)?;
    validate_projection_invariants(connection)
}

fn validate_v6_upgrade_source_connection(connection: &Connection) -> Result<(), StoreError> {
    let version = pragma_i64(connection, "user_version")?;
    if version != 6 {
        return Err(StoreError::SchemaVersionMismatch {
            found: version,
            supported: 6,
        });
    }
    let application_id = pragma_i64(connection, "application_id")?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::ApplicationIdMismatch {
            found: application_id,
            expected: APPLICATION_ID,
        });
    }
    let metadata: (i64, String) = connection.query_row(
        "SELECT schema_version, schema_artifact_digest
         FROM schema_metadata WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if metadata.0 != 6 || metadata.1 != SCHEMA_V6_ARTIFACT_DIGEST {
        return Err(StoreError::Integrity(
            "schema-v6 metadata does not identify the exact qualified schema artifact".into(),
        ));
    }
    let quick_check: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(StoreError::Integrity(quick_check));
    }
    let foreign_key_failures: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_key_failures != 0 {
        return Err(StoreError::Integrity(format!(
            "{foreign_key_failures} schema-v6 foreign-key violations"
        )));
    }
    let expected = EXPECTED_SCHEMA_V6_FINGERPRINT.as_ref().map_err(|error| {
        StoreError::Integrity(format!(
            "compiled v6 schema cannot be fingerprinted: {error}"
        ))
    })?;
    let actual = schema_fingerprint(connection)?;
    if &actual != expected {
        return Err(StoreError::Integrity(format!(
            "schema-v6 definition fingerprint {actual} differs from exact qualified v6 {expected}"
        )));
    }
    validate_stored_digests(connection)?;
    validate_upgrade_receipts(connection)?;
    validate_all_admission_context_digests(connection)?;
    validate_local_provider_admissions(connection)?;
    validate_provider_intake_invariants(connection)?;
    validate_refusal_invariants(connection)?;
    validate_run_results(connection)?;
    validate_evaluation_refusal_invariants(connection)?;
    validate_diagnostic_artifact_invariants(connection)?;
    validate_runtime_record_ledger(connection)?;
    validate_admitted_report_associations_connection(connection)?;
    validate_status_sequence_lower_bound(connection)?;
    validate_projection_invariants(connection)
}

fn validate_admitted_report_associations_connection(
    connection: &Connection,
) -> Result<(), StoreError> {
    let invalid_sequence: Option<i64> = connection
        .query_row(
            "SELECT report_sequence FROM admitted_reports
             WHERE report_sequence <= 0 ORDER BY report_sequence LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(sequence) = invalid_sequence {
        return Err(StoreError::Integrity(format!(
            "admitted report sequence must be positive; found {sequence}"
        )));
    }
    let wrong_count: Option<(String, i64)> = connection
        .query_row(
            "SELECT submission.submission_id, COUNT(report.report_id)
             FROM raw_submissions AS submission
             LEFT JOIN admitted_reports AS report
               ON report.submission_id = submission.submission_id
             WHERE submission.admission_outcome = 'admitted'
             GROUP BY submission.submission_id
             HAVING COUNT(report.report_id) <> 1
             ORDER BY submission.submission_id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((submission_id, count)) = wrong_count {
        return Err(StoreError::Integrity(format!(
            "admitted submission {submission_id} requires exactly one report; found {count}"
        )));
    }
    let broken: Option<String> = connection
        .query_row(
            "SELECT report.report_id
             FROM admitted_reports AS report
             LEFT JOIN raw_submissions AS submission
               ON submission.submission_id = report.submission_id
             LEFT JOIN watcher_runs AS run ON run.run_id = submission.run_id
             LEFT JOIN admission_records AS admission
               ON admission.admission_id = run.admission_id
             WHERE submission.submission_id IS NULL
                OR submission.admission_outcome <> 'admitted'
                OR run.run_id IS NULL OR admission.admission_id IS NULL
                OR report.instance_id IS NOT run.instance_id
                OR report.instance_id IS NOT admission.instance_id
                OR report.profile_id IS NOT run.profile_id
                OR report.profile_version IS NOT run.profile_version
                OR report.profile_digest IS NOT run.profile_digest
                OR report.profile_id IS NOT admission.profile_id
                OR report.profile_version IS NOT admission.profile_version
                OR report.profile_digest IS NOT admission.profile_digest
                OR report.received_at IS NOT submission.received_at
             ORDER BY report.report_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(report_id) = broken {
        return Err(StoreError::Integrity(format!(
            "admitted report {report_id} has a broken submission/run/admission association"
        )));
    }
    Ok(())
}

fn append_digest_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), StoreError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| StoreError::Invariant("logical-state field exceeds u64".into()))?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

/// Hash the typed contents of every schema-v3 table as an order-independent
/// row multiset. This deliberately excludes SQLite page layout while retaining
/// value types, duplicate rows, `sqlite_sequence`, and every durable byte.
fn v3_logical_state_digest(connection: &Connection) -> Result<String, StoreError> {
    logical_state_digest(connection, b"nq.schema_v3.logical_state.v1\0")
}

fn v4_logical_state_digest(connection: &Connection) -> Result<String, StoreError> {
    logical_state_digest(connection, b"nq.schema_v4.logical_state.v1\0")
}

fn v5_logical_state_digest(connection: &Connection) -> Result<String, StoreError> {
    logical_state_digest(connection, b"nq.schema_v5.logical_state.v1\0")
}

fn v6_logical_state_digest(connection: &Connection) -> Result<String, StoreError> {
    logical_state_digest(connection, b"nq.schema_v6.logical_state.v1\0")
}

fn logical_state_digest(connection: &Connection, domain: &[u8]) -> Result<String, StoreError> {
    let mut names =
        connection.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")?;
    let table_names = names
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(names);

    let mut state = Sha256::new();
    state.update(domain);
    state.update(pragma_i64(connection, "application_id")?.to_be_bytes());
    state.update(pragma_i64(connection, "user_version")?.to_be_bytes());
    for table_name in table_names {
        append_digest_field(&mut state, table_name.as_bytes())?;
        let quoted = table_name.replace('"', "\"\"");
        let mut statement = connection.prepare(&format!("SELECT * FROM \"{quoted}\""))?;
        let column_count = statement.column_count();
        state.update(
            u64::try_from(column_count)
                .map_err(|_| StoreError::Invariant("v3 table has too many columns".into()))?
                .to_be_bytes(),
        );
        let mut rows = statement.query([])?;
        let mut row_digests = Vec::new();
        while let Some(row) = rows.next()? {
            let mut row_hasher = Sha256::new();
            row_hasher.update(b"nq.schema_v3.logical_row.v1\0");
            for index in 0..column_count {
                use rusqlite::types::ValueRef;
                match row.get_ref(index)? {
                    ValueRef::Null => row_hasher.update([0]),
                    ValueRef::Integer(value) => {
                        row_hasher.update([1]);
                        row_hasher.update(value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        row_hasher.update([2]);
                        row_hasher.update(value.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(value) => {
                        row_hasher.update([3]);
                        append_digest_field(&mut row_hasher, value)?;
                    }
                    ValueRef::Blob(value) => {
                        row_hasher.update([4]);
                        append_digest_field(&mut row_hasher, value)?;
                    }
                }
            }
            row_digests.push(row_hasher.finalize());
        }
        row_digests.sort_unstable();
        state.update(
            u64::try_from(row_digests.len())
                .map_err(|_| StoreError::Invariant("v3 table has too many rows".into()))?
                .to_be_bytes(),
        );
        for row_digest in row_digests {
            state.update(row_digest);
        }
    }
    Ok(format!("sha256:{:x}", state.finalize()))
}

fn pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, StoreError> {
    let sql = match pragma {
        "application_id" => "PRAGMA application_id",
        "user_version" => "PRAGMA user_version",
        _ => {
            return Err(StoreError::Invariant(format!(
                "unsupported internal pragma {pragma}"
            )));
        }
    };
    connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(StoreError::from)
}

fn validate_required_objects(connection: &Connection) -> Result<(), StoreError> {
    const TABLES: &[&str] = &[
        "schema_metadata",
        "profile_descriptor_snapshots",
        "admission_records",
        "local_provider_admissions",
        "instance_binding_events",
        "binding_materialization_events",
        "watcher_runs",
        "provider_intake_attempts",
        "local_watcher_provider_intakes",
        "legacy_v3_watcher_run_intake_gaps",
        "raw_submissions",
        "admitted_reports",
        "observations",
        "report_coverage",
        "observation_coverage",
        "report_errors",
        "evaluation_runs",
        "evaluation_watermarks",
        "refusals",
        "diagnostic_artifact_commitments",
        "diagnostic_artifact_payloads",
        "local_diagnostic_artifact_origins",
        "diagnostic_artifact_import_events",
        "imported_diagnostic_artifact_origins",
        "finding_events",
        "finding_evidence",
        "finding_current",
        "notification_outbox",
        "notification_attempts",
        "retention_tombstones",
        "genesis_records",
        "legacy_references",
        "upgrade_receipts",
        "runtime_record_checkpoints",
        "runtime_dependency_trust_roots",
        "runtime_dependency_generation_commitments",
        "runtime_dependency_generation_payloads",
        "runtime_checkpoint_dependency_bindings",
        "runtime_dependency_binding_migration_boundaries",
        "runtime_record_ledger",
        "runtime_record_lookup",
        "local_diagnostic_artifact_provider_attempt_bindings",
        "status_events",
        "provider_intake_acknowledgments",
        "status_current",
    ];
    const VIEWS: &[&str] = &[
        "public_finding_snapshot_v3",
        "public_status_snapshot_v1",
        "public_notification_status_v1",
    ];
    for (object_type, names) in [("table", TABLES), ("view", VIEWS)] {
        for name in names {
            let present: bool = connection.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2
                 )",
                params![object_type, name],
                |row| row.get(0),
            )?;
            if !present {
                return Err(StoreError::Integrity(format!(
                    "required {object_type} {name} is missing"
                )));
            }
        }
    }
    Ok(())
}

fn schema_fingerprint(connection: &Connection) -> Result<String, StoreError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '')
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name, tbl_name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut basis = Vec::new();
    for row in rows {
        let (object_type, name, table, sql) = row?;
        for field in [object_type, name, table, sql] {
            basis.extend_from_slice(field.len().to_string().as_bytes());
            basis.push(b':');
            basis.extend_from_slice(field.as_bytes());
            basis.push(b'\n');
        }
    }
    Ok(sha256_digest(&basis))
}

/// Recompute every stored content-addressed digest from its persisted bytes and
/// refuse any mismatch. This catches silent byte corruption that schema,
/// foreign-key, and `quick_check` passes cannot: raw custody bytes, admitted
/// report bytes, and compiled descriptor bytes must each still hash to their
/// recorded identity. O(rows); a beta-scale startup integrity obligation.
fn validate_stored_digests(connection: &Connection) -> Result<(), StoreError> {
    let mut raw = connection.prepare(
        "SELECT submission_id, raw_bytes, raw_sha256 FROM raw_submissions ORDER BY submission_id",
    )?;
    let mut raw_rows = raw.query([])?;
    while let Some(row) = raw_rows.next()? {
        let submission_id: String = row.get(0)?;
        let raw_bytes: Vec<u8> = row.get(1)?;
        let stored: String = row.get(2)?;
        let recomputed = sha256_digest(&raw_bytes);
        if recomputed != stored {
            return Err(StoreError::Integrity(format!(
                "raw submission {submission_id} bytes hash to {recomputed}, not stored {stored}"
            )));
        }
    }

    let mut reports = connection.prepare(
        "SELECT report_id, canonical_json, semantic_digest FROM admitted_reports ORDER BY report_id",
    )?;
    let mut report_rows = reports.query([])?;
    while let Some(row) = report_rows.next()? {
        let report_id: String = row.get(0)?;
        let canonical_json: Vec<u8> = row.get(1)?;
        let stored: String = row.get(2)?;
        let document =
            CanonicalDocument::from_canonical_bytes(canonical_json).map_err(|error| {
                StoreError::Integrity(format!("admitted report {report_id}: {error}"))
            })?;
        if document.digest() != stored {
            return Err(StoreError::Integrity(format!(
                "admitted report {report_id} bytes hash to {}, not stored {stored}",
                document.digest()
            )));
        }
    }

    let mut descriptors = connection.prepare(
        "SELECT profile_id, profile_version, descriptor_json, profile_digest
         FROM profile_descriptor_snapshots ORDER BY profile_id, profile_version, profile_digest",
    )?;
    let mut descriptor_rows = descriptors.query([])?;
    while let Some(row) = descriptor_rows.next()? {
        let profile_id: String = row.get(0)?;
        let profile_version: String = row.get(1)?;
        let descriptor_json: Vec<u8> = row.get(2)?;
        let stored: String = row.get(3)?;
        let document =
            CanonicalDocument::from_canonical_bytes(descriptor_json).map_err(|error| {
                StoreError::Integrity(format!(
                    "descriptor {profile_id}/{profile_version}: {error}"
                ))
            })?;
        if document.digest() != stored {
            return Err(StoreError::Integrity(format!(
                "descriptor {profile_id}/{profile_version} bytes hash to {}, not stored {stored}",
                document.digest()
            )));
        }
    }
    Ok(())
}

fn stored_provider_intake_row(
    row: &rusqlite::Row<'_>,
) -> Result<StoredProviderIntake, rusqlite::Error> {
    Ok(StoredProviderIntake {
        intake_id: row.get(0)?,
        attempt_id: row.get(1)?,
        idempotency_key: row.get(2)?,
        request_id: row.get(3)?,
        provider_admission_id: row.get(4)?,
        admission_context_digest: row.get(5)?,
        provider_semantic_id: row.get(6)?,
        provider_artifact_digest: row.get(7)?,
        provider_protocol_identity: row.get(8)?,
        provider_config_digest: row.get(9)?,
        binding_digest: row.get(10)?,
        instance_id: row.get(11)?,
        profile_id: row.get(12)?,
        profile_version: row.get(13)?,
        profile_digest: row.get(14)?,
        profile_semantic_id: row.get(15)?,
        evaluator_artifact_digest: row.get(16)?,
        context_json: row.get(17)?,
        context_digest: row.get(18)?,
        interpretation_kind: row.get(19)?,
        interpretation_json: row.get(20)?,
        interpretation_digest: row.get(21)?,
        native_outcome_kind: row.get(22)?,
        native_outcome_json: row.get(23)?,
        native_outcome_digest: row.get(24)?,
        raw_bytes: row.get(25)?,
        raw_sha256: row.get(26)?,
        started_at: row.get(27)?,
        finished_at: row.get(28)?,
        received_at: row.get(29)?,
        replay_digest: row.get(30)?,
        intake_digest: row.get(31)?,
        source_admission_id: row.get(32)?,
        provider_sequence: row.get(33)?,
        origin_carrier: row.get(34)?,
        deadline_at: row.get(35)?,
        checkpoint_contract_digest: row.get(36)?,
        execution_identity_digest: row.get(37)?,
        run_id: row.get(38)?,
        source_capability_grant_json: row.get(39)?,
        source_lock_json: row.get(40)?,
    })
}

/// Prove that provider-intake custody is exact and every run is explicitly
/// classified as either a real v4 intake or a non-upgraded v3 historical gap.
#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn validate_provider_intake_invariants(connection: &Connection) -> Result<(), StoreError> {
    let invalid_run: Option<(String, i64, i64)> = connection
        .query_row(
            "SELECT run.run_id,
                    COUNT(DISTINCT local.intake_id),
                    COUNT(DISTINCT legacy.run_id)
             FROM watcher_runs AS run
             LEFT JOIN local_watcher_provider_intakes AS local ON local.run_id = run.run_id
             LEFT JOIN legacy_v3_watcher_run_intake_gaps AS legacy ON legacy.run_id = run.run_id
             GROUP BY run.run_id
             HAVING COUNT(DISTINCT local.intake_id) + COUNT(DISTINCT legacy.run_id) <> 1
             ORDER BY run.run_id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((run_id, intakes, gaps)) = invalid_run {
        return Err(StoreError::Integrity(format!(
            "watcher run {run_id} must have exactly one real provider intake or explicit v3 gap; found {intakes} intake links and {gaps} gaps"
        )));
    }

    let incomplete_intake: Option<(String, i64, i64)> = connection
        .query_row(
            "SELECT intake.intake_id,
                    COUNT(DISTINCT local.run_id),
                    COUNT(DISTINCT acknowledgment.acknowledgment_id)
             FROM provider_intake_attempts AS intake
             LEFT JOIN local_watcher_provider_intakes AS local
               ON local.intake_id = intake.intake_id
             LEFT JOIN provider_intake_acknowledgments AS acknowledgment
               ON acknowledgment.intake_id = intake.intake_id
              AND acknowledgment.provider_admission_id = intake.provider_admission_id
             GROUP BY intake.intake_id
             HAVING COUNT(DISTINCT local.run_id) <> 1
                 OR COUNT(DISTINCT acknowledgment.acknowledgment_id) <> 1
             ORDER BY intake.intake_id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((intake_id, origins, acknowledgments)) = incomplete_intake {
        return Err(StoreError::Integrity(format!(
            "provider intake {intake_id} requires one local origin and one durable acknowledgment; found {origins} origins and {acknowledgments} acknowledgments"
        )));
    }

    let mut legacy = connection.prepare(
        "SELECT run_id, source_schema_version, source_schema_artifact_digest,
                limitation_code, detail_json
         FROM legacy_v3_watcher_run_intake_gaps ORDER BY run_id",
    )?;
    let mut legacy_rows = legacy.query([])?;
    while let Some(row) = legacy_rows.next()? {
        let run_id: String = row.get(0)?;
        let source_version: i64 = row.get(1)?;
        let source_digest: String = row.get(2)?;
        let limitation: String = row.get(3)?;
        let detail: Vec<u8> = row.get(4)?;
        if source_version != 3
            || source_digest != SCHEMA_V3_ARTIFACT_DIGEST
            || limitation != "provider_intake_not_recorded"
        {
            return Err(StoreError::Integrity(format!(
                "legacy provider-intake gap {run_id} substitutes its source or limitation"
            )));
        }
        CanonicalDocument::from_canonical_bytes(detail).map_err(|error| {
            StoreError::Integrity(format!(
                "legacy provider-intake gap {run_id} is not canonical: {error}"
            ))
        })?;
    }

    let mut statement = connection.prepare(
        "SELECT intake.intake_id, intake.attempt_id, intake.idempotency_key,
                intake.request_id, intake.provider_admission_id,
                intake.admission_context_digest, intake.provider_semantic_id,
                intake.provider_artifact_digest, intake.provider_protocol_identity,
                intake.provider_config_digest, intake.binding_digest,
                intake.instance_id, intake.profile_id, intake.profile_version,
                intake.profile_digest, intake.profile_semantic_id,
                intake.evaluator_artifact_digest, intake.context_json,
                intake.context_digest, intake.interpretation_kind,
                intake.interpretation_json, intake.interpretation_digest,
                intake.native_outcome_kind, intake.native_outcome_json,
                intake.native_outcome_digest, intake.raw_bytes, intake.raw_sha256,
                intake.started_at, intake.finished_at, intake.received_at,
                intake.replay_digest, intake.intake_digest,
                intake.source_admission_id, intake.provider_sequence,
                intake.origin_carrier, intake.deadline_at,
                intake.checkpoint_contract_digest,
                intake.execution_identity_digest, local.run_id,
                source.capability_grant_json, source.lock_json
         FROM provider_intake_attempts AS intake
         JOIN local_watcher_provider_intakes AS local ON local.intake_id = intake.intake_id
         JOIN admission_records AS source
           ON source.admission_id = intake.source_admission_id
         ORDER BY intake.intake_sequence",
    )?;
    let rows = statement.query_map([], stored_provider_intake_row)?;
    for row in rows {
        let stored = row?;
        let parse_digest = |name: &str, value: String| {
            Sha256Digest::parse(value).map_err(|error| {
                StoreError::Integrity(format!(
                    "provider intake {} has invalid {name}: {error}",
                    stored.intake_id
                ))
            })
        };
        let context = CanonicalDocument::from_canonical_bytes(stored.context_json.clone())
            .map_err(|error| {
                StoreError::Integrity(format!(
                    "provider intake {} context is not canonical: {error}",
                    stored.intake_id
                ))
            })?;
        let interpretation = CanonicalDocument::from_canonical_bytes(
            stored.interpretation_json.clone(),
        )
        .map_err(|error| {
            StoreError::Integrity(format!(
                "provider intake {} interpretation is not canonical: {error}",
                stored.intake_id
            ))
        })?;
        let native_outcome = CanonicalDocument::from_canonical_bytes(
            stored.native_outcome_json.clone(),
        )
        .map_err(|error| {
            StoreError::Integrity(format!(
                "provider intake {} native outcome is not canonical: {error}",
                stored.intake_id
            ))
        })?;
        let intake = ProviderIntakeInput {
            intake_id: stored.intake_id.clone(),
            attempt_id: stored.attempt_id.clone(),
            idempotency_key: stored.idempotency_key.clone(),
            request_id: stored.request_id.clone(),
            provider_admission_id: stored.provider_admission_id.clone(),
            source_admission_id: stored.source_admission_id.clone(),
            provider_sequence: stored.provider_sequence.clone(),
            origin_carrier: stored.origin_carrier.clone(),
            deadline_at: stored.deadline_at.clone(),
            checkpoint_contract_digest: stored.checkpoint_contract_digest.clone(),
            execution_identity_digest: Sha256Digest::parse(
                stored.execution_identity_digest.clone(),
            )
            .map_err(|error| {
                StoreError::Integrity(format!(
                    "provider intake {} has invalid execution identity digest: {error}",
                    stored.intake_id
                ))
            })?,
            admission_context_digest: parse_digest(
                "admission context digest",
                stored.admission_context_digest.clone(),
            )?,
            provider_semantic_id: parse_digest(
                "provider semantic identity",
                stored.provider_semantic_id.clone(),
            )?,
            provider_artifact_digest: parse_digest(
                "provider artifact digest",
                stored.provider_artifact_digest.clone(),
            )?,
            provider_protocol_identity: stored.provider_protocol_identity.clone(),
            provider_config_digest: parse_digest(
                "provider configuration digest",
                stored.provider_config_digest.clone(),
            )?,
            binding_digest: stored.binding_digest.clone(),
            instance_id: stored.instance_id.clone(),
            profile_id: stored.profile_id.clone(),
            profile_version: stored.profile_version.clone(),
            profile_digest: stored.profile_digest.clone(),
            profile_semantic_id: parse_digest(
                "profile semantic identity",
                stored.profile_semantic_id.clone(),
            )?,
            evaluator_artifact_digest: parse_digest(
                "evaluator artifact digest",
                stored.evaluator_artifact_digest.clone(),
            )?,
            context,
            interpretation_kind: stored.interpretation_kind.clone(),
            interpretation,
            native_outcome_kind: stored.native_outcome_kind.clone(),
            native_outcome,
            raw_bytes: stored.raw_bytes.clone(),
            started_at: stored.started_at.clone(),
            finished_at: stored.finished_at.clone(),
            received_at: stored.received_at.clone(),
        };
        validate_provider_admission(connection, &intake, false)?;
        let digests = provider_intake_digests(&intake)?;
        if digests.context_digest != stored.context_digest
            || digests.interpretation_digest != stored.interpretation_digest
            || digests.native_outcome_digest != stored.native_outcome_digest
            || digests.raw_sha256 != stored.raw_sha256
            || digests.replay_digest != stored.replay_digest
            || digests.intake_digest != stored.intake_digest
        {
            return Err(StoreError::Integrity(format!(
                "provider intake {} has substituted canonical bytes or derived digests",
                stored.intake_id
            )));
        }
        let run: (
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Vec<u8>,
            String,
            String,
            String,
            Vec<u8>,
        ) = connection.query_row(
            "SELECT request_id, admission_id, binding_digest, instance_id,
                        profile_id, profile_version, profile_digest, started_at,
                        finished_at, resource_outcome_json, carrier, deadline_at,
                        checkpoint_contract_digest, execution_identity_json
                 FROM watcher_runs WHERE run_id = ?1",
            [&stored.run_id],
            |run| {
                Ok((
                    run.get(0)?,
                    run.get(1)?,
                    run.get(2)?,
                    run.get(3)?,
                    run.get(4)?,
                    run.get(5)?,
                    run.get(6)?,
                    run.get(7)?,
                    run.get(8)?,
                    run.get(9)?,
                    run.get(10)?,
                    run.get(11)?,
                    run.get(12)?,
                    run.get(13)?,
                ))
            },
        )?;
        let run_execution_identity =
            CanonicalDocument::from_canonical_bytes(run.13).map_err(|error| {
                StoreError::Integrity(format!(
                    "watcher run {} execution identity is not canonical: {error}",
                    stored.run_id
                ))
            })?;
        if stored.request_id != run.0
            || run.1.as_deref() != Some(stored.source_admission_id.as_str())
            || stored.binding_digest != run.2
            || stored.instance_id != run.3
            || stored.profile_id != run.4
            || stored.profile_version != run.5
            || stored.profile_digest != run.6
            || stored.started_at != run.7
            || stored.finished_at != run.8
            || stored.native_outcome_json != run.9
            || stored.origin_carrier != run.10
            || stored.deadline_at != run.11
            || stored.checkpoint_contract_digest != run.12
            || stored.execution_identity_digest != run_execution_identity.digest()
        {
            return Err(StoreError::Integrity(format!(
                "provider intake {} does not match its local watcher run {}",
                stored.intake_id, stored.run_id
            )));
        }
        let submission: Option<(Vec<u8>, String, String)> = connection
            .query_row(
                "SELECT raw_bytes, raw_sha256, received_at
                 FROM raw_submissions WHERE run_id = ?1",
                [&stored.run_id],
                |submission| Ok((submission.get(0)?, submission.get(1)?, submission.get(2)?)),
            )
            .optional()?;
        if let Some((bytes, digest, received_at)) = submission
            && (bytes != stored.raw_bytes
                || digest != stored.raw_sha256
                || received_at != stored.received_at)
        {
            return Err(StoreError::Integrity(format!(
                "provider intake {} and protocol submission do not share exact raw custody",
                stored.intake_id
            )));
        }
        if provider_acknowledgment_for_intake(connection, &stored.intake_id)?.is_none() {
            return Err(StoreError::Integrity(format!(
                "provider intake {} lacks an exact durable acknowledgment",
                stored.intake_id
            )));
        }
    }
    Ok(())
}

/// Prove that every rejected custody row has one exact typed refusal and that
/// every duplicated projection agrees with the refusal's originating run.
///
/// Schema v2 and later store the full association in `refusals.submission_id`; these
/// semantic checks make that representation fail closed without inventing
/// testimony for historical rows.
#[allow(clippy::too_many_lines)]
fn validate_refusal_invariants(connection: &Connection) -> Result<(), StoreError> {
    let invalid_association: Option<String> = connection
        .query_row(
            "SELECT refusal_id FROM refusals
             WHERE NOT (
                    (run_id IS NOT NULL AND submission_id IS NOT NULL
                     AND evaluation_id IS NULL)
                 OR (run_id IS NULL AND submission_id IS NULL
                     AND evaluation_id IS NOT NULL)
             )
             ORDER BY refusal_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(refusal_id) = invalid_association {
        return Err(StoreError::Integrity(format!(
            "typed refusal {refusal_id} is orphaned or cross-linked across identity models"
        )));
    }

    let missing_or_duplicate: Option<(String, i64)> = connection
        .query_row(
            "SELECT submission.submission_id, COUNT(refusal.refusal_id)
             FROM raw_submissions AS submission
             LEFT JOIN refusals AS refusal
               ON refusal.submission_id = submission.submission_id
             WHERE submission.admission_outcome = 'rejected'
             GROUP BY submission.submission_id
             HAVING COUNT(refusal.refusal_id) <> 1
             ORDER BY submission.submission_id
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((submission_id, count)) = missing_or_duplicate {
        return Err(StoreError::Integrity(format!(
            "rejected custody {submission_id} requires exactly one typed refusal; found {count}"
        )));
    }

    let admitted_link: Option<String> = connection
        .query_row(
            "SELECT submission.submission_id
             FROM raw_submissions AS submission
             JOIN refusals AS refusal
               ON refusal.submission_id = submission.submission_id
             WHERE submission.admission_outcome <> 'rejected'
             ORDER BY submission.submission_id
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(submission_id) = admitted_link {
        return Err(StoreError::Integrity(format!(
            "admitted custody {submission_id} is incorrectly linked to a typed refusal"
        )));
    }

    let mismatch: Option<String> = connection
        .query_row(
            "SELECT submission.submission_id
             FROM raw_submissions AS submission
             JOIN watcher_runs AS run ON run.run_id = submission.run_id
             JOIN refusals AS refusal
               ON refusal.submission_id = submission.submission_id
             LEFT JOIN admission_records AS admission
               ON admission.admission_id = run.admission_id
             WHERE submission.admission_outcome = 'rejected'
               AND (
                    submission.rejection_code IS NOT refusal.code
                 OR refusal.run_id IS NOT submission.run_id
                 OR refusal.responsible_instance_id IS NOT run.instance_id
                 OR refusal.profile_id IS NOT run.profile_id
                 OR refusal.profile_version IS NOT run.profile_version
                 OR refusal.profile_digest IS NOT run.profile_digest
                 OR refusal.evaluation_id IS NOT NULL
                 OR (refusal.source_kind = 'profile' AND (
                        run.admission_id IS NULL
                     OR admission.admission_id IS NULL
                     OR admission.instance_id IS NOT run.instance_id
                     OR admission.profile_id IS NOT run.profile_id
                     OR admission.profile_version IS NOT run.profile_version
                     OR admission.profile_digest IS NOT run.profile_digest
                     OR refusal.profile_semantic_id IS NOT admission.profile_semantic_id
                 ))
                 OR (refusal.source_kind <> 'profile'
                     AND refusal.profile_semantic_id IS NOT NULL)
               )
             ORDER BY submission.submission_id
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(submission_id) = mismatch {
        return Err(StoreError::Integrity(format!(
            "rejected custody {submission_id} has a typed refusal whose code or run identity does not match"
        )));
    }

    let mut statement =
        connection.prepare("SELECT refusal_id, detail_json FROM refusals ORDER BY refusal_id")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let refusal_id: String = row.get(0)?;
        let detail_json: Vec<u8> = row.get(1)?;
        CanonicalDocument::from_canonical_bytes(detail_json).map_err(|error| {
            StoreError::Integrity(format!(
                "typed refusal {refusal_id} detail is not exact canonical JSON: {error}"
            ))
        })?;
    }
    Ok(())
}

/// Every watcher run has exactly one canonical result linked by
/// `status_events.run_id`.
/// Admission-refused statuses have no watcher run and remain out of scope.
fn validate_run_results(connection: &Connection) -> Result<(), StoreError> {
    let missing_or_duplicate: Option<(String, i64)> = connection
        .query_row(
            "SELECT run.run_id, COUNT(status.status_event_id)
             FROM watcher_runs AS run
             LEFT JOIN status_events AS status ON status.run_id = run.run_id
             GROUP BY run.run_id
             HAVING COUNT(status.status_event_id) <> 1
             ORDER BY run.run_id
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((run_id, count)) = missing_or_duplicate {
        return Err(StoreError::Integrity(format!(
            "completed watcher run {run_id} requires exactly one canonical run-linked result; found {count}"
        )));
    }

    let invalid_link: Option<String> = connection
        .query_row(
            "SELECT status.run_id
             FROM status_events AS status
             JOIN watcher_runs AS run ON run.run_id = status.run_id
             WHERE status.run_id IS NOT NULL
               AND (
                    status.component_kind <> 'instance'
                 OR status.component_id <> run.instance_id
               )
             ORDER BY status.run_id
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(run_id) = invalid_link {
        return Err(StoreError::Integrity(format!(
            "status event has invalid canonical completed-run link {run_id}"
        )));
    }

    validate_admitted_evaluation_closures(connection)?;
    validate_admitted_run_result_documents(connection)?;

    let invalid_evaluation_trigger: Option<String> = connection
        .query_row(
            "SELECT evaluation.evaluation_id
             FROM evaluation_runs AS evaluation
             WHERE evaluation.trigger_run_id IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1
                   FROM raw_submissions AS submission
                   WHERE submission.run_id = evaluation.trigger_run_id
                     AND submission.admission_outcome = 'admitted'
               )
             ORDER BY evaluation.evaluation_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(evaluation_id) = invalid_evaluation_trigger {
        return Err(StoreError::Integrity(format!(
            "evaluation {evaluation_id} links a run without an admitted report"
        )));
    }
    Ok(())
}

/// An admitted run must execute exactly the detector suite and evaluator
/// artifact bound by its admission. This validation is shared by the atomic
/// writer and historical reopening, so neither path can accept a semantically
/// partial or substituted judging mechanism.
fn validate_admitted_evaluation_closures(connection: &Connection) -> Result<(), StoreError> {
    let admitted_runs = {
        let mut statement = connection.prepare(
            "SELECT run.run_id, admission.detector_identity_digest,
                    admission.evaluator_artifact_digest
             FROM watcher_runs AS run
             JOIN raw_submissions AS submission ON submission.run_id = run.run_id
             JOIN admission_records AS admission
               ON admission.admission_id = run.admission_id
             WHERE submission.admission_outcome = 'admitted'
             ORDER BY run.run_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };

    for (run_id, expected_detector_identity, expected_evaluator_artifact) in admitted_runs {
        let evaluations = {
            let mut statement = connection.prepare(
                "SELECT evaluation_id, detector_digest, evaluator_artifact_digest
                 FROM evaluation_runs
                 WHERE trigger_run_id = ?1
                 ORDER BY evaluation_sequence",
            )?;
            statement
                .query_map([&run_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let detector_digests = evaluations
            .iter()
            .map(|(_, detector_digest, _)| detector_digest.clone())
            .collect::<Vec<_>>();
        let unique_detectors = detector_digests.iter().collect::<BTreeSet<_>>();
        if unique_detectors.len() != detector_digests.len() {
            return Err(StoreError::Integrity(format!(
                "admitted watcher run {run_id} evaluates a detector more than once"
            )));
        }
        let actual_detector_identity = detector_suite_identity_digest(detector_digests)
            .map_err(|error| StoreError::Integrity(error.to_string()))?;
        if actual_detector_identity.as_str() != expected_detector_identity {
            return Err(StoreError::Integrity(format!(
                "admitted watcher run {run_id} detector suite identity {} does not match admission {expected_detector_identity}",
                actual_detector_identity.as_str()
            )));
        }
        if let Some((evaluation_id, actual_evaluator_artifact)) =
            evaluations
                .iter()
                .find_map(|(evaluation_id, _, evaluator_artifact)| {
                    (evaluator_artifact != &expected_evaluator_artifact)
                        .then_some((evaluation_id, evaluator_artifact))
                })
        {
            return Err(StoreError::Integrity(format!(
                "evaluation {evaluation_id} for admitted watcher run {run_id} uses evaluator artifact {actual_evaluator_artifact} but its admission binds {expected_evaluator_artifact}"
            )));
        }
    }
    Ok(())
}

fn validate_admitted_run_result_documents(connection: &Connection) -> Result<(), StoreError> {
    let admitted_results = {
        let mut statement = connection.prepare(
            "SELECT run.run_id, run.instance_id, report.report_id,
                    report.report_status, report.semantic_digest, status.detail_json
             FROM watcher_runs AS run
             JOIN raw_submissions AS submission ON submission.run_id = run.run_id
             JOIN admitted_reports AS report
               ON report.submission_id = submission.submission_id
             JOIN status_events AS status ON status.run_id = run.run_id
             WHERE submission.admission_outcome = 'admitted'
             ORDER BY run.run_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (run_id, instance_id, report_id, report_status, semantic_digest, detail) in admitted_results
    {
        let evaluations = {
            let mut statement = connection.prepare(
                "SELECT detail_json FROM evaluation_runs
                 WHERE trigger_run_id = ?1 ORDER BY evaluation_sequence",
            )?;
            statement
                .query_map([&run_id], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        validate_admitted_result_document(
            &detail,
            &run_id,
            &instance_id,
            &report_id,
            &report_status,
            &semantic_digest,
            evaluations.iter().map(Vec::as_slice),
        )
        .map_err(|defect| {
            StoreError::Integrity(format!(
                "admitted watcher run {run_id} has an invalid canonical result: {defect}"
            ))
        })?;
    }
    Ok(())
}

fn validate_status_sequence_lower_bound(connection: &Connection) -> Result<(), StoreError> {
    let invalid_sequence: Option<i64> = connection
        .query_row(
            "SELECT status_sequence FROM status_events
             WHERE status_sequence <= 0 ORDER BY status_sequence LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(sequence) = invalid_sequence {
        return Err(StoreError::Integrity(format!(
            "status event sequence must be positive; found {sequence}"
        )));
    }
    Ok(())
}

fn validate_all_admission_context_digests(connection: &Connection) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT admission_id, config_digest, helper_artifact_digest,
                profile_semantic_id, detector_identity_digest,
                evaluator_source_digest, evaluator_artifact_digest,
                protocol_version, admission_context_digest
         FROM admission_records ORDER BY admission_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let admission_id: String = row.get(0)?;
        let parse = |field: &str, value: String| {
            Sha256Digest::parse(value).map_err(|_| {
                StoreError::Integrity(format!(
                    "admission {admission_id} has invalid {field} digest"
                ))
            })
        };
        let identity = AdmissionIdentity {
            config_digest: parse("config", row.get(1)?)?,
            helper_artifact_digest: parse("helper artifact", row.get(2)?)?,
            profile_semantic_id: parse("profile semantic", row.get(3)?)?,
            detector_identity_digest: parse("detector identity", row.get(4)?)?,
            evaluator_source_digest: parse("evaluator source", row.get(5)?)?,
            evaluator_artifact_digest: parse("evaluator artifact", row.get(6)?)?,
            protocol_version: row.get(7)?,
            target_triple: String::new(),
            artifact_identity_method: String::new(),
            platform_runtime_version: String::new(),
        };
        let stored: String = row.get(8)?;
        let recomputed = identity
            .context_digest()
            .map_err(|error| StoreError::Integrity(error.to_string()))?;
        if recomputed != stored {
            return Err(StoreError::Integrity(format!(
                "admission {admission_id} context digest {stored} does not recompute to {recomputed}"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn validate_local_provider_admissions(connection: &Connection) -> Result<(), StoreError> {
    let rows = {
        let mut statement = connection.prepare(
            "SELECT provider.provider_admission_id, provider.source_admission_id,
                    provider.provider_semantic_id, provider.provider_artifact_digest,
                    provider.provider_protocol_identity,
                    provider.provider_config_digest, provider.contract_json,
                    provider.contract_digest, admission.instance_id,
                    admission.admission_context_digest, admission.profile_id,
                    admission.profile_version, admission.profile_digest,
                    admission.profile_semantic_id,
                    admission.evaluator_artifact_digest,
                    admission.capability_grant_json, admission.conformance_json,
                    admission.lock_json, admission.helper_artifact_digest,
                    admission.protocol_version, admission.config_digest,
                    provider.source_admitted_at, provider.derived_at,
                    provider.derivation_kind, admission.admitted_at
             FROM local_provider_admissions AS provider
             JOIN admission_records AS admission
               ON admission.admission_id = provider.source_admission_id
             ORDER BY provider.provider_admission_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, Vec<u8>>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, String>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, String>(21)?,
                    row.get::<_, String>(22)?,
                    row.get::<_, String>(23)?,
                    row.get::<_, String>(24)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for row in rows {
        let contract = CanonicalDocument::from_canonical_bytes(row.6).map_err(|error| {
            StoreError::Integrity(format!(
                "local provider admission {} contract is not canonical: {error}",
                row.0
            ))
        })?;
        let capability = CanonicalDocument::from_canonical_bytes(row.15)?;
        let conformance = CanonicalDocument::from_canonical_bytes(row.16)?;
        let lock = CanonicalDocument::from_canonical_bytes(row.17)?;
        let expected_semantic = local_provider_semantic_id(&row.19, &conformance)?.into_string();
        let expected_contract =
            CanonicalDocument::from_serializable(&LocalProviderAdmissionContract {
                schema: LOCAL_PROVIDER_ADMISSION_SCHEMA,
                source_admission_id: &row.1,
                instance_id: &row.8,
                provider_semantic_id: &expected_semantic,
                provider_artifact_digest: &row.18,
                provider_protocol_identity: &row.19,
                provider_config_digest: &row.20,
                admission_context_digest: &row.9,
                profile_id: &row.10,
                profile_version: &row.11,
                profile_digest: &row.12,
                profile_semantic_id: &row.13,
                evaluator_artifact_digest: &row.14,
                capability_grant_digest: capability.digest(),
                conformance_digest: conformance.digest(),
                lock_digest: lock.digest(),
            })?;
        if row.2 != expected_semantic
            || row.3 != row.18
            || row.4 != row.19
            || row.5 != row.20
            || contract.as_bytes() != expected_contract.as_bytes()
            || row.7 != expected_contract.digest()
            || row.0 != expected_contract.digest()
            || row.21 != row.24
            || chrono::DateTime::parse_from_rfc3339(&row.21).is_err()
            || chrono::DateTime::parse_from_rfc3339(&row.22).is_err()
            || !matches!(row.23.as_str(), "admission_append" | "schema_v3_migration")
        {
            return Err(StoreError::Integrity(format!(
                "local provider admission {} does not recompute from its NQ-owned source admission",
                row.0
            )));
        }
    }
    let missing: i64 = connection.query_row(
        "SELECT COUNT(*) FROM admission_records AS admission
         WHERE NOT EXISTS (
             SELECT 1 FROM local_provider_admissions AS provider
             WHERE provider.source_admission_id = admission.admission_id
         )",
        [],
        |row| row.get(0),
    )?;
    if missing != 0 {
        return Err(StoreError::Integrity(format!(
            "{missing} source admissions lack their derived local-provider admission"
        )));
    }
    let orphaned_migration_derivations: i64 = connection.query_row(
        "SELECT COUNT(*) FROM local_provider_admissions AS provider
         WHERE provider.derivation_kind = 'schema_v3_migration'
           AND NOT EXISTS (
               SELECT 1 FROM upgrade_receipts AS receipt
               WHERE receipt.from_schema_version = 3
                 AND receipt.to_schema_version = 4
           )",
        [],
        |row| row.get(0),
    )?;
    if orphaned_migration_derivations != 0 {
        return Err(StoreError::Integrity(format!(
            "{orphaned_migration_derivations} local-provider admissions claim schema-v3 derivation without a transactional v3-to-v4 receipt"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_evaluation_refusal_invariants(connection: &Connection) -> Result<(), StoreError> {
    validate_evaluation_revision_shape(connection)?;
    let wrong_count: Option<(String, String, i64)> = connection
        .query_row(
            "SELECT evaluation.evaluation_id, evaluation.outcome,
                    COUNT(refusal.refusal_id)
             FROM evaluation_runs AS evaluation
             LEFT JOIN refusals AS refusal
               ON refusal.evaluation_id = evaluation.evaluation_id
             GROUP BY evaluation.evaluation_id
             HAVING (evaluation.outcome = 'cannot_evaluate'
                     AND COUNT(refusal.refusal_id) <> 1)
                 OR (evaluation.outcome <> 'cannot_evaluate'
                     AND COUNT(refusal.refusal_id) <> 0)
             ORDER BY evaluation.evaluation_id
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((evaluation_id, outcome, count)) = wrong_count {
        return Err(StoreError::Integrity(format!(
            "evaluation {evaluation_id} outcome {outcome} has {count} typed refusals"
        )));
    }

    let duplicate_finding: Option<(String, i64)> = connection
        .query_row(
            "SELECT evaluation_id, COUNT(event_id)
             FROM finding_events
             GROUP BY evaluation_id HAVING COUNT(event_id) > 1
             ORDER BY evaluation_id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((evaluation_id, count)) = duplicate_finding {
        return Err(StoreError::Integrity(format!(
            "evaluation {evaluation_id} has {count} finding events; expected at most one"
        )));
    }

    let substituted_lineage: Option<String> = connection
        .query_row(
            "SELECT event.event_id
             FROM finding_events AS event
             JOIN evaluation_runs AS evaluation
               ON evaluation.evaluation_id = event.evaluation_id
             WHERE (event.event_revision = 1 AND event.event_kind <> 'opened')
                OR (event.event_revision > 1 AND NOT EXISTS (
                    SELECT 1
                    FROM finding_events AS prior
                    JOIN evaluation_runs AS prior_evaluation
                      ON prior_evaluation.evaluation_id = prior.evaluation_id
                    WHERE prior.finding_id = event.finding_id
                      AND prior.event_revision = event.event_revision - 1
                      AND event.event_kind <> 'opened'
                      AND prior.instance_id = event.instance_id
                      AND prior.detector_id = event.detector_id
                      AND prior.detector_version = event.detector_version
                      AND prior.detector_digest = event.detector_digest
                      AND prior.profile_id = event.profile_id
                      AND prior.profile_version = event.profile_version
                      AND prior.profile_digest = event.profile_digest
                      AND prior_evaluation.profile_semantic_id = evaluation.profile_semantic_id
                      AND prior_evaluation.evaluation_revision
                          < evaluation.evaluation_revision
                      AND prior.subject_json = event.subject_json
                      AND prior.condition_name = event.condition_name
                      AND prior.basis_json = event.basis_json
                ))
             ORDER BY event.event_id
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = substituted_lineage {
        return Err(StoreError::Integrity(format!(
            "finding event {event_id} substitutes immutable finding lineage"
        )));
    }

    let mismatch: Option<String> = connection
        .query_row(
            "SELECT evaluation.evaluation_id
             FROM evaluation_runs AS evaluation
             LEFT JOIN refusals AS refusal
               ON refusal.evaluation_id = evaluation.evaluation_id
             LEFT JOIN finding_events AS finding
               ON finding.evaluation_id = evaluation.evaluation_id
             WHERE (refusal.refusal_id IS NOT NULL AND (
                       refusal.source_kind <> 'profile'
                    OR refusal.profile_id IS NULL
                    OR refusal.profile_version IS NULL
                    OR refusal.profile_digest IS NULL
                    OR refusal.profile_semantic_id IS NULL
                    OR refusal.profile_id IS NOT evaluation.profile_id
                    OR refusal.profile_version IS NOT evaluation.profile_version
                    OR refusal.profile_digest IS NOT evaluation.profile_digest
                    OR refusal.profile_semantic_id IS NOT evaluation.profile_semantic_id
                    OR NOT EXISTS (
                        SELECT 1 FROM evaluation_watermarks AS watermark
                        WHERE watermark.evaluation_id = evaluation.evaluation_id
                          AND watermark.instance_id = refusal.responsible_instance_id
                    )
                 ))
                OR (finding.event_id IS NOT NULL AND (
                       finding.detector_id IS NOT evaluation.detector_id
                    OR finding.detector_version IS NOT evaluation.detector_version
                    OR finding.detector_digest IS NOT evaluation.detector_digest
                    OR finding.evaluator_artifact_digest
                        IS NOT evaluation.evaluator_artifact_digest
                    OR finding.evaluation_revision IS NOT evaluation.evaluation_revision
                    OR finding.profile_id IS NOT evaluation.profile_id
                    OR finding.profile_version IS NOT evaluation.profile_version
                    OR finding.profile_digest IS NOT evaluation.profile_digest
                    OR finding.evaluated_at IS NOT evaluation.evaluated_at
                    OR (evaluation.outcome = 'condition_present'
                        AND finding.condition_state <> 'present')
                    OR (evaluation.outcome = 'condition_explicitly_absent'
                        AND finding.condition_state <> 'explicitly_absent')
                    OR (refusal.refusal_id IS NULL AND finding.refusal_json IS NOT NULL)
                    OR (refusal.refusal_id IS NOT NULL
                        AND finding.refusal_json IS NOT refusal.detail_json)
                 ))
                OR (evaluation.outcome = 'cannot_evaluate'
                    AND finding.event_id IS NOT NULL
                    AND (
                         finding.visibility_state = 'sufficient'
                      OR NOT EXISTS (
                          SELECT 1 FROM finding_events AS prior
                          WHERE prior.finding_id = finding.finding_id
                            AND prior.event_revision = finding.event_revision - 1
                            AND prior.condition_state = finding.condition_state
                      )
                    ))
             ORDER BY evaluation.evaluation_id
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(evaluation_id) = mismatch {
        return Err(StoreError::Integrity(format!(
            "evaluation {evaluation_id} has inconsistent governed refusal or finding linkage"
        )));
    }

    let mut evaluations = connection
        .prepare("SELECT evaluation_id, detail_json FROM evaluation_runs ORDER BY evaluation_id")?;
    let mut rows = evaluations.query([])?;
    while let Some(row) = rows.next()? {
        let evaluation_id: String = row.get(0)?;
        let detail: Vec<u8> = row.get(1)?;
        CanonicalDocument::from_canonical_bytes(detail).map_err(|error| {
            StoreError::Integrity(format!(
                "evaluation {evaluation_id} detail is not exact canonical JSON: {error}"
            ))
        })?;
    }
    Ok(())
}

fn validate_evaluation_revision_shape(connection: &Connection) -> Result<(), StoreError> {
    let invalid_revision: Option<(String, i64)> = connection
        .query_row(
            "SELECT identity, revision FROM (
                 SELECT evaluation_id AS identity, evaluation_revision AS revision
                 FROM evaluation_runs WHERE evaluation_revision <= 0
                 UNION ALL
                 SELECT event_id AS identity, event_revision AS revision
                 FROM finding_events WHERE event_revision <= 0
                 UNION ALL
                 SELECT event_id AS identity, evaluation_revision AS revision
                 FROM finding_events WHERE evaluation_revision <= 0
             ) ORDER BY identity LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((identity, revision)) = invalid_revision {
        return Err(StoreError::Integrity(format!(
            "evaluation/finding {identity} has impossible durable revision {revision}"
        )));
    }
    let sequence_shape: (i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MIN(evaluation_sequence), 0),
                COALESCE(MAX(evaluation_sequence), 0), COUNT(*)
         FROM evaluation_runs",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if sequence_shape.2 != 0 && (sequence_shape.0 != 1 || sequence_shape.1 != sequence_shape.2) {
        return Err(StoreError::Integrity(format!(
            "evaluation append sequence is not exact: {}..{} across {} rows",
            sequence_shape.0, sequence_shape.1, sequence_shape.2
        )));
    }
    let non_contiguous: Option<(String, String, i64, i64, i64)> = connection
        .query_row(
            "SELECT detector_id, detector_version,
                    MIN(evaluation_revision), MAX(evaluation_revision), COUNT(*)
             FROM evaluation_runs
             GROUP BY detector_id, detector_version
             HAVING MIN(evaluation_revision) <> 1
                 OR MAX(evaluation_revision) <> COUNT(*)
             ORDER BY detector_id, detector_version LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((detector_id, detector_version, minimum, maximum, count)) = non_contiguous {
        return Err(StoreError::Integrity(format!(
            "evaluation lineage {detector_id}/{detector_version} has revisions {minimum}..{maximum} across {count} rows"
        )));
    }
    Ok(())
}

fn validate_projection_invariants(connection: &Connection) -> Result<(), StoreError> {
    let bindings_without_intent: i64 = connection.query_row(
        "SELECT COUNT(*) FROM instance_binding_events AS binding
         WHERE NOT EXISTS (
             SELECT 1 FROM binding_materialization_events AS intent
             WHERE intent.binding_event_id = binding.binding_event_id
               AND intent.instance_id = binding.instance_id
               AND intent.phase = 'intent'
         )",
        [],
        |row| row.get(0),
    )?;
    if bindings_without_intent != 0 {
        return Err(StoreError::Integrity(format!(
            "{bindings_without_intent} binding events lack a recovery intent"
        )));
    }
    let invalid_completions: i64 = connection.query_row(
        "SELECT COUNT(*) FROM binding_materialization_events AS completed
         WHERE completed.phase = 'completed' AND NOT EXISTS (
             SELECT 1 FROM binding_materialization_events AS intent
             WHERE intent.operation_id = completed.operation_id
               AND intent.instance_id = completed.instance_id
               AND intent.binding_event_id = completed.binding_event_id
               AND intent.phase = 'intent'
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_completions != 0 {
        return Err(StoreError::Integrity(format!(
            "{invalid_completions} binding materialization completions lack an exact intent"
        )));
    }
    let multiply_pending_instances: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (
             SELECT intent.instance_id
             FROM binding_materialization_events AS intent
             WHERE intent.phase = 'intent' AND NOT EXISTS (
                 SELECT 1 FROM binding_materialization_events AS completed
                 WHERE completed.operation_id = intent.operation_id
                   AND completed.phase = 'completed'
             )
             GROUP BY intent.instance_id HAVING COUNT(*) > 1
         )",
        [],
        |row| row.get(0),
    )?;
    if multiply_pending_instances != 0 {
        return Err(StoreError::Integrity(format!(
            "{multiply_pending_instances} instances have multiple pending binding materializations"
        )));
    }

    let stale_findings: i64 = connection.query_row(
        "SELECT COUNT(*) FROM finding_events AS event
         WHERE NOT EXISTS (
            SELECT 1 FROM finding_current AS current
            JOIN finding_events AS selected ON selected.event_id = current.latest_event_id
            WHERE current.finding_id = event.finding_id
              AND selected.finding_id = event.finding_id
              AND selected.event_revision >= event.event_revision
         )",
        [],
        |row| row.get(0),
    )?;
    if stale_findings != 0 {
        return Err(StoreError::Integrity(format!(
            "finding_current is stale or inconsistent for {stale_findings} events"
        )));
    }
    let stale_statuses: i64 = connection.query_row(
        "SELECT COUNT(*) FROM status_events AS event
         WHERE NOT EXISTS (
            SELECT 1 FROM status_current AS current
            JOIN status_events AS selected
              ON selected.status_event_id = current.latest_status_event_id
            WHERE current.component_kind = event.component_kind
              AND current.component_id = event.component_id
              AND selected.component_kind = event.component_kind
              AND selected.component_id = event.component_id
              AND selected.status_sequence >= event.status_sequence
         )",
        [],
        |row| row.get(0),
    )?;
    if stale_statuses != 0 {
        return Err(StoreError::Integrity(format!(
            "status_current is stale or inconsistent for {stale_statuses} events"
        )));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> String {
    nq_protocol::sha256_bytes(bytes).into_string()
}

fn sha256_file(path: &Path) -> Result<String, StoreError> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn remove_database_artifact(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(sidecar));
    }
}

fn validate_digest(field: &str, digest: &str) -> Result<(), StoreError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(StoreError::Invariant(format!(
            "{field} must be an algorithm-qualified lowercase SHA-256 digest"
        )));
    };
    if hex.len() == 64
        && hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Ok(())
    } else {
        Err(StoreError::Invariant(format!(
            "{field} must be an algorithm-qualified lowercase SHA-256 digest"
        )))
    }
}

fn validate_public_limit(limit: u32) -> Result<(), StoreError> {
    if (1..=MAX_PUBLIC_QUERY_ROWS).contains(&limit) {
        Ok(())
    } else {
        Err(StoreError::Invariant(format!(
            "public query limit must be between 1 and {MAX_PUBLIC_QUERY_ROWS}"
        )))
    }
}

fn rejected_custody_row(row: &rusqlite::Row<'_>) -> Result<RejectedCustodyRow, rusqlite::Error> {
    Ok(RejectedCustodyRow {
        submission_id: row.get(0)?,
        run_id: row.get(1)?,
        request_id: row.get(2)?,
        instance_id: row.get(3)?,
        profile_id: row.get(4)?,
        profile_version: row.get(5)?,
        profile_digest: row.get(6)?,
        admission_id: row.get(7)?,
        profile_semantic_id: row.get(8)?,
        raw_sha256: row.get(9)?,
        received_at: row.get(10)?,
        protocol_outcome: row.get(11)?,
        refusal_id: row.get(12)?,
        source_kind: row.get(13)?,
        responsible_instance_id: row.get(14)?,
        boundary: row.get(15)?,
        code: row.get(16)?,
        detail_json: row.get(17)?,
        created_at: row.get(18)?,
    })
}

fn finding_evidence_history(
    connection: &Connection,
    event_id: &str,
) -> Result<Vec<FindingEvidenceHistoryRow>, StoreError> {
    let mut evidence = connection.prepare(
        "SELECT evidence.ordinal, evidence.report_id,
                evidence.report_semantic_digest, evidence.observation_ordinal,
                evidence.observed_at, evidence.received_at, report.instance_id,
                report.report_sequence, report.observed_at, report.received_at,
                CASE WHEN evidence.observation_ordinal IS NULL THEN 1
                     ELSE EXISTS (
                         SELECT 1 FROM observations AS observation
                         WHERE observation.report_id = evidence.report_id
                           AND observation.ordinal = evidence.observation_ordinal
                     )
                END,
                (SELECT observation.observed_at
                 FROM observations AS observation
                 WHERE observation.report_id = evidence.report_id
                   AND observation.ordinal = evidence.observation_ordinal)
         FROM finding_evidence AS evidence
         JOIN admitted_reports AS report
           ON report.report_id = evidence.report_id
          AND report.semantic_digest = evidence.report_semantic_digest
         WHERE evidence.event_id = ?1
         ORDER BY evidence.ordinal",
    )?;
    evidence
        .query_map([event_id], |evidence| {
            Ok(FindingEvidenceHistoryRow {
                ordinal: evidence.get(0)?,
                report_id: evidence.get(1)?,
                report_semantic_digest: evidence.get(2)?,
                observation_ordinal: evidence.get(3)?,
                observed_at: evidence.get(4)?,
                received_at: evidence.get(5)?,
                report_instance_id: evidence.get(6)?,
                report_sequence: evidence.get(7)?,
                report_observed_at: evidence.get(8)?,
                report_received_at: evidence.get(9)?,
                observation_exists: evidence.get(10)?,
                observation_observed_at: evidence.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn validate_document_size(size: usize) -> Result<(), StoreError> {
    if size <= MAX_STORED_JSON_BYTES {
        Ok(())
    } else {
        Err(StoreError::Invariant(format!(
            "canonical document is {size} bytes; limit is {MAX_STORED_JSON_BYTES}"
        )))
    }
}

#[allow(clippy::too_many_lines)]
fn validate_collection(collection: &CollectionInput) -> Result<(), StoreError> {
    validate_provider_intake_shape(
        &collection.intake,
        &collection.run,
        collection.submission.as_ref(),
    )?;
    validate_digest("binding_digest", &collection.run.binding_digest)?;
    validate_digest(
        "checkpoint_contract_digest",
        &collection.run.checkpoint_contract_digest,
    )?;
    validate_digest("profile_digest", &collection.run.profile_digest)?;
    let resource: Value = serde_json::from_slice(collection.run.resource_outcome.as_bytes())
        .map_err(|error| {
            StoreError::Invariant(format!("run resource outcome cannot decode: {error}"))
        })?;
    if resource.get("schema").and_then(Value::as_str) != Some("nq.run_resource_outcome.v1") {
        return Err(StoreError::Invariant(
            "run resource outcome has unsupported or missing schema".into(),
        ));
    }
    let exact_outcome = resource
        .pointer("/outcome/outcome")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            StoreError::Invariant(
                "run resource outcome lacks exact typed acquisition outcome".into(),
            )
        })?;
    let projected_outcome = match exact_outcome {
        "exchange_timeout" => "timeout",
        "response"
        | "spawn_failed"
        | "request_write_failed"
        | "timeout"
        | "output_too_large"
        | "stderr_too_large"
        | "eof"
        | "malformed_framing"
        | "malformed_json"
        | "exit_nonzero"
        | "helper_exited"
        | "disconnect"
        | "carrier_startup_failed"
        | "not_running"
        | "io_failed" => exact_outcome,
        _ => {
            return Err(StoreError::Invariant(format!(
                "run resource outcome has unknown acquisition variant {exact_outcome}"
            )));
        }
    };
    if projected_outcome != collection.run.acquisition_outcome {
        return Err(StoreError::Invariant(format!(
            "run acquisition projection {} disagrees with exact resource outcome {exact_outcome}",
            collection.run.acquisition_outcome
        )));
    }
    let Some(submission) = &collection.submission else {
        return Ok(());
    };
    if submission.raw_bytes.len() > nq_protocol::MAX_RESPONSE_FRAME_BYTES {
        return Err(StoreError::Invariant(format!(
            "raw response is {} bytes; protocol limit is {}",
            submission.raw_bytes.len(),
            nq_protocol::MAX_RESPONSE_FRAME_BYTES
        )));
    }
    match &submission.disposition {
        SubmissionDisposition::Rejected { refusal } => {
            if refusal.responsible_instance_id != collection.run.instance_id {
                return Err(StoreError::Invariant(
                    "refusal lost the run's exact responsible instance".to_owned(),
                ));
            }
        }
        SubmissionDisposition::Admitted(report) => {
            if report.observations.len() > nq_protocol::MAX_OBSERVATIONS {
                return Err(StoreError::Invariant(
                    "report exceeds the protocol observation ceiling".to_owned(),
                ));
            }
            let coverage_entries = report.coverage.len()
                + report
                    .observations
                    .iter()
                    .map(|observation| observation.coverage.len())
                    .sum::<usize>();
            if coverage_entries > nq_protocol::MAX_COVERAGE_ENTRIES {
                return Err(StoreError::Invariant(
                    "report exceeds the protocol coverage ceiling".to_owned(),
                ));
            }
            if report.errors.len() > nq_protocol::MAX_REPORT_ERRORS {
                return Err(StoreError::Invariant(
                    "report exceeds the protocol error ceiling".to_owned(),
                ));
            }
            if report.instance_id != collection.run.instance_id
                || report.profile_id != collection.run.profile_id
                || report.profile_version != collection.run.profile_version
                || report.profile_digest != collection.run.profile_digest
            {
                return Err(StoreError::Invariant(
                    "admitted report identity does not match its bound run".to_owned(),
                ));
            }
            if report.received_at != submission.received_at {
                return Err(StoreError::Invariant(
                    "report and raw submission received times disagree".to_owned(),
                ));
            }
            validate_ordered_unique(
                "observation",
                report.observations.iter().map(|item| item.ordinal),
            )?;
            validate_ordered_unique(
                "report coverage",
                report.coverage.iter().map(|item| item.ordinal),
            )?;
            validate_ordered_unique(
                "report error",
                report.errors.iter().map(|item| item.ordinal),
            )?;
            for observation in &report.observations {
                validate_ordered_unique(
                    "observation coverage",
                    observation.coverage.iter().map(|item| item.ordinal),
                )?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_provider_intake_shape(
    intake: &ProviderIntakeInput,
    run: &RunInput,
    submission: Option<&SubmissionInput>,
) -> Result<(), StoreError> {
    for (name, value) in [
        ("intake_id", intake.intake_id.as_str()),
        ("attempt_id", intake.attempt_id.as_str()),
        ("request_id", intake.request_id.as_str()),
        (
            "provider_admission_id",
            intake.provider_admission_id.as_str(),
        ),
        ("source_admission_id", intake.source_admission_id.as_str()),
        ("instance_id", intake.instance_id.as_str()),
        ("profile_id", intake.profile_id.as_str()),
        ("profile_version", intake.profile_version.as_str()),
        (
            "provider_protocol_identity",
            intake.provider_protocol_identity.as_str(),
        ),
        ("origin_carrier", intake.origin_carrier.as_str()),
    ] {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(StoreError::Invariant(format!(
                "provider intake {name} must be nonempty, bounded, and printable"
            )));
        }
    }
    validate_digest("idempotency_key", &intake.idempotency_key)?;
    if intake.idempotency_key
        != provider_idempotency_key(&intake.provider_admission_id, &intake.attempt_id)?
    {
        return Err(StoreError::Invariant(
            "provider idempotency key does not match its admitted provider and attempt".into(),
        ));
    }
    validate_digest("binding_digest", &intake.binding_digest)?;
    validate_digest("profile_digest", &intake.profile_digest)?;
    validate_digest(
        "checkpoint_contract_digest",
        &intake.checkpoint_contract_digest,
    )?;
    if intake.provider_sequence.as_ref().is_some_and(|sequence| {
        sequence.is_empty() || sequence.len() > 256 || sequence.chars().any(char::is_control)
    }) {
        return Err(StoreError::Invariant(
            "provider sequence must be absent or nonempty, bounded, and printable".into(),
        ));
    }
    if intake.provider_sequence.is_some() {
        return Err(StoreError::Invariant(
            "the schema-v4 local-helper provider contract does not admit a provider sequence"
                .into(),
        ));
    }
    let raw_limit = nq_protocol::MAX_RESPONSE_FRAME_BYTES
        + usize::from(intake.native_outcome_kind == "output_too_large");
    if intake.raw_bytes.len() > raw_limit {
        return Err(StoreError::Invariant(format!(
            "provider intake raw capture is {} bytes; exact outcome limit is {raw_limit}",
            intake.raw_bytes.len(),
        )));
    }
    if intake.context.as_bytes().len() > 1_048_576
        || intake.native_outcome.as_bytes().len() > 1_048_576
    {
        return Err(StoreError::Invariant(
            "provider intake context or native outcome exceeds its 1 MiB bound".into(),
        ));
    }
    if !matches!(
        intake.interpretation_kind.as_str(),
        "unavailable" | "protocol_rejected" | "provider_refusal" | "candidate_report"
    ) {
        return Err(StoreError::Invariant(
            "provider intake has an unsupported interpretation kind".into(),
        ));
    }
    if !matches!(
        intake.native_outcome_kind.as_str(),
        "response"
            | "spawn_failed"
            | "request_write_failed"
            | "timeout"
            | "output_too_large"
            | "stderr_too_large"
            | "eof"
            | "malformed_framing"
            | "malformed_json"
            | "exit_nonzero"
            | "helper_exited"
            | "disconnect"
            | "carrier_startup_failed"
            | "not_running"
            | "io_failed"
    ) {
        return Err(StoreError::Invariant(
            "provider intake has an unsupported native outcome kind".into(),
        ));
    }
    for (name, value) in [
        ("started_at", intake.started_at.as_str()),
        ("finished_at", intake.finished_at.as_str()),
        ("received_at", intake.received_at.as_str()),
        ("deadline_at", intake.deadline_at.as_str()),
    ] {
        if chrono::DateTime::parse_from_rfc3339(value).is_err() {
            return Err(StoreError::Invariant(format!(
                "provider intake {name} is not an RFC3339 timestamp"
            )));
        }
    }
    let started_at = chrono::DateTime::parse_from_rfc3339(&intake.started_at)
        .expect("provider intake start was validated");
    let finished_at = chrono::DateTime::parse_from_rfc3339(&intake.finished_at)
        .expect("provider intake finish was validated");
    let received_at = chrono::DateTime::parse_from_rfc3339(&intake.received_at)
        .expect("provider intake receive time was validated");
    if started_at > finished_at || finished_at > received_at {
        return Err(StoreError::Invariant(
            "provider intake timestamps must satisfy start <= finish <= receive".into(),
        ));
    }
    if intake.request_id != run.request_id
        || intake.source_admission_id != run.admission_id.as_deref().unwrap_or_default()
        || intake.binding_digest != run.binding_digest
        || intake.origin_carrier != run.carrier
        || intake.deadline_at != run.deadline_at
        || intake.checkpoint_contract_digest != run.checkpoint_contract_digest
        || intake.execution_identity_digest.as_str() != run.execution_identity.digest()
        || intake.instance_id != run.instance_id
        || intake.profile_id != run.profile_id
        || intake.profile_version != run.profile_version
        || intake.profile_digest != run.profile_digest
        || intake.started_at != run.started_at
        || intake.finished_at != run.finished_at
        || intake.native_outcome_kind != run.acquisition_outcome
        || intake.native_outcome.as_bytes() != run.resource_outcome.as_bytes()
    {
        return Err(StoreError::Invariant(
            "provider intake identity or native outcome does not match its local watcher run"
                .into(),
        ));
    }
    if run.acquisition_outcome == "response" && intake.interpretation_kind == "unavailable" {
        return Err(StoreError::Invariant(
            "a completed response requires an exact pre-admission interpretation".into(),
        ));
    }
    if run.acquisition_outcome != "response" && intake.interpretation_kind != "unavailable" {
        return Err(StoreError::Invariant(
            "a non-response acquisition cannot claim a parsed provider interpretation".into(),
        ));
    }
    if let Some(submission) = submission
        && (submission.raw_bytes != intake.raw_bytes
            || submission.received_at != intake.received_at)
    {
        return Err(StoreError::Invariant(
            "protocol submission does not preserve the provider intake's exact raw bytes or receive time"
                .into(),
        ));
    }
    let interpretation_matches_protocol = match (intake.interpretation_kind.as_str(), submission) {
        ("unavailable", None) => true,
        ("unavailable", Some(submission)) => {
            submission.protocol_outcome == "not_validated"
                && matches!(
                    &submission.disposition,
                    SubmissionDisposition::Rejected { .. }
                )
        }
        ("protocol_rejected", Some(submission)) => submission.protocol_outcome == "rejected",
        ("provider_refusal", Some(submission)) => submission.protocol_outcome == "valid_refusal",
        ("candidate_report", Some(submission)) => submission.protocol_outcome == "valid_report",
        _ => false,
    };
    if !interpretation_matches_protocol {
        return Err(StoreError::Invariant(
            "provider interpretation does not match the raw submission protocol outcome".into(),
        ));
    }
    Ok(())
}

fn validate_ordered_unique(
    kind: &str,
    ordinals: impl IntoIterator<Item = u32>,
) -> Result<(), StoreError> {
    for (expected, actual) in ordinals.into_iter().enumerate() {
        let expected = u32::try_from(expected)
            .map_err(|_| StoreError::Invariant(format!("too many {kind} entries")))?;
        if actual != expected {
            return Err(StoreError::Invariant(format!(
                "{kind} ordinals must be contiguous from zero; expected {expected}, got {actual}"
            )));
        }
    }
    Ok(())
}

fn validate_materialization(
    event: &BindingMaterializationInput,
    expected_phase: &str,
) -> Result<(), StoreError> {
    if event.phase != expected_phase
        || uuid::Uuid::parse_str(&event.materialization_event_id).is_err()
        || uuid::Uuid::parse_str(&event.operation_id).is_err()
        || uuid::Uuid::parse_str(&event.binding_event_id).is_err()
        || event.instance_id.is_empty()
        || event.instance_id.len() > 128
        || !event
            .instance_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || chrono::DateTime::parse_from_rfc3339(&event.occurred_at).is_err()
    {
        return Err(StoreError::Invariant(format!(
            "malformed {expected_phase} binding materialization event"
        )));
    }
    if event.detail.as_bytes().len() > MAX_BINDING_MATERIALIZATION_BYTES {
        return Err(StoreError::Invariant(format!(
            "binding materialization detail is {} bytes; limit is {MAX_BINDING_MATERIALIZATION_BYTES}",
            event.detail.as_bytes().len()
        )));
    }
    Ok(())
}

fn validate_binding_event(event: &BindingEventInput) -> Result<(), StoreError> {
    validate_digest("binding_digest", &event.binding_digest)?;
    let active = matches!(event.event_kind.as_str(), "activate" | "rollback");
    let inactive = matches!(event.event_kind.as_str(), "quiesce" | "revoke");
    if uuid::Uuid::parse_str(&event.binding_event_id).is_err()
        || event.instance_id.is_empty()
        || event.instance_id.len() > 128
        || !event
            .instance_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !active && !inactive
        || active
            && event
                .admission_id
                .as_deref()
                .is_none_or(|id| uuid::Uuid::parse_str(id).is_err())
        || inactive && event.admission_id.is_some()
        || chrono::DateTime::parse_from_rfc3339(&event.occurred_at).is_err()
        || event.reason_code.as_ref().is_some_and(|reason| {
            reason.is_empty() || reason.len() > 128 || reason.chars().any(char::is_control)
        })
        || event.detail.as_bytes().len() > 65_536
    {
        return Err(StoreError::Invariant(
            "malformed authoritative binding event".to_owned(),
        ));
    }
    Ok(())
}

fn insert_binding_event(
    transaction: &Transaction<'_>,
    event: &BindingEventInput,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO instance_binding_events (
            binding_event_id, instance_id, event_kind, admission_id, binding_digest,
            occurred_at, reason_code, detail_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            event.binding_event_id,
            event.instance_id,
            event.event_kind,
            event.admission_id,
            event.binding_digest,
            event.occurred_at,
            event.reason_code,
            event.detail.as_bytes(),
        ],
    )?;
    Ok(())
}

fn insert_materialization_event(
    transaction: &Transaction<'_>,
    event: &BindingMaterializationInput,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO binding_materialization_events (
            materialization_event_id, operation_id, instance_id,
            binding_event_id, phase, occurred_at, detail_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event.materialization_event_id,
            event.operation_id,
            event.instance_id,
            event.binding_event_id,
            event.phase,
            event.occurred_at,
            event.detail.as_bytes(),
        ],
    )?;
    Ok(())
}

fn validate_non_success_input(
    collection: &CollectionInput,
    result: &RunResultStatusInput,
) -> Result<(), StoreError> {
    if result.run_id != collection.run.run_id {
        return Err(StoreError::Invariant(format!(
            "canonical result run {} does not match collection run {}",
            result.run_id, collection.run.run_id
        )));
    }
    if result.status.component_kind != "instance"
        || result.status.component_id != collection.run.instance_id
    {
        return Err(StoreError::Invariant(
            "run-bearing result must be an instance status for the collection instance".into(),
        ));
    }
    if !is_non_success_collection(collection) {
        return Err(StoreError::Invariant(
            "atomic non-success commit requires failed acquisition or rejected custody".into(),
        ));
    }
    Ok(())
}

fn validate_admitted_completion<T>(
    collection: &CollectionInput,
    receipt: &CollectionReceipt,
    completion: &AdmittedCollectionCompletion<T>,
) -> Result<(), StoreError> {
    if completion.status.component_kind != "instance"
        || completion.status.component_id != collection.run.instance_id
    {
        return Err(StoreError::Invariant(
            "admitted result must be an instance status for the collection instance".into(),
        ));
    }
    let mut evaluation_ids = BTreeSet::new();
    for input in &completion.evaluations {
        if input.evaluation.trigger_run_id.as_deref() != Some(collection.run.run_id.as_str()) {
            return Err(StoreError::Invariant(format!(
                "admitted evaluation {} does not link the collection run {}",
                input.evaluation.evaluation_id, collection.run.run_id
            )));
        }
        if !evaluation_ids.insert(&input.evaluation.evaluation_id) {
            return Err(StoreError::Invariant(format!(
                "admitted result duplicates evaluation {}",
                input.evaluation.evaluation_id
            )));
        }
    }
    let SubmissionDisposition::Admitted(report) = &collection
        .submission
        .as_ref()
        .expect("admitted collection was checked")
        .disposition
    else {
        unreachable!("admitted collection was checked")
    };
    validate_admitted_result_document(
        completion.status.detail.as_bytes(),
        &collection.run.run_id,
        &collection.run.instance_id,
        &report.report_id,
        &report.report_status,
        receipt
            .semantic_digest
            .as_deref()
            .expect("admitted receipt was checked"),
        completion
            .evaluations
            .iter()
            .map(|input| input.evaluation.detail.as_bytes()),
    )
    .map_err(StoreError::Invariant)?;
    Ok(())
}

fn validate_admitted_result_document<'a>(
    detail: &[u8],
    run_id: &str,
    instance_id: &str,
    report_id: &str,
    report_status: &str,
    semantic_digest: &str,
    evaluations: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), String> {
    let value: Value = serde_json::from_slice(detail)
        .map_err(|error| format!("admitted result is not JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "admitted result is not an object".to_owned())?;
    let top_level: BTreeSet<_> = object.keys().map(String::as_str).collect();
    if top_level != BTreeSet::from(["schema", "instance_id", "run_id", "result"]) {
        return Err("admitted result has omitted or unknown envelope fields".into());
    }
    if value.get("schema").and_then(Value::as_str) != Some("nq.collection_outcome.v2")
        || value.get("instance_id").and_then(Value::as_str) != Some(instance_id)
        || value.get("run_id").and_then(Value::as_str) != Some(run_id)
    {
        return Err("admitted result substitutes its schema, instance, or run identity".into());
    }
    let result = value
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| "admitted result has no typed result object".to_owned())?;
    let result_fields: BTreeSet<_> = result.keys().map(String::as_str).collect();
    if result_fields
        != BTreeSet::from([
            "outcome",
            "report_id",
            "report_status",
            "semantic_digest",
            "evaluations",
        ])
    {
        return Err("admitted result has omitted or unknown admitted fields".into());
    }
    if result.get("outcome").and_then(Value::as_str) != Some("admitted")
        || result.get("report_id").and_then(Value::as_str) != Some(report_id)
        || result.get("report_status").and_then(Value::as_str) != Some(report_status)
        || result.get("semantic_digest").and_then(Value::as_str) != Some(semantic_digest)
    {
        return Err("admitted result substitutes its report projections".into());
    }
    let carried = result
        .get("evaluations")
        .and_then(Value::as_array)
        .ok_or_else(|| "admitted result evaluations are not an array".to_owned())?;
    let carried = carried
        .iter()
        .map(|value| {
            CanonicalDocument::from_serializable(value)
                .map(|document| document.as_bytes().to_vec())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let persisted = evaluations
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if carried != persisted {
        return Err(
            "admitted result evaluations differ from the exact persisted trigger sequence".into(),
        );
    }
    Ok(())
}

fn is_non_success_collection(collection: &CollectionInput) -> bool {
    collection.run.acquisition_outcome != "response"
        || collection.submission.as_ref().is_some_and(|submission| {
            matches!(
                submission.disposition,
                SubmissionDisposition::Rejected { .. }
            )
        })
}

fn is_admitted_collection(collection: &CollectionInput) -> bool {
    collection.run.acquisition_outcome == "response"
        && collection.submission.as_ref().is_some_and(|submission| {
            matches!(submission.disposition, SubmissionDisposition::Admitted(_))
        })
}

#[allow(clippy::too_many_lines)]
fn validate_provider_admission(
    connection: &Connection,
    intake: &ProviderIntakeInput,
    require_current: bool,
) -> Result<(), StoreError> {
    let admission = connection
        .query_row(
            "SELECT admission.instance_id, admission.config_digest,
                    admission.helper_artifact_digest, admission.profile_semantic_id,
                    admission.evaluator_artifact_digest,
                    admission.admission_context_digest, admission.profile_id,
                    admission.profile_version, admission.profile_digest,
                    admission.protocol_version, admission.conformance_json,
                    provider.source_admission_id, provider.provider_semantic_id,
                    provider.provider_artifact_digest,
                    provider.provider_protocol_identity,
                    provider.provider_config_digest, provider.contract_json,
                    provider.contract_digest, admission.lock_json,
                    admission.execution_chain_json
             FROM local_provider_admissions AS provider
             JOIN admission_records AS admission
               ON admission.admission_id = provider.source_admission_id
             WHERE provider.provider_admission_id = ?1",
            [&intake.provider_admission_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, Vec<u8>>(18)?,
                    row.get::<_, Vec<u8>>(19)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            StoreError::Invariant(format!(
                "provider intake names missing admission {}",
                intake.provider_admission_id
            ))
        })?;
    let conformance = CanonicalDocument::from_canonical_bytes(admission.10).map_err(|error| {
        StoreError::Integrity(format!(
            "provider admission {} conformance is not canonical: {error}",
            intake.provider_admission_id
        ))
    })?;
    let expected_semantic = local_provider_semantic_id(&admission.9, &conformance)?.into_string();
    let contract = CanonicalDocument::from_canonical_bytes(admission.16).map_err(|error| {
        StoreError::Integrity(format!(
            "provider admission {} contract is not canonical: {error}",
            intake.provider_admission_id
        ))
    })?;
    let source_lock = CanonicalDocument::from_canonical_bytes(admission.18).map_err(|error| {
        StoreError::Integrity(format!(
            "provider admission {} source lock is not canonical: {error}",
            intake.provider_admission_id
        ))
    })?;
    let source_execution =
        CanonicalDocument::from_canonical_bytes(admission.19).map_err(|error| {
            StoreError::Integrity(format!(
                "provider admission {} source execution identity is not canonical: {error}",
                intake.provider_admission_id
            ))
        })?;
    if intake.instance_id != admission.0
        || intake.source_admission_id != admission.11
        || intake.provider_config_digest.as_str() != admission.1
        || intake.provider_artifact_digest.as_str() != admission.2
        || intake.profile_semantic_id.as_str() != admission.3
        || intake.evaluator_artifact_digest.as_str() != admission.4
        || intake.admission_context_digest.as_str() != admission.5
        || intake.profile_id != admission.6
        || intake.profile_version != admission.7
        || intake.profile_digest != admission.8
        || intake.provider_protocol_identity != admission.9
        || intake.provider_semantic_id.as_str() != expected_semantic
        || admission.12 != expected_semantic
        || admission.13 != admission.2
        || admission.14 != admission.9
        || admission.15 != admission.1
        || contract.digest() != admission.17
        || contract.digest() != intake.provider_admission_id
        || source_lock.digest() != intake.binding_digest
        || source_execution.digest() != intake.execution_identity_digest.as_str()
    {
        return Err(StoreError::Invariant(
            "provider intake identity does not match NQ-owned admission facts".into(),
        ));
    }
    if require_current {
        let current: Option<(String, Option<String>, String)> = connection
            .query_row(
                "SELECT event_kind, admission_id, binding_digest
                 FROM instance_binding_events
                 WHERE instance_id = ?1
                 ORDER BY binding_sequence DESC LIMIT 1",
                [&intake.instance_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let active = current.is_some_and(|(kind, admission_id, binding_digest)| {
            matches!(kind.as_str(), "activate" | "rollback")
                && admission_id.as_deref() == Some(intake.source_admission_id.as_str())
                && binding_digest == intake.binding_digest
        });
        if !active {
            return Err(StoreError::Invariant(format!(
                "provider admission {} is not the current exact active binding for {}",
                intake.provider_admission_id, intake.instance_id
            )));
        }
    }
    Ok(())
}

fn provider_intake_preflight_on_connection(
    connection: &Connection,
    intake: &ProviderIntakeInput,
    require_current: bool,
) -> Result<ProviderIntakePreflight, StoreError> {
    validate_provider_admission(connection, intake, require_current)?;
    let digests = provider_intake_digests(intake)?;
    let existing: Option<(String, String, String)> = connection
        .query_row(
            "SELECT intake_id, idempotency_key, replay_digest
             FROM provider_intake_attempts
             WHERE idempotency_key = ?1 OR attempt_id = ?2 OR request_id = ?3
             ORDER BY intake_sequence LIMIT 1",
            params![intake.idempotency_key, intake.attempt_id, intake.request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((intake_id, idempotency_key, replay_digest)) = existing else {
        return Ok(ProviderIntakePreflight::New);
    };
    if idempotency_key != intake.idempotency_key || replay_digest != digests.replay_digest {
        return Err(StoreError::ReplayConflict(format!(
            "attempt, request, or idempotency identity is already bound to intake {intake_id} with different exact evidence or context"
        )));
    }
    let (acknowledgment, canonical_result) =
        provider_acknowledgment_for_intake(connection, &intake_id)?.ok_or_else(|| {
            StoreError::Integrity(format!(
                "provider intake {intake_id} exists without a durable acknowledgment"
            ))
        })?;
    Ok(ProviderIntakePreflight::Existing {
        acknowledgment,
        canonical_result,
    })
}

fn insert_provider_intake(
    transaction: &Transaction<'_>,
    intake: &ProviderIntakeInput,
) -> Result<(), StoreError> {
    validate_provider_admission(transaction, intake, true)?;
    let digests = provider_intake_digests(intake)?;
    transaction.execute(
        "INSERT INTO provider_intake_attempts (
            intake_id, schema_id, idempotency_key, attempt_id, request_id,
            provider_admission_id, admission_context_digest,
            provider_semantic_id, provider_artifact_digest,
            provider_protocol_identity, provider_config_digest, binding_digest,
            instance_id, profile_id, profile_version, profile_digest,
            profile_semantic_id, evaluator_artifact_digest,
            context_json, context_digest, interpretation_kind,
            interpretation_json, interpretation_digest, native_outcome_kind,
            native_outcome_json, native_outcome_digest, raw_bytes, raw_sha256,
            started_at, finished_at, received_at, replay_digest, intake_digest,
            source_admission_id, provider_sequence, origin_carrier, deadline_at,
            checkpoint_contract_digest, execution_identity_digest
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
            ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38,
            ?39
         )",
        params![
            intake.intake_id,
            PROVIDER_INTAKE_SCHEMA,
            intake.idempotency_key,
            intake.attempt_id,
            intake.request_id,
            intake.provider_admission_id,
            intake.admission_context_digest.as_str(),
            intake.provider_semantic_id.as_str(),
            intake.provider_artifact_digest.as_str(),
            intake.provider_protocol_identity,
            intake.provider_config_digest.as_str(),
            intake.binding_digest,
            intake.instance_id,
            intake.profile_id,
            intake.profile_version,
            intake.profile_digest,
            intake.profile_semantic_id.as_str(),
            intake.evaluator_artifact_digest.as_str(),
            intake.context.as_bytes(),
            digests.context_digest,
            intake.interpretation_kind,
            intake.interpretation.as_bytes(),
            digests.interpretation_digest,
            intake.native_outcome_kind,
            intake.native_outcome.as_bytes(),
            digests.native_outcome_digest,
            intake.raw_bytes,
            digests.raw_sha256,
            intake.started_at,
            intake.finished_at,
            intake.received_at,
            digests.replay_digest,
            digests.intake_digest,
            intake.source_admission_id,
            intake.provider_sequence,
            intake.origin_carrier,
            intake.deadline_at,
            intake.checkpoint_contract_digest,
            intake.execution_identity_digest.as_str(),
        ],
    )?;
    Ok(())
}

fn insert_local_provider_intake_link(
    transaction: &Transaction<'_>,
    intake_id: &str,
    run_id: &str,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO local_watcher_provider_intakes (intake_id, run_id)
         VALUES (?1, ?2)",
        params![intake_id, run_id],
    )?;
    Ok(())
}

fn build_provider_acknowledgment(
    intake: &ProviderIntakeInput,
    run_id: &str,
    status: &StatusEventInput,
) -> Result<(DurableIntakeAcknowledgment, CanonicalDocument), StoreError> {
    let digests = provider_intake_digests(intake)?;
    let acknowledgment_id = uuid::Uuid::new_v4().to_string();
    let committed_at = now_utc();
    let canonical_result_digest = status.detail.digest().to_owned();
    let detail = CanonicalDocument::from_serializable(&ProviderAcknowledgmentDocument {
        schema: PROVIDER_INTAKE_ACK_SCHEMA,
        acknowledgment_id: &acknowledgment_id,
        intake_id: &intake.intake_id,
        attempt_id: &intake.attempt_id,
        run_id,
        provider_admission_id: &intake.provider_admission_id,
        intake_digest: &digests.intake_digest,
        raw_sha256: &digests.raw_sha256,
        status_event_id: &status.status_event_id,
        canonical_result_digest: &canonical_result_digest,
        committed_at: &committed_at,
        establishes: "durable_custody_and_canonical_processing",
        does_not_establish: [
            "report_admission",
            "detector_result",
            "health",
            "testimonial_sufficiency",
            "authority",
            "external_obligation_discharge",
        ],
    })?;
    Ok((
        DurableIntakeAcknowledgment {
            acknowledgment_id,
            intake_id: intake.intake_id.clone(),
            attempt_id: intake.attempt_id.clone(),
            run_id: run_id.to_owned(),
            provider_admission_id: intake.provider_admission_id.clone(),
            intake_digest: digests.intake_digest,
            raw_sha256: digests.raw_sha256,
            status_event_id: status.status_event_id.clone(),
            canonical_result_digest,
            committed_at,
            detail_json: detail.as_bytes().to_vec(),
        },
        detail,
    ))
}

fn insert_provider_acknowledgment(
    transaction: &Transaction<'_>,
    intake: &ProviderIntakeInput,
    run_id: &str,
    status: &StatusEventInput,
) -> Result<DurableIntakeAcknowledgment, StoreError> {
    let (acknowledgment, detail) = build_provider_acknowledgment(intake, run_id, status)?;
    transaction.execute(
        "INSERT INTO provider_intake_acknowledgments (
            acknowledgment_id, intake_id, run_id, provider_admission_id,
            status_event_id, schema_id, detail_json, acknowledgment_digest,
            committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            acknowledgment.acknowledgment_id,
            acknowledgment.intake_id,
            acknowledgment.run_id,
            acknowledgment.provider_admission_id,
            acknowledgment.status_event_id,
            PROVIDER_INTAKE_ACK_SCHEMA,
            detail.as_bytes(),
            detail.digest(),
            acknowledgment.committed_at,
        ],
    )?;
    Ok(acknowledgment)
}

#[allow(clippy::too_many_lines)]
fn provider_acknowledgment_for_intake(
    connection: &Connection,
    intake_id: &str,
) -> Result<Option<(DurableIntakeAcknowledgment, CanonicalDocument)>, StoreError> {
    let row = connection
        .query_row(
            "SELECT acknowledgment.acknowledgment_id,
                    acknowledgment.intake_id, intake.attempt_id,
                    acknowledgment.run_id, acknowledgment.provider_admission_id,
                    intake.intake_digest, intake.raw_sha256,
                    acknowledgment.status_event_id,
                    acknowledgment.acknowledgment_digest,
                    acknowledgment.committed_at, acknowledgment.detail_json,
                    status.detail_json
             FROM provider_intake_acknowledgments AS acknowledgment
             JOIN provider_intake_attempts AS intake
               ON intake.intake_id = acknowledgment.intake_id
              AND intake.provider_admission_id = acknowledgment.provider_admission_id
             JOIN local_watcher_provider_intakes AS local
               ON local.intake_id = intake.intake_id
              AND local.run_id = acknowledgment.run_id
             JOIN status_events AS status
               ON status.status_event_id = acknowledgment.status_event_id
              AND status.run_id = local.run_id
             WHERE acknowledgment.intake_id = ?1",
            [intake_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let detail = CanonicalDocument::from_canonical_bytes(row.10).map_err(|error| {
        StoreError::Integrity(format!(
            "provider intake {} acknowledgment is not canonical: {error}",
            row.1
        ))
    })?;
    if detail.digest() != row.8 {
        return Err(StoreError::Integrity(format!(
            "provider intake {} acknowledgment digest does not match its exact bytes",
            row.1
        )));
    }
    let canonical_result = CanonicalDocument::from_canonical_bytes(row.11).map_err(|error| {
        StoreError::Integrity(format!(
            "provider intake {} canonical result is not exact: {error}",
            row.1
        ))
    })?;
    if chrono::DateTime::parse_from_rfc3339(&row.9).is_err() {
        return Err(StoreError::Integrity(format!(
            "provider intake {} acknowledgment has an invalid transaction timestamp",
            row.1
        )));
    }
    let expected = CanonicalDocument::from_serializable(&ProviderAcknowledgmentDocument {
        schema: PROVIDER_INTAKE_ACK_SCHEMA,
        acknowledgment_id: &row.0,
        intake_id: &row.1,
        attempt_id: &row.2,
        run_id: &row.3,
        provider_admission_id: &row.4,
        intake_digest: &row.5,
        raw_sha256: &row.6,
        status_event_id: &row.7,
        canonical_result_digest: canonical_result.digest(),
        committed_at: &row.9,
        establishes: "durable_custody_and_canonical_processing",
        does_not_establish: [
            "report_admission",
            "detector_result",
            "health",
            "testimonial_sufficiency",
            "authority",
            "external_obligation_discharge",
        ],
    })?;
    if expected.as_bytes() != detail.as_bytes() {
        return Err(StoreError::Integrity(format!(
            "provider intake {} acknowledgment substitutes its bound identities or canonical result",
            row.1
        )));
    }
    Ok(Some((
        DurableIntakeAcknowledgment {
            acknowledgment_id: row.0,
            intake_id: row.1,
            attempt_id: row.2,
            run_id: row.3,
            provider_admission_id: row.4,
            intake_digest: row.5,
            raw_sha256: row.6,
            status_event_id: row.7,
            canonical_result_digest: canonical_result.digest().to_owned(),
            committed_at: row.9,
            detail_json: detail.as_bytes().to_vec(),
        },
        canonical_result,
    )))
}

fn collection_receipt_for_run(
    connection: &Connection,
    run_id: &str,
) -> Result<CollectionReceipt, StoreError> {
    let raw_sha256: Option<String> = connection
        .query_row(
            "SELECT raw_sha256 FROM raw_submissions WHERE run_id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .optional()?;
    let admitted: Option<(String, i64)> = connection
        .query_row(
            "SELECT report.semantic_digest, report.report_sequence
             FROM raw_submissions AS submission
             JOIN admitted_reports AS report ON report.submission_id = submission.submission_id
             WHERE submission.run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let refusal_id: Option<String> = connection
        .query_row(
            "SELECT refusal.refusal_id
             FROM raw_submissions AS submission
             JOIN refusals AS refusal ON refusal.submission_id = submission.submission_id
             WHERE submission.run_id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(CollectionReceipt {
        raw_sha256,
        semantic_digest: admitted.as_ref().map(|row| row.0.clone()),
        report_sequence: admitted.map(|row| row.1),
        refusal_id,
    })
}

fn insert_collection(
    transaction: &Transaction<'_>,
    collection: &CollectionInput,
) -> Result<CollectionReceipt, StoreError> {
    insert_provider_intake(transaction, &collection.intake)?;
    insert_run(transaction, &collection.run)?;
    insert_local_provider_intake_link(
        transaction,
        &collection.intake.intake_id,
        &collection.run.run_id,
    )?;
    let mut receipt = CollectionReceipt {
        raw_sha256: None,
        semantic_digest: None,
        report_sequence: None,
        refusal_id: None,
    };
    let Some(submission) = &collection.submission else {
        return Ok(receipt);
    };
    let raw_sha256 = sha256_digest(&submission.raw_bytes);
    let (admission_outcome, rejection_code) = match &submission.disposition {
        SubmissionDisposition::Rejected { refusal } => ("rejected", Some(refusal.code.as_str())),
        SubmissionDisposition::Admitted(_) => ("admitted", None),
    };
    transaction.execute(
        "INSERT INTO raw_submissions (
            submission_id, run_id, raw_bytes, raw_sha256, received_at,
            protocol_outcome, admission_outcome, rejection_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            submission.submission_id,
            collection.run.run_id,
            submission.raw_bytes,
            raw_sha256,
            submission.received_at,
            submission.protocol_outcome,
            admission_outcome,
            rejection_code,
        ],
    )?;
    receipt.raw_sha256 = Some(raw_sha256);

    match &submission.disposition {
        SubmissionDisposition::Rejected { refusal } => {
            insert_refusal(
                transaction,
                refusal,
                Some(&collection.run.run_id),
                Some(&submission.submission_id),
                None,
                Some((
                    &collection.run.profile_id,
                    &collection.run.profile_version,
                    &collection.run.profile_digest,
                )),
            )?;
            receipt.refusal_id = Some(refusal.refusal_id.clone());
        }
        SubmissionDisposition::Admitted(report) => {
            let admission_id = collection.run.admission_id.as_deref().ok_or_else(|| {
                StoreError::Invariant(
                    "an admitted report requires a run bound to an admission".to_owned(),
                )
            })?;
            let (admission_instance_id, admission_context_digest): (String, String) = transaction
                .query_row(
                    "SELECT instance_id, admission_context_digest FROM admission_records
                     WHERE admission_id = ?1",
                    [admission_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    StoreError::Invariant(format!(
                        "run admission {admission_id} is not recorded; cannot bind report context"
                    ))
                })?;
            if admission_instance_id != collection.run.instance_id {
                return Err(StoreError::Invariant(format!(
                    "run instance {} cannot bind admission {admission_id} of instance {admission_instance_id}",
                    collection.run.instance_id
                )));
            }
            let sequence = insert_report(
                transaction,
                &submission.submission_id,
                report,
                &admission_context_digest,
            )?;
            receipt.semantic_digest = Some(report.canonical_report.digest().to_owned());
            receipt.report_sequence = Some(sequence);
        }
    }
    Ok(receipt)
}

fn insert_status_event(
    transaction: &Transaction<'_>,
    status: &StatusEventInput,
    run_id: Option<&str>,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO status_events (
            status_event_id, component_kind, component_id, run_id, state, code,
            detail_json, observed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            status.status_event_id,
            status.component_kind,
            status.component_id,
            run_id,
            status.state,
            status.code,
            status.detail.as_bytes(),
            status.observed_at,
        ],
    )?;
    transaction.execute(
        "INSERT INTO status_current (component_kind, component_id, latest_status_event_id)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(component_kind, component_id) DO UPDATE
         SET latest_status_event_id = excluded.latest_status_event_id",
        params![
            status.component_kind,
            status.component_id,
            status.status_event_id,
        ],
    )?;
    Ok(())
}

fn insert_run(transaction: &Transaction<'_>, run: &RunInput) -> Result<(), StoreError> {
    validate_digest(
        "checkpoint_contract_digest",
        &run.checkpoint_contract_digest,
    )?;
    if let Some(admission_id) = &run.admission_id {
        let binding: Option<(String, String, String, String)> = transaction
            .query_row(
                "SELECT instance_id, profile_id, profile_version, profile_digest
                 FROM admission_records WHERE admission_id = ?1",
                [admission_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((instance_id, profile_id, profile_version, profile_digest)) = binding else {
            return Err(StoreError::Invariant(format!(
                "watcher run names missing admission {admission_id}"
            )));
        };
        if run.instance_id != instance_id
            || run.profile_id != profile_id
            || run.profile_version != profile_version
            || run.profile_digest != profile_digest
        {
            return Err(StoreError::Invariant(format!(
                "watcher run cannot bind admission {admission_id}: instance or profile identity disagrees"
            )));
        }
    }
    transaction.execute(
        "INSERT INTO watcher_runs (
            run_id, request_id, instance_id, admission_id, binding_digest,
            checkpoint_contract_digest, profile_id, profile_version, profile_digest, carrier, started_at,
            deadline_at, finished_at, acquisition_outcome, execution_identity_json,
            resource_outcome_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            run.run_id,
            run.request_id,
            run.instance_id,
            run.admission_id,
            run.binding_digest,
            run.checkpoint_contract_digest,
            run.profile_id,
            run.profile_version,
            run.profile_digest,
            run.carrier,
            run.started_at,
            run.deadline_at,
            run.finished_at,
            run.acquisition_outcome,
            run.execution_identity.as_bytes(),
            run.resource_outcome.as_bytes(),
        ],
    )?;
    Ok(())
}

fn insert_report(
    transaction: &Transaction<'_>,
    submission_id: &str,
    report: &ReportInput,
    admission_context_digest: &str,
) -> Result<i64, StoreError> {
    let judgment_digest =
        judgment_digest(admission_context_digest, report.validated_report.digest())?;
    transaction.execute(
        "INSERT INTO admitted_reports (
            report_id, submission_id, instance_id, profile_id, profile_version,
            profile_digest, observed_at, received_at, report_status, canonical_json,
            semantic_digest, validated_report_json, judgment_schema_version,
            judgment_digest, admission_context_digest, next_checkpoint_json, admitted_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            report.report_id,
            submission_id,
            report.instance_id,
            report.profile_id,
            report.profile_version,
            report.profile_digest,
            report.observed_at,
            report.received_at,
            report.report_status,
            report.canonical_report.as_bytes(),
            report.canonical_report.digest(),
            report.validated_report.as_bytes(),
            JUDGMENT_SCHEMA_VERSION,
            judgment_digest,
            admission_context_digest,
            report
                .next_checkpoint
                .as_ref()
                .map(CanonicalDocument::as_bytes),
            report.admitted_at,
        ],
    )?;
    let report_sequence = transaction.last_insert_rowid();
    for observation in &report.observations {
        transaction.execute(
            "INSERT INTO observations (
                report_id, ordinal, kind, subject_json, observed_at, payload_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                report.report_id,
                observation.ordinal,
                observation.kind,
                observation.subject.as_bytes(),
                observation.observed_at,
                observation.payload.as_bytes(),
            ],
        )?;
        for coverage in &observation.coverage {
            transaction.execute(
                "INSERT INTO observation_coverage (
                    report_id, observation_ordinal, ordinal, coverage_kind,
                    coverage_state, detail_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    report.report_id,
                    observation.ordinal,
                    coverage.ordinal,
                    coverage.coverage_kind,
                    coverage.coverage_state,
                    coverage.detail.as_bytes(),
                ],
            )?;
        }
    }
    for coverage in &report.coverage {
        transaction.execute(
            "INSERT INTO report_coverage (
                report_id, ordinal, coverage_kind, coverage_state, detail_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                report.report_id,
                coverage.ordinal,
                coverage.coverage_kind,
                coverage.coverage_state,
                coverage.detail.as_bytes(),
            ],
        )?;
    }
    for error in &report.errors {
        transaction.execute(
            "INSERT INTO report_errors (report_id, ordinal, code, detail_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                report.report_id,
                error.ordinal,
                error.code,
                error.detail.as_bytes(),
            ],
        )?;
    }
    Ok(report_sequence)
}

fn insert_refusal(
    transaction: &Transaction<'_>,
    refusal: &RefusalInput,
    run_id: Option<&str>,
    submission_id: Option<&str>,
    evaluation_id: Option<&str>,
    profile: Option<(&str, &str, &str)>,
) -> Result<(), StoreError> {
    if refusal.source_kind == "profile" {
        let semantic = refusal.profile_semantic_id.as_deref().ok_or_else(|| {
            StoreError::Invariant(
                "profile-origin refusal requires a profile semantic identity".into(),
            )
        })?;
        validate_digest("profile_semantic_id", semantic)?;
        if profile.is_none() {
            return Err(StoreError::Invariant(
                "profile-origin refusal requires an exact profile binding".into(),
            ));
        }
    } else if refusal.profile_semantic_id.is_some() {
        return Err(StoreError::Invariant(
            "non-profile refusal cannot carry a profile semantic projection".into(),
        ));
    }
    let (profile_id, profile_version, profile_digest) = profile
        .map_or((None, None, None), |(id, version, digest)| {
            (Some(id), Some(version), Some(digest))
        });
    transaction.execute(
        "INSERT INTO refusals (
            refusal_id, source_kind, responsible_instance_id, boundary, code,
            run_id, submission_id, evaluation_id, profile_id, profile_version,
            profile_digest, profile_semantic_id, detail_json, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            refusal.refusal_id,
            refusal.source_kind,
            refusal.responsible_instance_id,
            refusal.boundary,
            refusal.code,
            run_id,
            submission_id,
            evaluation_id,
            profile_id,
            profile_version,
            profile_digest,
            refusal.profile_semantic_id,
            refusal.detail.as_bytes(),
            refusal.created_at,
        ],
    )?;
    Ok(())
}

fn validate_watermark(
    transaction: &Transaction<'_>,
    watermark: &EvaluationWatermark,
) -> Result<(), StoreError> {
    if watermark.max_report_sequence < 0 {
        return Err(StoreError::Invariant(
            "evaluation watermark cannot be negative".to_owned(),
        ));
    }
    if watermark.max_report_sequence == 0 {
        if watermark.watermark_received_at.is_some() {
            return Err(StoreError::Invariant(
                "empty watermark cannot carry a received time".to_owned(),
            ));
        }
        return Ok(());
    }
    let received_at: Option<String> = transaction
        .query_row(
            "SELECT received_at FROM admitted_reports
             WHERE instance_id = ?1 AND report_sequence = ?2",
            params![watermark.instance_id, watermark.max_report_sequence],
            |row| row.get(0),
        )
        .optional()?;
    if received_at.as_ref() != watermark.watermark_received_at.as_ref() {
        return Err(StoreError::Invariant(format!(
            "watermark {}:{} does not identify an admitted report",
            watermark.instance_id, watermark.max_report_sequence
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn insert_evaluation(
    transaction: &Transaction<'_>,
    evaluation: &EvaluationInput,
    finding: Option<&FindingEventInput>,
) -> Result<EvaluationReceipt, StoreError> {
    validate_digest("detector_digest", &evaluation.detector_digest)?;
    validate_digest(
        "evaluator_artifact_digest",
        &evaluation.evaluator_artifact_digest,
    )?;
    validate_digest("profile_digest", &evaluation.profile.profile_digest)?;
    if (evaluation.outcome == "cannot_evaluate") != evaluation.refusal.is_some() {
        return Err(StoreError::Invariant(
            "cannot_evaluate requires exactly one typed refusal".to_owned(),
        ));
    }
    if let Some(finding) = finding {
        validate_finding_against_evaluation(finding, evaluation)?;
    }

    if let Some(trigger_run_id) = evaluation.trigger_run_id.as_deref() {
        let trigger: Option<(String, String, String, String, i64, String)> = transaction
            .query_row(
                "SELECT run.instance_id, run.profile_id, run.profile_version,
                        run.profile_digest, report.report_sequence,
                        admission.evaluator_artifact_digest
                 FROM watcher_runs AS run
                 JOIN raw_submissions AS submission ON submission.run_id = run.run_id
                 JOIN admitted_reports AS report
                   ON report.submission_id = submission.submission_id
                 JOIN admission_records AS admission
                   ON admission.admission_id = run.admission_id
                 WHERE run.run_id = ?1 AND submission.admission_outcome = 'admitted'",
                [trigger_run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            instance_id,
            profile_id,
            profile_version,
            profile_digest,
            report_sequence,
            admission_evaluator_artifact_digest,
        )) = trigger
        else {
            return Err(StoreError::Invariant(format!(
                "evaluation trigger run {trigger_run_id} is not an admitted collection"
            )));
        };
        if evaluation.evaluator_artifact_digest != admission_evaluator_artifact_digest {
            return Err(StoreError::Invariant(format!(
                "evaluation trigger run {trigger_run_id} uses evaluator artifact {} but its admission binds {admission_evaluator_artifact_digest}",
                evaluation.evaluator_artifact_digest
            )));
        }
        if profile_id != evaluation.profile.profile_id
            || profile_version != evaluation.profile.profile_version
            || profile_digest != evaluation.profile.profile_digest
            || !matches!(evaluation.watermarks.as_slice(), [watermark]
                if watermark.instance_id == instance_id
                    && watermark.max_report_sequence == report_sequence)
        {
            return Err(StoreError::Invariant(format!(
                "evaluation trigger run {trigger_run_id} disagrees with its profile or instance watermark"
            )));
        }
    }
    let current_revision: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(evaluation_revision), 0)
         FROM evaluation_runs
         WHERE detector_id = ?1 AND detector_version = ?2",
        params![evaluation.detector_id, evaluation.detector_version],
        |row| row.get(0),
    )?;
    let evaluation_revision = current_revision.checked_add(1).ok_or_else(|| {
        StoreError::Invariant("evaluation revision space is exhausted".to_owned())
    })?;
    let current_sequence: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(evaluation_sequence), 0) FROM evaluation_runs",
        [],
        |row| row.get(0),
    )?;
    let evaluation_sequence = current_sequence.checked_add(1).ok_or_else(|| {
        StoreError::Invariant("evaluation sequence space is exhausted".to_owned())
    })?;
    transaction.execute(
        "INSERT INTO evaluation_runs (
            evaluation_id, evaluation_sequence, trigger_run_id, detector_id, detector_version,
            detector_digest, evaluator_artifact_digest,
            profile_id, profile_version, profile_digest, profile_semantic_id,
            evaluation_revision, started_at, evaluated_at, outcome, detail_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16)",
        params![
            evaluation.evaluation_id,
            evaluation_sequence,
            evaluation.trigger_run_id,
            evaluation.detector_id,
            evaluation.detector_version,
            evaluation.detector_digest,
            evaluation.evaluator_artifact_digest,
            evaluation.profile.profile_id,
            evaluation.profile.profile_version,
            evaluation.profile.profile_digest,
            evaluation.profile.profile_semantic_id.as_str(),
            evaluation_revision,
            evaluation.started_at,
            evaluation.evaluated_at,
            evaluation.outcome,
            evaluation.detail.as_bytes(),
        ],
    )?;

    let mut seen_instances = BTreeSet::new();
    let mut watermarks = Vec::with_capacity(evaluation.watermarks.len());
    for watermark in &evaluation.watermarks {
        if !seen_instances.insert(watermark.instance_id.clone()) {
            return Err(StoreError::Invariant(format!(
                "duplicate evaluation watermark for {}",
                watermark.instance_id
            )));
        }
        validate_watermark(transaction, watermark)?;
        transaction.execute(
            "INSERT INTO evaluation_watermarks (
                evaluation_id, instance_id, max_report_sequence, watermark_received_at
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                evaluation.evaluation_id,
                watermark.instance_id,
                watermark.max_report_sequence,
                watermark.watermark_received_at,
            ],
        )?;
        watermarks.push(watermark.clone());
    }

    if let Some(refusal) = &evaluation.refusal {
        if refusal.source_kind != "profile"
            || !evaluation
                .watermarks
                .iter()
                .any(|watermark| watermark.instance_id == refusal.responsible_instance_id)
            || refusal.profile_semantic_id.as_deref()
                != Some(evaluation.profile.profile_semantic_id.as_str())
        {
            return Err(StoreError::Invariant(
                "evaluation refusal disagrees with its required profile semantic binding".into(),
            ));
        }
        insert_refusal(
            transaction,
            refusal,
            None,
            None,
            Some(&evaluation.evaluation_id),
            Some((
                &evaluation.profile.profile_id,
                &evaluation.profile.profile_version,
                &evaluation.profile.profile_digest,
            )),
        )?;
    }
    if let Some(finding) = finding {
        insert_finding_event(
            transaction,
            evaluation,
            evaluation_revision,
            finding,
            &watermarks,
        )?;
    }
    Ok(EvaluationReceipt {
        evaluation_id: evaluation.evaluation_id.clone(),
        evaluation_sequence: u64::try_from(evaluation_sequence).map_err(|_| {
            StoreError::Invariant("allocated a negative evaluation sequence".to_owned())
        })?,
        evaluation_revision: u64::try_from(evaluation_revision).map_err(|_| {
            StoreError::Invariant("allocated a negative evaluation revision".to_owned())
        })?,
        watermarks,
    })
}

fn validate_finding_against_evaluation(
    finding: &FindingEventInput,
    evaluation: &EvaluationInput,
) -> Result<(), StoreError> {
    validate_digest("profile_digest", &finding.profile_digest)?;
    if finding.profile_id != evaluation.profile.profile_id
        || finding.profile_version != evaluation.profile.profile_version
        || finding.profile_digest != evaluation.profile.profile_digest
    {
        return Err(StoreError::Invariant(
            "finding profile binding disagrees with its evaluation".into(),
        ));
    }
    if finding.refusal.as_ref().map(CanonicalDocument::as_bytes)
        != evaluation
            .refusal
            .as_ref()
            .map(|refusal| refusal.detail.as_bytes())
    {
        return Err(StoreError::Invariant(
            "finding refusal must be the exact canonical evaluation refusal".into(),
        ));
    }
    if finding.event_kind == "resolved"
        && (evaluation.outcome != "condition_explicitly_absent"
            || finding.condition_state != "explicitly_absent"
            || finding.visibility_state != "sufficient")
    {
        return Err(StoreError::Invariant(
            "only explicit absence under sufficient current coverage can resolve a finding"
                .to_owned(),
        ));
    }
    if evaluation.outcome == "condition_present" && finding.condition_state != "present" {
        return Err(StoreError::Invariant(
            "finding condition disagrees with detector outcome".to_owned(),
        ));
    }
    if evaluation.outcome == "condition_explicitly_absent"
        && finding.condition_state != "explicitly_absent"
    {
        return Err(StoreError::Invariant(
            "finding condition disagrees with detector outcome".to_owned(),
        ));
    }
    if evaluation.outcome == "cannot_evaluate" && finding.event_kind == "resolved" {
        return Err(StoreError::Invariant(
            "a detector refusal cannot resolve a finding".to_owned(),
        ));
    }
    if evaluation.outcome == "cannot_evaluate" && finding.event_kind == "opened" {
        return Err(StoreError::Invariant(
            "a detector refusal cannot open a finding without a prior present condition".into(),
        ));
    }
    validate_ordered_unique(
        "finding evidence",
        finding.evidence.iter().map(|evidence| evidence.ordinal),
    )
}

#[allow(clippy::too_many_lines)]
fn insert_finding_event(
    transaction: &Transaction<'_>,
    evaluation: &EvaluationInput,
    evaluation_revision: i64,
    finding: &FindingEventInput,
    watermarks: &[EvaluationWatermark],
) -> Result<(), StoreError> {
    let current: Option<(i64, String, String)> = transaction
        .query_row(
            "SELECT e.event_revision, e.event_kind, e.condition_state
             FROM finding_current AS c
             JOIN finding_events AS e ON e.event_id = c.latest_event_id
             WHERE c.finding_id = ?1",
            [&finding.finding_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match &current {
        None if finding.event_kind != "opened" => {
            return Err(StoreError::Invariant(
                "a new finding must begin with an opened event".to_owned(),
            ));
        }
        Some(_) if finding.event_kind == "opened" => {
            return Err(StoreError::Invariant(
                "an existing finding cannot be opened twice".to_owned(),
            ));
        }
        _ => {}
    }
    if current.is_some() {
        let same_lineage: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM finding_current AS current
                JOIN finding_events AS prior
                  ON prior.event_id = current.latest_event_id
                JOIN evaluation_runs AS prior_evaluation
                  ON prior_evaluation.evaluation_id = prior.evaluation_id
                WHERE current.finding_id = ?1
                  AND prior.instance_id = ?2
                  AND prior.detector_id = ?3
                  AND prior.detector_version = ?4
                  AND prior.detector_digest = ?5
                  AND prior.profile_id = ?6
                  AND prior.profile_version = ?7
                  AND prior.profile_digest = ?8
                  AND prior_evaluation.profile_semantic_id = ?9
                  AND prior.subject_json = ?10
                  AND prior.condition_name = ?11
                  AND prior.basis_json = ?12
             )",
            params![
                finding.finding_id,
                finding.instance_id,
                evaluation.detector_id,
                evaluation.detector_version,
                evaluation.detector_digest,
                finding.profile_id,
                finding.profile_version,
                finding.profile_digest,
                evaluation.profile.profile_semantic_id.as_str(),
                finding.subject.as_bytes(),
                finding.condition_name,
                finding.basis.as_bytes(),
            ],
            |row| row.get(0),
        )?;
        if !same_lineage {
            return Err(StoreError::Invariant(
                "finding update cannot substitute immutable detector, profile, subject, or condition lineage"
                    .into(),
            ));
        }
    }
    if evaluation.outcome == "cannot_evaluate" {
        let Some((_, _, current_condition_state)) = &current else {
            return Err(StoreError::Invariant(
                "a detector refusal cannot create a finding without prior condition state".into(),
            ));
        };
        if finding.visibility_state == "sufficient" {
            return Err(StoreError::Invariant(
                "a detector refusal cannot claim sufficient evidence visibility".into(),
            ));
        }
        if &finding.condition_state != current_condition_state {
            return Err(StoreError::Invariant(
                "a detector refusal must retain the prior finding condition state".into(),
            ));
        }
    }
    let event_revision = current.as_ref().map_or(Ok(1_i64), |(revision, _, _)| {
        revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Invariant("finding revision space is exhausted".to_owned()))
    })?;

    let watermark_by_instance: BTreeMap<&str, i64> = watermarks
        .iter()
        .map(|watermark| {
            (
                watermark.instance_id.as_str(),
                watermark.max_report_sequence,
            )
        })
        .collect();
    for evidence in &finding.evidence {
        validate_digest("report_semantic_digest", &evidence.report_semantic_digest)?;
        let (instance_id, report_sequence): (String, i64) = transaction
            .query_row(
                "SELECT instance_id, report_sequence FROM admitted_reports
                 WHERE report_id = ?1 AND semantic_digest = ?2",
                params![evidence.report_id, evidence.report_semantic_digest],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| {
                StoreError::Invariant(format!(
                    "finding evidence {} is not an admitted report: {error}",
                    evidence.report_id
                ))
            })?;
        let Some(max_sequence) = watermark_by_instance.get(instance_id.as_str()) else {
            return Err(StoreError::Invariant(format!(
                "finding evidence {} is outside the evaluation watermark",
                evidence.report_id
            )));
        };
        if report_sequence > *max_sequence {
            return Err(StoreError::Invariant(format!(
                "finding evidence {} is newer than the evaluation watermark",
                evidence.report_id
            )));
        }
        if let Some(observation_ordinal) = evidence.observation_ordinal {
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM observations WHERE report_id = ?1 AND ordinal = ?2
                 )",
                params![evidence.report_id, observation_ordinal],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(StoreError::Invariant(format!(
                    "finding evidence references missing observation {}:{}",
                    evidence.report_id, observation_ordinal
                )));
            }
        }
    }

    transaction.execute(
        "INSERT INTO finding_events (
            event_id, finding_id, event_revision, event_kind, evaluation_id,
            instance_id, detector_id, detector_version, detector_digest, evaluator_artifact_digest,
            evaluation_revision, profile_id, profile_version, profile_digest,
            subject_json, condition_name, condition_state, visibility_state, operator_work_state,
            severity, summary, limitations_json, safe_next_checks_json,
            freshness_json, basis_json, refusal_json, origin_mode,
            historical_refs_json, observed_at, received_at, evaluated_at, created_at
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
            ?31, ?32
         )",
        params![
            finding.event_id,
            finding.finding_id,
            event_revision,
            finding.event_kind,
            evaluation.evaluation_id,
            finding.instance_id,
            evaluation.detector_id,
            evaluation.detector_version,
            evaluation.detector_digest,
            evaluation.evaluator_artifact_digest,
            evaluation_revision,
            finding.profile_id,
            finding.profile_version,
            finding.profile_digest,
            finding.subject.as_bytes(),
            finding.condition_name,
            finding.condition_state,
            finding.visibility_state,
            finding.operator_work_state,
            finding.severity,
            finding.summary,
            finding.limitations.as_bytes(),
            finding.safe_next_checks.as_bytes(),
            finding.freshness.as_bytes(),
            finding.basis.as_bytes(),
            finding.refusal.as_ref().map(CanonicalDocument::as_bytes),
            finding.origin_mode,
            finding.historical_refs.as_bytes(),
            finding.observed_at,
            finding.received_at,
            evaluation.evaluated_at,
            finding.created_at,
        ],
    )?;
    for evidence in &finding.evidence {
        transaction.execute(
            "INSERT INTO finding_evidence (
                event_id, ordinal, report_id, report_semantic_digest,
                observation_ordinal, observed_at, received_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                finding.event_id,
                evidence.ordinal,
                evidence.report_id,
                evidence.report_semantic_digest,
                evidence.observation_ordinal,
                evidence.observed_at,
                evidence.received_at,
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO finding_current (finding_id, latest_event_id)
         VALUES (?1, ?2)
         ON CONFLICT(finding_id) DO UPDATE
         SET latest_event_id = excluded.latest_event_id",
        params![finding.finding_id, finding.event_id],
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    const TIME: &str = "2026-07-16T12:00:00.000Z";
    const ADMISSION_A: &str = "00000000-0000-4000-8000-000000000000";
    const BINDING_A: &str = "00000000-0000-4000-8000-000000000001";
    const OPERATION_A: &str = "00000000-0000-4000-8000-000000000002";
    const INTENT_A: &str = "00000000-0000-4000-8000-000000000003";
    const COMPLETE_A: &str = "00000000-0000-4000-8000-000000000004";
    const BINDING_B: &str = "00000000-0000-4000-8000-000000000005";
    const OPERATION_B: &str = "00000000-0000-4000-8000-000000000006";
    const INTENT_B: &str = "00000000-0000-4000-8000-000000000007";
    const OVERSIZED: &str = "00000000-0000-4000-8000-000000000008";

    fn document(value: Value) -> CanonicalDocument {
        CanonicalDocument::from_serializable(&value).expect("fixture JSON canonicalizes")
    }

    fn digest(label: &str) -> String {
        nq_protocol::sha256_bytes(label.as_bytes()).into_string()
    }

    fn write_empty_exact_v3(path: &Path) {
        let connection = Connection::open(path).expect("open exact schema-v3 fixture");
        connection
            .execute_batch(SCHEMA_V3)
            .expect("install exact schema-v3 definition");
        connection
            .execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version,
                    schema_artifact_digest, initialized_at
                 ) VALUES (1, 'nq-ng', 3, ?1, ?2)",
                params![SCHEMA_V3_ARTIFACT_DIGEST, TIME],
            )
            .expect("record exact schema-v3 identity");
    }

    fn write_empty_exact_v4(path: &Path) {
        let connection = Connection::open(path).expect("open exact schema-v4 fixture");
        connection
            .execute_batch(SCHEMA_V4)
            .expect("install exact schema-v4 definition");
        connection
            .execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version,
                    schema_artifact_digest, initialized_at
                 ) VALUES (1, 'nq-ng', 4, ?1, ?2)",
                params![SCHEMA_V4_ARTIFACT_DIGEST, TIME],
            )
            .expect("record exact schema-v4 identity");
    }

    fn write_empty_exact_v5(path: &Path) {
        let connection = Connection::open(path).expect("open exact schema-v5 fixture");
        connection
            .execute_batch(SCHEMA_V5)
            .expect("install exact schema-v5 definition");
        connection
            .execute(
                "INSERT INTO schema_metadata (
                    singleton, product, schema_version,
                    schema_artifact_digest, initialized_at
                 ) VALUES (1, 'nq-ng', 5, ?1, ?2)",
                params![SCHEMA_V5_ARTIFACT_DIGEST, TIME],
            )
            .expect("record exact schema-v5 identity");
    }

    fn exact_v3_to_v4_receipt(backup: &BackupArtifact) -> UpgradeReceiptInput {
        UpgradeReceiptInput {
            receipt_id: "upgrade-v3-v4-provider".to_owned(),
            from_schema_version: 3,
            to_schema_version: 4,
            migrations: document(json!(["schema_v3_to_v4_provider_intake"])),
            binary_digest: digest("migration-binary"),
            backup_digest: backup.sha256.clone(),
            backup_location: backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-22T12:00:00Z".to_owned(),
            finished_at: "2026-07-22T12:00:01Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: document(json!({"uid": 991})),
            verification: document(json!({
                "integrity": "ok",
                "source_schema_version": 3,
                "source_schema_artifact_digest": SCHEMA_V3_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_provider_intake": "explicit_gap_only",
                "provider_intakes_synthesized": false,
                "acknowledgments_synthesized": false,
            })),
        }
    }

    fn exact_v4_to_v5_receipt(backup: &BackupArtifact) -> UpgradeReceiptInput {
        UpgradeReceiptInput {
            receipt_id: "upgrade-v4-v5-diagnostic-artifacts".to_owned(),
            from_schema_version: 4,
            to_schema_version: 5,
            migrations: document(json!(["schema_v4_to_v5_diagnostic_artifacts"])),
            binary_digest: digest("migration-binary-v5"),
            backup_digest: backup.sha256.clone(),
            backup_location: backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-28T12:00:00Z".to_owned(),
            finished_at: "2026-07-28T12:00:01Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: document(json!({"uid": 991})),
            verification: document(json!({
                "integrity": "ok",
                "source_schema_version": 4,
                "source_schema_artifact_digest": SCHEMA_V4_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_diagnostic_artifacts": "no_durable_commitments",
                "diagnostic_artifacts_synthesized": false,
            })),
        }
    }

    fn exact_v5_to_v6_receipt(backup: &BackupArtifact) -> UpgradeReceiptInput {
        UpgradeReceiptInput {
            receipt_id: "upgrade-v5-v6-runtime-ledger".to_owned(),
            from_schema_version: 5,
            to_schema_version: 6,
            migrations: document(json!(["schema_v5_to_v6_runtime_ledger"])),
            binary_digest: digest("migration-binary-v6"),
            backup_digest: backup.sha256.clone(),
            backup_location: backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-28T12:00:00Z".to_owned(),
            finished_at: "2026-07-28T12:00:01Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: document(json!({"uid": 991})),
            verification: document(json!({
                "integrity": "ok",
                "source_schema_version": 5,
                "source_schema_artifact_digest": SCHEMA_V5_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_runtime_records": "no_durable_commitments",
                "runtime_records_synthesized": false,
                "diagnostic_execution_bindings_synthesized": false,
            })),
        }
    }

    fn exact_v6_to_v7_receipt(backup: &BackupArtifact) -> UpgradeReceiptInput {
        UpgradeReceiptInput {
            receipt_id: "upgrade-v6-v7-runtime-dependencies".to_owned(),
            from_schema_version: 6,
            to_schema_version: 7,
            migrations: document(json!(["schema_v6_to_v7_runtime_dependencies"])),
            binary_digest: digest("migration-binary-v7"),
            backup_digest: backup.sha256.clone(),
            backup_location: backup.path.to_string_lossy().into_owned(),
            started_at: "2026-07-01T12:00:00Z".to_owned(),
            finished_at: "2026-07-01T12:00:01Z".to_owned(),
            result: "migrated".to_owned(),
            operator_identity: document(json!({"uid": 991})),
            verification: document(json!({
                "integrity": "ok",
                "source_schema_version": 6,
                "source_schema_artifact_digest": SCHEMA_V6_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_dependency_binding": "legacy_unbound",
                "dependency_generations_synthesized": false,
                "trust_anchors_synthesized": false,
            })),
        }
    }

    fn runtime_record(label: &str, schema: &str, committed_at: &str) -> RuntimeRecordInput {
        RuntimeRecordInput {
            record_id: digest(&format!("runtime-record-{label}")),
            record_schema: schema.to_owned(),
            canonical_bytes: document(json!({
                "schema": schema,
                "fixture": label,
            })),
            committed_at: committed_at.to_owned(),
        }
    }

    fn runtime_dependency(label: &str) -> RuntimeCheckpointDependencyInput {
        let anchor = document(json!({
            "schema": "nq.test_dependency_anchor.v1",
            "label": label,
        }));
        let trust_anchor_id =
            Sha256Digest::parse(anchor.digest().to_owned()).expect("test anchor digest");
        let generation = document(json!({
            "schema": "nq.test_runtime_dependency_generation.v1",
            "label": label,
            "trust_anchor_id": trust_anchor_id,
        }));
        let dependency_generation_id =
            Sha256Digest::parse(generation.digest().to_owned()).expect("test generation digest");
        let canonical_custody = document(json!({
            "schema": RUNTIME_DEPENDENCY_GENERATION_CUSTODY_SCHEMA,
            "generation_id": dependency_generation_id,
            "generation_canonical_bytes": hex::encode(generation.as_bytes()),
            "identity_catalog_canonical_bytes": "",
            "external_dependency_canonical_bytes": "",
            "authority_admission_canonical_bytes": "",
            "trust_anchor_canonical_bytes": hex::encode(anchor.as_bytes()),
            "admission_receipt_set_canonical_bytes": "",
        }));
        RuntimeCheckpointDependencyInput {
            dependency_generation_id,
            trust_anchor_id,
            canonical_custody,
        }
    }

    fn initial_runtime_batch(records: Vec<RuntimeRecordInput>) -> RuntimeRecordBatchInput {
        RuntimeRecordBatchInput {
            checkpoint_id: digest("runtime-checkpoint-initial"),
            expected_predecessor_checkpoint_id: None,
            expected_predecessor_ledger_root: None,
            dependency: runtime_dependency("default"),
            records,
        }
    }

    fn establish_runtime_root(store: &mut Store, dependency: &RuntimeCheckpointDependencyInput) {
        store
            .establish_runtime_dependency_trust_root(&dependency.trust_anchor_id)
            .expect("runtime dependency bootstrap trust root");
    }

    #[derive(Clone, Copy)]
    enum GovernedDerivationSubstitution {
        Identity,
        DependencyGeneration,
        DependencyCustodyDigest,
        TrustAnchor,
        Evaluation,
        ProfileSemantic,
        EvaluatorIdentity,
        EvaluatorArtifact,
        DerivedAt,
        ClockIdentity,
        ClockQualification,
    }

    #[derive(Clone, Copy)]
    enum GovernedProjectionFixtureMode {
        Complete,
        InsufficientCommittedCapacity,
        LegacyV1Complete,
        FullTopologyNativeLaunch,
        DuplicateOuterRequestInReservation,
        DuplicateInvocationDecisionInReservation,
        DuplicateCustodyReservationInReservation,
        MissingSql,
        RawSubstitution,
        ProviderDocumentSubstitution,
        IncompleteRuntimeWriteSet,
        DiagnosticEvaluatorArtifactMasquerade,
        DiagnosticClockQualificationSubstitution,
        NativeDeadlineReferenceSubstitution,
        NativeDeadlineProvenanceSubstitution,
        NativeLaunchExtraneousRecord,
        DerivationSubstitution(GovernedDerivationSubstitution),
        ReservationCheckpointIdentitySubstitution,
        ReservationCheckpointDigestSubstitution,
        ReservationCheckpointMembershipSubstitution,
        LaunchCheckpointIdentitySubstitution,
        LaunchCheckpointDigestSubstitution,
        LaunchCheckpointMembershipSubstitution,
        LaunchClaimTimeSubstitution,
    }

    struct GovernedProjectionFixture {
        store: Store,
        directory: tempfile::TempDir,
        reservation: GovernedCustodyReservation,
        reservation_record_id: Sha256Digest,
        launch_checkpoint_id: Sha256Digest,
        diagnostic_artifact_id: Sha256Digest,
        exact_closure_bytes: Vec<u8>,
    }

    fn governed_runtime_record(
        record_id: Sha256Digest,
        record_schema: &str,
        value: Value,
    ) -> RuntimeRecordInput {
        RuntimeRecordInput {
            record_id: record_id.into_string(),
            record_schema: record_schema.to_owned(),
            canonical_bytes: document(value),
            committed_at: TIME.to_owned(),
        }
    }

    fn governed_record_reference(record: &RuntimeRecordInput) -> Value {
        json!({
            "schema": record.record_schema,
            "record_id": record.record_id,
            "bytes_digest": record.canonical_bytes.digest(),
        })
    }

    fn admitted_run_level_collection(
        store: &mut Store,
        suffix: &str,
        profile_digest: &str,
    ) -> CollectionInput {
        let run = bound_fixture_run(store, "fixture-a", suffix, profile_digest);
        fixture_collection(
            store,
            run,
            Some(SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes: format!("admitted-{suffix}\n").into_bytes(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    suffix,
                    profile_digest,
                    document(json!({"run_level": suffix})),
                )),
            }),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn admitted_run_level_artifact(
        store: &mut Store,
        collection: &CollectionInput,
        provider_intake: &ProviderIntakeInput,
        suffix: &str,
    ) -> DiagnosticArtifactCommitInput {
        let dependency = runtime_dependency(&format!("run-level-{suffix}"));
        establish_runtime_root(store, &dependency);
        let outer_request_id = format!("outer-request-{suffix}");
        let outer_request = governed_runtime_record(
            typed_digest(&format!("run-level-outer-request-{suffix}")),
            "nq.diagnostic_invocation_request.v1",
            json!({
                "schema": "nq.diagnostic_invocation_request.v1",
                "request_id": outer_request_id,
            }),
        );
        let invocation_decision = governed_runtime_record(
            typed_digest(&format!("run-level-decision-{suffix}")),
            "nq.invocation_decision.v1",
            json!({
                "schema": "nq.invocation_decision.v1",
                "decision": "accepted",
            }),
        );
        let reservation_batch = RuntimeRecordBatchInput {
            checkpoint_id: typed_digest(&format!("run-level-reservation-checkpoint-{suffix}"))
                .into_string(),
            expected_predecessor_checkpoint_id: None,
            expected_predecessor_ledger_root: None,
            dependency: dependency.clone(),
            records: vec![outer_request.clone(), invocation_decision.clone()],
        };
        let reservation_receipt = store
            .append_runtime_records(&reservation_batch)
            .expect("run-level reservation records");
        let execution_launch = governed_runtime_record(
            typed_digest(&format!("run-level-launch-{suffix}")),
            "nq.execution_launch.v1",
            json!({
                "schema": "nq.execution_launch.v1",
                "status": "launched",
                "outer_request": governed_record_reference(&outer_request),
                "invocation_decision": governed_record_reference(&invocation_decision),
            }),
        );
        let launch_batch = RuntimeRecordBatchInput {
            checkpoint_id: typed_digest(&format!("run-level-launch-checkpoint-{suffix}"))
                .into_string(),
            expected_predecessor_checkpoint_id: Some(
                reservation_receipt.checkpoint.checkpoint_id.clone(),
            ),
            expected_predecessor_ledger_root: Some(
                reservation_receipt
                    .checkpoint
                    .checkpoint_ledger_root
                    .clone(),
            ),
            dependency: dependency.clone(),
            records: vec![execution_launch.clone()],
        };
        let launch_receipt = store
            .append_runtime_records(&launch_batch)
            .expect("run-level launch record");
        let provider_record_id =
            provider_intake_record_id(provider_intake).expect("provider record identity");
        let provider_record = governed_runtime_record(
            provider_record_id,
            "nq.provider_intake.v1",
            json!({
                "schema": "nq.provider_intake.v1",
                "intake_id": provider_intake.intake_id,
                "request_id": provider_intake.request_id,
            }),
        );
        let artifact_id = typed_digest(&format!("run-level-artifact-{suffix}"));
        let diagnostic = document(json!({
            "schema": "nq.diagnostic_execution.v2",
            "artifact_id": artifact_id,
            "run_id": collection.run.run_id,
            "request_id": outer_request_id,
            "profile": {
                "id": collection.run.profile_id,
                "version": collection.run.profile_version,
                "digest": collection.run.profile_digest,
            },
            "completed_at": TIME,
            "disposition": "established",
        }));
        let binding_id = typed_digest(&format!("run-level-binding-{suffix}"));
        let binding_record = governed_runtime_record(
            binding_id.clone(),
            "nq.execution_identity_binding.v2",
            json!({
                "schema": "nq.execution_identity_binding.v2",
                "binding_id": binding_id,
                "outer_request": governed_record_reference(&outer_request),
                "invocation_decision": governed_record_reference(&invocation_decision),
                "execution_launch": governed_record_reference(&execution_launch),
                "diagnostic": {
                    "schema": "nq.diagnostic_execution.v2",
                    "request_id": outer_request_id,
                    "artifact_id": artifact_id,
                    "file_bytes_digest": diagnostic.digest(),
                },
                "provider_attempts": [governed_record_reference(&provider_record)],
            }),
        );
        DiagnosticArtifactCommitInput {
            artifact_id,
            contract_schema: "nq.diagnostic_execution.v2".into(),
            canonical_bytes: diagnostic,
            local_origin: DiagnosticArtifactLocalOriginInput {
                run_id: collection.run.run_id.clone(),
                evaluation_id: None,
                completed_at: TIME.into(),
                execution_binding: Some(DiagnosticArtifactExecutionBindingInput {
                    runtime_records: RuntimeRecordBatchInput {
                        checkpoint_id: typed_digest(&format!(
                            "run-level-final-checkpoint-{suffix}"
                        ))
                        .into_string(),
                        expected_predecessor_checkpoint_id: Some(
                            launch_receipt.checkpoint.checkpoint_id,
                        ),
                        expected_predecessor_ledger_root: Some(
                            launch_receipt.checkpoint.checkpoint_ledger_root,
                        ),
                        dependency,
                        records: vec![provider_record.clone(), binding_record.clone()],
                    },
                    execution_binding_record_id: binding_record.record_id,
                    outer_request_record_id: outer_request.record_id,
                    invocation_decision_record_id: invocation_decision.record_id,
                    execution_launch_record_id: execution_launch.record_id,
                    outer_request_id,
                    provider_attempts: vec![DiagnosticArtifactProviderAttemptBindingInput {
                        provider_attempt_record_id: provider_record.record_id,
                        intake_id: provider_intake.intake_id.clone(),
                    }],
                }),
            },
        }
    }

    fn admitted_run_level_completion(
        collection: &CollectionInput,
        artifact: DiagnosticArtifactCommitInput,
        receipt: &CollectionReceipt,
    ) -> AdmittedRunLevelDiagnosticCompletion<()> {
        let report = match &collection
            .submission
            .as_ref()
            .expect("admitted submission")
            .disposition
        {
            SubmissionDisposition::Admitted(report) => report,
            SubmissionDisposition::Rejected { .. } => panic!("admitted fixture"),
        };
        AdmittedRunLevelDiagnosticCompletion {
            value: (),
            diagnostic_artifact: artifact,
            status: StatusEventInput {
                status_event_id: format!("status-{}", collection.run.run_id),
                component_kind: "instance".into(),
                component_id: collection.run.instance_id.clone(),
                state: "healthy".into(),
                code: "report_complete".into(),
                detail: document(json!({
                    "schema": "nq.collection_outcome.v2",
                    "instance_id": collection.run.instance_id,
                    "run_id": collection.run.run_id,
                    "result": {
                        "outcome": "admitted",
                        "report_id": report.report_id,
                        "report_status": report.report_status,
                        "semantic_digest": receipt.semantic_digest,
                        "evaluations": [],
                    },
                })),
                observed_at: TIME.into(),
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    fn governed_projection_fixture(
        mode: GovernedProjectionFixtureMode,
    ) -> GovernedProjectionFixture {
        let legacy_v1 = matches!(mode, GovernedProjectionFixtureMode::LegacyV1Complete);
        let native_launch = matches!(
            mode,
            GovernedProjectionFixtureMode::FullTopologyNativeLaunch
                | GovernedProjectionFixtureMode::NativeDeadlineReferenceSubstitution
                | GovernedProjectionFixtureMode::NativeDeadlineProvenanceSubstitution
                | GovernedProjectionFixtureMode::NativeLaunchExtraneousRecord
        );
        let directory = tempdir().expect("governed fixture directory");
        let database = directory.path().join("nq.db");
        let mut store = Store::initialize(&database).expect("governed fixture store");
        let profile_digest = append_fixture_descriptor(&mut store);
        let collection =
            rejected_fixture_collection(&mut store, "fixture-a", "governed", &profile_digest);
        let final_capacity_bytes = if matches!(
            mode,
            GovernedProjectionFixtureMode::InsufficientCommittedCapacity
        ) {
            65_536
        } else {
            131_072
        };
        let reserved_bytes = 65_536_u64
            .checked_add(65_536)
            .and_then(|subtotal| subtotal.checked_add(final_capacity_bytes))
            .expect("fixture reservation capacity");

        let dependency = runtime_dependency("governed-projection");
        establish_runtime_root(&mut store, &dependency);
        let outer_request_id = "outer-request-governed";
        let outer_request = governed_runtime_record(
            typed_digest("governed-outer-request"),
            "nq.diagnostic_invocation_request.v1",
            json!({
                "schema": "nq.diagnostic_invocation_request.v1",
                "request_id": outer_request_id,
            }),
        );
        let invocation_decision = governed_runtime_record(
            typed_digest("governed-invocation-decision"),
            "nq.invocation_decision.v1",
            json!({
                "schema": "nq.invocation_decision.v1",
                "decision": "accepted",
            }),
        );
        let reservation_record = governed_runtime_record(
            typed_digest("governed-reservation"),
            "nq.custody_reservation.v1",
            json!({
                "schema": "nq.custody_reservation.v1",
                "reservation": "governed-projection",
                "component_bounds": {
                    "diagnostic_artifact_bytes": 65_536,
                    "raw_evidence_bytes": 65_536,
                    "dependency_closure_bytes": 65_536,
                },
                "reserved_bytes": reserved_bytes,
            }),
        );
        let role_manifest = governed_runtime_record(
            typed_digest("governed-role-manifest"),
            "nq.role_manifest.v1",
            json!({
                "schema": "nq.role_manifest.v1",
                "fixture": "full-topology-role",
            }),
        );
        let cohort_manifest = governed_runtime_record(
            typed_digest("governed-cohort-manifest"),
            "nq.static_profile_cohort_manifest.v1",
            json!({
                "schema": "nq.static_profile_cohort_manifest.v1",
                "fixture": "full-topology-cohort",
            }),
        );
        let node_enrollment = governed_runtime_record(
            typed_digest("governed-node-enrollment"),
            "nq.node_enrollment.v1",
            json!({
                "schema": "nq.node_enrollment.v1",
                "fixture": "full-topology-node",
            }),
        );
        let activation = governed_runtime_record(
            typed_digest("governed-runtime-activation"),
            "nq.runtime_activation.v1",
            json!({
                "schema": "nq.runtime_activation.v1",
                "fixture": "full-topology-activation",
            }),
        );
        let witness = governed_runtime_record(
            typed_digest("governed-witness-attachment"),
            "nq.witness_attachment.v1",
            json!({
                "schema": "nq.witness_attachment.v1",
                "fixture": "full-topology-witness",
            }),
        );
        let profile_qualification = governed_runtime_record(
            typed_digest("governed-native-profile-qualification"),
            "nq.native_profile_qualification.v1",
            json!({
                "schema": "nq.native_profile_qualification.v1",
                "fixture": "full-topology-profile-qualification",
            }),
        );
        let native_clock_qualification = governed_runtime_record(
            typed_digest("governed-native-clock-qualification"),
            "nq.native_clock_qualification.v1",
            json!({
                "schema": "nq.native_clock_qualification.v1",
                "fixture": "full-topology-clock-qualification",
            }),
        );
        let deadline = governed_runtime_record(
            typed_digest("governed-deadline-evaluation"),
            "nq.deadline_evaluation.v1",
            json!({
                "schema": "nq.deadline_evaluation.v1",
                "outer_request": governed_record_reference(&outer_request),
                "activation": governed_record_reference(&activation),
                "clock_qualification": governed_record_reference(&native_clock_qualification),
                "clock": {"fixture": "boottime-realtime-bridge"},
                "request_bounds": {
                    "maximum_execution_ms": 1_000,
                },
                "sample": {
                    "boot_epoch": typed_digest("governed-boot-epoch"),
                    "boottime_at_ns": "1000000000",
                },
                "derived": {
                    "launched_at": if matches!(
                        mode,
                        GovernedProjectionFixtureMode::NativeDeadlineProvenanceSubstitution
                    ) {
                        "2026-07-29T23:59:58Z"
                    } else {
                        TIME
                    },
                    "attempt_deadline": "2026-07-30T00:00:01Z",
                    "boottime_expiry_ns": "2000000000",
                },
                "decision": {
                    "state": "accepted",
                    "violations": [],
                },
            }),
        );
        let launch_deadline_reference = if matches!(
            mode,
            GovernedProjectionFixtureMode::NativeDeadlineReferenceSubstitution
        ) {
            json!({
                "schema": "nq.deadline_evaluation.v1",
                "record_id": typed_digest("substituted-deadline-reference"),
                "bytes_digest": deadline.canonical_bytes.digest(),
            })
        } else {
            governed_record_reference(&deadline)
        };
        let execution_launch = governed_runtime_record(
            typed_digest("governed-execution-launch"),
            "nq.execution_launch.v1",
            if native_launch {
                json!({
                    "schema": "nq.execution_launch.v1",
                    "status": "launched",
                    "launched_at": TIME,
                    "attempt_deadline": "2026-07-30T00:00:01Z",
                    "maximum_execution_ms": 1_000,
                    "clock": {"fixture": "boottime-realtime-bridge"},
                    "outer_request": governed_record_reference(&outer_request),
                    "invocation_decision": governed_record_reference(&invocation_decision),
                    "custody_reservation": governed_record_reference(&reservation_record),
                    "activation_snapshot": governed_record_reference(&activation),
                    "prelaunch_checks": {
                        "deadline": launch_deadline_reference,
                    },
                })
            } else {
                json!({
                    "schema": "nq.execution_launch.v1",
                    "status": "launched",
                    "launched_at": TIME,
                    "outer_request": governed_record_reference(&outer_request),
                    "invocation_decision": governed_record_reference(&invocation_decision),
                })
            },
        );
        let mut reservation_records = vec![
            outer_request.clone(),
            invocation_decision.clone(),
            reservation_record.clone(),
        ];
        if native_launch {
            reservation_records.extend([
                role_manifest,
                cohort_manifest,
                node_enrollment,
                activation,
                witness,
                profile_qualification,
                native_clock_qualification,
            ]);
        }
        match mode {
            GovernedProjectionFixtureMode::DuplicateOuterRequestInReservation => {
                reservation_records.push(governed_runtime_record(
                    typed_digest("duplicate-governed-outer-request"),
                    "nq.diagnostic_invocation_request.v1",
                    json!({
                        "schema": "nq.diagnostic_invocation_request.v1",
                        "request_id": "duplicate-outer-request",
                    }),
                ));
            }
            GovernedProjectionFixtureMode::DuplicateInvocationDecisionInReservation => {
                reservation_records.push(governed_runtime_record(
                    typed_digest("duplicate-governed-invocation-decision"),
                    "nq.invocation_decision.v1",
                    json!({
                        "schema": "nq.invocation_decision.v1",
                        "decision": "accepted",
                    }),
                ));
            }
            GovernedProjectionFixtureMode::DuplicateCustodyReservationInReservation => {
                reservation_records.push(governed_runtime_record(
                    typed_digest("duplicate-governed-custody-reservation"),
                    "nq.custody_reservation.v1",
                    json!({
                        "schema": "nq.custody_reservation.v1",
                        "reservation": "duplicate-governed-projection",
                    }),
                ));
            }
            _ => {}
        }
        let reservation_batch = RuntimeRecordBatchInput {
            checkpoint_id: typed_digest("governed-reservation-checkpoint").into_string(),
            expected_predecessor_checkpoint_id: None,
            expected_predecessor_ledger_root: None,
            dependency: dependency.clone(),
            records: reservation_records,
        };
        let reservation_batch_digest =
            runtime_record_batch_digest(&reservation_batch).expect("reservation batch digest");
        let dependency_custody_digest =
            Sha256Digest::parse(dependency.canonical_custody.digest().to_owned())
                .expect("dependency custody digest");
        let reservation = GovernedCustodyReservation {
            reservation_record_id: Sha256Digest::parse(reservation_record.record_id.clone())
                .expect("reservation identity"),
            reservation_manifest_digest: Sha256Digest::parse(
                reservation_record.canonical_bytes.digest().to_owned(),
            )
            .expect("reservation bytes digest"),
            outer_request_record_id: Sha256Digest::parse(outer_request.record_id.clone())
                .expect("request record identity"),
            outer_request_id: outer_request_id.to_owned(),
            outer_request_digest: Sha256Digest::parse(
                outer_request.canonical_bytes.digest().to_owned(),
            )
            .expect("request bytes digest"),
            dependency_generation_id: dependency.dependency_generation_id.clone(),
            dependency_generation_custody_digest: dependency_custody_digest.clone(),
            trust_anchor_id: dependency.trust_anchor_id.clone(),
            prelaunch_checkpoint_id: Sha256Digest::parse(reservation_batch.checkpoint_id.clone())
                .expect("reservation checkpoint identity"),
            prelaunch_checkpoint_digest: reservation_batch_digest.clone(),
            dependency_closure_capacity_bytes: 65_536,
            raw_capacity_bytes: 65_536,
            diagnostic_artifact_capacity_bytes: 65_536,
            final_capacity_bytes,
            protected_failure_capacity_bytes: 16_384,
        };
        let mut custody = store
            .reserve_governed_custody(reservation.clone(), dependency.canonical_custody.as_bytes())
            .expect("physical governed reservation");
        let reservation_receipt = store
            .append_runtime_records(&reservation_batch)
            .expect("reservation checkpoint");
        let launch_batch = RuntimeRecordBatchInput {
            checkpoint_id: typed_digest("governed-launch-checkpoint").into_string(),
            expected_predecessor_checkpoint_id: Some(
                reservation_receipt.checkpoint.checkpoint_id.clone(),
            ),
            expected_predecessor_ledger_root: Some(
                reservation_receipt
                    .checkpoint
                    .checkpoint_ledger_root
                    .clone(),
            ),
            dependency: dependency.clone(),
            records: if native_launch {
                let mut records = vec![deadline.clone(), execution_launch.clone()];
                if matches!(
                    mode,
                    GovernedProjectionFixtureMode::NativeLaunchExtraneousRecord
                ) {
                    records.push(governed_runtime_record(
                        typed_digest("extraneous-native-launch-record"),
                        "nq.host_role_lifecycle_event.v1",
                        json!({
                            "schema": "nq.host_role_lifecycle_event.v1",
                            "fixture": "must not share a native launch checkpoint",
                        }),
                    ));
                }
                records
            } else {
                vec![execution_launch.clone()]
            },
        };
        let launch_receipt = store
            .append_runtime_records(&launch_batch)
            .expect("launch checkpoint");
        custody
            .claim_launch(
                Sha256Digest::parse(execution_launch.record_id.clone())
                    .expect("launch record identity"),
                if matches!(
                    mode,
                    GovernedProjectionFixtureMode::LaunchClaimTimeSubstitution
                ) {
                    "2026-07-29T23:59:58Z".to_owned()
                } else {
                    TIME.to_owned()
                },
            )
            .expect("physical launch claim");

        let provider_record_id =
            provider_intake_record_id(&collection.intake).expect("provider record identity");
        let provider_record = governed_runtime_record(
            provider_record_id.clone(),
            "nq.provider_intake.v1",
            json!({
                "schema": "nq.provider_intake.v1",
                "intake_id": collection.intake.intake_id,
                "request_id": collection.intake.request_id,
            }),
        );
        let diagnostic_artifact_id = typed_digest("governed-diagnostic-artifact");
        let evaluator_identity_digest = typed_digest("governed-evaluator-identity");
        let clock_qualification = if legacy_v1 {
            json!({
                "state": "bounded",
                "maximum_error_ms": 1,
            })
        } else {
            json!({
                "state": "unqualified",
                "code": "fixture_clock_unqualified",
                "detail": "the fixture establishes no finite UTC-error bound",
            })
        };
        let clock_qualification_digest =
            nq_protocol::semantic_digest(&clock_qualification).expect("clock qualification");
        let diagnostic_clock_qualification = if matches!(
            mode,
            GovernedProjectionFixtureMode::DiagnosticClockQualificationSubstitution
        ) {
            json!({
                "state": "unqualified",
                "code": "substituted_clock_qualification",
                "detail": "hostile diagnostic-side substitution",
            })
        } else {
            clock_qualification.clone()
        };
        let diagnostic_evaluator_digest = if legacy_v1
            || matches!(
                mode,
                GovernedProjectionFixtureMode::DiagnosticEvaluatorArtifactMasquerade
            ) {
            collection.intake.evaluator_artifact_digest.clone()
        } else {
            evaluator_identity_digest.clone()
        };
        let diagnostic = document(json!({
            "schema": "nq.diagnostic_execution.v2",
            "artifact_id": diagnostic_artifact_id,
            "run_id": collection.run.run_id,
            "request_id": outer_request_id,
            "attempt_interval": {
                "qualification": diagnostic_clock_qualification,
            },
            "evaluator": {
                "digest": diagnostic_evaluator_digest,
            },
            "execution_clock": {
                "digest": typed_digest("governed-clock"),
            },
            "profile": {
                "id": collection.run.profile_id,
                "version": collection.run.profile_version,
                "digest": collection.run.profile_digest,
            },
            "profile_semantic_id": collection.intake.profile_semantic_id,
            "completed_at": TIME,
            "disposition": "refused",
        }));
        let binding_id = typed_digest("governed-execution-binding");
        let binding_record = governed_runtime_record(
            binding_id.clone(),
            "nq.execution_identity_binding.v2",
            json!({
                "schema": "nq.execution_identity_binding.v2",
                "binding_id": binding_id,
                "outer_request": governed_record_reference(&outer_request),
                "invocation_decision": governed_record_reference(&invocation_decision),
                "execution_launch": governed_record_reference(&execution_launch),
                "diagnostic": {
                    "schema": "nq.diagnostic_execution.v2",
                    "request_id": outer_request_id,
                    "artifact_id": diagnostic_artifact_id,
                    "file_bytes_digest": diagnostic.digest(),
                },
                "provider_attempts": [governed_record_reference(&provider_record)],
            }),
        );
        let final_batch = RuntimeRecordBatchInput {
            checkpoint_id: typed_digest("governed-final-checkpoint").into_string(),
            expected_predecessor_checkpoint_id: Some(
                launch_receipt.checkpoint.checkpoint_id.clone(),
            ),
            expected_predecessor_ledger_root: Some(
                launch_receipt.checkpoint.checkpoint_ledger_root.clone(),
            ),
            dependency: dependency.clone(),
            records: vec![provider_record.clone(), binding_record.clone()],
        };
        let artifact = DiagnosticArtifactCommitInput {
            artifact_id: diagnostic_artifact_id.clone(),
            contract_schema: "nq.diagnostic_execution.v2".to_owned(),
            canonical_bytes: diagnostic.clone(),
            local_origin: DiagnosticArtifactLocalOriginInput {
                run_id: collection.run.run_id.clone(),
                evaluation_id: None,
                completed_at: TIME.to_owned(),
                execution_binding: Some(DiagnosticArtifactExecutionBindingInput {
                    runtime_records: final_batch.clone(),
                    execution_binding_record_id: binding_record.record_id.clone(),
                    outer_request_record_id: outer_request.record_id.clone(),
                    invocation_decision_record_id: invocation_decision.record_id.clone(),
                    execution_launch_record_id: execution_launch.record_id.clone(),
                    outer_request_id: outer_request_id.to_owned(),
                    provider_attempts: vec![DiagnosticArtifactProviderAttemptBindingInput {
                        provider_attempt_record_id: provider_record.record_id.clone(),
                        intake_id: collection.intake.intake_id.clone(),
                    }],
                }),
            },
        };

        let raw_provider_bytes = if matches!(mode, GovernedProjectionFixtureMode::RawSubstitution) {
            b"substituted physical raw bytes".to_vec()
        } else {
            collection.intake.raw_bytes.clone()
        };
        let exact_provider_intake_bytes = if matches!(
            mode,
            GovernedProjectionFixtureMode::ProviderDocumentSubstitution
        ) {
            nq_protocol::canonical_json_bytes(&json!({
                "schema": "nq.provider_intake.v1",
                "intake_id": "substituted-provider-document",
                "request_id": collection.intake.request_id,
            }))
            .expect("substituted provider document")
        } else {
            provider_record.canonical_bytes.as_bytes().to_vec()
        };
        custody
            .seal_acquisition(GovernedAcquisitionCustodyInput {
                execution_launch_record_id: Sha256Digest::parse(execution_launch.record_id.clone())
                    .expect("launch identity"),
                provider_intake_record_id: provider_record_id,
                exact_provider_intake_bytes,
                exact_raw_provider_bytes: raw_provider_bytes,
            })
            .expect("physical acquisition seal");
        let derivation_claim = GovernedDerivationCustodyClaim {
            derivation_id: typed_digest("governed-derivation"),
            dependency_generation_id: dependency.dependency_generation_id.clone(),
            dependency_generation_custody_digest: dependency_custody_digest.clone(),
            trust_anchor_id: dependency.trust_anchor_id.clone(),
            evaluation_id: None,
            profile_semantic_id: collection.intake.profile_semantic_id.clone(),
            evaluator_identity_digest: evaluator_identity_digest.clone(),
            evaluator_artifact_digest: collection.intake.evaluator_artifact_digest.clone(),
            derived_at: TIME.to_owned(),
            clock_identity: typed_digest("governed-clock"),
            clock_qualification_digest,
        };
        if legacy_v1 {
            custody
                .claim_legacy_derivation_v1_for_reopen_test(crate::custody_arena::DerivationClaim {
                    derivation_id: derivation_claim.derivation_id.clone(),
                    dependency_generation_id: derivation_claim.dependency_generation_id.clone(),
                    dependency_generation_custody_digest: derivation_claim
                        .dependency_generation_custody_digest
                        .clone(),
                    trust_anchor_id: derivation_claim.trust_anchor_id.clone(),
                    evaluation_id: derivation_claim.evaluation_id.clone(),
                    profile_semantic_id: derivation_claim.profile_semantic_id.clone(),
                    evaluator_semantic_digest: None,
                    evaluator_artifact_digest: derivation_claim.evaluator_artifact_digest.clone(),
                    derived_at: derivation_claim.derived_at.clone(),
                    clock_identity: derivation_claim.clock_identity.clone(),
                    clock_uncertainty_ms: Some(1),
                    clock_qualification_digest: None,
                })
                .expect("legacy V1 physical derivation claim");
        } else {
            custody
                .claim_derivation(derivation_claim.clone())
                .expect("physical derivation claim");
        }

        let runtime_records = if matches!(
            mode,
            GovernedProjectionFixtureMode::IncompleteRuntimeWriteSet
        ) {
            vec![governed_record_reference(&provider_record)]
        } else {
            vec![
                governed_record_reference(&provider_record),
                governed_record_reference(&binding_record),
            ]
        };
        let reservation_checkpoint_id = if matches!(
            mode,
            GovernedProjectionFixtureMode::ReservationCheckpointIdentitySubstitution
        ) {
            typed_digest("substituted-reservation-checkpoint")
        } else {
            Sha256Digest::parse(reservation_receipt.checkpoint.checkpoint_id.clone())
                .expect("reservation checkpoint identity")
        };
        let reservation_checkpoint_digest = if matches!(
            mode,
            GovernedProjectionFixtureMode::ReservationCheckpointDigestSubstitution
        ) {
            typed_digest("substituted-reservation-checkpoint-digest")
        } else {
            reservation_receipt.checkpoint.batch_digest.clone()
        };
        let reservation_checkpoint_records = if matches!(
            mode,
            GovernedProjectionFixtureMode::ReservationCheckpointMembershipSubstitution
        ) {
            vec![
                governed_record_reference(&outer_request),
                governed_record_reference(&reservation_record),
            ]
        } else {
            reservation_batch
                .records
                .iter()
                .map(governed_record_reference)
                .collect()
        };
        let launch_checkpoint_id = if matches!(
            mode,
            GovernedProjectionFixtureMode::LaunchCheckpointIdentitySubstitution
        ) {
            typed_digest("substituted-launch-checkpoint")
        } else {
            Sha256Digest::parse(launch_receipt.checkpoint.checkpoint_id.clone())
                .expect("launch checkpoint identity")
        };
        let launch_checkpoint_digest = if matches!(
            mode,
            GovernedProjectionFixtureMode::LaunchCheckpointDigestSubstitution
        ) {
            typed_digest("substituted-launch-checkpoint-digest")
        } else {
            launch_receipt.checkpoint.batch_digest.clone()
        };
        let launch_checkpoint_records = if matches!(
            mode,
            GovernedProjectionFixtureMode::LaunchCheckpointMembershipSubstitution
        ) {
            vec![governed_record_reference(&reservation_record)]
        } else {
            launch_batch
                .records
                .iter()
                .map(governed_record_reference)
                .collect()
        };
        let derivation_substitution = match mode {
            GovernedProjectionFixtureMode::DerivationSubstitution(field) => Some(field),
            _ => None,
        };
        let closure_derivation_id = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::Identity)
        ) {
            typed_digest("substituted-derivation")
        } else {
            derivation_claim.derivation_id.clone()
        };
        let closure_dependency_generation_id = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::DependencyGeneration)
        ) {
            typed_digest("substituted-dependency-generation")
        } else {
            derivation_claim.dependency_generation_id.clone()
        };
        let closure_dependency_custody_digest = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::DependencyCustodyDigest)
        ) {
            typed_digest("substituted-dependency-custody")
        } else {
            derivation_claim
                .dependency_generation_custody_digest
                .clone()
        };
        let closure_trust_anchor = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::TrustAnchor)
        ) {
            typed_digest("substituted-trust-anchor")
        } else {
            derivation_claim.trust_anchor_id.clone()
        };
        let closure_evaluation_id = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::Evaluation)
        ) {
            Some("substituted-evaluation".to_owned())
        } else {
            derivation_claim.evaluation_id.clone()
        };
        let closure_profile_semantic_id = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::ProfileSemantic)
        ) {
            typed_digest("substituted-profile-semantic")
        } else {
            derivation_claim.profile_semantic_id.clone()
        };
        let closure_evaluator_identity_digest = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::EvaluatorIdentity)
        ) {
            typed_digest("substituted-evaluator-identity")
        } else {
            derivation_claim.evaluator_identity_digest.clone()
        };
        let closure_evaluator_artifact_digest = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::EvaluatorArtifact)
        ) {
            typed_digest("substituted-evaluator-artifact")
        } else {
            derivation_claim.evaluator_artifact_digest.clone()
        };
        let closure_derived_at = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::DerivedAt)
        ) {
            "2026-07-29T23:59:59Z".to_owned()
        } else {
            derivation_claim.derived_at.clone()
        };
        let closure_clock_identity = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::ClockIdentity)
        ) {
            typed_digest("substituted-clock")
        } else {
            derivation_claim.clock_identity.clone()
        };
        let closure_clock_qualification_digest = if matches!(
            derivation_substitution,
            Some(GovernedDerivationSubstitution::ClockQualification)
        ) {
            typed_digest("substituted-clock-qualification")
        } else {
            derivation_claim.clock_qualification_digest.clone()
        };
        let final_batch_digest =
            runtime_record_batch_digest(&final_batch).expect("final checkpoint digest");
        let mut closure = json!({
            "schema": if legacy_v1 {
                GOVERNED_CUSTODY_CLOSURE_SCHEMA
            } else {
                GOVERNED_CUSTODY_CLOSURE_V2_SCHEMA
            },
            "reservation": governed_record_reference(&reservation_record),
            "prelaunch": {
                "outer_request": governed_record_reference(&outer_request),
                "invocation_decision": governed_record_reference(&invocation_decision),
                "reservation_checkpoint": {
                    "checkpoint_id": reservation_checkpoint_id,
                    "batch_digest": reservation_checkpoint_digest,
                    "runtime_records": reservation_checkpoint_records,
                },
                "launch_checkpoint": {
                    "checkpoint_id": launch_checkpoint_id,
                    "batch_digest": launch_checkpoint_digest,
                    "runtime_records": launch_checkpoint_records,
                },
            },
            "acquisition": {
                "execution_launch_record_id": execution_launch.record_id,
                "provider_intake": governed_record_reference(&provider_record),
                "intake_id": collection.intake.intake_id,
                "raw_provider_bytes_digest":
                    nq_protocol::sha256_bytes(&collection.intake.raw_bytes),
            },
            "derivation": {
                "derivation_id": closure_derivation_id,
                "dependency_generation_id": closure_dependency_generation_id,
                "dependency_generation_custody_digest":
                    closure_dependency_custody_digest,
                "trust_anchor_id": closure_trust_anchor,
                "evaluation_id": closure_evaluation_id,
                "profile_semantic_id": closure_profile_semantic_id,
                "evaluator_semantic_digest": closure_evaluator_identity_digest,
                "evaluator_artifact_digest": closure_evaluator_artifact_digest,
                "derived_at": closure_derived_at,
                "clock_identity": closure_clock_identity,
                "clock_qualification_digest": closure_clock_qualification_digest,
            },
            "diagnostic": serde_json::from_slice::<Value>(diagnostic.as_bytes())
                .expect("diagnostic value"),
            "local_origin": {
                "run_id": collection.run.run_id,
                "evaluation_id": null,
                "completed_at": TIME,
            },
            "execution_binding": governed_record_reference(&binding_record),
            "runtime_records": runtime_records,
            "dependency_generation": {
                "checkpoint_id": final_batch.checkpoint_id,
                "checkpoint_digest": final_batch_digest,
                "generation_id": dependency.dependency_generation_id,
                "trust_anchor_id": dependency.trust_anchor_id,
                "custody_bytes_digest": dependency_custody_digest,
            },
        });
        if legacy_v1 {
            let derivation = closure
                .get_mut("derivation")
                .and_then(Value::as_object_mut)
                .expect("closure derivation object");
            derivation.remove("evaluator_semantic_digest");
            derivation.remove("clock_qualification_digest");
            derivation.insert("clock_uncertainty_ms".to_owned(), json!(1));
        }
        let closure_id = nq_protocol::semantic_digest(&closure).expect("governed closure identity");
        closure
            .as_object_mut()
            .expect("closure object")
            .insert("closure_id".to_owned(), json!(closure_id));
        let exact_closure_bytes =
            nq_protocol::canonical_json_bytes(&closure).expect("governed closure bytes");
        custody
            .seal_final_closure(exact_closure_bytes.clone())
            .expect("physical final closure");
        drop(custody);

        if !matches!(mode, GovernedProjectionFixtureMode::MissingSql) {
            store
                .commit_non_success_collection_with_artifact(
                    &collection,
                    &non_success_status(
                        &collection.run.run_id,
                        &collection.run.instance_id,
                        "governed",
                    ),
                    Some(&artifact),
                )
                .expect("governed SQL projection");
        }

        GovernedProjectionFixture {
            store,
            directory,
            reservation_record_id: reservation.reservation_record_id.clone(),
            launch_checkpoint_id: Sha256Digest::parse(
                launch_receipt.checkpoint.checkpoint_id.clone(),
            )
            .expect("launch checkpoint identity"),
            reservation,
            diagnostic_artifact_id,
            exact_closure_bytes,
        }
    }

    fn assert_governed_projection_pending(store: &Store, reservation_record_id: &Sha256Digest) {
        let inventory = store
            .governed_custody_inventory()
            .expect("governed custody inventory");
        let frontier = inventory
            .iter()
            .find_map(|entry| match entry {
                GovernedCustodyInventoryEntry::Verified(frontier)
                    if &frontier.reservation_record_id == reservation_record_id =>
                {
                    Some(frontier)
                }
                _ => None,
            })
            .expect("governed frontier");
        assert_eq!(
            frontier.recovery_class,
            GovernedCustodyRecoveryClass::FinalClosureAwaitingProjection
        );
    }

    #[test]
    fn admitted_run_level_diagnostic_commits_reopens_and_replays_exactly() {
        let directory = tempdir().expect("run-level directory");
        let database = directory.path().join("nq.db");
        let mut store = Store::initialize(&database).expect("run-level store");
        let profile_digest = append_fixture_descriptor(&mut store);
        let collection =
            admitted_run_level_collection(&mut store, "run-level-positive", &profile_digest);
        let artifact = admitted_run_level_artifact(
            &mut store,
            &collection,
            &collection.intake,
            "run-level-positive",
        );
        let committed = store
            .commit_admitted_run_level_diagnostic(&collection, |_view, receipt| {
                Ok::<_, StoreError>(admitted_run_level_completion(
                    &collection,
                    artifact.clone(),
                    receipt,
                ))
            })
            .expect("run-level diagnostic commits");
        assert!(matches!(committed, ProviderIntakeCommit::Committed { .. }));
        let admitted = store
            .admitted_collection_for_run(&collection.run.run_id)
            .expect("admitted run query")
            .expect("admitted run");
        assert_eq!(admitted.evaluations, 0);
        let DiagnosticArtifactLookup::Found(access) = store
            .diagnostic_artifact(&artifact.artifact_id, &["nq.diagnostic_execution.v2"])
            .expect("run-level artifact")
        else {
            panic!("run-level artifact missing");
        };
        assert!(matches!(
            access.commitment.origin,
            DiagnosticArtifactOrigin::Local {
                evaluation_id: None,
                execution_binding_record_id: Some(_),
                ..
            }
        ));
        assert!(
            store
                .diagnostic_artifact_execution_binding(&artifact.artifact_id)
                .expect("exact production binding")
                .is_some()
        );
        store.validate().expect("run-level store validates");
        drop(store);

        let mut reopened = Store::open(&database).expect("run-level store reopens");
        reopened
            .validate()
            .expect("reopened run-level store validates");
        let replay = reopened
            .commit_admitted_run_level_diagnostic(&collection, |_view, receipt| {
                Ok::<_, StoreError>(admitted_run_level_completion(
                    &collection,
                    artifact,
                    receipt,
                ))
            })
            .expect("exact run-level replay");
        assert!(matches!(replay, ProviderIntakeCommit::Replayed { .. }));
    }

    #[test]
    fn admitted_run_level_path_preserves_detector_law_and_rolls_back_hostiles() {
        for mutation in ["legacy_api", "missing_binding", "evaluation_origin"] {
            let (mut store, profile_digest) = configured_store();
            let suffix = format!("run-level-{mutation}");
            let collection = admitted_run_level_collection(&mut store, &suffix, &profile_digest);
            let mut artifact =
                admitted_run_level_artifact(&mut store, &collection, &collection.intake, &suffix);
            if mutation == "missing_binding" {
                artifact.local_origin.execution_binding = None;
            } else if mutation == "evaluation_origin" {
                artifact.local_origin.evaluation_id = Some("fabricated-evaluation".into());
            }
            let artifact_id = artifact.artifact_id.clone();
            let result = if mutation == "legacy_api" {
                store.commit_admitted_collection(&collection, |_view, receipt| {
                    let completion =
                        admitted_run_level_completion(&collection, artifact.clone(), receipt);
                    Ok::<_, StoreError>(AdmittedCollectionCompletion {
                        value: (),
                        evaluations: Vec::new(),
                        diagnostic_artifact: Some(completion.diagnostic_artifact),
                        status: completion.status,
                    })
                })
            } else {
                store.commit_admitted_run_level_diagnostic(&collection, |_view, receipt| {
                    Ok::<_, StoreError>(admitted_run_level_completion(
                        &collection,
                        artifact.clone(),
                        receipt,
                    ))
                })
            };
            let expected_refusal = match (&result, mutation) {
                (Err(StoreError::Invariant(message)), "legacy_api") => {
                    message.contains("admitted detector diagnostic")
                }
                (Err(StoreError::Invariant(message)), "missing_binding") => {
                    message.contains("run-level diagnostic requires")
                }
                (Err(StoreError::Invariant(message)), "evaluation_origin") => {
                    message.contains("provenance")
                        || message.contains("run-level diagnostic requires")
                }
                _ => false,
            };
            assert!(expected_refusal, "unexpected hostile result: {result:?}");
            assert!(
                store
                    .admitted_collection_for_run(&collection.run.run_id)
                    .expect("rolled-back run query")
                    .is_none()
            );
            assert!(matches!(
                store
                    .diagnostic_artifact(&artifact_id, &["nq.diagnostic_execution.v2"])
                    .expect("rolled-back artifact query"),
                DiagnosticArtifactLookup::NotFound
            ));
            store.validate().expect("hostile rollback validates");
        }
    }

    #[test]
    fn admitted_run_level_path_rejects_swapped_intake_and_incomplete_replay() {
        let (mut store, profile_digest) = configured_store();
        let prior = admitted_run_level_collection(&mut store, "run-level-prior", &profile_digest);
        commit_admitted_fixture(&mut store, prior.clone()).expect("prior admitted run");

        let replay = store.commit_admitted_run_level_diagnostic(
            &prior,
            |_view, _receipt| -> Result<AdmittedRunLevelDiagnosticCompletion<()>, StoreError> {
                panic!("replay must not invoke completion builder")
            },
        );
        assert!(
            matches!(
                replay,
                Err(StoreError::ReplayConflict(ref message))
                if message.contains("not one exact run-level V2 diagnostic")
            ),
            "unexpected incomplete replay result: {replay:?}"
        );

        let current =
            admitted_run_level_collection(&mut store, "run-level-current", &profile_digest);
        let swapped =
            admitted_run_level_artifact(&mut store, &current, &prior.intake, "run-level-current");
        assert!(matches!(
            store.commit_admitted_run_level_diagnostic(&current, |_view, receipt| {
                Ok::<_, StoreError>(admitted_run_level_completion(
                    &current,
                    swapped.clone(),
                    receipt,
                ))
            }),
            Err(StoreError::Invariant(message)) if message.contains("current provider attempt")
        ));
        assert!(
            store
                .admitted_collection_for_run(&current.run.run_id)
                .expect("swapped run query")
                .is_none()
        );
        assert!(matches!(
            store
                .diagnostic_artifact(&swapped.artifact_id, &["nq.diagnostic_execution.v2"])
                .expect("swapped artifact query"),
            DiagnosticArtifactLookup::NotFound
        ));

        store.validate().expect("replay refusal leaves store valid");
    }

    #[test]
    fn governed_projection_verification_is_reservation_only_and_idempotent() {
        let fixture = governed_projection_fixture(GovernedProjectionFixtureMode::Complete);
        let first = fixture
            .store
            .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
            .expect("first exact projection verification");
        assert_eq!(
            first.disposition,
            GovernedProjectionVerificationDisposition::Indexed
        );
        assert_eq!(first.diagnostic_artifact_id, fixture.diagnostic_artifact_id);
        let second = fixture
            .store
            .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
            .expect("idempotent exact projection re-verification");
        assert_eq!(
            second.disposition,
            GovernedProjectionVerificationDisposition::AlreadyIndexed
        );
        assert_eq!(second.closure_id, first.closure_id);
        assert_eq!(second.runtime_checkpoint_id, first.runtime_checkpoint_id);
    }

    #[test]
    fn governed_v2_committed_capacity_is_verified_before_effect() {
        let sufficient = governed_projection_fixture(GovernedProjectionFixtureMode::Complete);
        let capacity = sufficient
            .store
            .verify_governed_execution_custody_closure_v2_capacity(
                &sufficient.reservation,
                &sufficient.launch_checkpoint_id,
            )
            .expect("exact committed capacity is sufficient");
        assert_eq!(
            capacity.diagnostic_artifact_capacity_bytes,
            sufficient.reservation.diagnostic_artifact_capacity_bytes
        );
        assert!(
            capacity.final_closure_capacity_bytes <= sufficient.reservation.final_capacity_bytes
        );

        let insufficient = governed_projection_fixture(
            GovernedProjectionFixtureMode::InsufficientCommittedCapacity,
        );
        let refusal = insufficient
            .store
            .verify_governed_execution_custody_closure_v2_capacity(
                &insufficient.reservation,
                &insufficient.launch_checkpoint_id,
            );
        assert!(
            matches!(
                refusal,
                Err(StoreError::Invariant(ref message) | StoreError::Integrity(ref message))
                    if message.contains("final closure requires")
                        && message.contains("exact reservation provides")
            ),
            "unexpected insufficient-capacity result: {refusal:?}"
        );
    }

    #[test]
    fn governed_projection_reopens_committed_v1_closure_byte_identically() {
        let fixture = governed_projection_fixture(GovernedProjectionFixtureMode::LegacyV1Complete);
        let database = fixture
            .store
            .path()
            .expect("filesystem-backed fixture")
            .to_path_buf();
        let reservation = fixture.reservation.clone();
        let reservation_record_id = fixture.reservation_record_id.clone();
        let exact_closure_bytes = fixture.exact_closure_bytes.clone();
        let directory = fixture.directory;
        drop(fixture.store);

        let reopened_store = Store::open(&database).expect("reopen committed V1 store");
        let reopened_custody = reopened_store
            .open_governed_custody(reservation)
            .expect("reopen committed V1 arena");
        assert_eq!(
            reopened_custody
                .final_closure_bytes()
                .expect("reopen exact closure"),
            Some(exact_closure_bytes),
            "V1 bytes must not be upgraded or re-encoded during reopen"
        );
        drop(reopened_custody);
        reopened_store
            .verify_governed_projection_and_mark_indexed(&reservation_record_id)
            .expect("legacy V1 projection remains verifiable");
        drop(directory);
    }

    #[test]
    fn governed_projection_accepts_full_topology_and_native_deadline_launch_pair() {
        let fixture =
            governed_projection_fixture(GovernedProjectionFixtureMode::FullTopologyNativeLaunch);
        let closure: Value =
            serde_json::from_slice(&fixture.exact_closure_bytes).expect("V2 closure JSON");
        assert_ne!(
            closure["derivation"]["evaluator_semantic_digest"],
            closure["derivation"]["evaluator_artifact_digest"],
            "semantic evaluator identity must remain distinct from executable identity"
        );
        assert!(
            closure["derivation"].get("clock_uncertainty_ms").is_none(),
            "V2 must not encode an unqualified clock as a numeric sentinel"
        );
        assert_eq!(
            closure["derivation"]["clock_qualification_digest"],
            Value::String(
                nq_protocol::semantic_digest(
                    &closure["diagnostic"]["attempt_interval"]["qualification"]
                )
                .expect("exact clock qualification digest")
                .to_string()
            )
        );
        fixture
            .store
            .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
            .expect("full exact topology and native deadline provenance");
    }

    #[test]
    fn governed_projection_refuses_semantic_executable_and_clock_substitution() {
        for mode in [
            GovernedProjectionFixtureMode::DiagnosticEvaluatorArtifactMasquerade,
            GovernedProjectionFixtureMode::DiagnosticClockQualificationSubstitution,
        ] {
            let fixture = governed_projection_fixture(mode);
            let error = fixture
                .store
                .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
                .expect_err("diagnostic-side identity substitution must refuse");
            assert!(
                matches!(error, StoreError::Integrity(ref message)
                    if message.contains("governed projection")),
                "{error}"
            );
            assert_governed_projection_pending(&fixture.store, &fixture.reservation_record_id);
        }
    }

    #[test]
    fn governed_projection_refuses_native_deadline_reference_or_provenance_substitution() {
        for mode in [
            GovernedProjectionFixtureMode::NativeDeadlineReferenceSubstitution,
            GovernedProjectionFixtureMode::NativeDeadlineProvenanceSubstitution,
            GovernedProjectionFixtureMode::NativeLaunchExtraneousRecord,
        ] {
            let fixture = governed_projection_fixture(mode);
            let error = fixture
                .store
                .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
                .expect_err("native deadline substitution must refuse");
            assert!(
                matches!(error, StoreError::Integrity(ref message)
                    if message.contains("deadline")),
                "{error}"
            );
            assert_governed_projection_pending(&fixture.store, &fixture.reservation_record_id);
        }
    }

    #[test]
    fn governed_projection_refuses_duplicate_essential_reservation_records() {
        for mode in [
            GovernedProjectionFixtureMode::DuplicateOuterRequestInReservation,
            GovernedProjectionFixtureMode::DuplicateInvocationDecisionInReservation,
            GovernedProjectionFixtureMode::DuplicateCustodyReservationInReservation,
        ] {
            let fixture = governed_projection_fixture(mode);
            let error = fixture
                .store
                .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
                .expect_err("an essential reservation record must be unique");
            assert!(
                matches!(error, StoreError::Integrity(ref message)
                    if message.contains("reservation checkpoint membership")),
                "{error}"
            );
            assert_governed_projection_pending(&fixture.store, &fixture.reservation_record_id);
        }
    }

    #[test]
    fn governed_projection_verification_refuses_missing_or_mismatching_sql() {
        for mode in [
            GovernedProjectionFixtureMode::MissingSql,
            GovernedProjectionFixtureMode::RawSubstitution,
            GovernedProjectionFixtureMode::ProviderDocumentSubstitution,
            GovernedProjectionFixtureMode::IncompleteRuntimeWriteSet,
        ] {
            let fixture = governed_projection_fixture(mode);
            let error = fixture
                .store
                .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
                .expect_err("mismatching projection must refuse");
            assert!(
                matches!(error, StoreError::Integrity(ref message)
                    if message.contains("governed projection")),
                "{error}"
            );
            assert_governed_projection_pending(&fixture.store, &fixture.reservation_record_id);
        }
    }

    #[test]
    fn governed_projection_verification_binds_derivation_and_two_phase_prelaunch() {
        for mode in [
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::Identity,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::DependencyGeneration,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::DependencyCustodyDigest,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::TrustAnchor,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::Evaluation,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::ProfileSemantic,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::EvaluatorIdentity,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::EvaluatorArtifact,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::DerivedAt,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::ClockIdentity,
            ),
            GovernedProjectionFixtureMode::DerivationSubstitution(
                GovernedDerivationSubstitution::ClockQualification,
            ),
            GovernedProjectionFixtureMode::ReservationCheckpointIdentitySubstitution,
            GovernedProjectionFixtureMode::ReservationCheckpointDigestSubstitution,
            GovernedProjectionFixtureMode::ReservationCheckpointMembershipSubstitution,
            GovernedProjectionFixtureMode::LaunchCheckpointIdentitySubstitution,
            GovernedProjectionFixtureMode::LaunchCheckpointDigestSubstitution,
            GovernedProjectionFixtureMode::LaunchCheckpointMembershipSubstitution,
            GovernedProjectionFixtureMode::LaunchClaimTimeSubstitution,
        ] {
            let fixture = governed_projection_fixture(mode);
            let error = fixture
                .store
                .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
                .expect_err("substituted derivation or prelaunch binding must refuse");
            assert!(
                matches!(error, StoreError::Integrity(ref message)
                    if message.contains("governed projection")),
                "{error}"
            );
            assert_governed_projection_pending(&fixture.store, &fixture.reservation_record_id);
        }
    }

    #[test]
    fn governed_projection_reverification_detects_sql_corruption_after_indexing() {
        let fixture = governed_projection_fixture(GovernedProjectionFixtureMode::Complete);
        fixture
            .store
            .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
            .expect("initial exact projection verification");
        fixture
            .store
            .connection
            .execute_batch("DROP TRIGGER immutable_diagnostic_artifact_payloads_update;")
            .expect("test-only payload trigger removal");
        fixture
            .store
            .connection
            .execute(
                "UPDATE diagnostic_artifact_payloads
                 SET canonical_bytes = X'7b7d'
                 WHERE artifact_id = ?1",
                [fixture.diagnostic_artifact_id.as_str()],
            )
            .expect("test-only artifact corruption");
        let error = fixture
            .store
            .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
            .expect_err("already-indexed state must not bypass exact re-verification");
        assert!(
            matches!(error, StoreError::Integrity(ref message)
                if message.contains("diagnostic artifact")),
            "{error}"
        );
        let inventory = fixture
            .store
            .governed_custody_inventory()
            .expect("post-corruption physical inventory");
        let frontier = inventory
            .iter()
            .find_map(|entry| match entry {
                GovernedCustodyInventoryEntry::Verified(frontier)
                    if frontier.reservation_record_id == fixture.reservation_record_id =>
                {
                    Some(frontier)
                }
                _ => None,
            })
            .expect("indexed physical frontier remains visible");
        assert_eq!(
            frontier.recovery_class,
            GovernedCustodyRecoveryClass::Indexed,
            "the physical state bit is not a current SQL-integrity oracle"
        );
    }

    fn next_runtime_batch(
        label: &str,
        predecessor: &RuntimeLedgerCheckpoint,
        dependency: RuntimeCheckpointDependencyInput,
    ) -> RuntimeRecordBatchInput {
        RuntimeRecordBatchInput {
            checkpoint_id: digest(&format!("runtime-checkpoint-{label}")),
            expected_predecessor_checkpoint_id: Some(predecessor.checkpoint_id.clone()),
            expected_predecessor_ledger_root: Some(predecessor.checkpoint_ledger_root.clone()),
            dependency,
            records: vec![runtime_record(
                label,
                "nq.provider_intake.v1",
                "2026-07-29T12:00:10Z",
            )],
        }
    }

    fn insert_exact_v6_runtime_checkpoint(connection: &Connection) -> RuntimeLedgerCheckpoint {
        let checkpoint_id = digest("schema-v6-legacy-checkpoint");
        let record = runtime_record(
            "schema-v6-legacy",
            "nq.provider_intake.v1",
            "2026-07-29T11:59:59Z",
        );
        let ledger_root =
            runtime_record_root(1, &record, &checkpoint_id, None, None).expect("v6 ledger root");
        let batch_digest = legacy_runtime_record_batch_digest(
            &checkpoint_id,
            None,
            None,
            std::slice::from_ref(&record),
        )
        .expect("v6 batch digest");
        connection
            .execute(
                "INSERT INTO runtime_record_checkpoints (
                    checkpoint_id, batch_digest, first_record_sequence,
                    last_record_sequence, record_count, predecessor_checkpoint_id,
                    predecessor_ledger_root, checkpoint_ledger_root, committed_at
                 ) VALUES (?1, ?2, 1, 1, 1, NULL, NULL, ?3, ?4)",
                params![
                    checkpoint_id,
                    batch_digest.as_str(),
                    ledger_root.as_str(),
                    "2026-07-29T12:00:00Z",
                ],
            )
            .expect("insert exact v6 checkpoint");
        connection
            .execute(
                "INSERT INTO runtime_record_ledger (
                    record_sequence, record_id, record_schema, canonical_bytes,
                    canonical_bytes_sha256, checkpoint_id, predecessor_record_id,
                    predecessor_ledger_root, ledger_root, committed_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7)",
                params![
                    record.record_id,
                    record.record_schema,
                    record.canonical_bytes.as_bytes(),
                    record.canonical_bytes.digest(),
                    checkpoint_id,
                    ledger_root.as_str(),
                    record.committed_at,
                ],
            )
            .expect("insert exact v6 record");
        connection
            .execute(
                "INSERT INTO runtime_record_lookup (
                    record_id, record_sequence, record_schema, ledger_root
                 ) VALUES (?1, 1, ?2, ?3)",
                params![record.record_id, record.record_schema, ledger_root.as_str()],
            )
            .expect("insert exact v6 lookup");
        validate_v6_upgrade_source_connection(connection).expect("exact v6 history validates");
        runtime_ledger_checkpoint_on_connection(connection)
            .expect("v6 frontier")
            .expect("v6 checkpoint")
    }

    fn configured_store() -> (Store, String) {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let profile_digest = append_fixture_descriptor(&mut store);
        (store, profile_digest)
    }

    #[test]
    fn sole_genesis_identity_fails_closed_on_zero_or_multiple_records() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        assert!(
            store
                .sole_genesis_id()
                .expect_err("a store without genesis cannot identify a node")
                .to_string()
                .contains("no genesis identity")
        );

        store
            .append_genesis(&GenesisInput {
                genesis_id: "genesis-a".to_owned(),
                legacy_manifest_digest: None,
                created_at: TIME.to_owned(),
                detail: document(json!({"source": "test"})),
            })
            .expect("append first genesis");
        assert_eq!(
            store.sole_genesis_id().expect("one genesis is exact"),
            "genesis-a"
        );

        store
            .append_genesis(&GenesisInput {
                genesis_id: "genesis-b".to_owned(),
                legacy_manifest_digest: None,
                created_at: TIME.to_owned(),
                detail: document(json!({"source": "test"})),
            })
            .expect("append second genesis");
        assert!(
            store
                .sole_genesis_id()
                .expect_err("multiple genesis records cannot identify one node")
                .to_string()
                .contains("more than one genesis identity")
        );
    }

    fn append_fixture_descriptor(store: &mut Store) -> String {
        let descriptor = document(json!({
            "profile_id": "fixture.health",
            "profile_version": "1",
            "observation_kinds": ["fixture.state"]
        }));
        let profile_digest = descriptor.digest().to_owned();
        store
            .append_profile_descriptor(&ProfileDescriptorInput {
                profile_id: "fixture.health".to_owned(),
                profile_version: "1".to_owned(),
                descriptor,
                recorded_at: TIME.to_owned(),
            })
            .expect("descriptor appends");
        profile_digest
    }

    fn typed_digest(label: &str) -> Sha256Digest {
        nq_protocol::sha256_bytes(label.as_bytes())
    }

    fn fixture_identity() -> AdmissionIdentity {
        AdmissionIdentity {
            profile_semantic_id: typed_digest("profile-semantic"),
            detector_identity_digest: detector_suite_identity_digest(Vec::<String>::new())
                .expect("empty fixture detector suite identity"),
            evaluator_source_digest: typed_digest("evaluator-source"),
            evaluator_artifact_digest: typed_digest("evaluator-artifact"),
            helper_artifact_digest: typed_digest("helper-executable"),
            config_digest: typed_digest("config"),
            protocol_version: "1.0".to_owned(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            artifact_identity_method: "fixture".to_owned(),
            platform_runtime_version: "test".to_owned(),
        }
    }

    fn append_fixture_admission(
        store: &mut Store,
        profile_digest: &str,
        instance_id: &str,
        admission_id: &str,
    ) {
        append_fixture_admission_with_identity(
            store,
            profile_digest,
            instance_id,
            admission_id,
            fixture_identity(),
        );
    }

    fn append_fixture_admission_with_identity(
        store: &mut Store,
        profile_digest: &str,
        instance_id: &str,
        admission_id: &str,
        identity: AdmissionIdentity,
    ) {
        store
            .append_admission(&AdmissionInput {
                admission_id: admission_id.to_owned(),
                instance_id: instance_id.to_owned(),
                identity,
                execution_chain: document(json!({"artifacts": []})),
                profile_id: "fixture.health".to_owned(),
                profile_version: "1".to_owned(),
                profile_digest: profile_digest.to_owned(),
                capability_grant: document(json!([])),
                conformance: document(json!({"passed": true})),
                lock: document(json!({
                    "schema": "fixture.admission",
                    "admission_id": admission_id,
                    "instance_id": instance_id,
                })),
                admitted_at: TIME.to_owned(),
                operator_identity: document(json!({"uid": 991})),
            })
            .expect("fixture admission appends");
    }

    fn run(instance_id: &str, suffix: &str, profile_digest: &str) -> RunInput {
        RunInput {
            run_id: format!("run-{suffix}"),
            request_id: format!("request-{suffix}"),
            instance_id: instance_id.to_owned(),
            admission_id: None,
            binding_digest: digest(&format!("binding-{instance_id}")),
            checkpoint_contract_digest: digest(&format!("checkpoint-{instance_id}")),
            profile_id: "fixture.health".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.to_owned(),
            carrier: "stdio".to_owned(),
            started_at: TIME.to_owned(),
            deadline_at: "2026-07-16T12:00:10.000Z".to_owned(),
            finished_at: TIME.to_owned(),
            acquisition_outcome: "response".to_owned(),
            execution_identity: document(json!({"uid": 991})),
            resource_outcome: document(json!({
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
        }
    }

    fn activate_fixture_provider(store: &mut Store, run: &RunInput, provider_admission_id: &str) {
        let transaction = store
            .immediate_transaction()
            .expect("fixture binding writer");
        let binding_event_id = uuid::Uuid::new_v4().to_string();
        let operation_id = uuid::Uuid::new_v4().to_string();
        insert_binding_event(
            &transaction,
            &BindingEventInput {
                binding_event_id: binding_event_id.clone(),
                instance_id: run.instance_id.clone(),
                event_kind: "activate".to_owned(),
                admission_id: Some(provider_admission_id.to_owned()),
                binding_digest: run.binding_digest.clone(),
                occurred_at: TIME.to_owned(),
                reason_code: Some("provider_intake_fixture".to_owned()),
                detail: document(json!({"fixture": true})),
            },
        )
        .expect("fixture provider binding inserts");
        for phase in ["intent", "completed"] {
            insert_materialization_event(
                &transaction,
                &BindingMaterializationInput {
                    materialization_event_id: uuid::Uuid::new_v4().to_string(),
                    operation_id: operation_id.clone(),
                    instance_id: run.instance_id.clone(),
                    binding_event_id: binding_event_id.clone(),
                    phase: phase.to_owned(),
                    occurred_at: TIME.to_owned(),
                    detail: document(json!({"fixture": true, "phase": phase})),
                },
            )
            .expect("fixture provider materialization inserts");
        }
        transaction
            .commit()
            .expect("fixture provider binding commits");
    }

    fn fixture_collection(
        store: &mut Store,
        mut run: RunInput,
        submission: Option<SubmissionInput>,
    ) -> CollectionInput {
        let source_admission_id = run
            .admission_id
            .as_deref()
            .expect("live fixture run has provider admission")
            .to_owned();
        let admission = store
            .admission(&source_admission_id)
            .expect("fixture admission query")
            .expect("fixture admission exists");
        run.binding_digest = CanonicalDocument::from_canonical_bytes(admission.lock_json.clone())
            .expect("fixture source lock canonical")
            .digest()
            .to_owned();
        let execution_identity_bytes: Vec<u8> = store
            .connection
            .query_row(
                "SELECT execution_chain_json FROM admission_records WHERE admission_id = ?1",
                [&source_admission_id],
                |row| row.get(0),
            )
            .expect("fixture source execution identity");
        run.execution_identity = CanonicalDocument::from_canonical_bytes(execution_identity_bytes)
            .expect("fixture execution identity canonical");
        activate_fixture_provider(store, &run, &source_admission_id);
        let provider_admission = store
            .provider_admission_for_source(&source_admission_id)
            .expect("fixture provider admission query")
            .expect("fixture provider admission exists");
        let conformance_bytes: Vec<u8> = store
            .connection
            .query_row(
                "SELECT conformance_json FROM admission_records WHERE admission_id = ?1",
                [&source_admission_id],
                |row| row.get(0),
            )
            .expect("fixture conformance");
        let conformance = CanonicalDocument::from_canonical_bytes(conformance_bytes)
            .expect("fixture conformance canonical");
        let raw_bytes = submission
            .as_ref()
            .map_or_else(Vec::new, |submission| submission.raw_bytes.clone());
        let received_at = submission.as_ref().map_or_else(
            || run.finished_at.clone(),
            |submission| submission.received_at.clone(),
        );
        let (interpretation_kind, interpretation) = match submission.as_ref() {
            Some(SubmissionInput {
                protocol_outcome,
                disposition: SubmissionDisposition::Admitted(report),
                ..
            }) if protocol_outcome == "valid_report" => (
                "candidate_report".to_owned(),
                report.canonical_report.clone(),
            ),
            Some(SubmissionInput {
                raw_bytes,
                protocol_outcome,
                disposition: SubmissionDisposition::Rejected { .. },
                ..
            }) if protocol_outcome == "valid_report" => (
                "candidate_report".to_owned(),
                document(json!({
                    "schema": "fixture.candidate_report.v1",
                    "raw_sha256": sha256_digest(raw_bytes),
                })),
            ),
            Some(SubmissionInput {
                protocol_outcome,
                disposition: SubmissionDisposition::Rejected { refusal },
                ..
            }) if protocol_outcome == "valid_refusal" => (
                "provider_refusal".to_owned(),
                document(json!({
                    "schema": "fixture.provider_interpretation.v1",
                    "refusal_id": refusal.refusal_id,
                    "source_kind": refusal.source_kind,
                    "code": refusal.code,
                    "detail": serde_json::from_slice::<Value>(refusal.detail.as_bytes())
                        .expect("fixture refusal detail JSON"),
                })),
            ),
            Some(SubmissionInput {
                protocol_outcome,
                disposition: SubmissionDisposition::Rejected { refusal },
                ..
            }) if protocol_outcome == "rejected" => (
                "protocol_rejected".to_owned(),
                document(json!({
                    "schema": "fixture.provider_interpretation.v1",
                    "refusal_id": refusal.refusal_id,
                    "source_kind": refusal.source_kind,
                    "code": refusal.code,
                    "detail": serde_json::from_slice::<Value>(refusal.detail.as_bytes())
                        .expect("fixture refusal detail JSON"),
                })),
            ),
            Some(SubmissionInput {
                protocol_outcome,
                disposition: SubmissionDisposition::Rejected { .. },
                ..
            }) if protocol_outcome == "not_validated" => {
                ("unavailable".to_owned(), document(Value::Null))
            }
            None => ("unavailable".to_owned(), document(Value::Null)),
            Some(submission) => panic!(
                "fixture submission has unsupported protocol outcome {}",
                submission.protocol_outcome
            ),
        };
        let intake_id = format!("intake-{}", run.run_id);
        let attempt_id = format!("attempt-{}", run.run_id);
        let provider_admission_id = provider_admission.provider_admission_id;
        let idempotency_key = provider_idempotency_key(&provider_admission_id, &attempt_id)
            .expect("fixture provider idempotency identity");
        let intake = ProviderIntakeInput {
            intake_id,
            attempt_id,
            idempotency_key,
            request_id: run.request_id.clone(),
            provider_admission_id,
            source_admission_id,
            provider_sequence: None,
            origin_carrier: run.carrier.clone(),
            deadline_at: run.deadline_at.clone(),
            checkpoint_contract_digest: run.checkpoint_contract_digest.clone(),
            execution_identity_digest: Sha256Digest::parse(
                run.execution_identity.digest().to_owned(),
            )
            .expect("fixture execution identity digest"),
            admission_context_digest: Sha256Digest::parse(admission.admission_context_digest)
                .expect("fixture admission context digest"),
            provider_semantic_id: local_provider_semantic_id(
                &admission.protocol_version,
                &conformance,
            )
            .expect("fixture provider semantic identity"),
            provider_artifact_digest: Sha256Digest::parse(admission.helper_artifact_digest)
                .expect("fixture helper artifact digest"),
            provider_protocol_identity: admission.protocol_version,
            provider_config_digest: Sha256Digest::parse(admission.config_digest)
                .expect("fixture config digest"),
            binding_digest: run.binding_digest.clone(),
            instance_id: run.instance_id.clone(),
            profile_id: run.profile_id.clone(),
            profile_version: run.profile_version.clone(),
            profile_digest: run.profile_digest.clone(),
            profile_semantic_id: Sha256Digest::parse(admission.profile_semantic_id)
                .expect("fixture profile semantic identity"),
            evaluator_artifact_digest: Sha256Digest::parse(admission.evaluator_artifact_digest)
                .expect("fixture evaluator artifact digest"),
            context: document(json!({
                "schema": "fixture.provider_intake_context.v1",
                "subject": format!("fixture:{}", run.instance_id),
                "scope": {"kind": "fixture", "instance": run.instance_id},
                "vantage": {"kind": "local"},
                "requested_capabilities": [],
                "declared_coverage": [],
                "incomplete": false,
            })),
            interpretation_kind,
            interpretation,
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

    fn bound_fixture_run(
        store: &mut Store,
        instance_id: &str,
        suffix: &str,
        profile_digest: &str,
    ) -> RunInput {
        let admission_id = format!("admission-provider-{suffix}");
        append_fixture_admission(store, profile_digest, instance_id, &admission_id);
        let mut run = run(instance_id, suffix, profile_digest);
        run.admission_id = Some(admission_id);
        run
    }

    fn rejected_fixture_collection(
        store: &mut Store,
        instance_id: &str,
        suffix: &str,
        profile_digest: &str,
    ) -> CollectionInput {
        let run = bound_fixture_run(store, instance_id, suffix, profile_digest);
        fixture_collection(
            store,
            run,
            Some(SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes: format!("rejected-{suffix}\n").into_bytes(),
                received_at: TIME.to_owned(),
                protocol_outcome: "rejected".to_owned(),
                disposition: SubmissionDisposition::Rejected {
                    refusal: RefusalInput {
                        refusal_id: format!("refusal-{suffix}"),
                        source_kind: "protocol".to_owned(),
                        responsible_instance_id: instance_id.to_owned(),
                        boundary: "response".to_owned(),
                        code: "invalid_response".to_owned(),
                        profile_semantic_id: None,
                        detail: document(json!({"fixture": suffix})),
                        created_at: TIME.to_owned(),
                    },
                },
            }),
        )
    }

    fn committed_parts<T>(commit: ProviderIntakeCommit<T>) -> (CollectionReceipt, T) {
        match commit {
            ProviderIntakeCommit::Committed { receipt, value, .. } => (receipt, value),
            ProviderIntakeCommit::Replayed { .. } => {
                panic!("fresh fixture unexpectedly replayed provider intake")
            }
        }
    }

    fn evaluation_profile(profile_digest: &str) -> EvaluationProfileBinding {
        EvaluationProfileBinding {
            profile_id: "fixture.health".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.to_owned(),
            profile_semantic_id: typed_digest("profile-semantic"),
        }
    }

    fn non_success_status(run_id: &str, instance_id: &str, suffix: &str) -> RunResultStatusInput {
        RunResultStatusInput {
            run_id: run_id.to_owned(),
            status: StatusEventInput {
                status_event_id: format!("status-{suffix}"),
                component_kind: "instance".to_owned(),
                component_id: instance_id.to_owned(),
                state: "failed".to_owned(),
                code: "collection_failed".to_owned(),
                detail: document(json!({"run_id": run_id})),
                observed_at: TIME.to_owned(),
            },
        }
    }

    fn run_only_diagnostic_artifact(
        collection: &CollectionInput,
        suffix: &str,
    ) -> DiagnosticArtifactCommitInput {
        let artifact_id = typed_digest(&format!("run-only-diagnostic-artifact-{suffix}"));
        DiagnosticArtifactCommitInput {
            artifact_id: artifact_id.clone(),
            contract_schema: "nq.diagnostic_execution.v1".to_owned(),
            canonical_bytes: document(json!({
                "schema": "nq.diagnostic_execution.v1",
                "artifact_id": artifact_id.as_str(),
                "run_id": collection.run.run_id,
                "request_id": collection.run.request_id,
                "profile": {
                    "id": collection.run.profile_id,
                    "version": collection.run.profile_version,
                    "digest": collection.run.profile_digest,
                },
                "completed_at": TIME,
                "fixture": suffix,
            })),
            local_origin: DiagnosticArtifactLocalOriginInput {
                run_id: collection.run.run_id.clone(),
                evaluation_id: None,
                completed_at: TIME.to_owned(),
                execution_binding: None,
            },
        }
    }

    /// Seed a historical row through the internal primitives, deliberately
    /// bypassing the public atomic commit API while retaining a canonical
    /// run-linked result. Hostile tests can then isolate the intended defect.
    fn append_historical_run_with_result(store: &mut Store, run: &RunInput) {
        let transaction = store.immediate_transaction().expect("historical writer");
        insert_run(&transaction, run).expect("historical run insert");
        insert_fixture_legacy_intake_gap(&transaction, &run.run_id);
        insert_status_event(
            &transaction,
            &StatusEventInput {
                status_event_id: format!("status-historical-{}", run.run_id),
                component_kind: "instance".to_owned(),
                component_id: run.instance_id.clone(),
                state: "failed".to_owned(),
                code: "collection_failed".to_owned(),
                detail: document(json!({"run_id": &run.run_id})),
                observed_at: TIME.to_owned(),
            },
            Some(&run.run_id),
        )
        .expect("historical result insert");
        transaction.commit().expect("historical run commit");
    }

    fn insert_fixture_legacy_intake_gap(transaction: &Transaction<'_>, run_id: &str) {
        transaction
            .execute(
                "INSERT INTO legacy_v3_watcher_run_intake_gaps (
                    run_id, source_schema_version, source_schema_artifact_digest,
                    limitation_code, detail_json, migrated_at
                 ) VALUES (?1, 3, ?2, 'provider_intake_not_recorded', ?3, ?4)",
                params![
                    run_id,
                    SCHEMA_V3_ARTIFACT_DIGEST,
                    document(json!({
                        "schema": "nq.legacy_provider_intake_gap.v1",
                        "provider_intake_synthesized": false,
                    }))
                    .as_bytes(),
                    TIME,
                ],
            )
            .expect("fixture legacy provider-intake gap");
    }

    fn report(
        instance_id: &str,
        suffix: &str,
        profile_digest: &str,
        canonical_report: CanonicalDocument,
    ) -> ReportInput {
        let fixture_payload: Value =
            serde_json::from_slice(canonical_report.as_bytes()).expect("fixture payload JSON");
        let subject =
            nq_protocol::SubjectId::new(format!("fixture:{instance_id}")).expect("fixture subject");
        let protocol_report = nq_protocol::EvidenceReport {
            schema: nq_protocol::EVIDENCE_REPORT_SCHEMA.to_owned(),
            profile: nq_protocol::ProfileBinding {
                id: nq_protocol::ProfileId::new("fixture.health").expect("profile id"),
                version: nq_protocol::ProfileVersion::new("1").expect("profile version"),
                digest: Sha256Digest::parse(profile_digest.to_owned()).expect("profile digest"),
            },
            binding: nq_protocol::SubjectBinding {
                subject: subject.clone(),
                scope: nq_protocol::ScopeBinding {
                    kind: nq_protocol::ScopeKind::new("fixture").expect("scope kind"),
                    value: json!({"instance": instance_id}),
                },
                vantage: nq_protocol::VantageBinding {
                    kind: nq_protocol::VantageKind::new("local").expect("vantage kind"),
                    value: json!({}),
                },
            },
            observed_at: chrono::DateTime::parse_from_rfc3339(TIME)
                .expect("fixture time")
                .with_timezone(&Utc),
            status: nq_protocol::ReportStatus::Complete,
            coverage: vec![nq_protocol::CoverageDeclaration {
                kind: nq_protocol::CoverageKind::new("inventory").expect("coverage kind"),
                subject: None,
                state: nq_protocol::CoverageState::Complete,
                detail: None,
            }],
            observations: vec![nq_protocol::Observation {
                ordinal: 0,
                kind: nq_protocol::ObservationKind::new("fixture.state").expect("observation kind"),
                subject: subject.clone(),
                observed_at: chrono::DateTime::parse_from_rfc3339(TIME)
                    .expect("fixture time")
                    .with_timezone(&Utc),
                payload: fixture_payload,
            }],
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
        nq_protocol::validate_report(&protocol_report).expect("fixture report");
        let canonical_report =
            CanonicalDocument::from_serializable(&protocol_report).expect("canonical report");
        let report_digest = canonical_report.digest().to_owned();
        ReportInput {
            report_id: format!("report-{suffix}"),
            instance_id: instance_id.to_owned(),
            profile_id: "fixture.health".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.to_owned(),
            observed_at: TIME.to_owned(),
            received_at: TIME.to_owned(),
            report_status: "complete".to_owned(),
            canonical_report,
            validated_report: document(json!({
                "schema": "fixture.validated_report.v1",
                "instance_id": instance_id,
                "report_digest": report_digest,
                "profile": {"id": "fixture.health", "version": 1},
                "profile_digest": profile_digest,
                "status": "complete",
                "observed_at": TIME,
                "received_at": TIME,
            })),
            next_checkpoint: None,
            admitted_at: TIME.to_owned(),
            observations: vec![ObservationInput {
                ordinal: 0,
                kind: "fixture.state".to_owned(),
                subject: document(json!(subject.to_string())),
                observed_at: TIME.to_owned(),
                payload: document(protocol_report.observations[0].payload.clone()),
                coverage: vec![CoverageInput {
                    ordinal: 0,
                    coverage_kind: "inventory".to_owned(),
                    coverage_state: "complete".to_owned(),
                    detail: document(Value::Null),
                }],
            }],
            coverage: vec![CoverageInput {
                ordinal: 0,
                coverage_kind: "inventory".to_owned(),
                coverage_state: "complete".to_owned(),
                detail: document(json!({"subject": null, "detail": null})),
            }],
            errors: Vec::new(),
        }
    }

    fn commit_admitted(
        store: &mut Store,
        instance_id: &str,
        suffix: &str,
        profile_digest: &str,
        canonical_report: CanonicalDocument,
        raw_bytes: Vec<u8>,
    ) -> CollectionReceipt {
        // An admitted report requires a run bound to a recorded admission.
        let admission_id = format!("admission-{suffix}");
        append_fixture_admission(store, profile_digest, instance_id, &admission_id);
        let mut bound_run = run(instance_id, suffix, profile_digest);
        bound_run.admission_id = Some(admission_id);
        let collection = fixture_collection(
            store,
            bound_run,
            Some(SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes,
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    instance_id,
                    suffix,
                    profile_digest,
                    canonical_report,
                )),
            }),
        );
        commit_admitted_fixture(store, collection).expect("collection commits")
    }

    fn commit_admitted_fixture(
        store: &mut Store,
        collection: CollectionInput,
    ) -> Result<CollectionReceipt, StoreError> {
        let run_id = collection.run.run_id.clone();
        let instance_id = collection.run.instance_id.clone();
        let (report_id, report_status) = match &collection
            .submission
            .as_ref()
            .expect("admitted fixture submission")
            .disposition
        {
            SubmissionDisposition::Admitted(report) => {
                (report.report_id.clone(), report.report_status.clone())
            }
            SubmissionDisposition::Rejected { .. } => panic!("admitted fixture disposition"),
        };
        let (receipt, ()) = committed_parts(store.commit_admitted_collection(
            &collection,
            |_view, receipt| {
                Ok::<_, StoreError>(AdmittedCollectionCompletion {
                    value: (),
                    evaluations: Vec::new(),
                    diagnostic_artifact: None,
                    status: StatusEventInput {
                        status_event_id: format!("status-{run_id}"),
                        component_kind: "instance".to_owned(),
                        component_id: instance_id.clone(),
                        state: "healthy".to_owned(),
                        code: "report_complete".to_owned(),
                        detail: document(json!({
                            "schema": "nq.collection_outcome.v2",
                            "instance_id": instance_id,
                            "run_id": run_id,
                            "result": {
                                "outcome": "admitted",
                                "report_id": report_id,
                                "report_status": report_status,
                                "semantic_digest": receipt.semantic_digest,
                                "evaluations": [],
                            },
                        })),
                        observed_at: TIME.to_owned(),
                    },
                })
            },
        )?);
        Ok(receipt)
    }

    fn commit_diagnostic_artifact_fixture(
        store: &mut Store,
        suffix: &str,
        profile_digest: &str,
        artifact_evaluation_id: &str,
    ) -> (
        String,
        Sha256Digest,
        Result<ProviderIntakeCommit<()>, StoreError>,
    ) {
        let detector_digest = digest(&format!("diagnostic-detector-{suffix}"));
        let evaluator_digest = typed_digest(&format!("diagnostic-evaluator-{suffix}"));
        let mut identity = fixture_identity();
        identity.detector_identity_digest =
            detector_suite_identity_digest([detector_digest.as_str()])
                .expect("diagnostic detector suite");
        identity.evaluator_artifact_digest = evaluator_digest.clone();
        let admission_id = format!("admission-diagnostic-{suffix}");
        append_fixture_admission_with_identity(
            store,
            profile_digest,
            "fixture-a",
            &admission_id,
            identity,
        );
        let mut bound_run = run("fixture-a", suffix, profile_digest);
        bound_run.admission_id = Some(admission_id);
        let run_id = bound_run.run_id.clone();
        let evaluation_id = format!("evaluation-{suffix}");
        let report_id = format!("report-{suffix}");
        let collection = fixture_collection(
            store,
            bound_run,
            Some(SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes: format!("diagnostic {suffix}").into_bytes(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    suffix,
                    profile_digest,
                    document(json!({"diagnostic": suffix})),
                )),
            }),
        );
        let artifact_id = typed_digest(&format!("diagnostic-artifact-{suffix}"));
        let artifact_document = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": artifact_id.as_str(),
            "run_id": run_id,
            "request_id": collection.run.request_id,
            "profile": {
                "id": collection.run.profile_id,
                "version": collection.run.profile_version,
                "digest": collection.run.profile_digest,
            },
            "completed_at": TIME,
            "fixture": suffix,
        }));
        let result = store.commit_admitted_collection(&collection, |_view, receipt| {
            let report_sequence = receipt.report_sequence.expect("pending report sequence");
            Ok::<_, StoreError>(AdmittedCollectionCompletion {
                value: (),
                evaluations: vec![EvaluationCommitInput {
                    evaluation: EvaluationInput {
                        evaluation_id: evaluation_id.clone(),
                        trigger_run_id: Some(run_id.clone()),
                        detector_id: "fixture.detector".to_owned(),
                        detector_version: "1".to_owned(),
                        detector_digest: detector_digest.clone(),
                        evaluator_artifact_digest: evaluator_digest.as_str().to_owned(),
                        started_at: TIME.to_owned(),
                        evaluated_at: TIME.to_owned(),
                        outcome: "condition_explicitly_absent".to_owned(),
                        detail: document(json!({"result": "absent"})),
                        profile: evaluation_profile(profile_digest),
                        watermarks: vec![EvaluationWatermark {
                            instance_id: "fixture-a".to_owned(),
                            max_report_sequence: report_sequence,
                            watermark_received_at: Some(TIME.to_owned()),
                        }],
                        refusal: None,
                    },
                    finding: None,
                }],
                diagnostic_artifact: Some(DiagnosticArtifactCommitInput {
                    artifact_id: artifact_id.clone(),
                    contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                    canonical_bytes: artifact_document.clone(),
                    local_origin: DiagnosticArtifactLocalOriginInput {
                        run_id: run_id.clone(),
                        evaluation_id: Some(artifact_evaluation_id.to_owned()),
                        completed_at: TIME.to_owned(),
                        execution_binding: None,
                    },
                }),
                status: StatusEventInput {
                    status_event_id: format!("status-{suffix}"),
                    component_kind: "instance".to_owned(),
                    component_id: "fixture-a".to_owned(),
                    state: "healthy".to_owned(),
                    code: "report_complete".to_owned(),
                    detail: document(json!({
                        "schema": "nq.collection_outcome.v2",
                        "instance_id": "fixture-a",
                        "run_id": run_id,
                        "result": {
                            "outcome": "admitted",
                            "report_id": report_id,
                            "report_status": "complete",
                            "semantic_digest": receipt.semantic_digest,
                            "evaluations": [{"result": "absent"}],
                        },
                    })),
                    observed_at: TIME.to_owned(),
                },
            })
        });
        (run_id, artifact_id, result)
    }

    fn commit_rejected(
        store: &mut Store,
        suffix: &str,
        profile_digest: &str,
        refusal_id: &str,
        code: &str,
        detail: CanonicalDocument,
    ) -> CollectionReceipt {
        let admission_id = format!("admission-{suffix}");
        append_fixture_admission(store, profile_digest, "fixture-a", &admission_id);
        let mut bound_run = run("fixture-a", suffix, profile_digest);
        bound_run.admission_id = Some(admission_id);
        let collection = fixture_collection(
            store,
            bound_run,
            Some(SubmissionInput {
                submission_id: format!("submission-{suffix}"),
                raw_bytes: format!("raw-{suffix}\n").into_bytes(),
                received_at: TIME.to_owned(),
                protocol_outcome: "rejected".to_owned(),
                disposition: SubmissionDisposition::Rejected {
                    refusal: RefusalInput {
                        refusal_id: refusal_id.to_owned(),
                        source_kind: "protocol".to_owned(),
                        responsible_instance_id: "fixture-a".to_owned(),
                        boundary: "collection".to_owned(),
                        code: code.to_owned(),
                        profile_semantic_id: None,
                        detail,
                        created_at: TIME.to_owned(),
                    },
                },
            }),
        );
        let result = non_success_status(&collection.run.run_id, "fixture-a", suffix);
        committed_parts(
            store
                .commit_non_success_collection(&collection, &result)
                .expect("rejected collection commits"),
        )
        .0
    }

    #[derive(Clone, Copy)]
    enum HistoricalRefusalDefect {
        WrongRun,
        WrongInstance,
        WrongProfileId,
        WrongProfileVersion,
        WrongProfileDigest,
        WrongCode,
        NonCanonicalDetail,
    }

    /// Model rows written outside the typed Store API. The physical schema can
    /// represent them, but semantic reopening must refuse any association that
    /// cannot prove its exact typed refusal linkage.
    fn historical_rejection_with(defect: HistoricalRefusalDefect) -> Store {
        let (mut store, profile_digest) = configured_store();
        let suffix = "historical";
        append_historical_run_with_result(&mut store, &run("fixture-a", suffix, &profile_digest));
        if matches!(defect, HistoricalRefusalDefect::WrongRun) {
            append_historical_run_with_result(
                &mut store,
                &run("fixture-b", "other", &profile_digest),
            );
        }

        let raw = b"historical rejected bytes\n";
        store
            .connection
            .execute(
                "INSERT INTO raw_submissions (
                    submission_id, run_id, raw_bytes, raw_sha256, received_at,
                    protocol_outcome, admission_outcome, rejection_code
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'rejected', ?7)",
                params![
                    "submission-historical",
                    "run-historical",
                    raw,
                    sha256_digest(raw),
                    TIME,
                    "valid_refusal",
                    "collection_failed",
                ],
            )
            .expect("historical custody appends");

        let refusal_run = if matches!(defect, HistoricalRefusalDefect::WrongRun) {
            "run-other"
        } else {
            "run-historical"
        };
        let responsible = if matches!(defect, HistoricalRefusalDefect::WrongInstance) {
            "fixture-b"
        } else {
            "fixture-a"
        };
        let profile_id = if matches!(defect, HistoricalRefusalDefect::WrongProfileId) {
            "other.profile"
        } else {
            "fixture.health"
        };
        let profile_version = if matches!(defect, HistoricalRefusalDefect::WrongProfileVersion) {
            "2"
        } else {
            "1"
        };
        let refusal_profile_digest =
            if matches!(defect, HistoricalRefusalDefect::WrongProfileDigest) {
                digest("other-profile")
            } else {
                profile_digest
            };
        let refusal_code = if matches!(defect, HistoricalRefusalDefect::WrongCode) {
            "other_code"
        } else {
            "collection_failed"
        };
        let detail: &[u8] = if matches!(defect, HistoricalRefusalDefect::NonCanonicalDetail) {
            br#"{ "retriable": true, "details": {"attempt": 1} }"#
        } else {
            br#"{"details":{"attempt":1},"retriable":true}"#
        };
        store
            .connection
            .execute(
                "INSERT INTO refusals (
                    refusal_id, source_kind, responsible_instance_id, boundary,
                    code, run_id, submission_id, evaluation_id, profile_id,
                    profile_version, profile_digest, detail_json, created_at
                 ) VALUES (?1, 'protocol', ?2, 'collection', ?3, ?4, ?5,
                           NULL, ?6, ?7, ?8, ?9, ?10)",
                params![
                    "refusal-historical",
                    responsible,
                    refusal_code,
                    refusal_run,
                    "submission-historical",
                    profile_id,
                    profile_version,
                    refusal_profile_digest,
                    detail,
                    TIME,
                ],
            )
            .expect("historical refusal appends");
        store
    }

    #[test]
    fn initialization_is_explicit_and_version_gated() {
        let directory = tempdir().expect("temp dir");
        let missing = directory.path().join("missing.db");
        assert!(matches!(
            Store::open(&missing),
            Err(StoreError::NotInitialized(_))
        ));

        let path = directory.path().join("nq.db");
        let store = Store::initialize(&path).expect("explicit init works");
        assert!(matches!(
            Store::initialize(&path),
            Err(StoreError::AlreadyInitialized { .. })
        ));
        store
            .connection
            .pragma_update(None, "user_version", 2)
            .expect("mark fixture as an incompatible v2 store");
        drop(store);
        let v2_bytes = std::fs::read(&path).expect("read v2 sentinel");
        let v2_digest = nq_protocol::sha256_bytes(&v2_bytes);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::SchemaVersionMismatch {
                found: 2,
                supported: SCHEMA_VERSION
            })
        ));
        let after_open = std::fs::read(&path).expect("reread refused v2 sentinel");
        assert_eq!(
            after_open, v2_bytes,
            "failed open must not rewrite v2 bytes"
        );
        assert_eq!(
            nq_protocol::sha256_bytes(&after_open),
            v2_digest,
            "failed open must preserve the exact v2 file identity"
        );

        let empty_path = directory.path().join("empty.db");
        std::fs::File::create(&empty_path).expect("empty file");
        Store::initialize(&empty_path).expect("zero-byte placeholder can be initialized");
    }

    #[test]
    fn immutable_open_preserves_prepared_archive_bytes_and_file_inventory() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("sealed.db");
        let store = Store::initialize(&path).expect("initialize sealed store");
        store
            .prepare_archive_copy()
            .expect("checkpoint and freeze archive copy");
        drop(store);
        let inventory = || {
            let mut names = std::fs::read_dir(directory.path())
                .expect("read inventory")
                .map(|entry| {
                    entry
                        .expect("inventory entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let before_inventory = inventory();
        let before = std::fs::read(&path).expect("read sealed database");
        let before_digest = nq_protocol::sha256_bytes(&before);

        for _ in 0..2 {
            let store = Store::open_immutable(&path).expect("immutable reopen");
            store.validate().expect("immutable validation");
            drop(store);
        }

        let after = std::fs::read(&path).expect("reread sealed database");
        assert_eq!(
            after, before,
            "read-only verification changed database bytes"
        );
        assert_eq!(nq_protocol::sha256_bytes(&after), before_digest);
        assert_eq!(
            inventory(),
            before_inventory,
            "read-only verification created or removed a SQLite sidecar"
        );
    }

    #[test]
    fn raw_submission_is_byte_exact_and_rejected_evidence_is_isolated() {
        let (mut store, profile_digest) = configured_store();
        let raw = vec![0, 0xff, b'\n', b'{', b'}', 0];
        let bound_run = bound_fixture_run(&mut store, "fixture-a", "rejected", &profile_digest);
        let collection = fixture_collection(
            &mut store,
            bound_run,
            Some(SubmissionInput {
                submission_id: "submission-rejected".to_owned(),
                raw_bytes: raw.clone(),
                received_at: TIME.to_owned(),
                protocol_outcome: "rejected".to_owned(),
                disposition: SubmissionDisposition::Rejected {
                    refusal: RefusalInput {
                        refusal_id: "refusal-rejected".to_owned(),
                        source_kind: "protocol".to_owned(),
                        responsible_instance_id: "fixture-a".to_owned(),
                        boundary: "response_frame".to_owned(),
                        code: "malformed_json".to_owned(),
                        profile_semantic_id: None,
                        detail: document(json!({"offset": 1})),
                        created_at: TIME.to_owned(),
                    },
                },
            }),
        );
        let result = non_success_status(&collection.run.run_id, "fixture-a", "rejected");
        let (receipt, ()) = committed_parts(
            store
                .commit_non_success_collection(&collection, &result)
                .expect("rejected custody commits"),
        );
        assert_eq!(
            receipt.raw_sha256,
            Some(nq_protocol::sha256_bytes(&raw).into_string())
        );
        assert_eq!(
            store
                .raw_submission_bytes("submission-rejected")
                .expect("raw query"),
            Some(raw)
        );
        assert_eq!(
            store
                .report_id_for_submission("submission-rejected")
                .expect("report query"),
            None
        );

        let malicious_insert = store.connection.execute(
            "INSERT INTO admitted_reports (
                report_id, submission_id, instance_id, profile_id, profile_version,
                profile_digest, observed_at, received_at, report_status, canonical_json,
                semantic_digest, admitted_at
             ) VALUES ('bad-report', 'submission-rejected', 'fixture-a',
                'fixture.health', '1', ?1, ?2, ?2, 'failed', '{}', ?3, ?2)",
            params![profile_digest, TIME, digest("bad-report")],
        );
        assert!(malicious_insert.is_err());
    }

    #[test]
    fn non_success_commit_is_atomic_and_ordinary_path_fails_closed() {
        let (mut store, profile_digest) = configured_store();
        let incomplete_run = bound_fixture_run(
            &mut store,
            "fixture-a",
            "incomplete-response",
            &profile_digest,
        );
        let incomplete = fixture_collection(&mut store, incomplete_run, None);
        assert!(matches!(
            store.commit_collection(&incomplete),
            Err(StoreError::Invariant(message))
                if message.contains("completed response requires an exact pre-admission interpretation")
        ));

        let ordinary =
            rejected_fixture_collection(&mut store, "fixture-a", "ordinary", &profile_digest);
        assert!(matches!(
            store.commit_collection(&ordinary),
            Err(StoreError::Invariant(message))
                if message.contains("commit_non_success_collection")
        ));

        store
            .record_status(&StatusEventInput {
                status_event_id: "status-duplicate".to_owned(),
                component_kind: "database".to_owned(),
                component_id: "primary".to_owned(),
                state: "healthy".to_owned(),
                code: "ok".to_owned(),
                detail: document(json!({})),
                observed_at: TIME.to_owned(),
            })
            .expect("seed duplicate status identity");
        let atomic =
            rejected_fixture_collection(&mut store, "fixture-a", "rollback", &profile_digest);
        let mut result = non_success_status(&atomic.run.run_id, "fixture-a", "rollback");
        result.status.status_event_id = "status-duplicate".to_owned();
        assert!(
            store
                .commit_non_success_collection(&atomic, &result)
                .is_err()
        );

        for (table, column, identity) in [
            ("watcher_runs", "run_id", "run-rollback"),
            (
                "provider_intake_attempts",
                "intake_id",
                "intake-run-rollback",
            ),
            ("provider_intake_acknowledgments", "run_id", "run-rollback"),
            ("raw_submissions", "submission_id", "submission-rollback"),
            ("refusals", "refusal_id", "refusal-rollback"),
        ] {
            let count: i64 = store
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
                    [identity],
                    |row| row.get(0),
                )
                .expect("count rolled-back row");
            assert_eq!(count, 0, "{table} survived failed atomic commit");
        }
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM watcher_runs", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count all runs"),
            0,
            "ordinary and failed atomic paths must leave no watcher run"
        );
    }

    #[test]
    fn historical_response_run_without_result_fails_closed() {
        let (mut store, profile_digest) = configured_store();
        let historical = run("fixture-a", "historical-resultless", &profile_digest);
        let transaction = store.immediate_transaction().expect("historical writer");
        insert_run(&transaction, &historical).expect("insert resultless historical run");
        insert_fixture_legacy_intake_gap(&transaction, &historical.run_id);
        transaction
            .commit()
            .expect("commit resultless historical run");

        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("exactly one canonical run-linked result")
        ));
    }

    #[test]
    fn admitted_detector_suite_and_evaluator_binding_fail_atomically() {
        let required_detector = digest("suite-required-detector");
        let extra_detector = digest("suite-extra-detector");
        let expected_evaluator = typed_digest("suite-evaluator");
        let cases = [
            (
                "omitted",
                Vec::<String>::new(),
                expected_evaluator.as_str().to_owned(),
                "detector suite identity",
            ),
            (
                "duplicate",
                vec![required_detector.clone(), required_detector.clone()],
                expected_evaluator.as_str().to_owned(),
                "evaluates a detector more than once",
            ),
            (
                "extra",
                vec![required_detector.clone(), extra_detector],
                expected_evaluator.as_str().to_owned(),
                "detector suite identity",
            ),
            (
                "wrong-evaluator",
                vec![required_detector.clone()],
                digest("suite-substituted-evaluator"),
                "uses evaluator artifact",
            ),
        ];

        for (suffix, actual_detectors, actual_evaluator, expected_error) in cases {
            let (mut store, profile_digest) = configured_store();
            let admission_id = format!("admission-suite-{suffix}");
            let mut identity = fixture_identity();
            identity.detector_identity_digest =
                detector_suite_identity_digest([required_detector.as_str()])
                    .expect("required detector suite identity");
            identity.evaluator_artifact_digest = expected_evaluator.clone();
            append_fixture_admission_with_identity(
                &mut store,
                &profile_digest,
                "fixture-a",
                &admission_id,
                identity,
            );
            let mut admitted_run = run("fixture-a", suffix, &profile_digest);
            admitted_run.admission_id = Some(admission_id);
            let run_id = admitted_run.run_id.clone();
            let report_id = format!("report-{suffix}");
            let collection = fixture_collection(
                &mut store,
                admitted_run,
                Some(SubmissionInput {
                    submission_id: format!("submission-{suffix}"),
                    raw_bytes: format!("suite {suffix}").into_bytes(),
                    received_at: TIME.to_owned(),
                    protocol_outcome: "valid_report".to_owned(),
                    disposition: SubmissionDisposition::Admitted(report(
                        "fixture-a",
                        suffix,
                        &profile_digest,
                        document(json!({"suite": suffix})),
                    )),
                }),
            );
            let error = store
                .commit_admitted_collection(&collection, |_view, receipt| {
                    let report_sequence = receipt.report_sequence.expect("pending report");
                    let mut evaluation_documents = Vec::new();
                    let evaluations = actual_detectors
                        .iter()
                        .enumerate()
                        .map(|(ordinal, detector_digest)| {
                            let detail = json!({"case": suffix, "ordinal": ordinal});
                            evaluation_documents.push(detail.clone());
                            EvaluationCommitInput {
                                evaluation: EvaluationInput {
                                    evaluation_id: format!("evaluation-{suffix}-{ordinal}"),
                                    trigger_run_id: Some(run_id.clone()),
                                    detector_id: format!("fixture.detector.{ordinal}"),
                                    detector_version: "1".to_owned(),
                                    detector_digest: detector_digest.clone(),
                                    evaluator_artifact_digest: actual_evaluator.clone(),
                                    started_at: TIME.to_owned(),
                                    evaluated_at: TIME.to_owned(),
                                    outcome: "condition_explicitly_absent".to_owned(),
                                    detail: document(detail),
                                    profile: evaluation_profile(&profile_digest),
                                    watermarks: vec![EvaluationWatermark {
                                        instance_id: "fixture-a".to_owned(),
                                        max_report_sequence: report_sequence,
                                        watermark_received_at: Some(TIME.to_owned()),
                                    }],
                                    refusal: None,
                                },
                                finding: None,
                            }
                        })
                        .collect();
                    Ok::<_, StoreError>(AdmittedCollectionCompletion {
                        value: (),
                        evaluations,
                        diagnostic_artifact: None,
                        status: StatusEventInput {
                            status_event_id: format!("status-suite-{suffix}"),
                            component_kind: "instance".to_owned(),
                            component_id: "fixture-a".to_owned(),
                            state: "healthy".to_owned(),
                            code: "report_complete".to_owned(),
                            detail: document(json!({
                                "schema": "nq.collection_outcome.v2",
                                "instance_id": "fixture-a",
                                "run_id": run_id,
                                "result": {
                                    "outcome": "admitted",
                                    "report_id": report_id,
                                    "report_status": "complete",
                                    "semantic_digest": receipt.semantic_digest,
                                    "evaluations": evaluation_documents,
                                },
                            })),
                            observed_at: TIME.to_owned(),
                        },
                    })
                })
                .expect_err("inexact admitted judging mechanism must roll back");
            assert!(
                error.to_string().contains(expected_error),
                "unexpected {suffix} error: {error}"
            );
            for (table, predicate, identity) in [
                ("watcher_runs", "run_id", run_id.as_str()),
                ("raw_submissions", "run_id", run_id.as_str()),
                ("admitted_reports", "report_id", report_id.as_str()),
                ("evaluation_runs", "trigger_run_id", run_id.as_str()),
                ("status_events", "run_id", run_id.as_str()),
            ] {
                let count: i64 = store
                    .connection
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE {predicate} = ?1"),
                        [identity],
                        |row| row.get(0),
                    )
                    .expect("count rolled-back suite row");
                assert_eq!(count, 0, "{table} survived {suffix} suite rollback");
            }
            store
                .validate()
                .expect("failed atomic suite leaves valid store");
        }
    }

    #[test]
    fn admitted_report_evaluations_and_result_rollback_as_one_unit() {
        let (mut store, profile_digest) = configured_store();
        let atomic_detector = digest("atomic-detector");
        let atomic_evaluator = typed_digest("atomic-evaluator");
        let mut identity = fixture_identity();
        identity.detector_identity_digest =
            detector_suite_identity_digest([atomic_detector.as_str()])
                .expect("atomic detector suite identity");
        identity.evaluator_artifact_digest = atomic_evaluator.clone();
        append_fixture_admission_with_identity(
            &mut store,
            &profile_digest,
            "fixture-a",
            "admission-atomic-admitted",
            identity,
        );
        store
            .record_status(&StatusEventInput {
                status_event_id: "status-collision".to_owned(),
                component_kind: "database".to_owned(),
                component_id: "primary".to_owned(),
                state: "healthy".to_owned(),
                code: "ok".to_owned(),
                detail: document(json!({})),
                observed_at: TIME.to_owned(),
            })
            .expect("seed status identity collision");
        let mut admitted_run = run("fixture-a", "atomic-admitted", &profile_digest);
        admitted_run.admission_id = Some("admission-atomic-admitted".to_owned());
        let run_id = admitted_run.run_id.clone();
        let collection = fixture_collection(
            &mut store,
            admitted_run,
            Some(SubmissionInput {
                submission_id: "submission-atomic-admitted".to_owned(),
                raw_bytes: b"atomic admitted".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    "atomic-admitted",
                    &profile_digest,
                    document(json!({"fixture": "atomic-admitted"})),
                )),
            }),
        );
        let error = store
            .commit_admitted_collection(&collection, |_view, receipt| {
                let report_sequence = receipt.report_sequence.expect("pending report sequence");
                let evaluation_detail = document(json!({"result": "absent"}));
                Ok::<_, StoreError>(AdmittedCollectionCompletion {
                    value: (),
                    evaluations: vec![EvaluationCommitInput {
                        evaluation: EvaluationInput {
                            evaluation_id: "evaluation-atomic-admitted".to_owned(),
                            trigger_run_id: Some(run_id.clone()),
                            detector_id: "fixture.detector".to_owned(),
                            detector_version: "1".to_owned(),
                            detector_digest: atomic_detector.clone(),
                            evaluator_artifact_digest: atomic_evaluator.as_str().to_owned(),
                            started_at: TIME.to_owned(),
                            evaluated_at: TIME.to_owned(),
                            outcome: "condition_explicitly_absent".to_owned(),
                            detail: evaluation_detail,
                            profile: evaluation_profile(&profile_digest),
                            watermarks: vec![EvaluationWatermark {
                                instance_id: "fixture-a".to_owned(),
                                max_report_sequence: report_sequence,
                                watermark_received_at: Some(TIME.to_owned()),
                            }],
                            refusal: None,
                        },
                        finding: None,
                    }],
                    diagnostic_artifact: None,
                    status: StatusEventInput {
                        status_event_id: "status-collision".to_owned(),
                        component_kind: "instance".to_owned(),
                        component_id: "fixture-a".to_owned(),
                        state: "healthy".to_owned(),
                        code: "report_complete".to_owned(),
                        detail: document(json!({
                            "schema": "nq.collection_outcome.v2",
                            "instance_id": "fixture-a",
                            "run_id": run_id,
                            "result": {
                                "outcome": "admitted",
                                "report_id": "report-atomic-admitted",
                                "report_status": "complete",
                                "semantic_digest": receipt.semantic_digest,
                                "evaluations": [{"result": "absent"}],
                            },
                        })),
                        observed_at: TIME.to_owned(),
                    },
                })
            })
            .expect_err("late status failure rolls the admitted transaction back");
        assert!(matches!(error, StoreError::Sqlite(_)));
        for (table, column, identity) in [
            ("watcher_runs", "run_id", "run-atomic-admitted"),
            (
                "provider_intake_attempts",
                "intake_id",
                "intake-run-atomic-admitted",
            ),
            (
                "provider_intake_acknowledgments",
                "run_id",
                "run-atomic-admitted",
            ),
            (
                "raw_submissions",
                "submission_id",
                "submission-atomic-admitted",
            ),
            ("admitted_reports", "report_id", "report-atomic-admitted"),
            (
                "evaluation_runs",
                "evaluation_id",
                "evaluation-atomic-admitted",
            ),
        ] {
            let count: i64 = store
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
                    [identity],
                    |row| row.get(0),
                )
                .expect("count rolled-back admitted row");
            assert_eq!(count, 0, "{table} survived failed admitted completion");
        }
        store.validate().expect("preexisting store remains valid");
    }

    #[test]
    fn historical_reopen_rejects_reordered_admitted_evaluation_sequence() {
        let directory = tempdir().expect("temporary directory");
        let live = directory.path().join("ordered-evaluations.db");
        let backup = directory.path().join("ordered-evaluations-backup.db");
        let mut store = Store::initialize(&live).expect("ordered store initializes");
        let profile_digest = append_fixture_descriptor(&mut store);
        let first_detector = digest("ordered-detector-a");
        let second_detector = digest("ordered-detector-b");
        let evaluator = typed_digest("ordered-evaluator");
        let mut identity = fixture_identity();
        identity.detector_identity_digest =
            detector_suite_identity_digest([first_detector.as_str(), second_detector.as_str()])
                .expect("ordered detector suite identity");
        identity.evaluator_artifact_digest = evaluator.clone();
        append_fixture_admission_with_identity(
            &mut store,
            &profile_digest,
            "fixture-a",
            "admission-ordered-evaluations",
            identity,
        );

        let mut admitted_run = run("fixture-a", "ordered-evaluations", &profile_digest);
        admitted_run.admission_id = Some("admission-ordered-evaluations".to_owned());
        let run_id = admitted_run.run_id.clone();
        let collection = fixture_collection(
            &mut store,
            admitted_run,
            Some(SubmissionInput {
                submission_id: "submission-ordered-evaluations".to_owned(),
                raw_bytes: b"ordered evaluations".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    "ordered-evaluations",
                    &profile_digest,
                    document(json!({"fixture": "ordered-evaluations"})),
                )),
            }),
        );
        let first_detail = json!({
            "code": "cannot_evaluate",
            "order": "first",
            "payload": {"phase": "exchange-timeout"},
        });
        let second_detail = json!({
            "code": "cannot_evaluate",
            "order": "second",
            "payload": {"phase": "helper-collection"},
        });
        let expected_sequence = vec![first_detail.clone(), second_detail.clone()];
        store
            .commit_admitted_collection(&collection, |_view, receipt| {
                let report_sequence = receipt.report_sequence.expect("pending report sequence");
                let evaluations = [
                    ("a", first_detector.clone(), first_detail.clone()),
                    ("b", second_detector.clone(), second_detail.clone()),
                ]
                .into_iter()
                .map(|(ordinal, detector_digest, detail)| EvaluationCommitInput {
                    evaluation: EvaluationInput {
                        evaluation_id: format!("evaluation-ordered-{ordinal}"),
                        trigger_run_id: Some(run_id.clone()),
                        detector_id: format!("fixture.detector.{ordinal}"),
                        detector_version: "1".to_owned(),
                        detector_digest,
                        evaluator_artifact_digest: evaluator.as_str().to_owned(),
                        started_at: TIME.to_owned(),
                        evaluated_at: TIME.to_owned(),
                        outcome: "condition_explicitly_absent".to_owned(),
                        detail: document(detail),
                        profile: evaluation_profile(&profile_digest),
                        watermarks: vec![EvaluationWatermark {
                            instance_id: "fixture-a".to_owned(),
                            max_report_sequence: report_sequence,
                            watermark_received_at: Some(TIME.to_owned()),
                        }],
                        refusal: None,
                    },
                    finding: None,
                })
                .collect();
                Ok::<_, StoreError>(AdmittedCollectionCompletion {
                    value: (),
                    evaluations,
                    diagnostic_artifact: None,
                    status: StatusEventInput {
                        status_event_id: "status-ordered-evaluations".to_owned(),
                        component_kind: "instance".to_owned(),
                        component_id: "fixture-a".to_owned(),
                        state: "healthy".to_owned(),
                        code: "report_complete".to_owned(),
                        detail: document(json!({
                            "schema": "nq.collection_outcome.v2",
                            "instance_id": "fixture-a",
                            "run_id": run_id,
                            "result": {
                                "outcome": "admitted",
                                "report_id": "report-ordered-evaluations",
                                "report_status": "complete",
                                "semantic_digest": receipt.semantic_digest,
                                "evaluations": expected_sequence,
                            },
                        })),
                        observed_at: TIME.to_owned(),
                    },
                })
            })
            .expect("ordered admitted evaluation sequence commits");
        store.validate().expect("original sequence validates");
        store
            .backup_verified(&backup)
            .expect("ordered sequence creates a verified backup");

        let reorder = |connection: &Connection| {
            let immutable_trigger: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name = 'immutable_evaluation_runs_update'",
                    [],
                    |row| row.get(0),
                )
                .expect("read exact immutable trigger definition");
            connection
                .execute_batch(
                    "DROP TRIGGER immutable_evaluation_runs_update;
                     UPDATE evaluation_runs
                     SET evaluation_sequence = evaluation_sequence + 100
                     WHERE trigger_run_id = 'run-ordered-evaluations';
                     UPDATE evaluation_runs
                     SET evaluation_sequence = CASE evaluation_id
                         WHEN 'evaluation-ordered-a' THEN 2
                         WHEN 'evaluation-ordered-b' THEN 1
                         ELSE evaluation_sequence
                     END
                     WHERE trigger_run_id = 'run-ordered-evaluations';",
                )
                .expect("hostile writer reverses persisted sequence");
            connection
                .execute_batch(&immutable_trigger)
                .expect("restore the byte-exact immutable trigger definition");
        };

        reorder(&store.connection);
        let live_validation = store.validate();
        assert!(
            matches!(
                live_validation,
                Err(StoreError::Integrity(ref message))
                    if message.contains("exact persisted trigger sequence")
            ),
            "reordered live sequence reopened: {live_validation:?}"
        );
        drop(store);
        let live_reopen = Store::open(&live).err();
        assert!(
            matches!(
                live_reopen,
                Some(StoreError::Integrity(ref message))
                    if message.contains("exact persisted trigger sequence")
            ),
            "unexpected reordered live reopen result: {live_reopen:?}"
        );

        let hostile_backup = Connection::open(&backup).expect("open backup for hostile reorder");
        reorder(&hostile_backup);
        drop(hostile_backup);
        let backup_reopen = Store::open_immutable(&backup).err();
        assert!(
            matches!(
                backup_reopen,
                Some(StoreError::Integrity(ref message))
                    if message.contains("exact persisted trigger sequence")
            ),
            "unexpected reordered immutable backup reopen result: {backup_reopen:?}"
        );
    }

    #[test]
    fn historical_admitted_report_without_run_result_fails_closed() {
        let (mut store, profile_digest) = configured_store();
        append_fixture_admission(
            &mut store,
            &profile_digest,
            "fixture-a",
            "admission-historical-admitted",
        );
        let mut admitted_run = run("fixture-a", "historical-admitted", &profile_digest);
        admitted_run.admission_id = Some("admission-historical-admitted".to_owned());
        let collection = fixture_collection(
            &mut store,
            admitted_run,
            Some(SubmissionInput {
                submission_id: "submission-historical-admitted".to_owned(),
                raw_bytes: b"historical admitted".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    "historical-admitted",
                    &profile_digest,
                    document(json!({"fixture": "historical-admitted"})),
                )),
            }),
        );
        let transaction = store.immediate_transaction().expect("historical writer");
        insert_collection(&transaction, &collection).expect("insert historical partial chain");
        transaction
            .commit()
            .expect("commit historical partial chain");
        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("durable acknowledgment")
                    || message.contains("exactly one canonical run-linked result")
        ));
    }

    #[test]
    fn historical_reopen_rejects_omitted_admission_detector_suite() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("omitted-suite.db");
        let mut store = Store::initialize(&path).expect("historical store");
        let profile_digest = append_fixture_descriptor(&mut store);
        let required_detector = digest("historical-required-detector");
        let mut identity = fixture_identity();
        identity.detector_identity_digest =
            detector_suite_identity_digest([required_detector.as_str()])
                .expect("required detector suite identity");
        append_fixture_admission_with_identity(
            &mut store,
            &profile_digest,
            "fixture-a",
            "admission-historical-omitted-suite",
            identity,
        );
        let mut admitted_run = run("fixture-a", "historical-omitted-suite", &profile_digest);
        admitted_run.admission_id = Some("admission-historical-omitted-suite".to_owned());
        let run_id = admitted_run.run_id.clone();
        let collection = fixture_collection(
            &mut store,
            admitted_run,
            Some(SubmissionInput {
                submission_id: "submission-historical-omitted-suite".to_owned(),
                raw_bytes: b"historical omitted suite".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    "historical-omitted-suite",
                    &profile_digest,
                    document(json!({"historical": "omitted-suite"})),
                )),
            }),
        );
        let transaction = store.immediate_transaction().expect("historical writer");
        let receipt = insert_collection(&transaction, &collection).expect("historical collection");
        let status = StatusEventInput {
            status_event_id: "status-historical-omitted-suite".to_owned(),
            component_kind: "instance".to_owned(),
            component_id: "fixture-a".to_owned(),
            state: "healthy".to_owned(),
            code: "report_complete".to_owned(),
            detail: document(json!({
                "schema": "nq.collection_outcome.v2",
                "instance_id": "fixture-a",
                "run_id": run_id,
                "result": {
                    "outcome": "admitted",
                    "report_id": "report-historical-omitted-suite",
                    "report_status": "complete",
                    "semantic_digest": receipt.semantic_digest,
                    "evaluations": [],
                },
            })),
            observed_at: TIME.to_owned(),
        };
        insert_status_event(&transaction, &status, Some(&run_id))
            .expect("historical canonical result");
        insert_provider_acknowledgment(&transaction, &collection.intake, &run_id, &status)
            .expect("historical provider acknowledgment");
        transaction.commit().expect("historical partial commit");
        drop(store);

        assert!(matches!(
            Store::open(&path),
            Err(StoreError::Integrity(message))
                if message.contains("detector suite identity")
        ));
    }

    #[test]
    fn historical_reopen_rejects_substituted_admission_evaluator_artifact() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("substituted-evaluator.db");
        let mut store = Store::initialize(&path).expect("historical store");
        let profile_digest = append_fixture_descriptor(&mut store);
        let required_detector = digest("historical-evaluator-detector");
        let expected_evaluator = typed_digest("historical-expected-evaluator");
        let mut identity = fixture_identity();
        identity.detector_identity_digest =
            detector_suite_identity_digest([required_detector.as_str()])
                .expect("required detector suite identity");
        identity.evaluator_artifact_digest = expected_evaluator;
        append_fixture_admission_with_identity(
            &mut store,
            &profile_digest,
            "fixture-a",
            "admission-historical-substituted-evaluator",
            identity,
        );
        let mut admitted_run = run(
            "fixture-a",
            "historical-substituted-evaluator",
            &profile_digest,
        );
        admitted_run.admission_id = Some("admission-historical-substituted-evaluator".to_owned());
        let run_id = admitted_run.run_id.clone();
        let collection = fixture_collection(
            &mut store,
            admitted_run,
            Some(SubmissionInput {
                submission_id: "submission-historical-substituted-evaluator".to_owned(),
                raw_bytes: b"historical substituted evaluator".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    "historical-substituted-evaluator",
                    &profile_digest,
                    document(json!({"historical": "substituted-evaluator"})),
                )),
            }),
        );
        let evaluation_value = json!({"historical": "wrong-evaluator"});
        let evaluation_detail = document(evaluation_value.clone());
        let transaction = store.immediate_transaction().expect("historical writer");
        let receipt = insert_collection(&transaction, &collection).expect("historical collection");
        let report_sequence = receipt.report_sequence.expect("historical report sequence");
        transaction
            .execute(
                "INSERT INTO evaluation_runs (
                    evaluation_id, evaluation_sequence, trigger_run_id,
                    detector_id, detector_version, detector_digest,
                    evaluator_artifact_digest, profile_id, profile_version,
                    profile_digest, profile_semantic_id, evaluation_revision,
                    started_at, evaluated_at, outcome, detail_json
                 ) VALUES (?1, 1, ?2, 'fixture.detector', '1', ?3, ?4,
                           'fixture.health', '1', ?5, ?6, 1, ?7, ?7,
                           'condition_explicitly_absent', ?8)",
                params![
                    "evaluation-historical-substituted-evaluator",
                    run_id,
                    required_detector,
                    digest("historical-wrong-evaluator"),
                    profile_digest,
                    typed_digest("profile-semantic").as_str(),
                    TIME,
                    evaluation_detail.as_bytes(),
                ],
            )
            .expect("raw historical evaluation");
        transaction
            .execute(
                "INSERT INTO evaluation_watermarks (
                    evaluation_id, instance_id, max_report_sequence,
                    watermark_received_at
                 ) VALUES ('evaluation-historical-substituted-evaluator',
                           'fixture-a', ?1, ?2)",
                params![report_sequence, TIME],
            )
            .expect("raw historical evaluation watermark");
        let status = StatusEventInput {
            status_event_id: "status-historical-substituted-evaluator".to_owned(),
            component_kind: "instance".to_owned(),
            component_id: "fixture-a".to_owned(),
            state: "healthy".to_owned(),
            code: "report_complete".to_owned(),
            detail: document(json!({
                "schema": "nq.collection_outcome.v2",
                "instance_id": "fixture-a",
                "run_id": run_id,
                "result": {
                    "outcome": "admitted",
                    "report_id": "report-historical-substituted-evaluator",
                    "report_status": "complete",
                    "semantic_digest": receipt.semantic_digest,
                    "evaluations": [evaluation_value],
                },
            })),
            observed_at: TIME.to_owned(),
        };
        insert_status_event(&transaction, &status, Some(&run_id))
            .expect("historical canonical result");
        insert_provider_acknowledgment(&transaction, &collection.intake, &run_id, &status)
            .expect("historical provider acknowledgment");
        transaction.commit().expect("historical partial commit");
        drop(store);

        assert!(matches!(
            Store::open(&path),
            Err(StoreError::Integrity(message))
                if message.contains("uses evaluator artifact")
        ));
    }

    #[test]
    fn historical_partial_evaluation_set_cannot_reopen_as_admitted_result() {
        let (mut store, profile_digest) = configured_store();
        let receipt = commit_admitted(
            &mut store,
            "fixture-a",
            "historical-partial-evaluation",
            &profile_digest,
            document(json!({"fixture": "historical-partial-evaluation"})),
            b"historical partial evaluation".to_vec(),
        );
        let report_sequence = receipt.report_sequence.expect("report sequence");
        store
            .connection
            .execute(
                "INSERT INTO evaluation_runs (
                    evaluation_id, evaluation_sequence, trigger_run_id,
                    detector_id, detector_version, detector_digest,
                    evaluator_artifact_digest, profile_id, profile_version,
                    profile_digest, profile_semantic_id, evaluation_revision,
                    started_at, evaluated_at, outcome, detail_json
                 ) VALUES (?1, 1, ?2, ?3, '1', ?4, ?5, 'fixture.health', '1',
                           ?6, ?7, 1, ?8, ?8, 'condition_explicitly_absent', ?9)",
                params![
                    "evaluation-historical-partial",
                    "run-historical-partial-evaluation",
                    "fixture.detector",
                    digest("historical-partial-detector"),
                    digest("historical-partial-evaluator"),
                    profile_digest,
                    typed_digest("profile-semantic").as_str(),
                    TIME,
                    document(json!({"result": "unsealed-late-evaluation"})).as_bytes(),
                ],
            )
            .expect("historical writer appends a late evaluation");
        store
            .connection
            .execute(
                "INSERT INTO evaluation_watermarks (
                    evaluation_id, instance_id, max_report_sequence,
                    watermark_received_at
                 ) VALUES (?1, 'fixture-a', ?2, ?3)",
                params!["evaluation-historical-partial", report_sequence, TIME],
            )
            .expect("historical writer appends the late watermark");
        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("detector suite identity")
        ));
    }

    /// Release regression: a historical/raw writer cannot append rejected
    /// custody without the typed testimony required for reopening.
    #[test]
    fn forcing_rejected_submission_requires_typed_refusal() {
        let (mut store, profile_digest) = configured_store();
        let raw = b"malformed helper response\n";
        append_historical_run_with_result(
            &mut store,
            &run("fixture-a", "missing-refusal", &profile_digest),
        );
        store
            .connection
            .execute(
                "INSERT INTO raw_submissions (
                    submission_id, run_id, raw_bytes, raw_sha256, received_at,
                    protocol_outcome, admission_outcome, rejection_code
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'rejected', ?7)",
                params![
                    "submission-missing-refusal",
                    "run-missing-refusal",
                    raw,
                    sha256_digest(raw),
                    TIME,
                    "rejected",
                    "invalid_response",
                ],
            )
            .expect("physical schema permits the historical hostile row");
        let result = store.validate();
        assert!(
            matches!(
                result,
                Err(StoreError::Integrity(ref message))
                    if message.contains("typed refusal")
            ),
            "rejected custody without typed refusal reopened: {result:?}"
        );
    }

    #[test]
    fn same_code_refusal_payloads_and_links_survive_backup_and_reopen() {
        let directory = tempdir().expect("temp dir");
        let live = directory.path().join("live.db");
        let backup = directory.path().join("backup.db");
        let mut store = Store::initialize(&live).expect("store initializes");
        let profile_digest = append_fixture_descriptor(&mut store);

        let transient_detail = document(json!({
            "responsible_instance_id": "fixture-a",
            "boundary": "collection",
            "code": "collection_failed",
            "message": "backend collection failed",
            "retriable": true,
            "details": {"attempt": 1, "errno": "EAGAIN"},
        }));
        let permanent_detail = document(json!({
            "responsible_instance_id": "fixture-a",
            "boundary": "collection",
            "code": "collection_failed",
            "message": "backend collection failed",
            "retriable": false,
            "details": {"device": "nvme0", "errno": "ENODEV"},
        }));
        let transient = commit_rejected(
            &mut store,
            "a-transient",
            &profile_digest,
            "refusal-transient",
            "collection_failed",
            transient_detail,
        );
        let permanent = commit_rejected(
            &mut store,
            "b-permanent",
            &profile_digest,
            "refusal-permanent",
            "collection_failed",
            permanent_detail,
        );
        assert_eq!(transient.refusal_id.as_deref(), Some("refusal-transient"));
        assert_eq!(permanent.refusal_id.as_deref(), Some("refusal-permanent"));

        let live_rows = store.rejected_custody(10).expect("enumerate live custody");
        assert_eq!(live_rows.len(), 2);
        assert_eq!(live_rows[0].code, live_rows[1].code);
        assert_eq!(live_rows[0].code, "collection_failed");
        assert_ne!(live_rows[0].refusal_id, live_rows[1].refusal_id);
        assert_ne!(live_rows[0].detail_json, live_rows[1].detail_json);
        let first: Value = serde_json::from_slice(&live_rows[0].detail_json).expect("first detail");
        let second: Value =
            serde_json::from_slice(&live_rows[1].detail_json).expect("second detail");
        assert_eq!(first["retriable"], true);
        assert_eq!(second["retriable"], false);
        assert_eq!(first["details"]["errno"], "EAGAIN");
        assert_eq!(second["details"]["errno"], "ENODEV");

        let first_page = store
            .rejected_custody_bounded(1, None)
            .expect("first custody page");
        assert_eq!(first_page, live_rows[..1]);
        let second_page = store
            .rejected_custody_bounded(1, Some(&first_page[0].submission_id))
            .expect("second custody page");
        assert_eq!(second_page, live_rows[1..]);
        assert!(
            store
                .rejected_custody_bounded(1, Some(&second_page[0].submission_id))
                .expect("custody exhausted")
                .is_empty()
        );

        store.backup_verified(&backup).expect("verified backup");
        drop(store);
        let reopened = Store::open(&backup).expect("backup reopens");
        assert_eq!(
            reopened.rejected_custody(10).expect("reopened custody"),
            live_rows
        );
        assert_eq!(
            reopened
                .raw_submission_bytes("submission-a-transient")
                .expect("reopened raw bytes"),
            Some(b"raw-a-transient\n".to_vec())
        );
    }

    #[test]
    fn refusal_linkage_validation_rejects_duplicate_and_admitted_links() {
        let (mut duplicate, profile_digest) = configured_store();
        commit_rejected(
            &mut duplicate,
            "duplicate",
            &profile_digest,
            "refusal-first",
            "collection_failed",
            document(json!({"details": {"attempt": 1}, "retriable": true})),
        );
        duplicate
            .connection
            .execute(
                "INSERT INTO refusals (
                    refusal_id, source_kind, responsible_instance_id, boundary,
                    code, run_id, submission_id, evaluation_id, profile_id,
                    profile_version, profile_digest, detail_json, created_at
                 ) VALUES (?1, 'protocol', 'fixture-a', 'collection',
                           'collection_failed', 'run-duplicate',
                           'submission-duplicate', NULL, 'fixture.health', '1',
                           ?2, ?3, ?4)",
                params![
                    "refusal-second",
                    profile_digest,
                    br#"{"details":{"attempt":2},"retriable":false}"#,
                    TIME,
                ],
            )
            .expect("physical schema permits duplicate historical linkage");
        assert!(matches!(
            duplicate.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("exactly one typed refusal") && message.contains("found 2")
        ));

        let (mut admitted, admitted_profile_digest) = configured_store();
        commit_admitted(
            &mut admitted,
            "fixture-a",
            "admitted-link",
            &admitted_profile_digest,
            document(json!({"report": "admitted-link"})),
            b"admitted bytes".to_vec(),
        );
        admitted
            .connection
            .execute(
                "INSERT INTO refusals (
                    refusal_id, source_kind, responsible_instance_id, boundary,
                    code, run_id, submission_id, evaluation_id, profile_id,
                    profile_version, profile_digest, detail_json, created_at
                 ) VALUES (?1, 'protocol', 'fixture-a', 'collection',
                           'collection_failed', 'run-admitted-link',
                           'submission-admitted-link', NULL, 'fixture.health', '1',
                           ?2, ?3, ?4)",
                params![
                    "refusal-on-admitted",
                    admitted_profile_digest,
                    br#"{"details":{},"retriable":false}"#,
                    TIME,
                ],
            )
            .expect("physical schema permits hostile admitted linkage");
        assert!(matches!(
            admitted.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("admitted custody") && message.contains("typed refusal")
        ));
    }

    #[test]
    fn historical_refusal_mismatches_and_noncanonical_detail_fail_closed() {
        for defect in [
            HistoricalRefusalDefect::WrongRun,
            HistoricalRefusalDefect::WrongInstance,
            HistoricalRefusalDefect::WrongProfileId,
            HistoricalRefusalDefect::WrongProfileVersion,
            HistoricalRefusalDefect::WrongProfileDigest,
            HistoricalRefusalDefect::WrongCode,
        ] {
            let store = historical_rejection_with(defect);
            assert!(matches!(
                store.validate(),
                Err(StoreError::Integrity(message)) if message.contains("does not match")
            ));
        }

        let noncanonical = historical_rejection_with(HistoricalRefusalDefect::NonCanonicalDetail);
        assert!(matches!(
            noncanonical.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("not exact canonical JSON")
        ));
    }

    #[test]
    fn unknown_profile_submission_remains_queryable_quarantine() {
        let (mut store, profile_digest) = configured_store();
        let bound_run = bound_fixture_run(&mut store, "fixture-a", "unknown", &profile_digest);
        let collection = fixture_collection(
            &mut store,
            bound_run,
            Some(SubmissionInput {
                submission_id: "submission-unknown".to_owned(),
                raw_bytes: b"{\"claimed_profile\":\"unknown.profile\"}\n".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Rejected {
                    refusal: RefusalInput {
                        refusal_id: "refusal-unknown".to_owned(),
                        // An unknown profile has no compiled profile
                        // semantic identity; retain it as upstream protocol
                        // quarantine rather than inventing profile meaning.
                        source_kind: "protocol".to_owned(),
                        responsible_instance_id: "fixture-a".to_owned(),
                        boundary: "profile_registry".to_owned(),
                        code: "unknown_profile".to_owned(),
                        profile_semantic_id: None,
                        detail: document(json!({"profile_id": "unknown.profile"})),
                        created_at: TIME.to_owned(),
                    },
                },
            }),
        );
        let result = non_success_status(&collection.run.run_id, "fixture-a", "unknown");
        committed_parts(
            store
                .commit_non_success_collection(&collection, &result)
                .expect("unknown claimed profile is retained as rejected custody"),
        );
        assert!(
            store
                .raw_submission_bytes("submission-unknown")
                .expect("query")
                .is_some()
        );
        assert_eq!(
            store
                .report_id_for_submission("submission-unknown")
                .expect("query"),
            None
        );
    }

    #[test]
    fn canonical_digest_is_stable_across_object_key_order() {
        let first = CanonicalDocument::from_serializable(&json!({
            "z": {"b": 2, "a": 1}, "a": [3, 2, 1]
        }))
        .expect("canonical document");
        let second = CanonicalDocument::from_serializable(&json!({
            "a": [3, 2, 1], "z": {"a": 1, "b": 2}
        }))
        .expect("canonical document");
        assert_eq!(first, second);
        assert!(CanonicalDocument::from_canonical_bytes(br#"{"z":1,"a":2}"#.to_vec()).is_err());
    }

    #[test]
    fn same_profile_instances_remain_distinct_and_renewal_is_immutable() {
        let (mut store, profile_digest) = configured_store();
        let semantic = document(json!({"status": "healthy"}));
        let first = commit_admitted(
            &mut store,
            "fixture-a",
            "a-1",
            &profile_digest,
            semantic.clone(),
            b"first raw response\n".to_vec(),
        );
        let renewal = commit_admitted(
            &mut store,
            "fixture-a",
            "a-2",
            &profile_digest,
            semantic,
            b"second raw response\n".to_vec(),
        );
        commit_admitted(
            &mut store,
            "fixture-b",
            "b-1",
            &profile_digest,
            document(json!({"status": "healthy"})),
            b"third raw response\n".to_vec(),
        );
        assert_eq!(first.semantic_digest, renewal.semantic_digest);
        assert_ne!(first.report_sequence, renewal.report_sequence);

        let snapshot = store
            .evidence_snapshot(&["fixture-a".to_owned(), "fixture-b".to_owned()])
            .expect("evidence snapshot");
        assert_eq!(snapshot.reports.len(), 3);
        assert_eq!(
            snapshot
                .reports
                .iter()
                .filter(|report| report.instance_id == "fixture-a")
                .count(),
            2
        );
        assert!(
            store
                .connection
                .execute(
                    "UPDATE admitted_reports SET observed_at = ?1 WHERE report_id = 'report-a-1'",
                    ["2099-01-01T00:00:00Z"],
                )
                .is_err()
        );
    }

    #[test]
    fn stale_refusal_retains_active_condition_and_evidence_until_explicit_resolution() {
        let (mut store, profile_digest) = configured_store();
        let collection = commit_admitted(
            &mut store,
            "fixture-a",
            "finding",
            &profile_digest,
            document(json!({"status": "unhealthy"})),
            b"unhealthy\n".to_vec(),
        );
        let snapshot = store
            .evidence_snapshot(&["fixture-a".to_owned()])
            .expect("snapshot");
        let report_digest = collection.semantic_digest.expect("semantic digest");
        let evaluation = EvaluationInput {
            evaluation_id: "evaluation-open".to_owned(),
            trigger_run_id: None,
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "condition_present".to_owned(),
            detail: document(json!({})),
            profile: evaluation_profile(&profile_digest),
            watermarks: snapshot.watermarks.clone(),
            refusal: None,
        };
        let opened = FindingEventInput {
            event_id: "event-open".to_owned(),
            finding_id: "finding-opaque".to_owned(),
            event_kind: "opened".to_owned(),
            instance_id: "fixture-a".to_owned(),
            profile_id: "fixture.health".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.clone(),
            subject: document(json!({"fixture": "finding"})),
            condition_name: "fixture.unhealthy".to_owned(),
            condition_state: "present".to_owned(),
            visibility_state: "sufficient".to_owned(),
            operator_work_state: "unacknowledged".to_owned(),
            severity: "warning".to_owned(),
            summary: "Fixture is unhealthy".to_owned(),
            limitations: document(json!([])),
            safe_next_checks: document(json!(["inspect fixture"])),
            freshness: document(json!({"state": "current"})),
            basis: document(json!({"profile": "fixture.health"})),
            refusal: None,
            origin_mode: "native".to_owned(),
            historical_refs: document(json!([])),
            observed_at: Some(TIME.to_owned()),
            received_at: Some(TIME.to_owned()),
            created_at: TIME.to_owned(),
            evidence: vec![FindingEvidenceInput {
                ordinal: 0,
                report_id: "report-finding".to_owned(),
                report_semantic_digest: report_digest.clone(),
                observation_ordinal: Some(0),
                observed_at: TIME.to_owned(),
                received_at: TIME.to_owned(),
            }],
        };
        let opened_receipt = store
            .commit_evaluation(&evaluation, Some(&opened))
            .expect("finding opens");
        assert_eq!(opened_receipt.evaluation_revision, 1);

        let mut substituted_semantics = evaluation.clone();
        substituted_semantics.evaluation_id = "evaluation-substituted-semantics".to_owned();
        substituted_semantics.profile.profile_semantic_id = typed_digest("other-semantics");
        let mut substituted_lineage = opened.clone();
        substituted_lineage.event_id = "event-substituted-semantics".to_owned();
        substituted_lineage.event_kind = "updated".to_owned();
        let error = store
            .commit_evaluation(&substituted_semantics, Some(&substituted_lineage))
            .expect_err("same descriptor with different semantics cannot reuse a finding");
        assert!(matches!(error, StoreError::Invariant(message)
            if message.contains("immutable detector, profile, subject, or condition lineage")));

        let stale_refusal = document(json!({
            "boundary": "detector",
            "code": "evidence_stale",
            "responsible_instance_id": "fixture-a"
        }));
        let refused_evaluation = EvaluationInput {
            evaluation_id: "evaluation-refused".to_owned(),
            trigger_run_id: None,
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "cannot_evaluate".to_owned(),
            detail: document(json!({})),
            profile: evaluation_profile(&profile_digest),
            watermarks: snapshot.watermarks.clone(),
            refusal: Some(RefusalInput {
                refusal_id: "evaluation-refusal".to_owned(),
                source_kind: "profile".to_owned(),
                responsible_instance_id: "fixture-a".to_owned(),
                boundary: "detector".to_owned(),
                code: "evidence_stale".to_owned(),
                profile_semantic_id: Some(typed_digest("profile-semantic").into_string()),
                detail: stale_refusal.clone(),
                created_at: TIME.to_owned(),
            }),
        };
        let mut stale_update = opened.clone();
        stale_update.event_id = "event-stale".to_owned();
        stale_update.event_kind = "updated".to_owned();
        stale_update.visibility_state = "stale".to_owned();
        stale_update.freshness = document(json!({"state": "stale"}));
        stale_update.refusal = Some(stale_refusal);
        let mut substituted_condition = stale_update.clone();
        substituted_condition.event_id = "event-substituted-condition".to_owned();
        substituted_condition.condition_state = "explicitly_absent".to_owned();
        let error = store
            .commit_evaluation(&refused_evaluation, Some(&substituted_condition))
            .expect_err("a refusal cannot substitute prior condition state");
        assert!(matches!(error, StoreError::Invariant(message)
            if message.contains("retain the prior finding condition state")));

        let mut sufficient_refusal = stale_update.clone();
        sufficient_refusal.event_id = "event-sufficient-refusal".to_owned();
        sufficient_refusal.visibility_state = "sufficient".to_owned();
        let error = store
            .commit_evaluation(&refused_evaluation, Some(&sufficient_refusal))
            .expect_err("a refusal cannot claim sufficient visibility");
        assert!(matches!(error, StoreError::Invariant(message)
            if message.contains("cannot claim sufficient")));

        let stale_receipt = store
            .commit_evaluation(&refused_evaluation, Some(&stale_update))
            .expect("staleness updates visibility without negating the condition");
        assert_eq!(stale_receipt.evaluation_revision, 2);

        let stale_public = store.finding_snapshots().expect("public view");
        assert_eq!(stale_public.len(), 1);
        assert_eq!(stale_public[0].condition_name, "fixture.unhealthy");
        assert_eq!(stale_public[0].condition_state, "present");
        assert_eq!(stale_public[0].visibility_state, "stale");
        assert!(stale_public[0].refusal_json.is_some());
        let stale_evidence: serde_json::Value =
            serde_json::from_str(&stale_public[0].evidence_json).expect("evidence JSON");
        assert_eq!(stale_evidence.as_array().map(Vec::len), Some(1));
        assert_eq!(stale_evidence[0]["report_id"], "report-finding");
        assert_eq!(stale_evidence[0]["semantic_digest"], report_digest);
        assert_eq!(stale_evidence[0]["observation_ordinal"], 0);

        let resolution_refusal = document(json!({
            "boundary": "detector",
            "code": "evidence_stale",
            "responsible_instance_id": "fixture-a",
            "attempt": "resolution"
        }));
        let refused_resolution_evaluation = EvaluationInput {
            evaluation_id: "evaluation-refused-resolution".to_owned(),
            trigger_run_id: None,
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "cannot_evaluate".to_owned(),
            detail: document(json!({})),
            profile: evaluation_profile(&profile_digest),
            watermarks: snapshot.watermarks.clone(),
            refusal: Some(RefusalInput {
                refusal_id: "evaluation-refusal-resolution".to_owned(),
                source_kind: "profile".to_owned(),
                responsible_instance_id: "fixture-a".to_owned(),
                boundary: "detector".to_owned(),
                code: "evidence_stale".to_owned(),
                profile_semantic_id: Some(typed_digest("profile-semantic").into_string()),
                detail: resolution_refusal.clone(),
                created_at: TIME.to_owned(),
            }),
        };
        let mut invalid_resolution = stale_update.clone();
        invalid_resolution.event_id = "event-invalid-resolution".to_owned();
        invalid_resolution.event_kind = "resolved".to_owned();
        invalid_resolution.condition_state = "explicitly_absent".to_owned();
        invalid_resolution.visibility_state = "sufficient".to_owned();
        invalid_resolution.refusal = Some(resolution_refusal);
        let error = store
            .commit_evaluation(&refused_resolution_evaluation, Some(&invalid_resolution))
            .expect_err("a refusal cannot resolve an active finding");
        assert!(matches!(error, StoreError::Invariant(message)
            if message.contains("only explicit absence")));
        let after_refusal = store.finding_snapshots().expect("public view");
        assert_eq!(after_refusal[0].condition_state, "present");
        assert_eq!(after_refusal[0].visibility_state, "stale");
        assert_eq!(
            after_refusal[0].evidence_json,
            stale_public[0].evidence_json
        );

        let absence = EvaluationInput {
            evaluation_id: "evaluation-resolve".to_owned(),
            trigger_run_id: None,
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "condition_explicitly_absent".to_owned(),
            detail: document(json!({})),
            profile: evaluation_profile(&profile_digest),
            watermarks: snapshot.watermarks,
            refusal: None,
        };
        let mut resolved = stale_update;
        resolved.event_id = "event-resolved".to_owned();
        resolved.event_kind = "resolved".to_owned();
        resolved.condition_state = "explicitly_absent".to_owned();
        resolved.visibility_state = "sufficient".to_owned();
        resolved.freshness = document(json!({"state": "current"}));
        resolved.refusal = None;
        let resolved_receipt = store
            .commit_evaluation(&absence, Some(&resolved))
            .expect("sufficient explicit absence resolves");
        assert_eq!(
            resolved_receipt.evaluation_revision, 3,
            "the failed transaction must not consume a durable revision"
        );
        let public = store.finding_snapshots().expect("public view");
        assert_eq!(public.len(), 1);
        assert_eq!(public[0].condition_state, "explicitly_absent");
        assert_eq!(public[0].visibility_state, "sufficient");
        assert!(public[0].refusal_json.is_none());
        assert_eq!(public[0].finding_id, "finding-opaque");

        let event_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM finding_events", [], |row| row.get(0))
            .expect("event count");
        assert_eq!(event_count, 3);
        let event_revisions: Vec<i64> = store
            .connection
            .prepare(
                "SELECT event_revision FROM finding_events
                 WHERE finding_id = 'finding-opaque'
                 ORDER BY event_revision",
            )
            .expect("prepare event revision query")
            .query_map([], |row| row.get(0))
            .expect("query event revisions")
            .collect::<Result<_, _>>()
            .expect("read event revisions");
        assert_eq!(event_revisions, vec![1, 2, 3]);

        let mut historical_evaluation = absence;
        historical_evaluation.evaluation_id = "evaluation-hostile-lineage".to_owned();
        let historical_receipt = store
            .commit_evaluation(&historical_evaluation, None)
            .expect("append evaluation for hostile historical event");
        assert_eq!(historical_receipt.evaluation_revision, 4);
        store
            .connection
            .execute(
                "INSERT INTO finding_events (
                    event_id, finding_id, event_revision, event_kind, evaluation_id,
                    instance_id, detector_id, detector_version, detector_digest,
                    evaluator_artifact_digest, evaluation_revision, profile_id,
                    profile_version, profile_digest, subject_json, condition_name,
                    condition_state, visibility_state, operator_work_state, severity,
                    summary, limitations_json, safe_next_checks_json, freshness_json,
                    basis_json, refusal_json, origin_mode, historical_refs_json,
                    observed_at, received_at, evaluated_at, created_at
                 )
                 SELECT 'event-hostile-lineage', finding_id, 4, 'updated',
                        'evaluation-hostile-lineage', instance_id, detector_id,
                        detector_version, detector_digest, evaluator_artifact_digest,
                        4, profile_id, profile_version, profile_digest,
                        CAST('{\"fixture\":\"substituted\"}' AS BLOB), condition_name,
                        condition_state, visibility_state, operator_work_state, severity,
                        summary, limitations_json, safe_next_checks_json, freshness_json,
                        basis_json, refusal_json, origin_mode, historical_refs_json,
                        observed_at, received_at, evaluated_at, created_at
                 FROM finding_events WHERE event_id = 'event-resolved'",
                [],
            )
            .expect("schema permits hostile historical lineage for validator regression");
        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("substitutes immutable finding lineage")
        ));
    }

    #[test]
    fn status_history_is_append_only_while_public_projection_advances() {
        let (mut store, _) = configured_store();
        for (event, state) in [("status-1", "starting"), ("status-2", "healthy")] {
            store
                .record_status(&StatusEventInput {
                    status_event_id: event.to_owned(),
                    component_kind: "database".to_owned(),
                    component_id: "primary".to_owned(),
                    state: state.to_owned(),
                    code: "ok".to_owned(),
                    detail: document(json!({})),
                    observed_at: TIME.to_owned(),
                })
                .expect("status event appends");
        }
        let status = store.status_snapshots().expect("status view");
        assert_eq!(status[0].state, "healthy");
        let first_page = store
            .status_history_bounded(1, None)
            .expect("first history page");
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].status_event_id, "status-1");
        assert_eq!(first_page[0].state, "starting");
        let second_page = store
            .status_history_bounded(1, Some(first_page[0].status_sequence))
            .expect("second history page");
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].status_event_id, "status-2");
        assert_eq!(second_page[0].state, "healthy");
        assert!(
            store
                .status_history_bounded(1, Some(second_page[0].status_sequence))
                .expect("history exhausted")
                .is_empty()
        );
        assert!(matches!(
            store.status_history_bounded(1, Some(-1)),
            Err(StoreError::Invariant(_))
        ));
        assert!(matches!(
            store.status_snapshots_bounded(MAX_PUBLIC_QUERY_ROWS + 1, None),
            Err(StoreError::Invariant(_))
        ));
        let event_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM status_events", [], |row| row.get(0))
            .expect("count");
        assert_eq!(event_count, 2);

        store
            .connection
            .execute(
                "UPDATE status_current SET latest_status_event_id = 'status-1'",
                [],
            )
            .expect("test damages projection");
        assert!(matches!(store.validate(), Err(StoreError::Integrity(_))));
        store
            .rebuild_current_projections()
            .expect("projection rebuilds from events");
        assert_eq!(
            store.status_snapshots().expect("rebuilt view")[0].state,
            "healthy"
        );
    }

    #[test]
    fn binding_event_and_recovery_intent_are_atomic_and_survive_process_restart() {
        let directory = tempdir().expect("temp dir");
        let database = directory.path().join("binding.db");
        let mut store = Store::initialize(&database).expect("initialize");
        let descriptor = document(json!({
            "profile_id": "fixture.health",
            "profile_version": "1",
        }));
        let profile_digest = descriptor.digest().to_owned();
        store
            .append_profile_descriptor(&ProfileDescriptorInput {
                profile_id: "fixture.health".to_owned(),
                profile_version: "1".to_owned(),
                descriptor,
                recorded_at: TIME.to_owned(),
            })
            .expect("descriptor");
        append_fixture_admission(&mut store, &profile_digest, "fixture-a", ADMISSION_A);

        let event = BindingEventInput {
            binding_event_id: BINDING_A.to_owned(),
            instance_id: "fixture-a".to_owned(),
            event_kind: "activate".to_owned(),
            admission_id: Some(ADMISSION_A.to_owned()),
            binding_digest: digest("binding-a"),
            occurred_at: TIME.to_owned(),
            reason_code: Some("test".to_owned()),
            detail: document(json!({})),
        };
        let mut intent = BindingMaterializationInput {
            materialization_event_id: INTENT_A.to_owned(),
            operation_id: OPERATION_A.to_owned(),
            instance_id: "fixture-a".to_owned(),
            binding_event_id: BINDING_A.to_owned(),
            phase: "intent".to_owned(),
            occurred_at: TIME.to_owned(),
            detail: document(json!({"desired": "active"})),
        };

        let mut mismatched = intent.clone();
        mismatched.binding_event_id = BINDING_B.to_owned();
        assert!(matches!(
            store.begin_binding_transition(&event, &mismatched),
            Err(StoreError::Invariant(_))
        ));
        let mut malformed_id = intent.clone();
        malformed_id.materialization_event_id = "not-a-uuid".to_owned();
        assert!(matches!(
            store.begin_binding_transition(&event, &malformed_id),
            Err(StoreError::Invariant(_))
        ));
        let mut unsafe_instance = intent.clone();
        unsafe_instance.instance_id = "../escape".to_owned();
        assert!(matches!(
            store.begin_binding_transition(&event, &unsafe_instance),
            Err(StoreError::Invariant(_))
        ));
        let mut malformed_time = intent.clone();
        malformed_time.occurred_at = "not-rfc3339".to_owned();
        assert!(matches!(
            store.begin_binding_transition(&event, &malformed_time),
            Err(StoreError::Invariant(_))
        ));
        assert!(store.latest_binding("fixture-a").expect("latest").is_none());

        store
            .begin_binding_transition(&event, &intent)
            .expect("binding and intent commit together");
        assert_eq!(
            store
                .latest_binding("fixture-a")
                .expect("latest")
                .expect("binding")
                .binding_event_id,
            BINDING_A
        );
        assert!(
            store
                .pending_binding_materialization("fixture-a")
                .expect("pending")
                .is_some()
        );

        // Simulate process death after the authoritative DB transaction but
        // before filesystem materialization/completion.
        drop(store);
        let mut recovered = Store::open(&database).expect("restart opens store");
        let pending = recovered
            .pending_binding_materialization("fixture-a")
            .expect("pending query")
            .expect("intent survives restart");
        assert_eq!(pending.operation_id, OPERATION_A);

        // A hostile second mutation cannot overtake the unfinished one.
        let second_event = BindingEventInput {
            binding_event_id: BINDING_B.to_owned(),
            ..event.clone()
        };
        intent.materialization_event_id = INTENT_B.to_owned();
        intent.operation_id = OPERATION_B.to_owned();
        intent.binding_event_id = BINDING_B.to_owned();
        assert!(matches!(
            recovered.begin_binding_transition(&second_event, &intent),
            Err(StoreError::Invariant(message)) if message.contains("pending")
        ));
        assert_eq!(
            recovered
                .latest_binding("fixture-a")
                .expect("latest")
                .expect("binding")
                .binding_event_id,
            BINDING_A,
            "rejected overtaking transition must not partially append"
        );

        recovered
            .complete_binding_materialization(&BindingMaterializationInput {
                materialization_event_id: COMPLETE_A.to_owned(),
                operation_id: OPERATION_A.to_owned(),
                instance_id: "fixture-a".to_owned(),
                binding_event_id: BINDING_A.to_owned(),
                phase: "completed".to_owned(),
                occurred_at: TIME.to_owned(),
                detail: document(json!({"durable": true})),
            })
            .expect("completion appends");
        assert!(
            recovered
                .pending_binding_materialization("fixture-a")
                .expect("pending after completion")
                .is_none()
        );
        for mutation in [
            "UPDATE binding_materialization_events SET occurred_at = 'forged'",
            "DELETE FROM binding_materialization_events",
        ] {
            let error = recovered
                .connection
                .execute(mutation, [])
                .expect_err("materialization history is append-only");
            assert!(error.to_string().contains("append-only table"));
        }
        let oversized = BindingMaterializationInput {
            materialization_event_id: OVERSIZED.to_owned(),
            operation_id: OPERATION_A.to_owned(),
            instance_id: "fixture-a".to_owned(),
            binding_event_id: BINDING_A.to_owned(),
            phase: "completed".to_owned(),
            occurred_at: TIME.to_owned(),
            detail: document(json!("x".repeat(MAX_BINDING_MATERIALIZATION_BYTES + 1))),
        };
        assert!(matches!(
            recovered.complete_binding_materialization(&oversized),
            Err(StoreError::Invariant(message)) if message.contains("materialization detail")
        ));
    }

    #[test]
    fn checkpoint_lookup_is_isolated_by_exact_contract_digest() {
        let (mut store, profile_digest) = configured_store();
        for (suffix, contract, cursor) in [
            ("contract-a", digest("contract-a"), "cursor-a"),
            ("contract-b", digest("contract-b"), "cursor-b"),
        ] {
            let admission_id = format!("admission-{suffix}");
            append_fixture_admission(&mut store, &profile_digest, "fixture-a", &admission_id);
            let mut run = run("fixture-a", suffix, &profile_digest);
            run.checkpoint_contract_digest = contract;
            run.admission_id = Some(admission_id);
            let mut admitted = report(
                "fixture-a",
                suffix,
                &profile_digest,
                document(json!({"report": suffix})),
            );
            admitted.next_checkpoint = Some(document(json!({"cursor": cursor})));
            let collection = fixture_collection(
                &mut store,
                run,
                Some(SubmissionInput {
                    submission_id: format!("submission-{suffix}"),
                    raw_bytes: suffix.as_bytes().to_vec(),
                    received_at: TIME.to_owned(),
                    protocol_outcome: "valid_report".to_owned(),
                    disposition: SubmissionDisposition::Admitted(admitted),
                }),
            );
            commit_admitted_fixture(&mut store, collection).expect("admitted checkpoint");
        }

        let cursor_a: Value = serde_json::from_slice(
            &store
                .latest_checkpoint("fixture-a", &digest("contract-a"))
                .expect("query a")
                .expect("cursor a"),
        )
        .expect("decode a");
        let cursor_b: Value = serde_json::from_slice(
            &store
                .latest_checkpoint("fixture-a", &digest("contract-b"))
                .expect("query b")
                .expect("cursor b"),
        )
        .expect("decode b");
        assert_eq!(cursor_a, json!({"cursor": "cursor-a"}));
        assert_eq!(cursor_b, json!({"cursor": "cursor-b"}));
        assert!(
            store
                .latest_checkpoint("fixture-a", &digest("unknown-contract"))
                .expect("unknown query")
                .is_none()
        );
    }

    #[test]
    fn acknowledgment_insert_failure_rolls_back_checkpoint_and_complete_intake() {
        let (mut store, profile_digest) = configured_store();
        let admission_id = "admission-ack-checkpoint-rollback";
        append_fixture_admission(&mut store, &profile_digest, "fixture-a", admission_id);
        let mut run = run("fixture-a", "ack-checkpoint-rollback", &profile_digest);
        run.admission_id = Some(admission_id.to_owned());
        let checkpoint_contract = run.checkpoint_contract_digest.clone();
        let mut admitted = report(
            "fixture-a",
            "ack-checkpoint-rollback",
            &profile_digest,
            document(json!({"report": "ack-checkpoint-rollback"})),
        );
        admitted.next_checkpoint = Some(document(json!({"cursor": "must-not-advance"})));
        let collection = fixture_collection(
            &mut store,
            run,
            Some(SubmissionInput {
                submission_id: "submission-ack-checkpoint-rollback".to_owned(),
                raw_bytes: b"ack-checkpoint-rollback".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(admitted),
            }),
        );
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER hostile_acknowledgment_insert_failure
                 BEFORE INSERT ON provider_intake_acknowledgments
                 BEGIN
                   SELECT RAISE(ABORT, 'hostile acknowledgment insert failure');
                 END;",
            )
            .expect("install hostile acknowledgment trigger");

        let error = commit_admitted_fixture(&mut store, collection)
            .expect_err("an acknowledgment failure must abort the admitted commit");
        assert!(
            error
                .to_string()
                .contains("hostile acknowledgment insert failure"),
            "unexpected acknowledgment failure: {error}"
        );
        assert!(
            store
                .latest_checkpoint("fixture-a", &checkpoint_contract)
                .expect("checkpoint lookup after rollback")
                .is_none(),
            "checkpoint became visible without a durable acknowledgment"
        );
        for (table, column, identity) in [
            (
                "provider_intake_attempts",
                "intake_id",
                "intake-run-ack-checkpoint-rollback",
            ),
            ("watcher_runs", "run_id", "run-ack-checkpoint-rollback"),
            (
                "raw_submissions",
                "submission_id",
                "submission-ack-checkpoint-rollback",
            ),
            (
                "admitted_reports",
                "report_id",
                "report-ack-checkpoint-rollback",
            ),
            (
                "provider_intake_acknowledgments",
                "run_id",
                "run-ack-checkpoint-rollback",
            ),
        ] {
            let count: i64 = store
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
                    [identity],
                    |row| row.get(0),
                )
                .expect("count rolled-back acknowledged collection row");
            assert_eq!(count, 0, "{table} survived acknowledgment failure");
        }
    }

    #[test]
    fn schema_shape_and_backup_are_verified() {
        let directory = tempdir().expect("temp dir");
        let source = directory.path().join("source.db");
        let backup = directory.path().join("backup.db");
        let store = Store::initialize(&source).expect("initialize");
        let artifact = store.backup_verified(&backup).expect("verified backup");
        assert_eq!(artifact.path, backup);
        assert!(artifact.size_bytes > 0);
        validate_digest("backup", &artifact.sha256).expect("qualified backup digest");
        drop(Store::open(&backup).expect("backup reopens"));

        store
            .connection
            .execute_batch("DROP VIEW public_status_snapshot_v1")
            .expect("test damages schema");
        drop(store);
        assert!(matches!(
            Store::open(&source),
            Err(StoreError::Integrity(message)) if message.contains("public_status_snapshot_v1")
        ));

        let altered = directory.path().join("altered.db");
        let altered_store = Store::initialize(&altered).expect("initialize altered fixture");
        altered_store
            .connection
            .execute_batch(
                "DROP VIEW public_status_snapshot_v1;
                 CREATE VIEW public_status_snapshot_v1 AS SELECT 'forged' AS schema",
            )
            .expect("replace required view under the same name");
        drop(altered_store);
        assert!(matches!(
            Store::open(&altered),
            Err(StoreError::Integrity(message)) if message.contains("schema definition fingerprint")
        ));
    }

    #[test]
    fn admitted_report_persists_context_bound_recomputable_judgment() {
        let (mut store, profile_digest) = configured_store();
        commit_admitted(
            &mut store,
            "fixture-a",
            "a",
            &profile_digest,
            document(json!({"report": "a"})),
            b"raw-a".to_vec(),
        );

        // The store derives admission_context_digest from the constituents, so
        // 3B can recompute it from the persisted admission row alone.
        let expected_context = fixture_identity().context_digest().expect("context digest");
        let admission = store
            .admission("admission-a")
            .expect("query admission")
            .expect("admission row");
        assert_eq!(admission.admission_context_digest, expected_context);

        // The report copies exactly that context and stores a versioned,
        // byte-lossless judgment whose digest recomputes over schema + context +
        // report bytes.
        let (validated_json, schema_version, judgment, report_context): (
            Vec<u8>,
            String,
            String,
            String,
        ) = store
            .connection
            .query_row(
                "SELECT validated_report_json, judgment_schema_version, judgment_digest,
                        admission_context_digest
                 FROM admitted_reports WHERE report_id = 'report-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("admitted report row");
        assert_eq!(
            report_context, expected_context,
            "report binds the admission context"
        );
        assert_eq!(schema_version, JUDGMENT_SCHEMA_VERSION);
        let validated = CanonicalDocument::from_canonical_bytes(validated_json)
            .expect("validated report is canonical");
        let recomputed =
            judgment_digest(&expected_context, validated.digest()).expect("judgment digest");
        assert_eq!(
            judgment, recomputed,
            "judgment digest binds schema version, admission context, and report bytes"
        );
        // Tamper detection substrate: a different judgment context yields a
        // different digest, so a swapped context cannot pass a later re-check.
        let foreign = judgment_digest(&digest("other-context"), validated.digest())
            .expect("foreign judgment digest");
        assert_ne!(judgment, foreign);
    }

    #[test]
    fn admitted_report_requires_a_run_bound_to_an_admission() {
        let (mut store, profile_digest) = configured_store();
        // A run with no admission cannot carry an admitted report, and the
        // failed commit leaves neither the run nor the submission behind.
        let bound = bound_fixture_run(&mut store, "fixture-a", "a", &profile_digest);
        let mut collection = fixture_collection(
            &mut store,
            bound,
            Some(SubmissionInput {
                submission_id: "submission-a".to_owned(),
                raw_bytes: b"raw".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "fixture-a",
                    "a",
                    &profile_digest,
                    document(json!({"report": "a"})),
                )),
            }),
        );
        collection.run.admission_id = None;
        let error = commit_admitted_fixture(&mut store, collection)
            .expect_err("an admitted report requires a run bound to an admission");
        assert!(matches!(error, StoreError::Invariant(message)
                if message.contains("provider intake identity")
                    || message.contains("bound to an admission")));
        let runs: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM watcher_runs", [], |row| row.get(0))
            .expect("count runs");
        assert_eq!(runs, 0, "the atomic commit rolled back the run");
    }

    #[test]
    fn admission_context_binding_trigger_rejects_a_forged_report_context() {
        let (mut store, profile_digest) = configured_store();
        append_fixture_admission(&mut store, &profile_digest, "fixture-a", "admission-a");
        let context = fixture_identity().context_digest().expect("context digest");

        // Build a run + admitted submission graph directly, then attempt to bind
        // a report to a context that is not the one reached through its run. The
        // database trigger must refuse it regardless of what the writer claims.
        store
            .connection
            .execute_batch(
                "INSERT INTO watcher_runs (
                    run_id, request_id, instance_id, admission_id, binding_digest,
                    checkpoint_contract_digest, profile_id, profile_version, profile_digest,
                    carrier, started_at, deadline_at, finished_at, acquisition_outcome,
                    execution_identity_json, resource_outcome_json
                 ) VALUES (
                    'run-a', 'request-a', 'fixture-a', 'admission-a',
                    'sha256:0000000000000000000000000000000000000000000000000000000000000000',
                    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                    'fixture.health', '1', 'unused-profile-digest', 'stdio',
                    '2026-07-16T12:00:00.000Z', '2026-07-16T12:00:10.000Z',
                    '2026-07-16T12:00:01.000Z', 'response',
                    CAST('{}' AS BLOB), CAST('{}' AS BLOB)
                 );
                 INSERT INTO raw_submissions (
                    submission_id, run_id, raw_bytes, raw_sha256, received_at,
                    protocol_outcome, admission_outcome, rejection_code
                 ) VALUES (
                    'submission-a', 'run-a', X'6162',
                    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
                    '2026-07-16T12:00:01.000Z', 'valid_exchange', 'admitted', NULL
                 );",
            )
            .expect("run and admitted submission graph");

        let insert_report_with_context = |context_digest: &str| {
            store.connection.execute(
                "INSERT INTO admitted_reports (
                    report_id, submission_id, instance_id, profile_id, profile_version,
                    profile_digest, observed_at, received_at, report_status, canonical_json,
                    semantic_digest, validated_report_json, judgment_schema_version,
                    judgment_digest, admission_context_digest, next_checkpoint_json, admitted_at
                 ) VALUES (
                    'report-a', 'submission-a', 'fixture-a', 'fixture.health', '1',
                    ?1, '2026-07-16T12:00:00.000Z', '2026-07-16T12:00:01.000Z', 'complete',
                    CAST('{}' AS BLOB),
                    'sha256:3333333333333333333333333333333333333333333333333333333333333333',
                    CAST('{}' AS BLOB), ?2,
                    'sha256:4444444444444444444444444444444444444444444444444444444444444444',
                    ?3, NULL, '2026-07-16T12:00:01.000Z'
                 )",
                params![profile_digest, JUDGMENT_SCHEMA_VERSION, context_digest],
            )
        };

        let forged = digest("forged-context");
        let refusal = insert_report_with_context(&forged)
            .expect_err("a forged admission context must be refused by the trigger");
        assert!(refusal.to_string().contains("bind the admission context"));

        insert_report_with_context(&context).expect("the correct admission context is accepted");
    }

    #[test]
    fn a_database_from_a_different_schema_artifact_is_refused() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("stale.db");
        // Hand-craft a database whose stored schema artifact digest belongs to a
        // different schema.sql revision. The immutable triggers block in-place
        // edits, so a stale candidate arises only at creation — model that here.
        {
            let connection = Connection::open(&path).expect("open raw database");
            connection.execute_batch(SCHEMA).expect("apply schema");
            connection
                .execute(
                    "INSERT INTO schema_metadata (
                        singleton, product, schema_version, schema_artifact_digest, initialized_at
                     ) VALUES (1, 'nq-ng', ?1, ?2, ?3)",
                    params![
                        SCHEMA_VERSION,
                        "sha256:9999999999999999999999999999999999999999999999999999999999999999",
                        TIME
                    ],
                )
                .expect("insert stale metadata");
        }
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::Integrity(message))
                if message.contains("stale candidate") && message.contains("recreated")
        ));
    }

    #[test]
    fn a_run_cannot_borrow_another_instances_admission_context() {
        let (mut store, profile_digest) = configured_store();
        append_fixture_admission(&mut store, &profile_digest, "instance-a", "admission-a");

        // A run for instance-b names instance-a's admission. The store must
        // refuse to bind the report to a context that does not govern its run.
        let mut foreign = run("instance-b", "b", &profile_digest);
        foreign.admission_id = Some("admission-a".to_owned());
        let collection = fixture_collection(
            &mut store,
            foreign,
            Some(SubmissionInput {
                submission_id: "submission-b".to_owned(),
                raw_bytes: b"raw".to_vec(),
                received_at: TIME.to_owned(),
                protocol_outcome: "valid_report".to_owned(),
                disposition: SubmissionDisposition::Admitted(report(
                    "instance-b",
                    "b",
                    &profile_digest,
                    document(json!({"report": "b"})),
                )),
            }),
        );
        let error = commit_admitted_fixture(&mut store, collection)
            .expect_err("a run cannot borrow another instance's admission");
        assert!(matches!(error, StoreError::Invariant(message)
                if message.contains("provider intake identity")
                    || message.contains("cannot bind admission")));

        let mut substituted_profile = run("instance-a", "profile-substitution", &profile_digest);
        substituted_profile.admission_id = Some("admission-a".to_owned());
        substituted_profile.profile_digest = digest("substituted-profile-descriptor");
        let transaction = store
            .immediate_transaction()
            .expect("profile hostile writer");
        let error = insert_run(&transaction, &substituted_profile)
            .expect_err("a run cannot substitute its admission profile digest");
        assert!(matches!(error, StoreError::Invariant(message)
            if message.contains("cannot bind admission")));
    }

    #[test]
    fn a_replace_cannot_invalidate_an_append_only_row() {
        let store = Store::initialize_in_memory().expect("store initializes");
        // With recursive triggers enabled, the implicit delete of INSERT OR
        // REPLACE fires the immutability trigger, so a parent row an admitted
        // report depends on cannot be silently swapped out from under it.
        let error = store
            .connection
            .execute(
                "INSERT OR REPLACE INTO schema_metadata (
                    singleton, product, schema_version, schema_artifact_digest, initialized_at
                 ) VALUES (1, 'nq-ng', ?1, ?2, ?3)",
                params![SCHEMA_VERSION, schema_artifact_digest(), TIME],
            )
            .expect_err("INSERT OR REPLACE must fire the immutability trigger");
        assert!(error.to_string().contains("append-only table"));
    }

    #[test]
    fn a_database_missing_the_schema_artifact_column_is_refused_actionably() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("pre_column.db");
        // Model a database created by the earlier provisional schema, before the
        // schema_artifact_digest column existed.
        {
            let connection = Connection::open(&path).expect("open raw database");
            connection.execute_batch(SCHEMA).expect("apply schema");
            connection
                .execute(
                    "INSERT INTO schema_metadata (
                        singleton, product, schema_version, schema_artifact_digest, initialized_at
                     ) VALUES (1, 'nq-ng', ?1, ?2, ?3)",
                    params![SCHEMA_VERSION, schema_artifact_digest(), TIME],
                )
                .expect("insert metadata");
            connection
                .execute_batch("ALTER TABLE schema_metadata DROP COLUMN schema_artifact_digest")
                .expect("drop the column to model the older schema");
        }
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::Integrity(message))
                if message.contains("stale candidate") && message.contains("recreated")
        ));
    }

    fn admitted_report_count(store: &Store) -> i64 {
        store
            .connection
            .query_row("SELECT COUNT(*) FROM admitted_reports", [], |row| {
                row.get(0)
            })
            .expect("count admitted reports")
    }

    #[test]
    fn verify_admitted_snapshot_authenticates_and_carries_stored_identity() {
        let (mut store, profile_digest) = configured_store();
        commit_admitted(
            &mut store,
            "instance-a",
            "a",
            &profile_digest,
            document(json!({"report": "a"})),
            b"raw-a".to_vec(),
        );
        let snapshot = store
            .verify_admitted_snapshot("report-a")
            .expect("a valid report authenticates");
        assert_eq!(snapshot.admission_id, "admission-a");
        assert_eq!(snapshot.instance_id, "instance-a");
        assert_eq!(snapshot.judgment_schema_version, JUDGMENT_SCHEMA_VERSION);
        // The snapshot carries the evaluator identity as recorded at admission,
        // for the caller to compare against a freshly observed one.
        assert_eq!(
            snapshot.evaluator_artifact_digest,
            typed_digest("evaluator-artifact").into_string()
        );
        assert_eq!(snapshot.artifact_identity_method, "fixture");
        assert_eq!(snapshot.platform_runtime_version, "test");
    }

    #[test]
    fn verify_admitted_snapshot_reports_an_unknown_report() {
        let (store, _profile_digest) = configured_store();
        assert!(matches!(
            store.verify_admitted_snapshot("no-such-report"),
            Err(SnapshotVerificationError::ReportNotFound(id)) if id == "no-such-report"
        ));
    }

    #[test]
    fn verify_admitted_snapshot_detects_a_corrupted_constituent() {
        let (mut store, profile_digest) = configured_store();
        commit_admitted(
            &mut store,
            "instance-a",
            "a",
            &profile_digest,
            document(json!({"report": "a"})),
            b"raw-a".to_vec(),
        );
        store
            .verify_admitted_snapshot("report-a")
            .expect("valid before tampering");
        let before = admitted_report_count(&store);
        // Simulate external tampering: edit a stored constituent without
        // recomputing the context digest, bypassing the immutability guard.
        store
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_admission_records_update;
                 UPDATE admission_records
                    SET evaluator_artifact_digest =
                        'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                  WHERE admission_id = 'admission-a';",
            )
            .expect("tamper with a constituent");
        assert!(matches!(
            store.verify_admitted_snapshot("report-a"),
            Err(SnapshotVerificationError::AdmissionContextCorrupt(_))
        ));
        assert_eq!(
            admitted_report_count(&store),
            before,
            "verification never mutates the store"
        );
    }

    #[test]
    fn verify_admitted_snapshot_detects_a_substituted_report_context() {
        let (mut store, profile_digest) = configured_store();
        commit_admitted(
            &mut store,
            "instance-a",
            "a",
            &profile_digest,
            document(json!({"report": "a"})),
            b"raw-a".to_vec(),
        );
        // Point the report at a different context than its run's admission.
        store
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_admitted_reports_update;
                 UPDATE admitted_reports
                    SET admission_context_digest =
                        'sha256:1111111111111111111111111111111111111111111111111111111111111111'
                  WHERE report_id = 'report-a';",
            )
            .expect("substitute the report context");
        assert!(matches!(
            store.verify_admitted_snapshot("report-a"),
            Err(SnapshotVerificationError::BindingBroken(_))
        ));
    }

    #[test]
    fn verify_admitted_snapshot_detects_a_tampered_judgment() {
        let (mut store, profile_digest) = configured_store();
        commit_admitted(
            &mut store,
            "instance-a",
            "a",
            &profile_digest,
            document(json!({"report": "a"})),
            b"raw-a".to_vec(),
        );
        // Replace the persisted judgment bytes; the stored judgment digest no
        // longer recomputes.
        store
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_admitted_reports_update;
                 UPDATE admitted_reports
                    SET validated_report_json = CAST('{\"tampered\":true}' AS BLOB)
                  WHERE report_id = 'report-a';",
            )
            .expect("tamper with the judgment");
        assert!(matches!(
            store.verify_admitted_snapshot("report-a"),
            Err(SnapshotVerificationError::JudgmentCorrupt(_))
        ));
    }

    #[test]
    fn validate_recomputes_stored_content_digests() {
        let (store, _profile_digest) = configured_store();
        store.validate().expect("valid before tampering");
        // Append a raw custody row whose recorded digest does not match its
        // bytes. Appending is allowed (the immutability triggers only block
        // edits), so the schema fingerprint stays intact and the byte-digest
        // recompute — not schema/FK/quick_check — is what must catch it.
        store
            .connection
            .execute_batch(
                "INSERT INTO watcher_runs (
                    run_id, request_id, instance_id, admission_id, binding_digest,
                    checkpoint_contract_digest, profile_id, profile_version, profile_digest,
                    carrier, started_at, deadline_at, finished_at, acquisition_outcome,
                    execution_identity_json, resource_outcome_json
                 ) VALUES (
                    'run-x', 'req-x', 'inst-x', NULL,
                    'sha256:0000000000000000000000000000000000000000000000000000000000000000',
                    'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                    'fixture.health', '1', 'unused', 'stdio',
                    '2026-07-16T12:00:00.000Z', '2026-07-16T12:00:10.000Z',
                    '2026-07-16T12:00:01.000Z', 'transport_error',
                    CAST('{}' AS BLOB), CAST('{}' AS BLOB)
                 );
                 INSERT INTO raw_submissions (
                    submission_id, run_id, raw_bytes, raw_sha256, received_at,
                    protocol_outcome, admission_outcome, rejection_code
                 ) VALUES (
                    'sub-x', 'run-x', X'78',
                    'sha256:2222222222222222222222222222222222222222222222222222222222222222',
                    '2026-07-16T12:00:01.000Z', 'protocol_error', 'rejected', 'bad'
                 );",
            )
            .expect("append a raw custody row with a wrong digest");
        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message)) if message.contains("bytes hash to")
        ));
    }

    #[test]
    fn an_incompatible_database_can_be_backed_up_before_it_is_refused() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("incompatible.db");
        // A database open() refuses (stale schema artifact digest).
        {
            let connection = Connection::open(&path).expect("open raw database");
            connection.execute_batch(SCHEMA).expect("apply schema");
            connection
                .execute(
                    "INSERT INTO schema_metadata (
                        singleton, product, schema_version, schema_artifact_digest, initialized_at
                     ) VALUES (1, 'nq-ng', ?1, ?2, ?3)",
                    params![
                        SCHEMA_VERSION,
                        "sha256:9999999999999999999999999999999999999999999999999999999999999999",
                        TIME
                    ],
                )
                .expect("insert stale metadata");
        }
        assert!(matches!(Store::open(&path), Err(StoreError::Integrity(_))));
        // It can still be preserved before recreation — backup is not gated
        // behind passing validation.
        let backup = directory.path().join("preserved.db");
        let artifact =
            Store::backup_incompatible(&path, &backup).expect("incompatible database backs up");
        assert_eq!(artifact.path, backup);
        assert!(artifact.sha256.starts_with("sha256:"));
        assert!(backup.is_file());
    }

    #[test]
    fn provider_admission_is_derived_distinct_and_does_not_admit_a_report() {
        let (mut store, profile_digest) = configured_store();
        let source_admission_id = uuid::Uuid::new_v4().to_string();
        append_fixture_admission(
            &mut store,
            &profile_digest,
            "fixture-a",
            &source_admission_id,
        );
        let provider = store
            .provider_admission_for_source(&source_admission_id)
            .expect("provider admission query")
            .expect("derived provider admission");
        assert_ne!(provider.provider_admission_id, source_admission_id);
        assert_eq!(provider.provider_admission_id, provider.contract_digest);
        assert_eq!(provider.source_admission_id, source_admission_id);
        assert_eq!(provider.source_admitted_at, TIME);
        assert_eq!(provider.derivation_kind, "admission_append");
        chrono::DateTime::parse_from_rfc3339(&provider.derived_at)
            .expect("provider derivation time is exact RFC 3339");
        let contract: serde_json::Value =
            serde_json::from_slice(&provider.contract_json).expect("provider contract JSON");
        assert!(contract.get("source_admitted_at").is_none());
        assert!(contract.get("derived_at").is_none());
        assert!(contract.get("derivation_kind").is_none());
        assert!(
            store
                .evidence_snapshot(&[])
                .expect("empty evidence")
                .reports
                .is_empty()
        );
        store
            .validate()
            .expect("derived provider admission validates");
    }

    #[test]
    fn provider_interpretation_cannot_disagree_with_raw_protocol_outcome() {
        let (mut store, profile_digest) = configured_store();
        let mut collection =
            rejected_fixture_collection(&mut store, "fixture-a", "cross-plane", &profile_digest);
        assert_eq!(collection.intake.interpretation_kind, "protocol_rejected");
        collection
            .submission
            .as_mut()
            .expect("rejected raw submission")
            .protocol_outcome = "valid_refusal".to_owned();
        let result = non_success_status(&collection.run.run_id, "fixture-a", "cross-plane");
        assert!(matches!(
            store.commit_non_success_collection(&collection, &result),
            Err(StoreError::Invariant(message))
                if message.contains("interpretation does not match")
        ));
        assert!(
            store
                .provider_intakes_bounded(10, None)
                .expect("provider intake query")
                .is_empty(),
            "a cross-plane mismatch must fail before durable custody"
        );
    }

    #[test]
    fn provider_replay_is_exact_and_revocation_blocks_live_retry_not_history() {
        let (mut store, profile_digest) = configured_store();
        let collection =
            rejected_fixture_collection(&mut store, "fixture-a", "replay", &profile_digest);
        let result = non_success_status(&collection.run.run_id, "fixture-a", "replay");
        let first = store
            .commit_non_success_collection(&collection, &result)
            .expect("initial provider intake commits");
        let ProviderIntakeCommit::Committed {
            acknowledgment: first_ack,
            ..
        } = first
        else {
            panic!("initial provider intake replayed");
        };
        let replay = store
            .commit_non_success_collection(&collection, &result)
            .expect("identical provider intake replays");
        let ProviderIntakeCommit::Replayed {
            acknowledgment: replay_ack,
            ..
        } = replay
        else {
            panic!("identical provider intake was re-evaluated");
        };
        assert_eq!(replay_ack, first_ack);

        let mut changed_bytes = collection.clone();
        changed_bytes.intake.raw_bytes.push(b'!');
        changed_bytes
            .submission
            .as_mut()
            .expect("rejected submission")
            .raw_bytes
            .push(b'!');
        assert!(matches!(
            store.commit_non_success_collection(&changed_bytes, &result),
            Err(StoreError::ReplayConflict(_))
        ));
        for (field, value) in [
            ("subject", json!({"subject": "substituted"})),
            ("scope", json!({"scope": {"kind": "other"}})),
            ("vantage", json!({"vantage": {"kind": "remote"}})),
            (
                "unsupported_capability",
                json!({"granted_capabilities": ["external_actuation"]}),
            ),
        ] {
            let mut changed_context = collection.clone();
            changed_context.intake.context = document(json!({
                "schema": "fixture.provider_intake_context.v1",
                "mutated_field": field,
                "request": value,
            }));
            assert!(matches!(
                store.commit_non_success_collection(&changed_context, &result),
                Err(StoreError::ReplayConflict(_))
            ));
        }
        let mut changed_sequence = collection.clone();
        changed_sequence.intake.provider_sequence = Some("provider-sequence-2".to_owned());
        assert!(matches!(
            store.commit_non_success_collection(&changed_sequence, &result),
            Err(StoreError::Invariant(message)) if message.contains("provider sequence")
        ));
        let mut changed_profile = collection.clone();
        changed_profile.intake.profile_semantic_id = typed_digest("substituted-profile");
        assert!(matches!(
            store.commit_non_success_collection(&changed_profile, &result),
            Err(StoreError::Invariant(_))
        ));
        let mut changed_evaluator = collection.clone();
        changed_evaluator.intake.evaluator_artifact_digest = typed_digest("substituted-evaluator");
        assert!(matches!(
            store.commit_non_success_collection(&changed_evaluator, &result),
            Err(StoreError::Invariant(_))
        ));

        let replacement_source = uuid::Uuid::new_v4().to_string();
        append_fixture_admission(
            &mut store,
            &profile_digest,
            "fixture-a",
            &replacement_source,
        );
        let mut replacement_run = collection.run.clone();
        replacement_run.admission_id = Some(replacement_source);
        let replacement =
            fixture_collection(&mut store, replacement_run, collection.submission.clone());
        assert_ne!(
            replacement.intake.provider_admission_id,
            collection.intake.provider_admission_id
        );
        assert!(matches!(
            store.preflight_provider_intake(&collection.intake),
            Err(StoreError::Invariant(message)) if message.contains("not the current")
        ));
        let historical_after_replacement = store
            .provider_intake_acknowledgment(&collection.intake.idempotency_key)
            .expect("historical acknowledgment after provider replacement")
            .expect("replaced provider history remains reopenable");
        assert_eq!(historical_after_replacement.0, first_ack);
        assert!(matches!(
            store.commit_non_success_collection(&replacement, &result),
            Err(StoreError::ReplayConflict(_))
        ));

        let transaction = store.immediate_transaction().expect("revocation writer");
        let binding_event_id = uuid::Uuid::new_v4().to_string();
        let operation_id = uuid::Uuid::new_v4().to_string();
        insert_binding_event(
            &transaction,
            &BindingEventInput {
                binding_event_id: binding_event_id.clone(),
                instance_id: collection.run.instance_id.clone(),
                event_kind: "revoke".to_owned(),
                admission_id: None,
                binding_digest: collection.run.binding_digest.clone(),
                occurred_at: TIME.to_owned(),
                reason_code: Some("hostile_replay_test".to_owned()),
                detail: document(json!({})),
            },
        )
        .expect("revocation inserts");
        for phase in ["intent", "completed"] {
            insert_materialization_event(
                &transaction,
                &BindingMaterializationInput {
                    materialization_event_id: uuid::Uuid::new_v4().to_string(),
                    operation_id: operation_id.clone(),
                    instance_id: collection.run.instance_id.clone(),
                    binding_event_id: binding_event_id.clone(),
                    phase: phase.to_owned(),
                    occurred_at: TIME.to_owned(),
                    detail: document(json!({"phase": phase})),
                },
            )
            .expect("revocation materialization inserts");
        }
        transaction.commit().expect("revocation commits");
        assert!(matches!(
            store.preflight_provider_intake(&collection.intake),
            Err(StoreError::Invariant(message)) if message.contains("not the current")
        ));
        let historical = store
            .provider_intake_acknowledgment(&collection.intake.idempotency_key)
            .expect("historical acknowledgment query")
            .expect("historical acknowledgment remains");
        assert_eq!(historical.0, first_ack);
    }

    #[test]
    fn lossy_native_outcome_retains_partial_outer_bytes_without_report_admission() {
        let (mut store, profile_digest) = configured_store();
        let mut failed_run =
            bound_fixture_run(&mut store, "fixture-a", "partial-loss", &profile_digest);
        failed_run.acquisition_outcome = "output_too_large".to_owned();
        failed_run.resource_outcome = document(json!({
            "schema": "nq.run_resource_outcome.v1",
            "duration_ms": 7,
            "exit_code": null,
            "hard_limits": {
                "address_space_bytes_per_process": 1,
                "cpu_seconds_per_process": 1,
                "processes_per_execution_uid": 1,
                "open_files_per_process": 1,
                "file_bytes_per_regular_file": 1,
                "core_bytes": 0
            },
            "stdout_bytes_retained": 4,
            "stderr_bytes_retained": 2,
            "stderr_hex": "6f6b",
            "outcome": {"outcome": "output_too_large"},
        }));
        let mut collection = fixture_collection(&mut store, failed_run, None);
        collection.intake.raw_bytes = b"part".to_vec();
        let result = non_success_status(&collection.run.run_id, "fixture-a", "partial-loss");
        committed_parts(
            store
                .commit_non_success_collection(&collection, &result)
                .expect("lossy attempt commits exact intake"),
        );
        let row = store
            .provider_intake(&collection.intake.intake_id)
            .expect("provider intake query")
            .expect("provider intake exists");
        assert_eq!(row.native_outcome_kind, "output_too_large");
        let native: serde_json::Value =
            serde_json::from_slice(&row.native_outcome_json).expect("typed native outcome JSON");
        assert_eq!(
            native.pointer("/outcome/outcome").and_then(Value::as_str),
            Some("output_too_large")
        );
        assert_eq!(
            native.get("stdout_bytes_retained").and_then(Value::as_u64),
            Some(4)
        );
        assert_eq!(
            native.get("stderr_hex").and_then(Value::as_str),
            Some("6f6b")
        );
        assert!(native.get("incomplete").is_none());
        assert!(native.get("loss").is_none());
        assert_eq!(row.interpretation_kind, "unavailable");
        assert_eq!(
            store
                .provider_intake_raw_bytes(&collection.intake.intake_id)
                .expect("raw provider bytes"),
            Some(b"part".to_vec())
        );
        assert!(row.context_digest.starts_with("sha256:"));
        assert!(
            store
                .evidence_snapshot(&[])
                .expect("evidence query")
                .reports
                .is_empty()
        );
    }

    #[test]
    fn v3_upgrade_refuses_an_unrelated_valid_backup_with_a_different_logical_state() {
        let directory = tempdir().expect("temporary directory");
        let source_a = directory.path().join("schema-v3-a.db");
        let source_b = directory.path().join("schema-v3-b.db");
        let backup = directory.path().join("schema-v3-a.backup.db");
        write_empty_exact_v3(&source_a);
        write_empty_exact_v3(&source_b);

        // A and B are independently valid exact-v3 stores. The extra durable
        // fact makes their logical states different without corrupting B.
        let connection = Connection::open(&source_b).expect("reopen v3 source B");
        connection
            .execute(
                "INSERT INTO retention_tombstones (
                    tombstone_id, target_kind, target_id, target_digest,
                    reason_code, detail_json, created_at
                 ) VALUES ('after-backup', 'fixture', 'new-state', NULL,
                           'fixture_change', CAST('{}' AS BLOB), ?1)",
                [TIME],
            )
            .expect("append a valid source-B fact");
        drop(connection);
        drop(
            Store::open_v3_upgrade_source_read_only(&source_a).expect("source A is valid exact v3"),
        );
        drop(
            Store::open_v3_upgrade_source_read_only(&source_b).expect("source B is valid exact v3"),
        );
        let backup =
            Store::backup_v3_verified(&source_a, &backup).expect("verified backup of source A");

        let error = Store::upgrade_v3_to_v4(&source_b, &exact_v3_to_v4_receipt(&backup))
            .expect_err("source A's valid backup cannot authorize migration of source B");
        assert!(matches!(
            error,
            StoreError::Invariant(message) if message.contains("logical state")
        ));
        assert_eq!(Store::database_schema_version(&source_a).unwrap(), 3);
        assert_eq!(Store::database_schema_version(&source_b).unwrap(), 3);
        assert_eq!(Store::database_schema_version(&backup.path).unwrap(), 3);
    }

    #[test]
    fn v3_upgrade_receipt_has_closed_vocabulary_and_ordered_rfc3339_times() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("schema-v3.db");
        let backup_path = directory.path().join("schema-v3.backup.db");
        write_empty_exact_v3(&source);
        let backup = Store::backup_v3_verified(&source, &backup_path).expect("verified v3 backup");
        let receipt = exact_v3_to_v4_receipt(&backup);

        let aliased_backup_path = directory.path().join("schema-v3.alias.db");
        std::fs::hard_link(&source, &aliased_backup_path).expect("hard-link source alias");
        let mut aliased_backup = receipt.clone();
        aliased_backup.backup_location = aliased_backup_path.to_string_lossy().into_owned();
        aliased_backup.backup_digest = sha256_file(&aliased_backup_path).unwrap();
        assert!(matches!(
            Store::upgrade_v3_to_v4(&source, &aliased_backup),
            Err(StoreError::Invariant(message)) if message.contains("distinct from the source")
        ));
        std::fs::remove_file(&aliased_backup_path).expect("remove hard-link fixture");

        let mut wrong_migration = receipt.clone();
        wrong_migration.migrations = document(json!(["schema_v3_to_v4_provider.sql"]));
        assert!(matches!(
            Store::upgrade_v3_to_v4(&source, &wrong_migration),
            Err(StoreError::Invariant(message)) if message.contains("migration vocabulary")
        ));

        let mut wrong_result = receipt.clone();
        wrong_result.result = "success".to_owned();
        assert!(matches!(
            Store::upgrade_v3_to_v4(&source, &wrong_result),
            Err(StoreError::Invariant(message)) if message.contains("exactly migrated")
        ));
        let mut current = Store::initialize_in_memory().expect("current store");
        assert!(matches!(
            current.append_upgrade_receipt(&wrong_result),
            Err(StoreError::Invariant(message)) if message.contains("exactly migrated")
        ));
        let forged_receipts: i64 = current
            .connection
            .query_row("SELECT COUNT(*) FROM upgrade_receipts", [], |row| {
                row.get(0)
            })
            .expect("count rejected receipt writes");
        assert_eq!(forged_receipts, 0);

        let mut omitted_verification = receipt.clone();
        omitted_verification.verification = document(json!({
            "integrity": "ok",
            "source_schema_version": 3,
            "source_schema_artifact_digest": SCHEMA_V3_ARTIFACT_DIGEST,
            "backup_reopened": true,
            "historical_provider_intake": "explicit_gap_only",
            "provider_intakes_synthesized": false,
        }));
        assert!(matches!(
            Store::upgrade_v3_to_v4(&source, &omitted_verification),
            Err(StoreError::Invariant(message)) if message.contains("closed vocabulary")
        ));

        let mut extended_verification = receipt.clone();
        extended_verification.verification = document(json!({
            "integrity": "ok",
            "source_schema_version": 3,
            "source_schema_artifact_digest": SCHEMA_V3_ARTIFACT_DIGEST,
            "backup_reopened": true,
            "historical_provider_intake": "explicit_gap_only",
            "provider_intakes_synthesized": false,
            "acknowledgments_synthesized": false,
            "waived": true,
        }));
        assert!(matches!(
            Store::upgrade_v3_to_v4(&source, &extended_verification),
            Err(StoreError::Invariant(message)) if message.contains("closed vocabulary")
        ));

        let mut malformed_time = receipt.clone();
        malformed_time.started_at = "not-a-time".to_owned();
        assert!(matches!(
            Store::upgrade_v3_to_v4(&source, &malformed_time),
            Err(StoreError::Invariant(message)) if message.contains("RFC 3339")
        ));

        let mut reversed_time = receipt;
        reversed_time.started_at = "2026-07-22T12:00:02Z".to_owned();
        reversed_time.finished_at = "2026-07-22T12:00:01Z".to_owned();
        assert!(matches!(
            Store::upgrade_v3_to_v4(&source, &reversed_time),
            Err(StoreError::Invariant(message)) if message.contains("precedes")
        ));
        assert_eq!(
            Store::database_schema_version(&source).unwrap(),
            3,
            "hostile receipts cannot partially migrate the source"
        );
    }

    #[test]
    fn exact_v3_upgrade_derives_provider_authority_but_not_intake_evidence() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("schema-v3.db");
        let backup = directory.path().join("schema-v3.backup.db");
        let source_admission_id = uuid::Uuid::new_v4().to_string();
        let descriptor = document(json!({
            "profile_id": "fixture.health",
            "profile_version": "1",
        }));
        let profile_digest = descriptor.digest().to_owned();
        let admission = AdmissionInput {
            admission_id: source_admission_id.clone(),
            instance_id: "fixture-a".to_owned(),
            identity: fixture_identity(),
            execution_chain: document(json!({"artifacts": []})),
            profile_id: "fixture.health".to_owned(),
            profile_version: "1".to_owned(),
            profile_digest: profile_digest.clone(),
            capability_grant: document(json!([])),
            conformance: document(json!({"passed": true})),
            lock: document(json!({"source": "qualified-v3"})),
            admitted_at: TIME.to_owned(),
            operator_identity: document(json!({"uid": 991})),
        };
        {
            let mut connection = Connection::open(&source).expect("open v3 fixture");
            configure_connection(&connection, true).expect("configure v3 fixture");
            let transaction = connection.transaction().expect("v3 fixture transaction");
            transaction
                .execute_batch(SCHEMA_V3)
                .expect("apply exact v3 schema");
            transaction
                .execute(
                    "INSERT INTO schema_metadata (
                        singleton, product, schema_version,
                        schema_artifact_digest, initialized_at
                     ) VALUES (1, 'nq-ng', 3, ?1, ?2)",
                    params![SCHEMA_V3_ARTIFACT_DIGEST, TIME],
                )
                .expect("v3 metadata");
            transaction
                .execute(
                    "INSERT INTO profile_descriptor_snapshots (
                        profile_id, profile_version, profile_digest,
                        descriptor_json, recorded_at
                     ) VALUES ('fixture.health', '1', ?1, ?2, ?3)",
                    params![profile_digest, descriptor.as_bytes(), TIME],
                )
                .expect("v3 descriptor");
            let identity = &admission.identity;
            transaction
                .execute(
                    "INSERT INTO admission_records (
                        admission_id, instance_id, config_digest,
                        helper_artifact_digest, profile_semantic_id,
                        detector_identity_digest, evaluator_source_digest,
                        evaluator_artifact_digest, admission_context_digest,
                        execution_chain_json, profile_id, profile_version,
                        profile_digest, protocol_version, target_triple,
                        artifact_identity_method, platform_runtime_version,
                        capability_grant_json, conformance_json, lock_json,
                        admitted_at, operator_identity_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                               ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
                               ?20, ?21, ?22)",
                    params![
                        admission.admission_id,
                        admission.instance_id,
                        identity.config_digest.as_str(),
                        identity.helper_artifact_digest.as_str(),
                        identity.profile_semantic_id.as_str(),
                        identity.detector_identity_digest.as_str(),
                        identity.evaluator_source_digest.as_str(),
                        identity.evaluator_artifact_digest.as_str(),
                        identity.context_digest().expect("v3 admission context"),
                        admission.execution_chain.as_bytes(),
                        admission.profile_id,
                        admission.profile_version,
                        admission.profile_digest,
                        identity.protocol_version,
                        identity.target_triple,
                        identity.artifact_identity_method,
                        identity.platform_runtime_version,
                        admission.capability_grant.as_bytes(),
                        admission.conformance.as_bytes(),
                        admission.lock.as_bytes(),
                        admission.admitted_at,
                        admission.operator_identity.as_bytes(),
                    ],
                )
                .expect("v3 admission");
            let mut historical_run = run("fixture-a", "migrated-v3", &profile_digest);
            historical_run.admission_id = Some(source_admission_id.clone());
            insert_run(&transaction, &historical_run).expect("v3 watcher run");
            let mut historical_report = report(
                "fixture-a",
                "migrated-v3",
                &profile_digest,
                document(json!({"source": "qualified-v3"})),
            );
            historical_report.next_checkpoint =
                Some(document(json!({"cursor": "historical-v3-only"})));
            let raw_bytes = historical_report.canonical_report.as_bytes().to_vec();
            transaction
                .execute(
                    "INSERT INTO raw_submissions (
                        submission_id, run_id, raw_bytes, raw_sha256, received_at,
                        protocol_outcome, admission_outcome, rejection_code
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'valid_report', 'admitted', NULL)",
                    params![
                        "submission-migrated-v3",
                        historical_run.run_id,
                        raw_bytes,
                        sha256_digest(historical_report.canonical_report.as_bytes()),
                        TIME,
                    ],
                )
                .expect("v3 raw admitted submission");
            let admission_context_digest = admission
                .identity
                .context_digest()
                .expect("v3 admission context");
            insert_report(
                &transaction,
                "submission-migrated-v3",
                &historical_report,
                &admission_context_digest,
            )
            .expect("v3 admitted report with historical checkpoint");
            insert_status_event(
                &transaction,
                &StatusEventInput {
                    status_event_id: "status-migrated-v3".to_owned(),
                    component_kind: "instance".to_owned(),
                    component_id: "fixture-a".to_owned(),
                    state: "healthy".to_owned(),
                    code: "report_complete".to_owned(),
                    detail: document(json!({
                        "schema": "nq.collection_outcome.v2",
                        "instance_id": "fixture-a",
                        "run_id": historical_run.run_id,
                        "result": {
                            "outcome": "admitted",
                            "report_id": historical_report.report_id,
                            "report_status": historical_report.report_status,
                            "semantic_digest": historical_report.canonical_report.digest(),
                            "evaluations": [],
                        },
                    })),
                    observed_at: TIME.to_owned(),
                },
                Some(&historical_run.run_id),
            )
            .expect("v3 run result");
            transaction.commit().expect("commit exact v3 fixture");
        }
        assert_eq!(
            Store::database_schema_version(&source).expect("v3 version"),
            3
        );
        let backup_artifact =
            Store::backup_v3_verified(&source, &backup).expect("verified v3 backup");
        let receipt = UpgradeReceiptInput {
            receipt_id: "upgrade-v3-v4-provider".to_owned(),
            from_schema_version: 3,
            to_schema_version: 4,
            migrations: document(json!(["schema_v3_to_v4_provider_intake"])),
            binary_digest: digest("migration-binary"),
            backup_digest: backup_artifact.sha256.clone(),
            backup_location: backup.to_string_lossy().into_owned(),
            started_at: TIME.to_owned(),
            finished_at: TIME.to_owned(),
            result: "migrated".to_owned(),
            operator_identity: document(json!({"uid": 991})),
            verification: document(json!({
                "integrity": "ok",
                "source_schema_version": 3,
                "source_schema_artifact_digest": SCHEMA_V3_ARTIFACT_DIGEST,
                "backup_reopened": true,
                "historical_provider_intake": "explicit_gap_only",
                "provider_intakes_synthesized": false,
                "acknowledgments_synthesized": false,
            })),
        };
        Store::upgrade_v3_to_v4(&source, &receipt).expect("exact v3 upgrades to v4");
        let migrated =
            Store::open_v4_upgrade_source_read_only(&source).expect("migrated v4 reopens");
        assert_eq!(
            Store::database_schema_version(&source).expect("v4 version"),
            4
        );
        assert_eq!(
            Store::database_schema_version(&backup).expect("backup version"),
            3
        );
        let provider = migrated
            .provider_admission_for_source(&source_admission_id)
            .expect("migrated provider query")
            .expect("migrated provider admission derived");
        assert_ne!(provider.provider_admission_id, source_admission_id);
        assert_eq!(provider.provider_admission_id, provider.contract_digest);
        assert_eq!(provider.source_admitted_at, TIME);
        assert_eq!(provider.derivation_kind, "schema_v3_migration");
        chrono::DateTime::parse_from_rfc3339(&provider.derived_at)
            .expect("migration derivation time is exact RFC 3339");
        let contract: serde_json::Value =
            serde_json::from_slice(&provider.contract_json).expect("provider contract JSON");
        assert!(contract.get("source_admitted_at").is_none());
        assert!(contract.get("derived_at").is_none());
        assert!(contract.get("derivation_kind").is_none());
        assert!(
            migrated
                .provider_intakes_bounded(10, None)
                .expect("intakes")
                .is_empty()
        );
        let gaps = migrated
            .legacy_provider_intake_gaps_bounded(10, None)
            .expect("legacy gaps");
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].run_id, "run-migrated-v3");
        assert_eq!(provider.derived_at, gaps[0].migrated_at);
        let acknowledgment_count: i64 = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM provider_intake_acknowledgments",
                [],
                |row| row.get(0),
            )
            .expect("acknowledgment count");
        assert_eq!(acknowledgment_count, 0);
        let historical_checkpoint: Vec<u8> = migrated
            .connection
            .query_row(
                "SELECT next_checkpoint_json FROM admitted_reports
                 WHERE report_id = 'report-migrated-v3'",
                [],
                |row| row.get(0),
            )
            .expect("historical v3 checkpoint remains preserved");
        assert_eq!(
            serde_json::from_slice::<Value>(&historical_checkpoint)
                .expect("decode preserved historical checkpoint"),
            json!({"cursor": "historical-v3-only"})
        );
        assert!(
            migrated
                .latest_checkpoint("fixture-a", &digest("checkpoint-fixture-a"))
                .expect("query migrated v3 checkpoint eligibility")
                .is_none(),
            "a migrated checkpoint without a real provider acknowledgment cannot advance live intake"
        );
        validate_v4_upgrade_source_connection(&migrated.connection).expect("migrated v4 validates");
    }

    #[test]
    fn diagnostic_artifact_import_preserves_commitment_availability_and_corruption_states() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("artifact.db");
        let mut store = Store::initialize(&database).expect("store initializes");
        let artifact_id = typed_digest("artifact-identity-not-full-byte-digest");
        let artifact = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": artifact_id.as_str(),
            "outcome": "fixture",
        }));
        assert_ne!(artifact_id.as_str(), artifact.digest());
        let receipt = store
            .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                import_id: "import-initial".to_owned(),
                artifact_id: artifact_id.clone(),
                contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                canonical_bytes: artifact.clone(),
                imported_at: TIME.to_owned(),
            })
            .expect("exact artifact import commits");
        assert_eq!(
            receipt.disposition,
            DiagnosticArtifactImportDisposition::Committed
        );
        assert_eq!(receipt.canonical_bytes_sha256.as_str(), artifact.digest());
        let replay = store
            .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                import_id: "import-initial".to_owned(),
                artifact_id: artifact_id.clone(),
                contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                canonical_bytes: artifact.clone(),
                imported_at: "2026-07-28T12:00:30Z".to_owned(),
            })
            .expect("same import operation reopens its first committed receipt");
        assert_eq!(replay, receipt);
        drop(store);

        let mut store = Store::open(&database).expect("store reopens after restart");
        let DiagnosticArtifactLookup::Found(access) = store
            .diagnostic_artifact(&artifact_id, &["nq.diagnostic_execution.v1"])
            .expect("artifact lookup")
        else {
            panic!("artifact commitment disappeared");
        };
        assert_eq!(
            access.schema_support,
            DiagnosticArtifactSchemaSupport::Supported
        );
        assert_eq!(
            access.commitment.canonical_bytes_sha256.as_str(),
            artifact.digest()
        );
        assert!(matches!(
            access.byte_state,
            DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes }
                if canonical_bytes == artifact
        ));
        let DiagnosticArtifactLookup::Found(unsupported) = store
            .diagnostic_artifact(&artifact_id, &[])
            .expect("unsupported-schema lookup")
        else {
            panic!("artifact commitment disappeared");
        };
        assert!(matches!(
            unsupported.schema_support,
            DiagnosticArtifactSchemaSupport::Unsupported { contract_schema }
                if contract_schema == "nq.diagnostic_execution.v1"
        ));
        assert!(matches!(
            unsupported.byte_state,
            DiagnosticArtifactByteState::VerifiedAvailable { .. }
        ));

        // Simulate loss below the typed API while restoring the exact schema
        // definition. The commitment remains valid and lookup must not invent
        // bytes or report NotFound.
        let delete_trigger: String = store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_diagnostic_artifact_payloads_delete'",
                [],
                |row| row.get(0),
            )
            .expect("capture exact delete trigger");
        store
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_diagnostic_artifact_payloads_delete;
                 DELETE FROM diagnostic_artifact_payloads;",
            )
            .expect("simulate payload loss");
        store
            .connection
            .execute_batch(&delete_trigger)
            .expect("restore exact delete trigger");
        store.validate().expect("commitment-only store validates");
        let DiagnosticArtifactLookup::Found(unavailable) = store
            .diagnostic_artifact(&artifact_id, &["nq.diagnostic_execution.v1"])
            .expect("unavailable lookup")
        else {
            panic!("artifact commitment disappeared");
        };
        assert_eq!(
            unavailable.byte_state,
            DiagnosticArtifactByteState::CommittedUnavailable
        );
        let rematerialized = store
            .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                import_id: "import-rematerialize".to_owned(),
                artifact_id: artifact_id.clone(),
                contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                canonical_bytes: artifact.clone(),
                imported_at: "2026-07-28T12:01:00Z".to_owned(),
            })
            .expect("matching exact bytes rematerialize");
        assert_eq!(
            rematerialized.disposition,
            DiagnosticArtifactImportDisposition::Rematerialized
        );

        let corrupt_id = typed_digest("corrupt-artifact-identity");
        let corrupt = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": corrupt_id.as_str(),
            "outcome": "fixture",
        }));
        store
            .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                import_id: "import-corrupt".to_owned(),
                artifact_id: corrupt_id.clone(),
                contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                canonical_bytes: corrupt,
                imported_at: TIME.to_owned(),
            })
            .expect("second artifact commits");
        let update_trigger: String = store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_diagnostic_artifact_payloads_update'",
                [],
                |row| row.get(0),
            )
            .expect("capture exact update trigger");
        store
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_diagnostic_artifact_payloads_update;
                 UPDATE diagnostic_artifact_payloads
                 SET canonical_bytes = CAST(
                    '{\"schema\":\"nq.diagnostic_execution.v1\"}' AS BLOB
                 )
                 WHERE artifact_id = (SELECT artifact_id
                    FROM imported_diagnostic_artifact_origins
                    WHERE import_id = 'import-corrupt');",
            )
            .expect("simulate corrupt bytes");
        store
            .connection
            .execute_batch(&update_trigger)
            .expect("restore exact update trigger");
        store
            .validate()
            .expect("corruption remains an access state");
        let DiagnosticArtifactLookup::Found(corrupt_access) = store
            .diagnostic_artifact(&corrupt_id, &["nq.diagnostic_execution.v1"])
            .expect("corrupt lookup")
        else {
            panic!("corrupt artifact commitment disappeared");
        };
        assert!(matches!(
            corrupt_access.byte_state,
            DiagnosticArtifactByteState::Corrupt { .. }
        ));
    }

    #[test]
    fn unavailable_import_is_custody_only_and_exact_import_rematerializes_it() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let artifact_id = typed_digest("unavailable-artifact");
        let artifact = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": artifact_id.as_str(),
        }));
        let commitment = store
            .import_unavailable_diagnostic_artifact(&UnavailableDiagnosticArtifactImportInput {
                import_id: "unavailable-import".to_owned(),
                artifact_id: artifact_id.clone(),
                contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                canonical_bytes_sha256: Sha256Digest::parse(artifact.digest().to_owned())
                    .expect("typed full-byte digest"),
                canonical_bytes_length: u64::try_from(artifact.as_bytes().len())
                    .expect("fixture length"),
                imported_at: TIME.to_owned(),
            })
            .expect("unavailable commitment imports");
        assert_eq!(
            commitment.disposition,
            DiagnosticArtifactImportDisposition::CommittedUnavailable
        );
        let DiagnosticArtifactLookup::Found(unavailable) = store
            .diagnostic_artifact(&artifact_id, &["nq.diagnostic_execution.v1"])
            .expect("unavailable lookup")
        else {
            panic!("unavailable commitment missing");
        };
        assert!(matches!(
            unavailable.commitment.origin,
            DiagnosticArtifactOrigin::Imported { import_id, .. }
                if import_id == "unavailable-import"
        ));
        assert_eq!(
            unavailable.byte_state,
            DiagnosticArtifactByteState::CommittedUnavailable
        );
        assert!(
            store
                .diagnostic_artifact_id_for_run("run-that-never-existed")
                .expect("local lookup")
                .is_none(),
            "custody-only import became a local execution origin"
        );
        let rematerialized = store
            .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                import_id: "available-import".to_owned(),
                artifact_id: artifact_id.clone(),
                contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                canonical_bytes: artifact,
                imported_at: "2026-07-28T12:01:00Z".to_owned(),
            })
            .expect("exact bytes rematerialize");
        assert_eq!(
            rematerialized.disposition,
            DiagnosticArtifactImportDisposition::Rematerialized
        );
    }

    #[test]
    fn imported_receipts_reject_hostile_cross_links_and_field_substitution_after_restart() {
        let mutations = [
            "artifact_cross_link",
            "contract",
            "digest",
            "length",
            "time",
            "outcome",
        ];
        for mutation in mutations {
            let directory = tempdir().expect("temporary directory");
            let database = directory.path().join(format!("{mutation}.db"));
            let mut store = Store::initialize(&database).expect("store initializes");
            let primary_artifact_id = typed_digest(&format!("{mutation}-artifact-a"));
            let artifact_a = document(json!({
                "schema": "nq.diagnostic_execution.v1",
                "artifact_id": primary_artifact_id.as_str(),
            }));
            store
                .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                    import_id: "import-a".to_owned(),
                    artifact_id: primary_artifact_id,
                    contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                    canonical_bytes: artifact_a,
                    imported_at: TIME.to_owned(),
                })
                .expect("first import");
            let cross_link_target_id = typed_digest(&format!("{mutation}-artifact-b"));
            let artifact_b = document(json!({
                "schema": "nq.diagnostic_execution.v1",
                "artifact_id": cross_link_target_id.as_str(),
            }));
            store
                .import_diagnostic_artifact(&DiagnosticArtifactImportInput {
                    import_id: "import-b".to_owned(),
                    artifact_id: cross_link_target_id.clone(),
                    contract_schema: "nq.diagnostic_execution.v1".to_owned(),
                    canonical_bytes: artifact_b,
                    imported_at: "2026-07-28T12:01:00Z".to_owned(),
                })
                .expect("second import");
            let trigger: String = store
                .connection
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name = 'immutable_diagnostic_artifact_import_events_update'",
                    [],
                    |row| row.get(0),
                )
                .expect("capture receipt update trigger");
            store
                .connection
                .execute_batch("DROP TRIGGER immutable_diagnostic_artifact_import_events_update;")
                .expect("drop receipt trigger below typed API");
            match mutation {
                "artifact_cross_link" => {
                    store
                        .connection
                        .execute(
                            "UPDATE diagnostic_artifact_import_events
                             SET artifact_id = ?1 WHERE import_id = 'import-a'",
                            [cross_link_target_id.as_str()],
                        )
                        .expect("cross-link receipt");
                }
                "contract" => {
                    store
                        .connection
                        .execute(
                            "UPDATE diagnostic_artifact_import_events
                             SET contract_schema = 'nq.hostile.v1'
                             WHERE import_id = 'import-a'",
                            [],
                        )
                        .expect("substitute contract");
                }
                "digest" => {
                    store
                        .connection
                        .execute(
                            "UPDATE diagnostic_artifact_import_events
                             SET canonical_bytes_sha256 = ?1
                             WHERE import_id = 'import-a'",
                            [typed_digest("hostile-receipt-digest").as_str()],
                        )
                        .expect("substitute digest");
                }
                "length" => {
                    store
                        .connection
                        .execute(
                            "UPDATE diagnostic_artifact_import_events
                             SET canonical_bytes_length = canonical_bytes_length + 1
                             WHERE import_id = 'import-a'",
                            [],
                        )
                        .expect("substitute length");
                }
                "time" => {
                    store
                        .connection
                        .execute(
                            "UPDATE diagnostic_artifact_import_events
                             SET imported_at = '2026-07-28T13:00:00Z'
                             WHERE import_id = 'import-a'",
                            [],
                        )
                        .expect("substitute time");
                }
                "outcome" => {
                    store
                        .connection
                        .execute(
                            "UPDATE diagnostic_artifact_import_events
                             SET outcome = 'committed_unavailable'
                             WHERE import_id = 'import-a'",
                            [],
                        )
                        .expect("substitute outcome");
                }
                _ => unreachable!(),
            }
            store
                .connection
                .execute_batch(&trigger)
                .expect("restore receipt trigger");
            drop(store);

            assert!(matches!(
                Store::open(&database),
                Err(StoreError::Integrity(message))
                    if message.contains("does not exactly correspond")
            ));
        }
    }

    #[test]
    fn local_artifact_completion_accepts_equivalent_rfc3339_spelling_only() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("equivalent-completion-time.db");
        let mut store = Store::initialize(&database).expect("store initializes");
        let profile_digest = append_fixture_descriptor(&mut store);
        let collection =
            rejected_fixture_collection(&mut store, "fixture-a", "exact-second", &profile_digest);
        let result = non_success_status(&collection.run.run_id, "fixture-a", "exact-second");
        let mut artifact = run_only_diagnostic_artifact(&collection, "exact-second");

        let mut shifted = artifact.clone();
        shifted.canonical_bytes = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": shifted.artifact_id.as_str(),
            "run_id": collection.run.run_id,
            "request_id": collection.run.request_id,
            "profile": {
                "id": collection.run.profile_id,
                "version": collection.run.profile_version,
                "digest": collection.run.profile_digest,
            },
            "completed_at": "2026-07-16T12:00:00.001Z",
            "fixture": "exact-second",
        }));
        assert!(matches!(
            store.commit_non_success_collection_with_artifact(
                &collection,
                &result,
                Some(&shifted),
            ),
            Err(StoreError::Invariant(message))
                if message.contains("completion time differs")
        ));

        artifact.canonical_bytes = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": artifact.artifact_id.as_str(),
            "run_id": collection.run.run_id,
            "request_id": collection.run.request_id,
            "profile": {
                "id": collection.run.profile_id,
                "version": collection.run.profile_version,
                "digest": collection.run.profile_digest,
            },
            "completed_at": "2026-07-16T12:00:00Z",
            "fixture": "exact-second",
        }));
        store
            .commit_non_success_collection_with_artifact(&collection, &result, Some(&artifact))
            .expect("equivalent exact-second completion spellings commit");
        store.validate().expect("exact-second artifact validates");
    }

    #[test]
    fn run_only_diagnostic_artifact_preserves_provenance_and_replay_identity() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("run-only-artifact.db");
        let mut store = Store::initialize(&database).expect("store initializes");
        let profile_digest = append_fixture_descriptor(&mut store);
        let collection =
            rejected_fixture_collection(&mut store, "fixture-a", "run-only", &profile_digest);
        let result = non_success_status(&collection.run.run_id, "fixture-a", "run-only");
        let artifact = run_only_diagnostic_artifact(&collection, "run-only");

        let mut future_completion = artifact.clone();
        future_completion.local_origin.completed_at = "2099-01-01T00:00:00Z".to_owned();
        future_completion.canonical_bytes = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": future_completion.artifact_id.as_str(),
            "run_id": collection.run.run_id,
            "request_id": collection.run.request_id,
            "profile": {
                "id": collection.run.profile_id,
                "version": collection.run.profile_version,
                "digest": collection.run.profile_digest,
            },
            "completed_at": future_completion.local_origin.completed_at,
            "fixture": "run-only",
        }));
        assert!(matches!(
            store.commit_non_success_collection_with_artifact(
                &collection,
                &result,
                Some(&future_completion),
            ),
            Err(StoreError::Integrity(message))
                if message.contains("completes after its custody commitment")
        ));

        let mut falsely_evaluated = artifact.clone();
        falsely_evaluated.local_origin.evaluation_id = Some("evaluation-that-never-ran".to_owned());
        assert!(matches!(
            store.commit_non_success_collection_with_artifact(
                &collection,
                &result,
                Some(&falsely_evaluated),
            ),
            Err(StoreError::Invariant(message))
                if message.contains("cannot claim an evaluation origin")
        ));

        let mut substituted = artifact.clone();
        substituted.canonical_bytes = document(json!({
            "schema": "nq.diagnostic_execution.v1",
            "artifact_id": substituted.artifact_id.as_str(),
            "run_id": collection.run.run_id,
            "request_id": "request-substituted",
            "profile": {
                "id": collection.run.profile_id,
                "version": collection.run.profile_version,
                "digest": collection.run.profile_digest,
            },
            "completed_at": TIME,
        }));
        assert!(matches!(
            store.commit_non_success_collection_with_artifact(
                &collection,
                &result,
                Some(&substituted),
            ),
            Err(StoreError::Invariant(message))
                if message.contains("run, request, or profile provenance")
        ));
        assert_eq!(
            store
                .diagnostic_artifact_id_for_run(&collection.run.run_id)
                .expect("failed provenance lookup"),
            None
        );

        let committed = store
            .commit_non_success_collection_with_artifact(&collection, &result, Some(&artifact))
            .expect("run-only diagnostic artifact commits");
        assert_eq!(
            committed.diagnostic_artifact_id,
            Some(artifact.artifact_id.clone())
        );
        assert!(matches!(
            committed.intake,
            ProviderIntakeCommit::Committed { .. }
        ));
        let DiagnosticArtifactLookup::Found(access) = store
            .diagnostic_artifact(&artifact.artifact_id, &["nq.diagnostic_execution.v1"])
            .expect("run-only artifact lookup")
        else {
            panic!("run-only artifact commitment is missing")
        };
        assert!(matches!(
            access.commitment.origin,
            DiagnosticArtifactOrigin::Local {
                run_id,
                evaluation_id: None,
                completed_at,
                ..
            } if run_id == collection.run.run_id && completed_at == TIME
        ));
        assert!(matches!(
            access.byte_state,
            DiagnosticArtifactByteState::VerifiedAvailable { canonical_bytes }
                if canonical_bytes == artifact.canonical_bytes
        ));
        assert_eq!(
            store
                .collection_result_for_run(&collection.run.run_id)
                .expect("run result lookup"),
            Some(result.status.detail.clone())
        );
        store.validate().expect("run-only artifact validates");
        drop(store);

        let mut reopened = Store::open(&database).expect("store reopens");
        let replayed = reopened
            .commit_non_success_collection_with_artifact(&collection, &result, Some(&artifact))
            .expect("exact non-success intake replays");
        assert_eq!(
            replayed.diagnostic_artifact_id,
            Some(artifact.artifact_id.clone())
        );
        assert!(matches!(
            replayed.intake,
            ProviderIntakeCommit::Replayed { .. }
        ));

        let historical =
            rejected_fixture_collection(&mut reopened, "fixture-a", "no-artifact", &profile_digest);
        let historical_result =
            non_success_status(&historical.run.run_id, "fixture-a", "no-artifact");
        assert!(matches!(
            reopened
                .commit_non_success_collection(&historical, &historical_result)
                .expect("historical non-success commits without artifact"),
            ProviderIntakeCommit::Committed { .. }
        ));
        let candidate = run_only_diagnostic_artifact(&historical, "no-artifact");
        let replay_without_synthesis = reopened
            .commit_non_success_collection_with_artifact(
                &historical,
                &historical_result,
                Some(&candidate),
            )
            .expect("historical non-success replays");
        assert_eq!(replay_without_synthesis.diagnostic_artifact_id, None);
        assert!(matches!(
            replay_without_synthesis.intake,
            ProviderIntakeCommit::Replayed { .. }
        ));
        assert_eq!(
            reopened
                .diagnostic_artifact(&candidate.artifact_id, &["nq.diagnostic_execution.v1"])
                .expect("candidate lookup"),
            DiagnosticArtifactLookup::NotFound
        );
    }

    #[test]
    fn run_only_artifact_failure_after_insertion_rolls_back_every_row() {
        let (mut store, profile_digest) = configured_store();
        let collection =
            rejected_fixture_collection(&mut store, "fixture-a", "rollback", &profile_digest);
        let result = non_success_status(&collection.run.run_id, "fixture-a", "rollback");
        let artifact = run_only_diagnostic_artifact(&collection, "rollback");

        FAIL_NON_SUCCESS_AFTER_ARTIFACT_INSERT.with(|fail| fail.set(true));
        assert!(matches!(
            store.commit_non_success_collection_with_artifact(
                &collection,
                &result,
                Some(&artifact),
            ),
            Err(StoreError::Invariant(message))
                if message.contains("injected failure after non-success")
        ));

        let identities = [
            (
                "provider_intake_attempts",
                "intake_id",
                collection.intake.intake_id.as_str(),
            ),
            (
                "local_watcher_provider_intakes",
                "run_id",
                collection.run.run_id.as_str(),
            ),
            ("watcher_runs", "run_id", collection.run.run_id.as_str()),
            ("raw_submissions", "run_id", collection.run.run_id.as_str()),
            ("refusals", "run_id", collection.run.run_id.as_str()),
            (
                "diagnostic_artifact_commitments",
                "artifact_id",
                artifact.artifact_id.as_str(),
            ),
            (
                "diagnostic_artifact_payloads",
                "artifact_id",
                artifact.artifact_id.as_str(),
            ),
            (
                "local_diagnostic_artifact_origins",
                "artifact_id",
                artifact.artifact_id.as_str(),
            ),
            ("status_events", "run_id", collection.run.run_id.as_str()),
            (
                "provider_intake_acknowledgments",
                "run_id",
                collection.run.run_id.as_str(),
            ),
        ];
        for (table, column, identity) in identities {
            let count: i64 = store
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
                    [identity],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("count {table}.{column}: {error}"));
            assert_eq!(count, 0, "{table}.{column} survived rollback");
        }
        assert_eq!(
            store
                .diagnostic_artifact(&artifact.artifact_id, &["nq.diagnostic_execution.v1"])
                .expect("rolled-back artifact lookup"),
            DiagnosticArtifactLookup::NotFound
        );
        store.validate().expect("rolled-back store remains valid");
    }

    #[test]
    fn local_diagnostic_artifact_is_atomic_with_its_run_and_evaluation() {
        let (mut store, profile_digest) = configured_store();
        let (failed_run, failed_artifact, failed) = commit_diagnostic_artifact_fixture(
            &mut store,
            "diagnostic-mismatch",
            &profile_digest,
            "evaluation-not-in-this-completion",
        );
        assert!(matches!(
            failed,
            Err(StoreError::Invariant(message))
                if message.contains("exactly one evaluation in the same completion")
        ));
        let failed_run_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM watcher_runs WHERE run_id = ?1",
                [&failed_run],
                |row| row.get(0),
            )
            .expect("failed run count");
        assert_eq!(failed_run_count, 0);
        assert_eq!(
            store
                .diagnostic_artifact(&failed_artifact, &["nq.diagnostic_execution.v1"])
                .expect("failed artifact lookup"),
            DiagnosticArtifactLookup::NotFound
        );

        let expected_evaluation = "evaluation-diagnostic-atomic";
        let (run_id, artifact_id, committed) = commit_diagnostic_artifact_fixture(
            &mut store,
            "diagnostic-atomic",
            &profile_digest,
            expected_evaluation,
        );
        assert!(matches!(
            committed,
            Ok(ProviderIntakeCommit::Committed { .. })
        ));
        assert_eq!(
            store
                .diagnostic_artifact_id_for_run(&run_id)
                .expect("artifact-by-run lookup"),
            Some(artifact_id.clone())
        );
        let DiagnosticArtifactLookup::Found(access) = store
            .diagnostic_artifact(&artifact_id, &["nq.diagnostic_execution.v1"])
            .expect("local artifact lookup")
        else {
            panic!("local artifact commitment missing");
        };
        assert!(matches!(
            access.commitment.origin,
            DiagnosticArtifactOrigin::Local {
                run_id: origin_run,
                evaluation_id,
                completed_at,
                ..
            } if origin_run == run_id
                && evaluation_id.as_deref() == Some(expected_evaluation)
                && completed_at == TIME
        ));
        assert!(matches!(
            access.byte_state,
            DiagnosticArtifactByteState::VerifiedAvailable { .. }
        ));
        let origin = store
            .evaluation_origin(expected_evaluation)
            .expect("evaluation origin lookup")
            .expect("evaluation origin");
        assert_eq!(origin.evaluation_id, expected_evaluation);
        assert!(origin.evaluation_sequence > 0);
        assert_eq!(origin.trigger_run_id, Some(run_id));
        store.validate().expect("atomic artifact store validates");
    }

    #[test]
    fn local_artifact_provenance_rejects_swapped_run_and_evaluation_origins() {
        let (mut store, profile_digest) = configured_store();
        let (run_a, artifact_a, committed_a) = commit_diagnostic_artifact_fixture(
            &mut store,
            "origin-a",
            &profile_digest,
            "evaluation-origin-a",
        );
        let (run_b, artifact_b, committed_b) = commit_diagnostic_artifact_fixture(
            &mut store,
            "origin-b",
            &profile_digest,
            "evaluation-origin-b",
        );
        assert!(matches!(
            (committed_a, committed_b),
            (
                Ok(ProviderIntakeCommit::Committed { .. }),
                Ok(ProviderIntakeCommit::Committed { .. })
            )
        ));

        let delete_trigger: String = store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_local_diagnostic_artifact_origins_delete'",
                [],
                |row| row.get(0),
            )
            .expect("capture local-origin delete trigger");
        store
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_local_diagnostic_artifact_origins_delete;
                 DELETE FROM local_diagnostic_artifact_origins;",
            )
            .expect("remove origins below the typed API");
        store
            .connection
            .execute(
                "INSERT INTO local_diagnostic_artifact_origins (
                    artifact_id, run_id, evaluation_id, completed_at
                 ) VALUES (?1, ?2, 'evaluation-origin-b', ?3)",
                params![artifact_a.as_str(), run_b, TIME],
            )
            .expect("substitute artifact A origin");
        store
            .connection
            .execute(
                "INSERT INTO local_diagnostic_artifact_origins (
                    artifact_id, run_id, evaluation_id, completed_at
                 ) VALUES (?1, ?2, 'evaluation-origin-a', ?3)",
                params![artifact_b.as_str(), run_a, TIME],
            )
            .expect("substitute artifact B origin");
        store
            .connection
            .execute_batch(&delete_trigger)
            .expect("restore local-origin delete trigger");

        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("provenance is invalid")
                    && message.contains("run, request, or profile provenance")
        ));
    }

    #[test]
    fn local_artifact_provenance_rejects_substituted_completion_time() {
        let (mut store, profile_digest) = configured_store();
        let (_, artifact_id, committed) = commit_diagnostic_artifact_fixture(
            &mut store,
            "completion-time",
            &profile_digest,
            "evaluation-completion-time",
        );
        assert!(matches!(
            committed,
            Ok(ProviderIntakeCommit::Committed { .. })
        ));
        let trigger: String = store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_local_diagnostic_artifact_origins_update'",
                [],
                |row| row.get(0),
            )
            .expect("capture local-origin update trigger");
        store
            .connection
            .execute_batch("DROP TRIGGER immutable_local_diagnostic_artifact_origins_update;")
            .expect("drop local-origin update trigger");
        store
            .connection
            .execute(
                "UPDATE local_diagnostic_artifact_origins
                 SET completed_at = '2026-07-28T13:00:00Z'
                 WHERE artifact_id = ?1",
                [artifact_id.as_str()],
            )
            .expect("substitute completion time below typed API");
        store
            .connection
            .execute_batch(&trigger)
            .expect("restore local-origin update trigger");

        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("provenance is invalid")
                    && message.contains("completion time")
        ));
    }

    #[test]
    fn runtime_checkpoint_cannot_select_or_replace_the_store_bootstrap_root() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let batch = initial_runtime_batch(vec![runtime_record(
            "root-required",
            "nq.provider_intake.v1",
            "2026-07-29T12:00:00Z",
        )]);
        assert!(matches!(
            store.append_runtime_records(&batch),
            Err(StoreError::Invariant(message))
                if message.contains("trust root must be established")
        ));
        assert!(
            store
                .runtime_ledger_checkpoint()
                .expect("empty frontier")
                .is_none()
        );
        establish_runtime_root(&mut store, &batch.dependency);
        assert_eq!(
            store
                .runtime_dependency_trust_root()
                .expect("bootstrap root"),
            Some(batch.dependency.trust_anchor_id.clone())
        );
        store
            .append_runtime_records(&batch)
            .expect("checkpoint under bootstrap root");

        let replacement = runtime_dependency("replacement-root");
        assert_ne!(
            replacement.trust_anchor_id,
            batch.dependency.trust_anchor_id
        );
        assert!(matches!(
            store.establish_runtime_dependency_trust_root(&replacement.trust_anchor_id),
            Err(StoreError::ReplayConflict(message))
                if message.contains("trust root differs")
        ));
        assert_eq!(
            store
                .runtime_dependency_trust_root()
                .expect("unchanged bootstrap root"),
            Some(batch.dependency.trust_anchor_id)
        );
    }

    #[test]
    fn runtime_ledger_is_globally_sequenced_replayable_and_snapshot_pinned() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let batch = initial_runtime_batch(vec![
            runtime_record(
                "request",
                "nq.diagnostic_invocation_request.v1",
                "2026-07-29T12:00:00Z",
            ),
            runtime_record(
                "decision",
                "nq.invocation_decision.v1",
                "2026-07-29T12:00:01Z",
            ),
        ]);
        establish_runtime_root(&mut store, &batch.dependency);
        let committed = store
            .append_runtime_records(&batch)
            .expect("runtime batch commits");
        assert_eq!(
            committed.disposition,
            RuntimeRecordAppendDisposition::Committed
        );
        assert_eq!(committed.checkpoint.first_record_sequence, 1);
        assert_eq!(committed.checkpoint.last_record_sequence, 2);
        assert_eq!(committed.checkpoint.record_count, 2);

        let replayed = store
            .append_runtime_records(&batch)
            .expect("exact runtime batch replays");
        assert_eq!(
            replayed.disposition,
            RuntimeRecordAppendDisposition::Replayed
        );
        assert_eq!(replayed.checkpoint, committed.checkpoint);

        let first_page = store
            .runtime_record_page(Some(&committed.checkpoint), 0, 1)
            .expect("first pinned page");
        assert!(!first_page.complete);
        assert_eq!(first_page.records.len(), 1);
        assert_eq!(first_page.next_after_record_sequence, Some(1));
        let second_page = store
            .runtime_record_page(
                Some(&committed.checkpoint),
                first_page.next_after_record_sequence.unwrap(),
                1,
            )
            .expect("second pinned page");
        assert!(second_page.complete);
        assert_eq!(second_page.records.len(), 1);
        assert_eq!(second_page.records[0].record_sequence, 2);
        assert_eq!(
            store
                .runtime_record(&batch.records[0].record_id)
                .expect("exact lookup")
                .expect("record retained")
                .canonical_bytes,
            batch.records[0].canonical_bytes
        );
        store.validate().expect("runtime history validates");
    }

    #[test]
    fn checkpoint_dependency_closure_is_deduplicated_and_exactly_reopened() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let first = initial_runtime_batch(vec![runtime_record(
            "dependency-dedupe-first",
            "nq.provider_intake.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut store, &first.dependency);
        let first_receipt = store
            .append_runtime_records(&first)
            .expect("first dependency-bound checkpoint");
        let second = next_runtime_batch(
            "dependency-dedupe-second",
            &first_receipt.checkpoint,
            first.dependency.clone(),
        );
        let second_receipt = store
            .append_runtime_records(&second)
            .expect("second dependency-bound checkpoint");

        let counts: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM runtime_dependency_generation_commitments),
                    (SELECT COUNT(*) FROM runtime_dependency_generation_payloads),
                    (SELECT COUNT(*) FROM runtime_checkpoint_dependency_bindings)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("dependency custody counts");
        assert_eq!(counts, (1, 1, 2));
        for checkpoint in [&first_receipt.checkpoint, &second_receipt.checkpoint] {
            let access = store
                .runtime_checkpoint_dependency(&checkpoint.checkpoint_id)
                .expect("dependency access")
                .expect("dependency binding");
            assert!(matches!(
                access.binding,
                RuntimeCheckpointDependencyBinding::Authenticated {
                    dependency_generation_id,
                    trust_anchor_id,
                    canonical_bytes_sha256,
                    canonical_bytes_length,
                } if dependency_generation_id == first.dependency.dependency_generation_id
                    && trust_anchor_id == first.dependency.trust_anchor_id
                    && canonical_bytes_sha256.as_str()
                        == first.dependency.canonical_custody.digest()
                    && canonical_bytes_length
                        == u64::try_from(first.dependency.canonical_custody.as_bytes().len())
                            .expect("dependency length")
            ));
            assert!(matches!(
                access.byte_state,
                Some(RuntimeDependencyGenerationByteState::VerifiedAvailable {
                    canonical_custody,
                }) if canonical_custody == first.dependency.canonical_custody
            ));
        }
        store.validate().expect("deduplicated history validates");
    }

    #[test]
    fn checkpoint_dependency_bytes_preserve_unavailable_and_corrupt_states() {
        let mut unavailable = Store::initialize_in_memory().expect("unavailable store");
        let unavailable_batch = initial_runtime_batch(vec![runtime_record(
            "dependency-unavailable",
            "nq.provider_intake.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut unavailable, &unavailable_batch.dependency);
        let unavailable_receipt = unavailable
            .append_runtime_records(&unavailable_batch)
            .expect("dependency-bound checkpoint");
        let delete_trigger: String = unavailable
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_runtime_dependency_generation_payloads_delete'",
                [],
                |row| row.get(0),
            )
            .expect("payload delete trigger");
        unavailable
            .connection
            .execute_batch("DROP TRIGGER immutable_runtime_dependency_generation_payloads_delete;")
            .expect("drop payload delete trigger");
        unavailable
            .connection
            .execute(
                "DELETE FROM runtime_dependency_generation_payloads
                 WHERE dependency_generation_id = ?1",
                [unavailable_batch
                    .dependency
                    .dependency_generation_id
                    .as_str()],
            )
            .expect("remove exact dependency bytes");
        unavailable
            .connection
            .execute_batch(&delete_trigger)
            .expect("restore payload delete trigger");
        unavailable
            .validate()
            .expect("committed-unavailable dependency remains valid custody");
        assert!(matches!(
            unavailable
                .runtime_checkpoint_dependency(&unavailable_receipt.checkpoint.checkpoint_id)
                .expect("unavailable access")
                .expect("unavailable binding")
                .byte_state,
            Some(RuntimeDependencyGenerationByteState::CommittedUnavailable)
        ));

        let mut corrupt = Store::initialize_in_memory().expect("corrupt store");
        let corrupt_batch = initial_runtime_batch(vec![runtime_record(
            "dependency-corrupt",
            "nq.provider_intake.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut corrupt, &corrupt_batch.dependency);
        let corrupt_receipt = corrupt
            .append_runtime_records(&corrupt_batch)
            .expect("dependency-bound checkpoint");
        let update_trigger: String = corrupt
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_runtime_dependency_generation_payloads_update'",
                [],
                |row| row.get(0),
            )
            .expect("payload update trigger");
        let original = corrupt_batch
            .dependency
            .canonical_custody
            .as_bytes()
            .to_vec();
        let mut substituted_value: Value =
            serde_json::from_slice(&original).expect("canonical dependency JSON");
        let generation_hex = substituted_value["generation_canonical_bytes"]
            .as_str()
            .expect("generation hex")
            .to_owned();
        let replacement_head = if generation_hex.starts_with('0') {
            "1"
        } else {
            "0"
        };
        substituted_value["generation_canonical_bytes"] =
            Value::String(format!("{replacement_head}{}", &generation_hex[1..]));
        let substituted = document(substituted_value);
        assert_eq!(substituted.as_bytes().len(), original.len());
        assert_ne!(substituted.as_bytes(), original);
        corrupt
            .connection
            .execute_batch("DROP TRIGGER immutable_runtime_dependency_generation_payloads_update;")
            .expect("drop payload update trigger");
        corrupt
            .connection
            .execute(
                "UPDATE runtime_dependency_generation_payloads
                 SET canonical_bytes = ?1
                 WHERE dependency_generation_id = ?2",
                params![
                    substituted.as_bytes(),
                    corrupt_batch.dependency.dependency_generation_id.as_str(),
                ],
            )
            .expect("substitute dependency payload");
        corrupt
            .connection
            .execute_batch(&update_trigger)
            .expect("restore payload update trigger");
        corrupt
            .validate()
            .expect("corrupt bytes remain an explicit access state");
        assert!(matches!(
            corrupt
                .runtime_checkpoint_dependency(&corrupt_receipt.checkpoint.checkpoint_id)
                .expect("corrupt access")
                .expect("corrupt binding")
                .byte_state,
            Some(RuntimeDependencyGenerationByteState::Corrupt { .. })
        ));
    }

    #[test]
    fn missing_dependency_commitment_and_new_anchor_binding_substitution_fail_closed() {
        let mut missing = Store::initialize_in_memory().expect("missing store");
        let missing_batch = initial_runtime_batch(vec![runtime_record(
            "dependency-missing",
            "nq.provider_intake.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut missing, &missing_batch.dependency);
        let missing_receipt = missing
            .append_runtime_records(&missing_batch)
            .expect("dependency-bound checkpoint");
        let delete_trigger: String = missing
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_runtime_dependency_generation_commitments_delete'",
                [],
                |row| row.get(0),
            )
            .expect("commitment delete trigger");
        missing
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_runtime_dependency_generation_commitments_delete;
                 PRAGMA foreign_keys = OFF;",
            )
            .expect("permit hostile commitment deletion");
        missing
            .connection
            .execute(
                "DELETE FROM runtime_dependency_generation_commitments
                 WHERE dependency_generation_id = ?1",
                [missing_batch.dependency.dependency_generation_id.as_str()],
            )
            .expect("remove dependency commitment");
        missing
            .connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .expect("restore foreign keys");
        missing
            .connection
            .execute_batch(&delete_trigger)
            .expect("restore commitment delete trigger");
        assert!(matches!(
            missing.runtime_checkpoint_dependency(&missing_receipt.checkpoint.checkpoint_id),
            Err(StoreError::Integrity(message))
                if message.contains("missing dependency commitment")
        ));
        assert!(missing.validate().is_err());

        let mut substituted = Store::initialize_in_memory().expect("substitution store");
        let first = initial_runtime_batch(vec![runtime_record(
            "anchor-substitution-first",
            "nq.provider_intake.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut substituted, &first.dependency);
        let first_receipt = substituted
            .append_runtime_records(&first)
            .expect("first dependency generation");
        let new_anchor = runtime_dependency("new-anchor");
        assert_ne!(new_anchor.trust_anchor_id, first.dependency.trust_anchor_id);
        let second = next_runtime_batch(
            "anchor-substitution-second",
            &first_receipt.checkpoint,
            new_anchor.clone(),
        );
        assert!(matches!(
            substituted.append_runtime_records(&second),
            Err(StoreError::ReplayConflict(message))
                if message.contains("store bootstrap root")
        ));
        assert_eq!(
            substituted
                .runtime_ledger_checkpoint()
                .expect("frontier after rejected anchor"),
            Some(first_receipt.checkpoint.clone())
        );
        let binding_trigger: String = substituted
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_runtime_checkpoint_dependency_bindings_update'",
                [],
                |row| row.get(0),
            )
            .expect("binding update trigger");
        substituted
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_runtime_checkpoint_dependency_bindings_update;
                 PRAGMA foreign_keys = OFF;",
            )
            .expect("drop binding update trigger");
        substituted
            .connection
            .execute(
                "UPDATE runtime_checkpoint_dependency_bindings
                 SET trust_anchor_id = ?1
                 WHERE checkpoint_id = ?2",
                params![
                    new_anchor.trust_anchor_id.as_str(),
                    first_receipt.checkpoint.checkpoint_id,
                ],
            )
            .expect("substitute new anchor binding into g1");
        substituted
            .connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .expect("restore foreign keys");
        substituted
            .connection
            .execute_batch(&binding_trigger)
            .expect("restore binding update trigger");
        assert!(matches!(
            substituted.runtime_checkpoint_dependency(
                &first_receipt.checkpoint.checkpoint_id
            ),
            Err(StoreError::Integrity(message))
                if message.contains("selected non-bootstrap trust root")
        ));
        assert!(matches!(
            substituted.validate(),
            Err(StoreError::Integrity(_))
        ));
    }

    #[test]
    fn runtime_ledger_admits_exact_native_correspondence_vocabulary_only() {
        const CORRESPONDENCE_SCHEMAS: [&str; 3] = [
            "nq.native_profile_qualification.v1",
            "nq.native_clock_qualification.v1",
            "nq.deadline_evaluation.v1",
        ];
        for schema in CORRESPONDENCE_SCHEMAS {
            assert!(
                SUPPORTED_RUNTIME_RECORD_SCHEMAS.contains(&schema),
                "{schema} must be an ordinary exact-custody runtime record"
            );
        }

        let mut store = Store::initialize_in_memory().expect("store initializes");
        let admitted = initial_runtime_batch(
            CORRESPONDENCE_SCHEMAS
                .into_iter()
                .enumerate()
                .map(|(index, schema)| {
                    runtime_record(
                        &format!("native-correspondence-{index}"),
                        schema,
                        "2026-07-29T12:00:00Z",
                    )
                })
                .collect(),
        );
        establish_runtime_root(&mut store, &admitted.dependency);
        let committed = store
            .append_runtime_records(&admitted)
            .expect("exact correspondence vocabulary is admitted");

        for hostile_schema in [
            "nq.native_profile_qualification.v2",
            "nq.native_clock_qualification.v2",
            "nq.deadline_evaluation.v2",
            "nq.native_profile_qualification.v1.extra",
        ] {
            let hostile = RuntimeRecordBatchInput {
                checkpoint_id: digest(&format!("hostile-{hostile_schema}")),
                expected_predecessor_checkpoint_id: Some(
                    committed.checkpoint.checkpoint_id.clone(),
                ),
                expected_predecessor_ledger_root: Some(
                    committed.checkpoint.checkpoint_ledger_root.clone(),
                ),
                dependency: admitted.dependency.clone(),
                records: vec![runtime_record(
                    &format!("hostile-{hostile_schema}"),
                    hostile_schema,
                    "2026-07-29T12:00:01Z",
                )],
            };
            assert!(matches!(
                store.append_runtime_records(&hostile),
                Err(StoreError::Invariant(message)) if message.contains("unsupported schema")
            ));
            assert_eq!(
                store
                    .runtime_ledger_checkpoint()
                    .expect("checkpoint reads")
                    .expect("checkpoint remains"),
                committed.checkpoint,
                "hostile near-match must not move the ledger frontier"
            );
        }
    }

    #[test]
    fn runtime_ledger_refuses_schema_and_identity_collisions_atomically() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let first = initial_runtime_batch(vec![runtime_record(
            "request",
            "nq.diagnostic_invocation_request.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut store, &first.dependency);
        let committed = store
            .append_runtime_records(&first)
            .expect("first runtime batch");

        let mut checkpoint_collision = first.clone();
        checkpoint_collision.records[0] = runtime_record(
            "other-request",
            "nq.diagnostic_invocation_request.v1",
            "2026-07-29T12:00:00Z",
        );
        assert!(matches!(
            store.append_runtime_records(&checkpoint_collision),
            Err(StoreError::ReplayConflict(_))
        ));

        let record_collision = RuntimeRecordBatchInput {
            checkpoint_id: digest("runtime-checkpoint-collision"),
            expected_predecessor_checkpoint_id: Some(committed.checkpoint.checkpoint_id.clone()),
            expected_predecessor_ledger_root: Some(
                committed.checkpoint.checkpoint_ledger_root.clone(),
            ),
            dependency: first.dependency.clone(),
            records: first.records.clone(),
        };
        assert!(matches!(
            store.append_runtime_records(&record_collision),
            Err(StoreError::ReplayConflict(_))
        ));

        let unsupported = RuntimeRecordBatchInput {
            checkpoint_id: digest("runtime-checkpoint-unsupported"),
            expected_predecessor_checkpoint_id: Some(committed.checkpoint.checkpoint_id.clone()),
            expected_predecessor_ledger_root: Some(
                committed.checkpoint.checkpoint_ledger_root.clone(),
            ),
            dependency: first.dependency.clone(),
            records: vec![runtime_record(
                "unsupported",
                "nq.unratified_runtime_plugin.v1",
                "2026-07-29T12:00:02Z",
            )],
        };
        assert!(matches!(
            store.append_runtime_records(&unsupported),
            Err(StoreError::Invariant(message)) if message.contains("unsupported schema")
        ));
        assert_eq!(
            store
                .runtime_ledger_checkpoint()
                .expect("checkpoint reads")
                .expect("checkpoint remains"),
            committed.checkpoint
        );

        let second = RuntimeRecordBatchInput {
            checkpoint_id: digest("runtime-checkpoint-second"),
            expected_predecessor_checkpoint_id: Some(committed.checkpoint.checkpoint_id.clone()),
            expected_predecessor_ledger_root: Some(
                committed.checkpoint.checkpoint_ledger_root.clone(),
            ),
            dependency: first.dependency.clone(),
            records: vec![
                runtime_record("role", "nq.role_manifest.v1", "2026-07-29T12:00:03Z"),
                runtime_record(
                    "cohort",
                    "nq.static_profile_cohort_manifest.v1",
                    "2026-07-29T12:00:04Z",
                ),
            ],
        };
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_second_runtime_record
                 BEFORE INSERT ON runtime_record_ledger
                 WHEN NEW.record_sequence = 3
                 BEGIN SELECT RAISE(ABORT, 'injected runtime append failure'); END;",
            )
            .expect("install failure trigger");
        assert!(matches!(
            store.append_runtime_records(&second),
            Err(StoreError::Sqlite(_))
        ));
        store
            .connection
            .execute_batch("DROP TRIGGER fail_second_runtime_record;")
            .expect("remove failure trigger");
        let counts: (i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM runtime_record_ledger),
                    (SELECT COUNT(*) FROM runtime_record_checkpoints)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("runtime counts");
        assert_eq!(counts, (1, 1), "failed batch must roll back completely");
        store.validate().expect("history remains valid");
    }

    #[test]
    fn runtime_lookup_is_disposable_detectable_and_rebuildable() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let batch = initial_runtime_batch(vec![runtime_record(
            "role",
            "nq.role_manifest.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut store, &batch.dependency);
        let receipt = store
            .append_runtime_records(&batch)
            .expect("runtime batch commits");
        store
            .connection
            .execute("DELETE FROM runtime_record_lookup", [])
            .expect("delete disposable lookup");
        let stale = store.runtime_record_lookup_status().expect("lookup status");
        assert_eq!(stale.missing_records, 1);
        assert!(!stale.is_current());
        assert!(matches!(
            store.runtime_records_by_schema_bounded(
                "nq.role_manifest.v1",
                &receipt.checkpoint,
                0,
                10,
            ),
            Err(StoreError::Integrity(message)) if message.contains("lookup is stale")
        ));
        let rebuilt = store
            .rebuild_runtime_record_lookup()
            .expect("lookup rebuilds");
        assert!(rebuilt.is_current());
        assert_eq!(
            store
                .runtime_records_by_schema_bounded(
                    "nq.role_manifest.v1",
                    &receipt.checkpoint,
                    0,
                    10,
                )
                .expect("schema lookup"),
            vec![
                store
                    .runtime_record(&batch.records[0].record_id)
                    .expect("lookup")
                    .expect("record")
            ]
        );
    }

    #[test]
    fn runtime_ledger_detects_root_or_canonical_byte_substitution() {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let batch = initial_runtime_batch(vec![runtime_record(
            "request",
            "nq.diagnostic_invocation_request.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut store, &batch.dependency);
        store
            .append_runtime_records(&batch)
            .expect("runtime batch commits");
        let trigger: String = store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name = 'immutable_runtime_record_ledger_update'",
                [],
                |row| row.get(0),
            )
            .expect("capture append-only trigger");
        store
            .connection
            .execute_batch("DROP TRIGGER immutable_runtime_record_ledger_update;")
            .expect("drop trigger for hostile substitution");
        store
            .connection
            .execute(
                "UPDATE runtime_record_ledger SET ledger_root = ?1
                 WHERE record_id = ?2",
                params![digest("substituted-root"), batch.records[0].record_id],
            )
            .expect("substitute root below typed API");
        store
            .connection
            .execute_batch(&trigger)
            .expect("restore append-only trigger");
        assert!(matches!(
            store.validate(),
            Err(StoreError::Integrity(message))
                if message.contains("invalid ledger root")
                    || message.contains("root differs")
        ));
    }

    #[test]
    fn runtime_history_survives_verified_backup_and_read_only_refuses_append() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("runtime.db");
        let backup = directory.path().join("runtime-backup.db");
        let mut store = Store::initialize(&source).expect("initialize file store");
        let batch = initial_runtime_batch(vec![runtime_record(
            "provider-intake",
            "nq.provider_intake.v1",
            "2026-07-29T12:00:00Z",
        )]);
        establish_runtime_root(&mut store, &batch.dependency);
        let receipt = store
            .append_runtime_records(&batch)
            .expect("runtime batch commits");
        store.backup_verified(&backup).expect("verified backup");
        let reopened = Store::open_read_only(&backup).expect("backup reopens read-only");
        assert_eq!(
            reopened
                .runtime_dependency_trust_root()
                .expect("backup bootstrap root"),
            Some(batch.dependency.trust_anchor_id.clone())
        );
        assert_eq!(
            reopened
                .runtime_ledger_checkpoint()
                .expect("backup checkpoint")
                .expect("checkpoint retained"),
            receipt.checkpoint
        );
        assert_eq!(
            reopened
                .runtime_record(&batch.records[0].record_id)
                .expect("backup record")
                .expect("record retained")
                .canonical_bytes,
            batch.records[0].canonical_bytes
        );
        let dependency = reopened
            .runtime_checkpoint_dependency(&receipt.checkpoint.checkpoint_id)
            .expect("backup dependency access")
            .expect("backup dependency binding");
        assert!(matches!(
            dependency.binding,
            RuntimeCheckpointDependencyBinding::Authenticated {
                dependency_generation_id,
                trust_anchor_id,
                canonical_bytes_sha256,
                ..
            } if dependency_generation_id == batch.dependency.dependency_generation_id
                && trust_anchor_id == batch.dependency.trust_anchor_id
                && canonical_bytes_sha256.as_str()
                    == batch.dependency.canonical_custody.digest()
        ));
        assert!(matches!(
            dependency.byte_state,
            Some(RuntimeDependencyGenerationByteState::VerifiedAvailable {
                canonical_custody,
            }) if canonical_custody == batch.dependency.canonical_custody
        ));
        drop(reopened);

        let mut read_only = Store::open_read_only(&source).expect("source opens read-only");
        let second = RuntimeRecordBatchInput {
            checkpoint_id: digest("runtime-checkpoint-read-only"),
            expected_predecessor_checkpoint_id: Some(receipt.checkpoint.checkpoint_id.clone()),
            expected_predecessor_ledger_root: Some(
                receipt.checkpoint.checkpoint_ledger_root.clone(),
            ),
            dependency: batch.dependency.clone(),
            records: vec![runtime_record(
                "read-only",
                "nq.role_manifest.v1",
                "2026-07-29T12:00:01Z",
            )],
        };
        assert!(matches!(
            read_only.append_runtime_records(&second),
            Err(StoreError::Sqlite(_))
        ));
    }

    #[test]
    fn exact_v5_upgrade_adds_empty_runtime_ledger_without_synthesis() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("source-v5.db");
        let backup_path = directory.path().join("backup-v5.db");
        write_empty_exact_v5(&source);
        let backup = Store::backup_v5_verified(&source, &backup_path).expect("verified v5 backup");
        let receipt = exact_v5_to_v6_receipt(&backup);
        Store::upgrade_v5_to_v6(&source, &receipt).expect("exact v5 upgrades to v6");
        assert_eq!(
            Store::database_schema_version(&source).expect("source version"),
            6
        );
        assert_eq!(
            Store::database_schema_version(&backup_path).expect("backup version"),
            5
        );
        let migrated =
            Store::open_v6_upgrade_source_read_only(&source).expect("schema-v6 source reopens");
        assert!(
            migrated
                .runtime_ledger_checkpoint()
                .expect("empty checkpoint")
                .is_none()
        );
        let counts: (i64, i64, i64) = migrated
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM runtime_record_ledger),
                    (SELECT COUNT(*) FROM runtime_record_checkpoints),
                    (SELECT COUNT(*) FROM local_diagnostic_artifact_provider_attempt_bindings)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("migration counts");
        assert_eq!(counts, (0, 0, 0));
        validate_v6_upgrade_source_connection(&migrated.connection).expect("migrated v6 validates");
    }

    #[test]
    fn exact_v6_upgrade_preserves_legacy_checkpoint_as_unbound_prefix() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("source-v6.db");
        let v5_backup_path = directory.path().join("backup-v5.db");
        let v6_backup_path = directory.path().join("backup-v6.db");
        write_empty_exact_v5(&source);
        let v5_backup =
            Store::backup_v5_verified(&source, &v5_backup_path).expect("verified v5 backup");
        Store::upgrade_v5_to_v6(&source, &exact_v5_to_v6_receipt(&v5_backup))
            .expect("exact v5 upgrades to v6");
        let connection = Connection::open(&source).expect("open writable exact v6");
        configure_connection(&connection, false).expect("configure exact v6");
        let legacy_checkpoint = insert_exact_v6_runtime_checkpoint(&connection);
        drop(connection);

        let v6_backup =
            Store::backup_v6_verified(&source, &v6_backup_path).expect("verified v6 backup");
        let mut migrated = Store::upgrade_v6_to_v7(&source, &exact_v6_to_v7_receipt(&v6_backup))
            .expect("exact v6 upgrades to v7");
        assert_eq!(
            Store::database_schema_version(&source).expect("source version"),
            7
        );
        assert_eq!(
            Store::database_schema_version(&v6_backup_path).expect("backup version"),
            6
        );
        let legacy_access = migrated
            .runtime_checkpoint_dependency(&legacy_checkpoint.checkpoint_id)
            .expect("legacy dependency access")
            .expect("legacy dependency binding");
        assert_eq!(
            legacy_access.binding,
            RuntimeCheckpointDependencyBinding::LegacyUnbound {
                source_schema_version: 6,
            }
        );
        assert_eq!(legacy_access.byte_state, None);
        let counts: (i64, i64, i64, i64, i64) = migrated
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM runtime_dependency_trust_roots),
                    (SELECT COUNT(*) FROM runtime_dependency_generation_commitments),
                    (SELECT COUNT(*) FROM runtime_dependency_generation_payloads),
                    (SELECT COUNT(*) FROM runtime_checkpoint_dependency_bindings
                     WHERE binding_state = 'legacy_unbound'),
                    (SELECT legacy_checkpoint_count
                     FROM runtime_dependency_binding_migration_boundaries
                     WHERE singleton = 1)",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("v7 migration counts");
        assert_eq!(
            counts,
            (0, 0, 0, 1, 1),
            "migration must classify history without inventing dependencies"
        );

        let current = next_runtime_batch(
            "post-v6-migration",
            &legacy_checkpoint,
            runtime_dependency("post-v6-migration"),
        );
        let error = migrated
            .establish_runtime_dependency_trust_root(&current.dependency.trust_anchor_id)
            .expect_err("migration cannot self-bootstrap a production trust root");
        assert!(matches!(
            error,
            StoreError::Invariant(message)
                if message.contains("post-v6 runtime dependency trust-root bootstrap is unsupported")
        ));
        assert!(matches!(
            migrated.append_runtime_records(&current),
            Err(StoreError::Invariant(message))
                if message.contains("trust root must be established")
        ));
        migrated
            .validate()
            .expect("legacy-unbound migrated history remains explicitly quarantined");
    }

    #[test]
    fn exact_v4_upgrade_adds_empty_artifact_custody_without_synthesis() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("source-v4.db");
        let backup_path = directory.path().join("backup-v4.db");
        write_empty_exact_v4(&source);
        let backup = Store::backup_v4_verified(&source, &backup_path).expect("verified v4 backup");
        let receipt = exact_v4_to_v5_receipt(&backup);
        Store::upgrade_v4_to_v5(&source, &receipt).expect("exact v4 upgrades to v5");
        assert_eq!(
            Store::database_schema_version(&source).expect("source version"),
            5
        );
        assert_eq!(
            Store::database_schema_version(&backup_path).expect("backup version"),
            4
        );
        let migrated =
            Store::open_v5_upgrade_source_read_only(&source).expect("migrated v5 reopens");
        let commitment_count: i64 = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM diagnostic_artifact_commitments",
                [],
                |row| row.get(0),
            )
            .expect("artifact commitment count");
        assert_eq!(
            commitment_count, 0,
            "migration synthesized artifacts from schema-v4 absence"
        );
        validate_v5_upgrade_source_connection(&migrated.connection).expect("migrated v5 validates");
    }
}
