#![allow(missing_docs, clippy::doc_markdown, clippy::missing_errors_doc)]

//! Durable, profile-neutral storage for nq-ng.
//!
//! The schema deliberately separates byte-for-byte custody from admitted semantic
//! evidence. Durable facts are append-only. The two mutable tables are explicitly
//! rebuildable pointers to the latest finding and status events.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{SecondsFormat, Utc};
use nq_protocol::Sha256Digest;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCHEMA: &str = include_str!("schema.sql");
const APPLICATION_ID: i64 = 1_313_951_303;

/// Schema tag bound into every admission-context digest preimage. Bump only when
/// the constituent set or its canonicalization changes.
pub const ADMISSION_CONTEXT_SCHEMA: &str = "nq-ng.admission_context.v1";

/// Version of the persisted admitted-judgment representation. Bound into every
/// `judgment_digest` and stored beside the judgment so 3B verification pins the
/// exact format it is checking.
pub const JUDGMENT_SCHEMA_VERSION: &str = "nq-ng.judgment.v1";
static EXPECTED_SCHEMA_FINGERPRINT: LazyLock<Result<String, String>> = LazyLock::new(|| {
    let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
    connection
        .execute_batch(SCHEMA)
        .map_err(|error| error.to_string())?;
    schema_fingerprint(&connection).map_err(|error| error.to_string())
});

/// The only schema version understood by this crate.
pub const SCHEMA_VERSION: i64 = 1;

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

/// A typed refusal retained at its exact boundary and responsible instance.
#[derive(Clone, Debug)]
pub struct RefusalInput {
    pub refusal_id: String,
    pub source_kind: String,
    pub responsible_instance_id: String,
    pub boundary: String,
    pub code: String,
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
    run_instance_id: String,
    admission_instance_id: String,
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
    /// Explicitly create a v1 store. Existing schemas are never overwritten.
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

    /// Open only an already-initialized, exactly compatible v1 store.
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
        validate_refusal_invariants(&self.connection)?;
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
        transaction.commit()?;
        Ok(())
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
                "SELECT submission_id, instance_id, validated_report_json,
                        judgment_schema_version, judgment_digest, admission_context_digest
                 FROM admitted_reports WHERE report_id = ?1",
                [report_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| SnapshotVerificationError::BindingBroken(error.to_string()))?
            .ok_or_else(|| SnapshotVerificationError::ReportNotFound(report_id.to_owned()))?;
        let (
            submission_id,
            report_instance_id,
            validated_report_json,
            judgment_schema_version,
            stored_judgment_digest,
            report_context_digest,
        ) = report;

        // Reach the admission through the report's own run. A null admission_id
        // or missing row yields no result: an admitted report whose run has no
        // recorded admission is a broken binding, never a silent pass.
        let admission = self
            .connection
            .query_row(
                "SELECT run.instance_id, a.instance_id, a.admission_id, a.admission_context_digest,
                        a.config_digest, a.helper_artifact_digest, a.profile_semantic_id,
                        a.detector_identity_digest, a.evaluator_source_digest,
                        a.evaluator_artifact_digest, a.protocol_version,
                        a.artifact_identity_method, a.platform_runtime_version
                 FROM raw_submissions AS s
                 JOIN watcher_runs AS run ON run.run_id = s.run_id
                 JOIN admission_records AS a ON a.admission_id = run.admission_id
                 WHERE s.submission_id = ?1",
                [&submission_id],
                |row| {
                    Ok(StoredAdmissionConstituents {
                        run_instance_id: row.get(0)?,
                        admission_instance_id: row.get(1)?,
                        admission_id: row.get(2)?,
                        admission_context_digest: row.get(3)?,
                        config_digest: row.get(4)?,
                        helper_artifact_digest: row.get(5)?,
                        profile_semantic_id: row.get(6)?,
                        detector_identity_digest: row.get(7)?,
                        evaluator_source_digest: row.get(8)?,
                        evaluator_artifact_digest: row.get(9)?,
                        protocol_version: row.get(10)?,
                        artifact_identity_method: row.get(11)?,
                        platform_runtime_version: row.get(12)?,
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
        if report_context_digest != admission.admission_context_digest {
            return Err(SnapshotVerificationError::BindingBroken(format!(
                "report context {report_context_digest} is not the run's admission context {}",
                admission.admission_context_digest
            )));
        }
        if report_instance_id != admission.run_instance_id
            || report_instance_id != admission.admission_instance_id
        {
            return Err(SnapshotVerificationError::BindingBroken(format!(
                "instance {report_instance_id} does not match run {} / admission {}",
                admission.run_instance_id, admission.admission_instance_id
            )));
        }

        // Only recompute a judgment whose schema this binary owns; a foreign
        // schema version is surfaced, never recomputed under the wrong preimage.
        if judgment_schema_version != JUDGMENT_SCHEMA_VERSION {
            return Err(SnapshotVerificationError::UnsupportedJudgmentSchema {
                stored: judgment_schema_version,
                supported: JUDGMENT_SCHEMA_VERSION.to_owned(),
            });
        }

        // The stored judgment must recompute to its stored digest over exactly
        // the persisted judgment bytes and context — no re-evaluation.
        let validated = CanonicalDocument::from_canonical_bytes(validated_report_json.clone())
            .map_err(|error| {
                SnapshotVerificationError::JudgmentCorrupt(format!(
                    "persisted judgment is not canonical: {error}"
                ))
            })?;
        let recomputed_judgment = judgment_digest(&report_context_digest, validated.digest())
            .map_err(|error| SnapshotVerificationError::JudgmentCorrupt(error.to_string()))?;
        if recomputed_judgment != stored_judgment_digest {
            return Err(SnapshotVerificationError::JudgmentCorrupt(format!(
                "recomputed {recomputed_judgment} does not match stored {stored_judgment_digest}"
            )));
        }

        Ok(AdmittedSnapshot {
            report_id: report_id.to_owned(),
            admission_id: admission.admission_id,
            instance_id: report_instance_id,
            admission_context_digest: admission.admission_context_digest,
            judgment_schema_version,
            judgment_digest: stored_judgment_digest,
            validated_report_json,
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

    /// Atomically append acquisition, custody, admission, report, and observation rows.
    pub fn commit_collection(
        &mut self,
        collection: &CollectionInput,
    ) -> Result<CollectionReceipt, StoreError> {
        validate_collection(collection)?;
        let transaction = self.immediate_transaction()?;
        insert_run(&transaction, &collection.run)?;

        let mut receipt = CollectionReceipt {
            raw_sha256: None,
            semantic_digest: None,
            report_sequence: None,
            refusal_id: None,
        };
        if let Some(submission) = &collection.submission {
            let raw_sha256 = sha256_digest(&submission.raw_bytes);
            let (admission_outcome, rejection_code) = match &submission.disposition {
                SubmissionDisposition::Rejected { refusal } => {
                    ("rejected", Some(refusal.code.as_str()))
                }
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
                        &transaction,
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
                    // A run that produced an admitted report must carry a
                    // complete admission context. Resolve it here (fail closed)
                    // and bind the report to exactly that context; the trigger
                    // rejects any other value at the database boundary.
                    let admission_id = collection.run.admission_id.as_deref().ok_or_else(|| {
                        StoreError::Invariant(
                            "an admitted report requires a run bound to an admission".to_owned(),
                        )
                    })?;
                    let (admission_instance_id, admission_context_digest): (String, String) =
                        transaction
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
                    // The named admission must govern this run's own instance; a
                    // run may not borrow another instance's admission context.
                    if admission_instance_id != collection.run.instance_id {
                        return Err(StoreError::Invariant(format!(
                            "run instance {} cannot bind admission {admission_id} of instance {admission_instance_id}",
                            collection.run.instance_id
                        )));
                    }
                    let sequence = insert_report(
                        &transaction,
                        &submission.submission_id,
                        report,
                        &admission_context_digest,
                    )?;
                    receipt.semantic_digest = Some(report.canonical_report.digest().to_owned());
                    receipt.report_sequence = Some(sequence);
                }
            }
        }
        transaction.commit()?;
        Ok(receipt)
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

    /// Enumerate rejected custody with its exact linked typed refusal.
    ///
    /// The result is bounded and ordered by immutable run/submission identity.
    /// Validation guarantees that every returned rejection has exactly one
    /// matching refusal; this method never guesses from a coarse code or log.
    pub fn rejected_custody(&self, limit: u32) -> Result<Vec<RejectedCustodyRow>, StoreError> {
        validate_public_limit(limit)?;
        // Refuse rather than expose a partial or ambiguous history if the live
        // connection has acquired an invalid row since it was opened.
        validate_refusal_invariants(&self.connection)?;
        let mut statement = self.connection.prepare(
            "SELECT submission.submission_id, submission.run_id, run.request_id,
                    run.instance_id, run.profile_id, run.profile_version,
                    run.profile_digest, submission.raw_sha256,
                    submission.received_at, submission.protocol_outcome,
                    refusal.refusal_id, refusal.source_kind,
                    refusal.responsible_instance_id, refusal.boundary,
                    refusal.code, refusal.detail_json, refusal.created_at
             FROM raw_submissions AS submission
             JOIN watcher_runs AS run ON run.run_id = submission.run_id
             JOIN refusals AS refusal
               ON refusal.submission_id = submission.submission_id
             WHERE submission.admission_outcome = 'rejected'
             ORDER BY run.started_at, submission.submission_id
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], rejected_custody_row)?;
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
                        run.profile_digest, submission.raw_sha256,
                        submission.received_at, submission.protocol_outcome,
                        refusal.refusal_id, refusal.source_kind,
                        refusal.responsible_instance_id, refusal.boundary,
                        refusal.code, refusal.detail_json, refusal.created_at
                 FROM raw_submissions AS submission
                 JOIN watcher_runs AS run ON run.run_id = submission.run_id
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
    /// Exact watermarks returned by [`Store::evidence_snapshot`].
    pub watermarks: Vec<EvaluationWatermark>,
    pub refusal: Option<RefusalInput>,
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
    pub evaluation_revision: u64,
    pub watermarks: Vec<EvaluationWatermark>,
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

/// One row from the stable `nq.finding_snapshot.v2` public read model.
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
        let mut instances = BTreeSet::new();
        instances.extend(instance_ids.iter().cloned());
        let mut watermarks = Vec::with_capacity(instances.len());
        let mut reports = Vec::new();
        for instance_id in instances {
            let max_report_sequence: i64 = transaction.query_row(
                "SELECT COALESCE(MAX(report_sequence), 0)
                 FROM admitted_reports WHERE instance_id = ?1",
                [&instance_id],
                |row| row.get(0),
            )?;
            let watermark_received_at = if max_report_sequence == 0 {
                None
            } else {
                transaction.query_row(
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

            let mut statement = transaction.prepare(
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
        transaction.commit()?;
        Ok(EvidenceSnapshot {
            watermarks,
            reports,
        })
    }

    /// Return the newest committed non-null checkpoint for one instance.
    /// Rejected submissions and uncommitted reports can never advance it.
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
    pub fn commit_evaluation(
        &mut self,
        evaluation: &EvaluationInput,
        finding: Option<&FindingEventInput>,
    ) -> Result<EvaluationReceipt, StoreError> {
        validate_digest("detector_digest", &evaluation.detector_digest)?;
        validate_digest(
            "evaluator_artifact_digest",
            &evaluation.evaluator_artifact_digest,
        )?;
        if (evaluation.outcome == "cannot_evaluate") != evaluation.refusal.is_some() {
            return Err(StoreError::Invariant(
                "cannot_evaluate requires exactly one typed refusal".to_owned(),
            ));
        }
        if let Some(finding) = finding {
            validate_finding_against_evaluation(finding, evaluation)?;
        }

        let transaction = self.immediate_transaction()?;
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
        transaction.execute(
            "INSERT INTO evaluation_runs (
                evaluation_id, detector_id, detector_version, detector_digest,
                evaluation_revision, started_at, evaluated_at, outcome, detail_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                evaluation.evaluation_id,
                evaluation.detector_id,
                evaluation.detector_version,
                evaluation.detector_digest,
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
            validate_watermark(&transaction, watermark)?;
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
            insert_refusal(
                &transaction,
                refusal,
                None,
                None,
                Some(&evaluation.evaluation_id),
                None,
            )?;
        }
        if let Some(finding) = finding {
            insert_finding_event(
                &transaction,
                evaluation,
                evaluation_revision,
                finding,
                &watermarks,
            )?;
        }
        transaction.commit()?;
        Ok(EvaluationReceipt {
            evaluation_id: evaluation.evaluation_id.clone(),
            evaluation_revision: u64::try_from(evaluation_revision).map_err(|_| {
                StoreError::Invariant("allocated a negative evaluation revision".to_owned())
            })?,
            watermarks,
        })
    }

    /// Read the complete stable finding projection in opaque finding-id order.
    pub fn finding_snapshots(&self) -> Result<Vec<FindingSnapshotRow>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT finding_id, instance_id, detector_id, detector_version,
                    detector_digest, evaluation_revision, profile_id, profile_version,
                    profile_digest, subject_json, condition_name, condition_state, visibility_state,
                    operator_work_state, severity, summary, limitations_json,
                    safe_next_checks_json, freshness_json, basis_json, refusal_json,
                    origin_mode, historical_refs_json, observed_at, received_at,
                    evaluated_at, evidence_json
             FROM public_finding_snapshot_v2 ORDER BY finding_id",
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
                subject_json: row.get(9)?,
                condition_name: row.get(10)?,
                condition_state: row.get(11)?,
                visibility_state: row.get(12)?,
                operator_work_state: row.get(13)?,
                severity: row.get(14)?,
                summary: row.get(15)?,
                limitations_json: row.get(16)?,
                safe_next_checks_json: row.get(17)?,
                freshness_json: row.get(18)?,
                basis_json: row.get(19)?,
                refusal_json: row.get(20)?,
                origin_mode: row.get(21)?,
                historical_refs_json: row.get(22)?,
                observed_at: row.get(23)?,
                received_at: row.get(24)?,
                evaluated_at: row.get(25)?,
                evidence_json: row.get(26)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
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
                    profile_digest, subject_json, condition_name, condition_state, visibility_state,
                    operator_work_state, severity, summary, limitations_json,
                    safe_next_checks_json, freshness_json, basis_json, refusal_json,
                    origin_mode, historical_refs_json, observed_at, received_at,
                    evaluated_at, evidence_json
             FROM public_finding_snapshot_v2
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
                subject_json: row.get(9)?,
                condition_name: row.get(10)?,
                condition_state: row.get(11)?,
                visibility_state: row.get(12)?,
                operator_work_state: row.get(13)?,
                severity: row.get(14)?,
                summary: row.get(15)?,
                limitations_json: row.get(16)?,
                safe_next_checks_json: row.get(17)?,
                freshness_json: row.get(18)?,
                basis_json: row.get(19)?,
                refusal_json: row.get(20)?,
                origin_mode: row.get(21)?,
                historical_refs_json: row.get(22)?,
                observed_at: row.get(23)?,
                received_at: row.get(24)?,
                evaluated_at: row.get(25)?,
                evidence_json: row.get(26)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Append a status event and atomically advance only its rebuildable pointer.
    pub fn record_status(&mut self, status: &StatusEventInput) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        transaction.execute(
            "INSERT INTO status_events (
                status_event_id, component_kind, component_id, state, code,
                detail_json, observed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                status.status_event_id,
                status.component_kind,
                status.component_id,
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
        validate_digest("binary_digest", &receipt.binary_digest)?;
        validate_digest("backup_digest", &receipt.backup_digest)?;
        let transaction = self.immediate_transaction()?;
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
        transaction.commit()?;
        Ok(())
    }
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
        "instance_binding_events",
        "binding_materialization_events",
        "watcher_runs",
        "raw_submissions",
        "admitted_reports",
        "observations",
        "report_coverage",
        "observation_coverage",
        "report_errors",
        "evaluation_runs",
        "evaluation_watermarks",
        "refusals",
        "finding_events",
        "finding_evidence",
        "finding_current",
        "notification_outbox",
        "notification_attempts",
        "retention_tombstones",
        "genesis_records",
        "legacy_references",
        "upgrade_receipts",
        "status_events",
        "status_current",
    ];
    const VIEWS: &[&str] = &[
        "public_finding_snapshot_v2",
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

/// Prove that every rejected custody row has one exact typed refusal and that
/// every duplicated projection agrees with the refusal's originating run.
///
/// Schema v1 already stores the full association in `refusals.submission_id`;
/// these semantic checks make that existing representation fail closed without
/// inventing testimony for historical rows or changing the schema artifact.
fn validate_refusal_invariants(connection: &Connection) -> Result<(), StoreError> {
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
             WHERE submission.admission_outcome = 'rejected'
               AND (
                    submission.rejection_code IS NOT refusal.code
                 OR refusal.run_id IS NOT submission.run_id
                 OR refusal.responsible_instance_id IS NOT run.instance_id
                 OR refusal.profile_id IS NOT run.profile_id
                 OR refusal.profile_version IS NOT run.profile_version
                 OR refusal.profile_digest IS NOT run.profile_digest
                 OR refusal.evaluation_id IS NOT NULL
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
        raw_sha256: row.get(7)?,
        received_at: row.get(8)?,
        protocol_outcome: row.get(9)?,
        refusal_id: row.get(10)?,
        source_kind: row.get(11)?,
        responsible_instance_id: row.get(12)?,
        boundary: row.get(13)?,
        code: row.get(14)?,
        detail_json: row.get(15)?,
        created_at: row.get(16)?,
    })
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

fn validate_collection(collection: &CollectionInput) -> Result<(), StoreError> {
    validate_digest("binding_digest", &collection.run.binding_digest)?;
    validate_digest(
        "checkpoint_contract_digest",
        &collection.run.checkpoint_contract_digest,
    )?;
    validate_digest("profile_digest", &collection.run.profile_digest)?;
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

fn insert_run(transaction: &Transaction<'_>, run: &RunInput) -> Result<(), StoreError> {
    validate_digest(
        "checkpoint_contract_digest",
        &run.checkpoint_contract_digest,
    )?;
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
    let (profile_id, profile_version, profile_digest) = profile
        .map_or((None, None, None), |(id, version, digest)| {
            (Some(id), Some(version), Some(digest))
        });
    transaction.execute(
        "INSERT INTO refusals (
            refusal_id, source_kind, responsible_instance_id, boundary, code,
            run_id, submission_id, evaluation_id, profile_id, profile_version,
            profile_digest, detail_json, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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

fn validate_finding_against_evaluation(
    finding: &FindingEventInput,
    evaluation: &EvaluationInput,
) -> Result<(), StoreError> {
    validate_digest("profile_digest", &finding.profile_digest)?;
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
    let current: Option<(i64, String)> = transaction
        .query_row(
            "SELECT e.event_revision, e.event_kind
             FROM finding_current AS c
             JOIN finding_events AS e ON e.event_id = c.latest_event_id
             WHERE c.finding_id = ?1",
            [&finding.finding_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
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
    let event_revision = current.as_ref().map_or(Ok(1_i64), |(revision, _)| {
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

    fn configured_store() -> (Store, String) {
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let profile_digest = append_fixture_descriptor(&mut store);
        (store, profile_digest)
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
            detector_identity_digest: typed_digest("detector-identity"),
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
        store
            .append_admission(&AdmissionInput {
                admission_id: admission_id.to_owned(),
                instance_id: instance_id.to_owned(),
                identity: fixture_identity(),
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
            finished_at: "2026-07-16T12:00:01.000Z".to_owned(),
            acquisition_outcome: "response".to_owned(),
            execution_identity: document(json!({"uid": 991})),
            resource_outcome: document(json!({"exit_code": 0})),
        }
    }

    fn report(
        instance_id: &str,
        suffix: &str,
        profile_digest: &str,
        canonical_report: CanonicalDocument,
    ) -> ReportInput {
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
                "schema": "fixture.validated_report",
                "instance_id": instance_id,
                "report": suffix,
            })),
            next_checkpoint: None,
            admitted_at: TIME.to_owned(),
            observations: vec![ObservationInput {
                ordinal: 0,
                kind: "fixture.state".to_owned(),
                subject: document(json!({"fixture": suffix})),
                observed_at: TIME.to_owned(),
                payload: document(json!({"healthy": true})),
                coverage: vec![CoverageInput {
                    ordinal: 0,
                    coverage_kind: "subject".to_owned(),
                    coverage_state: "covered".to_owned(),
                    detail: document(json!({})),
                }],
            }],
            coverage: vec![CoverageInput {
                ordinal: 0,
                coverage_kind: "inventory".to_owned(),
                coverage_state: "complete".to_owned(),
                detail: document(json!({"enumerated": true})),
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
        store
            .commit_collection(&CollectionInput {
                run: bound_run,
                submission: Some(SubmissionInput {
                    submission_id: format!("submission-{suffix}"),
                    raw_bytes,
                    received_at: TIME.to_owned(),
                    protocol_outcome: "valid_exchange".to_owned(),
                    disposition: SubmissionDisposition::Admitted(report(
                        instance_id,
                        suffix,
                        profile_digest,
                        canonical_report,
                    )),
                }),
            })
            .expect("collection commits")
    }

    fn commit_rejected(
        store: &mut Store,
        suffix: &str,
        profile_digest: &str,
        refusal_id: &str,
        code: &str,
        detail: CanonicalDocument,
    ) -> CollectionReceipt {
        store
            .commit_collection(&CollectionInput {
                run: run("fixture-a", suffix, profile_digest),
                submission: Some(SubmissionInput {
                    submission_id: format!("submission-{suffix}"),
                    raw_bytes: format!("raw-{suffix}\n").into_bytes(),
                    received_at: TIME.to_owned(),
                    protocol_outcome: "valid_refusal".to_owned(),
                    disposition: SubmissionDisposition::Rejected {
                        refusal: RefusalInput {
                            refusal_id: refusal_id.to_owned(),
                            source_kind: "protocol".to_owned(),
                            responsible_instance_id: "fixture-a".to_owned(),
                            boundary: "collection".to_owned(),
                            code: code.to_owned(),
                            detail,
                            created_at: TIME.to_owned(),
                        },
                    },
                }),
            })
            .expect("rejected collection commits")
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

    /// Model an existing schema-v1 database written outside the typed Store API.
    /// The schema can represent these rows, but the product must refuse to reopen
    /// any association that cannot prove its exact typed refusal linkage.
    fn historical_rejection_with(defect: HistoricalRefusalDefect) -> Store {
        let (mut store, profile_digest) = configured_store();
        let suffix = "historical";
        store
            .commit_collection(&CollectionInput {
                run: run("fixture-a", suffix, &profile_digest),
                submission: None,
            })
            .expect("historical run commits");
        if matches!(defect, HistoricalRefusalDefect::WrongRun) {
            store
                .commit_collection(&CollectionInput {
                    run: run("fixture-b", "other", &profile_digest),
                    submission: None,
                })
                .expect("alternate historical run commits");
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
            .expect("test changes version");
        drop(store);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::SchemaVersionMismatch {
                found: 2,
                supported: SCHEMA_VERSION
            })
        ));

        let empty_path = directory.path().join("empty.db");
        std::fs::File::create(&empty_path).expect("empty file");
        Store::initialize(&empty_path).expect("zero-byte placeholder can be initialized");
    }

    #[test]
    fn raw_submission_is_byte_exact_and_rejected_evidence_is_isolated() {
        let (mut store, profile_digest) = configured_store();
        let raw = vec![0, 0xff, b'\n', b'{', b'}', 0];
        let receipt = store
            .commit_collection(&CollectionInput {
                run: run("fixture-a", "rejected", &profile_digest),
                submission: Some(SubmissionInput {
                    submission_id: "submission-rejected".to_owned(),
                    raw_bytes: raw.clone(),
                    received_at: TIME.to_owned(),
                    protocol_outcome: "malformed_framing".to_owned(),
                    disposition: SubmissionDisposition::Rejected {
                        refusal: RefusalInput {
                            refusal_id: "refusal-rejected".to_owned(),
                            source_kind: "protocol".to_owned(),
                            responsible_instance_id: "fixture-a".to_owned(),
                            boundary: "response_frame".to_owned(),
                            code: "malformed_json".to_owned(),
                            detail: document(json!({"offset": 1})),
                            created_at: TIME.to_owned(),
                        },
                    },
                }),
            })
            .expect("rejected custody commits");
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

    /// Release regression: a historical/raw writer cannot append rejected
    /// custody without the typed testimony required for reopening.
    #[test]
    fn forcing_rejected_submission_requires_typed_refusal() {
        let (mut store, profile_digest) = configured_store();
        let raw = b"malformed helper response\n";
        store
            .commit_collection(&CollectionInput {
                run: run("fixture-a", "missing-refusal", &profile_digest),
                submission: None,
            })
            .expect("run commits before hostile raw insertion");
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
            .expect("schema v1 deliberately permits the historical hostile row");
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
            .expect("schema v1 permits duplicate historical linkage");
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
            .expect("schema v1 permits hostile admitted linkage");
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
        let mut store = Store::initialize_in_memory().expect("store initializes");
        let unknown_digest = digest("unknown-profile");
        let mut unknown_run = run("fixture-unknown", "unknown", &unknown_digest);
        unknown_run.profile_id = "unknown.profile".to_owned();
        unknown_run.profile_version = "99".to_owned();
        store
            .commit_collection(&CollectionInput {
                run: unknown_run,
                submission: Some(SubmissionInput {
                    submission_id: "submission-unknown".to_owned(),
                    raw_bytes: b"{\"claimed_profile\":\"unknown.profile\"}\n".to_vec(),
                    received_at: TIME.to_owned(),
                    protocol_outcome: "valid_json".to_owned(),
                    disposition: SubmissionDisposition::Rejected {
                        refusal: RefusalInput {
                            refusal_id: "refusal-unknown".to_owned(),
                            source_kind: "profile".to_owned(),
                            responsible_instance_id: "fixture-unknown".to_owned(),
                            boundary: "profile_registry".to_owned(),
                            code: "unknown_profile".to_owned(),
                            detail: document(json!({"profile_id": "unknown.profile"})),
                            created_at: TIME.to_owned(),
                        },
                    },
                }),
            })
            .expect("unknown profile is retained as rejected custody");
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
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "condition_present".to_owned(),
            detail: document(json!({})),
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

        let refused_evaluation = EvaluationInput {
            evaluation_id: "evaluation-refused".to_owned(),
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "cannot_evaluate".to_owned(),
            detail: document(json!({})),
            watermarks: snapshot.watermarks.clone(),
            refusal: Some(RefusalInput {
                refusal_id: "evaluation-refusal".to_owned(),
                source_kind: "evaluation".to_owned(),
                responsible_instance_id: "fixture-a".to_owned(),
                boundary: "detector".to_owned(),
                code: "evidence_stale".to_owned(),
                detail: document(json!({})),
                created_at: TIME.to_owned(),
            }),
        };
        let mut stale_update = opened.clone();
        stale_update.event_id = "event-stale".to_owned();
        stale_update.event_kind = "updated".to_owned();
        stale_update.visibility_state = "stale".to_owned();
        stale_update.freshness = document(json!({"state": "stale"}));
        stale_update.refusal = Some(document(json!({
            "boundary": "detector",
            "code": "evidence_stale",
            "responsible_instance_id": "fixture-a"
        })));
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

        let refused_resolution_evaluation = EvaluationInput {
            evaluation_id: "evaluation-refused-resolution".to_owned(),
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "cannot_evaluate".to_owned(),
            detail: document(json!({})),
            watermarks: snapshot.watermarks.clone(),
            refusal: Some(RefusalInput {
                refusal_id: "evaluation-refusal-resolution".to_owned(),
                source_kind: "evaluation".to_owned(),
                responsible_instance_id: "fixture-a".to_owned(),
                boundary: "detector".to_owned(),
                code: "evidence_stale".to_owned(),
                detail: document(json!({})),
                created_at: TIME.to_owned(),
            }),
        };
        let mut invalid_resolution = stale_update.clone();
        invalid_resolution.event_id = "event-invalid-resolution".to_owned();
        invalid_resolution.event_kind = "resolved".to_owned();
        invalid_resolution.condition_state = "explicitly_absent".to_owned();
        invalid_resolution.visibility_state = "sufficient".to_owned();
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
            detector_id: "fixture.unhealthy".to_owned(),
            detector_version: "1".to_owned(),
            detector_digest: digest("detector-v1"),
            evaluator_artifact_digest: digest("evaluator-artifact"),
            started_at: TIME.to_owned(),
            evaluated_at: TIME.to_owned(),
            outcome: "condition_explicitly_absent".to_owned(),
            detail: document(json!({})),
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
            store
                .commit_collection(&CollectionInput {
                    run,
                    submission: Some(SubmissionInput {
                        submission_id: format!("submission-{suffix}"),
                        raw_bytes: suffix.as_bytes().to_vec(),
                        received_at: TIME.to_owned(),
                        protocol_outcome: "valid_exchange".to_owned(),
                        disposition: SubmissionDisposition::Admitted(admitted),
                    }),
                })
                .expect("admitted checkpoint");
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
        let unbound = run("fixture-a", "a", &profile_digest);
        let error = store
            .commit_collection(&CollectionInput {
                run: unbound,
                submission: Some(SubmissionInput {
                    submission_id: "submission-a".to_owned(),
                    raw_bytes: b"raw".to_vec(),
                    received_at: TIME.to_owned(),
                    protocol_outcome: "valid_exchange".to_owned(),
                    disposition: SubmissionDisposition::Admitted(report(
                        "fixture-a",
                        "a",
                        &profile_digest,
                        document(json!({"report": "a"})),
                    )),
                }),
            })
            .expect_err("an admitted report requires a run bound to an admission");
        assert!(
            matches!(error, StoreError::Invariant(message) if message.contains("bound to an admission"))
        );
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
        let error = store
            .commit_collection(&CollectionInput {
                run: foreign,
                submission: Some(SubmissionInput {
                    submission_id: "submission-b".to_owned(),
                    raw_bytes: b"raw".to_vec(),
                    received_at: TIME.to_owned(),
                    protocol_outcome: "valid_exchange".to_owned(),
                    disposition: SubmissionDisposition::Admitted(report(
                        "instance-b",
                        "b",
                        &profile_digest,
                        document(json!({"report": "b"})),
                    )),
                }),
            })
            .expect_err("a run cannot borrow another instance's admission");
        assert!(
            matches!(error, StoreError::Invariant(message) if message.contains("cannot bind admission"))
        );
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
}
