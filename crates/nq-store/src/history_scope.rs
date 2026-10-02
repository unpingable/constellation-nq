//! Bounded history validation: the append frontier, the scope a validator
//! covers, and the digest-bound validation watermark.
//!
//! Every history table is append-only (update/delete triggers abort, and the
//! schema fingerprint proves those triggers exist on every open). Rowids
//! therefore grow monotonically in append order. A completed full validation
//! records the per-table frontier it covered; a later open validates only rows
//! beyond that frontier, after proving that the rows at or below it are still
//! the rows that were validated (per-table row counts plus a digest over the
//! commitment identities).
//!
//! The watermark is advisory in one direction only: when it is absent,
//! unreadable, or bound to another store, schema, or rule set, the store is
//! validated in full. It never makes an unvalidated row count as validated.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CanonicalDocument, StoreError};

/// Watermark document schema.
pub const VALIDATION_WATERMARK_SCHEMA: &str = "nq.validation_watermark.v1";

/// Identity of the validation rules a watermark vouches for. Any change to
/// what full validation checks must change this value so that existing
/// watermarks stop applying and the next open validates in full.
pub const VALIDATION_RULES: &str = concat!("nq-store/", env!("CARGO_PKG_VERSION"), "/rules.1");

/// Every append-only history table. The frontier covers all of them so that a
/// row appended at or below a recorded bound (which append-only writers never
/// do) is detected as a count mismatch.
pub(crate) const HISTORY_TABLES: &[&str] = &[
    "admission_records",
    "admitted_reports",
    "binding_materialization_events",
    "diagnostic_artifact_commitments",
    "diagnostic_artifact_import_events",
    "diagnostic_artifact_payloads",
    "evaluation_runs",
    "evaluation_watermarks",
    "finding_events",
    "finding_evidence",
    "genesis_records",
    "imported_diagnostic_artifact_origins",
    "instance_binding_events",
    "legacy_references",
    "legacy_v3_watcher_run_intake_gaps",
    "local_diagnostic_artifact_origins",
    "local_provider_admissions",
    "local_successor_acquisition_events",
    "local_successor_acquisition_intents",
    "local_watcher_provider_intakes",
    "maintenance_declarations",
    "notification_attempts",
    "notification_delivery_events",
    "notification_delivery_intents",
    "notification_outbox",
    "observation_coverage",
    "observations",
    "profile_descriptor_snapshots",
    "provider_intake_acknowledgments",
    "provider_intake_attempts",
    "raw_submissions",
    "refusals",
    "report_coverage",
    "report_errors",
    "retention_tombstones",
    "saved_check_definitions",
    "saved_check_events",
    "status_events",
    "upgrade_receipts",
    "watcher_runs",
];

/// Commitment identities bound into the watermark digest: each validated
/// row's rowid and stable identity, read through the identity's own index.
/// Substituting, removing, or inserting one of these rows at or below the
/// frontier changes the digest. Payload bytes behind an unchanged identity
/// are re-proven only by full validation.
const COMMITMENT_IDENTITIES: &[(&str, &str)] = &[
    ("diagnostic_artifact_commitments", "artifact_id"),
    ("provider_intake_attempts", "intake_id"),
    ("watcher_runs", "run_id"),
    ("raw_submissions", "submission_id"),
    ("admitted_reports", "report_id"),
    ("evaluation_runs", "evaluation_id"),
    ("status_events", "status_event_id"),
    ("local_successor_acquisition_intents", "acquisition_id"),
];

/// The append position of one history table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableFrontier {
    /// Highest rowid present, or `None` when the table was empty.
    pub max_rowid: Option<i64>,
    /// Rows at or below `max_rowid`.
    pub rows: i64,
}

/// Per-table append positions plus the evaluation sequence, which history
/// paging uses instead of the rowid.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryFrontier {
    /// Append position of each history table.
    pub tables: BTreeMap<String, TableFrontier>,
    /// Highest evaluation append sequence at or below the frontier.
    pub evaluation_sequence: i64,
}

impl HistoryFrontier {
    /// Read the current append position and row count of every history
    /// table, as a watermark records it.
    pub(crate) fn capture(connection: &Connection) -> Result<Self, StoreError> {
        Self::read(connection, true)
    }

    /// Read only the append positions (each an O(log n) rowid lookup). Row
    /// counts are left at zero: such a frontier scopes writers and is never
    /// recorded as a watermark.
    pub(crate) fn capture_bounds(connection: &Connection) -> Result<Self, StoreError> {
        Self::read(connection, false)
    }

    fn read(connection: &Connection, with_counts: bool) -> Result<Self, StoreError> {
        let mut tables = BTreeMap::new();
        for table in HISTORY_TABLES {
            let count = if with_counts {
                format!("(SELECT COUNT(*) FROM {table})")
            } else {
                "0".to_owned()
            };
            let (max_rowid, rows): (Option<i64>, i64) = connection.query_row(
                &format!("SELECT (SELECT MAX(rowid) FROM {table}), {count}"),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            tables.insert((*table).to_owned(), TableFrontier { max_rowid, rows });
        }
        let evaluation_sequence = connection.query_row(
            "SELECT COALESCE(MAX(evaluation_sequence), 0) FROM evaluation_runs",
            [],
            |row| row.get(0),
        )?;
        Ok(Self {
            tables,
            evaluation_sequence,
        })
    }

    /// The highest rowid covered for `table`, or `None` when no row of it is
    /// covered (so every row is beyond the frontier).
    #[must_use]
    pub fn max_rowid(&self, table: &str) -> Option<i64> {
        self.tables
            .get(table)
            .and_then(|frontier| frontier.max_rowid)
    }

    /// Prove that the rows at or below this frontier are exactly the rows that
    /// were present when it was captured: the same count, and the bounding row
    /// still present. Append-only writers can only add rows above it.
    fn verify_unchanged(&self, connection: &Connection) -> Result<(), StoreError> {
        for table in HISTORY_TABLES {
            let recorded = self.tables.get(*table).copied().ok_or_else(|| {
                StoreError::Integrity(format!(
                    "validation watermark has no frontier for history table {table}"
                ))
            })?;
            let Some(bound) = recorded.max_rowid else {
                // Empty when validated: every present row is beyond the
                // frontier and is validated as new.
                if recorded.rows != 0 {
                    return Err(watermark_mismatch(table));
                }
                continue;
            };
            // COUNT(*) without a predicate uses the smallest index; only the
            // rows beyond the bound are walked by rowid.
            let (total, beyond, bounding): (i64, i64, i64) = connection.query_row(
                &format!(
                    "SELECT (SELECT COUNT(*) FROM {table}),
                            (SELECT COUNT(*) FROM {table} WHERE rowid > ?1),
                            (SELECT COUNT(*) FROM {table} WHERE rowid = ?1)"
                ),
                [bound],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            if total - beyond != recorded.rows || bounding != 1 {
                return Err(watermark_mismatch(table));
            }
        }
        Ok(())
    }

    /// Digest over the commitment identities at or below this frontier.
    fn commitment_digest(&self, connection: &Connection) -> Result<String, StoreError> {
        let mut hasher = Sha256::new();
        hasher.update(VALIDATION_WATERMARK_SCHEMA.as_bytes());
        for (table, column) in COMMITMENT_IDENTITIES {
            hasher.update(b"\ntable\0");
            hasher.update(table.as_bytes());
            let Some(bound) = self.max_rowid(table) else {
                continue;
            };
            // Selecting only the identity and rowid lets SQLite answer from
            // the identity's covering index instead of reading row payloads.
            let mut statement =
                connection.prepare(&format!("SELECT rowid, {column} FROM {table}"))?;
            let mut rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .filter(|row| row.as_ref().map_or(true, |(rowid, _)| *rowid <= bound))
                .collect::<Result<Vec<_>, _>>()?;
            rows.sort_unstable_by_key(|(rowid, _)| *rowid);
            for (rowid, identity) in rows {
                hasher.update(rowid.to_be_bytes());
                hasher.update(
                    u64::try_from(identity.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                hasher.update(identity.as_bytes());
            }
        }
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

fn watermark_mismatch(table: &str) -> StoreError {
    StoreError::Integrity(format!(
        "history table {table} no longer matches its validation watermark: rows at or below \
         the validated frontier were added, removed, or substituted; run \
         `nq admin validate --full` to re-establish validation"
    ))
}

/// Which history rows a validator must examine.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scope<'a> {
    after: Option<&'a HistoryFrontier>,
}

impl<'a> Scope<'a> {
    /// Every row: the full validation.
    pub(crate) const FULL: Scope<'static> = Scope { after: None };

    /// Only rows beyond `frontier`, whose rows were already validated.
    pub(crate) fn after(frontier: &'a HistoryFrontier) -> Self {
        Self {
            after: Some(frontier),
        }
    }

    pub(crate) fn is_full(self) -> bool {
        self.after.is_none()
    }

    /// SQL predicate selecting rows of `table` (aliased `alias`) beyond the
    /// frontier; `1` (every row) for a full scope or an uncovered table.
    pub(crate) fn new_rows(self, table: &str, alias: &str) -> String {
        match self.after.and_then(|frontier| frontier.max_rowid(table)) {
            Some(bound) => format!("{alias}.rowid > {bound}"),
            None => "1".to_owned(),
        }
    }

    /// SQL predicate selecting the parent rows whose validation obligations
    /// may have changed: the parent row is new, or a new row in one of the
    /// `children` tables names it through the given column. `1` for a full
    /// scope, so full validation runs the original unrestricted query.
    pub(crate) fn affected(
        self,
        key: &str,
        parent_table: &str,
        parent_alias: &str,
        children: &[(&str, &str)],
    ) -> String {
        if self.is_full() {
            return "1".to_owned();
        }
        let mut terms = vec![self.new_rows(parent_table, parent_alias)];
        for (table, column) in children {
            terms.push(format!(
                "{key} IN (SELECT child.{column} FROM {table} AS child WHERE {})",
                self.new_rows(table, "child")
            ));
        }
        format!("({})", terms.join(" OR "))
    }
}

/// A completed validation, bound to one store, schema, and rule set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationWatermark {
    /// Always [`VALIDATION_WATERMARK_SCHEMA`].
    pub schema: String,
    /// The [`VALIDATION_RULES`] that produced it.
    pub validation_rules: String,
    /// The store's sole genesis identity.
    pub genesis_id: String,
    /// Schema version of the validated store.
    pub schema_version: i64,
    /// Schema artifact digest of the validated store.
    pub schema_artifact_digest: String,
    /// Frontier through which store validation and the provider-intake and
    /// diagnostic-artifact history were proven (what every engine open
    /// validates).
    pub frontier: HistoryFrontier,
    /// Digest over the commitment identities at or below `frontier`.
    pub commitment_digest: String,
    /// Frontier, never beyond `frontier`, through which the complete semantic
    /// history (admitted reports, runs, status, rejected custody, evaluation
    /// and finding replay) was also proven; `None` when not established.
    pub semantic_frontier: Option<HistoryFrontier>,
    /// When the covered validation completed.
    pub validated_at: String,
}

/// Why an open validated history in full.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FullValidationReason {
    /// No watermark file exists.
    NoWatermark,
    /// The watermark could not be read or decoded.
    UnreadableWatermark,
    /// The watermark belongs to another store, schema, or rule set.
    InapplicableWatermark,
    /// The caller required full validation.
    Requested,
    /// The handle has no backing file (in-memory or immutable archive).
    NoBackingFile,
}

/// How history was validated when a handle opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenValidation {
    /// Every history row was validated.
    Full(FullValidationReason),
    /// Rows at or below the watermark frontier were proven unchanged; only
    /// rows beyond it were validated.
    SinceWatermark {
        /// Frontier of the store-level and core history certification.
        frontier: Box<HistoryFrontier>,
        /// Frontier of the semantic history certification, if established.
        semantic_frontier: Option<Box<HistoryFrontier>>,
    },
}

/// Whether a recorded watermark also certifies the complete semantic history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticCertification {
    /// The caller validated every semantic plane beyond the handle's prior
    /// semantic frontier (or in full) and it now extends to the open frontier.
    Established,
    /// The semantic history is not certified by this watermark.
    NotEstablished,
}

impl HistoryFrontier {
    /// Whether every table bound of `self` is at or below that of `other`.
    fn within(&self, other: &Self) -> bool {
        self.evaluation_sequence <= other.evaluation_sequence
            && self.tables.iter().all(|(table, frontier)| {
                match (frontier.max_rowid, other.max_rowid(table)) {
                    (None, _) => true,
                    (Some(_), None) => false,
                    (Some(mine), Some(theirs)) => mine <= theirs,
                }
            })
    }
}

/// Sidecar path holding the watermark for `database`.
#[must_use]
pub fn watermark_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(".validation-watermark.json");
    PathBuf::from(name)
}

pub(crate) struct StoreIdentity {
    pub genesis_id: String,
    pub schema_version: i64,
    pub schema_artifact_digest: String,
}

/// Read and decode the sidecar without consulting the database.
pub(crate) fn read_watermark(database: &Path) -> Result<ValidationWatermark, FullValidationReason> {
    let bytes = match std::fs::read(watermark_path(database)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(FullValidationReason::NoWatermark);
        }
        Err(_) => return Err(FullValidationReason::UnreadableWatermark),
    };
    let watermark = serde_json::from_slice::<ValidationWatermark>(&bytes)
        .map_err(|_| FullValidationReason::UnreadableWatermark)?;
    if watermark.schema != VALIDATION_WATERMARK_SCHEMA
        || watermark.validation_rules != VALIDATION_RULES
    {
        return Err(FullValidationReason::InapplicableWatermark);
    }
    Ok(watermark)
}

/// Decide whether a decoded watermark belongs to this store and schema, then
/// prove the rows at or below its frontier unchanged. A watermark for another
/// store or schema is ignored (full validation follows); one that belongs to
/// this store but no longer matches its rows fails closed, because validated
/// history changed.
pub(crate) fn verify_watermark(
    connection: &Connection,
    watermark: ValidationWatermark,
    identity: Option<&StoreIdentity>,
) -> Result<Result<OpenValidation, FullValidationReason>, StoreError> {
    let Some(identity) = identity else {
        return Ok(Err(FullValidationReason::InapplicableWatermark));
    };
    if watermark.genesis_id != identity.genesis_id
        || watermark.schema_version != identity.schema_version
        || watermark.schema_artifact_digest != identity.schema_artifact_digest
    {
        return Ok(Err(FullValidationReason::InapplicableWatermark));
    }
    watermark.frontier.verify_unchanged(connection)?;
    let digest = watermark.frontier.commitment_digest(connection)?;
    if digest != watermark.commitment_digest {
        return Err(StoreError::Integrity(format!(
            "commitment digest {digest} differs from validation watermark {}: validated history \
             was substituted; run `nq admin validate --full` to re-establish validation",
            watermark.commitment_digest
        )));
    }
    // A semantic frontier beyond the verified one is not covered by the
    // digest; it is ignored rather than trusted.
    let semantic_frontier = watermark
        .semantic_frontier
        .filter(|semantic| semantic.within(&watermark.frontier))
        .map(Box::new);
    Ok(Ok(OpenValidation::SinceWatermark {
        frontier: Box::new(watermark.frontier),
        semantic_frontier,
    }))
}

/// Atomically replace the sidecar with a watermark for `frontier`.
pub(crate) fn write_watermark(
    connection: &Connection,
    database: &Path,
    identity: &StoreIdentity,
    frontier: &HistoryFrontier,
    semantic: SemanticCertification,
    validated_at: String,
) -> Result<(), StoreError> {
    let watermark = ValidationWatermark {
        schema: VALIDATION_WATERMARK_SCHEMA.to_owned(),
        validation_rules: VALIDATION_RULES.to_owned(),
        genesis_id: identity.genesis_id.clone(),
        schema_version: identity.schema_version,
        schema_artifact_digest: identity.schema_artifact_digest.clone(),
        frontier: frontier.clone(),
        commitment_digest: frontier.commitment_digest(connection)?,
        semantic_frontier: (semantic == SemanticCertification::Established)
            .then(|| frontier.clone()),
        validated_at,
    };
    let document = CanonicalDocument::from_serializable(&watermark)?;
    let path = watermark_path(database);
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".tmp-{}", std::process::id()));
    let temporary = PathBuf::from(temporary);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(document.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(StoreError::from)
}

/// Delta accessors for semantic history validation layered above the store.
/// Each returns the records whose obligations are not covered by `frontier`,
/// in append order; the caller reopens and validates exactly those.
impl crate::Store {
    /// The frontier this handle's open proved validated, or `None` when the
    /// open validated history in full (so callers must too).
    #[must_use]
    pub fn validated_history_frontier(&self) -> Option<&HistoryFrontier> {
        match &self.validation.opened {
            OpenValidation::SinceWatermark { frontier, .. } => Some(frontier),
            OpenValidation::Full(_) => None,
        }
    }

    /// The frontier through which the open's watermark certified the complete
    /// semantic history, or `None` when semantic history must be validated in
    /// full.
    #[must_use]
    pub fn validated_semantic_frontier(&self) -> Option<&HistoryFrontier> {
        match &self.validation.opened {
            OpenValidation::SinceWatermark {
                semantic_frontier, ..
            } => semantic_frontier.as_deref(),
            OpenValidation::Full(_) => None,
        }
    }

    fn ids_since(&self, sql: &str) -> Result<Vec<String>, StoreError> {
        self.connection
            .prepare(sql)?
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Provider intakes whose custody, run correspondence, or acknowledgment
    /// is not covered by `frontier`.
    pub fn provider_intake_ids_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<Vec<String>, StoreError> {
        let selection = crate::IntakeSelection::Scope(Scope::after(frontier));
        self.ids_since(&format!(
            "SELECT intake.intake_id FROM provider_intake_attempts AS intake
             JOIN local_watcher_provider_intakes AS local ON local.intake_id = intake.intake_id
             WHERE {} ORDER BY intake.intake_sequence",
            selection.intake_correspondence()
        ))
    }

    /// Legacy v3 provider-intake gaps appended beyond `frontier` (only the
    /// v3-to-v4 migration writes them, so normally none).
    pub fn legacy_provider_intake_gaps_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<Vec<crate::LegacyProviderIntakeGapRow>, StoreError> {
        self.connection
            .prepare(&format!(
                "SELECT run_id, source_schema_version, source_schema_artifact_digest,
                        limitation_code, detail_json, migrated_at
                 FROM legacy_v3_watcher_run_intake_gaps AS gap
                 WHERE {} ORDER BY gap.rowid",
                Scope::after(frontier).new_rows("legacy_v3_watcher_run_intake_gaps", "gap")
            ))?
            .query_map([], |row| {
                Ok(crate::LegacyProviderIntakeGapRow {
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

    /// Admitted reports that are new, or whose observations, coverage, or
    /// errors gained a row, beyond `frontier`.
    pub fn admitted_report_ids_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<Vec<String>, StoreError> {
        let scope = Scope::after(frontier);
        self.ids_since(&format!(
            "SELECT report.report_id FROM admitted_reports AS report WHERE {}
             ORDER BY report.report_sequence",
            scope.affected(
                "report.report_id",
                "admitted_reports",
                "report",
                &[
                    ("observations", "report_id"),
                    ("report_coverage", "report_id"),
                    ("observation_coverage", "report_id"),
                    ("report_errors", "report_id"),
                ],
            )
        ))
    }

    /// Watcher runs appended beyond `frontier`. A run's reopened resource
    /// outcome and profile identity depend only on its own immutable row.
    pub fn watcher_run_ids_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<Vec<String>, StoreError> {
        self.ids_since(&format!(
            "SELECT run.run_id FROM watcher_runs AS run WHERE {} ORDER BY run.rowid",
            Scope::after(frontier).new_rows("watcher_runs", "run")
        ))
    }

    /// Rejected custody whose submission or refusal is beyond `frontier`.
    pub fn rejected_custody_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<Vec<crate::RejectedCustodyRow>, StoreError> {
        let scope = Scope::after(frontier);
        crate::validate_refusal_invariants(&self.connection, scope)?;
        self.connection
            .prepare(&format!(
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
                 WHERE submission.admission_outcome = 'rejected' AND {}
                 ORDER BY submission.rowid",
                scope.affected(
                    "submission.submission_id",
                    "raw_submissions",
                    "submission",
                    &[("refusals", "submission_id")],
                )
            ))?
            .query_map([], crate::rejected_custody_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Diagnostic artifacts whose commitment, payload, or origin is beyond
    /// `frontier`, in commitment order.
    pub fn diagnostic_artifact_ids_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<Vec<String>, StoreError> {
        self.ids_since(&format!(
            "SELECT commitment.artifact_id FROM diagnostic_artifact_commitments AS commitment
             WHERE {} ORDER BY commitment.artifact_sequence",
            Scope::after(frontier).affected(
                "commitment.artifact_id",
                "diagnostic_artifact_commitments",
                "commitment",
                &[
                    ("diagnostic_artifact_payloads", "artifact_id"),
                    ("local_diagnostic_artifact_origins", "artifact_id"),
                    ("imported_diagnostic_artifact_origins", "artifact_id"),
                ],
            )
        ))
    }

    /// Store-wide evaluation, refusal, and finding laws for rows beyond
    /// `frontier`.
    pub fn validate_evaluation_history_invariants_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<(), StoreError> {
        crate::validate_evaluation_refusal_invariants(&self.connection, Scope::after(frontier))
    }

    /// Store-wide run-result laws for rows beyond `frontier`.
    pub fn validate_run_results_since(&self, frontier: &HistoryFrontier) -> Result<(), StoreError> {
        crate::validate_run_results(&self.connection, Scope::after(frontier))
    }

    /// Store-wide report association laws for rows beyond `frontier`.
    pub fn validate_admitted_report_associations_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<(), StoreError> {
        crate::validate_admitted_report_associations_connection(
            &self.connection,
            Scope::after(frontier),
        )
    }

    /// Store-wide provider-intake laws for rows beyond `frontier`.
    pub fn validate_provider_intake_history_invariants_since(
        &self,
        frontier: &HistoryFrontier,
    ) -> Result<(), StoreError> {
        crate::validate_provider_intake_invariants(&self.connection, Scope::after(frontier))
    }

    /// The canonical detail of every evaluation triggered by `run_id`, in
    /// append order.
    pub fn evaluation_details_for_run(&self, run_id: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        self.connection
            .prepare(
                "SELECT detail_json FROM evaluation_runs
                 WHERE trigger_run_id = ?1 ORDER BY evaluation_sequence",
            )?
            .query_map([run_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Evaluation sequences, at or below `through_evaluation_sequence`, of the
    /// latest finding event of each finding: the state a finding-lineage
    /// replay holds after replaying evaluations through that sequence.
    pub fn finding_lineage_heads_through(
        &self,
        through_evaluation_sequence: i64,
    ) -> Result<Vec<i64>, StoreError> {
        self.connection
            .prepare(
                "SELECT MAX(evaluation.evaluation_sequence)
                 FROM finding_events AS event
                 JOIN evaluation_runs AS evaluation
                   ON evaluation.evaluation_id = event.evaluation_id
                 WHERE evaluation.evaluation_sequence <= ?1
                 GROUP BY event.finding_id
                 ORDER BY 1",
            )?
            .query_map([through_evaluation_sequence], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }
}
