//! Bounded history validation: the append frontier, the scope a validator
//! covers, and the store-specific validation watermark.
//!
//! Ordinary update/delete triggers abort, and the schema fingerprint proves
//! those triggers exist on every open; only the guarded retention expiry
//! deletes or compacts rows, and only at or below its declared floors. Rowids
//! therefore grow monotonically in append order. A completed validation
//! records, per table, the highest validated rowid, the row count, and an
//! additive content accumulator: the 256-bit modular sum of one digest per
//! covered row, each binding the table, the rowid and every column value.
//! Recording adds only newly validated rows, so it costs O(new rows).
//!
//! A watermark is bound to the retention boundary (generation, the four
//! floors and the retired lineage floors) it was certified under, and
//! applies only while the store's boundary is the same. The expiry that
//! changes the boundary carries the handle's watermark forward in O(changed
//! rows): it subtracts the digest of every covered row it deletes, replaces
//! the digest of every covered row it compacts, re-anchors a bound whose row
//! it deleted, and records the new boundary. An expiry interrupted between
//! its commit and that write leaves a watermark for the old boundary, which
//! no longer applies: exactly one full validation follows.
//!
//! An ordinary open proves that the watermark belongs to this store, that the
//! covered prefix still ends where it was recorded (each bounding row is
//! present with its recorded encoding), and then validates only rows beyond
//! the frontier. It does not re-read untouched covered rows: those are
//! re-proven when an operation references them (replay, qualification,
//! export, inspection, and collection re-verify the closure they read), and
//! by explicit full validation, which recomputes every chain from the stored
//! rows and refuses if any covered row changed since it was certified.
//!
//! The watermark is advisory in one direction only: when it is absent,
//! unreadable, or written for another schema or rule set, the store is
//! validated in full. It never makes an unvalidated row count as validated.
//! A watermark written for another store (another genesis) is refused.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CanonicalDocument, StoreError};

/// Watermark document schema.
pub const VALIDATION_WATERMARK_SCHEMA: &str = "nq.validation_watermark.v4";

/// Identity of the store validation rules a watermark vouches for. Any change
/// to what store validation checks must change this value so that existing
/// watermarks stop applying and the next open validates in full. Semantic
/// rules layered above the store are bound separately through the engine
/// rules a watermark records.
pub const VALIDATION_RULES: &str = concat!("nq-store/", env!("CARGO_PKG_VERSION"), "/rules.4");

/// Every append-only history table. The frontier covers all of them.
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

thread_local! {
    static SQL_WORK: Cell<Option<u64>> = const { Cell::new(None) };
}

/// SQLite virtual-machine operations between two work-counter ticks: every
/// operation is counted, so a test can assert exact equality.
pub const SQL_WORK_TICK: i32 = 1;

/// Deterministic measure of the SQL work a thread performs: start counting
/// before opening a store, and every connection opened afterwards on this
/// thread reports one tick per [`SQL_WORK_TICK`] SQLite virtual-machine
/// operations. Used by tests and measurements to assert that bounded paths do
/// not grow with retained history; inert unless started.
pub fn start_sql_work_count() {
    SQL_WORK.with(|work| work.set(Some(0)));
}

/// Ticks counted since [`start_sql_work_count`], or `None` when not counting.
#[must_use]
pub fn sql_work_count() -> Option<u64> {
    SQL_WORK.with(Cell::get)
}

/// Stop counting and return the ticks counted.
#[must_use]
pub fn stop_sql_work_count() -> Option<u64> {
    SQL_WORK.with(|work| work.replace(None))
}

pub(crate) fn install_sql_work_counter(connection: &Connection) {
    if sql_work_count().is_none() {
        return;
    }
    connection.progress_handler(
        SQL_WORK_TICK,
        Some(|| {
            SQL_WORK.with(|work| {
                if let Some(count) = work.get() {
                    work.set(Some(count.saturating_add(1)));
                }
            });
            false
        }),
    );
}

/// The append position and content commitment of one history table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableFrontier {
    /// Highest rowid present, or `None` when the table was empty.
    pub max_rowid: Option<i64>,
    /// Rows at or below `max_rowid`.
    pub rows: i64,
    /// Additive content accumulator: the sum modulo 2^256 (lowercase hex)
    /// of the row element of every row at or below `max_rowid`. A row
    /// element is a digest of the table name and the row's full encoding,
    /// rowid included, so it is order-independent and supports removing one
    /// row's contribution without re-reading the others. Advisory: it
    /// detects accidental change, not deliberate forgery.
    pub accumulator: String,
    /// Digest of the full encoding of the row at `max_rowid`.
    pub boundary: Option<String>,
}

/// Per-table append positions plus the evaluation sequence, which history
/// paging uses instead of the rowid. A frontier from
/// [`HistoryFrontier::capture_bounds`] carries positions only and scopes
/// validation; a certified frontier also carries counts and accumulators.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryFrontier {
    /// Append position of each history table.
    pub tables: BTreeMap<String, TableFrontier>,
    /// Evaluation append sequence of the last covered evaluation row.
    pub evaluation_sequence: i64,
}

/// The accumulator of an empty table.
const EMPTY_ACCUMULATOR: [u8; 32] = [0; 32];

/// The accumulator element of one row: binds the table and the row digest.
fn row_element(table: &str, row: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VALIDATION_WATERMARK_SCHEMA.as_bytes());
    hasher.update(b"/row\0");
    hasher.update(table.as_bytes());
    hasher.update(b"\0");
    hasher.update(row);
    hasher.finalize().into()
}

/// `accumulator + element` modulo 2^256, big-endian.
fn accumulate(accumulator: &mut [u8; 32], element: &[u8; 32]) {
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let sum = u16::from(accumulator[index]) + u16::from(element[index]) + carry;
        accumulator[index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
}

/// `accumulator - element` modulo 2^256, big-endian.
fn deduct(accumulator: &mut [u8; 32], element: &[u8; 32]) {
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let mut difference = i16::from(accumulator[index]) - i16::from(element[index]) - borrow;
        borrow = 0;
        if difference < 0 {
            difference += 256;
            borrow = 1;
        }
        accumulator[index] = u8::try_from(difference).unwrap_or(0);
    }
}

fn parse_accumulator(table: &str, value: &str) -> Result<[u8; 32], StoreError> {
    let invalid = || {
        StoreError::Integrity(format!(
            "validation watermark accumulator for history table {table} is not 64 hex digits"
        ))
    };
    if value.len() != 64 {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Digest of one row's complete stored encoding: its rowid and every column
/// value in schema order, each typed and length-prefixed.
fn row_digest(row: &rusqlite::Row<'_>, columns: usize) -> Result<[u8; 32], rusqlite::Error> {
    let mut hasher = Sha256::new();
    for index in 0..columns {
        match row.get_ref(index)? {
            ValueRef::Null => hasher.update([0u8]),
            ValueRef::Integer(value) => {
                hasher.update([1u8]);
                hasher.update(value.to_be_bytes());
            }
            ValueRef::Real(value) => {
                hasher.update([2u8]);
                hasher.update(value.to_bits().to_be_bytes());
            }
            ValueRef::Text(bytes) => {
                hasher.update([3u8]);
                hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(bytes);
            }
            ValueRef::Blob(bytes) => {
                hasher.update([4u8]);
                hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(bytes);
            }
        }
    }
    Ok(hasher.finalize().into())
}

/// Columns of `SELECT rowid, * FROM table`.
fn column_count(connection: &Connection, table: &str) -> Result<usize, StoreError> {
    let columns: i64 = connection.query_row(
        &format!("SELECT COUNT(*) FROM pragma_table_info('{table}')"),
        [],
        |row| row.get(0),
    )?;
    Ok(usize::try_from(columns).unwrap_or(0) + 1)
}


impl HistoryFrontier {
    /// Read the current append position of every history table (each an
    /// O(log n) rowid lookup), without counts or chains.
    pub(crate) fn capture_bounds(connection: &Connection) -> Result<Self, StoreError> {
        // One snapshot for every table: a frontier bounds what later rows can
        // reference only if no commit lands between its reads.
        let _snapshot = if connection.is_autocommit() {
            Some(connection.unchecked_transaction()?)
        } else {
            None
        };
        let mut tables = BTreeMap::new();
        for table in HISTORY_TABLES {
            let max_rowid: Option<i64> =
                connection.query_row(&format!("SELECT MAX(rowid) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            tables.insert(
                (*table).to_owned(),
                TableFrontier {
                    max_rowid,
                    ..TableFrontier::default()
                },
            );
        }
        // Evaluation sequences are allocated in append order, so the bounding
        // row carries the highest covered sequence.
        let evaluation_sequence = match tables
            .get("evaluation_runs")
            .and_then(|frontier| frontier.max_rowid)
        {
            Some(bound) => connection.query_row(
                "SELECT evaluation_sequence FROM evaluation_runs WHERE rowid = ?1",
                [bound],
                |row| row.get(0),
            )?,
            None => 0,
        };
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

    /// Certify the rows at or below `bounds`: add the rows beyond `base` to
    /// its accumulators (O(new rows)), or accumulate every row from scratch
    /// without a base. With `prior` (certified under the same retention
    /// boundary), every table's accumulator is also checkpointed at the prior
    /// bound and must equal the prior one, proving that no covered row
    /// changed since `prior` was certified.
    pub(crate) fn certify(
        connection: &Connection,
        base: Option<&HistoryFrontier>,
        bounds: &HistoryFrontier,
        prior: Option<&ValidationWatermark>,
    ) -> Result<Self, StoreError> {
        let mut tables = BTreeMap::new();
        for table in HISTORY_TABLES {
            let bound = bounds.max_rowid(table);
            let from = base
                .and_then(|base| base.tables.get(*table))
                .filter(|from| from.max_rowid <= bound);
            let (start, mut rows, mut accumulator, mut boundary) = match from {
                Some(from) => (
                    from.max_rowid,
                    from.rows,
                    parse_accumulator(table, &from.accumulator)?,
                    from.boundary.clone(),
                ),
                None => (None, 0, EMPTY_ACCUMULATOR, None),
            };
            // A prior certification is compared only on a recomputation from
            // scratch, at the prior bound.
            let checkpoint = prior
                .filter(|_| from.is_none())
                .and_then(|prior| prior.frontier.tables.get(*table));
            let checkpoint_bound = checkpoint.and_then(|checkpoint| checkpoint.max_rowid);
            if checkpoint_bound > bound {
                return Err(StoreError::Integrity(format!(
                    "the validation watermark covers history table {table} through rowid {} but \
                     the store ends at {}: rows certified earlier are missing (rollback or \
                     truncation). If this database was deliberately restored, move the watermark \
                     aside and validate again",
                    checkpoint_bound.map_or_else(|| "none".to_owned(), |b| b.to_string()),
                    bound.map_or_else(|| "none".to_owned(), |b| b.to_string()),
                )));
            }
            let mut checkpoint_seen = checkpoint_bound.is_none();
            if let Some(bound) = bound {
                let columns = column_count(connection, table)?;
                let mut statement = connection.prepare(&format!(
                    "SELECT rowid, * FROM {table} WHERE rowid > ?1 AND rowid <= ?2 ORDER BY rowid"
                ))?;
                let mut cursor = statement.query([start.unwrap_or(i64::MIN), bound])?;
                while let Some(row) = cursor.next()? {
                    let rowid: i64 = row.get(0)?;
                    let digest = row_digest(row, columns)?;
                    accumulate(&mut accumulator, &row_element(table, &digest));
                    rows += 1;
                    if rowid == bound {
                        boundary = Some(hex(&digest));
                    }
                    if Some(rowid) == checkpoint_bound
                        && let Some(checkpoint) = checkpoint
                    {
                        verify_checkpoint(table, checkpoint, rows, &hex(&accumulator), prior)?;
                        checkpoint_seen = true;
                    }
                }
            }
            if !checkpoint_seen {
                return Err(StoreError::Integrity(format!(
                    "history table {table} no longer contains the row at rowid {} that bounded \
                     the history certified at {}: a covered row was removed or renumbered",
                    checkpoint_bound.unwrap_or_default(),
                    prior.map_or("an earlier validation", |prior| prior.validated_at.as_str())
                )));
            }
            tables.insert(
                (*table).to_owned(),
                TableFrontier {
                    max_rowid: bound,
                    rows,
                    accumulator: hex(&accumulator),
                    boundary: bound.and(boundary),
                },
            );
        }
        Ok(Self {
            tables,
            evaluation_sequence: bounds.evaluation_sequence,
        })
    }

    /// Prove the covered prefix still ends where it was certified: every
    /// bounding row is present with its recorded encoding. O(tables).
    fn verify_boundaries(&self, connection: &Connection) -> Result<(), StoreError> {
        for table in HISTORY_TABLES {
            let recorded = self.tables.get(*table).ok_or_else(|| {
                StoreError::Integrity(format!(
                    "validation watermark has no frontier for history table {table}"
                ))
            })?;
            let (Some(bound), Some(boundary)) = (recorded.max_rowid, recorded.boundary.as_ref())
            else {
                if recorded.max_rowid.is_some() {
                    return Err(boundary_mismatch(table, None));
                }
                continue;
            };
            let columns = column_count(connection, table)?;
            let mut statement =
                connection.prepare(&format!("SELECT rowid, * FROM {table} WHERE rowid = ?1"))?;
            let mut cursor = statement.query([bound])?;
            let present = match cursor.next()? {
                Some(row) => Some(hex(&row_digest(row, columns)?)),
                None => None,
            };
            if present.as_ref() != Some(boundary) {
                return Err(boundary_mismatch(table, Some(bound)));
            }
        }
        Ok(())
    }

    /// Feed every table's bound, count, accumulator and boundary, plus the
    /// evaluation sequence, into `hasher`.
    fn hash_into(&self, hasher: &mut Sha256) {
        for (table, frontier) in &self.tables {
            hasher.update(b"\ntable\0");
            hasher.update(table.as_bytes());
            hasher.update(frontier.max_rowid.unwrap_or(0).to_be_bytes());
            hasher.update(frontier.rows.to_be_bytes());
            hasher.update(frontier.accumulator.as_bytes());
            hasher.update(frontier.boundary.as_deref().unwrap_or("").as_bytes());
        }
        hasher.update(self.evaluation_sequence.to_be_bytes());
    }
}

fn verify_checkpoint(
    table: &str,
    checkpoint: &TableFrontier,
    rows: i64,
    accumulator: &str,
    prior: Option<&ValidationWatermark>,
) -> Result<(), StoreError> {
    if checkpoint.rows != rows || checkpoint.accumulator != accumulator {
        return Err(StoreError::Integrity(format!(
            "history table {table} changed at or below the frontier certified at {}: a covered row \
             was added, removed, or rewritten since it was validated",
            prior.map_or("an earlier validation", |prior| prior.validated_at.as_str())
        )));
    }
    Ok(())
}

fn boundary_mismatch(table: &str, bound: Option<i64>) -> StoreError {
    StoreError::Integrity(format!(
        "history table {table} no longer matches its validation watermark: the covered row at \
         rowid {} is missing or rewritten (truncation, rollback, substitution, or a watermark from \
         a later state of this store); run `nq admin validate --full`, which refuses if certified \
         history changed",
        bound.map_or_else(|| "?".to_owned(), |bound| bound.to_string())
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

    /// Ordering for a query restricted to new rows of `alias`: the original
    /// key for full validation (so its first reported violation is
    /// unchanged), the rowid in scope so SQLite walks only the new rowid range.
    pub(crate) fn order(self, alias: &str, key: &str) -> String {
        if self.is_full() {
            format!("{alias}.{key}")
        } else {
            format!("{alias}.rowid")
        }
    }

    /// The validated frontier, or `None` for a full scope.
    pub(crate) fn frontier(self) -> Option<&'a HistoryFrontier> {
        self.after
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
    ///
    /// `key` is `alias.column` of the parent; the predicate is an `IN` over
    /// a union of rowid-bounded subqueries so SQLite can drive the parent
    /// from its key index instead of scanning it.
    pub(crate) fn affected(
        self,
        key: &str,
        parent_table: &str,
        children: &[(&str, &str)],
    ) -> String {
        self.affected_with(key, parent_table, children, &[])
    }

    /// [`Self::affected`] plus further subqueries, each yielding parent keys.
    pub(crate) fn affected_with(
        self,
        key: &str,
        parent_table: &str,
        children: &[(&str, &str)],
        extra: &[String],
    ) -> String {
        if self.is_full() {
            return "1".to_owned();
        }
        let column = key.rsplit('.').next().unwrap_or(key);
        let mut keys = vec![format!(
            "SELECT parent.{column} FROM {parent_table} AS parent WHERE {}",
            self.new_rows(parent_table, "parent")
        )];
        for (table, child_column) in children {
            keys.push(format!(
                "SELECT child.{child_column} FROM {table} AS child WHERE {}",
                self.new_rows(table, "child")
            ));
        }
        keys.extend(extra.iter().cloned());
        format!("{key} IN ({})", keys.join(" UNION "))
    }
}

/// Evaluations by triggering run, as present when the index was built.
#[derive(Debug)]
pub(crate) struct RunEvaluations {
    /// Highest evaluation rowid the index covers.
    bound: Option<i64>,
    by_run: std::collections::HashMap<String, Vec<i64>>,
}

impl RunEvaluations {
    fn build(connection: &Connection, through: i64) -> Result<Self, StoreError> {
        let bound: Option<i64> = connection.query_row(
            "SELECT MAX(rowid) FROM evaluation_runs WHERE rowid <= ?1",
            [through],
            |row| row.get(0),
        )?;
        let mut by_run: std::collections::HashMap<String, Vec<i64>> =
            std::collections::HashMap::new();
        let mut statement = connection.prepare(
            "SELECT trigger_run_id, rowid FROM evaluation_runs
             WHERE trigger_run_id IS NOT NULL AND rowid <= ?1 ORDER BY evaluation_sequence",
        )?;
        let mut rows = statement.query([bound.unwrap_or(i64::MIN)])?;
        while let Some(row) = rows.next()? {
            by_run.entry(row.get(0)?).or_default().push(row.get(1)?);
        }
        Ok(Self { bound, by_run })
    }

    /// Fold in the evaluations appended beyond the index's bound, through
    /// rowid `through`.
    fn extend(&mut self, connection: &Connection, through: i64) -> Result<(), StoreError> {
        let mut statement = connection.prepare(
            "SELECT trigger_run_id, rowid FROM evaluation_runs NOT INDEXED
             WHERE rowid > ?1 AND rowid <= ?2 ORDER BY rowid",
        )?;
        let mut rows = statement.query([self.bound.unwrap_or(i64::MIN), through])?;
        while let Some(row) = rows.next()? {
            let rowid: i64 = row.get(1)?;
            if let Some(run_id) = row.get::<_, Option<String>>(0)? {
                self.by_run.entry(run_id).or_default().push(rowid);
            }
            self.bound = Some(rowid);
        }
        Ok(())
    }
}

/// Latest finding event of one evaluation lineage, as the finding-lineage
/// replay holds it after replaying every covered evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageHead {
    /// Hex encoding of the lineage key.
    pub lineage: String,
    /// Finding identity of the lineage.
    pub finding_id: String,
    /// Revision of the latest finding event.
    pub event_revision: i64,
    /// Condition state of the latest finding event.
    pub condition_state: String,
}

/// Newest evaluation of one evaluation lineage: the row the current status
/// surface reports for it. Within a lineage the newest revision wins, the
/// same rule the complete-history selection applies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationHead {
    /// Hex encoding of the lineage key.
    pub lineage: String,
    /// Append sequence of the lineage's newest evaluation.
    pub evaluation_sequence: i64,
    /// Revision of that evaluation.
    pub evaluation_revision: i64,
}

/// Semantic certification carried by a watermark: the complete semantic
/// history is proven through the watermark frontier, and replay resumes from
/// these lineage heads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticState {
    /// Finding-lineage replay state at the frontier.
    pub lineage_heads: Vec<LineageHead>,
    /// Newest evaluation of every evaluation lineage through the frontier,
    /// in lineage order: the certified projection the bounded status
    /// snapshot resumes from instead of reopening every evaluation.
    pub evaluation_heads: Vec<EvaluationHead>,
}

/// The retention boundary a watermark was certified under: the expiry
/// generation, the four expired-through floors, and the digest of the
/// retired lineage floors. A watermark applies only to a store whose current
/// boundary is identical.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionWitness {
    /// Expiry generation.
    pub generation: i64,
    /// Evaluations expired through this sequence.
    pub evaluation_floor: i64,
    /// Admitted reports expired through this sequence.
    pub report_floor: i64,
    /// Provider intakes expired through this sequence.
    pub intake_floor: i64,
    /// Status events expired through this sequence.
    pub status_floor: i64,
    /// SHA-256 of the exact persisted retired lineage floors.
    pub lineage_floors_digest: String,
}

impl RetentionWitness {
    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update(b"\nretention\0");
        for value in [
            self.generation,
            self.evaluation_floor,
            self.report_floor,
            self.intake_floor,
            self.status_floor,
        ] {
            hasher.update(value.to_be_bytes());
        }
        hasher.update(
            u64::try_from(self.lineage_floors_digest.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(self.lineage_floors_digest.as_bytes());
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
    /// Identity of the semantic validation rules (engine and compiled
    /// profile catalog) that certified the history above the store.
    pub engine_rules: String,
    /// The store's sole genesis identity.
    pub genesis_id: String,
    /// Schema version of the validated store.
    pub schema_version: i64,
    /// Schema artifact digest of the validated store.
    pub schema_artifact_digest: String,
    /// Retention boundary the certification holds under.
    pub retention: RetentionWitness,
    /// Frontier through which store validation and the provider-intake and
    /// diagnostic-artifact history were proven, with each table's content
    /// chain.
    pub frontier: HistoryFrontier,
    /// [`ValidationWatermark::computed_commitment`] at write time.
    pub commitment_digest: String,
    /// Present when the complete semantic history is also certified through
    /// `frontier`.
    pub semantic: Option<SemanticState>,
    /// When the covered validation completed.
    pub validated_at: String,
}

impl ValidationWatermark {
    /// The commitment this watermark should carry: a digest over its store
    /// identity, rule sets, certified frontier (every table's bound, count,
    /// content chain, and boundary row), and semantic replay state.
    #[must_use]
    pub fn computed_commitment(&self) -> String {
        let mut hasher = Sha256::new();
        for field in [
            self.schema.as_str(),
            self.validation_rules.as_str(),
            self.engine_rules.as_str(),
            self.genesis_id.as_str(),
            self.schema_artifact_digest.as_str(),
        ] {
            hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.update(self.schema_version.to_be_bytes());
        self.retention.hash_into(&mut hasher);
        self.frontier.hash_into(&mut hasher);
        match &self.semantic {
            None => hasher.update([0u8]),
            Some(state) => {
                hasher.update([1u8]);
                for head in &state.lineage_heads {
                    for field in [&head.lineage, &head.finding_id, &head.condition_state] {
                        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
                        hasher.update(field.as_bytes());
                    }
                    hasher.update(head.event_revision.to_be_bytes());
                }
                hasher.update(
                    u64::try_from(state.evaluation_heads.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                for head in &state.evaluation_heads {
                    hasher.update(
                        u64::try_from(head.lineage.len())
                            .unwrap_or(u64::MAX)
                            .to_be_bytes(),
                    );
                    hasher.update(head.lineage.as_bytes());
                    hasher.update(head.evaluation_sequence.to_be_bytes());
                    hasher.update(head.evaluation_revision.to_be_bytes());
                }
            }
        }
        format!("sha256:{}", hex(&hasher.finalize()))
    }
}

/// Why an open validated history in full.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FullValidationReason {
    /// No watermark file exists.
    NoWatermark,
    /// The watermark could not be read or decoded.
    UnreadableWatermark,
    /// The watermark was written for another schema or rule set.
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
    /// The covered prefix was proven to end where it was certified; only rows
    /// beyond it were validated.
    SinceWatermark(Box<ValidationWatermark>),
}

/// Whether a recorded watermark also certifies the complete semantic history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticCertification {
    /// The caller validated every semantic plane beyond the handle's prior
    /// semantic certification (or in full); replay state at the frontier.
    Established(SemanticState),
    /// The semantic history is not certified by this watermark.
    NotEstablished,
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
    pub retention: RetentionWitness,
}

/// A sidecar as read from disk, before it is related to the database.
pub(crate) enum SidecarState {
    Absent,
    Unreadable,
    Present(Box<ValidationWatermark>),
}

pub(crate) fn read_sidecar(database: &Path) -> SidecarState {
    let bytes = match std::fs::read(watermark_path(database)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return SidecarState::Absent;
        }
        Err(_) => return SidecarState::Unreadable,
    };
    serde_json::from_slice::<ValidationWatermark>(&bytes)
        .map_or(SidecarState::Unreadable, |watermark| {
            SidecarState::Present(Box::new(watermark))
        })
}

/// Refuse a sidecar written for another store: a different genesis means the
/// file next to this database was not produced by validating it.
pub(crate) fn refuse_foreign(
    database: &Path,
    watermark: &ValidationWatermark,
    identity: Option<&StoreIdentity>,
) -> Result<(), StoreError> {
    if let Some(identity) = identity
        && watermark.genesis_id != identity.genesis_id
    {
        return Err(StoreError::Integrity(format!(
            "validation watermark {} was written for store genesis {}, not this store's {}; it \
             does not belong to this database. Confirm which database belongs at this path, move \
             the watermark aside, and open again (the next open validates in full)",
            watermark_path(database).display(),
            watermark.genesis_id,
            identity.genesis_id
        )));
    }
    Ok(())
}

/// Whether a watermark of this store was written under the current schema
/// and store rules, so its frontier and chains are meaningful here.
pub(crate) fn applies(watermark: &ValidationWatermark, identity: &StoreIdentity) -> bool {
    applies_except_retention(watermark, identity) && watermark.retention == identity.retention
}

/// Whether a watermark of this store was written under the current schema and
/// store rules, whatever retention boundary it certified (an expiry since
/// then supersedes it).
pub(crate) fn applies_except_retention(
    watermark: &ValidationWatermark,
    identity: &StoreIdentity,
) -> bool {
    watermark.schema == VALIDATION_WATERMARK_SCHEMA
        && watermark.validation_rules == VALIDATION_RULES
        && watermark.genesis_id == identity.genesis_id
        && watermark.schema_version == identity.schema_version
        && watermark.schema_artifact_digest == identity.schema_artifact_digest
}

/// Prove an applicable watermark's frontier still bounds this store.
pub(crate) fn verify_watermark(
    connection: &Connection,
    watermark: &ValidationWatermark,
) -> Result<(), StoreError> {
    if watermark.computed_commitment() != watermark.commitment_digest {
        return Err(StoreError::Integrity(format!(
            "validation watermark commitment {} does not match its own frontier; the watermark \
             was edited. Run `nq admin validate --full`",
            watermark.commitment_digest
        )));
    }
    watermark.frontier.verify_boundaries(connection)
}

/// Atomically replace the sidecar with a watermark for `frontier`. The
/// temporary file name is unique per write; any failure is reported with the
/// path it concerned.
pub(crate) fn write_watermark(
    database: &Path,
    identity: &StoreIdentity,
    engine_rules: &str,
    frontier: HistoryFrontier,
    semantic: SemanticCertification,
    validated_at: String,
) -> Result<ValidationWatermark, StoreError> {
    let mut watermark = ValidationWatermark {
        schema: VALIDATION_WATERMARK_SCHEMA.to_owned(),
        validation_rules: VALIDATION_RULES.to_owned(),
        engine_rules: engine_rules.to_owned(),
        genesis_id: identity.genesis_id.clone(),
        schema_version: identity.schema_version,
        schema_artifact_digest: identity.schema_artifact_digest.clone(),
        retention: identity.retention.clone(),
        commitment_digest: String::new(),
        frontier,
        semantic: match semantic {
            SemanticCertification::Established(state) => Some(state),
            SemanticCertification::NotEstablished => None,
        },
        validated_at,
    };
    watermark.commitment_digest = watermark.computed_commitment();
    let document = CanonicalDocument::from_serializable(&watermark)?;
    crate::capacity::preflight_watermark(database, document.as_bytes().len())
        .map_err(|error| StoreError::WatermarkWrite(error.to_string()))?;
    let path = watermark_path(database);
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
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
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(StoreError::WatermarkWrite(format!(
            "cannot write validation watermark {}: {error}",
            path.display()
        )));
    }
    remove_stale_temporaries(&path);
    Ok(watermark)
}

/// The covered rows one expiry transaction deleted or rewrote, recorded
/// before and after each mutation so the transaction's watermark can be
/// carried forward without re-reading surviving history.
#[derive(Debug)]
pub(crate) struct ExpiryDelta {
    bounds: BTreeMap<String, Option<i64>>,
    tables: BTreeMap<String, TableDelta>,
}

#[derive(Debug)]
struct TableDelta {
    removed: [u8; 32],
    added: [u8; 32],
    rows_removed: i64,
    rows_added: i64,
}

impl ExpiryDelta {
    /// Track changes to rows at or below `frontier`'s per-table bounds.
    pub(crate) fn new(frontier: &HistoryFrontier) -> Self {
        Self {
            bounds: frontier
                .tables
                .iter()
                .map(|(table, recorded)| (table.clone(), recorded.max_rowid))
                .collect(),
            tables: BTreeMap::new(),
        }
    }

    /// Rows of `table` matching `predicate` (SQL over alias `t`), with their
    /// rowids and digests, restricted to the covered range.
    pub(crate) fn covered_rows(
        &self,
        connection: &Connection,
        table: &str,
        predicate: &str,
    ) -> Result<Vec<(i64, [u8; 32])>, StoreError> {
        let Some(Some(bound)) = self.bounds.get(table) else {
            return Ok(Vec::new());
        };
        let columns = column_count(connection, table)?;
        let mut statement = connection.prepare(&format!(
            "SELECT t.rowid, t.* FROM {table} AS t WHERE t.rowid <= ?1 AND ({predicate})"
        ))?;
        let mut cursor = statement.query([bound])?;
        let mut out = Vec::new();
        while let Some(row) = cursor.next()? {
            out.push((row.get(0)?, row_digest(row, columns)?));
        }
        Ok(out)
    }

    /// Remove `rows` (as read before the mutation) from `table`'s accumulator.
    pub(crate) fn removed(&mut self, table: &str, rows: &[(i64, [u8; 32])]) {
        let entry = self.entry(table);
        for (_, digest) in rows {
            accumulate(&mut entry.removed, &row_element(table, digest));
            entry.rows_removed += 1;
        }
    }

    /// Add `rows` (as read after the mutation) to `table`'s accumulator.
    pub(crate) fn added(&mut self, table: &str, rows: &[(i64, [u8; 32])]) {
        let entry = self.entry(table);
        for (_, digest) in rows {
            accumulate(&mut entry.added, &row_element(table, digest));
            entry.rows_added += 1;
        }
    }

    fn entry(&mut self, table: &str) -> &mut TableDelta {
        self.tables
            .entry(table.to_owned())
            .or_insert(TableDelta {
                removed: EMPTY_ACCUMULATOR,
                added: EMPTY_ACCUMULATOR,
                rows_removed: 0,
                rows_added: 0,
            })
    }

    /// The certified frontier after the expiry: `frontier` with each changed
    /// table's accumulator and count adjusted, and its bound re-anchored to
    /// the highest surviving rowid at or below it (with that row's digest).
    /// `None` when the bounding evaluation row did not survive: the
    /// evaluation sequence the semantic certification is bound to would move,
    /// so the next open validates in full instead.
    pub(crate) fn carry(
        &self,
        connection: &Connection,
        frontier: &HistoryFrontier,
    ) -> Result<Option<HistoryFrontier>, StoreError> {
        let mut carried = frontier.clone();
        for (table, delta) in &self.tables {
            let recorded = carried.tables.get_mut(table).ok_or_else(|| {
                StoreError::Integrity(format!(
                    "validation watermark has no frontier for history table {table}"
                ))
            })?;
            let mut accumulator = parse_accumulator(table, &recorded.accumulator)?;
            deduct(&mut accumulator, &delta.removed);
            accumulate(&mut accumulator, &delta.added);
            recorded.accumulator = hex(&accumulator);
            recorded.rows = recorded.rows - delta.rows_removed + delta.rows_added;
            let Some(bound) = recorded.max_rowid else {
                continue;
            };
            let surviving: Option<i64> = connection.query_row(
                &format!("SELECT MAX(rowid) FROM {table} WHERE rowid <= ?1"),
                [bound],
                |row| row.get(0),
            )?;
            if table == "evaluation_runs" && surviving != Some(bound) {
                return Ok(None);
            }
            recorded.max_rowid = surviving;
            recorded.boundary = match surviving {
                Some(rowid) => {
                    let columns = column_count(connection, table)?;
                    let mut statement = connection
                        .prepare(&format!("SELECT rowid, * FROM {table} WHERE rowid = ?1"))?;
                    let mut cursor = statement.query([rowid])?;
                    let row = cursor.next()?.ok_or_else(|| {
                        StoreError::Integrity(format!("history table {table} lost row {rowid}"))
                    })?;
                    Some(hex(&row_digest(row, columns)?))
                }
                None => None,
            };
            if recorded.rows < 0 || (surviving.is_none() && (recorded.rows != 0 || accumulator != EMPTY_ACCUMULATOR)) {
                return Err(StoreError::Integrity(format!(
                    "validation watermark carry-forward for history table {table} is inconsistent"
                )));
            }
        }
        Ok(Some(carried))
    }
}

/// Re-anchor append positions captured by a handle (positions only) after an
/// expiry deleted rows at or below them, so a reused rowid can never fall
/// inside a range the handle treats as validated.
pub(crate) fn reanchor_bounds(
    connection: &Connection,
    frontier: &HistoryFrontier,
) -> Result<HistoryFrontier, StoreError> {
    let mut out = frontier.clone();
    for (table, recorded) in &mut out.tables {
        if let Some(bound) = recorded.max_rowid {
            recorded.max_rowid = connection.query_row(
                &format!("SELECT MAX(rowid) FROM {table} WHERE rowid <= ?1"),
                [bound],
                |row| row.get(0),
            )?;
        }
    }
    let evaluation_bound = out.max_rowid("evaluation_runs");
    if evaluation_bound != frontier.max_rowid("evaluation_runs") {
        out.evaluation_sequence = match evaluation_bound {
            Some(rowid) => connection.query_row(
                "SELECT evaluation_sequence FROM evaluation_runs WHERE rowid = ?1",
                [rowid],
                |row| row.get(0),
            )?,
            None => 0,
        };
    }
    Ok(out)
}

/// Remove temporary watermark files that a killed writer left behind. Only
/// files older than ten minutes are removed, so a concurrent writer's file in
/// flight is left alone; failures are ignored (the next write retries).
fn remove_stale_temporaries(path: &Path) {
    const STALE: std::time::Duration = std::time::Duration::from_secs(600);
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let mut prefix = name.to_os_string();
    prefix.push(".tmp-");
    let prefix = prefix.to_string_lossy().into_owned();
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= STALE);
        if stale && entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Delta accessors for semantic history validation layered above the store.
/// Each returns the records whose obligations are not covered by `frontier`,
/// in append order; the caller reopens and validates exactly those.
impl crate::Store {
    /// Count this handle's SQL work into the thread's work counter (see
    /// [`start_sql_work_count`]) from now on, for a handle opened before
    /// counting started. Measurement only; inert unless counting.
    pub fn count_sql_work_on_this_handle(&self) {
        install_sql_work_counter(&self.connection);
    }

    /// The watermark this handle's open applied, or `None` when the open
    /// validated history in full.
    #[must_use]
    pub fn applied_watermark(&self) -> Option<&ValidationWatermark> {
        match &self.validation.opened {
            OpenValidation::SinceWatermark(watermark) => Some(watermark),
            OpenValidation::Full(_) => None,
        }
    }

    /// The applicable watermark of this store that a full validation
    /// (`open_validating_fully`) found and must not contradict: its covered
    /// rows (checked when recording) and its semantic certification
    /// (checked by the engine's full replay).
    #[must_use]
    pub fn prior_watermark(&self) -> Option<&ValidationWatermark> {
        self.validation.prior.as_deref()
    }

    /// History rows beyond the applied watermark's frontier: what the next
    /// engine open validates and records. O(rows beyond). `None` without an
    /// applied watermark.
    pub fn uncovered_history_rows(&self) -> Result<Option<i64>, StoreError> {
        let Some(frontier) = self.validated_history_frontier() else {
            return Ok(None);
        };
        let mut uncovered = 0i64;
        for table in HISTORY_TABLES {
            let beyond: i64 = self.connection.query_row(
                &format!("SELECT COUNT(*) FROM {table} NOT INDEXED WHERE rowid > ?1"),
                [frontier.max_rowid(table).unwrap_or(i64::MIN)],
                |row| row.get(0),
            )?;
            uncovered = uncovered.saturating_add(beyond);
        }
        Ok(Some(uncovered))
    }

    /// The append frontier this handle captured before its open validated
    /// history: the frontier a watermark recorded by this handle names.
    #[must_use]
    pub fn open_frontier(&self) -> Option<&HistoryFrontier> {
        self.validation.open_frontier.as_ref()
    }

    /// The frontier through which this handle has proven the store-level
    /// history laws: its open frontier, advanced by each of its own commits
    /// that validates the rows beyond it. `None` when its writers validate in
    /// full.
    #[must_use]
    pub fn store_validated_frontier(&self) -> Option<&HistoryFrontier> {
        self.validation.store_validated.as_ref()
    }

    /// The frontier this handle's open proved validated, or `None` when the
    /// open validated history in full (so callers must too).
    #[must_use]
    pub fn validated_history_frontier(&self) -> Option<&HistoryFrontier> {
        self.applied_watermark()
            .map(|watermark| &watermark.frontier)
    }

    /// The frontier through which the applied watermark certified the
    /// complete semantic history, with the replay state there; `None` when
    /// semantic history must be validated in full.
    #[must_use]
    pub fn validated_semantic_state(&self) -> Option<(&HistoryFrontier, &SemanticState)> {
        self.applied_watermark().and_then(|watermark| {
            watermark
                .semantic
                .as_ref()
                .map(|state| (&watermark.frontier, state))
        })
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

    /// The frontiers whose capture time bounds what newer rows can
    /// reference, newest first: this handle's store-validated frontier (its
    /// open frontier advanced by its own commits, each captured in one
    /// snapshot), then the applied watermark's. A row newer than one of them
    /// can be bounded by it; the newest that applies bounds most tightly.
    pub(crate) fn reference_frontiers(&self) -> impl Iterator<Item = &HistoryFrontier> {
        self.validation
            .store_validated
            .iter()
            .chain(self.validated_history_frontier())
    }

    /// Rowid lower bound for the evaluations that can name `run_id`: the
    /// handle's store-validated frontier when the run is newer than it; else,
    /// for a handle that has neither committed nor indexed evaluations by run
    /// (a short-lived reader), the applied watermark's frontier when the run
    /// is newer than that. `None` sends the lookup to the per-handle index,
    /// which a long-lived handle keeps current at the cost of the rows
    /// appended since, so its lookups never rescan from its open.
    pub(crate) fn run_evaluation_bound(&self, run_id: &str) -> Result<Option<i64>, StoreError> {
        if self.reference_frontiers().next().is_none() {
            return Ok(None);
        }
        let rowid: Option<i64> = self
            .connection
            .query_row(
                "SELECT rowid FROM watcher_runs WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(rowid) = rowid else {
            return Ok(None);
        };
        if let Some(bound) =
            crate::run_evaluation_bound(self.validation.store_validated.as_ref(), rowid)
        {
            return Ok(Some(bound));
        }
        let unadvanced = self.validation.store_validated == self.validation.open_frontier;
        if unadvanced && self.validation.run_evaluations.borrow().is_none() {
            return Ok(crate::run_evaluation_bound(
                self.validated_history_frontier(),
                rowid,
            ));
        }
        Ok(None)
    }

    /// Rowids of every evaluation triggered by `run_id`, in append order.
    /// `trigger_run_id` is unindexed in schema 13: a run newer than a
    /// reference frontier is answered from the rowid range beyond it (see
    /// [`Self::run_evaluation_bound`]); any other run from an index of
    /// evaluations by run built once per handle (one scan of the evaluation
    /// table) and extended by the committed range appended since, so a
    /// long-lived handle reads each evaluation once.
    pub(crate) fn run_evaluation_rowids(&self, run_id: &str) -> Result<Vec<i64>, StoreError> {
        let beyond = |bound: Option<i64>| -> Result<Vec<i64>, StoreError> {
            self.connection
                .prepare(&crate::run_evaluations_sql("rowid", bound))?
                .query_map([run_id], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        };
        if let Some(bound) = self.run_evaluation_bound(run_id)? {
            return beyond(Some(bound));
        }
        let mut cache = self.validation.run_evaluations.borrow_mut();
        // Only committed rows enter the index. Outside a transaction every
        // visible row is committed; inside one, the rows beyond the handle's
        // validated frontier may be this transaction's and may still roll
        // back, so the index covers rows only through it.
        let through = if self.connection.is_autocommit() {
            i64::MAX
        } else {
            self.validation
                .store_validated
                .as_ref()
                .and_then(|frontier| frontier.max_rowid("evaluation_runs"))
                .unwrap_or(i64::MIN)
        };
        match cache.as_mut() {
            None => *cache = Some(RunEvaluations::build(&self.connection, through)?),
            Some(index) => index.extend(&self.connection, through)?,
        }
        let index = cache
            .as_ref()
            .ok_or_else(|| StoreError::Invariant("evaluation index was not built".into()))?;
        let mut rowids = index.by_run.get(run_id).cloned().unwrap_or_default();
        rowids.extend(beyond(Some(index.bound.unwrap_or(i64::MIN)))?);
        Ok(rowids)
    }

    /// The canonical detail of every evaluation triggered by `run_id`, in
    /// append order.
    pub fn evaluation_details_for_run(&self, run_id: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        crate::evaluations_by_rowid(
            &self.connection,
            "detail_json",
            &self.run_evaluation_rowids(run_id)?,
            |row| row.get(0),
        )
    }
}
