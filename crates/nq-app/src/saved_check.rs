//! Canonical local contracts for saved checks and maintenance declarations.
//!
//! One bounded SQLite read yields a local check result. Store custody and
//! caller-supplied source observations do not confer diagnostic admissibility,
//! attention, admission, or notification authority.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

/// Supported read-only saved-check predicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedCheckMode {
    /// Fail when the query returns one or more rows.
    NonEmpty,
    /// Fail when the query returns no rows.
    Empty,
    /// Fail when a named numeric column exceeds its threshold.
    Threshold,
}

/// Canonical saved-check definition, before durable installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SavedCheckSchema {
    #[serde(rename = "nq.saved-check-definition/v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckDefinition {
    pub schema: SavedCheckSchema,
    /// Stable operator-selected reference.
    pub reference: String,
    /// Explicit local-adapter identity, never inferred from a pathname.
    pub source_identity: String,
    /// Maximum allowed age of that observation at evaluation.
    pub currentness_seconds: u32,
    /// Human-readable unique name.
    pub name: String,
    /// Read-only SQL query bytes.
    pub sql_text: String,
    /// Predicate applied to bounded query results.
    pub mode: SavedCheckMode,
    /// Required only for threshold mode.
    pub threshold: Option<f64>,
    /// Required only for threshold mode.
    pub column: Option<String>,
    /// Optional explanation retained with the definition.
    pub description: Option<String>,
}

/// Append-only declaration of an expected scoped disturbance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaintenanceSchema {
    #[serde(rename = "nq.maintenance-declaration/v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceDeclaration {
    pub schema: MaintenanceSchema,
    /// Stable declaration identifier.
    pub maintenance_id: String,
    /// Declaring operator identity string.
    pub declared_by: Option<String>,
    /// RFC3339 UTC start time, supplied as canonical text.
    pub start_at: String,
    /// RFC3339 UTC end time, supplied as canonical text.
    pub end_at: String,
    /// Exact component scope.
    pub component: String,
    /// Exact condition kind scope.
    pub kind: String,
    /// Optional wildcard-able subject scope.
    pub subject: Option<String>,
    /// Optional bounded rationale.
    pub reason: Option<String>,
}

/// Bounded, non-authoritative saved-check evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedCheckOutcome {
    Passed,
    Failed,
    Refused(&'static str),
}

/// Fixed limits on returned evidence and SQLite work.
pub const MAX_RESULT_ROWS: usize = 1_024;
pub const MAX_RESULT_BYTES: usize = 256 * 1024;
pub const MAX_EXECUTION_TIME: Duration = Duration::from_secs(2);

/// A declaration can annotate, but never alter, an underlying condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceAnnotation {
    Covered,
    Overrun,
}

/// Select a matching declaration using the legacy active/expired precedence.
pub fn maintenance_annotation<'a>(
    declarations: impl IntoIterator<Item = (&'a MaintenanceDeclaration, DateTime<Utc>)>,
    component: &str,
    kind: &str,
    subject: &str,
    now: DateTime<Utc>,
) -> Result<Option<(&'a MaintenanceDeclaration, MaintenanceAnnotation)>> {
    let mut active = Vec::new();
    let mut expired = Vec::new();
    for (d, declared_at) in declarations {
        // Invalid recorded material is an unavailable annotation, not proof
        // that the condition has no maintenance coverage.
        d.validate()?;
        // A projection at `now` cannot rely on a declaration retained later.
        // It may still describe a planned future window when that declaration
        // was already recorded at the projected time.
        if declared_at > now {
            continue;
        }
        if d.component != component
            || d.kind != kind
            || !d
                .subject
                .as_deref()
                .is_none_or(|p| wildcard_matches(p, subject))
        {
            continue;
        }
        let start = DateTime::parse_from_rfc3339(&d.start_at)
            .context("invalid retained maintenance start")?
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339(&d.end_at)
            .context("invalid retained maintenance end")?
            .with_timezone(&Utc);
        if start <= now && now < end {
            active.push((d, declared_at));
        } else if end <= now {
            expired.push((d, declared_at, end));
        }
    }
    active.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| b.0.maintenance_id.cmp(&a.0.maintenance_id))
    });
    if let Some((d, _)) = active.into_iter().next() {
        return Ok(Some((d, MaintenanceAnnotation::Covered)));
    }
    expired.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| b.0.maintenance_id.cmp(&a.0.maintenance_id))
    });
    Ok(expired
        .into_iter()
        .next()
        .map(|(d, _, _)| (d, MaintenanceAnnotation::Overrun)))
}

fn wildcard_matches(pattern: &str, subject: &str) -> bool {
    // Bounded dynamic programming: '*' may consume zero or more bytes.
    // Keeping one state per position avoids exponential duplicate states.
    let mut previous = vec![false; subject.len() + 1];
    previous[0] = true;
    for token in pattern.bytes() {
        let mut next = vec![false; subject.len() + 1];
        next[0] = token == b'*' && previous[0];
        for (index, byte) in subject.bytes().enumerate() {
            next[index + 1] = if token == b'*' {
                previous[index + 1] || next[index]
            } else {
                token == byte && previous[index]
            };
        }
        previous = next;
    }
    previous[subject.len()]
}

/// Evaluate one saved check against an explicit local SQLite target.
pub fn evaluate_read_only(
    definition: &SavedCheckDefinition,
    target: &std::path::Path,
    source_observed_at: DateTime<Utc>,
) -> Result<SavedCheckOutcome> {
    evaluate_read_only_at(definition, target, source_observed_at, Utc::now())
}

/// Evaluate only a current explicit source observation within fixed limits.
pub fn evaluate_read_only_at(
    definition: &SavedCheckDefinition,
    target: &std::path::Path,
    observed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<SavedCheckOutcome> {
    definition.validate()?;
    if now < observed_at
        || now.signed_duration_since(observed_at)
            > chrono::Duration::seconds(i64::from(definition.currentness_seconds))
    {
        return Ok(SavedCheckOutcome::Refused("source_not_current"));
    }
    let connection = Connection::open_with_flags(
        target,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("saved check target is unavailable")?;
    connection.busy_timeout(MAX_EXECUTION_TIME)?;
    // Bound individual SQLite values before Rust sees or allocates them. The
    // aggregate result limit below is separate from SQLite's per-value cap.
    connection.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        MAX_RESULT_BYTES as i32,
    )?;
    connection.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_COLUMN, 128)?;
    connection.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_EXPR_DEPTH, 100)?;
    connection.pragma_update(None, "query_only", "ON")?;
    let sql = definition.sql_text.trim();
    let keyword = sql
        .trim_start()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if keyword != "SELECT" && keyword != "WITH" {
        return Ok(SavedCheckOutcome::Refused("unsupported_statement"));
    }
    let timed_out = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + MAX_EXECUTION_TIME;
    let timeout = Arc::clone(&timed_out);
    connection.progress_handler(
        1_000,
        Some(move || {
            let stop = Instant::now() >= deadline;
            if stop {
                timeout.store(true, Ordering::Relaxed);
            }
            stop
        }),
    );
    let mut statement = match connection.prepare(sql) {
        Ok(value) => value,
        Err(_) => return Ok(SavedCheckOutcome::Refused("statement_preparation_failed")),
    };
    if !statement.readonly() {
        return Ok(SavedCheckOutcome::Refused("statement_not_read_only"));
    }
    let columns = statement
        .column_names()
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>();
    let threshold_index = match (&definition.mode, definition.column.as_deref()) {
        (SavedCheckMode::Threshold, Some(column)) => {
            match columns.iter().position(|name| name == column) {
                Some(index) => Some(index),
                None => return Ok(SavedCheckOutcome::Refused("threshold_column_missing")),
            }
        }
        _ => None,
    };
    let mut rows = match statement.query([]) {
        Ok(value) => value,
        Err(_) => return Ok(SavedCheckOutcome::Refused("query_failed")),
    };
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut exceeds = false;
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(_) => {
                return Ok(SavedCheckOutcome::Refused(
                    if timed_out.load(Ordering::Relaxed) {
                        "execution_time_limit"
                    } else {
                        "row_evaluation_failed"
                    },
                ));
            }
        };
        count += 1;
        if count > MAX_RESULT_ROWS {
            return Ok(SavedCheckOutcome::Refused("result_row_limit"));
        }
        for index in 0..columns.len() {
            let value = row.get_ref(index);
            let Ok(value) = value else {
                return Ok(SavedCheckOutcome::Refused("unsupported_result_value"));
            };
            bytes = bytes.saturating_add(match value {
                rusqlite::types::ValueRef::Null => 0,
                rusqlite::types::ValueRef::Integer(_) | rusqlite::types::ValueRef::Real(_) => 8,
                rusqlite::types::ValueRef::Text(value) => value.len(),
                rusqlite::types::ValueRef::Blob(value) => value.len(),
            });
            if bytes > MAX_RESULT_BYTES {
                return Ok(SavedCheckOutcome::Refused("result_byte_limit"));
            }
        }
        if let (Some(index), Some(threshold)) = (threshold_index, definition.threshold) {
            let value: std::result::Result<f64, _> = row.get(index);
            let Ok(value) = value else {
                return Ok(SavedCheckOutcome::Refused("threshold_value_not_numeric"));
            };
            if !value.is_finite() {
                return Ok(SavedCheckOutcome::Refused("threshold_value_not_finite"));
            }
            if value > threshold {
                exceeds = true;
            }
        }
    }
    if timed_out.load(Ordering::Relaxed) {
        return Ok(SavedCheckOutcome::Refused("execution_time_limit"));
    }
    Ok(match definition.mode {
        SavedCheckMode::NonEmpty => {
            if count > 0 {
                SavedCheckOutcome::Failed
            } else {
                SavedCheckOutcome::Passed
            }
        }
        SavedCheckMode::Empty => {
            if count == 0 {
                SavedCheckOutcome::Failed
            } else {
                SavedCheckOutcome::Passed
            }
        }
        SavedCheckMode::Threshold => {
            if exceeds {
                SavedCheckOutcome::Failed
            } else {
                SavedCheckOutcome::Passed
            }
        }
    })
}

fn bounded(field: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("{field} must be 1..={max} non-control bytes");
    }
    Ok(())
}

impl SavedCheckDefinition {
    /// Validate read-only legacy-compatible definition material.
    pub fn validate(&self) -> Result<()> {
        bounded("reference", &self.reference, 256)?;
        bounded("source_identity", &self.source_identity, 256)?;
        if self.currentness_seconds == 0 || self.currentness_seconds > 86_400 {
            bail!("currentness_seconds must be 1..=86400");
        }
        bounded("name", &self.name, 256)?;
        if self.sql_text.is_empty() || self.sql_text.len() > 16_384 || self.sql_text.contains('\0')
        {
            bail!("sql_text must contain 1..=16384 non-NUL bytes");
        }
        if let Some(value) = &self.description {
            bounded("description", value, 2048)?;
        }
        if let Some(value) = &self.column {
            bounded("column", value, 256)?;
        }
        // Preserve legacy multiline SQL and literals verbatim. The SQLite
        // evaluator, opened read-only, proves one read-only statement later.
        match self.mode {
            SavedCheckMode::Threshold
                if self.threshold.is_some_and(f64::is_finite)
                    && self.column.as_deref().is_some_and(|v| !v.is_empty()) => {}
            SavedCheckMode::Threshold => bail!("threshold mode requires threshold and column"),
            _ if self.threshold.is_none() && self.column.is_none() => {}
            _ => bail!("only threshold mode accepts threshold or column"),
        }
        Ok(())
    }
}

impl MaintenanceDeclaration {
    /// Validate bounded immutable scope material; timestamp ordering is checked
    /// by the clock-owning storage command.
    pub fn validate(&self) -> Result<()> {
        for (field, value, max) in [
            ("maintenance_id", &self.maintenance_id, 256),
            ("start_at", &self.start_at, 64),
            ("end_at", &self.end_at, 64),
            ("component", &self.component, 256),
            ("kind", &self.kind, 256),
        ] {
            bounded(field, value, max)?;
        }
        for (field, value, max) in [
            ("declared_by", self.declared_by.as_deref(), 256),
            ("subject", self.subject.as_deref(), 256),
            ("reason", self.reason.as_deref(), 1024),
        ] {
            if let Some(value) = value {
                bounded(field, value, max)?;
            }
        }
        if !self.start_at.ends_with('Z') || !self.end_at.ends_with('Z') {
            bail!("maintenance timestamps must be RFC3339 UTC");
        }
        let start = DateTime::parse_from_rfc3339(&self.start_at)
            .context("invalid maintenance start_at")?
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339(&self.end_at)
            .context("invalid maintenance end_at")?
            .with_timezone(&Utc);
        if start >= end {
            bail!("maintenance end_at must be after start_at");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn threshold_requires_complete_material_and_read_only_sql() {
        let mut c = SavedCheckDefinition {
            schema: SavedCheckSchema::V1,
            reference: "component.capacity".into(),
            source_identity: "fixture-source".into(),
            currentness_seconds: 60,
            name: "volume".into(),
            sql_text: "SELECT free_bytes FROM x".into(),
            mode: SavedCheckMode::Threshold,
            threshold: Some(1.0),
            column: Some("free_bytes".into()),
            description: None,
        };
        assert!(c.validate().is_ok());
        c.column = None;
        assert!(c.validate().is_err());
        c.mode = SavedCheckMode::Empty;
        c.threshold = None;
        c.sql_text = "WITH rows AS (SELECT ';' AS value)\nSELECT value FROM rows;".into();
        assert!(c.validate().is_ok());
    }
    #[test]
    fn maintenance_window_and_scope_are_bounded() {
        let d = MaintenanceDeclaration {
            schema: MaintenanceSchema::V1,
            maintenance_id: "m1".into(),
            declared_by: None,
            start_at: "2026-09-14T00:00:00Z".into(),
            end_at: "2026-09-14T00:01:00Z".into(),
            component: "component".into(),
            kind: "storage".into(),
            subject: None,
            reason: None,
        };
        assert!(d.validate().is_ok());
    }
    #[test]
    fn maintenance_refuses_non_utc_or_non_timestamp_windows() {
        let d = MaintenanceDeclaration {
            schema: MaintenanceSchema::V1,
            maintenance_id: "m1".into(),
            declared_by: Some("\n".into()),
            start_at: "not-a-time".into(),
            end_at: "2026-09-14T00:01:00+01:00".into(),
            component: "component".into(),
            kind: "kind".into(),
            subject: None,
            reason: None,
        };
        assert!(d.validate().is_err());
    }
    #[test]
    fn maintenance_active_and_expired_precedence_are_exact() {
        let base = MaintenanceDeclaration {
            schema: MaintenanceSchema::V1,
            maintenance_id: "a".into(),
            declared_by: None,
            start_at: "2026-09-14T00:00:00Z".into(),
            end_at: "2026-09-14T01:00:00Z".into(),
            component: "component".into(),
            kind: "capacity".into(),
            subject: Some("disk-*".into()),
            reason: None,
        };
        let mut later = base.clone();
        later.maintenance_id = "b".into();
        let declared = DateTime::parse_from_rfc3339("2026-09-13T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let now = DateTime::parse_from_rfc3339("2026-09-14T00:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            maintenance_annotation(
                [(&base, declared), (&later, declared)],
                "component",
                "capacity",
                "disk-root",
                now
            )
            .unwrap()
            .map(|(d, a)| (&d.maintenance_id, a)),
            Some((&"b".to_string(), MaintenanceAnnotation::Covered))
        );
        let after = DateTime::parse_from_rfc3339("2026-09-14T02:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            maintenance_annotation(
                [(&base, declared)],
                "component",
                "capacity",
                "disk-root",
                after
            )
            .unwrap()
            .map(|(_, a)| a),
            Some(MaintenanceAnnotation::Overrun)
        );
    }

    #[test]
    fn maintenance_recorded_after_projection_time_does_not_annotate_history() {
        let declaration = MaintenanceDeclaration {
            schema: MaintenanceSchema::V1,
            maintenance_id: "future-record".into(),
            declared_by: None,
            start_at: "2026-09-14T00:00:00Z".into(),
            end_at: "2026-09-14T01:00:00Z".into(),
            component: "component".into(),
            kind: "capacity".into(),
            subject: None,
            reason: None,
        };
        let at = DateTime::parse_from_rfc3339("2026-09-14T00:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let retained_later = DateTime::parse_from_rfc3339("2026-09-14T00:31:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            maintenance_annotation(
                [(&declaration, retained_later)],
                "component",
                "capacity",
                "subject",
                at,
            )
            .unwrap(),
            None
        );
    }
    #[test]
    fn stale_source_refuses_before_target_open() {
        let definition = SavedCheckDefinition {
            schema: SavedCheckSchema::V1,
            reference: "component.capacity".into(),
            source_identity: "fixture".into(),
            currentness_seconds: 1,
            name: "capacity".into(),
            sql_text: "SELECT 1".into(),
            mode: SavedCheckMode::Empty,
            threshold: None,
            column: None,
            description: None,
        };
        let now = DateTime::parse_from_rfc3339("2026-09-14T00:00:02Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            evaluate_read_only_at(
                &definition,
                std::path::Path::new("/absent/target.db"),
                now - chrono::Duration::seconds(2),
                now
            )
            .unwrap(),
            SavedCheckOutcome::Refused("source_not_current")
        );
    }
    #[test]
    fn wildcard_subject_requires_complete_match() {
        assert!(wildcard_matches("disk-*", "disk-root"));
        assert!(!wildcard_matches("disk-*", "volume-root"));
        assert!(wildcard_matches("*root", "root"));
        assert!(wildcard_matches("**", ""));
    }

    #[test]
    fn invalid_retained_maintenance_is_not_uncovered() {
        let invalid = MaintenanceDeclaration {
            schema: MaintenanceSchema::V1,
            maintenance_id: "invalid".into(),
            declared_by: None,
            start_at: "not-a-time".into(),
            end_at: "2026-09-14T01:00:00Z".into(),
            component: "component".into(),
            kind: "capacity".into(),
            subject: None,
            reason: None,
        };
        assert!(
            maintenance_annotation(
                [(&invalid, Utc::now())],
                "component",
                "capacity",
                "disk",
                Utc::now()
            )
            .is_err()
        );
    }

    fn run_sql(
        sql: &str,
        mode: SavedCheckMode,
        threshold: Option<f64>,
        column: Option<&str>,
    ) -> SavedCheckOutcome {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE samples(value INTEGER); INSERT INTO samples VALUES (2), (5);",
            )
            .unwrap();
        drop(connection);
        let definition = SavedCheckDefinition {
            schema: SavedCheckSchema::V1,
            reference: "generic.capacity".into(),
            source_identity: "local-fixture".into(),
            currentness_seconds: 30,
            name: "Generic check".into(),
            sql_text: sql.into(),
            mode,
            threshold,
            column: column.map(str::to_owned),
            description: None,
        };
        let now = Utc::now();
        evaluate_read_only_at(&definition, &path, now, now).unwrap()
    }

    #[test]
    fn saved_check_modes_preserve_predicate_semantics() {
        assert_eq!(
            run_sql(
                "SELECT value FROM samples",
                SavedCheckMode::NonEmpty,
                None,
                None
            ),
            SavedCheckOutcome::Failed
        );
        assert_eq!(
            run_sql(
                "SELECT value FROM samples WHERE 0",
                SavedCheckMode::NonEmpty,
                None,
                None
            ),
            SavedCheckOutcome::Passed
        );
        assert_eq!(
            run_sql(
                "SELECT value FROM samples",
                SavedCheckMode::Empty,
                None,
                None
            ),
            SavedCheckOutcome::Passed
        );
        assert_eq!(
            run_sql(
                "SELECT value FROM samples WHERE 0",
                SavedCheckMode::Empty,
                None,
                None
            ),
            SavedCheckOutcome::Failed
        );
        assert_eq!(
            run_sql(
                "SELECT value FROM samples",
                SavedCheckMode::Threshold,
                Some(5.0),
                Some("value")
            ),
            SavedCheckOutcome::Passed
        );
        assert_eq!(
            run_sql(
                "SELECT value FROM samples",
                SavedCheckMode::Threshold,
                Some(4.0),
                Some("value")
            ),
            SavedCheckOutcome::Failed
        );
    }

    #[test]
    fn multiline_and_quoted_semicolon_are_not_multiple_statements() {
        assert_eq!(
            run_sql(
                "WITH quoted AS (SELECT ';' AS value)\nSELECT value FROM quoted;",
                SavedCheckMode::Empty,
                None,
                None
            ),
            SavedCheckOutcome::Passed
        );
        assert_eq!(
            run_sql("SELECT 1; SELECT 2", SavedCheckMode::Empty, None, None),
            SavedCheckOutcome::Refused("statement_preparation_failed")
        );
    }

    #[test]
    fn row_error_is_not_a_successful_empty_result() {
        assert_eq!(
            run_sql(
                "SELECT abs(-9223372036854775808)",
                SavedCheckMode::NonEmpty,
                None,
                None
            ),
            SavedCheckOutcome::Refused("row_evaluation_failed")
        );
    }

    #[test]
    fn mutation_missing_columns_and_nonnumeric_values_refuse() {
        assert_eq!(
            run_sql(
                "SELECT 1e999 AS value",
                SavedCheckMode::Threshold,
                Some(1.0),
                Some("value")
            ),
            SavedCheckOutcome::Refused("threshold_value_not_finite")
        );
        assert_eq!(
            run_sql("DELETE FROM samples", SavedCheckMode::Empty, None, None),
            SavedCheckOutcome::Refused("unsupported_statement")
        );
        assert_eq!(
            run_sql(
                "SELECT value FROM samples",
                SavedCheckMode::Threshold,
                Some(1.0),
                Some("missing")
            ),
            SavedCheckOutcome::Refused("threshold_column_missing")
        );
        assert_eq!(
            run_sql(
                "SELECT 'text' AS value",
                SavedCheckMode::Threshold,
                Some(1.0),
                Some("value")
            ),
            SavedCheckOutcome::Refused("threshold_value_not_numeric")
        );
    }

    #[test]
    fn excessive_rows_and_single_values_refuse() {
        assert_eq!(
            run_sql(
                "WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<1025) SELECT v FROM n",
                SavedCheckMode::Empty,
                None,
                None
            ),
            SavedCheckOutcome::Refused("result_row_limit")
        );
        assert_eq!(
            run_sql("SELECT zeroblob(262145)", SavedCheckMode::Empty, None, None),
            SavedCheckOutcome::Refused("row_evaluation_failed")
        );
    }

    #[test]
    fn same_saved_definition_accepts_a_new_explicit_source_observation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE sample(v INTEGER);")
            .unwrap();
        let definition = SavedCheckDefinition {
            schema: SavedCheckSchema::V1,
            reference: "generic.repeat".into(),
            source_identity: "fixture".into(),
            currentness_seconds: 1,
            name: "Repeat".into(),
            sql_text: "SELECT 1".into(),
            mode: SavedCheckMode::Empty,
            threshold: None,
            column: None,
            description: None,
        };
        let now = Utc::now();
        assert_eq!(
            evaluate_read_only_at(&definition, &path, now - chrono::Duration::seconds(2), now)
                .unwrap(),
            SavedCheckOutcome::Refused("source_not_current")
        );
        assert_eq!(
            evaluate_read_only_at(&definition, &path, now, now).unwrap(),
            SavedCheckOutcome::Passed
        );
    }
}
