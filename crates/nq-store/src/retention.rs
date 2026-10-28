//! Conservative prefix reclamation inside the existing store. Dependencies
//! stop the prefix; capacity refusal is preferable to guessing their release.
use crate::history_scope::{ExpiryDelta, OpenValidation, RetentionWitness};
use crate::{CanonicalDocument, HistoryFrontier, Scope, Store, StoreError, ValidationState};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetentionBoundary {
    pub generation: i64,
    pub evaluation_floor: i64,
    pub report_floor: i64,
    pub intake_floor: i64,
    pub status_floor: i64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionResult {
    pub boundary: RetentionBoundary,
    pub deleted_rows: usize,
    /// A batch-limited expiry selected its limit of candidate runs, so more
    /// aged history may remain eligible for the next batch.
    pub candidates_remaining: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LineageFloor {
    detector_id: String,
    detector_version: String,
    revision: i64,
}

/// Subprocess qualification stops without running SQLite/Store destructors.
/// This hook and its environment selector do not exist in production builds.
#[cfg(test)]
fn crash_phase_for_test(phase: &str, exit_code: i32) {
    if std::env::var("NQ_RETENTION_CRASH_PHASE").as_deref() == Ok(phase) {
        std::process::exit(exit_code);
    }
}

fn present(connection: &Connection) -> Result<bool, StoreError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='retention_state')",
        [],
        |r| r.get(0),
    )?)
}
pub(crate) fn boundary(connection: &Connection) -> Result<RetentionBoundary, StoreError> {
    if !present(connection)? {
        return Ok(RetentionBoundary::default());
    }
    connection.query_row("SELECT generation,evaluation_floor,report_floor,intake_floor,status_floor FROM retention_state WHERE singleton=1", [], |r| Ok(RetentionBoundary {generation:r.get(0)?,evaluation_floor:r.get(1)?,report_floor:r.get(2)?,intake_floor:r.get(3)?,status_floor:r.get(4)?})).map_err(StoreError::from)
}
/// The retention witness a validation watermark is bound to: the boundary
/// plus the digest of the exact persisted retired lineage floors.
pub(crate) fn witness(connection: &Connection) -> Result<RetentionWitness, StoreError> {
    let b = boundary(connection)?;
    let floors: Vec<u8> = if present(connection)? {
        connection.query_row(
            "SELECT lineage_floors_json FROM retention_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?
    } else {
        Vec::new()
    };
    Ok(RetentionWitness {
        generation: b.generation,
        evaluation_floor: b.evaluation_floor,
        report_floor: b.report_floor,
        intake_floor: b.intake_floor,
        status_floor: b.status_floor,
        lineage_floors_digest: crate::sha256_digest(&floors),
    })
}

fn validate_boundary_header(connection: &Connection) -> Result<RetentionBoundary, StoreError> {
    let b = boundary(connection)?;
    let enabled: i64 = connection.query_row(
        "SELECT delete_enabled FROM retention_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if enabled != 0 || (b.generation == 0 && b != RetentionBoundary::default()) {
        return Err(StoreError::Integrity(
            "invalid retention boundary or unfinished deletion transaction".into(),
        ));
    }
    let bytes: Vec<u8> = connection.query_row(
        "SELECT lineage_floors_json FROM retention_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let floors: Vec<LineageFloor> =
        serde_json::from_slice(&bytes).map_err(|e| StoreError::Integrity(e.to_string()))?;
    if (b.generation == 0 && !floors.is_empty()) || floors.iter().any(|f| f.revision <= 0) {
        return Err(StoreError::Integrity(
            "invalid retired lineage revisions".into(),
        ));
    }
    Ok(b)
}

pub(crate) fn validate_boundary_scoped(
    connection: &Connection,
    scope: crate::Scope<'_>,
) -> Result<(), StoreError> {
    let b = validate_boundary_header(connection)?;
    // Before any expiry, the certified append-only frontier already proves
    // old rows. Check only newly appended intake rows for an impossible retired
    // representation. Full validation and every post-expiry path still prove
    // complete retained coverage and retired identity commitments below.
    if b.generation > 0 && !scope.is_full() {
        return validate_boundary_since(connection, &b, scope);
    }
    if b.generation == 0 && !scope.is_full() {
        let new_rows = scope.new_rows("provider_intake_attempts", "p");
        let invalid: bool = connection.query_row(&format!(
            "SELECT EXISTS(SELECT 1 FROM provider_intake_attempts p WHERE ({new_rows}) AND (history_expired!=0 OR retired_identity_digest IS NOT NULL OR retired_run_id IS NOT NULL OR retired_submission_id IS NOT NULL OR retired_report_id IS NOT NULL OR retired_report_semantic_digest IS NOT NULL))"
        ), [], |r| r.get(0))?;
        if invalid {
            return Err(StoreError::Integrity(
                "retired intake without expiry boundary".into(),
            ));
        }
        return Ok(());
    }
    validate_boundary(connection)
}

/// After expiry, an incremental scope relies on a watermark certified under
/// this exact boundary (identity binds it), so the retained-below-floor
/// declaration and every retired commitment were proven when it was
/// certified or carried forward. Rows appended since must lie above every
/// floor, be full (never compact or retired), and continue each sequence
/// contiguously. O(new rows).
fn validate_boundary_since(
    connection: &Connection,
    b: &RetentionBoundary,
    scope: Scope<'_>,
) -> Result<(), StoreError> {
    let holes = holes_schema(connection)?;
    for (table, column, floor, compact) in [
        ("evaluation_runs", "evaluation_sequence", b.evaluation_floor, holes.then_some("source_expired<>0")),
        ("admitted_reports", "report_sequence", b.report_floor, holes.then_some("source_expired<>0")),
        (
            "provider_intake_attempts",
            "intake_sequence",
            b.intake_floor,
            Some("history_expired<>0 OR retired_identity_digest IS NOT NULL OR retired_run_id IS NOT NULL OR retired_submission_id IS NOT NULL OR retired_report_id IS NOT NULL OR retired_report_semantic_digest IS NOT NULL"),
        ),
        ("status_events", "status_sequence", b.status_floor, None),
    ] {
        let new_rows = scope.new_rows(table, "t");
        let (count, minimum, maximum, invalid): (i64, Option<i64>, Option<i64>, bool) = connection.query_row(
            &format!(
                "SELECT COUNT(*),MIN({column}),MAX({column}),COALESCE(MAX({column}<=?1 OR ({})),0) FROM {table} AS t WHERE {new_rows}",
                compact.unwrap_or("0")
            ),
            [floor],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        if invalid {
            return Err(StoreError::Integrity(format!(
                "{table} revives an expired prefix: a row appended since validation is at or below floor {floor} or not full"
            )));
        }
        if count == 0 {
            continue;
        }
        let previous: Option<i64> = match scope.frontier().and_then(|frontier| frontier.max_rowid(table)) {
            Some(bound) => connection
                .query_row(&format!("SELECT {column} FROM {table} WHERE rowid=?1"), [bound], |r| r.get(0))
                .optional()?,
            None => None,
        };
        let start = previous.unwrap_or(0).max(floor) + 1;
        if minimum != Some(start) || maximum != Some(start + count - 1) {
            return Err(StoreError::Integrity(format!(
                "{table} has an undeclared retained coverage gap"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_boundary(connection: &Connection) -> Result<(), StoreError> {
    validate_boundary_with(connection, None)
}

/// [`validate_boundary`]; with `retired_now`, the retired provider identity
/// commitments are recomputed only for those intakes (the ones this expiry
/// transaction retired; earlier ones were proven when the certification the
/// caller relies on was established) instead of for every retired intake.
fn validate_boundary_with(
    connection: &Connection,
    retired_now: Option<&[String]>,
) -> Result<(), StoreError> {
    let b = validate_boundary_header(connection)?;
    if retired_now.is_some() {
        // Inside an expiry that relies on a certification under the previous
        // boundary: rows above the new floors were contiguous above the old
        // ones and the expiry changed none of them, so only the candidate
        // closures it selected need their new declared form proven.
        validate_retained_below_floors_filtered(connection, &b, true)?;
    } else {
        validate_retained_below_floors(connection, &b)?;
    }
    for (table, column, floor) in [
        ("admitted_reports", "report_sequence", b.report_floor),
        (
            "provider_intake_attempts",
            "intake_sequence",
            b.intake_floor,
        ),
        ("status_events", "status_sequence", b.status_floor),
    ] {
        if retired_now.is_some() {
            break;
        }
        let (count, minimum, maximum): (i64, Option<i64>, Option<i64>) = connection.query_row(
            &format!("SELECT COUNT(*),MIN({column}),MAX({column}) FROM {table} WHERE {column}>?1"),
            [floor],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if count > 0 && (minimum != Some(floor + 1) || maximum != Some(floor + count)) {
            return Err(StoreError::Integrity(format!(
                "{table} has an undeclared retained coverage gap"
            )));
        }
    }
    let intake_scope = if retired_now.is_some() {
        "intake_id IN (SELECT intake_id FROM expiry_links UNION SELECT l.intake_id FROM local_watcher_provider_intakes l WHERE l.run_id IN (SELECT run_id FROM expiry_runs)) AND "
    } else {
        ""
    };
    let invalid:i64=connection.query_row(&(format!("SELECT COUNT(*) FROM provider_intake_attempts WHERE {intake_scope}(") + "(history_expired=1 AND (intake_sequence>?1 OR retired_identity_digest IS NULL OR retired_run_id IS NULL OR length(raw_bytes)!=0 OR context_json!=CAST('{}' AS BLOB) OR interpretation_json!=CAST('{}' AS BLOB) OR native_outcome_json!=CAST('{}' AS BLOB))) OR (history_expired=0 AND (retired_identity_digest IS NOT NULL OR retired_run_id IS NOT NULL OR retired_submission_id IS NOT NULL OR retired_report_id IS NOT NULL OR retired_report_semantic_digest IS NOT NULL)))"),[b.intake_floor],|r|r.get(0))?;
    if invalid != 0 {
        return Err(StoreError::Integrity(
            "invalid expired provider identity commitment".into(),
        ));
    }
    let expired: Vec<(String, String)> = match retired_now {
        None => connection.prepare("SELECT intake_id,retired_identity_digest FROM provider_intake_attempts WHERE history_expired=1")?.query_map([],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<Result<_,_>>()?,
        Some(ids) => {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                out.push((id.clone(), connection.query_row("SELECT retired_identity_digest FROM provider_intake_attempts WHERE intake_id=?1 AND history_expired=1", [id], |r| r.get(0))?));
            }
            out
        }
    };
    for (id, expected) in expired {
        if retired_identity_commitment(connection, &id)? != expected {
            return Err(StoreError::Integrity(format!(
                "expired provider identity commitment {id} changed"
            )));
        }
    }
    Ok(())
}
/// Each full evaluation in `scope` carries the exact derived
/// `min_cited_report_sequence` (the lowest sequence among admitted reports
/// its envelope names), on which expiry's closure relies to find the
/// evaluations that name an aged report.
pub(crate) fn validate_cited_report_sequences(
    connection: &Connection,
    scope: Scope<'_>,
) -> Result<(), StoreError> {
    if !holes_schema(connection)? {
        return Ok(());
    }
    let new_rows = scope.new_rows("evaluation_runs", "e");
    let invalid: Option<String> = connection
        .query_row(
            &format!(
                "SELECT e.evaluation_id FROM evaluation_runs e WHERE ({new_rows}) AND e.source_expired=0 AND e.min_cited_report_sequence IS NOT (SELECT MIN((SELECT a.report_sequence FROM admitted_reports a WHERE a.report_id=j.value)) FROM json_tree(CAST(e.detail_json AS TEXT)) j WHERE j.type='text') LIMIT 1"
            ),
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id) = invalid {
        return Err(StoreError::Integrity(format!(
            "evaluation {id} misstates the lowest admitted report its envelope names"
        )));
    }
    Ok(())
}

/// Evaluation `e` (full) has a root relationship that may keep it below the
/// floor: a finding or saved-check row names it, it is a diagnostic origin,
/// or it is the newest evaluation of its lineage at or below the floor.
fn evaluation_root_sql(e: &str) -> String {
    let lineage_e = lineage_sql(e);
    let lineage_n = lineage_sql("root_newer");
    format!(
        "(EXISTS(SELECT 1 FROM finding_events root_f WHERE root_f.evaluation_id={e}.evaluation_id) OR EXISTS(SELECT 1 FROM saved_check_events root_c WHERE root_c.evaluation_id={e}.evaluation_id) OR EXISTS(SELECT 1 FROM local_diagnostic_artifact_origins root_o WHERE root_o.evaluation_id={e}.evaluation_id) OR NOT EXISTS(SELECT 1 FROM evaluation_watermarks root_w JOIN evaluation_runs root_newer ON root_newer.evaluation_id=root_w.evaluation_id WHERE root_w.instance_id=(SELECT own.instance_id FROM evaluation_watermarks own WHERE own.evaluation_id={e}.evaluation_id) AND root_newer.detector_id={e}.detector_id AND root_newer.detector_version={e}.detector_version AND root_newer.evaluation_revision>{e}.evaluation_revision AND root_newer.evaluation_sequence<=?1 AND root_newer.source_expired=0 AND {lineage_n}={lineage_e}))"
    )
}

/// Run `x` has a root relationship that justifies keeping its whole closure
/// below the floors. Liveness is not required: a root released since the last
/// expiry stays legal until the next expiry reclaims it. Parameters: ?1
/// evaluation floor, ?2 report floor, ?4 status floor.
fn justified_run_sql(x: &str) -> String {
    let evaluation_root = evaluation_root_sql("je");
    format!(
        "(EXISTS(SELECT 1 FROM local_successor_acquisition_intents js WHERE js.run_id={x})
          OR EXISTS(SELECT 1 FROM local_diagnostic_artifact_origins jo WHERE jo.run_id={x})
          OR EXISTS(SELECT 1 FROM evaluation_runs je WHERE je.trigger_run_id={x} AND je.source_expired=0 AND {evaluation_root})
          OR EXISTS(SELECT 1 FROM raw_submissions jr JOIN admitted_reports ja ON ja.submission_id=jr.submission_id WHERE jr.run_id={x} AND ja.source_expired=0 AND (
               ja.report_id IN (SELECT report_id FROM finding_evidence)
            OR ja.report_sequence=(SELECT MAX(jx.report_sequence) FROM admitted_reports jx WHERE jx.instance_id=ja.instance_id AND jx.report_sequence<=?2)
            OR EXISTS(SELECT 1 FROM evaluation_watermarks jw JOIN evaluation_runs jwe ON jwe.evaluation_id=jw.evaluation_id WHERE jw.instance_id=ja.instance_id AND jw.max_report_sequence=ja.report_sequence AND jwe.source_expired=0)
            OR EXISTS(SELECT 1 FROM evaluation_runs jj, json_tree(CAST(jj.detail_json AS TEXT)) j WHERE jj.source_expired=0 AND jj.min_cited_report_sequence IS NOT NULL AND jj.min_cited_report_sequence<=ja.report_sequence AND j.type='text' AND j.value=ja.report_id)
            OR (ja.next_checkpoint_json IS NOT NULL AND EXISTS(SELECT 1 FROM watcher_runs jcw JOIN local_watcher_provider_intakes jcl ON jcl.run_id=jcw.run_id JOIN provider_intake_acknowledgments jca ON jca.intake_id=jcl.intake_id AND jca.run_id=jcl.run_id WHERE jcw.run_id={x} AND NOT EXISTS(SELECT 1 FROM admitted_reports newer JOIN raw_submissions ns ON ns.submission_id=newer.submission_id JOIN watcher_runs nw ON nw.run_id=ns.run_id JOIN local_watcher_provider_intakes nl ON nl.run_id=nw.run_id JOIN provider_intake_acknowledgments na ON na.intake_id=nl.intake_id AND na.run_id=nl.run_id WHERE newer.instance_id=ja.instance_id AND nw.checkpoint_contract_digest=jcw.checkpoint_contract_digest AND newer.next_checkpoint_json IS NOT NULL AND newer.report_sequence>ja.report_sequence AND newer.report_sequence<=?2)))))
          OR EXISTS(SELECT 1 FROM status_events jt WHERE jt.run_id={x} AND jt.status_sequence=(SELECT MAX(jo2.status_sequence) FROM status_events jo2 WHERE jo2.component_kind=jt.component_kind AND jo2.component_id=jt.component_id AND jo2.run_id IS NOT NULL AND jo2.status_sequence<=?4)))"
    )
}

/// Declared protected holes: every row that survives at or below a floor is
/// either part of a whole collection some root relationship justifies, or a
/// compact source record a retained consequential row names. Anything else is
/// an undeclared retained row and fails closed. A live root whose closure was
/// compacted fails closed too (under-retention).
fn validate_retained_below_floors(
    connection: &Connection,
    b: &RetentionBoundary,
) -> Result<(), StoreError> {
    validate_retained_below_floors_filtered(connection, b, false)
}

/// [`validate_retained_below_floors`]; with `candidates`, only the rows of
/// the current expiry plan's candidate closures (its `expiry_evaluations`,
/// `expiry_runs` and `expiry_compact_reports`) are checked.
#[allow(clippy::too_many_lines)]
fn validate_retained_below_floors_filtered(
    connection: &Connection,
    b: &RetentionBoundary,
    candidates: bool,
) -> Result<(), StoreError> {
    let only = |filter: &str| if candidates { format!(" AND {filter}") } else { String::new() };
    let evaluation_filter = only("e.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations)");
    let floors = [
        b.evaluation_floor,
        b.report_floor,
        b.intake_floor,
        b.status_floor,
    ];
    // Each check binds exactly the floors it names (?1..?4 by position).
    let first = |sql: &str| -> Result<Option<String>, StoreError> {
        let mut statement = connection.prepare(sql)?;
        let count = statement.parameter_count();
        Ok(statement
            .query_row(rusqlite::params_from_iter(&floors[..count]), |r| r.get(0))
            .optional()?)
    };
    let justified = |x: &str| justified_run_sql(x);
    let evaluation_root = evaluation_root_sql("e");
    for (table, floor, sql) in [
        (
            "evaluation_runs",
            b.evaluation_floor,
            format!("SELECT e.evaluation_id FROM evaluation_runs e WHERE e.evaluation_sequence<=?1 AND e.source_expired=0{evaluation_filter} AND NOT ({evaluation_root} OR (e.trigger_run_id IS NOT NULL AND {})) ORDER BY e.evaluation_sequence LIMIT 1", justified("e.trigger_run_id")),
        ),
        (
            "admitted_reports",
            b.report_floor,
            format!("SELECT a.report_id FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE a.report_sequence<=?2 AND a.source_expired=0{} AND NOT {} ORDER BY a.report_sequence LIMIT 1", only("r.run_id IN (SELECT run_id FROM expiry_runs)"), justified("r.run_id")),
        ),
        (
            "provider_intake_attempts",
            b.intake_floor,
            format!("SELECT p.intake_id FROM provider_intake_attempts p LEFT JOIN local_watcher_provider_intakes l ON l.intake_id=p.intake_id WHERE p.intake_sequence<=?3 AND p.history_expired=0{} AND (l.run_id IS NULL OR NOT {}) ORDER BY p.intake_sequence LIMIT 1", only("p.intake_id IN (SELECT intake_id FROM expiry_links UNION SELECT x.intake_id FROM local_watcher_provider_intakes x WHERE x.run_id IN (SELECT run_id FROM expiry_runs))"), justified("l.run_id")),
        ),
        (
            "status_events",
            b.status_floor,
            format!("SELECT s.status_event_id FROM status_events s WHERE s.status_sequence<=?4 AND s.run_id IS NOT NULL{} AND NOT {} ORDER BY s.status_sequence LIMIT 1", only("s.run_id IN (SELECT run_id FROM expiry_runs)"), justified("s.run_id")),
        ),
    ] {
        if let Some(key) = first(&sql)? {
            return Err(StoreError::Integrity(format!(
                "{table} revives an expired prefix: undeclared retained row {key} below floor {floor}"
            )));
        }
    }
    if let Some(id) = first(&(format!("SELECT e.evaluation_id FROM evaluation_runs e WHERE e.source_expired=1{evaluation_filter} AND (") + "e.evaluation_sequence>?1 OR e.detail_json<>CAST('{}' AS BLOB) OR NOT (EXISTS(SELECT 1 FROM finding_events f WHERE f.evaluation_id=e.evaluation_id) OR EXISTS(SELECT 1 FROM saved_check_events c WHERE c.evaluation_id=e.evaluation_id)) OR EXISTS(SELECT 1 FROM evaluation_watermarks w WHERE w.evaluation_id=e.evaluation_id) OR EXISTS(SELECT 1 FROM refusals x WHERE x.evaluation_id=e.evaluation_id) OR (e.trigger_run_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM raw_submissions s WHERE s.run_id=e.trigger_run_id AND s.source_expired=1))) LIMIT 1"))? {
        return Err(StoreError::Integrity(format!(
            "source-expired evaluation {id} is not a declared decision record"
        )));
    }
    if let Some(id) = first(&(format!("SELECT a.report_id FROM admitted_reports a WHERE a.source_expired=1{} AND (", only("a.submission_id IN (SELECT submission_id FROM raw_submissions WHERE run_id IN (SELECT run_id FROM expiry_runs))")) + "a.report_sequence>?2 OR a.canonical_json<>CAST('{}' AS BLOB) OR a.validated_report_json<>CAST('{}' AS BLOB) OR a.next_checkpoint_json IS NOT NULL OR NOT (a.report_id IN (SELECT report_id FROM finding_evidence) OR EXISTS(SELECT 1 FROM raw_submissions r JOIN evaluation_runs e ON e.trigger_run_id=r.run_id WHERE r.submission_id=a.submission_id AND e.source_expired=1)) OR EXISTS(SELECT 1 FROM observations o WHERE o.report_id=a.report_id) OR EXISTS(SELECT 1 FROM report_coverage c WHERE c.report_id=a.report_id) OR EXISTS(SELECT 1 FROM report_errors x WHERE x.report_id=a.report_id) OR NOT EXISTS(SELECT 1 FROM raw_submissions r WHERE r.submission_id=a.submission_id AND r.source_expired=1)) LIMIT 1"))? {
        return Err(StoreError::Integrity(format!(
            "source-expired report {id} is not a declared evidence record"
        )));
    }
    if let Some(id) = first(&(format!("SELECT r.submission_id FROM raw_submissions r WHERE r.source_expired=1{} AND (", only("r.run_id IN (SELECT run_id FROM expiry_runs)")) + "length(r.raw_bytes)<>0 OR r.admission_outcome<>'admitted' OR NOT EXISTS(SELECT 1 FROM admitted_reports a WHERE a.submission_id=r.submission_id AND a.source_expired=1) OR EXISTS(SELECT 1 FROM status_events s WHERE s.run_id=r.run_id) OR EXISTS(SELECT 1 FROM local_watcher_provider_intakes l WHERE l.run_id=r.run_id)) LIMIT 1"))? {
        return Err(StoreError::Integrity(format!(
            "source-expired submission {id} is not a declared anchor"
        )));
    }
    if let Some(id) = first(&format!("SELECT e.evaluation_id FROM evaluation_runs e JOIN raw_submissions s ON s.run_id=e.trigger_run_id WHERE e.source_expired=0 AND s.source_expired=1{} LIMIT 1", only("s.run_id IN (SELECT run_id FROM expiry_runs)")))? {
        return Err(StoreError::Integrity(format!(
            "evaluation {id} keeps full history for a source-expired run"
        )));
    }
    let live = live_finding_event_sql("f");
    let live_events = if candidates {
        "(SELECT f.* FROM finding_events f WHERE f.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations) UNION SELECT f.* FROM expiry_compact_reports c JOIN finding_evidence v ON v.report_id=c.report_id JOIN finding_events f ON f.event_id=v.event_id)"
    } else {
        "finding_events"
    };
    // A live event may cite a compact report only as a re-citation of
    // evidence first cited at or before the finding's latest resolution
    // before it: that evidence was released with the resolved episode, and
    // a later event that supplies no evidence of its own (cannot evaluate)
    // keeps it by identity. Evidence of a continuously unresolved episode is
    // always protected, so any other compact citation is under-retention.
    if let Some(id) = first(&format!("SELECT f.event_id FROM {live_events} f WHERE {live} AND (EXISTS(SELECT 1 FROM evaluation_runs e WHERE e.evaluation_id=f.evaluation_id AND e.source_expired=1) OR EXISTS(SELECT 1 FROM finding_evidence v JOIN admitted_reports a ON a.report_id=v.report_id WHERE v.event_id=f.event_id AND a.source_expired=1 AND NOT {})) LIMIT 1", released_recitation_sql("f", "v")))? {
        return Err(StoreError::Integrity(format!(
            "live protected closure compacted: finding event {id}"
        )));
    }
    if let Some(id) = first(&(format!("SELECT c.evaluation_id FROM saved_check_events c JOIN evaluation_runs e ON e.evaluation_id=c.evaluation_id WHERE e.source_expired=1{evaluation_filter} AND c.outcome='claimed' ") + "AND NOT EXISTS(SELECT 1 FROM saved_check_events t WHERE t.evaluation_id=c.evaluation_id AND t.outcome IN ('refused','passed','failed')) LIMIT 1"))? {
        return Err(StoreError::Integrity(format!(
            "live protected closure compacted: saved-check claim {id}"
        )));
    }
    Ok(())
}

pub(crate) fn lineage_floor(
    connection: &Connection,
    id: &str,
    version: &str,
) -> Result<i64, StoreError> {
    if !present(connection)? {
        return Ok(0);
    }
    let bytes: Vec<u8> = connection.query_row(
        "SELECT lineage_floors_json FROM retention_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let floors: Vec<LineageFloor> =
        serde_json::from_slice(&bytes).map_err(|e| StoreError::Integrity(e.to_string()))?;
    Ok(floors
        .into_iter()
        .find(|f| f.detector_id == id && f.detector_version == version)
        .map_or(0, |f| f.revision))
}
pub(crate) fn available_intake_condition(
    connection: &Connection,
    alias: &str,
) -> Result<String, StoreError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    Ok(if version >= 14 {
        format!("{alias}.history_expired=0")
    } else {
        "1".into()
    })
}
fn retired_identity_commitment(connection: &Connection, id: &str) -> Result<String, StoreError> {
    retired_identity_commitment_with_links(connection, id, None)
}
fn retired_identity_commitment_with_links(
    connection: &Connection,
    id: &str,
    links: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Result<String, StoreError> {
    let names: Vec<String> = connection
        .prepare("PRAGMA table_info(provider_intake_attempts)")?
        .query_map([], |r| r.get(1))?
        .collect::<Result<_, _>>()?;
    let names: Vec<_> = names
        .into_iter()
        .filter(|n| {
            ![
                "raw_bytes",
                "context_json",
                "interpretation_json",
                "native_outcome_json",
                "history_expired",
                "retired_identity_digest",
            ]
            .contains(&n.as_str())
        })
        .collect();
    let sql = format!(
        "SELECT {} FROM provider_intake_attempts WHERE intake_id=?1",
        names.join(",")
    );
    let mut values = connection.query_row(&sql, [id], |row| {
        let mut values = serde_json::Map::new();
        for (index, name) in names.iter().enumerate() {
            let value = match row.get_ref(index)? {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(n) => serde_json::Value::from(n),
                rusqlite::types::ValueRef::Text(t) => {
                    serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                }
                _ => {
                    return Err(rusqlite::Error::InvalidColumnType(
                        index,
                        name.clone(),
                        row.get_ref(index)?.data_type(),
                    ));
                }
            };
            values.insert(name.clone(), value);
        }
        Ok(serde_json::Value::Object(values))
    })?;
    if let (serde_json::Value::Object(values), Some(links)) = (&mut values, links) {
        values.extend(links.clone());
    }
    Ok(CanonicalDocument::from_serializable(&values)?
        .digest()
        .to_owned())
}
// Only a contiguous prefix can retire. A fresh earliest anchor therefore
// blocks the prefix even when later timestamps are older. This is a candidate
// test, not a claim that every historical row is recent or dependency-free.
fn prefix_may_advance(
    connection: &Connection,
    cutoff: &str,
    b: &RetentionBoundary,
) -> Result<bool, StoreError> {
    Ok(connection.query_row(
        "WITH first_runs(run_id) AS (
            SELECT run_id FROM raw_submissions WHERE submission_id=(SELECT submission_id FROM admitted_reports WHERE report_sequence>?2 ORDER BY report_sequence LIMIT 1)
            UNION SELECT run_id FROM local_watcher_provider_intakes WHERE intake_id=(SELECT intake_id FROM provider_intake_attempts WHERE intake_sequence>?3 ORDER BY intake_sequence LIMIT 1)
            UNION SELECT run_id FROM status_events WHERE status_sequence=(CASE WHEN EXISTS(SELECT 1 FROM status_events WHERE run_id IS NOT NULL LIMIT 1) THEN (SELECT status_sequence FROM status_events WHERE status_sequence>?4 AND run_id IS NOT NULL ORDER BY status_sequence LIMIT 1) END)
        ) SELECT EXISTS(SELECT 1 FROM evaluation_runs WHERE evaluation_sequence=(SELECT evaluation_sequence FROM evaluation_runs WHERE evaluation_sequence>?5 ORDER BY evaluation_sequence LIMIT 1) AND julianday(evaluated_at)<julianday(?1))
        OR EXISTS(SELECT 1 FROM first_runs f JOIN watcher_runs w ON w.run_id=f.run_id WHERE julianday(w.finished_at)<julianday(?1)
            AND NOT EXISTS(SELECT 1 FROM raw_submissions r WHERE r.run_id=w.run_id AND (julianday(r.received_at)>=julianday(?1) OR julianday(r.received_at) IS NULL))
            AND NOT EXISTS(SELECT 1 FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE r.run_id=w.run_id AND (julianday(a.received_at)>=julianday(?1) OR julianday(a.admitted_at)>=julianday(?1) OR julianday(a.received_at) IS NULL OR julianday(a.admitted_at) IS NULL))
            AND NOT EXISTS(SELECT 1 FROM local_watcher_provider_intakes l JOIN provider_intake_attempts p ON p.intake_id=l.intake_id WHERE l.run_id=w.run_id AND (julianday(p.received_at)>=julianday(?1) OR julianday(p.received_at) IS NULL)))",
        params![cutoff,b.report_floor,b.intake_floor,b.status_floor,b.evaluation_floor], |r| r.get(0),
    )? || released_island_exists(connection, b)?)
}

/// A full evaluation kept below the floor for a finding or saved-check root
/// whose obligation has ended (resolved and custody terminal, or claim
/// completed), and which no other evaluation root still holds. Such an
/// island becomes reclaimable even when no new row has aged.
fn released_island_exists(
    connection: &Connection,
    b: &RetentionBoundary,
) -> Result<bool, StoreError> {
    Ok(released_islands(connection, b)? > 0)
}

/// Count of [`released_island_exists`] candidates.
fn released_islands(connection: &Connection, b: &RetentionBoundary) -> Result<i64, StoreError> {
    if b.generation == 0 || !holes_schema(connection)? {
        return Ok(0);
    }
    let live = live_finding_event_sql("f");
    let newest = lineage_newest_sql("e");
    Ok(connection.query_row(
        &format!(
            "SELECT COUNT(*) FROM (SELECT 1 FROM evaluation_runs e WHERE e.evaluation_sequence<=?1 AND e.source_expired=0
               AND (EXISTS(SELECT 1 FROM finding_events f WHERE f.evaluation_id=e.evaluation_id) OR EXISTS(SELECT 1 FROM saved_check_events c WHERE c.evaluation_id=e.evaluation_id))
               AND NOT EXISTS(SELECT 1 FROM finding_events f WHERE f.evaluation_id=e.evaluation_id AND {live})
               AND NOT EXISTS(SELECT 1 FROM saved_check_events c WHERE c.evaluation_id=e.evaluation_id AND c.outcome='claimed' AND NOT EXISTS(SELECT 1 FROM saved_check_events t WHERE t.evaluation_id=c.evaluation_id AND t.outcome IN ('refused','passed','failed')))
               AND NOT EXISTS(SELECT 1 FROM local_diagnostic_artifact_origins o WHERE o.evaluation_id=e.evaluation_id)
               AND NOT EXISTS(SELECT 1 FROM local_diagnostic_artifact_origins o WHERE o.run_id=e.trigger_run_id)
               AND NOT EXISTS(SELECT 1 FROM local_successor_acquisition_intents s WHERE s.run_id=e.trigger_run_id)
               AND NOT {newest})"
        ),
        [b.evaluation_floor],
        |r| r.get(0),
    )?)
}

/// SQL for the evaluation-lineage identity of `evaluation_runs` row `alias`,
/// over the same envelope fields the engine's lineage key covers. Compact
/// rows carry no envelope and never match a full row.
pub(crate) fn lineage_sql(alias: &str) -> String {
    let field = |path: &str| {
        format!("json_extract(CAST({alias}.detail_json AS TEXT),'{path}')")
    };
    format!(
        "json_array({},{},{},{},{},{},{})",
        field("$.context.instance_id"),
        field("$.detector"),
        field("$.profile"),
        field("$.context.subject"),
        field("$.context.scope"),
        field("$.context.vantage"),
        field("$.result.condition"),
    )
}

/// Evaluation `e` is the newest full evaluation of its evaluation lineage.
/// Candidates are read through the instance-scoped watermark index, so a
/// stale lineage of a removed instance is decided from that instance's rows.
pub(crate) fn lineage_newest_sql(e: &str) -> String {
    let lineage_e = lineage_sql(e);
    let lineage_n = lineage_sql("newer");
    format!(
        "NOT EXISTS(SELECT 1 FROM evaluation_watermarks newer_watermark JOIN evaluation_runs newer ON newer.evaluation_id=newer_watermark.evaluation_id WHERE newer_watermark.instance_id=(SELECT own.instance_id FROM evaluation_watermarks own WHERE own.evaluation_id={e}.evaluation_id) AND newer.detector_id={e}.detector_id AND newer.detector_version={e}.detector_version AND newer.evaluation_revision>{e}.evaluation_revision AND newer.source_expired=0 AND {lineage_n}={lineage_e})"
    )
}

/// Whether the connection's schema has declared protected holes (v15+).
pub(crate) fn holes_schema(connection: &Connection) -> Result<bool, StoreError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    Ok(version >= 15)
}

/// Predicate selecting full (not source-expired) rows of `alias`.
pub(crate) fn full_source_condition(
    connection: &Connection,
    alias: &str,
) -> Result<String, StoreError> {
    Ok(if holes_schema(connection)? {
        format!("{alias}.source_expired=0")
    } else {
        "1".into()
    })
}

/// Predicate over a run alias excluding compact anchor runs: runs kept only as
/// the identity a compact report or evaluation names. Their result, intake and
/// evaluation closure expired; they are validated as commitments instead.
pub(crate) fn non_anchor_run_condition(
    connection: &Connection,
    run_alias: &str,
) -> Result<String, StoreError> {
    Ok(if holes_schema(connection)? {
        format!(
            "NOT EXISTS (SELECT 1 FROM raw_submissions AS anchor_submission WHERE anchor_submission.run_id = {run_alias}.run_id AND anchor_submission.source_expired = 1)"
        )
    } else {
        "1".into()
    })
}

/// Notification custody for outbox row `o` has ended: a delivery intent has an
/// accepted, refused or failed outcome, or a legacy outbox (no intent) is
/// terminal exactly as `public_notification_status_v1` reports it: an attempt
/// delivered, or its attempts reached `max_attempts`. A legacy `failed`
/// attempt below `max_attempts` reads as pending there and keeps custody
/// here. `unknown` and pending keep it.
const CUSTODY_TERMINAL: &str = "((EXISTS(SELECT 1 FROM notification_delivery_intents i WHERE i.notification_id=o.notification_id) AND EXISTS(SELECT 1 FROM notification_delivery_events d WHERE d.notification_id=o.notification_id AND d.outcome IN ('accepted','refused','failed'))) OR (NOT EXISTS(SELECT 1 FROM notification_delivery_intents i WHERE i.notification_id=o.notification_id) AND (EXISTS(SELECT 1 FROM notification_attempts a WHERE a.notification_id=o.notification_id AND a.outcome='delivered') OR (SELECT COUNT(*) FROM notification_attempts a WHERE a.notification_id=o.notification_id)>=o.max_attempts)))";

/// Evidence row `v` of finding event `f` re-cites a report that an earlier
/// event of the same finding cited at or before the finding's latest
/// resolution preceding `f` (evidence released with a resolved episode).
pub(crate) fn released_recitation_sql(f: &str, v: &str) -> String {
    format!(
        "EXISTS(SELECT 1 FROM finding_events rx JOIN finding_evidence rv ON rv.event_id=rx.event_id WHERE rx.finding_id={f}.finding_id AND rx.event_revision<{f}.event_revision AND rv.report_id={v}.report_id AND rv.report_semantic_digest={v}.report_semantic_digest AND EXISTS(SELECT 1 FROM finding_events rz WHERE rz.finding_id={f}.finding_id AND rz.event_kind='resolved' AND rz.event_revision>=rx.event_revision AND rz.event_revision<{f}.event_revision))"
    )
}

/// Finding events `e` whose closure must stay complete: the latest event and
/// the current episode's opening event of an unresolved finding, and any event
/// whose notification custody has not ended, unless its closure was already
/// compacted before that custody began. Such custody keeps the finding event
/// itself (finding rows are never deleted) but cannot restore the released
/// sources, so it holds nothing more and never makes a compacted closure
/// "live" (which validation would then reject as under-retention).
pub(crate) fn live_finding_event_sql(e: &str) -> String {
    format!(
        "(EXISTS(SELECT 1 FROM finding_current c JOIN finding_events h ON h.event_id=c.latest_event_id WHERE c.finding_id={e}.finding_id AND h.condition_state<>'explicitly_absent' AND (h.event_id={e}.event_id OR {e}.event_revision=(SELECT MAX(x.event_revision) FROM finding_events x WHERE x.finding_id={e}.finding_id AND x.event_kind IN ('opened','reopened')))) OR (EXISTS(SELECT 1 FROM notification_outbox o WHERE o.finding_event_id={e}.event_id AND NOT {CUSTODY_TERMINAL}) AND NOT EXISTS(SELECT 1 FROM evaluation_runs custody_e WHERE custody_e.evaluation_id={e}.evaluation_id AND custody_e.source_expired=1)))"
    )
}

/// The expiry decision computed inside the guarded transaction. Temporary
/// tables carry the selected rows to the mutation phase:
/// `expiry_runs` (aged candidates), `expiry_protected` (island runs),
/// `expiry_evaluations` (full evaluations at or below the new floor with their
/// disposition: island, compact, or delete), `expiry_compact_reports`, and
/// `expiry_dead_runs` (runs whose closure retires; `anchor=1` keeps the run
/// row because a compact report names it).
struct ExpiryPlan {
    evaluation_floor: i64,
    report_floor: i64,
    intake_floor: i64,
    status_floor: i64,
    affected_runs: i64,
    affected_evaluations: i64,
    candidates_remaining: bool,
}

#[allow(clippy::too_many_lines)]
fn plan_expiry(
    tx: &Connection,
    cutoff: &str,
    before: &RetentionBoundary,
    max_candidate_runs: Option<usize>,
) -> Result<ExpiryPlan, StoreError> {
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS expiry_runs(run_id TEXT PRIMARY KEY); DELETE FROM expiry_runs;
         CREATE TEMP TABLE IF NOT EXISTS expiry_protected(run_id TEXT PRIMARY KEY); DELETE FROM expiry_protected;
         CREATE TEMP TABLE IF NOT EXISTS expiry_evaluations(evaluation_id TEXT PRIMARY KEY, trigger_run_id TEXT, disposition TEXT NOT NULL); DELETE FROM expiry_evaluations;
         CREATE TEMP TABLE IF NOT EXISTS expiry_compact_reports(report_id TEXT PRIMARY KEY); DELETE FROM expiry_compact_reports;
         CREATE TEMP TABLE IF NOT EXISTS expiry_dead_runs(run_id TEXT PRIMARY KEY, anchor INTEGER NOT NULL); DELETE FROM expiry_dead_runs;",
    )?;
    // Aged, completed runs. Anchor runs (a compact report names them) are
    // already retired and never candidates again.
    tx.execute("INSERT INTO expiry_runs SELECT run_id FROM watcher_runs w WHERE julianday(finished_at)<julianday(?1) AND NOT EXISTS(SELECT 1 FROM raw_submissions r WHERE r.run_id=w.run_id AND (julianday(r.received_at)>=julianday(?1) OR julianday(r.received_at) IS NULL)) AND NOT EXISTS(SELECT 1 FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE r.run_id=w.run_id AND (julianday(a.received_at)>=julianday(?1) OR julianday(a.admitted_at)>=julianday(?1) OR julianday(a.received_at) IS NULL OR julianday(a.admitted_at) IS NULL)) AND NOT EXISTS(SELECT 1 FROM local_watcher_provider_intakes l JOIN provider_intake_attempts p ON p.intake_id=l.intake_id WHERE l.run_id=w.run_id AND (julianday(p.received_at)>=julianday(?1) OR julianday(p.received_at) IS NULL)) AND NOT EXISTS(SELECT 1 FROM raw_submissions s WHERE s.run_id=w.run_id AND s.source_expired=1)", [cutoff])?;
    // A batch keeps every existing island (re-examined each time, O(islands))
    // and only the oldest `max_candidate_runs` aged runs beyond the floors,
    // in append order; floors then advance over that prefix only. Runs at or
    // below the status floor are existing islands (an expired run's status
    // event is deleted with it).
    let mut candidates_remaining = false;
    if let Some(limit) = max_candidate_runs {
        let trimmed = tx.execute(
            "DELETE FROM expiry_runs WHERE run_id IN (SELECT x.run_id FROM expiry_runs x JOIN watcher_runs w ON w.run_id=x.run_id WHERE NOT EXISTS(SELECT 1 FROM status_events s WHERE s.run_id=x.run_id AND s.status_sequence<=?1) ORDER BY w.rowid LIMIT -1 OFFSET ?2)",
            params![before.status_floor, i64::try_from(limit).unwrap_or(i64::MAX)],
        )?;
        candidates_remaining = trimmed > 0;
    }
    // Floors stop only at young rows or rows of non-candidate runs; protected
    // dependencies no longer stop them (declared holes). Rows already at or
    // below a floor are islands or compact records and never lower it.
    let (ef, rf, inf, sf) = loop {
        let run_count: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_runs", [], |r| r.get(0))?;
        let ef: i64 = tx.query_row("SELECT MAX(?2, COALESCE((SELECT MIN(evaluation_sequence)-1 FROM evaluation_runs e WHERE evaluation_sequence>?2 AND (julianday(evaluated_at)>=julianday(?1) OR julianday(evaluated_at) IS NULL OR (trigger_run_id IS NOT NULL AND trigger_run_id NOT IN (SELECT run_id FROM expiry_runs)))),(SELECT MAX(evaluation_sequence) FROM evaluation_runs),?2))", params![cutoff, before.evaluation_floor], |r| r.get(0))?;
        let rf: i64 = tx.query_row("SELECT MAX(?1, COALESCE((SELECT MIN(a.report_sequence)-1 FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE a.report_sequence>?1 AND r.run_id NOT IN (SELECT run_id FROM expiry_runs)),(SELECT MAX(report_sequence) FROM admitted_reports),?1))", [before.report_floor], |r| r.get(0))?;
        let inf: i64 = tx.query_row("SELECT MAX(?1, COALESCE((SELECT MIN(p.intake_sequence)-1 FROM provider_intake_attempts p LEFT JOIN local_watcher_provider_intakes l ON l.intake_id=p.intake_id WHERE p.intake_sequence>?1 AND p.history_expired=0 AND (l.run_id IS NULL OR l.run_id NOT IN (SELECT run_id FROM expiry_runs))),(SELECT MAX(intake_sequence) FROM provider_intake_attempts),?1))", [before.intake_floor], |r| r.get(0))?;
        let sf: i64 = tx.query_row("SELECT MAX(?1, COALESCE((SELECT MIN(status_sequence)-1 FROM status_events WHERE status_sequence>?1 AND run_id IS NOT NULL AND run_id NOT IN (SELECT run_id FROM expiry_runs)),(SELECT MAX(status_sequence) FROM status_events WHERE run_id IS NOT NULL),?1))", [before.status_floor], |r| r.get(0))?;
        tx.execute("DELETE FROM expiry_runs WHERE run_id IN(SELECT trigger_run_id FROM evaluation_runs WHERE evaluation_sequence>?1 UNION SELECT r.run_id FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE a.report_sequence>?2 UNION SELECT l.run_id FROM local_watcher_provider_intakes l JOIN provider_intake_attempts p ON p.intake_id=l.intake_id WHERE p.intake_sequence>?3 UNION SELECT run_id FROM status_events WHERE status_sequence>?4)", params![ef, rf, inf, sf])?;
        let after: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_runs", [], |r| r.get(0))?;
        if after == run_count {
            break (ef, rf, inf, sf);
        }
    };
    // Full evaluations at or below the new floor: newly eligible ones and
    // existing islands, each re-examined against the live roots.
    tx.execute("INSERT INTO expiry_evaluations SELECT evaluation_id, trigger_run_id, 'delete' FROM evaluation_runs WHERE evaluation_sequence<=?1 AND source_expired=0", [ef])?;
    let live = live_finding_event_sql("e");
    let newest = lineage_newest_sql("e");
    // Evaluation roots: live finding events, pending saved-check claims,
    // diagnostic origins, and the newest evaluation of every evaluation
    // lineage (so no lineage ever disappears from status).
    tx.execute(&format!("UPDATE expiry_evaluations SET disposition='island' WHERE evaluation_id IN (
            SELECT e.evaluation_id FROM finding_events e WHERE e.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations) AND {live}
            UNION SELECT c.evaluation_id FROM saved_check_events c WHERE c.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations) AND c.outcome='claimed' AND NOT EXISTS(SELECT 1 FROM saved_check_events t WHERE t.evaluation_id=c.evaluation_id AND t.outcome IN ('refused','passed','failed'))
            UNION SELECT o.evaluation_id FROM local_diagnostic_artifact_origins o WHERE o.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations)
            UNION SELECT e.evaluation_id FROM evaluation_runs e WHERE e.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations) AND {newest})"), [])?;
    // Run roots. Every root names a candidate run only through the
    // `expiry_runs` join, so non-candidate runs are untouched.
    // Each root is probed per candidate run through the run's own indexed
    // rows, so the work is O(candidates), not O(retained history).
    tx.execute(&format!("INSERT OR IGNORE INTO expiry_protected SELECT x.run_id FROM expiry_runs x WHERE
               EXISTS(SELECT 1 FROM local_successor_acquisition_intents i WHERE i.run_id=x.run_id)
            OR EXISTS(SELECT 1 FROM local_diagnostic_artifact_origins o WHERE o.run_id=x.run_id)
            OR EXISTS(SELECT 1 FROM status_events s JOIN status_current c ON c.latest_status_event_id=s.status_event_id WHERE s.run_id=x.run_id)
            OR EXISTS(SELECT 1 FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE r.run_id=x.run_id AND a.report_sequence=(SELECT MAX(m.report_sequence) FROM admitted_reports m WHERE m.instance_id=a.instance_id))
            OR EXISTS(SELECT 1 FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id JOIN watcher_runs w ON w.run_id=r.run_id JOIN local_watcher_provider_intakes l ON l.run_id=w.run_id JOIN provider_intake_acknowledgments ack ON ack.intake_id=l.intake_id AND ack.run_id=l.run_id WHERE r.run_id=x.run_id AND a.next_checkpoint_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM admitted_reports newer JOIN raw_submissions ns ON ns.submission_id=newer.submission_id JOIN watcher_runs nw ON nw.run_id=ns.run_id JOIN local_watcher_provider_intakes nl ON nl.run_id=nw.run_id JOIN provider_intake_acknowledgments na ON na.intake_id=nl.intake_id AND na.run_id=nl.run_id WHERE newer.instance_id=a.instance_id AND nw.checkpoint_contract_digest=w.checkpoint_contract_digest AND newer.next_checkpoint_json IS NOT NULL AND newer.report_sequence>a.report_sequence))
            OR EXISTS(SELECT 1 FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id JOIN finding_evidence f ON f.report_id=a.report_id JOIN finding_events e ON e.event_id=f.event_id WHERE r.run_id=x.run_id AND {live})"), [])?;
    // Closure: an island run keeps every evaluation it triggered, and every
    // surviving full evaluation keeps the reports it names (watermark report
    // and any report id its envelope carries).
    loop {
        let protected: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_protected", [], |r| r.get(0))?;
        let islands: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_evaluations WHERE disposition='island'", [], |r| r.get(0))?;
        tx.execute("INSERT OR IGNORE INTO expiry_protected SELECT trigger_run_id FROM expiry_evaluations WHERE disposition='island' AND trigger_run_id IS NOT NULL AND trigger_run_id IN (SELECT run_id FROM expiry_runs)", [])?;
        tx.execute("UPDATE expiry_evaluations SET disposition='island' WHERE trigger_run_id IN (SELECT run_id FROM expiry_protected)", [])?;
        tx.execute("INSERT OR IGNORE INTO expiry_protected SELECT r.run_id FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE r.run_id IN (SELECT run_id FROM expiry_runs) AND (EXISTS(SELECT 1 FROM evaluation_watermarks w JOIN evaluation_runs e ON e.evaluation_id=w.evaluation_id WHERE w.instance_id=a.instance_id AND w.max_report_sequence=a.report_sequence AND (e.evaluation_sequence>?1 OR e.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations WHERE disposition='island'))) OR EXISTS(SELECT 1 FROM evaluation_runs e, json_tree(CAST(e.detail_json AS TEXT)) j WHERE e.source_expired=0 AND e.min_cited_report_sequence IS NOT NULL AND e.min_cited_report_sequence<=a.report_sequence AND (e.evaluation_sequence>?1 OR e.evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations WHERE disposition='island')) AND j.type='text' AND j.value=a.report_id))", [ef])?;
        let protected_after: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_protected", [], |r| r.get(0))?;
        let islands_after: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_evaluations WHERE disposition='island'", [], |r| r.get(0))?;
        if protected == protected_after && islands == islands_after {
            break;
        }
    }
    // Released decisions that retained finding or saved-check rows still name
    // stay as compact records; everything else at or below the floor retires.
    tx.execute("UPDATE expiry_evaluations SET disposition='compact' WHERE disposition='delete' AND (evaluation_id IN (SELECT evaluation_id FROM finding_events) OR evaluation_id IN (SELECT evaluation_id FROM saved_check_events WHERE evaluation_id IS NOT NULL))", [])?;
    tx.execute("INSERT INTO expiry_compact_reports SELECT a.report_id FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE a.source_expired=0 AND a.report_sequence<=?1 AND r.run_id IN (SELECT run_id FROM expiry_runs) AND r.run_id NOT IN (SELECT run_id FROM expiry_protected) AND (a.report_id IN (SELECT report_id FROM finding_evidence) OR r.run_id IN (SELECT trigger_run_id FROM expiry_evaluations WHERE disposition='compact'))", [rf])?;
    tx.execute("INSERT INTO expiry_dead_runs SELECT e.run_id, EXISTS(SELECT 1 FROM raw_submissions r JOIN expiry_compact_reports c ON c.report_id=(SELECT a.report_id FROM admitted_reports a WHERE a.submission_id=r.submission_id) WHERE r.run_id=e.run_id) FROM expiry_runs e WHERE e.run_id NOT IN (SELECT run_id FROM expiry_protected)", [])?;
    let affected_runs: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_dead_runs", [], |r| r.get(0))?;
    let affected_evaluations: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_evaluations WHERE disposition<>'island'", [], |r| r.get(0))?;
    Ok(ExpiryPlan {
        evaluation_floor: ef,
        report_floor: rf,
        intake_floor: inf,
        status_floor: sf,
        affected_runs,
        affected_evaluations,
        candidates_remaining,
    })
}

/// Operator-facing retention state (`nq doctor`): the expired-through
/// boundary, the declared islands kept below it by root kind, the compact
/// records, notification custody holds, and the age of the oldest history
/// still above the floors. Counts are per root kind; one island can have
/// several roots.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RetentionReport {
    pub generation: i64,
    pub evaluation_floor: i64,
    pub report_floor: i64,
    pub intake_floor: i64,
    pub status_floor: i64,
    pub cutoff: Option<String>,
    pub horizon_seconds: Option<u64>,
    pub island_runs: i64,
    pub island_evaluations: i64,
    pub islands_by_root: std::collections::BTreeMap<String, i64>,
    pub compact_evaluations: i64,
    pub compact_reports: i64,
    pub retired_intake_commitments: i64,
    pub custody_pending_events: i64,
    pub custody_unknown_events: i64,
    /// Notifications bound to a finding event (`finding_event_id`): only
    /// these engage the notification-custody hold.
    pub custody_bound_notifications: i64,
    /// Notifications with no finding event (every intent submitted by the
    /// shipped notification commands): they never hold history.
    pub custody_unbound_notifications: i64,
    pub oldest_unexpired_run_finished_at: Option<String>,
    /// Rows that survive expiry permanently (see docs/retention.md,
    /// "Permanent residue"). They are charged to the byte budget.
    pub residue: ResidueCounts,
}

/// Permanent residue rows: compact source records, anchor runs, retired
/// intake commitments, and the finding rows that name them. None is ever
/// reclaimed, including after the finding resolves.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ResidueCounts {
    pub compact_evaluations: i64,
    pub compact_reports: i64,
    pub compact_raw_submissions: i64,
    pub anchor_runs: i64,
    pub retired_intake_commitments: i64,
    pub finding_events: i64,
    pub finding_evidence: i64,
}

/// Operator-facing capacity state: the persisted envelope against current
/// occupancy, and whether an ordinary write would be admitted now.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CapacityReport {
    pub aggregate_bytes: u64,
    pub occupied_bytes: u64,
    pub main_bytes: u64,
    pub max_pages: u64,
    pub page_count: i64,
    pub freelist_pages: i64,
    pub reserve_bytes: u64,
    pub available_bytes: u64,
    pub preflight: String,
}

impl Store {
    pub fn retention_boundary(&self) -> Result<RetentionBoundary, StoreError> {
        boundary(&self.connection)
    }
    /// The retention state `nq doctor` reports. Read-only.
    #[allow(clippy::too_many_lines)]
    pub fn retention_report(&self) -> Result<RetentionReport, StoreError> {
        let b = self.retention_boundary()?;
        let c = &self.connection;
        let cutoff: Option<String> =
            c.query_row("SELECT cutoff FROM retention_state WHERE singleton=1", [], |r| r.get(0))?;
        let horizon_seconds = self
            .retention_capacity_document()
            .ok()
            .and_then(|document| {
                serde_json::from_slice::<crate::capacity::OperatingEnvelope>(document.as_bytes()).ok()
            })
            .map(|envelope| envelope.policy.horizon_seconds);
        let count = |sql: &str| -> Result<i64, StoreError> {
            let mut statement = c.prepare(sql)?;
            let n = statement.parameter_count();
            let floors = [b.evaluation_floor, b.report_floor, b.intake_floor, b.status_floor];
            Ok(statement.query_row(rusqlite::params_from_iter(&floors[..n]), |r| r.get(0))?)
        };
        let mut report = RetentionReport {
            generation: b.generation,
            evaluation_floor: b.evaluation_floor,
            report_floor: b.report_floor,
            intake_floor: b.intake_floor,
            status_floor: b.status_floor,
            cutoff,
            horizon_seconds,
            ..RetentionReport::default()
        };
        report.retired_intake_commitments =
            count("SELECT COUNT(*) FROM provider_intake_attempts WHERE history_expired=1")?;
        let custody = format!(
            "SELECT COUNT(DISTINCT o.finding_event_id) FROM notification_outbox o WHERE o.finding_event_id IS NOT NULL AND NOT {CUSTODY_TERMINAL}"
        );
        report.custody_pending_events = count(&custody)?;
        report.custody_unknown_events = count("SELECT COUNT(DISTINCT o.finding_event_id) FROM notification_outbox o JOIN notification_delivery_events d ON d.notification_id=o.notification_id WHERE o.finding_event_id IS NOT NULL AND d.outcome='unknown'")?;
        report.custody_bound_notifications =
            count("SELECT COUNT(*) FROM notification_outbox WHERE finding_event_id IS NOT NULL")?;
        report.custody_unbound_notifications =
            count("SELECT COUNT(*) FROM notification_outbox WHERE finding_event_id IS NULL")?;
        report.oldest_unexpired_run_finished_at = c.query_row(
            "SELECT MIN(w.finished_at) FROM watcher_runs w JOIN status_events s ON s.run_id=w.run_id WHERE s.status_sequence>?1",
            [b.status_floor],
            |r| r.get(0),
        )?;
        report.residue.retired_intake_commitments = report.retired_intake_commitments;
        report.residue.finding_events = count("SELECT COUNT(*) FROM finding_events")?;
        report.residue.finding_evidence = count("SELECT COUNT(*) FROM finding_evidence")?;
        if b.generation == 0 || !holes_schema(c)? {
            return Ok(report);
        }
        report.residue.compact_raw_submissions =
            count("SELECT COUNT(*) FROM raw_submissions WHERE source_expired=1")?;
        report.residue.anchor_runs = count(
            "SELECT COUNT(*) FROM watcher_runs w WHERE EXISTS(SELECT 1 FROM raw_submissions r WHERE r.run_id=w.run_id AND r.source_expired=1)",
        )?;
        report.compact_evaluations =
            count("SELECT COUNT(*) FROM evaluation_runs WHERE source_expired=1")?;
        report.compact_reports =
            count("SELECT COUNT(*) FROM admitted_reports WHERE source_expired=1")?;
        report.residue.compact_evaluations = report.compact_evaluations;
        report.residue.compact_reports = report.compact_reports;
        report.island_evaluations = count(
            "SELECT COUNT(*) FROM evaluation_runs WHERE evaluation_sequence<=?1 AND source_expired=0",
        )?;
        report.island_runs = count("SELECT COUNT(*) FROM watcher_runs w WHERE EXISTS(SELECT 1 FROM status_events s WHERE s.run_id=w.run_id AND s.status_sequence<=?4)")?;
        let live = live_finding_event_sql("f");
        let newest = lineage_newest_sql("e");
        let island = "e.evaluation_sequence<=?1 AND e.source_expired=0";
        let island_run = "EXISTS(SELECT 1 FROM status_events s WHERE s.run_id=x.run_id AND s.status_sequence<=?4)";
        for (kind, sql) in [
            ("unresolved_finding", format!("SELECT COUNT(*) FROM evaluation_runs e WHERE {island} AND EXISTS(SELECT 1 FROM finding_events f JOIN finding_current c ON c.finding_id=f.finding_id JOIN finding_events h ON h.event_id=c.latest_event_id WHERE f.evaluation_id=e.evaluation_id AND h.condition_state<>'explicitly_absent' AND {live})")),
            ("notification_custody", format!("SELECT COUNT(*) FROM evaluation_runs e WHERE {island} AND EXISTS(SELECT 1 FROM finding_events f JOIN notification_outbox o ON o.finding_event_id=f.event_id WHERE f.evaluation_id=e.evaluation_id AND NOT {CUSTODY_TERMINAL})")),
            ("saved_check_claim", format!("SELECT COUNT(*) FROM evaluation_runs e WHERE {island} AND EXISTS(SELECT 1 FROM saved_check_events c WHERE c.evaluation_id=e.evaluation_id AND c.outcome='claimed' AND NOT EXISTS(SELECT 1 FROM saved_check_events t WHERE t.evaluation_id=c.evaluation_id AND t.outcome IN ('refused','passed','failed')))")),
            ("lineage_latest", format!("SELECT COUNT(*) FROM evaluation_runs e WHERE {island} AND {newest}")),
            ("diagnostic_origin", format!("SELECT COUNT(*) FROM watcher_runs x WHERE {island_run} AND EXISTS(SELECT 1 FROM local_diagnostic_artifact_origins o WHERE o.run_id=x.run_id)")),
            ("successor_intent", format!("SELECT COUNT(*) FROM watcher_runs x WHERE {island_run} AND EXISTS(SELECT 1 FROM local_successor_acquisition_intents i WHERE i.run_id=x.run_id)")),
            ("status_current", format!("SELECT COUNT(*) FROM watcher_runs x WHERE {island_run} AND EXISTS(SELECT 1 FROM status_events s JOIN status_current c ON c.latest_status_event_id=s.status_event_id WHERE s.run_id=x.run_id)")),
            ("latest_report", format!("SELECT COUNT(*) FROM watcher_runs x WHERE {island_run} AND EXISTS(SELECT 1 FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE r.run_id=x.run_id AND a.report_sequence=(SELECT MAX(m.report_sequence) FROM admitted_reports m WHERE m.instance_id=a.instance_id))")),
        ] {
            report.islands_by_root.insert(kind.to_owned(), count(&sql)?);
        }
        report
            .islands_by_root
            .insert("released_pending".to_owned(), released_islands(c, &b)?);
        Ok(report)
    }

    /// Persisted envelope against current occupancy, and whether an ordinary
    /// write would be admitted now. Read-only.
    pub fn capacity_report(&self) -> Result<CapacityReport, StoreError> {
        let envelope: crate::capacity::OperatingEnvelope =
            serde_json::from_slice(self.retention_capacity_document()?.as_bytes())
                .map_err(|error| StoreError::Invariant(format!("persisted capacity envelope invalid: {error}")))?;
        let path = self
            .path()
            .ok_or_else(|| StoreError::Invariant("capacity report requires a file-backed store".into()))?;
        let observed = crate::capacity::observe(path)?;
        let page_count: i64 = self.connection.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let freelist_pages: i64 =
            self.connection.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        Ok(CapacityReport {
            aggregate_bytes: envelope.aggregate_bytes,
            occupied_bytes: observed.occupied_bytes,
            main_bytes: envelope.main_bytes,
            max_pages: envelope.max_pages,
            page_count,
            freelist_pages,
            reserve_bytes: envelope.policy.reserve_bytes,
            available_bytes: observed.available_bytes,
            preflight: match envelope.preflight(path) {
                Ok(()) => "admit".to_owned(),
                Err(error) => format!("refuse: {error}"),
            },
        })
    }

    /// Full evaluations kept at or below the evaluation floor (declared
    /// islands), in sequence order.
    pub fn island_evaluation_sequences(&self) -> Result<Vec<i64>, StoreError> {
        let b = self.retention_boundary()?;
        if b.generation == 0 || !holes_schema(&self.connection)? {
            return Ok(Vec::new());
        }
        self.connection
            .prepare("SELECT evaluation_sequence FROM evaluation_runs WHERE evaluation_sequence<=?1 AND source_expired=0 ORDER BY evaluation_sequence")?
            .query_map([b.evaluation_floor], |r| r.get(0))?
            .collect::<Result<_, _>>()
            .map_err(StoreError::from)
    }

    /// Count of [`Self::island_evaluation_sequences`].
    pub fn retained_evaluations_below_floor(&self) -> Result<i64, StoreError> {
        Ok(i64::try_from(self.island_evaluation_sequences()?.len()).unwrap_or(i64::MAX))
    }

    /// The retention witness (boundary plus retired lineage floors digest)
    /// a validation watermark must match to apply.
    pub fn retention_witness(&self) -> Result<RetentionWitness, StoreError> {
        witness(&self.connection)
    }
    /// The persisted envelope's preflight for the next ordinary write, as the
    /// admission applies it. `Ok` for a store without a capacity envelope.
    pub fn capacity_preflight(&self) -> Result<(), StoreError> {
        match (&self.capacity, self.path()) {
            (Some(envelope), Some(path)) => envelope.preflight(path),
            _ => Ok(()),
        }
    }

    pub fn retention_generation(&self) -> Result<i64, StoreError> {
        Ok(self.retention_boundary()?.generation)
    }
    /// Full original-history verification is intentionally unavailable after expiry.
    /// Validation of surviving rows remains available and must still detect corruption.
    pub fn require_complete_history(&self) -> Result<(), StoreError> {
        let b = self.retention_boundary()?;
        if b.generation > 0 {
            return Err(StoreError::HistoryExpired {
                through_evaluation_sequence: b.evaluation_floor,
                retained_below_floor: self.retained_evaluations_below_floor()?,
            });
        }
        Ok(())
    }
    pub fn retention_capacity_document(&self) -> Result<CanonicalDocument, StoreError> {
        let bytes: Vec<u8> = self.connection.query_row(
            "SELECT capacity_json FROM retention_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        CanonicalDocument::from_canonical_bytes(bytes)
    }
    /// Validate typed history before irreversible retirement, without holding
    /// the write lock during replay. Refuse if another writer changed the
    /// validated snapshot before the guarded deletion transaction begins.
    pub fn expire_ordinary_before_validated<E, F>(
        &mut self,
        cutoff: &str,
        validate: F,
    ) -> Result<RetentionResult, E>
    where
        E: From<StoreError>,
        F: FnOnce(&Self) -> Result<(), E>,
    {
        self.expire_ordinary_before_certified(
            cutoff,
            validate,
            None::<fn(&Self, &ExpiryCandidates) -> Result<(), E>>,
        )
    }

    /// [`Self::expire_ordinary_before_validated`] for a caller that also
    /// validates exactly the expiry's candidate closures. `validate` runs over
    /// a read snapshot (the caller validates the history its certification
    /// does not cover); `validate_candidates` runs inside the guarded
    /// transaction after the deletion plan is selected and before any row
    /// changes, with every candidate the plan may delete, compact or keep as
    /// an island. When this handle verified or recorded a watermark under the
    /// current retention boundary, the in-lock store checks are then scoped to
    /// the rows beyond the handle's validated frontier plus those candidates,
    /// and the watermark is carried forward to the new boundary after commit.
    /// Selection never reads the watermark.
    pub fn expire_ordinary_before_certified<E, F, G>(
        &mut self,
        cutoff: &str,
        validate: F,
        validate_candidates: Option<G>,
    ) -> Result<RetentionResult, E>
    where
        E: From<StoreError>,
        F: FnOnce(&Self) -> Result<(), E>,
        G: FnOnce(&Self, &ExpiryCandidates) -> Result<(), E>,
    {
        self.expire_ordinary_before_inner(
            cutoff,
            None,
            None,
            |store: &Self, _| validate(store).map(|()| None),
            validate_candidates,
        )
    }

    /// [`Self::expire_ordinary_before_certified`] for a caller whose
    /// snapshot validation receives the exact append bounds it must certify and
    /// covers every semantic plane beyond this handle's
    /// certification under `engine_rules` and returns the resulting
    /// certification. Before the expiry carries the handle's certification
    /// forward, that validation is promoted into it: the store-level laws of
    /// the rows beyond the certified frontier are validated in the same
    /// snapshot and the certification is extended to the snapshot frontier
    /// (as [`Self::record_validation_watermark`] extends an applied
    /// watermark), so the carried watermark covers the current frontier
    /// rather than the one this handle certified when it opened.
    ///
    /// With `max_candidate_runs`, the expiry is one batch: it selects at most
    /// that many aged runs beyond the floors (oldest first) besides the
    /// existing islands, so the guarded transaction's work is bounded, and
    /// reports `candidates_remaining` when it left aged runs for a later
    /// batch.
    pub fn expire_ordinary_before_promoting<E, F, G>(
        &mut self,
        cutoff: &str,
        engine_rules: &str,
        max_candidate_runs: Option<usize>,
        validate: F,
        validate_candidates: Option<G>,
    ) -> Result<RetentionResult, E>
    where
        E: From<StoreError>,
        F: FnOnce(&Self, &crate::HistoryFrontier) -> Result<crate::SemanticCertification, E>,
        G: FnOnce(&Self, &ExpiryCandidates) -> Result<(), E>,
    {
        self.expire_ordinary_before_inner(
            cutoff,
            Some(engine_rules),
            max_candidate_runs,
            |store: &Self, bounds| validate(store, bounds).map(Some),
            validate_candidates,
        )
    }

    fn expire_ordinary_before_inner<E, F, G>(
        &mut self,
        cutoff: &str,
        engine_rules: Option<&str>,
        max_candidate_runs: Option<usize>,
        validate: F,
        validate_candidates: Option<G>,
    ) -> Result<RetentionResult, E>
    where
        E: From<StoreError>,
        F: FnOnce(&Self, &crate::HistoryFrontier) -> Result<Option<crate::SemanticCertification>, E>,
        G: FnOnce(&Self, &ExpiryCandidates) -> Result<(), E>,
    {
        chrono::DateTime::parse_from_rfc3339(cutoff)
            .map_err(|e| E::from(StoreError::Invariant(format!("invalid expiry cutoff: {e}"))))?;
        self.require_current_schema().map_err(E::from)?;
        self.observe_retention_boundary().map_err(E::from)?;
        let current = validate_boundary_header(&self.connection).map_err(E::from)?;
        if !prefix_may_advance(&self.connection, cutoff, &current).map_err(E::from)? {
            return Ok(RetentionResult {
                boundary: current,
                deleted_rows: 0,
                candidates_remaining: false,
            });
        }
        let data_version: i64 = self
            .connection
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .map_err(StoreError::from)
            .map_err(E::from)?;
        let (proof, promoted) = self.with_read_snapshot(|store, bounds| {
            let semantic = validate(store, bounds)?;
            let promoted = match (semantic, engine_rules) {
                (Some(semantic), Some(rules)) => {
                    store.promoted_certification(bounds, semantic, rules).map_err(E::from)?
                }
                _ => None,
            };
            Ok::<_, E>((
                (
                    bounds.clone(),
                    store.retention_boundary().map_err(E::from)?,
                    data_version,
                ),
                promoted.map(|watermark| (watermark, bounds.clone())),
            ))
        })?;
        if let Some((watermark, bounds)) = promoted {
            // The handle has now validated, by the same rules as an open,
            // everything through the snapshot frontier: it certifies it.
            let may_record = self.validation.may_record;
            let prior = self.validation.prior.take();
            let prior_superseded = self.validation.prior_superseded;
            let open_retention = self.validation.open_retention.take();
            let observed_retention = self.validation.observed_retention.take();
            self.validation = ValidationState {
                opened: OpenValidation::SinceWatermark(Box::new(watermark.clone())),
                open_frontier: Some(bounds.clone()),
                store_validated: Some(bounds),
                may_record,
                prior,
                prior_superseded,
                open_retention,
                observed_retention,
                certified: std::cell::RefCell::new(Some(Box::new(watermark))),
                run_evaluations: std::cell::RefCell::new(None),
            };
        }
        let after: i64 = self
            .connection
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .map_err(StoreError::from)
            .map_err(E::from)?;
        if after != data_version {
            return Err(E::from(StoreError::Refused(
                crate::Refusal::HistoryChanged("during"),
            )));
        }
        let supplied = validate_candidates.is_some();
        let mut failure: Option<E> = None;
        let result = {
            let mut pending = validate_candidates;
            let mut wrapper = |store: &Self, candidates: &ExpiryCandidates| -> Result<(), StoreError> {
                let Some(validate) = pending.take() else {
                    return Ok(());
                };
                validate(store, candidates).map_err(|error| {
                    failure = Some(error);
                    StoreError::Invariant("expiry candidate validation failed".into())
                })
            };
            if supplied {
                self.expire_ordinary_before_checked(cutoff, Some(&proof), Some(&mut wrapper), max_candidate_runs)
            } else {
                self.expire_ordinary_before_checked(cutoff, Some(&proof), None, max_candidate_runs)
            }
        };
        result.map_err(|error| failure.take().unwrap_or_else(|| E::from(error)))
    }

    /// Retire complete ordinary prefixes, stopping at any known dependency.
    /// The caller supplies its explicitly configured arrival-time cutoff.
    /// This Store-only entrypoint does not certify a consumer's typed semantics.
    pub fn expire_ordinary_before(&mut self, cutoff: &str) -> Result<RetentionResult, StoreError> {
        self.expire_ordinary_before_checked(cutoff, None, None, None)
    }

    /// This handle's certification extended to `bounds` (the frontier of
    /// the read snapshot the caller just validated), when it has one to
    /// carry under the current boundary and `engine_rules`: the store-level
    /// laws of the rows beyond it are validated here, in the same snapshot,
    /// and the accumulators are extended over them. `None` leaves the
    /// certification as it is.
    fn promoted_certification(
        &self,
        bounds: &HistoryFrontier,
        semantic: crate::SemanticCertification,
        engine_rules: &str,
    ) -> Result<Option<crate::ValidationWatermark>, StoreError> {
        let current = witness(&self.connection)?;
        let Some(certified) = self.carriable_watermark(&current) else {
            return Ok(None);
        };
        if certified.engine_rules != engine_rules
            || certified.frontier.tables.iter().any(|(table, frontier)| {
                frontier.max_rowid > bounds.max_rowid(table)
            })
        {
            return Ok(None);
        }
        let Some(identity) = self.store_identity()? else {
            return Ok(None);
        };
        if identity.retention != current {
            return Ok(None);
        }
        self.validate_history_since(&certified.frontier)?;
        let frontier =
            HistoryFrontier::certify(&self.connection, Some(&certified.frontier), bounds, None)?;
        Ok(Some(crate::history_scope::build_watermark(
            &identity,
            engine_rules,
            frontier,
            semantic,
            crate::now_utc(),
        )))
    }

    /// The watermark this handle may carry across an expiry: one it verified
    /// at open or recorded, certified under the current boundary, for a
    /// handle that records watermarks and has a validated frontier.
    fn carriable_watermark(
        &self,
        current: &RetentionWitness,
    ) -> Option<Box<crate::ValidationWatermark>> {
        if !self.validation.may_record || self.validation.store_validated.is_none() {
            return None;
        }
        self.validation
            .certified
            .borrow()
            .as_ref()
            .filter(|watermark| &watermark.retention == current)
            .cloned()
    }

    #[allow(clippy::too_many_lines)]
    fn expire_ordinary_before_checked(
        &mut self,
        cutoff: &str,
        proof: Option<&(HistoryFrontier, RetentionBoundary, i64)>,
        validate_candidates: Option<CandidateValidator<'_>>,
        max_candidate_runs: Option<usize>,
    ) -> Result<RetentionResult, StoreError> {
        chrono::DateTime::parse_from_rfc3339(cutoff)
            .map_err(|e| StoreError::Invariant(format!("invalid expiry cutoff: {e}")))?;
        self.require_current_schema()?;
        let current = validate_boundary_header(&self.connection)?;
        if !prefix_may_advance(&self.connection, cutoff, &current)? {
            return Ok(RetentionResult {
                boundary: current,
                deleted_rows: 0,
                candidates_remaining: false,
            });
        }
        // A durable expiry marker and its deletions commit together. FULL is
        // selected before the write transaction; NORMAL is insufficient for
        // treating physical reclamation as irreversible committed retirement.
        self.connection.pragma_update(None, "synchronous", "FULL")?;
        let store: &Self = self;
        let tx = store.shared_immediate_transaction()?;
        let current = validate_boundary_header(&tx)?;
        if !prefix_may_advance(&tx, cutoff, &current)? {
            tx.rollback()?;
            return Ok(RetentionResult {
                boundary: current,
                deleted_rows: 0,
                candidates_remaining: false,
            });
        }
        if let Some((validated, validated_boundary, data_version)) = proof {
            let current_version: i64 = tx.query_row("PRAGMA data_version", [], |r| r.get(0))?;
            if &current_version != data_version
                || &current != validated_boundary
                || &HistoryFrontier::capture_bounds(&tx)? != validated
            {
                return Err(StoreError::Refused(crate::Refusal::HistoryChanged("after")));
            }
        }
        let before_witness = witness(&tx)?;
        let carry = store.carriable_watermark(&before_witness);
        // Scoped in-lock validation requires both a certification this handle
        // established and a caller that validates every candidate closure in
        // full; otherwise every surviving row is re-proven here.
        let validated_frontier = store.validation.store_validated.clone();
        let scoped = match (&carry, &validated_frontier, validate_candidates.is_some()) {
            (Some(_), Some(frontier), true) => Some(frontier.clone()),
            _ => None,
        };
        match &scoped {
            Some(frontier) => {
                validate_boundary_scoped(&tx, Scope::after(frontier))?;
                // Do not trust an advisory validation sidecar when selecting
                // deletion: selection below reads only the database.
                crate::validate_stored_digests(&tx, Scope::after(frontier))?;
            }
            None => {
                validate_boundary(&tx)?;
                crate::validate_stored_digests(&tx, Scope::FULL)?;
            }
        }
        let before = boundary(&tx)?;
        let plan = plan_expiry(&tx, cutoff, &before, max_candidate_runs)?;
        let (ef, rf, inf, sf) = (plan.evaluation_floor, plan.report_floor, plan.intake_floor, plan.status_floor);
        let floors_moved = (ef, rf, inf, sf)
            != (
                before.evaluation_floor,
                before.report_floor,
                before.intake_floor,
                before.status_floor,
            );
        if !floors_moved && plan.affected_runs == 0 && plan.affected_evaluations == 0 {
            tx.rollback()?;
            return Ok(RetentionResult {
                boundary: before,
                deleted_rows: 0,
                candidates_remaining: false,
            });
        }
        if let Some(validate_candidates) = validate_candidates {
            let candidates = expiry_candidates(&tx)?;
            validate_candidate_digests(&tx)?;
            validate_candidates(store, &candidates)?;
        }
        let mut next = RetentionBoundary {
            generation: before.generation,
            evaluation_floor: ef,
            report_floor: rf,
            intake_floor: inf,
            status_floor: sf,
        };
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Invariant("retention generation exhausted".into()))?;
        let old: Vec<u8> = tx.query_row(
            "SELECT lineage_floors_json FROM retention_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let mut floors: Vec<LineageFloor> =
            serde_json::from_slice(&old).map_err(|e| StoreError::Integrity(e.to_string()))?;
        let retired:Vec<LineageFloor>=tx.prepare("SELECT detector_id,detector_version,MAX(evaluation_revision) FROM evaluation_runs WHERE evaluation_sequence<=?1 GROUP BY detector_id,detector_version")?.query_map([ef],|r|Ok(LineageFloor{detector_id:r.get(0)?,detector_version:r.get(1)?,revision:r.get(2)?}))?.collect::<Result<_,_>>()?;
        for f in retired {
            if let Some(old) = floors.iter_mut().find(|old| {
                old.detector_id == f.detector_id && old.detector_version == f.detector_version
            }) {
                old.revision = old.revision.max(f.revision);
            } else {
                floors.push(f);
            }
        }
        floors.sort_by(|a, b| {
            (&a.detector_id, &a.detector_version).cmp(&(&b.detector_id, &b.detector_version))
        });
        let document = CanonicalDocument::from_serializable(&floors)?;
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS expiry_links(intake_id TEXT PRIMARY KEY,run_id TEXT NOT NULL,submission_id TEXT,report_id TEXT,semantic_digest TEXT);DELETE FROM expiry_links;INSERT INTO expiry_links SELECT l.intake_id,l.run_id,r.submission_id,a.report_id,a.semantic_digest FROM local_watcher_provider_intakes l JOIN expiry_dead_runs e ON e.run_id=l.run_id LEFT JOIN raw_submissions r ON r.run_id=l.run_id LEFT JOIN admitted_reports a ON a.submission_id=r.submission_id;")?;
        // Evaluations whose full row this expiry deletes or compacts: a
        // certified evaluation head among them cannot be carried forward.
        let affected_sequences: std::collections::BTreeSet<i64> = tx
            .prepare("SELECT e.evaluation_sequence FROM evaluation_runs e JOIN expiry_evaluations x ON x.evaluation_id=e.evaluation_id WHERE x.disposition<>'island'")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut delta = carry.as_ref().map(|watermark| ExpiryDelta::new(&watermark.frontier));
        #[cfg(test)]
        crash_phase_for_test("before_mutations", 71);
        tx.execute(
            "UPDATE retention_state SET delete_enabled=1 WHERE singleton=1",
            [],
        )?;
        // Compaction deletes and re-inserts compact rows that finding,
        // evidence and anchor rows reference; the references are checked at
        // the end of the transaction (and by the explicit foreign-key check
        // below) instead of between the two statements.
        tx.execute_batch("PRAGMA defer_foreign_keys=ON")?;
        let mut deleted = 0usize;
        // Evaluations at or below the floor that are neither islands nor
        // compact decision records retire with their watermarks and refusals.
        // Each mutation records the covered rows it removes or rewrites.
        for (table, mutation) in [
            ("refusals", Mutation::Delete("evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations WHERE disposition<>'island') OR run_id IN (SELECT run_id FROM expiry_dead_runs) OR submission_id IN (SELECT submission_id FROM raw_submissions WHERE run_id IN (SELECT run_id FROM expiry_dead_runs))")),
            ("evaluation_watermarks", Mutation::Delete("evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations WHERE disposition<>'island')")),
            ("evaluation_runs", Mutation::Delete("evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations WHERE disposition='delete')")),
            ("evaluation_runs", Mutation::Repack(Some("source_expired=1, detail_json=CAST('{}' AS BLOB)"), "evaluation_id IN (SELECT evaluation_id FROM expiry_evaluations WHERE disposition='compact')")),
            ("observation_coverage", Mutation::Delete("report_id IN (SELECT a.report_id FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE r.run_id IN (SELECT run_id FROM expiry_dead_runs))")),
            ("observations", Mutation::Delete("report_id IN (SELECT a.report_id FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE r.run_id IN (SELECT run_id FROM expiry_dead_runs))")),
            ("report_coverage", Mutation::Delete("report_id IN (SELECT a.report_id FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE r.run_id IN (SELECT run_id FROM expiry_dead_runs))")),
            ("report_errors", Mutation::Delete("report_id IN (SELECT a.report_id FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE r.run_id IN (SELECT run_id FROM expiry_dead_runs))")),
            ("admitted_reports", Mutation::Delete("submission_id IN (SELECT submission_id FROM raw_submissions WHERE run_id IN (SELECT run_id FROM expiry_dead_runs)) AND report_id NOT IN (SELECT report_id FROM expiry_compact_reports)")),
            ("admitted_reports", Mutation::Repack(Some("source_expired=1, canonical_json=CAST('{}' AS BLOB), validated_report_json=CAST('{}' AS BLOB), next_checkpoint_json=NULL"), "report_id IN (SELECT report_id FROM expiry_compact_reports)")),
            ("provider_intake_acknowledgments", Mutation::Delete("run_id IN (SELECT run_id FROM expiry_dead_runs)")),
            ("local_watcher_provider_intakes", Mutation::Delete("run_id IN (SELECT run_id FROM expiry_dead_runs)")),
            ("legacy_v3_watcher_run_intake_gaps", Mutation::Delete("run_id IN (SELECT run_id FROM expiry_dead_runs)")),
            ("raw_submissions", Mutation::Delete("run_id IN (SELECT run_id FROM expiry_dead_runs) AND submission_id NOT IN (SELECT a.submission_id FROM admitted_reports a JOIN expiry_compact_reports c ON c.report_id=a.report_id)")),
            ("raw_submissions", Mutation::Repack(Some("source_expired=1, raw_bytes=X''"), "submission_id IN (SELECT a.submission_id FROM admitted_reports a JOIN expiry_compact_reports c ON c.report_id=a.report_id)")),
            ("status_events", Mutation::Delete("run_id IN (SELECT run_id FROM expiry_dead_runs)")),
            ("watcher_runs", Mutation::Delete("run_id IN (SELECT run_id FROM expiry_dead_runs WHERE anchor=0)")),
        ] {
            deleted += mutation.apply(&tx, table, delta.as_mut())?;
        }
        // Anchor runs are kept unchanged (not counted as deleted or
        // compacted); re-inserting them after their neighbours' deletion
        // packs them into fewer pages.
        Mutation::Repack(None, "run_id IN (SELECT run_id FROM expiry_dead_runs WHERE anchor=1)").apply(
            &tx,
            "watcher_runs",
            delta.as_mut(),
        )?;
        let retire_ids:Vec<String>=tx.prepare("SELECT intake_id FROM provider_intake_attempts WHERE history_expired=0 AND intake_sequence<=?1 AND intake_id IN (SELECT intake_id FROM expiry_links)")?.query_map([inf],|r|r.get(0))?.collect::<Result<_,_>>()?;
        for id in &retire_ids {
            let (run,submission,report,digest):(String,Option<String>,Option<String>,Option<String>)=tx.query_row("SELECT run_id,submission_id,report_id,semantic_digest FROM expiry_links WHERE intake_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            let mut links = serde_json::Map::new();
            links.insert("retired_run_id".into(), serde_json::json!(run));
            links.insert(
                "retired_submission_id".into(),
                serde_json::json!(submission),
            );
            links.insert("retired_report_id".into(), serde_json::json!(report));
            links.insert(
                "retired_report_semantic_digest".into(),
                serde_json::json!(digest),
            );
            let commitment = retired_identity_commitment_with_links(&tx, id, Some(&links))?;
            let predicate = format!("intake_id='{}'", id.replace('\'', "''"));
            let old_rows = match &delta {
                Some(delta) => delta.covered_rows(&tx, "provider_intake_attempts", &predicate)?,
                None => Vec::new(),
            };
            deleted+=tx.execute("UPDATE provider_intake_attempts SET history_expired=1,raw_bytes=X'',context_json=CAST('{}' AS BLOB),interpretation_json=CAST('{}' AS BLOB),native_outcome_json=CAST('{}' AS BLOB),retired_identity_digest=?1,retired_run_id=?3,retired_submission_id=?4,retired_report_id=?5,retired_report_semantic_digest=?6 WHERE intake_id=?2",params![commitment,id,run,submission,report,digest])?;
            if let Some(delta) = delta.as_mut() {
                let new_rows = delta.covered_rows(&tx, "provider_intake_attempts", &predicate)?;
                delta.removed("provider_intake_attempts", &old_rows);
                delta.added("provider_intake_attempts", &new_rows);
            }
        }
        // Retired intake commitments shrank in place; re-insert them so the
        // pages their full bodies occupied are released.
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS expiry_retired_intakes(intake_id TEXT PRIMARY KEY); DELETE FROM expiry_retired_intakes;")?;
        for id in &retire_ids {
            tx.execute("INSERT INTO expiry_retired_intakes VALUES(?1)", [id])?;
        }
        Mutation::Repack(None, "intake_id IN (SELECT intake_id FROM expiry_retired_intakes)").apply(
            &tx,
            "provider_intake_attempts",
            delta.as_mut(),
        )?;
        tx.execute("UPDATE retention_state SET generation=?1,evaluation_floor=?2,report_floor=?3,intake_floor=?4,status_floor=?5,cutoff=?6,lineage_floors_json=?7,delete_enabled=0 WHERE singleton=1",params![next.generation,ef,rf,inf,sf,cutoff,document.as_bytes()])?;
        // The resulting boundary is validated in full except for retired
        // commitments: with a scoped validation, only those retired by this
        // transaction are recomputed (the rest were certified unchanged).
        if scoped.is_some() {
            validate_boundary_with(&tx, Some(&retire_ids))?;
        } else {
            validate_boundary(&tx)?;
        }
        let violations: i64 =
            tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        if violations != 0 {
            return Err(StoreError::Integrity(
                "expiry closure has surviving foreign-key references".into(),
            ));
        }
        // Carry the certification forward inside the transaction, where the
        // surviving rows at or below each bound cannot change underneath.
        let after_witness = witness(&tx)?;
        let carried = match (&carry, &delta) {
            // An inconsistent carry-forward withdraws the shortcut (the next
            // open validates in full); it never fails the expiry.
            (Some(watermark), Some(delta)) => delta
                .carry(&tx, &watermark.frontier)
                .ok()
                .flatten()
                .map(|frontier| (watermark, frontier, carry_semantic(watermark, &affected_sequences, ef))),
            _ => None,
        };
        let reanchored = match (&store.validation.open_frontier, &store.validation.store_validated) {
            (Some(open), Some(validated)) => Some((
                crate::history_scope::reanchor_bounds(&tx, open)?,
                crate::history_scope::reanchor_bounds(&tx, validated)?,
            )),
            _ => None,
        };
        #[cfg(test)]
        crash_phase_for_test("inside_transaction", 72);
        tx.commit()?;
        #[cfg(test)]
        crash_phase_for_test("after_commit", 73);
        let written = match (carried, self.path.clone(), self.store_identity()?) {
            (Some((watermark, frontier, semantic)), Some(path), Some(identity))
                if identity.retention == after_witness =>
            {
                crate::history_scope::write_watermark(
                    &path,
                    &identity,
                    &watermark.engine_rules,
                    frontier,
                    semantic,
                    watermark.validated_at.clone(),
                )
                .ok()
            }
            _ => None,
        };
        match (written, reanchored) {
            (Some(watermark), Some((open, validated))) => {
                let may_record = self.validation.may_record;
                self.validation = ValidationState {
                    opened: OpenValidation::SinceWatermark(Box::new(watermark.clone())),
                    open_frontier: Some(open),
                    store_validated: Some(validated),
                    may_record,
                    prior: None,
                    prior_superseded: false,
                    open_retention: Some(after_witness.clone()),
                    observed_retention: Some(after_witness.clone()),
                    certified: std::cell::RefCell::new(Some(Box::new(watermark))),
                    run_evaluations: std::cell::RefCell::new(None),
                };
            }
            // No certification was carried: later opens and engine paths
            // validate in full, and this handle records nothing under the
            // new boundary. Its own store-level frontier stays proven (the
            // surviving rows below it were validated, and this transaction
            // validated what it changed), re-anchored past deleted bounds.
            (None, Some((open, validated))) => {
                self.validation = ValidationState {
                    open_frontier: Some(open),
                    store_validated: Some(validated),
                    observed_retention: Some(after_witness),
                    ..ValidationState::default()
                };
            }
            _ => self.validation = ValidationState::default(),
        }
        Ok(RetentionResult {
            boundary: next,
            deleted_rows: deleted,
            candidates_remaining: plan.candidates_remaining,
        })
    }
}

/// The in-lock validation of one expiry's candidate closures.
type CandidateValidator<'a> =
    &'a mut dyn FnMut(&Store, &ExpiryCandidates) -> Result<(), StoreError>;

/// The candidates one expiry plan selected: every full evaluation at or below
/// the new evaluation floor (deleted, compacted, or kept as an island) and
/// every aged run with its reports, provider intakes and status events.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpiryCandidates {
    /// Evaluation sequences, ascending.
    pub evaluation_sequences: Vec<i64>,
    /// Watcher runs.
    pub run_ids: Vec<String>,
    /// Full admitted reports of those runs.
    pub report_ids: Vec<String>,
    /// Unretired provider intakes of those runs.
    pub intake_ids: Vec<String>,
    /// Status event sequences of those runs, ascending.
    pub status_sequences: Vec<i64>,
}

fn expiry_candidates(tx: &Connection) -> Result<ExpiryCandidates, StoreError> {
    let strings = |sql: &str| -> Result<Vec<String>, StoreError> {
        Ok(tx.prepare(sql)?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
    };
    let numbers = |sql: &str| -> Result<Vec<i64>, StoreError> {
        Ok(tx.prepare(sql)?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
    };
    Ok(ExpiryCandidates {
        evaluation_sequences: numbers("SELECT e.evaluation_sequence FROM evaluation_runs e JOIN expiry_evaluations x ON x.evaluation_id=e.evaluation_id ORDER BY 1")?,
        run_ids: strings("SELECT run_id FROM expiry_runs ORDER BY run_id")?,
        report_ids: strings("SELECT a.report_id FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE r.run_id IN (SELECT run_id FROM expiry_runs) AND a.source_expired=0 ORDER BY a.report_sequence")?,
        intake_ids: strings("SELECT l.intake_id FROM local_watcher_provider_intakes l JOIN provider_intake_attempts p ON p.intake_id=l.intake_id WHERE l.run_id IN (SELECT run_id FROM expiry_runs) AND p.history_expired=0 ORDER BY p.intake_sequence")?,
        status_sequences: numbers("SELECT status_sequence FROM status_events WHERE run_id IN (SELECT run_id FROM expiry_runs) ORDER BY 1")?,
    })
}

/// Stored-digest validation of exactly the candidate runs' raw submissions,
/// admitted reports and provider-intake bytes.
fn validate_candidate_digests(tx: &Connection) -> Result<(), StoreError> {
    let mut raw = tx.prepare("SELECT submission_id, raw_bytes, raw_sha256 FROM raw_submissions WHERE run_id IN (SELECT run_id FROM expiry_runs) AND source_expired=0")?;
    let mut rows = raw.query([])?;
    while let Some(row) = rows.next()? {
        let (id, bytes, stored): (String, Vec<u8>, String) = (row.get(0)?, row.get(1)?, row.get(2)?);
        let recomputed = crate::sha256_digest(&bytes);
        if recomputed != stored {
            return Err(StoreError::Integrity(format!(
                "raw submission {id} bytes hash to {recomputed}, not stored {stored}"
            )));
        }
    }
    let mut reports = tx.prepare("SELECT a.report_id, a.canonical_json, a.semantic_digest FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE r.run_id IN (SELECT run_id FROM expiry_runs) AND a.source_expired=0")?;
    let mut rows = reports.query([])?;
    while let Some(row) = rows.next()? {
        let (id, bytes, stored): (String, Vec<u8>, String) = (row.get(0)?, row.get(1)?, row.get(2)?);
        let document = CanonicalDocument::from_canonical_bytes(bytes)
            .map_err(|error| StoreError::Integrity(format!("admitted report {id}: {error}")))?;
        if document.digest() != stored {
            return Err(StoreError::Integrity(format!(
                "admitted report {id} bytes hash to {}, not stored {stored}",
                document.digest()
            )));
        }
    }
    let mut intakes = tx.prepare("SELECT p.intake_id, p.raw_bytes, p.raw_sha256 FROM provider_intake_attempts p JOIN local_watcher_provider_intakes l ON l.intake_id=p.intake_id WHERE l.run_id IN (SELECT run_id FROM expiry_runs) AND p.history_expired=0")?;
    let mut rows = intakes.query([])?;
    while let Some(row) = rows.next()? {
        let (id, bytes, stored): (String, Vec<u8>, String) = (row.get(0)?, row.get(1)?, row.get(2)?);
        let recomputed = crate::sha256_digest(&bytes);
        if recomputed != stored {
            return Err(StoreError::Integrity(format!(
                "provider intake {id} bytes hash to {recomputed}, not stored {stored}"
            )));
        }
    }
    Ok(())
}

/// The semantic certification after an expiry: the evaluation heads are
/// unchanged (each lineage's newest evaluation is a protected island and
/// never deleted or compacted; if one were, the certification is withdrawn),
/// and finding-lineage heads are kept only for lineages whose newest
/// evaluation lies above the new evaluation floor, which is exactly the state
/// a replay of the surviving history from the floor reaches (a lineage first
/// met above the floor is seeded from its finding events, which are never
/// deleted).
fn carry_semantic(
    watermark: &crate::ValidationWatermark,
    affected: &std::collections::BTreeSet<i64>,
    evaluation_floor: i64,
) -> crate::SemanticCertification {
    let Some(state) = &watermark.semantic else {
        return crate::SemanticCertification::NotEstablished;
    };
    if state
        .evaluation_heads
        .iter()
        .any(|head| affected.contains(&head.evaluation_sequence))
    {
        return crate::SemanticCertification::NotEstablished;
    }
    let above: std::collections::BTreeSet<&str> = state
        .evaluation_heads
        .iter()
        .filter(|head| head.evaluation_sequence > evaluation_floor)
        .map(|head| head.lineage.as_str())
        .collect();
    crate::SemanticCertification::Established(crate::SemanticState {
        lineage_heads: state
            .lineage_heads
            .iter()
            .filter(|head| above.contains(head.lineage.as_str()))
            .cloned()
            .collect(),
        evaluation_heads: state.evaluation_heads.clone(),
    })
}

/// One expiry mutation over a history table (alias-free predicate).
enum Mutation {
    Delete(&'static str),
    /// Rewrite the selected rows in place (kept for reference; compaction
    /// uses [`Mutation::Repack`]).
    #[allow(dead_code)]
    Update(&'static str, &'static str),
    /// Rewrite the selected rows as delete and re-insert with the same rowid
    /// and key columns, applying the optional `SET` to the re-inserted form.
    /// SQLite never rebalances a leaf page when an update shrinks a row, so
    /// a compact row rewritten in place keeps the page it occupied when full
    /// (and in an append-only table that page is never reused); deleting
    /// the rows first lets their pages merge or free, and the re-inserted
    /// compact rows pack densely. The watermark delta treats it exactly as
    /// an update (covered row digests before and after).
    Repack(Option<&'static str>, &'static str),
}

/// Delete and re-insert the rows of `table` matching `predicate`, with
/// `set` applied to the re-inserted form. Returns the rows rewritten.
fn repack(tx: &Connection, table: &str, set: Option<&str>, predicate: &str) -> Result<usize, StoreError> {
    let columns: Vec<String> = tx
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let list = columns.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(",");
    tx.execute_batch("DROP TABLE IF EXISTS temp.expiry_repack")?;
    tx.execute(
        &format!("CREATE TEMP TABLE expiry_repack AS SELECT rowid AS repack_rowid, {list} FROM main.{table} WHERE {predicate}"),
        [],
    )?;
    if let Some(set) = set {
        tx.execute(&format!("UPDATE temp.expiry_repack SET {set}"), [])?;
    }
    tx.execute(
        &format!("DELETE FROM main.{table} WHERE rowid IN (SELECT repack_rowid FROM temp.expiry_repack)"),
        [],
    )?;
    let inserted = tx.execute(
        &format!("INSERT INTO main.{table}(rowid,{list}) SELECT repack_rowid,{list} FROM temp.expiry_repack ORDER BY repack_rowid"),
        [],
    )?;
    tx.execute_batch("DROP TABLE temp.expiry_repack")?;
    Ok(inserted)
}

impl Mutation {
    fn apply(
        &self,
        tx: &Connection,
        table: &str,
        delta: Option<&mut ExpiryDelta>,
    ) -> Result<usize, StoreError> {
        match (self, delta) {
            (Self::Delete(predicate), None) => Ok(tx.execute(&format!("DELETE FROM {table} WHERE {predicate}"), [])?),
            (Self::Update(set, predicate), None) => Ok(tx.execute(&format!("UPDATE {table} SET {set} WHERE {predicate}"), [])?),
            (Self::Delete(predicate), Some(delta)) => {
                let removed = delta.covered_rows(tx, table, predicate)?;
                let changed = tx.execute(&format!("DELETE FROM {table} WHERE {predicate}"), [])?;
                delta.removed(table, &removed);
                Ok(changed)
            }
            (Self::Repack(set, predicate), None) => repack(tx, table, *set, predicate),
            (Self::Repack(set, predicate), Some(delta)) => {
                let before = delta.covered_rows(tx, table, predicate)?;
                let changed = repack(tx, table, *set, predicate)?;
                let after = delta.covered_rows(tx, table, predicate)?;
                delta.removed(table, &before);
                delta.added(table, &after);
                Ok(changed)
            }
            (Self::Update(set, predicate), Some(delta)) => {
                let before = delta.covered_rows(tx, table, predicate)?;
                let changed = tx.execute(&format!("UPDATE {table} SET {set} WHERE {predicate}"), [])?;
                let after = delta.covered_rows(tx, table, predicate)?;
                delta.removed(table, &before);
                delta.added(table, &after);
                Ok(changed)
            }
        }
    }
}
