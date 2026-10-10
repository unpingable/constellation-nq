//! Conservative prefix reclamation inside the existing store. Dependencies
//! stop the prefix; capacity refusal is preferable to guessing their release.
use crate::{CanonicalDocument, HistoryFrontier, Store, StoreError, ValidationState};
use rusqlite::{Connection, params};
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

pub(crate) fn validate_boundary(connection: &Connection) -> Result<(), StoreError> {
    let b = validate_boundary_header(connection)?;
    for (table, column, floor) in [
        ("evaluation_runs", "evaluation_sequence", b.evaluation_floor),
        ("admitted_reports", "report_sequence", b.report_floor),
        (
            "provider_intake_attempts",
            "intake_sequence",
            b.intake_floor,
        ),
        ("status_events", "status_sequence", b.status_floor),
    ] {
        let subtype = if table == "status_events" {
            " AND run_id IS NOT NULL"
        } else if table == "provider_intake_attempts" {
            " AND history_expired=0"
        } else {
            ""
        };
        let count: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {column}<=?1{subtype}"),
            [floor],
            |r| r.get(0),
        )?;
        if count != 0 {
            return Err(StoreError::Integrity(format!(
                "{table} revives an expired prefix"
            )));
        }
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
    let invalid:i64=connection.query_row("SELECT COUNT(*) FROM provider_intake_attempts WHERE (history_expired=1 AND (intake_sequence>?1 OR retired_identity_digest IS NULL OR retired_run_id IS NULL OR length(raw_bytes)!=0 OR context_json!=CAST('{}' AS BLOB) OR interpretation_json!=CAST('{}' AS BLOB) OR native_outcome_json!=CAST('{}' AS BLOB))) OR (history_expired=0 AND (retired_identity_digest IS NOT NULL OR retired_run_id IS NOT NULL OR retired_submission_id IS NOT NULL OR retired_report_id IS NOT NULL OR retired_report_semantic_digest IS NOT NULL))",[b.intake_floor],|r|r.get(0))?;
    if invalid != 0 {
        return Err(StoreError::Integrity(
            "invalid expired provider identity commitment".into(),
        ));
    }
    let expired:Vec<(String,String)>=connection.prepare("SELECT intake_id,retired_identity_digest FROM provider_intake_attempts WHERE history_expired=1")?.query_map([],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<Result<_,_>>()?;
    for (id, expected) in expired {
        if retired_identity_commitment(connection, &id)? != expected {
            return Err(StoreError::Integrity(format!(
                "expired provider identity commitment {id} changed"
            )));
        }
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
    )?)
}

impl Store {
    pub fn retention_boundary(&self) -> Result<RetentionBoundary, StoreError> {
        boundary(&self.connection)
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
        chrono::DateTime::parse_from_rfc3339(cutoff)
            .map_err(|e| E::from(StoreError::Invariant(format!("invalid expiry cutoff: {e}"))))?;
        self.require_current_schema().map_err(E::from)?;
        let current = validate_boundary_header(&self.connection).map_err(E::from)?;
        if !prefix_may_advance(&self.connection, cutoff, &current).map_err(E::from)? {
            return Ok(RetentionResult {
                boundary: current,
                deleted_rows: 0,
            });
        }
        let data_version: i64 = self
            .connection
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .map_err(StoreError::from)
            .map_err(E::from)?;
        let proof = self.with_read_snapshot(|store, bounds| {
            validate(store)?;
            Ok::<_, E>((
                bounds.clone(),
                store.retention_boundary().map_err(E::from)?,
                data_version,
            ))
        })?;
        let after: i64 = self
            .connection
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .map_err(StoreError::from)
            .map_err(E::from)?;
        if after != data_version {
            return Err(E::from(StoreError::Invariant(
                "expiry history changed during typed semantic validation; retry against current history".into(),
            )));
        }
        self.expire_ordinary_before_checked(cutoff, Some(&proof))
            .map_err(E::from)
    }

    /// Retire complete ordinary prefixes, stopping at any known dependency.
    /// The caller supplies its explicitly configured arrival-time cutoff.
    /// This Store-only entrypoint does not certify a consumer's typed semantics.
    pub fn expire_ordinary_before(&mut self, cutoff: &str) -> Result<RetentionResult, StoreError> {
        self.expire_ordinary_before_checked(cutoff, None)
    }

    fn expire_ordinary_before_checked(
        &mut self,
        cutoff: &str,
        proof: Option<&(HistoryFrontier, RetentionBoundary, i64)>,
    ) -> Result<RetentionResult, StoreError> {
        chrono::DateTime::parse_from_rfc3339(cutoff)
            .map_err(|e| StoreError::Invariant(format!("invalid expiry cutoff: {e}")))?;
        self.require_current_schema()?;
        let current = validate_boundary_header(&self.connection)?;
        if !prefix_may_advance(&self.connection, cutoff, &current)? {
            return Ok(RetentionResult {
                boundary: current,
                deleted_rows: 0,
            });
        }
        // A durable expiry marker and its deletions commit together. FULL is
        // selected before the write transaction; NORMAL is insufficient for
        // treating physical reclamation as irreversible committed retirement.
        self.connection.pragma_update(None, "synchronous", "FULL")?;
        let tx = self.immediate_transaction()?;
        let current = validate_boundary_header(&tx)?;
        if !prefix_may_advance(&tx, cutoff, &current)? {
            tx.rollback()?;
            return Ok(RetentionResult {
                boundary: current,
                deleted_rows: 0,
            });
        }
        if let Some((validated, validated_boundary, data_version)) = proof {
            let current_version: i64 = tx.query_row("PRAGMA data_version", [], |r| r.get(0))?;
            if &current_version != data_version
                || &current != validated_boundary
                || &HistoryFrontier::capture_bounds(&tx)? != validated
            {
                return Err(StoreError::Invariant(
                    "expiry history changed after typed semantic validation; retry against current history".into(),
                ));
            }
        }
        validate_boundary(&tx)?;
        // Do not trust an advisory validation sidecar when selecting deletion.
        crate::validate_stored_digests(&tx, crate::Scope::FULL)?;
        let before = boundary(&tx)?;
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS expiry_runs(run_id TEXT PRIMARY KEY); DELETE FROM expiry_runs;")?;
        tx.execute("INSERT INTO expiry_runs SELECT run_id FROM watcher_runs w WHERE julianday(finished_at)<julianday(?1) AND NOT EXISTS(SELECT 1 FROM raw_submissions r WHERE r.run_id=w.run_id AND (julianday(r.received_at)>=julianday(?1) OR julianday(r.received_at) IS NULL)) AND NOT EXISTS(SELECT 1 FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE r.run_id=w.run_id AND (julianday(a.received_at)>=julianday(?1) OR julianday(a.admitted_at)>=julianday(?1) OR julianday(a.received_at) IS NULL OR julianday(a.admitted_at) IS NULL)) AND NOT EXISTS(SELECT 1 FROM local_watcher_provider_intakes l JOIN provider_intake_attempts p ON p.intake_id=l.intake_id WHERE l.run_id=w.run_id AND (julianday(p.received_at)>=julianday(?1) OR julianday(p.received_at) IS NULL))", [cutoff])?;
        // These roots have no observable downstream release condition. Every
        // diagnostic/successor and finding/notification/checkpoint dependency
        // is protected even if the occurrence completed a long time ago.
        tx.execute_batch("DELETE FROM expiry_runs WHERE run_id IN (
            SELECT run_id FROM local_successor_acquisition_intents
            UNION SELECT run_id FROM local_diagnostic_artifact_origins
            UNION SELECT r.run_id FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id JOIN finding_evidence f ON f.report_id=a.report_id
            UNION SELECT e.trigger_run_id FROM evaluation_runs e JOIN finding_events f ON f.evaluation_id=e.evaluation_id
            UNION SELECT e.trigger_run_id FROM evaluation_runs e JOIN saved_check_events s ON s.evaluation_id=e.evaluation_id
            UNION SELECT run_id FROM status_events WHERE status_event_id IN (SELECT latest_status_event_id FROM status_current)
            UNION SELECT r.run_id FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE a.report_sequence IN (SELECT MAX(report_sequence) FROM admitted_reports GROUP BY instance_id)
            UNION SELECT r.run_id FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id JOIN watcher_runs w ON w.run_id=r.run_id JOIN local_watcher_provider_intakes l ON l.run_id=w.run_id JOIN provider_intake_acknowledgments ack ON ack.intake_id=l.intake_id AND ack.run_id=l.run_id WHERE a.next_checkpoint_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM admitted_reports newer JOIN raw_submissions ns ON ns.submission_id=newer.submission_id JOIN watcher_runs nw ON nw.run_id=ns.run_id JOIN local_watcher_provider_intakes nl ON nl.run_id=nw.run_id JOIN provider_intake_acknowledgments na ON na.intake_id=nl.intake_id AND na.run_id=nl.run_id WHERE newer.instance_id=a.instance_id AND nw.checkpoint_contract_digest=w.checkpoint_contract_digest AND newer.next_checkpoint_json IS NOT NULL AND newer.report_sequence>a.report_sequence)
        );")?;
        let (ef, rf, inf, sf) = loop {
            let run_count: i64 =
                tx.query_row("SELECT COUNT(*) FROM expiry_runs", [], |r| r.get(0))?;
            // Retain one evaluation per detector lineage for monotonic issuance.
            let ef=tx.query_row("SELECT COALESCE(MIN(evaluation_sequence)-1,(SELECT MAX(evaluation_sequence) FROM evaluation_runs),?2) FROM evaluation_runs e WHERE julianday(evaluated_at)>=julianday(?1) OR julianday(evaluated_at) IS NULL OR (trigger_run_id IS NOT NULL AND trigger_run_id NOT IN (SELECT run_id FROM expiry_runs)) OR evaluation_id IN (SELECT evaluation_id FROM finding_events UNION SELECT evaluation_id FROM saved_check_events UNION SELECT evaluation_id FROM local_diagnostic_artifact_origins) OR evaluation_sequence IN (SELECT MAX(evaluation_sequence) FROM evaluation_runs GROUP BY detector_id,detector_version)",params![cutoff,before.evaluation_floor],|r|r.get(0))?;
            // All surviving canonical evaluation references protect their
            // report, including references represented only in JSON.
            tx.execute("DELETE FROM expiry_runs WHERE run_id IN (SELECT r.run_id FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE a.report_sequence IN (SELECT max_report_sequence FROM evaluation_watermarks w JOIN evaluation_runs e ON e.evaluation_id=w.evaluation_id WHERE e.evaluation_sequence>?1) OR a.report_id IN (SELECT j.value FROM evaluation_runs e,json_tree(CAST(e.detail_json AS TEXT)) j WHERE e.evaluation_sequence>?1 AND j.type='text'))",[ef])?;
            let rf=tx.query_row("SELECT COALESCE(MIN(a.report_sequence)-1,(SELECT MAX(report_sequence) FROM admitted_reports),?1) FROM admitted_reports a JOIN raw_submissions r ON r.submission_id=a.submission_id WHERE r.run_id NOT IN(SELECT run_id FROM expiry_runs)",[before.report_floor],|r|r.get(0))?;
            let inf=tx.query_row("SELECT COALESCE(MIN(p.intake_sequence)-1,(SELECT MAX(intake_sequence) FROM provider_intake_attempts),?1) FROM provider_intake_attempts p LEFT JOIN local_watcher_provider_intakes l ON l.intake_id=p.intake_id WHERE p.history_expired=0 AND (l.run_id IS NULL OR l.run_id NOT IN(SELECT run_id FROM expiry_runs))",[before.intake_floor],|r|r.get(0))?;
            let sf=tx.query_row("SELECT COALESCE(MIN(status_sequence)-1,(SELECT MAX(status_sequence) FROM status_events WHERE run_id IS NOT NULL),?1) FROM status_events WHERE run_id IS NOT NULL AND run_id NOT IN(SELECT run_id FROM expiry_runs)",[before.status_floor],|r|r.get(0))?;
            tx.execute("DELETE FROM expiry_runs WHERE run_id IN(SELECT trigger_run_id FROM evaluation_runs WHERE evaluation_sequence>?1 UNION SELECT r.run_id FROM raw_submissions r JOIN admitted_reports a ON a.submission_id=r.submission_id WHERE a.report_sequence>?2 UNION SELECT l.run_id FROM local_watcher_provider_intakes l JOIN provider_intake_attempts p ON p.intake_id=l.intake_id WHERE p.intake_sequence>?3 UNION SELECT run_id FROM status_events WHERE status_sequence>?4)",params![ef,rf,inf,sf])?;
            let after: i64 = tx.query_row("SELECT COUNT(*) FROM expiry_runs", [], |r| r.get(0))?;
            if after == run_count {
                break (ef, rf, inf, sf);
            }
        };
        let mut next = RetentionBoundary {
            generation: before.generation,
            evaluation_floor: ef,
            report_floor: rf,
            intake_floor: inf,
            status_floor: sf,
        };
        if next == before {
            tx.rollback()?;
            return Ok(RetentionResult {
                boundary: before,
                deleted_rows: 0,
            });
        }
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
                old.revision = f.revision;
            } else {
                floors.push(f);
            }
        }
        floors.sort_by(|a, b| {
            (&a.detector_id, &a.detector_version).cmp(&(&b.detector_id, &b.detector_version))
        });
        let document = CanonicalDocument::from_serializable(&floors)?;
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS expiry_links(intake_id TEXT PRIMARY KEY,run_id TEXT NOT NULL,submission_id TEXT,report_id TEXT,semantic_digest TEXT);DELETE FROM expiry_links;INSERT INTO expiry_links SELECT l.intake_id,l.run_id,r.submission_id,a.report_id,a.semantic_digest FROM local_watcher_provider_intakes l JOIN expiry_runs e ON e.run_id=l.run_id LEFT JOIN raw_submissions r ON r.run_id=l.run_id LEFT JOIN admitted_reports a ON a.submission_id=r.submission_id;")?;
        #[cfg(test)]
        crash_phase_for_test("before_mutations", 71);
        tx.execute(
            "UPDATE retention_state SET delete_enabled=1 WHERE singleton=1",
            [],
        )?;
        let mut deleted = 0usize;
        for sql in [
            "DELETE FROM refusals WHERE evaluation_id IN(SELECT evaluation_id FROM evaluation_runs WHERE evaluation_sequence<=?1) OR run_id IN(SELECT run_id FROM expiry_runs) OR submission_id IN(SELECT submission_id FROM raw_submissions WHERE run_id IN(SELECT run_id FROM expiry_runs))",
            "DELETE FROM evaluation_watermarks WHERE evaluation_id IN(SELECT evaluation_id FROM evaluation_runs WHERE evaluation_sequence<=?1)",
            "DELETE FROM evaluation_runs WHERE evaluation_sequence<=?1",
        ] {
            deleted += tx.execute(sql, [ef])?;
        }
        for sql in [
            "DELETE FROM observation_coverage WHERE report_id IN(SELECT report_id FROM admitted_reports WHERE report_sequence<=?1)",
            "DELETE FROM observations WHERE report_id IN(SELECT report_id FROM admitted_reports WHERE report_sequence<=?1)",
            "DELETE FROM report_coverage WHERE report_id IN(SELECT report_id FROM admitted_reports WHERE report_sequence<=?1)",
            "DELETE FROM report_errors WHERE report_id IN(SELECT report_id FROM admitted_reports WHERE report_sequence<=?1)",
            "DELETE FROM admitted_reports WHERE report_sequence<=?1",
        ] {
            deleted += tx.execute(sql, [rf])?;
        }
        for sql in [
            "DELETE FROM provider_intake_acknowledgments WHERE run_id IN(SELECT run_id FROM expiry_runs)",
            "DELETE FROM local_watcher_provider_intakes WHERE run_id IN(SELECT run_id FROM expiry_runs)",
            "DELETE FROM legacy_v3_watcher_run_intake_gaps WHERE run_id IN(SELECT run_id FROM expiry_runs)",
            "DELETE FROM raw_submissions WHERE run_id IN(SELECT run_id FROM expiry_runs)",
            "DELETE FROM status_events WHERE run_id IN(SELECT run_id FROM expiry_runs)",
            "DELETE FROM watcher_runs WHERE run_id IN(SELECT run_id FROM expiry_runs)",
        ] {
            deleted += tx.execute(sql, [])?;
        }
        let retire_ids:Vec<String>=tx.prepare("SELECT intake_id FROM provider_intake_attempts WHERE history_expired=0 AND intake_sequence<=?1")?.query_map([inf],|r|r.get(0))?.collect::<Result<_,_>>()?;
        for id in retire_ids {
            let (run,submission,report,digest):(String,Option<String>,Option<String>,Option<String>)=tx.query_row("SELECT run_id,submission_id,report_id,semantic_digest FROM expiry_links WHERE intake_id=?1",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
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
            let commitment = retired_identity_commitment_with_links(&tx, &id, Some(&links))?;
            deleted+=tx.execute("UPDATE provider_intake_attempts SET history_expired=1,raw_bytes=X'',context_json=CAST('{}' AS BLOB),interpretation_json=CAST('{}' AS BLOB),native_outcome_json=CAST('{}' AS BLOB),retired_identity_digest=?1,retired_run_id=?3,retired_submission_id=?4,retired_report_id=?5,retired_report_semantic_digest=?6 WHERE intake_id=?2",params![commitment,id,run,submission,report,digest])?;
        }
        tx.execute("UPDATE retention_state SET generation=?1,evaluation_floor=?2,report_floor=?3,intake_floor=?4,status_floor=?5,cutoff=?6,lineage_floors_json=?7,delete_enabled=0 WHERE singleton=1",params![next.generation,ef,rf,inf,sf,cutoff,document.as_bytes()])?;
        validate_boundary(&tx)?;
        let violations: i64 =
            tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        if violations != 0 {
            return Err(StoreError::Integrity(
                "expiry closure has surviving foreign-key references".into(),
            ));
        }
        #[cfg(test)]
        crash_phase_for_test("inside_transaction", 72);
        tx.commit()?;
        #[cfg(test)]
        crash_phase_for_test("after_commit", 73);
        self.validation = ValidationState::default();
        Ok(RetentionResult {
            boundary: next,
            deleted_rows: deleted,
        })
    }
}
