//! Ordinary current-question custody. Unreferenced older source is outside
//! this proof; the separate complete-source proof and full audit retain it.

use std::{collections::BTreeMap, sync::Arc};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    ADMITTED_REPORT_COLUMNS, AdmittedReportRow, CanonicalDocument, EvaluationFindingLineage,
    EvaluationWatermark, EvidenceSnapshot, Refusal, Store, StoreError, decode_admitted_report,
    prepared_evidence::{SnapshotStamp, current_admitted_report},
};

/// Consumed source support for one ordinary current question: its absolute
/// instance head and the exact current finding lineage's citation closure.
/// It does not certify unreferenced older report bytes or profile eligibility.
pub struct PreparedCurrentEvidenceSnapshot {
    lineage: EvaluationFindingLineage,
    handle: Arc<()>,
    stamp: SnapshotStamp,
    generation: i64,
    selected: CurrentSelection,
}

#[derive(PartialEq, Eq)]
struct CurrentSelection {
    snapshot: EvidenceSnapshot,
    findings: Vec<FindingSupport>,
}

#[derive(PartialEq, Eq)]
struct FindingSupport {
    finding_id: String,
    citations: Vec<Citation>,
}

#[derive(PartialEq, Eq)]
struct Citation {
    ordinal: i64,
    report_id: String,
    digest: String,
    observation_ordinal: Option<i64>,
    observed_at: String,
    received_at: String,
}

impl PreparedCurrentEvidenceSnapshot {
    #[must_use]
    pub fn snapshot(&self) -> &EvidenceSnapshot {
        &self.selected.snapshot
    }

    #[must_use]
    pub fn retention_generation(&self) -> i64 {
        self.generation
    }

    pub(super) fn require_instance(&self, instance: &str) -> Result<(), StoreError> {
        if self.lineage.instance_id != instance {
            return Err(StoreError::Invariant(
                "prepared current evidence belongs to a different instance".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn resolve(
        self,
        store: &Store,
        transaction: &Transaction<'_>,
    ) -> Result<ResolvedCurrentSnapshot, StoreError> {
        if store.retention_generation()? != self.generation {
            return Err(StoreError::Refused(Refusal::HistoryChanged("during")));
        }
        let unchanged = Arc::ptr_eq(&self.handle, &store.prepared_handle)
            && SnapshotStamp::capture(transaction)? == self.stamp;
        let selected = if unchanged {
            self.selected
        } else {
            // Reselect membership, not just the originally captured report IDs:
            // a current finding may replace its citations without a new report.
            let current = select_current(transaction, &self.lineage)?
                .ok_or(StoreError::Refused(Refusal::HistoryChanged("during")))?;
            if current != self.selected {
                return Err(StoreError::Refused(Refusal::HistoryChanged("during")));
            }
            current
        };
        Ok(ResolvedCurrentSnapshot {
            instance_id: self.lineage.instance_id,
            snapshot: selected.snapshot,
        })
    }
}

pub(super) struct ResolvedCurrentSnapshot {
    instance_id: String,
    snapshot: EvidenceSnapshot,
}

impl ResolvedCurrentSnapshot {
    pub(super) fn finish(
        mut self,
        transaction: &Transaction<'_>,
        current: Option<(&str, &str, i64)>,
    ) -> Result<EvidenceSnapshot, StoreError> {
        if let Some((instance, report_id, sequence)) = current {
            if instance != self.instance_id {
                return Err(StoreError::Invariant(
                    "current occurrence differs from the prepared current instance".into(),
                ));
            }
            let row = current_admitted_report(transaction, instance, report_id, sequence)?;
            if sequence <= self.snapshot.watermarks[0].max_report_sequence {
                return Err(StoreError::Invariant(
                    "new current occurrence does not advance its absolute instance head".into(),
                ));
            }
            self.snapshot.watermarks[0] = watermark(instance, Some(&row));
            self.snapshot.reports.push(row);
        }
        // The scoped selection already carries its exact compact citations.
        // Do not broaden it through the all-lineage metadata helper.
        Ok(self.snapshot)
    }
}

impl Store {
    /// Prepare a separate ordinary current-question proof. A compact absolute
    /// head returns `None`; callers must use the complete-source path. Core
    /// separately owns exact law eligibility and canonical context fallback.
    pub fn prepare_current_evidence_snapshot(
        &mut self,
        lineage: &EvaluationFindingLineage,
    ) -> Result<Option<PreparedCurrentEvidenceSnapshot>, StoreError> {
        let generation = self.retention_generation()?;
        let stamp = SnapshotStamp::capture(&self.connection)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let selected = select_current(&transaction, lineage)?;
        transaction.commit()?;
        Ok(selected.map(|selected| PreparedCurrentEvidenceSnapshot {
            lineage: lineage.clone(),
            handle: Arc::clone(&self.prepared_handle),
            stamp,
            generation,
            selected,
        }))
    }
}

fn watermark(instance: &str, head: Option<&AdmittedReportRow>) -> EvaluationWatermark {
    EvaluationWatermark {
        instance_id: instance.to_owned(),
        max_report_sequence: head.map_or(0, |row| row.report_sequence),
        watermark_received_at: head.map(|row| row.received_at.clone()),
    }
}

fn decode_selected(row: &rusqlite::Row<'_>) -> rusqlite::Result<(AdmittedReportRow, bool)> {
    Ok((decode_admitted_report(row)?, row.get(11)?))
}

#[allow(clippy::too_many_lines)] // Keep the closed head/citation selection law together.
fn select_current(
    connection: &Connection,
    lineage: &EvaluationFindingLineage,
) -> Result<Option<CurrentSelection>, StoreError> {
    // The existing instance/sequence index selects the absolute head, including
    // compact rows. Never scan backwards looking for a convenient full source.
    let head = connection
        .query_row(
            &format!(
                "SELECT {ADMITTED_REPORT_COLUMNS}, source_expired FROM admitted_reports
         WHERE instance_id=?1 ORDER BY report_sequence DESC LIMIT 1"
            ),
            [&lineage.instance_id],
            decode_selected,
        )
        .optional()?;
    if head.as_ref().is_some_and(|(_, compact)| *compact) {
        return Ok(None);
    }
    let mark = watermark(&lineage.instance_id, head.as_ref().map(|(row, _)| row));
    let mut selected = BTreeMap::new();
    if let Some((row, compact)) = head {
        selected.insert(row.report_id.clone(), (row, compact));
    }
    let subject = CanonicalDocument::from_canonical_bytes(lineage.subject_json.clone())?;
    let basis = CanonicalDocument::from_canonical_bytes(lineage.basis_json.clone())?;
    // Pin lookup order to current pointers followed by event/evaluation PKs;
    // neither retained event history nor public finding/refusal projections are
    // materialized for this question.
    let mut statement = connection.prepare(
        "SELECT current.finding_id, event.event_id
         FROM finding_current AS current
         CROSS JOIN finding_events AS event ON event.event_id=current.latest_event_id
         CROSS JOIN evaluation_runs AS evaluation ON evaluation.evaluation_id=event.evaluation_id
         WHERE event.instance_id=?1 AND event.detector_id=?2 AND event.detector_version=?3
           AND event.detector_digest=?4 AND event.profile_id=?5 AND event.profile_version=?6
           AND event.profile_digest=?7 AND evaluation.profile_semantic_id=?8
           AND event.subject_json=?9 AND event.condition_name=?10 AND event.basis_json=?11
         ORDER BY current.finding_id",
    )?;
    let current = statement
        .query_map(
            params![
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
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut findings = Vec::with_capacity(current.len());
    let mut references = connection.prepare(
        "SELECT ordinal, report_id, report_semantic_digest, observation_ordinal, observed_at, received_at
         FROM finding_evidence WHERE event_id=?1 ORDER BY ordinal"
    )?;
    for (finding_id, event_id) in current {
        let citations = references
            .query_map([&event_id], |row| {
                Ok(Citation {
                    ordinal: row.get(0)?,
                    report_id: row.get(1)?,
                    digest: row.get(2)?,
                    observation_ordinal: row.get(3)?,
                    observed_at: row.get(4)?,
                    received_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for citation in &citations {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                selected.entry(citation.report_id.clone())
            {
                // Look up by ID alone, then compare the digest. An inner join
                // on both could silently erase a missing or substituted source.
                let report = connection.query_row(&format!(
                    "SELECT {ADMITTED_REPORT_COLUMNS}, source_expired FROM admitted_reports WHERE report_id=?1"
                ), [&citation.report_id], decode_selected).optional()?.ok_or_else(||
                    StoreError::Integrity(format!("current finding {finding_id} cites missing report {}", citation.report_id)))?;
                entry.insert(report);
            }
            let (report, _) = &selected[&citation.report_id];
            if report.semantic_digest != citation.digest
                || report.instance_id != lineage.instance_id
                || report.report_sequence > mark.max_report_sequence
            {
                return Err(StoreError::Integrity(format!(
                    "current finding {finding_id} citation {} differs from its report identity or instance head",
                    citation.report_id
                )));
            }
        }
        findings.push(FindingSupport {
            finding_id,
            citations,
        });
    }
    let mut reports = Vec::new();
    let mut expired_citations = Vec::new();
    for (row, compact) in selected.into_values() {
        if compact {
            expired_citations.push(row);
        } else {
            reports.push(row);
        }
    }
    reports.sort_by_key(|row| row.report_sequence);
    expired_citations.sort_by_key(|row| row.report_sequence);
    Ok(Some(CurrentSelection {
        snapshot: EvidenceSnapshot {
            watermarks: vec![mark],
            reports,
            expired_citations,
        },
        findings,
    }))
}
