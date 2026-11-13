//! Consumed, operation-local evidence custody; never a persistent history cache.

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    ADMITTED_REPORT_COLUMNS, AdmittedReportRow, EvidenceSnapshot, Refusal, Store, StoreError,
    decode_admitted_report, evidence_snapshot_from_connection,
    evidence_snapshot_metadata_from_connection, retention,
};

#[derive(PartialEq, Eq)]
pub(super) struct SnapshotStamp {
    data_version: i64,
    total_changes: u64,
    schema_cookie: i64,
}

impl SnapshotStamp {
    pub(super) fn capture(connection: &Connection) -> Result<Self, StoreError> {
        Ok(Self {
            data_version: connection.query_row("PRAGMA data_version", [], |row| row.get(0))?,
            total_changes: connection.total_changes(),
            schema_cookie: connection.query_row("PRAGMA schema_version", [], |row| row.get(0))?,
        })
    }
}

/// Private dispatch only: the public complete and current proof types remain
/// distinct so callers cannot silently narrow the old source contract.
pub(super) enum PreparedSource {
    Full(PreparedEvidenceSnapshot),
    Current(Box<super::PreparedCurrentEvidenceSnapshot>),
}

impl PreparedSource {
    pub(super) fn is_current(&self) -> bool {
        matches!(self, Self::Current(_))
    }

    pub(super) fn require_instance(&self, instance: &str) -> Result<(), StoreError> {
        match self {
            Self::Full(proof) => proof.require_instance(instance),
            Self::Current(proof) => proof.require_instance(instance),
        }
    }

    pub(super) fn resolve(
        self,
        store: &Store,
        transaction: &Transaction<'_>,
    ) -> Result<ResolvedSource, StoreError> {
        match self {
            Self::Full(proof) => proof.resolve(store, transaction).map(ResolvedSource::Full),
            Self::Current(proof) => proof
                .resolve(store, transaction)
                .map(ResolvedSource::Current),
        }
    }
}

pub(super) enum ResolvedSource {
    Full(ResolvedPreparedSnapshot),
    Current(super::current_evidence::ResolvedCurrentSnapshot),
}

impl ResolvedSource {
    pub(super) fn finish(
        self,
        transaction: &Transaction<'_>,
        current: Option<(&str, &str, i64)>,
    ) -> Result<EvidenceSnapshot, StoreError> {
        match self {
            Self::Full(proof) => proof.finish(transaction, current),
            Self::Current(proof) => proof.finish(transaction, current),
        }
    }
}

/// One complete source snapshot, bound to its originating Store handle and
/// pre-read database stamp. Only shared source access is exposed; commit
/// consumes the proof and resolves it inside the existing guarded transaction.
pub struct PreparedEvidenceSnapshot {
    instance_id: String,
    handle: Arc<()>,
    stamp: SnapshotStamp,
    generation: i64,
    snapshot: EvidenceSnapshot,
}

impl PreparedEvidenceSnapshot {
    #[must_use]
    pub fn snapshot(&self) -> &EvidenceSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn retention_generation(&self) -> i64 {
        self.generation
    }

    pub(super) fn require_instance(&self, instance_id: &str) -> Result<(), StoreError> {
        if self.instance_id != instance_id {
            return Err(StoreError::Invariant(
                "prepared evidence belongs to a different instance".into(),
            ));
        }
        Ok(())
    }

    /// Called after guarded validation and immediately before insertion. A
    /// different handle or changed stamp selects exact reconciliation, never a
    /// new refusal merely because an unrelated commit or rollback occurred.
    pub(super) fn resolve(
        self,
        store: &Store,
        transaction: &Transaction<'_>,
    ) -> Result<ResolvedPreparedSnapshot, StoreError> {
        if store.retention_generation()? != self.generation {
            return Err(StoreError::Refused(Refusal::HistoryChanged("during")));
        }
        let unchanged = Arc::ptr_eq(&self.handle, &store.prepared_handle)
            && SnapshotStamp::capture(transaction)? == self.stamp;
        let snapshot = if unchanged {
            self.snapshot
        } else {
            let current = evidence_snapshot_from_connection(
                transaction,
                std::slice::from_ref(&self.instance_id),
            )?;
            if current.reports != self.snapshot.reports {
                return Err(StoreError::Refused(Refusal::HistoryChanged("during")));
            }
            current
        };
        Ok(ResolvedPreparedSnapshot {
            instance_id: self.instance_id,
            snapshot,
        })
    }
}

pub(super) struct ResolvedPreparedSnapshot {
    instance_id: String,
    snapshot: EvidenceSnapshot,
}

impl ResolvedPreparedSnapshot {
    pub(super) fn finish(
        mut self,
        transaction: &Transaction<'_>,
        current: Option<(&str, &str, i64)>,
    ) -> Result<EvidenceSnapshot, StoreError> {
        if let Some((instance, report_id, sequence)) = current {
            if instance != self.instance_id {
                return Err(StoreError::Invariant(
                    "current occurrence differs from the prepared instance".into(),
                ));
            }
            self.snapshot.reports.push(current_admitted_report(
                transaction,
                instance,
                report_id,
                sequence,
            )?);
        }
        // These planes belong to the current guarded transaction, including
        // the just-inserted current report and its current retained citations.
        let (watermarks, expired_citations) = evidence_snapshot_metadata_from_connection(
            transaction,
            std::slice::from_ref(&self.instance_id),
        )?;
        self.snapshot.watermarks = watermarks;
        self.snapshot.expired_citations = expired_citations;
        Ok(self.snapshot)
    }
}

impl Store {
    pub fn prepare_evidence_snapshot(
        &mut self,
        instance_id: &str,
    ) -> Result<PreparedEvidenceSnapshot, StoreError> {
        // Keep the original conservative generation capture before reading S.
        let generation = self.retention_generation()?;
        // Capture BEFORE establishing the deferred read snapshot. A commit
        // between these steps must cause fallback, not stamp older S as newer.
        let stamp = SnapshotStamp::capture(&self.connection)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let snapshot = evidence_snapshot_from_connection(&transaction, &[instance_id.to_owned()])?;
        transaction.commit()?;
        Ok(PreparedEvidenceSnapshot {
            instance_id: instance_id.to_owned(),
            handle: Arc::clone(&self.prepared_handle),
            stamp,
            generation,
            snapshot,
        })
    }
}

pub(super) fn current_admitted_report(
    connection: &Connection,
    instance_id: &str,
    report_id: &str,
    sequence: i64,
) -> Result<AdmittedReportRow, StoreError> {
    connection
        .query_row(
            &format!(
                "SELECT {ADMITTED_REPORT_COLUMNS} FROM admitted_reports AS report
             WHERE instance_id=?1 AND report_id=?2 AND report_sequence=?3 AND {}",
                retention::full_source_condition(connection, "report")?,
            ),
            params![instance_id, report_id, sequence],
            decode_admitted_report,
        )
        .optional()?
        .ok_or_else(|| {
            StoreError::Invariant(
                "newly admitted report is absent or differs from its exact receipt identity".into(),
            )
        })
}
