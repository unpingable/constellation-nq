//! Disposable read-only projection over canonical runtime ledger rows.

use std::collections::BTreeMap;

use nq_protocol::Sha256Digest;
use nq_store::RuntimeRecordRow;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Availability of the disposable in-memory inspector index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectorProjectionState {
    /// Projection was reconstructed from canonical ledger rows.
    Available,
    /// Projection was intentionally discarded and carries no meaning until
    /// reconstructed.
    Discarded,
}

/// One non-authoritative, read-only index entry.
///
/// Every field either repeats immutable ledger metadata or is a literal
/// bounded field copied from the canonical record. No health, posture,
/// recurrence, comparability, authorization, or action meaning is derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectorEntry {
    /// Immutable ledger position.
    pub record_sequence: u64,
    /// Exact record identity.
    pub record_id: String,
    /// Exact record schema.
    pub record_schema: String,
    /// Digest of the exact canonical record bytes.
    pub canonical_bytes_sha256: Sha256Digest,
    /// Checkpoint that committed the record.
    pub checkpoint_id: String,
    /// Exact append-only ledger root after this record.
    pub ledger_root: Sha256Digest,
    /// Caller-supplied record commit time retained by the ledger.
    pub committed_at: String,
    /// Literal diagnostic artifact identity where the carrier exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    /// Literal V2 binding result, with no reinterpretation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_result: Option<String>,
    /// Literal delivery state, with no posture meaning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_state: Option<String>,
    /// Literal lifecycle operation, with no action affordance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_operation: Option<String>,
}

impl InspectorEntry {
    pub(crate) fn from_row(row: &RuntimeRecordRow) -> Self {
        let value: Option<Value> = serde_json::from_slice(row.canonical_bytes.as_bytes()).ok();
        Self {
            record_sequence: row.record_sequence,
            record_id: row.record_id.clone(),
            record_schema: row.record_schema.clone(),
            canonical_bytes_sha256: row.canonical_bytes_sha256.clone(),
            checkpoint_id: row.checkpoint_id.clone(),
            ledger_root: row.ledger_root.clone(),
            committed_at: row.committed_at.clone(),
            artifact_id: value.as_ref().and_then(extract_artifact_id),
            binding_result: literal(value.as_ref(), "binding_result"),
            delivery_state: literal(value.as_ref(), "state")
                .filter(|_| row.record_schema == "nq.artifact_delivery_record.v1"),
            lifecycle_operation: literal(value.as_ref(), "operation").filter(|_| {
                matches!(
                    row.record_schema.as_str(),
                    "nq.host_role_lifecycle_event.v1"
                        | "nq.witness_lifecycle_event.v1"
                        | "nq.node_key_lifecycle_event.v1"
                )
            }),
        }
    }
}

fn literal(value: Option<&Value>, field: &str) -> Option<String> {
    value?.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn extract_artifact_id(value: &Value) -> Option<String> {
    value
        .get("diagnostic")
        .or_else(|| value.get("artifact"))
        .and_then(|artifact| artifact.get("artifact_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// One immutable page of inspector references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectorPage {
    /// Exact runtime checkpoint identity, absent only for an empty ledger.
    pub checkpoint_id: Option<String>,
    /// Exact runtime dependency-pair identity.
    pub dependency_binding_digest: Sha256Digest,
    /// Exclusive sequence cursor supplied by the reader.
    pub after_record_sequence: u64,
    /// Read-only index entries in append order.
    pub entries: Vec<InspectorEntry>,
    /// Cursor for another page, absent when complete.
    pub next_after_record_sequence: Option<u64>,
    /// Whether this page completes the immutable snapshot.
    pub complete: bool,
}

/// Disposable inspector projection reconstructed from canonical ledger rows.
#[derive(Debug, Clone, Default)]
pub struct InspectorProjection {
    by_sequence: BTreeMap<u64, InspectorEntry>,
    state: Option<InspectorProjectionState>,
}

impl InspectorProjection {
    pub(crate) fn rebuilt(rows: &[RuntimeRecordRow]) -> Self {
        Self {
            by_sequence: rows
                .iter()
                .map(|row| (row.record_sequence, InspectorEntry::from_row(row)))
                .collect(),
            state: Some(InspectorProjectionState::Available),
        }
    }

    pub(crate) fn discard(&mut self) {
        self.by_sequence.clear();
        self.state = Some(InspectorProjectionState::Discarded);
    }

    pub(crate) fn state(&self) -> InspectorProjectionState {
        self.state.unwrap_or(InspectorProjectionState::Discarded)
    }

    pub(crate) fn entries_after(
        &self,
        after_record_sequence: u64,
        through_record_sequence: u64,
        limit: usize,
    ) -> Vec<InspectorEntry> {
        self.by_sequence
            .range((
                std::ops::Bound::Excluded(after_record_sequence),
                std::ops::Bound::Included(through_record_sequence),
            ))
            .take(limit)
            .map(|(_, entry)| entry.clone())
            .collect()
    }
}
