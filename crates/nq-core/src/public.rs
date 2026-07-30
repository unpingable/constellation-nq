//! Stable public read-model DTOs shared by CLI, local API, and console.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::{CollectionOutcome, EvaluationEnvelopeV2, GovernedRefusal};

/// Finding snapshot schema identifier.
pub const FINDING_SNAPSHOT_SCHEMA: &str = "nq.finding_snapshot.v3";
/// Status snapshot schema identifier.
pub const STATUS_SNAPSHOT_SCHEMA: &str = "nq.status_snapshot.v1";
/// Lossless typed status snapshot schema identifier.
pub const STATUS_SNAPSHOT_V2_SCHEMA: &str = "nq.status_snapshot.v2";
/// Status snapshot with authoritative current evaluation results.
pub const STATUS_SNAPSHOT_V3_SCHEMA: &str = "nq.status_snapshot.v3";
/// Bounded immutable evaluation-history page schema identifier.
pub const EVALUATION_HISTORY_SCHEMA: &str = "nq.evaluation_history.v1";
/// Typed rejected-custody history schema identifier.
pub const REJECTED_CUSTODY_SCHEMA: &str = "nq.rejected_custody.v1";

/// One current bounded operational diagnosis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FindingSnapshotV3 {
    /// Exact DTO schema.
    pub schema: String,
    /// Opaque NQ-owned identity. Consumers never reconstruct this value.
    pub finding_id: String,
    /// Exact watcher instance evaluated.
    pub instance_id: String,
    /// Exact compiled detector identity.
    pub detector: DetectorIdentity,
    /// Exact compiled profile identity.
    pub profile: PublicProfileIdentity,
    /// Profile-validated subject.
    pub subject: serde_json::Value,
    /// Monotonic revision of this detector's evaluation history.
    pub evaluation_revision: u64,
    /// Condition state, kept separate from evidence visibility.
    pub condition: ConditionView,
    /// Whether current evidence supports reliance.
    pub visibility: VisibilityView,
    /// Operator workflow state, never inferred as authority.
    pub operator_work_state: String,
    /// Operational severity assigned by compiled NQ semantics.
    pub severity: Severity,
    /// Concise operator-facing diagnosis.
    pub summary: String,
    /// Exact report/observation references.
    pub evidence: Vec<PublicEvidenceReference>,
    /// Material limits on the diagnosis.
    pub limitations: Vec<String>,
    /// Safe read-only or diagnostic next checks.
    pub safe_next_checks: Vec<String>,
    /// Overall source observation time, when meaningful.
    pub observed_at: Option<DateTime<Utc>>,
    /// NQ receive time for the newest cited report.
    pub received_at: Option<DateTime<Utc>>,
    /// Exact evaluation time.
    pub evaluated_at: DateTime<Utc>,
    /// Whether the finding is native nq-ng evidence or contains a historical
    /// reference. Historical references never create current state themselves.
    pub origin_mode: OriginMode,
    /// Optional immutable legacy references.
    pub historical_references: Vec<String>,
}

/// Compiled detector identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DetectorIdentity {
    /// Stable detector ID.
    pub id: String,
    /// Detector version.
    pub version: u32,
    /// Canonical detector descriptor digest.
    pub digest: String,
}

/// Compiled profile identity exposed to consumers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicProfileIdentity {
    /// Stable profile ID.
    pub id: String,
    /// Profile version.
    pub version: u32,
    /// Canonical descriptor digest.
    pub digest: String,
    /// Composite compiled profile/protocol/evaluator semantic identity.
    pub semantic_id: String,
}

/// Current detector condition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConditionView {
    /// Stable condition vocabulary entry.
    pub name: String,
    /// Tri-state detector result.
    pub state: ConditionState,
}

/// Detector condition state. Only explicit absence under sufficient visibility
/// can resolve a finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionState {
    /// Condition is supported by current admitted evidence.
    Present,
    /// Sufficient current coverage explicitly supports absence.
    ExplicitlyAbsent,
    /// Current evidence cannot support either result.
    CannotEvaluate,
}

/// Evidence visibility, freshness, basis, and exact refusal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VisibilityView {
    /// Current visibility state.
    pub state: VisibilityState,
    /// Profile-owned freshness detail.
    pub freshness: serde_json::Value,
    /// Profile-owned basis/vantage detail.
    pub basis: serde_json::Value,
    /// Typed refusal when evaluation cannot proceed.
    pub refusal: Option<GovernedRefusal>,
}

/// Reliance state of the evidence plane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityState {
    /// Coverage and freshness are sufficient.
    Sufficient,
    /// A valid partial report exists.
    Partial,
    /// Otherwise valid evidence is outside its reliance window.
    Stale,
    /// No qualifying admitted evidence exists.
    Missing,
    /// Exact validation/evaluation boundary refused.
    Refused,
}

/// Product severity vocabulary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational state.
    Info,
    /// Operator attention is useful.
    Warning,
    /// Bounded condition is operationally degraded.
    Error,
    /// Immediate operator attention is warranted.
    Critical,
}

/// One evidence reference from a finding to immutable admitted testimony.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicEvidenceReference {
    /// NQ-owned report identity.
    pub report_id: String,
    /// Canonical semantic report digest.
    pub semantic_digest: String,
    /// Specific observation ordinal, if applicable.
    pub observation_ordinal: Option<u32>,
    /// Underlying observation time.
    pub observed_at: DateTime<Utc>,
    /// NQ receive time.
    pub received_at: DateTime<Utc>,
}

/// Origin classification; it never upgrades historical context into current
/// testimony.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OriginMode {
    /// Entirely nq-ng-native admitted evidence.
    Native,
    /// Native finding that links immutable historical context.
    NativeWithHistoricalReference,
}

/// Complete local service health snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshotV1 {
    /// Exact DTO schema.
    pub schema: String,
    /// Snapshot generation time.
    pub generated_at: DateTime<Utc>,
    /// Current independently reported component states.
    pub components: Vec<ComponentStatus>,
}

/// One component of the service health surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentStatus {
    /// Component class.
    pub kind: ComponentKind,
    /// Stable local component identity.
    pub id: String,
    /// Coarse health state.
    pub state: HealthState,
    /// Precise stable diagnostic code.
    pub code: String,
    /// Bounded diagnostic details.
    pub details: serde_json::Value,
    /// Time the component was observed.
    pub observed_at: DateTime<Utc>,
}

/// Complete local service health snapshot whose instance results are decoded
/// into the versioned canonical collection carrier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshotV2 {
    /// Exact DTO schema.
    pub schema: String,
    /// Snapshot generation time.
    pub generated_at: DateTime<Utc>,
    /// Current independently reported component states.
    pub components: Vec<ComponentStatusV2>,
}

/// Typed details of one v2 component status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "detail_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComponentStatusDetailV2 {
    /// Canonical result for a watcher instance.
    Collection {
        /// Complete versioned collection envelope.
        result: CollectionOutcome,
    },
    /// Non-instance operational diagnostic retained as bounded JSON.
    Diagnostic {
        /// Exact bounded diagnostic value stored by the component.
        value: serde_json::Value,
    },
}

/// One component of the v2 status surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentStatusV2 {
    /// Component class.
    pub kind: ComponentKind,
    /// Stable local component identity.
    pub id: String,
    /// Coarse health state.
    pub state: HealthState,
    /// Precise stable diagnostic code.
    pub code: String,
    /// Typed collection result or non-instance diagnostic.
    pub detail: ComponentStatusDetailV2,
    /// Time the component was observed.
    pub observed_at: DateTime<Utc>,
}

/// Complete local service health snapshot with authoritative evaluation
/// results selected from immutable evaluation history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshotV3 {
    /// Exact DTO schema.
    pub schema: String,
    /// Snapshot generation time.
    pub generated_at: DateTime<Utc>,
    /// Highest evaluation append sequence included in this snapshot.
    pub evaluation_through_sequence: u64,
    /// Current independently reported components and the latest exact result
    /// for every complete semantic evaluation lineage.
    pub components: Vec<ComponentStatusV3>,
}

/// Typed details of one v3 component status.
// The exact governed envelopes intentionally stay inline: boxing would alter
// the canonical Rust carrier without changing the bounded wire document.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "detail_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComponentStatusDetailV3 {
    /// Canonical result for a watcher instance.
    Collection {
        /// Complete versioned collection envelope.
        result: CollectionOutcome,
    },
    /// Canonical result of the latest evaluation in one exact semantic lineage.
    Evaluation {
        /// Store-wide append sequence of this immutable evaluation.
        sequence: u64,
        /// Complete canonical evaluation envelope.
        result: EvaluationEnvelopeV2,
    },
    /// Non-instance operational diagnostic retained as bounded JSON.
    Diagnostic {
        /// Exact bounded diagnostic value stored by the component.
        value: serde_json::Value,
    },
}

/// One component of the v3 status surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentStatusV3 {
    /// Component class.
    pub kind: ComponentKind,
    /// Stable local identity. Evaluation components use the immutable identity
    /// of the selected canonical evaluation event.
    pub id: String,
    /// Coarse health state derived from the canonical detail.
    pub state: HealthState,
    /// Precise stable diagnostic code derived from the canonical detail.
    pub code: String,
    /// Typed collection, evaluation, or operational detail.
    pub detail: ComponentStatusDetailV3,
    /// Time the component was observed.
    pub observed_at: DateTime<Utc>,
}

/// One immutable evaluation record and its monotone store cursor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationHistoryRecordV1 {
    /// Store-wide gap-free append sequence.
    pub sequence: u64,
    /// Exact canonical evaluation result.
    pub result: EvaluationEnvelopeV2,
}

/// Explicitly bounded page of immutable governed evaluation history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationHistoryPageV1 {
    /// Exact DTO schema.
    pub schema: String,
    /// Page generation time.
    pub generated_at: DateTime<Utc>,
    /// Requested maximum record count.
    pub limit: u32,
    /// Exclusive append-sequence cursor supplied by the caller.
    pub after_sequence: Option<u64>,
    /// Inclusive frozen upper bound for this logical history snapshot.
    pub through_sequence: u64,
    /// Exact immutable records in append order.
    pub records: Vec<EvaluationHistoryRecordV1>,
    /// Cursor for the next page within `through_sequence`, when one exists.
    pub next_after_sequence: Option<u64>,
    /// True only when this page reaches `through_sequence`.
    pub complete: bool,
}

/// Bounded, typed historical rejected-custody snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RejectedCustodySnapshotV1 {
    /// Exact DTO schema.
    pub schema: String,
    /// Snapshot generation time.
    pub generated_at: DateTime<Utc>,
    /// Immutable rejected submissions with their linked canonical refusals.
    pub records: Vec<RejectedCustodyV1>,
}

/// One immutable rejected submission and its exact linked typed refusal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RejectedCustodyV1 {
    /// NQ-owned raw-submission identity.
    pub submission_id: String,
    /// NQ-owned collection-run identity.
    pub run_id: String,
    /// Originating helper request identity.
    pub request_id: String,
    /// Responsible watcher instance.
    pub instance_id: String,
    /// Exact compiled profile identity bound to the run.
    pub profile: PublicProfileIdentity,
    /// Digest of the byte-exact rejected helper output.
    pub raw_sha256: String,
    /// NQ receive time.
    pub received_at: DateTime<Utc>,
    /// Stable protocol processing outcome.
    pub protocol_outcome: String,
    /// Exact canonical refusal linked by stable refusal ID.
    pub refusal: GovernedRefusal,
    /// Refusal creation time.
    pub created_at: DateTime<Utc>,
}

/// Status component classes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    /// Resident service process.
    Daemon,
    /// `SQLite` substrate.
    Database,
    /// Compiled profile registry.
    ProfileCatalog,
    /// Admission bindings.
    Admission,
    /// Legacy decode-only scheduler status retained so immutable pre-v2 status
    /// rows remain inspectable. Current NQ code must never emit this kind.
    Scheduler,
    /// Watcher instance.
    Instance,
    /// One bounded diagnostic execution. This reports processing outcome only;
    /// it is not the health of the subject or resident watcher instance.
    DiagnosticExecution,
    /// Detector evaluator.
    Evaluation,
    /// Legacy decode-only notification status retained so immutable pre-v2
    /// status rows remain inspectable. Nightshift owns current notification
    /// posture and delivery semantics; current NQ code must never emit this
    /// kind.
    Notification,
}

/// Coarse status health.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Component is healthy for its bounded purpose.
    Healthy,
    /// Component is functioning with a material limitation.
    Degraded,
    /// Component cannot perform its bounded purpose.
    Failed,
    /// No current state is known.
    Unknown,
}

impl StatusSnapshotV1 {
    /// Create an empty snapshot. Empty is distinct from healthy.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema: STATUS_SNAPSHOT_SCHEMA.into(),
            generated_at: Utc::now(),
            components: Vec::new(),
        }
    }
}

impl StatusSnapshotV2 {
    /// Create an empty typed snapshot. Empty is distinct from healthy.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema: STATUS_SNAPSHOT_V2_SCHEMA.into(),
            generated_at: Utc::now(),
            components: Vec::new(),
        }
    }
}

impl StatusSnapshotV3 {
    /// Create an empty typed snapshot. Empty is distinct from healthy.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema: STATUS_SNAPSHOT_V3_SCHEMA.into(),
            generated_at: Utc::now(),
            evaluation_through_sequence: 0,
            components: Vec::new(),
        }
    }
}
