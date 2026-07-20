//! Stable public read-model DTOs shared by CLI, local API, and console.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Finding snapshot schema identifier.
pub const FINDING_SNAPSHOT_SCHEMA: &str = "nq.finding_snapshot.v2";
/// Status snapshot schema identifier.
pub const STATUS_SNAPSHOT_SCHEMA: &str = "nq.status_snapshot.v1";

/// One current bounded operational diagnosis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FindingSnapshotV2 {
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
    pub refusal: Option<serde_json::Value>,
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
    /// Independent scheduler.
    Scheduler,
    /// Watcher instance.
    Instance,
    /// Detector evaluator.
    Evaluation,
    /// Notification outbox/delivery.
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
