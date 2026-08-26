//! Append-only custody and deterministic state machine for the bounded
//! recurring diagnostic office.
//!
//! The service manager may call `tick` repeatedly, but only an immutable,
//! deployment-constrained enrollment can create one acquisition occurrence for
//! one deterministic slot.  This module deliberately has no provider runner,
//! Nightshift client, cron parser, alert surface, or unbounded loop.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::Sha256Digest;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CanonicalDocument, Store, StoreError};

/// Closed deployment safety-envelope schema.
pub const RECURRING_OFFICE_POLICY_SCHEMA_V1: &str = "nq.recurring_office_policy.v1";
/// Closed immutable operator enrollment schema.
pub const RECURRENCE_ENROLLMENT_SPEC_SCHEMA_V1: &str = "nq.recurrence_enrollment_spec.v1";
/// Persisted enrollment representation.
pub const RECURRENCE_ENROLLMENT_SCHEMA_V1: &str = "nq.recurrence_enrollment.v1";
/// Immutable slot identity preimage.
pub const RECURRENCE_SLOT_SCHEMA_V1: &str = "nq.recurrence_slot.v1";
/// Immutable slot-to-acquisition binding.
pub const RECURRENCE_ACQUISITION_BINDING_SCHEMA_V1: &str = "nq.recurrence_acquisition_binding.v1";
/// Canonical envelope for every append-only recurrence state-machine event.
pub const RECURRENCE_EVENT_SCHEMA_V1: &str = "nq.recurrence_event.v1";
/// Exact provider-activity evidence schema. It deliberately has no diagnostic
/// result field.
pub const PROVIDER_ACTIVITY_EVIDENCE_SCHEMA_V1: &str = "nq.provider_activity_evidence.v1";
/// Closed producer that supervises one local stdio helper process group.
pub const LOCAL_STDIO_PROCESS_GROUP_SUPERVISION_V1: &str =
    "nq.local_stdio_process_group_supervision.v1";
/// Append-only acceptance/release event schema.
pub const PROVIDER_ACTIVITY_RECONCILIATION_SCHEMA_V1: &str =
    "nq.provider_activity_reconciliation.v1";
/// Only acquisition reason supported by the bounded V1 office.
pub const RECURRENCE_REASON_V1: &str = "diagnostic_recurrence";
/// Only origin profile supported by the deployed V1 office.
pub const LINODE_ORIGIN_PROFILE_V1: &str = "linode_instance_metadata_v1";
/// Closed helper issuer used by the qualified Linode metadata profile.
pub const LINODE_ORIGIN_HELPER_ISSUER_V1: &str = "origin-helper:linode-instance-metadata:v1";

/// Closed missed-slot behavior selected within deployment policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissedSlotPolicyV1 {
    /// Record a missed range and wait for a later slot.
    Skip,
    /// Record older missed slots and attempt only the latest due slot.
    LatestOnly,
}

/// Closed startup behavior selected within deployment policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupPolicyV1 {
    /// The first eligible slot is strictly after enrollment creation.
    WaitForNextSlot,
    /// The slot open at enrollment creation is eligible.
    EvaluateCurrentSlot,
}

/// One deployment-owned shared-provider coordination boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationDomainPolicyV1 {
    /// Opaque deployment-owned identifier; never inferred from names/URLs.
    pub domain_id: String,
    /// V1 supports the correctness-preserving value one only.
    pub max_in_flight: u16,
    /// Minimum spacing between provider invocation fences in this domain.
    pub min_provider_start_spacing_ms: u64,
}

/// Exact deployment mapping from watcher semantics to one coordination domain
/// and one qualified Linode-origin acquisition configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherCoordinationBindingV1 {
    pub watcher_instance_id: String,
    pub watcher_semantic_digest: String,
    pub coordination_domain_id: String,
    pub origin_profile: String,
    pub expected_instance_id_sha256: String,
    pub origin_helper_path: String,
    pub origin_helper_sha256: String,
    pub origin_helper_account: String,
    pub origin_helper_public_key_path: String,
    pub origin_helper_issuer: String,
    pub origin_helper_key_id: String,
}

/// Versioned deployment safety envelope. It permits selections but creates no
/// acquisition authority itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringOfficePolicyV1 {
    pub schema: String,
    pub deployment_profile_ref: String,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
    pub min_timer_granularity_ms: u64,
    pub max_enrollment_lifetime_ms: u64,
    pub max_acquisition_occurrences: u32,
    pub allowed_missed_slot_policies: BTreeSet<MissedSlotPolicyV1>,
    pub allowed_startup_policies: BTreeSet<StartupPolicyV1>,
    pub max_pre_provider_attempts: u16,
    pub min_pre_provider_backoff_ms: u64,
    pub max_pre_provider_backoff_ms: u64,
    pub max_consecutive_failure_threshold: u16,
    pub max_in_flight_per_watcher: u16,
    pub provider_timeout_ceiling_ms: u64,
    pub max_store_bytes: u64,
    pub min_free_bytes: u64,
    pub allowed_acquisition_reasons: BTreeSet<String>,
    pub coordination_domains: Vec<CoordinationDomainPolicyV1>,
    pub watcher_bindings: Vec<WatcherCoordinationBindingV1>,
}

/// Operator-selected finite recurrence terms. Every field participates in the
/// content-derived enrollment identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceEnrollmentSpecV1 {
    pub schema: String,
    pub operator_occurrence_id: String,
    pub policy_id: String,
    pub watcher_instance_id: String,
    pub anchor_unix_ms: i64,
    pub interval_ms: u64,
    pub max_acquisition_occurrences: u32,
    pub expires_at_unix_ms: i64,
    pub missed_slot_policy: MissedSlotPolicyV1,
    pub startup_policy: StartupPolicyV1,
    pub max_pre_provider_attempts: u16,
    pub pre_provider_backoff_ms: u64,
    pub failure_pause_threshold: u16,
    pub requested_domain_concurrency: u16,
    pub acquisition_reason: String,
}

/// Immutable materialized enrollment, including policy and watcher snapshots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceEnrollmentV1 {
    pub schema: String,
    pub enrollment_id: String,
    pub spec: RecurrenceEnrollmentSpecV1,
    pub watcher_semantic_digest: String,
    pub coordination_domain_id: String,
    pub first_eligible_slot: u64,
    pub created_at_unix_ms: i64,
}

/// Exact deterministic slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceSlotV1 {
    pub schema: String,
    pub slot_id: String,
    pub enrollment_id: String,
    pub slot_index: u64,
    pub scheduled_for_unix_ms: i64,
}

/// Immutable slot-to-acquisition and policy snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceAcquisitionBindingV1 {
    pub schema: String,
    pub acquisition_id: String,
    pub enrollment_id: String,
    pub policy_id: String,
    pub slot: RecurrenceSlotV1,
    pub watcher_instance_id: String,
    pub watcher_semantic_digest: String,
    pub coordination_domain_id: String,
    pub interval_ms: u64,
    pub max_pre_provider_attempts: u16,
    pub pre_provider_backoff_ms: u64,
    pub failure_pause_threshold: u16,
    pub max_store_bytes: u64,
    pub min_free_bytes: u64,
    pub provider_timeout_ceiling_ms: u64,
    pub domain_max_in_flight: u16,
    pub min_provider_start_spacing_ms: u64,
    pub created_at_unix_ms: i64,
}

/// Exact context checked immediately before the diagnostic provider invocation
/// fence. A stale epoch cannot regain custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecurrenceProviderFenceV1 {
    pub acquisition_id: String,
    pub enrollment_id: String,
    pub policy_id: String,
    pub coordination_domain_id: String,
    pub fencing_epoch: u64,
    pub attempt_number: u16,
    pub occurred_at_unix_ms: i64,
    pub watcher_instance_id: String,
    pub watcher_semantic_digest: String,
    pub origin_profile: String,
    pub expected_instance_id_sha256: String,
    pub origin_helper_issuer: String,
    pub origin_helper_key_id: String,
}

/// Closed provider-activity claim. Neither variant says what the diagnostic
/// concluded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderActivityClaimV1 {
    ProviderNotInvoked,
    ProviderQuiescent,
}

impl ProviderActivityClaimV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderNotInvoked => "provider_not_invoked",
            Self::ProviderQuiescent => "provider_quiescent",
        }
    }

    const fn disposition(self) -> &'static str {
        match self {
            Self::ProviderNotInvoked => "provider_not_invoked",
            Self::ProviderQuiescent => "outcome_unknown_provider_quiescent",
        }
    }
}

/// Exact NQ-produced provider-activity evidence for one fenced attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderActivityEvidenceV1 {
    pub schema: String,
    pub evidence_id: String,
    pub acquisition_id: String,
    pub enrollment_id: String,
    pub slot_id: String,
    pub coordination_domain_id: String,
    pub fencing_epoch: u64,
    pub attempt_number: u16,
    pub claim: ProviderActivityClaimV1,
    pub producer_schema: String,
    pub provider_attempt_id: String,
    pub provider_run_id: String,
    pub provider_request_id: String,
    pub provider_semantic_id: String,
    pub provider_artifact_digest: String,
    pub provider_execution_identity_digest: String,
    pub runner_outcome: String,
    pub observed_at_unix_ms: i64,
}

/// Read-only split projection for one provider-fenced acquisition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderFenceStatusV1 {
    pub schema: String,
    pub acquisition_id: String,
    pub enrollment_id: String,
    pub slot_id: String,
    pub coordination_domain_id: String,
    pub fencing_epoch: u64,
    pub diagnostic_outcome: String,
    pub provider_activity: String,
    pub coordination: String,
    pub evidence_id: Option<String>,
    pub reconciliation_event_id: Option<String>,
    pub reason: String,
}

impl ProviderActivityEvidenceV1 {
    /// Construct content-addressed evidence from facts already owned by the
    /// closed local stdio runner. This constructor creates no provider fact.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        acquisition: &RecurrenceAcquisitionBindingV1,
        fencing_epoch: u64,
        attempt_number: u16,
        claim: ProviderActivityClaimV1,
        provider_attempt_id: String,
        provider_run_id: String,
        provider_request_id: String,
        provider_semantic_id: String,
        provider_artifact_digest: String,
        provider_execution_identity_digest: String,
        runner_outcome: String,
        observed_at_unix_ms: i64,
    ) -> Result<Self, StoreError> {
        let basis = serde_json::json!({
            "schema": PROVIDER_ACTIVITY_EVIDENCE_SCHEMA_V1,
            "acquisition_id": acquisition.acquisition_id,
            "enrollment_id": acquisition.enrollment_id,
            "slot_id": acquisition.slot.slot_id,
            "coordination_domain_id": acquisition.coordination_domain_id,
            "fencing_epoch": fencing_epoch,
            "attempt_number": attempt_number,
            "claim": claim,
            "producer_schema": LOCAL_STDIO_PROCESS_GROUP_SUPERVISION_V1,
            "provider_attempt_id": provider_attempt_id,
            "provider_run_id": provider_run_id,
            "provider_request_id": provider_request_id,
            "provider_semantic_id": provider_semantic_id,
            "provider_artifact_digest": provider_artifact_digest,
            "provider_execution_identity_digest": provider_execution_identity_digest,
            "runner_outcome": runner_outcome,
            "observed_at_unix_ms": observed_at_unix_ms,
        });
        let evidence_id = CanonicalDocument::from_serializable(&basis)?
            .digest()
            .to_owned();
        let evidence = Self {
            schema: PROVIDER_ACTIVITY_EVIDENCE_SCHEMA_V1.into(),
            evidence_id,
            acquisition_id: acquisition.acquisition_id.clone(),
            enrollment_id: acquisition.enrollment_id.clone(),
            slot_id: acquisition.slot.slot_id.clone(),
            coordination_domain_id: acquisition.coordination_domain_id.clone(),
            fencing_epoch,
            attempt_number,
            claim,
            producer_schema: LOCAL_STDIO_PROCESS_GROUP_SUPERVISION_V1.into(),
            provider_attempt_id,
            provider_run_id,
            provider_request_id,
            provider_semantic_id,
            provider_artifact_digest,
            provider_execution_identity_digest,
            runner_outcome,
            observed_at_unix_ms,
        };
        evidence.validate_identity()?;
        Ok(evidence)
    }

    fn validate_identity(&self) -> Result<(), StoreError> {
        for (name, value) in [
            ("provider semantic identity", &self.provider_semantic_id),
            ("provider artifact digest", &self.provider_artifact_digest),
            (
                "provider execution identity digest",
                &self.provider_execution_identity_digest,
            ),
        ] {
            Sha256Digest::parse(value.clone())
                .map_err(|error| StoreError::Invariant(format!("{name} is invalid: {error}")))?;
        }
        if self.schema != PROVIDER_ACTIVITY_EVIDENCE_SCHEMA_V1
            || self.producer_schema != LOCAL_STDIO_PROCESS_GROUP_SUPERVISION_V1
            || self.fencing_epoch == 0
            || self.attempt_number == 0
            || self.observed_at_unix_ms < 0
            || self.provider_attempt_id.is_empty()
            || self.provider_run_id.is_empty()
            || self.provider_request_id.is_empty()
            || self.runner_outcome.is_empty()
        {
            return Err(StoreError::Invariant(
                "provider-activity evidence has invalid bounded fields".into(),
            ));
        }
        let basis = serde_json::json!({
            "schema": self.schema,
            "acquisition_id": self.acquisition_id,
            "enrollment_id": self.enrollment_id,
            "slot_id": self.slot_id,
            "coordination_domain_id": self.coordination_domain_id,
            "fencing_epoch": self.fencing_epoch,
            "attempt_number": self.attempt_number,
            "claim": self.claim,
            "producer_schema": self.producer_schema,
            "provider_attempt_id": self.provider_attempt_id,
            "provider_run_id": self.provider_run_id,
            "provider_request_id": self.provider_request_id,
            "provider_semantic_id": self.provider_semantic_id,
            "provider_artifact_digest": self.provider_artifact_digest,
            "provider_execution_identity_digest": self.provider_execution_identity_digest,
            "runner_outcome": self.runner_outcome,
            "observed_at_unix_ms": self.observed_at_unix_ms,
        });
        let expected = CanonicalDocument::from_serializable(&basis)?
            .digest()
            .to_owned();
        if self.evidence_id != expected {
            return Err(StoreError::ReplayConflict(
                "provider-activity evidence content identity mismatch".into(),
            ));
        }
        Ok(())
    }
}

/// One exact policy/enrollment refusal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecurrenceRefusalV1 {
    pub code: String,
    pub detail: String,
}

/// Result of deterministic tick evaluation. None of these variants is a
/// diagnostic conclusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RecurrenceTickPlanV1 {
    NotDue {
        next_due_unix_ms: i64,
    },
    Noop {
        reason: String,
    },
    ClockRollback {
        highest_evaluated_slot: u64,
    },
    EnrollmentUnavailable {
        state: String,
    },
    CoordinationBlocked {
        acquisition_id: String,
        domain_id: String,
        holder_acquisition_id: String,
        holder_watcher_instance_id: String,
    },
    Backoff {
        acquisition_id: String,
        retry_not_before_unix_ms: i64,
    },
    ReconcileRequired {
        acquisition_id: String,
    },
    Ready {
        acquisition: Box<RecurrenceAcquisitionBindingV1>,
        fencing_epoch: u64,
        attempt_number: u16,
        watcher_binding: Box<WatcherCoordinationBindingV1>,
    },
}

/// Operator/read-only projection over immutable recurrence history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecurrenceStatusV1 {
    pub schema: String,
    pub enrollment: RecurrenceEnrollmentV1,
    pub active_deployment_policy_id: Option<String>,
    pub enrollment_policy_current: bool,
    pub enrollment_state: String,
    pub highest_evaluated_slot: Option<u64>,
    pub next_due_slot: u64,
    pub next_due_unix_ms: i64,
    pub acquisition_occurrences: u32,
    pub remaining_occurrences: u32,
    pub in_flight_acquisition_id: Option<String>,
    pub last_completed_acquisition_id: Option<String>,
    pub failure_streak: u16,
    pub skipped_slot_count: u64,
    pub skipped_ranges: Vec<(u64, u64)>,
    pub coordination_domain_id: String,
    pub domain_max_in_flight: u16,
    pub current_fencing_epoch: Option<u64>,
    pub holder_acquisition_id: Option<String>,
    pub holder_watcher_instance_id: Option<String>,
    pub provider_safe_next_start_unix_ms: Option<i64>,
    pub coordination_blocked: bool,
    pub coordination_blocked_reason: Option<String>,
    pub outcome_unknown_fences_domain: bool,
    pub storage_guard_max_store_bytes: u64,
    pub storage_guard_min_free_bytes: u64,
}

#[derive(Clone, Debug)]
struct DomainProjection {
    epoch: Option<u64>,
    holder_acquisition_id: Option<String>,
    holder_watcher_instance_id: Option<String>,
    fenced_unknown: bool,
    last_provider_start_unix_ms: Option<i64>,
}

impl RecurringOfficePolicyV1 {
    /// Validate protocol bounds and relational safety constraints.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), RecurrenceRefusalV1> {
        require(
            self.schema == RECURRING_OFFICE_POLICY_SCHEMA_V1,
            "wrong_schema",
            "unsupported recurring-office policy schema",
        )?;
        require(
            valid_ref(&self.deployment_profile_ref),
            "invalid_deployment_profile",
            "deployment profile reference is not a bounded identity",
        )?;
        require(
            self.min_interval_ms > 0 && self.min_interval_ms <= self.max_interval_ms,
            "invalid_interval_bounds",
            "interval bounds are empty or reversed",
        )?;
        require(
            self.min_timer_granularity_ms > 0
                && self.min_interval_ms >= self.min_timer_granularity_ms,
            "unsafe_timer_granularity",
            "minimum interval is finer than deployment scheduling granularity",
        )?;
        require(
            self.max_enrollment_lifetime_ms > 0,
            "unbounded_lifetime",
            "deployment policy must bound enrollment lifetime",
        )?;
        require(
            self.max_acquisition_occurrences > 0,
            "unbounded_occurrences",
            "deployment policy must bound acquisition occurrences",
        )?;
        require(
            !self.allowed_missed_slot_policies.is_empty(),
            "missing_missed_slot_policy",
            "deployment policy permits no missed-slot behavior",
        )?;
        require(
            !self.allowed_startup_policies.is_empty(),
            "missing_startup_policy",
            "deployment policy permits no startup behavior",
        )?;
        require(
            self.max_pre_provider_attempts > 0,
            "invalid_retry_budget",
            "deployment policy must permit a finite positive attempt count",
        )?;
        require(
            self.min_pre_provider_backoff_ms <= self.max_pre_provider_backoff_ms,
            "invalid_backoff_bounds",
            "backoff bounds are reversed",
        )?;
        require(
            self.max_consecutive_failure_threshold > 0,
            "invalid_failure_threshold",
            "failure threshold must be finite and positive",
        )?;
        require(
            self.max_in_flight_per_watcher == 1,
            "unsupported_watcher_concurrency",
            "V1 protocol invariant permits exactly one in-flight acquisition per watcher",
        )?;
        require(
            self.provider_timeout_ceiling_ms > 0,
            "invalid_provider_timeout",
            "provider timeout ceiling must be positive",
        )?;
        require(
            self.max_store_bytes > 0 && self.min_free_bytes > 0,
            "missing_storage_guard",
            "deployment policy must configure both store-size and free-space guards",
        )?;
        require(
            self.allowed_acquisition_reasons == BTreeSet::from([RECURRENCE_REASON_V1.to_owned()]),
            "unsupported_acquisition_reason",
            "V1 permits only diagnostic_recurrence",
        )?;

        let mut domains = BTreeMap::new();
        for domain in &self.coordination_domains {
            require(
                valid_domain(&domain.domain_id),
                "invalid_coordination_domain",
                "coordination domain is not a bounded deployment identity",
            )?;
            require(
                domain.max_in_flight == 1,
                "unsupported_domain_concurrency",
                "V1 durable fencing supports exactly one in-flight acquisition per domain",
            )?;
            require(
                domains.insert(domain.domain_id.clone(), domain).is_none(),
                "duplicate_coordination_domain",
                "coordination domain appears more than once",
            )?;
        }
        require(
            !domains.is_empty(),
            "missing_coordination_domain",
            "deployment policy has no coordination domains",
        )?;
        let mut watchers = BTreeSet::new();
        for binding in &self.watcher_bindings {
            validate_digest("watcher semantic digest", &binding.watcher_semantic_digest)?;
            validate_digest(
                "expected Linode instance digest",
                &binding.expected_instance_id_sha256,
            )?;
            validate_digest("origin helper digest", &binding.origin_helper_sha256)?;
            require(
                valid_ref(&binding.watcher_instance_id),
                "invalid_watcher",
                "watcher instance is not a bounded identity",
            )?;
            require(
                binding.origin_profile == LINODE_ORIGIN_PROFILE_V1,
                "unsupported_origin_profile",
                "V1 recurrence supports only linode_instance_metadata_v1",
            )?;
            require(
                binding.origin_helper_issuer == LINODE_ORIGIN_HELPER_ISSUER_V1,
                "unsupported_origin_issuer",
                "V1 recurrence supports only the closed Linode metadata helper issuer",
            )?;
            require(
                binding.origin_helper_path.starts_with('/'),
                "relative_origin_helper",
                "origin helper path must be absolute",
            )?;
            require(
                binding.origin_helper_public_key_path.starts_with('/'),
                "relative_origin_key",
                "origin helper public-key path must be absolute",
            )?;
            require(
                valid_ref(&binding.origin_helper_account)
                    && valid_ref(&binding.origin_helper_issuer)
                    && valid_ref(&binding.origin_helper_key_id),
                "invalid_origin_identity",
                "origin helper account/issuer/key identity is invalid",
            )?;
            require(
                domains.contains_key(&binding.coordination_domain_id),
                "unknown_coordination_domain",
                "watcher maps to an undeclared coordination domain",
            )?;
            require(
                watchers.insert(binding.watcher_instance_id.clone()),
                "duplicate_watcher_mapping",
                "watcher appears in more than one coordination mapping",
            )?;
        }
        require(
            !watchers.is_empty(),
            "missing_watcher_mapping",
            "deployment policy maps no watchers",
        )?;
        Ok(())
    }

    /// Content-derived deployment profile identity.
    pub fn policy_id(&self) -> Result<String, StoreError> {
        self.validate().map_err(refusal_as_store)?;
        Ok(CanonicalDocument::from_serializable(self)?
            .digest()
            .to_owned())
    }

    #[must_use]
    pub fn watcher_binding(&self, instance_id: &str) -> Option<&WatcherCoordinationBindingV1> {
        self.watcher_bindings
            .iter()
            .find(|binding| binding.watcher_instance_id == instance_id)
    }

    #[must_use]
    pub fn domain(&self, domain_id: &str) -> Option<&CoordinationDomainPolicyV1> {
        self.coordination_domains
            .iter()
            .find(|domain| domain.domain_id == domain_id)
    }
}

impl RecurrenceEnrollmentV1 {
    /// Construct and validate one immutable finite enrollment.
    #[allow(clippy::too_many_lines)]
    pub fn new(
        spec: RecurrenceEnrollmentSpecV1,
        policy: &RecurringOfficePolicyV1,
        watcher_semantic_digest: &str,
        watcher_provider_timeout_ms: u64,
        created_at_unix_ms: i64,
    ) -> Result<Self, RecurrenceRefusalV1> {
        policy.validate()?;
        require(
            spec.schema == RECURRENCE_ENROLLMENT_SPEC_SCHEMA_V1,
            "wrong_enrollment_schema",
            "unsupported enrollment spec schema",
        )?;
        require(
            valid_ref(&spec.operator_occurrence_id),
            "invalid_operator_occurrence",
            "operator occurrence is not a bounded identity",
        )?;
        require(
            spec.policy_id
                == policy
                    .policy_id()
                    .map_err(|error| refusal("policy_identity_invalid", error.to_string()))?,
            "wrong_policy",
            "enrollment names different deployment policy bytes",
        )?;
        validate_digest("watcher semantic digest", watcher_semantic_digest)?;
        let binding = policy
            .watcher_binding(&spec.watcher_instance_id)
            .ok_or_else(|| {
                refusal(
                    "watcher_not_mapped",
                    "deployment policy does not map this watcher",
                )
            })?;
        require(
            binding.watcher_semantic_digest == watcher_semantic_digest,
            "watcher_semantics_changed",
            "watcher semantic digest differs from deployment mapping",
        )?;
        require(
            spec.interval_ms >= policy.min_interval_ms,
            "interval_below_deployment_minimum",
            "enrollment interval is below deployment minimum",
        )?;
        require(
            spec.interval_ms <= policy.max_interval_ms,
            "interval_above_deployment_maximum",
            "enrollment interval is above deployment maximum",
        )?;
        require(
            spec.interval_ms >= policy.min_timer_granularity_ms,
            "interval_below_scheduling_granularity",
            "enrollment interval is finer than deployable scheduling precision",
        )?;
        require(
            spec.max_acquisition_occurrences > 0
                && spec.max_acquisition_occurrences <= policy.max_acquisition_occurrences,
            "occurrence_bound_exceeds_policy",
            "enrollment occurrence bound is zero or exceeds deployment maximum",
        )?;
        require(
            policy
                .allowed_missed_slot_policies
                .contains(&spec.missed_slot_policy),
            "missed_slot_policy_disallowed",
            "deployment policy disallows selected missed-slot behavior",
        )?;
        require(
            policy
                .allowed_startup_policies
                .contains(&spec.startup_policy),
            "startup_policy_disallowed",
            "deployment policy disallows selected startup behavior",
        )?;
        require(
            spec.max_pre_provider_attempts > 0
                && spec.max_pre_provider_attempts <= policy.max_pre_provider_attempts,
            "retry_budget_exceeds_policy",
            "enrollment retry budget is zero or exceeds deployment maximum",
        )?;
        require(
            spec.pre_provider_backoff_ms >= policy.min_pre_provider_backoff_ms
                && spec.pre_provider_backoff_ms <= policy.max_pre_provider_backoff_ms,
            "backoff_outside_policy",
            "enrollment backoff is outside deployment bounds",
        )?;
        require(
            spec.failure_pause_threshold > 0
                && spec.failure_pause_threshold <= policy.max_consecutive_failure_threshold,
            "failure_threshold_exceeds_policy",
            "enrollment failure threshold is zero or exceeds deployment maximum",
        )?;
        let domain = policy
            .domain(&binding.coordination_domain_id)
            .ok_or_else(|| {
                refusal(
                    "unknown_coordination_domain",
                    "mapped coordination domain is absent",
                )
            })?;
        require(
            spec.requested_domain_concurrency > 0
                && spec.requested_domain_concurrency <= domain.max_in_flight,
            "domain_concurrency_exceeds_policy",
            "requested concurrency exceeds coordination-domain maximum",
        )?;
        require(
            spec.requested_domain_concurrency == 1,
            "unsupported_domain_concurrency",
            "V1 protocol invariant permits one in-flight acquisition per domain",
        )?;
        require(
            watcher_provider_timeout_ms <= policy.provider_timeout_ceiling_ms,
            "provider_timeout_exceeds_policy",
            "watcher provider timeout exceeds deployment ceiling",
        )?;
        require(
            spec.interval_ms >= domain.min_provider_start_spacing_ms,
            "interval_below_provider_safe_spacing",
            "interval is shorter than coordination-domain provider-safe spacing",
        )?;
        require(
            spec.acquisition_reason == RECURRENCE_REASON_V1
                && policy
                    .allowed_acquisition_reasons
                    .contains(&spec.acquisition_reason),
            "acquisition_reason_disallowed",
            "enrollment requests an unsupported acquisition reason",
        )?;
        require(
            spec.anchor_unix_ms >= 0 && created_at_unix_ms >= 0,
            "negative_time",
            "anchor/creation time must be nonnegative Unix milliseconds",
        )?;
        require(
            spec.expires_at_unix_ms > created_at_unix_ms
                && spec.expires_at_unix_ms > spec.anchor_unix_ms,
            "invalid_expiry",
            "enrollment expiry must be after anchor and creation",
        )?;
        let lifetime = u64::try_from(spec.expires_at_unix_ms - created_at_unix_ms)
            .map_err(|_| refusal("lifetime_overflow", "enrollment lifetime overflowed"))?;
        require(
            lifetime <= policy.max_enrollment_lifetime_ms,
            "lifetime_exceeds_policy",
            "enrollment lifetime exceeds deployment maximum",
        )?;
        require(
            spec.pre_provider_backoff_ms < lifetime,
            "backoff_exceeds_enrollment_window",
            "pre-provider backoff is not smaller than enrollment lifetime",
        )?;
        let current_slot =
            slot_index_at(spec.anchor_unix_ms, spec.interval_ms, created_at_unix_ms).unwrap_or(0);
        let first_eligible_slot = match spec.startup_policy {
            StartupPolicyV1::EvaluateCurrentSlot => current_slot,
            StartupPolicyV1::WaitForNextSlot => current_slot
                .checked_add(1)
                .ok_or_else(|| refusal("slot_overflow", "first eligible slot overflowed"))?,
        };
        let preimage = CanonicalDocument::from_serializable(&serde_json::json!({
            "schema": RECURRENCE_ENROLLMENT_SCHEMA_V1,
            "spec": &spec,
            "watcher_semantic_digest": watcher_semantic_digest,
            "coordination_domain_id": binding.coordination_domain_id,
            "first_eligible_slot": first_eligible_slot,
            "created_at_unix_ms": created_at_unix_ms,
        }))
        .map_err(|error| refusal("canonicalization_failed", error.to_string()))?;
        Ok(Self {
            schema: RECURRENCE_ENROLLMENT_SCHEMA_V1.to_owned(),
            enrollment_id: preimage.digest().to_owned(),
            spec,
            watcher_semantic_digest: watcher_semantic_digest.to_owned(),
            coordination_domain_id: binding.coordination_domain_id.clone(),
            first_eligible_slot,
            created_at_unix_ms,
        })
    }

    pub fn slot(&self, slot_index: u64) -> Result<RecurrenceSlotV1, StoreError> {
        let offset = self
            .spec
            .interval_ms
            .checked_mul(slot_index)
            .ok_or_else(|| StoreError::Invariant("recurrence slot offset overflowed".into()))?;
        let offset = i64::try_from(offset)
            .map_err(|_| StoreError::Invariant("recurrence slot offset exceeds i64".into()))?;
        let scheduled_for_unix_ms = self
            .spec
            .anchor_unix_ms
            .checked_add(offset)
            .ok_or_else(|| StoreError::Invariant("recurrence slot time overflowed".into()))?;
        let preimage = CanonicalDocument::from_serializable(&serde_json::json!({
            "schema": RECURRENCE_SLOT_SCHEMA_V1,
            "enrollment_id": self.enrollment_id,
            "slot_index": slot_index,
            "scheduled_for_unix_ms": scheduled_for_unix_ms,
        }))?;
        Ok(RecurrenceSlotV1 {
            schema: RECURRENCE_SLOT_SCHEMA_V1.to_owned(),
            slot_id: preimage.digest().to_owned(),
            enrollment_id: self.enrollment_id.clone(),
            slot_index,
            scheduled_for_unix_ms,
        })
    }
}

/// Deterministic integer slot calculation. The anchor is inclusive.
#[must_use]
pub fn slot_index_at(anchor_unix_ms: i64, interval_ms: u64, now_unix_ms: i64) -> Option<u64> {
    if anchor_unix_ms < 0 || now_unix_ms < anchor_unix_ms || interval_ms == 0 {
        return None;
    }
    u64::try_from(now_unix_ms - anchor_unix_ms)
        .ok()
        .map(|elapsed| elapsed / interval_ms)
}

fn valid_ref(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
        })
}

fn valid_domain(value: &str) -> bool {
    valid_ref(value)
}

fn validate_digest(name: &str, value: &str) -> Result<(), RecurrenceRefusalV1> {
    Sha256Digest::parse(value.to_owned())
        .map(|_| ())
        .map_err(|error| refusal("invalid_digest", format!("{name}: {error}")))
}

fn require(condition: bool, code: &str, detail: &str) -> Result<(), RecurrenceRefusalV1> {
    if condition {
        Ok(())
    } else {
        Err(refusal(code, detail))
    }
}

fn refusal(code: &str, detail: impl Into<String>) -> RecurrenceRefusalV1 {
    RecurrenceRefusalV1 {
        code: code.to_owned(),
        detail: detail.into(),
    }
}

fn refusal_as_store(value: RecurrenceRefusalV1) -> StoreError {
    let RecurrenceRefusalV1 { code, detail } = value;
    StoreError::Invariant(format!("recurrence policy refused [{code}]: {detail}"))
}

fn canonical<T: Serialize>(value: &T) -> Result<CanonicalDocument, StoreError> {
    CanonicalDocument::from_serializable(value)
}

fn row_document(bytes: Vec<u8>, what: &str) -> Result<CanonicalDocument, StoreError> {
    CanonicalDocument::from_canonical_bytes(bytes)
        .map_err(|error| StoreError::Integrity(format!("{what} is not canonical JSON: {error}")))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8], what: &str) -> Result<T, StoreError> {
    serde_json::from_slice(bytes)
        .map_err(|error| StoreError::Integrity(format!("{what} cannot decode: {error}")))
}

#[allow(clippy::needless_pass_by_value)]
fn event_document(
    kind: &str,
    occurred_at_unix_ms: i64,
    fields: Value,
) -> Result<CanonicalDocument, StoreError> {
    canonical(&serde_json::json!({
        "schema": RECURRENCE_EVENT_SCHEMA_V1,
        "event_kind": kind,
        "occurred_at_unix_ms": occurred_at_unix_ms,
        "fields": fields,
    }))
}

fn acquisition_id_for_slot(slot: &RecurrenceSlotV1) -> String {
    format!("recurrence:{}", slot.slot_id.trim_start_matches("sha256:"))
}

impl Store {
    /// Register exact deployment-policy bytes. Exact replay converges.
    pub fn register_recurring_office_policy(
        &mut self,
        policy: &RecurringOfficePolicyV1,
        registered_at_unix_ms: i64,
        operator_identity: &CanonicalDocument,
    ) -> Result<String, StoreError> {
        policy.validate().map_err(refusal_as_store)?;
        if registered_at_unix_ms < 0 {
            return Err(StoreError::Invariant(
                "negative policy registration time".into(),
            ));
        }
        let policy_doc = canonical(policy)?;
        let policy_id = policy_doc.digest().to_owned();
        let transaction = self.immediate_transaction()?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT policy_json FROM recurring_office_policies WHERE policy_id = ?1",
                [&policy_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(bytes) = existing {
            if bytes == policy_doc.as_bytes() {
                return Ok(policy_id);
            }
            return Err(StoreError::ReplayConflict(
                "recurring-office policy identity was reused for different bytes".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO recurring_office_policies (
                policy_id, schema_id, policy_json, policy_digest,
                registered_at_unix_ms, operator_identity_json
             ) VALUES (?1, ?2, ?3, ?1, ?4, ?5)",
            params![
                policy_id,
                RECURRING_OFFICE_POLICY_SCHEMA_V1,
                policy_doc.as_bytes(),
                registered_at_unix_ms,
                operator_identity.as_bytes()
            ],
        )?;
        transaction.commit()?;
        Ok(policy_id)
    }

    /// Append an explicit activation. Policy registration alone grants no slot.
    pub fn activate_recurring_office_policy(
        &mut self,
        policy_id: &str,
        operation_id: &str,
        occurred_at_unix_ms: i64,
        operator_identity: &CanonicalDocument,
    ) -> Result<String, StoreError> {
        validate_bounded(operation_id, "policy activation operation")?;
        let event = event_document(
            "activated",
            occurred_at_unix_ms,
            serde_json::json!({"policy_id": policy_id, "operation_id": operation_id}),
        )?;
        let event_id = event.digest().to_owned();
        let transaction = self.immediate_transaction()?;
        let present: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM recurring_office_policies WHERE policy_id = ?1)",
            [policy_id],
            |row| row.get(0),
        )?;
        if !present {
            return Err(StoreError::Invariant(
                "cannot activate unknown recurring-office policy".into(),
            ));
        }
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT event_json FROM recurring_office_policy_events WHERE event_id = ?1",
                [&event_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(bytes) = existing {
            if bytes == event.as_bytes() {
                return Ok(event_id);
            }
            return Err(StoreError::ReplayConflict(
                "policy activation event identity conflict".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO recurring_office_policy_events (
                event_id, policy_id, event_kind, event_json, event_digest,
                occurred_at_unix_ms, operator_identity_json
             ) VALUES (?1, ?2, 'activated', ?3, ?1, ?4, ?5)",
            params![
                event_id,
                policy_id,
                event.as_bytes(),
                occurred_at_unix_ms,
                operator_identity.as_bytes()
            ],
        )?;
        transaction.commit()?;
        Ok(event_id)
    }

    pub fn active_recurring_office_policy_id(&self) -> Result<Option<String>, StoreError> {
        self.connection.query_row(
            "SELECT policy_id FROM recurring_office_policy_events ORDER BY event_sequence DESC LIMIT 1",
            [], |row| row.get(0),
        ).optional().map_err(StoreError::from)
    }

    pub fn recurring_office_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<RecurringOfficePolicyV1>, StoreError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT policy_json FROM recurring_office_policies WHERE policy_id = ?1",
                [policy_id],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let doc = row_document(bytes, "recurring-office policy")?;
                if doc.digest() != policy_id {
                    return Err(StoreError::Integrity(
                        "recurring-office policy digest mismatch".into(),
                    ));
                }
                let policy: RecurringOfficePolicyV1 =
                    decode(doc.as_bytes(), "recurring-office policy")?;
                policy.validate().map_err(refusal_as_store)?;
                Ok(policy)
            })
            .transpose()
    }

    /// Persist one finite immutable enrollment and its creation event.
    #[allow(clippy::too_many_lines)]
    pub fn create_recurrence_enrollment(
        &mut self,
        enrollment: &RecurrenceEnrollmentV1,
        operator_identity: &CanonicalDocument,
    ) -> Result<String, StoreError> {
        if self.active_recurring_office_policy_id()?.as_deref() != Some(&enrollment.spec.policy_id)
        {
            return Err(StoreError::Invariant(
                "enrollment policy is not the active deployment policy".into(),
            ));
        }
        let policy = self
            .recurring_office_policy(&enrollment.spec.policy_id)?
            .ok_or_else(|| StoreError::Invariant("enrollment policy is absent".into()))?;
        let binding = policy
            .watcher_binding(&enrollment.spec.watcher_instance_id)
            .ok_or_else(|| StoreError::Invariant("enrollment watcher is not mapped".into()))?;
        if binding.watcher_semantic_digest != enrollment.watcher_semantic_digest
            || binding.coordination_domain_id != enrollment.coordination_domain_id
        {
            return Err(StoreError::Invariant(
                "enrollment materialization differs from deployment mapping".into(),
            ));
        }
        let enrollment_doc = canonical(enrollment)?;
        let transaction = self.immediate_transaction()?;
        let prior_operation: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT r.enrollment_json
                 FROM recurrence_enrollment_events AS e
                 JOIN recurrence_enrollments AS r ON r.enrollment_id = e.enrollment_id
                 WHERE e.event_kind = 'enrolled' AND e.operation_id = ?1",
                [&enrollment.spec.operator_occurrence_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(bytes) = prior_operation {
            let prior: RecurrenceEnrollmentV1 = decode(&bytes, "prior recurrence enrollment")?;
            if prior.spec == enrollment.spec
                && prior.watcher_semantic_digest == enrollment.watcher_semantic_digest
                && prior.coordination_domain_id == enrollment.coordination_domain_id
            {
                return Ok(prior.enrollment_id);
            }
            return Err(StoreError::ReplayConflict(
                "recurrence enrollment operation was reused for different semantics".into(),
            ));
        }
        let event = event_document(
            "enrolled",
            enrollment.created_at_unix_ms,
            serde_json::json!({"enrollment_id": enrollment.enrollment_id, "operator_occurrence_id": enrollment.spec.operator_occurrence_id}),
        )?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT enrollment_json FROM recurrence_enrollments WHERE enrollment_id = ?1",
                [&enrollment.enrollment_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(bytes) = existing {
            if bytes == enrollment_doc.as_bytes() {
                return Ok(enrollment.enrollment_id.clone());
            }
            return Err(StoreError::ReplayConflict(
                "recurrence enrollment identity was reused for different bytes".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO recurrence_enrollments (
                enrollment_id, schema_id, policy_id, watcher_instance_id,
                watcher_semantic_digest, coordination_domain_id, anchor_unix_ms,
                interval_ms, first_eligible_slot, max_acquisition_occurrences,
                expires_at_unix_ms, missed_slot_policy, startup_policy,
                max_pre_provider_attempts, pre_provider_backoff_ms,
                failure_pause_threshold, requested_domain_concurrency,
                enrollment_json, enrollment_digest, created_at_unix_ms,
                operator_identity_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?1, ?19, ?20)",
            params![
                enrollment.enrollment_id,
                RECURRENCE_ENROLLMENT_SCHEMA_V1,
                enrollment.spec.policy_id,
                enrollment.spec.watcher_instance_id,
                enrollment.watcher_semantic_digest,
                enrollment.coordination_domain_id,
                enrollment.spec.anchor_unix_ms,
                enrollment.spec.interval_ms,
                enrollment.first_eligible_slot,
                enrollment.spec.max_acquisition_occurrences,
                enrollment.spec.expires_at_unix_ms,
                enum_json_name(&enrollment.spec.missed_slot_policy)?,
                enum_json_name(&enrollment.spec.startup_policy)?,
                enrollment.spec.max_pre_provider_attempts,
                enrollment.spec.pre_provider_backoff_ms,
                enrollment.spec.failure_pause_threshold,
                enrollment.spec.requested_domain_concurrency,
                enrollment_doc.as_bytes(),
                enrollment.created_at_unix_ms,
                operator_identity.as_bytes(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO recurrence_enrollment_events (
                event_id, enrollment_id, event_kind, operation_id, event_json,
                event_digest, occurred_at_unix_ms, operator_identity_json
             ) VALUES (?1, ?2, 'enrolled', ?3, ?4, ?1, ?5, ?6)",
            params![
                event.digest(),
                enrollment.enrollment_id,
                enrollment.spec.operator_occurrence_id,
                event.as_bytes(),
                enrollment.created_at_unix_ms,
                operator_identity.as_bytes()
            ],
        )?;
        transaction.commit()?;
        Ok(enrollment.enrollment_id.clone())
    }

    pub fn recurrence_enrollment(
        &self,
        enrollment_id: &str,
    ) -> Result<Option<RecurrenceEnrollmentV1>, StoreError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT enrollment_json FROM recurrence_enrollments WHERE enrollment_id = ?1",
                [enrollment_id],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| decode(&bytes, "recurrence enrollment"))
            .transpose()
    }

    /// Append an exact operator lifecycle event. Resume is refused while an
    /// outcome-unknown acquisition fences the enrollment/domain.
    pub fn append_recurrence_enrollment_operator_event(
        &mut self,
        enrollment_id: &str,
        event_kind: &str,
        operation_id: &str,
        occurred_at_unix_ms: i64,
        reason: &str,
        operator_identity: &CanonicalDocument,
    ) -> Result<String, StoreError> {
        if !matches!(
            event_kind,
            "paused_operator" | "resumed_operator" | "revoked_operator"
        ) {
            return Err(StoreError::Invariant(
                "unsupported recurrence operator event".into(),
            ));
        }
        validate_bounded(operation_id, "recurrence operator operation")?;
        let state = self.recurrence_enrollment_state(enrollment_id)?;
        match event_kind {
            "paused_operator" if state != "active" => {
                return Err(StoreError::Invariant(format!(
                    "cannot pause recurrence from state {state}"
                )));
            }
            "resumed_operator"
                if !matches!(
                    state.as_str(),
                    "paused_operator" | "paused_failure_threshold" | "paused_outcome_unknown"
                ) =>
            {
                return Err(StoreError::Invariant(format!(
                    "cannot resume recurrence from state {state}"
                )));
            }
            "revoked_operator" if state == "revoked" => {
                return Err(StoreError::Invariant(
                    "recurrence enrollment is already revoked".into(),
                ));
            }
            _ => {}
        }
        if event_kind == "resumed_operator" && self.enrollment_has_outcome_unknown(enrollment_id)? {
            return Err(StoreError::Invariant(
                "outcome-unknown recurrence cannot be resumed before exact reconciliation".into(),
            ));
        }
        let event = event_document(
            event_kind,
            occurred_at_unix_ms,
            serde_json::json!({"enrollment_id": enrollment_id, "operation_id": operation_id, "reason": reason}),
        )?;
        let transaction = self.immediate_transaction()?;
        let existing: Option<Vec<u8>> = transaction.query_row(
            "SELECT event_json FROM recurrence_enrollment_events WHERE enrollment_id = ?1 AND operation_id = ?2",
            params![enrollment_id, operation_id], |row| row.get(0),
        ).optional()?;
        if let Some(bytes) = existing {
            if bytes == event.as_bytes() {
                return Ok(event.digest().to_owned());
            }
            return Err(StoreError::ReplayConflict(
                "recurrence operator operation was substituted".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO recurrence_enrollment_events (
                event_id, enrollment_id, event_kind, operation_id, event_json,
                event_digest, occurred_at_unix_ms, operator_identity_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?1, ?6, ?7)",
            params![
                event.digest(),
                enrollment_id,
                event_kind,
                operation_id,
                event.as_bytes(),
                occurred_at_unix_ms,
                operator_identity.as_bytes()
            ],
        )?;
        transaction.commit()?;
        Ok(event.digest().to_owned())
    }

    /// Evaluate one deterministic tick and, when permitted, persist exactly one
    /// slot/acquisition/domain claim before returning provider authority.
    #[allow(clippy::too_many_lines)]
    pub fn plan_recurrence_tick(
        &mut self,
        enrollment_id: &str,
        watcher_semantic_digest: &str,
        now_unix_ms: i64,
    ) -> Result<RecurrenceTickPlanV1, StoreError> {
        let enrollment = self
            .recurrence_enrollment(enrollment_id)?
            .ok_or_else(|| StoreError::Invariant("unknown recurrence enrollment".into()))?;
        if enrollment.watcher_semantic_digest != watcher_semantic_digest {
            return Err(StoreError::Invariant(
                "watcher semantic substitution refused for recurrence tick".into(),
            ));
        }
        let policy = self
            .recurring_office_policy(&enrollment.spec.policy_id)?
            .ok_or_else(|| {
                StoreError::Integrity("recurrence enrollment policy disappeared".into())
            })?;
        let watcher_binding = policy
            .watcher_binding(&enrollment.spec.watcher_instance_id)
            .ok_or_else(|| StoreError::Integrity("recurrence watcher mapping disappeared".into()))?
            .clone();
        let domain_policy = policy
            .domain(&enrollment.coordination_domain_id)
            .ok_or_else(|| {
                StoreError::Integrity("recurrence coordination-domain policy disappeared".into())
            })?
            .clone();

        if let Some(pending) =
            self.pending_recurrence_acquisition(&enrollment.spec.watcher_instance_id)?
        {
            return self.plan_existing_acquisition(
                &enrollment,
                &watcher_binding,
                &domain_policy,
                pending,
                now_unix_ms,
            );
        }
        let state = self.recurrence_enrollment_state(enrollment_id)?;
        if state != "active" {
            return Ok(RecurrenceTickPlanV1::EnrollmentUnavailable { state });
        }
        if self.active_recurring_office_policy_id()?.as_deref() != Some(&enrollment.spec.policy_id)
        {
            return Ok(RecurrenceTickPlanV1::EnrollmentUnavailable {
                state: "deployment_policy_superseded".into(),
            });
        }
        if now_unix_ms < enrollment.spec.anchor_unix_ms {
            return Ok(RecurrenceTickPlanV1::NotDue {
                next_due_unix_ms: enrollment.spec.anchor_unix_ms,
            });
        }
        if now_unix_ms >= enrollment.spec.expires_at_unix_ms {
            self.append_automatic_enrollment_event(
                &enrollment,
                "expired",
                now_unix_ms,
                "exclusive enrollment expiry reached",
            )?;
            return Ok(RecurrenceTickPlanV1::EnrollmentUnavailable {
                state: "expired".into(),
            });
        }
        let current_slot = slot_index_at(
            enrollment.spec.anchor_unix_ms,
            enrollment.spec.interval_ms,
            now_unix_ms,
        )
        .ok_or_else(|| StoreError::Invariant("due recurrence slot cannot be derived".into()))?;
        if current_slot < enrollment.first_eligible_slot {
            return Ok(RecurrenceTickPlanV1::NotDue {
                next_due_unix_ms: enrollment
                    .slot(enrollment.first_eligible_slot)?
                    .scheduled_for_unix_ms,
            });
        }
        let highest = self.highest_evaluated_slot(enrollment_id)?;
        if highest.is_some_and(|value| current_slot < value) {
            self.append_slot_event(
                &enrollment.slot(current_slot)?,
                "clock_rollback",
                None,
                now_unix_ms,
                serde_json::json!({"highest_evaluated_slot": highest}),
            )?;
            return Ok(RecurrenceTickPlanV1::ClockRollback {
                highest_evaluated_slot: highest.unwrap_or(0),
            });
        }
        if highest == Some(current_slot) {
            return Ok(RecurrenceTickPlanV1::Noop {
                reason: "slot_already_evaluated".into(),
            });
        }
        let expected_next = highest.map_or(enrollment.first_eligible_slot, |value| {
            value.saturating_add(1)
        });
        let gap = current_slot.saturating_sub(expected_next);
        if gap > 0 {
            let skipped_to = match enrollment.spec.missed_slot_policy {
                MissedSlotPolicyV1::Skip => current_slot,
                MissedSlotPolicyV1::LatestOnly => current_slot - 1,
            };
            self.append_slot_event(&enrollment.slot(current_slot)?, "skipped", None, now_unix_ms, serde_json::json!({"skipped_from": expected_next, "skipped_to": skipped_to, "policy": enum_json_name(&enrollment.spec.missed_slot_policy)?}))?;
            if enrollment.spec.missed_slot_policy == MissedSlotPolicyV1::Skip {
                return Ok(RecurrenceTickPlanV1::Noop {
                    reason: "missed_slots_skipped".into(),
                });
            }
        }
        let occurrence_count = self.recurrence_occurrence_count(enrollment_id)?;
        if occurrence_count >= enrollment.spec.max_acquisition_occurrences {
            self.append_automatic_enrollment_event(
                &enrollment,
                "exhausted",
                now_unix_ms,
                "finite occurrence bound reached",
            )?;
            return Ok(RecurrenceTickPlanV1::EnrollmentUnavailable {
                state: "exhausted".into(),
            });
        }
        let slot = enrollment.slot(current_slot)?;
        let acquisition = self.create_recurrence_acquisition(
            &enrollment,
            &policy,
            &domain_policy,
            &slot,
            now_unix_ms,
        )?;
        self.claim_or_defer(
            &enrollment,
            &watcher_binding,
            &domain_policy,
            acquisition,
            now_unix_ms,
            1,
        )
    }

    fn plan_existing_acquisition(
        &mut self,
        enrollment: &RecurrenceEnrollmentV1,
        watcher_binding: &WatcherCoordinationBindingV1,
        domain_policy: &CoordinationDomainPolicyV1,
        pending: RecurrenceAcquisitionBindingV1,
        now_unix_ms: i64,
    ) -> Result<RecurrenceTickPlanV1, StoreError> {
        if pending.enrollment_id != enrollment.enrollment_id {
            return Ok(RecurrenceTickPlanV1::CoordinationBlocked {
                acquisition_id: pending.acquisition_id.clone(),
                domain_id: pending.coordination_domain_id.clone(),
                holder_acquisition_id: pending.acquisition_id,
                holder_watcher_instance_id: pending.watcher_instance_id,
            });
        }
        let last = self
            .recurrence_acquisition_state(&pending.acquisition_id)?
            .ok_or_else(|| {
                StoreError::Integrity("recurrence acquisition lacks creation event".into())
            })?;
        match last.event_kind.as_str() {
            "provider_invocation_started" | "outcome_unknown" => {
                Ok(RecurrenceTickPlanV1::ReconcileRequired {
                    acquisition_id: pending.acquisition_id,
                })
            }
            "created" => self.claim_or_defer(
                enrollment,
                watcher_binding,
                domain_policy,
                pending,
                now_unix_ms,
                1,
            ),
            "pre_provider_failed" => {
                let next_attempt = u16::try_from(last.attempt_number)
                    .map_err(|_| {
                        StoreError::Integrity("recurrence attempt number overflowed".into())
                    })?
                    .saturating_add(1);
                if next_attempt > enrollment.spec.max_pre_provider_attempts {
                    self.finish_recurrence_acquisition(
                        &pending.acquisition_id,
                        "pre_provider_exhausted",
                        last.attempt_number,
                        last.fencing_epoch,
                        now_unix_ms,
                        serde_json::json!({"reason": "pre_provider_attempt_budget_exhausted"}),
                    )?;
                    return Ok(RecurrenceTickPlanV1::Noop {
                        reason: "pre_provider_attempt_budget_exhausted".into(),
                    });
                }
                let retry_not_before = last
                    .occurred_at_unix_ms
                    .checked_add(
                        i64::try_from(enrollment.spec.pre_provider_backoff_ms)
                            .map_err(|_| StoreError::Invariant("backoff exceeds i64".into()))?,
                    )
                    .ok_or_else(|| StoreError::Invariant("retry time overflowed".into()))?;
                if now_unix_ms < retry_not_before {
                    return Ok(RecurrenceTickPlanV1::Backoff {
                        acquisition_id: pending.acquisition_id,
                        retry_not_before_unix_ms: retry_not_before,
                    });
                }
                self.claim_or_defer(
                    enrollment,
                    watcher_binding,
                    domain_policy,
                    pending,
                    now_unix_ms,
                    next_attempt,
                )
            }
            other => Err(StoreError::Integrity(format!(
                "nonterminal recurrence query returned terminal event {other}"
            ))),
        }
    }

    fn claim_or_defer(
        &mut self,
        enrollment: &RecurrenceEnrollmentV1,
        watcher_binding: &WatcherCoordinationBindingV1,
        domain_policy: &CoordinationDomainPolicyV1,
        acquisition: RecurrenceAcquisitionBindingV1,
        now_unix_ms: i64,
        attempt_number: u16,
    ) -> Result<RecurrenceTickPlanV1, StoreError> {
        let domain = self.domain_projection(&enrollment.coordination_domain_id)?;
        if domain.fenced_unknown {
            return Ok(RecurrenceTickPlanV1::CoordinationBlocked {
                acquisition_id: acquisition.acquisition_id,
                domain_id: enrollment.coordination_domain_id.clone(),
                holder_acquisition_id: domain
                    .holder_acquisition_id
                    .unwrap_or_else(|| "unknown".into()),
                holder_watcher_instance_id: domain
                    .holder_watcher_instance_id
                    .unwrap_or_else(|| "unknown".into()),
            });
        }
        if let (Some(holder), Some(holder_watcher)) = (
            &domain.holder_acquisition_id,
            &domain.holder_watcher_instance_id,
        ) && holder != &acquisition.acquisition_id
        {
            self.append_slot_event(&acquisition.slot, "coordination_deferred", Some(&acquisition.acquisition_id), now_unix_ms, serde_json::json!({"domain_id": enrollment.coordination_domain_id, "holder_acquisition_id": holder, "holder_watcher_instance_id": holder_watcher}))?;
            return Ok(RecurrenceTickPlanV1::CoordinationBlocked {
                acquisition_id: acquisition.acquisition_id,
                domain_id: enrollment.coordination_domain_id.clone(),
                holder_acquisition_id: holder.clone(),
                holder_watcher_instance_id: holder_watcher.clone(),
            });
        }
        if let Some(last_start) = domain.last_provider_start_unix_ms {
            let safe = last_start
                .checked_add(
                    i64::try_from(domain_policy.min_provider_start_spacing_ms).map_err(|_| {
                        StoreError::Invariant("provider spacing exceeds i64".into())
                    })?,
                )
                .ok_or_else(|| {
                    StoreError::Invariant("provider safe-start time overflowed".into())
                })?;
            if now_unix_ms < safe {
                return Ok(RecurrenceTickPlanV1::Backoff {
                    acquisition_id: acquisition.acquisition_id,
                    retry_not_before_unix_ms: safe,
                });
            }
        }
        let epoch = if domain.holder_acquisition_id.as_deref() == Some(&acquisition.acquisition_id)
        {
            domain
                .epoch
                .ok_or_else(|| StoreError::Integrity("domain holder lacks fencing epoch".into()))?
        } else {
            self.append_coordination_claim(&acquisition, now_unix_ms)?
        };
        Ok(RecurrenceTickPlanV1::Ready {
            acquisition: Box::new(acquisition),
            fencing_epoch: epoch,
            attempt_number,
            watcher_binding: Box::new(watcher_binding.clone()),
        })
    }

    fn create_recurrence_acquisition(
        &mut self,
        enrollment: &RecurrenceEnrollmentV1,
        policy: &RecurringOfficePolicyV1,
        domain: &CoordinationDomainPolicyV1,
        slot: &RecurrenceSlotV1,
        created_at_unix_ms: i64,
    ) -> Result<RecurrenceAcquisitionBindingV1, StoreError> {
        let acquisition_id = acquisition_id_for_slot(slot);
        let binding = RecurrenceAcquisitionBindingV1 {
            schema: RECURRENCE_ACQUISITION_BINDING_SCHEMA_V1.to_owned(),
            acquisition_id: acquisition_id.clone(),
            enrollment_id: enrollment.enrollment_id.clone(),
            policy_id: enrollment.spec.policy_id.clone(),
            slot: slot.clone(),
            watcher_instance_id: enrollment.spec.watcher_instance_id.clone(),
            watcher_semantic_digest: enrollment.watcher_semantic_digest.clone(),
            coordination_domain_id: enrollment.coordination_domain_id.clone(),
            interval_ms: enrollment.spec.interval_ms,
            max_pre_provider_attempts: enrollment.spec.max_pre_provider_attempts,
            pre_provider_backoff_ms: enrollment.spec.pre_provider_backoff_ms,
            failure_pause_threshold: enrollment.spec.failure_pause_threshold,
            max_store_bytes: policy.max_store_bytes,
            min_free_bytes: policy.min_free_bytes,
            provider_timeout_ceiling_ms: policy.provider_timeout_ceiling_ms,
            domain_max_in_flight: domain.max_in_flight,
            min_provider_start_spacing_ms: domain.min_provider_start_spacing_ms,
            created_at_unix_ms,
        };
        let document = canonical(&binding)?;
        let event = event_document(
            "created",
            created_at_unix_ms,
            serde_json::json!({"acquisition_id": acquisition_id, "slot_id": slot.slot_id, "binding_digest": document.digest()}),
        )?;
        let transaction = self.immediate_transaction()?;
        let existing: Option<Vec<u8>> = transaction.query_row("SELECT binding_json FROM recurrence_acquisitions WHERE slot_id = ?1 OR acquisition_id = ?2", params![slot.slot_id, acquisition_id], |row| row.get(0)).optional()?;
        if let Some(bytes) = existing {
            if bytes == document.as_bytes() {
                return Ok(binding);
            }
            return Err(StoreError::ReplayConflict(
                "recurrence slot/acquisition identity was substituted".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO recurrence_acquisitions (
                acquisition_id, schema_id, enrollment_id, policy_id, slot_id,
                slot_index, scheduled_for_unix_ms, watcher_instance_id,
                watcher_semantic_digest, coordination_domain_id, binding_json,
                binding_digest, created_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                acquisition_id,
                RECURRENCE_ACQUISITION_BINDING_SCHEMA_V1,
                enrollment.enrollment_id,
                enrollment.spec.policy_id,
                slot.slot_id,
                slot.slot_index,
                slot.scheduled_for_unix_ms,
                enrollment.spec.watcher_instance_id,
                enrollment.watcher_semantic_digest,
                enrollment.coordination_domain_id,
                document.as_bytes(),
                document.digest(),
                created_at_unix_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO recurrence_acquisition_events (
                event_id, acquisition_id, event_kind, attempt_number,
                fencing_epoch, event_json, event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, 'created', 0, NULL, ?3, ?1, ?4)",
            params![
                event.digest(),
                acquisition_id,
                event.as_bytes(),
                created_at_unix_ms
            ],
        )?;
        let slot_event = event_document(
            "acquisition_created",
            created_at_unix_ms,
            serde_json::json!({"slot": slot, "acquisition_id": acquisition_id}),
        )?;
        transaction.execute(
            "INSERT INTO recurrence_slot_events (
                event_id, enrollment_id, slot_index, slot_id,
                scheduled_for_unix_ms, event_kind, acquisition_id,
                event_json, event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'acquisition_created', ?6, ?7, ?1, ?8)",
            params![
                slot_event.digest(),
                enrollment.enrollment_id,
                slot.slot_index,
                slot.slot_id,
                slot.scheduled_for_unix_ms,
                acquisition_id,
                slot_event.as_bytes(),
                created_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(binding)
    }

    fn append_coordination_claim(
        &mut self,
        acquisition: &RecurrenceAcquisitionBindingV1,
        now_unix_ms: i64,
    ) -> Result<u64, StoreError> {
        let transaction = self.immediate_transaction()?;
        let latest: Option<(u64, String)> = transaction.query_row(
            "SELECT fencing_epoch, event_kind FROM recurrence_coordination_events WHERE coordination_domain_id = ?1 ORDER BY fencing_epoch DESC, event_sequence DESC LIMIT 1",
            [&acquisition.coordination_domain_id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if latest
            .as_ref()
            .is_some_and(|(_, kind)| !matches!(kind.as_str(), "released"))
        {
            return Err(StoreError::Invariant(
                "coordination domain became occupied before claim".into(),
            ));
        }
        let epoch = latest.map_or(1, |(value, _)| value.saturating_add(1));
        let event = event_document(
            "claimed",
            now_unix_ms,
            serde_json::json!({"coordination_domain_id": acquisition.coordination_domain_id, "fencing_epoch": epoch, "holder_acquisition_id": acquisition.acquisition_id, "holder_watcher_instance_id": acquisition.watcher_instance_id}),
        )?;
        transaction.execute(
            "INSERT INTO recurrence_coordination_events (
                event_id, coordination_domain_id, fencing_epoch, event_kind,
                holder_acquisition_id, holder_watcher_instance_id, event_json,
                event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, ?3, 'claimed', ?4, ?5, ?6, ?1, ?7)",
            params![
                event.digest(),
                acquisition.coordination_domain_id,
                epoch,
                acquisition.acquisition_id,
                acquisition.watcher_instance_id,
                event.as_bytes(),
                now_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(epoch)
    }

    /// Commit the recurrence/domain fencing token immediately before NQ's V3
    /// provider dispatch fence. This is a protocol law, not a configurable path.
    pub fn commit_recurrence_provider_fence(
        &mut self,
        fence: &RecurrenceProviderFenceV1,
    ) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        let binding: Option<(String, String, String, String, String)> = transaction.query_row(
            "SELECT enrollment_id, policy_id, coordination_domain_id, watcher_instance_id, watcher_semantic_digest FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [&fence.acquisition_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        let Some((enrollment_id, policy_id, domain_id, watcher_id, watcher_digest)) = binding
        else {
            return Err(StoreError::Invariant(
                "recurrence provider fence names unknown acquisition".into(),
            ));
        };
        if enrollment_id != fence.enrollment_id
            || policy_id != fence.policy_id
            || domain_id != fence.coordination_domain_id
            || watcher_id != fence.watcher_instance_id
            || watcher_digest != fence.watcher_semantic_digest
        {
            return Err(StoreError::ReplayConflict(
                "recurrence provider fence substituted enrollment, policy, domain, or watcher"
                    .into(),
            ));
        }
        let policy_bytes: Vec<u8> = transaction.query_row(
            "SELECT policy_json FROM recurring_office_policies WHERE policy_id = ?1",
            [&policy_id],
            |row| row.get(0),
        )?;
        let policy: RecurringOfficePolicyV1 =
            decode(&policy_bytes, "recurrence provider-fence policy")?;
        let deployment_binding = policy.watcher_binding(&watcher_id).ok_or_else(|| {
            StoreError::Integrity("recurrence provider-fence watcher mapping disappeared".into())
        })?;
        if deployment_binding.origin_profile != fence.origin_profile
            || deployment_binding.expected_instance_id_sha256 != fence.expected_instance_id_sha256
            || deployment_binding.origin_helper_issuer != fence.origin_helper_issuer
            || deployment_binding.origin_helper_key_id != fence.origin_helper_key_id
        {
            return Err(StoreError::ReplayConflict(
                "recurrence provider fence substituted origin profile, coordinate, issuer, or key"
                    .into(),
            ));
        }
        let domain = domain_projection_on(&transaction, &domain_id)?;
        if domain.epoch != Some(fence.fencing_epoch)
            || domain.holder_acquisition_id.as_deref() != Some(&fence.acquisition_id)
            || domain.fenced_unknown
        {
            return Err(StoreError::Invariant(
                "stale or unowned recurrence fencing epoch refused".into(),
            ));
        }
        let prior: Option<String> = transaction.query_row(
            "SELECT event_kind FROM recurrence_acquisition_events WHERE acquisition_id = ?1 ORDER BY event_sequence DESC LIMIT 1",
            [&fence.acquisition_id], |row| row.get(0),
        ).optional()?;
        if !matches!(prior.as_deref(), Some("created" | "pre_provider_failed")) {
            return Err(StoreError::Invariant(
                "recurrence acquisition is not eligible to cross provider fence".into(),
            ));
        }
        let event = event_document(
            "provider_invocation_started",
            fence.occurred_at_unix_ms,
            serde_json::json!({"acquisition_id": fence.acquisition_id, "enrollment_id": fence.enrollment_id, "policy_id": fence.policy_id, "coordination_domain_id": fence.coordination_domain_id, "fencing_epoch": fence.fencing_epoch, "attempt_number": fence.attempt_number, "watcher_instance_id": fence.watcher_instance_id, "watcher_semantic_digest": fence.watcher_semantic_digest, "origin_profile": fence.origin_profile, "expected_instance_id_sha256": fence.expected_instance_id_sha256, "origin_helper_issuer": fence.origin_helper_issuer, "origin_helper_key_id": fence.origin_helper_key_id}),
        )?;
        transaction.execute(
            "INSERT INTO recurrence_acquisition_events (
                event_id, acquisition_id, event_kind, attempt_number,
                fencing_epoch, event_json, event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, 'provider_invocation_started', ?3, ?4, ?5, ?1, ?6)",
            params![
                event.digest(),
                fence.acquisition_id,
                fence.attempt_number,
                fence.fencing_epoch,
                event.as_bytes(),
                fence.occurred_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Record a pre-provider refusal while retaining the same semantic
    /// occurrence and coordination epoch for bounded retry.
    #[allow(clippy::needless_pass_by_value)]
    pub fn record_recurrence_pre_provider_failure(
        &mut self,
        acquisition_id: &str,
        attempt_number: u16,
        fencing_epoch: u64,
        occurred_at_unix_ms: i64,
        detail: Value,
    ) -> Result<(), StoreError> {
        let event = event_document(
            "pre_provider_failed",
            occurred_at_unix_ms,
            serde_json::json!({"acquisition_id": acquisition_id, "attempt_number": attempt_number, "fencing_epoch": fencing_epoch, "detail": detail}),
        )?;
        let transaction = self.immediate_transaction()?;
        let domain = recurrence_binding_domain_on(&transaction, acquisition_id)?;
        let projection = domain_projection_on(&transaction, &domain)?;
        if projection.epoch != Some(fencing_epoch)
            || projection.holder_acquisition_id.as_deref() != Some(acquisition_id)
        {
            return Err(StoreError::Invariant(
                "pre-provider failure has stale coordination custody".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO recurrence_acquisition_events (
                event_id, acquisition_id, event_kind, attempt_number,
                fencing_epoch, event_json, event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, 'pre_provider_failed', ?3, ?4, ?5, ?1, ?6)",
            params![
                event.digest(),
                acquisition_id,
                attempt_number,
                fencing_epoch,
                event.as_bytes(),
                occurred_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Finish one occurrence and release or conservatively fence its domain.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn finish_recurrence_acquisition(
        &mut self,
        acquisition_id: &str,
        event_kind: &str,
        attempt_number: u64,
        fencing_epoch: Option<u64>,
        occurred_at_unix_ms: i64,
        detail: Value,
    ) -> Result<(), StoreError> {
        if !matches!(
            event_kind,
            "pre_provider_exhausted"
                | "provider_succeeded"
                | "provider_terminal_failed"
                | "outcome_unknown"
        ) {
            return Err(StoreError::Invariant(
                "unsupported recurrence terminal event".into(),
            ));
        }
        let epoch = fencing_epoch.ok_or_else(|| {
            StoreError::Invariant("terminal recurrence event lacks fencing epoch".into())
        })?;
        let event = event_document(
            event_kind,
            occurred_at_unix_ms,
            serde_json::json!({"acquisition_id": acquisition_id, "attempt_number": attempt_number, "fencing_epoch": epoch, "detail": detail}),
        )?;
        let transaction = self.immediate_transaction()?;
        let domain = recurrence_binding_domain_on(&transaction, acquisition_id)?;
        let projection = domain_projection_on(&transaction, &domain)?;
        if projection.epoch != Some(epoch)
            || projection.holder_acquisition_id.as_deref() != Some(acquisition_id)
        {
            return Err(StoreError::Invariant(
                "terminal recurrence event has stale coordination custody".into(),
            ));
        }
        let prior: String = transaction.query_row(
            "SELECT event_kind FROM recurrence_acquisition_events WHERE acquisition_id = ?1 ORDER BY event_sequence DESC LIMIT 1",
            [acquisition_id],
            |row| row.get(0),
        )?;
        let valid_prior = if event_kind == "pre_provider_exhausted" {
            prior == "pre_provider_failed"
        } else {
            prior == "provider_invocation_started"
        };
        if !valid_prior {
            return Err(StoreError::Invariant(format!(
                "terminal recurrence transition {prior} -> {event_kind} refused"
            )));
        }
        transaction.execute(
            "INSERT INTO recurrence_acquisition_events (
                event_id, acquisition_id, event_kind, attempt_number,
                fencing_epoch, event_json, event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?1, ?7)",
            params![
                event.digest(),
                acquisition_id,
                event_kind,
                attempt_number,
                epoch,
                event.as_bytes(),
                occurred_at_unix_ms
            ],
        )?;
        let coordination_kind = if event_kind == "outcome_unknown" {
            "fenced_outcome_unknown"
        } else {
            "released"
        };
        let coordination = event_document(
            coordination_kind,
            occurred_at_unix_ms,
            serde_json::json!({"coordination_domain_id": domain, "fencing_epoch": epoch, "holder_acquisition_id": acquisition_id}),
        )?;
        let watcher: String = transaction.query_row(
            "SELECT watcher_instance_id FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [acquisition_id],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO recurrence_coordination_events (
                event_id, coordination_domain_id, fencing_epoch, event_kind,
                holder_acquisition_id, holder_watcher_instance_id, event_json,
                event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?1, ?8)",
            params![
                coordination.digest(),
                domain,
                epoch,
                coordination_kind,
                acquisition_id,
                watcher,
                coordination.as_bytes(),
                occurred_at_unix_ms
            ],
        )?;
        let enrollment_id: String = transaction.query_row(
            "SELECT enrollment_id FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [acquisition_id],
            |row| row.get(0),
        )?;
        if event_kind == "outcome_unknown" {
            append_automatic_enrollment_event_on(
                &transaction,
                &enrollment_id,
                "paused_outcome_unknown",
                occurred_at_unix_ms,
                "provider outcome is unknown",
                acquisition_id,
            )?;
        } else if matches!(
            event_kind,
            "pre_provider_exhausted" | "provider_terminal_failed"
        ) {
            let enrollment =
                recurrence_enrollment_on(&transaction, &enrollment_id)?.ok_or_else(|| {
                    StoreError::Integrity("terminal acquisition enrollment disappeared".into())
                })?;
            let streak = failure_streak_on(&transaction, &enrollment_id)?;
            if streak >= enrollment.spec.failure_pause_threshold {
                append_automatic_enrollment_event_on(
                    &transaction,
                    &enrollment_id,
                    "paused_failure_threshold",
                    occurred_at_unix_ms,
                    "consecutive terminal failure threshold reached",
                    acquisition_id,
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn recurrence_status(&self, enrollment_id: &str) -> Result<RecurrenceStatusV1, StoreError> {
        let enrollment = self
            .recurrence_enrollment(enrollment_id)?
            .ok_or_else(|| StoreError::Invariant("unknown recurrence enrollment".into()))?;
        let policy = self
            .recurring_office_policy(&enrollment.spec.policy_id)?
            .ok_or_else(|| StoreError::Integrity("recurrence policy disappeared".into()))?;
        let domain_policy = policy
            .domain(&enrollment.coordination_domain_id)
            .ok_or_else(|| StoreError::Integrity("recurrence domain disappeared".into()))?;
        let highest = self.highest_evaluated_slot(enrollment_id)?;
        let next_slot = highest.map_or(enrollment.first_eligible_slot, |value| {
            value.saturating_add(1)
        });
        let count = self.recurrence_occurrence_count(enrollment_id)?;
        let domain = self.domain_projection(&enrollment.coordination_domain_id)?;
        let pending = self.pending_recurrence_acquisition(&enrollment.spec.watcher_instance_id)?;
        let last_completed = self.connection.query_row(
            "SELECT a.acquisition_id FROM recurrence_acquisitions AS a
             JOIN recurrence_acquisition_events AS e ON e.acquisition_id = a.acquisition_id
             WHERE a.enrollment_id = ?1 AND e.event_kind IN ('provider_succeeded', 'pre_provider_exhausted', 'provider_terminal_failed')
             ORDER BY e.event_sequence DESC LIMIT 1",
            [enrollment_id], |row| row.get(0),
        ).optional()?;
        let skipped_ranges = self.skipped_ranges(enrollment_id)?;
        let last_start = domain.last_provider_start_unix_ms;
        let safe_next = last_start.and_then(|value| {
            value.checked_add(i64::try_from(domain_policy.min_provider_start_spacing_ms).ok()?)
        });
        Ok(RecurrenceStatusV1 {
            schema: "nq.recurrence_status.v1".into(),
            active_deployment_policy_id: self.active_recurring_office_policy_id()?,
            enrollment_policy_current: self.active_recurring_office_policy_id()?.as_deref()
                == Some(&enrollment.spec.policy_id),
            enrollment_state: self.recurrence_enrollment_state(enrollment_id)?,
            highest_evaluated_slot: highest,
            next_due_slot: next_slot,
            next_due_unix_ms: enrollment.slot(next_slot)?.scheduled_for_unix_ms,
            acquisition_occurrences: count,
            remaining_occurrences: enrollment
                .spec
                .max_acquisition_occurrences
                .saturating_sub(count),
            in_flight_acquisition_id: pending.map(|value| value.acquisition_id),
            last_completed_acquisition_id: last_completed,
            failure_streak: self.failure_streak(enrollment_id)?,
            skipped_slot_count: skipped_ranges
                .iter()
                .map(|(from, to)| to.saturating_sub(*from).saturating_add(1))
                .sum(),
            skipped_ranges,
            coordination_domain_id: enrollment.coordination_domain_id.clone(),
            domain_max_in_flight: domain_policy.max_in_flight,
            current_fencing_epoch: domain.epoch,
            holder_acquisition_id: domain.holder_acquisition_id.clone(),
            holder_watcher_instance_id: domain.holder_watcher_instance_id.clone(),
            provider_safe_next_start_unix_ms: safe_next,
            coordination_blocked: domain.holder_acquisition_id.is_some(),
            coordination_blocked_reason: domain.holder_acquisition_id.as_ref().map(|_| {
                if domain.fenced_unknown {
                    "outcome_unknown_domain_fence".into()
                } else {
                    "domain_occupied".into()
                }
            }),
            outcome_unknown_fences_domain: domain.fenced_unknown,
            storage_guard_max_store_bytes: policy.max_store_bytes,
            storage_guard_min_free_bytes: policy.min_free_bytes,
            enrollment,
        })
    }

    fn recurrence_enrollment_state(&self, enrollment_id: &str) -> Result<String, StoreError> {
        let mut statement = self.connection.prepare("SELECT event_kind FROM recurrence_enrollment_events WHERE enrollment_id = ?1 ORDER BY event_sequence")?;
        let events = statement
            .query_map([enrollment_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut state = "absent";
        for event in &events {
            state = match event.as_str() {
                "enrolled" | "resumed_operator" => "active",
                "paused_operator" => "paused_operator",
                "revoked_operator" => "revoked",
                "paused_failure_threshold" => "paused_failure_threshold",
                "paused_outcome_unknown" => "paused_outcome_unknown",
                "exhausted" => "exhausted",
                "expired" => "expired",
                _ => {
                    return Err(StoreError::Integrity(format!(
                        "unknown recurrence enrollment event {event}"
                    )));
                }
            };
        }
        Ok(state.to_owned())
    }

    fn enrollment_has_outcome_unknown(&self, enrollment_id: &str) -> Result<bool, StoreError> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                SELECT 1 FROM recurrence_acquisitions AS a
                JOIN recurrence_acquisition_events AS e ON e.acquisition_id = a.acquisition_id
                WHERE a.enrollment_id = ?1
                  AND e.event_sequence = (
                    SELECT MAX(e2.event_sequence)
                    FROM recurrence_acquisition_events AS e2
                    WHERE e2.acquisition_id = a.acquisition_id)
                  AND e.event_kind = 'outcome_unknown'
                  AND NOT EXISTS(
                    SELECT 1 FROM provider_activity_reconciliation_events AS r
                    WHERE r.acquisition_id = a.acquisition_id))",
                [enrollment_id],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    fn highest_evaluated_slot(&self, enrollment_id: &str) -> Result<Option<u64>, StoreError> {
        self.connection
            .query_row(
                "SELECT MAX(slot_index) FROM recurrence_slot_events WHERE enrollment_id = ?1",
                [enrollment_id],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    fn recurrence_occurrence_count(&self, enrollment_id: &str) -> Result<u32, StoreError> {
        let count: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM recurrence_acquisitions WHERE enrollment_id = ?1",
            [enrollment_id],
            |row| row.get(0),
        )?;
        u32::try_from(count)
            .map_err(|_| StoreError::Integrity("recurrence occurrence count overflowed".into()))
    }

    fn skipped_ranges(&self, enrollment_id: &str) -> Result<Vec<(u64, u64)>, StoreError> {
        let mut statement = self.connection.prepare("SELECT event_json FROM recurrence_slot_events WHERE enrollment_id = ?1 AND event_kind = 'skipped' ORDER BY event_sequence")?;
        let rows = statement.query_map([enrollment_id], |row| row.get::<_, Vec<u8>>(0))?;
        let mut ranges = Vec::new();
        for bytes in rows {
            let value: Value = serde_json::from_slice(&bytes?).map_err(|error| {
                StoreError::Integrity(format!("skipped-slot event cannot decode: {error}"))
            })?;
            let detail = value
                .get("fields")
                .and_then(|fields| fields.get("detail"))
                .ok_or_else(|| StoreError::Integrity("skipped-slot event lacks detail".into()))?;
            let from = detail
                .get("skipped_from")
                .and_then(Value::as_u64)
                .ok_or_else(|| StoreError::Integrity("skipped-slot event lacks from".into()))?;
            let to = detail
                .get("skipped_to")
                .and_then(Value::as_u64)
                .ok_or_else(|| StoreError::Integrity("skipped-slot event lacks to".into()))?;
            ranges.push((from, to));
        }
        Ok(ranges)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn append_slot_event(
        &mut self,
        slot: &RecurrenceSlotV1,
        kind: &str,
        acquisition_id: Option<&str>,
        occurred_at_unix_ms: i64,
        detail: Value,
    ) -> Result<(), StoreError> {
        let event = event_document(
            kind,
            occurred_at_unix_ms,
            serde_json::json!({"slot": slot, "detail": detail, "acquisition_id": acquisition_id}),
        )?;
        let transaction = self.immediate_transaction()?;
        let existing: Option<Vec<u8>> = if kind == "coordination_deferred" {
            transaction
                .query_row(
                    "SELECT event_json FROM recurrence_slot_events WHERE event_id = ?1",
                    [event.digest()],
                    |row| row.get(0),
                )
                .optional()?
        } else {
            transaction.query_row("SELECT event_json FROM recurrence_slot_events WHERE enrollment_id = ?1 AND slot_index = ?2 AND event_kind = ?3", params![slot.enrollment_id, slot.slot_index, kind], |row| row.get(0)).optional()?
        };
        if let Some(bytes) = existing {
            if bytes == event.as_bytes() {
                return Ok(());
            }
            return Err(StoreError::ReplayConflict(
                "recurrence slot event substitution refused".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO recurrence_slot_events (
                event_id, enrollment_id, slot_index, slot_id,
                scheduled_for_unix_ms, event_kind, acquisition_id,
                event_json, event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?1, ?9)",
            params![
                event.digest(),
                slot.enrollment_id,
                slot.slot_index,
                slot.slot_id,
                slot.scheduled_for_unix_ms,
                kind,
                acquisition_id,
                event.as_bytes(),
                occurred_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn append_automatic_enrollment_event(
        &mut self,
        enrollment: &RecurrenceEnrollmentV1,
        kind: &str,
        occurred_at_unix_ms: i64,
        reason: &str,
    ) -> Result<(), StoreError> {
        let transaction = self.immediate_transaction()?;
        let cause_id = format!("state:{kind}");
        append_automatic_enrollment_event_on(
            &transaction,
            &enrollment.enrollment_id,
            kind,
            occurred_at_unix_ms,
            reason,
            &cause_id,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn pending_recurrence_acquisition(
        &self,
        watcher_instance_id: &str,
    ) -> Result<Option<RecurrenceAcquisitionBindingV1>, StoreError> {
        let bytes: Option<Vec<u8>> = self.connection.query_row(
            "SELECT a.binding_json FROM recurrence_acquisitions AS a
             JOIN recurrence_acquisition_events AS e ON e.acquisition_id = a.acquisition_id
             WHERE a.watcher_instance_id = ?1
               AND e.event_sequence = (SELECT MAX(e2.event_sequence) FROM recurrence_acquisition_events AS e2 WHERE e2.acquisition_id = a.acquisition_id)
               AND e.event_kind IN ('created', 'pre_provider_failed', 'provider_invocation_started', 'outcome_unknown')
               AND NOT (e.event_kind = 'outcome_unknown' AND EXISTS(
                   SELECT 1 FROM provider_activity_reconciliation_events AS r
                   WHERE r.acquisition_id = a.acquisition_id))
             ORDER BY a.created_at_unix_ms, a.acquisition_id LIMIT 1",
            [watcher_instance_id], |row| row.get(0),
        ).optional()?;
        bytes
            .map(|bytes| decode(&bytes, "recurrence acquisition binding"))
            .transpose()
    }

    pub fn recurrence_acquisition_state(
        &self,
        acquisition_id: &str,
    ) -> Result<Option<RecurrenceAcquisitionStateV1>, StoreError> {
        self.connection.query_row(
            "SELECT event_kind, attempt_number, fencing_epoch, occurred_at_unix_ms FROM recurrence_acquisition_events WHERE acquisition_id = ?1 ORDER BY event_sequence DESC LIMIT 1",
            [acquisition_id], |row| Ok(RecurrenceAcquisitionStateV1 { event_kind: row.get(0)?, attempt_number: row.get(1)?, fencing_epoch: row.get(2)?, occurred_at_unix_ms: row.get(3)? }),
        ).optional().map_err(StoreError::from)
    }

    /// Reopen one exact immutable recurrence acquisition binding by identity.
    /// This read-only lookup creates no trigger or provider work.
    pub fn recurrence_acquisition(
        &self,
        acquisition_id: &str,
    ) -> Result<Option<RecurrenceAcquisitionBindingV1>, StoreError> {
        self.connection
            .query_row(
                "SELECT binding_json FROM recurrence_acquisitions WHERE acquisition_id = ?1",
                [acquisition_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|bytes| decode(&bytes, "recurrence acquisition binding"))
            .transpose()
    }

    /// Release an outcome-unknown domain fence only after exact local artifact
    /// custody for this same acquisition has been reopened by the caller. This
    /// transition never invokes a provider and leaves the enrollment paused
    /// until a separate explicit operator resume.
    #[allow(clippy::too_many_lines)] // Keep the exact result/release transaction auditable.
    pub fn reconcile_recurrence_from_exact_custody(
        &mut self,
        acquisition_id: &str,
        attempt_number: u64,
        fencing_epoch: u64,
        artifact_id: &str,
        occurred_at_unix_ms: i64,
    ) -> Result<(), StoreError> {
        Sha256Digest::parse(artifact_id.to_owned()).map_err(|error| {
            StoreError::Invariant(format!("reconciled artifact identity is invalid: {error}"))
        })?;
        let transaction = self.immediate_transaction()?;
        let domain = recurrence_binding_domain_on(&transaction, acquisition_id)?;
        let projection = domain_projection_on(&transaction, &domain)?;
        let activity_released: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_activity_reconciliation_events
             WHERE acquisition_id = ?1 AND fencing_epoch = ?2)",
            params![acquisition_id, fencing_epoch],
            |row| row.get(0),
        )?;
        if projection.epoch != Some(fencing_epoch)
            || (!activity_released
                && (projection.holder_acquisition_id.as_deref() != Some(acquisition_id)
                    || !projection.fenced_unknown))
        {
            return Err(StoreError::Invariant(
                "recurrence reconciliation lacks the exact outcome-unknown domain fence".into(),
            ));
        }
        let prior: (String, u64, Option<u64>) = transaction.query_row(
            "SELECT event_kind, attempt_number, fencing_epoch
             FROM recurrence_acquisition_events
             WHERE acquisition_id = ?1 ORDER BY event_sequence DESC LIMIT 1",
            [acquisition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if prior
            != (
                "outcome_unknown".to_owned(),
                attempt_number,
                Some(fencing_epoch),
            )
        {
            return Err(StoreError::Invariant(
                "recurrence reconciliation differs from the exact terminal attempt/fence".into(),
            ));
        }
        if !exact_local_diagnostic_artifact_on(&transaction, acquisition_id, artifact_id)? {
            return Err(StoreError::Invariant(
                "recurrence reconciliation artifact is not exact local custody for this acquisition"
                    .into(),
            ));
        }
        let event = event_document(
            "provider_succeeded",
            occurred_at_unix_ms,
            serde_json::json!({
                "acquisition_id": acquisition_id,
                "attempt_number": attempt_number,
                "fencing_epoch": fencing_epoch,
                "detail": {
                    "artifact_id": artifact_id,
                    "reconciled_from_exact_custody": true
                }
            }),
        )?;
        transaction.execute(
            "INSERT INTO recurrence_acquisition_events (
                event_id, acquisition_id, event_kind, attempt_number,
                fencing_epoch, event_json, event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, 'provider_succeeded', ?3, ?4, ?5, ?1, ?6)",
            params![
                event.digest(),
                acquisition_id,
                attempt_number,
                fencing_epoch,
                event.as_bytes(),
                occurred_at_unix_ms
            ],
        )?;
        let watcher: String = transaction.query_row(
            "SELECT watcher_instance_id FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [acquisition_id],
            |row| row.get(0),
        )?;
        if !activity_released {
            let coordination = event_document(
                "released",
                occurred_at_unix_ms,
                serde_json::json!({
                    "coordination_domain_id": domain,
                    "fencing_epoch": fencing_epoch,
                    "holder_acquisition_id": acquisition_id,
                    "reconciled_from_exact_custody": true
                }),
            )?;
            transaction.execute(
                "INSERT INTO recurrence_coordination_events (
                    event_id, coordination_domain_id, fencing_epoch, event_kind,
                    holder_acquisition_id, holder_watcher_instance_id, event_json,
                    event_digest, occurred_at_unix_ms
                 ) VALUES (?1, ?2, ?3, 'released', ?4, ?5, ?6, ?1, ?7)",
                params![
                    coordination.digest(),
                    domain,
                    fencing_epoch,
                    acquisition_id,
                    watcher,
                    coordination.as_bytes(),
                    occurred_at_unix_ms
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Persist exact prospective evidence produced by the closed local stdio
    /// supervisor. This does not release a fence or classify a diagnostic.
    #[allow(clippy::too_many_lines)] // Keep identity, fence, and provider-basis checks atomic.
    pub fn append_provider_activity_evidence(
        &mut self,
        evidence: &ProviderActivityEvidenceV1,
    ) -> Result<String, StoreError> {
        evidence.validate_identity()?;
        let document = CanonicalDocument::from_serializable(evidence)?;
        let transaction = self.immediate_transaction()?;
        let binding: RecurrenceAcquisitionBindingV1 = transaction
            .query_row(
                "SELECT binding_json FROM recurrence_acquisitions WHERE acquisition_id = ?1",
                [&evidence.acquisition_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|bytes| decode(&bytes, "provider-activity recurrence binding"))
            .transpose()?
            .ok_or_else(|| {
                StoreError::Invariant("provider-activity evidence names unknown acquisition".into())
            })?;
        if evidence.enrollment_id != binding.enrollment_id
            || evidence.slot_id != binding.slot.slot_id
            || evidence.coordination_domain_id != binding.coordination_domain_id
        {
            return Err(StoreError::ReplayConflict(
                "provider-activity evidence substituted enrollment, slot, or domain".into(),
            ));
        }
        let fenced: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM recurrence_acquisition_events
             WHERE acquisition_id = ?1 AND event_kind = 'provider_invocation_started'
               AND attempt_number = ?2 AND fencing_epoch = ?3)",
            params![
                evidence.acquisition_id,
                evidence.attempt_number,
                evidence.fencing_epoch
            ],
            |row| row.get(0),
        )?;
        if !fenced {
            return Err(StoreError::Invariant(
                "provider-activity evidence lacks its exact provider invocation fence".into(),
            ));
        }
        let claim_matches_runner = match evidence.claim {
            ProviderActivityClaimV1::ProviderNotInvoked => {
                evidence.runner_outcome == "spawn_failed"
            }
            ProviderActivityClaimV1::ProviderQuiescent => matches!(
                evidence.runner_outcome.as_str(),
                "response"
                    | "request_write_failed"
                    | "timeout"
                    | "output_too_large"
                    | "stderr_too_large"
                    | "eof"
                    | "malformed_framing"
                    | "malformed_json"
                    | "exit_nonzero"
            ),
        };
        if !claim_matches_runner {
            return Err(StoreError::Invariant(
                "runner outcome cannot establish the claimed provider activity".into(),
            ));
        }
        let intent_bytes: Vec<u8> = transaction.query_row(
            "SELECT intent_json FROM substrate_origin_acquisition_intents WHERE acquisition_id = ?1",
            [&evidence.acquisition_id],
            |row| row.get(0),
        )?;
        let intent: Value = serde_json::from_slice(&intent_bytes).map_err(|error| {
            StoreError::Integrity(format!(
                "provider-activity substrate intent cannot decode: {error}"
            ))
        })?;
        let text = |path: &str| intent.pointer(path).and_then(Value::as_str);
        if text("/attempt_id") != Some(&evidence.provider_attempt_id)
            || text("/run_id") != Some(&evidence.provider_run_id)
            || text("/request/request_id") != Some(&evidence.provider_request_id)
            || text("/provider/provider_semantic_id") != Some(&evidence.provider_semantic_id)
            || text("/provider/artifact_digest") != Some(&evidence.provider_artifact_digest)
            || text("/provider/execution_identity_digest")
                != Some(&evidence.provider_execution_identity_digest)
            || text("/origin_carrier") != Some("stdio")
        {
            return Err(StoreError::ReplayConflict(
                "provider-activity evidence substituted exact provider request, run, attempt, identity, or carrier"
                    .into(),
            ));
        }
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT evidence_json FROM provider_activity_evidence WHERE evidence_id = ?1
             OR (acquisition_id = ?2 AND fencing_epoch = ?3 AND attempt_number = ?4
                 AND claim = ?5 AND producer_schema = ?6)",
                params![
                    evidence.evidence_id,
                    evidence.acquisition_id,
                    evidence.fencing_epoch,
                    evidence.attempt_number,
                    evidence.claim.as_str(),
                    evidence.producer_schema
                ],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == document.as_bytes() {
                transaction.commit()?;
                return Ok(evidence.evidence_id.clone());
            }
            return Err(StoreError::ReplayConflict(
                "provider-activity evidence replay changed exact bytes".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO provider_activity_evidence (
                evidence_id, schema_id, acquisition_id, enrollment_id, slot_id,
                coordination_domain_id, fencing_epoch, attempt_number, claim,
                producer_schema, evidence_json, evidence_digest, observed_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?1, ?12)",
            params![
                evidence.evidence_id,
                evidence.schema,
                evidence.acquisition_id,
                evidence.enrollment_id,
                evidence.slot_id,
                evidence.coordination_domain_id,
                evidence.fencing_epoch,
                evidence.attempt_number,
                evidence.claim.as_str(),
                evidence.producer_schema,
                document.as_bytes(),
                evidence.observed_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(evidence.evidence_id.clone())
    }

    /// Accept one exact stored provider-activity evidence object and release
    /// only its matching outcome-unknown coordination fence. Diagnostic state
    /// remains outcome_unknown.
    #[allow(clippy::too_many_lines)] // Keep evidence acceptance and fence release atomic.
    pub fn reconcile_provider_activity(
        &mut self,
        acquisition_id: &str,
        enrollment_id: &str,
        coordination_domain_id: &str,
        fencing_epoch: u64,
        evidence_id: &str,
        occurred_at_unix_ms: i64,
    ) -> Result<String, StoreError> {
        let transaction = self.immediate_transaction()?;
        let existing_event: Option<(String, String)> = transaction
            .query_row(
                "SELECT event_id, evidence_id FROM provider_activity_reconciliation_events
             WHERE acquisition_id = ?1 AND fencing_epoch = ?2",
                params![acquisition_id, fencing_epoch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((event_id, existing_evidence)) = existing_event {
            if existing_evidence == evidence_id {
                transaction.commit()?;
                return Ok(event_id);
            }
            return Err(StoreError::ReplayConflict(
                "provider-activity reconciliation substituted evidence".into(),
            ));
        }
        let evidence_bytes: Vec<u8> = transaction
            .query_row(
                "SELECT evidence_json FROM provider_activity_evidence WHERE evidence_id = ?1",
                [evidence_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::Invariant(
                    "provider-activity reconciliation evidence is unknown to local custody".into(),
                )
            })?;
        let evidence: ProviderActivityEvidenceV1 =
            decode(&evidence_bytes, "provider-activity reconciliation evidence")?;
        evidence.validate_identity()?;
        if evidence.acquisition_id != acquisition_id
            || evidence.enrollment_id != enrollment_id
            || evidence.coordination_domain_id != coordination_domain_id
            || evidence.fencing_epoch != fencing_epoch
            || evidence.evidence_id != evidence_id
        {
            return Err(StoreError::ReplayConflict(
                "provider-activity reconciliation substituted target identity".into(),
            ));
        }
        let state: (String, u64, Option<u64>) = transaction.query_row(
            "SELECT event_kind, attempt_number, fencing_epoch FROM recurrence_acquisition_events
             WHERE acquisition_id = ?1 ORDER BY event_sequence DESC LIMIT 1",
            [acquisition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if state
            != (
                "outcome_unknown".into(),
                u64::from(evidence.attempt_number),
                Some(fencing_epoch),
            )
        {
            return Err(StoreError::Invariant(
                "provider-activity reconciliation requires the exact terminal outcome-unknown attempt"
                    .into(),
            ));
        }
        let projection = domain_projection_on(&transaction, coordination_domain_id)?;
        if projection.epoch != Some(fencing_epoch)
            || projection.holder_acquisition_id.as_deref() != Some(acquisition_id)
            || !projection.fenced_unknown
        {
            return Err(StoreError::Invariant(
                "provider-activity reconciliation lacks exact fenced domain ownership".into(),
            ));
        }
        let event = canonical(&serde_json::json!({
            "schema": PROVIDER_ACTIVITY_RECONCILIATION_SCHEMA_V1,
            "occurred_at_unix_ms": occurred_at_unix_ms,
            "fields": {
                "acquisition_id": acquisition_id,
                "enrollment_id": enrollment_id,
                "coordination_domain_id": coordination_domain_id,
                "fencing_epoch": fencing_epoch,
                "evidence_id": evidence_id,
                "disposition": evidence.claim.disposition(),
                "diagnostic_outcome": "outcome_unknown"
            }
        }))?;
        transaction.execute(
            "INSERT INTO provider_activity_reconciliation_events (
                event_id, acquisition_id, evidence_id, enrollment_id,
                coordination_domain_id, fencing_epoch, disposition, event_json,
                event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?1, ?9)",
            params![
                event.digest(),
                acquisition_id,
                evidence_id,
                enrollment_id,
                coordination_domain_id,
                fencing_epoch,
                evidence.claim.disposition(),
                event.as_bytes(),
                occurred_at_unix_ms
            ],
        )?;
        let watcher: String = transaction.query_row(
            "SELECT watcher_instance_id FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [acquisition_id],
            |row| row.get(0),
        )?;
        let release = event_document(
            "released",
            occurred_at_unix_ms,
            serde_json::json!({
                "coordination_domain_id": coordination_domain_id,
                "fencing_epoch": fencing_epoch,
                "holder_acquisition_id": acquisition_id,
                "provider_activity_reconciliation_event_id": event.digest(),
                "diagnostic_outcome": "outcome_unknown"
            }),
        )?;
        transaction.execute(
            "INSERT INTO recurrence_coordination_events (
                event_id, coordination_domain_id, fencing_epoch, event_kind,
                holder_acquisition_id, holder_watcher_instance_id, event_json,
                event_digest, occurred_at_unix_ms
             ) VALUES (?1, ?2, ?3, 'released', ?4, ?5, ?6, ?1, ?7)",
            params![
                release.digest(),
                coordination_domain_id,
                fencing_epoch,
                acquisition_id,
                watcher,
                release.as_bytes(),
                occurred_at_unix_ms
            ],
        )?;
        transaction.commit()?;
        Ok(event.digest().to_owned())
    }

    /// Project diagnostic uncertainty and provider-activity certainty
    /// independently without changing either.
    pub fn provider_fence_status(
        &self,
        acquisition_id: &str,
    ) -> Result<ProviderFenceStatusV1, StoreError> {
        let binding = self
            .recurrence_acquisition(acquisition_id)?
            .ok_or_else(|| {
                StoreError::Invariant("provider-fence status names unknown acquisition".into())
            })?;
        let state = self
            .recurrence_acquisition_state(acquisition_id)?
            .ok_or_else(|| {
                StoreError::Integrity("provider-fence acquisition lacks state".into())
            })?;
        let epoch = state.fencing_epoch.ok_or_else(|| {
            StoreError::Invariant("provider-fence acquisition lacks fencing epoch".into())
        })?;
        let evidence: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT evidence_id, claim FROM provider_activity_evidence
             WHERE acquisition_id = ?1 AND fencing_epoch = ?2
             ORDER BY observed_at_unix_ms, evidence_id LIMIT 1",
                params![acquisition_id, epoch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let reconciliation: Option<String> = self
            .connection
            .query_row(
                "SELECT event_id FROM provider_activity_reconciliation_events
             WHERE acquisition_id = ?1 AND fencing_epoch = ?2",
                params![acquisition_id, epoch],
                |row| row.get(0),
            )
            .optional()?;
        let domain = domain_projection_on(&self.connection, &binding.coordination_domain_id)?;
        let diagnostic_outcome = match state.event_kind.as_str() {
            "provider_succeeded" => "exact_result_known",
            "provider_terminal_failed" => "exact_provider_failure_known",
            "outcome_unknown" => "unknown",
            _ => "not_terminal",
        };
        let provider_activity = if reconciliation.is_some() {
            evidence
                .as_ref()
                .map_or("unknown", |(_, claim)| claim.as_str())
        } else if evidence.is_some() {
            "exact_evidence_available_not_applied"
        } else {
            "unknown"
        };
        let coordination = if domain.fenced_unknown {
            "fenced"
        } else {
            "released"
        };
        let reason = match (diagnostic_outcome, provider_activity, coordination) {
            ("unknown", "unknown", "fenced") => {
                "provider invocation crossed; no exact result custody or accepted provider-activity evidence"
            }
            ("unknown", "provider_not_invoked" | "provider_quiescent", "released") => {
                "overlap risk is proven absent; diagnostic result remains unknown"
            }
            ("exact_result_known", _, "released") => {
                "exact result custody recovered; coordination released"
            }
            _ => "see exact acquisition, evidence, and coordination histories",
        };
        Ok(ProviderFenceStatusV1 {
            schema: "nq.provider_fence_status.v1".into(),
            acquisition_id: acquisition_id.into(),
            enrollment_id: binding.enrollment_id,
            slot_id: binding.slot.slot_id,
            coordination_domain_id: binding.coordination_domain_id,
            fencing_epoch: epoch,
            diagnostic_outcome: diagnostic_outcome.into(),
            provider_activity: provider_activity.into(),
            coordination: coordination.into(),
            evidence_id: evidence.map(|value| value.0),
            reconciliation_event_id: reconciliation,
            reason: reason.into(),
        })
    }

    fn domain_projection(&self, domain_id: &str) -> Result<DomainProjection, StoreError> {
        domain_projection_on(&self.connection, domain_id)
    }

    fn failure_streak(&self, enrollment_id: &str) -> Result<u16, StoreError> {
        failure_streak_on(&self.connection, enrollment_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecurrenceAcquisitionStateV1 {
    pub event_kind: String,
    pub attempt_number: u64,
    pub fencing_epoch: Option<u64>,
    pub occurred_at_unix_ms: i64,
}

fn recurrence_enrollment_on(
    connection: &rusqlite::Connection,
    enrollment_id: &str,
) -> Result<Option<RecurrenceEnrollmentV1>, StoreError> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT enrollment_json FROM recurrence_enrollments WHERE enrollment_id = ?1",
            [enrollment_id],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| decode(&bytes, "recurrence enrollment"))
        .transpose()
}

fn recurrence_binding_domain_on(
    connection: &rusqlite::Connection,
    acquisition_id: &str,
) -> Result<String, StoreError> {
    connection
        .query_row(
            "SELECT coordination_domain_id FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [acquisition_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn exact_local_diagnostic_artifact_on(
    connection: &rusqlite::Connection,
    acquisition_id: &str,
    artifact_id: &str,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM local_diagnostic_artifact_origins AS origin
                JOIN local_watcher_provider_intakes AS intake
                  ON intake.run_id = origin.run_id
                JOIN diagnostic_artifact_payloads AS payload
                  ON payload.artifact_id = origin.artifact_id
                WHERE intake.intake_id = ?1 AND origin.artifact_id = ?2)",
            params![acquisition_id, artifact_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn domain_projection_on(
    connection: &rusqlite::Connection,
    domain_id: &str,
) -> Result<DomainProjection, StoreError> {
    let latest: Option<(u64, String, String, String)> = connection
        .query_row(
            "SELECT fencing_epoch, event_kind, holder_acquisition_id, holder_watcher_instance_id
         FROM recurrence_coordination_events WHERE coordination_domain_id = ?1
         ORDER BY fencing_epoch DESC, event_sequence DESC LIMIT 1",
            [domain_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let last_provider_start_unix_ms = connection.query_row(
        "SELECT MAX(e.occurred_at_unix_ms)
         FROM recurrence_acquisition_events AS e
         JOIN recurrence_acquisitions AS a ON a.acquisition_id = e.acquisition_id
         WHERE a.coordination_domain_id = ?1 AND e.event_kind = 'provider_invocation_started'",
        [domain_id],
        |row| row.get(0),
    )?;
    Ok(match latest {
        None => DomainProjection {
            epoch: None,
            holder_acquisition_id: None,
            holder_watcher_instance_id: None,
            fenced_unknown: false,
            last_provider_start_unix_ms,
        },
        Some((epoch, kind, _, _)) if kind == "released" => DomainProjection {
            epoch: Some(epoch),
            holder_acquisition_id: None,
            holder_watcher_instance_id: None,
            fenced_unknown: false,
            last_provider_start_unix_ms,
        },
        Some((epoch, kind, acquisition, watcher)) => DomainProjection {
            epoch: Some(epoch),
            holder_acquisition_id: Some(acquisition),
            holder_watcher_instance_id: Some(watcher),
            fenced_unknown: kind == "fenced_outcome_unknown",
            last_provider_start_unix_ms,
        },
    })
}

fn append_automatic_enrollment_event_on(
    connection: &rusqlite::Connection,
    enrollment_id: &str,
    kind: &str,
    occurred_at_unix_ms: i64,
    reason: &str,
    cause_id: &str,
) -> Result<(), StoreError> {
    let operation_id = format!("automatic:{kind}:{cause_id}");
    let event = event_document(
        kind,
        occurred_at_unix_ms,
        serde_json::json!({"enrollment_id": enrollment_id, "reason": reason, "cause_id": cause_id}),
    )?;
    let existing: Option<Vec<u8>> = connection.query_row("SELECT event_json FROM recurrence_enrollment_events WHERE enrollment_id = ?1 AND operation_id = ?2", params![enrollment_id, operation_id], |row| row.get(0)).optional()?;
    if let Some(bytes) = existing {
        if bytes == event.as_bytes() {
            return Ok(());
        }
        return Err(StoreError::ReplayConflict(
            "automatic recurrence state event was substituted".into(),
        ));
    }
    let system_identity =
        canonical(&serde_json::json!({"kind": "nq_recurring_office_state_machine"}))?;
    connection.execute(
        "INSERT INTO recurrence_enrollment_events (
            event_id, enrollment_id, event_kind, operation_id, event_json,
            event_digest, occurred_at_unix_ms, operator_identity_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?1, ?6, ?7)",
        params![
            event.digest(),
            enrollment_id,
            kind,
            operation_id,
            event.as_bytes(),
            occurred_at_unix_ms,
            system_identity.as_bytes()
        ],
    )?;
    Ok(())
}

fn failure_streak_on(
    connection: &rusqlite::Connection,
    enrollment_id: &str,
) -> Result<u16, StoreError> {
    let mut statement = connection.prepare(
        "SELECT e.event_kind FROM recurrence_acquisition_events AS e
         JOIN recurrence_acquisitions AS a ON a.acquisition_id = e.acquisition_id
         WHERE a.enrollment_id = ?1 AND e.event_kind IN ('provider_succeeded', 'pre_provider_exhausted', 'provider_terminal_failed')
         ORDER BY e.event_sequence",
    )?;
    let events = statement.query_map([enrollment_id], |row| row.get::<_, String>(0))?;
    let mut streak = 0_u16;
    for event in events {
        if event? == "provider_succeeded" {
            streak = 0;
        } else {
            streak = streak.saturating_add(1);
        }
    }
    Ok(streak)
}

fn enum_json_name<T: Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_value(value)
        .map_err(|error| {
            StoreError::Invariant(format!("closed recurrence enum cannot serialize: {error}"))
        })?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            StoreError::Invariant("closed recurrence enum did not serialize to a string".into())
        })
}

fn validate_bounded(value: &str, name: &str) -> Result<(), StoreError> {
    if valid_ref(value) {
        Ok(())
    } else {
        Err(StoreError::Invariant(format!(
            "{name} is not a bounded identity"
        )))
    }
}

/// Recompute all content identities and state-machine orderings from the
/// append-only recurrence tables during every store validation.
#[allow(clippy::too_many_lines)]
pub(super) fn validate_recurrence_invariants(
    connection: &rusqlite::Connection,
) -> Result<(), StoreError> {
    let mut policies = connection.prepare(
        "SELECT policy_id, policy_json, operator_identity_json
         FROM recurring_office_policies ORDER BY policy_id",
    )?;
    let policy_rows = policies.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for row in policy_rows {
        let (policy_id, bytes, operator) = row?;
        let document = row_document(bytes, "recurring-office policy")?;
        if document.digest() != policy_id {
            return Err(StoreError::Integrity(format!(
                "recurring-office policy {policy_id} digest mismatch"
            )));
        }
        let policy: RecurringOfficePolicyV1 =
            decode(document.as_bytes(), "recurring-office policy")?;
        policy.validate().map_err(refusal_as_store)?;
        row_document(operator, "recurring-office policy operator identity")?;
    }

    let mut enrollments = connection.prepare(
        "SELECT enrollment_id, policy_id, watcher_instance_id,
                watcher_semantic_digest, coordination_domain_id,
                first_eligible_slot, enrollment_json, operator_identity_json
         FROM recurrence_enrollments ORDER BY enrollment_id",
    )?;
    let enrollment_rows = enrollments.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u64>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
        ))
    })?;
    for row in enrollment_rows {
        let (id, policy_id, watcher, watcher_digest, domain, first, bytes, operator) = row?;
        let document = row_document(bytes, "recurrence enrollment")?;
        let value: RecurrenceEnrollmentV1 = decode(document.as_bytes(), "recurrence enrollment")?;
        if value.enrollment_id != id
            || value.spec.policy_id != policy_id
            || value.spec.watcher_instance_id != watcher
            || value.watcher_semantic_digest != watcher_digest
            || value.coordination_domain_id != domain
            || value.first_eligible_slot != first
        {
            return Err(StoreError::Integrity(format!(
                "recurrence enrollment {id} differs from indexed identity fields"
            )));
        }
        let preimage = canonical(&serde_json::json!({
            "schema": RECURRENCE_ENROLLMENT_SCHEMA_V1,
            "spec": &value.spec,
            "watcher_semantic_digest": value.watcher_semantic_digest,
            "coordination_domain_id": value.coordination_domain_id,
            "first_eligible_slot": value.first_eligible_slot,
            "created_at_unix_ms": value.created_at_unix_ms,
        }))?;
        if preimage.digest() != id {
            return Err(StoreError::Integrity(format!(
                "recurrence enrollment {id} content-derived identity mismatch"
            )));
        }
        let policy_bytes: Vec<u8> = connection.query_row(
            "SELECT policy_json FROM recurring_office_policies WHERE policy_id = ?1",
            [&policy_id],
            |row| row.get(0),
        )?;
        let policy: RecurringOfficePolicyV1 =
            decode(&policy_bytes, "recurrence enrollment policy")?;
        let mapping = policy.watcher_binding(&watcher).ok_or_else(|| {
            StoreError::Integrity(format!(
                "recurrence enrollment {id} watcher is absent from its deployment policy"
            ))
        })?;
        if mapping.watcher_semantic_digest != watcher_digest
            || mapping.coordination_domain_id != domain
            || policy.domain(&domain).is_none()
        {
            return Err(StoreError::Integrity(format!(
                "recurrence enrollment {id} differs from its deployment mapping"
            )));
        }
        row_document(operator, "recurrence enrollment operator identity")?;
    }

    let mut acquisitions = connection.prepare(
        "SELECT acquisition_id, enrollment_id, policy_id, slot_id, slot_index,
                scheduled_for_unix_ms, watcher_instance_id,
                watcher_semantic_digest, coordination_domain_id,
                binding_json, binding_digest
         FROM recurrence_acquisitions ORDER BY acquisition_id",
    )?;
    let acquisition_rows = acquisitions.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, u64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, String>(10)?,
        ))
    })?;
    for row in acquisition_rows {
        let (
            id,
            enrollment_id,
            policy_id,
            slot_id,
            slot_index,
            scheduled,
            watcher,
            watcher_digest,
            domain,
            bytes,
            digest,
        ) = row?;
        let document = row_document(bytes, "recurrence acquisition binding")?;
        if document.digest() != digest {
            return Err(StoreError::Integrity(format!(
                "recurrence acquisition {id} binding digest mismatch"
            )));
        }
        let binding: RecurrenceAcquisitionBindingV1 =
            decode(document.as_bytes(), "recurrence acquisition binding")?;
        if binding.acquisition_id != id
            || binding.enrollment_id != enrollment_id
            || binding.policy_id != policy_id
            || binding.slot.slot_id != slot_id
            || binding.slot.slot_index != slot_index
            || binding.slot.scheduled_for_unix_ms != scheduled
            || binding.watcher_instance_id != watcher
            || binding.watcher_semantic_digest != watcher_digest
            || binding.coordination_domain_id != domain
            || acquisition_id_for_slot(&binding.slot) != id
        {
            return Err(StoreError::Integrity(format!(
                "recurrence acquisition {id} differs from exact indexed binding"
            )));
        }
        let slot_preimage = canonical(&serde_json::json!({
            "schema": RECURRENCE_SLOT_SCHEMA_V1,
            "enrollment_id": binding.slot.enrollment_id,
            "slot_index": binding.slot.slot_index,
            "scheduled_for_unix_ms": binding.slot.scheduled_for_unix_ms,
        }))?;
        if slot_preimage.digest() != slot_id {
            return Err(StoreError::Integrity(format!(
                "recurrence acquisition {id} slot identity mismatch"
            )));
        }
        let enrollment =
            recurrence_enrollment_on(connection, &enrollment_id)?.ok_or_else(|| {
                StoreError::Integrity(format!(
                    "recurrence acquisition {id} enrollment disappeared"
                ))
            })?;
        let policy_bytes: Vec<u8> = connection.query_row(
            "SELECT policy_json FROM recurring_office_policies WHERE policy_id = ?1",
            [&policy_id],
            |row| row.get(0),
        )?;
        let policy: RecurringOfficePolicyV1 =
            decode(&policy_bytes, "recurrence acquisition policy")?;
        let domain_policy = policy.domain(&domain).ok_or_else(|| {
            StoreError::Integrity(format!("recurrence acquisition {id} domain disappeared"))
        })?;
        if binding.slot.enrollment_id != enrollment_id
            || binding.interval_ms != enrollment.spec.interval_ms
            || binding.max_pre_provider_attempts != enrollment.spec.max_pre_provider_attempts
            || binding.pre_provider_backoff_ms != enrollment.spec.pre_provider_backoff_ms
            || binding.failure_pause_threshold != enrollment.spec.failure_pause_threshold
            || binding.max_store_bytes != policy.max_store_bytes
            || binding.min_free_bytes != policy.min_free_bytes
            || binding.provider_timeout_ceiling_ms != policy.provider_timeout_ceiling_ms
            || binding.domain_max_in_flight != domain_policy.max_in_flight
            || binding.min_provider_start_spacing_ms != domain_policy.min_provider_start_spacing_ms
        {
            return Err(StoreError::Integrity(format!(
                "recurrence acquisition {id} policy/enrollment snapshot mismatch"
            )));
        }
        validate_recurrence_acquisition_events(connection, &id)?;
    }

    validate_recurrence_slot_events(connection)?;
    validate_recurrence_coordination_events(connection)?;

    let mut events = connection.prepare(
        "SELECT event_id, event_kind, occurred_at_unix_ms, policy_id,
                event_json, operator_identity_json
         FROM recurring_office_policy_events
         UNION ALL
         SELECT event_id, event_kind, occurred_at_unix_ms, enrollment_id,
                event_json, operator_identity_json
         FROM recurrence_enrollment_events",
    )?;
    let rows = events.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    for row in rows {
        let (id, kind, occurred_at, object_id, bytes, operator) = row?;
        let event = row_document(bytes, "recurrence authority event")?;
        if event.digest() != id {
            return Err(StoreError::Integrity(format!(
                "recurrence authority event {id} digest mismatch"
            )));
        }
        let value: Value = decode(event.as_bytes(), "recurrence authority event")?;
        let fields = value.get("fields").ok_or_else(|| {
            StoreError::Integrity(format!("recurrence authority event {id} lacks fields"))
        })?;
        let exact_object = if kind == "activated" {
            fields.get("policy_id")
        } else {
            fields.get("enrollment_id")
        };
        if value.get("schema").and_then(Value::as_str) != Some(RECURRENCE_EVENT_SCHEMA_V1)
            || value.get("event_kind").and_then(Value::as_str) != Some(&kind)
            || value.get("occurred_at_unix_ms").and_then(Value::as_i64) != Some(occurred_at)
            || exact_object.and_then(Value::as_str) != Some(&object_id)
        {
            return Err(StoreError::Integrity(format!(
                "recurrence authority event {id} differs from indexed kind/time"
            )));
        }
        row_document(operator, "recurrence authority-event operator identity")?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_recurrence_acquisition_events(
    connection: &rusqlite::Connection,
    acquisition_id: &str,
) -> Result<(), StoreError> {
    let binding: (String, String, String, String, String, String, String) = connection.query_row(
        "SELECT enrollment_id, policy_id, coordination_domain_id,
                watcher_instance_id, watcher_semantic_digest, slot_id,
                binding_digest
         FROM recurrence_acquisitions WHERE acquisition_id = ?1",
        [acquisition_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        },
    )?;
    let policy_bytes: Vec<u8> = connection.query_row(
        "SELECT policy_json FROM recurring_office_policies WHERE policy_id = ?1",
        [binding.1.as_str()],
        |row| row.get(0),
    )?;
    let policy: RecurringOfficePolicyV1 = decode(&policy_bytes, "recurrence acquisition policy")?;
    let watcher_binding = policy.watcher_binding(&binding.3).ok_or_else(|| {
        StoreError::Integrity(format!(
            "recurrence acquisition {acquisition_id} watcher mapping disappeared"
        ))
    })?;
    let mut statement = connection.prepare(
        "SELECT event_id, event_kind, attempt_number, fencing_epoch,
                occurred_at_unix_ms, event_json
         FROM recurrence_acquisition_events
         WHERE acquisition_id = ?1 ORDER BY event_sequence",
    )?;
    let rows = statement.query_map([acquisition_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u64>(2)?,
            row.get::<_, Option<u64>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut state = "absent";
    let mut provider_started = false;
    let mut held_epoch = None;
    let mut last_attempt = 0_u64;
    for row in rows {
        let (id, kind, attempt, epoch, occurred_at, bytes) = row?;
        let event = row_document(bytes, "recurrence acquisition event")?;
        if event.digest() != id {
            return Err(StoreError::Integrity(format!(
                "recurrence acquisition event {id} digest mismatch"
            )));
        }
        let value: Value = decode(event.as_bytes(), "recurrence acquisition event")?;
        let fields = value.get("fields").ok_or_else(|| {
            StoreError::Integrity(format!("recurrence acquisition event {id} lacks fields"))
        })?;
        if value.get("schema").and_then(Value::as_str) != Some(RECURRENCE_EVENT_SCHEMA_V1)
            || value.get("event_kind").and_then(Value::as_str) != Some(&kind)
            || value.get("occurred_at_unix_ms").and_then(Value::as_i64) != Some(occurred_at)
            || fields.get("acquisition_id").and_then(Value::as_str) != Some(acquisition_id)
            || (kind != "created"
                && (fields.get("attempt_number").and_then(Value::as_u64) != Some(attempt)
                    || fields.get("fencing_epoch").and_then(Value::as_u64) != epoch))
        {
            return Err(StoreError::Integrity(format!(
                "recurrence acquisition event {id} differs from indexed kind/acquisition"
            )));
        }
        if kind == "created"
            && (fields.get("slot_id").and_then(Value::as_str) != Some(binding.5.as_str())
                || fields.get("binding_digest").and_then(Value::as_str) != Some(binding.6.as_str()))
        {
            return Err(StoreError::Integrity(format!(
                "recurrence acquisition event {id} substituted slot/binding custody"
            )));
        }
        if kind == "provider_invocation_started"
            && (fields.get("enrollment_id").and_then(Value::as_str) != Some(binding.0.as_str())
                || fields.get("policy_id").and_then(Value::as_str) != Some(binding.1.as_str())
                || fields.get("coordination_domain_id").and_then(Value::as_str)
                    != Some(binding.2.as_str())
                || fields.get("watcher_instance_id").and_then(Value::as_str)
                    != Some(binding.3.as_str())
                || fields
                    .get("watcher_semantic_digest")
                    .and_then(Value::as_str)
                    != Some(binding.4.as_str())
                || fields.get("origin_profile").and_then(Value::as_str)
                    != Some(watcher_binding.origin_profile.as_str())
                || fields
                    .get("expected_instance_id_sha256")
                    .and_then(Value::as_str)
                    != Some(watcher_binding.expected_instance_id_sha256.as_str())
                || fields.get("origin_helper_issuer").and_then(Value::as_str)
                    != Some(watcher_binding.origin_helper_issuer.as_str())
                || fields.get("origin_helper_key_id").and_then(Value::as_str)
                    != Some(watcher_binding.origin_helper_key_id.as_str()))
        {
            return Err(StoreError::Integrity(format!(
                "recurrence provider fence event {id} substituted exact acquisition/origin custody"
            )));
        }
        match kind.as_str() {
            "created" if state == "absent" && attempt == 0 && epoch.is_none() => state = "created",
            "pre_provider_failed"
                if matches!(state, "created" | "pre_provider_failed")
                    && !provider_started
                    && epoch.is_some()
                    && attempt == last_attempt + 1
                    && held_epoch.is_none_or(|held| Some(held) == epoch) =>
            {
                held_epoch = epoch;
                last_attempt = attempt;
                state = "pre_provider_failed";
            }
            "provider_invocation_started"
                if matches!(state, "created" | "pre_provider_failed")
                    && !provider_started
                    && epoch.is_some()
                    && attempt == last_attempt + 1
                    && held_epoch.is_none_or(|held| Some(held) == epoch) =>
            {
                held_epoch = epoch;
                last_attempt = attempt;
                provider_started = true;
                state = "provider_invocation_started";
            }
            "pre_provider_exhausted"
                if state == "pre_provider_failed"
                    && epoch == held_epoch
                    && attempt == last_attempt =>
            {
                state = "terminal";
            }
            "provider_succeeded" | "provider_terminal_failed"
                if state == "provider_invocation_started"
                    && epoch == held_epoch
                    && attempt == last_attempt =>
            {
                state = "terminal";
            }
            "outcome_unknown"
                if state == "provider_invocation_started"
                    && epoch == held_epoch
                    && attempt == last_attempt =>
            {
                state = "outcome_unknown";
            }
            "provider_succeeded"
                if state == "outcome_unknown" && epoch == held_epoch && attempt == last_attempt =>
            {
                state = "terminal";
            }
            _ => {
                return Err(StoreError::Integrity(format!(
                    "recurrence acquisition {acquisition_id} has invalid event transition {state} -> {kind}"
                )));
            }
        }
    }
    if state == "absent" {
        return Err(StoreError::Integrity(format!(
            "recurrence acquisition {acquisition_id} has no creation event"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_recurrence_slot_events(connection: &rusqlite::Connection) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT event_id, enrollment_id, slot_index, slot_id,
                scheduled_for_unix_ms, event_kind, acquisition_id,
                occurred_at_unix_ms, event_json
         FROM recurrence_slot_events ORDER BY event_sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Vec<u8>>(8)?,
        ))
    })?;
    for row in rows {
        let (
            id,
            enrollment_id,
            slot_index,
            slot_id,
            scheduled,
            kind,
            acquisition,
            occurred_at,
            bytes,
        ) = row?;
        let event = row_document(bytes, "recurrence slot event")?;
        if event.digest() != id {
            return Err(StoreError::Integrity(format!(
                "recurrence slot event {id} digest mismatch"
            )));
        }
        let value: Value = decode(event.as_bytes(), "recurrence slot event")?;
        let fields = value.get("fields").ok_or_else(|| {
            StoreError::Integrity(format!("recurrence slot event {id} lacks fields"))
        })?;
        if value.get("schema").and_then(Value::as_str) != Some(RECURRENCE_EVENT_SCHEMA_V1)
            || value.get("event_kind").and_then(Value::as_str) != Some(&kind)
            || value.get("occurred_at_unix_ms").and_then(Value::as_i64) != Some(occurred_at)
            || fields
                .get("slot")
                .and_then(|slot| slot.get("slot_id"))
                .and_then(Value::as_str)
                != Some(&slot_id)
        {
            return Err(StoreError::Integrity(format!(
                "recurrence slot event {id} differs from indexed kind/slot"
            )));
        }
        let enrollment =
            recurrence_enrollment_on(connection, &enrollment_id)?.ok_or_else(|| {
                StoreError::Integrity(format!("recurrence slot event {id} enrollment disappeared"))
            })?;
        let exact_slot = enrollment.slot(slot_index)?;
        let event_slot: RecurrenceSlotV1 = fields
            .get("slot")
            .cloned()
            .ok_or_else(|| StoreError::Integrity(format!("slot event {id} lacks exact slot")))
            .and_then(|slot| {
                serde_json::from_value(slot).map_err(|error| {
                    StoreError::Integrity(format!("slot event {id} slot cannot decode: {error}"))
                })
            })?;
        if exact_slot.slot_id != slot_id
            || exact_slot.scheduled_for_unix_ms != scheduled
            || event_slot != exact_slot
            || fields.get("acquisition_id").and_then(Value::as_str) != acquisition.as_deref()
        {
            return Err(StoreError::Integrity(format!(
                "recurrence slot event {id} substituted its deterministic slot"
            )));
        }
        match kind.as_str() {
            "acquisition_created" => {
                let acquisition = acquisition.ok_or_else(|| {
                    StoreError::Integrity(format!("slot event {id} lacks acquisition"))
                })?;
                let stored: String = connection.query_row(
                    "SELECT acquisition_id FROM recurrence_acquisitions WHERE slot_id = ?1",
                    [&slot_id],
                    |row| row.get(0),
                )?;
                if stored != acquisition {
                    return Err(StoreError::Integrity(format!(
                        "slot event {id} acquisition binding mismatch"
                    )));
                }
            }
            "skipped" | "clock_rollback" if acquisition.is_none() => {}
            "coordination_deferred" if acquisition.is_some() => {}
            _ => {
                return Err(StoreError::Integrity(format!(
                    "recurrence slot event {id} has invalid acquisition linkage"
                )));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_recurrence_coordination_events(
    connection: &rusqlite::Connection,
) -> Result<(), StoreError> {
    #[derive(Clone)]
    struct State {
        epoch: u64,
        kind: String,
        acquisition: String,
        watcher: String,
    }
    let mut states: BTreeMap<String, State> = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT event_id, coordination_domain_id, fencing_epoch, event_kind,
                holder_acquisition_id, holder_watcher_instance_id,
                occurred_at_unix_ms, event_json
         FROM recurrence_coordination_events ORDER BY event_sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Vec<u8>>(7)?,
        ))
    })?;
    for row in rows {
        let (id, domain, epoch, kind, acquisition, watcher, occurred_at, bytes) = row?;
        let event = row_document(bytes, "recurrence coordination event")?;
        if event.digest() != id {
            return Err(StoreError::Integrity(format!(
                "recurrence coordination event {id} digest mismatch"
            )));
        }
        let value: Value = decode(event.as_bytes(), "recurrence coordination event")?;
        let fields = value.get("fields").ok_or_else(|| {
            StoreError::Integrity(format!("recurrence coordination event {id} lacks fields"))
        })?;
        if value.get("schema").and_then(Value::as_str) != Some(RECURRENCE_EVENT_SCHEMA_V1)
            || value.get("event_kind").and_then(Value::as_str) != Some(&kind)
            || value.get("occurred_at_unix_ms").and_then(Value::as_i64) != Some(occurred_at)
            || fields.get("coordination_domain_id").and_then(Value::as_str) != Some(&domain)
            || fields.get("fencing_epoch").and_then(Value::as_u64) != Some(epoch)
            || fields.get("holder_acquisition_id").and_then(Value::as_str) != Some(&acquisition)
        {
            return Err(StoreError::Integrity(format!(
                "recurrence coordination event {id} differs from indexed custody"
            )));
        }
        let binding: (String, String) = connection.query_row(
            "SELECT coordination_domain_id, watcher_instance_id FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [&acquisition],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if binding != (domain.clone(), watcher.clone()) {
            return Err(StoreError::Integrity(format!(
                "coordination event {id} holder binding mismatch"
            )));
        }
        match kind.as_str() {
            "claimed" => {
                let expected = states
                    .get(&domain)
                    .map_or(1, |state| state.epoch.saturating_add(1));
                if epoch != expected
                    || states
                        .get(&domain)
                        .is_some_and(|state| state.kind != "released")
                {
                    return Err(StoreError::Integrity(format!(
                        "coordination claim {id} violates epoch/ownership order"
                    )));
                }
                states.insert(
                    domain,
                    State {
                        epoch,
                        kind,
                        acquisition,
                        watcher,
                    },
                );
            }
            "released" | "fenced_outcome_unknown" => {
                let prior = states.get(&domain).ok_or_else(|| {
                    StoreError::Integrity(format!("coordination terminal event {id} lacks claim"))
                })?;
                let valid_prior = prior.kind == "claimed"
                    || (kind == "released" && prior.kind == "fenced_outcome_unknown");
                if !valid_prior
                    || prior.epoch != epoch
                    || prior.acquisition != acquisition
                    || prior.watcher != watcher
                {
                    return Err(StoreError::Integrity(format!(
                        "coordination terminal event {id} differs from exact claim"
                    )));
                }
                states.insert(
                    domain,
                    State {
                        epoch,
                        kind,
                        acquisition,
                        watcher,
                    },
                );
            }
            _ => {
                return Err(StoreError::Integrity(format!(
                    "unknown recurrence coordination event {kind}"
                )));
            }
        }
    }
    Ok(())
}

/// Recompute every provider-activity evidence and reconciliation binding.
/// Historical schema-v8 stores contain no rows; migration never synthesizes
/// quiescence for an already-fenced occurrence.
#[allow(clippy::too_many_lines)]
pub(super) fn validate_provider_activity_invariants(
    connection: &rusqlite::Connection,
) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT evidence_id, acquisition_id, enrollment_id, slot_id,
                coordination_domain_id, fencing_epoch, attempt_number, claim,
                producer_schema, evidence_json, observed_at_unix_ms
         FROM provider_activity_evidence ORDER BY evidence_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u64>(5)?,
            row.get::<_, u16>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, i64>(10)?,
        ))
    })?;
    for row in rows {
        let (
            id,
            acquisition_id,
            enrollment_id,
            slot_id,
            domain,
            epoch,
            attempt,
            claim,
            producer,
            bytes,
            observed_at,
        ) = row?;
        let document = row_document(bytes, "provider-activity evidence")?;
        let evidence: ProviderActivityEvidenceV1 =
            decode(document.as_bytes(), "provider-activity evidence")?;
        evidence.validate_identity().map_err(|error| {
            StoreError::Integrity(format!("provider-activity evidence {id}: {error}"))
        })?;
        if document.digest() == id {
            return Err(StoreError::Integrity(format!(
                "provider-activity evidence {id} incorrectly hashes its outer self identity"
            )));
        }
        if evidence.evidence_id != id
            || evidence.acquisition_id != acquisition_id
            || evidence.enrollment_id != enrollment_id
            || evidence.slot_id != slot_id
            || evidence.coordination_domain_id != domain
            || evidence.fencing_epoch != epoch
            || evidence.attempt_number != attempt
            || evidence.claim.as_str() != claim
            || evidence.producer_schema != producer
            || evidence.observed_at_unix_ms != observed_at
        {
            return Err(StoreError::Integrity(format!(
                "provider-activity evidence {id} differs from indexed custody"
            )));
        }
        let binding: (String, String, String) = connection.query_row(
            "SELECT enrollment_id, slot_id, coordination_domain_id
             FROM recurrence_acquisitions WHERE acquisition_id = ?1",
            [&acquisition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if binding != (enrollment_id, slot_id, domain) {
            return Err(StoreError::Integrity(format!(
                "provider-activity evidence {id} substituted recurrence binding"
            )));
        }
        let fence_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM recurrence_acquisition_events
             WHERE acquisition_id = ?1 AND event_kind = 'provider_invocation_started'
               AND attempt_number = ?2 AND fencing_epoch = ?3)",
            params![acquisition_id, attempt, epoch],
            |row| row.get(0),
        )?;
        if !fence_exists {
            return Err(StoreError::Integrity(format!(
                "provider-activity evidence {id} lacks exact provider fence"
            )));
        }
        let claim_matches_runner = match evidence.claim {
            ProviderActivityClaimV1::ProviderNotInvoked => {
                evidence.runner_outcome == "spawn_failed"
            }
            ProviderActivityClaimV1::ProviderQuiescent => matches!(
                evidence.runner_outcome.as_str(),
                "response"
                    | "request_write_failed"
                    | "timeout"
                    | "output_too_large"
                    | "stderr_too_large"
                    | "eof"
                    | "malformed_framing"
                    | "malformed_json"
                    | "exit_nonzero"
            ),
        };
        if !claim_matches_runner {
            return Err(StoreError::Integrity(format!(
                "provider-activity evidence {id} runner outcome cannot prove its claim"
            )));
        }
        let intent_bytes: Vec<u8> = connection.query_row(
            "SELECT intent_json FROM substrate_origin_acquisition_intents
             WHERE acquisition_id = ?1",
            [&acquisition_id],
            |row| row.get(0),
        )?;
        let intent: Value = serde_json::from_slice(&intent_bytes).map_err(|error| {
            StoreError::Integrity(format!(
                "provider-activity evidence {id} substrate intent cannot decode: {error}"
            ))
        })?;
        let text = |path: &str| intent.pointer(path).and_then(Value::as_str);
        if text("/attempt_id") != Some(&evidence.provider_attempt_id)
            || text("/run_id") != Some(&evidence.provider_run_id)
            || text("/request/request_id") != Some(&evidence.provider_request_id)
            || text("/provider/provider_semantic_id") != Some(&evidence.provider_semantic_id)
            || text("/provider/artifact_digest") != Some(&evidence.provider_artifact_digest)
            || text("/provider/execution_identity_digest")
                != Some(&evidence.provider_execution_identity_digest)
            || text("/origin_carrier") != Some("stdio")
        {
            return Err(StoreError::Integrity(format!(
                "provider-activity evidence {id} differs from exact substrate/provider intent"
            )));
        }
    }
    drop(statement);

    let mut reconciliations = connection.prepare(
        "SELECT event_id, acquisition_id, evidence_id, enrollment_id,
                coordination_domain_id, fencing_epoch, disposition, event_json,
                occurred_at_unix_ms
         FROM provider_activity_reconciliation_events ORDER BY event_sequence",
    )?;
    let rows = reconciliations.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u64>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })?;
    for row in rows {
        let (
            id,
            acquisition_id,
            evidence_id,
            enrollment_id,
            domain,
            epoch,
            disposition,
            bytes,
            occurred_at,
        ) = row?;
        let document = row_document(bytes, "provider-activity reconciliation")?;
        if document.digest() != id {
            return Err(StoreError::Integrity(format!(
                "provider-activity reconciliation {id} digest mismatch"
            )));
        }
        let value: Value = decode(document.as_bytes(), "provider-activity reconciliation")?;
        let fields = value.get("fields").ok_or_else(|| {
            StoreError::Integrity(format!(
                "provider-activity reconciliation {id} lacks fields"
            ))
        })?;
        if value.get("schema").and_then(Value::as_str)
            != Some(PROVIDER_ACTIVITY_RECONCILIATION_SCHEMA_V1)
            || value.get("occurred_at_unix_ms").and_then(Value::as_i64) != Some(occurred_at)
            || fields.get("acquisition_id").and_then(Value::as_str) != Some(&acquisition_id)
            || fields.get("evidence_id").and_then(Value::as_str) != Some(&evidence_id)
            || fields.get("enrollment_id").and_then(Value::as_str) != Some(&enrollment_id)
            || fields.get("coordination_domain_id").and_then(Value::as_str) != Some(&domain)
            || fields.get("fencing_epoch").and_then(Value::as_u64) != Some(epoch)
            || fields.get("disposition").and_then(Value::as_str) != Some(&disposition)
            || fields.get("diagnostic_outcome").and_then(Value::as_str) != Some("outcome_unknown")
        {
            return Err(StoreError::Integrity(format!(
                "provider-activity reconciliation {id} differs from indexed custody"
            )));
        }
        let evidence: (String, String, String, u64, String) = connection.query_row(
            "SELECT acquisition_id, enrollment_id, coordination_domain_id,
                    fencing_epoch, claim FROM provider_activity_evidence WHERE evidence_id = ?1",
            [&evidence_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        let expected_disposition = if evidence.4 == "provider_not_invoked" {
            "provider_not_invoked"
        } else {
            "outcome_unknown_provider_quiescent"
        };
        if evidence.0 != acquisition_id
            || evidence.1 != enrollment_id
            || evidence.2 != domain
            || evidence.3 != epoch
            || disposition != expected_disposition
        {
            return Err(StoreError::Integrity(format!(
                "provider-activity reconciliation {id} substituted evidence target"
            )));
        }
        let release_json: Option<Vec<u8>> = connection
            .query_row(
                "SELECT event_json FROM recurrence_coordination_events
             WHERE coordination_domain_id = ?1 AND fencing_epoch = ?2
               AND event_kind = 'released' AND holder_acquisition_id = ?3",
                params![domain, epoch, acquisition_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(release_json) = release_json else {
            return Err(StoreError::Integrity(format!(
                "provider-activity reconciliation {id} lacks exact coordination release"
            )));
        };
        let release: Value = serde_json::from_slice(&release_json).map_err(|error| {
            StoreError::Integrity(format!(
                "provider-activity reconciliation {id} release cannot decode: {error}"
            ))
        })?;
        if release
            .pointer("/fields/provider_activity_reconciliation_event_id")
            .and_then(Value::as_str)
            != Some(&id)
            || release
                .pointer("/fields/diagnostic_outcome")
                .and_then(Value::as_str)
                != Some("outcome_unknown")
        {
            return Err(StoreError::Integrity(format!(
                "provider-activity reconciliation {id} release loses uncertainty binding"
            )));
        }
        let unknown_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM recurrence_acquisition_events
             WHERE acquisition_id = ?1 AND event_kind = 'outcome_unknown'
               AND attempt_number = (SELECT attempt_number FROM provider_activity_evidence WHERE evidence_id = ?2)
               AND fencing_epoch = ?3)",
            params![acquisition_id, evidence_id, epoch],
            |row| row.get(0),
        )?;
        if !unknown_exists {
            return Err(StoreError::Integrity(format!(
                "provider-activity reconciliation {id} lacks exact outcome-unknown history"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type EnrollmentMutation = fn(&mut RecurrenceEnrollmentSpecV1);

    fn policy() -> RecurringOfficePolicyV1 {
        RecurringOfficePolicyV1 {
            schema: RECURRING_OFFICE_POLICY_SCHEMA_V1.into(),
            deployment_profile_ref: "deployment:test/v1".into(),
            min_interval_ms: 1_000,
            max_interval_ms: 60_000,
            min_timer_granularity_ms: 100,
            max_enrollment_lifetime_ms: 600_000,
            max_acquisition_occurrences: 5,
            allowed_missed_slot_policies: BTreeSet::from([
                MissedSlotPolicyV1::Skip,
                MissedSlotPolicyV1::LatestOnly,
            ]),
            allowed_startup_policies: BTreeSet::from([
                StartupPolicyV1::WaitForNextSlot,
                StartupPolicyV1::EvaluateCurrentSlot,
            ]),
            max_pre_provider_attempts: 3,
            min_pre_provider_backoff_ms: 10,
            max_pre_provider_backoff_ms: 500,
            max_consecutive_failure_threshold: 2,
            max_in_flight_per_watcher: 1,
            provider_timeout_ceiling_ms: 5_000,
            max_store_bytes: 10_000_000,
            min_free_bytes: 1_000_000,
            allowed_acquisition_reasons: BTreeSet::from([RECURRENCE_REASON_V1.into()]),
            coordination_domains: vec![CoordinationDomainPolicyV1 {
                domain_id: "domain:test".into(),
                max_in_flight: 1,
                min_provider_start_spacing_ms: 500,
            }],
            watcher_bindings: vec![WatcherCoordinationBindingV1 {
                watcher_instance_id: "watcher-a".into(),
                watcher_semantic_digest: format!("sha256:{}", "1".repeat(64)),
                coordination_domain_id: "domain:test".into(),
                origin_profile: LINODE_ORIGIN_PROFILE_V1.into(),
                expected_instance_id_sha256: format!("sha256:{}", "2".repeat(64)),
                origin_helper_path: "/opt/nq/bin/origin-helper".into(),
                origin_helper_sha256: format!("sha256:{}", "3".repeat(64)),
                origin_helper_account: "nq-origin".into(),
                origin_helper_public_key_path: "/etc/nq/origin.pub".into(),
                origin_helper_issuer: LINODE_ORIGIN_HELPER_ISSUER_V1.into(),
                origin_helper_key_id: "helper:test".into(),
            }],
        }
    }

    fn policy_with_second_watcher(same_domain: bool) -> RecurringOfficePolicyV1 {
        let mut value = policy();
        if !same_domain {
            value.coordination_domains.push(CoordinationDomainPolicyV1 {
                domain_id: "domain:independent".into(),
                max_in_flight: 1,
                min_provider_start_spacing_ms: 500,
            });
        }
        value.watcher_bindings.push(WatcherCoordinationBindingV1 {
            watcher_instance_id: "watcher-b".into(),
            watcher_semantic_digest: format!("sha256:{}", "4".repeat(64)),
            coordination_domain_id: if same_domain {
                "domain:test"
            } else {
                "domain:independent"
            }
            .into(),
            origin_profile: LINODE_ORIGIN_PROFILE_V1.into(),
            expected_instance_id_sha256: format!("sha256:{}", "2".repeat(64)),
            origin_helper_path: "/opt/nq/bin/origin-helper".into(),
            origin_helper_sha256: format!("sha256:{}", "3".repeat(64)),
            origin_helper_account: "nq-origin".into(),
            origin_helper_public_key_path: "/etc/nq/origin.pub".into(),
            origin_helper_issuer: LINODE_ORIGIN_HELPER_ISSUER_V1.into(),
            origin_helper_key_id: "helper:test".into(),
        });
        value
    }

    fn second_enrollment(policy: &RecurringOfficePolicyV1, now: i64) -> RecurrenceEnrollmentV1 {
        let mut spec = enrollment(policy, now).spec;
        spec.operator_occurrence_id = "operator:second-enrollment".into();
        spec.watcher_instance_id = "watcher-b".into();
        RecurrenceEnrollmentV1::new(
            spec,
            policy,
            &format!("sha256:{}", "4".repeat(64)),
            1_000,
            now,
        )
        .expect("second enrollment")
    }

    fn enrollment(policy: &RecurringOfficePolicyV1, now: i64) -> RecurrenceEnrollmentV1 {
        let spec = RecurrenceEnrollmentSpecV1 {
            schema: RECURRENCE_ENROLLMENT_SPEC_SCHEMA_V1.into(),
            operator_occurrence_id: "operator:test-enrollment".into(),
            policy_id: policy.policy_id().expect("policy id"),
            watcher_instance_id: "watcher-a".into(),
            anchor_unix_ms: 1_000,
            interval_ms: 1_000,
            max_acquisition_occurrences: 3,
            expires_at_unix_ms: 20_000,
            missed_slot_policy: MissedSlotPolicyV1::LatestOnly,
            startup_policy: StartupPolicyV1::EvaluateCurrentSlot,
            max_pre_provider_attempts: 2,
            pre_provider_backoff_ms: 100,
            failure_pause_threshold: 2,
            requested_domain_concurrency: 1,
            acquisition_reason: RECURRENCE_REASON_V1.into(),
        };
        RecurrenceEnrollmentV1::new(
            spec,
            policy,
            &format!("sha256:{}", "1".repeat(64)),
            1_000,
            now,
        )
        .expect("enrollment")
    }

    fn operator() -> CanonicalDocument {
        canonical(&serde_json::json!({"uid": 991})).expect("operator")
    }

    fn activated_store(policy: &RecurringOfficePolicyV1) -> Store {
        let mut store = Store::initialize_in_memory().expect("store");
        let id = store
            .register_recurring_office_policy(policy, 1_000, &operator())
            .expect("register");
        store
            .activate_recurring_office_policy(&id, "activate:test", 1_000, &operator())
            .expect("activate");
        store
    }

    fn provider_fence(
        acquisition: &RecurrenceAcquisitionBindingV1,
        epoch: u64,
        attempt: u16,
        now: i64,
    ) -> RecurrenceProviderFenceV1 {
        RecurrenceProviderFenceV1 {
            acquisition_id: acquisition.acquisition_id.clone(),
            enrollment_id: acquisition.enrollment_id.clone(),
            policy_id: acquisition.policy_id.clone(),
            coordination_domain_id: acquisition.coordination_domain_id.clone(),
            fencing_epoch: epoch,
            attempt_number: attempt,
            occurred_at_unix_ms: now,
            watcher_instance_id: acquisition.watcher_instance_id.clone(),
            watcher_semantic_digest: acquisition.watcher_semantic_digest.clone(),
            origin_profile: LINODE_ORIGIN_PROFILE_V1.into(),
            expected_instance_id_sha256: format!("sha256:{}", "2".repeat(64)),
            origin_helper_issuer: LINODE_ORIGIN_HELPER_ISSUER_V1.into(),
            origin_helper_key_id: "helper:test".into(),
        }
    }

    fn finish_success(
        store: &mut Store,
        acquisition: &RecurrenceAcquisitionBindingV1,
        epoch: u64,
        now: i64,
    ) {
        store
            .commit_recurrence_provider_fence(&provider_fence(acquisition, epoch, 1, now))
            .expect("provider fence");
        store
            .finish_recurrence_acquisition(
                &acquisition.acquisition_id,
                "provider_succeeded",
                1,
                Some(epoch),
                now,
                serde_json::json!({}),
            )
            .expect("finish");
    }

    #[test]
    fn deterministic_slots_and_duplicate_ticks_converge() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let enrollment = enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");
        let first = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_000,
            )
            .expect("tick");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = first
        else {
            panic!("expected ready");
        };
        let duplicate = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_000,
            )
            .expect("duplicate");
        let RecurrenceTickPlanV1::Ready {
            acquisition: duplicate_acquisition,
            fencing_epoch: duplicate_epoch,
            ..
        } = duplicate
        else {
            panic!("expected same ready");
        };
        assert_eq!(acquisition, duplicate_acquisition);
        assert_eq!(fencing_epoch, duplicate_epoch);
        assert_eq!(acquisition.slot, enrollment.slot(0).expect("slot"));
    }

    #[test]
    fn forward_jump_is_latest_only_and_rollback_does_not_reopen() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let enrollment = enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                6_000,
            )
            .expect("forward")
        else {
            panic!("ready");
        };
        assert_eq!(acquisition.slot.slot_index, 5);
        finish_success(&mut store, &acquisition, fencing_epoch, 6_000);
        assert!(matches!(
            store
                .plan_recurrence_tick(
                    &enrollment.enrollment_id,
                    &enrollment.watcher_semantic_digest,
                    2_000
                )
                .expect("rollback"),
            RecurrenceTickPlanV1::ClockRollback { .. }
        ));
        let status = store
            .recurrence_status(&enrollment.enrollment_id)
            .expect("status");
        assert_eq!(status.skipped_ranges, vec![(0, 4)]);
    }

    #[test]
    fn unsafe_enrollment_values_refuse_without_clamping() {
        let policy = policy();
        let mut spec = enrollment(&policy, 1_000).spec;
        spec.interval_ms = 499;
        let error = RecurrenceEnrollmentV1::new(
            spec,
            &policy,
            &format!("sha256:{}", "1".repeat(64)),
            1_000,
            1_000,
        )
        .expect_err("unsafe");
        assert_eq!(error.code, "interval_below_deployment_minimum");
    }

    #[test]
    fn deployment_envelope_refuses_each_unsafe_operator_selection() {
        let policy = policy();
        let watcher_digest = format!("sha256:{}", "1".repeat(64));
        let cases: &[(&str, EnrollmentMutation)] = &[
            ("interval_above_deployment_maximum", |spec| {
                spec.interval_ms = 60_001;
            }),
            ("retry_budget_exceeds_policy", |spec| {
                spec.max_pre_provider_attempts = 4;
            }),
            ("failure_threshold_exceeds_policy", |spec| {
                spec.failure_pause_threshold = 3;
            }),
            ("domain_concurrency_exceeds_policy", |spec| {
                spec.requested_domain_concurrency = 2;
            }),
            ("lifetime_exceeds_policy", |spec| {
                spec.expires_at_unix_ms = 700_000;
            }),
        ];
        for (expected, mutate) in cases {
            let mut spec = enrollment(&policy, 1_000).spec;
            mutate(&mut spec);
            let error = RecurrenceEnrollmentV1::new(spec, &policy, &watcher_digest, 1_000, 1_000)
                .expect_err("unsafe selection must refuse");
            assert_eq!(&error.code, expected);
        }

        let mut missed_policy = policy.clone();
        missed_policy.allowed_missed_slot_policies = BTreeSet::from([MissedSlotPolicyV1::Skip]);
        let mut missed_spec = enrollment(&policy, 1_000).spec;
        missed_spec.policy_id = missed_policy.policy_id().expect("missed policy");
        missed_spec.missed_slot_policy = MissedSlotPolicyV1::LatestOnly;
        assert_eq!(
            RecurrenceEnrollmentV1::new(
                missed_spec,
                &missed_policy,
                &watcher_digest,
                1_000,
                1_000,
            )
            .expect_err("disallowed missed-slot mode")
            .code,
            "missed_slot_policy_disallowed"
        );

        let mut startup_policy = policy.clone();
        startup_policy.allowed_startup_policies =
            BTreeSet::from([StartupPolicyV1::WaitForNextSlot]);
        let mut startup_spec = enrollment(&policy, 1_000).spec;
        startup_spec.policy_id = startup_policy.policy_id().expect("startup policy");
        startup_spec.startup_policy = StartupPolicyV1::EvaluateCurrentSlot;
        assert_eq!(
            RecurrenceEnrollmentV1::new(
                startup_spec,
                &startup_policy,
                &watcher_digest,
                1_000,
                1_000,
            )
            .expect_err("disallowed startup mode")
            .code,
            "startup_policy_disallowed"
        );

        let spec = enrollment(&policy, 1_000).spec;
        assert_eq!(
            RecurrenceEnrollmentV1::new(
                spec,
                &policy,
                &watcher_digest,
                policy.provider_timeout_ceiling_ms + 1,
                1_000,
            )
            .expect_err("provider timeout outside envelope")
            .code,
            "provider_timeout_exceeds_policy"
        );

        let mut relational_policy = policy.clone();
        relational_policy.min_interval_ms = 100;
        let mut relational_spec = enrollment(&policy, 1_000).spec;
        relational_spec.policy_id = relational_policy.policy_id().expect("relational policy");
        relational_spec.interval_ms = 100;
        assert_eq!(
            RecurrenceEnrollmentV1::new(
                relational_spec,
                &relational_policy,
                &watcher_digest,
                1_000,
                1_000,
            )
            .expect_err("interval violates domain spacing")
            .code,
            "interval_below_provider_safe_spacing"
        );
    }

    #[test]
    fn policy_profile_identity_changes_enrollment_identity() {
        let first = policy();
        let mut second = first.clone();
        second.deployment_profile_ref = "deployment:test/v2".into();
        let first_enrollment = enrollment(&first, 1_000);
        let mut spec = first_enrollment.spec.clone();
        spec.policy_id = second.policy_id().expect("second policy");
        let second_enrollment = RecurrenceEnrollmentV1::new(
            spec,
            &second,
            &first_enrollment.watcher_semantic_digest,
            1_000,
            1_000,
        )
        .expect("second enrollment");
        assert_ne!(
            first_enrollment.enrollment_id,
            second_enrollment.enrollment_id
        );
    }

    #[test]
    fn duplicate_enrollment_operation_converges_and_substitution_refuses() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let first = enrollment(&policy, 1_000);
        let first_id = store
            .create_recurrence_enrollment(&first, &operator())
            .expect("first enrollment");

        let replay_candidate = RecurrenceEnrollmentV1::new(
            first.spec.clone(),
            &policy,
            &first.watcher_semantic_digest,
            1_000,
            1_500,
        )
        .expect("later replay candidate");
        assert_ne!(
            replay_candidate.enrollment_id, first.enrollment_id,
            "candidate wall time would otherwise create another identity"
        );
        assert_eq!(
            store
                .create_recurrence_enrollment(&replay_candidate, &operator())
                .expect("duplicate operation converges"),
            first_id
        );

        let mut substituted_spec = first.spec.clone();
        substituted_spec.interval_ms = 2_000;
        let substituted = RecurrenceEnrollmentV1::new(
            substituted_spec,
            &policy,
            &first.watcher_semantic_digest,
            1_000,
            1_500,
        )
        .expect("valid but distinct candidate");
        assert!(matches!(
            store.create_recurrence_enrollment(&substituted, &operator()),
            Err(StoreError::ReplayConflict(_))
        ));
    }

    #[test]
    fn retry_retains_slot_acquisition_epoch_and_anchored_future_schedule() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let enrollment = enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_000,
            )
            .expect("tick")
        else {
            panic!("ready");
        };
        store
            .record_recurrence_pre_provider_failure(
                &acquisition.acquisition_id,
                1,
                fencing_epoch,
                1_010,
                serde_json::json!({"reason":"fixture"}),
            )
            .expect("failure");
        assert!(matches!(
            store
                .plan_recurrence_tick(
                    &enrollment.enrollment_id,
                    &enrollment.watcher_semantic_digest,
                    1_109
                )
                .expect("backoff"),
            RecurrenceTickPlanV1::Backoff { .. }
        ));
        let RecurrenceTickPlanV1::Ready {
            acquisition: retry,
            fencing_epoch: retry_epoch,
            attempt_number,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_110,
            )
            .expect("retry")
        else {
            panic!("retry ready");
        };
        assert_eq!(retry.acquisition_id, acquisition.acquisition_id);
        assert_eq!(retry.slot, acquisition.slot);
        assert_eq!(retry_epoch, fencing_epoch);
        assert_eq!(attempt_number, 2);
        assert_eq!(
            enrollment.slot(1).expect("next slot").scheduled_for_unix_ms,
            2_000
        );
    }

    #[test]
    fn outcome_unknown_fences_the_domain_and_operator_resume_refuses() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let enrollment = enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_000,
            )
            .expect("tick")
        else {
            panic!("ready");
        };
        store
            .commit_recurrence_provider_fence(&provider_fence(
                &acquisition,
                fencing_epoch,
                1,
                1_000,
            ))
            .expect("fence");
        store
            .finish_recurrence_acquisition(
                &acquisition.acquisition_id,
                "outcome_unknown",
                1,
                Some(fencing_epoch),
                1_100,
                serde_json::json!({}),
            )
            .expect("unknown");
        assert!(
            store
                .append_recurrence_enrollment_operator_event(
                    &enrollment.enrollment_id,
                    "resumed_operator",
                    "resume:bad",
                    1_200,
                    "cannot know",
                    &operator()
                )
                .is_err()
        );
        let status = store
            .recurrence_status(&enrollment.enrollment_id)
            .expect("status");
        assert!(status.outcome_unknown_fences_domain);
        assert_eq!(status.enrollment_state, "paused_outcome_unknown");
        store
            .append_recurrence_enrollment_operator_event(
                &enrollment.enrollment_id,
                "revoked_operator",
                "retire:unknown-provider",
                1_300,
                "retire future enrollment authority without clearing provider uncertainty",
                &operator(),
            )
            .expect("enrollment may be retired append-only");
        let retired = store
            .recurrence_status(&enrollment.enrollment_id)
            .expect("retired status");
        assert_eq!(retired.enrollment_state, "revoked");
        assert!(
            retired.outcome_unknown_fences_domain,
            "enrollment retirement cannot release the coordination domain"
        );
    }

    #[test]
    fn unqualified_provider_overlap_cannot_bypass_an_outcome_unknown_domain_fence() {
        let policy = policy_with_second_watcher(true);
        let mut store = activated_store(&policy);
        let first = enrollment(&policy, 1_000);
        let second = second_enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&first, &operator())
            .expect("first enroll");
        store
            .create_recurrence_enrollment(&second, &operator())
            .expect("second enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(&first.enrollment_id, &first.watcher_semantic_digest, 1_000)
            .expect("first tick")
        else {
            panic!("first ready");
        };
        store
            .commit_recurrence_provider_fence(&provider_fence(
                &acquisition,
                fencing_epoch,
                1,
                1_000,
            ))
            .expect("provider fence");
        store
            .finish_recurrence_acquisition(
                &acquisition.acquisition_id,
                "outcome_unknown",
                1,
                Some(fencing_epoch),
                1_100,
                serde_json::json!({"reason":"provider_activity_unknown"}),
            )
            .expect("unknown");

        let blocked = store
            .plan_recurrence_tick(
                &second.enrollment_id,
                &second.watcher_semantic_digest,
                1_100,
            )
            .expect("coordination projection");
        assert!(
            matches!(
                blocked,
                RecurrenceTickPlanV1::CoordinationBlocked {
                    ref holder_acquisition_id,
                    ..
                } if holder_acquisition_id == &acquisition.acquisition_id
            ),
            "a same-domain operation cannot turn an unqualified overlap claim into authority: {blocked:?}"
        );
        let second_status = store
            .recurrence_status(&second.enrollment_id)
            .expect("second status");
        assert_eq!(
            second_status.coordination_blocked_reason.as_deref(),
            Some("outcome_unknown_domain_fence")
        );
        assert_eq!(
            store
                .recurrence_acquisition_state(&acquisition.acquisition_id)
                .expect("state")
                .expect("acquisition")
                .event_kind,
            "outcome_unknown"
        );
    }

    #[test]
    fn policy_tightening_does_not_reinterpret_inflight_but_blocks_future_slots() {
        let first = policy();
        let mut store = activated_store(&first);
        let enrollment = enrollment(&first, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_000,
            )
            .expect("tick")
        else {
            panic!("ready");
        };
        let mut tightened = first.clone();
        tightened.max_interval_ms = 30_000;
        tightened.deployment_profile_ref = "deployment:test/tightened".into();
        let second_id = store
            .register_recurring_office_policy(&tightened, 1_050, &operator())
            .expect("register second");
        store
            .activate_recurring_office_policy(&second_id, "activate:tightened", 1_050, &operator())
            .expect("activate");
        let RecurrenceTickPlanV1::Ready {
            acquisition: recovered,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_060,
            )
            .expect("recover")
        else {
            panic!("inflight remains eligible");
        };
        assert_eq!(recovered.policy_id, acquisition.policy_id);
        finish_success(&mut store, &acquisition, fencing_epoch, 1_100);
        assert!(
            matches!(store.plan_recurrence_tick(&enrollment.enrollment_id, &enrollment.watcher_semantic_digest, 2_000).expect("future"), RecurrenceTickPlanV1::EnrollmentUnavailable { state } if state == "deployment_policy_superseded")
        );
    }

    #[test]
    fn stale_fencing_epoch_and_terminal_without_provider_start_refuse() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let enrollment = enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_000,
            )
            .expect("tick")
        else {
            panic!("ready");
        };
        let mut stale = provider_fence(&acquisition, fencing_epoch + 1, 1, 1_000);
        assert!(store.commit_recurrence_provider_fence(&stale).is_err());
        assert!(
            store
                .finish_recurrence_acquisition(
                    &acquisition.acquisition_id,
                    "provider_succeeded",
                    1,
                    Some(fencing_epoch),
                    1_001,
                    serde_json::json!({})
                )
                .is_err()
        );
        stale.fencing_epoch = fencing_epoch;
        store
            .commit_recurrence_provider_fence(&stale)
            .expect("exact fence");
        assert!(store.commit_recurrence_provider_fence(&stale).is_err());
    }

    #[test]
    fn finite_bound_and_exclusive_expiry_stop_future_authority() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let mut bounded = enrollment(&policy, 1_000);
        bounded.spec.max_acquisition_occurrences = 1;
        // Re-materialize identity after changing semantic enrollment bytes.
        bounded = RecurrenceEnrollmentV1::new(
            bounded.spec,
            &policy,
            &format!("sha256:{}", "1".repeat(64)),
            1_000,
            1_000,
        )
        .expect("bounded enrollment");
        store
            .create_recurrence_enrollment(&bounded, &operator())
            .expect("enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(
                &bounded.enrollment_id,
                &bounded.watcher_semantic_digest,
                1_000,
            )
            .expect("tick")
        else {
            panic!("ready");
        };
        finish_success(&mut store, &acquisition, fencing_epoch, 1_100);
        assert!(
            matches!(store.plan_recurrence_tick(&bounded.enrollment_id, &bounded.watcher_semantic_digest, 2_000).expect("exhausted"), RecurrenceTickPlanV1::EnrollmentUnavailable { state } if state == "exhausted")
        );

        let mut expiring = enrollment(&policy, 1_000);
        expiring.spec.operator_occurrence_id = "operator:expiring".into();
        expiring.spec.expires_at_unix_ms = 2_000;
        expiring = RecurrenceEnrollmentV1::new(
            expiring.spec,
            &policy,
            &format!("sha256:{}", "1".repeat(64)),
            1_000,
            1_000,
        )
        .expect("expiring");
        store
            .create_recurrence_enrollment(&expiring, &operator())
            .expect("second enroll");
        assert!(
            matches!(store.plan_recurrence_tick(&expiring.enrollment_id, &expiring.watcher_semantic_digest, 2_000).expect("expiry equality"), RecurrenceTickPlanV1::EnrollmentUnavailable { state } if state == "expired")
        );
    }

    #[test]
    fn same_domain_watchers_serialize_and_provider_spacing_is_global() {
        let policy = policy_with_second_watcher(true);
        let mut store = activated_store(&policy);
        let first = enrollment(&policy, 1_000);
        let second = second_enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&first, &operator())
            .expect("first enroll");
        store
            .create_recurrence_enrollment(&second, &operator())
            .expect("second enroll");
        let RecurrenceTickPlanV1::Ready {
            acquisition: first_acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(&first.enrollment_id, &first.watcher_semantic_digest, 1_000)
            .expect("first")
        else {
            panic!("first ready");
        };
        assert!(matches!(
            store
                .plan_recurrence_tick(
                    &second.enrollment_id,
                    &second.watcher_semantic_digest,
                    1_000
                )
                .expect("second blocked"),
            RecurrenceTickPlanV1::CoordinationBlocked { .. }
        ));
        finish_success(&mut store, &first_acquisition, fencing_epoch, 1_010);
        let spacing = store
            .plan_recurrence_tick(
                &second.enrollment_id,
                &second.watcher_semantic_digest,
                1_100,
            )
            .expect("spacing");
        assert!(
            matches!(spacing, RecurrenceTickPlanV1::Backoff { retry_not_before_unix_ms, .. } if retry_not_before_unix_ms == 1_510),
            "{spacing:?}"
        );
        assert!(matches!(
            store
                .plan_recurrence_tick(
                    &second.enrollment_id,
                    &second.watcher_semantic_digest,
                    1_510
                )
                .expect("unblocked"),
            RecurrenceTickPlanV1::Ready { .. }
        ));
    }

    #[test]
    fn distinct_coordination_domains_may_be_ready_concurrently() {
        let policy = policy_with_second_watcher(false);
        let mut store = activated_store(&policy);
        let first = enrollment(&policy, 1_000);
        let second = second_enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&first, &operator())
            .expect("first enroll");
        store
            .create_recurrence_enrollment(&second, &operator())
            .expect("second enroll");
        assert!(matches!(
            store
                .plan_recurrence_tick(&first.enrollment_id, &first.watcher_semantic_digest, 1_000)
                .expect("first"),
            RecurrenceTickPlanV1::Ready { .. }
        ));
        assert!(matches!(
            store
                .plan_recurrence_tick(
                    &second.enrollment_id,
                    &second.watcher_semantic_digest,
                    1_000
                )
                .expect("second"),
            RecurrenceTickPlanV1::Ready { .. }
        ));
    }

    #[test]
    fn enrollment_cannot_move_watcher_to_another_domain_or_widen_concurrency() {
        let policy = policy_with_second_watcher(false);
        let mut spec = enrollment(&policy, 1_000).spec;
        spec.requested_domain_concurrency = 2;
        let error = RecurrenceEnrollmentV1::new(
            spec,
            &policy,
            &format!("sha256:{}", "1".repeat(64)),
            1_000,
            1_000,
        )
        .expect_err("concurrency refuses");
        assert_eq!(error.code, "domain_concurrency_exceeds_policy");
        let materialized = enrollment(&policy, 1_000);
        assert_eq!(materialized.coordination_domain_id, "domain:test");
    }

    #[test]
    fn startup_and_missed_slot_modes_are_explicit_policy_facts() {
        let policy = policy();
        let mut wait_spec = enrollment(&policy, 1_000).spec;
        wait_spec.operator_occurrence_id = "operator:wait".into();
        wait_spec.startup_policy = StartupPolicyV1::WaitForNextSlot;
        wait_spec.missed_slot_policy = MissedSlotPolicyV1::Skip;
        let wait = RecurrenceEnrollmentV1::new(
            wait_spec,
            &policy,
            &format!("sha256:{}", "1".repeat(64)),
            1_000,
            1_000,
        )
        .expect("wait enrollment");
        assert_eq!(wait.first_eligible_slot, 1);
        let mut store = activated_store(&policy);
        store
            .create_recurrence_enrollment(&wait, &operator())
            .expect("enroll");
        assert!(matches!(
            store
                .plan_recurrence_tick(&wait.enrollment_id, &wait.watcher_semantic_digest, 1_000)
                .expect("startup"),
            RecurrenceTickPlanV1::NotDue {
                next_due_unix_ms: 2_000
            }
        ));
        assert!(
            matches!(store.plan_recurrence_tick(&wait.enrollment_id, &wait.watcher_semantic_digest, 5_000).expect("skip"), RecurrenceTickPlanV1::Noop { reason } if reason == "missed_slots_skipped")
        );
        assert_eq!(
            store
                .recurrence_status(&wait.enrollment_id)
                .expect("status")
                .skipped_ranges,
            vec![(1, 4)]
        );
    }

    #[test]
    fn pause_resume_preserves_anchor_history_and_slot_identity() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let enrollment = enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");
        store
            .append_recurrence_enrollment_operator_event(
                &enrollment.enrollment_id,
                "paused_operator",
                "pause:1",
                1_100,
                "maintenance",
                &operator(),
            )
            .expect("pause");
        assert!(
            matches!(store.plan_recurrence_tick(&enrollment.enrollment_id, &enrollment.watcher_semantic_digest, 2_000).expect("paused"), RecurrenceTickPlanV1::EnrollmentUnavailable { state } if state == "paused_operator")
        );
        store
            .append_recurrence_enrollment_operator_event(
                &enrollment.enrollment_id,
                "resumed_operator",
                "resume:1",
                2_100,
                "continue",
                &operator(),
            )
            .expect("resume");
        let RecurrenceTickPlanV1::Ready { acquisition, .. } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                2_100,
            )
            .expect("tick")
        else {
            panic!("ready");
        };
        assert_eq!(acquisition.slot.slot_index, 1);
        assert_eq!(acquisition.slot.scheduled_for_unix_ms, 2_000);
        assert_eq!(enrollment.spec.anchor_unix_ms, 1_000);
    }

    #[test]
    fn failure_threshold_pauses_and_success_after_explicit_resume_resets_projection() {
        let policy = policy();
        let mut store = activated_store(&policy);
        let enrollment = enrollment(&policy, 1_000);
        store
            .create_recurrence_enrollment(&enrollment, &operator())
            .expect("enroll");

        for (slot_time, terminal_time) in [(1_000, 1_010), (2_000, 2_010)] {
            let RecurrenceTickPlanV1::Ready {
                acquisition,
                fencing_epoch,
                ..
            } = store
                .plan_recurrence_tick(
                    &enrollment.enrollment_id,
                    &enrollment.watcher_semantic_digest,
                    slot_time,
                )
                .expect("failure acquisition")
            else {
                panic!("ready");
            };
            store
                .commit_recurrence_provider_fence(&provider_fence(
                    &acquisition,
                    fencing_epoch,
                    1,
                    slot_time,
                ))
                .expect("provider fence");
            store
                .finish_recurrence_acquisition(
                    &acquisition.acquisition_id,
                    "provider_terminal_failed",
                    1,
                    Some(fencing_epoch),
                    terminal_time,
                    serde_json::json!({"fixture": "terminal"}),
                )
                .expect("terminal failure");
        }
        let paused = store
            .recurrence_status(&enrollment.enrollment_id)
            .expect("paused status");
        assert_eq!(paused.failure_streak, 2);
        assert_eq!(paused.enrollment_state, "paused_failure_threshold");

        store
            .append_recurrence_enrollment_operator_event(
                &enrollment.enrollment_id,
                "resumed_operator",
                "resume:after-failures",
                2_500,
                "explicit bounded continuation",
                &operator(),
            )
            .expect("resume");
        let RecurrenceTickPlanV1::Ready {
            acquisition,
            fencing_epoch,
            ..
        } = store
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                3_000,
            )
            .expect("success acquisition")
        else {
            panic!("ready");
        };
        finish_success(&mut store, &acquisition, fencing_epoch, 3_010);
        let recovered = store
            .recurrence_status(&enrollment.enrollment_id)
            .expect("recovered status");
        assert_eq!(recovered.failure_streak, 0);
        assert_eq!(recovered.enrollment_state, "active");
        assert_eq!(recovered.enrollment.spec.anchor_unix_ms, 1_000);
    }

    #[test]
    fn reopen_recovers_pre_provider_custody_and_never_reopens_provider_started() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("recurrence.sqlite3");
        let policy = policy();
        let enrollment = enrollment(&policy, 1_000);
        let (acquisition, fencing_epoch) = {
            let mut store = Store::initialize(&path).expect("initialize");
            let policy_id = store
                .register_recurring_office_policy(&policy, 1_000, &operator())
                .expect("register");
            store
                .activate_recurring_office_policy(
                    &policy_id,
                    "activate:restart",
                    1_000,
                    &operator(),
                )
                .expect("activate");
            store
                .create_recurrence_enrollment(&enrollment, &operator())
                .expect("enroll");
            let RecurrenceTickPlanV1::Ready {
                acquisition,
                fencing_epoch,
                ..
            } = store
                .plan_recurrence_tick(
                    &enrollment.enrollment_id,
                    &enrollment.watcher_semantic_digest,
                    1_000,
                )
                .expect("tick")
            else {
                panic!("ready");
            };
            (acquisition, fencing_epoch)
        };

        let mut reopened = Store::open(&path).expect("reopen before provider");
        let RecurrenceTickPlanV1::Ready {
            acquisition: recovered,
            fencing_epoch: recovered_epoch,
            ..
        } = reopened
            .plan_recurrence_tick(
                &enrollment.enrollment_id,
                &enrollment.watcher_semantic_digest,
                1_100,
            )
            .expect("recover")
        else {
            panic!("same pre-provider occurrence must recover");
        };
        assert_eq!(recovered.acquisition_id, acquisition.acquisition_id);
        assert_eq!(recovered_epoch, fencing_epoch);
        reopened
            .commit_recurrence_provider_fence(&provider_fence(
                &acquisition,
                fencing_epoch,
                1,
                1_100,
            ))
            .expect("provider fence");
        drop(reopened);

        let mut after_fence = Store::open(&path).expect("reopen after provider fence");
        assert!(matches!(
            after_fence
                .plan_recurrence_tick(
                    &enrollment.enrollment_id,
                    &enrollment.watcher_semantic_digest,
                    1_200,
                )
                .expect("reconcile"),
            RecurrenceTickPlanV1::ReconcileRequired { acquisition_id }
                if acquisition_id == acquisition.acquisition_id
        ));
        after_fence.validate().expect("reopened custody validates");
    }
}
