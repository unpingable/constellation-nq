//! Strict canonical carriers for the ratified host-role runtime records.

use std::collections::BTreeSet;

use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde_json::{Map, Value};

use crate::{
    ContractError, Result,
    capacity::{
        AppendExtentGeometryV1, CAPACITY_IJSON_SAFE_INTEGER_MAX_V1, CapacityCandidateChargeV1,
        CapacityLimitRefusalV1, CapacityLogicalDispositionV1, CapacityLogicalLimitsV1,
        CapacitySemanticComponentsV1, CapacityUsageComponentsV1, CapacityWatermarkClassificationV1,
        CustodyArenaGeometryV1, checked_append_extent_geometry_v1,
        checked_capacity_semantic_sum_v1, checked_custody_arena_geometry_v1,
        checked_logical_preallocated_custody_carriers_v1,
    },
    identity::{
        EffectiveInterval, Generation, IdentityKind, IdentityRef, NamespaceSnapshot, RecordRef,
        Timestamp, Token,
    },
};

const RESERVATION_PLAN_SCHEMA: &str = "nq.custody_reservation_plan.v1";
const RESERVATION_PLAN_DIGEST_DOMAIN: &[u8] = b"nq.custody_reservation_plan.v1\0";
const CAPACITY_ALLOCATION_DIGEST_DOMAIN: &[u8] = b"nq.custody_capacity_allocation.v1\0";
const QUEUE_OCCURRENCE_DIGEST_DOMAIN: &[u8] = b"nq.capacity_queue_occurrence.v1\0";
const DESTINATION_GENERATION_DIGEST_DOMAIN: &[u8] = b"nq.capacity_destination_generation.v1\0";
const DELIVERY_POLICY_GENERATION_DIGEST_DOMAIN: &[u8] =
    b"nq.capacity_delivery_policy_generation.v1\0";
const NEUTRAL_STORE_SNAPSHOT: &str = "nq.capacity-allocation-store-snapshot/v1";
const NEUTRAL_RESERVATION_COMMIT: &str = "nq.capacity-allocation-commit/v1";
const NEUTRAL_CAPACITY_ALLOCATION_ID: &str = "nq.capacity-allocation-id/unbound-v1";
/// Authority-neutral future-artifact slot used before terminal finalization.
pub const CAPACITY_FUTURE_ARTIFACT_SLOT: &str = "nq.future-artifact-slot/unbound-v1";
const RETRYABLE_OUTCOMES: [&str; 4] = [
    "transport_unavailable",
    "transport_timeout",
    "receiver_rate_limited",
    "ambiguous_possible_acceptance",
];
const DELIVERY_STATES: [&str; 11] = [
    "not_required",
    "export_committed",
    "queued",
    "attempt_in_progress",
    "retry_scheduled",
    "delivery_ambiguous",
    "acknowledged_custody",
    "terminal_rejected",
    "attempts_exhausted",
    "blocked_backpressure",
    "committed_unavailable",
];

/// Closed schema set implemented by this package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeSchema {
    /// `nq.role_manifest.v1`.
    RoleManifestV1,
    /// `nq.buffer_delivery_policy.v1`.
    BufferDeliveryPolicyV1,
    /// `nq.static_profile_cohort_manifest.v1`.
    StaticProfileCohortManifestV1,
    /// `nq.node_enrollment.v1`.
    NodeEnrollmentV1,
    /// `nq.host_role_relation.v1`.
    HostRoleRelationV1,
    /// `nq.runtime_activation.v1`.
    RuntimeActivationV1,
    /// `nq.witness_attachment.v1`.
    WitnessAttachmentV1,
    /// `nq.host_role_lifecycle_event.v1`.
    HostRoleLifecycleEventV1,
    /// `nq.witness_lifecycle_event.v1`.
    WitnessLifecycleEventV1,
    /// `nq.node_key_lifecycle_event.v1`.
    NodeKeyLifecycleEventV1,
    /// `nq.restore_activation_proof.v1`.
    RestoreActivationProofV1,
    /// `nq.diagnostic_invocation_request.v1`.
    DiagnosticInvocationRequestV1,
    /// `nq.invocation_decision.v1`.
    InvocationDecisionV1,
    /// `nq.operation_authorization.v1`.
    OperationAuthorizationV1,
    /// `nq.custody_reservation.v1`.
    CustodyReservationV1,
    /// `nq.custody_capacity_allocation.v1`.
    CustodyCapacityAllocationV1,
    /// `nq.execution_launch.v1`.
    ExecutionLaunchV1,
    /// `nq.native_profile_qualification.v1`.
    NativeProfileQualificationV1,
    /// `nq.native_clock_qualification.v1`.
    NativeClockQualificationV1,
    /// `nq.deadline_evaluation.v1`.
    DeadlineEvaluationV1,
    /// `nq.execution_identity_binding.v2`.
    ExecutionIdentityBindingV2,
    /// `nq.authenticated_artifact_envelope.v1`.
    AuthenticatedArtifactEnvelopeV1,
    /// `nq.artifact_delivery_attempt.v1`.
    ArtifactDeliveryAttemptV1,
    /// `nightshift.artifact_custody_receipt.v1`.
    ArtifactCustodyReceiptV1,
    /// `nq.artifact_delivery_record.v1`.
    ArtifactDeliveryRecordV1,
    /// `nq.inspector_result_set.v1`.
    InspectorResultSetV1,
    /// `nq.inspector_snapshot.v1`.
    InspectorSnapshotV1,
    /// `nq.inspector_read_receipt.v1`.
    InspectorReadReceiptV1,
    /// `nq.decommission_ledger_snapshot.v1`.
    DecommissionLedgerSnapshotV1,
    /// `nq.decommission_cut.v1`.
    DecommissionCutV1,
}

/// Immutable provenance package containing one runtime schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaPackageClass {
    /// Schema bytes from the frozen Campaign 3A decision package.
    Frozen3A,
    /// Additive native-profile and native-clock correspondence package.
    NativeCorrespondence,
    /// Additive, content-addressed physical-capacity package.
    Capacity,
}

impl RuntimeSchema {
    /// Every supported record schema.
    pub const ALL: [Self; 30] = [
        Self::RoleManifestV1,
        Self::BufferDeliveryPolicyV1,
        Self::StaticProfileCohortManifestV1,
        Self::NodeEnrollmentV1,
        Self::HostRoleRelationV1,
        Self::RuntimeActivationV1,
        Self::WitnessAttachmentV1,
        Self::HostRoleLifecycleEventV1,
        Self::WitnessLifecycleEventV1,
        Self::NodeKeyLifecycleEventV1,
        Self::RestoreActivationProofV1,
        Self::DiagnosticInvocationRequestV1,
        Self::InvocationDecisionV1,
        Self::OperationAuthorizationV1,
        Self::CustodyReservationV1,
        Self::CustodyCapacityAllocationV1,
        Self::ExecutionLaunchV1,
        Self::NativeProfileQualificationV1,
        Self::NativeClockQualificationV1,
        Self::DeadlineEvaluationV1,
        Self::ExecutionIdentityBindingV2,
        Self::AuthenticatedArtifactEnvelopeV1,
        Self::ArtifactDeliveryAttemptV1,
        Self::ArtifactCustodyReceiptV1,
        Self::ArtifactDeliveryRecordV1,
        Self::InspectorResultSetV1,
        Self::InspectorSnapshotV1,
        Self::InspectorReadReceiptV1,
        Self::DecommissionLedgerSnapshotV1,
        Self::DecommissionCutV1,
    ];

    /// Returns the exact contract schema identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoleManifestV1 => "nq.role_manifest.v1",
            Self::BufferDeliveryPolicyV1 => "nq.buffer_delivery_policy.v1",
            Self::StaticProfileCohortManifestV1 => "nq.static_profile_cohort_manifest.v1",
            Self::NodeEnrollmentV1 => "nq.node_enrollment.v1",
            Self::HostRoleRelationV1 => "nq.host_role_relation.v1",
            Self::RuntimeActivationV1 => "nq.runtime_activation.v1",
            Self::WitnessAttachmentV1 => "nq.witness_attachment.v1",
            Self::HostRoleLifecycleEventV1 => "nq.host_role_lifecycle_event.v1",
            Self::WitnessLifecycleEventV1 => "nq.witness_lifecycle_event.v1",
            Self::NodeKeyLifecycleEventV1 => "nq.node_key_lifecycle_event.v1",
            Self::RestoreActivationProofV1 => "nq.restore_activation_proof.v1",
            Self::DiagnosticInvocationRequestV1 => "nq.diagnostic_invocation_request.v1",
            Self::InvocationDecisionV1 => "nq.invocation_decision.v1",
            Self::OperationAuthorizationV1 => "nq.operation_authorization.v1",
            Self::CustodyReservationV1 => "nq.custody_reservation.v1",
            Self::CustodyCapacityAllocationV1 => "nq.custody_capacity_allocation.v1",
            Self::ExecutionLaunchV1 => "nq.execution_launch.v1",
            Self::NativeProfileQualificationV1 => "nq.native_profile_qualification.v1",
            Self::NativeClockQualificationV1 => "nq.native_clock_qualification.v1",
            Self::DeadlineEvaluationV1 => "nq.deadline_evaluation.v1",
            Self::ExecutionIdentityBindingV2 => "nq.execution_identity_binding.v2",
            Self::AuthenticatedArtifactEnvelopeV1 => "nq.authenticated_artifact_envelope.v1",
            Self::ArtifactDeliveryAttemptV1 => "nq.artifact_delivery_attempt.v1",
            Self::ArtifactCustodyReceiptV1 => "nightshift.artifact_custody_receipt.v1",
            Self::ArtifactDeliveryRecordV1 => "nq.artifact_delivery_record.v1",
            Self::InspectorResultSetV1 => "nq.inspector_result_set.v1",
            Self::InspectorSnapshotV1 => "nq.inspector_snapshot.v1",
            Self::InspectorReadReceiptV1 => "nq.inspector_read_receipt.v1",
            Self::DecommissionLedgerSnapshotV1 => "nq.decommission_ledger_snapshot.v1",
            Self::DecommissionCutV1 => "nq.decommission_cut.v1",
        }
    }

    /// Parses one exact supported schema identity.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::UnknownRuntimeSchema`] for every other value.
    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|schema| schema.as_str() == value)
            .ok_or_else(|| ContractError::UnknownRuntimeSchema(value.to_owned()))
    }

    /// Whether this schema belongs to the additive native-correspondence
    /// extension rather than the frozen 3A source package.
    #[must_use]
    pub const fn is_native_correspondence(self) -> bool {
        matches!(
            self.package_class(),
            SchemaPackageClass::NativeCorrespondence
        )
    }

    /// Whether this schema belongs to the additive capacity extension.
    #[must_use]
    pub const fn is_capacity_extension(self) -> bool {
        matches!(self.package_class(), SchemaPackageClass::Capacity)
    }

    /// Whether this schema belongs to the frozen Campaign 3A package.
    #[must_use]
    pub const fn is_frozen_3a(self) -> bool {
        matches!(self.package_class(), SchemaPackageClass::Frozen3A)
    }

    /// Returns the immutable package class that owns this schema's bytes.
    #[must_use]
    pub const fn package_class(self) -> SchemaPackageClass {
        match self {
            Self::NativeProfileQualificationV1
            | Self::NativeClockQualificationV1
            | Self::DeadlineEvaluationV1 => SchemaPackageClass::NativeCorrespondence,
            Self::CustodyCapacityAllocationV1 => SchemaPackageClass::Capacity,
            _ => SchemaPackageClass::Frozen3A,
        }
    }

    /// Returns the immutable-record identity field.
    #[must_use]
    pub const fn record_id_field(self) -> &'static str {
        match self {
            Self::RoleManifestV1 | Self::StaticProfileCohortManifestV1 => "manifest_id",
            Self::BufferDeliveryPolicyV1 => "policy_id",
            Self::NodeEnrollmentV1 => "enrollment_id",
            Self::HostRoleRelationV1 => "relation_id",
            Self::RuntimeActivationV1 => "activation_id",
            Self::WitnessAttachmentV1 => "attachment_id",
            Self::DiagnosticInvocationRequestV1 => "request_digest",
            Self::InvocationDecisionV1 => "decision_id",
            Self::OperationAuthorizationV1 => "authorization_id",
            Self::CustodyReservationV1 => "reservation_id",
            Self::CustodyCapacityAllocationV1 => "allocation_id",
            Self::ExecutionLaunchV1 => "launch_id",
            Self::NativeProfileQualificationV1 | Self::NativeClockQualificationV1 => {
                "qualification_id"
            }
            Self::DeadlineEvaluationV1 => "evaluation_id",
            Self::ExecutionIdentityBindingV2 => "binding_id",
            Self::AuthenticatedArtifactEnvelopeV1 => "envelope_id",
            Self::ArtifactDeliveryAttemptV1 => "attempt_record_id",
            Self::ArtifactCustodyReceiptV1 | Self::InspectorReadReceiptV1 => "receipt_id",
            Self::ArtifactDeliveryRecordV1 => "delivery_record_id",
            Self::InspectorResultSetV1 | Self::DecommissionLedgerSnapshotV1 => "snapshot_id",
            Self::InspectorSnapshotV1 => "page_response_id",
            Self::HostRoleLifecycleEventV1
            | Self::WitnessLifecycleEventV1
            | Self::NodeKeyLifecycleEventV1 => "event_id",
            Self::RestoreActivationProofV1 => "proof_id",
            Self::DecommissionCutV1 => "cut_id",
        }
    }

    #[allow(clippy::too_many_lines)] // Closed per-schema top-level shape table.
    fn required_fields(self) -> &'static [&'static str] {
        match self {
            Self::RoleManifestV1 => &[
                "schema",
                "manifest_id",
                "namespace",
                "role",
                "generation",
                "effective_interval",
                "subject_scope_classes",
                "capability_classes",
                "permitted_profiles",
                "witness_slots",
                "custody_policy",
                "buffer_policy",
                "delivery_policy",
                "buffer_delivery_policy_record",
                "compatible_static_profile_cohorts",
                "nonclaims",
            ],
            Self::BufferDeliveryPolicyV1 => &[
                "schema",
                "policy_id",
                "namespace",
                "generation",
                "policy_identities",
                "effective_interval",
                "capacity",
                "reservation",
                "ordering",
                "duplicate_law",
                "retry",
                "offline",
                "backpressure",
                "acknowledgement",
                "nonclaims",
            ],
            Self::StaticProfileCohortManifestV1 => &[
                "schema",
                "manifest_id",
                "namespace",
                "cohort",
                "generation",
                "effective_interval",
                "members",
                "compatible_builds",
                "protocol_store_compatibility",
                "qualification_records",
                "nonclaims",
            ],
            Self::NodeEnrollmentV1 => &[
                "schema",
                "enrollment_id",
                "namespace",
                "node",
                "store_genesis_id",
                "enrolled_at",
                "enrollment_authorization",
                "initial_key",
                "initial_relations",
                "deployment_generation",
                "configuration_generation",
                "lineage",
                "nonclaims",
            ],
            Self::HostRoleRelationV1 => &[
                "schema",
                "relation_id",
                "namespace",
                "relation_kind",
                "left",
                "right",
                "generation",
                "effective_interval",
                "administrative_authorization",
                "continuity_decision",
                "nonclaims",
            ],
            Self::RuntimeActivationV1 => &[
                "schema",
                "activation_id",
                "namespace",
                "node",
                "enrollment",
                "role_scope",
                "generation",
                "relations",
                "role",
                "role_manifest",
                "role_generation",
                "static_profile_cohort",
                "cohort_manifest",
                "cohort_generation",
                "deployment_generation",
                "configuration_generation",
                "active_key",
                "witness_attachments",
                "effective_interval",
                "activation_authorization",
                "nonclaims",
            ],
            Self::WitnessAttachmentV1 => &[
                "schema",
                "attachment_id",
                "namespace",
                "generation",
                "node",
                "enrollment",
                "role",
                "role_manifest",
                "role_slot",
                "witness_class",
                "witness",
                "provider",
                "provider_build",
                "provider_admission",
                "privileges",
                "namespaces",
                "resources",
                "supported_profiles",
                "effective_interval",
                "initial_state",
                "attachment_authorization",
                "nonclaims",
            ],
            Self::HostRoleLifecycleEventV1 => &[
                "schema",
                "event_id",
                "namespace",
                "node",
                "operation",
                "from_state",
                "to_state",
                "occurred_at",
                "administrative_authorization",
                "predecessor_events",
                "input_records",
                "result_records",
                "reason",
                "nonclaims",
            ],
            Self::WitnessLifecycleEventV1 => &[
                "schema",
                "event_id",
                "namespace",
                "node",
                "attachment",
                "witness",
                "attachment_generation",
                "operation",
                "from_state",
                "to_state",
                "occurred_at",
                "administrative_authorization",
                "predecessor_event",
                "input_records",
                "result_records",
                "reason",
                "nonclaims",
            ],
            Self::NodeKeyLifecycleEventV1 => &[
                "schema",
                "event_id",
                "namespace",
                "node",
                "key",
                "key_generation",
                "verification_material",
                "operation",
                "from_state",
                "to_state",
                "occurred_at",
                "administrative_authorization",
                "transition_bundle",
                "predecessor_event",
                "replacement_key_event",
                "resulting_activation",
                "nonclaims",
            ],
            Self::RestoreActivationProofV1 => &[
                "schema",
                "proof_id",
                "namespace",
                "node",
                "predecessor_enrollment",
                "restore_operation",
                "restored_snapshot_manifest",
                "restored_store_genesis_id",
                "source_deployment_generation",
                "new_deployment_generation",
                "administrative_authorization",
                "closure_verification",
                "prior_occurrence_fencing",
                "identity_uniqueness",
                "key_revalidation",
                "binding_revalidation",
                "new_key_event",
                "activation_candidate",
                "decision",
                "decided_at",
                "evaluator",
                "nonclaims",
            ],
            Self::DiagnosticInvocationRequestV1 => &[
                "schema",
                "request_id",
                "request_preimage_digest",
                "request_digest",
                "namespace",
                "requesting_principal",
                "authentication_evidence",
                "invocation_authorization",
                "target",
                "profile",
                "purpose",
                "expected_binding",
                "time_bounds",
                "idempotency",
                "delivery",
                "nonclaims",
            ],
            Self::InvocationDecisionV1 => &[
                "schema",
                "decision_id",
                "request",
                "request_digest",
                "activation_snapshot",
                "authentication_evidence",
                "invocation_authorization",
                "decision",
                "policy",
                "decided_at",
                "clock",
                "custody",
                "nonclaims",
            ],
            Self::OperationAuthorizationV1 => &[
                "schema",
                "authorization_id",
                "scope",
                "authorizing_principal",
                "requesting_principal",
                "operation",
                "binding",
                "effective_interval",
                "policy",
                "decision",
                "nonclaims",
            ],
            Self::CustodyReservationV1 => &[
                "schema",
                "reservation_id",
                "namespace",
                "node",
                "request",
                "activation",
                "profile",
                "custody_policy",
                "delivery_requirement",
                "store_snapshot",
                "calculation_rule",
                "component_bounds",
                "total_required_bytes",
                "reserved_bytes",
                "protected_failure_reserve_bytes",
                "decision",
                "reservation_commit",
                "reserved_at",
                "expires_at",
                "clock",
                "nonclaims",
            ],
            Self::CustodyCapacityAllocationV1 => &[
                "schema",
                "allocation_id",
                "namespace",
                "store_genesis_id",
                "store_integrity_key_generation",
                "predecessor_capacity",
                "policy",
                "rules",
                "before_snapshot",
                "request_occurrence",
                "reservation_plan",
                "plan_digest",
                "semantic_components",
                "semantic_sum_bytes",
                "carrier_bounds",
                "arena_layout",
                "canonical_record_extent",
                "delivery_ledger_extent",
                "retained_charge_bytes",
                "queue",
                "limits",
                "logical_preallocated_carrier_bytes_after",
                "watermark_classification",
                "decision",
                "refusal_reasons",
                "calculated_at",
                "clock",
                "nonclaims",
            ],
            Self::ExecutionLaunchV1 => &[
                "schema",
                "launch_id",
                "namespace",
                "node",
                "outer_request",
                "invocation_decision",
                "activation_snapshot",
                "custody_reservation",
                "profile",
                "selected_witness_attachments",
                "prelaunch_checks",
                "launch_commit",
                "launched_at",
                "attempt_deadline",
                "maximum_execution_ms",
                "clock",
                "status",
                "nonclaims",
            ],
            Self::NativeProfileQualificationV1 => &[
                "schema",
                "qualification_id",
                "namespace",
                "cohort",
                "cohort_generation",
                "cohort_semantics_digest",
                "production_profile",
                "production_question",
                "production_build",
                "native_profile",
                "native_evaluator",
                "qualification_evidence",
                "nonclaims",
            ],
            Self::NativeClockQualificationV1 => &[
                "schema",
                "qualification_id",
                "namespace",
                "cohort",
                "cohort_generation",
                "cohort_semantics_digest",
                "production_clock",
                "production_build",
                "platform",
                "absolute_time",
                "boottime",
                "wall_to_monotonic_bridge",
                "runner_watchdog",
                "qualification_evidence",
                "nonclaims",
            ],
            Self::DeadlineEvaluationV1 => &[
                "schema",
                "evaluation_id",
                "namespace",
                "outer_request",
                "activation",
                "clock_qualification",
                "clock",
                "request_bounds",
                "bracket_policy",
                "sample",
                "derived",
                "decision",
                "nonclaims",
            ],
            Self::ExecutionIdentityBindingV2 => &[
                "schema",
                "binding_id",
                "diagnostic",
                "namespace",
                "resolver",
                "outer_request",
                "invocation_decision",
                "execution_launch",
                "enrollment",
                "activation",
                "source_relations",
                "role_manifest",
                "static_profile_cohort_manifest",
                "witness_attachments",
                "provider_attempts",
                "resolved_references",
                "binding_result",
                "nonclaims",
            ],
            Self::AuthenticatedArtifactEnvelopeV1 => &[
                "schema",
                "envelope_id",
                "created_at",
                "artifact",
                "execution_binding",
                "producer_node",
                "producer_activation",
                "producer_key_generation",
                "intended_receiver",
                "destination_generation",
                "transport_policy",
                "authentication",
                "replay_key",
                "nonclaims",
            ],
            Self::ArtifactDeliveryAttemptV1 => &[
                "schema",
                "attempt_record_id",
                "attempt_occurrence_id",
                "attempt_number",
                "envelope",
                "artifact",
                "producer_node",
                "producer_key_generation",
                "destination",
                "destination_generation",
                "transport",
                "transport_policy",
                "started_at",
                "completed_at",
                "outcome",
                "predecessor_attempt_record",
                "next_attempt_not_before",
                "response_evidence",
                "nonclaims",
            ],
            Self::ArtifactCustodyReceiptV1 => &[
                "schema",
                "receipt_id",
                "received_at",
                "receiver",
                "receiver_key_generation",
                "authenticated_sender",
                "producer_key_generation",
                "destination_generation",
                "transport_policy",
                "envelope",
                "attempt",
                "artifact",
                "producer_authentication",
                "receipt_authentication",
                "replay",
                "custody",
                "semantic_admission",
                "nonclaims",
            ],
            Self::ArtifactDeliveryRecordV1 => &[
                "schema",
                "delivery_record_id",
                "artifact",
                "producer_node",
                "producer_key_generation",
                "destination",
                "destination_generation",
                "transport_policy",
                "state",
                "occurred_at",
                "predecessor",
                "envelope",
                "attempt",
                "receiver_custody_receipt",
                "next_attempt_not_before",
                "terminal_reason",
                "nonclaims",
            ],
            Self::InspectorResultSetV1 => &[
                "schema",
                "snapshot_id",
                "created_at",
                "ledger_generation",
                "ledger_commit",
                "query",
                "result_records",
                "index_state",
                "completeness",
                "nonclaims",
            ],
            Self::InspectorSnapshotV1 => &[
                "schema",
                "page_response_id",
                "snapshot",
                "snapshot_id",
                "query_digest",
                "created_at",
                "page",
                "cursor",
                "canonical_records",
                "projections",
                "ephemeral_observations",
                "nonclaims",
            ],
            Self::InspectorReadReceiptV1 => &[
                "schema",
                "receipt_id",
                "query_occurrence_id",
                "query_digest",
                "requesting_principal",
                "authentication_evidence",
                "sensitive_read_authorization",
                "access_policy",
                "decision",
                "decision_reason",
                "decided_at",
                "page_response",
                "retrieved_records",
                "page_response_digest",
                "page_response_bytes",
                "nonclaims",
            ],
            Self::DecommissionLedgerSnapshotV1 => &[
                "schema",
                "snapshot_id",
                "namespace",
                "node",
                "enrollment",
                "activation",
                "store_checkpoint",
                "evaluated_at",
                "evaluator",
                "ledger_entries",
                "ledger_entry_count",
                "ledger_entries_digest",
                "accepted_not_launched",
                "in_flight",
                "committed_deliveries",
                "nonclaims",
            ],
            Self::DecommissionCutV1 => &[
                "schema",
                "cut_id",
                "namespace",
                "node",
                "enrollment",
                "activation",
                "administrative_authorization",
                "predecessor_cut",
                "effective_at",
                "fence_transaction_id",
                "ledger_snapshot",
                "accepted_prestart_dispositions",
                "in_flight",
                "committed_deliveries",
                "unresolved_counts",
                "new_request_policy",
                "historical_read_policy",
                "result_state",
                "nonclaims",
            ],
        }
    }

    fn optional_fields(self) -> &'static [&'static str] {
        match self {
            Self::HostRoleLifecycleEventV1 => &["operation_proof"],
            _ => &[],
        }
    }
}

/// One strict record body. Its map is private so validated instances cannot be
/// mutated into a different record.
#[derive(Debug, Clone, PartialEq)]
struct StrictRecord {
    schema: RuntimeSchema,
    value: Value,
    record_id: Sha256Digest,
}

impl StrictRecord {
    fn parse(value: Value) -> Result<Self> {
        let object = value.as_object().ok_or(ContractError::RecordMustBeObject)?;
        let schema_text = object
            .get("schema")
            .and_then(Value::as_str)
            .ok_or(ContractError::MissingSchema)?;
        let schema = RuntimeSchema::parse(schema_text)?;
        require_exact_fields(
            object,
            schema.required_fields(),
            schema.optional_fields(),
            schema,
        )?;
        let record_id: Sha256Digest = serde_json::from_value(
            object
                .get(schema.record_id_field())
                .cloned()
                .ok_or(ContractError::MissingRecordId)?,
        )?;

        validate_common_value(&value)?;
        validate_local_semantics(schema, object)?;
        crate::schema::validate(schema, &value)?;
        Ok(Self {
            schema,
            value,
            record_id,
        })
    }

    fn as_value(&self) -> &Value {
        &self.value
    }

    fn field(&self, field: &'static str) -> Result<&Value> {
        self.value.get(field).ok_or(ContractError::MissingField {
            schema: self.schema,
            field,
        })
    }
}

macro_rules! carrier_types {
    ($(($variant:ident, $name:ident)),+ $(,)?) => {
        $(
            #[doc = concat!("Strict carrier for `", stringify!($name), "`.")]
            #[derive(Debug, Clone, PartialEq)]
            pub struct $name(StrictRecord);

            impl $name {
                /// Returns the immutable record as JSON.
                #[must_use]
                pub fn as_value(&self) -> &Value {
                    self.0.as_value()
                }

                /// Returns one required field.
                ///
                /// # Errors
                ///
                /// This only errors if an internal invariant was violated.
                pub fn field(&self, field: &'static str) -> Result<&Value> {
                    self.0.field(field)
                }

                /// Returns the declared immutable record identity.
                #[must_use]
                pub fn record_id(&self) -> &Sha256Digest {
                    &self.0.record_id
                }
            }
        )+

        /// Closed typed record set supported by the host-role package.
        #[derive(Debug, Clone, PartialEq)]
        pub enum RuntimeRecord {
            $(
                #[doc = concat!(stringify!($name), " record.")]
                $variant($name),
            )+
        }
    };
}

carrier_types!(
    (RoleManifest, RoleManifest),
    (BufferDeliveryPolicy, BufferDeliveryPolicy),
    (StaticProfileCohortManifest, StaticProfileCohortManifest),
    (NodeEnrollment, NodeEnrollment),
    (HostRoleRelation, HostRoleRelation),
    (RuntimeActivation, RuntimeActivation),
    (WitnessAttachment, WitnessAttachment),
    (HostRoleLifecycleEvent, HostRoleLifecycleEvent),
    (WitnessLifecycleEvent, WitnessLifecycleEvent),
    (NodeKeyLifecycleEvent, NodeKeyLifecycleEvent),
    (RestoreActivationProof, RestoreActivationProof),
    (DiagnosticInvocationRequest, DiagnosticInvocationRequest),
    (InvocationDecision, InvocationDecision),
    (OperationAuthorization, OperationAuthorization),
    (CustodyReservation, CustodyReservation),
    (CustodyCapacityAllocation, CustodyCapacityAllocation),
    (ExecutionLaunch, ExecutionLaunch),
    (NativeProfileQualification, NativeProfileQualification),
    (NativeClockQualification, NativeClockQualification),
    (DeadlineEvaluation, DeadlineEvaluation),
    (ExecutionIdentityBindingV2, ExecutionIdentityBindingV2),
    (AuthenticatedArtifactEnvelope, AuthenticatedArtifactEnvelope),
    (ArtifactDeliveryAttempt, ArtifactDeliveryAttempt),
    (ArtifactCustodyReceipt, ArtifactCustodyReceipt),
    (ArtifactDeliveryRecord, ArtifactDeliveryRecord),
    (InspectorResultSet, InspectorResultSet),
    (InspectorSnapshot, InspectorSnapshot),
    (InspectorReadReceipt, InspectorReadReceipt),
    (DecommissionLedgerSnapshot, DecommissionLedgerSnapshot),
    (DecommissionCut, DecommissionCut),
);

impl RuntimeRecord {
    fn parse(value: Value) -> Result<Self> {
        let record = StrictRecord::parse(value)?;
        Ok(match record.schema {
            RuntimeSchema::RoleManifestV1 => Self::RoleManifest(RoleManifest(record)),
            RuntimeSchema::BufferDeliveryPolicyV1 => {
                Self::BufferDeliveryPolicy(BufferDeliveryPolicy(record))
            }
            RuntimeSchema::StaticProfileCohortManifestV1 => {
                Self::StaticProfileCohortManifest(StaticProfileCohortManifest(record))
            }
            RuntimeSchema::NodeEnrollmentV1 => Self::NodeEnrollment(NodeEnrollment(record)),
            RuntimeSchema::HostRoleRelationV1 => Self::HostRoleRelation(HostRoleRelation(record)),
            RuntimeSchema::RuntimeActivationV1 => {
                Self::RuntimeActivation(RuntimeActivation(record))
            }
            RuntimeSchema::WitnessAttachmentV1 => {
                Self::WitnessAttachment(WitnessAttachment(record))
            }
            RuntimeSchema::HostRoleLifecycleEventV1 => {
                Self::HostRoleLifecycleEvent(HostRoleLifecycleEvent(record))
            }
            RuntimeSchema::WitnessLifecycleEventV1 => {
                Self::WitnessLifecycleEvent(WitnessLifecycleEvent(record))
            }
            RuntimeSchema::NodeKeyLifecycleEventV1 => {
                Self::NodeKeyLifecycleEvent(NodeKeyLifecycleEvent(record))
            }
            RuntimeSchema::RestoreActivationProofV1 => {
                Self::RestoreActivationProof(RestoreActivationProof(record))
            }
            RuntimeSchema::DiagnosticInvocationRequestV1 => {
                Self::DiagnosticInvocationRequest(DiagnosticInvocationRequest(record))
            }
            RuntimeSchema::InvocationDecisionV1 => {
                Self::InvocationDecision(InvocationDecision(record))
            }
            RuntimeSchema::OperationAuthorizationV1 => {
                Self::OperationAuthorization(OperationAuthorization(record))
            }
            RuntimeSchema::CustodyReservationV1 => {
                Self::CustodyReservation(CustodyReservation(record))
            }
            RuntimeSchema::CustodyCapacityAllocationV1 => {
                Self::CustodyCapacityAllocation(CustodyCapacityAllocation(record))
            }
            RuntimeSchema::ExecutionLaunchV1 => Self::ExecutionLaunch(ExecutionLaunch(record)),
            RuntimeSchema::NativeProfileQualificationV1 => {
                Self::NativeProfileQualification(NativeProfileQualification(record))
            }
            RuntimeSchema::NativeClockQualificationV1 => {
                Self::NativeClockQualification(NativeClockQualification(record))
            }
            RuntimeSchema::DeadlineEvaluationV1 => {
                Self::DeadlineEvaluation(DeadlineEvaluation(record))
            }
            RuntimeSchema::ExecutionIdentityBindingV2 => {
                Self::ExecutionIdentityBindingV2(ExecutionIdentityBindingV2(record))
            }
            RuntimeSchema::AuthenticatedArtifactEnvelopeV1 => {
                Self::AuthenticatedArtifactEnvelope(AuthenticatedArtifactEnvelope(record))
            }
            RuntimeSchema::ArtifactDeliveryAttemptV1 => {
                Self::ArtifactDeliveryAttempt(ArtifactDeliveryAttempt(record))
            }
            RuntimeSchema::ArtifactCustodyReceiptV1 => {
                Self::ArtifactCustodyReceipt(ArtifactCustodyReceipt(record))
            }
            RuntimeSchema::ArtifactDeliveryRecordV1 => {
                Self::ArtifactDeliveryRecord(ArtifactDeliveryRecord(record))
            }
            RuntimeSchema::InspectorResultSetV1 => {
                Self::InspectorResultSet(InspectorResultSet(record))
            }
            RuntimeSchema::InspectorSnapshotV1 => {
                Self::InspectorSnapshot(InspectorSnapshot(record))
            }
            RuntimeSchema::InspectorReadReceiptV1 => {
                Self::InspectorReadReceipt(InspectorReadReceipt(record))
            }
            RuntimeSchema::DecommissionLedgerSnapshotV1 => {
                Self::DecommissionLedgerSnapshot(DecommissionLedgerSnapshot(record))
            }
            RuntimeSchema::DecommissionCutV1 => Self::DecommissionCut(DecommissionCut(record)),
        })
    }

    fn strict(&self) -> &StrictRecord {
        match self {
            Self::RoleManifest(value) => &value.0,
            Self::BufferDeliveryPolicy(value) => &value.0,
            Self::StaticProfileCohortManifest(value) => &value.0,
            Self::NodeEnrollment(value) => &value.0,
            Self::HostRoleRelation(value) => &value.0,
            Self::RuntimeActivation(value) => &value.0,
            Self::WitnessAttachment(value) => &value.0,
            Self::HostRoleLifecycleEvent(value) => &value.0,
            Self::WitnessLifecycleEvent(value) => &value.0,
            Self::NodeKeyLifecycleEvent(value) => &value.0,
            Self::RestoreActivationProof(value) => &value.0,
            Self::DiagnosticInvocationRequest(value) => &value.0,
            Self::InvocationDecision(value) => &value.0,
            Self::OperationAuthorization(value) => &value.0,
            Self::CustodyReservation(value) => &value.0,
            Self::CustodyCapacityAllocation(value) => &value.0,
            Self::ExecutionLaunch(value) => &value.0,
            Self::NativeProfileQualification(value) => &value.0,
            Self::NativeClockQualification(value) => &value.0,
            Self::DeadlineEvaluation(value) => &value.0,
            Self::ExecutionIdentityBindingV2(value) => &value.0,
            Self::AuthenticatedArtifactEnvelope(value) => &value.0,
            Self::ArtifactDeliveryAttempt(value) => &value.0,
            Self::ArtifactCustodyReceipt(value) => &value.0,
            Self::ArtifactDeliveryRecord(value) => &value.0,
            Self::InspectorResultSet(value) => &value.0,
            Self::InspectorSnapshot(value) => &value.0,
            Self::InspectorReadReceipt(value) => &value.0,
            Self::DecommissionLedgerSnapshot(value) => &value.0,
            Self::DecommissionCut(value) => &value.0,
        }
    }

    /// Returns the exact schema.
    #[must_use]
    pub fn schema(&self) -> RuntimeSchema {
        self.strict().schema
    }

    /// Returns the declared immutable record identity.
    #[must_use]
    pub fn record_id(&self) -> &Sha256Digest {
        &self.strict().record_id
    }

    /// Returns the immutable JSON value.
    #[must_use]
    pub fn as_value(&self) -> &Value {
        self.strict().as_value()
    }

    /// Replays local carrier and self-identity validation.
    ///
    /// # Errors
    ///
    /// Returns the exact typed refusal for malformed carrier semantics.
    pub fn validate(&self) -> Result<()> {
        StrictRecord::parse(self.as_value().clone()).map(|_| ())
    }
}

/// One locally validated record plus its exact canonical bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedRuntimeRecord {
    record: RuntimeRecord,
    canonical_bytes: Vec<u8>,
    bytes_digest: Sha256Digest,
}

impl ValidatedRuntimeRecord {
    /// Decodes exact RFC 8785 canonical bytes.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical bytes, duplicate-key JSON, unsupported schemas,
    /// unknown fields, malformed shared carriers, and failed local invariants.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        let canonical = canonical_json_bytes(&value)?;
        if canonical != bytes {
            return Err(ContractError::NonCanonicalRecord);
        }
        Self::from_canonical_value(value, canonical)
    }

    /// Validates a JSON value and canonicalizes it.
    ///
    /// # Errors
    ///
    /// Returns the same carrier errors as [`Self::decode_canonical`], except
    /// that input serialization order is intentionally not retained.
    pub fn validate_value(value: Value) -> Result<Self> {
        let canonical = canonical_json_bytes(&value)?;
        Self::from_canonical_value(value, canonical)
    }

    fn from_canonical_value(value: Value, canonical_bytes: Vec<u8>) -> Result<Self> {
        let record = RuntimeRecord::parse(value)?;
        let bytes_digest = sha256_bytes(&canonical_bytes);
        Ok(Self {
            record,
            canonical_bytes,
            bytes_digest,
        })
    }

    /// Returns the typed runtime record.
    #[must_use]
    pub fn record(&self) -> &RuntimeRecord {
        &self.record
    }

    /// Returns the exact schema.
    #[must_use]
    pub fn schema(&self) -> RuntimeSchema {
        self.record.schema()
    }

    /// Returns the declared immutable record identity.
    #[must_use]
    pub fn record_id(&self) -> &Sha256Digest {
        self.record.record_id()
    }

    /// Returns SHA-256 of the complete canonical record bytes.
    #[must_use]
    pub fn bytes_digest(&self) -> &Sha256Digest {
        &self.bytes_digest
    }

    /// Returns the exact canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Consumes the carrier and returns exact canonical bytes.
    #[must_use]
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }

    /// Returns an exact reference to this record.
    ///
    /// # Panics
    ///
    /// Panics only if a compile-time supported schema identity violates the
    /// package's bounded token alphabet.
    #[must_use]
    pub fn exact_reference(&self) -> RecordRef {
        RecordRef {
            schema: Token::parse(self.schema().as_str())
                .expect("supported schema identities satisfy token law"),
            record_id: self.record_id().clone(),
            bytes_digest: self.bytes_digest.clone(),
        }
    }
}

/// Exact authority-neutral transform of one valid v1 custody reservation.
///
/// The canonical bytes intentionally carry no record identity. Their
/// separately returned [`Self::plan_digest`] is domain-separated, so the
/// plan cannot acquire a self-hash cycle or masquerade as a runtime record.
#[derive(Debug, Clone, PartialEq)]
pub struct CustodyReservationPlan {
    value: Value,
    canonical_bytes: Vec<u8>,
    plan_digest: Sha256Digest,
}

impl CustodyReservationPlan {
    /// Constructs the total neutral transform of one validated v1
    /// reservation.
    ///
    /// # Errors
    ///
    /// Refuses a non-reservation source or any transformed carrier that does
    /// not satisfy the closed plan schema.
    pub fn from_reservation(reservation: &ValidatedRuntimeRecord) -> Result<Self> {
        if reservation.schema() != RuntimeSchema::CustodyReservationV1 {
            return Err(ContractError::InvalidReservationPlan);
        }
        let mut value = reservation.record().as_value().clone();
        let object = value
            .as_object_mut()
            .ok_or(ContractError::InvalidReservationPlan)?;
        object.remove("reservation_id");
        object.insert(
            "schema".to_owned(),
            Value::String(RESERVATION_PLAN_SCHEMA.to_owned()),
        );
        object.insert(
            "store_snapshot".to_owned(),
            Value::String(NEUTRAL_STORE_SNAPSHOT.to_owned()),
        );
        object.insert(
            "reservation_commit".to_owned(),
            Value::String(NEUTRAL_RESERVATION_COMMIT.to_owned()),
        );
        Self::validate_value(value)
    }

    /// Decodes exact canonical plan bytes.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical bytes or a malformed authority-neutral plan.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        let canonical_bytes = canonical_json_bytes(&value)?;
        if canonical_bytes != bytes {
            return Err(ContractError::NonCanonicalRecord);
        }
        Self::from_canonical_value(value, canonical_bytes)
    }

    /// Validates and canonicalizes an authority-neutral plan value.
    ///
    /// # Errors
    ///
    /// Refuses every unknown field, unsafe integer, malformed identity,
    /// invalid reservation arithmetic, authority-bearing token, or invalid
    /// timestamp interval.
    pub fn validate_value(value: Value) -> Result<Self> {
        let canonical_bytes = canonical_json_bytes(&value)?;
        Self::from_canonical_value(value, canonical_bytes)
    }

    fn from_canonical_value(value: Value, canonical_bytes: Vec<u8>) -> Result<Self> {
        validate_common_value(&value)?;
        crate::schema::validate_capacity_document(RESERVATION_PLAN_SCHEMA, &value)?;
        validate_reservation_plan(
            value
                .as_object()
                .ok_or(ContractError::InvalidReservationPlan)?,
        )?;
        let plan_digest = domain_separated_digest(RESERVATION_PLAN_DIGEST_DOMAIN, &canonical_bytes);
        Ok(Self {
            value,
            canonical_bytes,
            plan_digest,
        })
    }

    /// Returns the exact neutral plan value.
    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.value
    }

    /// Returns exact RFC 8785 canonical plan bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated digest bound by the allocation.
    #[must_use]
    pub const fn plan_digest(&self) -> &Sha256Digest {
        &self.plan_digest
    }

    /// Proves that this plan is the exact total transform of a reservation.
    ///
    /// # Errors
    ///
    /// Refuses a non-reservation input or malformed source carrier.
    pub fn matches_reservation(&self, reservation: &ValidatedRuntimeRecord) -> Result<bool> {
        Ok(Self::from_reservation(reservation)?.canonical_bytes == self.canonical_bytes)
    }
}

/// Derives the acyclic identity of a capacity-allocation record.
///
/// The preimage removes the root identity and every derived queue-occurrence
/// identity, and replaces each allocation backlink with one fixed
/// domain-separated sentinel. All verdict-relevant queue inputs remain.
///
/// # Errors
///
/// Refuses a malformed allocation shape or canonicalization failure.
pub fn derive_capacity_allocation_identity(value: &Value) -> Result<Sha256Digest> {
    let mut preimage = value.clone();
    let object = preimage
        .as_object_mut()
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    object.remove("allocation_id");
    let occurrences = object
        .get_mut("queue")
        .and_then(Value::as_object_mut)
        .and_then(|queue| queue.get_mut("occurrences"))
        .and_then(Value::as_array_mut)
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    for occurrence in occurrences {
        let occurrence = occurrence
            .as_object_mut()
            .ok_or(ContractError::InvalidCapacityAllocation)?;
        occurrence.remove("occurrence_id");
        occurrence.insert(
            "capacity_allocation_id".to_owned(),
            Value::String(NEUTRAL_CAPACITY_ALLOCATION_ID.to_owned()),
        );
    }
    let bytes = canonical_json_bytes(&preimage)?;
    Ok(domain_separated_digest(
        CAPACITY_ALLOCATION_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Derives one queue-occurrence identity from its exact five ratified inputs.
///
/// # Errors
///
/// Refuses a malformed occurrence shape or canonicalization failure.
pub fn derive_capacity_queue_occurrence_identity(value: &Value) -> Result<Sha256Digest> {
    let object = value
        .as_object()
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    if object.get("future_artifact_slot").and_then(Value::as_str)
        != Some(CAPACITY_FUTURE_ARTIFACT_SLOT)
    {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    let allocation_id = digest_field(object, "capacity_allocation_id")?;
    let request_occurrence_id = digest_field(object, "request_occurrence_id")?;
    let destination_generation_id = digest_field(object, "destination_generation_id")?;
    let delivery_policy_generation_id = digest_field(object, "delivery_policy_generation_id")?;
    capacity_queue_occurrence_identity(
        &allocation_id,
        &request_occurrence_id,
        &destination_generation_id,
        &delivery_policy_generation_id,
    )
}

/// Computes the one canonical queue-occurrence identity law.
///
/// Store code must call this function rather than duplicate the preimage,
/// canonicalization, or domain separator.
///
/// # Errors
///
/// Returns a canonicalization error only if the fixed typed preimage cannot
/// be serialized by the production canonicalizer.
pub fn capacity_queue_occurrence_identity(
    capacity_allocation_id: &Sha256Digest,
    request_occurrence_id: &Sha256Digest,
    destination_generation_id: &Sha256Digest,
    delivery_policy_generation_id: &Sha256Digest,
) -> Result<Sha256Digest> {
    let preimage = serde_json::json!({
        "capacity_allocation_id": capacity_allocation_id,
        "request_occurrence_id": request_occurrence_id,
        "destination_generation_id": destination_generation_id,
        "delivery_policy_generation_id": delivery_policy_generation_id,
        "future_artifact_slot": CAPACITY_FUTURE_ARTIFACT_SLOT,
    });
    let bytes = canonical_json_bytes(&preimage)?;
    Ok(domain_separated_digest(
        QUEUE_OCCURRENCE_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Computes the exact source-bound identity of one destination generation.
///
/// This identity binds the admitted destination descriptor and the request's
/// exact destination generation.  It does not claim that two destinations are
/// independent, reachable, current, or authorized.
///
/// # Errors
///
/// Returns a canonicalization error only if the fixed typed preimage cannot
/// be serialized by the production canonicalizer.
pub fn capacity_destination_generation_identity(
    destination: &IdentityRef,
    generation: &Generation,
) -> Result<Sha256Digest> {
    let preimage = serde_json::json!({
        "schema": "nq.capacity_destination_generation.v1",
        "destination": destination,
        "generation": generation,
    });
    let bytes = canonical_json_bytes(&preimage)?;
    Ok(domain_separated_digest(
        DESTINATION_GENERATION_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Computes the exact source-bound identity of one delivery-policy generation.
///
/// The preimage binds both the immutable buffer-policy record reference and
/// the delivery-policy descriptor selected by that record.  This preserves
/// policy-generation source authority without making the derived digest a
/// policy, authorization, or delivery result.
///
/// # Errors
///
/// Returns a canonicalization error only if the fixed typed preimage cannot
/// be serialized by the production canonicalizer.
pub fn capacity_delivery_policy_generation_identity(
    buffer_delivery_policy: &RecordRef,
    delivery_policy: &IdentityRef,
    generation: &Generation,
) -> Result<Sha256Digest> {
    let preimage = serde_json::json!({
        "schema": "nq.capacity_delivery_policy_generation.v1",
        "buffer_delivery_policy": buffer_delivery_policy,
        "delivery_policy": delivery_policy,
        "generation": generation,
    });
    let bytes = canonical_json_bytes(&preimage)?;
    Ok(domain_separated_digest(
        DELIVERY_POLICY_GENERATION_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Computes P0-1 `OccurrenceKeyV1` from one exact validated request.
///
/// Authorization-record rotation is deliberately absent from the stable
/// occurrence key.  The complete node and requesting-principal identity
/// references remain present, so principal rotation does not collapse.
///
/// # Errors
///
/// Refuses a non-request carrier or malformed request fields.
pub fn invocation_occurrence_key_v1(request: &ValidatedRuntimeRecord) -> Result<Sha256Digest> {
    request_key_v1(request, "nq.invocation-occurrence-key.v1", "request_id")
}

/// Computes P0-1 `IdempotencyKeyV1` from one exact validated request.
///
/// # Errors
///
/// Refuses a non-request carrier or malformed request fields.
pub fn invocation_idempotency_key_v1(request: &ValidatedRuntimeRecord) -> Result<Sha256Digest> {
    if request.schema() != RuntimeSchema::DiagnosticInvocationRequestV1 {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    let value = request.record().as_value();
    let node: IdentityRef = serde_json::from_value(value["target"]["node"].clone())?;
    let principal: IdentityRef = serde_json::from_value(value["requesting_principal"].clone())?;
    let key = value["idempotency"]["key"]
        .as_str()
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    let preimage = serde_json::json!(["nq.invocation-idempotency-key.v1", node, principal, key,]);
    Ok(sha256_bytes(&canonical_json_bytes(&preimage)?))
}

/// Inspectable source closure bound to one closed capacity rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityRuleArtifactSourceV1 {
    rule_identity: &'static str,
    rule_version: &'static str,
    digest_domain: &'static str,
    source_paths: &'static [&'static str],
    artifact_digest: Sha256Digest,
}

impl CapacityRuleArtifactSourceV1 {
    /// Closed rule identity.
    #[must_use]
    pub const fn rule_identity(&self) -> &'static str {
        self.rule_identity
    }

    /// Closed rule version.
    #[must_use]
    pub const fn rule_version(&self) -> &'static str {
        self.rule_version
    }

    /// Domain separating this source closure from every other digest use.
    #[must_use]
    pub const fn digest_domain(&self) -> &'static str {
        self.digest_domain
    }

    /// Ordered repository-relative source paths committed by the digest.
    #[must_use]
    pub const fn source_paths(&self) -> &'static [&'static str] {
        self.source_paths
    }

    /// Exact digest required by the allocation carrier.
    #[must_use]
    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }
}

/// Returns the exact seven-entry rule/source/digest map used by allocation
/// validation.
///
/// This is inspectable build evidence only. It does not establish that a
/// deployed binary was built from, loaded, or is executing the listed source.
///
/// # Errors
///
/// Refuses if any embedded source asset cannot be resolved.
pub fn capacity_rule_artifact_sources_v1() -> Result<Vec<CapacityRuleArtifactSourceV1>> {
    [
        "nq.logical_preallocated_custody_carriers",
        "nq.custody_carrier_map",
        "nq.custody_arena_layout",
        "nq.append_extent_layout",
        "nq.delivery_extent_layout",
        "nq.v3_projection_capsule_bound",
        "rfc8785-jcs-sha256",
    ]
    .into_iter()
    .map(|rule_identity| {
        let (digest_domain, source_paths) = capacity_rule_source_descriptor_v1(rule_identity)?;
        Ok(CapacityRuleArtifactSourceV1 {
            rule_identity,
            rule_version: "1",
            digest_domain,
            source_paths,
            artifact_digest: capacity_rule_artifact_digest_v1(rule_identity)?,
        })
    })
    .collect()
}

/// Returns the exact implementation/static-asset digest admitted for one of
/// the seven closed capacity rule identities.
///
/// Equal digests for distinct geometry rules are intentional when the same
/// exact implementation source owns both laws.  The rule identity remains a
/// separate closed field.  The V3 entry binds the exact inspected candidate
/// manifest bytes; this source correspondence does not satisfy CAP-H14 or
/// qualify that candidate as a production bound.
///
/// # Errors
///
/// Refuses every identity outside the seven-rule vocabulary.
pub fn capacity_rule_artifact_digest_v1(rule_identity: &str) -> Result<Sha256Digest> {
    let digest = match rule_identity {
        "nq.logical_preallocated_custody_carriers" => source_closure_digest(
            "nq.logical_preallocated_custody_carriers.v1",
            &[(
                "crates/nq-host-role-contract/src/capacity.rs",
                include_bytes!("capacity.rs"),
            )],
        ),
        "nq.custody_carrier_map" => source_closure_digest(
            "nq.custody_carrier_map.v1",
            &[(
                "crates/nq-host-role-contract/assets/nq.custody_carrier_map.v1.json",
                crate::assets::embedded_capacity_static_asset("nq.custody_carrier_map.v1")
                    .ok_or(ContractError::InvalidCapacityAllocation)?,
            )],
        ),
        "nq.custody_arena_layout" | "nq.append_extent_layout" | "nq.delivery_extent_layout" => {
            source_closure_digest(
                "nq.capacity_geometry.v1",
                &[(
                    "crates/nq-host-role-contract/src/capacity.rs",
                    include_bytes!("capacity.rs"),
                )],
            )
        }
        "nq.v3_projection_capsule_bound" => source_closure_digest(
            "nq.v3_projection_capsule_bound.v1",
            &[(
                "crates/nq-host-role-contract/assets/nq.v3_projection_capsule_bound_manifest.v1.json",
                crate::assets::embedded_capacity_static_asset(
                    "nq.v3_projection_capsule_bound_manifest.v1",
                )
                .ok_or(ContractError::InvalidCapacityAllocation)?,
            )],
        ),
        "rfc8785-jcs-sha256" => source_closure_digest(
            "nq.rfc8785_jcs_sha256_implementation.v1",
            &[
                (
                    "crates/nq-protocol/src/canonical.rs",
                    include_bytes!("../../nq-protocol/src/canonical.rs"),
                ),
                (
                    "crates/nq-protocol/Cargo.toml",
                    include_bytes!("../../nq-protocol/Cargo.toml"),
                ),
                ("Cargo.toml", include_bytes!("../../../Cargo.toml")),
                ("Cargo.lock", include_bytes!("../../../Cargo.lock")),
            ],
        ),
        _ => return Err(ContractError::InvalidCapacityAllocation),
    };
    Ok(digest)
}

fn capacity_rule_source_descriptor_v1(
    rule_identity: &str,
) -> Result<(&'static str, &'static [&'static str])> {
    match rule_identity {
        "nq.logical_preallocated_custody_carriers" => Ok((
            "nq.logical_preallocated_custody_carriers.v1",
            &["crates/nq-host-role-contract/src/capacity.rs"],
        )),
        "nq.custody_carrier_map" => Ok((
            "nq.custody_carrier_map.v1",
            &["crates/nq-host-role-contract/assets/nq.custody_carrier_map.v1.json"],
        )),
        "nq.custody_arena_layout" | "nq.append_extent_layout" | "nq.delivery_extent_layout" => {
            Ok((
                "nq.capacity_geometry.v1",
                &["crates/nq-host-role-contract/src/capacity.rs"],
            ))
        }
        "nq.v3_projection_capsule_bound" => Ok((
            "nq.v3_projection_capsule_bound.v1",
            &[
                "crates/nq-host-role-contract/assets/nq.v3_projection_capsule_bound_manifest.v1.json",
            ],
        )),
        "rfc8785-jcs-sha256" => Ok((
            "nq.rfc8785_jcs_sha256_implementation.v1",
            &[
                "crates/nq-protocol/src/canonical.rs",
                "crates/nq-protocol/Cargo.toml",
                "Cargo.toml",
                "Cargo.lock",
            ],
        )),
        _ => Err(ContractError::InvalidCapacityAllocation),
    }
}

fn source_closure_digest(domain: &str, sources: &[(&str, &[u8])]) -> Sha256Digest {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    for (path, bytes) in sources {
        preimage.extend_from_slice(path.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(sha256_bytes(bytes).as_str().as_bytes());
        preimage.push(0);
    }
    sha256_bytes(&preimage)
}

fn request_key_v1(
    request: &ValidatedRuntimeRecord,
    domain: &'static str,
    field: &'static str,
) -> Result<Sha256Digest> {
    if request.schema() != RuntimeSchema::DiagnosticInvocationRequestV1 {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    let value = request.record().as_value();
    let node: IdentityRef = serde_json::from_value(value["target"]["node"].clone())?;
    let principal: IdentityRef = serde_json::from_value(value["requesting_principal"].clone())?;
    let occurrence = value[field]
        .as_str()
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    let preimage = serde_json::json!([domain, node, principal, occurrence]);
    Ok(sha256_bytes(&canonical_json_bytes(&preimage)?))
}

fn domain_separated_digest(domain: &[u8], canonical_bytes: &[u8]) -> Sha256Digest {
    let mut preimage = Vec::with_capacity(domain.len().saturating_add(canonical_bytes.len()));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical_bytes);
    sha256_bytes(&preimage)
}

fn require_exact_fields(
    object: &Map<String, Value>,
    required_fields: &[&str],
    optional_fields: &[&str],
    schema: RuntimeSchema,
) -> Result<()> {
    let expected: BTreeSet<&str> = required_fields.iter().copied().collect();
    let allowed: BTreeSet<&str> = required_fields
        .iter()
        .chain(optional_fields.iter())
        .copied()
        .collect();
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if !actual.is_subset(&allowed) || !expected.is_subset(&actual) {
        let unknown = actual
            .difference(&allowed)
            .copied()
            .map(str::to_owned)
            .collect();
        let missing = expected
            .difference(&actual)
            .copied()
            .map(str::to_owned)
            .collect();
        return Err(ContractError::RecordShape {
            schema,
            unknown,
            missing,
        });
    }
    Ok(())
}

fn validate_common_value(value: &Value) -> Result<()> {
    fn visit(value: &Value, key: Option<&str>) -> Result<()> {
        match value {
            Value::Object(object) => {
                const FORBIDDEN: [&str; 6] = [
                    "comparison_set",
                    "cron",
                    "expiry",
                    "posture",
                    "recurrence",
                    "schedule",
                ];
                if object.keys().any(|key| FORBIDDEN.contains(&key.as_str())) {
                    return Err(ContractError::ForbiddenAuthorityField);
                }
                let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
                if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                    serde_json::from_value::<IdentityRef>(value.clone())?;
                } else if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                    serde_json::from_value::<RecordRef>(value.clone())?;
                } else if keys
                    == BTreeSet::from([
                        "namespace_id",
                        "namespace_version",
                        "catalog_generation",
                        "catalog_id",
                    ])
                {
                    serde_json::from_value::<NamespaceSnapshot>(value.clone())?;
                }
                if key == Some("effective_interval") {
                    serde_json::from_value::<EffectiveInterval>(value.clone())?.validate()?;
                }
                for (child_key, child) in object {
                    visit(child, Some(child_key))?;
                }
            }
            Value::Array(values) => {
                if key == Some("nonclaims")
                    && (values.is_empty()
                        || values
                            .iter()
                            .any(|item| item.as_str().is_none_or(str::is_empty)))
                {
                    return Err(ContractError::InvalidNonclaims);
                }
                let mut seen = BTreeSet::new();
                for child in values {
                    let digest = semantic_digest(child)?;
                    if !seen.insert(digest) {
                        return Err(ContractError::DuplicateArrayMember);
                    }
                    visit(child, key)?;
                }
            }
            Value::Number(number) => {
                if number
                    .as_u64()
                    .is_some_and(|value| value > CAPACITY_IJSON_SAFE_INTEGER_MAX_V1)
                    || number.as_i64().is_some_and(|value| {
                        value.unsigned_abs() > CAPACITY_IJSON_SAFE_INTEGER_MAX_V1
                    })
                {
                    return Err(ContractError::UnsafeInteger);
                }
            }
            Value::String(text) => {
                if key.is_some_and(|key| {
                    key == "generation"
                        || key.ends_with("_generation")
                        || key == "destination_generation"
                }) {
                    Generation::parse(text.clone())?;
                }
                if key.is_some_and(|key| {
                    key.ends_with("_at")
                        || key == "deadline"
                        || key == "not_before"
                        || key == "effective_from"
                        || key == "effective_until"
                        || key == "expires_at"
                        || key == "attempt_deadline"
                        || key == "next_attempt_not_before"
                }) {
                    Timestamp::parse(text.clone())?;
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
        Ok(())
    }
    visit(value, None)
}

fn validate_local_semantics(schema: RuntimeSchema, object: &Map<String, Value>) -> Result<()> {
    match schema {
        RuntimeSchema::RoleManifestV1 => validate_role(object),
        RuntimeSchema::BufferDeliveryPolicyV1 => validate_buffer_delivery_policy(object),
        RuntimeSchema::StaticProfileCohortManifestV1 => validate_cohort(object),
        RuntimeSchema::NodeEnrollmentV1 => {
            identity(object, "node")?.require_kind(IdentityKind::NqNode, "enrollment.node")?;
            identity(object, "initial_key")?
                .require_kind(IdentityKind::KeyGeneration, "enrollment.initial_key")
        }
        RuntimeSchema::HostRoleRelationV1 => validate_relation(object),
        RuntimeSchema::RuntimeActivationV1 => {
            identity(object, "node")?.require_kind(IdentityKind::NqNode, "activation.node")?;
            identity(object, "role")?.require_kind(IdentityKind::Role, "activation.role")?;
            identity(object, "static_profile_cohort")?.require_kind(
                IdentityKind::StaticCohort,
                "activation.static_profile_cohort",
            )?;
            identity(object, "active_key")?
                .require_kind(IdentityKind::KeyGeneration, "activation.active_key")
        }
        RuntimeSchema::WitnessAttachmentV1 => validate_attachment(object),
        RuntimeSchema::HostRoleLifecycleEventV1 => validate_host_lifecycle_event(object),
        RuntimeSchema::WitnessLifecycleEventV1 => validate_witness_lifecycle_event(object),
        RuntimeSchema::NodeKeyLifecycleEventV1 => validate_node_key_lifecycle_event(object),
        RuntimeSchema::RestoreActivationProofV1 => validate_restore_activation_proof(object),
        RuntimeSchema::DiagnosticInvocationRequestV1 => validate_request(object),
        RuntimeSchema::InvocationDecisionV1 => validate_decision(object),
        RuntimeSchema::OperationAuthorizationV1 => validate_authorization(object),
        RuntimeSchema::CustodyReservationV1 => validate_reservation(object),
        RuntimeSchema::CustodyCapacityAllocationV1 => validate_capacity_allocation(object),
        RuntimeSchema::ExecutionLaunchV1 => validate_launch(object),
        RuntimeSchema::NativeProfileQualificationV1 => {
            validate_native_profile_qualification(object)
        }
        RuntimeSchema::NativeClockQualificationV1 => validate_native_clock_qualification(object),
        RuntimeSchema::DeadlineEvaluationV1 => validate_deadline_evaluation(object),
        RuntimeSchema::ExecutionIdentityBindingV2 => validate_binding(object),
        RuntimeSchema::AuthenticatedArtifactEnvelopeV1 => validate_envelope(object),
        RuntimeSchema::ArtifactDeliveryAttemptV1 => validate_attempt(object),
        RuntimeSchema::ArtifactCustodyReceiptV1 => validate_custody_receipt(object),
        RuntimeSchema::ArtifactDeliveryRecordV1 => validate_delivery_record(object),
        RuntimeSchema::InspectorResultSetV1 => validate_result_set(object),
        RuntimeSchema::InspectorSnapshotV1 => validate_inspector_snapshot(object),
        RuntimeSchema::InspectorReadReceiptV1 => validate_inspector_read_receipt(object),
        RuntimeSchema::DecommissionLedgerSnapshotV1 => {
            validate_decommission_ledger_snapshot(object)
        }
        RuntimeSchema::DecommissionCutV1 => validate_decommission_cut(object),
    }
}

fn identity(object: &Map<String, Value>, field: &'static str) -> Result<IdentityRef> {
    Ok(serde_json::from_value(object.get(field).cloned().ok_or(
        ContractError::MissingField {
            schema: RuntimeSchema::RoleManifestV1,
            field,
        },
    )?)?)
}

fn identities(value: &Value) -> Result<Vec<IdentityRef>> {
    value
        .as_array()
        .ok_or(ContractError::ExpectedArray)?
        .iter()
        .cloned()
        .map(|value| serde_json::from_value(value).map_err(ContractError::from))
        .collect()
}

fn text<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ContractError::ExpectedString(field))
}

fn unsigned(object: &Map<String, Value>, field: &'static str) -> Result<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ContractError::ExpectedUnsigned(field))
}

fn digest_field(object: &Map<String, Value>, field: &'static str) -> Result<Sha256Digest> {
    serde_json::from_value(
        object
            .get(field)
            .cloned()
            .ok_or(ContractError::ExpectedString(field))?,
    )
    .map_err(ContractError::from)
}

fn boolean(object: &Map<String, Value>, field: &'static str) -> Result<bool> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(ContractError::ExpectedBoolean(field))
}

fn array<'a>(source: &'a Map<String, Value>, field: &'static str) -> Result<&'a Vec<Value>> {
    source
        .get(field)
        .and_then(Value::as_array)
        .ok_or(ContractError::ExpectedArray)
}

fn object<'a>(
    source: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Map<String, Value>> {
    source
        .get(field)
        .and_then(Value::as_object)
        .ok_or(ContractError::ExpectedObject(field))
}

#[allow(clippy::too_many_lines)] // One closed policy record with coupled capacity/retry laws.
fn validate_buffer_delivery_policy(policy: &Map<String, Value>) -> Result<()> {
    let identities = object(policy, "policy_identities")?;
    require_exact_fields_generic(
        identities,
        &["custody", "buffer", "delivery"],
        "buffer_delivery_policy.policy_identities",
    )?;
    for field in ["custody", "buffer", "delivery"] {
        identity(identities, field)?.require_kind(
            IdentityKind::Policy,
            "buffer_delivery_policy.policy_identity",
        )?;
    }

    let capacity = object(policy, "capacity")?;
    require_exact_fields_generic(
        capacity,
        &[
            "total_bytes",
            "high_watermark_bytes",
            "protected_failure_receipt_bytes",
            "maximum_single_execution_closure_bytes",
            "maximum_queue_entries",
        ],
        "buffer_delivery_policy.capacity",
    )?;
    let protected = unsigned(capacity, "protected_failure_receipt_bytes")?;
    let high = unsigned(capacity, "high_watermark_bytes")?;
    let total = unsigned(capacity, "total_bytes")?;
    if protected == 0
        || high == 0
        || total == 0
        || protected >= high
        || high >= total
        || unsigned(capacity, "maximum_single_execution_closure_bytes")? == 0
        || unsigned(capacity, "maximum_queue_entries")? == 0
    {
        return Err(ContractError::InvalidCapacityPolicy);
    }

    let reservation = object(policy, "reservation")?;
    require_exact_fields_generic(
        reservation,
        &[
            "mode",
            "before_provider_launch",
            "transient_evaluation_fallback",
        ],
        "buffer_delivery_policy.reservation",
    )?;
    if text(reservation, "mode")? != "profile_maximum_closure_plus_required_ledgers"
        || !boolean(reservation, "before_provider_launch")?
        || boolean(reservation, "transient_evaluation_fallback")?
        || text(policy, "ordering")? != "per_destination_artifact_commit_sequence"
        || text(policy, "duplicate_law")? != "exact_idempotent_collision_on_substitution"
        || text(policy, "acknowledgement")? != "authenticated_receiver_custody_of_exact_bytes_only"
    {
        return Err(ContractError::InvalidBufferDeliveryPolicy);
    }

    let retry = object(policy, "retry")?;
    require_exact_fields_generic(
        retry,
        &[
            "maximum_attempts",
            "attempt_delays_ms",
            "durable_next_attempt_deadline",
            "retryable_outcomes",
        ],
        "buffer_delivery_policy.retry",
    )?;
    let attempts = unsigned(retry, "maximum_attempts")?;
    let delays = array(retry, "attempt_delays_ms")?;
    if attempts == 0
        || usize::try_from(attempts).ok() != Some(delays.len())
        || delays.len() > 16
        || !boolean(retry, "durable_next_attempt_deadline")?
        || delays.iter().any(|delay| delay.as_u64().is_none())
    {
        return Err(ContractError::InvalidRetryPolicy);
    }
    if array(retry, "retryable_outcomes")?.is_empty()
        || array(retry, "retryable_outcomes")?.iter().any(|value| {
            value
                .as_str()
                .is_none_or(|value| !RETRYABLE_OUTCOMES.contains(&value))
        })
    {
        return Err(ContractError::InvalidRetryPolicy);
    }

    let offline = object(policy, "offline")?;
    let backpressure = object(policy, "backpressure")?;
    if text(offline, "local_execution")? != "separately_received_authorized_requests_only"
        || boolean(offline, "automatic_diagnostic_reinvocation")?
        || text(backpressure, "at_high_watermark")? != "admit_only_if_exact_reservation_remains"
        || text(backpressure, "at_reservation_failure")? != "refuse_before_acquisition"
    {
        return Err(ContractError::InvalidBufferDeliveryPolicy);
    }
    Ok(())
}

fn validate_role(role: &Map<String, Value>) -> Result<()> {
    identity(role, "role")?.require_kind(IdentityKind::Role, "role.role")?;
    for profile in identities(&role["permitted_profiles"])? {
        profile.require_kind(IdentityKind::DiagnosticProfile, "role.permitted_profiles")?;
    }
    for slot in role["witness_slots"]
        .as_array()
        .ok_or(ContractError::ExpectedArray)?
    {
        let slot = slot
            .as_object()
            .ok_or(ContractError::ExpectedObject("role.witness_slots[]"))?;
        require_exact_fields_generic(
            slot,
            &[
                "slot_id",
                "requirement",
                "witness_class",
                "privilege_ceiling",
                "namespace_ceiling",
                "supported_profiles",
            ],
            "role.witness_slots[]",
        )?;
        identity(slot, "witness_class")?
            .require_kind(IdentityKind::Witness, "role.witness_class")?;
        for profile in identities(&slot["supported_profiles"])? {
            profile.require_kind(IdentityKind::DiagnosticProfile, "role.supported_profiles")?;
        }
    }
    Ok(())
}

fn validate_cohort(cohort: &Map<String, Value>) -> Result<()> {
    identity(cohort, "cohort")?.require_kind(IdentityKind::StaticCohort, "cohort.cohort")?;
    let members = object(cohort, "members")?;
    let expected = [
        ("profiles", IdentityKind::DiagnosticProfile),
        ("questions", IdentityKind::DiagnosticQuestion),
        ("evaluators", IdentityKind::Evaluator),
        ("detector_suites", IdentityKind::DetectorSuite),
        ("schemas", IdentityKind::ContractSchema),
        ("canonicalization_rules", IdentityKind::Canonicalization),
        ("normalization_rules", IdentityKind::NormalizationRule),
        ("projection_rules", IdentityKind::Projection),
        ("threshold_policies", IdentityKind::ThresholdPolicy),
    ];
    require_exact_fields_generic(members, &expected.map(|(field, _)| field), "cohort.members")?;
    for (field, kind) in expected {
        for member in identities(&members[field])? {
            member.require_kind(kind, "cohort.members")?;
            if matches!(
                member.kind,
                IdentityKind::NqNode
                    | IdentityKind::Subject
                    | IdentityKind::Platform
                    | IdentityKind::Vantage
                    | IdentityKind::Role
                    | IdentityKind::StaticCohort
                    | IdentityKind::Witness
                    | IdentityKind::Provider
                    | IdentityKind::Principal
            ) {
                return Err(ContractError::TopologyIdentityInSemanticCohort);
            }
        }
    }
    for build in identities(&cohort["compatible_builds"])? {
        build.require_kind(IdentityKind::Build, "cohort.compatible_builds")?;
    }
    for compatibility in identities(&cohort["protocol_store_compatibility"])? {
        compatibility.require_kind(
            IdentityKind::Compatibility,
            "cohort.protocol_store_compatibility",
        )?;
    }
    Ok(())
}

fn validate_relation(relation: &Map<String, Value>) -> Result<()> {
    let left = identity(relation, "left")?;
    let right = identity(relation, "right")?;
    let expected = match text(relation, "relation_kind")? {
        "node_subject" => (IdentityKind::NqNode, IdentityKind::Subject),
        "subject_platform" => (IdentityKind::Subject, IdentityKind::Platform),
        "node_vantage" => (IdentityKind::NqNode, IdentityKind::Vantage),
        "node_role" => (IdentityKind::NqNode, IdentityKind::Role),
        "node_static_profile_cohort" => (IdentityKind::NqNode, IdentityKind::StaticCohort),
        other => return Err(ContractError::UnknownRelationKind(other.to_owned())),
    };
    left.require_kind(expected.0, "relation.left")?;
    right.require_kind(expected.1, "relation.right")
}

fn validate_attachment(attachment: &Map<String, Value>) -> Result<()> {
    identity(attachment, "node")?.require_kind(IdentityKind::NqNode, "attachment.node")?;
    identity(attachment, "role")?.require_kind(IdentityKind::Role, "attachment.role")?;
    let class = identity(attachment, "witness_class")?;
    let witness = identity(attachment, "witness")?;
    class.require_kind(IdentityKind::Witness, "attachment.witness_class")?;
    witness.require_kind(IdentityKind::Witness, "attachment.witness")?;
    if class == witness {
        return Err(ContractError::WitnessClassInstanceAlias);
    }
    identity(attachment, "provider")?
        .require_kind(IdentityKind::Provider, "attachment.provider")?;
    identity(attachment, "provider_build")?
        .require_kind(IdentityKind::Build, "attachment.provider_build")?;
    for profile in identities(&attachment["supported_profiles"])? {
        profile.require_kind(
            IdentityKind::DiagnosticProfile,
            "attachment.supported_profiles",
        )?;
    }
    Ok(())
}

fn validate_host_lifecycle_event(event: &Map<String, Value>) -> Result<()> {
    identity(event, "node")?.require_kind(IdentityKind::NqNode, "host_lifecycle.node")?;
    let operation = text(event, "operation")?;
    let from = text(event, "from_state")?;
    let to = text(event, "to_state")?;
    let predecessors = array(event, "predecessor_events")?;
    let allowed = matches!(
        (operation, from, to),
        ("bootstrap", "unbootstrapped", "bootstrapped_unenrolled")
            | ("enroll", "bootstrapped_unenrolled", "enrolled_inactive")
            | ("activate", "enrolled_inactive", "active")
            | (
                "rekey" | "rehome" | "change_role" | "change_static_profile_cohort",
                "enrolled_inactive",
                "enrolled_inactive"
            )
            | (
                "rekey" | "rehome" | "change_role" | "change_static_profile_cohort",
                "active",
                "active"
            )
            | (
                "begin_restore",
                "bootstrapped_unenrolled",
                "recovery_quarantined"
            )
            | (
                "complete_restore",
                "recovery_quarantined",
                "enrolled_inactive"
            )
            | (
                "begin_decommission",
                "enrolled_inactive" | "active",
                "draining"
            )
            | ("complete_decommission", "draining", "decommissioned")
    );
    if !allowed
        || (operation == "bootstrap" && !predecessors.is_empty())
        || (operation != "bootstrap" && predecessors.len() != 1)
    {
        return Err(ContractError::InvalidLifecycleTransition);
    }
    let proof_required = matches!(
        operation,
        "complete_restore" | "begin_decommission" | "complete_decommission"
    );
    if proof_required != event.contains_key("operation_proof") {
        return Err(ContractError::LifecycleProofMismatch);
    }
    if array(event, "input_records")?.is_empty()
        || array(event, "result_records")?.is_empty()
        || text(event, "reason")?.is_empty()
    {
        return Err(ContractError::InvalidLifecycleTransition);
    }
    Ok(())
}

fn validate_witness_lifecycle_event(event: &Map<String, Value>) -> Result<()> {
    identity(event, "node")?.require_kind(IdentityKind::NqNode, "witness_lifecycle.node")?;
    identity(event, "witness")?.require_kind(IdentityKind::Witness, "witness_lifecycle.witness")?;
    let operation = text(event, "operation")?;
    let from = text(event, "from_state")?;
    let to = text(event, "to_state")?;
    let predecessor = &event["predecessor_event"];
    let allowed = matches!(
        (operation, from, to),
        ("activate", "admitted_inactive", "active")
            | ("suspend", "active", "suspended")
            | ("resume", "suspended", "active")
            | (
                "retire",
                "admitted_inactive" | "active" | "suspended",
                "retired"
            )
    );
    if !allowed
        || (operation == "activate" && !predecessor.is_null())
        || (matches!(operation, "suspend" | "resume") && predecessor.is_null())
        || array(event, "input_records")?.is_empty()
        || array(event, "result_records")?.is_empty()
    {
        return Err(ContractError::InvalidLifecycleTransition);
    }
    Ok(())
}

fn validate_node_key_lifecycle_event(event: &Map<String, Value>) -> Result<()> {
    identity(event, "node")?.require_kind(IdentityKind::NqNode, "key_lifecycle.node")?;
    identity(event, "key")?.require_kind(IdentityKind::KeyGeneration, "key_lifecycle.key")?;
    let operation = text(event, "operation")?;
    let from = text(event, "from_state")?;
    let to = text(event, "to_state")?;
    let predecessor = &event["predecessor_event"];
    let replacement = &event["replacement_key_event"];
    let activation = &event["resulting_activation"];
    let valid = match (operation, from, to) {
        ("activate", "pending", "active") => replacement.is_null() && !activation.is_null(),
        ("supersede", "active", "superseded") => {
            !predecessor.is_null() && !replacement.is_null() && !activation.is_null()
        }
        ("revoke", "active", "revoked") => {
            !predecessor.is_null() && replacement.is_null() && activation.is_null()
        }
        _ => false,
    };
    if !valid {
        return Err(ContractError::InvalidLifecycleTransition);
    }
    Ok(())
}

fn validate_restore_activation_proof(proof: &Map<String, Value>) -> Result<()> {
    identity(proof, "node")?.require_kind(IdentityKind::NqNode, "restore.node")?;
    identity(proof, "source_deployment_generation")?.require_kind(
        IdentityKind::DeploymentGeneration,
        "restore.source_deployment_generation",
    )?;
    identity(proof, "new_deployment_generation")?.require_kind(
        IdentityKind::DeploymentGeneration,
        "restore.new_deployment_generation",
    )?;
    identity(proof, "evaluator")?.require_kind(IdentityKind::Evaluator, "restore.evaluator")?;
    let decision = text(proof, "decision")?;
    if !matches!(
        decision,
        "recovery_quarantined" | "eligible_enrolled_inactive" | "replacement_required"
    ) {
        return Err(ContractError::InvalidRestoreDecision);
    }
    let check_fields = [
        "closure_verification",
        "prior_occurrence_fencing",
        "identity_uniqueness",
        "key_revalidation",
        "binding_revalidation",
    ];
    let all_established = check_fields.iter().try_fold(true, |acc, field| {
        let check = object(proof, field)?;
        let status = text(check, "status")?;
        if !matches!(status, "established" | "unresolved" | "unavailable") {
            return Err(ContractError::InvalidRestoreDecision);
        }
        Ok(acc && status == "established")
    })?;
    if decision == "eligible_enrolled_inactive" {
        if !all_established
            || proof["new_key_event"].is_null()
            || proof["activation_candidate"].is_null()
        {
            return Err(ContractError::InvalidRestoreDecision);
        }
    } else if !proof["activation_candidate"].is_null() {
        return Err(ContractError::RestoreQuarantineBypass);
    }
    Ok(())
}

fn validate_request(request: &Map<String, Value>) -> Result<()> {
    identity(request, "requesting_principal")?
        .require_kind(IdentityKind::Principal, "request.requesting_principal")?;
    identity(request, "profile")?
        .require_kind(IdentityKind::DiagnosticProfile, "request.profile")?;
    let target = object(request, "target")?;
    identity(target, "node")?.require_kind(IdentityKind::NqNode, "request.target.node")?;
    identity(target, "subject")?.require_kind(IdentityKind::Subject, "request.target.subject")?;
    identity(target, "vantage")?.require_kind(IdentityKind::Vantage, "request.target.vantage")?;

    let mut preimage = Value::Object(request.clone());
    let preimage_object = preimage
        .as_object_mut()
        .expect("constructed from request object");
    preimage_object.remove("request_digest");
    preimage_object.remove("request_preimage_digest");
    preimage_object.remove("invocation_authorization");
    let expected_preimage = semantic_digest(&preimage)?;
    let claimed_preimage: Sha256Digest =
        serde_json::from_value(request["request_preimage_digest"].clone())?;
    if claimed_preimage != expected_preimage {
        return Err(ContractError::RequestPreimageDigestMismatch);
    }

    let mut complete = Value::Object(request.clone());
    complete
        .as_object_mut()
        .expect("constructed from request object")
        .remove("request_digest");
    let expected = semantic_digest(&complete)?;
    let claimed: Sha256Digest = serde_json::from_value(request["request_digest"].clone())?;
    if claimed != expected {
        return Err(ContractError::RequestDigestMismatch);
    }
    Ok(())
}

fn validate_decision(decision: &Map<String, Value>) -> Result<()> {
    let state = text(decision, "decision")?;
    if !matches!(
        state,
        "accepted"
            | "authentication_refused"
            | "authorization_refused"
            | "binding_refused"
            | "capability_refused"
            | "deadline_refused"
            | "custody_refused"
            | "stale_before_start"
            | "decommissioned_before_start"
    ) {
        return Err(ContractError::UnknownInvocationDecision(state.to_owned()));
    }
    identity(decision, "policy")?
        .require_kind(IdentityKind::Policy, "invocation_decision.policy")?;
    identity(decision, "clock")?.require_kind(IdentityKind::Clock, "invocation_decision.clock")?;

    let custody = object(decision, "custody")?;
    let custody_state = text(custody, "state")?;
    let reservation = custody
        .get("reservation")
        .ok_or(ContractError::InvalidInvocationDecision)?;
    let custody_matches = match state {
        "accepted" => custody_state == "reserved" && !reservation.is_null(),
        "custody_refused" => custody_state == "refused" && !reservation.is_null(),
        _ => custody_state == "not_applicable" && reservation.is_null(),
    };
    if !custody_matches {
        return Err(ContractError::InvalidInvocationDecision);
    }
    if !reservation.is_null() {
        serde_json::from_value::<RecordRef>(reservation.clone())
            .map_err(|_| ContractError::InvalidInvocationDecision)?;
    }

    let required = if state == "accepted" {
        [
            "acceptance does not establish diagnostic success",
            "acceptance does not authorize action",
        ]
    } else {
        [
            "refusal does not establish diagnostic success",
            "refusal does not authorize action",
        ]
    };
    if !required_nonclaims(decision, &required)? {
        return Err(ContractError::InvalidInvocationDecision);
    }
    Ok(())
}

fn validate_authorization(authorization: &Map<String, Value>) -> Result<()> {
    identity(authorization, "authorizing_principal")?.require_kind(
        IdentityKind::Principal,
        "authorization.authorizing_principal",
    )?;
    identity(authorization, "requesting_principal")?.require_kind(
        IdentityKind::Principal,
        "authorization.requesting_principal",
    )?;
    identity(authorization, "policy")?
        .require_kind(IdentityKind::Policy, "authorization.policy")?;
    if !matches!(text(authorization, "decision")?, "granted" | "refused") {
        return Err(ContractError::InvalidAuthorizationDecision);
    }
    Ok(())
}

fn validate_reservation(reservation: &Map<String, Value>) -> Result<()> {
    identity(reservation, "node")?.require_kind(IdentityKind::NqNode, "reservation.node")?;
    identity(reservation, "profile")?
        .require_kind(IdentityKind::DiagnosticProfile, "reservation.profile")?;
    identity(reservation, "custody_policy")?
        .require_kind(IdentityKind::Policy, "reservation.custody_policy")?;
    identity(reservation, "clock")?.require_kind(IdentityKind::Clock, "reservation.clock")?;
    let components = object(reservation, "component_bounds")?;
    let mut total = 0_u64;
    for value in components.values() {
        total = total
            .checked_add(
                value
                    .as_u64()
                    .ok_or(ContractError::InvalidReservationArithmetic)?,
            )
            .ok_or(ContractError::InvalidReservationArithmetic)?;
    }
    let total_required = unsigned(reservation, "total_required_bytes")?;
    let reserved_bytes = unsigned(reservation, "reserved_bytes")?;
    if total != total_required {
        return Err(ContractError::InvalidReservationArithmetic);
    }
    match text(reservation, "decision")? {
        "reserved" if reserved_bytes < total_required => {
            return Err(ContractError::InvalidReservationArithmetic);
        }
        "reserved" | "refused" => {}
        state => {
            return Err(ContractError::UnknownCustodyReservationDecision(
                state.to_owned(),
            ));
        }
    }
    if !required_nonclaims(
        reservation,
        &[
            "reservation does not establish diagnostic success",
            "protected failure reserve is not execution payload capacity",
        ],
    )? {
        return Err(ContractError::InvalidCustodyReservation);
    }
    let reserved = Timestamp::parse(text(reservation, "reserved_at")?)?;
    let expires = Timestamp::parse(text(reservation, "expires_at")?)?;
    if expires.instant() <= reserved.instant() {
        return Err(ContractError::ExpiredCustodyReservation);
    }
    Ok(())
}

fn validate_reservation_plan(plan: &Map<String, Value>) -> Result<()> {
    if text(plan, "schema")? != RESERVATION_PLAN_SCHEMA
        || text(plan, "store_snapshot")? != NEUTRAL_STORE_SNAPSHOT
        || text(plan, "reservation_commit")? != NEUTRAL_RESERVATION_COMMIT
    {
        return Err(ContractError::InvalidReservationPlan);
    }
    identity(plan, "node")?.require_kind(IdentityKind::NqNode, "reservation_plan.node")?;
    identity(plan, "profile")?
        .require_kind(IdentityKind::DiagnosticProfile, "reservation_plan.profile")?;
    identity(plan, "custody_policy")?
        .require_kind(IdentityKind::Policy, "reservation_plan.custody_policy")?;
    identity(plan, "calculation_rule")?
        .require_kind(IdentityKind::Policy, "reservation_plan.calculation_rule")?;
    identity(plan, "clock")?.require_kind(IdentityKind::Clock, "reservation_plan.clock")?;

    let components = object(plan, "component_bounds")?;
    let semantic_sum = components.values().try_fold(0_u64, |sum, value| {
        let component = value
            .as_u64()
            .ok_or(ContractError::InvalidReservationPlan)?;
        sum.checked_add(component)
            .filter(|value| *value <= CAPACITY_IJSON_SAFE_INTEGER_MAX_V1)
            .ok_or(ContractError::InvalidReservationPlan)
    })?;
    let total_required = unsigned(plan, "total_required_bytes")?;
    let reserved = unsigned(plan, "reserved_bytes")?;
    if total_required == 0 || semantic_sum != total_required {
        return Err(ContractError::InvalidReservationPlan);
    }
    match text(plan, "decision")? {
        "reserved" if reserved == semantic_sum => {}
        "refused" => {}
        _ => return Err(ContractError::InvalidReservationPlan),
    }
    let reserved_at = Timestamp::parse(text(plan, "reserved_at")?)?;
    let expires_at = Timestamp::parse(text(plan, "expires_at")?)?;
    if expires_at.instant() <= reserved_at.instant()
        || !required_nonclaims(
            plan,
            &[
                "reservation does not establish diagnostic success",
                "protected failure reserve is not execution payload capacity",
            ],
        )?
    {
        return Err(ContractError::InvalidReservationPlan);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One closed carrier keeps all no-borrow and identity joins visible.
fn validate_capacity_allocation(allocation: &Map<String, Value>) -> Result<()> {
    identity(allocation, "store_integrity_key_generation")?.require_kind(
        IdentityKind::KeyGeneration,
        "capacity_allocation.store_integrity_key_generation",
    )?;
    identity(allocation, "clock")?
        .require_kind(IdentityKind::Clock, "capacity_allocation.clock")?;
    let policy = object(allocation, "policy")?;
    identity(policy, "capacity_policy")?
        .require_kind(IdentityKind::Policy, "capacity_allocation.capacity_policy")?;
    identity(policy, "delivery_policy")?
        .require_kind(IdentityKind::Policy, "capacity_allocation.delivery_policy")?;
    let delivery_policy_generation_id = digest_field(policy, "delivery_policy_generation_id")?;
    let rules = object(allocation, "rules")?;
    for (field, expected_identity) in [
        (
            "capacity_calculation",
            "nq.logical_preallocated_custody_carriers",
        ),
        ("carrier_map", "nq.custody_carrier_map"),
        ("arena_layout", "nq.custody_arena_layout"),
        ("record_extent", "nq.append_extent_layout"),
        ("delivery_extent", "nq.delivery_extent_layout"),
        ("v3_capsule_bound", "nq.v3_projection_capsule_bound"),
        ("canonicalization", "rfc8785-jcs-sha256"),
    ] {
        require_capacity_rule(rules, field, expected_identity)?;
    }

    let plan = CustodyReservationPlan::validate_value(
        allocation
            .get("reservation_plan")
            .cloned()
            .ok_or(ContractError::InvalidCapacityAllocation)?,
    )
    .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let plan_value = plan
        .as_value()
        .as_object()
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    if digest_field(allocation, "plan_digest")? != *plan.plan_digest()
        || allocation.get("semantic_components") != plan_value.get("component_bounds")
        || policy.get("capacity_policy") != plan_value.get("custody_policy")
        || allocation.get("clock") != plan_value.get("clock")
        || allocation.get("calculated_at") != plan_value.get("reserved_at")
        || object(allocation, "request_occurrence")?.get("request") != plan_value.get("request")
    {
        return Err(ContractError::InvalidCapacityAllocation);
    }

    let components = object(allocation, "semantic_components")?;
    let semantic_components: CapacitySemanticComponentsV1 =
        serde_json::from_value(Value::Object(components.clone()))
            .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let semantic_sum = checked_capacity_semantic_sum_v1(&semantic_components)
        .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    if semantic_sum == 0 || semantic_sum != unsigned(allocation, "semantic_sum_bytes")? {
        return Err(ContractError::InvalidCapacityAllocation);
    }

    let bounds = object(allocation, "carrier_bounds")?;
    let dependency = unsigned(bounds, "dependency_payload_bytes")?;
    let raw = unsigned(bounds, "raw_acquisition_payload_bytes")?;
    let projection = unsigned(bounds, "projection_capsule_bound_bytes")?;
    let final_closure = unsigned(bounds, "final_closure_payload_bytes")?;
    let canonical_record = unsigned(bounds, "canonical_record_payload_bytes")?;
    let protected_failure = unsigned(bounds, "protected_failure_payload_bytes")?;
    let final_semantic = checked_sum([
        unsigned(components, "normalized_bytes")?,
        unsigned(components, "projected_bytes")?,
        unsigned(components, "diagnostic_artifact_bytes")?,
    ])?;
    let canonical_semantic = checked_sum([
        unsigned(components, "request_and_decision_bytes")?,
        unsigned(components, "commit_checkpoint_overhead_bytes")?,
    ])?;
    if dependency == 0
        || raw == 0
        || projection == 0
        || final_closure == 0
        || canonical_record == 0
        || protected_failure == 0
        || dependency < unsigned(components, "dependency_closure_bytes")?
        || raw < unsigned(components, "raw_evidence_bytes")?
        || final_closure < projection
        || final_closure < final_semantic
        || canonical_record < canonical_semantic
    {
        return Err(ContractError::InvalidCapacityAllocation);
    }

    let limits = object(allocation, "limits")?;
    let capacity_limits = CapacityLogicalLimitsV1 {
        total_bytes: unsigned(limits, "total_bytes")?,
        high_watermark_bytes: unsigned(limits, "high_watermark_bytes")?,
        protected_failure_receipt_bytes: unsigned(limits, "protected_failure_receipt_bytes")?,
        maximum_single_execution_closure_bytes: unsigned(
            limits,
            "maximum_single_execution_closure_bytes",
        )?,
        maximum_queue_entries: unsigned(object(allocation, "queue")?, "maximum_entries")?,
    };

    let arena = object(allocation, "arena_layout")?;
    validate_arena_layout(arena, dependency, raw, final_closure, protected_failure)?;
    let record_extent = object(allocation, "canonical_record_extent")?;
    validate_append_extent(record_extent, canonical_record)?;

    let delivery_semantic = unsigned(components, "mandatory_delivery_ledger_bytes")?;
    let delivery_value = allocation
        .get("delivery_ledger_extent")
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    let queue = object(allocation, "queue")?;
    let occurrences = array(queue, "occurrences")?;
    let queue_requirement = text(queue, "requirement")?;
    let plan_delivery_requirement = plan_value
        .get("delivery_requirement")
        .ok_or(ContractError::InvalidCapacityAllocation)?;
    let delivery_length = match (queue_requirement, delivery_value.as_object()) {
        ("not_required", None)
            if delivery_value.is_null()
                && delivery_semantic == 0
                && occurrences.is_empty()
                && unsigned(queue, "slots_reserved")? == 0
                && plan_delivery_requirement.is_null() =>
        {
            0
        }
        ("required", Some(extent))
            if delivery_semantic > 0
                && !occurrences.is_empty()
                && plan_delivery_requirement
                    == policy
                        .get("buffer_delivery_policy")
                        .ok_or(ContractError::InvalidCapacityAllocation)?
                && usize::try_from(unsigned(queue, "slots_reserved")?).ok()
                    == Some(occurrences.len()) =>
        {
            validate_append_extent_at_least(extent, delivery_semantic)?;
            unsigned(extent, "extent_length_bytes")?
        }
        _ => return Err(ContractError::InvalidCapacityAllocation),
    };

    let queue_before = unsigned(queue, "slots_before")?;
    let queue_reserved = unsigned(queue, "slots_reserved")?;
    if capacity_limits.maximum_queue_entries != unsigned(queue, "maximum_entries")? {
        return Err(ContractError::InvalidCapacityAllocation);
    }

    let request_occurrence = object(allocation, "request_occurrence")?;
    let request_occurrence_id = digest_field(request_occurrence, "occurrence_id")?;
    let allocation_id = digest_field(allocation, "allocation_id")?;
    let mut destination_generations = BTreeSet::new();
    let mut occurrence_ids = BTreeSet::new();
    let mut prior_destination_generation = None;
    for occurrence in occurrences {
        let occurrence = occurrence
            .as_object()
            .ok_or(ContractError::InvalidCapacityAllocation)?;
        let occurrence_id = digest_field(occurrence, "occurrence_id")?;
        let destination_generation_id = digest_field(occurrence, "destination_generation_id")?;
        if digest_field(occurrence, "capacity_allocation_id")? != allocation_id
            || digest_field(occurrence, "request_occurrence_id")? != request_occurrence_id
            || digest_field(occurrence, "delivery_policy_generation_id")?
                != delivery_policy_generation_id
            || derive_capacity_queue_occurrence_identity(&Value::Object(occurrence.clone()))?
                != occurrence_id
            || prior_destination_generation
                .as_ref()
                .is_some_and(|prior| prior >= &destination_generation_id)
            || !destination_generations.insert(destination_generation_id)
            || !occurrence_ids.insert(occurrence_id)
        {
            return Err(ContractError::InvalidCapacityAllocation);
        }
        prior_destination_generation = Some(
            digest_field(occurrence, "destination_generation_id")
                .map_err(|_| ContractError::InvalidCapacityAllocation)?,
        );
    }

    let before = object(allocation, "before_snapshot")?;
    let aggregate = checked_logical_preallocated_custody_carriers_v1(
        &semantic_components,
        &CapacityUsageComponentsV1 {
            bootstrap_integrity_carrier_bytes: unsigned(
                before,
                "bootstrap_integrity_carrier_bytes",
            )?,
            global_prelaunch_refusal_bytes: unsigned(before, "global_prelaunch_refusal_bytes")?,
            matched_retained_bytes: unsigned(before, "matched_retained_bytes")?,
            physical_orphan_bytes: unsigned(before, "physical_orphan_bytes")?,
            missing_committed_bytes: unsigned(before, "missing_committed_bytes")?,
            active_queue_entries: queue_before,
        },
        &CapacityCandidateChargeV1 {
            arena_file_length_bytes: unsigned(arena, "file_length_bytes")?,
            canonical_record_extent_length_bytes: unsigned(record_extent, "extent_length_bytes")?,
            delivery_ledger_extent_length_bytes: delivery_length,
            final_closure_payload_bytes: final_closure,
            protected_failure_payload_bytes: protected_failure,
            queue_entries_reserved: queue_reserved,
        },
        &capacity_limits,
    )
    .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let actual_refusals: Vec<CapacityLimitRefusalV1> =
        serde_json::from_value(Value::Array(array(allocation, "refusal_reasons")?.clone()))
            .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let actual_decision: CapacityLogicalDispositionV1 =
        serde_json::from_value(Value::String(text(allocation, "decision")?.to_owned()))
            .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let plan_decision_matches = matches!(
        (aggregate.disposition(), text(plan_value, "decision")?),
        (
            CapacityLogicalDispositionV1::WithinLogicalLimits,
            "reserved"
        ) | (CapacityLogicalDispositionV1::Refused, "refused")
    );
    let watermark = object(allocation, "watermark_classification")?;
    let actual_before_watermark: CapacityWatermarkClassificationV1 =
        serde_json::from_value(Value::String(text(watermark, "used_before")?.to_owned()))
            .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let actual_after_watermark: CapacityWatermarkClassificationV1 =
        serde_json::from_value(Value::String(text(watermark, "used_after")?.to_owned()))
            .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    if semantic_sum != aggregate.semantic_sum_bytes()
        || aggregate.retained_charge_bytes() != unsigned(allocation, "retained_charge_bytes")?
        || aggregate.logical_preallocated_carrier_bytes_before()
            != unsigned(before, "logical_preallocated_carrier_bytes")?
        || aggregate.logical_preallocated_carrier_bytes_after()
            != unsigned(allocation, "logical_preallocated_carrier_bytes_after")?
        || aggregate.queue_entries_after() != unsigned(queue, "slots_after")?
        || actual_refusals != aggregate.refusal_reasons()
        || actual_decision != aggregate.disposition()
        || !plan_decision_matches
        || unsigned(plan_value, "protected_failure_reserve_bytes")?
            != capacity_limits.protected_failure_receipt_bytes
        || actual_before_watermark != aggregate.used_before_watermark()
        || actual_after_watermark != aggregate.used_after_watermark()
        || derive_capacity_allocation_identity(&Value::Object(allocation.clone()))? != allocation_id
        || !required_nonclaims(
            allocation,
            &[
                "capacity allocation performs no filesystem allocation or provider effect",
                "within logical limits does not establish request acceptance, reservation, launch, or diagnostic result",
                "capacity allocation validation establishes internal arithmetic only, not evaluator/source-set correspondence or Store-owned construction",
                "capacity allocation grants no reliance, authorization, or action",
                "exact source or asset digest correspondence does not establish deployed build or live execution correspondence",
            ],
        )?
    {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    Ok(())
}

fn require_capacity_rule(
    rules: &Map<String, Value>,
    field: &'static str,
    expected_identity: &str,
) -> Result<()> {
    let rule = object(rules, field)?;
    if text(rule, "identity")? != expected_identity || text(rule, "version")? != "1" {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    let actual_digest: Sha256Digest = serde_json::from_value(
        rule.get("artifact_digest")
            .cloned()
            .ok_or(ContractError::InvalidCapacityAllocation)?,
    )
    .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    if actual_digest != capacity_rule_artifact_digest_v1(expected_identity)? {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    Ok(())
}

fn validate_arena_layout(
    arena: &Map<String, Value>,
    dependency: u64,
    raw: u64,
    final_closure: u64,
    protected_failure: u64,
) -> Result<()> {
    let actual: CustodyArenaGeometryV1 = serde_json::from_value(Value::Object(arena.clone()))
        .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let expected =
        checked_custody_arena_geometry_v1(dependency, raw, final_closure, protected_failure)
            .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    if actual == expected {
        Ok(())
    } else {
        Err(ContractError::InvalidCapacityAllocation)
    }
}

fn validate_append_extent(extent: &Map<String, Value>, payload: u64) -> Result<()> {
    validate_append_extent_at_least(extent, payload)?;
    if unsigned(extent, "payload_bytes")? != payload {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    Ok(())
}

fn validate_append_extent_at_least(
    extent: &Map<String, Value>,
    minimum_payload: u64,
) -> Result<()> {
    let actual: AppendExtentGeometryV1 = serde_json::from_value(Value::Object(extent.clone()))
        .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    let payload = actual.payload_bytes;
    if payload == 0 || payload < minimum_payload {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    let expected = checked_append_extent_geometry_v1(payload)
        .map_err(|_| ContractError::InvalidCapacityAllocation)?;
    if actual != expected {
        return Err(ContractError::InvalidCapacityAllocation);
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .filter(|value| *value <= CAPACITY_IJSON_SAFE_INTEGER_MAX_V1)
        .ok_or(ContractError::InvalidCapacityAllocation)
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0_u64, checked_add)
}

fn validate_launch(launch: &Map<String, Value>) -> Result<()> {
    identity(launch, "node")?.require_kind(IdentityKind::NqNode, "launch.node")?;
    identity(launch, "profile")?.require_kind(IdentityKind::DiagnosticProfile, "launch.profile")?;
    identity(launch, "clock")?.require_kind(IdentityKind::Clock, "launch.clock")?;
    if text(launch, "status")? != "launched" {
        return Err(ContractError::InvalidLaunchStatus);
    }
    let launched = Timestamp::parse(text(launch, "launched_at")?)?;
    let deadline = Timestamp::parse(text(launch, "attempt_deadline")?)?;
    let maximum_execution_ms = unsigned(launch, "maximum_execution_ms")?;
    let maximum_execution_ms_i64 =
        i64::try_from(maximum_execution_ms).map_err(|_| ContractError::UnsafeInteger)?;
    let elapsed = deadline.instant().signed_duration_since(launched.instant());
    if maximum_execution_ms == 0
        || elapsed != chrono::Duration::milliseconds(maximum_execution_ms_i64)
    {
        return Err(ContractError::LaunchDeadlineSubstitution);
    }
    Ok(())
}

fn validate_native_profile_qualification(qualification: &Map<String, Value>) -> Result<()> {
    identity(qualification, "cohort")?.require_kind(
        IdentityKind::StaticCohort,
        "native_profile_qualification.cohort",
    )?;
    let production_profile = identity(qualification, "production_profile")?;
    production_profile.require_kind(
        IdentityKind::DiagnosticProfile,
        "native_profile_qualification.production_profile",
    )?;
    identity(qualification, "production_question")?.require_kind(
        IdentityKind::DiagnosticQuestion,
        "native_profile_qualification.production_question",
    )?;
    let _: Sha256Digest = serde_json::from_value(qualification["cohort_semantics_digest"].clone())?;
    let production_build = identity(qualification, "production_build")?;
    production_build.require_kind(
        IdentityKind::Build,
        "native_profile_qualification.production_build",
    )?;
    let native_profile = object(qualification, "native_profile")?;
    let native_evaluator = object(qualification, "native_evaluator")?;
    let descriptor_digest: Sha256Digest =
        serde_json::from_value(native_profile["descriptor_digest"].clone())?;
    let evaluator_artifact_digest: Sha256Digest =
        serde_json::from_value(native_evaluator["artifact_digest"].clone())?;
    if production_profile.descriptor_digest == descriptor_digest
        || production_build.descriptor_digest == evaluator_artifact_digest
    {
        return Err(ContractError::CorrespondenceIdentityCollapse);
    }
    if text(native_profile, "descriptor_schema")? != "nq.profile_descriptor.v1"
        || text(native_profile, "semantic_identity_schema")? != "nq.profile_semantic_id.v1"
        || text(native_profile, "helper_protocol_version")? != "nq.helper.v1"
        || unsigned(native_profile, "profile_version")? == 0
        || unsigned(
            object(native_profile, "detector_closure")?,
            "detector_count",
        )? > CAPACITY_IJSON_SAFE_INTEGER_MAX_V1
        || array(qualification, "qualification_evidence")?.is_empty()
        || !required_nonclaims(
            qualification,
            &[
                "relates production and native identities but does not equate them",
                "does not establish invocation, reliance, authorization, or action",
            ],
        )?
    {
        return Err(ContractError::InvalidNativeProfileQualification);
    }
    verify_identity_without(
        qualification,
        "qualification_id",
        "native_profile_qualification.qualification_id",
    )
}

fn validate_native_clock_qualification(qualification: &Map<String, Value>) -> Result<()> {
    identity(qualification, "cohort")?.require_kind(
        IdentityKind::StaticCohort,
        "native_clock_qualification.cohort",
    )?;
    let _: Sha256Digest = serde_json::from_value(qualification["cohort_semantics_digest"].clone())?;
    let production_clock = identity(qualification, "production_clock")?;
    production_clock.require_kind(
        IdentityKind::Clock,
        "native_clock_qualification.production_clock",
    )?;
    identity(qualification, "production_build")?.require_kind(
        IdentityKind::Build,
        "native_clock_qualification.production_build",
    )?;
    identity(qualification, "platform")?.require_kind(
        IdentityKind::Platform,
        "native_clock_qualification.platform",
    )?;
    let absolute_time = object(qualification, "absolute_time")?;
    let boottime = object(qualification, "boottime")?;
    let bridge = object(qualification, "wall_to_monotonic_bridge")?;
    let watchdog = object(qualification, "runner_watchdog")?;
    let absolute_identity: Sha256Digest =
        serde_json::from_value(absolute_time["semantic_identity_digest"].clone())?;
    let boottime_identity: Sha256Digest =
        serde_json::from_value(boottime["semantic_identity_digest"].clone())?;
    let bridge_identity: Sha256Digest =
        serde_json::from_value(bridge["semantic_identity_digest"].clone())?;
    if [&absolute_identity, &boottime_identity, &bridge_identity]
        .contains(&&production_clock.descriptor_digest)
        || absolute_identity == boottime_identity
        || absolute_identity == bridge_identity
        || boottime_identity == bridge_identity
    {
        return Err(ContractError::CorrespondenceIdentityCollapse);
    }
    if text(absolute_time, "clock_id")? != "CLOCK_REALTIME"
        || text(absolute_time, "epoch")? != "unix"
        || text(absolute_time, "unit")? != "nanosecond"
        || text(object(absolute_time, "accuracy_qualification")?, "status")? != "unqualified"
        || text(boottime, "clock_id")? != "CLOCK_BOOTTIME"
        || text(boottime, "unit")? != "nanosecond"
        || text(boottime, "suspend_semantics")? != "includes_suspended_time"
        || text(watchdog, "relation_to_governed_deadline")? != "auxiliary_non_equivalent"
        || array(qualification, "qualification_evidence")?.is_empty()
        || !required_nonclaims(
            qualification,
            &[
                "UTC accuracy remains unqualified",
                "does not establish cross-host clock coherence",
                "runner watchdog is not the governed deadline",
            ],
        )?
    {
        return Err(ContractError::InvalidNativeClockQualification);
    }
    verify_identity_without(
        qualification,
        "qualification_id",
        "native_clock_qualification.qualification_id",
    )
}

fn validate_deadline_evaluation(evaluation: &Map<String, Value>) -> Result<()> {
    identity(evaluation, "clock")?
        .require_kind(IdentityKind::Clock, "deadline_evaluation.clock")?;
    identity(object(evaluation, "bracket_policy")?, "policy")?
        .require_kind(IdentityKind::Policy, "deadline_evaluation.bracket_policy")?;
    let bounds = object(evaluation, "request_bounds")?;
    let policy = object(evaluation, "bracket_policy")?;
    let sample = object(evaluation, "sample")?;
    let derived = object(evaluation, "derived")?;
    let decision = object(evaluation, "decision")?;

    let not_before = Timestamp::parse(text(bounds, "not_before")?)?.instant();
    let request_deadline = Timestamp::parse(text(bounds, "deadline")?)?.instant();
    let realtime_before = Timestamp::parse(text(sample, "realtime_before")?)?.instant();
    let realtime_after = Timestamp::parse(text(sample, "realtime_after")?)?.instant();
    let launched_at = Timestamp::parse(text(derived, "launched_at")?)?.instant();
    let attempt_deadline = Timestamp::parse(text(derived, "attempt_deadline")?)?.instant();
    let maximum_execution_ms = unsigned(bounds, "maximum_execution_ms")?;
    let maximum_execution_ms_i64 = i64::try_from(maximum_execution_ms)
        .map_err(|_| ContractError::DeadlineEvaluationMismatch)?;

    let signed_bracket_ns = realtime_after
        .signed_duration_since(realtime_before)
        .num_nanoseconds()
        .ok_or(ContractError::DeadlineEvaluationMismatch)?;
    let expected_bracket_ns = u64::try_from(signed_bracket_ns).unwrap_or(0);
    let expected_attempt_deadline = realtime_after
        .checked_add_signed(chrono::Duration::milliseconds(maximum_execution_ms_i64))
        .ok_or(ContractError::DeadlineEvaluationMismatch)?;
    let expected_boottime_expiry_ns = decimal_u64(sample, "boottime_at_ns")?
        .checked_add(
            maximum_execution_ms
                .checked_mul(1_000_000)
                .ok_or(ContractError::DeadlineEvaluationMismatch)?,
        )
        .ok_or(ContractError::DeadlineEvaluationMismatch)?;
    if unsigned(sample, "bracket_width_ns")? != expected_bracket_ns
        || launched_at != realtime_after
        || attempt_deadline != expected_attempt_deadline
        || decimal_u64(derived, "boottime_expiry_ns")? != expected_boottime_expiry_ns
    {
        return Err(ContractError::DeadlineEvaluationMismatch);
    }

    let mut expected_violations = Vec::new();
    if signed_bracket_ns < 0 {
        expected_violations.push("realtime_bracket_reversed");
    }
    if request_deadline <= not_before {
        expected_violations.push("invalid_request_window");
    }
    if expected_bracket_ns > unsigned(policy, "maximum_width_ns")? {
        expected_violations.push("bracket_too_wide");
    }
    if realtime_after < not_before {
        expected_violations.push("before_not_before");
    }
    if realtime_after >= request_deadline {
        expected_violations.push("request_deadline_exhausted");
    }
    if expected_attempt_deadline > request_deadline {
        expected_violations.push("execution_budget_exceeds_request_deadline");
    }
    let actual_violations = array(decision, "violations")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ContractError::DeadlineEvaluationMismatch)
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_state = if expected_violations.is_empty() {
        "accepted"
    } else {
        "refused"
    };
    if text(decision, "state")? != expected_state
        || actual_violations != expected_violations
        || !required_nonclaims(
            evaluation,
            &[
                "does not reference or authorize an execution launch",
                "does not establish source-evidence freshness or Nightshift currentness",
                "does not grant reliance, authorization, or action",
            ],
        )?
    {
        return Err(ContractError::DeadlineEvaluationMismatch);
    }
    verify_identity_without(
        evaluation,
        "evaluation_id",
        "deadline_evaluation.evaluation_id",
    )
}

fn required_nonclaims(object: &Map<String, Value>, required: &[&str]) -> Result<bool> {
    let actual = array(object, "nonclaims")?;
    Ok(required
        .iter()
        .all(|required| actual.iter().any(|value| value.as_str() == Some(required))))
}

fn decimal_u64(object: &Map<String, Value>, field: &'static str) -> Result<u64> {
    let value = text(object, field)?;
    if value != "0" && value.starts_with('0') {
        return Err(ContractError::DeadlineEvaluationMismatch);
    }
    value
        .parse()
        .map_err(|_| ContractError::DeadlineEvaluationMismatch)
}

fn validate_binding(binding: &Map<String, Value>) -> Result<()> {
    identity(binding, "resolver")?.require_kind(IdentityKind::Resolver, "binding.resolver")?;
    if text(binding, "binding_result")? != "resolved" {
        return Err(ContractError::BindingNotResolved);
    }
    let diagnostic = object(binding, "diagnostic")?;
    if text(diagnostic, "schema")? != "nq.diagnostic_execution.v2" {
        return Err(ContractError::UnsupportedDiagnosticContract);
    }
    let expected_resolved = [
        ("node", IdentityKind::NqNode),
        ("subject", IdentityKind::Subject),
        ("platform", IdentityKind::Platform),
        ("vantage", IdentityKind::Vantage),
        ("role", IdentityKind::Role),
        ("static_profile_cohort", IdentityKind::StaticCohort),
        ("witness", IdentityKind::Witness),
        ("diagnostic_profile", IdentityKind::DiagnosticProfile),
    ];
    let resolved = object(binding, "resolved_references")?;
    require_exact_fields_generic(
        resolved,
        &expected_resolved.map(|(field, _)| field),
        "binding.resolved_references",
    )?;
    for (field, kind) in expected_resolved {
        let entry = object(resolved, field)?;
        identity(entry, "identity")?.require_kind(kind, "binding.resolved_references.identity")?;
    }
    Ok(())
}

fn validate_envelope(envelope: &Map<String, Value>) -> Result<()> {
    identity(envelope, "producer_node")?
        .require_kind(IdentityKind::NqNode, "envelope.producer_node")?;
    identity(envelope, "producer_key_generation")?.require_kind(
        IdentityKind::KeyGeneration,
        "envelope.producer_key_generation",
    )?;
    identity(envelope, "intended_receiver")?
        .require_kind(IdentityKind::Destination, "envelope.intended_receiver")?;
    identity(envelope, "transport_policy")?
        .require_kind(IdentityKind::Policy, "envelope.transport_policy")?;
    validate_signed_projection(envelope, "authentication")
}

fn validate_attempt(attempt: &Map<String, Value>) -> Result<()> {
    if unsigned(attempt, "attempt_number")? == 0 {
        return Err(ContractError::InvalidAttemptNumber);
    }
    identity(attempt, "producer_node")?
        .require_kind(IdentityKind::NqNode, "attempt.producer_node")?;
    identity(attempt, "producer_key_generation")?.require_kind(
        IdentityKind::KeyGeneration,
        "attempt.producer_key_generation",
    )?;
    identity(attempt, "destination")?
        .require_kind(IdentityKind::Destination, "attempt.destination")?;
    identity(attempt, "transport")?.require_kind(IdentityKind::Transport, "attempt.transport")?;
    identity(attempt, "transport_policy")?
        .require_kind(IdentityKind::Policy, "attempt.transport_policy")?;
    Ok(())
}

fn validate_custody_receipt(receipt: &Map<String, Value>) -> Result<()> {
    identity(receipt, "receiver")?.require_kind(IdentityKind::Destination, "receipt.receiver")?;
    identity(receipt, "authenticated_sender")?
        .require_kind(IdentityKind::NqNode, "receipt.authenticated_sender")?;
    if text(receipt, "semantic_admission")? != "not_established_by_custody_receipt" {
        return Err(ContractError::CustodyReceiptClaimsSemanticAdmission);
    }
    validate_signed_projection(receipt, "receipt_authentication")
}

fn validate_delivery_record(delivery: &Map<String, Value>) -> Result<()> {
    identity(delivery, "producer_node")?
        .require_kind(IdentityKind::NqNode, "delivery.producer_node")?;
    identity(delivery, "producer_key_generation")?.require_kind(
        IdentityKind::KeyGeneration,
        "delivery.producer_key_generation",
    )?;
    let state = text(delivery, "state")?;
    if !DELIVERY_STATES.contains(&state) {
        return Err(ContractError::UnknownDeliveryState(state.to_owned()));
    }
    Ok(())
}

fn validate_result_set(result: &Map<String, Value>) -> Result<()> {
    let commit_preimage = serde_json::json!({
        "ledger_generation": result["ledger_generation"],
        "query_digest": result["query"]["query_digest"],
        "result_records": result["result_records"],
        "index_state": result["index_state"],
        "completeness": result["completeness"],
    });
    let commit: Sha256Digest = serde_json::from_value(result["ledger_commit"].clone())?;
    if commit != semantic_digest(&commit_preimage)? {
        return Err(ContractError::InspectorLedgerCommitMismatch);
    }
    verify_identity_without(result, "snapshot_id", "snapshot_id")
}

fn validate_inspector_snapshot(snapshot: &Map<String, Value>) -> Result<()> {
    let bound_snapshot: Sha256Digest = serde_json::from_value(snapshot["snapshot_id"].clone())?;
    let result_ref: RecordRef = serde_json::from_value(snapshot["snapshot"].clone())?;
    if bound_snapshot != result_ref.record_id {
        return Err(ContractError::InspectorSnapshotSubstitution);
    }
    verify_identity_without(snapshot, "page_response_id", "page_response_id")
}

fn validate_inspector_read_receipt(receipt: &Map<String, Value>) -> Result<()> {
    let decision = text(receipt, "decision")?;
    if !matches!(decision, "granted" | "refused") {
        return Err(ContractError::InvalidInspectorDecision);
    }
    if decision == "refused"
        && (receipt["page_response"] != Value::Null
            || !receipt["retrieved_records"]
                .as_array()
                .is_some_and(Vec::is_empty)
            || receipt["page_response_digest"] != Value::Null
            || unsigned(receipt, "page_response_bytes")? != 0)
    {
        return Err(ContractError::RefusedInspectorReadDisclosesData);
    }
    Ok(())
}

fn validate_decommission_ledger_snapshot(snapshot: &Map<String, Value>) -> Result<()> {
    identity(snapshot, "node")?.require_kind(IdentityKind::NqNode, "decommission_snapshot.node")?;
    identity(snapshot, "evaluator")?
        .require_kind(IdentityKind::Evaluator, "decommission_snapshot.evaluator")?;
    let entries = array(snapshot, "ledger_entries")?;
    if usize::try_from(unsigned(snapshot, "ledger_entry_count")?).ok() != Some(entries.len())
        || serde_json::from_value::<Sha256Digest>(snapshot["ledger_entries_digest"].clone())?
            != semantic_digest(entries)?
    {
        return Err(ContractError::DecommissionSnapshotCommitmentMismatch);
    }
    let mut prior_key: Option<(String, String, String)> = None;
    for entry in entries {
        let entry = entry
            .as_object()
            .ok_or(ContractError::ExpectedObject("ledger_entries[]"))?;
        require_exact_fields_generic(
            entry,
            &["record", "committed_at"],
            "decommission_snapshot.ledger_entries[]",
        )?;
        let reference: RecordRef = serde_json::from_value(entry["record"].clone())?;
        Timestamp::parse(
            entry["committed_at"]
                .as_str()
                .ok_or(ContractError::ExpectedString("committed_at"))?
                .to_owned(),
        )?;
        let key = (
            reference.schema.to_string(),
            reference.record_id.to_string(),
            reference.bytes_digest.to_string(),
        );
        if prior_key.as_ref().is_some_and(|prior| prior >= &key) {
            return Err(ContractError::DecommissionSnapshotNotCanonical);
        }
        prior_key = Some(key);
    }
    verify_identity_without(snapshot, "snapshot_id", "snapshot_id")
}

fn validate_decommission_cut(cut: &Map<String, Value>) -> Result<()> {
    identity(cut, "node")?.require_kind(IdentityKind::NqNode, "decommission_cut.node")?;
    identity(cut, "historical_read_policy")?.require_kind(
        IdentityKind::Policy,
        "decommission_cut.historical_read_policy",
    )?;
    if text(cut, "new_request_policy")? != "refuse" {
        return Err(ContractError::DecommissionFenceGap);
    }
    let state = text(cut, "result_state")?;
    if !matches!(state, "draining" | "decommissioned") {
        return Err(ContractError::InvalidDecommissionState);
    }
    let counts = object(cut, "unresolved_counts")?;
    require_exact_fields_generic(
        counts,
        &["accepted_not_launched", "in_flight", "committed_deliveries"],
        "decommission_cut.unresolved_counts",
    )?;
    if state == "draining" {
        if !cut["predecessor_cut"].is_null() {
            return Err(ContractError::DecommissionPredecessorMismatch);
        }
    } else if cut["predecessor_cut"].is_null()
        || !array(cut, "accepted_prestart_dispositions")?.is_empty()
        || !array(cut, "in_flight")?.is_empty()
        || !array(cut, "committed_deliveries")?.is_empty()
        || ["accepted_not_launched", "in_flight", "committed_deliveries"]
            .iter()
            .any(|field| unsigned(counts, field).is_ok_and(|value| value != 0))
    {
        return Err(ContractError::DecommissionDrainIncomplete);
    }
    Ok(())
}

fn verify_identity_without(
    object: &Map<String, Value>,
    identity_field: &'static str,
    error_field: &'static str,
) -> Result<()> {
    let claimed: Sha256Digest = serde_json::from_value(object[identity_field].clone())?;
    let mut preimage = object.clone();
    preimage.remove(identity_field);
    if claimed != semantic_digest(&Value::Object(preimage))? {
        return Err(ContractError::SelfIdentityMismatch(error_field));
    }
    Ok(())
}

fn validate_signed_projection(
    record: &Map<String, Value>,
    authentication_field: &'static str,
) -> Result<()> {
    let authentication = object(record, authentication_field)?;
    let pointers = authentication["signed_fields"]
        .as_array()
        .ok_or(ContractError::ExpectedArray)?;
    let mut projection = Vec::with_capacity(pointers.len());
    for pointer in pointers {
        let pointer = pointer
            .as_str()
            .ok_or(ContractError::ExpectedString("signed_fields[]"))?;
        projection.push(serde_json::json!({
            "pointer": pointer,
            "value": resolve_pointer(&Value::Object(record.clone()), pointer)?,
        }));
    }
    let claimed: Sha256Digest =
        serde_json::from_value(authentication["signed_content_digest"].clone())?;
    if claimed != semantic_digest(&projection)? {
        return Err(ContractError::SignedProjectionMismatch);
    }
    Ok(())
}

pub(crate) fn resolve_pointer<'a>(document: &'a Value, pointer: &str) -> Result<&'a Value> {
    if pointer.is_empty() {
        return Ok(document);
    }
    let mut current = document;
    let path = pointer
        .strip_prefix('/')
        .ok_or_else(|| ContractError::InvalidJsonPointer(pointer.to_owned()))?;
    for raw in path.split('/') {
        let token = decode_pointer_token(raw, pointer)?;
        current =
            match current {
                Value::Object(object) => object
                    .get(&token)
                    .ok_or_else(|| ContractError::UnresolvedJsonPointer(pointer.to_owned()))?,
                Value::Array(array) => {
                    let canonical_index = token == "0"
                        || (token
                            .as_bytes()
                            .first()
                            .is_some_and(|first| first.is_ascii_digit() && *first != b'0')
                            && token.as_bytes().iter().all(u8::is_ascii_digit));
                    if !canonical_index {
                        return Err(ContractError::UnresolvedJsonPointer(pointer.to_owned()));
                    }
                    array
                        .get(token.parse::<usize>().map_err(|_| {
                            ContractError::UnresolvedJsonPointer(pointer.to_owned())
                        })?)
                        .ok_or_else(|| ContractError::UnresolvedJsonPointer(pointer.to_owned()))?
                }
                _ => return Err(ContractError::UnresolvedJsonPointer(pointer.to_owned())),
            };
    }
    Ok(current)
}

fn decode_pointer_token(raw: &str, pointer: &str) -> Result<String> {
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => return Err(ContractError::InvalidJsonPointer(pointer.to_owned())),
        }
    }
    Ok(decoded)
}

fn require_exact_fields_generic(
    object: &Map<String, Value>,
    fields: &[&str],
    context: &'static str,
) -> Result<()> {
    let expected: BTreeSet<&str> = fields.iter().copied().collect();
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if expected != actual {
        return Err(ContractError::NestedRecordShape(context));
    }
    Ok(())
}
