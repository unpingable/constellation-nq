//! Strict canonical carriers for the ratified host-role runtime records.

use std::collections::BTreeSet;

use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde_json::{Map, Value};

use crate::{
    ContractError, Result,
    identity::{
        EffectiveInterval, Generation, IdentityKind, IdentityRef, NamespaceSnapshot, RecordRef,
        Timestamp, Token,
    },
};

/// Maximum safe integer under the I-JSON/JCS number model.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
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
    /// `nq.execution_launch.v1`.
    ExecutionLaunchV1,
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

impl RuntimeSchema {
    /// Every supported record schema.
    pub const ALL: [Self; 26] = [
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
        Self::ExecutionLaunchV1,
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
            Self::ExecutionLaunchV1 => "nq.execution_launch.v1",
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
            Self::ExecutionLaunchV1 => "launch_id",
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
    (ExecutionLaunch, ExecutionLaunch),
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
            RuntimeSchema::ExecutionLaunchV1 => Self::ExecutionLaunch(ExecutionLaunch(record)),
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
            Self::ExecutionLaunch(value) => &value.0,
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
                    .is_some_and(|value| value > MAX_SAFE_INTEGER)
                    || number
                        .as_i64()
                        .is_some_and(|value| value.unsigned_abs() > MAX_SAFE_INTEGER)
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
        RuntimeSchema::ExecutionLaunchV1 => validate_launch(object),
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
        "accepted" | "refused" | "unsupported" | "failed_before_launch"
    ) {
        return Err(ContractError::UnknownInvocationDecision(state.to_owned()));
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
    if total != unsigned(reservation, "total_required_bytes")?
        || unsigned(reservation, "reserved_bytes")? < total
    {
        return Err(ContractError::InvalidReservationArithmetic);
    }
    if text(reservation, "decision")? != "reserved" {
        return Err(ContractError::CustodyNotReserved);
    }
    let reserved = Timestamp::parse(text(reservation, "reserved_at")?)?;
    let expires = Timestamp::parse(text(reservation, "expires_at")?)?;
    if expires.instant() <= reserved.instant() {
        return Err(ContractError::ExpiredCustodyReservation);
    }
    Ok(())
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
    let elapsed = deadline
        .instant()
        .signed_duration_since(launched.instant())
        .num_milliseconds();
    if elapsed <= 0
        || u64::try_from(elapsed).ok() != Some(unsigned(launch, "maximum_execution_ms")?)
    {
        return Err(ContractError::LaunchDeadlineSubstitution);
    }
    Ok(())
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

fn resolve_pointer<'a>(document: &'a Value, pointer: &str) -> Result<&'a Value> {
    if pointer.is_empty() {
        return Ok(document);
    }
    let mut current = document;
    let path = pointer
        .strip_prefix('/')
        .ok_or_else(|| ContractError::InvalidJsonPointer(pointer.to_owned()))?;
    for raw in path.split('/') {
        let token = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(object) => object
                .get(&token)
                .ok_or_else(|| ContractError::UnresolvedJsonPointer(pointer.to_owned()))?,
            Value::Array(array) => array
                .get(
                    token
                        .parse::<usize>()
                        .map_err(|_| ContractError::UnresolvedJsonPointer(pointer.to_owned()))?,
                )
                .ok_or_else(|| ContractError::UnresolvedJsonPointer(pointer.to_owned()))?,
            _ => return Err(ContractError::UnresolvedJsonPointer(pointer.to_owned())),
        };
    }
    Ok(current)
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
