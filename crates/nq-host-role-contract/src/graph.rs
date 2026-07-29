//! Cross-record resolution and semantic join validation.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::Sha256Digest;
use serde_json::Value;

use crate::{
    ContractError, Result,
    identity::{IdentityCatalog, IdentityRef, RecordRef, Timestamp},
    record::{RuntimeSchema, ValidatedRuntimeRecord},
};

/// Exact externally retained record references admitted for one validation.
///
/// External admission confirms only that a reference may resolve outside this
/// record set. It grants no invocation, reliance, or mutation authority.
#[derive(Debug, Default, Clone)]
pub struct ExternalRecordCatalog {
    records: BTreeSet<RecordRef>,
}

impl ExternalRecordCatalog {
    /// Creates an empty external-reference catalog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeSet::new(),
        }
    }

    /// Admits one exact external reference.
    pub fn insert(&mut self, reference: RecordRef) {
        self.records.insert(reference);
    }

    fn contains(&self, reference: &RecordRef) -> bool {
        self.records.contains(reference)
    }
}

/// Exact catalogs used to validate one closed runtime record graph.
#[derive(Debug, Default, Clone)]
pub struct ValidationContext {
    /// Authoritative production identity descriptor catalog.
    pub identities: IdentityCatalog,
    /// Exact dependencies retained outside this record graph.
    pub external_records: ExternalRecordCatalog,
}

/// Closed immutable runtime record graph.
#[derive(Debug, Default, Clone)]
pub struct RuntimeRecordSet {
    records: BTreeMap<Sha256Digest, ValidatedRuntimeRecord>,
}

impl RuntimeRecordSet {
    /// Creates an empty record graph.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Inserts one locally validated canonical record.
    ///
    /// Exact replay is idempotent. Reusing a declared record identity with a
    /// different schema, digest, or bytes is refused.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::DuplicateRecordIdentity`] on substitution.
    pub fn insert(&mut self, record: ValidatedRuntimeRecord) -> Result<()> {
        match self.records.get(record.record_id()) {
            Some(existing)
                if existing.schema() == record.schema()
                    && existing.canonical_bytes() == record.canonical_bytes() =>
            {
                Ok(())
            }
            Some(_) => Err(ContractError::DuplicateRecordIdentity),
            None => {
                self.records.insert(record.record_id().clone(), record);
                Ok(())
            }
        }
    }

    /// Returns one exact record by immutable identity.
    #[must_use]
    pub fn get(&self, id: &Sha256Digest) -> Option<&ValidatedRuntimeRecord> {
        self.records.get(id)
    }

    /// Iterates all records in stable identity order.
    pub fn records(&self) -> impl Iterator<Item = &ValidatedRuntimeRecord> {
        self.records.values()
    }

    /// Returns the number of materialized records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Validates exact identity/reference closure, graph acyclicity, and the
    /// ratified topology, generation, invocation, delivery, and inspector
    /// joins implemented by this package.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal at the first failed invariant. No record is
    /// rewritten, defaulted, or reinterpreted.
    pub fn validate(&self, context: &ValidationContext) -> Result<()> {
        self.validate_catalogs(context)?;
        self.validate_reference_dag()?;
        self.validate_topology()?;
        self.validate_lifecycle()?;
        self.validate_invocations()?;
        self.validate_bindings()?;
        self.validate_delivery()?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Mirrors three closed ratified lifecycle graphs.
    fn validate_lifecycle(&self) -> Result<()> {
        let mut host_successors = BTreeMap::<Sha256Digest, usize>::new();
        for event in self.by_schema(RuntimeSchema::HostRoleLifecycleEventV1) {
            let value = event.record().as_value();
            if let Some(predecessor_value) = value["predecessor_events"]
                .as_array()
                .and_then(|items| items.first())
            {
                let predecessor = self.resolve_value(predecessor_value)?;
                require_schema(predecessor, RuntimeSchema::HostRoleLifecycleEventV1)?;
                require_equal(
                    value,
                    "node",
                    predecessor.record().as_value(),
                    "node",
                    "host lifecycle node",
                )?;
                if predecessor.record().as_value()["to_state"] != value["from_state"]
                    || timestamp(predecessor.record().as_value(), "occurred_at")?
                        >= timestamp(value, "occurred_at")?
                {
                    return Err(ContractError::LifecycleJoin(
                        "host lifecycle predecessor continuity",
                    ));
                }
                *host_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if host_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::LifecycleJoin("host lifecycle fork"));
                }
            }
            let operation = value["operation"]
                .as_str()
                .ok_or(ContractError::LifecycleJoin("host operation"))?;
            if let Some(proof) = value.get("operation_proof") {
                let proof = self.resolve_value(proof)?;
                let expected = match operation {
                    "complete_restore" => RuntimeSchema::RestoreActivationProofV1,
                    "begin_decommission" | "complete_decommission" => {
                        RuntimeSchema::DecommissionCutV1
                    }
                    _ => {
                        return Err(ContractError::LifecycleJoin(
                            "unexpected host lifecycle proof",
                        ));
                    }
                };
                require_schema(proof, expected)?;
                if !value["result_records"]
                    .as_array()
                    .is_some_and(|records| records.contains(&Value::from(proof.exact_reference())))
                {
                    return Err(ContractError::LifecycleJoin(
                        "operation proof outside result records",
                    ));
                }
            }
        }

        let mut witness_successors = BTreeMap::<Sha256Digest, usize>::new();
        for event in self.by_schema(RuntimeSchema::WitnessLifecycleEventV1) {
            let value = event.record().as_value();
            let attachment = self.resolve_field(value, "attachment")?;
            require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
            for field in ["node", "witness"] {
                require_equal(
                    value,
                    field,
                    attachment.record().as_value(),
                    field,
                    "witness lifecycle attachment",
                )?;
            }
            if value["attachment_generation"] != attachment.record().as_value()["generation"] {
                return Err(ContractError::LifecycleJoin(
                    "witness attachment generation",
                ));
            }
            if value["predecessor_event"] != Value::Null {
                let predecessor = self.resolve_field(value, "predecessor_event")?;
                require_schema(predecessor, RuntimeSchema::WitnessLifecycleEventV1)?;
                for field in ["node", "attachment", "witness", "attachment_generation"] {
                    if value[field] != predecessor.record().as_value()[field] {
                        return Err(ContractError::LifecycleJoin("witness predecessor identity"));
                    }
                }
                if predecessor.record().as_value()["to_state"] != value["from_state"]
                    || timestamp(predecessor.record().as_value(), "occurred_at")?
                        >= timestamp(value, "occurred_at")?
                {
                    return Err(ContractError::LifecycleJoin(
                        "witness predecessor continuity",
                    ));
                }
                *witness_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if witness_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::LifecycleJoin("witness lifecycle fork"));
                }
            }
        }

        let mut key_successors = BTreeMap::<Sha256Digest, usize>::new();
        for event in self.by_schema(RuntimeSchema::NodeKeyLifecycleEventV1) {
            let value = event.record().as_value();
            if value["predecessor_event"] != Value::Null {
                let predecessor = self.resolve_field(value, "predecessor_event")?;
                require_schema(predecessor, RuntimeSchema::NodeKeyLifecycleEventV1)?;
                require_equal(
                    value,
                    "node",
                    predecessor.record().as_value(),
                    "node",
                    "key lifecycle node",
                )?;
                if predecessor.record().as_value()["to_state"] != value["from_state"]
                    || timestamp(predecessor.record().as_value(), "occurred_at")?
                        >= timestamp(value, "occurred_at")?
                {
                    return Err(ContractError::LifecycleJoin("key predecessor continuity"));
                }
                *key_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if key_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::LifecycleJoin("key lifecycle fork"));
                }
            }
            if value["resulting_activation"] != Value::Null {
                let activation = self.resolve_field(value, "resulting_activation")?;
                require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
                if value["node"] != activation.record().as_value()["node"]
                    || value["key"] != activation.record().as_value()["active_key"]
                {
                    return Err(ContractError::LifecycleJoin("key resulting activation"));
                }
            }
        }

        self.validate_restore_and_decommission()
    }

    fn validate_restore_and_decommission(&self) -> Result<()> {
        for proof in self.by_schema(RuntimeSchema::RestoreActivationProofV1) {
            let value = proof.record().as_value();
            let enrollment = self.resolve_field(value, "predecessor_enrollment")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_equal(
                value,
                "node",
                enrollment.record().as_value(),
                "node",
                "restore enrollment node",
            )?;
            if value["decision"] == "eligible_enrolled_inactive" {
                let key = self.resolve_field(value, "new_key_event")?;
                let activation = self.resolve_field(value, "activation_candidate")?;
                require_schema(key, RuntimeSchema::NodeKeyLifecycleEventV1)?;
                require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
                if key.record().as_value()["node"] != value["node"]
                    || activation.record().as_value()["node"] != value["node"]
                    || key.record().as_value()["resulting_activation"]
                        != Value::from(activation.exact_reference())
                    || activation.record().as_value()["active_key"]
                        != key.record().as_value()["key"]
                {
                    return Err(ContractError::RetirementJoin(
                        "restore activation candidate",
                    ));
                }
            }
        }

        for snapshot in self.by_schema(RuntimeSchema::DecommissionLedgerSnapshotV1) {
            let value = snapshot.record().as_value();
            let enrollment = self.resolve_field(value, "enrollment")?;
            let activation = self.resolve_field(value, "activation")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            if value["node"] != enrollment.record().as_value()["node"]
                || value["node"] != activation.record().as_value()["node"]
                || value["enrollment"] != activation.record().as_value()["enrollment"]
                || value["namespace"] != enrollment.record().as_value()["namespace"]
                || value["namespace"] != activation.record().as_value()["namespace"]
            {
                return Err(ContractError::RetirementJoin("decommission snapshot scope"));
            }
        }

        let mut cut_successors = BTreeMap::<Sha256Digest, usize>::new();
        for cut in self.by_schema(RuntimeSchema::DecommissionCutV1) {
            let value = cut.record().as_value();
            let enrollment = self.resolve_field(value, "enrollment")?;
            let activation = self.resolve_field(value, "activation")?;
            let snapshot = self.resolve_field(value, "ledger_snapshot")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(snapshot, RuntimeSchema::DecommissionLedgerSnapshotV1)?;
            for target in [enrollment, activation, snapshot] {
                if value["node"] != target.record().as_value()["node"] {
                    return Err(ContractError::RetirementJoin("decommission node"));
                }
            }
            if value["enrollment"] != activation.record().as_value()["enrollment"]
                || value["enrollment"] != snapshot.record().as_value()["enrollment"]
                || value["activation"] != snapshot.record().as_value()["activation"]
                || value["effective_at"] != snapshot.record().as_value()["evaluated_at"]
            {
                return Err(ContractError::RetirementJoin("decommission cut snapshot"));
            }
            if value["result_state"] == "decommissioned" {
                let predecessor = self.resolve_field(value, "predecessor_cut")?;
                require_schema(predecessor, RuntimeSchema::DecommissionCutV1)?;
                if predecessor.record().as_value()["result_state"] != "draining"
                    || predecessor.record().as_value()["node"] != value["node"]
                    || timestamp(predecessor.record().as_value(), "effective_at")?
                        >= timestamp(value, "effective_at")?
                {
                    return Err(ContractError::RetirementJoin("decommission predecessor"));
                }
                *cut_successors
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if cut_successors[predecessor.record_id()] > 1 {
                    return Err(ContractError::RetirementJoin("decommission cut fork"));
                }
            }
        }
        Ok(())
    }

    fn validate_catalogs(&self, context: &ValidationContext) -> Result<()> {
        for record in self.records() {
            let mut identities = Vec::new();
            let mut references = Vec::new();
            collect_carriers(record.record().as_value(), &mut identities, &mut references)?;
            for identity in identities {
                context.identities.resolve(&identity)?;
            }
            for reference in references {
                match self.records.get(&reference.record_id) {
                    Some(target)
                        if target.schema().as_str() == reference.schema.as_str()
                            && target.bytes_digest() == &reference.bytes_digest => {}
                    Some(_) => return Err(ContractError::RecordReferenceSubstitution),
                    None if context.external_records.contains(&reference) => {}
                    None => {
                        return Err(ContractError::UnresolvedRecordReference(
                            reference.record_id.to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_reference_dag(&self) -> Result<()> {
        let mut edges: BTreeMap<Sha256Digest, BTreeSet<Sha256Digest>> = BTreeMap::new();
        for record in self.records() {
            let mut identities = Vec::new();
            let mut references = Vec::new();
            collect_carriers(record.record().as_value(), &mut identities, &mut references)?;
            edges.insert(
                record.record_id().clone(),
                references
                    .into_iter()
                    .filter(|reference| self.records.contains_key(&reference.record_id))
                    .map(|reference| reference.record_id)
                    .collect(),
            );
        }
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for node in edges.keys() {
            visit_reference_dag(node, &edges, &mut visiting, &mut visited)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Closed topology join is intentionally audited together.
    fn validate_topology(&self) -> Result<()> {
        for activation in self.by_schema(RuntimeSchema::RuntimeActivationV1) {
            let value = activation.record().as_value();
            let enrollment = self.resolve_field(value, "enrollment")?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            let role = self.resolve_field(value, "role_manifest")?;
            require_schema(role, RuntimeSchema::RoleManifestV1)?;
            let cohort = self.resolve_field(value, "cohort_manifest")?;
            require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;

            require_equal(
                value,
                "node",
                enrollment.record().as_value(),
                "node",
                "node",
            )?;
            require_equal(value, "role", role.record().as_value(), "role", "role")?;
            require_equal(
                value,
                "role_generation",
                role.record().as_value(),
                "generation",
                "role generation",
            )?;
            require_equal(
                value,
                "static_profile_cohort",
                cohort.record().as_value(),
                "cohort",
                "cohort",
            )?;
            require_equal(
                value,
                "cohort_generation",
                cohort.record().as_value(),
                "generation",
                "cohort generation",
            )?;

            let relations = value["relations"]
                .as_object()
                .ok_or(ContractError::TopologyJoin("activation relations"))?;
            let required_relations = [
                "node_subject",
                "subject_platform",
                "node_vantage",
                "node_role",
                "node_static_profile_cohort",
            ];
            if relations
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(required_relations)
            {
                return Err(ContractError::TopologyJoin("activation relation closure"));
            }
            for (kind, reference) in relations {
                let relation = self.resolve_value(reference)?;
                require_schema(relation, RuntimeSchema::HostRoleRelationV1)?;
                if relation.record().as_value()["relation_kind"] != *kind {
                    return Err(ContractError::TopologyJoin("relation kind"));
                }
                validate_relation_endpoints(value, relation.record().as_value())?;
            }

            let attachments = value["witness_attachments"]
                .as_array()
                .ok_or(ContractError::TopologyJoin("activation attachments"))?;
            if attachments.is_empty() {
                return Err(ContractError::TopologyJoin("empty activation attachments"));
            }
            for reference in attachments {
                let attachment = self.resolve_value(reference)?;
                require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
                require_equal(
                    attachment.record().as_value(),
                    "node",
                    value,
                    "node",
                    "attachment node",
                )?;
                require_reference_equal(
                    attachment.record().as_value(),
                    "enrollment",
                    enrollment,
                    "attachment enrollment",
                )?;
                require_equal(
                    attachment.record().as_value(),
                    "role",
                    value,
                    "role",
                    "attachment role",
                )?;
                require_reference_equal(
                    attachment.record().as_value(),
                    "role_manifest",
                    role,
                    "attachment role manifest",
                )?;
                validate_witness_slot(attachment.record().as_value(), role.record().as_value())?;
            }

            let compatible = role.record().as_value()["compatible_static_profile_cohorts"]
                .as_array()
                .ok_or(ContractError::TopologyJoin("role cohort compatibility"))?;
            let cohort_ref = cohort.exact_reference();
            let admitted = compatible.iter().any(|entry| {
                entry["cohort"] == value["static_profile_cohort"]
                    && entry["generation"] == value["cohort_generation"]
                    && serde_json::from_value::<RecordRef>(entry["manifest"].clone())
                        .is_ok_and(|reference| reference == cohort_ref)
            });
            if !admitted {
                return Err(ContractError::TopologyJoin("role/cohort compatibility"));
            }
        }
        Ok(())
    }

    fn validate_invocations(&self) -> Result<()> {
        for decision in self.by_schema(RuntimeSchema::InvocationDecisionV1) {
            let value = decision.record().as_value();
            let request = self.resolve_field(value, "request")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            if value["request_digest"] != request.record().as_value()["request_digest"] {
                return Err(ContractError::InvocationJoin("decision request digest"));
            }
            let activation = self.resolve_field(value, "activation_snapshot")?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            if value["invocation_authorization"]
                != request.record().as_value()["invocation_authorization"]
                || value["authentication_evidence"]
                    != request.record().as_value()["authentication_evidence"]
            {
                return Err(ContractError::InvocationJoin(
                    "decision authentication/authorization",
                ));
            }
        }
        for reservation in self.by_schema(RuntimeSchema::CustodyReservationV1) {
            let value = reservation.record().as_value();
            let request = self.resolve_field(value, "request")?;
            let activation = self.resolve_field(value, "activation")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_equal(
                value,
                "node",
                request.record().as_value(),
                "target",
                "reservation request target",
            )
            .or_else(|_| {
                if value["node"] == request.record().as_value()["target"]["node"] {
                    Ok(())
                } else {
                    Err(ContractError::InvocationJoin("reservation node"))
                }
            })?;
            if value["node"] != activation.record().as_value()["node"]
                || value["profile"] != request.record().as_value()["profile"]
            {
                return Err(ContractError::InvocationJoin(
                    "reservation activation/profile",
                ));
            }
        }
        for launch in self.by_schema(RuntimeSchema::ExecutionLaunchV1) {
            let value = launch.record().as_value();
            let request = self.resolve_field(value, "outer_request")?;
            let decision = self.resolve_field(value, "invocation_decision")?;
            let activation = self.resolve_field(value, "activation_snapshot")?;
            let reservation = self.resolve_field(value, "custody_reservation")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            require_schema(decision, RuntimeSchema::InvocationDecisionV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(reservation, RuntimeSchema::CustodyReservationV1)?;
            require_reference_equal(
                decision.record().as_value(),
                "request",
                request,
                "launch decision request",
            )?;
            require_reference_equal(
                reservation.record().as_value(),
                "request",
                request,
                "launch reservation request",
            )?;
            require_reference_equal(
                reservation.record().as_value(),
                "activation",
                activation,
                "launch reservation activation",
            )?;
            if value["node"] != request.record().as_value()["target"]["node"]
                || value["node"] != activation.record().as_value()["node"]
                || value["profile"] != request.record().as_value()["profile"]
            {
                return Err(ContractError::InvocationJoin("launch node/profile"));
            }
            for attachment in value["selected_witness_attachments"]
                .as_array()
                .ok_or(ContractError::InvocationJoin("launch attachments"))?
            {
                let attachment = self.resolve_value(attachment)?;
                require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
                if !activation.record().as_value()["witness_attachments"]
                    .as_array()
                    .is_some_and(|items| items.contains(&Value::from(attachment.exact_reference())))
                {
                    return Err(ContractError::InvocationJoin(
                        "launch attachment outside activation",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_bindings(&self) -> Result<()> {
        for binding in self.by_schema(RuntimeSchema::ExecutionIdentityBindingV2) {
            let value = binding.record().as_value();
            let request = self.resolve_field(value, "outer_request")?;
            let decision = self.resolve_field(value, "invocation_decision")?;
            let launch = self.resolve_field(value, "execution_launch")?;
            let enrollment = self.resolve_field(value, "enrollment")?;
            let activation = self.resolve_field(value, "activation")?;
            let role = self.resolve_field(value, "role_manifest")?;
            let cohort = self.resolve_field(value, "static_profile_cohort_manifest")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            require_schema(decision, RuntimeSchema::InvocationDecisionV1)?;
            require_schema(launch, RuntimeSchema::ExecutionLaunchV1)?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(role, RuntimeSchema::RoleManifestV1)?;
            require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;

            require_reference_equal(
                launch.record().as_value(),
                "outer_request",
                request,
                "binding launch request",
            )?;
            require_reference_equal(
                launch.record().as_value(),
                "invocation_decision",
                decision,
                "binding launch decision",
            )?;
            require_reference_equal(
                launch.record().as_value(),
                "activation_snapshot",
                activation,
                "binding launch activation",
            )?;
            require_reference_equal(
                activation.record().as_value(),
                "enrollment",
                enrollment,
                "binding activation enrollment",
            )?;
            require_reference_equal(
                activation.record().as_value(),
                "role_manifest",
                role,
                "binding activation role",
            )?;
            require_reference_equal(
                activation.record().as_value(),
                "cohort_manifest",
                cohort,
                "binding activation cohort",
            )?;
            if value["source_relations"] != activation.record().as_value()["relations"]
                || value["diagnostic"]["request_id"] != request.record().as_value()["request_id"]
            {
                return Err(ContractError::TopologyJoin(
                    "binding relation/request closure",
                ));
            }
            if value["witness_attachments"] != activation.record().as_value()["witness_attachments"]
            {
                return Err(ContractError::TopologyJoin(
                    "binding witness attachment closure",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Delivery state and custody joins form one closed law.
    fn validate_delivery(&self) -> Result<()> {
        for envelope in self.by_schema(RuntimeSchema::AuthenticatedArtifactEnvelopeV1) {
            let value = envelope.record().as_value();
            let binding = self.resolve_field(value, "execution_binding")?;
            let activation = self.resolve_field(value, "producer_activation")?;
            require_schema(binding, RuntimeSchema::ExecutionIdentityBindingV2)?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            let artifact = &value["artifact"];
            let diagnostic = &binding.record().as_value()["diagnostic"];
            if ["schema", "artifact_id", "file_bytes_digest"]
                .iter()
                .any(|field| artifact[*field] != diagnostic[*field])
                || value["producer_node"] != activation.record().as_value()["node"]
                || value["producer_key_generation"] != activation.record().as_value()["active_key"]
            {
                return Err(ContractError::DeliveryJoin(
                    "envelope artifact/producer binding",
                ));
            }
        }

        for attempt in self.by_schema(RuntimeSchema::ArtifactDeliveryAttemptV1) {
            let value = attempt.record().as_value();
            let envelope = self.resolve_field(value, "envelope")?;
            require_schema(envelope, RuntimeSchema::AuthenticatedArtifactEnvelopeV1)?;
            if !artifact_tuple_equal(
                &value["artifact"],
                &envelope.record().as_value()["artifact"],
            ) || value["producer_node"] != envelope.record().as_value()["producer_node"]
                || value["producer_key_generation"]
                    != envelope.record().as_value()["producer_key_generation"]
                || value["destination"] != envelope.record().as_value()["intended_receiver"]
                || value["destination_generation"]
                    != envelope.record().as_value()["destination_generation"]
                || value["transport_policy"] != envelope.record().as_value()["transport_policy"]
            {
                return Err(ContractError::DeliveryJoin("attempt envelope binding"));
            }
            if value["predecessor_attempt_record"] != Value::Null {
                let predecessor = self.resolve_field(value, "predecessor_attempt_record")?;
                require_schema(predecessor, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
                if predecessor.record().as_value()["envelope"] != value["envelope"]
                    || predecessor.record().as_value()["artifact"] != value["artifact"]
                {
                    return Err(ContractError::DeliveryJoin("attempt predecessor"));
                }
            }
        }

        for receipt in self.by_schema(RuntimeSchema::ArtifactCustodyReceiptV1) {
            let value = receipt.record().as_value();
            let envelope = self.resolve_field(value, "envelope")?;
            let attempt = self.resolve_field(value, "attempt")?;
            require_schema(envelope, RuntimeSchema::AuthenticatedArtifactEnvelopeV1)?;
            require_schema(attempt, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
            if !artifact_tuple_equal(
                &value["artifact"],
                &envelope.record().as_value()["artifact"],
            ) || !artifact_tuple_equal(
                &value["artifact"],
                &attempt.record().as_value()["artifact"],
            ) || value["authenticated_sender"] != envelope.record().as_value()["producer_node"]
                || value["receiver"] != envelope.record().as_value()["intended_receiver"]
            {
                return Err(ContractError::DeliveryJoin("receiver custody binding"));
            }
        }

        let deliveries: Vec<_> = self
            .by_schema(RuntimeSchema::ArtifactDeliveryRecordV1)
            .collect();
        let mut successor_counts = BTreeMap::<Sha256Digest, usize>::new();
        for delivery in &deliveries {
            let value = delivery.record().as_value();
            if value["predecessor"] == Value::Null {
                if !matches!(
                    value["state"].as_str(),
                    Some("not_required" | "export_committed")
                ) {
                    return Err(ContractError::DeliveryJoin("delivery root state"));
                }
            } else {
                let predecessor = self.resolve_field(value, "predecessor")?;
                require_schema(predecessor, RuntimeSchema::ArtifactDeliveryRecordV1)?;
                *successor_counts
                    .entry(predecessor.record_id().clone())
                    .or_default() += 1;
                if successor_counts[predecessor.record_id()] > 1 {
                    return Err(ContractError::DeliveryJoin("delivery chain fork"));
                }
                for field in [
                    "artifact",
                    "producer_node",
                    "producer_key_generation",
                    "destination",
                    "destination_generation",
                    "transport_policy",
                ] {
                    if value[field] != predecessor.record().as_value()[field] {
                        return Err(ContractError::DeliveryJoin(
                            "delivery transition substitution",
                        ));
                    }
                }
                if !allowed_delivery_transition(
                    predecessor.record().as_value()["state"].as_str(),
                    value["state"].as_str(),
                ) {
                    return Err(ContractError::DeliveryJoin("invalid delivery transition"));
                }
            }
        }
        Ok(())
    }

    fn by_schema(&self, schema: RuntimeSchema) -> impl Iterator<Item = &ValidatedRuntimeRecord> {
        self.records()
            .filter(move |record| record.schema() == schema)
    }

    fn resolve_field<'a>(
        &'a self,
        value: &Value,
        field: &'static str,
    ) -> Result<&'a ValidatedRuntimeRecord> {
        self.resolve_value(
            value
                .get(field)
                .ok_or(ContractError::TopologyJoin("missing reference field"))?,
        )
    }

    fn resolve_value(&self, value: &Value) -> Result<&ValidatedRuntimeRecord> {
        let reference: RecordRef = serde_json::from_value(value.clone())?;
        let target = self.records.get(&reference.record_id).ok_or_else(|| {
            ContractError::UnresolvedRecordReference(reference.record_id.to_string())
        })?;
        if target.schema().as_str() != reference.schema.as_str()
            || target.bytes_digest() != &reference.bytes_digest
        {
            return Err(ContractError::RecordReferenceSubstitution);
        }
        Ok(target)
    }
}

fn visit_reference_dag(
    node: &Sha256Digest,
    edges: &BTreeMap<Sha256Digest, BTreeSet<Sha256Digest>>,
    visiting: &mut BTreeSet<Sha256Digest>,
    visited: &mut BTreeSet<Sha256Digest>,
) -> Result<()> {
    if visiting.contains(node) {
        return Err(ContractError::RecordReferenceCycle);
    }
    if visited.contains(node) {
        return Ok(());
    }
    visiting.insert(node.clone());
    if let Some(children) = edges.get(node) {
        for child in children {
            visit_reference_dag(child, edges, visiting, visited)?;
        }
    }
    visiting.remove(node);
    visited.insert(node.clone());
    Ok(())
}

fn artifact_tuple_equal(left: &Value, right: &Value) -> bool {
    ["schema", "artifact_id", "file_bytes_digest", "byte_length"]
        .iter()
        .all(|field| {
            left.get(*field)
                .zip(right.get(*field))
                .is_none_or(|(left, right)| left == right)
        })
        && ["schema", "artifact_id", "file_bytes_digest"]
            .iter()
            .all(|field| left.get(*field) == right.get(*field))
}

fn collect_carriers(
    value: &Value,
    identities: &mut Vec<IdentityRef>,
    references: &mut Vec<RecordRef>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
            if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                identities.push(serde_json::from_value(value.clone())?);
                return Ok(());
            }
            if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                references.push(serde_json::from_value(value.clone())?);
                return Ok(());
            }
            for child in object.values() {
                collect_carriers(child, identities, references)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_carriers(child, identities, references)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn require_schema(record: &ValidatedRuntimeRecord, expected: RuntimeSchema) -> Result<()> {
    if record.schema() != expected {
        return Err(ContractError::RecordReferenceSubstitution);
    }
    Ok(())
}

fn require_reference_equal(
    source: &Value,
    field: &'static str,
    target: &ValidatedRuntimeRecord,
    context: &'static str,
) -> Result<()> {
    if source[field] != Value::from(target.exact_reference()) {
        return Err(ContractError::TopologyJoin(context));
    }
    Ok(())
}

fn require_equal(
    left: &Value,
    left_field: &'static str,
    right: &Value,
    right_field: &'static str,
    context: &'static str,
) -> Result<()> {
    if left[left_field] != right[right_field] {
        return Err(ContractError::TopologyJoin(context));
    }
    Ok(())
}

fn timestamp(value: &Value, field: &'static str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    let text = value[field]
        .as_str()
        .ok_or(ContractError::ExpectedString(field))?;
    Ok(Timestamp::parse(text.to_owned())?.instant())
}

fn validate_relation_endpoints(activation: &Value, relation: &Value) -> Result<()> {
    let kind = relation["relation_kind"]
        .as_str()
        .ok_or(ContractError::TopologyJoin("relation kind"))?;
    let node = &activation["node"];
    match kind {
        "node_subject" | "node_vantage" | "node_role" | "node_static_profile_cohort"
            if relation["left"] != *node =>
        {
            Err(ContractError::TopologyJoin("relation node endpoint"))
        }
        "node_role" if relation["right"] != activation["role"] => {
            Err(ContractError::TopologyJoin("relation role endpoint"))
        }
        "node_static_profile_cohort"
            if relation["right"] != activation["static_profile_cohort"] =>
        {
            Err(ContractError::TopologyJoin("relation cohort endpoint"))
        }
        _ => Ok(()),
    }
}

fn validate_witness_slot(attachment: &Value, role: &Value) -> Result<()> {
    let slot_id = attachment["role_slot"]
        .as_str()
        .ok_or(ContractError::WitnessSlotJoin("slot identity"))?;
    let slots = role["witness_slots"]
        .as_array()
        .ok_or(ContractError::WitnessSlotJoin("role slots"))?;
    let slot = slots
        .iter()
        .find(|slot| slot["slot_id"].as_str() == Some(slot_id))
        .ok_or(ContractError::WitnessSlotJoin("unknown role slot"))?;
    if attachment["witness_class"] != slot["witness_class"] {
        return Err(ContractError::WitnessSlotJoin("witness class"));
    }
    for (attachment_field, ceiling_field) in [
        ("privileges", "privilege_ceiling"),
        ("namespaces", "namespace_ceiling"),
        ("supported_profiles", "supported_profiles"),
    ] {
        let ceiling = slot[ceiling_field]
            .as_array()
            .ok_or(ContractError::WitnessSlotJoin("role slot ceiling"))?;
        let members = attachment[attachment_field]
            .as_array()
            .ok_or(ContractError::WitnessSlotJoin("attachment members"))?;
        if members.iter().any(|member| !ceiling.contains(member)) {
            return Err(ContractError::WitnessSlotJoin(attachment_field));
        }
    }
    Ok(())
}

fn allowed_delivery_transition(predecessor: Option<&str>, successor: Option<&str>) -> bool {
    matches!(
        (predecessor, successor),
        (
            Some("export_committed"),
            Some("queued" | "blocked_backpressure" | "committed_unavailable")
        ) | (
            Some("queued"),
            Some("attempt_in_progress" | "blocked_backpressure" | "committed_unavailable")
        ) | (
            Some("attempt_in_progress"),
            Some(
                "retry_scheduled"
                    | "delivery_ambiguous"
                    | "acknowledged_custody"
                    | "terminal_rejected"
                    | "attempts_exhausted"
                    | "committed_unavailable"
            )
        ) | (
            Some("retry_scheduled"),
            Some("attempt_in_progress" | "attempts_exhausted" | "committed_unavailable")
        ) | (
            Some("delivery_ambiguous"),
            Some(
                "attempt_in_progress"
                    | "acknowledged_custody"
                    | "attempts_exhausted"
                    | "committed_unavailable"
            )
        ) | (
            Some("blocked_backpressure" | "committed_unavailable"),
            Some("queued" | "committed_unavailable")
        )
    )
}

impl From<RecordRef> for Value {
    fn from(value: RecordRef) -> Self {
        serde_json::to_value(value).expect("RecordRef is JSON serializable")
    }
}
