//! Cross-record resolution and semantic join validation.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, semantic_digest};
use serde_json::{Map, Value};

use crate::{
    ContractError, Result,
    identity::{EffectiveInterval, IdentityCatalog, IdentityRef, RecordRef, Timestamp},
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
        self.validate_authorizations()?;
        self.validate_topology()?;
        self.validate_lifecycle()?;
        self.validate_invocations()?;
        self.validate_bindings()?;
        self.validate_delivery()?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One closed authorization/consumer law.
    fn validate_authorizations(&self) -> Result<()> {
        let administrative: Vec<_> = self
            .by_schema(RuntimeSchema::OperationAuthorizationV1)
            .filter(|record| record.record().as_value()["scope"] == "administrative_lifecycle")
            .collect();
        let mut occurrence_ids = BTreeSet::new();
        for authorization in &administrative {
            let occurrence =
                authorization.record().as_value()["binding"]["transition_occurrence_id"]
                    .as_str()
                    .ok_or(ContractError::AuthorizationJoin(
                        "administrative occurrence identity",
                    ))?;
            if !occurrence_ids.insert(occurrence) {
                return Err(ContractError::AuthorizationJoin(
                    "administrative occurrence identity replay",
                ));
            }
        }

        let mut consumers = BTreeMap::<Sha256Digest, Vec<&ValidatedRuntimeRecord>>::new();
        for consumer in self.records() {
            let Some(field) = administrative_authority_field(consumer.schema()) else {
                continue;
            };
            let authorization = self.resolve_field(consumer.record().as_value(), field)?;
            require_schema(authorization, RuntimeSchema::OperationAuthorizationV1)?;
            if authorization.record().as_value()["scope"] != "administrative_lifecycle" {
                return Err(ContractError::AuthorizationJoin(
                    "administrative consumer substituted authorization scope",
                ));
            }
            consumers
                .entry(authorization.record_id().clone())
                .or_default()
                .push(consumer);
        }

        let neutral_digests = self.administrative_neutral_digests()?;
        for authorization in administrative {
            let value = authorization.record().as_value();
            let binding = value["binding"]
                .as_object()
                .ok_or(ContractError::AuthorizationJoin(
                    "administrative binding absent",
                ))?;
            let operation = value["operation"]
                .as_str()
                .ok_or(ContractError::AuthorizationJoin(
                    "administrative operation absent",
                ))?;
            let authorized = binding["authorized_records"].as_array().ok_or(
                ContractError::AuthorizationJoin("authorized record set absent"),
            )?;
            let mut previous: Option<(String, Sha256Digest)> = None;
            let mut expected = BTreeSet::new();
            for item in authorized {
                let schema = item["schema"]
                    .as_str()
                    .ok_or(ContractError::AuthorizationJoin("authorized record schema"))?
                    .to_owned();
                let record_id: Sha256Digest = serde_json::from_value(item["record_id"].clone())?;
                let preimage: Sha256Digest =
                    serde_json::from_value(item["record_preimage_digest"].clone())?;
                let key = (schema.clone(), record_id.clone());
                if previous.as_ref().is_some_and(|prior| prior >= &key)
                    || !expected.insert(key.clone())
                {
                    return Err(ContractError::AuthorizationJoin(
                        "authorized records are not strictly sorted and unique",
                    ));
                }
                previous = Some(key.clone());
                if neutral_digests.get(&key) != Some(&preimage) {
                    return Err(ContractError::AuthorizationJoin(
                        "authority-neutral consumer preimage mismatch",
                    ));
                }
            }

            let mut snapshot = binding.clone();
            snapshot.remove("input_snapshot_digest");
            snapshot.insert("operation".to_owned(), Value::String(operation.to_owned()));
            let expected_snapshot = semantic_digest(&Value::Object(snapshot))?;
            if binding["input_snapshot_digest"] != Value::String(expected_snapshot.to_string()) {
                return Err(ContractError::AuthorizationJoin(
                    "administrative input snapshot substitution",
                ));
            }

            let actual_records = consumers
                .get(authorization.record_id())
                .map_or(&[][..], Vec::as_slice);
            let actual: BTreeSet<_> = actual_records
                .iter()
                .map(|record| {
                    (
                        record.schema().as_str().to_owned(),
                        record.record_id().clone(),
                    )
                })
                .collect();
            match value["decision"].as_str() {
                Some("granted") if actual != expected => {
                    return Err(ContractError::AuthorizationJoin(
                        "grant consumer set differs from authorized record set",
                    ));
                }
                Some("refused") if !actual.is_empty() => {
                    return Err(ContractError::AuthorizationJoin(
                        "refused administrative authority was consumed",
                    ));
                }
                Some("granted" | "refused") => {}
                _ => {
                    return Err(ContractError::AuthorizationJoin(
                        "invalid administrative decision",
                    ));
                }
            }

            if value["decision"] == "granted" && !administrative_shape(operation, actual_records)? {
                return Err(ContractError::AuthorizationJoin(
                    "administrative operation did not close its exact record shape",
                ));
            }
            let interval: EffectiveInterval =
                serde_json::from_value(value["effective_interval"].clone())?;
            for consumer in actual_records {
                if !operation_matches_consumer(operation, consumer.record().as_value())?
                    || !interval.contains(&Timestamp::parse(
                        consumer_occurrence_time(consumer)?.to_owned(),
                    )?)
                {
                    return Err(ContractError::AuthorizationJoin(
                        "administrative grant operation or interval mismatch",
                    ));
                }
                self.validate_administrative_scope(operation, binding, consumer)?;
            }
        }
        Ok(())
    }

    fn administrative_neutral_digests(
        &self,
    ) -> Result<BTreeMap<(String, Sha256Digest), Sha256Digest>> {
        let consumers: BTreeMap<_, _> = self
            .records()
            .filter(|record| administrative_authority_field(record.schema()).is_some())
            .map(|record| {
                (
                    (
                        record.schema().as_str().to_owned(),
                        record.record_id().clone(),
                    ),
                    record,
                )
            })
            .collect();
        let mut memo = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        for key in consumers.keys() {
            administrative_neutral_digest(self, &consumers, key, &mut memo, &mut visiting)?;
        }
        Ok(memo)
    }

    #[allow(clippy::too_many_lines)] // Exact per-consumer administrative scope joins.
    fn validate_administrative_scope(
        &self,
        operation: &str,
        binding: &Map<String, Value>,
        consumer: &ValidatedRuntimeRecord,
    ) -> Result<()> {
        let value = consumer.record().as_value();
        if value
            .get("node")
            .is_some_and(|node| node != &binding["node"])
        {
            return Err(ContractError::AuthorizationJoin(
                "administrative consumer substituted node",
            ));
        }
        match consumer.schema() {
            RuntimeSchema::NodeEnrollmentV1 => {
                if operation != "enroll"
                    || value["initial_key"] != binding["active_key"]
                    || value["deployment_generation"] != binding["deployment_generation"]
                    || value["configuration_generation"] != binding["configuration_generation"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "enrollment substituted authorized generations",
                    ));
                }
            }
            RuntimeSchema::WitnessAttachmentV1 => {
                let role = self.resolve_field(value, "role_manifest")?;
                if operation != "admit_witness"
                    || !binding["witness_attachment_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.contains(&value["attachment_id"]))
                    || role.record().as_value()["manifest_id"] != binding["role_manifest_id"]
                    || role.record().as_value()["generation"] != binding["role_generation"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "witness attachment substituted role or identity",
                    ));
                }
            }
            RuntimeSchema::HostRoleRelationV1 => {
                let (left, right) = self.administrative_relation_endpoints(binding, value)?;
                if value["left"] != left || value["right"] != right {
                    return Err(ContractError::AuthorizationJoin(
                        "relation substituted authorized endpoints",
                    ));
                }
            }
            RuntimeSchema::RuntimeActivationV1 => {
                let attachments: Vec<_> = value["witness_attachments"]
                    .as_array()
                    .ok_or(ContractError::AuthorizationJoin(
                        "activation witness set absent",
                    ))?
                    .iter()
                    .map(|item| item["record_id"].clone())
                    .collect();
                if value["role_manifest"]["record_id"] != binding["role_manifest_id"]
                    || value["role_generation"] != binding["role_generation"]
                    || value["cohort_manifest"]["record_id"] != binding["cohort_manifest_id"]
                    || value["cohort_generation"] != binding["cohort_generation"]
                    || Value::Array(attachments) != binding["witness_attachment_ids"]
                    || value["active_key"] != binding["active_key"]
                    || value["deployment_generation"] != binding["deployment_generation"]
                    || value["configuration_generation"] != binding["configuration_generation"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "activation substituted authorized topology or generations",
                    ));
                }
                for relation in value["relations"]
                    .as_object()
                    .ok_or(ContractError::AuthorizationJoin(
                        "activation relation set absent",
                    ))?
                    .values()
                {
                    let relation = self.resolve_value(relation)?;
                    let (left, right) = self
                        .administrative_relation_endpoints(binding, relation.record().as_value())?;
                    if relation.record().as_value()["left"] != left
                        || relation.record().as_value()["right"] != right
                    {
                        return Err(ContractError::AuthorizationJoin(
                            "activation relation scope substitution",
                        ));
                    }
                }
            }
            RuntimeSchema::HostRoleLifecycleEventV1
            | RuntimeSchema::WitnessLifecycleEventV1
            | RuntimeSchema::NodeKeyLifecycleEventV1 => {
                if value["from_state"] != binding["from_state"]
                    || value["to_state"] != binding["to_state"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "lifecycle transition substituted authorized state edge",
                    ));
                }
                if consumer.schema() == RuntimeSchema::NodeKeyLifecycleEventV1
                    && value["key"] != binding["active_key"]
                {
                    return Err(ContractError::AuthorizationJoin(
                        "key transition substituted active key",
                    ));
                }
            }
            RuntimeSchema::RestoreActivationProofV1 => {
                if value["new_deployment_generation"] != binding["deployment_generation"]
                    || (operation == "complete_restore"
                        && value["decision"] != "eligible_enrolled_inactive")
                {
                    return Err(ContractError::AuthorizationJoin(
                        "restore proof cannot complete from quarantine",
                    ));
                }
            }
            RuntimeSchema::DecommissionCutV1 => {
                let expected = if value["result_state"] == "decommissioned" {
                    "complete_decommission"
                } else {
                    "begin_decommission"
                };
                if operation != expected || binding["to_state"] != value["result_state"] {
                    return Err(ContractError::AuthorizationJoin(
                        "decommission cut substituted operation or state",
                    ));
                }
            }
            _ => {
                return Err(ContractError::AuthorizationJoin(
                    "unsupported administrative consumer schema",
                ));
            }
        }
        Ok(())
    }

    fn administrative_relation_endpoints(
        &self,
        binding: &Map<String, Value>,
        relation: &Value,
    ) -> Result<(Value, Value)> {
        let pair = match relation["relation_kind"].as_str() {
            Some("node_subject") => (binding["node"].clone(), binding["subject"].clone()),
            Some("subject_platform") => (binding["subject"].clone(), binding["platform"].clone()),
            Some("node_vantage") => (binding["node"].clone(), binding["vantage"].clone()),
            Some("node_role") => {
                let role_id: Sha256Digest =
                    serde_json::from_value(binding["role_manifest_id"].clone())?;
                let role = self.get(&role_id).ok_or(ContractError::AuthorizationJoin(
                    "authorized role manifest absent",
                ))?;
                require_schema(role, RuntimeSchema::RoleManifestV1)?;
                (
                    binding["node"].clone(),
                    role.record().as_value()["role"].clone(),
                )
            }
            Some("node_static_profile_cohort") => {
                let cohort_id: Sha256Digest =
                    serde_json::from_value(binding["cohort_manifest_id"].clone())?;
                let cohort = self
                    .get(&cohort_id)
                    .ok_or(ContractError::AuthorizationJoin(
                        "authorized cohort manifest absent",
                    ))?;
                require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;
                (
                    binding["node"].clone(),
                    cohort.record().as_value()["cohort"].clone(),
                )
            }
            _ => {
                return Err(ContractError::AuthorizationJoin(
                    "unknown administrative relation kind",
                ));
            }
        };
        Ok(pair)
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
        let activations: Vec<_> = self.by_schema(RuntimeSchema::RuntimeActivationV1).collect();
        for activation in &activations {
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
            for dependency in [role, cohort] {
                if !interval_covers(
                    &dependency.record().as_value()["effective_interval"],
                    &value["effective_interval"],
                )? {
                    return Err(ContractError::TopologyJoin(
                        "activation exceeds role/cohort effective interval",
                    ));
                }
            }
            for reference in relations.values() {
                let relation = self.resolve_value(reference)?;
                if !interval_covers(
                    &relation.record().as_value()["effective_interval"],
                    &value["effective_interval"],
                )? {
                    return Err(ContractError::TopologyJoin(
                        "activation exceeds relation effective interval",
                    ));
                }
            }
            for reference in attachments {
                let attachment = self.resolve_value(reference)?;
                if !interval_covers(
                    &attachment.record().as_value()["effective_interval"],
                    &value["effective_interval"],
                )? {
                    return Err(ContractError::TopologyJoin(
                        "activation exceeds witness effective interval",
                    ));
                }
            }
        }
        for (index, left) in activations.iter().enumerate() {
            for right in &activations[index + 1..] {
                let left_value = left.record().as_value();
                let right_value = right.record().as_value();
                if left_value["node"] == right_value["node"]
                    && intervals_overlap(
                        &left_value["effective_interval"],
                        &right_value["effective_interval"],
                    )?
                {
                    return Err(ContractError::TopologyJoin(
                        "node has overlapping effective activation intervals",
                    ));
                }
                if left_value["enrollment"] == right_value["enrollment"]
                    && left_value["active_key"] != right_value["active_key"]
                    && intervals_overlap(
                        &left_value["effective_interval"],
                        &right_value["effective_interval"],
                    )?
                {
                    return Err(ContractError::TopologyJoin(
                        "enrollment has overlapping active key generations",
                    ));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One closed request/admission/custody/launch law.
    fn validate_invocations(&self) -> Result<()> {
        let mut request_occurrences = BTreeMap::<(String, Sha256Digest, String), Vec<u8>>::new();
        let mut idempotency_occurrences =
            BTreeMap::<(String, Sha256Digest, String), Vec<u8>>::new();
        for request in self.by_schema(RuntimeSchema::DiagnosticInvocationRequestV1) {
            let value = request.record().as_value();
            let authorization = self.resolve_field(value, "invocation_authorization")?;
            require_schema(authorization, RuntimeSchema::OperationAuthorizationV1)?;
            let authorization_value = authorization.record().as_value();
            if authorization_value["scope"] != "diagnostic_invocation"
                || authorization_value["operation"] != "diagnostic.invoke"
                || authorization_value["decision"] != "granted"
                || authorization_value["requesting_principal"] != value["requesting_principal"]
            {
                return Err(ContractError::InvocationJoin(
                    "request lacks exact granted diagnostic authority",
                ));
            }
            let activation = self.resolve_field(&value["expected_binding"], "activation")?;
            let role = self.resolve_field(&value["expected_binding"], "role_manifest")?;
            let cohort = self.resolve_field(&value["expected_binding"], "cohort_manifest")?;
            let enrollment = self.resolve_field(&value["expected_binding"], "enrollment")?;
            require_schema(activation, RuntimeSchema::RuntimeActivationV1)?;
            require_schema(role, RuntimeSchema::RoleManifestV1)?;
            require_schema(cohort, RuntimeSchema::StaticProfileCohortManifestV1)?;
            require_schema(enrollment, RuntimeSchema::NodeEnrollmentV1)?;
            for (field, expected) in [
                ("node", &value["target"]["node"]),
                ("subject", &value["target"]["subject"]),
                ("vantage", &value["target"]["vantage"]),
            ] {
                let actual = match field {
                    "node" => activation.record().as_value()["node"].clone(),
                    "subject" => {
                        let relation = self.resolve_field(
                            &activation.record().as_value()["relations"],
                            "node_subject",
                        )?;
                        relation.record().as_value()["right"].clone()
                    }
                    "vantage" => {
                        let relation = self.resolve_field(
                            &activation.record().as_value()["relations"],
                            "node_vantage",
                        )?;
                        relation.record().as_value()["right"].clone()
                    }
                    _ => unreachable!(),
                };
                if &actual != expected {
                    return Err(ContractError::InvocationJoin(
                        "request target differs from effective activation",
                    ));
                }
            }
            if value["expected_binding"]["activation_generation"]
                != activation.record().as_value()["generation"]
                || value["expected_binding"]["role_generation"]
                    != role.record().as_value()["generation"]
                || value["expected_binding"]["cohort_generation"]
                    != cohort.record().as_value()["generation"]
                || value["expected_binding"]["witness_attachments"]
                    != activation.record().as_value()["witness_attachments"]
                || activation.record().as_value()["enrollment"]
                    != Value::from(enrollment.exact_reference())
                || activation.record().as_value()["role_manifest"]
                    != Value::from(role.exact_reference())
                || activation.record().as_value()["cohort_manifest"]
                    != Value::from(cohort.exact_reference())
            {
                return Err(ContractError::InvocationJoin(
                    "request expected topology generation substitution",
                ));
            }
            let profile = &value["profile"];
            if !role.record().as_value()["permitted_profiles"]
                .as_array()
                .is_some_and(|profiles| profiles.contains(profile))
                || !cohort.record().as_value()["members"]["profiles"]
                    .as_array()
                    .is_some_and(|profiles| profiles.contains(profile))
            {
                return Err(ContractError::InvocationJoin(
                    "profile absent from exact role/cohort",
                ));
            }
            for attachment_ref in value["expected_binding"]["witness_attachments"]
                .as_array()
                .ok_or(ContractError::InvocationJoin("request witness set absent"))?
            {
                let attachment = self.resolve_value(attachment_ref)?;
                require_schema(attachment, RuntimeSchema::WitnessAttachmentV1)?;
                if !attachment.record().as_value()["supported_profiles"]
                    .as_array()
                    .is_some_and(|profiles| profiles.contains(profile))
                {
                    return Err(ContractError::InvocationJoin(
                        "selected witness does not support profile",
                    ));
                }
            }
            let binding = serde_json::json!({
                "request_preimage_digest": value["request_preimage_digest"],
                "node": value["target"]["node"],
                "subject": value["target"]["subject"],
                "vantage": value["target"]["vantage"],
                "profile": value["profile"],
                "activation_id": activation.record_id(),
                "activation_generation": activation.record().as_value()["generation"],
                "role_manifest_id": role.record_id(),
                "role_generation": role.record().as_value()["generation"],
                "cohort_manifest_id": cohort.record_id(),
                "cohort_generation": cohort.record().as_value()["generation"],
                "witness_attachment_ids": value["expected_binding"]["witness_attachments"]
                    .as_array()
                    .expect("validated request witness array")
                    .iter()
                    .map(|reference| reference["record_id"].clone())
                    .collect::<Vec<_>>(),
                "purpose_digest": semantic_digest(&value["purpose"])?,
                "time_bounds_digest": semantic_digest(&value["time_bounds"])?,
                "delivery_binding_digest": semantic_digest(&value["delivery"])?,
            });
            if authorization_value["binding"] != binding {
                return Err(ContractError::InvocationJoin(
                    "invocation grant did not bind exact request inputs",
                ));
            }
            let interval: EffectiveInterval =
                serde_json::from_value(authorization_value["effective_interval"].clone())?;
            let not_before = value["time_bounds"]["not_before"]
                .as_str()
                .ok_or(ContractError::InvocationJoin("request not-before absent"))?;
            if !interval.contains(&Timestamp::parse(not_before.to_owned())?) {
                return Err(ContractError::InvocationJoin(
                    "invocation grant not effective at request admission",
                ));
            }
            let authorization_id = authorization.record_id().clone();
            let target_node = serde_json::to_string(&value["target"]["node"])?;
            let request_id = value["request_id"]
                .as_str()
                .ok_or(ContractError::InvocationJoin("request occurrence absent"))?
                .to_owned();
            let idempotency = value["idempotency"]["key"]
                .as_str()
                .ok_or(ContractError::InvocationJoin("idempotency key absent"))?
                .to_owned();
            for (map, key) in [
                (
                    &mut request_occurrences,
                    (target_node.clone(), authorization_id.clone(), request_id),
                ),
                (
                    &mut idempotency_occurrences,
                    (target_node, authorization_id, idempotency),
                ),
            ] {
                if map
                    .insert(key, request.canonical_bytes().to_vec())
                    .is_some_and(|prior| prior != request.canonical_bytes())
                {
                    return Err(ContractError::InvocationJoin(
                        "request or idempotency occurrence collision",
                    ));
                }
            }
        }

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
                || value["clock"] != request.record().as_value()["time_bounds"]["clock"]
            {
                return Err(ContractError::InvocationJoin(
                    "decision authentication/authorization",
                ));
            }
            if value["decision"] == "accepted" {
                let reservation = self.resolve_field(&value["custody"], "reservation")?;
                require_schema(reservation, RuntimeSchema::CustodyReservationV1)?;
                if value["custody"]["state"] != "reserved"
                    || reservation.record().as_value()["decision"] != "reserved"
                {
                    return Err(ContractError::InvocationJoin(
                        "accepted decision lacks exact reserved custody",
                    ));
                }
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
                || value["clock"] != request.record().as_value()["time_bounds"]["clock"]
            {
                return Err(ContractError::InvocationJoin(
                    "reservation activation/profile",
                ));
            }
            let policy = self.resolve_field(value, "delivery_requirement")?;
            require_schema(policy, RuntimeSchema::BufferDeliveryPolicyV1)?;
            let total = value["component_bounds"]
                .as_object()
                .ok_or(ContractError::InvocationJoin("reservation components"))?
                .values()
                .try_fold(0_u64, |sum, component| {
                    component
                        .as_u64()
                        .and_then(|value| sum.checked_add(value))
                        .ok_or(ContractError::InvocationJoin(
                            "reservation component arithmetic",
                        ))
                })?;
            let required = value["total_required_bytes"]
                .as_u64()
                .ok_or(ContractError::InvocationJoin("reservation total"))?;
            let reserved = value["reserved_bytes"]
                .as_u64()
                .ok_or(ContractError::InvocationJoin("reservation bytes"))?;
            let protected = value["protected_failure_reserve_bytes"].as_u64().ok_or(
                ContractError::InvocationJoin("reservation protected reserve"),
            )?;
            let capacity = policy.record().as_value()["capacity"]["total_bytes"]
                .as_u64()
                .ok_or(ContractError::InvocationJoin("policy capacity"))?;
            if value["decision"] != "reserved"
                || total != required
                || reserved < required
                || protected
                    != policy.record().as_value()["capacity"]["protected_failure_receipt_bytes"]
                        .as_u64()
                        .ok_or(ContractError::InvocationJoin("policy protected reserve"))?
                || reserved
                    .checked_add(protected)
                    .is_none_or(|used| used > capacity)
                || value["custody_policy"]
                    != policy.record().as_value()["policy_identities"]["custody"]
            {
                return Err(ContractError::InvocationJoin(
                    "reservation does not close custody policy and capacity",
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
                || value["clock"] != request.record().as_value()["time_bounds"]["clock"]
                || decision.record().as_value()["decision"] != "accepted"
                || decision.record().as_value()["custody"]["reservation"]
                    != Value::from(reservation.exact_reference())
                || value["selected_witness_attachments"]
                    != request.record().as_value()["expected_binding"]["witness_attachments"]
            {
                return Err(ContractError::InvocationJoin("launch node/profile"));
            }
            if value["prelaunch_checks"]["authentication"]
                != request.record().as_value()["authentication_evidence"]
                || value["prelaunch_checks"]["invocation_authorization"]
                    != request.record().as_value()["invocation_authorization"]
                || value["prelaunch_checks"]["custody"]
                    != reservation.record().as_value()["reservation_commit"]
            {
                return Err(ContractError::InvocationJoin(
                    "launch prechecks substituted authentication, authority, or custody",
                ));
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
            let reserved_at = timestamp(reservation.record().as_value(), "reserved_at")?;
            let decided_at = timestamp(decision.record().as_value(), "decided_at")?;
            let launched_at = timestamp(value, "launched_at")?;
            let expires_at = timestamp(reservation.record().as_value(), "expires_at")?;
            let not_before = Timestamp::parse(
                request.record().as_value()["time_bounds"]["not_before"]
                    .as_str()
                    .ok_or(ContractError::InvocationJoin("request not-before"))?
                    .to_owned(),
            )?
            .instant();
            let request_deadline = Timestamp::parse(
                request.record().as_value()["time_bounds"]["deadline"]
                    .as_str()
                    .ok_or(ContractError::InvocationJoin("request deadline"))?
                    .to_owned(),
            )?
            .instant();
            let attempt_deadline = timestamp(value, "attempt_deadline")?;
            if !(reserved_at <= decided_at
                && decided_at <= launched_at
                && launched_at < expires_at
                && launched_at >= not_before
                && attempt_deadline <= request_deadline)
            {
                return Err(ContractError::InvocationJoin(
                    "custody, decision, launch, or deadline ordering",
                ));
            }
            let budget = request.record().as_value()["time_bounds"]["maximum_execution_ms"]
                .as_i64()
                .ok_or(ContractError::InvocationJoin("request execution budget"))?;
            if value["maximum_execution_ms"].as_i64() != Some(budget)
                || (attempt_deadline - launched_at).num_milliseconds() != budget
            {
                return Err(ContractError::InvocationJoin(
                    "launch execution budget/deadline substitution",
                ));
            }
            for dependency in [
                activation,
                self.resolve_field(activation.record().as_value(), "role_manifest")?,
                self.resolve_field(activation.record().as_value(), "cohort_manifest")?,
            ] {
                if !interval_contains_attempt(
                    &dependency.record().as_value()["effective_interval"],
                    launched_at,
                    attempt_deadline,
                )? {
                    return Err(ContractError::InvocationJoin(
                        "topology dependency does not cover execution attempt",
                    ));
                }
            }
            for relation in activation.record().as_value()["relations"]
                .as_object()
                .ok_or(ContractError::InvocationJoin("activation relations"))?
                .values()
            {
                let relation = self.resolve_value(relation)?;
                if !interval_contains_attempt(
                    &relation.record().as_value()["effective_interval"],
                    launched_at,
                    attempt_deadline,
                )? {
                    return Err(ContractError::InvocationJoin(
                        "relation does not cover execution attempt",
                    ));
                }
            }
            for attachment in value["selected_witness_attachments"]
                .as_array()
                .expect("validated launch attachments")
            {
                let attachment = self.resolve_value(attachment)?;
                if !interval_contains_attempt(
                    &attachment.record().as_value()["effective_interval"],
                    launched_at,
                    attempt_deadline,
                )? {
                    return Err(ContractError::InvocationJoin(
                        "witness does not cover execution attempt",
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
            let request = self.resolve_field(binding.record().as_value(), "outer_request")?;
            require_schema(request, RuntimeSchema::DiagnosticInvocationRequestV1)?;
            if ["schema", "artifact_id", "file_bytes_digest"]
                .iter()
                .any(|field| artifact[*field] != diagnostic[*field])
                || value["producer_node"] != activation.record().as_value()["node"]
                || value["producer_key_generation"] != activation.record().as_value()["active_key"]
                || value["intended_receiver"]
                    != request.record().as_value()["delivery"]["destination"]
                || value["destination_generation"]
                    != request.record().as_value()["delivery"]["destination_generation"]
                || value["transport_policy"]
                    != request.record().as_value()["delivery"]["delivery_policy"]
            {
                return Err(ContractError::DeliveryJoin(
                    "envelope artifact/producer binding",
                ));
            }
        }

        let mut attempt_starts = BTreeMap::<String, &ValidatedRuntimeRecord>::new();
        let mut attempt_completions = BTreeMap::<String, &ValidatedRuntimeRecord>::new();
        let mut attempt_numbers = BTreeSet::<(Sha256Digest, u64)>::new();
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
            let occurrence = value["attempt_occurrence_id"]
                .as_str()
                .ok_or(ContractError::DeliveryJoin("attempt occurrence identity"))?
                .to_owned();
            let number = value["attempt_number"]
                .as_u64()
                .ok_or(ContractError::DeliveryJoin("attempt number"))?;
            if value["outcome"] == "in_progress" {
                if attempt_starts.insert(occurrence.clone(), attempt).is_some()
                    || !attempt_numbers.insert((envelope.record_id().clone(), number))
                {
                    return Err(ContractError::DeliveryJoin(
                        "duplicate attempt start occurrence or number",
                    ));
                }
                if number == 1 && value["predecessor_attempt_record"] != Value::Null {
                    return Err(ContractError::DeliveryJoin(
                        "first attempt start has predecessor",
                    ));
                }
                if number > 1 {
                    if value["predecessor_attempt_record"] == Value::Null {
                        return Err(ContractError::DeliveryJoin(
                            "later attempt start lacks predecessor",
                        ));
                    }
                    let predecessor = self.resolve_field(value, "predecessor_attempt_record")?;
                    require_schema(predecessor, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
                    if predecessor.record().as_value()["outcome"] == "in_progress"
                        || predecessor.record().as_value()["attempt_number"].as_u64()
                            != Some(number - 1)
                        || predecessor.record().as_value()["envelope"] != value["envelope"]
                        || predecessor.record().as_value()["artifact"] != value["artifact"]
                        || predecessor.record().as_value()["destination"] != value["destination"]
                        || predecessor.record().as_value()["destination_generation"]
                            != value["destination_generation"]
                        || predecessor.record().as_value()["transport_policy"]
                            != value["transport_policy"]
                        || timestamp(predecessor.record().as_value(), "completed_at")?
                            > timestamp(value, "started_at")?
                    {
                        return Err(ContractError::DeliveryJoin(
                            "later attempt predecessor substitution",
                        ));
                    }
                    if predecessor.record().as_value()["next_attempt_not_before"] != Value::Null
                        && Timestamp::parse(
                            predecessor.record().as_value()["next_attempt_not_before"]
                                .as_str()
                                .ok_or(ContractError::DeliveryJoin("retry deadline malformed"))?
                                .to_owned(),
                        )?
                        .instant()
                            > timestamp(value, "started_at")?
                    {
                        return Err(ContractError::DeliveryJoin(
                            "retry started before durable deadline",
                        ));
                    }
                }
            } else {
                if attempt_completions
                    .insert(occurrence.clone(), attempt)
                    .is_some()
                {
                    return Err(ContractError::DeliveryJoin(
                        "duplicate attempt completion occurrence",
                    ));
                }
                let predecessor = self.resolve_field(value, "predecessor_attempt_record")?;
                require_schema(predecessor, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
                for field in [
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
                ] {
                    if predecessor.record().as_value()[field] != value[field] {
                        return Err(ContractError::DeliveryJoin(
                            "attempt completion substituted start occurrence",
                        ));
                    }
                }
                if predecessor.record().as_value()["outcome"] != "in_progress"
                    || timestamp(value, "completed_at")? < timestamp(value, "started_at")?
                {
                    return Err(ContractError::DeliveryJoin(
                        "attempt completion lacks exact start",
                    ));
                }
            }
        }
        if attempt_completions
            .keys()
            .any(|occurrence| !attempt_starts.contains_key(occurrence))
        {
            return Err(ContractError::DeliveryJoin(
                "attempt completion exists without start",
            ));
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
                || value["producer_key_generation"]
                    != envelope.record().as_value()["producer_key_generation"]
                || value["destination_generation"]
                    != envelope.record().as_value()["destination_generation"]
                || value["transport_policy"] != envelope.record().as_value()["transport_policy"]
                || value["envelope"] != attempt.record().as_value()["envelope"]
                || value["replay"]["replay_key"] != envelope.record().as_value()["replay_key"]
                || value["producer_authentication"]["verified_signed_content_digest"]
                    != envelope.record().as_value()["authentication"]["signed_content_digest"]
                || value["custody"]["exact_bytes_digest"] != value["artifact"]["file_bytes_digest"]
                || value["custody"]["byte_length"] != value["artifact"]["byte_length"]
            {
                return Err(ContractError::DeliveryJoin("receiver custody binding"));
            }
            if timestamp(value, "received_at")?
                < timestamp(attempt.record().as_value(), "completed_at")?
                || Timestamp::parse(
                    value["custody"]["committed_at"]
                        .as_str()
                        .ok_or(ContractError::DeliveryJoin(
                            "receiver custody time malformed",
                        ))?
                        .to_owned(),
                )?
                .instant()
                    < timestamp(value, "received_at")?
            {
                return Err(ContractError::DeliveryJoin("receiver custody ordering"));
            }
        }

        let deliveries: Vec<_> = self
            .by_schema(RuntimeSchema::ArtifactDeliveryRecordV1)
            .collect();
        let mut successor_counts = BTreeMap::<Sha256Digest, usize>::new();
        let mut roots = BTreeSet::<String>::new();
        for delivery in &deliveries {
            let value = delivery.record().as_value();
            if value["predecessor"] == Value::Null {
                if !matches!(
                    value["state"].as_str(),
                    Some("not_required" | "export_committed")
                ) {
                    return Err(ContractError::DeliveryJoin("delivery root state"));
                }
                let root = serde_json::to_string(&serde_json::json!({
                    "artifact": value["artifact"],
                    "producer_node": value["producer_node"],
                    "destination": value["destination"],
                    "destination_generation": value["destination_generation"],
                    "transport_policy": value["transport_policy"],
                }))?;
                if !roots.insert(root) {
                    return Err(ContractError::DeliveryJoin("delivery chain root fork"));
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
                if timestamp(value, "occurred_at")?
                    < timestamp(predecessor.record().as_value(), "occurred_at")?
                {
                    return Err(ContractError::DeliveryJoin("delivery transition ordering"));
                }
            }
            if value["envelope"] != Value::Null {
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
                    return Err(ContractError::DeliveryJoin(
                        "delivery state substituted envelope",
                    ));
                }
            }
            if value["attempt"] != Value::Null {
                let attempt = self.resolve_field(value, "attempt")?;
                require_schema(attempt, RuntimeSchema::ArtifactDeliveryAttemptV1)?;
                if !artifact_tuple_equal(
                    &value["artifact"],
                    &attempt.record().as_value()["artifact"],
                ) || value["envelope"] != attempt.record().as_value()["envelope"]
                    || value["destination"] != attempt.record().as_value()["destination"]
                    || value["destination_generation"]
                        != attempt.record().as_value()["destination_generation"]
                    || value["transport_policy"] != attempt.record().as_value()["transport_policy"]
                    || !delivery_state_accepts_outcome(
                        value["state"].as_str(),
                        attempt.record().as_value()["outcome"].as_str(),
                    )
                {
                    return Err(ContractError::DeliveryJoin(
                        "delivery state substituted attempt or outcome",
                    ));
                }
                if value["state"] != "attempt_in_progress"
                    && timestamp(value, "occurred_at")?
                        < timestamp(attempt.record().as_value(), "completed_at")?
                {
                    return Err(ContractError::DeliveryJoin(
                        "delivery outcome precedes attempt completion",
                    ));
                }
                if value["state"] == "retry_scheduled"
                    && value["next_attempt_not_before"]
                        != attempt.record().as_value()["next_attempt_not_before"]
                {
                    return Err(ContractError::DeliveryJoin(
                        "delivery retry deadline substitution",
                    ));
                }
            }
            if value["receiver_custody_receipt"] != Value::Null {
                let receipt = self.resolve_field(value, "receiver_custody_receipt")?;
                require_schema(receipt, RuntimeSchema::ArtifactCustodyReceiptV1)?;
                if value["state"] != "acknowledged_custody"
                    || value["attempt"] != receipt.record().as_value()["attempt"]
                    || value["envelope"] != receipt.record().as_value()["envelope"]
                    || !artifact_tuple_equal(
                        &value["artifact"],
                        &receipt.record().as_value()["artifact"],
                    )
                {
                    return Err(ContractError::DeliveryJoin(
                        "acknowledged custody borrowed receipt",
                    ));
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

fn administrative_authority_field(schema: RuntimeSchema) -> Option<&'static str> {
    match schema {
        RuntimeSchema::NodeEnrollmentV1 => Some("enrollment_authorization"),
        RuntimeSchema::RuntimeActivationV1 => Some("activation_authorization"),
        RuntimeSchema::WitnessAttachmentV1 => Some("attachment_authorization"),
        RuntimeSchema::HostRoleRelationV1
        | RuntimeSchema::HostRoleLifecycleEventV1
        | RuntimeSchema::WitnessLifecycleEventV1
        | RuntimeSchema::NodeKeyLifecycleEventV1
        | RuntimeSchema::RestoreActivationProofV1
        | RuntimeSchema::DecommissionCutV1 => Some("administrative_authorization"),
        _ => None,
    }
}

fn administrative_neutral_digest(
    records: &RuntimeRecordSet,
    consumers: &BTreeMap<(String, Sha256Digest), &ValidatedRuntimeRecord>,
    key: &(String, Sha256Digest),
    memo: &mut BTreeMap<(String, Sha256Digest), Sha256Digest>,
    visiting: &mut BTreeSet<(String, Sha256Digest)>,
) -> Result<Sha256Digest> {
    if let Some(digest) = memo.get(key) {
        return Ok(digest.clone());
    }
    if !visiting.insert(key.clone()) {
        return Err(ContractError::AuthorizationJoin(
            "administrative authority-neutral dependency cycle",
        ));
    }
    let record = consumers.get(key).ok_or(ContractError::AuthorizationJoin(
        "administrative consumer absent",
    ))?;
    let authority_field = administrative_authority_field(record.schema()).ok_or(
        ContractError::AuthorizationJoin("administrative consumer field absent"),
    )?;
    let mut preimage = record
        .record()
        .as_value()
        .as_object()
        .ok_or(ContractError::AuthorizationJoin(
            "administrative consumer must be an object",
        ))?
        .clone();
    preimage.remove(authority_field);
    let preimage = neutralize_administrative_references(
        records,
        consumers,
        Value::Object(preimage),
        memo,
        visiting,
    )?;
    let digest = semantic_digest(&preimage)?;
    visiting.remove(key);
    memo.insert(key.clone(), digest.clone());
    Ok(digest)
}

fn neutralize_administrative_references(
    records: &RuntimeRecordSet,
    consumers: &BTreeMap<(String, Sha256Digest), &ValidatedRuntimeRecord>,
    value: Value,
    memo: &mut BTreeMap<(String, Sha256Digest), Sha256Digest>,
    visiting: &mut BTreeSet<(String, Sha256Digest)>,
) -> Result<Value> {
    match value {
        Value::Object(object)
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
        {
            let reference: RecordRef = serde_json::from_value(Value::Object(object.clone()))?;
            if let Some(target) = records.get(&reference.record_id) {
                if administrative_authority_field(target.schema()).is_some() {
                    let key = (
                        target.schema().as_str().to_owned(),
                        target.record_id().clone(),
                    );
                    let digest =
                        administrative_neutral_digest(records, consumers, &key, memo, visiting)?;
                    return Ok(serde_json::json!({
                        "schema": target.schema().as_str(),
                        "record_id": target.record_id(),
                        "record_preimage_digest": digest,
                    }));
                }
            } else if RuntimeSchema::parse(reference.schema.as_str())
                .ok()
                .is_some_and(|schema| administrative_authority_field(schema).is_some())
            {
                return Err(ContractError::AuthorizationJoin(
                    "external administrative consumer cannot close a local grant",
                ));
            }
            Ok(Value::Object(object))
        }
        Value::Object(object) => Ok(Value::Object(
            object
                .into_iter()
                .map(|(key, child)| {
                    neutralize_administrative_references(records, consumers, child, memo, visiting)
                        .map(|child| (key, child))
                })
                .collect::<Result<Map<_, _>>>()?,
        )),
        Value::Array(array) => Ok(Value::Array(
            array
                .into_iter()
                .map(|child| {
                    neutralize_administrative_references(records, consumers, child, memo, visiting)
                })
                .collect::<Result<Vec<_>>>()?,
        )),
        primitive => Ok(primitive),
    }
}

fn consumer_occurrence_time(record: &ValidatedRuntimeRecord) -> Result<&str> {
    let value = record.record().as_value();
    let field = match record.schema() {
        RuntimeSchema::NodeEnrollmentV1 => "enrolled_at",
        RuntimeSchema::RuntimeActivationV1
        | RuntimeSchema::WitnessAttachmentV1
        | RuntimeSchema::HostRoleRelationV1 => {
            return value["effective_interval"]["effective_from"]
                .as_str()
                .ok_or(ContractError::AuthorizationJoin(
                    "administrative effective interval",
                ));
        }
        RuntimeSchema::HostRoleLifecycleEventV1
        | RuntimeSchema::WitnessLifecycleEventV1
        | RuntimeSchema::NodeKeyLifecycleEventV1 => "occurred_at",
        RuntimeSchema::RestoreActivationProofV1 => "decided_at",
        RuntimeSchema::DecommissionCutV1 => "effective_at",
        _ => {
            return Err(ContractError::AuthorizationJoin(
                "administrative occurrence time law absent",
            ));
        }
    };
    value[field]
        .as_str()
        .ok_or(ContractError::AuthorizationJoin(
            "administrative occurrence time absent",
        ))
}

fn interval_bounds(
    value: &Value,
) -> Result<(
    chrono::DateTime<chrono::FixedOffset>,
    Option<chrono::DateTime<chrono::FixedOffset>>,
)> {
    let start = value["effective_from"]
        .as_str()
        .ok_or(ContractError::TopologyJoin("interval start absent"))?;
    let end = value
        .get("effective_until")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .ok_or(ContractError::TopologyJoin("interval end malformed"))
                .and_then(|value| Ok(Timestamp::parse(value.to_owned())?.instant()))
        })
        .transpose()?;
    Ok((Timestamp::parse(start.to_owned())?.instant(), end))
}

fn interval_covers(outer: &Value, inner: &Value) -> Result<bool> {
    let (outer_start, outer_end) = interval_bounds(outer)?;
    let (inner_start, inner_end) = interval_bounds(inner)?;
    Ok(outer_start <= inner_start
        && match (outer_end, inner_end) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(outer), Some(inner)) => outer >= inner,
        })
}

fn intervals_overlap(left: &Value, right: &Value) -> Result<bool> {
    let (left_start, left_end) = interval_bounds(left)?;
    let (right_start, right_end) = interval_bounds(right)?;
    Ok(
        left_end.is_none_or(|end| right_start < end)
            && right_end.is_none_or(|end| left_start < end),
    )
}

fn interval_contains_attempt(
    interval: &Value,
    start: chrono::DateTime<chrono::FixedOffset>,
    deadline: chrono::DateTime<chrono::FixedOffset>,
) -> Result<bool> {
    let (effective_from, effective_until) = interval_bounds(interval)?;
    Ok(effective_from <= start && effective_until.is_none_or(|end| deadline <= end))
}

fn operation_matches_consumer(operation: &str, consumer: &Value) -> Result<bool> {
    Ok(match consumer["schema"].as_str() {
        Some("nq.node_enrollment.v1") => operation == "enroll",
        Some("nq.witness_attachment.v1") => operation == "admit_witness",
        Some("nq.host_role_relation.v1") => match consumer["relation_kind"].as_str() {
            Some("node_subject") => operation == "enroll",
            Some("subject_platform" | "node_vantage") => {
                matches!(operation, "enroll" | "rehome")
            }
            Some("node_role") => matches!(operation, "enroll" | "change_role"),
            Some("node_static_profile_cohort") => {
                matches!(operation, "enroll" | "change_static_profile_cohort")
            }
            _ => false,
        },
        Some("nq.runtime_activation.v1") => matches!(
            operation,
            "activate_node"
                | "rekey"
                | "rehome"
                | "change_role"
                | "change_static_profile_cohort"
                | "complete_restore"
        ),
        Some("nq.host_role_lifecycle_event.v1") => {
            let mapped = match consumer["operation"].as_str() {
                Some("activate") => "activate_node",
                Some(value) => value,
                None => return Err(ContractError::AuthorizationJoin("host operation absent")),
            };
            operation == mapped
        }
        Some("nq.witness_lifecycle_event.v1") => {
            let mapped = match consumer["operation"].as_str() {
                Some("activate") => "activate_witness",
                Some(value) => value,
                None => {
                    return Err(ContractError::AuthorizationJoin("witness operation absent"));
                }
            };
            operation == mapped
        }
        Some("nq.node_key_lifecycle_event.v1") => match consumer["operation"].as_str() {
            Some("activate") => matches!(operation, "activate_key" | "rekey" | "complete_restore"),
            Some("supersede" | "revoke") => operation == "rekey",
            _ => false,
        },
        Some("nq.restore_activation_proof.v1") => {
            matches!(operation, "begin_restore" | "complete_restore")
        }
        Some("nq.decommission_cut.v1") => {
            operation
                == if consumer["result_state"] == "decommissioned" {
                    "complete_decommission"
                } else {
                    "begin_decommission"
                }
        }
        _ => false,
    })
}

fn administrative_shape(operation: &str, consumers: &[&ValidatedRuntimeRecord]) -> Result<bool> {
    let expected = expected_administrative_shape(operation)?;
    let mut actual = BTreeMap::<&str, usize>::new();
    for consumer in consumers {
        *actual.entry(consumer.schema().as_str()).or_default() += 1;
    }
    Ok(expected
        .iter()
        .all(|(schema, count)| actual.get(schema) == Some(count))
        && actual.len() == expected.len())
}

fn expected_administrative_shape(operation: &str) -> Result<&'static [(&'static str, usize)]> {
    Ok(match operation {
        "bootstrap" => &[("nq.host_role_lifecycle_event.v1", 1)],
        "enroll" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.host_role_relation.v1", 5),
            ("nq.node_enrollment.v1", 1),
        ],
        "admit_witness" => &[("nq.witness_attachment.v1", 1)],
        "activate_witness" | "suspend_witness" | "resume_witness" | "retire_witness" => {
            &[("nq.witness_lifecycle_event.v1", 1)]
        }
        "activate_key" => &[("nq.node_key_lifecycle_event.v1", 1)],
        "activate_node" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.runtime_activation.v1", 1),
        ],
        "rekey" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.node_key_lifecycle_event.v1", 2),
            ("nq.runtime_activation.v1", 1),
        ],
        "rehome" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.host_role_relation.v1", 2),
            ("nq.runtime_activation.v1", 1),
        ],
        "change_role" | "change_static_profile_cohort" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.host_role_relation.v1", 1),
            ("nq.runtime_activation.v1", 1),
        ],
        // The first restore decision is the quarantine/eligibility proof
        // itself. Completion is the closed topology mutation it authorizes.
        "begin_restore" => &[("nq.restore_activation_proof.v1", 1)],
        "complete_restore" => &[
            ("nq.host_role_lifecycle_event.v1", 1),
            ("nq.node_key_lifecycle_event.v1", 1),
            ("nq.restore_activation_proof.v1", 1),
            ("nq.runtime_activation.v1", 1),
        ],
        "begin_decommission" | "complete_decommission" => &[
            ("nq.decommission_cut.v1", 1),
            ("nq.host_role_lifecycle_event.v1", 1),
        ],
        _ => {
            return Err(ContractError::AuthorizationJoin(
                "operation has no exact administrative record-shape law",
            ));
        }
    })
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

fn delivery_state_accepts_outcome(state: Option<&str>, outcome: Option<&str>) -> bool {
    matches!(
        (state, outcome),
        (Some("attempt_in_progress"), Some("in_progress"))
            | (
                Some("retry_scheduled" | "attempts_exhausted"),
                Some("transport_unavailable" | "transport_timeout" | "receiver_rate_limited")
            )
            | (
                Some("delivery_ambiguous"),
                Some("ambiguous_possible_acceptance" | "transport_completed_receipt_pending")
            )
            | (
                Some("acknowledged_custody"),
                Some("transport_completed_receipt_pending")
            )
            | (Some("terminal_rejected"), Some("terminal_rejected"))
    )
}

impl From<RecordRef> for Value {
    fn from(value: RecordRef) -> Self {
        serde_json::to_value(value).expect("RecordRef is JSON serializable")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use super::{RuntimeRecordSet, expected_administrative_shape};
    use crate::{ContractError, ValidatedRuntimeRecord};

    const RECORDS: &str = include_str!("../assets/host-role-runtime-records.v1.json");

    #[test]
    fn every_ratified_administrative_operation_has_one_exact_shape_law() {
        for operation in [
            "bootstrap",
            "enroll",
            "admit_witness",
            "activate_witness",
            "suspend_witness",
            "resume_witness",
            "retire_witness",
            "activate_key",
            "activate_node",
            "rekey",
            "rehome",
            "change_role",
            "change_static_profile_cohort",
            "begin_restore",
            "complete_restore",
            "begin_decommission",
            "complete_decommission",
        ] {
            assert!(
                !expected_administrative_shape(operation)
                    .expect("ratified operation must have a shape")
                    .is_empty()
            );
        }
        assert!(expected_administrative_shape("invented_operation").is_err());
    }

    #[test]
    fn self_consistent_refused_administrative_grant_cannot_be_consumed() {
        let mut values = fixture_values();
        values
            .get_mut("activate_node_authorization")
            .expect("authorization")["decision"] = json!("refused");
        let authorization =
            ValidatedRuntimeRecord::validate_value(values["activate_node_authorization"].clone())
                .expect("locally valid refused grant");
        let reference = serde_json::to_value(authorization.exact_reference()).expect("reference");
        values.get_mut("activation").expect("activation")["activation_authorization"] =
            reference.clone();
        values.get_mut("lifecycle_event").expect("lifecycle event")["administrative_authorization"] =
            reference;
        let records = record_set(values);
        assert!(matches!(
            records.validate_authorizations(),
            Err(ContractError::AuthorizationJoin(
                "refused administrative authority was consumed"
            ))
        ));
    }

    #[test]
    fn overlapping_activation_and_active_key_intervals_refuse() {
        let mut values = fixture_values();
        let mut activation = values["activation"].clone();
        activation["activation_id"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        values.insert("overlapping_activation".to_owned(), activation);
        let records = record_set(values);
        assert!(matches!(
            records.validate_topology(),
            Err(ContractError::TopologyJoin(
                "node has overlapping effective activation intervals"
            ))
        ));
    }

    #[test]
    fn accepted_invocation_cannot_substitute_administrative_authority() {
        let mut values = fixture_values();
        let administrative =
            ValidatedRuntimeRecord::validate_value(values["activate_node_authorization"].clone())
                .expect("administrative authorization");
        values
            .get_mut("invocation_decision")
            .expect("invocation decision")["invocation_authorization"] =
            serde_json::to_value(administrative.exact_reference()).expect("reference");
        let records = record_set(values);
        assert!(matches!(
            records.validate_invocations(),
            Err(ContractError::InvocationJoin(
                "decision authentication/authorization"
            ))
        ));
    }

    #[test]
    fn acknowledged_delivery_cannot_borrow_an_unreceipted_attempt() {
        let mut values = fixture_values();
        let attempt =
            ValidatedRuntimeRecord::validate_value(values["delivery_attempt_start_record"].clone())
                .expect("attempt start");
        values.get_mut("delivery").expect("delivery")["attempt"] =
            serde_json::to_value(attempt.exact_reference()).expect("reference");
        let records = record_set(values);
        assert!(matches!(
            records.validate_delivery(),
            Err(ContractError::DeliveryJoin(
                "delivery state substituted attempt or outcome"
                    | "acknowledged custody borrowed receipt"
            ))
        ));
    }

    fn fixture_values() -> BTreeMap<String, Value> {
        let fixture: Value = serde_json::from_str(RECORDS).expect("fixture");
        fixture["records"]
            .as_object()
            .expect("records")
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    fn record_set(values: BTreeMap<String, Value>) -> RuntimeRecordSet {
        let mut records = RuntimeRecordSet::new();
        for (name, value) in values {
            let record = ValidatedRuntimeRecord::validate_value(value)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            records.insert(record).expect("unique fixture identity");
        }
        records
    }
}
