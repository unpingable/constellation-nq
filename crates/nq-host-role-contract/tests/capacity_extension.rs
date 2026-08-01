//! Additive, content-addressed custody-capacity contract qualification.

use std::collections::BTreeSet;

use nq_host_role_contract::{
    CAPACITY_FUTURE_ARTIFACT_SLOT, CAPACITY_IJSON_SAFE_INTEGER_MAX_V1, CapacityCandidateChargeV1,
    CapacityDeliveryRequirementV1, CapacityLogicalLimitsV1, CapacitySemanticComponentsV1,
    CapacityUsageComponentsV1, ContractError, CustodyReservationPlan, ExternalRecordCatalog,
    Generation, IdentityCatalog, IdentityRef, RecordRef, RuntimeRecordSet,
    STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE, ValidatedRuntimeRecord, ValidationContext,
    capacity_delivery_policy_generation_identity, capacity_destination_generation_identity,
    capacity_queue_occurrence_identity, capacity_rule_artifact_digest_v1,
    capacity_rule_artifact_sources_v1, checked_append_extent_geometry_v1,
    checked_custody_arena_geometry_v1, checked_logical_preallocated_custody_carriers_v1,
    derive_capacity_allocation_identity, derive_capacity_queue_occurrence_identity,
    inspected_candidate_v3_projection_capsule_bound_manifest,
    require_qualified_v3_projection_capsule_bound_manifest_v2,
    verified_capacity_extension_manifest, verified_corrected_specimen,
    verified_custody_carrier_map, verified_v3_projection_capsule_bound_qualification_v1,
};
use nq_protocol::{Sha256Digest, semantic_digest, sha256_bytes};
use serde_json::{Value, json};

fn digest(label: &str) -> String {
    sha256_bytes(label.as_bytes()).to_string()
}

fn identity(kind: &str, id: &str, version: &str, descriptor: &str) -> Value {
    json!({
        "kind": kind,
        "id": id,
        "version": version,
        "descriptor_digest": digest(descriptor),
    })
}

fn reference(schema: &str, label: &str) -> Value {
    json!({
        "schema": schema,
        "record_id": digest(&format!("{label}/record")),
        "bytes_digest": digest(&format!("{label}/bytes")),
    })
}

fn leaf_pointers(value: &Value, pointer: &str, output: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                leaf_pointers(child, &format!("{pointer}/{escaped}"), output);
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                leaf_pointers(child, &format!("{pointer}/{index}"), output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            output.push(pointer.to_owned());
        }
    }
}

fn substitute_leaf(value: &mut Value) {
    *value = match value {
        Value::Null => Value::Bool(true),
        Value::Bool(boolean) => Value::Bool(!*boolean),
        Value::Number(number) => json!(number.as_u64().unwrap_or_default().saturating_add(1)),
        Value::String(text) => Value::String(format!("{text}-substituted")),
        Value::Array(_) | Value::Object(_) => unreachable!("only leaf values are substituted"),
    };
}

fn namespace() -> Value {
    json!({
        "namespace_id": "nq.production",
        "namespace_version": "1",
        "catalog_generation": "7",
        "catalog_id": digest("catalog/7"),
    })
}

fn arena(dependency: u64, raw: u64, final_closure: u64, failure: u64) -> Value {
    serde_json::to_value(
        checked_custody_arena_geometry_v1(dependency, raw, final_closure, failure)
            .expect("valid test arena geometry"),
    )
    .expect("serialize arena geometry")
}

fn extent(payload: u64) -> Value {
    serde_json::to_value(
        checked_append_extent_geometry_v1(payload).expect("valid test append geometry"),
    )
    .expect("serialize append geometry")
}

fn reseal_allocation(mut value: Value) -> Value {
    value["allocation_id"] = Value::String(digest("allocation/placeholder"));
    let occurrences = value["queue"]["occurrences"]
        .as_array_mut()
        .expect("queue occurrences");
    for occurrence in occurrences {
        occurrence["occurrence_id"] = Value::String(digest("occurrence/placeholder"));
        occurrence["capacity_allocation_id"] =
            Value::String(digest("allocation/backlink-placeholder"));
    }
    let allocation_id =
        derive_capacity_allocation_identity(&value).expect("allocation identity preimage");
    value["allocation_id"] = Value::String(allocation_id.to_string());
    let occurrences = value["queue"]["occurrences"]
        .as_array_mut()
        .expect("queue occurrences");
    for occurrence in occurrences {
        occurrence["capacity_allocation_id"] = Value::String(allocation_id.to_string());
        let occurrence_id = derive_capacity_queue_occurrence_identity(occurrence)
            .expect("queue occurrence identity");
        occurrence["occurrence_id"] = Value::String(occurrence_id.to_string());
    }
    value
}

fn bind_reservation_plan(mut value: Value) -> Value {
    let queue_required = value["queue"]["requirement"] == "required";
    let total_required = value["semantic_components"]
        .as_object()
        .expect("semantic components")
        .values()
        .map(|component| component.as_u64().expect("semantic component"))
        .sum::<u64>();
    let reserved = value["decision"] == "within_logical_limits";
    let plan_value = json!({
        "schema": "nq.custody_reservation_plan.v1",
        "namespace": value["namespace"].clone(),
        "node": identity("nq_node", "node/lab", "1", "node/lab/1"),
        "request": value["request_occurrence"]["request"].clone(),
        "activation": reference("nq.runtime_activation.v1", "activation/1"),
        "profile": identity(
            "diagnostic_profile",
            "host-resource",
            "1",
            "host-resource/1"
        ),
        "custody_policy": value["policy"]["capacity_policy"].clone(),
        "delivery_requirement": if queue_required {
            value["policy"]["buffer_delivery_policy"].clone()
        } else {
            Value::Null
        },
        "store_snapshot": "nq.capacity-allocation-store-snapshot/v1",
        "calculation_rule": identity(
            "policy",
            "custody-reservation-calculation",
            "1",
            "custody-reservation-calculation/1"
        ),
        "component_bounds": value["semantic_components"].clone(),
        "total_required_bytes": total_required,
        "reserved_bytes": if reserved { total_required } else { 0 },
        "protected_failure_reserve_bytes":
            value["limits"]["protected_failure_receipt_bytes"].clone(),
        "decision": if reserved { "reserved" } else { "refused" },
        "reservation_commit": "nq.capacity-allocation-commit/v1",
        "reserved_at": value["calculated_at"].clone(),
        "expires_at": "2026-07-29T20:01:00Z",
        "clock": value["clock"].clone(),
        "nonclaims": [
            "reservation does not establish diagnostic success",
            "protected failure reserve is not execution payload capacity",
        ],
    });
    let plan = CustodyReservationPlan::validate_value(plan_value).expect("valid bound plan");
    value["reservation_plan"] = plan.as_value().clone();
    value["plan_digest"] = Value::String(plan.plan_digest().to_string());
    value
}

fn collect_carriers(
    value: &Value,
    identities: &mut Vec<IdentityRef>,
    references: &mut Vec<RecordRef>,
) {
    match value {
        Value::Object(object) => {
            let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                identities.push(serde_json::from_value(value.clone()).expect("identity carrier"));
            } else if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                references.push(serde_json::from_value(value.clone()).expect("record reference"));
            } else {
                for child in object.values() {
                    collect_carriers(child, identities, references);
                }
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_carriers(child, identities, references);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn record_set(values: impl IntoIterator<Item = Value>) -> (RuntimeRecordSet, ValidationContext) {
    let mut identities = Vec::<IdentityRef>::new();
    let mut references = Vec::<RecordRef>::new();
    let mut local_ids = BTreeSet::new();
    let mut set = RuntimeRecordSet::new();
    for value in values {
        collect_carriers(&value, &mut identities, &mut references);
        let record = ValidatedRuntimeRecord::validate_value(value).expect("local record");
        local_ids.insert(record.record_id().clone());
        set.insert(record).expect("unique immutable record");
    }
    let mut identity_catalog = IdentityCatalog::new();
    for identity in identities {
        identity_catalog
            .insert(identity)
            .expect("identity descriptor non-substitution");
    }
    let mut external_records = ExternalRecordCatalog::new();
    for reference in references {
        if !local_ids.contains(&reference.record_id) {
            external_records.insert(reference);
        }
    }
    (
        set,
        ValidationContext {
            identities: identity_catalog,
            external_records,
        },
    )
}

#[allow(clippy::too_many_lines)] // One closed fixture keeps every capacity carrier inspectable.
fn allocation() -> Value {
    let semantic = json!({
        "request_and_decision_bytes": 100,
        "raw_evidence_bytes": 200,
        "normalized_bytes": 50,
        "projected_bytes": 60,
        "diagnostic_artifact_bytes": 70,
        "dependency_closure_bytes": 80,
        "commit_checkpoint_overhead_bytes": 90,
        "mandatory_delivery_ledger_bytes": 100,
    });
    let semantic_sum = 750;
    let dependency = 100;
    let raw = 250;
    let projection = 300;
    let final_closure = 400;
    let canonical_record = 250;
    let protected_failure = 4_096;
    let arena = arena(dependency, raw, final_closure, protected_failure);
    let canonical_extent = extent(canonical_record);
    let delivery_extent = extent(128);
    let retained_charge = arena["file_length_bytes"].as_u64().unwrap()
        + canonical_extent["extent_length_bytes"].as_u64().unwrap()
        + delivery_extent["extent_length_bytes"].as_u64().unwrap();
    let used_before = 8_192;
    let delivery_policy_generation_id = digest("delivery-policy-generation/1");
    let request_occurrence_id = digest("request-occurrence/1");
    let occurrence = |destination: &str| {
        json!({
            "occurrence_id": digest("occurrence/placeholder"),
            "capacity_allocation_id": digest("allocation/backlink-placeholder"),
            "request_occurrence_id": request_occurrence_id,
            "destination_generation_id": digest(destination),
            "delivery_policy_generation_id": delivery_policy_generation_id,
            "future_artifact_slot": CAPACITY_FUTURE_ARTIFACT_SLOT,
        })
    };
    let value = json!({
        "schema": "nq.custody_capacity_allocation.v1",
        "allocation_id": digest("allocation/placeholder"),
        "namespace": namespace(),
        "store_genesis_id": digest("store-genesis/1"),
        "store_integrity_key_generation":
            identity("key_generation", "store/integrity", "1", "store-integrity-key/1"),
        "predecessor_capacity": {
            "sequence": 3,
            "root": digest("capacity-root/3"),
        },
        "policy": {
            "buffer_delivery_policy": reference(
                "nq.buffer_delivery_policy.v1",
                "buffer-delivery-policy"
            ),
            "policy_generation": "1",
            "capacity_policy": identity(
                "policy",
                "custody-capacity",
                "1",
                "custody-capacity-policy/1"
            ),
            "delivery_policy": identity(
                "policy",
                "nightshift-delivery",
                "1",
                "delivery-policy/1"
            ),
            "delivery_policy_generation_id": delivery_policy_generation_id,
        },
        "rules": {
            "capacity_calculation": rule("nq.logical_preallocated_custody_carriers", "1"),
            "carrier_map": rule("nq.custody_carrier_map", "1"),
            "arena_layout": rule("nq.custody_arena_layout", "1"),
            "record_extent": rule("nq.append_extent_layout", "1"),
            "delivery_extent": rule("nq.delivery_extent_layout", "1"),
            "v3_capsule_bound": rule("nq.v3_projection_capsule_bound", "1"),
            "canonicalization": rule("rfc8785-jcs-sha256", "1"),
        },
        "before_snapshot": {
            "inventory_root": digest("inventory-root/3"),
            "inventory_count": 0,
            "bootstrap_integrity_carrier_bytes": 4_096,
            "matched_retained_bytes": 0,
            "physical_orphan_bytes": 0,
            "missing_committed_bytes": 0,
            "global_prelaunch_refusal_bytes": 4_096,
            "logical_preallocated_carrier_bytes": used_before,
        },
        "request_occurrence": {
            "occurrence_id": request_occurrence_id,
            "idempotency_key_id": digest("idempotency-key/1"),
            "request": reference("nq.diagnostic_invocation_request.v1", "request/1"),
        },
        "reservation_plan": {},
        "plan_digest": digest("reservation-plan/1"),
        "semantic_components": semantic,
        "semantic_sum_bytes": semantic_sum,
        "carrier_bounds": {
            "dependency_payload_bytes": dependency,
            "raw_acquisition_payload_bytes": raw,
            "projection_capsule_bound_bytes": projection,
            "final_closure_payload_bytes": final_closure,
            "canonical_record_payload_bytes": canonical_record,
            "protected_failure_payload_bytes": protected_failure,
        },
        "arena_layout": arena,
        "canonical_record_extent": canonical_extent,
        "delivery_ledger_extent": delivery_extent,
        "retained_charge_bytes": retained_charge,
        "queue": {
            "requirement": "required",
            "slots_before": 0,
            "slots_reserved": 2,
            "slots_after": 2,
            "maximum_entries": 4,
            "occurrences": [
                occurrence("nightshift/west/generation-1"),
                occurrence("nightshift/east/generation-1"),
            ],
        },
        "limits": {
            "maximum_single_execution_closure_bytes": 1_000,
            "protected_failure_receipt_bytes": protected_failure,
            "high_watermark_bytes": 900_000,
            "total_bytes": 1_000_000,
        },
        "logical_preallocated_carrier_bytes_after": used_before + retained_charge,
        "watermark_classification": {
            "used_before": "below",
            "used_after": "below",
        },
        "decision": "within_logical_limits",
        "refusal_reasons": [],
        "calculated_at": "2026-07-29T20:00:00Z",
        "clock": identity("clock", "host/clock", "1", "host-clock/1"),
        "nonclaims": [
            "capacity allocation performs no filesystem allocation or provider effect",
            "within logical limits does not establish request acceptance, reservation, launch, or diagnostic result",
            "capacity allocation validation establishes internal arithmetic only, not evaluator/source-set correspondence or Store-owned construction",
            "capacity allocation grants no reliance, authorization, or action",
            "exact source or asset digest correspondence does not establish deployed build or live execution correspondence",
        ],
    });
    reseal_allocation(bind_reservation_plan(value))
}

fn no_delivery_allocation() -> Value {
    let mut value = allocation();
    let delivery_length = value["delivery_ledger_extent"]["extent_length_bytes"]
        .as_u64()
        .expect("delivery extent length");
    value["semantic_components"]["mandatory_delivery_ledger_bytes"] = json!(0);
    value["semantic_sum_bytes"] = json!(650);
    value["delivery_ledger_extent"] = Value::Null;
    value["retained_charge_bytes"] = json!(
        value["retained_charge_bytes"]
            .as_u64()
            .expect("retained charge")
            - delivery_length
    );
    value["queue"] = json!({
        "requirement": "not_required",
        "slots_before": 0,
        "slots_reserved": 0,
        "slots_after": 0,
        "maximum_entries": 4,
        "occurrences": [],
    });
    value["logical_preallocated_carrier_bytes_after"] = json!(
        value["before_snapshot"]["logical_preallocated_carrier_bytes"]
            .as_u64()
            .expect("used before")
            + value["retained_charge_bytes"]
                .as_u64()
                .expect("retained charge")
    );
    reseal_allocation(bind_reservation_plan(value))
}

#[allow(clippy::too_many_lines)] // One source-bound fixture exposes every exact join input.
fn source_bound_allocation(records: &serde_json::Map<String, Value>) -> Value {
    let request =
        ValidatedRuntimeRecord::validate_value(records["request"].clone()).expect("source request");
    let reservation =
        ValidatedRuntimeRecord::validate_value(records["custody_reservation"].clone())
            .expect("source reservation");
    let plan = CustodyReservationPlan::from_reservation(&reservation).expect("source plan");
    let policy = ValidatedRuntimeRecord::validate_value(records["buffer_delivery_policy"].clone())
        .expect("source buffer policy");
    let policy_value = policy.record().as_value();
    let policy_generation = Generation::parse(
        policy_value["generation"]
            .as_str()
            .expect("policy generation"),
    )
    .expect("valid policy generation");
    let delivery_policy: IdentityRef =
        serde_json::from_value(policy_value["policy_identities"]["delivery"].clone())
            .expect("delivery policy identity");
    let delivery_policy_generation_id = capacity_delivery_policy_generation_identity(
        &policy.exact_reference(),
        &delivery_policy,
        &policy_generation,
    )
    .expect("delivery policy generation identity");
    let destination: IdentityRef =
        serde_json::from_value(request.record().as_value()["delivery"]["destination"].clone())
            .expect("destination identity");
    let destination_generation = Generation::parse(
        request.record().as_value()["delivery"]["destination_generation"]
            .as_str()
            .expect("destination generation"),
    )
    .expect("valid destination generation");
    let destination_generation_id =
        capacity_destination_generation_identity(&destination, &destination_generation)
            .expect("destination generation identity");
    let request_occurrence_id =
        nq_host_role_contract::invocation_occurrence_key_v1(&request).expect("P0-1 occurrence");
    let idempotency_key_id =
        nq_host_role_contract::invocation_idempotency_key_v1(&request).expect("P0-1 idempotency");

    let semantic = plan.as_value()["component_bounds"].clone();
    let semantic_sum = semantic
        .as_object()
        .expect("semantic components")
        .values()
        .map(|component| component.as_u64().expect("semantic component"))
        .sum::<u64>();
    let dependency = semantic["dependency_closure_bytes"]
        .as_u64()
        .expect("dependency bound");
    let raw = semantic["raw_evidence_bytes"].as_u64().expect("raw bound");
    let final_closure = semantic["normalized_bytes"].as_u64().expect("normalized")
        + semantic["projected_bytes"].as_u64().expect("projected")
        + semantic["diagnostic_artifact_bytes"]
            .as_u64()
            .expect("artifact");
    let canonical_record = semantic["request_and_decision_bytes"]
        .as_u64()
        .expect("request material")
        + semantic["commit_checkpoint_overhead_bytes"]
            .as_u64()
            .expect("commit material");
    let protected_failure = policy_value["capacity"]["protected_failure_receipt_bytes"]
        .as_u64()
        .expect("protected failure");
    let arena = arena(dependency, raw, final_closure, protected_failure);
    let canonical_extent = extent(canonical_record);
    let delivery_extent = extent(
        semantic["mandatory_delivery_ledger_bytes"]
            .as_u64()
            .expect("delivery material"),
    );
    let retained_charge = arena["file_length_bytes"].as_u64().expect("arena length")
        + canonical_extent["extent_length_bytes"]
            .as_u64()
            .expect("record length")
        + delivery_extent["extent_length_bytes"]
            .as_u64()
            .expect("delivery length");
    let used_before = 8_192;
    let occurrence = json!({
        "occurrence_id": digest("occurrence/placeholder"),
        "capacity_allocation_id": digest("allocation/backlink-placeholder"),
        "request_occurrence_id": request_occurrence_id,
        "destination_generation_id": destination_generation_id,
        "delivery_policy_generation_id": delivery_policy_generation_id,
        "future_artifact_slot": CAPACITY_FUTURE_ARTIFACT_SLOT,
    });
    let value = json!({
        "schema": "nq.custody_capacity_allocation.v1",
        "allocation_id": digest("allocation/placeholder"),
        "namespace": plan.as_value()["namespace"].clone(),
        "store_genesis_id": digest("source-bound-store-genesis/1"),
        "store_integrity_key_generation":
            identity("key_generation", "source-bound-store/integrity", "1", "source-bound-store-integrity/1"),
        "predecessor_capacity": {
            "sequence": 0,
            "root": digest("source-bound-capacity-root/0"),
        },
        "policy": {
            "buffer_delivery_policy": policy.exact_reference(),
            "policy_generation": policy_value["generation"].clone(),
            "capacity_policy": policy_value["policy_identities"]["custody"].clone(),
            "delivery_policy": delivery_policy,
            "delivery_policy_generation_id": delivery_policy_generation_id,
        },
        "rules": {
            "capacity_calculation": rule("nq.logical_preallocated_custody_carriers", "1"),
            "carrier_map": rule("nq.custody_carrier_map", "1"),
            "arena_layout": rule("nq.custody_arena_layout", "1"),
            "record_extent": rule("nq.append_extent_layout", "1"),
            "delivery_extent": rule("nq.delivery_extent_layout", "1"),
            "v3_capsule_bound": rule("nq.v3_projection_capsule_bound", "1"),
            "canonicalization": rule("rfc8785-jcs-sha256", "1"),
        },
        "before_snapshot": {
            "inventory_root": digest("source-bound-inventory-root/0"),
            "inventory_count": 0,
            "bootstrap_integrity_carrier_bytes": 4_096,
            "matched_retained_bytes": 0,
            "physical_orphan_bytes": 0,
            "missing_committed_bytes": 0,
            "global_prelaunch_refusal_bytes": 4_096,
            "logical_preallocated_carrier_bytes": used_before,
        },
        "request_occurrence": {
            "occurrence_id": request_occurrence_id,
            "idempotency_key_id": idempotency_key_id,
            "request": request.exact_reference(),
        },
        "reservation_plan": plan.as_value().clone(),
        "plan_digest": plan.plan_digest(),
        "semantic_components": semantic,
        "semantic_sum_bytes": semantic_sum,
        "carrier_bounds": {
            "dependency_payload_bytes": dependency,
            "raw_acquisition_payload_bytes": raw,
            "projection_capsule_bound_bytes": final_closure,
            "final_closure_payload_bytes": final_closure,
            "canonical_record_payload_bytes": canonical_record,
            "protected_failure_payload_bytes": protected_failure,
        },
        "arena_layout": arena,
        "canonical_record_extent": canonical_extent,
        "delivery_ledger_extent": delivery_extent,
        "retained_charge_bytes": retained_charge,
        "queue": {
            "requirement": "required",
            "slots_before": 0,
            "slots_reserved": 1,
            "slots_after": 1,
            "maximum_entries": policy_value["capacity"]["maximum_queue_entries"].clone(),
            "occurrences": [occurrence],
        },
        "limits": {
            "maximum_single_execution_closure_bytes":
                policy_value["capacity"]["maximum_single_execution_closure_bytes"].clone(),
            "protected_failure_receipt_bytes": protected_failure,
            "high_watermark_bytes": policy_value["capacity"]["high_watermark_bytes"].clone(),
            "total_bytes": policy_value["capacity"]["total_bytes"].clone(),
        },
        "logical_preallocated_carrier_bytes_after": used_before + retained_charge,
        "watermark_classification": {
            "used_before": "below",
            "used_after": "below",
        },
        "decision": "within_logical_limits",
        "refusal_reasons": [],
        "calculated_at": plan.as_value()["reserved_at"].clone(),
        "clock": plan.as_value()["clock"].clone(),
        "nonclaims": [
            "capacity allocation performs no filesystem allocation or provider effect",
            "within logical limits does not establish request acceptance, reservation, launch, or diagnostic result",
            "capacity allocation validation establishes internal arithmetic only, not evaluator/source-set correspondence or Store-owned construction",
            "capacity allocation grants no reliance, authorization, or action",
            "exact source or asset digest correspondence does not establish deployed build or live execution correspondence",
        ],
    });
    reseal_allocation(value)
}

fn replace_allocation_plan(mut allocation: Value, plan_value: Value) -> Value {
    let plan = CustodyReservationPlan::validate_value(plan_value).expect("replacement plan");
    allocation["reservation_plan"] = plan.as_value().clone();
    allocation["plan_digest"] = Value::String(plan.plan_digest().to_string());
    reseal_allocation(allocation)
}

fn reseal_request(request: &mut Value) {
    let mut preimage = request.clone();
    let preimage = preimage.as_object_mut().expect("request object");
    preimage.remove("request_digest");
    preimage.remove("request_preimage_digest");
    preimage.remove("invocation_authorization");
    request["request_preimage_digest"] = Value::String(
        semantic_digest(&Value::Object(preimage.clone()))
            .expect("request preimage")
            .to_string(),
    );

    let mut complete = request.clone();
    complete
        .as_object_mut()
        .expect("request object")
        .remove("request_digest");
    request["request_digest"] = Value::String(
        semantic_digest(&complete)
            .expect("request digest")
            .to_string(),
    );
}

fn rule(identity: &str, version: &str) -> Value {
    json!({
        "identity": identity,
        "version": version,
        "artifact_digest": capacity_rule_artifact_digest_v1(identity)
            .expect("closed capacity rule"),
    })
}

#[test]
fn exact_capacity_package_preserves_blocked_v1_and_qualifies_additive_v2() {
    let manifest = verified_capacity_extension_manifest().expect("capacity extension");
    assert_eq!(manifest.schema_assets.len(), 6);
    assert_eq!(manifest.static_assets.len(), 4);
    assert!(
        !verified_custody_carrier_map()
            .expect("carrier map")
            .is_empty()
    );
    let candidate = inspected_candidate_v3_projection_capsule_bound_manifest()
        .expect("inspect V3 bound candidate");
    assert!(!candidate.is_empty());
    let candidate: Value = serde_json::from_slice(candidate).expect("candidate JSON");
    assert_eq!(candidate["qualification_gaps"][0]["gate"], "CAP-H14");
    assert_eq!(candidate["qualification_gaps"][0]["status"], "blocked");

    let qualification = verified_v3_projection_capsule_bound_qualification_v1()
        .expect("positive qualification carrier");
    assert!(!qualification.is_empty());
    let qualified = require_qualified_v3_projection_capsule_bound_manifest_v2()
        .expect("presence-based positive v2 pair");
    assert_eq!(
        qualified.qualification_basis_sha256.as_str(),
        "sha256:f2f90fba7be1601c0749def3d7fd2fa843a05d174249fb73d52b234a5bcf9b8c"
    );
}

#[test]
fn reservation_plan_is_exact_authority_neutral_total_transform() {
    let fixture: Value =
        serde_json::from_slice(verified_corrected_specimen().expect("corrected specimen"))
            .expect("fixture JSON");
    let reservation =
        ValidatedRuntimeRecord::validate_value(fixture["records"]["custody_reservation"].clone())
            .expect("reservation");
    let plan = CustodyReservationPlan::from_reservation(&reservation).expect("neutral plan");
    assert!(
        plan.matches_reservation(&reservation)
            .expect("exact transform")
    );
    assert_eq!(
        plan.as_value()["store_snapshot"],
        "nq.capacity-allocation-store-snapshot/v1"
    );
    assert_eq!(
        plan.as_value()["reservation_commit"],
        "nq.capacity-allocation-commit/v1"
    );
    assert!(plan.as_value().get("reservation_id").is_none());
    assert_eq!(
        CustodyReservationPlan::decode_canonical(plan.canonical_bytes())
            .expect("canonical replay")
            .plan_digest(),
        plan.plan_digest()
    );

    let mut changed = fixture["records"]["custody_reservation"].clone();
    changed["expires_at"] = Value::String("2026-07-28T22:04:00Z".into());
    let changed =
        ValidatedRuntimeRecord::validate_value(changed).expect("changed valid reservation");
    assert_ne!(
        CustodyReservationPlan::from_reservation(&changed)
            .expect("changed plan")
            .plan_digest(),
        plan.plan_digest()
    );
}

#[test]
fn allocation_identity_neutralizes_only_the_documented_cycle_fields() {
    let value = allocation();
    let identity = derive_capacity_allocation_identity(&value).expect("identity");
    assert_eq!(value["allocation_id"], identity.to_string());

    let mut root_identity = value.clone();
    root_identity["allocation_id"] = Value::String(digest("foreign-allocation"));
    assert_eq!(
        derive_capacity_allocation_identity(&root_identity).expect("neutral root"),
        identity
    );
    let mut occurrence_identity = value.clone();
    occurrence_identity["queue"]["occurrences"][0]["occurrence_id"] =
        Value::String(digest("foreign-occurrence"));
    assert_eq!(
        derive_capacity_allocation_identity(&occurrence_identity).expect("neutral occurrence"),
        identity
    );
    let mut backlink = value.clone();
    backlink["queue"]["occurrences"][0]["capacity_allocation_id"] =
        Value::String(digest("foreign-backlink"));
    assert_eq!(
        derive_capacity_allocation_identity(&backlink).expect("neutral backlink"),
        identity
    );

    let mut pointers = Vec::new();
    leaf_pointers(&value, "", &mut pointers);
    for pointer in pointers {
        let queue_derived = pointer.starts_with("/queue/occurrences/")
            && (pointer.ends_with("/occurrence_id")
                || pointer.ends_with("/capacity_allocation_id"));
        if pointer == "/allocation_id" || queue_derived {
            continue;
        }
        let mut changed = value.clone();
        substitute_leaf(
            changed
                .pointer_mut(&pointer)
                .unwrap_or_else(|| panic!("{pointer} resolves")),
        );
        assert_ne!(
            derive_capacity_allocation_identity(&changed)
                .unwrap_or_else(|error| panic!("{pointer} preimage: {error}")),
            identity,
            "{pointer} was silently erased from allocation identity"
        );
    }
}

#[test]
fn capacity_allocation_closes_arithmetic_queue_policy_and_identity_joins() {
    let value = allocation();
    ValidatedRuntimeRecord::validate_value(value.clone()).expect("valid allocation");

    let mut occurrence = value.clone();
    occurrence["queue"]["occurrences"][0]["occurrence_id"] =
        Value::String(digest("substituted-occurrence"));
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(occurrence),
        Err(ContractError::InvalidCapacityAllocation)
    ));

    let mut backlink = value.clone();
    backlink["queue"]["occurrences"][0]["capacity_allocation_id"] =
        Value::String(digest("substituted-allocation"));
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(backlink),
        Err(ContractError::InvalidCapacityAllocation)
    ));

    for substituted in [4_095, 4_097] {
        let mut changed = value.clone();
        changed["carrier_bounds"]["protected_failure_payload_bytes"] = json!(substituted);
        assert!(matches!(
            ValidatedRuntimeRecord::validate_value(changed),
            Err(ContractError::InvalidCapacityAllocation)
        ));
    }

    let mut duplicate_destination = value.clone();
    duplicate_destination["queue"]["occurrences"][1]["destination_generation_id"] =
        duplicate_destination["queue"]["occurrences"][0]["destination_generation_id"].clone();
    let duplicate_destination = reseal_allocation(duplicate_destination);
    assert!(ValidatedRuntimeRecord::validate_value(duplicate_destination).is_err());

    let mut policy_substitution = value.clone();
    policy_substitution["queue"]["occurrences"][0]["delivery_policy_generation_id"] =
        Value::String(digest("other-delivery-policy-generation"));
    let policy_substitution = reseal_allocation(policy_substitution);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(policy_substitution),
        Err(ContractError::InvalidCapacityAllocation)
    ));

    let mut arena_substitution = value.clone();
    arena_substitution["arena_layout"]["alignment_bytes"] = json!(
        arena_substitution["arena_layout"]["alignment_bytes"]
            .as_u64()
            .expect("arena alignment")
            + 1
    );
    let arena_substitution = reseal_allocation(arena_substitution);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(arena_substitution),
        Err(ContractError::InvalidCapacityAllocation)
    ));

    let mut extent_substitution = value.clone();
    extent_substitution["canonical_record_extent"]["payload_offset"] = json!(16_385);
    let extent_substitution = reseal_allocation(extent_substitution);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(extent_substitution),
        Err(ContractError::InvalidCapacityAllocation)
    ));

    let mut weakened_nonclaim = value;
    weakened_nonclaim["nonclaims"]
        .as_array_mut()
        .expect("allocation nonclaims")
        .remove(2);
    let weakened_nonclaim = reseal_allocation(weakened_nonclaim);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(weakened_nonclaim),
        Err(ContractError::InvalidCapacityAllocation)
    ));
}

#[test]
fn no_delivery_refusal_and_watermark_states_are_independent_and_exact() {
    ValidatedRuntimeRecord::validate_value(no_delivery_allocation())
        .expect("closed not-required delivery form");

    let mut refused = allocation();
    refused["limits"]["maximum_single_execution_closure_bytes"] = json!(700);
    refused["decision"] = Value::String("refused".into());
    refused["refusal_reasons"] = json!(["maximum_single_execution_closure_exceeded"]);
    let refused = reseal_allocation(bind_reservation_plan(refused));
    ValidatedRuntimeRecord::validate_value(refused.clone()).expect("pure limit refusal");

    let mut laundered = refused;
    laundered["decision"] = Value::String("within_logical_limits".into());
    laundered["refusal_reasons"] = json!([]);
    let laundered = reseal_allocation(laundered);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(laundered),
        Err(ContractError::InvalidCapacityAllocation)
    ));

    let mut crossing = allocation();
    crossing["limits"]["high_watermark_bytes"] = json!(9_000);
    crossing["watermark_classification"]["used_after"] = Value::String("at_or_above".into());
    let crossing = reseal_allocation(crossing);
    ValidatedRuntimeRecord::validate_value(crossing.clone()).expect("exact watermark transition");

    let mut wrong_before = crossing;
    wrong_before["watermark_classification"]["used_before"] = Value::String("at_or_above".into());
    let wrong_before = reseal_allocation(wrong_before);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(wrong_before),
        Err(ContractError::InvalidCapacityAllocation)
    ));
}

#[test]
fn queue_order_cardinality_and_direct_key_law_are_load_bearing() {
    let value = allocation();
    let original = derive_capacity_allocation_identity(&value).expect("original identity");

    let mut reordered = value.clone();
    reordered["queue"]["occurrences"]
        .as_array_mut()
        .expect("occurrences")
        .reverse();
    assert_ne!(
        derive_capacity_allocation_identity(&reordered).expect("reordered identity"),
        original
    );
    assert!(ValidatedRuntimeRecord::validate_value(reordered).is_err());

    let mut removed = value.clone();
    removed["queue"]["occurrences"]
        .as_array_mut()
        .expect("occurrences")
        .pop();
    assert_ne!(
        derive_capacity_allocation_identity(&removed).expect("reduced identity"),
        original
    );
    assert!(ValidatedRuntimeRecord::validate_value(removed).is_err());

    let occurrence = value["queue"]["occurrences"][0]
        .as_object()
        .expect("occurrence");
    let expected = capacity_queue_occurrence_identity(
        &serde_json::from_value::<Sha256Digest>(occurrence["capacity_allocation_id"].clone())
            .expect("allocation digest"),
        &serde_json::from_value::<Sha256Digest>(occurrence["request_occurrence_id"].clone())
            .expect("request digest"),
        &serde_json::from_value::<Sha256Digest>(occurrence["destination_generation_id"].clone())
            .expect("destination digest"),
        &serde_json::from_value::<Sha256Digest>(
            occurrence["delivery_policy_generation_id"].clone(),
        )
        .expect("policy digest"),
    )
    .expect("direct key law");
    assert_eq!(occurrence["occurrence_id"], expected.to_string());
}

#[test]
fn safe_integer_boundary_applies_to_inputs_and_checked_intermediates() {
    let mut exact_maximum = allocation();
    exact_maximum["before_snapshot"]["inventory_count"] = json!(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1);
    let exact_maximum = reseal_allocation(exact_maximum);
    ValidatedRuntimeRecord::validate_value(exact_maximum)
        .expect("an otherwise independent exact safe-maximum input remains representable");

    let mut unsafe_successor = allocation();
    unsafe_successor["before_snapshot"]["inventory_count"] =
        json!(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1 + 1);
    assert!(ValidatedRuntimeRecord::validate_value(unsafe_successor).is_err());

    let mut unsafe_sum = allocation();
    unsafe_sum["before_snapshot"]["matched_retained_bytes"] =
        json!(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1);
    unsafe_sum["before_snapshot"]["logical_preallocated_carrier_bytes"] =
        json!(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1);
    unsafe_sum["logical_preallocated_carrier_bytes_after"] =
        json!(CAPACITY_IJSON_SAFE_INTEGER_MAX_V1);
    let unsafe_sum = reseal_allocation(unsafe_sum);
    assert!(matches!(
        ValidatedRuntimeRecord::validate_value(unsafe_sum),
        Err(ContractError::InvalidCapacityAllocation)
    ));
}

#[test]
fn every_rule_digest_and_the_inspectable_source_map_are_load_bearing() {
    let sources = capacity_rule_artifact_sources_v1().expect("closed source map");
    assert_eq!(sources.len(), 7);
    assert_eq!(
        sources
            .iter()
            .map(nq_host_role_contract::CapacityRuleArtifactSourceV1::rule_identity)
            .collect::<BTreeSet<_>>()
            .len(),
        7
    );
    for source in &sources {
        assert_eq!(source.rule_version(), "1");
        assert!(!source.digest_domain().is_empty());
        assert!(!source.source_paths().is_empty());
        assert_eq!(
            source.artifact_digest(),
            &capacity_rule_artifact_digest_v1(source.rule_identity()).expect("mapped rule digest")
        );
    }

    let exact = allocation();
    for field in [
        "capacity_calculation",
        "carrier_map",
        "arena_layout",
        "record_extent",
        "delivery_extent",
        "v3_capsule_bound",
        "canonicalization",
    ] {
        let mut substituted = exact.clone();
        substituted["rules"][field]["artifact_digest"] =
            Value::String(digest(&format!("substituted-rule/{field}")));
        let substituted = reseal_allocation(substituted);
        assert!(
            matches!(
                ValidatedRuntimeRecord::validate_value(substituted),
                Err(ContractError::InvalidCapacityAllocation)
            ),
            "{field} digest substitution was accepted"
        );
    }
}

#[test]
fn aggregate_usage_counts_missing_committed_bytes_exactly_once() {
    let semantic = CapacitySemanticComponentsV1 {
        request_and_decision_bytes: 1,
        raw_evidence_bytes: 1,
        normalized_bytes: 1,
        projected_bytes: 1,
        diagnostic_artifact_bytes: 1,
        dependency_closure_bytes: 1,
        commit_checkpoint_overhead_bytes: 1,
        mandatory_delivery_ledger_bytes: 0,
    };
    let result = checked_logical_preallocated_custody_carriers_v1(
        &semantic,
        &CapacityUsageComponentsV1 {
            bootstrap_integrity_carrier_bytes: 10,
            global_prelaunch_refusal_bytes: 20,
            matched_retained_bytes: 30,
            physical_orphan_bytes: 40,
            missing_committed_bytes: 50,
            active_queue_entries: 0,
        },
        &CapacityCandidateChargeV1 {
            arena_file_length_bytes: 100,
            canonical_record_extent_length_bytes: 200,
            delivery_ledger_extent_length_bytes: 0,
            final_closure_payload_bytes: 8,
            protected_failure_payload_bytes: 1,
            queue_entries_reserved: 0,
        },
        &CapacityLogicalLimitsV1 {
            total_bytes: 1_000,
            high_watermark_bytes: 900,
            protected_failure_receipt_bytes: 1,
            maximum_single_execution_closure_bytes: 100,
            maximum_queue_entries: 1,
        },
    )
    .expect("checked aggregate");
    assert_eq!(result.logical_preallocated_carrier_bytes_before(), 150);
    assert_eq!(result.logical_preallocated_carrier_bytes_after(), 450);
}

#[test]
fn neutral_plan_preselection_earns_required_and_not_requested_delivery_without_allocation() {
    let fixture: Value =
        serde_json::from_slice(verified_corrected_specimen().expect("corrected specimen"))
            .expect("fixture JSON");
    let records = fixture["records"].as_object().expect("fixture record map");
    let reservation =
        ValidatedRuntimeRecord::validate_value(records["custody_reservation"].clone())
            .expect("source reservation");
    let required_plan =
        CustodyReservationPlan::from_reservation(&reservation).expect("required plan");
    let (required_set, _) = record_set([
        records["request"].clone(),
        records["activation"].clone(),
        records["role_manifest"].clone(),
        records["buffer_delivery_policy"].clone(),
    ]);
    let required = required_set
        .select_reservation_plan_delivery_requirement(&required_plan)
        .expect("required preselection");
    let request =
        ValidatedRuntimeRecord::validate_value(records["request"].clone()).expect("request");
    assert_eq!(
        required.requirement(),
        CapacityDeliveryRequirementV1::Required
    );
    assert_eq!(required.destination_generation_ids().len(), 1);
    assert_eq!(
        required.request_occurrence_id(),
        &nq_host_role_contract::invocation_occurrence_key_v1(&request).expect("P0-1 occurrence")
    );
    assert_eq!(
        required.idempotency_key_id(),
        &nq_host_role_contract::invocation_idempotency_key_v1(&request).expect("P0-1 idempotency")
    );

    let mut no_delivery_request = records["request"].clone();
    no_delivery_request["delivery"] = json!({"mode": "not_requested"});
    reseal_request(&mut no_delivery_request);
    let no_delivery_request =
        ValidatedRuntimeRecord::validate_value(no_delivery_request).expect("no-delivery request");
    let mut no_delivery_plan = required_plan.as_value().clone();
    no_delivery_plan["request"] = Value::from(no_delivery_request.exact_reference());
    no_delivery_plan["delivery_requirement"] = Value::Null;
    let delivery_bytes = no_delivery_plan["component_bounds"]["mandatory_delivery_ledger_bytes"]
        .as_u64()
        .expect("delivery component");
    no_delivery_plan["component_bounds"]["mandatory_delivery_ledger_bytes"] = json!(0);
    no_delivery_plan["total_required_bytes"] = json!(
        no_delivery_plan["total_required_bytes"]
            .as_u64()
            .expect("total required")
            - delivery_bytes
    );
    no_delivery_plan["reserved_bytes"] = no_delivery_plan["total_required_bytes"].clone();
    let no_delivery_plan =
        CustodyReservationPlan::validate_value(no_delivery_plan).expect("no-delivery plan");
    let (no_delivery_set, _) = record_set([
        no_delivery_request.record().as_value().clone(),
        records["activation"].clone(),
        records["role_manifest"].clone(),
        records["buffer_delivery_policy"].clone(),
    ]);
    let no_delivery = no_delivery_set
        .select_reservation_plan_delivery_requirement(&no_delivery_plan)
        .expect("not-requested preselection");
    assert_eq!(
        no_delivery.requirement(),
        CapacityDeliveryRequirementV1::NotRequired
    );
    assert!(no_delivery.destination_generation_ids().is_empty());
    assert!(no_delivery.delivery_buffer_policy().is_none());
    assert!(no_delivery.delivery_policy_generation_id().is_none());
}

#[test]
fn allocation_only_frontier_is_source_valid_but_c3_blocks_product_graph_and_completion() {
    let fixture: Value =
        serde_json::from_slice(verified_corrected_specimen().expect("corrected specimen"))
            .expect("fixture JSON");
    let records = fixture["records"].as_object().expect("fixture record map");
    let mut allocation = source_bound_allocation(records);
    let mut unmatched_plan = allocation["reservation_plan"].clone();
    unmatched_plan["expires_at"] = Value::String("2026-07-28T22:03:01Z".into());
    allocation = replace_allocation_plan(allocation, unmatched_plan);
    let allocation_reference = ValidatedRuntimeRecord::validate_value(allocation.clone())
        .expect("allocation-only carrier")
        .exact_reference();
    let mut values = records.values().cloned().collect::<Vec<_>>();
    values.push(allocation);
    let (set, context) = record_set(values);

    let graph_error = set
        .validate(&context)
        .expect_err("C3 blocks an otherwise source-valid allocation frontier");
    assert!(
        graph_error
            .to_string()
            .contains(STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE)
    );
    assert!(matches!(
        set.select_capacity_delivery_requirement(&allocation_reference),
        Err(ContractError::CapacityJoin(
            "nested plan does not have exactly one final reservation source"
        ))
    ));
}

#[test]
fn product_graph_and_completed_selection_retain_the_independent_c3_gate() {
    let graph_source = include_str!("../src/graph.rs");
    assert_eq!(
        graph_source
            .matches("require_store_owned_capacity_allocation_construction()")
            .count(),
        2,
        "full graph validation and direct completed selection must each retain the C3 gate"
    );
}

#[test]
fn exact_final_reservation_reaches_c3_but_duplicate_refuses_exact_one() {
    let fixture: Value =
        serde_json::from_slice(verified_corrected_specimen().expect("corrected specimen"))
            .expect("fixture JSON");
    let records = fixture["records"].as_object().expect("fixture record map");
    let allocation = source_bound_allocation(records);
    let allocation_reference = ValidatedRuntimeRecord::validate_value(allocation.clone())
        .expect("source-bound allocation")
        .exact_reference();
    let expected_reservation =
        ValidatedRuntimeRecord::validate_value(records["custody_reservation"].clone())
            .expect("source reservation")
            .exact_reference();
    let mut values = records.values().cloned().collect::<Vec<_>>();
    values.push(allocation.clone());
    let (set, _) = record_set(values);
    let exact_error = set
        .select_capacity_delivery_requirement(&allocation_reference)
        .expect_err("C3-blocked allocation cannot produce a completed selection");
    assert!(
        exact_error
            .to_string()
            .contains(STORE_OWNED_CAPACITY_ALLOCATION_CONSTRUCTION_GATE)
    );

    let mut duplicate = records["custody_reservation"].clone();
    duplicate["reservation_id"] = Value::String(digest("duplicate-final-reservation"));
    let duplicate =
        ValidatedRuntimeRecord::validate_value(duplicate).expect("distinct matching reservation");
    assert_ne!(duplicate.exact_reference(), expected_reservation);
    let mut duplicated_values = records.values().cloned().collect::<Vec<_>>();
    duplicated_values.push(allocation);
    duplicated_values.push(duplicate.record().as_value().clone());
    let (duplicated, _) = record_set(duplicated_values);
    assert!(matches!(
        duplicated.select_capacity_delivery_requirement(&allocation_reference),
        Err(ContractError::CapacityJoin(
            "nested plan does not have exactly one final reservation source"
        ))
    ));
}

#[test]
fn allocation_source_join_refuses_occurrence_and_idempotency_substitution_before_c3() {
    let fixture: Value =
        serde_json::from_slice(verified_corrected_specimen().expect("corrected specimen"))
            .expect("fixture JSON");
    let records = fixture["records"].as_object().expect("fixture record map");
    let exact = source_bound_allocation(records);

    let mut occurrence_substitution = exact.clone();
    let substituted_occurrence = digest("foreign-P0-1-occurrence");
    occurrence_substitution["request_occurrence"]["occurrence_id"] =
        Value::String(substituted_occurrence.clone());
    for occurrence in occurrence_substitution["queue"]["occurrences"]
        .as_array_mut()
        .expect("occurrences")
    {
        occurrence["request_occurrence_id"] = Value::String(substituted_occurrence.clone());
    }
    let occurrence_substitution = reseal_allocation(occurrence_substitution);
    ValidatedRuntimeRecord::validate_value(occurrence_substitution.clone())
        .expect("locally coherent occurrence substitution");

    let mut idempotency_substitution = exact;
    idempotency_substitution["request_occurrence"]["idempotency_key_id"] =
        Value::String(digest("foreign-P0-1-idempotency"));
    let idempotency_substitution = reseal_allocation(idempotency_substitution);
    ValidatedRuntimeRecord::validate_value(idempotency_substitution.clone())
        .expect("locally coherent idempotency substitution");

    for substituted in [occurrence_substitution, idempotency_substitution] {
        let mut values = records.values().cloned().collect::<Vec<_>>();
        values.push(substituted);
        let (set, context) = record_set(values);
        assert!(matches!(
            set.validate(&context),
            Err(ContractError::CapacityJoin(
                "allocation plan, request occurrence, or idempotency substitution"
            ))
        ));
    }
}
