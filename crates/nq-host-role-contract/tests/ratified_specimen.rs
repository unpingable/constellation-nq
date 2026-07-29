//! Conformance and hostile tests against the exact ratified 3A specimen.

use std::collections::{BTreeMap, BTreeSet};

use nq_host_role_contract::{
    CONTRACT_SOURCE_COMMIT, ContractError, ExternalRecordCatalog, IdentityCatalog, IdentityRef,
    RecordRef, RuntimeRecordSet, RuntimeSchema, ValidatedRuntimeRecord, ValidationContext,
    verified_package_manifest,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes};
use serde_json::{Value, json};

const RECORDS: &str = include_str!("../assets/host-role-runtime-records.v1.json");

fn specimen() -> (BTreeMap<String, Value>, RuntimeRecordSet, ValidationContext) {
    let fixture: Value = serde_json::from_str(RECORDS).expect("embedded specimen is JSON");
    assert_eq!(fixture["source_commit"], CONTRACT_SOURCE_COMMIT);
    let records = fixture["records"]
        .as_object()
        .expect("fixture records are an object");

    let mut set = RuntimeRecordSet::new();
    let mut by_id = BTreeSet::new();
    let mut identities = Vec::<IdentityRef>::new();
    let mut references = Vec::<RecordRef>::new();
    let mut values = BTreeMap::new();
    for (name, value) in records {
        collect_carriers(value, &mut identities, &mut references);
        let validated = ValidatedRuntimeRecord::validate_value(value.clone())
            .unwrap_or_else(|error| panic!("{name} failed local validation: {error}"));
        by_id.insert(validated.record_id().clone());
        assert_eq!(
            ValidatedRuntimeRecord::decode_canonical(validated.canonical_bytes())
                .expect("canonical replay")
                .record_id(),
            validated.record_id()
        );
        set.insert(validated).expect("unique immutable identity");
        values.insert(name.clone(), value.clone());
    }

    let mut identity_catalog = IdentityCatalog::new();
    for identity in identities {
        identity_catalog
            .insert(identity)
            .expect("fixture descriptor non-substitution");
    }
    let mut external_records = ExternalRecordCatalog::new();
    for reference in references {
        if !by_id.contains(&reference.record_id) {
            external_records.insert(reference);
        }
    }
    (
        values,
        set,
        ValidationContext {
            identities: identity_catalog,
            external_records,
        },
    )
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
                identities
                    .push(serde_json::from_value(value.clone()).expect("fixture identity carrier"));
            } else if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                references
                    .push(serde_json::from_value(value.clone()).expect("fixture record reference"));
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

fn graph_from(values: &[Value]) -> (RuntimeRecordSet, ValidationContext) {
    let mut identities = Vec::<IdentityRef>::new();
    let mut references = Vec::<RecordRef>::new();
    let mut local_ids = BTreeSet::new();
    let mut set = RuntimeRecordSet::new();
    for value in values {
        collect_carriers(value, &mut identities, &mut references);
        let record = ValidatedRuntimeRecord::validate_value(value.clone()).expect("local record");
        local_ids.insert(record.record_id().clone());
        set.insert(record).expect("unique identity");
    }
    let mut identity_catalog = IdentityCatalog::new();
    for identity in identities {
        identity_catalog.insert(identity).expect("catalog insert");
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

#[test]
fn all_ratified_schema_assets_are_embedded_and_all_carriers_parse() {
    let manifest = verified_package_manifest().expect("exact pinned schema assets");
    assert_eq!(manifest.assets.len(), RuntimeSchema::ALL.len() + 1);

    let (values, _, _) = specimen();
    let observed = values
        .values()
        .map(|value| value["schema"].as_str().expect("schema"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        observed,
        RuntimeSchema::ALL
            .iter()
            .map(|schema| schema.as_str())
            .collect()
    );
}

#[test]
fn complete_ratified_specimen_passes_closed_graph_validation() {
    let (_, records, context) = specimen();
    assert_eq!(records.len(), 50);
    records.validate(&context).expect("ratified closed graph");
}

#[test]
fn canonical_bytes_and_declared_identity_are_distinct_and_stable() {
    let (_, records, _) = specimen();
    for record in records.records() {
        assert_eq!(
            &Sha256Digest::parse(record.bytes_digest().as_str()).expect("digest"),
            record.bytes_digest()
        );
        assert_eq!(
            canonical_json_bytes(record.record().as_value()).expect("canonical JSON"),
            record.canonical_bytes()
        );
    }
}

#[test]
fn buffer_retry_and_capacity_laws_refuse_substitution() {
    let (values, _, _) = specimen();
    let mut policy = values["buffer_delivery_policy"].clone();
    policy["capacity"]["protected_failure_receipt_bytes"] =
        policy["capacity"]["high_watermark_bytes"].clone();
    let error = ValidatedRuntimeRecord::validate_value(policy).expect_err("capacity collision");
    assert!(matches!(error, ContractError::InvalidCapacityPolicy));

    let mut policy = values["buffer_delivery_policy"].clone();
    policy["retry"]["maximum_attempts"] = json!(4);
    let error = ValidatedRuntimeRecord::validate_value(policy).expect_err("retry mismatch");
    assert!(matches!(error, ContractError::InvalidRetryPolicy));
}

#[test]
fn lifecycle_edges_and_proofs_are_closed() {
    let (values, _, _) = specimen();
    let mut bootstrap = values["bootstrap_event"].clone();
    bootstrap["to_state"] = json!("active");
    let error =
        ValidatedRuntimeRecord::validate_value(bootstrap).expect_err("illegal bootstrap edge");
    assert!(matches!(error, ContractError::InvalidLifecycleTransition));

    let mut decommission = values["decommission_complete_event"].clone();
    decommission
        .as_object_mut()
        .expect("object")
        .remove("operation_proof");
    let error =
        ValidatedRuntimeRecord::validate_value(decommission).expect_err("missing exact cut proof");
    assert!(matches!(error, ContractError::LifecycleProofMismatch));
}

#[test]
fn restore_quarantine_cannot_expose_activation_eligibility() {
    let (values, _, _) = specimen();
    let mut proof = values["restore_proof"].clone();
    proof["activation_candidate"] = values["activation"].clone();
    let error =
        ValidatedRuntimeRecord::validate_value(proof).expect_err("quarantine activation bypass");
    assert!(matches!(error, ContractError::RestoreQuarantineBypass));
}

#[test]
fn decommission_snapshot_and_terminal_cut_commitments_are_load_bearing() {
    let (values, _, _) = specimen();
    let mut snapshot = values["decommission_begin_snapshot"].clone();
    snapshot["ledger_entry_count"] = json!(0);
    let error =
        ValidatedRuntimeRecord::validate_value(snapshot).expect_err("snapshot count substitution");
    assert!(matches!(
        error,
        ContractError::DecommissionSnapshotCommitmentMismatch
    ));

    let mut cut = values["decommission_cut"].clone();
    cut["unresolved_counts"]["in_flight"] = json!(1);
    let error = ValidatedRuntimeRecord::validate_value(cut).expect_err("terminal unresolved work");
    assert!(matches!(error, ContractError::DecommissionDrainIncomplete));
}

#[test]
fn catalog_snapshot_is_deterministic_but_mints_no_identity_authority() {
    let (_, _, context) = specimen();
    let namespace: nq_host_role_contract::NamespaceSnapshot = serde_json::from_value(json!({
        "namespace_id": "nq.production",
        "namespace_version": "1",
        "catalog_generation": "1",
        "catalog_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }))
    .expect("namespace snapshot");
    let snapshot = context.identities.snapshot(namespace);
    snapshot.validate().expect("canonical catalog ordering");
    let digest = snapshot.semantic_digest().expect("catalog digest");
    let bytes = snapshot
        .canonical_bytes()
        .expect("canonical snapshot bytes");
    assert_eq!(
        nq_host_role_contract::CatalogSnapshot::decode_canonical(&bytes)
            .expect("canonical snapshot replay"),
        snapshot
    );
    let reopened = IdentityCatalog::from_snapshot(&snapshot).expect("deterministic reopen");
    assert_eq!(
        reopened.entries().collect::<Vec<_>>(),
        context.identities.entries().collect::<Vec<_>>()
    );
    assert_eq!(snapshot.semantic_digest().expect("stable digest"), digest);

    let pretty = serde_json::to_vec_pretty(&snapshot).expect("pretty snapshot");
    assert!(matches!(
        nq_host_role_contract::CatalogSnapshot::decode_canonical(&pretty),
        Err(ContractError::NonCanonicalCatalogSnapshot)
    ));
}

#[test]
fn unknown_fields_and_nightshift_authority_are_refused() {
    let (values, _, _) = specimen();
    let mut role = values["role_manifest"].clone();
    role["schedule"] = json!("every-minute");
    let error = ValidatedRuntimeRecord::validate_value(role).expect_err("NQ recurrence trespass");
    assert!(matches!(
        error,
        ContractError::RecordShape { .. } | ContractError::ForbiddenAuthorityField
    ));
}

#[test]
fn host_lifecycle_forks_are_refused_without_reinterpreting_the_predecessor() {
    let (values, _, _) = specimen();
    let bootstrap = values["bootstrap_event"].clone();
    let enroll = values["enroll_event"].clone();
    let mut fork = enroll.clone();
    fork["event_id"] =
        json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    fork["occurred_at"] = json!("2026-07-28T22:00:01Z");

    let (records, context) = graph_from(&[bootstrap, enroll, fork]);
    let error = records.validate(&context).expect_err("lifecycle fork");
    assert!(matches!(
        error,
        ContractError::LifecycleJoin("host lifecycle fork")
    ));
}

#[test]
fn immutable_record_identity_reuse_refuses_byte_substitution() {
    let (values, _, _) = specimen();
    let original = ValidatedRuntimeRecord::validate_value(values["bootstrap_event"].clone())
        .expect("original");
    let mut substitution = values["bootstrap_event"].clone();
    substitution["reason"] = json!("different exact occurrence description");
    let substitution =
        ValidatedRuntimeRecord::validate_value(substitution).expect("locally valid substitution");
    let mut set = RuntimeRecordSet::new();
    set.insert(original).expect("first insert");
    assert!(matches!(
        set.insert(substitution),
        Err(ContractError::DuplicateRecordIdentity)
    ));
}
