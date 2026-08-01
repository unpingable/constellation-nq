//! Opt-in downstream qualification fixtures.
//!
//! This module is available only through the `test-support` feature. It
//! constructs authenticated dependency material and then delegates opaque
//! invocation preparation to [`super::HostRoleRuntime`]. Nothing here grants
//! production authority, bypasses graph validation, fabricates an opaque
//! prepared token, or ships in the default feature set.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use nq_host_role_contract::{
    IdentityId, IdentityKind, IdentityRef, IdentityVersion, RecordRef, RuntimeSchema, Token,
    ValidatedRuntimeRecord,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde_json::{Map, Value, json};

use nq_runtime_dependency_authority::test_support::{
    FIXTURE_DOMAIN, FIXTURE_HOST_ROLE, FIXTURE_RESIDENT_GENERATION, FIXTURE_RESIDENT_ID,
    FIXTURE_ROLE_MANIFEST_GENERATION, RawAuthorityFixture,
};
use nq_store::Store;

use super::{
    AppendRecord, AppendRequest, HostRoleRuntime, NativeDeadlinePrelaunchRequest,
    PROVIDER_INTAKE_SCHEMA, RuntimeAuthorityResidentBinding, RuntimeDependencies,
    cohort_semantics_digest, seal_semantic_identity,
};
const RECORDS: &str =
    include_str!("../../nq-host-role-contract/assets/host-role-runtime-records.v1.json");
const FIXTURE_ANCHOR: &str = "2026-07-28T22:02:00Z";

/// Initialize a fully governed Gen4 Store through the named
/// [`HostRoleRuntime::initialize`] route, then return the established Store for
/// downstream test operations.
///
/// This helper cannot expose the Store-private branded authority scope. Its
/// self-consistent fixture bundle exercises the chartered fresh-file nonclaim
/// and earns no predetermined-actor or estate-custody claim.
///
/// # Panics
///
/// Panics if the repository-owned authenticated dependency or authority
/// fixtures no longer establish through the production runtime path.
#[must_use]
pub fn initialized_gen4_store(path: impl AsRef<std::path::Path>) -> Store {
    let dependencies =
        authenticated_runtime_dependencies(91, Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let anchor = dependencies
        .custody()
        .trust_anchor_id()
        .expect("fixture trust anchor");
    let authority = RawAuthorityFixture::fresh_genesis_with_anchor(anchor);
    let resident = RuntimeAuthorityResidentBinding {
        resident_identity: FIXTURE_RESIDENT_ID.to_owned(),
        resident_generation: FIXTURE_RESIDENT_GENERATION,
        host_role: FIXTURE_HOST_ROLE.to_owned(),
        role_manifest_generation: FIXTURE_ROLE_MANIFEST_GENERATION,
        domain: FIXTURE_DOMAIN.to_owned(),
        policy_floor: 1,
    };
    HostRoleRuntime::initialize(path, dependencies, &authority.custody(), &resident)
        .expect("named Gen4 runtime initialization")
        .into_store()
}

/// Exact native compiled-profile fields required by the governed seam.
#[derive(Clone, Debug)]
pub struct NativeProfileFixtureBinding {
    /// Profile descriptor schema.
    pub descriptor_schema: String,
    /// Compiled native profile identifier.
    pub profile_id: String,
    /// Compiled native profile version.
    pub profile_version: u64,
    /// Exact compiled descriptor digest.
    pub descriptor_digest: Sha256Digest,
    /// Semantic-identity carrier schema.
    pub semantic_identity_schema: String,
    /// Exact compiled semantic identity.
    pub semantic_identity_digest: Sha256Digest,
    /// Exact evaluator-source identity.
    pub evaluator_source_digest: Sha256Digest,
    /// Exact helper protocol.
    pub helper_protocol_version: String,
    /// Exact zero-detector closure identity.
    pub detector_closure_identity_digest: Sha256Digest,
    /// Detector count. The initial governed conformance seam requires zero.
    pub detector_count: u64,
}

/// Exact independently observed evaluator fields required by the seam.
#[derive(Clone, Debug)]
pub struct NativeEvaluatorFixtureBinding {
    /// Running evaluator artifact digest.
    pub artifact_digest: Sha256Digest,
    /// Running evaluator artifact identity method.
    pub artifact_identity_method: String,
    /// Running evaluator target triple.
    pub target_triple: String,
}

/// Downstream inputs that join a real local-provider admission to the contract
/// specimen without manufacturing provider standing.
#[derive(Clone, Debug)]
pub struct NativeEngineFixtureBinding {
    /// Exact NQ-derived local-provider admission reference.
    pub provider_admission: RecordRef,
    /// Exact canonical local-provider admission bytes.
    pub provider_admission_bytes: Vec<u8>,
    /// Production profile identity named by the governed request.
    pub production_profile_id: String,
    /// Production profile generation named by the governed request.
    pub production_profile_version: u64,
    /// Exact compiled native profile identity.
    pub native_profile: NativeProfileFixtureBinding,
    /// Exact observed native evaluator identity.
    pub native_evaluator: NativeEvaluatorFixtureBinding,
    /// Runtime-owned attempt budget used by the native deadline path.
    pub maximum_execution_ms: u64,
}

/// Authenticated material for one downstream engine effect-path test.
///
/// Consumers must still initialize a real [`HostRoleRuntime`] and call
/// [`HostRoleRuntime::prepare_native_deadline_invocation`]. This bundle cannot
/// construct, deserialize, or counterfeit [`PreparedGovernedInvocation`].
#[derive(Clone, Debug)]
pub struct NativeEngineFixture {
    /// Exact authenticated dependency generation.
    pub dependencies: RuntimeDependencies,
    /// Request accepted only by the production native-deadline preparation
    /// path.
    pub request: NativeDeadlinePrelaunchRequest,
    /// Independently established dependency trust root.
    pub dependency_anchor_id: Sha256Digest,
}

/// Build one exact native host-role fixture around a real NQ provider
/// admission.
///
/// The function is qualification scaffolding, not an enrollment, admission,
/// authorization, or execution API. Every returned record is subsequently
/// revalidated by the ordinary runtime graph and custody paths.
///
/// # Panics
///
/// Panics when the caller supplies inconsistent exact identities or when the
/// repository-owned contract specimen no longer satisfies its own structural
/// and authenticated-dependency invariants. It is test-only scaffolding, so a
/// fixture construction failure is intentionally terminal.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn native_engine_fixture(binding: &NativeEngineFixtureBinding) -> NativeEngineFixture {
    assert_eq!(
        sha256_bytes(&binding.provider_admission_bytes),
        binding.provider_admission.bytes_digest,
        "provider admission exact bytes"
    );
    assert_eq!(
        binding.provider_admission.record_id, binding.provider_admission.bytes_digest,
        "local-provider admission content identity"
    );
    assert_eq!(
        binding.provider_admission.schema.as_str(),
        "nq.local_provider_admission.v1",
        "local-provider admission schema"
    );
    assert_eq!(
        binding.native_profile.detector_count, 0,
        "initial governed conformance fixture is zero-detector"
    );
    assert!(binding.maximum_execution_ms > 0);

    let document: Value = serde_json::from_str(RECORDS).expect("runtime contract specimen");
    let mut values = document["records"]
        .as_object()
        .expect("runtime records")
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let original_records = validate_records(&values);
    let original_closure = transitive_runtime_closure(
        &original_records,
        [
            original_records["request"].exact_reference(),
            original_records["invocation_decision"].exact_reference(),
            original_records["custody_reservation"].exact_reference(),
            original_records["execution_launch"].exact_reference(),
        ],
    );
    values.retain(|name, _| original_closure.contains_key(name));

    let original_refs = exact_runtime_refs(&values);
    shift_fixture_times(&mut values);
    patch_engine_binding(&mut values, binding);
    increase_fixture_dependency_capacity(&mut values);
    let mut external_inputs = install_production_identity_descriptors(&mut values);
    stabilize_runtime_references(&mut values, original_refs);

    let pre_qualification_refs = exact_runtime_refs(&values);
    install_native_qualifications(&mut values, binding);
    stabilize_runtime_references(&mut values, pre_qualification_refs);

    let original_refs = exact_runtime_refs(&values);
    external_inputs.extend(replace_external_references(
        &mut values,
        &BTreeMap::from([(
            binding.provider_admission.clone(),
            binding.provider_admission_bytes.clone(),
        )]),
    ));
    stabilize_runtime_references(&mut values, original_refs);
    let records = validate_records(&values);

    let request_record = records["request"].clone();
    let decision = records["invocation_decision"].clone();
    let reservation = records["custody_reservation"].clone();
    let launch = records["execution_launch"].clone();
    let closure = transitive_runtime_closure(
        &records,
        [
            request_record.exact_reference(),
            decision.exact_reference(),
            reservation.exact_reference(),
            launch.exact_reference(),
        ],
    );
    let mut identities = Vec::new();
    let mut external_refs = BTreeSet::new();
    for record in closure.values() {
        collect_test_carriers(
            record.record().as_value(),
            &mut identities,
            &mut external_refs,
        );
    }
    let (resolver, resolver_source) =
        production_identity_source(IdentityKind::Resolver, "nq-test-resolver", "1");
    identities.push(resolver);
    external_inputs.push(resolver_source);
    for identity in &identities {
        let descriptor = external_inputs
            .iter()
            .find(|(reference, _)| {
                reference.bytes_digest == identity.descriptor_digest
                    && reference.schema.as_str() == "nq.production_identity_descriptor.v1"
            })
            .unwrap_or_else(|| panic!("descriptor bytes for {identity:?}"));
        external_refs.insert(descriptor.0.clone());
    }
    let external_by_ref = external_inputs.into_iter().collect::<BTreeMap<_, _>>();
    let exact_external_inputs = external_refs
        .iter()
        .map(|reference| {
            (
                reference.clone(),
                external_by_ref
                    .get(reference)
                    .unwrap_or_else(|| panic!("external bytes for {reference:?}"))
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    let operation_authorizations = closure
        .values()
        .filter(|record| record.schema() == RuntimeSchema::OperationAuthorizationV1)
        .map(ValidatedRuntimeRecord::exact_reference)
        .collect::<Vec<_>>();
    let authentication: RecordRef = serde_json::from_value(
        request_record.record().as_value()["authentication_evidence"].clone(),
    )
    .expect("authentication reference");
    identities.sort();
    identities.dedup();
    let dependencies = authenticated_runtime_dependencies(
        41,
        identities,
        exact_external_inputs,
        operation_authorizations,
        vec![authentication],
    );
    let dependency_anchor_id = dependencies
        .custody()
        .trust_anchor_id()
        .expect("fixture dependency anchor");

    let mut reservation_records = closure
        .values()
        .filter(|record| record.record_id() != launch.record_id())
        .map(|record| AppendRecord::from_contract(record, timestamp_near_now(-1)))
        .collect::<Vec<_>>();
    reservation_records.sort_by(|left, right| left.record_id.cmp(&right.record_id));
    let generic_launch: Value =
        serde_json::from_slice(launch.canonical_bytes()).expect("generic launch");
    let reservation_value = reservation.record().as_value();
    let request = NativeDeadlinePrelaunchRequest {
        reservation_custody: AppendRequest {
            checkpoint_id: sha256_bytes(b"engine-test-runtime-reservation").to_string(),
            records: reservation_records,
        },
        outer_request_record_id: request_record.record_id().clone(),
        invocation_decision_record_id: decision.record_id().clone(),
        custody_reservation_record_id: reservation.record_id().clone(),
        generation_match: serde_json::from_value(
            generic_launch["prelaunch_checks"]["generation_match"].clone(),
        )
        .expect("generation check"),
        capability: serde_json::from_value(
            generic_launch["prelaunch_checks"]["capability"].clone(),
        )
        .expect("capability check"),
        launch_commit: serde_json::from_value(generic_launch["launch_commit"].clone())
            .expect("launch commit"),
        bracket_policy: serde_json::from_value(reservation_value["calculation_rule"].clone())
            .expect("bracket policy"),
        maximum_bracket_width_ns: 100_000_000,
    };
    NativeEngineFixture {
        dependencies,
        request,
        dependency_anchor_id,
    }
}

fn timestamp_near_now(offset_seconds: i64) -> String {
    (Utc::now() + Duration::seconds(offset_seconds)).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn shift_fixture_times(values: &mut BTreeMap<String, Value>) {
    let anchor = DateTime::parse_from_rfc3339(FIXTURE_ANCHOR)
        .expect("fixture anchor")
        .with_timezone(&Utc);
    let target = Utc::now() - Duration::seconds(1);
    let delta = target - anchor;
    for value in values.values_mut() {
        shift_timestamps(value, delta);
    }
}

fn shift_timestamps(value: &mut Value, delta: Duration) {
    match value {
        Value::String(text) => {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(text) {
                *text = (parsed.with_timezone(&Utc) + delta)
                    .to_rfc3339_opts(SecondsFormat::Millis, true);
            }
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                shift_timestamps(child, delta);
            }
        }
        Value::Array(array) => {
            for child in array {
                shift_timestamps(child, delta);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn patch_engine_binding(
    values: &mut BTreeMap<String, Value>,
    binding: &NativeEngineFixtureBinding,
) {
    for value in values.values_mut() {
        rewrite_diagnostic_profile_identity(
            value,
            &binding.production_profile_id,
            binding.production_profile_version,
        );
    }
    let witness = values
        .get_mut("witness_attachment")
        .expect("witness attachment");
    witness["provider_admission"] =
        serde_json::to_value(&binding.provider_admission).expect("provider admission reference");
    witness["privileges"] = json!([]);
    witness["namespaces"] = json!([]);
    witness["resources"] = json!([]);

    values.get_mut("request").expect("diagnostic request")["time_bounds"]["maximum_execution_ms"] =
        json!(binding.maximum_execution_ms);
    values
        .get_mut("execution_launch")
        .expect("generic execution launch")["maximum_execution_ms"] =
        json!(binding.maximum_execution_ms);
    let launch = values
        .get_mut("execution_launch")
        .expect("generic execution launch");
    let launched_at = DateTime::parse_from_rfc3339(
        launch["launched_at"]
            .as_str()
            .expect("generic launch timestamp"),
    )
    .expect("generic launch timestamp")
    .with_timezone(&Utc);
    let maximum_execution_ms =
        i64::try_from(binding.maximum_execution_ms).expect("fixture execution budget");
    launch["attempt_deadline"] = json!(
        (launched_at + Duration::milliseconds(maximum_execution_ms))
            .to_rfc3339_opts(SecondsFormat::Millis, true)
    );
}

fn rewrite_diagnostic_profile_identity(value: &mut Value, profile_id: &str, profile_version: u64) {
    match value {
        Value::Object(object)
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["kind", "id", "version", "descriptor_digest"])
                && object["kind"] == "diagnostic_profile" =>
        {
            object.insert("id".to_owned(), Value::String(profile_id.to_owned()));
            object.insert(
                "version".to_owned(),
                Value::String(profile_version.to_string()),
            );
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                rewrite_diagnostic_profile_identity(child, profile_id, profile_version);
            }
        }
        Value::Array(array) => {
            for child in array {
                rewrite_diagnostic_profile_identity(child, profile_id, profile_version);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn validate_records(values: &BTreeMap<String, Value>) -> BTreeMap<String, ValidatedRuntimeRecord> {
    values
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                ValidatedRuntimeRecord::validate_value(value.clone())
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
            )
        })
        .collect()
}

fn exact_runtime_refs(values: &BTreeMap<String, Value>) -> BTreeMap<String, RecordRef> {
    validate_records(values)
        .into_iter()
        .map(|(name, record)| (name, record.exact_reference()))
        .collect()
}

fn increase_fixture_dependency_capacity(values: &mut BTreeMap<String, Value>) {
    let reservation = values
        .get_mut("custody_reservation")
        .expect("custody reservation");
    let replacements = [
        ("dependency_closure_bytes", 262_144_u64),
        ("raw_evidence_bytes", 16_777_216_u64),
        ("diagnostic_artifact_bytes", 16_777_216_u64),
        // The V3 capsule is an independently bounded physical projection
        // carrier. The enlarged engine-qualification fixture must raise this
        // component alongside the other enlarged exact-byte partitions; this
        // does not change the ratified production default.
        ("projected_bytes", 16_777_216_u64),
    ];
    let increase = replacements
        .into_iter()
        .map(|(field, replacement)| {
            let previous = reservation["component_bounds"][field]
                .as_u64()
                .expect("component capacity");
            reservation["component_bounds"][field] = json!(replacement);
            replacement
                .checked_sub(previous)
                .expect("larger component capacity")
        })
        .sum::<u64>();
    for field in ["reserved_bytes", "total_required_bytes"] {
        reservation[field] = json!(
            reservation[field]
                .as_u64()
                .expect("reservation total")
                .checked_add(increase)
                .expect("reservation total capacity")
        );
    }
}

fn install_production_identity_descriptors(
    values: &mut BTreeMap<String, Value>,
) -> Vec<(RecordRef, Vec<u8>)> {
    let mut sources = BTreeMap::<(String, String, String), (RecordRef, Vec<u8>)>::new();
    for value in values.values_mut() {
        rewrite_identity_descriptors(value, &mut sources);
    }
    sources.into_values().collect()
}

fn rewrite_identity_descriptors(
    value: &mut Value,
    sources: &mut BTreeMap<(String, String, String), (RecordRef, Vec<u8>)>,
) {
    match value {
        Value::Object(object)
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) =>
        {
            let key = (
                object["kind"].as_str().expect("identity kind").to_owned(),
                object["id"].as_str().expect("identity id").to_owned(),
                object["version"]
                    .as_str()
                    .expect("identity version")
                    .to_owned(),
            );
            let (reference, _) = sources.entry(key.clone()).or_insert_with(|| {
                let bytes = canonical_json_bytes(&json!({
                    "schema": "nq.production_identity_descriptor.v1",
                    "kind": key.0,
                    "id": key.1,
                    "version": key.2,
                }))
                .expect("production identity descriptor");
                let bytes_digest = sha256_bytes(&bytes);
                (
                    RecordRef {
                        schema: Token::parse("nq.production_identity_descriptor.v1")
                            .expect("descriptor schema"),
                        record_id: semantic_digest(
                            &serde_json::from_slice::<Value>(&bytes).expect("descriptor value"),
                        )
                        .expect("descriptor identity"),
                        bytes_digest: bytes_digest.clone(),
                    },
                    bytes,
                )
            });
            object.insert(
                "descriptor_digest".to_owned(),
                Value::String(reference.bytes_digest.to_string()),
            );
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                rewrite_identity_descriptors(child, sources);
            }
        }
        Value::Array(array) => {
            for child in array {
                rewrite_identity_descriptors(child, sources);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn production_identity_source(
    kind: IdentityKind,
    id: &str,
    version: &str,
) -> (IdentityRef, (RecordRef, Vec<u8>)) {
    let kind_value = serde_json::to_value(kind).expect("identity kind");
    let bytes = canonical_json_bytes(&json!({
        "schema": "nq.production_identity_descriptor.v1",
        "kind": kind_value,
        "id": id,
        "version": version,
    }))
    .expect("production identity descriptor");
    let bytes_digest = sha256_bytes(&bytes);
    let reference = RecordRef {
        schema: Token::parse("nq.production_identity_descriptor.v1").expect("descriptor schema"),
        record_id: semantic_digest(
            &serde_json::from_slice::<Value>(&bytes).expect("descriptor value"),
        )
        .expect("descriptor identity"),
        bytes_digest: bytes_digest.clone(),
    };
    (
        IdentityRef {
            kind,
            id: IdentityId::parse(id).expect("identity id"),
            version: IdentityVersion::parse(version).expect("identity version"),
            descriptor_digest: bytes_digest,
        },
        (reference, bytes),
    )
}

#[allow(clippy::too_many_lines)]
fn install_native_qualifications(
    values: &mut BTreeMap<String, Value>,
    binding: &NativeEngineFixtureBinding,
) {
    let cohort = &values["cohort_manifest"];
    let cohort_semantics_digest = cohort_semantics_digest(cohort).expect("cohort semantics digest");
    let qualification_evidence = cohort["qualification_records"][0].clone();
    let mut profile = json!({
        "schema": "nq.native_profile_qualification.v1",
        "qualification_id": sha256_bytes(b"native profile placeholder"),
        "namespace": cohort["namespace"],
        "cohort": cohort["cohort"],
        "cohort_generation": cohort["generation"],
        "cohort_semantics_digest": cohort_semantics_digest,
        "production_profile": cohort["members"]["profiles"][0],
        "production_question": cohort["members"]["questions"][0],
        "production_build": cohort["compatible_builds"][0],
        "native_profile": {
            "descriptor_schema": binding.native_profile.descriptor_schema,
            "profile_id": binding.native_profile.profile_id,
            "profile_version": binding.native_profile.profile_version,
            "descriptor_digest": binding.native_profile.descriptor_digest,
            "semantic_identity_schema": binding.native_profile.semantic_identity_schema,
            "semantic_identity_digest": binding.native_profile.semantic_identity_digest,
            "evaluator_source_digest": binding.native_profile.evaluator_source_digest,
            "helper_protocol_version": binding.native_profile.helper_protocol_version,
            "detector_closure": {
                "schema": "nq.detector_closure.v1",
                "identity_digest": binding.native_profile.detector_closure_identity_digest,
                "detector_count": binding.native_profile.detector_count,
            },
        },
        "native_evaluator": {
            "artifact_digest": binding.native_evaluator.artifact_digest,
            "artifact_identity_method": binding.native_evaluator.artifact_identity_method,
            "target_triple": binding.native_evaluator.target_triple,
        },
        "qualification_evidence": [qualification_evidence],
        "nonclaims": [
            "relates production and native identities but does not equate them",
            "does not establish invocation, reliance, authorization, or action",
        ],
    });
    seal_semantic_identity(&mut profile, "qualification_id").expect("profile identity");
    let profile = ValidatedRuntimeRecord::validate_value(profile).expect("profile qualifier");

    let mut clock = json!({
        "schema": "nq.native_clock_qualification.v1",
        "qualification_id": sha256_bytes(b"native clock placeholder"),
        "namespace": values["cohort_manifest"]["namespace"],
        "cohort": values["cohort_manifest"]["cohort"],
        "cohort_generation": values["cohort_manifest"]["generation"],
        "cohort_semantics_digest": cohort_semantics_digest,
        "production_clock": values["request"]["time_bounds"]["clock"],
        "production_build": values["cohort_manifest"]["compatible_builds"][0],
        "platform": values["subject_platform_relation"]["right"],
        "absolute_time": {
            "semantic_identity_digest": sha256_bytes(b"native CLOCK_REALTIME semantics"),
            "observation_method": "clock_gettime-clock-realtime-v1",
            "clock_id": "CLOCK_REALTIME",
            "epoch": "unix",
            "unit": "nanosecond",
            "accuracy_qualification": {"status": "unqualified"},
        },
        "boottime": {
            "semantic_identity_digest": sha256_bytes(b"native CLOCK_BOOTTIME semantics"),
            "observation_method": "clock_gettime-clock-boottime-v1",
            "clock_id": "CLOCK_BOOTTIME",
            "boot_epoch_binding_method": "linux-boot-id-v1",
            "unit": "nanosecond",
            "suspend_semantics": "includes_suspended_time",
        },
        "wall_to_monotonic_bridge": {
            "semantic_identity_digest": sha256_bytes(b"native clock bracket semantics"),
            "method": "realtime-boottime-bracket-v1",
        },
        "runner_watchdog": {
            "method": "std-instant-v1",
            "relation_to_governed_deadline": "auxiliary_non_equivalent",
        },
        "qualification_evidence": [
            values["cohort_manifest"]["qualification_records"][0],
        ],
        "nonclaims": [
            "UTC accuracy remains unqualified",
            "does not establish cross-host clock coherence",
            "runner watchdog is not the governed deadline",
        ],
    });
    seal_semantic_identity(&mut clock, "qualification_id").expect("clock identity");
    let clock = ValidatedRuntimeRecord::validate_value(clock).expect("clock qualifier");
    values.get_mut("cohort_manifest").expect("cohort manifest")["qualification_records"]
        .as_array_mut()
        .expect("qualification records")
        .extend([
            Value::from(profile.exact_reference()),
            Value::from(clock.exact_reference()),
        ]);
    values.insert(
        "native_profile_qualification".to_owned(),
        profile.record().as_value().clone(),
    );
    values.insert(
        "native_clock_qualification".to_owned(),
        clock.record().as_value().clone(),
    );
}

fn replace_external_references(
    values: &mut BTreeMap<String, Value>,
    pinned: &BTreeMap<RecordRef, Vec<u8>>,
) -> Vec<(RecordRef, Vec<u8>)> {
    let mut references = BTreeSet::new();
    for value in values.values() {
        collect_record_references(value, &mut references);
    }
    let mut replacements = BTreeMap::new();
    let mut exact = Vec::new();
    for reference in references {
        if RuntimeSchema::parse(reference.schema.as_str()).is_ok()
            || reference.schema.as_str() == PROVIDER_INTAKE_SCHEMA
        {
            continue;
        }
        if let Some(bytes) = pinned.get(&reference) {
            assert_eq!(sha256_bytes(bytes), reference.bytes_digest);
            exact.push((reference, bytes.clone()));
            continue;
        }
        let bytes = canonical_json_bytes(&json!({
            "schema": reference.schema,
            "fixture_source_record_id": reference.record_id,
        }))
        .expect("external bytes");
        let replacement = RecordRef {
            schema: reference.schema.clone(),
            record_id: semantic_digest(&json!({
                "schema": reference.schema,
                "fixture_source_record_id": reference.record_id,
            }))
            .expect("external identity"),
            bytes_digest: sha256_bytes(&bytes),
        };
        replacements.insert(reference, replacement.clone());
        exact.push((replacement, bytes));
    }
    for value in values.values_mut() {
        replace_record_references(value, &replacements);
    }
    exact
}

fn stabilize_runtime_references(
    values: &mut BTreeMap<String, Value>,
    mut prior: BTreeMap<String, RecordRef>,
) {
    for _ in 0..64 {
        for value in values.values_mut() {
            refresh_self_identity(value);
        }
        repair_invocation_authorization(values);
        repair_decision_request_digest(values);
        repair_administrative_authorizations(values);
        for value in values.values_mut() {
            refresh_self_identity(value);
        }
        let current = values
            .iter()
            .map(|(name, value)| {
                let schema =
                    RuntimeSchema::parse(value["schema"].as_str().expect("runtime schema"))
                        .expect("known schema");
                let record_id: Sha256Digest =
                    serde_json::from_value(value[schema.record_id_field()].clone())
                        .expect("record id");
                (
                    name.clone(),
                    RecordRef {
                        schema: Token::parse(schema.as_str()).expect("schema token"),
                        record_id,
                        bytes_digest: sha256_bytes(
                            &canonical_json_bytes(value).expect("record bytes"),
                        ),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let replacements = prior
            .iter()
            .filter_map(|(name, old)| {
                let new = &current[name];
                (old != new).then(|| (old.clone(), new.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut changed = false;
        for value in values.values_mut() {
            changed |= replace_record_references(value, &replacements);
        }
        prior = current;
        if !changed {
            for value in values.values_mut() {
                refresh_self_identity(value);
            }
            return;
        }
    }
    panic!("runtime fixture references did not stabilize");
}

#[allow(clippy::filter_map_bool_then)]
fn repair_invocation_authorization(values: &mut BTreeMap<String, Value>) {
    let requests = values
        .iter()
        .filter_map(|(name, value)| {
            (value["schema"] == RuntimeSchema::DiagnosticInvocationRequestV1.as_str())
                .then(|| (name.clone(), value.clone()))
        })
        .collect::<Vec<_>>();
    for (_name, request) in requests {
        let reference: RecordRef =
            serde_json::from_value(request["invocation_authorization"].clone())
                .expect("invocation authorization reference");
        let Some(authorization_name) = values.iter().find_map(|(name, value)| {
            (value["schema"] == RuntimeSchema::OperationAuthorizationV1.as_str()
                && value["authorization_id"] == reference.record_id.as_str())
            .then(|| name.clone())
        }) else {
            continue;
        };
        let authorization = values
            .get_mut(&authorization_name)
            .expect("invocation authorization");
        authorization["binding"] = json!({
            "request_preimage_digest": request["request_preimage_digest"],
            "node": request["target"]["node"],
            "subject": request["target"]["subject"],
            "vantage": request["target"]["vantage"],
            "profile": request["profile"],
            "activation_id": request["expected_binding"]["activation"]["record_id"],
            "activation_generation": request["expected_binding"]["activation_generation"],
            "role_manifest_id": request["expected_binding"]["role_manifest"]["record_id"],
            "role_generation": request["expected_binding"]["role_generation"],
            "cohort_manifest_id": request["expected_binding"]["cohort_manifest"]["record_id"],
            "cohort_generation": request["expected_binding"]["cohort_generation"],
            "witness_attachment_ids": request["expected_binding"]["witness_attachments"]
                .as_array()
                .expect("witness attachments")
                .iter()
                .map(|reference| reference["record_id"].clone())
                .collect::<Vec<_>>(),
            "purpose_digest": semantic_digest(&request["purpose"]).expect("purpose digest"),
            "time_bounds_digest":
                semantic_digest(&request["time_bounds"]).expect("time bounds digest"),
            "delivery_binding_digest":
                semantic_digest(&request["delivery"]).expect("delivery digest"),
        });
    }
}

fn repair_decision_request_digest(values: &mut BTreeMap<String, Value>) {
    let Some(request_digest) = values.values().find_map(|value| {
        (value["schema"] == RuntimeSchema::DiagnosticInvocationRequestV1.as_str())
            .then(|| value["request_digest"].clone())
    }) else {
        return;
    };
    for value in values.values_mut() {
        if value["schema"] == RuntimeSchema::InvocationDecisionV1.as_str() {
            value["request_digest"] = request_digest.clone();
        }
    }
}

#[allow(clippy::filter_map_bool_then)]
fn repair_administrative_authorizations(values: &mut BTreeMap<String, Value>) {
    let by_id = values
        .iter()
        .map(|(name, value)| {
            let schema = RuntimeSchema::parse(value["schema"].as_str().expect("runtime schema"))
                .expect("known schema");
            let record_id: Sha256Digest =
                serde_json::from_value(value[schema.record_id_field()].clone()).expect("record id");
            (record_id, name.clone())
        })
        .collect::<BTreeMap<_, _>>();
    let mut consumers = BTreeMap::<Sha256Digest, Vec<String>>::new();
    for (name, value) in values.iter() {
        let schema =
            RuntimeSchema::parse(value["schema"].as_str().expect("schema")).expect("schema");
        let Some(field) = administrative_authority_field(schema) else {
            continue;
        };
        let reference: RecordRef =
            serde_json::from_value(value[field].clone()).expect("authority reference");
        consumers
            .entry(reference.record_id)
            .or_default()
            .push(name.clone());
    }

    let authorizations = values
        .iter()
        .filter_map(|(name, value)| {
            (value["schema"] == RuntimeSchema::OperationAuthorizationV1.as_str()
                && value["scope"] == "administrative_lifecycle")
                .then(|| {
                    let record_id: Sha256Digest =
                        serde_json::from_value(value["authorization_id"].clone())
                            .expect("authorization identity");
                    (name.clone(), record_id)
                })
        })
        .collect::<Vec<_>>();
    for (authorization_name, authorization_id) in authorizations {
        let mut memo = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        let mut authorized_records = consumers
            .get(&authorization_id)
            .into_iter()
            .flatten()
            .map(|consumer_name| {
                let consumer = &values[consumer_name];
                let schema =
                    RuntimeSchema::parse(consumer["schema"].as_str().expect("consumer schema"))
                        .expect("consumer schema");
                let record_id: Sha256Digest =
                    serde_json::from_value(consumer[schema.record_id_field()].clone())
                        .expect("consumer identity");
                let preimage = administrative_neutral_digest(
                    values,
                    &by_id,
                    consumer_name,
                    &mut memo,
                    &mut visiting,
                );
                json!({
                    "schema": schema.as_str(),
                    "record_id": record_id,
                    "record_preimage_digest": preimage,
                })
            })
            .collect::<Vec<_>>();
        authorized_records.sort_by(|left, right| {
            let left_key = (
                left["schema"].as_str().expect("schema"),
                left["record_id"].as_str().expect("record id"),
            );
            let right_key = (
                right["schema"].as_str().expect("schema"),
                right["record_id"].as_str().expect("record id"),
            );
            left_key.cmp(&right_key)
        });
        let authorization = values.get_mut(&authorization_name).expect("authorization");
        authorization["binding"]["authorized_records"] = Value::Array(authorized_records);
        let mut snapshot = authorization["binding"]
            .as_object()
            .expect("binding")
            .clone();
        snapshot.remove("input_snapshot_digest");
        snapshot.insert("operation".to_owned(), authorization["operation"].clone());
        authorization["binding"]["input_snapshot_digest"] = Value::String(
            semantic_digest(&Value::Object(snapshot))
                .expect("authorization snapshot")
                .to_string(),
        );
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
    values: &BTreeMap<String, Value>,
    by_id: &BTreeMap<Sha256Digest, String>,
    name: &str,
    memo: &mut BTreeMap<String, Sha256Digest>,
    visiting: &mut BTreeSet<String>,
) -> Sha256Digest {
    if let Some(digest) = memo.get(name) {
        return digest.clone();
    }
    assert!(
        visiting.insert(name.to_owned()),
        "authority-neutral dependency cycle"
    );
    let record = &values[name];
    let schema = RuntimeSchema::parse(record["schema"].as_str().expect("schema")).expect("schema");
    let authority_field = administrative_authority_field(schema).expect("administrative consumer");
    let mut preimage = record
        .as_object()
        .expect("administrative consumer object")
        .clone();
    preimage.remove(authority_field);
    let preimage = neutralize_administrative_references(
        values,
        by_id,
        Value::Object(preimage),
        memo,
        visiting,
    );
    let digest = semantic_digest(&preimage).expect("authority-neutral digest");
    visiting.remove(name);
    memo.insert(name.to_owned(), digest.clone());
    digest
}

fn neutralize_administrative_references(
    values: &BTreeMap<String, Value>,
    by_id: &BTreeMap<Sha256Digest, String>,
    value: Value,
    memo: &mut BTreeMap<String, Sha256Digest>,
    visiting: &mut BTreeSet<String>,
) -> Value {
    match value {
        Value::Object(object)
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
        {
            let reference: RecordRef =
                serde_json::from_value(Value::Object(object.clone())).expect("record reference");
            if let Some(name) = by_id.get(&reference.record_id) {
                let target = &values[name];
                let schema =
                    RuntimeSchema::parse(target["schema"].as_str().expect("target schema"))
                        .expect("target schema");
                if administrative_authority_field(schema).is_some() {
                    let digest = administrative_neutral_digest(values, by_id, name, memo, visiting);
                    return json!({
                        "schema": schema.as_str(),
                        "record_id": reference.record_id,
                        "record_preimage_digest": digest,
                    });
                }
            }
            Value::Object(object)
        }
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, child)| {
                    (
                        key,
                        neutralize_administrative_references(values, by_id, child, memo, visiting),
                    )
                })
                .collect::<Map<_, _>>(),
        ),
        Value::Array(array) => Value::Array(
            array
                .into_iter()
                .map(|child| {
                    neutralize_administrative_references(values, by_id, child, memo, visiting)
                })
                .collect(),
        ),
        primitive => primitive,
    }
}

fn refresh_self_identity(value: &mut Value) {
    let schema =
        RuntimeSchema::parse(value["schema"].as_str().expect("schema")).expect("runtime schema");
    if schema == RuntimeSchema::DiagnosticInvocationRequestV1 {
        let mut preimage = value.clone();
        let preimage = preimage.as_object_mut().expect("request object");
        preimage.remove("request_digest");
        preimage.remove("request_preimage_digest");
        preimage.remove("invocation_authorization");
        value["request_preimage_digest"] = Value::String(
            semantic_digest(&Value::Object(preimage.clone()))
                .expect("request preimage")
                .to_string(),
        );
    } else if !matches!(
        schema,
        RuntimeSchema::NativeProfileQualificationV1
            | RuntimeSchema::NativeClockQualificationV1
            | RuntimeSchema::DeadlineEvaluationV1
    ) {
        return;
    }
    let object = value.as_object_mut().expect("runtime record object");
    object.remove(schema.record_id_field());
    let identity = semantic_digest(&Value::Object(object.clone())).expect("record identity");
    object.insert(
        schema.record_id_field().into(),
        Value::String(identity.to_string()),
    );
}

fn replace_record_references(
    value: &mut Value,
    replacements: &BTreeMap<RecordRef, RecordRef>,
) -> bool {
    match value {
        Value::Object(object)
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
        {
            let Ok(reference) = serde_json::from_value::<RecordRef>(Value::Object(object.clone()))
            else {
                return false;
            };
            if let Some(replacement) = replacements.get(&reference) {
                *value = serde_json::to_value(replacement).expect("replacement");
                true
            } else {
                false
            }
        }
        Value::Object(object) => object.values_mut().fold(false, |changed, child| {
            replace_record_references(child, replacements) || changed
        }),
        Value::Array(array) => array.iter_mut().fold(false, |changed, child| {
            replace_record_references(child, replacements) || changed
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn collect_record_references(value: &Value, references: &mut BTreeSet<RecordRef>) {
    match value {
        Value::Object(object)
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["schema", "record_id", "bytes_digest"]) =>
        {
            references.insert(serde_json::from_value(value.clone()).expect("record reference"));
        }
        Value::Object(object) => {
            for child in object.values() {
                collect_record_references(child, references);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_record_references(child, references);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn collect_test_carriers(
    value: &Value,
    identities: &mut Vec<IdentityRef>,
    references: &mut BTreeSet<RecordRef>,
) {
    match value {
        Value::Object(object) => {
            let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if keys == BTreeSet::from(["kind", "id", "version", "descriptor_digest"]) {
                identities.push(serde_json::from_value(value.clone()).expect("identity"));
            } else if keys == BTreeSet::from(["schema", "record_id", "bytes_digest"]) {
                let reference: RecordRef =
                    serde_json::from_value(value.clone()).expect("reference");
                if RuntimeSchema::parse(reference.schema.as_str()).is_err()
                    && reference.schema.as_str() != PROVIDER_INTAKE_SCHEMA
                {
                    references.insert(reference);
                }
            } else {
                for child in object.values() {
                    collect_test_carriers(child, identities, references);
                }
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_test_carriers(child, identities, references);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn transitive_runtime_closure(
    records: &BTreeMap<String, ValidatedRuntimeRecord>,
    roots: impl IntoIterator<Item = RecordRef>,
) -> BTreeMap<String, ValidatedRuntimeRecord> {
    let by_id = records
        .iter()
        .map(|(name, record)| (record.record_id().clone(), (name, record)))
        .collect::<BTreeMap<_, _>>();
    let mut pending = roots.into_iter().collect::<Vec<_>>();
    let mut selected = BTreeMap::new();
    while let Some(reference) = pending.pop() {
        if RuntimeSchema::parse(reference.schema.as_str()).is_err() {
            continue;
        }
        let (name, record) = by_id
            .get(&reference.record_id)
            .unwrap_or_else(|| panic!("runtime dependency {reference:?}"));
        if selected.contains_key(*name) {
            continue;
        }
        let mut nested = BTreeSet::new();
        collect_record_references(record.record().as_value(), &mut nested);
        if record.schema() == RuntimeSchema::OperationAuthorizationV1
            && record.record().as_value()["scope"] == "administrative_lifecycle"
        {
            for authorized in record.record().as_value()["binding"]["authorized_records"]
                .as_array()
                .expect("authorized records")
            {
                let record_id: Sha256Digest =
                    serde_json::from_value(authorized["record_id"].clone())
                        .expect("authorized record id");
                let (_, consumer) = by_id
                    .get(&record_id)
                    .unwrap_or_else(|| panic!("authorized consumer {record_id}"));
                assert_eq!(
                    consumer.schema().as_str(),
                    authorized["schema"].as_str().expect("authorized schema")
                );
                nested.insert(consumer.exact_reference());
            }
        }
        pending.extend(nested);
        selected.insert((*name).clone(), (*record).clone());
    }
    selected
}

#[allow(clippy::too_many_lines)]
/// Build one complete authenticated dependency closure for a downstream
/// qualification fixture.  The returned closure carries no runtime authority;
/// callers must still supply matching signed genesis custody through a named
/// production initialization or migration path.
#[must_use]
pub fn authenticated_runtime_dependencies(
    seed: u8,
    runtime_identities: Vec<IdentityRef>,
    external_inputs: Vec<(RecordRef, Vec<u8>)>,
    operation_authorizations: Vec<RecordRef>,
    invocation_authentication: Vec<RecordRef>,
) -> RuntimeDependencies {
    nq_host_role_dependency_custody::test_support::authenticated_runtime_fixture(
        seed,
        runtime_identities,
        external_inputs,
        operation_authorizations,
        invocation_authentication,
    )
}
