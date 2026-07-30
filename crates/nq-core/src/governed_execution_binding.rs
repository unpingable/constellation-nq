//! Core-owned construction of one exact production execution binding.
//!
//! This module closes the correspondence seam between a prepared governed
//! invocation, one canonical [`DiagnosticExecutionV2`], and the exact
//! provider-intake occurrence retained for that invocation. It derives every
//! topology value from the prepared graph and authenticated dependency
//! generation; no caller supplies a resolver or resolved identity.
//!
//! A successful construction establishes only that the named immutable
//! artifacts and identities correspond under
//! `nq.execution_identity_binding.v2`. It does not grant reliance,
//! authorization, recurrence, posture, delivery, or action authority.

use std::collections::BTreeSet;

use nq_host_role_contract::{
    IdentityKind, IdentityRef, RecordRef, RuntimeRecordSet, RuntimeSchema, ValidatedRuntimeRecord,
};
use nq_host_role_runtime::{
    ExternalDependencyAvailability, PreparedGovernedInvocation, RuntimeDependencies,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{DiagnosticExecutionError, DiagnosticExecutionV2, SemanticIdentityV1};

const PROVIDER_INTAKE_SCHEMA: &str = "nq.provider_intake.v1";
const PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA: &str = "nq.production_identity_descriptor.v1";
const REQUIRED_NONCLAIMS: [&str; 2] = [
    "does not modify nq.diagnostic_execution.v2 bytes",
    "does not establish reliance or authorization",
];

/// Failure to construct one exact production execution binding.
///
/// These failures are correspondence refusals. They do not alter the
/// diagnostic artifact and cannot be treated as an adverse subject result.
#[derive(Debug, Error)]
pub(crate) enum GovernedExecutionBindingError {
    /// The diagnostic artifact itself was not a valid canonical V2 artifact.
    #[error("diagnostic execution is not canonical V2: {0}")]
    Diagnostic(#[from] DiagnosticExecutionError),
    /// A runtime record failed its closed structural contract.
    #[error("execution binding violates the host-role contract: {0}")]
    Contract(#[from] nq_host_role_contract::ContractError),
    /// A typed field could not be decoded.
    #[error("execution binding field is malformed: {0}")]
    Json(#[from] serde_json::Error),
    /// A semantic digest or canonical preimage could not be computed.
    #[error("execution binding canonicalization failed: {0}")]
    Canonical(#[from] nq_protocol::CanonicalizationError),
    /// The exact prepared correspondence closure could not be established.
    #[error("execution binding correspondence refused: {0}")]
    Correspondence(String),
}

type Result<T> = std::result::Result<T, GovernedExecutionBindingError>;

/// Construct one exact `nq.execution_identity_binding.v2` carrier.
///
/// The prepared invocation is the sole source of topology, namespace,
/// enrollment, role, cohort, witness, and resolver identity. The diagnostic
/// contributes only its already-validated immutable identity, exact canonical
/// byte digest, and request-bound diagnostic semantics. `provider_intake` is
/// retained as one exact opaque occurrence; native provider correspondence is
/// independently checked by the NQ execution path that produced it.
///
/// # Errors
///
/// Refuses a malformed or noncanonical diagnostic, substituted prepared
/// reference, unresolved topology relation, ambiguous profile membership,
/// absent or ambiguous resolver, unavailable or substituted production
/// identity descriptor, diagnostic/topology mismatch, invalid provider-intake
/// reference, structurally invalid binding, or binding self-digest mismatch.
#[allow(clippy::too_many_lines)]
pub(crate) fn construct_governed_execution_binding_v2(
    prepared: &PreparedGovernedInvocation,
    diagnostic: &DiagnosticExecutionV2,
    provider_intake: &RecordRef,
) -> Result<ValidatedRuntimeRecord> {
    let diagnostic_bytes = diagnostic.canonical_bytes()?;
    let diagnostic_bytes_digest = sha256_bytes(&diagnostic_bytes);

    if provider_intake.schema.as_str() != PROVIDER_INTAKE_SCHEMA {
        return correspondence(format!(
            "provider attempt uses {}, not {PROVIDER_INTAKE_SCHEMA}",
            provider_intake.schema.as_str()
        ));
    }

    let records = prepared.prelaunch_records();
    let request = exact_record(
        records,
        prepared.outer_request(),
        RuntimeSchema::DiagnosticInvocationRequestV1,
        "outer request",
    )?;
    let decision = exact_record(
        records,
        prepared.invocation_decision(),
        RuntimeSchema::InvocationDecisionV1,
        "invocation decision",
    )?;
    let launch = exact_record(
        records,
        prepared.execution_launch(),
        RuntimeSchema::ExecutionLaunchV1,
        "execution launch",
    )?;

    let request_value = request.record().as_value();
    if string_field(request_value, "request_id", "outer request")? != prepared.request_id() {
        return correspondence(
            "prepared request occurrence differs from the exact outer request".to_owned(),
        );
    }
    if string_field(
        decision.record().as_value(),
        "decision",
        "invocation decision",
    )? != "accepted"
    {
        return correspondence("prepared invocation decision is not accepted".to_owned());
    }
    let launch_value = launch.record().as_value();
    if string_field(launch_value, "status", "execution launch")? != "launched" {
        return correspondence("prepared execution launch is not launched".to_owned());
    }
    require_reference_field(
        launch_value,
        "outer_request",
        &request.exact_reference(),
        "execution launch outer request",
    )?;
    require_reference_field(
        launch_value,
        "invocation_decision",
        &decision.exact_reference(),
        "execution launch invocation decision",
    )?;

    let activation_reference: RecordRef =
        decode_field(launch_value, "activation_snapshot", "execution launch")?;
    let activation = exact_record(
        records,
        &activation_reference,
        RuntimeSchema::RuntimeActivationV1,
        "runtime activation",
    )?;
    let activation_value = activation.record().as_value();

    let enrollment_reference: RecordRef =
        decode_field(activation_value, "enrollment", "runtime activation")?;
    let enrollment = exact_record(
        records,
        &enrollment_reference,
        RuntimeSchema::NodeEnrollmentV1,
        "node enrollment",
    )?;
    let role_reference: RecordRef =
        decode_field(activation_value, "role_manifest", "runtime activation")?;
    let role = exact_record(
        records,
        &role_reference,
        RuntimeSchema::RoleManifestV1,
        "role manifest",
    )?;
    let cohort_reference: RecordRef =
        decode_field(activation_value, "cohort_manifest", "runtime activation")?;
    let cohort = exact_record(
        records,
        &cohort_reference,
        RuntimeSchema::StaticProfileCohortManifestV1,
        "static profile cohort manifest",
    )?;

    let relations = object_field(activation_value, "relations", "runtime activation")?;
    require_exact_keys(
        relations,
        &[
            "node_subject",
            "subject_platform",
            "node_vantage",
            "node_role",
            "node_static_profile_cohort",
        ],
        "runtime activation relations",
    )?;
    let node_subject = exact_relation(records, relations, "node_subject")?;
    let subject_platform = exact_relation(records, relations, "subject_platform")?;
    let node_vantage = exact_relation(records, relations, "node_vantage")?;
    let node_role = exact_relation(records, relations, "node_role")?;
    let node_cohort = exact_relation(records, relations, "node_static_profile_cohort")?;

    let node: IdentityRef = decode_field(activation_value, "node", "runtime activation")?;
    require_kind(&node, IdentityKind::NqNode, "activation node")?;
    let subject = relation_identity(node_subject, "right", IdentityKind::Subject)?;
    let platform = relation_identity(subject_platform, "right", IdentityKind::Platform)?;
    let vantage = relation_identity(node_vantage, "right", IdentityKind::Vantage)?;
    let role_identity =
        decode_identity_field(role.record().as_value(), "role", IdentityKind::Role, "role")?;
    let cohort_identity = decode_identity_field(
        cohort.record().as_value(),
        "cohort",
        IdentityKind::StaticCohort,
        "cohort",
    )?;

    require_relation(
        node_subject,
        "node_subject",
        &node,
        &subject,
        "node-subject relation",
    )?;
    require_relation(
        subject_platform,
        "subject_platform",
        &subject,
        &platform,
        "subject-platform relation",
    )?;
    require_relation(
        node_vantage,
        "node_vantage",
        &node,
        &vantage,
        "node-vantage relation",
    )?;
    require_relation(
        node_role,
        "node_role",
        &node,
        &role_identity,
        "node-role relation",
    )?;
    require_relation(
        node_cohort,
        "node_static_profile_cohort",
        &node,
        &cohort_identity,
        "node-cohort relation",
    )?;

    require_identity_field(activation_value, "role", &role_identity, "activation role")?;
    require_identity_field(
        activation_value,
        "static_profile_cohort",
        &cohort_identity,
        "activation cohort",
    )?;
    require_identity_field(
        enrollment.record().as_value(),
        "node",
        &node,
        "enrollment node",
    )?;

    let selected_witnesses = array_field(
        launch_value,
        "selected_witness_attachments",
        "execution launch",
    )?;
    let [selected_witness] = selected_witnesses.as_slice() else {
        return correspondence(format!(
            "execution launch selects {} witness attachments rather than exactly one",
            selected_witnesses.len()
        ));
    };
    let witness_reference: RecordRef = serde_json::from_value(selected_witness.clone())?;
    let witness = exact_record(
        records,
        &witness_reference,
        RuntimeSchema::WitnessAttachmentV1,
        "selected witness attachment",
    )?;
    let activation_witnesses = array_field(
        activation_value,
        "witness_attachments",
        "runtime activation",
    )?;
    if activation_witnesses != selected_witnesses {
        return correspondence(
            "selected witness does not equal the activation's closed witness set".to_owned(),
        );
    }
    let witness_identity = decode_identity_field(
        witness.record().as_value(),
        "witness",
        IdentityKind::Witness,
        "witness attachment",
    )?;
    require_identity_field(witness.record().as_value(), "node", &node, "witness node")?;
    require_identity_field(
        witness.record().as_value(),
        "role",
        &role_identity,
        "witness role",
    )?;
    require_reference_field(
        witness.record().as_value(),
        "enrollment",
        &enrollment.exact_reference(),
        "witness enrollment",
    )?;
    require_reference_field(
        witness.record().as_value(),
        "role_manifest",
        &role.exact_reference(),
        "witness role manifest",
    )?;

    let requested_profile = decode_identity_field(
        request_value,
        "profile",
        IdentityKind::DiagnosticProfile,
        "outer request",
    )?;
    let profiles = array_path(
        cohort.record().as_value(),
        &["members", "profiles"],
        "cohort members profiles",
    )?;
    let matching_profile_indexes = profiles
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == &request_value["profile"]).then_some(index))
        .collect::<Vec<_>>();
    let [profile_index] = matching_profile_indexes.as_slice() else {
        return correspondence(format!(
            "requested profile occurs {} times in the exact cohort rather than once",
            matching_profile_indexes.len()
        ));
    };

    require_request_target(request_value, &node, &subject, &vantage)?;
    require_diagnostic_correspondence(
        prepared,
        diagnostic,
        &node,
        &subject,
        &vantage,
        &cohort_identity,
        &requested_profile,
    )?;

    let dependencies = prepared.dependencies();
    let (resolver, _resolver_descriptor) = unique_resolver(dependencies)?;
    let node_descriptor = exact_descriptor_reference(dependencies, &node, "node")?;
    let subject_descriptor = exact_descriptor_reference(dependencies, &subject, "subject")?;
    let platform_descriptor = exact_descriptor_reference(dependencies, &platform, "platform")?;
    let vantage_descriptor = exact_descriptor_reference(dependencies, &vantage, "vantage")?;
    let role_descriptor = exact_descriptor_reference(dependencies, &role_identity, "role")?;
    let cohort_descriptor =
        exact_descriptor_reference(dependencies, &cohort_identity, "static profile cohort")?;
    let witness_descriptor =
        exact_descriptor_reference(dependencies, &witness_identity, "witness")?;
    let profile_descriptor =
        exact_descriptor_reference(dependencies, &requested_profile, "diagnostic profile")?;

    let resolved_source = |source: &ValidatedRuntimeRecord,
                           pointer: String,
                           identity: &IdentityRef,
                           descriptor: &RecordRef| {
        json!({
            "identity": identity,
            "source_artifact": source.exact_reference(),
            "source_pointer": pointer,
            "descriptor": descriptor,
        })
    };

    let mut binding = json!({
        "schema": RuntimeSchema::ExecutionIdentityBindingV2.as_str(),
        "binding_id": sha256_bytes(b"nq execution identity binding v2 unsealed"),
        "diagnostic": {
            "schema": "nq.diagnostic_execution.v2",
            "artifact_id": diagnostic.artifact_id.as_digest(),
            "file_bytes_digest": diagnostic_bytes_digest,
            "request_id": diagnostic.request_id.as_str(),
        },
        "namespace": request_value["namespace"].clone(),
        "resolver": resolver,
        "outer_request": request.exact_reference(),
        "invocation_decision": decision.exact_reference(),
        "execution_launch": launch.exact_reference(),
        "enrollment": enrollment.exact_reference(),
        "activation": activation.exact_reference(),
        "source_relations": activation_value["relations"].clone(),
        "role_manifest": role.exact_reference(),
        "static_profile_cohort_manifest": cohort.exact_reference(),
        "witness_attachments": [witness.exact_reference()],
        "provider_attempts": [provider_intake],
        "resolved_references": {
            "node": resolved_source(
                activation,
                "/node".to_owned(),
                &node,
                &node_descriptor,
            ),
            "subject": resolved_source(
                node_subject,
                "/right".to_owned(),
                &subject,
                &subject_descriptor,
            ),
            "platform": resolved_source(
                subject_platform,
                "/right".to_owned(),
                &platform,
                &platform_descriptor,
            ),
            "vantage": resolved_source(
                node_vantage,
                "/right".to_owned(),
                &vantage,
                &vantage_descriptor,
            ),
            "role": resolved_source(
                role,
                "/role".to_owned(),
                &role_identity,
                &role_descriptor,
            ),
            "static_profile_cohort": resolved_source(
                cohort,
                "/cohort".to_owned(),
                &cohort_identity,
                &cohort_descriptor,
            ),
            "witness": resolved_source(
                witness,
                "/witness".to_owned(),
                &witness_identity,
                &witness_descriptor,
            ),
            "diagnostic_profile": resolved_source(
                cohort,
                format!("/members/profiles/{profile_index}"),
                &requested_profile,
                &profile_descriptor,
            ),
        },
        "binding_result": "resolved",
        "nonclaims": REQUIRED_NONCLAIMS,
    });

    let sealed_id = seal_binding_identity(&mut binding)?;
    let validated = ValidatedRuntimeRecord::validate_value(binding)?;
    let recomputed = recompute_binding_identity(validated.record().as_value())?;
    if validated.record_id() != &sealed_id || recomputed != sealed_id {
        return correspondence(
            "binding_id did not survive structural validation as the exact complete-preimage digest"
                .to_owned(),
        );
    }
    if validated.record().as_value()["nonclaims"] != json!(REQUIRED_NONCLAIMS) {
        return correspondence("required execution-binding nonclaims were altered".to_owned());
    }
    Ok(validated)
}

fn exact_record<'a>(
    records: &'a RuntimeRecordSet,
    reference: &RecordRef,
    expected_schema: RuntimeSchema,
    purpose: &str,
) -> Result<&'a ValidatedRuntimeRecord> {
    let record = records.get(&reference.record_id).ok_or_else(|| {
        GovernedExecutionBindingError::Correspondence(format!(
            "{purpose} {} is absent from the prepared graph",
            reference.record_id
        ))
    })?;
    if record.schema() != expected_schema || record.exact_reference() != *reference {
        return correspondence(format!(
            "{purpose} {} is schema- or byte-substituted",
            reference.record_id
        ));
    }
    Ok(record)
}

fn exact_relation<'a>(
    records: &'a RuntimeRecordSet,
    relations: &Map<String, Value>,
    name: &'static str,
) -> Result<&'a ValidatedRuntimeRecord> {
    let reference: RecordRef = serde_json::from_value(
        relations
            .get(name)
            .cloned()
            .ok_or_else(|| missing(format!("runtime activation lacks relation {name}")))?,
    )?;
    exact_record(records, &reference, RuntimeSchema::HostRoleRelationV1, name)
}

fn require_relation(
    relation: &ValidatedRuntimeRecord,
    expected_kind: &str,
    expected_left: &IdentityRef,
    expected_right: &IdentityRef,
    purpose: &str,
) -> Result<()> {
    let value = relation.record().as_value();
    let actual_kind = string_field(value, "relation_kind", purpose)?;
    let left: IdentityRef = decode_field(value, "left", purpose)?;
    let right: IdentityRef = decode_field(value, "right", purpose)?;
    if actual_kind != expected_kind || &left != expected_left || &right != expected_right {
        return correspondence(format!(
            "{purpose} does not preserve its exact kind and endpoint identities"
        ));
    }
    Ok(())
}

fn relation_identity(
    relation: &ValidatedRuntimeRecord,
    side: &'static str,
    kind: IdentityKind,
) -> Result<IdentityRef> {
    decode_identity_field(
        relation.record().as_value(),
        side,
        kind,
        "topology relation",
    )
}

fn require_request_target(
    request: &Value,
    node: &IdentityRef,
    subject: &IdentityRef,
    vantage: &IdentityRef,
) -> Result<()> {
    let target = object_field(request, "target", "outer request")?;
    for (field, expected) in [("node", node), ("subject", subject), ("vantage", vantage)] {
        let actual: IdentityRef = serde_json::from_value(
            target
                .get(field)
                .cloned()
                .ok_or_else(|| missing(format!("outer request target lacks {field}")))?,
        )?;
        if &actual != expected {
            return correspondence(format!(
                "outer request target {field} differs from the resolved topology"
            ));
        }
    }
    Ok(())
}

fn require_diagnostic_correspondence(
    prepared: &PreparedGovernedInvocation,
    diagnostic: &DiagnosticExecutionV2,
    node: &IdentityRef,
    subject: &IdentityRef,
    vantage: &IdentityRef,
    cohort: &IdentityRef,
    profile: &IdentityRef,
) -> Result<()> {
    let production = prepared.production_identity();
    if production.node() != node
        || production.subject() != subject
        || production.vantage() != vantage
        || production.cohort() != cohort
    {
        return correspondence(
            "prepared production identity differs from the exact activation closure".to_owned(),
        );
    }
    if diagnostic.request_id.as_str() != prepared.request_id()
        || diagnostic.producer.node_id != node.id.as_str()
        || diagnostic.subject.id != subject.id.as_str()
        || !semantic_identity_matches(&diagnostic.vantage, vantage)
        || !semantic_identity_matches(&diagnostic.producer.cohort, cohort)
        || !semantic_identity_matches(&diagnostic.profile, profile)
    {
        return correspondence(
            "diagnostic request, node, subject, vantage, cohort, or profile differs from the prepared invocation"
                .to_owned(),
        );
    }
    Ok(())
}

fn semantic_identity_matches(semantic: &SemanticIdentityV1, identity: &IdentityRef) -> bool {
    semantic.id == identity.id.as_str()
        && semantic.version == identity.version.as_str()
        && semantic.digest == identity.descriptor_digest
}

fn unique_resolver(dependencies: &RuntimeDependencies) -> Result<(IdentityRef, RecordRef)> {
    let resolvers = dependencies
        .catalog_snapshot()
        .identities
        .iter()
        .filter(|identity| identity.kind == IdentityKind::Resolver)
        .collect::<Vec<_>>();
    let [resolver] = resolvers.as_slice() else {
        return correspondence(format!(
            "authenticated dependency generation contains {} resolver identities rather than exactly one",
            resolvers.len()
        ));
    };
    let descriptor = exact_descriptor_reference(dependencies, resolver, "resolver")?;
    Ok(((*resolver).clone(), descriptor))
}

fn exact_descriptor_reference(
    dependencies: &RuntimeDependencies,
    identity: &IdentityRef,
    purpose: &str,
) -> Result<RecordRef> {
    let aliases = dependencies
        .catalog_snapshot()
        .identities
        .iter()
        .filter(|candidate| candidate.descriptor_digest == identity.descriptor_digest)
        .collect::<Vec<_>>();
    if aliases.as_slice() != [identity] {
        return correspondence(format!(
            "{purpose} descriptor digest resolves to {} catalog identities rather than one exact identity",
            aliases.len()
        ));
    }

    let sources = dependencies
        .external_dependency_snapshot()
        .dependencies
        .iter()
        .filter(|dependency| {
            dependency.reference.schema.as_str() == PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA
                && dependency.reference.bytes_digest == identity.descriptor_digest
        })
        .collect::<Vec<_>>();
    let [source] = sources.as_slice() else {
        return correspondence(format!(
            "{purpose} descriptor resolves to {} authenticated exact-byte sources rather than one",
            sources.len()
        ));
    };
    if !matches!(
        source.availability,
        ExternalDependencyAvailability::Online | ExternalDependencyAvailability::ArchivedRetrieved
    ) {
        return correspondence(format!(
            "{purpose} descriptor bytes are committed but unavailable"
        ));
    }
    let encoded = source.exact_bytes_hex.as_deref().ok_or_else(|| {
        missing(format!(
            "{purpose} descriptor is marked available without exact bytes"
        ))
    })?;
    let bytes = hex::decode(encoded).map_err(|error| {
        missing(format!(
            "{purpose} descriptor bytes are not canonical hexadecimal: {error}"
        ))
    })?;
    if hex::encode(&bytes) != encoded
        || sha256_bytes(&bytes) != source.reference.bytes_digest
        || source.reference.bytes_digest != identity.descriptor_digest
    {
        return correspondence(format!(
            "{purpose} descriptor exact bytes or digest were substituted"
        ));
    }
    let descriptor: Value = serde_json::from_slice(&bytes)?;
    if canonical_json_bytes(&descriptor)? != bytes
        || semantic_digest(&descriptor)? != source.reference.record_id
    {
        return correspondence(format!(
            "{purpose} descriptor record identity or canonical preimage was substituted"
        ));
    }
    let descriptor_object = descriptor.as_object().ok_or_else(|| {
        missing(format!(
            "{purpose} production identity descriptor is not an object"
        ))
    })?;
    require_exact_keys(
        descriptor_object,
        &["schema", "kind", "id", "version"],
        "production identity descriptor",
    )?;
    let expected_kind = serde_json::to_value(identity.kind)?;
    if descriptor_object["schema"] != PRODUCTION_IDENTITY_DESCRIPTOR_SCHEMA
        || descriptor_object["kind"] != expected_kind
        || descriptor_object["id"].as_str() != Some(identity.id.as_str())
        || descriptor_object["version"].as_str() != Some(identity.version.as_str())
    {
        return correspondence(format!(
            "{purpose} descriptor preimage does not describe the exact production identity"
        ));
    }
    Ok(source.reference.clone())
}

fn seal_binding_identity(binding: &mut Value) -> Result<Sha256Digest> {
    let object = binding
        .as_object_mut()
        .ok_or_else(|| missing("execution binding is not an object".to_owned()))?;
    object.remove("binding_id");
    let binding_id = semantic_digest(&Value::Object(object.clone()))?;
    object.insert(
        "binding_id".to_owned(),
        Value::String(binding_id.to_string()),
    );
    Ok(binding_id)
}

fn recompute_binding_identity(binding: &Value) -> Result<Sha256Digest> {
    let object = binding
        .as_object()
        .ok_or_else(|| missing("validated execution binding is not an object".to_owned()))?;
    let mut preimage = object.clone();
    preimage
        .remove("binding_id")
        .ok_or_else(|| missing("validated execution binding has no binding_id".to_owned()))?;
    Ok(semantic_digest(&Value::Object(preimage))?)
}

fn require_reference_field(
    value: &Value,
    field: &'static str,
    expected: &RecordRef,
    purpose: &str,
) -> Result<()> {
    let actual: RecordRef = decode_field(value, field, purpose)?;
    if &actual != expected {
        return correspondence(format!("{purpose} reference was substituted"));
    }
    Ok(())
}

fn require_identity_field(
    value: &Value,
    field: &'static str,
    expected: &IdentityRef,
    purpose: &str,
) -> Result<()> {
    let actual: IdentityRef = decode_field(value, field, purpose)?;
    if &actual != expected {
        return correspondence(format!("{purpose} identity was substituted"));
    }
    Ok(())
}

fn decode_identity_field(
    value: &Value,
    field: &'static str,
    expected_kind: IdentityKind,
    purpose: &str,
) -> Result<IdentityRef> {
    let identity: IdentityRef = decode_field(value, field, purpose)?;
    require_kind(&identity, expected_kind, purpose)?;
    Ok(identity)
}

fn require_kind(identity: &IdentityRef, expected: IdentityKind, purpose: &str) -> Result<()> {
    if identity.kind != expected {
        return correspondence(format!(
            "{purpose} has identity kind {:?}, not {expected:?}",
            identity.kind
        ));
    }
    Ok(())
}

fn decode_field<T: DeserializeOwned>(
    value: &Value,
    field: &'static str,
    purpose: &str,
) -> Result<T> {
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| missing(format!("{purpose} lacks {field}")))?,
    )
    .map_err(Into::into)
}

fn object_field<'a>(
    value: &'a Value,
    field: &'static str,
    purpose: &str,
) -> Result<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| missing(format!("{purpose} {field} is not an object")))
}

fn array_field<'a>(value: &'a Value, field: &'static str, purpose: &str) -> Result<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| missing(format!("{purpose} {field} is not an array")))
}

fn array_path<'a>(value: &'a Value, path: &[&str], purpose: &str) -> Result<&'a Vec<Value>> {
    let mut current = value;
    for component in path {
        current = current
            .get(*component)
            .ok_or_else(|| missing(format!("{purpose} lacks {component}")))?;
    }
    current
        .as_array()
        .ok_or_else(|| missing(format!("{purpose} is not an array")))
}

fn string_field<'a>(value: &'a Value, field: &'static str, purpose: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| missing(format!("{purpose} {field} is not a string")))
}

fn require_exact_keys(object: &Map<String, Value>, expected: &[&str], purpose: &str) -> Result<()> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return correspondence(format!(
            "{purpose} has keys {actual:?}, expected {expected:?}"
        ));
    }
    Ok(())
}

fn missing(message: String) -> GovernedExecutionBindingError {
    GovernedExecutionBindingError::Correspondence(message)
}

fn correspondence<T>(message: String) -> Result<T> {
    Err(GovernedExecutionBindingError::Correspondence(message))
}

// Integration qualification belongs with the engine call site because
// `PreparedGovernedInvocation` deliberately has no public constructor.
// Required caller-level cases are: exact successful construction; successful
// and refused diagnostic outcomes; substituted request/launch/activation;
// zero and duplicate resolver descriptors; zero and duplicate cohort-profile
// membership; unavailable descriptor bytes; provider-intake schema
// substitution; diagnostic/topology mismatch; and independent rejection of a
// post-construction binding-id mutation.
