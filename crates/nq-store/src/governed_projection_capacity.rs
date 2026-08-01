//! Pure, pre-effect capacity model for the governed V3 projection capsule.
//!
//! This module deliberately performs no Store, filesystem, provider, SQL, or
//! delivery effect.  It closes the production capsule's physical JSON shapes
//! over an immutable field manifest and a set of already-identified prelaunch
//! bound sources.  Observed post-effect values can fit or refuse; they can
//! never select or enlarge the symbolic candidate ceiling.

// CAP-H14 intentionally keeps this whole candidate evaluator test-only. Some
// candidate inspection helpers are retained for hostile audit even when a
// particular test does not call them directly; no product API can reach them.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{BoundedJsonDescriptor, Sha256Digest, canonical_json_bytes, semantic_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CanonicalDocument, CollectionInput, GovernedProjectionCapsule, GovernedProjectionCapsuleInput,
    GovernedProjectionCapsuleMode, StoreError, SubmissionDisposition,
    governed_projection_capsule::ProjectionCapsuleOutcomeBranchV1,
};

/// Closed identity of the V3 projection-capsule bound contract.
pub const V3_PROJECTION_CAPSULE_BOUND_MANIFEST_SCHEMA: &str =
    "nq.v3_projection_capsule_bound_manifest.v1";
const V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA: &str =
    "nq.v3_projection_capsule_bound_manifest.v2";
const V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_SCHEMA: &str =
    "nq.v3_projection_capsule_bound_qualification.v1";
const CAP_H14_QUALIFICATION_BASIS_IDENTITY: &str =
    "nq.v3_projection_capsule_bound_qualification_basis.v1";
const CAP_H14_QUALIFICATION_BUDGET_IDENTITY: &str =
    "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1";

/// Closed bounded-JSON source slots used by the production capsule.
///
/// Coverage detail deliberately occupies one semantic source slot but two
/// physical pointer families (report and observation coverage).  Together
/// these fifteen descriptors plus exact dependency custody close the sixteen
/// formerly generic values and seventeen physical pointer families.
pub const PROJECTION_CAPSULE_BOUNDED_JSON_SOURCE_SLOTS: [&str; 15] = [
    "provider_intake_context",
    "provider_intake_interpretation",
    "provider_intake_native_outcome",
    "run_execution_identity",
    "run_resource_outcome",
    "refusal_detail",
    "coverage_detail",
    "observation_subject",
    "observation_payload",
    "report_error_detail",
    "canonical_report",
    "validated_report",
    "next_checkpoint",
    "status_detail",
    "runtime_record_canonical_bytes",
];

/// Every physical generic-JSON pointer family in the production serializer.
pub const PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES: [(&str, &str); 17] = [
    ("/collection/intake/context", "provider_intake_context"),
    (
        "/collection/intake/interpretation",
        "provider_intake_interpretation",
    ),
    (
        "/collection/intake/native_outcome",
        "provider_intake_native_outcome",
    ),
    (
        "/collection/run/execution_identity",
        "run_execution_identity",
    ),
    ("/collection/run/resource_outcome", "run_resource_outcome"),
    (
        "/collection/submission/disposition/refusal/detail",
        "refusal_detail",
    ),
    (
        "/collection/submission/disposition/report/coverage/*/detail",
        "coverage_detail",
    ),
    (
        "/collection/submission/disposition/report/observations/*/coverage/*/detail",
        "coverage_detail",
    ),
    (
        "/collection/submission/disposition/report/observations/*/subject",
        "observation_subject",
    ),
    (
        "/collection/submission/disposition/report/observations/*/payload",
        "observation_payload",
    ),
    (
        "/collection/submission/disposition/report/errors/*/detail",
        "report_error_detail",
    ),
    (
        "/collection/submission/disposition/report/canonical_report",
        "canonical_report",
    ),
    (
        "/collection/submission/disposition/report/validated_report",
        "validated_report",
    ),
    (
        "/collection/submission/disposition/report/next_checkpoint",
        "next_checkpoint",
    ),
    ("/status/detail", "status_detail"),
    (
        "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody",
        "authenticated_runtime_dependency_custody",
    ),
    (
        "/diagnostic/local_origin/execution_binding/runtime_records/records/*/canonical_bytes",
        "runtime_record_canonical_bytes",
    ),
];

/// One immutable pointer/source row from the static capsule-bound manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleBoundFieldV1 {
    /// Canonical JSON pointer family. `*` denotes a bounded array element.
    pub pointer_family: String,
    /// Closed field classification.
    pub classification: String,
    /// Pre-effect descriptor slot or exact-byte source.
    pub bound_source: String,
}

const PROJECTION_CAPSULE_PRODUCTION_CARRIER_SOURCE: &str =
    "nq.governed_projection_capsule.production_carrier.v1";
const PROJECTION_CAPSULE_SCALAR_MAXIMA_SOURCE: &str =
    "nq.v3_projection_capsule_bound_manifest.scalar_maxima.v1";
const PROJECTION_CAPSULE_PHYSICAL_BRANCH_SOURCE: &str =
    "nq.v3_projection_capsule_bound_manifest.physical_branches.v1";

/// Derive the exhaustive named-field inventory from all three production
/// carrier shapes.
///
/// This is intentionally independent of the static manifest rows. Adding,
/// removing, renaming, or retyping a serialized production field changes this
/// derived inventory and therefore fails manifest validation until the
/// contract asset is explicitly revised. Array wildcards represent the same
/// named field in each bounded element; the synthetic element itself is not
/// counted as a field.
pub(crate) fn production_capsule_field_inventory_v1()
-> Result<Vec<ProjectionCapsuleBoundFieldV1>, StoreError> {
    let mut inventory = BTreeMap::<String, ProjectionCapsuleBoundFieldV1>::new();
    for branch in ProjectionCapsuleOutcomeBranchV1::ALL {
        let shape_witness =
            crate::governed_projection_capsule::projection_capsule_symbolic_shape_witness_v1(
                branch,
            )?;
        collect_production_capsule_fields(&shape_witness, "", &mut inventory)?;
    }
    Ok(inventory.into_values().collect())
}

fn collect_production_capsule_fields(
    value: &Value,
    pointer: &str,
    inventory: &mut BTreeMap<String, ProjectionCapsuleBoundFieldV1>,
) -> Result<(), StoreError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{}", escape_json_pointer_token(key));
                let (classification, bound_source) =
                    classify_production_capsule_field(&child_pointer, child)?;
                let row = ProjectionCapsuleBoundFieldV1 {
                    pointer_family: child_pointer.clone(),
                    classification: classification.into(),
                    bound_source: bound_source.into(),
                };
                if inventory
                    .insert(child_pointer.clone(), row.clone())
                    .is_some_and(|previous| previous != row)
                {
                    return Err(StoreError::Invariant(format!(
                        "production capsule field {child_pointer} changes classification across physical branches"
                    )));
                }
                if !is_closed_generic_pointer(&child_pointer) {
                    collect_production_capsule_fields(child, &child_pointer, inventory)?;
                }
            }
            Ok(())
        }
        Value::Array(array) => {
            if let Some(element) = array.first() {
                let wildcard = format!("{pointer}/*");
                collect_production_capsule_fields(element, &wildcard, inventory)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn classify_production_capsule_field(
    pointer: &str,
    value: &Value,
) -> Result<(&'static str, &'static str), StoreError> {
    if let Some((_, source)) = PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES
        .iter()
        .find(|(family, _)| pointer_matches_family(pointer, family))
    {
        return Ok(if *source == "authenticated_runtime_dependency_custody" {
            (
                "exact_pre_effect_bytes",
                "authenticated_runtime_dependency_custody",
            )
        } else {
            ("bounded_canonical_json", source)
        });
    }

    if is_closed_optional_pointer(pointer) {
        return Ok(("option_or_enum", optional_branch_source(pointer)));
    }
    if pointer == "/collection/intake/provider_sequence" {
        return Ok((
            "option_or_enum",
            "nq.core.ProviderIntakeRecordV1.provider_sequence_local_helper_absence.v1",
        ));
    }
    if pointer == "/diagnostic/local_origin/evaluation_id" {
        return Ok((
            "option_or_enum",
            "nq.core.GovernedDerivationCustodyClaim.evaluation_id_absence.v1",
        ));
    }
    if pointer == "/diagnostic/local_origin/execution_binding" {
        return Ok((
            "bounded_canonical_json",
            PROJECTION_CAPSULE_PRODUCTION_CARRIER_SOURCE,
        ));
    }
    if let Some(source) = semantic_enum_source(pointer) {
        return Ok(("option_or_enum", source));
    }
    if is_fixed_literal_pointer(pointer) {
        return Ok((
            "fixed_literal",
            PROJECTION_CAPSULE_PRODUCTION_CARRIER_SOURCE,
        ));
    }
    if is_timestamp_pointer(pointer) {
        return Ok(("scalar_maximum", PROJECTION_CAPSULE_SCALAR_MAXIMA_SOURCE));
    }
    if is_digest_pointer(pointer) {
        return Ok(("scalar_maximum", "nq.protocol.Sha256Digest.v1"));
    }
    if pointer.ends_with("/ordinal") {
        return Ok((
            "scalar_maximum",
            "nq.v3_projection_capsule_bound_manifest.cardinalities.v1",
        ));
    }
    if pointer == "/raw_capture/byte_length" {
        return Ok(("scalar_maximum", PROJECTION_CAPSULE_SCALAR_MAXIMA_SOURCE));
    }
    if pointer.ends_with("/report_sequence") || pointer.ends_with("/status_sequence") {
        return Ok(("scalar_maximum", PROJECTION_CAPSULE_SCALAR_MAXIMA_SOURCE));
    }

    match value {
        // The typed carrier fixes the object/key skeleton while descendant
        // inventory rows close every varying child value.  This is a
        // structural bounded-canonical-JSON classification backed by the
        // pinned production serializer and symbolic shape derivations, not one of
        // the descriptor-backed formerly-generic JSON slots.
        Value::Object(_) => Ok((
            "bounded_canonical_json",
            PROJECTION_CAPSULE_PRODUCTION_CARRIER_SOURCE,
        )),
        Value::Array(_) => collection_field_source(pointer)
            .map(|source| ("bounded_collection", source))
            .ok_or_else(|| {
                StoreError::Invariant(format!(
                    "production capsule contains an unclassified collection field at {pointer}"
                ))
            }),
        Value::String(_) => Ok(("scalar_maximum", PROJECTION_CAPSULE_SCALAR_MAXIMA_SOURCE)),
        Value::Null => Err(StoreError::Invariant(format!(
            "production capsule contains an unclassified null field at {pointer}"
        ))),
        Value::Bool(_) => Ok((
            "fixed_literal",
            PROJECTION_CAPSULE_PRODUCTION_CARRIER_SOURCE,
        )),
        Value::Number(_) => Err(StoreError::Invariant(format!(
            "production capsule contains an unclassified numeric field at {pointer}"
        ))),
    }
}

fn escape_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn is_closed_generic_pointer(pointer: &str) -> bool {
    PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES
        .iter()
        .any(|(family, _)| pointer_matches_family(pointer, family))
}

fn is_closed_optional_pointer(pointer: &str) -> bool {
    matches!(
        pointer,
        "/expected_semantic_digest"
            | "/publication/report_sequence"
            | "/collection/run/admission_id"
            | "/collection/submission"
            | "/collection/submission/disposition/refusal/profile_semantic_id"
            | "/collection/submission/disposition/report/next_checkpoint"
            | "/diagnostic/local_origin/execution_binding/runtime_records/expected_predecessor_checkpoint_id"
            | "/diagnostic/local_origin/execution_binding/runtime_records/expected_predecessor_ledger_root"
    )
}

fn optional_branch_source(pointer: &str) -> &'static str {
    if matches!(
        pointer,
        "/expected_semantic_digest" | "/publication/report_sequence" | "/collection/submission"
    ) {
        PROJECTION_CAPSULE_PHYSICAL_BRANCH_SOURCE
    } else {
        PROJECTION_CAPSULE_PRODUCTION_CARRIER_SOURCE
    }
}

fn semantic_enum_source(pointer: &str) -> Option<&'static str> {
    match pointer {
        "/mode"
        | "/collection/submission/disposition"
        | "/collection/submission/disposition/disposition" => {
            Some(PROJECTION_CAPSULE_PHYSICAL_BRANCH_SOURCE)
        }
        "/collection/run/acquisition_outcome" | "/collection/intake/native_outcome_kind" => {
            Some("nq.core.ProjectedAcquisitionOutcome.v1")
        }
        "/collection/intake/interpretation_kind" => {
            Some("nq.core.ProviderResponseInterpretationV1.kind.v1")
        }
        "/collection/submission/protocol_outcome" => {
            Some("nq.core.NativeGovernedSqlCommitPlan.protocol_outcome.v1")
        }
        "/collection/submission/disposition/report/report_status" => {
            Some("nq.core.semantic_report_status_projection.v1")
        }
        "/collection/submission/disposition/report/coverage/*/coverage_state"
        | "/collection/submission/disposition/report/observations/*/coverage/*/coverage_state" => {
            Some("nq.core.semantic_coverage_state_projection.v1")
        }
        "/collection/submission/disposition/refusal/source_kind" => {
            Some("nq.core.governed_refusal_projections.source_kind.v1")
        }
        "/collection/submission/disposition/refusal/boundary" => {
            Some("nq.core.governed_refusal_projections.boundary_union.v1")
        }
        "/collection/submission/disposition/refusal/code" => {
            Some("nq.core.governed_refusal_projections.code_union.v1")
        }
        "/status/state" => Some("nq.core.governed_execution_status_projection.state.v1"),
        "/status/code" => Some("nq.core.governed_execution_status_projection.code.v1"),
        _ => None,
    }
}

fn is_fixed_literal_pointer(pointer: &str) -> bool {
    matches!(
        pointer,
        "/schema" | "/diagnostic/contract_schema" | "/status/component_kind"
    )
}

fn collection_field_source(pointer: &str) -> Option<&'static str> {
    match pointer {
        "/collection/submission/disposition/report/observations" => {
            Some("nq.protocol.max_observations.v1")
        }
        "/collection/submission/disposition/report/coverage"
        | "/collection/submission/disposition/report/observations/*/coverage" => {
            Some("nq.protocol.max_coverage_entries.v1")
        }
        "/collection/submission/disposition/report/errors" => {
            Some("nq.protocol.max_report_errors.v1")
        }
        "/diagnostic/local_origin/execution_binding/provider_attempts" => {
            Some("nq.governed_projection.provider_attempt_cardinality.v1")
        }
        "/diagnostic/local_origin/execution_binding/runtime_records/records" => {
            Some("nq.governed_projection.runtime_record_cardinality.v1")
        }
        _ => None,
    }
}

fn is_digest_pointer(pointer: &str) -> bool {
    [
        "/capsule_id",
        "/reservation_record_id",
        "/expected_semantic_digest",
        "/raw_capture/bytes_digest",
        "/collection/intake/admission_context_digest",
        "/collection/intake/evaluator_artifact_digest",
        "/collection/intake/execution_identity_digest",
        "/collection/intake/profile_semantic_id",
        "/collection/intake/provider_artifact_digest",
        "/collection/intake/provider_config_digest",
        "/collection/intake/provider_semantic_id",
        "/diagnostic/artifact_id",
        "/diagnostic/canonical_bytes_digest",
        "/diagnostic/local_origin/execution_binding/runtime_records/expected_predecessor_ledger_root",
        "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody_digest",
        "/diagnostic/local_origin/execution_binding/runtime_records/dependency/dependency_generation_id",
        "/diagnostic/local_origin/execution_binding/runtime_records/dependency/trust_anchor_id",
        "/diagnostic/local_origin/execution_binding/runtime_records/records/*/canonical_bytes_digest",
    ]
    .contains(&pointer)
}

/// Fixed scalar and collection maxima carried by the static manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleScalarMaximaV1 {
    /// Maximum UTF-8 bytes in a non-generic, non-literal string.
    pub non_generic_string_utf8_bytes: u64,
    /// Maximum bytes in an admitted RFC 3339 timestamp.
    pub rfc3339_timestamp_utf8_bytes: u64,
    /// Maximum exact-I-JSON positive publication sequence.
    pub positive_publication_sequence: u64,
    /// Canonical width of the maximum publication sequence.
    pub positive_publication_sequence_decimal_width: u8,
    /// Maximum raw capture length, including the bounded overflow sentinel.
    pub raw_byte_length: u64,
    /// Canonical width of the maximum raw byte length.
    pub raw_byte_length_decimal_width: u8,
    /// Exact `sha256:` string width.
    pub sha256_string_utf8_bytes: u8,
    /// Widest signed exact-I-JSON integer representation.
    pub ijson_integer_decimal_width: u8,
    /// Widest ordinal representation admitted by the product cardinalities.
    pub ordinal_decimal_width: u8,
}

/// One immutable sourced collection cardinality.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleCardinalityV1 {
    /// Closed maximum (and exact value for product-fixed singleton groups).
    pub maximum: u32,
    /// Contract identity from which the maximum is selected.
    pub source_identity: String,
}

/// Every bounded collection used by the physical serializer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleCardinalitiesV1 {
    /// Maximum observations.
    pub observations: ProjectionCapsuleCardinalityV1,
    /// Maximum report and nested coverage entries in aggregate.
    pub total_coverage_entries: ProjectionCapsuleCardinalityV1,
    /// Maximum report errors.
    pub report_errors: ProjectionCapsuleCardinalityV1,
    /// Exact provider-attempt bindings.
    pub provider_attempt_bindings: ProjectionCapsuleCardinalityV1,
    /// Exact terminal runtime records.
    pub runtime_records: ProjectionCapsuleCardinalityV1,
}

/// Static declaration of one bounded-JSON descriptor source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleBoundedJsonDeclarationV1 {
    /// Closed descriptor slot.
    pub descriptor_key: String,
    /// Exact source identity expected in the pre-effect source set.
    pub source_identity: String,
    /// Provider/profile/policy source class.
    pub source_class: String,
    /// Exact JSON pointer selecting the descriptor from the source record.
    pub descriptor_pointer: String,
    /// Closed source-record schema where the source family fixes one.
    pub source_record_schema: Option<String>,
    /// Required descriptor schema.
    pub required_descriptor_type_identity: String,
}

/// Exhaustive semantic variants nested inside the three physical branches.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleSemanticVariantFamilyV1 {
    /// Closed family identity.
    pub variant_family: String,
    /// Native Rust/protocol contract identity.
    pub source_identity: String,
    /// Repository-relative native source path.
    pub source_path: String,
    /// Digest of the exact native source file.
    pub source_sha256: Sha256Digest,
    /// Whether variants select the outer capsule branch or occur only inside
    /// bounded nested runtime-record bytes.
    pub representation_location: String,
    /// Declared cardinality, checked against the exhaustive variant list.
    pub variant_count: u32,
    /// Exhaustive serialized variants.
    pub variants: Vec<String>,
}

/// Native semantic variants that cannot inhabit the projection capsule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleSemanticExclusionV1 {
    /// Native semantic family.
    pub source_identity: String,
    /// Repository-relative native source path.
    pub source_path: String,
    /// Digest of the exact native source file.
    pub source_sha256: Sha256Digest,
    /// Exhaustive excluded variants.
    pub excluded_variants: Vec<String>,
    /// Exact representation reason.
    pub reason: String,
}

/// Exact governed producer that makes one semantic exclusion true.
///
/// These are source-backed reachability facts, not an assertion that the
/// excluded variant is smaller or uninteresting. If a producer stops
/// enforcing one of these facts, the variant must move into the bounded
/// semantic census before this candidate can remain inspectable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProjectionCapsuleSemanticExclusionEnforcementV1 {
    source_identity: &'static str,
    producer_source_path: &'static str,
    production_constructor: &'static str,
}

const PROJECTION_CAPSULE_SEMANTIC_EXCLUSION_ENFORCEMENT:
    [ProjectionCapsuleSemanticExclusionEnforcementV1; 9] = [
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.AdmissionRefusalBoundary.v1",
        producer_source_path: "crates/nq-core/src/engine.rs",
        production_constructor: "NativeGovernedSqlCommitPlan::projection_capsule_input(postlaunch-only)",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.AdmissionRefusalCode.v1",
        producer_source_path: "crates/nq-core/src/engine.rs",
        production_constructor: "NativeGovernedSqlCommitPlan::projection_capsule_input(postlaunch-only)",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.AdmissionRefusalDetails.v1",
        producer_source_path: "crates/nq-core/src/engine.rs",
        production_constructor: "NativeGovernedSqlCommitPlan::projection_capsule_input(postlaunch-only)",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.CollectionResult.admitted.evaluations.v1",
        producer_source_path: "crates/nq-core/src/engine.rs",
        production_constructor: "prepare_native_governed_sql_commit::CollectionOutcome::admitted(Vec::new())",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.CollectionResult.v1",
        producer_source_path: "crates/nq-core/src/engine.rs",
        production_constructor: "governed_execution_status_event(run_id-required)",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.GovernedDerivationCustodyClaim.evaluation_id_absence.v1",
        producer_source_path: "crates/nq-core/src/governed_custody_projection.rs",
        production_constructor: "construct_governed_custody_projection_v2(evaluation_id=None)",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.GovernedExecutionRefusalCode.v1",
        producer_source_path: "crates/nq-core/src/engine.rs",
        production_constructor: "terminalize_native_pre_effect_refusal(no SQL plan)",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.ProviderIntakeRecordV1.provider_sequence_local_helper_absence.v1",
        producer_source_path: "crates/nq-core/src/provider_intake.rs",
        production_constructor: "ProviderIntakeV1::from_capture(provider_sequence=None)",
    },
    ProjectionCapsuleSemanticExclusionEnforcementV1 {
        source_identity: "nq.core.governed_execution_status_projection.code.v1",
        producer_source_path: "crates/nq-core/src/engine.rs",
        production_constructor: "governed_execution_status_event(run_id-required)",
    },
];

/// One descriptor-governed semantic surface whose vocabulary is intentionally
/// open rather than a closed NQ enum family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleDescriptorGovernedOpenSemanticV1 {
    /// Descriptor slot that bounds the containing canonical JSON.
    pub descriptor_key: String,
    /// Native type or semantic source responsible for this open vocabulary.
    pub source_identity: String,
    /// Repository-relative native source path.
    pub source_path: String,
    /// Digest of the exact native source file.
    pub source_sha256: Sha256Digest,
    /// Exact pointer within the descriptor-bound value.
    pub json_pointer: String,
    /// Why this semantic surface is not represented as a closed variant set.
    pub reason: String,
}

/// Static physical branch declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsulePhysicalBranchV1 {
    /// Branch identity.
    pub branch: ProjectionCapsuleOutcomeBranchV1,
    /// Capsule mode.
    pub mode: String,
    /// Submission shape.
    pub submission: String,
    /// Expected semantic-digest presence.
    pub expected_semantic_digest: String,
    /// Report-sequence presence.
    pub report_sequence: String,
}

/// Static symbolic production-shape derivation declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleSymbolicShapeDerivationV1 {
    /// Closed branch.
    pub branch: ProjectionCapsuleOutcomeBranchV1,
    /// Exact symbolic shape-evaluator identity.
    pub shape_evaluator_identity: String,
}

/// Ratified method for closing infeasibly large serializer shapes without
/// claiming that their material maxima were allocated or serialized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleSymbolicShapeMethodV1 {
    /// Source of the closed object/key/branch structure.
    pub carrier_shape_source: String,
    /// Exact substitution operation applied to each bounded field family.
    pub substitution: String,
    /// Independent arithmetic required to agree with the traversal.
    pub cross_check: String,
    /// Explicit materialization claim, necessarily `none` in v1.
    pub materialization_claim: String,
}

/// One explicit qualification gate not earned by this candidate contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleQualificationGapV1 {
    /// Gate identity.
    pub gate: String,
    /// Closed gap status.
    pub status: String,
    /// Evidence the ratified gate requires.
    pub required_evidence: String,
    /// Evidence actually present in this candidate.
    pub current_evidence: String,
    /// Load-bearing consequence of the gap.
    pub consequence: String,
}

/// Immutable mechanically closed contract for the V3 capsule calculation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V3ProjectionCapsuleBoundManifestV1 {
    schema: String,
    manifest_identity: String,
    manifest_version: String,
    capsule_schema: String,
    capsule_implementation_source_path: String,
    capsule_implementation_source_sha256: Sha256Digest,
    canonical_serializer_identity: String,
    canonicalization_identity: String,
    generic_field_count: u32,
    generic_pointer_family_count: u32,
    capsule_field_count: u32,
    physical_branches: Vec<ProjectionCapsulePhysicalBranchV1>,
    semantic_outcome_variants: Vec<ProjectionCapsuleSemanticVariantFamilyV1>,
    semantic_exclusions: Vec<ProjectionCapsuleSemanticExclusionV1>,
    descriptor_governed_open_semantics: Vec<ProjectionCapsuleDescriptorGovernedOpenSemanticV1>,
    scalar_maxima: ProjectionCapsuleScalarMaximaV1,
    cardinalities: ProjectionCapsuleCardinalitiesV1,
    bounded_json_sources: Vec<ProjectionCapsuleBoundedJsonDeclarationV1>,
    generic_pointer_bounds: Vec<ProjectionCapsuleBoundFieldV1>,
    capsule_field_inventory: Vec<ProjectionCapsuleBoundFieldV1>,
    symbolic_shape_method: ProjectionCapsuleSymbolicShapeMethodV1,
    symbolic_shape_derivations: Vec<ProjectionCapsuleSymbolicShapeDerivationV1>,
    qualification_gaps: Vec<ProjectionCapsuleQualificationGapV1>,
    bound_evaluator_identity: String,
    nonclaims: Vec<String>,
}

impl V3ProjectionCapsuleBoundManifestV1 {
    /// Parse exact canonical candidate bytes and inspect their content closure.
    ///
    /// This verifies content closure only. The caller must obtain `bytes`
    /// through the host-role contract crate's content-addressed inspected
    /// accessor; arbitrary bytes do not acquire contract authority here.
    fn from_inspected_candidate_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| StoreError::Invariant(format!("capsule-bound manifest: {error}")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    #[allow(clippy::too_many_lines)] // One closed immutable manifest audit.
    fn validate(&self) -> Result<(), StoreError> {
        if self.schema != V3_PROJECTION_CAPSULE_BOUND_MANIFEST_SCHEMA
            || self.manifest_identity != V3_PROJECTION_CAPSULE_BOUND_MANIFEST_SCHEMA
            || self.manifest_version != "1"
            || self.capsule_schema != crate::GOVERNED_PROJECTION_CAPSULE_SCHEMA
            || self.capsule_implementation_source_path
                != "crates/nq-store/src/governed_projection_capsule.rs"
            || self.capsule_implementation_source_sha256
                != nq_protocol::sha256_bytes(include_bytes!("governed_projection_capsule.rs"))
            || self.canonical_serializer_identity.is_empty()
            || self.canonicalization_identity.is_empty()
            || self.generic_field_count != 16
            || self.generic_pointer_family_count != 17
            || self.bound_evaluator_identity.is_empty()
            || self
                .physical_branches
                .iter()
                .map(|branch| branch.branch)
                .collect::<Vec<_>>()
                != ProjectionCapsuleOutcomeBranchV1::ALL
            || self.scalar_maxima.non_generic_string_utf8_bytes != 256
            || self.scalar_maxima.rfc3339_timestamp_utf8_bytes != 35
            || self.scalar_maxima.positive_publication_sequence != 9_007_199_254_740_991
            || self
                .scalar_maxima
                .positive_publication_sequence_decimal_width
                != 16
            || self.scalar_maxima.raw_byte_length
                != u64::try_from(nq_protocol::MAX_RESPONSE_FRAME_BYTES)
                    .map_err(|_| StoreError::Invariant("protocol raw maximum overflowed".into()))?
                    .checked_add(1)
                    .ok_or_else(|| {
                        StoreError::Invariant("protocol raw maximum overflowed".into())
                    })?
            || self.scalar_maxima.raw_byte_length_decimal_width != 8
            || self.scalar_maxima.sha256_string_utf8_bytes != 71
            || self.scalar_maxima.ijson_integer_decimal_width != 17
            || self.scalar_maxima.ordinal_decimal_width != 5
            || self.cardinalities.observations.maximum
                != u32::try_from(nq_protocol::MAX_OBSERVATIONS).map_err(|_| {
                    StoreError::Invariant("protocol observation maximum overflowed".into())
                })?
            || self.cardinalities.total_coverage_entries.maximum
                != u32::try_from(nq_protocol::MAX_COVERAGE_ENTRIES).map_err(|_| {
                    StoreError::Invariant("protocol coverage maximum overflowed".into())
                })?
            || self.cardinalities.report_errors.maximum
                != u32::try_from(nq_protocol::MAX_REPORT_ERRORS).map_err(|_| {
                    StoreError::Invariant("protocol error maximum overflowed".into())
                })?
            || self.cardinalities.provider_attempt_bindings.maximum != 1
            || self.cardinalities.runtime_records.maximum != 2
            || self.cardinalities.observations.source_identity != "nq.protocol.max_observations.v1"
            || self.cardinalities.total_coverage_entries.source_identity
                != "nq.protocol.max_coverage_entries.v1"
            || self.cardinalities.report_errors.source_identity
                != "nq.protocol.max_report_errors.v1"
            || self.cardinalities.provider_attempt_bindings.source_identity
                != "nq.governed_projection.provider_attempt_cardinality.v1"
            || self.cardinalities.runtime_records.source_identity
                != "nq.governed_projection.runtime_record_cardinality.v1"
            || self.symbolic_shape_method.carrier_shape_source
                != "production typed branch serializer shapes"
            || self.symbolic_shape_method.substitution
                != "exact symbolic substitution of committed maxima"
            || self.symbolic_shape_method.cross_check
                != "independent hand-derived JCS object and array arithmetic"
            || self.symbolic_shape_method.materialization_claim != "none"
        {
            return Err(StoreError::Invariant(
                "capsule-bound manifest scalar, branch, identity, or cardinality closure differs"
                    .into(),
            ));
        }
        if self.qualification_gaps
            != [ProjectionCapsuleQualificationGapV1 {
                gate: "CAP-H14".into(),
                status: "blocked".into(),
                required_evidence:
                    "maximal exact production values for every closed branch serialized by the production canonical serializer"
                        .into(),
                current_evidence:
                    "symbolic production-shape substitution cross-checked by independent JCS arithmetic"
                        .into(),
                consequence:
                    "this candidate manifest does not qualify the V3 capsule bound or satisfy the Campaign 3B stopping rule"
                        .into(),
            }]
        {
            return Err(StoreError::Invariant(
                "capsule-bound candidate qualification-gap declaration differs".into(),
            ));
        }

        let expected = PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES
            .into_iter()
            .map(|(pointer, source)| (pointer.to_owned(), source.to_owned()))
            .collect::<BTreeSet<_>>();
        let actual = self
            .generic_pointer_bounds
            .iter()
            .map(|row| (row.pointer_family.clone(), row.bound_source.clone()))
            .collect::<BTreeSet<_>>();
        if actual.len() != self.generic_pointer_bounds.len() || actual != expected {
            return Err(StoreError::Invariant(
                "capsule-bound manifest generic pointer inventory is missing, duplicated, or substituted"
                    .into(),
            ));
        }
        if self.generic_pointer_bounds.iter().any(|row| {
            if row.pointer_family
                == "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody"
            {
                row.classification != "exact_pre_effect_bytes"
                    || row.bound_source != "authenticated_runtime_dependency_custody"
            } else {
                row.classification != "bounded_canonical_json"
            }
        }) {
            return Err(StoreError::Invariant(
                "capsule-bound manifest field classification differs".into(),
            ));
        }
        let expected_inventory = production_capsule_field_inventory_v1()?;
        let expected_inventory_count = u32::try_from(expected_inventory.len()).map_err(|_| {
            StoreError::Invariant("production capsule field inventory count overflowed".into())
        })?;
        if self.capsule_field_count != expected_inventory_count
            || self.capsule_field_inventory != expected_inventory
        {
            let missing = expected_inventory
                .iter()
                .filter(|expected| {
                    !self
                        .capsule_field_inventory
                        .iter()
                        .any(|actual| actual.pointer_family == expected.pointer_family)
                })
                .map(|row| {
                    format!(
                        "{}={}/{}",
                        row.pointer_family, row.classification, row.bound_source
                    )
                })
                .collect::<Vec<_>>();
            let extra = self
                .capsule_field_inventory
                .iter()
                .filter(|actual| {
                    !expected_inventory
                        .iter()
                        .any(|expected| expected.pointer_family == actual.pointer_family)
                })
                .map(|row| {
                    format!(
                        "{}={}/{}",
                        row.pointer_family, row.classification, row.bound_source
                    )
                })
                .collect::<Vec<_>>();
            let differing = expected_inventory
                .iter()
                .filter_map(|expected| {
                    self.capsule_field_inventory
                        .iter()
                        .find(|actual| actual.pointer_family == expected.pointer_family)
                        .filter(|actual| *actual != expected)
                        .map(|actual| {
                            format!(
                                "{}: expected={}/{} actual={}/{}",
                                expected.pointer_family,
                                expected.classification,
                                expected.bound_source,
                                actual.classification,
                                actual.bound_source
                            )
                        })
                })
                .collect::<Vec<_>>();
            let order_differs = self
                .capsule_field_inventory
                .iter()
                .map(|row| row.pointer_family.as_str())
                .ne(expected_inventory
                    .iter()
                    .map(|row| row.pointer_family.as_str()));
            return Err(StoreError::Invariant(format!(
                "capsule-bound manifest exhaustive field inventory differs from the {expected_inventory_count}-field production serializer: missing={missing:?}; extra={extra:?}; differing={differing:?}; order_differs={order_differs}"
            )));
        }
        let expected_slots = PROJECTION_CAPSULE_BOUNDED_JSON_SOURCE_SLOTS
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual_slots = self
            .bounded_json_sources
            .iter()
            .map(|source| source.descriptor_key.as_str())
            .collect::<BTreeSet<_>>();
        if actual_slots.len() != self.bounded_json_sources.len()
            || actual_slots != expected_slots
            || self.bounded_json_sources.iter().any(|source| {
                source.source_identity.is_empty()
                    || (!source.descriptor_pointer.is_empty()
                        && !source.descriptor_pointer.starts_with('/'))
                    || source
                        .source_record_schema
                        .as_ref()
                        .is_some_and(String::is_empty)
                    || !matches!(
                        source.source_class.as_str(),
                        "provider_maximum"
                            | "profile_maximum"
                            | "policy_maximum"
                            | "closed_runtime_schema_maximum"
                    )
                    || source.required_descriptor_type_identity
                        != "nq.protocol.BoundedJsonDescriptor.v1"
            })
        {
            return Err(StoreError::Invariant(
                "capsule-bound manifest descriptor-source closure differs".into(),
            ));
        }
        let mut seen_families = BTreeSet::new();
        if self.semantic_outcome_variants.is_empty()
            || self.semantic_outcome_variants.iter().any(|family| {
                !seen_families.insert(family.variant_family.as_str())
                    || family.source_identity.is_empty()
                    || !matches!(
                        family.representation_location.as_str(),
                        "capsule_branch_selector" | "nested_runtime_record_bytes"
                    )
                    || usize::try_from(family.variant_count).ok() != Some(family.variants.len())
                    || family.variants.is_empty()
                    || family.variants.iter().any(String::is_empty)
                    || family.variants.iter().collect::<BTreeSet<_>>().len()
                        != family.variants.len()
                    || semantic_source_digest(&family.source_path).as_ref()
                        != Some(&family.source_sha256)
            })
        {
            return Err(StoreError::Invariant(
                "capsule-bound manifest semantic subvariant inventory differs".into(),
            ));
        }
        let mut seen_exclusions = BTreeSet::new();
        if self.semantic_exclusions.is_empty()
            || self.semantic_exclusions.iter().any(|exclusion| {
                !seen_exclusions.insert((
                    exclusion.source_identity.as_str(),
                    exclusion.excluded_variants.as_slice(),
                )) || exclusion.source_identity.is_empty()
                    || exclusion.excluded_variants.is_empty()
                    || exclusion.excluded_variants.iter().any(String::is_empty)
                    || exclusion
                        .excluded_variants
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != exclusion.excluded_variants.len()
                    || exclusion.reason.is_empty()
                    || semantic_source_digest(&exclusion.source_path).as_ref()
                        != Some(&exclusion.source_sha256)
            })
        {
            return Err(StoreError::Invariant(
                "capsule-bound manifest semantic exclusions differ".into(),
            ));
        }
        let expected_exclusion_enforcement = PROJECTION_CAPSULE_SEMANTIC_EXCLUSION_ENFORCEMENT
            .iter()
            .map(|enforcement| {
                (
                    enforcement.source_identity,
                    enforcement.producer_source_path,
                )
            })
            .collect::<BTreeSet<_>>();
        let actual_exclusion_enforcement = self
            .semantic_exclusions
            .iter()
            .map(|exclusion| {
                (
                    exclusion.source_identity.as_str(),
                    exclusion.source_path.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        if expected_exclusion_enforcement.len()
            != PROJECTION_CAPSULE_SEMANTIC_EXCLUSION_ENFORCEMENT.len()
            || actual_exclusion_enforcement != expected_exclusion_enforcement
            || PROJECTION_CAPSULE_SEMANTIC_EXCLUSION_ENFORCEMENT
                .iter()
                .any(|enforcement| enforcement.production_constructor.is_empty())
        {
            return Err(StoreError::Invariant(
                "capsule-bound semantic exclusion lacks an exact governed producer".into(),
            ));
        }
        let descriptor_slots = self
            .bounded_json_sources
            .iter()
            .map(|source| source.descriptor_key.as_str())
            .collect::<BTreeSet<_>>();
        let mut seen_open_semantics = BTreeSet::new();
        let open_semantic_slots = self
            .descriptor_governed_open_semantics
            .iter()
            .map(|surface| surface.descriptor_key.as_str())
            .collect::<BTreeSet<_>>();
        if self.descriptor_governed_open_semantics.is_empty()
            || open_semantic_slots != descriptor_slots
            || self
                .descriptor_governed_open_semantics
                .iter()
                .any(|surface| {
                    !seen_open_semantics.insert((
                        surface.descriptor_key.as_str(),
                        surface.source_identity.as_str(),
                        surface.json_pointer.as_str(),
                    ))
                        || !descriptor_slots.contains(surface.descriptor_key.as_str())
                        || surface.source_identity.is_empty()
                        || (!surface.json_pointer.is_empty()
                            && !surface.json_pointer.starts_with('/'))
                        || !matches!(
                            surface.reason.as_str(),
                            "application- or profile-controlled JSON vocabulary is bounded structurally and bytewise by the exact pre-effect descriptor; that bound does not establish semantic validity, continuity, standing, or authorization, and the vocabulary is not a closed NQ semantic family"
                                | "production identity, topology, or runtime token is bounded structurally and bytewise by the exact pre-effect descriptor; that bound does not establish semantic validity, continuity, standing, or authorization, and the token is not a closed NQ semantic family"
                        )
                        || semantic_source_digest(&surface.source_path).as_ref()
                            != Some(&surface.source_sha256)
                })
        {
            return Err(StoreError::Invariant(
                "capsule-bound manifest descriptor-governed open-semantic inventory differs"
                    .into(),
            ));
        }
        if self
            .physical_branches
            .iter()
            .zip([
                ("admitted", "required", "required"),
                ("absent", "absent", "absent"),
                ("rejected", "absent", "absent"),
            ])
            .any(|(branch, expected)| {
                branch.mode
                    != if branch.branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
                        "admitted"
                    } else {
                        "non_success"
                    }
                    || (
                        branch.submission.as_str(),
                        branch.expected_semantic_digest.as_str(),
                        branch.report_sequence.as_str(),
                    ) != expected
            })
            || self
                .symbolic_shape_derivations
                .iter()
                .map(|derivation| derivation.branch)
                .collect::<Vec<_>>()
                != ProjectionCapsuleOutcomeBranchV1::ALL
            || self
                .symbolic_shape_derivations
                .iter()
                .any(|derivation| derivation.shape_evaluator_identity.is_empty())
        {
            return Err(StoreError::Invariant(
                "capsule-bound manifest physical branch closure differs".into(),
            ));
        }
        if self.nonclaims
            != [
                "observed capsule length cannot select or enlarge a pre-effect bound",
                "the authenticated dependency closure remains exact pre-effect input rather than generic JSON",
                "symbolic shape derivation does not claim infeasibly maximal typed values were materialized or serialized",
                "the bound manifest performs no provider effect or filesystem allocation",
                "the bound manifest grants no invocation, diagnostic result, reliance, authorization, or action",
            ]
        {
            return Err(StoreError::Invariant(
                "capsule-bound manifest nonclaims differ".into(),
            ));
        }
        Ok(())
    }

    /// Stable manifest identity selected by the contract package.
    #[must_use]
    pub fn manifest_identity(&self) -> &str {
        &self.manifest_identity
    }

    /// Fixed product maxima.
    #[must_use]
    pub const fn scalar_maxima(&self) -> &ProjectionCapsuleScalarMaximaV1 {
        &self.scalar_maxima
    }

    fn direct_semantic_variant_bound(&self, source_identity: &str) -> Result<u64, StoreError> {
        let family = self
            .semantic_outcome_variants
            .iter()
            .find(|family| {
                family.source_identity == source_identity
                    && family.representation_location == "capsule_branch_selector"
            })
            .ok_or_else(|| {
                StoreError::Invariant(format!(
                    "capsule-bound candidate lacks direct semantic family {source_identity}"
                ))
            })?;
        family
            .variants
            .iter()
            .map(|variant| fixed_string_bound(variant))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or_else(|| {
                StoreError::Invariant(format!(
                    "capsule-bound candidate direct semantic family {source_identity} is empty"
                ))
            })
    }

    /// Refuse any attempt to promote this inspectable candidate into a
    /// qualified capacity contract while a ratified gate remains blocked.
    fn require_qualified_capacity_contract(&self) -> Result<(), StoreError> {
        if self.qualification_gaps.is_empty() {
            Ok(())
        } else {
            Err(StoreError::Invariant(format!(
                "V3 projection capsule capacity is not qualified; blocked gate(s): {}",
                self.qualification_gaps
                    .iter()
                    .map(|gap| gap.gate.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationBasisV1 {
    projection_identity: String,
    digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationReferenceV1 {
    schema: String,
    qualification_id: Sha256Digest,
    canonical_bytes_sha256: Sha256Digest,
}

#[derive(Clone, Debug)]
struct V3ProjectionCapsuleBoundManifestV2 {
    common: V3ProjectionCapsuleBoundManifestV1,
    qualification_basis: ProjectionCapsuleQualificationBasisV1,
    cap_h14_qualification: ProjectionCapsuleQualificationReferenceV1,
}

impl V3ProjectionCapsuleBoundManifestV2 {
    fn from_qualified_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut value: Value = serde_json::from_slice(bytes).map_err(|error| {
            StoreError::Invariant(format!("qualified capsule-bound manifest: {error}"))
        })?;
        let object = value.as_object_mut().ok_or_else(|| {
            StoreError::Invariant("qualified capsule-bound manifest is not an object".into())
        })?;
        let qualification_basis =
            serde_json::from_value(object.remove("qualification_basis").ok_or_else(|| {
                StoreError::Invariant(
                    "qualified capsule-bound manifest lacks qualification basis".into(),
                )
            })?)
            .map_err(|error| StoreError::Invariant(format!("qualification basis: {error}")))?;
        let cap_h14_qualification =
            serde_json::from_value(object.remove("cap_h14_qualification").ok_or_else(|| {
                StoreError::Invariant(
                    "qualified capsule-bound manifest lacks CAP-H14 qualification".into(),
                )
            })?)
            .map_err(|error| StoreError::Invariant(format!("CAP-H14 reference: {error}")))?;
        let common: V3ProjectionCapsuleBoundManifestV1 =
            serde_json::from_value(value).map_err(|error| {
                StoreError::Invariant(format!("qualified capsule-bound common fields: {error}"))
            })?;
        let manifest = Self {
            common,
            qualification_basis,
            cap_h14_qualification,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.common.schema != V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA
            || self.common.manifest_identity != V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA
            || self.common.manifest_version != "2"
            || self.qualification_basis.projection_identity != CAP_H14_QUALIFICATION_BASIS_IDENTITY
            || self.cap_h14_qualification.schema
                != V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_SCHEMA
            || !self.common.qualification_gaps.is_empty()
            || self.common.symbolic_shape_method.materialization_claim
                != "typed per-evidence disposition in nq.v3_projection_capsule_bound_qualification.v1"
            || self.common.bound_evaluator_identity != "nq.v3_projection_capsule_bound_evaluator.v1"
            || self.common.canonical_serializer_identity != "nq.production-canonical-json.v1"
            || self.common.canonicalization_identity != "rfc8785-jcs-sha256-v1"
            || self.common.nonclaims
                != [
                    "observed capsule length cannot select or enlarge a pre-effect bound",
                    "the authenticated dependency closure remains exact pre-effect input rather than generic JSON",
                    "typed qualification evidence does not authorize physical allocation or Store mutation",
                    "the qualified bound manifest does not establish Store-owned source/evaluator correspondence or satisfy C3-STORE-OWNED-CAPACITY-ALLOCATION-CONSTRUCTION",
                    "the bound manifest grants no invocation, diagnostic result, reliance, authorization, or action",
                ]
        {
            return Err(StoreError::Invariant(
                "qualified capsule-bound manifest v2 identity, qualification, or nonclaim closure differs"
                    .into(),
            ));
        }

        // Reuse the exhaustive v1 production census/source validation after
        // replacing only the fields whose v2 meaning is intentionally
        // additive. The retained `common` value remains v2-identified for
        // actual candidate derivation and output.
        let mut common = self.common.clone();
        common.schema = V3_PROJECTION_CAPSULE_BOUND_MANIFEST_SCHEMA.into();
        common.manifest_identity = V3_PROJECTION_CAPSULE_BOUND_MANIFEST_SCHEMA.into();
        common.manifest_version = "1".into();
        common.symbolic_shape_method.materialization_claim = "none".into();
        common.qualification_gaps = vec![ProjectionCapsuleQualificationGapV1 {
            gate: "CAP-H14".into(),
            status: "blocked".into(),
            required_evidence:
                "maximal exact production values for every closed branch serialized by the production canonical serializer"
                    .into(),
            current_evidence:
                "symbolic production-shape substitution cross-checked by independent JCS arithmetic"
                    .into(),
            consequence:
                "this candidate manifest does not qualify the V3 capsule bound or satisfy the Campaign 3B stopping rule"
                    .into(),
        }];
        common.nonclaims = vec![
            "observed capsule length cannot select or enlarge a pre-effect bound".into(),
            "the authenticated dependency closure remains exact pre-effect input rather than generic JSON"
                .into(),
            "symbolic shape derivation does not claim infeasibly maximal typed values were materialized or serialized"
                .into(),
            "the bound manifest performs no provider effect or filesystem allocation".into(),
            "the bound manifest grants no invocation, diagnostic result, reliance, authorization, or action"
                .into(),
        ];
        common.validate()
    }
}

/// Resolve the exact acyclic source cut admitted by the candidate manifest.
///
/// The cut contains only native semantic/carrier sources. It deliberately
/// excludes the candidate manifest, its schema, the capacity extension, and
/// `assets.rs` (which embeds those assets), so no digest can validate itself
/// directly or transitively.
fn semantic_source_bytes(source_path: &str) -> Option<&'static [u8]> {
    let bytes: &'static [u8] = match source_path {
        "crates/nq-core/src/engine.rs" => include_bytes!("../../nq-core/src/engine.rs"),
        "crates/nq-core/src/provider_intake.rs" => {
            include_bytes!("../../nq-core/src/provider_intake.rs")
        }
        "crates/nq-core/src/runner.rs" => include_bytes!("../../nq-core/src/runner.rs"),
        "crates/nq-core/src/identity.rs" => include_bytes!("../../nq-core/src/identity.rs"),
        "crates/nq-core/src/runtime.rs" => include_bytes!("../../nq-core/src/runtime.rs"),
        "crates/nq-core/src/governed_custody_projection.rs" => {
            include_bytes!("../../nq-core/src/governed_custody_projection.rs")
        }
        "crates/nq-core/src/governed_execution_binding.rs" => {
            include_bytes!("../../nq-core/src/governed_execution_binding.rs")
        }
        "crates/nq-protocol/src/model.rs" => include_bytes!("../../nq-protocol/src/model.rs"),
        "crates/nq-protocol/src/ids.rs" => include_bytes!("../../nq-protocol/src/ids.rs"),
        "crates/nq-profiles/src/validation.rs" => {
            include_bytes!("../../nq-profiles/src/validation.rs")
        }
        "crates/nq-profiles/src/detector.rs" => {
            include_bytes!("../../nq-profiles/src/detector.rs")
        }
        "crates/nq-profiles/src/descriptor.rs" => {
            include_bytes!("../../nq-profiles/src/descriptor.rs")
        }
        "crates/nq-host-role-contract/src/identity.rs" => {
            include_bytes!("../../nq-host-role-contract/src/identity.rs")
        }
        "crates/nq-host-role-contract/src/record.rs" => {
            include_bytes!("../../nq-host-role-contract/src/record.rs")
        }
        "crates/nq-helper-sandbox/src/lib.rs" => {
            include_bytes!("../../nq-helper-sandbox/src/lib.rs")
        }
        _ => return None,
    };
    Some(bytes)
}

fn semantic_source_digest(source_path: &str) -> Option<Sha256Digest> {
    semantic_source_bytes(source_path).map(nq_protocol::sha256_bytes)
}

/// Inspect the content-addressed capsule-bound candidate from the host-role
/// contract package and verify its Store-side content closure.
///
/// This does not qualify the bound. The parsed candidate carries a
/// load-bearing CAP-H14 gap and cannot be promoted to a usable capacity
/// contract by this module.
pub(crate) fn inspected_v3_projection_capsule_bound_candidate_v1()
-> Result<V3ProjectionCapsuleBoundManifestV1, StoreError> {
    let bytes = nq_host_role_contract::inspected_candidate_v3_projection_capsule_bound_manifest()
        .map_err(|error| StoreError::Integrity(error.to_string()))?;
    V3ProjectionCapsuleBoundManifestV1::from_inspected_candidate_bytes(bytes)
}

/// One identified pre-effect bounded-JSON descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleBoundedJsonSourceV1 {
    slot: String,
    source_identity: String,
    source_record_schema: Option<String>,
    source_record_digest: Sha256Digest,
    source_record_canonical_bytes: String,
    descriptor_pointer: String,
    descriptor: BoundedJsonDescriptor,
}

impl ProjectionCapsuleBoundedJsonSourceV1 {
    /// Construct a source from an exact canonical source record selected
    /// before provider effect.
    ///
    /// The descriptor is decoded from `descriptor_pointer`; callers cannot
    /// attach a caller-selected descriptor to a ceremonial source label.  The
    /// exact record bytes, their verified digest, and the pointer all
    /// participate in the enclosing source-set identity.
    ///
    /// This proves content binding, not standing.  A later live Store API must
    /// supply only records selected under authenticated provider/profile/policy
    /// custody; possession of matching bytes does not grant that authority.
    pub fn from_canonical_source_record(
        slot: impl Into<String>,
        source_identity: impl Into<String>,
        source_record_digest: Sha256Digest,
        source_record_canonical_bytes: impl Into<Vec<u8>>,
        descriptor_pointer: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let source_record_canonical_bytes = source_record_canonical_bytes.into();
        let decoded: Value =
            serde_json::from_slice(&source_record_canonical_bytes).map_err(|error| {
                StoreError::Invariant(format!(
                    "capsule bounded-JSON source record is not JSON: {error}"
                ))
            })?;
        let canonical = canonical_json_bytes(&decoded)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        if canonical != source_record_canonical_bytes {
            return Err(StoreError::Integrity(
                "capsule bounded-JSON source record bytes are not exact production-canonical JSON"
                    .into(),
            ));
        }
        if nq_protocol::sha256_bytes(&source_record_canonical_bytes) != source_record_digest {
            return Err(StoreError::Integrity(
                "capsule bounded-JSON source record digest does not authenticate its exact bytes"
                    .into(),
            ));
        }
        let descriptor_pointer = descriptor_pointer.into();
        if !descriptor_pointer.is_empty() && !descriptor_pointer.starts_with('/') {
            return Err(StoreError::Invariant(
                "capsule bounded-JSON descriptor pointer is not a JSON pointer".into(),
            ));
        }
        let descriptor_value = if descriptor_pointer.is_empty() {
            &decoded
        } else {
            decoded.pointer(&descriptor_pointer).ok_or_else(|| {
                StoreError::Invariant(format!(
                    "capsule bounded-JSON source record has no descriptor at {descriptor_pointer}"
                ))
            })?
        };
        let descriptor: BoundedJsonDescriptor =
            serde_json::from_value(descriptor_value.clone()).map_err(|error| {
                StoreError::Invariant(format!(
                    "capsule bounded-JSON source descriptor at {descriptor_pointer:?} is invalid: {error}"
                ))
            })?;
        let source_record_schema = decoded
            .as_object()
            .and_then(|record| record.get("schema"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let source_record_canonical_bytes = String::from_utf8(source_record_canonical_bytes)
            .map_err(|_| {
                StoreError::Invariant(
                    "capsule bounded-JSON canonical source record is not UTF-8".into(),
                )
            })?;
        let source = Self {
            slot: slot.into(),
            source_identity: source_identity.into(),
            source_record_schema,
            source_record_digest,
            source_record_canonical_bytes,
            descriptor_pointer,
            descriptor,
        };
        if source.slot.is_empty() || source.source_identity.is_empty() {
            return Err(StoreError::Invariant(
                "capsule bounded-JSON source slot or identity is empty".into(),
            ));
        }
        Ok(source)
    }

    /// Closed descriptor slot.
    #[must_use]
    pub fn slot(&self) -> &str {
        &self.slot
    }

    /// Identified profile/provider/policy source of the descriptor.
    #[must_use]
    pub fn source_identity(&self) -> &str {
        &self.source_identity
    }

    /// Declared source-record schema, if the exact record carries one.
    #[must_use]
    pub fn source_record_schema(&self) -> Option<&str> {
        self.source_record_schema.as_deref()
    }

    /// Digest authenticating the exact canonical source-record bytes.
    #[must_use]
    pub const fn source_record_digest(&self) -> &Sha256Digest {
        &self.source_record_digest
    }

    /// Exact canonical source-record bytes from which the descriptor was
    /// decoded.
    #[must_use]
    pub fn source_record_canonical_bytes(&self) -> &[u8] {
        self.source_record_canonical_bytes.as_bytes()
    }

    /// JSON pointer selecting the descriptor inside the exact source record.
    #[must_use]
    pub fn descriptor_pointer(&self) -> &str {
        &self.descriptor_pointer
    }

    /// Immutable descriptor selected before provider effect.
    #[must_use]
    pub const fn descriptor(&self) -> &BoundedJsonDescriptor {
        &self.descriptor
    }
}

/// Complete pre-effect inputs to one capsule-bound calculation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCapsuleBoundSourcesV1 {
    bounded_json: BTreeMap<String, ProjectionCapsuleBoundedJsonSourceV1>,
    dependency_generation_id: Sha256Digest,
    dependency_canonical_custody_digest: Sha256Digest,
    dependency_canonical_custody_bytes: u64,
}

impl ProjectionCapsuleBoundSourcesV1 {
    /// Close every descriptor slot plus the exact authenticated dependency
    /// custody selected before provider effect.
    pub fn new(
        bounded_json: impl IntoIterator<Item = ProjectionCapsuleBoundedJsonSourceV1>,
        dependency_generation_id: Sha256Digest,
        dependency_canonical_custody: &CanonicalDocument,
    ) -> Result<Self, StoreError> {
        let dependency_canonical_custody_bytes =
            u64::try_from(dependency_canonical_custody.as_bytes().len()).map_err(|_| {
                StoreError::Invariant("exact dependency custody length overflowed".into())
            })?;
        if dependency_canonical_custody_bytes == 0 {
            return Err(StoreError::Invariant(
                "exact dependency custody length must be positive".into(),
            ));
        }
        let dependency_canonical_custody_digest =
            Sha256Digest::parse(dependency_canonical_custody.digest().to_owned())
                .map_err(|error| StoreError::Invariant(error.to_string()))?;
        let mut by_slot = BTreeMap::new();
        for source in bounded_json {
            if by_slot.insert(source.slot.clone(), source).is_some() {
                return Err(StoreError::Invariant(
                    "capsule bound repeats a bounded-JSON source slot".into(),
                ));
            }
        }
        let expected = PROJECTION_CAPSULE_BOUNDED_JSON_SOURCE_SLOTS
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual = by_slot.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(StoreError::Invariant(
                "capsule bound omits or adds a bounded-JSON source slot".into(),
            ));
        }
        Ok(Self {
            bounded_json: by_slot,
            dependency_generation_id,
            dependency_canonical_custody_digest,
            dependency_canonical_custody_bytes,
        })
    }

    fn descriptor(&self, slot: &str) -> Result<&BoundedJsonDescriptor, StoreError> {
        self.bounded_json
            .get(slot)
            .map(ProjectionCapsuleBoundedJsonSourceV1::descriptor)
            .ok_or_else(|| {
                StoreError::Invariant(format!(
                    "capsule bound has no bounded-JSON descriptor for {slot}"
                ))
            })
    }

    /// Exact pre-effect dependency-custody length.
    #[must_use]
    pub const fn dependency_canonical_custody_bytes(&self) -> u64 {
        self.dependency_canonical_custody_bytes
    }
}

/// One conservative symbolic physical closure shape considered by the
/// candidate evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrelaunchClosureShapeV1 {
    outcome_branch: ProjectionCapsuleOutcomeBranchV1,
    coverage_distribution: String,
    provider_attempts: u32,
    runtime_records: u32,
    canonical_bytes: u64,
}

impl PrelaunchClosureShapeV1 {
    /// Closed post-effect outcome branch.
    #[must_use]
    pub const fn outcome_branch(&self) -> ProjectionCapsuleOutcomeBranchV1 {
        self.outcome_branch
    }

    /// Named conservative coverage distribution used by this shape.
    #[must_use]
    pub fn coverage_distribution(&self) -> &str {
        &self.coverage_distribution
    }

    /// Derived canonical-byte ceiling for this shape.
    #[must_use]
    pub const fn canonical_bytes(&self) -> u64 {
        self.canonical_bytes
    }
}

const CAP_H14_TRACTABLE_DESCRIPTOR_EVIDENCE_ID: &str =
    "nq.cap-h14.tractable-descriptor-component.v1";
const CAP_H14_UNATTAINABLE_DESCRIPTOR_EVIDENCE_ID: &str =
    "nq.cap-h14.zero-key-two-member-descriptor.v1";
const CAP_H14_ADMITTED_REPORT_SHAPE_EVIDENCE_ID: &str =
    "nq.cap-h14.shape.admitted-all-report-level.v1";
const CAP_H14_ADMITTED_OBSERVED_SHAPE_EVIDENCE_ID: &str =
    "nq.cap-h14.shape.admitted-one-per-observation-then-nested.v1";
const CAP_H14_NO_SUBMISSION_SHAPE_EVIDENCE_ID: &str =
    "nq.cap-h14.shape.non-success-no-submission.v1";
const CAP_H14_REJECTED_SHAPE_EVIDENCE_ID: &str =
    "nq.cap-h14.shape.non-success-rejected-submission.v1";
const CAP_H14_LARGE_DESCRIPTOR_EVIDENCE_ID: &str =
    "nq.cap-h14.large-generic-descriptor-component.v1";
const CAP_H14_LARGE_CAPSULE_EVIDENCE_ID: &str = "nq.cap-h14.large-generic-full-capsule.v1";

/// One exact physical-shape scope to which a qualification census row applies.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationShapeScopeV1 {
    branch: String,
    distribution: String,
}

/// Exact qualification-evidence coverage for one production field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationFieldEvidenceV1 {
    pointer_family: String,
    classification: String,
    bound_source: String,
    applicable_shapes: Vec<ProjectionCapsuleQualificationShapeScopeV1>,
    evidence_case_ids: Vec<String>,
}

/// Exact qualification-evidence coverage for one bound source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationSourceEvidenceV1 {
    source_identity: String,
    pointer_families: Vec<String>,
    applicable_shapes: Vec<ProjectionCapsuleQualificationShapeScopeV1>,
    evidence_case_ids: Vec<String>,
}

/// Exact qualification evidence for one closed symbolic shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationShapeEvidenceV1 {
    branch: String,
    distribution: String,
    canonical_bytes: u64,
    evidence_case_id: String,
    attempt_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationSourceBindingV1 {
    identity: String,
    path: String,
    sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationPolicyBindingsV1 {
    operator_decision: ProjectionCapsuleQualificationSourceBindingV1,
    controlling_supplement: ProjectionCapsuleQualificationSourceBindingV1,
    accepted_adjudication: ProjectionCapsuleQualificationSourceBindingV1,
    materialization_budget_decision: ProjectionCapsuleQualificationSourceBindingV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationImplementationBindingsV1 {
    evaluator: ProjectionCapsuleQualificationSourceBindingV1,
    canonical_serializer: ProjectionCapsuleQualificationSourceBindingV1,
    independent_arithmetic: ProjectionCapsuleQualificationSourceBindingV1,
    test_source: ProjectionCapsuleQualificationSourceBindingV1,
    post_acceptance_review: ProjectionCapsuleQualificationReviewBindingV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationReviewBindingV1 {
    identity: String,
    path: String,
    sha256: Sha256Digest,
    qualification_basis_sha256: Sha256Digest,
    pre_review_projection_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationPreallocationReceiptV1 {
    schema: String,
    receipt_identity: String,
    receipt_sha256: Sha256Digest,
    budget_identity: String,
    preallocated_workspace_bytes: u64,
    slot_count: u64,
    slot_bytes: u64,
    maximum_observed_parallel_materializations: u64,
    allocated_block_bytes: u64,
    result: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationBudgetV1 {
    schema: String,
    identity: String,
    maximum_single_canonical_witness_bytes: u64,
    closed_shape_count: u64,
    maximum_total_preallocated_witness_bytes: u64,
    maximum_parallel_witnesses: u64,
    enforcement_identity: String,
    enforcement_binding: ProjectionCapsuleQualificationSourceBindingV1,
    preallocation_receipt: ProjectionCapsuleQualificationPreallocationReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationCensusRowsV1<T> {
    population: u64,
    manifest_rows_sha256: Sha256Digest,
    qualification_rows_sha256: Sha256Digest,
    rows: Vec<T>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationCensusV1 {
    fields:
        ProjectionCapsuleQualificationCensusRowsV1<ProjectionCapsuleQualificationFieldEvidenceV1>,
    sources:
        ProjectionCapsuleQualificationCensusRowsV1<ProjectionCapsuleQualificationSourceEvidenceV1>,
    shapes:
        ProjectionCapsuleQualificationCensusRowsV1<ProjectionCapsuleQualificationShapeEvidenceV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleMaterializationAttemptV1 {
    branch: String,
    distribution: String,
    budget_receipt_sha256: Sha256Digest,
    slot_index: u64,
    attempt_identity: String,
    disposition: String,
    output_length_bytes: Option<u64>,
    output_sha256: Option<Sha256Digest>,
    refusal_reason: Option<String>,
    observed_parallel_materializations: u64,
    attempt_receipt_canonical_bytes: u64,
    attempt_receipt_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCapsuleQualificationEvidenceDispositionV1 {
    evidence_id: String,
    scope: String,
    subject_identity: String,
    disposition: String,
    symbolic_ceiling_bytes: u64,
    actual_canonical_bytes: Option<u64>,
    production_witness_sha256: Option<Sha256Digest>,
    unattainability_proof_identity: Option<String>,
    unattainability_proof_canonical_bytes: Option<u64>,
    unattainability_proof_sha256: Option<Sha256Digest>,
    budget_identity: Option<String>,
    source_constraints_identity: String,
    arithmetic_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct V3ProjectionCapsuleBoundQualificationV1 {
    schema: String,
    qualification_id: Sha256Digest,
    gate: String,
    status: String,
    qualification_basis: ProjectionCapsuleQualificationBasisV1,
    policy_bindings: ProjectionCapsuleQualificationPolicyBindingsV1,
    implementation_bindings: ProjectionCapsuleQualificationImplementationBindingsV1,
    qualification_budget: ProjectionCapsuleQualificationBudgetV1,
    census: ProjectionCapsuleQualificationCensusV1,
    materialization_attempts: Vec<ProjectionCapsuleMaterializationAttemptV1>,
    evidence_dispositions: Vec<ProjectionCapsuleQualificationEvidenceDispositionV1>,
    nonclaims: Vec<String>,
}

fn qualification_shape_scope(
    branch: ProjectionCapsuleOutcomeBranchV1,
    distribution: CoverageDistribution,
) -> ProjectionCapsuleQualificationShapeScopeV1 {
    ProjectionCapsuleQualificationShapeScopeV1 {
        branch: match branch {
            ProjectionCapsuleOutcomeBranchV1::Admitted => "admitted",
            ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission => "non_success_no_submission",
            ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected => {
                "non_success_rejected_submission"
            }
        }
        .to_owned(),
        distribution: match distribution {
            CoverageDistribution::None => "not_applicable",
            CoverageDistribution::Report => "all_report_level",
            CoverageDistribution::Observed => "one_per_observation_then_nested",
        }
        .to_owned(),
    }
}

fn qualification_shape_evidence_id(
    branch: ProjectionCapsuleOutcomeBranchV1,
    distribution: CoverageDistribution,
) -> &'static str {
    match (branch, distribution) {
        (ProjectionCapsuleOutcomeBranchV1::Admitted, CoverageDistribution::Report) => {
            CAP_H14_ADMITTED_REPORT_SHAPE_EVIDENCE_ID
        }
        (ProjectionCapsuleOutcomeBranchV1::Admitted, CoverageDistribution::Observed) => {
            CAP_H14_ADMITTED_OBSERVED_SHAPE_EVIDENCE_ID
        }
        (ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission, CoverageDistribution::None) => {
            CAP_H14_NO_SUBMISSION_SHAPE_EVIDENCE_ID
        }
        (ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected, CoverageDistribution::None) => {
            CAP_H14_REJECTED_SHAPE_EVIDENCE_ID
        }
        _ => unreachable!("closed qualification shape"),
    }
}

fn field_applies_to_qualification_shape(
    field: &ProjectionCapsuleBoundFieldV1,
    branch_fields: &BTreeSet<String>,
    distribution: CoverageDistribution,
) -> bool {
    if !branch_fields.contains(&field.pointer_family) {
        return false;
    }
    if field
        .pointer_family
        .starts_with("/collection/submission/disposition/report/coverage/*/")
    {
        return matches!(distribution, CoverageDistribution::Report);
    }
    if field
        .pointer_family
        .starts_with("/collection/submission/disposition/report/observations/*/coverage/*/")
    {
        return matches!(distribution, CoverageDistribution::Observed);
    }
    true
}

#[allow(clippy::too_many_lines)] // One closed exact field/source evidence census.
fn qualification_evidence_maps_v1(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
) -> Result<
    (
        Vec<ProjectionCapsuleQualificationFieldEvidenceV1>,
        Vec<ProjectionCapsuleQualificationSourceEvidenceV1>,
    ),
    StoreError,
> {
    let branch_fields = ProjectionCapsuleOutcomeBranchV1::ALL
        .into_iter()
        .map(|branch| {
            let value =
                crate::governed_projection_capsule::projection_capsule_symbolic_shape_witness_v1(
                    branch,
                )?;
            let mut inventory = BTreeMap::new();
            collect_production_capsule_fields(&value, "", &mut inventory)?;
            Ok((branch, inventory.into_keys().collect::<BTreeSet<String>>()))
        })
        .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
    let shapes = [
        (
            ProjectionCapsuleOutcomeBranchV1::Admitted,
            CoverageDistribution::Report,
        ),
        (
            ProjectionCapsuleOutcomeBranchV1::Admitted,
            CoverageDistribution::Observed,
        ),
        (
            ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission,
            CoverageDistribution::None,
        ),
        (
            ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected,
            CoverageDistribution::None,
        ),
    ];

    let mut field_rows = Vec::with_capacity(manifest.capsule_field_inventory.len());
    for field in &manifest.capsule_field_inventory {
        let mut applicable_shapes = BTreeSet::new();
        let mut evidence_case_ids = BTreeSet::new();
        for (branch, distribution) in shapes {
            if field_applies_to_qualification_shape(
                field,
                branch_fields.get(&branch).expect("closed branch inventory"),
                distribution,
            ) {
                applicable_shapes.insert(qualification_shape_scope(branch, distribution));
                evidence_case_ids
                    .insert(qualification_shape_evidence_id(branch, distribution).to_owned());
            }
        }
        if PROJECTION_CAPSULE_BOUNDED_JSON_SOURCE_SLOTS.contains(&field.bound_source.as_str()) {
            evidence_case_ids.extend(
                [
                    CAP_H14_TRACTABLE_DESCRIPTOR_EVIDENCE_ID,
                    CAP_H14_UNATTAINABLE_DESCRIPTOR_EVIDENCE_ID,
                    CAP_H14_LARGE_DESCRIPTOR_EVIDENCE_ID,
                    CAP_H14_LARGE_CAPSULE_EVIDENCE_ID,
                ]
                .into_iter()
                .map(str::to_owned),
            );
        }
        if applicable_shapes.is_empty() || evidence_case_ids.is_empty() {
            return Err(StoreError::Invariant(format!(
                "qualification evidence map leaves field {} uncovered",
                field.pointer_family
            )));
        }
        field_rows.push(ProjectionCapsuleQualificationFieldEvidenceV1 {
            pointer_family: field.pointer_family.clone(),
            classification: field.classification.clone(),
            bound_source: field.bound_source.clone(),
            applicable_shapes: applicable_shapes.into_iter().collect(),
            evidence_case_ids: evidence_case_ids.into_iter().collect(),
        });
    }

    let mut source_rows = BTreeMap::<
        String,
        (
            BTreeSet<String>,
            BTreeSet<ProjectionCapsuleQualificationShapeScopeV1>,
            BTreeSet<String>,
        ),
    >::new();
    for field in &field_rows {
        let (pointers, shapes, cases) = source_rows.entry(field.bound_source.clone()).or_default();
        pointers.insert(field.pointer_family.clone());
        shapes.extend(field.applicable_shapes.iter().cloned());
        cases.extend(field.evidence_case_ids.iter().cloned());
    }
    let source_rows = source_rows
        .into_iter()
        .map(
            |(source_identity, (pointer_families, applicable_shapes, evidence_case_ids))| {
                ProjectionCapsuleQualificationSourceEvidenceV1 {
                    source_identity,
                    pointer_families: pointer_families.into_iter().collect(),
                    applicable_shapes: applicable_shapes.into_iter().collect(),
                    evidence_case_ids: evidence_case_ids.into_iter().collect(),
                }
            },
        )
        .collect::<Vec<_>>();
    if field_rows.len() != 151 || source_rows.len() != 38 {
        return Err(StoreError::Invariant(format!(
            "qualification evidence map population differs: fields={}, sources={}",
            field_rows.len(),
            source_rows.len()
        )));
    }
    Ok((field_rows, source_rows))
}

fn qualification_shape_evidence_rows_after_manifest_validation(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
) -> Result<Vec<ProjectionCapsuleQualificationShapeEvidenceV1>, StoreError> {
    let descriptor = BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3)
        .map_err(|error| StoreError::Invariant(format!("qualification descriptor: {error}")))?;
    let descriptor_bytes = canonical_json_bytes(
        &serde_json::to_value(&descriptor)
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?,
    )
    .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    let descriptor_digest = nq_protocol::sha256_bytes(&descriptor_bytes);
    let bounded_json = manifest
        .bounded_json_sources
        .iter()
        .map(|declaration| {
            ProjectionCapsuleBoundedJsonSourceV1::from_canonical_source_record(
                declaration.descriptor_key.clone(),
                declaration.source_identity.clone(),
                descriptor_digest.clone(),
                descriptor_bytes.clone(),
                declaration.descriptor_pointer.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let dependency = CanonicalDocument::from_serializable(&json!({}))?;
    let sources = ProjectionCapsuleBoundSourcesV1::new(
        bounded_json,
        nq_protocol::sha256_bytes(b"candidate-dependency-generation"),
        &dependency,
    )?;
    let candidate =
        symbolic_candidate_projection_capsule_bound_v1_after_validation(manifest, &sources)?;
    let attempts = [
        (
            ProjectionCapsuleOutcomeBranchV1::Admitted,
            "all_report_level",
            CAP_H14_ADMITTED_REPORT_SHAPE_EVIDENCE_ID,
            "nq.cap-h14.materialization-attempt.admitted-all-report-level.v1",
        ),
        (
            ProjectionCapsuleOutcomeBranchV1::Admitted,
            "one_per_observation_then_nested",
            CAP_H14_ADMITTED_OBSERVED_SHAPE_EVIDENCE_ID,
            "nq.cap-h14.materialization-attempt.admitted-one-per-observation-then-nested.v1",
        ),
        (
            ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission,
            "not_applicable",
            CAP_H14_NO_SUBMISSION_SHAPE_EVIDENCE_ID,
            "nq.cap-h14.materialization-attempt.non-success-no-submission.v1",
        ),
        (
            ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected,
            "not_applicable",
            CAP_H14_REJECTED_SHAPE_EVIDENCE_ID,
            "nq.cap-h14.materialization-attempt.non-success-rejected-submission.v1",
        ),
    ];
    candidate
        .shapes
        .iter()
        .zip(attempts)
        .map(
            |(shape, (branch, distribution, evidence_case_id, attempt_identity))| {
                if shape.outcome_branch != branch || shape.coverage_distribution != distribution {
                    return Err(StoreError::Invariant(
                        "qualification shape order or distribution differs".into(),
                    ));
                }
                Ok(ProjectionCapsuleQualificationShapeEvidenceV1 {
                    branch: match branch {
                        ProjectionCapsuleOutcomeBranchV1::Admitted => "admitted",
                        ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission => {
                            "non_success_no_submission"
                        }
                        ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected => {
                            "non_success_rejected_submission"
                        }
                    }
                    .to_owned(),
                    distribution: distribution.to_owned(),
                    canonical_bytes: shape.canonical_bytes,
                    evidence_case_id: evidence_case_id.to_owned(),
                    attempt_identity: attempt_identity.to_owned(),
                })
            },
        )
        .collect()
}

fn canonical_value_sha256<T: Serialize>(value: &T) -> Result<Sha256Digest, StoreError> {
    canonical_json_bytes(value)
        .map(|bytes| nq_protocol::sha256_bytes(&bytes))
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))
}

fn zero_key_uniqueness_unattainability_proof_receipt() -> Result<Vec<u8>, StoreError> {
    canonical_json_bytes(&json!({
        "schema": "nq.bounded_json_descriptor_unattainability_proof.v1",
        "proof_identity":
            "nq.bounded-json-descriptor.unique-object-key-unattainability.v1",
        "descriptor": {
            "maximum_canonical_bytes": 19,
            "maximum_depth": 2,
            "maximum_properties_per_object": 2,
            "maximum_array_items": 0,
            "maximum_key_utf8_bytes": 0,
            "maximum_string_utf8_bytes": 0,
            "maximum_integer_decimal_width": 1
        },
        "source_constraints": {
            "json_object_keys_unique": true,
            "possible_distinct_object_keys": 1,
            "sole_object_key": "",
            "maximum_leaf_canonical_bytes": 5
        },
        "checked_root_maxima": {
            "null": 4,
            "boolean": 5,
            "integer": 1,
            "string": 2,
            "array": 2,
            "object": 10
        },
        "symbolic_structural_ceiling_bytes": 19,
        "maximum_attainable_canonical_bytes": 10,
        "maximum_attainable_witness_sha256":
            "sha256:54755e5a76e179ba48aa9c21a030a938f63fcc7d7b7bd964754f2cb1795e8e1a",
        "conclusion":
            "two zero-byte object keys cannot be distinct; the nominal two-member structural recurrence is unattainable"
    }))
    .map_err(|error| StoreError::CanonicalJson(error.to_string()))
}

impl V3ProjectionCapsuleBoundQualificationV1 {
    fn from_qualified_bytes(
        bytes: &[u8],
        manifest: &V3ProjectionCapsuleBoundManifestV2,
        assets: &nq_host_role_contract::QualifiedV3ProjectionCapsuleBoundAssets,
    ) -> Result<Self, StoreError> {
        let qualification: Self = serde_json::from_slice(bytes).map_err(|error| {
            StoreError::Invariant(format!("CAP-H14 qualification carrier: {error}"))
        })?;
        qualification.validate(manifest, assets)?;
        Ok(qualification)
    }

    #[allow(clippy::too_many_lines)]
    fn validate(
        &self,
        manifest: &V3ProjectionCapsuleBoundManifestV2,
        assets: &nq_host_role_contract::QualifiedV3ProjectionCapsuleBoundAssets,
    ) -> Result<(), StoreError> {
        let budget = &self.qualification_budget;
        let receipt = &budget.preallocation_receipt;
        if self.schema != V3_PROJECTION_CAPSULE_BOUND_QUALIFICATION_V1_SCHEMA
            || self.gate != "CAP-H14"
            || self.status != "qualified"
            || self.qualification_basis != manifest.qualification_basis
            || self.qualification_basis.digest != assets.qualification_basis_sha256
            || self.qualification_id != manifest.cap_h14_qualification.qualification_id
            || manifest.cap_h14_qualification.canonical_bytes_sha256 != assets.qualification_sha256
            || budget.schema != "nq.v3_projection_capsule_materialization_budget.v1"
            || budget.identity != CAP_H14_QUALIFICATION_BUDGET_IDENTITY
            || budget.maximum_single_canonical_witness_bytes != 16_777_216
            || budget.closed_shape_count != 4
            || budget.maximum_total_preallocated_witness_bytes != 67_108_864
            || budget.maximum_parallel_witnesses != 1
            || budget.enforcement_identity
                != "nq.v3_projection_capsule_materialization_preallocation.v1"
            || receipt.schema
                != "nq.v3_projection_capsule_qualification_budget_enforcement_receipt.v1"
            || receipt.receipt_identity
                != "nq.v3_projection_capsule_qualification_budget_enforcement_receipt.v1"
            || receipt.budget_identity != CAP_H14_QUALIFICATION_BUDGET_IDENTITY
            || receipt.preallocated_workspace_bytes != 67_108_864
            || receipt.slot_count != 4
            || receipt.slot_bytes != 16_777_216
            || receipt.maximum_observed_parallel_materializations != 1
            || receipt.allocated_block_bytes < 67_108_864
            || receipt.result != "preallocation-verified"
        {
            return Err(StoreError::Invariant(
                "CAP-H14 positive identity, budget, or preallocation receipt differs".into(),
            ));
        }

        self.validate_bindings(&manifest.common, assets)?;
        self.validate_census(&manifest.common)?;
        self.validate_attempts()?;
        self.validate_evidence_dispositions()?;
        if self.nonclaims
            != [
                "CAP-H14 qualification does not establish Store-owned source/evaluator correspondence or satisfy C3-STORE-OWNED-CAPACITY-ALLOCATION-CONSTRUCTION",
                "qualification-budget enforcement performs no runtime custody allocation or Store mutation",
                "qualification evidence grants no invocation, diagnostic result, reliance, authorization, or action",
                "a finite symbolic ceiling is not a claim that its global literal maximum is attainable",
                "materialization feasibility does not alter the symbolic ceiling or admit observed-length sizing",
                "qualification of the pure C1 bound does not authorize C2 physical carriers, filesystem effects, provider launch, or delivery",
            ]
        {
            return Err(StoreError::Invariant(
                "CAP-H14 qualification nonclaims differ".into(),
            ));
        }
        Ok(())
    }

    fn validate_bindings(
        &self,
        manifest: &V3ProjectionCapsuleBoundManifestV1,
        assets: &nq_host_role_contract::QualifiedV3ProjectionCapsuleBoundAssets,
    ) -> Result<(), StoreError> {
        let policies = &self.policy_bindings;
        if (
            policies.operator_decision.identity.as_str(),
            policies.operator_decision.path.as_str(),
        ) != (
            "nq.host-role-runtime-seam.cap-h13-h14-clarification.2026-07-30",
            "audits/nq-host-role-runtime-seam-v1/records/cap-h13-h14-operator-decision.md",
        ) || (
            policies.controlling_supplement.identity.as_str(),
            policies.controlling_supplement.path.as_str(),
        ) != (
            "nq.host-role-runtime-seam.physical-aggregate-custody-capacity-supplement.v1",
            "audits/nq-host-role-runtime-seam-v1/records/physical-aggregate-custody-capacity-supplement.md",
        ) || (
            policies.accepted_adjudication.identity.as_str(),
            policies.accepted_adjudication.path.as_str(),
        ) != (
            "nq.host-role-runtime-seam.cap-h14-symbolic-bound-adjudication.v1",
            "audits/nq-host-role-runtime-seam-v1/records/cap-h14-symbolic-bound-adjudication.md",
        ) || (
            policies.materialization_budget_decision.identity.as_str(),
            policies.materialization_budget_decision.path.as_str(),
        ) != (
            CAP_H14_QUALIFICATION_BUDGET_IDENTITY,
            "audits/nq-host-role-runtime-seam-v1/records/cap-h14-materialization-budget-decision.md",
        ) {
            return Err(StoreError::Invariant(
                "CAP-H14 policy binding identity or path differs".into(),
            ));
        }

        let implementation = &self.implementation_bindings;
        let store_source_sha256 =
            nq_protocol::sha256_bytes(include_bytes!("governed_projection_capacity.rs"));
        let capsule_source_sha256 =
            nq_protocol::sha256_bytes(include_bytes!("governed_projection_capsule.rs"));
        for (binding, identity) in [
            (
                &implementation.evaluator,
                "nq.v3_projection_capsule_bound_evaluator.v1",
            ),
            (
                &implementation.independent_arithmetic,
                "nq.v3_projection_capsule_bound_independent_arithmetic.v1",
            ),
            (
                &implementation.test_source,
                "nq.v3_projection_capsule_bound_qualification_tests.v1",
            ),
        ] {
            if binding.identity != identity
                || binding.path != "crates/nq-store/src/governed_projection_capacity.rs"
                || binding.sha256 != store_source_sha256
            {
                return Err(StoreError::Invariant(format!(
                    "CAP-H14 implementation binding {identity} differs"
                )));
            }
        }
        if implementation.canonical_serializer.identity != manifest.canonical_serializer_identity
            || implementation.canonical_serializer.path
                != "crates/nq-store/src/governed_projection_capsule.rs"
            || implementation.canonical_serializer.sha256 != capsule_source_sha256
            || self.qualification_budget.enforcement_binding.identity
                != self.qualification_budget.enforcement_identity
            || self.qualification_budget.enforcement_binding.path
                != "crates/nq-store/src/governed_projection_capacity.rs"
            || self.qualification_budget.enforcement_binding.sha256 != store_source_sha256
            || implementation.post_acceptance_review.identity
                != assets.post_acceptance_review_identity
            || implementation.post_acceptance_review.path != assets.post_acceptance_review_path
            || implementation.post_acceptance_review.sha256 != assets.post_acceptance_review_sha256
            || implementation
                .post_acceptance_review
                .qualification_basis_sha256
                != self.qualification_basis.digest
        {
            return Err(StoreError::Invariant(
                "CAP-H14 serializer, budget-enforcement, or review binding differs".into(),
            ));
        }
        Ok(())
    }

    fn validate_census(
        &self,
        manifest: &V3ProjectionCapsuleBoundManifestV1,
    ) -> Result<(), StoreError> {
        let (expected_fields, expected_sources) = qualification_evidence_maps_v1(manifest)?;
        let expected_shapes =
            qualification_shape_evidence_rows_after_manifest_validation(manifest)?;
        if self.census.fields.population != 151
            || self.census.sources.population != 38
            || self.census.shapes.population != 4
            || self.census.fields.rows != expected_fields
            || self.census.sources.rows != expected_sources
            || self.census.shapes.rows != expected_shapes
        {
            return Err(StoreError::Invariant(
                "CAP-H14 field/source/shape evidence census differs".into(),
            ));
        }
        if self.census.fields.qualification_rows_sha256 != canonical_value_sha256(&expected_fields)?
            || self.census.sources.qualification_rows_sha256
                != canonical_value_sha256(&expected_sources)?
            || self.census.shapes.qualification_rows_sha256
                != canonical_value_sha256(&expected_shapes)?
        {
            return Err(StoreError::Integrity(
                "CAP-H14 qualification-row digest differs".into(),
            ));
        }
        let manifest_sources = manifest
            .capsule_field_inventory
            .iter()
            .map(|row| row.bound_source.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let manifest_shapes = expected_shapes
            .iter()
            .map(|shape| {
                json!({
                    "branch": shape.branch,
                    "distribution": shape.distribution,
                    "canonical_bytes": shape.canonical_bytes
                })
            })
            .collect::<Vec<_>>();
        if self.census.fields.manifest_rows_sha256
            != nq_protocol::sha256_bytes(
                &canonical_json_bytes(&manifest.capsule_field_inventory)
                    .map_err(|error| StoreError::CanonicalJson(error.to_string()))?,
            )
            || self.census.sources.manifest_rows_sha256
                != nq_protocol::sha256_bytes(
                    &canonical_json_bytes(&manifest_sources)
                        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?,
                )
            || self.census.shapes.manifest_rows_sha256
                != nq_protocol::sha256_bytes(
                    &canonical_json_bytes(&manifest_shapes)
                        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?,
                )
        {
            return Err(StoreError::Integrity(
                "CAP-H14 manifest-row census digest differs".into(),
            ));
        }
        Ok(())
    }

    fn validate_attempts(&self) -> Result<(), StoreError> {
        if self.materialization_attempts.len() != 4 {
            return Err(StoreError::Invariant(
                "CAP-H14 materialization-attempt population differs".into(),
            ));
        }
        let receipt_sha256 = &self
            .qualification_budget
            .preallocation_receipt
            .receipt_sha256;
        let mut slots = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        for (shape, attempt) in self
            .census
            .shapes
            .rows
            .iter()
            .zip(&self.materialization_attempts)
        {
            if shape.branch != attempt.branch
                || shape.distribution != attempt.distribution
                || shape.attempt_identity != attempt.attempt_identity
                || attempt.budget_receipt_sha256 != *receipt_sha256
                || !slots.insert(attempt.slot_index)
                || !attempts.insert(attempt.attempt_identity.as_str())
            {
                return Err(StoreError::Invariant(
                    "CAP-H14 shape/slot/attempt/preallocation join differs".into(),
                ));
            }
            let conditional_holds = if shape.canonical_bytes
                > self
                    .qualification_budget
                    .maximum_single_canonical_witness_bytes
            {
                attempt.disposition == "pre-materialization-refused-budget"
                    && attempt.output_length_bytes.is_none()
                    && attempt.output_sha256.is_none()
                    && attempt.refusal_reason.as_deref()
                        == Some("symbolic-ceiling-exceeds-single-materialization-budget")
                    && attempt.observed_parallel_materializations == 0
            } else {
                attempt.disposition == "materialized"
                    && attempt.output_length_bytes == Some(shape.canonical_bytes)
                    && attempt.output_sha256.is_some()
                    && attempt.refusal_reason.is_none()
                    && attempt.observed_parallel_materializations == 1
            };
            if !conditional_holds {
                return Err(StoreError::Invariant(
                    "CAP-H14 materialization-attempt conditional differs".into(),
                ));
            }
            let receipt = canonical_json_bytes(&json!({
                "branch": &attempt.branch,
                "distribution": &attempt.distribution,
                "budget_receipt_sha256": &attempt.budget_receipt_sha256,
                "slot_index": attempt.slot_index,
                "attempt_identity": &attempt.attempt_identity,
                "disposition": &attempt.disposition,
                "output_length_bytes": attempt.output_length_bytes,
                "output_sha256": &attempt.output_sha256,
                "refusal_reason": &attempt.refusal_reason,
                "observed_parallel_materializations":
                    attempt.observed_parallel_materializations
            }))
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
            if attempt.attempt_receipt_canonical_bytes
                != u64::try_from(receipt.len()).map_err(|_| capacity_overflow())?
                || attempt.attempt_receipt_sha256 != nq_protocol::sha256_bytes(&receipt)
            {
                return Err(StoreError::Integrity(
                    "CAP-H14 materialization-attempt receipt bytes differ".into(),
                ));
            }
            let disposition = self
                .evidence_dispositions
                .iter()
                .find(|evidence| evidence.evidence_id == shape.evidence_case_id)
                .ok_or_else(|| {
                    StoreError::Invariant(format!(
                        "CAP-H14 shape {} lacks its evidence disposition",
                        shape.evidence_case_id
                    ))
                })?;
            if disposition.symbolic_ceiling_bytes != shape.canonical_bytes
                || disposition.actual_canonical_bytes != attempt.output_length_bytes
                || disposition.production_witness_sha256 != attempt.output_sha256
            {
                return Err(StoreError::Invariant(
                    "CAP-H14 attempt and evidence disposition differ".into(),
                ));
            }
        }
        if slots != BTreeSet::from([0, 1, 2, 3]) {
            return Err(StoreError::Invariant(
                "CAP-H14 materialization slots are not the exact closed set".into(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One closed eight-row evidence audit.
    fn validate_evidence_dispositions(&self) -> Result<(), StoreError> {
        if self.evidence_dispositions.len() != 8 {
            return Err(StoreError::Invariant(
                "CAP-H14 evidence-disposition population differs".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for evidence in &self.evidence_dispositions {
            if !seen.insert(evidence.evidence_id.as_str())
                || evidence.arithmetic_identity
                    != "nq.v3_projection_capsule_bound_independent_arithmetic.v1"
            {
                return Err(StoreError::Invariant(
                    "CAP-H14 evidence identity is duplicated or arithmetic-unbound".into(),
                ));
            }
            let conditional_holds = match evidence.disposition.as_str() {
                "ATTAINABLE-MATERIALIZED" => {
                    evidence.actual_canonical_bytes == Some(evidence.symbolic_ceiling_bytes)
                        && evidence.production_witness_sha256.is_some()
                        && evidence.unattainability_proof_identity.is_none()
                        && evidence.unattainability_proof_canonical_bytes.is_none()
                        && evidence.unattainability_proof_sha256.is_none()
                        && evidence.budget_identity.is_none()
                }
                "UNATTAINABLE-PROVED" => {
                    evidence
                        .actual_canonical_bytes
                        .is_some_and(|actual| actual < evidence.symbolic_ceiling_bytes)
                        && evidence.production_witness_sha256.is_some()
                        && evidence.unattainability_proof_identity.is_some()
                        && evidence.unattainability_proof_canonical_bytes.is_some()
                        && evidence.unattainability_proof_sha256.is_some()
                        && evidence.budget_identity.is_none()
                }
                "INFEASIBLE-UNDER-IDENTIFIED-BUDGET" => {
                    evidence.symbolic_ceiling_bytes
                        > self
                            .qualification_budget
                            .maximum_single_canonical_witness_bytes
                        && evidence.actual_canonical_bytes.is_none()
                        && evidence.production_witness_sha256.is_none()
                        && evidence.unattainability_proof_identity.is_none()
                        && evidence.unattainability_proof_canonical_bytes.is_none()
                        && evidence.unattainability_proof_sha256.is_none()
                        && evidence.budget_identity.as_deref()
                            == Some(CAP_H14_QUALIFICATION_BUDGET_IDENTITY)
                }
                _ => false,
            };
            if !conditional_holds {
                return Err(StoreError::Invariant(format!(
                    "CAP-H14 evidence conditional differs for {}",
                    evidence.evidence_id
                )));
            }
            let exact = match evidence.evidence_id.as_str() {
                CAP_H14_TRACTABLE_DESCRIPTOR_EVIDENCE_ID => {
                    evidence.scope == "descriptor_component"
                        && evidence.subject_identity == "nq.bounded-json-descriptor.2-4-3-2-2-3.v1"
                        && evidence.symbolic_ceiling_bytes == 121
                        && evidence.actual_canonical_bytes == Some(121)
                        && evidence
                            .production_witness_sha256
                            .as_ref()
                            .map(Sha256Digest::as_str)
                            == Some(
                                "sha256:d03d6778f9ae980e590eea7283bc96a135aa34cb254f876a176fe2c56f4a49de",
                            )
                        && evidence.source_constraints_identity
                            == "nq.protocol.BoundedJsonDescriptor.v1"
                }
                CAP_H14_UNATTAINABLE_DESCRIPTOR_EVIDENCE_ID => {
                    let proof = zero_key_uniqueness_unattainability_proof_receipt()?;
                    evidence.scope == "descriptor_component"
                        && evidence.subject_identity == "nq.bounded-json-descriptor.2-2-0-0-0-1.v1"
                        && evidence.symbolic_ceiling_bytes == 19
                        && evidence.actual_canonical_bytes == Some(10)
                        && evidence
                            .production_witness_sha256
                            .as_ref()
                            .map(Sha256Digest::as_str)
                            == Some(
                                "sha256:54755e5a76e179ba48aa9c21a030a938f63fcc7d7b7bd964754f2cb1795e8e1a",
                            )
                        && evidence.unattainability_proof_identity.as_deref()
                            == Some(
                                "nq.bounded-json-descriptor.unique-object-key-unattainability.v1",
                            )
                        && evidence.unattainability_proof_canonical_bytes
                            == Some(u64::try_from(proof.len()).map_err(|_| capacity_overflow())?)
                        && evidence.unattainability_proof_sha256
                            == Some(nq_protocol::sha256_bytes(&proof))
                        && evidence.source_constraints_identity
                            == "nq.protocol.BoundedJsonDescriptor.v1"
                }
                CAP_H14_ADMITTED_REPORT_SHAPE_EVIDENCE_ID => exact_infeasible_evidence(
                    evidence,
                    "closed_shape",
                    "nq.v3_projection_capsule.shape.admitted.all-report-level.v1",
                    133_038_721,
                    V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA,
                ),
                CAP_H14_ADMITTED_OBSERVED_SHAPE_EVIDENCE_ID => exact_infeasible_evidence(
                    evidence,
                    "closed_shape",
                    "nq.v3_projection_capsule.shape.admitted.one-per-observation-then-nested.v1",
                    133_034_626,
                    V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA,
                ),
                CAP_H14_NO_SUBMISSION_SHAPE_EVIDENCE_ID => exact_materialized_shape_evidence(
                    evidence,
                    "nq.v3_projection_capsule.shape.non-success-no-submission.v1",
                    68_127,
                    "sha256:b8b5c2a6af80d544c1977fec8521bfbadd80c728e0af4c7f17f4cb87dd8492ca",
                ),
                CAP_H14_REJECTED_SHAPE_EVIDENCE_ID => exact_materialized_shape_evidence(
                    evidence,
                    "nq.v3_projection_capsule.shape.non-success-rejected-submission.v1",
                    74_768,
                    "sha256:4c13e0ee18899a1d5490b0ad1752612009ab9cfcfc45a93b10e7b9adfca6f99a",
                ),
                CAP_H14_LARGE_DESCRIPTOR_EVIDENCE_ID => exact_infeasible_evidence(
                    evidence,
                    "generic_domain",
                    "nq.bounded-json-descriptor.2-0-u32-max-0-0-1.v1",
                    25_769_803_771,
                    "nq.protocol.BoundedJsonDescriptor.v1",
                ),
                CAP_H14_LARGE_CAPSULE_EVIDENCE_ID => exact_infeasible_evidence(
                    evidence,
                    "generic_domain",
                    "nq.v3_projection_capsule.large-generic-descriptor-full-capsule.v1",
                    3_509_873_159_972_371,
                    V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA,
                ),
                _ => false,
            };
            if !exact {
                return Err(StoreError::Invariant(format!(
                    "CAP-H14 exact evidence row differs for {}",
                    evidence.evidence_id
                )));
            }
        }
        Ok(())
    }
}

fn exact_infeasible_evidence(
    evidence: &ProjectionCapsuleQualificationEvidenceDispositionV1,
    scope: &str,
    subject: &str,
    symbolic: u64,
    source_constraints: &str,
) -> bool {
    evidence.scope == scope
        && evidence.subject_identity == subject
        && evidence.disposition == "INFEASIBLE-UNDER-IDENTIFIED-BUDGET"
        && evidence.symbolic_ceiling_bytes == symbolic
        && evidence.source_constraints_identity == source_constraints
}

fn exact_materialized_shape_evidence(
    evidence: &ProjectionCapsuleQualificationEvidenceDispositionV1,
    subject: &str,
    symbolic: u64,
    digest: &str,
) -> bool {
    evidence.scope == "closed_shape"
        && evidence.subject_identity == subject
        && evidence.disposition == "ATTAINABLE-MATERIALIZED"
        && evidence.symbolic_ceiling_bytes == symbolic
        && evidence
            .production_witness_sha256
            .as_ref()
            .map(Sha256Digest::as_str)
            == Some(digest)
        && evidence.source_constraints_identity == V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA
}

/// Immutable result of one test-only V3 capsule capacity-candidate
/// calculation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct V3ProjectionCapsuleCapacityCandidateV1 {
    schema: String,
    manifest_identity: String,
    sources_identity: Sha256Digest,
    dependency_generation_id: Sha256Digest,
    dependency_canonical_custody_digest: Sha256Digest,
    dependency_canonical_custody_bytes: u64,
    scalar_maxima: ProjectionCapsuleScalarMaximaV1,
    cardinalities: ProjectionCapsuleCardinalitiesV1,
    bounded_json: BTreeMap<String, ProjectionCapsuleBoundedJsonSourceV1>,
    shapes: Vec<PrelaunchClosureShapeV1>,
    maximum_canonical_bytes: u64,
}

impl V3ProjectionCapsuleCapacityCandidateV1 {
    /// Mechanically closed conservative symbolic ceiling over every physical
    /// branch.
    #[must_use]
    pub const fn maximum_canonical_bytes(&self) -> u64 {
        self.maximum_canonical_bytes
    }

    /// Exact source-set identity.
    #[must_use]
    pub const fn sources_identity(&self) -> &Sha256Digest {
        &self.sources_identity
    }

    /// Symbolic branch/distribution shapes evaluated without provider effect.
    #[must_use]
    pub fn shapes(&self) -> &[PrelaunchClosureShapeV1] {
        &self.shapes
    }

    fn validate_length(&self, actual: u64) -> Result<(), StoreError> {
        if actual > self.maximum_canonical_bytes {
            return Err(StoreError::Invariant(format!(
                "governed projection capsule is {actual} bytes; symbolic candidate pre-effect ceiling is {}",
                self.maximum_canonical_bytes
            )));
        }
        Ok(())
    }
}

/// Qualified pure-C1 capacity output with exact positive evidence identities.
///
/// This remains a test-only, pre-effect result. In particular, it does not
/// construct a Store allocation or satisfy the independent C3 gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualifiedV3ProjectionCapsuleCapacityCandidateV2 {
    schema: String,
    manifest_identity: String,
    manifest_sha256: Sha256Digest,
    qualification_id: Sha256Digest,
    qualification_sha256: Sha256Digest,
    qualification_basis_sha256: Sha256Digest,
    bound_evaluator_identity: String,
    sources_identity: Sha256Digest,
    dependency_generation_id: Sha256Digest,
    dependency_canonical_custody_digest: Sha256Digest,
    dependency_canonical_custody_bytes: u64,
    scalar_maxima: ProjectionCapsuleScalarMaximaV1,
    cardinalities: ProjectionCapsuleCardinalitiesV1,
    bounded_json: BTreeMap<String, ProjectionCapsuleBoundedJsonSourceV1>,
    shapes: Vec<PrelaunchClosureShapeV1>,
    maximum_canonical_bytes: u64,
}

fn qualified_projection_capsule_bound_v2(
    sources: &ProjectionCapsuleBoundSourcesV1,
) -> Result<QualifiedV3ProjectionCapsuleCapacityCandidateV2, StoreError> {
    let assets = nq_host_role_contract::require_qualified_v3_projection_capsule_bound_manifest_v2()
        .map_err(|error| StoreError::Integrity(error.to_string()))?;
    let manifest = V3ProjectionCapsuleBoundManifestV2::from_qualified_bytes(assets.manifest_bytes)?;
    let qualification = V3ProjectionCapsuleBoundQualificationV1::from_qualified_bytes(
        assets.qualification_bytes,
        &manifest,
        &assets,
    )?;
    let candidate =
        symbolic_candidate_projection_capsule_bound_v1_after_validation(&manifest.common, sources)?;
    Ok(QualifiedV3ProjectionCapsuleCapacityCandidateV2 {
        schema: "nq.v3_projection_capsule_capacity_candidate.v2".into(),
        manifest_identity: manifest.common.manifest_identity,
        manifest_sha256: assets.manifest_sha256,
        qualification_id: qualification.qualification_id,
        qualification_sha256: assets.qualification_sha256,
        qualification_basis_sha256: assets.qualification_basis_sha256,
        bound_evaluator_identity: manifest.common.bound_evaluator_identity,
        sources_identity: candidate.sources_identity,
        dependency_generation_id: candidate.dependency_generation_id,
        dependency_canonical_custody_digest: candidate.dependency_canonical_custody_digest,
        dependency_canonical_custody_bytes: candidate.dependency_canonical_custody_bytes,
        scalar_maxima: candidate.scalar_maxima,
        cardinalities: candidate.cardinalities,
        bounded_json: candidate.bounded_json,
        shapes: candidate.shapes,
        maximum_canonical_bytes: candidate.maximum_canonical_bytes,
    })
}

/// Refuse promotion of the inspectable candidate while its ratified
/// qualification gate remains blocked.
fn projection_capsule_bound_v1(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    sources: &ProjectionCapsuleBoundSourcesV1,
) -> Result<V3ProjectionCapsuleCapacityCandidateV1, StoreError> {
    manifest.validate()?;
    manifest.require_qualified_capacity_contract()?;
    symbolic_candidate_projection_capsule_bound_v1_after_validation(manifest, sources)
}

/// Derive the conservative symbolic ceiling for audit evidence only.
///
/// This test-only evaluator does not discharge CAP-H14 and cannot be reached
/// by product code. It exists so the candidate arithmetic, source closure,
/// and tractable serializer comparisons remain executable while the
/// materialized-maximum gate is explicitly blocked.
fn symbolic_candidate_projection_capsule_bound_v1(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    sources: &ProjectionCapsuleBoundSourcesV1,
) -> Result<V3ProjectionCapsuleCapacityCandidateV1, StoreError> {
    manifest.validate()?;
    symbolic_candidate_projection_capsule_bound_v1_after_validation(manifest, sources)
}

fn symbolic_candidate_projection_capsule_bound_v1_after_validation(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    sources: &ProjectionCapsuleBoundSourcesV1,
) -> Result<V3ProjectionCapsuleCapacityCandidateV1, StoreError> {
    for declaration in &manifest.bounded_json_sources {
        let actual = sources
            .bounded_json
            .get(&declaration.descriptor_key)
            .ok_or_else(|| {
                StoreError::Invariant(format!(
                    "capsule bound lacks declared source {}",
                    declaration.descriptor_key
                ))
            })?;
        if actual.source_identity != declaration.source_identity {
            return Err(StoreError::Invariant(format!(
                "capsule bound source identity for {} differs from the static manifest",
                declaration.descriptor_key
            )));
        }
        if actual.descriptor_pointer != declaration.descriptor_pointer
            || actual.source_record_schema != declaration.source_record_schema
        {
            return Err(StoreError::Invariant(format!(
                "capsule bound source descriptor pointer or record schema for {} differs from the static manifest",
                declaration.descriptor_key
            )));
        }
    }
    let mut shapes = Vec::new();
    for branch in ProjectionCapsuleOutcomeBranchV1::ALL {
        if branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
            for distribution in [CoverageDistribution::Report, CoverageDistribution::Observed] {
                shapes.push(symbolic_shape(manifest, sources, branch, distribution)?);
            }
        } else {
            shapes.push(symbolic_shape(
                manifest,
                sources,
                branch,
                CoverageDistribution::None,
            )?);
        }
    }
    let maximum_canonical_bytes = shapes
        .iter()
        .map(PrelaunchClosureShapeV1::canonical_bytes)
        .max()
        .ok_or_else(|| StoreError::Invariant("capsule bound has no closed outcome".into()))?;
    let sources_identity = semantic_digest(&json!({
        "schema": "nq.v3_projection_capsule_bound_sources.v1",
        "manifest_identity": &manifest.manifest_identity,
        "bounded_json": &sources.bounded_json,
        "dependency_generation_id": &sources.dependency_generation_id,
        "dependency_canonical_custody_digest": &sources.dependency_canonical_custody_digest,
        "dependency_canonical_custody_bytes": sources.dependency_canonical_custody_bytes,
    }))
    .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    Ok(V3ProjectionCapsuleCapacityCandidateV1 {
        schema: "nq.v3_projection_capsule_capacity_candidate.v1".into(),
        manifest_identity: manifest.manifest_identity.clone(),
        sources_identity,
        dependency_generation_id: sources.dependency_generation_id.clone(),
        dependency_canonical_custody_digest: sources.dependency_canonical_custody_digest.clone(),
        dependency_canonical_custody_bytes: sources.dependency_canonical_custody_bytes,
        scalar_maxima: manifest.scalar_maxima.clone(),
        cardinalities: manifest.cardinalities.clone(),
        bounded_json: sources.bounded_json.clone(),
        shapes,
        maximum_canonical_bytes,
    })
}

/// Validate exact constructed bytes against an identified symbolic candidate
/// and its exact dependency source.
fn validate_capsule_against_symbolic_candidate_bound_v1(
    capsule: &GovernedProjectionCapsule,
    capacity: &V3ProjectionCapsuleCapacityCandidateV1,
) -> Result<(), StoreError> {
    let actual = u64::try_from(capsule.canonical_bytes().as_bytes().len())
        .map_err(|_| StoreError::Invariant("capsule length overflowed".into()))?;
    capacity.validate_length(actual)?;
    let value: Value = serde_json::from_slice(capsule.canonical_bytes().as_bytes())
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    let dependency = value
        .pointer(
            "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody",
        )
        .ok_or_else(|| {
            StoreError::Invariant(
                "capsule has no exact runtime dependency custody for its candidate source closure"
                    .into(),
            )
        })?;
    let dependency_bytes = canonical_json_bytes(dependency)
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
    let dependency_length = u64::try_from(dependency_bytes.len())
        .map_err(|_| StoreError::Invariant("dependency custody length overflowed".into()))?;
    if dependency_length != capacity.dependency_canonical_custody_bytes
        || nq_protocol::sha256_bytes(&dependency_bytes)
            != capacity.dependency_canonical_custody_digest
        || value
            .pointer(
                "/diagnostic/local_origin/execution_binding/runtime_records/dependency/dependency_generation_id",
            )
            .and_then(Value::as_str)
            != Some(capacity.dependency_generation_id.as_str())
    {
        return Err(StoreError::Integrity(
            "capsule dependency custody differs from identified candidate pre-effect sources"
                .into(),
        ));
    }
    validate_capsule_value_against_bound(&value, capacity)?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // One exhaustive typed-input boundary audit.
fn validate_capsule_input_against_symbolic_candidate_bound_v1(
    input: &GovernedProjectionCapsuleInput,
    capacity: &V3ProjectionCapsuleCapacityCandidateV1,
) -> Result<(), StoreError> {
    let scalar = &capacity.scalar_maxima;
    let cardinalities = &capacity.cardinalities;
    let text = |label: &str, value: &str| {
        validate_text(label, value, scalar.non_generic_string_utf8_bytes)
    };
    let time = |label: &str, value: &str| {
        validate_timestamp(label, value, scalar.rfc3339_timestamp_utf8_bytes)
    };
    let document = |slot: &str, value: &CanonicalDocument| {
        let decoded: Value = serde_json::from_slice(value.as_bytes())
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        capacity
            .bounded_json
            .get(slot)
            .ok_or_else(|| {
                StoreError::Invariant(format!("capsule capacity has no descriptor for {slot}"))
            })?
            .descriptor
            .validate(&decoded)
            .map_err(|error| {
                StoreError::Invariant(format!(
                    "capsule value for {slot} exceeds its identified descriptor: {error}"
                ))
            })
    };

    let branch = match (
        input.mode,
        input
            .collection
            .submission
            .as_ref()
            .map(|submission| &submission.disposition),
    ) {
        (GovernedProjectionCapsuleMode::Admitted, Some(SubmissionDisposition::Admitted(_))) => {
            ProjectionCapsuleOutcomeBranchV1::Admitted
        }
        (GovernedProjectionCapsuleMode::NonSuccess, None) => {
            ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission
        }
        (
            GovernedProjectionCapsuleMode::NonSuccess,
            Some(SubmissionDisposition::Rejected { .. }),
        ) => ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected,
        _ => {
            return Err(StoreError::Invariant(
                "capsule mode and physical submission branch disagree".into(),
            ));
        }
    };
    match (
        branch,
        input.expected_semantic_digest.is_some(),
        input.publication.report_sequence,
    ) {
        (ProjectionCapsuleOutcomeBranchV1::Admitted, true, Some(sequence))
            if sequence > 0
                && u64::try_from(sequence)
                    .is_ok_and(|value| value <= scalar.positive_publication_sequence) => {}
        (
            ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission
            | ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected,
            false,
            None,
        ) => {}
        _ => {
            return Err(StoreError::Invariant(
                "capsule semantic digest or report sequence disagrees with its physical branch"
                    .into(),
            ));
        }
    }
    if input.publication.status_sequence <= 0
        || u64::try_from(input.publication.status_sequence)
            .map_or(true, |value| value > scalar.positive_publication_sequence)
    {
        return Err(StoreError::Invariant(
            "capsule status sequence exceeds the exact-I-JSON publication bound".into(),
        ));
    }
    text(
        "projection publication acknowledgment_id",
        &input.publication.acknowledgment_id,
    )?;
    time(
        "projection publication acknowledgment_committed_at",
        &input.publication.acknowledgment_committed_at,
    )?;
    if u64::try_from(input.collection.intake.raw_bytes.len())
        .map_or(true, |length| length > scalar.raw_byte_length)
    {
        return Err(StoreError::Invariant(
            "capsule raw capture exceeds its committed scalar maximum".into(),
        ));
    }

    validate_collection_scalars(&input.collection, scalar)?;
    document("provider_intake_context", &input.collection.intake.context)?;
    document(
        "provider_intake_interpretation",
        &input.collection.intake.interpretation,
    )?;
    document(
        "provider_intake_native_outcome",
        &input.collection.intake.native_outcome,
    )?;
    document(
        "run_execution_identity",
        &input.collection.run.execution_identity,
    )?;
    document(
        "run_resource_outcome",
        &input.collection.run.resource_outcome,
    )?;

    if let Some(submission) = &input.collection.submission {
        text("submission_id", &submission.submission_id)?;
        text("submission protocol_outcome", &submission.protocol_outcome)?;
        time("submission received_at", &submission.received_at)?;
        match &submission.disposition {
            SubmissionDisposition::Rejected { refusal } => {
                for (label, value) in [
                    ("refusal_id", refusal.refusal_id.as_str()),
                    ("refusal source_kind", refusal.source_kind.as_str()),
                    (
                        "refusal responsible_instance_id",
                        refusal.responsible_instance_id.as_str(),
                    ),
                    ("refusal boundary", refusal.boundary.as_str()),
                    ("refusal code", refusal.code.as_str()),
                ] {
                    text(label, value)?;
                }
                if let Some(profile_semantic_id) = &refusal.profile_semantic_id {
                    text("refusal profile_semantic_id", profile_semantic_id)?;
                }
                time("refusal created_at", &refusal.created_at)?;
                document("refusal_detail", &refusal.detail)?;
            }
            SubmissionDisposition::Admitted(report) => {
                for (label, value) in [
                    ("report_id", report.report_id.as_str()),
                    ("report instance_id", report.instance_id.as_str()),
                    ("report profile_id", report.profile_id.as_str()),
                    ("report profile_version", report.profile_version.as_str()),
                    ("report profile_digest", report.profile_digest.as_str()),
                    ("report status", report.report_status.as_str()),
                ] {
                    text(label, value)?;
                }
                for (label, value) in [
                    ("report observed_at", report.observed_at.as_str()),
                    ("report received_at", report.received_at.as_str()),
                    ("report admitted_at", report.admitted_at.as_str()),
                ] {
                    time(label, value)?;
                }
                if report.observations.len()
                    > usize::try_from(cardinalities.observations.maximum).map_err(|_| {
                        StoreError::Invariant("observation maximum overflowed".into())
                    })?
                    || report.errors.len()
                        > usize::try_from(cardinalities.report_errors.maximum)
                            .map_err(|_| StoreError::Invariant("error maximum overflowed".into()))?
                {
                    return Err(StoreError::Invariant(
                        "capsule report exceeds committed collection cardinality".into(),
                    ));
                }
                let coverage_count = report.observations.iter().try_fold(
                    report.coverage.len(),
                    |count, observation| {
                        count
                            .checked_add(observation.coverage.len())
                            .ok_or_else(|| {
                                StoreError::Invariant(
                                    "capsule aggregate coverage cardinality overflowed".into(),
                                )
                            })
                    },
                )?;
                if coverage_count
                    > usize::try_from(cardinalities.total_coverage_entries.maximum)
                        .map_err(|_| StoreError::Invariant("coverage maximum overflowed".into()))?
                {
                    return Err(StoreError::Invariant(
                        "capsule report exceeds committed aggregate coverage cardinality".into(),
                    ));
                }
                document("canonical_report", &report.canonical_report)?;
                document("validated_report", &report.validated_report)?;
                if let Some(next_checkpoint) = &report.next_checkpoint {
                    document("next_checkpoint", next_checkpoint)?;
                }
                for coverage in &report.coverage {
                    validate_coverage_scalars(coverage, scalar)?;
                    document("coverage_detail", &coverage.detail)?;
                }
                for observation in &report.observations {
                    validate_ordinal(
                        "observation ordinal",
                        observation.ordinal,
                        cardinalities.observations.maximum,
                    )?;
                    text("observation kind", &observation.kind)?;
                    time("observation observed_at", &observation.observed_at)?;
                    document("observation_subject", &observation.subject)?;
                    document("observation_payload", &observation.payload)?;
                    for coverage in &observation.coverage {
                        validate_coverage_scalars(coverage, scalar)?;
                        document("coverage_detail", &coverage.detail)?;
                    }
                }
                for error in &report.errors {
                    validate_ordinal(
                        "report error ordinal",
                        error.ordinal,
                        cardinalities.report_errors.maximum,
                    )?;
                    text("report error code", &error.code)?;
                    document("report_error_detail", &error.detail)?;
                }
            }
        }
    }

    for (label, value) in [
        (
            "diagnostic contract_schema",
            input.diagnostic_artifact.contract_schema.as_str(),
        ),
        (
            "diagnostic origin run_id",
            input.diagnostic_artifact.local_origin.run_id.as_str(),
        ),
        ("status_event_id", input.status.status_event_id.as_str()),
        (
            "status component_kind",
            input.status.component_kind.as_str(),
        ),
        ("status component_id", input.status.component_id.as_str()),
        ("status state", input.status.state.as_str()),
        ("status code", input.status.code.as_str()),
    ] {
        text(label, value)?;
    }
    time(
        "diagnostic origin completed_at",
        &input.diagnostic_artifact.local_origin.completed_at,
    )?;
    time("status observed_at", &input.status.observed_at)?;
    document("status_detail", &input.status.detail)?;

    let binding = input
        .diagnostic_artifact
        .local_origin
        .execution_binding
        .as_ref()
        .ok_or_else(|| {
            StoreError::Invariant(
                "bounded V3 capsule requires the complete production execution binding".into(),
            )
        })?;
    if binding.provider_attempts.len()
        != usize::try_from(cardinalities.provider_attempt_bindings.maximum)
            .map_err(|_| StoreError::Invariant("attempt maximum overflowed".into()))?
        || binding.runtime_records.records.len()
            != usize::try_from(cardinalities.runtime_records.maximum)
                .map_err(|_| StoreError::Invariant("record maximum overflowed".into()))?
    {
        return Err(StoreError::Invariant(
            "bounded V3 capsule requires exactly one provider attempt and two runtime records"
                .into(),
        ));
    }
    if input
        .diagnostic_artifact
        .local_origin
        .evaluation_id
        .is_some()
    {
        return Err(StoreError::Invariant(
            "bounded production V3 capsule cannot carry a detector evaluation origin".into(),
        ));
    }
    for (label, value) in [
        (
            "runtime checkpoint_id",
            binding.runtime_records.checkpoint_id.as_str(),
        ),
        (
            "execution_binding_record_id",
            binding.execution_binding_record_id.as_str(),
        ),
        (
            "outer_request_record_id",
            binding.outer_request_record_id.as_str(),
        ),
        (
            "invocation_decision_record_id",
            binding.invocation_decision_record_id.as_str(),
        ),
        (
            "execution_launch_record_id",
            binding.execution_launch_record_id.as_str(),
        ),
        ("outer_request_id", binding.outer_request_id.as_str()),
    ] {
        text(label, value)?;
    }
    if let Some(predecessor) = &binding.runtime_records.expected_predecessor_checkpoint_id {
        text("runtime predecessor checkpoint_id", predecessor)?;
    }
    if binding.runtime_records.dependency.dependency_generation_id
        != capacity.dependency_generation_id
        || binding
            .runtime_records
            .dependency
            .canonical_custody
            .as_bytes()
            .len()
            != usize::try_from(capacity.dependency_canonical_custody_bytes).map_err(|_| {
                StoreError::Invariant("dependency custody maximum is not addressable".into())
            })?
        || Sha256Digest::parse(
            binding
                .runtime_records
                .dependency
                .canonical_custody
                .digest()
                .to_owned(),
        )
        .map_err(|error| StoreError::Invariant(error.to_string()))?
            != capacity.dependency_canonical_custody_digest
    {
        return Err(StoreError::Integrity(
            "capsule input dependency differs from identified candidate pre-effect sources".into(),
        ));
    }
    for record in &binding.runtime_records.records {
        text("runtime record_id", &record.record_id)?;
        text("runtime record_schema", &record.record_schema)?;
        time("runtime record committed_at", &record.committed_at)?;
        document("runtime_record_canonical_bytes", &record.canonical_bytes)?;
    }
    for attempt in &binding.provider_attempts {
        text(
            "provider_attempt_record_id",
            &attempt.provider_attempt_record_id,
        )?;
        text("provider attempt intake_id", &attempt.intake_id)?;
    }
    Ok(())
}

fn validate_collection_scalars(
    collection: &CollectionInput,
    maxima: &ProjectionCapsuleScalarMaximaV1,
) -> Result<(), StoreError> {
    let text = |label: &str, value: &str| {
        validate_text(label, value, maxima.non_generic_string_utf8_bytes)
    };
    let time = |label: &str, value: &str| {
        validate_timestamp(label, value, maxima.rfc3339_timestamp_utf8_bytes)
    };
    let intake = &collection.intake;
    for (label, value) in [
        ("intake_id", intake.intake_id.as_str()),
        ("attempt_id", intake.attempt_id.as_str()),
        ("idempotency_key", intake.idempotency_key.as_str()),
        ("provider request_id", intake.request_id.as_str()),
        (
            "provider_admission_id",
            intake.provider_admission_id.as_str(),
        ),
        ("source_admission_id", intake.source_admission_id.as_str()),
        ("origin_carrier", intake.origin_carrier.as_str()),
        (
            "checkpoint_contract_digest",
            intake.checkpoint_contract_digest.as_str(),
        ),
        (
            "provider_protocol_identity",
            intake.provider_protocol_identity.as_str(),
        ),
        ("binding_digest", intake.binding_digest.as_str()),
        ("provider instance_id", intake.instance_id.as_str()),
        ("provider profile_id", intake.profile_id.as_str()),
        ("provider profile_version", intake.profile_version.as_str()),
        ("provider profile_digest", intake.profile_digest.as_str()),
        ("interpretation_kind", intake.interpretation_kind.as_str()),
        ("native_outcome_kind", intake.native_outcome_kind.as_str()),
    ] {
        text(label, value)?;
    }
    if intake.provider_sequence.is_some() {
        return Err(StoreError::Invariant(
            "bounded production V3 capsule cannot carry a local-helper provider sequence".into(),
        ));
    }
    for (label, value) in [
        ("provider deadline_at", intake.deadline_at.as_str()),
        ("provider started_at", intake.started_at.as_str()),
        ("provider finished_at", intake.finished_at.as_str()),
        ("provider received_at", intake.received_at.as_str()),
    ] {
        time(label, value)?;
    }
    let run = &collection.run;
    for (label, value) in [
        ("run_id", run.run_id.as_str()),
        ("run request_id", run.request_id.as_str()),
        ("run instance_id", run.instance_id.as_str()),
        ("run binding_digest", run.binding_digest.as_str()),
        (
            "run checkpoint_contract_digest",
            run.checkpoint_contract_digest.as_str(),
        ),
        ("run profile_id", run.profile_id.as_str()),
        ("run profile_version", run.profile_version.as_str()),
        ("run profile_digest", run.profile_digest.as_str()),
        ("run carrier", run.carrier.as_str()),
        ("run acquisition_outcome", run.acquisition_outcome.as_str()),
    ] {
        text(label, value)?;
    }
    if let Some(admission_id) = &run.admission_id {
        text("run admission_id", admission_id)?;
    }
    for (label, value) in [
        ("run started_at", run.started_at.as_str()),
        ("run deadline_at", run.deadline_at.as_str()),
        ("run finished_at", run.finished_at.as_str()),
    ] {
        time(label, value)?;
    }
    Ok(())
}

fn validate_coverage_scalars(
    coverage: &crate::CoverageInput,
    maxima: &ProjectionCapsuleScalarMaximaV1,
) -> Result<(), StoreError> {
    validate_ordinal(
        "coverage ordinal",
        coverage.ordinal,
        nq_protocol::MAX_COVERAGE_ENTRIES
            .try_into()
            .map_err(|_| StoreError::Invariant("coverage maximum overflowed".into()))?,
    )?;
    validate_text(
        "coverage kind",
        &coverage.coverage_kind,
        maxima.non_generic_string_utf8_bytes,
    )?;
    validate_text(
        "coverage state",
        &coverage.coverage_state,
        maxima.non_generic_string_utf8_bytes,
    )
}

fn validate_ordinal(label: &str, value: u32, maximum_count: u32) -> Result<(), StoreError> {
    if value >= maximum_count {
        return Err(StoreError::Invariant(format!(
            "{label} {value} exceeds maximum cardinality {maximum_count}"
        )));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, maximum: u64) -> Result<(), StoreError> {
    let actual = u64::try_from(value.len())
        .map_err(|_| StoreError::Invariant(format!("{label} length overflowed")))?;
    if actual > maximum {
        return Err(StoreError::Invariant(format!(
            "{label} has {actual} UTF-8 bytes; maximum is {maximum}"
        )));
    }
    Ok(())
}

fn validate_timestamp(label: &str, value: &str, maximum: u64) -> Result<(), StoreError> {
    validate_text(label, value, maximum)?;
    if chrono::DateTime::parse_from_rfc3339(value).is_err() {
        return Err(StoreError::Invariant(format!(
            "{label} is not an RFC 3339 timestamp"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One exhaustive canonical-value boundary audit.
fn validate_capsule_value_against_bound(
    value: &Value,
    capacity: &V3ProjectionCapsuleCapacityCandidateV1,
) -> Result<(), StoreError> {
    validate_value_tree(value, "", capacity)?;
    let submission = value.pointer("/collection/submission").ok_or_else(|| {
        StoreError::Invariant("capsule lacks its closed submission branch".into())
    })?;
    let mode = value.get("mode").and_then(Value::as_str);
    let expected_digest = value.get("expected_semantic_digest");
    let report_sequence = value.pointer("/publication/report_sequence");
    match (
        mode,
        submission.is_null(),
        submission
            .pointer("/disposition/disposition")
            .and_then(Value::as_str),
        expected_digest,
        report_sequence,
    ) {
        (
            Some("admitted"),
            false,
            Some("admitted"),
            Some(Value::String(_)),
            Some(Value::Number(_)),
        )
        | (Some("non_success"), true, None, Some(Value::Null), Some(Value::Null))
        | (Some("non_success"), false, Some("rejected"), Some(Value::Null), Some(Value::Null)) => {}
        _ => {
            return Err(StoreError::Invariant(
                "capsule serialized mode, submission, digest, or report sequence branch disagrees"
                    .into(),
            ));
        }
    }

    let provider_attempts = value
        .pointer("/diagnostic/local_origin/execution_binding/provider_attempts")
        .and_then(Value::as_array)
        .ok_or_else(|| StoreError::Invariant("capsule lacks provider-attempt bindings".into()))?;
    let runtime_records = value
        .pointer("/diagnostic/local_origin/execution_binding/runtime_records/records")
        .and_then(Value::as_array)
        .ok_or_else(|| StoreError::Invariant("capsule lacks terminal runtime records".into()))?;
    if provider_attempts.len()
        != usize::try_from(capacity.cardinalities.provider_attempt_bindings.maximum)
            .map_err(|_| StoreError::Invariant("attempt maximum overflowed".into()))?
        || runtime_records.len()
            != usize::try_from(capacity.cardinalities.runtime_records.maximum)
                .map_err(|_| StoreError::Invariant("record maximum overflowed".into()))?
    {
        return Err(StoreError::Invariant(
            "capsule serialized cardinality differs from the committed product shape".into(),
        ));
    }
    let distinct_record_ids = runtime_records
        .iter()
        .filter_map(|record| record.get("record_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if distinct_record_ids.len() != runtime_records.len() {
        return Err(StoreError::Invariant(
            "capsule terminal runtime records do not have distinct identities".into(),
        ));
    }

    if let Some(report) = submission.pointer("/disposition/report") {
        let observations = report
            .get("observations")
            .and_then(Value::as_array)
            .ok_or_else(|| StoreError::Invariant("capsule report lacks observations".into()))?;
        let report_coverage = report
            .get("coverage")
            .and_then(Value::as_array)
            .ok_or_else(|| StoreError::Invariant("capsule report lacks coverage".into()))?;
        let errors = report
            .get("errors")
            .and_then(Value::as_array)
            .ok_or_else(|| StoreError::Invariant("capsule report lacks errors".into()))?;
        let nested_coverage = observations
            .iter()
            .try_fold(0_usize, |count, observation| {
                let coverage = observation
                    .get("coverage")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        StoreError::Invariant("capsule observation lacks its coverage array".into())
                    })?;
                count.checked_add(coverage.len()).ok_or_else(|| {
                    StoreError::Invariant(
                        "capsule aggregate coverage cardinality overflowed".into(),
                    )
                })
            })?;
        if observations.len()
            > usize::try_from(capacity.cardinalities.observations.maximum)
                .map_err(|_| StoreError::Invariant("observation maximum overflowed".into()))?
            || errors.len()
                > usize::try_from(capacity.cardinalities.report_errors.maximum)
                    .map_err(|_| StoreError::Invariant("error maximum overflowed".into()))?
            || report_coverage
                .len()
                .checked_add(nested_coverage)
                .is_none_or(|count| {
                    count
                        > usize::try_from(capacity.cardinalities.total_coverage_entries.maximum)
                            .unwrap_or(usize::MAX)
                })
        {
            return Err(StoreError::Invariant(
                "capsule serialized report exceeds committed cardinality".into(),
            ));
        }
    }
    Ok(())
}

fn validate_value_tree(
    value: &Value,
    pointer: &str,
    capacity: &V3ProjectionCapsuleCapacityCandidateV1,
) -> Result<(), StoreError> {
    if let Some((_, slot)) = PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES
        .iter()
        .find(|(family, _)| *family !=
            "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody"
            && pointer_matches_family(pointer, family))
    {
        capacity
            .bounded_json
            .get(*slot)
            .ok_or_else(|| {
                StoreError::Invariant(format!("capsule capacity has no descriptor for {slot}"))
            })?
            .descriptor
            .validate(value)
            .map_err(|error| {
                StoreError::Invariant(format!(
                    "capsule value at {pointer} exceeds its identified descriptor: {error}"
                ))
            })?;
        return Ok(());
    }
    if pointer
        == "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody"
    {
        return Ok(());
    }
    match value {
        Value::String(text) => {
            if is_timestamp_pointer(pointer) {
                validate_timestamp(
                    pointer,
                    text,
                    capacity.scalar_maxima.rfc3339_timestamp_utf8_bytes,
                )
            } else {
                validate_text(
                    pointer,
                    text,
                    capacity.scalar_maxima.non_generic_string_utf8_bytes,
                )
            }
        }
        Value::Number(number) => {
            let representation = number.to_string();
            if representation.len()
                > usize::from(capacity.scalar_maxima.ijson_integer_decimal_width)
                || number.as_i64().is_some_and(|integer| {
                    !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&integer)
                })
                || number
                    .as_u64()
                    .is_some_and(|integer| integer > 9_007_199_254_740_991)
                || (!number.is_i64() && !number.is_u64())
            {
                return Err(StoreError::Invariant(format!(
                    "capsule integer at {pointer} exceeds exact-I-JSON limits"
                )));
            }
            Ok(())
        }
        Value::Array(array) => {
            for child in array {
                validate_value_tree(child, &format!("{pointer}/*"), capacity)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for (key, child) in object {
                validate_value_tree(child, &format!("{pointer}/{key}"), capacity)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) => Ok(()),
    }
}

fn pointer_matches_family(pointer: &str, family: &str) -> bool {
    let actual = pointer.split('/').skip(1).collect::<Vec<_>>();
    let expected = family.split('/').skip(1).collect::<Vec<_>>();
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| expected == "*" || actual == &expected)
}

fn is_timestamp_pointer(pointer: &str) -> bool {
    [
        "/started_at",
        "/deadline_at",
        "/finished_at",
        "/received_at",
        "/observed_at",
        "/admitted_at",
        "/created_at",
        "/completed_at",
        "/committed_at",
        "/acknowledgment_committed_at",
    ]
    .iter()
    .any(|suffix| pointer.ends_with(suffix))
}

#[derive(Clone, Copy)]
enum CoverageDistribution {
    None,
    Report,
    Observed,
}

fn symbolic_shape(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    sources: &ProjectionCapsuleBoundSourcesV1,
    outcome_branch: ProjectionCapsuleOutcomeBranchV1,
    coverage_distribution: CoverageDistribution,
) -> Result<PrelaunchClosureShapeV1, StoreError> {
    let canonical_bytes =
        capsule_document_bound(manifest, sources, outcome_branch, coverage_distribution)?;
    Ok(PrelaunchClosureShapeV1 {
        outcome_branch,
        coverage_distribution: match coverage_distribution {
            CoverageDistribution::None => "not_applicable",
            CoverageDistribution::Report => "all_report_level",
            CoverageDistribution::Observed => "one_per_observation_then_nested",
        }
        .into(),
        provider_attempts: manifest.cardinalities.provider_attempt_bindings.maximum,
        runtime_records: manifest.cardinalities.runtime_records.maximum,
        canonical_bytes,
    })
}

fn capsule_document_bound(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    sources: &ProjectionCapsuleBoundSourcesV1,
    branch: ProjectionCapsuleOutcomeBranchV1,
    coverage_distribution: CoverageDistribution,
) -> Result<u64, StoreError> {
    let shape_witness =
        crate::governed_projection_capsule::projection_capsule_symbolic_shape_witness_v1(branch)?;
    let production_shape = production_shape_bound(
        &shape_witness,
        "",
        manifest,
        sources,
        branch,
        coverage_distribution,
    )?;
    let independent =
        hand_derived_capsule_document_bound(manifest, sources, branch, coverage_distribution)?;
    if production_shape != independent {
        return Err(StoreError::Invariant(format!(
            "production capsule serializer shape bound {production_shape} differs from independent field derivation {independent}"
        )));
    }
    Ok(production_shape)
}

// Independent arithmetic oracle for CAP-H14. These functions deliberately do
// not call the production traversal's object/array/string/decimal helpers.
// Keeping a second checked recurrence makes a shared undercount visible.
fn oracle_object_bound(fields: &[(&str, u64)]) -> Result<u64, StoreError> {
    let mut total = 1_u64; // opening brace
    for (index, (key, value)) in fields.iter().enumerate() {
        if index != 0 {
            total = total.checked_add(1).ok_or_else(capacity_overflow)?;
        }
        total = total
            .checked_add(oracle_fixed_string_bound(key)?)
            .and_then(|sum| sum.checked_add(1)) // colon
            .and_then(|sum| sum.checked_add(*value))
            .ok_or_else(capacity_overflow)?;
    }
    total.checked_add(1).ok_or_else(capacity_overflow) // closing brace
}

fn oracle_mixed_array_bound(groups: &[(u64, u64)]) -> Result<u64, StoreError> {
    let mut count = 0_u64;
    let mut member_bytes = 0_u64;
    for &(group_count, element_bytes) in groups {
        count = count
            .checked_add(group_count)
            .ok_or_else(capacity_overflow)?;
        member_bytes = member_bytes
            .checked_add(
                group_count
                    .checked_mul(element_bytes)
                    .ok_or_else(capacity_overflow)?,
            )
            .ok_or_else(capacity_overflow)?;
    }
    let separators = count.saturating_sub(1);
    2_u64
        .checked_add(member_bytes)
        .and_then(|sum| sum.checked_add(separators))
        .ok_or_else(capacity_overflow)
}

fn oracle_array_bound(element: u64, count: u64) -> Result<u64, StoreError> {
    oracle_mixed_array_bound(&[(count, element)])
}

const fn oracle_optional_bound(present: u64) -> u64 {
    if present > 4 { present } else { 4 }
}

fn oracle_escaped_string_bound(maximum_utf8_bytes: u64) -> Result<u64, StoreError> {
    2_u64
        .checked_add(
            maximum_utf8_bytes
                .checked_mul(6)
                .ok_or_else(capacity_overflow)?,
        )
        .ok_or_else(capacity_overflow)
}

fn oracle_ascii_string_bound(maximum_ascii_bytes: u64) -> Result<u64, StoreError> {
    maximum_ascii_bytes
        .checked_add(2)
        .ok_or_else(capacity_overflow)
}

fn oracle_decimal_bound(value: u64) -> Result<u64, StoreError> {
    u64::try_from(value.to_string().len())
        .map_err(|_| StoreError::Invariant("oracle decimal width overflowed".into()))
}

fn oracle_fixed_string_bound(value: &str) -> Result<u64, StoreError> {
    let mut total = 2_u64; // quotes
    for character in value.chars() {
        let width = match character {
            '"' | '\\' | '\u{0008}' | '\u{0009}' | '\u{000a}' | '\u{000c}' | '\u{000d}' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => u64::try_from(character.len_utf8())
                .map_err(|_| StoreError::Invariant("oracle string width overflowed".into()))?,
        };
        total = total.checked_add(width).ok_or_else(capacity_overflow)?;
    }
    Ok(total)
}

fn oracle_descriptor_bound(descriptor: &BoundedJsonDescriptor) -> Result<u64, StoreError> {
    let key = oracle_escaped_string_bound(descriptor.maximum_key_utf8_bytes())?;
    let string = oracle_escaped_string_bound(descriptor.maximum_string_utf8_bytes())?;
    let mut child = 5_u64
        .max(string)
        .max(u64::from(descriptor.maximum_integer_decimal_width()))
        .max(2);
    for _ in 1..descriptor.maximum_depth() {
        let array = oracle_array_bound(child, u64::from(descriptor.maximum_array_items()))?;
        let object_member = key
            .checked_add(1) // colon
            .and_then(|sum| sum.checked_add(child))
            .ok_or_else(capacity_overflow)?;
        let object = oracle_mixed_array_bound(&[(
            u64::from(descriptor.maximum_properties_per_object()),
            object_member,
        )])?;
        child = child.max(array).max(object);
    }
    Ok(child)
}

fn oracle_semantic_variant_bound(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    source_identity: &str,
) -> Result<u64, StoreError> {
    manifest
        .semantic_outcome_variants
        .iter()
        .find(|family| {
            family.source_identity == source_identity
                && family.representation_location == "capsule_branch_selector"
        })
        .ok_or_else(|| {
            StoreError::Invariant(format!(
                "oracle lacks direct semantic family {source_identity}"
            ))
        })?
        .variants
        .iter()
        .map(|variant| oracle_fixed_string_bound(variant))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or_else(|| {
            StoreError::Invariant(format!("oracle semantic family {source_identity} is empty"))
        })
}

#[allow(clippy::too_many_lines)] // Independent closed JCS arithmetic for the full carrier.
fn hand_derived_capsule_document_bound(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    sources: &ProjectionCapsuleBoundSourcesV1,
    branch: ProjectionCapsuleOutcomeBranchV1,
    coverage_distribution: CoverageDistribution,
) -> Result<u64, StoreError> {
    let scalar = &manifest.scalar_maxima;
    let cardinalities = &manifest.cardinalities;
    // Local bindings intentionally shadow the production helpers throughout
    // the hand-derived formula below.
    let object_bound = oracle_object_bound;
    let array_bound = oracle_array_bound;
    let mixed_array_bound = oracle_mixed_array_bound;
    let optional_bound = oracle_optional_bound;
    let fixed_string_bound = oracle_fixed_string_bound;
    let text = oracle_escaped_string_bound(scalar.non_generic_string_utf8_bytes)?;
    let timestamp = oracle_ascii_string_bound(scalar.rfc3339_timestamp_utf8_bytes)?;
    let digest = oracle_ascii_string_bound(u64::from(scalar.sha256_string_utf8_bytes))?;
    let sequence = oracle_decimal_bound(scalar.positive_publication_sequence)?;
    let byte_length = oracle_decimal_bound(scalar.raw_byte_length)?;
    let observation_ordinal = u64::from(scalar.ordinal_decimal_width);
    let coverage_ordinal = oracle_decimal_bound(u64::from(
        cardinalities
            .total_coverage_entries
            .maximum
            .saturating_sub(1),
    ))?;
    let error_ordinal = oracle_decimal_bound(u64::from(
        cardinalities.report_errors.maximum.saturating_sub(1),
    ))?;
    let generic = |slot: &str| {
        let descriptor = sources.descriptor(slot)?;
        let independently_derived = oracle_descriptor_bound(descriptor)?;
        if independently_derived != descriptor.maximum_canonical_bytes() {
            return Err(StoreError::Invariant(format!(
                "oracle descriptor ceiling for {slot} differs from the admitted descriptor"
            )));
        }
        Ok(independently_derived)
    };
    let semantic = |source_identity: &str| oracle_semantic_variant_bound(manifest, source_identity);

    let coverage = object_bound(&[
        ("coverage_kind", text),
        (
            "coverage_state",
            semantic("nq.core.semantic_coverage_state_projection.v1")?,
        ),
        ("detail", generic("coverage_detail")?),
        ("ordinal", coverage_ordinal),
    ])?;
    let empty_coverage = array_bound(coverage, 0)?;
    let one_coverage = array_bound(coverage, 1)?;
    let observation_empty = object_bound(&[
        ("coverage", empty_coverage),
        ("kind", text),
        ("observed_at", timestamp),
        ("ordinal", observation_ordinal),
        ("payload", generic("observation_payload")?),
        ("subject", generic("observation_subject")?),
    ])?;
    let observation_one = object_bound(&[
        ("coverage", one_coverage),
        ("kind", text),
        ("observed_at", timestamp),
        ("ordinal", observation_ordinal),
        ("payload", generic("observation_payload")?),
        ("subject", generic("observation_subject")?),
    ])?;
    let observations = match coverage_distribution {
        CoverageDistribution::Observed => mixed_array_bound(&[
            (
                u64::from(cardinalities.total_coverage_entries.maximum),
                observation_one,
            ),
            (
                u64::from(
                    cardinalities
                        .observations
                        .maximum
                        .checked_sub(cardinalities.total_coverage_entries.maximum)
                        .ok_or_else(|| {
                            StoreError::Invariant(
                                "coverage cardinality exceeds observations".into(),
                            )
                        })?,
                ),
                observation_empty,
            ),
        ])?,
        CoverageDistribution::Report | CoverageDistribution::None => array_bound(
            observation_empty,
            u64::from(cardinalities.observations.maximum),
        )?,
    };
    let report_coverage_count = if matches!(coverage_distribution, CoverageDistribution::Report) {
        u64::from(cardinalities.total_coverage_entries.maximum)
    } else {
        0
    };
    let report_error = object_bound(&[
        ("code", text),
        ("detail", generic("report_error_detail")?),
        ("ordinal", error_ordinal),
    ])?;
    let report = object_bound(&[
        ("admitted_at", timestamp),
        ("canonical_report", generic("canonical_report")?),
        ("coverage", array_bound(coverage, report_coverage_count)?),
        (
            "errors",
            array_bound(report_error, u64::from(cardinalities.report_errors.maximum))?,
        ),
        ("instance_id", text),
        (
            "next_checkpoint",
            optional_bound(generic("next_checkpoint")?),
        ),
        ("observations", observations),
        ("observed_at", timestamp),
        ("profile_digest", text),
        ("profile_id", text),
        ("profile_version", text),
        ("received_at", timestamp),
        ("report_id", text),
        (
            "report_status",
            semantic("nq.core.semantic_report_status_projection.v1")?,
        ),
        ("validated_report", generic("validated_report")?),
    ])?;
    let refusal = object_bound(&[
        (
            "boundary",
            semantic("nq.core.governed_refusal_projections.boundary_union.v1")?,
        ),
        (
            "code",
            semantic("nq.core.governed_refusal_projections.code_union.v1")?,
        ),
        ("created_at", timestamp),
        ("detail", generic("refusal_detail")?),
        ("profile_semantic_id", optional_bound(text)),
        ("refusal_id", text),
        ("responsible_instance_id", text),
        (
            "source_kind",
            semantic("nq.core.governed_refusal_projections.source_kind.v1")?,
        ),
    ])?;
    let admitted_disposition = object_bound(&[
        ("disposition", fixed_string_bound("admitted")?),
        ("report", report),
    ])?;
    let rejected_disposition = object_bound(&[
        ("disposition", fixed_string_bound("rejected")?),
        ("refusal", refusal),
    ])?;
    let submission = match branch {
        ProjectionCapsuleOutcomeBranchV1::Admitted => object_bound(&[
            ("disposition", admitted_disposition),
            (
                "protocol_outcome",
                semantic("nq.core.NativeGovernedSqlCommitPlan.protocol_outcome.v1")?,
            ),
            ("received_at", timestamp),
            ("submission_id", text),
        ])?,
        ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected => object_bound(&[
            ("disposition", rejected_disposition),
            (
                "protocol_outcome",
                semantic("nq.core.NativeGovernedSqlCommitPlan.protocol_outcome.v1")?,
            ),
            ("received_at", timestamp),
            ("submission_id", text),
        ])?,
        ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission => 4,
    };
    let intake = object_bound(&[
        ("admission_context_digest", digest),
        ("attempt_id", text),
        ("binding_digest", text),
        ("checkpoint_contract_digest", text),
        ("context", generic("provider_intake_context")?),
        ("deadline_at", timestamp),
        ("evaluator_artifact_digest", digest),
        ("execution_identity_digest", digest),
        ("finished_at", timestamp),
        ("idempotency_key", text),
        ("instance_id", text),
        ("intake_id", text),
        ("interpretation", generic("provider_intake_interpretation")?),
        (
            "interpretation_kind",
            semantic("nq.core.ProviderResponseInterpretationV1.kind.v1")?,
        ),
        ("native_outcome", generic("provider_intake_native_outcome")?),
        (
            "native_outcome_kind",
            semantic("nq.core.ProjectedAcquisitionOutcome.v1")?,
        ),
        ("origin_carrier", text),
        ("profile_digest", text),
        ("profile_id", text),
        ("profile_semantic_id", digest),
        ("profile_version", text),
        ("provider_admission_id", text),
        ("provider_artifact_digest", digest),
        ("provider_config_digest", digest),
        ("provider_protocol_identity", text),
        ("provider_semantic_id", digest),
        ("provider_sequence", 4),
        ("received_at", timestamp),
        ("request_id", text),
        ("source_admission_id", text),
        ("started_at", timestamp),
    ])?;
    let run = object_bound(&[
        (
            "acquisition_outcome",
            semantic("nq.core.ProjectedAcquisitionOutcome.v1")?,
        ),
        ("admission_id", optional_bound(text)),
        ("binding_digest", text),
        ("carrier", text),
        ("checkpoint_contract_digest", text),
        ("deadline_at", timestamp),
        ("execution_identity", generic("run_execution_identity")?),
        ("finished_at", timestamp),
        ("instance_id", text),
        ("profile_digest", text),
        ("profile_id", text),
        ("profile_version", text),
        ("request_id", text),
        ("resource_outcome", generic("run_resource_outcome")?),
        ("run_id", text),
        ("started_at", timestamp),
    ])?;
    let collection = object_bound(&[("intake", intake), ("run", run), ("submission", submission)])?;

    let runtime_record = object_bound(&[
        (
            "canonical_bytes",
            generic("runtime_record_canonical_bytes")?,
        ),
        ("canonical_bytes_digest", digest),
        ("committed_at", timestamp),
        ("record_id", text),
        ("record_schema", text),
    ])?;
    let dependency = object_bound(&[
        (
            "canonical_custody",
            sources.dependency_canonical_custody_bytes,
        ),
        ("canonical_custody_digest", digest),
        ("dependency_generation_id", digest),
        ("trust_anchor_id", digest),
    ])?;
    let runtime_records = object_bound(&[
        ("checkpoint_id", text),
        ("dependency", dependency),
        ("expected_predecessor_checkpoint_id", optional_bound(text)),
        ("expected_predecessor_ledger_root", optional_bound(digest)),
        (
            "records",
            array_bound(
                runtime_record,
                u64::from(cardinalities.runtime_records.maximum),
            )?,
        ),
    ])?;
    let provider_attempt =
        object_bound(&[("intake_id", text), ("provider_attempt_record_id", text)])?;
    let execution_binding = object_bound(&[
        ("execution_binding_record_id", text),
        ("execution_launch_record_id", text),
        ("invocation_decision_record_id", text),
        ("outer_request_id", text),
        ("outer_request_record_id", text),
        (
            "provider_attempts",
            array_bound(
                provider_attempt,
                u64::from(cardinalities.provider_attempt_bindings.maximum),
            )?,
        ),
        ("runtime_records", runtime_records),
    ])?;
    let local_origin = object_bound(&[
        ("completed_at", timestamp),
        ("evaluation_id", 4),
        ("execution_binding", execution_binding),
        ("run_id", text),
    ])?;
    let diagnostic = object_bound(&[
        ("artifact_id", digest),
        ("canonical_bytes_digest", digest),
        (
            "contract_schema",
            fixed_string_bound("nq.diagnostic_execution.v2")?,
        ),
        ("local_origin", local_origin),
    ])?;
    let publication = object_bound(&[
        ("acknowledgment_committed_at", timestamp),
        ("acknowledgment_id", text),
        (
            "report_sequence",
            if branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
                sequence
            } else {
                4
            },
        ),
        ("status_sequence", sequence),
    ])?;
    let raw_capture = object_bound(&[("byte_length", byte_length), ("bytes_digest", digest)])?;
    let status = object_bound(&[
        (
            "code",
            semantic("nq.core.governed_execution_status_projection.code.v1")?,
        ),
        ("component_id", text),
        (
            "component_kind",
            fixed_string_bound("diagnostic_execution")?,
        ),
        ("detail", generic("status_detail")?),
        ("observed_at", timestamp),
        (
            "state",
            semantic("nq.core.governed_execution_status_projection.state.v1")?,
        ),
        ("status_event_id", text),
    ])?;
    object_bound(&[
        ("capsule_id", digest),
        ("collection", collection),
        ("diagnostic", diagnostic),
        (
            "expected_semantic_digest",
            if branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
                digest
            } else {
                4
            },
        ),
        (
            "mode",
            fixed_string_bound(if branch == ProjectionCapsuleOutcomeBranchV1::Admitted {
                "admitted"
            } else {
                "non_success"
            })?,
        ),
        ("publication", publication),
        ("raw_capture", raw_capture),
        ("reservation_record_id", digest),
        (
            "schema",
            fixed_string_bound(crate::GOVERNED_PROJECTION_CAPSULE_SCHEMA)?,
        ),
        ("status", status),
    ])
}

#[allow(clippy::too_many_lines)] // One exhaustive production-shape traversal.
fn production_shape_bound(
    value: &Value,
    pointer: &str,
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    sources: &ProjectionCapsuleBoundSourcesV1,
    branch: ProjectionCapsuleOutcomeBranchV1,
    coverage_distribution: CoverageDistribution,
) -> Result<u64, StoreError> {
    if let Some((_, slot)) = PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES
        .iter()
        .find(|(family, _)| {
            *family
                != "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody"
                && pointer_matches_family(pointer, family)
        })
    {
        return sources
            .descriptor(slot)
            .map(BoundedJsonDescriptor::maximum_canonical_bytes);
    }
    if pointer
        == "/diagnostic/local_origin/execution_binding/runtime_records/dependency/canonical_custody"
    {
        return Ok(sources.dependency_canonical_custody_bytes);
    }
    if let Some(bound) = physical_branch_source_bound(manifest, branch, pointer, value)? {
        return Ok(bound);
    }
    if value.is_null() {
        return Ok(4);
    }
    if let Some(source_identity) = semantic_enum_source(pointer)
        && source_identity != PROJECTION_CAPSULE_PHYSICAL_BRANCH_SOURCE
    {
        return manifest.direct_semantic_variant_bound(source_identity);
    }
    if is_timestamp_pointer(pointer) {
        return ascii_string_bound(manifest.scalar_maxima.rfc3339_timestamp_utf8_bytes);
    }
    if is_digest_pointer(pointer) {
        return exact_ascii_string_bound(u64::from(
            manifest.scalar_maxima.sha256_string_utf8_bytes,
        ));
    }
    if pointer.ends_with("/ordinal") {
        let maximum =
            if pointer == "/collection/submission/disposition/report/observations/*/ordinal" {
                manifest.cardinalities.observations.maximum
            } else if pointer == "/collection/submission/disposition/report/errors/*/ordinal" {
                manifest.cardinalities.report_errors.maximum
            } else {
                manifest.cardinalities.total_coverage_entries.maximum
            };
        return decimal_bound(u64::from(maximum.saturating_sub(1)));
    }
    if pointer == "/raw_capture/byte_length" {
        return decimal_bound(manifest.scalar_maxima.raw_byte_length);
    }
    if pointer.ends_with("/report_sequence") || pointer.ends_with("/status_sequence") {
        return decimal_bound(manifest.scalar_maxima.positive_publication_sequence);
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => u64::try_from(
            canonical_json_bytes(value)
                .map_err(|error| StoreError::CanonicalJson(error.to_string()))?
                .len(),
        )
        .map_err(|_| StoreError::Invariant("capsule scalar bound overflowed".into())),
        Value::Object(object) => {
            let mut fields = Vec::with_capacity(object.len());
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{key}");
                fields.push((
                    key.as_str(),
                    production_shape_bound(
                        child,
                        &child_pointer,
                        manifest,
                        sources,
                        branch,
                        coverage_distribution,
                    )?,
                ));
            }
            object_bound(&fields)
        }
        Value::Array(array) => {
            if array.is_empty()
                && pointer == "/collection/submission/disposition/report/observations/*/coverage"
                && !matches!(coverage_distribution, CoverageDistribution::Observed)
            {
                return Ok(2);
            }
            let element = array.first().ok_or_else(|| {
                StoreError::Invariant(format!(
                    "production capsule symbolic shape witness has an empty array at {pointer}"
                ))
            })?;
            let wildcard = format!("{pointer}/*");
            match pointer {
                "/collection/submission/disposition/report/observations" => {
                    let mut empty = element.clone();
                    empty
                        .as_object_mut()
                        .and_then(|object| object.get_mut("coverage"))
                        .map(|coverage| *coverage = Value::Array(Vec::new()))
                        .ok_or_else(|| {
                            StoreError::Invariant(
                                "production observation shape witness lacks coverage".into(),
                            )
                        })?;
                    let empty_bound = production_shape_bound(
                        &empty,
                        &wildcard,
                        manifest,
                        sources,
                        branch,
                        CoverageDistribution::None,
                    )?;
                    if matches!(coverage_distribution, CoverageDistribution::Observed) {
                        let one_bound = production_shape_bound(
                            element,
                            &wildcard,
                            manifest,
                            sources,
                            branch,
                            CoverageDistribution::Observed,
                        )?;
                        mixed_array_bound(&[
                            (
                                u64::from(manifest.cardinalities.total_coverage_entries.maximum),
                                one_bound,
                            ),
                            (
                                u64::from(
                                    manifest
                                        .cardinalities
                                        .observations
                                        .maximum
                                        .checked_sub(
                                            manifest.cardinalities.total_coverage_entries.maximum,
                                        )
                                        .ok_or_else(|| {
                                            StoreError::Invariant(
                                                "coverage cardinality exceeds observations".into(),
                                            )
                                        })?,
                                ),
                                empty_bound,
                            ),
                        ])
                    } else {
                        array_bound(
                            empty_bound,
                            u64::from(manifest.cardinalities.observations.maximum),
                        )
                    }
                }
                "/collection/submission/disposition/report/coverage" => {
                    let count = if matches!(coverage_distribution, CoverageDistribution::Report) {
                        u64::from(manifest.cardinalities.total_coverage_entries.maximum)
                    } else {
                        0
                    };
                    let bound = production_shape_bound(
                        element,
                        &wildcard,
                        manifest,
                        sources,
                        branch,
                        coverage_distribution,
                    )?;
                    array_bound(bound, count)
                }
                "/collection/submission/disposition/report/observations/*/coverage" => {
                    let count = u64::from(matches!(
                        coverage_distribution,
                        CoverageDistribution::Observed
                    ));
                    let bound = production_shape_bound(
                        element,
                        &wildcard,
                        manifest,
                        sources,
                        branch,
                        coverage_distribution,
                    )?;
                    array_bound(bound, count)
                }
                "/collection/submission/disposition/report/errors" => {
                    let bound = production_shape_bound(
                        element,
                        &wildcard,
                        manifest,
                        sources,
                        branch,
                        coverage_distribution,
                    )?;
                    array_bound(
                        bound,
                        u64::from(manifest.cardinalities.report_errors.maximum),
                    )
                }
                "/diagnostic/local_origin/execution_binding/provider_attempts" => {
                    let bound = production_shape_bound(
                        element,
                        &wildcard,
                        manifest,
                        sources,
                        branch,
                        coverage_distribution,
                    )?;
                    array_bound(
                        bound,
                        u64::from(manifest.cardinalities.provider_attempt_bindings.maximum),
                    )
                }
                "/diagnostic/local_origin/execution_binding/runtime_records/records" => {
                    let bound = production_shape_bound(
                        element,
                        &wildcard,
                        manifest,
                        sources,
                        branch,
                        coverage_distribution,
                    )?;
                    array_bound(
                        bound,
                        u64::from(manifest.cardinalities.runtime_records.maximum),
                    )
                }
                _ => Err(StoreError::Invariant(format!(
                    "production capsule shape witness contains an unclassified array at {pointer}"
                ))),
            }
        }
    }
}

/// Resolve one branch-selected physical field against the exact manifest row.
///
/// Physical branch selectors are not native semantic families and therefore
/// do not belong in `semantic_outcome_variants`. Their source is the closed
/// `physical_branches` table itself. Scalar selectors return their exact
/// branch-local bound; container selectors validate the branch tag and then
/// continue structural traversal so every descendant remains accounted for.
fn physical_branch_source_bound(
    manifest: &V3ProjectionCapsuleBoundManifestV1,
    branch: ProjectionCapsuleOutcomeBranchV1,
    pointer: &str,
    value: &Value,
) -> Result<Option<u64>, StoreError> {
    let declaration = manifest
        .physical_branches
        .iter()
        .find(|declaration| declaration.branch == branch)
        .ok_or_else(|| {
            StoreError::Invariant(format!(
                "capsule-bound manifest lacks physical branch {branch:?}"
            ))
        })?;
    let mismatch = || {
        StoreError::Invariant(format!(
            "production capsule field {pointer} differs from physical branch {branch:?}"
        ))
    };
    match pointer {
        "/mode" => {
            if value.as_str() != Some(declaration.mode.as_str()) {
                return Err(mismatch());
            }
            fixed_string_bound(&declaration.mode).map(Some)
        }
        "/expected_semantic_digest" => match declaration.expected_semantic_digest.as_str() {
            "required" if value.as_str().is_some() => {
                exact_ascii_string_bound(u64::from(manifest.scalar_maxima.sha256_string_utf8_bytes))
                    .map(Some)
            }
            "absent" if value.is_null() => Ok(Some(4)),
            _ => Err(mismatch()),
        },
        "/publication/report_sequence" => match declaration.report_sequence.as_str() {
            "required" if value.as_i64().is_some_and(|sequence| sequence > 0) => {
                decimal_bound(manifest.scalar_maxima.positive_publication_sequence).map(Some)
            }
            "absent" if value.is_null() => Ok(Some(4)),
            _ => Err(mismatch()),
        },
        "/collection/submission" => match declaration.submission.as_str() {
            "absent" if value.is_null() => Ok(Some(4)),
            "admitted" | "rejected"
                if value
                    .pointer("/disposition/disposition")
                    .and_then(Value::as_str)
                    == Some(declaration.submission.as_str()) =>
            {
                Ok(None)
            }
            _ => Err(mismatch()),
        },
        "/collection/submission/disposition" => {
            if !matches!(declaration.submission.as_str(), "admitted" | "rejected")
                || value.get("disposition").and_then(Value::as_str)
                    != Some(declaration.submission.as_str())
            {
                return Err(mismatch());
            }
            Ok(None)
        }
        "/collection/submission/disposition/disposition" => {
            if value.as_str() != Some(declaration.submission.as_str())
                || !matches!(declaration.submission.as_str(), "admitted" | "rejected")
            {
                return Err(mismatch());
            }
            fixed_string_bound(&declaration.submission).map(Some)
        }
        _ => Ok(None),
    }
}

fn object_bound(fields: &[(&str, u64)]) -> Result<u64, StoreError> {
    if fields.is_empty() {
        return Ok(2);
    }
    let mut total = 2_u64;
    for (index, (key, value)) in fields.iter().enumerate() {
        total = total
            .checked_add(fixed_string_bound(key)?)
            .and_then(|sum| sum.checked_add(1))
            .and_then(|sum| sum.checked_add(*value))
            .ok_or_else(capacity_overflow)?;
        if index + 1 != fields.len() {
            total = total.checked_add(1).ok_or_else(capacity_overflow)?;
        }
    }
    Ok(total)
}

fn array_bound(element: u64, count: u64) -> Result<u64, StoreError> {
    if count == 0 {
        return Ok(2);
    }
    count
        .checked_mul(element)
        .and_then(|sum| sum.checked_add(count - 1))
        .and_then(|sum| sum.checked_add(2))
        .ok_or_else(capacity_overflow)
}

fn mixed_array_bound(groups: &[(u64, u64)]) -> Result<u64, StoreError> {
    let mut count = 0_u64;
    let mut members = 0_u64;
    for (group_count, element) in groups {
        count = count
            .checked_add(*group_count)
            .ok_or_else(capacity_overflow)?;
        members = members
            .checked_add(
                group_count
                    .checked_mul(*element)
                    .ok_or_else(capacity_overflow)?,
            )
            .ok_or_else(capacity_overflow)?;
    }
    if count == 0 {
        Ok(2)
    } else {
        members
            .checked_add(count - 1)
            .and_then(|sum| sum.checked_add(2))
            .ok_or_else(capacity_overflow)
    }
}

const fn optional_bound(present: u64) -> u64 {
    if present > 4 { present } else { 4 }
}

fn escaped_string_bound(maximum_utf8_bytes: u64) -> Result<u64, StoreError> {
    maximum_utf8_bytes
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or_else(capacity_overflow)
}

fn ascii_string_bound(maximum_bytes: u64) -> Result<u64, StoreError> {
    maximum_bytes.checked_add(2).ok_or_else(capacity_overflow)
}

fn exact_ascii_string_bound(exact_bytes: u64) -> Result<u64, StoreError> {
    ascii_string_bound(exact_bytes)
}

fn fixed_string_bound(value: &str) -> Result<u64, StoreError> {
    u64::try_from(
        canonical_json_bytes(&Value::String(value.to_owned()))
            .map_err(|error| StoreError::CanonicalJson(error.to_string()))?
            .len(),
    )
    .map_err(|_| StoreError::Invariant("fixed capsule string length overflowed".into()))
}

fn decimal_bound(maximum: u64) -> Result<u64, StoreError> {
    u64::try_from(maximum.to_string().len())
        .map_err(|_| StoreError::Invariant("capsule integer width overflowed".into()))
}

fn capacity_overflow() -> StoreError {
    StoreError::Invariant("V3 projection capsule capacity arithmetic overflowed".into())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Seek, SeekFrom, Write},
        os::unix::fs::MetadataExt,
        path::PathBuf,
    };

    use serde_json::{Map, json};
    use tempfile::tempdir;

    use super::*;

    const QUALIFICATION_WITNESS_SLOT_BYTES: u64 = 16 * 1024 * 1024;
    const QUALIFICATION_WITNESS_SLOT_COUNT: u64 = 4;
    const QUALIFICATION_WITNESS_PREALLOCATION_BYTES: u64 =
        QUALIFICATION_WITNESS_SLOT_BYTES * QUALIFICATION_WITNESS_SLOT_COUNT;
    const QUALIFICATION_WITNESS_MAXIMUM_PARALLELISM: u64 = 1;

    #[derive(Debug)]
    struct QualificationMaterializationRun {
        budget_receipt: Vec<u8>,
        attempt_receipts: Vec<Vec<u8>>,
        materialized_witnesses: BTreeMap<String, Vec<u8>>,
    }

    fn source_set(
        manifest: &V3ProjectionCapsuleBoundManifestV1,
        descriptor: &BoundedJsonDescriptor,
    ) -> ProjectionCapsuleBoundSourcesV1 {
        let descriptor_bytes =
            canonical_json_bytes(&serde_json::to_value(descriptor).expect("descriptor value"))
                .expect("canonical descriptor");
        let descriptor_digest = nq_protocol::sha256_bytes(&descriptor_bytes);
        let sources = manifest
            .bounded_json_sources
            .iter()
            .map(|declaration| {
                ProjectionCapsuleBoundedJsonSourceV1::from_canonical_source_record(
                    declaration.descriptor_key.clone(),
                    declaration.source_identity.clone(),
                    descriptor_digest.clone(),
                    descriptor_bytes.clone(),
                    declaration.descriptor_pointer.clone(),
                )
                .expect("exact bounded-JSON source")
            })
            .collect::<Vec<_>>();
        let dependency =
            CanonicalDocument::from_serializable(&json!({})).expect("dependency document");
        ProjectionCapsuleBoundSourcesV1::new(
            sources,
            nq_protocol::sha256_bytes(b"candidate-dependency-generation"),
            &dependency,
        )
        .expect("closed source set")
    }

    fn replace_pointer_family(value: &mut Value, family: &str, replacement: &Value) -> usize {
        fn descend(value: &mut Value, segments: &[&str], replacement: &Value) -> usize {
            let Some((head, tail)) = segments.split_first() else {
                *value = replacement.clone();
                return 1;
            };
            if *head == "*" {
                return value.as_array_mut().map_or(0, |array| {
                    array
                        .iter_mut()
                        .map(|child| descend(child, tail, replacement))
                        .sum()
                });
            }
            value
                .as_object_mut()
                .and_then(|object| object.get_mut(*head))
                .map_or(0, |child| descend(child, tail, replacement))
        }
        descend(
            value,
            &family.split('/').skip(1).collect::<Vec<_>>(),
            replacement,
        )
    }

    fn tractable_descriptor_maximum_value() -> Value {
        Value::Object(Map::from_iter([
            ("\0\0".to_owned(), Value::String("\0\0".to_owned())),
            ("\0\u{1}".to_owned(), Value::String("\0\0".to_owned())),
            ("\0\u{2}".to_owned(), Value::String("\0\0".to_owned())),
            ("\0\u{3}".to_owned(), Value::String("\0\0".to_owned())),
        ]))
    }

    fn materialized_tractable_branch_maximum(
        branch: ProjectionCapsuleOutcomeBranchV1,
    ) -> Result<Vec<u8>, StoreError> {
        let manifest =
            inspected_v3_projection_capsule_bound_candidate_v1().expect("inspect candidate");
        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        let descriptor_maximum = tractable_descriptor_maximum_value();
        let descriptor_bytes = descriptor
            .canonical_bytes(&descriptor_maximum)
            .expect("tractable descriptor maximum");
        assert_eq!(descriptor_bytes.len(), 121);

        let mut value =
            crate::governed_projection_capsule::projection_capsule_symbolic_shape_witness_v1(
                branch,
            )?;
        let exact_dependency_custody = json!({});
        for (family, source) in PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES {
            let replacement = if source == "authenticated_runtime_dependency_custody" {
                &exact_dependency_custody
            } else {
                &descriptor_maximum
            };
            replace_pointer_family(&mut value, family, replacement);
        }
        for field in &manifest.capsule_field_inventory {
            let Some(family) = manifest.semantic_outcome_variants.iter().find(|family| {
                field.classification == "option_or_enum"
                    && field.bound_source == family.source_identity
                    && family.representation_location == "capsule_branch_selector"
            }) else {
                continue;
            };
            let maximum = family
                .variants
                .iter()
                .max_by(|left, right| {
                    let left_length = canonical_json_bytes(&Value::String((*left).clone()))
                        .expect("semantic variant bytes")
                        .len();
                    let right_length = canonical_json_bytes(&Value::String((*right).clone()))
                        .expect("semantic variant bytes")
                        .len();
                    left_length.cmp(&right_length).then_with(|| left.cmp(right))
                })
                .expect("nonempty semantic variant family");
            replace_pointer_family(
                &mut value,
                &field.pointer_family,
                &Value::String(maximum.clone()),
            );
        }
        canonical_json_bytes(&value).map_err(|error| StoreError::CanonicalJson(error.to_string()))
    }

    #[allow(clippy::too_many_lines)] // One closed four-shape qualification run.
    fn qualification_materialization_run() -> Result<QualificationMaterializationRun, StoreError> {
        let directory = tempdir().map_err(StoreError::Io)?;
        let path = directory
            .path()
            .join("qualification-witness-preallocation.bin");
        let mut backing = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(StoreError::Io)?;
        let touch = vec![0_u8; 1024 * 1024];
        for _ in 0..(QUALIFICATION_WITNESS_PREALLOCATION_BYTES
            / u64::try_from(touch.len()).map_err(|_| capacity_overflow())?)
        {
            backing.write_all(&touch).map_err(StoreError::Io)?;
        }
        backing.sync_all().map_err(StoreError::Io)?;
        let metadata = backing.metadata().map_err(StoreError::Io)?;
        let allocated_bytes = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(capacity_overflow)?;
        if metadata.len() != QUALIFICATION_WITNESS_PREALLOCATION_BYTES
            || allocated_bytes < QUALIFICATION_WITNESS_PREALLOCATION_BYTES
        {
            return Err(StoreError::Invariant(format!(
                "qualification witness backing is sparse or incomplete: logical {}, allocated {allocated_bytes}",
                metadata.len()
            )));
        }

        let budget_receipt = canonical_json_bytes(&json!({
            "schema": "nq.v3_projection_capsule_qualification_budget_enforcement_receipt.v1",
            "budget_identity":
                "nq.host-role-runtime-seam.cap-h14-materialization-budget.v1",
            "maximum_single_canonical_witness_bytes": QUALIFICATION_WITNESS_SLOT_BYTES,
            "closed_shape_count": QUALIFICATION_WITNESS_SLOT_COUNT,
            "maximum_total_preallocated_witness_bytes":
                QUALIFICATION_WITNESS_PREALLOCATION_BYTES,
            "maximum_parallel_witnesses": QUALIFICATION_WITNESS_MAXIMUM_PARALLELISM,
            "backing": {
                "kind": "one_file_four_fixed_slots",
                "logical_bytes": QUALIFICATION_WITNESS_PREALLOCATION_BYTES,
                "minimum_physically_allocated_bytes":
                    QUALIFICATION_WITNESS_PREALLOCATION_BYTES,
                "allocated_block_bytes": allocated_bytes,
                "slot_count": QUALIFICATION_WITNESS_SLOT_COUNT,
                "slot_bytes": QUALIFICATION_WITNESS_SLOT_BYTES,
                "touch_method": "sequential_full_byte_write_then_sync_all",
                "sparse_declaration_accepted": false
            },
            "qualification_only": true,
            "runtime_store_effect": false
        }))
        .map_err(|error| StoreError::CanonicalJson(error.to_string()))?;
        let budget_receipt_sha256 = nq_protocol::sha256_bytes(&budget_receipt);
        let attempts = [
            (
                0_u64,
                ProjectionCapsuleOutcomeBranchV1::Admitted,
                "admitted",
                "all_report_level",
                CAP_H14_ADMITTED_REPORT_SHAPE_EVIDENCE_ID,
                "nq.cap-h14.materialization-attempt.admitted-all-report-level.v1",
                133_038_721_u64,
            ),
            (
                1,
                ProjectionCapsuleOutcomeBranchV1::Admitted,
                "admitted",
                "one_per_observation_then_nested",
                CAP_H14_ADMITTED_OBSERVED_SHAPE_EVIDENCE_ID,
                "nq.cap-h14.materialization-attempt.admitted-one-per-observation-then-nested.v1",
                133_034_626,
            ),
            (
                2,
                ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission,
                "non_success_no_submission",
                "not_applicable",
                CAP_H14_NO_SUBMISSION_SHAPE_EVIDENCE_ID,
                "nq.cap-h14.materialization-attempt.non-success-no-submission.v1",
                68_127,
            ),
            (
                3,
                ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected,
                "non_success_rejected_submission",
                "not_applicable",
                CAP_H14_REJECTED_SHAPE_EVIDENCE_ID,
                "nq.cap-h14.materialization-attempt.non-success-rejected-submission.v1",
                74_768,
            ),
        ];
        let mut attempt_receipts = Vec::with_capacity(attempts.len());
        let mut materialized_witnesses = BTreeMap::new();
        for (
            slot_index,
            branch,
            branch_name,
            distribution,
            evidence_case_id,
            attempt_identity,
            symbolic_ceiling_bytes,
        ) in attempts
        {
            let (disposition, output_length_bytes, output_sha256, refusal_reason, parallelism) =
                if symbolic_ceiling_bytes > QUALIFICATION_WITNESS_SLOT_BYTES {
                    (
                        "pre-materialization-refused-budget",
                        None,
                        None,
                        Some("symbolic-ceiling-exceeds-single-materialization-budget"),
                        0_u64,
                    )
                } else {
                    let witness = materialized_tractable_branch_maximum(branch)?;
                    let output_length = u64::try_from(witness.len())
                        .map_err(|_| StoreError::Invariant("witness length overflowed".into()))?;
                    if output_length != symbolic_ceiling_bytes
                        || output_length > QUALIFICATION_WITNESS_SLOT_BYTES
                    {
                        return Err(StoreError::Invariant(format!(
                            "qualification witness {evidence_case_id} differs from its closed slot ceiling"
                        )));
                    }
                    backing
                        .seek(SeekFrom::Start(
                            slot_index
                                .checked_mul(QUALIFICATION_WITNESS_SLOT_BYTES)
                                .ok_or_else(capacity_overflow)?,
                        ))
                        .map_err(StoreError::Io)?;
                    backing.write_all(&witness).map_err(StoreError::Io)?;
                    let digest = nq_protocol::sha256_bytes(&witness);
                    materialized_witnesses.insert(evidence_case_id.to_owned(), witness);
                    ("materialized", Some(output_length), Some(digest), None, 1)
                };
            attempt_receipts.push(
                canonical_json_bytes(&json!({
                    "branch": branch_name,
                    "distribution": distribution,
                    "budget_receipt_sha256": budget_receipt_sha256,
                    "slot_index": slot_index,
                    "attempt_identity": attempt_identity,
                    "disposition": disposition,
                    "output_length_bytes": output_length_bytes,
                    "output_sha256": output_sha256,
                    "refusal_reason": refusal_reason,
                    "observed_parallel_materializations": parallelism
                }))
                .map_err(|error| StoreError::CanonicalJson(error.to_string()))?,
            );
        }
        backing.sync_all().map_err(StoreError::Io)?;
        drop(backing);
        drop(directory);
        Ok(QualificationMaterializationRun {
            budget_receipt,
            attempt_receipts,
            materialized_witnesses,
        })
    }

    #[test]
    fn blocked_cap_h14_is_load_bearing_before_candidate_promotion() {
        let manifest =
            inspected_v3_projection_capsule_bound_candidate_v1().expect("inspect candidate");
        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        let sources = source_set(&manifest, &descriptor);
        let error =
            projection_capsule_bound_v1(&manifest, &sources).expect_err("CAP-H14 must block");
        assert!(
            error
                .to_string()
                .contains("not qualified; blocked gate(s): CAP-H14")
        );
    }

    #[test]
    fn qualified_v2_assets_are_parsed_by_store_and_emit_exact_positive_identities() {
        let assets =
            nq_host_role_contract::require_qualified_v3_projection_capsule_bound_manifest_v2()
                .expect("positive host-contract asset pair");
        let manifest =
            V3ProjectionCapsuleBoundManifestV2::from_qualified_bytes(assets.manifest_bytes)
                .expect("Store parses qualified v2 manifest");
        let qualification = V3ProjectionCapsuleBoundQualificationV1::from_qualified_bytes(
            assets.qualification_bytes,
            &manifest,
            &assets,
        )
        .expect("Store validates exact positive qualification");
        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        let candidate =
            qualified_projection_capsule_bound_v2(&source_set(&manifest.common, &descriptor))
                .expect("qualified pure-C1 candidate");
        assert_eq!(
            candidate.manifest_identity,
            V3_PROJECTION_CAPSULE_BOUND_MANIFEST_V2_SCHEMA
        );
        assert_eq!(candidate.manifest_sha256, assets.manifest_sha256);
        assert_eq!(candidate.qualification_id, qualification.qualification_id);
        assert_eq!(candidate.qualification_sha256, assets.qualification_sha256);
        assert_eq!(
            candidate.qualification_basis_sha256,
            assets.qualification_basis_sha256
        );
        assert_eq!(
            candidate.bound_evaluator_identity,
            "nq.v3_projection_capsule_bound_evaluator.v1"
        );
        assert_eq!(candidate.shapes.len(), 4);
        assert_eq!(candidate.maximum_canonical_bytes, 133_038_721);
        assert!(
            candidate
                .maximum_canonical_bytes
                .checked_add(1)
                .is_some_and(|one_over| {
                    let legacy_view = V3ProjectionCapsuleCapacityCandidateV1 {
                        schema: "nq.v3_projection_capsule_capacity_candidate.v1".into(),
                        manifest_identity: candidate.manifest_identity.clone(),
                        sources_identity: candidate.sources_identity.clone(),
                        dependency_generation_id: candidate.dependency_generation_id.clone(),
                        dependency_canonical_custody_digest: candidate
                            .dependency_canonical_custody_digest
                            .clone(),
                        dependency_canonical_custody_bytes: candidate
                            .dependency_canonical_custody_bytes,
                        scalar_maxima: candidate.scalar_maxima.clone(),
                        cardinalities: candidate.cardinalities.clone(),
                        bounded_json: candidate.bounded_json.clone(),
                        shapes: candidate.shapes.clone(),
                        maximum_canonical_bytes: candidate.maximum_canonical_bytes,
                    };
                    legacy_view
                        .validate_length(candidate.maximum_canonical_bytes)
                        .is_ok()
                        && legacy_view.validate_length(one_over).is_err()
                })
        );
    }

    #[test]
    fn qualified_v2_store_validator_refuses_substitution_and_budget_cannot_change_c() {
        let assets =
            nq_host_role_contract::require_qualified_v3_projection_capsule_bound_manifest_v2()
                .expect("positive host-contract asset pair");
        let manifest =
            V3ProjectionCapsuleBoundManifestV2::from_qualified_bytes(assets.manifest_bytes)
                .expect("Store parses qualified v2 manifest");
        let qualification: V3ProjectionCapsuleBoundQualificationV1 =
            serde_json::from_slice(assets.qualification_bytes).expect("typed qualification");
        qualification
            .validate(&manifest, &assets)
            .expect("exact qualification");

        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        let sources = source_set(&manifest.common, &descriptor);
        let baseline = symbolic_candidate_projection_capsule_bound_v1_after_validation(
            &manifest.common,
            &sources,
        )
        .expect("baseline symbolic C");

        let mut changed_budget = qualification.clone();
        changed_budget
            .qualification_budget
            .maximum_single_canonical_witness_bytes += 1;
        assert!(changed_budget.validate(&manifest, &assets).is_err());
        let after_refusal = symbolic_candidate_projection_capsule_bound_v1_after_validation(
            &manifest.common,
            &sources,
        )
        .expect("symbolic C is budget-orthogonal");
        assert_eq!(
            baseline.maximum_canonical_bytes,
            after_refusal.maximum_canonical_bytes
        );
        assert_eq!(baseline.shapes, after_refusal.shapes);

        let mut changed_evidence = qualification.clone();
        changed_evidence.evidence_dispositions[0]
            .evidence_id
            .push_str(".substituted");
        assert!(changed_evidence.validate(&manifest, &assets).is_err());

        let mut changed_map = qualification.clone();
        changed_map.census.fields.rows[0].evidence_case_ids.pop();
        assert!(changed_map.validate(&manifest, &assets).is_err());

        let mut changed_attempt = qualification.clone();
        changed_attempt.materialization_attempts[0].slot_index = 1;
        assert!(changed_attempt.validate(&manifest, &assets).is_err());

        let mut changed_evaluator = qualification;
        changed_evaluator
            .implementation_bindings
            .evaluator
            .identity
            .push_str(".substituted");
        assert!(changed_evaluator.validate(&manifest, &assets).is_err());
    }

    #[test]
    fn semantic_exclusion_enforcement_refuses_identity_path_and_digest_substitution() {
        let manifest =
            inspected_v3_projection_capsule_bound_candidate_v1().expect("inspect candidate");
        assert_eq!(
            manifest.semantic_exclusions.len(),
            PROJECTION_CAPSULE_SEMANTIC_EXCLUSION_ENFORCEMENT.len()
        );

        for index in 0..manifest.semantic_exclusions.len() {
            let source_identity = manifest.semantic_exclusions[index].source_identity.clone();

            let mut identity_substitution = manifest.clone();
            identity_substitution.semantic_exclusions[index]
                .source_identity
                .push_str(".substituted");
            assert!(
                identity_substitution.validate().is_err(),
                "{source_identity} accepted a substituted source identity"
            );

            let mut path_substitution = manifest.clone();
            path_substitution.semantic_exclusions[index].source_path =
                "crates/nq-core/src/runtime.rs".to_owned();
            assert!(
                path_substitution.validate().is_err(),
                "{source_identity} accepted a substituted enforcing source path"
            );

            let mut digest_substitution = manifest.clone();
            digest_substitution.semantic_exclusions[index].source_sha256 =
                nq_protocol::sha256_bytes(b"substituted semantic exclusion source");
            assert!(
                digest_substitution.validate().is_err(),
                "{source_identity} accepted substituted enforcing source bytes"
            );
        }
    }

    #[test]
    fn content_address_source_cut_is_acyclic() {
        let bytes =
            nq_host_role_contract::inspected_candidate_v3_projection_capsule_bound_manifest()
                .expect("inspect candidate bytes");
        let candidate_digest = nq_protocol::sha256_bytes(bytes);
        let manifest: V3ProjectionCapsuleBoundManifestV1 =
            V3ProjectionCapsuleBoundManifestV1::from_inspected_candidate_bytes(bytes)
                .expect("inspect candidate");
        let source_paths = manifest
            .semantic_outcome_variants
            .iter()
            .map(|row| row.source_path.as_str())
            .chain(
                manifest
                    .semantic_exclusions
                    .iter()
                    .map(|row| row.source_path.as_str()),
            )
            .chain(
                manifest
                    .descriptor_governed_open_semantics
                    .iter()
                    .map(|row| row.source_path.as_str()),
            )
            .collect::<BTreeSet<_>>();
        let forbidden_paths = [
            "crates/nq-host-role-contract/assets/nq.v3_projection_capsule_bound_manifest.v1.json",
            "crates/nq-host-role-contract/assets/schemas/nq.v3_projection_capsule_bound_manifest.v1.schema.json",
            "crates/nq-host-role-contract/assets/custody-capacity-extension-manifest.v1.json",
            "crates/nq-host-role-contract/src/assets.rs",
        ];
        for source_path in source_paths {
            assert!(!forbidden_paths.contains(&source_path));
            let source = semantic_source_bytes(source_path).expect("closed source cut");
            assert!(
                !source
                    .windows(candidate_digest.as_str().len())
                    .any(|window| window == candidate_digest.as_str().as_bytes()),
                "{source_path} embeds the candidate manifest digest"
            );
        }
        let capsule_source = include_bytes!("governed_projection_capsule.rs");
        assert!(
            !capsule_source
                .windows(b"governed_projection_capacity".len())
                .any(|window| window == b"governed_projection_capacity"),
            "production capsule source depends back on the candidate capacity module"
        );
        assert!(
            !capsule_source
                .windows(candidate_digest.as_str().len())
                .any(|window| window == candidate_digest.as_str().as_bytes())
        );
    }

    #[test]
    fn symbolic_candidate_cross_checks_production_shapes_and_independent_arithmetic() {
        let manifest =
            inspected_v3_projection_capsule_bound_candidate_v1().expect("inspect candidate");
        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        assert_eq!(descriptor.maximum_canonical_bytes(), 121);
        let capacity = symbolic_candidate_projection_capsule_bound_v1(
            &manifest,
            &source_set(&manifest, &descriptor),
        )
        .expect("candidate symbolic ceiling");
        assert_eq!(capacity.shapes().len(), 4);
        assert_eq!(
            capacity
                .shapes()
                .iter()
                .map(PrelaunchClosureShapeV1::canonical_bytes)
                .collect::<Vec<_>>(),
            [133_038_721, 133_034_626, 68_127, 74_768]
        );
        assert_eq!(capacity.maximum_canonical_bytes(), 133_038_721);
        assert_eq!(
            capacity.maximum_canonical_bytes(),
            capacity
                .shapes()
                .iter()
                .map(PrelaunchClosureShapeV1::canonical_bytes)
                .max()
                .expect("closed shapes")
        );
        eprintln!(
            "tractable candidate symbolic maximum: {} bytes; shapes: {:?}",
            capacity.maximum_canonical_bytes(),
            capacity.shapes()
        );
    }

    #[test]
    fn qualification_field_source_and_shape_evidence_maps_are_exact_and_closed() {
        let manifest =
            inspected_v3_projection_capsule_bound_candidate_v1().expect("inspect candidate");
        let (fields, sources) =
            qualification_evidence_maps_v1(&manifest).expect("qualification evidence maps");
        let shapes = qualification_shape_evidence_rows_after_manifest_validation(&manifest)
            .expect("qualification shape rows");
        assert_eq!(fields.len(), 151);
        assert_eq!(sources.len(), 38);
        assert_eq!(shapes.len(), 4);
        assert!(
            fields.iter().all(|row| {
                !row.applicable_shapes.is_empty()
                    && !row.evidence_case_ids.is_empty()
                    && row
                        .applicable_shapes
                        .windows(2)
                        .all(|window| window[0] < window[1])
                    && row
                        .evidence_case_ids
                        .windows(2)
                        .all(|window| window[0] < window[1])
            }),
            "every field requires sorted, unique, nonempty shape and evidence sets"
        );
        assert!(
            sources.iter().all(|row| {
                !row.pointer_families.is_empty()
                    && !row.applicable_shapes.is_empty()
                    && !row.evidence_case_ids.is_empty()
                    && row
                        .pointer_families
                        .windows(2)
                        .all(|window| window[0] < window[1])
                    && row
                        .applicable_shapes
                        .windows(2)
                        .all(|window| window[0] < window[1])
                    && row
                        .evidence_case_ids
                        .windows(2)
                        .all(|window| window[0] < window[1])
            }),
            "every source requires sorted, unique, nonempty pointer, shape, and evidence sets"
        );
        let referenced_cases = fields
            .iter()
            .flat_map(|row| row.evidence_case_ids.iter().map(String::as_str))
            .chain(
                sources
                    .iter()
                    .flat_map(|row| row.evidence_case_ids.iter().map(String::as_str)),
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(
            referenced_cases,
            BTreeSet::from([
                CAP_H14_TRACTABLE_DESCRIPTOR_EVIDENCE_ID,
                CAP_H14_UNATTAINABLE_DESCRIPTOR_EVIDENCE_ID,
                CAP_H14_ADMITTED_REPORT_SHAPE_EVIDENCE_ID,
                CAP_H14_ADMITTED_OBSERVED_SHAPE_EVIDENCE_ID,
                CAP_H14_NO_SUBMISSION_SHAPE_EVIDENCE_ID,
                CAP_H14_REJECTED_SHAPE_EVIDENCE_ID,
                CAP_H14_LARGE_DESCRIPTOR_EVIDENCE_ID,
                CAP_H14_LARGE_CAPSULE_EVIDENCE_ID,
            ])
        );

        let field_bytes = canonical_json_bytes(&fields).expect("canonical field rows");
        let source_bytes = canonical_json_bytes(&sources).expect("canonical source rows");
        let shape_bytes = canonical_json_bytes(&shapes).expect("canonical shape rows");
        if let Some(output_directory) = std::env::var_os("NQ_CAP_H14_CENSUS_OUTPUT_DIRECTORY") {
            let output_directory = PathBuf::from(output_directory);
            fs::create_dir_all(&output_directory).expect("create census output directory");
            for (name, bytes) in [
                ("fields.canonical.json", field_bytes.as_slice()),
                ("sources.canonical.json", source_bytes.as_slice()),
                ("shapes.canonical.json", shape_bytes.as_slice()),
            ] {
                fs::write(output_directory.join(name), bytes)
                    .expect("write disposable census output");
            }
        }
        eprintln!(
            "qualification census rows: fields={} {} bytes {}; sources={} {} bytes {}; shapes={} {} bytes {}",
            fields.len(),
            field_bytes.len(),
            nq_protocol::sha256_bytes(&field_bytes),
            sources.len(),
            source_bytes.len(),
            nq_protocol::sha256_bytes(&source_bytes),
            shapes.len(),
            shape_bytes.len(),
            nq_protocol::sha256_bytes(&shape_bytes)
        );
    }

    #[test]
    fn independent_oracle_closes_descriptor_crossings_and_overflow() {
        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        assert_eq!(
            oracle_descriptor_bound(&descriptor).expect("independent descriptor recurrence"),
            121
        );

        let source_limit = BoundedJsonDescriptor::new(1, 0, 0, 0, 2, 1).expect("string descriptor");
        let exact = json!("\u{0000}\u{0000}");
        let one_over = json!("\u{0000}\u{0000}\u{0000}");
        source_limit
            .validate(&exact)
            .expect("independently representable exact source maximum");
        assert!(
            source_limit.validate(&one_over).is_err(),
            "one independently representable source unit over must refuse"
        );
        assert_eq!(
            oracle_descriptor_bound(&source_limit).expect("source oracle"),
            source_limit.maximum_canonical_bytes()
        );

        assert!(oracle_escaped_string_bound(u64::MAX).is_err());
        assert!(oracle_mixed_array_bound(&[(u64::MAX, u64::MAX)]).is_err());
    }

    #[test]
    fn production_serializer_exercises_each_branch_and_exact_escape_maximum() {
        for branch in ProjectionCapsuleOutcomeBranchV1::ALL {
            let value =
                crate::governed_projection_capsule::projection_capsule_symbolic_shape_witness_v1(
                    branch,
                )
                .expect("typed branch shape");
            let canonical = canonical_json_bytes(&value).expect("production canonical bytes");
            let decoded: Value = serde_json::from_slice(&canonical).expect("canonical JSON");
            assert_eq!(decoded, value);
            let maximum_escape = value
                .pointer("/publication/acknowledgment_id")
                .expect("maximum-escape scalar");
            assert_eq!(
                canonical_json_bytes(maximum_escape)
                    .expect("maximum-escape bytes")
                    .len(),
                256 * 6 + 2
            );
            eprintln!(
                "actual typed branch {} serialized to {} production-canonical bytes",
                branch.as_str(),
                canonical.len()
            );
        }
    }

    #[test]
    fn production_serializer_exercises_scaled_typed_cardinalities() {
        let value =
            crate::governed_projection_capsule::projection_capsule_scaled_cardinality_witness_v1(
                ProjectionCapsuleOutcomeBranchV1::Admitted,
                8,
                4,
                3,
            )
            .expect("scaled typed branch");
        assert_eq!(
            value
                .pointer("/collection/submission/disposition/report/observations")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(8)
        );
        assert_eq!(
            value
                .pointer("/collection/submission/disposition/report/coverage")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(4)
        );
        assert_eq!(
            value
                .pointer("/collection/submission/disposition/report/errors")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );
        let canonical = canonical_json_bytes(&value).expect("production canonical bytes");
        let decoded: Value = serde_json::from_slice(&canonical).expect("canonical JSON");
        assert_eq!(decoded, value);
        eprintln!(
            "actual scaled typed branch (8 observations, 4 report coverage, 3 errors) serialized to {} production-canonical bytes",
            canonical.len()
        );
    }

    #[test]
    fn tractable_descriptor_component_attains_its_exact_production_jcs_ceiling() {
        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        let value = tractable_descriptor_maximum_value();
        let bytes = descriptor
            .canonical_bytes(&value)
            .expect("production JCS maximum");
        assert_eq!(bytes.len(), 121);
        assert_eq!(
            u64::try_from(bytes.len()).expect("component length"),
            descriptor.maximum_canonical_bytes()
        );
        eprintln!(
            "tractable descriptor production-JCS maximum: {} bytes, {}",
            bytes.len(),
            nq_protocol::sha256_bytes(&bytes)
        );
    }

    #[test]
    fn every_descriptor_slot_accepts_an_individually_materialized_exact_maximum() {
        let descriptor =
            BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("tractable descriptor");
        let replacement = tractable_descriptor_maximum_value();
        assert_eq!(
            descriptor
                .canonical_bytes(&replacement)
                .expect("exact component maximum")
                .len(),
            121
        );

        for slot in PROJECTION_CAPSULE_BOUNDED_JSON_SOURCE_SLOTS {
            let families = PROJECTION_CAPSULE_GENERIC_POINTER_FAMILIES
                .iter()
                .filter_map(|(family, source)| (*source == slot).then_some(*family))
                .collect::<Vec<_>>();
            let mut replacements = 0;
            for branch in ProjectionCapsuleOutcomeBranchV1::ALL {
                let mut value = crate::governed_projection_capsule::
                    projection_capsule_symbolic_shape_witness_v1(branch)
                    .expect("typed branch shape");
                for family in &families {
                    replacements += replace_pointer_family(&mut value, family, &replacement);
                }
                let canonical =
                    canonical_json_bytes(&value).expect("production canonical serializer");
                let decoded: Value =
                    serde_json::from_slice(&canonical).expect("canonical component vector");
                assert_eq!(decoded, value);
            }
            assert!(replacements > 0, "descriptor slot {slot} was not exercised");
        }
    }

    #[test]
    fn tractable_non_success_branches_attain_their_exact_production_jcs_ceilings() {
        let run = qualification_materialization_run().expect("qualified materialization workspace");
        for (evidence_case_id, branch, expected_length) in [
            (
                CAP_H14_NO_SUBMISSION_SHAPE_EVIDENCE_ID,
                ProjectionCapsuleOutcomeBranchV1::NonSuccessNoSubmission,
                68_127,
            ),
            (
                CAP_H14_REJECTED_SHAPE_EVIDENCE_ID,
                ProjectionCapsuleOutcomeBranchV1::NonSuccessRejected,
                74_768,
            ),
        ] {
            let bytes = run
                .materialized_witnesses
                .get(evidence_case_id)
                .expect("materialized branch maximum");
            assert_eq!(
                bytes.len(),
                expected_length,
                "{} materialized length",
                branch.as_str()
            );
            eprintln!(
                "{} materialized production-JCS maximum: {} bytes, {}",
                branch.as_str(),
                bytes.len(),
                nq_protocol::sha256_bytes(bytes)
            );
        }
    }

    #[test]
    fn qualification_budget_is_physically_preallocated_touched_and_exactly_receipted() {
        let run = qualification_materialization_run().expect("qualification budget enforcement");
        let receipt = run.budget_receipt;
        let value: Value =
            serde_json::from_slice(&receipt).expect("canonical qualification receipt JSON");
        assert_eq!(
            value["maximum_single_canonical_witness_bytes"],
            QUALIFICATION_WITNESS_SLOT_BYTES
        );
        assert_eq!(
            value["closed_shape_count"],
            QUALIFICATION_WITNESS_SLOT_COUNT
        );
        assert_eq!(
            value["maximum_total_preallocated_witness_bytes"],
            QUALIFICATION_WITNESS_PREALLOCATION_BYTES
        );
        assert_eq!(
            value["maximum_parallel_witnesses"],
            QUALIFICATION_WITNESS_MAXIMUM_PARALLELISM
        );
        assert_eq!(
            value["backing"]["minimum_physically_allocated_bytes"],
            QUALIFICATION_WITNESS_PREALLOCATION_BYTES
        );
        assert!(
            value["backing"]["allocated_block_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes >= QUALIFICATION_WITNESS_PREALLOCATION_BYTES)
        );
        assert_eq!(value["backing"]["sparse_declaration_accepted"], false);
        assert_eq!(value["qualification_only"], true);
        assert_eq!(value["runtime_store_effect"], false);
        assert_eq!(run.attempt_receipts.len(), 4);
        let budget_receipt_sha256 = nq_protocol::sha256_bytes(&receipt);
        let attempt_values = run
            .attempt_receipts
            .iter()
            .map(|attempt| {
                serde_json::from_slice::<Value>(attempt).expect("canonical attempt receipt")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            attempt_values
                .iter()
                .filter(|attempt| attempt["disposition"] == "materialized")
                .count(),
            2
        );
        assert_eq!(
            attempt_values
                .iter()
                .filter(|attempt| {
                    attempt["disposition"] == "pre-materialization-refused-budget"
                })
                .count(),
            2
        );
        assert_eq!(
            attempt_values
                .iter()
                .map(|attempt| attempt["slot_index"].as_u64().expect("slot"))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1, 2, 3])
        );
        assert!(attempt_values.iter().all(|attempt| {
            attempt["budget_receipt_sha256"].as_str() == Some(budget_receipt_sha256.as_str())
        }));
        for (attempt, receipt_bytes) in attempt_values.iter().zip(&run.attempt_receipts) {
            eprintln!(
                "qualification attempt {}: {} bytes, {}",
                attempt["attempt_identity"],
                receipt_bytes.len(),
                nq_protocol::sha256_bytes(receipt_bytes)
            );
        }
        eprintln!(
            "qualification budget enforcement receipt: {} bytes, {}, allocated block bytes {}",
            receipt.len(),
            nq_protocol::sha256_bytes(&receipt),
            value["backing"]["allocated_block_bytes"]
        );
    }

    #[test]
    fn valid_descriptor_can_have_no_literal_maximal_value() {
        let descriptor = BoundedJsonDescriptor::new(2, 2, 0, 0, 0, 1).expect("valid descriptor");
        assert_eq!(descriptor.maximum_canonical_bytes(), 19);

        // A zero-byte key limit permits only the one JSON key "". Inserting
        // the nominal two members necessarily replaces the first member, so
        // no serde_json::Map (and therefore no JSON object) can attain the
        // structural two-member ceiling used by the conservative recurrence.
        let value = Value::Object(Map::from_iter([
            (String::new(), Value::Null),
            (String::new(), Value::Bool(false)),
        ]));
        let object = value.as_object().expect("object");
        assert_eq!(object.len(), 1);
        descriptor.validate(&value).expect("admitted value");
        let bytes = canonical_json_bytes(&value).expect("production JCS");
        assert_eq!(bytes, br#"{"":false}"#);
        assert!(u64::try_from(bytes.len()).unwrap() < descriptor.maximum_canonical_bytes());
        eprintln!(
            "zero-key uniqueness-constrained specimen: {} bytes, {}",
            bytes.len(),
            nq_protocol::sha256_bytes(&bytes)
        );
        let proof = zero_key_uniqueness_unattainability_proof_receipt()
            .expect("canonical unattainability proof receipt");
        eprintln!(
            "zero-key uniqueness unattainability proof: {} bytes, {}",
            proof.len(),
            nq_protocol::sha256_bytes(&proof)
        );
    }

    #[test]
    fn generic_descriptor_domain_can_require_petabyte_scale_symbolic_capacity() {
        const PEBIBYTE: u64 = 1_u64 << 50;

        let manifest =
            inspected_v3_projection_capsule_bound_candidate_v1().expect("inspect candidate");
        let descriptor = BoundedJsonDescriptor::new(2, 0, u32::MAX, 0, 0, 1)
            .expect("valid large generic descriptor");
        assert_eq!(descriptor.maximum_canonical_bytes(), 25_769_803_771);
        let capacity = symbolic_candidate_projection_capsule_bound_v1(
            &manifest,
            &source_set(&manifest, &descriptor),
        )
        .expect("large symbolic candidate");
        assert!(capacity.maximum_canonical_bytes() > PEBIBYTE);
        eprintln!(
            "valid generic descriptor maximum: {}; resulting candidate capsule ceiling: {} bytes",
            descriptor.maximum_canonical_bytes(),
            capacity.maximum_canonical_bytes()
        );
    }
}
