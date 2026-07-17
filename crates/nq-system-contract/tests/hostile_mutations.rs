//! Hostile generated mutations across the complete system-cut artifact chain.
//!
//! These tests deliberately leave the shipped public fixtures byte-for-byte
//! unchanged. Mutations that could otherwise survive a superficial digest
//! check are re-digested before entering the authoritative Rust parsers.

use chrono::{TimeZone, Utc};
use nq_system_contract::{
    AuthoritySemantics, ContractError, CutId, MAX_DOCUMENT_BYTES, NQ_OBSERVATION_PROJECTION_SCHEMA,
    NqObservationProjectionV1, OperatorId, PORTER_ACTUATION_PROJECTION_SCHEMA,
    PorterActuationProjectionV1, PorterProjectionSelectionV1, ProjectionId, PublishedScopeCutV1,
    RatificationV1, SCOPE_CUT_PROPOSAL_SCHEMA, SCOPE_CUT_SCHEMA, ScopeCutProposalBodyV1,
    ScopeCutProposalV1, ScopeCutReferenceV1, SystemSpecV1, canonical_document,
    parse_nq_observation_projection, parse_porter_actuation_projection, parse_scope_cut,
    parse_scope_cut_proposal, parse_system_spec, versioned_artifact_digest,
};
use serde::Serialize;
use serde_json::{Value, json};

const SPEC: &[u8] = include_bytes!("../../../system-contract/fixtures/valid/system_spec.json");
const PROPOSAL: &[u8] =
    include_bytes!("../../../system-contract/fixtures/valid/scope_cut_proposal.json");
const CUT: &[u8] = include_bytes!("../../../system-contract/fixtures/valid/scope_cut.json");
const OBSERVATION: &[u8] =
    include_bytes!("../../../system-contract/fixtures/valid/nq_observation_projection.json");
const PORTER: &[u8] =
    include_bytes!("../../../system-contract/fixtures/valid/porter_actuation_projection.json");

fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
    canonical_document(value).expect("test artifact must remain bounded and canonicalizable")
}

fn compile_cut(
    spec: &SystemSpecV1,
    cut_id: &str,
    ratification_hour: u32,
) -> (ScopeCutProposalV1, PublishedScopeCutV1) {
    let cut_id = CutId::new(cut_id).expect("test cut identity");
    let system_id = spec.systems[0].system_id.clone();
    let proposal = spec
        .compile_cut_proposal(cut_id.clone(), &system_id)
        .expect("test proposal must compile");
    let ratification = RatificationV1::new(
        OperatorId::new("fixture:hostile-matrix").expect("test operator identity"),
        Utc.with_ymd_and_hms(2026, 7, 16, ratification_hour, 0, 0)
            .single()
            .expect("test time"),
        proposal.proposal_digest.clone(),
    )
    .expect("test ratification must identify its proposal");
    let cut = spec
        .compile_cut(cut_id, &system_id, ratification)
        .expect("test cut must compile");
    (proposal, cut)
}

fn newer_spec() -> SystemSpecV1 {
    let mut value: Value = serde_json::from_slice(SPEC).expect("public spec JSON");
    value["revision"] = json!(2);
    value["targets"][0]["target_identity_digest"] =
        json!("sha256:1111111111111111111111111111111111111111111111111111111111111111");
    parse_system_spec(&serde_json::to_vec(&value).expect("newer spec JSON"))
        .expect("newer test spec must remain valid")
}

fn cut_reference(cut: &PublishedScopeCutV1) -> ScopeCutReferenceV1 {
    ScopeCutReferenceV1 {
        cut_id: cut.cut.cut_id.clone(),
        cut_digest: cut.cut_digest.clone(),
    }
}

fn all_selection(cut: &PublishedScopeCutV1) -> PorterProjectionSelectionV1 {
    PorterProjectionSelectionV1 {
        target_ids: cut
            .cut
            .targets
            .iter()
            .map(|target| target.target_id.clone())
            .collect(),
        component_ids: cut
            .cut
            .components
            .iter()
            .map(|component| component.component_id.clone())
            .collect(),
    }
}

fn redigest_nq(projection: &mut NqObservationProjectionV1) {
    projection.projection_digest =
        versioned_artifact_digest(NQ_OBSERVATION_PROJECTION_SCHEMA, &projection.projection)
            .expect("mutated NQ projection body must be digestible");
}

fn redigest_porter(projection: &mut PorterActuationProjectionV1) {
    projection.projection_digest =
        versioned_artifact_digest(PORTER_ACTUATION_PROJECTION_SCHEMA, &projection.projection)
            .expect("mutated Porter projection body must be digestible");
}

fn proposal_body(cut: &PublishedScopeCutV1) -> ScopeCutProposalBodyV1 {
    ScopeCutProposalBodyV1 {
        cut_id: cut.cut.cut_id.clone(),
        source_spec: cut.cut.source_spec.clone(),
        system: cut.cut.system.clone(),
        source_snapshots: cut.cut.source_snapshots.clone(),
        targets: cut.cut.targets.clone(),
        components: cut.cut.components.clone(),
        dependencies: cut.cut.dependencies.clone(),
        observation_obligations: cut.cut.observation_obligations.clone(),
        authority: AuthoritySemantics::None,
    }
}

#[test]
fn independently_valid_projections_from_different_cuts_cannot_form_one_view() {
    let old_cut = parse_scope_cut(CUT).expect("public cut must verify");
    let old_nq = parse_nq_observation_projection(OBSERVATION, &old_cut)
        .expect("public NQ projection must verify against its cut");
    let old_porter = parse_porter_actuation_projection(PORTER, &old_cut)
        .expect("public Porter projection must verify against its cut");

    let (_, new_cut) = compile_cut(&newer_spec(), "conformance-system/2", 14);
    let new_nq = new_cut
        .nq_observation_projection(
            ProjectionId::new("nq/conformance-system/2").expect("projection identity"),
        )
        .expect("new NQ projection must compile");
    let new_porter = new_cut
        .porter_actuation_projection(
            ProjectionId::new("porter/conformance-system/2").expect("projection identity"),
            &all_selection(&new_cut),
        )
        .expect("new Porter projection must compile");

    old_nq.verify_against(&old_cut).expect("old NQ is valid");
    old_porter
        .verify_against(&old_cut)
        .expect("old Porter is valid");
    new_nq.verify_against(&new_cut).expect("new NQ is valid");
    new_porter
        .verify_against(&new_cut)
        .expect("new Porter is valid");
    assert_ne!(
        old_nq.projection.scope_cut, new_porter.projection.scope_cut,
        "independently valid projections must expose their inconsistent exact cuts"
    );

    assert!(matches!(
        parse_nq_observation_projection(&bytes(&old_nq), &new_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
    assert!(matches!(
        parse_porter_actuation_projection(&bytes(&new_porter), &old_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
    assert!(matches!(
        parse_nq_observation_projection(&bytes(&new_nq), &old_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
    assert!(matches!(
        parse_porter_actuation_projection(&bytes(&old_porter), &new_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
}

#[test]
fn proposal_ratification_cut_and_newer_projection_substitutions_are_rejected() {
    let old_spec = parse_system_spec(SPEC).expect("public spec must verify");
    let old_proposal = parse_scope_cut_proposal(PROPOSAL).expect("public proposal must verify");
    let old_cut = parse_scope_cut(CUT).expect("public cut must verify");
    old_cut
        .cut
        .ratification
        .verify()
        .expect("old ratification is independently self-consistent");

    let new_spec = newer_spec();
    let (new_proposal, new_cut) = compile_cut(&new_spec, "conformance-system/2", 14);

    let mut substituted_proposal_body = old_proposal.clone();
    substituted_proposal_body.proposal = new_proposal.proposal.clone();
    assert!(matches!(
        parse_scope_cut_proposal(&bytes(&substituted_proposal_body)),
        Err(ContractError::DigestMismatch("scope cut proposal"))
    ));

    let mut substituted_proposal_digest = old_proposal.clone();
    substituted_proposal_digest.proposal_digest = new_proposal.proposal_digest.clone();
    assert!(matches!(
        parse_scope_cut_proposal(&bytes(&substituted_proposal_digest)),
        Err(ContractError::DigestMismatch("scope cut proposal"))
    ));

    let mut substituted_ratification = new_cut.clone();
    substituted_ratification.cut.ratification = old_cut.cut.ratification.clone();
    substituted_ratification.cut_digest =
        versioned_artifact_digest(SCOPE_CUT_SCHEMA, &substituted_ratification.cut)
            .expect("substituted cut body must be digestible");
    assert!(matches!(
        parse_scope_cut(&bytes(&substituted_ratification)),
        Err(ContractError::RatificationProposalMismatch)
    ));

    let mut substituted_cut_envelope = new_cut.clone();
    substituted_cut_envelope.cut_digest = old_cut.cut_digest.clone();
    assert!(matches!(
        parse_scope_cut(&bytes(&substituted_cut_envelope)),
        Err(ContractError::DigestMismatch("scope cut"))
    ));
    assert!(matches!(
        new_cut.verify_against_spec(&old_spec),
        Err(ContractError::SourceSpecMismatch)
    ));

    let mut newer_nq_with_stale_cut = new_cut
        .nq_observation_projection(
            ProjectionId::new("nq/conformance-system/substituted").expect("projection identity"),
        )
        .expect("new NQ projection must compile");
    newer_nq_with_stale_cut.projection.scope_cut = cut_reference(&old_cut);
    redigest_nq(&mut newer_nq_with_stale_cut);
    assert!(matches!(
        parse_nq_observation_projection(&bytes(&newer_nq_with_stale_cut), &old_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
    assert!(matches!(
        parse_nq_observation_projection(&bytes(&newer_nq_with_stale_cut), &new_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));

    let mut newer_porter_with_stale_cut = new_cut
        .porter_actuation_projection(
            ProjectionId::new("porter/conformance-system/substituted")
                .expect("projection identity"),
            &all_selection(&new_cut),
        )
        .expect("new Porter projection must compile");
    newer_porter_with_stale_cut.projection.scope_cut = cut_reference(&old_cut);
    redigest_porter(&mut newer_porter_with_stale_cut);
    assert!(matches!(
        parse_porter_actuation_projection(&bytes(&newer_porter_with_stale_cut), &old_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
    assert!(matches!(
        parse_porter_actuation_projection(&bytes(&newer_porter_with_stale_cut), &new_cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
}

fn transitive_dependency_spec() -> SystemSpecV1 {
    let mut value: Value = serde_json::from_slice(SPEC).expect("public spec JSON");
    let component = value["components"][0].clone();
    let obligation = value["observation_obligations"][0].clone();

    let mut middle_component = component.clone();
    middle_component["component_id"] = json!("dependent-helper");
    let mut leaf_component = component;
    leaf_component["component_id"] = json!("leaf-helper");
    value["components"]
        .as_array_mut()
        .expect("components array")
        .extend([middle_component, leaf_component]);

    value["dependencies"] = json!([
        {
            "dependency_id": "dependent-on-echo",
            "consumer_component_id": "dependent-helper",
            "provider_component_id": "echo-helper",
            "requirement": "required",
            "source_snapshot_ids": ["authored-conformance-system"]
        },
        {
            "dependency_id": "leaf-on-dependent",
            "consumer_component_id": "leaf-helper",
            "provider_component_id": "dependent-helper",
            "requirement": "required",
            "source_snapshot_ids": ["authored-conformance-system"]
        }
    ]);

    let mut middle_obligation = obligation.clone();
    middle_obligation["observation_obligation_id"] = json!("observe-dependent");
    middle_obligation["component_id"] = json!("dependent-helper");
    middle_obligation["instance_id"] = json!("conformance-dependent-local");
    let mut leaf_obligation = obligation;
    leaf_obligation["observation_obligation_id"] = json!("observe-leaf");
    leaf_obligation["component_id"] = json!("leaf-helper");
    leaf_obligation["instance_id"] = json!("conformance-leaf-local");
    value["observation_obligations"]
        .as_array_mut()
        .expect("observation obligations array")
        .extend([middle_obligation, leaf_obligation]);

    let system = &mut value["systems"][0];
    system["component_ids"] = json!(["echo-helper", "dependent-helper", "leaf-helper"]);
    system["dependency_ids"] = json!(["dependent-on-echo", "leaf-on-dependent"]);
    system["observation_obligation_ids"] =
        json!(["observe-echo", "observe-dependent", "observe-leaf"]);

    parse_system_spec(&serde_json::to_vec(&value).expect("dependency spec JSON"))
        .expect("transitive dependency test spec must be valid")
}

#[test]
fn porter_cannot_understate_transitive_affected_or_verification_closure() {
    let (_, cut) = compile_cut(
        &transitive_dependency_spec(),
        "conformance-system/dependency-closure",
        14,
    );
    let selection = PorterProjectionSelectionV1 {
        target_ids: vec![cut.cut.targets[0].target_id.clone()],
        component_ids: vec![
            cut.cut
                .components
                .iter()
                .find(|component| component.component_id.as_str() == "echo-helper")
                .expect("echo component")
                .component_id
                .clone(),
        ],
    };
    let projection = cut
        .porter_actuation_projection(
            ProjectionId::new("porter/conformance-system/dependency-closure")
                .expect("projection identity"),
            &selection,
        )
        .expect("complete dependency projection must compile");
    let affected: Vec<_> = projection
        .projection
        .affected_components
        .iter()
        .map(|component| component.component_id.as_str())
        .collect();
    assert_eq!(affected, ["dependent-helper", "echo-helper", "leaf-helper"]);

    let mut understated_components = projection.clone();
    understated_components
        .projection
        .affected_components
        .retain(|component| component.component_id.as_str() != "leaf-helper");
    redigest_porter(&mut understated_components);
    assert!(matches!(
        parse_porter_actuation_projection(&bytes(&understated_components), &cut),
        Err(ContractError::ProjectionCutMismatch)
    ));

    let mut understated_witnesses = projection.clone();
    understated_witnesses
        .projection
        .verification_obligations
        .retain(|obligation| obligation.component_id.as_str() != "leaf-helper");
    redigest_porter(&mut understated_witnesses);
    assert!(matches!(
        parse_porter_actuation_projection(&bytes(&understated_witnesses), &cut),
        Err(ContractError::ProjectionCutMismatch)
    ));

    let mut understated_dependencies = projection;
    understated_dependencies
        .projection
        .boundary_dependencies
        .retain(|dependency| dependency.dependency_id.as_str() != "leaf-on-dependent");
    redigest_porter(&mut understated_dependencies);
    assert!(matches!(
        parse_porter_actuation_projection(&bytes(&understated_dependencies), &cut),
        Err(ContractError::ProjectionCutMismatch)
    ));
}

#[test]
fn strict_cut_boundary_rejects_duplicate_reordered_omitted_unknown_truncated_and_oversize() {
    let cut_text = std::str::from_utf8(CUT).expect("public cut is UTF-8");
    let duplicate = cut_text.replacen(
        "\"cut_id\": \"conformance-system/1\",",
        "\"cut_id\": \"conformance-system/1\",\n    \"cut_id\": \"conformance-system/1\",",
        1,
    );
    assert!(matches!(
        parse_scope_cut(duplicate.as_bytes()),
        Err(ContractError::InvalidJson(message)) if message.contains("duplicate object key")
    ));

    let mut reordered = parse_scope_cut(CUT).expect("public cut must verify");
    reordered.cut.source_snapshots.reverse();
    let reordered_proposal = proposal_body(&reordered);
    let reordered_proposal_digest =
        versioned_artifact_digest(SCOPE_CUT_PROPOSAL_SCHEMA, &reordered_proposal)
            .expect("reordered proposal must be digestible");
    reordered.cut.ratification = RatificationV1::new(
        reordered.cut.ratification.ratified_by.clone(),
        reordered.cut.ratification.ratified_at,
        reordered_proposal_digest,
    )
    .expect("reordered ratification must be internally consistent");
    reordered.cut_digest = versioned_artifact_digest(SCOPE_CUT_SCHEMA, &reordered.cut)
        .expect("reordered cut must be digestible");
    assert!(matches!(
        parse_scope_cut(&bytes(&reordered)),
        Err(ContractError::NonCanonical("scope cut proposal arrays"))
    ));

    let mut omitted: Value = serde_json::from_slice(CUT).expect("public cut JSON");
    omitted["cut"]
        .as_object_mut()
        .expect("cut object")
        .remove("ratification");
    assert!(matches!(
        parse_scope_cut(&serde_json::to_vec(&omitted).expect("omitted JSON")),
        Err(ContractError::InvalidJson(message)) if message.contains("missing field")
    ));

    let mut unknown: Value = serde_json::from_slice(CUT).expect("public cut JSON");
    unknown["cut"]["ratification"]
        .as_object_mut()
        .expect("ratification object")
        .insert("authorized".to_owned(), Value::Bool(true));
    assert!(matches!(
        parse_scope_cut(&serde_json::to_vec(&unknown).expect("unknown-field JSON")),
        Err(ContractError::InvalidJson(message)) if message.contains("unknown field")
    ));

    let mut truncated = CUT.to_vec();
    while truncated.last().is_some_and(u8::is_ascii_whitespace) {
        truncated.pop();
    }
    assert_eq!(truncated.pop(), Some(b'}'));
    assert!(matches!(
        parse_scope_cut(&truncated),
        Err(ContractError::InvalidJson(_))
    ));

    let mut oversized = CUT.to_vec();
    oversized.resize(MAX_DOCUMENT_BYTES + 1, b' ');
    assert!(matches!(
        parse_scope_cut(&oversized),
        Err(ContractError::TooLarge {
            actual,
            limit: MAX_DOCUMENT_BYTES,
        }) if actual == MAX_DOCUMENT_BYTES + 1
    ));
}
