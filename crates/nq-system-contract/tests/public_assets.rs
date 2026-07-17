//! Rust-authoritative round trip for every shipped language-neutral fixture.

use nq_system_contract::{
    PorterProjectionSelectionV1, parse_nq_observation_projection,
    parse_porter_actuation_projection, parse_scope_cut, parse_scope_cut_proposal,
    parse_system_spec,
};

const SPEC: &[u8] = include_bytes!("../../../system-contract/fixtures/valid/system_spec.json");
const PROPOSAL: &[u8] =
    include_bytes!("../../../system-contract/fixtures/valid/scope_cut_proposal.json");
const CUT: &[u8] = include_bytes!("../../../system-contract/fixtures/valid/scope_cut.json");
const OBSERVATION: &[u8] =
    include_bytes!("../../../system-contract/fixtures/valid/nq_observation_projection.json");
const PORTER: &[u8] =
    include_bytes!("../../../system-contract/fixtures/valid/porter_actuation_projection.json");

#[test]
fn shipped_fixture_chain_is_exactly_compiled_and_cross_bound() {
    let spec = parse_system_spec(SPEC).expect("public system specification must parse");
    let proposal =
        parse_scope_cut_proposal(PROPOSAL).expect("public cut proposal must verify custody");
    proposal
        .qualify_with_compiled_profiles()
        .expect("fixture proposal must qualify against the compiled conformance profile");
    let compiled_proposal = spec
        .compile_cut_proposal(
            proposal.proposal.cut_id.clone(),
            &proposal.proposal.system.system_id,
        )
        .expect("fixture proposal must compile from the exact source spec");
    assert_eq!(compiled_proposal, proposal);

    let cut = parse_scope_cut(CUT).expect("public cut must verify immutable custody");
    cut.qualify_with_compiled_profiles()
        .expect("fixture cut must qualify against the compiled conformance profile");
    cut.verify_against_spec(&spec)
        .expect("fixture cut must derive from the exact retained spec");
    assert_eq!(
        cut.cut.ratification.ratified_proposal_digest,
        proposal.proposal_digest
    );
    let compiled_cut = spec
        .compile_cut(
            cut.cut.cut_id.clone(),
            &cut.cut.system.system_id,
            cut.cut.ratification.clone(),
        )
        .expect("fixture cut must compile with its exact ratification record");
    assert_eq!(compiled_cut, cut);

    let observation = parse_nq_observation_projection(OBSERVATION, &cut)
        .expect("public NQ projection must derive from the exact cut");
    let compiled_observation = cut
        .nq_observation_projection(observation.projection.projection_id.clone())
        .expect("NQ projection fixture must compile");
    assert_eq!(compiled_observation, observation);

    let porter = parse_porter_actuation_projection(PORTER, &cut)
        .expect("public Porter projection must derive from the exact cut");
    let selection = PorterProjectionSelectionV1 {
        target_ids: porter
            .projection
            .actuation_targets
            .iter()
            .map(|target| target.target_id.clone())
            .collect(),
        component_ids: porter
            .projection
            .actuation_components
            .iter()
            .map(|component| component.component_id.clone())
            .collect(),
    };
    let compiled_porter = cut
        .porter_actuation_projection(porter.projection.projection_id.clone(), &selection)
        .expect("Porter projection fixture must compile");
    assert_eq!(compiled_porter, porter);
    assert_eq!(
        observation.projection.scope_cut,
        porter.projection.scope_cut
    );
}
