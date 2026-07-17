//! Required-observation coherence: a custody-valid cut is not thereby a
//! causally coherent one. These fixtures separate three classes deliberately:
//! custody-valid but coherence-invalid, V1-coherent, and (documented) cases a
//! richer model might later decide differently — a V1 pass must never be read as
//! epoch or historical coherence.

use chrono::{TimeZone, Utc};
use nq_system_contract::{
    AdmissibleSystemCutV1, CutCoherencePolicy, CutCoherenceRefusal, CutCoherenceWitnessV1, CutId,
    OperatorId, PublishedScopeCutV1, RatificationV1, SystemSpecV1, canonical_document,
    compute_cut_coherence_witness, parse_and_verify_admissible, parse_system_spec,
};
use serde_json::{Value, json};

const SPEC: &[u8] = include_bytes!("../../../system-contract/fixtures/valid/system_spec.json");

/// Build a custody-valid cut whose components are each observed at a chosen time
/// and related by the given required/incidental dependencies.
fn build_cut(
    components: &[(&str, &str)],
    deps: &[(&str, &str, &str, &str)],
) -> PublishedScopeCutV1 {
    let mut base: Value = serde_json::from_slice(SPEC).expect("base spec JSON");
    let snapshot_template = base["source_snapshots"][0].clone();
    let target_snapshot = base["source_snapshots"][1].clone();
    let component_template = base["components"][0].clone();
    let obligation_template = base["observation_obligations"][0].clone();

    let mut snapshots = Vec::new();
    for (component_id, captured_at) in components {
        let mut snapshot = snapshot_template.clone();
        snapshot["source_snapshot_id"] = json!(format!("snap-{component_id}"));
        snapshot["captured_at"] = json!(captured_at);
        snapshots.push(snapshot);
    }
    snapshots.push(target_snapshot);
    base["source_snapshots"] = json!(snapshots);

    let mut built_components = Vec::new();
    for (component_id, _) in components {
        let mut component = component_template.clone();
        component["component_id"] = json!(component_id);
        component["source_snapshot_ids"] = json!([format!("snap-{component_id}")]);
        built_components.push(component);
    }
    base["components"] = json!(built_components);

    let mut built_dependencies = Vec::new();
    for (dependency_id, consumer, provider, requirement) in deps {
        built_dependencies.push(json!({
            "dependency_id": dependency_id,
            "consumer_component_id": consumer,
            "provider_component_id": provider,
            "requirement": requirement,
            "source_snapshot_ids": [format!("snap-{consumer}")],
        }));
    }
    base["dependencies"] = json!(built_dependencies);

    let mut built_obligations = Vec::new();
    for (component_id, _) in components {
        let mut obligation = obligation_template.clone();
        obligation["observation_obligation_id"] = json!(format!("observe-{component_id}"));
        obligation["component_id"] = json!(component_id);
        obligation["instance_id"] = json!(format!("conformance-{component_id}-local"));
        obligation["source_snapshot_ids"] = json!([format!("snap-{component_id}")]);
        built_obligations.push(obligation);
    }
    base["observation_obligations"] = json!(built_obligations);

    let mut all_snapshot_ids: Vec<String> = components
        .iter()
        .map(|(component_id, _)| format!("snap-{component_id}"))
        .collect();
    all_snapshot_ids.push(target_snapshot_id(&base).expect("target snapshot id"));

    let system = &mut base["systems"][0];
    system["component_ids"] = json!(components.iter().map(|(c, _)| *c).collect::<Vec<_>>());
    system["dependency_ids"] = json!(deps.iter().map(|(d, _, _, _)| *d).collect::<Vec<_>>());
    system["observation_obligation_ids"] = json!(
        components
            .iter()
            .map(|(c, _)| format!("observe-{c}"))
            .collect::<Vec<_>>()
    );
    system["source_snapshot_ids"] = json!(all_snapshot_ids);

    let spec: SystemSpecV1 = parse_system_spec(&serde_json::to_vec(&base).expect("spec bytes"))
        .expect("synthesized coherence spec must be custody-valid");
    compile(&spec)
}

fn target_snapshot_id(base: &Value) -> Option<String> {
    base["source_snapshots"]
        .as_array()?
        .iter()
        .find_map(|snapshot| {
            let id = snapshot["source_snapshot_id"].as_str()?;
            (!id.starts_with("snap-")).then(|| id.to_owned())
        })
}

fn compile(spec: &SystemSpecV1) -> PublishedScopeCutV1 {
    let cut_id = CutId::new("coherence-cut").expect("cut id");
    let system_id = spec.systems[0].system_id.clone();
    let proposal = spec
        .compile_cut_proposal(cut_id.clone(), &system_id)
        .expect("proposal compiles");
    let ratification = RatificationV1::new(
        OperatorId::new("fixture:coherence").expect("operator id"),
        // After every snapshot in these fixtures.
        Utc.with_ymd_and_hms(2026, 7, 17, 0, 0, 0)
            .single()
            .expect("time"),
        proposal.proposal_digest.clone(),
    )
    .expect("ratification identifies its proposal");
    spec.compile_cut(cut_id, &system_id, ratification)
        .expect("cut compiles (custody is valid)")
}

fn window(seconds: u64) -> CutCoherencePolicy {
    CutCoherencePolicy::RequiredObservationV1 {
        coherence_window_seconds: seconds,
    }
}

// --- Class 1: custody-valid, coherence-invalid ---

#[test]
fn frankenstein_cut_passes_custody_but_fails_required_observation_coherence() {
    // consumer requires provider, but provider was observed a day later: every
    // constituent is valid and the cut compiles, yet the whole never existed.
    let cut = build_cut(
        &[
            ("consumer", "2026-07-15T12:00:00Z"),
            ("provider", "2026-07-16T12:00:00Z"),
        ],
        &[(
            "consumer-needs-provider",
            "consumer",
            "provider",
            "required",
        )],
    );
    let refusal = compute_cut_coherence_witness(&cut, window(86_400))
        .expect_err("required provider observed after its consumer is refused");
    assert!(matches!(
        refusal,
        CutCoherenceRefusal::RequiredProviderObservedLate { consumer, provider }
            if consumer == "consumer" && provider == "provider"
    ));
}

#[test]
fn long_required_chain_exceeds_the_window() {
    // Each adjacent pair is ordered, but the whole chain spans two weeks.
    let cut = build_cut(
        &[
            ("a", "2026-07-16T00:00:00Z"),
            ("b", "2026-07-09T00:00:00Z"),
            ("c", "2026-07-02T00:00:00Z"),
        ],
        &[
            ("a-needs-b", "a", "b", "required"),
            ("b-needs-c", "b", "c", "required"),
        ],
    );
    let refusal = compute_cut_coherence_witness(&cut, window(3_600))
        .expect_err("a required closure wider than the window is refused");
    assert!(matches!(
        refusal,
        CutCoherenceRefusal::RequiredClosureWindowExceeded { .. }
    ));
}

#[test]
fn required_cycle_with_unequal_instants_is_refused_as_a_cycle() {
    let cut = build_cut(
        &[("x", "2026-07-16T12:00:00Z"), ("y", "2026-07-16T13:00:00Z")],
        &[
            ("x-needs-y", "x", "y", "required"),
            ("y-needs-x", "y", "x", "required"),
        ],
    );
    let refusal = compute_cut_coherence_witness(&cut, window(86_400))
        .expect_err("an unequal-instant required cycle is refused");
    assert!(matches!(
        refusal,
        CutCoherenceRefusal::InconsistentRequiredCycle(_)
    ));
}

// --- Class 2: V1-coherent ---

#[test]
fn provider_earlier_than_consumer_passes() {
    let cut = build_cut(
        &[
            ("consumer", "2026-07-16T12:00:00Z"),
            ("provider", "2026-07-15T12:00:00Z"),
        ],
        &[(
            "consumer-needs-provider",
            "consumer",
            "provider",
            "required",
        )],
    );
    let witness = compute_cut_coherence_witness(&cut, window(172_800)).expect("coherent");
    assert_eq!(witness.cut_digest, cut.cut_digest);
    assert_eq!(witness.coherence_claim, "required_observation_v1");
}

#[test]
fn equal_instants_pass() {
    let cut = build_cut(
        &[
            ("consumer", "2026-07-16T12:00:00Z"),
            ("provider", "2026-07-16T12:00:00Z"),
        ],
        &[(
            "consumer-needs-provider",
            "consumer",
            "provider",
            "required",
        )],
    );
    compute_cut_coherence_witness(&cut, window(3_600)).expect("equal instants are coherent");
}

#[test]
fn late_incidental_provider_does_not_fail() {
    // The provider is observed later, but only incidentally related.
    let cut = build_cut(
        &[
            ("consumer", "2026-07-15T12:00:00Z"),
            ("provider", "2026-07-16T12:00:00Z"),
        ],
        &[(
            "consumer-knows-provider",
            "consumer",
            "provider",
            "incidental",
        )],
    );
    compute_cut_coherence_witness(&cut, window(3_600))
        .expect("incidental relations do not participate in coherence");
}

#[test]
fn unrelated_subgraphs_do_not_fail_on_total_span() {
    // Two independent, internally-tight required pairs whose union spans weeks.
    let cut = build_cut(
        &[
            ("new-consumer", "2026-07-16T12:00:00Z"),
            ("new-provider", "2026-07-16T11:00:00Z"),
            ("old-consumer", "2026-07-02T12:00:00Z"),
            ("old-provider", "2026-07-02T11:00:00Z"),
        ],
        &[
            ("new", "new-consumer", "new-provider", "required"),
            ("old", "old-consumer", "old-provider", "required"),
        ],
    );
    compute_cut_coherence_witness(&cut, window(3_600))
        .expect("unrelated closures are not penalized for the cut's total span");
}

// --- Witness binding and re-verification ---

#[test]
fn admissible_cut_reverifies_a_good_witness() {
    let cut = build_cut(
        &[
            ("consumer", "2026-07-16T12:00:00Z"),
            ("provider", "2026-07-15T12:00:00Z"),
        ],
        &[(
            "consumer-needs-provider",
            "consumer",
            "provider",
            "required",
        )],
    );
    let witness = compute_cut_coherence_witness(&cut, window(172_800)).expect("coherent");
    let admissible = AdmissibleSystemCutV1::verify(cut.clone(), witness.clone())
        .expect("a good witness re-verifies");
    assert_eq!(admissible.coherence_claim(), "required_observation_v1");

    // And re-verification survives a serialization round trip.
    let bytes = canonical_document(&witness).expect("witness serializes");
    parse_and_verify_admissible(cut, &bytes).expect("serialized witness re-verifies");
}

#[test]
fn witness_bound_to_another_cut_is_refused() {
    let coherent = build_cut(
        &[
            ("consumer", "2026-07-16T12:00:00Z"),
            ("provider", "2026-07-15T12:00:00Z"),
        ],
        &[(
            "consumer-needs-provider",
            "consumer",
            "provider",
            "required",
        )],
    );
    let other = build_cut(&[("solo", "2026-07-16T12:00:00Z")], &[]);
    let witness = compute_cut_coherence_witness(&coherent, window(172_800)).expect("coherent");
    let refusal = AdmissibleSystemCutV1::verify(other, witness)
        .expect_err("a witness for another cut is refused");
    assert!(matches!(
        refusal,
        CutCoherenceRefusal::WitnessCutMismatch { .. }
    ));
}

#[test]
fn witness_with_an_altered_window_is_refused() {
    let cut = build_cut(
        &[
            ("consumer", "2026-07-16T12:00:00Z"),
            ("provider", "2026-07-15T12:00:00Z"),
        ],
        &[(
            "consumer-needs-provider",
            "consumer",
            "provider",
            "required",
        )],
    );
    let witness = compute_cut_coherence_witness(&cut, window(172_800)).expect("coherent");
    // Tamper the window without recomputing the witness digest.
    let mut value: Value = serde_json::to_value(&witness).expect("witness value");
    value["policy"]["coherence_window_seconds"] = json!(1);
    let tampered: CutCoherenceWitnessV1 =
        serde_json::from_value(value).expect("still a witness shape");
    let refusal = AdmissibleSystemCutV1::verify(cut, tampered)
        .expect_err("an altered window breaks the witness digest");
    assert!(matches!(
        refusal,
        CutCoherenceRefusal::WitnessInconsistent(_)
    ));
}

#[test]
fn unknown_coherence_policy_fails_closed() {
    let cut = build_cut(&[("solo", "2026-07-16T12:00:00Z")], &[]);
    let witness = json!({
        "schema": "nq.cut_coherence_witness.v1",
        "cut_digest": cut.cut_digest,
        "coherence_claim": "required_observation_v99",
        "policy": { "policy_version": "required_observation_v99", "coherence_window_seconds": 3600 },
        "witness_digest": cut.cut_digest,
    });
    let bytes = serde_json::to_vec(&witness).expect("witness bytes");
    let refusal = parse_and_verify_admissible(cut, &bytes)
        .expect_err("an unknown policy version is refused, not coerced into V1");
    assert!(matches!(
        refusal,
        CutCoherenceRefusal::UnsupportedCoherencePolicy(version) if version == "required_observation_v99"
    ));
}
