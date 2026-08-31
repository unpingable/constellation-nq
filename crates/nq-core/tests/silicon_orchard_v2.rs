//! Corrected SILICON-ORCHARD exact custody and eligibility qualification.

use chrono::{DateTime, TimeZone as _, Utc};
use nq_core::{
    EcadEligibilityDispositionV1, OperationalEvidenceInputV1, OperationalQualificationArtifactV1,
    check_silicon_orchard_eligibility, qualify_operational_observations,
    silicon_orchard_claim_deck, silicon_orchard_ecad_profile,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Bundle {
    entries: Vec<Entry>,
    distant_traversal: Value,
}

#[derive(Deserialize)]
struct Entry {
    scenario: String,
    signed_monitor_record_json: String,
    exact_payload_json: Option<String>,
}

fn bundle() -> Bundle {
    serde_json::from_slice(include_bytes!(
        "fixtures/silicon-orchard/monitor-bundle.v1.json"
    ))
    .unwrap()
}

fn entry<'a>(bundle: &'a Bundle, scenario: &str) -> &'a Entry {
    bundle
        .entries
        .iter()
        .find(|value| value.scenario == scenario)
        .unwrap()
}

fn fixed_custody() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 16, 30, 0)
        .single()
        .unwrap()
}

fn input(bundle: &Bundle, entry: &Entry) -> OperationalEvidenceInputV1 {
    if entry.scenario != "delayed-duplicate-delivery" {
        return OperationalEvidenceInputV1 {
            input_id: format!("silicon:{}", entry.scenario),
            signed_monitor_record: entry.signed_monitor_record_json.as_bytes().to_vec(),
            payload_bytes: entry
                .exact_payload_json
                .as_ref()
                .map(|value| value.as_bytes().to_vec()),
            receiver_custody_at: fixed_custody(),
        };
    }
    let traversal = &bundle.distant_traversal;
    let observation = hex::decode(
        traversal["message"]["body"]["observation"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let payload = hex::decode(
        traversal["message"]["body"]["payload"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(observation, entry.signed_monitor_record_json.as_bytes());
    assert_eq!(
        payload,
        entry.exact_payload_json.as_ref().unwrap().as_bytes()
    );
    let custody = DateTime::parse_from_rfc3339(
        traversal["first_custody_receipt"]["body"]["received_at"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .with_timezone(&Utc);
    OperationalEvidenceInputV1 {
        input_id: format!("silicon:{}", entry.scenario),
        signed_monitor_record: observation,
        payload_bytes: Some(payload),
        receiver_custody_at: custody,
    }
}

fn qualify(bundle: &Bundle, scenarios: &[&str]) -> OperationalQualificationArtifactV1 {
    let inputs = scenarios
        .iter()
        .map(|scenario| input(bundle, entry(bundle, scenario)))
        .collect::<Vec<_>>();
    qualify_operational_observations(
        &silicon_orchard_ecad_profile(),
        &inputs,
        Utc.with_ymd_and_hms(2026, 8, 30, 16, 40, 0)
            .single()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn distant_retained_custody_is_the_exact_nq_intake_for_delayed_duplicate() {
    let bundle = bundle();
    let traversal = &bundle.distant_traversal;
    let delayed = entry(&bundle, "delayed-duplicate-delivery");
    let nq_input = input(&bundle, delayed);
    assert_eq!(
        nq_input.receiver_custody_at.to_rfc3339(),
        "2026-08-30T16:03:00+00:00"
    );
    assert_eq!(
        traversal["partition_attempt_record"]["outcome"],
        "partition"
    );
    assert_eq!(
        traversal["first_custody_attempt_record"]["outcome"],
        "custody_confirmed"
    );
    assert_eq!(
        traversal["retry_custody_attempt_record"]["outcome"],
        "custody_confirmed"
    );
    assert_eq!(
        traversal["first_custody_receipt"],
        traversal["replayed_custody_receipt"]
    );
    assert_eq!(
        traversal["sender_pending_ids_after_reopen"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let retained_inbox = hex::decode(
        traversal["retained_receiver_inbox"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let inbox: Value = serde_json::from_slice(&retained_inbox).unwrap();
    assert_eq!(inbox["message"], traversal["message"]);
    assert_eq!(
        inbox["first_attempt_id"],
        "attempt:silicon-wire:first-custody"
    );
    assert_eq!(inbox["first_received_at"], "2026-08-30T16:03:00Z");

    let retained_receipt = hex::decode(
        traversal["retained_receiver_receipt"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let receipt: Value = serde_json::from_slice(&retained_receipt).unwrap();
    assert_eq!(receipt, traversal["first_custody_receipt"]);
    let retained_delivered = hex::decode(
        traversal["retained_sender_delivered"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let delivered: Value = serde_json::from_slice(&retained_delivered).unwrap();
    assert_eq!(delivered, traversal["first_custody_receipt"]);

    let retained_lineage = hex::decode(
        traversal["retained_receiver_lineage"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let lineage: Value = serde_json::from_slice(&retained_lineage).unwrap();
    assert_eq!(
        lineage["claim"]["message_id"],
        traversal["message"]["message_id"]
    );
    assert_eq!(
        lineage["custody_receipt"],
        traversal["first_custody_receipt"]
    );

    let attempt_ids = traversal["retained_sender_attempts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|retained| {
            let bytes = hex::decode(retained["bytes_hex"].as_str().unwrap()).unwrap();
            let record: Value = serde_json::from_slice(&bytes).unwrap();
            record["delivery"]["attempt_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        attempt_ids,
        [
            "attempt:silicon-wire:partition",
            "attempt:silicon-wire:first-custody",
            "attempt:silicon-wire:retry-after-lost-ack",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let artifact = qualify(&bundle, &["delayed-duplicate-delivery"]);
    assert!(artifact.inputs[0].refusals.is_empty());
    assert_eq!(
        artifact.inputs[0].receiver_custody_at,
        nq_input.receiver_custody_at
    );
}

#[test]
fn closed_deck_requires_full_exact_evidence_and_never_treats_exit_as_result() {
    let bundle = bundle();
    let deck = silicon_orchard_claim_deck();
    deck.validate().unwrap();

    let nominal = qualify(&bundle, &["nominal"]);
    let nominal_check =
        check_silicon_orchard_eligibility(&deck, &nominal, "silicon:nominal").unwrap();
    assert_eq!(
        nominal_check.disposition,
        EcadEligibilityDispositionV1::EvidenceEligible
    );
    assert!(nominal_check.process_exit_was_not_treated_as_result);
    assert!(!nominal_check.grants_authority);

    let exit_zero = qualify(&bundle, &["exit-zero-missing-output"]);
    let exit_check =
        check_silicon_orchard_eligibility(&deck, &exit_zero, "silicon:exit-zero-missing-output")
            .unwrap();
    assert_eq!(
        exit_check.disposition,
        EcadEligibilityDispositionV1::EvidenceNotEstablished
    );

    let no_response = qualify(&bundle, &["license-no-response"]);
    let no_response_check =
        check_silicon_orchard_eligibility(&deck, &no_response, "silicon:license-no-response")
            .unwrap();
    assert_eq!(
        no_response_check.disposition,
        EcadEligibilityDispositionV1::EvidenceNotEstablished
    );

    let wrong_subject = qualify(&bundle, &["healthy-wrong-subject"]);
    let wrong_subject_check =
        check_silicon_orchard_eligibility(&deck, &wrong_subject, "silicon:healthy-wrong-subject")
            .unwrap();
    assert_eq!(
        wrong_subject_check.disposition,
        EcadEligibilityDispositionV1::Refused
    );

    let mut substituted_deck = deck.clone();
    substituted_deck.required_claims[0].claim_id = "ecad:invented".into();
    assert_eq!(
        substituted_deck.validate().unwrap_err(),
        "ecad_claim_deck_domain_invalid"
    );
}

#[test]
fn contradiction_and_temporal_cases_remain_independent() {
    let bundle = bundle();
    let deck = silicon_orchard_claim_deck();

    let cross_source = qualify(
        &bundle,
        &["scheduler-running-source", "worker-absent-source"],
    );
    assert!(
        cross_source
            .contradictions
            .iter()
            .any(|value| { value.claim_id == "ecad:worker-observation" })
    );
    let cross_check =
        check_silicon_orchard_eligibility(&deck, &cross_source, "silicon:scheduler-running-source")
            .unwrap();
    assert_eq!(
        cross_check.disposition,
        EcadEligibilityDispositionV1::Contradictory
    );

    let unresolved = qualify(
        &bundle,
        &[
            "scheduler-contradiction-a",
            "scheduler-contradiction-b",
            "agent-contradiction",
        ],
    );
    assert!(unresolved.contradictions.iter().any(|value| {
        value.claim_id == "ecad:scheduler-observation"
            && (value.first_input_id == "silicon:agent-contradiction"
                || value.second_input_id == "silicon:agent-contradiction")
    }));

    let historical = qualify(&bundle, &["repository-custody-historical"]);
    let successor = qualify(&bundle, &["repository-custody-successor"]);
    assert_eq!(
        check_silicon_orchard_eligibility(
            &deck,
            &historical,
            "silicon:repository-custody-historical",
        )
        .unwrap()
        .disposition,
        EcadEligibilityDispositionV1::EvidenceNotEstablished
    );
    assert_eq!(
        check_silicon_orchard_eligibility(
            &deck,
            &successor,
            "silicon:repository-custody-successor",
        )
        .unwrap()
        .disposition,
        EcadEligibilityDispositionV1::EvidenceNotEstablished
    );
    assert!(successor.inputs[0].refusals.is_empty());
    assert!(successor.inputs[0].cannot_testify.is_empty());

    let design = qualify(&bundle, &["wrong-design-revision"]);
    let repository = qualify(&bundle, &["wrong-revision"]);
    let design_input = &design.inputs[0];
    let repository_input = &repository.inputs[0];
    assert_ne!(
        design_input
            .claim_support
            .iter()
            .find(|value| value.claim_id == "ecad:observed-design-revision")
            .unwrap()
            .value_digest,
        silicon_orchard_claim_deck().required_claims[1].expected_value_digest
    );
    assert_ne!(
        repository_input
            .claim_support
            .iter()
            .find(|value| value.claim_id == "ecad:observed-repository-revision")
            .unwrap()
            .value_digest,
        silicon_orchard_claim_deck().required_claims[14].expected_value_digest
    );
}

#[test]
fn profile_and_deck_machine_schemas_match_closed_runtime_fields() {
    use nq_core::{
        EcadClaimDeckV1, OperationalQualificationProfileV1, SILICON_ECAD_DECK_JSON_SCHEMA_V1,
        SILICON_ECAD_PROFILE_JSON_SCHEMA_V1,
    };

    fn keys(value: &Value) -> std::collections::BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    }
    fn required(schema: &Value) -> std::collections::BTreeSet<String> {
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }

    let profile_schema: Value = serde_json::from_str(SILICON_ECAD_PROFILE_JSON_SCHEMA_V1).unwrap();
    let deck_schema: Value = serde_json::from_str(SILICON_ECAD_DECK_JSON_SCHEMA_V1).unwrap();
    assert_eq!(profile_schema["additionalProperties"], false);
    assert_eq!(deck_schema["additionalProperties"], false);
    let profile_value = serde_json::to_value(silicon_orchard_ecad_profile()).unwrap();
    let deck_value = serde_json::to_value(silicon_orchard_claim_deck()).unwrap();
    assert_eq!(keys(&profile_value), required(&profile_schema));
    assert_eq!(keys(&deck_value), required(&deck_schema));
    assert_eq!(
        profile_schema["properties"]["accepted_producer_identities"]["minItems"].as_u64(),
        Some(8)
    );
    assert_eq!(
        deck_schema["properties"]["required_claims"]["minItems"].as_u64(),
        Some(27)
    );

    let mut unknown_profile = profile_value.clone();
    unknown_profile
        .as_object_mut()
        .unwrap()
        .insert("aggregate_result".into(), Value::Bool(true));
    assert!(serde_json::from_value::<OperationalQualificationProfileV1>(unknown_profile).is_err());
    let mut unknown_deck = deck_value.clone();
    unknown_deck
        .as_object_mut()
        .unwrap()
        .insert("authorize".into(), Value::Bool(true));
    assert!(serde_json::from_value::<EcadClaimDeckV1>(unknown_deck).is_err());

    let mut missing_deck = deck_value;
    missing_deck
        .as_object_mut()
        .unwrap()
        .remove("requires_full_evidence");
    assert!(serde_json::from_value::<EcadClaimDeckV1>(missing_deck).is_err());
}
