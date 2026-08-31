//! SILICON-ORCHARD exact Monitor-to-NQ qualification cases.

use chrono::{TimeZone as _, Utc};
use nq_core::{
    OperationalEvidenceInputV1, qualify_operational_observations, silicon_orchard_ecad_profile,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Bundle {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    scenario: String,
    subject_identity_digest: String,
    producer_identity_digest: String,
    signed_monitor_record_json: String,
    exact_payload_json: Option<String>,
}

fn bundle() -> Bundle {
    serde_json::from_slice(include_bytes!(
        "fixtures/silicon-orchard/monitor-bundle.v1.json"
    ))
    .unwrap()
}

#[test]
fn exact_ecad_profile_qualifies_independent_facts_and_failures() {
    let bundle = bundle();
    let profile = silicon_orchard_ecad_profile();
    profile.validate().unwrap();
    let inputs = bundle
        .entries
        .iter()
        .map(|entry| OperationalEvidenceInputV1 {
            input_id: format!("silicon:{}", entry.scenario),
            signed_monitor_record: entry.signed_monitor_record_json.as_bytes().to_vec(),
            payload_bytes: entry
                .exact_payload_json
                .as_ref()
                .map(|value| value.as_bytes().to_vec()),
            receiver_custody_at: Utc
                .with_ymd_and_hms(2026, 8, 30, 16, 1, 0)
                .single()
                .unwrap(),
        })
        .collect::<Vec<_>>();
    let artifact = qualify_operational_observations(
        &profile,
        &inputs,
        Utc.with_ymd_and_hms(2026, 8, 30, 16, 2, 0)
            .single()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(artifact.inputs.len(), 20);
    let failed = artifact
        .inputs
        .iter()
        .find(|input| input.input_id == "silicon:license-no-response")
        .unwrap();
    assert!(failed.claim_support.is_empty());
    assert_eq!(failed.cannot_testify.len(), profile.claims.len());
    assert!(failed.refusals.is_empty());
    let exit_zero = artifact
        .inputs
        .iter()
        .find(|input| input.input_id == "silicon:exit-zero-missing-output")
        .unwrap();
    assert_eq!(exit_zero.claim_support.len(), profile.claims.len());
    let scheduler = artifact
        .contradictions
        .iter()
        .filter(|finding| finding.claim_id == "ecad:scheduler-observation")
        .collect::<Vec<_>>();
    assert!(scheduler.len() >= 2);
    assert!(
        artifact
            .nonclaims
            .iter()
            .any(|value| { value == "producer class alone grants no evidentiary precedence" })
    );
}

#[test]
fn exact_payload_and_identity_substitutions_refuse_without_claim_widening() {
    let bundle = bundle();
    let profile = silicon_orchard_ecad_profile();
    for entry in bundle
        .entries
        .iter()
        .filter(|entry| entry.scenario != "healthy-wrong-subject")
    {
        assert!(
            profile
                .accepted_subject_identity_digests
                .contains(&entry.subject_identity_digest)
        );
        assert!(
            profile
                .accepted_producer_identities
                .iter()
                .any(|value| value.producer_identity_digest == entry.producer_identity_digest)
        );
    }
    let entry = &bundle.entries[0];
    let input = OperationalEvidenceInputV1 {
        input_id: "silicon:substituted-payload".into(),
        signed_monitor_record: entry.signed_monitor_record_json.as_bytes().to_vec(),
        payload_bytes: Some(br#"{"substituted":true}"#.to_vec()),
        receiver_custody_at: Utc
            .with_ymd_and_hms(2026, 8, 30, 16, 1, 0)
            .single()
            .unwrap(),
    };
    let artifact = qualify_operational_observations(
        &profile,
        &[input],
        Utc.with_ymd_and_hms(2026, 8, 30, 16, 2, 0)
            .single()
            .unwrap(),
    )
    .unwrap();
    assert!(artifact.inputs[0].claim_support.is_empty());
    assert_eq!(artifact.inputs[0].refusals[0].code, "payload_substitution");
    assert!(
        !serde_json::to_string(&artifact)
            .unwrap()
            .contains("aggregate")
    );
    assert!(
        !serde_json::to_string(&artifact)
            .unwrap()
            .contains("authorize")
    );
}
