//! Emit corrected SILICON-ORCHARD per-case NQ qualification artifacts.

use chrono::{DateTime, TimeZone as _, Utc};
use nq_core::{
    EcadClaimDeckV1, EcadEligibilityCheckV1, OperationalEvidenceInputV1,
    OperationalQualificationArtifactV1, OperationalQualificationProfileV1,
    check_silicon_orchard_eligibility, qualify_operational_observations,
    silicon_orchard_claim_deck, silicon_orchard_ecad_profile,
};
use nq_protocol::{Sha256Digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const RAW_BUNDLE: &[u8] =
    include_bytes!("../tests/fixtures/silicon-orchard/monitor-bundle.v1.json");

#[derive(Deserialize)]
struct MonitorBundle {
    entries: Vec<Entry>,
    distant_traversal: Value,
}

#[derive(Deserialize)]
struct Entry {
    scenario: String,
    signed_monitor_record_json: String,
    exact_payload_json: Option<String>,
}

#[derive(Serialize)]
struct Case {
    scenario: String,
    qualification: OperationalQualificationArtifactV1,
    eligibility: EcadEligibilityCheckV1,
}

#[derive(Serialize)]
struct Output {
    schema: String,
    monitor_fixture_head: String,
    monitor_bundle_digest: Sha256Digest,
    profile: OperationalQualificationProfileV1,
    claim_deck: EcadClaimDeckV1,
    cases: Vec<Case>,
    distant_intake_binding: Value,
    nonclaims: Vec<String>,
}

fn entry<'a>(bundle: &'a MonitorBundle, scenario: &str) -> &'a Entry {
    bundle
        .entries
        .iter()
        .find(|value| value.scenario == scenario)
        .expect("closed scenario")
}

fn input(bundle: &MonitorBundle, scenario: &str) -> OperationalEvidenceInputV1 {
    let entry = entry(bundle, scenario);
    if scenario == "delayed-duplicate-delivery" {
        let traversal = &bundle.distant_traversal;
        let signed_monitor_record = hex::decode(
            traversal["message"]["body"]["observation"]["bytes_hex"]
                .as_str()
                .expect("wire observation"),
        )
        .expect("wire observation hex");
        let payload_bytes = hex::decode(
            traversal["message"]["body"]["payload"]["bytes_hex"]
                .as_str()
                .expect("wire payload"),
        )
        .expect("wire payload hex");
        assert_eq!(
            signed_monitor_record,
            entry.signed_monitor_record_json.as_bytes()
        );
        assert_eq!(
            payload_bytes,
            entry
                .exact_payload_json
                .as_ref()
                .expect("payload")
                .as_bytes()
        );
        let receiver_custody_at = DateTime::parse_from_rfc3339(
            traversal["first_custody_receipt"]["body"]["received_at"]
                .as_str()
                .expect("receipt time"),
        )
        .expect("RFC3339 receipt")
        .with_timezone(&Utc);
        return OperationalEvidenceInputV1 {
            input_id: format!("silicon:{scenario}"),
            signed_monitor_record,
            payload_bytes: Some(payload_bytes),
            receiver_custody_at,
        };
    }
    OperationalEvidenceInputV1 {
        input_id: format!("silicon:{scenario}"),
        signed_monitor_record: entry.signed_monitor_record_json.as_bytes().to_vec(),
        payload_bytes: entry
            .exact_payload_json
            .as_ref()
            .map(|value| value.as_bytes().to_vec()),
        receiver_custody_at: Utc
            .with_ymd_and_hms(2026, 8, 30, 16, 30, 0)
            .single()
            .expect("fixed custody"),
    }
}

fn group(scenario: &str) -> Vec<&str> {
    match scenario {
        "scheduler-running-source" | "worker-absent-source" => {
            vec!["scheduler-running-source", "worker-absent-source"]
        }
        "scheduler-contradiction-a" | "scheduler-contradiction-b" | "agent-contradiction" => vec![
            "scheduler-contradiction-a",
            "scheduler-contradiction-b",
            "agent-contradiction",
        ],
        _ => vec![scenario],
    }
}

fn main() {
    let bundle: MonitorBundle = serde_json::from_slice(RAW_BUNDLE).expect("exact Monitor bundle");
    let profile = silicon_orchard_ecad_profile();
    let deck = silicon_orchard_claim_deck();
    let cases = bundle
        .entries
        .iter()
        .map(|entry| {
            let inputs = group(&entry.scenario)
                .into_iter()
                .map(|scenario| input(&bundle, scenario))
                .collect::<Vec<_>>();
            let qualification = qualify_operational_observations(
                &profile,
                &inputs,
                Utc.with_ymd_and_hms(2026, 8, 30, 16, 40, 0)
                    .single()
                    .expect("fixed qualification time"),
            )
            .expect("SILICON qualification");
            let input_id = format!("silicon:{}", entry.scenario);
            let eligibility = check_silicon_orchard_eligibility(
                nq_core::SILICON_MONITOR_FIXTURE_HEAD,
                RAW_BUNDLE,
                &deck,
                &qualification,
                &input_id,
            )
            .expect("closed eligibility");
            Case {
                scenario: entry.scenario.clone(),
                qualification,
                eligibility,
            }
        })
        .collect();
    let output = Output {
        schema: "nq.ecad-qualification-bundle/v1".into(),
        monitor_fixture_head: nq_core::SILICON_MONITOR_FIXTURE_HEAD.into(),
        monitor_bundle_digest: sha256_bytes(RAW_BUNDLE),
        profile,
        claim_deck: deck,
        cases,
        distant_intake_binding: bundle.distant_traversal,
        nonclaims: vec![
            "evidence eligibility is not an ECAD result".into(),
            "process exit alone cannot establish evidence eligibility".into(),
            "NQ qualification grants no remediation or target-effect authority".into(),
        ],
    };
    println!(
        "{}",
        serde_json::to_string(&output).expect("output serializes")
    );
}
