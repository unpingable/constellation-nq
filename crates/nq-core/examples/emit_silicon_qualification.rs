//! Emit the checked-in SILICON-ORCHARD NQ artifact for downstream qualification.

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
    signed_monitor_record_json: String,
    exact_payload_json: Option<String>,
}

fn main() {
    let bundle: Bundle = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/silicon-orchard/monitor-bundle.v1.json"
    ))
    .expect("exact Monitor bundle");
    let inputs = bundle
        .entries
        .into_iter()
        .map(|entry| OperationalEvidenceInputV1 {
            input_id: format!("silicon:{}", entry.scenario),
            signed_monitor_record: entry.signed_monitor_record_json.into_bytes(),
            payload_bytes: entry.exact_payload_json.map(String::into_bytes),
            receiver_custody_at: Utc
                .with_ymd_and_hms(2026, 8, 30, 16, 1, 0)
                .single()
                .expect("fixed custody time"),
        })
        .collect::<Vec<_>>();
    let artifact = qualify_operational_observations(
        &silicon_orchard_ecad_profile(),
        &inputs,
        Utc.with_ymd_and_hms(2026, 8, 30, 16, 2, 0)
            .single()
            .expect("fixed qualification time"),
    )
    .expect("SILICON qualification");
    println!(
        "{}",
        serde_json::to_string(&artifact).expect("artifact serializes")
    );
}
