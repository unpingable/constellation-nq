//! Authority-neutral T9 probe for the BEDROCK external journal backend.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use nq_k3s_exact_occurrence::EvidenceBindingV1;
use nq_k3s_exact_occurrence::artifact_evidence::{
    EVIDENCE_EVENT_SCHEMA_V1, EXTERNAL_CUSTODY_SCHEMA_V1, EvidenceEventBodyV1, EvidenceEventKindV1,
    ExternalEvidenceCustodyV1,
};
use nq_k3s_exact_occurrence::filesystem_evidence::FilesystemEvidenceJournalV1;
use nq_protocol::{semantic_digest, sha256_bytes};
use serde::Serialize;

const FIXTURE_ID: &str = "BEDROCK-T9-AUTHORITY-NEUTRAL-CUSTODY-PROBE-V1";

#[derive(Serialize)]
struct ProbeResult {
    schema: &'static str,
    fixture_id: &'static str,
    operation: String,
    effect: Option<String>,
    canonical_root: String,
    custody_digest: String,
    event_count: usize,
    chain_digest: String,
}

fn binding() -> EvidenceBindingV1 {
    EvidenceBindingV1 {
        canonical_custody_id: sha256_bytes(b"BEDROCK T9 canonical custody probe"),
        selection_contract_digest: sha256_bytes(b"BEDROCK T9 selection contract probe"),
        external_journal_id: sha256_bytes(b"BEDROCK T9 external journal probe"),
        receipt_destination_id: sha256_bytes(b"BEDROCK T9 receipt destination probe"),
        required_free_bytes: 10 * 1024 * 1024 * 1024,
        retention_mode: "retain_all".into(),
    }
}

fn custody() -> ExternalEvidenceCustodyV1 {
    let binding = binding();
    ExternalEvidenceCustodyV1 {
        schema: EXTERNAL_CUSTODY_SCHEMA_V1.into(),
        journal_id: binding.external_journal_id,
        receipt_destination_id: binding.receipt_destination_id,
        outside_workload_ephemeral_state: true,
        append_only: true,
        retention_mode: "retain_all".into(),
        encoding: "rfc8785_jcs".into(),
        durability_law: "sync_event_then_parent_directory_v1".into(),
        writer_domain: sha256_bytes(b"BEDROCK T9 exclusive writer domain probe"),
    }
}

fn genesis() -> EvidenceEventBodyV1 {
    EvidenceEventBodyV1 {
        schema: EVIDENCE_EVENT_SCHEMA_V1.into(),
        sequence: 0,
        predecessor: None,
        journal_id: binding().external_journal_id,
        plan_id: sha256_bytes(b"BEDROCK T9 non-authorizing fixture plan"),
        nq_occurrence: sha256_bytes(b"BEDROCK T9 non-authorizing fixture occurrence"),
        docket: None,
        runtime: None,
        kind: EvidenceEventKindV1::Prepared,
        observation_digest: sha256_bytes(FIXTURE_ID.as_bytes()),
        observed_at_unix_ms: 1_787_956_800_000,
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let operation = arguments.next().ok_or("missing append|verify operation")?;
    let root = PathBuf::from(arguments.next().ok_or("missing journal root")?);
    if arguments.next().is_some() {
        return Err("unexpected additional argument".into());
    }
    let journal = FilesystemEvidenceJournalV1::open(&root, custody(), binding())?;
    let effect = match operation.as_str() {
        "append" => Some(format!("{:?}", journal.append(genesis())?)),
        "verify" => None,
        _ => return Err("operation must be append or verify".into()),
    };
    let chain = journal.reopen()?;
    let result = ProbeResult {
        schema: "nq.bedrock_filesystem_evidence_probe_result.v1",
        fixture_id: FIXTURE_ID,
        operation,
        effect,
        canonical_root: journal.canonical_root()?.display().to_string(),
        custody_digest: journal.custody_digest()?.into_string(),
        event_count: chain.events.len(),
        chain_digest: semantic_digest(&chain)?.into_string(),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("BEDROCK evidence probe refused: {error}");
            ExitCode::FAILURE
        }
    }
}
