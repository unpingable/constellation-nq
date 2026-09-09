//! Independent pre-cleanup backup/restore prerequisite. The earlier relief v1
//! profile remains unchanged; this separately named profile composes it.
use crate::labelwatch_relief::{
    self, FileIdentity, Observation, ObservationState, Phase, Source, Unknown,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCopy {
    pub path: String,
    pub identity: FileIdentity,
    pub verification_sha256: String,
    pub integrity: String,
    pub application_schema: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupSource {
    pub schema: String,
    pub source_owner: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub held_source: Source,
    pub backup: Observation<VerifiedCopy>,
    pub restore: Observation<VerifiedCopy>,
    pub unknowns: Vec<Unknown>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub held_request: labelwatch_relief::Request,
    pub backup: String,
    pub restore: String,
    pub backup_identity: FileIdentity,
    pub restore_identity: FileIdentity,
}

pub fn qualify(raw: &[u8], request: &Request) -> Result<Value, String> {
    let source: CleanupSource =
        nq_protocol::decode_json_document(raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    let held = &request.held_request;
    if source.schema != "labelwatch.sqlite-cleanup-observation/v1"
        || source.source_owner != "Labelwatch read-only observer"
        || request.schema != "nq.labelwatch-cleanup-request/v1"
        || held.phase != Phase::PreIngest
        || source.started_at > source.held_source.started_at
        || source.held_source.completed_at > source.completed_at
        || source.completed_at > held.evaluated_at
        || !request.backup.starts_with('/')
        || !request.restore.starts_with('/')
        || request.backup == request.restore
        || [&held.source, &held.original].contains(&&request.backup)
        || [&held.source, &held.original].contains(&&request.restore)
    {
        return Err("closed cleanup source/request or time/subject boundary differs".into());
    }
    let held_qualification = labelwatch_relief::qualify(
        &serde_json::to_vec(&source.held_source).map_err(|e| e.to_string())?,
        held,
    )?;
    let mut refuted = Vec::<String>::new();
    let mut unknown = Vec::<String>::new();
    match held_qualification["disposition"].as_str() {
        Some("ESTABLISHED") => (),
        Some("REFUTED") => refuted.push("held cut prerequisite refuted".into()),
        _ => unknown.push("held cut prerequisite not observable".into()),
    }
    if (held.evaluated_at - source.started_at).num_milliseconds()
        > i64::from(held.maximum_age_seconds) * 1000
    {
        unknown.push("cleanup observation stale".into());
    }
    let mut expected_unknowns = std::collections::BTreeSet::new();
    for (slot, observed, path, identity) in [
        (
            "backup",
            &source.backup,
            &request.backup,
            &request.backup_identity,
        ),
        (
            "restore",
            &source.restore,
            &request.restore,
            &request.restore_identity,
        ),
    ] {
        match (&observed.state, &observed.value) {
            (ObservationState::NotObservable, None) => {
                expected_unknowns.insert(slot);
                unknown.push(format!("{slot} not observable"));
            }
            (ObservationState::Observed, Some(copy)) => {
                if copy.identity.sha256.len() != 64
                    || !copy
                        .identity
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err("copy identity digest malformed".into());
                }
                if copy.path != *path || copy.identity != *identity {
                    refuted.push(format!("{slot} exact enrolled identity differs"));
                }
                if copy.verification_sha256 != held.expected_cut_sha256
                    || copy.integrity != "ok"
                    || copy.application_schema != 23
                {
                    refuted.push(format!("{slot} restored application/logical cut differs"));
                }
                if copy.identity.device == held.replacement_device {
                    refuted.push(format!("{slot} not on separate filesystem"));
                }
            }
            _ => return Err("cleanup observation state/value contradiction".into()),
        }
    }
    let actual_unknowns: std::collections::BTreeSet<_> =
        source.unknowns.iter().map(|u| u.slot.as_str()).collect();
    if actual_unknowns != expected_unknowns
        || actual_unknowns.len() != source.unknowns.len()
        || source.unknowns.iter().any(|u| u.reason.trim().is_empty())
    {
        return Err("cleanup unknown accounting differs".into());
    }
    if let (Some(backup), Some(restore)) = (&source.backup.value, &source.restore.value) {
        if backup.identity.device != restore.identity.device {
            refuted.push("restore not on enrolled backup filesystem".into());
        }
    }
    let disposition = if !refuted.is_empty() {
        "REFUTED"
    } else if !unknown.is_empty() {
        "NOT_OBSERVABLE"
    } else {
        "ESTABLISHED"
    };
    let mut receipt = json!({"schema":"nq.labelwatch-cleanup-qualification/v1",
        "request":request, "source_utf8":std::str::from_utf8(raw).map_err(|e|e.to_string())?,
        "source_owner":source.source_owner, "claim":"held_cut_and_recoverable_copy_prerequisites",
        "held_qualification":held_qualification, "disposition":disposition,
        "refuted":refuted, "unknown":unknown, "source_limitations":source.limitations,
        "limitations":["external projection under exact enrolled local custody, not producer authentication",
            "actual backup and restored application reads, not power-loss/off-host durability",
            "bounded observation interval; no cleanup authorization or future-state claim"]});
    receipt["receipt_id"] =
        json!(nq_protocol::semantic_digest(&receipt).map_err(|e| e.to_string())?);
    Ok(receipt)
}

pub fn replay(receipt: &Value) -> Result<(), String> {
    let request: Request =
        serde_json::from_value(receipt["request"].clone()).map_err(|e| e.to_string())?;
    let raw = receipt["source_utf8"]
        .as_str()
        .ok_or("cleanup source absent")?;
    if qualify(raw.as_bytes(), &request)? != *receipt {
        return Err("cleanup replay differs".into());
    }
    Ok(())
}
