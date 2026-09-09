//! Independent pre-cleanup backup/restore prerequisite. The earlier relief v1
//! profile remains unchanged; this separately named profile composes it.
use crate::labelwatch_relief::{
    self, FileIdentity, Observation, ObservationState, Phase, Source, Unknown,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileStamp {
    pub path: String,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub mtime_ns: String,
    pub ctime_ns: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Custody {
    pub hold_sha256: String,
    pub files: BTreeMap<String, FileStamp>,
    pub writers: BTreeMap<String, labelwatch_relief::Writer>,
}

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
    pub currentness_started_at: DateTime<Utc>,
    pub currentness_completed_at: DateTime<Utc>,
    pub acquisition_budget_seconds: u32,
    pub acquisition_duration_ms: u64,
    pub acquisition_exclusions: Vec<String>,
    pub opening_custody: Observation<Custody>,
    pub final_custody: Observation<Custody>,
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
    pub expected_hold_sha256: String,
    pub acquisition_budget_seconds: u32,
    pub maximum_currentness_age_seconds: u32,
    pub evaluated_at: DateTime<Utc>,
}

pub fn qualify(raw: &[u8], request: &Request) -> Result<Value, String> {
    let source: CleanupSource =
        nq_protocol::decode_json_document(raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    let held = &request.held_request;
    if source.schema != "labelwatch.sqlite-cleanup-observation/v2"
        || source.source_owner != "Labelwatch read-only observer"
        || request.schema != "nq.labelwatch-cleanup-request/v2"
        || held.phase != Phase::PreIngest
        || source.started_at > source.held_source.started_at
        || source.held_source.completed_at > source.completed_at
        || source.completed_at != held.evaluated_at
        || source.completed_at > source.currentness_started_at
        || source.currentness_started_at > source.currentness_completed_at
        || source.currentness_completed_at > request.evaluated_at
        || !(1..=7200).contains(&request.acquisition_budget_seconds)
        || request.acquisition_budget_seconds != source.acquisition_budget_seconds
        || held.maximum_age_seconds != request.acquisition_budget_seconds
        || !(1..=30).contains(&request.maximum_currentness_age_seconds)
        || request.expected_hold_sha256.len() != 64
        || !request
            .expected_hold_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || source.acquisition_exclusions.is_empty()
        || !request.backup.starts_with('/')
        || !request.restore.starts_with('/')
        || request.backup == request.restore
        || [&held.source, &held.original].contains(&&request.backup)
        || [&held.source, &held.original].contains(&&request.restore)
    {
        return Err("closed cleanup source/request or time/subject boundary differs".into());
    }
    let held_qualification = labelwatch_relief::qualify_held_acquisition(
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
    if (source.completed_at - source.started_at).num_milliseconds()
        > i64::from(request.acquisition_budget_seconds) * 1000
        || source.acquisition_duration_ms > u64::from(request.acquisition_budget_seconds) * 1000
    {
        unknown.push("cleanup acquisition budget exceeded".into());
    }
    if (request.evaluated_at - source.currentness_started_at).num_milliseconds()
        >= i64::from(request.maximum_currentness_age_seconds) * 1000
    {
        unknown.push("final currentness witness stale".into());
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
    for (slot, observation) in [
        ("opening_custody", &source.opening_custody),
        ("final_custody", &source.final_custody),
    ] {
        match (&observation.state, &observation.value) {
            (ObservationState::NotObservable, None) => {
                expected_unknowns.insert(slot);
                unknown.push(format!("{slot} not observable"));
            }
            (ObservationState::Observed, Some(custody)) => {
                if custody.hold_sha256 != request.expected_hold_sha256 {
                    refuted.push(format!("{slot} hold generation differs"));
                }
                if custody.files.keys().map(String::as_str).collect::<Vec<_>>()
                    != ["backup", "original", "restore", "source"]
                    || custody.writers.keys().collect::<Vec<_>>()
                        != held.writer_identities.keys().collect::<Vec<_>>()
                {
                    return Err("closed custody file/writer inventory differs".into());
                }
                for (role, writer) in &custody.writers {
                    let expected = &held.writer_identities[role];
                    if !writer.active
                        || writer.pid != expected.pid
                        || writer.start_ticks != expected.start_ticks
                    {
                        refuted.push(format!("{slot} exact held writer differs"));
                    }
                }
                let replacement = source
                    .held_source
                    .database
                    .value
                    .as_ref()
                    .map(|d| &d.identity);
                for (name, path, expected) in [
                    ("source", &held.source, replacement),
                    ("original", &held.original, Some(&held.original_identity)),
                    ("backup", &request.backup, Some(&request.backup_identity)),
                    ("restore", &request.restore, Some(&request.restore_identity)),
                ] {
                    let stamp = &custody.files[name];
                    if stamp.mtime_ns.parse::<i128>().is_err()
                        || stamp.ctime_ns.parse::<i128>().is_err()
                    {
                        return Err("custody timestamps malformed".into());
                    }
                    if let Some(expected) = expected {
                        if stamp.path != *path
                            || stamp.device != expected.device
                            || stamp.inode != expected.inode
                            || stamp.bytes != expected.bytes
                            || stamp.uid != expected.uid
                            || stamp.gid != expected.gid
                            || stamp.mode != expected.mode
                        {
                            refuted
                                .push(format!("{slot} {name} identity differs from acquired cut"));
                        }
                    }
                }
            }
            _ => return Err("custody state/value contradiction".into()),
        }
    }
    if let (Some(opening), Some(final_cut)) =
        (&source.opening_custody.value, &source.final_custody.value)
    {
        if opening.files != final_cut.files {
            refuted.push("file custody changed across acquisition".into());
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
    let mut receipt = json!({"schema":"nq.labelwatch-cleanup-qualification/v2",
        "request":request, "source_utf8":std::str::from_utf8(raw).map_err(|e|e.to_string())?,
        "source_owner":source.source_owner, "claim":"held_cut_and_recoverable_copy_prerequisites",
        "held_qualification":held_qualification, "disposition":disposition,
        "refuted":refuted, "unknown":unknown, "source_limitations":source.limitations,
        "acquisition_exclusions":source.acquisition_exclusions,
        "limitations":["external projection under exact enrolled local custody, not producer authentication",
            "full contents acquired across retained interval; final witness checks custody, not a new content scan",
            "metadata continuity requires externally enrolled all-writer quiescence and protected copy custody",
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
