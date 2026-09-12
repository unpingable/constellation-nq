//! Bounded factual qualification of a fresh Labelwatch read-only observation.
//! External-projection custody is explicit. No action authority, daemon, or
//! inference from an enactment receipt is introduced by this compiled profile.
use chrono::{DateTime, Utc};
use nq_protocol::semantic_digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub identity: FileIdentity,
    pub verification_sha256: String,
    pub matches_declared_cut: bool,
    pub application_schema: u32,
    pub integrity: String,
    pub progress_meta_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    pub device: u64,
    pub free_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presence {
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WriterIdentity {
    pub pid: u32,
    pub start_ticks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Writer {
    pub active: bool,
    pub pid: u32,
    pub start_ticks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation<T> {
    pub state: ObservationState,
    pub value: Option<T>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ObservationState {
    #[serde(rename = "OBSERVED")]
    Observed,
    #[serde(rename = "NOT_OBSERVABLE")]
    NotObservable,
}

impl<T> Observation<T> {
    fn observed(&self) -> Result<Option<&T>, String> {
        match (&self.state, &self.value) {
            (ObservationState::Observed, Some(value)) => Ok(Some(value)),
            (ObservationState::NotObservable, None) => Ok(None),
            _ => Err("observation state/value contradiction".into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unknown {
    pub slot: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub schema: String,
    pub source_owner: String,
    pub operation: String,
    pub source: String,
    pub original: String,
    pub application_revision: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub database: Observation<Database>,
    pub filesystem: Observation<Filesystem>,
    pub original_presence: Observation<Presence>,
    pub write_hold: Observation<bool>,
    pub writers: Observation<BTreeMap<String, Writer>>,
    pub unknowns: Vec<Unknown>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Phase {
    #[serde(rename = "pre_ingest")]
    PreIngest,
    #[serde(rename = "post_release")]
    PostRelease,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub operation: String,
    pub source: String,
    pub original: String,
    pub application_revision: String,
    pub expected_cut_sha256: String,
    pub original_identity: FileIdentity,
    pub replacement_device: u64,
    pub replacement_inode: u64,
    pub writer_identities: BTreeMap<String, WriterIdentity>,
    pub phase: Phase,
    pub required_free_bytes: u64,
    pub evaluated_at: DateTime<Utc>,
    pub maximum_age_seconds: u32,
    /// Exact earlier qualified pre-ingest record; replayed, never an enactment.
    pub pre_ingest_qualification: Option<Value>,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn qualify(raw: &[u8], request: &Request) -> Result<Value, String> {
    qualify_depth(raw, request, 0)
}

fn qualify_depth(raw: &[u8], r: &Request, depth: u8) -> Result<Value, String> {
    qualify_profile(raw, r, depth, false)
}

/// Qualify an explicitly bounded historical held acquisition, not currentness.
/// This separate profile does not change relief v1's 30-second semantics.
pub fn qualify_held_acquisition(raw: &[u8], r: &Request) -> Result<Value, String> {
    if r.phase != Phase::PreIngest || r.pre_ingest_qualification.is_some() {
        return Err("held acquisition is pre-ingest only".into());
    }
    qualify_profile(raw, r, 0, true)
}

fn qualify_profile(raw: &[u8], r: &Request, depth: u8, acquisition: bool) -> Result<Value, String> {
    if depth > 1 {
        return Err("bounded predecessor depth exceeded".into());
    }
    let value =
        nq_protocol::decode_json_document(raw, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    let s: Source = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let request_schema = if acquisition {
        "nq.labelwatch-held-acquisition-request/v1"
    } else {
        "nq.labelwatch-relief-request/v1"
    };
    if r.schema != request_schema
        || s.schema != "labelwatch.sqlite-relief-observation/v1"
        || s.source_owner != "Labelwatch read-only observer"
        || s.operation != r.operation
        || r.operation.is_empty()
        || s.source != r.source
        || s.original != r.original
        || !r.source.starts_with('/')
        || !r.original.starts_with('/')
        || r.source == r.original
        || s.application_revision != r.application_revision
        || !hex(&r.application_revision, 40)
        || !hex(&r.expected_cut_sha256, 64)
        || !hex(&r.original_identity.sha256, 64)
        || !(1..=if acquisition { 7200 } else { 30 }).contains(&r.maximum_age_seconds)
        || r.writer_identities
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != ["discovery", "main"]
        || r.writer_identities
            .values()
            .any(|w| w.pid == 0 || w.start_ticks == 0)
        || r.writer_identities["main"].pid == r.writer_identities["discovery"].pid
        || s.started_at > s.completed_at
        || s.completed_at > r.evaluated_at
    {
        return Err("exact request/source/identity/time binding refused".into());
    }
    let database = s.database.observed()?;
    let filesystem = s.filesystem.observed()?;
    let presence = s.original_presence.observed()?;
    let hold = s.write_hold.observed()?;
    let writers = s.writers.observed()?;
    let mut unknown = Vec::new();
    let mut refuted = Vec::new();
    for (slot, missing) in [
        ("database", database.is_none()),
        ("filesystem", filesystem.is_none()),
        ("original_presence", presence.is_none()),
        ("write_hold", hold.is_none()),
        ("writers", writers.is_none()),
    ] {
        if missing {
            unknown.push(slot);
        }
    }
    let unknown_slots: std::collections::BTreeSet<_> =
        s.unknowns.iter().map(|u| u.slot.as_str()).collect();
    if unknown_slots != unknown.iter().copied().collect()
        || s.unknowns.len() != unknown_slots.len()
        || s.unknowns.iter().any(|u| u.reason.is_empty())
    {
        return Err("unknown accounting differs from actual observation states".into());
    }
    if (r.evaluated_at - s.started_at).num_milliseconds() > i64::from(r.maximum_age_seconds) * 1000
    {
        unknown.push("stale observation");
    }
    if let Some(d) = database {
        if !hex(&d.verification_sha256, 64)
            || !hex(&d.progress_meta_sha256, 64)
            || !hex(&d.identity.sha256, 64)
            || d.identity.mode > 0o7777
        {
            return Err("malformed database observation".into());
        }
        if d.matches_declared_cut != (d.verification_sha256 == r.expected_cut_sha256) {
            return Err("declared-cut comparison contradicts exact digest".into());
        }
        if d.application_schema != 23
            || d.integrity != "ok"
            || d.identity.device != r.replacement_device
            || d.identity.inode != r.replacement_inode
        {
            refuted.push("replacement identity/application verification");
        }
        if r.phase == Phase::PreIngest && !d.matches_declared_cut {
            refuted.push("logical cut differs");
        }
    }
    if let Some(f) = filesystem {
        if f.device != r.replacement_device {
            refuted.push("filesystem identity differs");
        }
        if r.phase == Phase::PostRelease && f.free_bytes < r.required_free_bytes {
            refuted.push("resource margin absent");
        }
    }
    if let Some(p) = presence {
        if p.present != p.identity.is_some()
            || (!p.present
                && p.scope.as_deref() != Some("enrolled original pathname, not whole filesystem"))
        {
            return Err("original presence/identity shape inconsistent".into());
        }
        if r.phase == Phase::PreIngest {
            if p.identity.as_ref() != Some(&r.original_identity) {
                refuted.push("retained original differs");
            }
        } else if p.present {
            refuted.push("original still present");
        }
    }
    if let Some(held) = hold {
        if *held != (r.phase == Phase::PreIngest) {
            refuted.push("write hold phase differs");
        }
    }
    if let Some(observed) = writers {
        if observed.len() != 2 {
            return Err("enrolled writer inventory differs".into());
        }
        for (role, expected) in &r.writer_identities {
            let current = observed
                .get(role)
                .ok_or("enrolled writer absent from inventory")?;
            if current.pid != expected.pid || current.start_ticks != expected.start_ticks {
                return Err("writer identity differs from enrolled occurrence".into());
            }
            if !current.active {
                refuted.push("enrolled writer not active");
            }
        }
    }
    if r.phase == Phase::PreIngest {
        if r.pre_ingest_qualification.is_some() {
            return Err("pre-ingest cannot have a predecessor".into());
        }
    } else if let Some(previous) = &r.pre_ingest_qualification {
        replay_depth(previous, depth + 1)?;
        let pr: Request =
            serde_json::from_value(previous["request"].clone()).map_err(|e| e.to_string())?;
        if previous["disposition"] != "ESTABLISHED"
            || pr.phase != Phase::PreIngest
            || pr.operation != r.operation
            || pr.source != r.source
            || pr.original != r.original
            || pr.application_revision != r.application_revision
            || pr.expected_cut_sha256 != r.expected_cut_sha256
            || pr.original_identity != r.original_identity
            || pr.replacement_device != r.replacement_device
            || pr.replacement_inode != r.replacement_inode
            || pr.writer_identities != r.writer_identities
            || pr.evaluated_at > s.started_at
        {
            return Err("post-release predecessor not exact qualified pre-ingest subject".into());
        }
    } else {
        unknown.push("qualified pre-ingest evidence absent");
    }
    let disposition = if !refuted.is_empty() {
        "REFUTED"
    } else if !unknown.is_empty() {
        "NOT_OBSERVABLE"
    } else {
        "ESTABLISHED"
    };
    let receipt_schema = if acquisition {
        "nq.labelwatch-held-acquisition-qualification/v1"
    } else {
        "nq.labelwatch-relief-qualification/v1"
    };
    let mut result = json!({"schema":receipt_schema, "request":r,
        "source_utf8":std::str::from_utf8(raw).map_err(|e|e.to_string())?,
        "source_owner":"Labelwatch read-only observer", "disposition":disposition,
        "claim":if acquisition {"held_logical_cut_acquired_not_currentness"} else if r.phase==Phase::PreIngest {"held_logical_cut_preserved"} else {"resource_relief_postcondition"},
        "refuted":refuted,"unknown":unknown,"source_limitations":s.limitations,
        "limitations":["external projection under enrolled local source custody, not producer authentication",
            "qualified at observation interval, not persistent currentness or future execution",
            "no authorization or literal distributed exactly-once claim; pre-cut preservation and post-release reads are separate"]});
    result["receipt_id"] = json!(semantic_digest(&result).map_err(|e| e.to_string())?);
    Ok(result)
}

fn replay_depth(receipt: &Value, depth: u8) -> Result<(), String> {
    let r: Request =
        serde_json::from_value(receipt["request"].clone()).map_err(|e| e.to_string())?;
    let raw = receipt["source_utf8"]
        .as_str()
        .ok_or("source bytes absent")?;
    if qualify_depth(raw.as_bytes(), &r, depth)? != *receipt {
        return Err("qualification replay differs".into());
    }
    Ok(())
}

pub fn replay(receipt: &Value) -> Result<(), String> {
    replay_depth(receipt, 0)
}
