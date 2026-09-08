//! Closed Git-status observation profile. Replay establishes this historical
//! observation only; neither an atomic snapshot nor future execution custody.

use chrono::{DateTime, Utc};
use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "nq.repository_state.execution.v1";
pub const PROFILE: &str = "nq.repository_state.git_status.v1";
pub const MAX_OUTPUT: usize = 1_048_576;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositorySubject {
    pub worktree: String,
    pub device: u64,
    pub inode: u64,
    pub git_directory: String,
}

impl RepositorySubject {
    pub fn identity(&self) -> Result<Sha256Digest, String> {
        semantic_digest(self).map_err(|e| e.to_string())
    }
}

/// Exact stdout from a fixed, named acquisition operation. Error output is not
/// exported, because it may contain local configuration or sensitive locators.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandObservation {
    pub operation: String,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub failure: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryEvidence {
    pub subject: RepositorySubject,
    pub subject_identity: Sha256Digest,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub git_executable: Sha256Digest,
    pub collector_executable: Sha256Digest,
    pub commands: Vec<CommandObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RepositoryDisposition {
    Clean { head: String },
    ChangesPresent { head: String },
    NotEstablished { reason: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryExecution {
    pub schema: String,
    pub profile: String,
    pub evaluator_source: String,
    pub evidence: RepositoryEvidence,
    pub disposition: RepositoryDisposition,
    pub content_digest: Sha256Digest,
}

/// Closed operations: no arbitrary predicate or command is admitted.
pub const OPERATIONS: [&str; 6] = [
    "bare",
    "head_before",
    "index",
    "status",
    "head_after",
    "index_flags",
];

pub fn evaluate(evidence: &RepositoryEvidence) -> Result<RepositoryDisposition, String> {
    if evidence.subject_identity != evidence.subject.identity()?
        || !evidence.subject.worktree.starts_with('/')
        || !evidence.subject.git_directory.starts_with('/')
        || evidence.started_at > evidence.ended_at
        || (evidence.ended_at - evidence.started_at).num_seconds() > 30
        || evidence.commands.len() != OPERATIONS.len()
    {
        return Err("invalid subject, acquisition interval, or operation accounting".into());
    }
    for (command, operation) in evidence.commands.iter().zip(OPERATIONS) {
        if command.operation != operation || command.stdout.len() > MAX_OUTPUT {
            return Err("wrong operation or oversized evidence".into());
        }
        if command.failure.is_some() || command.exit_code != Some(0) {
            return Ok(RepositoryDisposition::NotEstablished {
                reason: format!("acquisition_unavailable:{operation}"),
            });
        }
    }
    let outputs = &evidence.commands;
    let flags = &outputs[5].stdout;
    if !flags.is_empty() && !flags.ends_with(&[0]) {
        return Err("truncated index flags".into());
    }
    for entry in flags.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        if entry.len() < 3 || entry[1] != b' ' {
            return Err("invalid index flags".into());
        }
        if entry[0].is_ascii_lowercase() || entry[0] == b'S' {
            return Ok(RepositoryDisposition::NotEstablished {
                reason: "index_suppression_flags_unsupported".into(),
            });
        }
        if !b"HMRCK?U".contains(&entry[0]) {
            return Err("unsupported index flag".into());
        }
    }
    if outputs[0].stdout != b"false\n" {
        return Ok(RepositoryDisposition::NotEstablished {
            reason: "bare_repository_unsupported".into(),
        });
    }
    let head = std::str::from_utf8(&outputs[1].stdout)
        .map_err(|_| "non-UTF8 HEAD")?
        .trim_end_matches('\n');
    if ![40, 64].contains(&head.len())
        || !head
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid HEAD".into());
    }
    if outputs[1].stdout != outputs[4].stdout {
        return Ok(RepositoryDisposition::NotEstablished {
            reason: "head_changed_during_observation".into(),
        });
    }
    // Reject submodules instead of treating their potentially ignored dirt as
    // evidence about the enrolled repository. Strict stage framing is retained.
    let index = &outputs[2].stdout;
    if !index.is_empty() && !index.ends_with(&[0]) {
        return Err("truncated index".into());
    }
    for entry in index.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        if entry.starts_with(b"160000 ") {
            return Ok(RepositoryDisposition::NotEstablished {
                reason: "submodules_unsupported".into(),
            });
        }
        let Some(tab) = entry.iter().position(|b| *b == b'\t') else {
            return Err("invalid index entry".into());
        };
        if tab < 10 || !entry[..tab].contains(&b' ') || tab + 1 == entry.len() {
            return Err("invalid index framing".into());
        }
    }
    let status = &outputs[3].stdout;
    if status.is_empty() {
        return Ok(RepositoryDisposition::Clean { head: head.into() });
    }
    if !status.ends_with(&[0]) {
        return Err("truncated porcelain status".into());
    }
    let mut entries = status.split(|b| *b == 0).peekable();
    while let Some(entry) = entries.next() {
        if entry.is_empty() && entries.peek().is_none() {
            break;
        }
        if entry.len() < 4
            || entry[2] != b' '
            || !entry[..2].iter().all(|b| b" MADRCU?!T".contains(b))
            || &entry[..2] == b"  "
            || entry[..2].contains(&b'!')
        {
            return Err("invalid porcelain entry".into());
        }
        if entry[..2].iter().any(|b| b"RC".contains(b))
            && entries.next().is_none_or(|e| e.is_empty())
        {
            return Err("missing rename source".into());
        }
    }
    Ok(RepositoryDisposition::ChangesPresent { head: head.into() })
}

impl RepositoryExecution {
    pub fn produce(evidence: RepositoryEvidence) -> Result<Self, String> {
        let disposition = evaluate(&evidence)?;
        let mut result = Self {
            schema: SCHEMA.into(),
            profile: PROFILE.into(),
            evaluator_source: crate::EVALUATOR_SOURCE_DIGEST.into(),
            evidence,
            disposition,
            content_digest: nq_protocol::sha256_bytes(b""),
        };
        result.content_digest = result.digest()?;
        Ok(result)
    }

    fn digest(&self) -> Result<Sha256Digest, String> {
        semantic_digest(&(
            SCHEMA,
            &self.profile,
            &self.evaluator_source,
            &self.evidence,
            &self.disposition,
        ))
        .map_err(|e| e.to_string())
    }

    /// Replay requires this exact evaluator source closure and exact producing
    /// executable; callers separately enroll the expected subject and time.
    pub fn replay(&self, producer: &Sha256Digest) -> Result<(), String> {
        if self.schema != SCHEMA
            || self.profile != PROFILE
            || self.evaluator_source != crate::EVALUATOR_SOURCE_DIGEST
            || self.evidence.collector_executable != *producer
            || self.content_digest != self.digest()?
            || self.disposition != evaluate(&self.evidence)?
        {
            return Err("repository execution identity or replay mismatch".into());
        }
        Ok(())
    }
}
