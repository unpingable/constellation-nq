//! Durable create-only filesystem custody for TURNSTILE evidence events.
//!
//! The journal is observation only. It cannot authorize, claim, execute, or
//! reconcile an occurrence. Each sequence has one immutable pathname, so a
//! concurrent writer can win at most one `create_new` transition.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use nq_protocol::{CanonicalizationError, canonical_json_bytes, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact_evidence::{
    DurableEvidenceEventV1, EvidenceEventBodyV1, ExternalEvidenceChainV1, ExternalEvidenceCustodyV1,
};
use crate::{EvidenceBindingV1, OccurrenceError, TransitionEffectV1};

const JOURNAL_METADATA_SCHEMA_V1: &str = "nq.turnstile_filesystem_evidence_journal.v1";
const METADATA_FILE: &str = "custody.json";
const EVENTS_DIRECTORY: &str = "events";

/// A durable filesystem-journal failure.
#[derive(Debug, Error)]
pub enum FilesystemEvidenceError {
    /// The pure TURNSTILE evidence law refused the content or transition.
    #[error("TURNSTILE evidence law refused filesystem content: {0}")]
    Occurrence(#[from] OccurrenceError),
    /// Canonical JSON encoding failed.
    #[error("cannot canonically encode TURNSTILE evidence: {0}")]
    Canonical(#[from] CanonicalizationError),
    /// Stored JSON could not be decoded.
    #[error("cannot decode TURNSTILE evidence: {0}")]
    Json(#[from] serde_json::Error),
    /// A filesystem operation failed.
    #[error("TURNSTILE evidence filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    /// The durable directory shape is not the closed V1 representation.
    #[error("invalid TURNSTILE evidence filesystem layout: {0}")]
    InvalidLayout(&'static str),
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalMetadataV1 {
    schema: String,
    custody: ExternalEvidenceCustodyV1,
    binding: EvidenceBindingV1,
}

/// Create-only external journal bound to one exact T0 custody identity.
#[derive(Clone, Debug)]
pub struct FilesystemEvidenceJournalV1 {
    root: PathBuf,
    custody: ExternalEvidenceCustodyV1,
    binding: EvidenceBindingV1,
}

impl FilesystemEvidenceJournalV1 {
    /// Creates or exactly reopens one journal directory.
    ///
    /// The root must be a real directory rather than a symbolic link. An
    /// existing metadata file is accepted only when its canonical bytes equal
    /// the requested custody and binding exactly.
    ///
    /// # Errors
    ///
    /// Refuses custody substitution, non-canonical metadata, symbolic links,
    /// or any alternate closed directory layout.
    pub fn open(
        root: impl AsRef<Path>,
        custody: ExternalEvidenceCustodyV1,
        binding: EvidenceBindingV1,
    ) -> Result<Self, FilesystemEvidenceError> {
        custody.verify_binding(&binding)?;
        let root = root.as_ref().to_path_buf();
        create_real_directory(&root)?;
        let events = root.join(EVENTS_DIRECTORY);
        create_real_directory(&events)?;

        let metadata = JournalMetadataV1 {
            schema: JOURNAL_METADATA_SCHEMA_V1.into(),
            custody: custody.clone(),
            binding: binding.clone(),
        };
        let metadata_bytes = canonical_json_bytes(&metadata)?;
        create_or_verify_exact(&root.join(METADATA_FILE), &metadata_bytes)?;
        sync_directory(&root)?;

        let journal = Self {
            root,
            custody,
            binding,
        };
        journal.reopen()?;
        Ok(journal)
    }

    /// Absolute journal directory after filesystem canonicalization.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the campaign custody path is no longer
    /// resolvable.
    pub fn canonical_root(&self) -> Result<PathBuf, FilesystemEvidenceError> {
        Ok(fs::canonicalize(&self.root)?)
    }

    /// Reopens every exact sequence object and validates the complete chain.
    ///
    /// # Errors
    ///
    /// Refuses gaps, alternate filenames, symbolic links, non-canonical JSON,
    /// content mutation, custody substitution, or broken transition links.
    pub fn reopen(&self) -> Result<ExternalEvidenceChainV1, FilesystemEvidenceError> {
        require_real_directory(&self.root)?;
        let metadata_bytes = fs::read(self.root.join(METADATA_FILE))?;
        let metadata: JournalMetadataV1 = serde_json::from_slice(&metadata_bytes)?;
        if metadata.schema != JOURNAL_METADATA_SCHEMA_V1
            || metadata.custody != self.custody
            || metadata.binding != self.binding
            || canonical_json_bytes(&metadata)? != metadata_bytes
        {
            return Err(FilesystemEvidenceError::InvalidLayout(
                "custody metadata substitution",
            ));
        }

        let events_path = self.root.join(EVENTS_DIRECTORY);
        require_real_directory(&events_path)?;
        let mut numbered = Vec::new();
        for entry in fs::read_dir(&events_path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(FilesystemEvidenceError::InvalidLayout(
                    "event object is not a regular file",
                ));
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| FilesystemEvidenceError::InvalidLayout("event filename UTF-8"))?;
            let Some(sequence) = parse_event_filename(&name) else {
                return Err(FilesystemEvidenceError::InvalidLayout(
                    "unknown event filename",
                ));
            };
            numbered.push((sequence, entry.path()));
        }
        numbered.sort_by_key(|(sequence, _)| *sequence);

        let mut events = Vec::with_capacity(numbered.len());
        for (expected, (sequence, path)) in numbered.into_iter().enumerate() {
            if sequence != expected as u64 {
                return Err(FilesystemEvidenceError::InvalidLayout(
                    "evidence sequence gap",
                ));
            }
            let bytes = fs::read(path)?;
            let event: DurableEvidenceEventV1 = serde_json::from_slice(&bytes)?;
            if canonical_json_bytes(&event)? != bytes {
                return Err(FilesystemEvidenceError::InvalidLayout(
                    "event is not canonical JCS bytes",
                ));
            }
            events.push(event);
        }
        Ok(ExternalEvidenceChainV1::reopen(
            &self.custody,
            &self.binding,
            events,
        )?)
    }

    /// Durably appends one exact event or accepts its exact replay.
    ///
    /// The event object is written with `create_new`, synchronized, and then
    /// followed by a parent-directory synchronization. A concurrent writer
    /// choosing different content for the same sequence deterministically
    /// refuses after one writer wins the pathname.
    ///
    /// # Errors
    ///
    /// Refuses transition, predecessor, replay, or filesystem substitution.
    pub fn append(
        &self,
        body: EvidenceEventBodyV1,
    ) -> Result<TransitionEffectV1, FilesystemEvidenceError> {
        let mut chain = self.reopen()?;
        let effect = chain.append(body)?;
        if effect == TransitionEffectV1::IdempotentReplay {
            return Ok(effect);
        }
        let event = chain
            .events
            .last()
            .ok_or(FilesystemEvidenceError::InvalidLayout(
                "applied append has no event",
            ))?;
        let bytes = canonical_json_bytes(event)?;
        let events_path = self.root.join(EVENTS_DIRECTORY);
        let path = events_path.join(event_filename(event.body.sequence));
        match create_exact_file(&path, &bytes) {
            Ok(()) => {
                sync_directory(&events_path)?;
                Ok(TransitionEffectV1::Applied)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let stored = fs::read(path)?;
                if stored == bytes {
                    Ok(TransitionEffectV1::IdempotentReplay)
                } else {
                    Err(OccurrenceError::ReplayConflict("filesystem evidence sequence").into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Content identity of the exact custody contract stored by this journal.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization error if the contract cannot be represented.
    pub fn custody_digest(&self) -> Result<nq_protocol::Sha256Digest, FilesystemEvidenceError> {
        Ok(semantic_digest(&self.custody)?)
    }
}

fn create_real_directory(path: &Path) -> Result<(), FilesystemEvidenceError> {
    match fs::create_dir(path) {
        Ok(()) => sync_directory(
            path.parent()
                .ok_or(FilesystemEvidenceError::InvalidLayout("directory parent"))?,
        )?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    require_real_directory(path)
}

fn require_real_directory(path: &Path) -> Result<(), FilesystemEvidenceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(FilesystemEvidenceError::InvalidLayout(
            "journal path is not a real directory",
        ));
    }
    Ok(())
}

fn create_or_verify_exact(path: &Path, bytes: &[u8]) -> Result<(), FilesystemEvidenceError> {
    match create_exact_file(path, bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::read(path)? == bytes {
                Ok(())
            } else {
                Err(FilesystemEvidenceError::InvalidLayout(
                    "existing immutable object differs",
                ))
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn create_exact_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn event_filename(sequence: u64) -> String {
    format!("{sequence:016}.json")
}

fn parse_event_filename(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".json")?;
    if digits.len() != 16 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use nq_protocol::{Sha256Digest, sha256_bytes};
    use tempfile::TempDir;

    use super::*;
    use crate::artifact_evidence::{
        EVIDENCE_EVENT_SCHEMA_V1, EXTERNAL_CUSTODY_SCHEMA_V1, EvidenceEventKindV1,
    };

    fn digest(value: &str) -> Sha256Digest {
        sha256_bytes(value.as_bytes())
    }

    fn binding() -> EvidenceBindingV1 {
        EvidenceBindingV1 {
            canonical_custody_id: digest("canonical"),
            selection_contract_digest: digest("selection"),
            external_journal_id: digest("journal"),
            receipt_destination_id: digest("receipts"),
            required_free_bytes: 10 * 1024 * 1024 * 1024,
            retention_mode: "retain_all".into(),
        }
    }

    fn custody() -> ExternalEvidenceCustodyV1 {
        ExternalEvidenceCustodyV1 {
            schema: EXTERNAL_CUSTODY_SCHEMA_V1.into(),
            journal_id: digest("journal"),
            receipt_destination_id: digest("receipts"),
            outside_workload_ephemeral_state: true,
            append_only: true,
            retention_mode: "retain_all".into(),
            encoding: "rfc8785_jcs".into(),
            durability_law: "sync_event_then_parent_directory_v1".into(),
            writer_domain: digest("writer-domain"),
        }
    }

    fn genesis(observation: &str) -> EvidenceEventBodyV1 {
        EvidenceEventBodyV1 {
            schema: EVIDENCE_EVENT_SCHEMA_V1.into(),
            sequence: 0,
            predecessor: None,
            journal_id: digest("journal"),
            plan_id: digest("plan"),
            nq_occurrence: digest("occurrence"),
            docket: None,
            runtime: None,
            kind: EvidenceEventKindV1::Prepared,
            observation_digest: digest(observation),
            observed_at_unix_ms: 1_000,
        }
    }

    fn open_journal(temp: &TempDir) -> FilesystemEvidenceJournalV1 {
        FilesystemEvidenceJournalV1::open(temp.path().join("journal"), custody(), binding())
            .unwrap()
    }

    #[test]
    fn durable_restart_and_exact_replay_preserve_one_event() {
        let temp = TempDir::new().unwrap();
        let journal = open_journal(&temp);
        assert_eq!(
            journal.append(genesis("prepared")).unwrap(),
            TransitionEffectV1::Applied
        );
        drop(journal);
        let reopened = open_journal(&temp);
        assert_eq!(reopened.reopen().unwrap().events.len(), 1);
        assert_eq!(
            reopened.append(genesis("prepared")).unwrap(),
            TransitionEffectV1::IdempotentReplay
        );
        assert_eq!(reopened.reopen().unwrap().events.len(), 1);
    }

    #[test]
    fn concurrent_different_genesis_has_one_winner_and_one_refusal() {
        let temp = TempDir::new().unwrap();
        let journal = Arc::new(open_journal(&temp));
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for observation in ["first", "second"] {
            let journal = Arc::clone(&journal);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                journal.append(genesis(observation))
            }));
        }
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
        assert_eq!(journal.reopen().unwrap().events.len(), 1);
    }

    #[test]
    fn content_mutation_and_sequence_gap_refuse_closed_reopen() {
        let temp = TempDir::new().unwrap();
        let journal = open_journal(&temp);
        journal.append(genesis("prepared")).unwrap();
        let event = temp.path().join("journal/events/0000000000000000.json");
        fs::set_permissions(&event, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        fs::write(&event, b"{}" as &[u8]).unwrap();
        assert!(journal.reopen().is_err());

        let other = TempDir::new().unwrap();
        let journal = open_journal(&other);
        fs::write(
            other.path().join("journal/events/0000000000000001.json"),
            b"{}" as &[u8],
        )
        .unwrap();
        assert!(matches!(
            journal.reopen(),
            Err(FilesystemEvidenceError::InvalidLayout(
                "evidence sequence gap"
            ))
        ));
    }

    #[test]
    fn metadata_substitution_and_symlink_root_refuse() {
        let temp = TempDir::new().unwrap();
        let journal = open_journal(&temp);
        let mut different = binding();
        different.required_free_bytes += 1;
        assert!(
            FilesystemEvidenceJournalV1::open(journal.root.clone(), custody(), different).is_err()
        );

        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&journal.root, &link).unwrap();
        assert!(FilesystemEvidenceJournalV1::open(link, custody(), binding()).is_err());
    }
}
