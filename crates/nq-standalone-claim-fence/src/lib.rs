//! Durable standalone NQ occurrence claim and provider-fence state machine.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path};
use std::time::Duration;

use nix::unistd::Uid;
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CLAIM_SCHEMA: &str = "nq.standalone_claim_request.v1";
const TRANSITION_SCHEMA: &str = "nq.standalone_claim_transition.v1";
const RECEIPT_SCHEMA: &str = "nq.standalone_claim_fence_receipt.v1";
const CLAIM_DOMAIN: &[u8] = b"nq.standalone_claim_request.v1\0";
const TRANSITION_DOMAIN: &[u8] = b"nq.standalone_claim_transition.v1\0";

/// Exact immutable inputs to one standalone occurrence claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequestV1 {
    /// Closed schema name.
    pub schema: String,
    /// Fresh durable occurrence identity.
    pub occurrence_id: String,
    /// Exact coordination domain serialized by this claim.
    pub coordination_domain_id: String,
    /// Exact qualified mechanics identity.
    pub mechanics_digest: Sha256Digest,
    /// Exact upstream authorization receipt identity; it grants no authority here.
    pub authorization_receipt_digest: Sha256Digest,
    /// Exact runtime identity to which a later fence applies.
    pub runtime_identity_digest: Sha256Digest,
    /// Fresh claim nonce.
    pub claim_nonce: String,
}

/// Durable claim state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    /// Exact occurrence and domain are exclusively claimed.
    Claimed,
    /// Provider/runtime fence is durably established.
    Fenced,
    /// One release was durably emitted; mechanics outcome is not yet terminal.
    Released,
    /// Released mechanics have no determinate retained outcome.
    OutcomeUnknown,
    /// Claim has a final retained outcome and no longer holds the domain.
    Terminal,
}

impl ClaimState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Fenced => "fenced",
            Self::Released => "released",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::Terminal => "terminal",
        }
    }

    fn parse(value: &str) -> Result<Self, ClaimFenceError> {
        match value {
            "claimed" => Ok(Self::Claimed),
            "fenced" => Ok(Self::Fenced),
            "released" => Ok(Self::Released),
            "outcome_unknown" => Ok(Self::OutcomeUnknown),
            "terminal" => Ok(Self::Terminal),
            _ => Err(ClaimFenceError::Refused(
                "stored claim state is unknown".into(),
            )),
        }
    }
}

/// Exact append-only transition kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    /// Establish the exact provider/runtime fence.
    Fence,
    /// Emit the one-use mechanics release.
    Release,
    /// Record a determinate completion.
    Complete,
    /// Record an indeterminate post-release outcome.
    MarkOutcomeUnknown,
    /// Resolve only a previously indeterminate outcome.
    Reconcile,
}

impl TransitionKind {
    fn edge(self) -> (ClaimState, ClaimState) {
        match self {
            Self::Fence => (ClaimState::Claimed, ClaimState::Fenced),
            Self::Release => (ClaimState::Fenced, ClaimState::Released),
            Self::Complete => (ClaimState::Released, ClaimState::Terminal),
            Self::MarkOutcomeUnknown => (ClaimState::Released, ClaimState::OutcomeUnknown),
            Self::Reconcile => (ClaimState::OutcomeUnknown, ClaimState::Terminal),
        }
    }
}

/// Exact request for one append-only claim transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRequestV1 {
    /// Closed schema name.
    pub schema: String,
    /// Domain-separated identity of the claimed request.
    pub claim_id: Sha256Digest,
    /// Repeated exact occurrence identity.
    pub occurrence_id: String,
    /// Repeated exact coordination domain.
    pub coordination_domain_id: String,
    /// Repeated exact mechanics identity.
    pub mechanics_digest: Sha256Digest,
    /// Requested transition edge.
    pub transition: TransitionKind,
    /// Fresh transition nonce, unique across the store.
    pub transition_nonce: String,
    /// Exact evidence for this transition.
    pub evidence_digest: Sha256Digest,
}

/// Whether this call appended state or reopened an exact prior mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// One new durable row/event was appended.
    Advanced,
    /// The exact request was already durable; no new release or transition occurred.
    ExactReplay,
}

/// Stable machine-readable receipt for claim/fence operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MutationReceiptV1 {
    /// Closed receipt schema.
    pub schema: &'static str,
    /// Mutation/replay disposition.
    pub disposition: Disposition,
    /// Exact claim identity.
    pub claim_id: Sha256Digest,
    /// Transition identity, absent only for claim creation/reopen.
    pub transition_id: Option<Sha256Digest>,
    /// State established by this exact mutation.
    pub resulting_state: ClaimState,
}

/// Standalone claim/fence failure.
#[derive(Debug, Error)]
pub enum ClaimFenceError {
    /// Filesystem custody failed.
    #[error("filesystem custody failed: {0}")]
    Io(#[from] std::io::Error),
    /// `SQLite` custody failed.
    #[error("durable claim store failed: {0}")]
    Store(#[from] rusqlite::Error),
    /// Canonical JSON failed.
    #[error("canonical JSON failed: {0}")]
    Canonical(#[from] nq_protocol::CanonicalizationError),
    /// Closed contract or state transition refused.
    #[error("claim/fence refused: {0}")]
    Refused(String),
}

/// Durable standalone claim/fence interface. It has no mechanics runner.
pub struct ClaimFence {
    connection: Connection,
}

impl ClaimFence {
    /// Opens or creates one private durable claim/fence store.
    ///
    /// # Errors
    ///
    /// Refuses non-private, symbolic-link, replaced, or incompatible state custody.
    pub fn open(path: &Path) -> Result<Self, ClaimFenceError> {
        let connection = open_secure(path)?;
        Ok(Self { connection })
    }

    /// Creates or exactly reopens one immutable occurrence claim.
    ///
    /// # Errors
    ///
    /// Refuses substituted identity, active-domain collision, or invalid input.
    pub fn claim(
        &mut self,
        request: &ClaimRequestV1,
    ) -> Result<MutationReceiptV1, ClaimFenceError> {
        validate_claim(request)?;
        let claim_id = framed_digest(CLAIM_DOMAIN, request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let by_occurrence: Option<(String, String, String, String, String, String)> = transaction
            .query_row(
                "SELECT claim_id,coordination_domain_id,mechanics_digest,authorization_receipt_digest,runtime_identity_digest,state FROM claims WHERE occurrence_id=?1",
                [&request.occurrence_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            ).optional()?;
        if let Some((stored_id, domain, mechanics, authorization, runtime, state)) = by_occurrence {
            if stored_id != claim_id.as_str()
                || domain != request.coordination_domain_id
                || mechanics != request.mechanics_digest.as_str()
                || authorization != request.authorization_receipt_digest.as_str()
                || runtime != request.runtime_identity_digest.as_str()
            {
                return Err(ClaimFenceError::Refused(
                    "occurrence already has a different immutable claim".into(),
                ));
            }
            transaction.commit()?;
            return Ok(MutationReceiptV1 {
                schema: RECEIPT_SCHEMA,
                disposition: Disposition::ExactReplay,
                claim_id,
                transition_id: None,
                resulting_state: ClaimState::parse(&state)?,
            });
        }
        let active: Option<String> = transaction
            .query_row(
                "SELECT claim_id FROM claims WHERE coordination_domain_id=?1 AND state!='terminal'",
                [&request.coordination_domain_id],
                |row| row.get(0),
            )
            .optional()?;
        if active.is_some() {
            return Err(ClaimFenceError::Refused(
                "coordination domain already has an active claim".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO claims(claim_id,occurrence_id,coordination_domain_id,mechanics_digest,authorization_receipt_digest,runtime_identity_digest,state) VALUES (?1,?2,?3,?4,?5,?6,'claimed')",
            params![claim_id.as_str(), request.occurrence_id, request.coordination_domain_id,
                request.mechanics_digest.as_str(), request.authorization_receipt_digest.as_str(), request.runtime_identity_digest.as_str()],
        )?;
        transaction.commit()?;
        Ok(MutationReceiptV1 {
            schema: RECEIPT_SCHEMA,
            disposition: Disposition::Advanced,
            claim_id,
            transition_id: None,
            resulting_state: ClaimState::Claimed,
        })
    }

    /// Advances one exact append-only fence/release/outcome transition.
    ///
    /// # Errors
    ///
    /// Refuses alternate histories, substitution, nonce reuse, and skipped edges.
    pub fn transition(
        &mut self,
        request: &TransitionRequestV1,
    ) -> Result<MutationReceiptV1, ClaimFenceError> {
        validate_transition(request)?;
        let transition_id = framed_digest(TRANSITION_DOMAIN, request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let replay: Option<(String, String)> = transaction
            .query_row(
                "SELECT claim_id,resulting_state FROM claim_events WHERE transition_id=?1",
                [transition_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((claim_id, state)) = replay {
            if claim_id != request.claim_id.as_str() {
                return Err(ClaimFenceError::Refused(
                    "transition identity belongs to another claim".into(),
                ));
            }
            transaction.commit()?;
            return Ok(MutationReceiptV1 {
                schema: RECEIPT_SCHEMA,
                disposition: Disposition::ExactReplay,
                claim_id: request.claim_id.clone(),
                transition_id: Some(transition_id),
                resulting_state: ClaimState::parse(&state)?,
            });
        }
        let nonce_owner: Option<String> = transaction
            .query_row(
                "SELECT transition_id FROM claim_events WHERE transition_nonce=?1",
                [&request.transition_nonce],
                |row| row.get(0),
            )
            .optional()?;
        if nonce_owner.is_some() {
            return Err(ClaimFenceError::Refused(
                "transition nonce was already used by another event".into(),
            ));
        }
        let claim: Option<(String, String, String, String)> = transaction.query_row(
            "SELECT occurrence_id,coordination_domain_id,mechanics_digest,state FROM claims WHERE claim_id=?1",
            [request.claim_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        let Some((occurrence, domain, mechanics, state)) = claim else {
            return Err(ClaimFenceError::Refused("claim identity is absent".into()));
        };
        if occurrence != request.occurrence_id
            || domain != request.coordination_domain_id
            || mechanics != request.mechanics_digest.as_str()
        {
            return Err(ClaimFenceError::Refused(
                "transition identity does not match immutable claim".into(),
            ));
        }
        let current = ClaimState::parse(&state)?;
        let (required, resulting) = request.transition.edge();
        if current != required {
            return Err(ClaimFenceError::Refused(format!(
                "alternate transition history: {:?} requires {:?}, found {:?}",
                request.transition, required, current
            )));
        }
        let updated = transaction.execute(
            "UPDATE claims SET state=?2 WHERE claim_id=?1 AND state=?3",
            params![
                request.claim_id.as_str(),
                resulting.as_str(),
                required.as_str()
            ],
        )?;
        if updated != 1 {
            return Err(ClaimFenceError::Refused(
                "transition did not update exactly one expected claim".into(),
            ));
        }
        let sequence: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM claim_events WHERE claim_id=?1",
            [request.claim_id.as_str()],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO claim_events(transition_id,claim_id,sequence,transition_nonce,transition_kind,evidence_digest,resulting_state) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![transition_id.as_str(), request.claim_id.as_str(), sequence, request.transition_nonce,
                request.transition.as_str(), request.evidence_digest.as_str(), resulting.as_str()],
        )?;
        transaction.commit()?;
        Ok(MutationReceiptV1 {
            schema: RECEIPT_SCHEMA,
            disposition: Disposition::Advanced,
            claim_id: request.claim_id.clone(),
            transition_id: Some(transition_id),
            resulting_state: resulting,
        })
    }
}

impl TransitionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fence => "fence",
            Self::Release => "release",
            Self::Complete => "complete",
            Self::MarkOutcomeUnknown => "mark_outcome_unknown",
            Self::Reconcile => "reconcile",
        }
    }
}

fn validate_claim(request: &ClaimRequestV1) -> Result<(), ClaimFenceError> {
    if request.schema != CLAIM_SCHEMA
        || request.occurrence_id.is_empty()
        || request.coordination_domain_id.is_empty()
        || request.claim_nonce.is_empty()
    {
        return Err(ClaimFenceError::Refused(
            "invalid claim schema or empty identity".into(),
        ));
    }
    Ok(())
}

fn validate_transition(request: &TransitionRequestV1) -> Result<(), ClaimFenceError> {
    if request.schema != TRANSITION_SCHEMA
        || request.occurrence_id.is_empty()
        || request.coordination_domain_id.is_empty()
        || request.transition_nonce.is_empty()
    {
        return Err(ClaimFenceError::Refused(
            "invalid transition schema or empty identity".into(),
        ));
    }
    Ok(())
}

fn framed_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Sha256Digest, ClaimFenceError> {
    let canonical = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&canonical);
    Ok(sha256_bytes(&preimage))
}

fn open_secure(path: &Path) -> Result<Connection, ClaimFenceError> {
    if !path.is_absolute() {
        return Err(ClaimFenceError::Refused(
            "state path must be absolute".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ClaimFenceError::Refused("state path has no parent".into()))?;
    if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(ClaimFenceError::Refused(
            "state filename is not exact".into(),
        ));
    }
    let parent_before = fs::symlink_metadata(parent)?;
    if parent_before.file_type().is_symlink()
        || !parent_before.is_dir()
        || parent_before.uid() != Uid::effective().as_raw()
        || parent_before.permissions().mode() & 0o077 != 0
        || fs::canonicalize(parent)? != parent
    {
        return Err(ClaimFenceError::Refused(
            "state parent is not an exact private owned directory".into(),
        ));
    }
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(ClaimFenceError::Refused(
            "state file cannot be a symbolic link".into(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let file_before = file.metadata()?;
    if !file_before.is_file()
        || file_before.uid() != Uid::effective().as_raw()
        || file_before.permissions().mode() & 0o077 != 0
    {
        return Err(ClaimFenceError::Refused(
            "state file is not an exact private owned file".into(),
        ));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let parent_after = fs::symlink_metadata(parent)?;
    let file_after = fs::symlink_metadata(path)?;
    if parent_after.dev() != parent_before.dev()
        || parent_after.ino() != parent_before.ino()
        || file_after.dev() != file_before.dev()
        || file_after.ino() != file_before.ino()
    {
        return Err(ClaimFenceError::Refused(
            "state pathname changed while SQLite opened".into(),
        ));
    }
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
         CREATE TABLE IF NOT EXISTS claims(
           claim_id TEXT PRIMARY KEY,
           occurrence_id TEXT NOT NULL UNIQUE,
           coordination_domain_id TEXT NOT NULL,
           mechanics_digest TEXT NOT NULL,
           authorization_receipt_digest TEXT NOT NULL,
           runtime_identity_digest TEXT NOT NULL,
           state TEXT NOT NULL CHECK(state IN ('claimed','fenced','released','outcome_unknown','terminal')));
         CREATE UNIQUE INDEX IF NOT EXISTS one_active_claim_per_domain
           ON claims(coordination_domain_id) WHERE state!='terminal';
         CREATE TABLE IF NOT EXISTS claim_events(
           transition_id TEXT PRIMARY KEY,
           claim_id TEXT NOT NULL REFERENCES claims(claim_id),
           sequence INTEGER NOT NULL,
           transition_nonce TEXT NOT NULL UNIQUE,
           transition_kind TEXT NOT NULL,
           evidence_digest TEXT NOT NULL,
           resulting_state TEXT NOT NULL,
           UNIQUE(claim_id,sequence));",
    )?;
    Ok(connection)
}

#[cfg(test)]
mod tests;
