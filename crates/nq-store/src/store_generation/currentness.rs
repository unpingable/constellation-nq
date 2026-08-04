//! Complete-set currentness resolution for C2 Store-generation records.
//!
//! Currentness is derived from one complete, predecessor-linked candidate
//! set.  It is never selected by arrival order, lexical order, a maximum cut,
//! or a maximum generation.  The resulting witness is inert: it does not
//! confer signer standing, custody, backend closure, or writer authority.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

/// One authenticated candidate in an exact predecessor chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentnessCandidateV1 {
    root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    binding_identity: Sha256Digest,
    predecessor_binding_identity: Option<Sha256Digest>,
    persisted_resolution_identity: Sha256Digest,
    effective_cut: u64,
    candidate_identity: Sha256Digest,
}

/// Resolution of one complete candidate set at an exact observation cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteCurrentCandidateSetV1 {
    root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    observation_cut: u64,
    initial_binding_identity: Sha256Digest,
    terminal_binding_identity: Sha256Digest,
    candidates: Vec<CurrentnessCandidateV1>,
}

/// Typed, no-write currentness refusal.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CurrentnessRefusalV1 {
    #[error("a currentness coordinate is empty or malformed")]
    MalformedCandidate,
    #[error("a currentness cut exceeds the exact I-JSON range")]
    UnsafeCut,
    #[error("a candidate belongs to another root or scope")]
    ForeignCandidate,
    #[error("a candidate identity is duplicated")]
    DuplicateCandidate,
    #[error("the candidate set has zero or multiple initial bindings")]
    InitialCardinality,
    #[error("a predecessor named by a candidate is absent")]
    PredecessorGap,
    #[error("one predecessor has competing successors")]
    Fork,
    #[error("the candidate set contains a cycle")]
    Cycle,
    #[error("the candidate set is not one complete rooted chain")]
    IncompleteCandidateSet,
    #[error("the chain has no unique structurally derived terminal")]
    TerminalCardinality,
    #[error("a successor cut does not strictly follow its predecessor cut")]
    CutOrder,
    #[error("the terminal differs from the exact expected terminal")]
    TerminalMismatch,
    #[error("candidate identity canonicalization failed")]
    Canonicalization,
}

#[derive(Serialize)]
struct CandidatePreimage<'a> {
    schema: &'static str,
    root_identity: &'a Sha256Digest,
    scope_identity: &'a Sha256Digest,
    binding_identity: &'a Sha256Digest,
    predecessor_binding_identity: &'a Option<Sha256Digest>,
    persisted_resolution_identity: &'a Sha256Digest,
    effective_cut: u64,
}

impl CurrentnessCandidateV1 {
    /// Construct an authenticated candidate projection.
    pub(crate) fn new(
        root_identity: Sha256Digest,
        scope_identity: Sha256Digest,
        binding_identity: Sha256Digest,
        predecessor_binding_identity: Option<Sha256Digest>,
        persisted_resolution_identity: Sha256Digest,
        effective_cut: u64,
    ) -> Result<Self, CurrentnessRefusalV1> {
        if effective_cut == 0 || effective_cut > MAX_IJSON_INTEGER {
            return Err(CurrentnessRefusalV1::UnsafeCut);
        }
        let candidate_identity = semantic_digest(&CandidatePreimage {
            schema: "nq.c2.currentness_candidate.v1",
            root_identity: &root_identity,
            scope_identity: &scope_identity,
            binding_identity: &binding_identity,
            predecessor_binding_identity: &predecessor_binding_identity,
            persisted_resolution_identity: &persisted_resolution_identity,
            effective_cut,
        })
        .map_err(|_| CurrentnessRefusalV1::Canonicalization)?;
        Ok(Self {
            root_identity,
            scope_identity,
            binding_identity,
            predecessor_binding_identity,
            persisted_resolution_identity,
            effective_cut,
            candidate_identity,
        })
    }

    fn verify_identity(&self) -> Result<(), CurrentnessRefusalV1> {
        let expected = Self::new(
            self.root_identity.clone(),
            self.scope_identity.clone(),
            self.binding_identity.clone(),
            self.predecessor_binding_identity.clone(),
            self.persisted_resolution_identity.clone(),
            self.effective_cut,
        )?;
        if expected.candidate_identity == self.candidate_identity {
            Ok(())
        } else {
            Err(CurrentnessRefusalV1::MalformedCandidate)
        }
    }

    /// The exact binding identified by this candidate.
    #[must_use]
    pub fn binding_identity(&self) -> &Sha256Digest {
        &self.binding_identity
    }

    /// Exact persisted resolution associated with the binding.
    #[must_use]
    pub fn persisted_resolution_identity(&self) -> &Sha256Digest {
        &self.persisted_resolution_identity
    }
}

impl CompleteCurrentCandidateSetV1 {
    /// Structurally derived terminal binding; this is not a maximum selector.
    #[must_use]
    pub fn terminal_binding_identity(&self) -> &Sha256Digest {
        &self.terminal_binding_identity
    }

    /// Initial binding pinned by the complete chain.
    #[must_use]
    pub fn initial_binding_identity(&self) -> &Sha256Digest {
        &self.initial_binding_identity
    }

    /// Exact observation cut at which this set was resolved.
    #[must_use]
    pub const fn observation_cut(&self) -> u64 {
        self.observation_cut
    }

    /// Complete retained candidates, in caller-supplied evidence order.
    #[must_use]
    pub fn candidates(&self) -> &[CurrentnessCandidateV1] {
        &self.candidates
    }

    /// Root to which every candidate was proven to belong.
    #[must_use]
    pub fn root_identity(&self) -> &Sha256Digest {
        &self.root_identity
    }

    /// Scope to which every candidate was proven to belong.
    #[must_use]
    pub fn scope_identity(&self) -> &Sha256Digest {
        &self.scope_identity
    }
}

/// Resolve an exact complete set without first/max/sort/tie-break selection.
pub(crate) fn resolve_complete_current_candidate_set_v1(
    root_identity: &Sha256Digest,
    scope_identity: &Sha256Digest,
    observation_cut: u64,
    expected_terminal_binding_identity: &Sha256Digest,
    candidates: Vec<CurrentnessCandidateV1>,
) -> Result<CompleteCurrentCandidateSetV1, CurrentnessRefusalV1> {
    if observation_cut == 0 || observation_cut > MAX_IJSON_INTEGER {
        return Err(CurrentnessRefusalV1::UnsafeCut);
    }
    if candidates.is_empty() {
        return Err(CurrentnessRefusalV1::InitialCardinality);
    }

    let mut by_binding = BTreeMap::new();
    for candidate in &candidates {
        candidate.verify_identity()?;
        if &candidate.root_identity != root_identity || &candidate.scope_identity != scope_identity
        {
            return Err(CurrentnessRefusalV1::ForeignCandidate);
        }
        if candidate.effective_cut > observation_cut {
            return Err(CurrentnessRefusalV1::CutOrder);
        }
        if by_binding
            .insert(candidate.binding_identity.clone(), candidate)
            .is_some()
        {
            return Err(CurrentnessRefusalV1::DuplicateCandidate);
        }
    }

    let initial: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.predecessor_binding_identity.is_none())
        .collect();
    if initial.len() != 1 {
        return Err(CurrentnessRefusalV1::InitialCardinality);
    }

    let mut successor_by_predecessor = BTreeMap::new();
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.predecessor_binding_identity.is_some())
    {
        let predecessor = candidate
            .predecessor_binding_identity
            .as_ref()
            .ok_or(CurrentnessRefusalV1::PredecessorGap)?;
        let predecessor_candidate = by_binding
            .get(predecessor)
            .ok_or(CurrentnessRefusalV1::PredecessorGap)?;
        if predecessor_candidate.effective_cut >= candidate.effective_cut {
            return Err(CurrentnessRefusalV1::CutOrder);
        }
        if successor_by_predecessor
            .insert(predecessor.clone(), &candidate.binding_identity)
            .is_some()
        {
            return Err(CurrentnessRefusalV1::Fork);
        }
    }

    let initial_id = initial[0].binding_identity.clone();
    let mut visited = BTreeSet::new();
    let mut cursor = initial_id.clone();
    loop {
        if !visited.insert(cursor.clone()) {
            return Err(CurrentnessRefusalV1::Cycle);
        }
        match successor_by_predecessor.get(&cursor) {
            Some(successor) => cursor = (*successor).clone(),
            None => break,
        }
    }
    if visited.len() != candidates.len() {
        return Err(CurrentnessRefusalV1::IncompleteCandidateSet);
    }

    let terminal_count = candidates
        .iter()
        .filter(|candidate| !successor_by_predecessor.contains_key(&candidate.binding_identity))
        .count();
    if terminal_count != 1 {
        return Err(CurrentnessRefusalV1::TerminalCardinality);
    }
    if &cursor != expected_terminal_binding_identity {
        return Err(CurrentnessRefusalV1::TerminalMismatch);
    }

    Ok(CompleteCurrentCandidateSetV1 {
        root_identity: root_identity.clone(),
        scope_identity: scope_identity.clone(),
        observation_cut,
        initial_binding_identity: initial_id,
        terminal_binding_identity: cursor,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn candidate(
        binding: char,
        predecessor: Option<char>,
        resolution: char,
        cut: u64,
    ) -> CurrentnessCandidateV1 {
        CurrentnessCandidateV1::new(
            digest('a'),
            digest('b'),
            digest(binding),
            predecessor.map(digest),
            digest(resolution),
            cut,
        )
        .unwrap()
    }

    #[test]
    fn terminal_is_derived_from_exact_adjacency_not_input_order() {
        let resolved = resolve_complete_current_candidate_set_v1(
            &digest('a'),
            &digest('b'),
            9,
            &digest('e'),
            vec![
                candidate('e', Some('d'), '8', 7),
                candidate('c', None, '6', 1),
                candidate('d', Some('c'), '7', 4),
            ],
        )
        .unwrap();
        assert_eq!(resolved.terminal_binding_identity(), &digest('e'));
        assert_eq!(resolved.initial_binding_identity(), &digest('c'));
    }

    #[test]
    fn competing_successors_refuse_instead_of_tie_breaking() {
        let refusal = resolve_complete_current_candidate_set_v1(
            &digest('a'),
            &digest('b'),
            9,
            &digest('d'),
            vec![
                candidate('c', None, '6', 1),
                candidate('d', Some('c'), '7', 4),
                candidate('e', Some('c'), '8', 8),
            ],
        )
        .unwrap_err();
        assert_eq!(refusal, CurrentnessRefusalV1::Fork);
    }

    #[test]
    fn detached_high_cut_candidate_refuses_instead_of_becoming_current() {
        let refusal = resolve_complete_current_candidate_set_v1(
            &digest('a'),
            &digest('b'),
            99,
            &digest('f'),
            vec![
                candidate('c', None, '6', 1),
                candidate('d', Some('c'), '7', 4),
                candidate('f', None, '8', 98),
            ],
        )
        .unwrap_err();
        assert_eq!(refusal, CurrentnessRefusalV1::InitialCardinality);
    }
}
