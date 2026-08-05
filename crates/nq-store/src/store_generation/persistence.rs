//! Append-only C2 persistence and schema-migration hooks.
//!
//! Authenticated B/G carriers remain canonical.  SQLite tables created by
//! this module's migration hook are projections only and never create a root,
//! currentness, signer standing, or writer authority.

use std::collections::{BTreeMap, BTreeSet};

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Closed provenance mode for one persisted current-binding projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedBindingModeV1 {
    Initial,
    NormalSuccessor,
    RecoverySuccessor,
}

/// Immutable root projection retained exactly once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableRootProjectionV1 {
    root_binding_identity: Sha256Digest,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    lifecycle_root_identity: Sha256Digest,
    scope_identity: Sha256Digest,
    canonical_bytes_sha256: Sha256Digest,
}

/// Exact append/receipt/resolution association for one current binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedBindingProjectionV1 {
    root_binding_identity: Sha256Digest,
    binding_identity: Sha256Digest,
    predecessor_binding_identity: Option<Sha256Digest>,
    transition_identity: Option<Sha256Digest>,
    authorization_identity: Option<Sha256Digest>,
    recovery_condition_identity: Option<Sha256Digest>,
    recovery_authority_identity: Option<Sha256Digest>,
    recovery_grant_identity: Option<Sha256Digest>,
    receipt_identity: Sha256Digest,
    append_identity: Sha256Digest,
    persisted_resolution_identity: Sha256Digest,
    standing_identity: Sha256Digest,
    mode: PersistedBindingModeV1,
    effective_cut: u64,
    association_identity: Sha256Digest,
}

/// Append-only in-process representation used before a Store-owned durable
/// append.  It exposes no replacement or deletion operation.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct C2PersistencePlanV1 {
    root: Option<ImmutableRootProjectionV1>,
    bindings: Vec<PersistedBindingProjectionV1>,
    binding_index: BTreeMap<Sha256Digest, usize>,
    transition_ids: BTreeSet<Sha256Digest>,
    receipt_ids: BTreeSet<Sha256Digest>,
    append_ids: BTreeSet<Sha256Digest>,
    resolution_ids: BTreeSet<Sha256Digest>,
    recovery_grant_ids: BTreeSet<Sha256Digest>,
    receipt_append_pairs: BTreeSet<(Sha256Digest, Sha256Digest)>,
}

/// Typed persistence refusal; every variant is no-write until a transaction
/// has passed all checks.
#[derive(Debug, Error)]
pub enum PersistenceRefusalV1 {
    #[error("a required persistence coordinate is empty")]
    EmptyCoordinate,
    #[error("a persistence cut is outside the exact I-JSON range")]
    UnsafeCut,
    #[error("the immutable root has already been installed")]
    ImmutableRootRewrite,
    #[error("a binding belongs to another immutable root")]
    RootMismatch,
    #[error("initial/normal/recovery fields disagree with the closed mode")]
    ModeAssociationMismatch,
    #[error("the binding does not consume the exact current terminal")]
    ImmediatePredecessorMismatch,
    #[error("a binding, transition, or receipt/append pair is duplicated")]
    DuplicateAssociation,
    #[error("the append cut does not strictly follow the current terminal")]
    CutOrder,
    #[error("the persisted association identity is malformed")]
    AssociationIdentityMismatch,
    #[error("canonical identity derivation failed")]
    Canonicalization,
}

#[derive(Serialize)]
struct RootProjectionPreimage<'a> {
    schema: &'static str,
    occurrence_id: &'a str,
    physical_store_generation_identity: &'a Sha256Digest,
    lifecycle_root_identity: &'a Sha256Digest,
    scope_identity: &'a Sha256Digest,
    canonical_bytes_sha256: &'a Sha256Digest,
}

#[derive(Serialize)]
struct BindingAssociationPreimage<'a> {
    schema: &'static str,
    root_binding_identity: &'a Sha256Digest,
    binding_identity: &'a Sha256Digest,
    predecessor_binding_identity: &'a Option<Sha256Digest>,
    transition_identity: &'a Option<Sha256Digest>,
    authorization_identity: &'a Option<Sha256Digest>,
    recovery_condition_identity: &'a Option<Sha256Digest>,
    recovery_authority_identity: &'a Option<Sha256Digest>,
    recovery_grant_identity: &'a Option<Sha256Digest>,
    receipt_identity: &'a Sha256Digest,
    append_identity: &'a Sha256Digest,
    persisted_resolution_identity: &'a Sha256Digest,
    standing_identity: &'a Sha256Digest,
    mode: PersistedBindingModeV1,
    effective_cut: u64,
}

impl ImmutableRootProjectionV1 {
    /// Build an immutable root projection and derive its identity from every
    /// associated coordinate rather than trusting an asserted digest.
    pub(crate) fn new(
        occurrence_id: String,
        physical_store_generation_identity: Sha256Digest,
        lifecycle_root_identity: Sha256Digest,
        scope_identity: Sha256Digest,
        canonical_bytes_sha256: Sha256Digest,
    ) -> Result<Self, PersistenceRefusalV1> {
        if occurrence_id.is_empty() {
            return Err(PersistenceRefusalV1::EmptyCoordinate);
        }
        let root_binding_identity = semantic_digest(&RootProjectionPreimage {
            schema: "nq.c2.immutable_root_projection.v1",
            occurrence_id: &occurrence_id,
            physical_store_generation_identity: &physical_store_generation_identity,
            lifecycle_root_identity: &lifecycle_root_identity,
            scope_identity: &scope_identity,
            canonical_bytes_sha256: &canonical_bytes_sha256,
        })
        .map_err(|_| PersistenceRefusalV1::Canonicalization)?;
        Ok(Self {
            root_binding_identity,
            occurrence_id,
            physical_store_generation_identity,
            lifecycle_root_identity,
            scope_identity,
            canonical_bytes_sha256,
        })
    }

    /// Derived root-binding identity.
    #[must_use]
    pub fn root_binding_identity(&self) -> &Sha256Digest {
        &self.root_binding_identity
    }
}

/// Inputs to one exact append association.  All fields are explicit; no
/// `valid` Boolean or generic evidence bag exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedBindingProjectionInputV1 {
    pub root_binding_identity: Sha256Digest,
    pub binding_identity: Sha256Digest,
    pub predecessor_binding_identity: Option<Sha256Digest>,
    pub transition_identity: Option<Sha256Digest>,
    pub authorization_identity: Option<Sha256Digest>,
    pub recovery_condition_identity: Option<Sha256Digest>,
    pub recovery_authority_identity: Option<Sha256Digest>,
    pub recovery_grant_identity: Option<Sha256Digest>,
    pub receipt_identity: Sha256Digest,
    pub append_identity: Sha256Digest,
    pub persisted_resolution_identity: Sha256Digest,
    pub standing_identity: Sha256Digest,
    pub mode: PersistedBindingModeV1,
    pub effective_cut: u64,
}

impl PersistedBindingProjectionV1 {
    /// Construct and bind one receipt/append/resolution association.
    pub(crate) fn new(
        input: PersistedBindingProjectionInputV1,
    ) -> Result<Self, PersistenceRefusalV1> {
        if input.effective_cut == 0 || input.effective_cut > MAX_IJSON_INTEGER {
            return Err(PersistenceRefusalV1::UnsafeCut);
        }
        let initial = input.predecessor_binding_identity.is_none()
            && input.transition_identity.is_none()
            && input.authorization_identity.is_none()
            && input.recovery_condition_identity.is_none()
            && input.recovery_authority_identity.is_none()
            && input.recovery_grant_identity.is_none();
        let normal = input.predecessor_binding_identity.is_some()
            && input.transition_identity.is_some()
            && input.authorization_identity.is_some()
            && input.recovery_condition_identity.is_none()
            && input.recovery_authority_identity.is_none()
            && input.recovery_grant_identity.is_none();
        let recovery = input.predecessor_binding_identity.is_some()
            && input.transition_identity.is_some()
            && input.authorization_identity.is_some()
            && input.recovery_condition_identity.is_some()
            && input.recovery_authority_identity.is_some()
            && input.recovery_grant_identity.is_some();
        let mode_matches = match input.mode {
            PersistedBindingModeV1::Initial => initial,
            PersistedBindingModeV1::NormalSuccessor => normal,
            PersistedBindingModeV1::RecoverySuccessor => recovery,
        };
        if !mode_matches {
            return Err(PersistenceRefusalV1::ModeAssociationMismatch);
        }
        let association_identity = semantic_digest(&BindingAssociationPreimage {
            schema: "nq.c2.persisted_binding_association.v1",
            root_binding_identity: &input.root_binding_identity,
            binding_identity: &input.binding_identity,
            predecessor_binding_identity: &input.predecessor_binding_identity,
            transition_identity: &input.transition_identity,
            authorization_identity: &input.authorization_identity,
            recovery_condition_identity: &input.recovery_condition_identity,
            recovery_authority_identity: &input.recovery_authority_identity,
            recovery_grant_identity: &input.recovery_grant_identity,
            receipt_identity: &input.receipt_identity,
            append_identity: &input.append_identity,
            persisted_resolution_identity: &input.persisted_resolution_identity,
            standing_identity: &input.standing_identity,
            mode: input.mode,
            effective_cut: input.effective_cut,
        })
        .map_err(|_| PersistenceRefusalV1::Canonicalization)?;
        Ok(Self {
            root_binding_identity: input.root_binding_identity,
            binding_identity: input.binding_identity,
            predecessor_binding_identity: input.predecessor_binding_identity,
            transition_identity: input.transition_identity,
            authorization_identity: input.authorization_identity,
            recovery_condition_identity: input.recovery_condition_identity,
            recovery_authority_identity: input.recovery_authority_identity,
            recovery_grant_identity: input.recovery_grant_identity,
            receipt_identity: input.receipt_identity,
            append_identity: input.append_identity,
            persisted_resolution_identity: input.persisted_resolution_identity,
            standing_identity: input.standing_identity,
            mode: input.mode,
            effective_cut: input.effective_cut,
            association_identity,
        })
    }

    fn verify_identity(&self) -> Result<(), PersistenceRefusalV1> {
        let expected = Self::new(PersistedBindingProjectionInputV1 {
            root_binding_identity: self.root_binding_identity.clone(),
            binding_identity: self.binding_identity.clone(),
            predecessor_binding_identity: self.predecessor_binding_identity.clone(),
            transition_identity: self.transition_identity.clone(),
            authorization_identity: self.authorization_identity.clone(),
            recovery_condition_identity: self.recovery_condition_identity.clone(),
            recovery_authority_identity: self.recovery_authority_identity.clone(),
            recovery_grant_identity: self.recovery_grant_identity.clone(),
            receipt_identity: self.receipt_identity.clone(),
            append_identity: self.append_identity.clone(),
            persisted_resolution_identity: self.persisted_resolution_identity.clone(),
            standing_identity: self.standing_identity.clone(),
            mode: self.mode,
            effective_cut: self.effective_cut,
        })?;
        if expected.association_identity == self.association_identity {
            Ok(())
        } else {
            Err(PersistenceRefusalV1::AssociationIdentityMismatch)
        }
    }
}

impl C2PersistencePlanV1 {
    /// Install the immutable root once.  An identical retry is not silently
    /// accepted because this hook models an append, not an idempotency cache.
    pub(crate) fn install_immutable_root(
        &mut self,
        root: ImmutableRootProjectionV1,
    ) -> Result<(), PersistenceRefusalV1> {
        if self.root.is_some() {
            return Err(PersistenceRefusalV1::ImmutableRootRewrite);
        }
        self.root = Some(root);
        Ok(())
    }

    /// Append one exact binding association against the prior terminal.
    pub(crate) fn append_binding(
        &mut self,
        binding: PersistedBindingProjectionV1,
    ) -> Result<(), PersistenceRefusalV1> {
        binding.verify_identity()?;
        let root = self
            .root
            .as_ref()
            .ok_or(PersistenceRefusalV1::RootMismatch)?;
        if binding.root_binding_identity != root.root_binding_identity {
            return Err(PersistenceRefusalV1::RootMismatch);
        }
        if self.binding_index.contains_key(&binding.binding_identity)
            || binding
                .transition_identity
                .as_ref()
                .is_some_and(|id| self.transition_ids.contains(id))
            || self.receipt_ids.contains(&binding.receipt_identity)
            || self.append_ids.contains(&binding.append_identity)
            || self
                .resolution_ids
                .contains(&binding.persisted_resolution_identity)
            || binding
                .recovery_grant_identity
                .as_ref()
                .is_some_and(|id| self.recovery_grant_ids.contains(id))
            || self.receipt_append_pairs.contains(&(
                binding.receipt_identity.clone(),
                binding.append_identity.clone(),
            ))
        {
            return Err(PersistenceRefusalV1::DuplicateAssociation);
        }
        match self.bindings.last() {
            None if binding.mode == PersistedBindingModeV1::Initial => {}
            Some(previous)
                if binding.mode != PersistedBindingModeV1::Initial
                    && binding.predecessor_binding_identity.as_ref()
                        == Some(&previous.binding_identity) =>
            {
                if binding.effective_cut <= previous.effective_cut {
                    return Err(PersistenceRefusalV1::CutOrder);
                }
            }
            _ => return Err(PersistenceRefusalV1::ImmediatePredecessorMismatch),
        }
        let index = self.bindings.len();
        self.binding_index
            .insert(binding.binding_identity.clone(), index);
        if let Some(transition) = &binding.transition_identity {
            self.transition_ids.insert(transition.clone());
        }
        self.receipt_ids.insert(binding.receipt_identity.clone());
        self.append_ids.insert(binding.append_identity.clone());
        self.resolution_ids
            .insert(binding.persisted_resolution_identity.clone());
        if let Some(grant) = &binding.recovery_grant_identity {
            self.recovery_grant_ids.insert(grant.clone());
        }
        self.receipt_append_pairs.insert((
            binding.receipt_identity.clone(),
            binding.append_identity.clone(),
        ));
        self.bindings.push(binding);
        Ok(())
    }

    /// Exact terminal binding; no sorted or maximum record selection occurs.
    #[must_use]
    pub fn terminal_binding(&self) -> Option<&PersistedBindingProjectionV1> {
        self.bindings.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn root() -> ImmutableRootProjectionV1 {
        ImmutableRootProjectionV1::new(
            "occurrence-a".into(),
            digest('a'),
            digest('b'),
            digest('c'),
            digest('d'),
        )
        .unwrap()
    }

    fn binding(
        root: &Sha256Digest,
        id: char,
        predecessor: Option<char>,
        transition: Option<char>,
        mode: PersistedBindingModeV1,
        cut: u64,
    ) -> PersistedBindingProjectionV1 {
        let recovery = mode == PersistedBindingModeV1::RecoverySuccessor;
        PersistedBindingProjectionV1::new(PersistedBindingProjectionInputV1 {
            root_binding_identity: root.clone(),
            binding_identity: digest(id),
            predecessor_binding_identity: predecessor.map(digest),
            transition_identity: transition.map(digest),
            authorization_identity: transition.map(|_| digest('8')),
            recovery_condition_identity: recovery.then(|| digest('9')),
            recovery_authority_identity: recovery.then(|| digest('a')),
            recovery_grant_identity: recovery.then(|| digest('b')),
            receipt_identity: digest(if id == 'e' { 'c' } else { 'd' }),
            append_identity: digest(if id == 'e' { 'f' } else { '0' }),
            persisted_resolution_identity: digest(if id == 'e' { '1' } else { '2' }),
            standing_identity: digest(if id == 'e' { '3' } else { '4' }),
            mode,
            effective_cut: cut,
        })
        .unwrap()
    }

    #[test]
    fn append_requires_the_exact_previous_terminal() {
        let root = root();
        let root_id = root.root_binding_identity().clone();
        let mut plan = C2PersistencePlanV1::default();
        plan.install_immutable_root(root).unwrap();
        plan.append_binding(binding(
            &root_id,
            'e',
            None,
            None,
            PersistedBindingModeV1::Initial,
            1,
        ))
        .unwrap();
        let skipped = binding(
            &root_id,
            '6',
            Some('7'),
            Some('9'),
            PersistedBindingModeV1::NormalSuccessor,
            3,
        );
        assert!(matches!(
            plan.append_binding(skipped),
            Err(PersistenceRefusalV1::ImmediatePredecessorMismatch)
        ));
    }

    #[test]
    fn recovery_association_requires_all_recovery_coordinates() {
        let input = PersistedBindingProjectionInputV1 {
            root_binding_identity: digest('a'),
            binding_identity: digest('b'),
            predecessor_binding_identity: Some(digest('c')),
            transition_identity: Some(digest('d')),
            authorization_identity: Some(digest('e')),
            recovery_condition_identity: None,
            recovery_authority_identity: Some(digest('f')),
            recovery_grant_identity: Some(digest('0')),
            receipt_identity: digest('1'),
            append_identity: digest('2'),
            persisted_resolution_identity: digest('3'),
            standing_identity: digest('4'),
            mode: PersistedBindingModeV1::RecoverySuccessor,
            effective_cut: 8,
        };
        assert!(matches!(
            PersistedBindingProjectionV1::new(input),
            Err(PersistenceRefusalV1::ModeAssociationMismatch)
        ));
    }

    #[test]
    fn recovery_grant_cannot_be_replayed_for_a_later_edge() {
        let root = root();
        let root_id = root.root_binding_identity().clone();
        let mut plan = C2PersistencePlanV1::default();
        plan.install_immutable_root(root).unwrap();
        plan.append_binding(binding(
            &root_id,
            'e',
            None,
            None,
            PersistedBindingModeV1::Initial,
            1,
        ))
        .unwrap();
        let recovery_one = PersistedBindingProjectionV1::new(PersistedBindingProjectionInputV1 {
            root_binding_identity: root_id.clone(),
            binding_identity: digest('5'),
            predecessor_binding_identity: Some(digest('e')),
            transition_identity: Some(digest('6')),
            authorization_identity: Some(digest('7')),
            recovery_condition_identity: Some(digest('8')),
            recovery_authority_identity: Some(digest('9')),
            recovery_grant_identity: Some(digest('a')),
            receipt_identity: digest('b'),
            append_identity: digest('c'),
            persisted_resolution_identity: digest('d'),
            standing_identity: digest('0'),
            mode: PersistedBindingModeV1::RecoverySuccessor,
            effective_cut: 4,
        })
        .unwrap();
        plan.append_binding(recovery_one).unwrap();
        let recovery_two = PersistedBindingProjectionV1::new(PersistedBindingProjectionInputV1 {
            root_binding_identity: root_id,
            binding_identity: digest('1'),
            predecessor_binding_identity: Some(digest('5')),
            transition_identity: Some(digest('2')),
            authorization_identity: Some(digest('3')),
            recovery_condition_identity: Some(digest('4')),
            recovery_authority_identity: Some(digest('f')),
            recovery_grant_identity: Some(digest('a')),
            receipt_identity: digest('6'),
            append_identity: digest('7'),
            persisted_resolution_identity: digest('8'),
            standing_identity: digest('9'),
            mode: PersistedBindingModeV1::RecoverySuccessor,
            effective_cut: 8,
        })
        .unwrap();
        assert!(matches!(
            plan.append_binding(recovery_two),
            Err(PersistenceRefusalV1::DuplicateAssociation)
        ));
    }
}
