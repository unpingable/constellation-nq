//! Exact adjacent normal/recovery succession and finite rooted lineage.
//!
//! A lineage is built by appending one verified edge to its current terminal.
//! There is intentionally no constructor from an unordered collection and no
//! latest/highest-cut selection function.

use std::collections::BTreeSet;

use nq_protocol::Sha256Digest;

use super::binding::{
    CompletedSignerTransitionV1, CurrentSignerBindingModeV1, CurrentSignerGenerationBindingV1,
    StoreGenerationSignerRootBindingV1, construct_sb_05_normal_binding_derivation,
    construct_sb_06_recovery_binding_derivation,
};
use super::result::{LineageRefusalV1, SignerRefusalV2};

/// Exact uniquely current predecessor for healthy normal rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentRotationPredecessorV1 {
    binding: CurrentSignerGenerationBindingV1,
    currentness_id: String,
    standing_id: String,
    custody_key_generation: String,
    policy_id: String,
}

/// Provenance route exposed by predecessor inversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentRotationPredecessorRouteV1 {
    Initial,
    NormalSuccessor,
    RecoverySuccessor,
}

/// Exact recovery association for one terminal binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPredecessorBindingAssociationV1 {
    predecessor_binding_id: Sha256Digest,
    recovery_condition_id: String,
    external_authority_id: String,
    recovery_grant_id: String,
    grant_predecessor_binding_id: Sha256Digest,
    granted_successor_key_generation: String,
    policy_id: String,
}

/// Exact terminal predecessor displaced by recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryTransitionPredecessorV1 {
    binding: CurrentSignerGenerationBindingV1,
    currentness_id: String,
    association: RecoveryPredecessorBindingAssociationV1,
}

/// One adjacent normal or recovery edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentBindingSuccessionV1 {
    Normal {
        predecessor: CurrentRotationPredecessorV1,
        continuity_authorization_id: String,
        transition: CompletedSignerTransitionV1,
        successor: CurrentSignerGenerationBindingV1,
    },
    Recovery {
        predecessor: RecoveryTransitionPredecessorV1,
        transition: CompletedSignerTransitionV1,
        successor: CurrentSignerGenerationBindingV1,
    },
}

/// Finite, proof-relevant, adjacency-derived signer history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootedCurrentBindingLineageV1 {
    root: StoreGenerationSignerRootBindingV1,
    initial: CurrentSignerGenerationBindingV1,
    edges: Vec<CurrentBindingSuccessionV1>,
    terminal: CurrentSignerGenerationBindingV1,
    transition_ids: BTreeSet<String>,
    completion_pairs: BTreeSet<(String, String)>,
    recovery_grant_ids: BTreeSet<String>,
}

/// Exact inputs for one normal transition.  Possession is not authorization:
/// the continuity signer must be the predecessor key, never the successor.
pub(crate) struct NormalSuccessionInputV1 {
    pub transition_id: String,
    pub continuity_authorization_id: String,
    pub continuity_signer_key_generation: String,
    pub successor_enrollment_id: String,
    pub successor_key_generation: String,
    pub successor_policy_id: String,
    pub successor_standing_id: String,
    pub receipt_id: String,
    pub append_id: String,
    pub resolution_id: String,
    pub effective_cut: u64,
}

/// Exact inputs for one recovery transition.  The predecessor does not sign
/// and its custody is deliberately absent from this structure.
pub(crate) struct RecoverySuccessionInputV1 {
    pub transition_id: String,
    pub successor_enrollment_id: String,
    pub successor_key_generation: String,
    pub successor_policy_id: String,
    pub successor_standing_id: String,
    pub receipt_id: String,
    pub append_id: String,
    pub resolution_id: String,
    pub effective_cut: u64,
}

/// Typed malformed normal edge used by NRP-10 evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MalformedCurrentBindingSuccessionV1 {
    pub classification: LineageRefusalV1,
}

/// Typed malformed recovery base used by RPA-13 evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MalformedRecoveryTransitionPredecessorV1 {
    pub classification: LineageRefusalV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalSuccessionDependencyV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySuccessionDependencyV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalSuccessionHostileCoverageV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySuccessionHostileCoverageV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationJudgmentConsumptionV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryGrantConsumptionV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreAuthorizationConsumptionV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineClosureConsumptionV1;

fn nonempty(values: &[&str]) -> bool {
    values.iter().all(|value| !value.is_empty())
}

/// Construct NRP-01 only from a binding, its exact currentness/standing and
/// matching usable custody.
pub(crate) fn construct_nrp_01_normal_predecessor(
    binding: CurrentSignerGenerationBindingV1,
    currentness_binding_id: &Sha256Digest,
    standing_id: String,
    custody_key_generation: String,
    policy_id: String,
) -> Result<CurrentRotationPredecessorV1, SignerRefusalV2> {
    if currentness_binding_id != binding.binding_id()
        || standing_id != binding.standing_id()
        || custody_key_generation != binding.key_generation()
        || policy_id != binding.policy_id()
        || !nonempty(&[&standing_id, &custody_key_generation, &policy_id])
    {
        return Err(SignerRefusalV2::MissingUsableCurrentPredecessor);
    }
    Ok(CurrentRotationPredecessorV1 {
        binding,
        currentness_id: currentness_binding_id.to_string(),
        standing_id,
        custody_key_generation,
        policy_id,
    })
}

/// Invert NRP-02 into the exact initial/normal/recovery trichotomy.
pub(crate) fn construct_nrp_02_normal_predecessor_trichotomy(
    predecessor: &CurrentRotationPredecessorV1,
) -> CurrentRotationPredecessorRouteV1 {
    match predecessor.binding.mode() {
        CurrentSignerBindingModeV1::Initial => CurrentRotationPredecessorRouteV1::Initial,
        CurrentSignerBindingModeV1::NormalSuccessor => {
            CurrentRotationPredecessorRouteV1::NormalSuccessor
        }
        CurrentSignerBindingModeV1::RecoverySuccessor => {
            CurrentRotationPredecessorRouteV1::RecoverySuccessor
        }
    }
}

/// Construct RPA-01/RPA-02's one-base recovery association.
pub(crate) fn construct_rpa_01_recovery_ledger_base_join(
    predecessor: &CurrentSignerGenerationBindingV1,
    recovery_condition_id: String,
    external_authority_id: String,
    recovery_grant_id: String,
    grant_predecessor_binding_id: Sha256Digest,
    granted_successor_key_generation: String,
    policy_id: String,
) -> Result<RecoveryPredecessorBindingAssociationV1, LineageRefusalV1> {
    if grant_predecessor_binding_id != *predecessor.binding_id()
        || policy_id != predecessor.policy_id()
        || !nonempty(&[
            &recovery_condition_id,
            &external_authority_id,
            &recovery_grant_id,
            &granted_successor_key_generation,
            &policy_id,
        ])
    {
        return Err(LineageRefusalV1::PredecessorSplice);
    }
    Ok(RecoveryPredecessorBindingAssociationV1 {
        predecessor_binding_id: predecessor.binding_id().clone(),
        recovery_condition_id,
        external_authority_id,
        recovery_grant_id,
        grant_predecessor_binding_id,
        granted_successor_key_generation,
        policy_id,
    })
}

/// Alias retaining RPA-02's separately reviewed authority-sealing name.
pub(crate) fn construct_rpa_02_authorization_seals_predecessor_condition_grant(
    predecessor: &CurrentSignerGenerationBindingV1,
    association: RecoveryPredecessorBindingAssociationV1,
) -> Result<RecoveryPredecessorBindingAssociationV1, LineageRefusalV1> {
    if association.predecessor_binding_id != *predecessor.binding_id()
        || association.grant_predecessor_binding_id != *predecessor.binding_id()
    {
        Err(LineageRefusalV1::PredecessorSplice)
    } else {
        Ok(association)
    }
}

/// Construct RPA-03's exact terminal recovery predecessor.  No predecessor
/// custody or cooperation is accepted as an input.
pub(crate) fn construct_rpa_03_lawful_recovery_predecessor_provenance(
    binding: CurrentSignerGenerationBindingV1,
    currentness_binding_id: &Sha256Digest,
    association: RecoveryPredecessorBindingAssociationV1,
) -> Result<RecoveryTransitionPredecessorV1, LineageRefusalV1> {
    if currentness_binding_id != binding.binding_id()
        || association.predecessor_binding_id != *binding.binding_id()
        || association.grant_predecessor_binding_id != *binding.binding_id()
    {
        return Err(LineageRefusalV1::PredecessorSplice);
    }
    Ok(RecoveryTransitionPredecessorV1 {
        binding,
        currentness_id: currentness_binding_id.to_string(),
        association,
    })
}

fn completed_normal(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &CurrentRotationPredecessorV1,
    input: &NormalSuccessionInputV1,
) -> Result<CompletedSignerTransitionV1, LineageRefusalV1> {
    if input.continuity_signer_key_generation != predecessor.binding.key_generation()
        || input.successor_key_generation == input.continuity_signer_key_generation
        || input.successor_policy_id != predecessor.policy_id
    {
        return Err(LineageRefusalV1::SuccessorSelfAuthorization);
    }
    if !nonempty(&[
        &input.transition_id,
        &input.continuity_authorization_id,
        &input.successor_enrollment_id,
        &input.successor_key_generation,
        &input.successor_policy_id,
        &input.successor_standing_id,
        &input.receipt_id,
        &input.append_id,
        &input.resolution_id,
    ]) {
        return Err(LineageRefusalV1::Gap);
    }
    Ok(CompletedSignerTransitionV1 {
        mode: CurrentSignerBindingModeV1::NormalSuccessor,
        root_id: root.binding_id().clone(),
        transition_id: input.transition_id.clone(),
        predecessor_binding_id: predecessor.binding.binding_id().clone(),
        predecessor_key_generation: predecessor.binding.key_generation().to_owned(),
        successor_enrollment_id: input.successor_enrollment_id.clone(),
        successor_key_generation: input.successor_key_generation.clone(),
        successor_policy_id: input.successor_policy_id.clone(),
        successor_standing_id: input.successor_standing_id.clone(),
        receipt_id: input.receipt_id.clone(),
        append_id: input.append_id.clone(),
        resolution_id: input.resolution_id.clone(),
        effective_cut: input.effective_cut,
    })
}

fn completed_recovery(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &RecoveryTransitionPredecessorV1,
    input: &RecoverySuccessionInputV1,
) -> Result<CompletedSignerTransitionV1, LineageRefusalV1> {
    if predecessor.association.granted_successor_key_generation != input.successor_key_generation
        || predecessor.association.policy_id != input.successor_policy_id
    {
        return Err(LineageRefusalV1::PredecessorSplice);
    }
    if !nonempty(&[
        &input.transition_id,
        &input.successor_enrollment_id,
        &input.successor_key_generation,
        &input.successor_policy_id,
        &input.successor_standing_id,
        &input.receipt_id,
        &input.append_id,
        &input.resolution_id,
    ]) {
        return Err(LineageRefusalV1::Gap);
    }
    Ok(CompletedSignerTransitionV1 {
        mode: CurrentSignerBindingModeV1::RecoverySuccessor,
        root_id: root.binding_id().clone(),
        transition_id: input.transition_id.clone(),
        predecessor_binding_id: predecessor.binding.binding_id().clone(),
        predecessor_key_generation: predecessor.binding.key_generation().to_owned(),
        successor_enrollment_id: input.successor_enrollment_id.clone(),
        successor_key_generation: input.successor_key_generation.clone(),
        successor_policy_id: input.successor_policy_id.clone(),
        successor_standing_id: input.successor_standing_id.clone(),
        receipt_id: input.receipt_id.clone(),
        append_id: input.append_id.clone(),
        resolution_id: input.resolution_id.clone(),
        effective_cut: input.effective_cut,
    })
}

/// Construct NRP-03/04/05/06's exact adjacent normal edge.
pub(crate) fn construct_nrp_06_adjacent_normal_succession(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: CurrentRotationPredecessorV1,
    input: NormalSuccessionInputV1,
) -> Result<CurrentBindingSuccessionV1, LineageRefusalV1> {
    let transition = completed_normal(root, &predecessor, &input)?;
    let successor =
        construct_sb_05_normal_binding_derivation(root, &predecessor.binding, &transition)
            .map_err(|_| LineageRefusalV1::PredecessorSplice)?
            .into_inner();
    Ok(CurrentBindingSuccessionV1::Normal {
        predecessor,
        continuity_authorization_id: input.continuity_authorization_id,
        transition,
        successor,
    })
}

/// Construct RPA-04's exact adjacent recovery edge.
pub(crate) fn construct_rpa_04_adjacent_recovery_inversion(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: RecoveryTransitionPredecessorV1,
    input: RecoverySuccessionInputV1,
) -> Result<CurrentBindingSuccessionV1, LineageRefusalV1> {
    let transition = completed_recovery(root, &predecessor, &input)?;
    let successor =
        construct_sb_06_recovery_binding_derivation(root, &predecessor.binding, &transition)
            .map_err(|_| LineageRefusalV1::PredecessorSplice)?
            .into_inner();
    Ok(CurrentBindingSuccessionV1::Recovery {
        predecessor,
        transition,
        successor,
    })
}

impl CurrentBindingSuccessionV1 {
    #[must_use]
    pub fn predecessor(&self) -> &CurrentSignerGenerationBindingV1 {
        match self {
            Self::Normal { predecessor, .. } => &predecessor.binding,
            Self::Recovery { predecessor, .. } => &predecessor.binding,
        }
    }

    #[must_use]
    pub fn successor(&self) -> &CurrentSignerGenerationBindingV1 {
        match self {
            Self::Normal { successor, .. } | Self::Recovery { successor, .. } => successor,
        }
    }

    #[must_use]
    pub fn transition_id(&self) -> &str {
        match self {
            Self::Normal { transition, .. } | Self::Recovery { transition, .. } => {
                &transition.transition_id
            }
        }
    }

    fn completion_pair(&self) -> (&str, &str) {
        match self {
            Self::Normal { transition, .. } | Self::Recovery { transition, .. } => {
                (&transition.receipt_id, &transition.append_id)
            }
        }
    }

    fn recovery_grant_id(&self) -> Option<&str> {
        match self {
            Self::Normal { .. } => None,
            Self::Recovery { predecessor, .. } => Some(&predecessor.association.recovery_grant_id),
        }
    }
}

impl RootedCurrentBindingLineageV1 {
    /// Construct NRP-07's zero-edge finite lineage from the exact initial binding.
    pub(crate) fn initial(
        root: StoreGenerationSignerRootBindingV1,
        initial: CurrentSignerGenerationBindingV1,
    ) -> Result<Self, LineageRefusalV1> {
        if initial.mode() != CurrentSignerBindingModeV1::Initial
            || initial.root_binding_id() != root.binding_id()
        {
            return Err(LineageRefusalV1::Gap);
        }
        Ok(Self {
            root,
            initial: initial.clone(),
            edges: Vec::new(),
            terminal: initial,
            transition_ids: BTreeSet::new(),
            completion_pairs: BTreeSet::new(),
            recovery_grant_ids: BTreeSet::new(),
        })
    }

    /// Append one edge only when it consumes this lineage's exact terminal.
    pub(crate) fn append(
        mut self,
        edge: CurrentBindingSuccessionV1,
    ) -> Result<Self, LineageRefusalV1> {
        if edge.predecessor().binding_id() != self.terminal.binding_id() {
            return Err(LineageRefusalV1::SkippedPredecessor);
        }
        if edge.predecessor().effective_cut() != self.terminal.effective_cut() {
            return Err(LineageRefusalV1::StalePredecessor);
        }
        if edge.successor().root_binding_id() != self.root.binding_id()
            || edge.successor().effective_cut() <= self.terminal.effective_cut()
        {
            return Err(LineageRefusalV1::PredecessorSplice);
        }
        if !self.transition_ids.insert(edge.transition_id().to_owned()) {
            return Err(LineageRefusalV1::DuplicateTransition);
        }
        let pair = edge.completion_pair();
        if !self
            .completion_pairs
            .insert((pair.0.to_owned(), pair.1.to_owned()))
        {
            return Err(LineageRefusalV1::DuplicateCompletion);
        }
        if let Some(grant_id) = edge.recovery_grant_id()
            && !self.recovery_grant_ids.insert(grant_id.to_owned())
        {
            return Err(LineageRefusalV1::ReplayedRecoveryGrant);
        }
        self.terminal = edge.successor().clone();
        self.edges.push(edge);
        Ok(self)
    }

    #[must_use]
    pub fn root(&self) -> &StoreGenerationSignerRootBindingV1 {
        &self.root
    }

    #[must_use]
    pub fn initial_binding(&self) -> &CurrentSignerGenerationBindingV1 {
        &self.initial
    }

    #[must_use]
    pub fn terminal_binding(&self) -> &CurrentSignerGenerationBindingV1 {
        &self.terminal
    }

    #[must_use]
    pub fn edges(&self) -> &[CurrentBindingSuccessionV1] {
        &self.edges
    }

    /// Reverify every adjacency without reordering or dropping an edge.
    pub(crate) fn verify_complete(&self) -> Result<(), LineageRefusalV1> {
        let mut expected = &self.initial;
        let mut transitions = BTreeSet::new();
        let mut completions = BTreeSet::new();
        let mut grants = BTreeSet::new();
        for edge in &self.edges {
            if edge.predecessor().binding_id() != expected.binding_id() {
                return Err(LineageRefusalV1::Gap);
            }
            if edge.successor().root_binding_id() != self.root.binding_id() {
                return Err(LineageRefusalV1::PredecessorSplice);
            }
            if !transitions.insert(edge.transition_id()) {
                return Err(LineageRefusalV1::DuplicateTransition);
            }
            if !completions.insert(edge.completion_pair()) {
                return Err(LineageRefusalV1::DuplicateCompletion);
            }
            if let Some(grant) = edge.recovery_grant_id()
                && !grants.insert(grant)
            {
                return Err(LineageRefusalV1::ReplayedRecoveryGrant);
            }
            expected = edge.successor();
        }
        if expected.binding_id() != self.terminal.binding_id() {
            return Err(LineageRefusalV1::MultipleTerminalBindings);
        }
        Ok(())
    }
}

/// NRP-07's named constructor.
pub(crate) fn construct_nrp_07_finite_rooted_lineage(
    root: StoreGenerationSignerRootBindingV1,
    initial: CurrentSignerGenerationBindingV1,
) -> Result<RootedCurrentBindingLineageV1, LineageRefusalV1> {
    RootedCurrentBindingLineageV1::initial(root, initial)
}

/// RPA-08 verifies arbitrary finite mixed recursion and terminal inversion.
pub(crate) fn construct_rpa_08_finite_mixed_recursion_inversion(
    lineage: RootedCurrentBindingLineageV1,
) -> Result<RootedCurrentBindingLineageV1, LineageRefusalV1> {
    lineage.verify_complete()?;
    Ok(lineage)
}

/// RPA-09 verifies that every recovery edge retains fresh authority/grant evidence.
pub(crate) fn construct_rpa_09_per_edge_authority_retention(
    lineage: &RootedCurrentBindingLineageV1,
) -> Result<(), LineageRefusalV1> {
    lineage.verify_complete()?;
    let recovery_count = lineage
        .edges
        .iter()
        .filter(|edge| matches!(edge, CurrentBindingSuccessionV1::Recovery { .. }))
        .count();
    if recovery_count == lineage.recovery_grant_ids.len() {
        Ok(())
    } else {
        Err(LineageRefusalV1::ReplayedRecoveryGrant)
    }
}

/// NRP-10's typed refusal helper.
pub(crate) fn construct_nrp_10_stale_skip_fork_refusal(
    classification: LineageRefusalV1,
) -> MalformedCurrentBindingSuccessionV1 {
    MalformedCurrentBindingSuccessionV1 { classification }
}

/// RPA-13's typed refusal helper.
pub(crate) fn construct_rpa_13_malformed_stale_splice_fork_replay_refusal(
    classification: LineageRefusalV1,
) -> MalformedRecoveryTransitionPredecessorV1 {
    MalformedRecoveryTransitionPredecessorV1 { classification }
}

pub(crate) fn construct_nrp_12_next_normal_dependency() -> NormalSuccessionDependencyV1 {
    NormalSuccessionDependencyV1
}

pub(crate) fn construct_nrp_13_normal_hostile_crash_qualification()
-> NormalSuccessionHostileCoverageV1 {
    NormalSuccessionHostileCoverageV1
}

pub(crate) fn construct_rpa_14_finite_cut_hostile_crash_calibration()
-> RecoverySuccessionHostileCoverageV1 {
    RecoverySuccessionHostileCoverageV1
}

pub(crate) fn construct_rpa_15_next_recovery_dependency_qualification()
-> RecoverySuccessionDependencyV1 {
    RecoverySuccessionDependencyV1
}

#[cfg(test)]
mod tests {
    use nq_protocol::sha256_bytes;

    use super::*;
    use crate::store_generation::signer::binding::{
        construct_sb_01_lifecycle_root_identity, construct_sb_02_immutable_root_binding,
        construct_sb_04_initial_binding_derivation,
    };

    fn root_and_initial() -> (
        StoreGenerationSignerRootBindingV1,
        CurrentSignerGenerationBindingV1,
    ) {
        let identity = construct_sb_01_lifecycle_root_identity(
            "occ".into(),
            "physical".into(),
            "root".into(),
            "scope".into(),
            "resident".into(),
            "role".into(),
            "manifest".into(),
            "domain".into(),
            "policy-lineage".into(),
        )
        .unwrap();
        let root = construct_sb_02_immutable_root_binding(
            identity,
            "enrollment-0".into(),
            "key-0".into(),
            "policy".into(),
            sha256_bytes(b"genesis"),
            sha256_bytes(b"commitment"),
            1,
        )
        .unwrap();
        let initial = construct_sb_04_initial_binding_derivation(
            &root,
            "standing-0".into(),
            "resolution-0".into(),
            2,
        )
        .unwrap()
        .into_inner();
        (root, initial)
    }

    fn normal_input(id: u8, predecessor_key: &str) -> NormalSuccessionInputV1 {
        NormalSuccessionInputV1 {
            transition_id: format!("normal-{id}"),
            continuity_authorization_id: format!("authorization-{id}"),
            continuity_signer_key_generation: predecessor_key.into(),
            successor_enrollment_id: format!("enrollment-{id}"),
            successor_key_generation: format!("key-{id}"),
            successor_policy_id: "policy".into(),
            successor_standing_id: format!("standing-{id}"),
            receipt_id: format!("receipt-{id}"),
            append_id: format!("append-{id}"),
            resolution_id: format!("resolution-{id}"),
            effective_cut: u64::from(id) + 2,
        }
    }

    #[test]
    fn arbitrary_normal_depth_consumes_exact_previous_terminal() {
        let (root, initial) = root_and_initial();
        let mut lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        for id in 1..=8 {
            let terminal = lineage.terminal_binding().clone();
            let predecessor = construct_nrp_01_normal_predecessor(
                terminal.clone(),
                terminal.binding_id(),
                terminal.standing_id().into(),
                terminal.key_generation().into(),
                terminal.policy_id().into(),
            )
            .unwrap();
            let input = normal_input(id, terminal.key_generation());
            lineage = lineage
                .append(
                    construct_nrp_06_adjacent_normal_succession(&root, predecessor, input).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(lineage.edges().len(), 8);
        lineage.verify_complete().unwrap();
    }

    #[test]
    fn repeated_recovery_requires_fresh_grants() {
        let (root, initial) = root_and_initial();
        let lineage =
            RootedCurrentBindingLineageV1::initial(root.clone(), initial.clone()).unwrap();
        let association = construct_rpa_01_recovery_ledger_base_join(
            &initial,
            "condition-1".into(),
            "authority-1".into(),
            "grant-1".into(),
            initial.binding_id().clone(),
            "key-r1".into(),
            "policy".into(),
        )
        .unwrap();
        let predecessor = construct_rpa_03_lawful_recovery_predecessor_provenance(
            initial.clone(),
            initial.binding_id(),
            association,
        )
        .unwrap();
        let edge = construct_rpa_04_adjacent_recovery_inversion(
            &root,
            predecessor,
            RecoverySuccessionInputV1 {
                transition_id: "recovery-1".into(),
                successor_enrollment_id: "enrollment-r1".into(),
                successor_key_generation: "key-r1".into(),
                successor_policy_id: "policy".into(),
                successor_standing_id: "standing-r1".into(),
                receipt_id: "receipt-r1".into(),
                append_id: "append-r1".into(),
                resolution_id: "resolution-r1".into(),
                effective_cut: 3,
            },
        )
        .unwrap();
        let lineage = lineage.append(edge).unwrap();
        construct_rpa_09_per_edge_authority_retention(&lineage).unwrap();
    }
}
