//! Exact adjacent normal/restore/recovery succession and finite rooted lineage.
//!
//! A lineage is built by appending one verified edge to its current terminal.
//! There is intentionally no constructor from an unordered collection and no
//! latest/highest-cut selection function.

use std::collections::BTreeSet;

use nq_protocol::Sha256Digest;

use super::binding::{
    CompletedSignerTransitionV1, CurrentSignerBindingModeV1, CurrentSignerGenerationBindingV1,
    PersistenceReadyCurrentSignerBindingV1, StoreGenerationSignerRootBindingV1,
    construct_sb_05_normal_binding_derivation, construct_sb_06_recovery_binding_derivation,
    construct_sb_06_restore_binding_derivation,
    construct_sb_10_successor_persistence_ready_binding,
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
    RestoreSuccessor,
    RecoverySuccessor,
}

/// Exact restore association for one displaced current binding and one
/// historical signer foundation.  The displaced predecessor and the
/// historical foundation are independent coordinates: restore authority names
/// the exact predecessor being displaced while re-adopting the historical
/// foundation's own identity/key-generation pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePredecessorBindingAssociationV1 {
    predecessor_binding_id: Sha256Digest,
    external_authority_id: String,
    restore_authorization_id: String,
    authorization_predecessor_binding_id: Sha256Digest,
    historical_foundation_id: String,
    historical_key_generation: String,
    restored_foundation_id: String,
    policy_id: String,
}

/// Exact current predecessor displaced by one restore authorization.  The
/// historical foundation being restored is retained separately in the
/// association.  Absence of usable predecessor custody is handled before this
/// inert completed-lineage projection is constructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreTransitionPredecessorV1 {
    binding: CurrentSignerGenerationBindingV1,
    currentness_id: String,
    association: RestorePredecessorBindingAssociationV1,
}

impl RestorePredecessorBindingAssociationV1 {
    #[must_use]
    pub fn predecessor_binding_id(&self) -> &Sha256Digest {
        &self.predecessor_binding_id
    }

    #[must_use]
    pub fn external_authority_id(&self) -> &str {
        &self.external_authority_id
    }

    #[must_use]
    pub fn restore_authorization_id(&self) -> &str {
        &self.restore_authorization_id
    }

    #[must_use]
    pub fn historical_foundation_id(&self) -> &str {
        &self.historical_foundation_id
    }

    #[must_use]
    pub fn historical_key_generation(&self) -> &str {
        &self.historical_key_generation
    }

    #[must_use]
    pub fn restored_foundation_id(&self) -> &str {
        &self.restored_foundation_id
    }
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

/// One adjacent normal, restore, or recovery edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentBindingSuccessionV1 {
    Normal {
        predecessor: CurrentRotationPredecessorV1,
        continuity_authorization_id: String,
        policy_continuity_authorization_id: Option<String>,
        transition: CompletedSignerTransitionV1,
        successor: CurrentSignerGenerationBindingV1,
    },
    Restore {
        predecessor: RestoreTransitionPredecessorV1,
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
    restore_authorization_ids: BTreeSet<String>,
    recovery_grant_ids: BTreeSet<String>,
}

/// Exact inputs for one normal transition.  Possession is not authorization:
/// the continuity signer must be the predecessor key, never the successor.
pub(crate) struct NormalSuccessionInputV1 {
    pub transition_id: String,
    pub continuity_authorization_id: String,
    /// Exact MSG-05 identity iff policy, activation, or applicability changes.
    pub policy_continuity_authorization_id: Option<String>,
    pub continuity_signer_key_generation: String,
    pub predecessor_activation_id: String,
    pub successor_activation_id: String,
    pub predecessor_applicability_id: String,
    pub successor_applicability_id: String,
    pub successor_enrollment_id: String,
    pub successor_key_generation: String,
    pub successor_policy_id: String,
    pub successor_standing_id: String,
    pub receipt_id: String,
    pub append_id: String,
    pub resolution_id: String,
    pub effective_cut: u64,
}

/// Exact inputs for one historical-foundation restore transition.  The
/// predecessor does not authorize the transition and no predecessor custody
/// enters this record; the separately verified external restore association
/// names the exact historical foundation being re-adopted.
pub(crate) struct RestoreSuccessionInputV1 {
    pub transition_id: String,
    pub restored_foundation_id: String,
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

/// Invert NRP-02 into the exact four-route completed-current provenance.
pub(crate) fn construct_nrp_02_normal_predecessor_trichotomy(
    predecessor: &CurrentRotationPredecessorV1,
) -> CurrentRotationPredecessorRouteV1 {
    match predecessor.binding.mode() {
        CurrentSignerBindingModeV1::Initial => CurrentRotationPredecessorRouteV1::Initial,
        CurrentSignerBindingModeV1::NormalSuccessor => {
            CurrentRotationPredecessorRouteV1::NormalSuccessor
        }
        CurrentSignerBindingModeV1::RestoreSuccessor => {
            CurrentRotationPredecessorRouteV1::RestoreSuccessor
        }
        CurrentSignerBindingModeV1::RecoverySuccessor => {
            CurrentRotationPredecessorRouteV1::RecoverySuccessor
        }
    }
}

/// Join one exact displaced current binding to one external restore
/// authorization and the exact historical foundation that authorization may
/// re-adopt.  The historical key-generation coordinate belongs to that
/// foundation, not to the displaced current predecessor.  Equivalent-looking
/// replacement foundation or key coordinates do not satisfy the downstream
/// restore transition.
#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_restore_01_historical_foundation_base_join(
    predecessor: &CurrentSignerGenerationBindingV1,
    external_authority_id: String,
    restore_authorization_id: String,
    authorization_predecessor_binding_id: Sha256Digest,
    historical_foundation_id: String,
    restored_foundation_id: String,
    historical_key_generation: String,
    policy_id: String,
) -> Result<RestorePredecessorBindingAssociationV1, LineageRefusalV1> {
    if authorization_predecessor_binding_id != *predecessor.binding_id()
        || historical_foundation_id != restored_foundation_id
        || policy_id != predecessor.policy_id()
        || !nonempty(&[
            &external_authority_id,
            &restore_authorization_id,
            &historical_foundation_id,
            &restored_foundation_id,
            &historical_key_generation,
            &policy_id,
        ])
    {
        return Err(LineageRefusalV1::PredecessorSplice);
    }
    Ok(RestorePredecessorBindingAssociationV1 {
        predecessor_binding_id: predecessor.binding_id().clone(),
        external_authority_id,
        restore_authorization_id,
        authorization_predecessor_binding_id,
        historical_foundation_id,
        historical_key_generation,
        restored_foundation_id,
        policy_id,
    })
}

/// Recheck that the restore association still seals the same predecessor and
/// exact historical foundation.  This consumes no live authority and cannot
/// convert the durable association into a pending or current signer.
pub(crate) fn construct_restore_02_authorization_seals_predecessor_foundation(
    predecessor: &CurrentSignerGenerationBindingV1,
    association: RestorePredecessorBindingAssociationV1,
) -> Result<RestorePredecessorBindingAssociationV1, LineageRefusalV1> {
    if association.predecessor_binding_id != *predecessor.binding_id()
        || association.authorization_predecessor_binding_id != *predecessor.binding_id()
        || association.historical_foundation_id != association.restored_foundation_id
        || association.historical_key_generation.is_empty()
        || association.policy_id != predecessor.policy_id()
    {
        Err(LineageRefusalV1::PredecessorSplice)
    } else {
        Ok(association)
    }
}

/// Construct the exact current predecessor displaced by restore.  Currentness
/// identifies that predecessor record; the separately bound historical pair
/// identifies what is re-adopted and supplies no ordinary continuity authority.
pub(crate) fn construct_restore_03_lawful_restore_predecessor_provenance(
    binding: CurrentSignerGenerationBindingV1,
    currentness_binding_id: &Sha256Digest,
    association: RestorePredecessorBindingAssociationV1,
) -> Result<RestoreTransitionPredecessorV1, LineageRefusalV1> {
    if currentness_binding_id != binding.binding_id()
        || association.predecessor_binding_id != *binding.binding_id()
        || association.authorization_predecessor_binding_id != *binding.binding_id()
        || association.historical_foundation_id != association.restored_foundation_id
        || association.historical_key_generation.is_empty()
        || association.policy_id != binding.policy_id()
    {
        return Err(LineageRefusalV1::PredecessorSplice);
    }
    Ok(RestoreTransitionPredecessorV1 {
        binding,
        currentness_id: currentness_binding_id.to_string(),
        association,
    })
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
    let policy_activation_or_applicability_changed =
        input.successor_policy_id != predecessor.policy_id
            || input.successor_activation_id != input.predecessor_activation_id
            || input.successor_applicability_id != input.predecessor_applicability_id;
    let policy_continuity_shape_is_exact = match (
        policy_activation_or_applicability_changed,
        input.policy_continuity_authorization_id.as_deref(),
    ) {
        (true, Some(identity)) => !identity.is_empty(),
        (false, None) => true,
        (true, None) | (false, Some(_)) => false,
    };
    if input.continuity_signer_key_generation != predecessor.binding.key_generation()
        || input.successor_key_generation == input.continuity_signer_key_generation
        || !policy_continuity_shape_is_exact
    {
        return Err(LineageRefusalV1::SuccessorSelfAuthorization);
    }
    if !nonempty(&[
        &input.transition_id,
        &input.continuity_authorization_id,
        &input.predecessor_activation_id,
        &input.successor_activation_id,
        &input.predecessor_applicability_id,
        &input.successor_applicability_id,
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

fn completed_restore(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: &RestoreTransitionPredecessorV1,
    input: &RestoreSuccessionInputV1,
) -> Result<CompletedSignerTransitionV1, LineageRefusalV1> {
    if predecessor.association.historical_foundation_id
        != predecessor.association.restored_foundation_id
        || input.restored_foundation_id != predecessor.association.restored_foundation_id
        || input.successor_key_generation != predecessor.association.historical_key_generation
        || input.successor_policy_id != predecessor.association.policy_id
    {
        return Err(LineageRefusalV1::PredecessorSplice);
    }
    if !nonempty(&[
        &input.transition_id,
        &input.restored_foundation_id,
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
        mode: CurrentSignerBindingModeV1::RestoreSuccessor,
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
        policy_continuity_authorization_id: input.policy_continuity_authorization_id,
        transition,
        successor,
    })
}

/// Construct the persistence-ready completed current binding for the healthy
/// successor route.  The caller supplies the existing sealed normal
/// predecessor and route input; no generic provenance selector or raw
/// completed transition crosses this boundary.
pub(crate) fn construct_nrp_06_persistence_ready_normal_current(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: CurrentRotationPredecessorV1,
    input: NormalSuccessionInputV1,
) -> Result<PersistenceReadyCurrentSignerBindingV1, LineageRefusalV1> {
    let edge = construct_nrp_06_adjacent_normal_succession(root, predecessor, input)?;
    persistence_ready_successor(edge)
}

/// Construct one exact adjacent restore edge.  Its completed binding records a
/// restore provenance distinct from recovery, while adjacency still consumes
/// the exact historical terminal predecessor.
pub(crate) fn construct_restore_04_adjacent_restore_inversion(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: RestoreTransitionPredecessorV1,
    input: RestoreSuccessionInputV1,
) -> Result<CurrentBindingSuccessionV1, LineageRefusalV1> {
    let transition = completed_restore(root, &predecessor, &input)?;
    let successor =
        construct_sb_06_restore_binding_derivation(root, &predecessor.binding, &transition)
            .map_err(|_| LineageRefusalV1::PredecessorSplice)?
            .into_inner();
    Ok(CurrentBindingSuccessionV1::Restore {
        predecessor,
        transition,
        successor,
    })
}

/// Construct the persistence-ready completed current binding for exact
/// historical-foundation restore.  Restore authority remains encoded in the
/// sealed predecessor and cannot be selected by a caller-provided mode.
pub(crate) fn construct_restore_04_persistence_ready_restore_current(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: RestoreTransitionPredecessorV1,
    input: RestoreSuccessionInputV1,
) -> Result<PersistenceReadyCurrentSignerBindingV1, LineageRefusalV1> {
    let edge = construct_restore_04_adjacent_restore_inversion(root, predecessor, input)?;
    persistence_ready_successor(edge)
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

/// Construct the persistence-ready completed current binding for externally
/// authorized recovery.  Recovery remains disjoint from restore and healthy
/// continuity because this entry point consumes only the recovery predecessor
/// proof and recovery input.
pub(crate) fn construct_rpa_04_persistence_ready_recovery_current(
    root: &StoreGenerationSignerRootBindingV1,
    predecessor: RecoveryTransitionPredecessorV1,
    input: RecoverySuccessionInputV1,
) -> Result<PersistenceReadyCurrentSignerBindingV1, LineageRefusalV1> {
    let edge = construct_rpa_04_adjacent_recovery_inversion(root, predecessor, input)?;
    persistence_ready_successor(edge)
}

fn persistence_ready_successor(
    edge: CurrentBindingSuccessionV1,
) -> Result<PersistenceReadyCurrentSignerBindingV1, LineageRefusalV1> {
    let current = edge.successor().clone();
    let transition = edge.transition();
    construct_sb_10_successor_persistence_ready_binding(current, transition)
        .map_err(|_| LineageRefusalV1::PredecessorSplice)
}

impl CurrentBindingSuccessionV1 {
    #[must_use]
    pub fn predecessor(&self) -> &CurrentSignerGenerationBindingV1 {
        match self {
            Self::Normal { predecessor, .. } => &predecessor.binding,
            Self::Restore { predecessor, .. } => &predecessor.binding,
            Self::Recovery { predecessor, .. } => &predecessor.binding,
        }
    }

    #[must_use]
    pub fn successor(&self) -> &CurrentSignerGenerationBindingV1 {
        match self {
            Self::Normal { successor, .. }
            | Self::Restore { successor, .. }
            | Self::Recovery { successor, .. } => successor,
        }
    }

    #[must_use]
    pub fn transition_id(&self) -> &str {
        match self {
            Self::Normal { transition, .. }
            | Self::Restore { transition, .. }
            | Self::Recovery { transition, .. } => &transition.transition_id,
        }
    }

    fn transition(&self) -> &CompletedSignerTransitionV1 {
        match self {
            Self::Normal { transition, .. }
            | Self::Restore { transition, .. }
            | Self::Recovery { transition, .. } => transition,
        }
    }

    /// Closed completed-current provenance of this exact adjacent edge.
    #[must_use]
    pub const fn mode(&self) -> CurrentSignerBindingModeV1 {
        match self {
            Self::Normal { .. } => CurrentSignerBindingModeV1::NormalSuccessor,
            Self::Restore { .. } => CurrentSignerBindingModeV1::RestoreSuccessor,
            Self::Recovery { .. } => CurrentSignerBindingModeV1::RecoverySuccessor,
        }
    }

    /// Exact route-specific authorization identity retained by this edge.
    /// This is durable evidence only and has no conversion into live authority.
    #[must_use]
    pub fn authorization_id(&self) -> &str {
        match self {
            Self::Normal {
                continuity_authorization_id,
                ..
            } => continuity_authorization_id,
            Self::Restore { predecessor, .. } => &predecessor.association.restore_authorization_id,
            Self::Recovery { predecessor, .. } => &predecessor.association.recovery_grant_id,
        }
    }

    /// Exact conditional MSG-05 retained by a normal edge. Absence is
    /// meaningful and is legal only for an unchanged policy/activation/
    /// applicability transition.
    #[must_use]
    pub fn policy_continuity_authorization_id(&self) -> Option<&str> {
        match self {
            Self::Normal {
                policy_continuity_authorization_id,
                ..
            } => policy_continuity_authorization_id.as_deref(),
            Self::Restore { .. } | Self::Recovery { .. } => None,
        }
    }

    fn completion_pair(&self) -> (&str, &str) {
        match self {
            Self::Normal { transition, .. }
            | Self::Restore { transition, .. }
            | Self::Recovery { transition, .. } => (&transition.receipt_id, &transition.append_id),
        }
    }

    fn restore_authorization_id(&self) -> Option<&str> {
        match self {
            Self::Restore { predecessor, .. } => {
                Some(&predecessor.association.restore_authorization_id)
            }
            Self::Normal { .. } | Self::Recovery { .. } => None,
        }
    }

    fn recovery_grant_id(&self) -> Option<&str> {
        match self {
            Self::Normal { .. } | Self::Restore { .. } => None,
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
            restore_authorization_ids: BTreeSet::new(),
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
        if let Some(authorization_id) = edge.restore_authorization_id()
            && !self
                .restore_authorization_ids
                .insert(authorization_id.to_owned())
        {
            return Err(LineageRefusalV1::CompetingSuccessors);
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
        let mut restore_authorizations = BTreeSet::new();
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
            if let Some(authorization) = edge.restore_authorization_id()
                && !restore_authorizations.insert(authorization)
            {
                return Err(LineageRefusalV1::CompetingSuccessors);
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
        if restore_authorizations.len() != self.restore_authorization_ids.len() {
            return Err(LineageRefusalV1::CompetingSuccessors);
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

/// RPA-08 verifies arbitrary finite normal/restore/recovery recursion and
/// terminal inversion.
pub(crate) fn construct_rpa_08_finite_mixed_recursion_inversion(
    lineage: RootedCurrentBindingLineageV1,
) -> Result<RootedCurrentBindingLineageV1, LineageRefusalV1> {
    lineage.verify_complete()?;
    Ok(lineage)
}

/// Every restore edge retains one exact, non-replayed MSG-13 authorization.
pub(crate) fn construct_restore_05_per_edge_authority_retention(
    lineage: &RootedCurrentBindingLineageV1,
) -> Result<(), LineageRefusalV1> {
    lineage.verify_complete()?;
    let restore_count = lineage
        .edges
        .iter()
        .filter(|edge| matches!(edge, CurrentBindingSuccessionV1::Restore { .. }))
        .count();
    if restore_count == lineage.restore_authorization_ids.len() {
        Ok(())
    } else {
        Err(LineageRefusalV1::CompetingSuccessors)
    }
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
            policy_continuity_authorization_id: None,
            continuity_signer_key_generation: predecessor_key.into(),
            predecessor_activation_id: "activation".into(),
            successor_activation_id: "activation".into(),
            predecessor_applicability_id: "applicability".into(),
            successor_applicability_id: "applicability".into(),
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
    fn normal_policy_continuity_is_present_exactly_for_a_changed_basis() {
        let (root, initial) = root_and_initial();
        let predecessor = || {
            construct_nrp_01_normal_predecessor(
                initial.clone(),
                initial.binding_id(),
                initial.standing_id().into(),
                initial.key_generation().into(),
                initial.policy_id().into(),
            )
            .unwrap()
        };

        let mut missing = normal_input(1, initial.key_generation());
        missing.successor_policy_id = "policy-changed".into();
        assert!(construct_nrp_06_adjacent_normal_succession(
            &root,
            predecessor(),
            missing,
        )
        .is_err());

        let mut changed = normal_input(1, initial.key_generation());
        changed.successor_activation_id = "activation-changed".into();
        changed.policy_continuity_authorization_id = Some("msg05-exact".into());
        let changed = construct_nrp_06_adjacent_normal_succession(
            &root,
            predecessor(),
            changed,
        )
        .unwrap();
        assert_eq!(
            changed.policy_continuity_authorization_id(),
            Some("msg05-exact")
        );

        let mut surplus = normal_input(1, initial.key_generation());
        surplus.policy_continuity_authorization_id = Some("msg05-surplus".into());
        assert!(construct_nrp_06_adjacent_normal_succession(
            &root,
            predecessor(),
            surplus,
        )
        .is_err());
    }

    fn restore_association(
        predecessor: &CurrentSignerGenerationBindingV1,
        authorization: &str,
        foundation: &str,
    ) -> RestorePredecessorBindingAssociationV1 {
        construct_restore_01_historical_foundation_base_join(
            predecessor,
            format!("external-{authorization}"),
            authorization.into(),
            predecessor.binding_id().clone(),
            foundation.into(),
            foundation.into(),
            predecessor.key_generation().into(),
            predecessor.policy_id().into(),
        )
        .unwrap()
    }

    fn restore_input(
        suffix: &str,
        foundation: &str,
        predecessor: &CurrentSignerGenerationBindingV1,
        effective_cut: u64,
    ) -> RestoreSuccessionInputV1 {
        RestoreSuccessionInputV1 {
            transition_id: format!("restore-{suffix}"),
            restored_foundation_id: foundation.into(),
            successor_enrollment_id: format!("enrollment-restore-{suffix}"),
            successor_key_generation: predecessor.key_generation().into(),
            successor_policy_id: predecessor.policy_id().into(),
            successor_standing_id: format!("standing-restore-{suffix}"),
            receipt_id: format!("receipt-restore-{suffix}"),
            append_id: format!("append-restore-{suffix}"),
            resolution_id: format!("resolution-restore-{suffix}"),
            effective_cut,
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
    fn persistence_facades_seal_each_successor_route_without_generic_selection() {
        let (root, initial) = root_and_initial();

        let normal_predecessor = construct_nrp_01_normal_predecessor(
            initial.clone(),
            initial.binding_id(),
            initial.standing_id().into(),
            initial.key_generation().into(),
            initial.policy_id().into(),
        )
        .unwrap();
        let normal = construct_nrp_06_persistence_ready_normal_current(
            &root,
            normal_predecessor,
            normal_input(1, initial.key_generation()),
        )
        .unwrap();
        assert_eq!(
            normal.current().mode(),
            CurrentSignerBindingModeV1::NormalSuccessor
        );
        assert_eq!(normal.association().transition_id(), Some("normal-1"));
        assert_eq!(normal.association().receipt_id(), "receipt-1");
        assert_eq!(normal.association().append_id(), "append-1");
        assert_eq!(
            normal.association().resulting_binding_id(),
            normal.current().binding_id()
        );

        let restore_predecessor = construct_restore_03_lawful_restore_predecessor_provenance(
            initial.clone(),
            initial.binding_id(),
            restore_association(&initial, "restore-ready", "foundation-0"),
        )
        .unwrap();
        let restore = construct_restore_04_persistence_ready_restore_current(
            &root,
            restore_predecessor,
            restore_input("ready", "foundation-0", &initial, 3),
        )
        .unwrap();
        assert_eq!(
            restore.current().mode(),
            CurrentSignerBindingModeV1::RestoreSuccessor
        );
        assert_eq!(restore.association().transition_id(), Some("restore-ready"));
        assert_eq!(
            restore.association().resolution_id(),
            "resolution-restore-ready"
        );

        let recovery_association = construct_rpa_01_recovery_ledger_base_join(
            &initial,
            "condition-ready".into(),
            "authority-ready".into(),
            "grant-ready".into(),
            initial.binding_id().clone(),
            "key-recovery-ready".into(),
            "policy".into(),
        )
        .unwrap();
        let recovery_predecessor = construct_rpa_03_lawful_recovery_predecessor_provenance(
            initial.clone(),
            initial.binding_id(),
            recovery_association,
        )
        .unwrap();
        let recovery = construct_rpa_04_persistence_ready_recovery_current(
            &root,
            recovery_predecessor,
            RecoverySuccessionInputV1 {
                transition_id: "recovery-ready".into(),
                successor_enrollment_id: "enrollment-recovery-ready".into(),
                successor_key_generation: "key-recovery-ready".into(),
                successor_policy_id: "policy".into(),
                successor_standing_id: "standing-recovery-ready".into(),
                receipt_id: "receipt-recovery-ready".into(),
                append_id: "append-recovery-ready".into(),
                resolution_id: "resolution-recovery-ready".into(),
                effective_cut: 3,
            },
        )
        .unwrap();
        assert_eq!(
            recovery.current().mode(),
            CurrentSignerBindingModeV1::RecoverySuccessor
        );
        assert_eq!(
            recovery.association().transition_id(),
            Some("recovery-ready")
        );
        assert_eq!(
            recovery.association().resulting_binding_id(),
            recovery.current().binding_id()
        );
    }

    #[test]
    fn restore_is_distinct_and_becomes_an_exact_ordinary_predecessor_only_when_current() {
        let (root, initial) = root_and_initial();
        let association = restore_association(&initial, "restore-authorization-1", "foundation-0");
        assert_eq!(association.predecessor_binding_id(), initial.binding_id());
        assert_eq!(
            association.external_authority_id(),
            "external-restore-authorization-1"
        );
        assert_eq!(
            association.restore_authorization_id(),
            "restore-authorization-1"
        );
        assert_eq!(association.historical_foundation_id(), "foundation-0");
        assert_eq!(association.restored_foundation_id(), "foundation-0");

        let predecessor = construct_restore_03_lawful_restore_predecessor_provenance(
            initial.clone(),
            initial.binding_id(),
            construct_restore_02_authorization_seals_predecessor_foundation(&initial, association)
                .unwrap(),
        )
        .unwrap();
        let restore = construct_restore_04_adjacent_restore_inversion(
            &root,
            predecessor,
            restore_input("1", "foundation-0", &initial, 3),
        )
        .unwrap();
        assert_eq!(restore.mode(), CurrentSignerBindingModeV1::RestoreSuccessor);
        assert_eq!(restore.authorization_id(), "restore-authorization-1");
        assert_eq!(
            restore.successor().mode(),
            CurrentSignerBindingModeV1::RestoreSuccessor
        );

        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial)
            .unwrap()
            .append(restore)
            .unwrap();
        construct_restore_05_per_edge_authority_retention(&lineage).unwrap();

        let restored = lineage.terminal_binding().clone();
        let ordinary_predecessor = construct_nrp_01_normal_predecessor(
            restored.clone(),
            restored.binding_id(),
            restored.standing_id().into(),
            restored.key_generation().into(),
            restored.policy_id().into(),
        )
        .unwrap();
        assert_eq!(
            construct_nrp_02_normal_predecessor_trichotomy(&ordinary_predecessor),
            CurrentRotationPredecessorRouteV1::RestoreSuccessor
        );
        let next = construct_nrp_06_adjacent_normal_succession(
            &root,
            ordinary_predecessor,
            normal_input(2, restored.key_generation()),
        )
        .unwrap();
        let lineage = lineage.append(next).unwrap();
        assert_eq!(lineage.edges().len(), 2);
        assert_eq!(
            lineage.terminal_binding().mode(),
            CurrentSignerBindingModeV1::NormalSuccessor
        );
        lineage.verify_complete().unwrap();
    }

    #[test]
    fn restore_re_adopts_an_older_foundation_without_equating_it_to_current_predecessor() {
        let (root, initial) = root_and_initial();
        let historical_key_generation = initial.key_generation().to_owned();
        let initial_binding_id = initial.binding_id().clone();

        let normal_predecessor = construct_nrp_01_normal_predecessor(
            initial.clone(),
            initial.binding_id(),
            initial.standing_id().into(),
            initial.key_generation().into(),
            initial.policy_id().into(),
        )
        .unwrap();
        let current_b_edge = construct_nrp_06_adjacent_normal_succession(
            &root,
            normal_predecessor,
            normal_input(1, initial.key_generation()),
        )
        .unwrap();
        let lineage_at_b = RootedCurrentBindingLineageV1::initial(root.clone(), initial.clone())
            .unwrap()
            .append(current_b_edge)
            .unwrap();
        let current_b = lineage_at_b.terminal_binding().clone();
        assert_eq!(historical_key_generation, "key-0");
        assert_eq!(current_b.key_generation(), "key-1");

        let association = construct_restore_01_historical_foundation_base_join(
            &current_b,
            "external-restore-a".into(),
            "restore-authorization-a".into(),
            current_b.binding_id().clone(),
            "foundation-a".into(),
            "foundation-a".into(),
            historical_key_generation.clone(),
            current_b.policy_id().into(),
        )
        .unwrap();
        assert_eq!(association.predecessor_binding_id(), current_b.binding_id());
        assert_ne!(association.predecessor_binding_id(), &initial_binding_id);
        assert_eq!(association.historical_foundation_id(), "foundation-a");
        assert_eq!(
            association.historical_key_generation(),
            historical_key_generation
        );

        let association = construct_restore_02_authorization_seals_predecessor_foundation(
            &current_b,
            association,
        )
        .unwrap();
        let current_b_binding_id = current_b.binding_id().clone();
        let restore_predecessor = construct_restore_03_lawful_restore_predecessor_provenance(
            current_b.clone(),
            &current_b_binding_id,
            association,
        )
        .unwrap();

        let mut substituted_foundation =
            restore_input("substituted-foundation", "foundation-a", &initial, 4);
        substituted_foundation.restored_foundation_id = "foundation-b".into();
        assert_eq!(
            construct_restore_04_adjacent_restore_inversion(
                &root,
                restore_predecessor.clone(),
                substituted_foundation,
            ),
            Err(LineageRefusalV1::PredecessorSplice)
        );

        let mut substituted_key_generation =
            restore_input("substituted-key", "foundation-a", &initial, 4);
        substituted_key_generation.successor_key_generation = current_b.key_generation().into();
        assert_eq!(
            construct_restore_04_adjacent_restore_inversion(
                &root,
                restore_predecessor.clone(),
                substituted_key_generation,
            ),
            Err(LineageRefusalV1::PredecessorSplice)
        );

        let restored_a = construct_restore_04_adjacent_restore_inversion(
            &root,
            restore_predecessor,
            restore_input("historical-a", "foundation-a", &initial, 4),
        )
        .unwrap();
        let restored_lineage = lineage_at_b.append(restored_a).unwrap();
        assert_eq!(
            restored_lineage.terminal_binding().key_generation(),
            historical_key_generation
        );
        assert_eq!(
            restored_lineage.terminal_binding().mode(),
            CurrentSignerBindingModeV1::RestoreSuccessor
        );
        restored_lineage.verify_complete().unwrap();
    }

    #[test]
    fn restore_requires_exact_historical_foundation_and_one_use_authorization() {
        let (root, initial) = root_and_initial();
        assert_eq!(
            construct_restore_01_historical_foundation_base_join(
                &initial,
                "external-restore".into(),
                "restore-authorization".into(),
                initial.binding_id().clone(),
                "historical-foundation".into(),
                "substituted-foundation".into(),
                initial.key_generation().into(),
                initial.policy_id().into(),
            ),
            Err(LineageRefusalV1::PredecessorSplice)
        );

        let first_predecessor = construct_restore_03_lawful_restore_predecessor_provenance(
            initial.clone(),
            initial.binding_id(),
            restore_association(&initial, "one-use-restore", "foundation-0"),
        )
        .unwrap();
        let first = construct_restore_04_adjacent_restore_inversion(
            &root,
            first_predecessor,
            restore_input("1", "foundation-0", &initial, 3),
        )
        .unwrap();
        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial)
            .unwrap()
            .append(first)
            .unwrap();
        let restored = lineage.terminal_binding().clone();
        let replayed_predecessor = construct_restore_03_lawful_restore_predecessor_provenance(
            restored.clone(),
            restored.binding_id(),
            restore_association(&restored, "one-use-restore", "foundation-0"),
        )
        .unwrap();
        let replay = construct_restore_04_adjacent_restore_inversion(
            &root,
            replayed_predecessor,
            restore_input("2", "foundation-0", &restored, 4),
        )
        .unwrap();
        assert_eq!(
            lineage.append(replay),
            Err(LineageRefusalV1::CompetingSuccessors)
        );
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
        assert_eq!(edge.mode(), CurrentSignerBindingModeV1::RecoverySuccessor);
        assert_eq!(edge.authorization_id(), "grant-1");
        let lineage = lineage.append(edge).unwrap();
        construct_rpa_09_per_edge_authority_retention(&lineage).unwrap();
    }
}
