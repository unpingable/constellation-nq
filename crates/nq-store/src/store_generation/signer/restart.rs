//! Exact initial and terminal-successor signer restart correspondence.
//!
//! Restart is read-only reconstruction from a complete rooted lineage and an
//! exact terminal custody observation.  There is no constructor from
//! currentness plus custody, no generic completed-generation route, and no
//! sorting or latest-record selection.

use nq_protocol::Sha256Digest;

use super::binding::{
    CurrentSignerBindingModeV1, CurrentSignerGenerationBindingV1,
    StoreGenerationSignerRootBindingV1, verify_sb_02_immutable_root_binding,
    verify_sb_03_evolving_current_binding,
};
use super::correspondence::{
    SuccessorTraceCutsV2, construct_normal_successor_trace_cut_order_correspondence,
    construct_recovery_successor_trace_cut_order_correspondence,
};
use super::lineage::{
    CurrentBindingSuccessionV1, RootedCurrentBindingLineageV1,
    construct_rpa_09_per_edge_authority_retention,
};
use super::result::{LineageRefusalV1, RestartRefusalV2, RestartResultV2};

/// Exact route derived from the verified terminal binding; callers never pick it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifiedRestartRouteV1 {
    Initial,
    NormalTerminal,
    RestoreTerminal,
    RecoveryTerminal,
}

/// Store-private proof that custody was observed for one exact binding/key in
/// one target process context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalCustodyProofV1 {
    occurrence_id: String,
    physical_store_generation: String,
    root_binding_id: Sha256Digest,
    binding_id: Sha256Digest,
    key_generation: String,
    process_context_id: String,
}

/// Build a custody proof only when every durable coordinate names the current
/// binding.  Actual file ownership/key checks are performed by `custody.rs`
/// before this process-local proof is supplied.
pub(crate) fn construct_terminal_custody_proof(
    root: &StoreGenerationSignerRootBindingV1,
    binding: &CurrentSignerGenerationBindingV1,
    occurrence_id: String,
    physical_store_generation: String,
    root_binding_id: Sha256Digest,
    binding_id: Sha256Digest,
    key_generation: String,
    process_context_id: String,
) -> Result<TerminalCustodyProofV1, RestartRefusalV2> {
    if occurrence_id.is_empty()
        || physical_store_generation.is_empty()
        || key_generation.is_empty()
        || process_context_id.is_empty()
        || occurrence_id != root.occurrence_id()
        || physical_store_generation != root.physical_store_generation()
        || root_binding_id != *root.binding_id()
        || binding_id != *binding.binding_id()
        || key_generation != binding.key_generation()
        || binding.root_binding_id() != root.binding_id()
    {
        return Err(RestartRefusalV2::MalformedOrSplicedEvidence);
    }
    Ok(TerminalCustodyProofV1 {
        occurrence_id,
        physical_store_generation,
        root_binding_id,
        binding_id,
        key_generation,
        process_context_id,
    })
}

/// Complete Store-native restart inputs.  The resolved terminal is supplied by
/// candidate-set resolution and must agree with the adjacency-derived lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompleteSignerRestartSnapshotV1 {
    lineage: RootedCurrentBindingLineageV1,
    resolved_current_binding_ids: Vec<Sha256Digest>,
    persisted_terminal_resolution_id: String,
    persisted_terminal_standing_id: String,
    custody_observations: Vec<TerminalCustodyProofV1>,
    target_process_context_id: String,
}

/// Construct an untrusted snapshot container.  Capability reconstruction still
/// reverifies every field; this constructor confers no standing.
pub(crate) fn construct_complete_signer_restart_snapshot(
    lineage: RootedCurrentBindingLineageV1,
    resolved_current_binding_ids: Vec<Sha256Digest>,
    persisted_terminal_resolution_id: String,
    persisted_terminal_standing_id: String,
    custody_observations: Vec<TerminalCustodyProofV1>,
    target_process_context_id: String,
) -> CompleteSignerRestartSnapshotV1 {
    CompleteSignerRestartSnapshotV1 {
        lineage,
        resolved_current_binding_ids,
        persisted_terminal_resolution_id,
        persisted_terminal_standing_id,
        custody_observations,
        target_process_context_id,
    }
}

/// Sealed capability reconstructed for exactly one terminal signer.  It has no
/// enrollment, rotation, recovery, restore, or external-judgment constructor.
pub(crate) struct ReconstructedTerminalSignerCapabilityV1 {
    root_binding_id: Sha256Digest,
    terminal_binding_id: Sha256Digest,
    terminal_key_generation: String,
    process_context_id: String,
    route: VerifiedRestartRouteV1,
}

impl ReconstructedTerminalSignerCapabilityV1 {
    #[must_use]
    pub(crate) fn terminal_binding_id(&self) -> &Sha256Digest {
        &self.terminal_binding_id
    }

    #[must_use]
    pub(crate) fn terminal_key_generation(&self) -> &str {
        &self.terminal_key_generation
    }

    #[must_use]
    pub(crate) const fn route(&self) -> VerifiedRestartRouteV1 {
        self.route
    }
}

impl std::fmt::Debug for ReconstructedTerminalSignerCapabilityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReconstructedTerminalSignerCapabilityV1")
            .field("root_binding_id", &self.root_binding_id)
            .field("terminal_binding_id", &self.terminal_binding_id)
            .field("terminal_key_generation", &self.terminal_key_generation)
            .field("process_context_id", &self.process_context_id)
            .field("route", &self.route)
            .finish()
    }
}

fn map_lineage_refusal(refusal: LineageRefusalV1) -> RestartRefusalV2 {
    match refusal {
        LineageRefusalV1::Gap | LineageRefusalV1::SkippedPredecessor => {
            RestartRefusalV2::IncompleteLineage
        }
        LineageRefusalV1::Fork
        | LineageRefusalV1::CompetingSuccessors
        | LineageRefusalV1::MultipleTerminalBindings => RestartRefusalV2::ForkedLineage,
        _ => RestartRefusalV2::MalformedOrSplicedEvidence,
    }
}

fn derived_route(
    lineage: &RootedCurrentBindingLineageV1,
) -> Result<VerifiedRestartRouteV1, RestartRefusalV2> {
    match lineage.terminal_binding().mode() {
        CurrentSignerBindingModeV1::Initial if lineage.edges().is_empty() => {
            Ok(VerifiedRestartRouteV1::Initial)
        }
        CurrentSignerBindingModeV1::Initial => {
            Err(RestartRefusalV2::InitialRouteHasSuccessorMaterial)
        }
        CurrentSignerBindingModeV1::NormalSuccessor
            if matches!(
                lineage.edges().last(),
                Some(CurrentBindingSuccessionV1::Normal { .. })
            ) =>
        {
            Ok(VerifiedRestartRouteV1::NormalTerminal)
        }
        CurrentSignerBindingModeV1::RestoreSuccessor
            if matches!(
                lineage.edges().last(),
                Some(CurrentBindingSuccessionV1::Restore { .. })
            ) =>
        {
            Ok(VerifiedRestartRouteV1::RestoreTerminal)
        }
        CurrentSignerBindingModeV1::RecoverySuccessor
            if matches!(
                lineage.edges().last(),
                Some(CurrentBindingSuccessionV1::Recovery { .. })
            ) =>
        {
            Ok(VerifiedRestartRouteV1::RecoveryTerminal)
        }
        _ => Err(RestartRefusalV2::RouteModeMismatch),
    }
}

fn verify_snapshot(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<VerifiedRestartRouteV1, RestartRefusalV2> {
    let root = snapshot.lineage.root();
    let terminal = snapshot.lineage.terminal_binding();
    verify_sb_02_immutable_root_binding(root)
        .map_err(|_| RestartRefusalV2::MalformedOrSplicedEvidence)?;
    verify_sb_03_evolving_current_binding(root, terminal)
        .map_err(|_| RestartRefusalV2::MalformedOrSplicedEvidence)?;
    snapshot
        .lineage
        .verify_complete()
        .map_err(map_lineage_refusal)?;
    construct_rpa_09_per_edge_authority_retention(&snapshot.lineage)
        .map_err(map_lineage_refusal)?;

    match snapshot.resolved_current_binding_ids.as_slice() {
        [] => return Err(RestartRefusalV2::IncompleteLineage),
        [only] if only == terminal.binding_id() => {}
        [_] => return Err(RestartRefusalV2::IncompleteLineage),
        _ => return Err(RestartRefusalV2::ForkedLineage),
    }
    if snapshot.persisted_terminal_resolution_id != terminal.persisted_resolution_id()
        || snapshot.persisted_terminal_standing_id != terminal.standing_id()
        || snapshot.target_process_context_id.is_empty()
    {
        return Err(RestartRefusalV2::MalformedOrSplicedEvidence);
    }

    let matching_custody = snapshot
        .custody_observations
        .iter()
        .filter(|observation| {
            observation.occurrence_id == root.occurrence_id()
                && observation.physical_store_generation == root.physical_store_generation()
                && observation.root_binding_id == *root.binding_id()
                && observation.binding_id == *terminal.binding_id()
                && observation.key_generation == terminal.key_generation()
                && observation.process_context_id == snapshot.target_process_context_id
        })
        .count();
    match matching_custody {
        0 => return Err(RestartRefusalV2::TerminalCustodyAbsent),
        1 => {}
        _ => return Err(RestartRefusalV2::MalformedOrSplicedEvidence),
    }
    derived_route(&snapshot.lineage)
}

fn reconstruct(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<(ReconstructedTerminalSignerCapabilityV1, RestartResultV2), RestartRefusalV2> {
    let route = verify_snapshot(snapshot)?;
    let root = snapshot.lineage.root();
    let terminal = snapshot.lineage.terminal_binding();
    let result = match route {
        VerifiedRestartRouteV1::Initial => RestartResultV2::InitialCapabilityReconstructed,
        VerifiedRestartRouteV1::NormalTerminal => {
            RestartResultV2::NormalTerminalCapabilityReconstructed
        }
        VerifiedRestartRouteV1::RestoreTerminal => {
            RestartResultV2::RestoreTerminalCapabilityReconstructed
        }
        VerifiedRestartRouteV1::RecoveryTerminal => {
            RestartResultV2::RecoveryTerminalCapabilityReconstructed
        }
    };
    Ok((
        ReconstructedTerminalSignerCapabilityV1 {
            root_binding_id: root.binding_id().clone(),
            terminal_binding_id: terminal.binding_id().clone(),
            terminal_key_generation: terminal.key_generation().to_owned(),
            process_context_id: snapshot.target_process_context_id.clone(),
            route,
        },
        result,
    ))
}

/// SG-N-29/NRP-11/RPA-11/RPA-12 closed terminal correspondence outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalSignerRestartCorrespondenceV1 {
    RestartReconstructsCapabilityCompleteDurableAuthorityPlusMatchingCustodyItVerified,
    TerminalIterativeRestartVerified,
    TerminalMixedRestartInversionVerified,
    HistoricalTerminalCustodyBoundaryVerified,
}

/// SG-N-29's sole capability-bearing constructor.
pub(crate) fn construct_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<ReconstructedTerminalSignerCapabilityV1, RestartRefusalV2> {
    reconstruct(snapshot).map(|(capability, _)| capability)
}

pub(crate) fn verify_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus(
    snapshot: &CompleteSignerRestartSnapshotV1,
    capability: &ReconstructedTerminalSignerCapabilityV1,
) -> Result<TerminalSignerRestartCorrespondenceV1, RestartRefusalV2> {
    let (expected, _) = reconstruct(snapshot)?;
    if expected.root_binding_id != capability.root_binding_id
        || expected.terminal_binding_id != capability.terminal_binding_id
        || expected.terminal_key_generation != capability.terminal_key_generation
        || expected.process_context_id != capability.process_context_id
        || expected.route != capability.route
    {
        return Err(RestartRefusalV2::MalformedOrSplicedEvidence);
    }
    Ok(TerminalSignerRestartCorrespondenceV1::RestartReconstructsCapabilityCompleteDurableAuthorityPlusMatchingCustodyItVerified)
}

/// SG-N-30's bounded local process/custody observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignerProcessCustodyObservationV1 {
    TwoProcessAliasCopiedStoreKeyForkChildNamespaceCrossVerified {
        terminal_binding_id: Sha256Digest,
        observed_process_context_id: String,
    },
}

pub(crate) fn construct_sg_n_30_two_process_alias_copied_store_key_fork(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<SignerProcessCustodyObservationV1, RestartRefusalV2> {
    verify_snapshot(snapshot)?;
    Ok(SignerProcessCustodyObservationV1::TwoProcessAliasCopiedStoreKeyForkChildNamespaceCrossVerified {
        terminal_binding_id: snapshot.lineage.terminal_binding().binding_id().clone(),
        observed_process_context_id: snapshot.target_process_context_id.clone(),
    })
}

pub(crate) fn verify_sg_n_30_two_process_alias_copied_store_key_fork(
    snapshot: &CompleteSignerRestartSnapshotV1,
    observation: &SignerProcessCustodyObservationV1,
) -> Result<SignerProcessCustodyObservationV1, RestartRefusalV2> {
    let expected = construct_sg_n_30_two_process_alias_copied_store_key_fork(snapshot)?;
    (observation == &expected)
        .then_some(expected)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

/// FRT-01 through FRT-18 theorem/runtime correspondence witnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalRestartCorrespondenceV1 {
    Frt01CutOrderingVerified,
    Frt02CutRootedAssociationVerified,
    Frt03CutRecoveryPolicyVerified,
    Frt11SuccessorRestartInversionVerified,
    Frt13RecoveryAuthorityInversionVerified,
    Frt15PersistedResolutionAssociationVerified,
    Frt18GovernedCrossingsNonLaunderingVerified,
}

/// Route-specific cut-order input for FRT-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuccessorCutRouteV1 {
    Normal,
    Recovery,
}

pub(crate) fn construct_frt_01_cut_ordering(
    route: SuccessorCutRouteV1,
    cuts: SuccessorTraceCutsV2,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    match route {
        SuccessorCutRouteV1::Normal => {
            construct_normal_successor_trace_cut_order_correspondence(cuts).map(|_| ())
        }
        SuccessorCutRouteV1::Recovery => {
            construct_recovery_successor_trace_cut_order_correspondence(cuts).map(|_| ())
        }
    }
    .map_err(|_| RestartRefusalV2::MalformedOrSplicedEvidence)?;
    Ok(FinalRestartCorrespondenceV1::Frt01CutOrderingVerified)
}

pub(crate) fn verify_frt_01_cut_ordering(
    route: SuccessorCutRouteV1,
    cuts: SuccessorTraceCutsV2,
    value: FinalRestartCorrespondenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_frt_01_cut_ordering(route, cuts)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

pub(crate) fn construct_frt_02_cut_rooted_association(
    lineage: &RootedCurrentBindingLineageV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    lineage.verify_complete().map_err(map_lineage_refusal)?;
    verify_sb_03_evolving_current_binding(lineage.root(), lineage.terminal_binding())
        .map_err(|_| RestartRefusalV2::MalformedOrSplicedEvidence)?;
    Ok(FinalRestartCorrespondenceV1::Frt02CutRootedAssociationVerified)
}

pub(crate) fn verify_frt_02_cut_rooted_association(
    lineage: &RootedCurrentBindingLineageV1,
    value: FinalRestartCorrespondenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_frt_02_cut_rooted_association(lineage)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

pub(crate) fn construct_frt_03_cut_recovery_policy(
    lineage: &RootedCurrentBindingLineageV1,
    expected_policy_id: &str,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    lineage.verify_complete().map_err(map_lineage_refusal)?;
    if !matches!(
        lineage.edges().last(),
        Some(CurrentBindingSuccessionV1::Recovery { .. })
    ) || lineage.terminal_binding().policy_id() != expected_policy_id
    {
        return Err(RestartRefusalV2::RecoveryResolverRejected);
    }
    Ok(FinalRestartCorrespondenceV1::Frt03CutRecoveryPolicyVerified)
}

pub(crate) fn verify_frt_03_cut_recovery_policy(
    lineage: &RootedCurrentBindingLineageV1,
    expected_policy_id: &str,
    value: FinalRestartCorrespondenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_frt_03_cut_recovery_policy(lineage, expected_policy_id)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::RecoveryResolverRejected)
}

pub(crate) fn construct_frt_04_recovery_resolver_refusal() -> RestartRefusalV2 {
    RestartRefusalV2::RecoveryResolverRejected
}

pub(crate) fn verify_frt_04_recovery_resolver_refusal(
    refusal: RestartRefusalV2,
) -> Result<RestartRefusalV2, RestartRefusalV2> {
    (refusal == RestartRefusalV2::RecoveryResolverRejected)
        .then_some(refusal)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

/// Exact pending state vocabulary; it cannot represent a completed successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingSignerRestartStateV1 {
    Normal {
        predecessor: CurrentSignerGenerationBindingV1,
        pending_transition_id: String,
    },
    Restore {
        historical_predecessor_binding_id: Sha256Digest,
        pending_transition_id: String,
    },
    Recovery {
        displaced_predecessor_binding_id: Sha256Digest,
        pending_transition_id: String,
    },
    Malformed,
}

pub(crate) fn construct_frt_05_pending_normal_restart(
    root: &StoreGenerationSignerRootBindingV1,
    state: &PendingSignerRestartStateV1,
) -> Result<RestartResultV2, RestartRefusalV2> {
    let PendingSignerRestartStateV1::Normal {
        predecessor,
        pending_transition_id,
    } = state
    else {
        return Err(RestartRefusalV2::RouteModeMismatch);
    };
    verify_sb_03_evolving_current_binding(root, predecessor)
        .map_err(|_| RestartRefusalV2::MalformedOrSplicedEvidence)?;
    if pending_transition_id.is_empty() {
        return Err(RestartRefusalV2::PendingStateMalformed);
    }
    Ok(RestartResultV2::PendingNormalPredecessorRetained)
}

pub(crate) fn verify_frt_05_pending_normal_restart(
    root: &StoreGenerationSignerRootBindingV1,
    state: &PendingSignerRestartStateV1,
    result: RestartResultV2,
) -> Result<RestartResultV2, RestartRefusalV2> {
    let expected = construct_frt_05_pending_normal_restart(root, state)?;
    (result == expected)
        .then_some(result)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

/// A durable pending-restore prefix is evidence only.  Ordinary restart does
/// not recreate its external entry authority or any pending signer brand.
pub(crate) fn construct_pending_restore_restart_refusal(
    state: &PendingSignerRestartStateV1,
) -> RestartRefusalV2 {
    match state {
        PendingSignerRestartStateV1::Restore {
            historical_predecessor_binding_id: _,
            pending_transition_id,
        } if !pending_transition_id.is_empty() => RestartRefusalV2::RestoreSuccessorQuarantined,
        _ => RestartRefusalV2::PendingStateMalformed,
    }
}

pub(crate) fn verify_pending_restore_restart_refusal(
    state: &PendingSignerRestartStateV1,
    refusal: RestartRefusalV2,
) -> Result<RestartRefusalV2, RestartRefusalV2> {
    let expected = construct_pending_restore_restart_refusal(state);
    (refusal == expected)
        .then_some(refusal)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

pub(crate) fn construct_frt_06_pending_recovery_restart(
    state: &PendingSignerRestartStateV1,
) -> RestartRefusalV2 {
    match state {
        PendingSignerRestartStateV1::Recovery {
            displaced_predecessor_binding_id: _,
            pending_transition_id,
        } if !pending_transition_id.is_empty() => RestartRefusalV2::PendingRecoveryNoCurrentSigner,
        _ => RestartRefusalV2::PendingStateMalformed,
    }
}

pub(crate) fn verify_frt_06_pending_recovery_restart(
    state: &PendingSignerRestartStateV1,
    refusal: RestartRefusalV2,
) -> Result<RestartRefusalV2, RestartRefusalV2> {
    let expected = construct_frt_06_pending_recovery_restart(state);
    (refusal == expected)
        .then_some(refusal)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

pub(crate) fn construct_frt_07_pending_malformed_refusal() -> RestartRefusalV2 {
    RestartRefusalV2::PendingStateMalformed
}

pub(crate) fn verify_frt_07_pending_malformed_refusal(
    state: &PendingSignerRestartStateV1,
) -> Result<RestartRefusalV2, RestartRefusalV2> {
    matches!(state, PendingSignerRestartStateV1::Malformed)
        .then_some(RestartRefusalV2::PendingStateMalformed)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

fn require_route(
    snapshot: &CompleteSignerRestartSnapshotV1,
    required: VerifiedRestartRouteV1,
) -> Result<RestartResultV2, RestartRefusalV2> {
    let (_, result) = reconstruct(snapshot)?;
    (derived_route(&snapshot.lineage)? == required)
        .then_some(result)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn construct_frt_08_completed_normal_indexed_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<RestartResultV2, RestartRefusalV2> {
    require_route(snapshot, VerifiedRestartRouteV1::NormalTerminal)
}

pub(crate) fn verify_frt_08_completed_normal_indexed_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
    result: RestartResultV2,
) -> Result<RestartResultV2, RestartRefusalV2> {
    let expected = construct_frt_08_completed_normal_indexed_restart(snapshot)?;
    (result == expected)
        .then_some(result)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

/// A completed restore reopens only through its exact terminal lineage and
/// fresh target-process custody observation.  Its persisted restore route is
/// not normalized into healthy succession or recovery.
pub(crate) fn construct_completed_restore_indexed_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<RestartResultV2, RestartRefusalV2> {
    require_route(snapshot, VerifiedRestartRouteV1::RestoreTerminal)
}

pub(crate) fn verify_completed_restore_indexed_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
    result: RestartResultV2,
) -> Result<RestartResultV2, RestartRefusalV2> {
    let expected = construct_completed_restore_indexed_restart(snapshot)?;
    (result == expected)
        .then_some(result)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn construct_frt_09_completed_recovery_indexed_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<RestartResultV2, RestartRefusalV2> {
    require_route(snapshot, VerifiedRestartRouteV1::RecoveryTerminal)
}

pub(crate) fn verify_frt_09_completed_recovery_indexed_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
    result: RestartResultV2,
) -> Result<RestartResultV2, RestartRefusalV2> {
    let expected = construct_frt_09_completed_recovery_indexed_restart(snapshot)?;
    (result == expected)
        .then_some(result)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn construct_frt_10_initial_restart_correspondence(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<RestartResultV2, RestartRefusalV2> {
    require_route(snapshot, VerifiedRestartRouteV1::Initial)
}

pub(crate) fn verify_frt_10_initial_restart_correspondence(
    snapshot: &CompleteSignerRestartSnapshotV1,
    result: RestartResultV2,
) -> Result<RestartResultV2, RestartRefusalV2> {
    let expected = construct_frt_10_initial_restart_correspondence(snapshot)?;
    (result == expected)
        .then_some(result)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn construct_frt_11_successor_restart_inversion(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let route = verify_snapshot(snapshot)?;
    if route == VerifiedRestartRouteV1::Initial || snapshot.lineage.edges().last().is_none() {
        return Err(RestartRefusalV2::RouteModeMismatch);
    }
    Ok(FinalRestartCorrespondenceV1::Frt11SuccessorRestartInversionVerified)
}

pub(crate) fn verify_frt_11_successor_restart_inversion(
    snapshot: &CompleteSignerRestartSnapshotV1,
    value: FinalRestartCorrespondenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_frt_11_successor_restart_inversion(snapshot)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn construct_frt_12_initial_successor_disjointness(
    snapshot: &CompleteSignerRestartSnapshotV1,
    claimed_route: VerifiedRestartRouteV1,
) -> Result<VerifiedRestartRouteV1, RestartRefusalV2> {
    let actual = verify_snapshot(snapshot)?;
    (actual == claimed_route)
        .then_some(actual)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn verify_frt_12_initial_successor_disjointness(
    snapshot: &CompleteSignerRestartSnapshotV1,
    claimed_route: VerifiedRestartRouteV1,
) -> Result<VerifiedRestartRouteV1, RestartRefusalV2> {
    construct_frt_12_initial_successor_disjointness(snapshot, claimed_route)
}

pub(crate) fn construct_frt_13_recovery_authority_inversion(
    lineage: &RootedCurrentBindingLineageV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    lineage.verify_complete().map_err(map_lineage_refusal)?;
    if !matches!(
        lineage.edges().last(),
        Some(CurrentBindingSuccessionV1::Recovery { .. })
    ) {
        return Err(RestartRefusalV2::RouteModeMismatch);
    }
    construct_rpa_09_per_edge_authority_retention(lineage).map_err(map_lineage_refusal)?;
    Ok(FinalRestartCorrespondenceV1::Frt13RecoveryAuthorityInversionVerified)
}

pub(crate) fn verify_frt_13_recovery_authority_inversion(
    lineage: &RootedCurrentBindingLineageV1,
    value: FinalRestartCorrespondenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_frt_13_recovery_authority_inversion(lineage)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

/// Deliberately insufficient observation: it has no root/current-binding
/// derivation, complete lineage, or target-local restart correspondence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentnessCustodyOnlyV1 {
    pub(crate) resolver_current_binding_id: Sha256Digest,
    pub(crate) custody_key_generation: String,
}

pub(crate) fn construct_frt_14_currentness_custody_non_sufficiency(
    observation: &CurrentnessCustodyOnlyV1,
) -> RestartRefusalV2 {
    let _ = observation;
    RestartRefusalV2::CurrentnessCustodyInsufficient
}

pub(crate) fn verify_frt_14_currentness_custody_non_sufficiency(
    observation: &CurrentnessCustodyOnlyV1,
    refusal: RestartRefusalV2,
) -> Result<RestartRefusalV2, RestartRefusalV2> {
    let expected = construct_frt_14_currentness_custody_non_sufficiency(observation);
    (refusal == expected)
        .then_some(refusal)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

pub(crate) fn construct_frt_15_persisted_resolution_association(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    verify_snapshot(snapshot)?;
    Ok(FinalRestartCorrespondenceV1::Frt15PersistedResolutionAssociationVerified)
}

pub(crate) fn verify_frt_15_persisted_resolution_association(
    snapshot: &CompleteSignerRestartSnapshotV1,
    value: FinalRestartCorrespondenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_frt_15_persisted_resolution_association(snapshot)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::PersistedResolutionAbsent)
}

/// Named malformed/spliced evidence classes; none is silently skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MalformedRestartEvidenceV1 {
    WrongRoot,
    WrongPhysicalGeneration,
    WrongTransition,
    WrongPolicy,
    WrongStanding,
    WrongResolution,
    DuplicateCompletion,
    Gap,
    Fork,
}

pub(crate) fn construct_frt_16_malformed_spliced_refusal(
    evidence: MalformedRestartEvidenceV1,
) -> RestartRefusalV2 {
    let _ = evidence;
    RestartRefusalV2::MalformedOrSplicedEvidence
}

pub(crate) fn verify_frt_16_malformed_spliced_refusal(
    evidence: MalformedRestartEvidenceV1,
    refusal: RestartRefusalV2,
) -> Result<RestartRefusalV2, RestartRefusalV2> {
    let expected = construct_frt_16_malformed_spliced_refusal(evidence);
    (refusal == expected)
        .then_some(refusal)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

/// Every authority-creating effect is excluded from ordinary restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestartAuthorityCreationAttemptV1 {
    Enroll,
    Grant,
    Rotate,
    Recover,
    Restore,
    Repair,
    MintStanding,
    MintCurrentness,
}

pub(crate) fn construct_frt_17_restart_noncreation(
    attempt: RestartAuthorityCreationAttemptV1,
) -> RestartRefusalV2 {
    let _ = attempt;
    RestartRefusalV2::AuthorityCreationAttempt
}

pub(crate) fn verify_frt_17_restart_noncreation(
    attempt: RestartAuthorityCreationAttemptV1,
    refusal: RestartRefusalV2,
) -> Result<RestartRefusalV2, RestartRefusalV2> {
    let expected = construct_frt_17_restart_noncreation(attempt);
    (refusal == expected)
        .then_some(refusal)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

/// Source-native transport evidence.  Its type intentionally contains no
/// restart capability or target-local authority bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransportedSignerEvidenceV1 {
    pub(crate) transport_identity: String,
    pub(crate) source_root_binding_id: Sha256Digest,
    pub(crate) source_terminal_binding_id: Sha256Digest,
}

pub(crate) fn construct_frt_18_governed_crossings_non_laundering(
    transported: &TransportedSignerEvidenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    if transported.transport_identity.is_empty()
        || transported.source_root_binding_id == transported.source_terminal_binding_id
    {
        return Err(RestartRefusalV2::MalformedOrSplicedEvidence);
    }
    Ok(FinalRestartCorrespondenceV1::Frt18GovernedCrossingsNonLaunderingVerified)
}

pub(crate) fn verify_frt_18_governed_crossings_non_laundering(
    transported: &TransportedSignerEvidenceV1,
    value: FinalRestartCorrespondenceV1,
) -> Result<FinalRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_frt_18_governed_crossings_non_laundering(transported)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::MalformedOrSplicedEvidence)
}

pub(crate) fn construct_nrp_11_terminal_iterative_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<TerminalSignerRestartCorrespondenceV1, RestartRefusalV2> {
    require_route(snapshot, VerifiedRestartRouteV1::NormalTerminal)?;
    if snapshot.lineage.edges().is_empty()
        || snapshot
            .lineage
            .edges()
            .iter()
            .any(|edge| !matches!(edge, CurrentBindingSuccessionV1::Normal { .. }))
    {
        return Err(RestartRefusalV2::RouteModeMismatch);
    }
    Ok(TerminalSignerRestartCorrespondenceV1::TerminalIterativeRestartVerified)
}

pub(crate) fn verify_nrp_11_terminal_iterative_restart(
    snapshot: &CompleteSignerRestartSnapshotV1,
    value: TerminalSignerRestartCorrespondenceV1,
) -> Result<TerminalSignerRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_nrp_11_terminal_iterative_restart(snapshot)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn construct_rpa_11_terminal_mixed_restart_inversion(
    snapshot: &CompleteSignerRestartSnapshotV1,
) -> Result<TerminalSignerRestartCorrespondenceV1, RestartRefusalV2> {
    let route = verify_snapshot(snapshot)?;
    if route == VerifiedRestartRouteV1::Initial
        || !snapshot
            .lineage
            .edges()
            .iter()
            .any(|edge| matches!(edge, CurrentBindingSuccessionV1::Recovery { .. }))
    {
        return Err(RestartRefusalV2::RouteModeMismatch);
    }
    construct_rpa_09_per_edge_authority_retention(&snapshot.lineage)
        .map_err(map_lineage_refusal)?;
    Ok(TerminalSignerRestartCorrespondenceV1::TerminalMixedRestartInversionVerified)
}

pub(crate) fn verify_rpa_11_terminal_mixed_restart_inversion(
    snapshot: &CompleteSignerRestartSnapshotV1,
    value: TerminalSignerRestartCorrespondenceV1,
) -> Result<TerminalSignerRestartCorrespondenceV1, RestartRefusalV2> {
    let expected = construct_rpa_11_terminal_mixed_restart_inversion(snapshot)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::RouteModeMismatch)
}

pub(crate) fn construct_rpa_12_historical_terminal_custody_boundary(
    snapshot: &CompleteSignerRestartSnapshotV1,
    historical_custody: &[TerminalCustodyProofV1],
) -> Result<TerminalSignerRestartCorrespondenceV1, RestartRefusalV2> {
    verify_snapshot(snapshot)?;
    let terminal = snapshot.lineage.terminal_binding();
    if historical_custody.iter().any(|observation| {
        observation.binding_id == *terminal.binding_id()
            || observation.key_generation == terminal.key_generation()
    }) {
        return Err(RestartRefusalV2::MalformedOrSplicedEvidence);
    }
    Ok(TerminalSignerRestartCorrespondenceV1::HistoricalTerminalCustodyBoundaryVerified)
}

pub(crate) fn verify_rpa_12_historical_terminal_custody_boundary(
    snapshot: &CompleteSignerRestartSnapshotV1,
    historical_custody: &[TerminalCustodyProofV1],
    value: TerminalSignerRestartCorrespondenceV1,
) -> Result<TerminalSignerRestartCorrespondenceV1, RestartRefusalV2> {
    let expected =
        construct_rpa_12_historical_terminal_custody_boundary(snapshot, historical_custody)?;
    (value == expected)
        .then_some(value)
        .ok_or(RestartRefusalV2::HistoricalSignerNotCurrent)
}

#[cfg(test)]
mod tests {
    use nq_protocol::sha256_bytes;

    use super::*;
    use crate::store_generation::signer::binding::{
        construct_sb_01_lifecycle_root_identity, construct_sb_02_immutable_root_binding,
        construct_sb_04_initial_binding_derivation,
    };
    use crate::store_generation::signer::lineage::{
        NormalSuccessionInputV1, RecoverySuccessionInputV1, RestoreSuccessionInputV1,
        construct_nrp_01_normal_predecessor, construct_nrp_06_adjacent_normal_succession,
        construct_restore_01_historical_foundation_base_join,
        construct_restore_02_authorization_seals_predecessor_foundation,
        construct_restore_03_lawful_restore_predecessor_provenance,
        construct_restore_04_adjacent_restore_inversion,
        construct_rpa_01_recovery_ledger_base_join,
        construct_rpa_03_lawful_recovery_predecessor_provenance,
        construct_rpa_04_adjacent_recovery_inversion,
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

    fn custody(
        root: &StoreGenerationSignerRootBindingV1,
        binding: &CurrentSignerGenerationBindingV1,
        context: &str,
    ) -> TerminalCustodyProofV1 {
        construct_terminal_custody_proof(
            root,
            binding,
            root.occurrence_id().into(),
            root.physical_store_generation().into(),
            root.binding_id().clone(),
            binding.binding_id().clone(),
            binding.key_generation().into(),
            context.into(),
        )
        .unwrap()
    }

    fn snapshot(
        lineage: RootedCurrentBindingLineageV1,
        custody_observations: Vec<TerminalCustodyProofV1>,
    ) -> CompleteSignerRestartSnapshotV1 {
        let terminal = lineage.terminal_binding();
        let current = terminal.binding_id().clone();
        let resolution = terminal.persisted_resolution_id().into();
        let standing = terminal.standing_id().into();
        construct_complete_signer_restart_snapshot(
            lineage,
            vec![current],
            resolution,
            standing,
            custody_observations,
            "process-b".into(),
        )
    }

    fn append_normal(
        root: &StoreGenerationSignerRootBindingV1,
        lineage: RootedCurrentBindingLineageV1,
        id: u64,
    ) -> RootedCurrentBindingLineageV1 {
        let terminal = lineage.terminal_binding().clone();
        let predecessor = construct_nrp_01_normal_predecessor(
            terminal.clone(),
            terminal.binding_id(),
            terminal.standing_id().into(),
            terminal.key_generation().into(),
            terminal.policy_id().into(),
        )
        .unwrap();
        let edge = construct_nrp_06_adjacent_normal_succession(
            root,
            predecessor,
            NormalSuccessionInputV1 {
                transition_id: format!("normal-{id}"),
                continuity_authorization_id: format!("continuity-{id}"),
                policy_continuity_authorization_id: None,
                continuity_signer_key_generation: terminal.key_generation().into(),
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
                effective_cut: id + 2,
            },
        )
        .unwrap();
        lineage.append(edge).unwrap()
    }

    fn append_recovery(
        root: &StoreGenerationSignerRootBindingV1,
        lineage: RootedCurrentBindingLineageV1,
        id: u64,
    ) -> RootedCurrentBindingLineageV1 {
        let terminal = lineage.terminal_binding().clone();
        let association = construct_rpa_01_recovery_ledger_base_join(
            &terminal,
            format!("condition-{id}"),
            format!("authority-{id}"),
            format!("grant-{id}"),
            terminal.binding_id().clone(),
            format!("recovery-key-{id}"),
            "policy".into(),
        )
        .unwrap();
        let binding_id = terminal.binding_id().clone();
        let predecessor = construct_rpa_03_lawful_recovery_predecessor_provenance(
            terminal,
            &binding_id,
            association,
        )
        .unwrap();
        let edge = construct_rpa_04_adjacent_recovery_inversion(
            root,
            predecessor,
            RecoverySuccessionInputV1 {
                transition_id: format!("recovery-{id}"),
                successor_enrollment_id: format!("recovery-enrollment-{id}"),
                successor_key_generation: format!("recovery-key-{id}"),
                successor_policy_id: "policy".into(),
                successor_standing_id: format!("recovery-standing-{id}"),
                receipt_id: format!("recovery-receipt-{id}"),
                append_id: format!("recovery-append-{id}"),
                resolution_id: format!("recovery-resolution-{id}"),
                effective_cut: id + 2,
            },
        )
        .unwrap();
        lineage.append(edge).unwrap()
    }

    fn append_restore(
        root: &StoreGenerationSignerRootBindingV1,
        lineage: RootedCurrentBindingLineageV1,
        id: u64,
    ) -> RootedCurrentBindingLineageV1 {
        let terminal = lineage.terminal_binding().clone();
        let historical_foundation_id = format!("historical-foundation-{id}");
        let association = construct_restore_01_historical_foundation_base_join(
            &terminal,
            format!("restore-authority-{id}"),
            format!("restore-authorization-{id}"),
            terminal.binding_id().clone(),
            historical_foundation_id.clone(),
            historical_foundation_id.clone(),
            terminal.key_generation().into(),
            terminal.policy_id().into(),
        )
        .unwrap();
        let association =
            construct_restore_02_authorization_seals_predecessor_foundation(&terminal, association)
                .unwrap();
        let binding_id = terminal.binding_id().clone();
        let predecessor = construct_restore_03_lawful_restore_predecessor_provenance(
            terminal.clone(),
            &binding_id,
            association,
        )
        .unwrap();
        let edge = construct_restore_04_adjacent_restore_inversion(
            root,
            predecessor,
            RestoreSuccessionInputV1 {
                transition_id: format!("restore-{id}"),
                restored_foundation_id: historical_foundation_id,
                successor_enrollment_id: format!("restore-enrollment-{id}"),
                successor_key_generation: terminal.key_generation().into(),
                successor_policy_id: terminal.policy_id().into(),
                successor_standing_id: format!("restore-standing-{id}"),
                receipt_id: format!("restore-receipt-{id}"),
                append_id: format!("restore-append-{id}"),
                resolution_id: format!("restore-resolution-{id}"),
                effective_cut: id + 2,
            },
        )
        .unwrap();
        lineage.append(edge).unwrap()
    }

    #[test]
    fn initial_restart_is_exact_and_predecessor_free() {
        let (root, initial) = root_and_initial();
        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        let terminal_custody = custody(&root, lineage.terminal_binding(), "process-b");
        let snapshot = snapshot(lineage, vec![terminal_custody]);
        let capability =
            construct_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus(
                &snapshot,
            )
            .unwrap();
        assert_eq!(capability.route(), VerifiedRestartRouteV1::Initial);
        assert_eq!(
            construct_frt_10_initial_restart_correspondence(&snapshot).unwrap(),
            RestartResultV2::InitialCapabilityReconstructed
        );
        assert_eq!(
            construct_frt_12_initial_successor_disjointness(
                &snapshot,
                VerifiedRestartRouteV1::NormalTerminal,
            ),
            Err(RestartRefusalV2::RouteModeMismatch)
        );
    }

    #[test]
    fn arbitrary_normal_lineage_restarts_only_terminal() {
        let (root, initial) = root_and_initial();
        let mut lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        for id in 1..=6 {
            lineage = append_normal(&root, lineage, id);
        }
        let terminal_id = lineage.terminal_binding().binding_id().clone();
        let terminal_key = lineage.terminal_binding().key_generation().to_owned();
        let terminal_custody = custody(&root, lineage.terminal_binding(), "process-b");
        let snapshot = snapshot(lineage, vec![terminal_custody]);
        let capability =
            construct_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus(
                &snapshot,
            )
            .unwrap();
        assert_eq!(capability.terminal_binding_id(), &terminal_id);
        assert_eq!(capability.terminal_key_generation(), terminal_key);
        assert_eq!(
            construct_nrp_11_terminal_iterative_restart(&snapshot).unwrap(),
            TerminalSignerRestartCorrespondenceV1::TerminalIterativeRestartVerified
        );
    }

    #[test]
    fn mixed_lineage_retains_recovery_and_restarts_terminal() {
        let (root, initial) = root_and_initial();
        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        let lineage = append_recovery(&root, lineage, 1);
        let lineage = append_normal(&root, lineage, 2);
        let lineage = append_recovery(&root, lineage, 3);
        let terminal_custody = custody(&root, lineage.terminal_binding(), "process-b");
        let snapshot = snapshot(lineage, vec![terminal_custody]);
        assert_eq!(
            construct_frt_09_completed_recovery_indexed_restart(&snapshot).unwrap(),
            RestartResultV2::RecoveryTerminalCapabilityReconstructed
        );
        assert_eq!(
            construct_rpa_11_terminal_mixed_restart_inversion(&snapshot).unwrap(),
            TerminalSignerRestartCorrespondenceV1::TerminalMixedRestartInversionVerified
        );
        assert_eq!(
            construct_frt_13_recovery_authority_inversion(&snapshot.lineage).unwrap(),
            FinalRestartCorrespondenceV1::Frt13RecoveryAuthorityInversionVerified
        );
    }

    #[test]
    fn completed_restore_restarts_as_distinct_restore_terminal() {
        let (root, initial) = root_and_initial();
        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        let lineage = append_restore(&root, lineage, 1);
        let terminal_custody = custody(&root, lineage.terminal_binding(), "process-b");
        let snapshot = snapshot(lineage, vec![terminal_custody]);

        let capability =
            construct_sg_n_29_restart_reconstructs_capability_complete_durable_authority_plus(
                &snapshot,
            )
            .unwrap();
        assert_eq!(capability.route(), VerifiedRestartRouteV1::RestoreTerminal);
        assert_eq!(
            construct_completed_restore_indexed_restart(&snapshot).unwrap(),
            RestartResultV2::RestoreTerminalCapabilityReconstructed
        );
        assert_eq!(
            construct_frt_09_completed_recovery_indexed_restart(&snapshot),
            Err(RestartRefusalV2::RouteModeMismatch)
        );
    }

    #[test]
    fn pending_restore_is_evidence_only_and_cannot_reopen_as_current() {
        let state = PendingSignerRestartStateV1::Restore {
            historical_predecessor_binding_id: sha256_bytes(b"historical-terminal"),
            pending_transition_id: "pending-restore".into(),
        };
        let refusal = construct_pending_restore_restart_refusal(&state);
        assert_eq!(refusal, RestartRefusalV2::RestoreSuccessorQuarantined);
        verify_pending_restore_restart_refusal(&state, refusal).unwrap();
        assert_eq!(
            construct_frt_06_pending_recovery_restart(&state),
            RestartRefusalV2::PendingStateMalformed
        );
    }

    #[test]
    fn historical_custody_cannot_replace_missing_terminal_custody() {
        let (root, initial) = root_and_initial();
        let historical = custody(&root, &initial, "process-b");
        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        let lineage = append_normal(&root, lineage, 1);
        let snapshot = snapshot(lineage, vec![historical]);
        assert_eq!(
            construct_frt_08_completed_normal_indexed_restart(&snapshot),
            Err(RestartRefusalV2::TerminalCustodyAbsent)
        );
    }

    #[test]
    fn custody_observed_in_another_process_context_is_not_transported_authority() {
        let (root, initial) = root_and_initial();
        let foreign_process_custody = custody(&root, &initial, "process-a");
        let lineage = RootedCurrentBindingLineageV1::initial(root, initial).unwrap();
        let snapshot = snapshot(lineage, vec![foreign_process_custody]);
        assert_eq!(
            construct_frt_10_initial_restart_correspondence(&snapshot),
            Err(RestartRefusalV2::TerminalCustodyAbsent)
        );
    }

    #[test]
    fn historical_custody_is_ignored_when_exact_terminal_custody_exists() {
        let (root, initial) = root_and_initial();
        let historical = custody(&root, &initial, "process-b");
        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        let lineage = append_recovery(&root, lineage, 1);
        let terminal = custody(&root, lineage.terminal_binding(), "process-b");
        let snapshot = snapshot(lineage, vec![terminal]);
        assert_eq!(
            construct_rpa_12_historical_terminal_custody_boundary(&snapshot, &[historical])
                .unwrap(),
            TerminalSignerRestartCorrespondenceV1::HistoricalTerminalCustodyBoundaryVerified
        );
    }

    #[test]
    fn currentness_and_custody_without_lineage_always_refuse() {
        let observation = CurrentnessCustodyOnlyV1 {
            resolver_current_binding_id: sha256_bytes(b"current"),
            custody_key_generation: "key".into(),
        };
        assert_eq!(
            construct_frt_14_currentness_custody_non_sufficiency(&observation),
            RestartRefusalV2::CurrentnessCustodyInsufficient
        );
    }

    #[test]
    fn candidate_set_must_have_one_exact_terminal() {
        let (root, initial) = root_and_initial();
        let lineage = RootedCurrentBindingLineageV1::initial(root.clone(), initial).unwrap();
        let terminal_custody = custody(&root, lineage.terminal_binding(), "process-b");
        let resolution = lineage.terminal_binding().persisted_resolution_id().into();
        let standing = lineage.terminal_binding().standing_id().into();
        let snapshot = construct_complete_signer_restart_snapshot(
            lineage,
            vec![sha256_bytes(b"candidate-a"), sha256_bytes(b"candidate-b")],
            resolution,
            standing,
            vec![terminal_custody],
            "process-b".into(),
        );
        assert_eq!(
            construct_frt_10_initial_restart_correspondence(&snapshot),
            Err(RestartRefusalV2::ForkedLineage)
        );
    }
}
