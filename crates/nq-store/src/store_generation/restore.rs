//! Exact restore-successor predecessor lineage and quarantine rules.
//!
//! Verification consumes the complete supplied sequence in its authenticated
//! adjacency order. It never sorts, selects a latest cut, or turns a copied
//! database into a physical Store-generation edge.

use std::collections::BTreeSet;

use nq_protocol::Sha256Digest;
use thiserror::Error;

/// Exact durable predecessor tuple repeated by every restore-successor record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RestorePredecessorTupleV1 {
    /// Store occurrence whose physical lineage is being extended.
    pub occurrence: String,
    /// Exact predecessor physical generation.
    pub physical_generation: Sha256Digest,
    /// Exact predecessor B bootstrap identity.
    pub bootstrap: Sha256Digest,
    /// Exact predecessor installation-completion receipt.
    pub completion_receipt: Sha256Digest,
    /// Exact predecessor installation cut.
    pub installation_cut: u64,
    /// Exact Gen4 restore disposition/proof.
    pub restore_disposition: Sha256Digest,
}

/// The six independent durable records that must carry byte-identical
/// predecessor coordinates.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RestoreTupleCarrierKindV1 {
    InstallPolicy,
    GenerationIdentityPreimage,
    Bootstrap,
    InstallationIntent,
    InstallationReceipt,
    ActivePolicy,
}

impl RestoreTupleCarrierKindV1 {
    const ALL: [Self; 6] = [
        Self::InstallPolicy,
        Self::GenerationIdentityPreimage,
        Self::Bootstrap,
        Self::InstallationIntent,
        Self::InstallationReceipt,
        Self::ActivePolicy,
    ];
}

/// One tuple as observed in one of the six exact carriers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreTupleCarrierV1 {
    /// Carrier role.
    pub kind: RestoreTupleCarrierKindV1,
    /// Repeated tuple.
    pub predecessor: RestorePredecessorTupleV1,
    /// Strictly later successor installation cut.
    pub successor_cut: u64,
}

/// Verified six-object equality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePredecessorTupleCorrespondenceV1 {
    predecessor: RestorePredecessorTupleV1,
    successor_cut: u64,
}

impl RestorePredecessorTupleCorrespondenceV1 {
    /// Exact predecessor tuple.
    #[must_use]
    pub const fn predecessor(&self) -> &RestorePredecessorTupleV1 {
        &self.predecessor
    }

    /// Strictly later successor cut.
    #[must_use]
    pub const fn successor_cut(&self) -> u64 {
        self.successor_cut
    }
}

/// One authenticated physical-generation edge in adjacency order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePhysicalLineageEdgeV1 {
    /// Exact predecessor tuple.
    pub predecessor: RestorePredecessorTupleV1,
    /// New successor physical generation.
    pub successor_generation: Sha256Digest,
    /// New successor occurrence (must equal the lineage occurrence).
    pub successor_occurrence: String,
    /// Strictly later successor installation cut.
    pub successor_cut: u64,
    /// Identity of the exact edge record.
    pub edge_identity: Sha256Digest,
}

/// Complete authenticated predecessor lineage ending at one exact terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2RestoreSuccessorLineageV1 {
    genesis_occurrence: String,
    genesis_generation: Sha256Digest,
    edges: Vec<RestorePhysicalLineageEdgeV1>,
    terminal_generation: Sha256Digest,
    terminal_cut: u64,
}

impl C2RestoreSuccessorLineageV1 {
    /// Exact authenticated edges in supplied adjacency order.
    #[must_use]
    pub fn edges(&self) -> &[RestorePhysicalLineageEdgeV1] {
        &self.edges
    }

    /// Unique terminal physical generation.
    #[must_use]
    pub const fn terminal_generation(&self) -> &Sha256Digest {
        &self.terminal_generation
    }
}

/// Refusal-total complete-lineage classifications.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum C2RestoreLineageRefusalV1 {
    /// Missing or substituted authenticated edge.
    #[error("restore lineage is absent, substituted, or incomplete")]
    AbsentSubstitutedOrGapped,
    /// A physical identity or occurrence belongs to another lineage.
    #[error("restore lineage contains a wrong occurrence or physical generation")]
    WrongOrCopiedIdentity,
    /// Multiple edges, cycles, forks, or duplicate edge identities exist.
    #[error("restore lineage is forked, cyclic, or duplicated")]
    ForkCycleOrDuplicate,
    /// A successor cut is not strictly greater than its predecessor.
    #[error("restore successor cut is not strictly greater")]
    SameOrRegressedCut,
    /// Claimed predecessor relation has zero or multiple exact edges.
    #[error("claimed restore predecessor relation does not have exactly one edge")]
    ClaimedEdgeCardinality,
    /// The complete input contains malformed or unknown material.
    #[error("complete restore lineage contains malformed or unknown material")]
    UnknownOrFilteredMaterial,
}

/// Separate axis-substitution refusal.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum C2RestoreIdentityAxisRefusalV1 {
    /// Occurrence, generation, policy succession, copy and successor axes were
    /// collapsed or substituted.
    #[error("restore occurrence/generation/policy/copy/successor axis substitution")]
    AxisSubstitution,
}

/// Pure read-only inspection of a lawful terminal historical predecessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2RestoreTerminalPredecessorInspectionV1 {
    /// Exact historical terminal generation.
    pub terminal_generation: Sha256Digest,
    /// Exact terminal cut.
    pub terminal_cut: u64,
    /// Explicitly false: inspection constructs no successor.
    pub successor_constructed: bool,
}

/// REC-12: verify six carrier roles, byte-equal tuples, and one later cut.
pub fn construct_rec_12_restore_tuple_correspondence(
    carriers: &[RestoreTupleCarrierV1],
) -> Result<RestorePredecessorTupleCorrespondenceV1, C2RestoreLineageRefusalV1> {
    verify_rec_12_restore_tuple_correspondence(carriers)
}

/// REC-12 verifier.
pub fn verify_rec_12_restore_tuple_correspondence(
    carriers: &[RestoreTupleCarrierV1],
) -> Result<RestorePredecessorTupleCorrespondenceV1, C2RestoreLineageRefusalV1> {
    if carriers.len() != RestoreTupleCarrierKindV1::ALL.len() {
        return Err(C2RestoreLineageRefusalV1::AbsentSubstitutedOrGapped);
    }
    let first = &carriers[0];
    let observed: BTreeSet<_> = carriers.iter().map(|carrier| carrier.kind).collect();
    let expected: BTreeSet<_> = RestoreTupleCarrierKindV1::ALL.into_iter().collect();
    if observed != expected
        || carriers.iter().any(|carrier| {
            carrier.predecessor != first.predecessor || carrier.successor_cut != first.successor_cut
        })
        || first.successor_cut <= first.predecessor.installation_cut
    {
        return Err(C2RestoreLineageRefusalV1::SameOrRegressedCut);
    }
    Ok(RestorePredecessorTupleCorrespondenceV1 {
        predecessor: first.predecessor.clone(),
        successor_cut: first.successor_cut,
    })
}

fn verify_complete_lineage(
    genesis_occurrence: &str,
    genesis_generation: &Sha256Digest,
    genesis_cut: u64,
    edges: &[RestorePhysicalLineageEdgeV1],
) -> Result<(Sha256Digest, u64), C2RestoreLineageRefusalV1> {
    if genesis_cut == 0 {
        return Err(C2RestoreLineageRefusalV1::UnknownOrFilteredMaterial);
    }
    let mut terminal = genesis_generation.clone();
    let mut terminal_cut = genesis_cut;
    let mut seen_generations = BTreeSet::from([genesis_generation.clone()]);
    let mut seen_edges = BTreeSet::new();
    for edge in edges {
        if edge.predecessor.occurrence.as_str() != genesis_occurrence
            || edge.successor_occurrence.as_str() != genesis_occurrence
            || edge.predecessor.physical_generation != terminal
        {
            return Err(C2RestoreLineageRefusalV1::WrongOrCopiedIdentity);
        }
        if edge.predecessor.installation_cut != terminal_cut || edge.successor_cut <= terminal_cut {
            return Err(C2RestoreLineageRefusalV1::SameOrRegressedCut);
        }
        if !seen_edges.insert(edge.edge_identity.clone())
            || !seen_generations.insert(edge.successor_generation.clone())
        {
            return Err(C2RestoreLineageRefusalV1::ForkCycleOrDuplicate);
        }
        terminal = edge.successor_generation.clone();
        terminal_cut = edge.successor_cut;
    }
    Ok((terminal, terminal_cut))
}

/// WU-11 builds one complete supplied lineage without sorting or inference.
pub fn construct_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(
    genesis_occurrence: String,
    genesis_generation: Sha256Digest,
    genesis_cut: u64,
    edges: Vec<RestorePhysicalLineageEdgeV1>,
) -> Result<C2RestoreSuccessorLineageV1, C2RestoreLineageRefusalV1> {
    let (terminal_generation, terminal_cut) = verify_complete_lineage(
        &genesis_occurrence,
        &genesis_generation,
        genesis_cut,
        &edges,
    )?;
    Ok(C2RestoreSuccessorLineageV1 {
        genesis_occurrence,
        genesis_generation,
        edges,
        terminal_generation,
        terminal_cut,
    })
}

/// WU-11 verifier recomputes adjacency from the exact preserved order.
pub fn verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(
    lineage: &C2RestoreSuccessorLineageV1,
) -> Result<(), C2RestoreLineageRefusalV1> {
    let (terminal, cut) = verify_complete_lineage(
        &lineage.genesis_occurrence,
        &lineage.genesis_generation,
        lineage.edges.first().map_or(lineage.terminal_cut, |edge| {
            edge.predecessor.installation_cut
        }),
        &lineage.edges,
    )?;
    if terminal != lineage.terminal_generation || cut != lineage.terminal_cut {
        return Err(C2RestoreLineageRefusalV1::UnknownOrFilteredMaterial);
    }
    Ok(())
}

/// N-33 exact refusal verifier for a claimed successor edge.
pub fn verify_n_33_complete_lineage_refusal(
    lineage: &C2RestoreSuccessorLineageV1,
    claimed_predecessor: &Sha256Digest,
    claimed_successor: &Sha256Digest,
) -> Result<(), C2RestoreLineageRefusalV1> {
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(lineage)?;
    let count = lineage
        .edges
        .iter()
        .filter(|edge| {
            &edge.predecessor.physical_generation == claimed_predecessor
                && &edge.successor_generation == claimed_successor
        })
        .count();
    if count != 1 {
        return Err(C2RestoreLineageRefusalV1::ClaimedEdgeCardinality);
    }
    Ok(())
}

/// AM-05 constructor alias over the same complete-lineage law.
pub fn construct_am_05_crosswalk_am_charter_durable_restore_successor_predecessor(
    genesis_occurrence: String,
    genesis_generation: Sha256Digest,
    genesis_cut: u64,
    edges: Vec<RestorePhysicalLineageEdgeV1>,
) -> Result<C2RestoreSuccessorLineageV1, C2RestoreLineageRefusalV1> {
    construct_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(
        genesis_occurrence,
        genesis_generation,
        genesis_cut,
        edges,
    )
}

/// AM-05 verifier alias.
pub fn verify_am_05_crosswalk_am_charter_durable_restore_successor_predecessor(
    lineage: &C2RestoreSuccessorLineageV1,
) -> Result<(), C2RestoreLineageRefusalV1> {
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(lineage)
}

/// RR-11 constructor requires the same six-object tuple and exact edge.
pub fn construct_rr_11_restore_successor_lineage(
    carriers: &[RestoreTupleCarrierV1],
    lineage: C2RestoreSuccessorLineageV1,
) -> Result<C2RestoreSuccessorLineageV1, C2RestoreLineageRefusalV1> {
    let tuple = verify_rec_12_restore_tuple_correspondence(carriers)?;
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(&lineage)?;
    let Some(last) = lineage.edges.last() else {
        return Err(C2RestoreLineageRefusalV1::ClaimedEdgeCardinality);
    };
    if last.predecessor != tuple.predecessor || last.successor_cut != tuple.successor_cut {
        return Err(C2RestoreLineageRefusalV1::AbsentSubstitutedOrGapped);
    }
    Ok(lineage)
}

/// RR-11 six-object verifier.
pub fn verify_rr_11_six_object_predecessor_correspondence(
    carriers: &[RestoreTupleCarrierV1],
    lineage: &C2RestoreSuccessorLineageV1,
) -> Result<(), C2RestoreLineageRefusalV1> {
    let tuple = verify_rec_12_restore_tuple_correspondence(carriers)?;
    let last = lineage
        .edges
        .last()
        .ok_or(C2RestoreLineageRefusalV1::ClaimedEdgeCardinality)?;
    if last.predecessor != tuple.predecessor || last.successor_cut != tuple.successor_cut {
        return Err(C2RestoreLineageRefusalV1::AbsentSubstitutedOrGapped);
    }
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(lineage)
}

/// RR-12 rejects any non-exact complete supplied lineage.
pub fn verify_rr_12_complete_supplied_physical_lineage(
    lineage: &C2RestoreSuccessorLineageV1,
) -> Result<(), C2RestoreLineageRefusalV1> {
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(lineage)
}

/// RR-13 read-only terminal inspection constructs no successor authority.
pub fn inspect_rr_13_terminal_predecessor(
    lineage: &C2RestoreSuccessorLineageV1,
) -> Result<C2RestoreTerminalPredecessorInspectionV1, C2RestoreLineageRefusalV1> {
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(lineage)?;
    Ok(C2RestoreTerminalPredecessorInspectionV1 {
        terminal_generation: lineage.terminal_generation.clone(),
        terminal_cut: lineage.terminal_cut,
        successor_constructed: false,
    })
}

/// RR-13 verifier preserves historical-only status.
pub fn verify_rr_13_read_only_terminal_predecessor(
    inspection: &C2RestoreTerminalPredecessorInspectionV1,
) -> Result<(), C2RestoreLineageRefusalV1> {
    if inspection.successor_constructed || inspection.terminal_cut == 0 {
        return Err(C2RestoreLineageRefusalV1::UnknownOrFilteredMaterial);
    }
    Ok(())
}

/// RR-14 creates a witness only when all identity axes remain distinct.
pub fn construct_rr_14_identity_axis_separation(
    occurrence: &str,
    predecessor_generation: &Sha256Digest,
    successor_generation: &Sha256Digest,
    active_policy: &Sha256Digest,
    copied_database_identity: &Sha256Digest,
) -> Result<(), C2RestoreIdentityAxisRefusalV1> {
    let axes = BTreeSet::from([
        occurrence.to_owned(),
        predecessor_generation.to_string(),
        successor_generation.to_string(),
        active_policy.to_string(),
        copied_database_identity.to_string(),
    ]);
    if axes.len() != 5 {
        return Err(C2RestoreIdentityAxisRefusalV1::AxisSubstitution);
    }
    Ok(())
}

/// RR-14 verifier alias.
pub fn verify_rr_14_occurrence_generation_policy_and_successor_axes(
    occurrence: &str,
    predecessor_generation: &Sha256Digest,
    successor_generation: &Sha256Digest,
    active_policy: &Sha256Digest,
    copied_database_identity: &Sha256Digest,
) -> Result<(), C2RestoreIdentityAxisRefusalV1> {
    construct_rr_14_identity_axis_separation(
        occurrence,
        predecessor_generation,
        successor_generation,
        active_policy,
        copied_database_identity,
    )
}

/// SEAM-07 requires the same exact lineage; database-only material cannot
/// satisfy this constructor because it has no edge evidence.
pub fn construct_seam_07_immutable_seam_backup_restore_current_backup_restore(
    lineage: C2RestoreSuccessorLineageV1,
) -> Result<C2RestoreSuccessorLineageV1, C2RestoreLineageRefusalV1> {
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(&lineage)?;
    if lineage.edges.is_empty() {
        return Err(C2RestoreLineageRefusalV1::ClaimedEdgeCardinality);
    }
    Ok(lineage)
}

/// SEAM-07 verifier alias.
pub fn verify_seam_07_immutable_seam_backup_restore_current_backup_restore(
    lineage: &C2RestoreSuccessorLineageV1,
) -> Result<(), C2RestoreLineageRefusalV1> {
    if lineage.edges.is_empty() {
        return Err(C2RestoreLineageRefusalV1::ClaimedEdgeCardinality);
    }
    verify_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(lineage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn tuple() -> RestorePredecessorTupleV1 {
        RestorePredecessorTupleV1 {
            occurrence: "occurrence-1".into(),
            physical_generation: digest('2'),
            bootstrap: digest('3'),
            completion_receipt: digest('4'),
            installation_cut: 10,
            restore_disposition: digest('5'),
        }
    }

    #[test]
    fn six_objects_must_repeat_one_exact_later_tuple() {
        let carriers: Vec<_> = RestoreTupleCarrierKindV1::ALL
            .into_iter()
            .map(|kind| RestoreTupleCarrierV1 {
                kind,
                predecessor: tuple(),
                successor_cut: 11,
            })
            .collect();
        assert!(verify_rec_12_restore_tuple_correspondence(&carriers).is_ok());
        let mut spliced = carriers;
        spliced[3].predecessor.bootstrap = digest('9');
        assert!(verify_rec_12_restore_tuple_correspondence(&spliced).is_err());
    }

    #[test]
    fn complete_lineage_is_adjacency_derived_not_sorted() {
        let edge = RestorePhysicalLineageEdgeV1 {
            predecessor: tuple(),
            successor_generation: digest('6'),
            successor_occurrence: "occurrence-1".into(),
            successor_cut: 11,
            edge_identity: digest('7'),
        };
        let lineage = construct_wu_11_immutable_wu_restore_successor_lineage_quarantine_restore(
            "occurrence-1".into(),
            digest('2'),
            10,
            vec![edge],
        )
        .unwrap();
        assert_eq!(lineage.terminal_generation(), &digest('6'));
        let inspection = inspect_rr_13_terminal_predecessor(&lineage).unwrap();
        assert!(!inspection.successor_constructed);
    }
}
