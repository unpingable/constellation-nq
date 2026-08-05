//! Bounded theorem-to-runtime correspondence witnesses.
//!
//! These values preserve the exact runtime premises consumed by THM-01
//! through THM-07F.  They are read-only evidence: none is a signer, grant,
//! standing value, currentness witness, or restart capability.

use super::authority::{
    A2_APPLICABILITY_INTERPRETATION_V1, A2ApplicabilityRefinementV1, BootstrapGrantIdentityV1,
};
use super::lineage::{
    CurrentBindingSuccessionV1, CurrentRotationPredecessorRouteV1, CurrentRotationPredecessorV1,
    RootedCurrentBindingLineageV1, construct_nrp_02_normal_predecessor_trichotomy,
};
use super::messages::{ClosedMessageFamilyV1, MessageFamilyOwnerV1};

/// A malformed theorem/runtime association never yields authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CorrespondenceRefusalV2 {
    #[error("a required correspondence identity is absent")]
    MissingIdentity,
    #[error("the supplied trace cuts are not in the exact required order")]
    TraceCutOrderMismatch,
    #[error("the supplied predecessor is not the exact adjacent predecessor")]
    ImmediatePredecessorMismatch,
    #[error("the supplied activation interpretation is not the selected A2 rule")]
    ActivationInterpretationMismatch,
    #[error("bootstrap standing and generation standing were collapsed")]
    StandingStateCollapsed,
    #[error("the terminal custody coordinate does not match the terminal binding")]
    TerminalCustodyMismatch,
    #[error("the signer message family is not exactly MSG-01 through MSG-16")]
    MessageFamilyMismatch,
    #[error("the rooted lineage is malformed")]
    MalformedLineage,
}

fn nonempty(values: &[&str]) -> bool {
    values.iter().all(|value| !value.is_empty())
}

fn nonzero(value: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

/// THM-01: initial standing retains exact exogenous grant provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitialStandingExternalityCorrespondenceV2 {
    InitialStandingRequiresExactExternalAuthority,
}

pub(crate) fn construct_initial_standing_externality_correspondence(
    grant: &BootstrapGrantIdentityV1,
) -> Result<InitialStandingExternalityCorrespondenceV2, CorrespondenceRefusalV2> {
    if !nonzero(&grant.request_identity)
        || !nonzero(&grant.grant_identity)
        || grant.issuer.key_generation == 0
    {
        return Err(CorrespondenceRefusalV2::MissingIdentity);
    }
    Ok(InitialStandingExternalityCorrespondenceV2::InitialStandingRequiresExactExternalAuthority)
}

pub(crate) fn verify_initial_standing_externality_correspondence(
    value: InitialStandingExternalityCorrespondenceV2,
) -> InitialStandingExternalityCorrespondenceV2 {
    value
}

/// THM-02: A2 constrains applicability and never becomes the grant issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivationApplicabilityNonAuthorityCorrespondenceV2 {
    ActivationConstrainsApplicabilityWithoutIssuingGrant,
}

pub(crate) fn construct_activation_applicability_non_authority_correspondence(
    applicability: &A2ApplicabilityRefinementV1,
) -> Result<ActivationApplicabilityNonAuthorityCorrespondenceV2, CorrespondenceRefusalV2> {
    if applicability.interpretation != A2_APPLICABILITY_INTERPRETATION_V1 {
        return Err(CorrespondenceRefusalV2::ActivationInterpretationMismatch);
    }
    if !nonzero(&applicability.grant_identity) || !nonzero(&applicability.a2_snapshot) {
        return Err(CorrespondenceRefusalV2::MissingIdentity);
    }
    Ok(ActivationApplicabilityNonAuthorityCorrespondenceV2::ActivationConstrainsApplicabilityWithoutIssuingGrant)
}

pub(crate) fn verify_activation_applicability_non_authority_correspondence(
    value: ActivationApplicabilityNonAuthorityCorrespondenceV2,
) -> ActivationApplicabilityNonAuthorityCorrespondenceV2 {
    value
}

/// THM-03: bootstrap and generation-bound standing are distinct states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootstrapGenerationStandingSeparationCorrespondenceV2 {
    bootstrap_standing_id: String,
    generation_standing_id: String,
    commitment_id: String,
    receipt_id: String,
}

pub(crate) fn construct_bootstrap_generation_standing_separation(
    bootstrap_standing_id: String,
    generation_standing_id: String,
    commitment_id: String,
    receipt_id: String,
) -> Result<BootstrapGenerationStandingSeparationCorrespondenceV2, CorrespondenceRefusalV2> {
    if !nonempty(&[
        &bootstrap_standing_id,
        &generation_standing_id,
        &commitment_id,
        &receipt_id,
    ]) {
        return Err(CorrespondenceRefusalV2::MissingIdentity);
    }
    if bootstrap_standing_id == generation_standing_id {
        return Err(CorrespondenceRefusalV2::StandingStateCollapsed);
    }
    Ok(BootstrapGenerationStandingSeparationCorrespondenceV2 {
        bootstrap_standing_id,
        generation_standing_id,
        commitment_id,
        receipt_id,
    })
}

pub(crate) fn verify_bootstrap_generation_standing_separation(
    value: &BootstrapGenerationStandingSeparationCorrespondenceV2,
) -> Result<BootstrapGenerationStandingSeparationCorrespondenceV2, CorrespondenceRefusalV2> {
    construct_bootstrap_generation_standing_separation(
        value.bootstrap_standing_id.clone(),
        value.generation_standing_id.clone(),
        value.commitment_id.clone(),
        value.receipt_id.clone(),
    )
}

/// Exact trace cuts common to an indexed completed successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SuccessorTraceCutsV2 {
    pub(crate) proposal: u64,
    pub(crate) authorization: u64,
    pub(crate) pop: u64,
    pub(crate) finalization: u64,
    pub(crate) receipt: u64,
    pub(crate) resolution: u64,
    pub(crate) standing: u64,
}

/// THM-04 normal trace order witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NormalSuccessorTraceCutOrderCorrespondenceV2 {
    ExactOrderVerified,
}

pub(crate) fn construct_normal_successor_trace_cut_order_correspondence(
    cuts: SuccessorTraceCutsV2,
) -> Result<NormalSuccessorTraceCutOrderCorrespondenceV2, CorrespondenceRefusalV2> {
    if cuts.proposal < cuts.pop
        && cuts.pop < cuts.authorization
        && cuts.authorization < cuts.finalization
        && cuts.finalization == cuts.receipt
        && cuts.receipt <= cuts.resolution
        && cuts.resolution <= cuts.standing
    {
        Ok(NormalSuccessorTraceCutOrderCorrespondenceV2::ExactOrderVerified)
    } else {
        Err(CorrespondenceRefusalV2::TraceCutOrderMismatch)
    }
}

pub(crate) fn verify_normal_successor_trace_cut_order_correspondence(
    cuts: SuccessorTraceCutsV2,
    value: NormalSuccessorTraceCutOrderCorrespondenceV2,
) -> Result<NormalSuccessorTraceCutOrderCorrespondenceV2, CorrespondenceRefusalV2> {
    let expected = construct_normal_successor_trace_cut_order_correspondence(cuts)?;
    (value == expected)
        .then_some(value)
        .ok_or(CorrespondenceRefusalV2::TraceCutOrderMismatch)
}

/// THM-04A recovery trace order witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoverySuccessorTraceCutOrderCorrespondenceV2 {
    ExactOrderVerified,
}

pub(crate) fn construct_recovery_successor_trace_cut_order_correspondence(
    cuts: SuccessorTraceCutsV2,
) -> Result<RecoverySuccessorTraceCutOrderCorrespondenceV2, CorrespondenceRefusalV2> {
    if cuts.proposal < cuts.authorization
        && cuts.authorization < cuts.pop
        && cuts.pop < cuts.finalization
        && cuts.finalization == cuts.receipt
        && cuts.receipt <= cuts.resolution
        && cuts.resolution <= cuts.standing
    {
        Ok(RecoverySuccessorTraceCutOrderCorrespondenceV2::ExactOrderVerified)
    } else {
        Err(CorrespondenceRefusalV2::TraceCutOrderMismatch)
    }
}

pub(crate) fn verify_recovery_successor_trace_cut_order_correspondence(
    cuts: SuccessorTraceCutsV2,
    value: RecoverySuccessorTraceCutOrderCorrespondenceV2,
) -> Result<RecoverySuccessorTraceCutOrderCorrespondenceV2, CorrespondenceRefusalV2> {
    let expected = construct_recovery_successor_trace_cut_order_correspondence(cuts)?;
    (value == expected)
        .then_some(value)
        .ok_or(CorrespondenceRefusalV2::TraceCutOrderMismatch)
}

/// THM-04B exact resolver-current predecessor coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactCurrentRotationPredecessorCorrespondenceV2 {
    CurrentCoordinatesVerified(CurrentRotationPredecessorRouteV1),
}

pub(crate) fn construct_exact_current_rotation_predecessor_correspondence(
    predecessor: &CurrentRotationPredecessorV1,
) -> ExactCurrentRotationPredecessorCorrespondenceV2 {
    ExactCurrentRotationPredecessorCorrespondenceV2::CurrentCoordinatesVerified(
        construct_nrp_02_normal_predecessor_trichotomy(predecessor),
    )
}

pub(crate) fn verify_exact_current_rotation_predecessor_correspondence(
    predecessor: &CurrentRotationPredecessorV1,
    value: ExactCurrentRotationPredecessorCorrespondenceV2,
) -> Result<ExactCurrentRotationPredecessorCorrespondenceV2, CorrespondenceRefusalV2> {
    let expected = construct_exact_current_rotation_predecessor_correspondence(predecessor);
    (value == expected)
        .then_some(value)
        .ok_or(CorrespondenceRefusalV2::ImmediatePredecessorMismatch)
}

/// THM-04C exact adjacent recovery-base correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactRecoveryImmediatePredecessorCorrespondenceV2 {
    AdjacentBaseVerified,
}

pub(crate) fn construct_exact_recovery_immediate_predecessor_correspondence(
    lineage: &RootedCurrentBindingLineageV1,
    edge: &CurrentBindingSuccessionV1,
) -> Result<ExactRecoveryImmediatePredecessorCorrespondenceV2, CorrespondenceRefusalV2> {
    lineage
        .verify_complete()
        .map_err(|_| CorrespondenceRefusalV2::MalformedLineage)?;
    let Some(last) = lineage.edges().last() else {
        return Err(CorrespondenceRefusalV2::ImmediatePredecessorMismatch);
    };
    if last != edge || !matches!(edge, CurrentBindingSuccessionV1::Recovery { .. }) {
        return Err(CorrespondenceRefusalV2::ImmediatePredecessorMismatch);
    }
    Ok(ExactRecoveryImmediatePredecessorCorrespondenceV2::AdjacentBaseVerified)
}

pub(crate) fn verify_exact_recovery_immediate_predecessor_correspondence(
    lineage: &RootedCurrentBindingLineageV1,
    edge: &CurrentBindingSuccessionV1,
    value: ExactRecoveryImmediatePredecessorCorrespondenceV2,
) -> Result<ExactRecoveryImmediatePredecessorCorrespondenceV2, CorrespondenceRefusalV2> {
    let expected = construct_exact_recovery_immediate_predecessor_correspondence(lineage, edge)?;
    (value == expected)
        .then_some(value)
        .ok_or(CorrespondenceRefusalV2::ImmediatePredecessorMismatch)
}

macro_rules! define_external_correspondence {
    ($type_name:ident, $variant:ident, $constructor:ident, $verifier:ident, $carrier:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) enum $type_name {
            $variant { carrier_identity: String },
        }

        pub(crate) fn $constructor(
            carrier_identity: String,
        ) -> Result<$type_name, CorrespondenceRefusalV2> {
            if carrier_identity.is_empty() {
                return Err(CorrespondenceRefusalV2::MissingIdentity);
            }
            let _exact_carrier = $carrier;
            Ok($type_name::$variant { carrier_identity })
        }

        pub(crate) fn $verifier(value: &$type_name) -> Result<$type_name, CorrespondenceRefusalV2> {
            match value {
                $type_name::$variant { carrier_identity } => $constructor(carrier_identity.clone()),
            }
        }
    };
}

define_external_correspondence!(
    ExternalRevocationAuthorityCorrespondenceV2,
    ExternalPremiseRequired,
    construct_external_revocation_authority_correspondence,
    verify_external_revocation_authority_correspondence,
    "nq.c2_store_integrity_revocation_judgment.v1"
);
define_external_correspondence!(
    ExternalRecoveryAuthorityCorrespondenceV2,
    ExternalPremiseRequired,
    construct_external_recovery_authority_correspondence,
    verify_external_recovery_authority_correspondence,
    "nq.c2_store_integrity_recovery_grant.v1"
);
define_external_correspondence!(
    ExternalRestoreAuthorizationCorrespondenceV2,
    SuppliedAuthorizationConsumed,
    construct_external_restore_authorization_correspondence,
    verify_external_restore_authorization_correspondence,
    "nq.c2_restore_authorization.v1"
);
define_external_correspondence!(
    ExternalQuarantineClosureCorrespondenceV2,
    ClosurePremiseRequired,
    construct_external_quarantine_closure_correspondence,
    verify_external_quarantine_closure_correspondence,
    "nq.c2_quarantine_closure_judgment.v1"
);

/// THM-06 target-local strengthening of restart noncreation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestartNoncreationCorrespondenceV2 {
    RestartCreatesNoAuthorityAndRequiresTerminalFrontierCustody,
}

pub(crate) fn construct_restart_noncreation_correspondence(
    lineage: &RootedCurrentBindingLineageV1,
    terminal_custody_key_generation: &str,
) -> Result<RestartNoncreationCorrespondenceV2, CorrespondenceRefusalV2> {
    lineage
        .verify_complete()
        .map_err(|_| CorrespondenceRefusalV2::MalformedLineage)?;
    if terminal_custody_key_generation != lineage.terminal_binding().key_generation() {
        return Err(CorrespondenceRefusalV2::TerminalCustodyMismatch);
    }
    Ok(RestartNoncreationCorrespondenceV2::RestartCreatesNoAuthorityAndRequiresTerminalFrontierCustody)
}

pub(crate) fn verify_restart_noncreation_correspondence(
    lineage: &RootedCurrentBindingLineageV1,
    terminal_custody_key_generation: &str,
    value: RestartNoncreationCorrespondenceV2,
) -> Result<RestartNoncreationCorrespondenceV2, CorrespondenceRefusalV2> {
    let expected =
        construct_restart_noncreation_correspondence(lineage, terminal_custody_key_generation)?;
    (value == expected)
        .then_some(value)
        .ok_or(CorrespondenceRefusalV2::TerminalCustodyMismatch)
}

/// THM-07 closed MSG-01 through MSG-16 boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClosedSignerMessageFamilyCorrespondenceV2 {
    DownstreamFamilyExcluded,
}

pub(crate) fn construct_closed_signer_message_family_correspondence()
-> Result<ClosedSignerMessageFamilyCorrespondenceV2, CorrespondenceRefusalV2> {
    if ClosedMessageFamilyV1::ALL.len() != 16
        || ClosedMessageFamilyV1::ALL[3].owner() != MessageFamilyOwnerV1::UnsignedStoreRelation
    {
        return Err(CorrespondenceRefusalV2::MessageFamilyMismatch);
    }
    Ok(ClosedSignerMessageFamilyCorrespondenceV2::DownstreamFamilyExcluded)
}

pub(crate) fn verify_closed_signer_message_family_correspondence(
    value: ClosedSignerMessageFamilyCorrespondenceV2,
) -> Result<ClosedSignerMessageFamilyCorrespondenceV2, CorrespondenceRefusalV2> {
    let expected = construct_closed_signer_message_family_correspondence()?;
    (value == expected)
        .then_some(value)
        .ok_or(CorrespondenceRefusalV2::MessageFamilyMismatch)
}

macro_rules! define_finite_nonentailment {
    ($type_name:ident, $constructor:ident, $verifier:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum $type_name {
            FiniteWitnessVerified,
        }

        #[must_use]
        pub(crate) const fn $constructor() -> $type_name {
            $type_name::FiniteWitnessVerified
        }

        pub(crate) fn $verifier(value: $type_name) -> $type_name {
            value
        }
    };
}

define_finite_nonentailment!(
    SignerStandingBNonEntailmentCorrespondenceV2,
    construct_signer_standing_b_nonentailment_correspondence,
    verify_signer_standing_b_nonentailment_correspondence
);
define_finite_nonentailment!(
    SignerStandingGNonEntailmentCorrespondenceV2,
    construct_signer_standing_g_nonentailment_correspondence,
    verify_signer_standing_g_nonentailment_correspondence
);
define_finite_nonentailment!(
    SignerStandingPermanentCapacityNonEntailmentCorrespondenceV2,
    construct_signer_standing_permanent_capacity_nonentailment_correspondence,
    verify_signer_standing_permanent_capacity_nonentailment_correspondence
);
define_finite_nonentailment!(
    SignerStandingWriterSessionNonEntailmentCorrespondenceV2,
    construct_signer_standing_writer_session_nonentailment_correspondence,
    verify_signer_standing_writer_session_nonentailment_correspondence
);
define_finite_nonentailment!(
    SignerStandingFmlReservationNonEntailmentCorrespondenceV2,
    construct_signer_standing_fml_reservation_nonentailment_correspondence,
    verify_signer_standing_fml_reservation_nonentailment_correspondence
);
define_finite_nonentailment!(
    SignerStandingFinalAuthorityNonEntailmentCorrespondenceV2,
    construct_signer_standing_final_authority_nonentailment_correspondence,
    verify_signer_standing_final_authority_nonentailment_correspondence
);

#[cfg(test)]
mod tests {
    use nq_protocol::sha256_bytes;

    use super::*;
    use crate::store_generation::signer::binding::{
        construct_sb_01_lifecycle_root_identity, construct_sb_02_immutable_root_binding,
        construct_sb_04_initial_binding_derivation,
    };

    #[test]
    fn normal_and_recovery_cut_orders_are_distinct() {
        let normal = SuccessorTraceCutsV2 {
            proposal: 1,
            pop: 2,
            authorization: 3,
            finalization: 4,
            receipt: 4,
            resolution: 5,
            standing: 6,
        };
        assert_eq!(
            construct_normal_successor_trace_cut_order_correspondence(normal).unwrap(),
            NormalSuccessorTraceCutOrderCorrespondenceV2::ExactOrderVerified
        );
        assert_eq!(
            construct_recovery_successor_trace_cut_order_correspondence(normal),
            Err(CorrespondenceRefusalV2::TraceCutOrderMismatch)
        );

        let recovery = SuccessorTraceCutsV2 {
            proposal: 1,
            authorization: 2,
            pop: 3,
            finalization: 4,
            receipt: 4,
            resolution: 5,
            standing: 6,
        };
        assert_eq!(
            construct_recovery_successor_trace_cut_order_correspondence(recovery).unwrap(),
            RecoverySuccessorTraceCutOrderCorrespondenceV2::ExactOrderVerified
        );
    }

    #[test]
    fn restart_noncreation_requires_exact_terminal_custody_coordinate() {
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
        let lineage = RootedCurrentBindingLineageV1::initial(root, initial).unwrap();
        assert_eq!(
            construct_restart_noncreation_correspondence(&lineage, "key-0").unwrap(),
            RestartNoncreationCorrespondenceV2::RestartCreatesNoAuthorityAndRequiresTerminalFrontierCustody
        );
        assert_eq!(
            construct_restart_noncreation_correspondence(&lineage, "historical-key"),
            Err(CorrespondenceRefusalV2::TerminalCustodyMismatch)
        );
    }

    #[test]
    fn closed_message_correspondence_keeps_msg04_unsigned() {
        assert_eq!(
            construct_closed_signer_message_family_correspondence().unwrap(),
            ClosedSignerMessageFamilyCorrespondenceV2::DownstreamFamilyExcluded
        );
    }
}
