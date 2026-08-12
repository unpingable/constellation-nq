//! Store-owned live C2 signer authority and restart/reopen boundary.
//!
//! This module is the process-local root of C2 authority.  Durable records,
//! digests, filesystem names, and manifest bytes remain evidence.  The only
//! values in this module that can participate in live signer standing are
//! minted inside a Store-owned operation after one exact Store snapshot and
//! the current process/runtime have been verified.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::marker::PhantomData;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::OnceLock;

use chrono::Utc;
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rusqlite::{Transaction, TransactionBehavior, params};
use rustix::fs::{AtFlags, Mode, OFlags, openat, statat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[cfg(test)]
fn source_io_test_precursor_selected_v1(cut: &'static str) -> bool {
    super::source_io_crash_test_support::selected_precursor_v1(cut)
}

#[cfg(not(test))]
const fn source_io_test_precursor_selected_v1(_cut: &'static str) -> bool {
    false
}

use super::candidate_qualification::StoreVerifiedCandidateCertificateV1;
use super::install::{
    C2InstallationCrashObserverV1, C2LiveInstallationRefusalV1, NoC2InstallationCrashV1,
    allocate_live_c2_fixed_files_v1,
};
use super::lock::{
    C2StoreGenerationLockErrorV1, C2StoreGenerationLockV1,
    construct_wu_04_immutable_wu_local_lock_flock_process_registry,
    finalize_provisional_generation_lock_v1,
    verify_wu_04_immutable_wu_local_lock_flock_process_registry,
};
use super::records::{
    A2ChainRootIdentityV1, C2InstallAuthorityTupleV1, C2InstallationModeV1,
    C2InstalledCarrierGeometryV1, C2StoreGenerationInstallPolicyCalculationInputV1,
    C2StoreGenerationInstallPolicyCalculationV1, C2StoreGenerationInstallPolicyInputV1,
    C2StoreGenerationInstallPolicyV1, C2StructuralCutV1, CanonicalC2RecordV1,
    ControllingActivationIdentityV1, DependencyAnchorIdentityV1, InstallPolicyIdentityV1,
    LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1, QualifiedBackendProfileIdentityV1,
    ResidentIdentityV1, RestoreInstallPredecessorV1, RoleManifestIdentityV1,
    StoreIntegrityKeyEnrollmentV1, StoreOccurrenceIdentityV1, construct_install_policy,
    construct_install_policy_calculation_v1, decode_install_policy_calculation_v1,
};
use super::signer::binding::{
    CurrentSignerBindingModeV1, CurrentSignerGenerationBindingV1,
    StoreGenerationSignerRootBindingV1, construct_sb_01_lifecycle_root_identity,
    construct_sb_02_immutable_root_binding, construct_sb_04_initial_binding_derivation,
    decode_verified_current_signer_generation_binding_v1,
    decode_verified_store_generation_signer_root_binding_v1,
};
use super::signer::coordinator::{
    C2PreparedSignedAppendV1, C2SignerTransitionCoordinator, ConsumedHealthyRotationIntentV1,
    ConsumedInitialProposalPoPV1, ConsumedInstallationBootstrapBatchV1, ConsumedSignedFrameV1,
    ConsumedSuccessorPossessionV1, SignedFrameAppendDispositionV1,
    StoreVerifiedHealthyRotationIntentFactsV1, StoreVerifiedPendingRotationReceiptFactsV1,
    StoreVerifiedSuccessorPossessionFactsV1, append_finalized_signed_frame_projection,
    append_initial_proposal_pop_v1, append_prepared_signed_frame, finalize_prepared_signed_frame,
    reproject_exact_durable_signer_carrier_suffix_v1, verify_durable_signer_carrier_envelope_v1,
    verify_durable_signer_carrier_pair_v1,
};
use super::signer::custody::{
    C2StoreIntegrityCustodian, PreGenerationCustodyCoordinatesV1,
    StoreCustodyPreparationReferenceV1, StoreCustodyProposalFrontierRowV1,
    StoreOrdinarySuccessorCustodyPreparationRequestV1, StoreRecoveryCustodyPreparationBasisV1,
    StoreReopenedGenerationCurrentCustodianV1, StoreVerifiedPreparedCustodyV1,
    VerifiedCustodyProposalFrontierV1, VerifiedFoundationalCustodyV1,
    resolve_store_custody_proposal_frontier_rows_v1,
    verify_stable_foundation_creation_lineage_for_adoption_v1,
};
use super::signer::external_governance::{
    C2ExternalIngressRefusalV1, C2PreparedExternalIngressV1, DurableExternalIngressReceiptV1,
    DurableQuarantineClosureEffectV1, DurableRevocationEffectV1,
    ExternalCarrierVerificationPermitV1, ExternalGovernanceExpectationV1,
    StoreAdoptedActivationSuccessorGrantV1, StoreAdoptedBootstrapGrantV1,
    StoreAdoptedProposalDispositionV1, StoreAdoptedRecoveryGrantV1,
    StoreAdoptedRestoreAuthorizationV1, StoreIntegrityActivationSuccessorGrantRequestV1,
    StoreIntegrityActivationSuccessorGrantV1, StoreIntegrityBootstrapGrantRequestV1,
    StoreIntegrityBootstrapGrantV1, StoreIntegrityProposalDispositionRequestV1,
    StoreIntegrityProposalDispositionV1, StoreIntegrityQuarantineClosureJudgmentV1,
    StoreIntegrityQuarantineClosureRequestV1, StoreIntegrityRecoveryGrantV1,
    StoreIntegrityRecoveryRequestV1, StoreIntegrityRestoreAuthorizationRequestV1,
    StoreIntegrityRestoreAuthorizationV1, StoreIntegrityRevocationJudgmentV1,
    StoreIntegrityRevocationRequestV1, TerminalA1AuthenticityVerifierV1, TerminalA1IssuerClaimV1,
    append_prepared_external_ingress, construct_bootstrap_grant_request,
    construct_recovery_request, load_durable_bootstrap_grant_pair_for_reopen_v1,
    prepare_activation_successor_grant_ingress, prepare_bootstrap_grant_ingress,
    prepare_proposal_disposition_ingress, prepare_recovery_grant_ingress,
    prepare_restore_authorization_ingress, prepare_verified_quarantine_closure_effect_v1,
    prepare_verified_revocation_effect_v1, refuse_if_current_signer_revoked_v1,
    verify_activation_successor_grant_ingress_consumption,
    verify_activation_successor_grant_terminal_a1_signature_scope_policy_cut_request_identity,
    verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity,
    verify_proposal_disposition_terminal_a1_signature_scope_policy_cut_request_identity,
    verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity,
    verify_recovery_grant_ingress_consumption,
    verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity,
    verify_restore_authorization_ingress_consumption,
    verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity,
    verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity,
};
use super::signer::lineage::{
    NormalSuccessionInputV1, RecoverySuccessionInputV1, RestoreSuccessionInputV1,
    construct_nrp_01_normal_predecessor, construct_nrp_06_persistence_ready_normal_current,
    construct_restore_01_historical_foundation_base_join,
    construct_restore_02_authorization_seals_predecessor_foundation,
    construct_restore_03_lawful_restore_predecessor_provenance,
    construct_restore_04_persistence_ready_restore_current,
    construct_rpa_01_recovery_ledger_base_join,
    construct_rpa_02_authorization_seals_predecessor_condition_grant,
    construct_rpa_03_lawful_recovery_predecessor_provenance,
    construct_rpa_04_persistence_ready_recovery_current,
};
use super::signer::manifest::{
    SignerImplementationManifestRefusalV1, StoreAdmittedSignerImplementationManifestV1,
    StoreIntegritySignerImplementationManifestV1, admit_signer_implementation_manifest_v1,
    verify_store_admitted_signer_implementation_manifest_v1,
};
use super::signer::messages::bootstrap_grant_permitted_family_projection_v1;
use super::signer::records::{
    FoundationalAdoptionLineageV1, PersistedFoundationalEnrollmentAdoptionV1,
    PersistedSignerEnrollmentAcceptanceV1, PreGenerationSignerCoordinatesV1,
    PreparedFoundationalEnrollmentAdoptionV1, PreparedSignerEnrollmentAcceptanceV1,
    StoreAcceptedSignerEnrollmentV1, StoreAdoptedFoundationalEnrollmentV1,
    StoreConsumedFoundationalAdoptionProvenanceV1, StoreIntegrityEnrollmentCandidateV1,
    StoreVerifiedDurableSignerEnrollmentV1, VerifiedInitialPossessionRequestV1,
    append_prepared_foundational_enrollment_adoption_v1,
    append_prepared_signer_enrollment_acceptance_v1, construct_sg_rec_05a_candidate,
    construct_verified_initial_possession_request_v1, derive_initial_foundational_enrollment_v1,
    load_verified_durable_enrollment_bridge_v1, load_verified_durable_signer_enrollment_v1,
    pre_generation_scope_identity_v1, prepare_store_consumed_foundational_enrollment_adoption_v1,
    prepare_store_foundational_enrollment_adoption_v1,
    prepare_store_signer_enrollment_acceptance_v1, rewrap_verified_durable_enrollment_bridge_v1,
    seal_store_accepted_signer_enrollment_v1, seal_store_adopted_foundational_enrollment_v1,
    verify_sg_rec_05_accepted_wrapper,
};
use super::signer::result::{LineageRefusalV1, SignerRefusalV2};
use super::signer::terminal::{
    DurableTerminalAppendRefusalV1, DurableTerminalResolutionRefusalV1,
    HealthySuccessorTerminalAppendV1, RecoverySuccessorTerminalAppendV1,
    RestoreSuccessorTerminalAppendV1, StoreVerifiedDurableGenerationCurrentV1,
    append_healthy_successor_terminal_v1, append_recovery_successor_terminal_v1,
    append_restore_successor_terminal_v1, prepare_healthy_successor_terminal_append_v1,
    prepare_recovery_successor_terminal_append_v1, prepare_restore_successor_terminal_append_v1,
    resolve_store_verified_durable_generation_current_v1,
};
use crate::append_extent::{
    C2AppendExtentRefusalV1, C2AppendFrameKindV1, C2CarrierFileFactsV1, C2CarrierPairInputV1,
    C2DurableAppendDispositionV1, C2DurableAppendPairV1, C2InstallationExtentInitializedV1,
    C2ObservedAppendExtentRefusalV1, construct_rec_30_pair_header_correspondence,
    construct_wu_03_immutable_wu_append_extents_b_g_carrier, open_durable_append_pair_v1,
};
use crate::capacity_backend::{
    C2BackendRefusalV1, begin_c2_backend_observation_epoch_v1,
    bind_c2_qualified_backend_profile_v1,
    initialize_durable_append_pair_for_installation_with_observer_v1,
    inspect_c2_backend_preflight_v1, preallocate_n_90_permanent_lock_b_g,
};
use crate::writer_session::{MaintenanceLockGuard, acquire_maintenance_locks};
use crate::{
    CurrentActivationForC2, CurrentActivationResolverInputV1, RuntimeAuthorityRestartSnapshot,
    Store, StoreError, collect_complete_gen4_authority_ledger, logical_state_digest, pragma_i64,
    presented_runtime_authority_set_on_connection, project_current_activation_for_c2,
    runtime_dependency_establishment_receipt_on_connection,
    runtime_dependency_trust_root_on_connection, runtime_migration_receipt_bytes_on_connection,
    sole_genesis_on_connection, validate_runtime_authority_invariants,
};
use nq_runtime_dependency_authority::ControllingActivationSnapshot;

const LIVE_C2_STORE_SNAPSHOT_DOMAIN_V1: &[u8] = b"nq.c2.live_store_snapshot.v1\0";
const LIVE_C2_STORE_INSTANCE_DOMAIN_V1: &[u8] = b"nq.c2.live_store_instance.v1\0";
const LIVE_C2_PROCESS_DOMAIN_V1: &[u8] = b"nq.c2.live_process.v1\0";
const C2_CUSTODY_EMPTY_FRONTIER_DOMAIN_V1: &[u8] = b"nq.c2.custody_proposal_frontier.empty.v1\0";
const C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1: &[u8] = b"nq.c2.custody_proposal_frontier.step.v1\0";
const C2_CUSTODY_PREPARATION_DOMAIN_V1: &[u8] = b"nq.c2.custody_proposal_preparation.identity.v1\0";

fn installation_authorization_precedes_acceptance_v1(
    policy_cut: u64,
    grant_cut: u64,
    accepted_cut: u64,
) -> bool {
    policy_cut == grant_cut && policy_cut < accepted_cut
}

/// Exact restore/recovery lifecycle cuts from the external authorization R.
/// MSG-07 is signed from PendingPossession at R+1; adoption, acceptance,
/// MSG-12, and completed currentness each occupy their own later cut.
fn discontinuity_cut_schedule_v1(entry_cut: u64) -> Option<(u64, u64, u64, u64, u64)> {
    Some((
        entry_cut.checked_add(1)?,
        entry_cut.checked_add(2)?,
        entry_cut.checked_add(3)?,
        entry_cut.checked_add(4)?,
        entry_cut.checked_add(5)?,
    ))
}

fn recovery_status_matches_discontinuity_condition_v1(
    condition: &StoreVerifiedDiscontinuityConditionV1,
    status: C2RecoveryPredecessorStatusV1,
) -> bool {
    matches!(
        (condition, status),
        (
            StoreVerifiedDiscontinuityConditionV1::OrdinaryContinuityUnavailable,
            C2RecoveryPredecessorStatusV1::ActiveLost
        ) | (
            StoreVerifiedDiscontinuityConditionV1::GovernedCurrentSignerRevocation { .. },
            C2RecoveryPredecessorStatusV1::InactiveRevoked
        )
    )
}

fn discontinuity_condition_identity_v1(
    lineage: C2LiveFoundationalLineageV1,
    condition: &StoreVerifiedDiscontinuityConditionV1,
    current_binding_identity: [u8; 32],
) -> Option<[u8; 32]> {
    let route = match lineage {
        C2LiveFoundationalLineageV1::RestoreHistorical => b"restore".as_slice(),
        C2LiveFoundationalLineageV1::RecoveryNewFoundation => b"recovery".as_slice(),
        _ => return None,
    };
    let condition_coordinate = match condition {
        StoreVerifiedDiscontinuityConditionV1::OrdinaryContinuityUnavailable => {
            b"ordinary_current_custody_unavailable".as_slice()
        }
        StoreVerifiedDiscontinuityConditionV1::GovernedCurrentSignerRevocation {
            effect_receipt_identity,
        } => effect_receipt_identity.as_str().as_bytes(),
    };
    Some(digest_fields_bytes(
        b"nq.c2.store_verified_discontinuity_eligibility.identity.v1\0",
        &[route, condition_coordinate, &current_binding_identity],
    ))
}

fn recovery_request_identity_v1(canonical_body_without_identity: &[u8]) -> Sha256Digest {
    sha256_bytes(
        &[
            b"nq.c2.store_integrity_recovery_request.identity.v1\0".as_slice(),
            canonical_body_without_identity,
        ]
        .concat(),
    )
}

/// Closed restart classifier for signer appends after the terminal binding
/// resolution. MSG-08 is an effect of the already-current generation; every
/// other Store-signable route either belongs to bootstrap or opens/continues
/// a lifecycle transition and therefore requires a new complete phase
/// resolution before GenerationCurrent may be reconstructed.
fn append_route_preserves_generation_current_v1(route: &str) -> bool {
    route == "msg08_global_refusal"
}

/// Inert policy selection used only to prepare the exact asynchronous MSG-01
/// request.  These coordinates grant no authority: the unique terminal A1
/// must later sign the exact request, and the final authenticated install
/// policy must repeat the selected mode/calculation/cut before installation.
///
/// The role-manifest coordinate is included because current A2 exposes its
/// generation but not the manifest digest; later policy/grant checks bind the
/// selection.  Signer-scope policy version is the closed v1 constant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::store_generation) struct C2BootstrapOperatorInstallSelectionV1 {
    pub(in crate::store_generation) operator_installation_nonce: String,
    pub(in crate::store_generation) installation_cut: C2StructuralCutV1,
    pub(in crate::store_generation) mode: C2InstallationModeV1,
    pub(in crate::store_generation) restore_predecessor: Option<RestoreInstallPredecessorV1>,
    pub(in crate::store_generation) geometry: C2InstalledCarrierGeometryV1,
    pub(in crate::store_generation) qualified_backend_profile: QualifiedBackendProfileIdentityV1,
    pub(in crate::store_generation) maximum_policy_generations: u32,
    pub(in crate::store_generation) maximum_key_generations: u32,
    pub(in crate::store_generation) predecessor_install_policy: Option<InstallPolicyIdentityV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2BootstrapPreparationIntentV1 {
    role_manifest_identity: Sha256Digest,
    signer_scope_policy_identity: Sha256Digest,
    operator_install_selection: C2BootstrapOperatorInstallSelectionV1,
}

impl C2BootstrapPreparationIntentV1 {
    pub(in crate::store_generation) fn from_operator_install_selection(
        role_manifest_identity: Sha256Digest,
        signer_scope_policy_identity: Sha256Digest,
        operator_install_selection: C2BootstrapOperatorInstallSelectionV1,
    ) -> Result<Self, C2LiveSignerRefusalV1> {
        if operator_install_selection.installation_cut.ledger_position == 0
            || operator_install_selection.installation_cut.ledger_position > 9_007_199_254_740_991
            || [&role_manifest_identity, &signer_scope_policy_identity]
                .into_iter()
                .any(|identity| identity.as_str().ends_with(&"0".repeat(64)))
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(Self {
            role_manifest_identity,
            signer_scope_policy_identity,
            operator_install_selection,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        role_manifest_identity: Sha256Digest,
        signer_scope_policy_identity: Sha256Digest,
        calculation_input: C2StoreGenerationInstallPolicyCalculationInputV1,
    ) -> Result<Self, C2LiveSignerRefusalV1> {
        if calculation_input.backend_identity != LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1 {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Self::from_operator_install_selection(
            role_manifest_identity,
            signer_scope_policy_identity,
            C2BootstrapOperatorInstallSelectionV1 {
                operator_installation_nonce: calculation_input.operator_installation_nonce,
                installation_cut: calculation_input.installation_cut,
                mode: calculation_input.mode,
                restore_predecessor: calculation_input.restore_predecessor,
                geometry: calculation_input.geometry,
                qualified_backend_profile: calculation_input.qualified_backend_profile,
                maximum_policy_generations: calculation_input.maximum_policy_generations,
                maximum_key_generations: calculation_input.maximum_key_generations,
                predecessor_install_policy: calculation_input.predecessor_install_policy,
            },
        )
    }
}

/// Inert durable preparation result exported across the asynchronous A1
/// boundary.  It contains only the canonical request and preparation
/// identity; the descriptor-owning custodian is deliberately dropped before
/// this value is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorePreparedBootstrapGrantRequestV1 {
    preparation_identity: Sha256Digest,
    request: StoreIntegrityBootstrapGrantRequestV1,
}

/// Closed caller-visible description of the discontinuity branch for which a
/// recovery request is being prepared.  The Store independently proves this
/// fact before creating custody or durable request evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2RecoveryPredecessorStatusV1 {
    ActiveLost,
    InactiveRevoked,
}

impl C2RecoveryPredecessorStatusV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveLost => "active_lost",
            Self::InactiveRevoked => "inactive_revoked",
        }
    }
}

/// Inert recovery preparation intent.  It chooses no Store, predecessor,
/// foundation, key, custody object, cut, policy, or authority coordinate.
/// Those are all resolved by the retained Store actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2RecoveryPreparationIntentV1 {
    predecessor_status: C2RecoveryPredecessorStatusV1,
    recovery_transition_identity: Sha256Digest,
    successor_pop_challenge_identity: Sha256Digest,
}

impl C2RecoveryPreparationIntentV1 {
    pub(crate) fn new(
        predecessor_status: C2RecoveryPredecessorStatusV1,
        recovery_transition_identity: Sha256Digest,
        successor_pop_challenge_identity: Sha256Digest,
    ) -> Result<Self, C2LiveSignerRefusalV1> {
        if [
            &recovery_transition_identity,
            &successor_pop_challenge_identity,
        ]
        .into_iter()
        .any(|identity| identity.as_str().ends_with(&"0".repeat(64)))
            || recovery_transition_identity == successor_pop_challenge_identity
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(Self {
            predecessor_status,
            recovery_transition_identity,
            successor_pop_challenge_identity,
        })
    }
}

/// The only value which crosses the asynchronous MSG-15 boundary.  It is
/// canonical request evidence plus its durable preparation identity; the key
/// custodian and discontinuity eligibility are deliberately dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorePreparedRecoveryGrantRequestV1 {
    preparation_identity: Sha256Digest,
    request: StoreIntegrityRecoveryRequestV1,
}

/// Inert caller request for one healthy successor operation.  The identities
/// describe only the proposed transition and PoP challenge; they are not
/// authority and are re-bound to the freshly reopened current predecessor,
/// newly Store-created custody, Store-resolved policy target, and exact
/// MSG-07/06/(conditional 05)/11 sequence before any foundation can be
/// adopted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C2HealthySuccessorIntentV1 {
    transition_identity: Sha256Digest,
    successor_pop_challenge_identity: Sha256Digest,
    transition_cut: u64,
}

impl C2HealthySuccessorIntentV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        transition_identity: Sha256Digest,
        successor_pop_challenge_identity: Sha256Digest,
        transition_cut: u64,
    ) -> Result<Self, C2LiveSignerRefusalV1> {
        if transition_cut == 0
            || [&transition_identity, &successor_pop_challenge_identity]
                .into_iter()
                .any(|identity| identity.as_str().ends_with(&"0".repeat(64)))
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(Self {
            transition_identity,
            successor_pop_challenge_identity,
            transition_cut,
        })
    }
}

/// Store-resolved policy/activation/applicability branch for one healthy
/// successor.  This value is private, inert, and has no raw-parts
/// constructor.  The unchanged constructor derives the exact current triple;
/// the changed constructor consumes one actor-relative Store-adopted MSG-01
/// grant and derives the target triple only from that verified carrier.
struct StoreResolvedHealthySuccessorPolicyTargetV1 {
    predecessor_active_policy_identity: [u8; 32],
    predecessor_activation_identity: [u8; 32],
    predecessor_applicability_identity: [u8; 32],
    target_active_policy_identity: [u8; 32],
    target_activation_identity: [u8; 32],
    target_applicability_identity: [u8; 32],
    required_activation_successor_grant_identity: Option<[u8; 32]>,
}

impl StoreResolvedHealthySuccessorPolicyTargetV1 {
    fn unchanged(current: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>) -> Self {
        let predecessor_active_policy_identity = current.coordinates.active_policy_identity;
        let predecessor_activation_identity = current.coordinates.current_a2_identity;
        let predecessor_applicability_identity =
            current_healthy_rotation_applicability_identity_v1(&current.coordinates);
        Self {
            predecessor_active_policy_identity,
            predecessor_activation_identity,
            predecessor_applicability_identity,
            target_active_policy_identity: predecessor_active_policy_identity,
            target_activation_identity: predecessor_activation_identity,
            target_applicability_identity: predecessor_applicability_identity,
            required_activation_successor_grant_identity: None,
        }
    }

    fn from_store_adopted_activation_successor_grant(
        actor: &StoreC2SnapshotActorV1<'_>,
        current: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        adopted: &StoreAdoptedActivationSuccessorGrantV1,
    ) -> Result<Self, C2LiveTransitionDriverRefusalV1> {
        current.verify_live(actor)?;
        verify_activation_successor_grant_ingress_consumption(actor, adopted)?;
        let carrier = adopted.verified().carrier();
        let predecessor_active_policy_identity = current.coordinates.active_policy_identity;
        let predecessor_activation_identity = current.coordinates.current_a2_identity;
        let predecessor_applicability_identity =
            current_healthy_rotation_applicability_identity_v1(&current.coordinates);
        let carrier_predecessor_policy =
            live_c2_digest_json_field_v1(carrier.field("predecessor_active_policy_identity"))?;
        let carrier_predecessor_activation =
            live_c2_digest_json_field_v1(carrier.field("predecessor_activation_identity"))?;
        let target_active_policy_identity =
            live_c2_digest_json_field_v1(carrier.field("successor_active_policy_identity"))?;
        let target_activation_identity =
            live_c2_digest_json_field_v1(carrier.field("successor_activation_identity"))?;
        let target_applicability_identity = *adopted.verified().carrier_identity().bytes();

        if carrier_predecessor_policy != predecessor_active_policy_identity
            || carrier_predecessor_activation != predecessor_activation_identity
            || (target_active_policy_identity == predecessor_active_policy_identity
                && target_activation_identity == predecessor_activation_identity
                && target_applicability_identity == predecessor_applicability_identity)
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
        }

        Ok(Self {
            predecessor_active_policy_identity,
            predecessor_activation_identity,
            predecessor_applicability_identity,
            target_active_policy_identity,
            target_activation_identity,
            target_applicability_identity,
            required_activation_successor_grant_identity: Some(target_applicability_identity),
        })
    }

    fn verify_for_current(
        &self,
        current: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        let target_changed = self.target_active_policy_identity
            != self.predecessor_active_policy_identity
            || self.target_activation_identity != self.predecessor_activation_identity
            || self.target_applicability_identity != self.predecessor_applicability_identity;
        let branch_shape_is_exact = match self.required_activation_successor_grant_identity {
            None => !target_changed,
            Some(grant_identity) => {
                target_changed && grant_identity == self.target_applicability_identity
            }
        };
        if self.predecessor_active_policy_identity != current.coordinates.active_policy_identity
            || self.predecessor_activation_identity != current.coordinates.current_a2_identity
            || self.predecessor_applicability_identity
                != current_healthy_rotation_applicability_identity_v1(&current.coordinates)
            || !branch_shape_is_exact
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }
}

impl StorePreparedBootstrapGrantRequestV1 {
    #[must_use]
    pub(crate) const fn preparation_identity(&self) -> &Sha256Digest {
        &self.preparation_identity
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &StoreIntegrityBootstrapGrantRequestV1 {
        &self.request
    }
}

impl StorePreparedRecoveryGrantRequestV1 {
    #[must_use]
    pub(crate) const fn preparation_identity(&self) -> &Sha256Digest {
        &self.preparation_identity
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &StoreIntegrityRecoveryRequestV1 {
        &self.request
    }
}

/// Typed fail-closed result surface for live C2 admission and process checks.
///
/// No variant contains an authority-bearing value or a value from which one
/// can be reconstructed.
#[derive(Debug, Error)]
pub(crate) enum C2LiveSignerRefusalV1 {
    #[error("verified external candidate evidence is unavailable")]
    QualifiedCandidateIdentityUnavailable,
    #[error("verified external source-tree evidence is unavailable")]
    SourceTreeIdentityUnavailable,
    #[error("verified external runtime-artifact evidence is unavailable")]
    RuntimeArtifactIdentityUnavailable,
    #[error("verified external signer-manifest evidence is unavailable")]
    QualifiedManifestIdentityUnavailable,
    #[error("an embedded candidate/runtime identity is malformed")]
    MalformedQualifiedIdentity,
    #[error("the running artifact does not match the qualified runtime artifact")]
    RuntimeArtifactMismatch,
    #[error("the Store is not one path-backed schema-v9 C2 candidate")]
    StoreBasisUnavailable,
    #[error("the Store occurrence is absent, ambiguous, or substituted")]
    OccurrenceMismatch,
    #[error("the Store snapshot changed or was substituted")]
    StoreSnapshotMismatch,
    #[error("the live C2 value belongs to another process")]
    PriorProcessAuthority,
    #[error("a live C2 correspondence coordinate was substituted")]
    CorrespondenceMismatch,
    #[error("no completed C2 generation is present")]
    GenerationCurrentAbsent,
    #[error("C2 installation or signer state is a durable incomplete/pending prefix")]
    GenerationCurrentIncomplete,
    #[error("more than one C2 installation, lineage, or current-state candidate exists")]
    GenerationCurrentAmbiguous,
    #[error("completed C2 generation evidence is malformed or internally inconsistent")]
    GenerationCurrentMalformed,
    #[error("the exact current signer has a complete durable revocation effect")]
    CurrentSignerRevoked,
    #[error("durable C2 governance evidence is malformed or internally inconsistent")]
    GenerationCurrentGovernanceMalformed,
    #[error("a live C2 operation encountered Store I/O: {0}")]
    Store(#[from] StoreError),
    #[error("a live C2 runtime measurement failed: {0}")]
    Io(#[from] io::Error),
}

/// Candidate/source/runtime coordinates supplied by the authenticated,
/// qualification-trust-root verifier.
///
/// This value is inert qualification evidence.  Its fields are private, it
/// has no raw-parts constructor, and it cannot itself admit a manifest or
/// construct live signer standing.  Development builds normally do not carry
/// a caller-authored record. Candidate freeze supplies the certificate
/// instance; it does not add another authority constructor.
pub(crate) struct StoreC2QualifiedRuntimeEvidenceV1 {
    qualified_candidate_identity: Sha256Digest,
    source_tree_identity: Sha256Digest,
    expected_runtime_artifact_identity: Sha256Digest,
    qualified_manifest_identity: Sha256Digest,
    qualification_evidence_identity: Sha256Digest,
    candidate_certificate_identity: Sha256Digest,
    qualification_trust_root_identity: Sha256Digest,
    verification_process_id: u32,
}

/// Candidate-bound record after the Store-owned qualification verifier has
/// authenticated its detached evidence/certificate and measured this process.
/// No expected artifact digest is embedded in the executable whose complete
/// bytes it identifies: that would create a self-hash cycle.
pub(crate) struct VerifiedC2ExternalCandidateRuntimeRecordV1 {
    qualified_candidate_identity: Sha256Digest,
    source_tree_identity: Sha256Digest,
    expected_runtime_artifact_identity: Sha256Digest,
    qualified_manifest_identity: Sha256Digest,
    qualification_evidence_identity: Sha256Digest,
    candidate_certificate_identity: Sha256Digest,
    qualification_trust_root_identity: Sha256Digest,
    verification_process_id: u32,
}

impl VerifiedC2ExternalCandidateRuntimeRecordV1 {
    /// Sole production conversion from an authenticated canonical candidate
    /// certificate into the inert coordinate record consumed by Store
    /// admission.  No raw digest tuple enters this seam.
    pub(in crate::store_generation) fn from_authenticated_candidate_certificate(
        certificate: StoreVerifiedCandidateCertificateV1,
    ) -> Self {
        Self {
            qualified_candidate_identity: certificate.qualified_candidate_identity().clone(),
            source_tree_identity: certificate.source_tree_identity().clone(),
            expected_runtime_artifact_identity: certificate.runtime_artifact_identity().clone(),
            qualified_manifest_identity: certificate
                .signer_implementation_manifest_identity()
                .clone(),
            qualification_evidence_identity: certificate.qualification_evidence_identity().clone(),
            candidate_certificate_identity: certificate.certificate_identity().clone(),
            qualification_trust_root_identity: certificate
                .qualification_trust_root_identity()
                .clone(),
            verification_process_id: std::process::id(),
        }
    }
}

impl StoreC2QualifiedRuntimeEvidenceV1 {
    /// Consume only a verifier-owned external qualification result.
    /// Possession of a JSON record or four digests cannot call this seam.
    pub(crate) fn from_verified_external_candidate(
        verified: VerifiedC2ExternalCandidateRuntimeRecordV1,
    ) -> Self {
        Self {
            qualified_candidate_identity: verified.qualified_candidate_identity,
            source_tree_identity: verified.source_tree_identity,
            expected_runtime_artifact_identity: verified.expected_runtime_artifact_identity,
            qualified_manifest_identity: verified.qualified_manifest_identity,
            qualification_evidence_identity: verified.qualification_evidence_identity,
            candidate_certificate_identity: verified.candidate_certificate_identity,
            qualification_trust_root_identity: verified.qualification_trust_root_identity,
            verification_process_id: verified.verification_process_id,
        }
    }

    #[cfg(test)]
    pub(in crate::store_generation) fn for_test(
        qualified_candidate_identity: Sha256Digest,
        source_tree_identity: Sha256Digest,
        expected_runtime_artifact_identity: Sha256Digest,
        qualified_manifest_identity: Sha256Digest,
    ) -> Self {
        Self::from_verified_external_candidate(VerifiedC2ExternalCandidateRuntimeRecordV1 {
            qualified_candidate_identity,
            source_tree_identity,
            expected_runtime_artifact_identity,
            qualified_manifest_identity,
            qualification_evidence_identity: nq_protocol::sha256_bytes(
                b"test-only externally verified candidate record",
            ),
            candidate_certificate_identity: nq_protocol::sha256_bytes(
                b"test-only candidate certificate",
            ),
            qualification_trust_root_identity: nq_protocol::sha256_bytes(
                b"test-only qualification trust root",
            ),
            verification_process_id: std::process::id(),
        })
    }

    fn verify_measured_runtime_artifact(
        &self,
        measured: &Sha256Digest,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        if self.verification_process_id != std::process::id() {
            return Err(C2LiveSignerRefusalV1::PriorProcessAuthority);
        }
        if measured != &self.expected_runtime_artifact_identity {
            return Err(C2LiveSignerRefusalV1::RuntimeArtifactMismatch);
        }
        Ok(())
    }

    fn qualification_binding_identity(&self) -> Sha256Digest {
        digest_fields(
            b"nq.c2.verified_external_candidate_runtime.binding.v1\0",
            &[
                self.qualified_candidate_identity.as_str().as_bytes(),
                self.source_tree_identity.as_str().as_bytes(),
                self.expected_runtime_artifact_identity.as_str().as_bytes(),
                self.qualified_manifest_identity.as_str().as_bytes(),
                self.qualification_evidence_identity.as_str().as_bytes(),
                self.candidate_certificate_identity.as_str().as_bytes(),
                self.qualification_trust_root_identity.as_str().as_bytes(),
            ],
        )
    }
}

/// One exact Store read result retained only for the dynamic extent of a
/// Store-owned live-C2 operation.
///
/// The seal is intentionally private and borrowed by the admission basis.  A
/// digest with the same bytes cannot substitute for this object.
struct StoreC2SnapshotSealV1 {
    store_snapshot_identity: Sha256Digest,
    store_instance_identity: Sha256Digest,
    occurrence_id: String,
    authority_candidate_set_identity: Sha256Digest,
    measured_runtime_artifact_identity: Sha256Digest,
    process_identity: Sha256Digest,
    creator_pid: u32,
}

/// Same-snapshot/process premise used by manifest admission and every live
/// C2 phase constructor.
///
/// It is not serializable, cloneable, copyable, defaultable, or constructible
/// from raw identities.  Its lifetime is bounded by `Store::with_c2_admission_basis`.
pub(crate) struct StoreC2AdmissionBasisV1<'store> {
    snapshot: &'store StoreC2SnapshotSealV1,
    qualified: &'store StoreC2QualifiedRuntimeEvidenceV1,
    _invariant: PhantomData<fn(&'store mut Store) -> &'store mut Store>,
}

/// One exact current-A2 projection associated with the same retained Store
/// transaction that minted the admission basis.
///
/// The association is nonserializable and noncloneable.  It retains the
/// actual resolver input and resolver output so verification uses pointer
/// provenance (`CurrentActivationForC2::is_exact_projection_of`), not merely
/// equality of a detached digest set.
pub(crate) struct StoreC2AuthoritySnapshotV1<'store> {
    admission_basis: &'store StoreC2AdmissionBasisV1<'store>,
    current_activation: CurrentActivationForC2<'store>,
    resolver_input: &'store CurrentActivationResolverInputV1<'store>,
    resolved: &'store ControllingActivationSnapshot,
}

impl<'store> StoreC2AuthoritySnapshotV1<'store> {
    #[must_use]
    pub(crate) const fn admission_basis(&self) -> &StoreC2AdmissionBasisV1<'store> {
        self.admission_basis
    }

    #[must_use]
    pub(crate) const fn current_activation(&self) -> &CurrentActivationForC2<'store> {
        &self.current_activation
    }

    /// Recheck exact pointer provenance plus process and occurrence binding.
    pub(crate) fn verify_same_process_and_snapshot(&self) -> Result<(), C2LiveSignerRefusalV1> {
        self.admission_basis.verify_same_process()?;
        if !self
            .current_activation
            .is_exact_projection_of(self.resolver_input, self.resolved)
            || self.current_activation.occurrence_id() != self.admission_basis.occurrence_id()
            || self.current_activation.candidate_set_digest()
                != &self
                    .admission_basis
                    .snapshot
                    .authority_candidate_set_identity
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }
}

/// Closed live signer phases selected by the Store resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2LiveSigningPhaseV1 {
    Bootstrap,
    GenerationCurrent,
    PendingPossession,
    PendingSelected,
}

/// Type-level phase markers.  They carry no values and cannot construct a
/// context.
pub(crate) enum BootstrapV1 {}
pub(crate) enum GenerationCurrentV1 {}
pub(crate) enum PendingPossessionV1 {}
pub(crate) enum PendingSelectedV1 {}

/// Exact Store-resolved inputs for the closed MSG-09/MSG-03 installation
/// batch.
///
/// The scalar fields are signing payload coordinates, not authority.  The
/// value itself can be minted only in this module after one live bootstrap
/// context, accepted enrollment, external grant, install policy, physical
/// allocation and manifest correspondence have been rechecked against the
/// same actor epoch.  The coordinator accepts this opaque value instead of a
/// list of caller-selected digests.
pub(in crate::store_generation) struct StoreVerifiedInstallationBootstrapFactsV1 {
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    bootstrap_grant_identity: [u8; 32],
    proposal_identity: [u8; 32],
    attempt_mode_identity: [u8; 32],
    initial_policy_identity: [u8; 32],
    generation_preimage_identity: [u8; 32],
    accepted_enrollment_identity: [u8; 32],
    bg_layout_profile_manifest_lock_facts_identity: [u8; 32],
    generation_commitment_identity: [u8; 32],
}

impl StoreVerifiedInstallationBootstrapFactsV1 {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, BootstrapV1>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        context.verify_live(actor)?;
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub(in crate::store_generation) const fn bootstrap_grant_identity(&self) -> [u8; 32] {
        self.bootstrap_grant_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn proposal_identity(&self) -> [u8; 32] {
        self.proposal_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn attempt_mode_identity(&self) -> [u8; 32] {
        self.attempt_mode_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn initial_policy_identity(&self) -> [u8; 32] {
        self.initial_policy_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn bootstrap_generation_preimage_identity(
        &self,
    ) -> [u8; 32] {
        self.generation_preimage_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn accepted_enrollment_identity(&self) -> [u8; 32] {
        self.accepted_enrollment_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn frozen_generation_preimage_identity(
        &self,
    ) -> [u8; 32] {
        // One exact preimage has two semantic roles in the closed registry;
        // duplicating storage would permit an impossible split.
        self.generation_preimage_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn bg_layout_profile_manifest_lock_facts_identity(
        &self,
    ) -> [u8; 32] {
        self.bg_layout_profile_manifest_lock_facts_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn generation_commitment_identity(&self) -> [u8; 32] {
        self.generation_commitment_identity
    }
}

/// Exact actor-sealed inputs for MSG-10.  The pre-receipt B/G/lock/backend
/// identity is derived only after the pending projection exists and the
/// physical pair has been reopened/observed at the same actor epoch.
pub(in crate::store_generation) struct StoreVerifiedInstallationReceiptFactsV1 {
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    installation_intent_message_identity: [u8; 32],
    physical_generation_bootstrap_message_identity: [u8; 32],
    generation_commitment_identity: [u8; 32],
    pre_receipt_bg_lock_backend_facts_identity: [u8; 32],
}

impl StoreVerifiedInstallationReceiptFactsV1 {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, BootstrapV1>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        context.verify_live(actor)?;
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }

    pub(in crate::store_generation) const fn installation_intent_message_identity(
        &self,
    ) -> [u8; 32] {
        self.installation_intent_message_identity
    }

    pub(in crate::store_generation) const fn physical_generation_bootstrap_message_identity(
        &self,
    ) -> [u8; 32] {
        self.physical_generation_bootstrap_message_identity
    }

    pub(in crate::store_generation) const fn generation_commitment_identity(&self) -> [u8; 32] {
        self.generation_commitment_identity
    }

    pub(in crate::store_generation) const fn pre_receipt_bg_lock_backend_facts_identity(
        &self,
    ) -> [u8; 32] {
        self.pre_receipt_bg_lock_backend_facts_identity
    }
}

/// Exact canonical pending projection written only by the installation
/// driver.  It is disposable indexing evidence; its embedded identity is
/// bound by MSG-09 and never constructs standing on its own.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct C2InstallationProjectionWireV1 {
    schema: String,
    schema_version: u8,
    projection_identity: Sha256Digest,
    occurrence_id: String,
    physical_store_generation_identity: Sha256Digest,
    bootstrap_identity: Sha256Digest,
    installation_nonce: String,
    state: String,
}

#[derive(Serialize)]
struct C2InstallationProjectionIdentityBodyV1<'a> {
    schema: &'static str,
    schema_version: u8,
    occurrence_id: &'a str,
    physical_store_generation_identity: &'a Sha256Digest,
    bootstrap_identity: &'a Sha256Digest,
    installation_nonce: &'a str,
    state: &'static str,
}

#[derive(Serialize)]
struct C2InitialLineageProjectionWireV1<'a> {
    schema: &'static str,
    lineage_identity: &'a Sha256Digest,
    root_binding_identity: &'a Sha256Digest,
    initial_binding_identity: &'a Sha256Digest,
    terminal_binding_identity: &'a Sha256Digest,
    edge_count: u64,
    terminal_candidate_set_identity: &'a Sha256Digest,
    effective_cut: u64,
}

/// Canonical unsigned MSG-04 relation.  This is inert durable evidence: it
/// closes the exact bootstrap-to-generation correspondence for the resolver,
/// but it is not a signing route and has no conversion into live standing.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct C2BootstrapGenerationRelationWireV1 {
    schema: String,
    schema_version: u8,
    identity_domain: String,
    relation_identity: Sha256Digest,
    bootstrap_grant_identity: Sha256Digest,
    foundational_enrollment_identity: Sha256Digest,
    signer_enrollment_identity: Sha256Digest,
    initial_pop_identity: Sha256Digest,
    physical_generation_bootstrap_identity: Sha256Digest,
    generation_commitment_identity: Sha256Digest,
    installation_receipt_identity: Sha256Digest,
    physical_store_generation_identity: Sha256Digest,
    transition_cut: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct C2BootstrapGenerationRelationIdentityBodyV1<'a> {
    schema: &'static str,
    schema_version: u8,
    identity_domain: &'static str,
    bootstrap_grant_identity: &'a Sha256Digest,
    foundational_enrollment_identity: &'a Sha256Digest,
    signer_enrollment_identity: &'a Sha256Digest,
    initial_pop_identity: &'a Sha256Digest,
    physical_generation_bootstrap_identity: &'a Sha256Digest,
    generation_commitment_identity: &'a Sha256Digest,
    installation_receipt_identity: &'a Sha256Digest,
    physical_store_generation_identity: &'a Sha256Digest,
    transition_cut: u64,
}

struct C2InstallationProjectionRowV1 {
    projection_identity: String,
    occurrence_id: String,
    physical_generation_identity: String,
    bootstrap_identity: String,
    installation_nonce: String,
    state: String,
    canonical_bytes: Vec<u8>,
    canonical_bytes_sha256: String,
    canonical_bytes_length: u64,
    installation_receipt_identity: String,
    installation_intent_identity: String,
    pre_receipt_b_root_identity: String,
    pre_receipt_b_cursor: u64,
    g_root_identity: String,
    g_cursor: u64,
    completion_state: String,
    canonical_receipt_sha256: String,
}

struct C2BootstrapGenerationRelationRowV1 {
    relation_identity: String,
    bootstrap_grant_identity: String,
    foundational_enrollment_identity: String,
    signer_enrollment_identity: String,
    initial_pop_identity: String,
    physical_generation_bootstrap_identity: String,
    generation_commitment_identity: String,
    installation_receipt_identity: String,
    physical_generation_identity: String,
    transition_cut: u64,
    canonical_bytes: Vec<u8>,
    canonical_bytes_sha256: String,
    canonical_bytes_length: u64,
}

struct C2RootBindingProjectionRowV1 {
    root_binding_identity: String,
    occurrence_id: String,
    physical_generation_identity: String,
    lifecycle_root_identity: String,
    initial_enrollment_identity: String,
    initial_key_generation: u64,
    initial_public_key: Vec<u8>,
    generation_genesis_identity: String,
    generation_commitment_identity: String,
    scope_identity: String,
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    authority_domain: String,
    policy_lineage_root_identity: String,
    creation_cut: u64,
    canonical_bytes: Vec<u8>,
    canonical_bytes_sha256: String,
    canonical_bytes_length: u64,
}

struct C2CurrentBindingProjectionRowV1 {
    current_binding_identity: String,
    root_binding_identity: String,
    occurrence_id: String,
    physical_generation_identity: String,
    lifecycle_root_identity: String,
    scope_identity: String,
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_generation: u64,
    authority_domain: String,
    policy_lineage_root_identity: String,
    current_enrollment_identity: String,
    current_key_generation: u64,
    current_public_key: Vec<u8>,
    current_policy_identity: String,
    current_standing_identity: String,
    binding_mode: String,
    transition_identity: Option<String>,
    predecessor_binding_identity: Option<String>,
    persisted_resolution_identity: String,
    effective_cut: u64,
    canonical_bytes: Vec<u8>,
    canonical_bytes_sha256: String,
    canonical_bytes_length: u64,
}

/// Durable evidence selected by the exact complete-generation resolver.
///
/// This value owns only reverified inert records and scalar evidence.  It is
/// not cloneable or serializable and has no conversion into a live context;
/// fresh manifest admission, custody, enrollment rewrap, physical reopen and
/// Store/process correspondence remain required by the phase constructor.
pub(crate) struct StoreResolvedGenerationCurrentEvidenceV1 {
    projection_identity: Sha256Digest,
    occurrence_id: String,
    physical_generation_identity: Sha256Digest,
    bootstrap_identity: Sha256Digest,
    installation_intent_identity: Sha256Digest,
    installation_receipt_identity: Sha256Digest,
    bootstrap_generation_relation_identity: Sha256Digest,
    bootstrap_generation_relation: C2BootstrapGenerationRelationWireV1,
    pre_receipt_b_root_identity: Sha256Digest,
    pre_receipt_b_cursor: u64,
    g_root_identity: Sha256Digest,
    g_cursor: u64,
    root: StoreGenerationSignerRootBindingV1,
    current: CurrentSignerGenerationBindingV1,
    current_public_key: [u8; 32],
    active_policy_generation: u64,
    resident_generation: u64,
    role_manifest_identity: [u8; 32],
    implementation_manifest_identity: Sha256Digest,
    lineage_identity: Sha256Digest,
    lineage_completion_identity: Sha256Digest,
    terminal_candidate_set_identity: Sha256Digest,
    /// Exact last durable signer event which the freshly reopened live
    /// context must extend.  This may be later than the binding's persisted
    /// resolution when healthy generation-current work (currently MSG-08)
    /// was appended before restart.
    predecessor_event_identity: [u8; 32],
    event_cut: u64,
    frontier_identity: [u8; 32],
    exact_content_identity: Sha256Digest,
    /// Closed, lineage-neutral durable terminal proof selected from the full
    /// append-only signer graph.  This remains inert evidence and is retained
    /// so reopen cannot fall back to the bootstrap-only enrollment bridge.
    durable_terminal: StoreVerifiedDurableGenerationCurrentV1,
}

/// Closed scope shapes available to route-specific signing constructors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2LiveSigningScopeV1 {
    PreGeneration,
    ProspectivePhysicalGeneration,
    GenerationBound,
}

/// Closed authority roles available to route-specific signing constructors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2LiveSigningAuthorityV1 {
    Bootstrap,
    GenerationCurrent,
    CurrentPredecessor,
    PendingSuccessor,
}

/// Process-local phase provenance.  This closed tag is selected only by the
/// four Store-owned constructors; it is never accepted as caller input and is
/// never itself authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum C2LiveFoundationalLineageV1 {
    InitialExternal,
    OrdinarySuccessorContinuity,
    RestoreHistorical,
    RecoveryNewFoundation,
}

/// Exact scalar projection of a sealed phase correspondence.
///
/// These fields are kept in one private value so the signer vocabulary can
/// read them only through `C2LiveSigningViewV1`.  There is deliberately no
/// raw-parts constructor and no conversion in the opposite direction: copied
/// coordinates never reconstruct the live context that selected them.
#[derive(Clone)]
struct C2LiveSigningCoordinatesV1 {
    occurrence_id: String,
    occurrence_identity: [u8; 32],
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_identity: [u8; 32],
    role_manifest_generation: u64,
    authority_domain: String,
    terminal_a1_identity: [u8; 32],
    current_a2_identity: [u8; 32],
    grant_identity: Option<[u8; 32]>,
    predecessor_standing_identity: Option<[u8; 32]>,
    standing_identity: [u8; 32],
    signer_public_key: [u8; 32],
    signer_key_generation: u64,
    signer_key_generation_identity: [u8; 32],
    signer_scope_identity: [u8; 32],
    signer_scope_policy_identity: [u8; 32],
    signer_scope_policy_version: u64,
    active_policy_identity: [u8; 32],
    active_policy_generation: u64,
    active_policy_digest: [u8; 32],
    attempt_identity: [u8; 32],
    physical_generation_identity: Option<[u8; 32]>,
    prospective_generation_preimage_identity: Option<[u8; 32]>,
    lifecycle_root_identity: Option<[u8; 32]>,
    current_binding_identity: Option<[u8; 32]>,
    foundational_lineage: C2LiveFoundationalLineageV1,
    lineage_authority_identity: Option<[u8; 32]>,
    request_identity: Option<[u8; 32]>,
    pending_challenge_identity: Option<[u8; 32]>,
    historical_foundation_identity: Option<[u8; 32]>,
    foundation_identity: Option<[u8; 32]>,
    adoption_identity: Option<[u8; 32]>,
    signer_acceptance_identity: Option<[u8; 32]>,
    event_cut: u64,
    predecessor_event_identity: Option<[u8; 32]>,
    transition_intent_identity: Option<[u8; 32]>,
    implementation_manifest_identity: [u8; 32],
    manifest_admission_correspondence_identity: [u8; 32],
    qualified_candidate_identity: [u8; 32],
    source_tree_identity: [u8; 32],
    runtime_artifact_identity: [u8; 32],
    frontier_namespace_identity: [u8; 32],
    predecessor_frontier_identity: [u8; 32],
    exact_content_identity: [u8; 32],
    scope_class: C2LiveSigningScopeV1,
    authority_class: C2LiveSigningAuthorityV1,
}

/// One common Store/session correspondence plus a type-indexed phase witness.
///
/// The fields and every constructor are private to this module.  The type is
/// process-local, nonserializable, noncloneable, noncopyable, and invariant in
/// its Store lifetime and phase.  Durable records and scalar projections have
/// no conversion into it.
pub(crate) struct C2LiveSignerContextV1<'live, 'store, Phase> {
    authority_snapshot: &'live StoreC2AuthoritySnapshotV1<'store>,
    admitted_manifest: &'live StoreAdmittedSignerImplementationManifestV1<'live, 'store>,
    coordinates: C2LiveSigningCoordinatesV1,
    foundational_custody: &'live VerifiedFoundationalCustodyV1<'live>,
    phase: C2LiveSigningPhaseV1,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
    _phase: PhantomData<fn(Phase) -> Phase>,
    _store: PhantomData<fn(&'store mut Store) -> &'store mut Store>,
}

/// Linear Store-derived authority for the exact current predecessor at one
/// actor epoch.  The pointer is used only as a same-process provenance seal;
/// it is never persisted or dereferenced.  A durable binding record or copied
/// digest therefore cannot be converted into predecessor authority.
pub(crate) struct StoreVerifiedCurrentPredecessorAuthorityV1<'authority, 'live, 'store> {
    context_address: *const (),
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    generation_identity: [u8; 32],
    lifecycle_root_identity: [u8; 32],
    current_binding_identity: [u8; 32],
    current_frontier_identity: [u8; 32],
    current_standing_identity: [u8; 32],
    _context: PhantomData<&'authority C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>>,
}

/// Post-MSG-07/MSG-06 Store authority for exactly one ordinary successor
/// foundation.  It owns the consumed typed route evidence and is deliberately
/// neither serializable nor cloneable.  Consuming it may establish one
/// foundational adoption; it cannot establish acceptance or currentness.
pub(crate) struct StoreVerifiedOrdinarySuccessorFoundationAuthorityV1 {
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    current_context_address: *const (),
    pending_context_address: *const (),
    physical_generation_identity: [u8; 32],
    lifecycle_root_identity: [u8; 32],
    current_binding_identity: [u8; 32],
    current_frontier_identity: [u8; 32],
    current_standing_identity: [u8; 32],
    successor_proposal_identity: [u8; 32],
    successor_key_generation_identity: [u8; 32],
    transition_identity: [u8; 32],
    possession: ConsumedSuccessorPossessionV1,
    continuity: ConsumedHealthyRotationIntentV1,
    creator_pid: u32,
}

/// One consumed Store-only authority premise for a non-initial foundation
/// adoption.  The private constructors below are route-specific; this common
/// value exists only so the enrollment layer can persist one canonical
/// adoption shape without accepting a caller-selected lineage tag or raw
/// coordinate tuple.  It is process-local, nonserializable, noncloneable and
/// is consumed by exactly one adoption attempt.
pub(crate) struct ConsumedStoreFoundationAdoptionAuthorityV1 {
    lineage: FoundationalAdoptionLineageV1,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    store_identity: Sha256Digest,
    occurrence_id: String,
    occurrence_identity: [u8; 32],
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_identity: [u8; 32],
    role_manifest_generation: u64,
    authority_domain: String,
    physical_generation_identity: [u8; 32],
    lifecycle_root_identity: [u8; 32],
    frontier_identity: [u8; 32],
    current_predecessor_identity: [u8; 32],
    predecessor_enrollment_identity: [u8; 32],
    predecessor_key_generation_identity: [u8; 32],
    transition_identity: [u8; 32],
    lineage_reference_identity: [u8; 32],
    authority_reference_identity: [u8; 32],
    request_identity: Option<[u8; 32]>,
    transaction_identity: [u8; 32],
    policy_basis_identity: [u8; 32],
    applicability_basis_identity: [u8; 32],
    attempt_identity: [u8; 32],
    candidate_identity: [u8; 32],
    proposal_identity: [u8; 32],
    challenge_identity: [u8; 32],
    proof_of_possession_identity: [u8; 32],
    custody_evidence_identity: Sha256Digest,
    public_key: [u8; 32],
    key_generation: u64,
    key_generation_identity: [u8; 32],
    signer_scope_identity: [u8; 32],
    signer_scope_policy_identity: [u8; 32],
    signer_scope_policy_version: u64,
    active_policy_identity: [u8; 32],
    active_policy_generation: u64,
    current_a2_identity: [u8; 32],
    terminal_a1_identity: [u8; 32],
    qualified_candidate_identity: [u8; 32],
    source_tree_identity: [u8; 32],
    runtime_artifact_identity: [u8; 32],
    implementation_manifest_identity: [u8; 32],
    candidate_cut: u64,
    proof_cut: u64,
    enrollment_cut: u64,
    historical: Option<StoreVerifiedDurableSignerEnrollmentV1>,
    creator_pid: u32,
}

impl ConsumedStoreFoundationAdoptionAuthorityV1 {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        actor.verify_same_snapshot()?;
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
            || self.store_identity != actor.store_instance_identity
            || self.enrollment_cut <= self.proof_cut
            || self.proof_cut <= self.candidate_cut
            || self.public_key.iter().all(|byte| *byte == 0)
            || (self.key_generation == 0
                && matches!(
                    self.lineage,
                    FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity
                        | FoundationalAdoptionLineageV1::RecoveryNewFoundation
                ))
            || [
                self.occurrence_identity,
                self.physical_generation_identity,
                self.lifecycle_root_identity,
                self.frontier_identity,
                self.current_predecessor_identity,
                self.predecessor_enrollment_identity,
                self.predecessor_key_generation_identity,
                self.transition_identity,
                self.lineage_reference_identity,
                self.authority_reference_identity,
                self.transaction_identity,
                self.policy_basis_identity,
                self.applicability_basis_identity,
                self.attempt_identity,
                self.candidate_identity,
                self.proposal_identity,
                self.challenge_identity,
                self.proof_of_possession_identity,
                self.key_generation_identity,
                self.signer_scope_identity,
                self.signer_scope_policy_identity,
                self.active_policy_identity,
                self.current_a2_identity,
                self.terminal_a1_identity,
                self.qualified_candidate_identity,
                self.source_tree_identity,
                self.runtime_artifact_identity,
                self.implementation_manifest_identity,
            ]
            .iter()
            .any(|identity| identity.iter().all(|byte| *byte == 0))
            || matches!(self.lineage, FoundationalAdoptionLineageV1::InitialExternal)
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }

    pub(in crate::store_generation) const fn lineage(&self) -> FoundationalAdoptionLineageV1 {
        self.lineage
    }

    pub(in crate::store_generation) const fn store_identity(&self) -> &Sha256Digest {
        &self.store_identity
    }

    pub(in crate::store_generation) fn occurrence_id(&self) -> &str {
        &self.occurrence_id
    }

    pub(in crate::store_generation) const fn occurrence_identity(&self) -> [u8; 32] {
        self.occurrence_identity
    }

    pub(in crate::store_generation) fn resident_identity(&self) -> &str {
        &self.resident_identity
    }

    pub(in crate::store_generation) const fn resident_generation(&self) -> u64 {
        self.resident_generation
    }

    pub(in crate::store_generation) fn host_role(&self) -> &str {
        &self.host_role
    }

    pub(in crate::store_generation) const fn role_manifest_identity(&self) -> [u8; 32] {
        self.role_manifest_identity
    }

    pub(in crate::store_generation) const fn role_manifest_generation(&self) -> u64 {
        self.role_manifest_generation
    }

    pub(in crate::store_generation) fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    pub(in crate::store_generation) const fn physical_generation_identity(&self) -> [u8; 32] {
        self.physical_generation_identity
    }

    pub(in crate::store_generation) const fn lifecycle_root_identity(&self) -> [u8; 32] {
        self.lifecycle_root_identity
    }

    pub(in crate::store_generation) const fn frontier_identity(&self) -> [u8; 32] {
        self.frontier_identity
    }

    pub(in crate::store_generation) const fn current_predecessor_identity(&self) -> [u8; 32] {
        self.current_predecessor_identity
    }

    pub(in crate::store_generation) const fn predecessor_enrollment_identity(&self) -> [u8; 32] {
        self.predecessor_enrollment_identity
    }

    pub(in crate::store_generation) const fn predecessor_key_generation_identity(
        &self,
    ) -> [u8; 32] {
        self.predecessor_key_generation_identity
    }

    pub(in crate::store_generation) const fn transition_identity(&self) -> [u8; 32] {
        self.transition_identity
    }

    pub(in crate::store_generation) const fn lineage_reference_identity(&self) -> [u8; 32] {
        self.lineage_reference_identity
    }

    pub(in crate::store_generation) const fn authority_reference_identity(&self) -> [u8; 32] {
        self.authority_reference_identity
    }

    pub(in crate::store_generation) const fn request_identity(&self) -> Option<[u8; 32]> {
        self.request_identity
    }

    pub(in crate::store_generation) const fn transaction_identity(&self) -> [u8; 32] {
        self.transaction_identity
    }

    pub(in crate::store_generation) const fn policy_basis_identity(&self) -> [u8; 32] {
        self.policy_basis_identity
    }

    pub(in crate::store_generation) const fn applicability_basis_identity(&self) -> [u8; 32] {
        self.applicability_basis_identity
    }

    pub(in crate::store_generation) const fn attempt_identity(&self) -> [u8; 32] {
        self.attempt_identity
    }

    pub(in crate::store_generation) const fn candidate_identity(&self) -> [u8; 32] {
        self.candidate_identity
    }

    pub(in crate::store_generation) const fn proposal_identity(&self) -> [u8; 32] {
        self.proposal_identity
    }

    pub(in crate::store_generation) const fn challenge_identity(&self) -> [u8; 32] {
        self.challenge_identity
    }

    pub(in crate::store_generation) const fn proof_of_possession_identity(&self) -> [u8; 32] {
        self.proof_of_possession_identity
    }

    pub(in crate::store_generation) const fn custody_evidence_identity(&self) -> &Sha256Digest {
        &self.custody_evidence_identity
    }

    pub(in crate::store_generation) const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub(in crate::store_generation) const fn key_generation(&self) -> u64 {
        self.key_generation
    }

    pub(in crate::store_generation) const fn key_generation_identity(&self) -> [u8; 32] {
        self.key_generation_identity
    }

    pub(in crate::store_generation) const fn signer_scope_identity(&self) -> [u8; 32] {
        self.signer_scope_identity
    }

    pub(in crate::store_generation) const fn signer_scope_policy_identity(&self) -> [u8; 32] {
        self.signer_scope_policy_identity
    }

    pub(in crate::store_generation) const fn signer_scope_policy_version(&self) -> u64 {
        self.signer_scope_policy_version
    }

    pub(in crate::store_generation) const fn active_policy_identity(&self) -> [u8; 32] {
        self.active_policy_identity
    }

    pub(in crate::store_generation) const fn active_policy_generation(&self) -> u64 {
        self.active_policy_generation
    }

    pub(in crate::store_generation) const fn current_a2_identity(&self) -> [u8; 32] {
        self.current_a2_identity
    }

    pub(in crate::store_generation) const fn terminal_a1_identity(&self) -> [u8; 32] {
        self.terminal_a1_identity
    }

    pub(in crate::store_generation) const fn qualified_candidate_identity(&self) -> [u8; 32] {
        self.qualified_candidate_identity
    }

    pub(in crate::store_generation) const fn source_tree_identity(&self) -> [u8; 32] {
        self.source_tree_identity
    }

    pub(in crate::store_generation) const fn runtime_artifact_identity(&self) -> [u8; 32] {
        self.runtime_artifact_identity
    }

    pub(in crate::store_generation) const fn implementation_manifest_identity(&self) -> [u8; 32] {
        self.implementation_manifest_identity
    }

    pub(in crate::store_generation) const fn candidate_cut(&self) -> u64 {
        self.candidate_cut
    }

    pub(in crate::store_generation) const fn proof_cut(&self) -> u64 {
        self.proof_cut
    }

    pub(in crate::store_generation) const fn enrollment_cut(&self) -> u64 {
        self.enrollment_cut
    }

    pub(in crate::store_generation) const fn historical(
        &self,
    ) -> Option<&StoreVerifiedDurableSignerEnrollmentV1> {
        self.historical.as_ref()
    }
}

/// Exact durable-shaped coordinates verified by a discontinuity resolver.
/// This private projection is not authority by itself; only the nominal live
/// restore/recovery wrappers below can carry it across the pre-PoP cut.
struct C2DiscontinuityEntryCoordinatesV1 {
    occurrence_id: String,
    occurrence_identity: [u8; 32],
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_identity: [u8; 32],
    role_manifest_generation: u64,
    authority_domain: String,
    terminal_a1_identity: [u8; 32],
    current_a2_identity: [u8; 32],
    physical_generation_identity: [u8; 32],
    lifecycle_root_identity: [u8; 32],
    frontier_identity: [u8; 32],
    terminal_binding_identity: [u8; 32],
    predecessor_enrollment_identity: [u8; 32],
    predecessor_key_generation_identity: [u8; 32],
    predecessor_standing_identity: [u8; 32],
    signer_scope_identity: [u8; 32],
    signer_scope_policy_identity: [u8; 32],
    signer_scope_policy_version: u64,
    active_policy_identity: [u8; 32],
    active_policy_generation: u64,
    policy_basis_identity: [u8; 32],
    applicability_basis_identity: [u8; 32],
    request_identity: [u8; 32],
    transition_identity: [u8; 32],
    proposal_identity: [u8; 32],
    candidate_identity: [u8; 32],
    challenge_identity: [u8; 32],
    attempt_identity: [u8; 32],
    transaction_identity: [u8; 32],
    exact_content_identity: [u8; 32],
    qualified_candidate_identity: [u8; 32],
    source_tree_identity: [u8; 32],
    runtime_artifact_identity: [u8; 32],
    implementation_manifest_identity: [u8; 32],
    manifest_admission_correspondence_identity: [u8; 32],
    entry_cut: u64,
    foundation_enrollment_cut: u64,
}

/// Inert result of resolving one exact historical restore basis.  It is
/// actor/snapshot and pointer bound, but deliberately is not the live entry
/// authority: the latter is minted only after the adopted MSG-13 input is
/// consumed by `begin_restore_successor_v1`.
struct StoreResolvedRestoreEntryBasisV1 {
    historical: StoreVerifiedDurableSignerEnrollmentV1,
    coordinates: C2DiscontinuityEntryCoordinatesV1,
    durable_terminal_address: *const (),
    custody_address: *const (),
    restored_public_key: [u8; 32],
    restored_key_generation: u64,
    restored_key_generation_identity: [u8; 32],
    restored_custody_identity: Sha256Digest,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

/// Inert result of resolving one exact recovery discontinuity and a new
/// custody basis.  As with restore, this value cannot enter PendingPossession
/// until the nominal Store-owned MSG-15 constructor consumes it.
struct StoreResolvedRecoveryEntryBasisV1 {
    historical: StoreVerifiedDurableSignerEnrollmentV1,
    coordinates: C2DiscontinuityEntryCoordinatesV1,
    durable_terminal_address: *const (),
    custody_address: *const (),
    successor_public_key: [u8; 32],
    successor_key_generation: u64,
    successor_key_generation_identity: [u8; 32],
    successor_custody_identity: Sha256Digest,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

/// Exact Store-derived reason why a discontinuity route may be considered.
///
/// This is deliberately neither caller-selected nor durable authority.  The
/// live actor either proves that the exact current custodian cannot be
/// reopened in this process, or resolves one exact durable MSG-14 revocation
/// effect for the current terminal tuple.  MSG-13/15 request fields are never
/// treated as that proof.
enum StoreVerifiedDiscontinuityConditionV1 {
    OrdinaryContinuityUnavailable,
    GovernedCurrentSignerRevocation {
        effect_receipt_identity: Sha256Digest,
    },
}

/// Process/snapshot-bound discontinuity eligibility.  Its private route tag
/// prevents restore and recovery from sharing one generic externally
/// selectable authority lane.
struct StoreVerifiedDiscontinuityEligibilityV1 {
    lineage: C2LiveFoundationalLineageV1,
    condition: StoreVerifiedDiscontinuityConditionV1,
    condition_identity: [u8; 32],
    current_binding_identity: [u8; 32],
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

/// Store-derived live MSG-13 entry authority.  Durable MSG-13 adoption and a
/// historical foundation are retained as evidence, but neither can construct
/// this process/snapshot-bound value after restart.
pub(crate) struct StoreVerifiedRestoreEntryAuthorityV1<'authority, 'store> {
    authority_snapshot: &'authority StoreC2AuthoritySnapshotV1<'store>,
    admitted_manifest: &'authority StoreAdmittedSignerImplementationManifestV1<'authority, 'store>,
    adopted: StoreAdoptedRestoreAuthorizationV1,
    historical: StoreVerifiedDurableSignerEnrollmentV1,
    coordinates: C2DiscontinuityEntryCoordinatesV1,
    custody_address: *const (),
    restored_public_key: [u8; 32],
    restored_key_generation: u64,
    restored_key_generation_identity: [u8; 32],
    restored_custody_identity: Sha256Digest,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

/// Store-derived live MSG-15 entry authority.  It is nominally distinct from
/// restore and binds both the unavailable predecessor and a semantically new
/// successor key/custody foundation.
pub(crate) struct StoreVerifiedRecoveryEntryAuthorityV1<'authority, 'store> {
    authority_snapshot: &'authority StoreC2AuthoritySnapshotV1<'store>,
    admitted_manifest: &'authority StoreAdmittedSignerImplementationManifestV1<'authority, 'store>,
    adopted: StoreAdoptedRecoveryGrantV1,
    historical: StoreVerifiedDurableSignerEnrollmentV1,
    coordinates: C2DiscontinuityEntryCoordinatesV1,
    custody_address: *const (),
    successor_public_key: [u8; 32],
    successor_key_generation: u64,
    successor_key_generation_identity: [u8; 32],
    successor_custody_identity: Sha256Digest,
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    creator_pid: u32,
}

/// Exact restore pre-PoP staging permit. It owns the MSG-13 entry authority
/// and is consumed by the MSG-07 refinement; it is not signer standing.
pub(crate) struct StoreVerifiedRestorePossessionPermitV1<'authority, 'store> {
    entry: StoreVerifiedRestoreEntryAuthorityV1<'authority, 'store>,
    pending_context_address: *const (),
}

/// Exact recovery pre-PoP staging permit. It cannot be converted to restore.
pub(crate) struct StoreVerifiedRecoveryPossessionPermitV1<'authority, 'store> {
    entry: StoreVerifiedRecoveryEntryAuthorityV1<'authority, 'store>,
    pending_context_address: *const (),
}

/// Post-MSG-07 restore authority for re-adopting exactly the historical
/// stable foundation. It cannot establish acceptance or currentness.
pub(crate) struct StoreVerifiedRestoreFoundationAuthorityV1<'authority, 'store> {
    permit: StoreVerifiedRestorePossessionPermitV1<'authority, 'store>,
    possession: ConsumedSuccessorPossessionV1,
}

/// Post-MSG-07 recovery authority for adopting exactly one new foundation.
pub(crate) struct StoreVerifiedRecoveryFoundationAuthorityV1<'authority, 'store> {
    permit: StoreVerifiedRecoveryPossessionPermitV1<'authority, 'store>,
    possession: ConsumedSuccessorPossessionV1,
}

impl StoreVerifiedRestoreEntryAuthorityV1<'_, '_> {
    fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        custody: &VerifiedFoundationalCustodyV1<'_>,
    ) -> Result<(), C2DiscontinuityRefusalV1> {
        actor.verify_same_snapshot()?;
        custody.verify_same_process()?;
        actor.verify_authority_lineage(self.authority_snapshot)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            self.admitted_manifest,
            self.admitted_manifest.manifest(),
            self.authority_snapshot.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity != actor.actor_instance_identity
            || self.actor_snapshot_identity != actor.current_snapshot_identity
            || self.actor_effect_epoch != actor.effect_epoch
            || self.custody_address != std::ptr::from_ref(custody).cast::<()>()
            || self.restored_public_key != custody.public_key()
            || self.restored_key_generation != custody.key_generation()
            || self.restored_custody_identity != *custody.custody_evidence_identity()
            || self.historical.foundation().public_key()? != self.restored_public_key
            || self.historical.foundation().key_generation() != self.restored_key_generation
            || self.historical.foundation().custody_evidence_identity()
                != &self.restored_custody_identity
            || self.coordinates.foundation_enrollment_cut
                <= self.coordinates.entry_cut.saturating_add(1)
        {
            return Err(C2DiscontinuityRefusalV1::HistoricalFoundationReuseMismatch);
        }
        Ok(())
    }
}

impl StoreVerifiedRecoveryEntryAuthorityV1<'_, '_> {
    fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        custody: &VerifiedFoundationalCustodyV1<'_>,
    ) -> Result<(), C2DiscontinuityRefusalV1> {
        actor.verify_same_snapshot()?;
        custody.verify_same_process()?;
        actor.verify_authority_lineage(self.authority_snapshot)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            self.admitted_manifest,
            self.admitted_manifest.manifest(),
            self.authority_snapshot.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity != actor.actor_instance_identity
            || self.actor_snapshot_identity != actor.current_snapshot_identity
            || self.actor_effect_epoch != actor.effect_epoch
            || self.custody_address != std::ptr::from_ref(custody).cast::<()>()
            || self.successor_public_key != custody.public_key()
            || self.successor_key_generation != custody.key_generation()
            || self.successor_custody_identity != *custody.custody_evidence_identity()
            || self.successor_public_key == self.historical.foundation().public_key()?
            || self.successor_custody_identity
                == *self.historical.foundation().custody_evidence_identity()
            || self.coordinates.foundation_enrollment_cut
                <= self.coordinates.entry_cut.saturating_add(1)
        {
            return Err(C2DiscontinuityRefusalV1::RecoveryFoundationNotNew);
        }
        Ok(())
    }
}

impl StoreC2SnapshotActorV1<'_> {
    fn mint_restore_pending_possession_v1<'live, 'store>(
        &self,
        entry: &StoreVerifiedRestoreEntryAuthorityV1<'live, 'store>,
        custody: &'live VerifiedFoundationalCustodyV1<'live>,
    ) -> Result<C2LiveSignerContextV1<'live, 'store, PendingPossessionV1>, C2DiscontinuityRefusalV1>
    {
        entry.verify_for_actor(self, custody)?;
        let standing_like_staging_identity = digest_fields_bytes(
            b"nq.c2.restore.pending_possession.staging_identity.v1\0",
            &[
                &entry.coordinates.request_identity,
                &entry.coordinates.transition_identity,
                &entry.coordinates.challenge_identity,
                &entry.coordinates.terminal_binding_identity,
            ],
        );
        Ok(C2LiveSignerContextV1 {
            authority_snapshot: entry.authority_snapshot,
            admitted_manifest: entry.admitted_manifest,
            coordinates: C2LiveSigningCoordinatesV1 {
                occurrence_id: entry.coordinates.occurrence_id.clone(),
                occurrence_identity: entry.coordinates.occurrence_identity,
                resident_identity: entry.coordinates.resident_identity.clone(),
                resident_generation: entry.coordinates.resident_generation,
                host_role: entry.coordinates.host_role.clone(),
                role_manifest_identity: entry.coordinates.role_manifest_identity,
                role_manifest_generation: entry.coordinates.role_manifest_generation,
                authority_domain: entry.coordinates.authority_domain.clone(),
                terminal_a1_identity: entry.coordinates.terminal_a1_identity,
                current_a2_identity: entry.coordinates.current_a2_identity,
                grant_identity: None,
                predecessor_standing_identity: Some(
                    entry.coordinates.predecessor_standing_identity,
                ),
                standing_identity: standing_like_staging_identity,
                signer_public_key: entry.restored_public_key,
                signer_key_generation: entry.restored_key_generation,
                signer_key_generation_identity: custody.key_generation_identity(),
                signer_scope_identity: entry.coordinates.signer_scope_identity,
                signer_scope_policy_identity: entry.coordinates.signer_scope_policy_identity,
                signer_scope_policy_version: entry.coordinates.signer_scope_policy_version,
                active_policy_identity: entry.coordinates.active_policy_identity,
                active_policy_generation: entry.coordinates.active_policy_generation,
                active_policy_digest: entry.coordinates.policy_basis_identity,
                attempt_identity: entry.coordinates.attempt_identity,
                physical_generation_identity: Some(entry.coordinates.physical_generation_identity),
                prospective_generation_preimage_identity: None,
                lifecycle_root_identity: Some(entry.coordinates.lifecycle_root_identity),
                current_binding_identity: Some(entry.coordinates.terminal_binding_identity),
                foundational_lineage: C2LiveFoundationalLineageV1::RestoreHistorical,
                lineage_authority_identity: Some(
                    *entry.adopted.verified().carrier_identity().bytes(),
                ),
                request_identity: Some(entry.coordinates.request_identity),
                pending_challenge_identity: Some(entry.coordinates.challenge_identity),
                historical_foundation_identity: Some(digest_identity_bytes(
                    entry.historical.foundation().identity(),
                )?),
                foundation_identity: None,
                adoption_identity: None,
                signer_acceptance_identity: None,
                event_cut: discontinuity_cut_schedule_v1(entry.coordinates.entry_cut)
                    .map(|schedule| schedule.0)
                    .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?,
                predecessor_event_identity: Some(entry.coordinates.terminal_binding_identity),
                transition_intent_identity: Some(entry.coordinates.transition_identity),
                implementation_manifest_identity: entry
                    .coordinates
                    .implementation_manifest_identity,
                manifest_admission_correspondence_identity: entry
                    .coordinates
                    .manifest_admission_correspondence_identity,
                qualified_candidate_identity: entry.coordinates.qualified_candidate_identity,
                source_tree_identity: entry.coordinates.source_tree_identity,
                runtime_artifact_identity: entry.coordinates.runtime_artifact_identity,
                frontier_namespace_identity: entry.coordinates.lifecycle_root_identity,
                predecessor_frontier_identity: entry.coordinates.frontier_identity,
                exact_content_identity: entry.coordinates.exact_content_identity,
                scope_class: C2LiveSigningScopeV1::GenerationBound,
                authority_class: C2LiveSigningAuthorityV1::PendingSuccessor,
            },
            foundational_custody: custody,
            phase: C2LiveSigningPhaseV1::PendingPossession,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
            _phase: PhantomData,
            _store: PhantomData,
        })
    }

    fn seal_restore_possession_permit_v1<'authority, 'store>(
        &self,
        entry: StoreVerifiedRestoreEntryAuthorityV1<'authority, 'store>,
        pending: &C2LiveSignerContextV1<'authority, 'store, PendingPossessionV1>,
    ) -> Result<StoreVerifiedRestorePossessionPermitV1<'authority, 'store>, C2DiscontinuityRefusalV1>
    {
        pending.verify_live(self)?;
        if pending.coordinates.foundational_lineage
            != C2LiveFoundationalLineageV1::RestoreHistorical
            || pending.coordinates.request_identity != Some(entry.coordinates.request_identity)
            || pending.coordinates.transition_intent_identity
                != Some(entry.coordinates.transition_identity)
            || pending.coordinates.historical_foundation_identity
                != Some(digest_identity_bytes(
                    entry.historical.foundation().identity(),
                )?)
        {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        Ok(StoreVerifiedRestorePossessionPermitV1 {
            entry,
            pending_context_address: std::ptr::from_ref(pending).cast::<()>(),
        })
    }

    fn mint_recovery_pending_possession_v1<'live, 'store>(
        &self,
        entry: &StoreVerifiedRecoveryEntryAuthorityV1<'live, 'store>,
        custody: &'live VerifiedFoundationalCustodyV1<'live>,
    ) -> Result<C2LiveSignerContextV1<'live, 'store, PendingPossessionV1>, C2DiscontinuityRefusalV1>
    {
        entry.verify_for_actor(self, custody)?;
        let staging_identity = digest_fields_bytes(
            b"nq.c2.recovery.pending_possession.staging_identity.v1\0",
            &[
                &entry.coordinates.request_identity,
                &entry.coordinates.transition_identity,
                &entry.coordinates.challenge_identity,
                &entry.coordinates.terminal_binding_identity,
            ],
        );
        Ok(C2LiveSignerContextV1 {
            authority_snapshot: entry.authority_snapshot,
            admitted_manifest: entry.admitted_manifest,
            coordinates: C2LiveSigningCoordinatesV1 {
                occurrence_id: entry.coordinates.occurrence_id.clone(),
                occurrence_identity: entry.coordinates.occurrence_identity,
                resident_identity: entry.coordinates.resident_identity.clone(),
                resident_generation: entry.coordinates.resident_generation,
                host_role: entry.coordinates.host_role.clone(),
                role_manifest_identity: entry.coordinates.role_manifest_identity,
                role_manifest_generation: entry.coordinates.role_manifest_generation,
                authority_domain: entry.coordinates.authority_domain.clone(),
                terminal_a1_identity: entry.coordinates.terminal_a1_identity,
                current_a2_identity: entry.coordinates.current_a2_identity,
                grant_identity: None,
                predecessor_standing_identity: Some(
                    entry.coordinates.predecessor_standing_identity,
                ),
                standing_identity: staging_identity,
                signer_public_key: entry.successor_public_key,
                signer_key_generation: entry.successor_key_generation,
                signer_key_generation_identity: custody.key_generation_identity(),
                signer_scope_identity: entry.coordinates.signer_scope_identity,
                signer_scope_policy_identity: entry.coordinates.signer_scope_policy_identity,
                signer_scope_policy_version: entry.coordinates.signer_scope_policy_version,
                active_policy_identity: entry.coordinates.active_policy_identity,
                active_policy_generation: entry.coordinates.active_policy_generation,
                active_policy_digest: entry.coordinates.policy_basis_identity,
                attempt_identity: entry.coordinates.attempt_identity,
                physical_generation_identity: Some(entry.coordinates.physical_generation_identity),
                prospective_generation_preimage_identity: None,
                lifecycle_root_identity: Some(entry.coordinates.lifecycle_root_identity),
                current_binding_identity: Some(entry.coordinates.terminal_binding_identity),
                foundational_lineage: C2LiveFoundationalLineageV1::RecoveryNewFoundation,
                lineage_authority_identity: Some(
                    *entry.adopted.verified().carrier_identity().bytes(),
                ),
                request_identity: Some(entry.coordinates.request_identity),
                pending_challenge_identity: Some(entry.coordinates.challenge_identity),
                historical_foundation_identity: None,
                foundation_identity: None,
                adoption_identity: None,
                signer_acceptance_identity: None,
                event_cut: discontinuity_cut_schedule_v1(entry.coordinates.entry_cut)
                    .map(|schedule| schedule.0)
                    .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?,
                predecessor_event_identity: Some(entry.coordinates.terminal_binding_identity),
                transition_intent_identity: Some(entry.coordinates.transition_identity),
                implementation_manifest_identity: entry
                    .coordinates
                    .implementation_manifest_identity,
                manifest_admission_correspondence_identity: entry
                    .coordinates
                    .manifest_admission_correspondence_identity,
                qualified_candidate_identity: entry.coordinates.qualified_candidate_identity,
                source_tree_identity: entry.coordinates.source_tree_identity,
                runtime_artifact_identity: entry.coordinates.runtime_artifact_identity,
                frontier_namespace_identity: entry.coordinates.lifecycle_root_identity,
                predecessor_frontier_identity: entry.coordinates.frontier_identity,
                exact_content_identity: entry.coordinates.exact_content_identity,
                scope_class: C2LiveSigningScopeV1::GenerationBound,
                authority_class: C2LiveSigningAuthorityV1::PendingSuccessor,
            },
            foundational_custody: custody,
            phase: C2LiveSigningPhaseV1::PendingPossession,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
            _phase: PhantomData,
            _store: PhantomData,
        })
    }

    fn seal_recovery_possession_permit_v1<'authority, 'store>(
        &self,
        entry: StoreVerifiedRecoveryEntryAuthorityV1<'authority, 'store>,
        pending: &C2LiveSignerContextV1<'authority, 'store, PendingPossessionV1>,
    ) -> Result<StoreVerifiedRecoveryPossessionPermitV1<'authority, 'store>, C2DiscontinuityRefusalV1>
    {
        pending.verify_live(self)?;
        if pending.coordinates.foundational_lineage
            != C2LiveFoundationalLineageV1::RecoveryNewFoundation
            || pending.coordinates.request_identity != Some(entry.coordinates.request_identity)
            || pending.coordinates.transition_intent_identity
                != Some(entry.coordinates.transition_identity)
            || pending.coordinates.historical_foundation_identity.is_some()
        {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        Ok(StoreVerifiedRecoveryPossessionPermitV1 {
            entry,
            pending_context_address: std::ptr::from_ref(pending).cast::<()>(),
        })
    }

    fn refine_restore_foundation_after_msg07_v1<'authority, 'store>(
        &self,
        permit: StoreVerifiedRestorePossessionPermitV1<'authority, 'store>,
        pending: &C2LiveSignerContextV1<'authority, 'store, PendingPossessionV1>,
        possession: ConsumedSuccessorPossessionV1,
    ) -> Result<
        StoreVerifiedRestoreFoundationAuthorityV1<'authority, 'store>,
        C2DiscontinuityRefusalV1,
    > {
        pending.verify_live(self)?;
        possession
            .verify_for_actor(self)
            .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let entry = &permit.entry;
        if permit.pending_context_address != std::ptr::from_ref(pending).cast::<()>()
            || entry.creator_pid != std::process::id()
            || entry.actor_instance_identity != self.actor_instance_identity
            || entry.actor_effect_epoch.checked_add(1) != Some(self.effect_epoch)
            || entry.coordinates.proposal_identity != possession.successor_proposal_identity()
            || entry.coordinates.transition_identity != possession.transition_identity()
            || entry.restored_public_key != pending.coordinates.signer_public_key
            || entry.restored_key_generation != pending.coordinates.signer_key_generation
            || entry.restored_custody_identity
                != *pending.foundational_custody.custody_evidence_identity()
            || pending.coordinates.foundational_lineage
                != C2LiveFoundationalLineageV1::RestoreHistorical
        {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        Ok(StoreVerifiedRestoreFoundationAuthorityV1 { permit, possession })
    }

    fn refine_recovery_foundation_after_msg07_v1<'authority, 'store>(
        &self,
        permit: StoreVerifiedRecoveryPossessionPermitV1<'authority, 'store>,
        pending: &C2LiveSignerContextV1<'authority, 'store, PendingPossessionV1>,
        possession: ConsumedSuccessorPossessionV1,
    ) -> Result<
        StoreVerifiedRecoveryFoundationAuthorityV1<'authority, 'store>,
        C2DiscontinuityRefusalV1,
    > {
        pending.verify_live(self)?;
        possession
            .verify_for_actor(self)
            .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let entry = &permit.entry;
        if permit.pending_context_address != std::ptr::from_ref(pending).cast::<()>()
            || entry.creator_pid != std::process::id()
            || entry.actor_instance_identity != self.actor_instance_identity
            || entry.actor_effect_epoch.checked_add(1) != Some(self.effect_epoch)
            || entry.coordinates.proposal_identity != possession.successor_proposal_identity()
            || entry.coordinates.transition_identity != possession.transition_identity()
            || entry.successor_public_key != pending.coordinates.signer_public_key
            || entry.successor_key_generation != pending.coordinates.signer_key_generation
            || entry.successor_custody_identity
                != *pending.foundational_custody.custody_evidence_identity()
            || pending.coordinates.foundational_lineage
                != C2LiveFoundationalLineageV1::RecoveryNewFoundation
        {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        Ok(StoreVerifiedRecoveryFoundationAuthorityV1 { permit, possession })
    }

    fn consume_restore_foundation_authority_v1(
        &self,
        authority: StoreVerifiedRestoreFoundationAuthorityV1<'_, '_>,
        pending: &C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
    ) -> Result<ConsumedStoreFoundationAdoptionAuthorityV1, C2DiscontinuityRefusalV1> {
        let StoreVerifiedRestoreFoundationAuthorityV1 { permit, possession } = authority;
        pending.verify_live(self)?;
        possession
            .verify_for_actor(self)
            .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let entry = permit.entry;
        if permit.pending_context_address != std::ptr::from_ref(pending).cast::<()>()
            || entry.actor_instance_identity != self.actor_instance_identity
            || entry.actor_effect_epoch.checked_add(1) != Some(self.effect_epoch)
            || entry.coordinates.proposal_identity != possession.successor_proposal_identity()
            || entry.coordinates.transition_identity != possession.transition_identity()
        {
            return Err(C2DiscontinuityRefusalV1::StaleOrConsumed);
        }
        let proof_cut = possession.msg07().event_cut;
        let enrollment_cut = proof_cut
            .checked_add(1)
            .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        if enrollment_cut != entry.coordinates.foundation_enrollment_cut {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        let historical_foundation_identity =
            digest_identity_bytes(entry.historical.foundation().identity())?;
        let restore_lineage_identity = discontinuity_identity_field(
            entry
                .adopted
                .verified()
                .request()
                .field("restore_declaration_identity"),
        )?;
        // The durable adoption transaction begins only after MSG-07 has
        // advanced the actor.  Bind its identity to this exact pre-adoption
        // snapshot, not to the earlier MSG-13 entry snapshot retained by the
        // live entry authority.
        let transaction_identity = digest_fields_bytes(
            b"nq.c2.restore.foundation_transaction.identity.v1\0",
            &[
                &entry.coordinates.request_identity,
                entry.adopted.verified().carrier_identity().bytes(),
                &restore_lineage_identity,
                entry.historical.foundation().identity().as_str().as_bytes(),
                self.current_snapshot_identity.as_str().as_bytes(),
            ],
        );
        let common = ConsumedStoreFoundationAdoptionAuthorityV1 {
            lineage: FoundationalAdoptionLineageV1::RestoreHistorical,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            store_identity: self.store_instance_identity.clone(),
            occurrence_id: entry.coordinates.occurrence_id,
            occurrence_identity: entry.coordinates.occurrence_identity,
            resident_identity: entry.coordinates.resident_identity,
            resident_generation: entry.coordinates.resident_generation,
            host_role: entry.coordinates.host_role,
            role_manifest_identity: entry.coordinates.role_manifest_identity,
            role_manifest_generation: entry.coordinates.role_manifest_generation,
            authority_domain: entry.coordinates.authority_domain,
            physical_generation_identity: entry.coordinates.physical_generation_identity,
            lifecycle_root_identity: entry.coordinates.lifecycle_root_identity,
            frontier_identity: possession.resulting_frontier_identity(),
            current_predecessor_identity: entry.coordinates.terminal_binding_identity,
            predecessor_enrollment_identity: entry.coordinates.predecessor_enrollment_identity,
            predecessor_key_generation_identity: entry
                .coordinates
                .predecessor_key_generation_identity,
            transition_identity: entry.coordinates.transition_identity,
            lineage_reference_identity: historical_foundation_identity,
            authority_reference_identity: *entry.adopted.verified().carrier_identity().bytes(),
            request_identity: Some(entry.coordinates.request_identity),
            transaction_identity,
            policy_basis_identity: entry.coordinates.policy_basis_identity,
            applicability_basis_identity: entry.coordinates.applicability_basis_identity,
            attempt_identity: entry.coordinates.attempt_identity,
            candidate_identity: entry.coordinates.candidate_identity,
            proposal_identity: entry.coordinates.proposal_identity,
            challenge_identity: entry.coordinates.challenge_identity,
            proof_of_possession_identity: possession.message_identity(),
            custody_evidence_identity: entry.restored_custody_identity,
            public_key: entry.restored_public_key,
            key_generation: entry.restored_key_generation,
            key_generation_identity: entry.restored_key_generation_identity,
            signer_scope_identity: entry.coordinates.signer_scope_identity,
            signer_scope_policy_identity: entry.coordinates.signer_scope_policy_identity,
            signer_scope_policy_version: entry.coordinates.signer_scope_policy_version,
            active_policy_identity: entry.coordinates.active_policy_identity,
            active_policy_generation: entry.coordinates.active_policy_generation,
            current_a2_identity: entry.coordinates.current_a2_identity,
            terminal_a1_identity: entry.coordinates.terminal_a1_identity,
            qualified_candidate_identity: entry.coordinates.qualified_candidate_identity,
            source_tree_identity: entry.coordinates.source_tree_identity,
            runtime_artifact_identity: entry.coordinates.runtime_artifact_identity,
            implementation_manifest_identity: entry.coordinates.implementation_manifest_identity,
            candidate_cut: entry.coordinates.entry_cut,
            proof_cut,
            enrollment_cut,
            historical: Some(entry.historical),
            creator_pid: std::process::id(),
        };
        common.verify_for_actor(self)?;
        Ok(common)
    }

    fn consume_recovery_foundation_authority_v1(
        &self,
        authority: StoreVerifiedRecoveryFoundationAuthorityV1<'_, '_>,
        pending: &C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
    ) -> Result<ConsumedStoreFoundationAdoptionAuthorityV1, C2DiscontinuityRefusalV1> {
        let StoreVerifiedRecoveryFoundationAuthorityV1 { permit, possession } = authority;
        pending.verify_live(self)?;
        possession
            .verify_for_actor(self)
            .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let entry = permit.entry;
        if permit.pending_context_address != std::ptr::from_ref(pending).cast::<()>()
            || entry.actor_instance_identity != self.actor_instance_identity
            || entry.actor_effect_epoch.checked_add(1) != Some(self.effect_epoch)
            || entry.coordinates.proposal_identity != possession.successor_proposal_identity()
            || entry.coordinates.transition_identity != possession.transition_identity()
        {
            return Err(C2DiscontinuityRefusalV1::StaleOrConsumed);
        }
        let proof_cut = possession.msg07().event_cut;
        let enrollment_cut = proof_cut
            .checked_add(1)
            .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        if enrollment_cut != entry.coordinates.foundation_enrollment_cut {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        let historical_reference = digest_identity_bytes(entry.historical.adoption().identity())?;
        // As with ordinary successor adoption, the durable recovery
        // transaction is cut after MSG-07.  The entry snapshot remains bound
        // by the live authority; the adoption identity must bind the exact
        // later pre-adoption Store snapshot that the terminal verifier can
        // rederive from durable evidence.
        let transaction_identity = digest_fields_bytes(
            b"nq.c2.recovery.foundation_transaction.identity.v1\0",
            &[
                &entry.coordinates.request_identity,
                entry.adopted.verified().carrier_identity().bytes(),
                &entry.coordinates.applicability_basis_identity,
                &entry.coordinates.proposal_identity,
                self.current_snapshot_identity.as_str().as_bytes(),
            ],
        );
        let common = ConsumedStoreFoundationAdoptionAuthorityV1 {
            lineage: FoundationalAdoptionLineageV1::RecoveryNewFoundation,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            store_identity: self.store_instance_identity.clone(),
            occurrence_id: entry.coordinates.occurrence_id,
            occurrence_identity: entry.coordinates.occurrence_identity,
            resident_identity: entry.coordinates.resident_identity,
            resident_generation: entry.coordinates.resident_generation,
            host_role: entry.coordinates.host_role,
            role_manifest_identity: entry.coordinates.role_manifest_identity,
            role_manifest_generation: entry.coordinates.role_manifest_generation,
            authority_domain: entry.coordinates.authority_domain,
            physical_generation_identity: entry.coordinates.physical_generation_identity,
            lifecycle_root_identity: entry.coordinates.lifecycle_root_identity,
            frontier_identity: possession.resulting_frontier_identity(),
            current_predecessor_identity: entry.coordinates.terminal_binding_identity,
            predecessor_enrollment_identity: entry.coordinates.predecessor_enrollment_identity,
            predecessor_key_generation_identity: entry
                .coordinates
                .predecessor_key_generation_identity,
            transition_identity: entry.coordinates.transition_identity,
            lineage_reference_identity: historical_reference,
            authority_reference_identity: *entry.adopted.verified().carrier_identity().bytes(),
            request_identity: Some(entry.coordinates.request_identity),
            transaction_identity,
            policy_basis_identity: entry.coordinates.policy_basis_identity,
            applicability_basis_identity: entry.coordinates.applicability_basis_identity,
            attempt_identity: entry.coordinates.attempt_identity,
            candidate_identity: entry.coordinates.candidate_identity,
            proposal_identity: entry.coordinates.proposal_identity,
            challenge_identity: entry.coordinates.challenge_identity,
            proof_of_possession_identity: possession.message_identity(),
            custody_evidence_identity: entry.successor_custody_identity,
            public_key: entry.successor_public_key,
            key_generation: entry.successor_key_generation,
            key_generation_identity: entry.successor_key_generation_identity,
            signer_scope_identity: entry.coordinates.signer_scope_identity,
            signer_scope_policy_identity: entry.coordinates.signer_scope_policy_identity,
            signer_scope_policy_version: entry.coordinates.signer_scope_policy_version,
            active_policy_identity: entry.coordinates.active_policy_identity,
            active_policy_generation: entry.coordinates.active_policy_generation,
            current_a2_identity: entry.coordinates.current_a2_identity,
            terminal_a1_identity: entry.coordinates.terminal_a1_identity,
            qualified_candidate_identity: entry.coordinates.qualified_candidate_identity,
            source_tree_identity: entry.coordinates.source_tree_identity,
            runtime_artifact_identity: entry.coordinates.runtime_artifact_identity,
            implementation_manifest_identity: entry.coordinates.implementation_manifest_identity,
            candidate_cut: entry.coordinates.entry_cut,
            proof_cut,
            enrollment_cut,
            historical: Some(entry.historical),
            creator_pid: std::process::id(),
        };
        common.verify_for_actor(self)?;
        Ok(common)
    }
}

impl StoreVerifiedOrdinarySuccessorFoundationAuthorityV1 {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        current: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        pending: &C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        current.verify_live(actor)?;
        pending.verify_live(actor)?;
        // MSG-07 is intentionally a historical input at this boundary: the
        // actor has since refreshed the predecessor and appended MSG-06 and
        // MSG-11. Requiring the MSG-07 post-append snapshot itself to remain
        // current would make the legal sequence impossible. Its nominal
        // consumed wrapper, exact cross-message identities, and strict cuts
        // are checked here instead.
        self.continuity
            .verify_for_actor(actor)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
            || self.current_context_address != std::ptr::from_ref(current).cast::<()>()
            || self.pending_context_address != std::ptr::from_ref(pending).cast::<()>()
            || Some(self.physical_generation_identity)
                != current.coordinates.physical_generation_identity
            || Some(self.lifecycle_root_identity) != current.coordinates.lifecycle_root_identity
            || Some(self.current_binding_identity) != current.coordinates.current_binding_identity
            || self.current_frontier_identity != current.coordinates.predecessor_frontier_identity
            || self.current_frontier_identity != pending.coordinates.predecessor_frontier_identity
            || self.current_standing_identity != current.coordinates.standing_identity
            || self.successor_proposal_identity != self.possession.successor_proposal_identity()
            || self.successor_proposal_identity
                != digest_identity_bytes(pending.foundational_custody.proposal_identity())?
            || self.successor_key_generation_identity
                != pending.coordinates.signer_key_generation_identity
            || self.transition_identity != self.possession.transition_identity()
            || self.transition_identity != self.continuity.transition_identity()
            || self.continuity.successor_pop_identity() != self.possession.message_identity()
            || self.possession.actor_instance_identity() != actor.actor_instance_identity()
            || self.possession.post_append_effect_epoch() >= actor.effect_epoch()
            || self.possession.msg07().event_cut >= self.continuity.mandatory_msg06().event_cut
            || self
                .continuity
                .mandatory_msg06()
                .message_identity
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub(in crate::store_generation) const fn possession(&self) -> &ConsumedSuccessorPossessionV1 {
        &self.possession
    }

    #[must_use]
    pub(in crate::store_generation) const fn continuity(&self) -> &ConsumedHealthyRotationIntentV1 {
        &self.continuity
    }

    #[must_use]
    pub(in crate::store_generation) const fn current_binding_identity(&self) -> [u8; 32] {
        self.current_binding_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn physical_generation_identity(&self) -> [u8; 32] {
        self.physical_generation_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn lifecycle_root_identity(&self) -> [u8; 32] {
        self.lifecycle_root_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn current_frontier_identity(&self) -> [u8; 32] {
        self.current_frontier_identity
    }
}

impl StoreC2SnapshotActorV1<'_> {
    /// Consume the exact post-MSG-07/post-MSG-06 healthy-rotation authority
    /// into the sole non-initial foundational-adoption premise.  This is a
    /// linear refinement: the predecessor authority and both typed messages
    /// are owned by `authority`, and no scalar projection can call it.
    fn consume_ordinary_successor_foundation_authority_v1(
        &self,
        authority: StoreVerifiedOrdinarySuccessorFoundationAuthorityV1,
        current: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        pending: &C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
    ) -> Result<ConsumedStoreFoundationAdoptionAuthorityV1, C2LiveSignerRefusalV1> {
        authority.verify_for_actor(self, current, pending)?;
        let proposal_identity = authority.successor_proposal_identity;
        let transition_identity = authority.transition_identity;
        let msg07 = authority.possession.msg07();
        let msg06 = authority.continuity.mandatory_msg06();
        let msg11 = authority.continuity.msg11();
        let challenge_identity = pending
            .coordinates
            .pending_challenge_identity
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let predecessor_enrollment_identity = current
            .coordinates
            .signer_acceptance_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let physical_generation_identity = current
            .coordinates
            .physical_generation_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let lifecycle_root_identity = current
            .coordinates
            .lifecycle_root_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let current_predecessor_identity = current
            .coordinates
            .current_binding_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let proof_cut = msg07.event_cut;
        let candidate_cut = proof_cut
            .checked_sub(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let enrollment_cut = msg11
            .event_cut
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if msg06.event_cut <= proof_cut
            || msg11.event_cut <= msg06.event_cut
            || pending.foundational_custody.key_generation()
                != current
                    .coordinates
                    .signer_key_generation
                    .checked_add(1)
                    .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        let candidate_identity = digest_fields_bytes(
            b"nq.c2.ordinary_successor.candidate.identity.v1\0",
            &[
                &proposal_identity,
                &challenge_identity,
                &pending.coordinates.signer_public_key,
                &pending.coordinates.signer_key_generation.to_be_bytes(),
                pending
                    .foundational_custody
                    .custody_evidence_identity()
                    .as_str()
                    .as_bytes(),
            ],
        );
        let transaction_identity = digest_fields_bytes(
            b"nq.c2.ordinary_successor.foundation_adoption.transaction.v1\0",
            &[
                &transition_identity,
                &msg07.message_identity,
                &msg06.message_identity,
                &msg11.message_identity,
                self.current_snapshot_identity.as_str().as_bytes(),
            ],
        );
        let applicability_basis_identity = digest_fields_bytes(
            b"nq.c2.ordinary_successor.applicability_basis.identity.v1\0",
            &[
                &current.coordinates.current_a2_identity,
                &pending.coordinates.active_policy_identity,
                &pending.coordinates.signer_scope_identity,
                &msg11.message_identity,
            ],
        );
        let consumed = ConsumedStoreFoundationAdoptionAuthorityV1 {
            lineage: FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            store_identity: self.store_instance_identity.clone(),
            occurrence_id: pending.coordinates.occurrence_id.clone(),
            occurrence_identity: pending.coordinates.occurrence_identity,
            resident_identity: pending.coordinates.resident_identity.clone(),
            resident_generation: pending.coordinates.resident_generation,
            host_role: pending.coordinates.host_role.clone(),
            role_manifest_identity: pending.coordinates.role_manifest_identity,
            role_manifest_generation: pending.coordinates.role_manifest_generation,
            authority_domain: pending.coordinates.authority_domain.clone(),
            physical_generation_identity,
            lifecycle_root_identity,
            frontier_identity: current.coordinates.predecessor_frontier_identity,
            current_predecessor_identity,
            predecessor_enrollment_identity,
            predecessor_key_generation_identity: current.coordinates.signer_key_generation_identity,
            transition_identity,
            lineage_reference_identity: current_predecessor_identity,
            authority_reference_identity: msg06.message_identity,
            request_identity: None,
            transaction_identity,
            policy_basis_identity: pending.coordinates.active_policy_identity,
            applicability_basis_identity,
            attempt_identity: pending.coordinates.attempt_identity,
            candidate_identity,
            proposal_identity,
            challenge_identity,
            proof_of_possession_identity: msg07.message_identity,
            custody_evidence_identity: pending
                .foundational_custody
                .custody_evidence_identity()
                .clone(),
            public_key: pending.coordinates.signer_public_key,
            key_generation: pending.coordinates.signer_key_generation,
            key_generation_identity: digest_fields_bytes(
                b"nq.c2.store_integrity_stable_key_generation.identity.v1\0",
                &[
                    &pending.coordinates.signer_public_key,
                    &pending.coordinates.signer_key_generation.to_be_bytes(),
                ],
            ),
            signer_scope_identity: pending.coordinates.signer_scope_identity,
            signer_scope_policy_identity: pending.coordinates.signer_scope_policy_identity,
            signer_scope_policy_version: pending.coordinates.signer_scope_policy_version,
            active_policy_identity: pending.coordinates.active_policy_identity,
            active_policy_generation: pending.coordinates.active_policy_generation,
            current_a2_identity: pending.coordinates.current_a2_identity,
            terminal_a1_identity: pending.coordinates.terminal_a1_identity,
            qualified_candidate_identity: pending.coordinates.qualified_candidate_identity,
            source_tree_identity: pending.coordinates.source_tree_identity,
            runtime_artifact_identity: pending.coordinates.runtime_artifact_identity,
            implementation_manifest_identity: pending.coordinates.implementation_manifest_identity,
            candidate_cut,
            proof_cut,
            enrollment_cut,
            historical: None,
            creator_pid: std::process::id(),
        };
        consumed.verify_for_actor(self)?;
        Ok(consumed)
    }

    /// Resolve the historical terminal/foundation and present custody for an
    /// exact MSG-13 occurrence.  The result is inert; it deliberately borrows
    /// neither authority nor a pending phase and can only be consumed by the
    /// nominal restore-entry constructor below.
    fn resolve_restore_entry_basis_v1<'manifest, 'store>(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'manifest, 'store>,
        durable_current: &StoreResolvedGenerationCurrentEvidenceV1,
        eligibility: &StoreVerifiedDiscontinuityEligibilityV1,
        adopted: &StoreAdoptedRestoreAuthorizationV1,
        custody: &VerifiedFoundationalCustodyV1<'_>,
    ) -> Result<StoreResolvedRestoreEntryBasisV1, C2DiscontinuityRefusalV1> {
        self.verify_same_snapshot()?;
        self.verify_authority_lineage(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        self.verify_discontinuity_eligibility_for_entry_v1(
            eligibility,
            C2LiveFoundationalLineageV1::RestoreHistorical,
            durable_current,
        )?;
        // Exact historical reuse of the current stable foundation necessarily
        // reopens that same custody in this actor.  Consequently the
        // continuity-unavailable branch cannot remain true at this cut;
        // restore entry requires the independently governed revocation branch.
        if !matches!(
            eligibility.condition,
            StoreVerifiedDiscontinuityConditionV1::GovernedCurrentSignerRevocation { .. }
        ) {
            return Err(C2DiscontinuityRefusalV1::RestoreEligibilityAbsent);
        }
        custody.verify_same_process()?;
        let request = adopted.verified().request();
        let carrier = adopted.verified().carrier();
        let current_binding_identity = digest_identity_bytes(durable_current.current.binding_id())?;
        let physical_generation_identity =
            digest_identity_bytes(&durable_current.physical_generation_identity)?;
        let lifecycle_root_identity =
            digest_text_identity(durable_current.root.lifecycle_root_id())?;
        let current_scope_identity = digest_text_identity(durable_current.root.scope_id())?;
        let current_standing_identity =
            digest_text_identity(durable_current.current.standing_id())?;
        let predecessor_enrollment_identity = digest_identity_bytes(
            durable_current
                .durable_terminal
                .enrollment()
                .acceptance()
                .identity(),
        )?;
        let predecessor_key_generation = durable_current
            .current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        let predecessor_key_generation_identity = digest_fields_bytes(
            b"nq.c2.store_integrity_stable_key_generation.identity.v1\0",
            &[
                &durable_current.current_public_key,
                &predecessor_key_generation.to_be_bytes(),
            ],
        );
        let active_policy_identity = digest_text_identity(durable_current.current.policy_id())?;
        let role_manifest_generation = durable_current
            .root
            .role_manifest_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        let target_enrollment =
            discontinuity_digest_field(request.field("target_signer_enrollment_identity"))?;
        let historical = load_verified_durable_signer_enrollment_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &target_enrollment,
        )
        .map_err(|_| C2DiscontinuityRefusalV1::HistoricalFoundationMissing)?;
        let historical_public_key = historical.foundation().public_key()?;
        let historical_generation = historical.foundation().key_generation();
        let restored_public_key = custody.public_key();
        let restored_generation = custody.key_generation();
        let restored_custody = custody.custody_evidence_identity().clone();
        let target_proposal =
            discontinuity_identity_field(request.field("target_signer_proposal_identity"))?;
        let restore_transition =
            discontinuity_identity_field(request.field("target_restore_proposal_identity"))?;
        let target_custody =
            discontinuity_digest_field(request.field("target_custody_binding_identity"))?;
        let request_identity = *adopted.verified().request_identity().bytes();
        let authority_identity = *adopted.verified().carrier_identity().bytes();
        let restore_lineage =
            discontinuity_identity_field(request.field("restore_declaration_identity"))?;
        let _restore_disposition =
            discontinuity_identity_field(request.field("restore_disposition_identity"))?;
        let restore_proof = discontinuity_identity_field(request.field("restore_proof_identity"))?;
        let restore_cut = discontinuity_u64_field(request.field("restore_cut"))?;
        let proposed_effect_cut = discontinuity_u64_field(request.field("proposed_effect_cut"))?;
        let historical_terminal_bindings = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .prepare(
                "SELECT binding.current_binding_identity
                 FROM c2_signer_current_binding_projection AS binding
                 JOIN c2_signer_lineage_completion_projection AS completion
                   ON completion.terminal_binding_identity = binding.current_binding_identity
                 WHERE binding.signer_lifecycle_root_identity = ?1
                   AND binding.current_enrollment_identity = ?2",
            )
            .map_err(StoreError::from)
            .map_err(C2LiveSignerRefusalV1::from)?
            .query_map(
                params![
                    identity_digest_from_bytes(lifecycle_root_identity)?.as_str(),
                    target_enrollment.as_str(),
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(StoreError::from)
            .map_err(C2LiveSignerRefusalV1::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
            .map_err(C2LiveSignerRefusalV1::from)?;
        let exact_current = [
            (
                request.field("physical_store_generation_identity"),
                physical_generation_identity,
            ),
            (
                request.field("signer_lifecycle_root_identity"),
                lifecycle_root_identity,
            ),
            (request.field("scope_identity"), current_scope_identity),
            (
                request.field("predecessor_current_signer_binding_identity"),
                current_binding_identity,
            ),
            (
                request.field("predecessor_generation_commitment_identity"),
                digest_identity_bytes(
                    &durable_current
                        .bootstrap_generation_relation
                        .generation_commitment_identity,
                )?,
            ),
        ];
        if historical_terminal_bindings.len() != 1
            || parse_digest(&historical_terminal_bindings[0])?
                != identity_digest_from_bytes(current_binding_identity)?
            || target_enrollment != identity_digest_from_bytes(predecessor_enrollment_identity)?
            || exact_current.into_iter().any(|(field, expected)| {
                !discontinuity_identity_field(field).is_ok_and(|actual| actual == expected)
            })
            || request.field("disposition").and_then(Value::as_str)
                != Some("restore_successor_authorized")
            || request
                .field("quarantine_remains_closed")
                .and_then(Value::as_bool)
                != Some(true)
            || restore_cut != proposed_effect_cut
            || restore_cut <= durable_current.event_cut
            || durable_current.occurrence_id != authority.current_activation().occurrence_id()
            || durable_current.root.resident_id()
                != authority.current_activation().resident_identity()
            || durable_current.resident_generation
                != authority.current_activation().resident_generation()
            || durable_current.root.role_id() != authority.current_activation().host_role()
            || role_manifest_generation != authority.current_activation().role_manifest_generation()
            || durable_current.root.domain_id() != authority.current_activation().domain()
            || custody.scope_identity() != current_scope_identity
            || digest_identity_bytes(custody.proposal_identity())? != target_proposal
            || target_custody != restored_custody
            || restored_public_key != historical_public_key
            || restored_generation != historical_generation
            || restored_custody != *historical.foundation().custody_evidence_identity()
            || carrier.field("target_signer_enrollment_identity")
                != request.field("target_signer_enrollment_identity")
        {
            return Err(C2DiscontinuityRefusalV1::HistoricalFoundationReuseMismatch);
        }
        let restored_key_generation_identity = digest_fields_bytes(
            b"nq.c2.store_integrity_stable_key_generation.identity.v1\0",
            &[&restored_public_key, &restored_generation.to_be_bytes()],
        );
        let challenge_identity = digest_fields_bytes(
            b"nq.c2.restore.successor_pop_challenge.identity.v1\0",
            &[&authority_identity, &target_proposal, &restore_transition],
        );
        let transaction_identity = digest_fields_bytes(
            b"nq.c2.restore.foundation_transaction.identity.v1\0",
            &[
                &request_identity,
                &authority_identity,
                &restore_lineage,
                historical.foundation().identity().as_str().as_bytes(),
                self.current_snapshot_identity.as_str().as_bytes(),
            ],
        );
        // R is the externally authorized discontinuity cut. PendingPossession
        // is R+1, the exact MSG-07 is signed at R+1, foundation adoption is
        // R+2, and the deliberately later signer acceptance is R+3.
        let (_, foundation_enrollment_cut, _, _, _) = discontinuity_cut_schedule_v1(restore_cut)
            .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        // A restore reuses the stable historical foundation, never the
        // historical adoption occurrence.  Candidate/attempt identities are
        // occurrence coordinates and therefore must be fresh for this exact
        // MSG-13 transaction; copying them from the historical adoption would
        // collide with the append-only one-use indices and would incorrectly
        // turn re-adoption into replay of the old event.
        let candidate_identity = digest_fields_bytes(
            b"nq.c2.restore.successor_candidate.identity.v1\0",
            &[
                &request_identity,
                &authority_identity,
                &target_proposal,
                &restore_transition,
                historical.foundation().identity().as_str().as_bytes(),
            ],
        );
        let attempt_identity = digest_fields_bytes(
            b"nq.c2.restore.adoption_attempt.identity.v1\0",
            &[
                &request_identity,
                &authority_identity,
                &restore_lineage,
                &restore_transition,
                &restore_cut.to_be_bytes(),
            ],
        );
        let coordinates = C2DiscontinuityEntryCoordinatesV1 {
            occurrence_id: durable_current.occurrence_id.clone(),
            occurrence_identity: text_identity_bytes(
                b"nq.c2.store_occurrence.identity.v1\0",
                &durable_current.occurrence_id,
            ),
            resident_identity: durable_current.root.resident_id().to_owned(),
            resident_generation: durable_current.resident_generation,
            host_role: durable_current.root.role_id().to_owned(),
            role_manifest_identity: durable_current.role_manifest_identity,
            role_manifest_generation,
            authority_domain: durable_current.root.domain_id().to_owned(),
            terminal_a1_identity: digest_identity_bytes(
                authority
                    .resolved
                    .terminal_operator_authority()
                    .record_digest(),
            )?,
            current_a2_identity: digest_identity_bytes(
                authority
                    .current_activation()
                    .controlling_tip_activation_digest(),
            )?,
            physical_generation_identity,
            lifecycle_root_identity,
            frontier_identity: durable_current.frontier_identity,
            terminal_binding_identity: current_binding_identity,
            predecessor_enrollment_identity,
            predecessor_key_generation_identity,
            predecessor_standing_identity: current_standing_identity,
            signer_scope_identity: current_scope_identity,
            signer_scope_policy_identity: custody.signer_scope_policy_identity(),
            signer_scope_policy_version: custody.signer_scope_policy_version(),
            active_policy_identity,
            active_policy_generation: durable_current.active_policy_generation,
            policy_basis_identity: active_policy_identity,
            applicability_basis_identity: eligibility.condition_identity,
            request_identity,
            transition_identity: restore_transition,
            proposal_identity: target_proposal,
            candidate_identity,
            challenge_identity,
            attempt_identity,
            transaction_identity,
            exact_content_identity: digest_fields_bytes(
                b"nq.c2.restore.entry.exact_content.v1\0",
                &[
                    carrier.canonical_bytes(),
                    request.canonical_bytes(),
                    &restore_proof,
                    historical.foundation().canonical_bytes(),
                ],
            ),
            qualified_candidate_identity: digest_identity_bytes(
                admitted_manifest.qualified_candidate_identity(),
            )?,
            source_tree_identity: digest_identity_bytes(admitted_manifest.source_tree_identity())?,
            runtime_artifact_identity: digest_identity_bytes(
                admitted_manifest.runtime_artifact_identity(),
            )?,
            implementation_manifest_identity: digest_identity_bytes(
                admitted_manifest.manifest_identity(),
            )?,
            manifest_admission_correspondence_identity: digest_identity_bytes(
                &admitted_manifest.correspondence_identity(),
            )?,
            entry_cut: restore_cut,
            foundation_enrollment_cut,
        };
        Ok(StoreResolvedRestoreEntryBasisV1 {
            historical,
            coordinates,
            durable_terminal_address: std::ptr::from_ref(durable_current).cast::<()>(),
            custody_address: std::ptr::from_ref(custody).cast::<()>(),
            restored_public_key,
            restored_key_generation: restored_generation,
            restored_key_generation_identity,
            restored_custody_identity: restored_custody,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
        })
    }

    /// Sole MSG-13-to-live-authority bridge.  This intentionally contains one
    /// call to the ingress-consumption verifier and performs no I/O; all
    /// historical resolution remains inert until this exact value is minted.
    fn begin_restore_successor_v1<'authority, 'store>(
        &self,
        authority: &'authority StoreC2AuthoritySnapshotV1<'store>,
        admitted_manifest: &'authority StoreAdmittedSignerImplementationManifestV1<
            'authority,
            'store,
        >,
        durable_current: &StoreResolvedGenerationCurrentEvidenceV1,
        adopted: StoreAdoptedRestoreAuthorizationV1,
        basis: StoreResolvedRestoreEntryBasisV1,
    ) -> Result<StoreVerifiedRestoreEntryAuthorityV1<'authority, 'store>, C2DiscontinuityRefusalV1>
    {
        verify_restore_authorization_ingress_consumption(self, &adopted)?;
        self.verify_authority_lineage(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if basis.creator_pid != std::process::id()
            || basis.actor_instance_identity != self.actor_instance_identity
            || basis.actor_snapshot_identity != self.current_snapshot_identity
            || basis.actor_effect_epoch != self.effect_epoch
            || basis.durable_terminal_address != std::ptr::from_ref(durable_current).cast::<()>()
            || basis.coordinates.request_identity != *adopted.verified().request_identity().bytes()
            || self.durable_append_pair.is_none()
            || self.generation_lock.is_none()
        {
            return Err(C2DiscontinuityRefusalV1::StaleOrConsumed);
        }
        Ok(StoreVerifiedRestoreEntryAuthorityV1 {
            authority_snapshot: authority,
            admitted_manifest,
            adopted,
            historical: basis.historical,
            coordinates: basis.coordinates,
            custody_address: basis.custody_address,
            restored_public_key: basis.restored_public_key,
            restored_key_generation: basis.restored_key_generation,
            restored_key_generation_identity: basis.restored_key_generation_identity,
            restored_custody_identity: basis.restored_custody_identity,
            actor_instance_identity: basis.actor_instance_identity,
            actor_snapshot_identity: basis.actor_snapshot_identity,
            actor_effect_epoch: basis.actor_effect_epoch,
            creator_pid: basis.creator_pid,
        })
    }

    /// Resolve one exact MSG-15 predecessor-unavailability occurrence and a
    /// semantically new custody basis.  The external grant and new key remain
    /// evidence until the nominal recovery-entry constructor consumes both
    /// this basis and the Store-adopted grant.
    fn resolve_recovery_entry_basis_v1<'manifest, 'store>(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'manifest, 'store>,
        durable_current: &StoreResolvedGenerationCurrentEvidenceV1,
        eligibility: &StoreVerifiedDiscontinuityEligibilityV1,
        adopted: &StoreAdoptedRecoveryGrantV1,
        custody: &VerifiedFoundationalCustodyV1<'_>,
    ) -> Result<StoreResolvedRecoveryEntryBasisV1, C2DiscontinuityRefusalV1> {
        self.verify_same_snapshot()?;
        self.verify_authority_lineage(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        self.verify_discontinuity_eligibility_for_entry_v1(
            eligibility,
            C2LiveFoundationalLineageV1::RecoveryNewFoundation,
            durable_current,
        )?;
        custody.verify_same_process()?;
        let request = adopted.verified().request();
        let carrier = adopted.verified().carrier();
        let current_binding_identity = digest_identity_bytes(durable_current.current.binding_id())?;
        let physical_generation_identity =
            digest_identity_bytes(&durable_current.physical_generation_identity)?;
        let lifecycle_root_identity =
            digest_text_identity(durable_current.root.lifecycle_root_id())?;
        let current_scope_identity = digest_text_identity(durable_current.root.scope_id())?;
        let current_standing_identity =
            digest_text_identity(durable_current.current.standing_id())?;
        let predecessor_enrollment_identity = digest_identity_bytes(
            durable_current
                .durable_terminal
                .enrollment()
                .acceptance()
                .identity(),
        )?;
        let predecessor_key_generation = durable_current
            .current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        let predecessor_key_generation_identity = digest_fields_bytes(
            b"nq.c2.store_integrity_stable_key_generation.identity.v1\0",
            &[
                &durable_current.current_public_key,
                &predecessor_key_generation.to_be_bytes(),
            ],
        );
        let active_policy_identity = digest_text_identity(durable_current.current.policy_id())?;
        let role_manifest_generation = durable_current
            .root
            .role_manifest_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        let predecessor_enrollment_digest =
            identity_digest_from_bytes(predecessor_enrollment_identity)?;
        let historical = load_verified_durable_signer_enrollment_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &predecessor_enrollment_digest,
        )
        .map_err(|_| C2DiscontinuityRefusalV1::HistoricalFoundationMissing)?;
        let successor_public_key = custody.public_key();
        let successor_key_generation = custody.key_generation();
        let successor_custody = custody.custody_evidence_identity().clone();
        let successor_proposal =
            discontinuity_identity_field(request.field("successor_proposal_identity"))?;
        let successor_challenge =
            discontinuity_identity_field(request.field("successor_pop_challenge_identity"))?;
        let request_identity = *adopted.verified().request_identity().bytes();
        let authority_identity = *adopted.verified().carrier_identity().bytes();
        let recovery_transition =
            discontinuity_identity_field(request.field("recovery_successor_projection_identity"))?;
        let recovery_cut = discontinuity_u64_field(request.field("proposed_effect_cut"))?;
        let expected_current = [
            (
                request.field("physical_store_generation_identity"),
                physical_generation_identity,
            ),
            (
                request.field("signer_lifecycle_root_identity"),
                lifecycle_root_identity,
            ),
            (request.field("scope_identity"), current_scope_identity),
            (
                request.field("recovery_predecessor_binding_identity"),
                current_binding_identity,
            ),
            (
                request.field("predecessor_enrollment_identity"),
                predecessor_enrollment_identity,
            ),
            (
                request.field("predecessor_standing_identity"),
                current_standing_identity,
            ),
        ];
        let request_predecessor_public_key =
            discontinuity_public_key_field(request.field("predecessor_public_key"))?;
        let request_predecessor_generation =
            discontinuity_u64_field(request.field("predecessor_key_generation"))?;
        let request_successor_public_key =
            discontinuity_public_key_field(request.field("successor_public_key"))?;
        let request_successor_generation =
            discontinuity_u64_field(request.field("successor_key_generation"))?;
        let request_successor_custody =
            discontinuity_digest_field(request.field("successor_custody_binding_identity"))?;
        let predecessor_status = request
            .field("predecessor_status")
            .and_then(Value::as_str)
            .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let new_key_generation_identity = digest_fields_bytes(
            b"nq.c2.store_integrity_stable_key_generation.identity.v1\0",
            &[
                &successor_public_key,
                &successor_key_generation.to_be_bytes(),
            ],
        );
        let old_key_generation_identity = digest_fields_bytes(
            b"nq.c2.store_integrity_stable_key_generation.identity.v1\0",
            &[
                &historical.foundation().public_key()?,
                &historical.foundation().key_generation().to_be_bytes(),
            ],
        );
        let successor_custody_bytes = digest_identity_bytes(&successor_custody)?;
        let reused_foundation_count: u64 = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .query_row(
                "SELECT COUNT(*) FROM c2_signer_foundations
                 WHERE public_key = ?1
                   AND key_generation = ?2
                   AND custody_evidence_identity = ?3",
                params![
                    &successor_public_key[..],
                    successor_key_generation,
                    &successor_custody_bytes[..],
                ],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
            .map_err(C2LiveSignerRefusalV1::from)?;
        if expected_current.into_iter().any(|(field, expected)| {
            !discontinuity_identity_field(field).is_ok_and(|actual| actual == expected)
        }) || request_predecessor_public_key != durable_current.current_public_key
            || request_predecessor_generation != predecessor_key_generation
            || request_successor_public_key != successor_public_key
            || request_successor_generation != successor_key_generation
            || request_successor_custody != successor_custody
            || digest_identity_bytes(custody.proposal_identity())? != successor_proposal
            || request
                .field("successor_pop_family")
                .and_then(Value::as_str)
                != Some("nq.c2_store_integrity_successor_pop.v1")
            || request.field("disposition").and_then(Value::as_str) != Some("recovery_authorized")
            || !matches!(
                (&eligibility.condition, predecessor_status),
                (
                    StoreVerifiedDiscontinuityConditionV1::OrdinaryContinuityUnavailable,
                    "active_lost"
                ) | (
                    StoreVerifiedDiscontinuityConditionV1::GovernedCurrentSignerRevocation { .. },
                    "inactive_revoked"
                )
            )
            || recovery_cut <= durable_current.event_cut
            || durable_current.occurrence_id != authority.current_activation().occurrence_id()
            || durable_current.root.resident_id()
                != authority.current_activation().resident_identity()
            || durable_current.resident_generation
                != authority.current_activation().resident_generation()
            || durable_current.root.role_id() != authority.current_activation().host_role()
            || role_manifest_generation != authority.current_activation().role_manifest_generation()
            || durable_current.root.domain_id() != authority.current_activation().domain()
            || custody.scope_identity() != current_scope_identity
        {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        if successor_public_key == historical.foundation().public_key()?
            || successor_custody == *historical.foundation().custody_evidence_identity()
            || new_key_generation_identity == old_key_generation_identity
            || reused_foundation_count != 0
        {
            return Err(C2DiscontinuityRefusalV1::RecoveryFoundationNotNew);
        }
        let recovery_condition_identity = eligibility.condition_identity;
        let transaction_identity = digest_fields_bytes(
            b"nq.c2.recovery.foundation_transaction.identity.v1\0",
            &[
                &request_identity,
                &authority_identity,
                &recovery_condition_identity,
                &successor_proposal,
                self.current_snapshot_identity.as_str().as_bytes(),
            ],
        );
        // Recovery uses the same strict discontinuity cut schedule as
        // restore: MSG-07 at R+1, adoption at R+2, acceptance at R+3.
        let (_, foundation_enrollment_cut, _, _, _) =
            discontinuity_cut_schedule_v1(recovery_cut)
                .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let candidate_identity = digest_fields_bytes(
            b"nq.c2.recovery.successor_candidate.identity.v1\0",
            &[
                &successor_proposal,
                &successor_challenge,
                &successor_public_key,
                &successor_key_generation.to_be_bytes(),
                successor_custody.as_str().as_bytes(),
            ],
        );
        let coordinates = C2DiscontinuityEntryCoordinatesV1 {
            occurrence_id: durable_current.occurrence_id.clone(),
            occurrence_identity: text_identity_bytes(
                b"nq.c2.store_occurrence.identity.v1\0",
                &durable_current.occurrence_id,
            ),
            resident_identity: durable_current.root.resident_id().to_owned(),
            resident_generation: durable_current.resident_generation,
            host_role: durable_current.root.role_id().to_owned(),
            role_manifest_identity: durable_current.role_manifest_identity,
            role_manifest_generation,
            authority_domain: durable_current.root.domain_id().to_owned(),
            terminal_a1_identity: digest_identity_bytes(
                authority
                    .resolved
                    .terminal_operator_authority()
                    .record_digest(),
            )?,
            current_a2_identity: digest_identity_bytes(
                authority
                    .current_activation()
                    .controlling_tip_activation_digest(),
            )?,
            physical_generation_identity,
            lifecycle_root_identity,
            frontier_identity: durable_current.frontier_identity,
            terminal_binding_identity: current_binding_identity,
            predecessor_enrollment_identity,
            predecessor_key_generation_identity,
            predecessor_standing_identity: current_standing_identity,
            signer_scope_identity: current_scope_identity,
            signer_scope_policy_identity: custody.signer_scope_policy_identity(),
            signer_scope_policy_version: custody.signer_scope_policy_version(),
            active_policy_identity,
            active_policy_generation: durable_current.active_policy_generation,
            policy_basis_identity: active_policy_identity,
            applicability_basis_identity: recovery_condition_identity,
            request_identity,
            transition_identity: recovery_transition,
            proposal_identity: successor_proposal,
            candidate_identity,
            challenge_identity: successor_challenge,
            attempt_identity: digest_fields_bytes(
                b"nq.c2.recovery.attempt.identity.v1\0",
                &[&request_identity, &successor_proposal, &recovery_transition],
            ),
            transaction_identity,
            exact_content_identity: digest_fields_bytes(
                b"nq.c2.recovery.entry.exact_content.v1\0",
                &[
                    carrier.canonical_bytes(),
                    request.canonical_bytes(),
                    &successor_public_key,
                ],
            ),
            qualified_candidate_identity: digest_identity_bytes(
                admitted_manifest.qualified_candidate_identity(),
            )?,
            source_tree_identity: digest_identity_bytes(admitted_manifest.source_tree_identity())?,
            runtime_artifact_identity: digest_identity_bytes(
                admitted_manifest.runtime_artifact_identity(),
            )?,
            implementation_manifest_identity: digest_identity_bytes(
                admitted_manifest.manifest_identity(),
            )?,
            manifest_admission_correspondence_identity: digest_identity_bytes(
                &admitted_manifest.correspondence_identity(),
            )?,
            entry_cut: recovery_cut,
            foundation_enrollment_cut,
        };
        Ok(StoreResolvedRecoveryEntryBasisV1 {
            historical,
            coordinates,
            durable_terminal_address: std::ptr::from_ref(durable_current).cast::<()>(),
            custody_address: std::ptr::from_ref(custody).cast::<()>(),
            successor_public_key,
            successor_key_generation,
            successor_key_generation_identity: new_key_generation_identity,
            successor_custody_identity: successor_custody,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
        })
    }

    /// Sole MSG-15-to-live-authority bridge.  Restore and recovery are
    /// nominally distinct, so neither authority can be substituted here.
    fn begin_recovery_entry_v1<'authority, 'store>(
        &self,
        authority: &'authority StoreC2AuthoritySnapshotV1<'store>,
        admitted_manifest: &'authority StoreAdmittedSignerImplementationManifestV1<
            'authority,
            'store,
        >,
        durable_current: &StoreResolvedGenerationCurrentEvidenceV1,
        adopted: StoreAdoptedRecoveryGrantV1,
        basis: StoreResolvedRecoveryEntryBasisV1,
    ) -> Result<StoreVerifiedRecoveryEntryAuthorityV1<'authority, 'store>, C2DiscontinuityRefusalV1>
    {
        verify_recovery_grant_ingress_consumption(self, &adopted)?;
        self.verify_authority_lineage(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if basis.creator_pid != std::process::id()
            || basis.actor_instance_identity != self.actor_instance_identity
            || basis.actor_snapshot_identity != self.current_snapshot_identity
            || basis.actor_effect_epoch != self.effect_epoch
            || basis.durable_terminal_address != std::ptr::from_ref(durable_current).cast::<()>()
            || basis.coordinates.request_identity != *adopted.verified().request_identity().bytes()
            || self.durable_append_pair.is_none()
            || self.generation_lock.is_none()
        {
            return Err(C2DiscontinuityRefusalV1::StaleOrConsumed);
        }
        Ok(StoreVerifiedRecoveryEntryAuthorityV1 {
            authority_snapshot: authority,
            admitted_manifest,
            adopted,
            historical: basis.historical,
            coordinates: basis.coordinates,
            custody_address: basis.custody_address,
            successor_public_key: basis.successor_public_key,
            successor_key_generation: basis.successor_key_generation,
            successor_key_generation_identity: basis.successor_key_generation_identity,
            successor_custody_identity: basis.successor_custody_identity,
            actor_instance_identity: basis.actor_instance_identity,
            actor_snapshot_identity: basis.actor_snapshot_identity,
            actor_effect_epoch: basis.actor_effect_epoch,
            creator_pid: basis.creator_pid,
        })
    }
}

/// Borrowed, one-way projection consumed by typed route constructors.
///
/// Possessing this view does not permit phase conversion and copied accessor
/// results do not reconstruct standing.  It is intentionally not Clone/Copy.
pub(crate) struct C2LiveSigningViewV1<'view, 'live, 'store, Phase> {
    context: &'view C2LiveSignerContextV1<'live, 'store, Phase>,
    scope_projection: Option<C2LiveSigningScopeV1>,
    authority_projection: Option<C2LiveSigningAuthorityV1>,
}

/// Linear proof that the actor rechecked one exact live view immediately
/// before opening the signer-append transaction boundary.
///
/// Custody accepts this permit instead of accepting the actor or a Boolean.
/// It is borrowed, noncloneable, nonserializable, and valid only for the
/// callback in `StoreC2SnapshotActorV1::with_signer_append_effect`.
pub(crate) struct StoreC2SignerAppendPermitV1<'permit, 'live, 'store, Phase> {
    live: &'permit C2LiveSigningViewV1<'permit, 'live, 'store, Phase>,
    actor_instance_identity: Sha256Digest,
    snapshot_identity: Sha256Digest,
    effect_epoch: u64,
}

/// Lexical Store authority for MSG-02, the sole signing path that exists
/// before live signer standing.
///
/// It is bound to one exact Store-minted possession request and actor epoch;
/// copied candidate/custody/frontier coordinates cannot construct it.
pub(crate) struct StoreC2InitialPossessionAppendPermitV1<'request, 'store> {
    request: &'request VerifiedInitialPossessionRequestV1<'request, 'store>,
    actor_instance_identity: Sha256Digest,
    snapshot_identity: Sha256Digest,
    effect_epoch: u64,
}

impl<'request, 'store> StoreC2InitialPossessionAppendPermitV1<'request, 'store> {
    pub(crate) fn verify_request(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        request: &VerifiedInitialPossessionRequestV1<'_, '_>,
    ) -> Result<(), SignerRefusalV2> {
        request.verify_for_actor(actor)?;
        if std::ptr::from_ref(self.request).cast::<()>() != std::ptr::from_ref(request).cast::<()>()
            || self.actor_instance_identity != *actor.actor_instance_identity()
            || self.snapshot_identity != *actor.current_snapshot_identity()
            || self.effect_epoch != actor.effect_epoch()
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub(crate) const fn request(
        &self,
    ) -> &'request VerifiedInitialPossessionRequestV1<'request, 'store> {
        self.request
    }
}

impl<Phase> StoreC2SignerAppendPermitV1<'_, '_, '_, Phase> {
    pub(crate) fn verify_live_view(
        &self,
        live: &C2LiveSigningViewV1<'_, '_, '_, Phase>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        // Cast away only the invariant lifetime parameters before comparing
        // addresses.  The permit still borrows the exact context for the
        // callback lifetime; copied coordinates cannot satisfy this check.
        if std::ptr::from_ref(self.live.context).cast::<()>()
            != std::ptr::from_ref(live.context).cast::<()>()
            || self.actor_instance_identity != live.context.actor_instance_identity
            || self.snapshot_identity != live.context.actor_snapshot_identity
            || self.effect_epoch != live.context.actor_effect_epoch
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }
}

/// Typed union preserving whether an atomic sign/append attempt failed at the
/// Store live-authority boundary or inside the closed signer vocabulary.
#[derive(Debug, Error)]
pub(crate) enum C2SignerAppendRefusalV1 {
    #[error("live C2 signer authority refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("typed C2 signer operation refused: {0}")]
    Signer(#[from] SignerRefusalV2),
    #[error("the same replay occurrence carried changed canonical content")]
    ChangedContentCollision,
    #[error("the durable signer sequence or frontier is not the exact successor")]
    SequenceOrFrontierGap,
    #[error("the durable signer append transaction failed: {0}")]
    DurableStore(StoreError),
    #[error("the authenticated physical B/G append refused: {0}")]
    PhysicalCarrier(#[from] C2AppendExtentRefusalV1),
    #[error("the authenticated physical B/G append pair is absent")]
    PhysicalCarrierUnavailable,
}

/// Closed error union for the two one-way durable enrollment transitions.
///
/// A refusal never returns either the prepared durable record or a sealed
/// adoption/acceptance wrapper, so failure cannot be used to recover a live
/// authority value from inert enrollment evidence.
#[derive(Debug, Error)]
pub(crate) enum C2EnrollmentBridgeRefusalV1 {
    #[error("live C2 Store correspondence refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("C2 enrollment transition refused: {0}")]
    Signer(#[from] SignerRefusalV2),
}

/// Closed refusal surface for the one fresh Store-owned C2 installation
/// driver. Every variant is inert; an error cannot return a descriptor,
/// permit, live phase, prepared frame, or partially consumed authority value.
#[derive(Debug, Error)]
pub(crate) enum C2LiveInstallationDriverRefusalV1 {
    #[error("live C2 correspondence refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("fixed C2 installation I/O refused: {0}")]
    Installation(#[from] C2LiveInstallationRefusalV1),
    #[error("C2 backend/profile correspondence refused: {0}")]
    Backend(#[from] C2BackendRefusalV1),
    #[error("C2 append carrier correspondence refused: {0}")]
    Append(#[from] C2AppendExtentRefusalV1),
    #[error("C2 permanent generation lock refused: {0}")]
    Lock(#[from] C2StoreGenerationLockErrorV1),
    #[error("typed C2 signing/append refused: {0}")]
    Signer(#[from] C2SignerAppendRefusalV1),
    #[error("the install policy, accepted enrollment, or derived generation facts disagree")]
    ContractMismatch,
    #[error("the durable C2 installation projection failed: {0}")]
    Durable(#[from] StoreError),
    #[error("the C2 installation projection could not be canonicalized")]
    Canonicalization,
}

/// Closed refusal surface for the sole complete-generation reopen root.
/// Distinct manifest admission, Store/process, and lifecycle/physical
/// failures remain observable; no refusal contains a live capability.
#[derive(Debug, Error)]
pub(crate) enum C2LiveReopenRefusalV1 {
    #[error("live C2 Store/process admission refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("signer implementation-manifest admission refused: {0}")]
    Manifest(#[from] SignerImplementationManifestRefusalV1),
    #[error("complete-generation lifecycle reopen refused: {0}")]
    Lifecycle(#[from] C2LiveInstallationDriverRefusalV1),
}

/// Closed refusal surface for the two bounded fresh-bootstrap roots: prepare
/// the asynchronous MSG-01 request, then resume its exact durable preparation
/// and run the sole Store-owned bootstrap/install path.
#[derive(Debug, Error)]
pub(crate) enum C2LiveBootstrapDriverRefusalV1 {
    #[error("live C2 Store/process admission refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("signer implementation-manifest admission refused: {0}")]
    Manifest(#[from] SignerImplementationManifestRefusalV1),
    #[error("custody/request preparation refused: {0}")]
    Custody(#[from] C2CustodyPreparationRefusalV1),
    #[error("terminal-A1 bootstrap grant refused: {0}")]
    Grant(#[from] C2GovernedCarrierIngressRefusalV1),
    #[error("initial possession signing refused: {0}")]
    Possession(#[from] C2SignerAppendRefusalV1),
    #[error("foundational/signer enrollment refused: {0}")]
    Enrollment(#[from] C2EnrollmentBridgeRefusalV1),
    #[error("live C2 installation refused: {0}")]
    Installation(#[from] C2LiveInstallationDriverRefusalV1),
}

/// Closed refusal surface for the three post-bootstrap lifecycle roots.
/// No variant carries a live phase, authority token, custodian, or prepared
/// mutation, so a refused transition cannot be resumed from caller-held
/// scalar evidence.
#[derive(Debug, Error)]
pub(crate) enum C2LiveTransitionDriverRefusalV1 {
    #[error("live C2 Store/process correspondence refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("signer implementation-manifest admission refused: {0}")]
    Manifest(#[from] SignerImplementationManifestRefusalV1),
    #[error("custody preparation/reopen refused: {0}")]
    Custody(#[from] C2CustodyPreparationRefusalV1),
    #[error("typed signer append refused: {0}")]
    Signer(#[from] C2SignerAppendRefusalV1),
    #[error("successor MSG-07 possession append refused: {0}")]
    SuccessorPossession(C2SignerAppendRefusalV1),
    #[error("healthy predecessor continuity/transition append refused: {0}")]
    HealthyContinuity(C2SignerAppendRefusalV1),
    #[error("pending-successor MSG-12 append refused: {0}")]
    PendingReceipt(C2SignerAppendRefusalV1),
    #[error("external discontinuity carrier ingress refused: {0}")]
    Governance(#[from] C2GovernedCarrierIngressRefusalV1),
    #[error("typed signer semantic construction refused: {0}")]
    SignerSemantic(#[from] SignerRefusalV2),
    #[error("foundational enrollment/acceptance refused: {0}")]
    Enrollment(#[from] C2EnrollmentBridgeRefusalV1),
    #[error("discontinuity entry refused: {0}")]
    Discontinuity(#[from] C2DiscontinuityRefusalV1),
    #[error("completed signer lineage refused: {0}")]
    Lineage(#[from] LineageRefusalV1),
    #[error("durable successor terminal refused: {0}")]
    Terminal(#[from] DurableTerminalAppendRefusalV1),
    #[error("physical C2 substrate/reopen refused: {0}")]
    Substrate(#[from] C2LiveInstallationDriverRefusalV1),
    #[error("durable Store transition failed: {0}")]
    Store(#[from] StoreError),
}

impl From<io::Error> for C2LiveTransitionDriverRefusalV1 {
    fn from(error: io::Error) -> Self {
        Self::Live(C2LiveSignerRefusalV1::Io(error))
    }
}

impl From<StoreError> for C2LiveBootstrapDriverRefusalV1 {
    fn from(error: StoreError) -> Self {
        Self::Live(C2LiveSignerRefusalV1::Store(error))
    }
}

impl From<io::Error> for C2LiveBootstrapDriverRefusalV1 {
    fn from(error: io::Error) -> Self {
        Self::Live(C2LiveSignerRefusalV1::Io(error))
    }
}

impl From<StoreError> for C2LiveReopenRefusalV1 {
    fn from(error: StoreError) -> Self {
        Self::Live(C2LiveSignerRefusalV1::Store(error))
    }
}

impl From<io::Error> for C2LiveReopenRefusalV1 {
    fn from(error: io::Error) -> Self {
        Self::Live(C2LiveSignerRefusalV1::Io(error))
    }
}

/// Closed error union for terminal-A1 verification plus durable governed
/// carrier ingress.  No refusal carries a permit or live Store value.
#[derive(Debug, Error)]
pub(crate) enum C2GovernedCarrierIngressRefusalV1 {
    #[error("live C2 Store correspondence refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("terminal-A1 governed carrier verification refused: {0}")]
    Signer(#[from] SignerRefusalV2),
    #[error("durable governed carrier ingress refused: {0}")]
    Durable(#[from] C2ExternalIngressRefusalV1),
}

/// Closed refusal surface for consequence-bearing restore/recovery entry.
/// These classifications are intentionally distinct from carrier decoding:
/// a perfectly authentic MSG-13/15 remains inert when the current Store,
/// lineage, custody, or discontinuity premises do not match.
#[derive(Debug, Error)]
pub(crate) enum C2DiscontinuityRefusalV1 {
    #[error("live C2 Store correspondence refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("typed signer evidence refused: {0}")]
    Signer(#[from] SignerRefusalV2),
    #[error("the requested historical signer foundation is absent")]
    HistoricalFoundationMissing,
    #[error("the historical terminal binding is absent, ambiguous, or superseded")]
    HistoricalTerminalMismatch,
    #[error("the requested historical foundation is not exactly reusable")]
    HistoricalFoundationReuseMismatch,
    #[error("recovery did not establish a semantically new key/custody foundation")]
    RecoveryFoundationNotNew,
    #[error("ordinary current-predecessor continuity may not be bypassed by this route")]
    OrdinaryContinuityRequired,
    #[error("restore lacks an exact Store-derived discontinuity condition")]
    RestoreEligibilityAbsent,
    #[error("recovery lacks the exact Store-derived predecessor-unavailability condition")]
    RecoveryEligibilityAbsent,
    #[error("the discontinuity route, request, lineage, or occurrence was substituted")]
    RouteOrLineageMismatch,
    #[error("the discontinuity entry was stale, replayed, or already consumed")]
    StaleOrConsumed,
}

/// Closed refusal surface for asynchronous Store-owned custody/request
/// preparation.  A refusal commits no durable preparation row; a
/// filesystem-first orphan remains detectable by the next exact frontier
/// enumeration and cannot be silently reused.
#[derive(Debug, Error)]
pub(crate) enum C2CustodyPreparationRefusalV1 {
    #[error("live C2 Store correspondence refused: {0}")]
    Live(#[from] C2LiveSignerRefusalV1),
    #[error("custody or canonical request preparation refused: {0}")]
    Signer(#[from] SignerRefusalV2),
    #[error("durable custody frontier operation refused: {0}")]
    Store(#[from] StoreError),
}

impl From<rusqlite::Error> for C2CustodyPreparationRefusalV1 {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(StoreError::from(error))
    }
}

/// Same-snapshot adapter over the authority resolver's unique terminal A1.
///
/// The adapter borrows the resolver result retained by the Store actor; it
/// cannot be constructed from a carrier's own issuer claim.
pub(in crate::store_generation) struct StoreTerminalA1VerifierV1<'authority> {
    resolved: &'authority ControllingActivationSnapshot,
}

impl TerminalA1AuthenticityVerifierV1 for StoreTerminalA1VerifierV1<'_> {
    fn verify_unique_terminal_a1(
        &self,
        claim: &TerminalA1IssuerClaimV1,
    ) -> Result<(), SignerRefusalV2> {
        let terminal = self.resolved.terminal_operator_authority();
        if claim.digest != terminal.record_digest().as_str()
            || claim.key_generation != terminal.key_generation()
            || claim.verification_key != *terminal.verification_key()
            || claim.operator_principal != terminal.operator_principal()
            || claim.domain != terminal.domain()
            || claim.policy_version != terminal.policy_version()
            || claim.policy_floor != terminal.policy_floor()
            || claim.issued_against_gen4_cut != terminal.cut().sequence()
            || claim.issued_against_terminal_event
                != self.resolved.terminal_authority_event_digest().as_str()
            || claim.issued_against_candidate_set != self.resolved.candidate_set_digest().as_str()
        {
            return Err(SignerRefusalV2::WrongTerminalA1Issuer);
        }
        Ok(())
    }
}

/// Exact durable append outcome; exact replay is distinct from a new write
/// and can never carry changed canonical content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C2SignerAppendDispositionV1 {
    Appended,
    ExactReplay,
}

impl<'live, 'store, Phase> C2LiveSignerContextV1<'live, 'store, Phase> {
    /// One-way borrow of the exact custodian already sealed into this live
    /// context. Copied key/scope coordinates cannot select another object.
    pub(in crate::store_generation) fn retained_custodian(
        &self,
    ) -> &'live C2StoreIntegrityCustodian {
        self.foundational_custody.retained_custodian()
    }

    pub(crate) fn signing_view(&self) -> C2LiveSigningViewV1<'_, 'live, 'store, Phase> {
        C2LiveSigningViewV1 {
            context: self,
            scope_projection: None,
            authority_projection: None,
        }
    }

    pub(crate) fn verify_live(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        actor.verify_same_snapshot()?;
        self.authority_snapshot.verify_same_process_and_snapshot()?;
        self.authority_snapshot
            .admission_basis()
            .verify_same_process()?;
        if self.creator_pid != std::process::id()
            || self.actor_instance_identity != actor.actor_instance_identity
            || self.actor_snapshot_identity != actor.current_snapshot_identity
            || self.actor_effect_epoch != actor.effect_epoch
            || self.admitted_manifest.process_identity()
                != self.authority_snapshot.admission_basis().process_identity()
            || self.admitted_manifest.store_snapshot_identity()
                != self
                    .authority_snapshot
                    .admission_basis()
                    .store_snapshot_identity()
            || self.admitted_manifest.manifest_identity()
                != self
                    .authority_snapshot
                    .admission_basis()
                    .qualified_manifest_identity()
            || self.foundational_custody.verify_same_process().is_err()
            || self.foundational_custody.public_key() != self.coordinates.signer_public_key
            || self.foundational_custody.key_generation() != self.coordinates.signer_key_generation
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }
}

impl<'live, 'store> C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1> {
    /// One-way request projection used only by MSG-05, MSG-06, and MSG-11.
    ///
    /// The current generation is still the same sealed Store correspondence;
    /// this view merely restricts its signing role to "current predecessor".
    /// There is no inverse projection and no scalar constructor, so a digest
    /// container cannot acquire predecessor authority by changing a tag.
    pub(crate) fn current_predecessor_signing_view(
        &self,
    ) -> C2LiveSigningViewV1<'_, 'live, 'store, GenerationCurrentV1> {
        C2LiveSigningViewV1 {
            context: self,
            scope_projection: None,
            authority_projection: Some(C2LiveSigningAuthorityV1::CurrentPredecessor),
        }
    }
}

impl<'live, 'store> C2LiveSignerContextV1<'live, 'store, BootstrapV1> {
    /// Restricted pre-generation request view for MSG-09.
    pub(crate) fn installation_intent_signing_view(
        &self,
    ) -> C2LiveSigningViewV1<'_, 'live, 'store, BootstrapV1> {
        C2LiveSigningViewV1 {
            context: self,
            scope_projection: Some(C2LiveSigningScopeV1::PreGeneration),
            authority_projection: None,
        }
    }

    /// Restricted prospective-generation view for MSG-03 and MSG-10.
    pub(crate) fn prospective_generation_signing_view(
        &self,
    ) -> C2LiveSigningViewV1<'_, 'live, 'store, BootstrapV1> {
        C2LiveSigningViewV1 {
            context: self,
            scope_projection: Some(C2LiveSigningScopeV1::ProspectivePhysicalGeneration),
            authority_projection: None,
        }
    }
}

impl<Phase> C2LiveSigningViewV1<'_, '_, '_, Phase> {
    #[must_use]
    pub(crate) fn phase(&self) -> C2LiveSigningPhaseV1 {
        self.context.phase
    }

    #[must_use]
    pub(crate) fn scope_class(&self) -> C2LiveSigningScopeV1 {
        self.scope_projection
            .unwrap_or(self.context.coordinates.scope_class)
    }

    #[must_use]
    pub(crate) fn authority_class(&self) -> C2LiveSigningAuthorityV1 {
        self.authority_projection
            .unwrap_or(self.context.coordinates.authority_class)
    }

    #[must_use]
    pub(crate) fn occurrence_id(&self) -> &str {
        &self.context.coordinates.occurrence_id
    }

    #[must_use]
    pub(crate) fn occurrence_identity(&self) -> [u8; 32] {
        self.context.coordinates.occurrence_identity
    }

    #[must_use]
    pub(crate) fn resident_identity(&self) -> &str {
        &self.context.coordinates.resident_identity
    }

    #[must_use]
    pub(crate) fn resident_generation(&self) -> u64 {
        self.context.coordinates.resident_generation
    }

    #[must_use]
    pub(crate) fn host_role(&self) -> &str {
        &self.context.coordinates.host_role
    }

    #[must_use]
    pub(crate) fn role_manifest_identity(&self) -> [u8; 32] {
        self.context.coordinates.role_manifest_identity
    }

    #[must_use]
    pub(crate) fn role_manifest_generation(&self) -> u64 {
        self.context.coordinates.role_manifest_generation
    }

    #[must_use]
    pub(crate) fn authority_domain(&self) -> &str {
        &self.context.coordinates.authority_domain
    }

    #[must_use]
    pub(crate) fn terminal_a1_identity(&self) -> [u8; 32] {
        self.context.coordinates.terminal_a1_identity
    }

    #[must_use]
    pub(crate) fn current_a2_identity(&self) -> [u8; 32] {
        self.context.coordinates.current_a2_identity
    }

    #[must_use]
    pub(crate) fn grant_identity(&self) -> Option<[u8; 32]> {
        self.context.coordinates.grant_identity
    }

    #[must_use]
    pub(crate) fn predecessor_standing_identity(&self) -> Option<[u8; 32]> {
        self.context.coordinates.predecessor_standing_identity
    }

    #[must_use]
    pub(crate) fn standing_identity(&self) -> [u8; 32] {
        self.context.coordinates.standing_identity
    }

    #[must_use]
    pub(crate) fn signer_public_key(&self) -> [u8; 32] {
        self.context.coordinates.signer_public_key
    }

    #[must_use]
    pub(crate) fn signer_key_generation(&self) -> u64 {
        self.context.coordinates.signer_key_generation
    }

    #[must_use]
    pub(crate) fn signer_key_generation_identity(&self) -> [u8; 32] {
        self.context.coordinates.signer_key_generation_identity
    }

    #[must_use]
    pub(crate) fn signer_scope_identity(&self) -> [u8; 32] {
        self.context.coordinates.signer_scope_identity
    }

    #[must_use]
    pub(crate) fn signer_scope_policy_identity(&self) -> [u8; 32] {
        self.context.coordinates.signer_scope_policy_identity
    }

    #[must_use]
    pub(crate) fn signer_scope_policy_version(&self) -> u64 {
        self.context.coordinates.signer_scope_policy_version
    }

    #[must_use]
    pub(crate) fn active_policy_identity(&self) -> [u8; 32] {
        self.context.coordinates.active_policy_identity
    }

    #[must_use]
    pub(crate) fn active_policy_generation(&self) -> u64 {
        self.context.coordinates.active_policy_generation
    }

    #[must_use]
    pub(crate) fn active_policy_digest(&self) -> [u8; 32] {
        self.context.coordinates.active_policy_digest
    }

    #[must_use]
    pub(crate) fn attempt_identity(&self) -> [u8; 32] {
        self.context.coordinates.attempt_identity
    }

    #[must_use]
    pub(crate) fn physical_generation_identity(&self) -> Option<[u8; 32]> {
        match self.scope_class() {
            // A pre-generation projection must not acquire the physical
            // generation that the installation actor may already have fixed
            // locally for a later route.  In particular MSG-09 remains the
            // exact pre-generation intent even though MSG-03 is prepared in
            // the same Store-owned installation operation.
            C2LiveSigningScopeV1::PreGeneration => None,
            C2LiveSigningScopeV1::ProspectivePhysicalGeneration
            | C2LiveSigningScopeV1::GenerationBound => {
                self.context.coordinates.physical_generation_identity
            }
        }
    }

    #[must_use]
    pub(crate) fn prospective_generation_preimage_identity(&self) -> Option<[u8; 32]> {
        match self.scope_class() {
            C2LiveSigningScopeV1::ProspectivePhysicalGeneration => {
                self.context
                    .coordinates
                    .prospective_generation_preimage_identity
            }
            C2LiveSigningScopeV1::PreGeneration | C2LiveSigningScopeV1::GenerationBound => None,
        }
    }

    #[must_use]
    pub(crate) fn lifecycle_root_identity(&self) -> Option<[u8; 32]> {
        match self.scope_class() {
            C2LiveSigningScopeV1::GenerationBound => {
                self.context.coordinates.lifecycle_root_identity
            }
            C2LiveSigningScopeV1::PreGeneration
            | C2LiveSigningScopeV1::ProspectivePhysicalGeneration => None,
        }
    }

    /// Exact terminal/current binding selected by the Store resolver.  It is
    /// absent before physical-generation currentness is established and is
    /// evidence only unless retained inside this live context.
    #[must_use]
    pub(crate) fn current_binding_identity(&self) -> Option<[u8; 32]> {
        self.context.coordinates.current_binding_identity
    }

    #[must_use]
    pub(crate) fn event_cut(&self) -> u64 {
        self.context.coordinates.event_cut
    }

    #[must_use]
    pub(crate) fn predecessor_event_identity(&self) -> Option<[u8; 32]> {
        self.context.coordinates.predecessor_event_identity
    }

    #[must_use]
    pub(crate) fn transition_intent_identity(&self) -> Option<[u8; 32]> {
        self.context.coordinates.transition_intent_identity
    }

    #[must_use]
    pub(crate) fn implementation_manifest_identity(&self) -> [u8; 32] {
        self.context.coordinates.implementation_manifest_identity
    }

    #[must_use]
    pub(crate) fn manifest_admission_correspondence_identity(&self) -> [u8; 32] {
        self.context
            .coordinates
            .manifest_admission_correspondence_identity
    }

    #[must_use]
    pub(crate) fn qualified_candidate_identity(&self) -> [u8; 32] {
        self.context.coordinates.qualified_candidate_identity
    }

    #[must_use]
    pub(crate) fn source_tree_identity(&self) -> [u8; 32] {
        self.context.coordinates.source_tree_identity
    }

    #[must_use]
    pub(crate) fn runtime_artifact_identity(&self) -> [u8; 32] {
        self.context.coordinates.runtime_artifact_identity
    }

    #[must_use]
    pub(crate) fn frontier_namespace_identity(&self) -> [u8; 32] {
        self.context.coordinates.frontier_namespace_identity
    }

    #[must_use]
    pub(crate) fn predecessor_frontier_identity(&self) -> [u8; 32] {
        self.context.coordinates.predecessor_frontier_identity
    }

    #[must_use]
    pub(crate) fn exact_content_identity(&self) -> [u8; 32] {
        self.context.coordinates.exact_content_identity
    }

    pub(crate) fn verify_live(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        self.context.verify_live(actor)
    }
}

impl StoreC2AdmissionBasisV1<'_> {
    #[must_use]
    pub(crate) const fn qualified_candidate_identity(&self) -> &Sha256Digest {
        &self.qualified.qualified_candidate_identity
    }

    #[must_use]
    pub(crate) const fn source_tree_identity(&self) -> &Sha256Digest {
        &self.qualified.source_tree_identity
    }

    #[must_use]
    pub(crate) const fn measured_runtime_artifact_identity(&self) -> &Sha256Digest {
        &self.snapshot.measured_runtime_artifact_identity
    }

    #[must_use]
    pub(crate) const fn qualified_manifest_identity(&self) -> &Sha256Digest {
        &self.qualified.qualified_manifest_identity
    }

    #[must_use]
    pub(crate) const fn qualification_evidence_identity(&self) -> &Sha256Digest {
        &self.qualified.qualification_evidence_identity
    }

    #[must_use]
    pub(crate) const fn store_snapshot_identity(&self) -> &Sha256Digest {
        &self.snapshot.store_snapshot_identity
    }

    #[must_use]
    pub(crate) const fn process_identity(&self) -> &Sha256Digest {
        &self.snapshot.process_identity
    }

    #[must_use]
    pub(crate) fn occurrence_id(&self) -> &str {
        &self.snapshot.occurrence_id
    }

    #[must_use]
    pub(crate) const fn store_instance_identity(&self) -> &Sha256Digest {
        &self.snapshot.store_instance_identity
    }

    /// Recheck the non-inheritable process premise.  A forked child inherits
    /// bytes but not this process identity because the PID is in the preimage.
    pub(crate) fn verify_same_process(&self) -> Result<(), C2LiveSignerRefusalV1> {
        if self.snapshot.creator_pid != std::process::id()
            || self.snapshot.process_identity != current_process_identity()?
        {
            return Err(C2LiveSignerRefusalV1::PriorProcessAuthority);
        }
        Ok(())
    }
}

/// Nonescaping Store actor retained for the complete live-C2 operation.
///
/// The immediate SQLite transaction prevents another Store writer from
/// advancing the enumerated snapshot.  The maintenance guard prevents a
/// second in-process/path installation actor and retains an OS-level flock on
/// the exact path.  The root descriptor is retained so later installation or
/// reopen verification resolves fixed children against one directory object.
/// Completed-generation operations additionally retain the permanent C2
/// generation lock through their closed-backend/live-phase correspondence.
pub(crate) struct StoreC2SnapshotActorV1<'store> {
    transaction: Option<Transaction<'store>>,
    _maintenance_guard: Vec<MaintenanceLockGuard>,
    root: File,
    database_file: File,
    database_path: PathBuf,
    database_device: u64,
    database_inode: u64,
    root_device: u64,
    root_inode: u64,
    initial_snapshot_identity: Sha256Digest,
    current_snapshot_identity: Sha256Digest,
    store_instance_identity: Sha256Digest,
    effect_transcript: Vec<Sha256Digest>,
    actor_instance_identity: Sha256Digest,
    effect_epoch: u64,
    process_identity: Sha256Digest,
    creator_pid: u32,
    poisoned: bool,
    durable_append_pair: Option<C2DurableAppendPairV1>,
    generation_lock: Option<C2StoreGenerationLockV1>,
}

/// Sole production writer capability for a complete live C2 generation.
///
/// Unlike the superseded scalar/closed-backend handoff, this session borrows
/// the exact Store actor and freshly minted `GenerationCurrent` brand.  The
/// retained transaction, root/database descriptors, permanent generation
/// lock, authenticated B/G pair, admitted manifest and custody therefore stay
/// alive for the whole operation.  No Store, transaction, descriptor, raw
/// digest, or generic signing surface is exposed to the callback.
pub(crate) struct C2LiveWriterSessionV1<'session, 'live, 'store> {
    actor: &'session mut StoreC2SnapshotActorV1<'store>,
    current: &'session mut C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
}

impl<'session, 'live, 'store> C2LiveWriterSessionV1<'session, 'live, 'store> {
    fn from_exact_generation_current(
        actor: &'session mut StoreC2SnapshotActorV1<'store>,
        current: &'session mut C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
    ) -> Result<Self, C2LiveSignerRefusalV1> {
        actor.verify_same_snapshot()?;
        current.verify_live(actor)?;
        let lock = actor
            .generation_lock
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if actor.durable_append_pair.is_none()
            || current.coordinates.physical_generation_identity
                != Some(digest_identity_bytes(
                    &lock.carrier().physical_store_generation_identity,
                )?)
            || current.coordinates.occurrence_id != lock.carrier().occurrence_id
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(Self { actor, current })
    }

    /// Purpose-typed current-predecessor signer lane (MSG-05/06/11). The
    /// callback receives only the lexical family-restricted permit/view; it
    /// cannot select raw bytes, a domain string, or a detached signature.
    pub(crate) fn with_current_predecessor_append(
        &mut self,
        prepare: impl FnOnce(
            &StoreC2SignerAppendPermitV1<'_, '_, '_, GenerationCurrentV1>,
            &C2LiveSigningViewV1<'_, '_, '_, GenerationCurrentV1>,
        ) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2>,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        self.actor
            .with_current_predecessor_append_effect(self.current, prepare)
    }

    /// Production ingress for the non-bootstrap MSG-01 activation-successor
    /// carrier. The authority snapshot is taken only from the sealed current
    /// context; no caller can select a Store/authority correspondence.
    pub(crate) fn adopt_activation_successor_grant(
        &mut self,
        request: &StoreIntegrityActivationSuccessorGrantRequestV1,
        grant: &StoreIntegrityActivationSuccessorGrantV1,
    ) -> Result<StoreAdoptedActivationSuccessorGrantV1, C2GovernedCarrierIngressRefusalV1> {
        let adopted = self.actor.adopt_activation_successor_grant_v1(
            self.current.authority_snapshot,
            request,
            grant,
        )?;
        self.actor
            .refresh_current_after_external_ingress_v1(self.current, adopted.durable_receipt())?;
        Ok(adopted)
    }

    pub(crate) fn adopt_proposal_disposition(
        &mut self,
        request: &StoreIntegrityProposalDispositionRequestV1,
        disposition: &StoreIntegrityProposalDispositionV1,
    ) -> Result<StoreAdoptedProposalDispositionV1, C2GovernedCarrierIngressRefusalV1> {
        self.actor.adopt_proposal_disposition_v1(
            self.current.authority_snapshot,
            request,
            disposition,
        )
    }

    pub(crate) fn adopt_restore_authorization(
        &mut self,
        request: &StoreIntegrityRestoreAuthorizationRequestV1,
        authorization: &StoreIntegrityRestoreAuthorizationV1,
    ) -> Result<StoreAdoptedRestoreAuthorizationV1, C2GovernedCarrierIngressRefusalV1> {
        let adopted = self.actor.adopt_restore_authorization_v1(
            self.current.authority_snapshot,
            request,
            authorization,
        )?;
        self.actor
            .refresh_current_after_external_ingress_v1(self.current, adopted.durable_receipt())?;
        Ok(adopted)
    }

    pub(crate) fn adopt_recovery_grant(
        &mut self,
        request: &StoreIntegrityRecoveryRequestV1,
        grant: &StoreIntegrityRecoveryGrantV1,
    ) -> Result<StoreAdoptedRecoveryGrantV1, C2GovernedCarrierIngressRefusalV1> {
        let adopted =
            self.actor
                .adopt_recovery_grant_v1(self.current.authority_snapshot, request, grant)?;
        self.actor
            .refresh_current_after_external_ingress_v1(self.current, adopted.durable_receipt())?;
        Ok(adopted)
    }

    pub(crate) fn apply_revocation_judgment(
        &mut self,
        request: &StoreIntegrityRevocationRequestV1,
        judgment: &StoreIntegrityRevocationJudgmentV1,
    ) -> Result<DurableRevocationEffectV1, C2GovernedCarrierIngressRefusalV1> {
        self.actor
            .apply_revocation_judgment_v1(self.current.authority_snapshot, request, judgment)
    }

    pub(crate) fn apply_quarantine_closure_judgment(
        &mut self,
        adopted_restore: &StoreAdoptedRestoreAuthorizationV1,
        request: &StoreIntegrityQuarantineClosureRequestV1,
        judgment: &StoreIntegrityQuarantineClosureJudgmentV1,
    ) -> Result<DurableQuarantineClosureEffectV1, C2GovernedCarrierIngressRefusalV1> {
        self.actor.apply_quarantine_closure_judgment_v1(
            self.current.authority_snapshot,
            self.current.admitted_manifest,
            adopted_restore,
            request,
            judgment,
        )
    }

    /// Reverify the complete borrowed writer correspondence without exposing
    /// any of its authority-bearing constituents.
    pub(crate) fn verify_live(&self) -> Result<(), C2LiveSignerRefusalV1> {
        self.actor.verify_same_snapshot()?;
        self.current.verify_live(self.actor)?;
        let lock = self
            .actor
            .generation_lock
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if self.actor.durable_append_pair.is_none() {
            return Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete);
        }
        Ok(())
    }
}

/// Closed mutation classes owned by the live C2 actor.  This is an audit
/// label, not a caller-selectable authorization domain; only the dedicated
/// actor methods below can enter one of these effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreC2EffectKindV1 {
    CustodyProposalPreparation,
    Installation,
    FoundationalEnrollmentAdoption,
    SignerAcceptance,
    GovernedCarrierIngress,
    SignerAppend,
    TerminalCurrentness,
    RecoveryOrQuarantine,
}

impl<'actor_store> StoreC2SnapshotActorV1<'actor_store> {
    #[must_use]
    pub(crate) const fn actor_instance_identity(&self) -> &Sha256Digest {
        &self.actor_instance_identity
    }

    #[must_use]
    pub(crate) const fn current_snapshot_identity(&self) -> &Sha256Digest {
        &self.current_snapshot_identity
    }

    #[must_use]
    pub(crate) const fn effect_epoch(&self) -> u64 {
        self.effect_epoch
    }

    /// Mint one nontransferable view of the freshly resolved current signer.
    /// This is the only bridge from `GenerationCurrent` into ordinary
    /// predecessor continuity; persisted current-binding rows cannot call it.
    fn mint_current_predecessor_authority_v1<'authority, 'live, 'store>(
        &self,
        current: &'authority C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
    ) -> Result<
        StoreVerifiedCurrentPredecessorAuthorityV1<'authority, 'live, 'store>,
        C2LiveSignerRefusalV1,
    > {
        current.verify_live(self)?;
        let generation_identity = current
            .coordinates
            .physical_generation_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let lifecycle_root_identity = current
            .coordinates
            .lifecycle_root_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let current_binding_identity = current
            .coordinates
            .current_binding_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        Ok(StoreVerifiedCurrentPredecessorAuthorityV1 {
            context_address: std::ptr::from_ref(current).cast::<()>(),
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            generation_identity,
            lifecycle_root_identity,
            current_binding_identity,
            current_frontier_identity: current.coordinates.predecessor_frontier_identity,
            current_standing_identity: current.coordinates.standing_identity,
            _context: PhantomData,
        })
    }

    fn consume_current_predecessor_authority_v1(
        &self,
        authority: StoreVerifiedCurrentPredecessorAuthorityV1<'_, '_, '_>,
        current: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        current.verify_live(self)?;
        if authority.context_address != std::ptr::from_ref(current).cast::<()>()
            || authority.actor_instance_identity != self.actor_instance_identity
            || authority.actor_snapshot_identity != self.current_snapshot_identity
            || authority.actor_effect_epoch != self.effect_epoch
            || Some(authority.generation_identity)
                != current.coordinates.physical_generation_identity
            || Some(authority.lifecycle_root_identity)
                != current.coordinates.lifecycle_root_identity
            || Some(authority.current_binding_identity)
                != current.coordinates.current_binding_identity
            || authority.current_frontier_identity
                != current.coordinates.predecessor_frontier_identity
            || authority.current_standing_identity != current.coordinates.standing_identity
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }

    /// Attach the descriptor-owning B/G pair once after Store-owned
    /// initialization or exact closed-backend reopen. The pair has no raw
    /// constructor and attaching append mechanics does not mint standing.
    pub(super) fn attach_durable_append_pair_v1(
        &mut self,
        pair: C2DurableAppendPairV1,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        if self.durable_append_pair.is_some() {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        verify_durable_signer_carrier_pair_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &pair,
        )
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        self.durable_append_pair = Some(pair);
        Ok(())
    }

    /// Retain the completed REC-29 lock without an unlock/reopen gap.
    /// Holding a lock is quiescence evidence only; it cannot select phase or
    /// construct signer standing.
    pub(super) fn attach_completed_generation_lock_v1(
        &mut self,
        lock: C2StoreGenerationLockV1,
        expected_occurrence: &str,
        expected_physical_generation: &Sha256Digest,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        verify_wu_04_immutable_wu_local_lock_flock_process_registry(&lock)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if self.generation_lock.is_some()
            || lock.carrier().occurrence_id != expected_occurrence
            || &lock.carrier().physical_store_generation_identity != expected_physical_generation
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        self.generation_lock = Some(lock);
        Ok(())
    }

    /// Bind a sealed authority projection to this actor's exact unmodified
    /// snapshot.  Scalar accessors above support an opaque request's later
    /// staleness check; they cannot create this association.
    pub(crate) fn verify_authority_snapshot(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        authority.verify_same_process_and_snapshot()?;
        if authority.admission_basis().store_instance_identity() != &self.store_instance_identity {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        if authority.admission_basis().store_snapshot_identity() != &self.current_snapshot_identity
        {
            return Err(C2LiveSignerRefusalV1::StoreSnapshotMismatch);
        }
        Ok(())
    }

    /// Verify that an immutable A2/manifest premise originated at this
    /// actor's initial snapshot and that every later snapshot advance stayed
    /// inside this actor's linear effect transcript.
    ///
    /// This is deliberately distinct from `verify_authority_snapshot`, which
    /// requires no intervening effect.  A pre-effect A2 projection does not
    /// magically acquire the post-effect snapshot identity; the actor's
    /// retained origin plus unforgeable transcript is the bridge.
    pub(in crate::store_generation) fn verify_authority_lineage(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        authority.verify_same_process_and_snapshot()?;
        if authority.admission_basis().store_instance_identity() != &self.store_instance_identity
            || authority.admission_basis().store_snapshot_identity()
                != &self.initial_snapshot_identity
            || self.effect_epoch as usize != self.effect_transcript.len()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(())
    }

    /// Sole bootstrap live-standing constructor.
    ///
    /// Every input other than the externally verified grant is a borrowed,
    /// Store/custody-owned seal. The prospective generation preimage,
    /// standing, frontier namespace, and exact-content identities are derived
    /// here; callers cannot populate them.
    pub(crate) fn mint_bootstrap_signer_context<'live, 'store>(
        &self,
        authority: &'live StoreC2AuthoritySnapshotV1<'store>,
        admitted_manifest: &'live StoreAdmittedSignerImplementationManifestV1<'live, 'store>,
        accepted: &StoreAcceptedSignerEnrollmentV1,
        custody: &'live VerifiedFoundationalCustodyV1<'live>,
        grant_adoption: &StoreAdoptedBootstrapGrantV1,
    ) -> Result<C2LiveSignerContextV1<'live, 'store, BootstrapV1>, C2LiveSignerRefusalV1> {
        self.verify_authority_lineage(authority)?;
        grant_adoption
            .verify_for_actor(self)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let grant = grant_adoption.verified();
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        verify_sg_rec_05_accepted_wrapper(accepted)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        custody
            .verify_same_process()
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;

        let candidate = accepted.adoption().candidate();
        let coordinates = &candidate.coordinates;
        if accepted.store_snapshot_identity() != &self.current_snapshot_identity
            || accepted.process_identity() != authority.admission_basis().process_identity()
            || candidate.proposal_identity != digest_identity_bytes(custody.proposal_identity())?
            || candidate.public_key != custody.public_key()
            || candidate.key_generation != custody.key_generation()
            || candidate.grant_identity != *grant.grant_identity().bytes()
            || candidate.grant_request_identity != *grant.request_identity().bytes()
            || coordinates.occurrence != authority.admission_basis().occurrence_id()
            || coordinates.occurrence != grant.occurrence_id()
            || &coordinates.controlling_activation
                != authority
                    .current_activation()
                    .controlling_tip_activation_digest()
            || &coordinates.a2_chain_root
                != authority
                    .current_activation()
                    .chain_root_activation_digest()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }

        let manifest_correspondence = admitted_manifest.correspondence_identity();
        let accepted_identity = accepted.record().identity();
        let prospective = digest_fields(
            b"nq.c2.prospective_physical_generation.preimage.v1\0",
            &[
                authority.admission_basis().occurrence_id().as_bytes(),
                accepted_identity.as_str().as_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                custody.proposal_identity().as_str().as_bytes(),
                &candidate.attempt_identity,
            ],
        );
        let standing = digest_fields(
            b"nq.c2.bootstrap_live_standing.v1\0",
            &[
                accepted_identity.as_str().as_bytes(),
                manifest_correspondence.as_str().as_bytes(),
                authority
                    .admission_basis()
                    .store_snapshot_identity()
                    .as_str()
                    .as_bytes(),
                prospective.as_str().as_bytes(),
            ],
        );
        let frontier_namespace = digest_fields(
            b"nq.c2.bootstrap_frontier_namespace.v1\0",
            &[
                authority.admission_basis().occurrence_id().as_bytes(),
                standing.as_str().as_bytes(),
                &candidate.attempt_identity,
            ],
        );
        let exact_content = digest_fields(
            b"nq.c2.bootstrap_live_exact_content.v1\0",
            &[
                accepted.record().canonical_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                custody.proposal_identity().as_str().as_bytes(),
                grant.grant_identity().bytes(),
            ],
        );
        let event_cut = accepted
            .record()
            .accepted_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let signing = C2LiveSigningCoordinatesV1 {
            occurrence_id: coordinates.occurrence.clone(),
            occurrence_identity: text_identity_bytes(
                b"nq.c2.store_occurrence.identity.v1\0",
                &coordinates.occurrence,
            ),
            resident_identity: coordinates.resident.clone(),
            resident_generation: coordinates.resident_generation,
            host_role: coordinates.role.clone(),
            role_manifest_identity: digest_identity_bytes(&coordinates.role_manifest)?,
            role_manifest_generation: coordinates.role_manifest_generation,
            authority_domain: coordinates.authority_domain.clone(),
            terminal_a1_identity: digest_text_identity(&grant.issuer().digest)?,
            current_a2_identity: digest_identity_bytes(&coordinates.controlling_activation)?,
            grant_identity: Some(candidate.grant_identity),
            predecessor_standing_identity: None,
            standing_identity: digest_identity_bytes(&standing)?,
            signer_public_key: custody.public_key(),
            signer_key_generation: custody.key_generation(),
            signer_key_generation_identity: custody.key_generation_identity(),
            signer_scope_identity: custody.scope_identity(),
            signer_scope_policy_identity: custody.signer_scope_policy_identity(),
            signer_scope_policy_version: coordinates.signer_scope_policy_version,
            active_policy_identity: candidate.active_policy,
            active_policy_generation: candidate.active_policy_generation,
            active_policy_digest: candidate.active_policy,
            attempt_identity: candidate.attempt_identity,
            physical_generation_identity: None,
            prospective_generation_preimage_identity: Some(digest_identity_bytes(&prospective)?),
            lifecycle_root_identity: None,
            current_binding_identity: None,
            foundational_lineage: C2LiveFoundationalLineageV1::InitialExternal,
            lineage_authority_identity: Some(candidate.grant_identity),
            request_identity: Some(candidate.grant_request_identity),
            pending_challenge_identity: None,
            historical_foundation_identity: None,
            foundation_identity: Some(digest_identity_bytes(
                accepted.adoption().foundation().identity(),
            )?),
            adoption_identity: Some(digest_identity_bytes(
                accepted.adoption().adoption_identity(),
            )?),
            signer_acceptance_identity: Some(digest_identity_bytes(accepted.record().identity())?),
            event_cut,
            predecessor_event_identity: Some(digest_identity_bytes(accepted_identity)?),
            transition_intent_identity: None,
            implementation_manifest_identity: digest_identity_bytes(
                admitted_manifest.manifest_identity(),
            )?,
            manifest_admission_correspondence_identity: digest_identity_bytes(
                &manifest_correspondence,
            )?,
            qualified_candidate_identity: digest_identity_bytes(
                admitted_manifest.qualified_candidate_identity(),
            )?,
            source_tree_identity: digest_identity_bytes(admitted_manifest.source_tree_identity())?,
            runtime_artifact_identity: digest_identity_bytes(
                admitted_manifest.runtime_artifact_identity(),
            )?,
            frontier_namespace_identity: digest_identity_bytes(&frontier_namespace)?,
            // Installation begins a new physical-generation namespace, but
            // its first semantic message is still causally downstream of the
            // exact MSG-02 possession append consumed by foundational
            // adoption.  Carry that sealed frontier forward; a caller cannot
            // choose the predecessor and the installation lane never starts
            // from an unbound zero frontier.
            predecessor_frontier_identity: accepted.adoption().msg02_resulting_frontier_identity(),
            exact_content_identity: digest_identity_bytes(&exact_content)?,
            scope_class: C2LiveSigningScopeV1::PreGeneration,
            authority_class: C2LiveSigningAuthorityV1::Bootstrap,
        };
        Ok(C2LiveSignerContextV1 {
            authority_snapshot: authority,
            admitted_manifest,
            coordinates: signing,
            foundational_custody: custody,
            phase: C2LiveSigningPhaseV1::Bootstrap,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
            _phase: PhantomData,
            _store: PhantomData,
        })
    }

    /// Seal the exact signing inputs for the MSG-09/MSG-03 installation
    /// batch after the physical-generation preimage has been fixed by this
    /// Store actor.  Final physical generation never comes from MSG-01 or the
    /// foundational enrollment; it is introduced only by the later
    /// installation construction represented by `physical_generation`.
    fn construct_installation_bootstrap_facts_v1(
        &self,
        context: &C2LiveSignerContextV1<'_, '_, BootstrapV1>,
        accepted: &StoreAcceptedSignerEnrollmentV1,
        grant_adoption: &StoreAdoptedBootstrapGrantV1,
        install_policy: &C2StoreGenerationInstallPolicyV1,
        physical_generation: &Sha256Digest,
        bg_layout_profile_manifest_lock_facts: &Sha256Digest,
    ) -> Result<StoreVerifiedInstallationBootstrapFactsV1, C2LiveSignerRefusalV1> {
        context.verify_live(self)?;
        grant_adoption
            .verify_for_actor(self)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let grant = grant_adoption.verified();
        accepted
            .verify_for_actor(self)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let candidate = accepted.adoption().candidate();
        let policy_authority = install_policy.authority();
        let policy_identity = install_policy.identity().digest();
        let expected_mode = match install_policy.mode() {
            C2InstallationModeV1::Fresh => "fresh",
            C2InstallationModeV1::RestoreSuccessor => "restore_successor",
        };
        if grant.grant_identity().bytes() != &candidate.grant_identity
            || grant.proposal_identity_bytes() != candidate.proposal_identity
            || grant.installed_policy_calculation_identity()
                != digest_identity_bytes(install_policy.installed_policy_calculation_identity())?
            || grant.installation_mode() != expected_mode
            || !installation_policy_binds_foundational_layer_v1(
                install_policy.enrollment().digest(),
                accepted.adoption().foundational().identity().digest(),
                accepted.record().identity(),
            )
            || policy_authority.occurrence.as_str() != candidate.coordinates.occurrence
            || policy_authority.resident.as_str() != candidate.coordinates.resident
            || policy_authority.resident_generation != candidate.coordinates.resident_generation
            || policy_authority.role != candidate.coordinates.role
            || policy_authority.role_manifest.digest() != &candidate.coordinates.role_manifest
            || policy_authority.role_manifest_generation
                != candidate.coordinates.role_manifest_generation
            || policy_authority.domain != candidate.coordinates.authority_domain
            || !installation_authorization_precedes_acceptance_v1(
                install_policy.installation_cut().ledger_position,
                grant.lifecycle_cut(),
                accepted.record().accepted_cut(),
            )
            || physical_generation.as_str().ends_with(&"0".repeat(64))
            || bg_layout_profile_manifest_lock_facts
                .as_str()
                .ends_with(&"0".repeat(64))
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        let generation_preimage = context
            .coordinates
            .prospective_generation_preimage_identity
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let attempt_mode = digest_fields(
            b"nq.c2.installation_attempt_mode.identity.v1\0",
            &[
                &candidate.attempt_identity,
                expected_mode.as_bytes(),
                policy_identity.as_str().as_bytes(),
                install_policy.operator_installation_nonce().as_bytes(),
            ],
        );
        let generation_commitment = digest_fields(
            b"nq.c2.physical_generation.commitment.v1\0",
            &[
                &generation_preimage,
                physical_generation.as_str().as_bytes(),
                accepted.record().identity().as_str().as_bytes(),
                policy_identity.as_str().as_bytes(),
                context
                    .admitted_manifest
                    .manifest_identity()
                    .as_str()
                    .as_bytes(),
                bg_layout_profile_manifest_lock_facts.as_str().as_bytes(),
            ],
        );
        Ok(StoreVerifiedInstallationBootstrapFactsV1 {
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            bootstrap_grant_identity: candidate.grant_identity,
            proposal_identity: candidate.proposal_identity,
            attempt_mode_identity: digest_identity_bytes(&attempt_mode)?,
            initial_policy_identity: candidate.active_policy,
            generation_preimage_identity: generation_preimage,
            accepted_enrollment_identity: digest_identity_bytes(accepted.record().identity())?,
            bg_layout_profile_manifest_lock_facts_identity: digest_identity_bytes(
                bg_layout_profile_manifest_lock_facts,
            )?,
            generation_commitment_identity: digest_identity_bytes(&generation_commitment)?,
        })
    }

    fn construct_installation_receipt_facts_v1(
        &self,
        context: &C2LiveSignerContextV1<'_, '_, BootstrapV1>,
        batch: &ConsumedInstallationBootstrapBatchV1,
        generation_commitment_identity: [u8; 32],
        pre_receipt_bg_lock_backend_facts: &Sha256Digest,
    ) -> Result<StoreVerifiedInstallationReceiptFactsV1, C2LiveSignerRefusalV1> {
        context.verify_live(self)?;
        if pre_receipt_bg_lock_backend_facts
            .as_str()
            .ends_with(&"0".repeat(64))
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        Ok(StoreVerifiedInstallationReceiptFactsV1 {
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            installation_intent_message_identity: batch.intent().message_identity,
            physical_generation_bootstrap_message_identity: batch.bootstrap().message_identity,
            generation_commitment_identity,
            pre_receipt_bg_lock_backend_facts_identity: digest_identity_bytes(
                pre_receipt_bg_lock_backend_facts,
            )?,
        })
    }

    /// Sole production fresh-installation entry point for C2.
    ///
    /// This consumes the only bootstrap live phase, creates the fixed
    /// descriptor footprint, initializes the authenticated B/G pair, and
    /// performs the closed MSG-09/MSG-03 batch before proceeding to the
    /// pending projection and MSG-10 completion below.  Restore-successor is
    /// intentionally excluded from this bounded entry point.
    pub(crate) fn install_c2_live_v1<'live, 'store>(
        &mut self,
        context: C2LiveSignerContextV1<'live, 'store, BootstrapV1>,
        accepted: &StoreAcceptedSignerEnrollmentV1,
        grant_adoption: &StoreAdoptedBootstrapGrantV1,
        install_policy: &C2StoreGenerationInstallPolicyV1,
    ) -> Result<
        C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
        C2LiveInstallationDriverRefusalV1,
    > {
        let mut observer = NoC2InstallationCrashV1;
        self.install_c2_live_with_observer_v1(
            context,
            accepted,
            grant_adoption,
            install_policy,
            &mut observer,
        )
    }

    fn install_c2_live_with_observer_v1<'live, 'store>(
        &mut self,
        mut context: C2LiveSignerContextV1<'live, 'store, BootstrapV1>,
        accepted: &StoreAcceptedSignerEnrollmentV1,
        grant_adoption: &StoreAdoptedBootstrapGrantV1,
        install_policy: &C2StoreGenerationInstallPolicyV1,
        observer: &mut impl C2InstallationCrashObserverV1,
    ) -> Result<
        C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
        C2LiveInstallationDriverRefusalV1,
    > {
        context.verify_live(self)?;
        accepted
            .verify_for_actor(self)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        grant_adoption
            .verify_for_actor(self)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        if install_policy.mode() != C2InstallationModeV1::Fresh {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }

        let geometry = install_policy.geometry();
        let layout = construct_wu_03_immutable_wu_append_extents_b_g_carrier(
            geometry.b_payload_bound,
            geometry.g_payload_bound,
            geometry.global_refusal_max_entries,
            geometry.global_refusal_entry_max_bytes,
        )?;
        let lock_length = layout
            .b_aggregate_length_with_lock()
            .checked_sub(layout.b_append_extent_length())
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;

        // Backend qualification is a pre-write premise.  It must be bound and
        // observed before exclusive creation of any fixed C2 carrier; a failed
        // profile check therefore leaves no S1 footprint to recover.
        let profile = bind_c2_qualified_backend_profile_v1(
            "linux_posix_fallocate_regular_file_v1",
            install_policy.qualified_backend_profile().digest().clone(),
            context.admitted_manifest.manifest_identity().clone(),
            context
                .admitted_manifest
                .manifest()
                .signer_message_contract_identity()
                .clone(),
        )?;
        let observation = begin_c2_backend_observation_epoch_v1(
            &self.root,
            self.actor_instance_identity.clone(),
        )?;
        let preflight = inspect_c2_backend_preflight_v1(&observation, &profile)?;
        observer.after_cut(super::install::C2IoCutV1::BackendProfilePreflight)?;

        let allocated = allocate_live_c2_fixed_files_v1(
            &self.root,
            lock_length,
            layout.b_append_extent_length(),
            layout.g_append_extent_length(),
            observer,
        )?;
        let (provisional_lock, b, g) = allocated.into_parts();
        let lock_facts = exact_c2_carrier_file_facts_v1(provisional_lock.file())?;
        let b_facts = exact_c2_carrier_file_facts_v1(&b)?;
        let g_facts = exact_c2_carrier_file_facts_v1(&g)?;

        let generation_preimage = context
            .coordinates
            .prospective_generation_preimage_identity
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let physical_generation = digest_fields(
            b"nq.c2.physical_store_generation.identity.v1\0",
            &[
                context.coordinates.occurrence_id.as_bytes(),
                &generation_preimage,
                accepted.record().identity().as_str().as_bytes(),
                install_policy.identity().digest().as_str().as_bytes(),
                context
                    .admitted_manifest
                    .manifest_identity()
                    .as_str()
                    .as_bytes(),
                lock_facts.file_identity.as_str().as_bytes(),
                b_facts.file_identity.as_str().as_bytes(),
                g_facts.file_identity.as_str().as_bytes(),
            ],
        );
        context.coordinates.physical_generation_identity =
            Some(digest_identity_bytes(&physical_generation)?);
        let physical = preallocate_n_90_permanent_lock_b_g(
            &preflight,
            provisional_lock.file(),
            lock_length,
            &b,
            layout.b_append_extent_length(),
            &g,
            layout.g_append_extent_length(),
        )?;
        let pair_input = C2CarrierPairInputV1 {
            occurrence_id: context.coordinates.occurrence_id.clone(),
            physical_store_generation_identity: physical_generation.clone(),
            qualified_backend_profile_identity: install_policy
                .qualified_backend_profile()
                .digest()
                .clone(),
            b_file: b_facts.clone(),
            g_file: g_facts.clone(),
        };
        let correspondence = construct_rec_30_pair_header_correspondence(&layout, pair_input)?;
        let pair = initialize_durable_append_pair_for_installation_with_observer_v1(
            &physical,
            &layout,
            &correspondence,
            &mut |extent| {
                observer.after_cut(match extent {
                    C2InstallationExtentInitializedV1::BootstrapB => {
                        super::install::C2IoCutV1::BHeaderWrite
                    }
                    C2InstallationExtentInitializedV1::GlobalRefusalG => {
                        super::install::C2IoCutV1::GHeaderWrite
                    }
                })
            },
        )
        .map_err(|refusal| match refusal {
            C2ObservedAppendExtentRefusalV1::Append(refusal) => {
                C2LiveInstallationDriverRefusalV1::Append(refusal)
            }
            C2ObservedAppendExtentRefusalV1::Observer(refusal) => {
                C2LiveInstallationDriverRefusalV1::Installation(refusal)
            }
        })?;
        drop(physical);
        self.attach_durable_append_pair_v1(pair)?;

        let layout_bytes = canonical_json_bytes(&layout)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let bg_facts_identity = digest_fields(
            b"nq.c2.installation.bg_layout_profile_manifest_lock_facts.v1\0",
            &[
                &layout_bytes,
                correspondence.pair_identity().as_str().as_bytes(),
                correspondence.b_header().identity().as_str().as_bytes(),
                correspondence.g_header().identity().as_str().as_bytes(),
                install_policy
                    .qualified_backend_profile()
                    .digest()
                    .as_str()
                    .as_bytes(),
                context
                    .admitted_manifest
                    .manifest_identity()
                    .as_str()
                    .as_bytes(),
                lock_facts.file_identity.as_str().as_bytes(),
            ],
        );
        let facts = self.construct_installation_bootstrap_facts_v1(
            &context,
            accepted,
            grant_adoption,
            install_policy,
            &physical_generation,
            &bg_facts_identity,
        )?;
        // MSG-09 is the first signed installation event, so it cannot use its
        // own not-yet-derived message identity as its transaction coordinate.
        // Bind it instead to the actor-derived exact installation attempt
        // (mode + policy + nonce).  The batch replaces this precursor with
        // the consumed MSG-09 identity before constructing MSG-03/MSG-10.
        if context.coordinates.transition_intent_identity.is_some() {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        context.coordinates.transition_intent_identity = Some(facts.attempt_mode_identity());
        let batch = {
            let mut coordinator =
                C2SignerTransitionCoordinator::from_store_actor(self, &mut context)?;
            coordinator.append_installation_bootstrap_batch(&facts)?
        };
        observer.after_cut(super::install::C2IoCutV1::BootstrapIntentAppend)?;
        observer.after_cut(super::install::C2IoCutV1::ImmutablePrefixSync)?;

        let completed_lock = finalize_provisional_generation_lock_v1(
            provisional_lock,
            context.coordinates.occurrence_id.clone(),
            physical_generation.clone(),
            batch.bootstrap_physical_frame_identity().clone(),
        )?;
        let lock_identity = completed_lock.carrier().lock_identity.clone();
        self.attach_completed_generation_lock_v1(
            completed_lock,
            &context.coordinates.occurrence_id,
            &physical_generation,
        )?;

        let projection_identity = self.persist_pending_installation_projection_v1(
            &mut context,
            install_policy,
            &physical_generation,
            &batch,
            observer,
        )?;

        let pre_receipt = batch.carrier_snapshot().clone();
        let pre_receipt_facts = digest_fields(
            b"nq.c2.installation.pre_receipt_bg_lock_backend_facts.v1\0",
            &[
                pre_receipt.b_content_root.as_str().as_bytes(),
                &pre_receipt.b_next_payload_offset.to_be_bytes(),
                &pre_receipt.b_next_slot.to_be_bytes(),
                pre_receipt.g_content_root.as_str().as_bytes(),
                &pre_receipt.g_next_payload_offset.to_be_bytes(),
                &pre_receipt.g_next_slot.to_be_bytes(),
                lock_identity.as_str().as_bytes(),
                correspondence.pair_identity().as_str().as_bytes(),
                correspondence.b_header().identity().as_str().as_bytes(),
                correspondence.g_header().identity().as_str().as_bytes(),
                install_policy
                    .qualified_backend_profile()
                    .digest()
                    .as_str()
                    .as_bytes(),
            ],
        );
        verify_reopened_c2_fixed_descriptors_v1(&self.root, &lock_facts, &b_facts, &g_facts)?;
        observer.after_cut(super::install::C2IoCutV1::PreReceiptDescriptorReopen)?;
        let receipt_facts = self.construct_installation_receipt_facts_v1(
            &context,
            &batch,
            facts.generation_commitment_identity(),
            &pre_receipt_facts,
        )?;
        let receipt = {
            let mut coordinator =
                C2SignerTransitionCoordinator::from_store_actor(self, &mut context)?;
            coordinator.append_installation_receipt(&receipt_facts)?
        };
        observer.after_cut(super::install::C2IoCutV1::CompletionReceiptAppend)?;
        observer.after_cut(super::install::C2IoCutV1::CompletionReceiptSync)?;

        let evidence = self.persist_initial_generation_current_projection_v1(
            &mut context,
            accepted,
            install_policy,
            &physical_generation,
            &projection_identity,
            &batch,
            &receipt,
            &pre_receipt,
            facts.generation_commitment_identity(),
        )?;
        verify_reopened_c2_fixed_descriptors_v1(&self.root, &lock_facts, &b_facts, &g_facts)?;
        observer.after_cut(super::install::C2IoCutV1::CompletedDescriptorReopen)?;
        self.mint_generation_current_from_bootstrap_v1(context, accepted, evidence)
    }

    fn persist_pending_installation_projection_v1(
        &mut self,
        context: &mut C2LiveSignerContextV1<'_, '_, BootstrapV1>,
        install_policy: &C2StoreGenerationInstallPolicyV1,
        physical_generation: &Sha256Digest,
        batch: &ConsumedInstallationBootstrapBatchV1,
        observer: &mut impl C2InstallationCrashObserverV1,
    ) -> Result<Sha256Digest, C2LiveInstallationDriverRefusalV1> {
        context.verify_live(self)?;
        let bootstrap_identity = identity_digest_from_bytes(batch.bootstrap().message_identity)?;
        let body = C2InstallationProjectionIdentityBodyV1 {
            schema: "nq.c2_installation_projection.v1",
            schema_version: 1,
            occurrence_id: &context.coordinates.occurrence_id,
            physical_store_generation_identity: physical_generation,
            bootstrap_identity: &bootstrap_identity,
            installation_nonce: install_policy.operator_installation_nonce(),
            state: "pending",
        };
        let body_bytes = canonical_json_bytes(&body)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let projection_identity = digest_fields(
            b"nq.c2.installation_projection.identity.v1\0",
            &[&body_bytes],
        );
        let wire = C2InstallationProjectionWireV1 {
            schema: "nq.c2_installation_projection.v1".to_owned(),
            schema_version: 1,
            projection_identity: projection_identity.clone(),
            occurrence_id: context.coordinates.occurrence_id.clone(),
            physical_store_generation_identity: physical_generation.clone(),
            bootstrap_identity,
            installation_nonce: install_policy.operator_installation_nonce().to_owned(),
            state: "pending".to_owned(),
        };
        let canonical = canonical_json_bytes(&wire)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let canonical_sha = sha256_bytes(&canonical);
        let canonical_length = u64::try_from(canonical.len())
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        self.with_permitted_effect(
            StoreC2EffectKindV1::Installation,
            |transaction| -> Result<(), C2LiveInstallationDriverRefusalV1> {
                transaction
                    .execute(
                        "INSERT INTO c2_installation_projection (
                            projection_identity, schema_id, schema_version,
                            occurrence_id, physical_store_generation_identity,
                            bootstrap_identity, installation_nonce, state,
                            canonical_bytes, canonical_bytes_sha256,
                            canonical_bytes_length, projected_at
                         ) VALUES (?1, 'nq.c2_installation_projection.v1', 1,
                                   ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?8, ?9)",
                        params![
                            projection_identity.as_str(),
                            context.coordinates.occurrence_id,
                            physical_generation.as_str(),
                            wire.bootstrap_identity.as_str(),
                            install_policy.operator_installation_nonce(),
                            canonical,
                            canonical_sha.as_str(),
                            canonical_length,
                            Utc::now().to_rfc3339(),
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-07");
                observer.after_cut(super::install::C2IoCutV1::PendingSqlProjectionInsert)?;
                Ok(())
            },
        )?;
        context.actor_snapshot_identity = self.current_snapshot_identity.clone();
        context.actor_effect_epoch = self.effect_epoch;
        Ok(projection_identity)
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_initial_generation_current_projection_v1(
        &mut self,
        context: &mut C2LiveSignerContextV1<'_, '_, BootstrapV1>,
        accepted: &StoreAcceptedSignerEnrollmentV1,
        install_policy: &C2StoreGenerationInstallPolicyV1,
        physical_generation: &Sha256Digest,
        projection_identity: &Sha256Digest,
        batch: &ConsumedInstallationBootstrapBatchV1,
        receipt: &ConsumedSignedFrameV1,
        pre_receipt: &crate::append_extent::C2DurableAppendPairSnapshotV1,
        generation_commitment_identity: [u8; 32],
    ) -> Result<StoreResolvedGenerationCurrentEvidenceV1, C2LiveInstallationDriverRefusalV1> {
        context.verify_live(self)?;
        let candidate = accepted.adoption().candidate();
        if candidate.key_generation != 0
            || receipt.route.as_str() != "msg10_installation_receipt"
            || receipt.effect_receipt_identity.is_empty()
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        let bootstrap_identity = identity_digest_from_bytes(batch.bootstrap().message_identity)?;
        let installation_intent_identity =
            identity_digest_from_bytes(batch.intent().message_identity)?;
        let installation_receipt_identity = identity_digest_from_bytes(receipt.message_identity)?;
        let generation_commitment = identity_digest_from_bytes(generation_commitment_identity)?;
        let bootstrap_grant_identity = identity_digest_from_bytes(candidate.grant_identity)?;
        let foundational_enrollment_identity = accepted
            .adoption()
            .foundational()
            .canonical_identity()
            .clone();
        let signer_enrollment_identity = accepted.record().identity().clone();
        let initial_pop_identity = identity_digest_from_bytes(accepted.adoption().pop_identity())?;
        let receipt_event_cut: u64 = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .query_row(
                "SELECT event_cut FROM c2_signer_message_appends
                 WHERE effect_receipt_identity = ?1
                   AND route = 'msg10_installation_receipt'",
                [receipt.effect_receipt_identity.as_str()],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        if receipt_event_cut <= accepted.record().accepted_cut() {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        let relation_body = C2BootstrapGenerationRelationIdentityBodyV1 {
            schema: "nq.c2_signer_bootstrap_transition.v1",
            schema_version: 1,
            identity_domain: "nq.c2.signer_bootstrap_transition.identity.v1",
            bootstrap_grant_identity: &bootstrap_grant_identity,
            foundational_enrollment_identity: &foundational_enrollment_identity,
            signer_enrollment_identity: &signer_enrollment_identity,
            initial_pop_identity: &initial_pop_identity,
            physical_generation_bootstrap_identity: &bootstrap_identity,
            generation_commitment_identity: &generation_commitment,
            installation_receipt_identity: &installation_receipt_identity,
            physical_store_generation_identity: physical_generation,
            transition_cut: receipt_event_cut,
        };
        let relation_body_bytes = canonical_json_bytes(&relation_body)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let relation_identity = canonical_domain_identity(
            relation_body.identity_domain.as_bytes(),
            &relation_body_bytes,
        );
        let relation_wire = C2BootstrapGenerationRelationWireV1 {
            schema: relation_body.schema.to_owned(),
            schema_version: relation_body.schema_version,
            identity_domain: relation_body.identity_domain.to_owned(),
            relation_identity: relation_identity.clone(),
            bootstrap_grant_identity,
            foundational_enrollment_identity,
            signer_enrollment_identity,
            initial_pop_identity,
            physical_generation_bootstrap_identity: bootstrap_identity.clone(),
            generation_commitment_identity: generation_commitment.clone(),
            installation_receipt_identity: installation_receipt_identity.clone(),
            physical_store_generation_identity: physical_generation.clone(),
            transition_cut: receipt_event_cut,
        };
        let relation_bytes = canonical_json_bytes(&relation_wire)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let relation_sha = sha256_bytes(&relation_bytes);
        let relation_len = u64::try_from(relation_bytes.len())
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let scope_identity = identity_digest_from_bytes(context.coordinates.signer_scope_identity)?;
        let initial_policy = identity_digest_from_bytes(candidate.active_policy)?;
        let lifecycle_root = digest_fields(
            b"nq.c2.signer_lifecycle_root.identity.v1\0",
            &[
                context.coordinates.occurrence_id.as_bytes(),
                physical_generation.as_str().as_bytes(),
                accepted.record().identity().as_str().as_bytes(),
                bootstrap_identity.as_str().as_bytes(),
                generation_commitment.as_str().as_bytes(),
                scope_identity.as_str().as_bytes(),
            ],
        );
        let policy_lineage_root = digest_fields(
            b"nq.c2.signer_policy_lineage_root.identity.v1\0",
            &[
                initial_policy.as_str().as_bytes(),
                install_policy.identity().digest().as_str().as_bytes(),
                context
                    .authority_snapshot
                    .current_activation()
                    .chain_root_activation_digest()
                    .as_str()
                    .as_bytes(),
            ],
        );
        let root_identity = construct_sb_01_lifecycle_root_identity(
            context.coordinates.occurrence_id.clone(),
            physical_generation.as_str().to_owned(),
            lifecycle_root.as_str().to_owned(),
            scope_identity.as_str().to_owned(),
            context.coordinates.resident_identity.clone(),
            context.coordinates.host_role.clone(),
            context.coordinates.role_manifest_generation.to_string(),
            context.coordinates.authority_domain.clone(),
            policy_lineage_root.as_str().to_owned(),
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let creation_cut = install_policy.installation_cut().ledger_position;
        let root = construct_sb_02_immutable_root_binding(
            root_identity,
            accepted.record().identity().as_str().to_owned(),
            candidate.key_generation.to_string(),
            initial_policy.as_str().to_owned(),
            bootstrap_identity.clone(),
            generation_commitment.clone(),
            creation_cut,
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let standing = digest_fields(
            b"nq.c2.initial_generation_current_standing.identity.v1\0",
            &[
                root.binding_id().as_str().as_bytes(),
                accepted.record().identity().as_str().as_bytes(),
                receipt.effect_receipt_identity.as_bytes(),
                &receipt.resulting_frontier_identity,
            ],
        );
        let effective_cut = creation_cut
            .max(accepted.record().accepted_cut())
            .checked_add(1)
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let current = construct_sb_04_initial_binding_derivation(
            &root,
            standing.as_str().to_owned(),
            receipt.effect_receipt_identity.clone(),
            effective_cut,
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?
        .into_inner();
        let terminal_candidate_set = context
            .authority_snapshot
            .current_activation()
            .candidate_set_digest()
            .clone();
        let lineage_identity = digest_fields(
            b"nq.c2.signer_lineage.identity.v1\0",
            &[
                root.binding_id().as_str().as_bytes(),
                current.binding_id().as_str().as_bytes(),
                terminal_candidate_set.as_str().as_bytes(),
                &effective_cut.to_be_bytes(),
            ],
        );
        let lineage_completion = digest_fields(
            b"nq.c2.signer_lineage_completion.identity.v1\0",
            &[
                lineage_identity.as_str().as_bytes(),
                root.binding_id().as_str().as_bytes(),
                current.binding_id().as_str().as_bytes(),
                installation_receipt_identity.as_str().as_bytes(),
            ],
        );

        let root_bytes = canonical_json_bytes(&root)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let current_bytes = canonical_json_bytes(&current)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let lineage_bytes = canonical_json_bytes(&C2InitialLineageProjectionWireV1 {
            schema: "nq.c2_signer_lineage_projection.v1",
            lineage_identity: &lineage_identity,
            root_binding_identity: root.binding_id(),
            initial_binding_identity: current.binding_id(),
            terminal_binding_identity: current.binding_id(),
            edge_count: 0,
            terminal_candidate_set_identity: &terminal_candidate_set,
            effective_cut,
        })
        .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let root_sha = sha256_bytes(&root_bytes);
        let current_sha = sha256_bytes(&current_bytes);
        let lineage_sha = sha256_bytes(&lineage_bytes);
        let root_len = u64::try_from(root_bytes.len())
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let current_len = u64::try_from(current_bytes.len())
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let lineage_len = u64::try_from(lineage_bytes.len())
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let public_key = context.coordinates.signer_public_key;
        let occurrence = context.coordinates.occurrence_id.clone();
        let resident = context.coordinates.resident_identity.clone();
        let resident_generation = context.coordinates.resident_generation;
        let host_role = context.coordinates.host_role.clone();
        let role_manifest_generation = context.coordinates.role_manifest_generation;
        let authority_domain = context.coordinates.authority_domain.clone();
        let now = Utc::now().to_rfc3339();

        self.with_permitted_effect(
            StoreC2EffectKindV1::Installation,
            |transaction| -> Result<(), C2LiveInstallationDriverRefusalV1> {
                let (stored_route, stored_message, effect_receipt_bytes): (
                    String,
                    Vec<u8>,
                    Vec<u8>,
                ) = transaction
                    .query_row(
                        "SELECT route, message_identity, effect_receipt_bytes
                         FROM c2_signer_message_appends
                         WHERE effect_receipt_identity = ?1",
                        [receipt.effect_receipt_identity.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(StoreError::from)?;
                if stored_route != "msg10_installation_receipt"
                    || stored_message != receipt.message_identity
                {
                    return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
                }
                let canonical_receipt_sha = sha256_bytes(&effect_receipt_bytes);
                transaction
                    .execute(
                        "INSERT INTO c2_installation_receipt_index (
                            installation_receipt_identity,
                            physical_store_generation_identity,
                            installation_intent_identity, bootstrap_identity,
                            pending_projection_identity, pre_receipt_b_root_identity,
                            pre_receipt_b_cursor, g_root_identity, g_cursor,
                            completion_state, canonical_receipt_sha256, indexed_at
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                                   'complete', ?10, ?11)",
                        params![
                            installation_receipt_identity.as_str(),
                            physical_generation.as_str(),
                            installation_intent_identity.as_str(),
                            bootstrap_identity.as_str(),
                            projection_identity.as_str(),
                            pre_receipt.b_content_root.as_str(),
                            pre_receipt.b_next_payload_offset,
                            pre_receipt.g_content_root.as_str(),
                            pre_receipt.g_next_payload_offset,
                            canonical_receipt_sha.as_str(),
                            now,
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-08");
                transaction
                    .execute(
                        "INSERT INTO c2_signer_bootstrap_transition (
                            relation_identity, schema_id, schema_version,
                            identity_domain, bootstrap_grant_identity,
                            foundational_enrollment_identity,
                            signer_enrollment_identity, initial_pop_identity,
                            physical_generation_bootstrap_identity,
                            generation_commitment_identity,
                            installation_receipt_identity,
                            physical_store_generation_identity, transition_cut,
                            canonical_bytes, canonical_bytes_sha256,
                            canonical_bytes_length, derived_at
                         ) VALUES (?1, 'nq.c2_signer_bootstrap_transition.v1', 1,
                                   'nq.c2.signer_bootstrap_transition.identity.v1',
                                   ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                                   ?11, ?12, ?13, ?14)",
                        params![
                            relation_identity.as_str(),
                            relation_wire.bootstrap_grant_identity.as_str(),
                            relation_wire.foundational_enrollment_identity.as_str(),
                            relation_wire.signer_enrollment_identity.as_str(),
                            relation_wire.initial_pop_identity.as_str(),
                            relation_wire
                                .physical_generation_bootstrap_identity
                                .as_str(),
                            relation_wire.generation_commitment_identity.as_str(),
                            relation_wire.installation_receipt_identity.as_str(),
                            relation_wire.physical_store_generation_identity.as_str(),
                            relation_wire.transition_cut,
                            relation_bytes,
                            relation_sha.as_str(),
                            relation_len,
                            now,
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-09");
                transaction
                    .execute(
                        "INSERT INTO c2_signer_root_binding_projection (
                            root_binding_identity, occurrence_id,
                            physical_store_generation_identity,
                            signer_lifecycle_root_identity,
                            initial_enrollment_identity, initial_key_generation,
                            initial_public_key, generation_genesis_identity,
                            generation_commitment_identity, scope_identity,
                            resident_identity, resident_generation, host_role,
                            role_manifest_generation, authority_domain,
                            policy_lineage_root_identity, creation_cut,
                            canonical_bytes, canonical_bytes_sha256,
                            canonical_bytes_length, projected_at
                         ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8,
                                   ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                                   ?17, ?18, ?19, ?20)",
                        params![
                            root.binding_id().as_str(),
                            occurrence,
                            physical_generation.as_str(),
                            lifecycle_root.as_str(),
                            accepted.record().identity().as_str(),
                            &public_key[..],
                            bootstrap_identity.as_str(),
                            generation_commitment.as_str(),
                            scope_identity.as_str(),
                            resident,
                            resident_generation,
                            host_role,
                            role_manifest_generation,
                            authority_domain,
                            policy_lineage_root.as_str(),
                            creation_cut,
                            root_bytes,
                            root_sha.as_str(),
                            root_len,
                            now,
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-10");
                transaction
                    .execute(
                        "INSERT INTO c2_signer_current_binding_projection (
                            current_binding_identity, root_binding_identity,
                            occurrence_id, physical_store_generation_identity,
                            signer_lifecycle_root_identity, scope_identity,
                            resident_identity, resident_generation, host_role,
                            role_manifest_generation, authority_domain,
                            policy_lineage_root_identity,
                            current_enrollment_identity, current_key_generation,
                            current_public_key, current_policy_identity,
                            current_standing_identity, binding_mode,
                            provenance_identity, transition_identity,
                            predecessor_binding_identity,
                            continuity_authorization_identity,
                            recovery_condition_identity, recovery_authority_identity,
                            recovery_grant_identity, persisted_resolution_identity,
                            effective_cut, canonical_bytes,
                            canonical_bytes_sha256, canonical_bytes_length, projected_at
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                                   ?10, ?11, ?12, ?13, 0, ?14, ?15, ?16,
                                   'initial', ?17, NULL, NULL, NULL, NULL, NULL,
                                   NULL, ?18, ?19, ?20, ?21, ?22, ?23)",
                        params![
                            current.binding_id().as_str(),
                            root.binding_id().as_str(),
                            occurrence,
                            physical_generation.as_str(),
                            lifecycle_root.as_str(),
                            scope_identity.as_str(),
                            resident,
                            resident_generation,
                            host_role,
                            role_manifest_generation,
                            authority_domain,
                            policy_lineage_root.as_str(),
                            accepted.record().identity().as_str(),
                            &public_key[..],
                            initial_policy.as_str(),
                            standing.as_str(),
                            root.binding_id().as_str(),
                            receipt.effect_receipt_identity,
                            effective_cut,
                            current_bytes,
                            current_sha.as_str(),
                            current_len,
                            now,
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-11");
                transaction
                    .execute(
                        "INSERT INTO c2_signer_lineage_projection (
                            lineage_identity, root_binding_identity,
                            initial_binding_identity, terminal_binding_identity,
                            edge_count, terminal_candidate_set_identity,
                            effective_cut, canonical_bytes,
                            canonical_bytes_sha256, canonical_bytes_length,
                            projected_at
                         ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            lineage_identity.as_str(),
                            root.binding_id().as_str(),
                            current.binding_id().as_str(),
                            current.binding_id().as_str(),
                            terminal_candidate_set.as_str(),
                            effective_cut,
                            lineage_bytes,
                            lineage_sha.as_str(),
                            lineage_len,
                            now,
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-12");
                transaction
                    .execute(
                        "INSERT INTO c2_signer_lineage_completion_projection (
                            lineage_identity, completion_identity,
                            root_binding_identity, terminal_binding_identity,
                            edge_count, completed_at
                         ) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                        params![
                            lineage_identity.as_str(),
                            lineage_completion.as_str(),
                            root.binding_id().as_str(),
                            current.binding_id().as_str(),
                            now,
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-13");
                Ok(())
            },
        )?;
        context.actor_snapshot_identity = self.current_snapshot_identity.clone();
        context.actor_effect_epoch = self.effect_epoch;
        self.resolve_generation_current_evidence_v1()
            .map_err(C2LiveInstallationDriverRefusalV1::from)
    }

    fn mint_generation_current_from_bootstrap_v1<'live, 'store>(
        &self,
        context: C2LiveSignerContextV1<'live, 'store, BootstrapV1>,
        accepted: &StoreAcceptedSignerEnrollmentV1,
        evidence: StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<
        C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
        C2LiveInstallationDriverRefusalV1,
    > {
        context.verify_live(self)?;
        context
            .foundational_custody
            .verify_same_process()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let pair = self
            .durable_append_pair
            .as_ref()
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let lock = self
            .generation_lock
            .as_ref()
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)?;
        let final_pair = pair.current_snapshot();
        let current_generation = evidence
            .current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let current_policy = parse_digest(evidence.current.policy_id())?;
        let physical_generation = parse_digest(evidence.root.physical_store_generation())?;
        let lifecycle_root = parse_digest(evidence.root.lifecycle_root_id())?;
        let standing = parse_digest(evidence.current.standing_id())?;
        let scope = parse_digest(evidence.root.scope_id())?;
        let accepted_identity = accepted.record().identity();
        if evidence.occurrence_id != context.coordinates.occurrence_id
            || evidence.physical_generation_identity != physical_generation
            || evidence.bootstrap_identity != *evidence.root.genesis_digest()
            || evidence.installation_intent_identity
                != identity_digest_from_bytes(
                    context
                        .coordinates
                        .transition_intent_identity
                        .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?,
                )?
            || evidence.current.mode() != CurrentSignerBindingModeV1::Initial
            || evidence.current.enrollment_id() != accepted_identity.as_str()
            || current_generation != context.foundational_custody.key_generation()
            || evidence.current_public_key != context.foundational_custody.public_key()
            || scope != identity_digest_from_bytes(context.coordinates.signer_scope_identity)?
            || lock.carrier().occurrence_id != evidence.occurrence_id
            || lock.carrier().physical_store_generation_identity != physical_generation
            || final_pair.b_next_slot != 3
            || final_pair.b_next_payload_offset <= evidence.pre_receipt_b_cursor
            || final_pair.b_content_root == evidence.pre_receipt_b_root_identity
            || final_pair.g_content_root != evidence.g_root_identity
            || final_pair.g_next_payload_offset != evidence.g_cursor
            || final_pair.g_next_slot != 0
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        let predecessor_standing = context.coordinates.standing_identity;
        let frontier_namespace = digest_fields(
            b"nq.c2.generation_current_frontier_namespace.v1\0",
            &[
                evidence.occurrence_id.as_bytes(),
                physical_generation.as_str().as_bytes(),
                lifecycle_root.as_str().as_bytes(),
                evidence.current.binding_id().as_str().as_bytes(),
            ],
        );
        let mut coordinates = context.coordinates;
        coordinates.predecessor_standing_identity = Some(predecessor_standing);
        coordinates.standing_identity = digest_identity_bytes(&standing)?;
        coordinates.signer_public_key = evidence.current_public_key;
        coordinates.signer_key_generation = current_generation;
        coordinates.signer_key_generation_identity =
            context.foundational_custody.key_generation_identity();
        coordinates.signer_scope_identity = digest_identity_bytes(&scope)?;
        coordinates.active_policy_identity = digest_identity_bytes(&current_policy)?;
        coordinates.active_policy_digest = digest_identity_bytes(&current_policy)?;
        coordinates.physical_generation_identity =
            Some(digest_identity_bytes(&physical_generation)?);
        coordinates.prospective_generation_preimage_identity = None;
        coordinates.lifecycle_root_identity = Some(digest_identity_bytes(&lifecycle_root)?);
        coordinates.current_binding_identity =
            Some(digest_identity_bytes(evidence.current.binding_id())?);
        coordinates.event_cut = evidence.current.effective_cut();
        coordinates.predecessor_event_identity = Some(digest_identity_bytes(
            &evidence.installation_receipt_identity,
        )?);
        coordinates.frontier_namespace_identity = digest_identity_bytes(&frontier_namespace)?;
        coordinates.predecessor_frontier_identity = evidence.frontier_identity;
        coordinates.exact_content_identity =
            digest_identity_bytes(&evidence.exact_content_identity)?;
        coordinates.scope_class = C2LiveSigningScopeV1::GenerationBound;
        coordinates.authority_class = C2LiveSigningAuthorityV1::GenerationCurrent;
        Ok(C2LiveSignerContextV1 {
            authority_snapshot: context.authority_snapshot,
            admitted_manifest: context.admitted_manifest,
            coordinates,
            foundational_custody: context.foundational_custody,
            phase: C2LiveSigningPhaseV1::GenerationCurrent,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
            _phase: PhantomData,
            _store: PhantomData,
        })
    }

    /// Retained Store root used only by exact fixed-name C2 operations.
    #[must_use]
    pub(crate) const fn retained_root(&self) -> &File {
        &self.root
    }

    /// Resolve one and only one complete generation-current durable state.
    ///
    /// Partial installation rows, incomplete signer lineage, multiple
    /// candidates, malformed canonical bytes, and a detached terminal
    /// frontier all refuse. The result is inert evidence; it cannot mint a
    /// phase without the remaining fresh-process reopen premises.
    pub(crate) fn resolve_generation_current_evidence_v1(
        &self,
    ) -> Result<StoreResolvedGenerationCurrentEvidenceV1, C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        resolve_generation_current_from_retained_basis_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &self.root,
        )
    }

    /// Resolve the exact complete durable terminal without asserting that
    /// its signer still has usable live custody/currentness.  This is inert
    /// evidence for externally authorized restore/recovery only; it cannot
    /// feed the ordinary GenerationCurrent mint.
    fn resolve_generation_current_evidence_before_governance_v1(
        &self,
    ) -> Result<StoreResolvedGenerationCurrentEvidenceV1, C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        load_generation_current_evidence_before_governance_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )
    }

    /// Select and verify the exact canonical custody preparation referenced by
    /// one stable foundation.  This performs only durable/canonical checks;
    /// filesystem custody availability is intentionally left to the caller so
    /// a discontinuity resolver can distinguish malformed Store evidence from
    /// a genuine inability to reopen otherwise-exact current custody.
    fn load_terminal_foundation_prepared_custody_v1<'admission>(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'admission, 'actor_store>,
        enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    ) -> Result<StoreVerifiedPreparedCustodyV1, C2LiveInstallationDriverRefusalV1> {
        self.verify_same_snapshot()?;
        // A restore/recovery carrier is admitted as a Store-owned effect
        // before historical/prepared custody is reopened.  The immutable A2
        // premise must still originate at this actor's exact initial
        // snapshot, but requiring byte-for-byte equality with that pre-effect
        // snapshot would make every legal discontinuity path unreachable.
        // The retained actor transcript is the non-forgeable bridge across
        // the governed-ingress effect.
        self.verify_authority_lineage(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let foundation = enrollment.foundation();
        let adoption = enrollment.adoption();
        let (
            preparation_lineage,
            occurrence_id,
            proposal_identity,
            proposal_bytes,
            proposal_sha256,
            proposal_length,
            manifest_identity,
            candidate_identity,
            source_tree_identity,
            runtime_artifact_identity,
        ): (
            String,
            String,
            String,
            Vec<u8>,
            String,
            u64,
            String,
            String,
            String,
            String,
        ) = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .query_row(
                "SELECT preparation_lineage, occurrence_id, proposal_identity,
                        proposal_canonical_bytes, proposal_canonical_sha256,
                        proposal_canonical_length, implementation_manifest_identity,
                        qualified_candidate_identity, source_tree_identity,
                        runtime_artifact_identity
                 FROM c2_custody_proposal_preparations
                 WHERE proposal_identity = ?1",
                [foundation.custody_evidence_identity().as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .map_err(StoreError::from)?;
        // Custody preparation records the immutable creation provenance of a
        // stable foundation.  Restore creates a new adoption event for that
        // same foundation, so its adoption lineage is deliberately different
        // from the original preparation lineage.  A restore-origin
        // preparation would instead imply a newly created restore key, which
        // the four-path contract forbids.
        if verify_stable_foundation_creation_lineage_for_adoption_v1(
            &preparation_lineage,
            adoption.lineage(),
        )
        .is_err()
            || occurrence_id != authority.admission_basis().occurrence_id()
            || proposal_identity != foundation.custody_evidence_identity().as_str()
            || proposal_sha256 != sha256_bytes(&proposal_bytes).as_str()
            || proposal_length != proposal_bytes.len() as u64
            || manifest_identity != admitted_manifest.manifest_identity().as_str()
            || candidate_identity != admitted_manifest.qualified_candidate_identity().as_str()
            || source_tree_identity != admitted_manifest.source_tree_identity().as_str()
            || runtime_artifact_identity != admitted_manifest.runtime_artifact_identity().as_str()
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        StoreVerifiedPreparedCustodyV1::from_store_selected_canonical_proposal(
            self,
            &proposal_bytes,
            admitted_manifest.manifest_identity().clone(),
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)
    }

    /// Reopen custody for the exact stable foundation selected by the closed
    /// durable terminal resolver.  Proposal bytes and their implementation
    /// coordinates are Store-loaded; no caller-authored coordinate container
    /// can enter this seam.
    fn reopen_terminal_foundation_custodian_v1<'admission>(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'admission, 'actor_store>,
        enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    ) -> Result<StoreReopenedGenerationCurrentCustodianV1, C2LiveInstallationDriverRefusalV1> {
        let prepared = self.load_terminal_foundation_prepared_custody_v1(
            authority,
            admitted_manifest,
            enrollment,
        )?;
        C2StoreIntegrityCustodian::reopen_prepared_generation_current_for_actor(
            self,
            prepared,
            enrollment.foundation(),
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)
    }

    /// Establish the frozen discontinuity-eligibility disjunction from Store
    /// state, never from MSG-13/15 request prose.  A complete logical custody
    /// preparation is selected first; only failure of the subsequent exact
    /// filesystem/key reopen counts as ordinary-continuity unavailability.
    /// Alternatively, one exact validated durable MSG-14 effect supplies the
    /// independently governed exceptional branch.
    fn resolve_discontinuity_eligibility_v1(
        &self,
        lineage: C2LiveFoundationalLineageV1,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, 'actor_store>,
        durable_current: &StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<StoreVerifiedDiscontinuityEligibilityV1, C2DiscontinuityRefusalV1> {
        self.verify_same_snapshot()?;
        // MSG-13/15 admission is the immediately preceding Store-owned
        // effect, so the actor is now on a descendant snapshot of the exact
        // authority snapshot which verified that carrier.  Require the
        // retained linear effect transcript rather than the pre-effect
        // snapshot equality used at initial admission.
        self.verify_authority_lineage(authority)?;
        if !matches!(
            lineage,
            C2LiveFoundationalLineageV1::RestoreHistorical
                | C2LiveFoundationalLineageV1::RecoveryNewFoundation
        ) {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
        }
        let enrollment = durable_current.durable_terminal.enrollment();
        let key_generation = durable_current
            .current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        let transaction = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?;
        let condition = match refuse_if_current_signer_revoked_v1(
            transaction,
            durable_current.root.physical_store_generation(),
            durable_current.root.lifecycle_root_id(),
            durable_current.root.scope_id(),
            durable_current.current.enrollment_id(),
            &durable_current.current_public_key,
            key_generation,
            durable_current.current.standing_id(),
        ) {
            Err(C2ExternalIngressRefusalV1::CurrentSignerRevoked) => {
                let effect_receipts = transaction
                    .prepare(
                        "SELECT effect_receipt_identity FROM c2_revocation_effects
                         WHERE physical_generation_identity = ?1
                           AND lifecycle_root_identity = ?2
                           AND scope_identity = ?3
                           AND target_enrollment_identity = ?4
                           AND target_public_key = ?5
                           AND target_key_generation = ?6
                           AND target_standing_identity = ?7",
                    )
                    .map_err(StoreError::from)
                    .map_err(C2LiveSignerRefusalV1::from)?
                    .query_map(
                        params![
                            durable_current.root.physical_store_generation(),
                            durable_current.root.lifecycle_root_id(),
                            durable_current.root.scope_id(),
                            durable_current.current.enrollment_id(),
                            durable_current.current_public_key.as_slice(),
                            key_generation,
                            durable_current.current.standing_id(),
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(StoreError::from)
                    .map_err(C2LiveSignerRefusalV1::from)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
                    .map_err(C2LiveSignerRefusalV1::from)?;
                if effect_receipts.len() != 1 {
                    return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch);
                }
                StoreVerifiedDiscontinuityConditionV1::GovernedCurrentSignerRevocation {
                    effect_receipt_identity: parse_digest(&effect_receipts[0])?,
                }
            }
            Ok(()) => {
                let prepared = self
                    .load_terminal_foundation_prepared_custody_v1(
                        authority,
                        admitted_manifest,
                        enrollment,
                    )
                    .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
                match C2StoreIntegrityCustodian::reopen_prepared_generation_current_for_actor(
                    self,
                    prepared,
                    enrollment.foundation(),
                ) {
                    Ok(current) => {
                        drop(current);
                        return Err(match lineage {
                            C2LiveFoundationalLineageV1::RestoreHistorical => {
                                C2DiscontinuityRefusalV1::RestoreEligibilityAbsent
                            }
                            C2LiveFoundationalLineageV1::RecoveryNewFoundation => {
                                C2DiscontinuityRefusalV1::RecoveryEligibilityAbsent
                            }
                            _ => C2DiscontinuityRefusalV1::OrdinaryContinuityRequired,
                        });
                    }
                    Err(_) => StoreVerifiedDiscontinuityConditionV1::OrdinaryContinuityUnavailable,
                }
            }
            Err(_) => return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch),
        };
        let current_binding_identity = digest_identity_bytes(durable_current.current.binding_id())?;
        let condition_identity =
            discontinuity_condition_identity_v1(lineage, &condition, current_binding_identity)
                .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        Ok(StoreVerifiedDiscontinuityEligibilityV1 {
            lineage,
            condition,
            condition_identity,
            current_binding_identity,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
        })
    }

    fn verify_discontinuity_eligibility_for_entry_v1(
        &self,
        eligibility: &StoreVerifiedDiscontinuityEligibilityV1,
        expected_lineage: C2LiveFoundationalLineageV1,
        durable_current: &StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<(), C2DiscontinuityRefusalV1> {
        if eligibility.creator_pid != std::process::id()
            || eligibility.actor_instance_identity != self.actor_instance_identity
            || eligibility.actor_snapshot_identity != self.current_snapshot_identity
            || eligibility.actor_effect_epoch != self.effect_epoch
            || eligibility.lineage != expected_lineage
            || eligibility.current_binding_identity
                != digest_identity_bytes(durable_current.current.binding_id())?
        {
            return Err(C2DiscontinuityRefusalV1::StaleOrConsumed);
        }
        Ok(())
    }

    /// Prepare one exact recovery custody proposal and canonical MSG-15
    /// request from Store-selected current state.  The returned value is
    /// deliberately inert; the newly created custodian and live eligibility
    /// seal are dropped before the asynchronous external-authority boundary.
    fn prepare_recovery_grant_request_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, 'actor_store>,
        intent: &C2RecoveryPreparationIntentV1,
    ) -> Result<StorePreparedRecoveryGrantRequestV1, C2LiveTransitionDriverRefusalV1> {
        self.verify_authority_snapshot(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let durable_current = self.resolve_generation_current_evidence_before_governance_v1()?;
        let eligibility = self.resolve_discontinuity_eligibility_v1(
            C2LiveFoundationalLineageV1::RecoveryNewFoundation,
            authority,
            admitted_manifest,
            &durable_current,
        )?;
        let status_exact = recovery_status_matches_discontinuity_condition_v1(
            &eligibility.condition,
            intent.predecessor_status,
        );
        if !status_exact {
            return Err(C2DiscontinuityRefusalV1::RecoveryEligibilityAbsent.into());
        }

        let current_enrollment = durable_current.durable_terminal.enrollment();
        let current_prepared = self.load_terminal_foundation_prepared_custody_v1(
            authority,
            admitted_manifest,
            current_enrollment,
        )?;
        let current_key_generation = current_enrollment.foundation().key_generation();
        let successor_key_generation = current_key_generation
            .checked_add(1)
            .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let successor_coordinates = current_prepared.recovery_successor_coordinates_for_actor(
            self,
            successor_key_generation,
            admitted_manifest.manifest_identity().clone(),
        )?;
        let scope_token = successor_coordinates.scope_token()?;
        let (next_ordinal, predecessor_frontier, committed) = resolve_custody_proposal_frontier_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &scope_token,
        )?;
        if next_ordinal
            != successor_key_generation
                .checked_add(1)
                .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?
        {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch.into());
        }
        let frontier = VerifiedCustodyProposalFrontierV1::from_store_actor_resolution(
            self,
            scope_token.clone(),
            next_ordinal,
            predecessor_frontier.clone(),
            committed,
        )?;
        let terminal_binding_identity = durable_current.current.binding_id().clone();
        let historical_foundation_identity = current_enrollment.foundation().identity().clone();
        let recovery_basis = StoreRecoveryCustodyPreparationBasisV1::from_store_actor_resolution(
            self,
            successor_coordinates,
            historical_foundation_identity.clone(),
            terminal_binding_identity.clone(),
            intent.recovery_transition_identity.clone(),
            intent.successor_pop_challenge_identity.clone(),
        )?;
        let (custodian, proposal) =
            C2StoreIntegrityCustodian::create_recovery_foundation_for_actor_v1(
                self,
                recovery_basis,
                &frontier,
            )?;
        let proposal_bytes = custodian.canonical_proposal_bytes()?;
        let proposal_identity = proposal.proposal_identity().clone();
        let successor_public_key = custodian.verifying_key()?;
        let proposed_effect_cut = durable_current
            .event_cut
            .checked_add(1)
            .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
        let desired_effect_projection_identity = digest_fields(
            b"nq.c2.recovery.desired_effect_projection.identity.v1\0",
            &[
                terminal_binding_identity.as_str().as_bytes(),
                historical_foundation_identity.as_str().as_bytes(),
                proposal_identity.as_str().as_bytes(),
                intent.recovery_transition_identity.as_str().as_bytes(),
                intent.successor_pop_challenge_identity.as_str().as_bytes(),
                &eligibility.condition_identity,
                &proposed_effect_cut.to_be_bytes(),
            ],
        );
        let terminal = authority.resolved.terminal_operator_authority();
        if terminal.permitted_scope() != "runtime_dependency_admission" {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch.into());
        }
        let current = authority.current_activation();
        let mut request_object = serde_json::json!({
            "schema": "nq.c2_store_integrity_recovery_request.v1",
            "schema_version": 1,
            "interpretation_policy": "nq.c2.a1_runtime_dependency_admission_refinement.v1",
            "issuer_a1_digest": terminal.record_digest().as_str(),
            "issuer_a1_key_generation": terminal.key_generation(),
            "issuer_a1_verification_key": hex::encode(terminal.verification_key()),
            "issuer_operator_principal": terminal.operator_principal(),
            "issuer_domain": terminal.domain(),
            "issuer_permitted_scope": terminal.permitted_scope(),
            "issuer_policy_version": terminal.policy_version(),
            "issuer_policy_floor": terminal.policy_floor(),
            "issued_against_gen4_cut": terminal.cut().sequence(),
            "issued_against_gen4_terminal_event": authority.resolved.terminal_authority_event_digest().as_str(),
            "issued_against_candidate_set": authority.resolved.candidate_set_digest().as_str(),
            "occurrence_id": current.occurrence_id(),
            "a2_chain_root": current.chain_root_activation_digest().as_str(),
            "controlling_activation": current.controlling_tip_activation_digest().as_str()
        })
        .as_object()
        .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?
        .clone();
        request_object.extend(
            serde_json::json!({
            "resident_identity": current.resident_identity(),
            "resident_generation": current.resident_generation(),
            "host_role": current.host_role(),
            "role_manifest_generation": current.role_manifest_generation(),
            "trust_anchor_id": current.trust_anchor_id().as_str(),
            "authority_domain": current.domain(),
            "activation_policy_version": current.policy_version(),
            "physical_store_generation_identity": durable_current.physical_generation_identity.as_str(),
            "signer_lifecycle_root_identity": durable_current.root.lifecycle_root_id(),
            "scope_identity": durable_current.root.scope_id(),
            "active_store_policy_identity": durable_current.current.policy_id(),
            "active_store_policy_generation": durable_current.active_policy_generation,
            "pre_effect_frontier_identity": identity_digest_from_bytes(durable_current.frontier_identity)?.as_str(),
            "desired_effect_projection_identity": desired_effect_projection_identity.as_str(),
            "proposed_effect_cut": proposed_effect_cut,
            "recovery_predecessor_binding_identity": terminal_binding_identity.as_str(),
            "predecessor_enrollment_identity": durable_current.current.enrollment_id()
            })
            .as_object()
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?
            .clone(),
        );
        request_object.extend(
            serde_json::json!({
            "predecessor_public_key": hex::encode(durable_current.current_public_key),
            "predecessor_key_generation": current_key_generation,
            "predecessor_standing_identity": durable_current.current.standing_id(),
            "predecessor_status": intent.predecessor_status.as_str(),
            "last_completed_lifecycle_receipt_identity": durable_current.current.persisted_resolution_id(),
            "successor_proposal_identity": proposal_identity.as_str(),
            "successor_custody_binding_identity": proposal_identity.as_str(),
            "successor_public_key": hex::encode(successor_public_key),
            "successor_key_generation": successor_key_generation,
            "successor_pop_challenge_identity": intent.successor_pop_challenge_identity.as_str(),
            "successor_pop_family": "nq.c2_store_integrity_successor_pop.v1",
            "recovery_successor_projection_identity": intent.recovery_transition_identity.as_str(),
            "disposition": "recovery_authorized"
            })
            .as_object()
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?
            .clone(),
        );
        let mut request_value = Value::Object(request_object);
        let request_body = canonical_json_bytes(&request_value)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let request_identity = recovery_request_identity_v1(&request_body);
        request_value
            .as_object_mut()
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?
            .insert(
                "recovery_request_identity".to_owned(),
                Value::String(request_identity.as_str().to_owned()),
            );
        let request = construct_recovery_request(request_value)?;
        let request_bytes = request.canonical_bytes().to_vec();
        let resulting_frontier = digest_fields(
            C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1,
            &[
                predecessor_frontier.as_str().as_bytes(),
                &next_ordinal.to_be_bytes(),
                proposal_identity.as_str().as_bytes(),
                request_identity.as_str().as_bytes(),
                sha256_bytes(&proposal_bytes).as_str().as_bytes(),
                sha256_bytes(&request_bytes).as_str().as_bytes(),
            ],
        );
        let preparation_identity = digest_fields(
            C2_CUSTODY_PREPARATION_DOMAIN_V1,
            &[
                b"recoveryNewFoundation",
                scope_token.as_str().as_bytes(),
                resulting_frontier.as_str().as_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                request_identity.as_str().as_bytes(),
                terminal_binding_identity.as_str().as_bytes(),
            ],
        );
        self.with_permitted_effect(
            StoreC2EffectKindV1::CustodyProposalPreparation,
            |transaction| {
                transaction
                    .execute(
                        "INSERT INTO c2_custody_proposal_preparations (
                        preparation_identity, preparation_lineage, occurrence_id,
                        scope_token, proposal_ordinal, predecessor_frontier_identity,
                        resulting_frontier_identity, proposal_identity,
                        proposal_canonical_bytes, proposal_canonical_sha256,
                        proposal_canonical_length, successor_request_identity,
                        successor_request_canonical_bytes,
                        successor_request_canonical_sha256,
                        successor_request_canonical_length,
                        predecessor_binding_identity, transition_identity,
                        historical_foundation_identity, terminal_binding_identity,
                        implementation_manifest_identity, qualified_candidate_identity,
                        source_tree_identity, runtime_artifact_identity, prepared_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                               ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                               ?19, ?20, ?21, ?22, ?23, ?24)",
                        params![
                            preparation_identity.as_str(),
                            "recoveryNewFoundation",
                            &durable_current.occurrence_id,
                            scope_token.as_str(),
                            next_ordinal,
                            predecessor_frontier.as_str(),
                            resulting_frontier.as_str(),
                            proposal_identity.as_str(),
                            &proposal_bytes,
                            sha256_bytes(&proposal_bytes).as_str(),
                            proposal_bytes.len() as u64,
                            request_identity.as_str(),
                            &request_bytes,
                            sha256_bytes(&request_bytes).as_str(),
                            request_bytes.len() as u64,
                            terminal_binding_identity.as_str(),
                            intent.recovery_transition_identity.as_str(),
                            historical_foundation_identity.as_str(),
                            terminal_binding_identity.as_str(),
                            admitted_manifest.manifest_identity().as_str(),
                            admitted_manifest.qualified_candidate_identity().as_str(),
                            admitted_manifest.source_tree_identity().as_str(),
                            admitted_manifest.runtime_artifact_identity().as_str(),
                            Utc::now().to_rfc3339(),
                        ],
                    )
                    .map_err(StoreError::from)?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-14");
                Ok::<(), C2LiveTransitionDriverRefusalV1>(())
            },
        )?;
        drop(custodian);
        Ok(StorePreparedRecoveryGrantRequestV1 {
            preparation_identity,
            request,
        })
    }

    /// Reopen the exact new-key custody proposal that was durably prepared
    /// for one recovery request.  The recovery request is inert evidence;
    /// this Store lookup rechecks its complete canonical bytes, route,
    /// predecessor/history coordinates, and admitted implementation basis
    /// before a current-process custodian can exist.
    fn reopen_prepared_recovery_custodian_v1(
        &self,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, 'actor_store>,
        request: &StoreIntegrityRecoveryRequestV1,
    ) -> Result<C2StoreIntegrityCustodian, C2LiveTransitionDriverRefusalV1> {
        self.verify_same_snapshot()?;
        let request_identity = identity_digest_from_bytes(*request.identity().bytes())?;
        let expected_proposal =
            discontinuity_digest_field(request.field("successor_proposal_identity"))?;
        let expected_predecessor =
            discontinuity_digest_field(request.field("recovery_predecessor_binding_identity"))?;
        let expected_transition =
            discontinuity_digest_field(request.field("recovery_successor_projection_identity"))?;
        let predecessor_enrollment =
            discontinuity_digest_field(request.field("predecessor_enrollment_identity"))?;
        let predecessor_enrollment = load_verified_durable_signer_enrollment_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &predecessor_enrollment,
        )?;
        let expected_historical = predecessor_enrollment.foundation().identity();
        let (
            preparation_lineage,
            proposal_identity,
            proposal_bytes,
            proposal_sha256,
            proposal_length,
            request_bytes,
            request_sha256,
            request_length,
            predecessor_binding,
            transition_identity,
            historical_foundation,
            terminal_binding,
            manifest_identity,
            candidate_identity,
            source_tree_identity,
            runtime_artifact_identity,
        ): (
            String,
            String,
            Vec<u8>,
            String,
            u64,
            Vec<u8>,
            String,
            u64,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ) = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .query_row(
                "SELECT preparation_lineage, proposal_identity,
                        proposal_canonical_bytes, proposal_canonical_sha256,
                        proposal_canonical_length,
                        successor_request_canonical_bytes,
                        successor_request_canonical_sha256,
                        successor_request_canonical_length,
                        predecessor_binding_identity, transition_identity,
                        historical_foundation_identity, terminal_binding_identity,
                        implementation_manifest_identity,
                        qualified_candidate_identity, source_tree_identity,
                        runtime_artifact_identity
                 FROM c2_custody_proposal_preparations
                 WHERE successor_request_identity = ?1",
                [request_identity.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                        row.get(14)?,
                        row.get(15)?,
                    ))
                },
            )
            .map_err(StoreError::from)?;
        if preparation_lineage != "recoveryNewFoundation"
            || proposal_identity != expected_proposal.as_str()
            || proposal_sha256 != sha256_bytes(&proposal_bytes).as_str()
            || proposal_length != proposal_bytes.len() as u64
            || request_bytes.as_slice() != request.canonical_bytes()
            || request_sha256 != sha256_bytes(&request_bytes).as_str()
            || request_length != request_bytes.len() as u64
            || predecessor_binding != expected_predecessor.as_str()
            || terminal_binding != expected_predecessor.as_str()
            || transition_identity != expected_transition.as_str()
            || historical_foundation != expected_historical.as_str()
            || manifest_identity != admitted_manifest.manifest_identity().as_str()
            || candidate_identity != admitted_manifest.qualified_candidate_identity().as_str()
            || source_tree_identity != admitted_manifest.source_tree_identity().as_str()
            || runtime_artifact_identity != admitted_manifest.runtime_artifact_identity().as_str()
        {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch.into());
        }
        let prepared = StoreVerifiedPreparedCustodyV1::from_store_selected_canonical_proposal(
            self,
            &proposal_bytes,
            admitted_manifest.manifest_identity().clone(),
        )?;
        C2StoreIntegrityCustodian::reopen_prepared_for_actor(self, prepared)
            .map_err(C2LiveTransitionDriverRefusalV1::from)
    }

    /// Reopen the exact completed physical generation under this fresh actor.
    ///
    /// Raw file names, digests, or a SQL current-binding row are insufficient:
    /// the method reconstructs the policy-selected geometry, authenticates the
    /// complete physical B/G record chain against its exact Store projection,
    /// reacquires the permanent lock from the physical MSG-03 frame, and
    /// rederives both the physical-generation and MSG-04 commitment bindings.
    fn reopen_complete_physical_generation_v1(
        &mut self,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, '_>,
        accepted: &StoreAcceptedSignerEnrollmentV1,
        custody: &VerifiedFoundationalCustodyV1<'_>,
        install_policy: &C2StoreGenerationInstallPolicyV1,
        evidence: &StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<usize, C2LiveInstallationDriverRefusalV1> {
        self.verify_same_snapshot()?;
        accepted
            .verify_for_actor(self)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        custody
            .verify_same_process()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        if install_policy.mode() != C2InstallationModeV1::Fresh
            || !installation_policy_binds_foundational_layer_v1(
                install_policy.enrollment().digest(),
                accepted.adoption().foundational().canonical_identity(),
                accepted.record().identity(),
            )
            || accepted.adoption().candidate().public_key != custody.public_key()
            || accepted.adoption().candidate().key_generation != custody.key_generation()
            || evidence
                .bootstrap_generation_relation
                .signer_enrollment_identity
                != *accepted.record().identity()
            || evidence
                .bootstrap_generation_relation
                .foundational_enrollment_identity
                != *accepted.adoption().foundational().canonical_identity()
            || evidence.bootstrap_generation_relation.initial_pop_identity
                != identity_digest_from_bytes(accepted.adoption().pop_identity())?
            || evidence
                .bootstrap_generation_relation
                .bootstrap_grant_identity
                != identity_digest_from_bytes(accepted.adoption().candidate().grant_identity)?
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }

        let geometry = install_policy.geometry();
        let layout = construct_wu_03_immutable_wu_append_extents_b_g_carrier(
            geometry.b_payload_bound,
            geometry.g_payload_bound,
            geometry.global_refusal_max_entries,
            geometry.global_refusal_entry_max_bytes,
        )?;
        let lock_file = File::from(
            openat(
                &self.root,
                super::C2_LOCK_FILE_V1,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(C2LiveSignerRefusalV1::Io)?,
        );
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-15");
        let b = File::from(
            openat(
                &self.root,
                super::C2_BOOTSTRAP_EXTENT_V1,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(C2LiveSignerRefusalV1::Io)?,
        );
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-16");
        let g = File::from(
            openat(
                &self.root,
                super::C2_GLOBAL_REFUSAL_EXTENT_V1,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(C2LiveSignerRefusalV1::Io)?,
        );
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-17");
        let lock_facts = exact_c2_carrier_file_facts_v1(&lock_file)?;
        let b_facts = exact_c2_carrier_file_facts_v1(&b)?;
        let g_facts = exact_c2_carrier_file_facts_v1(&g)?;
        let pair_input = C2CarrierPairInputV1 {
            occurrence_id: evidence.occurrence_id.clone(),
            physical_store_generation_identity: evidence.physical_generation_identity.clone(),
            qualified_backend_profile_identity: install_policy
                .qualified_backend_profile()
                .digest()
                .clone(),
            b_file: b_facts.clone(),
            g_file: g_facts.clone(),
        };
        let correspondence = construct_rec_30_pair_header_correspondence(&layout, pair_input)?;
        let pair = open_durable_append_pair_v1(&layout, &correspondence, &b, &g)?;
        let reprojected = self.with_permitted_effect(
            StoreC2EffectKindV1::RecoveryOrQuarantine,
            |transaction| -> Result<usize, C2LiveInstallationDriverRefusalV1> {
                let report = reproject_exact_durable_signer_carrier_suffix_v1(transaction, &pair)
                    .map_err(C2SignerAppendRefusalV1::Signer)
                    .map_err(C2LiveInstallationDriverRefusalV1::Signer)?;
                // Append-row reprojection is deliberately weaker than
                // lifecycle reconciliation.  Installation frames or a
                // completed transition receipt require their family-specific
                // recovery procedure; rolling this savepoint back prevents
                // either suffix from resealing stale GenerationCurrent.
                if report.requires_lifecycle_reconciliation() {
                    return Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete.into());
                }
                Ok(report.reprojected_count())
            },
        )?;
        verify_durable_signer_carrier_pair_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &pair,
        )
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        let b_genesis_frame = {
            let mut genesis = pair.authenticated_records().filter(|record| {
                record.role == crate::append_extent::C2AppendExtentRoleV1::BootstrapB
                    && record.kind == C2AppendFrameKindV1::StoreGenerationBootstrap
                    && record.slot == 0
            });
            let frame = genesis
                .next()
                .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?
                .frame_identity
                .clone();
            if genesis.next().is_some() {
                return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
            }
            frame
        };
        let lock = construct_wu_04_immutable_wu_local_lock_flock_process_registry(
            &self.root,
            &b_genesis_frame,
        )?;
        if lock.carrier().occurrence_id != evidence.occurrence_id
            || lock.carrier().physical_store_generation_identity
                != evidence.physical_generation_identity
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }

        let candidate = accepted.adoption().candidate();
        let prospective = digest_fields(
            b"nq.c2.prospective_physical_generation.preimage.v1\0",
            &[
                evidence.occurrence_id.as_bytes(),
                accepted.record().identity().as_str().as_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                custody.proposal_identity().as_str().as_bytes(),
                &candidate.attempt_identity,
            ],
        );
        let prospective_identity = digest_identity_bytes(&prospective)?;
        let rederived_physical_generation = digest_fields(
            b"nq.c2.physical_store_generation.identity.v1\0",
            &[
                evidence.occurrence_id.as_bytes(),
                &prospective_identity,
                accepted.record().identity().as_str().as_bytes(),
                install_policy.identity().digest().as_str().as_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                lock_facts.file_identity.as_str().as_bytes(),
                b_facts.file_identity.as_str().as_bytes(),
                g_facts.file_identity.as_str().as_bytes(),
            ],
        );
        let layout_bytes = canonical_json_bytes(&layout)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::Canonicalization)?;
        let bg_facts_identity = digest_fields(
            b"nq.c2.installation.bg_layout_profile_manifest_lock_facts.v1\0",
            &[
                &layout_bytes,
                correspondence.pair_identity().as_str().as_bytes(),
                correspondence.b_header().identity().as_str().as_bytes(),
                correspondence.g_header().identity().as_str().as_bytes(),
                install_policy
                    .qualified_backend_profile()
                    .digest()
                    .as_str()
                    .as_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                lock_facts.file_identity.as_str().as_bytes(),
            ],
        );
        let generation_commitment = digest_fields(
            b"nq.c2.physical_generation.commitment.v1\0",
            &[
                &prospective_identity,
                rederived_physical_generation.as_str().as_bytes(),
                accepted.record().identity().as_str().as_bytes(),
                install_policy.identity().digest().as_str().as_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                bg_facts_identity.as_str().as_bytes(),
            ],
        );
        if rederived_physical_generation != evidence.physical_generation_identity
            || generation_commitment
                != evidence
                    .bootstrap_generation_relation
                    .generation_commitment_identity
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        self.attach_durable_append_pair_v1(pair)?;
        self.attach_completed_generation_lock_v1(
            lock,
            &evidence.occurrence_id,
            &evidence.physical_generation_identity,
        )?;
        Ok(reprojected)
    }

    /// Mint a fresh-process GenerationCurrent brand from an exact completed
    /// durable state after custody and the physical B/G carrier have both
    /// been reopened under this actor.
    ///
    /// This is deliberately not a deserializer.  The durable resolver result
    /// supplies inert evidence only; the admitted manifest, freshly reopened
    /// custody, rewrapped enrollment and retained lock/descriptors are the
    /// non-persisted premises that make the result live in this process.
    /// Mint current signer authority from the lineage-neutral terminal proof.
    /// The durable enrollment and binding remain evidence; only this join with
    /// freshly admitted implementation, freshly authenticated custody, the
    /// retained physical generation, and the exact Store actor creates a live
    /// process-local context.
    fn mint_reopened_terminal_generation_current_v1<'live, 'store>(
        &self,
        authority: &'live StoreC2AuthoritySnapshotV1<'store>,
        admitted_manifest: &'live StoreAdmittedSignerImplementationManifestV1<'live, 'store>,
        custody: &'live VerifiedFoundationalCustodyV1<'live>,
        evidence: StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<
        C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
        C2LiveInstallationDriverRefusalV1,
    > {
        self.verify_authority_lineage(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        custody
            .verify_same_process()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let pair = self
            .durable_append_pair
            .as_ref()
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let lock = self
            .generation_lock
            .as_ref()
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)?;

        let terminal = &evidence.durable_terminal;
        let enrollment = terminal.enrollment();
        let foundation = enrollment.foundation();
        let adoption = enrollment.adoption();
        let acceptance = enrollment.acceptance();
        let current = terminal.terminal_binding();
        let current_generation = current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let physical_generation = parse_digest(evidence.root.physical_store_generation())?;
        let lifecycle_root = parse_digest(evidence.root.lifecycle_root_id())?;
        let scope = parse_digest(evidence.root.scope_id())?;
        let current_policy = parse_digest(current.policy_id())?;
        let standing = parse_digest(current.standing_id())?;
        let root_role_manifest_generation = evidence
            .root
            .role_manifest_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let current_activation = authority.current_activation();
        let pair_snapshot = pair.current_snapshot();
        if evidence.occurrence_id != authority.admission_basis().occurrence_id()
            || evidence.occurrence_id != current_activation.occurrence_id()
            || evidence.root.resident_id() != current_activation.resident_identity()
            || evidence.resident_generation != current_activation.resident_generation()
            || evidence.root.role_id() != current_activation.host_role()
            || root_role_manifest_generation != current_activation.role_manifest_generation()
            || evidence.root.domain_id() != current_activation.domain()
            || terminal.root().binding_id() != evidence.root.binding_id()
            || current.binding_id() != evidence.current.binding_id()
            || current.enrollment_id() != acceptance.identity().as_str()
            || acceptance.foundational_enrollment_identity() != adoption.identity()
            || adoption.foundation_identity() != foundation.identity()
            || foundation
                .public_key()
                .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?
                != custody.public_key()
            || foundation.key_generation() != custody.key_generation()
            || foundation.custody_evidence_identity() != custody.proposal_identity()
            || terminal.terminal_public_key() != custody.public_key()
            || current_generation != custody.key_generation()
            || evidence.current_public_key != custody.public_key()
            || adoption.occurrence_identity()
                != &identity_digest_from_bytes(text_identity_bytes(
                    b"nq.c2.store_occurrence.identity.v1\0",
                    &evidence.occurrence_id,
                ))?
            || adoption.signer_scope_identity() != &scope
            || custody.scope_identity() != digest_identity_bytes(&scope)?
            || evidence.implementation_manifest_identity != *admitted_manifest.manifest_identity()
            || lock.carrier().occurrence_id != evidence.occurrence_id
            || lock.carrier().physical_store_generation_identity != physical_generation
            || pair_snapshot.b_next_slot < 3
            || pair_snapshot.b_next_payload_offset <= evidence.pre_receipt_b_cursor
            || pair_snapshot.g_next_payload_offset < evidence.g_cursor
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        let lineage = match adoption.lineage() {
            FoundationalAdoptionLineageV1::InitialExternal => {
                C2LiveFoundationalLineageV1::InitialExternal
            }
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity => {
                C2LiveFoundationalLineageV1::OrdinarySuccessorContinuity
            }
            FoundationalAdoptionLineageV1::RestoreHistorical => {
                C2LiveFoundationalLineageV1::RestoreHistorical
            }
            FoundationalAdoptionLineageV1::RecoveryNewFoundation => {
                C2LiveFoundationalLineageV1::RecoveryNewFoundation
            }
        };
        let frontier_namespace = digest_fields(
            b"nq.c2.generation_current_frontier_namespace.v1\0",
            &[
                evidence.occurrence_id.as_bytes(),
                physical_generation.as_str().as_bytes(),
                lifecycle_root.as_str().as_bytes(),
                current.binding_id().as_str().as_bytes(),
            ],
        );
        let historical_foundation_identity = (adoption.lineage()
            == FoundationalAdoptionLineageV1::RestoreHistorical)
            .then(|| digest_identity_bytes(adoption.lineage_reference_identity()))
            .transpose()?;
        let coordinates = C2LiveSigningCoordinatesV1 {
            occurrence_id: evidence.occurrence_id.clone(),
            occurrence_identity: text_identity_bytes(
                b"nq.c2.store_occurrence.identity.v1\0",
                &evidence.occurrence_id,
            ),
            resident_identity: evidence.root.resident_id().to_owned(),
            resident_generation: evidence.resident_generation,
            host_role: evidence.root.role_id().to_owned(),
            role_manifest_identity: evidence.role_manifest_identity,
            role_manifest_generation: evidence
                .root
                .role_manifest_generation()
                .parse()
                .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?,
            authority_domain: evidence.root.domain_id().to_owned(),
            terminal_a1_identity: digest_identity_bytes(
                authority
                    .resolved
                    .terminal_operator_authority()
                    .record_digest(),
            )?,
            current_a2_identity: digest_identity_bytes(
                authority
                    .current_activation()
                    .controlling_tip_activation_digest(),
            )?,
            grant_identity: Some(digest_identity_bytes(
                adoption.authority_reference_identity(),
            )?),
            predecessor_standing_identity: None,
            standing_identity: digest_identity_bytes(&standing)?,
            signer_public_key: custody.public_key(),
            signer_key_generation: custody.key_generation(),
            signer_key_generation_identity: custody.key_generation_identity(),
            signer_scope_identity: custody.scope_identity(),
            signer_scope_policy_identity: custody.signer_scope_policy_identity(),
            signer_scope_policy_version: custody.signer_scope_policy_version(),
            active_policy_identity: digest_identity_bytes(&current_policy)?,
            active_policy_generation: evidence.active_policy_generation,
            active_policy_digest: digest_identity_bytes(&current_policy)?,
            attempt_identity: digest_identity_bytes(adoption.attempt_identity())?,
            physical_generation_identity: Some(digest_identity_bytes(&physical_generation)?),
            prospective_generation_preimage_identity: None,
            lifecycle_root_identity: Some(digest_identity_bytes(&lifecycle_root)?),
            current_binding_identity: Some(digest_identity_bytes(current.binding_id())?),
            foundational_lineage: lineage,
            lineage_authority_identity: Some(digest_identity_bytes(
                adoption.authority_reference_identity(),
            )?),
            request_identity: None,
            pending_challenge_identity: None,
            historical_foundation_identity,
            foundation_identity: Some(digest_identity_bytes(foundation.identity())?),
            adoption_identity: Some(digest_identity_bytes(adoption.identity())?),
            signer_acceptance_identity: Some(digest_identity_bytes(acceptance.identity())?),
            event_cut: evidence.event_cut,
            predecessor_event_identity: Some(evidence.predecessor_event_identity),
            transition_intent_identity: adoption
                .transition_identity()
                .map(digest_identity_bytes)
                .transpose()?,
            implementation_manifest_identity: digest_identity_bytes(
                admitted_manifest.manifest_identity(),
            )?,
            manifest_admission_correspondence_identity: digest_identity_bytes(
                &admitted_manifest.correspondence_identity(),
            )?,
            qualified_candidate_identity: digest_identity_bytes(
                admitted_manifest.qualified_candidate_identity(),
            )?,
            source_tree_identity: digest_identity_bytes(admitted_manifest.source_tree_identity())?,
            runtime_artifact_identity: digest_identity_bytes(
                admitted_manifest.runtime_artifact_identity(),
            )?,
            frontier_namespace_identity: digest_identity_bytes(&frontier_namespace)?,
            predecessor_frontier_identity: evidence.frontier_identity,
            exact_content_identity: digest_identity_bytes(&evidence.exact_content_identity)?,
            scope_class: C2LiveSigningScopeV1::GenerationBound,
            authority_class: C2LiveSigningAuthorityV1::GenerationCurrent,
        };
        Ok(C2LiveSignerContextV1 {
            authority_snapshot: authority,
            admitted_manifest,
            coordinates,
            foundational_custody: custody,
            phase: C2LiveSigningPhaseV1::GenerationCurrent,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
            _phase: PhantomData,
            _store: PhantomData,
        })
    }

    /// Reopen the immutable physical C2 substrate without minting current
    /// signer authority.  The bootstrap bridge authenticates only the B/G
    /// installation root; it is never treated as the current signer when a
    /// later lineage terminal is selected.  This inert helper is also the
    /// required substrate for externally rooted restore/recovery entry when
    /// current predecessor custody cannot be reopened.
    fn reopen_complete_physical_substrate_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, 'actor_store>,
        mut evidence: StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<StoreResolvedGenerationCurrentEvidenceV1, C2LiveInstallationDriverRefusalV1> {
        let bridge = load_verified_durable_enrollment_bridge_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &evidence
                .bootstrap_generation_relation
                .signer_enrollment_identity,
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let custodian = C2StoreIntegrityCustodian::reopen_from_foundational_evidence(
            bridge.foundational(),
            bridge.pre_generation_scope_identity(),
            admitted_manifest.manifest_identity(),
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let custody = custodian
            .seal_reopened_foundational_custody()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let (grant_request, grant) = load_durable_bootstrap_grant_pair_for_reopen_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            bridge.foundational().bootstrap_grant_request().digest(),
            bridge.foundational().bootstrap_grant().digest(),
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let calculation = load_install_policy_calculation_for_request_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            bridge.foundational().bootstrap_grant_request().digest(),
        )?;
        let grant_adoption = self
            .adopt_bootstrap_grant_v1(authority, &calculation, &custody, &grant_request, &grant)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let accepted = rewrap_verified_durable_enrollment_bridge_v1(
            self,
            authority,
            grant_adoption.verified(),
            &custody,
            bridge,
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let install_policy =
            self.derive_final_install_policy_v1(calculation, &grant_adoption, &accepted)?;
        let reprojected = self.reopen_complete_physical_generation_v1(
            admitted_manifest,
            &accepted,
            &custody,
            &install_policy,
            &evidence,
        )?;
        if reprojected != 0 {
            evidence = load_generation_current_evidence_before_governance_v1(
                self.transaction
                    .as_ref()
                    .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            )?;
        }
        Ok(evidence)
    }

    /// Execute one operation under a freshly reconstructed, process-local
    /// GenerationCurrent brand.  Every persisted input is loaded by this
    /// actor from its retained transaction; the caller cannot supply a prior
    /// process proposal, custody proof, accepted-enrollment wrapper, grant
    /// verification result, physical descriptor, or phase tag.
    fn with_reopened_generation_current_v1<R, E>(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, 'actor_store>,
        operation: impl for<'live> FnOnce(
            &'live mut StoreC2SnapshotActorV1<'actor_store>,
            &'live mut C2LiveSignerContextV1<'live, 'actor_store, GenerationCurrentV1>,
        ) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<C2LiveInstallationDriverRefusalV1>,
    {
        self.verify_authority_snapshot(authority)
            .map_err(C2LiveInstallationDriverRefusalV1::from)?;
        let evidence = self
            .resolve_generation_current_evidence_v1()
            .map_err(C2LiveInstallationDriverRefusalV1::from)?;
        let evidence = self
            .reopen_complete_physical_substrate_v1(authority, admitted_manifest, evidence)
            .map_err(E::from)?;
        let terminal_custodian = self
            .reopen_terminal_foundation_custodian_v1(
                authority,
                admitted_manifest,
                evidence.durable_terminal.enrollment(),
            )
            .map_err(E::from)?;
        let terminal_custody = terminal_custodian
            .verify_generation_current_custody()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)
            .map_err(E::from)?;
        let mut context = self
            .mint_reopened_terminal_generation_current_v1(
                authority,
                admitted_manifest,
                terminal_custody.foundational_custody(),
                evidence,
            )
            .map_err(E::from)?;
        operation(self, &mut context)
    }

    /// Exact database path observed before the actor transaction began.
    #[must_use]
    pub(crate) fn database_path(&self) -> &std::path::Path {
        &self.database_path
    }

    /// Reverify the database object and logical Store snapshot before an
    /// authority-bearing boundary.  This does not inspect mutable sidecars;
    /// completed-phase constructors must separately verify their retained C2
    /// generation lock/backend descriptors.
    pub(crate) fn verify_same_snapshot(&self) -> Result<(), C2LiveSignerRefusalV1> {
        if self.poisoned {
            return Err(C2LiveSignerRefusalV1::StoreSnapshotMismatch);
        }
        if self.creator_pid != std::process::id()
            || self.process_identity != current_process_identity()?
        {
            return Err(C2LiveSignerRefusalV1::PriorProcessAuthority);
        }
        let metadata = std::fs::metadata(&self.database_path)?;
        let retained_database = self.database_file.metadata()?;
        let retained_root = self.root.metadata()?;
        let database_name = self
            .database_path
            .file_name()
            .ok_or(C2LiveSignerRefusalV1::StoreBasisUnavailable)?;
        let resolved_database = File::from(
            openat(
                &self.root,
                database_name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-18");
        let resolved_metadata = resolved_database.metadata()?;
        let transaction = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?;
        let current = parse_digest(&logical_state_digest(
            transaction,
            LIVE_C2_STORE_SNAPSHOT_DOMAIN_V1,
        )?)?;
        if !metadata.file_type().is_file()
            || !retained_database.file_type().is_file()
            || !resolved_metadata.file_type().is_file()
            || (metadata.dev(), metadata.ino()) != (self.database_device, self.database_inode)
            || (retained_database.dev(), retained_database.ino())
                != (self.database_device, self.database_inode)
            || (resolved_metadata.dev(), resolved_metadata.ino())
                != (self.database_device, self.database_inode)
            || !retained_root.file_type().is_dir()
            || (retained_root.dev(), retained_root.ino()) != (self.root_device, self.root_inode)
            || current != self.current_snapshot_identity
        {
            return Err(C2LiveSignerRefusalV1::StoreSnapshotMismatch);
        }
        Ok(())
    }

    /// Run one C2-owned effect in the retained Store transaction.
    ///
    /// The pre-effect snapshot is reverified before the mutable transaction
    /// borrow is exposed.  On success the actor derives and retains the exact
    /// post-state snapshot and a before/kind/after transcript.  A later effect
    /// therefore starts from the prior effect's observed post-state; commit
    /// never requires a legitimate write to equal the original snapshot.
    fn with_permitted_effect<R, E>(
        &mut self,
        kind: StoreC2EffectKindV1,
        effect: impl FnOnce(&mut Transaction<'_>) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<C2LiveSignerRefusalV1>,
    {
        self.verify_same_snapshot().map_err(E::from)?;
        let before = self.current_snapshot_identity.clone();
        const SAVEPOINT: &str = "SAVEPOINT nq_c2_live_effect_v1";
        const ROLLBACK: &str = "ROLLBACK TO nq_c2_live_effect_v1; RELEASE nq_c2_live_effect_v1";
        const RELEASE: &str = "RELEASE nq_c2_live_effect_v1";
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)
            .map_err(E::from)?;
        transaction
            .execute_batch(SAVEPOINT)
            .map_err(StoreError::from)
            .map_err(C2LiveSignerRefusalV1::Store)
            .map_err(E::from)?;
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-19");
        let result = match effect(transaction) {
            Ok(result) => result,
            Err(refusal) => {
                if let Err(rollback_error) = transaction.execute_batch(ROLLBACK) {
                    self.poisoned = true;
                    return Err(E::from(C2LiveSignerRefusalV1::Store(
                        StoreError::Invariant(format!(
                            "C2 effect refused and its savepoint rollback failed: {rollback_error}"
                        )),
                    )));
                }
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-20");
                return Err(refusal);
            }
        };
        let post_effect_digest = if source_io_test_precursor_selected_v1("SC-21") {
            Err(C2LiveSignerRefusalV1::CorrespondenceMismatch)
        } else {
            logical_state_digest(transaction, LIVE_C2_STORE_SNAPSHOT_DOMAIN_V1)
                .map_err(C2LiveSignerRefusalV1::Store)
                .and_then(|digest| parse_digest(&digest))
        };
        let after = match post_effect_digest {
            Ok(after) => after,
            Err(refusal) => {
                if let Err(rollback_error) = transaction.execute_batch(ROLLBACK) {
                    self.poisoned = true;
                    return Err(E::from(C2LiveSignerRefusalV1::Store(
                        StoreError::Invariant(format!(
                            "C2 post-effect digest failed and its savepoint rollback failed: {rollback_error}"
                        )),
                    )));
                }
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-21");
                return Err(E::from(refusal));
            }
        };
        let changed = after != before;
        let next_effect_epoch = if changed {
            let advanced_epoch = if source_io_test_precursor_selected_v1("SC-22") {
                None
            } else {
                self.effect_epoch.checked_add(1)
            };
            match advanced_epoch {
                Some(epoch) => epoch,
                None => {
                    if let Err(rollback_error) = transaction.execute_batch(ROLLBACK) {
                        self.poisoned = true;
                        return Err(E::from(C2LiveSignerRefusalV1::Store(
                            StoreError::Invariant(format!(
                                "C2 effect epoch overflowed and its savepoint rollback failed: {rollback_error}"
                            )),
                        )));
                    }
                    #[cfg(test)]
                    super::source_io_crash_test_support::after_source_io_v1("SC-22");
                    return Err(E::from(C2LiveSignerRefusalV1::CorrespondenceMismatch));
                }
            }
        } else {
            self.effect_epoch
        };
        let kind_bytes = match kind {
            StoreC2EffectKindV1::CustodyProposalPreparation => {
                b"custody_proposal_preparation".as_slice()
            }
            StoreC2EffectKindV1::Installation => b"installation".as_slice(),
            StoreC2EffectKindV1::FoundationalEnrollmentAdoption => {
                b"foundational_enrollment_adoption".as_slice()
            }
            StoreC2EffectKindV1::SignerAcceptance => b"signer_acceptance".as_slice(),
            StoreC2EffectKindV1::GovernedCarrierIngress => b"governed_carrier_ingress".as_slice(),
            StoreC2EffectKindV1::SignerAppend => b"signer_append".as_slice(),
            StoreC2EffectKindV1::TerminalCurrentness => b"terminal_currentness".as_slice(),
            StoreC2EffectKindV1::RecoveryOrQuarantine => b"recovery_or_quarantine".as_slice(),
        };
        let transcript_entry = changed.then(|| {
            digest_fields(
                b"nq.c2.store_effect_transcript.v1\0",
                &[
                    before.as_str().as_bytes(),
                    kind_bytes,
                    after.as_str().as_bytes(),
                ],
            )
        });
        let release_result = if source_io_test_precursor_selected_v1("SC-24") {
            Err(rusqlite::Error::InvalidQuery)
        } else {
            transaction.execute_batch(RELEASE)
        };
        if let Err(release_error) = release_result {
            let rollback_result = transaction.execute_batch(ROLLBACK);
            if let Err(rollback_error) = rollback_result {
                self.poisoned = true;
                return Err(E::from(C2LiveSignerRefusalV1::Store(
                    StoreError::Invariant(format!(
                        "C2 effect savepoint release failed ({release_error}); rollback also failed ({rollback_error})"
                    )),
                )));
            }
            #[cfg(test)]
            super::source_io_crash_test_support::after_source_io_v1("SC-24");
            return Err(E::from(C2LiveSignerRefusalV1::Store(StoreError::from(
                release_error,
            ))));
        }
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-23");
        if let Some(transcript_entry) = transcript_entry {
            self.effect_transcript.push(transcript_entry);
            self.current_snapshot_identity = after;
            self.effect_epoch = next_effect_epoch;
        }
        Ok(result)
    }

    /// Adopt the exact foundational enrollment only after MSG-02 has been
    /// signed by the proposed key and durably consumed by this same actor.
    ///
    /// The actor owns both the append transaction and the post-effect seal.
    /// A raw foundational record, MSG-02 receipt, or digest cannot call the
    /// later signer-acceptance transition directly.
    pub(crate) fn adopt_foundational_enrollment_v1<'request, 'store>(
        &mut self,
        foundational: StoreIntegrityKeyEnrollmentV1,
        consumed: ConsumedInitialProposalPoPV1<'request, 'store>,
    ) -> Result<StoreAdoptedFoundationalEnrollmentV1, C2EnrollmentBridgeRefusalV1> {
        let prepared: PreparedFoundationalEnrollmentAdoptionV1 =
            prepare_store_foundational_enrollment_adoption_v1(self, foundational, consumed)?;
        prepared.verify_for_actor(self)?;
        let persisted: PersistedFoundationalEnrollmentAdoptionV1 = self.with_permitted_effect(
            StoreC2EffectKindV1::FoundationalEnrollmentAdoption,
            |transaction| {
                append_prepared_foundational_enrollment_adoption_v1(transaction, &prepared)
                    .map_err(C2EnrollmentBridgeRefusalV1::from)
            },
        )?;
        seal_store_adopted_foundational_enrollment_v1(self, prepared, persisted)
            .map_err(C2EnrollmentBridgeRefusalV1::from)
    }

    /// Accept signer enrollment at the unique later cut from one exact,
    /// already-adopted foundational enrollment.
    ///
    /// This consumes the sealed adoption.  There is no reverse constructor
    /// and the durable signer-acceptance record cannot reconstruct adoption.
    pub(crate) fn accept_signer_enrollment_v1(
        &mut self,
        adoption: StoreAdoptedFoundationalEnrollmentV1,
    ) -> Result<StoreAcceptedSignerEnrollmentV1, C2EnrollmentBridgeRefusalV1> {
        let prepared: PreparedSignerEnrollmentAcceptanceV1 =
            prepare_store_signer_enrollment_acceptance_v1(self, adoption)?;
        prepared.verify_for_actor(self)?;
        let persisted: PersistedSignerEnrollmentAcceptanceV1 =
            self.with_permitted_effect(StoreC2EffectKindV1::SignerAcceptance, |transaction| {
                append_prepared_signer_enrollment_acceptance_v1(transaction, &prepared)
                    .map_err(C2EnrollmentBridgeRefusalV1::from)
            })?;
        seal_store_accepted_signer_enrollment_v1(self, prepared, persisted)
            .map_err(C2EnrollmentBridgeRefusalV1::from)
    }

    /// Sole durable adoption boundary for ordinary-successor, restore, and
    /// recovery foundations.  The opaque consumed authority owns the closed
    /// lineage selection; this method accepts no raw lineage or coordinate
    /// tuple and yields foundation adoption only.
    fn adopt_consumed_foundational_enrollment_v1(
        &mut self,
        authority_snapshot: &StoreC2AuthoritySnapshotV1<'actor_store>,
        consumed: ConsumedStoreFoundationAdoptionAuthorityV1,
    ) -> Result<
        StoreAdoptedFoundationalEnrollmentV1<StoreConsumedFoundationalAdoptionProvenanceV1>,
        C2EnrollmentBridgeRefusalV1,
    > {
        let prepared: PreparedFoundationalEnrollmentAdoptionV1<
            StoreConsumedFoundationalAdoptionProvenanceV1,
        > = prepare_store_consumed_foundational_enrollment_adoption_v1(
            self,
            authority_snapshot,
            consumed,
        )?;
        prepared.verify_for_actor(self)?;
        let persisted = self.with_permitted_effect(
            StoreC2EffectKindV1::FoundationalEnrollmentAdoption,
            |transaction| {
                append_prepared_foundational_enrollment_adoption_v1(transaction, &prepared)
                    .map_err(C2EnrollmentBridgeRefusalV1::from)
            },
        )?;
        seal_store_adopted_foundational_enrollment_v1(self, prepared, persisted)
            .map_err(C2EnrollmentBridgeRefusalV1::from)
    }

    /// Later-cut signer acceptance for a sealed non-initial adoption.  This
    /// remains one-way: acceptance cannot reconstruct or authorize adoption.
    fn accept_consumed_signer_enrollment_v1(
        &mut self,
        adoption: StoreAdoptedFoundationalEnrollmentV1<
            StoreConsumedFoundationalAdoptionProvenanceV1,
        >,
    ) -> Result<
        StoreAcceptedSignerEnrollmentV1<StoreConsumedFoundationalAdoptionProvenanceV1>,
        C2EnrollmentBridgeRefusalV1,
    > {
        let prepared: PreparedSignerEnrollmentAcceptanceV1<
            StoreConsumedFoundationalAdoptionProvenanceV1,
        > = prepare_store_signer_enrollment_acceptance_v1(self, adoption)?;
        prepared.verify_for_actor(self)?;
        let persisted =
            self.with_permitted_effect(StoreC2EffectKindV1::SignerAcceptance, |transaction| {
                append_prepared_signer_enrollment_acceptance_v1(transaction, &prepared)
                    .map_err(C2EnrollmentBridgeRefusalV1::from)
            })?;
        seal_store_accepted_signer_enrollment_v1(self, prepared, persisted)
            .map_err(C2EnrollmentBridgeRefusalV1::from)
    }

    /// Atomically persist and immediately re-resolve one nominal healthy
    /// successor terminal.  The route-specific prepared value has already
    /// consumed the closed lineage proof, accepted enrollment, and MSG-12;
    /// this actor is the only production owner of the transaction.
    fn persist_healthy_successor_terminal_v1(
        &mut self,
        prior: &StoreVerifiedDurableGenerationCurrentV1,
        prepared: HealthySuccessorTerminalAppendV1,
    ) -> Result<StoreVerifiedDurableGenerationCurrentV1, C2LiveTransitionDriverRefusalV1> {
        self.with_permitted_effect(StoreC2EffectKindV1::TerminalCurrentness, |transaction| {
            append_healthy_successor_terminal_v1(transaction, prior, prepared)
                .map_err(C2LiveTransitionDriverRefusalV1::from)
        })
    }

    fn persist_restore_successor_terminal_v1(
        &mut self,
        prior: &StoreVerifiedDurableGenerationCurrentV1,
        prepared: RestoreSuccessorTerminalAppendV1,
    ) -> Result<StoreVerifiedDurableGenerationCurrentV1, C2LiveTransitionDriverRefusalV1> {
        self.with_permitted_effect(StoreC2EffectKindV1::TerminalCurrentness, |transaction| {
            append_restore_successor_terminal_v1(transaction, prior, prepared)
                .map_err(C2LiveTransitionDriverRefusalV1::from)
        })
    }

    fn persist_recovery_successor_terminal_v1(
        &mut self,
        prior: &StoreVerifiedDurableGenerationCurrentV1,
        prepared: RecoverySuccessorTerminalAppendV1,
    ) -> Result<StoreVerifiedDurableGenerationCurrentV1, C2LiveTransitionDriverRefusalV1> {
        self.with_permitted_effect(StoreC2EffectKindV1::TerminalCurrentness, |transaction| {
            append_recovery_successor_terminal_v1(transaction, prior, prepared)
                .map_err(C2LiveTransitionDriverRefusalV1::from)
        })
    }

    /// Construct MSG-12's restore selection coordinates exclusively from the
    /// sealed PendingSelected context and the exact durable enrollment/MSG-13
    /// rows.  No caller-provided candidate-set or resolution digest enters
    /// this boundary.
    fn append_store_derived_restore_msg12_v1(
        &mut self,
        selected: &mut C2LiveSignerContextV1<'_, '_, PendingSelectedV1>,
        prior: &StoreVerifiedDurableGenerationCurrentV1,
        enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    ) -> Result<ConsumedSignedFrameV1, C2LiveTransitionDriverRefusalV1> {
        selected.verify_live(self)?;
        if enrollment.adoption().lineage() != FoundationalAdoptionLineageV1::RestoreHistorical {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch.into());
        }
        let carrier_identity =
            digest_identity_bytes(enrollment.adoption().authority_reference_identity())?;
        let completed_effect: String = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .query_row(
                "SELECT effect_identity FROM c2_external_carrier_ingress
                 WHERE route = 'msg13_restore_authorization'
                   AND carrier_identity = ?1",
                [&carrier_identity[..]],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        let transition = selected
            .coordinates
            .transition_intent_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let complete_candidate_set = digest_fields_bytes(
            b"nq.c2.restore.complete_candidate_set.identity.v1\0",
            &[
                prior.terminal_candidate_set_identity().as_str().as_bytes(),
                enrollment.foundation().identity().as_str().as_bytes(),
                enrollment.adoption().identity().as_str().as_bytes(),
                enrollment.acceptance().identity().as_str().as_bytes(),
                enrollment
                    .adoption()
                    .authority_reference_identity()
                    .as_str()
                    .as_bytes(),
                &transition,
            ],
        );
        let pending_resolution = digest_fields_bytes(
            b"nq.c2.restore.pending_successor_resolution.identity.v1\0",
            &[
                &selected.coordinates.exact_content_identity,
                &selected
                    .coordinates
                    .physical_generation_identity
                    .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?,
                &selected
                    .coordinates
                    .lifecycle_root_identity
                    .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?,
                enrollment.acceptance_effect_identity().as_str().as_bytes(),
                enrollment.acceptance_receipt_identity().as_str().as_bytes(),
                &selected.coordinates.event_cut.to_be_bytes(),
            ],
        );
        self.append_pending_healthy_rotation_receipt_v1(
            selected,
            transition,
            digest_identity_bytes(&parse_digest(&completed_effect)?)?,
            complete_candidate_set,
            pending_resolution,
        )
        .map_err(C2LiveTransitionDriverRefusalV1::from)
    }

    /// Recovery has a distinct Store-derived MSG-12 namespace and consumes
    /// only the exact durable MSG-15 effect associated with the adopted new
    /// foundation.  This prevents restore/recovery receipt substitution.
    fn append_store_derived_recovery_msg12_v1(
        &mut self,
        selected: &mut C2LiveSignerContextV1<'_, '_, PendingSelectedV1>,
        prior: &StoreVerifiedDurableGenerationCurrentV1,
        enrollment: &StoreVerifiedDurableSignerEnrollmentV1,
    ) -> Result<ConsumedSignedFrameV1, C2LiveTransitionDriverRefusalV1> {
        selected.verify_live(self)?;
        if enrollment.adoption().lineage() != FoundationalAdoptionLineageV1::RecoveryNewFoundation {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch.into());
        }
        let carrier_identity =
            digest_identity_bytes(enrollment.adoption().authority_reference_identity())?;
        let completed_effect: String = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .query_row(
                "SELECT effect_identity FROM c2_external_carrier_ingress
                 WHERE route = 'msg15_recovery_grant'
                   AND carrier_identity = ?1",
                [&carrier_identity[..]],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        let transition = selected
            .coordinates
            .transition_intent_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let complete_candidate_set = digest_fields_bytes(
            b"nq.c2.recovery.complete_candidate_set.identity.v1\0",
            &[
                prior.terminal_candidate_set_identity().as_str().as_bytes(),
                enrollment.foundation().identity().as_str().as_bytes(),
                enrollment.adoption().identity().as_str().as_bytes(),
                enrollment.acceptance().identity().as_str().as_bytes(),
                enrollment
                    .adoption()
                    .authority_reference_identity()
                    .as_str()
                    .as_bytes(),
                &transition,
            ],
        );
        let pending_resolution = digest_fields_bytes(
            b"nq.c2.recovery.pending_successor_resolution.identity.v1\0",
            &[
                &selected.coordinates.exact_content_identity,
                &selected
                    .coordinates
                    .physical_generation_identity
                    .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?,
                &selected
                    .coordinates
                    .lifecycle_root_identity
                    .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?,
                enrollment.acceptance_effect_identity().as_str().as_bytes(),
                enrollment.acceptance_receipt_identity().as_str().as_bytes(),
                &selected.coordinates.event_cut.to_be_bytes(),
            ],
        );
        self.append_pending_healthy_rotation_receipt_v1(
            selected,
            transition,
            digest_identity_bytes(&parse_digest(&completed_effect)?)?,
            complete_candidate_set,
            pending_resolution,
        )
        .map_err(C2LiveTransitionDriverRefusalV1::from)
    }

    /// Complete one externally authorized historical-foundation restore.
    /// MSG-13 is first admitted as durable evidence; only this Store-owned
    /// driver can join it to the current discontinuity, exact historical
    /// terminal/foundation, freshly reopened custody, MSG-07, adoption,
    /// acceptance, MSG-12, and the append-only terminal projection.
    fn complete_store_restore_lifecycle_v1<'authority>(
        &mut self,
        authority: &'authority StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &'authority StoreAdmittedSignerImplementationManifestV1<
            'authority,
            'actor_store,
        >,
        request: &StoreIntegrityRestoreAuthorizationRequestV1,
        authorization: &StoreIntegrityRestoreAuthorizationV1,
    ) -> Result<Sha256Digest, C2LiveTransitionDriverRefusalV1> {
        let durable_before = self.resolve_generation_current_evidence_before_governance_v1()?;
        let durable_before = self.reopen_complete_physical_substrate_v1(
            authority,
            admitted_manifest,
            durable_before,
        )?;
        drop(durable_before);

        let adopted = self.adopt_restore_authorization_v1(authority, request, authorization)?;
        let durable_current = self.resolve_generation_current_evidence_before_governance_v1()?;
        let eligibility = self.resolve_discontinuity_eligibility_v1(
            C2LiveFoundationalLineageV1::RestoreHistorical,
            authority,
            admitted_manifest,
            &durable_current,
        )?;
        let target_enrollment =
            discontinuity_digest_field(request.field("target_signer_enrollment_identity"))?;
        let historical = load_verified_durable_signer_enrollment_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &target_enrollment,
        )?;
        let restored_custodian = self.reopen_terminal_foundation_custodian_v1(
            authority,
            admitted_manifest,
            &historical,
        )?;
        let restored_custody = restored_custodian.verify_generation_current_custody()?;
        let custody = restored_custody.foundational_custody();
        let basis = self.resolve_restore_entry_basis_v1(
            authority,
            admitted_manifest,
            &durable_current,
            &eligibility,
            &adopted,
            custody,
        )?;
        let entry = self.begin_restore_successor_v1(
            authority,
            admitted_manifest,
            &durable_current,
            adopted,
            basis,
        )?;
        let predecessor_binding = entry.coordinates.terminal_binding_identity;
        let transition = entry.coordinates.transition_identity;
        let challenge = entry.coordinates.challenge_identity;
        let prior = durable_current.durable_terminal;
        let mut pending = self.mint_restore_pending_possession_v1(&entry, custody)?;
        let permit = self.seal_restore_possession_permit_v1(entry, &pending)?;
        let possession = self.append_successor_possession_v1(
            &mut pending,
            challenge,
            predecessor_binding,
            transition,
        )?;
        let foundation_authority =
            self.refine_restore_foundation_after_msg07_v1(permit, &pending, possession)?;
        let consumed =
            self.consume_restore_foundation_authority_v1(foundation_authority, &pending)?;
        let adoption = self.adopt_consumed_foundational_enrollment_v1(authority, consumed)?;
        let accepted = self.accept_consumed_signer_enrollment_v1(adoption)?;
        let acceptance_identity = accepted.record().identity().clone();
        let mut selected =
            self.mint_pending_selected_from_consumed_acceptance_v1(pending, accepted)?;
        let successor_standing =
            identity_digest_from_bytes(selected.coordinates.standing_identity)?;
        let durable_enrollment = load_verified_durable_signer_enrollment_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &acceptance_identity,
        )?;
        let msg12 =
            self.append_store_derived_restore_msg12_v1(&mut selected, &prior, &durable_enrollment)?;
        let effective_cut = msg12
            .event_cut
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if selected.coordinates.event_cut != effective_cut {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch.into());
        }
        let historical_foundation = durable_enrollment.foundation().identity().clone();
        let restore_association = construct_restore_01_historical_foundation_base_join(
            prior.terminal_binding(),
            authority
                .resolved
                .terminal_operator_authority()
                .record_digest()
                .as_str()
                .to_owned(),
            durable_enrollment
                .adoption()
                .authority_reference_identity()
                .as_str()
                .to_owned(),
            prior.terminal_binding().binding_id().clone(),
            historical_foundation.as_str().to_owned(),
            historical_foundation.as_str().to_owned(),
            durable_enrollment.foundation().key_generation().to_string(),
            prior.terminal_binding().policy_id().to_owned(),
        )?;
        let restore_association = construct_restore_02_authorization_seals_predecessor_foundation(
            prior.terminal_binding(),
            restore_association,
        )?;
        let restore_predecessor = construct_restore_03_lawful_restore_predecessor_provenance(
            prior.terminal_binding().clone(),
            prior.terminal_binding().binding_id(),
            restore_association,
        )?;
        let ready = construct_restore_04_persistence_ready_restore_current(
            prior.root(),
            restore_predecessor,
            RestoreSuccessionInputV1 {
                transition_id: identity_digest_from_bytes(transition)?.as_str().to_owned(),
                restored_foundation_id: historical_foundation.as_str().to_owned(),
                successor_enrollment_id: acceptance_identity.as_str().to_owned(),
                successor_key_generation: durable_enrollment
                    .foundation()
                    .key_generation()
                    .to_string(),
                successor_policy_id: prior.terminal_binding().policy_id().to_owned(),
                successor_standing_id: successor_standing.as_str().to_owned(),
                receipt_id: identity_digest_from_bytes(msg12.message_identity)?
                    .as_str()
                    .to_owned(),
                append_id: msg12.append_identity.clone(),
                resolution_id: msg12.effect_receipt_identity.clone(),
                effective_cut,
            },
        )?;
        let prepared =
            prepare_restore_successor_terminal_append_v1(ready, &durable_enrollment, msg12)?;
        let current = self.persist_restore_successor_terminal_v1(&prior, prepared)?;
        Ok(current.terminal_binding().binding_id().clone())
    }

    /// Complete one exact prepared-custody MSG-15 recovery.  The prepared
    /// request and key remain inert until this driver reopens the exact row,
    /// verifies predecessor unavailability, consumes MSG-07, adopts a new
    /// foundation, and durably resolves the recovery terminal.
    fn complete_store_recovery_lifecycle_v1<'authority>(
        &mut self,
        authority: &'authority StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &'authority StoreAdmittedSignerImplementationManifestV1<
            'authority,
            'actor_store,
        >,
        request: &StoreIntegrityRecoveryRequestV1,
        grant: &StoreIntegrityRecoveryGrantV1,
    ) -> Result<Sha256Digest, C2LiveTransitionDriverRefusalV1> {
        let durable_before = self.resolve_generation_current_evidence_before_governance_v1()?;
        let durable_before = self.reopen_complete_physical_substrate_v1(
            authority,
            admitted_manifest,
            durable_before,
        )?;
        drop(durable_before);

        let adopted = self.adopt_recovery_grant_v1(authority, request, grant)?;
        let durable_current = self.resolve_generation_current_evidence_before_governance_v1()?;
        let eligibility = self.resolve_discontinuity_eligibility_v1(
            C2LiveFoundationalLineageV1::RecoveryNewFoundation,
            authority,
            admitted_manifest,
            &durable_current,
        )?;
        let recovered_custodian =
            self.reopen_prepared_recovery_custodian_v1(admitted_manifest, request)?;
        let custody = recovered_custodian.seal_reopened_foundational_custody()?;
        let basis = self.resolve_recovery_entry_basis_v1(
            authority,
            admitted_manifest,
            &durable_current,
            &eligibility,
            &adopted,
            &custody,
        )?;
        let entry = self.begin_recovery_entry_v1(
            authority,
            admitted_manifest,
            &durable_current,
            adopted,
            basis,
        )?;
        let predecessor_binding = entry.coordinates.terminal_binding_identity;
        let transition = entry.coordinates.transition_identity;
        let challenge = entry.coordinates.challenge_identity;
        let prior = durable_current.durable_terminal;
        let mut pending = self.mint_recovery_pending_possession_v1(&entry, &custody)?;
        let permit = self.seal_recovery_possession_permit_v1(entry, &pending)?;
        let possession = self.append_successor_possession_v1(
            &mut pending,
            challenge,
            predecessor_binding,
            transition,
        )?;
        let foundation_authority =
            self.refine_recovery_foundation_after_msg07_v1(permit, &pending, possession)?;
        let consumed =
            self.consume_recovery_foundation_authority_v1(foundation_authority, &pending)?;
        let adoption = self.adopt_consumed_foundational_enrollment_v1(authority, consumed)?;
        let accepted = self.accept_consumed_signer_enrollment_v1(adoption)?;
        let acceptance_identity = accepted.record().identity().clone();
        let mut selected =
            self.mint_pending_selected_from_consumed_acceptance_v1(pending, accepted)?;
        let successor_standing =
            identity_digest_from_bytes(selected.coordinates.standing_identity)?;
        let durable_enrollment = load_verified_durable_signer_enrollment_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &acceptance_identity,
        )?;
        let msg12 = self.append_store_derived_recovery_msg12_v1(
            &mut selected,
            &prior,
            &durable_enrollment,
        )?;
        let effective_cut = msg12
            .event_cut
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if selected.coordinates.event_cut != effective_cut {
            return Err(C2DiscontinuityRefusalV1::RouteOrLineageMismatch.into());
        }
        let recovery_association = construct_rpa_01_recovery_ledger_base_join(
            prior.terminal_binding(),
            durable_enrollment
                .adoption()
                .applicability_basis_identity()
                .as_str()
                .to_owned(),
            authority
                .resolved
                .terminal_operator_authority()
                .record_digest()
                .as_str()
                .to_owned(),
            durable_enrollment
                .adoption()
                .authority_reference_identity()
                .as_str()
                .to_owned(),
            prior.terminal_binding().binding_id().clone(),
            durable_enrollment.foundation().key_generation().to_string(),
            prior.terminal_binding().policy_id().to_owned(),
        )?;
        let recovery_association =
            construct_rpa_02_authorization_seals_predecessor_condition_grant(
                prior.terminal_binding(),
                recovery_association,
            )?;
        let recovery_predecessor = construct_rpa_03_lawful_recovery_predecessor_provenance(
            prior.terminal_binding().clone(),
            prior.terminal_binding().binding_id(),
            recovery_association,
        )?;
        let ready = construct_rpa_04_persistence_ready_recovery_current(
            prior.root(),
            recovery_predecessor,
            RecoverySuccessionInputV1 {
                transition_id: identity_digest_from_bytes(transition)?.as_str().to_owned(),
                successor_enrollment_id: acceptance_identity.as_str().to_owned(),
                successor_key_generation: durable_enrollment
                    .foundation()
                    .key_generation()
                    .to_string(),
                successor_policy_id: prior.terminal_binding().policy_id().to_owned(),
                successor_standing_id: successor_standing.as_str().to_owned(),
                receipt_id: identity_digest_from_bytes(msg12.message_identity)?
                    .as_str()
                    .to_owned(),
                append_id: msg12.append_identity.clone(),
                resolution_id: msg12.effect_receipt_identity.clone(),
                effective_cut,
            },
        )?;
        let prepared =
            prepare_recovery_successor_terminal_append_v1(ready, &durable_enrollment, msg12)?;
        let current = self.persist_recovery_successor_terminal_v1(&prior, prepared)?;
        Ok(current.terminal_binding().binding_id().clone())
    }

    /// Store-selected refinement from a non-standing possession phase plus
    /// exact sealed adoption/acceptance into PendingSelected.  The accepted
    /// record is consumed; neither it nor the prior pending record can be
    /// replayed to select a second successor.
    fn mint_pending_selected_from_consumed_acceptance_v1<'live, 'store>(
        &self,
        pending: C2LiveSignerContextV1<'live, 'store, PendingPossessionV1>,
        accepted: StoreAcceptedSignerEnrollmentV1<StoreConsumedFoundationalAdoptionProvenanceV1>,
    ) -> Result<C2LiveSignerContextV1<'live, 'store, PendingSelectedV1>, C2EnrollmentBridgeRefusalV1>
    {
        accepted.verify_for_actor(self)?;
        let adoption = accepted.adoption();
        let foundation = adoption.foundation();
        let durable_adoption = adoption.adoption_record();
        let expected_live_lineage = match durable_adoption.lineage() {
            FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity => {
                C2LiveFoundationalLineageV1::OrdinarySuccessorContinuity
            }
            FoundationalAdoptionLineageV1::RestoreHistorical => {
                C2LiveFoundationalLineageV1::RestoreHistorical
            }
            FoundationalAdoptionLineageV1::RecoveryNewFoundation => {
                C2LiveFoundationalLineageV1::RecoveryNewFoundation
            }
            FoundationalAdoptionLineageV1::InitialExternal => {
                return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
            }
        };
        let expected_epoch = pending
            .actor_effect_epoch
            .checked_add(2)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if pending.creator_pid != std::process::id()
            || pending.actor_instance_identity != self.actor_instance_identity
            || expected_epoch != self.effect_epoch
            || pending.coordinates.foundational_lineage != expected_live_lineage
            || foundation.public_key()? != pending.coordinates.signer_public_key
            || foundation.key_generation() != pending.coordinates.signer_key_generation
            || foundation.custody_evidence_identity()
                != pending.foundational_custody.custody_evidence_identity()
            || durable_adoption.proposal_identity()
                != pending.foundational_custody.proposal_identity()
            || accepted.record().foundational_enrollment_identity() != durable_adoption.identity()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
        }
        let mut coordinates = pending.coordinates;
        coordinates.foundation_identity = Some(digest_identity_bytes(foundation.identity())?);
        coordinates.adoption_identity = Some(digest_identity_bytes(durable_adoption.identity())?);
        coordinates.signer_acceptance_identity =
            Some(digest_identity_bytes(accepted.record().identity())?);
        // PendingSelected carries the exact acceptance-derived prospective
        // standing identity.  It is still not GenerationCurrent authority,
        // but the later terminal binding must retain this same identity
        // rather than inventing a second post-MSG-12 standing taxonomy.
        coordinates.standing_identity = digest_fields_bytes(
            b"nq.c2.pending_selected.acceptance_derived_standing.identity.v1\0",
            &[
                foundation.identity().as_str().as_bytes(),
                durable_adoption.identity().as_str().as_bytes(),
                accepted.record().identity().as_str().as_bytes(),
                accepted.acceptance_receipt_identity().as_str().as_bytes(),
                &coordinates
                    .transition_intent_identity
                    .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?,
            ],
        );
        // MSG-12 is a later lifecycle occurrence, not another spelling of
        // signer acceptance.  Its canonical message therefore starts at the
        // strict successor cut; terminal currentness is later again.
        coordinates.event_cut = accepted
            .record()
            .accepted_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        coordinates.exact_content_identity = digest_fields_bytes(
            b"nq.c2.pending_selected.exact_content.v1\0",
            &[
                &coordinates.exact_content_identity,
                foundation.identity().as_str().as_bytes(),
                durable_adoption.identity().as_str().as_bytes(),
                accepted.record().identity().as_str().as_bytes(),
                accepted.acceptance_receipt_identity().as_str().as_bytes(),
            ],
        );
        Ok(C2LiveSignerContextV1 {
            authority_snapshot: pending.authority_snapshot,
            admitted_manifest: pending.admitted_manifest,
            coordinates,
            foundational_custody: pending.foundational_custody,
            phase: C2LiveSigningPhaseV1::PendingSelected,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
            _phase: PhantomData,
            _store: PhantomData,
        })
    }

    /// Create and durably register the exact inert custody proposal for one
    /// ordinary successor.  This operation deliberately precedes MSG-07 and
    /// MSG-06: the preparation row therefore records the predecessor and
    /// transition coordinates but no serialized authority reference.
    fn prepare_ordinary_successor_custody_v1(
        &mut self,
        current: &mut C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        transition_identity: Sha256Digest,
        successor_challenge_identity: Sha256Digest,
    ) -> Result<
        (
            C2StoreIntegrityCustodian,
            StoreOrdinarySuccessorCustodyPreparationRequestV1,
        ),
        C2CustodyPreparationRefusalV1,
    > {
        current.verify_live(self)?;
        let activation = current.authority_snapshot.current_activation();
        let next_generation = current
            .coordinates
            .signer_key_generation
            .checked_add(1)
            .ok_or(SignerRefusalV2::CustodyPathMismatch)?;
        let coordinates = PreGenerationCustodyCoordinatesV1 {
            occurrence_id: current.coordinates.occurrence_id.clone(),
            scope_identity: identity_digest_from_bytes(current.coordinates.signer_scope_identity)?,
            a2_chain_root_identity: activation.chain_root_activation_digest().clone(),
            trust_anchor_identity: activation.trust_anchor_id().clone(),
            resident_identity: current.coordinates.resident_identity.clone(),
            resident_generation: current.coordinates.resident_generation,
            host_role: current.coordinates.host_role.clone(),
            role_manifest_generation: current.coordinates.role_manifest_generation,
            authority_domain: current.coordinates.authority_domain.clone(),
            signer_scope_policy_identity: identity_digest_from_bytes(
                current.coordinates.signer_scope_policy_identity,
            )?,
            signer_scope_policy_version: current.coordinates.signer_scope_policy_version,
            proposed_key_generation: next_generation,
            custodian_implementation_manifest_identity: current
                .admitted_manifest
                .manifest_identity()
                .clone(),
        };
        let scope_token = coordinates.scope_token()?;
        let (next_ordinal, predecessor_frontier, committed) = resolve_custody_proposal_frontier_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &scope_token,
        )?;
        if next_ordinal
            != next_generation
                .checked_add(1)
                .ok_or(SignerRefusalV2::CustodyPathMismatch)?
        {
            return Err(SignerRefusalV2::CustodyPathMismatch.into());
        }
        let frontier = VerifiedCustodyProposalFrontierV1::from_store_actor_resolution(
            self,
            scope_token.clone(),
            next_ordinal,
            predecessor_frontier.clone(),
            committed,
        )?;
        let current_view = current.signing_view();
        let (custodian, proposal, request) =
            C2StoreIntegrityCustodian::create_ordinary_successor_for_actor_v1(
                self,
                &current_view,
                coordinates,
                &frontier,
                transition_identity.clone(),
                successor_challenge_identity,
            )?;
        let proposal_bytes = custodian.canonical_proposal_bytes()?;
        let proposal_identity = proposal.proposal_identity().clone();
        let request_bytes = request.canonical_bytes()?;
        let request_identity = request.identity().clone();
        let resulting_frontier = digest_fields(
            C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1,
            &[
                predecessor_frontier.as_str().as_bytes(),
                &next_ordinal.to_be_bytes(),
                proposal_identity.as_str().as_bytes(),
                request_identity.as_str().as_bytes(),
                sha256_bytes(&proposal_bytes).as_str().as_bytes(),
                sha256_bytes(&request_bytes).as_str().as_bytes(),
            ],
        );
        let preparation_identity = digest_fields(
            C2_CUSTODY_PREPARATION_DOMAIN_V1,
            &[
                b"ordinarySuccessorContinuity",
                scope_token.as_str().as_bytes(),
                resulting_frontier.as_str().as_bytes(),
                current
                    .admitted_manifest
                    .manifest_identity()
                    .as_str()
                    .as_bytes(),
                transition_identity.as_str().as_bytes(),
            ],
        );
        let predecessor_binding = identity_digest_from_bytes(
            current
                .coordinates
                .current_binding_identity
                .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?,
        )?;
        self.with_permitted_effect(
            StoreC2EffectKindV1::CustodyProposalPreparation,
            |transaction| {
                transaction.execute(
                    "INSERT INTO c2_custody_proposal_preparations (
                        preparation_identity, preparation_lineage, occurrence_id,
                        scope_token, proposal_ordinal, predecessor_frontier_identity,
                        resulting_frontier_identity, proposal_identity,
                        proposal_canonical_bytes, proposal_canonical_sha256,
                        proposal_canonical_length, successor_request_identity,
                        successor_request_canonical_bytes,
                        successor_request_canonical_sha256,
                        successor_request_canonical_length,
                        predecessor_binding_identity, transition_identity,
                        implementation_manifest_identity, qualified_candidate_identity,
                        source_tree_identity, runtime_artifact_identity, prepared_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                               ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                               ?19, ?20, ?21, ?22)",
                    params![
                        preparation_identity.as_str(),
                        "ordinarySuccessorContinuity",
                        &current.coordinates.occurrence_id,
                        scope_token.as_str(),
                        next_ordinal,
                        predecessor_frontier.as_str(),
                        resulting_frontier.as_str(),
                        proposal_identity.as_str(),
                        &proposal_bytes,
                        sha256_bytes(&proposal_bytes).as_str(),
                        proposal_bytes.len() as u64,
                        request_identity.as_str(),
                        &request_bytes,
                        sha256_bytes(&request_bytes).as_str(),
                        request_bytes.len() as u64,
                        predecessor_binding.as_str(),
                        transition_identity.as_str(),
                        current.admitted_manifest.manifest_identity().as_str(),
                        current
                            .admitted_manifest
                            .qualified_candidate_identity()
                            .as_str(),
                        current.admitted_manifest.source_tree_identity().as_str(),
                        current
                            .admitted_manifest
                            .runtime_artifact_identity()
                            .as_str(),
                        Utc::now().to_rfc3339(),
                    ],
                )?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-25");
                Ok::<(), C2CustodyPreparationRefusalV1>(())
            },
        )?;
        current.actor_snapshot_identity = self.current_snapshot_identity.clone();
        current.actor_effect_epoch = self.effect_epoch;
        current.coordinates.exact_content_identity = digest_fields_bytes(
            b"nq.c2.current_after_ordinary_custody_preparation.v1\0",
            &[
                &current.coordinates.exact_content_identity,
                preparation_identity.as_str().as_bytes(),
                resulting_frontier.as_str().as_bytes(),
            ],
        );
        current.verify_live(self)?;
        Ok((custodian, request))
    }

    /// Select the non-standing PendingPossession phase for one ordinary
    /// successor.  The successor key/custody is Store-verified, while the
    /// exact predecessor remains separately live in `current`.
    fn mint_ordinary_successor_pending_possession_v1<'live, 'store>(
        &self,
        current: &C2LiveSignerContextV1<'live, 'store, GenerationCurrentV1>,
        successor_custody: &'live VerifiedFoundationalCustodyV1<'live>,
        successor_proposal_cut: u64,
        successor_challenge_identity: [u8; 32],
        transition_identity: [u8; 32],
    ) -> Result<C2LiveSignerContextV1<'live, 'store, PendingPossessionV1>, C2LiveSignerRefusalV1>
    {
        current.verify_live(self)?;
        successor_custody
            .verify_same_process()
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let successor_proposal_identity =
            digest_identity_bytes(successor_custody.proposal_identity())?;
        let expected_generation = current
            .coordinates
            .signer_key_generation
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if successor_proposal_cut <= current.coordinates.event_cut
            || successor_custody.key_generation() != expected_generation
            || successor_custody.scope_identity() != current.coordinates.signer_scope_identity
            || successor_custody.signer_scope_policy_identity()
                != current.coordinates.signer_scope_policy_identity
            || successor_challenge_identity.iter().all(|byte| *byte == 0)
            || transition_identity.iter().all(|byte| *byte == 0)
            || current.coordinates.current_binding_identity.is_none()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        let pending_authority = digest_fields(
            b"nq.c2.pending_possession.ordinary_successor.authority.v1\0",
            &[
                &current.coordinates.standing_identity,
                &successor_proposal_identity,
                &successor_challenge_identity,
                &transition_identity,
                self.current_snapshot_identity.as_str().as_bytes(),
                &successor_proposal_cut.to_be_bytes(),
            ],
        );
        let exact_content = digest_fields(
            b"nq.c2.pending_possession.ordinary_successor.exact_content.v1\0",
            &[
                &current.coordinates.exact_content_identity,
                successor_custody.proposal_identity().as_str().as_bytes(),
                &successor_challenge_identity,
                &transition_identity,
            ],
        );
        let mut coordinates = current.coordinates.clone();
        coordinates.predecessor_standing_identity = Some(current.coordinates.standing_identity);
        coordinates.standing_identity = digest_identity_bytes(&pending_authority)?;
        coordinates.signer_public_key = successor_custody.public_key();
        coordinates.signer_key_generation = successor_custody.key_generation();
        coordinates.signer_key_generation_identity = successor_custody.key_generation_identity();
        coordinates.attempt_identity = digest_fields_bytes(
            b"nq.c2.ordinary_successor.attempt.identity.v1\0",
            &[&successor_proposal_identity, &transition_identity],
        );
        coordinates.event_cut = successor_proposal_cut
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        coordinates.transition_intent_identity = Some(transition_identity);
        coordinates.foundational_lineage = C2LiveFoundationalLineageV1::OrdinarySuccessorContinuity;
        coordinates.lineage_authority_identity = None;
        coordinates.request_identity = None;
        coordinates.pending_challenge_identity = Some(successor_challenge_identity);
        coordinates.historical_foundation_identity = None;
        coordinates.foundation_identity = None;
        coordinates.adoption_identity = None;
        coordinates.signer_acceptance_identity = None;
        coordinates.exact_content_identity = digest_identity_bytes(&exact_content)?;
        coordinates.authority_class = C2LiveSigningAuthorityV1::PendingSuccessor;
        Ok(C2LiveSignerContextV1 {
            authority_snapshot: current.authority_snapshot,
            admitted_manifest: current.admitted_manifest,
            coordinates,
            foundational_custody: successor_custody,
            phase: C2LiveSigningPhaseV1::PendingPossession,
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            creator_pid: std::process::id(),
            _phase: PhantomData,
            _store: PhantomData,
        })
    }

    /// Sole Store-actor caller for typed MSG-07 successor possession.
    fn append_successor_possession_v1(
        &mut self,
        pending: &mut C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
        successor_challenge_identity: [u8; 32],
        predecessor_binding_identity: [u8; 32],
        transition_identity: [u8; 32],
    ) -> Result<ConsumedSuccessorPossessionV1, C2SignerAppendRefusalV1> {
        let facts = StoreVerifiedSuccessorPossessionFactsV1::from_store_actor_resolution(
            self,
            pending,
            successor_challenge_identity,
            predecessor_binding_identity,
            transition_identity,
        )?;
        let mut coordinator = C2SignerTransitionCoordinator::from_store_actor(self, pending)?;
        coordinator.append_successor_possession(facts)
    }

    /// Refine the retained predecessor after MSG-07.  The old predecessor
    /// context is intentionally stale; only this in-place Store check can
    /// advance it to the exact MSG-07 frontier without duplicating authority.
    fn refresh_current_predecessor_after_msg07_v1(
        &self,
        current: &mut C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        pending: &C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
        possession: &ConsumedSuccessorPossessionV1,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        pending.verify_live(self)?;
        possession
            .verify_for_actor(self)
            .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let prior_epoch = current
            .actor_effect_epoch
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if current.creator_pid != std::process::id()
            || current.actor_instance_identity != self.actor_instance_identity
            || prior_epoch != self.effect_epoch
            || current
                .authority_snapshot
                .admission_basis()
                .process_identity()
                != pending
                    .authority_snapshot
                    .admission_basis()
                    .process_identity()
            || current.coordinates.occurrence_id != pending.coordinates.occurrence_id
            || current.coordinates.physical_generation_identity
                != pending.coordinates.physical_generation_identity
            || current.coordinates.lifecycle_root_identity
                != pending.coordinates.lifecycle_root_identity
            || current.coordinates.current_binding_identity
                != pending.coordinates.current_binding_identity
            || Some(current.coordinates.standing_identity)
                != pending.coordinates.predecessor_standing_identity
            || possession.successor_proposal_identity()
                != digest_identity_bytes(pending.foundational_custody.proposal_identity())?
            || Some(possession.transition_identity())
                != pending.coordinates.transition_intent_identity
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        current.actor_snapshot_identity = self.current_snapshot_identity.clone();
        current.actor_effect_epoch = self.effect_epoch;
        current.coordinates.predecessor_frontier_identity =
            possession.resulting_frontier_identity();
        current.coordinates.predecessor_event_identity = Some(possession.message_identity());
        // The refreshed predecessor remains A's authority, but its next
        // signing operation is now purpose-bound to this exact proposed
        // successor transition.  Bootstrap currentness legitimately has no
        // historical transition identity; MSG-06/MSG-11 must therefore take
        // the transition only from the retained pending-successor context,
        // never from stale terminal records or caller coordinates.
        current.coordinates.transition_intent_identity =
            pending.coordinates.transition_intent_identity;
        current.coordinates.event_cut = pending
            .coordinates
            .event_cut
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        current.coordinates.exact_content_identity = digest_fields_bytes(
            b"nq.c2.current_predecessor.after_msg07.exact_content.v1\0",
            &[
                &current.coordinates.exact_content_identity,
                &possession.message_identity(),
                possession.append_identity().as_bytes(),
                possession.effect_receipt_identity().as_bytes(),
            ],
        );
        current.verify_live(self)
    }

    /// Sole Store-actor caller for the mandatory MSG-06, conditional MSG-05,
    /// and MSG-11 healthy-successor sequence.  It first refreshes the exact
    /// current predecessor from MSG-07, then reseals the still-pending
    /// successor at the resulting frontier.
    #[allow(clippy::too_many_arguments)]
    fn append_healthy_rotation_intent_v1(
        &mut self,
        current: &mut C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        pending: &mut C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
        possession: ConsumedSuccessorPossessionV1,
        transition_cut: u64,
        target_active_policy_identity: [u8; 32],
        target_activation_identity: [u8; 32],
        target_applicability_identity: [u8; 32],
    ) -> Result<StoreVerifiedOrdinarySuccessorFoundationAuthorityV1, C2SignerAppendRefusalV1> {
        self.refresh_current_predecessor_after_msg07_v1(current, pending, &possession)?;
        let predecessor = self.mint_current_predecessor_authority_v1(current)?;
        self.consume_current_predecessor_authority_v1(predecessor, current)?;
        let prior_enrollment_identity = current
            .coordinates
            .signer_acceptance_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let rotation_predecessor_identity = current
            .coordinates
            .current_binding_identity
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?;
        let facts = StoreVerifiedHealthyRotationIntentFactsV1::from_store_actor_resolution(
            self,
            current,
            &possession,
            prior_enrollment_identity,
            rotation_predecessor_identity,
            transition_cut,
            target_active_policy_identity,
            target_activation_identity,
            target_applicability_identity,
        )?;
        let mut coordinator = C2SignerTransitionCoordinator::from_store_actor(self, current)?;
        let continuity = coordinator.append_healthy_rotation_intent(facts)?;
        current.verify_live(self)?;
        if pending.actor_instance_identity != self.actor_instance_identity
            || pending.coordinates.current_binding_identity
                != current.coordinates.current_binding_identity
            || pending.coordinates.transition_intent_identity
                != Some(continuity.transition_identity())
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
        }
        pending.actor_snapshot_identity = self.current_snapshot_identity.clone();
        pending.actor_effect_epoch = self.effect_epoch;
        pending.coordinates.event_cut = current.coordinates.event_cut;
        pending.coordinates.predecessor_event_identity =
            current.coordinates.predecessor_event_identity;
        pending.coordinates.predecessor_frontier_identity =
            current.coordinates.predecessor_frontier_identity;
        // MSG-11 is the signed completion of the already-selected transition,
        // not a replacement transition identity. MSG-12 and the durable
        // enrollment must continue to name the original exact transition;
        // the MSG-11 append identity is joined separately as completed input.
        pending.coordinates.transition_intent_identity = Some(continuity.transition_identity());
        let prior_applicability_identity =
            current_healthy_rotation_applicability_identity_v1(&pending.coordinates);
        let policy_changed = target_active_policy_identity
            != pending.coordinates.active_policy_identity
            || target_activation_identity != pending.coordinates.current_a2_identity
            || target_applicability_identity != prior_applicability_identity;
        pending.coordinates.active_policy_identity = target_active_policy_identity;
        pending.coordinates.active_policy_digest = target_active_policy_identity;
        pending.coordinates.current_a2_identity = target_activation_identity;
        if policy_changed {
            pending.coordinates.active_policy_generation = pending
                .coordinates
                .active_policy_generation
                .checked_add(1)
                .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        }
        pending.coordinates.exact_content_identity = digest_fields_bytes(
            b"nq.c2.pending_possession.after_healthy_continuity.exact_content.v1\0",
            &[
                &pending.coordinates.exact_content_identity,
                &continuity.mandatory_msg06().message_identity,
                &continuity.msg11().message_identity,
                &target_active_policy_identity,
                &target_activation_identity,
                &target_applicability_identity,
                continuity.msg11().effect_receipt_identity.as_bytes(),
            ],
        );
        pending.verify_live(self)?;
        Ok(StoreVerifiedOrdinarySuccessorFoundationAuthorityV1 {
            actor_instance_identity: self.actor_instance_identity.clone(),
            actor_snapshot_identity: self.current_snapshot_identity.clone(),
            actor_effect_epoch: self.effect_epoch,
            current_context_address: std::ptr::from_ref(current).cast::<()>(),
            pending_context_address: std::ptr::from_ref(pending).cast::<()>(),
            physical_generation_identity: current
                .coordinates
                .physical_generation_identity
                .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?,
            lifecycle_root_identity: current
                .coordinates
                .lifecycle_root_identity
                .ok_or(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)?,
            current_binding_identity: rotation_predecessor_identity,
            current_frontier_identity: current.coordinates.predecessor_frontier_identity,
            current_standing_identity: current.coordinates.standing_identity,
            successor_proposal_identity: possession.successor_proposal_identity(),
            successor_key_generation_identity: pending.coordinates.signer_key_generation_identity,
            transition_identity: possession.transition_identity(),
            possession,
            continuity,
            creator_pid: std::process::id(),
        })
    }

    /// Sole Store-actor caller for selected-successor MSG-12.  Foundation
    /// adoption and signer acceptance must already have produced the exact
    /// PendingSelected context passed here.
    pub(crate) fn append_pending_healthy_rotation_receipt_v1(
        &mut self,
        selected: &mut C2LiveSignerContextV1<'_, '_, PendingSelectedV1>,
        selected_transition_input_identity: [u8; 32],
        completed_append_identity: [u8; 32],
        complete_candidate_set_identity: [u8; 32],
        pending_successor_resolution_identity: [u8; 32],
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        let facts = StoreVerifiedPendingRotationReceiptFactsV1::from_store_actor_resolution(
            self,
            selected,
            selected_transition_input_identity,
            completed_append_identity,
            complete_candidate_set_identity,
            pending_successor_resolution_identity,
        )?;
        let mut coordinator = C2SignerTransitionCoordinator::from_store_actor(self, selected)?;
        coordinator.append_pending_healthy_rotation_receipt(facts)
    }

    /// Run one complete Store-resolved healthy-successor lifecycle under the
    /// retained Store actor.
    ///
    /// The caller contributes only inert transition/challenge intent.  Every
    /// authority-bearing premise, semantic message input, completion join,
    /// and terminal projection is derived by this actor from its exact live
    /// predecessor and durable Store state.  In particular, MSG-07 is
    /// followed by an in-place predecessor refresh before mandatory MSG-06;
    /// no stale predecessor context or caller-authored MSG-12 identity enters
    /// this path.
    fn complete_healthy_successor_v1(
        &mut self,
        current: &mut C2LiveSignerContextV1<'_, 'actor_store, GenerationCurrentV1>,
        intent: &C2HealthySuccessorIntentV1,
        policy_target: StoreResolvedHealthySuccessorPolicyTargetV1,
    ) -> Result<Sha256Digest, C2LiveTransitionDriverRefusalV1> {
        current.verify_live(self)?;
        policy_target.verify_for_current(current)?;

        // Reject a completed transition occurrence before creating the next
        // custody key or touching B/G.  Terminal succession is the durable
        // one-use boundary: a precursor row alone is deliberately not used
        // here because an interrupted nonterminal prefix must remain subject
        // to the separate restart/reconciliation law rather than being
        // mislabeled as a completed replay.
        let transition_already_terminal: bool = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM c2_signer_succession_projection
                    WHERE transition_identity = ?1
                 )",
                [intent.transition_identity.as_str()],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        if transition_already_terminal {
            return Err(LineageRefusalV1::DuplicateTransition.into());
        }

        // Retain the inert predecessor terminal before the first successor
        // write.  The later terminal append re-resolves it transactionally;
        // this value never supplies live predecessor authority.
        let prior = self
            .resolve_generation_current_evidence_v1()?
            .durable_terminal;
        let predecessor_binding_identity =
            digest_identity_bytes(prior.terminal_binding().binding_id())?;
        let transition_identity = digest_identity_bytes(&intent.transition_identity)?;
        let successor_challenge_identity =
            digest_identity_bytes(&intent.successor_pop_challenge_identity)?;

        let proposal_cut = current
            .coordinates
            .event_cut
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let (successor_custodian, _preparation_request) = self
            .prepare_ordinary_successor_custody_v1(
                current,
                intent.transition_identity.clone(),
                intent.successor_pop_challenge_identity.clone(),
            )?;
        let successor_custody = successor_custodian
            .seal_reopened_foundational_custody()
            .map_err(C2CustodyPreparationRefusalV1::from)?;
        let mut pending = self.mint_ordinary_successor_pending_possession_v1(
            current,
            &successor_custody,
            proposal_cut,
            successor_challenge_identity,
            transition_identity,
        )?;
        let possession = self
            .append_successor_possession_v1(
                &mut pending,
                successor_challenge_identity,
                predecessor_binding_identity,
                transition_identity,
            )
            .map_err(C2LiveTransitionDriverRefusalV1::SuccessorPossession)?;

        let foundation_authority = self
            .append_healthy_rotation_intent_v1(
                current,
                &mut pending,
                possession,
                intent.transition_cut,
                policy_target.target_active_policy_identity,
                policy_target.target_activation_identity,
                policy_target.target_applicability_identity,
            )
            .map_err(C2LiveTransitionDriverRefusalV1::HealthyContinuity)?;
        let conditional_msg05_identity = foundation_authority
            .continuity()
            .conditional_msg05()
            .map(|message| message.message_identity);
        match (
            policy_target.required_activation_successor_grant_identity,
            conditional_msg05_identity,
        ) {
            (None, None) | (Some(_), Some(_)) => {}
            (None, Some(_)) | (Some(_), None) => {
                return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
            }
        }

        let mandatory_msg06_identity = foundation_authority
            .continuity()
            .mandatory_msg06()
            .message_identity;
        let completed_append_identity = digest_text_identity(
            foundation_authority
                .continuity()
                .msg11()
                .append_identity
                .as_str(),
        )?;
        let consumed = self.consume_ordinary_successor_foundation_authority_v1(
            foundation_authority,
            current,
            &pending,
        )?;
        let adoption =
            self.adopt_consumed_foundational_enrollment_v1(current.authority_snapshot, consumed)?;
        let accepted = self.accept_consumed_signer_enrollment_v1(adoption)?;

        let foundation_identity = accepted.adoption().foundation().identity().clone();
        let adoption_identity = accepted.adoption().adoption_record().identity().clone();
        let signer_enrollment_identity = accepted.record().identity().clone();
        let signer_acceptance_receipt_identity = accepted.acceptance_receipt_identity().clone();
        let successor_key_generation = accepted.adoption().foundation().key_generation();
        let durable_enrollment = load_verified_durable_signer_enrollment_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            &signer_enrollment_identity,
        )?;
        let mut selected =
            self.mint_pending_selected_from_consumed_acceptance_v1(pending, accepted)?;

        // These identities are not caller choices. They commit the MSG-12
        // receipt to the exact predecessor, proposal, foundation, adoption,
        // acceptance, MSG-06 continuity and current Store snapshot.
        let proposal_identity = selected.foundational_custody.proposal_identity().clone();
        let policy_continuity_branch_tag: &[u8] = if conditional_msg05_identity.is_some() {
            b"msg05"
        } else {
            b"unchanged"
        };
        let required_activation_successor_grant_identity = policy_target
            .required_activation_successor_grant_identity
            .unwrap_or([0; 32]);
        let exact_conditional_msg05_identity = conditional_msg05_identity.unwrap_or([0; 32]);
        let policy_continuity_branch_identity = digest_fields_bytes(
            b"nq.c2.healthy_successor.policy_continuity_branch.identity.v1\0",
            &[
                policy_continuity_branch_tag,
                &policy_target.predecessor_active_policy_identity,
                &policy_target.target_active_policy_identity,
                &policy_target.predecessor_activation_identity,
                &policy_target.target_activation_identity,
                &policy_target.predecessor_applicability_identity,
                &policy_target.target_applicability_identity,
                &required_activation_successor_grant_identity,
                &exact_conditional_msg05_identity,
            ],
        );
        let complete_candidate_set_identity = digest_fields_bytes(
            b"nq.c2.healthy_successor.complete_candidate_set.identity.v1\0",
            &[
                prior.terminal_binding().binding_id().as_str().as_bytes(),
                intent.transition_identity.as_str().as_bytes(),
                proposal_identity.as_str().as_bytes(),
                foundation_identity.as_str().as_bytes(),
                adoption_identity.as_str().as_bytes(),
                signer_enrollment_identity.as_str().as_bytes(),
                &mandatory_msg06_identity,
                &policy_continuity_branch_identity,
            ],
        );
        let pending_successor_resolution_identity = digest_fields_bytes(
            b"nq.c2.healthy_successor.pending_resolution.identity.v1\0",
            &[
                self.current_snapshot_identity.as_str().as_bytes(),
                intent.transition_identity.as_str().as_bytes(),
                signer_enrollment_identity.as_str().as_bytes(),
                signer_acceptance_receipt_identity.as_str().as_bytes(),
                &complete_candidate_set_identity,
            ],
        );
        let pending_msg12 = self
            .append_pending_healthy_rotation_receipt_v1(
                &mut selected,
                transition_identity,
                completed_append_identity,
                complete_candidate_set_identity,
                pending_successor_resolution_identity,
            )
            .map_err(C2LiveTransitionDriverRefusalV1::PendingReceipt)?;

        let successor_standing_identity =
            identity_digest_from_bytes(selected.coordinates.standing_identity)?;
        let predecessor = construct_nrp_01_normal_predecessor(
            prior.terminal_binding().clone(),
            prior.terminal_binding().binding_id(),
            prior.terminal_binding().standing_id().to_owned(),
            prior.terminal_binding().key_generation().to_owned(),
            prior.terminal_binding().policy_id().to_owned(),
        )?;
        let ready = construct_nrp_06_persistence_ready_normal_current(
            prior.root(),
            predecessor,
            NormalSuccessionInputV1 {
                transition_id: intent.transition_identity.to_string(),
                continuity_authorization_id: identity_digest_from_bytes(mandatory_msg06_identity)?
                    .to_string(),
                policy_continuity_authorization_id: conditional_msg05_identity
                    .map(identity_digest_from_bytes)
                    .transpose()?
                    .map(|identity| identity.to_string()),
                continuity_signer_key_generation: prior
                    .terminal_binding()
                    .key_generation()
                    .to_owned(),
                predecessor_activation_id: identity_digest_from_bytes(
                    policy_target.predecessor_activation_identity,
                )?
                .to_string(),
                successor_activation_id: identity_digest_from_bytes(
                    policy_target.target_activation_identity,
                )?
                .to_string(),
                predecessor_applicability_id: identity_digest_from_bytes(
                    policy_target.predecessor_applicability_identity,
                )?
                .to_string(),
                successor_applicability_id: identity_digest_from_bytes(
                    policy_target.target_applicability_identity,
                )?
                .to_string(),
                successor_enrollment_id: signer_enrollment_identity.to_string(),
                successor_key_generation: successor_key_generation.to_string(),
                successor_policy_id: identity_digest_from_bytes(
                    policy_target.target_active_policy_identity,
                )?
                .to_string(),
                successor_standing_id: successor_standing_identity.to_string(),
                receipt_id: identity_digest_from_bytes(pending_msg12.message_identity)?.to_string(),
                append_id: parse_digest(&pending_msg12.append_identity)?.to_string(),
                resolution_id: parse_digest(&pending_msg12.effect_receipt_identity)?.to_string(),
                effective_cut: selected.coordinates.event_cut,
            },
        )?;
        let prepared = prepare_healthy_successor_terminal_append_v1(
            ready,
            &durable_enrollment,
            pending_msg12,
        )?;
        let completed = self.persist_healthy_successor_terminal_v1(&prior, prepared)?;
        Ok(completed.terminal_binding().binding_id().clone())
    }

    /// Recheck one sealed phase and perform signing plus durable append inside
    /// the same retained Store transaction and actor epoch.
    ///
    /// The callback receives the only permit custody will accept.  No permit
    /// escapes, and the predecessor view becomes stale as soon as the exact
    /// post-state snapshot/epoch is recorded.
    pub(crate) fn with_signer_append_effect<Phase>(
        &mut self,
        context: &mut C2LiveSignerContextV1<'_, '_, Phase>,
        prepare: impl FnOnce(
            &StoreC2SignerAppendPermitV1<'_, '_, '_, Phase>,
            &C2LiveSigningViewV1<'_, '_, '_, Phase>,
        ) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2>,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        self.verify_same_snapshot()?;
        context.verify_live(self)?;
        let before = self.current_snapshot_identity.clone();
        let prepared = {
            let live = context.signing_view();
            let permit = StoreC2SignerAppendPermitV1 {
                live: &live,
                actor_instance_identity: self.actor_instance_identity.clone(),
                snapshot_identity: before.clone(),
                effect_epoch: self.effect_epoch,
            };
            // The coordinator may prepare exactly one typed signed frame, but
            // it never receives the Store transaction or a generic mutation
            // handle. The permit/view cannot escape this lexical boundary.
            prepare(&permit, &live)?
        };
        self.append_prepared_signer_effect(context, before, prepared)
    }

    /// Sign and durably append MSG-02 without manufacturing live standing.
    ///
    /// The request itself was minted from exact Store/admission/grant/
    /// candidate/custody correspondence.  The callback receives only a
    /// lexical permit for that same request; it receives neither a generic
    /// signer context nor the Store transaction.
    pub(crate) fn with_initial_possession_append_effect<'request, 'store>(
        &mut self,
        request: &'request VerifiedInitialPossessionRequestV1<'request, 'store>,
        prepare: impl FnOnce(
            &StoreC2InitialPossessionAppendPermitV1<'request, 'store>,
        ) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2>,
    ) -> Result<ConsumedInitialProposalPoPV1<'request, 'store>, C2SignerAppendRefusalV1> {
        self.verify_same_snapshot()?;
        request.verify_for_actor(self)?;
        let prepared = {
            let permit = StoreC2InitialPossessionAppendPermitV1 {
                request,
                actor_instance_identity: self.actor_instance_identity.clone(),
                snapshot_identity: self.current_snapshot_identity.clone(),
                effect_epoch: self.effect_epoch,
            };
            prepare(&permit)?
        };
        // MSG-02 is the closed pre-B/G proposal-key lane. Its consumed Store
        // receipt is later bound into foundational adoption; it does not
        // claim a physical generation or live signer standing.
        let result = self.with_permitted_effect(
            StoreC2EffectKindV1::SignerAppend,
            |transaction| -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
                append_prepared_signed_frame(transaction, prepared)
                    .map_err(C2SignerAppendRefusalV1::Signer)
            },
        )?;
        ConsumedInitialProposalPoPV1::from_actor_append(self, request, result)
            .map_err(C2SignerAppendRefusalV1::from)
    }

    /// Append one already verified route-specific carrier.  This helper is
    /// private so neither a verification permit nor the terminal-A1 adapter
    /// can escape to a caller-selected callback.
    fn append_verified_governed_carrier_effect(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        prepared: C2PreparedExternalIngressV1,
    ) -> Result<DurableExternalIngressReceiptV1, C2GovernedCarrierIngressRefusalV1> {
        self.verify_authority_lineage(authority)?;
        self.with_permitted_effect(
            StoreC2EffectKindV1::GovernedCarrierIngress,
            |transaction| -> Result<DurableExternalIngressReceiptV1, C2GovernedCarrierIngressRefusalV1> {
                append_prepared_external_ingress(transaction, prepared)
                    .map_err(C2GovernedCarrierIngressRefusalV1::Durable)
            },
        )
    }

    /// Refresh an otherwise unchanged current signer after an exact external
    /// carrier ingress transaction.  The durable carrier is evidence only:
    /// this refinement preserves the existing standing and signer frontier,
    /// while binding the live context to the actor's new snapshot/epoch so a
    /// later route-specific resolver cannot use stale authority.
    fn refresh_current_after_external_ingress_v1(
        &self,
        current: &mut C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        receipt: &DurableExternalIngressReceiptV1,
    ) -> Result<(), C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        let prior_epoch = current
            .actor_effect_epoch
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if current.creator_pid != std::process::id()
            || current.actor_instance_identity != self.actor_instance_identity
            || prior_epoch != self.effect_epoch
            || receipt.ingress_sequence == 0
            || receipt.effect_identity.is_empty()
            || receipt.receipt_identity.is_empty()
            || receipt.receipt_bytes.is_empty()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        current.actor_snapshot_identity = self.current_snapshot_identity.clone();
        current.actor_effect_epoch = self.effect_epoch;
        current.coordinates.exact_content_identity = digest_fields_bytes(
            b"nq.c2.generation_current.after_external_ingress.exact_content.v1\0",
            &[
                &current.coordinates.exact_content_identity,
                receipt.effect_identity.as_bytes(),
                receipt.receipt_identity.as_bytes(),
                &receipt.ingress_sequence.to_be_bytes(),
            ],
        );
        current.verify_live(self)
    }

    /// Reconstruct the exact Store-owned current/predecessor coordinate map
    /// used by governed external routes.  This projection is inert and never
    /// constructs a phase; it exists only long enough to compare an A1-signed
    /// request/carrier pair with this actor's retained transaction,
    /// authenticated B/G descriptors, permanent lock and authority snapshot.
    fn resolved_governance_exact_fields_v1(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        evidence: &StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<BTreeMap<String, Value>, C2LiveSignerRefusalV1> {
        self.verify_authority_lineage(authority)?;
        let current_activation = authority.current_activation();
        if evidence.occurrence_id != authority.admission_basis().occurrence_id()
            || evidence.occurrence_id != current_activation.occurrence_id()
            || evidence.physical_generation_identity.as_str()
                != evidence.root.physical_store_generation()
            || evidence.current.enrollment_id().is_empty()
            || evidence.current.standing_id().is_empty()
            || evidence.current.policy_id().is_empty()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch);
        }
        let key_generation = evidence
            .current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
        let frontier = identity_digest_from_bytes(evidence.frontier_identity)?;
        let current_public_key = hex::encode(evidence.current_public_key);
        let mut fields: BTreeMap<String, Value> = [
            (
                "issued_against_candidate_set",
                Value::String(
                    authority
                        .resolved
                        .candidate_set_digest()
                        .as_str()
                        .to_owned(),
                ),
            ),
            (
                "occurrence_id",
                Value::String(evidence.occurrence_id.clone()),
            ),
            (
                "a2_chain_root",
                Value::String(
                    current_activation
                        .chain_root_activation_digest()
                        .as_str()
                        .to_owned(),
                ),
            ),
            (
                "controlling_activation",
                Value::String(
                    current_activation
                        .controlling_tip_activation_digest()
                        .as_str()
                        .to_owned(),
                ),
            ),
            (
                "resident_identity",
                Value::String(current_activation.resident_identity().to_owned()),
            ),
            (
                "resident_generation",
                Value::Number(current_activation.resident_generation().into()),
            ),
            (
                "host_role",
                Value::String(current_activation.host_role().to_owned()),
            ),
            (
                "role_manifest_generation",
                Value::Number(current_activation.role_manifest_generation().into()),
            ),
            (
                "trust_anchor_id",
                Value::String(current_activation.trust_anchor_id().as_str().to_owned()),
            ),
            (
                "authority_domain",
                Value::String(current_activation.domain().to_owned()),
            ),
            (
                "activation_policy_version",
                Value::Number(current_activation.policy_version().into()),
            ),
            (
                "physical_store_generation_identity",
                Value::String(evidence.physical_generation_identity.as_str().to_owned()),
            ),
            (
                "signer_lifecycle_root_identity",
                Value::String(evidence.root.lifecycle_root_id().to_owned()),
            ),
            (
                "scope_identity",
                Value::String(evidence.root.scope_id().to_owned()),
            ),
            (
                "active_store_policy_identity",
                Value::String(evidence.current.policy_id().to_owned()),
            ),
            (
                "active_store_policy_generation",
                Value::Number(evidence.active_policy_generation.into()),
            ),
            (
                "pre_effect_frontier_identity",
                Value::String(frontier.as_str().to_owned()),
            ),
            (
                "target_enrollment_identity",
                Value::String(evidence.current.enrollment_id().to_owned()),
            ),
            (
                "target_public_key",
                Value::String(current_public_key.clone()),
            ),
            (
                "target_key_generation",
                Value::Number(key_generation.into()),
            ),
            (
                "target_standing_identity",
                Value::String(evidence.current.standing_id().to_owned()),
            ),
            (
                "predecessor_enrollment_identity",
                Value::String(evidence.current.enrollment_id().to_owned()),
            ),
            (
                "predecessor_public_key",
                Value::String(current_public_key.clone()),
            ),
            (
                "predecessor_key_generation",
                Value::Number(key_generation.into()),
            ),
            (
                "predecessor_standing_identity",
                Value::String(evidence.current.standing_id().to_owned()),
            ),
            (
                "recovery_predecessor_binding_identity",
                Value::String(evidence.current.binding_id().as_str().to_owned()),
            ),
            (
                "last_completed_lifecycle_receipt_identity",
                Value::String(evidence.current.persisted_resolution_id().to_owned()),
            ),
            (
                "current_signer_enrollment_identity",
                Value::String(evidence.current.enrollment_id().to_owned()),
            ),
            (
                "current_signer_public_key",
                Value::String(current_public_key.clone()),
            ),
            (
                "current_signer_key_generation",
                Value::Number(key_generation.into()),
            ),
            (
                "current_signer_standing_identity",
                Value::String(evidence.current.standing_id().to_owned()),
            ),
            (
                "store_integrity_public_key",
                Value::String(current_public_key),
            ),
            (
                "store_integrity_key_generation",
                Value::Number(key_generation.into()),
            ),
            (
                "installation_receipt_identity",
                Value::String(evidence.installation_receipt_identity.as_str().to_owned()),
            ),
            (
                "generation_commitment_identity",
                Value::String(
                    evidence
                        .bootstrap_generation_relation
                        .generation_commitment_identity
                        .as_str()
                        .to_owned(),
                ),
            ),
            (
                "restore_lineage_identity",
                Value::String(evidence.lineage_identity.as_str().to_owned()),
            ),
            (
                "implementation_manifest_identity",
                Value::String(
                    evidence
                        .implementation_manifest_identity
                        .as_str()
                        .to_owned(),
                ),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        if let Some(pair) = &self.durable_append_pair {
            let snapshot = pair.current_snapshot();
            fields.insert(
                "b_root_identity".to_owned(),
                Value::String(snapshot.b_content_root.as_str().to_owned()),
            );
            fields.insert(
                "b_cursor".to_owned(),
                Value::Number(snapshot.b_next_payload_offset.into()),
            );
            fields.insert(
                "g_root_identity".to_owned(),
                Value::String(snapshot.g_content_root.as_str().to_owned()),
            );
            fields.insert(
                "g_cursor".to_owned(),
                Value::Number(snapshot.g_next_payload_offset.into()),
            );
            fields.insert(
                "backend_profile_identity".to_owned(),
                Value::String(
                    pair.qualified_backend_profile_identity()
                        .as_str()
                        .to_owned(),
                ),
            );
        }
        if let Some(lock) = &self.generation_lock {
            fields.insert(
                "lock_domain_identity".to_owned(),
                Value::String(lock.carrier().lock_identity.as_str().to_owned()),
            );
        }
        Ok(fields)
    }

    /// Prepare the sole initial MSG-01 request without retaining live custody
    /// across the asynchronous terminal-A1 boundary.
    ///
    /// The actor derives the complete pre-generation scope from the exact
    /// current A2 projection plus the inert policy selection, enumerates the
    /// durable proposal frontier, creates one purpose-locked custody carrier,
    /// mechanically constructs the canonical request, and appends both inert
    /// records atomically to SQLite.  The descriptor-owning custodian is
    /// dropped before return.  Later grant consumption must reload this row
    /// and freshly reopen custody; the returned request cannot sign anything.
    pub(crate) fn prepare_initial_bootstrap_grant_request_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, 'actor_store>,
        intent: &C2BootstrapPreparationIntentV1,
    ) -> Result<StorePreparedBootstrapGrantRequestV1, C2CustodyPreparationRefusalV1> {
        self.verify_authority_snapshot(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let current = authority.current_activation();
        let selection = &intent.operator_install_selection;
        let calculation = construct_install_policy_calculation_v1(
            C2StoreGenerationInstallPolicyCalculationInputV1 {
                authority: C2InstallAuthorityTupleV1 {
                    occurrence: StoreOccurrenceIdentityV1::new(current.occurrence_id())
                        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?,
                    a2_chain_root: A2ChainRootIdentityV1::new(
                        current.chain_root_activation_digest().clone(),
                    ),
                    controlling_activation: ControllingActivationIdentityV1::new(
                        current.controlling_tip_activation_digest().clone(),
                    ),
                    dependency_anchor: DependencyAnchorIdentityV1::new(
                        current.trust_anchor_id().clone(),
                    ),
                    resident: ResidentIdentityV1::new(current.resident_identity())
                        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?,
                    resident_generation: current.resident_generation(),
                    role: current.host_role().to_owned(),
                    role_manifest: RoleManifestIdentityV1::new(
                        intent.role_manifest_identity.clone(),
                    ),
                    role_manifest_generation: current.role_manifest_generation(),
                    domain: current.domain().to_owned(),
                    policy_version: current.policy_version(),
                    authority_cut: C2StructuralCutV1 {
                        ledger_position: current.resolution_cut(),
                        effect_position: 0,
                    },
                },
                operator_installation_nonce: selection.operator_installation_nonce.clone(),
                installation_cut: selection.installation_cut,
                mode: selection.mode,
                restore_predecessor: selection.restore_predecessor.clone(),
                geometry: selection.geometry.clone(),
                backend_identity: LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1.to_owned(),
                qualified_backend_profile: selection.qualified_backend_profile.clone(),
                maximum_policy_generations: selection.maximum_policy_generations,
                maximum_key_generations: selection.maximum_key_generations,
                predecessor_install_policy: selection.predecessor_install_policy.clone(),
            },
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        if calculation.installation_cut().ledger_position <= current.resolution_cut() {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
        }
        let pre_generation = PreGenerationSignerCoordinatesV1 {
            occurrence: current.occurrence_id().to_owned(),
            signer_scope_policy: intent.signer_scope_policy_identity.clone(),
            signer_scope_policy_version: 1,
            a2_chain_root: current.chain_root_activation_digest().clone(),
            controlling_activation: current.controlling_tip_activation_digest().clone(),
            dependency_anchor: current.trust_anchor_id().clone(),
            resident: current.resident_identity().to_owned(),
            resident_generation: current.resident_generation(),
            role: current.host_role().to_owned(),
            role_manifest: intent.role_manifest_identity.clone(),
            role_manifest_generation: current.role_manifest_generation(),
            authority_domain: current.domain().to_owned(),
            activation_policy_version: current.policy_version(),
            active_store_policy: calculation.identity().clone(),
            active_store_policy_generation: 1,
        };
        let scope_identity_bytes = pre_generation_scope_identity_v1(&pre_generation)?;
        let scope_identity = identity_digest_from_bytes(scope_identity_bytes)?;
        let coordinates = PreGenerationCustodyCoordinatesV1 {
            occurrence_id: current.occurrence_id().to_owned(),
            scope_identity,
            a2_chain_root_identity: current.chain_root_activation_digest().clone(),
            trust_anchor_identity: current.trust_anchor_id().clone(),
            resident_identity: current.resident_identity().to_owned(),
            resident_generation: current.resident_generation(),
            host_role: current.host_role().to_owned(),
            role_manifest_generation: current.role_manifest_generation(),
            authority_domain: current.domain().to_owned(),
            signer_scope_policy_identity: intent.signer_scope_policy_identity.clone(),
            signer_scope_policy_version: 1,
            proposed_key_generation: 0,
            custodian_implementation_manifest_identity: admitted_manifest
                .manifest_identity()
                .clone(),
        };
        let scope_token = coordinates.scope_token()?;
        let (next_ordinal, predecessor_frontier, committed_proposals) =
            resolve_custody_proposal_frontier_v1(
                self.transaction
                    .as_ref()
                    .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
                &scope_token,
            )?;
        if next_ordinal != 1 {
            // This is the initial-bootstrap operation, not the rotation lane.
            // A prior row must be resumed by its exact durable identity rather
            // than silently creating a new key/attempt.
            return Err(SignerRefusalV2::CustodyPathMismatch.into());
        }
        let frontier = VerifiedCustodyProposalFrontierV1::from_store_actor_resolution(
            self,
            scope_token.clone(),
            next_ordinal,
            predecessor_frontier.clone(),
            committed_proposals,
        )?;
        let (custodian, proposal) = C2StoreIntegrityCustodian::create(coordinates, &frontier)?;
        let proposal_bytes = custodian.canonical_proposal_bytes()?;
        let proposal_identity = proposal.proposal_identity().clone();
        let public_key = custodian.verifying_key()?;
        let terminal = authority.resolved.terminal_operator_authority();
        if terminal.permitted_scope() != "runtime_dependency_admission" {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
        }
        let installation_mode = match calculation.mode() {
            C2InstallationModeV1::Fresh => "fresh",
            C2InstallationModeV1::RestoreSuccessor => "restore_successor",
        };
        let permitted_bootstrap_families = bootstrap_grant_permitted_family_projection_v1();
        let mut request_value = serde_json::json!({
            "schema": "nq.c2_store_integrity_bootstrap_grant_request.v1",
            "schema_version": 1,
            "interpretation_policy": "nq.c2.a1_runtime_dependency_admission_refinement.v1",
            "issuer_a1_digest": terminal.record_digest().as_str(),
            "issuer_a1_key_generation": terminal.key_generation(),
            "issuer_a1_verification_key": hex::encode(terminal.verification_key()),
            "issuer_operator_principal": terminal.operator_principal(),
            "issuer_domain": terminal.domain(),
            "issuer_permitted_scope": terminal.permitted_scope(),
            "issuer_policy_version": terminal.policy_version(),
            "issuer_policy_floor": terminal.policy_floor(),
            "issued_against_gen4_cut": terminal.cut().sequence(),
            "issued_against_gen4_terminal_event": authority.resolved.terminal_authority_event_digest().as_str(),
            "issued_against_candidate_set": authority.resolved.candidate_set_digest().as_str(),
            "occurrence_id": current.occurrence_id(),
            "a2_chain_root": current.chain_root_activation_digest().as_str(),
            "controlling_activation": current.controlling_tip_activation_digest().as_str(),
            "resident_identity": current.resident_identity(),
            "resident_generation": current.resident_generation(),
            "host_role": current.host_role(),
            "role_manifest_generation": current.role_manifest_generation(),
            "trust_anchor_id": current.trust_anchor_id().as_str(),
            "authority_domain": current.domain(),
            "activation_policy_version": current.policy_version(),
            "proposal_identity": proposal_identity.as_str(),
            "custody_instance_identity": proposal_identity.as_str(),
            "store_integrity_key_algorithm": "ed25519_store_integrity_v1",
            "store_integrity_public_key": hex::encode(public_key),
            "store_integrity_key_generation": 0,
            "signer_scope_policy_identity": intent.signer_scope_policy_identity.as_str(),
            "signer_scope_policy_version": 1,
            "permitted_bootstrap_families": permitted_bootstrap_families,
            "installation_mode": installation_mode,
            "installed_policy_calculation_identity": calculation.identity().as_str(),
            "c2_lifecycle_cut": calculation.installation_cut().ledger_position,
            "predecessor_c2_lifecycle_event": null,
            "expiry": null
        });
        let request_body = canonical_json_bytes(&request_value)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let request_identity = sha256_bytes(
            &[
                b"nq.c2.store_integrity_bootstrap_grant_request.identity.v1\0".as_slice(),
                request_body.as_slice(),
            ]
            .concat(),
        );
        request_value
            .as_object_mut()
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?
            .insert(
                "grant_request_identity".to_owned(),
                Value::String(request_identity.as_str().to_owned()),
            );
        let request = construct_bootstrap_grant_request(request_value)?;
        let request_bytes = request.canonical_bytes().to_vec();
        let resulting_frontier = digest_fields(
            C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1,
            &[
                predecessor_frontier.as_str().as_bytes(),
                &next_ordinal.to_be_bytes(),
                proposal_identity.as_str().as_bytes(),
                request_identity.as_str().as_bytes(),
                sha256_bytes(&proposal_bytes).as_str().as_bytes(),
                sha256_bytes(&request_bytes).as_str().as_bytes(),
            ],
        );
        let preparation_identity = digest_fields(
            C2_CUSTODY_PREPARATION_DOMAIN_V1,
            &[
                b"initialExternal",
                scope_token.as_str().as_bytes(),
                resulting_frontier.as_str().as_bytes(),
                admitted_manifest.manifest_identity().as_str().as_bytes(),
                admitted_manifest
                    .qualified_candidate_identity()
                    .as_str()
                    .as_bytes(),
                admitted_manifest.source_tree_identity().as_str().as_bytes(),
                admitted_manifest
                    .runtime_artifact_identity()
                    .as_str()
                    .as_bytes(),
            ],
        );
        self.with_permitted_effect(
            StoreC2EffectKindV1::CustodyProposalPreparation,
            |transaction| {
                transaction.execute(
                    "INSERT INTO c2_custody_proposal_preparations (
                        preparation_identity, occurrence_id, scope_token,
                        proposal_ordinal, predecessor_frontier_identity,
                        resulting_frontier_identity, proposal_identity,
                        proposal_canonical_bytes, proposal_canonical_sha256,
                        proposal_canonical_length, bootstrap_request_identity,
                        bootstrap_request_canonical_bytes,
                        bootstrap_request_canonical_sha256,
                        bootstrap_request_canonical_length,
                        install_policy_calculation_identity,
                        install_policy_calculation_canonical_bytes,
                        install_policy_calculation_canonical_sha256,
                        install_policy_calculation_canonical_length,
                        implementation_manifest_identity,
                        qualified_candidate_identity, source_tree_identity,
                        runtime_artifact_identity, prepared_at,
                        preparation_lineage
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                               ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                               ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
                    params![
                        preparation_identity.as_str(),
                        current.occurrence_id(),
                        scope_token.as_str(),
                        next_ordinal,
                        predecessor_frontier.as_str(),
                        resulting_frontier.as_str(),
                        proposal_identity.as_str(),
                        &proposal_bytes,
                        sha256_bytes(&proposal_bytes).as_str(),
                        proposal_bytes.len() as u64,
                        request_identity.as_str(),
                        &request_bytes,
                        sha256_bytes(&request_bytes).as_str(),
                        request_bytes.len() as u64,
                        calculation.identity().as_str(),
                        calculation.canonical_bytes(),
                        sha256_bytes(calculation.canonical_bytes()).as_str(),
                        calculation.canonical_bytes().len() as u64,
                        admitted_manifest.manifest_identity().as_str(),
                        admitted_manifest.qualified_candidate_identity().as_str(),
                        admitted_manifest.source_tree_identity().as_str(),
                        admitted_manifest.runtime_artifact_identity().as_str(),
                        Utc::now().to_rfc3339(),
                        "initialExternal",
                    ],
                )?;
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-26");
                Ok::<(), C2CustodyPreparationRefusalV1>(())
            },
        )?;
        drop(custodian);
        Ok(StorePreparedBootstrapGrantRequestV1 {
            preparation_identity,
            request,
        })
    }

    /// Reload the exact asynchronous preparation and mint fresh custody for
    /// the current actor.  The grant is used only to select its repeated
    /// request identity here; terminal-A1 signature verification still occurs
    /// in `adopt_bootstrap_grant_v1` immediately afterward.
    pub(in crate::store_generation) fn reopen_prepared_bootstrap_custodian_v1(
        &self,
        authority: &StoreC2AuthoritySnapshotV1<'actor_store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'_, 'actor_store>,
        grant: &StoreIntegrityBootstrapGrantV1,
    ) -> Result<
        (
            C2StoreIntegrityCustodian,
            StoreIntegrityBootstrapGrantRequestV1,
            C2StoreGenerationInstallPolicyCalculationV1,
            Sha256Digest,
        ),
        C2CustodyPreparationRefusalV1,
    > {
        self.verify_authority_snapshot(authority)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let requested_identity = grant
            .field("grant_request_identity")
            .and_then(Value::as_str)
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let transaction = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?;
        let row = transaction.query_row(
            "SELECT preparation_identity, occurrence_id, scope_token,
                    proposal_ordinal, predecessor_frontier_identity,
                    resulting_frontier_identity, proposal_identity,
                    proposal_canonical_bytes, proposal_canonical_sha256,
                    proposal_canonical_length, bootstrap_request_identity,
                    bootstrap_request_canonical_bytes,
                    bootstrap_request_canonical_sha256,
                    bootstrap_request_canonical_length,
                    install_policy_calculation_identity,
                    install_policy_calculation_canonical_bytes,
                    install_policy_calculation_canonical_sha256,
                    install_policy_calculation_canonical_length,
                    implementation_manifest_identity,
                    qualified_candidate_identity, source_tree_identity,
                    runtime_artifact_identity, preparation_lineage
             FROM c2_custody_proposal_preparations
             WHERE bootstrap_request_identity = ?1
               AND preparation_lineage = 'initialExternal'",
            params![requested_identity],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, u64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, u64>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, Vec<u8>>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, u64>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, String>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, String>(21)?,
                    row.get::<_, String>(22)?,
                ))
            },
        )?;
        let (
            preparation_identity,
            occurrence_id,
            scope_token,
            proposal_ordinal,
            predecessor_frontier,
            resulting_frontier,
            proposal_identity,
            proposal_bytes,
            proposal_sha,
            proposal_length,
            request_identity,
            request_bytes,
            request_sha,
            request_length,
            policy_calculation_identity,
            policy_calculation_bytes,
            policy_calculation_sha,
            policy_calculation_length,
            manifest_identity,
            candidate_identity,
            source_tree_identity,
            runtime_artifact_identity,
            preparation_lineage,
        ) = row;
        let proposal_value: Value = serde_json::from_slice(&proposal_bytes)
            .map_err(|_| SignerRefusalV2::CustodyFileMalformed)?;
        let request_value: Value = serde_json::from_slice(&request_bytes)
            .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let request = construct_bootstrap_grant_request(request_value.clone())?;
        let calculation = decode_install_policy_calculation_v1(&policy_calculation_bytes)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        let field_text = |value: &Value, name: &str| -> Result<String, SignerRefusalV2> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
        };
        let field_u64 = |value: &Value, name: &str| -> Result<u64, SignerRefusalV2> {
            value
                .get(name)
                .and_then(Value::as_u64)
                .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)
        };
        let current = authority.current_activation();
        let policy_authority = calculation.authority();
        let expected_mode = match calculation.mode() {
            C2InstallationModeV1::Fresh => "fresh",
            C2InstallationModeV1::RestoreSuccessor => "restore_successor",
        };
        let pre_generation = PreGenerationSignerCoordinatesV1 {
            occurrence: policy_authority.occurrence.as_str().to_owned(),
            signer_scope_policy: parse_digest(&field_text(
                &request_value,
                "signer_scope_policy_identity",
            )?)?,
            signer_scope_policy_version: field_u64(&request_value, "signer_scope_policy_version")?,
            a2_chain_root: policy_authority.a2_chain_root.digest().clone(),
            controlling_activation: policy_authority.controlling_activation.digest().clone(),
            dependency_anchor: policy_authority.dependency_anchor.digest().clone(),
            resident: policy_authority.resident.as_str().to_owned(),
            resident_generation: policy_authority.resident_generation,
            role: policy_authority.role.clone(),
            role_manifest: policy_authority.role_manifest.digest().clone(),
            role_manifest_generation: policy_authority.role_manifest_generation,
            authority_domain: policy_authority.domain.clone(),
            activation_policy_version: policy_authority.policy_version,
            active_store_policy: calculation.identity().clone(),
            active_store_policy_generation: 1,
        };
        let expected_scope =
            identity_digest_from_bytes(pre_generation_scope_identity_v1(&pre_generation)?)?;
        let coordinates = PreGenerationCustodyCoordinatesV1 {
            occurrence_id: occurrence_id.clone(),
            scope_identity: expected_scope,
            a2_chain_root_identity: policy_authority.a2_chain_root.digest().clone(),
            trust_anchor_identity: policy_authority.dependency_anchor.digest().clone(),
            resident_identity: policy_authority.resident.as_str().to_owned(),
            resident_generation: policy_authority.resident_generation,
            host_role: policy_authority.role.clone(),
            role_manifest_generation: policy_authority.role_manifest_generation,
            authority_domain: policy_authority.domain.clone(),
            signer_scope_policy_identity: pre_generation.signer_scope_policy.clone(),
            signer_scope_policy_version: pre_generation.signer_scope_policy_version,
            proposed_key_generation: 0,
            custodian_implementation_manifest_identity: admitted_manifest
                .manifest_identity()
                .clone(),
        };
        let parsed_scope_token = parse_digest(&scope_token)?;
        let expected_resulting = digest_fields(
            C2_CUSTODY_FRONTIER_STEP_DOMAIN_V1,
            &[
                predecessor_frontier.as_bytes(),
                &proposal_ordinal.to_be_bytes(),
                proposal_identity.as_bytes(),
                request_identity.as_bytes(),
                proposal_sha.as_bytes(),
                request_sha.as_bytes(),
            ],
        );
        let expected_preparation = digest_fields(
            C2_CUSTODY_PREPARATION_DOMAIN_V1,
            &[
                b"initialExternal",
                scope_token.as_bytes(),
                resulting_frontier.as_bytes(),
                manifest_identity.as_bytes(),
                candidate_identity.as_bytes(),
                source_tree_identity.as_bytes(),
                runtime_artifact_identity.as_bytes(),
            ],
        );
        if request_identity != requested_identity
            || preparation_lineage != "initialExternal"
            || preparation_identity != expected_preparation.as_str()
            || proposal_ordinal != 1
            || predecessor_frontier
                != digest_fields(
                    C2_CUSTODY_EMPTY_FRONTIER_DOMAIN_V1,
                    &[scope_token.as_bytes()],
                )
                .as_str()
            || resulting_frontier != expected_resulting.as_str()
            || proposal_sha != sha256_bytes(&proposal_bytes).as_str()
            || request_sha != sha256_bytes(&request_bytes).as_str()
            || proposal_length != proposal_bytes.len() as u64
            || request_length != request_bytes.len() as u64
            || policy_calculation_identity != calculation.identity().as_str()
            || policy_calculation_sha != sha256_bytes(&policy_calculation_bytes).as_str()
            || policy_calculation_length != policy_calculation_bytes.len() as u64
            || canonical_json_bytes(&proposal_value)
                .map_err(|_| SignerRefusalV2::CustodyFileMalformed)?
                != proposal_bytes
            || request.canonical_bytes() != request_bytes
            || proposal_value
                .get("proposal_identity")
                .and_then(Value::as_str)
                != Some(proposal_identity.as_str())
            || request_value
                .get("proposal_identity")
                .and_then(Value::as_str)
                != Some(proposal_identity.as_str())
            || coordinates.scope_token()? != parsed_scope_token
            || occurrence_id != current.occurrence_id()
            || field_text(&request_value, "a2_chain_root")?
                != current.chain_root_activation_digest().as_str()
            || field_text(&request_value, "controlling_activation")?
                != current.controlling_tip_activation_digest().as_str()
            || field_text(&request_value, "trust_anchor_id")? != current.trust_anchor_id().as_str()
            || field_text(&request_value, "installation_mode")? != expected_mode
            || field_text(&request_value, "installed_policy_calculation_identity")?
                != calculation.identity().as_str()
            || field_u64(&request_value, "c2_lifecycle_cut")?
                != calculation.installation_cut().ledger_position
            || manifest_identity != admitted_manifest.manifest_identity().as_str()
            || candidate_identity != admitted_manifest.qualified_candidate_identity().as_str()
            || source_tree_identity != admitted_manifest.source_tree_identity().as_str()
            || runtime_artifact_identity != admitted_manifest.runtime_artifact_identity().as_str()
        {
            return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into());
        }
        let sealed =
            StoreVerifiedPreparedCustodyV1::from_store_actor(self, coordinates, &proposal_bytes)?;
        let custodian = C2StoreIntegrityCustodian::reopen_prepared_for_actor(self, sealed)?;
        Ok((
            custodian,
            request,
            calculation,
            parse_digest(&preparation_identity)?,
        ))
    }

    /// Sole production MSG-01 bootstrap-grant verification/adoption route.
    ///
    /// The expectation is derived here from the exact same-snapshot Store
    /// authority, authenticated installation policy, and retained custody.
    /// Callers provide only canonical carrier/request values.  A verified
    /// grant is sealed and returned only after durable append succeeds, so a
    /// failed append cannot leak verifier output into enrollment or standing.
    pub(crate) fn adopt_bootstrap_grant_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        calculation: &C2StoreGenerationInstallPolicyCalculationV1,
        custody: &VerifiedFoundationalCustodyV1<'_>,
        request: &StoreIntegrityBootstrapGrantRequestV1,
        grant: &StoreIntegrityBootstrapGrantV1,
    ) -> Result<StoreAdoptedBootstrapGrantV1, C2GovernedCarrierIngressRefusalV1> {
        self.verify_authority_lineage(authority)?;
        custody.verify_same_process()?;
        let current = authority.current_activation();
        let installed = calculation.authority();
        if installed.occurrence.as_str() != current.occurrence_id()
            || installed.a2_chain_root.digest() != current.chain_root_activation_digest()
            || installed.controlling_activation.digest()
                != current.controlling_tip_activation_digest()
            || installed.dependency_anchor.digest() != current.trust_anchor_id()
            || installed.resident.as_str() != current.resident_identity()
            || installed.resident_generation != current.resident_generation()
            || installed.role != current.host_role()
            || installed.role_manifest_generation != current.role_manifest_generation()
            || installed.domain != current.domain()
            || installed.policy_version != current.policy_version()
            || installed.authority_cut.ledger_position != current.resolution_cut()
            || custody.key_generation() != 0
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch.into());
        }
        let installation_mode = match calculation.mode() {
            C2InstallationModeV1::Fresh => "fresh",
            C2InstallationModeV1::RestoreSuccessor => "restore_successor",
        };
        let exact_fields: BTreeMap<String, Value> = [
            (
                "occurrence_id",
                Value::String(installed.occurrence.as_str().to_owned()),
            ),
            (
                "a2_chain_root",
                Value::String(installed.a2_chain_root.digest().as_str().to_owned()),
            ),
            (
                "controlling_activation",
                Value::String(
                    installed
                        .controlling_activation
                        .digest()
                        .as_str()
                        .to_owned(),
                ),
            ),
            (
                "resident_identity",
                Value::String(installed.resident.as_str().to_owned()),
            ),
            (
                "resident_generation",
                Value::Number(installed.resident_generation.into()),
            ),
            ("host_role", Value::String(installed.role.clone())),
            (
                "role_manifest_generation",
                Value::Number(installed.role_manifest_generation.into()),
            ),
            (
                "trust_anchor_id",
                Value::String(installed.dependency_anchor.digest().as_str().to_owned()),
            ),
            ("authority_domain", Value::String(installed.domain.clone())),
            (
                "activation_policy_version",
                Value::Number(installed.policy_version.into()),
            ),
            (
                "proposal_identity",
                Value::String(custody.proposal_identity().as_str().to_owned()),
            ),
            (
                "custody_instance_identity",
                Value::String(custody.custody_evidence_identity().as_str().to_owned()),
            ),
            (
                "signer_scope_policy_identity",
                Value::String(
                    identity_digest_from_bytes(custody.signer_scope_policy_identity())?
                        .into_string(),
                ),
            ),
            (
                "signer_scope_policy_version",
                Value::Number(custody.signer_scope_policy_version().into()),
            ),
            (
                "store_integrity_public_key",
                Value::String(hex::encode(custody.public_key())),
            ),
            (
                "store_integrity_key_generation",
                Value::Number(0_u64.into()),
            ),
            (
                "installation_mode",
                Value::String(installation_mode.to_owned()),
            ),
            (
                "installed_policy_calculation_identity",
                Value::String(calculation.identity().as_str().to_owned()),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        let cut = calculation.installation_cut().ledger_position;
        let expectation = ExternalGovernanceExpectationV1::new(self, exact_fields, cut, cut)?;
        let permit = ExternalCarrierVerificationPermitV1::from_store_actor(self)?;
        let terminal = StoreTerminalA1VerifierV1 {
            resolved: authority.resolved,
        };
        let verified =
            verify_bootstrap_grant_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                grant,
                request,
                &expectation,
                &terminal,
            )?;
        let prepared = prepare_bootstrap_grant_ingress(&verified);
        let receipt = self.append_verified_governed_carrier_effect(authority, prepared)?;
        StoreAdoptedBootstrapGrantV1::from_actor_append(self, verified, receipt)
            .map_err(C2GovernedCarrierIngressRefusalV1::from)
    }

    fn construct_initial_enrollment_candidate_v1(
        &self,
        calculation: &C2StoreGenerationInstallPolicyCalculationV1,
        preparation_identity: &Sha256Digest,
        grant_adoption: &StoreAdoptedBootstrapGrantV1,
        custody: &VerifiedFoundationalCustodyV1<'_>,
    ) -> Result<StoreIntegrityEnrollmentCandidateV1, C2LiveInstallationDriverRefusalV1> {
        self.verify_same_snapshot()?;
        grant_adoption
            .verify_for_actor(self)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        custody
            .verify_same_process()
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let grant = grant_adoption.verified();
        let installed = calculation.authority();
        let coordinates = PreGenerationSignerCoordinatesV1 {
            occurrence: installed.occurrence.as_str().to_owned(),
            signer_scope_policy: identity_digest_from_bytes(
                custody.signer_scope_policy_identity(),
            )?,
            signer_scope_policy_version: custody.signer_scope_policy_version(),
            a2_chain_root: installed.a2_chain_root.digest().clone(),
            controlling_activation: installed.controlling_activation.digest().clone(),
            dependency_anchor: installed.dependency_anchor.digest().clone(),
            resident: installed.resident.as_str().to_owned(),
            resident_generation: installed.resident_generation,
            role: installed.role.clone(),
            role_manifest: installed.role_manifest.digest().clone(),
            role_manifest_generation: installed.role_manifest_generation,
            authority_domain: installed.domain.clone(),
            activation_policy_version: installed.policy_version,
            active_store_policy: calculation.identity().clone(),
            active_store_policy_generation: 1,
        };
        let candidate_cut = grant
            .lifecycle_cut()
            .checked_add(1)
            .ok_or(C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        construct_sg_rec_05a_candidate(
            candidate_cut,
            digest_identity_bytes(preparation_identity)?,
            digest_identity_bytes(custody.proposal_identity())?,
            *grant.grant_identity().bytes(),
            *grant.request_identity().bytes(),
            coordinates,
            custody.public_key(),
            custody.key_generation(),
            digest_identity_bytes(calculation.identity())?,
            1,
        )
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)
    }

    /// Derive the final inert install policy only after MSG-01 authenticated
    /// the complete acyclic calculation and the Store accepted the exact
    /// foundational enrollment produced from MSG-02. No independent policy
    /// signature or caller-authored final-policy identity participates.
    fn derive_final_install_policy_v1(
        &self,
        calculation: C2StoreGenerationInstallPolicyCalculationV1,
        grant_adoption: &StoreAdoptedBootstrapGrantV1,
        accepted: &StoreAcceptedSignerEnrollmentV1,
    ) -> Result<C2StoreGenerationInstallPolicyV1, C2LiveInstallationDriverRefusalV1> {
        self.verify_same_snapshot()?;
        grant_adoption
            .verify_for_actor(self)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        accepted
            .verify_for_actor(self)
            .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
        let foundational = accepted.adoption().foundational();
        if grant_adoption
            .verified()
            .installed_policy_calculation_identity()
            != digest_identity_bytes(calculation.identity())?
            || foundational.active_store_policy().digest() != calculation.identity()
            || foundational.maximum_retained_key_generations()
                != calculation.maximum_key_generations()
        {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
        construct_install_policy(C2StoreGenerationInstallPolicyInputV1 {
            calculation,
            enrollment: foundational.identity().clone(),
        })
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)
    }

    /// Store-owned MSG-01 activation-successor route.  The returned wrapper
    /// is inert outside the later policy-transition consumer and cannot mint
    /// enrollment, standing, or signer currentness.
    pub(crate) fn adopt_activation_successor_grant_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        request: &StoreIntegrityActivationSuccessorGrantRequestV1,
        grant: &StoreIntegrityActivationSuccessorGrantV1,
    ) -> Result<StoreAdoptedActivationSuccessorGrantV1, C2GovernedCarrierIngressRefusalV1> {
        let evidence = load_generation_current_evidence_before_governance_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )?;
        let cut = evidence
            .current
            .effective_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let mut exact_fields = self.resolved_governance_exact_fields_v1(authority, &evidence)?;
        exact_fields.insert(
            "predecessor_activation_identity".to_owned(),
            Value::String(
                authority
                    .current_activation()
                    .controlling_tip_activation_digest()
                    .as_str()
                    .to_owned(),
            ),
        );
        exact_fields.insert(
            "predecessor_active_policy_identity".to_owned(),
            Value::String(evidence.current.policy_id().to_owned()),
        );
        exact_fields.insert("proposed_effect_cut".to_owned(), Value::Number(cut.into()));
        exact_fields.retain(|name, _| request.field(name).is_some() || grant.field(name).is_some());
        let expectation = ExternalGovernanceExpectationV1::new(self, exact_fields, cut, cut)?;
        let permit = ExternalCarrierVerificationPermitV1::from_store_actor(self)?;
        let terminal = StoreTerminalA1VerifierV1 {
            resolved: authority.resolved,
        };
        let verified =
            verify_activation_successor_grant_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                grant,
                request,
                &expectation,
                &terminal,
            )?;
        drop(permit);
        let receipt = self.append_verified_governed_carrier_effect(
            authority,
            prepare_activation_successor_grant_ingress(&verified),
        )?;
        StoreAdoptedActivationSuccessorGrantV1::from_actor_append(self, verified, receipt)
            .map_err(C2GovernedCarrierIngressRefusalV1::from)
    }

    /// Store-owned MSG-01 deterministic proposal-disposition route.
    pub(crate) fn adopt_proposal_disposition_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        request: &StoreIntegrityProposalDispositionRequestV1,
        disposition: &StoreIntegrityProposalDispositionV1,
    ) -> Result<StoreAdoptedProposalDispositionV1, C2GovernedCarrierIngressRefusalV1> {
        let evidence = load_generation_current_evidence_before_governance_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )?;
        let cut = evidence
            .current
            .effective_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let mut exact_fields = self.resolved_governance_exact_fields_v1(authority, &evidence)?;
        exact_fields.insert(
            "governance_predecessor_identity".to_owned(),
            Value::String(evidence.current.binding_id().as_str().to_owned()),
        );
        exact_fields.insert("proposed_effect_cut".to_owned(), Value::Number(cut.into()));
        exact_fields
            .retain(|name, _| request.field(name).is_some() || disposition.field(name).is_some());
        let expectation = ExternalGovernanceExpectationV1::new(self, exact_fields, cut, cut)?;
        let permit = ExternalCarrierVerificationPermitV1::from_store_actor(self)?;
        let terminal = StoreTerminalA1VerifierV1 {
            resolved: authority.resolved,
        };
        let verified =
            verify_proposal_disposition_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                disposition,
                request,
                &expectation,
                &terminal,
            )?;
        drop(permit);
        let receipt = self.append_verified_governed_carrier_effect(
            authority,
            prepare_proposal_disposition_ingress(&verified),
        )?;
        StoreAdoptedProposalDispositionV1::from_actor_append(self, verified, receipt)
            .map_err(C2GovernedCarrierIngressRefusalV1::from)
    }

    /// Store-owned MSG-13 restore authorization route.  Adoption remains a
    /// process-local input to the restore-successor driver; it does not open
    /// quarantine or construct generation-current standing.
    pub(crate) fn adopt_restore_authorization_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        request: &StoreIntegrityRestoreAuthorizationRequestV1,
        authorization: &StoreIntegrityRestoreAuthorizationV1,
    ) -> Result<StoreAdoptedRestoreAuthorizationV1, C2GovernedCarrierIngressRefusalV1> {
        let evidence = load_generation_current_evidence_before_governance_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )?;
        let cut = evidence
            .current
            .effective_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let mut exact_fields = self.resolved_governance_exact_fields_v1(authority, &evidence)?;
        exact_fields.insert("proposed_effect_cut".to_owned(), Value::Number(cut.into()));
        exact_fields
            .retain(|name, _| request.field(name).is_some() || authorization.field(name).is_some());
        let expectation = ExternalGovernanceExpectationV1::new(self, exact_fields, cut, cut)?;
        let permit = ExternalCarrierVerificationPermitV1::from_store_actor(self)?;
        let terminal = StoreTerminalA1VerifierV1 {
            resolved: authority.resolved,
        };
        let verified =
            verify_restore_authorization_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                authorization,
                request,
                &expectation,
                &terminal,
            )?;
        drop(permit);
        let receipt = self.append_verified_governed_carrier_effect(
            authority,
            prepare_restore_authorization_ingress(&verified),
        )?;
        StoreAdoptedRestoreAuthorizationV1::from_actor_append(self, verified, receipt)
            .map_err(C2GovernedCarrierIngressRefusalV1::from)
    }

    /// Store-owned MSG-15 recovery-grant route.  The exact predecessor is
    /// resolved without treating its revoked status as live standing.
    pub(crate) fn adopt_recovery_grant_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        request: &StoreIntegrityRecoveryRequestV1,
        grant: &StoreIntegrityRecoveryGrantV1,
    ) -> Result<StoreAdoptedRecoveryGrantV1, C2GovernedCarrierIngressRefusalV1> {
        let evidence = load_generation_current_evidence_before_governance_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )?;
        let cut = evidence
            .current
            .effective_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let mut exact_fields = self.resolved_governance_exact_fields_v1(authority, &evidence)?;
        exact_fields.insert("proposed_effect_cut".to_owned(), Value::Number(cut.into()));
        exact_fields.retain(|name, _| request.field(name).is_some() || grant.field(name).is_some());
        let expectation = ExternalGovernanceExpectationV1::new(self, exact_fields, cut, cut)?;
        let permit = ExternalCarrierVerificationPermitV1::from_store_actor(self)?;
        let terminal = StoreTerminalA1VerifierV1 {
            resolved: authority.resolved,
        };
        let verified =
            verify_recovery_grant_terminal_a1_signature_scope_policy_cut_predecessor_successor_request_identity(
                &permit,
                grant,
                request,
                &expectation,
                &terminal,
            )?;
        drop(permit);
        let receipt = self.append_verified_governed_carrier_effect(
            authority,
            prepare_recovery_grant_ingress(&verified),
        )?;
        StoreAdoptedRecoveryGrantV1::from_actor_append(self, verified, receipt)
            .map_err(C2GovernedCarrierIngressRefusalV1::from)
    }

    /// Store-owned MSG-14 route.  Verification, generic ingress, revocation
    /// projection and unsigned effect receipt are one savepoint-bound actor
    /// mutation.  The caller never receives a generic ingress permit or a
    /// chance to author target coordinates.
    pub(crate) fn apply_revocation_judgment_v1(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        request: &StoreIntegrityRevocationRequestV1,
        judgment: &StoreIntegrityRevocationJudgmentV1,
    ) -> Result<DurableRevocationEffectV1, C2GovernedCarrierIngressRefusalV1> {
        let evidence = load_generation_current_evidence_before_governance_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )?;
        let cut = evidence
            .current
            .effective_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let frontier = identity_digest_from_bytes(evidence.frontier_identity)?;
        let projection = digest_fields(
            b"nq.c2.store_integrity.revocation_projection.identity.v1\0",
            &[
                evidence.physical_generation_identity.as_str().as_bytes(),
                evidence.current.enrollment_id().as_bytes(),
                evidence.current.standing_id().as_bytes(),
                frontier.as_str().as_bytes(),
                &cut.to_be_bytes(),
                b"operator_withdrawal",
            ],
        );
        let mut exact_fields = self.resolved_governance_exact_fields_v1(authority, &evidence)?;
        for (name, value) in [
            (
                "desired_effect_projection_identity",
                Value::String(projection.as_str().to_owned()),
            ),
            ("proposed_effect_cut", Value::Number(cut.into())),
            ("effective_cut", Value::Number(cut.into())),
            (
                "reason_code",
                Value::String("operator_withdrawal".to_owned()),
            ),
            ("disposition", Value::String("revoked".to_owned())),
            (
                "revocation_projection_identity",
                Value::String(projection.as_str().to_owned()),
            ),
        ] {
            exact_fields.insert(name.to_owned(), value);
        }
        exact_fields
            .retain(|name, _| request.field(name).is_some() || judgment.field(name).is_some());
        let expectation = ExternalGovernanceExpectationV1::new(self, exact_fields, cut, cut)?;
        let permit = ExternalCarrierVerificationPermitV1::from_store_actor(self)?;
        let terminal = StoreTerminalA1VerifierV1 {
            resolved: authority.resolved,
        };
        let verified =
            verify_revocation_judgment_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                judgment,
                request,
                &expectation,
                &terminal,
            )?;
        drop(permit);
        let prepared = prepare_verified_revocation_effect_v1(self, &verified, expectation)?;
        prepared.verify_for_actor(self)?;
        self.with_permitted_effect(StoreC2EffectKindV1::RecoveryOrQuarantine, |transaction| {
            prepared
                .apply(transaction)
                .map_err(C2GovernedCarrierIngressRefusalV1::Durable)
        })
    }

    /// Store-owned MSG-16 route.  It consumes an exact same-process MSG-13
    /// adoption and compares the judgment with the completed durable
    /// successor, retained B/G/lock/backend and admitted manifest before one
    /// atomic ingress/effect/receipt mutation.  No live signer phase is
    /// required or minted while quarantine remains open.
    pub(crate) fn apply_quarantine_closure_judgment_v1<'admission, 'store>(
        &mut self,
        authority: &StoreC2AuthoritySnapshotV1<'store>,
        admitted_manifest: &StoreAdmittedSignerImplementationManifestV1<'admission, 'store>,
        adopted_restore: &StoreAdoptedRestoreAuthorizationV1,
        request: &StoreIntegrityQuarantineClosureRequestV1,
        judgment: &StoreIntegrityQuarantineClosureJudgmentV1,
    ) -> Result<DurableQuarantineClosureEffectV1, C2GovernedCarrierIngressRefusalV1> {
        self.verify_authority_lineage(authority)?;
        adopted_restore.verify_for_actor(self)?;
        verify_store_admitted_signer_implementation_manifest_v1(
            admitted_manifest,
            admitted_manifest.manifest(),
            authority.admission_basis(),
        )
        .map_err(|_| C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let evidence = load_generation_current_evidence_before_governance_v1(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )?;
        if evidence.implementation_manifest_identity != *admitted_manifest.manifest_identity()
            || self.durable_append_pair.is_none()
            || self.generation_lock.is_none()
        {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
        }
        let authorization = adopted_restore.verified().carrier();
        let restore_identity = format!(
            "sha256:{}",
            hex::encode(adopted_restore.verified().carrier_identity().bytes())
        );
        let predecessor_generation = authorization
            .field("predecessor_physical_store_generation_identity")
            .and_then(Value::as_str)
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let restore_disposition = authorization
            .field("restore_disposition_identity")
            .and_then(Value::as_str)
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let restore_proof = authorization
            .field("restore_proof_identity")
            .and_then(Value::as_str)
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        if authorization
            .field("target_signer_enrollment_identity")
            .and_then(Value::as_str)
            != Some(evidence.current.enrollment_id())
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch.into());
        }
        let cut = evidence
            .current
            .effective_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let frontier = identity_digest_from_bytes(evidence.frontier_identity)?;
        let quarantine = digest_fields(
            b"nq.c2.restore_quarantine.identity.v1\0",
            &[
                restore_identity.as_bytes(),
                evidence.physical_generation_identity.as_str().as_bytes(),
                evidence.lineage_identity.as_str().as_bytes(),
                evidence.installation_receipt_identity.as_str().as_bytes(),
            ],
        );
        let projection = digest_fields(
            b"nq.c2.quarantine_closure_projection.identity.v1\0",
            &[
                quarantine.as_str().as_bytes(),
                frontier.as_str().as_bytes(),
                evidence.current.standing_id().as_bytes(),
                &cut.to_be_bytes(),
            ],
        );
        let mut exact_fields = self.resolved_governance_exact_fields_v1(authority, &evidence)?;
        for (name, value) in [
            (
                "desired_effect_projection_identity",
                Value::String(projection.as_str().to_owned()),
            ),
            ("proposed_effect_cut", Value::Number(cut.into())),
            (
                "restore_authorization_identity",
                Value::String(restore_identity),
            ),
            (
                "predecessor_physical_store_generation_identity",
                Value::String(predecessor_generation.to_owned()),
            ),
            (
                "restore_disposition_identity",
                Value::String(restore_disposition.to_owned()),
            ),
            (
                "restore_proof_identity",
                Value::String(restore_proof.to_owned()),
            ),
            (
                "quarantine_identity",
                Value::String(quarantine.as_str().to_owned()),
            ),
            (
                "quarantine_state",
                Value::String("closed_to_writes".to_owned()),
            ),
            ("closure_cut", Value::Number(cut.into())),
            (
                "quarantine_closure_projection_identity",
                Value::String(projection.as_str().to_owned()),
            ),
            (
                "disposition",
                Value::String("quarantine_closure_authorized".to_owned()),
            ),
            ("estate_wide_scope", Value::Bool(false)),
        ] {
            exact_fields.insert(name.to_owned(), value);
        }
        exact_fields
            .retain(|name, _| request.field(name).is_some() || judgment.field(name).is_some());
        let expectation = ExternalGovernanceExpectationV1::new(self, exact_fields, cut, cut)?;
        let permit = ExternalCarrierVerificationPermitV1::from_store_actor(self)?;
        let terminal = StoreTerminalA1VerifierV1 {
            resolved: authority.resolved,
        };
        let verified =
            verify_quarantine_closure_terminal_a1_signature_scope_policy_cut_request_identity(
                &permit,
                judgment,
                request,
                &expectation,
                &terminal,
            )?;
        drop(permit);
        let prepared = prepare_verified_quarantine_closure_effect_v1(self, &verified, expectation)?;
        prepared.verify_for_actor(self)?;
        self.with_permitted_effect(StoreC2EffectKindV1::RecoveryOrQuarantine, |transaction| {
            prepared
                .apply(transaction)
                .map_err(C2GovernedCarrierIngressRefusalV1::Durable)
        })
    }

    /// Atomic installation signer batch closing the MSG-09 -> MSG-03
    /// semantic dependency while preserving MSG-03 as physical B genesis.
    ///
    /// MSG-09 is first projected only inside this uncommitted Store
    /// transaction so MSG-03 receives the exact semantic successor frontier.
    /// The physical carrier is then synchronized in the required order:
    /// MSG-03 at B slot 0, MSG-09 at B slot 1. Only after both exact carrier
    /// records exist is the MSG-03 SQL projection inserted; the outer actor
    /// commits both projections together. A crash after physical slot 0
    /// leaves a detectable installation prefix and no committed SQL rows.
    pub(crate) fn with_installation_bootstrap_batch_effect(
        &mut self,
        context: &mut C2LiveSignerContextV1<'_, '_, BootstrapV1>,
        prepare_intent: impl FnOnce(
            &StoreC2SignerAppendPermitV1<'_, '_, '_, BootstrapV1>,
            &C2LiveSigningViewV1<'_, '_, '_, BootstrapV1>,
        ) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2>,
        prepare_bootstrap: impl FnOnce(
            &ConsumedSignedFrameV1,
            &StoreC2SignerAppendPermitV1<'_, '_, '_, BootstrapV1>,
            &C2LiveSigningViewV1<'_, '_, '_, BootstrapV1>,
        ) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2>,
    ) -> Result<ConsumedInstallationBootstrapBatchV1, C2SignerAppendRefusalV1> {
        self.verify_same_snapshot()?;
        context.verify_live(self)?;
        let before = self.current_snapshot_identity.clone();
        let prepared_intent = {
            let intent_live = context.installation_intent_signing_view();
            let intent_permit = StoreC2SignerAppendPermitV1 {
                live: &intent_live,
                actor_instance_identity: self.actor_instance_identity.clone(),
                snapshot_identity: before.clone(),
                effect_epoch: self.effect_epoch,
            };
            prepare_intent(&intent_permit, &intent_live)?
        };

        let transaction = self
            .transaction
            .as_ref()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?;
        transaction
            .execute_batch("SAVEPOINT c2_installation_signer_batch_v1")
            .map_err(StoreError::from)
            .map_err(C2SignerAppendRefusalV1::DurableStore)?;
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-27");
        let original_coordinates = context.coordinates.clone();
        let batch_result = (|| {
            let finalized_intent = finalize_prepared_signed_frame(transaction, prepared_intent)?;
            if !finalized_intent.is_installation_intent() {
                return Err(SignerRefusalV2::CapabilityFamilyMismatch.into());
            }
            let intent_projection_present = finalized_intent.projection_present();
            let intent_operation = finalized_intent.operation_identity()?;
            let intent_kind = finalized_intent.physical_kind();
            let intent_carrier = finalized_intent.canonical_carrier_bytes().to_vec();

            // Transaction-local only: this derives the exact semantic
            // successor frontier consumed by the staged MSG-03 constructor.
            let intent = append_finalized_signed_frame_projection(transaction, finalized_intent)?;
            context.coordinates.predecessor_frontier_identity = intent.resulting_frontier_identity;
            context.coordinates.predecessor_event_identity = Some(intent.message_identity);
            context.coordinates.transition_intent_identity = Some(intent.message_identity);
            context.coordinates.event_cut = context
                .coordinates
                .event_cut
                .checked_add(1)
                .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
            context.coordinates.exact_content_identity = digest_fields(
                b"nq.c2.live_context.staged_installation_intent.v1\0",
                &[
                    intent.append_identity.as_bytes(),
                    &intent.resulting_frontier_identity,
                ],
            )
            .as_str()
            .strip_prefix("sha256:")
            .and_then(|value| hex::decode(value).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;

            let prepared_bootstrap = {
                let bootstrap_live = context.prospective_generation_signing_view();
                let bootstrap_permit = StoreC2SignerAppendPermitV1 {
                    live: &bootstrap_live,
                    actor_instance_identity: self.actor_instance_identity.clone(),
                    snapshot_identity: before.clone(),
                    effect_epoch: self.effect_epoch,
                };
                prepare_bootstrap(&intent, &bootstrap_permit, &bootstrap_live)?
            };
            let finalized_bootstrap =
                finalize_prepared_signed_frame(transaction, prepared_bootstrap)?;
            if !finalized_bootstrap.is_physical_generation_bootstrap() {
                return Err(SignerRefusalV2::CapabilityFamilyMismatch.into());
            }
            let bootstrap_projection_present = finalized_bootstrap.projection_present();
            let bootstrap_operation = finalized_bootstrap.operation_identity()?;
            let bootstrap_kind = finalized_bootstrap.physical_kind();
            let bootstrap_carrier = finalized_bootstrap.canonical_carrier_bytes().to_vec();

            let pair = self
                .durable_append_pair
                .as_mut()
                .ok_or(C2SignerAppendRefusalV1::PhysicalCarrierUnavailable)?;
            let physical_bootstrap = pair.append_or_replay_exact(
                bootstrap_operation,
                bootstrap_kind,
                &bootstrap_carrier,
            )?;
            if bootstrap_projection_present
                && physical_bootstrap.disposition != C2DurableAppendDispositionV1::ExactReplay
            {
                return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
            }
            let physical_intent =
                pair.append_or_replay_exact(intent_operation, intent_kind, &intent_carrier)?;
            if intent_projection_present
                && physical_intent.disposition != C2DurableAppendDispositionV1::ExactReplay
            {
                return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
            }
            let bootstrap =
                append_finalized_signed_frame_projection(transaction, finalized_bootstrap)?;
            let carrier_snapshot = pair.current_snapshot();
            Ok(ConsumedInstallationBootstrapBatchV1::from_store_batch(
                intent,
                bootstrap,
                physical_bootstrap,
                physical_intent,
                carrier_snapshot,
            ))
        })();
        let batch = match batch_result {
            Ok(batch) => batch,
            Err(error) => {
                context.coordinates = original_coordinates;
                if let Err(rollback_error) = transaction.execute_batch(
                    "ROLLBACK TO c2_installation_signer_batch_v1; RELEASE c2_installation_signer_batch_v1",
                ) {
                    self.poisoned = true;
                    return Err(C2SignerAppendRefusalV1::DurableStore(
                        StoreError::Invariant(format!(
                            "installation signer batch refused ({error}); rollback failed ({rollback_error})"
                        )),
                    ));
                }
                #[cfg(test)]
                super::source_io_crash_test_support::after_source_io_v1("SC-28");
                return Err(error);
            }
        };

        // Derive every fallible post-state value while rollback is still
        // possible. The physical carrier may already contain the exact frames;
        // rolling this SQL savepoint back leaves a detectable, replayable
        // carrier-first prefix rather than an actor/context split.
        let staged_post_state = (|| {
            let after = parse_digest(
                &logical_state_digest(transaction, LIVE_C2_STORE_SNAPSHOT_DOMAIN_V1)
                    .map_err(C2SignerAppendRefusalV1::DurableStore)?,
            )?;
            if after == before {
                return Err(C2LiveSignerRefusalV1::StoreSnapshotMismatch.into());
            }
            let next_effect_epoch = self
                .effect_epoch
                .checked_add(1)
                .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
            let mut completed_coordinates = context.coordinates.clone();
            completed_coordinates.predecessor_frontier_identity =
                batch.bootstrap().resulting_frontier_identity;
            completed_coordinates.predecessor_event_identity =
                Some(batch.bootstrap().message_identity);
            completed_coordinates.transition_intent_identity =
                Some(batch.intent().message_identity);
            completed_coordinates.event_cut = completed_coordinates
                .event_cut
                .checked_add(1)
                .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
            let exact_content = digest_fields(
                b"nq.c2.live_context.installation_batch_content.v1\0",
                &[
                    batch.intent().append_identity.as_bytes(),
                    batch.bootstrap().append_identity.as_bytes(),
                    &batch.intent().resulting_frontier_identity,
                    &batch.bootstrap().resulting_frontier_identity,
                ],
            );
            completed_coordinates.exact_content_identity = digest_identity_bytes(&exact_content)?;
            let transcript_entry = digest_fields(
                b"nq.c2.store_effect_transcript.v1\0",
                &[
                    before.as_str().as_bytes(),
                    b"installation_bootstrap_batch",
                    after.as_str().as_bytes(),
                ],
            );
            Ok::<_, C2SignerAppendRefusalV1>((
                after,
                next_effect_epoch,
                completed_coordinates,
                transcript_entry,
            ))
        })();
        let (after, next_effect_epoch, completed_coordinates, transcript_entry) =
            match staged_post_state {
                Ok(staged) => staged,
                Err(error) => {
                    context.coordinates = original_coordinates;
                    if let Err(rollback_error) = transaction.execute_batch(
                        "ROLLBACK TO c2_installation_signer_batch_v1; RELEASE c2_installation_signer_batch_v1",
                    ) {
                        self.poisoned = true;
                        return Err(C2SignerAppendRefusalV1::DurableStore(
                            StoreError::Invariant(format!(
                                "installation signer post-state failed ({error}); rollback failed ({rollback_error})"
                                )),
                            ));
                    }
                    #[cfg(test)]
                    super::source_io_crash_test_support::after_source_io_v1("SC-29");
                    return Err(error);
                }
            };
        let release_result = if source_io_test_precursor_selected_v1("SC-31") {
            Err(rusqlite::Error::InvalidQuery)
        } else {
            transaction.execute_batch("RELEASE c2_installation_signer_batch_v1")
        };
        if let Err(release_error) = release_result {
            context.coordinates = original_coordinates;
            if let Err(rollback_error) = transaction.execute_batch(
                "ROLLBACK TO c2_installation_signer_batch_v1; RELEASE c2_installation_signer_batch_v1",
            ) {
                self.poisoned = true;
                return Err(C2SignerAppendRefusalV1::DurableStore(
                    StoreError::Invariant(format!(
                        "installation signer release failed ({release_error}); rollback failed ({rollback_error})"
                    )),
                ));
            }
            #[cfg(test)]
            super::source_io_crash_test_support::after_source_io_v1("SC-31");
            return Err(C2SignerAppendRefusalV1::DurableStore(StoreError::from(
                release_error,
            )));
        }
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-30");

        self.effect_transcript.push(transcript_entry);
        self.current_snapshot_identity = after;
        self.effect_epoch = next_effect_epoch;
        context.actor_snapshot_identity = self.current_snapshot_identity.clone();
        context.actor_effect_epoch = self.effect_epoch;
        context.coordinates = completed_coordinates;
        Ok(batch)
    }

    /// MSG-03 and MSG-10 share the exact prospective-generation bootstrap
    /// projection.  No generic projection selector is exposed.
    pub(crate) fn with_prospective_generation_append_effect(
        &mut self,
        context: &mut C2LiveSignerContextV1<'_, '_, BootstrapV1>,
        prepare: impl FnOnce(
            &StoreC2SignerAppendPermitV1<'_, '_, '_, BootstrapV1>,
            &C2LiveSigningViewV1<'_, '_, '_, BootstrapV1>,
        ) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2>,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        self.verify_same_snapshot()?;
        context.verify_live(self)?;
        let before = self.current_snapshot_identity.clone();
        let prepared = {
            let live = context.prospective_generation_signing_view();
            let permit = StoreC2SignerAppendPermitV1 {
                live: &live,
                actor_instance_identity: self.actor_instance_identity.clone(),
                snapshot_identity: before.clone(),
                effect_epoch: self.effect_epoch,
            };
            prepare(&permit, &live)?
        };
        self.append_prepared_signer_effect(context, before, prepared)
    }

    /// MSG-05, MSG-06, and MSG-11 consume the restricted current-predecessor
    /// view of one exact generation-current context.
    pub(crate) fn with_current_predecessor_append_effect(
        &mut self,
        context: &mut C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        prepare: impl FnOnce(
            &StoreC2SignerAppendPermitV1<'_, '_, '_, GenerationCurrentV1>,
            &C2LiveSigningViewV1<'_, '_, '_, GenerationCurrentV1>,
        ) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2>,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        self.verify_same_snapshot()?;
        context.verify_live(self)?;
        let before = self.current_snapshot_identity.clone();
        let prepared = {
            let live = context.current_predecessor_signing_view();
            let permit = StoreC2SignerAppendPermitV1 {
                live: &live,
                actor_instance_identity: self.actor_instance_identity.clone(),
                snapshot_identity: before.clone(),
                effect_epoch: self.effect_epoch,
            };
            prepare(&permit, &live)?
        };
        self.append_prepared_signer_effect(context, before, prepared)
    }

    fn append_prepared_signer_effect<Phase>(
        &mut self,
        context: &mut C2LiveSignerContextV1<'_, '_, Phase>,
        before: Sha256Digest,
        prepared: C2PreparedSignedAppendV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        if before != self.current_snapshot_identity {
            return Err(C2LiveSignerRefusalV1::StoreSnapshotMismatch.into());
        }
        let next_event_cut = context
            .coordinates
            .event_cut
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let finalized = finalize_prepared_signed_frame(
            self.transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
            prepared,
        )?;
        let projection_present = finalized.projection_present();
        let physical = self
            .durable_append_pair
            .as_mut()
            .ok_or(C2SignerAppendRefusalV1::PhysicalCarrierUnavailable)?
            .append_or_replay_exact(
                finalized.operation_identity()?,
                finalized.physical_kind(),
                finalized.canonical_carrier_bytes(),
            )?;
        // B/G is canonical and SQLite is a disposable projection. A
        // carrier-first crash is recovered by physical ExactReplay followed
        // by projection insert. The inverse state is corruption and refuses.
        if projection_present && physical.disposition != C2DurableAppendDispositionV1::ExactReplay {
            return Err(C2LiveSignerRefusalV1::CorrespondenceMismatch.into());
        }
        let result = match self.with_permitted_effect(
            StoreC2EffectKindV1::SignerAppend,
            |transaction| -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
                append_finalized_signed_frame_projection(transaction, finalized)
                    .map_err(C2SignerAppendRefusalV1::Signer)
            },
        ) {
            Ok(result) => result,
            Err(refusal) => {
                // At this point an authenticated canonical carrier exists in
                // B/G (either newly appended or observed as an exact replay),
                // but its disposable SQL projection did not complete.  The
                // predecessor brand must not remain usable: a fresh Store
                // actor must reconcile that exact carrier before any new
                // signing authority is minted.
                self.poisoned = true;
                return Err(refusal);
            }
        };
        if result.disposition == SignedFrameAppendDispositionV1::Appended {
            // Same-process continuation is linear: the predecessor context
            // is refreshed in place only from the actor-owned durable result.
            // No scalar result can construct or refresh a context elsewhere.
            context.actor_snapshot_identity = self.current_snapshot_identity.clone();
            context.actor_effect_epoch = self.effect_epoch;
            context.coordinates.predecessor_frontier_identity = result.resulting_frontier_identity;
            context.coordinates.predecessor_event_identity = Some(result.message_identity);
            let exact_content = digest_fields(
                b"nq.c2.live_context.exact_content_after_append.v1\0",
                &[
                    &result.message_identity,
                    result.append_identity.as_bytes(),
                    result.effect_receipt_identity.as_bytes(),
                    &result.resulting_frontier_identity,
                ],
            );
            context.coordinates.exact_content_identity = match digest_identity_bytes(&exact_content)
            {
                Ok(identity) => identity,
                Err(error) => {
                    // The Store effect is already released. Prevent any caller
                    // from catching an impossible digest-conversion failure
                    // and continuing with stale authority.
                    self.poisoned = true;
                    return Err(error.into());
                }
            };
            if matches!(
                result.route.as_str(),
                "msg09_installation_intent" | "msg11_policy_transition_intent"
            ) {
                context.coordinates.transition_intent_identity = Some(result.message_identity);
            }
            context.coordinates.event_cut = next_event_cut;
        } else {
            // Exact replay is durable no-write, so the original live context
            // must remain exactly current rather than being refreshed.
            context.verify_live(self)?;
        }
        Ok(result)
    }

    fn commit(mut self) -> Result<(), C2LiveSignerRefusalV1> {
        self.verify_same_snapshot()?;
        self.transaction
            .take()
            .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?
            .commit()
            .map_err(StoreError::from)?;
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-32");
        Ok(())
    }
}

impl Store {
    /// First bounded fresh-bootstrap root. It persists the exact custody,
    /// canonical MSG-01 request, and complete canonical pre-policy
    /// calculation, then returns only inert request evidence for terminal-A1.
    pub(crate) fn prepare_c2_live_bootstrap_v1(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        intent: &C2BootstrapPreparationIntentV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
    ) -> Result<StorePreparedBootstrapGrantRequestV1, C2LiveBootstrapDriverRefusalV1> {
        self.with_c2_authority_snapshot(qualified, resolve, |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            actor
                .prepare_initial_bootstrap_grant_request_v1(authority, &admitted, intent)
                .map_err(C2LiveBootstrapDriverRefusalV1::from)
        })
    }

    /// Second bounded fresh-bootstrap root. The caller supplies only the
    /// terminal-A1 carrier corresponding to a durable preparation. The Store
    /// reloads that preparation, reopens custody, verifies/adopts MSG-01,
    /// constructs and signs MSG-02, adopts/accepts enrollment, derives the
    /// final install policy, and runs the sole physical C2 installation.
    pub(crate) fn install_c2_live_from_bootstrap_grant_v1(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        grant: &StoreIntegrityBootstrapGrantV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
    ) -> Result<(), C2LiveBootstrapDriverRefusalV1> {
        self.with_c2_authority_snapshot(qualified, resolve, |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            let (custodian, request, calculation, preparation_identity) =
                actor.reopen_prepared_bootstrap_custodian_v1(authority, &admitted, grant)?;
            let custody = custodian
                .seal_reopened_foundational_custody()
                .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
            let grant_adoption = actor.adopt_bootstrap_grant_v1(
                authority,
                &calculation,
                &custody,
                &request,
                grant,
            )?;
            let candidate = actor.construct_initial_enrollment_candidate_v1(
                &calculation,
                &preparation_identity,
                &grant_adoption,
                &custody,
            )?;
            let possession = construct_verified_initial_possession_request_v1(
                actor,
                authority,
                &admitted,
                &grant_adoption,
                &candidate,
                &custody,
            )
            .map_err(C2SignerAppendRefusalV1::Signer)?;
            let consumed = append_initial_proposal_pop_v1(actor, &possession, &custodian)?;
            let foundational = derive_initial_foundational_enrollment_v1(
                &consumed,
                calculation.maximum_key_generations(),
            )
            .map_err(C2SignerAppendRefusalV1::Signer)?;
            let adoption = actor.adopt_foundational_enrollment_v1(foundational, consumed)?;
            let accepted = actor.accept_signer_enrollment_v1(adoption)?;
            let install_policy =
                actor.derive_final_install_policy_v1(calculation, &grant_adoption, &accepted)?;
            let context = actor.mint_bootstrap_signer_context(
                authority,
                &admitted,
                &accepted,
                &custody,
                &grant_adoption,
            )?;
            let current =
                actor.install_c2_live_v1(context, &accepted, &grant_adoption, &install_policy)?;
            drop(current);
            Ok(())
        })
    }

    /// Store-owned consequence-bearing MSG-13 route.  The caller supplies
    /// only canonical external request/carrier evidence; all historical
    /// selection, custody reauthentication, pending authority, enrollment,
    /// MSG-12 selection, and terminal currentness remain private to the
    /// retained Store actor.
    pub(crate) fn restore_c2_live_historical_foundation_v1(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        request: &StoreIntegrityRestoreAuthorizationRequestV1,
        authorization: &StoreIntegrityRestoreAuthorizationV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
    ) -> Result<Sha256Digest, C2LiveTransitionDriverRefusalV1> {
        self.with_c2_authority_snapshot(qualified, resolve, |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            actor.complete_store_restore_lifecycle_v1(authority, &admitted, request, authorization)
        })
    }

    /// First bounded recovery root.  It resolves the exact current terminal
    /// and Store-derived discontinuity condition, creates a semantically new
    /// custody proposal, and durably binds the mechanically derived canonical
    /// MSG-15 request.  Only inert request evidence crosses the external A1
    /// boundary.
    pub(crate) fn prepare_c2_live_recovery_v1(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        intent: &C2RecoveryPreparationIntentV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
    ) -> Result<StorePreparedRecoveryGrantRequestV1, C2LiveTransitionDriverRefusalV1> {
        self.with_c2_authority_snapshot(qualified, resolve, |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            actor.prepare_recovery_grant_request_v1(authority, &admitted, intent)
        })
    }

    /// Store-owned consequence-bearing MSG-15 continuation.  The request
    /// must name an exact durable recovery custody preparation; raw new-key
    /// coordinates cannot enter this root and the grant cannot select
    /// restore or healthy-rotation semantics.
    pub(crate) fn recover_c2_live_new_foundation_v1(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        request: &StoreIntegrityRecoveryRequestV1,
        grant: &StoreIntegrityRecoveryGrantV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
    ) -> Result<Sha256Digest, C2LiveTransitionDriverRefusalV1> {
        self.with_c2_authority_snapshot(qualified, resolve, |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            actor.complete_store_recovery_lifecycle_v1(authority, &admitted, request, grant)
        })
    }

    /// Sole fresh-process reopen root for a complete C2 GenerationCurrent
    /// lifecycle.  The callback cannot outlive the retained Store snapshot,
    /// freshly admitted manifest, reopened custody, permanent generation
    /// lock, or authenticated B/G descriptors.
    pub(crate) fn with_reopened_c2_generation_current_v1<R, E>(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
        operation: impl for<'session, 'live, 'snapshot> FnOnce(
            &'session mut C2LiveWriterSessionV1<'session, 'live, 'snapshot>,
        ) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<C2LiveSignerRefusalV1>
            + From<SignerImplementationManifestRefusalV1>
            + From<C2LiveInstallationDriverRefusalV1>
            + From<StoreError>
            + From<io::Error>,
    {
        self.with_c2_authority_snapshot(qualified, resolve, move |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            actor.with_reopened_generation_current_v1(authority, &admitted, |actor, context| {
                let mut session =
                    C2LiveWriterSessionV1::from_exact_generation_current(actor, context)?;
                operation(&mut session)
            })
        })
    }

    /// Sole Store-owned production root for an unchanged-policy healthy
    /// successor. It freshly reopens the exact GenerationCurrent predecessor,
    /// retains the physical C2 substrate and custody descriptors, and runs the
    /// complete linear MSG-07/06/11/adoption/acceptance/MSG-12/terminal path.
    /// Internal authority constructors and completion identities do not cross
    /// this boundary.
    pub(crate) fn rotate_c2_live_healthy_successor_v1(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        intent: &C2HealthySuccessorIntentV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
    ) -> Result<Sha256Digest, C2LiveTransitionDriverRefusalV1> {
        self.with_c2_authority_snapshot(qualified, resolve, |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            actor.with_reopened_generation_current_v1(authority, &admitted, |actor, current| {
                let policy_target = StoreResolvedHealthySuccessorPolicyTargetV1::unchanged(current);
                actor.complete_healthy_successor_v1(current, intent, policy_target)
            })
        })
    }

    /// Sole Store-owned production root for a healthy successor whose
    /// policy, activation, or applicability changes.  The MSG-01 carrier is
    /// first verified and durably adopted under the exact current authority
    /// snapshot.  The actor then refreshes the predecessor context and seals
    /// the MSG-05 target from that adopted carrier; callers cannot provide a
    /// raw policy target or select the conditional signing branch.
    pub(crate) fn rotate_c2_live_healthy_successor_with_activation_grant_v1(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        intent: &C2HealthySuccessorIntentV1,
        request: &StoreIntegrityActivationSuccessorGrantRequestV1,
        grant: &StoreIntegrityActivationSuccessorGrantV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
    ) -> Result<Sha256Digest, C2LiveTransitionDriverRefusalV1> {
        self.with_c2_authority_snapshot(qualified, resolve, |actor, authority| {
            let admitted =
                admit_signer_implementation_manifest_v1(manifest, authority.admission_basis())?;
            actor.with_reopened_generation_current_v1(authority, &admitted, |actor, current| {
                let adopted = actor.adopt_activation_successor_grant_v1(
                    current.authority_snapshot,
                    request,
                    grant,
                )?;
                actor.refresh_current_after_external_ingress_v1(
                    current,
                    adopted.durable_receipt(),
                )?;
                let policy_target = StoreResolvedHealthySuccessorPolicyTargetV1::
                        from_store_adopted_activation_successor_grant(
                            actor,
                            current,
                            &adopted,
                        )?;
                actor.complete_healthy_successor_v1(current, intent, policy_target)
            })
        })
    }

    /// Enter the sole Store-owned current-authority/manifest-admission root.
    ///
    /// The Store is enumerated under one immediate transaction retained for
    /// the whole operation together with the process/path guard and root
    /// descriptor.  A digest of a former snapshot is never accepted as the
    /// live borrow.  Success commits only after the snapshot and database
    /// object are reverified; refusal drops the transaction without commit.
    fn with_c2_authority_snapshot<R, E>(
        &mut self,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        resolve: impl FnOnce(
            &RuntimeAuthorityRestartSnapshot,
        ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1>,
        operation: impl for<'operation, 'snapshot> FnOnce(
            &'operation mut StoreC2SnapshotActorV1<'snapshot>,
            &'operation StoreC2AuthoritySnapshotV1<'snapshot>,
        ) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<C2LiveSignerRefusalV1> + From<StoreError> + From<io::Error>,
    {
        let database_path = self
            .path
            .as_deref()
            .ok_or(C2LiveSignerRefusalV1::StoreBasisUnavailable)?
            .to_path_buf();
        if pragma_i64(&self.connection, "user_version")? != 9 {
            return Err(C2LiveSignerRefusalV1::StoreBasisUnavailable.into());
        }

        let actual_runtime_artifact_identity = measure_current_runtime_artifact()?;
        qualified.verify_measured_runtime_artifact(&actual_runtime_artifact_identity)?;
        let process_identity = current_process_identity()?;
        let metadata = std::fs::metadata(&database_path)?;
        if !metadata.file_type().is_file() {
            return Err(C2LiveSignerRefusalV1::StoreBasisUnavailable.into());
        }
        let store_instance_identity = digest_fields(
            LIVE_C2_STORE_INSTANCE_DOMAIN_V1,
            &[
                &metadata.dev().to_be_bytes(),
                &metadata.ino().to_be_bytes(),
                database_path.as_os_str().as_encoded_bytes(),
            ],
        );

        let root_path = database_path
            .parent()
            .ok_or(C2LiveSignerRefusalV1::StoreBasisUnavailable)?;
        let root = File::open(root_path)?;
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-33");
        let root_metadata = root.metadata()?;
        if !root_metadata.file_type().is_dir() {
            return Err(C2LiveSignerRefusalV1::StoreBasisUnavailable.into());
        }
        let database_name = database_path
            .file_name()
            .ok_or(C2LiveSignerRefusalV1::StoreBasisUnavailable)?;
        let database_file = File::from(
            openat(
                &root,
                database_name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-34");
        let retained_database_metadata = database_file.metadata()?;
        if !retained_database_metadata.file_type().is_file()
            || (
                retained_database_metadata.dev(),
                retained_database_metadata.ino(),
            ) != (metadata.dev(), metadata.ino())
        {
            return Err(C2LiveSignerRefusalV1::StoreBasisUnavailable.into());
        }
        let maintenance_guard = acquire_maintenance_locks(&[database_path.as_path()])?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-35");
        validate_runtime_authority_invariants(&transaction)?;
        let root_identity = runtime_dependency_trust_root_on_connection(&transaction)?
            .ok_or(StoreError::EstablishmentRootMissing)?;
        let receipt = runtime_dependency_establishment_receipt_on_connection(&transaction)?
            .ok_or(StoreError::EstablishmentReceiptMissing)?;
        let occurrence_id = sole_genesis_on_connection(&transaction)?
            .ok_or(C2LiveSignerRefusalV1::OccurrenceMismatch)?;
        let presented = presented_runtime_authority_set_on_connection(&transaction)?;
        let migration_receipt = runtime_migration_receipt_bytes_on_connection(&transaction)?;
        let restart_snapshot = RuntimeAuthorityRestartSnapshot {
            root: root_identity,
            occurrence_id: occurrence_id.clone(),
            receipt,
            presented,
            migration_receipt,
        };
        let resolver_input = collect_complete_gen4_authority_ledger(&restart_snapshot)?;
        let resolved = resolve(&restart_snapshot)?;
        let current_activation = project_current_activation_for_c2(&resolver_input, &resolved)?;
        let snapshot_text = logical_state_digest(&transaction, LIVE_C2_STORE_SNAPSHOT_DOMAIN_V1)?;
        let store_snapshot_identity = parse_digest(&snapshot_text)?;

        let seal = StoreC2SnapshotSealV1 {
            store_snapshot_identity,
            store_instance_identity,
            occurrence_id,
            authority_candidate_set_identity: resolver_input.candidate_set_digest().clone(),
            measured_runtime_artifact_identity: actual_runtime_artifact_identity,
            process_identity,
            creator_pid: std::process::id(),
        };
        let basis = StoreC2AdmissionBasisV1 {
            snapshot: &seal,
            qualified,
            _invariant: PhantomData,
        };
        basis.verify_same_process()?;
        let mut actor = StoreC2SnapshotActorV1 {
            transaction: Some(transaction),
            _maintenance_guard: maintenance_guard,
            root,
            database_file,
            database_path,
            database_device: metadata.dev(),
            database_inode: metadata.ino(),
            root_device: root_metadata.dev(),
            root_inode: root_metadata.ino(),
            initial_snapshot_identity: seal.store_snapshot_identity.clone(),
            current_snapshot_identity: seal.store_snapshot_identity.clone(),
            store_instance_identity: seal.store_instance_identity.clone(),
            effect_transcript: Vec::new(),
            actor_instance_identity: digest_fields(
                b"nq.c2.store_snapshot_actor.instance.v1\0",
                &[
                    seal.store_instance_identity.as_str().as_bytes(),
                    seal.store_snapshot_identity.as_str().as_bytes(),
                    seal.process_identity.as_str().as_bytes(),
                    qualified
                        .qualification_binding_identity()
                        .as_str()
                        .as_bytes(),
                    process_epoch()?,
                ],
            ),
            effect_epoch: 0,
            process_identity: seal.process_identity.clone(),
            creator_pid: std::process::id(),
            poisoned: false,
            durable_append_pair: None,
            generation_lock: None,
        };
        let authority = StoreC2AuthoritySnapshotV1 {
            admission_basis: &basis,
            current_activation,
            resolver_input: &resolver_input,
            resolved: &resolved,
        };
        authority.verify_same_process_and_snapshot()?;
        let result = operation(&mut actor, &authority)?;
        actor.commit()?;
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-36");
        Ok(result)
    }
}

fn load_install_policy_calculation_for_request_v1(
    transaction: &Transaction<'_>,
    request_identity: &Sha256Digest,
) -> Result<C2StoreGenerationInstallPolicyCalculationV1, C2LiveInstallationDriverRefusalV1> {
    let (identity, bytes, digest, length): (String, Vec<u8>, String, u64) = transaction
        .query_row(
            "SELECT install_policy_calculation_identity,
                    install_policy_calculation_canonical_bytes,
                    install_policy_calculation_canonical_sha256,
                    install_policy_calculation_canonical_length
             FROM c2_custody_proposal_preparations
             WHERE bootstrap_request_identity = ?1",
            [request_identity.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(StoreError::from)?;
    let calculation = decode_install_policy_calculation_v1(&bytes)
        .map_err(|_| C2LiveInstallationDriverRefusalV1::ContractMismatch)?;
    if identity != calculation.identity().as_str()
        || digest != sha256_bytes(&bytes).as_str()
        || length != bytes.len() as u64
    {
        return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
    }
    Ok(calculation)
}

/// Enumerate and recompute one exact durable custody-proposal frontier.
/// Ordering is legal only because every adjacent row names the recomputed
/// predecessor; a maximum ordinal or insertion order alone is never enough.
fn resolve_custody_proposal_frontier_v1(
    transaction: &Transaction<'_>,
    scope_token: &Sha256Digest,
) -> Result<(u64, Sha256Digest, BTreeMap<u64, Sha256Digest>), C2CustodyPreparationRefusalV1> {
    let mut statement = transaction.prepare(
        "SELECT preparation_lineage, proposal_ordinal, predecessor_frontier_identity,
                resulting_frontier_identity, proposal_identity,
                proposal_canonical_bytes, proposal_canonical_sha256,
                proposal_canonical_length, bootstrap_request_identity,
                bootstrap_request_canonical_bytes,
                bootstrap_request_canonical_sha256,
                bootstrap_request_canonical_length,
                successor_request_identity,
                successor_request_canonical_bytes,
                successor_request_canonical_sha256,
                successor_request_canonical_length
         FROM c2_custody_proposal_preparations
         WHERE scope_token = ?1
         ORDER BY proposal_ordinal ASC",
    )?;
    let mut rows = statement.query(params![scope_token.as_str()])?;
    let mut typed_rows = Vec::new();
    while let Some(row) = rows.next()? {
        let lineage: String = row.get(0)?;
        let ordinal: u64 = row.get(1)?;
        let predecessor = Sha256Digest::parse(row.get::<_, String>(2)?)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        let resulting = Sha256Digest::parse(row.get::<_, String>(3)?)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        let proposal_identity = Sha256Digest::parse(row.get::<_, String>(4)?)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        let proposal_bytes: Vec<u8> = row.get(5)?;
        let proposal_sha = Sha256Digest::parse(row.get::<_, String>(6)?)
            .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?;
        let proposal_length: u64 = row.get(7)?;
        let bootstrap_identity: Option<String> = row.get(8)?;
        let bootstrap_bytes: Option<Vec<u8>> = row.get(9)?;
        let bootstrap_sha: Option<String> = row.get(10)?;
        let bootstrap_length: Option<u64> = row.get(11)?;
        let successor_identity: Option<String> = row.get(12)?;
        let successor_bytes: Option<Vec<u8>> = row.get(13)?;
        let successor_sha: Option<String> = row.get(14)?;
        let successor_length: Option<u64> = row.get(15)?;
        let typed = match lineage.as_str() {
            "initialExternal" => {
                let (identity, bytes, sha, length) = match (
                    bootstrap_identity,
                    bootstrap_bytes,
                    bootstrap_sha,
                    bootstrap_length,
                    successor_identity,
                    successor_bytes,
                    successor_sha,
                    successor_length,
                ) {
                    (
                        Some(identity),
                        Some(bytes),
                        Some(sha),
                        Some(length),
                        None,
                        None,
                        None,
                        None,
                    ) => (identity, bytes, sha, length),
                    _ => return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into()),
                };
                let request =
                    match StoreCustodyPreparationReferenceV1::decode_initial_external(&bytes)? {
                        StoreCustodyPreparationReferenceV1::InitialExternal(request) => request,
                        _ => return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into()),
                    };
                if identity_digest_from_bytes(*request.identity().bytes())?.as_str() != identity {
                    return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into());
                }
                StoreCustodyProposalFrontierRowV1::initial_external(
                    ordinal,
                    predecessor,
                    resulting,
                    proposal_identity,
                    proposal_bytes,
                    proposal_sha,
                    proposal_length,
                    request,
                    Sha256Digest::parse(sha)
                        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?,
                    length,
                )?
            }
            "ordinarySuccessorContinuity" => {
                let (identity, bytes, sha, length) = match (
                    bootstrap_identity,
                    bootstrap_bytes,
                    bootstrap_sha,
                    bootstrap_length,
                    successor_identity,
                    successor_bytes,
                    successor_sha,
                    successor_length,
                ) {
                    (
                        None,
                        None,
                        None,
                        None,
                        Some(identity),
                        Some(bytes),
                        Some(sha),
                        Some(length),
                    ) => (identity, bytes, sha, length),
                    _ => return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into()),
                };
                let request =
                    match StoreCustodyPreparationReferenceV1::decode_ordinary_successor(&bytes)? {
                        StoreCustodyPreparationReferenceV1::OrdinarySuccessor(request) => request,
                        _ => return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into()),
                    };
                if request.identity().as_str() != identity {
                    return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into());
                }
                StoreCustodyProposalFrontierRowV1::ordinary_successor(
                    ordinal,
                    predecessor,
                    resulting,
                    proposal_identity,
                    proposal_bytes,
                    proposal_sha,
                    proposal_length,
                    request,
                    Sha256Digest::parse(sha)
                        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?,
                    length,
                )?
            }
            "recoveryNewFoundation" => {
                let (identity, bytes, sha, length) = match (
                    bootstrap_identity,
                    bootstrap_bytes,
                    bootstrap_sha,
                    bootstrap_length,
                    successor_identity,
                    successor_bytes,
                    successor_sha,
                    successor_length,
                ) {
                    (
                        None,
                        None,
                        None,
                        None,
                        Some(identity),
                        Some(bytes),
                        Some(sha),
                        Some(length),
                    ) => (identity, bytes, sha, length),
                    _ => return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into()),
                };
                let request =
                    match StoreCustodyPreparationReferenceV1::decode_recovery_new_foundation(
                        &bytes,
                    )? {
                        StoreCustodyPreparationReferenceV1::RecoveryNewFoundation(request) => {
                            request
                        }
                        _ => return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into()),
                    };
                if identity_digest_from_bytes(*request.identity().bytes())?.as_str() != identity {
                    return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into());
                }
                StoreCustodyProposalFrontierRowV1::recovery_new_foundation(
                    ordinal,
                    predecessor,
                    resulting,
                    proposal_identity,
                    proposal_bytes,
                    proposal_sha,
                    proposal_length,
                    request,
                    Sha256Digest::parse(sha)
                        .map_err(|_| SignerRefusalV2::EnrollmentEvidenceCollision)?,
                    length,
                )?
            }
            _ => return Err(SignerRefusalV2::EnrollmentEvidenceCollision.into()),
        };
        typed_rows.push(typed);
    }
    resolve_store_custody_proposal_frontier_rows_v1(scope_token, typed_rows)
        .map_err(C2CustodyPreparationRefusalV1::from)
}

/// Refusal-only census of the fixed C2 carrier names beneath the exact root
/// descriptor retained by the Store actor.
///
/// Any directory entry at one of these names -- including a symlink or wrong
/// object type -- is a governed installation footprint. The census uses
/// `AT_SYMLINK_NOFOLLOW` and never opens or interprets the object. It may
/// classify otherwise SQL-absent state as incomplete, but cannot contribute a
/// premise to live authority construction.
fn has_any_c2_fixed_footprint_below_retained_root_v1(
    root: &File,
) -> Result<bool, C2LiveSignerRefusalV1> {
    for name in [
        super::C2_LOCK_FILE_V1,
        super::C2_BOOTSTRAP_EXTENT_V1,
        super::C2_GLOBAL_REFUSAL_EXTENT_V1,
    ] {
        match statat(root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Ok(true),
            Err(Errno::NOENT) => {}
            Err(error) => return Err(C2LiveSignerRefusalV1::Io(io::Error::from(error))),
        }
    }
    Ok(false)
}

fn resolve_generation_current_from_retained_basis_v1(
    transaction: &Transaction<'_>,
    root: &File,
) -> Result<StoreResolvedGenerationCurrentEvidenceV1, C2LiveSignerRefusalV1> {
    let resolved = load_generation_current_evidence_v1(transaction);
    match resolved {
        Err(C2LiveSignerRefusalV1::GenerationCurrentAbsent)
            if has_any_c2_fixed_footprint_below_retained_root_v1(root)? =>
        {
            // A filesystem-first S1--S3 prefix is already governed C2 state
            // even when the actor crashed before its first SQL projection.
            // Treating it as absence would permit a second bootstrap identity
            // to reinterpret an existing physical prefix.
            Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)
        }
        result => result,
    }
}

fn exact_table_count(
    transaction: &Transaction<'_>,
    table: &str,
) -> Result<u64, C2LiveSignerRefusalV1> {
    // `table` is supplied only by the closed call sites below. Keeping the
    // helper private prevents a caller-selected SQL identifier surface.
    let sql = format!("SELECT COUNT(*) FROM {table}");
    transaction
        .query_row(&sql, [], |row| row.get(0))
        .map_err(StoreError::from)
        .map_err(C2LiveSignerRefusalV1::Store)
}

fn load_installation_projection_v1(
    transaction: &Transaction<'_>,
) -> Result<C2InstallationProjectionRowV1, C2LiveSignerRefusalV1> {
    transaction
        .query_row(
            "SELECT p.projection_identity, p.occurrence_id,
                    p.physical_store_generation_identity, p.bootstrap_identity,
                    p.installation_nonce, p.state, p.canonical_bytes,
                    p.canonical_bytes_sha256, p.canonical_bytes_length,
                    r.installation_receipt_identity, r.installation_intent_identity,
                    r.pre_receipt_b_root_identity, r.pre_receipt_b_cursor,
                    r.g_root_identity, r.g_cursor, r.completion_state,
                    r.canonical_receipt_sha256
             FROM c2_installation_projection AS p
             JOIN c2_installation_receipt_index AS r
               ON r.pending_projection_identity = p.projection_identity
              AND r.physical_store_generation_identity = p.physical_store_generation_identity
              AND r.bootstrap_identity = p.bootstrap_identity",
            [],
            |row| {
                Ok(C2InstallationProjectionRowV1 {
                    projection_identity: row.get(0)?,
                    occurrence_id: row.get(1)?,
                    physical_generation_identity: row.get(2)?,
                    bootstrap_identity: row.get(3)?,
                    installation_nonce: row.get(4)?,
                    state: row.get(5)?,
                    canonical_bytes: row.get(6)?,
                    canonical_bytes_sha256: row.get(7)?,
                    canonical_bytes_length: row.get(8)?,
                    installation_receipt_identity: row.get(9)?,
                    installation_intent_identity: row.get(10)?,
                    pre_receipt_b_root_identity: row.get(11)?,
                    pre_receipt_b_cursor: row.get(12)?,
                    g_root_identity: row.get(13)?,
                    g_cursor: row.get(14)?,
                    completion_state: row.get(15)?,
                    canonical_receipt_sha256: row.get(16)?,
                })
            },
        )
        .map_err(StoreError::from)
        .map_err(C2LiveSignerRefusalV1::Store)
}

fn load_bootstrap_generation_relation_v1(
    transaction: &Transaction<'_>,
) -> Result<C2BootstrapGenerationRelationRowV1, C2LiveSignerRefusalV1> {
    transaction
        .query_row(
            "SELECT relation_identity, bootstrap_grant_identity,
                    foundational_enrollment_identity, signer_enrollment_identity,
                    initial_pop_identity, physical_generation_bootstrap_identity,
                    generation_commitment_identity, installation_receipt_identity,
                    physical_store_generation_identity, transition_cut,
                    canonical_bytes, canonical_bytes_sha256,
                    canonical_bytes_length
             FROM c2_signer_bootstrap_transition",
            [],
            |row| {
                Ok(C2BootstrapGenerationRelationRowV1 {
                    relation_identity: row.get(0)?,
                    bootstrap_grant_identity: row.get(1)?,
                    foundational_enrollment_identity: row.get(2)?,
                    signer_enrollment_identity: row.get(3)?,
                    initial_pop_identity: row.get(4)?,
                    physical_generation_bootstrap_identity: row.get(5)?,
                    generation_commitment_identity: row.get(6)?,
                    installation_receipt_identity: row.get(7)?,
                    physical_generation_identity: row.get(8)?,
                    transition_cut: row.get(9)?,
                    canonical_bytes: row.get(10)?,
                    canonical_bytes_sha256: row.get(11)?,
                    canonical_bytes_length: row.get(12)?,
                })
            },
        )
        .map_err(StoreError::from)
        .map_err(C2LiveSignerRefusalV1::Store)
}

fn verify_bootstrap_generation_relation_v1(
    transaction: &Transaction<'_>,
    row: &C2BootstrapGenerationRelationRowV1,
) -> Result<C2BootstrapGenerationRelationWireV1, C2LiveSignerRefusalV1> {
    let wire: C2BootstrapGenerationRelationWireV1 = serde_json::from_slice(&row.canonical_bytes)
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let relation_identity = parse_digest(&row.relation_identity)?;
    let bootstrap_grant = parse_digest(&row.bootstrap_grant_identity)?;
    let foundational_enrollment = parse_digest(&row.foundational_enrollment_identity)?;
    let signer_enrollment = parse_digest(&row.signer_enrollment_identity)?;
    let initial_pop = parse_digest(&row.initial_pop_identity)?;
    let msg03 = parse_digest(&row.physical_generation_bootstrap_identity)?;
    let commitment = parse_digest(&row.generation_commitment_identity)?;
    let msg10 = parse_digest(&row.installation_receipt_identity)?;
    let physical_generation = parse_digest(&row.physical_generation_identity)?;
    let body = C2BootstrapGenerationRelationIdentityBodyV1 {
        schema: "nq.c2_signer_bootstrap_transition.v1",
        schema_version: 1,
        identity_domain: "nq.c2.signer_bootstrap_transition.identity.v1",
        bootstrap_grant_identity: &bootstrap_grant,
        foundational_enrollment_identity: &foundational_enrollment,
        signer_enrollment_identity: &signer_enrollment,
        initial_pop_identity: &initial_pop,
        physical_generation_bootstrap_identity: &msg03,
        generation_commitment_identity: &commitment,
        installation_receipt_identity: &msg10,
        physical_store_generation_identity: &physical_generation,
        transition_cut: row.transition_cut,
    };
    let body_bytes = canonical_json_bytes(&body)
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    if canonical_json_bytes(&wire).map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?
        != row.canonical_bytes
        || row.canonical_bytes_length != row.canonical_bytes.len() as u64
        || parse_digest(&row.canonical_bytes_sha256)? != sha256_bytes(&row.canonical_bytes)
        || relation_identity
            != canonical_domain_identity(body.identity_domain.as_bytes(), &body_bytes)
        || wire.schema != body.schema
        || wire.schema_version != body.schema_version
        || wire.identity_domain != body.identity_domain
        || wire.relation_identity != relation_identity
        || wire.bootstrap_grant_identity != bootstrap_grant
        || wire.foundational_enrollment_identity != foundational_enrollment
        || wire.signer_enrollment_identity != signer_enrollment
        || wire.initial_pop_identity != initial_pop
        || wire.physical_generation_bootstrap_identity != msg03
        || wire.generation_commitment_identity != commitment
        || wire.installation_receipt_identity != msg10
        || wire.physical_store_generation_identity != physical_generation
        || wire.transition_cut != row.transition_cut
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }

    let (stored_foundation, stored_grant, stored_pop, stored_acceptance, accepted_cut): (
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        u64,
    ) = transaction
        .query_row(
            "SELECT a.foundational_enrollment_identity, a.grant_identity,
                    a.msg02_message_identity, s.signer_enrollment_identity,
                    s.accepted_cut
             FROM c2_signer_enrollment_acceptances AS s
             JOIN c2_foundational_enrollment_adoptions AS a
               ON a.adoption_identity = s.foundational_adoption_identity
             WHERE s.signer_enrollment_identity = ?1",
            [wire.signer_enrollment_identity.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(StoreError::from)?;
    let stored_grant: [u8; 32] = stored_grant
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let stored_pop: [u8; 32] = stored_pop
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let (stored_msg03, msg03_cut): (Vec<u8>, u64) = transaction
        .query_row(
            "SELECT message_identity, event_cut
             FROM c2_signer_message_appends
             WHERE route = 'msg03_physical_generation_bootstrap'",
            [],
            |record| Ok((record.get(0)?, record.get(1)?)),
        )
        .map_err(StoreError::from)?;
    let (stored_msg10, msg10_cut): (Vec<u8>, u64) = transaction
        .query_row(
            "SELECT message_identity, event_cut
             FROM c2_signer_message_appends
             WHERE route = 'msg10_installation_receipt'",
            [],
            |record| Ok((record.get(0)?, record.get(1)?)),
        )
        .map_err(StoreError::from)?;
    let stored_msg03: [u8; 32] = stored_msg03
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let stored_msg10: [u8; 32] = stored_msg10
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    if stored_foundation != wire.foundational_enrollment_identity.as_str()
        || stored_acceptance != wire.signer_enrollment_identity.as_str()
        || identity_digest_from_bytes(stored_grant)? != wire.bootstrap_grant_identity
        || identity_digest_from_bytes(stored_pop)? != wire.initial_pop_identity
        || identity_digest_from_bytes(stored_msg03)? != wire.physical_generation_bootstrap_identity
        || identity_digest_from_bytes(stored_msg10)? != wire.installation_receipt_identity
        || accepted_cut >= msg03_cut
        || msg03_cut >= msg10_cut
        || wire.transition_cut != msg10_cut
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    Ok(wire)
}

fn load_root_binding_projection_v1(
    transaction: &Transaction<'_>,
    identity: &str,
) -> Result<C2RootBindingProjectionRowV1, C2LiveSignerRefusalV1> {
    transaction
        .query_row(
            "SELECT root_binding_identity, occurrence_id,
                    physical_store_generation_identity,
                    signer_lifecycle_root_identity, initial_enrollment_identity,
                    initial_key_generation, initial_public_key,
                    generation_genesis_identity, generation_commitment_identity,
                    scope_identity, resident_identity, resident_generation,
                    host_role, role_manifest_generation, authority_domain,
                    policy_lineage_root_identity, creation_cut, canonical_bytes,
                    canonical_bytes_sha256, canonical_bytes_length
             FROM c2_signer_root_binding_projection
             WHERE root_binding_identity = ?1",
            [identity],
            |row| {
                Ok(C2RootBindingProjectionRowV1 {
                    root_binding_identity: row.get(0)?,
                    occurrence_id: row.get(1)?,
                    physical_generation_identity: row.get(2)?,
                    lifecycle_root_identity: row.get(3)?,
                    initial_enrollment_identity: row.get(4)?,
                    initial_key_generation: row.get(5)?,
                    initial_public_key: row.get(6)?,
                    generation_genesis_identity: row.get(7)?,
                    generation_commitment_identity: row.get(8)?,
                    scope_identity: row.get(9)?,
                    resident_identity: row.get(10)?,
                    resident_generation: row.get(11)?,
                    host_role: row.get(12)?,
                    role_manifest_generation: row.get(13)?,
                    authority_domain: row.get(14)?,
                    policy_lineage_root_identity: row.get(15)?,
                    creation_cut: row.get(16)?,
                    canonical_bytes: row.get(17)?,
                    canonical_bytes_sha256: row.get(18)?,
                    canonical_bytes_length: row.get(19)?,
                })
            },
        )
        .map_err(StoreError::from)
        .map_err(C2LiveSignerRefusalV1::Store)
}

fn load_current_binding_projection_v1(
    transaction: &Transaction<'_>,
    identity: &str,
) -> Result<C2CurrentBindingProjectionRowV1, C2LiveSignerRefusalV1> {
    transaction
        .query_row(
            "SELECT current_binding_identity, root_binding_identity,
                    occurrence_id, physical_store_generation_identity,
                    signer_lifecycle_root_identity, scope_identity,
                    resident_identity, resident_generation, host_role,
                    role_manifest_generation, authority_domain,
                    policy_lineage_root_identity, current_enrollment_identity,
                    current_key_generation, current_public_key,
                    current_policy_identity, current_standing_identity,
                    binding_mode, transition_identity,
                    predecessor_binding_identity, persisted_resolution_identity,
                    effective_cut, canonical_bytes, canonical_bytes_sha256,
                    canonical_bytes_length
             FROM c2_signer_current_binding_projection
             WHERE current_binding_identity = ?1",
            [identity],
            |row| {
                Ok(C2CurrentBindingProjectionRowV1 {
                    current_binding_identity: row.get(0)?,
                    root_binding_identity: row.get(1)?,
                    occurrence_id: row.get(2)?,
                    physical_generation_identity: row.get(3)?,
                    lifecycle_root_identity: row.get(4)?,
                    scope_identity: row.get(5)?,
                    resident_identity: row.get(6)?,
                    resident_generation: row.get(7)?,
                    host_role: row.get(8)?,
                    role_manifest_generation: row.get(9)?,
                    authority_domain: row.get(10)?,
                    policy_lineage_root_identity: row.get(11)?,
                    current_enrollment_identity: row.get(12)?,
                    current_key_generation: row.get(13)?,
                    current_public_key: row.get(14)?,
                    current_policy_identity: row.get(15)?,
                    current_standing_identity: row.get(16)?,
                    binding_mode: row.get(17)?,
                    transition_identity: row.get(18)?,
                    predecessor_binding_identity: row.get(19)?,
                    persisted_resolution_identity: row.get(20)?,
                    effective_cut: row.get(21)?,
                    canonical_bytes: row.get(22)?,
                    canonical_bytes_sha256: row.get(23)?,
                    canonical_bytes_length: row.get(24)?,
                })
            },
        )
        .map_err(StoreError::from)
        .map_err(C2LiveSignerRefusalV1::Store)
}

fn verify_root_projection_v1(
    row: &C2RootBindingProjectionRowV1,
) -> Result<StoreGenerationSignerRootBindingV1, C2LiveSignerRefusalV1> {
    let root = decode_verified_store_generation_signer_root_binding_v1(&row.canonical_bytes)
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let key_generation = root
        .initial_key_generation()
        .parse::<u64>()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let role_generation = root
        .role_manifest_generation()
        .parse::<u64>()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    if row.canonical_bytes_length != row.canonical_bytes.len() as u64
        || parse_digest(&row.canonical_bytes_sha256)? != sha256_bytes(&row.canonical_bytes)
        || row.root_binding_identity != root.binding_id().as_str()
        || row.occurrence_id != root.occurrence_id()
        || row.physical_generation_identity != root.physical_store_generation()
        || row.lifecycle_root_identity != root.lifecycle_root_id()
        || row.initial_enrollment_identity != root.initial_enrollment_id()
        || row.initial_key_generation != key_generation
        || row.generation_genesis_identity != root.genesis_digest().as_str()
        || row.generation_commitment_identity != root.generation_commitment_digest().as_str()
        || row.scope_identity != root.scope_id()
        || row.resident_identity != root.resident_id()
        || row.host_role != root.role_id()
        || row.role_manifest_generation != role_generation
        || row.authority_domain != root.domain_id()
        || row.policy_lineage_root_identity != root.policy_lineage_root()
        || row.creation_cut != root.creation_cut()
        || row.initial_public_key.len() != 32
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    Ok(root)
}

fn verify_current_projection_v1(
    root_row: &C2RootBindingProjectionRowV1,
    root: &StoreGenerationSignerRootBindingV1,
    row: &C2CurrentBindingProjectionRowV1,
) -> Result<CurrentSignerGenerationBindingV1, C2LiveSignerRefusalV1> {
    let current = decode_verified_current_signer_generation_binding_v1(root, &row.canonical_bytes)
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let key_generation = current
        .key_generation()
        .parse::<u64>()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let expected_mode = match current.mode() {
        CurrentSignerBindingModeV1::Initial => "initial",
        CurrentSignerBindingModeV1::NormalSuccessor => "normal_successor",
        CurrentSignerBindingModeV1::RestoreSuccessor => "restore_successor",
        CurrentSignerBindingModeV1::RecoverySuccessor => "recovery_successor",
    };
    if row.canonical_bytes_length != row.canonical_bytes.len() as u64
        || parse_digest(&row.canonical_bytes_sha256)? != sha256_bytes(&row.canonical_bytes)
        || row.current_binding_identity != current.binding_id().as_str()
        || row.root_binding_identity != root.binding_id().as_str()
        || row.occurrence_id != root_row.occurrence_id
        || row.physical_generation_identity != root_row.physical_generation_identity
        || row.lifecycle_root_identity != root_row.lifecycle_root_identity
        || row.scope_identity != root_row.scope_identity
        || row.resident_identity != root_row.resident_identity
        || row.resident_generation != root_row.resident_generation
        || row.host_role != root_row.host_role
        || row.role_manifest_generation != root_row.role_manifest_generation
        || row.authority_domain != root_row.authority_domain
        || row.policy_lineage_root_identity != root_row.policy_lineage_root_identity
        || row.current_enrollment_identity != current.enrollment_id()
        || row.current_key_generation != key_generation
        || row.current_policy_identity != current.policy_id()
        || row.current_standing_identity != current.standing_id()
        || row.binding_mode != expected_mode
        || row.transition_identity.as_deref() != current.transition_id()
        || row.predecessor_binding_identity.as_deref()
            != current.predecessor_binding_id().map(Sha256Digest::as_str)
        || row.persisted_resolution_identity != current.persisted_resolution_id()
        || row.effective_cut != current.effective_cut()
        || row.current_public_key.len() != 32
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    Ok(current)
}

fn load_generation_current_evidence_v1(
    transaction: &Transaction<'_>,
) -> Result<StoreResolvedGenerationCurrentEvidenceV1, C2LiveSignerRefusalV1> {
    let evidence = load_generation_current_evidence_before_governance_v1(transaction)?;
    match refuse_if_current_signer_revoked_v1(
        transaction,
        evidence.root.physical_store_generation(),
        evidence.root.lifecycle_root_id(),
        evidence.root.scope_id(),
        evidence.current.enrollment_id(),
        &evidence.current_public_key,
        evidence
            .current
            .key_generation()
            .parse::<u64>()
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?,
        evidence.current.standing_id(),
    ) {
        Ok(()) => Ok(evidence),
        Err(C2ExternalIngressRefusalV1::CurrentSignerRevoked) => {
            Err(C2LiveSignerRefusalV1::CurrentSignerRevoked)
        }
        Err(_) => Err(C2LiveSignerRefusalV1::GenerationCurrentGovernanceMalformed),
    }
}

/// Exact inert predecessor projection for Store-owned governance roots.  It
/// deliberately omits the revocation/currentness decision so recovery and
/// exact replay can inspect a superseded predecessor; only the gated wrapper
/// above may feed the live GenerationCurrent constructor.
fn load_generation_current_evidence_before_governance_v1(
    transaction: &Transaction<'_>,
) -> Result<StoreResolvedGenerationCurrentEvidenceV1, C2LiveSignerRefusalV1> {
    let projection_count = exact_table_count(transaction, "c2_installation_projection")?;
    let receipt_count = exact_table_count(transaction, "c2_installation_receipt_index")?;
    let relation_count = exact_table_count(transaction, "c2_signer_bootstrap_transition")?;
    if projection_count == 0 && receipt_count == 0 && relation_count == 0 {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentAbsent);
    }
    if projection_count == 0 || receipt_count == 0 || relation_count == 0 {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete);
    }
    if projection_count != 1 || receipt_count != 1 || relation_count != 1 {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentAmbiguous);
    }
    let installation = load_installation_projection_v1(transaction)?;
    let wire: C2InstallationProjectionWireV1 =
        serde_json::from_slice(&installation.canonical_bytes)
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let projection_identity = parse_digest(&installation.projection_identity)?;
    let physical_generation_identity = parse_digest(&installation.physical_generation_identity)?;
    let bootstrap_identity = parse_digest(&installation.bootstrap_identity)?;
    if canonical_json_bytes(&wire).map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?
        != installation.canonical_bytes
        || installation.canonical_bytes_length != installation.canonical_bytes.len() as u64
        || parse_digest(&installation.canonical_bytes_sha256)?
            != sha256_bytes(&installation.canonical_bytes)
        || wire.schema != "nq.c2_installation_projection.v1"
        || wire.schema_version != 1
        || wire.projection_identity != projection_identity
        || wire.occurrence_id != installation.occurrence_id
        || wire.physical_store_generation_identity != physical_generation_identity
        || wire.bootstrap_identity != bootstrap_identity
        || wire.installation_nonce != installation.installation_nonce
        || wire.state != "pending"
        || installation.state != "pending"
        || installation.completion_state != "complete"
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    let relation_row = load_bootstrap_generation_relation_v1(transaction)?;
    let relation = verify_bootstrap_generation_relation_v1(transaction, &relation_row)?;
    if relation.physical_generation_bootstrap_identity != bootstrap_identity
        || relation.installation_receipt_identity
            != parse_digest(&installation.installation_receipt_identity)?
        || relation.physical_store_generation_identity != physical_generation_identity
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }

    let root_count = exact_table_count(transaction, "c2_signer_root_binding_projection")?;
    if root_count == 0 {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete);
    }
    if root_count != 1 {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentAmbiguous);
    }
    let root_binding_identity: String = transaction
        .query_row(
            "SELECT root_binding_identity FROM c2_signer_root_binding_projection",
            [],
            |row| row.get(0),
        )
        .map_err(StoreError::from)?;
    let root_row = load_root_binding_projection_v1(transaction, &root_binding_identity)?;
    let root = verify_root_projection_v1(&root_row)?;
    if root_row.occurrence_id != installation.occurrence_id
        || root_row.physical_generation_identity != installation.physical_generation_identity
        || root_row.generation_genesis_identity != installation.bootstrap_identity
        || root_row.initial_enrollment_identity != relation.signer_enrollment_identity.as_str()
        || root_row.generation_commitment_identity
            != relation.generation_commitment_identity.as_str()
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }

    let durable_terminal = resolve_store_verified_durable_generation_current_v1(transaction, &root)
        .map_err(map_durable_terminal_refusal_v1)?;
    if durable_terminal.root().binding_id() != root.binding_id()
        || durable_terminal.initial_binding().mode() != CurrentSignerBindingModeV1::Initial
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    let current = durable_terminal.terminal_binding().clone();
    let terminal_binding_identity = current.binding_id().as_str().to_owned();
    let current_row = load_current_binding_projection_v1(transaction, &terminal_binding_identity)?;
    let current = verify_current_projection_v1(&root_row, &root, &current_row)?;
    if current.binding_id() != durable_terminal.terminal_binding().binding_id()
        || current.enrollment_id()
            != durable_terminal
                .enrollment()
                .acceptance()
                .identity()
                .as_str()
        || current_row.current_public_key.as_slice()
            != durable_terminal.terminal_public_key().as_slice()
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    let lineage_identity_text = durable_terminal.lineage_identity().as_str().to_owned();
    let lineage_bytes: Vec<u8> = transaction
        .query_row(
            "SELECT canonical_bytes FROM c2_signer_lineage_projection
             WHERE lineage_identity = ?1",
            [&lineage_identity_text],
            |row| row.get(0),
        )
        .map_err(StoreError::from)?;

    let (
        resolution_ledger_sequence,
        resolution_message_identity,
        resolution_frontier,
        resolution_exact_content,
        route,
        resolution_canonical_message,
        resolution_physical_carrier,
    ): (
        u64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
    ) = transaction
        .query_row(
            "SELECT ledger_sequence, message_identity,
                    resulting_frontier_identity, exact_content_identity,
                    route, canonical_message, physical_carrier_bytes
             FROM c2_signer_message_appends
             WHERE effect_receipt_identity = ?1",
            [&current_row.persisted_resolution_identity],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(StoreError::from)?;
    let resolution_message_identity: [u8; 32] = resolution_message_identity
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let resolution_frontier: [u8; 32] = resolution_frontier
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let resolution_exact_content: [u8; 32] = resolution_exact_content
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let resolution_physical_carrier = resolution_physical_carrier
        .as_deref()
        .ok_or(C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let verified_resolution_carrier =
        verify_durable_signer_carrier_envelope_v1(resolution_physical_carrier)
            .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    if verified_resolution_carrier.route().as_str() != route
        || verified_resolution_carrier.message_identity() != resolution_message_identity
        || verified_resolution_carrier.resulting_frontier_identity() != resolution_frontier
        || verified_resolution_carrier.canonical_message() != resolution_canonical_message
        || verified_resolution_carrier.effect_receipt_identity()
            != current_row.persisted_resolution_identity
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    let route_matches = match current.mode() {
        CurrentSignerBindingModeV1::Initial => route == "msg10_installation_receipt",
        CurrentSignerBindingModeV1::NormalSuccessor
        | CurrentSignerBindingModeV1::RestoreSuccessor
        | CurrentSignerBindingModeV1::RecoverySuccessor => {
            matches!(
                route.as_str(),
                "msg12_receipt_current" | "msg12_receipt_pending"
            )
        }
    };
    let current_public_key: [u8; 32] = current_row
        .current_public_key
        .clone()
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    if !route_matches {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    let resolution_message: Value = serde_json::from_slice(&resolution_canonical_message)
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let signed_exact_content = resolution_message
        .get("coordinates")
        .and_then(|coordinates| coordinates.get("exact_content_identity"))
        .and_then(Value::as_str)
        .ok_or(C2LiveSignerRefusalV1::GenerationCurrentMalformed)
        .and_then(|identity| {
            digest_text_identity(identity)
                .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)
        })?;
    if resolution_exact_content != signed_exact_content {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    let active_policy_generation = resolution_message
        .get("coordinates")
        .and_then(|coordinates| coordinates.get("active_store_policy_generation"))
        .and_then(Value::as_u64)
        .ok_or(C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let resident_generation = resolution_message
        .get("coordinates")
        .and_then(|coordinates| coordinates.get("resident_generation"))
        .and_then(Value::as_u64)
        .ok_or(C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let role_manifest_identity = resolution_message
        .get("coordinates")
        .and_then(|coordinates| coordinates.get("role_manifest_identity"))
        .and_then(Value::as_str)
        .ok_or(C2LiveSignerRefusalV1::GenerationCurrentMalformed)
        .and_then(digest_text_identity)?;
    let implementation_manifest_identity = resolution_message
        .get("coordinates")
        .and_then(|coordinates| coordinates.get("implementation_manifest_identity"))
        .and_then(Value::as_str)
        .ok_or(C2LiveSignerRefusalV1::GenerationCurrentMalformed)
        .and_then(parse_digest)?;
    if active_policy_generation == 0
        || resolution_message
            .get("coordinates")
            .and_then(|coordinates| coordinates.get("active_store_policy_identity"))
            .and_then(Value::as_str)
            != Some(current.policy_id())
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }

    // A complete lineage resolution is the only durable phase selector.
    // Any later lifecycle-family append is an unresolved PendingPossession or
    // PendingSelected prefix (or an illegal second installation prefix).  It
    // must never be reinterpreted as the preceding GenerationCurrent merely
    // because that older binding row remains complete.
    let mut later_routes_statement = transaction
        .prepare(
            "SELECT route
             FROM c2_signer_message_appends
             WHERE ledger_sequence > ?1
               AND occurrence_id = ?2
             ORDER BY ledger_sequence",
        )
        .map_err(StoreError::from)?;
    let later_routes = later_routes_statement
        .query_map(
            params![resolution_ledger_sequence, installation.occurrence_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(StoreError::from)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)?;
    if later_routes
        .iter()
        .any(|route| !append_route_preserves_generation_current_v1(route))
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete);
    }

    // Healthy generation-current work can advance the durable signer
    // frontier after the binding resolution.  Reopen must extend that exact
    // terminal event, not the stale installation/succession receipt.
    let (
        terminal_ledger_sequence,
        terminal_message_identity,
        terminal_frontier,
        terminal_event_cut,
        terminal_append_identity,
        terminal_effect_receipt_identity,
        terminal_frontier_namespace,
        terminal_physical_generation,
        terminal_lifecycle_root,
        terminal_binding,
        terminal_public_key,
        terminal_key_generation,
        terminal_policy_identity,
        terminal_policy_generation,
        terminal_manifest_identity,
    ): (
        u64,
        Vec<u8>,
        Vec<u8>,
        u64,
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        u64,
        Vec<u8>,
        u64,
        Vec<u8>,
    ) = transaction
        .query_row(
            "SELECT ledger_sequence, message_identity,
                    resulting_frontier_identity, event_cut, append_identity,
                    effect_receipt_identity, frontier_namespace_identity,
                    physical_generation_identity, lifecycle_root_identity,
                    terminal_binding_identity, signer_public_key,
                    signer_key_generation, active_store_policy_identity,
                    active_store_policy_generation,
                    implementation_manifest_identity
             FROM c2_signer_message_appends
             WHERE occurrence_id = ?1
             ORDER BY ledger_sequence DESC
             LIMIT 1",
            [&installation.occurrence_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                ))
            },
        )
        .map_err(StoreError::from)?;
    let predecessor_event_identity: [u8; 32] = terminal_message_identity
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let frontier_identity: [u8; 32] = terminal_frontier
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let expected_frontier_namespace = digest_fields(
        b"nq.c2.generation_current_frontier_namespace.v1\0",
        &[
            installation.occurrence_id.as_bytes(),
            physical_generation_identity.as_str().as_bytes(),
            root.lifecycle_root_id().as_bytes(),
            current.binding_id().as_str().as_bytes(),
        ],
    );
    let current_key_generation = current
        .key_generation()
        .parse::<u64>()
        .map_err(|_| C2LiveSignerRefusalV1::GenerationCurrentMalformed)?;
    let terminal_event_cut_mismatch = if terminal_ledger_sequence == resolution_ledger_sequence {
        match current.mode() {
            CurrentSignerBindingModeV1::Initial => terminal_event_cut < current.effective_cut(),
            CurrentSignerBindingModeV1::NormalSuccessor
            | CurrentSignerBindingModeV1::RestoreSuccessor
            | CurrentSignerBindingModeV1::RecoverySuccessor => {
                terminal_event_cut.checked_add(1) != Some(current.effective_cut())
            }
        }
    } else {
        // A later GenerationCurrent-preserving append is prepared at the
        // already-effective cut and may advance from there.  It must never
        // precede the binding's exact effective cut.
        terminal_event_cut < current.effective_cut()
    };
    if terminal_ledger_sequence < resolution_ledger_sequence
        || terminal_event_cut_mismatch
        || terminal_public_key != current_public_key
        || terminal_key_generation != current_key_generation
        || terminal_policy_identity != digest_text_identity(current.policy_id())?
        || terminal_policy_generation != active_policy_generation
        || terminal_manifest_identity != digest_identity_bytes(&implementation_manifest_identity)?
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }
    if terminal_ledger_sequence > resolution_ledger_sequence {
        if terminal_frontier_namespace != digest_identity_bytes(&expected_frontier_namespace)?
            || terminal_physical_generation.as_deref()
                != Some(digest_identity_bytes(&physical_generation_identity)?.as_slice())
            || terminal_lifecycle_root.as_deref()
                != Some(digest_text_identity(root.lifecycle_root_id())?.as_slice())
            || terminal_binding.as_deref()
                != Some(digest_identity_bytes(current.binding_id())?.as_slice())
        {
            return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
        }
    } else if predecessor_event_identity != resolution_message_identity
        || frontier_identity != resolution_frontier
    {
        return Err(C2LiveSignerRefusalV1::GenerationCurrentMalformed);
    }

    let installation_intent_identity = parse_digest(&installation.installation_intent_identity)?;
    let installation_receipt_identity = parse_digest(&installation.installation_receipt_identity)?;
    let pre_receipt_b_root_identity = parse_digest(&installation.pre_receipt_b_root_identity)?;
    let g_root_identity = parse_digest(&installation.g_root_identity)?;
    let lineage_identity = durable_terminal.lineage_identity().clone();
    let lineage_completion_identity = durable_terminal.lineage_completion_identity().clone();
    let terminal_candidate_set_identity =
        durable_terminal.terminal_candidate_set_identity().clone();
    let canonical_receipt_sha256 = parse_digest(&installation.canonical_receipt_sha256)?;
    let resolved_exact_content_identity = digest_fields(
        b"nq.c2.resolved_generation_current.exact_content.v1\0",
        &[
            installation.canonical_bytes.as_slice(),
            relation_row.canonical_bytes.as_slice(),
            root_row.canonical_bytes.as_slice(),
            current_row.canonical_bytes.as_slice(),
            lineage_bytes.as_slice(),
            resolution_canonical_message.as_slice(),
            canonical_receipt_sha256.as_str().as_bytes(),
            &resolution_frontier,
        ],
    );
    let exact_content_identity = if terminal_ledger_sequence == resolution_ledger_sequence {
        resolved_exact_content_identity
    } else {
        digest_fields(
            b"nq.c2.live_context.exact_content_after_append.v1\0",
            &[
                &predecessor_event_identity,
                terminal_append_identity.as_bytes(),
                terminal_effect_receipt_identity.as_bytes(),
                &frontier_identity,
            ],
        )
    };
    let event_cut = if terminal_ledger_sequence == resolution_ledger_sequence {
        current.effective_cut()
    } else {
        terminal_event_cut
            .checked_add(1)
            .filter(|cut| *cut <= 9_007_199_254_740_991)
            .ok_or(C2LiveSignerRefusalV1::GenerationCurrentMalformed)?
    };
    Ok(StoreResolvedGenerationCurrentEvidenceV1 {
        projection_identity,
        occurrence_id: installation.occurrence_id,
        physical_generation_identity,
        bootstrap_identity,
        installation_intent_identity,
        installation_receipt_identity,
        bootstrap_generation_relation_identity: relation.relation_identity.clone(),
        bootstrap_generation_relation: relation,
        pre_receipt_b_root_identity,
        pre_receipt_b_cursor: installation.pre_receipt_b_cursor,
        g_root_identity,
        g_cursor: installation.g_cursor,
        root,
        current,
        current_public_key,
        active_policy_generation,
        resident_generation,
        role_manifest_identity,
        implementation_manifest_identity,
        lineage_identity,
        lineage_completion_identity,
        terminal_candidate_set_identity,
        predecessor_event_identity,
        event_cut,
        frontier_identity,
        exact_content_identity,
        durable_terminal,
    })
}

fn map_durable_terminal_refusal_v1(
    refusal: DurableTerminalResolutionRefusalV1,
) -> C2LiveSignerRefusalV1 {
    match refusal {
        DurableTerminalResolutionRefusalV1::Absent => {
            C2LiveSignerRefusalV1::GenerationCurrentAbsent
        }
        DurableTerminalResolutionRefusalV1::Incomplete => {
            C2LiveSignerRefusalV1::GenerationCurrentIncomplete
        }
        DurableTerminalResolutionRefusalV1::Fork
        | DurableTerminalResolutionRefusalV1::MultipleMaximalTerminals => {
            C2LiveSignerRefusalV1::GenerationCurrentAmbiguous
        }
        DurableTerminalResolutionRefusalV1::Gap
        | DurableTerminalResolutionRefusalV1::Cycle
        | DurableTerminalResolutionRefusalV1::Disconnected
        | DurableTerminalResolutionRefusalV1::Malformed
        | DurableTerminalResolutionRefusalV1::ModeLineageMismatch
        | DurableTerminalResolutionRefusalV1::Enrollment(_)
        | DurableTerminalResolutionRefusalV1::Sql(_) => {
            C2LiveSignerRefusalV1::GenerationCurrentMalformed
        }
    }
}

const fn foundational_lineage_name_v1(lineage: FoundationalAdoptionLineageV1) -> &'static str {
    match lineage {
        FoundationalAdoptionLineageV1::InitialExternal => "initialExternal",
        FoundationalAdoptionLineageV1::OrdinarySuccessorContinuity => "ordinarySuccessorContinuity",
        FoundationalAdoptionLineageV1::RestoreHistorical => "restoreHistorical",
        FoundationalAdoptionLineageV1::RecoveryNewFoundation => "recoveryNewFoundation",
    }
}

fn parse_digest(value: &str) -> Result<Sha256Digest, C2LiveSignerRefusalV1> {
    Sha256Digest::parse(value.to_owned())
        .map_err(|_| C2LiveSignerRefusalV1::MalformedQualifiedIdentity)
}

fn digest_identity_bytes(digest: &Sha256Digest) -> Result<[u8; 32], C2LiveSignerRefusalV1> {
    let value = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(C2LiveSignerRefusalV1::MalformedQualifiedIdentity)?;
    hex::decode(value)
        .map_err(|_| C2LiveSignerRefusalV1::MalformedQualifiedIdentity)?
        .try_into()
        .map_err(|_| C2LiveSignerRefusalV1::MalformedQualifiedIdentity)
}

fn identity_digest_from_bytes(identity: [u8; 32]) -> Result<Sha256Digest, C2LiveSignerRefusalV1> {
    parse_digest(&format!("sha256:{}", hex::encode(identity)))
}

fn digest_text_identity(value: &str) -> Result<[u8; 32], C2LiveSignerRefusalV1> {
    digest_identity_bytes(&parse_digest(value)?)
}

fn live_c2_digest_json_field_v1(value: Option<&Value>) -> Result<[u8; 32], C2LiveSignerRefusalV1> {
    value
        .and_then(Value::as_str)
        .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)
        .and_then(digest_text_identity)
}

fn current_healthy_rotation_applicability_identity_v1(
    coordinates: &C2LiveSigningCoordinatesV1,
) -> [u8; 32] {
    digest_fields_bytes(
        b"nq.c2.healthy_rotation.current_applicability.identity.v1\0",
        &[
            &coordinates.current_a2_identity,
            &coordinates.active_policy_identity,
            &coordinates.active_policy_digest,
            &coordinates.signer_scope_policy_identity,
            &coordinates.signer_scope_identity,
            &coordinates.terminal_a1_identity,
        ],
    )
}

fn discontinuity_identity_field(
    value: Option<&Value>,
) -> Result<[u8; 32], C2DiscontinuityRefusalV1> {
    value
        .and_then(Value::as_str)
        .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)
        .and_then(|text| {
            digest_text_identity(text).map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)
        })
}

fn discontinuity_digest_field(
    value: Option<&Value>,
) -> Result<Sha256Digest, C2DiscontinuityRefusalV1> {
    value
        .and_then(Value::as_str)
        .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)
        .and_then(|text| {
            Sha256Digest::parse(text.to_owned())
                .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)
        })
}

fn discontinuity_u64_field(value: Option<&Value>) -> Result<u64, C2DiscontinuityRefusalV1> {
    value
        .and_then(Value::as_u64)
        .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)
}

fn discontinuity_public_key_field(
    value: Option<&Value>,
) -> Result<[u8; 32], C2DiscontinuityRefusalV1> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?;
    hex::decode(text)
        .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)?
        .try_into()
        .map_err(|_| C2DiscontinuityRefusalV1::RouteOrLineageMismatch)
}

fn text_identity_bytes(domain: &[u8], value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

/// Reopen all fixed names through the retained root and require exact inode,
/// ownership, mode, link, and length correspondence.  This is a read-only
/// observation; the returned descriptors are deliberately dropped and never
/// participate in standing construction.
fn verify_reopened_c2_fixed_descriptors_v1(
    root: &File,
    expected_lock: &C2CarrierFileFactsV1,
    expected_b: &C2CarrierFileFactsV1,
    expected_g: &C2CarrierFileFactsV1,
) -> Result<(), C2LiveInstallationDriverRefusalV1> {
    for (name, expected) in [
        (super::C2_LOCK_FILE_V1, expected_lock),
        (super::C2_BOOTSTRAP_EXTENT_V1, expected_b),
        (super::C2_GLOBAL_REFUSAL_EXTENT_V1, expected_g),
    ] {
        let reopened = File::from(
            openat(
                root,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(C2LiveSignerRefusalV1::Io)?,
        );
        #[cfg(test)]
        super::source_io_crash_test_support::after_source_io_v1("SC-37");
        if &exact_c2_carrier_file_facts_v1(&reopened)? != expected {
            return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
        }
    }
    Ok(())
}

fn exact_c2_carrier_file_facts_v1(
    file: &File,
) -> Result<C2CarrierFileFactsV1, C2LiveInstallationDriverRefusalV1> {
    let metadata = file.metadata().map_err(C2LiveSignerRefusalV1::Io)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(C2LiveInstallationDriverRefusalV1::ContractMismatch);
    }
    let identity = digest_fields(
        b"nq.c2.fixed_carrier_file.identity.v1\0",
        &[
            &metadata.dev().to_be_bytes(),
            &metadata.ino().to_be_bytes(),
            &metadata.uid().to_be_bytes(),
            &metadata.gid().to_be_bytes(),
            &(metadata.mode() & 0o777).to_be_bytes(),
            &metadata.len().to_be_bytes(),
            &metadata.nlink().to_be_bytes(),
        ],
    );
    Ok(C2CarrierFileFactsV1 {
        file_identity: identity,
        device: metadata.dev(),
        inode: metadata.ino(),
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
        mode: metadata.mode() & 0o777,
        physical_length: metadata.len(),
        link_count: metadata.nlink(),
    })
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Sha256Digest::parse(format!("sha256:{}", hex::encode(bytes)))
        .expect("SHA-256 bytes always form one valid algorithm-qualified digest")
}

fn digest_fields_bytes(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    digest_identity_bytes(&digest_fields(domain, fields))
        .expect("internally derived SHA-256 identity has a fixed 32-byte payload")
}

/// The install policy authenticates the pre-generation foundational
/// enrollment, never the later signer-acceptance record.  Keeping this as one
/// closed predicate prevents installation and reopen from silently choosing
/// different enrollment layers.
fn installation_policy_binds_foundational_layer_v1(
    policy_enrollment: &Sha256Digest,
    foundational_enrollment: &Sha256Digest,
    signer_acceptance: &Sha256Digest,
) -> bool {
    policy_enrollment == foundational_enrollment
        && policy_enrollment != signer_acceptance
        && foundational_enrollment != signer_acceptance
}

/// Identity law used by canonical semantic records whose contract fixes
/// `domain || NUL || RFC8785(body)` rather than the length-framed internal
/// coordinate digest used by `digest_fields`.
fn canonical_domain_identity(domain: &[u8], canonical_body: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical_body);
    let bytes: [u8; 32] = hasher.finalize().into();
    Sha256Digest::parse(format!("sha256:{}", hex::encode(bytes)))
        .expect("SHA-256 bytes always form one valid algorithm-qualified digest")
}

pub(in crate::store_generation) fn measure_current_runtime_artifact()
-> Result<Sha256Digest, C2LiveSignerRefusalV1> {
    // The qualification/runtime target is Linux. `current_exe()` returns a
    // pathname which can be replaced after exec; reopening that pathname can
    // therefore hash bytes other than the image mapped into this process.
    // Linux's procfs executable magic link opens the running image object
    // itself (including the unlinked original after pathname replacement).
    // Procfs semantics remain an executable/qualification premise, not a
    // semantic theorem.
    #[cfg(target_os = "linux")]
    let mut file = File::open("/proc/self/exe")?;
    #[cfg(all(test, target_os = "linux"))]
    super::source_io_crash_test_support::after_source_io_v1("SC-38");
    #[cfg(not(target_os = "linux"))]
    return Err(C2LiveSignerRefusalV1::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "exact running-image measurement is implemented only for Linux",
    )));
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(C2LiveSignerRefusalV1::RuntimeArtifactMismatch);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    parse_digest(&format!("sha256:{}", hex::encode(bytes)))
}

fn process_epoch() -> Result<&'static [u8; 32], C2LiveSignerRefusalV1> {
    static EPOCH: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(epoch) = EPOCH.get() {
        return Ok(epoch);
    }
    let mut epoch = [0_u8; 32];
    getrandom::fill(&mut epoch).map_err(io::Error::other)?;
    // Losing a race is harmless: every contender uses the one retained epoch.
    let _ = EPOCH.set(epoch);
    EPOCH.get().ok_or_else(|| {
        C2LiveSignerRefusalV1::Io(io::Error::other("process epoch initialization failed"))
    })
}

fn current_process_identity() -> Result<Sha256Digest, C2LiveSignerRefusalV1> {
    Ok(digest_fields(
        LIVE_C2_PROCESS_DOMAIN_V1,
        &[process_epoch()?, &std::process::id().to_be_bytes()],
    ))
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use ed25519_dalek::SigningKey;
    use nq_protocol::sha256_bytes;
    use nq_runtime_dependency_authority::test_support::RawAuthorityFixture;
    use nq_runtime_dependency_authority::{
        ControllingActivationSnapshot, resolve_for_restart, verify_for_establishment,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::store_generation::records::{
        A2ChainRootIdentityV1, APPEND_EXTENT_LAYOUT_V1, C2InstallAuthorityTupleV1,
        C2InstalledCarrierGeometryV1, C2StructuralCutV1, ControllingActivationIdentityV1,
        DependencyAnchorIdentityV1, LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1,
        QualifiedBackendProfileIdentityV1, ResidentIdentityV1, RoleManifestIdentityV1,
        StoreOccurrenceIdentityV1,
    };
    use crate::store_generation::signer::custody::with_test_production_custody_root_v1;
    use crate::store_generation::signer::external_governance::tests::{
        sign_exact_bootstrap_grant_for_test, sign_exact_quarantine_closure_for_test,
        sign_exact_recovery_grant_for_test, sign_exact_restore_authorization_for_test,
        sign_exact_revocation_judgment_for_test,
    };
    use crate::store_generation::signer::manifest::{
        SignerImplementationManifestDerivationInputV1, derive_signer_implementation_manifest_v1,
    };

    fn establish_runtime_authority_fixture(
        store: &mut Store,
        fixture: &RawAuthorityFixture,
    ) -> Result<(), StoreError> {
        let custody = fixture.custody();
        let presented = fixture.presented_set();
        let expectations = fixture.activation_expectations();
        store.with_runtime_authority_writer_session(|brand, session| {
            let resolved =
                verify_for_establishment(brand, &custody, &presented, None, &expectations)?;
            session.establish_runtime_dependency_trust_root(&resolved)?;
            Ok(())
        })
    }

    fn resolve_runtime_authority_fixture(
        fixture: &RawAuthorityFixture,
        snapshot: &RuntimeAuthorityRestartSnapshot,
    ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1> {
        let custody = fixture.custody();
        let expectations = fixture.restart_expectations();
        resolve_for_restart(
            &custody,
            &snapshot.presented,
            snapshot.migration_receipt.as_ref(),
            &expectations,
        )
        .map_err(StoreError::from)
        .map_err(C2LiveSignerRefusalV1::from)
    }

    fn executable_manifest() -> StoreIntegritySignerImplementationManifestV1 {
        derive_signer_implementation_manifest_v1(SignerImplementationManifestDerivationInputV1 {
            custody_format_identity: sha256_bytes(b"live-root-test/custody-format"),
            signer_message_contract_identity: sha256_bytes(b"live-root-test/msg-01-through-msg-16"),
            source_file_bytes: BTreeMap::from([
                (
                    "crates/nq-store/src/store_generation/live_c2.rs".to_owned(),
                    b"live-c2-root-test-basis".to_vec(),
                ),
                (
                    "crates/nq-store/src/store_generation/signer/custody.rs".to_owned(),
                    b"custody-root-test-basis".to_vec(),
                ),
            ]),
            cryptographic_backend_identity: sha256_bytes(b"live-root-test/ed25519-dalek-v2-strict"),
            toolchain_identity: sha256_bytes(b"live-root-test/rust-toolchain"),
            target_profile_identity: sha256_bytes(b"live-root-test/linux-target"),
            qualification_assumption_identities: BTreeSet::from([
                sha256_bytes(b"live-root-test/os-process-freshness"),
                sha256_bytes(b"live-root-test/sha256-collision-resistance"),
            ]),
        })
        .expect("derive exact executable-test implementation manifest")
    }

    fn bootstrap_intent(
        current: &ControllingActivationSnapshot,
        role_manifest_identity: &Sha256Digest,
        signer_scope_policy_identity: &Sha256Digest,
    ) -> C2BootstrapPreparationIntentV1 {
        let authority_cut = current.verification_cut().sequence();
        C2BootstrapPreparationIntentV1::new(
            role_manifest_identity.clone(),
            signer_scope_policy_identity.clone(),
            C2StoreGenerationInstallPolicyCalculationInputV1 {
                authority: C2InstallAuthorityTupleV1 {
                    occurrence: StoreOccurrenceIdentityV1::new(current.occurrence_id()).unwrap(),
                    a2_chain_root: A2ChainRootIdentityV1::new(
                        current.chain_root_activation_digest().clone(),
                    ),
                    controlling_activation: ControllingActivationIdentityV1::new(
                        current.controlling_tip_activation_digest().clone(),
                    ),
                    dependency_anchor: DependencyAnchorIdentityV1::new(
                        current.trust_anchor_id().clone(),
                    ),
                    resident: ResidentIdentityV1::new(current.resident_identity()).unwrap(),
                    resident_generation: current.resident_generation(),
                    role: current.host_role().to_owned(),
                    role_manifest: RoleManifestIdentityV1::new(role_manifest_identity.clone()),
                    role_manifest_generation: current.role_manifest_generation(),
                    domain: current.domain().to_owned(),
                    policy_version: current.policy_version(),
                    authority_cut: C2StructuralCutV1 {
                        ledger_position: authority_cut,
                        effect_position: 0,
                    },
                },
                operator_installation_nonce: "01".repeat(32),
                installation_cut: C2StructuralCutV1 {
                    ledger_position: authority_cut + 1,
                    effect_position: 0,
                },
                mode: C2InstallationModeV1::Fresh,
                restore_predecessor: None,
                geometry: C2InstalledCarrierGeometryV1 {
                    store_root_layout_version: "nq.c2.store_root_layout.v1".to_owned(),
                    lock_format_identity: "nq.c2.lock_format.v1".to_owned(),
                    append_extent_layout: APPEND_EXTENT_LAYOUT_V1.to_owned(),
                    b_role_identity: "nq.c2.bootstrap_extent.v1".to_owned(),
                    b_payload_bound: 1 << 20,
                    g_role_identity: "nq.c2.global_refusal_extent.v1".to_owned(),
                    g_payload_bound: 1 << 20,
                    global_refusal_max_entries: 64,
                    global_refusal_entry_max_bytes: 4096,
                },
                backend_identity: LINUX_POSIX_FALLOCATE_REGULAR_FILE_BACKEND_V1.to_owned(),
                qualified_backend_profile: QualifiedBackendProfileIdentityV1::new(sha256_bytes(
                    b"live-root-test/qualified-backend-profile",
                )),
                maximum_policy_generations: 16,
                maximum_key_generations: 16,
                predecessor_install_policy: None,
            },
        )
        .expect("construct exact executable bootstrap intent")
    }

    fn install_actual_c2_for_test(
        store: &mut Store,
        fixture: &RawAuthorityFixture,
        current: &ControllingActivationSnapshot,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
    ) {
        let intent = bootstrap_intent(
            current,
            &sha256_bytes(b"live-root-test/role-manifest"),
            &sha256_bytes(b"live-root-test/signer-scope-policy"),
        );
        let prepared = store
            .prepare_c2_live_bootstrap_v1(qualified, manifest, &intent, |snapshot| {
                resolve_runtime_authority_fixture(fixture, snapshot)
            })
            .expect("actual Store bootstrap-preparation root");
        let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
        let grant = sign_exact_bootstrap_grant_for_test(prepared.request(), &signing_key);
        store
            .install_c2_live_from_bootstrap_grant_v1(qualified, manifest, &grant, |snapshot| {
                resolve_runtime_authority_fixture(fixture, snapshot)
            })
            .expect("actual Store bootstrap-installation root");
    }

    fn exact_a1_request_fields_for_test(
        actor: &StoreC2SnapshotActorV1<'_>,
        authority: &StoreC2AuthoritySnapshotV1<'_>,
        evidence: &StoreResolvedGenerationCurrentEvidenceV1,
    ) -> Result<BTreeMap<String, Value>, C2LiveSignerRefusalV1> {
        let mut fields = actor.resolved_governance_exact_fields_v1(authority, evidence)?;
        let terminal = authority.resolved.terminal_operator_authority();
        for (name, value) in [
            (
                "issuer_a1_digest",
                Value::String(terminal.record_digest().as_str().to_owned()),
            ),
            (
                "issuer_a1_key_generation",
                Value::Number(terminal.key_generation().into()),
            ),
            (
                "issuer_a1_verification_key",
                Value::String(hex::encode(terminal.verification_key())),
            ),
            (
                "issuer_operator_principal",
                Value::String(terminal.operator_principal().to_owned()),
            ),
            ("issuer_domain", Value::String(terminal.domain().to_owned())),
            (
                "issuer_permitted_scope",
                Value::String(terminal.permitted_scope().to_owned()),
            ),
            (
                "issuer_policy_version",
                Value::Number(terminal.policy_version().into()),
            ),
            (
                "issuer_policy_floor",
                Value::Number(terminal.policy_floor().into()),
            ),
            (
                "issued_against_gen4_cut",
                Value::Number(terminal.cut().sequence().into()),
            ),
            (
                "issued_against_gen4_terminal_event",
                Value::String(
                    authority
                        .resolved
                        .terminal_authority_event_digest()
                        .as_str()
                        .to_owned(),
                ),
            ),
        ] {
            fields.insert(name.to_owned(), value);
        }
        Ok(fields)
    }

    fn exact_revocation_pair_for_test(
        store: &mut Store,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        fixture: &RawAuthorityFixture,
    ) -> (
        StoreIntegrityRevocationRequestV1,
        StoreIntegrityRevocationJudgmentV1,
    ) {
        store
            .with_c2_authority_snapshot(
                qualified,
                |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                |actor, authority| -> Result<_, C2LiveTransitionDriverRefusalV1> {
                    let evidence = actor.resolve_generation_current_evidence_v1()?;
                    let cut = evidence
                        .current
                        .effective_cut()
                        .checked_add(1)
                        .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
                    let frontier = identity_digest_from_bytes(evidence.frontier_identity)?;
                    let projection = digest_fields(
                        b"nq.c2.store_integrity.revocation_projection.identity.v1\0",
                        &[
                            evidence.physical_generation_identity.as_str().as_bytes(),
                            evidence.current.enrollment_id().as_bytes(),
                            evidence.current.standing_id().as_bytes(),
                            frontier.as_str().as_bytes(),
                            &cut.to_be_bytes(),
                            b"operator_withdrawal",
                        ],
                    );
                    let mut fields = exact_a1_request_fields_for_test(actor, authority, &evidence)?;
                    for (name, value) in [
                        (
                            "desired_effect_projection_identity",
                            Value::String(projection.as_str().to_owned()),
                        ),
                        ("proposed_effect_cut", Value::Number(cut.into())),
                        ("effective_cut", Value::Number(cut.into())),
                        (
                            "reason_code",
                            Value::String("operator_withdrawal".to_owned()),
                        ),
                        ("disposition", Value::String("revoked".to_owned())),
                        (
                            "revocation_projection_identity",
                            Value::String(projection.as_str().to_owned()),
                        ),
                    ] {
                        fields.insert(name.to_owned(), value);
                    }
                    Ok(sign_exact_revocation_judgment_for_test(
                        fields,
                        &SigningKey::from_bytes(&[1_u8; 32]),
                    ))
                },
            )
            .expect("derive exact Store-bound MSG-14 pair")
    }

    pub(in crate::store_generation) fn exact_restore_pair_for_test(
        store: &mut Store,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        fixture: &RawAuthorityFixture,
    ) -> (
        StoreIntegrityRestoreAuthorizationRequestV1,
        StoreIntegrityRestoreAuthorizationV1,
    ) {
        store
            .with_c2_authority_snapshot(
                qualified,
                |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                |actor, authority| -> Result<_, C2LiveTransitionDriverRefusalV1> {
                    let evidence =
                        actor.resolve_generation_current_evidence_before_governance_v1()?;
                    let cut = evidence
                        .current
                        .effective_cut()
                        .checked_add(1)
                        .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
                    let historical = evidence.durable_terminal.enrollment();
                    let historical_foundation = historical.foundation();
                    let historical_custody = historical_foundation.custody_evidence_identity();
                    let restore_declaration = sha256_bytes(b"live-root-test/restore/declaration");
                    let restore_disposition = sha256_bytes(b"live-root-test/restore/disposition");
                    let restore_proof = sha256_bytes(b"live-root-test/restore/proof");
                    let restore_transition = sha256_bytes(b"live-root-test/restore/transition");
                    let successor_preimage =
                        sha256_bytes(b"live-root-test/restore/successor-preimage");
                    let desired_projection = digest_fields(
                        b"nq.c2.test.restore.desired_projection.v1\0",
                        &[
                            evidence.current.binding_id().as_str().as_bytes(),
                            historical_foundation.identity().as_str().as_bytes(),
                            restore_transition.as_str().as_bytes(),
                            &cut.to_be_bytes(),
                        ],
                    );
                    let mut fields = exact_a1_request_fields_for_test(actor, authority, &evidence)?;
                    for (name, value) in [
                        (
                            "desired_effect_projection_identity",
                            Value::String(desired_projection.as_str().to_owned()),
                        ),
                        ("proposed_effect_cut", Value::Number(cut.into())),
                        (
                            "predecessor_physical_store_generation_identity",
                            Value::String(
                                evidence.physical_generation_identity.as_str().to_owned(),
                            ),
                        ),
                        (
                            "predecessor_generation_commitment_identity",
                            Value::String(
                                evidence
                                    .bootstrap_generation_relation
                                    .generation_commitment_identity
                                    .as_str()
                                    .to_owned(),
                            ),
                        ),
                        (
                            "predecessor_bootstrap_identity",
                            Value::String(evidence.bootstrap_identity.as_str().to_owned()),
                        ),
                        (
                            "predecessor_installation_receipt_identity",
                            Value::String(
                                evidence.installation_receipt_identity.as_str().to_owned(),
                            ),
                        ),
                        (
                            "predecessor_current_signer_binding_identity",
                            Value::String(evidence.current.binding_id().as_str().to_owned()),
                        ),
                        (
                            "restore_declaration_identity",
                            Value::String(restore_declaration.as_str().to_owned()),
                        ),
                        (
                            "restore_disposition_identity",
                            Value::String(restore_disposition.as_str().to_owned()),
                        ),
                        (
                            "restore_proof_identity",
                            Value::String(restore_proof.as_str().to_owned()),
                        ),
                        (
                            "target_restore_proposal_identity",
                            Value::String(restore_transition.as_str().to_owned()),
                        ),
                        (
                            "successor_generation_preimage_commitment",
                            Value::String(successor_preimage.as_str().to_owned()),
                        ),
                        (
                            "target_signer_proposal_identity",
                            Value::String(historical_custody.as_str().to_owned()),
                        ),
                        (
                            "target_signer_enrollment_identity",
                            Value::String(evidence.current.enrollment_id().to_owned()),
                        ),
                        (
                            "target_custody_binding_identity",
                            Value::String(historical_custody.as_str().to_owned()),
                        ),
                        ("restore_cut", Value::Number(cut.into())),
                        (
                            "disposition",
                            Value::String("restore_successor_authorized".to_owned()),
                        ),
                        ("quarantine_remains_closed", Value::Bool(true)),
                    ] {
                        fields.insert(name.to_owned(), value);
                    }
                    Ok(sign_exact_restore_authorization_for_test(
                        fields,
                        &SigningKey::from_bytes(&[1_u8; 32]),
                    ))
                },
            )
            .expect("derive exact Store-bound MSG-13 pair")
    }

    pub(in crate::store_generation) fn apply_exact_revocation_for_test(
        store: &mut Store,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        fixture: &RawAuthorityFixture,
    ) {
        let (request, judgment) = exact_revocation_pair_for_test(store, qualified, fixture);
        store
            .with_reopened_c2_generation_current_v1(
                qualified,
                manifest,
                |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                |session| -> Result<_, C2LiveTransitionDriverRefusalV1> {
                    session.apply_revocation_judgment(&request, &judgment)?;
                    Ok(())
                },
            )
            .expect("actual Store MSG-14 revocation root");
    }

    fn exact_quarantine_pair_for_live_session_for_test(
        session: &mut C2LiveWriterSessionV1<'_, '_, '_>,
        adopted_restore: &StoreAdoptedRestoreAuthorizationV1,
    ) -> Result<
        (
            StoreIntegrityQuarantineClosureRequestV1,
            StoreIntegrityQuarantineClosureJudgmentV1,
        ),
        C2LiveTransitionDriverRefusalV1,
    > {
        let actor = &mut *session.actor;
        let authority = session.current.authority_snapshot;
        let evidence = load_generation_current_evidence_before_governance_v1(
            actor
                .transaction
                .as_ref()
                .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?,
        )?;
        let authorization = adopted_restore.verified().carrier();
        let restore_identity = format!(
            "sha256:{}",
            hex::encode(adopted_restore.verified().carrier_identity().bytes())
        );
        let predecessor_generation = authorization
            .field("predecessor_physical_store_generation_identity")
            .and_then(Value::as_str)
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let restore_disposition = authorization
            .field("restore_disposition_identity")
            .and_then(Value::as_str)
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let restore_proof = authorization
            .field("restore_proof_identity")
            .and_then(Value::as_str)
            .ok_or(SignerRefusalV2::ExternalCarrierScopeMismatch)?;
        let cut = evidence
            .current
            .effective_cut()
            .checked_add(1)
            .ok_or(C2LiveSignerRefusalV1::CorrespondenceMismatch)?;
        let frontier = identity_digest_from_bytes(evidence.frontier_identity)?;
        let quarantine = digest_fields(
            b"nq.c2.restore_quarantine.identity.v1\0",
            &[
                restore_identity.as_bytes(),
                evidence.physical_generation_identity.as_str().as_bytes(),
                evidence.lineage_identity.as_str().as_bytes(),
                evidence.installation_receipt_identity.as_str().as_bytes(),
            ],
        );
        let projection = digest_fields(
            b"nq.c2.quarantine_closure_projection.identity.v1\0",
            &[
                quarantine.as_str().as_bytes(),
                frontier.as_str().as_bytes(),
                evidence.current.standing_id().as_bytes(),
                &cut.to_be_bytes(),
            ],
        );
        let mut fields = exact_a1_request_fields_for_test(actor, authority, &evidence)?;
        for (name, value) in [
            (
                "desired_effect_projection_identity",
                Value::String(projection.as_str().to_owned()),
            ),
            ("proposed_effect_cut", Value::Number(cut.into())),
            (
                "restore_authorization_identity",
                Value::String(restore_identity),
            ),
            (
                "predecessor_physical_store_generation_identity",
                Value::String(predecessor_generation.to_owned()),
            ),
            (
                "restore_disposition_identity",
                Value::String(restore_disposition.to_owned()),
            ),
            (
                "restore_proof_identity",
                Value::String(restore_proof.to_owned()),
            ),
            (
                "quarantine_identity",
                Value::String(quarantine.as_str().to_owned()),
            ),
            (
                "quarantine_state",
                Value::String("closed_to_writes".to_owned()),
            ),
            ("closure_cut", Value::Number(cut.into())),
            (
                "quarantine_closure_projection_identity",
                Value::String(projection.as_str().to_owned()),
            ),
            (
                "disposition",
                Value::String("quarantine_closure_authorized".to_owned()),
            ),
            ("estate_wide_scope", Value::Bool(false)),
        ] {
            fields.insert(name.to_owned(), value);
        }
        Ok(sign_exact_quarantine_closure_for_test(
            fields,
            &SigningKey::from_bytes(&[1_u8; 32]),
        ))
    }

    pub(in crate::store_generation) fn apply_exact_quarantine_for_test(
        store: &mut Store,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        fixture: &RawAuthorityFixture,
    ) {
        let (restore_request, restore_authorization) =
            exact_restore_pair_for_test(store, qualified, fixture);
        store
            .with_reopened_c2_generation_current_v1(
                qualified,
                manifest,
                |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                |session| -> Result<_, C2LiveTransitionDriverRefusalV1> {
                    let adopted = session
                        .adopt_restore_authorization(&restore_request, &restore_authorization)?;
                    let (request, judgment) =
                        exact_quarantine_pair_for_live_session_for_test(session, &adopted)?;
                    session.apply_quarantine_closure_judgment(&adopted, &request, &judgment)?;
                    Ok(())
                },
            )
            .expect("actual Store MSG-13 -> MSG-16 quarantine-closure root");
    }

    /// Build the exact Store-prepared/repository-signed MSG-15 pair used by
    /// production-root crash and replay specimens.  The Store still owns the
    /// preparation mutation; the returned values are inert carrier evidence,
    /// never a discontinuity-entry authority.
    pub(in crate::store_generation) fn exact_recovery_pair_for_test(
        store: &mut Store,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        manifest: &StoreIntegritySignerImplementationManifestV1,
        fixture: &RawAuthorityFixture,
    ) -> (
        StorePreparedRecoveryGrantRequestV1,
        StoreIntegrityRecoveryGrantV1,
    ) {
        let intent = C2RecoveryPreparationIntentV1::new(
            C2RecoveryPredecessorStatusV1::InactiveRevoked,
            sha256_bytes(b"live-root-test/recovery/transition"),
            sha256_bytes(b"live-root-test/recovery/challenge"),
        )
        .expect("construct exact inert recovery intent");
        let prepared = store
            .prepare_c2_live_recovery_v1(qualified, manifest, &intent, |snapshot| {
                resolve_runtime_authority_fixture(fixture, snapshot)
            })
            .expect("actual Store MSG-15 recovery preparation root");
        let grant = sign_exact_recovery_grant_for_test(
            prepared.request(),
            &SigningKey::from_bytes(&[1_u8; 32]),
        );
        (prepared, grant)
    }

    #[derive(Debug)]
    struct FoundationalAdoptionRowForTest {
        sequence: u64,
        adoption_identity: String,
        foundation_identity: String,
        lineage: String,
        public_key: Vec<u8>,
        key_generation: u64,
        custody_identity: Vec<u8>,
        lineage_reference_identity: String,
    }

    fn foundational_adoption_rows_for_test(
        store: &mut Store,
        qualified: &StoreC2QualifiedRuntimeEvidenceV1,
        fixture: &RawAuthorityFixture,
    ) -> Vec<FoundationalAdoptionRowForTest> {
        store
            .with_c2_authority_snapshot(
                qualified,
                |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                |actor, _authority| -> Result<_, C2LiveTransitionDriverRefusalV1> {
                    let transaction = actor
                        .transaction
                        .as_ref()
                        .ok_or(C2LiveSignerRefusalV1::StoreSnapshotMismatch)?;
                    let mut statement = transaction
                        .prepare(
                            "SELECT adoption.adoption_sequence,
                                    adoption.adoption_identity,
                                    adoption.foundation_identity,
                                    adoption.lineage,
                                    foundation.public_key,
                                    foundation.key_generation,
                                    foundation.custody_evidence_identity,
                                    json_extract(
                                        CAST(adoption.adoption_canonical_bytes AS TEXT),
                                        '$.lineage_reference_identity'
                                    )
                             FROM c2_foundational_enrollment_adoptions AS adoption
                             JOIN c2_signer_foundations AS foundation
                               ON foundation.foundation_identity = adoption.foundation_identity
                             ORDER BY adoption.adoption_sequence",
                        )
                        .map_err(StoreError::from)?;
                    let rows = statement
                        .query_map([], |row| {
                            Ok(FoundationalAdoptionRowForTest {
                                sequence: row.get(0)?,
                                adoption_identity: row.get(1)?,
                                foundation_identity: row.get(2)?,
                                lineage: row.get(3)?,
                                public_key: row.get(4)?,
                                key_generation: row.get(5)?,
                                custody_identity: row.get(6)?,
                                lineage_reference_identity: row.get(7)?,
                            })
                        })
                        .map_err(StoreError::from)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(StoreError::from)?;
                    Ok(rows)
                },
            )
            .expect("inspect durable foundational adoption rows")
    }

    #[test]
    fn actual_store_roots_bootstrap_and_reopen_complete_generation_current() {
        let store_directory = tempdir().unwrap();
        let custody_directory = tempdir().unwrap();
        fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();

        with_test_production_custody_root_v1(custody_directory.path(), || {
            let database = store_directory.path().join(super::super::C2_SQLITE_FILE_V1);
            let mut store = Store::initialize_runtime_authority_candidate(&database).unwrap();
            let fixture = RawAuthorityFixture::fresh_genesis();
            establish_runtime_authority_fixture(&mut store, &fixture).unwrap();
            let current = resolve_for_restart(
                &fixture.custody(),
                &fixture.presented_set(),
                None,
                &fixture.restart_expectations(),
            )
            .unwrap();
            let manifest = executable_manifest();
            let measured_artifact = measure_current_runtime_artifact().unwrap();
            let qualified = StoreC2QualifiedRuntimeEvidenceV1::for_test(
                sha256_bytes(b"live-root-test/candidate"),
                sha256_bytes(b"live-root-test/source-tree"),
                measured_artifact,
                manifest.manifest_identity().clone(),
            );
            let intent = bootstrap_intent(
                &current,
                &sha256_bytes(b"live-root-test/role-manifest"),
                &sha256_bytes(b"live-root-test/signer-scope-policy"),
            );

            let prepared = store
                .prepare_c2_live_bootstrap_v1(&qualified, &manifest, &intent, |snapshot| {
                    resolve_runtime_authority_fixture(&fixture, snapshot)
                })
                .expect("actual Store bootstrap-preparation root");
            let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
            let grant = sign_exact_bootstrap_grant_for_test(prepared.request(), &signing_key);
            store
                .install_c2_live_from_bootstrap_grant_v1(
                    &qualified,
                    &manifest,
                    &grant,
                    |snapshot| resolve_runtime_authority_fixture(&fixture, snapshot),
                )
                .expect("actual Store bootstrap-installation root");

            let a_to_b = C2HealthySuccessorIntentV1::new(
                sha256_bytes(b"live-root-test/transition/a-to-b"),
                sha256_bytes(b"live-root-test/challenge/b"),
                10_000,
            )
            .expect("construct inert A-to-B intent");
            let b_binding = store
                .rotate_c2_live_healthy_successor_v1(&qualified, &manifest, &a_to_b, |snapshot| {
                    resolve_runtime_authority_fixture(&fixture, snapshot)
                })
                .expect("actual Store A-to-B healthy successor root");

            let b_to_c = C2HealthySuccessorIntentV1::new(
                sha256_bytes(b"live-root-test/transition/b-to-c"),
                sha256_bytes(b"live-root-test/challenge/c"),
                20_000,
            )
            .expect("construct inert B-to-C intent");
            let c_binding = store
                .rotate_c2_live_healthy_successor_v1(&qualified, &manifest, &b_to_c, |snapshot| {
                    resolve_runtime_authority_fixture(&fixture, snapshot)
                })
                .expect("actual Store B-to-C healthy successor root");
            assert_ne!(
                b_binding, c_binding,
                "a second legal rotation must create a new terminal binding"
            );
            drop(store);

            let mut reopened = Store::open(&database).expect("reopen complete C2 Store");
            reopened
                .with_reopened_c2_generation_current_v1(
                    &qualified,
                    &manifest,
                    |snapshot| resolve_runtime_authority_fixture(&fixture, snapshot),
                    |_session| Ok::<_, C2LiveReopenRefusalV1>(()),
                )
                .expect("actual Store current-generation reopen root");
        });
    }

    #[test]
    fn actual_store_recovery_creates_new_foundation_and_reopens() {
        let store_directory = tempdir().unwrap();
        let custody_directory = tempdir().unwrap();
        fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();

        with_test_production_custody_root_v1(custody_directory.path(), || {
            let database = store_directory.path().join(super::super::C2_SQLITE_FILE_V1);
            let mut store = Store::initialize_runtime_authority_candidate(&database).unwrap();
            let fixture = RawAuthorityFixture::fresh_genesis();
            establish_runtime_authority_fixture(&mut store, &fixture).unwrap();
            let current = resolve_for_restart(
                &fixture.custody(),
                &fixture.presented_set(),
                None,
                &fixture.restart_expectations(),
            )
            .unwrap();
            let manifest = executable_manifest();
            let qualified = StoreC2QualifiedRuntimeEvidenceV1::for_test(
                sha256_bytes(b"live-root-test/recovery/candidate"),
                sha256_bytes(b"live-root-test/recovery/source-tree"),
                measure_current_runtime_artifact().unwrap(),
                manifest.manifest_identity().clone(),
            );
            install_actual_c2_for_test(&mut store, &fixture, &current, &manifest, &qualified);
            let initial = foundational_adoption_rows_for_test(&mut store, &qualified, &fixture);
            assert_eq!(initial.len(), 1);
            assert_eq!(initial[0].sequence, 1);
            assert_eq!(initial[0].lineage, "initialExternal");

            apply_exact_revocation_for_test(&mut store, &qualified, &manifest, &fixture);
            let (prepared, grant) =
                exact_recovery_pair_for_test(&mut store, &qualified, &manifest, &fixture);
            store
                .recover_c2_live_new_foundation_v1(
                    &qualified,
                    &manifest,
                    prepared.request(),
                    &grant,
                    |snapshot| resolve_runtime_authority_fixture(&fixture, snapshot),
                )
                .expect("actual Store MSG-15 recovery completion root");

            let recovered = foundational_adoption_rows_for_test(&mut store, &qualified, &fixture);
            assert_eq!(recovered.len(), 2);
            assert_eq!(recovered[1].sequence, 2);
            assert_eq!(recovered[1].lineage, "recoveryNewFoundation");
            assert_ne!(
                recovered[0].adoption_identity, recovered[1].adoption_identity,
                "adoption event is new"
            );
            assert_ne!(
                recovered[0].foundation_identity, recovered[1].foundation_identity,
                "stable foundation is new"
            );
            assert_ne!(recovered[0].public_key, recovered[1].public_key);
            assert_ne!(recovered[0].key_generation, recovered[1].key_generation);
            assert_ne!(recovered[0].custody_identity, recovered[1].custody_identity);
            assert_eq!(
                recovered[1].lineage_reference_identity, recovered[0].adoption_identity,
                "recovery retains its displaced predecessor only as lineage provenance"
            );
            drop(store);

            let mut reopened = Store::open(&database).expect("reopen recovered C2 Store");
            reopened
                .with_reopened_c2_generation_current_v1(
                    &qualified,
                    &manifest,
                    |snapshot| resolve_runtime_authority_fixture(&fixture, snapshot),
                    |_session| Ok::<_, C2LiveReopenRefusalV1>(()),
                )
                .expect("reopen complete recovered GenerationCurrent");
        });
    }

    #[test]
    fn actual_store_restore_readopts_same_foundation_with_new_adoption_and_reopens() {
        let store_directory = tempdir().unwrap();
        let custody_directory = tempdir().unwrap();
        fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();

        with_test_production_custody_root_v1(custody_directory.path(), || {
            let database = store_directory.path().join(super::super::C2_SQLITE_FILE_V1);
            let mut store = Store::initialize_runtime_authority_candidate(&database).unwrap();
            let fixture = RawAuthorityFixture::fresh_genesis();
            establish_runtime_authority_fixture(&mut store, &fixture).unwrap();
            let current = resolve_for_restart(
                &fixture.custody(),
                &fixture.presented_set(),
                None,
                &fixture.restart_expectations(),
            )
            .unwrap();
            let manifest = executable_manifest();
            let qualified = StoreC2QualifiedRuntimeEvidenceV1::for_test(
                sha256_bytes(b"live-root-test/restore/candidate"),
                sha256_bytes(b"live-root-test/restore/source-tree"),
                measure_current_runtime_artifact().unwrap(),
                manifest.manifest_identity().clone(),
            );
            install_actual_c2_for_test(&mut store, &fixture, &current, &manifest, &qualified);
            let initial = foundational_adoption_rows_for_test(&mut store, &qualified, &fixture);
            assert_eq!(initial.len(), 1);
            assert_eq!(initial[0].lineage, "initialExternal");

            apply_exact_revocation_for_test(&mut store, &qualified, &manifest, &fixture);
            let (request, authorization) =
                exact_restore_pair_for_test(&mut store, &qualified, &fixture);
            store
                .restore_c2_live_historical_foundation_v1(
                    &qualified,
                    &manifest,
                    &request,
                    &authorization,
                    |snapshot| resolve_runtime_authority_fixture(&fixture, snapshot),
                )
                .expect("actual Store MSG-13 restore completion root");

            let restored = foundational_adoption_rows_for_test(&mut store, &qualified, &fixture);
            assert_eq!(restored.len(), 2);
            assert_eq!(restored[1].lineage, "restoreHistorical");
            assert_ne!(restored[0].adoption_identity, restored[1].adoption_identity);
            assert_eq!(
                restored[0].foundation_identity,
                restored[1].foundation_identity
            );
            assert_eq!(restored[0].public_key, restored[1].public_key);
            assert_eq!(restored[0].key_generation, restored[1].key_generation);
            assert_eq!(restored[0].custody_identity, restored[1].custody_identity);
            assert_eq!(
                restored[1].lineage_reference_identity, restored[0].foundation_identity,
                "restore lineage names the exact stable historical foundation"
            );
            drop(store);

            let mut reopened = Store::open(&database).expect("reopen restored C2 Store");
            reopened
                .with_reopened_c2_generation_current_v1(
                    &qualified,
                    &manifest,
                    |snapshot| resolve_runtime_authority_fixture(&fixture, snapshot),
                    |_session| Ok::<_, C2LiveReopenRefusalV1>(()),
                )
                .expect("reopen complete restored GenerationCurrent");
        });
    }

    #[test]
    fn discontinuity_cut_schedule_separates_adoption_from_acceptance() {
        assert_eq!(
            discontinuity_cut_schedule_v1(41),
            Some((42, 43, 44, 45, 46))
        );
        assert_eq!(
            discontinuity_cut_schedule_v1(u64::MAX),
            None,
            "overflow must refuse rather than collapse lifecycle cuts"
        );
    }

    #[test]
    fn recovery_status_matches_only_the_store_verified_condition() {
        let unavailable = StoreVerifiedDiscontinuityConditionV1::OrdinaryContinuityUnavailable;
        let revoked = StoreVerifiedDiscontinuityConditionV1::GovernedCurrentSignerRevocation {
            effect_receipt_identity: sha256_bytes(b"exact-revocation-effect"),
        };

        assert!(recovery_status_matches_discontinuity_condition_v1(
            &unavailable,
            C2RecoveryPredecessorStatusV1::ActiveLost,
        ));
        assert!(!recovery_status_matches_discontinuity_condition_v1(
            &unavailable,
            C2RecoveryPredecessorStatusV1::InactiveRevoked,
        ));
        assert!(recovery_status_matches_discontinuity_condition_v1(
            &revoked,
            C2RecoveryPredecessorStatusV1::InactiveRevoked,
        ));
        assert!(!recovery_status_matches_discontinuity_condition_v1(
            &revoked,
            C2RecoveryPredecessorStatusV1::ActiveLost,
        ));
    }

    #[test]
    fn discontinuity_condition_identity_is_route_and_condition_separated() {
        let binding = sha256_bytes(b"current-binding");
        let binding_bytes: [u8; 32] = binding
            .as_str()
            .strip_prefix("sha256:")
            .and_then(|hex| hex::decode(hex).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .expect("digest bytes");
        let unavailable = StoreVerifiedDiscontinuityConditionV1::OrdinaryContinuityUnavailable;
        let revoked = StoreVerifiedDiscontinuityConditionV1::GovernedCurrentSignerRevocation {
            effect_receipt_identity: sha256_bytes(b"exact-revocation-effect"),
        };

        let restore = discontinuity_condition_identity_v1(
            C2LiveFoundationalLineageV1::RestoreHistorical,
            &unavailable,
            binding_bytes,
        )
        .expect("restore is a discontinuity route");
        let recovery = discontinuity_condition_identity_v1(
            C2LiveFoundationalLineageV1::RecoveryNewFoundation,
            &unavailable,
            binding_bytes,
        )
        .expect("recovery is a discontinuity route");
        let revoked_recovery = discontinuity_condition_identity_v1(
            C2LiveFoundationalLineageV1::RecoveryNewFoundation,
            &revoked,
            binding_bytes,
        )
        .expect("recovery is a discontinuity route");

        assert_ne!(
            restore, recovery,
            "MSG-13 and MSG-15 cannot share authority"
        );
        assert_ne!(
            recovery, revoked_recovery,
            "the exact Store condition is bound"
        );
        assert!(
            discontinuity_condition_identity_v1(
                C2LiveFoundationalLineageV1::OrdinarySuccessorContinuity,
                &unavailable,
                binding_bytes,
            )
            .is_none()
        );
    }

    #[test]
    fn recovery_request_identity_is_deterministic_and_content_sensitive() {
        let body = br#"{"predecessor_status":"active_lost"}"#;
        assert_eq!(
            recovery_request_identity_v1(body),
            recovery_request_identity_v1(body)
        );
        assert_ne!(
            recovery_request_identity_v1(body),
            recovery_request_identity_v1(br#"{"predecessor_status":"inactive_revoked"}"#)
        );
    }

    #[test]
    fn recovery_preparation_intent_keeps_transition_and_pop_distinct() {
        let shared = sha256_bytes(b"shared");
        assert!(matches!(
            C2RecoveryPreparationIntentV1::new(
                C2RecoveryPredecessorStatusV1::ActiveLost,
                shared.clone(),
                shared,
            ),
            Err(C2LiveSignerRefusalV1::CorrespondenceMismatch)
        ));
        assert!(
            C2RecoveryPreparationIntentV1::new(
                C2RecoveryPredecessorStatusV1::ActiveLost,
                sha256_bytes(b"transition"),
                sha256_bytes(b"pop-challenge"),
            )
            .is_ok()
        );
    }

    #[test]
    fn measured_artifact_is_checked_against_external_verified_evidence() {
        let measured = measure_current_runtime_artifact().unwrap();
        let matching = StoreC2QualifiedRuntimeEvidenceV1::for_test(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"tree"),
            measured.clone(),
            sha256_bytes(b"manifest"),
        );
        matching
            .verify_measured_runtime_artifact(&measured)
            .unwrap();

        let substituted = StoreC2QualifiedRuntimeEvidenceV1::for_test(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"tree"),
            sha256_bytes(b"another artifact"),
            sha256_bytes(b"manifest"),
        );
        assert!(matches!(
            substituted.verify_measured_runtime_artifact(&measured),
            Err(C2LiveSignerRefusalV1::RuntimeArtifactMismatch)
        ));
    }

    #[test]
    fn candidate_verifier_result_from_a_prior_process_cannot_be_reused() {
        let measured = measure_current_runtime_artifact().unwrap();
        let mut evidence = StoreC2QualifiedRuntimeEvidenceV1::for_test(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"tree"),
            measured.clone(),
            sha256_bytes(b"manifest"),
        );
        evidence.verification_process_id = std::process::id().wrapping_add(1);
        assert!(matches!(
            evidence.verify_measured_runtime_artifact(&measured),
            Err(C2LiveSignerRefusalV1::PriorProcessAuthority)
        ));
    }

    #[test]
    fn test_evidence_is_inert_and_process_identity_is_stable_in_process() {
        let artifact = measure_current_runtime_artifact().unwrap();
        let evidence = StoreC2QualifiedRuntimeEvidenceV1::for_test(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"tree"),
            artifact,
            sha256_bytes(b"manifest"),
        );
        assert_ne!(
            evidence.qualified_candidate_identity,
            evidence.source_tree_identity
        );
        assert_eq!(
            current_process_identity().unwrap(),
            current_process_identity().unwrap()
        );
    }

    #[test]
    fn qualification_record_substitution_changes_admission_binding() {
        let artifact = measure_current_runtime_artifact().unwrap();
        let record = |qualification: &[u8]| {
            StoreC2QualifiedRuntimeEvidenceV1::from_verified_external_candidate(
                VerifiedC2ExternalCandidateRuntimeRecordV1 {
                    qualified_candidate_identity: sha256_bytes(b"candidate"),
                    source_tree_identity: sha256_bytes(b"tree"),
                    expected_runtime_artifact_identity: artifact.clone(),
                    qualified_manifest_identity: sha256_bytes(b"manifest"),
                    qualification_evidence_identity: sha256_bytes(qualification),
                    candidate_certificate_identity: sha256_bytes(b"certificate"),
                    qualification_trust_root_identity: sha256_bytes(b"qualification-root"),
                    verification_process_id: std::process::id(),
                },
            )
        };
        let first = record(b"qualification-evidence-a");
        let substituted = record(b"qualification-evidence-b");
        assert_ne!(
            first.qualification_binding_identity(),
            substituted.qualification_binding_identity()
        );
    }

    #[test]
    fn install_policy_enrollment_is_foundational_not_signer_acceptance() {
        let foundational = sha256_bytes(b"foundational enrollment");
        let signer_acceptance = sha256_bytes(b"later signer acceptance");
        assert!(installation_policy_binds_foundational_layer_v1(
            &foundational,
            &foundational,
            &signer_acceptance,
        ));
        assert!(!installation_policy_binds_foundational_layer_v1(
            &signer_acceptance,
            &foundational,
            &signer_acceptance,
        ));
        assert!(!installation_policy_binds_foundational_layer_v1(
            &foundational,
            &foundational,
            &foundational,
        ));
    }

    #[test]
    fn msg01_policy_authorization_cut_must_precede_later_signer_acceptance() {
        assert!(installation_authorization_precedes_acceptance_v1(
            20, 20, 24
        ));
        assert!(!installation_authorization_precedes_acceptance_v1(
            24, 24, 20
        ));
        assert!(!installation_authorization_precedes_acceptance_v1(
            20, 21, 24
        ));
        assert!(!installation_authorization_precedes_acceptance_v1(
            20, 20, 20
        ));
    }

    #[test]
    fn only_msg08_can_advance_a_complete_current_binding_without_new_phase_resolution() {
        assert!(append_route_preserves_generation_current_v1(
            "msg08_global_refusal"
        ));
        for route in [
            "msg02_initial_pop",
            "msg03_physical_generation_bootstrap",
            "msg05_active_policy_continuity",
            "msg06_normal_rotation_continuity",
            "msg07_successor_pop",
            "msg09_installation_intent",
            "msg10_installation_receipt",
            "msg11_policy_transition_intent",
            "msg12_receipt_current",
            "msg12_receipt_pending",
            "unknown_future_route",
        ] {
            assert!(
                !append_route_preserves_generation_current_v1(route),
                "{route} was incorrectly allowed to preserve GenerationCurrent"
            );
        }
    }

    #[test]
    fn sql_absence_and_no_fixed_footprint_is_generation_absence() {
        let directory = tempdir().unwrap();
        let path = directory.path().join(super::super::C2_SQLITE_FILE_V1);
        let mut store = Store::initialize_unqualified_storage(&path).unwrap();
        let root = File::open(directory.path()).unwrap();
        let transaction = store.connection.transaction().unwrap();
        assert!(matches!(
            resolve_generation_current_from_retained_basis_v1(&transaction, &root),
            Err(C2LiveSignerRefusalV1::GenerationCurrentAbsent)
        ));
    }

    #[test]
    fn every_nonempty_fixed_footprint_with_empty_sql_is_incomplete() {
        let fixed = [
            super::super::C2_LOCK_FILE_V1,
            super::super::C2_BOOTSTRAP_EXTENT_V1,
            super::super::C2_GLOBAL_REFUSAL_EXTENT_V1,
        ];
        for mask in 1_u8..8 {
            let directory = tempdir().unwrap();
            let path = directory.path().join(super::super::C2_SQLITE_FILE_V1);
            let mut store = Store::initialize_unqualified_storage(&path).unwrap();
            for (index, name) in fixed.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    File::create(directory.path().join(name)).unwrap();
                }
            }
            let root = File::open(directory.path()).unwrap();
            let transaction = store.connection.transaction().unwrap();
            assert!(
                matches!(
                    resolve_generation_current_from_retained_basis_v1(&transaction, &root),
                    Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)
                ),
                "fixed C2 subset mask {mask:03b} was misclassified"
            );
        }
    }

    #[test]
    fn malformed_or_symlink_fixed_name_with_empty_sql_is_incomplete() {
        for malformed in ["wrong_type", "symlink"] {
            let directory = tempdir().unwrap();
            let path = directory.path().join(super::super::C2_SQLITE_FILE_V1);
            let mut store = Store::initialize_unqualified_storage(&path).unwrap();
            let lock_path = directory.path().join(super::super::C2_LOCK_FILE_V1);
            if malformed == "wrong_type" {
                std::fs::create_dir(&lock_path).unwrap();
            } else {
                std::os::unix::fs::symlink("missing-target", &lock_path).unwrap();
            }
            let root = File::open(directory.path()).unwrap();
            let transaction = store.connection.transaction().unwrap();
            assert!(
                matches!(
                    resolve_generation_current_from_retained_basis_v1(&transaction, &root),
                    Err(C2LiveSignerRefusalV1::GenerationCurrentIncomplete)
                ),
                "malformed fixed entry {malformed} was misclassified"
            );
        }
    }
}
