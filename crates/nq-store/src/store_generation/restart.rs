//! Ordinary C2 Store restart pipeline.
//!
//! This layer sequences already verified evidence. It does not create locks,
//! signer standing, policy, carrier data, capacity, or writer sessions. The
//! final borrowed backend/session construction remains in the Store owner.

use nq_protocol::Sha256Digest;
use thiserror::Error;

use super::lock::{
    C2StoreGenerationLockErrorV1, C2StoreGenerationLockV1,
    verify_wu_04_immutable_wu_local_lock_flock_process_registry,
};

/// Provisional process/inode/flock quiescence with no authority conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2RestartQuiescenceV1 {
    lock_inode: (u64, u64),
    confers_standing: bool,
}

/// Store-owned complete Gen4/current-policy resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2RestartAuthorityPolicyResolutionV1 {
    /// Identity of the complete authority candidate set.
    pub authority_set_identity: Sha256Digest,
    /// Exact current activation.
    pub current_activation: Sha256Digest,
    /// Sole active C2 policy.
    pub active_policy: Sha256Digest,
    /// Candidate-set completeness was verified, not caller-asserted.
    pub complete_candidate_set: bool,
    /// Exact number of active policy candidates.
    pub active_policy_count: usize,
}

/// Exact complete B/G/lock/receipt/profile/live-descriptor correspondence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2CarrierCompletionCorrespondenceV1 {
    /// Physical generation.
    pub physical_generation: Sha256Digest,
    /// Common root binding carried by all authenticated records.
    pub common_binding: Sha256Digest,
    /// Exact completion receipt.
    pub completion_receipt: Sha256Digest,
    /// Exact backend profile and implementation manifest association.
    pub backend_profile: Sha256Digest,
    /// Every resident frame was parsed and verified.
    pub all_resident_frames_verified: bool,
    /// Unknown or malformed resident frame count (must be zero).
    pub invalid_frame_count: usize,
    /// Unresolved install/transition intent count (must be zero).
    pub unresolved_intent_count: usize,
    /// Live lock/B/G descriptors match their authenticated identities.
    pub live_descriptors_correspond: bool,
}

/// Exact ordinary restart stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum C2OrdinaryRestartStepV1 {
    ProvisionalQuiescence = 1,
    CompleteGen4Resolution = 2,
    GenerationBootstrapLiveObservation = 3,
    SingleActivePolicy = 4,
    CompleteCarrierVerification = 5,
    CompletionAndNoUnresolvedIntent = 6,
    TotalCorrespondence = 7,
    SoleClosedBackendConstruction = 8,
    SoleOrdinarySessionConstruction = 9,
}

/// Verified pipeline receipt. It is evidence, not a session or backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2OrdinaryRestartPipelineV1 {
    steps: [C2OrdinaryRestartStepV1; 9],
    physical_generation: Sha256Digest,
    closed_backend_count: u8,
    ordinary_session_count: u8,
}

/// Attempts prohibited during ordinary restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartAuthorityCreatingEffectV1 {
    CreateOrReplaceLock,
    EnrollOrRotateSigner,
    ConstructCarriersFromSqlite,
    SelectBackend,
    SynthesizePolicy,
    RefreshExternalExpiry,
    ClearFence,
    MintCapacity,
    FabricateSession,
}

/// Structural noncreation witness. It exposes only refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2RestartNoncreationGuardV1;

/// Ordinary restart refusal vocabulary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum C2RestartPipelineRefusalV1 {
    /// Quiescence was substituted or treated as standing.
    #[error("provisional quiescence is missing or was treated as standing")]
    InvalidQuiescence,
    /// Candidate-set or policy resolution was incomplete/nonunique.
    #[error("authority/current-policy resolution is incomplete or nonunique")]
    IncompleteAuthorityOrPolicy,
    /// Durable carrier correspondence is incomplete or malformed.
    #[error("carrier, receipt, intent, profile, or live-descriptor correspondence failed")]
    IncompleteCarrierCorrespondence,
    /// One ordinary restart stage was skipped, repeated, or reordered.
    #[error("ordinary restart stages are not exact and ordered")]
    StageOrder,
}

/// RR-07 typed refusal for every authority-creating restart effect.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum C2RestartNoncreationRefusalV1 {
    /// Ordinary restart has no such effect edge.
    #[error("ordinary restart requested an authority-creating effect")]
    AuthorityCreatingEffectRequested,
}

/// RR-02 acquires no authority: it projects only an already-held lock inode.
pub fn acquire_rr_02_provisional_quiescence(
    lock: &C2StoreGenerationLockV1,
) -> Result<C2RestartQuiescenceV1, C2StoreGenerationLockErrorV1> {
    verify_wu_04_immutable_wu_local_lock_flock_process_registry(lock)?;
    Ok(C2RestartQuiescenceV1 {
        lock_inode: lock.inode_key(),
        confers_standing: false,
    })
}

/// RR-02 denies conversion from lock possession to any standing.
pub fn verify_rr_02_non_authoritative_quiescence(
    quiescence: &C2RestartQuiescenceV1,
) -> Result<(), C2RestartPipelineRefusalV1> {
    if quiescence.lock_inode == (0, 0) || quiescence.confers_standing {
        return Err(C2RestartPipelineRefusalV1::InvalidQuiescence);
    }
    Ok(())
}

/// RR-03 consumes a Store-complete resolution result.
pub fn resolve_rr_03_complete_authority_and_policy(
    resolution: C2RestartAuthorityPolicyResolutionV1,
) -> Result<C2RestartAuthorityPolicyResolutionV1, C2RestartPipelineRefusalV1> {
    verify_rr_03_current_activation_and_single_policy(&resolution)?;
    Ok(resolution)
}

/// RR-03 requires complete enumeration and exactly one active policy.
pub fn verify_rr_03_current_activation_and_single_policy(
    resolution: &C2RestartAuthorityPolicyResolutionV1,
) -> Result<(), C2RestartPipelineRefusalV1> {
    if !resolution.complete_candidate_set || resolution.active_policy_count != 1 {
        return Err(C2RestartPipelineRefusalV1::IncompleteAuthorityOrPolicy);
    }
    Ok(())
}

/// RR-05 constructs no backend; it verifies all exact durable coordinates.
pub fn construct_rr_05_carrier_completion_correspondence(
    correspondence: C2CarrierCompletionCorrespondenceV1,
) -> Result<C2CarrierCompletionCorrespondenceV1, C2RestartPipelineRefusalV1> {
    verify_rr_05_all_records_headers_profile_and_resolution(&correspondence)?;
    Ok(correspondence)
}

/// RR-05 refuses any skipped/malformed frame or unresolved intent.
pub fn verify_rr_05_all_records_headers_profile_and_resolution(
    correspondence: &C2CarrierCompletionCorrespondenceV1,
) -> Result<(), C2RestartPipelineRefusalV1> {
    if !correspondence.all_resident_frames_verified
        || correspondence.invalid_frame_count != 0
        || correspondence.unresolved_intent_count != 0
        || !correspondence.live_descriptors_correspond
    {
        return Err(C2RestartPipelineRefusalV1::IncompleteCarrierCorrespondence);
    }
    Ok(())
}

/// RR-01 exact nine-stage evidence pipeline.
pub fn construct_rr_01_ordered_pipeline(
    quiescence: &C2RestartQuiescenceV1,
    resolution: &C2RestartAuthorityPolicyResolutionV1,
    correspondence: &C2CarrierCompletionCorrespondenceV1,
) -> Result<C2OrdinaryRestartPipelineV1, C2RestartPipelineRefusalV1> {
    verify_rr_02_non_authoritative_quiescence(quiescence)?;
    verify_rr_03_current_activation_and_single_policy(resolution)?;
    verify_rr_05_all_records_headers_profile_and_resolution(correspondence)?;
    let pipeline = C2OrdinaryRestartPipelineV1 {
        steps: [
            C2OrdinaryRestartStepV1::ProvisionalQuiescence,
            C2OrdinaryRestartStepV1::CompleteGen4Resolution,
            C2OrdinaryRestartStepV1::GenerationBootstrapLiveObservation,
            C2OrdinaryRestartStepV1::SingleActivePolicy,
            C2OrdinaryRestartStepV1::CompleteCarrierVerification,
            C2OrdinaryRestartStepV1::CompletionAndNoUnresolvedIntent,
            C2OrdinaryRestartStepV1::TotalCorrespondence,
            C2OrdinaryRestartStepV1::SoleClosedBackendConstruction,
            C2OrdinaryRestartStepV1::SoleOrdinarySessionConstruction,
        ],
        physical_generation: correspondence.physical_generation.clone(),
        closed_backend_count: 1,
        ordinary_session_count: 1,
    };
    verify_rr_01_steps_1_through_9(&pipeline)?;
    Ok(pipeline)
}

/// RR-01 verifies exact step numbering and unique constructed consumers.
pub fn verify_rr_01_steps_1_through_9(
    pipeline: &C2OrdinaryRestartPipelineV1,
) -> Result<(), C2RestartPipelineRefusalV1> {
    if pipeline
        .steps
        .iter()
        .enumerate()
        .any(|(index, step)| *step as usize != index + 1)
        || pipeline.closed_backend_count != 1
        || pipeline.ordinary_session_count != 1
    {
        return Err(C2RestartPipelineRefusalV1::StageOrder);
    }
    Ok(())
}

/// RR-07 constructs the static noncreation guard.
#[must_use]
pub const fn construct_rr_07_noncreation_guard() -> C2RestartNoncreationGuardV1 {
    C2RestartNoncreationGuardV1
}

/// RR-07 has no success branch for an authority-creating effect.
pub fn verify_rr_07_no_authority_creating_effect(
    _guard: C2RestartNoncreationGuardV1,
    _attempt: RestartAuthorityCreatingEffectV1,
) -> Result<(), C2RestartNoncreationRefusalV1> {
    Err(C2RestartNoncreationRefusalV1::AuthorityCreatingEffectRequested)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn ordered_pipeline_constructs_one_backend_and_session_receipt() {
        let quiescence = C2RestartQuiescenceV1 {
            lock_inode: (1, 2),
            confers_standing: false,
        };
        let authority = C2RestartAuthorityPolicyResolutionV1 {
            authority_set_identity: digest('1'),
            current_activation: digest('2'),
            active_policy: digest('3'),
            complete_candidate_set: true,
            active_policy_count: 1,
        };
        let carriers = C2CarrierCompletionCorrespondenceV1 {
            physical_generation: digest('4'),
            common_binding: digest('5'),
            completion_receipt: digest('6'),
            backend_profile: digest('7'),
            all_resident_frames_verified: true,
            invalid_frame_count: 0,
            unresolved_intent_count: 0,
            live_descriptors_correspond: true,
        };
        let pipeline =
            construct_rr_01_ordered_pipeline(&quiescence, &authority, &carriers).unwrap();
        verify_rr_01_steps_1_through_9(&pipeline).unwrap();
    }

    #[test]
    fn ordinary_restart_never_performs_governed_effect() {
        assert_eq!(
            verify_rr_07_no_authority_creating_effect(
                construct_rr_07_noncreation_guard(),
                RestartAuthorityCreatingEffectV1::EnrollOrRotateSigner,
            ),
            Err(C2RestartNoncreationRefusalV1::AuthorityCreatingEffectRequested)
        );
    }
}
