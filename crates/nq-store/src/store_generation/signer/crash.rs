//! Exact, finite crash-cut evidence for the Store-integrity signer.
//!
//! This module models the sixteen reachable signer crash cuts assigned to
//! `crash.rs` by matrix V2. `SC-06` is deliberately absent as a runtime
//! record: its signature-before-transaction edge is a compile-time and
//! call-graph exclusion. The process inventory nevertheless counts `SC-06`
//! so the closed `SC-01` through `SC-17` corpus cannot silently lose it.
//!
//! These records are observations and typed outcomes only. They cannot yield
//! signer standing, currentness, custody, a signer capability, or any other
//! authority. In particular, the finite corpus must never be interpreted as
//! universal crash, filesystem, kernel, scheduling, or power-loss safety.

use serde::Serialize;
use thiserror::Error;

use super::result::{
    CrashCutResultV2, RestartRefusalV2, RestartResultV2, SignerCrashClaimBoundaryV1,
};

/// One nonzero canonical SHA-256 identity carried by a crash observation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub(crate) struct CrashDigestV1(String);

impl CrashDigestV1 {
    /// Parse the sole digest representation admitted by the crash schemas.
    pub(crate) fn parse(value: impl Into<String>) -> Result<Self, CrashIdentityRefusalV1> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(CrashIdentityRefusalV1::MalformedDigest);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || hex.bytes().all(|byte| byte == b'0')
        {
            return Err(CrashIdentityRefusalV1::MalformedDigest);
        }
        Ok(Self(value))
    }
}

/// Exact Store occurrence token used by the finite crash evidence schemas.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub(crate) struct CrashOccurrenceIdV1(String);

impl CrashOccurrenceIdV1 {
    /// Validate the closed lexical form accepted by the version-one schemas.
    pub(crate) fn parse(value: impl Into<String>) -> Result<Self, CrashIdentityRefusalV1> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 256
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
            })
        {
            return Err(CrashIdentityRefusalV1::MalformedOccurrence);
        }
        Ok(Self(value))
    }
}

/// Refusal to admit an identity into a crash-cut record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum CrashIdentityRefusalV1 {
    #[error("crash evidence digest is not a nonzero canonical sha256 identity")]
    MalformedDigest,
    #[error("crash evidence occurrence identity is malformed")]
    MalformedOccurrence,
}

/// Coordinates shared by every reachable signer crash-cut observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SignerCrashCutCoordinatesV1 {
    snapshot_identity: CrashDigestV1,
    occurrence_id: CrashOccurrenceIdV1,
    physical_store_generation_identity: CrashDigestV1,
    signer_lifecycle_root_identity: CrashDigestV1,
    durable_state_identity: CrashDigestV1,
}

impl SignerCrashCutCoordinatesV1 {
    pub(crate) fn new(
        snapshot_identity: CrashDigestV1,
        occurrence_id: CrashOccurrenceIdV1,
        physical_store_generation_identity: CrashDigestV1,
        signer_lifecycle_root_identity: CrashDigestV1,
        durable_state_identity: CrashDigestV1,
    ) -> Self {
        Self {
            snapshot_identity,
            occurrence_id,
            physical_store_generation_identity,
            signer_lifecycle_root_identity,
            durable_state_identity,
        }
    }
}

/// Stable closed IDs for the complete finite signer crash corpus.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum SignerCrashCutIdV1 {
    #[serde(rename = "SC-01")]
    Sc01,
    #[serde(rename = "SC-02")]
    Sc02,
    #[serde(rename = "SC-03")]
    Sc03,
    #[serde(rename = "SC-04")]
    Sc04,
    #[serde(rename = "SC-05")]
    Sc05,
    #[serde(rename = "SC-06")]
    Sc06,
    #[serde(rename = "SC-07")]
    Sc07,
    #[serde(rename = "SC-08")]
    Sc08,
    #[serde(rename = "SC-09")]
    Sc09,
    #[serde(rename = "SC-10")]
    Sc10,
    #[serde(rename = "SC-11")]
    Sc11,
    #[serde(rename = "SC-12")]
    Sc12,
    #[serde(rename = "SC-13")]
    Sc13,
    #[serde(rename = "SC-14")]
    Sc14,
    #[serde(rename = "SC-15")]
    Sc15,
    #[serde(rename = "SC-16")]
    Sc16,
    #[serde(rename = "SC-17")]
    Sc17,
}

pub(crate) const ALL_SIGNER_CRASH_CUTS_V1: [SignerCrashCutIdV1; 17] = [
    SignerCrashCutIdV1::Sc01,
    SignerCrashCutIdV1::Sc02,
    SignerCrashCutIdV1::Sc03,
    SignerCrashCutIdV1::Sc04,
    SignerCrashCutIdV1::Sc05,
    SignerCrashCutIdV1::Sc06,
    SignerCrashCutIdV1::Sc07,
    SignerCrashCutIdV1::Sc08,
    SignerCrashCutIdV1::Sc09,
    SignerCrashCutIdV1::Sc10,
    SignerCrashCutIdV1::Sc11,
    SignerCrashCutIdV1::Sc12,
    SignerCrashCutIdV1::Sc13,
    SignerCrashCutIdV1::Sc14,
    SignerCrashCutIdV1::Sc15,
    SignerCrashCutIdV1::Sc16,
    SignerCrashCutIdV1::Sc17,
];

/// Exact durable semantic class at a reachable signer crash cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableSignerCrashStateV1 {
    PendingKeyCarrierOnly,
    FinalKeyAndInertProposal,
    BootstrapGrantAndCandidate,
    ExactPreGenerationRequestSnapshot,
    IncompleteGenerationCommitmentPrefix,
    GenerationCommitmentWithoutReceipt,
    InitialReceiptAndBinding,
    PendingNormalEdgeWithoutSuccessorReceipt,
    PendingNormalEdgeWithoutAppendedFrame,
    ReceiptAndAppendWithoutResolution,
    IncompleteRevocationAssociation,
    PendingRecoveryWithoutCompletion,
    IncompleteRestoreSuccessorQuarantined,
    IncompleteQuarantineClosure,
    CompleteMixedLineageAndTerminalBinding,
}

/// Exact process-local material lost at a reachable signer crash cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EphemeralSignerCrashStateV1 {
    SeedNonceAndFileDescriptorLost,
    NoEphemeralSignerState,
    PopStandingAndCapabilityAbsent,
    PopWrapperAndBootstrapCapabilityLost,
    UnsignedGenerationRequestLost,
    InstallationTransactionAndCapabilityLost,
    ReceiptRequestLost,
    InitialProcessCapabilityAbsent,
    PendingSuccessorWorkLost,
    SignedUnappendedFrameLost,
    PersistedResolutionWorkLost,
    RevocationEffectWorkLost,
    RecoveryCompletionWorkLost,
    RestoreCompletionWorkLost,
    QuarantineClosureEffectWorkLost,
    KeyFdFlockFrameAndProcessEpochLost,
}

/// Authority-bearing state that remains durable after the process dies.
///
/// External governed judgments and durable standing are observations, not
/// authority minted by this module. No variant is a process signer capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableCrashAuthorityStateV1 {
    None,
    ExternalBootstrapGrantOnly,
    DurableInitialStandingOnly,
    DurablePredecessorStandingOnly,
    ExternalRevocationJudgmentOnly,
    ExternalRecoveryGrantOnly,
    ExternalRestoreAuthorizationOnly,
    ExternalQuarantineClosureJudgmentOnly,
    DurableTerminalStandingOnly,
}

/// The only write interpretation admitted for ordinary crash inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CrashWriteDispositionV1 {
    NoWrite,
    ReadOnlyReconstruction,
}

/// Exact separately invoked next act, if any; ordinary restart performs none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashNextLawfulActV1 {
    ContinueExactProposal,
    QueryGrantOrDisposition,
    RetryExactGrantBoundPop,
    RetryExactBootstrap,
    RetryFreshVerifiedGenerationRequest,
    ContinueExactInstallationIntent,
    ContinueExactReceipt,
    ReconstructInitialCapabilityReadOnly,
    RetainPredecessorOnly,
    RetainPredecessorAfterFrameLoss,
    AwaitExactPersistedResolution,
    CompleteExactRevocationPair,
    ContinueExactRecovery,
    ContinueExactRestore,
    CompleteExactQuarantineClosurePair,
    ReconstructTerminalCapabilityReadOnly,
}

/// Canonical expected-result strings used by the sixteen crash schemas.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum SignerCrashExpectedResultV1 {
    #[serde(rename = "proposal_absent")]
    ProposalAbsent,
    #[serde(rename = "proposal_inert")]
    ProposalInert,
    #[serde(rename = "pop_absent")]
    PopAbsent,
    #[serde(rename = "ephemeral_pop_lost")]
    EphemeralPopLost,
    #[serde(rename = "unsigned_request_discarded")]
    UnsignedRequestDiscarded,
    #[serde(rename = "generation_prefix_pending")]
    GenerationPrefixPending,
    #[serde(rename = "installation_receipt_absent")]
    InstallationReceiptAbsent,
    #[serde(rename = "initial_capability_reconstructed")]
    InitialCapabilityReconstructed,
    #[serde(rename = "pending_normal_predecessor_retained")]
    PendingNormalPredecessorRetained,
    #[serde(rename = "pending_normal_predecessor_retained_after_frame_loss")]
    PendingNormalPredecessorRetainedAfterFrameLoss,
    #[serde(rename = "persisted_resolution_absent")]
    PersistedResolutionAbsent,
    #[serde(rename = "incomplete_revocation_effect")]
    IncompleteRevocationEffect,
    #[serde(rename = "pending_recovery_no_current_signer")]
    PendingRecoveryNoCurrentSigner,
    #[serde(rename = "restore_successor_quarantined")]
    RestoreSuccessorQuarantined,
    #[serde(rename = "quarantine_closure_incomplete")]
    QuarantineClosureIncomplete,
    #[serde(rename = "terminal_capability_reconstructed_after_shutdown")]
    TerminalCapabilityReconstructedAfterShutdown,
}

/// Shared closed record serialized by each cut-specific schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SignerCrashCutRecordV1 {
    schema: &'static str,
    schema_version: u8,
    crash_cut: SignerCrashCutIdV1,
    snapshot_identity: CrashDigestV1,
    occurrence_id: CrashOccurrenceIdV1,
    physical_store_generation_identity: CrashDigestV1,
    signer_lifecycle_root_identity: CrashDigestV1,
    durable_state_identity: CrashDigestV1,
    ephemeral_state_class: EphemeralSignerCrashStateV1,
    expected_result: SignerCrashExpectedResultV1,
    write_disposition: CrashWriteDispositionV1,
    promotion_permitted: bool,
    finite_corpus_only: bool,
    universal_crash_safety_claimed: bool,
    #[serde(skip)]
    durable_state: DurableSignerCrashStateV1,
    #[serde(skip)]
    durable_authority_state: DurableCrashAuthorityStateV1,
    #[serde(skip)]
    next_lawful_act: CrashNextLawfulActV1,
    #[serde(skip)]
    ordinary_restart_mutates_lifecycle: bool,
    #[serde(skip)]
    process_capability_survives: bool,
    #[serde(skip)]
    claim_boundary: SignerCrashClaimBoundaryV1,
}

#[allow(clippy::too_many_arguments)]
fn construct_record(
    coordinates: SignerCrashCutCoordinatesV1,
    schema: &'static str,
    crash_cut: SignerCrashCutIdV1,
    durable_state: DurableSignerCrashStateV1,
    ephemeral_state: EphemeralSignerCrashStateV1,
    durable_authority_state: DurableCrashAuthorityStateV1,
    write_disposition: CrashWriteDispositionV1,
    next_lawful_act: CrashNextLawfulActV1,
    expected_result: SignerCrashExpectedResultV1,
) -> SignerCrashCutRecordV1 {
    SignerCrashCutRecordV1 {
        schema,
        schema_version: 1,
        crash_cut,
        snapshot_identity: coordinates.snapshot_identity,
        occurrence_id: coordinates.occurrence_id,
        physical_store_generation_identity: coordinates.physical_store_generation_identity,
        signer_lifecycle_root_identity: coordinates.signer_lifecycle_root_identity,
        durable_state_identity: coordinates.durable_state_identity,
        ephemeral_state_class: ephemeral_state,
        expected_result,
        write_disposition,
        promotion_permitted: false,
        finite_corpus_only: true,
        universal_crash_safety_claimed: false,
        durable_state,
        durable_authority_state,
        next_lawful_act,
        ordinary_restart_mutates_lifecycle: false,
        process_capability_survives: false,
        claim_boundary: SignerCrashClaimBoundaryV1::FiniteCorpusOnly,
    }
}

/// A reachable crash observation did not match its exact finite-cut contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum CrashCutVerificationRefusalV1 {
    #[error("crash record schema or stable cut identity differs")]
    SchemaOrCutMismatch,
    #[error("durable crash state differs from the exact cut")]
    DurableStateMismatch,
    #[error("ephemeral crash state differs from the exact cut")]
    EphemeralStateMismatch,
    #[error("durable authority observation differs from the exact cut")]
    DurableAuthorityStateMismatch,
    #[error("ordinary restart write disposition differs from the exact cut")]
    WriteDispositionMismatch,
    #[error("next lawful act differs from the exact cut")]
    NextLawfulActMismatch,
    #[error("typed expected result differs from the exact cut")]
    ExpectedResultMismatch,
    #[error("crash inspection attempts promotion or lifecycle mutation")]
    PromotionOrMutationAttempt,
    #[error("process-local capability purportedly survives the crash")]
    ProcessCapabilitySurvival,
    #[error("finite evidence was widened into a universal crash claim")]
    UniversalCrashClaim,
}

#[allow(clippy::too_many_arguments)]
fn verify_record(
    record: &SignerCrashCutRecordV1,
    schema: &'static str,
    crash_cut: SignerCrashCutIdV1,
    durable_state: DurableSignerCrashStateV1,
    ephemeral_state: EphemeralSignerCrashStateV1,
    durable_authority_state: DurableCrashAuthorityStateV1,
    write_disposition: CrashWriteDispositionV1,
    next_lawful_act: CrashNextLawfulActV1,
    expected_result: SignerCrashExpectedResultV1,
) -> Result<(), CrashCutVerificationRefusalV1> {
    if record.schema != schema || record.schema_version != 1 || record.crash_cut != crash_cut {
        return Err(CrashCutVerificationRefusalV1::SchemaOrCutMismatch);
    }
    if record.durable_state != durable_state {
        return Err(CrashCutVerificationRefusalV1::DurableStateMismatch);
    }
    if record.ephemeral_state_class != ephemeral_state {
        return Err(CrashCutVerificationRefusalV1::EphemeralStateMismatch);
    }
    if record.durable_authority_state != durable_authority_state {
        return Err(CrashCutVerificationRefusalV1::DurableAuthorityStateMismatch);
    }
    if record.write_disposition != write_disposition {
        return Err(CrashCutVerificationRefusalV1::WriteDispositionMismatch);
    }
    if record.next_lawful_act != next_lawful_act {
        return Err(CrashCutVerificationRefusalV1::NextLawfulActMismatch);
    }
    if record.expected_result != expected_result {
        return Err(CrashCutVerificationRefusalV1::ExpectedResultMismatch);
    }
    if record.promotion_permitted || record.ordinary_restart_mutates_lifecycle {
        return Err(CrashCutVerificationRefusalV1::PromotionOrMutationAttempt);
    }
    if record.process_capability_survives {
        return Err(CrashCutVerificationRefusalV1::ProcessCapabilitySurvival);
    }
    if !record.finite_corpus_only
        || record.universal_crash_safety_claimed
        || record.claim_boundary != SignerCrashClaimBoundaryV1::FiniteCorpusOnly
    {
        return Err(CrashCutVerificationRefusalV1::UniversalCrashClaim);
    }
    Ok(())
}

macro_rules! define_crash_result_cut {
    (
        $type_name:ident,
        $constructor:ident,
        $verifier:ident,
        $cut:ident,
        $schema:literal,
        $durable:ident,
        $ephemeral:ident,
        $authority:ident,
        $write:ident,
        $next:ident,
        $expected:ident,
        $result:ident
    ) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub(crate) struct $type_name(SignerCrashCutRecordV1);

        #[must_use]
        pub(crate) fn $constructor(coordinates: SignerCrashCutCoordinatesV1) -> $type_name {
            $type_name(construct_record(
                coordinates,
                $schema,
                SignerCrashCutIdV1::$cut,
                DurableSignerCrashStateV1::$durable,
                EphemeralSignerCrashStateV1::$ephemeral,
                DurableCrashAuthorityStateV1::$authority,
                CrashWriteDispositionV1::$write,
                CrashNextLawfulActV1::$next,
                SignerCrashExpectedResultV1::$expected,
            ))
        }

        pub(crate) fn $verifier(
            observation: &$type_name,
        ) -> Result<CrashCutResultV2, CrashCutVerificationRefusalV1> {
            verify_record(
                &observation.0,
                $schema,
                SignerCrashCutIdV1::$cut,
                DurableSignerCrashStateV1::$durable,
                EphemeralSignerCrashStateV1::$ephemeral,
                DurableCrashAuthorityStateV1::$authority,
                CrashWriteDispositionV1::$write,
                CrashNextLawfulActV1::$next,
                SignerCrashExpectedResultV1::$expected,
            )?;
            Ok(CrashCutResultV2::$result)
        }
    };
}

macro_rules! define_restart_refusal_cut {
    (
        $type_name:ident,
        $constructor:ident,
        $verifier:ident,
        $cut:ident,
        $schema:literal,
        $durable:ident,
        $ephemeral:ident,
        $authority:ident,
        $write:ident,
        $next:ident,
        $expected:ident,
        $result:ident
    ) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub(crate) struct $type_name(SignerCrashCutRecordV1);

        #[must_use]
        pub(crate) fn $constructor(coordinates: SignerCrashCutCoordinatesV1) -> $type_name {
            $type_name(construct_record(
                coordinates,
                $schema,
                SignerCrashCutIdV1::$cut,
                DurableSignerCrashStateV1::$durable,
                EphemeralSignerCrashStateV1::$ephemeral,
                DurableCrashAuthorityStateV1::$authority,
                CrashWriteDispositionV1::$write,
                CrashNextLawfulActV1::$next,
                SignerCrashExpectedResultV1::$expected,
            ))
        }

        pub(crate) fn $verifier(
            observation: &$type_name,
        ) -> Result<RestartRefusalV2, CrashCutVerificationRefusalV1> {
            verify_record(
                &observation.0,
                $schema,
                SignerCrashCutIdV1::$cut,
                DurableSignerCrashStateV1::$durable,
                EphemeralSignerCrashStateV1::$ephemeral,
                DurableCrashAuthorityStateV1::$authority,
                CrashWriteDispositionV1::$write,
                CrashNextLawfulActV1::$next,
                SignerCrashExpectedResultV1::$expected,
            )?;
            Ok(RestartRefusalV2::$result)
        }
    };
}

macro_rules! define_restart_success_cut {
    (
        $type_name:ident,
        $constructor:ident,
        $verifier:ident,
        $cut:ident,
        $schema:literal,
        $durable:ident,
        $ephemeral:ident,
        $authority:ident,
        $write:ident,
        $next:ident,
        $expected:ident,
        $result:ident
    ) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub(crate) struct $type_name(SignerCrashCutRecordV1);

        #[must_use]
        pub(crate) fn $constructor(coordinates: SignerCrashCutCoordinatesV1) -> $type_name {
            $type_name(construct_record(
                coordinates,
                $schema,
                SignerCrashCutIdV1::$cut,
                DurableSignerCrashStateV1::$durable,
                EphemeralSignerCrashStateV1::$ephemeral,
                DurableCrashAuthorityStateV1::$authority,
                CrashWriteDispositionV1::$write,
                CrashNextLawfulActV1::$next,
                SignerCrashExpectedResultV1::$expected,
            ))
        }

        pub(crate) fn $verifier(
            observation: &$type_name,
        ) -> Result<RestartResultV2, CrashCutVerificationRefusalV1> {
            verify_record(
                &observation.0,
                $schema,
                SignerCrashCutIdV1::$cut,
                DurableSignerCrashStateV1::$durable,
                EphemeralSignerCrashStateV1::$ephemeral,
                DurableCrashAuthorityStateV1::$authority,
                CrashWriteDispositionV1::$write,
                CrashNextLawfulActV1::$next,
                SignerCrashExpectedResultV1::$expected,
            )?;
            Ok(RestartResultV2::$result)
        }
    };
}

define_crash_result_cut!(
    SignerCrashCutSc01V1,
    construct_sc_01_complete_pending_key_carrier_is_durable_proposal,
    verify_sc_01_complete_pending_key_carrier_is_durable_proposal,
    Sc01,
    "nq.c2_signer_crash_cut_sc_01.v1",
    PendingKeyCarrierOnly,
    SeedNonceAndFileDescriptorLost,
    None,
    NoWrite,
    ContinueExactProposal,
    ProposalAbsent,
    Sc01ProposalAbsent
);
define_crash_result_cut!(
    SignerCrashCutSc02V1,
    construct_sc_02_key_inert_proposal_are_durable_grant_disposition,
    verify_sc_02_key_inert_proposal_are_durable_grant_disposition,
    Sc02,
    "nq.c2_signer_crash_cut_sc_02.v1",
    FinalKeyAndInertProposal,
    NoEphemeralSignerState,
    None,
    NoWrite,
    QueryGrantOrDisposition,
    ProposalInert,
    Sc02ProposalInert
);
define_crash_result_cut!(
    SignerCrashCutSc03V1,
    construct_sc_03_grant_candidate_are_durable_pop_standing_capability,
    verify_sc_03_grant_candidate_are_durable_pop_standing_capability,
    Sc03,
    "nq.c2_signer_crash_cut_sc_03.v1",
    BootstrapGrantAndCandidate,
    PopStandingAndCapabilityAbsent,
    ExternalBootstrapGrantOnly,
    NoWrite,
    RetryExactGrantBoundPop,
    PopAbsent,
    Sc03PopAbsent
);
define_crash_result_cut!(
    SignerCrashCutSc04V1,
    construct_sc_04_pop_accepted_wrapper_bootstrap_capability_were_ephemeral,
    verify_sc_04_pop_accepted_wrapper_bootstrap_capability_were_ephemeral,
    Sc04,
    "nq.c2_signer_crash_cut_sc_04.v1",
    BootstrapGrantAndCandidate,
    PopWrapperAndBootstrapCapabilityLost,
    ExternalBootstrapGrantOnly,
    NoWrite,
    RetryExactBootstrap,
    EphemeralPopLost,
    Sc04EphemeralPopLost
);
define_crash_result_cut!(
    SignerCrashCutSc05V1,
    construct_sc_05_unsigned_typed_generation_request_is_ephemeral_no,
    verify_sc_05_unsigned_typed_generation_request_is_ephemeral_no,
    Sc05,
    "nq.c2_signer_crash_cut_sc_05.v1",
    ExactPreGenerationRequestSnapshot,
    UnsignedGenerationRequestLost,
    None,
    NoWrite,
    RetryFreshVerifiedGenerationRequest,
    UnsignedRequestDiscarded,
    Sc05UnsignedRequestDiscarded
);
define_restart_refusal_cut!(
    SignerCrashCutSc07V1,
    construct_sc_07_incomplete_s2_s3_generation_commitment_prefix_is,
    verify_sc_07_incomplete_s2_s3_generation_commitment_prefix_is,
    Sc07,
    "nq.c2_signer_crash_cut_sc_07.v1",
    IncompleteGenerationCommitmentPrefix,
    InstallationTransactionAndCapabilityLost,
    None,
    NoWrite,
    ContinueExactInstallationIntent,
    GenerationPrefixPending,
    GenerationPrefixPendingExactIntentContinuation
);
define_crash_result_cut!(
    SignerCrashCutSc08V1,
    construct_sc_08_generation_commitment_is_durable_while_receipt_binding,
    verify_sc_08_generation_commitment_is_durable_while_receipt_binding,
    Sc08,
    "nq.c2_signer_crash_cut_sc_08.v1",
    GenerationCommitmentWithoutReceipt,
    ReceiptRequestLost,
    None,
    NoWrite,
    ContinueExactReceipt,
    InstallationReceiptAbsent,
    Sc08ReceiptAbsent
);
define_restart_success_cut!(
    SignerCrashCutSc09V1,
    construct_sc_09_receipt_initial_binding_are_durable_while_process,
    verify_sc_09_receipt_initial_binding_are_durable_while_process,
    Sc09,
    "nq.c2_signer_crash_cut_sc_09.v1",
    InitialReceiptAndBinding,
    InitialProcessCapabilityAbsent,
    DurableInitialStandingOnly,
    ReadOnlyReconstruction,
    ReconstructInitialCapabilityReadOnly,
    InitialCapabilityReconstructed,
    InitialCapabilityReconstructed
);
define_restart_success_cut!(
    SignerCrashCutSc10V1,
    construct_sc_10_pending_normal_edge_exists_before_successor_receipt,
    verify_sc_10_pending_normal_edge_exists_before_successor_receipt,
    Sc10,
    "nq.c2_signer_crash_cut_sc_10.v1",
    PendingNormalEdgeWithoutSuccessorReceipt,
    PendingSuccessorWorkLost,
    DurablePredecessorStandingOnly,
    NoWrite,
    RetainPredecessorOnly,
    PendingNormalPredecessorRetained,
    PendingNormalPredecessorRetained
);
define_restart_success_cut!(
    SignerCrashCutSc11V1,
    construct_sc_11_successor_receipt_frame_is_signed_ephemerally_unappended,
    verify_sc_11_successor_receipt_frame_is_signed_ephemerally_unappended,
    Sc11,
    "nq.c2_signer_crash_cut_sc_11.v1",
    PendingNormalEdgeWithoutAppendedFrame,
    SignedUnappendedFrameLost,
    DurablePredecessorStandingOnly,
    NoWrite,
    RetainPredecessorAfterFrameLoss,
    PendingNormalPredecessorRetainedAfterFrameLoss,
    PendingNormalPredecessorRetainedAfterFrameLoss
);
define_restart_refusal_cut!(
    SignerCrashCutSc12V1,
    construct_sc_12_receipt_append_exist_while_persisted_resolution_is,
    verify_sc_12_receipt_append_exist_while_persisted_resolution_is,
    Sc12,
    "nq.c2_signer_crash_cut_sc_12.v1",
    ReceiptAndAppendWithoutResolution,
    PersistedResolutionWorkLost,
    DurablePredecessorStandingOnly,
    NoWrite,
    AwaitExactPersistedResolution,
    PersistedResolutionAbsent,
    PersistedResolutionAbsent
);
define_restart_refusal_cut!(
    SignerCrashCutSc13V1,
    construct_sc_13_revocation_judgment_exists_while_judgment_effect_receipt,
    verify_sc_13_revocation_judgment_exists_while_judgment_effect_receipt,
    Sc13,
    "nq.c2_signer_crash_cut_sc_13.v1",
    IncompleteRevocationAssociation,
    RevocationEffectWorkLost,
    ExternalRevocationJudgmentOnly,
    NoWrite,
    CompleteExactRevocationPair,
    IncompleteRevocationEffect,
    IncompleteRevocationEffect
);
define_restart_refusal_cut!(
    SignerCrashCutSc14V1,
    construct_sc_14_recovery_grant_proposal_pop_are_pending_while,
    verify_sc_14_recovery_grant_proposal_pop_are_pending_while,
    Sc14,
    "nq.c2_signer_crash_cut_sc_14.v1",
    PendingRecoveryWithoutCompletion,
    RecoveryCompletionWorkLost,
    ExternalRecoveryGrantOnly,
    NoWrite,
    ContinueExactRecovery,
    PendingRecoveryNoCurrentSigner,
    PendingRecoveryNoCurrentSigner
);
define_restart_refusal_cut!(
    SignerCrashCutSc15V1,
    construct_sc_15_authorized_restore_successor_is_incomplete_remains_quarantined,
    verify_sc_15_authorized_restore_successor_is_incomplete_remains_quarantined,
    Sc15,
    "nq.c2_signer_crash_cut_sc_15.v1",
    IncompleteRestoreSuccessorQuarantined,
    RestoreCompletionWorkLost,
    ExternalRestoreAuthorizationOnly,
    NoWrite,
    ContinueExactRestore,
    RestoreSuccessorQuarantined,
    RestoreSuccessorQuarantined
);
define_restart_refusal_cut!(
    SignerCrashCutSc16V1,
    construct_sc_16_quarantine_closure_carrier_effect_receipt_pair_is,
    verify_sc_16_quarantine_closure_carrier_effect_receipt_pair_is,
    Sc16,
    "nq.c2_signer_crash_cut_sc_16.v1",
    IncompleteQuarantineClosure,
    QuarantineClosureEffectWorkLost,
    ExternalQuarantineClosureJudgmentOnly,
    NoWrite,
    CompleteExactQuarantineClosurePair,
    QuarantineClosureIncomplete,
    QuarantineClosureIncomplete
);
define_restart_success_cut!(
    SignerCrashCutSc17V1,
    construct_sc_17_shutdown_after_key_load_makes_no_durable,
    verify_sc_17_shutdown_after_key_load_makes_no_durable,
    Sc17,
    "nq.c2_signer_crash_cut_sc_17.v1",
    CompleteMixedLineageAndTerminalBinding,
    KeyFdFlockFrameAndProcessEpochLost,
    DurableTerminalStandingOnly,
    ReadOnlyReconstruction,
    ReconstructTerminalCapabilityReadOnly,
    TerminalCapabilityReconstructedAfterShutdown,
    TerminalCapabilityReconstructedAfterShutdown
);

/// Closed success result for the process/hostile/crash evidence inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignerProcessCrashEvidenceInventoryV2 {
    ProcessHostileFiniteCrashOwnerTwoProcessAliasCopyForkVerified,
}

/// Concrete inventory inputs checked before the SG-WU-07 result can exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SignerProcessCrashEvidenceObservationV2 {
    two_process_checked: bool,
    alias_checked: bool,
    copy_checked: bool,
    fork_checked: bool,
    exec_checked: bool,
    shutdown_checked: bool,
    hostile_corpus_closed: bool,
    signer_io_census_closed: bool,
    crash_cuts: [SignerCrashCutIdV1; 17],
}

impl SignerProcessCrashEvidenceObservationV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        two_process_checked: bool,
        alias_checked: bool,
        copy_checked: bool,
        fork_checked: bool,
        exec_checked: bool,
        shutdown_checked: bool,
        hostile_corpus_closed: bool,
        signer_io_census_closed: bool,
        crash_cuts: [SignerCrashCutIdV1; 17],
    ) -> Self {
        Self {
            two_process_checked,
            alias_checked,
            copy_checked,
            fork_checked,
            exec_checked,
            shutdown_checked,
            hostile_corpus_closed,
            signer_io_census_closed,
            crash_cuts,
        }
    }
}

/// Exact SG-WU-07 inventory refusal.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SignerProcessCrashInventoryRefusalV2 {
    #[error("two-process, alias, copy, fork, exec, or shutdown evidence is absent")]
    ProcessCaseMissing,
    #[error("the hostile corpus or signer I/O census is incomplete")]
    EvidenceInventoryIncomplete,
    #[error("the finite crash-cut census is not exactly SC-01 through SC-17")]
    CrashCutCensusMismatch,
}

pub(crate) fn verify_sg_wu_07_process_hostile_finite_crash_owner_two_process(
    observation: &SignerProcessCrashEvidenceObservationV2,
) -> Result<SignerProcessCrashEvidenceInventoryV2, SignerProcessCrashInventoryRefusalV2> {
    if !(observation.two_process_checked
        && observation.alias_checked
        && observation.copy_checked
        && observation.fork_checked
        && observation.exec_checked
        && observation.shutdown_checked)
    {
        return Err(SignerProcessCrashInventoryRefusalV2::ProcessCaseMissing);
    }
    if !(observation.hostile_corpus_closed && observation.signer_io_census_closed) {
        return Err(SignerProcessCrashInventoryRefusalV2::EvidenceInventoryIncomplete);
    }
    if observation.crash_cuts != ALL_SIGNER_CRASH_CUTS_V1 {
        return Err(SignerProcessCrashInventoryRefusalV2::CrashCutCensusMismatch);
    }
    Ok(
        SignerProcessCrashEvidenceInventoryV2::ProcessHostileFiniteCrashOwnerTwoProcessAliasCopyForkVerified,
    )
}

pub(crate) fn construct_sg_wu_07_process_hostile_finite_crash_owner_two_process(
    observation: SignerProcessCrashEvidenceObservationV2,
) -> Result<SignerProcessCrashEvidenceInventoryV2, SignerProcessCrashInventoryRefusalV2> {
    verify_sg_wu_07_process_hostile_finite_crash_owner_two_process(&observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> CrashDigestV1 {
        CrashDigestV1::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn coordinates() -> SignerCrashCutCoordinatesV1 {
        SignerCrashCutCoordinatesV1::new(
            digest('1'),
            CrashOccurrenceIdV1::parse("store-occurrence-1").unwrap(),
            digest('2'),
            digest('3'),
            digest('4'),
        )
    }

    #[test]
    fn every_reachable_cut_has_the_exact_typed_result() {
        assert_eq!(
            verify_sc_01_complete_pending_key_carrier_is_durable_proposal(
                &construct_sc_01_complete_pending_key_carrier_is_durable_proposal(coordinates())
            ),
            Ok(CrashCutResultV2::Sc01ProposalAbsent)
        );
        assert_eq!(
            verify_sc_02_key_inert_proposal_are_durable_grant_disposition(
                &construct_sc_02_key_inert_proposal_are_durable_grant_disposition(coordinates())
            ),
            Ok(CrashCutResultV2::Sc02ProposalInert)
        );
        assert_eq!(
            verify_sc_03_grant_candidate_are_durable_pop_standing_capability(
                &construct_sc_03_grant_candidate_are_durable_pop_standing_capability(coordinates())
            ),
            Ok(CrashCutResultV2::Sc03PopAbsent)
        );
        assert_eq!(
            verify_sc_04_pop_accepted_wrapper_bootstrap_capability_were_ephemeral(
                &construct_sc_04_pop_accepted_wrapper_bootstrap_capability_were_ephemeral(
                    coordinates()
                )
            ),
            Ok(CrashCutResultV2::Sc04EphemeralPopLost)
        );
        assert_eq!(
            verify_sc_05_unsigned_typed_generation_request_is_ephemeral_no(
                &construct_sc_05_unsigned_typed_generation_request_is_ephemeral_no(coordinates())
            ),
            Ok(CrashCutResultV2::Sc05UnsignedRequestDiscarded)
        );
        assert_eq!(
            verify_sc_07_incomplete_s2_s3_generation_commitment_prefix_is(
                &construct_sc_07_incomplete_s2_s3_generation_commitment_prefix_is(coordinates())
            ),
            Ok(RestartRefusalV2::GenerationPrefixPendingExactIntentContinuation)
        );
        assert_eq!(
            verify_sc_08_generation_commitment_is_durable_while_receipt_binding(
                &construct_sc_08_generation_commitment_is_durable_while_receipt_binding(
                    coordinates()
                )
            ),
            Ok(CrashCutResultV2::Sc08ReceiptAbsent)
        );
        assert_eq!(
            verify_sc_09_receipt_initial_binding_are_durable_while_process(
                &construct_sc_09_receipt_initial_binding_are_durable_while_process(coordinates())
            ),
            Ok(RestartResultV2::InitialCapabilityReconstructed)
        );
        assert_eq!(
            verify_sc_10_pending_normal_edge_exists_before_successor_receipt(
                &construct_sc_10_pending_normal_edge_exists_before_successor_receipt(coordinates())
            ),
            Ok(RestartResultV2::PendingNormalPredecessorRetained)
        );
        assert_eq!(
            verify_sc_11_successor_receipt_frame_is_signed_ephemerally_unappended(
                &construct_sc_11_successor_receipt_frame_is_signed_ephemerally_unappended(
                    coordinates()
                )
            ),
            Ok(RestartResultV2::PendingNormalPredecessorRetainedAfterFrameLoss)
        );
        assert_eq!(
            verify_sc_12_receipt_append_exist_while_persisted_resolution_is(
                &construct_sc_12_receipt_append_exist_while_persisted_resolution_is(coordinates())
            ),
            Ok(RestartRefusalV2::PersistedResolutionAbsent)
        );
        assert_eq!(
            verify_sc_13_revocation_judgment_exists_while_judgment_effect_receipt(
                &construct_sc_13_revocation_judgment_exists_while_judgment_effect_receipt(
                    coordinates()
                )
            ),
            Ok(RestartRefusalV2::IncompleteRevocationEffect)
        );
        assert_eq!(
            verify_sc_14_recovery_grant_proposal_pop_are_pending_while(
                &construct_sc_14_recovery_grant_proposal_pop_are_pending_while(coordinates())
            ),
            Ok(RestartRefusalV2::PendingRecoveryNoCurrentSigner)
        );
        assert_eq!(
            verify_sc_15_authorized_restore_successor_is_incomplete_remains_quarantined(
                &construct_sc_15_authorized_restore_successor_is_incomplete_remains_quarantined(
                    coordinates()
                )
            ),
            Ok(RestartRefusalV2::RestoreSuccessorQuarantined)
        );
        assert_eq!(
            verify_sc_16_quarantine_closure_carrier_effect_receipt_pair_is(
                &construct_sc_16_quarantine_closure_carrier_effect_receipt_pair_is(coordinates())
            ),
            Ok(RestartRefusalV2::QuarantineClosureIncomplete)
        );
        assert_eq!(
            verify_sc_17_shutdown_after_key_load_makes_no_durable(
                &construct_sc_17_shutdown_after_key_load_makes_no_durable(coordinates())
            ),
            Ok(RestartResultV2::TerminalCapabilityReconstructedAfterShutdown)
        );
    }

    #[test]
    fn verifier_rejects_universal_claim_and_promotion() {
        let mut cut =
            construct_sc_10_pending_normal_edge_exists_before_successor_receipt(coordinates());
        cut.0.universal_crash_safety_claimed = true;
        assert_eq!(
            verify_sc_10_pending_normal_edge_exists_before_successor_receipt(&cut),
            Err(CrashCutVerificationRefusalV1::UniversalCrashClaim)
        );

        let mut cut = construct_sc_14_recovery_grant_proposal_pop_are_pending_while(coordinates());
        cut.0.promotion_permitted = true;
        assert_eq!(
            verify_sc_14_recovery_grant_proposal_pop_are_pending_while(&cut),
            Err(CrashCutVerificationRefusalV1::PromotionOrMutationAttempt)
        );
    }

    #[test]
    fn serialized_cut_matches_the_closed_schema_surface() {
        let cut = construct_sc_01_complete_pending_key_carrier_is_durable_proposal(coordinates());
        let value = serde_json::to_value(cut).unwrap();
        assert_eq!(value["schema"], "nq.c2_signer_crash_cut_sc_01.v1");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["crash_cut"], "SC-01");
        assert_eq!(value["expected_result"], "proposal_absent");
        assert_eq!(value["write_disposition"], "no_write");
        assert_eq!(value["promotion_permitted"], false);
        assert_eq!(value["finite_corpus_only"], true);
        assert_eq!(value["universal_crash_safety_claimed"], false);
        assert_eq!(value.as_object().unwrap().len(), 14);
    }

    #[test]
    fn process_inventory_requires_every_case_and_all_seventeen_ids() {
        let complete = SignerProcessCrashEvidenceObservationV2::new(
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            ALL_SIGNER_CRASH_CUTS_V1,
        );
        assert_eq!(
            construct_sg_wu_07_process_hostile_finite_crash_owner_two_process(complete),
            Ok(SignerProcessCrashEvidenceInventoryV2::ProcessHostileFiniteCrashOwnerTwoProcessAliasCopyForkVerified)
        );

        let missing_fork = SignerProcessCrashEvidenceObservationV2::new(
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            ALL_SIGNER_CRASH_CUTS_V1,
        );
        assert_eq!(
            verify_sg_wu_07_process_hostile_finite_crash_owner_two_process(&missing_fork),
            Err(SignerProcessCrashInventoryRefusalV2::ProcessCaseMissing)
        );

        let mut duplicate = ALL_SIGNER_CRASH_CUTS_V1;
        duplicate[5] = SignerCrashCutIdV1::Sc05;
        let bad_census = SignerProcessCrashEvidenceObservationV2::new(
            true, true, true, true, true, true, true, true, duplicate,
        );
        assert_eq!(
            verify_sg_wu_07_process_hostile_finite_crash_owner_two_process(&bad_census),
            Err(SignerProcessCrashInventoryRefusalV2::CrashCutCensusMismatch)
        );
    }

    #[test]
    fn crash_identifiers_refuse_noncanonical_values() {
        assert_eq!(
            CrashDigestV1::parse("sha256:0"),
            Err(CrashIdentityRefusalV1::MalformedDigest)
        );
        assert_eq!(
            CrashOccurrenceIdV1::parse("bad occurrence"),
            Err(CrashIdentityRefusalV1::MalformedOccurrence)
        );
    }
}
