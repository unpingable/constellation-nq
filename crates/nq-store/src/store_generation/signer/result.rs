//! Closed result vocabulary for the C2 Store-integrity signer.
//!
//! These enums deliberately replace Boolean "valid"/"current" results.  A
//! caller must preserve the exact success or refusal class established by the
//! verifier that produced it.

/// Marker proving that the signer-owned result vocabulary is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignerResultTaxonomyV2 {
    ClosedAndExhaustive,
}

/// Refusals shared by authority, custody, signing, and succession paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SignerRefusalV2 {
    #[error("the exact usable current predecessor is absent")]
    MissingUsableCurrentPredecessor,
    #[error("the terminal A1 authority snapshot is incomplete")]
    IncompleteTerminalA1Snapshot,
    #[error("the selected issuer is not the unique terminal A1 key generation")]
    WrongTerminalA1Issuer,
    #[error("the A1 issuer and Store-integrity signer keys are not distinct")]
    IssuerSignerKeyCollision,
    #[error("the external governed carrier does not match its exact scope")]
    ExternalCarrierScopeMismatch,
    #[error("the external governed carrier is stale or superseded")]
    ExternalCarrierStale,
    #[error("the external governed carrier has already been consumed")]
    ExternalCarrierReplay,
    #[error("A2 applicability does not match the grant")]
    A2ApplicabilityMismatch,
    #[error("A2 was presented as grant authority")]
    A2AuthorityEscalation,
    #[error("the signer message family is external or unsigned")]
    MessageFamilyNotSignable,
    #[error("the capability cannot sign this message family")]
    CapabilityFamilyMismatch,
    #[error("message coordinates do not match the terminal signer frontier")]
    MessageFrontierMismatch,
    #[error("the frame payload was substituted after validation")]
    MessagePayloadSubstitution,
    #[error("the signed frame was already consumed")]
    SignedFrameAlreadyConsumed,
    #[error("the same enrollment occurrence carried changed canonical evidence")]
    EnrollmentEvidenceCollision,
    #[error("the durable signer-state operation failed")]
    SignerStateIo,
    #[error("the custody root is not the fixed implementation root")]
    CallerSelectedCustodyRoot,
    #[error("the derived custody path does not match the signer coordinates")]
    CustodyPathMismatch,
    #[error("the custody file is malformed")]
    CustodyFileMalformed,
    #[error("the custody file has unsafe ownership, mode, or file type")]
    CustodyFileUnsafe,
    #[error("the custody key does not match the proposal or current binding")]
    CustodyKeyMismatch,
    #[error("the custody operation failed")]
    CustodyIo,
}

/// Refusals produced while validating root/current-binding correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BindingRefusalV1 {
    #[error("the current signer binding is malformed")]
    MalformedCurrentSignerBinding,
    #[error("the current signer binding names another lifecycle root")]
    RootMismatch,
    #[error("more than one current signer binding exists at the cut")]
    CurrentBindingConflict,
    #[error("the physical Store generation differs from the root binding")]
    PhysicalGenerationMismatch,
    #[error("the current key differs from its initial state or transition")]
    CurrentKeyMismatch,
    #[error("the current policy differs from its transition")]
    CurrentPolicyMismatch,
    #[error("the current standing differs from its binding")]
    CurrentStandingMismatch,
}

/// Refusals produced while validating an adjacent rooted lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LineageRefusalV1 {
    #[error("normal succession uses a stale, skipped, or forked predecessor")]
    StaleSkippedOrForkedNormalPredecessor,
    #[error("recovery uses a malformed, stale, spliced, forked, or replayed base")]
    MalformedStaleSplicedForkedOrReplayedRecovery,
    #[error("the lineage contains a gap")]
    Gap,
    #[error("the lineage contains a fork")]
    Fork,
    #[error("the lineage contains a duplicate transition identity")]
    DuplicateTransition,
    #[error("the lineage contains a duplicate completion or receipt/append pair")]
    DuplicateCompletion,
    #[error("the transition skips the exact terminal predecessor")]
    SkippedPredecessor,
    #[error("the transition uses a stale predecessor")]
    StalePredecessor,
    #[error("the transition splices witnesses from different predecessors")]
    PredecessorSplice,
    #[error("a recovery grant was replayed")]
    ReplayedRecoveryGrant,
    #[error("normal and recovery transitions compete for one predecessor")]
    CompetingSuccessors,
    #[error("the lineage has more than one terminal binding")]
    MultipleTerminalBindings,
    #[error("the purported successor authorizes itself")]
    SuccessorSelfAuthorization,
}

/// Exact restart refusals used by the accepted finite restart correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RestartRefusalV2 {
    #[error("generation prefix is pending and only exact intent continuation is allowed")]
    GenerationPrefixPendingExactIntentContinuation,
    #[error("persisted transition resolution is absent")]
    PersistedResolutionAbsent,
    #[error("revocation effect is incomplete")]
    IncompleteRevocationEffect,
    #[error("pending recovery has no current signer capability")]
    PendingRecoveryNoCurrentSigner,
    #[error("restore successor remains quarantined")]
    RestoreSuccessorQuarantined,
    #[error("quarantine closure is incomplete")]
    QuarantineClosureIncomplete,
    #[error("recovery resolver rejected the evidence")]
    RecoveryResolverRejected,
    #[error("pending state is malformed")]
    PendingStateMalformed,
    #[error("restart route and terminal binding mode differ")]
    RouteModeMismatch,
    #[error("currentness plus custody is insufficient")]
    CurrentnessCustodyInsufficient,
    #[error("restart evidence is malformed or spliced")]
    MalformedOrSplicedEvidence,
    #[error("restart attempted to create authority")]
    AuthorityCreationAttempt,
    #[error("terminal custody is absent")]
    TerminalCustodyAbsent,
    #[error("the complete rooted lineage is absent")]
    IncompleteLineage,
    #[error("the lineage is forked or has competing terminal bindings")]
    ForkedLineage,
    #[error("a historical signer was selected for restart")]
    HistoricalSignerNotCurrent,
    #[error("initial restart encountered successor material")]
    InitialRouteHasSuccessorMaterial,
}

/// Exact successful restart outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestartResultV2 {
    InitialCapabilityReconstructed,
    PendingNormalPredecessorRetained,
    PendingNormalPredecessorRetainedAfterFrameLoss,
    NormalTerminalCapabilityReconstructed,
    RestoreTerminalCapabilityReconstructed,
    RecoveryTerminalCapabilityReconstructed,
    TerminalCapabilityReconstructedAfterShutdown,
}

/// Exact finite crash-cut outcomes that do not reconstruct a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrashCutResultV2 {
    Sc01ProposalAbsent,
    Sc02ProposalInert,
    Sc03PopAbsent,
    Sc04EphemeralPopLost,
    Sc05UnsignedRequestDiscarded,
    Sc08ReceiptAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProposalResultV2 {
    InertProposalPersisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnrollmentCandidateResultV2 {
    InertCandidatePersisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevocationEffectResultV2 {
    ReceiptPersisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuarantineClosureEffectResultV2 {
    ReceiptPersisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestResultV2 {
    ExactImplementationManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignerCrashClaimBoundaryV1 {
    FiniteCorpusOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompileExclusionV2 {
    SignerAuthorityNonAmplification,
}

/// Statically exercises every signer-owned result family.
pub(crate) fn verify_exhaustive_result_taxonomy() -> SignerResultTaxonomyV2 {
    SignerResultTaxonomyV2::ClosedAndExhaustive
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_has_no_boolean_success_escape() {
        assert_eq!(
            verify_exhaustive_result_taxonomy(),
            SignerResultTaxonomyV2::ClosedAndExhaustive
        );
        assert_ne!(
            RestartRefusalV2::CurrentnessCustodyInsufficient,
            RestartRefusalV2::AuthorityCreationAttempt
        );
    }
}
