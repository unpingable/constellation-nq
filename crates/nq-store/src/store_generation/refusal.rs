//! Closed C2 Store-generation refusal vocabulary.
//!
//! A refusal is inert evidence: it cannot be converted into standing,
//! currentness, a backend, a signer, capacity, or a writer session.  Its
//! representation is opaque outside `nq-store`; production verifiers select a
//! code only after detecting the corresponding mismatch.

use serde::Serialize;
use thiserror::Error;

/// Closed classifications emitted by C2 Store-generation verification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2StoreGenerationRefusalCodeV2 {
    RoleDomainKeyCrossUse,
    ActivationWrongStoreOccurrence,
    ActivationWrongPhysicalStoreGeneration,
    ActivationWrongResidentRoleGeneration,
    ActivationWrongDomain,
    SubstitutedActivationSameAnchor,
    CanonicalBFromSqlite,
    CanonicalBSelfAuthentication,
    CanonicalGWithoutControllingActivation,
    CanonicalBGIdentityMismatch,
    CopiedLockForeignOccurrence,
    StaleLockAccepted,
    LockBeforeAuthorityVerification,
    LockOwnershipAsAuthority,
    CallerSelectedBackend,
    BackendStateAsBootstrapAuthority,
    ClosedBackendCrossGenerationReuse,
    CapacityBeforeBackendClosure,
    WriterSessionBeforeC2Closure,
    ActivationMintsWriterSession,
    BackendMintsWriterSession,
    PartialFailureResidualAuthority,
    RestartSynthesizesMissingCarrier,
    RecoveryFabricatesRuntimeAuthority,
    CopiedStoreSimultaneousCurrentness,
    CallerMintedGenerationIdentity,
    PathOrSqliteGenerationInference,
    GenerationPolicyForkTieBreak,
    ActivationBindingMismatch,
    SameAnchorSubstitutedActivation,
    BFromSqliteOrSelfAuthentication,
    GWithoutControllingActivation,
    BGIdentityMismatch,
    StaleOrCopiedLock,
    LockAsAuthority,
    LockDomainAliasEscape,
    CopyLockDomainMismatch,
    CallerOrFeatureSelectedBackend,
    BackendStateAsAuthority,
    CapacityBeforeClosureOrBooleanSuccess,
    SessionBeforeFullClosure,
    PartialFailureResidualStanding,
    RestartSynthesizesBG,
    RecoveryFabricatesAuthority,
    BFromSqlite,
    BSelfAuthentication,
    GenerationPolicyGap,
    GenerationPolicyFork,
    GenerationPolicyCycle,
    GenerationPolicySameCutCollision,
    GenerationPolicyTieBreak,
    CopiedLock,
    StaleLock,
    ConfigurationSelectedBackend,
    FeatureFlagBackendSubstitution,
    BackendAsBootstrapAuthority,
    MockBackendProductionPath,
    ProfileManifestMismatch,
    BackendPreflightAsClosedStanding,
    ActivationMintsWriterStanding,
    LockMintsWriterStanding,
    BackendMintsWriterStanding,
    BMintsWriterStanding,
    GMintsWriterStanding,
    PreS5GRecord,
    RestoreWrongPredecessor,
    RestoredCopyWithoutQuarantineClosure,
    FailedConstructionExternalResidue,
}

/// Opaque refusal returned by Store-owned verification.
///
/// The field is private so callers cannot manufacture a favorable or
/// strategically selected product result.  Crate-private production paths
/// construct one only at the point where the mismatch is observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct C2StoreGenerationRefusalV2(C2StoreGenerationRefusalCodeV2);

impl C2StoreGenerationRefusalV2 {
    /// Inspect the exact closed classification without gaining any authority.
    #[must_use]
    pub const fn code(self) -> C2StoreGenerationRefusalCodeV2 {
        self.0
    }

    /// Crate-private construction at an actual production refusal boundary.
    pub(crate) const fn from_code(code: C2StoreGenerationRefusalCodeV2) -> Self {
        Self(code)
    }
}

/// Failure of an evidence test to observe the exact expected refusal.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("expected C2 refusal {expected:?}, observed {observed:?}")]
pub struct RefusalClassificationMismatchV1 {
    /// Expected closed classification.
    pub expected: C2StoreGenerationRefusalCodeV2,
    /// Classification actually returned by the production path.
    pub observed: C2StoreGenerationRefusalCodeV2,
}

fn verify_exact_refusal(
    observed: C2StoreGenerationRefusalV2,
    expected: C2StoreGenerationRefusalCodeV2,
) -> Result<(), RefusalClassificationMismatchV1> {
    if observed.code() == expected {
        Ok(())
    } else {
        Err(RefusalClassificationMismatchV1 {
            expected,
            observed: observed.code(),
        })
    }
}

macro_rules! exact_refusal_verifiers {
    ($(($name:ident, $code:ident)),+ $(,)?) => {
        $(
            #[doc = concat!("Verify the exact `", stringify!($code), "` production refusal.")]
            pub fn $name(
                observed: C2StoreGenerationRefusalV2,
            ) -> Result<(), RefusalClassificationMismatchV1> {
                verify_exact_refusal(
                    observed,
                    C2StoreGenerationRefusalCodeV2::$code,
                )
            }
        )+
    };
}

exact_refusal_verifiers!(
    (
        verify_n_19a_role_domain_key_cross_use_refusal,
        RoleDomainKeyCrossUse
    ),
    (verify_h32_01_refusal, ActivationWrongStoreOccurrence),
    (
        verify_h32_02_refusal,
        ActivationWrongPhysicalStoreGeneration
    ),
    (verify_h32_03_refusal, ActivationWrongResidentRoleGeneration),
    (verify_h32_04_refusal, ActivationWrongDomain),
    (verify_h32_05_refusal, SubstitutedActivationSameAnchor),
    (verify_h32_06_refusal, CanonicalBFromSqlite),
    (verify_h32_07_refusal, CanonicalBSelfAuthentication),
    (
        verify_h32_08_refusal,
        CanonicalGWithoutControllingActivation
    ),
    (verify_h32_09_refusal, CanonicalBGIdentityMismatch),
    (verify_h32_10_refusal, CopiedLockForeignOccurrence),
    (verify_h32_11_refusal, StaleLockAccepted),
    (verify_h32_12_refusal, LockBeforeAuthorityVerification),
    (verify_h32_13_refusal, LockOwnershipAsAuthority),
    (verify_h32_14_refusal, CallerSelectedBackend),
    (verify_h32_15_refusal, BackendStateAsBootstrapAuthority),
    (verify_h32_16_refusal, ClosedBackendCrossGenerationReuse),
    (verify_h32_17_refusal, CapacityBeforeBackendClosure),
    (verify_h32_21_refusal, WriterSessionBeforeC2Closure),
    (verify_h32_22_refusal, ActivationMintsWriterSession),
    (verify_h32_23_refusal, BackendMintsWriterSession),
    (verify_h32_24_refusal, PartialFailureResidualAuthority),
    (verify_h32_25_refusal, RestartSynthesizesMissingCarrier),
    (verify_h32_26_refusal, RecoveryFabricatesRuntimeAuthority),
    (verify_h32_27_refusal, CopiedStoreSimultaneousCurrentness),
    (verify_hr28_01_refusal, CallerMintedGenerationIdentity),
    (verify_hr28_02_refusal, PathOrSqliteGenerationInference),
    (verify_hr28_03_refusal, GenerationPolicyForkTieBreak),
    (verify_hr28_04_refusal, ActivationBindingMismatch),
    (verify_hr28_05_refusal, SameAnchorSubstitutedActivation),
    (verify_hr28_06_refusal, BFromSqliteOrSelfAuthentication),
    (verify_hr28_07_refusal, GWithoutControllingActivation),
    (verify_hr28_08_refusal, BGIdentityMismatch),
    (verify_hr28_09_refusal, StaleOrCopiedLock),
    (verify_hr28_10_refusal, LockAsAuthority),
    (verify_hr28_11_refusal, LockDomainAliasEscape),
    (verify_hr28_12_refusal, CopyLockDomainMismatch),
    (verify_hr28_13_refusal, CallerOrFeatureSelectedBackend),
    (verify_hr28_14_refusal, BackendStateAsAuthority),
    (
        verify_hr28_16_refusal,
        CapacityBeforeClosureOrBooleanSuccess
    ),
    (verify_hr28_19_refusal, SessionBeforeFullClosure),
    (verify_hr28_20_refusal, PartialFailureResidualStanding),
    (verify_hr28_21_refusal, RestartSynthesizesBG),
    (verify_hr28_22_refusal, RecoveryFabricatesAuthority),
    (verify_xh_01_refusal, ActivationWrongStoreOccurrence),
    (verify_xh_02_refusal, ActivationWrongPhysicalStoreGeneration),
    (verify_xh_03_refusal, ActivationWrongResidentRoleGeneration),
    (verify_xh_04_refusal, ActivationWrongDomain),
    (verify_xh_05_refusal, SameAnchorSubstitutedActivation),
    (verify_xh_06_refusal, BFromSqlite),
    (verify_xh_07_refusal, BSelfAuthentication),
    (verify_xh_08_refusal, GWithoutControllingActivation),
    (verify_xh_09_refusal, BGIdentityMismatch),
    (verify_xh_10_refusal, CallerMintedGenerationIdentity),
    (verify_xh_11_refusal, PathOrSqliteGenerationInference),
    (verify_xh_12_refusal, GenerationPolicyGap),
    (verify_xh_13_refusal, GenerationPolicyFork),
    (verify_xh_14_refusal, GenerationPolicyCycle),
    (verify_xh_15_refusal, GenerationPolicySameCutCollision),
    (verify_xh_16_refusal, GenerationPolicyTieBreak),
    (verify_xh_17_refusal, CopiedLock),
    (verify_xh_18_refusal, StaleLock),
    (verify_xh_19_refusal, LockBeforeAuthorityVerification),
    (verify_xh_20_refusal, LockAsAuthority),
    (verify_xh_21_refusal, LockDomainAliasEscape),
    (verify_xh_22_refusal, CopyLockDomainMismatch),
    (verify_xh_23_refusal, CallerSelectedBackend),
    (verify_xh_24_refusal, ConfigurationSelectedBackend),
    (verify_xh_25_refusal, FeatureFlagBackendSubstitution),
    (verify_xh_26_refusal, BackendAsBootstrapAuthority),
    (verify_xh_27_refusal, MockBackendProductionPath),
    (verify_xh_28_refusal, ProfileManifestMismatch),
    (verify_xh_29_refusal, BackendPreflightAsClosedStanding),
    (verify_xh_30_refusal, ClosedBackendCrossGenerationReuse),
    (verify_xh_31_refusal, CapacityBeforeBackendClosure),
    (verify_xh_37_refusal, WriterSessionBeforeC2Closure),
    (verify_xh_38_refusal, ActivationMintsWriterStanding),
    (verify_xh_39_refusal, LockMintsWriterStanding),
    (verify_xh_40_refusal, BackendMintsWriterStanding),
    (verify_xh_41_refusal, BMintsWriterStanding),
    (verify_xh_42_refusal, GMintsWriterStanding),
    (verify_xh_43_refusal, PartialFailureResidualAuthority),
    (verify_xh_44_refusal, PreS5GRecord),
    (verify_xh_45_refusal, RestartSynthesizesBG),
    (verify_xh_46_refusal, RecoveryFabricatesRuntimeAuthority),
    (verify_xh_47_refusal, RestoreWrongPredecessor),
    (verify_xh_48_refusal, RestoredCopyWithoutQuarantineClosure),
    (verify_xh_57_refusal, FailedConstructionExternalResidue),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_refusal_verifier_rejects_a_neighboring_classification() {
        let observed = C2StoreGenerationRefusalV2::from_code(
            C2StoreGenerationRefusalCodeV2::ActivationWrongStoreOccurrence,
        );
        assert!(verify_h32_01_refusal(observed).is_ok());
        assert_eq!(
            verify_h32_02_refusal(observed).unwrap_err(),
            RefusalClassificationMismatchV1 {
                expected: C2StoreGenerationRefusalCodeV2::ActivationWrongPhysicalStoreGeneration,
                observed: C2StoreGenerationRefusalCodeV2::ActivationWrongStoreOccurrence,
            }
        );
    }

    #[test]
    fn authority_amplification_has_distinct_closed_codes() {
        let activation = C2StoreGenerationRefusalV2::from_code(
            C2StoreGenerationRefusalCodeV2::ActivationMintsWriterStanding,
        );
        let backend = C2StoreGenerationRefusalV2::from_code(
            C2StoreGenerationRefusalCodeV2::BackendMintsWriterStanding,
        );
        assert_ne!(activation.code(), backend.code());
        assert!(verify_xh_38_refusal(activation).is_ok());
        assert!(verify_xh_40_refusal(backend).is_ok());
    }
}
