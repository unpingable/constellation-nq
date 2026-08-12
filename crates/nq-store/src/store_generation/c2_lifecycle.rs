//! Public, nominal orchestration surface for the live C2 Store lifecycle.
//!
//! `live_c2` owns every authority-bearing implementation value. This module
//! is its sole production facade. It exposes typed inert intents and exact
//! route-specific carrier wrappers, never a generic route selector, raw
//! authority tuple, digest-to-authority conversion, arbitrary signing input,
//! or detached-signature import path.
//!
//! Candidate freeze and qualification remain separate. A caller can name but
//! cannot construct [`StoreC2CandidateVerifierResultV1`]. Only the candidate
//! verifier bridge can seal its own exact verified result into that opaque
//! input. This implementation does not create a certificate, freeze a
//! candidate, or turn caller-authored identity coordinates into qualification.

use std::fmt;
use std::io;

use nq_protocol::Sha256Digest;
use nq_runtime_dependency_authority::{
    ControllingActivationSnapshot, GenesisAuthorityCustody, RestartExpectations,
    resolve_for_restart,
};
use serde_json::Value;
use thiserror::Error;

pub use super::candidate_qualification::C2CandidateVerificationRefusalV1;
use super::candidate_qualification::verify_candidate_certificate_for_current_runtime_v1;
use super::live_c2::{
    C2BootstrapOperatorInstallSelectionV1 as InternalC2BootstrapOperatorInstallSelectionV1,
    C2BootstrapPreparationIntentV1, C2GovernedCarrierIngressRefusalV1,
    C2HealthySuccessorIntentV1 as InternalC2HealthySuccessorIntentV1,
    C2LiveInstallationDriverRefusalV1, C2LiveSignerRefusalV1, C2LiveWriterSessionV1,
    C2RecoveryPredecessorStatusV1, C2RecoveryPreparationIntentV1,
    StoreC2QualifiedRuntimeEvidenceV1, StorePreparedBootstrapGrantRequestV1,
    StorePreparedRecoveryGrantRequestV1, VerifiedC2ExternalCandidateRuntimeRecordV1,
};
use super::records::{
    C2InstallationModeV1, C2InstalledCarrierGeometryV1, C2StructuralCutV1, InstallPolicyIdentityV1,
    QualifiedBackendProfileIdentityV1, RestoreInstallPredecessorV1,
};
use super::signer::external_governance::{
    DurableExternalIngressDispositionV1, DurableExternalIngressReceiptV1,
    DurableGovernedEffectDispositionV1, DurableQuarantineClosureEffectV1,
    DurableRevocationEffectV1, StoreIntegrityActivationSuccessorGrantRequestV1,
    StoreIntegrityActivationSuccessorGrantV1, StoreIntegrityBootstrapGrantV1,
    StoreIntegrityProposalDispositionRequestV1, StoreIntegrityProposalDispositionV1,
    StoreIntegrityQuarantineClosureJudgmentV1, StoreIntegrityQuarantineClosureRequestV1,
    StoreIntegrityRecoveryGrantV1, StoreIntegrityRestoreAuthorizationRequestV1,
    StoreIntegrityRestoreAuthorizationV1, StoreIntegrityRevocationJudgmentV1,
    StoreIntegrityRevocationRequestV1, construct_activation_successor_grant_request,
    construct_proposal_disposition_request, construct_quarantine_closure_request,
    construct_restore_authorization_request, construct_revocation_request,
    decode_quarantine_closure_judgment_v1, decode_restore_authorization_v1,
    decode_store_integrity_activation_successor_grant_v1,
    decode_store_integrity_bootstrap_grant_v1, decode_store_integrity_proposal_disposition_v1,
    decode_store_integrity_recovery_grant_v1, decode_store_integrity_revocation_judgment_v1,
};
use super::signer::manifest::{
    SignerImplementationManifestRefusalV1, StoreIntegritySignerImplementationManifestV1,
    decode_signer_implementation_manifest_v1,
};
use crate::{RuntimeAuthorityRestartSnapshot, Store, StoreError};

/// Opaque output of the detached candidate/runtime verifier.
///
/// This is inert evidence, not manifest admission, signer standing, a writer
/// capability, or a live Store brand. It is intentionally nonserializable,
/// non-`Clone`, non-`Copy`, and has no public constructor.
pub struct StoreC2CandidateVerifierResultV1 {
    evidence: StoreC2QualifiedRuntimeEvidenceV1,
}

/// Sole owner of the bridge from detached candidate verification into C2.
///
/// The verifier itself is opaque and has no public constructor. The
/// qualification-trust verifier lives inside `nq-store`, authenticates its
/// exact detached certificate, checks the manifest basis and running-image
/// measurement, and then calls the private sealing seam below. External
/// callers cannot implement or impersonate it.
pub struct StoreC2CandidateRuntimeVerifierV1 {
    _private: (),
}

impl StoreC2CandidateRuntimeVerifierV1 {
    /// Authenticate the canonical candidate certificate against the distinct
    /// fixed qualification trust source and the exact running image.
    ///
    /// Certificate bytes, manifest evidence, and their digests remain inert.
    /// This Store-owned verifier is the sole production mint for the opaque,
    /// process-local lifecycle prerequisite.
    pub fn verify_candidate_runtime(
        certificate_bytes: &[u8],
        manifest: &C2SignerImplementationManifestV1,
    ) -> Result<StoreC2CandidateVerifierResultV1, C2CandidateVerificationRefusalV1> {
        let certificate = verify_candidate_certificate_for_current_runtime_v1(
            certificate_bytes,
            manifest.inner(),
        )?;
        let verified =
            VerifiedC2ExternalCandidateRuntimeRecordV1::from_authenticated_candidate_certificate(
                certificate,
            );
        Ok(Self::seal_verified_candidate_runtime(verified))
    }

    /// Production certificate-to-lifecycle entry demonstration.
    ///
    /// The verifier result remains inside this dynamic extent. Every actual
    /// lifecycle operation still rechecks Store, manifest, runtime, process,
    /// and currentness correspondence through [`Store::c2_lifecycle_v1`].
    pub fn with_verified_c2_lifecycle<R>(
        store: &mut Store,
        certificate_bytes: &[u8],
        manifest: &C2SignerImplementationManifestV1,
        operation: impl FnOnce(&mut StoreC2LifecycleV1<'_>) -> R,
    ) -> Result<R, C2CandidateVerificationRefusalV1> {
        let verified = Self::verify_candidate_runtime(certificate_bytes, manifest)?;
        let mut lifecycle = store.c2_lifecycle_v1(&verified, manifest);
        Ok(operation(&mut lifecycle))
    }

    /// Qualification-owned bridge from an already sealed verifier record.
    /// No raw candidate/tree/artifact/manifest coordinate enters this method.
    pub(crate) fn seal_verified_candidate_runtime(
        verified: VerifiedC2ExternalCandidateRuntimeRecordV1,
    ) -> StoreC2CandidateVerifierResultV1 {
        StoreC2CandidateVerifierResultV1 {
            evidence: StoreC2QualifiedRuntimeEvidenceV1::from_verified_external_candidate(verified),
        }
    }
}

impl StoreC2CandidateVerifierResultV1 {
    const fn evidence(&self) -> &StoreC2QualifiedRuntimeEvidenceV1 {
        &self.evidence
    }
}

/// Canonical signer implementation-manifest evidence.
///
/// Parsing and possession do not admit the manifest or create authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2SignerImplementationManifestV1 {
    inner: StoreIntegritySignerImplementationManifestV1,
}

impl C2SignerImplementationManifestV1 {
    /// Decode exactly one RFC-8785 canonical manifest record.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, C2LifecycleInputRefusalV1> {
        decode_signer_implementation_manifest_v1(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| C2LifecycleInputRefusalV1::new(C2LifecycleInputKindV1::Manifest))
    }

    /// Exact manifest identity. The digest is evidence only.
    #[must_use]
    pub fn manifest_identity(&self) -> &Sha256Digest {
        self.inner.manifest_identity()
    }

    fn inner(&self) -> &StoreIntegritySignerImplementationManifestV1 {
        &self.inner
    }
}

/// Exact non-authority inputs used to re-run current-A2 verification inside
/// the Store-owned snapshot.
pub struct C2CurrentAuthorityVerificationV1<'input> {
    custody: &'input GenesisAuthorityCustody,
    expectations: &'input RestartExpectations,
}

impl<'input> C2CurrentAuthorityVerificationV1<'input> {
    /// Bind exact custody and restart expectations for one operation.
    #[must_use]
    pub const fn new(
        custody: &'input GenesisAuthorityCustody,
        expectations: &'input RestartExpectations,
    ) -> Self {
        Self {
            custody,
            expectations,
        }
    }

    fn resolve(
        &self,
        snapshot: &RuntimeAuthorityRestartSnapshot,
    ) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1> {
        resolve_for_restart(
            self.custody,
            &snapshot.presented,
            snapshot.migration_receipt.as_ref(),
            self.expectations,
        )
        .map_err(StoreError::from)
        .map_err(C2LiveSignerRefusalV1::Store)
    }
}

/// Inert operator/install selection for a bootstrap pre-policy.
///
/// The Store derives the complete authority tuple later from the freshly
/// resolved current activation. This public value contains no occurrence,
/// activation, resident, role, authority-cut, or other caller-authored
/// authority coordinate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2BootstrapInstallSelectionV1 {
    pub operator_installation_nonce: String,
    pub installation_cut: C2StructuralCutV1,
    pub mode: C2InstallationModeV1,
    pub restore_predecessor: Option<RestoreInstallPredecessorV1>,
    pub geometry: C2InstalledCarrierGeometryV1,
    pub qualified_backend_profile: QualifiedBackendProfileIdentityV1,
    pub maximum_policy_generations: u32,
    pub maximum_key_generations: u32,
    pub predecessor_install_policy: Option<InstallPolicyIdentityV1>,
}

impl From<C2BootstrapInstallSelectionV1> for InternalC2BootstrapOperatorInstallSelectionV1 {
    fn from(value: C2BootstrapInstallSelectionV1) -> Self {
        InternalC2BootstrapOperatorInstallSelectionV1 {
            operator_installation_nonce: value.operator_installation_nonce,
            installation_cut: value.installation_cut,
            mode: value.mode,
            restore_predecessor: value.restore_predecessor,
            geometry: value.geometry,
            qualified_backend_profile: value.qualified_backend_profile,
            maximum_policy_generations: value.maximum_policy_generations,
            maximum_key_generations: value.maximum_key_generations,
            predecessor_install_policy: value.predecessor_install_policy,
        }
    }
}

/// Inert bootstrap request intent. It carries no grant or live authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2BootstrapIntentV1 {
    inner: C2BootstrapPreparationIntentV1,
}

impl C2BootstrapIntentV1 {
    /// Construct a checked bootstrap intent; all identities remain evidence.
    pub fn new(
        role_manifest_identity: Sha256Digest,
        signer_scope_policy_identity: Sha256Digest,
        selection: C2BootstrapInstallSelectionV1,
    ) -> Result<Self, C2LifecycleInputRefusalV1> {
        C2BootstrapPreparationIntentV1::from_operator_install_selection(
            role_manifest_identity,
            signer_scope_policy_identity,
            selection.into(),
        )
        .map(|inner| Self { inner })
        .map_err(|_| C2LifecycleInputRefusalV1::new(C2LifecycleInputKindV1::BootstrapIntent))
    }
}

/// Inert healthy-successor intent. The Store supplies all authority-bearing
/// predecessor, custody, policy, and phase correspondence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2HealthySuccessorIntentV1 {
    inner: InternalC2HealthySuccessorIntentV1,
}

impl C2HealthySuccessorIntentV1 {
    /// Construct one checked successor transition/challenge occurrence.
    pub fn new(
        transition_identity: Sha256Digest,
        successor_pop_challenge_identity: Sha256Digest,
        transition_cut: u64,
    ) -> Result<Self, C2LifecycleInputRefusalV1> {
        super::live_c2::C2HealthySuccessorIntentV1::new(
            transition_identity,
            successor_pop_challenge_identity,
            transition_cut,
        )
        .map(|inner| Self { inner })
        .map_err(|_| C2LifecycleInputRefusalV1::new(C2LifecycleInputKindV1::HealthyIntent))
    }
}

/// Closed discontinuity condition requested for recovery preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2RecoveryConditionV1 {
    ActiveLost,
    InactiveRevoked,
}

impl From<C2RecoveryConditionV1> for C2RecoveryPredecessorStatusV1 {
    fn from(value: C2RecoveryConditionV1) -> Self {
        match value {
            C2RecoveryConditionV1::ActiveLost => Self::ActiveLost,
            C2RecoveryConditionV1::InactiveRevoked => Self::InactiveRevoked,
        }
    }
}

/// Inert recovery preparation intent. It cannot select a predecessor,
/// foundation, key, custody value, or live discontinuity authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2RecoveryIntentV1 {
    inner: C2RecoveryPreparationIntentV1,
}

impl C2RecoveryIntentV1 {
    /// Construct one checked recovery request occurrence.
    pub fn new(
        condition: C2RecoveryConditionV1,
        recovery_transition_identity: Sha256Digest,
        successor_pop_challenge_identity: Sha256Digest,
    ) -> Result<Self, C2LifecycleInputRefusalV1> {
        C2RecoveryPreparationIntentV1::new(
            condition.into(),
            recovery_transition_identity,
            successor_pop_challenge_identity,
        )
        .map(|inner| Self { inner })
        .map_err(|_| C2LifecycleInputRefusalV1::new(C2LifecycleInputKindV1::RecoveryIntent))
    }
}

fn exact_request<T>(
    bytes: &[u8],
    construct: impl FnOnce(Value) -> Result<T, super::signer::result::SignerRefusalV2>,
    canonical: impl FnOnce(&T) -> &[u8],
    kind: C2LifecycleInputKindV1,
) -> Result<T, C2LifecycleInputRefusalV1> {
    let value = serde_json::from_slice(bytes).map_err(|_| C2LifecycleInputRefusalV1::new(kind))?;
    let request = construct(value).map_err(|_| C2LifecycleInputRefusalV1::new(kind))?;
    if canonical(&request) != bytes {
        return Err(C2LifecycleInputRefusalV1::new(kind));
    }
    Ok(request)
}

macro_rules! request_wrapper {
    ($public:ident, $inner:ident, $construct:ident, $kind:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $public {
            inner: $inner,
        }

        impl $public {
            pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, C2LifecycleInputRefusalV1> {
                exact_request(
                    bytes,
                    $construct,
                    |value| value.canonical_bytes(),
                    C2LifecycleInputKindV1::$kind,
                )
                .map(|inner| Self { inner })
            }

            #[must_use]
            pub fn canonical_bytes(&self) -> &[u8] {
                self.inner.canonical_bytes()
            }
        }
    };
}

macro_rules! carrier_wrapper {
    ($public:ident, $inner:ident, $decode:ident, $kind:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $public {
            inner: $inner,
        }

        impl $public {
            pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, C2LifecycleInputRefusalV1> {
                $decode(bytes)
                    .map(|inner| Self { inner })
                    .map_err(|_| C2LifecycleInputRefusalV1::new(C2LifecycleInputKindV1::$kind))
            }

            #[must_use]
            pub fn canonical_bytes(&self) -> &[u8] {
                self.inner.canonical_bytes()
            }
        }
    };
}

request_wrapper!(
    C2ActivationSuccessorGrantRequestV1,
    StoreIntegrityActivationSuccessorGrantRequestV1,
    construct_activation_successor_grant_request,
    ActivationSuccessorGrantRequest
);
carrier_wrapper!(
    C2ActivationSuccessorGrantV1,
    StoreIntegrityActivationSuccessorGrantV1,
    decode_store_integrity_activation_successor_grant_v1,
    ActivationSuccessorGrant
);
request_wrapper!(
    C2RestoreAuthorizationRequestV1,
    StoreIntegrityRestoreAuthorizationRequestV1,
    construct_restore_authorization_request,
    RestoreAuthorizationRequest
);
carrier_wrapper!(
    C2RestoreAuthorizationV1,
    StoreIntegrityRestoreAuthorizationV1,
    decode_restore_authorization_v1,
    RestoreAuthorization
);
carrier_wrapper!(
    C2BootstrapGrantV1,
    StoreIntegrityBootstrapGrantV1,
    decode_store_integrity_bootstrap_grant_v1,
    BootstrapGrant
);
carrier_wrapper!(
    C2RecoveryGrantV1,
    StoreIntegrityRecoveryGrantV1,
    decode_store_integrity_recovery_grant_v1,
    RecoveryGrant
);
request_wrapper!(
    C2ProposalDispositionRequestV1,
    StoreIntegrityProposalDispositionRequestV1,
    construct_proposal_disposition_request,
    ProposalDispositionRequest
);
carrier_wrapper!(
    C2ProposalDispositionV1,
    StoreIntegrityProposalDispositionV1,
    decode_store_integrity_proposal_disposition_v1,
    ProposalDisposition
);
request_wrapper!(
    C2RevocationRequestV1,
    StoreIntegrityRevocationRequestV1,
    construct_revocation_request,
    RevocationRequest
);
carrier_wrapper!(
    C2RevocationJudgmentV1,
    StoreIntegrityRevocationJudgmentV1,
    decode_store_integrity_revocation_judgment_v1,
    RevocationJudgment
);
request_wrapper!(
    C2QuarantineClosureRequestV1,
    StoreIntegrityQuarantineClosureRequestV1,
    construct_quarantine_closure_request,
    QuarantineClosureRequest
);
carrier_wrapper!(
    C2QuarantineClosureJudgmentV1,
    StoreIntegrityQuarantineClosureJudgmentV1,
    decode_quarantine_closure_judgment_v1,
    QuarantineClosureJudgment
);

/// Inert Store-prepared bootstrap request crossing the asynchronous A1 seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2PreparedBootstrapGrantRequestV1 {
    inner: StorePreparedBootstrapGrantRequestV1,
}

impl C2PreparedBootstrapGrantRequestV1 {
    #[must_use]
    pub fn preparation_identity(&self) -> &Sha256Digest {
        self.inner.preparation_identity()
    }

    #[must_use]
    pub fn canonical_request_bytes(&self) -> &[u8] {
        self.inner.request().canonical_bytes()
    }
}

/// Inert Store-prepared recovery request crossing the asynchronous A1 seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2PreparedRecoveryGrantRequestV1 {
    inner: StorePreparedRecoveryGrantRequestV1,
}

impl C2PreparedRecoveryGrantRequestV1 {
    #[must_use]
    pub fn preparation_identity(&self) -> &Sha256Digest {
        self.inner.preparation_identity()
    }

    #[must_use]
    pub fn canonical_request_bytes(&self) -> &[u8] {
        self.inner.request().canonical_bytes()
    }
}

/// Public no-authority receipt from exact governed carrier ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2GovernedIngressReceiptV1 {
    inner: DurableExternalIngressReceiptV1,
}

impl C2GovernedIngressReceiptV1 {
    #[must_use]
    pub const fn ingress_sequence(&self) -> u64 {
        self.inner.ingress_sequence
    }

    #[must_use]
    pub fn receipt_identity(&self) -> &str {
        &self.inner.receipt_identity
    }

    #[must_use]
    pub fn canonical_receipt_bytes(&self) -> &[u8] {
        &self.inner.receipt_bytes
    }

    #[must_use]
    pub const fn disposition(&self) -> C2DurableDispositionV1 {
        match self.inner.disposition {
            DurableExternalIngressDispositionV1::Appended => C2DurableDispositionV1::Appended,
            DurableExternalIngressDispositionV1::ExactReplay => C2DurableDispositionV1::ExactReplay,
        }
    }
}

/// Public durable effect disposition; it carries no live authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2DurableDispositionV1 {
    Appended,
    ExactReplay,
}

fn governed_effect_disposition(
    value: DurableGovernedEffectDispositionV1,
) -> C2DurableDispositionV1 {
    match value {
        DurableGovernedEffectDispositionV1::Appended => C2DurableDispositionV1::Appended,
        DurableGovernedEffectDispositionV1::ExactReplay => C2DurableDispositionV1::ExactReplay,
    }
}

/// Durable MSG-14 revocation effect evidence.
#[derive(Debug)]
pub struct C2RevocationEffectV1 {
    inner: DurableRevocationEffectV1,
}

impl C2RevocationEffectV1 {
    #[must_use]
    pub fn disposition(&self) -> C2DurableDispositionV1 {
        governed_effect_disposition(self.inner.disposition())
    }

    #[must_use]
    pub fn canonical_receipt_bytes(&self) -> &[u8] {
        self.inner.receipt().canonical_bytes()
    }
}

/// Durable MSG-16 quarantine-closure effect evidence.
#[derive(Debug)]
pub struct C2QuarantineClosureEffectV1 {
    inner: DurableQuarantineClosureEffectV1,
}

impl C2QuarantineClosureEffectV1 {
    #[must_use]
    pub fn disposition(&self) -> C2DurableDispositionV1 {
        governed_effect_disposition(self.inner.disposition())
    }

    #[must_use]
    pub fn canonical_receipt_bytes(&self) -> &[u8] {
        self.inner.receipt().canonical_bytes()
    }
}

/// One public Store-owned facade for all live-C2 lifecycle operations.
/// Holding it does not grant authority; every call re-verifies the complete
/// Store/process/runtime/manifest/currentness correspondence.
pub struct StoreC2LifecycleV1<'store> {
    store: &'store mut Store,
    verified_candidate: &'store StoreC2CandidateVerifierResultV1,
    manifest: &'store C2SignerImplementationManifestV1,
}

impl Store {
    /// Enter the sole public live-C2 orchestration surface.
    pub fn c2_lifecycle_v1<'store>(
        &'store mut self,
        verified_candidate: &'store StoreC2CandidateVerifierResultV1,
        manifest: &'store C2SignerImplementationManifestV1,
    ) -> StoreC2LifecycleV1<'store> {
        StoreC2LifecycleV1 {
            store: self,
            verified_candidate,
            manifest,
        }
    }
}

impl StoreC2LifecycleV1<'_> {
    pub fn prepare_bootstrap(
        &mut self,
        intent: &C2BootstrapIntentV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<C2PreparedBootstrapGrantRequestV1, C2LifecycleRefusalV1> {
        self.store
            .prepare_c2_live_bootstrap_v1(
                self.verified_candidate.evidence(),
                self.manifest.inner(),
                &intent.inner,
                |snapshot| authority.resolve(snapshot),
            )
            .map(|inner| C2PreparedBootstrapGrantRequestV1 { inner })
            .map_err(|error| {
                C2LifecycleRefusalV1::from_error(
                    C2LifecycleRefusalCodeV1::BootstrapPreparation,
                    error,
                )
            })
    }

    pub fn complete_bootstrap(
        &mut self,
        grant: &C2BootstrapGrantV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<(), C2LifecycleRefusalV1> {
        self.store
            .install_c2_live_from_bootstrap_grant_v1(
                self.verified_candidate.evidence(),
                self.manifest.inner(),
                &grant.inner,
                |snapshot| authority.resolve(snapshot),
            )
            .map_err(|error| {
                C2LifecycleRefusalV1::from_error(
                    C2LifecycleRefusalCodeV1::BootstrapCompletion,
                    error,
                )
            })
    }

    pub fn rotate_healthy_successor(
        &mut self,
        intent: &C2HealthySuccessorIntentV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<Sha256Digest, C2LifecycleRefusalV1> {
        self.store
            .rotate_c2_live_healthy_successor_v1(
                self.verified_candidate.evidence(),
                self.manifest.inner(),
                &intent.inner,
                |snapshot| authority.resolve(snapshot),
            )
            .map_err(|error| {
                C2LifecycleRefusalV1::from_error(C2LifecycleRefusalCodeV1::HealthySuccessor, error)
            })
    }

    pub fn rotate_healthy_successor_with_activation_grant(
        &mut self,
        intent: &C2HealthySuccessorIntentV1,
        request: &C2ActivationSuccessorGrantRequestV1,
        grant: &C2ActivationSuccessorGrantV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<Sha256Digest, C2LifecycleRefusalV1> {
        self.store
            .rotate_c2_live_healthy_successor_with_activation_grant_v1(
                self.verified_candidate.evidence(),
                self.manifest.inner(),
                &intent.inner,
                &request.inner,
                &grant.inner,
                |snapshot| authority.resolve(snapshot),
            )
            .map_err(|error| {
                C2LifecycleRefusalV1::from_error(C2LifecycleRefusalCodeV1::HealthySuccessor, error)
            })
    }

    pub fn restore_historical_foundation(
        &mut self,
        request: &C2RestoreAuthorizationRequestV1,
        authorization: &C2RestoreAuthorizationV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<Sha256Digest, C2LifecycleRefusalV1> {
        self.store
            .restore_c2_live_historical_foundation_v1(
                self.verified_candidate.evidence(),
                self.manifest.inner(),
                &request.inner,
                &authorization.inner,
                |snapshot| authority.resolve(snapshot),
            )
            .map_err(|error| {
                C2LifecycleRefusalV1::from_error(C2LifecycleRefusalCodeV1::Restore, error)
            })
    }

    pub fn prepare_recovery(
        &mut self,
        intent: &C2RecoveryIntentV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<C2PreparedRecoveryGrantRequestV1, C2LifecycleRefusalV1> {
        self.store
            .prepare_c2_live_recovery_v1(
                self.verified_candidate.evidence(),
                self.manifest.inner(),
                &intent.inner,
                |snapshot| authority.resolve(snapshot),
            )
            .map(|inner| C2PreparedRecoveryGrantRequestV1 { inner })
            .map_err(|error| {
                C2LifecycleRefusalV1::from_error(
                    C2LifecycleRefusalCodeV1::RecoveryPreparation,
                    error,
                )
            })
    }

    pub fn complete_recovery(
        &mut self,
        prepared: &C2PreparedRecoveryGrantRequestV1,
        grant: &C2RecoveryGrantV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<Sha256Digest, C2LifecycleRefusalV1> {
        self.store
            .recover_c2_live_new_foundation_v1(
                self.verified_candidate.evidence(),
                self.manifest.inner(),
                prepared.inner.request(),
                &grant.inner,
                |snapshot| authority.resolve(snapshot),
            )
            .map_err(|error| {
                C2LifecycleRefusalV1::from_error(
                    C2LifecycleRefusalCodeV1::RecoveryCompletion,
                    error,
                )
            })
    }

    pub fn with_current_writer<R>(
        &mut self,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
        operation: impl for<'borrow, 'session, 'live, 'snapshot> FnOnce(
            &'borrow mut C2CurrentWriterV1<'borrow, 'session, 'live, 'snapshot>,
        ) -> Result<
            R,
            C2LifecycleRefusalV1,
        >,
    ) -> Result<R, C2LifecycleRefusalV1> {
        self.store.with_reopened_c2_generation_current_v1(
            self.verified_candidate.evidence(),
            self.manifest.inner(),
            |snapshot| authority.resolve(snapshot),
            |session| {
                let mut writer = C2CurrentWriterV1 { inner: session };
                operation(&mut writer)
            },
        )
    }

    pub fn adopt_proposal_disposition(
        &mut self,
        request: &C2ProposalDispositionRequestV1,
        disposition: &C2ProposalDispositionV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<C2GovernedIngressReceiptV1, C2LifecycleRefusalV1> {
        self.with_current_writer(authority, |writer| {
            writer.adopt_proposal_disposition(request, disposition)
        })
    }

    pub fn apply_revocation_judgment(
        &mut self,
        request: &C2RevocationRequestV1,
        judgment: &C2RevocationJudgmentV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<C2RevocationEffectV1, C2LifecycleRefusalV1> {
        self.with_current_writer(authority, |writer| {
            writer.apply_revocation_judgment(request, judgment)
        })
    }

    pub fn apply_quarantine_closure(
        &mut self,
        restore_request: &C2RestoreAuthorizationRequestV1,
        restore_authorization: &C2RestoreAuthorizationV1,
        request: &C2QuarantineClosureRequestV1,
        judgment: &C2QuarantineClosureJudgmentV1,
        authority: &C2CurrentAuthorityVerificationV1<'_>,
    ) -> Result<C2QuarantineClosureEffectV1, C2LifecycleRefusalV1> {
        self.with_current_writer(authority, |writer| {
            writer.apply_quarantine_closure(
                restore_request,
                restore_authorization,
                request,
                judgment,
            )
        })
    }
}

/// Public restricted view of one freshly reopened C2 writer session.
/// Its private borrowed inner value cannot escape the callback or serialize.
pub struct C2CurrentWriterV1<'borrow, 'session, 'live, 'store> {
    inner: &'borrow mut C2LiveWriterSessionV1<'session, 'live, 'store>,
}

impl C2CurrentWriterV1<'_, '_, '_, '_> {
    pub fn verify_live(&self) -> Result<(), C2LifecycleRefusalV1> {
        self.inner.verify_live().map_err(Into::into)
    }

    pub fn adopt_proposal_disposition(
        &mut self,
        request: &C2ProposalDispositionRequestV1,
        disposition: &C2ProposalDispositionV1,
    ) -> Result<C2GovernedIngressReceiptV1, C2LifecycleRefusalV1> {
        self.inner
            .adopt_proposal_disposition(&request.inner, &disposition.inner)
            .map(|adopted| C2GovernedIngressReceiptV1 {
                inner: adopted.durable_receipt().clone(),
            })
            .map_err(Into::into)
    }

    pub fn apply_revocation_judgment(
        &mut self,
        request: &C2RevocationRequestV1,
        judgment: &C2RevocationJudgmentV1,
    ) -> Result<C2RevocationEffectV1, C2LifecycleRefusalV1> {
        self.inner
            .apply_revocation_judgment(&request.inner, &judgment.inner)
            .map(|inner| C2RevocationEffectV1 { inner })
            .map_err(Into::into)
    }

    pub fn apply_quarantine_closure(
        &mut self,
        restore_request: &C2RestoreAuthorizationRequestV1,
        restore_authorization: &C2RestoreAuthorizationV1,
        request: &C2QuarantineClosureRequestV1,
        judgment: &C2QuarantineClosureJudgmentV1,
    ) -> Result<C2QuarantineClosureEffectV1, C2LifecycleRefusalV1> {
        let adopted = self
            .inner
            .adopt_restore_authorization(&restore_request.inner, &restore_authorization.inner)?;
        self.inner
            .apply_quarantine_closure_judgment(&adopted, &request.inner, &judgment.inner)
            .map(|inner| C2QuarantineClosureEffectV1 { inner })
            .map_err(Into::into)
    }
}

/// Public lifecycle refusal category. The detailed internal refusal is
/// presentation only and cannot be converted back into authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2LifecycleRefusalCodeV1 {
    AuthorityCorrespondence,
    ManifestAdmission,
    BootstrapPreparation,
    BootstrapCompletion,
    HealthySuccessor,
    Restore,
    RecoveryPreparation,
    RecoveryCompletion,
    Reopen,
    GovernedIngress,
}

/// Fail-closed public lifecycle refusal. It carries no live value.
#[derive(Debug, Error)]
#[error("C2 lifecycle refused ({code:?}): {detail}")]
pub struct C2LifecycleRefusalV1 {
    code: C2LifecycleRefusalCodeV1,
    detail: String,
}

impl C2LifecycleRefusalV1 {
    fn from_error(code: C2LifecycleRefusalCodeV1, error: impl fmt::Display) -> Self {
        Self {
            code,
            detail: error.to_string(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> C2LifecycleRefusalCodeV1 {
        self.code
    }
}

impl From<C2LiveSignerRefusalV1> for C2LifecycleRefusalV1 {
    fn from(error: C2LiveSignerRefusalV1) -> Self {
        Self::from_error(C2LifecycleRefusalCodeV1::AuthorityCorrespondence, error)
    }
}

impl From<SignerImplementationManifestRefusalV1> for C2LifecycleRefusalV1 {
    fn from(error: SignerImplementationManifestRefusalV1) -> Self {
        Self::from_error(C2LifecycleRefusalCodeV1::ManifestAdmission, error)
    }
}

impl From<C2LiveInstallationDriverRefusalV1> for C2LifecycleRefusalV1 {
    fn from(error: C2LiveInstallationDriverRefusalV1) -> Self {
        Self::from_error(C2LifecycleRefusalCodeV1::Reopen, error)
    }
}

impl From<C2GovernedCarrierIngressRefusalV1> for C2LifecycleRefusalV1 {
    fn from(error: C2GovernedCarrierIngressRefusalV1) -> Self {
        Self::from_error(C2LifecycleRefusalCodeV1::GovernedIngress, error)
    }
}

impl From<StoreError> for C2LifecycleRefusalV1 {
    fn from(error: StoreError) -> Self {
        Self::from_error(C2LifecycleRefusalCodeV1::AuthorityCorrespondence, error)
    }
}

impl From<io::Error> for C2LifecycleRefusalV1 {
    fn from(error: io::Error) -> Self {
        Self::from_error(C2LifecycleRefusalCodeV1::AuthorityCorrespondence, error)
    }
}

/// Closed input category for canonical parsing/smart-constructor refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C2LifecycleInputKindV1 {
    Manifest,
    BootstrapIntent,
    HealthyIntent,
    RecoveryIntent,
    BootstrapGrant,
    ActivationSuccessorGrantRequest,
    ActivationSuccessorGrant,
    RestoreAuthorizationRequest,
    RestoreAuthorization,
    RecoveryGrant,
    ProposalDispositionRequest,
    ProposalDisposition,
    RevocationRequest,
    RevocationJudgment,
    QuarantineClosureRequest,
    QuarantineClosureJudgment,
}

/// Refusal to construct one exact inert lifecycle input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("malformed or noncanonical C2 lifecycle input: {kind:?}")]
pub struct C2LifecycleInputRefusalV1 {
    kind: C2LifecycleInputKindV1,
}

impl C2LifecycleInputRefusalV1 {
    const fn new(kind: C2LifecycleInputKindV1) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> C2LifecycleInputKindV1 {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn facade_non_test_body_reaches_every_closed_store_root() {
        let source = include_str!("c2_lifecycle.rs");
        let non_test = source
            .split(concat!("#[cfg", "(test)]"))
            .next()
            .expect("module has a non-test body");
        for root in [
            concat!("prepare_c2_live_", "bootstrap_v1"),
            concat!("install_c2_live_from_", "bootstrap_grant_v1"),
            concat!("rotate_c2_live_", "healthy_successor_v1"),
            concat!(
                "rotate_c2_live_healthy_successor_",
                "with_activation_grant_v1"
            ),
            concat!("restore_c2_live_", "historical_foundation_v1"),
            concat!("prepare_c2_live_", "recovery_v1"),
            concat!("recover_c2_live_", "new_foundation_v1"),
            concat!("with_reopened_c2_", "generation_current_v1"),
        ] {
            assert!(
                non_test.contains(root),
                "missing non-test facade call to {root}"
            );
        }
    }

    #[test]
    fn facade_has_nominal_operations_and_no_generic_route_operation() {
        let source = include_str!("c2_lifecycle.rs");
        let non_test = source
            .split(concat!("#[cfg", "(test)]"))
            .next()
            .expect("module has a non-test body");
        for operation in [
            concat!("fn prepare_", "bootstrap"),
            concat!("fn complete_", "bootstrap"),
            concat!("fn rotate_", "healthy_successor"),
            concat!("fn restore_", "historical_foundation"),
            concat!("fn prepare_", "recovery"),
            concat!("fn complete_", "recovery"),
            concat!("fn with_current_", "writer"),
            concat!("fn adopt_proposal_", "disposition"),
            concat!("fn apply_revocation_", "judgment"),
            concat!("fn apply_quarantine_", "closure"),
        ] {
            assert!(
                non_test.contains(operation),
                "missing nominal operation {operation}"
            );
        }
        assert!(!non_test.contains(concat!("fn execute_", "route")));
        assert!(!non_test.contains(concat!("fn sign_", "bytes")));
        assert!(!non_test.contains(concat!("fn sign_", "digest")));
    }

    #[test]
    fn bootstrap_facade_exposes_no_raw_authority_tuple() {
        let facade = include_str!("c2_lifecycle.rs");
        let non_test = facade
            .split(concat!("#[cfg", "(test)]"))
            .next()
            .expect("module has a non-test body");
        assert!(non_test.contains("C2BootstrapInstallSelectionV1"));
        assert!(!non_test.contains(concat!("C2InstallAuthority", "TupleV1")));
        assert!(!non_test.contains("pub authority:"));

        let implementation = include_str!("live_c2.rs");
        let bootstrap_root = implementation
            .split("fn prepare_initial_bootstrap_grant_request_v1")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn reopen_prepared_bootstrap_custodian_v1")
                    .next()
            })
            .expect("bounded bootstrap preparation root");
        assert!(bootstrap_root.contains("let current = authority.current_activation()"));
        assert!(bootstrap_root.contains(concat!("authority: C2InstallAuthority", "TupleV1")));
        assert!(bootstrap_root.contains("current.controlling_tip_activation_digest()"));
        assert!(bootstrap_root.contains("current.resolution_cut()"));
    }
}
