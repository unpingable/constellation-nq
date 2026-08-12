//! The single closed MSG-01 through MSG-16 signer vocabulary.
//!
//! Family, route, phase, domain, verified-input class, scope class, authority
//! class, and sole consumer are selected together here.  No second signing
//! taxonomy is authoritative.  The production signing boundary consumes only
//! the sealed, route-specific message types defined in this module.

use nq_protocol::{canonical_json_bytes, sha256_bytes};
use serde::Serialize;

use super::coordinator::CoordinatorMessageConstructionPermitV1;
use super::records::VerifiedInitialPossessionRequestV1;
use super::result::SignerRefusalV2;
use crate::store_generation::live_c2::{
    C2LiveSignerRefusalV1, C2LiveSigningAuthorityV1, C2LiveSigningScopeV1, C2LiveSigningViewV1,
    StoreC2SignerAppendPermitV1, StoreC2SnapshotActorV1,
};

/// Stable 256-bit identity used inside the closed signer surface.
pub(super) type SignerIdentityV1 = [u8; 32];

/// Coordinates that custody rechecks for every Store/proposal-key signature.
///
/// These coordinates are evidence only.  They cannot construct a signer
/// capability; the coordinator additionally requires the appropriate sealed
/// live phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignerMessageCoordinatesV1 {
    pub(crate) occurrence: SignerIdentityV1,
    pub(crate) physical_generation: SignerIdentityV1,
    pub(crate) lifecycle_root: SignerIdentityV1,
    pub(crate) scope: SignerIdentityV1,
    pub(crate) policy: SignerIdentityV1,
    pub(crate) signer_key_generation: SignerIdentityV1,
    pub(crate) cut: u64,
}

impl SignerMessageCoordinatesV1 {
    fn validate(&self) -> Result<(), SignerRefusalV2> {
        if self.cut == 0
            || [
                self.occurrence,
                self.scope,
                self.policy,
                self.signer_key_generation,
            ]
            .iter()
            .any(is_zero)
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(())
    }
}

/// Exact tagged scope correspondence selected by Store-owned phase resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum C2ExactSigningScopeV1 {
    PreGeneration {
        scope_identity: SignerIdentityV1,
        attempt_identity: SignerIdentityV1,
    },
    ProspectivePhysicalGeneration {
        scope_identity: SignerIdentityV1,
        generation_preimage_identity: SignerIdentityV1,
        attempt_identity: SignerIdentityV1,
    },
    GenerationBound {
        scope_identity: SignerIdentityV1,
        physical_generation_identity: SignerIdentityV1,
        lifecycle_root_identity: SignerIdentityV1,
    },
}

impl C2ExactSigningScopeV1 {
    fn class(self) -> C2SigningScopeClassV1 {
        match self {
            Self::PreGeneration { .. } => C2SigningScopeClassV1::PreGeneration,
            Self::ProspectivePhysicalGeneration { .. } => {
                C2SigningScopeClassV1::ProspectivePhysicalGeneration
            }
            Self::GenerationBound { .. } => C2SigningScopeClassV1::GenerationBound,
        }
    }

    pub(super) fn physical_generation(self) -> Option<SignerIdentityV1> {
        match self {
            Self::GenerationBound {
                physical_generation_identity,
                ..
            } => Some(physical_generation_identity),
            Self::PreGeneration { .. } | Self::ProspectivePhysicalGeneration { .. } => None,
        }
    }

    pub(super) fn lifecycle_root(self) -> Option<SignerIdentityV1> {
        match self {
            Self::GenerationBound {
                lifecycle_root_identity,
                ..
            } => Some(lifecycle_root_identity),
            Self::PreGeneration { .. } | Self::ProspectivePhysicalGeneration { .. } => None,
        }
    }

    pub(super) fn prospective_generation_preimage(self) -> Option<SignerIdentityV1> {
        match self {
            Self::ProspectivePhysicalGeneration {
                generation_preimage_identity,
                ..
            } => Some(generation_preimage_identity),
            Self::PreGeneration { .. } | Self::GenerationBound { .. } => None,
        }
    }
}

/// Exact tagged authority correspondence.  A raw digest cannot change class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum C2ExactSigningAuthorityV1 {
    ProposedKey {
        grant_identity: SignerIdentityV1,
        candidate_identity: SignerIdentityV1,
    },
    Bootstrap {
        standing_identity: SignerIdentityV1,
    },
    CurrentPredecessor {
        standing_identity: SignerIdentityV1,
    },
    GenerationCurrent {
        standing_identity: SignerIdentityV1,
    },
    PendingSuccessor {
        standing_identity: SignerIdentityV1,
    },
}

impl C2ExactSigningAuthorityV1 {
    fn class(self) -> C2SigningAuthorityClassV1 {
        match self {
            Self::ProposedKey { .. } => C2SigningAuthorityClassV1::ProposedKey,
            Self::Bootstrap { .. } => C2SigningAuthorityClassV1::Bootstrap,
            Self::CurrentPredecessor { .. } => C2SigningAuthorityClassV1::CurrentPredecessor,
            Self::GenerationCurrent { .. } => C2SigningAuthorityClassV1::GenerationCurrent,
            Self::PendingSuccessor { .. } => C2SigningAuthorityClassV1::PendingSuccessor,
        }
    }

    fn identities(self) -> [SignerIdentityV1; 2] {
        match self {
            Self::ProposedKey {
                grant_identity,
                candidate_identity,
            } => [grant_identity, candidate_identity],
            Self::Bootstrap { standing_identity }
            | Self::CurrentPredecessor { standing_identity }
            | Self::GenerationCurrent { standing_identity }
            | Self::PendingSuccessor { standing_identity } => {
                [standing_identity, standing_identity]
            }
        }
    }
}

/// Complete Store-verified signing correspondence.  Construction is visible
/// only inside the Store-integrity signer owner and is the narrow adaptation
/// point for the live phase context.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
pub(super) struct StoreVerifiedSigningCoordinatesV1 {
    custody: SignerMessageCoordinatesV1,
    exact_scope: C2ExactSigningScopeV1,
    exact_authority: C2ExactSigningAuthorityV1,
    occurrence_id: String,
    resident_identity: String,
    resident_generation: u64,
    host_role: String,
    role_manifest_identity: SignerIdentityV1,
    role_manifest_generation: u64,
    authority_domain: String,
    terminal_a1_identity: SignerIdentityV1,
    current_a2_snapshot_identity: SignerIdentityV1,
    grant_or_predecessor_standing_identity: SignerIdentityV1,
    signer_public_key: [u8; 32],
    signer_key_generation: u64,
    signer_scope_policy_version: u64,
    active_store_policy_identity: SignerIdentityV1,
    active_store_policy_generation: u64,
    active_store_policy_digest: SignerIdentityV1,
    attempt_identity: SignerIdentityV1,
    event_predecessor_identity: SignerIdentityV1,
    transaction_intent_identity: SignerIdentityV1,
    implementation_manifest_identity: SignerIdentityV1,
    manifest_admission_correspondence_identity: SignerIdentityV1,
    qualified_candidate_identity: SignerIdentityV1,
    source_tree_identity: SignerIdentityV1,
    runtime_artifact_identity: SignerIdentityV1,
    frontier_namespace_identity: SignerIdentityV1,
    predecessor_frontier_identity: SignerIdentityV1,
    exact_content_identity: SignerIdentityV1,
}

impl StoreVerifiedSigningCoordinatesV1 {
    /// Project the sole pre-standing route from an actor-bound possession
    /// request.  The request is already tied to the exact Store snapshot,
    /// admitted manifest, proposal, and authenticated custody descriptor.
    pub(super) fn from_initial_possession(
        actor: &StoreC2SnapshotActorV1<'_>,
        request: &VerifiedInitialPossessionRequestV1<'_, '_>,
    ) -> Result<Self, SignerRefusalV2> {
        request.verify_for_actor(actor)?;
        let custody = SignerMessageCoordinatesV1 {
            occurrence: request.occurrence_identity()?,
            physical_generation: [0; 32],
            lifecycle_root: [0; 32],
            scope: request.signer_scope_identity(),
            policy: request.signer_scope_policy_identity()?,
            signer_key_generation: request.signer_key_generation_identity(),
            cut: request.event_cut(),
        };
        custody.validate()?;
        let value = Self {
            custody,
            exact_scope: C2ExactSigningScopeV1::PreGeneration {
                scope_identity: request.signer_scope_identity(),
                attempt_identity: request.attempt_identity(),
            },
            exact_authority: C2ExactSigningAuthorityV1::ProposedKey {
                grant_identity: request.grant_identity(),
                candidate_identity: request.candidate_identity(),
            },
            occurrence_id: request.occurrence_id().to_owned(),
            resident_identity: request.resident_identity().to_owned(),
            resident_generation: request.resident_generation(),
            host_role: request.host_role().to_owned(),
            role_manifest_identity: request.role_manifest_identity()?,
            role_manifest_generation: request.role_manifest_generation(),
            authority_domain: request.authority_domain().to_owned(),
            terminal_a1_identity: request.terminal_a1_identity()?,
            current_a2_snapshot_identity: request.current_a2_snapshot_identity()?,
            grant_or_predecessor_standing_identity: request.grant_identity(),
            signer_public_key: request.public_key(),
            signer_key_generation: request.signer_key_generation(),
            signer_scope_policy_version: request.signer_scope_policy_version(),
            active_store_policy_identity: request.active_store_policy_identity(),
            active_store_policy_generation: request.active_store_policy_generation(),
            active_store_policy_digest: request.active_store_policy_digest(),
            attempt_identity: request.attempt_identity(),
            event_predecessor_identity: request.predecessor_event_identity(),
            transaction_intent_identity: request.transaction_intent_identity(),
            implementation_manifest_identity: request.implementation_manifest_identity()?,
            manifest_admission_correspondence_identity: request
                .manifest_admission_correspondence_identity()?,
            qualified_candidate_identity: request.qualified_candidate_identity()?,
            source_tree_identity: request.source_tree_identity()?,
            runtime_artifact_identity: request.runtime_artifact_identity()?,
            frontier_namespace_identity: request.frontier_namespace_identity(),
            predecessor_frontier_identity: request.predecessor_frontier_identity(),
            exact_content_identity: request.exact_content_identity(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Project exact canonical message coordinates from the lifecycle-owned
    /// sealed view.  There is intentionally no scalar/raw-parts constructor.
    /// The projection is inert evidence and has no conversion back to standing.
    pub(super) fn from_live_store_context<Phase>(
        actor: &StoreC2SnapshotActorV1<'_>,
        view: &C2LiveSigningViewV1<'_, '_, '_, Phase>,
    ) -> Result<Self, SignerRefusalV2> {
        view.verify_live(actor).map_err(map_live_refusal)?;
        Self::from_verified_live_view(view)
    }

    /// Project from the exact actor-issued append permit inside a compound
    /// Store batch. This is required when the prior staged effect advances
    /// semantic frontier inside one uncommitted transaction; raw coordinates
    /// still cannot select or reconstruct the view.
    pub(super) fn from_store_append_permit<Phase>(
        permit: &StoreC2SignerAppendPermitV1<'_, '_, '_, Phase>,
        view: &C2LiveSigningViewV1<'_, '_, '_, Phase>,
    ) -> Result<Self, SignerRefusalV2> {
        permit.verify_live_view(view).map_err(map_live_refusal)?;
        Self::from_verified_live_view(view)
    }

    fn from_verified_live_view<Phase>(
        view: &C2LiveSigningViewV1<'_, '_, '_, Phase>,
    ) -> Result<Self, SignerRefusalV2> {
        let physical_generation = view.physical_generation_identity().unwrap_or([0; 32]);
        let lifecycle_root = view.lifecycle_root_identity().unwrap_or([0; 32]);
        let exact_scope =
            match view.scope_class() {
                C2LiveSigningScopeV1::PreGeneration => C2ExactSigningScopeV1::PreGeneration {
                    scope_identity: view.signer_scope_identity(),
                    attempt_identity: view.attempt_identity(),
                },
                C2LiveSigningScopeV1::ProspectivePhysicalGeneration => {
                    C2ExactSigningScopeV1::ProspectivePhysicalGeneration {
                        scope_identity: view.signer_scope_identity(),
                        generation_preimage_identity: view
                            .prospective_generation_preimage_identity()
                            .ok_or(SignerRefusalV2::MessageFrontierMismatch)?,
                        attempt_identity: view.attempt_identity(),
                    }
                }
                C2LiveSigningScopeV1::GenerationBound => C2ExactSigningScopeV1::GenerationBound {
                    scope_identity: view.signer_scope_identity(),
                    physical_generation_identity: view
                        .physical_generation_identity()
                        .ok_or(SignerRefusalV2::MessageFrontierMismatch)?,
                    lifecycle_root_identity: view
                        .lifecycle_root_identity()
                        .ok_or(SignerRefusalV2::MessageFrontierMismatch)?,
                },
            };
        let exact_authority = match view.authority_class() {
            C2LiveSigningAuthorityV1::Bootstrap => C2ExactSigningAuthorityV1::Bootstrap {
                standing_identity: view.standing_identity(),
            },
            C2LiveSigningAuthorityV1::GenerationCurrent => {
                C2ExactSigningAuthorityV1::GenerationCurrent {
                    standing_identity: view.standing_identity(),
                }
            }
            C2LiveSigningAuthorityV1::CurrentPredecessor => {
                C2ExactSigningAuthorityV1::CurrentPredecessor {
                    standing_identity: view.standing_identity(),
                }
            }
            C2LiveSigningAuthorityV1::PendingSuccessor => {
                C2ExactSigningAuthorityV1::PendingSuccessor {
                    standing_identity: view.standing_identity(),
                }
            }
        };
        let event_predecessor_identity = view
            .predecessor_event_identity()
            .ok_or(SignerRefusalV2::MessageFrontierMismatch)?;
        let transaction_intent_identity = view
            .transition_intent_identity()
            .ok_or(SignerRefusalV2::MessageFrontierMismatch)?;
        let grant_or_predecessor_standing_identity = view
            .grant_identity()
            .or_else(|| view.predecessor_standing_identity())
            .unwrap_or_else(|| view.standing_identity());
        let custody = SignerMessageCoordinatesV1 {
            occurrence: view.occurrence_identity(),
            physical_generation,
            lifecycle_root,
            scope: view.signer_scope_identity(),
            policy: view.signer_scope_policy_identity(),
            signer_key_generation: view.signer_key_generation_identity(),
            cut: view.event_cut(),
        };
        custody.validate()?;
        let value = Self {
            custody,
            exact_scope,
            exact_authority,
            occurrence_id: view.occurrence_id().to_owned(),
            resident_identity: view.resident_identity().to_owned(),
            resident_generation: view.resident_generation(),
            host_role: view.host_role().to_owned(),
            role_manifest_identity: view.role_manifest_identity(),
            role_manifest_generation: view.role_manifest_generation(),
            authority_domain: view.authority_domain().to_owned(),
            terminal_a1_identity: view.terminal_a1_identity(),
            current_a2_snapshot_identity: view.current_a2_identity(),
            grant_or_predecessor_standing_identity,
            signer_public_key: view.signer_public_key(),
            signer_key_generation: view.signer_key_generation(),
            signer_scope_policy_version: view.signer_scope_policy_version(),
            active_store_policy_identity: view.active_policy_identity(),
            active_store_policy_generation: view.active_policy_generation(),
            active_store_policy_digest: view.active_policy_digest(),
            attempt_identity: view.attempt_identity(),
            event_predecessor_identity,
            transaction_intent_identity,
            implementation_manifest_identity: view.implementation_manifest_identity(),
            manifest_admission_correspondence_identity: view
                .manifest_admission_correspondence_identity(),
            qualified_candidate_identity: view.qualified_candidate_identity(),
            source_tree_identity: view.source_tree_identity(),
            runtime_artifact_identity: view.runtime_artifact_identity(),
            frontier_namespace_identity: view.frontier_namespace_identity(),
            predecessor_frontier_identity: view.predecessor_frontier_identity(),
            exact_content_identity: view.exact_content_identity(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), SignerRefusalV2> {
        self.custody.validate()?;
        let (scope_exact_identities, scope_coordinate_mismatch) = match self.exact_scope {
            C2ExactSigningScopeV1::PreGeneration {
                scope_identity,
                attempt_identity,
            } => (
                [scope_identity, attempt_identity, attempt_identity],
                self.custody.scope != scope_identity
                    || self.attempt_identity != attempt_identity
                    || self.custody.physical_generation != [0; 32]
                    || self.custody.lifecycle_root != [0; 32],
            ),
            C2ExactSigningScopeV1::ProspectivePhysicalGeneration {
                scope_identity,
                generation_preimage_identity,
                attempt_identity,
            } => (
                [
                    scope_identity,
                    generation_preimage_identity,
                    attempt_identity,
                ],
                // MSG-03 can precede physical identity selection while
                // MSG-10 follows it; both remain prospectively scoped to
                // the same generation preimage.  The retained custody
                // check compares the physical coordinate to the exact
                // live view.  Lifecycle currentness must still be absent.
                self.custody.scope != scope_identity
                    || self.attempt_identity != attempt_identity
                    || self.custody.lifecycle_root != [0; 32],
            ),
            C2ExactSigningScopeV1::GenerationBound {
                scope_identity,
                physical_generation_identity,
                lifecycle_root_identity,
            } => (
                [
                    scope_identity,
                    physical_generation_identity,
                    lifecycle_root_identity,
                ],
                self.custody.scope != scope_identity
                    || self.custody.physical_generation != physical_generation_identity
                    || self.custody.lifecycle_root != lifecycle_root_identity,
            ),
        };
        let authority_identities = self.exact_authority.identities();
        if self.occurrence_id.is_empty()
            || self.resident_identity.is_empty()
            || self.host_role.is_empty()
            || self.authority_domain.is_empty()
            || self.resident_generation == 0
            || self.role_manifest_generation == 0
            || self.signer_scope_policy_version == 0
            || self.active_store_policy_generation == 0
            || scope_coordinate_mismatch
            || [
                self.role_manifest_identity,
                self.terminal_a1_identity,
                self.current_a2_snapshot_identity,
                self.grant_or_predecessor_standing_identity,
                self.signer_public_key,
                self.active_store_policy_identity,
                self.active_store_policy_digest,
                self.attempt_identity,
                self.event_predecessor_identity,
                self.transaction_intent_identity,
                self.implementation_manifest_identity,
                self.manifest_admission_correspondence_identity,
                self.qualified_candidate_identity,
                self.source_tree_identity,
                self.runtime_artifact_identity,
                self.frontier_namespace_identity,
                self.predecessor_frontier_identity,
                self.exact_content_identity,
            ]
            .iter()
            .chain(authority_identities.iter())
            .chain(scope_exact_identities.iter())
            .any(is_zero)
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(())
    }

    pub(super) const fn exact_scope(&self) -> C2ExactSigningScopeV1 {
        self.exact_scope
    }

    pub(super) const fn implementation_manifest_identity(&self) -> SignerIdentityV1 {
        self.implementation_manifest_identity
    }

    pub(super) const fn manifest_admission_correspondence_identity(&self) -> SignerIdentityV1 {
        self.manifest_admission_correspondence_identity
    }

    pub(super) const fn qualified_candidate_identity(&self) -> SignerIdentityV1 {
        self.qualified_candidate_identity
    }

    pub(super) const fn source_tree_identity(&self) -> SignerIdentityV1 {
        self.source_tree_identity
    }

    pub(super) const fn runtime_artifact_identity(&self) -> SignerIdentityV1 {
        self.runtime_artifact_identity
    }

    pub(super) const fn frontier_namespace_identity(&self) -> SignerIdentityV1 {
        self.frontier_namespace_identity
    }

    pub(super) const fn predecessor_frontier_identity(&self) -> SignerIdentityV1 {
        self.predecessor_frontier_identity
    }

    pub(super) const fn custody(&self) -> &SignerMessageCoordinatesV1 {
        &self.custody
    }

    pub(super) fn resident_identity(&self) -> &str {
        &self.resident_identity
    }

    pub(super) const fn resident_generation(&self) -> u64 {
        self.resident_generation
    }

    pub(super) fn host_role(&self) -> &str {
        &self.host_role
    }

    pub(super) const fn role_manifest_generation(&self) -> u64 {
        self.role_manifest_generation
    }

    pub(super) fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    pub(super) const fn terminal_a1_identity(&self) -> SignerIdentityV1 {
        self.terminal_a1_identity
    }

    pub(super) const fn current_a2_snapshot_identity(&self) -> SignerIdentityV1 {
        self.current_a2_snapshot_identity
    }

    pub(super) const fn grant_or_predecessor_standing_identity(&self) -> SignerIdentityV1 {
        self.grant_or_predecessor_standing_identity
    }

    pub(super) const fn signer_public_key(&self) -> [u8; 32] {
        self.signer_public_key
    }

    pub(super) const fn signer_scope_policy_version(&self) -> u64 {
        self.signer_scope_policy_version
    }

    pub(super) const fn active_store_policy_identity(&self) -> SignerIdentityV1 {
        self.active_store_policy_identity
    }

    pub(super) const fn active_store_policy_generation(&self) -> u64 {
        self.active_store_policy_generation
    }

    pub(super) const fn active_store_policy_digest(&self) -> SignerIdentityV1 {
        self.active_store_policy_digest
    }

    pub(super) const fn event_predecessor_identity(&self) -> SignerIdentityV1 {
        self.event_predecessor_identity
    }

    pub(super) const fn transaction_intent_identity(&self) -> SignerIdentityV1 {
        self.transaction_intent_identity
    }

    pub(super) const fn exact_authority(&self) -> C2ExactSigningAuthorityV1 {
        self.exact_authority
    }

    pub(super) fn occurrence_id(&self) -> &str {
        &self.occurrence_id
    }

    pub(super) const fn role_manifest_identity(&self) -> SignerIdentityV1 {
        self.role_manifest_identity
    }

    pub(super) const fn signer_key_generation(&self) -> u64 {
        self.signer_key_generation
    }

    pub(super) const fn exact_content_identity(&self) -> SignerIdentityV1 {
        self.exact_content_identity
    }
}

fn map_live_refusal(_refusal: C2LiveSignerRefusalV1) -> SignerRefusalV2 {
    SignerRefusalV2::MessageFrontierMismatch
}

/// Coarse family ownership retained for family-level archaeology checks.
/// Route-specific standing is defined by [`C2StoreSigningRouteV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MessageFamilyOwnerV1 {
    ExternalTerminalA1,
    ProposedKey,
    BootstrapSigner,
    UnsignedStoreRelation,
    CurrentGenerationSigner,
    CurrentPredecessor,
    PendingSuccessor,
    TransitionSelectedSigner,
}

/// Complete, non-extensible MSG-01 through MSG-16 family census.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ClosedMessageFamilyV1 {
    Msg01BootstrapGrant = 1,
    Msg02InitialProposalPop = 2,
    Msg03PhysicalGenerationBootstrap = 3,
    Msg04BootstrapToGenerationRelation = 4,
    Msg05ActivePolicyContinuity = 5,
    Msg06NormalRotationContinuity = 6,
    Msg07SuccessorPop = 7,
    Msg08GlobalRefusal = 8,
    Msg09InstallationIntent = 9,
    Msg10InstallationReceipt = 10,
    Msg11PolicyTransitionIntent = 11,
    Msg12PolicyTransitionReceipt = 12,
    Msg13RestoreAuthorization = 13,
    Msg14RevocationJudgment = 14,
    Msg15RecoveryGrant = 15,
    Msg16QuarantineClosure = 16,
}

impl ClosedMessageFamilyV1 {
    /// Exact closed family inventory.
    pub const ALL: [Self; 16] = [
        Self::Msg01BootstrapGrant,
        Self::Msg02InitialProposalPop,
        Self::Msg03PhysicalGenerationBootstrap,
        Self::Msg04BootstrapToGenerationRelation,
        Self::Msg05ActivePolicyContinuity,
        Self::Msg06NormalRotationContinuity,
        Self::Msg07SuccessorPop,
        Self::Msg08GlobalRefusal,
        Self::Msg09InstallationIntent,
        Self::Msg10InstallationReceipt,
        Self::Msg11PolicyTransitionIntent,
        Self::Msg12PolicyTransitionReceipt,
        Self::Msg13RestoreAuthorization,
        Self::Msg14RevocationJudgment,
        Self::Msg15RecoveryGrant,
        Self::Msg16QuarantineClosure,
    ];

    /// Exact stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Msg01BootstrapGrant => "MSG-01",
            Self::Msg02InitialProposalPop => "MSG-02",
            Self::Msg03PhysicalGenerationBootstrap => "MSG-03",
            Self::Msg04BootstrapToGenerationRelation => "MSG-04",
            Self::Msg05ActivePolicyContinuity => "MSG-05",
            Self::Msg06NormalRotationContinuity => "MSG-06",
            Self::Msg07SuccessorPop => "MSG-07",
            Self::Msg08GlobalRefusal => "MSG-08",
            Self::Msg09InstallationIntent => "MSG-09",
            Self::Msg10InstallationReceipt => "MSG-10",
            Self::Msg11PolicyTransitionIntent => "MSG-11",
            Self::Msg12PolicyTransitionReceipt => "MSG-12",
            Self::Msg13RestoreAuthorization => "MSG-13",
            Self::Msg14RevocationJudgment => "MSG-14",
            Self::Msg15RecoveryGrant => "MSG-15",
            Self::Msg16QuarantineClosure => "MSG-16",
        }
    }

    /// Exact identity domain shared by every route in this semantic family.
    pub const fn identity_domain(self) -> &'static str {
        match self {
            Self::Msg01BootstrapGrant => "nq.c2.store_integrity_bootstrap_grant.identity.v1",
            Self::Msg02InitialProposalPop => "nq.c2.store_integrity_initial_pop.identity.v1",
            Self::Msg03PhysicalGenerationBootstrap => {
                "nq.c2.store_generation.bootstrap.identity.v1"
            }
            Self::Msg04BootstrapToGenerationRelation => {
                "nq.c2.signer_bootstrap_transition.identity.v1"
            }
            Self::Msg05ActivePolicyContinuity => "nq.c2.active_policy_continuity.identity.v1",
            Self::Msg06NormalRotationContinuity => "nq.c2.signer_rotation_continuity.identity.v1",
            Self::Msg07SuccessorPop => "nq.c2.store_integrity_successor_pop.identity.v1",
            Self::Msg08GlobalRefusal => "nq.c2.global_refusal.identity.v1",
            Self::Msg09InstallationIntent => "nq.c2.installation_intent.identity.v1",
            Self::Msg10InstallationReceipt => "nq.c2.installation_receipt.identity.v1",
            Self::Msg11PolicyTransitionIntent => "nq.c2.policy_transition_intent.identity.v1",
            Self::Msg12PolicyTransitionReceipt => "nq.c2.policy_transition_receipt.identity.v1",
            Self::Msg13RestoreAuthorization => "nq.c2.restore_authorization.identity.v1",
            Self::Msg14RevocationJudgment => {
                "nq.c2.store_integrity_revocation_judgment.identity.v1"
            }
            Self::Msg15RecoveryGrant => "nq.c2.store_integrity_recovery_grant.identity.v1",
            Self::Msg16QuarantineClosure => "nq.c2.quarantine_closure_judgment.identity.v1",
        }
    }

    pub(crate) const fn owner(self) -> MessageFamilyOwnerV1 {
        match self {
            Self::Msg01BootstrapGrant
            | Self::Msg13RestoreAuthorization
            | Self::Msg14RevocationJudgment
            | Self::Msg15RecoveryGrant
            | Self::Msg16QuarantineClosure => MessageFamilyOwnerV1::ExternalTerminalA1,
            Self::Msg02InitialProposalPop => MessageFamilyOwnerV1::ProposedKey,
            Self::Msg03PhysicalGenerationBootstrap
            | Self::Msg09InstallationIntent
            | Self::Msg10InstallationReceipt => MessageFamilyOwnerV1::BootstrapSigner,
            Self::Msg04BootstrapToGenerationRelation => MessageFamilyOwnerV1::UnsignedStoreRelation,
            Self::Msg05ActivePolicyContinuity
            | Self::Msg06NormalRotationContinuity
            | Self::Msg11PolicyTransitionIntent => MessageFamilyOwnerV1::CurrentPredecessor,
            Self::Msg07SuccessorPop => MessageFamilyOwnerV1::PendingSuccessor,
            Self::Msg08GlobalRefusal => MessageFamilyOwnerV1::CurrentGenerationSigner,
            Self::Msg12PolicyTransitionReceipt => MessageFamilyOwnerV1::TransitionSelectedSigner,
        }
    }

    pub(crate) const fn is_store_signable(self) -> bool {
        !matches!(
            self.owner(),
            MessageFamilyOwnerV1::ExternalTerminalA1 | MessageFamilyOwnerV1::UnsignedStoreRelation
        )
    }
}

/// Closed signer phase vocabulary used by the normative route registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum C2SignerPhaseV1 {
    ProposedInitial,
    Bootstrap,
    CurrentPredecessor,
    GenerationCurrent,
    PendingSuccessor,
}

impl C2SignerPhaseV1 {
    /// Exact stable projection label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProposedInitial => "proposed_initial",
            Self::Bootstrap => "bootstrap",
            Self::CurrentPredecessor => "current_predecessor",
            Self::GenerationCurrent => "generation_current",
            Self::PendingSuccessor => "pending_successor",
        }
    }
}

/// Closed scope class.  The route selects this; callers do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum C2SigningScopeClassV1 {
    PreGeneration,
    ProspectivePhysicalGeneration,
    GenerationBound,
}

impl C2SigningScopeClassV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreGeneration => "pre_generation",
            Self::ProspectivePhysicalGeneration => "prospective_physical_generation",
            Self::GenerationBound => "generation_bound",
        }
    }
}

/// Closed authority class.  It prevents one digest from being relabeled as a
/// different standing phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum C2SigningAuthorityClassV1 {
    ProposedKey,
    Bootstrap,
    CurrentPredecessor,
    GenerationCurrent,
    PendingSuccessor,
}

impl C2SigningAuthorityClassV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProposedKey => "proposed_key",
            Self::Bootstrap => "bootstrap",
            Self::CurrentPredecessor => "current_predecessor",
            Self::GenerationCurrent => "generation_current",
            Self::PendingSuccessor => "pending_successor",
        }
    }
}

/// Exact verified semantic input class for each Store/proposal signing route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum C2VerifiedInputKindV1 {
    InitialPopCandidate,
    PhysicalGenerationBootstrapFacts,
    ActivePolicyContinuityFacts,
    HealthyRotationContinuityFacts,
    SuccessorPopChallenge,
    ClassifiedGlobalRefusal,
    InstallationIntentFacts,
    InstallationCompletionFacts,
    PolicyTransitionIntentFacts,
    TransitionReceiptCurrentFacts,
    TransitionReceiptPendingFacts,
}

impl C2VerifiedInputKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialPopCandidate => "initial_pop_candidate",
            Self::PhysicalGenerationBootstrapFacts => "physical_generation_bootstrap_facts",
            Self::ActivePolicyContinuityFacts => "active_policy_continuity_facts",
            Self::HealthyRotationContinuityFacts => "healthy_rotation_continuity_facts",
            Self::SuccessorPopChallenge => "successor_pop_challenge",
            Self::ClassifiedGlobalRefusal => "classified_global_refusal",
            Self::InstallationIntentFacts => "installation_intent_facts",
            Self::InstallationCompletionFacts => "installation_completion_facts",
            Self::PolicyTransitionIntentFacts => "policy_transition_intent_facts",
            Self::TransitionReceiptCurrentFacts => "transition_receipt_current_facts",
            Self::TransitionReceiptPendingFacts => "transition_receipt_pending_facts",
        }
    }
}

/// Sole legal consumer/effect class for each Store/proposal signing route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum C2SoleConsumerV1 {
    AcceptedEnrollmentWrapper,
    InstallationBootstrapAppend,
    ActivePolicyTransitionAppend,
    HealthyRotationAppend,
    SelectedSuccessorPop,
    GlobalRefusalAppend,
    InstallationIntentAppend,
    BootstrapTransitionClose,
    TransitionIntentAppend,
    GenerationCurrentResolution,
    PendingSuccessorResolution,
}

impl C2SoleConsumerV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedEnrollmentWrapper => "accepted_enrollment_wrapper",
            Self::InstallationBootstrapAppend => "installation_bootstrap_append",
            Self::ActivePolicyTransitionAppend => "active_policy_transition_append",
            Self::HealthyRotationAppend => "healthy_rotation_append",
            Self::SelectedSuccessorPop => "selected_successor_pop",
            Self::GlobalRefusalAppend => "global_refusal_append",
            Self::InstallationIntentAppend => "installation_intent_append",
            Self::BootstrapTransitionClose => "bootstrap_transition_close",
            Self::TransitionIntentAppend => "transition_intent_append",
            Self::GenerationCurrentResolution => "generation_current_resolution",
            Self::PendingSuccessorResolution => "pending_successor_resolution",
        }
    }
}

/// Eleven literal Store/proposal-key signing routes.  MSG-12 owns two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum C2StoreSigningRouteV1 {
    Msg02InitialPop = 1,
    Msg03PhysicalGenerationBootstrap = 2,
    Msg05ActivePolicyContinuity = 3,
    Msg06NormalRotationContinuity = 4,
    Msg07SuccessorPop = 5,
    Msg08GlobalRefusal = 6,
    Msg09InstallationIntent = 7,
    Msg10InstallationReceipt = 8,
    Msg11PolicyTransitionIntent = 9,
    Msg12ReceiptCurrent = 10,
    Msg12ReceiptPending = 11,
}

impl C2StoreSigningRouteV1 {
    /// Exact closed Store/proposal-key route inventory.
    pub const ALL: [Self; 11] = [
        Self::Msg02InitialPop,
        Self::Msg03PhysicalGenerationBootstrap,
        Self::Msg05ActivePolicyContinuity,
        Self::Msg06NormalRotationContinuity,
        Self::Msg07SuccessorPop,
        Self::Msg08GlobalRefusal,
        Self::Msg09InstallationIntent,
        Self::Msg10InstallationReceipt,
        Self::Msg11PolicyTransitionIntent,
        Self::Msg12ReceiptCurrent,
        Self::Msg12ReceiptPending,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Msg02InitialPop => "msg02_initial_pop",
            Self::Msg03PhysicalGenerationBootstrap => "msg03_physical_generation_bootstrap",
            Self::Msg05ActivePolicyContinuity => "msg05_active_policy_continuity",
            Self::Msg06NormalRotationContinuity => "msg06_normal_rotation_continuity",
            Self::Msg07SuccessorPop => "msg07_successor_pop",
            Self::Msg08GlobalRefusal => "msg08_global_refusal",
            Self::Msg09InstallationIntent => "msg09_installation_intent",
            Self::Msg10InstallationReceipt => "msg10_installation_receipt",
            Self::Msg11PolicyTransitionIntent => "msg11_policy_transition_intent",
            Self::Msg12ReceiptCurrent => "msg12_receipt_current",
            Self::Msg12ReceiptPending => "msg12_receipt_pending",
        }
    }

    pub const fn family(self) -> ClosedMessageFamilyV1 {
        match self {
            Self::Msg02InitialPop => ClosedMessageFamilyV1::Msg02InitialProposalPop,
            Self::Msg03PhysicalGenerationBootstrap => {
                ClosedMessageFamilyV1::Msg03PhysicalGenerationBootstrap
            }
            Self::Msg05ActivePolicyContinuity => ClosedMessageFamilyV1::Msg05ActivePolicyContinuity,
            Self::Msg06NormalRotationContinuity => {
                ClosedMessageFamilyV1::Msg06NormalRotationContinuity
            }
            Self::Msg07SuccessorPop => ClosedMessageFamilyV1::Msg07SuccessorPop,
            Self::Msg08GlobalRefusal => ClosedMessageFamilyV1::Msg08GlobalRefusal,
            Self::Msg09InstallationIntent => ClosedMessageFamilyV1::Msg09InstallationIntent,
            Self::Msg10InstallationReceipt => ClosedMessageFamilyV1::Msg10InstallationReceipt,
            Self::Msg11PolicyTransitionIntent => ClosedMessageFamilyV1::Msg11PolicyTransitionIntent,
            Self::Msg12ReceiptCurrent | Self::Msg12ReceiptPending => {
                ClosedMessageFamilyV1::Msg12PolicyTransitionReceipt
            }
        }
    }

    pub const fn phase(self) -> C2SignerPhaseV1 {
        match self {
            Self::Msg02InitialPop => C2SignerPhaseV1::ProposedInitial,
            Self::Msg03PhysicalGenerationBootstrap
            | Self::Msg09InstallationIntent
            | Self::Msg10InstallationReceipt => C2SignerPhaseV1::Bootstrap,
            Self::Msg05ActivePolicyContinuity
            | Self::Msg06NormalRotationContinuity
            | Self::Msg11PolicyTransitionIntent => C2SignerPhaseV1::CurrentPredecessor,
            Self::Msg07SuccessorPop | Self::Msg12ReceiptPending => {
                C2SignerPhaseV1::PendingSuccessor
            }
            Self::Msg08GlobalRefusal | Self::Msg12ReceiptCurrent => {
                C2SignerPhaseV1::GenerationCurrent
            }
        }
    }

    pub const fn identity_domain(self) -> &'static str {
        self.family().identity_domain()
    }

    pub const fn signature_domain(self) -> &'static str {
        match self {
            Self::Msg02InitialPop => "nq.c2.store_integrity_initial_pop.possession_signature.v1",
            Self::Msg03PhysicalGenerationBootstrap => {
                "nq.c2.store_generation.bootstrap.signature.v1"
            }
            Self::Msg05ActivePolicyContinuity => {
                "nq.c2.active_policy_continuity.current_predecessor_signature.v1"
            }
            Self::Msg06NormalRotationContinuity => {
                "nq.c2.signer_rotation_continuity.current_predecessor_signature.v1"
            }
            Self::Msg07SuccessorPop => {
                "nq.c2.store_integrity_successor_pop.pending_possession_signature.v1"
            }
            Self::Msg08GlobalRefusal => "nq.c2.global_refusal.generation_current_signature.v1",
            Self::Msg09InstallationIntent => {
                "nq.c2.installation_intent.store_integrity_signature.v1"
            }
            Self::Msg10InstallationReceipt => {
                "nq.c2.installation_receipt.store_integrity_signature.v1"
            }
            Self::Msg11PolicyTransitionIntent => {
                "nq.c2.policy_transition_intent.current_predecessor_signature.v1"
            }
            Self::Msg12ReceiptCurrent => {
                "nq.c2.policy_transition_receipt.generation_current_signature.v1"
            }
            Self::Msg12ReceiptPending => {
                "nq.c2.policy_transition_receipt.pending_successor_signature.v1"
            }
        }
    }

    pub const fn scope_class(self) -> C2SigningScopeClassV1 {
        match self {
            Self::Msg02InitialPop | Self::Msg09InstallationIntent => {
                C2SigningScopeClassV1::PreGeneration
            }
            Self::Msg03PhysicalGenerationBootstrap | Self::Msg10InstallationReceipt => {
                C2SigningScopeClassV1::ProspectivePhysicalGeneration
            }
            _ => C2SigningScopeClassV1::GenerationBound,
        }
    }

    pub const fn authority_class(self) -> C2SigningAuthorityClassV1 {
        match self {
            Self::Msg02InitialPop => C2SigningAuthorityClassV1::ProposedKey,
            Self::Msg03PhysicalGenerationBootstrap
            | Self::Msg09InstallationIntent
            | Self::Msg10InstallationReceipt => C2SigningAuthorityClassV1::Bootstrap,
            Self::Msg05ActivePolicyContinuity
            | Self::Msg06NormalRotationContinuity
            | Self::Msg11PolicyTransitionIntent => C2SigningAuthorityClassV1::CurrentPredecessor,
            Self::Msg07SuccessorPop | Self::Msg12ReceiptPending => {
                C2SigningAuthorityClassV1::PendingSuccessor
            }
            Self::Msg08GlobalRefusal | Self::Msg12ReceiptCurrent => {
                C2SigningAuthorityClassV1::GenerationCurrent
            }
        }
    }

    pub const fn input_kind(self) -> C2VerifiedInputKindV1 {
        match self {
            Self::Msg02InitialPop => C2VerifiedInputKindV1::InitialPopCandidate,
            Self::Msg03PhysicalGenerationBootstrap => {
                C2VerifiedInputKindV1::PhysicalGenerationBootstrapFacts
            }
            Self::Msg05ActivePolicyContinuity => C2VerifiedInputKindV1::ActivePolicyContinuityFacts,
            Self::Msg06NormalRotationContinuity => {
                C2VerifiedInputKindV1::HealthyRotationContinuityFacts
            }
            Self::Msg07SuccessorPop => C2VerifiedInputKindV1::SuccessorPopChallenge,
            Self::Msg08GlobalRefusal => C2VerifiedInputKindV1::ClassifiedGlobalRefusal,
            Self::Msg09InstallationIntent => C2VerifiedInputKindV1::InstallationIntentFacts,
            Self::Msg10InstallationReceipt => C2VerifiedInputKindV1::InstallationCompletionFacts,
            Self::Msg11PolicyTransitionIntent => C2VerifiedInputKindV1::PolicyTransitionIntentFacts,
            Self::Msg12ReceiptCurrent => C2VerifiedInputKindV1::TransitionReceiptCurrentFacts,
            Self::Msg12ReceiptPending => C2VerifiedInputKindV1::TransitionReceiptPendingFacts,
        }
    }

    pub const fn sole_consumer(self) -> C2SoleConsumerV1 {
        match self {
            Self::Msg02InitialPop => C2SoleConsumerV1::AcceptedEnrollmentWrapper,
            Self::Msg03PhysicalGenerationBootstrap => C2SoleConsumerV1::InstallationBootstrapAppend,
            Self::Msg05ActivePolicyContinuity => C2SoleConsumerV1::ActivePolicyTransitionAppend,
            Self::Msg06NormalRotationContinuity => C2SoleConsumerV1::HealthyRotationAppend,
            Self::Msg07SuccessorPop => C2SoleConsumerV1::SelectedSuccessorPop,
            Self::Msg08GlobalRefusal => C2SoleConsumerV1::GlobalRefusalAppend,
            Self::Msg09InstallationIntent => C2SoleConsumerV1::InstallationIntentAppend,
            Self::Msg10InstallationReceipt => C2SoleConsumerV1::BootstrapTransitionClose,
            Self::Msg11PolicyTransitionIntent => C2SoleConsumerV1::TransitionIntentAppend,
            Self::Msg12ReceiptCurrent => C2SoleConsumerV1::GenerationCurrentResolution,
            Self::Msg12ReceiptPending => C2SoleConsumerV1::PendingSuccessorResolution,
        }
    }

    /// Exact external-bootstrap-grant permission label, projected from the
    /// three bootstrap-phase routes that the grant can authorize.  `None`
    /// for every other route prevents a second caller-authored permission
    /// table from drifting away from the normative registry.
    pub const fn bootstrap_grant_permission_label(self) -> Option<&'static str> {
        match self {
            Self::Msg03PhysicalGenerationBootstrap => Some("physical_store_generation_genesis"),
            Self::Msg09InstallationIntent => Some("store_generation_installation_intent"),
            Self::Msg10InstallationReceipt => Some("store_generation_installation_receipt"),
            _ => None,
        }
    }
}

/// Mechanical, order-stable projection consumed by the canonical MSG-01
/// bootstrap-grant request. The strings remain schema vocabulary, but route
/// membership comes only from `C2StoreSigningRouteV1::ALL` above.
pub(crate) fn bootstrap_grant_permitted_family_projection_v1() -> Vec<&'static str> {
    C2StoreSigningRouteV1::ALL
        .into_iter()
        .filter_map(C2StoreSigningRouteV1::bootstrap_grant_permission_label)
        .collect()
}

/// Seven terminal-A1 routes over five external semantic families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum C2ExternalSigningRouteV1 {
    Msg01BootstrapGrant = 1,
    Msg01ActivationSuccessorGrant = 2,
    Msg01ProposalDisposition = 3,
    Msg13RestoreAuthorization = 4,
    Msg14RevocationJudgment = 5,
    Msg15RecoveryGrant = 6,
    Msg16QuarantineClosure = 7,
}

impl C2ExternalSigningRouteV1 {
    /// Exact closed external route inventory.
    pub const ALL: [Self; 7] = [
        Self::Msg01BootstrapGrant,
        Self::Msg01ActivationSuccessorGrant,
        Self::Msg01ProposalDisposition,
        Self::Msg13RestoreAuthorization,
        Self::Msg14RevocationJudgment,
        Self::Msg15RecoveryGrant,
        Self::Msg16QuarantineClosure,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Msg01BootstrapGrant => "msg01_bootstrap_grant",
            Self::Msg01ActivationSuccessorGrant => "msg01_activation_successor_grant",
            Self::Msg01ProposalDisposition => "msg01_proposal_disposition",
            Self::Msg13RestoreAuthorization => "msg13_restore_authorization",
            Self::Msg14RevocationJudgment => "msg14_revocation_judgment",
            Self::Msg15RecoveryGrant => "msg15_recovery_grant",
            Self::Msg16QuarantineClosure => "msg16_quarantine_closure",
        }
    }

    pub const fn family(self) -> ClosedMessageFamilyV1 {
        match self {
            Self::Msg01BootstrapGrant
            | Self::Msg01ActivationSuccessorGrant
            | Self::Msg01ProposalDisposition => ClosedMessageFamilyV1::Msg01BootstrapGrant,
            Self::Msg13RestoreAuthorization => ClosedMessageFamilyV1::Msg13RestoreAuthorization,
            Self::Msg14RevocationJudgment => ClosedMessageFamilyV1::Msg14RevocationJudgment,
            Self::Msg15RecoveryGrant => ClosedMessageFamilyV1::Msg15RecoveryGrant,
            Self::Msg16QuarantineClosure => ClosedMessageFamilyV1::Msg16QuarantineClosure,
        }
    }

    pub const fn identity_domain(self) -> &'static str {
        match self {
            Self::Msg01BootstrapGrant => "nq.c2.store_integrity_bootstrap_grant.identity.v1",
            Self::Msg01ActivationSuccessorGrant => {
                "nq.c2.store_integrity_activation_successor_grant.identity.v1"
            }
            Self::Msg01ProposalDisposition => {
                "nq.c2.store_integrity_proposal_disposition.identity.v1"
            }
            Self::Msg13RestoreAuthorization => "nq.c2.restore_authorization.identity.v1",
            Self::Msg14RevocationJudgment => {
                "nq.c2.store_integrity_revocation_judgment.identity.v1"
            }
            Self::Msg15RecoveryGrant => "nq.c2.store_integrity_recovery_grant.identity.v1",
            Self::Msg16QuarantineClosure => "nq.c2.quarantine_closure_judgment.identity.v1",
        }
    }

    pub const fn signature_domain(self) -> &'static str {
        match self {
            Self::Msg01BootstrapGrant => "nq.c2.store_integrity_bootstrap_grant.a1_signature.v1",
            Self::Msg01ActivationSuccessorGrant => {
                "nq.c2.store_integrity_activation_successor_grant.a1_signature.v1"
            }
            Self::Msg01ProposalDisposition => {
                "nq.c2.store_integrity_proposal_disposition.a1_signature.v1"
            }
            Self::Msg13RestoreAuthorization => "nq.c2.restore_authorization.a1_signature.v1",
            Self::Msg14RevocationJudgment => {
                "nq.c2.store_integrity_revocation_judgment.a1_signature.v1"
            }
            Self::Msg15RecoveryGrant => "nq.c2.store_integrity_recovery_grant.a1_signature.v1",
            Self::Msg16QuarantineClosure => "nq.c2.quarantine_closure_judgment.a1_signature.v1",
        }
    }

    pub const fn input_kind(self) -> &'static str {
        match self {
            Self::Msg01BootstrapGrant => "bootstrap_grant_request",
            Self::Msg01ActivationSuccessorGrant => "activation_successor_grant_request",
            Self::Msg01ProposalDisposition => "proposal_disposition_request",
            Self::Msg13RestoreAuthorization => "restore_authorization_request",
            Self::Msg14RevocationJudgment => "revocation_judgment_request",
            Self::Msg15RecoveryGrant => "recovery_grant_request",
            Self::Msg16QuarantineClosure => "quarantine_closure_request",
        }
    }

    pub const fn sole_consumer(self) -> &'static str {
        match self {
            Self::Msg01BootstrapGrant => "reserve_bootstrap_attempt",
            Self::Msg01ActivationSuccessorGrant => "active_policy_transition_regrant",
            Self::Msg01ProposalDisposition => "deterministic_proposal_disposition",
            Self::Msg13RestoreAuthorization => "restore_successor_continuation",
            Self::Msg14RevocationJudgment => "atomic_revocation_effect",
            Self::Msg15RecoveryGrant => "recovery_transition",
            Self::Msg16QuarantineClosure => "atomic_quarantine_closure_effect",
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Private trait implemented only by the eleven route-specific semantic
/// message types below.
pub(super) trait SignerMessageV1: sealed::Sealed {
    fn route(&self) -> C2StoreSigningRouteV1;
    fn coordinates(&self) -> &SignerMessageCoordinatesV1;
    fn verified_coordinates(&self) -> &StoreVerifiedSigningCoordinatesV1;
    fn message_identity(&self) -> SignerIdentityV1;
    fn transaction_identity(&self) -> SignerIdentityV1;
    fn canonical_message(&self) -> &[u8];
    fn canonical_preimage(&self) -> Vec<u8>;
    fn verify_closed_route(&self) -> Result<(), SignerRefusalV2>;

    fn family(&self) -> ClosedMessageFamilyV1 {
        self.route().family()
    }
}

fn is_zero(identity: &SignerIdentityV1) -> bool {
    identity.iter().all(|byte| *byte == 0)
}

#[derive(Serialize)]
struct CanonicalCoordinatesV1<'a> {
    occurrence_id: &'a str,
    occurrence: String,
    resident_identity: &'a str,
    resident_generation: u64,
    host_role: &'a str,
    role_manifest_identity: String,
    role_manifest_generation: u64,
    authority_domain: &'a str,
    terminal_a1_identity: String,
    current_a2_snapshot_identity: String,
    grant_or_predecessor_standing_identity: String,
    signer_public_key: String,
    signer_key_generation: u64,
    signer_key_generation_identity: String,
    scope_class: &'static str,
    scope_identity: String,
    attempt_identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prospective_generation_preimage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle_root: Option<String>,
    authority_class: &'static str,
    authority_premise_identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposed_candidate_identity: Option<String>,
    signer_scope_policy_identity: String,
    signer_scope_policy_version: u64,
    active_store_policy_identity: String,
    active_store_policy_generation: u64,
    active_store_policy_digest: String,
    cut: u64,
    event_predecessor_identity: String,
    transaction_intent_identity: String,
    implementation_manifest_identity: String,
    manifest_admission_correspondence_identity: String,
    qualified_candidate_identity: String,
    source_tree_identity: String,
    runtime_artifact_identity: String,
    frontier_namespace_identity: String,
    predecessor_frontier_identity: String,
    exact_content_identity: String,
}

impl<'a> From<&'a StoreVerifiedSigningCoordinatesV1> for CanonicalCoordinatesV1<'a> {
    fn from(value: &'a StoreVerifiedSigningCoordinatesV1) -> Self {
        let scope_identity = match value.exact_scope {
            C2ExactSigningScopeV1::PreGeneration {
                scope_identity,
                ..
            }
            | C2ExactSigningScopeV1::ProspectivePhysicalGeneration {
                scope_identity,
                ..
            }
            | C2ExactSigningScopeV1::GenerationBound { scope_identity, .. } => scope_identity,
        };
        let authority = value.exact_authority.identities();
        Self {
            occurrence_id: &value.occurrence_id,
            occurrence: identity_text(value.custody.occurrence),
            resident_identity: &value.resident_identity,
            resident_generation: value.resident_generation,
            host_role: &value.host_role,
            role_manifest_identity: identity_text(value.role_manifest_identity),
            role_manifest_generation: value.role_manifest_generation,
            authority_domain: &value.authority_domain,
            terminal_a1_identity: identity_text(value.terminal_a1_identity),
            current_a2_snapshot_identity: identity_text(value.current_a2_snapshot_identity),
            grant_or_predecessor_standing_identity: identity_text(
                value.grant_or_predecessor_standing_identity,
            ),
            signer_public_key: hex::encode(value.signer_public_key),
            signer_key_generation: value.signer_key_generation,
            signer_key_generation_identity: identity_text(value.custody.signer_key_generation),
            scope_class: value.exact_scope.class().as_str(),
            scope_identity: identity_text(scope_identity),
            attempt_identity: identity_text(value.attempt_identity),
            prospective_generation_preimage: value
                .exact_scope
                .prospective_generation_preimage()
                .map(identity_text),
            physical_generation: value.exact_scope.physical_generation().map(identity_text),
            lifecycle_root: value.exact_scope.lifecycle_root().map(identity_text),
            authority_class: value.exact_authority.class().as_str(),
            authority_premise_identity: identity_text(authority[0]),
            proposed_candidate_identity: (authority[0] != authority[1])
                .then(|| identity_text(authority[1])),
            signer_scope_policy_identity: identity_text(value.custody.policy),
            signer_scope_policy_version: value.signer_scope_policy_version,
            active_store_policy_identity: identity_text(value.active_store_policy_identity),
            active_store_policy_generation: value.active_store_policy_generation,
            active_store_policy_digest: identity_text(value.active_store_policy_digest),
            cut: value.custody.cut,
            event_predecessor_identity: identity_text(value.event_predecessor_identity),
            transaction_intent_identity: identity_text(value.transaction_intent_identity),
            implementation_manifest_identity: identity_text(value.implementation_manifest_identity),
            manifest_admission_correspondence_identity: identity_text(
                value.manifest_admission_correspondence_identity,
            ),
            qualified_candidate_identity: identity_text(value.qualified_candidate_identity),
            source_tree_identity: identity_text(value.source_tree_identity),
            runtime_artifact_identity: identity_text(value.runtime_artifact_identity),
            frontier_namespace_identity: identity_text(value.frontier_namespace_identity),
            predecessor_frontier_identity: identity_text(value.predecessor_frontier_identity),
            exact_content_identity: identity_text(value.exact_content_identity),
        }
    }
}

#[derive(Serialize)]
struct CanonicalMessageBodyV1<'a, S: Serialize> {
    schema: &'static str,
    family: &'static str,
    route: &'static str,
    identity_domain: &'static str,
    signature_domain: &'static str,
    signer_phase: &'static str,
    algorithm: &'static str,
    scope_class: &'static str,
    authority_class: &'static str,
    sole_consumer: &'static str,
    coordinates: CanonicalCoordinatesV1<'a>,
    verified_input: &'a S,
}

#[derive(Serialize)]
struct CanonicalMessageWithIdentityV1<'a, S: Serialize> {
    #[serde(flatten)]
    body: CanonicalMessageBodyV1<'a, S>,
    message_identity: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
struct ExactMessageEncodingV1 {
    message_identity: SignerIdentityV1,
    transaction_identity: SignerIdentityV1,
    canonical_message: Vec<u8>,
    signing_preimage: Vec<u8>,
}

fn digest_bytes(value: &str) -> Result<SignerIdentityV1, SignerRefusalV2> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(SignerRefusalV2::MessagePayloadSubstitution)?;
    hex::decode(hex)
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
        .try_into()
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)
}

fn identity_text(identity: SignerIdentityV1) -> String {
    format!("sha256:{}", hex::encode(identity))
}

fn encode_exact_message<S: Serialize>(
    route: C2StoreSigningRouteV1,
    coordinates: &StoreVerifiedSigningCoordinatesV1,
    source: &S,
) -> Result<ExactMessageEncodingV1, SignerRefusalV2> {
    coordinates.validate()?;
    if coordinates.exact_scope.class() != route.scope_class()
        || coordinates.exact_authority.class() != route.authority_class()
    {
        return Err(SignerRefusalV2::MessageFrontierMismatch);
    }
    let body = CanonicalMessageBodyV1 {
        schema: "nq.c2_store_integrity_signing_message.v1",
        family: route.family().as_str(),
        route: route.as_str(),
        identity_domain: route.identity_domain(),
        signature_domain: route.signature_domain(),
        signer_phase: route.phase().as_str(),
        algorithm: "ed25519",
        scope_class: route.scope_class().as_str(),
        authority_class: route.authority_class().as_str(),
        sole_consumer: route.sole_consumer().as_str(),
        coordinates: coordinates.into(),
        verified_input: source,
    };
    let canonical_body =
        canonical_json_bytes(&body).map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let mut identity_preimage =
        Vec::with_capacity(route.identity_domain().len() + 1 + canonical_body.len());
    identity_preimage.extend_from_slice(route.identity_domain().as_bytes());
    identity_preimage.push(0);
    identity_preimage.extend_from_slice(&canonical_body);
    let identity_text = sha256_bytes(&identity_preimage);
    let message_identity = digest_bytes(identity_text.as_str())?;
    let canonical_message = canonical_json_bytes(&CanonicalMessageWithIdentityV1 {
        body,
        message_identity: identity_text.as_str(),
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let mut signing_preimage =
        Vec::with_capacity(route.signature_domain().len() + 1 + canonical_message.len());
    signing_preimage.extend_from_slice(route.signature_domain().as_bytes());
    signing_preimage.push(0);
    signing_preimage.extend_from_slice(&canonical_message);
    Ok(ExactMessageEncodingV1 {
        message_identity,
        transaction_identity: coordinates.transaction_intent_identity,
        canonical_message,
        signing_preimage,
    })
}

macro_rules! define_verified_source {
    ($name:ident, $input_kind:ident { $($field:ident),+ $(,)? }) => {
        #[derive(Debug, PartialEq, Eq, Serialize)]
        pub(super) struct $name {
            input_kind: &'static str,
            $($field: String,)+
        }

        impl $name {
            #[allow(clippy::too_many_arguments)]
            pub(super) fn from_store_verified(
                _permit: &CoordinatorMessageConstructionPermitV1,
                $($field: SignerIdentityV1,)+
            ) -> Result<Self, SignerRefusalV2> {
                if [$($field,)+].iter().any(is_zero) {
                    return Err(SignerRefusalV2::MessagePayloadSubstitution);
                }
                Ok(Self {
                    input_kind: C2VerifiedInputKindV1::$input_kind.as_str(),
                    $($field: identity_text($field),)+
                })
            }
        }
    };
}

define_verified_source!(
    VerifiedInitialPopSourceV1,
    InitialPopCandidate {
        grant_selected_proposal_identity,
        candidate_identity,
        challenge_identity,
        public_key_identity,
        attempt_identity,
        pre_generation_scope_identity,
    }
);
define_verified_source!(
    VerifiedPhysicalGenerationBootstrapSourceV1,
    PhysicalGenerationBootstrapFacts {
        accepted_enrollment_identity,
        frozen_generation_preimage_identity,
        bg_layout_profile_manifest_lock_facts_identity,
        installation_intent_message_identity,
        generation_commitment_identity,
    }
);
define_verified_source!(
    VerifiedActivePolicyContinuitySourceV1,
    ActivePolicyContinuityFacts {
        immutable_signer_policy_identity,
        old_active_policy_identity,
        new_active_policy_identity,
        activation_identity,
        policy_predecessor_identity,
        successor_grant_or_unchanged_applicability_identity,
    }
);
define_verified_source!(
    VerifiedHealthyRotationContinuitySourceV1,
    HealthyRotationContinuityFacts {
        successor_proposal_identity,
        successor_pop_identity,
        prior_enrollment_identity,
        prior_policy_identity,
        rotation_predecessor_identity,
        exact_rotation_cuts_identity,
    }
);
define_verified_source!(
    VerifiedSuccessorPopSourceV1,
    SuccessorPopChallenge {
        successor_proposal_identity,
        successor_challenge_identity,
        successor_key_identity,
        predecessor_binding_identity,
        transition_identity,
    }
);
define_verified_source!(
    VerifiedGlobalRefusalSourceV1,
    ClassifiedGlobalRefusal {
        refusal_classification_identity,
        authority_custody_policy_evidence_identity,
        exact_refusal_frontier_identity,
    }
);
define_verified_source!(
    VerifiedInstallationIntentSourceV1,
    InstallationIntentFacts {
        bootstrap_grant_identity,
        proposal_identity,
        attempt_mode_identity,
        initial_policy_identity,
        bootstrap_generation_preimage_identity,
    }
);
define_verified_source!(
    VerifiedInstallationReceiptSourceV1,
    InstallationCompletionFacts {
        installation_intent_message_identity,
        physical_generation_bootstrap_message_identity,
        generation_commitment_identity,
        pre_receipt_bg_lock_backend_facts_identity,
    }
);
define_verified_source!(
    VerifiedPolicyTransitionIntentSourceV1,
    PolicyTransitionIntentFacts {
        transition_mode_identity,
        mandatory_rotation_continuity_message_identity,
        policy_continuity_or_unchanged_proof_identity,
        predecessor_successor_keys_identity,
        exact_transition_frontier_and_cuts_identity,
    }
);
define_verified_source!(
    VerifiedCurrentTransitionReceiptSourceV1,
    TransitionReceiptCurrentFacts {
        selected_transition_input_identity,
        completed_append_identity,
        complete_candidate_set_identity,
        generation_current_resolution_identity,
    }
);
define_verified_source!(
    VerifiedPendingTransitionReceiptSourceV1,
    TransitionReceiptPendingFacts {
        selected_transition_input_identity,
        completed_append_identity,
        complete_candidate_set_identity,
        pending_successor_resolution_identity,
    }
);

macro_rules! define_signed_message {
    ($name:ident, $route:ident, $source:ident) => {
        #[derive(Debug, PartialEq, Eq)]
        pub(crate) struct $name {
            coordinates: StoreVerifiedSigningCoordinatesV1,
            source: $source,
            exact: ExactMessageEncodingV1,
        }

        impl $name {
            pub(super) fn from_store_verified(
                _permit: &CoordinatorMessageConstructionPermitV1,
                coordinates: StoreVerifiedSigningCoordinatesV1,
                source: $source,
            ) -> Result<Self, SignerRefusalV2> {
                let exact =
                    encode_exact_message(C2StoreSigningRouteV1::$route, &coordinates, &source)?;
                Ok(Self {
                    coordinates,
                    source,
                    exact,
                })
            }

            fn verify(&self) -> Result<(), SignerRefusalV2> {
                let expected = encode_exact_message(
                    C2StoreSigningRouteV1::$route,
                    &self.coordinates,
                    &self.source,
                )?;
                if expected != self.exact {
                    return Err(SignerRefusalV2::MessagePayloadSubstitution);
                }
                Ok(())
            }
        }

        impl sealed::Sealed for $name {}

        impl SignerMessageV1 for $name {
            fn route(&self) -> C2StoreSigningRouteV1 {
                C2StoreSigningRouteV1::$route
            }

            fn coordinates(&self) -> &SignerMessageCoordinatesV1 {
                &self.coordinates.custody
            }

            fn verified_coordinates(&self) -> &StoreVerifiedSigningCoordinatesV1 {
                &self.coordinates
            }

            fn message_identity(&self) -> SignerIdentityV1 {
                self.exact.message_identity
            }

            fn transaction_identity(&self) -> SignerIdentityV1 {
                self.exact.transaction_identity
            }

            fn canonical_message(&self) -> &[u8] {
                &self.exact.canonical_message
            }

            fn canonical_preimage(&self) -> Vec<u8> {
                self.exact.signing_preimage.clone()
            }

            fn verify_closed_route(&self) -> Result<(), SignerRefusalV2> {
                self.verify()
            }
        }
    };
}

define_signed_message!(
    InitialProposalPoPFrameV1,
    Msg02InitialPop,
    VerifiedInitialPopSourceV1
);
define_signed_message!(
    PhysicalGenerationBootstrapFrameV1,
    Msg03PhysicalGenerationBootstrap,
    VerifiedPhysicalGenerationBootstrapSourceV1
);
define_signed_message!(
    ActivePolicyContinuityFrameV1,
    Msg05ActivePolicyContinuity,
    VerifiedActivePolicyContinuitySourceV1
);
define_signed_message!(
    NormalRotationContinuityFrameV1,
    Msg06NormalRotationContinuity,
    VerifiedHealthyRotationContinuitySourceV1
);
define_signed_message!(
    SuccessorPoPFrameV1,
    Msg07SuccessorPop,
    VerifiedSuccessorPopSourceV1
);
define_signed_message!(
    GlobalRefusalFrameV1,
    Msg08GlobalRefusal,
    VerifiedGlobalRefusalSourceV1
);
define_signed_message!(
    StoreGenerationInstallationIntentFrameV1,
    Msg09InstallationIntent,
    VerifiedInstallationIntentSourceV1
);
define_signed_message!(
    StoreGenerationInstallationReceiptFrameV1,
    Msg10InstallationReceipt,
    VerifiedInstallationReceiptSourceV1
);
define_signed_message!(
    PolicyTransitionIntentFrameV1,
    Msg11PolicyTransitionIntent,
    VerifiedPolicyTransitionIntentSourceV1
);
define_signed_message!(
    CurrentPolicyTransitionReceiptFrameV1,
    Msg12ReceiptCurrent,
    VerifiedCurrentTransitionReceiptSourceV1
);
define_signed_message!(
    PendingPolicyTransitionReceiptFrameV1,
    Msg12ReceiptPending,
    VerifiedPendingTransitionReceiptSourceV1
);

/// MSG-04 is an unsigned Store-derived relation and cannot implement
/// [`SignerMessageV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootstrapToGenerationRelationV1 {
    pub(crate) bootstrap_identity: SignerIdentityV1,
    pub(crate) generation_identity: SignerIdentityV1,
    pub(crate) transition_identity: SignerIdentityV1,
}

impl BootstrapToGenerationRelationV1 {
    fn validate(&self) -> Result<(), SignerRefusalV2> {
        if is_zero(&self.bootstrap_identity)
            || is_zero(&self.generation_identity)
            || is_zero(&self.transition_identity)
            || self.bootstrap_identity == self.generation_identity
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(())
    }
}

macro_rules! message_verifier {
    ($verify:ident, $ty:ident) => {
        pub(crate) fn $verify(message: &$ty) -> Result<(), SignerRefusalV2> {
            message.verify()
        }
    };
}

message_verifier!(
    verify_msg_02_initial_proposal_pop_proposed_store_integrity_key,
    InitialProposalPoPFrameV1
);
message_verifier!(
    verify_msg_03_chartered_physical_store_generation_bootstrap_bootstrap_signer,
    PhysicalGenerationBootstrapFrameV1
);
message_verifier!(
    verify_msg_05_active_policy_continuity_current_predecessor,
    ActivePolicyContinuityFrameV1
);
message_verifier!(
    verify_msg_06_healthy_rotation_continuity_current_usable_predecessor,
    NormalRotationContinuityFrameV1
);
message_verifier!(
    verify_msg_07_successor_pop_pending_successor_correspondence_not_authority,
    SuccessorPoPFrameV1
);
message_verifier!(
    verify_msg_08_global_refusal_current_generation_signer_after_g,
    GlobalRefusalFrameV1
);
message_verifier!(
    verify_msg_09_store_generation_installation_intent_bootstrap_signer,
    StoreGenerationInstallationIntentFrameV1
);
message_verifier!(
    verify_msg_10_store_generation_installation_receipt_bootstrap_signer_pre,
    StoreGenerationInstallationReceiptFrameV1
);
message_verifier!(
    verify_msg_11_policy_transition_intent_current_predecessor_signer_plus,
    PolicyTransitionIntentFrameV1
);
message_verifier!(
    verify_msg_12_policy_transition_receipt_generation_current,
    CurrentPolicyTransitionReceiptFrameV1
);
message_verifier!(
    verify_msg_12_policy_transition_receipt_pending_successor,
    PendingPolicyTransitionReceiptFrameV1
);

pub(crate) fn construct_msg_04_bootstrap_generation_transition_unsigned_store_derived_relation(
    bootstrap_identity: SignerIdentityV1,
    generation_identity: SignerIdentityV1,
    transition_identity: SignerIdentityV1,
) -> Result<BootstrapToGenerationRelationV1, SignerRefusalV2> {
    let relation = BootstrapToGenerationRelationV1 {
        bootstrap_identity,
        generation_identity,
        transition_identity,
    };
    relation.validate()?;
    Ok(relation)
}

pub(crate) fn verify_msg_04_bootstrap_generation_transition_unsigned_store_derived_relation(
    relation: &BootstrapToGenerationRelationV1,
) -> Result<(), SignerRefusalV2> {
    relation.validate()
}

/// Legacy-shaped fixture adapter used only by the custody and message unit
/// tests.  It is intentionally absent from production builds so raw digest
/// coordinates cannot become a production signing message.
#[cfg(test)]
pub(crate) fn construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
    custody: SignerMessageCoordinatesV1,
    verified_source_identity: SignerIdentityV1,
    transaction_identity: SignerIdentityV1,
) -> Result<NormalRotationContinuityFrameV1, SignerRefusalV2> {
    let permit = CoordinatorMessageConstructionPermitV1::for_test();
    let coordinates = StoreVerifiedSigningCoordinatesV1 {
        exact_scope: C2ExactSigningScopeV1::GenerationBound {
            scope_identity: custody.scope,
            physical_generation_identity: custody.physical_generation,
            lifecycle_root_identity: custody.lifecycle_root,
        },
        exact_authority: C2ExactSigningAuthorityV1::CurrentPredecessor {
            standing_identity: [21; 32],
        },
        custody,
        occurrence_id: "test-occurrence".to_owned(),
        resident_identity: "test-resident".to_owned(),
        resident_generation: 1,
        host_role: "store-integrity-signer".to_owned(),
        role_manifest_identity: [22; 32],
        role_manifest_generation: 1,
        authority_domain: "test-only".to_owned(),
        terminal_a1_identity: [23; 32],
        current_a2_snapshot_identity: [24; 32],
        grant_or_predecessor_standing_identity: [25; 32],
        signer_public_key: [26; 32],
        signer_key_generation: 1,
        signer_scope_policy_version: 1,
        active_store_policy_identity: [27; 32],
        active_store_policy_generation: 1,
        active_store_policy_digest: [28; 32],
        attempt_identity: [42; 32],
        event_predecessor_identity: verified_source_identity,
        transaction_intent_identity: transaction_identity,
        implementation_manifest_identity: [29; 32],
        manifest_admission_correspondence_identity: [30; 32],
        qualified_candidate_identity: [31; 32],
        source_tree_identity: [32; 32],
        runtime_artifact_identity: [33; 32],
        frontier_namespace_identity: [34; 32],
        predecessor_frontier_identity: [35; 32],
        exact_content_identity: [36; 32],
    };
    coordinates.validate()?;
    let source = VerifiedHealthyRotationContinuitySourceV1::from_store_verified(
        &permit,
        verified_source_identity,
        [37; 32],
        [38; 32],
        [39; 32],
        [40; 32],
        [41; 32],
    )?;
    NormalRotationContinuityFrameV1::from_store_verified(&permit, coordinates, source)
}

#[cfg(test)]
fn route_test_coordinates(
    route: C2StoreSigningRouteV1,
    signer_public_key: [u8; 32],
    discriminator: u8,
) -> StoreVerifiedSigningCoordinatesV1 {
    let id = |offset: u8| [discriminator.wrapping_add(offset).max(1); 32];
    let mut custody = SignerMessageCoordinatesV1 {
        occurrence: id(1),
        physical_generation: id(2),
        lifecycle_root: id(3),
        scope: id(4),
        policy: id(5),
        signer_key_generation: id(6),
        cut: 7,
    };
    if route.scope_class() != C2SigningScopeClassV1::GenerationBound {
        custody.physical_generation = [0; 32];
        custody.lifecycle_root = [0; 32];
    }
    let exact_scope = match route.scope_class() {
        C2SigningScopeClassV1::PreGeneration => C2ExactSigningScopeV1::PreGeneration {
            scope_identity: custody.scope,
            attempt_identity: id(7),
        },
        C2SigningScopeClassV1::ProspectivePhysicalGeneration => {
            C2ExactSigningScopeV1::ProspectivePhysicalGeneration {
                scope_identity: custody.scope,
                generation_preimage_identity: id(8),
                attempt_identity: id(7),
            }
        }
        C2SigningScopeClassV1::GenerationBound => C2ExactSigningScopeV1::GenerationBound {
            scope_identity: custody.scope,
            physical_generation_identity: custody.physical_generation,
            lifecycle_root_identity: custody.lifecycle_root,
        },
    };
    let exact_authority = match route.authority_class() {
        C2SigningAuthorityClassV1::ProposedKey => C2ExactSigningAuthorityV1::ProposedKey {
            grant_identity: id(9),
            candidate_identity: id(10),
        },
        C2SigningAuthorityClassV1::Bootstrap => C2ExactSigningAuthorityV1::Bootstrap {
            standing_identity: id(11),
        },
        C2SigningAuthorityClassV1::CurrentPredecessor => {
            C2ExactSigningAuthorityV1::CurrentPredecessor {
                standing_identity: id(11),
            }
        }
        C2SigningAuthorityClassV1::GenerationCurrent => {
            C2ExactSigningAuthorityV1::GenerationCurrent {
                standing_identity: id(11),
            }
        }
        C2SigningAuthorityClassV1::PendingSuccessor => {
            C2ExactSigningAuthorityV1::PendingSuccessor {
                standing_identity: id(11),
            }
        }
    };
    StoreVerifiedSigningCoordinatesV1 {
        custody,
        exact_scope,
        exact_authority,
        occurrence_id: format!("test-occurrence-{discriminator}"),
        resident_identity: format!("test-resident-{discriminator}"),
        resident_generation: 1,
        host_role: "store-integrity-signer".to_owned(),
        role_manifest_identity: id(12),
        role_manifest_generation: 1,
        authority_domain: "test-only".to_owned(),
        terminal_a1_identity: id(13),
        current_a2_snapshot_identity: id(14),
        grant_or_predecessor_standing_identity: id(15),
        signer_public_key,
        signer_key_generation: 1,
        signer_scope_policy_version: 1,
        active_store_policy_identity: id(16),
        active_store_policy_generation: 1,
        active_store_policy_digest: id(17),
        // The common attempt coordinate and the scope-specific attempt
        // coordinate are one semantic identity.  Keeping two independent
        // fixture values would describe a route that production validation
        // correctly refuses.
        attempt_identity: id(7),
        event_predecessor_identity: id(18),
        transaction_intent_identity: id(19),
        implementation_manifest_identity: id(20),
        manifest_admission_correspondence_identity: id(21),
        qualified_candidate_identity: id(22),
        source_tree_identity: id(23),
        runtime_artifact_identity: id(24),
        frontier_namespace_identity: id(25),
        predecessor_frontier_identity: id(26),
        exact_content_identity: id(27),
    }
}

/// Test-only executable construction of every Store/proposal route.  The
/// returned trait objects still use the sealed production verifier; this is
/// not a production raw-message constructor.
#[cfg(test)]
pub(super) fn construct_all_store_route_test_messages(
    signer_public_key: [u8; 32],
) -> Result<Vec<Box<dyn SignerMessageV1>>, SignerRefusalV2> {
    let permit = CoordinatorMessageConstructionPermitV1::for_test();
    let id =
        |route: C2StoreSigningRouteV1, offset: u8| [(route as u8).wrapping_add(offset).max(1); 32];
    macro_rules! push_message {
        ($messages:ident, $route:ident, $frame:ident, $source:ident, [$($offset:expr),+]) => {{
            let route = C2StoreSigningRouteV1::$route;
            let source = $source::from_store_verified(&permit, $(id(route, $offset),)+)?;
            let message = $frame::from_store_verified(
                &permit,
                route_test_coordinates(route, signer_public_key, route as u8),
                source,
            )?;
            $messages.push(Box::new(message) as Box<dyn SignerMessageV1>);
        }};
    }
    let mut messages: Vec<Box<dyn SignerMessageV1>> = Vec::new();
    push_message!(
        messages,
        Msg02InitialPop,
        InitialProposalPoPFrameV1,
        VerifiedInitialPopSourceV1,
        [40, 41, 42, 43, 44, 45]
    );
    push_message!(
        messages,
        Msg03PhysicalGenerationBootstrap,
        PhysicalGenerationBootstrapFrameV1,
        VerifiedPhysicalGenerationBootstrapSourceV1,
        [40, 41, 42, 43, 44]
    );
    push_message!(
        messages,
        Msg05ActivePolicyContinuity,
        ActivePolicyContinuityFrameV1,
        VerifiedActivePolicyContinuitySourceV1,
        [40, 41, 42, 43, 44, 45]
    );
    push_message!(
        messages,
        Msg06NormalRotationContinuity,
        NormalRotationContinuityFrameV1,
        VerifiedHealthyRotationContinuitySourceV1,
        [40, 41, 42, 43, 44, 45]
    );
    push_message!(
        messages,
        Msg07SuccessorPop,
        SuccessorPoPFrameV1,
        VerifiedSuccessorPopSourceV1,
        [40, 41, 42, 43, 44]
    );
    push_message!(
        messages,
        Msg08GlobalRefusal,
        GlobalRefusalFrameV1,
        VerifiedGlobalRefusalSourceV1,
        [40, 41, 42]
    );
    push_message!(
        messages,
        Msg09InstallationIntent,
        StoreGenerationInstallationIntentFrameV1,
        VerifiedInstallationIntentSourceV1,
        [40, 41, 42, 43, 44]
    );
    push_message!(
        messages,
        Msg10InstallationReceipt,
        StoreGenerationInstallationReceiptFrameV1,
        VerifiedInstallationReceiptSourceV1,
        [40, 41, 42, 43]
    );
    push_message!(
        messages,
        Msg11PolicyTransitionIntent,
        PolicyTransitionIntentFrameV1,
        VerifiedPolicyTransitionIntentSourceV1,
        [40, 41, 42, 43, 44]
    );
    push_message!(
        messages,
        Msg12ReceiptCurrent,
        CurrentPolicyTransitionReceiptFrameV1,
        VerifiedCurrentTransitionReceiptSourceV1,
        [40, 41, 42, 43]
    );
    push_message!(
        messages,
        Msg12ReceiptPending,
        PendingPolicyTransitionReceiptFrameV1,
        VerifiedPendingTransitionReceiptSourceV1,
        [40, 41, 42, 43]
    );
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::Value;

    use super::*;

    fn coordinates() -> SignerMessageCoordinatesV1 {
        SignerMessageCoordinatesV1 {
            occurrence: [1; 32],
            physical_generation: [2; 32],
            lifecycle_root: [3; 32],
            scope: [4; 32],
            policy: [5; 32],
            signer_key_generation: [6; 32],
            cut: 7,
        }
    }

    #[test]
    fn closed_family_route_and_external_census_is_exact_and_unique() {
        assert_eq!(ClosedMessageFamilyV1::ALL.len(), 16);
        assert_eq!(C2StoreSigningRouteV1::ALL.len(), 11);
        assert_eq!(C2ExternalSigningRouteV1::ALL.len(), 7);
        assert_eq!(
            C2StoreSigningRouteV1::ALL
                .iter()
                .map(|route| route.signature_domain())
                .collect::<BTreeSet<_>>()
                .len(),
            11
        );
        assert_eq!(
            C2ExternalSigningRouteV1::ALL
                .iter()
                .map(|route| route.signature_domain())
                .collect::<BTreeSet<_>>()
                .len(),
            7
        );
        assert_eq!(
            ClosedMessageFamilyV1::ALL
                .iter()
                .filter(|family| family.is_store_signable())
                .count(),
            10
        );
        assert_eq!(
            ClosedMessageFamilyV1::ALL
                .iter()
                .filter(|family| family.owner() == MessageFamilyOwnerV1::UnsignedStoreRelation)
                .copied()
                .collect::<Vec<_>>(),
            vec![ClosedMessageFamilyV1::Msg04BootstrapToGenerationRelation]
        );
    }

    #[test]
    fn bootstrap_grant_permission_projection_is_registry_derived_and_exact() {
        assert_eq!(
            bootstrap_grant_permitted_family_projection_v1(),
            vec![
                "physical_store_generation_genesis",
                "store_generation_installation_intent",
                "store_generation_installation_receipt",
            ],
        );
        assert_eq!(
            C2StoreSigningRouteV1::ALL
                .into_iter()
                .filter(|route| route.bootstrap_grant_permission_label().is_some())
                .collect::<Vec<_>>(),
            vec![
                C2StoreSigningRouteV1::Msg03PhysicalGenerationBootstrap,
                C2StoreSigningRouteV1::Msg09InstallationIntent,
                C2StoreSigningRouteV1::Msg10InstallationReceipt,
            ],
        );
    }

    #[test]
    fn every_store_route_has_executable_typed_construction_signing_and_verification() {
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let messages =
            construct_all_store_route_test_messages(signing_key.verifying_key().to_bytes())
                .expect("all closed route fixtures construct");
        assert_eq!(messages.len(), C2StoreSigningRouteV1::ALL.len());
        let mut observed = BTreeSet::new();
        for message in messages {
            message
                .verify_closed_route()
                .expect("closed route verifies");
            let preimage = message.canonical_preimage();
            assert!(preimage.starts_with(message.route().signature_domain().as_bytes()));
            let signature = signing_key.sign(&preimage);
            signing_key
                .verifying_key()
                .verify_strict(&preimage, &signature)
                .expect("route preimage is executable Ed25519 input");
            let wire: Value = serde_json::from_slice(message.canonical_message()).unwrap();
            assert_eq!(wire["route"], message.route().as_str());
            assert_eq!(wire["family"], message.family().as_str());
            assert_eq!(wire["identity_domain"], message.route().identity_domain());
            assert_eq!(wire["signature_domain"], message.route().signature_domain());
            assert!(observed.insert(message.route().as_str()));
        }
        assert_eq!(observed.len(), 11);
    }

    fn construct_msg06_from_exact_coordinates(
        coordinates: StoreVerifiedSigningCoordinatesV1,
    ) -> Result<NormalRotationContinuityFrameV1, SignerRefusalV2> {
        let permit = CoordinatorMessageConstructionPermitV1::for_test();
        let source = VerifiedHealthyRotationContinuitySourceV1::from_store_verified(
            &permit, [201; 32], [202; 32], [203; 32], [204; 32], [205; 32], [206; 32],
        )?;
        NormalRotationContinuityFrameV1::from_store_verified(&permit, coordinates, source)
    }

    #[test]
    fn every_common_coordinate_mutation_changes_identity_and_preimage_or_refuses() {
        let route = C2StoreSigningRouteV1::Msg06NormalRotationContinuity;
        let baseline_coordinates = route_test_coordinates(route, [77; 32], 70);
        let baseline =
            construct_msg06_from_exact_coordinates(baseline_coordinates.clone()).unwrap();
        let mut mutations: Vec<(&str, StoreVerifiedSigningCoordinatesV1)> = Vec::new();
        macro_rules! changed {
            ($name:literal, $body:expr) => {{
                let mut value = baseline_coordinates.clone();
                $body(&mut value);
                mutations.push(($name, value));
            }};
        }
        changed!(
            "custody.occurrence",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.custody.occurrence[0] ^= 1
        );
        changed!(
            "custody.physical_generation",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.custody.physical_generation[0] ^= 1
        );
        changed!(
            "custody.lifecycle_root",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.custody.lifecycle_root[0] ^= 1
        );
        changed!(
            "custody.scope",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.custody.scope[0] ^= 1
        );
        changed!(
            "custody.policy",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.custody.policy[0] ^= 1
        );
        changed!(
            "custody.signer_key_generation",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.custody.signer_key_generation[0] ^= 1
        );
        changed!(
            "custody.cut",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.custody.cut += 1
        );
        changed!(
            "exact_scope.scope",
            |v: &mut StoreVerifiedSigningCoordinatesV1| {
                if let C2ExactSigningScopeV1::GenerationBound { scope_identity, .. } =
                    &mut v.exact_scope
                {
                    scope_identity[0] ^= 1;
                }
            }
        );
        changed!(
            "exact_scope.physical_generation",
            |v: &mut StoreVerifiedSigningCoordinatesV1| {
                if let C2ExactSigningScopeV1::GenerationBound {
                    physical_generation_identity,
                    ..
                } = &mut v.exact_scope
                {
                    physical_generation_identity[0] ^= 1;
                }
            }
        );
        changed!(
            "exact_scope.lifecycle_root",
            |v: &mut StoreVerifiedSigningCoordinatesV1| {
                if let C2ExactSigningScopeV1::GenerationBound {
                    lifecycle_root_identity,
                    ..
                } = &mut v.exact_scope
                {
                    lifecycle_root_identity[0] ^= 1;
                }
            }
        );
        changed!(
            "exact_authority",
            |v: &mut StoreVerifiedSigningCoordinatesV1| {
                if let C2ExactSigningAuthorityV1::CurrentPredecessor { standing_identity } =
                    &mut v.exact_authority
                {
                    standing_identity[0] ^= 1;
                }
            }
        );
        changed!(
            "occurrence_id",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.occurrence_id.push('x')
        );
        changed!(
            "resident_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.resident_identity.push('x')
        );
        changed!(
            "resident_generation",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.resident_generation += 1
        );
        changed!("host_role", |v: &mut StoreVerifiedSigningCoordinatesV1| v
            .host_role
            .push('x'));
        changed!(
            "role_manifest_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.role_manifest_identity[0] ^= 1
        );
        changed!(
            "role_manifest_generation",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.role_manifest_generation += 1
        );
        changed!(
            "authority_domain",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.authority_domain.push('x')
        );
        changed!(
            "terminal_a1_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.terminal_a1_identity[0] ^= 1
        );
        changed!(
            "current_a2_snapshot_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.current_a2_snapshot_identity[0] ^= 1
        );
        changed!(
            "grant_or_predecessor_standing_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.grant_or_predecessor_standing_identity
                [0] ^= 1
        );
        changed!(
            "signer_public_key",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.signer_public_key[0] ^= 1
        );
        changed!(
            "signer_key_generation",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.signer_key_generation += 1
        );
        changed!(
            "signer_scope_policy_version",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.signer_scope_policy_version += 1
        );
        changed!(
            "active_store_policy_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.active_store_policy_identity[0] ^= 1
        );
        changed!(
            "active_store_policy_generation",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.active_store_policy_generation += 1
        );
        changed!(
            "active_store_policy_digest",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.active_store_policy_digest[0] ^= 1
        );
        changed!(
            "attempt_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.attempt_identity[0] ^= 1
        );
        changed!(
            "event_predecessor_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.event_predecessor_identity[0] ^= 1
        );
        changed!(
            "transaction_intent_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.transaction_intent_identity[0] ^= 1
        );
        changed!(
            "implementation_manifest_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.implementation_manifest_identity[0] ^= 1
        );
        changed!(
            "manifest_admission_correspondence_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v
                .manifest_admission_correspondence_identity[0] ^=
                1
        );
        changed!(
            "qualified_candidate_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.qualified_candidate_identity[0] ^= 1
        );
        changed!(
            "source_tree_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.source_tree_identity[0] ^= 1
        );
        changed!(
            "runtime_artifact_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.runtime_artifact_identity[0] ^= 1
        );
        changed!(
            "frontier_namespace_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.frontier_namespace_identity[0] ^= 1
        );
        changed!(
            "predecessor_frontier_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.predecessor_frontier_identity[0] ^= 1
        );
        changed!(
            "exact_content_identity",
            |v: &mut StoreVerifiedSigningCoordinatesV1| v.exact_content_identity[0] ^= 1
        );

        assert_eq!(mutations.len(), 38);
        for (name, coordinates) in mutations {
            match construct_msg06_from_exact_coordinates(coordinates) {
                Ok(mutated) => {
                    assert_ne!(
                        mutated.message_identity(),
                        baseline.message_identity(),
                        "{name}"
                    );
                    assert_ne!(
                        mutated.canonical_preimage(),
                        baseline.canonical_preimage(),
                        "{name}"
                    );
                }
                Err(
                    SignerRefusalV2::MessageFrontierMismatch
                    | SignerRefusalV2::MessagePayloadSubstitution,
                ) => {}
                Err(error) => panic!("unexpected refusal for {name}: {error}"),
            }
        }
    }

    #[test]
    fn msg12_routes_share_family_but_not_phase_or_signature_domain() {
        let current = C2StoreSigningRouteV1::Msg12ReceiptCurrent;
        let pending = C2StoreSigningRouteV1::Msg12ReceiptPending;
        assert_eq!(current.family(), pending.family());
        assert_ne!(current.phase(), pending.phase());
        assert_ne!(current.signature_domain(), pending.signature_domain());
        assert_eq!(current.identity_domain(), pending.identity_domain());
    }

    #[test]
    fn external_and_unsigned_families_have_no_store_route() {
        for family in [
            ClosedMessageFamilyV1::Msg01BootstrapGrant,
            ClosedMessageFamilyV1::Msg04BootstrapToGenerationRelation,
            ClosedMessageFamilyV1::Msg13RestoreAuthorization,
            ClosedMessageFamilyV1::Msg14RevocationJudgment,
            ClosedMessageFamilyV1::Msg15RecoveryGrant,
            ClosedMessageFamilyV1::Msg16QuarantineClosure,
        ] {
            assert!(
                C2StoreSigningRouteV1::ALL
                    .iter()
                    .all(|route| route.family() != family)
            );
        }
    }

    #[test]
    fn all_pairs_family_domain_substitution_is_excluded_by_closed_registry() {
        // Treat the complete registry projection as the decoder/signing-path
        // acceptance key.  For every ordered pair, a route accepts only its
        // own family/domain/phase/scope/authority/input/consumer tuple.  The
        // MSG-12 routes deliberately share family + identity domain, but the
        // pending/current phase and signature domains keep them distinct.
        for expected in C2StoreSigningRouteV1::ALL {
            for supplied in C2StoreSigningRouteV1::ALL {
                let accepted = expected.family() == supplied.family()
                    && expected.identity_domain() == supplied.identity_domain()
                    && expected.signature_domain() == supplied.signature_domain()
                    && expected.phase() == supplied.phase()
                    && expected.scope_class() == supplied.scope_class()
                    && expected.authority_class() == supplied.authority_class()
                    && expected.input_kind() == supplied.input_kind()
                    && expected.sole_consumer() == supplied.sole_consumer();
                assert_eq!(
                    accepted,
                    expected == supplied,
                    "{} accepted the registry tuple for {}",
                    expected.as_str(),
                    supplied.as_str(),
                );
            }
        }

        // External A1 routes form a separate closed signing lane.  Neither
        // an external domain nor an external family can be substituted into
        // any Store/proposal-key route.
        for store in C2StoreSigningRouteV1::ALL {
            for external in C2ExternalSigningRouteV1::ALL {
                assert_ne!(store.signature_domain(), external.signature_domain());
                assert!(
                    store.identity_domain() != external.identity_domain()
                        || store.family() != external.family(),
                    "external route {} aliases Store route {}",
                    external.as_str(),
                    store.as_str(),
                );
            }
        }
        for expected in C2ExternalSigningRouteV1::ALL {
            for supplied in C2ExternalSigningRouteV1::ALL {
                let accepted = expected.family() == supplied.family()
                    && expected.identity_domain() == supplied.identity_domain()
                    && expected.signature_domain() == supplied.signature_domain()
                    && expected.input_kind() == supplied.input_kind()
                    && expected.sole_consumer() == supplied.sole_consumer();
                assert_eq!(accepted, expected == supplied);
            }
        }
    }

    #[test]
    fn canonical_message_and_signature_preimage_follow_the_selected_domains() {
        let message = construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
            coordinates(),
            [11; 32],
            [12; 32],
        )
        .expect("valid message");
        let value: Value = serde_json::from_slice(message.canonical_message()).unwrap();
        assert_eq!(value["family"], "MSG-06");
        assert_eq!(value["route"], "msg06_normal_rotation_continuity");
        assert_eq!(
            value["signature_domain"],
            "nq.c2.signer_rotation_continuity.current_predecessor_signature.v1"
        );
        let prefix = b"nq.c2.signer_rotation_continuity.current_predecessor_signature.v1\0";
        assert!(message.canonical_preimage().starts_with(prefix));
        verify_msg_06_healthy_rotation_continuity_current_usable_predecessor(&message).unwrap();
    }

    #[test]
    fn every_coordinate_and_verified_input_mutation_changes_identity_and_preimage() {
        let original = construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
            coordinates(),
            [11; 32],
            [12; 32],
        )
        .unwrap();
        for index in 0..9 {
            let mut changed = coordinates();
            let (source, transaction) = match index {
                0 => {
                    changed.occurrence[0] ^= 1;
                    ([11; 32], [12; 32])
                }
                1 => {
                    changed.physical_generation[0] ^= 1;
                    ([11; 32], [12; 32])
                }
                2 => {
                    changed.lifecycle_root[0] ^= 1;
                    ([11; 32], [12; 32])
                }
                3 => {
                    changed.scope[0] ^= 1;
                    ([11; 32], [12; 32])
                }
                4 => {
                    changed.policy[0] ^= 1;
                    ([11; 32], [12; 32])
                }
                5 => {
                    changed.signer_key_generation[0] ^= 1;
                    ([11; 32], [12; 32])
                }
                6 => {
                    changed.cut += 1;
                    ([11; 32], [12; 32])
                }
                7 => ([13; 32], [12; 32]),
                _ => ([11; 32], [13; 32]),
            };
            let mutated = construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
                changed,
                source,
                transaction,
            )
            .unwrap();
            assert_ne!(mutated.message_identity(), original.message_identity());
            assert_ne!(mutated.canonical_preimage(), original.canonical_preimage());
        }
    }

    #[test]
    fn msg04_is_unsigned_and_cycle_free() {
        let relation =
            construct_msg_04_bootstrap_generation_transition_unsigned_store_derived_relation(
                [8; 32], [9; 32], [10; 32],
            )
            .expect("valid relation");
        verify_msg_04_bootstrap_generation_transition_unsigned_store_derived_relation(&relation)
            .expect("relation verifies");
    }
}
