//! Store-owned typed signing and durable B/G append coordination.
//!
//! A route-specific message can be assembled only while this coordinator
//! holds a sealed live phase.  Custody signs only inside the actor-minted
//! append callback, and the resulting frame is inserted into the durable
//! signer ledger before the callback can return.

use std::collections::BTreeSet;

use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::append_extent::{
    C2AppendExtentRefusalV1, C2AppendFrameKindV1, C2DurableAppendOutcomeV1,
    C2DurableAppendPairSnapshotV1, C2DurableAppendPairV1, C2LockBacklinkV1,
    construct_lock_backlink_from_durable_bootstrap_v1,
};
use crate::store_generation::live_c2::{
    BootstrapV1, C2LiveSignerContextV1, C2LiveSigningAuthorityV1, C2SignerAppendRefusalV1,
    GenerationCurrentV1, PendingPossessionV1, PendingSelectedV1, StoreC2SnapshotActorV1,
    StoreVerifiedInstallationBootstrapFactsV1, StoreVerifiedInstallationReceiptFactsV1,
};

use super::custody::{C2StoreIntegrityCustodian, CustodySignatureV1};
use super::messages::{
    ActivePolicyContinuityFrameV1, C2ExactSigningAuthorityV1, C2StoreSigningRouteV1,
    ClosedMessageFamilyV1, CurrentPolicyTransitionReceiptFrameV1, GlobalRefusalFrameV1,
    InitialProposalPoPFrameV1, NormalRotationContinuityFrameV1,
    PendingPolicyTransitionReceiptFrameV1, PhysicalGenerationBootstrapFrameV1,
    PolicyTransitionIntentFrameV1, SignerIdentityV1, SignerMessageV1,
    StoreGenerationInstallationIntentFrameV1, StoreGenerationInstallationReceiptFrameV1,
    StoreVerifiedSigningCoordinatesV1, SuccessorPoPFrameV1, VerifiedActivePolicyContinuitySourceV1,
    VerifiedCurrentTransitionReceiptSourceV1, VerifiedGlobalRefusalSourceV1,
    VerifiedHealthyRotationContinuitySourceV1, VerifiedInitialPopSourceV1,
    VerifiedInstallationIntentSourceV1, VerifiedInstallationReceiptSourceV1,
    VerifiedPendingTransitionReceiptSourceV1, VerifiedPhysicalGenerationBootstrapSourceV1,
    VerifiedPolicyTransitionIntentSourceV1, VerifiedSuccessorPopSourceV1,
};
use super::records::VerifiedInitialPossessionRequestV1;
use super::result::SignerRefusalV2;

const APPEND_IDENTITY_DOMAIN_V1: &[u8] = b"nq.c2.signer_message_append.identity.v1\0";
const APPEND_OCCURRENCE_DOMAIN_V1: &[u8] = b"nq.c2.signer_message_append.occurrence.v1\0";
const FRONTIER_IDENTITY_DOMAIN_V1: &[u8] = b"nq.c2.signer_frontier.identity.v1\0";

/// Lexical proof that custody was reached through the typed coordinator.
pub(super) struct CoordinatorSigningPermitV1 {
    _private: (),
}

impl CoordinatorSigningPermitV1 {
    fn issue() -> Self {
        Self { _private: () }
    }

    /// Test-only lexical token for custody hostile/specification tests.
    ///
    /// This deliberately does not exist in production builds: production
    /// custody is reachable only inside the Store actor's append callback.
    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self::issue()
    }
}

/// Lexical proof that route-specific source and message construction happened
/// inside the coordinator.  The permit carries no authority and never escapes.
pub(super) struct CoordinatorMessageConstructionPermitV1 {
    _private: (),
}

impl CoordinatorMessageConstructionPermitV1 {
    fn issue() -> Self {
        Self { _private: () }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self::issue()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignedFrameAppendDispositionV1 {
    Appended,
    ExactReplay,
}

/// Durable append/effect receipt.  It is evidence only and cannot construct a
/// signer phase or custody authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsumedSignedFrameV1 {
    pub(crate) disposition: SignedFrameAppendDispositionV1,
    pub(crate) family: ClosedMessageFamilyV1,
    pub(crate) route: C2StoreSigningRouteV1,
    pub(crate) message_identity: SignerIdentityV1,
    pub(crate) append_identity: String,
    pub(crate) signer_key_generation: SignerIdentityV1,
    pub(crate) ledger_sequence: u64,
    pub(crate) generation_sequence: u64,
    pub(crate) event_cut: u64,
    pub(crate) resulting_frontier_identity: SignerIdentityV1,
    pub(crate) effect_receipt_identity: String,
}

/// Exact Store-resolved policy outcome for one healthy rotation.
///
/// This is a closed append plan, not caller-selectable signing authority.
/// `Changed` retains the MSG-05 source coordinates selected by Store policy;
/// `Unchanged` retains the mechanically derived proof that policy,
/// activation, and applicability are all unchanged.  Neither variant can
/// omit the mandatory MSG-06 step below.
enum HealthyRotationPolicyOutcomeV1 {
    Changed {
        immutable_signer_policy_identity: SignerIdentityV1,
        old_active_policy_identity: SignerIdentityV1,
        new_active_policy_identity: SignerIdentityV1,
        activation_identity: SignerIdentityV1,
        policy_predecessor_identity: SignerIdentityV1,
        successor_grant_or_unchanged_applicability_identity: SignerIdentityV1,
    },
    Unchanged {
        exact_policy_activation_applicability_proof_identity: SignerIdentityV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HealthyRotationAppendStepV1 {
    MandatoryMsg06,
    ConditionalMsg05,
    Msg11,
}

impl HealthyRotationPolicyOutcomeV1 {
    fn append_plan(&self) -> &'static [HealthyRotationAppendStepV1] {
        match self {
            Self::Changed { .. } => &[
                HealthyRotationAppendStepV1::MandatoryMsg06,
                HealthyRotationAppendStepV1::ConditionalMsg05,
                HealthyRotationAppendStepV1::Msg11,
            ],
            Self::Unchanged { .. } => &[
                HealthyRotationAppendStepV1::MandatoryMsg06,
                HealthyRotationAppendStepV1::Msg11,
            ],
        }
    }
}

/// Actor-sealed exact MSG-07 source.  The proposal/key coordinates are
/// rechecked against the retained pending-successor custody before this value
/// can enter the typed coordinator.
pub(in crate::store_generation) struct StoreVerifiedSuccessorPossessionFactsV1 {
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    successor_proposal_identity: SignerIdentityV1,
    successor_challenge_identity: SignerIdentityV1,
    successor_key_identity: SignerIdentityV1,
    predecessor_binding_identity: SignerIdentityV1,
    transition_identity: SignerIdentityV1,
}

/// Process-local evidence that the exact successor PoP was durably appended.
/// It is not currentness or standing and can only feed the later predecessor
/// continuity decision under the same actor lineage.
pub(in crate::store_generation) struct ConsumedSuccessorPossessionV1 {
    actor_instance_identity: Sha256Digest,
    post_append_snapshot_identity: Sha256Digest,
    post_append_effect_epoch: u64,
    successor_proposal_identity: SignerIdentityV1,
    successor_key_identity: SignerIdentityV1,
    transition_identity: SignerIdentityV1,
    consumed: ConsumedSignedFrameV1,
}

/// Exact Store-resolved source for the current-predecessor half of a healthy
/// rotation.  Construction compares the target policy/activation/
/// applicability coordinates to the sealed live predecessor and therefore
/// decides, rather than accepts, whether MSG-05 is required.
pub(in crate::store_generation) struct StoreVerifiedHealthyRotationIntentFactsV1 {
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    successor_proposal_identity: SignerIdentityV1,
    successor_pop_identity: SignerIdentityV1,
    successor_key_identity: SignerIdentityV1,
    transition_identity: SignerIdentityV1,
    prior_enrollment_identity: SignerIdentityV1,
    prior_policy_identity: SignerIdentityV1,
    rotation_predecessor_identity: SignerIdentityV1,
    exact_rotation_cuts_identity: SignerIdentityV1,
    transition_mode_identity: SignerIdentityV1,
    predecessor_successor_keys_identity: SignerIdentityV1,
    transition_cut: u64,
    policy: HealthyRotationPolicyOutcomeV1,
}

/// Durable outputs of the mandatory continuity plus exact policy branch and
/// MSG-11 append.  Actual consumed message identities, never desired
/// identities, are retained for MSG-12 selection.
pub(in crate::store_generation) struct ConsumedHealthyRotationIntentV1 {
    actor_instance_identity: Sha256Digest,
    post_append_snapshot_identity: Sha256Digest,
    post_append_effect_epoch: u64,
    successor_proposal_identity: SignerIdentityV1,
    successor_pop_identity: SignerIdentityV1,
    transition_identity: SignerIdentityV1,
    mandatory_msg06: ConsumedSignedFrameV1,
    conditional_msg05: Option<ConsumedSignedFrameV1>,
    msg11: ConsumedSignedFrameV1,
}

/// Resolver-sealed pending-successor MSG-12 source. The Store carries the
/// exact selected transition and completed append identities forward from the
/// consumed MSG-11 evidence, then joins them to a freshly sealed
/// `PendingSelected` context. No former actor epoch is treated as current.
pub(in crate::store_generation) struct StoreVerifiedPendingRotationReceiptFactsV1 {
    actor_instance_identity: Sha256Digest,
    actor_snapshot_identity: Sha256Digest,
    actor_effect_epoch: u64,
    selected_transition_input_identity: SignerIdentityV1,
    completed_append_identity: SignerIdentityV1,
    complete_candidate_set_identity: SignerIdentityV1,
    pending_successor_resolution_identity: SignerIdentityV1,
}

fn require_nonzero_identity(
    identity: SignerIdentityV1,
) -> Result<SignerIdentityV1, SignerRefusalV2> {
    if identity.iter().all(|byte| *byte == 0) {
        Err(SignerRefusalV2::MessageFrontierMismatch)
    } else {
        Ok(identity)
    }
}

fn digest_qualified_identity(identity: &Sha256Digest) -> Result<SignerIdentityV1, SignerRefusalV2> {
    let encoded = identity
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(SignerRefusalV2::MessageFrontierMismatch)?;
    hex::decode(encoded)
        .map_err(|_| SignerRefusalV2::MessageFrontierMismatch)?
        .try_into()
        .map_err(|_| SignerRefusalV2::MessageFrontierMismatch)
}

fn rotation_identity(domain: &[u8], parts: &[&[u8]]) -> SignerIdentityV1 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn healthy_rotation_policy_changed(
    old_policy: SignerIdentityV1,
    current_activation: SignerIdentityV1,
    current_applicability: SignerIdentityV1,
    target_policy: SignerIdentityV1,
    target_activation: SignerIdentityV1,
    target_applicability: SignerIdentityV1,
) -> bool {
    target_policy != old_policy
        || target_activation != current_activation
        || target_applicability != current_applicability
}

impl StoreVerifiedSuccessorPossessionFactsV1 {
    /// Seal MSG-07 only from one live pending-possession context whose
    /// retained custody is the exact successor proposal/key.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn from_store_actor_resolution(
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
        successor_challenge_identity: SignerIdentityV1,
        predecessor_binding_identity: SignerIdentityV1,
        transition_identity: SignerIdentityV1,
    ) -> Result<Self, C2SignerAppendRefusalV1> {
        context.verify_live(actor)?;
        let view = context.signing_view();
        if view.phase() != crate::store_generation::live_c2::C2LiveSigningPhaseV1::PendingPossession
            || view.authority_class() != C2LiveSigningAuthorityV1::PendingSuccessor
        {
            return Err(SignerRefusalV2::CapabilityFamilyMismatch.into());
        }
        Ok(Self {
            actor_instance_identity: actor.actor_instance_identity().clone(),
            actor_snapshot_identity: actor.current_snapshot_identity().clone(),
            actor_effect_epoch: actor.effect_epoch(),
            successor_proposal_identity: digest_qualified_identity(
                context.retained_custodian().proposal_identity(),
            )?,
            successor_challenge_identity: require_nonzero_identity(successor_challenge_identity)?,
            successor_key_identity: require_nonzero_identity(
                view.signer_key_generation_identity(),
            )?,
            predecessor_binding_identity: require_nonzero_identity(predecessor_binding_identity)?,
            transition_identity: require_nonzero_identity(transition_identity)?,
        })
    }

    fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, PendingPossessionV1>,
    ) -> Result<(), C2SignerAppendRefusalV1> {
        context.verify_live(actor)?;
        let view = context.signing_view();
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
            || self.successor_proposal_identity
                != digest_qualified_identity(context.retained_custodian().proposal_identity())?
            || self.successor_key_identity != view.signer_key_generation_identity()
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch.into());
        }
        Ok(())
    }
}

impl ConsumedSuccessorPossessionV1 {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2SignerAppendRefusalV1> {
        actor.verify_same_snapshot()?;
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.post_append_snapshot_identity != *actor.current_snapshot_identity()
            || self.post_append_effect_epoch != actor.effect_epoch()
            || self.consumed.family != ClosedMessageFamilyV1::Msg07SuccessorPop
            || self.consumed.route != C2StoreSigningRouteV1::Msg07SuccessorPop
            || self.consumed.message_identity.iter().all(|byte| *byte == 0)
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch.into());
        }
        Ok(())
    }

    #[must_use]
    pub(in crate::store_generation) const fn actor_instance_identity(&self) -> &Sha256Digest {
        &self.actor_instance_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn post_append_snapshot_identity(&self) -> &Sha256Digest {
        &self.post_append_snapshot_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn post_append_effect_epoch(&self) -> u64 {
        self.post_append_effect_epoch
    }

    #[must_use]
    pub(in crate::store_generation) const fn message_identity(&self) -> SignerIdentityV1 {
        self.consumed.message_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn resulting_frontier_identity(
        &self,
    ) -> SignerIdentityV1 {
        self.consumed.resulting_frontier_identity
    }

    #[must_use]
    pub(in crate::store_generation) fn append_identity(&self) -> &str {
        &self.consumed.append_identity
    }

    #[must_use]
    pub(in crate::store_generation) fn effect_receipt_identity(&self) -> &str {
        &self.consumed.effect_receipt_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn successor_proposal_identity(
        &self,
    ) -> SignerIdentityV1 {
        self.successor_proposal_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn successor_key_identity(&self) -> SignerIdentityV1 {
        self.successor_key_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn transition_identity(&self) -> SignerIdentityV1 {
        self.transition_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn consumed(&self) -> &ConsumedSignedFrameV1 {
        &self.consumed
    }

    /// Exact consumed MSG-07 frame. This is durable append evidence only; the
    /// borrow cannot reconstruct pending-successor authority.
    #[must_use]
    pub(in crate::store_generation) const fn msg07(&self) -> &ConsumedSignedFrameV1 {
        &self.consumed
    }
}

impl StoreVerifiedHealthyRotationIntentFactsV1 {
    /// Decide the exact MSG-05 branch while sealing the mandatory MSG-06 and
    /// MSG-11 sources. The target triple must come from the Store policy
    /// resolver; this constructor itself mechanically compares it to the
    /// predecessor context, so an unchanged label cannot suppress MSG-05.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::store_generation) fn from_store_actor_resolution(
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
        possession: &ConsumedSuccessorPossessionV1,
        prior_enrollment_identity: SignerIdentityV1,
        rotation_predecessor_identity: SignerIdentityV1,
        transition_cut: u64,
        target_active_policy_identity: SignerIdentityV1,
        target_activation_identity: SignerIdentityV1,
        target_applicability_identity: SignerIdentityV1,
    ) -> Result<Self, C2SignerAppendRefusalV1> {
        possession.verify_for_actor(actor)?;
        context.verify_live(actor)?;
        let view = context.signing_view();
        if transition_cut <= view.event_cut() {
            return Err(SignerRefusalV2::MessageFrontierMismatch.into());
        }
        let prior_enrollment_identity = require_nonzero_identity(prior_enrollment_identity)?;
        let rotation_predecessor_identity =
            require_nonzero_identity(rotation_predecessor_identity)?;
        let target_active_policy_identity =
            require_nonzero_identity(target_active_policy_identity)?;
        let target_activation_identity = require_nonzero_identity(target_activation_identity)?;
        let target_applicability_identity =
            require_nonzero_identity(target_applicability_identity)?;
        let transition_identity = possession.transition_identity;
        let successor_proposal_identity = possession.successor_proposal_identity;
        let successor_pop_identity = possession.consumed.message_identity;
        let successor_key_identity = possession.successor_key_identity;
        let immutable_policy = view.signer_scope_policy_identity();
        let old_policy = view.active_policy_identity();
        let current_activation = view.current_a2_identity();
        // Applicability is a Store-derived correspondence over the current
        // authority/policy/scope snapshot.  The historical bootstrap grant is
        // deliberately not reused as a proxy for current applicability.
        let current_applicability = rotation_identity(
            b"nq.c2.healthy_rotation.current_applicability.identity.v1\0",
            &[
                &current_activation,
                &old_policy,
                &view.active_policy_digest(),
                &view.signer_scope_policy_identity(),
                &view.signer_scope_identity(),
                &view.terminal_a1_identity(),
            ],
        );
        let policy_predecessor = view
            .predecessor_event_identity()
            .unwrap_or(view.predecessor_frontier_identity());
        let event_cut = view.event_cut().to_be_bytes();
        let transition_cut_bytes = transition_cut.to_be_bytes();
        let exact_rotation_cuts_identity = rotation_identity(
            b"nq.c2.healthy_rotation.exact_cuts.identity.v1\0",
            &[
                &event_cut,
                &transition_cut_bytes,
                &view.predecessor_frontier_identity(),
                &transition_identity,
                actor.current_snapshot_identity().as_str().as_bytes(),
            ],
        );
        let transition_mode_identity = rotation_identity(
            b"nq.c2.healthy_rotation.mode.identity.v1\0",
            &[b"normal_successor"],
        );
        let predecessor_successor_keys_identity = rotation_identity(
            b"nq.c2.healthy_rotation.keys.identity.v1\0",
            &[
                &view.signer_key_generation_identity(),
                &successor_key_identity,
                &view.signer_public_key(),
                &transition_identity,
            ],
        );
        let changed = healthy_rotation_policy_changed(
            old_policy,
            current_activation,
            current_applicability,
            target_active_policy_identity,
            target_activation_identity,
            target_applicability_identity,
        );
        let policy = if changed {
            HealthyRotationPolicyOutcomeV1::Changed {
                immutable_signer_policy_identity: immutable_policy,
                old_active_policy_identity: old_policy,
                new_active_policy_identity: target_active_policy_identity,
                activation_identity: target_activation_identity,
                policy_predecessor_identity: policy_predecessor,
                successor_grant_or_unchanged_applicability_identity: target_applicability_identity,
            }
        } else {
            HealthyRotationPolicyOutcomeV1::Unchanged {
                exact_policy_activation_applicability_proof_identity: rotation_identity(
                    b"nq.c2.healthy_rotation.unchanged_policy_activation_applicability.v1\0",
                    &[
                        &immutable_policy,
                        &old_policy,
                        &view.active_policy_digest(),
                        &current_activation,
                        &current_applicability,
                        &rotation_predecessor_identity,
                        &successor_proposal_identity,
                        &successor_pop_identity,
                        &transition_identity,
                    ],
                ),
            }
        };
        Ok(Self {
            actor_instance_identity: actor.actor_instance_identity().clone(),
            actor_snapshot_identity: actor.current_snapshot_identity().clone(),
            actor_effect_epoch: actor.effect_epoch(),
            successor_proposal_identity,
            successor_pop_identity,
            successor_key_identity,
            transition_identity,
            prior_enrollment_identity,
            prior_policy_identity: old_policy,
            rotation_predecessor_identity,
            exact_rotation_cuts_identity,
            transition_mode_identity,
            predecessor_successor_keys_identity,
            transition_cut,
            policy,
        })
    }

    fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, GenerationCurrentV1>,
    ) -> Result<(), C2SignerAppendRefusalV1> {
        context.verify_live(actor)?;
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
            || self.transition_cut <= context.signing_view().event_cut()
            || self.policy.append_plan().first()
                != Some(&HealthyRotationAppendStepV1::MandatoryMsg06)
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch.into());
        }
        Ok(())
    }
}

impl ConsumedHealthyRotationIntentV1 {
    pub(in crate::store_generation) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), C2SignerAppendRefusalV1> {
        actor.verify_same_snapshot()?;
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.post_append_snapshot_identity != *actor.current_snapshot_identity()
            || self.post_append_effect_epoch != actor.effect_epoch()
            || self.mandatory_msg06.family != ClosedMessageFamilyV1::Msg06NormalRotationContinuity
            || self.mandatory_msg06.route != C2StoreSigningRouteV1::Msg06NormalRotationContinuity
            || self.msg11.family != ClosedMessageFamilyV1::Msg11PolicyTransitionIntent
            || self.msg11.route != C2StoreSigningRouteV1::Msg11PolicyTransitionIntent
            || self.msg11.message_identity.iter().all(|byte| *byte == 0)
            || self.conditional_msg05.as_ref().is_some_and(|message| {
                message.family != ClosedMessageFamilyV1::Msg05ActivePolicyContinuity
                    || message.route != C2StoreSigningRouteV1::Msg05ActivePolicyContinuity
            })
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch.into());
        }
        Ok(())
    }

    #[must_use]
    pub(in crate::store_generation) const fn successor_proposal_identity(
        &self,
    ) -> SignerIdentityV1 {
        self.successor_proposal_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn successor_pop_identity(&self) -> SignerIdentityV1 {
        self.successor_pop_identity
    }

    #[must_use]
    pub(in crate::store_generation) const fn transition_identity(&self) -> SignerIdentityV1 {
        self.transition_identity
    }

    /// Exact mandatory MSG-06 append consumed by MSG-11. This is durable
    /// evidence and does not transfer the predecessor's live authority.
    #[must_use]
    pub(in crate::store_generation) const fn mandatory_msg06(&self) -> &ConsumedSignedFrameV1 {
        &self.mandatory_msg06
    }

    /// Exact conditional MSG-05 append, present only when the Store-resolved
    /// policy/activation/applicability branch changed.
    #[must_use]
    pub(in crate::store_generation) fn conditional_msg05(&self) -> Option<&ConsumedSignedFrameV1> {
        self.conditional_msg05.as_ref()
    }

    /// Exact consumed MSG-11 transition intent selected downstream. Reading
    /// it does not claim that its former actor epoch is still current.
    #[must_use]
    pub(in crate::store_generation) const fn msg11(&self) -> &ConsumedSignedFrameV1 {
        &self.msg11
    }
}

impl StoreVerifiedPendingRotationReceiptFactsV1 {
    /// Seal the pending MSG-12 source at the fresh PendingSelected actor cut.
    ///
    /// The selected transition and completed append identities are durable
    /// evidence resolved by the Store before this call. The constructor does
    /// not require the older `ConsumedHealthyRotationIntentV1` to pretend its
    /// post-MSG-11 actor epoch remains live after foundation adoption,
    /// acceptance, and PendingSelected minting.
    pub(in crate::store_generation) fn from_store_actor_resolution(
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, PendingSelectedV1>,
        selected_transition_input_identity: SignerIdentityV1,
        completed_append_identity: SignerIdentityV1,
        complete_candidate_set_identity: SignerIdentityV1,
        pending_successor_resolution_identity: SignerIdentityV1,
    ) -> Result<Self, C2SignerAppendRefusalV1> {
        context.verify_live(actor)?;
        let view = context.signing_view();
        let selected_transition_input_identity =
            require_nonzero_identity(selected_transition_input_identity)?;
        let completed_append_identity = require_nonzero_identity(completed_append_identity)?;
        if view.phase() != crate::store_generation::live_c2::C2LiveSigningPhaseV1::PendingSelected
            || view.authority_class() != C2LiveSigningAuthorityV1::PendingSuccessor
        {
            return Err(SignerRefusalV2::CapabilityFamilyMismatch.into());
        }
        if view.transition_intent_identity() != Some(selected_transition_input_identity) {
            return Err(SignerRefusalV2::MessageFrontierMismatch.into());
        }
        Ok(Self {
            actor_instance_identity: actor.actor_instance_identity().clone(),
            actor_snapshot_identity: actor.current_snapshot_identity().clone(),
            actor_effect_epoch: actor.effect_epoch(),
            selected_transition_input_identity,
            completed_append_identity,
            complete_candidate_set_identity: require_nonzero_identity(
                complete_candidate_set_identity,
            )?,
            pending_successor_resolution_identity: require_nonzero_identity(
                pending_successor_resolution_identity,
            )?,
        })
    }

    fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
        context: &C2LiveSignerContextV1<'_, '_, PendingSelectedV1>,
    ) -> Result<(), C2SignerAppendRefusalV1> {
        context.verify_live(actor)?;
        if self.actor_instance_identity != *actor.actor_instance_identity()
            || self.actor_snapshot_identity != *actor.current_snapshot_identity()
            || self.actor_effect_epoch != actor.effect_epoch()
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch.into());
        }
        Ok(())
    }
}

/// Process-local proof that the exact actor-bound MSG-02 request was signed
/// by its proposed key and durably appended.  It is evidence for foundational
/// adoption only; it is not standing and has no raw-parts constructor.
pub(crate) struct ConsumedInitialProposalPoPV1<'request, 'store> {
    request: &'request VerifiedInitialPossessionRequestV1<'request, 'store>,
    actor_instance_identity: Sha256Digest,
    post_append_snapshot_identity: Sha256Digest,
    post_append_effect_epoch: u64,
    message_identity: SignerIdentityV1,
    append_identity: String,
    resulting_frontier_identity: SignerIdentityV1,
    effect_receipt_identity: String,
}

/// Opaque exact outcome of the installation genesis batch. It preserves
/// semantic receipts and physical B correspondence without equating their
/// identities or exposing a generic append capability.
pub(crate) struct ConsumedInstallationBootstrapBatchV1 {
    intent: ConsumedSignedFrameV1,
    bootstrap: ConsumedSignedFrameV1,
    physical_bootstrap: C2DurableAppendOutcomeV1,
    physical_intent: C2DurableAppendOutcomeV1,
    carrier_snapshot: C2DurableAppendPairSnapshotV1,
}

impl ConsumedInstallationBootstrapBatchV1 {
    pub(in crate::store_generation) fn from_store_batch(
        intent: ConsumedSignedFrameV1,
        bootstrap: ConsumedSignedFrameV1,
        physical_bootstrap: C2DurableAppendOutcomeV1,
        physical_intent: C2DurableAppendOutcomeV1,
        carrier_snapshot: C2DurableAppendPairSnapshotV1,
    ) -> Self {
        Self {
            intent,
            bootstrap,
            physical_bootstrap,
            physical_intent,
            carrier_snapshot,
        }
    }

    pub(crate) const fn intent(&self) -> &ConsumedSignedFrameV1 {
        &self.intent
    }

    pub(crate) const fn bootstrap(&self) -> &ConsumedSignedFrameV1 {
        &self.bootstrap
    }

    pub(crate) const fn bootstrap_physical_frame_identity(&self) -> &Sha256Digest {
        &self.physical_bootstrap.frame_identity
    }

    pub(crate) const fn bootstrap_physical_slot(&self) -> u32 {
        self.physical_bootstrap.slot
    }

    pub(crate) const fn bootstrap_resulting_root(&self) -> &Sha256Digest {
        &self.physical_bootstrap.resulting_root
    }

    pub(crate) const fn intent_physical_slot(&self) -> u32 {
        self.physical_intent.slot
    }

    pub(crate) const fn intent_resulting_root(&self) -> &Sha256Digest {
        &self.physical_intent.resulting_root
    }

    pub(crate) const fn carrier_snapshot(&self) -> &C2DurableAppendPairSnapshotV1 {
        &self.carrier_snapshot
    }

    pub(crate) fn construct_lock_backlink(
        &self,
        physical_generation_identity: Sha256Digest,
    ) -> Result<C2LockBacklinkV1, C2AppendExtentRefusalV1> {
        construct_lock_backlink_from_durable_bootstrap_v1(
            physical_generation_identity,
            &self.physical_bootstrap,
        )
    }
}

impl<'request, 'store> ConsumedInitialProposalPoPV1<'request, 'store> {
    pub(in crate::store_generation) fn from_actor_append(
        actor: &StoreC2SnapshotActorV1<'_>,
        request: &'request VerifiedInitialPossessionRequestV1<'request, 'store>,
        consumed: ConsumedSignedFrameV1,
    ) -> Result<Self, SignerRefusalV2> {
        if consumed.family != ClosedMessageFamilyV1::Msg02InitialProposalPop
            || consumed.route != C2StoreSigningRouteV1::Msg02InitialPop
        {
            return Err(SignerRefusalV2::CapabilityFamilyMismatch);
        }
        Ok(Self {
            request,
            actor_instance_identity: actor.actor_instance_identity().clone(),
            post_append_snapshot_identity: actor.current_snapshot_identity().clone(),
            post_append_effect_epoch: actor.effect_epoch(),
            message_identity: consumed.message_identity,
            append_identity: consumed.append_identity,
            resulting_frontier_identity: consumed.resulting_frontier_identity,
            effect_receipt_identity: consumed.effect_receipt_identity,
        })
    }

    pub(crate) fn verify_for_actor(
        &self,
        actor: &StoreC2SnapshotActorV1<'_>,
    ) -> Result<(), SignerRefusalV2> {
        actor
            .verify_same_snapshot()
            .map_err(|_| SignerRefusalV2::MessageFrontierMismatch)?;
        if actor.actor_instance_identity() != &self.actor_instance_identity
            || actor.current_snapshot_identity() != &self.post_append_snapshot_identity
            || actor.effect_epoch() != self.post_append_effect_epoch
            || self.message_identity.iter().all(|byte| *byte == 0)
            || self
                .resulting_frontier_identity
                .iter()
                .all(|byte| *byte == 0)
            || self.append_identity.is_empty()
            || self.effect_receipt_identity.is_empty()
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(())
    }

    pub(crate) const fn request(&self) -> &VerifiedInitialPossessionRequestV1<'request, 'store> {
        self.request
    }

    pub(crate) const fn message_identity(&self) -> SignerIdentityV1 {
        self.message_identity
    }

    pub(crate) fn append_identity(&self) -> &str {
        &self.append_identity
    }

    pub(crate) const fn resulting_frontier_identity(&self) -> SignerIdentityV1 {
        self.resulting_frontier_identity
    }

    pub(crate) fn effect_receipt_identity(&self) -> &str {
        &self.effect_receipt_identity
    }

    pub(crate) const fn event_cut(&self) -> u64 {
        self.request.event_cut()
    }
}

#[derive(Debug)]
struct SignerMessageBrandV1 {
    family: ClosedMessageFamilyV1,
    route: C2StoreSigningRouteV1,
    message_identity: SignerIdentityV1,
    transaction_identity: SignerIdentityV1,
    terminal_binding: Option<SignerIdentityV1>,
    payload_digest: SignerIdentityV1,
}

#[derive(Debug, Deserialize, Serialize)]
struct PreparedAppendCoordinatesV1 {
    occurrence_id: String,
    occurrence_identity: SignerIdentityV1,
    physical_generation_identity: Option<SignerIdentityV1>,
    lifecycle_root_identity: Option<SignerIdentityV1>,
    prospective_generation_preimage: Option<SignerIdentityV1>,
    scope_identity: SignerIdentityV1,
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
    signer_scope_policy_identity: SignerIdentityV1,
    signer_scope_policy_version: u64,
    active_store_policy_identity: SignerIdentityV1,
    active_store_policy_generation: u64,
    active_store_policy_digest: SignerIdentityV1,
    implementation_manifest_identity: SignerIdentityV1,
    manifest_admission_correspondence_identity: SignerIdentityV1,
    qualified_candidate_identity: SignerIdentityV1,
    source_tree_identity: SignerIdentityV1,
    runtime_artifact_identity: SignerIdentityV1,
    signer_key_generation: u64,
    signer_key_generation_identity: SignerIdentityV1,
    event_predecessor_identity: SignerIdentityV1,
    transaction_intent_identity: SignerIdentityV1,
    frontier_namespace_identity: SignerIdentityV1,
    predecessor_frontier_identity: SignerIdentityV1,
    exact_content_identity: SignerIdentityV1,
    event_cut: u64,
}

/// Opaque, noncloneable request returned to the Store actor after custody
/// signing.  Only the actor can pass it to the durable append primitive; the
/// request exposes neither a generic mutation callback nor detached signing.
#[derive(Debug)]
pub(crate) struct C2PreparedSignedAppendV1 {
    brand: SignerMessageBrandV1,
    coordinates: PreparedAppendCoordinatesV1,
    canonical_message: Vec<u8>,
    signing_preimage: Vec<u8>,
    signature: CustodySignatureV1,
}

#[derive(Serialize)]
struct DurableSignerCarrierEnvelopeV1<'a> {
    schema: &'static str,
    append_identity: &'a str,
    family: &'static str,
    route: &'static str,
    identity_domain: &'static str,
    signature_domain: &'static str,
    signer_phase: &'static str,
    scope_class: &'static str,
    authority_class: &'static str,
    input_kind: &'static str,
    sole_consumer: &'static str,
    ledger_sequence: u64,
    generation_sequence: u64,
    message_identity: String,
    transaction_identity: String,
    terminal_binding_identity: Option<String>,
    payload_digest: String,
    coordinates: &'a PreparedAppendCoordinatesV1,
    canonical_message: &'a [u8],
    signing_preimage: &'a [u8],
    signature_algorithm: &'static str,
    signer_key_generation_identity: String,
    signature: String,
    resulting_frontier_identity: String,
    effect_receipt_identity: &'a str,
    effect_receipt_bytes: &'a [u8],
}

/// Owned decoder shape for the one canonical physical signer envelope.
/// Decoding this value is evidence only.  The verifier below must reconstruct
/// every derived identity and verify the Ed25519 signature before any field is
/// used by reopen or replay resolution.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableSignerCarrierEnvelopeOwnedV1 {
    schema: String,
    append_identity: String,
    family: String,
    route: String,
    identity_domain: String,
    signature_domain: String,
    signer_phase: String,
    scope_class: String,
    authority_class: String,
    input_kind: String,
    sole_consumer: String,
    ledger_sequence: u64,
    generation_sequence: u64,
    message_identity: String,
    transaction_identity: String,
    terminal_binding_identity: Option<String>,
    payload_digest: String,
    coordinates: PreparedAppendCoordinatesV1,
    canonical_message: Vec<u8>,
    signing_preimage: Vec<u8>,
    signature_algorithm: String,
    signer_key_generation_identity: String,
    signature: String,
    resulting_frontier_identity: String,
    effect_receipt_identity: String,
    effect_receipt_bytes: Vec<u8>,
}

/// Reverified inert envelope evidence.  It cannot sign, append, select a
/// phase, or construct standing; it exists only long enough to compare the
/// authenticated physical carrier with the disposable Store projection.
pub(in crate::store_generation) struct VerifiedDurableSignerCarrierEnvelopeV1 {
    route: C2StoreSigningRouteV1,
    operation_identity: Sha256Digest,
    append_identity: String,
    message_identity: SignerIdentityV1,
    signer_public_key: [u8; 32],
    signer_key_generation_identity: SignerIdentityV1,
    resulting_frontier_identity: SignerIdentityV1,
    ledger_sequence: u64,
    generation_sequence: u64,
    event_cut: u64,
    canonical_message: Vec<u8>,
    effect_receipt_identity: String,
}

impl VerifiedDurableSignerCarrierEnvelopeV1 {
    pub(in crate::store_generation) const fn route(&self) -> C2StoreSigningRouteV1 {
        self.route
    }

    pub(in crate::store_generation) fn append_identity(&self) -> &str {
        &self.append_identity
    }

    pub(in crate::store_generation) const fn message_identity(&self) -> SignerIdentityV1 {
        self.message_identity
    }

    pub(in crate::store_generation) const fn signer_public_key(&self) -> [u8; 32] {
        self.signer_public_key
    }

    pub(in crate::store_generation) const fn signer_key_generation_identity(
        &self,
    ) -> SignerIdentityV1 {
        self.signer_key_generation_identity
    }

    pub(in crate::store_generation) const fn resulting_frontier_identity(
        &self,
    ) -> SignerIdentityV1 {
        self.resulting_frontier_identity
    }

    pub(in crate::store_generation) const fn ledger_sequence(&self) -> u64 {
        self.ledger_sequence
    }

    pub(in crate::store_generation) const fn generation_sequence(&self) -> u64 {
        self.generation_sequence
    }

    pub(in crate::store_generation) const fn event_cut(&self) -> u64 {
        self.event_cut
    }

    pub(in crate::store_generation) fn canonical_message(&self) -> &[u8] {
        &self.canonical_message
    }

    pub(in crate::store_generation) fn effect_receipt_identity(&self) -> &str {
        &self.effect_receipt_identity
    }
}

/// Fully deterministic physical append value. The actor must authenticate
/// this exact envelope in B/G before inserting or accepting its disposable
/// SQLite projection. It is opaque outside the Store generation module.
pub(crate) struct C2FinalizedSignedAppendV1 {
    frame: C2PreparedSignedAppendV1,
    consumed: ConsumedSignedFrameV1,
    effect_receipt_bytes: Vec<u8>,
    canonical_carrier_bytes: Vec<u8>,
    projection_present: bool,
}

impl C2FinalizedSignedAppendV1 {
    pub(in crate::store_generation) fn operation_identity(
        &self,
    ) -> Result<Sha256Digest, SignerRefusalV2> {
        // Stable replay/collision key. Append identity is content-bound and
        // therefore cannot be the physical occurrence key: changed content
        // under one route/Store occurrence/transaction must collide before
        // any second B/G record is written.
        Sha256Digest::parse(identity_text(digest_fields(
            APPEND_OCCURRENCE_DOMAIN_V1,
            &[
                self.consumed.route.as_str().as_bytes(),
                &self.frame.coordinates.occurrence_identity,
                &self.frame.brand.transaction_identity,
            ],
        )))
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)
    }

    pub(in crate::store_generation) const fn physical_kind(&self) -> C2AppendFrameKindV1 {
        match self.consumed.route {
            C2StoreSigningRouteV1::Msg03PhysicalGenerationBootstrap => {
                C2AppendFrameKindV1::StoreGenerationBootstrap
            }
            C2StoreSigningRouteV1::Msg05ActivePolicyContinuity => {
                C2AppendFrameKindV1::ActiveStorePolicy
            }
            C2StoreSigningRouteV1::Msg08GlobalRefusal => C2AppendFrameKindV1::GlobalRefusal,
            C2StoreSigningRouteV1::Msg09InstallationIntent => {
                C2AppendFrameKindV1::InstallationIntent
            }
            C2StoreSigningRouteV1::Msg10InstallationReceipt => {
                C2AppendFrameKindV1::InstallationReceipt
            }
            C2StoreSigningRouteV1::Msg02InitialPop => C2AppendFrameKindV1::KeyEnrollment,
            C2StoreSigningRouteV1::Msg06NormalRotationContinuity
            | C2StoreSigningRouteV1::Msg07SuccessorPop
            | C2StoreSigningRouteV1::Msg11PolicyTransitionIntent
            | C2StoreSigningRouteV1::Msg12ReceiptCurrent
            | C2StoreSigningRouteV1::Msg12ReceiptPending => C2AppendFrameKindV1::SignerTransition,
        }
    }

    pub(in crate::store_generation) fn canonical_carrier_bytes(&self) -> &[u8] {
        &self.canonical_carrier_bytes
    }

    pub(in crate::store_generation) const fn projection_present(&self) -> bool {
        self.projection_present
    }

    pub(in crate::store_generation) const fn is_installation_intent(&self) -> bool {
        matches!(
            self.consumed.route,
            C2StoreSigningRouteV1::Msg09InstallationIntent
        )
    }

    pub(in crate::store_generation) const fn is_physical_generation_bootstrap(&self) -> bool {
        matches!(
            self.consumed.route,
            C2StoreSigningRouteV1::Msg03PhysicalGenerationBootstrap
        )
    }
}

#[derive(Serialize)]
struct AppendIdentityPreimageV1<'a> {
    schema: &'static str,
    route: &'static str,
    message_identity: String,
    transaction_identity: String,
    frontier_namespace_identity: String,
    predecessor_frontier_identity: String,
    resulting_frontier_identity: String,
    ledger_sequence: u64,
    generation_sequence: u64,
    canonical_message_sha256: &'a str,
    signing_preimage_sha256: &'a str,
    signature: String,
}

#[derive(Serialize)]
struct AppendReceiptV1<'a> {
    schema: &'static str,
    append_identity: &'a str,
    route: &'static str,
    family: &'static str,
    message_identity: String,
    transaction_identity: String,
    ledger_sequence: u64,
    generation_sequence: u64,
    predecessor_frontier_identity: String,
    resulting_frontier_identity: String,
    sole_consumer: &'static str,
}

struct ExistingAppendV1 {
    ledger_sequence: u64,
    generation_sequence: u64,
    append_identity: String,
    message_identity: Vec<u8>,
    canonical_message: Vec<u8>,
    signing_preimage: Vec<u8>,
    signature: Vec<u8>,
    resulting_frontier_identity: Vec<u8>,
    effect_receipt_identity: String,
    physical_carrier_bytes: Option<Vec<u8>>,
}

/// The live coordinator borrows one Store actor, one phase context, and one
/// retained custodian.  It is noncloneable and nonserializable.
pub(crate) struct C2SignerTransitionCoordinator<
    'op,
    'actor_store,
    'context_live,
    'context_store,
    Phase,
> {
    actor: &'op mut StoreC2SnapshotActorV1<'actor_store>,
    context: &'op mut C2LiveSignerContextV1<'context_live, 'context_store, Phase>,
    custodian: &'context_live C2StoreIntegrityCustodian,
}

impl<'op, 'actor_store, 'context_live, 'context_store, Phase>
    C2SignerTransitionCoordinator<'op, 'actor_store, 'context_live, 'context_store, Phase>
{
    pub(crate) fn from_store_actor(
        actor: &'op mut StoreC2SnapshotActorV1<'actor_store>,
        context: &'op mut C2LiveSignerContextV1<'context_live, 'context_store, Phase>,
    ) -> Result<Self, C2SignerAppendRefusalV1> {
        context.verify_live(actor)?;
        let custodian = context.retained_custodian();
        Ok(Self {
            actor,
            context,
            custodian,
        })
    }

    fn sign_and_append<M: SignerMessageV1>(
        &mut self,
        message: M,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        message.verify_closed_route()?;
        let custodian = self.custodian;
        self.actor
            .with_signer_append_effect(self.context, |live_permit, live| {
                let brand = construct_signing_brand(&message)?;
                let signature = custodian.sign(
                    CoordinatorSigningPermitV1::issue(),
                    live_permit,
                    live,
                    &message,
                )?;
                construct_nonescaping_frame(&message, brand, signature)
            })
    }

    fn verified_coordinates(&self) -> Result<StoreVerifiedSigningCoordinatesV1, SignerRefusalV2> {
        StoreVerifiedSigningCoordinatesV1::from_live_store_context(
            self.actor,
            &self.context.signing_view(),
        )
    }
}

/// Sole typed production MSG-02 operation. It consumes one exact actor-bound
/// possession request, signs only with that request's retained proposed-key
/// custodian, and returns the sealed consumed result required by foundational
/// adoption. It deliberately does not require or create B/G/live standing.
pub(crate) fn append_initial_proposal_pop_v1<'request, 'store>(
    actor: &mut StoreC2SnapshotActorV1<'_>,
    request: &'request VerifiedInitialPossessionRequestV1<'request, 'store>,
    custodian: &C2StoreIntegrityCustodian,
) -> Result<ConsumedInitialProposalPoPV1<'request, 'store>, C2SignerAppendRefusalV1> {
    request.verify_for_actor(actor)?;
    let construction = CoordinatorMessageConstructionPermitV1::issue();
    let source = VerifiedInitialPopSourceV1::from_store_verified(
        &construction,
        request.proposal_identity(),
        request.candidate_identity(),
        request.challenge_identity(),
        request.public_key_identity(),
        request.attempt_identity(),
        request.signer_scope_identity(),
    )?;
    let message = InitialProposalPoPFrameV1::from_store_verified(
        &construction,
        StoreVerifiedSigningCoordinatesV1::from_initial_possession(actor, request)?,
        source,
    )?;
    message.verify_closed_route()?;
    actor.with_initial_possession_append_effect(request, |live_permit| {
        let brand = construct_signing_brand(&message)?;
        let signature = custodian.sign_initial_possession(
            CoordinatorSigningPermitV1::issue(),
            live_permit,
            request,
            &message,
        )?;
        construct_nonescaping_frame(&message, brand, signature)
    })
}

impl C2SignerTransitionCoordinator<'_, '_, '_, '_, BootstrapV1> {
    fn sign_and_append_prospective_generation<M: SignerMessageV1>(
        &mut self,
        message: M,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        message.verify_closed_route()?;
        let custodian = self.custodian;
        self.actor
            .with_prospective_generation_append_effect(self.context, |permit, live| {
                prepare_typed_signed_frame(custodian, permit, live, &message)
            })
    }

    /// Closed installation bootstrap batch. MSG-09 is signed first as a
    /// process-local staged semantic intent; its exact message identity is a
    /// typed source coordinate of MSG-03. The actor then owns the only legal
    /// durable ordering: MSG-03 physical B genesis, MSG-09 physical slot 1,
    /// with both SQL projections committed atomically.
    pub(in crate::store_generation) fn append_installation_bootstrap_batch(
        &mut self,
        facts: &StoreVerifiedInstallationBootstrapFactsV1,
    ) -> Result<ConsumedInstallationBootstrapBatchV1, C2SignerAppendRefusalV1> {
        facts.verify_for_actor(self.actor, self.context)?;
        let construction = CoordinatorMessageConstructionPermitV1::issue();
        let intent_source = VerifiedInstallationIntentSourceV1::from_store_verified(
            &construction,
            facts.bootstrap_grant_identity(),
            facts.proposal_identity(),
            facts.attempt_mode_identity(),
            facts.initial_policy_identity(),
            facts.bootstrap_generation_preimage_identity(),
        )?;
        let intent_coordinates = {
            let view = self.context.installation_intent_signing_view();
            StoreVerifiedSigningCoordinatesV1::from_live_store_context(self.actor, &view)?
        };
        let intent = StoreGenerationInstallationIntentFrameV1::from_store_verified(
            &construction,
            intent_coordinates,
            intent_source,
        )?;
        intent.verify_closed_route()?;
        let custodian = self.custodian;
        self.actor.with_installation_bootstrap_batch_effect(
            self.context,
            |intent_permit, intent_live| {
                prepare_typed_signed_frame(custodian, intent_permit, intent_live, &intent)
            },
            |consumed_intent, bootstrap_permit, bootstrap_live| {
                let bootstrap_construction = CoordinatorMessageConstructionPermitV1::issue();
                let bootstrap_source =
                    VerifiedPhysicalGenerationBootstrapSourceV1::from_store_verified(
                        &bootstrap_construction,
                        facts.accepted_enrollment_identity(),
                        facts.frozen_generation_preimage_identity(),
                        facts.bg_layout_profile_manifest_lock_facts_identity(),
                        consumed_intent.message_identity,
                        facts.generation_commitment_identity(),
                    )?;
                let bootstrap = PhysicalGenerationBootstrapFrameV1::from_store_verified(
                    &bootstrap_construction,
                    StoreVerifiedSigningCoordinatesV1::from_store_append_permit(
                        bootstrap_permit,
                        bootstrap_live,
                    )?,
                    bootstrap_source,
                )?;
                bootstrap.verify_closed_route()?;
                prepare_typed_signed_frame(custodian, bootstrap_permit, bootstrap_live, &bootstrap)
            },
        )
    }

    pub(in crate::store_generation) fn append_installation_receipt(
        &mut self,
        facts: &StoreVerifiedInstallationReceiptFactsV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        facts.verify_for_actor(self.actor, self.context)?;
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedInstallationReceiptSourceV1::from_store_verified(
            &permit,
            facts.installation_intent_message_identity(),
            facts.physical_generation_bootstrap_message_identity(),
            facts.generation_commitment_identity(),
            facts.pre_receipt_bg_lock_backend_facts_identity(),
        )?;
        let coordinates = {
            let view = self.context.prospective_generation_signing_view();
            StoreVerifiedSigningCoordinatesV1::from_live_store_context(self.actor, &view)?
        };
        let message = StoreGenerationInstallationReceiptFrameV1::from_store_verified(
            &permit,
            coordinates,
            source,
        )?;
        self.sign_and_append_prospective_generation(message)
    }
}

impl C2SignerTransitionCoordinator<'_, '_, '_, '_, GenerationCurrentV1> {
    fn verified_current_predecessor_coordinates(
        &self,
    ) -> Result<StoreVerifiedSigningCoordinatesV1, SignerRefusalV2> {
        let view = self.context.current_predecessor_signing_view();
        StoreVerifiedSigningCoordinatesV1::from_live_store_context(self.actor, &view)
    }

    fn sign_and_append_current_predecessor<M: SignerMessageV1>(
        &mut self,
        message: M,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        message.verify_closed_route()?;
        let custodian = self.custodian;
        self.actor
            .with_current_predecessor_append_effect(self.context, |permit, live| {
                prepare_typed_signed_frame(custodian, permit, live, &message)
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn append_active_policy_continuity(
        &mut self,
        immutable_signer_policy_identity: SignerIdentityV1,
        old_active_policy_identity: SignerIdentityV1,
        new_active_policy_identity: SignerIdentityV1,
        activation_identity: SignerIdentityV1,
        policy_predecessor_identity: SignerIdentityV1,
        successor_grant_or_unchanged_applicability_identity: SignerIdentityV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedActivePolicyContinuitySourceV1::from_store_verified(
            &permit,
            immutable_signer_policy_identity,
            old_active_policy_identity,
            new_active_policy_identity,
            activation_identity,
            policy_predecessor_identity,
            successor_grant_or_unchanged_applicability_identity,
        )?;
        let message = ActivePolicyContinuityFrameV1::from_store_verified(
            &permit,
            self.verified_current_predecessor_coordinates()?,
            source,
        )?;
        self.sign_and_append_current_predecessor(message)
    }

    #[allow(clippy::too_many_arguments)]
    fn append_normal_rotation_continuity(
        &mut self,
        successor_proposal_identity: SignerIdentityV1,
        successor_pop_identity: SignerIdentityV1,
        prior_enrollment_identity: SignerIdentityV1,
        prior_policy_identity: SignerIdentityV1,
        rotation_predecessor_identity: SignerIdentityV1,
        exact_rotation_cuts_identity: SignerIdentityV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedHealthyRotationContinuitySourceV1::from_store_verified(
            &permit,
            successor_proposal_identity,
            successor_pop_identity,
            prior_enrollment_identity,
            prior_policy_identity,
            rotation_predecessor_identity,
            exact_rotation_cuts_identity,
        )?;
        let message = NormalRotationContinuityFrameV1::from_store_verified(
            &permit,
            self.verified_current_predecessor_coordinates()?,
            source,
        )?;
        self.sign_and_append_current_predecessor(message)
    }

    fn append_global_refusal(
        &mut self,
        refusal_classification_identity: SignerIdentityV1,
        authority_custody_policy_evidence_identity: SignerIdentityV1,
        exact_refusal_frontier_identity: SignerIdentityV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedGlobalRefusalSourceV1::from_store_verified(
            &permit,
            refusal_classification_identity,
            authority_custody_policy_evidence_identity,
            exact_refusal_frontier_identity,
        )?;
        let message = GlobalRefusalFrameV1::from_store_verified(
            &permit,
            self.verified_coordinates()?,
            source,
        )?;
        self.sign_and_append(message)
    }

    fn append_policy_transition_intent(
        &mut self,
        transition_mode_identity: SignerIdentityV1,
        mandatory_rotation_continuity_message_identity: SignerIdentityV1,
        policy_continuity_or_unchanged_proof_identity: SignerIdentityV1,
        predecessor_successor_keys_identity: SignerIdentityV1,
        exact_transition_frontier_and_cuts_identity: SignerIdentityV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedPolicyTransitionIntentSourceV1::from_store_verified(
            &permit,
            transition_mode_identity,
            mandatory_rotation_continuity_message_identity,
            policy_continuity_or_unchanged_proof_identity,
            predecessor_successor_keys_identity,
            exact_transition_frontier_and_cuts_identity,
        )?;
        let message = PolicyTransitionIntentFrameV1::from_store_verified(
            &permit,
            self.verified_current_predecessor_coordinates()?,
            source,
        )?;
        self.sign_and_append_current_predecessor(message)
    }

    fn append_current_policy_transition_receipt(
        &mut self,
        selected_transition_input_identity: SignerIdentityV1,
        completed_append_identity: SignerIdentityV1,
        complete_candidate_set_identity: SignerIdentityV1,
        generation_current_resolution_identity: SignerIdentityV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedCurrentTransitionReceiptSourceV1::from_store_verified(
            &permit,
            selected_transition_input_identity,
            completed_append_identity,
            complete_candidate_set_identity,
            generation_current_resolution_identity,
        )?;
        let message = CurrentPolicyTransitionReceiptFrameV1::from_store_verified(
            &permit,
            self.verified_coordinates()?,
            source,
        )?;
        self.sign_and_append(message)
    }

    /// Closed current-predecessor healthy-rotation sequence.
    ///
    /// MSG-06 is appended unconditionally and its *consumed* message identity
    /// is inserted into MSG-11. MSG-05 is appended exactly when the Store-
    /// resolved target differs in policy, activation, or applicability; the
    /// unchanged branch inserts the mechanically derived proof instead.
    pub(in crate::store_generation) fn append_healthy_rotation_intent(
        &mut self,
        facts: StoreVerifiedHealthyRotationIntentFactsV1,
    ) -> Result<ConsumedHealthyRotationIntentV1, C2SignerAppendRefusalV1> {
        facts.verify_for_actor(self.actor, self.context)?;
        debug_assert_eq!(
            facts.policy.append_plan().first(),
            Some(&HealthyRotationAppendStepV1::MandatoryMsg06),
        );
        let mandatory_msg06 = self.append_normal_rotation_continuity(
            facts.successor_proposal_identity,
            facts.successor_pop_identity,
            facts.prior_enrollment_identity,
            facts.prior_policy_identity,
            facts.rotation_predecessor_identity,
            facts.exact_rotation_cuts_identity,
        )?;
        let (conditional_msg05, policy_continuity_or_unchanged_proof_identity) = match facts.policy
        {
            HealthyRotationPolicyOutcomeV1::Changed {
                immutable_signer_policy_identity,
                old_active_policy_identity,
                new_active_policy_identity,
                activation_identity,
                policy_predecessor_identity,
                successor_grant_or_unchanged_applicability_identity,
            } => {
                let consumed = self.append_active_policy_continuity(
                    immutable_signer_policy_identity,
                    old_active_policy_identity,
                    new_active_policy_identity,
                    activation_identity,
                    policy_predecessor_identity,
                    successor_grant_or_unchanged_applicability_identity,
                )?;
                let identity = consumed.message_identity;
                (Some(consumed), identity)
            }
            HealthyRotationPolicyOutcomeV1::Unchanged {
                exact_policy_activation_applicability_proof_identity,
            } => (None, exact_policy_activation_applicability_proof_identity),
        };
        let live = self.context.signing_view();
        let post_continuity_cut = live.event_cut().to_be_bytes();
        let transition_cut = facts.transition_cut.to_be_bytes();
        let exact_transition_frontier_and_cuts_identity = rotation_identity(
            b"nq.c2.healthy_rotation.transition_frontier_and_cuts.identity.v1\0",
            &[
                &live.predecessor_frontier_identity(),
                &post_continuity_cut,
                &transition_cut,
                &mandatory_msg06.message_identity,
                &policy_continuity_or_unchanged_proof_identity,
                &facts.transition_identity,
            ],
        );
        let msg11 = self.append_policy_transition_intent(
            facts.transition_mode_identity,
            mandatory_msg06.message_identity,
            policy_continuity_or_unchanged_proof_identity,
            facts.predecessor_successor_keys_identity,
            exact_transition_frontier_and_cuts_identity,
        )?;
        Ok(ConsumedHealthyRotationIntentV1 {
            actor_instance_identity: self.actor.actor_instance_identity().clone(),
            post_append_snapshot_identity: self.actor.current_snapshot_identity().clone(),
            post_append_effect_epoch: self.actor.effect_epoch(),
            successor_proposal_identity: facts.successor_proposal_identity,
            successor_pop_identity: facts.successor_pop_identity,
            transition_identity: facts.transition_identity,
            mandatory_msg06,
            conditional_msg05,
            msg11,
        })
    }
}

impl C2SignerTransitionCoordinator<'_, '_, '_, '_, PendingPossessionV1> {
    pub(in crate::store_generation) fn append_successor_possession(
        &mut self,
        facts: StoreVerifiedSuccessorPossessionFactsV1,
    ) -> Result<ConsumedSuccessorPossessionV1, C2SignerAppendRefusalV1> {
        facts.verify_for_actor(self.actor, self.context)?;
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedSuccessorPopSourceV1::from_store_verified(
            &permit,
            facts.successor_proposal_identity,
            facts.successor_challenge_identity,
            facts.successor_key_identity,
            facts.predecessor_binding_identity,
            facts.transition_identity,
        )?;
        let message = SuccessorPoPFrameV1::from_store_verified(
            &permit,
            self.verified_coordinates()?,
            source,
        )?;
        let consumed = self.sign_and_append(message)?;
        Ok(ConsumedSuccessorPossessionV1 {
            actor_instance_identity: self.actor.actor_instance_identity().clone(),
            post_append_snapshot_identity: self.actor.current_snapshot_identity().clone(),
            post_append_effect_epoch: self.actor.effect_epoch(),
            successor_proposal_identity: facts.successor_proposal_identity,
            successor_key_identity: facts.successor_key_identity,
            transition_identity: facts.transition_identity,
            consumed,
        })
    }
}

impl C2SignerTransitionCoordinator<'_, '_, '_, '_, PendingSelectedV1> {
    pub(in crate::store_generation) fn append_pending_healthy_rotation_receipt(
        &mut self,
        facts: StoreVerifiedPendingRotationReceiptFactsV1,
    ) -> Result<ConsumedSignedFrameV1, C2SignerAppendRefusalV1> {
        facts.verify_for_actor(self.actor, self.context)?;
        let permit = CoordinatorMessageConstructionPermitV1::issue();
        let source = VerifiedPendingTransitionReceiptSourceV1::from_store_verified(
            &permit,
            facts.selected_transition_input_identity,
            facts.completed_append_identity,
            facts.complete_candidate_set_identity,
            facts.pending_successor_resolution_identity,
        )?;
        let message = PendingPolicyTransitionReceiptFrameV1::from_store_verified(
            &permit,
            self.verified_coordinates()?,
            source,
        )?;
        self.sign_and_append(message)
    }
}

fn prepare_typed_signed_frame<M: SignerMessageV1, Phase>(
    custodian: &C2StoreIntegrityCustodian,
    live_permit: &crate::store_generation::live_c2::StoreC2SignerAppendPermitV1<'_, '_, '_, Phase>,
    live: &crate::store_generation::live_c2::C2LiveSigningViewV1<'_, '_, '_, Phase>,
    message: &M,
) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2> {
    let brand = construct_signing_brand(message)?;
    let signature = custodian.sign(
        CoordinatorSigningPermitV1::issue(),
        live_permit,
        live,
        message,
    )?;
    construct_nonescaping_frame(message, brand, signature)
}

fn construct_signing_brand<M: SignerMessageV1 + ?Sized>(
    message: &M,
) -> Result<SignerMessageBrandV1, SignerRefusalV2> {
    let route = message.route();
    if !message.family().is_store_signable() {
        return Err(SignerRefusalV2::MessageFamilyNotSignable);
    }
    let terminal_binding = match message.verified_coordinates().exact_authority() {
        C2ExactSigningAuthorityV1::ProposedKey { .. }
        | C2ExactSigningAuthorityV1::Bootstrap { .. } => None,
        C2ExactSigningAuthorityV1::CurrentPredecessor { standing_identity }
        | C2ExactSigningAuthorityV1::GenerationCurrent { standing_identity }
        | C2ExactSigningAuthorityV1::PendingSuccessor { standing_identity } => {
            Some(standing_identity)
        }
    };
    Ok(SignerMessageBrandV1 {
        family: route.family(),
        route,
        message_identity: message.message_identity(),
        transaction_identity: message.transaction_identity(),
        terminal_binding,
        payload_digest: Sha256::digest(message.canonical_preimage()).into(),
    })
}

fn construct_nonescaping_frame<M: SignerMessageV1 + ?Sized>(
    message: &M,
    brand: SignerMessageBrandV1,
    signature: CustodySignatureV1,
) -> Result<C2PreparedSignedAppendV1, SignerRefusalV2> {
    let signing_preimage = message.canonical_preimage();
    let canonical_message = message.canonical_message().to_vec();
    let digest: SignerIdentityV1 = Sha256::digest(&signing_preimage).into();
    if canonical_message.is_empty()
        || signing_preimage.is_empty()
        || brand.family != signature.family
        || brand.payload_digest != signature.payload_digest
        || brand.payload_digest != digest
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    let verified = message.verified_coordinates();
    let scope = verified.exact_scope();
    Ok(C2PreparedSignedAppendV1 {
        brand,
        coordinates: PreparedAppendCoordinatesV1 {
            occurrence_id: verified.occurrence_id().to_owned(),
            occurrence_identity: verified.custody().occurrence,
            physical_generation_identity: scope.physical_generation(),
            lifecycle_root_identity: scope.lifecycle_root(),
            prospective_generation_preimage: scope.prospective_generation_preimage(),
            scope_identity: verified.custody().scope,
            resident_identity: verified.resident_identity().to_owned(),
            resident_generation: verified.resident_generation(),
            host_role: verified.host_role().to_owned(),
            role_manifest_identity: verified.role_manifest_identity(),
            role_manifest_generation: verified.role_manifest_generation(),
            authority_domain: verified.authority_domain().to_owned(),
            terminal_a1_identity: verified.terminal_a1_identity(),
            current_a2_snapshot_identity: verified.current_a2_snapshot_identity(),
            grant_or_predecessor_standing_identity: verified
                .grant_or_predecessor_standing_identity(),
            signer_public_key: verified.signer_public_key(),
            signer_scope_policy_identity: verified.custody().policy,
            signer_scope_policy_version: verified.signer_scope_policy_version(),
            active_store_policy_identity: verified.active_store_policy_identity(),
            active_store_policy_generation: verified.active_store_policy_generation(),
            active_store_policy_digest: verified.active_store_policy_digest(),
            implementation_manifest_identity: verified.implementation_manifest_identity(),
            manifest_admission_correspondence_identity: verified
                .manifest_admission_correspondence_identity(),
            qualified_candidate_identity: verified.qualified_candidate_identity(),
            source_tree_identity: verified.source_tree_identity(),
            runtime_artifact_identity: verified.runtime_artifact_identity(),
            signer_key_generation: verified.signer_key_generation(),
            signer_key_generation_identity: verified.custody().signer_key_generation,
            event_predecessor_identity: verified.event_predecessor_identity(),
            transaction_intent_identity: verified.transaction_intent_identity(),
            frontier_namespace_identity: verified.frontier_namespace_identity(),
            predecessor_frontier_identity: verified.predecessor_frontier_identity(),
            exact_content_identity: verified.exact_content_identity(),
            event_cut: verified.custody().cut,
        },
        canonical_message,
        signing_preimage,
        signature,
    })
}

fn finalize_carrier_envelope(
    frame: C2PreparedSignedAppendV1,
    consumed: ConsumedSignedFrameV1,
    effect_receipt_bytes: Vec<u8>,
    projection_present: bool,
) -> Result<C2FinalizedSignedAppendV1, SignerRefusalV2> {
    let route = consumed.route;
    let canonical_carrier_bytes = canonical_json_bytes(&DurableSignerCarrierEnvelopeV1 {
        schema: "nq.c2_durable_signer_carrier_envelope.v1",
        append_identity: &consumed.append_identity,
        family: consumed.family.as_str(),
        route: route.as_str(),
        identity_domain: route.identity_domain(),
        signature_domain: route.signature_domain(),
        signer_phase: route.phase().as_str(),
        scope_class: route.scope_class().as_str(),
        authority_class: route.authority_class().as_str(),
        input_kind: route.input_kind().as_str(),
        sole_consumer: route.sole_consumer().as_str(),
        ledger_sequence: consumed.ledger_sequence,
        generation_sequence: consumed.generation_sequence,
        message_identity: identity_text(frame.brand.message_identity),
        transaction_identity: identity_text(frame.brand.transaction_identity),
        terminal_binding_identity: frame.brand.terminal_binding.map(identity_text),
        payload_digest: identity_text(frame.brand.payload_digest),
        coordinates: &frame.coordinates,
        canonical_message: &frame.canonical_message,
        signing_preimage: &frame.signing_preimage,
        signature_algorithm: "ed25519",
        signer_key_generation_identity: identity_text(frame.signature.signer_key_generation),
        signature: hex::encode(frame.signature.signature),
        resulting_frontier_identity: identity_text(consumed.resulting_frontier_identity),
        effect_receipt_identity: &consumed.effect_receipt_identity,
        effect_receipt_bytes: &effect_receipt_bytes,
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    Ok(C2FinalizedSignedAppendV1 {
        frame,
        consumed,
        effect_receipt_bytes,
        canonical_carrier_bytes,
        projection_present,
    })
}

fn physical_kind_for_route(
    route: C2StoreSigningRouteV1,
) -> Result<C2AppendFrameKindV1, SignerRefusalV2> {
    match route {
        C2StoreSigningRouteV1::Msg03PhysicalGenerationBootstrap => {
            Ok(C2AppendFrameKindV1::StoreGenerationBootstrap)
        }
        C2StoreSigningRouteV1::Msg05ActivePolicyContinuity => {
            Ok(C2AppendFrameKindV1::ActiveStorePolicy)
        }
        C2StoreSigningRouteV1::Msg08GlobalRefusal => Ok(C2AppendFrameKindV1::GlobalRefusal),
        C2StoreSigningRouteV1::Msg09InstallationIntent => {
            Ok(C2AppendFrameKindV1::InstallationIntent)
        }
        C2StoreSigningRouteV1::Msg10InstallationReceipt => {
            Ok(C2AppendFrameKindV1::InstallationReceipt)
        }
        C2StoreSigningRouteV1::Msg06NormalRotationContinuity
        | C2StoreSigningRouteV1::Msg07SuccessorPop
        | C2StoreSigningRouteV1::Msg11PolicyTransitionIntent
        | C2StoreSigningRouteV1::Msg12ReceiptCurrent
        | C2StoreSigningRouteV1::Msg12ReceiptPending => Ok(C2AppendFrameKindV1::SignerTransition),
        // MSG-02 is deliberately SQL-only before B/G exists.  Its appearance
        // in either physical carrier is a vocabulary violation.
        C2StoreSigningRouteV1::Msg02InitialPop => Err(SignerRefusalV2::MessageFamilyNotSignable),
    }
}

fn parse_identity_text_exact(value: &str) -> Result<SignerIdentityV1, SignerRefusalV2> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(SignerRefusalV2::MessagePayloadSubstitution)?;
    hex::decode(hex)
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
        .try_into()
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)
}

fn json_text<'value>(value: &'value Value, field: &str) -> Result<&'value str, SignerRefusalV2> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(SignerRefusalV2::MessagePayloadSubstitution)
}

fn json_u64(value: &Value, field: &str) -> Result<u64, SignerRefusalV2> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(SignerRefusalV2::MessagePayloadSubstitution)
}

fn exact_optional_identity_field(
    coordinates: &Value,
    field: &str,
    expected: Option<SignerIdentityV1>,
) -> Result<(), SignerRefusalV2> {
    match (coordinates.get(field), expected) {
        (None, None) => Ok(()),
        (Some(Value::String(observed)), Some(expected)) if observed == &identity_text(expected) => {
            Ok(())
        }
        _ => Err(SignerRefusalV2::MessagePayloadSubstitution),
    }
}

/// Recompute and authenticate one physical signer envelope from exact bytes.
///
/// This verifier intentionally does not trust duplicated envelope metadata.
/// It reselects the route from the closed registry, checks the complete
/// registry projection, recomputes the canonical message identity and signing
/// preimage, verifies Ed25519 with the signed coordinate key, and reconstructs
/// frontier, append, operation, and effect-receipt identities.
pub(in crate::store_generation) fn verify_durable_signer_carrier_envelope_v1(
    canonical_carrier: &[u8],
) -> Result<VerifiedDurableSignerCarrierEnvelopeV1, SignerRefusalV2> {
    let envelope: DurableSignerCarrierEnvelopeOwnedV1 =
        serde_json::from_slice(canonical_carrier)
            .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    if canonical_json_bytes(&envelope).map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
        != canonical_carrier
        || envelope.schema != "nq.c2_durable_signer_carrier_envelope.v1"
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    let route = C2StoreSigningRouteV1::ALL
        .into_iter()
        .find(|candidate| candidate.as_str() == envelope.route)
        .ok_or(SignerRefusalV2::MessageFamilyNotSignable)?;
    physical_kind_for_route(route)?;
    if envelope.family != route.family().as_str()
        || envelope.identity_domain != route.identity_domain()
        || envelope.signature_domain != route.signature_domain()
        || envelope.signer_phase != route.phase().as_str()
        || envelope.scope_class != route.scope_class().as_str()
        || envelope.authority_class != route.authority_class().as_str()
        || envelope.input_kind != route.input_kind().as_str()
        || envelope.sole_consumer != route.sole_consumer().as_str()
        || envelope.signature_algorithm != "ed25519"
        || envelope.ledger_sequence == 0
        || envelope.generation_sequence == 0
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }

    let message: Value = serde_json::from_slice(&envelope.canonical_message)
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    if canonical_json_bytes(&message).map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
        != envelope.canonical_message
        || json_text(&message, "schema")? != "nq.c2_store_integrity_signing_message.v1"
        || json_text(&message, "family")? != route.family().as_str()
        || json_text(&message, "route")? != route.as_str()
        || json_text(&message, "identity_domain")? != route.identity_domain()
        || json_text(&message, "signature_domain")? != route.signature_domain()
        || json_text(&message, "signer_phase")? != route.phase().as_str()
        || json_text(&message, "algorithm")? != "ed25519"
        || json_text(&message, "scope_class")? != route.scope_class().as_str()
        || json_text(&message, "authority_class")? != route.authority_class().as_str()
        || json_text(&message, "sole_consumer")? != route.sole_consumer().as_str()
        || json_text(
            message
                .get("verified_input")
                .ok_or(SignerRefusalV2::MessagePayloadSubstitution)?,
            "input_kind",
        )? != route.input_kind().as_str()
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }

    let mut body = message.clone();
    body.as_object_mut()
        .ok_or(SignerRefusalV2::MessagePayloadSubstitution)?
        .remove("message_identity")
        .ok_or(SignerRefusalV2::MessagePayloadSubstitution)?;
    let canonical_body =
        canonical_json_bytes(&body).map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let mut message_identity_preimage = route.identity_domain().as_bytes().to_vec();
    message_identity_preimage.push(0);
    message_identity_preimage.extend_from_slice(&canonical_body);
    let message_identity_text = sha256_bytes(&message_identity_preimage).into_string();
    if json_text(&message, "message_identity")? != message_identity_text
        || envelope.message_identity != message_identity_text
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    let message_identity = parse_identity_text_exact(&message_identity_text)?;

    let message_coordinates = message
        .get("coordinates")
        .ok_or(SignerRefusalV2::MessagePayloadSubstitution)?;
    let coordinates = &envelope.coordinates;
    let exact_text = |field: &str, expected: String| -> Result<(), SignerRefusalV2> {
        if json_text(message_coordinates, field)? == expected {
            Ok(())
        } else {
            Err(SignerRefusalV2::MessagePayloadSubstitution)
        }
    };
    if json_text(message_coordinates, "occurrence_id")? != coordinates.occurrence_id
        || json_u64(message_coordinates, "resident_generation")? != coordinates.resident_generation
        || json_text(message_coordinates, "resident_identity")? != coordinates.resident_identity
        || json_text(message_coordinates, "host_role")? != coordinates.host_role
        || json_u64(message_coordinates, "role_manifest_generation")?
            != coordinates.role_manifest_generation
        || json_text(message_coordinates, "authority_domain")? != coordinates.authority_domain
        || json_u64(message_coordinates, "signer_key_generation")?
            != coordinates.signer_key_generation
        || json_u64(message_coordinates, "signer_scope_policy_version")?
            != coordinates.signer_scope_policy_version
        || json_u64(message_coordinates, "active_store_policy_generation")?
            != coordinates.active_store_policy_generation
        || json_u64(message_coordinates, "cut")? != coordinates.event_cut
        || json_text(message_coordinates, "scope_class")? != route.scope_class().as_str()
        || json_text(message_coordinates, "authority_class")? != route.authority_class().as_str()
        || json_text(message_coordinates, "signer_public_key")?
            != hex::encode(coordinates.signer_public_key)
        || json_text(message_coordinates, "transaction_intent_identity")?
            != envelope.transaction_identity
        || identity_text(coordinates.transaction_intent_identity) != envelope.transaction_identity
        || envelope.signer_key_generation_identity
            != identity_text(coordinates.signer_key_generation_identity)
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    exact_text("occurrence", identity_text(coordinates.occurrence_identity))?;
    exact_text(
        "role_manifest_identity",
        identity_text(coordinates.role_manifest_identity),
    )?;
    exact_text(
        "terminal_a1_identity",
        identity_text(coordinates.terminal_a1_identity),
    )?;
    exact_text(
        "current_a2_snapshot_identity",
        identity_text(coordinates.current_a2_snapshot_identity),
    )?;
    exact_text(
        "grant_or_predecessor_standing_identity",
        identity_text(coordinates.grant_or_predecessor_standing_identity),
    )?;
    exact_text(
        "signer_key_generation_identity",
        identity_text(coordinates.signer_key_generation_identity),
    )?;
    exact_text("scope_identity", identity_text(coordinates.scope_identity))?;
    // `authority_premise_identity` is the exact tagged live authority used
    // by the signing route.  It is independently signed in the canonical
    // message and checked against the envelope terminal brand below; it is
    // not interchangeable with the separately signed grant/predecessor
    // coordinate.
    parse_identity_text_exact(json_text(
        message_coordinates,
        "authority_premise_identity",
    )?)?;
    if message_coordinates
        .get("proposed_candidate_identity")
        .is_some()
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    exact_text(
        "signer_scope_policy_identity",
        identity_text(coordinates.signer_scope_policy_identity),
    )?;
    exact_text(
        "active_store_policy_identity",
        identity_text(coordinates.active_store_policy_identity),
    )?;
    exact_text(
        "active_store_policy_digest",
        identity_text(coordinates.active_store_policy_digest),
    )?;
    exact_text(
        "event_predecessor_identity",
        identity_text(coordinates.event_predecessor_identity),
    )?;
    exact_text(
        "implementation_manifest_identity",
        identity_text(coordinates.implementation_manifest_identity),
    )?;
    exact_text(
        "manifest_admission_correspondence_identity",
        identity_text(coordinates.manifest_admission_correspondence_identity),
    )?;
    exact_text(
        "qualified_candidate_identity",
        identity_text(coordinates.qualified_candidate_identity),
    )?;
    exact_text(
        "source_tree_identity",
        identity_text(coordinates.source_tree_identity),
    )?;
    exact_text(
        "runtime_artifact_identity",
        identity_text(coordinates.runtime_artifact_identity),
    )?;
    exact_text(
        "frontier_namespace_identity",
        identity_text(coordinates.frontier_namespace_identity),
    )?;
    exact_text(
        "predecessor_frontier_identity",
        identity_text(coordinates.predecessor_frontier_identity),
    )?;
    exact_text(
        "exact_content_identity",
        identity_text(coordinates.exact_content_identity),
    )?;
    exact_optional_identity_field(
        message_coordinates,
        "prospective_generation_preimage",
        coordinates.prospective_generation_preimage,
    )?;
    exact_optional_identity_field(
        message_coordinates,
        "physical_generation",
        coordinates.physical_generation_identity,
    )?;
    exact_optional_identity_field(
        message_coordinates,
        "lifecycle_root",
        coordinates.lifecycle_root_identity,
    )?;

    let expected_terminal_binding = if route.authority_class().as_str() == "bootstrap" {
        None
    } else {
        // The terminal signing brand binds the exact tagged live authority
        // premise selected for this route.  That may deliberately differ
        // from the separately signed grant/predecessor-standing coordinate
        // (for example a successor or current-standing transition).
        Some(json_text(message_coordinates, "authority_premise_identity")?.to_owned())
    };
    if envelope.terminal_binding_identity != expected_terminal_binding {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }

    let mut signing_preimage = route.signature_domain().as_bytes().to_vec();
    signing_preimage.push(0);
    signing_preimage.extend_from_slice(&envelope.canonical_message);
    let signature_bytes: [u8; 64] = hex::decode(&envelope.signature)
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
        .try_into()
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    if signing_preimage != envelope.signing_preimage
        || envelope.payload_digest != sha256_bytes(&signing_preimage).as_str()
        || VerifyingKey::from_bytes(&coordinates.signer_public_key)
            .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
            .verify_strict(&signing_preimage, &Signature::from_bytes(&signature_bytes))
            .is_err()
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }

    let resulting_frontier_identity = digest_fields(
        FRONTIER_IDENTITY_DOMAIN_V1,
        &[
            &coordinates.frontier_namespace_identity,
            &coordinates.predecessor_frontier_identity,
            &envelope.generation_sequence.to_be_bytes(),
            &message_identity,
            &parse_identity_text_exact(&envelope.payload_digest)?,
            &signature_bytes,
        ],
    );
    if envelope.resulting_frontier_identity != identity_text(resulting_frontier_identity) {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    let canonical_message_sha256 = sha256_bytes(&envelope.canonical_message).into_string();
    let signing_preimage_sha256 = sha256_bytes(&envelope.signing_preimage).into_string();
    let append_preimage = canonical_json_bytes(&AppendIdentityPreimageV1 {
        schema: "nq.c2_signer_message_append_identity_preimage.v1",
        route: route.as_str(),
        message_identity: message_identity_text.clone(),
        transaction_identity: envelope.transaction_identity.clone(),
        frontier_namespace_identity: identity_text(coordinates.frontier_namespace_identity),
        predecessor_frontier_identity: identity_text(coordinates.predecessor_frontier_identity),
        resulting_frontier_identity: identity_text(resulting_frontier_identity),
        ledger_sequence: envelope.ledger_sequence,
        generation_sequence: envelope.generation_sequence,
        canonical_message_sha256: &canonical_message_sha256,
        signing_preimage_sha256: &signing_preimage_sha256,
        signature: envelope.signature.clone(),
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let append_identity = domain_digest_text(APPEND_IDENTITY_DOMAIN_V1, &append_preimage);
    let receipt_bytes = canonical_json_bytes(&AppendReceiptV1 {
        schema: "nq.c2_signer_message_append_receipt.v1",
        append_identity: &append_identity,
        route: route.as_str(),
        family: route.family().as_str(),
        message_identity: message_identity_text,
        transaction_identity: envelope.transaction_identity.clone(),
        ledger_sequence: envelope.ledger_sequence,
        generation_sequence: envelope.generation_sequence,
        predecessor_frontier_identity: identity_text(coordinates.predecessor_frontier_identity),
        resulting_frontier_identity: identity_text(resulting_frontier_identity),
        sole_consumer: route.sole_consumer().as_str(),
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    if envelope.append_identity != append_identity
        || envelope.effect_receipt_bytes != receipt_bytes
        || envelope.effect_receipt_identity != sha256_bytes(&receipt_bytes).as_str()
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    let operation_identity = Sha256Digest::parse(identity_text(digest_fields(
        APPEND_OCCURRENCE_DOMAIN_V1,
        &[
            route.as_str().as_bytes(),
            &coordinates.occurrence_identity,
            &coordinates.transaction_intent_identity,
        ],
    )))
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    Ok(VerifiedDurableSignerCarrierEnvelopeV1 {
        route,
        operation_identity,
        append_identity,
        message_identity,
        signer_public_key: coordinates.signer_public_key,
        signer_key_generation_identity: coordinates.signer_key_generation_identity,
        resulting_frontier_identity,
        ledger_sequence: envelope.ledger_sequence,
        generation_sequence: envelope.generation_sequence,
        event_cut: coordinates.event_cut,
        canonical_message: envelope.canonical_message,
        effect_receipt_identity: envelope.effect_receipt_identity,
    })
}

/// Authenticate every physical B/G signer envelope and require its exact
/// disposable SQL projection.  An empty newly initialized pair is valid;
/// any reopened carrier record without its complete projection is a detected
/// carrier-first partial state, never silently admitted as current.
pub(in crate::store_generation) fn verify_durable_signer_carrier_pair_v1(
    transaction: &Transaction<'_>,
    pair: &C2DurableAppendPairV1,
) -> Result<(), SignerRefusalV2> {
    let mut physical_append_identities = BTreeSet::new();
    for physical in pair.authenticated_records() {
        let verified = verify_durable_signer_carrier_envelope_v1(physical.canonical_payload)?;
        if &verified.operation_identity != physical.operation_identity
            || physical.kind != physical_kind_for_route(verified.route)?
            || physical.role != physical.kind.role()
        {
            return Err(SignerRefusalV2::MessagePayloadSubstitution);
        }
        let slot_is_legal = match verified.route {
            C2StoreSigningRouteV1::Msg03PhysicalGenerationBootstrap => physical.slot == 0,
            C2StoreSigningRouteV1::Msg09InstallationIntent => physical.slot == 1,
            C2StoreSigningRouteV1::Msg10InstallationReceipt => physical.slot == 2,
            _ => true,
        };
        if !slot_is_legal || !physical_append_identities.insert(verified.append_identity.clone()) {
            return Err(SignerRefusalV2::MessagePayloadSubstitution);
        }
        let projection = transaction
            .query_row(
                "SELECT family, route, identity_domain, signature_domain,
                        signer_public_key, canonical_message, signing_preimage,
                        signature, resulting_frontier_identity,
                        effect_receipt_identity, effect_receipt_bytes,
                        physical_carrier_bytes, physical_carrier_sha256,
                        physical_carrier_length
                 FROM c2_signer_message_appends
                 WHERE append_identity = ?1",
                [&verified.append_identity],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, Vec<u8>>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, u64>(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| SignerRefusalV2::SignerStateIo)?
            .ok_or(SignerRefusalV2::SignerStateIo)?;
        let envelope: DurableSignerCarrierEnvelopeOwnedV1 =
            serde_json::from_slice(physical.canonical_payload)
                .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
        if envelope.coordinates.occurrence_id != pair.occurrence_id()
            || envelope
                .coordinates
                .physical_generation_identity
                .is_some_and(|identity| {
                    identity_text(identity) != pair.physical_store_generation_identity().as_str()
                })
            || projection.0 != verified.route.family().as_str()
            || projection.1 != verified.route.as_str()
            || projection.2 != verified.route.identity_domain()
            || projection.3 != verified.route.signature_domain()
            || projection.4 != verified.signer_public_key
            || projection.5 != envelope.canonical_message
            || projection.6 != envelope.signing_preimage
            || projection.7
                != hex::decode(&envelope.signature)
                    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
            || projection.8 != verified.resulting_frontier_identity
            || projection.9 != envelope.effect_receipt_identity
            || projection.10 != envelope.effect_receipt_bytes
            || projection.11 != physical.canonical_payload
            || projection.12 != sha256_bytes(physical.canonical_payload).as_str()
            || projection.13
                != u64::try_from(physical.canonical_payload.len())
                    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
            || envelope.message_identity != identity_text(verified.message_identity)
        {
            return Err(SignerRefusalV2::MessagePayloadSubstitution);
        }
    }

    // The correspondence is bidirectional.  Physical->SQL alone would let a
    // SQL-only append influence resolver/frontier state after restart.  MSG-02
    // is the single deliberate pre-B/G exception; every other signed append
    // must have exactly one authenticated physical carrier envelope.
    let mut statement = transaction
        .prepare(
            "SELECT append_identity
             FROM c2_signer_message_appends
             WHERE route <> 'msg02_initial_pop'
             ORDER BY append_identity",
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    let sql_append_identities = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| SignerRefusalV2::SignerStateIo)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    if sql_append_identities != physical_append_identities {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    Ok(())
}

/// Reproject one exact authenticated carrier-first suffix into the disposable
/// SQLite signer-append ledger.
///
/// B/G is canonical.  A process may therefore die after a durable carrier
/// append but before the outer SQLite transaction commits.  Recovery is
/// intentionally narrower than a generic importer: every physical envelope
/// is first reauthenticated (closed family/route/domain census, canonical
/// message and preimage, Ed25519 signature, operation identity and frontier),
/// all existing SQL rows must form an exact prefix of the physical sequence,
/// and each missing row must be the deterministic next SQL append.  Holes,
/// SQL-only rows, changed content, or a non-successor sequence roll the whole
/// savepoint back.
///
/// The returned report is inert bookkeeping plus a closed lifecycle-family
/// classification.  The Store actor must refuse or run family-specific
/// lifecycle reconciliation whenever the report requires it, then run the
/// strict bidirectional verifier before resealing any live context.
/// Opaque semantic classification of an exact carrier-first suffix.
///
/// Reconstructing the disposable append rows is not, by itself, permission
/// to reconstruct a lifecycle effect.  In particular, a physical MSG-12
/// proves a consumed transition receipt; if its atomic lineage/current
/// projection did not commit, reopen must refuse/quarantine or run the exact
/// family-specific recovery procedure.  It must never mint the old current
/// signer as though MSG-12 were merely an unfinished proposal.
pub(in crate::store_generation) struct C2CarrierReprojectionReportV1 {
    reprojected_count: usize,
    saw_installation_lifecycle: bool,
    saw_pending_transition_prefix: bool,
    saw_completed_transition_receipt: bool,
}

impl C2CarrierReprojectionReportV1 {
    #[must_use]
    pub(in crate::store_generation) const fn reprojected_count(&self) -> usize {
        self.reprojected_count
    }

    #[must_use]
    pub(in crate::store_generation) const fn saw_installation_lifecycle(&self) -> bool {
        self.saw_installation_lifecycle
    }

    #[must_use]
    pub(in crate::store_generation) const fn saw_pending_transition_prefix(&self) -> bool {
        self.saw_pending_transition_prefix
    }

    #[must_use]
    pub(in crate::store_generation) const fn saw_completed_transition_receipt(&self) -> bool {
        self.saw_completed_transition_receipt
    }

    /// A true result requires more than append reprojection before any live
    /// phase can be minted.
    #[must_use]
    pub(in crate::store_generation) const fn requires_lifecycle_reconciliation(&self) -> bool {
        self.saw_installation_lifecycle
            || self.saw_pending_transition_prefix
            || self.saw_completed_transition_receipt
    }
}

pub(in crate::store_generation) fn reproject_exact_durable_signer_carrier_suffix_v1(
    transaction: &Transaction<'_>,
    pair: &C2DurableAppendPairV1,
) -> Result<C2CarrierReprojectionReportV1, SignerRefusalV2> {
    struct Candidate {
        canonical_carrier: Vec<u8>,
        operation_identity: Sha256Digest,
        kind: C2AppendFrameKindV1,
        role: crate::append_extent::C2AppendExtentRoleV1,
        envelope: DurableSignerCarrierEnvelopeOwnedV1,
        verified: VerifiedDurableSignerCarrierEnvelopeV1,
        projected: bool,
    }

    let mut candidates = Vec::new();
    let mut physical_append_identities = BTreeSet::new();
    for physical in pair.authenticated_records() {
        let verified = verify_durable_signer_carrier_envelope_v1(physical.canonical_payload)?;
        if &verified.operation_identity != physical.operation_identity
            || physical.kind != physical_kind_for_route(verified.route)?
            || physical.role != physical.kind.role()
        {
            return Err(SignerRefusalV2::MessagePayloadSubstitution);
        }
        let slot_is_legal = match verified.route {
            C2StoreSigningRouteV1::Msg03PhysicalGenerationBootstrap => physical.slot == 0,
            C2StoreSigningRouteV1::Msg09InstallationIntent => physical.slot == 1,
            C2StoreSigningRouteV1::Msg10InstallationReceipt => physical.slot == 2,
            _ => true,
        };
        if !slot_is_legal || !physical_append_identities.insert(verified.append_identity.clone()) {
            return Err(SignerRefusalV2::MessagePayloadSubstitution);
        }
        let envelope: DurableSignerCarrierEnvelopeOwnedV1 =
            serde_json::from_slice(physical.canonical_payload)
                .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
        if envelope.coordinates.occurrence_id != pair.occurrence_id()
            || envelope
                .coordinates
                .physical_generation_identity
                .is_some_and(|identity| {
                    identity_text(identity) != pair.physical_store_generation_identity().as_str()
                })
        {
            return Err(SignerRefusalV2::MessagePayloadSubstitution);
        }
        let projected_carrier = transaction
            .query_row(
                "SELECT physical_carrier_bytes
                 FROM c2_signer_message_appends
                 WHERE append_identity = ?1",
                [&verified.append_identity],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(|_| SignerRefusalV2::SignerStateIo)?;
        let projected = match projected_carrier {
            Some(Some(bytes)) if bytes == physical.canonical_payload => true,
            Some(_) => return Err(SignerRefusalV2::MessagePayloadSubstitution),
            None => false,
        };
        candidates.push(Candidate {
            canonical_carrier: physical.canonical_payload.to_vec(),
            operation_identity: physical.operation_identity.clone(),
            kind: physical.kind,
            role: physical.role,
            envelope,
            verified,
            projected,
        });
    }

    // A projection without one exact authenticated physical carrier is never
    // repaired by inventing carrier state. MSG-02 is the sole pre-B/G route.
    let mut statement = transaction
        .prepare(
            "SELECT append_identity
             FROM c2_signer_message_appends
             WHERE route <> 'msg02_initial_pop'",
        )
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    let sql_append_identities = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| SignerRefusalV2::SignerStateIo)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    if !sql_append_identities.is_subset(&physical_append_identities) {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }

    // Ledger order is carried inside and authenticated by every envelope.
    // Sorting does not select semantic currentness; it only establishes that
    // already-projected carrier records are an exact prefix and carrier-first
    // records are one gap-free suffix.
    candidates.sort_by_key(|candidate| candidate.envelope.ledger_sequence);
    if candidates
        .windows(2)
        .any(|pair| pair[0].envelope.ledger_sequence >= pair[1].envelope.ledger_sequence)
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    let mut saw_missing = false;
    for candidate in &candidates {
        if candidate.projected {
            if saw_missing {
                return Err(SignerRefusalV2::MessagePayloadSubstitution);
            }
        } else {
            saw_missing = true;
        }
    }
    let missing = candidates
        .iter()
        .filter(|candidate| !candidate.projected)
        .count();
    if missing == 0 {
        return Ok(C2CarrierReprojectionReportV1 {
            reprojected_count: 0,
            saw_installation_lifecycle: false,
            saw_pending_transition_prefix: false,
            saw_completed_transition_receipt: false,
        });
    }

    let missing_routes = candidates
        .iter()
        .filter(|candidate| !candidate.projected)
        .map(|candidate| candidate.verified.route)
        .collect::<Vec<_>>();
    let saw_installation_lifecycle = missing_routes.iter().any(|route| {
        matches!(
            route,
            C2StoreSigningRouteV1::Msg03PhysicalGenerationBootstrap
                | C2StoreSigningRouteV1::Msg09InstallationIntent
                | C2StoreSigningRouteV1::Msg10InstallationReceipt
        )
    });
    let saw_pending_transition_prefix = missing_routes.iter().any(|route| {
        matches!(
            route,
            C2StoreSigningRouteV1::Msg05ActivePolicyContinuity
                | C2StoreSigningRouteV1::Msg06NormalRotationContinuity
                | C2StoreSigningRouteV1::Msg07SuccessorPop
                | C2StoreSigningRouteV1::Msg11PolicyTransitionIntent
        )
    });
    let saw_completed_transition_receipt = missing_routes.iter().any(|route| {
        matches!(
            route,
            C2StoreSigningRouteV1::Msg12ReceiptCurrent | C2StoreSigningRouteV1::Msg12ReceiptPending
        )
    });

    transaction
        .execute_batch("SAVEPOINT c2_reproject_exact_carrier_suffix_v1")
        .map_err(|_| SignerRefusalV2::SignerStateIo)?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-41");
    let result = (|| {
        let mut reprojected = 0_usize;
        for candidate in candidates
            .into_iter()
            .filter(|candidate| !candidate.projected)
        {
            let envelope = candidate.envelope;
            let message_identity = parse_identity_text_exact(&envelope.message_identity)?;
            let transaction_identity = parse_identity_text_exact(&envelope.transaction_identity)?;
            let terminal_binding = envelope
                .terminal_binding_identity
                .as_deref()
                .map(parse_identity_text_exact)
                .transpose()?;
            let payload_digest = parse_identity_text_exact(&envelope.payload_digest)?;
            let signer_key_generation =
                parse_identity_text_exact(&envelope.signer_key_generation_identity)?;
            let signature: [u8; 64] = hex::decode(&envelope.signature)
                .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?
                .try_into()
                .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
            let frame = C2PreparedSignedAppendV1 {
                brand: SignerMessageBrandV1 {
                    family: candidate.verified.route.family(),
                    route: candidate.verified.route,
                    message_identity,
                    transaction_identity,
                    terminal_binding,
                    payload_digest,
                },
                coordinates: envelope.coordinates,
                canonical_message: envelope.canonical_message,
                signing_preimage: envelope.signing_preimage,
                signature: CustodySignatureV1 {
                    family: candidate.verified.route.family(),
                    signer_key_generation,
                    payload_digest,
                    signature,
                },
            };
            let consumed = append_prepared_signed_frame_with_physical_carrier(
                transaction,
                frame,
                Some(&candidate.canonical_carrier),
            )?;
            if consumed.disposition != SignedFrameAppendDispositionV1::Appended
                || consumed.route != candidate.verified.route
                || consumed.message_identity != candidate.verified.message_identity
                || consumed.append_identity != candidate.verified.append_identity
                || consumed.ledger_sequence != envelope.ledger_sequence
                || consumed.generation_sequence != envelope.generation_sequence
                || consumed.resulting_frontier_identity
                    != candidate.verified.resulting_frontier_identity
                || consumed.effect_receipt_identity != envelope.effect_receipt_identity
                || candidate.operation_identity != candidate.verified.operation_identity
                || candidate.kind != physical_kind_for_route(candidate.verified.route)?
                || candidate.role != candidate.kind.role()
            {
                return Err(SignerRefusalV2::MessagePayloadSubstitution);
            }
            reprojected = reprojected
                .checked_add(1)
                .ok_or(SignerRefusalV2::SignerStateIo)?;
        }
        Ok::<usize, SignerRefusalV2>(reprojected)
    })();
    match result {
        Ok(reprojected) => {
            transaction
                .execute_batch("RELEASE c2_reproject_exact_carrier_suffix_v1")
                .map_err(|_| SignerRefusalV2::SignerStateIo)?;
            #[cfg(test)]
            crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-42");
            Ok(C2CarrierReprojectionReportV1 {
                reprojected_count: reprojected,
                saw_installation_lifecycle,
                saw_pending_transition_prefix,
                saw_completed_transition_receipt,
            })
        }
        Err(error) => {
            if transaction
                .execute_batch(
                    "ROLLBACK TO c2_reproject_exact_carrier_suffix_v1; RELEASE c2_reproject_exact_carrier_suffix_v1",
                )
                .is_err()
            {
                return Err(SignerRefusalV2::SignerStateIo);
            }
            #[cfg(test)]
            crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-43");
            Err(error)
        }
    }
}

/// Resolve the exact deterministic append/frontier/receipt value without
/// writing. The returned envelope is the canonical B/G value; SQLite is only
/// inserted after the actor has durably authenticated this envelope.
pub(in crate::store_generation) fn finalize_prepared_signed_frame(
    transaction: &Transaction<'_>,
    frame: C2PreparedSignedAppendV1,
) -> Result<C2FinalizedSignedAppendV1, SignerRefusalV2> {
    let route = frame.brand.route;
    if frame.brand.family != route.family() || route == C2StoreSigningRouteV1::Msg02InitialPop {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }

    let (ledger_sequence, generation_sequence, resulting_frontier_identity, projection_present) =
        if let Some(existing) = load_existing_append(transaction, &frame)? {
            let resulting: SignerIdentityV1 = existing
                .resulting_frontier_identity
                .as_slice()
                .try_into()
                .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
            if existing.message_identity != frame.brand.message_identity
                || existing.canonical_message != frame.canonical_message
                || existing.signing_preimage != frame.signing_preimage
                || existing.signature != frame.signature.signature
            {
                return Err(SignerRefusalV2::SignedFrameAlreadyConsumed);
            }
            (
                existing.ledger_sequence,
                existing.generation_sequence,
                resulting,
                true,
            )
        } else {
            let ledger_sequence = next_sequence(transaction, "ledger_sequence", None)?;
            let generation_sequence = next_sequence(
                transaction,
                "generation_sequence",
                Some(frame.coordinates.frontier_namespace_identity),
            )?;
            let predecessor = frame.coordinates.predecessor_frontier_identity;
            if let Some(previous) =
                latest_frontier(transaction, frame.coordinates.frontier_namespace_identity)?
                && previous != predecessor
            {
                return Err(SignerRefusalV2::MessageFrontierMismatch);
            }
            let resulting = digest_fields(
                FRONTIER_IDENTITY_DOMAIN_V1,
                &[
                    &frame.coordinates.frontier_namespace_identity,
                    &predecessor,
                    &generation_sequence.to_be_bytes(),
                    &frame.brand.message_identity,
                    &frame.brand.payload_digest,
                    &frame.signature.signature,
                ],
            );
            (ledger_sequence, generation_sequence, resulting, false)
        };

    let canonical_message_sha256 = sha256_bytes(&frame.canonical_message).to_string();
    let signing_preimage_sha256 = sha256_bytes(&frame.signing_preimage).to_string();
    let append_preimage = canonical_json_bytes(&AppendIdentityPreimageV1 {
        schema: "nq.c2_signer_message_append_identity_preimage.v1",
        route: route.as_str(),
        message_identity: identity_text(frame.brand.message_identity),
        transaction_identity: identity_text(frame.brand.transaction_identity),
        frontier_namespace_identity: identity_text(frame.coordinates.frontier_namespace_identity),
        predecessor_frontier_identity: identity_text(
            frame.coordinates.predecessor_frontier_identity,
        ),
        resulting_frontier_identity: identity_text(resulting_frontier_identity),
        ledger_sequence,
        generation_sequence,
        canonical_message_sha256: &canonical_message_sha256,
        signing_preimage_sha256: &signing_preimage_sha256,
        signature: hex::encode(frame.signature.signature),
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let append_identity = domain_digest_text(APPEND_IDENTITY_DOMAIN_V1, &append_preimage);
    let receipt_bytes = canonical_json_bytes(&AppendReceiptV1 {
        schema: "nq.c2_signer_message_append_receipt.v1",
        append_identity: &append_identity,
        route: route.as_str(),
        family: route.family().as_str(),
        message_identity: identity_text(frame.brand.message_identity),
        transaction_identity: identity_text(frame.brand.transaction_identity),
        ledger_sequence,
        generation_sequence,
        predecessor_frontier_identity: identity_text(
            frame.coordinates.predecessor_frontier_identity,
        ),
        resulting_frontier_identity: identity_text(resulting_frontier_identity),
        sole_consumer: route.sole_consumer().as_str(),
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let effect_receipt_identity = sha256_bytes(&receipt_bytes).to_string();
    let disposition = if projection_present {
        SignedFrameAppendDispositionV1::ExactReplay
    } else {
        SignedFrameAppendDispositionV1::Appended
    };
    let consumed = ConsumedSignedFrameV1 {
        disposition,
        family: frame.brand.family,
        route,
        message_identity: frame.brand.message_identity,
        append_identity,
        signer_key_generation: frame.signature.signer_key_generation,
        ledger_sequence,
        generation_sequence,
        event_cut: frame.coordinates.event_cut,
        resulting_frontier_identity,
        effect_receipt_identity,
    };
    finalize_carrier_envelope(frame, consumed, receipt_bytes, projection_present)
}

/// Insert/verify the disposable SQL projection only after physical B/G is
/// durable. The exact preview must equal the row produced by the projection
/// implementation, closing drift between carrier and schema.
pub(in crate::store_generation) fn append_finalized_signed_frame_projection(
    transaction: &Transaction<'_>,
    finalized: C2FinalizedSignedAppendV1,
) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
    let C2FinalizedSignedAppendV1 {
        frame,
        consumed,
        effect_receipt_bytes,
        canonical_carrier_bytes,
        projection_present: _,
    } = finalized;
    if sha256_bytes(&effect_receipt_bytes).to_string() != consumed.effect_receipt_identity {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    let projected = append_prepared_signed_frame_with_physical_carrier(
        transaction,
        frame,
        Some(&canonical_carrier_bytes),
    )?;
    if projected != consumed {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    Ok(projected)
}

/// Store-only proposal lane used by MSG-02 before B/G allocation. Every later
/// route must use `finalize_prepared_signed_frame` plus physical B/G first.
pub(in crate::store_generation) fn append_prepared_signed_frame(
    transaction: &Transaction<'_>,
    frame: C2PreparedSignedAppendV1,
) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
    append_prepared_signed_frame_with_physical_carrier(transaction, frame, None)
}

fn append_prepared_signed_frame_with_physical_carrier(
    transaction: &Transaction<'_>,
    frame: C2PreparedSignedAppendV1,
    physical_carrier_bytes: Option<&[u8]>,
) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
    let route = frame.brand.route;
    if frame.brand.family != route.family()
        || (route == C2StoreSigningRouteV1::Msg02InitialPop) != physical_carrier_bytes.is_none()
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }

    if let Some(existing) = load_existing_append(transaction, &frame)? {
        let resulting: SignerIdentityV1 = existing
            .resulting_frontier_identity
            .as_slice()
            .try_into()
            .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
        if existing.message_identity == frame.brand.message_identity
            && existing.canonical_message == frame.canonical_message
            && existing.signing_preimage == frame.signing_preimage
            && existing.signature == frame.signature.signature
            && existing.physical_carrier_bytes.as_deref() == physical_carrier_bytes
        {
            return Ok(ConsumedSignedFrameV1 {
                disposition: SignedFrameAppendDispositionV1::ExactReplay,
                family: frame.brand.family,
                route,
                message_identity: frame.brand.message_identity,
                append_identity: existing.append_identity,
                signer_key_generation: frame.signature.signer_key_generation,
                ledger_sequence: existing.ledger_sequence,
                generation_sequence: existing.generation_sequence,
                event_cut: frame.coordinates.event_cut,
                resulting_frontier_identity: resulting,
                effect_receipt_identity: existing.effect_receipt_identity,
            });
        }
        return Err(SignerRefusalV2::SignedFrameAlreadyConsumed);
    }

    let coordinates = &frame.coordinates;
    let ledger_sequence = next_sequence(transaction, "ledger_sequence", None)?;
    let generation_sequence = next_sequence(
        transaction,
        "generation_sequence",
        Some(coordinates.frontier_namespace_identity),
    )?;
    let predecessor = coordinates.predecessor_frontier_identity;
    if let Some(previous) = latest_frontier(transaction, coordinates.frontier_namespace_identity)?
        && previous != predecessor
    {
        return Err(SignerRefusalV2::MessageFrontierMismatch);
    }
    let resulting_frontier_identity = digest_fields(
        FRONTIER_IDENTITY_DOMAIN_V1,
        &[
            &coordinates.frontier_namespace_identity,
            &predecessor,
            &generation_sequence.to_be_bytes(),
            &frame.brand.message_identity,
            &frame.brand.payload_digest,
            &frame.signature.signature,
        ],
    );
    let canonical_message_sha256 = sha256_bytes(&frame.canonical_message).to_string();
    let signing_preimage_sha256 = sha256_bytes(&frame.signing_preimage).to_string();
    let physical_carrier_sha256 = physical_carrier_bytes.map(sha256_bytes);
    let physical_carrier_length = physical_carrier_bytes
        .map(|bytes| u64::try_from(bytes.len()))
        .transpose()
        .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let append_preimage = canonical_json_bytes(&AppendIdentityPreimageV1 {
        schema: "nq.c2_signer_message_append_identity_preimage.v1",
        route: route.as_str(),
        message_identity: identity_text(frame.brand.message_identity),
        transaction_identity: identity_text(frame.brand.transaction_identity),
        frontier_namespace_identity: identity_text(coordinates.frontier_namespace_identity),
        predecessor_frontier_identity: identity_text(predecessor),
        resulting_frontier_identity: identity_text(resulting_frontier_identity),
        ledger_sequence,
        generation_sequence,
        canonical_message_sha256: &canonical_message_sha256,
        signing_preimage_sha256: &signing_preimage_sha256,
        signature: hex::encode(frame.signature.signature),
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let append_identity = domain_digest_text(APPEND_IDENTITY_DOMAIN_V1, &append_preimage);
    let receipt_bytes = canonical_json_bytes(&AppendReceiptV1 {
        schema: "nq.c2_signer_message_append_receipt.v1",
        append_identity: &append_identity,
        route: route.as_str(),
        family: route.family().as_str(),
        message_identity: identity_text(frame.brand.message_identity),
        transaction_identity: identity_text(frame.brand.transaction_identity),
        ledger_sequence,
        generation_sequence,
        predecessor_frontier_identity: identity_text(predecessor),
        resulting_frontier_identity: identity_text(resulting_frontier_identity),
        sole_consumer: route.sole_consumer().as_str(),
    })
    .map_err(|_| SignerRefusalV2::MessagePayloadSubstitution)?;
    let effect_receipt_identity = sha256_bytes(&receipt_bytes).to_string();
    let physical_generation = coordinates.physical_generation_identity;
    let lifecycle_root = coordinates.lifecycle_root_identity;
    let prospective = coordinates.prospective_generation_preimage;

    transaction
        .execute(
            "INSERT INTO c2_signer_message_appends (
                ledger_sequence, generation_sequence, append_identity,
                message_identity, family, route, identity_domain, signature_domain,
                signer_phase, scope_class, authority_class, input_kind, sole_consumer,
                signature_algorithm, occurrence_id, occurrence_identity,
                physical_generation_identity, lifecycle_root_identity,
                prospective_generation_preimage, scope_identity, resident_identity,
                resident_generation, host_role, role_manifest_identity,
                role_manifest_generation, authority_domain, terminal_a1_identity,
                current_a2_snapshot_identity, grant_or_predecessor_standing_identity,
                signer_public_key, signer_scope_policy_identity,
                signer_scope_policy_version, active_store_policy_identity,
                active_store_policy_generation, active_store_policy_digest,
                implementation_manifest_identity,
                manifest_admission_correspondence_identity, qualified_candidate_identity,
                source_tree_identity, runtime_artifact_identity, terminal_binding_identity,
                signer_key_generation, signer_key_generation_identity,
                event_predecessor_identity, transaction_identity,
                transaction_intent_identity, frontier_namespace_identity,
                predecessor_frontier_identity, exact_content_identity,
                resulting_frontier_identity, event_cut, canonical_message,
                canonical_message_sha256, signing_preimage, signing_preimage_sha256,
                signature, effect_receipt_identity, effect_receipt_bytes,
                physical_carrier_bytes, physical_carrier_sha256,
                physical_carrier_length, committed_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35,
                ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46,
                ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55, ?56, ?57,
                ?58, ?59, ?60, ?61, ?62
            )",
            params![
                ledger_sequence,
                generation_sequence,
                append_identity,
                &frame.brand.message_identity[..],
                route.family().as_str(),
                route.as_str(),
                route.identity_domain(),
                route.signature_domain(),
                route.phase().as_str(),
                route.scope_class().as_str(),
                route.authority_class().as_str(),
                route.input_kind().as_str(),
                route.sole_consumer().as_str(),
                "ed25519",
                coordinates.occurrence_id,
                &coordinates.occurrence_identity[..],
                physical_generation.as_ref().map(|v| &v[..]),
                lifecycle_root.as_ref().map(|v| &v[..]),
                prospective.as_ref().map(|v| &v[..]),
                &coordinates.scope_identity[..],
                coordinates.resident_identity,
                coordinates.resident_generation,
                coordinates.host_role,
                &coordinates.role_manifest_identity[..],
                coordinates.role_manifest_generation,
                coordinates.authority_domain,
                &coordinates.terminal_a1_identity[..],
                &coordinates.current_a2_snapshot_identity[..],
                &coordinates.grant_or_predecessor_standing_identity[..],
                &coordinates.signer_public_key[..],
                &coordinates.signer_scope_policy_identity[..],
                coordinates.signer_scope_policy_version,
                &coordinates.active_store_policy_identity[..],
                coordinates.active_store_policy_generation,
                &coordinates.active_store_policy_digest[..],
                &coordinates.implementation_manifest_identity[..],
                &coordinates.manifest_admission_correspondence_identity[..],
                &coordinates.qualified_candidate_identity[..],
                &coordinates.source_tree_identity[..],
                &coordinates.runtime_artifact_identity[..],
                frame.brand.terminal_binding.as_ref().map(|v| &v[..]),
                coordinates.signer_key_generation,
                &coordinates.signer_key_generation_identity[..],
                &coordinates.event_predecessor_identity[..],
                &frame.brand.transaction_identity[..],
                &coordinates.transaction_intent_identity[..],
                &coordinates.frontier_namespace_identity[..],
                &predecessor[..],
                &coordinates.exact_content_identity[..],
                &resulting_frontier_identity[..],
                coordinates.event_cut,
                frame.canonical_message,
                canonical_message_sha256,
                frame.signing_preimage,
                signing_preimage_sha256,
                &frame.signature.signature[..],
                effect_receipt_identity,
                receipt_bytes,
                physical_carrier_bytes,
                physical_carrier_sha256.as_ref().map(Sha256Digest::as_str),
                physical_carrier_length,
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    #[cfg(test)]
    crate::store_generation::source_io_crash_test_support::after_source_io_v1("SC-44");

    Ok(ConsumedSignedFrameV1 {
        disposition: SignedFrameAppendDispositionV1::Appended,
        family: frame.brand.family,
        route,
        message_identity: frame.brand.message_identity,
        append_identity,
        signer_key_generation: frame.signature.signer_key_generation,
        ledger_sequence,
        generation_sequence,
        event_cut: coordinates.event_cut,
        resulting_frontier_identity,
        effect_receipt_identity,
    })
}

fn load_existing_append(
    transaction: &Transaction<'_>,
    frame: &C2PreparedSignedAppendV1,
) -> Result<Option<ExistingAppendV1>, SignerRefusalV2> {
    transaction
        .query_row(
            "SELECT ledger_sequence, generation_sequence, append_identity,
                    message_identity, canonical_message, signing_preimage, signature,
                    resulting_frontier_identity, effect_receipt_identity,
                    physical_carrier_bytes
             FROM c2_signer_message_appends
             WHERE route = ?1 AND occurrence_identity = ?2 AND transaction_identity = ?3",
            params![
                frame.brand.route.as_str(),
                &frame.coordinates.occurrence_identity[..],
                &frame.brand.transaction_identity[..]
            ],
            |row| {
                Ok(ExistingAppendV1 {
                    ledger_sequence: row.get::<_, u64>(0)?,
                    generation_sequence: row.get::<_, u64>(1)?,
                    append_identity: row.get(2)?,
                    message_identity: row.get(3)?,
                    canonical_message: row.get(4)?,
                    signing_preimage: row.get(5)?,
                    signature: row.get(6)?,
                    resulting_frontier_identity: row.get(7)?,
                    effect_receipt_identity: row.get(8)?,
                    physical_carrier_bytes: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(|_| SignerRefusalV2::CustodyIo)
}

fn next_sequence(
    transaction: &Transaction<'_>,
    column: &str,
    namespace: Option<SignerIdentityV1>,
) -> Result<u64, SignerRefusalV2> {
    let current: u64 = if column == "ledger_sequence" {
        transaction
            .query_row(
                "SELECT COALESCE(MAX(ledger_sequence), 0) FROM c2_signer_message_appends",
                [],
                |row| row.get(0),
            )
            .map_err(|_| SignerRefusalV2::CustodyIo)?
    } else {
        let namespace = namespace.ok_or(SignerRefusalV2::MessageFrontierMismatch)?;
        transaction
            .query_row(
                "SELECT COALESCE(MAX(generation_sequence), 0)
                 FROM c2_signer_message_appends WHERE frontier_namespace_identity = ?1",
                params![&namespace[..]],
                |row| row.get(0),
            )
            .map_err(|_| SignerRefusalV2::CustodyIo)?
    };
    current
        .checked_add(1)
        .ok_or(SignerRefusalV2::MessageFrontierMismatch)
}

fn latest_frontier(
    transaction: &Transaction<'_>,
    namespace: SignerIdentityV1,
) -> Result<Option<SignerIdentityV1>, SignerRefusalV2> {
    let bytes: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT resulting_frontier_identity FROM c2_signer_message_appends
             WHERE frontier_namespace_identity = ?1 ORDER BY generation_sequence DESC LIMIT 1",
            params![&namespace[..]],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| SignerRefusalV2::CustodyIo)?;
    bytes
        .map(|value| {
            value
                .as_slice()
                .try_into()
                .map_err(|_| SignerRefusalV2::MessageFrontierMismatch)
        })
        .transpose()
}

fn identity_text(identity: SignerIdentityV1) -> String {
    format!("sha256:{}", hex::encode(identity))
}

fn domain_digest_text(domain: &[u8], bytes: &[u8]) -> String {
    let digest = digest_fields(domain, &[bytes]);
    identity_text(digest)
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> SignerIdentityV1 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod durable_carrier_hostile_tests {
    use std::fs::File;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::{Signer as _, SigningKey};
    use rusqlite::Connection;
    use serde_json::Value;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::append_extent::{
        C2CarrierFileFactsV1, C2CarrierPairInputV1, construct_rec_30_pair_header_correspondence,
        construct_wu_03_immutable_wu_append_extents_b_g_carrier, initialize_durable_append_pair_v1,
    };
    use crate::store_generation::signer::messages::{
        C2ExternalSigningRouteV1, construct_all_store_route_test_messages,
    };

    fn finalized_carrier(
        transaction: &Transaction<'_>,
        message: &dyn SignerMessageV1,
        signing_key: &SigningKey,
    ) -> C2FinalizedSignedAppendV1 {
        let brand = construct_signing_brand(message).expect("closed route brand");
        let preimage = message.canonical_preimage();
        let signature = signing_key.sign(&preimage).to_bytes();
        let custody_signature = CustodySignatureV1 {
            family: message.family(),
            signer_key_generation: message.coordinates().signer_key_generation,
            payload_digest: Sha256::digest(&preimage).into(),
            signature,
        };
        let frame = construct_nonescaping_frame(message, brand, custody_signature)
            .expect("typed nonescaping frame");
        finalize_prepared_signed_frame(transaction, frame).expect("deterministic carrier")
    }

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn file_facts(byte: char, file: &File) -> C2CarrierFileFactsV1 {
        let metadata = file.metadata().unwrap();
        C2CarrierFileFactsV1 {
            file_identity: digest(byte),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            mode: metadata.permissions().mode() & 0o7777,
            physical_length: metadata.len(),
            link_count: metadata.nlink(),
        }
    }

    fn initialized_pair(
        occurrence_id: &str,
        physical_generation_identity: SignerIdentityV1,
    ) -> (C2DurableAppendPairV1, NamedTempFile, NamedTempFile) {
        let layout =
            construct_wu_03_immutable_wu_append_extents_b_g_carrier(1_048_576, 262_144, 4, 65_536)
                .unwrap();
        let b = NamedTempFile::new().unwrap();
        let g = NamedTempFile::new().unwrap();
        b.as_file()
            .set_len(layout.b_append_extent_length())
            .unwrap();
        g.as_file()
            .set_len(layout.g_append_extent_length())
            .unwrap();
        std::fs::set_permissions(b.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(g.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let correspondence = construct_rec_30_pair_header_correspondence(
            &layout,
            C2CarrierPairInputV1 {
                occurrence_id: occurrence_id.into(),
                physical_store_generation_identity: Sha256Digest::parse(identity_text(
                    physical_generation_identity,
                ))
                .unwrap(),
                qualified_backend_profile_identity: digest('b'),
                b_file: file_facts('c', b.as_file()),
                g_file: file_facts('d', g.as_file()),
            },
        )
        .unwrap();
        let pair =
            initialize_durable_append_pair_v1(&layout, &correspondence, b.as_file(), g.as_file())
                .unwrap();
        (pair, b, g)
    }

    fn route_message(
        signing_key: &SigningKey,
        route: C2StoreSigningRouteV1,
    ) -> Box<dyn SignerMessageV1> {
        construct_all_store_route_test_messages(signing_key.verifying_key().to_bytes())
            .unwrap()
            .into_iter()
            .find(|message| message.route() == route)
            .expect("route fixture")
    }

    fn append_physical_carrier(
        pair: &mut C2DurableAppendPairV1,
        finalized: &C2FinalizedSignedAppendV1,
    ) {
        pair.append_or_replay_exact(
            finalized.operation_identity().unwrap(),
            finalized.physical_kind(),
            finalized.canonical_carrier_bytes(),
        )
        .expect("carrier-first append");
    }

    fn signer_row_count(transaction: &Transaction<'_>) -> u64 {
        transaction
            .query_row(
                "SELECT COUNT(*) FROM c2_signer_message_appends",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn set_message_registry_projection(
        message: &mut Value,
        family: &str,
        route: &str,
        identity_domain: &str,
        signature_domain: &str,
        signer_phase: Option<&str>,
        scope_class: Option<&str>,
        authority_class: Option<&str>,
        input_kind: &str,
        sole_consumer: &str,
    ) {
        let object = message.as_object_mut().expect("canonical message object");
        object.insert("family".into(), Value::String(family.into()));
        object.insert("route".into(), Value::String(route.into()));
        object.insert(
            "identity_domain".into(),
            Value::String(identity_domain.into()),
        );
        object.insert(
            "signature_domain".into(),
            Value::String(signature_domain.into()),
        );
        if let Some(signer_phase) = signer_phase {
            object.insert("signer_phase".into(), Value::String(signer_phase.into()));
        }
        if let Some(scope_class) = scope_class {
            object.insert("scope_class".into(), Value::String(scope_class.into()));
            object
                .get_mut("coordinates")
                .and_then(Value::as_object_mut)
                .expect("coordinate object")
                .insert("scope_class".into(), Value::String(scope_class.into()));
        }
        if let Some(authority_class) = authority_class {
            object.insert(
                "authority_class".into(),
                Value::String(authority_class.into()),
            );
            object
                .get_mut("coordinates")
                .and_then(Value::as_object_mut)
                .expect("coordinate object")
                .insert(
                    "authority_class".into(),
                    Value::String(authority_class.into()),
                );
        }
        object.insert("sole_consumer".into(), Value::String(sole_consumer.into()));
        object
            .get_mut("verified_input")
            .and_then(Value::as_object_mut)
            .expect("verified input object")
            .insert("input_kind".into(), Value::String(input_kind.into()));
    }

    fn relabel_as_store_route(carrier: &[u8], target: C2StoreSigningRouteV1) -> Vec<u8> {
        let mut envelope: DurableSignerCarrierEnvelopeOwnedV1 =
            serde_json::from_slice(carrier).expect("valid source envelope");
        envelope.family = target.family().as_str().into();
        envelope.route = target.as_str().into();
        envelope.identity_domain = target.identity_domain().into();
        envelope.signature_domain = target.signature_domain().into();
        envelope.signer_phase = target.phase().as_str().into();
        envelope.scope_class = target.scope_class().as_str().into();
        envelope.authority_class = target.authority_class().as_str().into();
        envelope.input_kind = target.input_kind().as_str().into();
        envelope.sole_consumer = target.sole_consumer().as_str().into();
        let mut message: Value =
            serde_json::from_slice(&envelope.canonical_message).expect("valid source message");
        set_message_registry_projection(
            &mut message,
            target.family().as_str(),
            target.as_str(),
            target.identity_domain(),
            target.signature_domain(),
            Some(target.phase().as_str()),
            Some(target.scope_class().as_str()),
            Some(target.authority_class().as_str()),
            target.input_kind().as_str(),
            target.sole_consumer().as_str(),
        );
        envelope.canonical_message = canonical_json_bytes(&message).unwrap();
        canonical_json_bytes(&envelope).unwrap()
    }

    fn relabel_as_external_route(carrier: &[u8], target: C2ExternalSigningRouteV1) -> Vec<u8> {
        let mut envelope: DurableSignerCarrierEnvelopeOwnedV1 =
            serde_json::from_slice(carrier).expect("valid source envelope");
        envelope.family = target.family().as_str().into();
        envelope.route = target.as_str().into();
        envelope.identity_domain = target.identity_domain().into();
        envelope.signature_domain = target.signature_domain().into();
        envelope.input_kind = target.input_kind().into();
        envelope.sole_consumer = target.sole_consumer().into();
        let mut message: Value =
            serde_json::from_slice(&envelope.canonical_message).expect("valid source message");
        set_message_registry_projection(
            &mut message,
            target.family().as_str(),
            target.as_str(),
            target.identity_domain(),
            target.signature_domain(),
            None,
            None,
            None,
            target.input_kind(),
            target.sole_consumer(),
        );
        envelope.canonical_message = canonical_json_bytes(&message).unwrap();
        canonical_json_bytes(&envelope).unwrap()
    }

    #[test]
    fn every_physical_store_carrier_refuses_all_cross_route_and_external_relabels() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let messages =
            construct_all_store_route_test_messages(signing_key.verifying_key().to_bytes())
                .unwrap();
        let mut physical_sources = 0_usize;
        let mut store_relabels = 0_usize;
        let mut external_relabels = 0_usize;
        let mut unsigned_relabels = 0_usize;
        for message in messages {
            if message.route() == C2StoreSigningRouteV1::Msg02InitialPop {
                continue;
            }
            physical_sources += 1;
            let finalized = finalized_carrier(&transaction, message.as_ref(), &signing_key);
            let carrier = finalized.canonical_carrier_bytes();
            if let Err(error) = verify_durable_signer_carrier_envelope_v1(carrier) {
                panic!(
                    "unmodified {} carrier must verify: {error:?}",
                    message.route().as_str(),
                );
            }

            for target in C2StoreSigningRouteV1::ALL {
                if target == message.route() {
                    continue;
                }
                store_relabels += 1;
                assert!(
                    verify_durable_signer_carrier_envelope_v1(&relabel_as_store_route(
                        carrier, target,
                    ))
                    .is_err(),
                    "{} carrier accepted relabel as {}",
                    message.route().as_str(),
                    target.as_str(),
                );
            }
            for target in C2ExternalSigningRouteV1::ALL {
                external_relabels += 1;
                assert!(
                    verify_durable_signer_carrier_envelope_v1(&relabel_as_external_route(
                        carrier, target,
                    ))
                    .is_err(),
                    "{} carrier accepted external relabel as {}",
                    message.route().as_str(),
                    target.as_str(),
                );
            }

            let mut unsigned: DurableSignerCarrierEnvelopeOwnedV1 =
                serde_json::from_slice(carrier).unwrap();
            unsigned.family = ClosedMessageFamilyV1::Msg04BootstrapToGenerationRelation
                .as_str()
                .into();
            unsigned.route = "msg04_bootstrap_to_generation_relation".into();
            unsigned_relabels += 1;
            assert!(
                verify_durable_signer_carrier_envelope_v1(
                    &canonical_json_bytes(&unsigned).unwrap(),
                )
                .is_err(),
                "{} carrier entered unsigned MSG-04 lane",
                message.route().as_str(),
            );
        }
        assert_eq!(physical_sources, 10);
        assert_eq!(store_relabels, 100);
        assert_eq!(external_relabels, 70);
        assert_eq!(unsigned_relabels, 10);
    }

    #[test]
    fn exact_carrier_first_orphan_reprojects_once_but_pending_prefix_requires_lifecycle_recovery() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let message = route_message(
            &signing_key,
            C2StoreSigningRouteV1::Msg06NormalRotationContinuity,
        );
        let finalized = finalized_carrier(&transaction, message.as_ref(), &signing_key);
        let (mut pair, _b, _g) = initialized_pair(
            message.verified_coordinates().occurrence_id(),
            message.coordinates().physical_generation,
        );
        append_physical_carrier(&mut pair, &finalized);
        assert_eq!(signer_row_count(&transaction), 0);

        let report = reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &pair)
            .expect("exact carrier suffix is reprojectable");
        assert_eq!(report.reprojected_count(), 1);
        assert!(!report.saw_installation_lifecycle());
        assert!(report.saw_pending_transition_prefix());
        assert!(!report.saw_completed_transition_receipt());
        assert!(report.requires_lifecycle_reconciliation());
        assert_eq!(signer_row_count(&transaction), 1);
        verify_durable_signer_carrier_pair_v1(&transaction, &pair).unwrap();

        let replay = reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &pair)
            .expect("second scan is exact and inert");
        assert_eq!(replay.reprojected_count(), 0);
        assert_eq!(signer_row_count(&transaction), 1);
    }

    #[test]
    fn msg12_carrier_first_orphan_requires_completed_transition_reconciliation() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let message = route_message(&signing_key, C2StoreSigningRouteV1::Msg12ReceiptPending);
        let finalized = finalized_carrier(&transaction, message.as_ref(), &signing_key);
        let (mut pair, _b, _g) = initialized_pair(
            message.verified_coordinates().occurrence_id(),
            message.coordinates().physical_generation,
        );
        append_physical_carrier(&mut pair, &finalized);
        let report = reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &pair)
            .expect("MSG-12 carrier itself is exactly authenticated");
        assert_eq!(report.reprojected_count(), 1);
        assert!(!report.saw_installation_lifecycle());
        assert!(!report.saw_pending_transition_prefix());
        assert!(report.saw_completed_transition_receipt());
        assert!(report.requires_lifecycle_reconciliation());
        assert_eq!(signer_row_count(&transaction), 1);
    }

    #[test]
    fn changed_carrier_content_is_not_reprojected_and_writes_nothing() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let message = route_message(
            &signing_key,
            C2StoreSigningRouteV1::Msg06NormalRotationContinuity,
        );
        let finalized = finalized_carrier(&transaction, message.as_ref(), &signing_key);
        let mut changed = finalized.canonical_carrier_bytes().to_vec();
        let changed_index = changed.len() / 2;
        changed[changed_index] ^= 1;
        let (mut pair, _b, _g) = initialized_pair(
            message.verified_coordinates().occurrence_id(),
            message.coordinates().physical_generation,
        );
        pair.append_or_replay_exact(
            finalized.operation_identity().unwrap(),
            finalized.physical_kind(),
            &changed,
        )
        .unwrap();

        assert!(reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &pair).is_err());
        assert_eq!(signer_row_count(&transaction), 0);
    }

    #[test]
    fn exact_carrier_cannot_be_substituted_across_store_occurrence_or_generation() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let message = route_message(
            &signing_key,
            C2StoreSigningRouteV1::Msg06NormalRotationContinuity,
        );
        let finalized = finalized_carrier(&transaction, message.as_ref(), &signing_key);

        let (mut wrong_occurrence, _ob, _og) = initialized_pair(
            "wrong-store-occurrence",
            message.coordinates().physical_generation,
        );
        append_physical_carrier(&mut wrong_occurrence, &finalized);
        assert!(
            reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &wrong_occurrence,)
                .is_err()
        );
        assert_eq!(signer_row_count(&transaction), 0);

        let (mut wrong_generation, _gb, _gg) =
            initialized_pair(message.verified_coordinates().occurrence_id(), [99; 32]);
        append_physical_carrier(&mut wrong_generation, &finalized);
        assert!(
            reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &wrong_generation,)
                .is_err()
        );
        assert_eq!(signer_row_count(&transaction), 0);
    }

    #[test]
    fn sql_only_projection_and_noncontiguous_carrier_suffix_are_refused_without_writes() {
        let signing_key = SigningKey::from_bytes(&[77; 32]);

        let mut sql_only_connection = Connection::open_in_memory().unwrap();
        sql_only_connection.execute_batch(crate::SCHEMA).unwrap();
        let sql_only_transaction = sql_only_connection.transaction().unwrap();
        let sql_only_message = route_message(
            &signing_key,
            C2StoreSigningRouteV1::Msg06NormalRotationContinuity,
        );
        let sql_only_finalized = finalized_carrier(
            &sql_only_transaction,
            sql_only_message.as_ref(),
            &signing_key,
        );
        append_finalized_signed_frame_projection(&sql_only_transaction, sql_only_finalized)
            .unwrap();
        let (empty_pair, _empty_b, _empty_g) = initialized_pair(
            sql_only_message.verified_coordinates().occurrence_id(),
            sql_only_message.coordinates().physical_generation,
        );
        assert!(
            reproject_exact_durable_signer_carrier_suffix_v1(&sql_only_transaction, &empty_pair,)
                .is_err()
        );
        assert_eq!(signer_row_count(&sql_only_transaction), 1);

        let mut gap_connection = Connection::open_in_memory().unwrap();
        gap_connection.execute_batch(crate::SCHEMA).unwrap();
        let gap_transaction = gap_connection.transaction().unwrap();
        gap_transaction
            .execute_batch("SAVEPOINT derive_ledger_gap")
            .unwrap();
        let first_message = route_message(
            &signing_key,
            C2StoreSigningRouteV1::Msg06NormalRotationContinuity,
        );
        let first = finalized_carrier(&gap_transaction, first_message.as_ref(), &signing_key);
        append_finalized_signed_frame_projection(&gap_transaction, first).unwrap();
        let second_message = route_message(&signing_key, C2StoreSigningRouteV1::Msg07SuccessorPop);
        let second = finalized_carrier(&gap_transaction, second_message.as_ref(), &signing_key);
        let second_operation = second.operation_identity().unwrap();
        let second_kind = second.physical_kind();
        let second_carrier = second.canonical_carrier_bytes().to_vec();
        gap_transaction
            .execute_batch("ROLLBACK TO derive_ledger_gap; RELEASE derive_ledger_gap")
            .unwrap();
        assert_eq!(signer_row_count(&gap_transaction), 0);
        let (mut gap_pair, _gap_b, _gap_g) = initialized_pair(
            second_message.verified_coordinates().occurrence_id(),
            second_message.coordinates().physical_generation,
        );
        gap_pair
            .append_or_replay_exact(second_operation, second_kind, &second_carrier)
            .unwrap();
        assert!(
            reproject_exact_durable_signer_carrier_suffix_v1(&gap_transaction, &gap_pair).is_err()
        );
        assert_eq!(signer_row_count(&gap_transaction), 0);
    }

    #[test]
    fn projection_failure_rolls_back_exactly_and_fresh_retry_recovers_once() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::SCHEMA).unwrap();
        let transaction = connection.transaction().unwrap();
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let message = route_message(
            &signing_key,
            C2StoreSigningRouteV1::Msg06NormalRotationContinuity,
        );
        let finalized = finalized_carrier(&transaction, message.as_ref(), &signing_key);
        let (mut pair, _b, _g) = initialized_pair(
            message.verified_coordinates().occurrence_id(),
            message.coordinates().physical_generation,
        );
        append_physical_carrier(&mut pair, &finalized);
        transaction
            .execute_batch(
                "CREATE TEMP TRIGGER c2_test_fail_projection
                 BEFORE INSERT ON c2_signer_message_appends
                 BEGIN SELECT RAISE(ABORT, 'injected projection cut'); END;",
            )
            .unwrap();
        assert!(reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &pair).is_err());
        assert_eq!(signer_row_count(&transaction), 0);
        transaction
            .execute_batch("DROP TRIGGER c2_test_fail_projection")
            .unwrap();

        let recovered = reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &pair)
            .expect("fresh exact retry recovers carrier-first suffix");
        assert_eq!(recovered.reprojected_count(), 1);
        assert!(recovered.requires_lifecycle_reconciliation());
        assert_eq!(signer_row_count(&transaction), 1);
        let duplicate = reproject_exact_durable_signer_carrier_suffix_v1(&transaction, &pair)
            .expect("repeated recovery has no duplicate effect");
        assert_eq!(duplicate.reprojected_count(), 0);
        assert_eq!(signer_row_count(&transaction), 1);
    }
}

#[cfg(test)]
mod healthy_rotation_tests {
    use super::*;

    fn id(value: u8) -> SignerIdentityV1 {
        [value; 32]
    }

    fn changed() -> HealthyRotationPolicyOutcomeV1 {
        HealthyRotationPolicyOutcomeV1::Changed {
            immutable_signer_policy_identity: id(1),
            old_active_policy_identity: id(2),
            new_active_policy_identity: id(3),
            activation_identity: id(4),
            policy_predecessor_identity: id(5),
            successor_grant_or_unchanged_applicability_identity: id(6),
        }
    }

    fn unchanged() -> HealthyRotationPolicyOutcomeV1 {
        HealthyRotationPolicyOutcomeV1::Unchanged {
            exact_policy_activation_applicability_proof_identity: id(7),
        }
    }

    #[test]
    fn healthy_rotation_always_plans_msg06_before_msg11() {
        for outcome in [changed(), unchanged()] {
            let plan = outcome.append_plan();
            assert_eq!(
                plan.first(),
                Some(&HealthyRotationAppendStepV1::MandatoryMsg06)
            );
            assert_eq!(plan.last(), Some(&HealthyRotationAppendStepV1::Msg11));
            assert_eq!(
                plan.iter()
                    .filter(|step| **step == HealthyRotationAppendStepV1::MandatoryMsg06)
                    .count(),
                1,
            );
        }
    }

    #[test]
    fn msg05_is_present_exactly_for_changed_policy_activation_or_applicability() {
        assert_eq!(
            changed().append_plan(),
            &[
                HealthyRotationAppendStepV1::MandatoryMsg06,
                HealthyRotationAppendStepV1::ConditionalMsg05,
                HealthyRotationAppendStepV1::Msg11,
            ],
        );
        assert_eq!(
            unchanged().append_plan(),
            &[
                HealthyRotationAppendStepV1::MandatoryMsg06,
                HealthyRotationAppendStepV1::Msg11,
            ],
        );

        let old_policy = id(10);
        let current_activation = id(11);
        let current_applicability = id(12);
        assert!(!healthy_rotation_policy_changed(
            old_policy,
            current_activation,
            current_applicability,
            old_policy,
            current_activation,
            current_applicability,
        ));
        assert!(healthy_rotation_policy_changed(
            old_policy,
            current_activation,
            current_applicability,
            id(13),
            current_activation,
            current_applicability,
        ));
        assert!(healthy_rotation_policy_changed(
            old_policy,
            current_activation,
            current_applicability,
            old_policy,
            id(14),
            current_applicability,
        ));
        assert!(healthy_rotation_policy_changed(
            old_policy,
            current_activation,
            current_applicability,
            old_policy,
            current_activation,
            id(15),
        ));
    }

    #[test]
    fn hostile_plan_cannot_omit_msg06_or_insert_msg05_on_unchanged_route() {
        let unchanged_plan = unchanged().append_plan();
        assert!(!unchanged_plan.contains(&HealthyRotationAppendStepV1::ConditionalMsg05));
        for outcome in [changed(), unchanged()] {
            assert!(!matches!(
                outcome.append_plan(),
                [HealthyRotationAppendStepV1::Msg11, ..]
            ));
        }
    }

    #[test]
    fn rotation_fact_constructors_are_confined_to_store_generation() {
        // live_c2 must be able to seal these facts, but no public or crate-wide
        // API may turn caller-authored coordinates into signing inputs.
        let source = include_str!("coordinator.rs");
        let confined_constructor = [
            "pub(in crate::store_generation) fn ",
            "from_store_actor_resolution",
        ]
        .concat();
        let crate_constructor = ["pub(crate) fn ", "from_store_actor_resolution"].concat();
        let public_constructor = ["pub fn ", "from_store_actor_resolution"].concat();
        assert_eq!(source.matches(&confined_constructor).count(), 3,);
        assert_eq!(source.matches(&crate_constructor).count(), 0);
        assert_eq!(source.matches(&public_constructor).count(), 0);

        // There is still no coordinator-local raw-coordinate caller. The only
        // legal production callers belong in Store generation resolution.
        let successor_constructor = [
            "StoreVerifiedSuccessorPossessionFactsV1",
            "::from_store_actor_resolution",
        ]
        .concat();
        let intent_constructor = [
            "StoreVerifiedHealthyRotationIntentFactsV1",
            "::from_store_actor_resolution",
        ]
        .concat();
        let receipt_constructor = [
            "StoreVerifiedPendingRotationReceiptFactsV1",
            "::from_store_actor_resolution",
        ]
        .concat();
        assert_eq!(source.matches(&successor_constructor).count(), 0,);
        assert_eq!(source.matches(&intent_constructor).count(), 0,);
        assert_eq!(source.matches(&receipt_constructor).count(), 0,);
    }

    fn consumed_frame(
        family: ClosedMessageFamilyV1,
        route: C2StoreSigningRouteV1,
        value: u8,
    ) -> ConsumedSignedFrameV1 {
        ConsumedSignedFrameV1 {
            disposition: SignedFrameAppendDispositionV1::Appended,
            family,
            route,
            message_identity: id(value),
            append_identity: format!("sha256:{:064x}", value),
            signer_key_generation: id(value.wrapping_add(1)),
            ledger_sequence: u64::from(value),
            generation_sequence: u64::from(value),
            event_cut: u64::from(value),
            resulting_frontier_identity: id(value.wrapping_add(2)),
            effect_receipt_identity: format!("sha256:{:064x}", value.wrapping_add(3)),
        }
    }

    #[test]
    fn consumed_rotation_accessors_preserve_exact_route_evidence() {
        let msg07 = consumed_frame(
            ClosedMessageFamilyV1::Msg07SuccessorPop,
            C2StoreSigningRouteV1::Msg07SuccessorPop,
            7,
        );
        let possession = ConsumedSuccessorPossessionV1 {
            actor_instance_identity: Sha256Digest::parse(format!("sha256:{:064x}", 1)).unwrap(),
            post_append_snapshot_identity: Sha256Digest::parse(format!("sha256:{:064x}", 2))
                .unwrap(),
            post_append_effect_epoch: 3,
            successor_proposal_identity: id(4),
            successor_key_identity: id(5),
            transition_identity: id(6),
            consumed: msg07,
        };
        assert_eq!(
            possession.msg07().family,
            ClosedMessageFamilyV1::Msg07SuccessorPop
        );
        assert_eq!(possession.message_identity(), id(7));
        assert_eq!(possession.successor_proposal_identity(), id(4));
        assert_eq!(possession.successor_key_identity(), id(5));
        assert_eq!(possession.transition_identity(), id(6));

        let intent = ConsumedHealthyRotationIntentV1 {
            actor_instance_identity: Sha256Digest::parse(format!("sha256:{:064x}", 8)).unwrap(),
            post_append_snapshot_identity: Sha256Digest::parse(format!("sha256:{:064x}", 9))
                .unwrap(),
            post_append_effect_epoch: 10,
            successor_proposal_identity: id(11),
            successor_pop_identity: id(12),
            transition_identity: id(13),
            mandatory_msg06: consumed_frame(
                ClosedMessageFamilyV1::Msg06NormalRotationContinuity,
                C2StoreSigningRouteV1::Msg06NormalRotationContinuity,
                14,
            ),
            conditional_msg05: Some(consumed_frame(
                ClosedMessageFamilyV1::Msg05ActivePolicyContinuity,
                C2StoreSigningRouteV1::Msg05ActivePolicyContinuity,
                15,
            )),
            msg11: consumed_frame(
                ClosedMessageFamilyV1::Msg11PolicyTransitionIntent,
                C2StoreSigningRouteV1::Msg11PolicyTransitionIntent,
                16,
            ),
        };
        assert_eq!(intent.successor_proposal_identity(), id(11));
        assert_eq!(intent.successor_pop_identity(), id(12));
        assert_eq!(intent.transition_identity(), id(13));
        assert_eq!(intent.mandatory_msg06().message_identity, id(14));
        assert_eq!(
            intent
                .conditional_msg05()
                .map(|frame| frame.message_identity),
            Some(id(15)),
        );
        assert_eq!(intent.msg11().message_identity, id(16));
    }

    #[test]
    fn pending_receipt_constructor_uses_fresh_selected_context_not_stale_intent_epoch() {
        let source = include_str!("coordinator.rs");
        let pending_impl = source
            .split("impl StoreVerifiedPendingRotationReceiptFactsV1")
            .nth(1)
            .expect("pending receipt fact implementation")
            .split("/// Process-local proof that the exact actor-bound MSG-02 request")
            .next()
            .expect("bounded pending receipt implementation");
        assert!(!pending_impl.contains("intent: &ConsumedHealthyRotationIntentV1"));
        assert!(pending_impl.contains("selected_transition_input_identity: SignerIdentityV1"));
        assert!(pending_impl.contains("completed_append_identity: SignerIdentityV1"));
        assert!(pending_impl.contains("context.verify_live(actor)?"));
        assert!(pending_impl.contains(
            "view.transition_intent_identity() != Some(selected_transition_input_identity)"
        ));
    }
}
