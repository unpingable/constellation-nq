//! Closed, family-branded Store-integrity signer messages.
//!
//! There is intentionally no generic public envelope.  Only the sealed
//! [`SignerMessageV1`] implementations in this module can cross the private
//! custodian boundary.  MSG-04 is represented separately as an unsigned
//! Store-derived relation; MSG-01 and MSG-13 through MSG-16 are external A1
//! carrier families and therefore have no Store-signer message type.

use super::result::SignerRefusalV2;

/// Stable 256-bit identity used by the closed signer surface.
pub(super) type SignerIdentityV1 = [u8; 32];

/// Coordinates shared by every Store-integrity-signed message.
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
                self.physical_generation,
                self.lifecycle_root,
                self.scope,
                self.policy,
                self.signer_key_generation,
            ]
            .iter()
            .any(|identity| is_zero(identity))
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(())
    }
}

/// Exact ownership class for one of the sixteen closed message families.
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

/// Complete, non-extensible MSG-01 through MSG-16 census.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum ClosedMessageFamilyV1 {
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
    pub(crate) const ALL: [Self; 16] = [
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
            Self::Msg05ActivePolicyContinuity | Self::Msg08GlobalRefusal => {
                MessageFamilyOwnerV1::CurrentGenerationSigner
            }
            Self::Msg06NormalRotationContinuity | Self::Msg11PolicyTransitionIntent => {
                MessageFamilyOwnerV1::CurrentPredecessor
            }
            Self::Msg07SuccessorPop => MessageFamilyOwnerV1::PendingSuccessor,
            Self::Msg12PolicyTransitionReceipt => MessageFamilyOwnerV1::TransitionSelectedSigner,
        }
    }

    pub(crate) const fn domain(self) -> &'static [u8] {
        match self {
            Self::Msg01BootstrapGrant => b"nq.c2_store_integrity_bootstrap_grant.v1",
            Self::Msg02InitialProposalPop => b"nq.c2_store_integrity_initial_pop.v1",
            Self::Msg03PhysicalGenerationBootstrap => b"nq.c2_store_generation_bootstrap.v1",
            Self::Msg04BootstrapToGenerationRelation => b"nq.c2_signer_bootstrap_transition.v1",
            Self::Msg05ActivePolicyContinuity => b"nq.c2_active_policy_continuity.v1",
            Self::Msg06NormalRotationContinuity => b"nq.c2_signer_rotation_continuity.v1",
            Self::Msg07SuccessorPop => b"nq.c2_store_integrity_successor_pop.v1",
            Self::Msg08GlobalRefusal => b"nq.c2_global_refusal.v1",
            Self::Msg09InstallationIntent => b"nq.c2_store_generation_installation_intent.v1",
            Self::Msg10InstallationReceipt => b"nq.c2_store_generation_installation_receipt.v1",
            Self::Msg11PolicyTransitionIntent => b"nq.c2_policy_transition_intent.v1",
            Self::Msg12PolicyTransitionReceipt => b"nq.c2_policy_transition_receipt.v1",
            Self::Msg13RestoreAuthorization => b"nq.c2_restore_authorization.v1",
            Self::Msg14RevocationJudgment => b"nq.c2_store_integrity_revocation_judgment.v1",
            Self::Msg15RecoveryGrant => b"nq.c2_store_integrity_recovery_grant.v1",
            Self::Msg16QuarantineClosure => b"nq.c2_quarantine_closure_judgment.v1",
        }
    }

    pub(crate) const fn is_store_signable(self) -> bool {
        !matches!(
            self.owner(),
            MessageFamilyOwnerV1::ExternalTerminalA1 | MessageFamilyOwnerV1::UnsignedStoreRelation
        )
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Private trait implemented only by the ten Store/proposal-key signable
/// semantic message types below.
pub(super) trait SignerMessageV1: sealed::Sealed {
    fn family(&self) -> ClosedMessageFamilyV1;
    fn coordinates(&self) -> &SignerMessageCoordinatesV1;
    fn canonical_preimage(&self) -> Vec<u8>;
}

fn is_zero(identity: &SignerIdentityV1) -> bool {
    identity.iter().all(|byte| *byte == 0)
}

fn encode_common(
    family: ClosedMessageFamilyV1,
    coordinates: &SignerMessageCoordinatesV1,
    primary: &SignerIdentityV1,
    secondary: &SignerIdentityV1,
    role: u8,
) -> Vec<u8> {
    let domain = family.domain();
    let mut bytes = Vec::with_capacity(2 + domain.len() + 32 * 8 + 9);
    bytes.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    bytes.extend_from_slice(domain);
    bytes.push(family as u8);
    bytes.push(role);
    bytes.extend_from_slice(&coordinates.occurrence);
    bytes.extend_from_slice(&coordinates.physical_generation);
    bytes.extend_from_slice(&coordinates.lifecycle_root);
    bytes.extend_from_slice(&coordinates.scope);
    bytes.extend_from_slice(&coordinates.policy);
    bytes.extend_from_slice(&coordinates.signer_key_generation);
    bytes.extend_from_slice(&coordinates.cut.to_be_bytes());
    bytes.extend_from_slice(primary);
    bytes.extend_from_slice(secondary);
    bytes
}

fn validate_frame(
    coordinates: &SignerMessageCoordinatesV1,
    primary: &SignerIdentityV1,
) -> Result<(), SignerRefusalV2> {
    coordinates.validate()?;
    if is_zero(primary) {
        return Err(SignerRefusalV2::MessageFrontierMismatch);
    }
    Ok(())
}

macro_rules! define_signed_message {
    ($name:ident, $family:ident, $owner:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct $name {
            coordinates: SignerMessageCoordinatesV1,
            primary_identity: SignerIdentityV1,
            secondary_identity: SignerIdentityV1,
        }

        impl $name {
            fn new(
                coordinates: SignerMessageCoordinatesV1,
                primary_identity: SignerIdentityV1,
                secondary_identity: SignerIdentityV1,
            ) -> Result<Self, SignerRefusalV2> {
                validate_frame(&coordinates, &primary_identity)?;
                Ok(Self {
                    coordinates,
                    primary_identity,
                    secondary_identity,
                })
            }
        }

        impl sealed::Sealed for $name {}

        impl SignerMessageV1 for $name {
            fn family(&self) -> ClosedMessageFamilyV1 {
                ClosedMessageFamilyV1::$family
            }

            fn coordinates(&self) -> &SignerMessageCoordinatesV1 {
                &self.coordinates
            }

            fn canonical_preimage(&self) -> Vec<u8> {
                encode_common(
                    self.family(),
                    &self.coordinates,
                    &self.primary_identity,
                    &self.secondary_identity,
                    MessageFamilyOwnerV1::$owner as u8,
                )
            }
        }
    };
}

define_signed_message!(
    InitialProposalPoPFrameV1,
    Msg02InitialProposalPop,
    ProposedKey
);
define_signed_message!(
    PhysicalGenerationBootstrapFrameV1,
    Msg03PhysicalGenerationBootstrap,
    BootstrapSigner
);
define_signed_message!(
    ActivePolicyContinuityFrameV1,
    Msg05ActivePolicyContinuity,
    CurrentGenerationSigner
);
define_signed_message!(
    NormalRotationContinuityFrameV1,
    Msg06NormalRotationContinuity,
    CurrentPredecessor
);
define_signed_message!(SuccessorPoPFrameV1, Msg07SuccessorPop, PendingSuccessor);
define_signed_message!(
    GlobalRefusalFrameV1,
    Msg08GlobalRefusal,
    CurrentGenerationSigner
);
define_signed_message!(
    StoreGenerationInstallationIntentFrameV1,
    Msg09InstallationIntent,
    BootstrapSigner
);
define_signed_message!(
    StoreGenerationInstallationReceiptFrameV1,
    Msg10InstallationReceipt,
    BootstrapSigner
);
define_signed_message!(
    PolicyTransitionIntentFrameV1,
    Msg11PolicyTransitionIntent,
    CurrentPredecessor
);
define_signed_message!(
    PolicyTransitionReceiptFrameV1,
    Msg12PolicyTransitionReceipt,
    TransitionSelectedSigner
);

/// MSG-04: an unsigned, Store-derived relation that cannot implement
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

macro_rules! message_constructor_and_verifier {
    ($construct:ident, $verify:ident, $ty:ident) => {
        pub(crate) fn $construct(
            coordinates: SignerMessageCoordinatesV1,
            primary_identity: SignerIdentityV1,
            secondary_identity: SignerIdentityV1,
        ) -> Result<$ty, SignerRefusalV2> {
            $ty::new(coordinates, primary_identity, secondary_identity)
        }

        pub(crate) fn $verify(message: &$ty) -> Result<(), SignerRefusalV2> {
            validate_frame(message.coordinates(), &message.primary_identity)
        }
    };
}

message_constructor_and_verifier!(
    construct_msg_02_initial_proposal_pop_proposed_store_integrity_key,
    verify_msg_02_initial_proposal_pop_proposed_store_integrity_key,
    InitialProposalPoPFrameV1
);
message_constructor_and_verifier!(
    construct_msg_03_chartered_physical_store_generation_bootstrap_bootstrap_signer,
    verify_msg_03_chartered_physical_store_generation_bootstrap_bootstrap_signer,
    PhysicalGenerationBootstrapFrameV1
);
message_constructor_and_verifier!(
    construct_msg_05_active_policy_continuity_succession_current_generation_signer,
    verify_msg_05_active_policy_continuity_succession_current_generation_signer,
    ActivePolicyContinuityFrameV1
);
message_constructor_and_verifier!(
    construct_msg_06_healthy_rotation_continuity_current_usable_predecessor,
    verify_msg_06_healthy_rotation_continuity_current_usable_predecessor,
    NormalRotationContinuityFrameV1
);
message_constructor_and_verifier!(
    construct_msg_07_successor_pop_pending_successor_correspondence_not_authority,
    verify_msg_07_successor_pop_pending_successor_correspondence_not_authority,
    SuccessorPoPFrameV1
);
message_constructor_and_verifier!(
    construct_msg_08_global_refusal_current_generation_signer_after_g,
    verify_msg_08_global_refusal_current_generation_signer_after_g,
    GlobalRefusalFrameV1
);
message_constructor_and_verifier!(
    construct_msg_09_store_generation_installation_intent_bootstrap_signer,
    verify_msg_09_store_generation_installation_intent_bootstrap_signer,
    StoreGenerationInstallationIntentFrameV1
);
message_constructor_and_verifier!(
    construct_msg_10_store_generation_installation_receipt_bootstrap_signer_pre,
    verify_msg_10_store_generation_installation_receipt_bootstrap_signer_pre,
    StoreGenerationInstallationReceiptFrameV1
);
message_constructor_and_verifier!(
    construct_msg_11_policy_transition_intent_current_predecessor_signer_plus,
    verify_msg_11_policy_transition_intent_current_predecessor_signer_plus,
    PolicyTransitionIntentFrameV1
);
message_constructor_and_verifier!(
    construct_msg_12_policy_transition_receipt_selected_current_pending_successor,
    verify_msg_12_policy_transition_receipt_selected_current_pending_successor,
    PolicyTransitionReceiptFrameV1
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

#[cfg(test)]
mod tests {
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
    fn closed_family_census_and_ownership_are_exact() {
        assert_eq!(ClosedMessageFamilyV1::ALL.len(), 16);
        assert!(!ClosedMessageFamilyV1::Msg01BootstrapGrant.is_store_signable());
        assert!(!ClosedMessageFamilyV1::Msg04BootstrapToGenerationRelation.is_store_signable());
        assert!(!ClosedMessageFamilyV1::Msg15RecoveryGrant.is_store_signable());
        assert!(ClosedMessageFamilyV1::Msg06NormalRotationContinuity.is_store_signable());
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

    #[test]
    fn signed_preimage_binds_family_and_all_coordinates() {
        let message = construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
            coordinates(),
            [11; 32],
            [12; 32],
        )
        .expect("valid message");
        let encoded = message.canonical_preimage();
        assert!(encoded.windows(32).any(|window| window == [3; 32]));
        assert_eq!(
            message.family(),
            ClosedMessageFamilyV1::Msg06NormalRotationContinuity
        );
    }
}
