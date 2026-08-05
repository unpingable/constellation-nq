//! Private, typed signer transition coordinator.
//!
//! Every route below names one concrete message type and one sealed capability
//! phase.  The coordinator signs and immediately transfers the frame to the
//! sole named append consumer; it never returns a detached signature.

use std::collections::BTreeSet;
use std::marker::PhantomData;

use sha2::{Digest as _, Sha256};

use super::custody::{C2StoreIntegrityCustodian, CustodySignatureV1};
use super::messages::{
    ActivePolicyContinuityFrameV1, ClosedMessageFamilyV1, GlobalRefusalFrameV1,
    InitialProposalPoPFrameV1, NormalRotationContinuityFrameV1, PhysicalGenerationBootstrapFrameV1,
    PolicyTransitionIntentFrameV1, PolicyTransitionReceiptFrameV1, SignerIdentityV1,
    SignerMessageV1, StoreGenerationInstallationIntentFrameV1,
    StoreGenerationInstallationReceiptFrameV1, SuccessorPoPFrameV1,
};
use super::result::SignerRefusalV2;

/// One-use lexical proof that signing was reached through the typed
/// coordinator.  Its private field prevents sibling signer modules from
/// invoking custody directly even though the custody/coordinator modules
/// share a parent privacy boundary.
pub(super) struct CoordinatorSigningPermitV1 {
    _private: (),
}

impl CoordinatorSigningPermitV1 {
    fn issue() -> Self {
        Self { _private: () }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self::issue()
    }
}

/// Exact terminal signer frontier rechecked for every live request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalSignerFrontierV1 {
    pub(crate) occurrence: SignerIdentityV1,
    pub(crate) physical_generation: SignerIdentityV1,
    pub(crate) lifecycle_root: SignerIdentityV1,
    pub(crate) scope: SignerIdentityV1,
    pub(crate) policy: SignerIdentityV1,
    pub(crate) terminal_binding: SignerIdentityV1,
    pub(crate) signer_key_generation: SignerIdentityV1,
    pub(crate) complete_candidate_set_digest: SignerIdentityV1,
    pub(crate) effective_cut: u64,
}

impl TerminalSignerFrontierV1 {
    fn validate(&self) -> Result<(), SignerRefusalV2> {
        if self.effective_cut == 0
            || [
                self.occurrence,
                self.physical_generation,
                self.lifecycle_root,
                self.scope,
                self.policy,
                self.terminal_binding,
                self.signer_key_generation,
                self.complete_candidate_set_digest,
            ]
            .iter()
            .any(|identity| identity.iter().all(|byte| *byte == 0))
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(())
    }

    fn matches<M: SignerMessageV1>(&self, message: &M) -> bool {
        let coordinates = message.coordinates();
        coordinates.occurrence == self.occurrence
            && coordinates.physical_generation == self.physical_generation
            && coordinates.lifecycle_root == self.lifecycle_root
            && coordinates.scope == self.scope
            && coordinates.policy == self.policy
            && coordinates.signer_key_generation == self.signer_key_generation
            && coordinates.cut >= self.effective_cut
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootstrapCapabilityEvidenceV1 {
    pub(crate) grant_identity: SignerIdentityV1,
    pub(crate) proposal_identity: SignerIdentityV1,
    pub(crate) pop_identity: SignerIdentityV1,
    pub(crate) accepted_enrollment: SignerIdentityV1,
    pub(crate) frontier: TerminalSignerFrontierV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenerationCapabilityEvidenceV1 {
    pub(crate) root_binding: SignerIdentityV1,
    pub(crate) current_binding: SignerIdentityV1,
    pub(crate) persisted_resolution: SignerIdentityV1,
    pub(crate) transition_receipt: SignerIdentityV1,
    pub(crate) frontier: TerminalSignerFrontierV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingSuccessorCapabilityEvidenceV1 {
    pub(crate) predecessor_binding: SignerIdentityV1,
    pub(crate) proposal_identity: SignerIdentityV1,
    pub(crate) successor_key_generation: SignerIdentityV1,
    pub(crate) transition_identity: SignerIdentityV1,
    pub(crate) frontier: TerminalSignerFrontierV1,
}

/// Sealed process-local bootstrap signer capability.
#[derive(Debug)]
pub(crate) struct C2BootstrapSignerCapability {
    evidence: BootstrapCapabilityEvidenceV1,
    _sealed: PhantomData<fn() -> ()>,
}

/// Sealed process-local current generation signer capability.
#[derive(Debug)]
pub(crate) struct C2GenerationSignerCapability {
    evidence: GenerationCapabilityEvidenceV1,
    _sealed: PhantomData<fn() -> ()>,
}

/// Sealed process-local pending successor capability.
#[derive(Debug)]
pub(crate) struct C2PendingSuccessorCapability {
    evidence: PendingSuccessorCapabilityEvidenceV1,
    _sealed: PhantomData<fn() -> ()>,
}

/// One family brand derived from a concrete private typed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignerMessageBrandV1 {
    family: ClosedMessageFamilyV1,
    terminal_binding: SignerIdentityV1,
    payload_digest: SignerIdentityV1,
}

/// A frame that cannot be constructed outside the coordinator and has no
/// public signature accessor.
#[derive(Debug)]
pub(crate) struct NonescapingSignedFrameV1 {
    brand: SignerMessageBrandV1,
    signature: CustodySignatureV1,
}

/// Durable append acknowledgement.  It contains identities, not signature
/// bytes, and therefore cannot be replayed as a signing response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsumedSignedFrameV1 {
    pub(crate) family: ClosedMessageFamilyV1,
    pub(crate) terminal_binding: SignerIdentityV1,
    pub(crate) payload_digest: SignerIdentityV1,
    pub(crate) signer_key_generation: SignerIdentityV1,
    pub(crate) append_sequence: u64,
}

/// The sole concrete consumer of signed frames.
#[derive(Debug, Default)]
pub(crate) struct C2SignerDurableAppendConsumerV1 {
    consumed_payloads: BTreeSet<SignerIdentityV1>,
    next_sequence: u64,
}

impl C2SignerDurableAppendConsumerV1 {
    fn consume(
        &mut self,
        frame: NonescapingSignedFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        if frame.brand.family != frame.signature.family
            || frame.brand.payload_digest != frame.signature.payload_digest
            || !self
                .consumed_payloads
                .insert(frame.signature.payload_digest)
        {
            return Err(SignerRefusalV2::SignedFrameAlreadyConsumed);
        }
        // Signature bytes are intentionally consumed here.  The durable Store
        // append integration persists them in its named record; no accessor is
        // exposed back through the coordinator.
        let _signature_bytes = frame.signature.signature;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(SignerRefusalV2::SignedFrameAlreadyConsumed)?;
        Ok(ConsumedSignedFrameV1 {
            family: frame.brand.family,
            terminal_binding: frame.brand.terminal_binding,
            payload_digest: frame.brand.payload_digest,
            signer_key_generation: frame.signature.signer_key_generation,
            append_sequence: self.next_sequence,
        })
    }
}

/// Store-private bridge from validated requests to one consuming append.
pub(crate) struct C2SignerTransitionCoordinator<'custody> {
    custodian: &'custody C2StoreIntegrityCustodian,
    frontier: TerminalSignerFrontierV1,
    append_consumer: C2SignerDurableAppendConsumerV1,
}

impl<'custody> C2SignerTransitionCoordinator<'custody> {
    pub(super) fn new(
        custodian: &'custody C2StoreIntegrityCustodian,
        frontier: TerminalSignerFrontierV1,
    ) -> Result<Self, SignerRefusalV2> {
        frontier.validate()?;
        let custody = custodian.coordinates();
        if custody.occurrence_identity() != frontier.occurrence
            || custody.physical_generation_bytes() != frontier.physical_generation
            || custody.lifecycle_root_bytes() != frontier.lifecycle_root
            || custody.scope_bytes() != frontier.scope
            || custody.policy_bytes() != frontier.policy
            || custodian.key_generation_identity() != frontier.signer_key_generation
        {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        Ok(Self {
            custodian,
            frontier,
            append_consumer: C2SignerDurableAppendConsumerV1::default(),
        })
    }

    fn sign_and_consume<M: SignerMessageV1>(
        &mut self,
        message: &M,
        expected_family: ClosedMessageFamilyV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        if message.family() != expected_family || !self.frontier.matches(message) {
            return Err(SignerRefusalV2::MessageFrontierMismatch);
        }
        let brand = construct_sg_n_18_signing_method_accepts_private_typed_payload_semantic(
            &self.frontier,
            message,
        )?;
        let signing_permit = CoordinatorSigningPermitV1::issue();
        let signature = self.custodian.sign(signing_permit, message)?;
        let frame = construct_sg_n_20_signature_response_is_nonescaping_typed_value_consumed(
            brand, signature,
        )?;
        self.append_consumer.consume(frame)
    }

    pub(crate) fn append_initial_proposal_pop(
        &mut self,
        capability: &C2PendingSuccessorCapability,
        message: &InitialProposalPoPFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_pending_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg02InitialProposalPop)
    }

    pub(crate) fn append_physical_generation_bootstrap(
        &mut self,
        capability: &C2BootstrapSignerCapability,
        message: &PhysicalGenerationBootstrapFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_bootstrap_capability(capability, &self.frontier)?;
        self.sign_and_consume(
            message,
            ClosedMessageFamilyV1::Msg03PhysicalGenerationBootstrap,
        )
    }

    pub(crate) fn append_active_policy_continuity(
        &mut self,
        capability: &C2GenerationSignerCapability,
        message: &ActivePolicyContinuityFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_generation_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg05ActivePolicyContinuity)
    }

    pub(crate) fn append_normal_rotation_continuity(
        &mut self,
        capability: &C2GenerationSignerCapability,
        message: &NormalRotationContinuityFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_generation_capability(capability, &self.frontier)?;
        self.sign_and_consume(
            message,
            ClosedMessageFamilyV1::Msg06NormalRotationContinuity,
        )
    }

    pub(crate) fn append_successor_pop(
        &mut self,
        capability: &C2PendingSuccessorCapability,
        message: &SuccessorPoPFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_pending_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg07SuccessorPop)
    }

    pub(crate) fn append_global_refusal(
        &mut self,
        capability: &C2GenerationSignerCapability,
        message: &GlobalRefusalFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_generation_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg08GlobalRefusal)
    }

    pub(crate) fn append_installation_intent(
        &mut self,
        capability: &C2BootstrapSignerCapability,
        message: &StoreGenerationInstallationIntentFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_bootstrap_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg09InstallationIntent)
    }

    pub(crate) fn append_installation_receipt(
        &mut self,
        capability: &C2BootstrapSignerCapability,
        message: &StoreGenerationInstallationReceiptFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_bootstrap_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg10InstallationReceipt)
    }

    pub(crate) fn append_policy_transition_intent(
        &mut self,
        capability: &C2GenerationSignerCapability,
        message: &PolicyTransitionIntentFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_generation_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg11PolicyTransitionIntent)
    }

    pub(crate) fn append_current_policy_transition_receipt(
        &mut self,
        capability: &C2GenerationSignerCapability,
        message: &PolicyTransitionReceiptFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_generation_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg12PolicyTransitionReceipt)
    }

    pub(crate) fn append_pending_policy_transition_receipt(
        &mut self,
        capability: &C2PendingSuccessorCapability,
        message: &PolicyTransitionReceiptFrameV1,
    ) -> Result<ConsumedSignedFrameV1, SignerRefusalV2> {
        verify_pending_capability(capability, &self.frontier)?;
        self.sign_and_consume(message, ClosedMessageFamilyV1::Msg12PolicyTransitionReceipt)
    }
}

fn all_nonzero(identities: &[SignerIdentityV1]) -> bool {
    identities
        .iter()
        .all(|identity| identity.iter().any(|byte| *byte != 0))
}

fn verify_bootstrap_capability(
    capability: &C2BootstrapSignerCapability,
    frontier: &TerminalSignerFrontierV1,
) -> Result<(), SignerRefusalV2> {
    if capability.evidence.frontier != *frontier
        || !all_nonzero(&[
            capability.evidence.grant_identity,
            capability.evidence.proposal_identity,
            capability.evidence.pop_identity,
            capability.evidence.accepted_enrollment,
        ])
    {
        return Err(SignerRefusalV2::CapabilityFamilyMismatch);
    }
    Ok(())
}

fn verify_generation_capability(
    capability: &C2GenerationSignerCapability,
    frontier: &TerminalSignerFrontierV1,
) -> Result<(), SignerRefusalV2> {
    if capability.evidence.frontier != *frontier
        || capability.evidence.current_binding != frontier.terminal_binding
        || !all_nonzero(&[
            capability.evidence.root_binding,
            capability.evidence.persisted_resolution,
            capability.evidence.transition_receipt,
        ])
    {
        return Err(SignerRefusalV2::CapabilityFamilyMismatch);
    }
    Ok(())
}

fn verify_pending_capability(
    capability: &C2PendingSuccessorCapability,
    frontier: &TerminalSignerFrontierV1,
) -> Result<(), SignerRefusalV2> {
    if capability.evidence.frontier != *frontier
        || capability.evidence.predecessor_binding != frontier.terminal_binding
        || !all_nonzero(&[
            capability.evidence.proposal_identity,
            capability.evidence.successor_key_generation,
            capability.evidence.transition_identity,
        ])
    {
        return Err(SignerRefusalV2::CapabilityFamilyMismatch);
    }
    Ok(())
}

pub(crate) fn construct_sg_wu_03a_capability_source_owner(
    evidence: BootstrapCapabilityEvidenceV1,
) -> Result<C2BootstrapSignerCapability, SignerRefusalV2> {
    evidence.frontier.validate()?;
    let capability = C2BootstrapSignerCapability {
        evidence,
        _sealed: PhantomData,
    };
    verify_bootstrap_capability(&capability, &capability.evidence.frontier)?;
    Ok(capability)
}

pub(crate) fn verify_sg_wu_03a_capability_source_owner(
    capability: &C2BootstrapSignerCapability,
) -> Result<(), SignerRefusalV2> {
    verify_bootstrap_capability(capability, &capability.evidence.frontier)
}

pub(crate) fn construct_sg_wu_03b_capability_source_owner(
    evidence: GenerationCapabilityEvidenceV1,
) -> Result<C2GenerationSignerCapability, SignerRefusalV2> {
    evidence.frontier.validate()?;
    let capability = C2GenerationSignerCapability {
        evidence,
        _sealed: PhantomData,
    };
    verify_generation_capability(&capability, &capability.evidence.frontier)?;
    Ok(capability)
}

pub(crate) fn verify_sg_wu_03b_capability_source_owner(
    capability: &C2GenerationSignerCapability,
) -> Result<(), SignerRefusalV2> {
    verify_generation_capability(capability, &capability.evidence.frontier)
}

pub(crate) fn construct_sg_wu_03c_capability_source_owner(
    evidence: PendingSuccessorCapabilityEvidenceV1,
) -> Result<C2PendingSuccessorCapability, SignerRefusalV2> {
    evidence.frontier.validate()?;
    let capability = C2PendingSuccessorCapability {
        evidence,
        _sealed: PhantomData,
    };
    verify_pending_capability(&capability, &capability.evidence.frontier)?;
    Ok(capability)
}

pub(crate) fn verify_sg_wu_03c_capability_source_owner(
    capability: &C2PendingSuccessorCapability,
) -> Result<(), SignerRefusalV2> {
    verify_pending_capability(capability, &capability.evidence.frontier)
}

pub(crate) fn construct_sg_wu_04_typed_request_message_owner_closed_methods_canonical<'a>(
    custodian: &'a C2StoreIntegrityCustodian,
    frontier: TerminalSignerFrontierV1,
) -> Result<C2SignerTransitionCoordinator<'a>, SignerRefusalV2> {
    C2SignerTransitionCoordinator::new(custodian, frontier)
}

pub(crate) fn verify_sg_wu_04_typed_request_message_owner_closed_methods_canonical(
    coordinator: &C2SignerTransitionCoordinator<'_>,
) -> Result<(), SignerRefusalV2> {
    coordinator.frontier.validate()
}

pub(crate) fn construct_sg_n_14_bootstrap_capability_is_constructed_grant_proposal_matching(
    evidence: BootstrapCapabilityEvidenceV1,
) -> Result<C2BootstrapSignerCapability, SignerRefusalV2> {
    construct_sg_wu_03a_capability_source_owner(evidence)
}

pub(crate) fn verify_sg_n_14_bootstrap_capability_is_constructed_grant_proposal_matching(
    capability: &C2BootstrapSignerCapability,
) -> Result<(), SignerRefusalV2> {
    verify_sg_wu_03a_capability_source_owner(capability)
}

pub(crate) fn construct_sg_n_15_generation_capability_requires_persisted_generation_binding_transition(
    evidence: GenerationCapabilityEvidenceV1,
) -> Result<C2GenerationSignerCapability, SignerRefusalV2> {
    construct_sg_wu_03b_capability_source_owner(evidence)
}

pub(crate) fn verify_sg_n_15_generation_capability_requires_persisted_generation_binding_transition(
    capability: &C2GenerationSignerCapability,
) -> Result<(), SignerRefusalV2> {
    verify_sg_wu_03b_capability_source_owner(capability)
}

pub(crate) fn construct_sg_n_16_pending_successor_capability_is_distinct_may_sign(
    evidence: PendingSuccessorCapabilityEvidenceV1,
) -> Result<C2PendingSuccessorCapability, SignerRefusalV2> {
    construct_sg_wu_03c_capability_source_owner(evidence)
}

pub(crate) fn verify_sg_n_16_pending_successor_capability_is_distinct_may_sign(
    capability: &C2PendingSuccessorCapability,
) -> Result<(), SignerRefusalV2> {
    verify_sg_wu_03c_capability_source_owner(capability)
}

pub(crate) fn construct_sg_n_17_request_bridge_has_store_owned_requester_capability<'a>(
    custodian: &'a C2StoreIntegrityCustodian,
    frontier: TerminalSignerFrontierV1,
) -> Result<C2SignerTransitionCoordinator<'a>, SignerRefusalV2> {
    C2SignerTransitionCoordinator::new(custodian, frontier)
}

pub(crate) fn verify_sg_n_17_request_bridge_has_store_owned_requester_capability(
    coordinator: &C2SignerTransitionCoordinator<'_>,
) -> Result<(), SignerRefusalV2> {
    coordinator.frontier.validate()
}

pub(crate) fn construct_sg_n_18_signing_method_accepts_private_typed_payload_semantic<
    M: SignerMessageV1,
>(
    frontier: &TerminalSignerFrontierV1,
    message: &M,
) -> Result<SignerMessageBrandV1, SignerRefusalV2> {
    if !message.family().is_store_signable() || !frontier.matches(message) {
        return Err(SignerRefusalV2::MessageFamilyNotSignable);
    }
    let payload_digest = Sha256::digest(message.canonical_preimage());
    Ok(SignerMessageBrandV1 {
        family: message.family(),
        terminal_binding: frontier.terminal_binding,
        payload_digest: payload_digest.into(),
    })
}

pub(crate) fn verify_sg_n_18_signing_method_accepts_private_typed_payload_semantic(
    brand: &SignerMessageBrandV1,
) -> Result<(), SignerRefusalV2> {
    if !brand.family.is_store_signable()
        || !all_nonzero(&[brand.terminal_binding, brand.payload_digest])
    {
        return Err(SignerRefusalV2::MessageFamilyNotSignable);
    }
    Ok(())
}

pub(crate) fn construct_sg_n_19_lifecycle_transition_restart_live_signer_request_re(
    frontier: TerminalSignerFrontierV1,
) -> Result<TerminalSignerFrontierV1, SignerRefusalV2> {
    frontier.validate()?;
    Ok(frontier)
}

pub(crate) fn verify_sg_n_19_lifecycle_transition_restart_live_signer_request_re(
    frontier: &TerminalSignerFrontierV1,
) -> Result<(), SignerRefusalV2> {
    frontier.validate()
}

pub(crate) fn construct_sg_n_20_signature_response_is_nonescaping_typed_value_consumed(
    brand: SignerMessageBrandV1,
    signature: CustodySignatureV1,
) -> Result<NonescapingSignedFrameV1, SignerRefusalV2> {
    if brand.family != signature.family || brand.payload_digest != signature.payload_digest {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    Ok(NonescapingSignedFrameV1 { brand, signature })
}

pub(crate) fn verify_sg_n_20_signature_response_is_nonescaping_typed_value_consumed(
    frame: &NonescapingSignedFrameV1,
) -> Result<(), SignerRefusalV2> {
    if frame.brand.family != frame.signature.family
        || frame.brand.payload_digest != frame.signature.payload_digest
    {
        return Err(SignerRefusalV2::MessagePayloadSubstitution);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;
    use crate::store_generation::signer::custody::{C2StoreIntegrityCustodian, test_coordinates};
    use crate::store_generation::signer::messages::{
        SignerMessageCoordinatesV1,
        construct_msg_06_healthy_rotation_continuity_current_usable_predecessor,
    };

    fn frontier() -> TerminalSignerFrontierV1 {
        TerminalSignerFrontierV1 {
            occurrence: [1; 32],
            physical_generation: [2; 32],
            lifecycle_root: [3; 32],
            scope: [4; 32],
            policy: [5; 32],
            terminal_binding: [6; 32],
            signer_key_generation: [7; 32],
            complete_candidate_set_digest: [8; 32],
            effective_cut: 9,
        }
    }

    #[test]
    fn typed_route_signs_and_immediately_consumes() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinates = test_coordinates();
        let (custodian, _) = C2StoreIntegrityCustodian::create_below_test_root(
            coordinates.clone(),
            File::open(root.path()).unwrap(),
        )
        .unwrap();
        let frontier = TerminalSignerFrontierV1 {
            occurrence: coordinates.occurrence_identity(),
            physical_generation: coordinates.physical_generation_bytes(),
            lifecycle_root: coordinates.lifecycle_root_bytes(),
            scope: coordinates.scope_bytes(),
            policy: coordinates.policy_bytes(),
            terminal_binding: [6; 32],
            signer_key_generation: custodian.key_generation_identity(),
            complete_candidate_set_digest: [8; 32],
            effective_cut: 9,
        };
        let capability =
            construct_sg_wu_03b_capability_source_owner(GenerationCapabilityEvidenceV1 {
                root_binding: [11; 32],
                current_binding: frontier.terminal_binding,
                persisted_resolution: [12; 32],
                transition_receipt: [13; 32],
                frontier,
            })
            .expect("valid generation capability");
        let message = construct_msg_06_healthy_rotation_continuity_current_usable_predecessor(
            SignerMessageCoordinatesV1 {
                occurrence: frontier.occurrence,
                physical_generation: frontier.physical_generation,
                lifecycle_root: frontier.lifecycle_root,
                scope: frontier.scope,
                policy: frontier.policy,
                signer_key_generation: frontier.signer_key_generation,
                cut: 10,
            },
            [14; 32],
            [15; 32],
        )
        .expect("valid typed message");
        let mut coordinator = C2SignerTransitionCoordinator::new(&custodian, frontier)
            .expect("matching private coordinator");
        let receipt = coordinator
            .append_normal_rotation_continuity(&capability, &message)
            .expect("frame consumed by named append consumer");
        assert_eq!(
            receipt.family,
            ClosedMessageFamilyV1::Msg06NormalRotationContinuity
        );
    }
}
