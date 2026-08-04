//! Exact bootstrap-to-generation transition ordering.
//!
//! This module consumes a verified external grant and already verified
//! proposal/PoP records.  It cannot create an external grant and it does not
//! expose a bootstrap capability before all preceding cuts are established.

use nq_protocol::sha256_bytes;

use super::external_governance::VerifiedBootstrapGrantV1;
use super::messages::SignerIdentityV1;
use super::records::{
    SignerRecordCoordinatesV1, StoreIntegrityBootstrapTransitionReceiptV1,
    StoreIntegrityEnrollmentV2, StoreIntegrityGenerationGenesisV1,
    StoreIntegrityProofOfPossessionV1, verify_sg_rec_05_accepted_wrapper,
    verify_sg_rec_06_generation_genesis_signed_payload_identity_signature_carrier,
    verify_sg_rec_07_bootstrap_generation_transition_receipt_binding_commitment_signature,
};
use super::result::SignerRefusalV2;

const BOOTSTRAP_TRANSITION_DOMAIN: &[u8] = b"nq.c2.signer_bootstrap_transition.identity.v1";

fn exact_identity(parts: &[&[u8]]) -> SignerIdentityV1 {
    let mut bytes = Vec::with_capacity(
        BOOTSTRAP_TRANSITION_DOMAIN.len()
            + 1
            + parts.iter().map(|part| part.len() + 8).sum::<usize>(),
    );
    bytes.extend_from_slice(BOOTSTRAP_TRANSITION_DOMAIN);
    bytes.push(0);
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    let digest = sha256_bytes(&bytes);
    hex::decode(&digest.as_str()[7..])
        .expect("canonical sha256")
        .try_into()
        .expect("sha256 is 32 bytes")
}

/// The nine exact dependency cuts in the initial signer transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum BootstrapTransitionStageV1 {
    GrantVerified = 1,
    ProposalPersisted = 2,
    PoPVerified = 3,
    BootstrapCapabilityBorrowed = 4,
    GenesisSigned = 5,
    GovernedCommitAppended = 6,
    TransitionReceiptPersisted = 7,
    BootstrapClosed = 8,
    GenerationCapabilityAvailable = 9,
}

/// Durable/ephemeral interpretation at one finite transition cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignerTransitionCutStateV1 {
    FailureRetryAtTransitionCutHasDurableEphemeralAuthorityCleanupVerified {
        reached: BootstrapTransitionStageV1,
        durable_through: BootstrapTransitionStageV1,
        ephemeral_signature_destroyed_on_failure: bool,
        retry_requires_same_grant_and_proposal: bool,
        generation_capability_available: bool,
    },
}

impl SignerTransitionCutStateV1 {
    pub(crate) const fn reached(&self) -> BootstrapTransitionStageV1 {
        match self {
            Self::FailureRetryAtTransitionCutHasDurableEphemeralAuthorityCleanupVerified {
                reached,
                ..
            } => *reached,
        }
    }
}

/// One complete initial transition. All fields are exact identities; no raw
/// private key or generic signer escapes in this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootstrapTransitionEvidenceV1 {
    transition_identity: SignerIdentityV1,
    grant_identity: SignerIdentityV1,
    grant_request_identity: SignerIdentityV1,
    candidate_identity: SignerIdentityV1,
    proposal_identity: SignerIdentityV1,
    pop_identity: SignerIdentityV1,
    enrollment_identity: SignerIdentityV1,
    install_policy_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    genesis_identity: SignerIdentityV1,
    store_commitment_identity: SignerIdentityV1,
    append_identity: SignerIdentityV1,
    persisted_resolution_identity: SignerIdentityV1,
    receipt_identity: SignerIdentityV1,
    initial_binding_identity: SignerIdentityV1,
    cuts: [u64; 9],
}

/// The two exact V2 row projections share one closed evidence record.  The
/// second projection records the dependency-order obligation without
/// inventing another transition identity or capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapToGenerationTransitionV1 {
    BootstrapGenerationOwnerGenerationGenesisSignatureStoreCommitmentTransitionReceiptVerified(
        BootstrapTransitionEvidenceV1,
    ),
    BootstrapGenerationTransitionFollowsGrantProposalPoPBootstrapCapabilityGenesisVerified(
        BootstrapTransitionEvidenceV1,
    ),
}

impl BootstrapToGenerationTransitionV1 {
    pub(crate) const fn transition_identity(&self) -> SignerIdentityV1 {
        match self {
            Self::BootstrapGenerationOwnerGenerationGenesisSignatureStoreCommitmentTransitionReceiptVerified(evidence)
            | Self::BootstrapGenerationTransitionFollowsGrantProposalPoPBootstrapCapabilityGenesisVerified(evidence) => {
                evidence.transition_identity
            }
        }
    }
}

fn verify_cut_order(cuts: &[u64; 9]) -> Result<(), SignerRefusalV2> {
    if cuts[0] == 0 || cuts.windows(2).any(|window| window[0] >= window[1]) {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

fn cycle_free_transition_identity(
    grant_identity: &SignerIdentityV1,
    grant_request_identity: &SignerIdentityV1,
    candidate_identity: &SignerIdentityV1,
    enrollment_identity: &SignerIdentityV1,
    pop_identity: &SignerIdentityV1,
    install_policy_identity: &SignerIdentityV1,
    coordinates: &SignerRecordCoordinatesV1,
    transition_cut: u64,
) -> SignerIdentityV1 {
    let coordinate_bytes = coordinates.identity_bytes();
    exact_identity(&[
        grant_identity,
        grant_request_identity,
        candidate_identity,
        enrollment_identity,
        pop_identity,
        install_policy_identity,
        &coordinate_bytes,
        &transition_cut.to_be_bytes(),
        &[0], // MSG-04 is the sole unsigned message-family relation.
    ])
}

#[allow(clippy::too_many_arguments)]
fn construct_transition(
    grant: &VerifiedBootstrapGrantV1,
    pop: &StoreIntegrityProofOfPossessionV1,
    enrollment: &StoreIntegrityEnrollmentV2,
    genesis: &StoreIntegrityGenerationGenesisV1,
    receipt: &StoreIntegrityBootstrapTransitionReceiptV1,
    store_commitment_identity: SignerIdentityV1,
    cuts: [u64; 9],
) -> Result<BootstrapTransitionEvidenceV1, SignerRefusalV2> {
    verify_cut_order(&cuts)?;
    verify_sg_rec_05_accepted_wrapper(enrollment)?;
    verify_sg_rec_06_generation_genesis_signed_payload_identity_signature_carrier(genesis)?;
    verify_sg_rec_07_bootstrap_generation_transition_receipt_binding_commitment_signature(receipt)?;
    if grant.proposed_key_generation() != 0
        || cuts[0] < grant.lifecycle_cut()
        || enrollment.candidate.candidate_cut != cuts[1]
        || pop.pop_cut != cuts[2]
        || enrollment.accepted_cut != cuts[3]
        || enrollment.candidate.key_generation != 0
        || grant.proposal_identity_bytes() != enrollment.candidate.proposal_identity
        || grant.store_integrity_public_key() != enrollment.candidate.public_key
        || grant.physical_generation_bytes() != enrollment.candidate.coordinates.physical_generation
        || grant.signer_scope_policy_bytes() != enrollment.candidate.coordinates.signer_policy
        || enrollment.candidate.grant_identity != *grant.grant_identity().bytes()
        || enrollment.candidate.grant_request_identity != *grant.request_identity().bytes()
        || pop.grant_identity != *grant.grant_identity().bytes()
        || pop.proposal_identity != enrollment.candidate.proposal_identity
        || pop.identity != enrollment.pop_identity
        || genesis.initial_enrollment_identity != enrollment.identity
        || genesis.bootstrap_identity != *grant.grant_identity().bytes()
        || genesis.generation_commitment_identity != store_commitment_identity
        || genesis.coordinates != enrollment.candidate.coordinates
        || genesis.signer_key_generation != enrollment.candidate.key_generation
        || genesis.signer_public_key != enrollment.candidate.public_key
        || receipt.bootstrap_grant_identity != *grant.grant_identity().bytes()
        || receipt.enrollment_identity != enrollment.identity
        || receipt.initial_pop_identity != pop.identity
        || receipt.coordinates != enrollment.candidate.coordinates
        || receipt.signer_key_generation != enrollment.candidate.key_generation
        || receipt.signer_public_key != enrollment.candidate.public_key
        || receipt.append_identity == [0; 32]
        || receipt.persisted_resolution_identity == [0; 32]
        || receipt.initial_current_binding_identity == [0; 32]
        || store_commitment_identity == [0; 32]
        || genesis.genesis_cut != cuts[4]
        || receipt.effective_cut != cuts[6]
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    // The relation identity must exist before the signed genesis and receipt
    // that name it.  Its preimage therefore contains only grant, inert
    // candidate/enrollment/PoP, immutable coordinates, install policy and the
    // selected transition cut; no later signature, append, resolution,
    // receipt, or root can feed its own ancestor.
    let transition_identity = cycle_free_transition_identity(
        grant.grant_identity().bytes(),
        grant.request_identity().bytes(),
        &enrollment.candidate.identity,
        &enrollment.identity,
        &pop.identity,
        &grant.install_policy_digest(),
        &enrollment.candidate.coordinates,
        receipt.effective_cut,
    );
    if genesis.bootstrap_transition_identity != transition_identity
        || receipt.transition_identity != transition_identity
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(BootstrapTransitionEvidenceV1 {
        transition_identity,
        grant_identity: *grant.grant_identity().bytes(),
        grant_request_identity: *grant.request_identity().bytes(),
        candidate_identity: enrollment.candidate.identity,
        proposal_identity: pop.proposal_identity,
        pop_identity: pop.identity,
        enrollment_identity: enrollment.identity,
        install_policy_identity: grant.install_policy_digest(),
        coordinates: enrollment.candidate.coordinates,
        genesis_identity: genesis.identity,
        store_commitment_identity,
        append_identity: receipt.append_identity,
        persisted_resolution_identity: receipt.persisted_resolution_identity,
        receipt_identity: receipt.identity,
        initial_binding_identity: receipt.initial_current_binding_identity,
        cuts,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_wu_05_bootstrap_generation_owner_generation_genesis_signature_store(
    grant: &VerifiedBootstrapGrantV1,
    pop: &StoreIntegrityProofOfPossessionV1,
    enrollment: &StoreIntegrityEnrollmentV2,
    genesis: &StoreIntegrityGenerationGenesisV1,
    receipt: &StoreIntegrityBootstrapTransitionReceiptV1,
    store_commitment_identity: SignerIdentityV1,
    cuts: [u64; 9],
) -> Result<BootstrapToGenerationTransitionV1, SignerRefusalV2> {
    construct_transition(grant, pop, enrollment, genesis, receipt, store_commitment_identity, cuts)
        .map(BootstrapToGenerationTransitionV1::BootstrapGenerationOwnerGenerationGenesisSignatureStoreCommitmentTransitionReceiptVerified)
}

pub(crate) fn verify_sg_wu_05_bootstrap_generation_owner_generation_genesis_signature_store(
    transition: &BootstrapToGenerationTransitionV1,
) -> Result<(), SignerRefusalV2> {
    let BootstrapToGenerationTransitionV1::BootstrapGenerationOwnerGenerationGenesisSignatureStoreCommitmentTransitionReceiptVerified(evidence) = transition else {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    };
    verify_transition_evidence(evidence)
}

fn verify_transition_evidence(
    evidence: &BootstrapTransitionEvidenceV1,
) -> Result<(), SignerRefusalV2> {
    verify_cut_order(&evidence.cuts)?;
    evidence.coordinates.verify()?;
    if [
        evidence.grant_identity,
        evidence.grant_request_identity,
        evidence.candidate_identity,
        evidence.proposal_identity,
        evidence.pop_identity,
        evidence.enrollment_identity,
        evidence.install_policy_identity,
        evidence.genesis_identity,
        evidence.store_commitment_identity,
        evidence.append_identity,
        evidence.persisted_resolution_identity,
        evidence.receipt_identity,
        evidence.initial_binding_identity,
    ]
    .iter()
    .any(|value| *value == [0; 32])
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let expected = cycle_free_transition_identity(
        &evidence.grant_identity,
        &evidence.grant_request_identity,
        &evidence.candidate_identity,
        &evidence.enrollment_identity,
        &evidence.pop_identity,
        &evidence.install_policy_identity,
        &evidence.coordinates,
        evidence.cuts[6],
    );
    if evidence.transition_identity != expected {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_n_21_bootstrap_generation_transition_follows_grant_proposal_pop(
    grant: &VerifiedBootstrapGrantV1,
    pop: &StoreIntegrityProofOfPossessionV1,
    enrollment: &StoreIntegrityEnrollmentV2,
    genesis: &StoreIntegrityGenerationGenesisV1,
    receipt: &StoreIntegrityBootstrapTransitionReceiptV1,
    store_commitment_identity: SignerIdentityV1,
    cuts: [u64; 9],
) -> Result<BootstrapToGenerationTransitionV1, SignerRefusalV2> {
    construct_transition(grant, pop, enrollment, genesis, receipt, store_commitment_identity, cuts)
        .map(BootstrapToGenerationTransitionV1::BootstrapGenerationTransitionFollowsGrantProposalPoPBootstrapCapabilityGenesisVerified)
}

pub(crate) fn verify_sg_n_21_bootstrap_generation_transition_follows_grant_proposal_pop(
    transition: &BootstrapToGenerationTransitionV1,
) -> Result<(), SignerRefusalV2> {
    let BootstrapToGenerationTransitionV1::BootstrapGenerationTransitionFollowsGrantProposalPoPBootstrapCapabilityGenesisVerified(evidence) = transition else {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    };
    verify_transition_evidence(evidence)
}

pub(crate) fn construct_sg_n_22_failure_retry_at_transition_cut_has_durable(
    reached: BootstrapTransitionStageV1,
    durable_through: BootstrapTransitionStageV1,
    ephemeral_signature_destroyed_on_failure: bool,
    retry_requires_same_grant_and_proposal: bool,
) -> Result<SignerTransitionCutStateV1, SignerRefusalV2> {
    if durable_through > reached
        || !ephemeral_signature_destroyed_on_failure
        || !retry_requires_same_grant_and_proposal
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(SignerTransitionCutStateV1::FailureRetryAtTransitionCutHasDurableEphemeralAuthorityCleanupVerified {
        reached, durable_through, ephemeral_signature_destroyed_on_failure,
        retry_requires_same_grant_and_proposal,
        generation_capability_available: reached == BootstrapTransitionStageV1::GenerationCapabilityAvailable,
    })
}

pub(crate) fn verify_sg_n_22_failure_retry_at_transition_cut_has_durable(
    state: &SignerTransitionCutStateV1,
) -> Result<(), SignerRefusalV2> {
    let SignerTransitionCutStateV1::FailureRetryAtTransitionCutHasDurableEphemeralAuthorityCleanupVerified {
        reached, durable_through, ephemeral_signature_destroyed_on_failure,
        retry_requires_same_grant_and_proposal, generation_capability_available,
    } = state;
    if durable_through > reached
        || !ephemeral_signature_destroyed_on_failure
        || !retry_requires_same_grant_and_proposal
        || *generation_capability_available
            != (*reached == BootstrapTransitionStageV1::GenerationCapabilityAvailable)
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_state_never_retroactively_grants_capability() {
        let state = construct_sg_n_22_failure_retry_at_transition_cut_has_durable(
            BootstrapTransitionStageV1::GovernedCommitAppended,
            BootstrapTransitionStageV1::GovernedCommitAppended,
            true,
            true,
        )
        .unwrap();
        assert!(verify_sg_n_22_failure_retry_at_transition_cut_has_durable(&state).is_ok());
        let SignerTransitionCutStateV1::FailureRetryAtTransitionCutHasDurableEphemeralAuthorityCleanupVerified {
            generation_capability_available, ..
        } = state;
        assert!(!generation_capability_available);
    }

    #[test]
    fn cut_order_must_be_strict() {
        assert!(verify_cut_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).is_ok());
        assert!(verify_cut_order(&[1, 2, 3, 4, 5, 5, 7, 8, 9]).is_err());
    }
}
