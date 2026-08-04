//! Canonical signer-lifecycle records owned by the Store-private signer.
//!
//! These records contain correspondence evidence only.  Constructors bind
//! every coordinate into a domain-separated identity and verifiers re-check
//! the complete relation.  None of the types contains private key material or
//! provides an authority-bearing constructor outside this crate.

use ed25519_dalek::{Signature, VerifyingKey};
use nq_protocol::sha256_bytes;

use super::messages::SignerIdentityV1;
use super::result::SignerRefusalV2;

const POP_DOMAIN: &[u8] = b"nq.c2.store_integrity.proof_of_possession.v1";
const ENROLLMENT_CANDIDATE_DOMAIN: &[u8] =
    b"nq.c2.store_integrity_enrollment_candidate.identity.v1";
const ENROLLMENT_DOMAIN: &[u8] = b"nq.c2.store_integrity_enrollment.identity.v2";
const GENESIS_DOMAIN: &[u8] = b"nq.c2.store_generation_genesis.identity.v1";
const BOOTSTRAP_RECEIPT_DOMAIN: &[u8] = b"nq.c2.signer_bootstrap_transition_receipt.identity.v1";
const NORMAL_INTENT_DOMAIN: &[u8] = b"nq.c2.signer_normal_rotation_intent.identity.v1";
const NORMAL_RECEIPT_DOMAIN: &[u8] = b"nq.c2.signer_normal_rotation_receipt.identity.v1";

fn nonzero(value: &SignerIdentityV1) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn exact_identity(domain: &[u8], parts: &[&[u8]]) -> SignerIdentityV1 {
    let mut bytes =
        Vec::with_capacity(domain.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    for part in parts {
        bytes.extend_from_slice(&((*part).len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    let digest = sha256_bytes(&bytes);
    hex::decode(&digest.as_str()[7..])
        .expect("sha256 digest is canonical hex")
        .try_into()
        .expect("sha256 is 32 bytes")
}

fn verify_signature(
    verifying_key: &[u8; 32],
    signature: &[u8; 64],
    preimage: &[u8],
) -> Result<(), SignerRefusalV2> {
    let key = VerifyingKey::from_bytes(verifying_key)
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)?;
    key.verify_strict(preimage, &Signature::from_bytes(signature))
        .map_err(|_| SignerRefusalV2::ExternalCarrierScopeMismatch)
}

/// Coordinates preserved across every record in one signer lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignerRecordCoordinatesV1 {
    pub(crate) occurrence: SignerIdentityV1,
    pub(crate) physical_generation: SignerIdentityV1,
    pub(crate) lifecycle_root: SignerIdentityV1,
    pub(crate) scope: SignerIdentityV1,
    pub(crate) resident: SignerIdentityV1,
    pub(crate) resident_generation: u64,
    pub(crate) role: SignerIdentityV1,
    pub(crate) role_manifest_generation: u64,
    pub(crate) authority_domain: SignerIdentityV1,
    pub(crate) signer_policy: SignerIdentityV1,
    pub(crate) signer_policy_version: u64,
}

impl SignerRecordCoordinatesV1 {
    pub(crate) fn verify(&self) -> Result<(), SignerRefusalV2> {
        if self.resident_generation == 0
            || self.role_manifest_generation == 0
            || self.signer_policy_version == 0
            || [
                self.occurrence,
                self.physical_generation,
                self.lifecycle_root,
                self.scope,
                self.resident,
                self.role,
                self.authority_domain,
                self.signer_policy,
            ]
            .iter()
            .any(|value| !nonzero(value))
        {
            return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
        }
        Ok(())
    }

    pub(crate) fn identity_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * 8 + 24);
        bytes.extend_from_slice(&self.occurrence);
        bytes.extend_from_slice(&self.physical_generation);
        bytes.extend_from_slice(&self.lifecycle_root);
        bytes.extend_from_slice(&self.scope);
        bytes.extend_from_slice(&self.resident);
        bytes.extend_from_slice(&self.resident_generation.to_be_bytes());
        bytes.extend_from_slice(&self.role);
        bytes.extend_from_slice(&self.role_manifest_generation.to_be_bytes());
        bytes.extend_from_slice(&self.authority_domain);
        bytes.extend_from_slice(&self.signer_policy);
        bytes.extend_from_slice(&self.signer_policy_version.to_be_bytes());
        bytes
    }
}

/// Exact, cycle-free proof-of-possession correspondence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityProofOfPossessionV1 {
    pub(crate) identity: SignerIdentityV1,
    pub(crate) proposal_identity: SignerIdentityV1,
    pub(crate) grant_identity: SignerIdentityV1,
    pub(crate) challenge_identity: SignerIdentityV1,
    pub(crate) custody_nonce: SignerIdentityV1,
    pub(crate) public_key: [u8; 32],
    pub(crate) key_generation: u64,
    pub(crate) attempt_identity: SignerIdentityV1,
    pub(crate) candidate_identity: SignerIdentityV1,
    pub(crate) coordinates: SignerRecordCoordinatesV1,
    pub(crate) pop_cut: u64,
    pub(crate) signature: [u8; 64],
}

fn pop_preimage(pop: &StoreIntegrityProofOfPossessionV1) -> Vec<u8> {
    let key_generation = pop.key_generation.to_be_bytes();
    let pop_cut = pop.pop_cut.to_be_bytes();
    let mut parts = vec![
        pop.proposal_identity.as_slice(),
        pop.grant_identity.as_slice(),
        pop.challenge_identity.as_slice(),
        pop.custody_nonce.as_slice(),
        pop.public_key.as_slice(),
        key_generation.as_slice(),
        pop.attempt_identity.as_slice(),
        pop.candidate_identity.as_slice(),
        pop_cut.as_slice(),
    ];
    let coordinate_bytes = pop.coordinates.identity_bytes();
    parts.push(&coordinate_bytes);
    let identity = exact_identity(POP_DOMAIN, &parts);
    let mut preimage = Vec::with_capacity(POP_DOMAIN.len() + 1 + 32);
    preimage.extend_from_slice(POP_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(&identity);
    preimage
}

fn verify_pop(pop: &StoreIntegrityProofOfPossessionV1) -> Result<(), SignerRefusalV2> {
    pop.coordinates.verify()?;
    if pop.pop_cut == 0
        || [
            pop.proposal_identity,
            pop.grant_identity,
            pop.challenge_identity,
            pop.custody_nonce,
            pop.attempt_identity,
            pop.candidate_identity,
        ]
        .iter()
        .any(|value| !nonzero(value))
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let preimage = pop_preimage(pop);
    if pop.identity != preimage[preimage.len() - 32..] {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_signature(&pop.public_key, &pop.signature, &preimage)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_n_09_proposal_identity_custody_nonce_public_key_key(
    proposal_identity: SignerIdentityV1,
    grant_identity: SignerIdentityV1,
    challenge_identity: SignerIdentityV1,
    custody_nonce: SignerIdentityV1,
    public_key: [u8; 32],
    key_generation: u64,
    attempt_identity: SignerIdentityV1,
    candidate_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    pop_cut: u64,
    signature: [u8; 64],
) -> Result<StoreIntegrityProofOfPossessionV1, SignerRefusalV2> {
    let mut pop = StoreIntegrityProofOfPossessionV1 {
        identity: [0; 32],
        proposal_identity,
        grant_identity,
        challenge_identity,
        custody_nonce,
        public_key,
        key_generation,
        attempt_identity,
        candidate_identity,
        coordinates,
        pop_cut,
        signature,
    };
    let preimage = pop_preimage(&pop);
    pop.identity
        .copy_from_slice(&preimage[preimage.len() - 32..]);
    verify_pop(&pop)?;
    Ok(pop)
}

pub(crate) fn verify_sg_n_09_proposal_identity_custody_nonce_public_key_key(
    pop: &StoreIntegrityProofOfPossessionV1,
) -> Result<(), SignerRefusalV2> {
    verify_pop(pop)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_rec_04_storeintegrityproofofpossessionv1_proposal_grant_challenge_scope_key_generation(
    proposal_identity: SignerIdentityV1,
    grant_identity: SignerIdentityV1,
    challenge_identity: SignerIdentityV1,
    custody_nonce: SignerIdentityV1,
    public_key: [u8; 32],
    key_generation: u64,
    attempt_identity: SignerIdentityV1,
    candidate_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    pop_cut: u64,
    signature: [u8; 64],
) -> Result<StoreIntegrityProofOfPossessionV1, SignerRefusalV2> {
    construct_sg_n_09_proposal_identity_custody_nonce_public_key_key(
        proposal_identity,
        grant_identity,
        challenge_identity,
        custody_nonce,
        public_key,
        key_generation,
        attempt_identity,
        candidate_identity,
        coordinates,
        pop_cut,
        signature,
    )
}

pub(crate) fn verify_sg_rec_04_storeintegrityproofofpossessionv1_proposal_grant_challenge_scope_key_generation(
    pop: &StoreIntegrityProofOfPossessionV1,
) -> Result<(), SignerRefusalV2> {
    verify_pop(pop)
}

/// Inert enrollment candidate fixed before PoP verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityEnrollmentCandidateV1 {
    pub(crate) identity: SignerIdentityV1,
    pub(crate) candidate_cut: u64,
    pub(crate) attempt_identity: SignerIdentityV1,
    pub(crate) proposal_identity: SignerIdentityV1,
    pub(crate) grant_identity: SignerIdentityV1,
    pub(crate) grant_request_identity: SignerIdentityV1,
    pub(crate) coordinates: SignerRecordCoordinatesV1,
    pub(crate) public_key: [u8; 32],
    pub(crate) key_generation: u64,
    pub(crate) active_policy: SignerIdentityV1,
    pub(crate) active_policy_generation: u64,
}

fn candidate_identity(candidate: &StoreIntegrityEnrollmentCandidateV1) -> SignerIdentityV1 {
    let key_generation = candidate.key_generation.to_be_bytes();
    let policy_generation = candidate.active_policy_generation.to_be_bytes();
    let candidate_cut = candidate.candidate_cut.to_be_bytes();
    let mut parts = vec![
        candidate.attempt_identity.as_slice(),
        candidate.proposal_identity.as_slice(),
        candidate.grant_identity.as_slice(),
        candidate.grant_request_identity.as_slice(),
        candidate.public_key.as_slice(),
        key_generation.as_slice(),
        candidate.active_policy.as_slice(),
        policy_generation.as_slice(),
        candidate_cut.as_slice(),
    ];
    let coordinate_bytes = candidate.coordinates.identity_bytes();
    parts.push(&coordinate_bytes);
    exact_identity(ENROLLMENT_CANDIDATE_DOMAIN, &parts)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_rec_05a_candidate(
    candidate_cut: u64,
    attempt_identity: SignerIdentityV1,
    proposal_identity: SignerIdentityV1,
    grant_identity: SignerIdentityV1,
    grant_request_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    public_key: [u8; 32],
    key_generation: u64,
    active_policy: SignerIdentityV1,
    active_policy_generation: u64,
) -> Result<StoreIntegrityEnrollmentCandidateV1, SignerRefusalV2> {
    coordinates.verify()?;
    if candidate_cut == 0
        || active_policy_generation == 0
        || [
            attempt_identity,
            proposal_identity,
            grant_identity,
            grant_request_identity,
            active_policy,
        ]
        .iter()
        .any(|value| !nonzero(value))
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let mut candidate = StoreIntegrityEnrollmentCandidateV1 {
        identity: [0; 32],
        candidate_cut,
        attempt_identity,
        proposal_identity,
        grant_identity,
        grant_request_identity,
        coordinates,
        public_key,
        key_generation,
        active_policy,
        active_policy_generation,
    };
    candidate.identity = candidate_identity(&candidate);
    Ok(candidate)
}

pub(crate) fn verify_sg_rec_05a_candidate(
    candidate: &StoreIntegrityEnrollmentCandidateV1,
) -> Result<(), SignerRefusalV2> {
    candidate.coordinates.verify()?;
    if candidate.identity != candidate_identity(candidate) {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

/// Runtime accepted enrollment wrapper. It is unavailable before exact PoP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityEnrollmentV2 {
    pub(crate) identity: SignerIdentityV1,
    pub(crate) candidate: StoreIntegrityEnrollmentCandidateV1,
    pub(crate) pop_identity: SignerIdentityV1,
    pub(crate) accepted_cut: u64,
}

pub(crate) fn construct_sg_rec_05_accepted_wrapper(
    candidate: StoreIntegrityEnrollmentCandidateV1,
    pop: &StoreIntegrityProofOfPossessionV1,
    accepted_cut: u64,
) -> Result<StoreIntegrityEnrollmentV2, SignerRefusalV2> {
    verify_sg_rec_05a_candidate(&candidate)?;
    verify_pop(pop)?;
    if accepted_cut <= candidate.candidate_cut
        || accepted_cut <= pop.pop_cut
        || pop.candidate_identity != candidate.identity
        || pop.attempt_identity != candidate.attempt_identity
        || pop.proposal_identity != candidate.proposal_identity
        || pop.grant_identity != candidate.grant_identity
        || pop.public_key != candidate.public_key
        || pop.key_generation != candidate.key_generation
        || pop.coordinates != candidate.coordinates
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    let identity = exact_identity(
        ENROLLMENT_DOMAIN,
        &[
            &candidate.identity,
            &pop.identity,
            &candidate.attempt_identity,
            &accepted_cut.to_be_bytes(),
        ],
    );
    Ok(StoreIntegrityEnrollmentV2 {
        identity,
        candidate,
        pop_identity: pop.identity,
        accepted_cut,
    })
}

pub(crate) fn verify_sg_rec_05_accepted_wrapper(
    enrollment: &StoreIntegrityEnrollmentV2,
) -> Result<(), SignerRefusalV2> {
    verify_sg_rec_05a_candidate(&enrollment.candidate)?;
    let expected = exact_identity(
        ENROLLMENT_DOMAIN,
        &[
            &enrollment.candidate.identity,
            &enrollment.pop_identity,
            &enrollment.candidate.attempt_identity,
            &enrollment.accepted_cut.to_be_bytes(),
        ],
    );
    if enrollment.accepted_cut <= enrollment.candidate.candidate_cut
        || enrollment.identity != expected
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    Ok(())
}

/// Signed generation genesis produced only by the bootstrap signer role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityGenerationGenesisV1 {
    pub(crate) identity: SignerIdentityV1,
    pub(crate) bootstrap_transition_identity: SignerIdentityV1,
    pub(crate) bootstrap_identity: SignerIdentityV1,
    pub(crate) generation_commitment_identity: SignerIdentityV1,
    pub(crate) initial_enrollment_identity: SignerIdentityV1,
    pub(crate) coordinates: SignerRecordCoordinatesV1,
    pub(crate) genesis_cut: u64,
    pub(crate) signer_key_generation: u64,
    pub(crate) signer_public_key: [u8; 32],
    pub(crate) signature: [u8; 64],
}

fn signed_record_preimage(domain: &[u8], identity: &SignerIdentityV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + 33);
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(identity);
    bytes
}

fn genesis_identity(record: &StoreIntegrityGenerationGenesisV1) -> SignerIdentityV1 {
    let genesis_cut = record.genesis_cut.to_be_bytes();
    let signer_generation = record.signer_key_generation.to_be_bytes();
    let mut parts = vec![
        record.bootstrap_transition_identity.as_slice(),
        record.bootstrap_identity.as_slice(),
        record.generation_commitment_identity.as_slice(),
        record.initial_enrollment_identity.as_slice(),
        genesis_cut.as_slice(),
        signer_generation.as_slice(),
    ];
    let coordinate_bytes = record.coordinates.identity_bytes();
    parts.push(&coordinate_bytes);
    exact_identity(GENESIS_DOMAIN, &parts)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_rec_06_generation_genesis_signed_payload_identity_signature_carrier(
    bootstrap_transition_identity: SignerIdentityV1,
    bootstrap_identity: SignerIdentityV1,
    generation_commitment_identity: SignerIdentityV1,
    initial_enrollment_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    genesis_cut: u64,
    signer_key_generation: u64,
    signer_public_key: [u8; 32],
    signature: [u8; 64],
) -> Result<StoreIntegrityGenerationGenesisV1, SignerRefusalV2> {
    coordinates.verify()?;
    let mut record = StoreIntegrityGenerationGenesisV1 {
        identity: [0; 32],
        bootstrap_transition_identity,
        bootstrap_identity,
        generation_commitment_identity,
        initial_enrollment_identity,
        coordinates,
        genesis_cut,
        signer_key_generation,
        signer_public_key,
        signature,
    };
    record.identity = genesis_identity(&record);
    verify_sg_rec_06_generation_genesis_signed_payload_identity_signature_carrier(&record)?;
    Ok(record)
}

pub(crate) fn verify_sg_rec_06_generation_genesis_signed_payload_identity_signature_carrier(
    record: &StoreIntegrityGenerationGenesisV1,
) -> Result<(), SignerRefusalV2> {
    record.coordinates.verify()?;
    if record.genesis_cut == 0
        || [
            record.bootstrap_transition_identity,
            record.bootstrap_identity,
            record.generation_commitment_identity,
            record.initial_enrollment_identity,
        ]
        .iter()
        .any(|value| !nonzero(value))
        || record.identity != genesis_identity(record)
    {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_signature(
        &record.signer_public_key,
        &record.signature,
        &signed_record_preimage(GENESIS_DOMAIN, &record.identity),
    )
}

/// Exact bootstrap transition receipt and initial binding projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityBootstrapTransitionReceiptV1 {
    pub(crate) identity: SignerIdentityV1,
    pub(crate) transition_identity: SignerIdentityV1,
    pub(crate) bootstrap_grant_identity: SignerIdentityV1,
    pub(crate) enrollment_identity: SignerIdentityV1,
    pub(crate) initial_pop_identity: SignerIdentityV1,
    pub(crate) append_identity: SignerIdentityV1,
    pub(crate) persisted_resolution_identity: SignerIdentityV1,
    pub(crate) initial_current_binding_identity: SignerIdentityV1,
    pub(crate) coordinates: SignerRecordCoordinatesV1,
    pub(crate) effective_cut: u64,
    pub(crate) signer_key_generation: u64,
    pub(crate) signer_public_key: [u8; 32],
    pub(crate) signature: [u8; 64],
}

fn bootstrap_receipt_identity(
    record: &StoreIntegrityBootstrapTransitionReceiptV1,
) -> SignerIdentityV1 {
    let effective_cut = record.effective_cut.to_be_bytes();
    let signer_generation = record.signer_key_generation.to_be_bytes();
    let mut parts = vec![
        record.transition_identity.as_slice(),
        record.bootstrap_grant_identity.as_slice(),
        record.enrollment_identity.as_slice(),
        record.initial_pop_identity.as_slice(),
        record.append_identity.as_slice(),
        record.persisted_resolution_identity.as_slice(),
        record.initial_current_binding_identity.as_slice(),
        effective_cut.as_slice(),
        signer_generation.as_slice(),
    ];
    let coordinate_bytes = record.coordinates.identity_bytes();
    parts.push(&coordinate_bytes);
    exact_identity(BOOTSTRAP_RECEIPT_DOMAIN, &parts)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_rec_07_bootstrap_generation_transition_receipt_binding_commitment_signature(
    transition_identity: SignerIdentityV1,
    bootstrap_grant_identity: SignerIdentityV1,
    enrollment_identity: SignerIdentityV1,
    initial_pop_identity: SignerIdentityV1,
    append_identity: SignerIdentityV1,
    persisted_resolution_identity: SignerIdentityV1,
    initial_current_binding_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    effective_cut: u64,
    signer_key_generation: u64,
    signer_public_key: [u8; 32],
    signature: [u8; 64],
) -> Result<StoreIntegrityBootstrapTransitionReceiptV1, SignerRefusalV2> {
    let mut record = StoreIntegrityBootstrapTransitionReceiptV1 {
        identity: [0; 32],
        transition_identity,
        bootstrap_grant_identity,
        enrollment_identity,
        initial_pop_identity,
        append_identity,
        persisted_resolution_identity,
        initial_current_binding_identity,
        coordinates,
        effective_cut,
        signer_key_generation,
        signer_public_key,
        signature,
    };
    record.identity = bootstrap_receipt_identity(&record);
    verify_sg_rec_07_bootstrap_generation_transition_receipt_binding_commitment_signature(&record)?;
    Ok(record)
}

pub(crate) fn verify_sg_rec_07_bootstrap_generation_transition_receipt_binding_commitment_signature(
    record: &StoreIntegrityBootstrapTransitionReceiptV1,
) -> Result<(), SignerRefusalV2> {
    record.coordinates.verify()?;
    if record.effective_cut == 0 || record.identity != bootstrap_receipt_identity(record) {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_signature(
        &record.signer_public_key,
        &record.signature,
        &signed_record_preimage(BOOTSTRAP_RECEIPT_DOMAIN, &record.identity),
    )
}

/// Exact healthy normal-rotation intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityNormalRotationIntentV1 {
    pub(crate) identity: SignerIdentityV1,
    pub(crate) transition_identity: SignerIdentityV1,
    pub(crate) predecessor_binding_identity: SignerIdentityV1,
    pub(crate) successor_proposal_identity: SignerIdentityV1,
    pub(crate) successor_pop_identity: SignerIdentityV1,
    pub(crate) rotation_continuity_identity: SignerIdentityV1,
    pub(crate) active_policy_continuity_identity: SignerIdentityV1,
    pub(crate) predecessor_policy_identity: SignerIdentityV1,
    pub(crate) successor_policy_identity: SignerIdentityV1,
    pub(crate) pre_effect_b_root_identity: SignerIdentityV1,
    pub(crate) pre_effect_b_cursor: u64,
    pub(crate) successor_projection_identity: SignerIdentityV1,
    pub(crate) coordinates: SignerRecordCoordinatesV1,
    pub(crate) transition_cut: u64,
    pub(crate) signer_key_generation: u64,
    pub(crate) predecessor_public_key: [u8; 32],
    pub(crate) signature: [u8; 64],
}

fn normal_intent_identity(record: &StoreIntegrityNormalRotationIntentV1) -> SignerIdentityV1 {
    let b_cursor = record.pre_effect_b_cursor.to_be_bytes();
    let transition_cut = record.transition_cut.to_be_bytes();
    let signer_generation = record.signer_key_generation.to_be_bytes();
    let mut parts = vec![
        record.transition_identity.as_slice(),
        record.predecessor_binding_identity.as_slice(),
        record.successor_proposal_identity.as_slice(),
        record.successor_pop_identity.as_slice(),
        record.rotation_continuity_identity.as_slice(),
        record.active_policy_continuity_identity.as_slice(),
        record.predecessor_policy_identity.as_slice(),
        record.successor_policy_identity.as_slice(),
        record.pre_effect_b_root_identity.as_slice(),
        b_cursor.as_slice(),
        record.successor_projection_identity.as_slice(),
        transition_cut.as_slice(),
        signer_generation.as_slice(),
    ];
    let coordinate_bytes = record.coordinates.identity_bytes();
    parts.push(&coordinate_bytes);
    exact_identity(NORMAL_INTENT_DOMAIN, &parts)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_rec_08_healthy_rotation_intent_binding_current_predecessor_successor(
    transition_identity: SignerIdentityV1,
    predecessor_binding_identity: SignerIdentityV1,
    successor_proposal_identity: SignerIdentityV1,
    successor_pop_identity: SignerIdentityV1,
    rotation_continuity_identity: SignerIdentityV1,
    active_policy_continuity_identity: SignerIdentityV1,
    predecessor_policy_identity: SignerIdentityV1,
    successor_policy_identity: SignerIdentityV1,
    pre_effect_b_root_identity: SignerIdentityV1,
    pre_effect_b_cursor: u64,
    successor_projection_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    transition_cut: u64,
    signer_key_generation: u64,
    predecessor_public_key: [u8; 32],
    signature: [u8; 64],
) -> Result<StoreIntegrityNormalRotationIntentV1, SignerRefusalV2> {
    let mut record = StoreIntegrityNormalRotationIntentV1 {
        identity: [0; 32],
        transition_identity,
        predecessor_binding_identity,
        successor_proposal_identity,
        successor_pop_identity,
        rotation_continuity_identity,
        active_policy_continuity_identity,
        predecessor_policy_identity,
        successor_policy_identity,
        pre_effect_b_root_identity,
        pre_effect_b_cursor,
        successor_projection_identity,
        coordinates,
        transition_cut,
        signer_key_generation,
        predecessor_public_key,
        signature,
    };
    record.identity = normal_intent_identity(&record);
    verify_sg_rec_08_healthy_rotation_intent_binding_current_predecessor_successor(&record)?;
    Ok(record)
}

pub(crate) fn verify_sg_rec_08_healthy_rotation_intent_binding_current_predecessor_successor(
    record: &StoreIntegrityNormalRotationIntentV1,
) -> Result<(), SignerRefusalV2> {
    record.coordinates.verify()?;
    if record.transition_cut == 0 || record.identity != normal_intent_identity(record) {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_signature(
        &record.predecessor_public_key,
        &record.signature,
        &signed_record_preimage(NORMAL_INTENT_DOMAIN, &record.identity),
    )
}

/// Exact normal-rotation completion receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreIntegrityNormalRotationReceiptV1 {
    pub(crate) identity: SignerIdentityV1,
    pub(crate) intent_identity: SignerIdentityV1,
    pub(crate) transition_identity: SignerIdentityV1,
    pub(crate) predecessor_binding_identity: SignerIdentityV1,
    pub(crate) successor_binding_identity: SignerIdentityV1,
    pub(crate) successor_enrollment_identity: SignerIdentityV1,
    pub(crate) pre_receipt_b_root_identity: SignerIdentityV1,
    pub(crate) pre_receipt_b_cursor: u64,
    pub(crate) append_identity: SignerIdentityV1,
    pub(crate) persisted_resolution_identity: SignerIdentityV1,
    pub(crate) coordinates: SignerRecordCoordinatesV1,
    pub(crate) effective_cut: u64,
    pub(crate) signer_key_generation: u64,
    pub(crate) successor_public_key: [u8; 32],
    pub(crate) signature: [u8; 64],
}

fn normal_receipt_identity(record: &StoreIntegrityNormalRotationReceiptV1) -> SignerIdentityV1 {
    let b_cursor = record.pre_receipt_b_cursor.to_be_bytes();
    let effective_cut = record.effective_cut.to_be_bytes();
    let signer_generation = record.signer_key_generation.to_be_bytes();
    let mut parts = vec![
        record.intent_identity.as_slice(),
        record.transition_identity.as_slice(),
        record.predecessor_binding_identity.as_slice(),
        record.successor_binding_identity.as_slice(),
        record.successor_enrollment_identity.as_slice(),
        record.pre_receipt_b_root_identity.as_slice(),
        b_cursor.as_slice(),
        record.append_identity.as_slice(),
        record.persisted_resolution_identity.as_slice(),
        effective_cut.as_slice(),
        signer_generation.as_slice(),
    ];
    let coordinate_bytes = record.coordinates.identity_bytes();
    parts.push(&coordinate_bytes);
    exact_identity(NORMAL_RECEIPT_DOMAIN, &parts)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_sg_rec_09_healthy_rotation_receipt_binding_intent_append_frontier(
    intent_identity: SignerIdentityV1,
    transition_identity: SignerIdentityV1,
    predecessor_binding_identity: SignerIdentityV1,
    successor_binding_identity: SignerIdentityV1,
    successor_enrollment_identity: SignerIdentityV1,
    pre_receipt_b_root_identity: SignerIdentityV1,
    pre_receipt_b_cursor: u64,
    append_identity: SignerIdentityV1,
    persisted_resolution_identity: SignerIdentityV1,
    coordinates: SignerRecordCoordinatesV1,
    effective_cut: u64,
    signer_key_generation: u64,
    successor_public_key: [u8; 32],
    signature: [u8; 64],
) -> Result<StoreIntegrityNormalRotationReceiptV1, SignerRefusalV2> {
    let mut record = StoreIntegrityNormalRotationReceiptV1 {
        identity: [0; 32],
        intent_identity,
        transition_identity,
        predecessor_binding_identity,
        successor_binding_identity,
        successor_enrollment_identity,
        pre_receipt_b_root_identity,
        pre_receipt_b_cursor,
        append_identity,
        persisted_resolution_identity,
        coordinates,
        effective_cut,
        signer_key_generation,
        successor_public_key,
        signature,
    };
    record.identity = normal_receipt_identity(&record);
    verify_sg_rec_09_healthy_rotation_receipt_binding_intent_append_frontier(&record)?;
    Ok(record)
}

pub(crate) fn verify_sg_rec_09_healthy_rotation_receipt_binding_intent_append_frontier(
    record: &StoreIntegrityNormalRotationReceiptV1,
) -> Result<(), SignerRefusalV2> {
    record.coordinates.verify()?;
    if record.effective_cut == 0 || record.identity != normal_receipt_identity(record) {
        return Err(SignerRefusalV2::ExternalCarrierScopeMismatch);
    }
    verify_signature(
        &record.successor_public_key,
        &record.signature,
        &signed_record_preimage(NORMAL_RECEIPT_DOMAIN, &record.identity),
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn id(value: u8) -> SignerIdentityV1 {
        [value; 32]
    }

    fn coordinates() -> SignerRecordCoordinatesV1 {
        SignerRecordCoordinatesV1 {
            occurrence: id(1),
            physical_generation: id(2),
            lifecycle_root: id(3),
            scope: id(4),
            resident: id(5),
            resident_generation: 1,
            role: id(6),
            role_manifest_generation: 1,
            authority_domain: id(7),
            signer_policy: id(8),
            signer_policy_version: 1,
        }
    }

    #[test]
    fn pop_is_bound_to_candidate_and_initial_generation_zero() {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let mut pop = StoreIntegrityProofOfPossessionV1 {
            identity: [0; 32],
            proposal_identity: id(10),
            grant_identity: id(11),
            challenge_identity: id(12),
            custody_nonce: id(13),
            public_key: signing.verifying_key().to_bytes(),
            key_generation: 0,
            attempt_identity: id(14),
            candidate_identity: id(15),
            coordinates: coordinates(),
            pop_cut: 2,
            signature: [0; 64],
        };
        let preimage = pop_preimage(&pop);
        pop.identity
            .copy_from_slice(&preimage[preimage.len() - 32..]);
        pop.signature = signing.sign(&preimage).to_bytes();
        assert!(verify_pop(&pop).is_ok());
        pop.candidate_identity = id(16);
        assert!(verify_pop(&pop).is_err());
    }
}
